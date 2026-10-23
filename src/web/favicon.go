package web

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/gif" // 注册 GIF 解码器（image.Decode 使用）
	"image/png"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// 目标地址网页图标（favicon）抓取：解析首页 <link rel=icon> 与 /favicon.ico，
// 支持 PNG/JPEG/GIF/ICO（含 ICO 内嵌 PNG 与未压缩 BMP），返回各尺寸图标供前端选择。

const (
	faviconMaxHTML      = 2 << 20 // 首页最大 2MB
	faviconMaxIcon      = 4 << 20 // 单个图标最大 4MB
	faviconFetchTimeout = 10 * time.Second
	faviconMaxRedirects = 5
	faviconMaxResults   = 12 // 返回最多 12 个图标
)

// faviconResult 一个可用的图标（已转为 base64 data URI，前端可直接预览/使用）。
type faviconResult struct {
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Format string `json:"format"` // png/jpeg（已归一化）
	Data   string `json:"data"`   // data:image/...;base64,...
	Source string `json:"source"` // 来源描述
}

var faviconHTTPClient = &http.Client{
	Timeout: faviconFetchTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= faviconMaxRedirects {
			return errors.New("重定向次数过多")
		}
		return nil
	},
}

// fetchFavicons 从目标地址抓取网页图标（含不同尺寸），失败时返回错误与过程中的 warning。
func fetchFavicons(addr string, port int) ([]faviconResult, []string, error) {
	host := normalizeFaviconHost(addr)
	if host == "" {
		return nil, nil, fmt.Errorf("无效的目标地址: %s", addr)
	}
	if port <= 0 {
		port = 80
	}
	base := fmt.Sprintf("http://%s:%d", host, port)

	var warnings []string
	candidates := []string{
		base + "/favicon.ico",
		base + "/favicon.png",
	}
	seen := map[string]bool{}

	// 1. 抓取首页并解析 <link rel=icon/apple-touch-icon> 图标引用
	if body, err := fetchFaviconURL(base + "/"); err == nil {
		for _, href := range parseFaviconLinks(string(body)) {
			abs, err := resolveFaviconURL(base, href)
			if err != nil {
				continue
			}
			candidates = append(candidates, abs)
		}
	} else {
		warnings = append(warnings, "获取首页失败: "+err.Error())
	}

	// 2. 逐个抓取并解析（seen 用于对重复候选去重）
	var out []faviconResult
	for _, cand := range candidates {
		if seen[cand] {
			continue
		}
		seen[cand] = true
		data, err := fetchFaviconURL(cand)
		if err != nil {
			continue
		}
		results, err := parseFaviconData(data, cand)
		if err != nil {
			warnings = append(warnings, "解析失败 "+cand+": "+err.Error())
			continue
		}
		out = append(out, results...)
		if len(out) >= faviconMaxResults {
			break
		}
	}
	out = dedupFaviconResults(out)
	if len(out) > faviconMaxResults {
		out = out[:faviconMaxResults]
	}
	if len(out) == 0 {
		return nil, warnings, fmt.Errorf("未从 %s 获取到可用图标（仅支持 PNG/JPEG/GIF/ICO）", base)
	}
	return out, warnings, nil
}

// parseFaviconData 识别图标字节格式并返回一个或多个（ICO 含多尺寸）图标结果。
func parseFaviconData(data []byte, source string) ([]faviconResult, error) {
	switch {
	case isPNGBytes(data):
		w, h, err := faviconImageSize(data)
		if err != nil {
			return nil, err
		}
		return []faviconResult{{Width: w, Height: h, Format: "png", Data: faviconDataURI(data, "png"), Source: source}}, nil
	case isJPEGBytes(data):
		w, h, err := faviconImageSize(data)
		if err != nil {
			return nil, err
		}
		return []faviconResult{{Width: w, Height: h, Format: "jpeg", Data: faviconDataURI(data, "jpeg"), Source: source}}, nil
	case isICOBytes(data):
		return parseICOFavicon(data, source)
	case isSVGBytes(data):
		// SVG 无法转为桌面图标（512×512 PNG），静默跳过
		return nil, nil
	default:
		// GIF 等其他可解码格式：统一重编码为 PNG
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("不支持的图标格式")
		}
		b, err := encodePNGFavicon(img)
		if err != nil {
			return nil, err
		}
		bounds := img.Bounds()
		return []faviconResult{{Width: bounds.Dx(), Height: bounds.Dy(), Format: "png", Data: faviconDataURI(b, "png"), Source: source}}, nil
	}
}

// parseICOFavicon 解析 ICO 目录，枚举内嵌的每个尺寸图像（PNG 或未压缩 BMP），转成 PNG。
func parseICOFavicon(data []byte, source string) ([]faviconResult, error) {
	if len(data) < 6 {
		return nil, errors.New("ICO 文件过短")
	}
	count := int(binary.LittleEndian.Uint16(data[4:6]))
	if count <= 0 || count > 256 {
		return nil, errors.New("ICO 目录项数量非法")
	}
	var out []faviconResult
	for i := 0; i < count; i++ {
		off := 6 + i*16
		if off+16 > len(data) {
			break
		}
		// 尺寸：字节 0/1 为宽/高（0 表示 256）
		size := int(binary.LittleEndian.Uint32(data[off+8 : off+12]))
		start := int(binary.LittleEndian.Uint32(data[off+12 : off+16]))
		if size <= 0 || start < 0 || start+size > len(data) {
			continue
		}
		entry := data[start : start+size]
		var img image.Image
		switch {
		case isPNGBytes(entry):
			im, err := png.Decode(bytes.NewReader(entry))
			if err != nil {
				continue
			}
			img = im
		case isDIBHeader(entry):
			im, err := decodeDIBFavicon(entry)
			if err != nil {
				continue
			}
			img = im
		default:
			continue
		}
		b, err := encodePNGFavicon(img)
		if err != nil {
			continue
		}
		bounds := img.Bounds()
		out = append(out, faviconResult{
			Width:  bounds.Dx(),
			Height: bounds.Dy(),
			Format: "png",
			Data:   faviconDataURI(b, "png"),
			Source: source,
		})
	}
	if len(out) == 0 {
		return nil, errors.New("ICO 内无可用图像")
	}
	return out, nil
}

// decodeDIBFavicon 解码 ICO 内嵌的未压缩 DIB（BITMAPINFOHEADER，支持 32/24/8 位色）。
// ICO 条目不含 BMP 文件头，直接以 BITMAPINFOHEADER 开头；高度含 AND 掩码需折半。
func decodeDIBFavicon(data []byte) (image.Image, error) {
	if len(data) < 40 {
		return nil, errors.New("DIB 数据过短")
	}
	biSize := int(binary.LittleEndian.Uint32(data[0:4]))
	if biSize < 40 || biSize > len(data) {
		return nil, errors.New("DIB 头非法")
	}
	w := int(int32(binary.LittleEndian.Uint32(data[4:8])))
	if w <= 0 || w > 4096 {
		return nil, errors.New("DIB 宽度非法")
	}
	h := int(int32(binary.LittleEndian.Uint32(data[8:12])))
	if h < 0 {
		h = -h
	}
	h /= 2 // 去掉 AND 掩码的高度
	if h <= 0 || h > 4096 {
		return nil, errors.New("DIB 高度非法")
	}
	bpp := int(binary.LittleEndian.Uint16(data[14:16]))
	compression := binary.LittleEndian.Uint32(data[16:20])
	if compression != 0 {
		return nil, errors.New("仅支持未压缩 DIB")
	}

	pixStart := biSize
	var palette []byte
	if bpp <= 8 {
		palBytes := (1 << uint(bpp)) * 4
		if biSize+palBytes > len(data) {
			return nil, errors.New("DIB 调色板越界")
		}
		palette = data[biSize : biSize+palBytes]
		pixStart = biSize + palBytes
	}

	var rowLen int
	switch bpp {
	case 32:
		rowLen = w * 4
	case 24:
		rowLen = (w*3 + 3) &^ 3
	case 8:
		rowLen = (w + 3) &^ 3
	default:
		return nil, fmt.Errorf("不支持的位深: %d", bpp)
	}
	if pixStart < 0 || rowLen*h <= 0 || pixStart+rowLen*h > len(data) {
		return nil, errors.New("DIB 像素数据越界")
	}

	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		rowStart := pixStart + (h-1-y)*rowLen
		row := data[rowStart : rowStart+rowLen]
		for x := 0; x < w; x++ {
			switch bpp {
			case 32:
				b, g, r, a := row[x*4], row[x*4+1], row[x*4+2], row[x*4+3]
				img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: a})
			case 24:
				b, g, r := row[x*3], row[x*3+1], row[x*3+2]
				img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
			case 8:
				idx := int(row[x])
				if idx*4+3 < len(palette) {
					b, g, r := palette[idx*4], palette[idx*4+1], palette[idx*4+2]
					img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
				}
			}
		}
	}
	return img, nil
}

// faviconLinkRe 匹配 <link ...> 标签。
var faviconLinkRe = regexp.MustCompile(`(?is)<link\b[^>]*>`)

// parseFaviconLinks 解析 HTML 中所有 rel 含 icon 的 <link> 的 href。
func parseFaviconLinks(html string) []string {
	var hrefs []string
	for _, tag := range faviconLinkRe.FindAllString(html, -1) {
		rel := strings.ToLower(faviconAttr(tag, "rel"))
		if !strings.Contains(rel, "icon") {
			continue // icon / shortcut icon / apple-touch-icon / mask-icon
		}
		if href := faviconAttr(tag, "href"); href != "" {
			hrefs = append(hrefs, href)
		}
	}
	// 去重保序
	seen := map[string]bool{}
	var out []string
	for _, h := range hrefs {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// faviconAttr 提取标签内指定属性的值（支持双引号/单引号）。
func faviconAttr(tag, name string) string {
	re := regexp.MustCompile(`(?i)\b` + name + `\s*=\s*("([^"]*)"|'([^']*)')`)
	m := re.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	if m[2] != "" {
		return m[2]
	}
	return m[3]
}

// fetchFaviconURL 抓取 URL 内容（带超时、大小与重定向限制）。
func fetchFaviconURL(rawURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "TunHook favicon-fetcher")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,image/avif,image/webp,image/*,*/*;q=0.8")
	resp, err := faviconHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	limit := int64(faviconMaxIcon)
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml") {
		limit = faviconMaxHTML
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// normalizeFaviconHost 规整目标地址为 host（IPv6 加方括号，去除 scheme/端口）。
func normalizeFaviconHost(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimSuffix(addr, "/")
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		addr = h
	}
	if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
		addr = "[" + addr + "]"
	}
	return addr
}

func resolveFaviconURL(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(u).String(), nil
}

func faviconImageSize(data []byte) (int, int, error) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return 0, 0, err
	}
	return cfg.Width, cfg.Height, nil
}

func encodePNGFavicon(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func faviconDataURI(data []byte, format string) string {
	return "data:image/" + format + ";base64," + base64.StdEncoding.EncodeToString(data)
}

// dedupFaviconResults 按（宽,高）去重并按面积升序排列。
func dedupFaviconResults(icons []faviconResult) []faviconResult {
	seen := map[[2]int]bool{}
	out := make([]faviconResult, 0, len(icons))
	for _, ic := range icons {
		key := [2]int{ic.Width, ic.Height}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ic)
	}
	sort.Slice(out, func(i, j int) bool {
		ai, aj := out[i].Width*out[i].Height, out[j].Width*out[j].Height
		if ai != aj {
			return ai < aj
		}
		return out[i].Width < out[j].Width
	})
	return out
}

func isPNGBytes(b []byte) bool {
	return len(b) >= 8 && bytes.Equal(b[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
}

func isJPEGBytes(b []byte) bool {
	return len(b) >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff
}

func isICOBytes(b []byte) bool {
	// 保留字(2)=0，类型(2)=1(图标)
	return len(b) >= 6 && b[0] == 0 && b[1] == 0 && b[2] == 1 && b[3] == 0
}

func isDIBHeader(b []byte) bool {
	// ICO 内嵌 DIB 以 BITMAPINFOHEADER 开头（biSize==40）
	return len(b) >= 4 && binary.LittleEndian.Uint32(b[0:4]) == 40
}

func isSVGBytes(b []byte) bool {
	s := bytes.TrimLeft(b, " \t\r\n")
	return bytes.HasPrefix(s, []byte("<svg")) || bytes.HasPrefix(s, []byte("<?xml")) ||
		bytes.Contains(s[:min(len(s), 512)], []byte("<svg"))
}

// handleFaviconFetch 从目标地址获取网页图标（POST /api/desktop/favicon）。
func (s *Server) handleFaviconFetch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Addr string `json:"addr"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if strings.TrimSpace(req.Addr) == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少目标地址"))
		return
	}
	icons, warnings, err := fetchFavicons(req.Addr, req.Port)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"icons":    icons,
		"warnings": warnings,
	}))
}
