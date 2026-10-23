package web

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============= Web 服务：文件分享 =============
//
// 独立分享页：服务端渲染文件列表，支持常见格式预览与下载统计。
// 访问控制：提取码 / 有效期 / 总下载上限 / 每 IP 每日下载上限。
// 统计：总下载、流量、按文件下载次数、最近下载记录、近 7 天趋势（内存态）。

const wsShareMaxFiles = 2000

// wsShareSearchMax 搜索结果上限，避免一次返回过多卡片。
const wsShareSearchMax = 500

// wsShareIndexTTL 目录索引缓存时长：文件增删最多延迟一个周期生效。
const wsShareIndexTTL = 30 * time.Second

// 内容接口（/raw、/api/list、/api/search）的单 IP 限速。
// 禁止下载时，这是阻止批量抓取的唯一有效手段：
// 持续 120 次/分钟，突发 40 次（覆盖一屏图片缩略图并发加载）。
const (
	wsShareRatePerSec = 2
	wsShareRateBurst  = 40
)

// 页面在场证明：
// 分享页可见时由前端定时上报，换取短时在场凭证；内容接口只认这份凭证。
// 页面隐藏、切到后台或长时间无心跳后凭证自然过期，后续请求按未授权处理。
const (
	wsShareTicketTTL   = 12 * time.Hour
	wsSharePresenceTTL = 60 * time.Second
)

type webShareRuntime struct {
	mu        sync.Mutex
	views     int64
	downloads int64
	bytes     int64
	perFile   map[string]*webShareStat
	perIP     map[string]map[string]int
	visitors  map[string]struct{}
	daily     map[string]int64
	recent    []webShareEvent

	idxMu   sync.Mutex
	idx     *webShareIndex
	idxAt   time.Time
	idxRoot string

	limiter *wsRateLimiter
}

type webShareStat struct {
	Downloads int64  `json:"downloads"`
	Bytes     int64  `json:"bytes"`
	Last      string `json:"last,omitempty"`
}

type webShareEvent struct {
	Time  string `json:"time"`
	IP    string `json:"ip"`
	File  string `json:"file"`
	Bytes int64  `json:"bytes"`
	UA    string `json:"ua,omitempty"`
}

type webShareView struct {
	Views     int64                    `json:"views"`
	Downloads int64                    `json:"downloads"`
	Bytes     int64                    `json:"bytes"`
	Visitors  int                      `json:"visitors"`
	Files     map[string]*webShareStat `json:"files"`
	Daily     map[string]int64         `json:"daily"`
	Recent    []webShareEvent          `json:"recent"`
	LastTime  string                   `json:"last_time,omitempty"`
	LastFile  string                   `json:"last_file,omitempty"`
}

type webShareFile struct {
	Rel   string
	Name  string
	Size  int64
	MTime time.Time
	Type  string
}

// webShareIndex 分享目录索引：按目录保存直接子项与递归统计。
// 页面只在进入目录时取该层条目，因此不受文件总数限制。
type webShareIndex struct {
	Files  map[string][]webShareFile  // 目录 -> 直接文件
	Subs   map[string][]string        // 目录 -> 直接子目录路径
	Dirs   map[string]*wsShareDirNode // 目录 -> 递归统计
	Total  int                        // 全量文件数
	Size   int64                      // 全量大小
	Latest time.Time                  // 全量最新修改时间
}

// wsParentDir 返回相对路径的上级目录，根目录返回空串。
func wsParentDir(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return ""
}

// wsBuildShareIndex 一次遍历构建整棵目录索引，供按需加载与全量统计共用。
func wsBuildShareIndex(root string) (*webShareIndex, error) {
	idx := &webShareIndex{
		Files: map[string][]webShareFile{},
		Subs:  map[string][]string{},
		Dirs:  map[string]*wsShareDirNode{},
	}
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		name := filepath.Base(root)
		idx.Files[""] = []webShareFile{{
			Rel: name, Name: name, Size: st.Size(), MTime: st.ModTime(), Type: wsShareType(root),
		}}
		idx.Total, idx.Size, idx.Latest = 1, st.Size(), st.ModTime()
		return idx, nil
	}
	err = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		f := webShareFile{
			Rel: rel, Name: filepath.Base(p), Size: info.Size(), MTime: info.ModTime(), Type: wsShareType(p),
		}
		dir := wsParentDir(rel)
		idx.Files[dir] = append(idx.Files[dir], f)
		idx.Total++
		idx.Size += f.Size
		if f.MTime.After(idx.Latest) {
			idx.Latest = f.MTime
		}
		for d := dir; d != ""; d = wsParentDir(d) {
			n := idx.Dirs[d]
			if n == nil {
				n = &wsShareDirNode{Path: d, Name: filepath.Base(d), Parent: wsParentDir(d)}
				idx.Dirs[d] = n
				idx.Subs[n.Parent] = append(idx.Subs[n.Parent], d)
			}
			n.Files++
			n.Size += f.Size
			if f.MTime.After(n.MTime) {
				n.MTime = f.MTime
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for k, files := range idx.Files {
		sort.Slice(files, func(i, j int) bool { return files[i].MTime.After(files[j].MTime) })
		idx.Files[k] = files
	}
	for k := range idx.Subs {
		sort.Strings(idx.Subs[k])
	}
	return idx, nil
}

// index 返回缓存的目录索引，超过 TTL 后重建。
func (r *webShareRuntime) index(root string) (*webShareIndex, error) {
	r.idxMu.Lock()
	defer r.idxMu.Unlock()
	if r.idx != nil && r.idxRoot == root && time.Since(r.idxAt) < wsShareIndexTTL {
		return r.idx, nil
	}
	idx, err := wsBuildShareIndex(root)
	if err != nil {
		return nil, err
	}
	r.idx, r.idxAt, r.idxRoot = idx, time.Now(), root
	return idx, nil
}

// view 返回分享统计快照。
func (r *webShareRuntime) view() *webShareView {
	r.mu.Lock()
	defer r.mu.Unlock()
	files := make(map[string]*webShareStat, len(r.perFile))
	for k, v := range r.perFile {
		c := *v
		files[k] = &c
	}
	daily := make(map[string]int64, len(r.daily))
	for k, v := range r.daily {
		daily[k] = v
	}
	recent := append([]webShareEvent(nil), r.recent...)
	lastTime, lastFile := "", ""
	for k, v := range r.perFile {
		if v.Last > lastTime {
			lastTime, lastFile = v.Last, k
		}
	}
	return &webShareView{
		Views:     r.views,
		Downloads: r.downloads,
		Bytes:     r.bytes,
		Visitors:  len(r.visitors),
		Files:     files,
		Daily:     daily,
		Recent:    recent,
		LastTime:  lastTime,
		LastFile:  lastFile,
	}
}

// newShareHandler 构造文件分享处理器。
func (s *Server) newShareHandler(site WebSite, run *webSiteRun) http.Handler {
	rt := &webShareRuntime{
		perFile:  map[string]*webShareStat{},
		perIP:    map[string]map[string]int{},
		visitors: map[string]struct{}{},
		daily:    map[string]int64{},
	}
	run.share = rt
	rt.limiter = newWSRateLimiter(wsShareRatePerSec, wsShareRateBurst, 0)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := wsClientIP(r, site.Security.TrustedProxies)
		if wsShareBotUA(r.UserAgent()) {
			// 爬虫即使拿到 200（例如水印占位图），也要在安全事件里留痕。
			wsMarkCrawler(w)
		}
		deny := func(msg string) {
			// 禁止下载时的直接下载尝试计入安全失败次数，达到阈值后按站点配置自动封禁。
			run.wsRecordAuthFail(ip, site.Security)
			http.Error(w, msg, http.StatusForbidden)
		}
		// 按 IP 限速：
		// - 禁止下载时，内容接口与目录接口是抓取入口，必须限速；
		// - 提取码提交始终限速，避免无限次爆破。
		// 超额同样计入失败次数，持续请求会触发自动封禁。
		needLimit := r.URL.Path == "/__unlock"
		if !needLimit && site.Share.DisableDownload {
			switch r.URL.Path {
			case "/raw", "/api/list", "/api/search", "/api/meta":
				needLimit = true
			}
		}
		if needLimit {
			if _, ok := rt.limiter.allow(ip); !ok {
				run.wsRecordAuthFail(ip, site.Security)
				w.Header().Set("Retry-After", "1")
				http.Error(w, "请求过于频繁，请稍后再试", http.StatusTooManyRequests)
				return
			}
		}
		// 提取码提交
		if r.URL.Path == "/__unlock" && r.Method == http.MethodPost {
			_ = r.ParseForm()
			code := strings.TrimSpace(r.PostFormValue("code"))
			if subtle.ConstantTimeCompare([]byte(code), []byte(strings.TrimSpace(site.Share.AccessCode))) == 1 {
				wsSetShareCodeCookie(w, site, r)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			// 提取码错误与下载受限同样计入失败次数，避免无限次爆破。
			run.wsRecordAuthFail(ip, site.Security)
			wsRenderShareGate(w, site, "提取码错误，请重试", http.StatusUnauthorized)
			return
		}

		expired := wsShareExpired(site.Share)
		needCode := strings.TrimSpace(site.Share.AccessCode) != "" && !wsShareCodeOK(site, r)

		// 页面在场证明：分享页可见时由前端定时换取短时凭证。
		if r.URL.Path == "/__presence" && r.Method == http.MethodPost {
			if expired {
				http.Error(w, "分享已过期", http.StatusGone)
				return
			}
			if needCode {
				http.Error(w, "需要提取码", http.StatusUnauthorized)
				return
			}
			s.wsSharePresenceSubmit(w, r, site)
			return
		}
		// 禁止下载时，内容接口必须有有效的在场凭证：
		// 未打开分享页、页面隐藏或长期无心跳的请求，图片返回带水印的 403，其余一律 403。
		if !expired && !needCode && site.Share.DisableDownload {
			content := r.URL.Path == "/api/list" || r.URL.Path == "/api/search" || r.URL.Path == "/api/meta" ||
				(r.URL.Path == "/raw" && site.Share.Preview)
			if content {
				ok, devtools := wsSharePresenceOK(site, r)
				if !ok {
					run.wsRecordAuthFail(ip, site.Security)
					if r.URL.Path == "/raw" && wsShareType(r.URL.Query().Get("path")) == "image" {
						wsSetShareNoStore(w)
						w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write(wsShareDeniedSVG(site, r, "未检测到分享页，已拦截"))
						return
					}
					http.Error(w, "请从分享页正常浏览", http.StatusForbidden)
					return
				}
				// 控制台打开：图片与 PDF 走水印，其余内容禁止查看。
				kind := wsShareType(r.URL.Query().Get("path"))
				if devtools && r.URL.Path == "/raw" && kind != "image" && kind != "pdf" {
					run.wsRecordAuthFail(ip, site.Security)
					http.Error(w, "控制台已打开，禁止查看该文件", http.StatusForbidden)
					return
				}
			}
		}

		switch {
		case r.URL.Path == "/api/list" || r.URL.Path == "/api/search":
			if expired {
				http.Error(w, "分享已过期", http.StatusGone)
				return
			}
			if needCode {
				http.Error(w, "需要提取码", http.StatusUnauthorized)
				return
			}
			if site.Share.DisableDownload && !wsSharePreviewAllowed(r, site) {
				deny("请从分享页查看")
				return
			}
			s.wsShareAPI(w, r, site, rt)
			return
		case r.URL.Path == "/api/meta":
			if !site.Share.Preview {
				http.NotFound(w, r)
				return
			}
			if expired {
				http.Error(w, "分享已过期", http.StatusGone)
				return
			}
			if needCode {
				http.Error(w, "需要提取码", http.StatusUnauthorized)
				return
			}
			if site.Share.DisableDownload && !wsSharePreviewAllowed(r, site) {
				deny("请从分享页查看")
				return
			}
			wsShareMediaMeta(w, r, site)
			return
		case r.URL.Path == "/dl":
			if expired {
				http.Error(w, "分享已过期", http.StatusGone)
				return
			}
			if needCode {
				http.Error(w, "需要提取码", http.StatusUnauthorized)
				return
			}
			if site.Share.DisableDownload {
				deny("该分享仅允许在线查看，未开放下载")
				return
			}
			s.wsShareDownload(w, r, site, run, false)
			return
		case r.URL.Path == "/raw":
			if !site.Share.Preview {
				http.NotFound(w, r)
				return
			}
			if expired {
				http.Error(w, "分享已过期", http.StatusGone)
				return
			}
			if needCode {
				http.Error(w, "需要提取码", http.StatusUnauthorized)
				return
			}
			if site.Share.DisableDownload {
				// 禁止下载时，/raw 只接受分享页发起的预览请求：
				// 1) 同源页面发起的 img / video / iframe / fetch 会带 Sec-Fetch-Site: same-origin；
				// 2) 旧内核可能不带 Fetch Metadata，退回查看 Cookie 或分享页 Referer。
				if !wsSharePreviewAllowed(r, site) {
					run.wsRecordAuthFail(ip, site.Security)
					// 图片请求返回带水印的占位图，让爬虫抓到的是“检测到爬虫访问”的图，而不是原图。
					if wsShareType(r.URL.Query().Get("path")) == "image" {
						wsServeShareWatermarkSVG(w, wsShareDeniedSVG(site, r, "检测到非浏览器 / 爬虫访问"))
						return
					}
					http.Error(w, "请从分享页在线查看", http.StatusForbidden)
					return
				}
			}
			s.wsShareDownload(w, r, site, run, true)
			return
		case r.URL.Path == "/pkg":
			if site.Share.DisableDownload {
				deny("该分享仅允许在线查看，未开放下载")
				return
			}
			if !site.Share.PackageDownload {
				http.NotFound(w, r)
				return
			}
			if expired {
				http.Error(w, "分享已过期", http.StatusGone)
				return
			}
			if needCode {
				http.Error(w, "需要提取码", http.StatusUnauthorized)
				return
			}
			s.wsSharePackage(w, r, site, run)
			return
		}

		// 页面：/ 或 /s/{slug}
		if r.URL.Path != "/" && !wsSharePagePath(site, r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		if expired {
			wsRenderShareExpired(w, site)
			return
		}
		if needCode {
			wsRenderShareGate(w, site, "", http.StatusOK)
			return
		}
		idx, err := rt.index(site.Root)
		if err != nil {
			http.Error(w, "读取分享目录失败", http.StatusInternalServerError)
			return
		}
		if site.Share.DisableDownload {
			wsShareViewSetCookie(w, r, site)
		}
		wsRenderSharePage(w, r, site, rt, idx)
	})
}

// wsShareAPIResp 目录/搜索接口响应：服务端渲染好的卡片片段与计数。
type wsShareAPIResp struct {
	HTML      string `json:"html"`
	Films     string `json:"films"`
	Dir       string `json:"dir"`
	Count     int    `json:"count"`
	Truncated bool   `json:"truncated,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	Total     int    `json:"total"`
	SizeText  string `json:"sizeText"`
}

// wsShareAPI 按目录或关键词返回卡片片段，页面不再一次性下发全部文件。
func (s *Server) wsShareAPI(w http.ResponseWriter, r *http.Request, site WebSite, run *webShareRuntime) {
	idx, err := run.index(site.Root)
	if err != nil {
		http.Error(w, "读取分享目录失败", http.StatusInternalServerError)
		return
	}
	resp := wsShareAPIResp{Total: idx.Total, SizeText: wsFmtSize(idx.Size)}
	if r.URL.Path == "/api/search" {
		q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		var matched []webShareFile
		if q != "" {
			for _, files := range idx.Files {
				for _, f := range files {
					if strings.Contains(strings.ToLower(f.Name), q) {
						matched = append(matched, f)
					}
				}
			}
		}
		sort.Slice(matched, func(i, j int) bool { return matched[i].MTime.After(matched[j].MTime) })
		if len(matched) > wsShareSearchMax {
			matched = matched[:wsShareSearchMax]
			resp.Truncated = true
			resp.Limit = wsShareSearchMax
		}
		resp.HTML, resp.Films = wsRenderShareTiles(site, run, matched, nil)
		resp.Count = len(matched)
	} else {
		dir := strings.Trim(r.URL.Query().Get("dir"), "/")
		subs := idx.Subs[dir]
		dirs := make([]wsShareDirNode, 0, len(subs))
		for _, p := range subs {
			if n := idx.Dirs[p]; n != nil {
				dirs = append(dirs, *n)
			}
		}
		resp.Dir = dir
		resp.HTML, resp.Films = wsRenderShareTiles(site, run, idx.Files[dir], dirs)
		resp.Count = len(idx.Files[dir]) + len(dirs)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

// wsShareMetaResp 预览信息栏使用的媒体元信息。
type wsShareMetaResp struct {
	Width      int     `json:"width,omitempty"`
	Height     int     `json:"height,omitempty"`
	Duration   float64 `json:"duration,omitempty"`
	FPS        string  `json:"fps,omitempty"`
	Codec      string  `json:"codec,omitempty"`
	Bitrate    int64   `json:"bitrate,omitempty"`
	SampleRate int     `json:"sampleRate,omitempty"`
}

// wsMediaMetaCache 缓存 ffprobe 结果，键包含文件大小与修改时间，文件变动后自动失效。
var wsMediaMetaCache = struct {
	sync.Mutex
	items map[string]wsShareMetaResp
}{items: map[string]wsShareMetaResp{}}

// wsShareMediaMeta 返回视频/音频的分辨率、时长、帧率、编码等元信息。
func wsShareMediaMeta(w http.ResponseWriter, r *http.Request, site WebSite) {
	rel := r.URL.Query().Get("path")
	kind := wsShareType(rel)
	if kind != "video" && kind != "audio" {
		http.NotFound(w, r)
		return
	}
	full, ok := wsResolveSharePath(site.Root, rel)
	if !ok {
		http.NotFound(w, r)
		return
	}
	st, err := os.Stat(full)
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(wsProbeMediaMeta(full, st))
}

func wsProbeMediaMeta(full string, st os.FileInfo) wsShareMetaResp {
	key := full + "|" + strconv.FormatInt(st.Size(), 10) + "|" + strconv.FormatInt(st.ModTime().Unix(), 10)
	wsMediaMetaCache.Lock()
	m, hit := wsMediaMetaCache.items[key]
	wsMediaMetaCache.Unlock()
	if hit {
		return m
	}
	m = wsRunFFProbe(full)
	wsMediaMetaCache.Lock()
	if len(wsMediaMetaCache.items) >= 512 {
		wsMediaMetaCache.items = map[string]wsShareMetaResp{}
	}
	wsMediaMetaCache.items[key] = m
	wsMediaMetaCache.Unlock()
	return m
}

// wsRunFFProbe 调用 ffprobe 读取首个视频/音频流的信息；未安装 ffprobe 时返回空结果。
func wsRunFFProbe(full string) wsShareMetaResp {
	var out wsShareMetaResp
	bin, err := exec.LookPath("ffprobe")
	if err != nil {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"-v", "error", "-print_format", "json",
		"-show_entries", "stream=codec_type,codec_name,width,height,avg_frame_rate,sample_rate,bit_rate",
		"-show_entries", "format=duration,bit_rate",
		full)
	data, err := cmd.Output()
	if err != nil {
		return out
	}
	var raw struct {
		Streams []struct {
			CodecType    string `json:"codec_type"`
			CodecName    string `json:"codec_name"`
			Width        int    `json:"width"`
			Height       int    `json:"height"`
			AvgFrameRate string `json:"avg_frame_rate"`
			SampleRate   string `json:"sample_rate"`
			BitRate      string `json:"bit_rate"`
		} `json:"streams"`
		Format struct {
			Duration string `json:"duration"`
			BitRate  string `json:"bit_rate"`
		} `json:"format"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return out
	}
	// 视频与音频编码分开收集：视频文件可能同时带音轨，编码应优先展示视频流。
	var audioCodec string
	var audioRate int
	var audioBitrate int64
	for _, st := range raw.Streams {
		switch st.CodecType {
		case "video":
			if out.Width == 0 {
				out.Width, out.Height = st.Width, st.Height
				out.FPS = wsFormatFPS(st.AvgFrameRate)
				out.Codec = st.CodecName
			}
		case "audio":
			if audioCodec == "" {
				audioCodec = st.CodecName
				audioRate, _ = strconv.Atoi(st.SampleRate)
				audioBitrate, _ = strconv.ParseInt(st.BitRate, 10, 64)
			}
		}
	}
	if out.Codec == "" {
		out.Codec, out.SampleRate, out.Bitrate = audioCodec, audioRate, audioBitrate
	}
	out.Duration, _ = strconv.ParseFloat(raw.Format.Duration, 64)
	if out.Bitrate == 0 {
		out.Bitrate, _ = strconv.ParseInt(raw.Format.BitRate, 10, 64)
	}
	return out
}

// wsFormatFPS 把 ffprobe 的 "30000/1001" 形式帧率转成两位小数的可读值。
func wsFormatFPS(s string) string {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return ""
	}
	num, err1 := strconv.ParseFloat(parts[0], 64)
	den, err2 := strconv.ParseFloat(parts[1], 64)
	if err1 != nil || err2 != nil || num <= 0 || den <= 0 {
		return ""
	}
	return strconv.FormatFloat(math.Round(num/den*100)/100, 'f', -1, 64)
}

// wsShareBase 返回分享页在站内引用资源时需要带的前缀。
// 端口模式直接挂在根路径；路径（域名）模式挂在 /s/{slug} 下，站内地址必须带上该前缀。
func wsShareBase(site WebSite) string {
	if site.AccessMode == "path" && site.PathPrefix != "" {
		return site.PathPrefix
	}
	return ""
}

func wsSharePagePath(site WebSite, p string) bool {
	slug := strings.Trim(site.Share.Slug, "/")
	if slug == "" {
		return false
	}
	return p == "/s/"+slug || p == "/s/"+slug+"/"
}

func wsShareExpired(cfg WebShareConfig) bool {
	if strings.TrimSpace(cfg.ExpiresAt) == "" {
		return false
	}
	t, err := parseWebTime(cfg.ExpiresAt)
	return err == nil && time.Now().After(t)
}

func wsShareCodeCookieName(siteID string) string { return "tunhook_share_code_" + siteID }

// wsShareCodeTTL 提取码通过后的凭证有效期。
const wsShareCodeTTL = 24 * time.Hour

// wsShareCodeSig 生成提取码凭证签名：绑定站点、提取码、IP、UA 与有效期。
// 任一维度变化（换 IP、换 UA、提取码被修改、过期）都会导致凭证失效。
func wsShareCodeSig(siteID, code, ip, ua string, exp int64) string {
	mac := hmac.New(sha256.New, wsCookieKey)
	_, _ = mac.Write([]byte("share-code|" + siteID + "|" + strings.TrimSpace(code) + "|" + ip + "|" + ua + "|" + strconv.FormatInt(exp, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func wsSetShareCodeCookie(w http.ResponseWriter, site WebSite, r *http.Request) {
	exp := time.Now().Add(wsShareCodeTTL).Unix()
	value := strconv.FormatInt(exp, 10) + "." + wsShareCodeSig(site.ID, site.Share.AccessCode, wsClientIP(r, site.Security.TrustedProxies), r.UserAgent(), exp)
	http.SetCookie(w, &http.Cookie{
		Name:     wsShareCodeCookieName(site.ID),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(wsShareCodeTTL / time.Second),
	})
}

func wsShareCodeOK(site WebSite, r *http.Request) bool {
	c, err := r.Cookie(wsShareCodeCookieName(site.ID))
	if err != nil {
		return false
	}
	expStr, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	want := wsShareCodeSig(site.ID, site.Share.AccessCode, wsClientIP(r, site.Security.TrustedProxies), r.UserAgent(), exp)
	return hmac.Equal([]byte(sig), []byte(want))
}

// ============= 页面在场证明 =============
//
// 分享页渲染时下发短时票据；页面可见时由前端上报票据换取 60 秒在场凭证。
// 内容接口只认在场凭证：未打开页面、页面隐藏或长期无心跳的请求一律视为未授权。
// 这只是提高抓取成本的威慑，不是身份认证：能读取页面并伪造上报的脚本仍可拿到凭证。

func wsSharePresenceCookieName(siteID string) string { return "tunhook_share_presence_" + siteID }

// wsSharePageTicket 生成页面票据（有效期 12 小时），绑定站点、提取码、IP 与 UA。
// 票据只用于换取短时在场凭证，本身不代表内容访问权限。
func wsSharePageTicket(site WebSite, r *http.Request) string {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return ""
	}
	payload := strconv.FormatInt(time.Now().Add(wsShareTicketTTL).Unix(), 10) + "." + hex.EncodeToString(nonce)
	ip := wsClientIP(r, site.Security.TrustedProxies)
	return payload + "." + wsShareTicketSig(site.ID, site.Share.AccessCode, ip, r.UserAgent(), payload)
}

func wsShareTicketSig(siteID, accessCode, ip, ua, payload string) string {
	mac := hmac.New(sha256.New, wsCookieKey)
	_, _ = mac.Write([]byte("share-ticket|" + siteID + "|" + strings.TrimSpace(accessCode) + "|" + ip + "|" + ua + "|" + payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func wsShareTicketOK(site WebSite, r *http.Request, ticket string) bool {
	parts := strings.Split(ticket, ".")
	if len(parts) != 3 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	payload := parts[0] + "." + parts[1]
	ip := wsClientIP(r, site.Security.TrustedProxies)
	return hmac.Equal([]byte(parts[2]), []byte(wsShareTicketSig(site.ID, site.Share.AccessCode, ip, r.UserAgent(), payload)))
}

func wsSharePresenceSig(siteID, ip, ua string, exp int64, devtools bool) string {
	flag := "0"
	if devtools {
		flag = "1"
	}
	mac := hmac.New(sha256.New, wsCookieKey)
	_, _ = mac.Write([]byte("share-presence|" + siteID + "|" + ip + "|" + ua + "|" + strconv.FormatInt(exp, 10) + "|" + flag))
	return hex.EncodeToString(mac.Sum(nil))
}

func wsSetSharePresenceCookie(w http.ResponseWriter, site WebSite, r *http.Request, devtools bool) {
	exp := time.Now().Add(wsSharePresenceTTL).Unix()
	flag := "0"
	if devtools {
		flag = "1"
	}
	value := strconv.FormatInt(exp, 10) + "." + flag + "." + wsSharePresenceSig(site.ID, wsClientIP(r, site.Security.TrustedProxies), r.UserAgent(), exp, devtools)
	http.SetCookie(w, &http.Cookie{
		Name:     wsSharePresenceCookieName(site.ID),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(wsSharePresenceTTL / time.Second),
	})
}

// wsSharePresenceOK 校验在场凭证，同时返回该凭证是否标记了「控制台已打开」。
func wsSharePresenceOK(site WebSite, r *http.Request) (bool, bool) {
	c, err := r.Cookie(wsSharePresenceCookieName(site.ID))
	if err != nil {
		return false, false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return false, false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false, false
	}
	devtools := parts[1] == "1"
	want := wsSharePresenceSig(site.ID, wsClientIP(r, site.Security.TrustedProxies), r.UserAgent(), exp, devtools)
	return hmac.Equal([]byte(parts[2]), []byte(want)), devtools
}

// wsSharePresenceSubmit 处理分享页的在场上报：页面可见且屏幕尺寸正常才签发短时凭证。
func (s *Server) wsSharePresenceSubmit(w http.ResponseWriter, r *http.Request, site WebSite) {
	_ = r.ParseForm()
	if !wsShareTicketOK(site, r, r.FormValue("ticket")) {
		http.Error(w, "页面凭证无效，请刷新分享页", http.StatusForbidden)
		return
	}
	if r.FormValue("visible") != "1" {
		http.Error(w, "页面不可见", http.StatusForbidden)
		return
	}
	sw, _ := strconv.Atoi(r.FormValue("sw"))
	sh, _ := strconv.Atoi(r.FormValue("sh"))
	if sw <= 0 || sh <= 0 {
		http.Error(w, "屏幕信息无效", http.StatusForbidden)
		return
	}
	devtools := r.FormValue("devtools") == "1"
	wsSetSharePresenceCookie(w, site, r, devtools)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":       true,
		"ttl":      int(wsSharePresenceTTL / time.Second),
		"devtools": devtools,
	})
}

// ============= 禁止下载：预览访问凭证 =============
//
// 说明：浏览器必须取得文件字节才能显示内容，因此无法从技术上阻止用户通过开发者工具
// 保存已经加载的预览内容。这里的凭证用于阻止“未访问分享页、直接构造 /raw 链接”的
// 爬虫与脚本下载，并让禁止下载的尝试进入安全失败计数。

const wsShareViewTTL = 4 * time.Hour

func wsShareViewCookieName(siteID string) string { return "tunhook_share_view_" + siteID }

func wsShareViewSig(siteID, ip, ua string, exp int64) string {
	mac := hmac.New(sha256.New, wsCookieKey)
	_, _ = mac.Write([]byte("share-view|" + siteID + "|" + ip + "|" + ua + "|" + strconv.FormatInt(exp, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// wsShareViewSetCookie 在分享页渲染时下发短期查看凭证，绑定站点、IP 与 UA。
func wsShareViewSetCookie(w http.ResponseWriter, r *http.Request, site WebSite) {
	exp := time.Now().Add(wsShareViewTTL).Unix()
	http.SetCookie(w, &http.Cookie{
		Name:     wsShareViewCookieName(site.ID),
		Value:    strconv.FormatInt(exp, 10) + "." + wsShareViewSig(site.ID, wsClientIP(r, site.Security.TrustedProxies), r.UserAgent(), exp),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(wsShareViewTTL / time.Second),
	})
}

// wsShareViewOK 校验查看凭证；IP 或 UA 变化、凭证过期都会失败。
func wsShareViewOK(r *http.Request, site WebSite) bool {
	c, err := r.Cookie(wsShareViewCookieName(site.ID))
	if err != nil {
		return false
	}
	expStr, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	want := wsShareViewSig(site.ID, wsClientIP(r, site.Security.TrustedProxies), r.UserAgent(), exp)
	return hmac.Equal([]byte(sig), []byte(want))
}

// wsSharePreviewAllowed 判断请求是否来自分享页本身。
// 同源 Fetch Metadata 最可靠；旧内核不发送时退回查看 Cookie，
// 最后用 Referer 兜底，避免内嵌预览窗口或 fetch 不带 Cookie 时被误杀。
func wsSharePreviewAllowed(r *http.Request, site WebSite) bool {
	if r.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return true
	}
	if wsShareViewOK(r, site) {
		return true
	}
	ref := r.Header.Get("Referer")
	if ref == "" {
		return false
	}
	u, err := url.Parse(ref)
	if err != nil || !strings.EqualFold(u.Host, r.Host) {
		return false
	}
	return u.Path == "/" || wsSharePagePath(site, u.Path)
}

// wsResolveSharePath 把分享内的相对路径解析为真实路径，并阻止目录穿越与符号链接逃逸。
func wsResolveSharePath(root, rel string) (string, bool) {
	root = filepath.Clean(root)
	st, err := os.Stat(root)
	if err != nil {
		return "", false
	}
	// 以根目录的真实路径为基准，后续所有命中都必须落在该目录内。
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	if !st.IsDir() {
		if rel == "" || rel == "/" || filepath.Base(rel) == filepath.Base(root) {
			return realRoot, true
		}
		return "", false
	}
	clean := filepath.Clean("/" + rel)
	full := filepath.Join(realRoot, filepath.FromSlash(clean))
	if full != realRoot && !strings.HasPrefix(full, realRoot+string(filepath.Separator)) {
		return "", false
	}
	// 符号链接可以指向根目录之外，必须按真实路径再校验一次。
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", false
	}
	if real != realRoot && !strings.HasPrefix(real, realRoot+string(filepath.Separator)) {
		return "", false
	}
	return real, true
}

// wsShareDownload 处理下载 / 内联预览。
func (s *Server) wsShareDownload(w http.ResponseWriter, r *http.Request, site WebSite, run *webSiteRun, inline bool) {
	rel := r.URL.Query().Get("path")
	full, ok := wsResolveSharePath(site.Root, rel)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// 禁止下载时，raw 只服务于在线预览；压缩包 / Office 等不可预览格式直接拒绝
	if inline && site.Share.DisableDownload && !wsSharePreviewable(rel) {
		run.wsRecordAuthFail(wsClientIP(r, site.Security.TrustedProxies), site.Security)
		http.Error(w, "该格式不支持在线查看，且该分享未开放下载", http.StatusForbidden)
		return
	}
	st, err := os.Stat(full)
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	if !inline {
		if !run.share.allowDownload(site, wsClientIP(r, site.Security.TrustedProxies), rel, st.Size()) {
			http.Error(w, "已达到下载限制", http.StatusTooManyRequests)
			return
		}
	}
	name := filepath.Base(full)
	// 仅在线查看时，以下请求返回带水印内容：
	// - 未通过浏览器特征校验（脚本 / 爬虫）；
	// - 在场凭证标记了「控制台已打开」。
	_, wmDevtools := wsSharePresenceOK(site, r)
	wmOn := inline && site.Share.DisableDownload && (wmDevtools || !wsShareBrowserRequest(r))
	if wmOn {
		switch wsShareType(name) {
		case "image":
			wmLines := wsWatermarkLines(site, r)
			if body, ok := wsShareWatermarkImage(full, wmLines); ok {
				wsSetShareNoStore(w)
				w.Header().Set("Content-Disposition", `inline; filename="`+strings.ReplaceAll(name, `"`, "")+`"`)
				w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
				_, _ = w.Write(body)
				return
			}
			// SVG / WebP 等无法用标准库解码的格式，退化为固定画布包装。
			if body, ok := wsShareWatermarkRawImage(full, wsImageMime(name), wmLines); ok {
				wsSetShareNoStore(w)
				w.Header().Set("Content-Disposition", `inline; filename="`+strings.ReplaceAll(name, `"`, "")+`"`)
				w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
				_, _ = w.Write(body)
				return
			}
		case "text":
			if body, ok := wsShareWatermarkTextFile(full, wsWatermarkText(site, r)); ok {
				wsSetShareNoStore(w)
				w.Header().Set("Content-Disposition", `inline; filename="`+strings.ReplaceAll(name, `"`, "")+`"`)
				ct := mime.TypeByExtension(filepath.Ext(name))
				if ct == "" {
					ct = "text/plain; charset=utf-8"
				}
				w.Header().Set("Content-Type", ct)
				_, _ = w.Write(body)
				return
			}
		case "pdf":
			if !wmDevtools {
				wsServeWatermarkedPDF(w, site, r, rel)
				return
			}
			// 开发者工具打开时由前端叠加菱形水印，这里直接返回 PDF 内容。
		}
	}
	f, err := os.Open(full)
	if err != nil {
		http.Error(w, "文件不可读", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	if !inline {
		w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(name, `"`, "")+`"`)
	} else if site.Share.DisableDownload {
		// 仅在线查看：禁止浏览器缓存预览内容，并显式声明 inline。
		w.Header().Set("Content-Disposition", `inline; filename="`+strings.ReplaceAll(name, `"`, "")+`"`)
		wsSetShareNoStore(w)
	}
	if ct := mime.TypeByExtension(filepath.Ext(name)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	http.ServeContent(w, r, name, st.ModTime(), f)
}

// wsSharePackage 打包下载整个分享目录。
func (s *Server) wsSharePackage(w http.ResponseWriter, r *http.Request, site WebSite, run *webSiteRun) {
	files, err := wsListShareFiles(site.Root)
	if err != nil {
		http.Error(w, "读取分享目录失败", http.StatusInternalServerError)
		return
	}
	if !run.share.allowPackage(site, wsClientIP(r, site.Security.TrustedProxies)) {
		http.Error(w, "已达到下载限制", http.StatusTooManyRequests)
		return
	}
	title := site.Name
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(title, `"`, "")+`.zip"`)
	zw := zip.NewWriter(w)
	defer zw.Close()
	for _, f := range files {
		full, ok := wsResolveSharePath(site.Root, f.Rel)
		if !ok {
			continue
		}
		src, err := os.Open(full)
		if err != nil {
			continue
		}
		dst, err := zw.Create(f.Rel)
		if err == nil {
			_, _ = io.Copy(dst, src)
		}
		_ = src.Close()
	}
}

// allowDownload 检查总下载上限与每 IP 每日上限，并记录统计。
func (r *webShareRuntime) allowDownload(site WebSite, ip, rel string, size int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if site.Share.MaxDownloads > 0 && r.downloads >= int64(site.Share.MaxDownloads) {
		return false
	}
	day := time.Now().Format("2006-01-02")
	if site.Share.PerIPDaily > 0 {
		m := r.perIP[ip]
		if m == nil {
			m = map[string]int{}
			r.perIP[ip] = m
		}
		if m[day] >= site.Share.PerIPDaily {
			return false
		}
		m[day]++
	}
	r.downloads++
	r.bytes += size
	r.daily[day]++
	if ip != "" {
		r.visitors[ip] = struct{}{}
	}
	st := r.perFile[rel]
	if st == nil {
		st = &webShareStat{}
		r.perFile[rel] = st
	}
	st.Downloads++
	st.Bytes += size
	st.Last = time.Now().Format("2006-01-02 15:04:05")
	if site.Share.LogDownloads {
		r.recent = append([]webShareEvent{{
			Time: st.Last, IP: ip, File: rel, Bytes: size,
		}}, r.recent...)
		if len(r.recent) > 200 {
			r.recent = r.recent[:200]
		}
	}
	return true
}

func (r *webShareRuntime) allowPackage(site WebSite, ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if site.Share.MaxDownloads > 0 && r.downloads >= int64(site.Share.MaxDownloads) {
		return false
	}
	day := time.Now().Format("2006-01-02")
	if site.Share.PerIPDaily > 0 {
		m := r.perIP[ip]
		if m == nil {
			m = map[string]int{}
			r.perIP[ip] = m
		}
		if m[day] >= site.Share.PerIPDaily {
			return false
		}
		m[day]++
	}
	r.downloads++
	r.daily[day]++
	if ip != "" {
		r.visitors[ip] = struct{}{}
	}
	return true
}

// wsListShareFiles 递归列出分享目录中的文件。
func wsListShareFiles(root string) ([]webShareFile, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []webShareFile{{
			Rel: filepath.Base(root), Name: filepath.Base(root), Size: st.Size(), MTime: st.ModTime(), Type: wsShareType(root),
		}}, nil
	}
	out := make([]webShareFile, 0, 64)
	err = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		out = append(out, webShareFile{
			Rel: rel, Name: filepath.Base(p), Size: info.Size(), MTime: info.ModTime(), Type: wsShareType(p),
		})
		if len(out) >= wsShareMaxFiles {
			return fmt.Errorf("too many files")
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out, nil
}

func wsShareType(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".avif", ".bmp", ".ico":
		return "image"
	case ".mp4", ".webm", ".ogg", ".mov", ".m4v":
		return "video"
	case ".mp3", ".wav", ".flac", ".m4a", ".aac":
		return "audio"
	case ".pdf":
		return "pdf"
	case ".md", ".markdown", ".txt", ".log", ".json", ".xml", ".yaml", ".yml", ".csv",
		".js", ".ts", ".css", ".html", ".go", ".py", ".java", ".sh", ".ini", ".conf":
		return "text"
	case ".zip", ".rar", ".7z", ".tar", ".gz":
		return "archive"
	default:
		return "other"
	}
}

// wsSharePreviewable 判断该文件是否支持浏览器内在线查看。
func wsSharePreviewable(name string) bool {
	switch wsShareType(name) {
	case "image", "video", "audio", "pdf", "text":
		return true
	default:
		return false
	}
}

// render 辅助
func wsFmtSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func wsFileIcon(t string) string {
	switch t {
	case "image":
		return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9.5" r="1.5"/><path d="m21 15-5-5L5 20"/></svg>`
	case "video":
		return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m10 9 5 3-5 3z" fill="currentColor" stroke="none"/></svg>`
	case "audio":
		return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 18V6l10-2v12"/><circle cx="6" cy="18" r="3"/><circle cx="19" cy="16" r="3"/></svg>`
	case "pdf":
		return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M6 3h9l4 4v14H6z"/><path d="M9 13h6M9 17h6M9 9h3"/></svg>`
	case "text":
		return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M6 3h9l4 4v14H6z"/><path d="M9 12h7M9 16h7M9 8h3"/></svg>`
	case "archive":
		return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 7h16v14H4z"/><path d="M4 7l2-4h12l2 4M10 11h4"/></svg>`
	default:
		return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>`
	}
}

func wsRenderShareGate(w http.ResponseWriter, site WebSite, errMsg string, status int) {
	title := site.Name
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="err">` + html.EscapeString(errMsg) + `</div>`
	}
	page := `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + html.EscapeString(title) + `</title>
<style>:root{--bg:#070c12;--bg2:#0a1119;--bg3:#0d151f;--text:#e6eef8;--text3:#8094ab;--bd:#1e2c3a}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif}.gate{width:min(420px,calc(100vw - 32px));background:var(--bg3);border:1px solid var(--bd);border-radius:14px;padding:30px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5)}.ico{width:52px;height:52px;border-radius:14px;background:rgba(185,157,250,.1);color:#b99dfa;display:flex;align-items:center;justify-content:center;margin:0 auto 14px}h2{font-size:18px;margin:0}p{font-size:12px;color:var(--text3);margin:8px 0 18px}input{width:100%;height:42px;border:1px solid #4a6075;border-radius:8px;background:var(--bg2);color:var(--text);text-align:center;font-size:18px;letter-spacing:8px;outline:none}button{width:100%;height:40px;margin-top:10px;border:none;border-radius:8px;background:#0b7e9c;color:#fff;font-weight:600}.err{color:#f58d8d;font-size:11px;margin-top:10px}.tip{font-size:10px;color:var(--text3);margin-top:12px}</style></head>
<body><form class="gate" method="post" action="/__unlock"><div class="ico"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg></div><h2>此分享需要提取码</h2><p>请输入分享者提供的提取码后查看文件。</p><input name="code" autocomplete="off" autofocus maxlength="32">` + errHTML + `<button type="submit">查看文件</button><div class="tip">提取码由分享者提供</div></form></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(page))
}

func wsRenderShareExpired(w http.ResponseWriter, site WebSite) {
	title := site.Name
	page := `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + html.EscapeString(title) + `</title>
<style>:root{--bg:#070c12;--bg3:#0d151f;--text:#e6eef8;--text3:#8094ab;--bd:#1e2c3a}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif}.card{width:min(420px,calc(100vw - 32px));background:var(--bg3);border:1px solid var(--bd);border-radius:14px;padding:30px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5)}.ico{width:52px;height:52px;border-radius:14px;background:rgba(245,158,11,.1);color:#f59e0b;display:flex;align-items:center;justify-content:center;margin:0 auto 14px}h2{font-size:18px;margin:0}p{font-size:12px;color:var(--text3);margin:8px 0 0;line-height:1.7}</style></head>
<body><div class="card"><div class="ico"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></div><h2>分享已过期</h2><p>` + html.EscapeString(site.Share.ExpiresAt) + ` 到期，文件不再对外提供。<br>如需继续访问，请联系分享者重新创建分享。</p></div></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusGone)
	_, _ = w.Write([]byte(page))
}

// ============= 仅在线查看：水印 =============
//
// 水印不是访问控制，而是追溯与威慑：内容一旦被截图或保存，水印就会带上站点、
// 访客 IP、时间与检测状态。真正的边界仍然是服务端拒绝下载。

// wsShareBotUA 粗粒度识别脚本 / 爬虫 UA，用于把检测结果写进水印。
func wsShareBotUA(ua string) bool {
	s := strings.ToLower(strings.TrimSpace(ua))
	if s == "" {
		return true
	}
	for _, k := range []string{
		"bot", "spider", "crawl", "curl/", "wget", "python-requests", "python/",
		"scrapy", "httpclient", "okhttp", "go-http-client", "libwww", "headlesschrome",
		"phantomjs", "axios/", "node-fetch", "postmanruntime", "insomnia", "java/",
	} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// wsShareBrowserRequest 判断请求是否具备浏览器资源请求的典型特征。
// 仅用于决定是否加水印，不作为访问控制：
// 浏览器正常预览不加，脚本只有在同时伪造 UA、Accept 与 Fetch Metadata 时才能拿到干净内容。
func wsShareBrowserRequest(r *http.Request) bool {
	if wsShareBotUA(r.UserAgent()) {
		return false
	}
	if strings.TrimSpace(r.Header.Get("Accept")) == "" {
		return false
	}
	// 现代浏览器会带上整套 Sec-Fetch-*；旧内核缺失时退回 Accept-Language。
	if r.Header.Get("Sec-Fetch-Site") != "" &&
		r.Header.Get("Sec-Fetch-Mode") != "" &&
		r.Header.Get("Sec-Fetch-Dest") != "" {
		return true
	}
	return strings.TrimSpace(r.Header.Get("Accept-Language")) != ""
}

// wsWatermarkLines 生成菱形水印的三行文案：站点、访客 IP、时间。
func wsWatermarkLines(site WebSite, r *http.Request) []string {
	name := site.Name
	if rs := []rune(name); len(rs) > 9 {
		name = string(rs[:9]) + "…"
	}
	lines := []string{name}
	if ip := wsClientIP(r, site.Security.TrustedProxies); ip != "" {
		lines = append(lines, ip)
	}
	lines = append(lines, time.Now().Format("2006-01-02 15:04"))
	return lines
}

// wsWatermarkText 生成水印文案：站点 访客IP 时间（参考飞书水印，只保留追溯信息）。
func wsWatermarkText(site WebSite, r *http.Request) string {
	name := site.Name
	parts := []string{name}
	if ip := wsClientIP(r, site.Security.TrustedProxies); ip != "" {
		parts = append(parts, ip)
	}
	parts = append(parts, time.Now().Format("2006-01-02 15:04"))
	if !wsShareBrowserRequest(r) {
		parts = append(parts, "已记录")
	}
	return strings.Join(parts, " ")
}

func wsSetShareNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Referrer-Policy", "same-origin")
}

// wsShareTiledText 输出平铺旋转水印文字，供图片水印与占位图复用。
// 参考飞书水印：-20° 斜排、砖块式错位、固定密度，文字只做追溯。
func wsShareTiledText(b *strings.Builder, w, h, fs int, text, opacity string) {
	esc := html.EscapeString(text)
	stepX := w / 5
	if stepX < 260 {
		stepX = 260
	}
	stepY := h / 8
	if stepY < 110 {
		stepY = 110
	}
	b.WriteString(`<g fill="#ffffff" fill-opacity="` + opacity + `" font-family="'Segoe UI',system-ui,sans-serif" font-size="` + strconv.Itoa(fs) + `" font-weight="500">`)
	row := 0
	for y := stepY / 2; y < h+stepY; y += stepY {
		// 相邻行水平错开半格，形成飞书式的砖块错位
		offset := 0
		if row%2 == 1 {
			offset = stepX / 2
		}
		row++
		for x := -stepX/2 + offset; x < w+stepX; x += stepX {
			b.WriteString(`<text x="` + strconv.Itoa(x) + `" y="` + strconv.Itoa(y) + `" transform="rotate(-20 ` + strconv.Itoa(x) + ` ` + strconv.Itoa(y) + `)">` + esc + `</text>`)
		}
	}
	b.WriteString(`</g>`)
}

// wsShareDiamondText 绘制铺满画布的菱形网格水印，每个菱形内显示追溯信息。
func wsShareDiamondText(b *strings.Builder, w, h int, lines []string) {
	step := w / 6
	if step < 180 {
		step = 180
	}
	if step > 600 {
		step = 600
	}
	fs := step / 14
	if fs < 10 {
		fs = 10
	}
	if fs > 40 {
		fs = 40
	}
	side := float64(step-20) / math.Sqrt2
	half := side / 2
	b.WriteString(`<g stroke="#ff8e8e" stroke-opacity="0.3" fill="none">`)
	for cy := step / 2; cy < h+step; cy += step {
		for cx := step / 2; cx < w+step; cx += step {
			b.WriteString(`<g transform="translate(` + strconv.Itoa(cx) + ` ` + strconv.Itoa(cy) + `) rotate(45)"><rect x="` + wsFtoa(-half) + `" y="` + wsFtoa(-half) + `" width="` + wsFtoa(side) + `" height="` + wsFtoa(side) + `"/></g>`)
		}
	}
	b.WriteString(`</g>`)
	b.WriteString(`<g fill="#ff8e8e" fill-opacity="0.48" stroke="#000000" stroke-opacity="0.16" stroke-width="1" paint-order="stroke" text-anchor="middle" font-family="'Segoe UI',system-ui,sans-serif" font-size="` + strconv.Itoa(fs) + `">`)
	lineH := float64(fs) * 1.6
	start := -float64(len(lines)-1) * lineH / 2
	for cy := step / 2; cy < h+step; cy += step {
		for cx := step / 2; cx < w+step; cx += step {
			for i, l := range lines {
				y := float64(cy) + start + float64(i)*lineH + float64(fs)/3
				b.WriteString(`<text x="` + strconv.Itoa(cx) + `" y="` + wsFtoa(y) + `">` + html.EscapeString(l) + `</text>`)
			}
		}
	}
	b.WriteString(`</g>`)
}

func wsFtoa(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }

// wsShareWatermarkImage 把原图嵌入 SVG 并叠加菱形网格水印。
// 只处理标准库可解码的 PNG / JPEG / GIF；其它格式交给前端覆盖层。
func wsShareWatermarkImage(path string, lines []string) ([]byte, bool) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > 12<<20 {
		return nil, false
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, false
	}
	w, h := cfg.Width, cfg.Height
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="` + strconv.Itoa(w) + `" height="` + strconv.Itoa(h) + `" viewBox="0 0 ` + strconv.Itoa(w) + ` ` + strconv.Itoa(h) + `">`)
	b.WriteString(`<image href="data:image/` + format + `;base64,` + base64.StdEncoding.EncodeToString(data) + `" width="` + strconv.Itoa(w) + `" height="` + strconv.Itoa(h) + `" preserveAspectRatio="none"/>`)
	wsShareDiamondText(&b, w, h, lines)
	b.WriteString(`</svg>`)
	return []byte(b.String()), true
}

// wsImageMime 按扩展名返回图片 MIME，供无法解码的格式做数据 URI 包装。
func wsImageMime(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".svg":
		return "image/svg+xml"
	case ".webp":
		return "image/webp"
	case ".avif":
		return "image/avif"
	case ".bmp":
		return "image/bmp"
	case ".ico":
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}

// wsShareWatermarkRawImage 把无法解码的图片（SVG / WebP 等）嵌入固定画布并叠加平铺水印。
func wsShareWatermarkRawImage(path, mimeType string, lines []string) ([]byte, bool) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > 12<<20 {
		return nil, false
	}
	const w, h = 1200, 800
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="800" viewBox="0 0 1200 800">`)
	b.WriteString(`<rect width="1200" height="800" fill="#04070b"/>`)
	b.WriteString(`<image href="data:` + mimeType + `;base64,` + base64.StdEncoding.EncodeToString(data) + `" width="1200" height="800" preserveAspectRatio="xMidYMid meet"/>`)
	wsShareDiamondText(&b, w, h, lines)
	b.WriteString(`</svg>`)
	return []byte(b.String()), true
}

// wsShareWatermarkTextFile 在文本内容中周期插入水印行，让响应体本身可追溯。
func wsShareWatermarkTextFile(path, text string) ([]byte, bool) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 4<<20 {
		return nil, false
	}
	line := "【TunHook 水印】" + text
	lines := strings.Split(string(data), "\n")
	var b strings.Builder
	b.WriteString(line + "\n")
	for i, l := range lines {
		b.WriteString(l + "\n")
		if (i+1)%80 == 0 {
			b.WriteString(line + "\n")
		}
	}
	b.WriteString(line + "\n")
	return []byte(b.String()), true
}

// wsServeWatermarkedPDF 返回带水印覆盖层的 HTML 外壳，内部仍由浏览器 PDF 查看器渲染。
// PDF 本身未做内容重写（需要引入 PDF 处理库），这里保证外层响应带追踪水印。
func wsServeWatermarkedPDF(w http.ResponseWriter, site WebSite, r *http.Request, rel string) {
	inner := "/raw?path=" + url.QueryEscape(rel)
	text := wsWatermarkText(site, r)
	page := `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><style>
html,body{margin:0;height:100%;background:#04070b;overflow:hidden}
iframe{display:block;width:100%;height:100%;border:0;background:#fff}
#wm{position:fixed;inset:0;pointer-events:none;overflow:hidden}
#wm span{position:absolute;font:12px/1 'Segoe UI',system-ui,sans-serif;color:rgba(230,238,248,.16);white-space:nowrap;transform:rotate(-20deg);transform-origin:left top}
</style></head><body>
<iframe src="` + html.EscapeString(inner) + `"></iframe>
<div id="wm"></div>
<script>
(function(){
  var T=` + strconv.Quote(text) + `,box=document.getElementById('wm');
  function fill(){
    var w=window.innerWidth||1200,h=window.innerHeight||800;
    var sx=Math.max(260,Math.min(420,Math.round(w/5))),sy=Math.max(120,Math.min(180,Math.round(h/8))),out='';
    var t=T.replace(/[&<>]/g,function(c){return c==='&'?'&amp;':c==='<'?'&lt;':'&gt;';});
    var row=0;
    for(var y=Math.round(sy/2);y<h+sy;y+=sy){
      var offset=(row++%2)?Math.round(sx/2):0;
      for(var x=-Math.round(sx/2)+offset;x<w+sx;x+=sx){
        out+='<span style="left:'+x+'px;top:'+y+'px">'+t+'</span>';
      }
    }
    box.innerHTML=out;
  }
  fill();window.addEventListener('resize',fill);
})();
</script></body></html>`
	wsSetShareNoStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}

// wsShareDeniedSVG 生成带水印的拒绝占位图：爬虫拿到的是追踪信息，不是原图。
func wsShareDeniedSVG(site WebSite, r *http.Request, reason string) []byte {
	const w, h = 1200, 800
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="800" viewBox="0 0 1200 800">`)
	b.WriteString(`<rect width="1200" height="800" fill="#0a1119"/>`)
	b.WriteString(`<rect x="1" y="1" width="1198" height="798" fill="none" stroke="#1e2c3a" stroke-width="2"/>`)
	wsShareTiledText(&b, w, h, 14, wsWatermarkText(site, r), "0.14")
	b.WriteString(`<g text-anchor="middle" font-family="'Segoe UI',system-ui,sans-serif">`)
	b.WriteString(`<text x="600" y="368" fill="#e6eef8" font-size="40" font-weight="700">仅供在线查看</text>`)
	b.WriteString(`<text x="600" y="416" fill="#f58d8d" font-size="22">` + html.EscapeString(reason) + `</text>`)
	b.WriteString(`<text x="600" y="456" fill="#8094ab" font-size="17">该图片未对未授权访问提供，访问信息已记录</text>`)
	b.WriteString(`</g></svg>`)
	return []byte(b.String())
}

func wsServeShareWatermarkSVG(w http.ResponseWriter, body []byte) {
	wsSetShareNoStore(w)
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	_, _ = w.Write(body)
}
