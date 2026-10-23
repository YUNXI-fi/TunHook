package web

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestParseFaviconLinks(t *testing.T) {
	html := `<html><head>
<link rel="icon" href="/favicon.ico">
<link rel="shortcut icon" href='icon.png' />
<link rel="apple-touch-icon" sizes="180x180" href="/apple.png">
<link rel="stylesheet" href="/style.css">
<link rel="mask-icon" href="safari.svg" color="red">
</head></html>`
	got := parseFaviconLinks(html)
	want := []string{"/favicon.ico", "icon.png", "/apple.png", "safari.svg"}
	if len(got) != len(want) {
		t.Fatalf("解析 link 数量不对，实际: %v", got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("第 %d 个 href = %q，期望 %q", i, got[i], w)
		}
	}
}

func TestParseFaviconPNG(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	for i := 0; i < 32; i++ {
		for j := 0; j < 32; j++ {
			img.SetRGBA(i, j, color.RGBA{R: 200, G: 30, B: 30, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	res, err := parseFaviconData(buf.Bytes(), "test.png")
	if err != nil || len(res) != 1 {
		t.Fatalf("PNG 解析失败: %v %v", res, err)
	}
	if res[0].Width != 32 || res[0].Height != 32 || res[0].Format != "png" {
		t.Errorf("PNG 尺寸/格式错误: %+v", res[0])
	}
	if !strings.HasPrefix(res[0].Data, "data:image/png;base64,") {
		t.Errorf("data URI 格式错误: %.40s", res[0].Data)
	}
}

func TestParseFaviconICO(t *testing.T) {
	// 构造 16×16 PNG 并打包为单条目 ICO（PNG 内嵌）
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			img.SetRGBA(i, j, color.RGBA{R: 10, G: 90, B: 200, A: 255})
		}
	}
	var pngData bytes.Buffer
	if err := png.Encode(&pngData, img); err != nil {
		t.Fatal(err)
	}
	ico := buildTestICO(pngData.Bytes())
	if !isICOBytes(ico) {
		t.Fatal("isICOBytes 未识别 ICO")
	}
	res, err := parseICOFavicon(ico, "test.ico")
	if err != nil || len(res) != 1 {
		t.Fatalf("ICO 解析失败: %v %v", res, err)
	}
	if res[0].Width != 16 || res[0].Height != 16 || res[0].Format != "png" {
		t.Errorf("ICO 尺寸/格式错误: %+v", res[0])
	}
}

func TestDecodeDIBFavicon(t *testing.T) {
	// 2×2 32bpp DIB，高度含 AND 掩码（4）
	w, h := 2, 4
	rowLen := w * 4
	data := make([]byte, 40+rowLen*h)
	binary.LittleEndian.PutUint32(data[0:4], 40)
	binary.LittleEndian.PutUint32(data[4:8], uint32(w))
	binary.LittleEndian.PutUint32(data[8:12], uint32(h))
	binary.LittleEndian.PutUint16(data[14:16], 32)
	// 颜色行自下而上：内存首行（40）为底行 y=1（蓝），次行（48）为顶行 y=0（红）。
	// 32bpp 内存顺序为 BGRA：蓝 = [B=255,G=0,R=0,A=255]，红 = [B=0,G=0,R=255,A=255]
	row0 := 40
	data[row0+0], data[row0+1], data[row0+2], data[row0+3] = 255, 0, 0, 255 // 蓝
	data[row0+4], data[row0+5], data[row0+6], data[row0+7] = 255, 0, 0, 255 // 蓝
	row1 := 40 + rowLen
	data[row1+0], data[row1+1], data[row1+2], data[row1+3] = 0, 0, 255, 255 // 红
	data[row1+4], data[row1+5], data[row1+6], data[row1+7] = 0, 0, 255, 255 // 红
	img, err := decodeDIBFavicon(data)
	if err != nil {
		t.Fatalf("DIB 解码失败: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 2 || b.Dy() != 2 {
		t.Fatalf("DIB 尺寸错误: %v", img.Bounds())
	}
	cr, cg, cb, _ := img.At(0, 0).RGBA()
	if cr>>8 != 255 || cg>>8 != 0 || cb>>8 != 0 {
		t.Errorf("顶行 y=0 颜色错误: r=%d g=%d b=%d", cr>>8, cg>>8, cb>>8)
	}
	cr, _, cb, _ = img.At(0, 1).RGBA()
	if cr>>8 != 0 || cb>>8 != 255 {
		t.Errorf("底行 y=1 颜色错误: r=%d b=%d", cr>>8, cb>>8)
	}
}

func TestFetchFaviconsHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><link rel="icon" href="/icons/fav32.png"></head></html>`))
		case "/icons/fav32.png":
			img := image.NewRGBA(image.Rect(0, 0, 32, 32))
			_ = png.Encode(w, img)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	icons, warns, err := fetchFavicons(host, port)
	if err != nil {
		t.Fatalf("fetchFavicons 失败: %v", err)
	}
	found := false
	for _, ic := range icons {
		if ic.Width == 32 && ic.Height == 32 {
			found = true
		}
	}
	if !found {
		t.Errorf("应包含 32×32 图标，实际: %+v，warns: %v", icons, warns)
	}
}

func TestNormalizeFaviconHost(t *testing.T) {
	cases := map[string]string{
		"192.168.1.5":      "192.168.1.5",
		" 192.168.1.5:80":  "192.168.1.5",
		"http://nas.local": "nas.local",
		"fe80::1":          "[fe80::1]",
		"[fe80::1]":        "[fe80::1]",
		"":                 "",
	}
	for in, want := range cases {
		if got := normalizeFaviconHost(in); got != want {
			t.Errorf("normalizeFaviconHost(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func buildTestICO(pngData []byte) []byte {
	out := make([]byte, 0, 6+16+len(pngData))
	out = append(out, 0, 0, 1, 0) // reserved=0, type=1(icon)
	var cnt [2]byte
	binary.LittleEndian.PutUint16(cnt[:], 1)
	out = append(out, cnt[:]...)
	entry := make([]byte, 16)
	entry[0] = 16 // 宽
	entry[1] = 16 // 高
	binary.LittleEndian.PutUint16(entry[4:6], 1)
	binary.LittleEndian.PutUint16(entry[6:8], 32)
	binary.LittleEndian.PutUint32(entry[8:12], uint32(len(pngData)))
	binary.LittleEndian.PutUint32(entry[12:16], 6+16)
	out = append(out, entry...)
	out = append(out, pngData...)
	return out
}
