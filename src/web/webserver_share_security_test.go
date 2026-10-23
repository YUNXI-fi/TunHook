package web

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWSClientIPProxyTrust 验证只有可信反代（含本机回环）的 X-Forwarded-For 才会被采信。
func TestWSClientIPProxyTrust(t *testing.T) {
	newReq := func(remote, realIP, xff string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if realIP != "" {
			r.Header.Set("X-Real-IP", realIP)
		}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	// 公网直连：伪造 XFF 必须被忽略
	if got := wsClientIP(newReq("203.0.113.9:1234", "", "1.2.3.4"), ""); got != "203.0.113.9" {
		t.Fatalf("公网直连应忽略 XFF，got %s", got)
	}
	// 可信反代：采信 XFF 第一跳
	if got := wsClientIP(newReq("10.0.0.5:1234", "", "1.2.3.4, 10.0.0.5"), "10.0.0.0/8"); got != "1.2.3.4" {
		t.Fatalf("可信反代应采信 XFF，got %s", got)
	}
	// 本机回环默认可信
	if got := wsClientIP(newReq("127.0.0.1:1234", "1.2.3.4", ""), ""); got != "1.2.3.4" {
		t.Fatalf("回环应采信 X-Real-IP，got %s", got)
	}
	// 非法头值被丢弃
	if got := wsClientIP(newReq("127.0.0.1:1234", "not-an-ip", ""), ""); got != "127.0.0.1" {
		t.Fatalf("非法 X-Real-IP 应被丢弃，got %s", got)
	}
}

// TestWSResolveSharePathBlocksSymlinkEscape 验证符号链接无法把读取范围带出分享根目录。
func TestWSResolveSharePathBlocksSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "share")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "leak.txt")); err != nil {
		t.Skipf("当前系统不支持创建符号链接：%v", err)
	}
	if _, ok := wsResolveSharePath(root, "leak.txt"); ok {
		t.Fatal("符号链接逃逸未被阻止")
	}

	inside := filepath.Join(root, "ok.txt")
	if err := os.WriteFile(inside, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := wsResolveSharePath(root, "ok.txt")
	if !ok || got != filepath.Join(realRoot, "ok.txt") {
		t.Fatalf("根目录内文件应可解析，got %q ok=%v", got, ok)
	}
}

// TestWSShareCodeCookieBindsIPAndUA 验证提取码凭证绑定 IP 与 UA。
func TestWSShareCodeCookieBindsIPAndUA(t *testing.T) {
	site := WebSite{ID: "site-test", Share: WebShareConfig{AccessCode: "246810"}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.7:5555"
	r.Header.Set("User-Agent", "UA-A")

	w := httptest.NewRecorder()
	wsSetShareCodeCookie(w, site, r)
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("未下发提取码凭证")
	}
	c := cookies[0]

	check := func(remote, ua string) bool {
		r2 := httptest.NewRequest("GET", "/", nil)
		r2.RemoteAddr = remote
		r2.Header.Set("User-Agent", ua)
		r2.AddCookie(c)
		return wsShareCodeOK(site, r2)
	}
	if !check("198.51.100.7:5555", "UA-A") {
		t.Fatal("相同 IP 与 UA 应通过")
	}
	if check("198.51.100.8:5555", "UA-A") {
		t.Fatal("换 IP 后凭证应失效")
	}
	if check("198.51.100.7:5555", "UA-B") {
		t.Fatal("换 UA 后凭证应失效")
	}
}

// TestNormalizeWebSiteAllowsNoPreviewWithDisableDownload 验证「禁止下载 + 禁止预览」组合可用。
func TestNormalizeWebSiteAllowsNoPreviewWithDisableDownload(t *testing.T) {
	site, err := normalizeWebSite(WebSite{
		Name:  "test",
		Type:  WebTypeShare,
		Addr:  "0.0.0.0",
		Port:  8090,
		Root:  t.TempDir(),
		Share: WebShareConfig{DisableDownload: true, Preview: false},
	})
	if err != nil {
		t.Fatalf("该组合应被允许：%v", err)
	}
	if site.Share.Preview {
		t.Fatal("Preview 不应被强制打开")
	}
	if site.Share.PackageDownload {
		t.Fatal("禁止下载时打包下载应被关闭")
	}
}

// TestShareHandlerPresenceAndRateLimit 验证在场凭证、控制台模式与限速。
func TestShareHandlerPresenceAndRateLimit(t *testing.T) {
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
	const remote = "198.51.100.20:1234"

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "note.md"), []byte("# hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	png, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dot.png"), png, 0o644); err != nil {
		t.Fatal(err)
	}

	site := WebSite{
		ID: "site-test", Name: "test", Type: WebTypeShare, Root: root,
		Share: WebShareConfig{Slug: "share", DisableDownload: true, Preview: true},
	}
	h := (&Server{}).newShareHandler(site, &webSiteRun{})
	rawText := "/raw?path=" + url.QueryEscape("note.md")
	rawImage := "/raw?path=" + url.QueryEscape("dot.png")

	presence := func(devtools bool) []*http.Cookie {
		tr := httptest.NewRequest("GET", "/s/share", nil)
		tr.RemoteAddr = remote
		tr.Header.Set("User-Agent", ua)
		form := url.Values{
			"ticket": {wsSharePageTicket(site, tr)}, "visible": {"1"}, "focus": {"1"},
			"sw": {"1920"}, "sh": {"1080"}, "devtools": {boolFlag(devtools)},
		}
		req := httptest.NewRequest("POST", "/__presence", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", ua)
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("在场上报应成功，got %d %s", w.Code, w.Body.String())
		}
		var out []*http.Cookie
		for _, c := range w.Result().Cookies() {
			if strings.HasPrefix(c.Name, "tunhook_share_presence_") {
				out = append(out, c)
			}
		}
		if len(out) == 0 {
			t.Fatal("未下发在场凭证")
		}
		return out
	}

	content := func(path string, browser bool, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = remote
		r.Header.Set("User-Agent", ua)
		if browser {
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header.Set("Sec-Fetch-Mode", "cors")
			r.Header.Set("Sec-Fetch-Dest", "empty")
			r.Header.Set("Accept", "*/*")
			r.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// 没有在场凭证：文本 403，图片 403 + 水印占位图
	if w := content(rawText, true); w.Code != http.StatusForbidden {
		t.Fatalf("无在场凭证时文本应 403，got %d", w.Code)
	}
	if w := content(rawImage, true); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "<svg") {
		t.Fatalf("无在场凭证时图片应 403 + 水印占位，got %d", w.Code)
	}

	p := presence(false)
	// 浏览器 + 在场凭证：返回原内容，无水印
	w := content(rawText, true, p...)
	if w.Code != http.StatusOK {
		t.Fatalf("浏览器预览应 200，got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "【TunHook 水印】") {
		t.Fatal("浏览器正常预览不应带水印")
	}
	// 完全不像浏览器的请求：即使有在场凭证也拒绝
	if w := content(rawText, false, p...); w.Code != http.StatusForbidden {
		t.Fatalf("非浏览器请求应 403，got %d", w.Code)
	}
	// 只伪装 Sec-Fetch-Site 的半脚本请求：放行但强制水印
	semi := httptest.NewRequest("GET", rawText, nil)
	semi.RemoteAddr = remote
	semi.Header.Set("User-Agent", ua)
	semi.Header.Set("Sec-Fetch-Site", "same-origin")
	for _, c := range p {
		semi.AddCookie(c)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, semi)
	if !strings.Contains(w.Body.String(), "【TunHook 水印】") {
		t.Fatalf("半伪装请求必须带水印：status=%d body=%q", w.Code, w.Body.String())
	}

	pd := presence(true)
	// 控制台打开：文本禁止查看，图片强制水印
	if w := content(rawText, true, pd...); w.Code != http.StatusForbidden {
		t.Fatalf("控制台打开时文本应 403，got %d", w.Code)
	}
	w = content(rawImage, true, pd...)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<svg") {
		t.Fatalf("控制台打开时图片应返回水印 SVG，got %d", w.Code)
	}

	// 页面必须注入在场证明脚本，并把图片缩略图改成 data-src 延迟加载
	pageReq := httptest.NewRequest("GET", "/s/share", nil)
	pageReq.RemoteAddr = remote
	pageReq.Header.Set("User-Agent", ua)
	pageW := httptest.NewRecorder()
	h.ServeHTTP(pageW, pageReq)
	if pageW.Code != http.StatusOK {
		t.Fatalf("分享页应 200，got %d", pageW.Code)
	}
	pageBody := pageW.Body.String()
	for _, marker := range []string{"/__presence", "data-src", "__tunhookDevtoolsChanged", "tunhook_dt_reload_"} {
		if !strings.Contains(pageBody, marker) {
			t.Fatalf("分享页缺少在场证明脚本标记：%s", marker)
		}
	}

	// 限速：同一 IP 连续请求超过突发上限后应出现 429
	limited := false
	for i := 0; i < wsShareRateBurst+10; i++ {
		if w := content(rawText, true, p...); w.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("连续请求未触发限速")
	}
}
