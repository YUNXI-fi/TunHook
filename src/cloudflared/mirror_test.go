package cloudflared

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestProbeMirror 测速探测只认「真的是 Linux 内核且真能持续传数据」的响应：
// 公益代理常以 HTTP 200 返回错误页或限流页，只看状态码会把死源当成可用源。
func TestProbeMirror(t *testing.T) {
	body := append([]byte{0x7F, 'E', 'L', 'F'}, make([]byte, 128<<10)...)
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "" {
			t.Error("探测应带 Range 头，避免测速时白拉整个内核")
		}
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(body)
	}))
	defer fast.Close()
	speed, err := probeMirror(context.Background(), http.DefaultClient, fast.URL)
	if err != nil {
		t.Errorf("可用的内核源应探测通过: %v", err)
	}
	if speed <= 0 {
		t.Errorf("采样吞吐应为正值，实际 %v", speed)
	}

	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>rate limited</html>"))
	}))
	defer html.Close()
	if _, err := probeMirror(context.Background(), http.DefaultClient, html.URL); err == nil {
		t.Error("返回错误页的源不应通过探测")
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bad.Close()
	if _, err := probeMirror(context.Background(), http.DefaultClient, bad.URL); err == nil {
		t.Error("HTTP 404 的源不应通过探测")
	}

	// 只有文件头、后续不给数据：连得上却下不动，按不可用处理
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte{0x7F, 'E', 'L', 'F'})
	}))
	defer stall.Close()
	if _, err := probeMirror(context.Background(), http.DefaultClient, stall.URL); err == nil {
		t.Error("连上却几乎不给数据的源不应通过探测")
	}
}

// TestPickedMirrorLabel 下载源展示名带采样吞吐，让用户看得出选源依据。
func TestPickedMirrorLabel(t *testing.T) {
	fast := pickedMirror{mirror: downloadMirror{name: "gh-proxy.com"}, speed: 3.5 * (1 << 20)}
	if got := fast.label(); got != "gh-proxy.com · 3.5MB/s" {
		t.Errorf("MB/s 档展示名不符: %q", got)
	}
	slow := pickedMirror{mirror: downloadMirror{name: "gh.dpik.top"}, speed: 200 * (1 << 10)}
	if got := slow.label(); got != "gh.dpik.top · 200KB/s" {
		t.Errorf("KB/s 档展示名不符: %q", got)
	}
	unprobed := pickedMirror{mirror: downloadMirror{name: "官方 GitHub"}}
	if got := unprobed.label(); got != "官方 GitHub" {
		t.Errorf("未测速时只显示名称: %q", got)
	}
}

// TestReleaseTag 最新版号从下载地址的重定向结果里解析：
// 只有真正跳到 releases/download/<tag>/ 才算拿到了版本；
// 仍停在 releases/latest/... 说明该源没暴露标签，应返回空串换下一个源。
func TestReleaseTag(t *testing.T) {
	cases := map[string]string{
		"/cloudflare/cloudflared/releases/download/2026.9.1/cloudflared-linux-amd64": "2026.9.1",
		"https://github.com/cloudflare/cloudflared/releases/download/2026.9.1/cloudflared-linux-amd64": "2026.9.1",
		// 镜像代理把原始地址拼在自己路径里（实测 gh.idayer.com 等就是这样暴露最终地址的）
		"/https://github.com/cloudflare/cloudflared/releases/download/2026.9.1/cloudflared-linux-amd64": "2026.9.1",
		// 未发生重定向：拿不到版本
		"/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64": "",
		"/": "",
	}
	for path, want := range cases {
		if got := releaseTag(path); got != want {
			t.Errorf("releaseTag(%q) = %q，期望 %q", path, got, want)
		}
	}
}

// TestDownloadMirrorsPointToKernel 候选表每一项都必须指向同一个内核文件，
// 否则可能选出「能连通但下到的不是内核」的源。
func TestDownloadMirrorsPointToKernel(t *testing.T) {
	if len(downloadMirrors) < 2 {
		t.Fatal("候选表应至少包含官方源与一个镜像")
	}
	for _, m := range downloadMirrors {
		if !strings.HasSuffix(m.url, DownloadURL) {
			t.Errorf("%s 的地址没有指向内核文件: %s", m.name, m.url)
		}
	}
}
