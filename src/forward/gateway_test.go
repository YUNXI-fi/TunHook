package forward

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// newGatewayBackend 返回一个用于验证统一网关转发的测试后端：
// 任意路径返回所接收到的路径、Host、X-Forwarded-* 与 Cookie 信息；
// /redirect 返回相对 Location 重定向（附带 Set-Cookie）；
// /redirect-abs 返回指向后端自身地址的绝对 Location 重定向。
func newGatewayBackend(t *testing.T) *httptest.Server {
	t.Helper()
	var selfAddr string // 后端自身 host:port，由 closure 捕获（server 创建后赋值）
	mux := http.NewServeMux()
	infoHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "path="+r.URL.Path+
			"|q="+r.URL.RawQuery+
			"|host="+r.Host+
			"|xfh="+r.Header.Get("X-Forwarded-Host")+
			"|xfp="+r.Header.Get("X-Forwarded-Proto")+
			"|cookie="+r.Header.Get("Cookie"))
	}
	mux.HandleFunc("/", infoHandler) // 兜底：验证任意剥离后的子路径
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "from", Value: "redirect", Path: "/"})
		w.Header().Set("Location", "/login?next=/")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/redirect-abs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://"+selfAddr+"/abs-page")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/spa", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<!doctype html><html><head><script src="/assets/app.js"></script>`+
			`<link href="/css/style.css" rel="stylesheet"></head>`+
			`<body style="background:url(/img/bg.png)"><a href="/login">登录</a></body></html>`)
	})
	srv := httptest.NewServer(mux)
	selfAddr = strings.TrimPrefix(srv.URL, "http://")
	return srv
}

func TestGatewayForwarderStripsPrefixAndPreservesHost(t *testing.T) {
	backend := newGatewayBackend(t)
	defer backend.Close()

	// 仅取 host:port，构造转发目标
	remote := strings.TrimPrefix(backend.URL, "http://")
	gf, err := NewGatewayForwarder("myname", remote, "/app/TunHook", "", "", "", zap.NewNop())
	if err != nil {
		t.Fatalf("NewGatewayForwarder: %v", err)
	}
	if gf == nil {
		t.Fatal("expected non-nil forwarder")
	}

	// 网关前缀已由 gatewayStripMiddleware 剥离，转发器收到 /proxy/{name} 下的深层子路径：
	// 后端应只收到剥离后的路径
	req := httptest.NewRequest(http.MethodGet, "http://nas.local/proxy/myname/api/foo?x=1", nil)
	req.Header.Set("X-Trim-Userid", "1000")
	req.Host = "nas.local"

	rec := httptest.NewRecorder()
	gf.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "path=/api/foo") {
		t.Errorf("backend path = %q, want /api/foo", body)
	}
	// 保留原始 Host 并回填 X-Forwarded-*，保证后端可生成正确地址/通过同源校验
	if !strings.Contains(body, "|host=nas.local") {
		t.Errorf("backend host not preserved: %q", body)
	}
	if !strings.Contains(body, "|xfh=nas.local") {
		t.Errorf("X-Forwarded-Host not set: %q", body)
	}
	if !strings.Contains(body, "|xfp=http") {
		t.Errorf("X-Forwarded-Proto not set: %q", body)
	}
}

// TestGatewayForwarderFollowsRedirect 验证代理在服务端跟随后端 3xx 重定向：
// 浏览器收到最终内容（200）而非 302，且中间跳转的 Set-Cookie 被带到下一跳。
func TestGatewayForwarderFollowsRedirect(t *testing.T) {
	backend := newGatewayBackend(t)
	defer backend.Close()

	remote := strings.TrimPrefix(backend.URL, "http://")
	gf, err := NewGatewayForwarder("myname", remote, "/app/TunHook", "", "", "", zap.NewNop())
	if err != nil {
		t.Fatalf("NewGatewayForwarder: %v", err)
	}

	cases := []struct {
		path string
		want string // 最终响应 body 中应包含的内容
	}{
		{"/proxy/myname/redirect", "path=/login"},
		{"/proxy/myname/redirect-abs", "path=/abs-page"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "http://nas.local"+tc.path, nil)
		req.Host = "nas.local"
		rec := httptest.NewRecorder()
		gf.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200（服务端已跟进重定向）; Location=%q", tc.path, rec.Code, rec.Header().Get("Location"))
			continue
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: body 缺少 %q, got %q", tc.path, tc.want, rec.Body.String())
		}
	}

	// 相对重定向跟随时：查询串保留 + 携带中间响应的 Set-Cookie
	req := httptest.NewRequest(http.MethodGet, "http://nas.local/proxy/myname/redirect", nil)
	req.Host = "nas.local"
	rec := httptest.NewRecorder()
	gf.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "|q=next=/") {
		t.Errorf("重定向查询串未保留, got %q", body)
	}
	if !strings.Contains(body, "|cookie=from=redirect") {
		t.Errorf("重定向 Cookie 未带到下一跳, got %q", body)
	}
}

// TestGatewayForwarderRewriteLocationFallback 验证未在服务端跟进的 3xx
// （如 POST）仍会把 Location 拼接上网关前缀，交给浏览器跟随。
func TestGatewayForwarderRewriteLocationFallback(t *testing.T) {
	backend := newGatewayBackend(t)
	defer backend.Close()

	remote := strings.TrimPrefix(backend.URL, "http://")
	gf, err := NewGatewayForwarder("myname", remote, "/app/TunHook", "", "", "", zap.NewNop())
	if err != nil {
		t.Fatalf("NewGatewayForwarder: %v", err)
	}

	// POST 不自动跟进，302 原样返回，但 Location 需改写为网关路径
	req := httptest.NewRequest(http.MethodPost, "http://nas.local/proxy/myname/redirect", nil)
	req.Host = "nas.local"
	rec := httptest.NewRecorder()
	gf.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302（POST 交还浏览器）", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/app/TunHook/proxy/myname/login?next=/" {
		t.Errorf("Location = %q, want 网关前缀拼接后的路径", got)
	}
}

// TestGatewayForwarderLocalDevNoPrefix 验证本地开发（无网关前缀）时仍能剥离 /proxy/{name}。
func TestGatewayForwarderLocalDevNoPrefix(t *testing.T) {
	backend := newGatewayBackend(t)
	defer backend.Close()

	remote := strings.TrimPrefix(backend.URL, "http://")
	gf, err := NewGatewayForwarder("dev", remote, "", "", "", "", zap.NewNop())
	if err != nil {
		t.Fatalf("NewGatewayForwarder: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/proxy/dev/info", nil)
	rec := httptest.NewRecorder()
	gf.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "path=/info") {
		t.Errorf("backend path = %q, want /info", rec.Body.String())
	}
}

// TestGatewayForwarderRewriteHTML 验证 HTML 内容里的根相对路径资源被拼接上网关前缀，
// 单页应用通过统一网关转发时页面资源可正常加载。
func TestGatewayForwarderRewriteHTML(t *testing.T) {
	backend := newGatewayBackend(t)
	defer backend.Close()

	remote := strings.TrimPrefix(backend.URL, "http://")
	gf, err := NewGatewayForwarder("myname", remote, "/app/TunHook", "", "", "", zap.NewNop())
	if err != nil {
		t.Fatalf("NewGatewayForwarder: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://nas.local/proxy/myname/spa", nil)
	rec := httptest.NewRecorder()
	gf.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	base := "/app/TunHook/proxy/myname"
	for _, want := range []string{
		`src="` + base + `/assets/app.js"`,
		`href="` + base + `/css/style.css"`,
		`url(` + base + `/img/bg.png)`,
		`href="` + base + `/login"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("HTML 未正确拼接路径，缺少 %q\nbody: %s", want, body)
		}
	}
	// Content-Length 需与改写后的 body 一致
	if cl := rec.Header().Get("Content-Length"); cl != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length = %s, body len = %d", cl, len(body))
	}
}

// TestGatewayForwarderRewriteSourcePrefix 验证配置了源路径前缀后，响应内容
// （HTML/JS/CSS）中写死的绝对前缀（如 /app/canvasboard）被替换为代理前缀。
func TestGatewayForwarderRewriteSourcePrefix(t *testing.T) {
	spBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/canvasboard/index.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, `<html><head><script src="/app/canvasboard/cb-api.js"></script>`+
				`<img src="/app/canvasboard/img/icon.svg"></head></html>`)
		case "/app/canvasboard/cb-api.js":
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, `const BASE='/app/canvasboard';function me(){return fetch(BASE+'/api/me')}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer spBackend.Close()

	remote := strings.TrimPrefix(spBackend.URL, "http://")
	gf, err := NewGatewayForwarder("canvas", remote, "/app/TunHook", "/app/canvasboard", "", "", zap.NewNop())
	if err != nil {
		t.Fatalf("NewGatewayForwarder: %v", err)
	}
	base := "/app/TunHook/proxy/canvas"

	// HTML：源前缀替换 + 根相对路径拼接
	req := httptest.NewRequest(http.MethodGet, "http://nas.local/proxy/canvas/app/canvasboard/index.html", nil)
	rec := httptest.NewRecorder()
	gf.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `src="`+base+`/cb-api.js"`) {
		t.Errorf("HTML 源前缀未替换，body: %s", body)
	}
	if !strings.Contains(body, `src="`+base+`/img/icon.svg"`) {
		t.Errorf("HTML 图片路径未替换，body: %s", body)
	}

	// JS：写死的 BASE 常量被替换为代理前缀
	req2 := httptest.NewRequest(http.MethodGet, "http://nas.local/proxy/canvas/app/canvasboard/cb-api.js", nil)
	rec2 := httptest.NewRecorder()
	gf.ServeHTTP(rec2, req2)
	js := rec2.Body.String()
	if !strings.Contains(js, `const BASE='`+base+`'`) || strings.Contains(js, "/app/canvasboard") {
		t.Errorf("JS 源前缀未替换，js: %s", js)
	}
}

// TestGatewayForwarderRewriteHTMLWithGzip 验证浏览器场景（携带 Accept-Encoding: gzip）
// 下，代理会移除出站 Accept-Encoding 让传输层透明解压，HTML 改写依然生效。
func TestGatewayForwarderRewriteHTMLWithGzip(t *testing.T) {
	gzBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		io.WriteString(zw, `<html><head><script src="/assets/gz.js"></script></head></html>`)
		zw.Close()
		w.Write(buf.Bytes())
	}))
	defer gzBackend.Close()

	remote := strings.TrimPrefix(gzBackend.URL, "http://")
	gf, err := NewGatewayForwarder("myname", remote, "/app/TunHook", "", "", "", zap.NewNop())
	if err != nil {
		t.Fatalf("NewGatewayForwarder: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://nas.local/proxy/myname/", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rec := httptest.NewRecorder()
	gf.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `src="/app/TunHook/proxy/myname/assets/gz.js"`) {
		t.Errorf("gzip HTML 未改写，body: %s", body)
	}
	if rec.Header().Get("Content-Encoding") != "" {
		t.Errorf("Content-Encoding 应为空（已解压），got %q", rec.Header().Get("Content-Encoding"))
	}
}

// TestGatewayForwarderPathPrefix 验证配置了后端路径前缀（pathPrefix）后：
// 请求转发到后端时剥离 /proxy/{name} 后拼接 pathPrefix；
// 后端返回的以 pathPrefix 开头的 Location 会被剥离后回写网关路径。
func TestGatewayForwarderPathPrefix(t *testing.T) {
	ppBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/canvasboard", "/app/canvasboard/", "/app/canvasboard/api/foo", "/app/canvasboard/login":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "path="+r.URL.Path)
		case "/app/canvasboard/redir":
			w.Header().Set("Location", "/app/canvasboard/login?next=/")
			w.WriteHeader(http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ppBackend.Close()

	remote := strings.TrimPrefix(ppBackend.URL, "http://")
	gf, err := NewGatewayForwarder("myname", remote, "/app/TunHook", "", "", "/app/canvasboard", zap.NewNop())
	if err != nil {
		t.Fatalf("NewGatewayForwarder: %v", err)
	}

	// 根路径 → 后端 pathPrefix
	req := httptest.NewRequest(http.MethodGet, "http://nas.local/proxy/myname/", nil)
	rec := httptest.NewRecorder()
	gf.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "path=/app/canvasboard") {
		t.Errorf("根路径未拼接 pathPrefix, body: %s", rec.Body.String())
	}

	// 深层子路径 → pathPrefix + 子路径
	req2 := httptest.NewRequest(http.MethodGet, "http://nas.local/proxy/myname/api/foo", nil)
	rec2 := httptest.NewRecorder()
	gf.ServeHTTP(rec2, req2)
	if !strings.Contains(rec2.Body.String(), "path=/app/canvasboard/api/foo") {
		t.Errorf("子路径未拼接 pathPrefix, body: %s", rec2.Body.String())
	}

	// POST 302 交还浏览器：后端 Location 带 pathPrefix，需剥离后回写网关路径
	req3 := httptest.NewRequest(http.MethodPost, "http://nas.local/proxy/myname/redir", nil)
	rec3 := httptest.NewRecorder()
	gf.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302（POST 交还浏览器）", rec3.Code)
	}
	if got := rec3.Header().Get("Location"); got != "/app/TunHook/proxy/myname/login?next=/" {
		t.Errorf("Location = %q, want 剥离 pathPrefix 后的网关路径", got)
	}
}

// TestGatewayForwarderLargeHTMLNotTruncated 验证超过改写上限（16MB）的 text/html 响应不会被截断：
// 已知 Content-Length 时直接透传；分块传输（长度未知）时已读部分与剩余流合并透传，
// 客户端均能收到完整响应体。
func TestGatewayForwarderLargeHTMLNotTruncated(t *testing.T) {
	const total = 17 << 20 // 17MB，超过 16MB 改写上限
	chunk := []byte("<div>test</div>")
	data := bytes.Repeat(chunk, (total+len(chunk)-1)/len(chunk))[:total]

	// 场景一：已知 Content-Length 的大响应 → 跳过改写直接透传
	backendCL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
	}))
	remote := strings.TrimPrefix(backendCL.URL, "http://")
	gf, err := NewGatewayForwarder("bigcl", remote, "/app/TunHook", "", "", "", zap.NewNop())
	if err != nil {
		t.Fatalf("NewGatewayForwarder: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://nas.local/proxy/bigcl/", nil)
	rec := httptest.NewRecorder()
	gf.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("known-length: status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != len(data) {
		t.Fatalf("known-length: 收到 %d 字节，期望 %d（不得截断）", rec.Body.Len(), len(data))
	}
	backendCL.Close()

	// 场景二：分块传输（未知 Content-Length）的流式大响应 → 合并透传不截断
	backendTE := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		for i := 0; i < len(data); i += 64 << 10 {
			end := i + 64<<10
			if end > len(data) {
				end = len(data)
			}
			w.Write(data[i:end])
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
		}
	}))
	defer backendTE.Close()
	remote = strings.TrimPrefix(backendTE.URL, "http://")
	gf, err = NewGatewayForwarder("bigte", remote, "/app/TunHook", "", "", "", zap.NewNop())
	if err != nil {
		t.Fatalf("NewGatewayForwarder: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "http://nas.local/proxy/bigte/", nil)
	rec = httptest.NewRecorder()
	gf.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("chunked: status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != len(data) {
		t.Fatalf("chunked: 收到 %d 字节，期望 %d（不得截断）", rec.Body.Len(), len(data))
	}
}
