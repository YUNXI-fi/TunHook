package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestWafBuiltinRules 验证内置规则对典型攻击 payload 的命中，以及正常请求不误报。
func TestWafBuiltinRules(t *testing.T) {
	cfg := defaultWafSettings()
	cases := []struct {
		name   string
		method string
		url    string
		body   string
		ua     string
		header string
		want   string
	}{
		{"sql injection", "GET", "/search?q=1 union select 1,2", "", "Mozilla/5.0", "", "SQL 注入"},
		{"xss", "GET", "/?q=<script>alert(1)</script>", "", "Mozilla/5.0", "", "XSS 跨站脚本"},
		{"traversal", "GET", "/download?file=../../etc/passwd", "", "Mozilla/5.0", "", "路径穿越"},
		{"command injection", "POST", "/run", "cmd=; whoami", "Mozilla/5.0", "", "命令注入"},
		{"scanner", "GET", "/", "", "sqlmap/1.7", "", "恶意扫描器"},
		{"sensitive path", "GET", "/.env", "", "Mozilla/5.0", "", "敏感路径探测"},
		{"normal query", "GET", "/api/ports/scan?mode=lan&ports=80,443", "", "Mozilla/5.0", "session=abc", ""},
		{"normal json", "POST", "/api/login", `{"username":"alice","password":"pass"}`, "Mozilla/5.0", "", ""},
	}
	for _, c := range cases {
		targets := map[string]string{"url": c.url, "body": c.body, "ua": c.ua, "header": c.header}
		if got := matchWaf(cfg, nil, c.method, targets); got != c.want {
			t.Errorf("%s: matchWaf = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestWafCustomRule 验证自定义规则：URL 匹配、方法匹配、停用规则不参与。
func TestWafCustomRule(t *testing.T) {
	cfg := defaultWafSettings()
	rules := compileWafRules([]wafCustomRule{
		{ID: "1", Name: "拦截下载", Enabled: true, Field: "url", Pattern: `(?i)/download`},
		{ID: "2", Name: "停用规则", Enabled: false, Field: "url", Pattern: `.*`},
		{ID: "3", Name: "方法限制", Enabled: true, Field: "method", Pattern: `^(TRACE|CONNECT)$`},
	})
	if got := matchWaf(cfg, rules, "GET", map[string]string{"url": "/download/file"}); got != "拦截下载" {
		t.Errorf("自定义 URL 规则未命中: %q", got)
	}
	if got := matchWaf(cfg, rules, "TRACE", map[string]string{"url": "/ok"}); got != "方法限制" {
		t.Errorf("自定义方法规则未命中: %q", got)
	}
	if got := matchWaf(cfg, rules, "GET", map[string]string{"url": "/anything"}); got != "" {
		t.Errorf("停用规则被匹配: %q", got)
	}
}

// TestWafShouldInspectBody 验证请求体检查范围：文本类型才读，GET/上传/WebSocket 跳过。
func TestWafShouldInspectBody(t *testing.T) {
	req := func(method, ct, upgrade string) *http.Request {
		r, _ := http.NewRequest(method, "http://x/", strings.NewReader("body"))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		if upgrade != "" {
			r.Header.Set("Upgrade", upgrade)
		}
		return r
	}
	if !wafShouldInspectBody(req("POST", "application/json", "")) {
		t.Error("JSON 请求体应检查")
	}
	if !wafShouldInspectBody(req("POST", "application/x-www-form-urlencoded", "")) {
		t.Error("表单请求体应检查")
	}
	if wafShouldInspectBody(req("GET", "application/json", "")) {
		t.Error("GET 不应检查请求体")
	}
	if wafShouldInspectBody(req("POST", "multipart/form-data; boundary=x", "")) {
		t.Error("文件上传不应检查请求体")
	}
	if wafShouldInspectBody(req("POST", "application/json", "websocket")) {
		t.Error("WebSocket 升级不应检查请求体")
	}
}

// TestWafURLDecodeBypass 验证查询串 URL 编码后仍能被规则命中（%20 编码绕过）。
func TestWafURLDecodeBypass(t *testing.T) {
	u, err := url.Parse("/search?q=1%20union%20select%201,2")
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]string{"url": wafURLText(u), "ua": "Mozilla/5.0"}
	if got := matchWaf(defaultWafSettings(), nil, "GET", targets); got != "SQL 注入" {
		t.Fatalf("编码查询串未命中: %q", got)
	}
}

// TestWafBuiltinToggle 验证关闭某条内置规则后不再命中。
func TestWafBuiltinToggle(t *testing.T) {
	cfg := defaultWafSettings()
	cfg.Builtin["sqli"] = false
	payload := map[string]string{"url": "/q?x=1 union select 1,2", "ua": "Mozilla/5.0"}
	if got := matchWaf(cfg, nil, "GET", payload); got != "" {
		t.Errorf("关闭 SQL 注入规则后仍命中: %q", got)
	}
}
