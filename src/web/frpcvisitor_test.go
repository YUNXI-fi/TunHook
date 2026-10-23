package web

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tunhook/frpc"
)

// 测试 frpcProxyForRequest：从请求的 Host(自定义域名) / 网关路径(/proxy/{name}) 解析 frpc 代理名。
func TestFrpcProxyForRequest(t *testing.T) {
	dir := t.TempDir()
	cfg := frpc.Config{
		Servers: []frpc.Server{{Name: frpc.DefaultServerName, Addr: "frp.example.com", Port: 7000}},
		Proxies: []frpc.Proxy{
			{Name: "by-domain", Type: "http", Enabled: true, LocalIP: "127.0.0.1", LocalPort: 8080, CustomDomains: "app.example.com,alt.example.com"},
			{Name: "by-subdomain", Type: "http", Enabled: true, LocalIP: "127.0.0.1", LocalPort: 8081, Subdomain: "nas", Server: frpc.DefaultServerName},
			{Name: "by-path", Type: "http", Enabled: true, LocalIP: "127.0.0.1", LocalPort: 8082},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "frpc.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	srv := &Server{frpcMgr: frpc.NewManager(dir, nil), domainIndex: map[string]string{}}

	tests := []struct {
		name string
		host string
		path string
		want string
	}{
		{"custom-domain 精确匹配", "app.example.com", "/", "by-domain"},
		{"custom-domain 携带端口", "app.example.com:443", "/", "by-domain"},
		{"custom-domain 多域名第二项", "alt.example.com", "/", "by-domain"},
		{"网关路径 /proxy/{name}", "", "/proxy/by-path/", "by-path"},
		{"子域名访问地址", "nas.frp.example.com", "/", "by-subdomain"},
		{"完全不同域名", "other.example.com", "/", ""},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "http://"+tt.host+tt.path, nil)
		r.Host = tt.host
		if got := srv.frpcProxyForRequest(r); got != tt.want {
			t.Errorf("%s: frpcProxyForRequest = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// 测试 connVisitorFor：socket 精确匹配失败时，回退到代理名归集的访客（网关场景展示 IP），
// 两者都命中不到时返回 "-"。
func TestConnVisitorFor(t *testing.T) {
	srv := &Server{
		connVisitors:        map[string]connVisitor{},
		connVisitorsByProxy: map[string]connVisitor{},
	}
	// 无任何记录：默认 "-"
	if ip, port := srv.connVisitorFor("10.0.0.1:555", []string{"active"}); ip != "-" || port != "-" {
		t.Errorf("无记录应返回 '-'/'-'，got %q/%q", ip, port)
	}
	// socket 精确命中（直连场景）
	srv.connVisitors["10.0.0.1:555"] = connVisitor{IP: "198.51.100.9", Port: "33000", Last: time.Now()}
	if ip, port := srv.connVisitorFor("10.0.0.1:555", []string{"active"}); ip != "198.51.100.9" || port != "33000" {
		t.Errorf("socket 精确匹配失败，got %q/%q", ip, port)
	}
	// socket 失效(不存在)，回退代理名归集（网关场景）
	srv.recordVisitorByProxy("active", "203.0.113.7", "54321")
	if ip, port := srv.connVisitorFor("10.0.0.1:999", []string{"active"}); ip != "203.0.113.7" || port != "54321" {
		t.Errorf("代理名回退失败，got %q/%q", ip, port)
	}
	// 端口缺失时回退为 "-"
	if _, port := srv.connVisitorFor("10.0.0.1:999", []string{"active"}); port != "54321" {
		t.Errorf("已记录端口应保留，got %q", port)
	}
}

// 测试访客按代理名归集的写入/读取回路。
func TestVisitorByProxyRoundTrip(t *testing.T) {
	srv := &Server{connVisitorsByProxy: map[string]connVisitor{}}

	srv.recordVisitorByProxy("by-domain", "203.0.113.7", "54321")
	v := srv.visitorForProxy("by-domain")
	if v.IP != "203.0.113.7" || v.Port != "54321" {
		t.Fatalf("round-trip 失败: got %+v", v)
	}

	// 端口缺失时回退为 "-"
	srv.recordVisitorByProxy("by-domain", "203.0.113.7", "")
	if v := srv.visitorForProxy("by-domain"); v.Port != "-" {
		t.Errorf("空端口应回退为 '-'，got %q", v.Port)
	}

	// 未记录的代理名返回空值（不应 panic，map 为 nil 时也安全）
	srvNil := &Server{}
	if v := srvNil.visitorForProxy("missing"); v.IP != "" {
		t.Errorf("未记录代理应返回空值，got %+v", v)
	}
}
