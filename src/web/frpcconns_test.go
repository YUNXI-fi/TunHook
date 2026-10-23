package web

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"tunhook/config"
	"tunhook/frpc"
)

// 子进程模式：连接目标端口后保持，模拟一条 frpc 转发连接。
func TestFrpcConnStatsAndDetail(t *testing.T) {
	if os.Getenv("TUNHOOK_FRPC_CHILD") == "1" {
		port := os.Getenv("TUNHOOK_FRPC_CHILD_PORT")
		conn, err := net.Dial("tcp", "127.0.0.1:"+port)
		if err != nil {
			os.Exit(1)
		}
		time.Sleep(30 * time.Second)
		conn.Close()
		os.Exit(0)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	targetPort := ln.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	// 模拟真实 frpc 进程：把测试二进制复制成 <dir>/frpc 并以该路径启动子进程。
	// frpc.Manager 会按 /proc/<pid>/exe 校验 pid 归属（防止 pid 文件残留 + PID 被复用
	// 导致状态误报与误杀无关进程），因此子进程必须真的以该路径运行，否则会被正确判定为
	// 「不是我们的进程」而统计不到连接。
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(dir, frpc.BinName)
	binData, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, binData, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binPath, 0755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binPath, "-test.run=TestFrpcConnStatsAndDetail")
	cmd.Env = append(os.Environ(),
		"TUNHOOK_FRPC_CHILD=1",
		"TUNHOOK_FRPC_CHILD_PORT="+strconv.Itoa(targetPort))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	time.Sleep(500 * time.Millisecond) // 等待子进程连接建立

	frpcJSON := fmt.Sprintf(`{"servers":[{"name":"默认服务器","addr":"1.2.3.4","port":7000}],"proxies":[
		{"name":"idle","type":"tcp","enabled":true,"local_ip":"127.0.0.1","local_port":18001},
		{"name":"active","type":"tcp","enabled":true,"local_ip":"127.0.0.1","local_port":%d}
	]}`, targetPort)
	if err := os.WriteFile(filepath.Join(dir, "frpc.json"), []byte(frpcJSON), 0644); err != nil {
		t.Fatal(err)
	}
	mgr := frpc.NewManager(dir, nil)
	// pid 文件按服务器名命名（frpc-<serverKey>.pid），不能硬编码 frpc.pid
	if err := os.WriteFile(mgr.PidPath("默认服务器"), []byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
		t.Fatal(err)
	}

	srv := &Server{frpcMgr: mgr, connVisitors: map[string]connVisitor{}}

	stats := srv.frpcConnStats()
	if v, ok := stats["idle"]; !ok || v != 0 {
		t.Errorf("idle 代理应返回 0（而非缺项）: got %v, ok=%v", v, ok)
	}
	if v := stats["active"]; v != 1 {
		t.Errorf("active 代理应统计到 1 条连接: got %d", v)
	}

	detail := srv.frpcConnDetail()
	if len(detail["active"]) != 1 {
		t.Fatalf("active 代理应展示 1 条连接详情（无访客也展示）: got %d", len(detail["active"]))
	}
	if d := detail["active"][0]; d.VisitorIP != "-" || d.VisitorPort != "-" {
		t.Errorf("无访客关联的连接应展示 -/-: got %q/%q", d.VisitorIP, d.VisitorPort)
	}
}

// TestEnsureCustomDomainProxyPreservesAuth 验证转发通道自建代理在目标变更同步时
// 只更新路由字段，保留用户手动开启的 HTTP Basic 认证与加密/压缩等设置
// （此前会用最小字段重建代理，把认证覆盖掉，表现为「访问认证不生效」）。
func TestEnsureCustomDomainProxyPreservesAuth(t *testing.T) {
	dir := t.TempDir()
	cfg := frpc.Config{
		Servers: []frpc.Server{{Name: frpc.DefaultServerName, Addr: "1.2.3.4", Port: 7000}},
		Proxies: []frpc.Proxy{{
			Name:          "auto-proxy",
			Type:          "http",
			Enabled:       true,
			LocalIP:       "127.0.0.1",
			LocalPort:     8080,
			CustomDomains: "a.example.com",
			HTTPUser:      "admin",
			HTTPPassword:  "secret123",
			Encryption:    true,
			Compression:   true,
		}},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "frpc.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	srv := &Server{frpcMgr: frpc.NewManager(dir, nil)}
	// 转发通道目标端口从 8080 改为 9090，触发自建代理目标同步
	rule := config.ForwardRule{RemoteAddr: "127.0.0.1", RemotePort: 9090, CustomDomain: "a.example.com"}
	if err := srv.ensureCustomDomainProxy(rule); err != nil {
		t.Fatalf("ensureCustomDomainProxy: %v", err)
	}

	var p *frpc.Proxy
	for _, x := range srv.frpcMgr.LoadConfig().Proxies {
		if x.Name == "auto-proxy" {
			p = &x
			break
		}
	}
	if p == nil {
		t.Fatal("自建代理不存在")
	}
	if p.LocalPort != 9090 {
		t.Errorf("目标端口应同步为 9090，实际 %d", p.LocalPort)
	}
	if p.HTTPUser != "admin" || p.HTTPPassword != "secret123" {
		t.Errorf("访问认证被覆盖: http_user=%q http_password=%q", p.HTTPUser, p.HTTPPassword)
	}
	if !p.Encryption || !p.Compression {
		t.Errorf("加密/压缩被覆盖: encryption=%v compression=%v", p.Encryption, p.Compression)
	}
}

// TestEnsureCustomDomainProxyDomainCaseInsensitive 验证按域名复用既有代理时忽略大小写。
// 域名按 DNS 规则不区分大小写，若比对区分大小写，既有代理存的是 `Case.Mix.Test.com`
// 而转发规则填 `case.mix.test.com` 时会被当成两个域名，重复创建代理并造成 frps 域名冲突
// （frpc 报 router config conflict，而界面上看是两条不同域名的代理）。
func TestEnsureCustomDomainProxyDomainCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	cfg := frpc.Config{
		Servers: []frpc.Server{{Name: frpc.DefaultServerName, Addr: "1.2.3.4", Port: 7000}},
		Proxies: []frpc.Proxy{{
			Name:          "auto-proxy",
			Type:          "http",
			Enabled:       true,
			LocalIP:       "127.0.0.1",
			LocalPort:     8080,
			CustomDomains: "Case.Mix.Test.com", // 既有代理存的是大写域名
		}},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "frpc.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	srv := &Server{frpcMgr: frpc.NewManager(dir, nil)}
	rule := config.ForwardRule{RemoteAddr: "127.0.0.1", RemotePort: 9090, CustomDomain: "case.mix.test.com"}
	if err := srv.ensureCustomDomainProxy(rule); err != nil {
		t.Fatalf("ensureCustomDomainProxy: %v", err)
	}

	proxies := srv.frpcMgr.LoadConfig().Proxies
	if len(proxies) != 1 {
		got := make([]string, 0, len(proxies))
		for _, p := range proxies {
			got = append(got, p.Name+"("+p.CustomDomains+")")
		}
		t.Fatalf("应复用既有代理而非重复创建，实际 %d 条: %v", len(proxies), got)
	}
	if proxies[0].Name != "auto-proxy" {
		t.Errorf("应复用 auto-proxy，实际 %q", proxies[0].Name)
	}
	if proxies[0].LocalPort != 9090 {
		t.Errorf("目标端口应同步为 9090，实际 %d", proxies[0].LocalPort)
	}
}
