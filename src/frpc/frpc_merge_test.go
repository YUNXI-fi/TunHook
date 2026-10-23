package frpc

import (
	"os"
	"strings"
	"testing"
)

// newLogManager 建一个仅用于日志解析测试的 Manager（日志目录独立）。
func newLogManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	m := NewManager(dir, nil)
	m.SetPaths(dir, dir)
	return m
}

// writeLog 写入指定服务器的 frpc 日志内容。
func writeLog(t *testing.T, m *Manager, name, content string) {
	t.Helper()
	if err := os.WriteFile(m.logPathFor(name), []byte(content), 0644); err != nil {
		t.Fatalf("写入日志失败: %v", err)
	}
}

// frpc 真实日志行首带 ANSI 颜色码；[I] 是普通日志、[W]/[E] 才是问题。
func TestLastErrorForSkipsInfoLines(t *testing.T) {
	m := newLogManager(t)
	log := "\x1b[0m\x1b[1;34m2026-10-16 10:05:37.983 [I] [client/service.go:312] try to connect to server...\x1b[0m\n" +
		"\x1b[0m\x1b[1;33m2026-10-16 10:05:35.793 [W] [client/service.go:323] connect to server error: connection write timeout\x1b[0m\n" +
		"\x1b[0m\x1b[1;34m2026-10-16 10:05:38.018 [I] [http/middleware.go:38] http response [/api/status]: code [200]\x1b[0m\n"
	writeLog(t, m, "默认服务器", log)

	if got := m.LastErrorFor("默认服务器"); got != "connect to server error: connection write timeout" {
		t.Fatalf("期望取到 write timeout，实际 %q", got)
	}
}

func TestLastErrorForNoErrorReturnsEmpty(t *testing.T) {
	m := newLogManager(t)
	writeLog(t, m, "默认服务器", "\x1b[0m\x1b[1;34m2026-10-16 10:05:38.018 [I] [http/middleware.go:38] http response [/api/status]: code [200]\x1b[0m\n")

	if got := m.LastErrorFor("默认服务器"); got != "" {
		t.Fatalf("只有 [I] 行时应返回空串，实际 %q", got)
	}
}

func TestLastErrorForAuthFailed(t *testing.T) {
	m := newLogManager(t)
	writeLog(t, m, "默认服务器", "\x1b[0m\x1b[1;31m2026-10-16 10:05:35.793 [E] [client/service.go:339] login to the server failed: authorization failed\x1b[0m\n")

	if got := m.LastErrorFor("默认服务器"); got != "login to the server failed: authorization failed" {
		t.Fatalf("期望取到 authorization failed，实际 %q", got)
	}
}

func TestLastErrorForPlainLine(t *testing.T) {
	m := newLogManager(t)
	writeLog(t, m, "默认服务器", "2026-10-16 10:05:35.793 [W] [client/service.go:323] connect to server error: i/o timeout\n")

	if got := m.LastErrorFor("默认服务器"); got != "connect to server error: i/o timeout" {
		t.Fatalf("期望取到 i/o timeout，实际 %q", got)
	}
}

func TestLastErrorForPerServer(t *testing.T) {
	m := newLogManager(t)
	writeLog(t, m, "A", "\x1b[0m\x1b[1;33m2026-10-16 10:05:35.793 [W] [c/s.go:1] a failed: timeout\x1b[0m\n")
	writeLog(t, m, "B", "\x1b[0m\x1b[1;31m2026-10-16 10:05:36.793 [E] [c/s.go:2] b failed: refused\x1b[0m\n")

	if got := m.LastErrorFor("A"); got != "a failed: timeout" {
		t.Fatalf("A 期望 timeout，实际 %q", got)
	}
	if got := m.LastErrorFor("B"); got != "b failed: refused" {
		t.Fatalf("B 期望 refused，实际 %q", got)
	}
	if got := m.LastErrorFor("C"); got != "" {
		t.Fatalf("未配置服务器应返回空串，实际 %q", got)
	}
}

// ==================== 合并：UI 可编辑字段必须生效 ====================

// 核心回归：UI 改了 token，合并后的 toml 必须用新 token。
// 修复前会保留原始配置里的旧 token，表现为「保存成功但不生效」。
func TestMergeProxySectionTokenTakesEffect(t *testing.T) {
	m := newLogManager(t)
	raw := `serverAddr = "8.134.92.34"
serverPort = 7000
auth.method = "token"
auth.token = "OLD_TOKEN"
user = "OLD_USER"
loginFailExit = false
`
	cfg := Config{
		Servers: []Server{{
			Name: "默认服务器", Addr: "8.134.92.34", Port: 7000,
			Token: "NEW_TOKEN", User: "NEW_USER",
		}},
		ActiveServer: "默认服务器",
		Proxies:      []Proxy{},
	}
	got, err := m.mergeProxySection(cfg, "默认服务器", raw)
	if err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	if strings.Contains(got, "OLD_TOKEN") || strings.Contains(got, "OLD_USER") {
		t.Fatalf("旧凭据残留：\n%s", got)
	}
	if !strings.Contains(got, `auth.token = "NEW_TOKEN"`) {
		t.Fatalf("新 token 未写入：\n%s", got)
	}
	if !strings.Contains(got, `user = "NEW_USER"`) {
		t.Fatalf("新 user 未写入：\n%s", got)
	}
	// 不得出现重复键（否则 frpc 解析歧义）
	if n := strings.Count(got, "auth.token"); n != 1 {
		t.Fatalf("auth.token 出现 %d 次，应为 1 次：\n%s", n, got)
	}
	if n := strings.Count(got, "serverAddr"); n != 1 {
		t.Fatalf("serverAddr 出现 %d 次，应为 1 次：\n%s", n, got)
	}
}

// 地址/端口同样是 UI 可编辑字段，改了必须生效
func TestMergeProxySectionAddrTakesEffect(t *testing.T) {
	m := newLogManager(t)
	raw := "serverAddr = \"1.1.1.1\"\nserverPort = 7000\n"
	cfg := Config{
		Servers:      []Server{{Name: "默认服务器", Addr: "8.134.92.34", Port: 8000}},
		ActiveServer: "默认服务器",
		Proxies:      []Proxy{},
	}
	got, err := m.mergeProxySection(cfg, "默认服务器", raw)
	if err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	if strings.Contains(got, "1.1.1.1") {
		t.Fatalf("旧地址残留：\n%s", got)
	}
	if !strings.Contains(got, `serverAddr = "8.134.92.34"`) || !strings.Contains(got, "serverPort = 8000") {
		t.Fatalf("新地址/端口未写入：\n%s", got)
	}
}

// UI 管不到的键必须保留：这是保留手写配置的唯一目的
func TestMergeProxySectionKeepsManualKeys(t *testing.T) {
	m := newLogManager(t)
	raw := `serverAddr = "8.134.92.34"
serverPort = 7000
auth.method = "token"
auth.token = "OLD"
metadatas.var_1 = "hello"
plugin.dns_server = "223.5.5.5"
transport.heartbeatTimeout = 30
`
	cfg := Config{
		Servers:      []Server{{Name: "默认服务器", Addr: "8.134.92.34", Port: 7000, Token: "NEW"}},
		ActiveServer: "默认服务器",
		Proxies:      []Proxy{},
	}
	got, err := m.mergeProxySection(cfg, "默认服务器", raw)
	if err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	for _, want := range []string{`metadatas.var_1 = "hello"`, `plugin.dns_server = "223.5.5.5"`, "transport.heartbeatTimeout = 30"} {
		if !strings.Contains(got, want) {
			t.Fatalf("手写键 %q 被误删：\n%s", want, got)
		}
	}
	if !strings.Contains(got, `auth.token = "NEW"`) {
		t.Fatalf("token 未更新：\n%s", got)
	}
}

// 单行内联表形式的 auth 也必须被正确覆盖
func TestMergeProxySectionInlineAuth(t *testing.T) {
	m := newLogManager(t)
	raw := `serverAddr = "8.134.92.34"
serverPort = 7000
auth = { method = "token", token = "OLD" }
`
	cfg := Config{
		Servers:      []Server{{Name: "默认服务器", Addr: "8.134.92.34", Port: 7000, Token: "NEW"}},
		ActiveServer: "默认服务器",
		Proxies:      []Proxy{},
	}
	got, err := m.mergeProxySection(cfg, "默认服务器", raw)
	if err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	if strings.Contains(got, "OLD") {
		t.Fatalf("内联 auth 旧值残留：\n%s", got)
	}
	if !strings.Contains(got, `auth.token = "NEW"`) {
		t.Fatalf("新 token 未写入：\n%s", got)
	}
}

// 代理段替换：旧的应被清掉，新的应存在
func TestMergeProxySectionReplacesProxies(t *testing.T) {
	m := newLogManager(t)
	raw := `serverAddr = "8.134.92.34"
serverPort = 7000
auth.token = "T"

[[proxies]]
name = "旧代理"
type = "tcp"
localPort = 9000
`
	cfg := Config{
		Servers:      []Server{{Name: "默认服务器", Addr: "8.134.92.34", Port: 7000, Token: "T"}},
		ActiveServer: "默认服务器",
		Proxies:      []Proxy{{Name: "新代理", Type: "tcp", LocalIP: "127.0.0.1", LocalPort: 1234}},
	}
	got, err := m.mergeProxySection(cfg, "默认服务器", raw)
	if err != nil {
		t.Fatalf("合并失败: %v", err)
	}
	if strings.Contains(got, "旧代理") {
		t.Fatalf("旧代理未清除：\n%s", got)
	}
	if !strings.Contains(got, `name = "新代理"`) {
		t.Fatalf("新代理未写入：\n%s", got)
	}
}
