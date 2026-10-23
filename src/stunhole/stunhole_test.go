package stunhole

import (
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tunhook/store"

	"github.com/pion/stun/v3"
	"go.uber.org/zap"
)

// newTestManager 构造带临时库的 Manager（仅供测试）。
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return NewManager(st, zap.NewNop())
}

func TestIsPrivateOrCGNAT(t *testing.T) {
	cases := []struct {
		hostPort string
		want     bool
	}{
		{"192.168.1.1:1234", true},        // RFC1918 私有
		{"10.0.0.1:80", true},             // RFC1918 私有
		{"172.16.0.1:80", true},           // RFC1918 私有
		{"127.0.0.1:80", true},            // 回环
		{"100.64.0.1:80", true},           // CGNAT 100.64/10
		{"100.127.255.255:80", true},      // CGNAT 上界
		{"180.136.228.172:23840", false},  // 公网
		{"8.8.8.8:53", false},             // 公网
		{"100.128.0.1:80", false},         // CGNAT 之外
	}
	for _, c := range cases {
		if got := isPrivateOrCGNAT(c.hostPort); got != c.want {
			t.Errorf("isPrivateOrCGNAT(%s) = %v, want %v", c.hostPort, got, c.want)
		}
	}
}

func TestParseStunPublic(t *testing.T) {
	// 构造 Binding Success + XORMappedAddress，验证能解析出公网映射地址
	msg := stun.MustBuild(stun.BindingSuccess, stun.TransactionID,
		stun.XORMappedAddress{IP: net.ParseIP("180.136.228.172"), Port: 23840},
		stun.Fingerprint)
	got, ok := parseStunPublic(msg.Raw)
	if !ok {
		t.Fatal("parseStunPublic should succeed for BindingSuccess")
	}
	if got != "180.136.228.172:23840" {
		t.Errorf("parseStunPublic = %q, want %q", got, "180.136.228.172:23840")
	}

	// BindingRequest 不应被解析为映射
	req := stun.MustBuild(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
	if _, ok := parseStunPublic(req.Raw); ok {
		t.Error("parseStunPublic should fail for BindingRequest")
	}
}

func TestRateLimiterUnlimited(t *testing.T) {
	l := newRateLimiter(0) // 0 = 不限速
	start := time.Now()
	l.wait(1 << 20)
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("unlimited limiter should return immediately, took %v", d)
	}
}

func TestRateLimiterThrottles(t *testing.T) {
	l := newRateLimiter(1000) // 1000 bytes/s，桶容量 1000
	start := time.Now()
	l.wait(1000) // 首次需累积满 1 秒配额
	d := time.Since(start)
	if d < 800*time.Millisecond || d > 1800*time.Millisecond {
		t.Errorf("wait(1000) @1000B/s should take ~1s, took %v", d)
	}
}

func TestAllocPort(t *testing.T) {
	p, err := allocPort()
	if err != nil {
		t.Fatalf("allocPort: %v", err)
	}
	if p < 20000 || p > 65000 {
		t.Errorf("allocPort = %d, want in [20000, 65000]", p)
	}
	if !portFree(p) {
		t.Errorf("allocPort returned occupied port %d", p)
	}
}

func TestManagerCRUD(t *testing.T) {
	m := newTestManager(t)
	created, err := m.Create(Hole{Name: "test", Proto: "udp", Target: "127.0.0.1:8080"}, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" || created.ListenPort == 0 {
		t.Fatalf("Create returned invalid hole: %+v", created)
	}

	// List 应包含该通道
	list := m.List()
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("List = %+v, want single channel %s", list, created.ID)
	}

	// Get
	got, ok := m.Get(created.ID)
	if !ok || got.Name != "test" {
		t.Fatalf("Get = %+v ok=%v", got, ok)
	}

	// Update
	updated, err := m.Update(created.ID, Hole{Name: "renamed", Proto: "udp", Target: "127.0.0.1:9090"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "renamed" || updated.Target != "127.0.0.1:9090" {
		t.Fatalf("Update result = %+v", updated)
	}

	// Delete
	if err := m.Delete(created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(m.List()) != 0 {
		t.Fatalf("after Delete, List should be empty, got %d", len(m.List()))
	}
}

// TestUpdatePreservesWebhookChannel 回归：编辑 auto/custom 通道时不得清空后端回写的 webhook_channel。
func TestUpdatePreservesWebhookChannel(t *testing.T) {
	m := newTestManager(t)
	created, err := m.Create(Hole{Name: "auto", Proto: "udp", Target: "127.0.0.1:8080", WebhookMode: "auto"}, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// 模拟联动首次触发后后端回写通道 ID
	m.SetWebhookChannel(created.ID, "1")

	// 编辑（auto 模式不变，请求体不携带 webhook_channel）
	updated, err := m.Update(created.ID, Hole{Name: "auto", Proto: "udp", Target: "127.0.0.1:8080", WebhookMode: "auto", WebhookTrigger: "every_probe"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.WebhookChannel != "1" {
		t.Errorf("webhook_channel should be preserved, got %q", updated.WebhookChannel)
	}

	// 切换到 select 模式时，应改用请求携带的通道 ID
	updated, err = m.Update(created.ID, Hole{Name: "auto", Proto: "udp", Target: "127.0.0.1:8080", WebhookMode: "select", WebhookChannel: "42"})
	if err != nil {
		t.Fatalf("Update to select: %v", err)
	}
	if updated.WebhookChannel != "42" {
		t.Errorf("select mode should apply requested channel, got %q", updated.WebhookChannel)
	}

	// select 切回 auto：应清空通道 ID，等待首次联动重新分配
	updated, err = m.Update(created.ID, Hole{Name: "auto", Proto: "udp", Target: "127.0.0.1:8080", WebhookMode: "auto"})
	if err != nil {
		t.Fatalf("Update back to auto: %v", err)
	}
	if updated.WebhookChannel != "" {
		t.Errorf("switch to auto should clear channel, got %q", updated.WebhookChannel)
	}
}

// TestNoDeadlockSetStatusAndList 回归：setStatus 与 List 并发不得死锁（此前 setStatus 持 r.mu 调 addLogL → m.mu，与 List 的 m.mu→r.mu 形成 AB-BA 死锁）。
func TestNoDeadlockSetStatusAndList(t *testing.T) {
	m := newTestManager(t)
	created, err := m.Create(Hole{Name: "x", Proto: "udp", Target: "127.0.0.1:8080"}, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	m.mu.Lock()
	r := m.holes[created.ID]
	m.mu.Unlock()
	if r == nil {
		t.Fatal("runtime not found")
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			r.setStatus("starting", "test")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			m.List()
		}
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: setStatus/List did not complete")
	}
}

// TestMaxFailuresTripsAutoStop 连续打洞失败达到上限后通道应自动熔断：
// 唯一候选为非法端口地址（解析立即失败，零网络依赖），约 2 次轮换间隔后触发。
func TestMaxFailuresTripsAutoStop(t *testing.T) {
	m := newTestManager(t)
	m.SetStunServers([]StunServer{{Addr: "127.0.0.1:99999", Proto: "udp"}})
	created, err := m.Create(Hole{
		Name: "fuse", Proto: "udp", Target: "127.0.0.1:8080", MaxFailures: 3,
	}, true)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := m.Get(created.ID)
		if !got.Running && !got.Enabled && got.Status == "error" {
			if !strings.Contains(got.LastError, "连续 3 次") {
				t.Fatalf("LastError = %q, want 包含连续失败次数", got.LastError)
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	got, _ := m.Get(created.ID)
	t.Fatalf("熔断未触发: Running=%v Enabled=%v Status=%q LastError=%q",
		got.Running, got.Enabled, got.Status, got.LastError)
}

// TestStartStopEnabledSync 回归：Start 应置 Enabled=true、Stop 应置 Enabled=false，
// 使服务重启后 Restore 能按 Enabled 正确恢复运行中的通道。
func TestStartStopEnabledSync(t *testing.T) {
	m := newTestManager(t)
	created, err := m.Create(Hole{Name: "x", Proto: "udp", Target: "127.0.0.1:8080"}, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, _ := m.Get(created.ID); got.Enabled {
		t.Error("forceStart=false 时 Enabled 应为 false")
	}

	m.Start(created.ID)
	got, _ := m.Get(created.ID)
	if !got.Enabled || !got.Running {
		t.Errorf("Start 后应 Enabled=true 且 Running=true，got Enabled=%v Running=%v", got.Enabled, got.Running)
	}

	m.Stop(created.ID)
	got, _ = m.Get(created.ID)
	if got.Enabled || got.Running {
		t.Errorf("Stop 后应 Enabled=false 且 Running=false，got Enabled=%v Running=%v", got.Enabled, got.Running)
	}
}

