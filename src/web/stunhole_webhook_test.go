package web

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"tunhook/store"
	"tunhook/stunhole"

	"go.uber.org/zap"
)

// newTestReceiver 构造带临时库的最小 whReceiver（仅供测试）。
func newTestReceiver(t *testing.T) *whReceiver {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	srv := &Server{store: st, logger: zap.NewNop()}
	return &whReceiver{
		s:       srv,
		records: map[string]*whRecord{},
		groups:  map[string]bool{defaultGroupName: true},
		logs:    map[string]*LogBuffer{},
		hist:    map[string]*compHistory{},
	}
}

// TestEnsureStunChannelAutoNoDeadlock 回归：ensureStunChannel 在 auto 模式（id 空）分配 ID 时，
// 不得在持有写锁时调用 allocateID（其内部 RLock），否则 RWMutex 重入死锁。
func TestEnsureStunChannelAutoNoDeadlock(t *testing.T) {
	r := newTestReceiver(t)
	type res struct {
		cid string
	}
	ch := make(chan res, 1)
	go func() {
		cid := r.ensureStunChannel("", "stun-test", "1.2.3.4", 8080, stunWhOpts{}, r.allocateID)
		ch <- res{cid}
	}()
	select {
	case v := <-ch:
		if v.cid == "" {
			t.Fatal("expected non-empty channel id from auto allocation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("deadlock: ensureStunChannel blocked on allocateID")
	}
}

// TestEnsureStunChannelCreatesWithOpts 验证 custom 模式创建时写入回调配置。
func TestEnsureStunChannelCreatesWithOpts(t *testing.T) {
	r := newTestReceiver(t)
	opts := stunWhOpts{URL: "https://example.com/cb", Method: "POST", Body: "{}", Headers: "X-Source: stun", Callback: "secret", NoCheck: false}
	cid := r.ensureStunChannel("", "stun-test", "1.2.3.4", 8080, opts, r.allocateID)
	if cid == "" {
		t.Fatal("expected non-empty channel id")
	}
	rec := r.get(cid)
	if rec == nil {
		t.Fatalf("channel %s not created", cid)
	}
	if rec.WebhookURL != opts.URL || rec.WebhookMethod != "POST" || rec.CallbackChar != "secret" || rec.WebhookHeaders != "X-Source: stun" {
		t.Errorf("opts not applied: %+v", rec)
	}
	if rec.PublicIP != "1.2.3.4" || rec.PublicPort != 8080 {
		t.Errorf("public not set: %s:%d", rec.PublicIP, rec.PublicPort)
	}
}

// TestEnsureStunChannelUpdatesExisting 验证通道已存在时仅更新地址，不重建。
func TestEnsureStunChannelUpdatesExisting(t *testing.T) {
	r := newTestReceiver(t)
	r.records["9"] = &whRecord{ChannelID: "9", Description: "已有", PublicIP: "1.1.1.1", PublicPort: 1111}
	cid := r.ensureStunChannel("9", "stun-test", "2.2.2.2", 2222, stunWhOpts{}, nil)
	if cid != "9" {
		t.Fatalf("expected channel 9, got %q", cid)
	}
	rec := r.get("9")
	if rec.PublicIP != "2.2.2.2" || rec.PublicPort != 2222 {
		t.Errorf("public not updated: %s:%d", rec.PublicIP, rec.PublicPort)
	}
	if rec.Description != "已有" {
		t.Errorf("description should be preserved, got %q", rec.Description)
	}
}

// TestUpdateStunPublic 验证仅更新已存在通道的公网地址。
func TestUpdateStunPublic(t *testing.T) {
	r := newTestReceiver(t)
	r.records["5"] = &whRecord{ChannelID: "5", PublicIP: "1.1.1.1", PublicPort: 1111}
	r.updateStunPublic("5", "stun-test", "3.3.3.3", 3333)
	rec := r.get("5")
	if rec.PublicIP != "3.3.3.3" || rec.PublicPort != 3333 {
		t.Errorf("public not updated: %s:%d", rec.PublicIP, rec.PublicPort)
	}
	// 不存在的通道应被忽略（不 panic、不创建）
	r.updateStunPublic("999", "stun-test", "4.4.4.4", 4444)
	if r.get("999") != nil {
		t.Error("updateStunPublic should not create missing channel")
	}
}

// TestNormalizeStunWebhook 验证三种联动模式的校验与归一化。
func TestNormalizeStunWebhook(t *testing.T) {
	r := newTestReceiver(t)
	srv := &Server{store: r.s.store, logger: zap.NewNop(), whRecv: r}

	// auto：清空通道 ID，校验分组存在
	h := &stunhole.Hole{WebhookMode: "auto", WebhookGroup: "Webhook 通道", WebhookChannel: "1"}
	if msg := srv.normalizeStunWebhook(h); msg != "" {
		t.Fatalf("auto normalize: %s", msg)
	}
	if h.WebhookChannel != "" {
		t.Errorf("auto should clear channel, got %q", h.WebhookChannel)
	}

	// auto：不存在的分组应报错
	h = &stunhole.Hole{WebhookMode: "auto", WebhookGroup: "不存在"}
	if msg := srv.normalizeStunWebhook(h); msg == "" {
		t.Error("auto with missing group should fail")
	}

	// custom：URL 非 http(s) 应报错
	h = &stunhole.Hole{WebhookMode: "custom", WebhookURL: "ftp://x", WebhookMethod: "POST"}
	if msg := srv.normalizeStunWebhook(h); msg == "" {
		t.Error("custom with bad url should fail")
	}

	// custom：非法请求方式应报错
	h = &stunhole.Hole{WebhookMode: "custom", WebhookURL: "https://x", WebhookMethod: "FOO"}
	if msg := srv.normalizeStunWebhook(h); msg == "" {
		t.Error("custom with bad method should fail")
	}

	// custom：合法配置通过，方法归一化为大写
	h = &stunhole.Hole{WebhookMode: "custom", WebhookURL: "https://x", WebhookMethod: "post", WebhookCallback: "s"}
	if msg := srv.normalizeStunWebhook(h); msg != "" {
		t.Fatalf("custom normalize: %s", msg)
	}
	if h.WebhookMethod != "POST" {
		t.Errorf("method should be upper-cased, got %q", h.WebhookMethod)
	}

	// select / 空：归一化为 select
	h = &stunhole.Hole{WebhookMode: "", WebhookChannel: " 42 "}
	if msg := srv.normalizeStunWebhook(h); msg != "" {
		t.Fatalf("empty mode normalize: %s", msg)
	}
	if h.WebhookMode != "select" || h.WebhookChannel != "42" {
		t.Errorf("empty mode should normalize to select, got mode=%q channel=%q", h.WebhookMode, h.WebhookChannel)
	}

	// 非法触发条件应报错
	h = &stunhole.Hole{WebhookMode: "select", WebhookTrigger: "bogus"}
	if msg := srv.normalizeStunWebhook(h); msg == "" {
		t.Error("bad trigger should fail")
	}
}

// TestDeleteStunHoleCleansWebhook 回归：删除 STUN 通道时，auto/custom 模式"一同创建"的
// 联动 Webhook 通道应一并删除；select 模式关联的用户已有通道应保留。
func TestDeleteStunHoleCleansWebhook(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	mgr := stunhole.NewManager(st, zap.NewNop())
	srv := &Server{store: st, logger: zap.NewNop(), stunholeMgr: mgr}
	srv.whRecv = &whReceiver{
		s:       srv,
		records: map[string]*whRecord{},
		groups:  map[string]bool{defaultGroupName: true},
		logs:    map[string]*LogBuffer{},
		hist:    map[string]*compHistory{},
	}

	// auto 模式：删除 STUN 通道应一并删除联动 Webhook 通道
	h, err := mgr.Create(stunhole.Hole{Name: "auto", Proto: "udp", Target: "127.0.0.1:8080", WebhookMode: "auto"}, false)
	if err != nil {
		t.Fatalf("Create auto: %v", err)
	}
	mgr.SetWebhookChannel(h.ID, "1")
	srv.whRecv.records["1"] = &whRecord{ChannelID: "1", Description: "STUN · auto"}

	req := httptest.NewRequest("DELETE", "/api/stunhole/"+h.ID, nil)
	req.SetPathValue("id", h.ID)
	rec := httptest.NewRecorder()
	srv.handleStunHoleDelete(rec, req)
	if rec.Code != 200 {
		t.Errorf("delete status = %d", rec.Code)
	}
	if len(mgr.List()) != 0 {
		t.Error("stun hole should be deleted")
	}
	if srv.whRecv.get("1") != nil {
		t.Error("auto-linked webhook channel should be deleted")
	}

	// select 模式：删除 STUN 通道不应删除关联的已有 Webhook 通道
	h2, err := mgr.Create(stunhole.Hole{Name: "sel", Proto: "udp", Target: "127.0.0.1:8080", WebhookMode: "select", WebhookChannel: "2"}, false)
	if err != nil {
		t.Fatalf("Create select: %v", err)
	}
	srv.whRecv.records["2"] = &whRecord{ChannelID: "2", Description: "用户已有通道"}

	req2 := httptest.NewRequest("DELETE", "/api/stunhole/"+h2.ID, nil)
	req2.SetPathValue("id", h2.ID)
	rec2 := httptest.NewRecorder()
	srv.handleStunHoleDelete(rec2, req2)
	if srv.whRecv.get("2") == nil {
		t.Error("select-linked webhook channel should be preserved")
	}
}
