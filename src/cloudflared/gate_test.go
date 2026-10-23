package cloudflared

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestGateProxyAndPause 闸门的两条路径：
// 未暂停时透传到真实本地服务，暂停时直接回 503 且完全不碰真实服务。
// 这正是「暂停后访客看到 503，而隧道连接与访问地址保持不变」的实现方式。
func TestGateProxyAndPause(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("TARGET"))
	}))
	defer target.Close()

	gate := NewGate(target.URL, nil)
	url, err := gate.Start()
	if err != nil {
		t.Fatalf("启动闸门失败: %v", err)
	}
	defer gate.Stop()
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("闸门应只监听本地回环，实际 %q", url)
	}

	if code, body := gateGet(t, url, ""); code != http.StatusOK || body != "TARGET" {
		t.Errorf("未暂停时应透传到真实服务，实际 %d %q", code, body)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("真实服务应被访问 1 次，实际 %d", got)
	}

	gate.SetPaused(true)
	if !gate.Paused() {
		t.Error("SetPaused(true) 后 Paused() 应为 true")
	}
	// 非浏览器请求：回退为纯文本，不塞 HTML
	if code, body := gateGet(t, url, ""); code != http.StatusServiceUnavailable || !strings.Contains(body, "隧道已暂停") {
		t.Errorf("暂停时应返回 503 纯文本，实际 %d %q", code, body)
	}
	// 浏览器请求：用「错误页面」模块里的 503 页面
	if code, body := gateGet(t, url, "text/html,application/xhtml+xml"); code != http.StatusServiceUnavailable || !strings.Contains(body, "<html") {
		t.Errorf("暂停时浏览器应拿到 503 页面，实际 %d %q", code, body)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("暂停期间不应访问真实服务，实际访问 %d 次", got)
	}

	gate.SetPaused(false)
	if code, body := gateGet(t, url, ""); code != http.StatusOK || body != "TARGET" {
		t.Errorf("恢复后应再次透传，实际 %d %q", code, body)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("恢复后真实服务应被再访问 1 次，实际 %d", got)
	}

	// Stop 需可重复调用，且关闭后不再接受连接
	gate.Stop()
	gate.Stop()
	if resp, err := http.Get(url); err == nil {
		resp.Body.Close()
		t.Error("闸门关闭后不应再接受连接")
	}
}

// TestGateRejectsInvalidTarget 目标地址不合法时必须在 Start 阶段报错，
// 而不是等到 cloudflared 连上来才发现。
func TestGateRejectsInvalidTarget(t *testing.T) {
	for _, target := range []string{"", "127.0.0.1:8080", "ftp://127.0.0.1:8080"} {
		gate := NewGate(target, nil)
		if _, err := gate.Start(); err == nil {
			gate.Stop()
			t.Errorf("目标地址 %q 不合法，Start 应报错", target)
		}
	}
}

// TestGateSetTargetSwapsOrigin 闸门可在不重启隧道的前提下切换回源。
// 这是「编辑本地地址后访问地址不被重置」的实现基础：cloudflared 始终指向闸门，换源只是闸门内部的事。
func TestGateSetTargetSwapsOrigin(t *testing.T) {
	oldSvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OLD"))
	}))
	defer oldSvc.Close()
	newSvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("NEW"))
	}))
	defer newSvc.Close()

	gate := NewGate(oldSvc.URL, nil)
	url, err := gate.Start()
	if err != nil {
		t.Fatalf("启动闸门失败: %v", err)
	}
	defer gate.Stop()

	if code, body := gateGet(t, url, ""); code != http.StatusOK || body != "OLD" {
		t.Fatalf("初始应转发到旧回源，实际 %d %q", code, body)
	}
	if err := gate.SetTarget(newSvc.URL); err != nil {
		t.Fatalf("切换回源失败: %v", err)
	}
	// 闸门地址没变，说明隧道无需重启
	if code, body := gateGet(t, url, ""); code != http.StatusOK || body != "NEW" {
		t.Errorf("切换后应立即走新回源，实际 %d %q", code, body)
	}
	// 非法目标必须被拒绝，且不得破坏既有转发
	if err := gate.SetTarget("127.0.0.1:8080"); err == nil {
		t.Error("非法回源地址应报错")
	}
	if code, body := gateGet(t, url, ""); code != http.StatusOK || body != "NEW" {
		t.Errorf("非法目标不应影响既有转发，实际 %d %q", code, body)
	}
}

// TestGateCountsTraffic 闸门在连接层统计上下行字节。
// 必须是连接层口径：GET 没有请求体，若只统计请求体，上行会恒为 0，
// 「端口转发」列表的实时速率列看着就像坏了（且与 STUN/frpc 的 socket 口径不一致）。
func TestGateCountsTraffic(t *testing.T) {
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte("response-payload"))
	}))
	defer svc.Close()

	gate := NewGate(svc.URL, nil)
	url, err := gate.Start()
	if err != nil {
		t.Fatalf("启动闸门失败: %v", err)
	}
	defer gate.Stop()
	if gate.Addr() == "" {
		t.Error("监听中应能拿到闸门地址")
	}

	// GET：没有请求体，上行仍应统计到请求报文
	if code, body := gateGet(t, url, ""); code != http.StatusOK || body != "response-payload" {
		t.Fatalf("GET 应正常透传，实际 %d %q", code, body)
	}
	txGet, rxGet, activeGet := gate.Counters()
	if txGet <= 0 {
		t.Errorf("GET 的上行应统计到请求报文（含报文头），实际 %d 字节", txGet)
	}
	if rxGet < int64(len("response-payload")) {
		t.Errorf("下行应至少覆盖响应体，实际 %d 字节", rxGet)
	}
	if activeGet != 0 {
		t.Errorf("请求结束后活跃数应归零，实际 %d", activeGet)
	}

	// POST 带 1KB 请求体：上行增量必须覆盖请求体本身
	payload := bytes.Repeat([]byte("x"), 1024)
	resp, err := http.Post(url, "text/plain", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST 闸门失败: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	txPost, rxPost, _ := gate.Counters()
	if got := txPost - txGet; got < int64(len(payload)) {
		t.Errorf("POST 相对 GET 的上行增量应不少于请求体大小 %d，实际 %d", len(payload), got)
	}
	if rxPost <= rxGet {
		t.Errorf("下行累计应随请求增长，实际 %d → %d", rxGet, rxPost)
	}

	gate.Stop()
	if gate.Addr() != "" {
		t.Error("关闭后不应再报告监听地址")
	}
}

func gateGet(t *testing.T, url, accept string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求闸门失败: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
