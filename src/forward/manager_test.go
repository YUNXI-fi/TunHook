package forward

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"

	"tunhook/config"

	"go.uber.org/zap"
)

type protocolModeTestListener struct{}

func (protocolModeTestListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (protocolModeTestListener) Close() error              { return nil }
func (protocolModeTestListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestHTTPForwarderRejectsProtocolModeChange(t *testing.T) {
	p := &httpProxy{
		localAddr:  "127.0.0.1:18080",
		logger:     zap.NewNop(),
		routes:     make(map[string]*httpRoute),
		tlsCerts:   make(map[string]*tls.Certificate),
		listener:   protocolModeTestListener{},
		servingTLS: false,
	}
	httpProxyRegMu.Lock()
	httpProxyReg[p.localAddr] = p
	httpProxyRegMu.Unlock()
	t.Cleanup(func() { removeHTTPProxy(p.localAddr) })

	f := &httpForwarder{
		localAddr: p.localAddr,
		domain:    "secure.example.com",
		isTLS:     true,
		logger:    zap.NewNop(),
	}
	if err := f.Start(); err == nil {
		t.Fatal("expected adding HTTPS route to running HTTP listener to fail")
	}
	if len(p.routes) != 0 {
		t.Fatalf("failed route must be rolled back, got %d routes", len(p.routes))
	}
}

func TestNewManager(t *testing.T) {
	logger := zap.NewNop()
	mgr := NewManager(logger, nil)
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestManagerStartStopRule(t *testing.T) {
	logger := zap.NewNop()
	mgr := NewManager(logger, nil)

	rule := config.ForwardRule{
		Protocol:   "tcp",
		LocalAddr:  "127.0.0.1",
		LocalPort:  0,
		RemoteAddr: "127.0.0.1",
		RemotePort: 80,
	}

	err := mgr.StartRule(rule)
	if err != nil {
		t.Fatalf("StartRule: %v", err)
	}

	rules := mgr.RunningRules()
	if len(rules) != 1 {
		t.Errorf("expected 1 running rule, got %d", len(rules))
	}

	mgr.StopRule(rule)
	rules = mgr.RunningRules()
	if len(rules) != 0 {
		t.Errorf("expected 0 running rules, got %d", len(rules))
	}
}

func TestManagerStopAll(t *testing.T) {
	logger := zap.NewNop()
	mgr := NewManager(logger, nil)

	rule := config.ForwardRule{
		Protocol:   "tcp",
		LocalAddr:  "127.0.0.1",
		LocalPort:  0,
		RemoteAddr: "127.0.0.1",
		RemotePort: 80,
	}

	mgr.StartRule(rule)
	mgr.StopAll()

	rules := mgr.RunningRules()
	if len(rules) != 0 {
		t.Errorf("expected 0 running rules after StopAll, got %d", len(rules))
	}
}

func TestRuleKey(t *testing.T) {
	rule := config.ForwardRule{
		Protocol:   "tcp",
		LocalAddr:  "0.0.0.0",
		LocalPort:  8080,
		RemoteAddr: "192.168.1.1",
		RemotePort: 80,
	}

	key := ruleKey(rule)
	expected := "tcp://0.0.0.0:8080->192.168.1.1:80"
	if key != expected {
		t.Errorf("ruleKey = %q, want %q", key, expected)
	}
}
