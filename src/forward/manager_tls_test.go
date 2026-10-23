package forward

import (
	"testing"

	"tunhook/config"

	"go.uber.org/zap"
)

// TestManagerUpdateRuleWithTLS 模拟用户在已有 TCP 规则上开启 TLS 的更新流程。
func TestManagerUpdateRuleWithTLS(t *testing.T) {
	logger := zap.NewNop()
	mgr := NewManager(logger, nil)

	// 1) 先启动一个无 TLS 的 TCP 规则
	base := config.ForwardRule{
		Protocol:   "tcp",
		LocalAddr:  "127.0.0.1",
		LocalPort:  0,
		RemoteAddr: "127.0.0.1",
		RemotePort: 80,
	}
	if err := mgr.StartRule(base); err != nil {
		t.Fatalf("StartRule base failed: %v", err)
	}
	baseKey := ruleKey(base)
	if mgr.IsTLS(baseKey) {
		t.Fatalf("expected IsTLS=false for base rule")
	}

	// 2) 模拟用户开启 TLS
	updated := base
	updated.TLSEnable = true

	// 与 handleForwardUpdate 相同的逻辑：先停再启
	mgr.StopRule(base)
	if err := mgr.StartRule(updated); err != nil {
		t.Fatalf("StartRule with TLSEnable failed: %v", err)
	}

	newKey := ruleKey(updated)
	if newKey != baseKey {
		t.Errorf("rule key changed unexpectedly: old=%s new=%s", baseKey, newKey)
	}
	if !mgr.IsTLS(newKey) {
		t.Errorf("expected IsTLS=true after enabling TLS")
	}

	// 3) 模拟再次关闭 TLS
	updated2 := updated
	updated2.TLSEnable = false
	mgr.StopRule(updated)
	if err := mgr.StartRule(updated2); err != nil {
		t.Fatalf("StartRule without TLSEnable failed: %v", err)
	}
	if mgr.IsTLS(newKey) {
		t.Errorf("expected IsTLS=false after disabling TLS")
	}

	mgr.StopRule(updated2)
}
