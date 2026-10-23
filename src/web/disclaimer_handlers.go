package web

import (
	"net/http"
	"time"
)

// ============= 使用免责声明 =============
//
// 同意状态存服务端 SQLite（settings KV），不能存浏览器 localStorage：
// localStorage 按「设备 + 浏览器」隔离，每换一台设备都会重复弹窗；
// 服务端记录后，所有设备共享同一份确认状态，全局只需同意一次。
//   - disclaimer.shown_at：免责声明首次展示的时间（RFC3339，仅记录第一次）
//   - disclaimer.agreed_at：用户点击「我已阅读并同意」的时间（RFC3339，空串=未同意）

const (
	settingDisclaimerShownAt  = "disclaimer.shown_at"
	settingDisclaimerAgreedAt = "disclaimer.agreed_at"
)

// disclaimerState 读取两个时间戳（读失败按空串处理：未同意时下次请求会补写）。
func (s *Server) disclaimerState() (shownAt, agreedAt string) {
	shownAt, _ = s.store.GetSetting(settingDisclaimerShownAt)
	agreedAt, _ = s.store.GetSetting(settingDisclaimerAgreedAt)
	return
}

// handleDisclaimerGet 返回免责声明状态。
// 未同意时顺带把「首次弹窗时间」落库——只在为空时写一次，已存在不覆盖。
func (s *Server) handleDisclaimerGet(w http.ResponseWriter, r *http.Request) {
	shownAt, agreedAt := s.disclaimerState()
	if agreedAt == "" && shownAt == "" {
		shownAt = time.Now().Format(time.RFC3339)
		_ = s.store.SetSetting(settingDisclaimerShownAt, shownAt)
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"agreed":    agreedAt != "",
		"shown_at":  shownAt,
		"agreed_at": agreedAt,
	}))
}

// handleDisclaimerAgree 记录用户同意时间（幂等：重复提交不覆盖首次确认时间）。
func (s *Server) handleDisclaimerAgree(w http.ResponseWriter, r *http.Request) {
	shownAt, agreedAt := s.disclaimerState()
	now := time.Now().Format(time.RFC3339)
	// 正常流程 shown_at 已由 GET 写入；直接调 POST（或写库失败）时在此补齐
	if shownAt == "" {
		shownAt = now
		_ = s.store.SetSetting(settingDisclaimerShownAt, now)
	}
	if agreedAt == "" {
		agreedAt = now
		_ = s.store.SetSetting(settingDisclaimerAgreedAt, now)
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"agreed":    true,
		"shown_at":  shownAt,
		"agreed_at": agreedAt,
	}))
}
