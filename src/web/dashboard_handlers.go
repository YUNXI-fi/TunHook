package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"tunhook/config"

	"go.uber.org/zap"
)

// ============= 仪表盘布局 =============
//
// 保存 KPI 概览与卡片各自的顺序与显隐，供用户按自己的关注点调整仪表盘。
// 布局项清单由前端定义（卡片内容在前端 markup 中），后端只做结构校验与持久化：
// 数量上限、id 去重与非空、长度限制。这里不做 id 白名单——白名单会导致前后端清单漂移，
// 而布局数据即便被写入未知 id 也只会被前端忽略（不会造成功能异常或界面锁死）。
// 数据放配置项，随备份导出/恢复与重启自动保留。

// dashboardLayoutLimit 单个列表（KPI / 卡片）的条目上限，防异常数据撑爆配置。
const dashboardLayoutLimit = 40

// dashboardFieldLimit 单项（卡片）内部可隐藏字段的数量上限。
const dashboardFieldLimit = 30

// normalizeFieldList 校验卡片内的字段 id 列表（被隐藏的行 / 行的显示顺序）：
// 丢弃空值与重复项，限制单项长度与数量。返回 nil 表示无该配置（等价于全部显示 / 默认顺序）。
func normalizeFieldList(fields []string, limit int) []string {
	out := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" || len(f) > 40 || seen[f] {
			continue
		}
		if len(out) >= limit {
			break
		}
		seen[f] = true
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeDashboardItems 结构校验：丢弃空 id 与重复 id，限制长度与数量。
func normalizeDashboardItems(items []config.DashboardItem) []config.DashboardItem {
	out := make([]config.DashboardItem, 0, len(items))
	seen := map[string]bool{}
	for _, it := range items {
		id := strings.TrimSpace(it.ID)
		if id == "" || len(id) > 40 || seen[id] {
			continue
		}
		if len(out) >= dashboardLayoutLimit {
			break
		}
		seen[id] = true
		out = append(out, config.DashboardItem{
			ID:           id,
			Visible:      it.Visible,
			HiddenFields: normalizeFieldList(it.HiddenFields, dashboardFieldLimit),
			FieldOrder:   normalizeFieldList(it.FieldOrder, dashboardFieldLimit),
		})
	}
	return out
}

// handleDashboardLayoutGet 读取仪表盘布局（未设置过时返回空列表，前端按默认布局渲染）。
func (s *Server) handleDashboardLayoutGet(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	kpis := append([]config.DashboardItem(nil), s.cfg.Dashboard.KPIs...)
	cards := append([]config.DashboardItem(nil), s.cfg.Dashboard.Cards...)
	s.cfgMu.RUnlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"kpis":  normalizeDashboardItems(kpis),
		"cards": normalizeDashboardItems(cards),
	}))
}

// handleDashboardLayoutSave 保存仪表盘布局（即时生效，无需「保存设置」）。
func (s *Server) handleDashboardLayoutSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KPIs  []config.DashboardItem `json:"kpis"`
		Cards []config.DashboardItem `json:"cards"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	kpis := normalizeDashboardItems(req.KPIs)
	cards := normalizeDashboardItems(req.Cards)
	s.cfgMu.Lock()
	s.cfg.Dashboard.KPIs = kpis
	s.cfg.Dashboard.Cards = cards
	s.cfgMu.Unlock()
	s.persistConfig("dashboard.kpis", kpis)
	s.persistConfig("dashboard.cards", cards)
	s.logger.Info("仪表盘布局已更新", zap.Int("kpis", len(kpis)), zap.Int("cards", len(cards)))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"kpis":  kpis,
		"cards": cards,
	}))
}
