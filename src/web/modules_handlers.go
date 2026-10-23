package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"go.uber.org/zap"
)

// ============= 模块管理 =============
//
// 允许用户关闭暂不使用的功能模块：关闭后前端不再展示其导航入口，直接访问该页也会被拦下。
// 刻意不影响已运行的服务（已启动的隧道 / 转发规则照常工作），避免「关掉模块把隧道关了」这类意外。
// 仪表盘与系统设置（模块管理在其中）为常驻模块——允许关闭会失去重新开启的入口。

// allowDisableModules 允许被关闭的模块 id 白名单（与前端 MODULES 清单保持一致）。
var allowDisableModules = map[string]bool{
	"stun":       true,
	"tunnel":     true,
	"forward":    true,
	"webhook":    true,
	"mefrp":      true,
	"lolia":      true,
	"cloudflare": true,
	"dns":        true,
	"portscan":   true,
	"wol":        true,
	"waf":        true,
	"webserver":  true,
}

// normalizeDisabledModules 过滤非白名单项并去重。
// 后端必须自行校验：直接调接口可绕过界面限制，若混入常驻 id（如 settings）会让界面被锁死。
func normalizeDisabledModules(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || !allowDisableModules[id] || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// allowDisableModulesList 白名单列表（一并返回给前端，便于核对清单是否漂移）。
func allowDisableModulesList() []string {
	out := make([]string, 0, len(allowDisableModules))
	for id := range allowDisableModules {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// handleModulesGet 读取已关闭模块列表。
func (s *Server) handleModulesGet(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	disabled := append([]string(nil), s.cfg.Modules.Disabled...)
	s.cfgMu.RUnlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"disabled": normalizeDisabledModules(disabled),
		"allow":    allowDisableModulesList(),
	}))
}

// handleModulesSave 保存已关闭模块列表（即时生效，无需「保存设置」）。
func (s *Server) handleModulesSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Disabled []string `json:"disabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	disabled := normalizeDisabledModules(req.Disabled)
	s.cfgMu.Lock()
	s.cfg.Modules.Disabled = disabled
	s.cfgMu.Unlock()
	s.persistConfig("modules.disabled", disabled)
	s.logger.Info("模块启用状态已更新", zap.Strings("disabled", disabled))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"disabled": disabled}))
}
