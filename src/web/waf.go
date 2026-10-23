package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ============= WAF 防火墙 =============
//
// 保护对象：
//   - 自身 Web 管理界面与 API（scope=admin）
//   - Webhook 通道访问入口（scope=webhook）
//   - frpc HTTP 代理经 TunHook 的本地反代层（scope=frpc）
//
// 检测内容：URL、请求体（限 256KB）、User-Agent、Cookie/Referer。
// 两种模式：observe（只记录不拦截）、block（命中返回 403）。
// 内置规则默认全部启用，误报风险高的规则可在界面单独关闭。

const (
	wafSettingsKey = "waf.settings"
	wafRulesKey    = "waf.rules"
	wafLogLimit    = 500
	wafMaxBody     = 256 << 10 // 单请求最多检查 256KB 请求体
)

// wafSettings WAF 全局设置。
type wafSettings struct {
	Enabled bool            `json:"enabled"` // 总开关
	Mode    string          `json:"mode"`    // observe(观察) / block(拦截)
	Builtin map[string]bool `json:"builtin"` // 内置规则 id → 是否启用
}

// wafCustomRule 用户自定义规则。
type wafCustomRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Field   string `json:"field"`   // url / body / ua / header / method
	Pattern string `json:"pattern"` // 正则表达式
}

// wafRulesStore 自定义规则的持久化结构。
type wafRulesStore struct {
	Rules []wafCustomRule `json:"rules"`
}

// wafCompiledRule 编译后的自定义规则（保存/加载时构建，避免每请求重复编译）。
type wafCompiledRule struct {
	Rule wafCustomRule
	Re   *regexp.Regexp
}

// wafBuiltinRule 内置规则定义。Targets 取值：url / body / ua / header。
type wafBuiltinRule struct {
	ID      string
	Name    string
	Targets []string
	Re      *regexp.Regexp
}

// wafBuiltinRules 内置规则集。正则按 Go RE2 语法编写，避免灾难性回溯。
var wafBuiltinRules = []wafBuiltinRule{
	{
		ID:      "sqli",
		Name:    "SQL 注入",
		Targets: []string{"url", "body", "header"},
		Re: regexp.MustCompile(`(?i)(\bunion\b[\s+/]+(\ball\b[\s+/]+)?\bselect\b` +
			`|\bselect\b[\s\S]{1,80}\bfrom\b` +
			`|\binsert\b[\s\S]{1,40}\binto\b` +
			`|\bdelete\b[\s\S]{1,40}\bfrom\b` +
			`|\bdrop\b[\s\S]{1,20}\btable\b` +
			`|\bupdate\b[\s\S]{1,60}\bset\b` +
			`|\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+` +
			`|sleep\s*\(|benchmark\s*\(|information_schema|load_file\s*\()`),
	},
	{
		ID:      "xss",
		Name:    "XSS 跨站脚本",
		Targets: []string{"url", "body", "header"},
		Re: regexp.MustCompile(`(?i)(<\s*script\b|javascript\s*:` +
			`|on(error|load|click|mouseover|focus)\s*=` +
			`|<\s*iframe\b|<\s*svg[^>]*\bonload|\bdocument\.(cookie|location)\b)`),
	},
	{
		ID:      "traversal",
		Name:    "路径穿越",
		Targets: []string{"url", "body"},
		Re: regexp.MustCompile(`(?i)(\.\.[/\\]|%2e%2e(%2f|/|%5c|\\)` +
			`|/etc/(passwd|shadow)|/proc/self/|c:\\windows\\)`),
	},
	{
		ID:      "cmdi",
		Name:    "命令注入",
		Targets: []string{"url", "body"},
		Re: regexp.MustCompile(`(?i)([;|]\s*(cat|ls|whoami|id|wget|curl|bash|sh|nc)\b` +
			`|\$\(|\x60|%60)`),
	},
	{
		ID:      "scanner",
		Name:    "恶意扫描器",
		Targets: []string{"ua"},
		Re: regexp.MustCompile(`(?i)(sqlmap|nikto|nmap|masscan|acunetix|nessus|` +
			`dirbuster|gobuster|wpscan|hydra|metasploit|zgrab|nuclei)`),
	},
	{
		ID:      "sensitive_path",
		Name:    "敏感路径探测",
		Targets: []string{"url"},
		Re: regexp.MustCompile(`(?i)(/wp-(admin|login\.php)|/phpmyadmin|/\.git/` +
			`|/\.env(\b|$)|/actuator/|/adminer\.php|/cgi-bin/|/shell\.php|/xmlrpc\.php)`),
	},
}

// wafHit WAF 命中记录（内存环形缓冲，最新在前）。
type wafHit struct {
	Time   string `json:"time"`
	Scope  string `json:"scope"`  // admin / webhook / frpc
	IP     string `json:"ip"`     // 客户端 IP
	Method string `json:"method"` // 请求方法
	Path   string `json:"path"`   // 请求路径（含查询串，过长截断）
	Rule   string `json:"rule"`   // 命中的规则名
	Action string `json:"action"` // observe / block
}

// defaultWafSettings 首次启用时的默认设置：默认关闭、观察模式、内置规则全开。
func defaultWafSettings() wafSettings {
	m := make(map[string]bool, len(wafBuiltinRules))
	for _, r := range wafBuiltinRules {
		m[r.ID] = true
	}
	return wafSettings{Enabled: false, Mode: "observe", Builtin: m}
}

// wafEnsureLoaded 惰性加载设置与自定义规则（保存后由保存接口直接更新缓存）。
func (s *Server) wafEnsureLoaded() {
	s.wafMu.RLock()
	loaded := s.wafLoaded
	s.wafMu.RUnlock()
	if loaded {
		return
	}
	s.wafMu.Lock()
	defer s.wafMu.Unlock()
	if s.wafLoaded {
		return
	}
	cfg := defaultWafSettings()
	if raw, err := s.store.GetSetting(wafSettingsKey); err == nil && raw != "" {
		var c wafSettings
		if json.Unmarshal([]byte(raw), &c) == nil {
			if c.Mode != "block" {
				c.Mode = "observe"
			}
			if c.Builtin == nil {
				c.Builtin = map[string]bool{}
			}
			// 新增内置规则时自动补为启用，避免升级后规则缺失
			for _, r := range wafBuiltinRules {
				if _, ok := c.Builtin[r.ID]; !ok {
					c.Builtin[r.ID] = true
				}
			}
			cfg = c
		}
	}
	var st wafRulesStore
	if raw, err := s.store.GetSetting(wafRulesKey); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	s.wafCfg = cfg
	s.wafRules = st.Rules
	s.wafCompiled = compileWafRules(st.Rules)
	s.wafLoaded = true
}

// wafSnapshot 返回当前设置与已编译规则（请求路径上的快速读取）。
func (s *Server) wafSnapshot() (wafSettings, []wafCompiledRule) {
	s.wafEnsureLoaded()
	s.wafMu.RLock()
	defer s.wafMu.RUnlock()
	return s.wafCfg, s.wafCompiled
}

// compileWafRules 编译启用状态的自定义规则，非法正则直接跳过（保存时已校验）。
func compileWafRules(rules []wafCustomRule) []wafCompiledRule {
	out := make([]wafCompiledRule, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		out = append(out, wafCompiledRule{Rule: r, Re: re})
	}
	return out
}

// wafURLText 返回用于检测的 URL 文本：路径 + 原始查询串 + 解码后的查询串。
// 解码后能识别 %20union%20select 这类编码绕过，原文能保留 %2e%2e 等编码特征。
func wafURLText(u *url.URL) string {
	text := u.Path
	if u.RawQuery != "" {
		decoded := u.RawQuery
		if d, err := url.QueryUnescape(u.RawQuery); err == nil {
			decoded = d
		}
		text += "?" + u.RawQuery + "\n?" + decoded
	}
	return text
}

// matchWaf 对请求各字段执行内置与自定义规则，返回命中的规则名（未命中返回空）。
// targets 键：url / body / ua / header；请求方法单独传入。
func matchWaf(cfg wafSettings, rules []wafCompiledRule, method string, targets map[string]string) string {
	targetValue := func(field string) string {
		if field == "method" {
			return method
		}
		return targets[field]
	}
	// 内置规则优先：按固定顺序返回第一条命中
	for _, br := range wafBuiltinRules {
		if !cfg.Builtin[br.ID] {
			continue
		}
		for _, t := range br.Targets {
			if v := targetValue(t); v != "" && br.Re.MatchString(v) {
				return br.Name
			}
		}
	}
	// 自定义规则
	for _, cr := range rules {
		if v := targetValue(cr.Rule.Field); v != "" && cr.Re.MatchString(v) {
			return cr.Rule.Name
		}
	}
	return ""
}

// wafGuardHTTP 检查单个请求：命中且为拦截模式时直接写 403 并返回 true。
func (s *Server) wafGuardHTTP(w http.ResponseWriter, r *http.Request, scope string) bool {
	// WAF 管理接口自身不做检测：保存规则时请求体里可能就包含攻击特征字符串
	if strings.HasPrefix(r.URL.Path, "/api/waf/") {
		return false
	}
	cfg, rules := s.wafSnapshot()
	if !cfg.Enabled {
		return false
	}

	urlText := wafURLText(r.URL)
	uaText := r.UserAgent()
	headerText := strings.Join([]string{
		r.Header.Get("Cookie"),
		r.Header.Get("Referer"),
	}, "\n")

	// 仅对文本类请求体做检查；恢复 body 供后续处理器正常读取
	var bodyText string
	if wafShouldInspectBody(r) {
		orig := r.Body
		head, _ := io.ReadAll(io.LimitReader(orig, wafMaxBody))
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(head), orig))
		bodyText = string(head)
	}

	targets := map[string]string{
		"url":    urlText,
		"body":   bodyText,
		"ua":     uaText,
		"header": headerText,
	}
	hitRule := matchWaf(cfg, rules, r.Method, targets)
	if hitRule == "" {
		return false
	}

	action := "observe"
	if cfg.Mode == "block" {
		action = "block"
	}
	// 日志只记录原始请求路径，避免把解码后的检测文本写进日志
	logPath := r.URL.Path
	if r.URL.RawQuery != "" {
		logPath += "?" + r.URL.RawQuery
	}
	logPath = truncateWafPath(logPath)
	s.addWafHit(wafHit{
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Scope:  scope,
		IP:     clientIP(r),
		Method: r.Method,
		Path:   logPath,
		Rule:   hitRule,
		Action: action,
	})
	if action == "block" {
		if s.logger != nil {
			s.logger.Warn("WAF 拦截请求",
				zap.String("scope", scope), zap.String("ip", clientIP(r)),
				zap.String("method", r.Method), zap.String("path", logPath),
				zap.String("rule", hitRule))
		}
		s.writeJSON(w, http.StatusForbidden, apiErr("请求被 WAF 拦截："+hitRule))
		return true
	}
	return false
}

// wafShouldInspectBody 判断是否需要读取请求体：只检查文本类型，跳过上传与长连接。
func wafShouldInspectBody(r *http.Request) bool {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return false
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	for _, t := range []string{"application/json", "application/x-www-form-urlencoded", "text/", "application/xml", "application/graphql"} {
		if strings.Contains(ct, t) {
			return true
		}
	}
	return false
}

// truncateWafPath 截断过长的请求路径，避免日志被超长 URL 撑爆。
func truncateWafPath(p string) string {
	if len(p) > 512 {
		return p[:512] + "…"
	}
	return p
}

// addWafHit 写入命中日志（环形缓冲，最新在前）。
func (s *Server) addWafHit(h wafHit) {
	s.wafLogMu.Lock()
	defer s.wafLogMu.Unlock()
	s.wafLogs = append([]wafHit{h}, s.wafLogs...)
	if len(s.wafLogs) > wafLogLimit {
		s.wafLogs = s.wafLogs[:wafLogLimit]
	}
}

// wafMiddleware 把 WAF 挂到 HTTP handler 前；scope 标识流量来源。
func (s *Server) wafMiddleware(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.wafGuardHTTP(w, r, scope) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ============= API =============

// handleWafSettingsGet 返回 WAF 设置。
func (s *Server) handleWafSettingsGet(w http.ResponseWriter, r *http.Request) {
	cfg, _ := s.wafSnapshot()
	s.writeJSON(w, http.StatusOK, apiOK(cfg))
}

// handleWafSettingsSave 保存 WAF 设置（总开关 / 模式 / 内置规则开关）。
func (s *Server) handleWafSettingsSave(w http.ResponseWriter, r *http.Request) {
	var req wafSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	if req.Mode != "block" {
		req.Mode = "observe"
	}
	normalized := make(map[string]bool, len(wafBuiltinRules))
	for _, br := range wafBuiltinRules {
		v, ok := req.Builtin[br.ID]
		normalized[br.ID] = ok && v
	}
	req.Builtin = normalized
	if err := s.store.SetJSON(wafSettingsKey, req); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("保存 WAF 设置失败: "+err.Error()))
		return
	}
	s.wafMu.Lock()
	s.wafCfg = req
	s.wafLoaded = true
	s.wafMu.Unlock()
	s.writeJSON(w, http.StatusOK, apiOK(req))
}

// handleWafRulesGet 返回自定义规则。
func (s *Server) handleWafRulesGet(w http.ResponseWriter, r *http.Request) {
	s.wafEnsureLoaded()
	s.wafMu.RLock()
	rules := append([]wafCustomRule(nil), s.wafRules...)
	s.wafMu.RUnlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"rules": rules}))
}

// handleWafRulesSave 整体保存自定义规则：校验字段与正则，补齐 ID 后落库。
func (s *Server) handleWafRulesSave(w http.ResponseWriter, r *http.Request) {
	var req wafRulesStore
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	validFields := map[string]bool{"url": true, "body": true, "ua": true, "header": true, "method": true}
	out := make([]wafCustomRule, 0, len(req.Rules))
	seen := map[string]bool{}
	for _, rule := range req.Rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			s.writeJSON(w, http.StatusBadRequest, apiErr("规则名称不能为空"))
			return
		}
		if len([]rune(name)) > 64 {
			s.writeJSON(w, http.StatusBadRequest, apiErr("「"+name+"」名称不能超过 64 个字符"))
			return
		}
		field := strings.ToLower(strings.TrimSpace(rule.Field))
		if !validFields[field] {
			s.writeJSON(w, http.StatusBadRequest, apiErr("「"+name+"」检测位置无效"))
			return
		}
		pattern := strings.TrimSpace(rule.Pattern)
		if pattern == "" {
			s.writeJSON(w, http.StatusBadRequest, apiErr("「"+name+"」正则不能为空"))
			return
		}
		if len(pattern) > 500 {
			s.writeJSON(w, http.StatusBadRequest, apiErr("「"+name+"」正则不能超过 500 个字符"))
			return
		}
		if _, err := regexp.Compile(pattern); err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiErr("「"+name+"」正则无效: "+err.Error()))
			return
		}
		id := strings.TrimSpace(rule.ID)
		if id == "" || seen[id] {
			id = strconv.FormatInt(time.Now().UnixNano(), 36)
		}
		seen[id] = true
		out = append(out, wafCustomRule{
			ID: id, Name: name, Enabled: rule.Enabled, Field: field, Pattern: pattern,
		})
	}
	if err := s.store.SetJSON(wafRulesKey, wafRulesStore{Rules: out}); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("保存 WAF 规则失败: "+err.Error()))
		return
	}
	s.wafMu.Lock()
	s.wafRules = out
	s.wafCompiled = compileWafRules(out)
	s.wafLoaded = true
	s.wafMu.Unlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"rules": out}))
}

// handleWafLogsGet 返回命中日志（最新在前）。
func (s *Server) handleWafLogsGet(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= wafLogLimit {
		limit = v
	}
	s.wafLogMu.Lock()
	logs := append([]wafHit(nil), s.wafLogs...)
	s.wafLogMu.Unlock()
	if len(logs) > limit {
		logs = logs[:limit]
	}
	if logs == nil {
		logs = []wafHit{}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"logs": logs}))
}

// handleWafLogsClear 清空命中日志。
func (s *Server) handleWafLogsClear(w http.ResponseWriter, r *http.Request) {
	s.wafLogMu.Lock()
	s.wafLogs = nil
	s.wafLogMu.Unlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"ok": true}))
}
