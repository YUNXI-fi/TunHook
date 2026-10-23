package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"image"
	_ "image/jpeg" // 注册 JPEG 解码器（image.Decode 使用）
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"tunhook/config"

	"go.uber.org/zap"
)

//go:embed hookpage
var hookPageFS embed.FS

// ============= 导航页（/hook） =============
// 简化自 STUN 面板的导航页：集中展示 Webhook 接收器已注册的通道（按分组卡片），
// 以及转发规则列表与 frpc 代理列表（可分别开关），点击卡片直达访问地址。
// 页面公开可看，右上角提供管理密码登录入口（仅登录校验，不限制访问）。访问地址 /hook
// 与通道访问 /{channel_id} 同源；关闭开关后 /hook 及其数据接口返回 404。

// hookDefaultAdminPass 导航页管理密码默认值（配置未设置时使用）
const hookDefaultAdminPass = "TunHook"

// hookIconVariants 导航页图标固定文件名（icons/ 目录下，按格式区分）。
func hookIconVariants() []string {
	return []string{"hook_icon.png", "hook_icon.jpg", "hook_icon.ico", "hook_icon.svg"}
}

// hookEnabled 返回导航页开关状态。
func (s *Server) hookEnabled() bool {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg.Hook.Enabled
}

// 本地搜索引擎图标（static/ 嵌入目录下的 SVG），供默认引擎回填
var defaultEngineIcons = map[string]string{
	"bing":     "/static/bing.svg",
	"google":   "/static/Google.svg",
	"bilibili": "/static/bilibili.svg",
	"douyin":   "/static/douyin.svg",
}

// hookConfigView 返回导航页公开配置（供页面应用标题/图标/搜索栏/分区显隐/搜索引擎与自定义 UI）。
func (s *Server) hookConfigView() map[string]any {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	// 默认引擎图标：已保存配置若缺少图标（旧数据），自动回填本地 SVG
	engines := make([]config.SearchEngineConfig, len(s.cfg.Hook.SearchEngines))
	for i, e := range s.cfg.Hook.SearchEngines {
		engines[i] = e
		if e.Icon == "" {
			if icon, ok := defaultEngineIcons[e.ID]; ok {
				engines[i].Icon = icon
			}
		}
	}
	return map[string]any{
		"title":             s.cfg.Hook.Title,
		"local_ip":          s.localIP, // 本机局域网 IPv4，供前端拼转发/通道直连地址
		"search_engine":     s.cfg.Hook.SearchEngine,
		"search_engines":    engines,
		"show_search":       s.cfg.Hook.ShowSearch,
		"icon":              s.cfg.Hook.Icon,
		"show_webhook":      s.cfg.Hook.ShowWebhook,
		"show_forwards":     s.cfg.Hook.ShowForwards,
		"show_proxies":      s.cfg.Hook.ShowProxies,
		"clock_enabled":     s.cfg.Hook.ClockEnabled,
		"clock_format":      s.cfg.Hook.ClockFormat,
		"wall_source":       s.cfg.Hook.WallSource,
		"wall_api":          s.cfg.Hook.WallAPI,
		"wall_url":          s.cfg.Hook.WallURL,
		"wall_upload":       s.cfg.Hook.WallUpload,
		"wall_blur":         s.cfg.Hook.WallBlur,
		"wall_mask":         s.cfg.Hook.WallMask,
		"wall_mask_opacity": s.cfg.Hook.WallMaskOpacity,
		"footer_text":       s.cfg.Hook.FooterText,
		"content_max_width": s.cfg.Hook.ContentMaxWidth,
		"side_margin":       s.cfg.Hook.SideMargin,
		"top_margin":        s.cfg.Hook.TopMargin,
		"bottom_margin":     s.cfg.Hook.BottomMargin,
		"show_stats":        s.cfg.Hook.ShowStats,
	}
}

// hookForwardViews 转发规则公开列表（仅当前运行中的规则，导航页只展示运行项）。
func (s *Server) hookForwardViews() []map[string]any {
	keys := s.fwdMgr.RunningRules()
	views := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		v := s.hookForwardView(k)
		if v["running"] == true { // 只显示运行中，暂停/停止的规则不再出现在导航页
			views = append(views, v)
		}
	}
	sort.Slice(views, func(i, j int) bool { return views[i]["key"].(string) < views[j]["key"].(string) })
	return views
}

// hookForwardView 单条转发规则的公开视图。
func (s *Server) hookForwardView(key string) map[string]any {
	v := map[string]any{"key": key}
	proto := key
	if idx := strings.Index(key, "://"); idx >= 0 {
		proto = strings.ToUpper(key[:idx])
	}
	v["protocol"] = proto
	if rule, err := parseRuleKey(key); err == nil {
		if rule.Name != "" {
			v["name"] = rule.Name
		}
		if rule.Domain != "" {
			v["domain"] = rule.Domain
		}
		if rule.LocalPort > 0 {
			v["local_port"] = rule.LocalPort
		}
	}
	if desc := s.getDesc("forward", key); desc != "" {
		v["description"] = desc
	}
	if s.isForwardRunning(key) {
		v["running"] = true
	}
	return v
}

// hookProxyViews frpc 代理公开列表（仅当前运行中的代理，导航页只展示运行项）。
func (s *Server) hookProxyViews() []map[string]any {
	cfg := s.frpcMgr.LoadConfig()
	states, _, _ := s.frpcProxyRuntime()
	views := make([]map[string]any, 0, len(cfg.Proxies))
	for _, p := range cfg.Proxies {
		st, ok := states[p.Name]
		if !ok || st != "running" {
			continue // 只显示运行中，未启用/连接中/异常/状态未知的代理不展示
		}
		v := map[string]any{
			"name":    p.Name,
			"type":    p.Type,
			"enabled": p.Enabled,
			"status":  st,
		}
		if p.LocalPort != 0 {
			v["local_port"] = p.LocalPort
		}
		if p.RemotePort != 0 {
			v["remote_port"] = p.RemotePort
		}
		if p.CustomDomains != "" {
			v["custom_domains"] = p.CustomDomains
		}
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool { return views[i]["name"].(string) < views[j]["name"].(string) })
	return views
}

// handleHookIndex 导航页入口：输出 hook.html；开关关闭时 404。
func (s *Server) handleHookIndex(w http.ResponseWriter, r *http.Request) {
	if !s.hookEnabled() {
		http.NotFound(w, r)
		return
	}
	data, err := hookPageFS.ReadFile("hookpage/hook.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 页面内容随版本更新（内联脚本/样式），禁止任何缓存，确保刷新即最新
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// img-src 允许 http(s)/data:/blob: 供自定义壁纸（API 随机图 / 图片链接 / 本地上传）与缓存对象URL；
	// connect-src 允许 http(s) 供壁纸抓取写入 Cache Storage。
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob: https: http:; connect-src 'self' https: http:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Write(data)
}

// handleHookData 导航页数据源（公开）：Webhook 通道分组 + 转发/代理列表 + 页面配置。
func (s *Server) handleHookData(w http.ResponseWriter, r *http.Request) {
	if !s.hookEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	recs := s.whRecv.list()
	groups := map[string][]map[string]any{}
	for _, rec := range recs {
		isOnline := rec.PublicIP != "" && rec.PublicPort != 0
		if !isOnline {
			continue // 只显示在线通道，从未上报/无连接端点的通道不展示
		}
		g := rec.Group
		if g == "" {
			g = "default"
		}
		groups[g] = append(groups[g], map[string]any{
			"channel_id":    rec.ChannelID,
			"custom_id":     rec.CustomID,
			"custom_domain": rec.CustomDomain,
			"description":   rec.Description,
			"group":         rec.Group,
			"online":        isOnline,
			"password":      rec.Password != "", // 仅标记是否启用密码，不暴露密码本身
		})
	}
	names := make([]string, 0, len(groups))
	for g := range groups {
		names = append(names, g)
	}
	// 排序：default 分组优先，其余按名称字母序，保证展示稳定
	sort.Slice(names, func(i, j int) bool {
		if names[i] == "default" {
			return true
		}
		if names[j] == "default" {
			return false
		}
		return names[i] < names[j]
	})
	out := make([]map[string]any, 0, len(names))
	for _, g := range names {
		out = append(out, map[string]any{"name": g, "channels": groups[g]})
	}
	forwards := s.hookForwardViews()
	proxies := s.hookProxyViews()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]any{
		"groups":   out,
		"forwards": forwards,
		"proxies":  proxies,
		"config":   s.hookConfigView(),
	}))
}

// handleHookAuth 导航页管理密码登录校验（右上角登录入口，页面本身公开）：
// POST {"password":"..."}，与配置 hook.admin_pass（默认 TunHook）一致返回成功，否则 401。
func (s *Server) handleHookAuth(w http.ResponseWriter, r *http.Request) {
	if !s.hookEnabled() {
		http.NotFound(w, r)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	if err := dec.Decode(&body); err != nil || strings.TrimSpace(body.Password) == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请输入管理密码"))
		return
	}
	pass := s.cfg.Hook.AdminPass
	if pass == "" {
		pass = hookDefaultAdminPass
	}
	if body.Password != pass {
		s.writeJSON(w, http.StatusUnauthorized, apiErr("管理密码错误"))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]any{"success": true}))
}

// hookAdminAuthorized 校验 /hook 设置请求的管理密码（Authorization: Bearer <管理密码>）
func (s *Server) hookAdminAuthorized(r *http.Request) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	pass := s.cfg.Hook.AdminPass
	if pass == "" {
		pass = hookDefaultAdminPass
	}
	return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == pass
}

// hookAdminRequired 包装需要管理密码认证的处理器（Webhook 端口开放的导航页管理操作）
func (s *Server) hookAdminRequired(f func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hookAdminAuthorized(r) {
			s.writeJSON(w, http.StatusUnauthorized, apiErr("请先登录"))
			return
		}
		f(w, r)
	})
}

// handleHookSettings 修改导航页设置（需已登录：Authorization: Bearer <管理密码>）：
// POST 支持导航页基础配置与自定义 UI（时钟/壁纸/页脚/内容布局/统计条）。
func (s *Server) handleHookSettings(w http.ResponseWriter, r *http.Request) {
	if !s.hookEnabled() {
		http.NotFound(w, r)
		return
	}
	if !s.hookAdminAuthorized(r) {
		s.writeJSON(w, http.StatusUnauthorized, apiErr("请先登录"))
		return
	}
	var body struct {
		Title           *string                      `json:"title"`
		AdminPass       *string                      `json:"admin_pass"`
		ShowSearch      *bool                        `json:"show_search"`
		ShowWebhook     *bool                        `json:"show_webhook"`
		ShowForwards    *bool                        `json:"show_forwards"`
		ShowProxies     *bool                        `json:"show_proxies"`
		SearchEngine    *string                      `json:"search_engine"`
		SearchEngines   *[]config.SearchEngineConfig `json:"search_engines"`
		ClockEnabled    *bool                        `json:"clock_enabled"`
		ClockFormat     *string                      `json:"clock_format"`
		WallSource      *string                      `json:"wall_source"`
		WallAPI         *string                      `json:"wall_api"`
		WallURL         *string                      `json:"wall_url"`
		WallUpload      *string                      `json:"wall_upload"`
		WallBlur        *int                         `json:"wall_blur"`
		WallMask        *bool                        `json:"wall_mask"`
		WallMaskOpacity *int                         `json:"wall_mask_opacity"`
		FooterText      *string                      `json:"footer_text"`
		ContentMaxWidth *int                         `json:"content_max_width"`
		SideMargin      *int                         `json:"side_margin"`
		TopMargin       *int                         `json:"top_margin"`
		BottomMargin    *int                         `json:"bottom_margin"`
		ShowStats       *bool                        `json:"show_stats"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 512*1024))
	if err := dec.Decode(&body); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求参数格式错误"))
		return
	}
	clamp := func(v, lo, hi int) int {
		if v < lo {
			return lo
		}
		if v > hi {
			return hi
		}
		return v
	}
	s.cfgMu.Lock()
	if body.Title != nil {
		title := strings.TrimSpace(*body.Title)
		if title == "" {
			title = "通道导航"
		}
		if len([]rune(title)) > 20 {
			s.cfgMu.Unlock()
			s.writeJSON(w, http.StatusBadRequest, apiErr("页面标题不能超过 20 个字符"))
			return
		}
		s.cfg.Hook.Title = title
		s.persistConfig("hook.title", title)
	}
	if body.AdminPass != nil {
		ap := strings.TrimSpace(*body.AdminPass)
		if ap != "" {
			if len([]rune(ap)) < 6 || len([]rune(ap)) > 64 {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("管理密码长度需为 6-64 位"))
				return
			}
			s.cfg.Hook.AdminPass = ap
			s.persistConfig("hook.admin_pass", ap)
		}
	}
	if body.ShowSearch != nil {
		s.cfg.Hook.ShowSearch = *body.ShowSearch
		s.persistConfig("hook.show_search", *body.ShowSearch)
	}
	if body.ShowWebhook != nil {
		s.cfg.Hook.ShowWebhook = *body.ShowWebhook
		s.persistConfig("hook.show_webhook", *body.ShowWebhook)
	}
	if body.ShowForwards != nil {
		s.cfg.Hook.ShowForwards = *body.ShowForwards
		s.persistConfig("hook.show_forwards", *body.ShowForwards)
	}
	if body.ShowProxies != nil {
		s.cfg.Hook.ShowProxies = *body.ShowProxies
		s.persistConfig("hook.show_proxies", *body.ShowProxies)
	}
	// ---- 搜索引擎（列表整体替换 + 默认引擎） ----
	if body.SearchEngines != nil {
		engines := make([]config.SearchEngineConfig, 0, len(*body.SearchEngines))
		seen := map[string]bool{}
		for _, e := range *body.SearchEngines {
			id := strings.TrimSpace(e.ID)
			title := strings.TrimSpace(e.Title)
			url := strings.TrimSpace(e.URL)
			icon := strings.TrimSpace(e.Icon)
			if id == "" || title == "" || url == "" || seen[id] || len(seen) >= 20 {
				continue
			}
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				continue
			}
			// 图标链接可选：仅保留 http(s) 或 data:image 类型
			if icon != "" && !strings.HasPrefix(icon, "http://") && !strings.HasPrefix(icon, "https://") && !strings.HasPrefix(icon, "data:image/") {
				icon = ""
			}
			seen[id] = true
			engines = append(engines, config.SearchEngineConfig{ID: id, Title: title, URL: url, Icon: icon})
		}
		if len(engines) == 0 {
			s.cfgMu.Unlock()
			s.writeJSON(w, http.StatusBadRequest, apiErr("至少需要一个有效的搜索引擎"))
			return
		}
		cur := s.cfg.Hook.SearchEngine
		if !seen[cur] {
			cur = engines[0].ID
		}
		s.cfg.Hook.SearchEngines = engines
		s.cfg.Hook.SearchEngine = cur
		s.persistConfig("hook.search_engines", engines)
		s.persistConfig("hook.search_engine", cur)
	}
	if body.SearchEngine != nil {
		se := strings.TrimSpace(*body.SearchEngine)
		if se != "" {
			valid := false
			for _, e := range s.cfg.Hook.SearchEngines {
				if e.ID == se {
					valid = true
					break
				}
			}
			if !valid {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("默认搜索引擎不存在"))
				return
			}
			s.cfg.Hook.SearchEngine = se
			s.persistConfig("hook.search_engine", se)
		}
	}
	// ---- 自定义 UI ----
	if body.ClockEnabled != nil {
		s.cfg.Hook.ClockEnabled = *body.ClockEnabled
		s.persistConfig("hook.clock_enabled", *body.ClockEnabled)
	}
	if body.ClockFormat != nil {
		f := *body.ClockFormat
		if f != "24h" && f != "24h-ns" && f != "12h" {
			f = "24h"
		}
		s.cfg.Hook.ClockFormat = f
		s.persistConfig("hook.clock_format", f)
	}
	if body.WallSource != nil {
		src := *body.WallSource
		if src != "api" && src != "url" && src != "upload" {
			src = "api"
		}
		s.cfg.Hook.WallSource = src
		s.persistConfig("hook.wall_source", src)
	}
	if body.WallAPI != nil {
		s.cfg.Hook.WallAPI = strings.TrimSpace(*body.WallAPI)
		s.persistConfig("hook.wall_api", s.cfg.Hook.WallAPI)
	}
	if body.WallURL != nil {
		s.cfg.Hook.WallURL = strings.TrimSpace(*body.WallURL)
		s.persistConfig("hook.wall_url", s.cfg.Hook.WallURL)
	}
	if body.WallUpload != nil {
		// 空串表示不修改（避免误清），仅接受非空的上传 dataURL
		if strings.TrimSpace(*body.WallUpload) != "" {
			if len(*body.WallUpload) > 6*1024*1024 {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("壁纸图片过大（超过 6MB）"))
				return
			}
			s.cfg.Hook.WallUpload = *body.WallUpload
			s.persistConfig("hook.wall_upload", s.cfg.Hook.WallUpload)
		}
	}
	if body.WallBlur != nil {
		s.cfg.Hook.WallBlur = clamp(*body.WallBlur, 0, 20)
		s.persistConfig("hook.wall_blur", s.cfg.Hook.WallBlur)
	}
	if body.WallMask != nil {
		s.cfg.Hook.WallMask = *body.WallMask
		s.persistConfig("hook.wall_mask", *body.WallMask)
	}
	if body.WallMaskOpacity != nil {
		s.cfg.Hook.WallMaskOpacity = clamp(*body.WallMaskOpacity, 0, 100)
		s.persistConfig("hook.wall_mask_opacity", s.cfg.Hook.WallMaskOpacity)
	}
	if body.FooterText != nil {
		s.cfg.Hook.FooterText = strings.TrimSpace(*body.FooterText)
		s.persistConfig("hook.footer_text", s.cfg.Hook.FooterText)
	}
	if body.ContentMaxWidth != nil {
		s.cfg.Hook.ContentMaxWidth = clamp(*body.ContentMaxWidth, 50, 100)
		s.persistConfig("hook.content_max_width", s.cfg.Hook.ContentMaxWidth)
	}
	if body.SideMargin != nil {
		s.cfg.Hook.SideMargin = clamp(*body.SideMargin, 0, 200)
		s.persistConfig("hook.side_margin", s.cfg.Hook.SideMargin)
	}
	if body.TopMargin != nil {
		s.cfg.Hook.TopMargin = clamp(*body.TopMargin, 0, 50)
		s.persistConfig("hook.top_margin", s.cfg.Hook.TopMargin)
	}
	if body.BottomMargin != nil {
		s.cfg.Hook.BottomMargin = clamp(*body.BottomMargin, 0, 50)
		s.persistConfig("hook.bottom_margin", s.cfg.Hook.BottomMargin)
	}
	if body.ShowStats != nil {
		s.cfg.Hook.ShowStats = *body.ShowStats
		s.persistConfig("hook.show_stats", *body.ShowStats)
	}
	s.cfgMu.Unlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]any{"success": true}))
}

// 本地搜索引擎 SVG 图标白名单（static/ 嵌入目录，仅允许这 4 个）
var engineIconFiles = map[string]string{
	"bing.svg":     "image/svg+xml",
	"Google.svg":   "image/svg+xml",
	"bilibili.svg": "image/svg+xml",
	"douyin.svg":   "image/svg+xml",
}

// fallbackEngineIcon 内置通用搜索图标：即使某个引擎 SVG 因构建丢失（vite emptyOutDir 清空 static
// 且不在 public 目录时）也返回该图标，保证搜索引擎图标永不 404。
const fallbackEngineIcon = `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="2"/><path d="m16.5 16.5 4 4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`

// handleEngineStaticIcon 提供本地搜索引擎 SVG 图标（白名单，静态资源允许长缓存）
func (s *Server) handleEngineStaticIcon(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ct, ok := engineIconFiles[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	data, err := staticFS.ReadFile("static/" + name)
	if err != nil {
		// 兜底：内置 SVG 缺失时返回通用搜索图标，避免图标加载失败（404）
		w.Write([]byte(fallbackEngineIcon))
		return
	}
	w.Write(data)
}

// ============= 导航页图标（PNG/JPG 裁剪 256×256；ICO/SVG 原样存储） =============

// processHookIcon 将上传的 PNG/JPG 图标居中裁剪为 1:1 后缩放至 256×256，输出 PNG。
func processHookIcon(data []byte) ([]byte, error) {
	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	dst := cropSquareResize(src, 256)
	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// detectIconFormat 按文件内容识别图标格式，返回 (扩展名, Content-Type, 是否合法)。
// 支持：PNG / JPG / ICO / SVG（不信任用户提供的文件名）。
func detectIconFormat(data []byte) (string, string, bool) {
	if len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		return ".png", "image/png", true
	}
	if len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff {
		return ".jpg", "image/jpeg", true
	}
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{0x00, 0x00, 0x01, 0x00}) {
		return ".ico", "image/x-icon", true
	}
	head := strings.ToLower(strings.TrimSpace(string(data[:min(len(data), 512)])))
	if strings.Contains(head, "<svg") || strings.HasPrefix(head, "<?xml") {
		return ".svg", "image/svg+xml", true
	}
	return "", "", false
}

// svgSafe 扫描 SVG 内容中的脚本注入特征（与 STUN 面板一致）。
func svgSafe(data []byte) bool {
	low := strings.ToLower(string(data))
	if strings.Contains(low, "<script") || strings.Contains(low, "javascript:") ||
		strings.Contains(low, "onload=") || strings.Contains(low, "onerror=") ||
		strings.Contains(low, "onclick=") || strings.Contains(low, "foreignobject") {
		return false
	}
	return true
}

// iconContentType 返回导航页图标文件对应的 Content-Type。
func iconContentType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".ico":
		return "image/x-icon"
	case ".svg":
		return "image/svg+xml"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	default:
		return "image/png"
	}
}

// handleHookIcon 输出导航页图标（公开；未设置时 404）。
func (s *Server) handleHookIcon(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	name := s.cfg.Hook.Icon
	s.cfgMu.RUnlock()
	if name == "" {
		http.NotFound(w, r)
		return
	}
	dir := s.iconsDir()
	p := filepath.Join(dir, name)
	// 防路径穿越：确保最终路径位于 icons 目录内
	if !strings.HasPrefix(p, filepath.Clean(dir)) {
		http.NotFound(w, r)
		return
	}
	if _, err := os.Stat(p); err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", iconContentType(name))
	// 图标会随上传更新，禁止浏览器长缓存
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, p)
}

// handleHookIconUpload 上传导航页图标（multipart 字段名 icon）：
// 支持 PNG/JPG/ICO/SVG；PNG/JPG 裁剪缩放为 256×256 PNG，ICO/SVG 原样存储；
// 原始大小不超过 2MB，SVG 扫描脚本注入。
func (s *Server) handleHookIconUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20+64<<10)
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体过大或非法"))
		return
	}
	file, header, err := r.FormFile("icon")
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少图标文件"))
		return
	}
	defer file.Close()
	if header.Size > 2<<20 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("图标大小不能超过 2MB"))
		return
	}
	data, err := io.ReadAll(file)
	if err != nil || len(data) == 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("图标文件读取失败"))
		return
	}
	ext, _, ok := detectIconFormat(data)
	if !ok {
		s.writeJSON(w, http.StatusBadRequest, apiErr("仅支持 PNG / JPG / ICO / SVG 格式"))
		return
	}
	if ext == ".svg" && !svgSafe(data) {
		s.writeJSON(w, http.StatusBadRequest, apiErr("SVG 内容包含不安全的脚本"))
		return
	}
	// PNG/JPG 裁剪缩放为 256×256 PNG；ICO/SVG 原样存储
	fileName := "hook_icon" + ext
	if ext == ".png" || ext == ".jpg" {
		out, err := processHookIcon(data)
		if err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiErr("图片无法解码，请更换 PNG/JPG 图片"))
			return
		}
		data = out
		fileName = "hook_icon.png"
	}
	dir := s.iconsDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("图标目录创建失败"))
		return
	}
	// 清理旧格式图标，避免残留
	for _, old := range hookIconVariants() {
		os.Remove(filepath.Join(dir, old))
	}
	if err := os.WriteFile(filepath.Join(dir, fileName), data, 0644); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("图标保存失败"))
		return
	}
	s.cfgMu.Lock()
	s.cfg.Hook.Icon = fileName
	s.persistConfig("hook.icon", fileName)
	s.cfgMu.Unlock()
	s.logger.Info("导航页图标已更新", zap.String("file", fileName))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]any{"icon": fileName}))
}

// handleHookIconDelete 删除导航页图标（恢复默认，无图标时幂等）。
func (s *Server) handleHookIconDelete(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.Lock()
	had := s.cfg.Hook.Icon != ""
	s.cfg.Hook.Icon = ""
	s.persistConfig("hook.icon", "")
	s.cfgMu.Unlock()
	if had {
		for _, n := range hookIconVariants() {
			os.Remove(filepath.Join(s.iconsDir(), n))
		}
		s.logger.Info("导航页图标已删除")
	}
	s.writeJSON(w, http.StatusOK, apiOK(nil))
}
