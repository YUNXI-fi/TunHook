package web

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tunhook/mefrp"

	"go.uber.org/zap"
)

// ============= MEFrp 云端隧道 API =============
//
// 接入 ME Frp 幻缘映射开放 API：验证访问密钥、同步隧道列表、
// 拉取服务端生成的 frpc 配置并作为独立进程启动（不进「内网穿透」服务器列表）。

// mefrpListTTL 隧道列表缓存时长（MEFrp 服务端本身有约 5 分钟 Redis 缓存，
// 客户端短缓存可减少请求量、降低被 WAF 拦截概率；前端可带 refresh=1 强刷）。
const mefrpListTTL = 60 * time.Second

// mefrpClient 按当前配置构造 MEFrp 客户端。
func (s *Server) mefrpClient() *mefrp.Client {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return mefrp.NewClient(s.cfg.MEFRP.Token)
}

// maskToken 访问密钥脱敏展示（保留前 4 后 4 位）。
func maskToken(t string) string {
	if len(t) <= 8 {
		return "****"
	}
	return t[:4] + "****" + t[len(t)-4:]
}

// handleMefrpConfigGet 读取 MEFrp 配置（token 脱敏）。
func (s *Server) handleMefrpConfigGet(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	token := s.cfg.MEFRP.Token
	s.cfgMu.RUnlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"configured": strings.TrimSpace(token) != "",
		"token":      maskToken(strings.TrimSpace(token)),
	}))
}

// handleMefrpConfigSave 保存访问密钥：立即调 /auth/user/info 验证，成功才落库。
func (s *Server) handleMefrpConfigSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("访问密钥不能为空"))
		return
	}
	user, err := mefrp.NewClient(token).UserInfo()
	if err != nil {
		s.logger.Warn("MEFrp 密钥验证失败", zap.Error(err))
		s.writeJSON(w, http.StatusOK, apiErr("密钥验证失败: "+err.Error()))
		return
	}
	s.cfgMu.Lock()
	s.cfg.MEFRP.Token = token
	s.cfgMu.Unlock()
	s.persistConfig("mefrp.token", token)
	s.logger.Info("MEFrp 访问密钥已保存", zap.String("username", user.Username))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"token": maskToken(token),
		"user":  user,
	}))
}

// handleMefrpTunnels 获取隧道列表（60s 缓存，refresh=1 强制刷新）。
func (s *Server) handleMefrpTunnels(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("refresh") == "1"
	s.mefrpMu.Lock()
	list, at := s.mefrpList, s.mefrpListAt
	if force || list == nil || time.Since(at) > mefrpListTTL {
		var err error
		list, err = s.mefrpClient().ProxyList()
		if err != nil {
			s.mefrpMu.Unlock()
			if errors.Is(err, mefrp.ErrBlocked) {
				s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
			} else {
				s.writeJSON(w, http.StatusOK, apiErr("获取隧道列表失败: "+err.Error()))
			}
			return
		}
		s.mefrpList, s.mefrpListAt = list, time.Now()
		at = s.mefrpListAt
	}
	s.mefrpMu.Unlock()
	// MEFrp 服务端在线状态有约 5 分钟缓存滞后：本地 frpc 进程在跑、该隧道在本地配置里、
	// 且云端未标记禁用时，说明隧道实际已上线，用本地状态兜底修正（进入页面不再显示陈旧的「离线」）。
	// 拷贝一份再改，避免污染共享缓存副本（toggle 禁用/kick 后 isDisabled=true 时不兜底，跟随云端）
	proxies := make([]mefrp.Proxy, len(list.Proxies))
	copy(proxies, list.Proxies)
	running := s.mefrpRun.Running()
	var localNames map[string]bool
	if running {
		localNames = s.mefrpRun.ProxyNames()
	}
	for i := range proxies {
		p := &proxies[i]
		if running && !p.IsOnline && !p.IsDisabled && localNames[p.ProxyName] {
			p.IsOnline = true
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"nodes":    list.Nodes,
		"proxies":  proxies,
		"cachedAt": at.UnixMilli(),
	}))
}

// mefrpStartWithIDs 拉取指定隧道的 frpc 配置并启动本地进程（自启与手动启动共用）。
// 已在运行时先停旧进程再启动（云端离线但本地进程活着的场景 = 重启重新注册隧道）。
func (s *Server) mefrpStartWithIDs(ids []int64) error {
	s.cfgMu.RLock()
	token := s.cfg.MEFRP.Token
	s.cfgMu.RUnlock()
	config, err := mefrp.NewClient(token).ProxyConfig(ids, "toml")
	if err != nil {
		return err
	}
	if s.mefrpRun.Running() {
		if err := s.mefrpRun.Stop(); err != nil {
			return err
		}
	}
	return s.mefrpRun.Start(s.frpcMgr.BinPath(), config)
}

// handleMefrpStart 启动选中的隧道：云端已禁用的自动启用 → 校验同节点 → 拉取 frpc TOML → 独立进程启动。
// 启动成功后把 proxyIds 记入配置，服务重启时自动恢复（mefrp 自启）。
func (s *Server) handleMefrpStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProxyIDs []int64 `json:"proxyIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	if len(req.ProxyIDs) == 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请先选择要启动的隧道"))
		return
	}
	// 强制刷新列表：启用判定与同节点校验都要用最新云端状态（列表缓存可能有约 5 分钟滞后）
	fresh, err := s.mefrpClient().ProxyList()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("获取隧道列表失败: "+err.Error()))
		return
	}
	s.mefrpMu.Lock()
	s.mefrpList, s.mefrpListAt = fresh, time.Now()
	s.mefrpMu.Unlock()
	// 校验隧道存在且属于同一节点（MEFrp 多隧道配置接口仅支持同节点）
	byID := map[int64]mefrp.Proxy{}
	for _, p := range fresh.Proxies {
		byID[p.ProxyID] = p
	}
	nodeID := int64(-1)
	for _, id := range req.ProxyIDs {
		p, ok := byID[id]
		if !ok {
			s.writeJSON(w, http.StatusOK, apiErr("隧道不存在或已被删除，请刷新后重试"))
			return
		}
		if nodeID < 0 {
			nodeID = p.NodeID
		} else if p.NodeID != nodeID {
			s.writeJSON(w, http.StatusOK, apiErr("所选隧道分布在不同节点，请选择同一节点的隧道"))
			return
		}
	}
	// 云端已禁用的隧道自动启用（toggle 是翻转语义，必须以刚刷新的 isDisabled 为准，误翻会反手禁用）
	client := s.mefrpClient()
	enabledAny := false
	for _, id := range req.ProxyIDs {
		if p := byID[id]; p.IsDisabled {
			if _, err := client.ToggleProxy(id, false); err != nil {
				s.writeJSON(w, http.StatusOK, apiErr("自动启用隧道失败: "+err.Error()))
				return
			}
			enabledAny = true
		}
	}
	if enabledAny {
		// 留出缓冲等禁用状态在服务端生效，避免 frpc 立刻注册仍被「隧道已禁用」拒绝
		time.Sleep(2 * time.Second)
	}
	// 本地 frpc 已在运行时（云端离线但进程活着）改为重启：用「当前自启集合 ∪ 本次所选（同节点）」
	// 拉起新进程，既重新注册离线隧道，又不丢掉正在运行的其他隧道
	wasRunning := s.mefrpRun.Running()
	ids := append([]int64(nil), req.ProxyIDs...)
	if wasRunning {
		s.cfgMu.RLock()
		existing := append([]int64(nil), s.cfg.MEFRP.AutostartIDs...)
		s.cfgMu.RUnlock()
		inSet := map[int64]bool{}
		for _, id := range ids {
			inSet[id] = true
		}
		for _, id := range existing {
			if inSet[id] {
				continue
			}
			// MEFrp 配置接口限制多隧道必须同节点，跨节点的旧隧道无法与新隧道共存于一个进程
			if p, ok := byID[id]; ok && p.NodeID == nodeID {
				ids = append(ids, id)
				inSet[id] = true
			}
		}
	}
	if err := s.mefrpStartWithIDs(ids); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("启动失败: "+err.Error()))
		return
	}
	// 记录自启列表：服务重启后自动恢复这批隧道
	s.cfgMu.Lock()
	s.cfg.MEFRP.AutostartIDs = ids
	s.cfgMu.Unlock()
	s.persistConfig("mefrp.autostart_ids", ids)
	var msg string
	switch {
	case wasRunning && enabledAny:
		msg = "隧道已自动启用，frpc 已重启"
	case wasRunning:
		msg = "MEFrp frpc 已重启，正在重新注册隧道"
	case enabledAny:
		msg = "隧道已自动启用并启动"
	default:
		msg = "MEFrp 隧道已启动"
	}
	s.writeJSON(w, http.StatusOK, apiMsg(msg))
}

// handleMefrpStop 停止 MEFrp frpc 进程，并清空自启列表（手动停止 = 不随服务自启）。
func (s *Server) handleMefrpStop(w http.ResponseWriter, r *http.Request) {
	if err := s.mefrpRun.Stop(); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("停止失败: "+err.Error()))
		return
	}
	s.cfgMu.Lock()
	s.cfg.MEFRP.AutostartIDs = nil
	s.cfgMu.Unlock()
	s.persistConfig("mefrp.autostart_ids", []int64{})
	s.writeJSON(w, http.StatusOK, apiMsg("MEFrp 隧道已停止"))
}

// handleMefrpStatus 本地 frpc 进程状态 + 当前加载的隧道 name 列表（前端编辑拦截/状态展示用）。
func (s *Server) handleMefrpStatus(w http.ResponseWriter, r *http.Request) {
	names := []string{}
	if s.mefrpRun.Running() {
		for n := range s.mefrpRun.ProxyNames() {
			names = append(names, n)
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"running": s.mefrpRun.Running(),
		"pid":     s.mefrpRun.PID(),
		"names":   names,
	}))
}

// handleMefrpLog 返回 MEFrp frpc 日志末尾 n 行（默认 200）。
func (s *Server) handleMefrpLog(w http.ResponseWriter, r *http.Request) {
	n := 200
	if v := r.URL.Query().Get("lines"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 2000 {
			n = parsed
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"log": s.mefrpRun.LogTail(n),
	}))
}

// ============= MEFrp 签到 / 权益抽取 =============

// mefrpDrawKey 当日抽奖累计流量的存储键（按天隔离，隔天自动重新计数），值单位为 MB。
func mefrpDrawKey() string {
	return "mefrp.drawmb." + time.Now().Format("20060102")
}

// mefrpDrawLegacyKey 旧版存储键：历史实现把奖励的 GB 数值直接当 MB 累计，
// 仅用于升级当天的存量数据折算（×1024），新数据一律写入 mefrpDrawKey。
func mefrpDrawLegacyKey() string {
	return "mefrp.draw." + time.Now().Format("20060102")
}

// mefrpTodayDrawMB 读取当日累计抽到的流量（MB）。
func (s *Server) mefrpTodayDrawMB() int64 {
	if v, err := s.store.GetSetting(mefrpDrawKey()); err == nil && v != "" {
		var mb int64
		json.Unmarshal([]byte(v), &mb)
		return mb
	}
	if v, err := s.store.GetSetting(mefrpDrawLegacyKey()); err == nil && v != "" {
		var gb int64
		if json.Unmarshal([]byte(v), &gb) == nil {
			return gb * 1024
		}
	}
	return 0
}

// mefrpDrawData 抽奖接口 data 的真实结构（官网前端即按此解析）：
//
//	{"type":"traffic|none|coupon|vip|special","prize":"25 GB 流量|优惠码|…","value":25}
//
// 流量奖的 value 与 prize 文案单位均为 GB，不是 MB。
type mefrpDrawData struct {
	Type  string  `json:"type"`
	Prize string  `json:"prize"`
	Value float64 `json:"value"`
}

// extractRewardMB 从抽奖结果中解析奖励流量并折算为 MB。
func extractRewardMB(data json.RawMessage, msg string) int64 {
	if len(data) > 0 {
		var d mefrpDrawData
		if json.Unmarshal(data, &d) == nil && d.Type == "traffic" {
			if d.Value > 0 {
				return int64(math.Round(d.Value * 1024))
			}
			if mb := parseRewardMB(d.Prize); mb > 0 {
				return mb
			}
		}
	}
	return parseRewardMB(msg)
}

// parseRewardMB 从「数字+单位」文案中解析流量并折算为 MB。
func parseRewardMB(s string) int64 {
	m := rewardUnitRe.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	switch strings.ToUpper(m[2]) {
	case "GB":
		return int64(math.Round(v * 1024))
	case "MB":
		return int64(math.Round(v))
	case "KB":
		return int64(math.Round(v / 1024))
	}
	return 0
}

var rewardUnitRe = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*(GB|MB|KB)`)

// extractCoupon 从抽奖结果中解析优惠码。
// 优惠码奖的 data 形如 {"type":"coupon","prize":"<码值或含码文案>"}，码值只在 prize 里。
func extractCoupon(data json.RawMessage, msg string) string {
	if len(data) > 0 {
		var d mefrpDrawData
		if json.Unmarshal(data, &d) == nil && d.Type == "coupon" {
			if code := couponCodeOf(d.Prize); code != "" {
				return code
			}
		}
	}
	if m := couponRe.FindStringSubmatch(msg); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// couponCodeRe 优惠码形态：6 位以上的字母数字组合（官网按 [A-Z0-9]{6,} 提取）。
var couponCodeRe = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9_-]{5,}`)

// couponCodeOf 从 prize 文案中提取码值；文案本身就是码时原样返回。
func couponCodeOf(s string) string {
	return couponCodeRe.FindString(strings.TrimSpace(s))
}

var couponRe = regexp.MustCompile(`(?:优惠码|兑换码|礼包码|卡密)[：:]?\s*([A-Za-z0-9][A-Za-z0-9-_]{2,})`)

// handleMefrpUser 获取当前绑定的账户信息（用于页面加载时刷新签到状态/配额）。
func (s *Server) handleMefrpUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.mefrpClient().UserInfo()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("获取用户信息失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(user))
}

// handleMefrpSign 签到（可携带人机验证 token），返回服务端提示与刷新后的用户信息。
func (s *Server) handleMefrpSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CaptchaToken string `json:"captchaToken"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	msg, err := s.mefrpClient().Sign(req.CaptchaToken)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	user, uerr := s.mefrpClient().UserInfo()
	if uerr != nil {
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"message": msg}))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"message": msg, "user": user}))
}

// handleMefrpLotteryStatus 抽奖状态：count=每日总次数；remaining=剩余次数（-1 表示服务端未提供具体剩余）。
func (s *Server) handleMefrpLotteryStatus(w http.ResponseWriter, r *http.Request) {
	count, remaining, err := s.mefrpClient().LotteryInfo()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("获取抽奖次数失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"count":     count,
		"remaining": remaining,
		"todayMB":   s.mefrpTodayDrawMB(),
	}))
}

// handleMefrpDraw 单次抽奖：解析奖励流量并累计到当日总数（按天持久化到数据库）。
func (s *Server) handleMefrpDraw(w http.ResponseWriter, r *http.Request) {
	data, msg, err := s.mefrpClient().LotteryDraw()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	rewardMB := extractRewardMB(data, msg)
	todayMB := s.mefrpTodayDrawMB()
	if rewardMB > 0 {
		todayMB += rewardMB
		if err := s.store.SetJSON(mefrpDrawKey(), todayMB); err != nil {
			s.logger.Warn("持久化抽奖累计失败", zap.String("key", mefrpDrawKey()), zap.Error(err))
		}
	}
	count, remaining, lerr := s.mefrpClient().LotteryInfo()
	if lerr != nil {
		remaining = -1 // 获取失败不阻塞展示
		count = 0
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"message":   msg,
		"rewardMB":  rewardMB,
		"coupon":    extractCoupon(data, msg),
		"todayMB":   todayMB,
		"count":     count,
		"remaining": remaining,
	}))
}

// ============= MEFrp 创建隧道 =============

// handleMefrpCreateData 获取创建隧道所需数据（节点 allowType/allowPort/带宽、用户组），
// 并从 /auth/node/status 合并各节点实时负载 loadPercent 供前端节点卡片与筛选展示。
func (s *Server) handleMefrpCreateData(w http.ResponseWriter, r *http.Request) {
	data, err := s.mefrpClient().CreateProxyData()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("获取创建数据失败: "+err.Error()))
		return
	}
	out := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &out); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("解析创建数据失败: "+err.Error()))
		return
	}
	// 合并节点负载（失败不阻塞，节点卡片以 0 负载展示）
	if st, serr := s.mefrpClient().NodeStatus(); serr == nil && len(st) > 0 {
		var arr []struct {
			NodeID      int64 `json:"nodeId"`
			LoadPercent int   `json:"loadPercent"`
		}
		if json.Unmarshal(st, &arr) == nil {
			lm := map[int64]int{}
			for _, a := range arr {
				lm[a.NodeID] = a.LoadPercent
			}
			var nodes []map[string]any
			if raw, ok := out["nodes"]; ok && json.Unmarshal(raw, &nodes) == nil {
				for _, n := range nodes {
					if id, ok := n["nodeId"].(float64); ok {
						n["loadPercent"] = lm[int64(id)]
					}
				}
				if merged, merr := json.Marshal(nodes); merr == nil {
					out["nodes"] = merged
				}
			}
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(out))
}

// handleMefrpNodeAddresses 节点连接地址列表（GET /auth/node/nameList）。
// MEFrp 的创建数据接口不返回连接地址（那里的 hostname 恒为空字符串），节点连接地址
// 只能从这个接口取；且它只包含「已创建过隧道」的节点，未建过隧道的节点拿不到地址。
func (s *Server) handleMefrpNodeAddresses(w http.ResponseWriter, r *http.Request) {
	addrs, err := s.mefrpClient().NodeAddressList()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("获取节点连接地址失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(addrs))
}

// handleMefrpProxyCreate 创建隧道：校验必填项后调用 MEFrp 新版创建接口（0.65.0+）。
func (s *Server) handleMefrpProxyCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID               int64             `json:"nodeId"`
		ProxyName            string            `json:"proxyName"`
		ProxyType            string            `json:"proxyType"`
		LocalIP              string            `json:"localIp"`
		LocalPort            int               `json:"localPort"`
		RemotePort           int               `json:"remotePort"`
		Domain               string            `json:"domain"`
		AccessKey            string            `json:"accessKey"`
		Locations            string            `json:"locations"`
		HostHeaderRewrite    string            `json:"hostHeaderRewrite"`
		HTTPPlugin           string            `json:"httpPlugin"`
		CrtPath              string            `json:"crtPath"`
		KeyPath              string            `json:"keyPath"`
		RequestHeaders       map[string]string `json:"requestHeaders"`
		ResponseHeaders      map[string]string `json:"responseHeaders"`
		HTTPUser             string            `json:"httpUser"`
		HTTPPassword         string            `json:"httpPassword"`
		ProxyProtocolVersion string            `json:"proxyProtocolVersion"`
		TransportProtocol    string            `json:"transportProtocol"`
		UseEncryption        bool              `json:"useEncryption"`
		UseCompression       bool              `json:"useCompression"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	if req.NodeID <= 0 {
		s.writeJSON(w, http.StatusOK, apiErr("请选择服务器（节点）"))
		return
	}
	req.ProxyName = strings.TrimSpace(req.ProxyName)
	req.ProxyType = strings.ToLower(strings.TrimSpace(req.ProxyType))
	req.LocalIP = strings.TrimSpace(req.LocalIP)
	if req.ProxyName == "" {
		s.writeJSON(w, http.StatusOK, apiErr("隧道名称不能为空"))
		return
	}
	switch req.ProxyType {
	case "tcp", "udp", "http", "https":
	default:
		s.writeJSON(w, http.StatusOK, apiErr("隧道类型仅支持 tcp/udp/http/https"))
		return
	}
	if req.LocalIP == "" {
		req.LocalIP = "127.0.0.1"
	}
	if req.LocalPort < 1 || req.LocalPort > 65535 {
		s.writeJSON(w, http.StatusOK, apiErr("本地端口须在 1-65535 之间"))
		return
	}
	if req.RemotePort < 1 || req.RemotePort > 65535 {
		s.writeJSON(w, http.StatusOK, apiErr("远程端口须在 1-65535 之间"))
		return
	}
	// HTTP 插件与 PROXY protocol 取值校验（语义见创建隧道文档）
	switch req.HTTPPlugin {
	case "", "http2https", "https2http", "https2https":
	default:
		s.writeJSON(w, http.StatusOK, apiErr("HTTP 插件仅支持 http2https/https2http/https2https"))
		return
	}
	if (req.HTTPPlugin == "https2http" || req.HTTPPlugin == "https2https") && (strings.TrimSpace(req.CrtPath) == "" || strings.TrimSpace(req.KeyPath) == "") {
		s.writeJSON(w, http.StatusOK, apiErr("该插件需要提供 TLS 证书与私钥路径"))
		return
	}
	req.ProxyProtocolVersion = strings.ToLower(strings.TrimSpace(req.ProxyProtocolVersion))
	if req.ProxyProtocolVersion != "" && req.ProxyProtocolVersion != "v1" && req.ProxyProtocolVersion != "v2" {
		s.writeJSON(w, http.StatusOK, apiErr("PROXY protocol 仅支持 v1/v2"))
		return
	}
	req.TransportProtocol = strings.ToLower(strings.TrimSpace(req.TransportProtocol))
	switch req.TransportProtocol {
	case "", "tcp", "quic", "websocket":
	default:
		s.writeJSON(w, http.StatusOK, apiErr("传输协议仅支持 tcp/quic/websocket"))
		return
	}
	if req.RequestHeaders == nil {
		req.RequestHeaders = map[string]string{}
	}
	if req.ResponseHeaders == nil {
		req.ResponseHeaders = map[string]string{}
	}
	// 服务端校验规则：accessKey 与 httpUser/httpPassword 不能同时存在
	req.AccessKey = strings.TrimSpace(req.AccessKey)
	if req.AccessKey != "" && (strings.TrimSpace(req.HTTPUser) != "" || strings.TrimSpace(req.HTTPPassword) != "") {
		s.writeJSON(w, http.StatusOK, apiErr("访问密钥（accessKey）与基础认证（httpUser/httpPassword）不能同时使用"))
		return
	}
	body := map[string]any{
		"nodeId": req.NodeID, "proxyName": req.ProxyName, "proxyType": req.ProxyType,
		"localIp": req.LocalIP, "localPort": req.LocalPort, "remotePort": req.RemotePort,
		"domain":               strings.TrimSpace(req.Domain),
		"accessKey":            req.AccessKey,
		"locations":            strings.TrimSpace(req.Locations),
		"hostHeaderRewrite":    strings.TrimSpace(req.HostHeaderRewrite),
		"httpPlugin":           req.HTTPPlugin,
		"crtPath":              strings.TrimSpace(req.CrtPath),
		"keyPath":              strings.TrimSpace(req.KeyPath),
		"requestHeaders":       req.RequestHeaders,
		"responseHeaders":      req.ResponseHeaders,
		"httpUser":             strings.TrimSpace(req.HTTPUser),
		"httpPassword":         strings.TrimSpace(req.HTTPPassword),
		"proxyProtocolVersion": req.ProxyProtocolVersion,
		"transportProtocol":    req.TransportProtocol,
		"useEncryption":        req.UseEncryption,
		"useCompression":       req.UseCompression,
	}
	msg, err := s.mefrpClient().CreateProxy(body)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("创建失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"message": msg}))
}

// mefrpProxyAction 处理按 proxyId 的简单隧道操作（toggle/delete/kick）。
func (s *Server) mefrpProxyAction(w http.ResponseWriter, r *http.Request, action string) {
	var req struct {
		ProxyID    int64 `json:"proxyId"`
		IsDisabled bool  `json:"isDisabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ProxyID <= 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("参数有误"))
		return
	}
	var (
		msg string
		err error
	)
	client := s.mefrpClient()
	switch action {
	case "toggle":
		msg, err = client.ToggleProxy(req.ProxyID, req.IsDisabled)
	case "delete":
		msg, err = client.DeleteProxy(req.ProxyID)
	case "kick":
		msg, err = client.KickProxy(req.ProxyID)
	default:
		s.writeJSON(w, http.StatusBadRequest, apiErr("未知操作"))
		return
	}
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"message": msg}))
}

// handleMefrpProxyToggle 启用/禁用隧道。
func (s *Server) handleMefrpProxyToggle(w http.ResponseWriter, r *http.Request) {
	s.mefrpProxyAction(w, r, "toggle")
}

// handleMefrpProxyDelete 删除隧道。
func (s *Server) handleMefrpProxyDelete(w http.ResponseWriter, r *http.Request) {
	s.mefrpProxyAction(w, r, "delete")
}

// handleMefrpProxyKick 强制下线隧道：云端踢下线 + 本地 frpc 同步移除该隧道。
// 只踢云端的话，本地 frpc 会在几秒内自动重连重新注册，强制下线形同虚设；
// 因此从自启集合移除该隧道并按剩余隧道重启本地 frpc（无剩余则停止进程），
// 下线后不再随服务自启，重新上线点「启动隧道」即可。
func (s *Server) handleMefrpProxyKick(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProxyID int64 `json:"proxyId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ProxyID <= 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("参数有误"))
		return
	}
	msg, err := s.mefrpClient().KickProxy(req.ProxyID)
	if err != nil {
		// 服务端在线状态有缓存滞后，本地刚注册成功的隧道踢下线可能被「隧道不在线」拒绝；
		// 下线本就是强制下线的目标状态，视为已达成，继续执行本地同步下线
		if !strings.Contains(err.Error(), "不在线") {
			s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
			return
		}
		msg = "云端已下线"
	}
	// 从自启集合移除（该隧道不在集合中则只踢云端，不动本地进程）
	s.cfgMu.RLock()
	existing := append([]int64(nil), s.cfg.MEFRP.AutostartIDs...)
	s.cfgMu.RUnlock()
	rest := make([]int64, 0, len(existing))
	for _, id := range existing {
		if id != req.ProxyID {
			rest = append(rest, id)
		}
	}
	if len(rest) == len(existing) {
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"message": msg}))
		return
	}
	s.cfgMu.Lock()
	s.cfg.MEFRP.AutostartIDs = rest
	s.cfgMu.Unlock()
	s.persistConfig("mefrp.autostart_ids", rest)
	if s.mefrpRun.Running() {
		if len(rest) == 0 {
			if err := s.mefrpRun.Stop(); err != nil {
				s.writeJSON(w, http.StatusOK, apiErr("云端已下线，但停止本地 frpc 失败: "+err.Error()))
				return
			}
			msg += "，本地 frpc 已停止"
		} else if err := s.mefrpStartWithIDs(rest); err != nil {
			s.writeJSON(w, http.StatusOK, apiErr("云端已下线，但本地 frpc 重启失败: "+err.Error()))
			return
		} else {
			msg += "，本地 frpc 已同步下线该隧道"
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"message": msg}))
}

// handleMefrpProxyUpdate 修改隧道（MEFrp 按名称定位，隧道名称不可更改）。
// 修改接口仅支持基础字段与 Host 重写/PROXY protocol/加密/压缩，不支持 HTTP 插件与自定义头。
func (s *Server) handleMefrpProxyUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProxyID              int64  `json:"proxyId"`
		ProxyName            string `json:"proxyName"`
		ProxyType            string `json:"proxyType"`
		NodeID               int64  `json:"nodeId"`
		LocalIP              string `json:"localIp"`
		LocalPort            int    `json:"localPort"`
		RemotePort           int    `json:"remotePort"`
		Domain               string `json:"domain"`
		HostHeaderRewrite    string `json:"hostHeaderRewrite"`
		ProxyProtocolVersion string `json:"proxyProtocolVersion"`
		UseEncryption        bool   `json:"useEncryption"`
		UseCompression       bool   `json:"useCompression"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	req.ProxyName = strings.TrimSpace(req.ProxyName)
	req.ProxyType = strings.ToLower(strings.TrimSpace(req.ProxyType))
	req.LocalIP = strings.TrimSpace(req.LocalIP)
	if req.ProxyID <= 0 {
		s.writeJSON(w, http.StatusOK, apiErr("缺少隧道 ID"))
		return
	}
	if req.ProxyName == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少隧道名称"))
		return
	}
	switch req.ProxyType {
	case "tcp", "udp", "http", "https":
	default:
		s.writeJSON(w, http.StatusOK, apiErr("隧道类型仅支持 tcp/udp/http/https"))
		return
	}
	if req.LocalIP == "" {
		req.LocalIP = "127.0.0.1"
	}
	if req.NodeID <= 0 || req.LocalPort < 1 || req.LocalPort > 65535 || req.RemotePort < 1 || req.RemotePort > 65535 {
		s.writeJSON(w, http.StatusOK, apiErr("节点/端口参数有误"))
		return
	}
	req.ProxyProtocolVersion = strings.ToLower(strings.TrimSpace(req.ProxyProtocolVersion))
	if req.ProxyProtocolVersion != "" && req.ProxyProtocolVersion != "v1" && req.ProxyProtocolVersion != "v2" {
		s.writeJSON(w, http.StatusOK, apiErr("PROXY protocol 仅支持 v1/v2"))
		return
	}
	body := map[string]any{
		"proxyId":   req.ProxyID,
		"proxyName": req.ProxyName, "proxyType": req.ProxyType, "nodeId": req.NodeID,
		"localIp": req.LocalIP, "localPort": req.LocalPort, "remotePort": req.RemotePort,
		"domain":               strings.TrimSpace(req.Domain),
		"hostHeaderRewrite":    strings.TrimSpace(req.HostHeaderRewrite),
		"headerXFromWhere":     "",
		"proxyProtocolVersion": req.ProxyProtocolVersion,
		"useEncryption":        req.UseEncryption,
		"useCompression":       req.UseCompression,
	}
	msg, err := s.mefrpClient().UpdateProxy(body)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("修改失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"message": msg}))
}
