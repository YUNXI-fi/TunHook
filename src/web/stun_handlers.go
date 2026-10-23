package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"tunhook/stunhole"
	"tunhook/stunprobe"

	"go.uber.org/zap"
)

// ============= STUN 设置 =============
//
// STUN 服务器列表与打洞保活间隔支持在「系统设置 → STUN设置」中自定义，
// 持久化于 KV（stun.settings）；未配置时使用下列默认值。

const stunSettingsKey = "stun.settings"

// stunSrvCfg 单个 STUN 服务器配置。
type stunSrvCfg struct {
	Addr  string `json:"addr"`
	Proto string `json:"proto,omitempty"` // 支持的协议：udp / tcp / both（默认）
}

// stunSettingsConfig STUN 设置（服务器列表 + 保活间隔秒数）。
// Version 用于一次性迁移旧默认值：v1 的 25 秒保活过于贴近常见 NAT 超时。
type stunSettingsConfig struct {
	Servers      []stunSrvCfg `json:"servers"`
	KeepaliveSec int          `json:"keepalive_sec"`
	Version      int          `json:"version,omitempty"`
}

// defaultStunServers 默认服务器列表：与打洞模块共用同一份已验证 TCP/UDP 列表。
func defaultStunServers() []stunSrvCfg {
	list := stunhole.DefaultStunServers()
	out := make([]stunSrvCfg, 0, len(list))
	for _, s := range list {
		out = append(out, stunSrvCfg{Addr: s.Addr, Proto: s.Proto})
	}
	return out
}

// isLegacyDefaultServers 判断是否为旧版内置列表（Google ×2 + MiWiFi）。
// 这三个地址只验证过 UDP，不能继续作为 TCP 通道的默认服务器。
func isLegacyDefaultServers(list []stunSrvCfg) bool {
	if len(list) != 3 {
		return false
	}
	want := map[string]bool{
		"stun.l.google.com:19302":  true,
		"stun1.l.google.com:19302": true,
		"stun.miwifi.com:3478":     true,
	}
	for _, s := range list {
		if !want[s.Addr] {
			return false
		}
	}
	return true
}

// stunCfgMu 保护内存中的设置副本（探测/服务器列表接口并发读，保存接口写）。
var stunCfgMu sync.Mutex

// loadStunSettings 从 KV 加载设置到内存（无配置或解析失败时用默认值），
// 并把服务器候选注入打洞管理器（按通道协议自动选择 / 失败切换使用）。
func (s *Server) loadStunSettings() {
	s.stunServers = defaultStunServers()
	s.stunKeepaliveSec = 5
	raw, err := s.store.GetSetting(stunSettingsKey)
	if err != nil || raw == "" {
		s.injectStunServers()
		return
	}
	var cfg stunSettingsConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		s.logger.Warn("STUN 设置解析失败，使用默认值", zap.Error(err))
		s.injectStunServers()
		return
	}
	servers := make([]stunSrvCfg, 0, len(cfg.Servers))
	for _, sv := range cfg.Servers {
		if sv.Addr == "" {
			continue
		}
		if sv.Proto != "udp" && sv.Proto != "tcp" && sv.Proto != "both" {
			sv.Proto = "udp" // 未知协议按 UDP 处理，避免 TCP 通道误用
		}
		servers = append(servers, sv)
	}
	migrated := false
	// 旧版内置服务器列表只验证过 UDP，整体替换为已验证 TCP/UDP 的新列表；
	// 用户自定义过的列表（地址不完全一致）保持原样。
	if isLegacyDefaultServers(servers) {
		servers = defaultStunServers()
		migrated = true
	}
	if len(servers) > 0 {
		s.stunServers = servers
	}
	// v1 → v2：旧默认 25 秒改为 5 秒（仅迁移一次，之后用户可自行设回 25）
	if cfg.Version < 2 {
		if cfg.KeepaliveSec == 25 {
			cfg.KeepaliveSec = 5
		}
		cfg.Version = 2
		migrated = true
	}
	if cfg.KeepaliveSec >= 5 && cfg.KeepaliveSec <= 300 {
		s.stunKeepaliveSec = cfg.KeepaliveSec
	}
	// 旧版配置的服务器项含已废弃的 name 字段：用清洗后的结构回写一次 KV，清除残留字段。
	// json.Unmarshal 本会忽略未知字段，但不回写则数据库里的 name 永远残留（用户明确要求删除该字段）。
	if strings.Contains(raw, `"name"`) || migrated {
		ka := s.stunKeepaliveSec
		if cfg.KeepaliveSec >= 5 && cfg.KeepaliveSec <= 300 {
			ka = cfg.KeepaliveSec
		}
		if clean, err := json.Marshal(stunSettingsConfig{Servers: servers, KeepaliveSec: ka, Version: 2}); err == nil {
			if err := s.store.SetSetting(stunSettingsKey, string(clean)); err != nil {
				s.logger.Warn("清理 STUN 设置失败", zap.Error(err))
			}
		}
	}
	s.injectStunServers()
	s.stunholeMgr.SetKeepalive(time.Duration(s.stunKeepaliveSec) * time.Second)
}

// injectStunServers 把内存中的服务器列表（addr+proto）注入打洞管理器。
func (s *Server) injectStunServers() {
	list := make([]stunhole.StunServer, 0, len(s.stunServers))
	for _, sv := range s.stunServers {
		proto := sv.Proto
		if proto != "udp" && proto != "tcp" && proto != "both" {
			// 未知值不能当作“TCP 也可用”：默认按 UDP 处理，避免 TCP 通道选中
			// 一个未验证 STUN-over-TCP 的服务器。
			proto = "udp"
		}
		list = append(list, stunhole.StunServer{Addr: sv.Addr, Proto: proto})
	}
	s.stunholeMgr.SetStunServers(list)
}

// handleStunSettingsGet 返回 STUN 设置。
func (s *Server) handleStunSettingsGet(w http.ResponseWriter, r *http.Request) {
	stunCfgMu.Lock()
	defer stunCfgMu.Unlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"servers":       s.stunServers,
		"keepalive_sec": s.stunKeepaliveSec,
	}))
}

// handleStunSettingsPost 保存 STUN 设置（立即生效：服务器列表用于探测/创建，保活间隔热应用到打洞通道）。
func (s *Server) handleStunSettingsPost(w http.ResponseWriter, r *http.Request) {
	var cfg stunSettingsConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	servers := make([]stunSrvCfg, 0, len(cfg.Servers))
	for _, sv := range cfg.Servers {
		if sv.Addr == "" {
			continue
		}
		servers = append(servers, sv)
	}
	if len(servers) == 0 {
		s.writeJSON(w, http.StatusOK, apiErr("至少保留一个 STUN 服务器"))
		return
	}
	if cfg.KeepaliveSec < 5 || cfg.KeepaliveSec > 300 {
		s.writeJSON(w, http.StatusOK, apiErr("保活间隔需在 5-300 秒之间"))
		return
	}
	raw, err := json.Marshal(stunSettingsConfig{Servers: servers, KeepaliveSec: cfg.KeepaliveSec, Version: 2})
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("序列化失败"))
		return
	}
	if err := s.store.SetSetting(stunSettingsKey, string(raw)); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("保存失败: "+err.Error()))
		return
	}
	stunCfgMu.Lock()
	s.stunServers = servers
	s.stunKeepaliveSec = cfg.KeepaliveSec
	stunCfgMu.Unlock()
	s.injectStunServers()
	s.stunholeMgr.SetKeepalive(time.Duration(cfg.KeepaliveSec) * time.Second)
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"servers":       servers,
		"keepalive_sec": cfg.KeepaliveSec,
	}))
}

// handleStunCheck 批量检测 STUN 服务器连通性（Binding 请求单次往返）。
// 请求项可带 proto：udp / tcp / both；both 会同时验证 UDP 与 TCP，两者都通才算可用。
// 并发限制为 3：并发过高时大量 socket 闪连易被 NAT/防火墙丢包，造成误判；
// 单服务器超时 3 秒；最多一次检测 100 个地址。
// 响应为 NDJSON 流：每测完一个立即输出一行结果，前端实时逐个展示。
func (s *Server) handleStunCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Items []struct {
			Addr  string `json:"addr"`
			Proto string `json:"proto"`
		} `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	if len(req.Items) == 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("未提供检测地址"))
		return
	}
	if len(req.Items) > 100 {
		req.Items = req.Items[:100]
	}
	type checkItem struct {
		Addr string `json:"addr"`
		OK   bool   `json:"ok"`
		MS   int64  `json:"ms"`
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	flusher, canFlush := w.(http.Flusher)
	var writeMu sync.Mutex
	writeLine := func(it checkItem) {
		b, err := json.Marshal(it)
		if err != nil {
			return
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_, _ = w.Write(append(b, '\n'))
		if canFlush {
			flusher.Flush()
		}
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < 3; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				it := req.Items[i]
				var ms time.Duration
				var ok bool
				switch it.Proto {
				case "tcp":
					ms, ok = stunprobe.PingTCP(it.Addr, 3*time.Second)
				case "both":
					udpMS, udpOK := stunprobe.Ping(it.Addr, 3*time.Second)
					tcpMS, tcpOK := stunprobe.PingTCP(it.Addr, 3*time.Second)
					ok = udpOK && tcpOK
					if udpMS > tcpMS {
						ms = udpMS
					} else {
						ms = tcpMS
					}
				default:
					ms, ok = stunprobe.Ping(it.Addr, 3*time.Second)
				}
				writeLine(checkItem{Addr: it.Addr, OK: ok, MS: ms.Milliseconds()})
			}
		}()
	}
	for i := range req.Items {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

// ============= STUN 探测 API =============

// handleStunServers 返回可用 STUN 服务器列表（来自 STUN 设置），供前端下拉选择。
// ?type=tcp / udp 时只返回支持该协议的服务器（both 两边都返回）。
func (s *Server) handleStunServers(w http.ResponseWriter, r *http.Request) {
	typ := r.URL.Query().Get("type")
	stunCfgMu.Lock()
	defer stunCfgMu.Unlock()
	out := make([]stunSrvCfg, 0, len(s.stunServers))
	for _, sv := range s.stunServers {
		proto := sv.Proto
		if proto != "udp" && proto != "tcp" && proto != "both" {
			proto = "udp"
		}
		if typ == "tcp" && proto == "udp" {
			continue
		}
		if typ == "udp" && proto == "tcp" {
			continue
		}
		out = append(out, stunSrvCfg{Addr: sv.Addr, Proto: proto})
	}
	s.writeJSON(w, http.StatusOK, apiOK(out))
}

// handleStunProbe 执行 STUN NAT 行为探测：?server=addr 可指定服务器（默认首个）。
// 单轮等待 3s（公共 STUN 通常毫秒级响应，change-request 判定类测试等满上限）；
// 指定服务器失败时自动回退其余服务器，避免单点不可达导致整体失败。
func (s *Server) handleStunProbe(w http.ResponseWriter, r *http.Request) {
	reqServer := r.URL.Query().Get("server")
	stunCfgMu.Lock()
	cfgServers := s.stunServers
	stunCfgMu.Unlock()
	servers := make([]string, 0, len(cfgServers)+1)
	if reqServer != "" {
		servers = append(servers, reqServer)
	}
	for _, sv := range cfgServers {
		if sv.Addr != reqServer {
			servers = append(servers, sv.Addr)
		}
	}
	var lastErr error
	for _, sv := range servers {
		res, err := stunprobe.Probe(sv, 4*time.Second, s.logger)
		if err != nil {
			lastErr = err
			s.logger.Warn("STUN 探测失败，尝试下一个服务器", zap.String("server", sv), zap.Error(err))
			continue
		}
		s.writeJSON(w, http.StatusOK, apiOK(res))
		return
	}
	s.writeJSON(w, http.StatusOK, apiErr("STUN 探测失败: "+lastErr.Error()))
}

// handleStunNatChain 扫描本机到公网的 NAT 链路（traceroute 逐跳识别内网/CGN/公网）。
func (s *Server) handleStunNatChain(w http.ResponseWriter, r *http.Request) {
	chain, err := stunprobe.ScanNATChain("114.114.114.114", 30*time.Second)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("NAT 链路扫描失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"chain": chain,
		"desc":  stunprobe.NatChainDesc(chain),
	}))
}
