package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tunhook/config"
	"tunhook/frpc"

	"go.uber.org/zap"
)

// ============= frpc 客户端管理 API =============

// handleFrpcStatus 返回 frpc 状态（安装/版本/运行/自启/内置包）。
func (s *Server) handleFrpcStatus(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcConns 返回各代理实时连接数（代理名 → 连接数），供穿透列表「连接统计」列展示。
// 携带 detail=1 时额外返回每个代理当前活跃连接的详情（连接双方端点 + 累计流量），
// 并额外返回每代理的持久累计流量（cumulative）与实时速率（rates），供累计展示与列表实时速率列使用。
func (s *Server) handleFrpcConns(w http.ResponseWriter, r *http.Request) {
	states, remotePorts, failed := s.frpcProxyRuntime()
	resp := map[string]interface{}{
		"conns":        s.frpcConnStats(),
		"states":       states,
		"remote_ports": remotePorts, // frps 自动分配端口（remote_port=0）的实际值，供穿透列表回填代理地址
		"failed":       failed,      // 管理API 查询失败的服务器及原因，非空即代表该实例隧道状态未知
	}
	if r.URL.Query().Get("detail") == "1" {
		detail := s.frpcConnDetail()
		resp["detail"] = detail
		resp["recents"] = s.webRecents()
		cum := map[string]map[string]int64{}
		rates := map[string]map[string]float64{}
		// 遍历全部已知代理（含无活跃连接的），保证无连接时也能返回持久累计（不再显示 0）
		for _, name := range s.frpcAllProxyNames() {
			var lrx, ltx int64
			for _, c := range detail[name] {
				if c.RX > 0 {
					lrx += c.RX
				}
				if c.TX > 0 {
					ltx += c.TX
				}
			}
			cumRx, cumTx, rateRx, rateTx := s.frpcTrafficSample(name, lrx, ltx)
			cum[name] = map[string]int64{"rx": cumRx, "tx": cumTx}
			rates[name] = map[string]float64{"rx": rateRx, "tx": rateTx}
		}
		resp["cumulative"] = cum
		resp["rates"] = rates
	}
	s.writeJSON(w, http.StatusOK, apiOK(resp))
}

// frpcAllProxyNames 枚举全部已配置的 frpc 代理名（代理为全局列表，去重）。
// 供流量累计按「全部已知代理」返回，保证无活跃连接时也能展示持久累计。
func (s *Server) frpcAllProxyNames() []string {
	cfg := s.frpcMgr.LoadConfig()
	seen := map[string]bool{}
	var names []string
	for _, p := range cfg.Proxies {
		if p.Name != "" && !seen[p.Name] {
			seen[p.Name] = true
			names = append(names, p.Name)
		}
	}
	return names
}

// frpcTrafficAgg 单个 frpc 代理的流量采样状态。// lastRx/lastTx 为上一次采样的活跃连接总字节（TCP_INFO），cumRx/cumTx 为持久累计（正增量累加）。
type frpcTrafficAgg struct {
	lastRx, lastTx int64
	lastT          time.Time
	cumRx, cumTx   int64
	persistAt      time.Time
}

const frpcTrafficPersistEvery = 30 * time.Second

// frpcTrafficSample 用当前活跃连接总字节数（liveRx/liveTx）更新某代理的累计与实时速率。
// 累计值只累加正增量（active 连接字节为单调 socket 计数；连接断开回落时不倒扣、保证无连接也保留历史累计）。
// 返回累计上下行（cumRx/cumTx）与瞬时速率（rateRx/rateTx，字节/秒）。
func (s *Server) frpcTrafficSample(name string, liveRx, liveTx int64) (cumRx, cumTx int64, rateRx, rateTx float64) {
	now := time.Now()
	v, _ := s.frpcTraffic.LoadOrStore(name, &frpcTrafficAgg{})
	a := v.(*frpcTrafficAgg)
	if a.lastT.IsZero() {
		cumRx, cumTx = s.loadFrpcTrafficBaseline(name)
		a.cumRx, a.cumTx = cumRx, cumTx
		a.lastRx, a.lastTx = liveRx, liveTx
		a.lastT = now
		s.persistFrpcTraffic(name, a.cumRx, a.cumTx)
		a.persistAt = now
		return a.cumRx, a.cumTx, 0, 0
	}
	dt := now.Sub(a.lastT).Seconds()
	if dt > 0 {
		incRx := liveRx - a.lastRx
		incTx := liveTx - a.lastTx
		if incRx > 0 {
			a.cumRx += incRx
		}
		if incTx > 0 {
			a.cumTx += incTx
		}
		if incRx > 0 {
			rateRx = float64(incRx) / dt
		}
		if incTx > 0 {
			rateTx = float64(incTx) / dt
		}
		a.lastRx, a.lastTx = liveRx, liveTx
		a.lastT = now
	}
	// 节流持久化（避免每次轮询写库）
	if now.Sub(a.persistAt) >= frpcTrafficPersistEvery {
		s.persistFrpcTraffic(name, a.cumRx, a.cumTx)
		a.persistAt = now
	}
	return a.cumRx, a.cumTx, rateRx, rateTx
}

// loadFrpcTrafficBaseline 从设置持久层读取某代理的历史累计流量（无记录返回 0）。
func (s *Server) loadFrpcTrafficBaseline(name string) (int64, int64) {
	v, err := s.store.GetSetting("frpctraffic." + name)
	if err != nil || v == "" {
		return 0, 0
	}
	var b struct {
		Rx int64 `json:"rx"`
		Tx int64 `json:"tx"`
	}
	if json.Unmarshal([]byte(v), &b) != nil {
		return 0, 0
	}
	return b.Rx, b.Tx
}

// persistFrpcTraffic 持久化某代理的累计流量到设置存储。
func (s *Server) persistFrpcTraffic(name string, rx, tx int64) {
	if err := s.store.SetJSON("frpctraffic."+name, struct {
		Rx int64 `json:"rx"`
		Tx int64 `json:"tx"`
	}{Rx: rx, Tx: tx}); err != nil {
		s.logger.Warn("持久化 frpc 代理累计流量失败", zap.String("proxy", name), zap.Error(err))
	}
}

// frpcProxyRuntime 遍历所有运行中的 frpc 实例，通过各自管理 API（webServer 127.0.0.1:<AdminPort>）
// 查询各代理实时状态，合并为：
//   - states：代理名 → 连接状态（running / connecting / error）
//   - remotePorts：代理名 → frps 实际分配的服务端端口（配置 remote_port=0 时由服务端自动分配，
//     admin /api/status 会返回实际值，供前端回填代理地址）
//   - failed：查询失败的实例（服务器名 → 失败原因）。
//
// 静默跳过不可取：frpc 进程活着但登不上服务器时，管理端口仍在听、/api/status 仍可达，
// 但隧道是断的；跳过会让界面显示「无数据」，把「隧道断开」伪装成「查不到状态」。
func (s *Server) frpcProxyRuntime() (map[string]string, map[string]int, map[string]string) {
	states := map[string]string{}
	remotePorts := map[string]int{}
	failed := map[string]string{}
	cfg := s.frpcMgr.LoadConfig()
	client := &http.Client{Timeout: 600 * time.Millisecond}
	for _, srv := range cfg.Servers {
		if !s.frpcMgr.ServerRunning(srv.Name) {
			continue
		}
		port := srv.AdminPort
		if port <= 0 {
			port = frpc.AdminPortBase
		}
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/status", port))
		if err != nil {
			failed[srv.Name] = "管理API 无应答: " + err.Error()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			failed[srv.Name] = fmt.Sprintf("管理API 返回 HTTP %d", resp.StatusCode)
			continue
		}
		// frp 0.71 客户端 /api/status 返回按类型分组的 {"http":[{name,status,remote_port,...}], "tcp":[...]}，
		// 非旧版的扁平 {"proxies":[...]} 结构，需逐组解析。
		var data map[string][]struct {
			Name       string `json:"name"`
			Status     string `json:"status"`
			RemotePort int    `json:"remote_port"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
		if decodeErr != nil {
			failed[srv.Name] = "管理API 响应解析失败: " + decodeErr.Error()
			continue
		}
		for _, proxies := range data {
			for _, p := range proxies {
				if p.Name == "" {
					continue
				}
				switch strings.TrimSpace(p.Status) {
				case "running":
					states[p.Name] = "running"
				case "start error", "check failed", "closed":
					states[p.Name] = "error"
				default: // new / wait start 等视为连接中
					states[p.Name] = "connecting"
				}
				if p.RemotePort > 0 {
					remotePorts[p.Name] = p.RemotePort
				}
			}
		}
	}
	return states, remotePorts, failed
}

// measureFrpcLatency 探测指定 frp 服务器（缺省为激活服务器，addr:port）的连通性与延迟。
// 连通性：连续 3 次 TCP 连接 frp 控制端口；延迟：HTTP 首响应往返（80 → 443）。
// 注：经本地隧道（如 FlClash TUN）时 TCP connect() 只到虚拟网卡（<1ms，显示 0），
// 必须用应用层往返才能测出真实 RTT；无 HTTP 服务时回退 connect 耗时。失败时 best<0。
// name 为空时测激活服务器——服务器列表是多实例的，界面按行展示，各自度量才有意义。
func (s *Server) measureFrpcLatency(name string) (best int64, addr, lastErr string) {
	cfg := s.frpcMgr.LoadConfig()
	name = strings.TrimSpace(name)
	var srv frpc.Server
	if name == "" {
		srv, _ = cfg.Active()
	} else {
		x, found := findFrpcServer(cfg, name)
		if !found {
			return -1, "", "服务器「" + name + "」不存在"
		}
		srv = x
	}
	host := strings.TrimSpace(srv.Addr)
	port := srv.Port
	if port <= 0 {
		port = frpc.DefaultPort
	}
	if host == "" {
		return -1, "", "未配置 frp 服务器地址"
	}
	addr = net.JoinHostPort(host, strconv.Itoa(port))
	best, lastErr = tcpDialLatency(addr)
	if best < 0 {
		return -1, addr, lastErr
	}
	// 用 HTTP 往返测真实延迟；测不到则回退 TCP connect 耗时
	for _, p := range []int{80, 443} {
		if ms, ok := httpRTT(host, p); ok {
			return ms, addr, ""
		}
	}
	return best, addr, ""
}

// tcpDialLatency 连续 3 次 TCP 建连取最小耗时（ms）；best<0 表示全部失败。
func tcpDialLatency(addr string) (best int64, lastErr string) {
	best = -1
	for i := 0; i < 3; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			lastErr = err.Error()
			time.Sleep(100 * time.Millisecond)
			continue
		}
		elapsed := time.Since(start).Milliseconds()
		conn.Close()
		if best < 0 || elapsed < best {
			best = elapsed
		}
	}
	return best, lastErr
}

// parseProbeTarget 解析仪表盘自定义延迟检测地址（host 或 host:port）。
// 未写端口时按 80 处理；允许误粘贴 http(s):// 前缀、路径与结尾斜杠。
func parseProbeTarget(raw string) (host string, port int, err error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if raw == "" {
		return "", 0, errors.New("请填写检测地址")
	}
	host, portStr := raw, ""
	switch {
	case strings.HasPrefix(raw, "["):
		// [IPv6] 或 [IPv6]:port
		if h, p, e := net.SplitHostPort(raw); e == nil {
			host, portStr = h, p
		} else {
			host = strings.Trim(raw, "[]")
		}
	case strings.Count(raw, ":") == 1:
		i := strings.LastIndex(raw, ":")
		host, portStr = raw[:i], raw[i+1:]
	case strings.Count(raw, ":") > 1:
		// 裸 IPv6，无端口
	}
	port = 80
	if portStr != "" {
		p, e := strconv.Atoi(portStr)
		if e != nil || p < 1 || p > 65535 {
			return "", 0, errors.New("端口无效")
		}
		port = p
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", 0, errors.New("请填写检测地址")
	}
	return host, port, nil
}

// measureCustomLatency 探测用户指定地址的往返延迟（HTTP 80/443 优先用应用层往返）。
func measureCustomLatency(raw string) (best int64, addr, lastErr string) {
	host, port, err := parseProbeTarget(raw)
	if err != nil {
		return -1, "", err.Error()
	}
	addr = net.JoinHostPort(host, strconv.Itoa(port))
	best, lastErr = tcpDialLatency(addr)
	if best < 0 {
		return -1, addr, lastErr
	}
	if port == 80 || port == 443 {
		if ms, ok := httpRTT(host, port); ok {
			return ms, addr, ""
		}
	}
	return best, addr, ""
}

// findFrpcServer 按名称在配置中查找 frp 服务器实例。
func findFrpcServer(cfg frpc.Config, name string) (frpc.Server, bool) {
	for _, s := range cfg.Servers {
		if s.Name == name {
			return s, true
		}
	}
	return frpc.Server{}, false
}

// handleFrpcServerLatency 测量指定 frp 服务器（缺省为激活服务器，addr:port）的连通性与延迟。
// addr 参数指定自定义检测地址时优先使用它（仪表盘可点击「延迟」修改）。
// 响应带 name：前端「全部启动/重启」会并发测多台，靠它把失败结果对回具体实例。
func (s *Server) handleFrpcServerLatency(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	custom := strings.TrimSpace(r.URL.Query().Get("addr"))
	var best int64
	var addr, lastErr string
	if custom != "" {
		best, addr, lastErr = measureCustomLatency(custom)
	} else {
		best, addr, lastErr = s.measureFrpcLatency(name)
	}
	if best < 0 {
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
			"name": name, "online": false, "latency_ms": 0, "addr": addr, "error": lastErr,
		}))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"name": name, "online": true, "latency_ms": best, "addr": addr,
	}))
}

// handleFrpcConfigGet 读取 frpc 配置。
func (s *Server) handleFrpcConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.frpcMgr.LoadConfig()
	s.writeJSON(w, http.StatusOK, apiOK(cfg))
}

// handleFrpcConfigSave 保存 frpc 配置；运行中则立即应用（含激活服务器）。
func (s *Server) handleFrpcConfigSave(w http.ResponseWriter, r *http.Request) {
	var cfg frpc.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	// 规范化并过滤无效规则
	cfg.Proxies = normalizeProxies(cfg.Proxies)
	cfg = frpc.NormalizeConfig(cfg)
	if srv, ok := cfg.Active(); ok && strings.TrimSpace(srv.Addr) == "" && len(cfg.Proxies) > 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("配置了代理规则但未填写服务器地址"))
		return
	}
	if err := s.frpcMgr.SaveConfig(cfg); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("保存配置失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcConfigFileGet 返回指定服务器对应的 frpc.toml 原始内容（供「配置文件」查看/编辑）。
// 支持 ?name=<服务器名>：缺省或为激活服务器时返回当前 frpc.toml；
// 其他服务器返回其独立原始配置（未保存过时按结构化配置实时生成预览）。
func (s *Server) handleFrpcConfigFileGet(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	content, isActive, err := s.frpcMgr.ReadRawConfig(name)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("读取配置失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"content":       content,
		"name":          name,
		"is_active":     isActive,
		"active_server": s.frpcMgr.ActiveServerName(),
	}))
}

// handleFrpcConfigFileSave 保存指定服务器的 frpc.toml 原始内容：先以 frpc verify 校验语法，
// 通过后写入配置文件；激活服务器运行中则直接以该文件重启（跳过结构化配置重新生成），
// 非激活服务器仅写入独立文件，切换为激活时生效。
func (s *Server) handleFrpcConfigFileSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
		Name    string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("配置内容不能为空"))
		return
	}
	dir := s.frpcMgr.Dir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("创建目录失败: "+err.Error()))
		return
	}
	// 先写入临时文件并用 frpc verify 校验语法，避免保存损坏配置
	tmp := filepath.Join(dir, ".frpc.toml.verify")
	if err := os.WriteFile(tmp, []byte(req.Content), 0644); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("写入临时配置失败: "+err.Error()))
		return
	}
	defer os.Remove(tmp)
	out, err := exec.Command(s.frpcMgr.BinPath(), "verify", "-c", tmp).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "syntax is ok") {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		s.writeJSON(w, http.StatusBadRequest, apiErr("配置校验失败: "+msg))
		return
	}
	if err := s.frpcMgr.SaveRawConfigFor(strings.TrimSpace(req.Name), req.Content); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("保存配置失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"active_server": s.frpcMgr.ActiveServerName(),
	}))
}

// handleFrpcServerAdd 添加服务器实例（名称唯一），添加后自动切换为激活服务器。
// 可选携带 raw_config（完整 frpc.toml 片段）：添加成功后作为该服务器的原始配置保存，
// 便于直接粘贴带 user/metadatas/传输参数等的高级配置。
func (s *Server) handleFrpcServerAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Addr      string `json:"addr"`
		Port      int    `json:"port"`
		Token     string `json:"token"`
		RawConfig string `json:"raw_config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请填写服务器名称"))
		return
	}
	srv := frpc.Server{Name: req.Name, Addr: strings.TrimSpace(req.Addr), Port: req.Port, Token: strings.TrimSpace(req.Token)}
	if err := s.frpcMgr.AddServer(srv); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	// 粘贴了配置文件：校验语法后保存为该服务器原始配置（立即生效并同步代理）
	if strings.TrimSpace(req.RawConfig) != "" {
		if err := s.saveServerRawConfig(req.Name, req.RawConfig); err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
			return
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// saveServerRawConfig 为指定服务器保存原始 frpc.toml 配置：先以 frpc verify 校验语法，
// 通过后写入该服务器独立配置文件（激活服务器运行中会重启生效）。
func (s *Server) saveServerRawConfig(name, content string) error {
	dir := s.frpcMgr.Dir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %s", err.Error())
	}
	// 先写入临时文件并用 frpc verify 校验语法，避免保存损坏配置
	tmp := filepath.Join(dir, ".frpc.toml.verify")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		return fmt.Errorf("写入临时配置失败: %s", err.Error())
	}
	defer os.Remove(tmp)
	out, err := exec.Command(s.frpcMgr.BinPath(), "verify", "-c", tmp).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "syntax is ok") {
		msg := strings.TrimSpace(string(out))
		if msg == "" && err != nil {
			msg = err.Error()
		}
		return fmt.Errorf("配置校验失败: %s", msg)
	}
	return s.frpcMgr.SaveRawConfigFor(name, content)
}

// handleFrpcServerSwitch 切换激活服务器（按名称，即时生效，无需刷新页面）。
func (s *Server) handleFrpcServerSwitch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少服务器名称"))
		return
	}
	if err := s.frpcMgr.SwitchServer(req.Name); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcServerAutoStart 设置指定服务器的开机自启标志（默认服务器强制开启，拒绝关闭）。
func (s *Server) handleFrpcServerAutoStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少服务器名称"))
		return
	}
	if err := s.frpcMgr.SaveAutoStart(strings.TrimSpace(req.Name), req.Enabled); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcServerDelete 删除服务器实例；删除激活服务器时自动切换到剩余第一个。
func (s *Server) handleFrpcServerDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少服务器名称"))
		return
	}
	if err := s.frpcMgr.DeleteServer(req.Name); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcServerRename 修改服务器实例名称；重命名激活服务器时同步激活标记。
func (s *Server) handleFrpcServerRename(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		NewName string `json:"new_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if err := s.frpcMgr.RenameServer(req.Name, req.NewName); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

func normalizeProxies(list []frpc.Proxy) []frpc.Proxy {
	out := make([]frpc.Proxy, 0, len(list))
	for _, p := range list {
		p.Name = strings.TrimSpace(p.Name)
		p.Type = strings.ToLower(strings.TrimSpace(p.Type))
		if p.Type == "" {
			p.Type = "tcp"
		}
		p.LocalIP = strings.TrimSpace(p.LocalIP)
		p.CustomDomains = strings.TrimSpace(p.CustomDomains)
		p.Subdomain = strings.TrimSpace(p.Subdomain)
		p.HTTPUser = strings.TrimSpace(p.HTTPUser)
		p.HTTPPassword = strings.TrimSpace(p.HTTPPassword)
		p.BandwidthLimit = strings.TrimSpace(p.BandwidthLimit)
		p.SecretKey = strings.TrimSpace(p.SecretKey)
		if p.Name == "" {
			continue
		}
		if p.LocalIP == "" {
			p.LocalIP = "127.0.0.1"
		}
		out = append(out, p)
	}
	return out
}

// validateProxy 校验代理规则必填项（创建/更新共用）。
func validateProxy(p frpc.Proxy) error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("请填写代理名称")
	}
	if p.LocalPort <= 0 || p.LocalPort > 65535 {
		return errors.New("请填写有效的本地端口（1-65535）")
	}
	switch p.Type {
	case "tcp", "udp":
		if p.RemotePort < 0 || p.RemotePort > 65535 {
			return errors.New("远程端口必须在 0-65535 之间（0=服务端自动分配）")
		}
	case "http", "https":
		if strings.TrimSpace(p.CustomDomains) == "" && strings.TrimSpace(p.Subdomain) == "" {
			return errors.New("HTTP/HTTPS 代理需配置自定义域名或子域名")
		}
	case "stcp", "xtcp":
		if strings.TrimSpace(p.SecretKey) == "" {
			return errors.New("STCP/XTCP 代理需填写 SecretKey 密钥（访问端需配置相同密钥）")
		}
	default:
		return errors.New("不支持的代理类型: " + p.Type)
	}
	return nil
}

// handleFrpcProxyCreate 新增 frpc 代理规则（可选同步设置客户端级日志参数）。
func (s *Server) handleFrpcProxyCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proxy      frpc.Proxy `json:"proxy"`
		LogLevel   string     `json:"log_level"`
		LogEntries *int       `json:"log_entries"` // frpc.log 保留行数（0=不限制）
		LogDays    *int       `json:"log_days"`    // 客户端级日志保留天数（0=不限制/跟随服务器）
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	proxies := normalizeProxies([]frpc.Proxy{req.Proxy})
	if len(proxies) == 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请填写代理名称"))
		return
	}
	req.Proxy = proxies[0]
	if err := validateProxy(req.Proxy); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	req.Proxy = s.syncFrpcReverseProxy(req.Proxy, "")
	if err := s.frpcMgr.SaveProxyWithLog(req.Proxy, "", frpc.LogOpts{
		Level:   req.LogLevel,
		Entries: req.LogEntries,
		Days:    req.LogDays,
	}); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcProxyUpdate 更新 frpc 代理规则（可选同步设置客户端级日志参数）。
func (s *Server) handleFrpcProxyUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string     `json:"name"`
		Proxy      frpc.Proxy `json:"proxy"`
		LogLevel   string     `json:"log_level"`
		LogEntries *int       `json:"log_entries"` // frpc.log 保留行数（0=不限制）
		LogDays    *int       `json:"log_days"`    // 客户端级日志保留天数（0=不限制/跟随服务器）
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	proxies := normalizeProxies([]frpc.Proxy{req.Proxy})
	if len(proxies) == 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请填写代理名称"))
		return
	}
	req.Proxy = proxies[0]
	if err := validateProxy(req.Proxy); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	req.Proxy = s.syncFrpcReverseProxy(req.Proxy, strings.TrimSpace(req.Name))
	if err := s.frpcMgr.SaveProxyWithLog(req.Proxy, strings.TrimSpace(req.Name), frpc.LogOpts{
		Level:   req.LogLevel,
		Entries: req.LogEntries,
		Days:    req.LogDays,
	}); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcProxyCheck 供前端在填写代理时就地提示冲突，避免保存后才发现（纯查询，不落库）：
//   - 域名 / 远程端口与既有代理冲突（判定与保存时共用 frpc.CheckProxyConflicts，保证提示与拦截一致）；
//   - 本地端口是否已有本机服务监听（仅当本地 IP 指向本机时才能判断）。
func (s *Server) handleFrpcProxyCheck(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := frpc.Proxy{
		CustomDomains: q.Get("domain"),
		Server:        strings.TrimSpace(q.Get("server")),
	}
	if v, err := strconv.Atoi(q.Get("remote_port")); err == nil {
		p.RemotePort = v
	}
	listening, checked := false, false
	if lp, err := strconv.Atoi(q.Get("local_port")); err == nil &&
		lp >= 1 && lp <= 65535 && isLoopbackHost(q.Get("local_ip")) {
		listening, checked = isPortListening(lp), true
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"conflicts":            s.frpcMgr.CheckProxyConflicts(p, strings.TrimSpace(q.Get("exclude"))),
		"local_port_listening": listening,
		"local_port_checked":   checked,
	}))
}

// isLoopbackHost 判断本地 IP 是否指向本机回环（空值按回环处理：frpc 默认本地 IP 即 127.0.0.1）。
// 非回环地址（如局域网内其他主机）无法用 /proc/net 判断其端口监听情况，故不做检查。
func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// handleFrpcProxyDelete 删除 frpc 代理规则。
func (s *Server) handleFrpcProxyDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少代理名称"))
		return
	}
	if err := s.frpcMgr.DeleteProxy(strings.TrimSpace(req.Name)); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	s.stopFRPCReverseProxy(strings.TrimSpace(req.Name))
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcProxyToggle 启用/停用单条 frpc 代理。
func (s *Server) handleFrpcProxyToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少代理名称"))
		return
	}
	if err := s.frpcMgr.SetProxyEnabled(strings.TrimSpace(req.Name), req.Enabled); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	name := strings.TrimSpace(req.Name)
	if req.Enabled {
		// 启用：若该代理启用了 TunHook 反代，恢复本地反代层（复用已持久化的反代端口）
		for _, p := range s.frpcMgr.LoadConfig().Proxies {
			if p.Name != name {
				continue
			}
			typ := strings.ToLower(strings.TrimSpace(p.Type))
			if p.ViaTunHook && p.RealLocalPort > 0 {
				var err error
				switch typ {
				case "http":
					_, err = s.startFRPCHTTPProxy(p, p.LocalPort)
				case "tcp":
					_, err = s.startFRPCTCPProxy(p, p.LocalPort)
				}
				if err != nil {
					s.logger.Warn("frpc 反代恢复失败",
						zap.String("proxy", name), zap.String("type", typ), zap.Error(err))
				}
			}
			break
		}
	} else {
		s.stopFRPCReverseProxy(name)
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcInstall 从内置安装包安装 frpc。
func (s *Server) handleFrpcInstall(w http.ResponseWriter, r *http.Request) {
	if s.frpcMgr.Installed() {
		s.writeJSON(w, http.StatusConflict, apiErr("frpc 已安装，如需升级请使用升级功能"))
		return
	}
	if err := s.frpcMgr.Install(); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("安装失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcStart 启动 frpc：可选 body {server:"名称"} 指定单台，缺省启动所有已配置地址的服务器。
func (s *Server) handleFrpcStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server string `json:"server"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var err error
	if strings.TrimSpace(req.Server) != "" {
		err = s.frpcMgr.StartServer(strings.TrimSpace(req.Server))
	} else {
		err = s.frpcMgr.Start()
	}
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcStop 停止 frpc：可选 body {server:"名称"} 指定单台，缺省停止全部。
func (s *Server) handleFrpcStop(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server string `json:"server"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var err error
	if strings.TrimSpace(req.Server) != "" {
		err = s.frpcMgr.StopServer(strings.TrimSpace(req.Server))
	} else {
		err = s.frpcMgr.Stop()
	}
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcRestart 重启 frpc：可选 body {server:"名称"} 指定单台，缺省重启全部。
func (s *Server) handleFrpcRestart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server string `json:"server"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var err error
	if strings.TrimSpace(req.Server) != "" {
		err = s.frpcMgr.RestartServer(strings.TrimSpace(req.Server))
	} else {
		err = s.frpcMgr.Restart()
	}
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcUpgradeCheck 检查 GitHub 最新版本。
func (s *Server) handleFrpcUpgradeCheck(w http.ResponseWriter, r *http.Request) {
	latest, err := s.frpcMgr.LatestRelease()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"latest":           latest,
		"current":          s.frpcMgr.Version(),
		"has_update":       latest != "" && latest != s.frpcMgr.Version(),
		"bundle_available": s.frpcMgr.Status().BundleAvailable,
	}))
}

// handleFrpcUpgradeDownload 下载指定版本并升级（运行中会先停止，升级后恢复）。
func (s *Server) handleFrpcUpgradeDownload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Version) == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少版本号"))
		return
	}
	wasRunning := s.frpcMgr.Status().Running
	if err := s.frpcMgr.DownloadUpgrade(req.Version); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr(err.Error()))
		return
	}
	if wasRunning {
		if err := s.frpcMgr.Start(); err != nil {
			s.writeJSON(w, http.StatusInternalServerError, apiErr("升级成功，但重新启动失败: "+err.Error()))
			return
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcUpgradeUpload 上传离线升级包（.tar.gz）并升级。
func (s *Server) handleFrpcUpgradeUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(256 << 20); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("上传失败: "+err.Error()))
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请选择要上传的 .tar.gz 升级包"))
		return
	}
	defer file.Close()

	name := filepath.Base(hdr.Filename)
	if !strings.HasSuffix(strings.ToLower(name), ".tar.gz") {
		s.writeJSON(w, http.StatusBadRequest, apiErr("升级包必须是 .tar.gz 格式"))
		return
	}
	pkgDir := filepath.Join(s.frpcMgr.Dir(), frpc.PackagesDir)
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr(err.Error()))
		return
	}
	tmp := filepath.Join(pkgDir, ".upload-"+name)
	dst, err := os.Create(tmp)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr(err.Error()))
		return
	}
	if _, err := io.Copy(dst, file); err != nil {
		dst.Close()
		os.Remove(tmp)
		s.writeJSON(w, http.StatusInternalServerError, apiErr("保存升级包失败: "+err.Error()))
		return
	}
	// 校验上传完整（浏览器/客户端异常中断时提前结束）
	if hdr.Size > 0 {
		if st, err := dst.Stat(); err == nil && st.Size() != hdr.Size {
			dst.Close()
			os.Remove(tmp)
			s.writeJSON(w, http.StatusInternalServerError, apiErr(fmt.Sprintf("上传不完整: 已接收 %d / %d 字节", st.Size(), hdr.Size)))
			return
		}
	}
	dst.Close()
	final := filepath.Join(pkgDir, name)
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		s.writeJSON(w, http.StatusInternalServerError, apiErr(err.Error()))
		return
	}

	wasRunning := s.frpcMgr.Status().Running
	if err := s.frpcMgr.UpgradeFromArchive(final); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("升级失败: "+err.Error()))
		return
	}
	if wasRunning {
		if err := s.frpcMgr.Start(); err != nil {
			s.writeJSON(w, http.StatusInternalServerError, apiErr("升级成功，但重新启动失败: "+err.Error()))
			return
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.frpcMgr.Status()))
}

// handleFrpcLog 返回 frpc 运行日志末尾若干行。
func (s *Server) handleFrpcLog(w http.ResponseWriter, r *http.Request) {
	lines := 200
	if v := r.URL.Query().Get("lines"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &lines); err == nil && n == 1 && lines > 0 && lines <= 2000 {
			// ok
		} else {
			lines = 200
		}
	}
	// 按服务器名读取日志（缺省为激活服务器），多实例各自独立日志文件
	server := strings.TrimSpace(r.URL.Query().Get("server"))
	if server == "" {
		server = s.frpcMgr.ActiveServerName()
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"log": s.frpcMgr.LogTailFor(server, lines),
	}))
}

// ============= 自定义域名 → 自动创建 frpc 代理通道 =============

// ensureCustomDomainProxy 保存转发规则时若填写了自定义域名，
// 自动在内网穿透模块使用默认服务器创建/更新对应 HTTP 代理通道（frpc proxy）：
//   - 代理名称优先取自定义ID，其次从域名推导（字母/数字/连字符）；
//   - 目标指向转发规则的内网服务（remote_addr:remote_port）；
//   - 已存在使用同一域名的代理时仅更新目标，避免重复创建；
//   - frpc 未安装/服务器未配置时仅记录日志，不阻断转发规则保存。
func (s *Server) ensureCustomDomainProxy(rule config.ForwardRule) error {
	// 域名按 DNS 规则不区分大小写，统一小写后再用于比对、推导名称与落库：
	// 否则 `Web.Example.com` 与 `web.example.com` 会被当成两个域名，重复创建代理并触发 frps 域名冲突。
	domain := strings.ToLower(strings.TrimSpace(rule.CustomDomain))
	if domain == "" {
		return nil
	}
	cfg := s.frpcMgr.LoadConfig()
	// 代理归属：优先「默认服务器」实例（通道跟随默认服务器），不存在时归属激活服务器。
	// 多实例模式下不再切换激活服务器，仅把代理写入目标服务器的配置。
	targetServer := frpc.DefaultServerName
	hasDefault := false
	for _, x := range cfg.Servers {
		if x.Name == frpc.DefaultServerName {
			hasDefault = true
			break
		}
	}
	if !hasDefault {
		targetServer = cfg.ActiveServer
	}

	// 代理名称：优先自定义ID（仅字母/数字，天然合法）；否则从域名推导
	name := strings.TrimSpace(rule.CustomID)
	if name == "" {
		base := strings.TrimPrefix(domain, "*.")
		name = sanitizeProxyName(base)
	}
	// 代理目标 = 转发规则的内网服务
	localIP := strings.TrimSpace(rule.RemoteAddr)
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	localPort := rule.RemotePort
	if localPort < 1 || localPort > 65535 {
		return fmt.Errorf("自定义域名代理需要有效的目标端口（1-65535）")
	}
	proxy := frpc.Proxy{
		Name:          name,
		Type:          "http",
		Enabled:       true,
		Server:        targetServer,
		LocalIP:       localIP,
		LocalPort:     localPort,
		CustomDomains: domain,
	}

	// 已存在使用同一自定义域名的代理 → 仅更新目标（支持改名/改端口后同步）。
	// 只覆盖同步管理的路由字段，保留用户已配置的访问认证/加密压缩/带宽/健康检查等，
	// 否则保存转发通道会覆盖代理上手动开启的 HTTP Basic 认证（表现为认证不生效）。
	cfg = s.frpcMgr.LoadConfig()
	for _, p := range cfg.Proxies {
		for _, d := range strings.Split(p.CustomDomains, ",") {
			// 与 frpcProxyByDomain 同一口径：比对前统一小写，
			// 已有代理存的是大写域名（如通过代理弹窗手动填写）时也能正确匹配到同一条。
			if strings.ToLower(strings.TrimSpace(d)) == domain {
				if p.LocalIP == localIP && p.LocalPort == localPort && p.Type == "http" {
					return nil // 目标一致，无需更新
				}
				proxy.Name = p.Name
				proxy.Server = p.Server
				proxy.HTTPUser = p.HTTPUser
				proxy.HTTPPassword = p.HTTPPassword
				proxy.Encryption = p.Encryption
				proxy.Compression = p.Compression
				proxy.BandwidthLimit = p.BandwidthLimit
				proxy.SecretKey = p.SecretKey
				proxy.HealthCheck = p.HealthCheck
				return s.frpcMgr.UpdateProxy(p.Name, proxy)
			}
		}
	}
	return s.frpcMgr.AddProxy(proxy)
}

// sanitizeProxyName 把任意文本清理为 frp 代理名称（仅字母/数字/_- .，压缩分隔符，截断 32 字符）。
func sanitizeProxyName(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, ".", "-")
	re := regexp.MustCompile(`[^A-Za-z0-9_\-]`)
	s = re.ReplaceAllString(s, "-")
	re = regexp.MustCompile(`-+`)
	s = re.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-_")
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}
