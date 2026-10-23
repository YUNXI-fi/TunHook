package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tunhook/cloudflared"
	"tunhook/config"

	"go.uber.org/zap"
)

// ============= Cloudflare Tunnel 接入（多实例） =============
//
// 定位：第三种接入方式，只做 HTTP(S) 域名入口。每条「实例」= 一份凭证 + 一个 cloudflared 进程
// + 一张路由表；多条实例可同时运行，各自独立启停、独立日志、独立本地回源与连接协议。
// 三种托管方式：
//   - token：隧道与 Public Hostname 路由在 Cloudflare 后台配置，本地仅托管连接器；
//   - api：隧道、路由与 DNS 记录均由本程序通过 Cloudflare API 维护；
//   - quick：匿名临时入口，免账号免 Token，由 Cloudflare 随机下发临时域名（每次启动都变）。
// 不替代 FRP：TCP/UDP 端口映射、需要访问者装客户端的 TCP/SSH/RDP 服务均不在此能力范围。

// ---------- 实例配置的读写 ----------

// cfInstances 读取实例列表（副本，避免调用方改动内存中的配置）。
func (s *Server) cfInstances() []config.CloudflareInstance {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return append([]config.CloudflareInstance(nil), s.cfg.Cloudflare.Instances...)
}

// cfFind 按 ID 查找实例（返回副本；不存在时下标为 -1）。
func (s *Server) cfFind(id string) (config.CloudflareInstance, int) {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	i := s.cfg.Cloudflare.Index(id)
	if i < 0 {
		return config.CloudflareInstance{}, -1
	}
	return s.cfg.Cloudflare.Instances[i], i
}

// cfCommit 把内存中的实例列表落盘（内部自行加锁取副本，调用方不要持有 cfgMu）。
// 为什么整份落盘：实例是数组，逐字段写回配置会产生不一致的中间态。
func (s *Server) cfCommit() {
	s.cfgMu.RLock()
	list := append([]config.CloudflareInstance(nil), s.cfg.Cloudflare.Instances...)
	s.cfgMu.RUnlock()
	s.persistConfig("cloudflare.instances", list)
}

// cfPut 新增或覆盖一条实例并落盘（按 ID 判定新增/更新）。
func (s *Server) cfPut(inst config.CloudflareInstance) {
	s.cfgMu.Lock()
	if i := s.cfg.Cloudflare.Index(inst.ID); i >= 0 {
		s.cfg.Cloudflare.Instances[i] = inst
	} else {
		s.cfg.Cloudflare.Instances = append(s.cfg.Cloudflare.Instances, inst)
	}
	s.cfgMu.Unlock()
	s.cfCommit()
}

// cfRemove 删除一条实例并落盘（返回是否存在）。
func (s *Server) cfRemove(id string) bool {
	s.cfgMu.Lock()
	i := s.cfg.Cloudflare.Index(id)
	if i < 0 {
		s.cfgMu.Unlock()
		return false
	}
	s.cfg.Cloudflare.Instances = append(s.cfg.Cloudflare.Instances[:i], s.cfg.Cloudflare.Instances[i+1:]...)
	s.cfgMu.Unlock()
	s.cfCommit()
	return true
}

// cfUpdate 就地修改一条实例并落盘；实例不存在或 fn 返回 false（无改动）时不做任何事，返回是否落盘。
func (s *Server) cfUpdate(id string, fn func(*config.CloudflareInstance) bool) bool {
	s.cfgMu.Lock()
	i := s.cfg.Cloudflare.Index(id)
	if i < 0 {
		s.cfgMu.Unlock()
		return false
	}
	if !fn(&s.cfg.Cloudflare.Instances[i]) {
		s.cfgMu.Unlock()
		return false
	}
	s.cfgMu.Unlock()
	s.cfCommit()
	return true
}

// cfRoutes 某实例的本地路由表副本。
func (s *Server) cfRoutes(id string) []config.CloudflareRoute {
	inst, i := s.cfFind(id)
	if i < 0 {
		return nil
	}
	return append([]config.CloudflareRoute(nil), inst.Routes...)
}

// cfSaveRoutes 保存某实例的路由表（内存 + 落盘）。
func (s *Server) cfSaveRoutes(id string, list []config.CloudflareRoute) {
	s.cfUpdate(id, func(inst *config.CloudflareInstance) bool {
		inst.Routes = list
		return true
	})
}

// ---------- 进程注册表：每条实例一个 cloudflared 进程 ----------

// cfRunner 取（必要时创建）某实例的进程管理器。
// 工作目录 <dataDir>/cloudflared/instances/<实例ID>，日志与 PID 文件都在其中，多实例完全隔离。
func (s *Server) cfRunner(id string) *cloudflared.Runner {
	s.cfRunsMu.Lock()
	defer s.cfRunsMu.Unlock()
	if r, ok := s.cfRuns[id]; ok {
		return r
	}
	r := cloudflared.NewRunner(s.cfInstanceDir(id), s.cfMgr.BinPath(), s.logger)
	s.cfRuns[id] = r
	return r
}

// cfInstanceDir 实例运行目录（日志 / PID 文件）。
func (s *Server) cfInstanceDir(id string) string {
	return filepath.Join(s.cfMgr.Dir(), "instances", id)
}

// cfDropRunner 停止并移除某实例的进程与运行目录（删除实例时调用）。
// 即便内存中没有该实例的 runner（例如应用重启后从未启动过），也按目录兜底清理残留进程与日志。
func (s *Server) cfDropRunner(id string) {
	s.cfRunsMu.Lock()
	r := s.cfRuns[id]
	delete(s.cfRuns, id)
	s.cfRunsMu.Unlock()
	if r == nil {
		r = cloudflared.NewRunner(s.cfInstanceDir(id), s.cfMgr.BinPath(), s.logger)
	}
	if err := r.Stop(); err != nil {
		s.logger.Warn("cloudflared 实例停止失败", zap.String("id", id), zap.Error(err))
	}
	if err := os.RemoveAll(r.Dir()); err != nil {
		s.logger.Warn("cloudflared 实例目录清理失败", zap.String("id", id), zap.Error(err))
	}
}

// cfStopAll 停止所有实例的进程（应用退出时调用）。
func (s *Server) cfStopAll() {
	s.cfRunsMu.Lock()
	rs := make([]*cloudflared.Runner, 0, len(s.cfRuns))
	for _, r := range s.cfRuns {
		rs = append(rs, r)
	}
	s.cfRunsMu.Unlock()
	for _, r := range rs {
		_ = r.Stop()
	}
}

// cfRestartAll 重启所有正在运行的实例（内核更新后让新内核生效）。
func (s *Server) cfRestartAll() {
	for _, inst := range s.cfInstances() {
		if s.cfRunner(inst.ID).Running() {
			s.restartCfInstanceIfRunning(inst.ID)
		}
	}
}

// ---------- 启停 ----------

// startCfInstance 按实例配置启动连接器（quick 用本地回源地址，其余用隧道 Token）。
func (s *Server) startCfInstance(inst config.CloudflareInstance) error {
	if !s.cfMgr.Installed() {
		return errors.New("cloudflared 内核未安装，请先下载内核或上传离线包")
	}
	r := s.cfRunner(inst.ID)
	bin := s.cfMgr.BinPath()
	if inst.NormalizeMode() == config.CloudflareModeQuick {
		if err := r.StartQuick(bin, inst.RuntimeTarget(), inst.Protocol); err != nil {
			return err
		}
		// 暂停状态随实例持久化：应用重启 / 隧道重启后按上次的状态继续（连接照旧，只是仍回 503）
		r.SetPaused(inst.Paused)
		return nil
	}
	return r.Start(bin, inst.RuntimeToken(), inst.Protocol)
}

// cfNotReadyReason 实例不具备启动条件时的具体原因（给用户可操作的提示）。
func cfNotReadyReason(inst config.CloudflareInstance) string {
	switch inst.NormalizeMode() {
	case config.CloudflareModeQuick:
		return "请先填写本地服务地址与端口（临时入口以它为回源）"
	case config.CloudflareModeAPI:
		return "该实例缺少隧道 Token，请重新绑定 Cloudflare 账号与域名"
	default:
		return "请先保存隧道 Token（Cloudflare Zero Trust → Networks → Tunnels）"
	}
}

// restartCfInstanceIfRunning 实例配置或内核变更后重启它（未运行则不做任何事）。
func (s *Server) restartCfInstanceIfRunning(id string) {
	r := s.cfRunner(id)
	if !r.Running() {
		return
	}
	if err := r.Stop(); err != nil {
		s.logger.Warn("cloudflared 实例重启前停止失败", zap.String("id", id), zap.Error(err))
		return
	}
	inst, i := s.cfFind(id)
	if i < 0 || !inst.Ready() {
		return
	}
	if err := s.startCfInstance(inst); err != nil {
		s.logger.Warn("cloudflared 实例重启失败", zap.String("id", id), zap.Error(err))
	}
}

// cfSetAutoStart 记录/清除某实例的自启意图（跟随最后一次启停操作，异常退出不改变）。
func (s *Server) cfSetAutoStart(id string, on bool) {
	s.cfUpdate(id, func(inst *config.CloudflareInstance) bool {
		if inst.AutoStart == on {
			return false // 无变化不必落盘
		}
		inst.AutoStart = on
		return true
	})
}

// ---------- 状态 ----------

// cloudflareStatusData 汇总内核 + 全部实例状态（各接口统一返回它，前端一次拿全）。
func (s *Server) cloudflareStatusData() map[string]interface{} {
	installed := s.cfMgr.Installed()
	version := ""
	if installed {
		version = s.cfMgr.Version()
	}
	list := s.cfInstances()
	views := make([]map[string]interface{}, 0, len(list))
	for _, inst := range list {
		views = append(views, s.cfInstanceView(inst))
	}
	return map[string]interface{}{
		"installed": installed,
		"version":   version,
		"latest":    s.cfMgr.Latest(),
		"instances": views,
	}
}

// cfInstanceView 单条实例的前端视图（含运行态、访问地址与路由表）。
func (s *Server) cfInstanceView(inst config.CloudflareInstance) map[string]interface{} {
	r := s.cfRunner(inst.ID)
	scheme, addr, port := inst.LocalOrigin()
	return map[string]interface{}{
		"id":         inst.ID,
		"name":       inst.DisplayName(),
		"mode":       inst.NormalizeMode(),
		"running":    r.Running(),
		"pid":        r.PID(),
		"ready":      r.Ready(),
		"paused":     r.Paused(),
		"configured": inst.Ready(),
		"protocol":   cloudflared.NormalizeProtocol(inst.Protocol),
		"autoStart":  inst.AutoStart,
		"local": map[string]interface{}{
			"scheme": scheme,
			"addr":   addr,
			"port":   port,
		},
		"token":    maskToken(inst.Token),
		"tokenSet": strings.TrimSpace(inst.Token) != "",
		"api": map[string]interface{}{
			"bound":      inst.TunnelID != "",
			"dnsAccount": inst.DNSAccount,
			"accountId":  inst.AccountID,
			"zoneName":   inst.ZoneName,
			"zoneId":     inst.ZoneID,
			"tunnelId":   inst.TunnelID,
		},
		"quick": map[string]interface{}{
			"target": inst.RuntimeTarget(),
			"url":    r.QuickURL(),
		},
		"accessURL": cfAccessURL(inst, r.QuickURL()),
		"routes":    append([]config.CloudflareRoute(nil), inst.Routes...),
	}
}

// cfAccessURL 实例对外的访问地址：
//   - quick：Cloudflare 本次下发的变化域名（未取得时为空）；
//   - api：路由表里的第一个域名（第一条即主入口）；
//   - token：域名在 Cloudflare 后台配置，本程序无从得知。
func cfAccessURL(inst config.CloudflareInstance, quickURL string) string {
	switch inst.NormalizeMode() {
	case config.CloudflareModeQuick:
		return quickURL
	case config.CloudflareModeAPI:
		if len(inst.Routes) > 0 {
			return "https://" + inst.Routes[0].Hostname
		}
	}
	return ""
}

// ---------- HTTP 接口：状态与内核 ----------

// handleCloudflareStatus 查询内核与全部实例状态。
func (s *Server) handleCloudflareStatus(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, apiOK(s.cloudflareStatusData()))
}

// handleCloudflareInstall 下载官方最新版内核并安装（异步，进度走 /api/cloudflare/install/progress）。
func (s *Server) handleCloudflareInstall(w http.ResponseWriter, r *http.Request) {
	_, busy, _ := s.cfMgr.State()
	if busy {
		s.writeJSON(w, http.StatusOK, apiErr("内核正在下载/安装中，请稍候"))
		return
	}
	go func() {
		if err := s.cfMgr.Download(); err != nil {
			s.logger.Warn("cloudflared 内核下载失败", zap.Error(err))
			return
		}
		// 内核替换为原子 rename，下载期间隧道不受影响；这里重启一次让新内核生效。
		s.cfRestartAll()
	}()
	s.writeJSON(w, http.StatusOK, apiMsg("已开始下载内核"))
}

// handleCloudflareInstallProgress 查询内核下载/安装进度。
func (s *Server) handleCloudflareInstallProgress(w http.ResponseWriter, r *http.Request) {
	p, busy, lastErr := s.cfMgr.State()
	installed := s.cfMgr.Installed()
	version := ""
	if installed {
		version = s.cfMgr.Version()
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"busy":      busy,
		"percent":   p.Percent,
		"done":      p.Done,
		"total":     p.Total,
		"stage":     p.Stage,
		"error":     lastErr,
		"installed": installed,
		"version":   version,
	}))
}

// handleCloudflareInstallUpload 上传离线内核包并安装（网络不可用时的兜底路径）。
// 只做可执行性校验（执行 --version），不依赖文件扩展名。
func (s *Server) handleCloudflareInstallUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(256 << 20); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("上传失败: "+err.Error()))
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请选择要上传的 cloudflared 内核文件"))
		return
	}
	defer file.Close()

	dir := filepath.Join(s.cfMgr.Dir(), cloudflared.PackagesDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr(err.Error()))
		return
	}
	tmp := filepath.Join(dir, ".upload-"+filepath.Base(hdr.Filename))
	dst, err := os.Create(tmp)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr(err.Error()))
		return
	}
	if _, err := io.Copy(dst, file); err != nil {
		dst.Close()
		os.Remove(tmp)
		s.writeJSON(w, http.StatusInternalServerError, apiErr("保存内核文件失败: "+err.Error()))
		return
	}
	// 校验上传完整（浏览器/客户端异常中断时提前结束）
	if hdr.Size > 0 {
		if st, err := dst.Stat(); err == nil && st.Size() != hdr.Size {
			dst.Close()
			os.Remove(tmp)
			s.writeJSON(w, http.StatusBadRequest, apiErr("内核文件上传不完整，请重试"))
			return
		}
	}
	dst.Close()
	defer os.Remove(tmp)

	version, err := s.cfMgr.InstallFromFile(tmp)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	s.cfRestartAll()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"version": version,
		"status":  s.cloudflareStatusData(),
	}))
}

// ---------- HTTP 接口：实例增删改查与启停 ----------

// cfInstanceReq 新建实例请求。
type cfInstanceReq struct {
	Name        string `json:"name"`
	Mode        string `json:"mode"`
	Token       string `json:"token"`
	Account     string `json:"account"`     // api 模式：Cloudflare 账号名（「域名解析」中的账号）
	Zone        string `json:"zone"`        // api 模式：发布域名（zone）
	TunnelID    string `json:"tunnelId"`    // api 模式：复用账号下已有隧道（留空则新建）
	TunnelName  string `json:"tunnelName"`  // api 模式：新建隧道名（留空自动生成）
	LocalScheme string `json:"localScheme"` // 本地回源协议：http（默认）| https
	LocalAddr   string `json:"localAddr"`
	LocalPort   *int   `json:"localPort"`
	Protocol    string `json:"protocol"`
	AutoStart   bool   `json:"autoStart"`
	Start       *bool  `json:"start"` // 创建后是否立即启动（缺省 true）
}

// handleCloudflareInstanceCreate 新建一条隧道实例。
// mode=api 时同时完成「绑定」：按账号+域名创建（或复用指定）云端隧道，首次接管会导入其已有路由。
func (s *Server) handleCloudflareInstanceCreate(w http.ResponseWriter, r *http.Request) {
	var req cfInstanceReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	inst := config.CloudflareInstance{
		ID:          config.NewInstanceID(),
		Name:        strings.TrimSpace(req.Name),
		Mode:        req.Mode,
		Token:       strings.TrimSpace(req.Token),
		DNSAccount:  strings.TrimSpace(req.Account),
		ZoneName:    strings.TrimSpace(req.Zone),
		LocalScheme: req.LocalScheme,
		LocalAddr:   req.LocalAddr,
		Protocol:    req.Protocol,
		AutoStart:   req.AutoStart,
	}
	if req.LocalPort != nil {
		inst.LocalPort = *req.LocalPort
	}
	if err := normalizeCfInstance(&inst); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	if inst.NormalizeMode() == config.CloudflareModeAPI {
		if err := s.cfBindAPI(r.Context(), &inst, req.TunnelID, req.TunnelName); err != nil {
			s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
			return
		}
	} else if !inst.Ready() {
		s.writeJSON(w, http.StatusOK, apiErr(cfNotReadyReason(inst)))
		return
	}
	s.cfPut(inst)
	s.logger.Info("Cloudflare 隧道实例已创建",
		zap.String("id", inst.ID), zap.String("name", inst.Name), zap.String("mode", inst.NormalizeMode()))

	warning := ""
	if req.Start == nil || *req.Start {
		if err := s.startCfInstance(inst); err != nil {
			warning = "实例已创建，但启动失败: " + err.Error()
		} else {
			s.cfSetAutoStart(inst.ID, true)
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"status":  s.cloudflareStatusData(),
		"id":      inst.ID,
		"warning": warning,
	}))
}

// cfInstanceUpdateReq 更新实例请求：指针字段区分「未传」与「置空」。
type cfInstanceUpdateReq struct {
	Name        *string `json:"name"`
	Token       *string `json:"token"`
	Account     string  `json:"account"`    // api 模式：重新绑定时的账号
	Zone        string  `json:"zone"`       // api 模式：重新绑定时的域名
	TunnelID    string  `json:"tunnelId"`   // api 模式：复用指定隧道（留空则新建）
	TunnelName  string  `json:"tunnelName"` // api 模式：新建隧道名
	LocalScheme *string `json:"localScheme"`
	LocalAddr   *string `json:"localAddr"`
	LocalPort   *int    `json:"localPort"`
	Protocol    *string `json:"protocol"`
	AutoStart   *bool   `json:"autoStart"`
}

// handleCloudflareInstanceUpdate 更新一条实例（名称 / 凭证 / 本地回源 / 协议 / 自启）。
// api 模式带上账号+域名时按重新绑定处理（换隧道或换域名）；凭证与回源类改动会重启该实例。
func (s *Server) handleCloudflareInstanceUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	inst, i := s.cfFind(id)
	if i < 0 {
		s.writeJSON(w, http.StatusOK, apiErr("实例不存在（可能已被删除）"))
		return
	}
	var req cfInstanceUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	// 区分「必须重启内核」与「只改了本地回源」——后者不该重启：
	// 临时入口的回源走本地闸门，改闸门目标即可；而重启会让它拿到新的 trycloudflare 地址。
	//   - 凭证 / 连接协议 / 重新绑定：内核启动参数变了，只能重启；
	//   - 本地回源：api 模式的 ingress 由路由表各自的 service 决定、token 模式在 Cloudflare 后台，
	//     都不依赖内核进程，改配置本就无需重启；只有临时入口需要顺带把新回源同步给闸门。
	needRestart := false   // 必须重启内核才能生效
	originChanged := false // 仅本地回源发生变化
	if req.Name != nil {
		inst.Name = strings.TrimSpace(*req.Name)
	}
	if req.Token != nil {
		if t := strings.TrimSpace(*req.Token); t != inst.Token {
			inst.Token = t
			needRestart = true
		}
	}
	if req.LocalScheme != nil {
		if v := strings.ToLower(strings.TrimSpace(*req.LocalScheme)); v != inst.LocalScheme {
			inst.LocalScheme = v
			originChanged = true
		}
	}
	if req.LocalAddr != nil {
		if v := strings.TrimSpace(*req.LocalAddr); v != inst.LocalAddr {
			inst.LocalAddr = v
			originChanged = true
		}
	}
	if req.LocalPort != nil && *req.LocalPort != inst.LocalPort {
		inst.LocalPort = *req.LocalPort
		originChanged = true
	}
	if req.Protocol != nil {
		if v := cloudflared.NormalizeProtocol(*req.Protocol); v != cloudflared.NormalizeProtocol(inst.Protocol) {
			inst.Protocol = v
			needRestart = true
		}
	}
	if req.AutoStart != nil {
		inst.AutoStart = *req.AutoStart
	}
	account := strings.TrimSpace(req.Account)
	zone := strings.TrimSpace(req.Zone)
	if account != "" && zone != "" {
		if inst.NormalizeMode() != config.CloudflareModeAPI {
			s.writeJSON(w, http.StatusOK, apiErr("只有 API 全托管实例支持绑定 Cloudflare 账号与域名"))
			return
		}
		inst.DNSAccount, inst.ZoneName = account, zone
		if err := s.cfBindAPI(r.Context(), &inst, req.TunnelID, req.TunnelName); err != nil {
			s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
			return
		}
		needRestart = true
	}
	if err := normalizeCfInstance(&inst); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	if !inst.Ready() {
		s.writeJSON(w, http.StatusOK, apiErr(cfNotReadyReason(inst)))
		return
	}
	s.cfPut(inst)
	// applied 告诉前端这次保存是否需要重启（前端不再自己重算一遍规则，避免两边判定不一致）
	applied := "none"
	if needRestart {
		s.restartCfInstanceIfRunning(id)
		applied = "restart"
	} else if originChanged {
		s.cfApplyOrigin(inst)
		applied = "origin"
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"status":  s.cloudflareStatusData(),
		"warning": "",
		"applied": applied,
	}))
}

// cfApplyOrigin 把实例当前的本地回源同步给运行中的闸门（仅临时入口有闸门）。
// 同步成功就不必重启内核——重启会让临时入口拿到新的访问地址，而用户只是想改回源。
func (s *Server) cfApplyOrigin(inst config.CloudflareInstance) {
	if inst.NormalizeMode() != config.CloudflareModeQuick {
		return // 其余模式的回源不在本进程内（Cloudflare ingress / 后台配置），无需任何动作
	}
	r := s.cfRunner(inst.ID)
	if !r.Running() {
		return // 未运行：下次启动自然按新回源建立闸门
	}
	if !r.SetTarget(inst.RuntimeTarget()) {
		// 闸门不可用（异常状态启动的实例）：退回重启，宁可换地址也要让新回源生效
		s.logger.Warn("闸门切换回源失败，改为重启实例", zap.String("id", inst.ID))
		s.restartCfInstanceIfRunning(inst.ID)
	}
}

// handleCloudflareInstanceDelete 删除一条实例：先停进程并清理运行目录，再从配置移除。
// 只解除本机接管，不动 Cloudflare 云端隧道与 DNS 记录（那些由用户在后台自行管理）。
func (s *Server) handleCloudflareInstanceDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	inst, i := s.cfFind(id)
	if i < 0 {
		s.writeJSON(w, http.StatusOK, apiErr("实例不存在（可能已被删除）"))
		return
	}
	s.cfDropRunner(id)
	s.cfRemove(id)
	s.logger.Info("Cloudflare 隧道实例已删除",
		zap.String("id", id), zap.String("name", inst.Name), zap.String("mode", inst.NormalizeMode()))
	s.writeJSON(w, http.StatusOK, apiOK(s.cloudflareStatusData()))
}

// handleCloudflareInstanceStart 启动某实例（quick 用本地回源地址，其余用已保存的 Token）。
func (s *Server) handleCloudflareInstanceStart(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	inst, i := s.cfFind(id)
	if i < 0 {
		s.writeJSON(w, http.StatusOK, apiErr("实例不存在（可能已被删除）"))
		return
	}
	if !inst.Ready() {
		s.writeJSON(w, http.StatusOK, apiErr(cfNotReadyReason(inst)))
		return
	}
	if s.cfRunner(id).Running() {
		s.writeJSON(w, http.StatusOK, apiErr("该隧道已在运行中"))
		return
	}
	if err := s.startCfInstance(inst); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("启动失败: "+err.Error()))
		return
	}
	// 记录自启意图：应用重启后自动恢复这条隧道
	s.cfSetAutoStart(id, true)
	s.writeJSON(w, http.StatusOK, apiOK(s.cloudflareStatusData()))
}

// handleCloudflareInstanceStop 停止某实例。
func (s *Server) handleCloudflareInstanceStop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, i := s.cfFind(id); i < 0 {
		s.writeJSON(w, http.StatusOK, apiErr("实例不存在（可能已被删除）"))
		return
	}
	if err := s.cfRunner(id).Stop(); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("停止失败: "+err.Error()))
		return
	}
	// 主动停止即清除自启意图（异常退出不走这里，不影响自启设置）
	s.cfSetAutoStart(id, false)
	// 停止是全停：连暂停标记一并清掉，避免下次启动后仍回 503
	s.cfUpdate(id, func(inst *config.CloudflareInstance) bool {
		if !inst.Paused {
			return false
		}
		inst.Paused = false
		return true
	})
	s.writeJSON(w, http.StatusOK, apiOK(s.cloudflareStatusData()))
}

// handleCloudflareInstancePause 暂停一条临时入口（隧道连接与访问地址保持不变，回源改回 503）。
func (s *Server) handleCloudflareInstancePause(w http.ResponseWriter, r *http.Request) {
	s.cfSetPaused(w, r, true)
}

// handleCloudflareInstanceResume 恢复一条被暂停的临时入口。
func (s *Server) handleCloudflareInstanceResume(w http.ResponseWriter, r *http.Request) {
	s.cfSetPaused(w, r, false)
}

// cfSetPaused 暂停/恢复的共用实现。
//
// 暂停不碰 cloudflared 进程：隧道连接与 trycloudflare 域名都保持不变，
// 只把回源闸门切到 503 页面（用「错误页面」模块里的 503）。
// 域名固定的隧道（token / api）不需要这个中间状态——直接停止即可。
func (s *Server) cfSetPaused(w http.ResponseWriter, r *http.Request, paused bool) {
	id := r.PathValue("id")
	inst, i := s.cfFind(id)
	if i < 0 {
		s.writeJSON(w, http.StatusOK, apiErr("实例不存在（可能已被删除）"))
		return
	}
	if inst.NormalizeMode() != config.CloudflareModeQuick {
		s.writeJSON(w, http.StatusOK, apiErr("只有临时入口支持暂停；域名固定的隧道直接停止即可"))
		return
	}
	run := s.cfRunner(id)
	if !run.Running() {
		s.writeJSON(w, http.StatusOK, apiErr("隧道未运行，无需暂停"))
		return
	}
	run.SetPaused(paused)
	s.cfUpdate(id, func(x *config.CloudflareInstance) bool {
		if x.Paused == paused {
			return false
		}
		x.Paused = paused
		return true
	})
	s.writeJSON(w, http.StatusOK, apiOK(s.cloudflareStatusData()))
}

// handleCloudflareInstanceLog 读取某实例内核日志末尾 300 行。
func (s *Server) handleCloudflareInstanceLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, i := s.cfFind(id); i < 0 {
		s.writeJSON(w, http.StatusOK, apiErr("实例不存在（可能已被删除）"))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"log": s.cfRunner(id).LogTail(300),
	}))
}

// ---------- 绑定：账号凭证与云端隧道 ----------

// cfBinding 某条 api 实例的 Cloudflare 绑定（客户端 + 账号/域名/隧道标识）。
type cfBinding struct {
	client    *cloudflared.APIClient
	accountID string
	zoneID    string
	zoneName  string
	tunnelID  string
}

// cloudflareAccountToken 从「域名解析」模块的 Cloudflare 账号中取出 API Token。
func (s *Server) cloudflareAccountToken(name string) (string, error) {
	accounts, err := s.store.ListDNSAccounts()
	if err != nil {
		return "", fmt.Errorf("读取 DNS 账户失败: %w", err)
	}
	for i := range accounts {
		if !strings.EqualFold(accounts[i].Name, name) {
			continue
		}
		if !strings.EqualFold(accounts[i].Provider, "Cloudflare") {
			return "", fmt.Errorf("账号 %s 不是 Cloudflare 账号", name)
		}
		if t := strings.TrimSpace(accounts[i].Credentials["api_token"]); t != "" {
			return t, nil
		}
		return "", fmt.Errorf("Cloudflare 账号 %s 缺少 API Token", name)
	}
	return "", fmt.Errorf("Cloudflare 账号不存在: %s（可能已在「域名解析」中删除）", name)
}

// cfBindingFor 构造 API 客户端并返回实例绑定；非 api 模式、未绑定或凭证缺失时返回错误。
func (s *Server) cfBindingFor(inst config.CloudflareInstance) (*cfBinding, error) {
	if inst.NormalizeMode() != config.CloudflareModeAPI {
		return nil, errors.New("该实例不是 API 全托管模式，其路由由 Cloudflare 后台维护")
	}
	if inst.TunnelID == "" {
		return nil, errors.New("该实例尚未绑定隧道，请先完成绑定")
	}
	if inst.AccountID == "" || inst.ZoneID == "" {
		return nil, errors.New("隧道绑定信息不完整，请重新绑定")
	}
	token, err := s.cloudflareAccountToken(inst.DNSAccount)
	if err != nil {
		return nil, err
	}
	return &cfBinding{
		client:    cloudflared.NewAPIClient(token),
		accountID: inst.AccountID,
		zoneID:    inst.ZoneID,
		zoneName:  inst.ZoneName,
		tunnelID:  inst.TunnelID,
	}, nil
}

// cfBindAPI 为 api 模式实例补齐账号/域名/隧道凭证：
//   - tunnelID 非空：复用账号下指定的已有隧道；
//   - 否则新建一条隧道，名字取 tunnelName，留空则用 tunhook-<主机名>（已占用时自动加序号）。
//
// 首次绑定且本地路由表为空时导入云端已有路由（不覆盖本页已编辑的路由）。
func (s *Server) cfBindAPI(ctx context.Context, inst *config.CloudflareInstance, tunnelID, tunnelName string) error {
	account, zoneName := strings.TrimSpace(inst.DNSAccount), strings.TrimSpace(inst.ZoneName)
	if account == "" || zoneName == "" {
		return errors.New("请先选择 Cloudflare 账号与域名")
	}
	apiToken, err := s.cloudflareAccountToken(account)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	client := cloudflared.NewAPIClient(apiToken)
	zone, err := client.ZoneByName(ctx, zoneName)
	if err != nil {
		return err
	}
	inst.DNSAccount, inst.AccountID, inst.ZoneID, inst.ZoneName = account, zone.AccountID, zone.ID, zone.Name

	var tunnel *cloudflared.Tunnel
	var tunnelToken string
	if id := strings.TrimSpace(tunnelID); id != "" {
		tunnel, err = client.GetTunnel(ctx, zone.AccountID, id)
		if err != nil {
			return fmt.Errorf("云端未找到该隧道（可能已被删除）: %w", err)
		}
		if tunnelToken, err = client.GetTunnelToken(ctx, zone.AccountID, id); err != nil {
			return fmt.Errorf("获取隧道 Token 失败: %w", err)
		}
	} else {
		name, err := s.cfFreeTunnelName(ctx, client, zone.AccountID, tunnelName)
		if err != nil {
			return err
		}
		if tunnel, tunnelToken, err = client.CreateTunnel(ctx, zone.AccountID, name); err != nil {
			return fmt.Errorf("创建隧道失败: %w", err)
		}
	}
	if strings.TrimSpace(tunnelToken) == "" {
		return errors.New("未取得隧道 Token，请在 Cloudflare 后台确认该隧道状态后重试")
	}
	inst.TunnelID, inst.TunnelToken = tunnel.ID, tunnelToken
	if strings.TrimSpace(inst.Name) == "" {
		inst.Name = tunnel.Name
	}
	// 首次接管：本地路由表为空时导入云端已有规则，避免与本页编辑互相覆盖
	if len(inst.Routes) == 0 {
		if remote, err := client.GetIngress(ctx, zone.AccountID, tunnel.ID); err == nil && len(remote) > 0 {
			list := make([]config.CloudflareRoute, 0, len(remote))
			for _, r := range remote {
				list = append(list, config.CloudflareRoute{Hostname: r.Hostname, Service: r.Service, Path: r.Path})
			}
			inst.Routes = list
		}
	}
	return nil
}

// cfFreeTunnelName 生成账号内未被占用的隧道名：want 为空时用 tunhook-<主机名>，
// 被占用则依次追加 -2、-3…（Cloudflare 要求同账号下隧道名唯一）。
func (s *Server) cfFreeTunnelName(ctx context.Context, client *cloudflared.APIClient, accountID, want string) (string, error) {
	base := strings.TrimSpace(want)
	if base == "" {
		base = defaultTunnelName()
	}
	exist, err := client.ListTunnels(ctx, accountID)
	if err != nil {
		return "", fmt.Errorf("读取云端隧道列表失败: %w", err)
	}
	used := make(map[string]bool, len(exist))
	for _, t := range exist {
		used[t.Name] = true
	}
	if !used[base] {
		return base, nil
	}
	for i := 2; i < 100; i++ {
		name := fmt.Sprintf("%s-%d", base, i)
		if !used[name] {
			return name, nil
		}
	}
	return "", errors.New("该账号下同名隧道过多，请手动填写隧道名")
}

// defaultTunnelName 默认隧道名：tunhook-<主机名>（按设备区分，避免多台设备误共享同一隧道）。
func defaultTunnelName() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		host = "local"
	}
	return "tunhook-" + strings.ToLower(strings.TrimSpace(host))
}

// normalizeCfInstance 归一化并校验实例的基础字段（协议、本地回源）。
func normalizeCfInstance(inst *config.CloudflareInstance) error {
	inst.LocalScheme = strings.ToLower(strings.TrimSpace(inst.LocalScheme))
	if inst.LocalScheme == "" {
		inst.LocalScheme = "http"
	}
	if inst.LocalScheme != "http" && inst.LocalScheme != "https" {
		return errors.New("本地服务协议只支持 http 或 https")
	}
	inst.LocalAddr = strings.TrimSpace(inst.LocalAddr)
	if inst.LocalAddr == "" {
		inst.LocalAddr = "127.0.0.1"
	}
	if inst.LocalPort < 0 || inst.LocalPort > 65535 {
		return errors.New("端口需在 1-65535 之间（0 表示未配置）")
	}
	inst.Protocol = cloudflared.NormalizeProtocol(inst.Protocol)
	return nil
}

// ---------- 云端隧道列表（新建/编辑 API 实例时选择） ----------

// cfTunnelView 云端隧道列表项。
type cfTunnelView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	UsedBy string `json:"usedBy"` // 已被本程序的哪条实例接管（空=未被接管）
}

// handleCloudflareTunnelsList 列出某 Cloudflare 账号下的隧道（需账号 + 该账号下任一域名用于解析账号 ID）。
func (s *Server) handleCloudflareTunnelsList(w http.ResponseWriter, r *http.Request) {
	account := strings.TrimSpace(r.URL.Query().Get("account"))
	zoneName := strings.TrimSpace(r.URL.Query().Get("zone"))
	if account == "" || zoneName == "" {
		s.writeJSON(w, http.StatusOK, apiErr("请先选择 Cloudflare 账号与域名"))
		return
	}
	apiToken, err := s.cloudflareAccountToken(account)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	client := cloudflared.NewAPIClient(apiToken)
	zone, err := client.ZoneByName(ctx, zoneName)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	list, err := client.ListTunnels(ctx, zone.AccountID)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("拉取云端隧道失败: "+err.Error()))
		return
	}
	// 已被本程序接管的隧道：标出属于哪条实例，避免把同一隧道绑到两条实例上
	used := map[string]string{}
	for _, inst := range s.cfInstances() {
		if inst.TunnelID != "" {
			used[inst.TunnelID] = inst.DisplayName()
		}
	}
	out := make([]cfTunnelView, 0, len(list))
	for _, t := range list {
		out = append(out, cfTunnelView{ID: t.ID, Name: t.Name, Status: t.Status, UsedBy: used[t.ID]})
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"zone":    zone.Name,
		"tunnels": out,
	}))
}

// ---------- 域名路由（仅 API 全托管实例） ----------

// handleCloudflareRoutesSave 新增/更新某实例的一条路由：整份下发 ingress → 补建 CNAME → 落库。
func (s *Server) handleCloudflareRoutesSave(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	inst, i := s.cfFind(id)
	if i < 0 {
		s.writeJSON(w, http.StatusOK, apiErr("实例不存在（可能已被删除）"))
		return
	}
	var req struct {
		Hostname string `json:"hostname"`
		Service  string `json:"service"`
		Path     string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	hostname := strings.ToLower(strings.TrimSpace(req.Hostname))
	service := strings.TrimSpace(req.Service)
	path := strings.TrimSpace(req.Path)
	if hostname == "" || service == "" {
		s.writeJSON(w, http.StatusOK, apiErr("请填写域名与本地服务地址"))
		return
	}
	if !cloudflared.ValidService(service) {
		s.writeJSON(w, http.StatusOK, apiErr("服务地址仅支持 http:// 或 https:// 开头（Cloudflare 公网域名只能发布 HTTP/HTTPS 服务）"))
		return
	}
	b, err := s.cfBindingFor(inst)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	if !cloudflared.HostnameInZone(hostname, b.zoneName) {
		s.writeJSON(w, http.StatusOK, apiErr(fmt.Sprintf("域名需为 %s 或其子域名", b.zoneName)))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	routes := upsertRoute(s.cfRoutes(id), config.CloudflareRoute{Hostname: hostname, Service: service, Path: path})
	if err := b.client.PutIngress(ctx, b.accountID, b.tunnelID, toIngress(routes)); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("下发路由失败: "+err.Error()))
		return
	}
	s.cfSaveRoutes(id, routes)
	warning := ""
	if err := b.client.EnsureTunnelCNAME(ctx, b.zoneID, hostname, b.tunnelID); err != nil {
		warning = "路由已下发，但 DNS 记录处理失败: " + err.Error()
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"status":  s.cloudflareStatusData(),
		"warning": warning,
	}))
}

// handleCloudflareRoutesDelete 删除某实例的一条路由：整份下发 ingress → 清理 CNAME → 落库。
func (s *Server) handleCloudflareRoutesDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	inst, i := s.cfFind(id)
	if i < 0 {
		s.writeJSON(w, http.StatusOK, apiErr("实例不存在（可能已被删除）"))
		return
	}
	var req struct {
		Hostname string `json:"hostname"`
		Path     string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	hostname := strings.ToLower(strings.TrimSpace(req.Hostname))
	path := strings.TrimSpace(req.Path)
	if hostname == "" {
		s.writeJSON(w, http.StatusOK, apiErr("请指定要删除的域名"))
		return
	}
	b, err := s.cfBindingFor(inst)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	routes := removeRoute(s.cfRoutes(id), hostname, path)
	if err := b.client.PutIngress(ctx, b.accountID, b.tunnelID, toIngress(routes)); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("下发路由失败: "+err.Error()))
		return
	}
	s.cfSaveRoutes(id, routes)
	warning := ""
	// 同一域名下还有其它路由时不删 DNS 记录
	if !routeUsesHostname(routes, hostname) {
		if err := b.client.DeleteTunnelCNAME(ctx, b.zoneID, hostname, b.tunnelID); err != nil {
			warning = "路由已删除，但 DNS 记录清理失败: " + err.Error()
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"status":  s.cloudflareStatusData(),
		"warning": warning,
	}))
}

// handleCloudflareRoutesImport 从云端拉取 ingress 覆盖某实例的本地路由表（把后台的改动同步回本页）。
func (s *Server) handleCloudflareRoutesImport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	inst, i := s.cfFind(id)
	if i < 0 {
		s.writeJSON(w, http.StatusOK, apiErr("实例不存在（可能已被删除）"))
		return
	}
	b, err := s.cfBindingFor(inst)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	remote, err := b.client.GetIngress(ctx, b.accountID, b.tunnelID)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("拉取云端路由失败: "+err.Error()))
		return
	}
	list := make([]config.CloudflareRoute, 0, len(remote))
	for _, rule := range remote {
		list = append(list, config.CloudflareRoute{Hostname: rule.Hostname, Service: rule.Service, Path: rule.Path})
	}
	s.cfSaveRoutes(id, list)
	s.writeJSON(w, http.StatusOK, apiOK(s.cloudflareStatusData()))
}

// ---------- 路由表工具 ----------

// toIngress 本地路由表 → Cloudflare ingress 规则。
func toIngress(list []config.CloudflareRoute) []cloudflared.IngressRule {
	out := make([]cloudflared.IngressRule, 0, len(list))
	for _, r := range list {
		out = append(out, cloudflared.IngressRule{Hostname: r.Hostname, Path: r.Path, Service: r.Service})
	}
	return out
}

// upsertRoute 按 (域名, 路径) 覆盖式写入路由。
func upsertRoute(list []config.CloudflareRoute, item config.CloudflareRoute) []config.CloudflareRoute {
	for i := range list {
		if list[i].Hostname == item.Hostname && list[i].Path == item.Path {
			list[i] = item
			return list
		}
	}
	return append(list, item)
}

// removeRoute 按 (域名, 路径) 删除路由。
func removeRoute(list []config.CloudflareRoute, hostname, path string) []config.CloudflareRoute {
	out := make([]config.CloudflareRoute, 0, len(list))
	for _, r := range list {
		if r.Hostname == hostname && r.Path == path {
			continue
		}
		out = append(out, r)
	}
	return out
}

// routeUsesHostname 该域名下是否还有其它路由。
func routeUsesHostname(list []config.CloudflareRoute, hostname string) bool {
	for _, r := range list {
		if r.Hostname == hostname {
			return true
		}
	}
	return false
}
