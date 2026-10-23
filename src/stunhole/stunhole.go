// Package stunhole 实现基于 STUN 的本地端口公网暴露（尽力而为）。
//
// UDP：用一个 socket 同时承担「打洞保活」与「转发入口」——周期用 pion/stun 向 STUN
// 服务器发 Binding 维护 NAT 映射，读到的公网进来的包转发到目标服务。
// TCP：借助 go-reuseport 端口复用（SO_REUSEPORT），本地转发监听与 STUN-over-TCP
// 保活连接共存于同一端口，解决二次绑定端口冲突。
// 处于 CGNAT / 对称 NAT 时无法被公网直连，仅标记状态并提示（无中继兜底）。
package stunhole

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tunhook/store"

	"github.com/google/uuid"
	"github.com/pion/stun/v3"
	"go.uber.org/zap"
)

const (
	// stunPrefix 存储 KV 前缀（stunhole.{id}）。
	stunPrefix = "stunhole."
	// defaultKeepalive 默认保活 / 重探周期。
	// UDP NAT 映射超时常见为 10~30 秒，25 秒过于贴近上限；5 秒留足容错。
	defaultKeepalive = 5 * time.Second
	// defaultMaxFailures 打洞连续失败次数上限（未配置 / 旧数据缺字段时生效），
	// 达到后通道自动熔断停止，避免在不可达网络下无限轮换重试。
	defaultMaxFailures = 30
	// maxFailuresLimit 失败次数可配置上限（前端 / Create 校验）。
	maxFailuresLimit = 1000
)

// Hole 一个公网暴露通道（持久化配置 + 运行期状态）。
type Hole struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Proto       string `json:"proto"`        // udp / tcp
	ListenPort  int    `json:"listen_port"`  // 本地监听端口（要暴露到公网的端口）
	ListenIP    string `json:"listen_ip"`    // 监听通道：指定 IP（空 = 自动，监听所有地址）
	ListenIface string `json:"listen_iface"` // 监听通道：指定网卡名（非空时优先生效）
	Target      string `json:"target"`       // 转发目标，如 127.0.0.1:8080
	// UseDefaultStun 使用系统默认 STUN 服务器列表（默认开启）；
	// 关闭时使用 StunServers，仅对当前通道生效。
	UseDefaultStun bool     `json:"use_default_stun"`
	StunServers    []string `json:"stun_servers,omitempty"`
	Enabled        bool     `json:"enabled"`

	WebhookMode    string `json:"webhook_mode,omitempty"`    // Webhook 联动模式：auto=自动创建 / select=选择已有 / custom=自定义回调（空=select 兼容旧数据）
	WebhookTrigger string `json:"webhook_trigger,omitempty"` // 联动触发条件：addr_change=地址变化 / every_probe=每次打洞成功 / first_time=仅首次（空=addr_change）
	WebhookChannel string `json:"webhook_channel,omitempty"` // 联动的 Webhook 通道 ID（auto/custom 由联动自动分配回写；空=不联动）
	WebhookGroup   string `json:"webhook_group,omitempty"`   // auto 模式：新通道归入的分组（空=默认分组）
	WebhookURL     string `json:"webhook_url,omitempty"`     // custom 模式：通道回调接口地址（http(s)）
	WebhookMethod  string `json:"webhook_method,omitempty"`  // custom 模式：回调请求方式（默认 POST）
	WebhookBody    string `json:"webhook_body,omitempty"`    // custom 模式：回调请求体（JSON 模板）
	WebhookHeaders string `json:"webhook_headers,omitempty"` // custom 模式：回调请求头（每行一条 Key: Value）
	WebhookCallback string `json:"webhook_callback,omitempty"` // custom 模式：回调字符（上报验证）
	WebhookNoCheck bool   `json:"webhook_no_check,omitempty"` // custom 模式：禁用回调字符检测（默认开启检测）
	LogLevel       string `json:"log_level,omitempty"`       // 通道日志输出级别 debug/info/warn/error（空=info）
	LogEntries     int    `json:"log_entries,omitempty"`     // 通道日志保留条数 100-10000（空=默认 200）

	// 进阶选项（按协议生效，0 = 不限制 / 默认值）
	RateLimitKB     int64 `json:"rate_limit_kb,omitempty"`     // TCP 单端口限速（KB/s，0=不限）
	MaxConns        int   `json:"max_conns,omitempty"`         // TCP 单端口最大连接数（0=不限）
	UDPTimeoutMS    int   `json:"udp_timeout_ms,omitempty"`    // UDP 会话超时（毫秒，0=默认 30000）
	UDPMaxSessions  int   `json:"udp_max_sessions,omitempty"`  // UDP 单端口最大会话数（0=不限）
	UDPBlockSize    int   `json:"udp_block_size,omitempty"`    // UDP 最大块长度（字节，0=默认 1500）
	MaxFailures     int   `json:"max_failures,omitempty"`      // 连续打洞失败次数上限（1-1000，0/缺省=默认 30），达到后自动停止

	ListenAddr string `json:"listen_addr"` // 启动时实际解析出的监听 IPv4（运行期填充，重启后重新解析）

	Running   bool   `json:"running"`
	Public    string `json:"public"` // 公网映射 ip:port
	Status    string `json:"status"` // running / blocked / error / off
	LastError string `json:"last_error"`
	UpdatedAt int64  `json:"updated_at"`
	RxBytes   int64  `json:"rx_bytes"` // 累计下行（外部→目标），运行期内存计数，重启归零
	TxBytes   int64  `json:"tx_bytes"` // 累计上行（目标→外部）
	Conns     int64  `json:"conns"`    // 当前活跃转发会话数
}

// runtime 单个通道运行实例。
type runtime struct {
	cfg     Hole
	owner   *Manager
	cancel  context.CancelFunc
	mu      sync.Mutex
	bindIP  net.IP       // 启动时解析出的本地监听 IPv4（Start 填充，锁保护）
	logBuf  *holeLogBuf  // 通道事件日志缓冲（容量按 cfg.LogEntries，级别按 cfg.LogLevel 过滤）
	pc      *net.UDPConn // UDP 打洞 + 转发 socket
	ln      net.Listener // TCP 转发监听（与 STUN 保活连接经 reuseport 共存）
	clients sync.Map     // clientAddr(string) → *net.UDPConn(target)
	wg      sync.WaitGroup
	stopped bool
	rx      atomic.Int64 // 累计下行（外部→目标）
	tx      atomic.Int64 // 累计上行（目标→外部）
	conns   atomic.Int64 // 当前活跃转发会话数（TCP 连接 / UDP 会话）
	curSrv  string       // 当前使用的 STUN 服务器（打洞失败自动轮换，mu 保护）
	limiter *rateLimiter // 单端口限速器（TCP 转发双向共享；rate<=0 时空操作）
	failCount int        // 连续打洞失败次数（Start 清零，收到有效 STUN 响应清零，mu 保护）
	// UDP 公网自检：临时令牌与接收通知（mu 保护）
	checkToken []byte
	checkCh    chan struct{}
}

// stunCandidates 返回当前通道可用的 STUN 服务器地址：
// 开启“使用默认服务器”时取系统列表，否则取通道自己的列表；
// 最后按通道协议过滤（udp 通道 → udp/both；tcp 通道 → tcp/both）。
func (r *runtime) stunCandidates() []string {
	r.mu.Lock()
	useDefault := r.cfg.UseDefaultStun
	custom := append([]string(nil), r.cfg.StunServers...)
	proto := r.cfg.Proto
	r.mu.Unlock()

	var list []StunServer
	if useDefault || len(custom) == 0 {
		if r.owner != nil {
			list = r.owner.StunServers()
		}
	} else {
		// 通道自定义列表由用户按当前协议填写，视为同时适用于该协议的服务器
		for _, addr := range custom {
			list = append(list, StunServer{Addr: addr, Proto: "both"})
		}
	}
	if len(list) == 0 {
		list = DefaultStunServers()
	}
	var out []string
	for _, s := range list {
		if s.Proto == "tcp" && proto != "tcp" {
			continue
		}
		if s.Proto == "udp" && proto != "udp" {
			continue
		}
		out = append(out, s.Addr)
	}
	return out
}

// currentServer 返回上次成功使用的服务器；不在候选列表时取第一个。
func (r *runtime) currentServer() string {
	c := r.stunCandidates()
	if len(c) == 0 {
		return ""
	}
	r.mu.Lock()
	cur := r.curSrv
	r.mu.Unlock()
	for _, s := range c {
		if s == cur {
			return cur
		}
	}
	r.mu.Lock()
	r.curSrv = c[0]
	r.mu.Unlock()
	return c[0]
}

// rememberServer 记录本次成功的服务器，下次启动优先使用。
func (r *runtime) rememberServer(server string) {
	r.mu.Lock()
	r.curSrv = server
	r.mu.Unlock()
}

// rotateServer 打洞失败后切换到下一个支持通道协议的 STUN 服务器（循环轮换）。
func (r *runtime) rotateServer() string {
	c := r.stunCandidates()
	if len(c) == 0 {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := -1
	for i, a := range c {
		if a == r.curSrv {
			idx = i
			break
		}
	}
	next := c[(idx+1)%len(c)]
	r.curSrv = next
	return next
}

// HoleLog 通道事件日志条目（内存环形缓冲，重启清零）。
type HoleLog struct {
	Ts    int64  `json:"ts"`
	Level string `json:"level,omitempty"` // debug / info / warn / error
	Msg   string `json:"msg"`
}

const holeLogCap = 200 // 每通道默认日志条数（通道未配置 LogEntries 时生效）

// holeLogBuf 单通道日志缓冲（容量创建时固定）。
type holeLogBuf struct {
	mu  sync.Mutex
	buf []HoleLog
}

// newHoleLogBuf 创建日志缓冲；entries 限制在 100-10000，非法/未配置时用默认容量。
func newHoleLogBuf(entries int) *holeLogBuf {
	cap2 := entries
	if cap2 < 100 || cap2 > 10000 {
		cap2 = holeLogCap
	}
	return &holeLogBuf{buf: make([]HoleLog, 0, cap2)}
}

func (b *holeLogBuf) add(ts int64, level, msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, HoleLog{Ts: ts, Level: level, Msg: msg})
	if len(b.buf) >= cap(b.buf) && cap(b.buf) > 0 {
		b.buf = b.buf[len(b.buf)-cap(b.buf)+1:]
	}
}

func (b *holeLogBuf) snapshot() []HoleLog {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]HoleLog, len(b.buf))
	copy(out, b.buf)
	return out
}

// logLevelRank 日志级别权重（数值越大越严重），用于按通道配置过滤输出。
func logLevelRank(l string) int {
	switch l {
	case "debug":
		return 0
	case "warn":
		return 2
	case "error":
		return 3
	default:
		return 1 // info（含未配置）
	}
}

// StunServer STUN 服务器候选（来自系统设置，打洞时按通道协议筛选）。
type StunServer struct {
	Addr  string
	Proto string // udp / tcp / both
}

// DefaultStunServers 是内置默认列表（2026-10 实测均支持 TCP 与 UDP）。
// 不能把未验证的 UDP-only 服务器标成 both，否则 TCP 通道会选中一个无法完成
// STUN-over-TCP 事务的地址，表现为“TCP 握手成功但读响应超时”。
func DefaultStunServers() []StunServer {
	return []StunServer{
		{Addr: "stun.nextcloud.com:3478", Proto: "both"},
		{Addr: "stun.hot-chilli.net:3478", Proto: "both"},
		{Addr: "stun.voip.blackberry.com:3478", Proto: "both"},
		{Addr: "stun.radiojar.com:3478", Proto: "both"},
		{Addr: "stun.freeswitch.org:3478", Proto: "both"},
	}
}

// normalizeStunServers 去空、去重并校验 host:port 格式。
func normalizeStunServers(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			return nil, fmt.Errorf("STUN 服务器 %q 格式应为 host:port", s)
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

// Manager 管理多个打洞暴露通道。
type Manager struct {
	st     *store.Store
	logger *zap.Logger
	mu     sync.Mutex
	holes  map[string]*runtime
	ka     atomic.Int64 // 保活 / 重探周期（纳秒），可由 STUN 设置调整
	srvMu   sync.Mutex
	srvList []StunServer // STUN 服务器候选（web 层注入）

	// OnPublicChange 公网映射地址变化回调（web 层注入，如联动注册 Webhook 通道）。
	// 在锁外调用，参数为通道配置拷贝；回调内不得再调用 Manager.Get/List（避免锁等待）。
	OnPublicChange func(h Hole)
}

// NewManager 创建 Manager。
func NewManager(st *store.Store, logger *zap.Logger) *Manager {
	m := &Manager{st: st, logger: logger, holes: map[string]*runtime{}, srvList: DefaultStunServers()}
	m.ka.Store(int64(defaultKeepalive))
	return m
}

// SetStunServers 注入 STUN 服务器候选列表（系统设置保存/加载时调用）。
func (m *Manager) SetStunServers(list []StunServer) {
	m.srvMu.Lock()
	defer m.srvMu.Unlock()
	m.srvList = append([]StunServer(nil), list...)
}

// StunServers 返回 STUN 服务器候选列表（副本）。
func (m *Manager) StunServers() []StunServer {
	m.srvMu.Lock()
	defer m.srvMu.Unlock()
	return append([]StunServer(nil), m.srvList...)
}

// SetKeepalive 调整保活周期（下限 5 秒），对之后创建的 ticker 生效。
func (m *Manager) SetKeepalive(d time.Duration) {
	if d >= 5*time.Second {
		m.ka.Store(int64(d))
	}
}

// Keepalive 返回当前保活周期。
func (m *Manager) Keepalive() time.Duration { return time.Duration(m.ka.Load()) }

// Restore 从数据库恢复持久化通道，并拉起启用中的通道。
func (m *Manager) Restore() {
	kv, err := m.st.SettingsByPrefix(stunPrefix)
	if err != nil {
		m.logger.Warn("stunhole: 加载持久化通道失败", zap.Error(err))
		return
	}
	for key, raw := range kv {
		var h Hole
		if err := json.Unmarshal([]byte(raw), &h); err != nil {
			m.logger.Warn("stunhole: 通道解析失败", zap.String("key", key), zap.Error(err))
			continue
		}
		// Running 是运行态，重启后一律复位为未运行，实际是否拉起由 Enabled 决定
		h.Running = false
		// 旧数据没有 use_default_stun/stun_servers 字段：回落到系统默认列表，
		// 避免继续沿用旧的单一 stun_server（可能是 UDP-only 地址）。
		if !h.UseDefaultStun && len(h.StunServers) == 0 {
			h.UseDefaultStun = true
		}
		if !h.Enabled {
			h.Status = "off"
		}
		m.mu.Lock()
		m.holes[h.ID] = newRuntime(h, m)
		enabled := h.Enabled
		m.mu.Unlock()
		if enabled {
			m.Start(h.ID)
		}
	}
}

// List 返回所有通道（含运行态与流量计数）。
func (m *Manager) List() []Hole {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Hole, 0, len(m.holes))
	for _, r := range m.holes {
		out = append(out, r.snapshot())
	}
	return out
}

// Get 返回单个通道（含运行态与流量计数）。
func (m *Manager) Get(id string) (Hole, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.holes[id]
	if !ok {
		return Hole{}, false
	}
	return r.snapshot(), true
}

// snapshot 拷贝配置并填充实时流量计数与活跃会话数。
func (r *runtime) snapshot() Hole {
	r.mu.Lock()
	h := r.cfg
	r.mu.Unlock()
	h.RxBytes = r.rx.Load()
	h.TxBytes = r.tx.Load()
	h.Conns = r.conns.Load()
	return h
}

// newRuntime 创建通道运行实例（日志缓冲容量按通道 LogEntries 配置，限速器按 RateLimitKB 初始化）。
func newRuntime(cfg Hole, owner *Manager) *runtime {
	return &runtime{cfg: cfg, owner: owner, logBuf: newHoleLogBuf(cfg.LogEntries), limiter: newRateLimiter(cfg.RateLimitKB * 1024)}
}

// udpBlockSize 返回 UDP 读缓冲块长度（0=默认 1500，上限 65000）。
func (r *runtime) udpBlockSize() int {
	r.mu.Lock()
	size := r.cfg.UDPBlockSize
	r.mu.Unlock()
	if size <= 0 {
		size = 1500
	}
	if size > 65000 {
		size = 65000
	}
	return size
}

// udpMaxSessions 返回 UDP 单端口最大会话数（0=不限）。
func (r *runtime) udpMaxSessions() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg.UDPMaxSessions
}

// udpTimeout 返回 UDP 会话空闲超时（0=默认 30 秒）。
func (r *runtime) udpTimeout() time.Duration {
	r.mu.Lock()
	ms := r.cfg.UDPTimeoutMS
	r.mu.Unlock()
	if ms <= 0 {
		return 30 * time.Second
	}
	return time.Duration(ms) * time.Millisecond
}

// maxFailures 返回打洞连续失败次数上限（未配置 / 旧数据缺字段 → 默认 30）。
func (r *runtime) maxFailures() int {
	r.mu.Lock()
	n := r.cfg.MaxFailures
	r.mu.Unlock()
	if n <= 0 {
		return defaultMaxFailures
	}
	return n
}

// bumpFailure 连续失败计数 +1 并返回当前次数。
func (r *runtime) bumpFailure() int {
	r.mu.Lock()
	r.failCount++
	n := r.failCount
	r.mu.Unlock()
	return n
}

// SetWebhookChannel 回写自动分配的联动 Webhook 通道 ID（auto 模式首次联动时调用，不触发通道重启）。
func (m *Manager) SetWebhookChannel(id, channelID string) {
	m.mu.Lock()
	r := m.holes[id]
	m.mu.Unlock()
	if r == nil {
		return
	}
	r.mu.Lock()
	r.cfg.WebhookChannel = channelID
	h := r.cfg
	r.mu.Unlock()
	_ = m.persist(h)
}

// Create 创建并持久化一个通道；forceStart 为 true 时立即尝试打洞。
func (m *Manager) Create(h Hole, forceStart bool) (Hole, error) {
	if h.Proto == "" {
		h.Proto = "tcp"
	}
	if h.Proto != "udp" && h.Proto != "tcp" {
		return h, fmt.Errorf("协议仅支持 udp / tcp")
	}
	// 本地监听端口：0 表示由系统自动分配一个未被占用的高位端口（删除后自动释放）；
	// 用户指定时校验范围并检查占用（创建即打洞，避免创建成功却启动失败）。
	if h.ListenPort == 0 {
		port, err := allocPort()
		if err != nil {
			return h, fmt.Errorf("自动分配端口失败: %w", err)
		}
		h.ListenPort = port
	} else if h.ListenPort < 1 || h.ListenPort > 65535 {
		return h, fmt.Errorf("监听端口无效")
	} else if !portFree(h.ListenPort) {
		return h, fmt.Errorf("端口 %d 已被占用", h.ListenPort)
	}
	if h.ListenIP != "" && net.ParseIP(strings.TrimSpace(h.ListenIP)).To4() == nil {
		return h, fmt.Errorf("监听地址 %s 不是有效的 IPv4", h.ListenIP)
	}
	if h.Target == "" {
		return h, fmt.Errorf("转发目标不能为空")
	}
	if h.Name == "" {
		h.Name = "stun-" + strconv.Itoa(h.ListenPort)
	}
	servers, err := normalizeStunServers(h.StunServers)
	if err != nil {
		return h, err
	}
	h.StunServers = servers
	// 未填自定义列表时一律回落到系统默认列表（兼容旧数据与 API 调用）
	if len(h.StunServers) == 0 {
		h.UseDefaultStun = true
	}
	// 最大连续失败次数：0/缺省 = 默认 30，超出上限拒绝（前端同步约束）
	if h.MaxFailures == 0 {
		h.MaxFailures = defaultMaxFailures
	} else if h.MaxFailures < 0 || h.MaxFailures > maxFailuresLimit {
		return h, fmt.Errorf("最大失败次数需在 1-%d 之间", maxFailuresLimit)
	}
	if h.ID == "" {
		h.ID = uuid.NewString()
	}
	h.Status = "off"
	h.Running = false
	if !forceStart {
		h.Enabled = false
	}
	if err := m.persist(h); err != nil {
		return h, err
	}
	m.mu.Lock()
	m.holes[h.ID] = newRuntime(h, m)
	m.mu.Unlock()
	if forceStart {
		m.Start(h.ID)
	}
	return h, nil
}

// Delete 删除通道（停止运行并移除持久化）。
func (m *Manager) Delete(id string) error {
	m.Stop(id)
	m.mu.Lock()
	delete(m.holes, id)
	m.mu.Unlock()
	return m.st.DeleteSetting(stunPrefix + id)
}

// addLog 记录通道事件日志（info 级别）。
func (m *Manager) addLog(id, format string, args ...interface{}) {
	m.addLogL(id, "info", format, args...)
}

// addLogL 记录通道事件日志；低于通道配置输出级别的日志直接丢弃。
func (m *Manager) addLogL(id, level, format string, args ...interface{}) {
	m.mu.Lock()
	r := m.holes[id]
	m.mu.Unlock()
	if r == nil || r.logBuf == nil {
		return
	}
	r.mu.Lock()
	minRank := logLevelRank(r.cfg.LogLevel)
	r.mu.Unlock()
	if logLevelRank(level) < minRank {
		return
	}
	r.logBuf.add(time.Now().Unix(), level, fmt.Sprintf(format, args...))
}

// Logs 返回通道事件日志（时间升序）。
func (m *Manager) Logs(id string) []HoleLog {
	m.mu.Lock()
	r := m.holes[id]
	m.mu.Unlock()
	if r == nil || r.logBuf == nil {
		return []HoleLog{}
	}
	return r.logBuf.snapshot()
}

// Start 启动通道打洞暴露。
func (m *Manager) Start(id string) {
	m.mu.Lock()
	r := m.holes[id]
	m.mu.Unlock()
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.cfg.Running {
		r.mu.Unlock()
		return
	}
	// 解析监听通道：指定网卡 / 指定 IP / 自动本机局域网 IPv4；失败直接置错误态
	bindIP, berr := r.resolveBindIP()
	if berr != nil {
		r.cfg.Running = false
		r.cfg.Status = "error"
		r.cfg.LastError = berr.Error()
		r.cfg.UpdatedAt = time.Now().Unix()
		r.mu.Unlock()
		m.persist(r.cfg)
		m.addLogL(id, "error", "启动失败：%s", berr.Error())
		return
	}
	r.bindIP = bindIP
	r.cfg.ListenAddr = bindIP.String()
	r.cfg.Running = true
	r.cfg.Enabled = true // 启用状态：服务重启后 Restore 据此恢复运行中的通道
	r.cfg.Status = "starting"
	r.cfg.LastError = ""
	r.cfg.UpdatedAt = time.Now().Unix()
	r.stopped = false
	r.failCount = 0 // 新的启动周期：连续失败计数从零开始
	r.mu.Unlock()
	m.persist(r.cfg)

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	var fwdErr error
	if r.cfg.Proto == "tcp" {
		fwdErr = r.startTCP(ctx)
	} else {
		fwdErr = r.startUDP(ctx)
	}
	if fwdErr != nil {
		r.mu.Lock()
		r.cfg.Running = false
		r.cfg.Status = "error"
		r.cfg.LastError = "监听失败: " + fwdErr.Error()
		r.cfg.UpdatedAt = time.Now().Unix()
		r.mu.Unlock()
		m.persist(r.cfg)
		m.addLogL(id, "error", "启动失败：监听 %d 端口失败（%v）", r.cfg.ListenPort, fwdErr)
		return
	}
	stunDesc := "系统默认列表"
	if !r.cfg.UseDefaultStun {
		stunDesc = strings.Join(r.cfg.StunServers, "、")
	}
	m.addLog(id, "已启动，本地监听端口 %d（%s → %s，STUN %s）", r.cfg.ListenPort, r.cfg.Proto, r.cfg.Target, stunDesc)
	// 自动在网关添加 UPnP 端口映射（尽力而为，失败只告警不影响转发；Stop 时随 ctx 取消自动删除）
	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.upnpLoop(ctx) }()
	m.logger.Info("stunhole: 打洞通道已启动", zap.String("id", id), zap.Int("port", r.cfg.ListenPort))
}

// teardown 取消运行上下文并等待所有 goroutine 退出（含 UPnP 网关映射删除）。
// 只做资源回收，不触碰持久化的启用状态与配置。
func (r *runtime) teardown() {
	if r.cancel != nil {
		r.cancel()
	}
	r.mu.Lock()
	pc, ln := r.pc, r.ln
	r.stopped = true
	r.mu.Unlock()
	if pc != nil {
		pc.Close()
	}
	if ln != nil {
		ln.Close()
	}
	r.clients.Range(func(k, v interface{}) bool {
		if c, ok := v.(*net.UDPConn); ok {
			c.Close()
		}
		return true
	})
	r.wg.Wait()
}

// Stop 停止通道（用户手动停用）：回收资源并持久化为停用状态，重启后不再恢复。
func (m *Manager) Stop(id string) {
	m.mu.Lock()
	r := m.holes[id]
	m.mu.Unlock()
	if r == nil {
		return
	}
	r.teardown()
	r.mu.Lock()
	r.cfg.Running = false
	r.cfg.Enabled = false // 停用状态：服务重启后不再恢复
	r.cfg.Status = "off"
	r.cfg.UpdatedAt = time.Now().Unix()
	h := r.cfg
	r.mu.Unlock()
	m.persist(h)
	m.addLog(id, "已停止")
}

// autoStopByFailure 连续打洞失败达到上限后的自动熔断：置错误停用态并持久化，
// 重启后不再自动拉起，需用户排查网络 / STUN 服务器后手动启动（Start 会重新计数）。
// 资源回收必须异步：本方法运行在打洞循环 goroutine 内（它自身是 r.wg 成员），
// 同步调 teardown() 的 wg.Wait() 会等待自己而永久死锁。
func (m *Manager) autoStopByFailure(id string, fails int) {
	m.mu.Lock()
	r := m.holes[id]
	m.mu.Unlock()
	if r == nil {
		return
	}
	r.mu.Lock()
	r.cfg.Running = false
	r.cfg.Enabled = false
	r.cfg.Status = "error"
	r.cfg.LastError = fmt.Sprintf("连续 %d 次 STUN 打洞失败，已自动停止", fails)
	r.cfg.UpdatedAt = time.Now().Unix()
	h := r.cfg
	r.mu.Unlock()
	m.persist(h)
	m.addLogL(id, "error", "连续 %d 次打洞失败（已达上限），通道自动停止；排查网络或 STUN 服务器后可手动启动", fails)
	m.logger.Warn("stunhole: 连续打洞失败达到上限，通道已自动停止", zap.String("id", id), zap.Int("failures", fails))
	// 独立 goroutine 回收：cancel 后打洞循环随即退出（wg.Done），Wait 方可正常返回
	go r.teardown()
}

// StopAll 服务退出时停止全部运行中的通道：回收资源（删除网关上的 UPnP 映射等），
// 但不改变持久化的 Enabled 状态，服务下次启动后启用中的通道照常恢复。
func (m *Manager) StopAll() {
	m.mu.Lock()
	rs := make([]*runtime, 0, len(m.holes))
	for _, r := range m.holes {
		rs = append(rs, r)
	}
	m.mu.Unlock()
	for _, r := range rs {
		r.mu.Lock()
		running := r.cfg.Running
		r.mu.Unlock()
		if running {
			r.teardown()
		}
	}
}

// Update 更新通道配置（名称/协议/目标/STUN 服务器）；监听端口保持不变，
// 运行中的通道自动重启以应用新配置。
func (m *Manager) Update(id string, req Hole) (Hole, error) {
	m.mu.Lock()
	r := m.holes[id]
	m.mu.Unlock()
	if r == nil {
		return Hole{}, errors.New("通道不存在")
	}
	if req.Proto != "" && req.Proto != "udp" && req.Proto != "tcp" {
		return Hole{}, fmt.Errorf("协议仅支持 udp / tcp")
	}
	// 最大连续失败次数（仅依赖入参，放在 r.mu 加锁前校验，避免锁内提前返回泄漏锁）：
	// 0 = 回退默认 30
	if req.MaxFailures < 0 || req.MaxFailures > maxFailuresLimit {
		return Hole{}, fmt.Errorf("最大失败次数需在 1-%d 之间", maxFailuresLimit)
	}
	if req.MaxFailures == 0 {
		req.MaxFailures = defaultMaxFailures
	}
	servers, err := normalizeStunServers(req.StunServers)
	if err != nil {
		return Hole{}, err
	}
	useDefaultStun := req.UseDefaultStun || len(servers) == 0
	r.mu.Lock()
	h := r.cfg
	wasRunning := h.Running
	if req.Name != "" {
		h.Name = req.Name
	}
	if req.Proto != "" {
		h.Proto = req.Proto
	}
	if req.Target != "" {
		h.Target = req.Target
	}
	h.UseDefaultStun = useDefaultStun
	h.StunServers = servers
	// 监听端口：> 0 时更新（0 = 保持不变）；启动失败会在状态中反馈占用错误
	if req.ListenPort > 0 {
		if req.ListenPort > 65535 {
			return Hole{}, fmt.Errorf("监听端口无效")
		}
		h.ListenPort = req.ListenPort
	}
	// 监听通道（指定 IP / 指定网卡）：前端总是显式提交，直接覆盖（均为空 = 自动）
	if req.ListenIP != "" && net.ParseIP(strings.TrimSpace(req.ListenIP)).To4() == nil {
		return Hole{}, fmt.Errorf("监听地址 %s 不是有效的 IPv4", req.ListenIP)
	}
	h.ListenIP = strings.TrimSpace(req.ListenIP)
	h.ListenIface = strings.TrimSpace(req.ListenIface)
	// Webhook 联动与日志设置：显式覆盖（log_entries 非法时按默认容量处理）
	modeChanged := h.WebhookMode != req.WebhookMode
	h.WebhookMode = req.WebhookMode
	h.WebhookTrigger = req.WebhookTrigger
	switch req.WebhookMode {
	case "select":
		h.WebhookChannel = strings.TrimSpace(req.WebhookChannel)
	default: // auto / custom：通道 ID 由后端联动分配回写，模式不变时保留原值，切换模式时清空待首次联动重新分配
		if modeChanged {
			h.WebhookChannel = ""
		}
	}
	h.WebhookGroup = strings.TrimSpace(req.WebhookGroup)
	h.WebhookURL = strings.TrimSpace(req.WebhookURL)
	h.WebhookMethod = strings.TrimSpace(req.WebhookMethod)
	h.WebhookBody = req.WebhookBody
	h.WebhookHeaders = strings.TrimSpace(req.WebhookHeaders)
	h.WebhookCallback = strings.TrimSpace(req.WebhookCallback)
	h.WebhookNoCheck = req.WebhookNoCheck
	h.LogLevel = req.LogLevel
	h.LogEntries = req.LogEntries
	// 进阶选项：显式覆盖（0 = 不限制 / 默认值），限速参数变化时重建限速器
	h.RateLimitKB = req.RateLimitKB
	h.MaxConns = req.MaxConns
	h.UDPTimeoutMS = req.UDPTimeoutMS
	h.UDPMaxSessions = req.UDPMaxSessions
	h.UDPBlockSize = req.UDPBlockSize
	h.MaxFailures = req.MaxFailures
	h.UpdatedAt = time.Now().Unix()
	logRebuilt := r.cfg.LogEntries != h.LogEntries
	rateChanged := r.cfg.RateLimitKB != h.RateLimitKB
	r.cfg = h
	if logRebuilt {
		r.logBuf = newHoleLogBuf(h.LogEntries) // 容量变化重建日志缓冲（旧日志随之清空）
	}
	if rateChanged {
		r.limiter = newRateLimiter(h.RateLimitKB * 1024)
	}
	r.mu.Unlock()
	if err := m.persist(h); err != nil {
		return h, err
	}
	stunDesc := "系统默认列表"
	if !h.UseDefaultStun {
		stunDesc = strings.Join(h.StunServers, "、")
	}
	m.addLog(id, "配置已更新：协议 %s，目标 %s，STUN %s", h.Proto, h.Target, stunDesc)
	if wasRunning {
		m.addLog(id, "通道运行中，自动重启以应用新配置")
		m.Stop(id)
		m.Start(id)
	}
	return r.snapshot(), nil
}

// persist 写入数据库（KV: stunhole.{id}）。
func (m *Manager) persist(h Hole) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return m.st.SetSetting(stunPrefix+h.ID, string(b))
}

// startUDP 启动打洞 + 转发循环（socket 由 udpServe 建立，切换服务器时自动重建）。
func (r *runtime) startUDP(ctx context.Context) error {
	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.udpLoop(ctx) }()
	return nil
}

// udpLoop 打洞主循环：当前 STUN 服务器不可用（解析失败 / socket 异常 / 连续无响应）时，
// 自动切换到下一个支持通道协议的服务器重试（循环轮换，候选穷尽后从头再来）。
func (r *runtime) udpLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		server := r.currentServer()
		if err := r.udpServe(ctx, server); err != nil {
			fails := r.bumpFailure()
			limit := r.maxFailures()
			if r.owner != nil {
				r.owner.addLogL(r.cfg.ID, "warn", "STUN 服务器 %s 打洞失败（%v），自动切换（连续失败 %d/%d）", server, err, fails, limit)
			}
			if fails >= limit {
				// 连续失败达上限：熔断停止，不再轮换（autoStopByFailure 会取消 ctx 并回收资源）
				if r.owner != nil {
					r.owner.autoStopByFailure(r.cfg.ID, fails)
				}
				return
			}
			r.setStatus("error", "STUN 服务器不可用: "+err.Error())
		}
		next := r.rotateServer()
		if ctx.Err() != nil {
			return
		}
		// 服务器轮换是正常流转，只记事件日志；不得写入 LastError，否则会作为「错误」常驻状态列
		r.setStatus("starting", "")
		if r.owner != nil {
			r.owner.addLogL(r.cfg.ID, "info", "已切换 STUN 服务器 → %s", next)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second): // 切换间隔，避免紧密重试
		}
	}
}

// udpServe 用指定 STUN 服务器建立打洞 + 转发循环。
// 返回 nil 表示 ctx 结束（正常停止）；返回错误表示该服务器不可用，应切换重试。
func (r *runtime) udpServe(ctx context.Context, server string) error {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: r.bindAddr(), Port: r.cfg.ListenPort})
	if err != nil {
		return fmt.Errorf("监听 %d 端口失败: %w", r.cfg.ListenPort, err)
	}
	r.mu.Lock()
	r.pc = pc
	r.mu.Unlock()
	defer func() {
		pc.Close()
		r.mu.Lock()
		if r.pc == pc {
			r.pc = nil
		}
		r.mu.Unlock()
	}()
	stunAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return fmt.Errorf("解析 STUN 服务器失败: %w", err)
	}
	stunIP := stunAddr.IP

	sendBinding := func() {
		msg := stun.MustBuild(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
		_, _ = pc.WriteToUDP(msg.Raw, stunAddr)
	}
	sendBinding() // 立即探测一次

	// 保活与无响应判定改用时间戳，不再用 ticker + select(default)：
	// 原结构靠 select 的 default 分支"顺带"检查 ticker，一旦读操作立即返回
	//（时钟跳变、平台 poller 异常等），节流点就失效、退化为全速空转。
	// 现改为每次读返回后按时间戳判断，并给超时路径补足等待兜底。
	lastSend := time.Now() // 最近一次发保活的时间
	lastMap := time.Now()  // 最近一次收到公网映射的时间（无响应判定基准）
	firstProbe := true     // 首次探测使用短超时，坏服务器不阻塞启动
	checked := false       // 公网自检只在首个映射后执行一次
	ka := r.owner.Keepalive()
	buf := make([]byte, r.udpBlockSize())
	const readWait = 500 * time.Millisecond
	for {
		start := time.Now()
		_ = pc.SetReadDeadline(start.Add(readWait))
		n, src, err := pc.ReadFromUDP(buf)

		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if time.Since(lastSend) >= ka {
			sendBinding() // 保活 / 重探
			lastSend = time.Now()
		}
		if firstProbe {
			// 启动阶段：单个服务器最多等 5 秒，失败立即轮换到下一个
			if time.Since(lastMap) > 5*time.Second {
				return fmt.Errorf("STUN 服务器 %s 首次探测超时", server)
			}
		} else if time.Since(lastMap) > 4*ka {
			// 连续 4 个保活周期无任何映射响应 → 判定该服务器不可用，触发切换
			return fmt.Errorf("连续 %s 无 STUN 响应", (4 * ka).Round(time.Second))
		}

		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// 正常应等满 readWait 才超时；若立即返回，说明 deadline 未生效，
				// 主动补足等待，避免本循环退化成全速空转
				if wait := readWait - time.Since(start); wait > 0 {
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(wait):
					}
				}
				continue
			}
			select {
			case <-ctx.Done():
				return nil // Stop 关闭 socket 所致
			default:
			}
			return fmt.Errorf("socket 异常: %w", err)
		}
		// 公网自检令牌：从另一个 socket 发到自身公网地址，能回到这里说明回环可达
		r.mu.Lock()
		token, tokenCh := r.checkToken, r.checkCh
		r.mu.Unlock()
		if token != nil && bytes.Equal(buf[:n], token) {
			select {
			case tokenCh <- struct{}{}:
			default:
			}
			continue
		}
		if src.IP.Equal(stunIP) {
			if public, ok := parseStunPublic(buf[:n]); ok {
				lastMap = time.Now()
				firstProbe = false
				r.rememberServer(server)
				r.applyPublic(public)
				if !checked {
					checked = true
					go func(pub string) {
						if err := r.udpSelfCheck(pub, 3*time.Second); err != nil {
							if r.owner != nil {
								r.owner.addLogL(r.cfg.ID, "warn", "公网自检未通过（部分 NAT 不支持回环，可忽略）：%v", err)
							}
						}
					}(public)
				}
			}
			continue
		}
		r.forwardUDP(buf[:n], src)
		r.rx.Add(int64(n))
	}
}

// udpSelfCheck 从另一个 UDP socket 向自身公网地址发送随机令牌，
// 若能经 NAT 回环回到通道 socket，说明入站路径可达。
// 很多 NAT 不支持 hairpin，失败只告警，不影响通道运行。
func (r *runtime) udpSelfCheck(public string, timeout time.Duration) error {
	token := make([]byte, 16)
	_, _ = rand.Read(token)
	ch := make(chan struct{}, 1)
	r.mu.Lock()
	r.checkToken, r.checkCh = token, ch
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		// 只清理自己设置的令牌，避免服务器轮换时误清新一轮自检
		if bytes.Equal(r.checkToken, token) {
			r.checkToken, r.checkCh = nil, nil
		}
		r.mu.Unlock()
	}()
	c, err := net.Dial("udp4", public)
	if err != nil {
		return err
	}
	defer c.Close()
	wait := timeout / 3
	for i := 0; i < 3; i++ {
		if _, err := c.Write(token); err != nil {
			return err
		}
		select {
		case <-ch:
			return nil
		case <-time.After(wait):
		}
	}
	return errors.New("未收到回环数据包")
}

// forwardUDP 把外部来的包转发到 target；target 响应写回来源。
// 超出通道 UDPMaxSessions 上限时丢弃新来源的包（0=不限）。
func (r *runtime) forwardUDP(buf []byte, src *net.UDPAddr) {
	var dst *net.UDPConn
	if v, ok := r.clients.Load(src.String()); ok {
		dst = v.(*net.UDPConn)
	} else {
		if max := r.udpMaxSessions(); max > 0 && r.conns.Load() >= int64(max) {
			return // 超出最大会话数，丢弃
		}
		target, err := net.ResolveUDPAddr("udp", r.cfg.Target)
		if err != nil {
			return
		}
		dst, err = net.DialUDP("udp", nil, target)
		if err != nil {
			return
		}
		r.clients.Store(src.String(), dst)
		r.wg.Add(1)
		go r.udpBackLoop(src, dst)
	}
	// 来源仍活跃：刷新会话读超时（udpBackLoop 超时未刷新则回收会话）
	_ = dst.SetReadDeadline(time.Now().Add(r.udpTimeout()))
	_, _ = dst.Write(buf)
}

// udpBackLoop 读 target 响应写回 client；会话空闲超过 udpTimeout 后自动回收。
func (r *runtime) udpBackLoop(src *net.UDPAddr, dst *net.UDPConn) {
	defer r.wg.Done()
	defer r.conns.Add(-1)
	r.conns.Add(1)
	defer r.clients.Delete(src.String())
	buf := make([]byte, r.udpBlockSize())
	_ = dst.SetReadDeadline(time.Now().Add(r.udpTimeout()))
	for {
		n, err := dst.Read(buf)
		if err != nil {
			return
		}
		if _, werr := r.pc.WriteToUDP(buf[:n], src); werr != nil {
			return
		}
		r.tx.Add(int64(n))
	}
}

// applyPublic 根据映射结果更新状态与公网地址；按触发条件决定是否通知联动钩子（锁外）。
func (r *runtime) applyPublic(public string) {
	r.mu.Lock()
	prev := r.cfg.Public
	changed := prev != public
	r.cfg.Public = public
	// 收到有效 STUN 响应即说明当前服务器可用（CGNAT 映射也算），连续失败计数清零
	r.failCount = 0
	r.cfg.UpdatedAt = time.Now().Unix()
	private := isPrivateOrCGNAT(public)
	if private {
		r.cfg.Status = "blocked"
		r.cfg.LastError = "处于 CGNAT / 私有 NAT，公网无法直连"
	} else {
		r.cfg.Status = "running"
		r.cfg.LastError = ""
	}
	h := r.cfg
	r.mu.Unlock()

	if r.owner == nil {
		return
	}
	_ = r.owner.persist(h)
	// 仅映射地址变化时记录，避免保活周期重复刷日志
	if changed {
		if private {
			r.owner.addLogL(h.ID, "warn", "公网映射地址 %s（CGNAT / 私有，公网无法直连）", public)
		} else {
			r.owner.addLogL(h.ID, "info", "公网映射地址 %s", public)
		}
	}
	// Webhook 联动按触发条件判定：addr_change（默认，地址变化）/ every_probe（每次打洞成功）/ first_time（仅首次获得地址）
	if !private && r.owner.OnPublicChange != nil {
		fire := false
		switch h.WebhookTrigger {
		case "every_probe":
			fire = true
		case "first_time":
			fire = prev == ""
		default: // addr_change / 空
			fire = changed
		}
		if fire {
			r.owner.OnPublicChange(h)
		}
	}
}

// setStatus 更新运行状态；状态或错误信息变化时记入事件日志（锁外记日志，避免与 List 的 m.mu→r.mu 顺序死锁）。
func (r *runtime) setStatus(status, lastErr string) {
	r.mu.Lock()
	changed := r.cfg.Status != status || r.cfg.LastError != lastErr
	r.cfg.Status = status
	r.cfg.LastError = lastErr
	r.cfg.UpdatedAt = time.Now().Unix()
	id := r.cfg.ID
	r.mu.Unlock()
	if changed && r.owner != nil {
		if lastErr != "" {
			r.owner.addLogL(id, "warn", "状态 → %s：%s", status, lastErr)
		} else {
			r.owner.addLog(id, "状态 → %s", status)
		}
	}
}

// parseStunPublic 解析 STUN Binding Success 响应中的公网映射地址。
func parseStunPublic(raw []byte) (string, bool) {
	m := new(stun.Message)
	m.Raw = raw
	if err := m.Decode(); err != nil {
		return "", false
	}
	if m.Type != stun.BindingSuccess {
		return "", false
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(m); err != nil {
		return "", false
	}
	return net.JoinHostPort(xor.IP.String(), strconv.Itoa(xor.Port)), true
}

// isPrivateOrCGNAT 判断公网映射地址是否为私有 / CGNAT 段（无法被公网直连）。
func isPrivateOrCGNAT(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	v4 := ip.To4()
	if v4 == nil {
		return ip.IsLoopback() || ip.IsLinkLocalUnicast()
	}
	if v4[0] == 100 && v4[1]&0xc0 == 0x40 { // 100.64.0.0/10 CGNAT
		return true
	}
	return v4.IsPrivate() || v4.IsLoopback() || v4.IsLinkLocalUnicast()
}

// ifaceIPv4 返回指定网卡上首个可用 IPv4（跳过回环 / 链路本地 / 组播地址）。
func ifaceIPv4(name string) (net.IP, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() && !ip4.IsMulticast() {
			return ip4, nil
		}
	}
	return nil, errors.New("未找到可用 IPv4")
}

// autoLocalIPv4 返回本机局域网 IPv4（首个启用且带地址的网卡）。
func autoLocalIPv4() net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ip, err := ifaceIPv4(ifc.Name); err == nil {
			return ip
		}
	}
	return nil
}

// resolveBindIP 解析通道的本地监听 IPv4：
// 指定网卡 → 取该网卡首个可用 IPv4（失败报错，不做静默回退）；
// 指定 IP → 校验为合法 IPv4；
// 均未指定 → 监听 0.0.0.0，由内核路由决定出站源地址。
// 不再默认绑定“访问公网时的源 IPv4”：多网卡 / VPN / Docker 环境下该地址
// 可能不是路由器可达的 LAN 地址，会导致入站连接与 UPnP 映射指向错误接口。
func (r *runtime) resolveBindIP() (net.IP, error) {
	if name := strings.TrimSpace(r.cfg.ListenIface); name != "" {
		ip, err := ifaceIPv4(name)
		if err != nil {
			return nil, fmt.Errorf("监听网卡 %s 无可用 IPv4: %w", name, err)
		}
		return ip, nil
	}
	if s := strings.TrimSpace(r.cfg.ListenIP); s != "" {
		ip := net.ParseIP(s).To4()
		if ip == nil {
			return nil, fmt.Errorf("监听地址 %s 不是有效的 IPv4", s)
		}
		return ip, nil
	}
	return net.IPv4zero, nil
}

// bindAddr 返回当前监听绑定的 IPv4（未解析时 0.0.0.0 全网卡）。
func (r *runtime) bindAddr() net.IP {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bindIP != nil {
		return r.bindIP
	}
	return net.IPv4zero
}

// portFree 检查端口在 TCP 与 UDP 上是否均未被占用。
func portFree(port int) bool {
	if l, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port)); err != nil {
		return false
	} else {
		l.Close()
	}
	if c, err := net.ListenPacket("udp", "0.0.0.0:"+strconv.Itoa(port)); err != nil {
		return false
	} else {
		c.Close()
	}
	return true
}

// allocPort 从高位区间（20000-65000）随机分配一个空闲端口（最多尝试 80 次）。
func allocPort() (int, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 80; i++ {
		p := 20000 + r.Intn(45000)
		if portFree(p) {
			return p, nil
		}
	}
	return 0, errors.New("未找到空闲的高位端口")
}
