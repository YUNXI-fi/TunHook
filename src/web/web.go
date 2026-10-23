package web

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg" // 注册 JPEG 解码器（image.Decode 使用）
	"image/png"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"tunhook/cloudflared"
	"tunhook/config"
	"tunhook/errpage"
	"tunhook/forward"
	"tunhook/frpc"
	"tunhook/geoloc"
	"tunhook/lolia"
	"tunhook/mefrp"
	"tunhook/store"
	"tunhook/stunhole"
	"tunhook/stunprobe"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

//go:embed static
var staticFS embed.FS

type LogEntry struct {
	Level   string `json:"level"`
	Time    string `json:"time"`
	Module  string `json:"module"`
	Message string `json:"message"`
}

type LogBuffer struct {
	mu      sync.RWMutex
	entries []LogEntry
	cap     int
}

func NewLogBuffer(cap int) *LogBuffer {
	return &LogBuffer{entries: make([]LogEntry, 0, cap), cap: cap}
}

func (b *LogBuffer) Append(entry LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) >= b.cap {
		b.entries = b.entries[1:]
	}
	b.entries = append(b.entries, entry)
}

func (b *LogBuffer) SetCap(newCap int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cap = newCap
	if len(b.entries) > b.cap {
		b.entries = b.entries[len(b.entries)-b.cap:]
	}
}

// Cap 返回缓冲容量。
func (b *LogBuffer) Cap() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.cap
}

// isAccessLog 判断日志消息是否为访问日志（连接/断开/UDP会话等）。
func isAccessLog(msg string) bool {
	return strings.HasPrefix(msg, "连接建立") || strings.HasPrefix(msg, "连接断开") ||
		strings.HasPrefix(msg, "UDP会话建立") || strings.HasPrefix(msg, "UDP会话超时") ||
		strings.HasPrefix(msg, "connection established")
}

// logModuleOf 从 zap caller 路径提取日志来源模块（如 .../tunhook/web/web.go → web；无路径时为全局/入口）。
func logModuleOf(caller zapcore.EntryCaller) string {
	file := caller.File
	if file == "" {
		return ""
	}
	if i := strings.LastIndex(file, "/tunhook/"); i >= 0 {
		file = file[i+len("/tunhook/"):]
	}
	// 取调用文件所在目录名（兼容相对/绝对路径）
	if i := strings.LastIndex(file, "/"); i >= 0 {
		return file[:i][strings.LastIndex(file[:i], "/")+1:]
	}
	return ""
}

// Query 按条件查询日志，category 取值 ""(全部)、"access"(仅访问日志)、"channel"(仅通道运行日志)。
// module 取值 ""(全部) 或模块名（web/forward/frpc/...）；date 取值 ""(全部) 或 "2006-01-02"。
// excludeModule 非空时排除该模块（如仪表盘「最近日志」排除 web 访问日志，避免高频请求淹没业务日志）。
func (b *LogBuffer) Query(page, pageSize int, level, search, category, module, date, excludeModule string) ([]LogEntry, int) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var filtered []LogEntry
	for _, e := range b.entries {
		if level != "" && !strings.EqualFold(e.Level, level) {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(e.Message), strings.ToLower(search)) {
			continue
		}
		if module != "" && e.Module != module {
			continue
		}
		if excludeModule != "" && e.Module == excludeModule {
			continue
		}
		if date != "" && !strings.HasPrefix(e.Time, date) {
			continue
		}
		if category == "access" && !isAccessLog(e.Message) {
			continue
		}
		if category == "channel" && isAccessLog(e.Message) {
			continue
		}
		if category == "system" && (isAccessLog(e.Message) || strings.HasPrefix(e.Message, "[")) {
			continue
		}
		filtered = append(filtered, e)
	}

	// 倒序分页：第 1 页为最新日志
	return paginateLogEntriesDesc(filtered, page, pageSize)
}

// paginateLogEntriesDesc 按时间倒序分页：filtered 为时间升序的过滤结果，
// 第 1 页取最后 pageSize 条（最新日志），页内反转为新→旧返回。
func paginateLogEntriesDesc(filtered []LogEntry, page, pageSize int) ([]LogEntry, int) {
	total := len(filtered)
	end := total - (page-1)*pageSize
	if end <= 0 {
		return nil, total
	}
	start := end - pageSize
	if start < 0 {
		start = 0
	}
	out := filtered[start:end]
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, total
}

type logCore struct {
	buf         *LogBuffer
	forwardLogs *ruleLogRegistry
	fields      []zapcore.Field
}

func (c *logCore) Enabled(level zapcore.Level) bool { return true }
func (c *logCore) Sync() error                      { return nil }

func (c *logCore) With(fields []zapcore.Field) zapcore.Core {
	return &logCore{
		buf:         c.buf,
		forwardLogs: c.forwardLogs,
		fields:      append(c.fields, fields...),
	}
}

func (c *logCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		ce = ce.AddCore(entry, c)
	}
	return ce
}

// ruleLogBuffers 单个通道的两类独立日志缓冲：
// channel 记录通道运行日志，access 记录访问日志，各自有独立的条数上限。
type ruleLogBuffers struct {
	channel *LogBuffer
	access  *LogBuffer
}

// ruleLogConfig 单个通道的日志配置（消息同步/日志设置选项卡落库后生效）：
// level 为空表示不限制（跟随全局）；chCap/acCap 为 0 表示使用全局默认条数。
type ruleLogConfig struct {
	level string
	chCap int
	acCap int
}

// ruleLogRegistry 维护每个通道独立的日志缓冲（id -> ruleLogBuffers）及每通道日志配置。
type ruleLogRegistry struct {
	mu        sync.RWMutex
	m         map[string]*ruleLogBuffers
	cfg       map[string]*ruleLogConfig
	chCapFunc func() int // 返回每通道运行日志条数上限
	acCapFunc func() int // 返回每通道访问日志条数上限
}

// logLevelThresholds 通道日志级别过滤阈值（zapcore 级别：Debug < Info < Warn < Error）。
var logLevelThresholds = map[string]zapcore.Level{
	"DEBUG": zapcore.DebugLevel,
	"INFO":  zapcore.InfoLevel,
	"WARN":  zapcore.WarnLevel,
	"ERROR": zapcore.ErrorLevel,
}

// validLogLevel 校验通道日志输出级别是否合法（空 = 跟随全局，也视为合法）。
func validLogLevel(l string) bool {
	if l == "" {
		return true
	}
	_, ok := logLevelThresholds[l]
	return ok
}

// clampLogEntries 规范通道日志存储条数：负数归零（0 = 跟随全局默认条数）。
func clampLogEntries(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// customIDRe 自定义ID：仅字母/数字（不区分大小写），1-32 位。
var customIDRe = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)

// domainRe 自定义域名：标准域名格式（可含通配符前缀 *.，仅允许字母/数字/连字符/点）。
var domainRe = regexp.MustCompile(`^(?:\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

// validCustomID 校验自定义ID（仅字母/数字，不区分大小写）。
func validCustomID(s string) bool {
	return customIDRe.MatchString(strings.TrimSpace(s))
}

// validDomain 校验自定义域名格式（支持 *.example.com 通配前缀）。
func validDomain(s string) bool {
	d := strings.TrimSpace(s)
	if len(d) > 253 {
		return false
	}
	return domainRe.MatchString(d)
}

// httpMethods 常用 HTTP 请求方法白名单（Webhook 模板）。
var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true,
}

// validHTTPMethod 校验 Webhook 模板请求方法是否在常用方法白名单内。
func validHTTPMethod(m string) bool {
	return httpMethods[m]
}

// setRuleConfig 更新单条规则的日志配置（级别 + 运行/访问日志条数），并即时调整已存在缓冲的容量。
func (r *ruleLogRegistry) setRuleConfig(id, level string, chCap, acCap int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.cfg[id] = &ruleLogConfig{level: level, chCap: chCap, acCap: acCap}
	b, ok := r.m[id]
	r.mu.Unlock()
	if ok {
		if chCap > 0 {
			b.channel.SetCap(chCap)
		}
		if acCap > 0 {
			b.access.SetCap(acCap)
		}
	}
}

// ruleLevel 返回通道配置的日志级别（空 = 不限制）。
func (r *ruleLogRegistry) ruleLevel(id string) string {
	if r == nil {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if c, ok := r.cfg[id]; ok {
		return c.level
	}
	return ""
}

// passLevel 判断通道日志是否达到该通道配置的输出级别（未配置级别时全部记录）。
func (r *ruleLogRegistry) passLevel(id string, lvl zapcore.Level) bool {
	lvlStr := r.ruleLevel(id)
	if lvlStr == "" {
		return true
	}
	threshold, ok := logLevelThresholds[lvlStr]
	if !ok {
		return true
	}
	return lvl >= threshold
}

// buffers 获取通道的两类缓冲（不存在时创建，创建时应用该通道的日志条数配置）。
func (r *ruleLogRegistry) buffers(id string) *ruleLogBuffers {
	r.mu.RLock()
	b, ok := r.m[id]
	r.mu.RUnlock()
	if ok {
		return b
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if b, ok = r.m[id]; ok {
		return b
	}
	var chCap, acCap int
	if c, ok := r.cfg[id]; ok {
		chCap, acCap = c.chCap, c.acCap
	}
	if chCap <= 0 {
		chCap = r.chCapFunc()
	}
	if acCap <= 0 {
		acCap = r.acCapFunc()
	}
	b = &ruleLogBuffers{
		channel: NewLogBuffer(chCap),
		access:  NewLogBuffer(acCap),
	}
	r.m[id] = b
	return b
}

// remove 删除通道缓冲及其日志配置（隧道删除时调用，释放内存）。
func (r *ruleLogRegistry) remove(id string) {
	r.mu.Lock()
	delete(r.m, id)
	delete(r.cfg, id)
	r.mu.Unlock()
}

// setCapsAll 更新所有通道缓冲的容量上限（运行日志/访问日志分开设置）。
// 已配置独立日志条数的通道不受全局变更影响（跟随全局的通道 0 值才会被覆盖）。
func (r *ruleLogRegistry) setCapsAll(chCap, acCap int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for id, b := range r.m {
		c, hasCfg := r.cfg[id]
		if !hasCfg {
			b.channel.SetCap(chCap)
			b.access.SetCap(acCap)
			continue
		}
		if c.chCap <= 0 {
			b.channel.SetCap(chCap)
		}
		if c.acCap <= 0 {
			b.access.SetCap(acCap)
		}
	}
}

// query 按条件查询指定通道的日志：category ""(全部)、"access"(仅访问日志)、"channel"(仅通道运行日志)。
// module/date 仅对日志弹窗前端可选，通道日志全部属于 forward 模块，此处忽略 module 过滤，date 生效。
func (r *ruleLogRegistry) query(id string, page, pageSize int, level, search, category, module, date string) ([]LogEntry, int) {
	r.mu.RLock()
	ls, ok := r.m[id]
	r.mu.RUnlock()
	if !ok {
		return nil, 0
	}

	var bufs []*LogBuffer
	switch category {
	case "access":
		bufs = []*LogBuffer{ls.access}
	case "channel":
		bufs = []*LogBuffer{ls.channel}
	default:
		bufs = []*LogBuffer{ls.channel, ls.access}
	}

	var all []LogEntry
	for _, b := range bufs {
		b.mu.RLock()
		all = append(all, b.entries...)
		b.mu.RUnlock()
	}
	// 合并多缓冲时按时间升序排列，保持原有的先后顺序
	if len(bufs) > 1 {
		sort.SliceStable(all, func(i, j int) bool {
			return all[i].Time < all[j].Time
		})
	}

	var filtered []LogEntry
	for _, e := range all {
		if level != "" && !strings.EqualFold(e.Level, level) {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(e.Message), strings.ToLower(search)) {
			continue
		}
		if date != "" && !strings.HasPrefix(e.Time, date) {
			continue
		}
		filtered = append(filtered, e)
	}

	// 倒序分页：第 1 页为最新日志
	return paginateLogEntriesDesc(filtered, page, pageSize)
}

func (c *logCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	base := entry.Message
	allFields := append(c.fields, fields...)
	var forwardKey string
	var extra string
	if len(allFields) > 0 {
		enc := zapcore.NewMapObjectEncoder()
		for _, f := range allFields {
			f.AddTo(enc)
		}
		for k, v := range enc.Fields {
			if k == "forward" {
				if s, ok := v.(string); ok && s != "" {
					forwardKey = s
				}
				continue
			}
			extra += " " + k + "=" + fmt.Sprint(v)
		}
	}

	// 转发日志：独立记录到对应规则的缓冲（规则级日志级别/条数过滤）
	if forwardKey != "" && c.forwardLogs != nil && c.forwardLogs.passLevel(forwardKey, entry.Level) {
		lb := c.forwardLogs.buffers(forwardKey)
		target := lb.channel
		if isAccessLog(base) {
			target = lb.access
		}
		target.Append(LogEntry{
			Level:   entry.Level.String(),
			Time:    entry.Time.Format("2006-01-02 15:04:05"),
			Module:  logModuleOf(entry.Caller),
			Message: base,
		})
	}

	// 全局日志（保留原样，含 [id] 前缀与字段，便于区分与排查）
	msg := base + extra
	if forwardKey != "" {
		msg = "[" + forwardKey + "] " + msg
	}
	c.buf.Append(LogEntry{
		Level:   entry.Level.String(),
		Time:    entry.Time.Format("2006-01-02 15:04:05"),
		Module:  logModuleOf(entry.Caller),
		Message: msg,
	})
	return nil
}

type Server struct {
	addr          string // 本地开发 TCP 监听地址（仅 --addr/--port 显式指定时启用）
	socketPath    string
	gatewayPrefix string
	logger        *zap.Logger
	logBuf        *LogBuffer
	forwardLogs   *ruleLogRegistry
	fwdMgr        *forward.Manager
	certApplier   *forward.CertApplier
	geo           *geoloc.DB
	geoCatalog    *geoloc.Catalog
	cfg           *config.Config
	cfgMu         sync.RWMutex // 保护 s.cfg 的并发读写（logCleanup goroutine / settings handler / 定时刷新）

	store *store.Store

	// ACME 申请期间的临时路由（taskID → 恢复信息），申请结束后恢复原配置
	acmeRoutesMu sync.Mutex
	acmeRoutes   map[string]acmeRouteRestore

	// 自动续签：记录每个域名最近一次尝试时间，避免配置错误时每小时反复触发
	certRenewMu   sync.Mutex
	certRenewLast map[string]time.Time

	// frpc 客户端管理（内置安装包安装、配置、启停、升级）
	frpcMgr *frpc.Manager

	// MEFrp 云端隧道（独立 frpc 进程，不进「内网穿透」服务器列表）+ 隧道列表缓存
	mefrpRun    *mefrp.Runner
	mefrpMu     sync.Mutex
	mefrpList   *mefrp.ProxyList
	mefrpListAt time.Time

	// LoliaFrp 云端隧道（同为独立 frpc 进程，数据目录 <dataDir>/lolia）+ 隧道/节点列表缓存
	loliaRun        *lolia.Runner
	loliaMu         sync.Mutex
	loliaList       []lolia.Tunnel
	loliaListAt     time.Time
	loliaNodes      []lolia.Node
	loliaNodesAt    time.Time
	loliaAuthMu     sync.Mutex
	loliaAuthStates map[string]loliaAuthState // 进行中的 OAuth 授权（state → 回跳信息，一次性）
	loliaTokenMu    sync.Mutex                // OAuth access_token 自动续期串行化（refresh_token 单次有效，禁止并发刷新）

	// Cloudflare Tunnel：内核管理器（全局共用一份二进制）+ 每条隧道实例一个连接器进程
	cfMgr    *cloudflared.Manager
	cfRunsMu sync.Mutex
	cfRuns   map[string]*cloudflared.Runner

	// STUN 打洞暴露（本地 UDP 端口 → 公网映射，尽力而为）
	stunholeMgr *stunhole.Manager
	// STUN 设置（服务器列表 + 保活间隔），持久化于 KV，内存副本供探测/列表接口读取
	stunServers      []stunSrvCfg
	stunKeepaliveSec int

	// Webhook 接收器（接收客户端上报的公网地址，提供 /wh/{channel_id} 访问入口）
	whRecv *whReceiver

	// 桌面图标空应用管理（root 运行时调用 fnpack/appcenter-cli 打包安装/卸载）
	deskApps *deskAppManager

	descriptions sync.Map

	// 累计流量基线（key -> *[2]int64{tx, rx}）：启动时从数据库加载，
	// 展示值 = 基线 + 当前转发器计数器；每 5 分钟与进程关闭时把累计值写回数据库，防止重启丢失。
	fwdTrafficBase sync.Map

	// frpc 代理累计流量状态（name -> *frpcTrafficAgg）：活跃连接 TCP_INFO 正增量累加 + 数据库持久化，
	// 无活跃连接时仍保留历史累计，供「连接统计」弹窗的累计上下行展示（不再无连接即归零）。
	frpcTraffic sync.Map

	// 转发规则实时速率采样状态（key -> *fwdRateSample）：由 /api/forward/list 轮询累计值差值计算，
	// 用于列表「实时速率」列展示。
	fwdRate sync.Map

	mu         sync.RWMutex
	startTime  time.Time
	dataDir    string
	shareLog   string
	shareRules string

	ln               net.Listener // 本地开发 TCP 监听器
	socketLn         net.Listener // 统一网关 Unix Socket 监听器
	whLn             net.Listener // Webhook 端口监听器（接收上报 + 通道访问入口，直接访问显示通道查找页）
	whLnMu           sync.Mutex   // 保护 whLn 的创建/关闭（设置保存变更端口时重建）
	logCleanupTicker *time.Ticker
	stopCh           chan struct{}
	stopOnce         sync.Once
	// stopCtx 随 stopCh 一并取消，供后台网络任务（如 IP 归属地数据源检测/下载）
	// 在关服时立即中断正在进行的 HTTP 请求，避免阻塞 Stop() 的 bgWG.Wait()
	stopCtx    context.Context
	stopCancel context.CancelFunc
	bgWG       sync.WaitGroup

	// 禁止使用 IP/IP 段缓存（来自 ip_filter_entries 表，手动录入）
	blockRanges   []*net.IPNet
	blockRangesMu sync.RWMutex

	// 白名单 IP/IP 段缓存（命中白名单优先放行）
	whitelistRanges   []*net.IPNet
	whitelistRangesMu sync.RWMutex

	// 自动记录被拦截 IP 开关（缓存自 ip_filter.auto_record）
	ipFilterAutoRecord   bool
	ipFilterAutoRecordMu sync.RWMutex

	// WAF 防火墙：设置与自定义规则（惰性加载）+ 命中日志（内存环形缓冲）
	wafMu       sync.RWMutex
	wafCfg      wafSettings
	wafRules    []wafCustomRule
	wafCompiled []wafCompiledRule
	wafLoaded   bool
	wafLogMu    sync.Mutex
	wafLogs     []wafHit

	// Web 服务（本地静态站点托管）：站点配置 + 运行实例 + 最近一次启动错误
	wsMu    sync.Mutex
	wsSites []WebSite
	wsRuns  map[string]*webSiteRun
	wsErrs  map[string]string
	// 路径模式站点共用同一个 HTTP 监听（默认复用 HTTP 默认端口）
	wsPathSrv  *http.Server
	wsPathLn   net.Listener
	wsPathPort int

	// 网络信息缓存（受 s.mu 保护，由定时任务刷新）
	localIP   string    // 本机局域网 IPv4
	localIPv6 string    // 本机局域网 IPv6（全局单播/ULA）
	gatewayIP string    // 默认路由网关（路由器）IPv4
	pubIPv4   string    // 公网 IPv4（外部探测缓存，失败回退客户端上报）
	pubIPv6   string    // 公网 IPv6（外部探测缓存）
	pubIPTime time.Time // 公网地址探测缓存时间

	// 系统实时网络速率采样（/proc/net/dev 差值）
	netMu   sync.Mutex
	netLast time.Time
	netRx   uint64
	netTx   uint64

	// 系统流量统计：每秒采样 /proc/net/dev 差值，内存环形缓冲保存最近 10 分钟，
	// 批量写入 traffic_samples 表供 1 小时 / 24 小时视图聚合查询。
	trafficRing   []store.TrafficSample
	trafficRingMu sync.Mutex

	// 最近 web 访问记录（供「连接统计」弹窗展示访客真实 IP/端口与流量），环形保留最近 50 条
	accessRecents   []webAccessRec
	accessRecentsMu sync.Mutex

	// frpc 转发连接 → 访客真实 IP/端口 映射（key 为 HTTP 请求 RemoteAddr，即 frpc 连接本地端点）。
	// 供「连接统计」弹窗把活跃 TCP 连接与访客信息关联（连接断开即不再展示）。
	connVisitors   map[string]connVisitor
	connVisitorsMu sync.Mutex

	// 代理名 → 访客真实 IP/端口 映射（key 为 frpc 代理名，访客 IP 来自 X-Forwarded-For / X-Real-IP）。
	// 网关/反代场景下 frpc 只连接到网关、与访客没有同一 socket 端点，无法按 RemoteAddr 精确匹配，
	// 因此按「访客 IP 归属到代理名」做关联，供「连接统计」弹窗回退兜底展示访客 IP/端口。
	connVisitorsByProxy   map[string]connVisitor
	connVisitorsByProxyMu sync.Mutex

	// frpc http/https 代理经 TunHook 反代时的本地反代层（记录访客真实 IP/端口）
	httpProxyMu      sync.Mutex
	httpProxyByProxy map[string]*frpcHTTPProxy

	// frpc tcp 代理经 TunHook 反代时的本地 PROXY 解析层（frps/frpc 开启 proxy_protocol v2 时记录访客真实 IP/端口）
	tcpProxyMu      sync.Mutex
	tcpProxyByProxy map[string]*frpcTCPProxy

	// 自定义域名 → frpc 代理名 缓存（访问日志热路径避免每次读配置文件）。
	domainIndex   map[string]string
	domainIndexMu sync.RWMutex
	domainIndexAt time.Time
}

// connVisitor 一条 frpc 转发连接关联的访客信息。
type connVisitor struct {
	IP   string    // 访客真实 IP（X-Real-IP / X-Forwarded-For 解析）
	Port string    // 访客源端口（X-Real-Port），不可得时 "-"
	Last time.Time // 最近一次请求时间（用于清理过期项）
}

// ipToNet 把单个 IP 或 CIDR 文本转为 *net.IPNet（非法输入返回 nil）。
func ipToNet(c string) *net.IPNet {
	c = strings.TrimSpace(c)
	if c == "" {
		return nil
	}
	if _, cidr, err := net.ParseCIDR(c); err == nil {
		return cidr
	}
	if ip := net.ParseIP(c); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return &net.IPNet{IP: ip4.Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)}
		}
		if ip16 := ip.To16(); ip16 != nil {
			return &net.IPNet{IP: ip16.Mask(net.CIDRMask(128, 128)), Mask: net.CIDRMask(128, 128)}
		}
	}
	return nil
}

// isPrivateIP 判断 IP 是否属于本机/内网地址（回环、私网、链路本地、未指定）。
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// clientIP 从请求中解析真实客户端 IP，优先级：
//  1. X-Real-IP（Nginx 等反代直接面对访问者，最可靠）；
//  2. X-Forwarded-For 中第一个非内网地址（反代 → frp 多级链路时末端是内网/回环地址，真实 IP 在最前）；
//  3. 回退 TCP 对端地址（r.RemoteAddr）。
func clientIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		if ip := net.ParseIP(v); ip != nil {
			return ip.String()
		}
	}
	for _, part := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		part = strings.TrimSpace(part)
		if ip := net.ParseIP(part); ip != nil && !isPrivateIP(ip) {
			return ip.String()
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// webAccessRec 一条 web 访问记录（供连接统计弹窗展示访客真实 IP/端口与流量）。
type webAccessRec struct {
	Time   string `json:"time"`   // 访问时间 HH:MM:SS
	IP     string `json:"ip"`     // 访客真实 IP（X-Real-IP / X-Forwarded-For 解析）
	Port   string `json:"port"`   // 访客源端口（X-Real-Port，需反代配置透传），不可得时 "-"
	Method string `json:"method"` // 请求方法
	Path   string `json:"path"`   // 请求路径
	Status int    `json:"status"` // 响应状态码
	RX     int64  `json:"rx"`     // 请求体字节（Content-Length）
	TX     int64  `json:"tx"`     // 响应体字节
}

// statusWriter 包装 http.ResponseWriter 以捕获实际写入的响应状态码与响应字节数。
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
	tx     int64
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.tx += int64(n)
	return n, err
}

// Hijack 支持 WebSocket / 长连接升级：底层 ResponseWriter 实现 http.Hijacker 时透传。
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}

// Flush 支持流式响应（SSE / 分块传输）透传。
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// recordAccess 把一条访问记录写入最近访问环形缓冲（保留最近 50 条）。
func (s *Server) recordAccess(rec webAccessRec) {
	if rec.Port == "" {
		rec.Port = "-"
	}
	if rec.RX < 0 {
		rec.RX = 0
	}
	s.accessRecentsMu.Lock()
	defer s.accessRecentsMu.Unlock()
	s.accessRecents = append(s.accessRecents, rec)
	if len(s.accessRecents) > 50 {
		s.accessRecents = s.accessRecents[len(s.accessRecents)-50:]
	}
}

// webRecents 返回最近 web 访问记录（最新的在前）。
func (s *Server) webRecents() []webAccessRec {
	s.accessRecentsMu.Lock()
	defer s.accessRecentsMu.Unlock()
	out := make([]webAccessRec, len(s.accessRecents))
	copy(out, s.accessRecents)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// recordVisitor 把 HTTP 请求（RemoteAddr = frpc 转发连接的本地端点）与访客真实 IP/端口关联。
// 连接断开后不再有该 RemoteAddr 的活跃 socket，连接统计不再展示，映射项顺带清理。
func (s *Server) recordVisitor(remoteAddr, ip, port string) {
	if remoteAddr == "" {
		return
	}
	if port == "" {
		port = "-"
	}
	now := time.Now()
	s.connVisitorsMu.Lock()
	// 项数过多时清理 5 分钟内无请求的过期项，避免长期累积
	if len(s.connVisitors) > 200 {
		for k, v := range s.connVisitors {
			if now.Sub(v.Last) > 5*time.Minute {
				delete(s.connVisitors, k)
			}
		}
	}
	s.connVisitors[remoteAddr] = connVisitor{IP: ip, Port: port, Last: now}
	s.connVisitorsMu.Unlock()
}

// visitorFor 查询 frpc 转发连接（RemoteAddr）对应的访客信息；无记录时返回空值。
func (s *Server) visitorFor(remoteAddr string) connVisitor {
	s.connVisitorsMu.Lock()
	defer s.connVisitorsMu.Unlock()
	return s.connVisitors[remoteAddr]
}

// recordVisitorByProxy 按代理名记录访客真实 IP/端口（key 为 frpc 代理名）。
// 用于网关/反代场景下 frpc 与访客没有同一 socket 端点、无法按 RemoteAddr 精确匹配时的兜底关联。
func (s *Server) recordVisitorByProxy(proxy, ip, port string) {
	if proxy == "" {
		return
	}
	if ip == "" {
		ip = "-"
	}
	if port == "" {
		port = "-"
	}
	s.connVisitorsByProxyMu.Lock()
	s.connVisitorsByProxy[proxy] = connVisitor{IP: ip, Port: port, Last: time.Now()}
	s.connVisitorsByProxyMu.Unlock()
}

// visitorForProxy 查询某 frpc 代理最近关联的访客信息；无记录时返回空值。
func (s *Server) visitorForProxy(proxy string) connVisitor {
	s.connVisitorsByProxyMu.Lock()
	defer s.connVisitorsByProxyMu.Unlock()
	return s.connVisitorsByProxy[proxy]
}

// connVisitorFor 为一条 frpc 转发连接解析访客真实 IP/端口：
//  1. 优先按连接本地端点（HTTP 请求 RemoteAddr）精确匹配（直连场景，逐连接准确）；
//  2. 匹配不到时回退到该连接所属代理名下最近记录的访客 IP（网关/反代场景兜底）；
//  3. 都命中不到时返回 "-" / "-"（普通 TCP/UDP 代理无法得知访客 IP）。
func (s *Server) connVisitorFor(local string, names []string) (ip, port string) {
	if v := s.visitorFor(local); v.IP != "" && v.IP != "-" && time.Since(v.Last) <= 60*time.Second {
		return v.IP, v.Port
	}
	for _, name := range names {
		if v := s.visitorForProxy(name); v.IP != "" && v.IP != "-" && time.Since(v.Last) <= 60*time.Second {
			return v.IP, v.Port
		}
	}
	return "-", "-"
}

// frpcProxyForRequest 从请求推断其所属的 frpc 代理名，供「访客 IP 按代理名关联」使用：
//  1. 优先按 /proxy/{name} 网关路径（转发规则名通常与自动创建的同名 frpc 代理对应）；
//  2. 其次按 Host（自定义域名）匹配 frpc 代理的 custom_domains。
func (s *Server) frpcProxyForRequest(r *http.Request) string {
	// 网关路径 /proxy/{name}
	if p := r.URL.Path; strings.HasPrefix(p, "/proxy/") {
		name := strings.Trim(strings.TrimPrefix(p, "/proxy/"), "/")
		if name != "" && !strings.Contains(name, "/") {
			return name
		}
	}
	// Host 自定义域名/子域名匹配（剥离端口后比对；小写）
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	// 每 10 秒刷新一次域名索引，避免热路径上每次请求读配置文件
	s.domainIndexMu.Lock()
	if time.Since(s.domainIndexAt) > 10*time.Second {
		cfg := s.frpcMgr.LoadConfig()
		idx := map[string]string{}
		// 服务器地址（仅域名形态，用于拼接子域名访问地址）
		serverDomains := map[string]string{}
		for _, srv := range cfg.Servers {
			d := strings.ToLower(strings.TrimSpace(srv.Addr))
			if h, _, err := net.SplitHostPort(d); err == nil {
				d = h
			}
			if isDomainLike(d) {
				serverDomains[srv.Name] = d
			}
		}
		for _, p := range cfg.Proxies {
			for _, d := range strings.Split(p.CustomDomains, ",") {
				d = strings.ToLower(strings.TrimSpace(d))
				if d != "" {
					idx[d] = p.Name
				}
			}
			// 子域名访问地址 = <subdomain>.<服务器域名>（仅当服务器地址为域名时可用）
			if sub := strings.ToLower(strings.TrimSpace(p.Subdomain)); sub != "" {
				base := serverDomains[p.Server]
				if base == "" {
					base = serverDomains[cfg.ActiveServer]
				}
				if base != "" {
					idx[sub+"."+base] = p.Name
				}
			}
		}
		s.domainIndex = idx
		s.domainIndexAt = time.Now()
	}
	name := s.domainIndex[host]
	s.domainIndexMu.Unlock()
	return name
}

// isDomainLike 判断是否为「域名」而非 IP/含端口文本（用于子域名父后缀拼接）。
func isDomainLike(s string) bool {
	if s == "" || strings.Contains(s, ":") || strings.ContainsAny(s, " \t") {
		return false
	}
	if net.ParseIP(s) != nil {
		return false
	}
	return strings.Contains(s, ".")
}

// accessLogMiddleware 记录 web 访问日志（真实客户端 IP / 方法 / 路径 / 状态码），
// 消息进入系统日志缓冲，可在「日志」页面查看；同时记录访客真实 IP/端口与流量，
// 供「连接统计」弹窗展示。静态资源与高频延迟探测跳过以免刷屏。
func (s *Server) accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") || r.URL.Path == "/api/ping" {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		visitorIP := clientIP(r)
		visitorPort := strings.TrimSpace(r.Header.Get("X-Real-Port"))
		s.logger.Info("HTTP 访问",
			zap.String("ip", visitorIP),
			zap.String("host", r.Host),
			zap.String("remote", r.RemoteAddr),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", sw.status),
			zap.String("ua", truncateStr(r.UserAgent(), 120)))
		s.recordAccess(webAccessRec{
			Time:   time.Now().Format("15:04:05"),
			IP:     visitorIP,
			Port:   visitorPort,
			Method: r.Method,
			Path:   r.URL.Path,
			Status: sw.status,
			RX:     r.ContentLength,
			TX:     sw.tx,
		})
		// 关联 frpc 转发连接（RemoteAddr = frpc 连接本地端点）与访客真实 IP/端口
		s.recordVisitor(r.RemoteAddr, visitorIP, visitorPort)
		// 网关/反代场景 frpc 与访客没有同一 socket 端点：额外按代理名归集访客 IP/端口，
		// 供「连接统计」弹窗在端点精确匹配不到时回退展示（避免显示 -）
		if proxy := s.frpcProxyForRequest(r); proxy != "" {
			s.recordVisitorByProxy(proxy, visitorIP, visitorPort)
			s.logger.Info("访客按代理关联",
				zap.String("proxy", proxy),
				zap.String("ip", visitorIP),
				zap.String("port", visitorPort),
				zap.String("host", r.Host),
				zap.String("path", r.URL.Path))
		}
	})
}

// ipFilterMiddleware 在 IP 过滤开启时，对每个 web 请求用真实客户端 IP 做黑白名单与公网校验，
// 命中拦截返回 403（本地/内网直连同样生效，可通过白名单放行）。
func (s *Server) ipFilterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.cfgMu.RLock()
		enabled := s.cfg.IPFilter.Enabled
		s.cfgMu.RUnlock()
		if !enabled {
			next.ServeHTTP(w, r)
			return
		}
		ip := net.ParseIP(clientIP(r))
		if ip == nil || !s.isAllowedIP(ip) {
			s.writeJSON(w, http.StatusForbidden, apiErr("IP 已被拦截（命中 IP 过滤规则）"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// truncateStr 截断长字符串（按 rune 数），超长补省略号。
func truncateStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// loadBlocklist 从 ip_filter_entries 表加载禁止使用的 IP/IP 段（仅手动录入），
// 并同步加载白名单与自动记录开关。
func (s *Server) loadBlocklist() {
	s.blockRangesMu.Lock()
	s.whitelistRangesMu.Lock()
	defer s.blockRangesMu.Unlock()
	defer s.whitelistRangesMu.Unlock()
	s.blockRanges = nil
	s.whitelistRanges = nil

	custom, err := s.store.ListCustomIPs()
	if err != nil {
		s.logger.Warn("读取禁止IP列表失败", zap.Error(err))
	} else {
		for _, c := range custom {
			if n := ipToNet(c); n != nil {
				s.blockRanges = append(s.blockRanges, n)
			}
		}
	}

	white, err := s.store.ListWhitelistIPs()
	if err != nil {
		s.logger.Warn("读取白名单IP列表失败", zap.Error(err))
	} else {
		for _, c := range white {
			if n := ipToNet(c); n != nil {
				s.whitelistRanges = append(s.whitelistRanges, n)
			}
		}
	}

	s.ipFilterAutoRecordMu.Lock()
	s.ipFilterAutoRecord = s.ipFilterAutoRecordSetting()
	s.ipFilterAutoRecordMu.Unlock()
	s.logger.Info("IP过滤规则已加载",
		zap.Int("block", len(s.blockRanges)),
		zap.Int("whitelist", len(s.whitelistRanges)),
		zap.Bool("auto_record", s.ipFilterAutoRecord))
}

// ipFilterAutoRecordSetting 读取自动记录被拦截 IP 的开关（默认关闭）。
func (s *Server) ipFilterAutoRecordSetting() bool {
	v, err := s.store.GetSetting("ip_filter.auto_record")
	if err != nil || v == "" {
		return false
	}
	return v == "1" || v == "true"
}

// isAllowedIP 执行 IP 过滤校验：
//  0. 本机回环地址（127.0.0.1 / ::1，即 localhost）固定放行；
//     白名单模式（whitelist）：仅白名单（条目或地区） + （开启「局域网放行」时的）内网地址放行，其余一律拦截；
//     黑名单模式（blacklist，默认）：白名单（条目或地区）优先放行 → 黑名单（条目或地区）命中拦截 → （开启「局域网放行」时的）内网地址放行 → 通过公网 IP 段校验。
//
// 开启自动记录时，被拦截的 IP 会写入 ip_filter_entries（source=blocked）。
func (s *Server) isAllowedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// 本机回环地址（127.0.0.1 / ::1，即 localhost）固定放行，避免误拦截本地访问
	if ip.IsLoopback() {
		return true
	}
	s.cfgMu.RLock()
	mode := s.cfg.IPFilter.Mode
	allowLAN := s.cfg.IPFilter.AllowLAN
	whitelistRegions := s.cfg.IPFilter.WhitelistRegions
	blacklistRegions := s.cfg.IPFilter.BlacklistRegions
	s.cfgMu.RUnlock()
	ipStr := ip.String()
	switch mode {
	case "whitelist":
		// 白名单模式：白名单条目或白名单地区，或开启「局域网放行」时的内网地址
		if s.isAllowedInWhitelistMode(ip) {
			return true
		}
		s.recordBlockedIP(ip)
		return false
	default: // blacklist 黑名单模式（默认）
		// 白名单（条目或地区）优先放行
		if s.isWhitelistedIP(ip) || s.ipInRegions(whitelistRegions, ipStr) {
			return true
		}
		// 黑名单（条目或地区）命中即拒绝
		if s.isBlockedIP(ip) || s.ipInRegions(blacklistRegions, ipStr) {
			s.recordBlockedIP(ip)
			return false
		}
		// 开启「局域网放行」时，内网地址直接放行，不参与公网段校验
		if allowLAN && isPrivateIP(ip) {
			return true
		}
		// 其余地址需通过公网 IP 段校验
		if !s.isPublicIP(ip) {
			s.recordBlockedIP(ip)
			return false
		}
		return true
	}
}

// isAllowedInWhitelistMode 白名单模式下的放行判定：回环地址、白名单条目或地区、开启「局域网放行」时的内网地址。
func (s *Server) isAllowedInWhitelistMode(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	s.cfgMu.RLock()
	allowLAN := s.cfg.IPFilter.AllowLAN
	regions := s.cfg.IPFilter.WhitelistRegions
	s.cfgMu.RUnlock()
	if s.isWhitelistedIP(ip) || s.ipInRegions(regions, ip.String()) {
		return true
	}
	return allowLAN && isPrivateIP(ip)
}

// ipInRegions 检查 IP 是否命中任一地区规则（按 IP 归属地匹配）。
func (s *Server) ipInRegions(regions []config.RegionRule, ipStr string) bool {
	if s.geo == nil || len(regions) == 0 {
		return false
	}
	for _, rg := range regions {
		if rg.Category == "" || rg.Name == "" {
			continue
		}
		if s.geo.RegionContains(rg.Category, rg.Name, ipStr) {
			return true
		}
	}
	return false
}

// isWhitelistedIP 检查 IP 是否命中白名单（命中即放行）。
func (s *Server) isWhitelistedIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	s.whitelistRangesMu.RLock()
	defer s.whitelistRangesMu.RUnlock()
	for _, cidr := range s.whitelistRanges {
		if cidr.Contains(ip4) {
			return true
		}
	}
	return false
}

// recordBlockedIP 在自动记录开启时，把一个被拦截的 IP 写入记录表。
func (s *Server) recordBlockedIP(ip net.IP) {
	if ip == nil {
		return
	}
	s.ipFilterAutoRecordMu.RLock()
	on := s.ipFilterAutoRecord
	s.ipFilterAutoRecordMu.RUnlock()
	if !on {
		return
	}
	if err := s.store.RecordBlockedIP(ip.String()); err != nil {
		s.logger.Warn("记录被拦截IP失败", zap.String("ip", ip.String()), zap.Error(err))
	}
}

// isBlockedIP 检查 IP 是否命中禁止列表（ip_filter_entries 表，手动录入的 IP/IP 段）。
func (s *Server) isBlockedIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	s.blockRangesMu.RLock()
	defer s.blockRangesMu.RUnlock()
	for _, cidr := range s.blockRanges {
		if cidr.Contains(ip4) {
			return true
		}
	}
	return false
}

// isPublicIP 确认 IP 存在于 geo_ip_ranges（属于允许使用的公网 IP/IP 段）。
// 优先使用归属地内存索引；未就绪时回退数据库直接查询，避免启动初期误判。
func (s *Server) isPublicIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		// IPv6 不参与 IPv4 公网段校验
		return true
	}
	if s.geo != nil && s.geo.Ready() {
		return s.geo.ContainsIP(ip4.String())
	}
	ok, err := s.store.IsIPInGeoRanges(ipToUint32(ip4))
	if err != nil {
		s.logger.Warn("查询公网IP段失败", zap.Error(err))
		return false
	}
	return ok
}

// ipToUint32 把 IPv4 地址转为 uint32；非法或 IPv6 返回 0。
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

// newLogRegistry 创建独立的日志缓冲注册表（通道/转发规则各一个实例），
// 容量上限动态读取当前全局配置（TunnelMaxEntries / TunnelAccessMaxEntries）。
func newLogRegistry(srv **Server) *ruleLogRegistry {
	return &ruleLogRegistry{
		m:   make(map[string]*ruleLogBuffers),
		cfg: make(map[string]*ruleLogConfig),
		chCapFunc: func() int {
			if *srv == nil {
				return 128
			}
			(*srv).cfgMu.RLock()
			defer (*srv).cfgMu.RUnlock()
			n := (*srv).cfg.Log.TunnelMaxEntries
			if n <= 0 {
				return 128
			}
			return n
		},
		acCapFunc: func() int {
			if *srv == nil {
				return 128
			}
			(*srv).cfgMu.RLock()
			defer (*srv).cfgMu.RUnlock()
			n := (*srv).cfg.Log.TunnelAccessMaxEntries
			if n <= 0 {
				return 128
			}
			return n
		},
	}
}

func NewServer(addr string, cfg *config.Config, logger *zap.Logger, st *store.Store, dataDir string, shareLog string, shareRules string, frpcConfigDir string, socketPath string, gatewayPrefix string) *Server {
	var srv *Server
	// 转发规则独立日志缓冲注册表（运行日志/访问日志分开，cap 动态读取当前配置）
	forwardLogs := newLogRegistry(&srv)
	// Create log buffer and hook it into the logger
	logBuf := NewLogBuffer(5000)
	logger = logger.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return zapcore.NewTee(core, &logCore{buf: logBuf, forwardLogs: forwardLogs})
	}))

	// 一次性迁移旧版文件存储的数据
	if err := st.MigrateFromFiles(dataDir, shareRules); err != nil {
		logger.Warn("migrate legacy file data failed", zap.Error(err))
	}

	// 自定义错误页：加载 <dataDir>/errorpages 下的模板文件（Web / 域名转发 / frpc 反代 共用），
	// 缺失的文件写入内置默认模板；目录不可用时错误页回退内置默认内容并告警。
	if err := errpage.Init(filepath.Join(dataDir, "errorpages")); err != nil {
		logger.Warn("init error page templates failed", zap.Error(err))
	}

	fwdMgr := forward.NewManager(logger, st)
	fwdMgr.SetGatewayPrefix(gatewayPrefix)

	certApplier := forward.NewCertApplier(st, logger)

	// frpc 运行数据在 @appdata/TunHook/frp（二进制/pid/版本/离线包）；
	// 配置（frpc.json/frpc.toml）在 @appconf/TunHook，日志（frpc.log）在 @appshare/tunhook/log
	frpcMgr := frpc.NewManager(filepath.Join(dataDir, "frp"), logger)
	frpcMgr.SetPaths(frpcConfigDir, shareLog)

	// MEFrp 独立 frpc 进程（配置/日志/PID 在 @appdata/TunHook/mefrp，不出现在内网穿透列表）；
	// 传入 frpc 内核路径用于 pid 归属校验（残留 pid 文件 + PID 被复用时不误判/不误杀）
	mefrpRun := mefrp.NewRunner(filepath.Join(dataDir, "mefrp"), frpcMgr.BinPath(), logger)

	// LoliaFrp 独立 frpc 进程（配置/日志/PID 在 @appdata/TunHook/lolia，不出现在内网穿透列表）；
	// 复用 frpc.Manager 安装的内核，路径同样用于 pid 归属校验
	loliaRun := lolia.NewRunner(filepath.Join(dataDir, "lolia"), frpcMgr.BinPath(), logger)

	// Cloudflare Tunnel：内核（约 40MB，按需下载）+ 每条隧道实例一个连接器进程，
	// 内核在 @appdata/TunHook/cloudflared，各实例的运行数据在 cloudflared/instances/<实例ID>。
	cfDir := filepath.Join(dataDir, "cloudflared")
	cfMgr := cloudflared.NewManager(cfDir, logger)

	// STUN 打洞暴露管理器（本地 UDP 端口 → 公网映射，尽力而为）
	stunholeMgr := stunhole.NewManager(st, logger)

	stopCtx, stopCancel := context.WithCancel(context.Background())

	srv = &Server{
		addr:                addr,
		socketPath:          socketPath,
		stopCh:              make(chan struct{}),
		stopCtx:             stopCtx,
		stopCancel:          stopCancel,
		gatewayPrefix:       gatewayPrefix,
		logger:              logger,
		logBuf:              logBuf,
		forwardLogs:         forwardLogs,
		fwdMgr:              fwdMgr,
		certApplier:         certApplier,
		cfg:                 cfg,
		store:               st,
		dataDir:             dataDir,
		frpcMgr:             frpcMgr,
		mefrpRun:            mefrpRun,
		loliaRun:            loliaRun,
		loliaAuthStates:     map[string]loliaAuthState{},
		cfMgr:               cfMgr,
		cfRuns:              map[string]*cloudflared.Runner{},
		stunholeMgr:         stunholeMgr,
		deskApps:            newDeskAppManager(dataDir, logger),
		shareLog:            shareLog,
		shareRules:          shareRules,
		startTime:           time.Now(),
		acmeRoutes:          map[string]acmeRouteRestore{},
		certRenewLast:       map[string]time.Time{},
		connVisitors:        map[string]connVisitor{},
		connVisitorsByProxy: map[string]connVisitor{},
		httpProxyByProxy:    map[string]*frpcHTTPProxy{},
		tcpProxyByProxy:     map[string]*frpcTCPProxy{},
		domainIndex:         map[string]string{},
		wsRuns:              map[string]*webSiteRun{},
		wsErrs:              map[string]string{},
	}

	// Webhook 接收器（从数据库恢复已注册通道）
	srv.whRecv = newWhReceiver(srv)

	// 旧版「单实例」Cloudflare 配置迁移为一条隧道实例（一次性、幂等）：不迁移会丢失用户已有绑定
	if srv.cfg.Cloudflare.MigrateLegacy() {
		logger.Info("Cloudflare 配置已迁移为多实例结构",
			zap.Int("instances", len(srv.cfg.Cloudflare.Instances)))
		srv.persistConfig("cloudflare.instances", append([]config.CloudflareInstance(nil), srv.cfg.Cloudflare.Instances...))
	}

	// STUN 打洞公网映射变化时联动注册 Webhook 通道（用户在 STUN 通道弹窗指定 webhook_channel 时生效）
	stunholeMgr.OnPublicChange = srv.onStunholePublicChange

	// 证书申请到达终态时恢复申请期间的临时路由
	srv.certApplier.SetOnFinish(srv.restoreACMERouting)

	// 加载持久化的描述（转发规则的 description）
	srv.loadDescriptions()

	// Load saved forward rules
	savedRules := fwdMgr.LoadSavedRules()
	for _, rule := range savedRules {
		if err := fwdMgr.StartRule(rule); err != nil {
			logger.Warn("load saved forward rule failed", zap.Error(err))
		} else {
			// 应用每规则日志配置（级别过滤 + 日志条数）
			srv.forwardLogs.setRuleConfig(ruleKey(rule), rule.LogLevel, rule.ChannelLogEntries, rule.AccessLogEntries)
			logger.Info("loaded saved forward rule", zap.String("rule", ruleKey(rule)))
		}
	}
	// 加载已保存转发规则的累计流量基线（每 5 分钟与关闭时持久化，重启后从基线续算）
	if recs, err := srv.store.ListForwardRules(); err == nil {
		for _, rec := range recs {
			srv.fwdTrafficBase.Store(rec.Key, &[2]int64{rec.TxBytes, rec.RxBytes})
		}
	}

	// Load IP filter ranges
	srv.loadBlocklist()

	// 初始化本地 IP / 网关缓存（启动后立即可用）
	srv.refreshLocalNetworkInfo()

	// IP 归属地/运营商数据（优先从数据库加载，无数据时后台下载并写入数据库，失败不影响主流程）
	srv.geo = geoloc.New(dataDir, srv.store)
	srv.geo.SetLogger(srv.logger)
	srv.geoCatalog = geoloc.NewCatalog(srv.store, nil)
	srv.geoCatalog.SetLogger(srv.logger)
	go func() {
		srv.geo.Load()
		if srv.geo.Ready() {
			srv.logger.Info("IP归属地数据加载完成")
		} else {
			srv.logger.Warn("IP归属地数据加载失败")
		}
		// 启动后同步一次数据源目录（失败不阻断，稍后由定时任务重试）
		if n, err := srv.geoCatalog.Refresh(srv.stopCtx); err != nil {
			srv.logger.Warn("IP段数据源目录同步失败", zap.Error(err))
		} else if n > 0 {
			srv.logger.Info("IP段数据源目录同步完成", zap.Int("sources", n))
		}
	}()
	srv.startFRPCHTTPProxies()
	srv.startFRPCTCPProxies()

	// 加载 STUN 设置（服务器列表 + 保活间隔），并恢复打洞通道
	srv.loadStunSettings()
	srv.stunholeMgr.Restore()

	// 本地静态站点：恢复站点配置，并启动设置了「开机自启」的站点
	srv.wsLoad()
	srv.wsRestore()

	return srv
}

func (s *Server) Start() error {
	// Start log cleanup timer: check every hour, clean at midnight
	s.logCleanupTicker = time.NewTicker(1 * time.Hour)
	s.bgWG.Add(1)
	go func() {
		defer s.bgWG.Done()
		for {
			select {
			case <-s.stopCh:
				return
			case <-s.logCleanupTicker.C:
				now := time.Now()
				// Only clean at midnight (00:00-01:00)
				if now.Hour() == 0 {
					s.cfgMu.RLock()
					expireDays := s.cfg.Log.ExpireDays
					s.cfgMu.RUnlock()
					s.logBuf.mu.Lock()
					cutoff := now.AddDate(0, 0, -expireDays)
					var kept []LogEntry
					for _, e := range s.logBuf.entries {
						t, err := time.Parse("2006-01-02 15:04:05", e.Time)
						if err != nil || t.After(cutoff) {
							kept = append(kept, e)
						}
					}
					removed := len(s.logBuf.entries) - len(kept)
					s.logBuf.entries = kept
					s.logBuf.mu.Unlock()
					if removed > 0 {
						s.logger.Info("Log cleanup (scheduled)", zap.Int("removed", removed), zap.Int("remaining", len(kept)))
					}
				}
			}
		}
	}()
	// Start periodic local network info refresh every 30 minutes
	s.bgWG.Add(1)
	go func() {
		defer s.bgWG.Done()
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		// Also run once immediately
		s.refreshLocalNetworkInfo()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.refreshLocalNetworkInfo()
			}
		}
	}()

	// Start DDNS engine (every 5 minutes)
	s.startDDNSEngine()

	// 证书自动续签引擎（每小时检查一次，到期前 30 天自动重新申请）
	s.startCertRenewEngine()

	// 累计流量统计每 5 分钟持久化一次（隧道 + 转发），进程关闭时由 Stop() 再写一次，防止数据丢失
	s.bgWG.Add(1)
	go func() {
		defer s.bgWG.Done()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.persistAllTraffic()
			}
		}
	}()

	// 系统流量统计：每秒采样 /proc/net/dev 差值，内存环形缓冲（最近 10 分钟）+ 批量落库；
	// 数据保留天数由「日志管理 → 流量统计数据保存时间」配置（默认 31 天）。
	s.bgWG.Add(1)
	go func() {
		defer s.bgWG.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		var pending []store.TrafficSample
		lastRx, lastTx := systemNetBytes()
		lastTs := time.Now()
		lastCleanup := time.Now()
		flush := func() {
			if len(pending) == 0 {
				return
			}
			if err := s.store.InsertTrafficSamplesBatch(pending); err != nil {
				s.logger.Warn("写入流量采样失败", zap.Error(err))
			}
			pending = pending[:0]
		}
		// 启动时清理一次超期数据
		s.cleanupTrafficSamples()
		for {
			select {
			case <-s.stopCh:
				flush()
				return
			case <-ticker.C:
				rx, tx := systemNetBytes()
				now := time.Now()
				dt := now.Sub(lastTs).Seconds()
				lastTs = now
				if dt <= 0 {
					continue
				}
				var sRx, sTx int64
				if rx >= lastRx {
					sRx = int64(float64(rx-lastRx) / dt)
				}
				if tx >= lastTx {
					sTx = int64(float64(tx-lastTx) / dt)
				}
				lastRx, lastTx = rx, tx

				sp := store.TrafficSample{TS: now.Unix(), RX: sRx, TX: sTx}
				s.trafficRingMu.Lock()
				s.trafficRing = append(s.trafficRing, sp)
				if len(s.trafficRing) > 620 {
					s.trafficRing = s.trafficRing[len(s.trafficRing)-620:]
				}
				s.trafficRingMu.Unlock()

				pending = append(pending, sp)
				if len(pending) >= 5 {
					flush()
				}
				if time.Since(lastCleanup) >= time.Hour {
					s.cleanupTrafficSamples()
					lastCleanup = time.Now()
				}
			}
		}
	}()

	// IP 归属地数据定时自动更新（间隔可在设置中配置，默认 24 小时）；
	// 同时每 6 小时定期刷新数据源目录并检测链接有效性。
	s.bgWG.Add(1)
	go func() {
		defer s.bgWG.Done()
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		nextCatalogCheck := time.Now()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				// 目录定期刷新 + 链接有效性检测（每 6 小时一次）
				if time.Now().After(nextCatalogCheck) {
					nextCatalogCheck = time.Now().Add(6 * time.Hour)
					if n, err := s.geoCatalog.Refresh(s.stopCtx); err != nil {
						s.logger.Warn("IP段数据源目录定期刷新失败", zap.Error(err))
					} else if n > 0 {
						s.logger.Info("IP段数据源目录定期刷新完成", zap.Int("sources", n))
					}
					if _, failed, err := s.geoCatalog.CheckLinks(s.stopCtx); err != nil {
						s.logger.Warn("IP段数据源链接检测失败", zap.Error(err))
					} else if failed > 0 {
						s.logger.Warn("存在无效的数据源链接", zap.Int("failed", failed))
					}
				}
				interval := s.geoAutoUpdateHours()
				if interval <= 0 {
					continue
				}
				last := s.geo.LastUpdate()
				if time.Since(last) < time.Duration(interval)*time.Hour {
					continue
				}
				// 更新前先同步目录，确保使用最新链接
				if _, err := s.geoCatalog.Refresh(s.stopCtx); err != nil {
					s.logger.Warn("IP段数据源目录刷新失败", zap.Error(err))
				}
				if err := s.geo.Update(s.stopCtx); err != nil {
					s.logger.Warn("IP归属地数据定时更新失败", zap.Error(err))
				} else {
					s.logger.Info("IP归属地数据定时更新完成")
				}
			}
		}
	}()

	// frpc 开机自启（默认开启）：启动 30 秒后延迟拉起 frpc 子进程，避开开机资源高峰；
	// 未安装时静默跳过，失败仅记录日志，不阻断主服务
	s.bgWG.Add(1)
	go func() {
		defer s.bgWG.Done()
		t := time.NewTimer(30 * time.Second)
		defer t.Stop()
		select {
		case <-s.stopCh:
			return
		case <-t.C:
		}
		if err := s.frpcMgr.AutoStart(); err != nil {
			s.logger.Warn("frpc 自动启动失败", zap.Error(err))
		}
		// frpc 拉起后再启动登录看门狗：连续登录失败达阈值自动重启实例，
		// 避免 loginFailExit=false 下进程活着但隧道不通、且永不恢复
		if err := s.frpcMgr.StartWatchdog(s.stopCtx); err != nil {
			s.logger.Warn("frpc 登录看门狗启动失败", zap.Error(err))
		}
	}()

	// MEFrp 隧道自启：上次启动过隧道（autostart_ids 非空）且已绑定密钥时，
	// 延迟 35 秒拉起（晚于 frpc 自启错峰）；走网络拉取配置，失败仅记录日志不阻断主服务
	s.bgWG.Add(1)
	go func() {
		defer s.bgWG.Done()
		t := time.NewTimer(35 * time.Second)
		defer t.Stop()
		select {
		case <-s.stopCh:
			return
		case <-t.C:
		}
		s.cfgMu.RLock()
		token := s.cfg.MEFRP.Token
		ids := append([]int64(nil), s.cfg.MEFRP.AutostartIDs...)
		s.cfgMu.RUnlock()
		if strings.TrimSpace(token) == "" || len(ids) == 0 || s.mefrpRun.Running() {
			return
		}
		if err := s.mefrpStartWithIDs(ids); err != nil {
			s.logger.Warn("MEFrp 隧道自动启动失败", zap.Int64s("proxyIds", ids), zap.Error(err))
			return
		}
		s.logger.Info("MEFrp 隧道已自动启动", zap.Int64s("proxyIds", ids))
	}()

	// LoliaFrp 自启：已保存密钥与上次启动的隧道 name 列表、且当前未在运行时，延迟 45 秒拉起
	// （与 frpc/MEFrp/cloudflared 自启错峰；开机时网络可能未就绪，frpc 会自行重连）
	s.bgWG.Add(1)
	go func() {
		defer s.bgWG.Done()
		t := time.NewTimer(45 * time.Second)
		defer t.Stop()
		select {
		case <-s.stopCh:
			return
		case <-t.C:
		}
		s.cfgMu.RLock()
		token := s.cfg.Lolia.AccessToken
		names := append([]string(nil), s.cfg.Lolia.AutostartNames...)
		s.cfgMu.RUnlock()
		if strings.TrimSpace(token) == "" || len(names) == 0 || s.loliaRun.Running() {
			return
		}
		if err := s.loliaStartWithNames(names); err != nil {
			s.logger.Warn("LoliaFrp 隧道自动启动失败", zap.Strings("names", names), zap.Error(err))
			return
		}
		s.logger.Info("LoliaFrp 隧道已自动启动", zap.Strings("names", names))
	}()

	// Cloudflare Tunnel 自启：上次处于「运行中」（auto_start 为真）、已装内核且已配置（Token 或临时入口目标地址）时，
	// 延迟 40 秒拉起（与 frpc/MEFrp 自启错峰）；此时网络可能尚未就绪，cloudflared 会自行退避重连
	s.bgWG.Add(1)
	go func() {
		defer s.bgWG.Done()
		t := time.NewTimer(40 * time.Second)
		defer t.Stop()
		select {
		case <-s.stopCh:
			return
		case <-t.C:
		}
		// 逐条拉起设置了自启的实例（未运行且配置完整的才启动）
		if !s.cfMgr.Installed() {
			s.logger.Warn("Cloudflare 隧道自启跳过：内核未安装")
			return
		}
		for _, inst := range s.cfInstances() {
			if !inst.AutoStart || !inst.Ready() || s.cfRunner(inst.ID).Running() {
				continue
			}
			if err := s.startCfInstance(inst); err != nil {
				s.logger.Warn("Cloudflare 隧道自启失败",
					zap.String("id", inst.ID), zap.String("name", inst.Name), zap.Error(err))
				continue
			}
			s.logger.Info("Cloudflare 隧道已自动启动",
				zap.String("id", inst.ID), zap.String("name", inst.DisplayName()))
		}
	}()

	mux := http.NewServeMux()
	// 根路径不限定方法：避免与全方法匹配的 /proxy/{name} 代理路由冲突
	// （handleIndex 本身只对 "/" 返回页面，其余路径返回 404）
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("GET /static/icon.png", s.handleIcon)
	// 应用图标（通道查找页网页图标/品牌图标）
	mux.HandleFunc("GET /static/icon.svg", func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFS.ReadFile("static/icon.svg")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Write(data)
	})
	// 默认桌面图标（创建图标时无自定义图标使用的兜底图）
	mux.HandleFunc("GET /static/fnos.svg", func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFS.ReadFile("static/fnos.svg")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Write(data)
	})
	// 本地搜索引擎图标（/static/bing.svg 等，白名单）
	mux.HandleFunc("GET /static/{name}", s.handleEngineStaticIcon)
	// Svelte 构建产物静态资源（hash 文件名，可长缓存；FileServer 自带 ETag/Last-Modified 条件请求）
	{
		staticSub, err := fs.Sub(staticFS, "static")
		if err != nil {
			return fmt.Errorf("embed static sub: %w", err)
		}
		fileHandler := http.FileServerFS(staticSub)
		mux.HandleFunc("GET /assets/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			fileHandler.ServeHTTP(w, r)
		})
	}
	// 统一网关转发：/proxy/{name} 反向代理到对应转发规则的远端目标
	// 同时注册 {name}/ 子路径，保证 /proxy/xxx/api 等深层路径也能命中
	mux.HandleFunc("/proxy/{name}", s.handleGatewayProxy)
	mux.HandleFunc("/proxy/{name}/", s.handleGatewayProxy)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/ping", s.handlePing)
	mux.HandleFunc("GET /api/network/public", s.handlePublicIP)
	mux.HandleFunc("GET /api/stun/servers", s.handleStunServers)
	mux.HandleFunc("GET /api/stun/probe", s.handleStunProbe)
	mux.HandleFunc("GET /api/stun/natchain", s.handleStunNatChain)
	mux.HandleFunc("GET /api/stun/settings", s.handleStunSettingsGet)
	mux.HandleFunc("POST /api/stun/settings", s.handleStunSettingsPost)
	mux.HandleFunc("POST /api/stun/check", s.handleStunCheck)
	mux.HandleFunc("GET /api/stunhole/list", s.handleStunHoleList)
	mux.HandleFunc("POST /api/stunhole/create", s.handleStunHoleCreate)
	mux.HandleFunc("POST /api/stunhole/{id}/start", s.handleStunHoleStart)
	mux.HandleFunc("POST /api/stunhole/{id}/stop", s.handleStunHoleStop)
	mux.HandleFunc("POST /api/stunhole/{id}/update", s.handleStunHoleUpdate)
	mux.HandleFunc("GET /api/stunhole/{id}/logs", s.handleStunHoleLogs)
	mux.HandleFunc("DELETE /api/stunhole/{id}", s.handleStunHoleDelete)
	mux.HandleFunc("GET /api/system/stats", s.handleSystemStats)
	mux.HandleFunc("GET /api/system/net", s.handleSystemNet)
	mux.HandleFunc("GET /api/system/conns", s.handleSystemConns)
	mux.HandleFunc("GET /api/system/conns/detail", s.handleSystemConnsDetail)
	mux.HandleFunc("GET /api/system/processes", s.handleSystemProcesses)
	mux.HandleFunc("GET /api/traffic/stats", s.handleTrafficStats)
	mux.HandleFunc("GET /api/traffic/history", s.handleTrafficHistory)
	mux.HandleFunc("GET /api/logs", s.handleLogs)
	mux.HandleFunc("GET /api/logs/archive", s.handleLogArchive)

	// Settings
	mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	mux.HandleFunc("POST /api/settings", s.handleSaveSettings)
	mux.HandleFunc("POST /api/settings/logs/cleanup", s.handleLogCleanup)

	// 错误页面（每状态码一份 HTML 模板文件，三处 HTTP 入口共用）
	mux.HandleFunc("GET /api/errorpages", s.handleErrorPagesGet)
	mux.HandleFunc("POST /api/errorpages", s.handleErrorPagesPost)
	mux.HandleFunc("GET /api/errorpages/preview", s.handleErrorPagesPreview)

	// 模块管理（关闭指定功能模块的入口，即时生效）
	mux.HandleFunc("GET /api/modules", s.handleModulesGet)
	mux.HandleFunc("POST /api/modules", s.handleModulesSave)

	// 使用免责声明（同意状态存服务端，所有设备只弹一次）
	mux.HandleFunc("GET /api/disclaimer", s.handleDisclaimerGet)
	mux.HandleFunc("POST /api/disclaimer/agree", s.handleDisclaimerAgree)

	// 仪表盘布局（卡片顺序与显隐，即时生效）
	mux.HandleFunc("GET /api/dashboard/layout", s.handleDashboardLayoutGet)
	mux.HandleFunc("POST /api/dashboard/layout", s.handleDashboardLayoutSave)

	// 备份 / 恢复
	mux.HandleFunc("POST /api/backup/export", s.handleBackupExport)
	mux.HandleFunc("POST /api/backup/preview", s.handleBackupPreview)
	mux.HandleFunc("POST /api/backup/import", s.handleBackupImport)

	// IP 过滤（即时保存，单条增删/开关不依赖“保存设置”按钮）
	mux.HandleFunc("POST /api/ipfilter/custom", s.handleAddCustomIP)
	mux.HandleFunc("DELETE /api/ipfilter/custom", s.handleDeleteCustomIP)
	mux.HandleFunc("POST /api/ipfilter/enabled", s.handleSetIPFilterEnabled)
	mux.HandleFunc("POST /api/ipfilter/mode", s.handleSetIPFilterMode)
	mux.HandleFunc("POST /api/ipfilter/allowlan", s.handleSetIPFilterAllowLAN)
	mux.HandleFunc("POST /api/ipfilter/region", s.handleAddRegionToIPFilter)
	mux.HandleFunc("DELETE /api/ipfilter/region", s.handleDeleteRegionFromIPFilter)
	mux.HandleFunc("GET /api/ipfilter/whitelist", s.handleListWhitelist)
	mux.HandleFunc("POST /api/ipfilter/whitelist", s.handleAddWhitelist)
	mux.HandleFunc("DELETE /api/ipfilter/whitelist", s.handleDeleteWhitelist)
	mux.HandleFunc("GET /api/ipfilter/blocked", s.handleListBlocked)
	mux.HandleFunc("DELETE /api/ipfilter/blocked", s.handleDeleteBlocked)
	mux.HandleFunc("POST /api/ipfilter/autorecord", s.handleSetAutoRecord)

	// WAF 防火墙（设置 / 自定义规则 / 命中日志）
	mux.HandleFunc("GET /api/waf/settings", s.handleWafSettingsGet)
	mux.HandleFunc("POST /api/waf/settings", s.handleWafSettingsSave)
	mux.HandleFunc("GET /api/waf/rules", s.handleWafRulesGet)
	mux.HandleFunc("POST /api/waf/rules", s.handleWafRulesSave)
	mux.HandleFunc("GET /api/waf/logs", s.handleWafLogsGet)
	mux.HandleFunc("DELETE /api/waf/logs", s.handleWafLogsClear)

	// Web 服务（本地静态站点托管：站点增删改查 / 启停 / 访问日志 / 目录浏览）
	mux.HandleFunc("GET /api/webserver/sites", s.handleWebSitesGet)
	mux.HandleFunc("POST /api/webserver/sites", s.handleWebSiteSave)
	mux.HandleFunc("DELETE /api/webserver/sites/{id}", s.handleWebSiteDelete)
	mux.HandleFunc("POST /api/webserver/sites/{id}/start", s.handleWebSiteStart)
	mux.HandleFunc("POST /api/webserver/sites/{id}/stop", s.handleWebSiteStop)
	mux.HandleFunc("GET /api/webserver/sites/{id}/logs", s.handleWebSiteLogs)
	mux.HandleFunc("DELETE /api/webserver/sites/{id}/logs", s.handleWebSiteLogsClear)
	mux.HandleFunc("GET /api/webserver/sites/{id}/share/stats", s.handleWebShareStats)
	mux.HandleFunc("POST /api/webserver/sites/{id}/temp-shares", s.handleWebTempShareCreate)
	mux.HandleFunc("DELETE /api/webserver/sites/{id}/temp-shares/{shareID}", s.handleWebTempShareDelete)
	mux.HandleFunc("GET /api/webserver/sites/{id}/bans", s.handleWebBansGet)
	mux.HandleFunc("DELETE /api/webserver/sites/{id}/bans", s.handleWebBanDelete)
	mux.HandleFunc("GET /api/webserver/browse", s.handleWebSiteBrowse)

	// IP 归属地数据库（查询 / 统计 / 手动更新 / 自动更新设置 / 数据源管理）
	mux.HandleFunc("GET /api/geoloc/stats", s.handleGeoStats)
	mux.HandleFunc("GET /api/geoloc/lookup", s.handleGeoLookup)
	mux.HandleFunc("GET /api/geoloc/regions", s.handleGeoRegions)
	mux.HandleFunc("POST /api/geoloc/update", s.handleGeoUpdate)
	mux.HandleFunc("POST /api/geoloc/autoupdate", s.handleGeoAutoUpdate)
	mux.HandleFunc("GET /api/geoloc/sources", s.handleGeoSources)
	mux.HandleFunc("POST /api/geoloc/import", s.handleGeoImport)
	mux.HandleFunc("POST /api/geoloc/sources/update", s.handleGeoSourcesUpdate)
	mux.HandleFunc("POST /api/geoloc/sources/toggle", s.handleGeoToggleSource)
	mux.HandleFunc("POST /api/geoloc/catalog/refresh", s.handleGeoCatalogRefresh)

	// frpc 客户端（内置安装包安装 / 配置 / 启停 / 升级 / 日志）
	mux.HandleFunc("GET /api/frpc/status", s.handleFrpcStatus)
	mux.HandleFunc("GET /api/frpc/config", s.handleFrpcConfigGet)
	mux.HandleFunc("POST /api/frpc/config", s.handleFrpcConfigSave)
	mux.HandleFunc("GET /api/frpc/configfile", s.handleFrpcConfigFileGet)
	mux.HandleFunc("POST /api/frpc/configfile", s.handleFrpcConfigFileSave)
	mux.HandleFunc("POST /api/frpc/server/add", s.handleFrpcServerAdd)
	mux.HandleFunc("POST /api/frpc/server/switch", s.handleFrpcServerSwitch)
	mux.HandleFunc("POST /api/frpc/server/autostart", s.handleFrpcServerAutoStart)
	mux.HandleFunc("POST /api/frpc/server/delete", s.handleFrpcServerDelete)
	mux.HandleFunc("POST /api/frpc/server/rename", s.handleFrpcServerRename)
	mux.HandleFunc("POST /api/frpc/proxy/create", s.handleFrpcProxyCreate)
	mux.HandleFunc("POST /api/frpc/proxy/update", s.handleFrpcProxyUpdate)
	mux.HandleFunc("POST /api/frpc/proxy/delete", s.handleFrpcProxyDelete)
	mux.HandleFunc("POST /api/frpc/proxy/toggle", s.handleFrpcProxyToggle)
	// 代理填写时就地提示域名 / 远程端口冲突与本地端口监听状态（纯查询）
	mux.HandleFunc("GET /api/frpc/proxy/check", s.handleFrpcProxyCheck)
	mux.HandleFunc("POST /api/frpc/install", s.handleFrpcInstall)
	mux.HandleFunc("POST /api/frpc/start", s.handleFrpcStart)
	mux.HandleFunc("POST /api/frpc/stop", s.handleFrpcStop)
	mux.HandleFunc("POST /api/frpc/restart", s.handleFrpcRestart)
	mux.HandleFunc("POST /api/frpc/upgrade/check", s.handleFrpcUpgradeCheck)
	mux.HandleFunc("POST /api/frpc/upgrade/download", s.handleFrpcUpgradeDownload)
	mux.HandleFunc("POST /api/frpc/upgrade/upload", s.handleFrpcUpgradeUpload)
	mux.HandleFunc("GET /api/frpc/log", s.handleFrpcLog)
	mux.HandleFunc("GET /api/frpc/conns", s.handleFrpcConns)

	// MEFrp 云端隧道（独立 frpc 进程，不进内网穿透服务器列表）
	mux.HandleFunc("GET /api/mefrp/config", s.handleMefrpConfigGet)
	mux.HandleFunc("POST /api/mefrp/config", s.handleMefrpConfigSave)
	mux.HandleFunc("GET /api/mefrp/tunnels", s.handleMefrpTunnels)
	mux.HandleFunc("POST /api/mefrp/start", s.handleMefrpStart)
	mux.HandleFunc("POST /api/mefrp/stop", s.handleMefrpStop)
	mux.HandleFunc("GET /api/mefrp/status", s.handleMefrpStatus)
	mux.HandleFunc("GET /api/mefrp/log", s.handleMefrpLog)
	mux.HandleFunc("GET /api/mefrp/user", s.handleMefrpUser)
	mux.HandleFunc("POST /api/mefrp/sign", s.handleMefrpSign)
	mux.HandleFunc("GET /api/mefrp/lottery", s.handleMefrpLotteryStatus)
	mux.HandleFunc("POST /api/mefrp/draw", s.handleMefrpDraw)
	mux.HandleFunc("GET /api/mefrp/createdata", s.handleMefrpCreateData)
	// 节点连接地址列表（仅含已创建过隧道的节点；创建数据接口不返回地址）
	mux.HandleFunc("GET /api/mefrp/node-addresses", s.handleMefrpNodeAddresses)
	mux.HandleFunc("POST /api/mefrp/proxy/create", s.handleMefrpProxyCreate)
	mux.HandleFunc("POST /api/mefrp/proxy/update", s.handleMefrpProxyUpdate)
	mux.HandleFunc("POST /api/mefrp/proxy/toggle", s.handleMefrpProxyToggle)
	mux.HandleFunc("POST /api/mefrp/proxy/delete", s.handleMefrpProxyDelete)
	mux.HandleFunc("POST /api/mefrp/proxy/kick", s.handleMefrpProxyKick)

	// LoliaFrp 云端隧道
	mux.HandleFunc("GET /api/lolia/config", s.handleLoliaConfigGet)
	mux.HandleFunc("POST /api/lolia/config", s.handleLoliaConfigSave)
	mux.HandleFunc("POST /api/lolia/oauth/start", s.handleLoliaOAuthStart)
	mux.HandleFunc("POST /api/lolia/oauth/disconnect", s.handleLoliaOAuthDisconnect)
	mux.HandleFunc("GET /api/lolia/user", s.handleLoliaUser)
	mux.HandleFunc("GET /api/lolia/tunnels", s.handleLoliaTunnels)
	mux.HandleFunc("POST /api/lolia/tunnels", s.handleLoliaTunnelCreate)
	mux.HandleFunc("GET /api/lolia/tunnel/{name}", s.handleLoliaTunnelDetail)
	mux.HandleFunc("PUT /api/lolia/tunnel/{name}", s.handleLoliaTunnelUpdate)
	mux.HandleFunc("DELETE /api/lolia/tunnel/{name}", s.handleLoliaTunnelDelete)
	mux.HandleFunc("GET /api/lolia/domains", s.handleLoliaDomainsGet)
	mux.HandleFunc("POST /api/lolia/domains", s.handleLoliaDomainAdd)
	mux.HandleFunc("POST /api/lolia/domains/verify", s.handleLoliaDomainVerify)
	mux.HandleFunc("DELETE /api/lolia/domain/{id}", s.handleLoliaDomainDelete)
	mux.HandleFunc("GET /api/lolia/nodes", s.handleLoliaNodes)
	mux.HandleFunc("POST /api/lolia/start", s.handleLoliaStart)
	mux.HandleFunc("POST /api/lolia/stop", s.handleLoliaStop)
	mux.HandleFunc("GET /api/lolia/status", s.handleLoliaStatus)
	mux.HandleFunc("GET /api/lolia/log", s.handleLoliaLog)

	// Cloudflare Tunnel：每条隧道一个实例（独立进程/日志/启停），内核按需下载或离线安装
	mux.HandleFunc("GET /api/cloudflare/status", s.handleCloudflareStatus)
	mux.HandleFunc("POST /api/cloudflare/install", s.handleCloudflareInstall)
	mux.HandleFunc("GET /api/cloudflare/install/progress", s.handleCloudflareInstallProgress)
	mux.HandleFunc("POST /api/cloudflare/install/upload", s.handleCloudflareInstallUpload)
	// 实例：新建（api 模式同时完成账号+域名绑定）/ 更新 / 删除
	mux.HandleFunc("POST /api/cloudflare/instances", s.handleCloudflareInstanceCreate)
	mux.HandleFunc("POST /api/cloudflare/instances/{id}/update", s.handleCloudflareInstanceUpdate)
	mux.HandleFunc("DELETE /api/cloudflare/instances/{id}", s.handleCloudflareInstanceDelete)
	mux.HandleFunc("POST /api/cloudflare/instances/{id}/start", s.handleCloudflareInstanceStart)
	mux.HandleFunc("POST /api/cloudflare/instances/{id}/stop", s.handleCloudflareInstanceStop)
	mux.HandleFunc("POST /api/cloudflare/instances/{id}/pause", s.handleCloudflareInstancePause)
	mux.HandleFunc("POST /api/cloudflare/instances/{id}/resume", s.handleCloudflareInstanceResume)
	mux.HandleFunc("GET /api/cloudflare/instances/{id}/log", s.handleCloudflareInstanceLog)
	// 域名路由（仅 API 全托管实例：ingress 与 DNS 记录由本程序维护）
	mux.HandleFunc("POST /api/cloudflare/instances/{id}/routes", s.handleCloudflareRoutesSave)
	mux.HandleFunc("POST /api/cloudflare/instances/{id}/routes/delete", s.handleCloudflareRoutesDelete)
	mux.HandleFunc("POST /api/cloudflare/instances/{id}/routes/import", s.handleCloudflareRoutesImport)
	// 账号下的云端隧道列表（新建/编辑 API 实例时选择复用已有隧道）
	mux.HandleFunc("GET /api/cloudflare/tunnels", s.handleCloudflareTunnelsList)
	// frp 服务器连通性与延迟探测（仪表盘展示）
	mux.HandleFunc("GET /api/frpc/server/latency", s.handleFrpcServerLatency)

	// Forward
	mux.HandleFunc("POST /api/forward/start", s.handleForwardStart)
	mux.HandleFunc("GET /api/forward/probe", s.handleForwardProbe)
	mux.HandleFunc("POST /api/forward/stop", s.handleForwardStop)
	mux.HandleFunc("POST /api/forward/update", s.handleForwardUpdate)
	mux.HandleFunc("POST /api/forward/toggle", s.handleForwardToggle)
	mux.HandleFunc("GET /api/forward/list", s.handleForwardList)

	// Webhook 接收器：接收 STUN 客户端上报（POST /api/channel/update，兼容旧路径 /wh/receive），
	// 以及根路径 /{channel_id}（IP:端口/域名 + 通道ID 或自定义ID，兼容旧路径 /tun/、/wh/）
	// 的访问入口（重定向/代理到公网地址）。
	// 字面量路由优先于通配符，/api/channel/update 不会被 {channel_id} 捕获。
	mux.HandleFunc("POST /api/channel/update", s.handleWhReceive)
	mux.HandleFunc("POST /wh/receive", s.handleWhReceive)
	mux.HandleFunc("/{channel_id}", s.handleWhAccess)
	mux.HandleFunc("/{channel_id}/", s.handleWhAccess)
	mux.HandleFunc("/tun/{channel_id}", s.handleWhAccess)
	mux.HandleFunc("/tun/{channel_id}/", s.handleWhAccess)
	mux.HandleFunc("/wh/{channel_id}", s.handleWhAccess)
	mux.HandleFunc("/wh/{channel_id}/", s.handleWhAccess)
	// 导航页（/hook）：集中展示已注册通道的公开页面（开关关闭时 404）
	mux.HandleFunc("GET /hook", s.handleHookIndex)
	mux.HandleFunc("GET /hook/api/data", s.handleHookData)
	mux.HandleFunc("GET /hook/icon", s.handleHookIcon)
	mux.HandleFunc("POST /hook/api/auth", s.handleHookAuth)
	mux.HandleFunc("POST /hook/api/settings", s.handleHookSettings)
	// 图标上传/删除属于管理操作，仅主入口（网关）提供，不在 Webhook 端口开放
	mux.HandleFunc("POST /hook/icon", s.handleHookIconUpload)
	mux.HandleFunc("DELETE /hook/icon", s.handleHookIconDelete)
	// 注册记录管理（列表/注册/编辑/删除/清空）与分组、成功率统计
	mux.HandleFunc("GET /api/wh/records", s.handleWhRecords)
	mux.HandleFunc("POST /api/wh/records", s.handleWhRecords)
	mux.HandleFunc("DELETE /api/wh/records", s.handleWhRecords)
	// 自定义域名验证：校验域名并调用 frpc 代理模块创建域名通道
	mux.HandleFunc("POST /api/wh/domain/verify", s.handleWhDomainVerify)
	// 系统「访问域名」创建/更新 frpc 域名代理（域名模式，Webhook 接收与通道访问）
	mux.HandleFunc("POST /api/wh/system/proxy", s.handleWhSystemProxy)
	mux.HandleFunc("GET /api/wh/groups", s.handleWhGroups)
	mux.HandleFunc("POST /api/wh/groups", s.handleWhGroups)
	mux.HandleFunc("DELETE /api/wh/groups", s.handleWhGroups)
	mux.HandleFunc("POST /api/wh/groups/rename", s.handleWhGroupRename)
	mux.HandleFunc("GET /api/wh/stats", s.handleWhStats)
	mux.HandleFunc("GET /api/wh/log", s.handleWhLog)

	// 端口扫描（对外监听端口 / 服务名称 / 进程名称）
	mux.HandleFunc("GET /api/ports/scan", s.handlePortScan)
	// 上次本机端口扫描的持久化快照（进入页面时立即展示，扫描完成后自动更新）
	mux.HandleFunc("GET /api/ports/snapshot", s.handlePortSnapshot)
	// 端口占用检查 / 空闲端口分配（前端实时显示端口状态与自动选端口）
	mux.HandleFunc("GET /api/ports/check", s.handlePortCheck)
	mux.HandleFunc("GET /api/ports/free", s.handlePortFree)
	// 自动识别宿主机所在局域网网段（局域网扫描默认使用，供前端展示）
	mux.HandleFunc("GET /api/ports/laninfo", s.handleLanInfo)
	// 域名解析（域名 → IPv4 列表，端口扫描前确认目标：单地址直扫，多地址由用户选择）
	mux.HandleFunc("GET /api/ports/resolve", s.handlePortResolve)
	// 域名 DNS 记录查询（A / AAAA / CNAME / MX / NS / TXT）
	mux.HandleFunc("GET /api/ports/dns", s.handlePortDNS)
	// 批量 HTTP(S) 探测主机 Web 服务状态（DNS 记录详情表状态列）
	mux.HandleFunc("GET /api/ports/http-probe", s.handleHTTPProbe)
	// 子域名发现（内置字典枚举 + crt.sh 证书透明度日志）
	mux.HandleFunc("GET /api/ports/subdomains", s.handleSubdomains)
	// 端口卡片操作：TCP 探测 / Ping / 结束占用进程
	mux.HandleFunc("POST /api/ports/probe", s.handlePortProbe)
	mux.HandleFunc("POST /api/ports/ping", s.handlePortPing)
	mux.HandleFunc("POST /api/ports/kill", s.handlePortKill)

	// 网络唤醒（Wake-on-LAN）：设备列表持久化 + 发送魔术包
	mux.HandleFunc("GET /api/wol/devices", s.handleWolDevicesGet)
	mux.HandleFunc("POST /api/wol/devices", s.handleWolDevicesSave)
	mux.HandleFunc("GET /api/wol/scan", s.handleWolScan)
	mux.HandleFunc("GET /api/wol/status", s.handleWolStatus)
	mux.HandleFunc("POST /api/wol/wake", s.handleWolWake)

	// 证书管理（TLS 证书库）
	mux.HandleFunc("GET /api/cert/list", s.handleCertList)
	mux.HandleFunc("POST /api/cert/import", s.handleCertImport)
	mux.HandleFunc("POST /api/cert/apply", s.handleCertApply)
	mux.HandleFunc("GET /api/cert/apply/status", s.handleCertApplyStatus)
	mux.HandleFunc("GET /api/cert/apply/list", s.handleCertApplyList)
	mux.HandleFunc("POST /api/cert/delete", s.handleCertDelete)
	mux.HandleFunc("GET /api/cert/auto-renew", s.handleCertAutoRenewGet)
	mux.HandleFunc("POST /api/cert/auto-renew", s.handleCertAutoRenewSet)
	// 联系人邮箱管理（证书申请账号邮箱）
	mux.HandleFunc("GET /api/email/list", s.handleEmailList)
	mux.HandleFunc("POST /api/email/add", s.handleEmailAdd)
	mux.HandleFunc("POST /api/email/delete", s.handleEmailDelete)
	mux.HandleFunc("GET /api/dns/list", s.handleDNSList)
	mux.HandleFunc("POST /api/dns/add", s.handleDNSAdd)
	mux.HandleFunc("POST /api/dns/delete", s.handleDNSDelete)
	// 域名解析模块：记录管理（列域名/列记录/增/改/删）
	mux.HandleFunc("GET /api/dns/domains", s.handleDNSDomains)
	// 跨账户聚合全部域名（「绑定域名」下拉用；上面的接口必须指定账户）
	mux.HandleFunc("GET /api/dns/all-domains", s.handleDNSAllDomains)
	// 按指定 frp 服务器地址筛选“已解析到该服务器 IP”的域名（转发隧道快捷选择）
	mux.HandleFunc("GET /api/dns/domain-picks", s.handleDNSDomainPicks)
	mux.HandleFunc("GET /api/dns/records", s.handleDNSRecords)
	mux.HandleFunc("POST /api/dns/record/add", s.handleDNSRecordAdd)
	mux.HandleFunc("POST /api/dns/record/update", s.handleDNSRecordUpdate)
	mux.HandleFunc("POST /api/dns/record/delete", s.handleDNSRecordDelete)
	// 域名解析模块：DDNS 动态解析任务
	mux.HandleFunc("GET /api/ddns/list", s.handleDDNSList)
	mux.HandleFunc("POST /api/ddns/add", s.handleDDNSAdd)
	mux.HandleFunc("POST /api/ddns/update", s.handleDDNSUpdate)
	mux.HandleFunc("POST /api/ddns/toggle", s.handleDDNSToggle)
	mux.HandleFunc("POST /api/ddns/delete", s.handleDDNSDelete)
	mux.HandleFunc("POST /api/ddns/now", s.handleDDNSNow)
	mux.HandleFunc("POST /api/ddns/record-bind", s.handleDDNSRecordBind)
	mux.HandleFunc("GET /api/network/interfaces", s.handleNetworkInterfaces)
	mux.HandleFunc("GET /api/network/public/config", s.handlePublicIPConfigGet)
	mux.HandleFunc("POST /api/network/public/config", s.handlePublicIPConfigSet)

	// 桌面图标（fnOS 桌面入口，参考 app-entry 文档）
	mux.HandleFunc("GET /desk/icon/{file}", s.handleDeskIconFile)
	mux.HandleFunc("GET /api/desktop/icon", s.handleDeskIconGet)
	mux.HandleFunc("POST /api/desktop/icon", s.handleDeskIconSave)
	mux.HandleFunc("DELETE /api/desktop/icon", s.handleDeskIconDelete)
	mux.HandleFunc("GET /api/desktop/task", s.handleDeskTaskGet)
	mux.HandleFunc("POST /api/desktop/favicon", s.handleFaviconFetch)

	// 网关路径前缀剥离（socket 与 TCP 共用，处理器仍按根路径工作）
	var handler http.Handler = mux
	if s.gatewayPrefix != "" {
		handler = s.gatewayStripMiddleware(handler)
	}
	// 访问日志（记录真实客户端 IP）+ IP 过滤：先记录后过滤，被拦截的请求（403）也会留下访问日志
	// WAF 在 IP 过滤之后、业务处理之前检查（自身管理界面与 API）
	handler = s.accessLogMiddleware(s.ipFilterMiddleware(s.wafMiddleware("admin", handler)))
	// 自定义域名直达：Host 匹配通道自定义域名时直接按该通道跳转/代理到公网地址（域名根路径即可访问）
	handler = s.whDomainAccessMiddleware(handler)
	// Let's Encrypt HTTP-01 挑战：申请期间临时路由到本服务时直接响应（最外层，绕过网关鉴权）
	challengeHandler := s.acmeChallengeMiddleware(handler)
	// 自定义错误页（最外层）：把本服务产生的 403/404/405/500 等错误响应换成用户自定义页面，
	// 只接管浏览器页面请求，接口（/api/）与统一网关透传上游（/proxy/）不介入
	challengeHandler = errpage.Handler(challengeHandler, s.gatewayPrefix)

	// 统一网关入口：监听网关 Unix Socket，只放行经网关转发的请求（生产部署方式）
	if s.socketPath != "" {
		socketHandler := errpage.Handler(s.acmeChallengeMiddleware(s.gatewayOnlyMiddleware(handler)), s.gatewayPrefix)
		os.Remove(s.socketPath)
		socketLn, err := net.Listen("unix", s.socketPath)
		if err != nil {
			return fmt.Errorf("create gateway socket: %w", err)
		}
		s.socketLn = socketLn
		// 身份头由 HTTP 客户端控制，必须先把可连接 socket 的进程限制为
		// 当前运行 UID（fnOS 网关与本服务均由 root 启动）。
		if err := os.Chmod(s.socketPath, 0600); err != nil {
			s.socketLn.Close()
			s.socketLn = nil
			os.Remove(s.socketPath)
			return fmt.Errorf("secure gateway socket: %w", err)
		}
		s.logger.Info("gateway socket created", zap.String("path", s.socketPath))
		go func() {
			if err := http.Serve(s.socketLn, socketHandler); err != nil && !errors.Is(err, net.ErrClosed) {
				s.logger.Error("gateway socket serve failed", zap.Error(err))
			}
		}()
	}

	// 本地开发入口：--addr/--port 显式指定时额外提供 TCP 监听（生产 cmd/main 不传，保持仅网关访问）
	if s.addr != "" {
		ln, err := net.Listen("tcp", s.addr)
		if err != nil {
			return fmt.Errorf("tcp listen: %w", err)
		}
		s.ln = ln
		s.logger.Info("tcp listener starting (local dev)", zap.String("addr", s.addr))
		go func() {
			if err := http.Serve(s.ln, challengeHandler); err != nil && !errors.Is(err, net.ErrClosed) {
				s.logger.Error("tcp serve failed", zap.Error(err))
			}
		}()
	}

	// Webhook 端口：接收 STUN 客户端上报 + 通道访问入口（直接访问显示通道查找页）
	if err := s.startWhListener(); err != nil {
		return fmt.Errorf("webhook listen: %w", err)
	}

	if s.socketLn == nil && s.ln == nil && s.whLn == nil {
		return fmt.Errorf("no listener configured: provide --socket or --addr/--port")
	}

	<-s.stopCh
	return nil
}

// whPortHandler 构建 Webhook 端口独立路由（不含管理界面/管理 API）：
// 根路径显示通道查找页，/{id} 为通道访问入口，/api/channel/update 接收客户端上报。
func (s *Server) whPortHandler() http.Handler {
	mux := http.NewServeMux()
	// 根路径：通道查找页（仅精确匹配 "/"，其余未知路径 404）
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		s.serveWhIndexPage(w, r)
	})
	// 通道访问：根路径 /{通道id}（兼容旧路径 /tun/、/wh/）
	mux.HandleFunc("/{channel_id}", s.handleWhAccess)
	mux.HandleFunc("/{channel_id}/", s.handleWhAccess)
	mux.HandleFunc("/tun/{channel_id}", s.handleWhAccess)
	mux.HandleFunc("/tun/{channel_id}/", s.handleWhAccess)
	mux.HandleFunc("/wh/{channel_id}", s.handleWhAccess)
	mux.HandleFunc("/wh/{channel_id}/", s.handleWhAccess)
	// 导航页（/hook）：集中展示已注册通道的公开页面（开关关闭时 404）
	mux.HandleFunc("GET /hook", s.handleHookIndex)
	mux.HandleFunc("GET /hook/api/data", s.handleHookData)
	mux.HandleFunc("GET /hook/icon", s.handleHookIcon)
	mux.HandleFunc("POST /hook/api/auth", s.handleHookAuth)
	mux.HandleFunc("POST /hook/api/settings", s.handleHookSettings)
	// 导航页 LOGO 上传/删除（需管理密码鉴权，供 /hook 设置弹窗使用）
	mux.HandleFunc("POST /hook/icon", s.hookAdminRequired(s.handleHookIconUpload))
	mux.HandleFunc("DELETE /hook/icon", s.hookAdminRequired(s.handleHookIconDelete))
	// 接收 STUN 客户端上报
	mux.HandleFunc("POST /api/channel/update", s.handleWhReceive)
	mux.HandleFunc("POST /wh/receive", s.handleWhReceive)
	// LoliaFrp OAuth2 授权回调（用户在 LoliaFrp 应用中登记的 redirect_uri 即指向这里）
	mux.HandleFunc("GET /api/lolia", s.handleLoliaOAuthCallback)
	// 通道查找页数据源（脱敏：仅公开信息）
	mux.HandleFunc("GET /api/wh/public", s.handleWhPublicRecords)
	// 状态页数据源（系统组件运行情况）
	mux.HandleFunc("GET /api/status/overview", s.handleWhStatusOverview)
	// 查找页图标
	mux.HandleFunc("GET /static/icon.svg", func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFS.ReadFile("static/icon.svg")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Write(data)
	})
	// 本地搜索引擎图标（/static/bing.svg 等，白名单）
	mux.HandleFunc("GET /static/{name}", s.handleEngineStaticIcon)
	// 访问日志（记录真实客户端 IP）+ IP 过滤 + WAF + 自定义域名直达 + ACME 挑战
	handler := s.accessLogMiddleware(s.ipFilterMiddleware(s.wafMiddleware("webhook", mux)))
	handler = s.whDomainAccessMiddleware(handler)
	handler = s.acmeChallengeMiddleware(handler)
	// 自定义错误页：通道查找页/通道访问页/导航页的 404 等换成用户自定义页面
	return errpage.Handler(handler, "")
}

// startWhListener 启动 Webhook 端口监听（接收上报 + 通道访问入口）。端口<=0 时不监听。
func (s *Server) startWhListener() error {
	s.whLnMu.Lock()
	defer s.whLnMu.Unlock()
	port := s.whReceiverCfg().ReceivePort
	if port <= 0 {
		return nil
	}
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	s.whLn = ln
	s.logger.Info("webhook listener started (receive + channel access)", zap.Int("port", port))
	go func() {
		handler := s.whPortHandler()
		if err := http.Serve(ln, handler); err != nil && !errors.Is(err, net.ErrClosed) {
			s.logger.Error("webhook serve failed", zap.Error(err))
		}
	}()
	return nil
}

// stopWhListener 关闭 Webhook 端口监听。
func (s *Server) stopWhListener() {
	s.whLnMu.Lock()
	defer s.whLnMu.Unlock()
	if s.whLn != nil {
		s.whLn.Close()
		s.whLn = nil
	}
}

// restartWhListener 按最新配置重建 Webhook 端口监听（设置变更端口后调用）。
func (s *Server) restartWhListener() {
	s.stopWhListener()
	if err := s.startWhListener(); err != nil {
		s.logger.Warn("webhook listener restart failed", zap.Error(err))
	}
}

// syncWhDomainProxyPort 端口变更后同步已有 frpc 域名代理的回落端口：
// 将回落旧 Webhook 端口的 http/https 代理更新为新端口，避免域名访问仍指向旧端口。
func (s *Server) syncWhDomainProxyPort(oldPort, newPort int) {
	if oldPort <= 0 || oldPort == newPort {
		return
	}
	cfg := s.frpcMgr.LoadConfig()
	changed := false
	for i := range cfg.Proxies {
		p := &cfg.Proxies[i]
		typ := strings.ToLower(strings.TrimSpace(p.Type))
		if (typ == "http" || typ == "https") && p.LocalPort == oldPort {
			p.LocalPort = newPort
			changed = true
		}
	}
	if !changed {
		return
	}
	if err := s.frpcMgr.SaveConfig(cfg); err != nil {
		s.logger.Warn("同步 frpc 域名代理回落端口失败", zap.Int("old", oldPort), zap.Int("new", newPort), zap.Error(err))
		return
	}
	s.logger.Info("已同步 frpc 域名代理回落端口", zap.Int("old", oldPort), zap.Int("new", newPort))
}

// syncSystemDomainProxy 设置变更后同步系统「访问域名」的 frpc 域名代理：
// 清空域名时删除旧域名代理；设置/修改域名时自动创建或更新代理（幂等）。
func (s *Server) syncSystemDomainProxy(oldDomain, newDomain string) {
	if newDomain == "" {
		if oldDomain != "" {
			// 清理旧域名代理：按域名定位（含已停用/归属其它服务器的代理），避免残留孤儿代理
			if p := s.frpcProxyUsingDomain(oldDomain); p != "" {
				if err := s.frpcMgr.DeleteProxy(p); err != nil {
					s.logger.Warn("删除系统域名代理失败", zap.String("domain", oldDomain), zap.String("proxy", p), zap.Error(err))
					return
				}
				s.logger.Info("已删除系统域名代理", zap.String("domain", oldDomain), zap.String("proxy", p))
			}
		}
		return
	}
	if newDomain == oldDomain {
		return
	}
	proxyName, err := s.applySystemDomainProxy(newDomain)
	if err != nil {
		s.logger.Warn("同步系统域名代理失败", zap.String("domain", newDomain), zap.Error(err))
		return
	}
	s.logger.Info("已同步系统域名代理", zap.String("domain", newDomain), zap.String("proxy", proxyName))
}

// gatewayOnlyMiddleware 只放行经飞牛统一网关转发的请求：
// 网关在鉴权后会注入 X-Trim-Userid 等身份头，缺少该头说明请求未经过网关，
// 直接拒绝，确保仅能通过统一网关访问。
func (s *Server) gatewayOnlyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Trim-Userid") == "" {
			s.writeJSON(w, http.StatusForbidden, apiErr("仅允许通过飞牛统一网关访问"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleGatewayProxy 处理“统一网关”转发：经飞牛网关鉴权后的请求在 /proxy/{name}
// 下反向代理到对应转发规则的远端目标。规则未运行或不存在时返回 404。
func (s *Server) handleGatewayProxy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		errpage.Write(w, r, http.StatusNotFound, "404 page not found")
		return
	}
	// 无尾斜杠的网关根路径重定向到带尾斜杠版本（仅 GET/HEAD，排除 WebSocket 升级）：
	// 否则页面内相对路径资源（如 scripts/x.js）会被浏览器解析到 /proxy/scripts/x.js，
	// 导致规则名称段丢失而 404（典型如 Synology DSM 桌面/登录页）。
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		!strings.EqualFold(r.Header.Get("Connection"), "upgrade") &&
		!strings.HasSuffix(r.URL.Path, "/") && r.URL.Path == "/proxy/"+name {
		target := r.URL.Path + "/"
		if s.gatewayPrefix != "" {
			target = s.gatewayPrefix + target
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return
	}
	h := s.fwdMgr.GatewayHandler(name)
	if h == nil {
		errpage.Write(w, r, http.StatusNotFound, "404 page not found")
		return
	}
	h.ServeHTTP(w, r)
}

// gatewayStripMiddleware strips the gateway prefix from request paths,
// so all handlers can keep working with root-relative paths (/api/..., /, etc.).
// 同时兼容桌面图标空应用前缀 /app/TunHook-{name}：请求经图标应用 socket 软链进入本应用，
// 把前缀改写成 /proxy/{name}，复用统一网关转发链路。
func (s *Server) gatewayStripMiddleware(next http.Handler) http.Handler {
	prefix := s.gatewayPrefix
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 桌面图标空应用前缀（/app/TunHook-{规则名}），改写为 /proxy/{规则名}
		if name, rest, ok := matchDeskAppPath(r.URL.Path, prefix); ok {
			newPath := "/proxy/" + name + rest
			if rest == "" {
				newPath += "/"
			}
			originalPath := r.URL.Path
			r.URL.Path = newPath
			s.logger.Debug("desk app prefix rewritten",
				zap.String("original", originalPath),
				zap.String("rewritten", newPath),
			)
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix) {
			newPath := strings.TrimPrefix(r.URL.Path, prefix)
			if newPath == "" {
				newPath = "/"
			}
			// Redirect root path without trailing slash so relative URLs resolve correctly
			if newPath == "/" && !strings.HasSuffix(r.URL.Path, "/") {
				http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
				return
			}
			originalPath := r.URL.Path
			r.URL.Path = newPath
			s.logger.Debug("gateway prefix stripped",
				zap.String("original", originalPath),
				zap.String("rewritten", newPath),
			)
		}
		next.ServeHTTP(w, r)
	})
}

// matchDeskAppPath 匹配桌面图标空应用的网关前缀 /app/TunHook-{规则名}（规则名仅字母数字），
// 返回规则名与剩余路径。主应用自身前缀（/app/TunHook 及其全部子路径）由调用方先行排除，
// 否则 /app/TunHook/、/app/TunHook/api/status 等会被误判为规则名 "ook" 的
// 图标应用而改写为 /proxy/ook/ 导致 404。
func matchDeskAppPath(p, selfPrefix string) (name, rest string, ok bool) {
	const head = "/app/TunHook-"
	if !strings.HasPrefix(p, head) || p == selfPrefix || strings.HasPrefix(p, selfPrefix+"/") {
		return "", "", false
	}
	tail := p[len(head):]
	i := 0
	for i < len(tail) {
		c := tail[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			i++
			continue
		}
		break
	}
	if i == 0 {
		return "", "", false
	}
	if i < len(tail) && tail[i] != '/' {
		return "", "", false
	}
	return tail[:i], tail[i:], true
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, resp interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func apiOK(data interface{}) map[string]interface{} {
	return map[string]interface{}{"success": true, "data": data}
}
func apiMsg(msg string) map[string]interface{} {
	return map[string]interface{}{"success": true, "message": msg}
}
func apiErr(msg string) map[string]interface{} {
	return map[string]interface{}{"success": false, "error": msg}
}

func (s *Server) getDesc(kind, id string) string {
	v, ok := s.descriptions.Load(kind + ":" + id)
	if ok {
		return v.(string)
	}
	return ""
}

// loadDescriptions 启动时把持久化的描述加载进内存缓存。
func (s *Server) loadDescriptions() {
	kv, err := s.store.SettingsByPrefix("desc.")
	if err != nil {
		return
	}
	for k, v := range kv {
		s.descriptions.Store(strings.TrimPrefix(k, "desc."), v)
	}
}

// setDescription 更新描述（非空写入/空则删除），同时落库。
func (s *Server) setDescription(kind, id, desc string) {
	if desc != "" {
		s.descriptions.Store(kind+":"+id, desc)
		s.store.SetSetting("desc."+kind+":"+id, desc)
	} else {
		s.descriptions.Delete(kind + ":" + id)
		s.store.DeleteSetting("desc." + kind + ":" + id)
	}
}

// persistConfig 把 Web 端修改的配置项持久化（dotted key，JSON value），
// 重启后由 cli.applyDBConfig 覆盖回配置。
func (s *Server) persistConfig(key string, v interface{}) {
	if err := s.store.SetJSON("cfg."+key, v); err != nil {
		s.logger.Warn("persist config failed", zap.String("key", key), zap.Error(err))
	}
}

// ============= 累计流量统计持久化 =============

// trafficBase 读取指定条目的累计流量基线（tx, rx）；无记录时返回 0。
func (s *Server) trafficBase(m *sync.Map, id string) (int64, int64) {
	if v, ok := m.Load(id); ok {
		if b, ok := v.(*[2]int64); ok {
			return b[0], b[1]
		}
	}
	return 0, 0
}

// persistTrafficItem 把「基线 + 当前计数器」写回数据库（累计值）。
// flush=true 时同时更新内存基线为累计值（用于停止/暂停：计数器即将清零，下次以新基线续算）。
func (s *Server) persistTrafficItem(m *sync.Map, id string, cTx, cRx int64, flush bool) {
	baseTx, baseRx := s.trafficBase(m, id)
	totalTx, totalRx := baseTx+cTx, baseRx+cRx
	if err := s.store.UpdateForwardTraffic(id, totalTx, totalRx); err != nil {
		s.logger.Warn("持久化流量统计失败",
			zap.String("id", id), zap.Error(err))
		return
	}
	if flush {
		m.Store(id, &[2]int64{totalTx, totalRx})
	}
}

// persistAllTraffic 持久化所有运行中转发规则的累计流量
// （每 5 分钟定时调用；进程关闭时也调用一次，防止统计数据丢失）。
func (s *Server) persistAllTraffic() {
	for _, key := range s.fwdMgr.RunningRules() {
		tx, rx, _ := s.fwdMgr.GetStats(key)
		s.persistTrafficItem(&s.fwdTrafficBase, key, tx, rx, false)
	}
}

// ============= Logs =============

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	page := 1
	pageSize := 50
	fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
	fmt.Sscanf(r.URL.Query().Get("pageSize"), "%d", &pageSize)
	level := r.URL.Query().Get("level")
	search := r.URL.Query().Get("search")
	category := r.URL.Query().Get("category")
	module := r.URL.Query().Get("module")
	date := r.URL.Query().Get("date")
	excludeModule := r.URL.Query().Get("exclude_module")
	if category != "access" && category != "channel" && category != "system" {
		category = ""
	}
	if page < 1 || page > 1000000 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}

	var entries []LogEntry
	var total int
	if fwdKey := r.URL.Query().Get("forward"); fwdKey != "" {
		// 转发日志：从该规则的独立缓冲查询（通道日志全部属于 forward 模块，module 过滤忽略）
		entries, total = s.forwardLogs.query(fwdKey, page, pageSize, level, search, category, module, date)
	} else if shID := r.URL.Query().Get("stunhole"); shID != "" {
		// STUN 通道日志：内存环形缓冲，转为统一 LogEntry 结构，复用日志弹窗的分页/过滤
		all := make([]LogEntry, 0, 64)
		if s.stunholeMgr != nil {
			for _, l := range s.stunholeMgr.Logs(shID) {
				all = append(all, LogEntry{
					Level:   l.Level,
					Time:    time.Unix(l.Ts, 0).Format("2006-01-02 15:04:05"),
					Module:  "stunhole",
					Message: l.Msg,
				})
			}
		}
		entries, total = filterLogEntries(all, level, search, page, pageSize)
	} else {
		entries, total = s.logBuf.Query(page, pageSize, level, search, category, module, date, excludeModule)
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"entries":  entries,
		"total":    total,
		"page":     page,
		"pageSize": pageSize,
		"modules":  s.logBuf.Modules(),
	}))
}

// filterLogEntries 对内存日志条目做级别/关键字过滤与倒序分页，
// 供 STUN 打洞通道等「非 LogBuffer」来源复用 /api/logs 的分页协议。
func filterLogEntries(all []LogEntry, level, search string, page, pageSize int) ([]LogEntry, int) {
	kw := strings.ToLower(strings.TrimSpace(search))
	matched := make([]LogEntry, 0, len(all))
	for _, e := range all {
		if level != "" && !strings.EqualFold(e.Level, level) {
			continue
		}
		if kw != "" && !strings.Contains(strings.ToLower(e.Message), kw) {
			continue
		}
		matched = append(matched, e)
	}
	return paginateLogEntriesDesc(matched, page, pageSize)
}

// Modules 返回日志缓冲中出现过的来源模块（去重、按出现顺序），用于前端筛选下拉。
func (b *LogBuffer) Modules() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	seen := make(map[string]bool, 8)
	var out []string
	for _, e := range b.entries {
		if e.Module == "" || seen[e.Module] {
			continue
		}
		seen[e.Module] = true
		out = append(out, e.Module)
	}
	return out
}

// handleLogArchive 将共享日志目录中的磁盘日志文件（tunhook-*.log / frpc.log 等）打包为 zip 下载。
func (s *Server) handleLogArchive(w http.ResponseWriter, r *http.Request) {
	dir := s.shareLog
	if dir == "" {
		dir = s.dataDir
	}
	var files []string
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".log."+time.Now().Format("2006-01-02")) {
				files = append(files, filepath.Join(dir, name))
			}
		}
	}
	if len(files) == 0 {
		s.writeJSON(w, http.StatusOK, apiErr("日志目录中暂无日志文件"))
		return
	}
	sort.Strings(files)

	zipName := fmt.Sprintf("tunhook-logs-%s.zip", time.Now().Format("2006-01-02-150405"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename="+zipName)
	zw := zip.NewWriter(w)
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		zh, err := zw.Create(filepath.Base(f))
		if err != nil {
			continue
		}
		in, err := os.Open(f)
		if err != nil {
			continue
		}
		_, _ = io.Copy(zh, io.LimitReader(in, fi.Size()))
		in.Close()
	}
	zw.Close()
}

// ============= Settings =============

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	logCfg := map[string]interface{}{
		"max_entries":               s.cfg.Log.MaxEntries,
		"tunnel_max_entries":        s.cfg.Log.TunnelMaxEntries,
		"tunnel_access_max_entries": s.cfg.Log.TunnelAccessMaxEntries,
		"expire_days":               s.cfg.Log.ExpireDays,
		"traffic_retention_days":    s.cfg.Log.TrafficRetentionDays,
	}
	forwardCfg := map[string]interface{}{
		"http_default_port":  s.cfg.Forward.HTTPDefaultPort,
		"https_default_port": s.cfg.Forward.HTTPSDefaultPort,
		"web_access_mode":    s.cfg.Forward.WebAccessMode,
		"web_access_domain":  s.cfg.Forward.WebAccessDomain,
		"web_access_ip":      s.cfg.Forward.WebAccessIP,
	}
	// Webhook 接收器配置（地址模式 + 单一 Webhook 端口：接收与访问共用，access_port 同步为 receive_port）
	whReceiverCfg := map[string]interface{}{
		"enabled":       s.cfg.WebhookReceiver.Enabled,
		"secret":        s.cfg.WebhookReceiver.Secret,
		"addr_mode":     s.cfg.WebhookReceiver.AddrMode,
		"receive_addr":  s.cfg.WebhookReceiver.ReceiveAddr,
		"receive_port":  s.cfg.WebhookReceiver.ReceivePort,
		"access_ip":     s.cfg.WebhookReceiver.AccessIP,
		"access_domain": s.cfg.WebhookReceiver.AccessDomain,
		"access_port":   s.cfg.WebhookReceiver.ReceivePort, // 已合并：访问端口与接收端口保持一致
		"mode":          s.cfg.WebhookReceiver.Mode,
		"callback":      s.cfg.WebhookReceiver.Callback,
	}
	// Webhook 模板（请求方法/请求头/请求体/成功字符）
	whTemplateCfg := map[string]interface{}{
		"method":         s.cfg.WebhookTemplate.Method,
		"headers":        s.cfg.WebhookTemplate.Headers,
		"body":           s.cfg.WebhookTemplate.Body,
		"success_string": s.cfg.WebhookTemplate.SuccessString,
	}
	// IP 过滤开关（默认关闭，由「IP 过滤」页的拦截功能开关控制；过滤开启时 ipFilterMiddleware 才会执行黑白名单/公网校验）
	ipFilterEnabled := s.cfg.IPFilter.Enabled
	// 导航页（/hook）配置：开关 + 标题 + 图标 + 搜索引擎 + 搜索栏/分区显隐
	hookCfg := map[string]interface{}{
		"enabled":       s.cfg.Hook.Enabled,
		"title":         s.cfg.Hook.Title,
		"search_engine": s.cfg.Hook.SearchEngine,
		"show_search":   s.cfg.Hook.ShowSearch,
		"icon":          s.cfg.Hook.Icon,
		"show_webhook":  s.cfg.Hook.ShowWebhook,
		"show_forwards": s.cfg.Hook.ShowForwards,
		"show_proxies":  s.cfg.Hook.ShowProxies,
	}
	s.cfgMu.RUnlock()

	// 自定义 IP（禁止列表）来自 ip_filter_entries 表
	customIPs, err := s.store.ListCustomIPs()
	if err != nil {
		s.logger.Warn("读取自定义IP列表失败", zap.Error(err))
		customIPs = nil
	}
	whitelistIPs, err := s.store.ListWhitelistIPs()
	if err != nil {
		s.logger.Warn("读取白名单列表失败", zap.Error(err))
		whitelistIPs = nil
	}
	blockedIPs, err := s.store.ListBlockedIPs()
	if err != nil {
		s.logger.Warn("读取拦截记录失败", zap.Error(err))
		blockedIPs = nil
	}

	resp := apiOK(map[string]interface{}{
		"log":         logCfg,
		"forward":     forwardCfg,
		"wh_receiver": whReceiverCfg,
		"wh_template": whTemplateCfg,
		"ip_filter": map[string]interface{}{
			"enabled":           ipFilterEnabled,
			"mode":              s.cfg.IPFilter.Mode,
			"allow_lan":         s.cfg.IPFilter.AllowLAN,
			"auto_record":       s.ipFilterAutoRecordSetting(),
			"custom_ips":        customIPs,
			"whitelist_ips":     whitelistIPs,
			"blocked_ips":       blockedIPs,
			"whitelist_regions": s.cfg.IPFilter.WhitelistRegions,
			"blacklist_regions": s.cfg.IPFilter.BlacklistRegions,
		},
		"hook": hookCfg,
	})

	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	whPortChanged := false // Webhook 端口是否变更（变更后重建独立监听并同步 frpc 代理回落）
	whOldPort := 0         // 变更前的 Webhook 端口
	whNewPort := 0         // 变更后的 Webhook 端口
	domainChanged := false // 系统访问域名/地址模式是否变更（变更后自动同步 frpc 域名代理）
	whOldDomain := ""      // 变更前的访问域名
	whNewDomain := ""      // 变更后的访问域名
	closeDisabled := false // 存在通道时禁止关闭 Webhook 接收（强制保持开启）
	var req struct {
		Log *struct {
			MaxEntries             *int `json:"max_entries"`
			TunnelMaxEntries       *int `json:"tunnel_max_entries"`
			TunnelAccessMaxEntries *int `json:"tunnel_access_max_entries"`
			ExpireDays             *int `json:"expire_days"`
			TrafficRetentionDays   *int `json:"traffic_retention_days"`
		} `json:"log"`
		Forward *struct {
			HTTPDefaultPort  *int    `json:"http_default_port"`
			HTTPSDefaultPort *int    `json:"https_default_port"`
			WebAccessMode    *string `json:"web_access_mode"`
			WebAccessDomain  *string `json:"web_access_domain"`
			WebAccessIP      *string `json:"web_access_ip"`
		} `json:"forward"`
		WhReceiver *struct {
			Enabled      *bool   `json:"enabled"`
			Secret       *string `json:"secret"`
			AddrMode     *string `json:"addr_mode"`
			ReceiveAddr  *string `json:"receive_addr"`
			ReceivePort  *int    `json:"receive_port"`
			AccessIP     *string `json:"access_ip"`
			AccessDomain *string `json:"access_domain"`
			AccessPort   *int    `json:"access_port"`
			Mode         *string `json:"mode"`
			Callback     *string `json:"callback"`
		} `json:"wh_receiver"`
		WhTemplate *struct {
			Method        *string           `json:"method"`
			Headers       map[string]string `json:"headers"`
			Body          *string           `json:"body"`
			SuccessString *string           `json:"success_string"`
		} `json:"wh_template"`
		IPFilter *struct {
			Enabled  *bool   `json:"enabled"`
			Mode     *string `json:"mode"`
			AllowLAN *bool   `json:"allow_lan"`
		} `json:"ip_filter"`
		Hook *struct {
			Enabled      *bool   `json:"enabled"`
			Title        *string `json:"title"`
			SearchEngine *string `json:"search_engine"`
			ShowSearch   *bool   `json:"show_search"`
			ShowWebhook  *bool   `json:"show_webhook"`
			ShowForwards *bool   `json:"show_forwards"`
			ShowProxies  *bool   `json:"show_proxies"`
			AdminPass    *string `json:"admin_pass"`
		} `json:"hook"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}

	// 一次性获取写锁保护 s.cfg 的所有写入
	s.cfgMu.Lock()

	// 更新日志配置
	if req.Log != nil {
		if req.Log.MaxEntries != nil && *req.Log.MaxEntries > 0 {
			s.cfg.Log.MaxEntries = *req.Log.MaxEntries
			s.logBuf.SetCap(*req.Log.MaxEntries)
			s.persistConfig("log.max_entries", *req.Log.MaxEntries)
		}
		if req.Log.TunnelMaxEntries != nil && *req.Log.TunnelMaxEntries > 0 {
			s.cfg.Log.TunnelMaxEntries = *req.Log.TunnelMaxEntries
			s.forwardLogs.setCapsAll(*req.Log.TunnelMaxEntries, s.cfg.Log.TunnelAccessMaxEntries)
			s.persistConfig("log.tunnel_max_entries", *req.Log.TunnelMaxEntries)
		}
		if req.Log.TunnelAccessMaxEntries != nil && *req.Log.TunnelAccessMaxEntries > 0 {
			s.cfg.Log.TunnelAccessMaxEntries = *req.Log.TunnelAccessMaxEntries
			s.forwardLogs.setCapsAll(s.cfg.Log.TunnelMaxEntries, *req.Log.TunnelAccessMaxEntries)
			s.persistConfig("log.tunnel_access_max_entries", *req.Log.TunnelAccessMaxEntries)
		}
		if req.Log.ExpireDays != nil && *req.Log.ExpireDays > 0 {
			s.cfg.Log.ExpireDays = *req.Log.ExpireDays
			s.persistConfig("log.expire_days", *req.Log.ExpireDays)
		}
		if req.Log.TrafficRetentionDays != nil && *req.Log.TrafficRetentionDays > 0 {
			s.cfg.Log.TrafficRetentionDays = *req.Log.TrafficRetentionDays
			s.persistConfig("log.traffic_retention_days", *req.Log.TrafficRetentionDays)
			// 保存后立即清理一次，使新保留策略马上生效
			go s.cleanupTrafficSamples()
		}
	}

	// 更新转发默认端口配置
	if req.Forward != nil {
		if req.Forward.HTTPDefaultPort != nil && *req.Forward.HTTPDefaultPort > 0 && *req.Forward.HTTPDefaultPort <= 65535 {
			s.cfg.Forward.HTTPDefaultPort = *req.Forward.HTTPDefaultPort
			s.persistConfig("forward.http_default_port", *req.Forward.HTTPDefaultPort)
		}
		if req.Forward.HTTPSDefaultPort != nil && *req.Forward.HTTPSDefaultPort > 0 && *req.Forward.HTTPSDefaultPort <= 65535 {
			s.cfg.Forward.HTTPSDefaultPort = *req.Forward.HTTPSDefaultPort
			s.persistConfig("forward.https_default_port", *req.Forward.HTTPSDefaultPort)
		}
		if req.Forward.WebAccessMode != nil {
			mode := strings.ToLower(strings.TrimSpace(*req.Forward.WebAccessMode))
			if mode != "ip" && mode != "domain" {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("路径访问方式仅支持 ip 或 domain"))
				return
			}
			s.cfg.Forward.WebAccessMode = mode
			s.persistConfig("forward.web_access_mode", mode)
		}
		if req.Forward.WebAccessDomain != nil {
			domain := strings.TrimSpace(*req.Forward.WebAccessDomain)
			if strings.ContainsAny(domain, " /?#") {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("访问域名格式无效，只填写域名本身"))
				return
			}
			s.cfg.Forward.WebAccessDomain = domain
			s.persistConfig("forward.web_access_domain", domain)
		}
		if req.Forward.WebAccessIP != nil {
			ip := strings.TrimSpace(*req.Forward.WebAccessIP)
			if ip != "" && net.ParseIP(ip) == nil {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("访问 IP 格式无效"))
				return
			}
			s.cfg.Forward.WebAccessIP = ip
			s.persistConfig("forward.web_access_ip", ip)
		}
		if s.cfg.Forward.WebAccessMode == "domain" && strings.TrimSpace(s.cfg.Forward.WebAccessDomain) == "" {
			s.cfgMu.Unlock()
			s.writeJSON(w, http.StatusBadRequest, apiErr("选择域名访问时必须填写访问域名"))
			return
		}
	}

	// 更新 Webhook 接收器配置
	if req.WhReceiver != nil {
		if req.WhReceiver.Enabled != nil {
			// 存在通道时必须保持开启（否则客户端上报接口不可用）：拒绝关闭并回写开启
			if !*req.WhReceiver.Enabled && s.whRecv.count() > 0 {
				s.cfg.WebhookReceiver.Enabled = true
				s.persistConfig("wh_receiver.enabled", true)
				closeDisabled = true
			} else {
				s.cfg.WebhookReceiver.Enabled = *req.WhReceiver.Enabled
				s.persistConfig("wh_receiver.enabled", *req.WhReceiver.Enabled)
			}
		}
		if req.WhReceiver.AddrMode != nil {
			mode := strings.ToLower(strings.TrimSpace(*req.WhReceiver.AddrMode))
			if mode != "ip" && mode != "domain" {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("地址模式仅支持 ip 或 domain"))
				return
			}
			s.cfg.WebhookReceiver.AddrMode = mode
			s.persistConfig("wh_receiver.addr_mode", mode)
			// 切换到域名模式且已配置访问域名：自动创建域名代理（实时生效）
			if mode == "domain" && s.cfg.WebhookReceiver.AccessDomain != "" {
				domainChanged = true
				whNewDomain = s.cfg.WebhookReceiver.AccessDomain
			}
		}
		if req.WhReceiver.Secret != nil {
			s.cfg.WebhookReceiver.Secret = strings.TrimSpace(*req.WhReceiver.Secret)
			s.persistConfig("wh_receiver.secret", s.cfg.WebhookReceiver.Secret)
		}
		if req.WhReceiver.ReceiveAddr != nil {
			s.cfg.WebhookReceiver.ReceiveAddr = strings.TrimSpace(*req.WhReceiver.ReceiveAddr)
			s.persistConfig("wh_receiver.receive_addr", s.cfg.WebhookReceiver.ReceiveAddr)
		}
		if req.WhReceiver.ReceivePort != nil {
			p := *req.WhReceiver.ReceivePort
			if p < 0 || p > 65535 {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("Webhook 端口必须为 0-65535"))
				return
			}
			// 接收与访问共用同一端口：同步保存两个配置键
			whOldPort = s.cfg.WebhookReceiver.ReceivePort
			whNewPort = p
			s.cfg.WebhookReceiver.ReceivePort = p
			s.cfg.WebhookReceiver.AccessPort = p
			s.persistConfig("wh_receiver.receive_port", p)
			s.persistConfig("wh_receiver.access_port", p)
			whPortChanged = true
		}
		if req.WhReceiver.AccessIP != nil {
			ip := strings.TrimSpace(*req.WhReceiver.AccessIP)
			if ip != "" && net.ParseIP(ip) == nil {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("访问IP 格式无效，例如 192.168.1.70"))
				return
			}
			s.cfg.WebhookReceiver.AccessIP = ip
			s.persistConfig("wh_receiver.access_ip", ip)
		}
		if req.WhReceiver.AccessDomain != nil {
			whOldDomain = s.cfg.WebhookReceiver.AccessDomain
			whNewDomain = strings.ToLower(strings.TrimSpace(*req.WhReceiver.AccessDomain))
			s.cfg.WebhookReceiver.AccessDomain = whNewDomain
			s.persistConfig("wh_receiver.access_domain", whNewDomain)
			// 域名模式：访问域名变更时自动创建/更新或删除 frpc 域名代理（实时生效）
			if s.cfg.WebhookReceiver.AddrMode == "domain" && (whNewDomain != whOldDomain || whNewDomain == "") {
				domainChanged = true
			}
		}
		if req.WhReceiver.AccessPort != nil {
			p := *req.WhReceiver.AccessPort
			if p < 1 || p > 65535 {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("Webhook 端口必须为 1-65535"))
				return
			}
			// 兼容旧版客户端：访问端口与接收端口合并，保存时同步为同一值
			whOldPort = s.cfg.WebhookReceiver.ReceivePort
			whNewPort = p
			s.cfg.WebhookReceiver.AccessPort = p
			s.cfg.WebhookReceiver.ReceivePort = p
			s.persistConfig("wh_receiver.access_port", p)
			s.persistConfig("wh_receiver.receive_port", p)
			whPortChanged = true
		}
		if req.WhReceiver.Mode != nil {
			mode := strings.ToLower(strings.TrimSpace(*req.WhReceiver.Mode))
			if mode != "redirect" && mode != "proxy" {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("Webhook 访问方式仅支持 redirect 或 proxy"))
				return
			}
			s.cfg.WebhookReceiver.Mode = mode
			s.persistConfig("wh_receiver.mode", mode)
		}
		if req.WhReceiver.Callback != nil {
			s.cfg.WebhookReceiver.Callback = strings.TrimSpace(*req.WhReceiver.Callback)
			s.persistConfig("wh_receiver.callback", s.cfg.WebhookReceiver.Callback)
		}
	}

	// 更新 Webhook 模板（请求方法/请求头/请求体/成功字符）
	if req.WhTemplate != nil {
		if req.WhTemplate.Method != nil {
			method := strings.ToUpper(strings.TrimSpace(*req.WhTemplate.Method))
			if !validHTTPMethod(method) {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("请求方法仅支持 GET/POST/PUT/DELETE 等常用 HTTP 方法"))
				return
			}
			s.cfg.WebhookTemplate.Method = method
			s.persistConfig("wh_template.method", method)
		}
		if req.WhTemplate.Headers != nil {
			h := map[string]string{}
			for k, v := range req.WhTemplate.Headers {
				k = strings.TrimSpace(k)
				if k != "" {
					h[k] = v
				}
			}
			s.cfg.WebhookTemplate.Headers = h
			s.persistConfig("wh_template.headers", h)
		}
		if req.WhTemplate.Body != nil {
			s.cfg.WebhookTemplate.Body = *req.WhTemplate.Body
			s.persistConfig("wh_template.body", *req.WhTemplate.Body)
		}
		if req.WhTemplate.SuccessString != nil {
			s.cfg.WebhookTemplate.SuccessString = strings.TrimSpace(*req.WhTemplate.SuccessString)
			s.persistConfig("wh_template.success_string", s.cfg.WebhookTemplate.SuccessString)
		}
	}

	// 更新 IP 过滤配置（条目仅通过 /api/ipfilter/custom 手动录入）
	if req.IPFilter != nil {
		if req.IPFilter.Enabled != nil {
			s.cfg.IPFilter.Enabled = *req.IPFilter.Enabled
			s.persistConfig("ip_filter.enabled", *req.IPFilter.Enabled)
		}
		if req.IPFilter.Mode != nil && (*req.IPFilter.Mode == "blacklist" || *req.IPFilter.Mode == "whitelist") {
			s.cfg.IPFilter.Mode = *req.IPFilter.Mode
			s.persistConfig("ip_filter.mode", *req.IPFilter.Mode)
		}
		if req.IPFilter.AllowLAN != nil {
			s.cfg.IPFilter.AllowLAN = *req.IPFilter.AllowLAN
			s.persistConfig("ip_filter.allow_lan", *req.IPFilter.AllowLAN)
		}
	}

	// 更新导航页配置（/hook 访问入口）：开关 / 标题 / 搜索引擎 / 搜索栏与统计条显隐
	if req.Hook != nil {
		if req.Hook.Enabled != nil {
			s.cfg.Hook.Enabled = *req.Hook.Enabled
			s.persistConfig("hook.enabled", *req.Hook.Enabled)
		}
		if req.Hook.Title != nil {
			title := strings.TrimSpace(*req.Hook.Title)
			if len([]rune(title)) > 20 {
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("导航页标题不能超过 20 个字符"))
				return
			}
			s.cfg.Hook.Title = title
			s.persistConfig("hook.title", title)
		}
		if req.Hook.SearchEngine != nil {
			se := strings.ToLower(strings.TrimSpace(*req.Hook.SearchEngine))
			switch se {
			case "bing", "google", "bilibili", "douyin":
			default:
				s.cfgMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("不支持的搜索引擎"))
				return
			}
			s.cfg.Hook.SearchEngine = se
			s.persistConfig("hook.search_engine", se)
		}
		if req.Hook.ShowSearch != nil {
			s.cfg.Hook.ShowSearch = *req.Hook.ShowSearch
			s.persistConfig("hook.show_search", *req.Hook.ShowSearch)
		}
		if req.Hook.ShowWebhook != nil {
			s.cfg.Hook.ShowWebhook = *req.Hook.ShowWebhook
			s.persistConfig("hook.show_webhook", *req.Hook.ShowWebhook)
		}
		if req.Hook.ShowForwards != nil {
			s.cfg.Hook.ShowForwards = *req.Hook.ShowForwards
			s.persistConfig("hook.show_forwards", *req.Hook.ShowForwards)
		}
		if req.Hook.ShowProxies != nil {
			s.cfg.Hook.ShowProxies = *req.Hook.ShowProxies
			s.persistConfig("hook.show_proxies", *req.Hook.ShowProxies)
		}
		if req.Hook.AdminPass != nil {
			ap := strings.TrimSpace(*req.Hook.AdminPass)
			if ap != "" {
				if len([]rune(ap)) < 6 || len([]rune(ap)) > 64 {
					s.cfgMu.Unlock()
					s.writeJSON(w, http.StatusBadRequest, apiErr("管理密码长度需为 6-64 位"))
					return
				}
				s.cfg.Hook.AdminPass = ap
				s.persistConfig("hook.admin_pass", ap)
			}
			// 空值表示不修改，保持当前密码
		}
	}
	s.cfgMu.Unlock()

	// Webhook 端口变更后重建独立监听（接收上报 + 通道访问入口），
	// 并同步已有 frpc 域名代理的回落端口到新端口
	if whPortChanged {
		s.restartWhListener()
		s.syncWhDomainProxyPort(whOldPort, whNewPort)
	}
	// 系统访问域名/地址模式变更后自动同步 frpc 域名代理（实时生效）
	if domainChanged {
		s.syncSystemDomainProxy(whOldDomain, whNewDomain)
	}

	// 配置写完后重载禁止列表（loadBlocklist 内部会自行加锁）
	if req.IPFilter != nil {
		s.loadBlocklist()
	}

	s.logger.Info("Settings updated")

	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"close_disabled": closeDisabled}))
}

// validIPOrCIDR 校验输入是否为合法 IP 或 CIDR 网段。
func validIPOrCIDR(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}

// handleAddCustomIP 添加一条自定义 IP/网段并立即持久化、重载过滤规则。
func (s *Server) handleAddCustomIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	ip := strings.TrimSpace(req.IP)
	if !validIPOrCIDR(ip) {
		s.writeJSON(w, http.StatusBadRequest, apiErr("IP 地址或网段格式无效"))
		return
	}
	if err := s.store.AddCustomIP(ip); err != nil {
		s.logger.Warn("添加自定义IP失败", zap.String("ip", ip), zap.Error(err))
		s.writeJSON(w, http.StatusInternalServerError, apiErr("添加失败"))
		return
	}
	s.loadBlocklist()
	s.writeJSON(w, http.StatusOK, apiOK(nil))
}

// handleDeleteCustomIP 删除一条自定义 IP/网段并立即持久化、重载过滤规则。
func (s *Server) handleDeleteCustomIP(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少 ip 参数"))
		return
	}
	if err := s.store.DeleteCustomIP(ip); err != nil {
		s.logger.Warn("删除自定义IP失败", zap.String("ip", ip), zap.Error(err))
		s.writeJSON(w, http.StatusInternalServerError, apiErr("删除失败"))
		return
	}
	s.loadBlocklist()
	s.writeJSON(w, http.StatusOK, apiOK(nil))
}

// handleSetIPFilterEnabled 即时保存 IP 过滤开关状态并重载过滤规则。
// 白名单模式下开启拦截前会校验当前客户端 IP 是否会被放行，避免用户把自己锁在门外。
func (s *Server) handleSetIPFilterEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if req.Enabled {
		s.cfgMu.RLock()
		mode := s.cfg.IPFilter.Mode
		s.cfgMu.RUnlock()
		if mode == "whitelist" && !s.isAllowedInWhitelistMode(net.ParseIP(clientIP(r))) {
			s.writeJSON(w, http.StatusForbidden, apiErr("当前 IP 不在白名单中：白名单模式下开启拦截后将无法访问本页面，已拒绝开启。请先把当前 IP 加入白名单，或开启「局域网地址放行」后再试。"))
			return
		}
	}
	s.cfgMu.Lock()
	s.cfg.IPFilter.Enabled = req.Enabled
	s.persistConfig("ip_filter.enabled", req.Enabled)
	s.cfgMu.Unlock()
	s.loadBlocklist()
	s.logger.Info("IP过滤开关已保存", zap.Bool("enabled", req.Enabled))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"enabled": req.Enabled}))
}

// handleSetIPFilterMode 保存 IP 过滤模式（blacklist 黑名单 / whitelist 白名单）。
// 过滤已开启时切换到白名单模式会先校验当前客户端 IP，避免用户把自己锁在门外。
func (s *Server) handleSetIPFilterMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if req.Mode != "blacklist" && req.Mode != "whitelist" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的过滤模式"))
		return
	}
	if req.Mode == "whitelist" {
		s.cfgMu.RLock()
		enabled := s.cfg.IPFilter.Enabled
		s.cfgMu.RUnlock()
		if enabled && !s.isAllowedInWhitelistMode(net.ParseIP(clientIP(r))) {
			s.writeJSON(w, http.StatusForbidden, apiErr("当前 IP 不在白名单中：切换为白名单模式后将无法访问本页面，已拒绝切换。请先把当前 IP 加入白名单，或开启「局域网地址放行」后再试。"))
			return
		}
	}
	s.cfgMu.Lock()
	s.cfg.IPFilter.Mode = req.Mode
	s.persistConfig("ip_filter.mode", req.Mode)
	s.cfgMu.Unlock()
	s.logger.Info("IP过滤模式已保存", zap.String("mode", req.Mode))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"mode": req.Mode}))
}

// handleSetIPFilterAllowLAN 保存「局域网地址放行」开关（默认开启）。
func (s *Server) handleSetIPFilterAllowLAN(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	s.cfgMu.Lock()
	s.cfg.IPFilter.AllowLAN = req.Enabled
	s.persistConfig("ip_filter.allow_lan", req.Enabled)
	s.cfgMu.Unlock()
	s.logger.Info("IP过滤局域网放行开关已保存", zap.Bool("enabled", req.Enabled))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"enabled": req.Enabled}))
}

// ============= IP 过滤：白名单 / 拦截记录 =============

// handleListWhitelist 返回全部白名单 IP/网段。
func (s *Server) handleListWhitelist(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListWhitelistIPs()
	if err != nil {
		s.logger.Warn("读取白名单失败", zap.Error(err))
		s.writeJSON(w, http.StatusInternalServerError, apiErr("读取失败"))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"ips": list}))
}

// handleAddWhitelist 添加一条白名单 IP/网段并立即重载过滤规则。
func (s *Server) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	ip := strings.TrimSpace(req.IP)
	if !validIPOrCIDR(ip) {
		s.writeJSON(w, http.StatusBadRequest, apiErr("IP 地址或网段格式无效"))
		return
	}
	if err := s.store.AddWhitelistIP(ip); err != nil {
		s.logger.Warn("添加白名单IP失败", zap.String("ip", ip), zap.Error(err))
		s.writeJSON(w, http.StatusInternalServerError, apiErr("添加失败"))
		return
	}
	s.loadBlocklist()
	s.writeJSON(w, http.StatusOK, apiOK(nil))
}

// handleDeleteWhitelist 删除一条白名单 IP/网段并立即重载过滤规则。
func (s *Server) handleDeleteWhitelist(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少 ip 参数"))
		return
	}
	if err := s.store.DeleteWhitelistIP(ip); err != nil {
		s.logger.Warn("删除白名单IP失败", zap.String("ip", ip), zap.Error(err))
		s.writeJSON(w, http.StatusInternalServerError, apiErr("删除失败"))
		return
	}
	s.loadBlocklist()
	s.writeJSON(w, http.StatusOK, apiOK(nil))
}

// handleListBlocked 返回自动记录的被拦截 IP 列表。
func (s *Server) handleListBlocked(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListBlockedIPs()
	if err != nil {
		s.logger.Warn("读取拦截记录失败", zap.Error(err))
		s.writeJSON(w, http.StatusInternalServerError, apiErr("读取失败"))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"ips": list}))
}

// handleDeleteBlocked 删除一条（带 ip 参数）或清空（不带参数）拦截记录。
func (s *Server) handleDeleteBlocked(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		if err := s.store.ClearBlockedIPs(); err != nil {
			s.logger.Warn("清空拦截记录失败", zap.Error(err))
			s.writeJSON(w, http.StatusInternalServerError, apiErr("清空失败"))
			return
		}
	} else {
		if err := s.store.DeleteBlockedIP(ip); err != nil {
			s.logger.Warn("删除拦截记录失败", zap.String("ip", ip), zap.Error(err))
			s.writeJSON(w, http.StatusInternalServerError, apiErr("删除失败"))
			return
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(nil))
}

// handleSetAutoRecord 保存「自动记录被拦截 IP」开关并立即生效。
func (s *Server) handleSetAutoRecord(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	val := "0"
	if req.Enabled {
		val = "1"
	}
	if err := s.store.SetSetting("ip_filter.auto_record", val); err != nil {
		s.logger.Warn("保存自动记录开关失败", zap.Error(err))
		s.writeJSON(w, http.StatusInternalServerError, apiErr("保存失败"))
		return
	}
	s.ipFilterAutoRecordMu.Lock()
	s.ipFilterAutoRecord = req.Enabled
	s.ipFilterAutoRecordMu.Unlock()
	s.logger.Info("自动记录被拦截IP开关已保存", zap.Bool("enabled", req.Enabled))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"enabled": req.Enabled}))
}

// ============= IP 归属地数据库 =============

// geoAutoUpdateKey 保存归属地数据自动更新间隔（小时）的设置键。
const geoAutoUpdateKey = "geoloc.auto_update_hours"

// defaultGeoAutoUpdateHours 自动更新间隔默认值（小时），0 表示关闭自动更新。
const defaultGeoAutoUpdateHours = 24

// geoAutoUpdateHours 读取自动更新间隔（小时），失败时返回默认值。
func (s *Server) geoAutoUpdateHours() int {
	v, err := s.store.GetSetting(geoAutoUpdateKey)
	if err != nil || v == "" {
		return defaultGeoAutoUpdateHours
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return defaultGeoAutoUpdateHours
	}
	return n
}

// handleGeoStats 返回归属地数据库统计信息与自动更新配置。
func (s *Server) handleGeoStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{}
	if s.geo != nil {
		for k, v := range s.geo.Stats() {
			stats[k] = v
		}
		if total, err := s.geo.TotalIPCount(); err == nil {
			stats["total_ips"] = total
		}
	}
	stats["auto_update_hours"] = s.geoAutoUpdateHours()
	s.writeJSON(w, http.StatusOK, apiOK(stats))
}

// handleGeoLookup 查询单个 IP 的归属地/运营商信息。
func (s *Server) handleGeoLookup(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少 ip 参数"))
		return
	}
	location := ""
	ready := false
	if s.geo != nil {
		ready = s.geo.Ready()
		if ready {
			location = s.geo.Lookup(ip)
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"ip":       ip,
		"location": location,
		"ready":    ready,
	}))
}

// handleGeoRegions 返回 IP 地址库全部地区（按分类、归属名称聚合），供白/黑名单从地区批量添加。
func (s *Server) handleGeoRegions(w http.ResponseWriter, r *http.Request) {
	regions, err := s.store.ListGeoRegions()
	if err != nil {
		s.logger.Warn("读取IP地址库地区列表失败", zap.Error(err))
		s.writeJSON(w, http.StatusInternalServerError, apiErr("读取IP地址库地区列表失败"))
		return
	}
	for i := range regions {
		regions[i].Label = geoloc.CategoryLabels[regions[i].Category]
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"regions": regions}))
}

// handleAddRegionToIPFilter 把 IP 地址库中的地区作为规则直接加入白名单（whitelist）或
// 黑名单（blacklist）：匹配时按请求 IP 的归属地判定，不再展开为具体网段条目。
func (s *Server) handleAddRegionToIPFilter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		List     string `json:"list"`     // whitelist | blacklist
		Category string `json:"category"` // country/province/city/isp/cloud…
		Name     string `json:"name"`     // 归属名称
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.List = strings.TrimSpace(req.List)
	req.Category = strings.TrimSpace(req.Category)
	req.Name = strings.TrimSpace(req.Name)
	if req.List != "whitelist" && req.List != "blacklist" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的名单类型"))
		return
	}
	if req.Category == "" || req.Name == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少地区参数"))
		return
	}
	// 确认地址库中确实存在该地区
	ranges, err := s.store.LoadGeoRangesByRegion(req.Category, req.Name)
	if err != nil {
		s.logger.Warn("读取地区IP段失败", zap.String("category", req.Category), zap.String("name", req.Name), zap.Error(err))
		s.writeJSON(w, http.StatusInternalServerError, apiErr("读取地区IP段失败"))
		return
	}
	if len(ranges) == 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("IP 地址库中未找到该地区"))
		return
	}
	rule := config.RegionRule{Category: req.Category, Name: req.Name}
	s.cfgMu.Lock()
	var regions []config.RegionRule
	key := ""
	if req.List == "whitelist" {
		regions = s.cfg.IPFilter.WhitelistRegions
		key = "ip_filter.whitelist_regions"
	} else {
		regions = s.cfg.IPFilter.BlacklistRegions
		key = "ip_filter.blacklist_regions"
	}
	added := 0
	dup := false
	for _, rg := range regions {
		if rg.Category == rule.Category && rg.Name == rule.Name {
			dup = true
			break
		}
	}
	if !dup {
		regions = append(regions, rule)
		added = 1
	}
	if req.List == "whitelist" {
		s.cfg.IPFilter.WhitelistRegions = regions
	} else {
		s.cfg.IPFilter.BlacklistRegions = regions
	}
	s.persistConfig(key, regions)
	s.cfgMu.Unlock()
	s.logger.Info("已把地区加入IP过滤名单",
		zap.String("list", req.List), zap.String("category", req.Category),
		zap.String("name", req.Name), zap.Int("added", added))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"list":     req.List,
		"category": req.Category,
		"name":     req.Name,
		"added":    added,
	}))
}

// handleDeleteRegionFromIPFilter 从白名单/黑名单中移除一个地区规则。
func (s *Server) handleDeleteRegionFromIPFilter(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	list := strings.TrimSpace(q.Get("list"))
	category := strings.TrimSpace(q.Get("category"))
	name := strings.TrimSpace(q.Get("name"))
	if list != "whitelist" && list != "blacklist" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的名单类型"))
		return
	}
	if category == "" || name == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少地区参数"))
		return
	}
	s.cfgMu.Lock()
	var regions []config.RegionRule
	key := ""
	if list == "whitelist" {
		regions = s.cfg.IPFilter.WhitelistRegions
		key = "ip_filter.whitelist_regions"
	} else {
		regions = s.cfg.IPFilter.BlacklistRegions
		key = "ip_filter.blacklist_regions"
	}
	removed := 0
	out := regions[:0]
	for _, rg := range regions {
		if rg.Category == category && rg.Name == name {
			removed++
			continue
		}
		out = append(out, rg)
	}
	if list == "whitelist" {
		s.cfg.IPFilter.WhitelistRegions = out
	} else {
		s.cfg.IPFilter.BlacklistRegions = out
	}
	s.persistConfig(key, out)
	s.cfgMu.Unlock()
	s.logger.Info("已从IP过滤名单移除地区",
		zap.String("list", list), zap.String("category", category), zap.String("name", name))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"list":     list,
		"category": category,
		"name":     name,
		"removed":  removed,
	}))
}

// handleGeoUpdate 手动全量更新归属地数据（先同步目录，再异步下载全部启用源，立即返回）。
func (s *Server) handleGeoUpdate(w http.ResponseWriter, r *http.Request) {
	if s.geo == nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("归属地服务未初始化"))
		return
	}
	if s.geo.Updating() {
		s.writeJSON(w, http.StatusOK, apiErr("数据正在更新中，请稍候"))
		return
	}
	go func() {
		if _, err := s.geoCatalog.Refresh(s.stopCtx); err != nil {
			s.logger.Warn("IP段数据源目录刷新失败", zap.Error(err))
		}
		if err := s.geo.Update(s.stopCtx); err != nil {
			s.logger.Warn("IP归属地数据手动更新失败", zap.Error(err))
		} else {
			s.logger.Info("IP归属地数据手动更新完成")
		}
	}()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"started": true}))
}

// handleGeoSources 返回数据源目录列表（弹窗展示：ID/类别/分类/IP数量/更新时间）。
func (s *Server) handleGeoSources(w http.ResponseWriter, r *http.Request) {
	sources, err := s.store.ListGeoSources()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("读取数据源列表失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"sources": sources,
		"total":   len(sources),
	}))
}

// handleGeoImport 导入本地 IP 段数据文件（文本：CIDR / ip2region 管道 / 起始IP-结束IP 名称），
// 解析后按 (category, class) 落库为数据源并覆盖其 IP 段，供查询与公网 IP 过滤使用。
func (s *Server) handleGeoImport(w http.ResponseWriter, r *http.Request) {
	if s.geo == nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("归属地服务未初始化"))
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("读取上传内容失败: "+err.Error()))
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请选择要导入的数据文件"))
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 64<<20))
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("读取文件失败: "+err.Error()))
		return
	}
	category := strings.TrimSpace(r.FormValue("category"))
	class := strings.TrimSpace(r.FormValue("class"))
	name := strings.TrimSpace(r.FormValue("name"))
	switch category {
	case "country", "china", "province", "city", "isp", "cloud":
	default:
		s.writeJSON(w, http.StatusBadRequest, apiErr("类别必须为 country/china/province/city/isp/cloud 之一"))
		return
	}
	if class == "" || name == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请填写分类与归属名称"))
		return
	}
	ranges, skipped, err := geoloc.ParseData(string(data), category, name, class)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	sourceID, err := s.store.UpsertGeoSource(store.GeoSource{
		Category:  category,
		Class:     class,
		Name:      name,
		URL:       "本地导入",
		IPCount:   geoloc.CountIPAddresses(ranges),
		UpdatedAt: time.Now().Format("2006-01-02 15:04:05"),
		Enabled:   true,
		Status:    "ok",
		LastCheck: time.Now().Format("2006-01-02 15:04:05"),
	})
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("保存数据源失败: "+err.Error()))
		return
	}
	if err := s.store.ReplaceGeoRangesBySource(sourceID, ranges); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("写入 IP 段失败: "+err.Error()))
		return
	}
	// 重建内存索引，使导入数据立即生效
	go func() { s.geo.Load() }()
	s.logger.Info("IP段数据导入完成",
		zap.String("category", category), zap.String("class", class),
		zap.Int("ranges", len(ranges)), zap.Int64("skipped", skipped))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"source_id": sourceID,
		"imported":  len(ranges),
		"skipped":   skipped,
		"ip_count":  geoloc.CountIPAddresses(ranges),
	}))
}

// handleGeoSourcesUpdate 增量更新：仅更新选中的数据源（异步执行，立即返回）。
func (s *Server) handleGeoSourcesUpdate(w http.ResponseWriter, r *http.Request) {
	if s.geo == nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("归属地服务未初始化"))
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if s.geo.Updating() {
		s.writeJSON(w, http.StatusOK, apiErr("数据正在更新中，请稍候"))
		return
	}
	go func() {
		if err := s.geo.UpdateSources(s.stopCtx, req.IDs); err != nil {
			s.logger.Warn("IP段增量更新失败", zap.Error(err))
		} else {
			s.logger.Info("IP段增量更新完成", zap.Int("sources", len(req.IDs)))
		}
	}()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"started": true}))
}

// handleGeoToggleSource 启用/停用数据源。
func (s *Server) handleGeoToggleSource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      int64 `json:"id"`
		Enabled bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if err := s.store.SetGeoSourceEnabled(req.ID, req.Enabled); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("保存失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"id": req.ID, "enabled": req.Enabled}))
}

// handleGeoCatalogRefresh 手动刷新数据源目录并检测链接有效性（异步执行，立即返回）。
func (s *Server) handleGeoCatalogRefresh(w http.ResponseWriter, r *http.Request) {
	if s.geoCatalog == nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("目录服务未初始化"))
		return
	}
	go func() {
		n, err := s.geoCatalog.Refresh(s.stopCtx)
		if err != nil {
			s.logger.Warn("IP段数据源目录刷新失败", zap.Error(err))
			return
		}
		if _, failed, err := s.geoCatalog.CheckLinks(s.stopCtx); err != nil {
			s.logger.Warn("IP段数据源链接检测失败", zap.Error(err))
		} else if failed > 0 {
			s.logger.Warn("存在无效的数据源链接", zap.Int("failed", failed))
		}
		s.logger.Info("IP段数据源目录手动刷新完成", zap.Int("sources", n))
	}()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"started": true}))
}

// handleGeoAutoUpdate 保存归属地数据自动更新间隔（小时），0 表示关闭。
func (s *Server) handleGeoAutoUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hours *int `json:"hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Hours == nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	hours := *req.Hours
	if hours < 0 {
		hours = 0
	}
	if err := s.store.SetSetting(geoAutoUpdateKey, strconv.Itoa(hours)); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("保存失败"))
		return
	}
	s.logger.Info("归属地数据自动更新间隔已保存", zap.Int("hours", hours))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"hours": hours}))
}

func (s *Server) handleLogCleanup(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") == "true"

	s.cfgMu.RLock()
	expireDays := s.cfg.Log.ExpireDays
	s.cfgMu.RUnlock()

	s.logBuf.mu.Lock()
	var removed int
	if all {
		removed = len(s.logBuf.entries)
		s.logBuf.entries = s.logBuf.entries[:0]
	} else {
		cutoff := time.Now().AddDate(0, 0, -expireDays)
		var kept []LogEntry
		for _, e := range s.logBuf.entries {
			t, err := time.Parse("2006-01-02 15:04:05", e.Time)
			if err != nil || t.After(cutoff) {
				kept = append(kept, e)
			}
		}
		removed = len(s.logBuf.entries) - len(kept)
		s.logBuf.entries = kept
	}
	remaining := len(s.logBuf.entries)
	s.logBuf.mu.Unlock()

	s.logger.Info("Log cleanup done", zap.Int("removed", removed), zap.Int("remaining", remaining))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"removed":   removed,
		"remaining": remaining,
	}))
}

// ============= Forward =============

// validPathPrefix 校验统一网关的后端路径前缀：为空或必须以 / 开头，且不含
// 空格与 URL 不安全字符（?、#、\ 等）。具体规范化由转发器内部完成。
func validPathPrefix(p string) bool {
	if p == "" {
		return true
	}
	if !strings.HasPrefix(p, "/") {
		return false
	}
	for _, c := range p {
		if c == ' ' || c == '\\' || c == '?' || c == '#' {
			return false
		}
	}
	return true
}

// probeAbsURLRe 匹配 HTML 中 src/href/action/poster 的根相对路径（/xxx/...）。
var probeAbsURLRe = regexp.MustCompile(`(?:src|href|action|poster)\s*=\s*["'](/(?:[^"'#?]*))["']`)

// probeScriptSrcRe 匹配 HTML 中 <script src="..."> 的脚本地址（自动检测时抓取分析 JS 内的根相对接口）。
var probeScriptSrcRe = regexp.MustCompile(`<script[^>]+src\s*=\s*["']([^"']+)["']`)

// probeRootPathRe 匹配 JS 中引号包裹的根相对路径（"/api/xxx"、'/api/xxx'）。
var probeRootPathRe = regexp.MustCompile(`["'](/(?:[a-zA-Z0-9_-]{2,32})(?:/[^"'?]*)?)["']`)

// probeTplPathRe 匹配 JS 模板字符串内拼在表达式之后的根相对路径（如 `${BASE_URL}/ping` 中的 /ping）。
var probeTplPathRe = regexp.MustCompile("`[^`]{0,600}?\\$[^`}]*}\\s*(/(?:[a-zA-Z0-9_-]{2,32})(?:/[^\"'`?]*)?)")

// isResourceRoot 判定根路径首段是否为静态资源/构建目录。
// 这类前缀不是“应用部署路径前缀”（sourcePrefix），不应被自动检测当作应用前缀。
func isResourceRoot(first string) bool {
	switch first {
	case "_next", "static", "assets", "build", "dist", "media", "images", "img", "css", "js", "fonts", "icons", "favicon", "uploads", "files", "resources":
		return true
	}
	return false
}

// handleForwardProbe 自动探测统一网关远端服务的路径前缀：
// 请求远端根路径（跟随重定向）抓取首页 HTML，分析其中绝对资源路径的公共前缀，
// 作为「源路径前缀」建议；若最终访问路径部署在 /app/ 子路径下，同时给出
// 「后端路径前缀」建议；并抓取主要脚本分析根相对接口前缀，给出「根相对路径前缀」建议。
// 供创建/编辑网关转发规则时一键回填。
func (s *Server) handleForwardProbe(w http.ResponseWriter, r *http.Request) {
	remote := strings.TrimSpace(r.URL.Query().Get("remote"))
	if remote == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少 remote 参数（格式 host:port）"))
		return
	}
	base := strings.TrimSpace(r.URL.Query().Get("base"))
	if base == "" {
		base = "/"
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get("http://" + remote + base)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"error": "无法连接远端服务: " + err.Error()}))
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))

	finalPath := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalPath = resp.Request.URL.Path
	}
	sourcePrefix := detectSourcePrefix(string(body))
	pathPrefix := ""
	if finalPath != "" && finalPath != "/" {
		p := strings.TrimRight(finalPath, "/")
		// 仅当部署在 /app/ 子路径下才给出后端前缀建议，避免 /login 等误判
		if strings.HasPrefix(p, "/app/") {
			pathPrefix = p
		}
	}
	// 抓取首页主要脚本，分析 JS 内根相对接口前缀（如 /api、/_next）
	jsBody := ""
	jsLimit := 0
	for _, m := range probeScriptSrcRe.FindAllStringSubmatch(string(body), -1) {
		if len(m) != 2 {
			continue
		}
		src := m[1]
		if !strings.HasPrefix(src, "/") || strings.HasPrefix(src, "//") {
			continue
		}
		if jsLimit >= 15 {
			break // 最多抓取 15 个脚本，避免探测过慢
		}
		resp2, err := client.Get("http://" + remote + src)
		if err != nil {
			continue
		}
		b2, _ := io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
		resp2.Body.Close()
		if len(jsBody)+len(b2) > 4<<20 {
			break // 累计脚本大小上限 4MB
		}
		jsBody += string(b2)
		jsLimit++
	}
	rootPrefixes := detectRootPrefixes(string(body), jsBody)
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"base_url":      "http://" + remote + base,
		"final_path":    finalPath,
		"source_prefix": sourcePrefix,
		"path_prefix":   pathPrefix,
		"root_prefixes": rootPrefixes,
	}))
}

// detectSourcePrefix 从 HTML 中提取全部绝对资源路径，按 "/" 分段求公共前缀；
// 无资源引用或公共前缀为空/为无关根前缀（/api、/login 等）时返回空串（按根路径处理）。
func detectSourcePrefix(html string) string {
	var paths []string
	for _, m := range probeAbsURLRe.FindAllStringSubmatch(html, -1) {
		if len(m) == 2 && len(m[1]) > 1 && !strings.HasPrefix(m[1], "//") {
			paths = append(paths, m[1])
		}
	}
	if len(paths) == 0 {
		return ""
	}
	segs := strings.Split(strings.Trim(paths[0], "/"), "/")
	for _, p := range paths[1:] {
		s2 := strings.Split(strings.Trim(p, "/"), "/")
		n := len(segs)
		if len(s2) < n {
			n = len(s2)
		}
		i := 0
		for i < n && segs[i] == s2[i] {
			i++
		}
		segs = segs[:i]
	}
	if len(segs) == 0 {
		return ""
	}
	out := "/" + strings.Join(segs, "/")
	// 过滤常见的无关根前缀，避免把 /api、/static 等误判为应用路径
	for _, bad := range []string{"/api", "/login", "/static", "/assets", "/favicon", "/js", "/css"} {
		if out == bad {
			return ""
		}
	}
	// 首段为静态资源/构建目录（/_next、/static、/assets 等）时也不是应用部署前缀，
	// 避免把 Next.js 等框架的资源目录误判为「源路径前缀」
	if isResourceRoot(segs[0]) {
		return ""
	}
	return out
}

// detectRootPrefixes 自动分析首页 HTML 的资源路径与主要 JS 内的根相对路径，
// 提取出现次数较多的根路径首段前缀（如 /api、/_next），供网关「根相对路径前缀」配置，
// 使前端硬编码的根相对接口/资源在代理子路径下被改写为网关路径。
func detectRootPrefixes(html, jsBody string) string {
	counts := map[string]int{}
	collect := func(s string, res ...*regexp.Regexp) {
		for _, re := range res {
			for _, m := range re.FindAllStringSubmatch(s, -1) {
				if len(m) != 2 {
					continue
				}
				p := m[1]
				if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
					continue
				}
				segs := strings.Split(strings.Trim(p, "/"), "/")
				if len(segs) == 0 || len(segs[0]) < 2 {
					continue // 跳过空/单字符首段（如 /a、/x），避免误匹配
				}
				counts["/"+segs[0]]++
			}
		}
	}
	collect(html, probeAbsURLRe)
	if jsBody != "" {
		collect(jsBody, probeRootPathRe, probeTplPathRe)
	}
	var out []string
	for p, n := range counts {
		if n < 2 {
			continue // 出现次数太少，可能是误匹配，不建议自动配置
		}
		switch p {
		case "/login", "/logout", "/favicon", "/error", "/notfound", "/not-found", "/404":
			continue // 登录/错误页等跳转路径，不应改写
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func (s *Server) handleForwardStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Protocol     string `json:"protocol"`
		LocalAddr    string `json:"local_addr"`
		LocalPort    int    `json:"local_port"`
		RemoteAddr   string `json:"remote_addr"`
		RemotePort   int    `json:"remote_port"`
		Domain       string `json:"domain"`
		Name         string `json:"name"`
		SourcePrefix string `json:"source_prefix"`
		RootPrefixes string `json:"root_prefixes"`
		PathPrefix   string `json:"path_prefix"`
		AutoDetect   bool   `json:"auto_detect"`
		Description  string `json:"description"`
		CertPEM      string `json:"cert_pem"`
		KeyPEM       string `json:"key_pem"`
		TLSEnable    bool   `json:"tls_enable"`
		// 进阶/日志设置
		RateLimit         int    `json:"rate_limit"`
		MaxConnections    int    `json:"max_connections"`
		ProxyProtocol     bool   `json:"proxy_protocol"`
		TLSSource         bool   `json:"tls_source"`
		UDPSessionTimeout int    `json:"udp_session_timeout"`
		UDPMaxSessions    int    `json:"udp_max_sessions"`
		UDPMaxBlockLen    int    `json:"udp_max_block_len"`
		LogLevel          string `json:"log_level"`
		ChannelLogEntries int    `json:"channel_log_entries"`
		AccessLogEntries  int    `json:"access_log_entries"`
		LogRetentionHours int    `json:"log_retention_hours"`
		// 进阶设置（访问链接配置）
		CustomID       string `json:"custom_id"`
		CustomDomain   string `json:"custom_domain"`
		LinkKey        string `json:"link_key"`
		AccessPassword string `json:"access_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if req.LocalAddr == "" {
		req.LocalAddr = "0.0.0.0"
	}
	// 开启 HTTPS（自签名证书）仅适用于 TCP（TLS 只能承载于 TCP 之上）
	if req.TLSEnable && !strings.EqualFold(req.Protocol, "tcp") {
		s.writeJSON(w, http.StatusOK, apiErr("开启 HTTPS（自签名证书）仅支持 TCP 协议"))
		return
	}
	// HTTP/HTTPS 协议默认使用系统设置的默认端口（隐藏监听端口输入时使用）
	s.cfgMu.RLock()
	httpDefaultPort := s.cfg.Forward.HTTPDefaultPort
	httpsDefaultPort := s.cfg.Forward.HTTPSDefaultPort
	s.cfgMu.RUnlock()
	if (req.Protocol == "http" || req.Protocol == "HTTP") && req.LocalPort == 0 {
		req.LocalPort = httpDefaultPort
	}
	if (req.Protocol == "https" || req.Protocol == "HTTPS") && req.LocalPort == 0 {
		req.LocalPort = httpsDefaultPort
	}
	// HTTP/HTTPS 协议必须提供域名
	if (req.Protocol == "http" || req.Protocol == "HTTP" || req.Protocol == "https" || req.Protocol == "HTTPS") && req.Domain == "" {
		s.writeJSON(w, http.StatusOK, apiErr("HTTP/HTTPS 协议必须提供域名"))
		return
	}
	// 统一网关模式必须提供子路径名称（不监听本地端口）
	if (req.Protocol == "gateway" || req.Protocol == "GATEWAY") && req.Name == "" {
		s.writeJSON(w, http.StatusOK, apiErr("统一网关模式必须填写路径名称"))
		return
	}
	// 统一网关模式的后端路径前缀必须以 / 开头
	if (req.Protocol == "gateway" || req.Protocol == "GATEWAY") && !validPathPrefix(req.PathPrefix) {
		s.writeJSON(w, http.StatusOK, apiErr("后端路径前缀必须以 / 开头（如 /app/canvasboard）"))
		return
	}
	// HTTPS 转发：未提供证书时优先从证书库匹配（精确或通配域名），无需重复粘贴证书
	if (req.Protocol == "https" || req.Protocol == "HTTPS") && req.CertPEM == "" {
		if rec, err := forward.FindCertificateForDomain(s.store, req.Domain); err == nil && rec != nil {
			req.CertPEM = rec.CertPEM
			req.KeyPEM = rec.KeyPEM
		}
	}
	// 进阶设置校验：自定义ID（仅字母/数字）、自定义域名格式、链接密钥/访问密码长度、日志存储时间范围
	req.CustomID = strings.TrimSpace(req.CustomID)
	req.CustomDomain = strings.TrimSpace(req.CustomDomain)
	req.LinkKey = strings.TrimSpace(req.LinkKey)
	if req.CustomID != "" && !validCustomID(req.CustomID) {
		s.writeJSON(w, http.StatusOK, apiErr("自定义ID仅支持字母和数字（不区分大小写）"))
		return
	}
	if req.CustomDomain != "" && !validDomain(req.CustomDomain) {
		s.writeJSON(w, http.StatusOK, apiErr("自定义域名格式无效，例如 web.example.com"))
		return
	}
	if len([]rune(req.LinkKey)) > 64 {
		s.writeJSON(w, http.StatusOK, apiErr("链接密钥长度不能超过 64 个字符"))
		return
	}
	if len([]rune(req.AccessPassword)) > 128 {
		s.writeJSON(w, http.StatusOK, apiErr("访问密码长度不能超过 128 个字符"))
		return
	}
	if req.LogRetentionHours < 0 || req.LogRetentionHours > 87600 {
		s.writeJSON(w, http.StatusOK, apiErr("日志存储时间必须在 0-87600 小时（0=跟随全局）"))
		return
	}
	rule := config.ForwardRule{
		Protocol:     req.Protocol,
		LocalAddr:    req.LocalAddr,
		LocalPort:    req.LocalPort,
		RemoteAddr:   req.RemoteAddr,
		RemotePort:   req.RemotePort,
		Domain:       req.Domain,
		Name:         req.Name,
		SourcePrefix: req.SourcePrefix,
		RootPrefixes: req.RootPrefixes,
		PathPrefix:   req.PathPrefix,
		AutoDetect:   req.AutoDetect,
		CertPEM:      req.CertPEM,
		KeyPEM:       req.KeyPEM,
		TLSEnable:    req.TLSEnable,
		// 进阶/日志设置
		RateLimit:         req.RateLimit,
		MaxConnections:    req.MaxConnections,
		ProxyProtocol:     req.ProxyProtocol,
		TLSSource:         req.TLSSource,
		UDPSessionTimeout: req.UDPSessionTimeout,
		UDPMaxSessions:    req.UDPMaxSessions,
		UDPMaxBlockLen:    req.UDPMaxBlockLen,
		LogLevel:          req.LogLevel,
		ChannelLogEntries: req.ChannelLogEntries,
		AccessLogEntries:  req.AccessLogEntries,
		LogRetentionHours: req.LogRetentionHours,
		CustomID:          req.CustomID,
		CustomDomain:      req.CustomDomain,
		LinkKey:           req.LinkKey,
		AccessPassword:    req.AccessPassword,
	}
	// 开启 HTTPS（自签名证书）需要真实转发：目标为本机且端口相同时属直连模式（无转发器），会导致回环
	if req.TLSEnable && forward.IsLocalDirectTarget(rule) {
		s.writeJSON(w, http.StatusOK, apiErr("开启 HTTPS（自签名证书）时目标不能为本机且与监听端口相同（直连模式）"))
		return
	}
	if err := s.fwdMgr.StartRule(rule); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	key := ruleKey(rule)
	s.setDescription("forward", key, req.Description)
	// 应用每规则日志配置（级别过滤 + 日志条数）
	s.forwardLogs.setRuleConfig(key, req.LogLevel, req.ChannelLogEntries, req.AccessLogEntries)
	// 自定义域名保存成功后，自动在内网穿透模块使用默认服务器创建对应代理通道（frpc HTTP 代理）
	if req.CustomDomain != "" {
		if err := s.ensureCustomDomainProxy(rule); err != nil {
			s.logger.Warn("自定义域名自动创建 frpc 代理失败",
				zap.String("domain", req.CustomDomain), zap.Error(err))
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.forwardToMap(key)))
}

func (s *Server) handleForwardStop(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if req.Key == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少 key 参数"))
		return
	}
	if isSystemForwardKey(req.Key) {
		s.writeJSON(w, http.StatusOK, apiErr("系统自动生成的转发不可删除，请在对应功能页面管理"))
		return
	}
	rule, err := parseRuleKey(req.Key)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	// 删除转发规则：无论是否运行中都停止并从存储移除，同时清理描述与桌面图标入口，
	// 否则已暂停/已停止的规则无法删除，且残留描述会让规则继续显示在列表中。
	s.fwdMgr.StopRule(rule)
	s.setDescription("forward", req.Key, "")
	// 规则删除时同步清理桌面图标入口
	s.deleteDeskConfig(req.Key)
	// 清理该规则的独立日志缓冲与累计流量基线
	s.forwardLogs.remove(req.Key)
	s.fwdTrafficBase.Delete(req.Key)
	s.writeJSON(w, http.StatusOK, apiMsg("转发已删除: "+req.Key))
}

func (s *Server) handleForwardUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key          string  `json:"key"`
		Description  string  `json:"description"`
		Protocol     string  `json:"protocol"`
		LocalAddr    *string `json:"local_addr"`
		LocalPort    *int    `json:"local_port"`
		RemoteAddr   string  `json:"remote_addr"`
		RemotePort   int     `json:"remote_port"`
		Domain       string  `json:"domain"`
		Name         string  `json:"name"`
		SourcePrefix *string `json:"source_prefix"`
		RootPrefixes *string `json:"root_prefixes"`
		PathPrefix   *string `json:"path_prefix"`
		AutoDetect   *bool   `json:"auto_detect"`
		CertPEM      string  `json:"cert_pem"`
		KeyPEM       string  `json:"key_pem"`
		TLSEnable    *bool   `json:"tls_enable"`
		// 进阶/日志设置（不在 key 中，需对比内存中的旧值；-1/缺失 表示不修改）
		RateLimit         *int    `json:"rate_limit"`
		MaxConnections    *int    `json:"max_connections"`
		ProxyProtocol     *bool   `json:"proxy_protocol"`
		TLSSource         *bool   `json:"tls_source"`
		UDPSessionTimeout *int    `json:"udp_session_timeout"`
		UDPMaxSessions    *int    `json:"udp_max_sessions"`
		UDPMaxBlockLen    *int    `json:"udp_max_block_len"`
		LogLevel          *string `json:"log_level"`
		ChannelLogEntries *int    `json:"channel_log_entries"`
		AccessLogEntries  *int    `json:"access_log_entries"`
		LogRetentionHours *int    `json:"log_retention_hours"`
		// 进阶设置（访问链接配置）
		CustomID       *string `json:"custom_id"`
		CustomDomain   *string `json:"custom_domain"`
		LinkKey        *string `json:"link_key"`
		AccessPassword *string `json:"access_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if req.Key == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少Key参数"))
		return
	}
	if isSystemForwardKey(req.Key) {
		s.writeJSON(w, http.StatusOK, apiErr("系统自动生成的转发不可编辑，请在对应功能页面管理"))
		return
	}

	oldRule, err := parseRuleKey(req.Key)
	if err == nil {
		changed := false
		newRule := oldRule
		// 源路径前缀/根路径前缀不在 key 中，从运行/缓存中取当前值，避免其它字段更新时丢失
		newRule.SourcePrefix = s.fwdMgr.SourcePrefix(req.Key)
		newRule.RootPrefixes = s.fwdMgr.RootPrefixes(req.Key)
		if req.Protocol != "" && req.Protocol != oldRule.Protocol {
			newRule.Protocol = req.Protocol
			changed = true
		}
		if req.LocalAddr != nil && *req.LocalAddr != oldRule.LocalAddr {
			v := *req.LocalAddr
			if v == "" {
				v = "0.0.0.0"
			}
			newRule.LocalAddr = v
			changed = true
		}
		if req.LocalPort != nil && *req.LocalPort != oldRule.LocalPort {
			newRule.LocalPort = *req.LocalPort
			changed = true
		}
		if req.RemoteAddr != "" && req.RemoteAddr != oldRule.RemoteAddr {
			newRule.RemoteAddr = req.RemoteAddr
			changed = true
		}
		if req.RemotePort > 0 && req.RemotePort != oldRule.RemotePort {
			newRule.RemotePort = req.RemotePort
			changed = true
		}
		if req.Domain != "" && req.Domain != oldRule.Domain {
			newRule.Domain = req.Domain
			changed = true
		}
		// 网关名称作为 key 的一部分不可修改；切换到统一网关时必须已有名称
		if req.Name != "" && req.Name != oldRule.Name {
			newRule.Name = req.Name
			changed = true
		}
		// 源路径前缀不在 key 中，需对比内存中的旧值（支持修改/清空）
		if req.SourcePrefix != nil && *req.SourcePrefix != s.fwdMgr.SourcePrefix(req.Key) {
			newRule.SourcePrefix = *req.SourcePrefix
			changed = true
		}
		// 根路径前缀列表不在 key 中，需对比内存中的旧值（支持修改/清空）
		if req.RootPrefixes != nil && *req.RootPrefixes != s.fwdMgr.RootPrefixes(req.Key) {
			newRule.RootPrefixes = *req.RootPrefixes
			changed = true
		}
		// 后端路径前缀不在 key 中，需对比内存中的旧值（支持修改/清空）
		if req.PathPrefix != nil && *req.PathPrefix != s.fwdMgr.PathPrefix(req.Key) {
			if !validPathPrefix(*req.PathPrefix) {
				s.writeJSON(w, http.StatusOK, apiErr("后端路径前缀必须以 / 开头（如 /app/canvasboard）"))
				return
			}
			newRule.PathPrefix = *req.PathPrefix
			changed = true
		}
		// 自动检测路径开关不在 key 中，需对比内存中的旧值（支持修改）
		if req.AutoDetect != nil && *req.AutoDetect != s.fwdMgr.AutoDetect(req.Key) {
			newRule.AutoDetect = *req.AutoDetect
			changed = true
		}
		// TCP+HTTPS 开关不在 key 中，需对比内存中的旧值（支持修改）
		if req.TLSEnable != nil && *req.TLSEnable != s.fwdMgr.IsTLS(req.Key) {
			newRule.TLSEnable = *req.TLSEnable
			changed = true
		}
		// 进阶/日志设置不在 key 中，需对比当前值（nil=不修改，-1 数字=不修改）
		cur := s.fwdAdvanced(req.Key)
		if req.RateLimit != nil && cur.RateLimit != *req.RateLimit {
			newRule.RateLimit = *req.RateLimit
			changed = true
		}
		if req.MaxConnections != nil && cur.MaxConnections != *req.MaxConnections {
			newRule.MaxConnections = *req.MaxConnections
			changed = true
		}
		if req.ProxyProtocol != nil && cur.ProxyProtocol != *req.ProxyProtocol {
			newRule.ProxyProtocol = *req.ProxyProtocol
			changed = true
		}
		if req.TLSSource != nil && cur.TLSSource != *req.TLSSource {
			newRule.TLSSource = *req.TLSSource
			changed = true
		}
		if req.UDPSessionTimeout != nil && cur.UDPSessionTimeout != *req.UDPSessionTimeout {
			newRule.UDPSessionTimeout = *req.UDPSessionTimeout
			changed = true
		}
		if req.UDPMaxSessions != nil && cur.UDPMaxSessions != *req.UDPMaxSessions {
			newRule.UDPMaxSessions = *req.UDPMaxSessions
			changed = true
		}
		if req.UDPMaxBlockLen != nil && cur.UDPMaxBlockLen != *req.UDPMaxBlockLen {
			newRule.UDPMaxBlockLen = *req.UDPMaxBlockLen
			changed = true
		}
		if req.LogLevel != nil && cur.LogLevel != *req.LogLevel {
			if !validLogLevel(*req.LogLevel) {
				s.writeJSON(w, http.StatusOK, apiErr("日志输出级别必须为 DEBUG/INFO/WARN/ERROR 之一"))
				return
			}
			newRule.LogLevel = *req.LogLevel
			changed = true
		}
		if req.ChannelLogEntries != nil && cur.ChannelLogEntries != *req.ChannelLogEntries {
			newRule.ChannelLogEntries = clampLogEntries(*req.ChannelLogEntries)
			changed = true
		}
		if req.AccessLogEntries != nil && cur.AccessLogEntries != *req.AccessLogEntries {
			newRule.AccessLogEntries = clampLogEntries(*req.AccessLogEntries)
			changed = true
		}
		// 进阶访问链接配置不在 key 中，从持久化记录取当前值（nil=不修改，支持清空）。
		// 先整体继承存储值，再按需覆盖，避免仅更新其它字段时这些字段被清空。
		stored, _ := s.store.GetForwardRule(req.Key)
		newRule.LogRetentionHours = stored.LogRetentionHours
		newRule.CustomID = stored.CustomID
		newRule.CustomDomain = stored.CustomDomain
		newRule.LinkKey = stored.LinkKey
		newRule.AccessPassword = stored.AccessPassword
		if req.LogRetentionHours != nil {
			h := *req.LogRetentionHours
			if h < 0 || h > 87600 {
				s.writeJSON(w, http.StatusOK, apiErr("日志存储时间必须在 0-87600 小时（0=跟随全局）"))
				return
			}
			if stored.LogRetentionHours != h {
				newRule.LogRetentionHours = h
				changed = true
			}
		}
		if req.CustomID != nil {
			v := strings.TrimSpace(*req.CustomID)
			if v != "" && !validCustomID(v) {
				s.writeJSON(w, http.StatusOK, apiErr("自定义ID仅支持字母和数字（不区分大小写）"))
				return
			}
			if stored.CustomID != v {
				newRule.CustomID = v
				changed = true
			}
		}
		if req.CustomDomain != nil {
			v := strings.TrimSpace(*req.CustomDomain)
			if v != "" && !validDomain(v) {
				s.writeJSON(w, http.StatusOK, apiErr("自定义域名格式无效，例如 web.example.com"))
				return
			}
			if stored.CustomDomain != v {
				newRule.CustomDomain = v
				changed = true
			}
		}
		if req.LinkKey != nil {
			v := strings.TrimSpace(*req.LinkKey)
			if len([]rune(v)) > 64 {
				s.writeJSON(w, http.StatusOK, apiErr("链接密钥长度不能超过 64 个字符"))
				return
			}
			if stored.LinkKey != v {
				newRule.LinkKey = v
				changed = true
			}
		}
		if req.AccessPassword != nil {
			v := *req.AccessPassword
			if len([]rune(v)) > 128 {
				s.writeJSON(w, http.StatusOK, apiErr("访问密码长度不能超过 128 个字符"))
				return
			}
			if stored.AccessPassword != v {
				newRule.AccessPassword = v
				changed = true
			}
		}
		// 开启 HTTPS（自签名证书）仅适用于 TCP（TLS 只能承载于 TCP 之上）
		if newRule.TLSEnable && !strings.EqualFold(newRule.Protocol, "tcp") {
			s.writeJSON(w, http.StatusOK, apiErr("开启 HTTPS（自签名证书）仅支持 TCP 协议"))
			return
		}
		// HTTPS 证书：仅当提供新证书时更新；未提供时从持久化记录沿用原证书，
		// 保证域名/端口等变更时 TLS 证书不丢失；持久化记录为空时从证书库匹配。
		if req.CertPEM != "" || req.KeyPEM != "" {
			newRule.CertPEM = req.CertPEM
			newRule.KeyPEM = req.KeyPEM
			changed = true
		} else if strings.EqualFold(newRule.Protocol, "https") {
			if rec, err := s.store.GetForwardRule(req.Key); err == nil && rec.CertPEM != "" {
				newRule.CertPEM = rec.CertPEM
				newRule.KeyPEM = rec.KeyPEM
			} else if certRec, err := forward.FindCertificateForDomain(s.store, newRule.Domain); err == nil && certRec != nil {
				newRule.CertPEM = certRec.CertPEM
				newRule.KeyPEM = certRec.KeyPEM
			}
		} else if newRule.TLSEnable {
			// TCP+HTTPS 规则：沿用持久化的自签名证书，保证用户已信任的证书不失效
			if rec, err := s.store.GetForwardRule(req.Key); err == nil && rec.CertPEM != "" {
				newRule.CertPEM = rec.CertPEM
				newRule.KeyPEM = rec.KeyPEM
			}
		}
		if (newRule.Protocol == "gateway" || newRule.Protocol == "GATEWAY") && newRule.Name == "" {
			s.writeJSON(w, http.StatusOK, apiErr("统一网关模式必须填写路径名称"))
			return
		}
		// 开启 HTTPS（自签名证书）需要真实转发：目标为本机且端口相同时属直连模式（无转发器），会导致回环
		if newRule.TLSEnable && forward.IsLocalDirectTarget(newRule) {
			s.writeJSON(w, http.StatusOK, apiErr("开启 HTTPS（自签名证书）时目标不能为本机且与监听端口相同（直连模式）"))
			return
		}

		if changed {
			s.fwdMgr.StopRule(oldRule)
			s.setDescription("forward", req.Key, "")
			if err := s.fwdMgr.StartRule(newRule); err != nil {
				s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
				return
			}
			newKey := ruleKey(newRule)
			s.setDescription("forward", newKey, req.Description)
			// key 变更时迁移桌面图标配置（图标以 UUID 命名，需重新上传），
			// 并卸载旧规则对应的桌面图标空应用，避免桌面残留旧图标。
			if newKey != req.Key {
				if v, err := s.store.GetSetting(s.deskSettingKey(req.Key)); err == nil && v != "" {
					var dc DesktopIconConfig
					if json.Unmarshal([]byte(v), &dc) == nil {
						if dc.Enabled {
							if oldApp := s.deskAppNameForRule(req.Key); oldApp != "" {
								if err := s.deskApps.uninstall(nil, oldApp); err != nil {
									s.logger.Warn("规则更新后卸载旧桌面图标应用失败",
										zap.String("rule", oldApp),
										zap.Error(err),
									)
								}
							}
						}
						dc.Icon = ""
						if b, err := json.Marshal(dc); err == nil {
							s.store.SetSetting(s.deskSettingKey(newKey), string(b))
						}
					}
				}
				s.store.DeleteSetting(s.deskSettingKey(req.Key))
				s.deleteIconFile(req.Key)
			}
			// 规则更新后同步桌面入口配置（桌面图标应用打包安装由前端保存桌面图标时触发；
			// 此处兜底刷新主应用入口，保证桌面入口与最新转发规则一致）
			s.syncDesktopEntries()
			// 自定义域名变更后，同步内网穿透模块的 frpc 代理通道（默认服务器）
			if newRule.CustomDomain != "" {
				if err := s.ensureCustomDomainProxy(newRule); err != nil {
					s.logger.Warn("自定义域名同步 frpc 代理失败",
						zap.String("domain", newRule.CustomDomain), zap.Error(err))
				}
			}
			s.writeJSON(w, http.StatusOK, apiOK(s.forwardToMap(newKey)))
			return
		}
	}

	s.setDescription("forward", req.Key, req.Description)
	s.writeJSON(w, http.StatusOK, apiMsg("转发已更新: "+req.Key))
}

func (s *Server) handleForwardToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if isSystemForwardKey(req.Key) {
		s.writeJSON(w, http.StatusOK, apiErr("系统自动生成的转发不可启停，请在对应功能页面管理"))
		return
	}
	if s.isForwardRunning(req.Key) {
		rule, err := parseRuleKey(req.Key)
		if err != nil {
			s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
			return
		}
		// 暂停前持久化累计流量（flush 更新内存基线，下次启动从此续算）
		tx, rx, _ := s.fwdMgr.GetStats(req.Key)
		s.persistTrafficItem(&s.fwdTrafficBase, req.Key, tx, rx, true)
		// 暂停：仅停止转发器，保留存储配置（否则再次启动时 TLS/证书标记丢失）
		s.fwdMgr.StopRuleKeepConfig(rule)
		s.writeJSON(w, http.StatusOK, apiMsg("转发已暂停: "+req.Key))
	} else {
		rule, err := parseRuleKey(req.Key)
		if err != nil {
			s.writeJSON(w, http.StatusOK, apiErr("无效的Key格式"))
			return
		}
		// parseRuleKey 仅解析 key 字符串，不包含 TLS 开关、证书、进阶/日志等持久化字段；
		// 从存储恢复，保证「启动」按钮以正确的配置拉起规则
		if rec, rerr := s.store.GetForwardRule(req.Key); rerr == nil {
			rule.TLSEnable = rec.TLSEnable
			rule.CertPEM = rec.CertPEM
			rule.KeyPEM = rec.KeyPEM
			rule.RateLimit = rec.RateLimit
			rule.MaxConnections = rec.MaxConnections
			rule.ProxyProtocol = rec.ProxyProtocol
			rule.TLSSource = rec.TLSSource
			rule.UDPSessionTimeout = rec.UDPSessionTimeout
			rule.UDPMaxSessions = rec.UDPMaxSessions
			rule.UDPMaxBlockLen = rec.UDPMaxBlockLen
			rule.LogLevel = rec.LogLevel
			rule.ChannelLogEntries = rec.ChannelLogEntries
			rule.AccessLogEntries = rec.AccessLogEntries
			rule.LogRetentionHours = rec.LogRetentionHours
			rule.CustomID = rec.CustomID
			rule.CustomDomain = rec.CustomDomain
			rule.LinkKey = rec.LinkKey
			rule.AccessPassword = rec.AccessPassword
		}
		if err := s.fwdMgr.StartRule(rule); err != nil {
			s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
			return
		}
		s.writeJSON(w, http.StatusOK, apiMsg("转发已启动: "+req.Key))
	}
}

func (s *Server) handleForwardList(w http.ResponseWriter, r *http.Request) {
	keys := s.fwdMgr.RunningRules()
	views := make([]map[string]interface{}, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		views = append(views, s.forwardToMap(k))
		seen[k] = true
	}
	// 包含已保存但未运行的规则（暂停/停止），避免「关闭（暂停）」后无描述规则从列表消失，
	// 用户误以为被删除；运行中的规则已在上方加入，按 key 去重。
	if recs, err := s.store.ListForwardRules(); err == nil {
		for _, rec := range recs {
			if rec.Key != "" && !seen[rec.Key] {
				views = append(views, s.forwardToMap(rec.Key))
				seen[rec.Key] = true
			}
		}
	}
	// also include stopped rules that have descriptions（兼容描述残留/历史数据）
	s.descriptions.Range(func(key, _ interface{}) bool {
		k := key.(string)
		if strings.HasPrefix(k, "forward:") {
			id := k[8:]
			if !seen[id] {
				views = append(views, s.forwardToMap(id))
				seen[id] = true
			}
		}
		return true
	})
	// 追加系统自动生成的转发通道（前端以 system=true 标记并禁用操作按钮）：
	//   - STUN 打洞：本地监听端口 → 打洞目标
	//   - 内网穿透：frpc http 代理开启「TunHook 转发」后的本地反代 → 真实后端
	views = append(views, s.systemForwardViews()...)
	sort.Slice(views, func(i, j int) bool {
		return views[i]["key"].(string) < views[j]["key"].(string)
	})
	s.writeJSON(w, http.StatusOK, apiOK(views))
}

// systemForwardViews 构造「系统自动生成的转发」视图列表：
//   - STUN 打洞通道：本地监听地址 → 打洞目标（src/stunhole）
//   - 内网穿透 frpc http 代理开启「TunHook 转发」：本地反代监听 → 真实后端（frpc_http_proxy.go）
//
// 这些转发由对应功能自动创建与维护，因此标记 system=true，前端据此仅禁用「启停/编辑/删除」，
// 防止用户在转发列表改动后导致打洞或穿透功能失效；日志与流量为只读查看，仍可正常打开。
// ref 为对应功能的原始标识（STUN 通道 ID / frpc 代理名），供日志弹窗按来源查询。
// key 使用 stun:// / frpc:// 伪协议，与用户转发规则（tcp/udp/http/https/gateway）的命名空间隔离。
func (s *Server) systemForwardViews() []map[string]interface{} {
	views := make([]map[string]interface{}, 0, 4)
	if s.stunholeMgr != nil {
		for _, h := range s.stunholeMgr.List() {
			if h.ListenPort <= 0 {
				continue
			}
			addr := strings.TrimSpace(h.ListenAddr)
			if addr == "" {
				addr = strings.TrimSpace(h.ListenIP)
			}
			if addr == "" {
				addr = "0.0.0.0"
			}
			desc := strings.TrimSpace(h.Name)
			if desc == "" {
				desc = "STUN 打洞通道"
			}
			// 速率单独采样（键加 fwd: 前缀），避免与「STUN」页面共用采样状态互相干扰
			rateTx, rateRx := stunholeSampleRate("fwd:"+h.ID, h.TxBytes, h.RxBytes)
			tcpConns, udpConns := int64(0), int64(0)
			if strings.EqualFold(h.Proto, "udp") {
				udpConns = h.Conns
			} else {
				tcpConns = h.Conns
			}
			views = append(views, map[string]interface{}{
				"key":         fmt.Sprintf("stun://%s:%d->%s", addr, h.ListenPort, h.Target),
				"description": desc,
				"protocol":    h.Proto, // 真实监听协议（tcp/udp），供转发列表「协议」列显示，避免伪协议 stun 被当作协议
				"running":     h.Running,
				"system":      true,
				"source":      "stun",
				"ref":         h.ID,
				"tx_bytes":    h.TxBytes,
				"rx_bytes":    h.RxBytes,
				"tx_rate":     rateTx,
				"rx_rate":     rateRx,
				"tcp_conns":   tcpConns,
				"udp_conns":   udpConns,
				"clients":     []map[string]interface{}{},
			})
		}
	}
	// frpc http 反代层：仅对启用「TunHook 转发」且已运行的 http 代理存在（本地反代监听 → 真实后端）
	s.httpProxyMu.Lock()
	proxies := make([]*frpcHTTPProxy, 0, len(s.httpProxyByProxy))
	for _, hp := range s.httpProxyByProxy {
		proxies = append(proxies, hp)
	}
	s.httpProxyMu.Unlock()
	if len(proxies) > 0 {
		// 反代层自身不统计流量，取所属 frpc 代理的实时累计与速率（与「代理列表」同口径）
		detail := s.frpcConnDetail()
		for _, hp := range proxies {
			if hp == nil || hp.lis == nil {
				continue
			}
			var liveRx, liveTx int64
			for _, c := range detail[hp.name] {
				if c.RX > 0 {
					liveRx += c.RX
				}
				if c.TX > 0 {
					liveTx += c.TX
				}
			}
			cumRx, cumTx, rateRx, rateTx := s.frpcTrafficSample(hp.name, liveRx, liveTx)
			views = append(views, map[string]interface{}{
				"key":         fmt.Sprintf("frpc://%s->%s", hp.lis.Addr().String(), hp.backend),
				"description": hp.name + "（内网穿透 TunHook 反代）",
				"protocol":    "http", // 本地反代层为明文 HTTP 监听（frpc_http_proxy.go）
				"running":     true,
				"system":      true,
				"source":      "frpc",
				"ref":         hp.name,
				"tx_bytes":    cumTx,
				"rx_bytes":    cumRx,
				"tx_rate":     rateTx,
				"rx_rate":     rateRx,
				"tcp_conns":   0,
				"udp_conns":   0,
				"clients":     []map[string]interface{}{},
			})
		}
	}
	// Cloudflare 隧道的本地回源闸门：它同样是一条本机转发（闸门口 → 真实本地服务），
	// 按 STUN / frpc 的同一套规则列出来，免得用户看到 7451-7501 被占用却不知来路。
	for _, inst := range s.cfInstances() {
		run := s.cfRunner(inst.ID)
		addr := run.GateAddr()
		if addr == "" {
			continue // 未运行（或非临时入口）时没有监听端口，不占一行
		}
		tx, rx, active := run.GateCounters()
		// 速率采样键加 cf: 前缀，避免与「STUN」页面/转发列表里同 ID 的采样互相干扰
		rateTx, rateRx := stunholeSampleRate("cf:"+inst.ID, tx, rx)
		views = append(views, map[string]interface{}{
			"key":         fmt.Sprintf("cloudflare://%s->%s", addr, forwardTargetHostPort(inst)),
			"description": inst.DisplayName() + "（Cloudflare 隧道回源）",
			"protocol":    "http", // 闸门对内核是明文 HTTP 监听；对本地服务按实例配置走 http/https
			"running":     true,
			"system":      true,
			"source":      "cloudflare",
			"ref":         inst.ID,
			"tx_bytes":    tx,
			"rx_bytes":    rx,
			"tx_rate":     rateTx,
			"rx_rate":     rateRx,
			"tcp_conns":   active,
			"udp_conns":   0,
			"clients":     []map[string]interface{}{},
		})
	}
	return views
}

// forwardTargetHostPort 实例本地回源的 host:port 形式（转发列表的 key 用）。
// 转发列表按「host:port」解析目标地址，所以这里剥掉 scheme。
func forwardTargetHostPort(inst config.CloudflareInstance) string {
	t := inst.RuntimeTarget()
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "https://")
	return strings.TrimSuffix(t, "/")
}

// isSystemForwardKey 判断 key 是否属于系统自动生成的转发（stun:// / frpc:// / cloudflare:// 伪协议）。
// 这类转发由 STUN 打洞 / 内网穿透 / Cloudflare 隧道功能维护，禁止通过转发规则接口启停/编辑/删除，否则会导致对应功能失效。
func isSystemForwardKey(key string) bool {
	return strings.HasPrefix(key, "stun://") || strings.HasPrefix(key, "frpc://") || strings.HasPrefix(key, "cloudflare://")
}

// ============= 证书管理（TLS 证书库） =============

// handleCertList 返回证书库列表（不含证书内容）。
func (s *Server) handleCertList(w http.ResponseWriter, r *http.Request) {
	certs, err := s.store.ListCertificates()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("读取证书库失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(certs))
}

// handleCertImport 导入已有证书（PEM/CRT + 私钥），按域名保存到证书库。
func (s *Server) handleCertImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain    string `json:"domain"`
		Email     string `json:"email"`
		CertPEM   string `json:"cert_pem"`
		KeyPEM    string `json:"key_pem"`
		IssuerTag string `json:"issuer_tag"` // 可选：自定义发证机构名称（留空自动识别）
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.Domain = strings.TrimSpace(req.Domain)
	req.CertPEM = strings.TrimSpace(req.CertPEM)
	req.KeyPEM = strings.TrimSpace(req.KeyPEM)
	if req.Domain == "" {
		s.writeJSON(w, http.StatusOK, apiErr("请填写域名"))
		return
	}
	if req.CertPEM == "" || req.KeyPEM == "" {
		s.writeJSON(w, http.StatusOK, apiErr("请同时提供证书与私钥内容（PEM 格式）"))
		return
	}
	// 校验证书与私钥匹配，并解析证书信息
	domains, notBefore, notAfter, issuer, err := forward.ParseCertInfo(req.CertPEM)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	if req.IssuerTag != "" {
		issuer = req.IssuerTag
	}
	if len(domains) > 0 && !containsDomain(domains, req.Domain) {
		s.writeJSON(w, http.StatusOK, apiErr("证书 SAN 中不包含域名 "+req.Domain+"（证书包含: "+strings.Join(domains, ", ")+"）"))
		return
	}
	rec := store.CertRecord{
		Domain:    req.Domain,
		Email:     req.Email,
		Issuer:    issuer,
		CertPEM:   req.CertPEM,
		KeyPEM:    req.KeyPEM,
		NotBefore: forward.FormatDate(notBefore),
		NotAfter:  forward.FormatDate(notAfter),
		CreatedAt: forward.FormatDateTime(time.Now()),
	}
	if err := s.store.SaveCertificate(rec); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("保存证书失败: "+err.Error()))
		return
	}
	s.logger.Info("证书已导入", zap.String("domain", req.Domain), zap.String("issuer", issuer))
	s.writeJSON(w, http.StatusOK, apiOK(rec))
}

// containsDomain 判断域名是否在列表中（忽略大小写，支持通配域名）。
func containsDomain(list []string, domain string) bool {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, item := range list {
		if strings.EqualFold(item, d) {
			return true
		}
		// 通配证书匹配具体子域名
		if strings.HasPrefix(item, "*.") {
			base := strings.TrimPrefix(item, "*.")
			if strings.HasSuffix(d, "."+base) {
				return true
			}
		}
	}
	return false
}

// handleCertApply 提交 Let's Encrypt 证书申请（异步，返回任务 ID 供轮询）。
// 申请期间会自动把该域名的 HTTP 路由临时指向本服务以响应 HTTP-01 挑战，完成后恢复。
func (s *Server) handleCertApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain     string `json:"domain"`
		Email      string `json:"email"`
		DNSAccount string `json:"dns_account"`
		CAType     string `json:"ca_type"`
		KeyAlg     string `json:"key_alg"`
		EABKID     string `json:"eab_kid"`
		EABHMAC    string `json:"eab_hmac"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	domain := strings.TrimSpace(req.Domain)
	email := strings.TrimSpace(req.Email)
	dnsName := strings.TrimSpace(req.DNSAccount)
	// 按名称查找 DNS 账户，取出服务商与凭证
	var dnsProvider string
	var dnsCreds map[string]string
	if dnsName != "" {
		accounts, err := s.store.ListDNSAccounts()
		if err != nil {
			s.writeJSON(w, http.StatusOK, apiErr("读取 DNS 账户失败: "+err.Error()))
			return
		}
		var found *store.DNSAccount
		for i := range accounts {
			if accounts[i].Name == dnsName {
				found = &accounts[i]
				break
			}
		}
		if found == nil {
			s.writeJSON(w, http.StatusOK, apiErr("DNS 账户不存在: "+dnsName))
			return
		}
		dnsProvider = found.Provider
		dnsCreds = found.Credentials
	}
	taskID, err := s.startCertApply(forward.CertApplyOptions{
		Domain:      domain,
		Email:       email,
		DNSProvider: dnsProvider,
		DNSCreds:    dnsCreds,
		DNSAccount:  dnsName,
		CAType:      req.CAType,
		KeyAlg:      req.KeyAlg,
		EABKID:      req.EABKID,
		EABHMAC:     req.EABHMAC,
	})
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]string{"task_id": taskID}))
}

// startCertApply 启动一次申请/续签任务；HTTP-01 时临时把域名路由指向本服务响应挑战。
func (s *Server) startCertApply(opts forward.CertApplyOptions) (string, error) {
	taskID, err := s.certApplier.StartApply(opts)
	if err != nil {
		return "", err
	}
	// HTTP-01 需临时把域名路由指向本服务响应挑战；DNS-01 走解析验证，无需改路由
	if opts.DNSProvider == "" {
		s.setupACMERouting(opts.Domain, taskID)
	}
	return taskID, nil
}

// acmeChallengeMiddleware 响应 Let's Encrypt HTTP-01 挑战请求
// （申请期间域名被临时路由到本服务，绕过来源 IP 校验与网关鉴权）。
func (s *Server) acmeChallengeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			if token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/"); token != "" {
				if ka, ok := forward.LookupACMEChallenge(token); ok {
					w.Header().Set("Content-Type", "text/plain")
					w.Write([]byte(ka))
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// webTCPAddr 返回本服务可供 frpc 临时路由指向的 TCP 监听地址：
// 优先 Webhook 端口（接收上报 + 通道访问入口），其次开发模式 TCP 监听；
// 均不存在（纯网关部署且未监听 Webhook 端口）时返回空，跳过自动路由。
func (s *Server) webTCPAddr() string {
	// 域名代理回落优先 Webhook 端口（接收上报 + 通道访问入口）
	if s.whLn != nil {
		return s.whLn.Addr().String()
	}
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// acmeRouteRestore 记录证书申请期间临时改动的 frpc 路由，用于结束后恢复。
type acmeRouteRestore struct {
	name        string      // 受影响的代理名
	createdTemp bool        // true=申请时新建的临时代理，结束后删除；false=临时改指已有代理，恢复原值
	original    *frpc.Proxy // 已有代理的原配置（createdTemp=false 时非空）
}

// setupACMERouting 申请期间把域名 HTTP 路由临时指向本服务：
// Let's Encrypt 的 HTTP-01 挑战走端口 80，frps 的 vhost HTTP 端口只路由 http 类型代理
// （https 代理不响应端口 80 请求）。因此已有 http 代理覆盖该域名时临时改指，
// 否则（仅有 https 代理或没有代理）新建 http 类型临时代理。
func (s *Server) setupACMERouting(domain, taskID string) {
	webAddr := s.webTCPAddr()
	if webAddr == "" {
		s.logger.Info("无 TCP 监听，跳过 ACME 临时路由", zap.String("domain", domain))
		return
	}
	host, portStr, err := net.SplitHostPort(webAddr)
	if err != nil {
		return
	}
	port, _ := strconv.Atoi(portStr)
	if host == "::" || host == "" {
		host = "127.0.0.1"
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || port <= 0 {
		return
	}

	cfg := s.frpcMgr.LoadConfig()
	for i := range cfg.Proxies {
		p := &cfg.Proxies[i]
		if !strings.EqualFold(strings.TrimSpace(p.Type), "http") {
			continue
		}
		for _, d := range strings.Split(p.CustomDomains, ",") {
			if strings.ToLower(strings.TrimSpace(d)) == domain {
				orig := *p
				p.LocalIP = host
				p.LocalPort = port
				p.Enabled = true
				if err := s.frpcMgr.SaveConfig(cfg); err != nil {
					s.logger.Warn("ACME 临时改指代理失败", zap.String("name", p.Name), zap.Error(err))
					return
				}
				s.acmeRoutesMu.Lock()
				s.acmeRoutes[taskID] = acmeRouteRestore{name: p.Name, original: &orig}
				s.acmeRoutesMu.Unlock()
				s.logger.Info("ACME 申请期间临时改指代理", zap.String("name", p.Name), zap.String("domain", domain), zap.String("to", webAddr))
				return
			}
		}
	}
	// 无 http 代理覆盖该域名：新建 http 类型临时代理（仅响应申请期间的挑战，结束后删除）
	name := "acme-" + strings.ToLower(strings.NewReplacer(".", "-", "*", "x", ":", "-").Replace(domain))
	cfg.Proxies = append(cfg.Proxies, frpc.Proxy{
		Name:          name,
		Type:          "http",
		Enabled:       true,
		LocalIP:       host,
		LocalPort:     port,
		CustomDomains: domain,
	})
	if err := s.frpcMgr.SaveConfig(cfg); err != nil {
		s.logger.Warn("ACME 创建临时代理失败", zap.String("domain", domain), zap.Error(err))
		return
	}
	s.acmeRoutesMu.Lock()
	s.acmeRoutes[taskID] = acmeRouteRestore{name: name, createdTemp: true}
	s.acmeRoutesMu.Unlock()
	s.logger.Info("ACME 申请期间创建 http 临时代理", zap.String("name", name), zap.String("domain", domain))
}

// restoreACMERouting 证书申请到达终态后恢复被临时改动的路由。
func (s *Server) restoreACMERouting(taskID string) {
	s.acmeRoutesMu.Lock()
	info, ok := s.acmeRoutes[taskID]
	delete(s.acmeRoutes, taskID)
	s.acmeRoutesMu.Unlock()
	if !ok {
		return
	}
	cfg := s.frpcMgr.LoadConfig()
	changed := false
	if info.createdTemp {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name == info.name {
				cfg.Proxies = append(cfg.Proxies[:i], cfg.Proxies[i+1:]...)
				changed = true
				break
			}
		}
	} else if info.original != nil {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name == info.name {
				cfg.Proxies[i] = *info.original
				changed = true
				break
			}
		}
	}
	if changed {
		if err := s.frpcMgr.SaveConfig(cfg); err != nil {
			s.logger.Warn("恢复 ACME 临时路由失败", zap.String("proxy", info.name), zap.Error(err))
			return
		}
		s.logger.Info("ACME 临时路由已恢复", zap.String("proxy", info.name), zap.Bool("deleted", info.createdTemp))
	}
}

// handleCertApplyStatus 查询证书申请任务状态。
func (s *Server) handleCertApplyStatus(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("task_id")
	if taskID == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少 task_id 参数"))
		return
	}
	st, ok := s.certApplier.Status(taskID)
	if !ok {
		s.writeJSON(w, http.StatusOK, apiErr("任务不存在或已过期"))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(st))
}

// handleCertApplyList 返回全部证书申请任务（域名 + 申请进度），最新的在前。
func (s *Server) handleCertApplyList(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, apiOK(s.certApplier.Tasks()))
}

// ============= 证书自动续签 =============

const (
	certAutoRenewSetting  = "cert:auto-renew"
	certRenewDaysSetting  = "cert:auto-renew-days"
	certRenewDaysDefault  = 30
	certRenewDaysMin      = 1
	certRenewDaysMax      = 90
	certRenewRetryBackoff = 6 * time.Hour
)

// certAutoRenewEnabled 读取全局自动续签开关。
func (s *Server) certAutoRenewEnabled() bool {
	v, _ := s.store.GetSetting(certAutoRenewSetting)
	return v == "1" || strings.EqualFold(v, "true")
}

// certAutoRenewDays 读取「到期前多少天开始续签」，未配置或越界时回退默认值。
func (s *Server) certAutoRenewDays() int {
	v, _ := s.store.GetSetting(certRenewDaysSetting)
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < certRenewDaysMin || n > certRenewDaysMax {
		return certRenewDaysDefault
	}
	return n
}

func (s *Server) handleCertAutoRenewGet(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"enabled": s.certAutoRenewEnabled(),
		"days":    s.certAutoRenewDays(),
	}))
}

func (s *Server) handleCertAutoRenewSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled *bool `json:"enabled"`
		Days    *int  `json:"days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if req.Days != nil {
		if *req.Days < certRenewDaysMin || *req.Days > certRenewDaysMax {
			s.writeJSON(w, http.StatusBadRequest, apiErr(fmt.Sprintf("提前续签天数应在 %d-%d 之间", certRenewDaysMin, certRenewDaysMax)))
			return
		}
		if err := s.store.SetSetting(certRenewDaysSetting, strconv.Itoa(*req.Days)); err != nil {
			s.writeJSON(w, http.StatusOK, apiErr("保存提前续签天数失败: "+err.Error()))
			return
		}
	}
	if req.Enabled != nil {
		v := "0"
		if *req.Enabled {
			v = "1"
		}
		if err := s.store.SetSetting(certAutoRenewSetting, v); err != nil {
			s.writeJSON(w, http.StatusOK, apiErr("保存自动续签设置失败: "+err.Error()))
			return
		}
	}
	s.logger.Info("证书自动续签设置已更新",
		zap.Bool("enabled", s.certAutoRenewEnabled()), zap.Int("days", s.certAutoRenewDays()))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"enabled": s.certAutoRenewEnabled(),
		"days":    s.certAutoRenewDays(),
	}))
}

// startCertRenewEngine 启动自动续签引擎：启动 30 秒后检查一次，之后每小时检查。
func (s *Server) startCertRenewEngine() {
	s.bgWG.Add(1)
	go func() {
		defer s.bgWG.Done()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		initial := time.NewTimer(30 * time.Second)
		defer initial.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-initial.C:
				s.renewExpiringCerts()
			case <-ticker.C:
				s.renewExpiringCerts()
			}
		}
	}()
}

// renewExpiringCerts 对「通过本服务 ACME 签发且进入续签窗口」的证书发起续签。
// 续签窗口由「提前续签天数」设置决定（默认 30 天）。
// 导入证书没有 CA/密钥类型/验证方式参数，无法自动续签，直接跳过。
func (s *Server) renewExpiringCerts() {
	if !s.certAutoRenewEnabled() {
		return
	}
	certs, err := s.store.ListCertificates()
	if err != nil {
		s.logger.Warn("自动续签读取证书库失败", zap.Error(err))
		return
	}
	now := time.Now()
	renewDays := s.certAutoRenewDays()
	for _, c := range certs {
		if strings.TrimSpace(c.CAType) == "" {
			continue
		}
		exp, err := time.ParseInLocation("2006-01-02", strings.TrimSpace(c.NotAfter), time.Local)
		if err != nil {
			continue
		}
		if exp.After(now.AddDate(0, 0, renewDays)) {
			continue
		}
		if s.certApplier.IsApplying(c.Domain) {
			continue
		}
		// 同一域名失败后 6 小时内不重复尝试，避免配置错误时每小时消耗 CA 配额
		s.certRenewMu.Lock()
		if last, ok := s.certRenewLast[c.Domain]; ok && now.Sub(last) < certRenewRetryBackoff {
			s.certRenewMu.Unlock()
			continue
		}
		s.certRenewLast[c.Domain] = now
		s.certRenewMu.Unlock()

		full, err := s.store.GetCertificate(c.Domain)
		if err != nil {
			s.logger.Warn("自动续签读取证书失败", zap.String("domain", c.Domain), zap.Error(err))
			continue
		}
		var provider string
		var creds map[string]string
		if full.DNSAccount != "" {
			accounts, err := s.store.ListDNSAccounts()
			if err != nil {
				s.logger.Warn("自动续签读取 DNS 账户失败", zap.String("domain", c.Domain), zap.Error(err))
				continue
			}
			found := false
			for i := range accounts {
				if accounts[i].Name == full.DNSAccount {
					provider, creds, found = accounts[i].Provider, accounts[i].Credentials, true
					break
				}
			}
			if !found {
				s.logger.Warn("自动续签跳过：DNS 账户不存在", zap.String("domain", c.Domain), zap.String("account", full.DNSAccount))
				continue
			}
		}
		if _, err := s.startCertApply(forward.CertApplyOptions{
			Domain:      full.Domain,
			Email:       full.Email,
			DNSProvider: provider,
			DNSCreds:    creds,
			DNSAccount:  full.DNSAccount,
			CAType:      full.CAType,
			KeyAlg:      full.KeyAlg,
			EABKID:      full.EABKID,
			EABHMAC:     full.EABHMAC,
			Renewal:     true,
		}); err != nil {
			s.logger.Warn("自动续签启动失败", zap.String("domain", c.Domain), zap.Error(err))
			continue
		}
		s.logger.Info("已启动证书自动续签", zap.String("domain", c.Domain), zap.String("ca", full.CAType), zap.String("expire", c.NotAfter))
	}
}

// handleCertDelete 按域名删除证书。
func (s *Server) handleCertDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.Domain = strings.TrimSpace(req.Domain)
	if req.Domain == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少域名参数"))
		return
	}
	if err := s.store.DeleteCertificate(req.Domain); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("删除证书失败: "+err.Error()))
		return
	}
	s.logger.Info("证书已删除", zap.String("domain", req.Domain))
	s.writeJSON(w, http.StatusOK, apiMsg("证书已删除: "+req.Domain))
}

// ============= 联系人邮箱管理 =============

// handleEmailList 返回联系人邮箱列表。
func (s *Server) handleEmailList(w http.ResponseWriter, r *http.Request) {
	emails, err := s.store.ListEmails()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("读取邮箱列表失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(emails))
}

// handleEmailAdd 添加 ACME 账户（邮箱 + 账号类型 + 密钥算法）。
func (s *Server) handleEmailAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email  string `json:"email"`
		CAType string `json:"ca_type"`
		KeyAlg string `json:"key_alg"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if !validEmail(req.Email) {
		s.writeJSON(w, http.StatusOK, apiErr("请填写有效的邮箱地址"))
		return
	}
	caType := strings.TrimSpace(req.CAType)
	if caType == "" {
		caType = "Let's Encrypt"
	}
	if caType != "Let's Encrypt" && caType != "ZeroSSL" {
		s.writeJSON(w, http.StatusOK, apiErr("不支持的账号类型: "+caType))
		return
	}
	keyAlg := strings.TrimSpace(req.KeyAlg)
	if keyAlg == "" {
		keyAlg = "EC 256"
	}
	switch keyAlg {
	case "EC 256", "EC 384", "RSA 2048", "RSA 3072", "RSA 4096":
	default:
		s.writeJSON(w, http.StatusOK, apiErr("不支持的密钥算法: "+keyAlg))
		return
	}
	if err := s.store.AddEmail(req.Email, caType, keyAlg); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("保存邮箱失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(req.Email))
}

// handleEmailDelete 删除联系人邮箱。
func (s *Server) handleEmailDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少邮箱参数"))
		return
	}
	if err := s.store.DeleteEmail(req.Email); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("删除邮箱失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiMsg("邮箱已删除: "+req.Email))
}

// ============= DNS 账户管理（Let's Encrypt DNS-01 验证用） =============

// handleDNSList 返回 DNS 账户列表。
func (s *Server) handleDNSList(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.store.ListDNSAccounts()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("读取 DNS 账户列表失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(accounts))
}

// handleDNSAdd 添加 DNS 账户（服务商 + 多字段凭证）。
func (s *Server) handleDNSAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string            `json:"name"`
		Provider    string            `json:"provider"`
		Credentials map[string]string `json:"credentials"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Provider = strings.TrimSpace(req.Provider)
	if req.Name == "" {
		s.writeJSON(w, http.StatusOK, apiErr("请填写账户名称"))
		return
	}
	switch req.Provider {
	case "阿里云 DNS", "腾讯云 DNSPod", "Cloudflare", "华为云 DNS", "其他":
	default:
		s.writeJSON(w, http.StatusOK, apiErr("请选择 DNS 服务商"))
		return
	}
	// 清理空值凭证
	creds := map[string]string{}
	for k, v := range req.Credentials {
		if v = strings.TrimSpace(v); v != "" {
			creds[k] = v
		}
	}
	if len(creds) == 0 {
		s.writeJSON(w, http.StatusOK, apiErr("请填写 API 凭证信息"))
		return
	}
	if err := s.store.AddDNSAccount(req.Name, req.Provider, creds); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("保存 DNS 账户失败: "+err.Error()))
		return
	}
	s.logger.Info("DNS 账户已添加", zap.String("name", req.Name), zap.String("provider", req.Provider))
	s.writeJSON(w, http.StatusOK, apiOK(req.Name))
}

// handleDNSDelete 删除 DNS 账户。
func (s *Server) handleDNSDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少账户名称"))
		return
	}
	if err := s.store.DeleteDNSAccount(req.Name); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("删除 DNS 账户失败: "+err.Error()))
		return
	}
	s.logger.Info("DNS 账户已删除", zap.String("name", req.Name))
	s.writeJSON(w, http.StatusOK, apiMsg("DNS 账户已删除: "+req.Name))
}

// validEmail 简单邮箱格式校验。
func validEmail(email string) bool {
	if email == "" || len(email) > 254 || !strings.Contains(email, "@") {
		return false
	}
	parts := strings.SplitN(email, "@", 2)
	if parts[0] == "" || parts[1] == "" || strings.Contains(parts[1], "@") {
		return false
	}
	if strings.ContainsAny(email, " \t\n") {
		return false
	}
	return true
}

func (s *Server) isForwardRunning(key string) bool {
	for _, k := range s.fwdMgr.RunningRules() {
		if k == key {
			return true
		}
	}
	return false
}

// clientsToViews 将转发器返回的客户端统计转换为前端展示结构（附加归属地）。
func (s *Server) clientsToViews(clients []forward.ClientInfo) []map[string]interface{} {
	views := make([]map[string]interface{}, 0, len(clients))
	for _, c := range clients {
		location := ""
		if s.geo != nil {
			location = s.geo.Lookup(c.Addr)
		}
		views = append(views, map[string]interface{}{
			"addr":     c.Addr,
			"location": location,
			"tx_bytes": c.TxBytes,
			"rx_bytes": c.RxBytes,
			"tx_rate":  c.TxRate,
			"rx_rate":  c.RxRate,
		})
	}
	return views
}

// fwdAdvanced 返回转发规则的进阶/日志设置（内存缓存优先，缺失时回退存储）。
func (s *Server) fwdAdvanced(key string) *forward.RuleAdvanced {
	if adv := s.fwdMgr.Advanced(key); adv != nil {
		return adv
	}
	if rec, err := s.store.GetForwardRule(key); err == nil {
		return &forward.RuleAdvanced{
			RateLimit:         rec.RateLimit,
			MaxConnections:    rec.MaxConnections,
			ProxyProtocol:     rec.ProxyProtocol,
			TLSSource:         rec.TLSSource,
			UDPSessionTimeout: rec.UDPSessionTimeout,
			UDPMaxSessions:    rec.UDPMaxSessions,
			UDPMaxBlockLen:    rec.UDPMaxBlockLen,
			LogLevel:          rec.LogLevel,
			ChannelLogEntries: rec.ChannelLogEntries,
			AccessLogEntries:  rec.AccessLogEntries,
		}
	}
	return &forward.RuleAdvanced{}
}

func (s *Server) forwardToMap(key string) map[string]interface{} {
	running := s.isForwardRunning(key)
	desc := s.getDesc("forward", key)
	uuid := s.fwdMgr.GetUUID(key)
	rule, _ := parseRuleKey(key)
	// 累计流量基线：未运行（暂停/停止）时仍展示历史累计值
	baseTx, baseRx := s.trafficBase(&s.fwdTrafficBase, key)
	m := map[string]interface{}{
		"key":       key,
		"running":   running,
		"uuid":      uuid,
		"tx_bytes":  baseTx,
		"rx_bytes":  baseRx,
		"tcp_conns": 0,
		"udp_conns": 0,
		"clients":   []map[string]interface{}{},
	}
	if rule.Domain != "" {
		m["domain"] = rule.Domain
	}
	if rule.Name != "" {
		m["name"] = rule.Name
	}
	// HTTPS 规则（域名 HTTPS 或 TCP+自签名证书开关）：是否使用用户上传的证书（false 表示自动生成的自签名证书）
	isTLS := s.fwdMgr.IsTLS(key) || strings.HasPrefix(key, "https://")
	if isTLS {
		m["tls"] = true
		m["has_custom_cert"] = s.fwdMgr.HasCustomCert(key)
	}
	// tls_enable：TCP+自签名证书开关的持久化状态。运行中以内存为准；暂停/未运行时回退到存储记录，
	// 保证前端编辑弹窗能正确回填「是否开启 TLS」状态（否则保存会误把 TLS 关闭）。
	if rec, err := s.store.GetForwardRule(key); err == nil {
		m["tls_enable"] = rec.TLSEnable
	} else {
		m["tls_enable"] = isTLS && strings.HasPrefix(key, "tcp")
	}
	if sp := s.fwdMgr.SourcePrefix(key); sp != "" {
		m["source_prefix"] = sp
	}
	if rp := s.fwdMgr.RootPrefixes(key); rp != "" {
		m["root_prefixes"] = rp
	}
	if pp := s.fwdMgr.PathPrefix(key); pp != "" {
		m["path_prefix"] = pp
	}
	if s.fwdMgr.AutoDetect(key) {
		m["auto_detect"] = true
	}
	if desc != "" {
		m["description"] = desc
	}
	// 进阶/日志设置（转发规则编辑回填）；未运行/重启后缓存缺失时从存储恢复
	if adv := s.fwdMgr.Advanced(key); adv != nil {
		m["rate_limit"] = adv.RateLimit
		m["max_connections"] = adv.MaxConnections
		m["proxy_protocol"] = adv.ProxyProtocol
		m["tls_source"] = adv.TLSSource
		m["udp_session_timeout"] = adv.UDPSessionTimeout
		m["udp_max_sessions"] = adv.UDPMaxSessions
		m["udp_max_block_len"] = adv.UDPMaxBlockLen
		m["log_level"] = adv.LogLevel
		m["channel_log_entries"] = adv.ChannelLogEntries
		m["access_log_entries"] = adv.AccessLogEntries
	} else if rec, err := s.store.GetForwardRule(key); err == nil {
		m["rate_limit"] = rec.RateLimit
		m["max_connections"] = rec.MaxConnections
		m["proxy_protocol"] = rec.ProxyProtocol
		m["tls_source"] = rec.TLSSource
		m["udp_session_timeout"] = rec.UDPSessionTimeout
		m["udp_max_sessions"] = rec.UDPMaxSessions
		m["udp_max_block_len"] = rec.UDPMaxBlockLen
		m["log_level"] = rec.LogLevel
		m["channel_log_entries"] = rec.ChannelLogEntries
		m["access_log_entries"] = rec.AccessLogEntries
	}
	// 进阶访问链接配置（仅持久化存储，不从运行缓存回填）
	if rec, err := s.store.GetForwardRule(key); err == nil {
		if rec.LogRetentionHours != 0 {
			m["log_retention_hours"] = rec.LogRetentionHours
		}
		if rec.CustomID != "" {
			m["custom_id"] = rec.CustomID
		}
		if rec.CustomDomain != "" {
			m["custom_domain"] = rec.CustomDomain
		}
		if rec.LinkKey != "" {
			m["link_key"] = rec.LinkKey
		}
		if rec.AccessPassword != "" {
			m["access_password"] = rec.AccessPassword
		}
	}

	if running {
		// 目标端口可达性（由后台探测缓存）：未知时按可达处理，避免图标闪烁
		if reachable, known := s.fwdMgr.TargetReachable(key); known {
			m["target_ok"] = reachable
		} else {
			m["target_ok"] = true
		}
		txBytes, rxBytes, connCount := s.fwdMgr.GetStats(key)
		m["tx_bytes"] = baseTx + txBytes
		m["rx_bytes"] = baseRx + rxBytes
		// 实时速率（字节/秒）：相邻两次轮询的累计流量差值计算，供列表「实时速率」列展示
		rateTx, rateRx := s.fwdRateSample(key, baseTx+txBytes, baseRx+rxBytes)
		m["tx_rate"] = rateTx
		m["rx_rate"] = rateRx
		m["clients"] = s.clientsToViews(s.fwdMgr.GetClients(key))
		// 统一网关/HTTP/HTTPS 转发按连接数统计（与 TCP 一致）
		if strings.HasPrefix(key, "tcp://") || strings.HasPrefix(key, "http://") || strings.HasPrefix(key, "https://") || strings.HasPrefix(key, "gateway://") {
			m["tcp_conns"] = connCount
		} else {
			m["udp_conns"] = connCount
		}
	}

	return m
}

// fwdRateSample 单个转发规则的实时速率采样状态（相邻两次 /api/forward/list 轮询的累计值差值）。
type fwdRateSample struct {
	lastTx, lastRx int64
	lastT          time.Time
}

// fwdRateSample 用当前转发规则累计流量（txBytes/rxBytes）采样实时速率（字节/秒，>=0）。
// 累计值为「基线+计数器」（单调），速率 = 相邻两次采样的差值 / 间隔；首次采样或间隔过短时返回 0。
func (s *Server) fwdRateSample(key string, txBytes, rxBytes int64) (rateTx, rateRx float64) {
	now := time.Now()
	v, _ := s.fwdRate.LoadOrStore(key, &fwdRateSample{})
	a := v.(*fwdRateSample)
	if a.lastT.IsZero() {
		a.lastTx, a.lastRx, a.lastT = txBytes, rxBytes, now
		return 0, 0
	}
	dt := now.Sub(a.lastT).Seconds()
	if dt > 0 {
		if txBytes > a.lastTx {
			rateTx = float64(txBytes-a.lastTx) / dt
		}
		if rxBytes > a.lastRx {
			rateRx = float64(rxBytes-a.lastRx) / dt
		}
	}
	a.lastTx, a.lastRx, a.lastT = txBytes, rxBytes, now
	return rateTx, rateRx
}

func ruleKey(r config.ForwardRule) string {
	if r.Protocol == "http" || r.Protocol == "HTTP" || r.Protocol == "https" || r.Protocol == "HTTPS" {
		proto := strings.ToLower(r.Protocol)
		return fmt.Sprintf("%s://%s:%d/%s->%s:%d",
			proto, r.LocalAddr, r.LocalPort, r.Domain, r.RemoteAddr, r.RemotePort)
	}
	if r.Protocol == "gateway" || r.Protocol == "GATEWAY" {
		return fmt.Sprintf("gateway://%s->%s:%d",
			r.Name, r.RemoteAddr, r.RemotePort)
	}
	return fmt.Sprintf("%s://%s:%d->%s:%d", r.Protocol, r.LocalAddr, r.LocalPort, r.RemoteAddr, r.RemotePort)
}

// parseRuleKey 从 ruleKey 生成的字符串中解析出 ForwardRule。
// fmt.Sscanf 的 %s 是贪婪的，不适合解析此格式，因此手动解析。
func parseRuleKey(key string) (config.ForwardRule, error) {
	var r config.ForwardRule

	idx := strings.Index(key, "://")
	if idx < 0 {
		return r, fmt.Errorf("invalid key: missing ://")
	}
	r.Protocol = key[:idx]
	rest := key[idx+3:]

	arrowIdx := strings.Index(rest, "->")
	if arrowIdx < 0 {
		return r, fmt.Errorf("invalid key: missing ->")
	}

	localPart := rest[:arrowIdx]
	remotePart := rest[arrowIdx+2:]

	// HTTP/HTTPS 格式: addr:port/domain，从 localPart 中提取域名
	if r.Protocol == "http" || r.Protocol == "HTTP" || r.Protocol == "https" || r.Protocol == "HTTPS" {
		slashIdx := strings.Index(localPart, "/")
		if slashIdx >= 0 {
			r.Domain = localPart[slashIdx+1:]
			localPart = localPart[:slashIdx]
		}
	}

	// 统一网关格式: gateway://name->addr:port，localPart 即子路径名称（无端口）
	if r.Protocol != "gateway" && r.Protocol != "GATEWAY" {
		lastColon := strings.LastIndex(localPart, ":")
		if lastColon < 0 {
			return r, fmt.Errorf("invalid key: local part missing port")
		}
		r.LocalAddr = localPart[:lastColon]
		fmt.Sscanf(localPart[lastColon+1:], "%d", &r.LocalPort)
	} else {
		r.Name = localPart
	}

	lastColon := strings.LastIndex(remotePart, ":")
	if lastColon < 0 {
		return r, fmt.Errorf("invalid key: remote part missing port")
	}
	r.RemoteAddr = remotePart[:lastColon]
	fmt.Sscanf(remotePart[lastColon+1:], "%d", &r.RemotePort)

	return r, nil
}

// ============= 桌面图标（fnOS 桌面入口） =============

// DesktopIconConfig 一条转发规则对应的 fnOS 桌面图标配置。
// 参考 app-entry 文档：title（图标名称）、type（打开方式）、icon（图标）、allUsers（可见性）。
type DesktopIconConfig struct {
	Enabled  bool   `json:"enabled"`
	Name     string `json:"name"`           // 图标名称（入口 title）
	Type     string `json:"type"`           // 打开方式: iframe（桌面窗口）| url（浏览器标签页）
	Icon     string `json:"icon,omitempty"` // 图标文件名（icons/ 目录下），空表示使用应用默认图标
	AllUsers bool   `json:"all_users"`      // 桌面访问（可见性）: true 所有用户 | false 仅管理员
}

const (
	deskConfigPrefix = "desk."
	deskEntryPrefix  = "TunHook.desk."
	deskIconMaxBytes = 8 << 20 // 8MB：原始图直接上传上限（服务端会裁剪压缩至 512×512 PNG）
)

func (s *Server) deskSettingKey(key string) string { return deskConfigPrefix + key }

func (s *Server) getDeskConfig(key string) DesktopIconConfig {
	var cfg DesktopIconConfig
	if v, err := s.store.GetSetting(s.deskSettingKey(key)); err == nil && v != "" {
		json.Unmarshal([]byte(v), &cfg)
		// 旧版配置无 all_users 字段，默认对所有用户可见
		if !strings.Contains(v, `"all_users"`) {
			cfg.AllUsers = true
		}
	}
	return cfg
}

func (s *Server) saveDeskConfig(key string, cfg DesktopIconConfig) error {
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.store.SetSetting(s.deskSettingKey(key), string(b))
}

// deskIconFile 规则对应图标文件名（由规则 UUID 派生，稳定且唯一）。
func (s *Server) deskIconFile(key string) string {
	uuid := s.fwdMgr.GetUUID(key)
	if uuid == "" {
		uuid = fmt.Sprintf("%x", sha1.Sum([]byte(key)))[:8]
	}
	return "desk_" + uuid + ".png"
}

// deskAppUUID 返回规则对应的稳定 UUID（用于非网关协议的空应用名，仅字母数字）。
func (s *Server) deskAppUUID(key string) string {
	if uuid := s.fwdMgr.GetUUID(key); uuid != "" {
		return uuid
	}
	return fmt.Sprintf("%x", sha1.Sum([]byte(key)))[:8]
}

// deskEntryID 规则对应的桌面入口 ID（appname 前缀 + 稳定后缀，不含点号/扩展名）。
func (s *Server) deskEntryID(key string) string {
	return deskEntryPrefix + strings.TrimSuffix(s.deskIconFile(key), ".png")
}

func (s *Server) iconsDir() string {
	return filepath.Join(s.dataDir, "icons")
}

// deskAppNameForRule 返回规则对应的桌面图标空应用名（网关协议用路径名称，其余用稳定 UUID）。
func (s *Server) deskAppNameForRule(key string) string {
	rule, err := parseRuleKey(key)
	if err != nil {
		return ""
	}
	if rule.Protocol == "gateway" || rule.Protocol == "GATEWAY" {
		return rule.Name
	}
	return s.deskAppUUID(key)
}

// deleteDeskConfigData 删除规则对应的桌面图标配置与图标文件，并重建桌面入口（快速部分）。
// 返回删除前是否存在已启用的桌面图标配置（调用方据此决定是否需要卸载空应用，
// 避免对从未创建过桌面图标的规则执行无意义的 appcenter-cli 卸载）。
func (s *Server) deleteDeskConfigData(key string) bool {
	hadEnabled := false
	if v, err := s.store.GetSetting(s.deskSettingKey(key)); err == nil && v != "" {
		var dc DesktopIconConfig
		if json.Unmarshal([]byte(v), &dc) == nil && dc.Enabled {
			hadEnabled = true
		}
	}
	s.store.DeleteSetting(s.deskSettingKey(key))
	s.deleteIconFile(key)
	s.syncDesktopEntries()
	return hadEnabled
}

// deleteDeskConfig 删除规则对应的桌面图标配置与图标文件，卸载桌面图标空应用，并重建桌面入口。
func (s *Server) deleteDeskConfig(key string) {
	// 从未创建过桌面图标时无需卸载（避免 appcenter-cli 缺失时产生误导性报错）
	if !s.deleteDeskConfigData(key) {
		return
	}
	// 自动卸载对应空应用（root 运行时可调用 appcenter-cli uninstall）；
	// 卸载失败不阻断规则删除，仅记录日志。
	if appName := s.deskAppNameForRule(key); appName != "" {
		if err := s.deskApps.uninstall(nil, appName); err != nil {
			s.logger.Warn("卸载桌面图标应用失败",
				zap.String("rule", appName),
				zap.Error(err),
			)
		}
	}
}

// deleteDeskConfigAsync 删除配置/图标并重建入口（同步完成），随后异步卸载桌面图标空应用，
// 返回任务句柄供前端轮询实时卸载进度。
func (s *Server) deleteDeskConfigAsync(key string) *DeskTask {
	hadEnabled := s.deleteDeskConfigData(key)
	appName := s.deskAppNameForRule(key)
	task := s.deskApps.newTask("uninstall")
	go func() {
		// 任务保留在表中供前端轮询读取最终状态，由后续新任务创建时按上限清理
		if !hadEnabled || appName == "" {
			task.setDone()
			return
		}
		if err := s.deskApps.uninstall(task, appName); err != nil {
			task.setFailed(err)
			s.logger.Warn("卸载桌面图标应用失败",
				zap.String("rule", appName),
				zap.Error(err),
			)
		}
	}()

	return task
}

// deleteIconFile 删除规则图标文件（应用数据目录 + target/ui/images）。
func (s *Server) deleteIconFile(key string) {
	icon := s.deskIconFile(key)
	for _, dir := range []string{s.iconsDir(), filepath.Join(os.Getenv("TRIM_APPDEST"), "ui", "images")} {
		if dir == "" {
			continue
		}
		os.Remove(filepath.Join(dir, icon))
	}
}

// validIconData 校验上传文件是否为 PNG 或 JPEG。
func validIconData(head []byte) bool {
	return (len(head) >= 8 && bytes.Equal(head[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})) ||
		(len(head) >= 3 && head[0] == 0xff && head[1] == 0xd8 && head[2] == 0xff)
}

// cropSquareResize 将图片居中裁剪为 1:1 后双线性缩放到 size×size。
func cropSquareResize(src image.Image, size int) *image.RGBA {
	sb := src.Bounds()
	w, h := sb.Dx(), sb.Dy()
	side := w
	if h < side {
		side = h
	}
	ox := sb.Min.X + (w-side)/2
	oy := sb.Min.Y + (h-side)/2
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	if size <= 0 {
		return dst
	}
	toRGBA := func(c color.Color) color.RGBA {
		if rc, ok := c.(color.RGBA); ok {
			return rc
		}
		return color.RGBAModel.Convert(c).(color.RGBA)
	}
	if size == 1 {
		dst.SetRGBA(0, 0, toRGBA(src.At(ox+side/2, oy+side/2)))
		return dst
	}
	lerp := func(a, b uint8, t float64) uint8 {
		return uint8(float64(a) + (float64(b)-float64(a))*t + 0.5)
	}
	for dy := 0; dy < size; dy++ {
		sy := float64(oy) + float64(side-1)*float64(dy)/float64(size-1)
		y0 := int(math.Floor(sy))
		y1 := y0 + 1
		if y1 > oy+side-1 {
			y1 = oy + side - 1
		}
		fy := sy - float64(y0)
		for dx := 0; dx < size; dx++ {
			sx := float64(ox) + float64(side-1)*float64(dx)/float64(size-1)
			x0 := int(math.Floor(sx))
			x1 := x0 + 1
			if x1 > ox+side-1 {
				x1 = ox + side - 1
			}
			fx := sx - float64(x0)
			c00 := toRGBA(src.At(x0, y0))
			c10 := toRGBA(src.At(x1, y0))
			c01 := toRGBA(src.At(x0, y1))
			c11 := toRGBA(src.At(x1, y1))
			dst.SetRGBA(dx, dy, color.RGBA{
				R: lerp(lerp(c00.R, c10.R, fx), lerp(c01.R, c11.R, fx), fy),
				G: lerp(lerp(c00.G, c10.G, fx), lerp(c01.G, c11.G, fx), fy),
				B: lerp(lerp(c00.B, c10.B, fx), lerp(c01.B, c11.B, fx), fy),
				A: lerp(lerp(c00.A, c10.A, fx), lerp(c01.A, c11.A, fx), fy),
			})
		}
	}
	return dst
}

// processIconImage 解码上传的 PNG/JPG 图片，居中裁剪为 1:1 并缩放至 512×512，输出 PNG。
// 在服务端统一处理，可兼容浏览器无法解码图片的环境（前端解码失败时直接上传原图）。
func processIconImage(data []byte) ([]byte, error) {
	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	dst := cropSquareResize(src, 512)
	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// handleDeskIconGet 返回规则当前的桌面图标配置。
func (s *Server) handleDeskIconGet(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少 key 参数"))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.getDeskConfig(key)))
}

// handleDeskIconSave 保存（或删除）规则的桌面图标配置，并同步写入 fnOS 桌面入口。
// multipart 表单：key、enabled、name、type、icon（可选文件）。
func (s *Server) handleDeskIconSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, deskIconMaxBytes+64<<10)
	if err := r.ParseMultipartForm(deskIconMaxBytes + 64<<10); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体过大或非法: "+err.Error()))
		return
	}
	key := r.FormValue("key")
	enabled := r.FormValue("enabled") == "true"
	name := strings.TrimSpace(r.FormValue("name"))
	typ := r.FormValue("type")
	// 外部地址入口（frpc 代理 / Webhook 通道等非转发规则场景）：桌面入口直接打开该完整 URL
	//（仅支持浏览器标签页打开方式，后端 url 模式下会强制 type=url）
	externalURL := strings.TrimSpace(r.FormValue("url"))
	if typ == "" {
		typ = "iframe"
	}
	if typ != "iframe" && typ != "url" {
		s.writeJSON(w, http.StatusOK, apiErr("打开方式仅支持 iframe（桌面窗口）或 url（浏览器标签页）"))
		return
	}

	// 支持统一网关 / TCP / UDP / HTTP 转发规则创建桌面图标；
	// 非网关协议使用端口入口（http://{NAS_IP}:{localPort}），网关协议使用网关前缀入口；
	// 提供 url 字段时使用外部地址入口（无需解析转发规则 key）。
	rule, ruleErr := parseRuleKey(key)
	isGateway := false
	if ruleErr == nil {
		isGateway = rule.Protocol == "gateway" || rule.Protocol == "GATEWAY"
	}

	if !enabled {
		// 关闭桌面图标：删除配置/图标并重建入口（同步），异步卸载空应用并返回任务供进度轮询
		task := s.deleteDeskConfigAsync(key)
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
			"config":      DesktopIconConfig{},
			"task_id":     task.ID,
			"install_msg": "正在卸载桌面图标应用...",
		}))
		return
	}

	// 网关协议使用路径名称作为空应用名；其他协议使用规则 UUID；外部地址入口使用派生稳定名
	deskName := s.deskAppUUID(key)
	if isGateway {
		deskName = rule.Name
	}
	if name == "" {
		name = deskName
	}
	cfg := s.getDeskConfig(key)
	cfg.Enabled = true
	cfg.Name = name
	cfg.Type = typ
	// 桌面访问（可见性）：默认所有用户可见
	cfg.AllUsers = r.FormValue("all_users") != "false"

	// 处理上传的图标文件（服务端统一裁剪压缩，兼容浏览器无法解码的环境）
	if fh, _, err := r.FormFile("icon"); err == nil {
		data, err := io.ReadAll(fh)
		fh.Close()
		if err != nil {
			s.writeJSON(w, http.StatusOK, apiErr("读取图标失败: "+err.Error()))
			return
		}
		if !validIconData(data) {
			s.writeJSON(w, http.StatusOK, apiErr("图标格式不支持，仅支持 PNG/JPG"))
			return
		}
		// 居中裁剪为 1:1 并缩放至 512×512，输出 PNG
		out, err := processIconImage(data)
		if err != nil {
			s.writeJSON(w, http.StatusOK, apiErr("图片无法解码，文件可能已损坏，请换一张 PNG/JPG 图片"))
			return
		}
		iconFile := s.deskIconFile(key)
		if err := os.MkdirAll(s.iconsDir(), 0755); err != nil {
			s.writeJSON(w, http.StatusOK, apiErr("创建图标目录失败: "+err.Error()))
			return
		}
		if err := os.WriteFile(filepath.Join(s.iconsDir(), iconFile), out, 0644); err != nil {
			s.writeJSON(w, http.StatusOK, apiErr("保存图标失败: "+err.Error()))
			return
		}
		cfg.Icon = iconFile
	}

	if err := s.saveDeskConfig(key, cfg); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("保存配置失败: "+err.Error()))
		return
	}
	warning := s.syncDesktopEntries()

	// 生成并安装桌面图标空应用（root 运行时可调用 fnpack/appcenter-cli）。
	// 打包/卸载/安装耗时较长，改为后台异步执行并通过 task_id 向前端提供实时进度；
	// 配置已保存，安装结果由前端轮询 /api/desktop/task 获取。
	installMsg := "桌面图标应用打包安装已开始，请在弹出的进度窗口查看"
	iconPath := ""
	if cfg.Icon != "" {
		iconPath = filepath.Join(s.iconsDir(), cfg.Icon)
	}
	mode := "gateway"
	localPort := 0
	switch {
	case externalURL != "":
		// 外部地址入口（frpc 代理 / Webhook 通道等）：桌面入口直接打开该 URL
		mode = "url"
	case !isGateway:
		mode = "port"
		localPort = rule.LocalPort
	}
	task := s.deskApps.newTask("install")
	go func() {
		// 任务保留在表中供前端轮询读取最终状态，由后续新任务创建时按上限清理
		if err := s.deskApps.install(task, deskName, cfg.Name, cfg.Type, cfg.AllUsers, iconPath, mode, localPort, s.fwdMgr.IsTLS(key), externalURL); err != nil {
			task.setFailed(err)
			s.logger.Error("安装桌面图标应用失败",
				zap.String("rule", deskName),
				zap.Error(err),
			)
		}
	}()

	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"config":      cfg,
		"warning":     warning,
		"install_msg": installMsg,
		"task_id":     task.ID,
	}))
}

// handleDeskTaskGet 返回桌面图标任务的实时进度（打包/卸载/安装），供前端轮询展示。
// 任务不存在（已结束并清理）时返回 data:null。
func (s *Server) handleDeskTaskGet(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("task_id")
	if id == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少 task_id 参数"))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.deskApps.task(id)))
}

// handleDeskIconDelete 删除规则的桌面图标配置（幂等），并异步卸载对应空应用。
func (s *Server) handleDeskIconDelete(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少 key 参数"))
		return
	}
	task := s.deleteDeskConfigAsync(key)
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"key":     key,
		"task_id": task.ID,
	}))
}

// handleDeskIconFile 预览已上传的图标（从应用数据目录提供，仅供前端预览）。
func (s *Server) handleDeskIconFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if name == "" || strings.ContainsAny(name, "/\\") {
		http.NotFound(w, r)
		return
	}
	base := s.iconsDir()
	p := filepath.Join(base, name)
	if !strings.HasPrefix(p, base+string(os.PathSeparator)) {
		http.NotFound(w, r)
		return
	}
	if _, err := os.Stat(p); err != nil {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, p)
}

// syncDesktopEntries 将全部已启用的桌面图标配置写入 fnOS 桌面入口文件 target/ui/config：
// 保留应用静态入口，清理旧的动态入口后按配置重建。
// target 目录不可写时返回 warning（配置仍保存在数据库，可稍后重试）。
func (s *Server) syncDesktopEntries() (warning string) {
	appDest := os.Getenv("TRIM_APPDEST")
	if appDest == "" {
		return "图标配置已保存；当前为本地预览环境，桌面入口需在 fnOS 设备上运行应用后才会生成"
	}
	uiDir := filepath.Join(appDest, "ui")
	configPath := filepath.Join(uiDir, "config")

	var doc map[string]interface{}
	if raw, err := os.ReadFile(configPath); err == nil && len(raw) > 0 {
		json.Unmarshal(raw, &doc)
	}
	if doc == nil {
		doc = map[string]interface{}{}
	}
	urlMap, _ := doc[".url"].(map[string]interface{})
	if urlMap == nil {
		urlMap = map[string]interface{}{}
		doc[".url"] = urlMap
	}

	// 清理旧的动态入口
	for k := range urlMap {
		if strings.HasPrefix(k, deskEntryPrefix) {
			delete(urlMap, k)
		}
	}

	// 收集已启用的桌面图标配置
	deskCfgs, err := s.store.SettingsByPrefix(deskConfigPrefix)
	if err != nil {
		return "读取桌面图标配置失败: " + err.Error()
	}
	written := 0
	for skey, v := range deskCfgs {
		key := strings.TrimPrefix(skey, deskConfigPrefix)
		var cfg DesktopIconConfig
		if json.Unmarshal([]byte(v), &cfg) != nil || !cfg.Enabled {
			continue
		}
		rule, err := parseRuleKey(key)
		if err != nil || !(rule.Protocol == "gateway" || rule.Protocol == "GATEWAY") {
			continue
		}
		entry := map[string]interface{}{
			"title":    cfg.Name,
			"type":     cfg.Type,
			"url":      "/app/TunHook-" + rule.Name,
			"allUsers": cfg.AllUsers,
		}
		if cfg.Icon != "" {
			if err := s.copyIconToUIDir(key, cfg.Icon); err != nil {
				entry["icon"] = "images/icon-{0}.png"
			} else {
				entry["icon"] = "images/" + cfg.Icon
			}
		} else {
			entry["icon"] = "images/icon-{0}.png"
		}
		urlMap[s.deskEntryID(key)] = entry
		written++
	}

	out, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		return "生成入口配置失败: " + err.Error()
	}
	if err := os.WriteFile(configPath, out, 0644); err != nil {
		return fmt.Sprintf("桌面入口写入失败（%s 不可写）: %v（配置已保存在数据库中）", configPath, err)
	}
	s.logger.Info("已同步桌面入口", zap.Int("desk_entries", written), zap.String("config", configPath))
	return ""
}

// copyIconToUIDir 将上传的图标复制到 target/ui/images 目录供 fnOS 桌面入口引用。
func (s *Server) copyIconToUIDir(key, icon string) error {
	appDest := os.Getenv("TRIM_APPDEST")
	if appDest == "" {
		return fmt.Errorf("TRIM_APPDEST 未设置")
	}
	imagesDir := filepath.Join(appDest, "ui", "images")
	if err := os.MkdirAll(imagesDir, 0755); err != nil {
		return err
	}
	src, err := os.ReadFile(filepath.Join(s.iconsDir(), icon))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(imagesDir, icon), src, 0644)
}

// ============= 本地网络信息 =============

// defaultRouteFromProc 解析 /proc/net/route，返回默认路由（Destination=00000000）
// 所在网卡名与网关 IPv4（选择 Metric 最小的一条）。非 Linux 或无默认路由时返回空。
func defaultRouteFromProc() (iface, gateway string) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", ""
	}
	bestMetric := math.MaxUint32
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		if fields[1] != "00000000" { // 仅默认路由
			continue
		}
		var metric int
		fmt.Sscanf(fields[6], "%d", &metric)
		if metric > bestMetric {
			continue
		}
		bestMetric = metric
		iface = fields[0]
		gateway = parseProcRouteIP(fields[2])
	}
	return iface, gateway
}

// parseProcRouteIP 把 /proc/net/route 中的小端十六进制 IP 转为点分十进制。
func parseProcRouteIP(hex string) string {
	if len(hex) != 8 {
		return ""
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
		if err != nil {
			return ""
		}
		b[i] = byte(v)
	}
	// /proc/net/route 中 IP 为小端存储，显示时反转字节序
	return net.IPv4(b[3], b[2], b[1], b[0]).String()
}

// interfaceIPv4 返回指定网卡上第一个非回环/链路本地的 IPv4 地址。
func interfaceIPv4(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
			continue
		}
		return ip4.String()
	}
	return ""
}

// primaryLocalIPv4 返回本机主用局域网 IPv4：
// 优先取默认路由所在网卡的地址，否则取第一个全局单播 IPv4。
func primaryLocalIPv4() string {
	iface, _ := defaultRouteFromProc()
	if iface != "" {
		if ip := interfaceIPv4(iface); ip != "" {
			return ip
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsMulticast() {
			continue
		}
		return ip4.String()
	}
	return ""
}

// primaryLocalIPv6 返回本机主用局域网 IPv6：
// 优先返回全局单播地址，其次 ULA（fc00::/7）；跳过回环/链路本地（fe80::）/组播/未指定地址。
func primaryLocalIPv6() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	ula := ""
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.To4() != nil {
				continue // 仅保留 IPv6
			}
			ip6 := ip.To16()
			if ip6 == nil || ip6.IsLoopback() || ip6.IsLinkLocalUnicast() || ip6.IsMulticast() || ip6.IsUnspecified() {
				continue
			}
			if ip6[0]&0xfe == 0xfc { // fc00::/7 ULA 地址，暂存备用
				if ula == "" {
					ula = ip6.String()
				}
				continue
			}
			return ip6.String() // 全局单播地址，立即返回
		}
	}
	return ula
}

// refreshLocalNetworkInfo 刷新本地 IPv4/IPv6 与网关缓存。
func (s *Server) refreshLocalNetworkInfo() {
	localIP := primaryLocalIPv4()
	localIPv6 := primaryLocalIPv6()
	_, gatewayIP := defaultRouteFromProc()
	s.mu.Lock()
	s.localIP = localIP
	s.localIPv6 = localIPv6
	s.gatewayIP = gatewayIP
	s.mu.Unlock()
	s.logger.Info("本地网络信息已刷新",
		zap.String("local_ip", localIP),
		zap.String("local_ipv6", localIPv6),
		zap.String("gateway", gatewayIP),
	)
}

// ============= 公网地址探测 =============

// publicIPTTL 公网地址探测成功结果的缓存时长（避免频繁请求外部回显服务）。
const publicIPTTL = 10 * time.Minute

// publicIPRetry 首次探测失败后的重试间隔（外部服务抖动时快速补探）。
const publicIPRetry = time.Minute

// publicIPV4Probes 公网 IPv4 回显服务列表（按顺序尝试，均需返回纯文本 IP）。
var publicIPV4Probes = []string{
	"https://ipv4.icanhazip.com",
	"https://api-ipv4.ip.sb/ip",
	"https://ipinfo.io/ip",
}

// publicIPV6Probes 公网 IPv6 回显服务列表（按顺序尝试，均需返回纯文本 IP）。
var publicIPV6Probes = []string{
	"https://ipv6.icanhazip.com",
	"https://api-ipv6.ip.sb/ip",
}

// handlePublicIP 返回本机公网 IPv4/IPv6 地址：
// 依次请求外部回显服务，IPv4 失败时回退客户端上报的公网地址；结果缓存 publicIPTTL。
// 传 ?refresh=1 可强制重新探测。
func (s *Server) handlePublicIP(w http.ResponseWriter, r *http.Request) {
	refresh := r.URL.Query().Get("refresh") == "1"
	s.mu.Lock()
	if refresh || s.pubIPTime.IsZero() || time.Since(s.pubIPTime) >= publicIPTTL {
		nv4, nv6 := s.detectPublicIP()
		got := nv4 != "" || nv6 != ""
		// 探测失败且已有旧缓存时保留旧值（避免一次网络抖动清空已获取的地址）
		if got || (s.pubIPv4 == "" && s.pubIPv6 == "") {
			s.pubIPv4, s.pubIPv6 = nv4, nv6
		}
		switch {
		case got:
			s.pubIPTime = time.Now() // 成功：缓存 publicIPTTL
		case s.pubIPTime.IsZero():
			// 首次探测失败：publicIPRetry 后重试，避免长时间空白
			s.pubIPTime = time.Now().Add(-publicIPTTL + publicIPRetry)
		default:
			// 已有旧值且本次失败：保留旧值并顺延缓存，避免外部服务故障时频繁重探
			s.pubIPTime = time.Now()
		}
	}
	v4, v6, ts := s.pubIPv4, s.pubIPv6, s.pubIPTime
	s.mu.Unlock()
	// 基于公网地址做 CGNAT/可直连判定（与 STUN 探测共用同一判定逻辑）。
	isCGNAT, directOK := stunprobe.ClassifyPublicIP(v4)
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"ipv4":      v4,
		"ipv6":      v6,
		"cached_at": ts.Format("2006-01-02 15:04:05"),
		"nat": map[string]interface{}{
			"cgnat":     isCGNAT,
			"direct_ok": directOK,
		},
	}))
}

// detectPublicIP 探测本机公网地址（每次调用发起网络请求，调用方负责缓存）：
//   - 按配置的获取方式（curl/http）与 v4/v6 回显 URL 抓取，失败回退内置 probes；
//   - IPv4 全部失败时回退 STUN 客户端上报的公网地址；
//   - IPv6 仅当本机存在全局/ULA IPv6 地址时尝试（避免无 IPv6 网络时无谓等待）。
func (s *Server) detectPublicIP() (v4, v6 string) {
	cfg := s.loadPubIPSrcCfg()
	const timeout = 5 * time.Second

	fetch := func(url string, wantV6 bool) string {
		var text string
		if cfg.Method == "http" {
			text = httpFetch(url, timeout)
		} else {
			text = curlFetch(url, timeout)
		}
		return validIPText(text, wantV6)
	}

	if cfg.V4URL != "" {
		v4 = fetch(cfg.V4URL, false)
	}
	if v4 == "" {
		v4 = probePublicIP(publicIPV4Probes, false)
		if v4 == "" {
			v4 = s.systemPublicIP()
		}
	}
	if primaryLocalIPv6() != "" {
		if cfg.V6URL != "" {
			v6 = fetch(cfg.V6URL, true)
		}
		if v6 == "" {
			v6 = probePublicIP(publicIPV6Probes, true)
		}
	}
	return v4, v6
}

// probePublicIP 依次请求回显服务返回纯文本 IP；首个有效结果即返回，全部失败返回空。
// wantV6=true 时仅接受 IPv6 地址（出站经代理/NAT64 时 IPv6 服务可能回显 IPv4，需跳过）。
func probePublicIP(urls []string, wantV6 bool) string {
	client := &http.Client{Timeout: 3 * time.Second}
	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		resp.Body.Close()
		ip := strings.TrimSpace(string(body))
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if wantV6 && parsed.To4() != nil {
			continue // 期望 IPv6 但返回 IPv4，跳过
		}
		return ip
	}
	return ""
}

// ============= Status =============

// handlePing 空响应，供面板测量「面板 ↔ 宿主机」的往返延迟。
// 204 省去序列化与服务端处理时间，结果更接近真实网络 RTT；该路径不记录访问日志。
func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	localIP := s.localIP
	gatewayIP := s.gatewayIP
	s.mu.RUnlock()

	// 设备时间：server_time 为 Unix 秒，utc_offset 为设备时区偏移（秒）；
	// 前端据此把浏览器时钟校正为设备墙上时间并每秒推进。
	now := time.Now()
	_, utcOffset := now.Zone()

	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"version":       "0.6.6.172",
		"uptime":        int(time.Since(s.startTime).Seconds()),
		"forward_count": len(s.fwdMgr.RunningRules()),
		"local_ip":      localIP,
		"local_ipv6":    s.localIPv6,
		"gateway":       gatewayIP,
		"public_ip":     s.systemPublicIP(),
		"hostname":      systemHostname(),
		"os_version":    systemOSVersion(),
		"server_time":   now.Unix(),
		"utc_offset":    utcOffset,
	}))
}

// systemHostname 返回设备主机名；读取失败返回空串。
func systemHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}

// systemOSVersion 取 /etc/os-release 的 PRETTY_NAME 作为设备操作系统版本；
// 非 Linux 或读取失败时回退为运行时系统标识（linux / darwin / windows）。
func systemOSVersion() string {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "PRETTY_NAME=") {
				continue
			}
			v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "PRETTY_NAME=")), `"`)
			if v != "" {
				return v
			}
		}
	}
	return runtime.GOOS
}

// systemMemTotalKB 读取 /proc/meminfo 的 MemTotal（单位 kB），失败返回 0。
func systemMemTotalKB() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			var kb uint64
			if _, err := fmt.Sscanf(line, "MemTotal: %d kB", &kb); err == nil {
				return kb
			}
			return 0
		}
	}
	return 0
}

// systemMemUsedKB 读取 /proc/meminfo 计算系统已用内存 = MemTotal - MemAvailable（单位 kB），失败返回 0。
func systemMemUsedKB() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	var total, available uint64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(line, "MemTotal: %d kB", &total)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fmt.Sscanf(line, "MemAvailable: %d kB", &available)
		}
		if total > 0 && available > 0 {
			break
		}
	}
	if total > available {
		return total - available
	}
	return 0
}

// systemLoadAvg 读取 /proc/loadavg 的 1/5/15 分钟平均负载，失败（非 Linux）返回 0。
func systemLoadAvg() (float64, float64, float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	var l1, l5, l15 float64
	if _, err := fmt.Sscanf(string(data), "%f %f %f", &l1, &l5, &l15); err != nil {
		return 0, 0, 0
	}
	return l1, l5, l15
}

// readCPUStat 读取 /proc/stat 首行（cpu 汇总）的 idle 与 total 计数。
func readCPUStat() (uint64, uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	// 仅解析第一行（cpu 汇总），避免把后续行的中断/上下文切换等计数并入 total
	line := string(data)
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	parts := strings.Fields(line)
	if len(parts) == 0 || parts[0] != "cpu" {
		return 0, 0
	}
	var fields []uint64
	for _, p := range parts[1:] {
		var v uint64
		if _, err := fmt.Sscanf(p, "%d", &v); err == nil {
			fields = append(fields, v)
		}
	}
	if len(fields) < 4 {
		return 0, 0
	}
	var total uint64
	for _, v := range fields {
		total += v
	}
	idle := fields[3]
	if len(fields) >= 5 {
		idle += fields[4] // iowait 计入空闲
	}
	return idle, total
}

// cpuPercent 两次采样 /proc/stat 计算系统 CPU 使用率（百分比）。
func cpuPercent() float64 {
	idle1, total1 := readCPUStat()
	time.Sleep(200 * time.Millisecond)
	idle2, total2 := readCPUStat()
	if total2 <= total1 {
		return 0
	}
	return (1 - float64(idle2-idle1)/float64(total2-total1)) * 100
}

// handleSystemStats 返回系统资源信息：版本、运行时长、CPU/内存占用率、进程/协程数。
func (s *Server) handleSystemStats(w http.ResponseWriter, r *http.Request) {
	memTotalKB := systemMemTotalKB()
	memUsedKB := systemMemUsedKB()
	memPercent := 0.0
	if memTotalKB > 0 {
		memPercent = float64(memUsedKB) / float64(memTotalKB) * 100
	}
	load1, load5, load15 := systemLoadAvg()

	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"version":      "0.6.6.172",
		"uptime":       int(time.Since(s.startTime).Seconds()),
		"cpu_percent":  math.Round(cpuPercent()*10) / 10,
		"mem_percent":  math.Round(memPercent*10) / 10,
		"disk_percent": systemDiskPercent(),
		"load1":        math.Round(load1*100) / 100,
		"load5":        math.Round(load5*100) / 100,
		"load15":       math.Round(load15*100) / 100,
		"mem_used_mb":  math.Round(float64(memUsedKB)/1024*10) / 10,
		"mem_total_mb": math.Round(float64(memTotalKB)/1024*10) / 10,
		"processes":    systemProcCount(),
		"goroutines":   runtime.NumGoroutine(),
		"go_version":   runtime.Version(),
	}))
}

// systemProcCount 返回系统当前进程数（Linux 统计 /proc 下数字目录个数）。
// 非 Linux 或读取失败时返回 0。
func systemProcCount() int {
	if runtime.GOOS != "linux" {
		return 0
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err == nil {
			count++
		}
	}
	return count
}

// systemNetBytes 读取 /proc/net/dev 汇总所有非回环网卡的接收/发送字节数。
// 非 Linux 或读取失败时返回 0。
func systemNetBytes() (rx, tx uint64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n")[2:] {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:idx])
		if iface == "lo" {
			continue // 排除回环接口
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 9 {
			continue
		}
		var r, t uint64
		fmt.Sscanf(fields[0], "%d", &r) // 第 1 列：接收字节数
		fmt.Sscanf(fields[8], "%d", &t) // 第 9 列：发送字节数
		rx += r
		tx += t
	}
	return rx, tx
}

// handleSystemNet 返回系统实时网络速率（基于 /proc/net/dev 两次采样的差值）。
// 返回每秒接收/发送字节数；首次调用（无上次采样）返回 0。
func (s *Server) handleSystemNet(w http.ResponseWriter, r *http.Request) {
	rx, tx := systemNetBytes()
	now := time.Now()

	s.netMu.Lock()
	rxRate := 0.0
	txRate := 0.0
	if !s.netLast.IsZero() {
		dt := now.Sub(s.netLast).Seconds()
		if dt > 0 {
			if rx >= s.netRx {
				rxRate = float64(rx-s.netRx) / dt
			}
			if tx >= s.netTx {
				txRate = float64(tx-s.netTx) / dt
			}
		}
	}
	s.netLast = now
	s.netRx = rx
	s.netTx = tx
	s.netMu.Unlock()

	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"rx":       math.Round(rxRate*10) / 10,
		"tx":       math.Round(txRate*10) / 10,
		"rx_total": rx,
		"tx_total": tx,
	}))
}

// trafficModeLabel 返回流量统计模式的描述文本（用于查询历史记录）。
func trafficModeLabel(mode string) string {
	switch mode {
	case "1h":
		return "最近 1 小时（每分钟 1 个采样点）"
	case "7h":
		return "最近 7 小时（每分钟 1 个采样点）"
	case "12h":
		return "最近 12 小时（每分钟 1 个采样点）"
	case "24h":
		return "最近 24 小时（每分钟 1 个采样点）"
	default:
		return "实时（最近 10 分钟，每秒 1 个采样点）"
	}
}

// handleTrafficStats 返回流量统计曲线数据。
// mode: realtime（最近 10 分钟 / 1s 采样）| 1h（最近 1 小时 / 1m 聚合）| 24h（最近 24 小时 / 1m 聚合）。
// record=1 时记录一条查询历史（仅用户切换模式 / 手动刷新时由前端携带）。
func (s *Server) handleTrafficStats(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "realtime"
	}
	record := r.URL.Query().Get("record") == "1"

	now := time.Now()
	var points []store.TrafficSample
	sampling := "1s"
	var rangeInfo map[string]interface{}
	switch mode {
	case "1h":
		sampling = "1m"
		ps, err := s.store.QueryTrafficSamples(now.Add(-time.Hour).Unix(), now.Unix(), 60)
		if err != nil {
			s.logger.Warn("查询1小时流量统计失败", zap.Error(err))
		} else {
			points = ps
		}
	case "7h":
		sampling = "1m"
		ps, err := s.store.QueryTrafficSamples(now.Add(-7*time.Hour).Unix(), now.Unix(), 60)
		if err != nil {
			s.logger.Warn("查询7小时流量统计失败", zap.Error(err))
		} else {
			points = ps
		}
	case "12h":
		sampling = "1m"
		ps, err := s.store.QueryTrafficSamples(now.Add(-12*time.Hour).Unix(), now.Unix(), 60)
		if err != nil {
			s.logger.Warn("查询12小时流量统计失败", zap.Error(err))
		} else {
			points = ps
		}
	case "24h":
		sampling = "1m"
		ps, err := s.store.QueryTrafficSamples(now.Add(-24*time.Hour).Unix(), now.Unix(), 60)
		if err != nil {
			s.logger.Warn("查询24小时流量统计失败", zap.Error(err))
		} else {
			points = ps
		}
	case "history":
		// 历史区间查询（24 小时之前的数据）：from/to 为 Unix 秒，按小时聚合
		sampling = "1h"
		nowU := now.Unix()
		from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
		to, _ := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
		if to <= 0 || to > nowU {
			to = nowU
		}
		if from <= 0 || from >= to {
			from = to - 7*86400
		}
		// 限制在保留期内
		s.cfgMu.RLock()
		days := s.cfg.Log.TrafficRetentionDays
		s.cfgMu.RUnlock()
		if days <= 0 {
			days = 31
		}
		if min := nowU - int64(days)*86400; from < min {
			from = min
		}
		if from >= to {
			from = to - 3600
		}
		ps, err := s.store.QueryTrafficSamples(from, to, 3600)
		if err != nil {
			s.logger.Warn("查询历史流量统计失败", zap.Error(err))
		} else {
			points = ps
		}
		rangeInfo = map[string]interface{}{"from": from, "to": to}
	default: // realtime：直接返回内存环形缓冲（秒级，最新）
		mode = "realtime"
		s.trafficRingMu.Lock()
		points = append([]store.TrafficSample{}, s.trafficRing...)
		s.trafficRingMu.Unlock()
	}

	if record {
		if err := s.store.InsertTrafficQueryRecord(mode, now.Unix(), trafficModeLabel(mode)); err != nil {
			s.logger.Warn("写入流量查询历史失败", zap.Error(err))
		}
	}

	s.cfgMu.RLock()
	days := s.cfg.Log.TrafficRetentionDays
	s.cfgMu.RUnlock()
	if days <= 0 {
		days = 31
	}

	// 累计流量：实时模式展示设备总累计（/proc/net/dev 原始计数器）；
	// 非实时模式（1h/7h/12h/24h/history）展示所选时间区间内的累计 = Σ(采样速率 × 相邻间隔)。
	var rxTotal, txTotal int64
	if mode == "realtime" {
		rxu, txu := systemNetBytes()
		rxTotal, txTotal = int64(rxu), int64(txu)
	} else {
		var sec int64 = 60 // 默认按分钟采样
		for i := 0; i < len(points); i++ {
			if i+1 < len(points) && points[i+1].TS > points[i].TS {
				sec = points[i+1].TS - points[i].TS
			}
			rxTotal += points[i].RX * sec
			txTotal += points[i].TX * sec
		}
	}

	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"mode":           mode,
		"points":         points,
		"sampling":       sampling,
		"retention_days": days,
		"rx_total":       rxTotal,
		"tx_total":       txTotal,
		"server_time":    now.Unix(),
		"range":          rangeInfo,
	}))
}

// handleTrafficHistory 返回流量统计查询历史记录（新→旧，最多 500 条）。
func (s *Server) handleTrafficHistory(w http.ResponseWriter, r *http.Request) {
	records, err := s.store.ListTrafficQueryRecords(500)
	if err != nil {
		s.logger.Warn("读取流量查询历史失败", zap.Error(err))
		records = nil
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"records": records}))
}

// cleanupTrafficSamples 按配置保留天数清理超期采样，并裁剪查询历史至最近 500 条。
func (s *Server) cleanupTrafficSamples() {
	s.cfgMu.RLock()
	days := s.cfg.Log.TrafficRetentionDays
	s.cfgMu.RUnlock()
	if days <= 0 {
		days = 31
	}
	cutoff := time.Now().AddDate(0, 0, -days).Unix()
	n, err := s.store.DeleteTrafficSamplesBefore(cutoff)
	if err != nil {
		s.logger.Warn("清理流量采样失败", zap.Error(err))
		return
	}
	if n > 0 {
		s.logger.Info("流量采样已清理", zap.Int64("removed", n), zap.Int("days", days))
	}
	if err := s.store.TrimTrafficQueryHistory(500); err != nil {
		s.logger.Warn("清理流量查询历史失败", zap.Error(err))
	}
}

// handleSystemConns 返回宿主机实时连接数（基于 /proc/net/{tcp,tcp6,udp,udp6}）。
// 字段：total 总连接数、tcp TCP 会话（所有状态）、tcp_established 已建立 TCP、listen 监听端口、udp UDP 会话。
func (s *Server) handleSystemConns(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, apiOK(systemConnStats()))
}

// systemConnStats 统计宿主机当前连接数。非 Linux 或读取失败时返回全 0。
func systemConnStats() map[string]int {
	out := map[string]int{"total": 0, "tcp": 0, "tcp_established": 0, "listen": 0, "udp": 0}
	if runtime.GOOS != "linux" {
		return out
	}
	// TCP：/proc/net/tcp 与 tcp6，第 4 列为状态（0A=LISTEN，01=ESTABLISHED）；每行均为一个 TCP 会话
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			out["total"]++
			out["tcp"]++
			switch fields[3] {
			case "0A":
				out["listen"]++
			case "01":
				out["tcp_established"]++
			}
		}
	}
	// UDP：/proc/net/udp 与 udp6，每行一个会话
	for _, f := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] {
			if strings.TrimSpace(line) == "" {
				continue
			}
			out["total"]++
			out["udp"]++
		}
	}
	return out
}

// handleSystemConnsDetail 返回宿主机当前 TCP/UDP 连接明细列表。
func (s *Server) handleSystemConnsDetail(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, apiOK(systemConnDetails()))
}

// handleSystemProcesses 返回宿主机当前进程列表。
func (s *Server) handleSystemProcesses(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, apiOK(systemProcessDetails()))
}

// systemConnDetails 解析 /proc/net/{tcp,tcp6,udp,udp6}，返回连接明细。
// 非 Linux 或读取失败时返回空列表。
func systemConnDetails() []map[string]interface{} {
	if runtime.GOOS != "linux" {
		return []map[string]interface{}{}
	}
	var out []map[string]interface{}
	// 每个条目：proto(协议) local(本地地址:端口) remote(远端地址:端口) state(状态) uid(用户) inode
	parse := func(path, proto string, states map[string]string, readRemote bool) {
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			local := decodeSockAddr(fields[1])
			remote := ""
			if readRemote {
				remote = decodeSockAddr(fields[2])
			}
			state := states[fields[3]]
			if state == "" {
				state = "状态 " + fields[3]
			}
			uid, _ := strconv.Atoi(fields[7])
			inode := int64(0)
			if len(fields) > 9 {
				inode, _ = strconv.ParseInt(fields[9], 10, 64)
			}
			out = append(out, map[string]interface{}{
				"proto": proto, "local": local, "remote": remote, "state": state, "uid": uid, "inode": inode,
			})
		}
	}
	parse("/proc/net/tcp", "TCP", tcpStates, true)
	parse("/proc/net/tcp6", "TCP", tcpStates, true)
	parse("/proc/net/udp", "UDP", udpStates, true)
	parse("/proc/net/udp6", "UDP", udpStates, true)
	return out
}

// tcpStates /proc/net/tcp 第 4 列状态码 → 中文语义。
var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
	"06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN",
	"0B": "CLOSING", "0C": "NEW_SYN_RECV",
}

// udpStates UDP 无连接状态码语义（07=未连接，01=已连接）。
var udpStates = map[string]string{
	"01": "已连接", "07": "未连接",
}

// decodeSockAddr 解析 /proc/net 的十六进制 "地址:端口" 为可读 "IP:端口"。
// IPv4 与 IPv6（tcp6/udp6）地址字节序不同。
func decodeSockAddr(hex string) string {
	parts := strings.SplitN(hex, ":", 2)
	if len(parts) != 2 {
		return hex
	}
	port := int64(0)
	if v, err := strconv.ParseInt(parts[1], 16, 64); err == nil {
		port = v
	}
	ip := hexIP(parts[0])
	return net.JoinHostPort(ip, strconv.FormatInt(port, 10))
}

// hexIP 把 hex 地址转为 IP 字符串（IPv4 为 4 字节小端序，IPv6 为按 4 字节组小端序）。
func hexIP(hex string) string {
	h := strings.TrimSpace(hex)
	if h == "" {
		return "0.0.0.0"
	}
	// 8 位十六进制 = IPv4 小端序
	if len(h) == 8 {
		var b [4]byte
		for i := 0; i < 4; i++ {
			v, _ := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
			b[i] = byte(v)
		}
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	// 32 位十六进制 = IPv6，每 4 字节一组小端序
	if len(h) == 32 {
		var b [16]byte
		for g := 0; g < 4; g++ {
			for i := 0; i < 4; i++ {
				v, _ := strconv.ParseUint(h[(g*4+i)*2:(g*4+i)*2+2], 16, 8)
				b[g*4+3-i] = byte(v)
			}
		}
		return net.IP(b[:]).String()
	}
	return h
}

// systemProcessDetails 解析 /proc 下的进程快照，返回进程列表。
// 非 Linux 或读取失败时返回空列表。
func systemProcessDetails() []map[string]interface{} {
	if runtime.GOOS != "linux" {
		return []map[string]interface{}{}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []map[string]interface{}{}
	}
	out := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		name, state, mem := readProcInfo(pid)
		if name == "" {
			name = e.Name()
		}
		out = append(out, map[string]interface{}{
			"pid": pid, "name": name, "state": state, "mem_mb": mem,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["pid"].(int) < out[j]["pid"].(int)
	})
	return out
}

// readProcInfo 读取单个进程的名称 / 状态 / 内存占用(MB)。
func readProcInfo(pid int) (name, state string, memMB float64) {
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return
	}
	// 格式：pid (comm) state ppid ... 其中 comm 可能含空格/括号，需按最后一个 ')' 切分
	s := string(stat)
	first := strings.Index(s, "(")
	last := strings.LastIndex(s, ")")
	if first < 0 || last < 0 || last <= first+1 {
		return
	}
	name = s[first+1 : last]
	rest := strings.Fields(s[last+2:])
	if len(rest) < 1 {
		return
	}
	state = rest[0]
	mem := "0"
	if status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status")); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "VmRSS:" {
				mem = f[1]
				break
			}
		}
	}
	if mb, err := strconv.ParseFloat(mem, 64); err == nil {
		memMB = math.Round(mb/1024*100) / 100
	}
	return
}

func (s *Server) handleIcon(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/icon.png")
	if err != nil {
		http.Error(w, "未找到", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "页面未找到", http.StatusNotFound)
		return
	}
	// 基于页面内容生成 ETag：配合 Cache-Control: no-cache，浏览器每次请求都会重新验证，
	// 内容更新（重新编译部署）后必定获取最新页面，避免旧页面缓存导致改动“不生效”。
	etag := `"` + fmt.Sprintf("%x", sha1.Sum(data)) + `"`
	if inm := r.Header.Get("If-None-Match"); inm == etag {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 页面内容随版本更新（内联脚本/样式），禁止浏览器缓存旧版页面，
	// 否则重启服务后仍显示旧界面导致功能异常（如日志弹窗按钮失效）。
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	// SAMEORIGIN：允许 fnOS 应用中心同源窗口嵌入；跨源仍拒绝，防点击劫持。
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// 前端为 Svelte 构建产物（外部 JS/CSS），但 index.html 头部保留了一段
	// 内联脚本（推断统一网关前缀设置图标地址），必须放行 'unsafe-inline'。
	// img-src 放行 data: 供网页图标（favicon）抓取结果与 canvas 裁剪预览使用。
	// frame-src 仅放行 MEFrp 官方人机验证页：MEFrp 页签到弹窗以 iframe 内嵌该页，
	// 不开 frame-src 会回退到 default-src 'self' 被浏览器拦截（白屏）。
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-src https://www.mefrp.com; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Write(data)
}

func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		// 取消后台网络任务：正在进行的 IP 归属地数据源检测/下载会立即返回，
		// 否则 bgWG.Wait() 需等整轮跑完，关服可能卡住数分钟乃至更久
		s.stopCancel()
	})
	if s.logCleanupTicker != nil {
		s.logCleanupTicker.Stop()
	}
	// 关闭前最后一次持久化累计流量统计（转发），防止统计数据丢失
	s.persistAllTraffic()
	// 先停止打洞通道：取消上下文后 UPnP 协程会主动删除网关端口映射，
	// 必须在进程退出前完成（仅回收资源，不改启用状态，重启后自动恢复）
	if s.stunholeMgr != nil {
		s.stunholeMgr.StopAll()
	}
	// 停止所有 Cloudflare 隧道实例进程（自启意图不改，重启后按 AutoStart 恢复）
	s.cfStopAll()
	// 停止所有本地静态站点（自启意图不改，重启后按 AutoStart 恢复）
	s.wsStopAll()
	s.fwdMgr.StopAll()
	s.fwdMgr.Close()
	if s.ln != nil {
		s.ln.Close()
	}
	if s.socketLn != nil {
		s.socketLn.Close()
	}
	s.stopWhListener()
	if s.socketPath != "" {
		os.Remove(s.socketPath)
	}
	s.bgWG.Wait()
}
