// Package frpc 提供 frp 客户端（frpc）的集成管理：
// 安装（内置/离线包）、配置生成、启停进程、版本升级与运行状态查询。
// 运行数据统一存放在 dataDir/frp/ 下（frpc 二进制、frpc.toml、frpc.json、frpc.log）。
package frpc

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"tunhook/procutil"

	"github.com/pelletier/go-toml/v2"
	"go.uber.org/zap"
)

const (
	BinName            = "frpc"
	ConfigFile         = "frpc.toml"
	ConfigJSON         = "frpc.json"
	LogFile            = "frpc.log"
	VersionFile        = "version"
	PackagesDir        = "packages"
	DefaultPort        = 7000
	DefaultStunServer  = "stun.miwifi.com:3478"
	MaxServers         = 6    // 服务器实例数量上限
	AdminPortBase      = 7400 // frpc 管理 API 基础端口：多实例按列表位置分配 7400+i
	AdminPortMax       = 7450 // 管理端口上限（实例超过 50 时循环复用）
	archiveNameRe      = `^frp_([\d.]+)_linux_(amd64|arm64)\.tar\.gz$`
	validVersionRe     = `^\d+\.\d+\.\d+$`
	latestProbeTimeout = 6 * time.Second // 单个源解析最新版号的超时（并发探测，死源不拖累整体）
	latestProbeTotal   = 8 * time.Second // 解析最新版号的整体超时
	downloadTimeout    = 5 * time.Minute
)

var (
	archiveRe  = regexp.MustCompile(archiveNameRe)
	versionRe  = regexp.MustCompile(validVersionRe)
	hostnameRe = regexp.MustCompile(`[^a-zA-Z0-9._\-]`) // 清理宿主机名中的非法字符（frp user 仅允许字母数字 . _ -）
)

// frpGitHubRaw frp 官方仓库地址。
const frpGitHubRaw = "https://github.com/fatedier/frp"

// frpLatestProbeFile 用于探测最新 tag 的占位文件名：该文件在 release 资产中并不存在，
// 但 GitHub 对 releases/latest/download/<file> 一律先 302 到 /releases/download/<tag>/<file>，
// 不跟随重定向即可从 Location 取出最新 tag（不走 api.github.com，免触发未认证限流 403）。
const frpLatestProbeFile = "frp_latest_linux_amd64.tar.gz"

// frpMirror 一个 GitHub 资源源：prefix 为空表示官方源；国内镜像均为 URL 前缀代理，
// 把完整 GitHub 链接原样拼在 prefix 之后即可。
type frpMirror struct {
	name   string
	prefix string
}

// frpGitHubMirrors 候选源表：官方 + 国内公益加速镜像，与 cloudflared 模块的候选表保持同步。
// 公益域名会不定期失效或变慢，全部登记、用时实测（版本号并发探测、下载顺序回退），不写死单一源。
var frpGitHubMirrors = []frpMirror{
	{"官方 GitHub", ""},
	{"gh.catmak.name", "https://gh.catmak.name/"},
	{"fastgit.cc", "https://fastgit.cc/"},
	{"gh-proxy.com", "https://gh-proxy.com/"},
	{"gh.dpik.top", "https://gh.dpik.top/"},
	{"gh.acmsz.top", "https://gh.acmsz.top/"},
	{"ghfast.top", "https://ghfast.top/"},
	{"gh.idayer.com", "https://gh.idayer.com/"},
	{"ghproxy.net", "https://ghproxy.net/"},
}

// HealthCheck 代理健康检查配置（frp healthCheck，type 为空表示关闭）。
type HealthCheck struct {
	Type            string `json:"type"` // tcp | http | ""（关闭）
	IntervalSeconds int    `json:"interval_seconds"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	MaxFailed       int    `json:"max_failed"`
	Path            string `json:"path"`
}

// Proxy 一条 frp 代理规则（参考 frp 官方文档基础/进阶配置）。
type Proxy struct {
	Name               string       `json:"name"`
	Type               string       `json:"type"` // tcp | udp | http | https | stcp | xtcp
	Enabled            bool         `json:"enabled"`
	Server             string       `json:"server,omitempty"` // 归属服务器名（空=激活服务器，规范化时补齐）
	LocalIP            string       `json:"local_ip"`
	LocalPort          int          `json:"local_port"`
	RealLocalPort      int          `json:"real_local_port,omitempty"` // http/https 经 TunHook 反代时的真实后端端口（LocalPort 为反代端口）
	ViaTunHook         bool         `json:"via_tunhook"`               // http 代理是否经 TunHook 反代（记录访客真实 IP）；无 omitempty：关闭(false)也写入，保证重启后状态不丢
	RemotePort         int          `json:"remote_port"`               // TCP/UDP 服务端绑定端口，0=由服务端自动分配
	CustomDomains      string       `json:"custom_domains"`
	Subdomain          string       `json:"subdomain"`
	HTTPUser           string       `json:"http_user"`
	HTTPPassword       string       `json:"http_password"`
	Encryption         bool         `json:"encryption"`                     // transport.useEncryption
	Compression        bool         `json:"compression"`                    // transport.useCompression
	BandwidthLimit     string       `json:"bandwidth_limit"`                // transport.bandwidthLimit，如 "10MB"/"512KB"，空=不限
	BandwidthLimitMode string       `json:"bandwidth_limit_mode,omitempty"` // transport.bandwidthLimitMode：client/server，空=跟随服务端默认
	SecretKey          string       `json:"secret_key"`                     // STCP/XTCP 安全密钥（访问端需配置相同密钥）
	HealthCheck        *HealthCheck `json:"health_check,omitempty"`
}

// Server 一个 frp 服务器实例配置（以唯一名称标识，支持多实例快速切换）。
// 除基础连接信息外，还保存该实例的客户端级参数（对应 frpc 客户端配置）。
type Server struct {
	Name                   string `json:"name"`
	Addr                   string `json:"addr"`
	Port                   int    `json:"port"`
	Token                  string `json:"token"`
	User                   string `json:"user"`                      // 用户名称（留空默认使用宿主机名称）
	Protocol               string `json:"protocol"`                  // transport.protocol: tcp/kcp/quic/websocket，默认 tcp
	PoolCount              int    `json:"pool_count"`                // transport.poolCount 预建立连接池数量
	QuicKeepalivePeriod    int    `json:"quic_keepalive_period"`     // transport.quic.keepalivePeriod（秒，默认10，仅 QUIC 生效）
	QuicMaxIdleTimeout     int    `json:"quic_max_idle_timeout"`     // transport.quic.maxIdleTimeout（秒，默认30，仅 QUIC 生效）
	QuicMaxIncomingStreams int    `json:"quic_max_incoming_streams"` // transport.quic.maxIncomingStreams（默认100000，仅 QUIC 生效）
	StunServer             string `json:"stun_server"`               // natHoleStunServer（xtcp 打洞 STUN 服务器）
	ProxyProtocol          string `json:"proxy_protocol"`            // 代理默认 proxy protocol 版本：""关闭 / v1 / v2（写入各代理 transport.proxyProtocolVersion）
	TcpMux                 *bool  `json:"tcp_mux"`                   // transport.tcpMux（nil=默认开启）
	UseEncryption          bool   `json:"use_encryption"`            // 代理默认传输加密（写入各代理 transport.useEncryption）
	UseCompression         bool   `json:"use_compression"`           // 代理默认传输压缩（写入各代理 transport.useCompression）
	LogDays                int    `json:"log_days"`                  // log.maxDays 日志保留天数
	AdminPort              int    `json:"admin_port"`                // 本实例 frpc 管理 API 端口（多实例各自独立，首次分配后保持稳定，仅冲突时重分配）
	AutoStartOn            *bool  `json:"auto_start,omitempty"`      // 开机自启（nil=默认开启；默认服务器强制开启）
}

// Config frpc 客户端配置（持久化为 dataDir/frp/frpc.json）。
type Config struct {
	Servers      []Server `json:"servers"`
	ActiveServer string   `json:"active_server"`
	LogLevel     string   `json:"log_level"`
	LogEntries   int      `json:"log_entries"` // frpc.log 日志文件保留行数（0=不限制）
	LogDays      int      `json:"log_days"`    // 客户端级日志保留天数（log.maxDays，0=不限制/跟随服务器）
	Proxies      []Proxy  `json:"proxies"`
}

// Active 返回当前激活的服务器配置（按名称匹配，未匹配时回退第一个）。
func (c Config) Active() (Server, bool) {
	for _, s := range c.Servers {
		if s.Name == c.ActiveServer {
			return s, true
		}
	}
	if len(c.Servers) > 0 {
		return c.Servers[0], true
	}
	return Server{}, false
}

// DefaultServerName 服务器列表为空或迁移失败时的默认名称。
const DefaultServerName = "默认服务器"

// ServerStatus 单台服务器的运行状态。
type ServerStatus struct {
	Name        string `json:"name"`
	Configured  bool   `json:"configured"` // 已配置有效地址
	Running     bool   `json:"running"`
	PID         int    `json:"pid"`
	AdminPort   int    `json:"admin_port"`
	AutoStartOn bool   `json:"auto_start"`           // 开机自启（默认服务器强制开启）
	LastError   string `json:"last_error,omitempty"` // 日志中最近一次警告/错误的原因（空=无异常）
	// 连续登录失败次数（达阈值后看门狗自动重启实例；0=当前正常）
	WatchdogFails int `json:"watchdog_fails,omitempty"`
}

// Status 一次状态快照。
type Status struct {
	Installed       bool           `json:"installed"`
	Version         string         `json:"version"`
	Running         bool           `json:"running"`
	BundleAvailable bool           `json:"bundle_available"`
	ConfigPath      string         `json:"config_path"`
	Servers         []ServerStatus `json:"servers,omitempty"`  // 各服务器运行状态
	Progress        *Progress      `json:"progress,omitempty"` // 升级进行中的实时进度
	Error           string         `json:"error,omitempty"`
}

// Progress 内核升级实时进度（仅升级过程中非空）。
type Progress struct {
	Done    int64  `json:"done"`
	Total   int64  `json:"total"`
	Percent int    `json:"percent"`
	Stage   string `json:"stage"`
}

// Manager 管理 frpc 的安装、配置、启停与升级。
// 支持多服务器实例：每台服务器可独立运行一个 frpc 进程（cmds 按服务器名索引）。
type Manager struct {
	logger     *zap.Logger
	dir        string // 运行数据目录（@appdata/TunHook/frp：二进制、pid、版本、离线包）
	configDir  string // 配置目录（@appconf/TunHook：frpc.json/frpc.toml，空=跟随 dir）
	logDir     string // 日志目录（@appshare/tunhook/log：frpc.log，空=跟随 dir）
	mu         sync.Mutex
	cmds       map[string]*exec.Cmd // 服务器名 → 运行中的 frpc 进程
	progressMu sync.Mutex
	progress   *Progress

	// 延迟应用去抖：经 frp 隧道管理自身配置时，把应用动作推迟到当前请求响应写回之后，
	// 避免同步重启把正在传输的响应打断（公网经反代访问时表现为 HTTP 400/502）。
	// 代理段变更优先热加载（frpc 管理 API），只有连接级参数变更才整进程重启。
	restartMu      sync.Mutex
	restartPending bool
	restartForce   bool // 本次待执行动作是否必须整进程重启

	// 登录看门狗：进程活着不等于登录成功。frpc 以 loginFailExit=false 无限重试时
	// 会锁死在同一个坏状态（管理端口在听、日志刷 write timeout、隧道不通），
	// 不重启就永不恢复。故按登录结果连续计数，超阈值自动重启该实例。
	watchdogMu      sync.Mutex
	watchdogRunning bool
	watchdogFail    map[string]int       // 服务器名 → 连续登录失败次数
	watchdogStarted map[string]time.Time // 服务器名 → 当前进程启动时刻（启动宽限期判定用）
	watchdogPID     map[string]int       // 服务器名 → 上次判定时的 PID（用于识别进程重启）
}

// 看门狗参数：连续登录失败达到 watchdogFailLimit 次即重启该实例。
// 取 10 次（约 20s，frpc 自身重试间隔 10s）偏保守：既能快速自愈，
// 又不会因网络抖动或服务端短暂重启而误重启。
const (
	watchdogInterval    = 2 * time.Second
	watchdogFailLimit   = 10
	watchdogStartWindow = 30 * time.Second // 进程启动后这段时间内不判定，等待首次登录

	// logTrimInterval 日志裁剪的最小间隔。裁剪同样由看门狗循环驱动，
	// 但与 2s 的登录判定分开节流：裁剪要读全文、必要时重写全文，不能按判定频率做。
	logTrimInterval = 60 * time.Second
)

// StartWatchdog 启动登录看门狗（幂等）。应在Server 启动后调用一次，
// ctx 取消时停止。重复调用返回 error，避免多个看门狗同时重启同一实例。
func (m *Manager) StartWatchdog(ctx context.Context) error {
	m.watchdogMu.Lock()
	if m.watchdogRunning {
		m.watchdogMu.Unlock()
		return errors.New("登录看门狗已在运行")
	}
	m.watchdogRunning = true
	m.watchdogMu.Unlock()
	if m.watchdogFail == nil {
		m.watchdogFail = map[string]int{}
	}
	if m.watchdogStarted == nil {
		m.watchdogStarted = map[string]time.Time{}
	}
	if m.watchdogPID == nil {
		m.watchdogPID = map[string]int{}
	}
	go m.watchdogLoop(ctx)
	return nil
}

// watchdogLoop 看门狗主循环：按间隔检查各实例的登录结果。
func (m *Manager) watchdogLoop(ctx context.Context) {
	ticker := time.NewTicker(watchdogInterval)
	defer ticker.Stop()
	defer func() {
		m.watchdogMu.Lock()
		m.watchdogRunning = false
		m.watchdogMu.Unlock()
	}()
	// 日志裁剪复用同一个 ticker，但按 logTrimInterval 节流：
	// 裁剪要读全文、必要时重写全文，不能按 2s 的登录判定频率做。
	lastTrim := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkAllWatchdogs()
			if time.Since(lastTrim) >= logTrimInterval {
				lastTrim = time.Now()
				m.TrimLogs()
			}
		}
	}
}

// checkAllWatchdogs 逐一检查各frpc 实例的登录结果并按需重启。
func (m *Manager) checkAllWatchdogs() {
	cfg := m.LoadConfig()
	for _, srv := range cfg.Servers {
		if strings.TrimSpace(srv.Addr) == "" {
			continue
		}
		// 用户主动停掉的不监控：进程不在运行 = 没有看门狗可管的故障
		if !m.ServerRunning(srv.Name) {
			m.resetWatchdog(srv.Name)
			continue
		}
		// 启动宽限期：进程刚起时不做失败判定，等它写出首次登录结果。
		// 必须做宽限期，否则重启后新进程尚未写日志、检查到的仍是上一轮的失败行，
		// 会立刻重新计数触发下一轮重启，形成连续重启风暴。
		if !m.watchdogGraceElapsed(srv.Name) {
			continue
		}
		ok, logged := m.loginSucceeded(srv.Name)
		if ok {
			m.resetWatchdog(srv.Name)
			continue
		}
		if !logged {
			// 启动窗口内且尚无失败记录：不计数
			continue
		}
		if m.bumpWatchdog(srv.Name) < watchdogFailLimit {
			continue
		}
		m.resetWatchdog(srv.Name)
		if m.logger != nil {
			m.logger.Warn("frpc 连续登录失败，自动重启实例",
				zap.String("server", srv.Name),
				zap.Int("fails", watchdogFailLimit))
		}
		if err := m.RestartServer(srv.Name); err != nil && m.logger != nil {
			m.logger.Warn("frpc 看门狗自动重启失败", zap.String("server", srv.Name), zap.Error(err))
		}
	}
}

// loginSucceeded 判断指定实例是否已登录成功，以及日志中是否已出现登录尝试记录。
// 判定依据是 frpc 日志中最后一条「登录尝试」的结果：
//   - "login to server success" → 已登录，隧道正常
//   - "connect to server error" / "login to server failed" → 登录失败
//
// 二者都没有 → 尚无登录记录（logged=false），处于启动窗口内。
func (m *Manager) loginSucceeded(name string) (ok bool, logged bool) {
	lines := strings.Split(m.LogTailFor(name, 500), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		ln := ansiRe.ReplaceAllString(lines[i], "")
		if strings.Contains(ln, loginSuccessMarker) {
			return true, true
		}
		for _, marker := range loginFailMarkers {
			if strings.Contains(ln, marker) {
				return false, true
			}
		}
	}
	return false, false
}

// loginSuccessMarker / loginFailMarkers 为 frpc 日志中的登录结果标记。
// 不同 frp 版本措辞不同（0.7x 为 "login to server success"，
// 早期版本为 "login to the server success"），故成功标记取两种子串的公共部分。
const loginSuccessMarker = "ogin to server success"

var loginFailMarkers = []string{
	"connect to server error",
	"login to server failed",
	"login to the server failed",
	"authorization failed",
}

// bumpWatchdog 登录失败计数 +1 并返回当前次数。
func (m *Manager) bumpWatchdog(name string) int {
	m.watchdogMu.Lock()
	defer m.watchdogMu.Unlock()
	m.watchdogFail[name]++
	return m.watchdogFail[name]
}

// watchdogGraceElapsed 判断该实例是否已过启动宽限期。
// 首次见到某实例时以当前时刻为起点；进程重启（PID 变化）则重置宽限期。
func (m *Manager) watchdogGraceElapsed(name string) bool {
	pid := m.PIDFor(name)
	m.watchdogMu.Lock()
	defer m.watchdogMu.Unlock()
	if prev, ok := m.watchdogPID[name]; !ok || prev != pid {
		m.watchdogPID[name] = pid
		m.watchdogStarted[name] = time.Now()
		return false
	}
	return time.Since(m.watchdogStarted[name]) >= watchdogStartWindow
}

// resetWatchdog 清零登录失败计数（登录成功或进程停止时调用）。
func (m *Manager) resetWatchdog(name string) {
	m.watchdogMu.Lock()
	defer m.watchdogMu.Unlock()
	delete(m.watchdogFail, name)
}

// WatchdogFails 返回指定实例的连续登录失败次数（无失败记录时为 0），供状态接口与界面告警展示。
func (m *Manager) WatchdogFails(name string) int {
	m.watchdogMu.Lock()
	defer m.watchdogMu.Unlock()
	return m.watchdogFail[name]
}

// NewManager 创建管理器，dir 为 frpc 运行数据目录。
func NewManager(dir string, logger *zap.Logger) *Manager {
	return &Manager{dir: dir, logger: logger, cmds: make(map[string]*exec.Cmd)}
}

// serverKey 生成服务器独立文件名后缀（名称清洗 + 哈希去重），与激活状态无关。
func serverKey(name string) string {
	safe := hostnameRe.ReplaceAllString(name, "_")
	h := sha1.Sum([]byte(name))
	return fmt.Sprintf("%s-%x", safe, h[:4])
}

// configRawFileName 生成服务器独立原始配置文件的安全文件名，
// 服务器切换为激活时由 startLocked 提升为 frpc.toml。
func configRawFileName(name string) string {
	return "frpc-" + serverKey(name) + ".toml"
}

// activeServerName 返回当前激活（默认）服务器名称。
func (m *Manager) activeServerName() string {
	return m.LoadConfig().ActiveServer
}

// serverByName 按名称查找服务器配置。
func serverByName(cfg Config, name string) (Server, bool) {
	for _, s := range cfg.Servers {
		if s.Name == name {
			return s, true
		}
	}
	return Server{}, false
}

// pidFileName 返回指定服务器对应的 pid 文件名（与激活状态无关，每台固定唯一，
// 避免切换默认服务器后同一服务器的 pid 路径变化导致无法停止/误杀其他进程）。
func (m *Manager) pidFileName(name string) string {
	return "frpc-" + serverKey(name) + ".pid"
}

// logFileName 返回指定服务器对应的日志文件名（与激活状态无关，每台固定唯一，多实例各自独立）。
func (m *Manager) logFileName(name string) string {
	return "frpc-" + serverKey(name) + ".log"
}

// pidPath 返回指定服务器 pid 文件路径。
func (m *Manager) pidPath(name string) string {
	return filepath.Join(m.dir, m.pidFileName(name))
}

// PidPath 导出 pidPath：供外部（含测试）按服务器名定位 pid 文件，
// 文件名规则为 frpc-<serverKey>.pid，不能硬编码为 frpc.pid。
func (m *Manager) PidPath(name string) string {
	return m.pidPath(name)
}

// logPathFor 返回指定服务器日志文件路径。
func (m *Manager) logPathFor(name string) string {
	if m.logDir != "" {
		return filepath.Join(m.logDir, m.logFileName(name))
	}
	return filepath.Join(m.dir, m.logFileName(name))
}

// SetPaths 设置配置目录与日志目录（为空时回退到运行数据目录）：
// 配置（frpc.json/frpc.toml）→ @appconf/TunHook；日志（frpc.log）→ @appshare/tunhook/log；
// 运行数据（二进制/pid/版本/离线包）保持在 dataDir/frp（@appdata/TunHook/frp）。
func (m *Manager) SetPaths(configDir, logDir string) {
	m.configDir = configDir
	m.logDir = logDir
}

// configPath 返回配置文件路径（配置目录优先，未指定时使用运行数据目录）。
func (m *Manager) configPath(name string) string {
	if m.configDir != "" {
		return filepath.Join(m.configDir, name)
	}
	return filepath.Join(m.dir, name)
}

// ensureConfigDir 确保配置文件目录存在（未指定配置目录时使用运行数据目录）。
func (m *Manager) ensureConfigDir() error {
	dir := m.configDir
	if dir == "" {
		dir = m.dir
	}
	return os.MkdirAll(dir, 0755)
}

// logFilePath 返回 frpc 日志文件路径（日志目录优先，未指定时使用运行数据目录）。
func (m *Manager) logFilePath() string {
	if m.logDir != "" {
		return filepath.Join(m.logDir, LogFile)
	}
	return filepath.Join(m.dir, LogFile)
}

// Dir 返回运行数据目录。
func (m *Manager) Dir() string { return m.dir }

// BinPath 返回 frpc 二进制路径。
func (m *Manager) BinPath() string { return filepath.Join(m.dir, BinName) }

// ==================== 安装 ====================

// findBundle 依次在环境变量、应用目录（生产 TRIM_APPDEST/app/frp，开发可执行文件同级 frp）、
// 以及已下载的 packages 目录中查找内置 frp 离线安装包。
func (m *Manager) findBundle() string {
	var cands []string
	if v := os.Getenv("TUNHOOK_FRP_BUNDLE"); v != "" {
		cands = append(cands, v)
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		cands = append(cands,
			filepath.Join(exeDir, "app", "frp"), // 生产：安装包 app/frp
			filepath.Join(exeDir, "frp"),        // 开发：可执行文件同级 frp
			filepath.Join(exeDir, "..", "frp"),  // 回退：项目根 frp
		)
	}
	cands = append(cands, filepath.Join(m.dir, PackagesDir))
	for _, dir := range cands {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			if archiveRe.MatchString(e.Name()) {
				return filepath.Join(dir, e.Name())
			}
		}
	}
	return ""
}

// Install 从内置安装包安装 frpc（未安装时调用）。
func (m *Manager) Install() error {
	pkg := m.findBundle()
	if pkg == "" {
		return errors.New("未找到内置 frp 安装包")
	}
	return m.installFromArchive(pkg, true)
}

// installFromArchive 解压 tar.gz 并替换 frpc 二进制（安装/升级共用）。
// keepCopy 为 true 时把安装包留档到 packages 目录，便于后续重装。
func (m *Manager) installFromArchive(pkg string, keepCopy bool) error {
	if !strings.HasSuffix(strings.ToLower(pkg), ".tar.gz") {
		return errors.New("安装包必须是 .tar.gz 格式")
	}
	version := parseVersionFromName(pkg)
	if m.logger != nil {
		m.logger.Info("frpc 安装包处理中", zap.String("pkg", pkg), zap.String("version", version))
	}

	binData, err := readFrpcFromArchive(pkg)
	if err != nil {
		return err
	}

	// 先停止运行中的进程，再替换二进制
	m.setProgress(0, 0, "正在停止运行中的 frpc…")
	if err := m.Stop(); err != nil {
		m.clearProgress()
		return err
	}
	m.setProgress(0, 0, "正在写入新内核…")
	if err := os.MkdirAll(m.dir, 0755); err != nil {
		m.clearProgress()
		return err
	}
	dst := m.BinPath()
	if err := os.WriteFile(dst, binData, 0755); err != nil {
		m.clearProgress()
		return fmt.Errorf("写入 frpc 二进制失败: %w", err)
	}
	if err := os.Chmod(dst, 0755); err != nil {
		m.clearProgress()
		return err
	}

	if version == "" {
		if v, err := m.binVersion(); err == nil {
			version = v
		}
	}
	if version != "" {
		_ = os.WriteFile(filepath.Join(m.dir, VersionFile), []byte(version), 0644)
	}

	if keepCopy {
		pkgDir := filepath.Join(m.dir, PackagesDir)
		dstPkg := filepath.Join(pkgDir, filepath.Base(pkg))
		// 安装包已位于 packages 目录（如离线上传路径）时跳过，避免自我截断
		if filepath.Clean(pkg) != filepath.Clean(dstPkg) {
			if err := os.MkdirAll(pkgDir, 0755); err == nil {
				_ = copyFile(pkg, dstPkg)
			}
		}
	}
	if m.logger != nil {
		m.logger.Info("frpc 安装/升级完成", zap.String("version", version))
	}
	m.clearProgress()
	return nil
}

// UpgradeFromArchive 使用用户上传的 tar.gz 离线包升级（替换二进制）。
func (m *Manager) UpgradeFromArchive(pkg string) error {
	return m.installFromArchive(pkg, true)
}

// readFrpcFromArchive 从 tar.gz 中读取名为 frpc 的文件内容。
func readFrpcFromArchive(pkg string) ([]byte, error) {
	f, err := os.Open(pkg)
	if err != nil {
		return nil, fmt.Errorf("打开安装包失败: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("解压安装包失败: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("读取安装包失败: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == BinName {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("读取 frpc 失败: %w", err)
			}
			if len(data) == 0 {
				return nil, errors.New("安装包中的 frpc 为空文件")
			}
			return data, nil
		}
	}
	return nil, errors.New("安装包中未找到 frpc 可执行文件")
}

func parseVersionFromName(pkg string) string {
	m := archiveRe.FindStringSubmatch(filepath.Base(pkg))
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// ==================== 配置 ====================

// LoadConfig 读取持久化的 frpc 配置（不存在时返回默认值）。
// 旧版单服务器平铺配置（server_addr/server_port/token）自动迁移为 servers 列表。
func (m *Manager) LoadConfig() Config {
	var cfg Config
	data, err := os.ReadFile(m.configPath(ConfigJSON))
	if err == nil {
		_ = json.Unmarshal(data, &cfg)
		// 兼容旧版单服务器平铺字段
		if len(cfg.Servers) == 0 {
			var legacy struct {
				ServerAddr string `json:"server_addr"`
				ServerPort int    `json:"server_port"`
				Token      string `json:"token"`
			}
			if err := json.Unmarshal(data, &legacy); err == nil {
				if legacy.ServerAddr != "" || legacy.Token != "" || legacy.ServerPort > 0 {
					cfg.Servers = []Server{{Name: DefaultServerName, Addr: legacy.ServerAddr, Port: legacy.ServerPort, Token: legacy.Token}}
				}
			}
		}
	}
	return NormalizeConfig(cfg)
}

// validAdminPort 管理 API 端口是否落在本程序为 frpc 预留的区间内。
func validAdminPort(p int) bool {
	return p >= AdminPortBase && p < AdminPortMax
}

// adminPortTaken 管理 API 端口是否已被同配置内的其他服务器占用。
func adminPortTaken(servers []Server, port int) bool {
	for _, s := range servers {
		if s.AdminPort == port {
			return true
		}
	}
	return false
}

// allocAdminPort 在预留区间内取一个未被占用的管理 API 端口（区间占满时回退起始端口）。
func allocAdminPort(servers []Server) int {
	for p := AdminPortBase; p < AdminPortMax; p++ {
		if !adminPortTaken(servers, p) {
			return p
		}
	}
	return AdminPortBase
}

// NormalizeConfig 规范配置：服务器名称去空格/去重、端口默认值、激活服务器有效性、
// 代理规则规范化与日志级别兜底。
func NormalizeConfig(cfg Config) Config {
	var servers []Server
	seen := make(map[string]bool)
	for _, s := range cfg.Servers {
		s.Name = strings.TrimSpace(s.Name)
		if s.Name == "" || seen[s.Name] {
			continue
		}
		s.Addr = strings.TrimSpace(s.Addr)
		s.Token = strings.TrimSpace(s.Token)
		s.User = strings.TrimSpace(s.User)
		if s.User == "" {
			// 用户名称留空时默认填充宿主机名称（去除非法字符，避免 frpc 校验失败）
			if hn, err := os.Hostname(); err == nil {
				s.User = strings.TrimSpace(hostnameRe.ReplaceAllString(hn, ""))
			}
		}
		s.Protocol = strings.ToLower(strings.TrimSpace(s.Protocol))
		if s.Protocol == "" {
			s.Protocol = "tcp"
		}
		s.StunServer = strings.TrimSpace(s.StunServer)
		if s.StunServer == "" {
			// STUN 服务器默认使用公共服务（xtcp 打洞等 NAT 穿透场景）
			s.StunServer = DefaultStunServer
		}
		s.ProxyProtocol = strings.ToLower(strings.TrimSpace(s.ProxyProtocol))
		if s.TcpMux == nil {
			t := true
			s.TcpMux = &t
		}
		if s.PoolCount <= 0 {
			// 预建立连接池数量默认 5（与推荐配置一致）
			s.PoolCount = 5
		}
		if s.QuicKeepalivePeriod <= 0 {
			// QUIC 保活周期默认 10 秒（frp 默认值）
			s.QuicKeepalivePeriod = 10
		}
		if s.QuicMaxIdleTimeout <= 0 {
			// QUIC 最大空闲超时默认 30 秒（frp 默认值）
			s.QuicMaxIdleTimeout = 30
		}
		if s.QuicMaxIncomingStreams <= 0 {
			// QUIC 最大流入流数默认 100000（frp 默认值）
			s.QuicMaxIncomingStreams = 100000
		}
		if s.LogDays <= 0 {
			// 日志保留天数默认 7（与推荐配置一致）
			s.LogDays = 7
		}
		if s.Port <= 0 {
			s.Port = DefaultPort
		}
		// 管理 API 端口：已分配的保持稳定，仅在缺失、越界或与同配置内其他服务器冲突时才重新分配。
		// 历史实现按列表位置（len(servers)）每次重算，删除靠前的服务器会让其后所有实例的管理端口
		// 集体搬家；而运行中的 frpc 既不会重写 toml 也不会重启，仍监听旧端口，
		// 于是管理 API 查询全部落空（前端表现为代理一直显示「连接中」）。
		if !validAdminPort(s.AdminPort) || adminPortTaken(servers, s.AdminPort) {
			s.AdminPort = allocAdminPort(servers)
		}
		// 开机自启：未设置（旧数据/新服务器）默认开启
		if s.AutoStartOn == nil {
			t := true
			s.AutoStartOn = &t
		}
		seen[s.Name] = true
		servers = append(servers, s)
	}
	if len(servers) == 0 {
		servers = []Server{{Name: DefaultServerName, Addr: "", Port: DefaultPort}}
	}
	cfg.Servers = servers
	cfg.ActiveServer = strings.TrimSpace(cfg.ActiveServer)
	match := false
	for _, s := range servers {
		if s.Name == cfg.ActiveServer {
			match = true
			break
		}
	}
	if !match {
		cfg.ActiveServer = servers[0].Name
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.LogEntries < 0 {
		cfg.LogEntries = 0
	}
	if cfg.LogEntries > 100000 {
		cfg.LogEntries = 100000
	}
	if cfg.LogDays < 0 {
		cfg.LogDays = 0
	}
	if cfg.LogDays > 3650 {
		cfg.LogDays = 3650
	}
	// 代理规则规范化
	var proxies []Proxy
	seenProxy := make(map[string]bool)
	for _, p := range cfg.Proxies {
		p = normalizeProxy(p)
		if p.Name == "" || seenProxy[p.Name] {
			continue
		}
		// 代理归属服务器：空（旧数据）兜底为激活服务器
		if p.Server == "" {
			p.Server = cfg.ActiveServer
		}
		seenProxy[p.Name] = true
		proxies = append(proxies, p)
	}
	if proxies == nil {
		proxies = []Proxy{}
	}
	cfg.Proxies = proxies
	return cfg
}

// normalizeProxy 规范化单条代理规则字段。
func normalizeProxy(p Proxy) Proxy {
	p.Name = strings.TrimSpace(p.Name)
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	if p.Type == "" {
		p.Type = "tcp"
	}
	p.LocalIP = strings.TrimSpace(p.LocalIP)
	if p.LocalIP == "" {
		p.LocalIP = "127.0.0.1"
	}
	p.CustomDomains = strings.TrimSpace(p.CustomDomains)
	p.Subdomain = strings.TrimSpace(p.Subdomain)
	p.HTTPUser = strings.TrimSpace(p.HTTPUser)
	p.HTTPPassword = strings.TrimSpace(p.HTTPPassword)
	p.BandwidthLimit = strings.TrimSpace(p.BandwidthLimit)
	if p.LocalPort < 0 {
		p.LocalPort = 0
	}
	if p.RemotePort < 0 {
		p.RemotePort = 0
	}
	if p.HealthCheck != nil {
		hc := *p.HealthCheck
		hc.Type = strings.ToLower(strings.TrimSpace(hc.Type))
		hc.Path = strings.TrimSpace(hc.Path)
		if hc.Type == "" {
			p.HealthCheck = nil
		} else {
			p.HealthCheck = &hc
		}
	}
	return p
}

// persistConfig 仅持久化 frpc.json（不触发重启/重新生成 TOML）。
func (m *Manager) persistConfig(cfg Config) error {
	if err := m.ensureConfigDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.configPath(ConfigJSON), data, 0600)
}

// SaveConfig 持久化 frpc 配置，并立即重新生成 frpc.toml；
// 运行中且激活服务器已配置地址时自动应用新配置：
//   - 仅代理段变化 → 走 frpc 管理 API 热加载，不中断任何已建立的隧道；
//   - 连接/日志等客户端级参数变化 → 必须整进程重启才能生效。
func (m *Manager) SaveConfig(cfg Config) error {
	cfg = NormalizeConfig(cfg)
	prev := m.LoadConfig()
	if err := m.persistConfig(cfg); err != nil {
		return err
	}
	// 运行中且激活服务器地址完整则延迟应用（异步，保证当前请求响应先写回）；
	// 地址为空时保持当前连接不打断
	if m.isRunning() {
		if srv, ok := cfg.Active(); ok && strings.TrimSpace(srv.Addr) != "" {
			m.scheduleApply(!sameRuntimeConfig(prev, cfg))
		}
		return nil
	}
	return writeTOML(cfg, m.configPath(ConfigFile))
}

// sameRuntimeConfig 判断两份配置除代理段外是否完全一致。
// 代理段可由 frpc 热加载生效；连接、日志等客户端级参数只能靠重启生效。
func sameRuntimeConfig(a, b Config) bool {
	a.Proxies = nil
	b.Proxies = nil
	return reflect.DeepEqual(a, b)
}

// SaveAutoStart 设置指定服务器的开机自启标志（仅持久化，不重启进程）。
// 默认服务器必须保持开机自启，拒绝关闭。
func (m *Manager) SaveAutoStart(name string, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.LoadConfig()
	idx := -1
	for i, s := range cfg.Servers {
		if s.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("服务器「%s」不存在", name)
	}
	if cfg.Servers[idx].Name == cfg.ActiveServer && !on {
		return errors.New("默认服务器必须保持开机自启")
	}
	b := on
	cfg.Servers[idx].AutoStartOn = &b
	return m.persistConfig(cfg)
}

// AddServer 添加服务器实例（名称唯一），并切换为激活服务器。
func (m *Manager) AddServer(s Server) error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" {
		return errors.New("请填写服务器名称")
	}
	if s.Port <= 0 {
		s.Port = DefaultPort
	}
	cfg := m.LoadConfig()
	if len(cfg.Servers) >= MaxServers {
		return fmt.Errorf("最多只能添加 %d 台服务器", MaxServers)
	}
	for _, x := range cfg.Servers {
		if x.Name == s.Name {
			return fmt.Errorf("服务器名称「%s」已存在", s.Name)
		}
	}
	cfg.Servers = append(cfg.Servers, s)
	cfg.ActiveServer = s.Name
	return m.SaveConfig(cfg)
}

// SwitchServer 切换激活服务器（按名称，即时生效），无该名称时报错。
// 切换时原默认服务器的代理自动迁移到新默认服务器（同名保留新默认服务器已有的，避免通道中断）。
func (m *Manager) SwitchServer(name string) error {
	name = strings.TrimSpace(name)
	cfg := m.LoadConfig()
	found := false
	for _, x := range cfg.Servers {
		if x.Name == name {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("服务器「%s」不存在", name)
	}
	if cfg.ActiveServer == name {
		return nil
	}
	oldActive := cfg.ActiveServer
	cfg.ActiveServer = name
	// 迁移原默认服务器的代理到新默认服务器（新默认服务器已有的同名代理保留）
	taken := make(map[string]bool)
	for _, p := range cfg.Proxies {
		if p.Server == name {
			taken[p.Name] = true
		}
	}
	var proxies []Proxy
	for _, p := range cfg.Proxies {
		if p.Server == oldActive && !taken[p.Name] {
			p.Server = name
		}
		proxies = append(proxies, p)
	}
	cfg.Proxies = proxies
	return m.SaveConfig(cfg)
}

// DeleteServer 删除服务器实例；删除激活服务器时自动切换到第一个剩余实例。
// 被删除服务器的代理自动迁移到激活服务器（同名保留激活服务器已有的）。
func (m *Manager) DeleteServer(name string) error {
	name = strings.TrimSpace(name)
	cfg := m.LoadConfig()
	idx := -1
	for i, x := range cfg.Servers {
		if x.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("服务器「%s」不存在", name)
	}
	cfg.Servers = append(cfg.Servers[:idx], cfg.Servers[idx+1:]...)
	if cfg.ActiveServer == name {
		if len(cfg.Servers) > 0 {
			cfg.ActiveServer = cfg.Servers[0].Name
		} else {
			cfg.ActiveServer = ""
		}
	}
	// 被删服务器的代理迁移到激活服务器（同名跳过保留）
	if cfg.ActiveServer != "" {
		taken := make(map[string]bool)
		for _, p := range cfg.Proxies {
			if p.Server == cfg.ActiveServer {
				taken[p.Name] = true
			}
		}
		var proxies []Proxy
		for _, p := range cfg.Proxies {
			if p.Server == name && !taken[p.Name] {
				p.Server = cfg.ActiveServer
			}
			proxies = append(proxies, p)
		}
		cfg.Proxies = proxies
	}
	return m.SaveConfig(cfg)
}

// RenameServer 修改服务器实例名称；重命名激活服务器时同步更新激活标记。
func (m *Manager) RenameServer(oldName, newName string) error {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return errors.New("请填写服务器名称")
	}
	cfg := m.LoadConfig()
	idx := -1
	for i, x := range cfg.Servers {
		if x.Name == oldName {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("服务器「%s」不存在", oldName)
	}
	for i, x := range cfg.Servers {
		if i != idx && x.Name == newName {
			return fmt.Errorf("服务器名称「%s」已存在", newName)
		}
	}
	cfg.Servers[idx].Name = newName
	if cfg.ActiveServer == oldName {
		cfg.ActiveServer = newName
	}
	// 同步更新归属该服务器的代理归属字段
	for i := range cfg.Proxies {
		if cfg.Proxies[i].Server == oldName {
			cfg.Proxies[i].Server = newName
		}
	}
	return m.SaveConfig(cfg)
}

// AddProxy 新增代理规则（名称唯一），保存后运行中自动重启生效。
func (m *Manager) AddProxy(p Proxy) error {
	p = normalizeProxy(p)
	if p.Name == "" {
		return errors.New("请填写代理名称")
	}
	cfg := m.LoadConfig()
	for _, x := range cfg.Proxies {
		if x.Name == p.Name {
			return fmt.Errorf("代理名称「%s」已存在", p.Name)
		}
	}
	cfg.Proxies = append(cfg.Proxies, p)
	return m.SaveConfig(cfg)
}

// UpdateProxy 更新代理规则（按原名称定位，支持改名）。
func (m *Manager) UpdateProxy(name string, p Proxy) error {
	p = normalizeProxy(p)
	if p.Name == "" {
		return errors.New("请填写代理名称")
	}
	cfg := m.LoadConfig()
	idx := -1
	for i, x := range cfg.Proxies {
		if x.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("代理「%s」不存在", name)
	}
	if p.Name != name {
		for _, x := range cfg.Proxies {
			if x.Name == p.Name {
				return fmt.Errorf("代理名称「%s」已存在", p.Name)
			}
		}
	}
	cfg.Proxies[idx] = p
	return m.SaveConfig(cfg)
}

// DeleteProxy 删除代理规则。
func (m *Manager) DeleteProxy(name string) error {
	cfg := m.LoadConfig()
	idx := -1
	for i, x := range cfg.Proxies {
		if x.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("代理「%s」不存在", name)
	}
	cfg.Proxies = append(cfg.Proxies[:idx], cfg.Proxies[idx+1:]...)
	return m.SaveConfig(cfg)
}

// ProxyConflict 一条与待保存代理冲突的既有代理（Kind 区分冲突类型）。
type ProxyConflict struct {
	Name   string `json:"name"`   // 冲突的既有代理名
	Server string `json:"server"` // 其所属服务器
	Kind   string `json:"kind"`   // domain | remote_port
	Value  string `json:"value"`  // 冲突的域名或远程端口
}

// CheckProxyConflicts 返回待保存代理 p 与既有代理的冲突项（只查询、不落库）；
// exclude 为更新时的原代理名，用于排除自身。
func (m *Manager) CheckProxyConflicts(p Proxy, exclude string) []ProxyConflict {
	return checkProxyConflicts(m.LoadConfig(), p, exclude)
}

// checkProxyConflicts 判定两类 frps 侧资源冲突（均已在实际使用中导致代理启动失败）：
//
//   - 自定义域名：frps 按域名路由，同名域名必然报 "router config conflict"。
//     域名是面向公网的唯一入口，即便配到两台不同服务器上，同一域名也只能解析到其中一台，
//     属于误配，故跨全部服务器比对。
//   - 远程端口：整份覆盖式的服务端端口，只在同一台 frps 内有意义，故仅比对同一服务器；
//     remote_port=0 表示由服务端自动分配，不存在冲突。
//
// 不区分 enabled：停用的代理虽暂不下发，但重新启用即冲突，提前提示可避免埋雷。
func checkProxyConflicts(cfg Config, p Proxy, exclude string) []ProxyConflict {
	out := []ProxyConflict{}
	if p.Server == "" {
		p.Server = cfg.ActiveServer
	}
	want := make(map[string]bool)
	for _, d := range splitDomains(p.CustomDomains) {
		want[d] = true
	}
	for _, x := range cfg.Proxies {
		if exclude != "" && x.Name == exclude {
			continue
		}
		for _, d := range splitDomains(x.CustomDomains) {
			if want[d] {
				out = append(out, ProxyConflict{Name: x.Name, Server: x.Server, Kind: "domain", Value: d})
			}
		}
		if p.RemotePort > 0 && x.RemotePort == p.RemotePort && x.Server == p.Server {
			out = append(out, ProxyConflict{
				Name: x.Name, Server: x.Server, Kind: "remote_port", Value: strconv.Itoa(p.RemotePort),
			})
		}
	}
	return out
}

// splitDomains 把逗号分隔的域名串拆成规范化（小写、去空白）的域名列表，
// 与前端提交前的 resolveCustomDomains 口径一致，避免大小写/空格造成漏判。
func splitDomains(s string) []string {
	out := []string{}
	for _, d := range strings.Split(s, ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// proxyConflictMessage 把冲突列表拼成可直接展示给用户的错误文案。
func proxyConflictMessage(cs []ProxyConflict) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		switch c.Kind {
		case "domain":
			parts = append(parts, fmt.Sprintf("域名「%s」已被代理「%s」占用", c.Value, c.Name))
		case "remote_port":
			parts = append(parts, fmt.Sprintf("远程端口 %s 已被代理「%s」占用（服务器「%s」）", c.Value, c.Name, c.Server))
		}
	}
	return "配置冲突：" + strings.Join(parts, "；")
}

// LogOpts 客户端级日志设置（新增/更新代理时可选同步设置）。
// 指针字段为 nil 表示不修改（0 值可显式写入，如 0=不限制）。
type LogOpts struct {
	Level   string // 客户端全局日志级别（非空时覆盖）
	Entries *int   // frpc.log 保留行数（0=不限制）
	Days    *int   // 客户端级日志保留天数（0=不限制/跟随服务器）
}

// SaveProxyWithLog 新增（origName 为空）或更新（按 origName 定位）代理规则，
// 并可选同步更新客户端级日志参数，单次落库/重启。
func (m *Manager) SaveProxyWithLog(p Proxy, origName string, opts LogOpts) error {
	p = normalizeProxy(p)
	if p.Name == "" {
		return errors.New("请填写代理名称")
	}
	cfg := m.LoadConfig()
	// 域名 / 远程端口冲突必须在此拦下：frps 按域名路由、按服务器分配远程端口，
	// 放行后表现为 frpc 报 "router config conflict" 或代理启动失败，而界面上看不出原因。
	// 在改动 cfg（追加/替换代理）之前判定，保证比对的是既有配置。
	if cs := checkProxyConflicts(cfg, p, origName); len(cs) > 0 {
		return errors.New(proxyConflictMessage(cs))
	}
	if origName != "" {
		idx := -1
		for i, x := range cfg.Proxies {
			if x.Name == origName {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("代理「%s」不存在", origName)
		}
		if p.Name != origName {
			for _, x := range cfg.Proxies {
				if x.Name == p.Name {
					return fmt.Errorf("代理名称「%s」已存在", p.Name)
				}
			}
		}
		cfg.Proxies[idx] = p
	} else {
		for _, x := range cfg.Proxies {
			if x.Name == p.Name {
				return fmt.Errorf("代理名称「%s」已存在", p.Name)
			}
		}
		cfg.Proxies = append(cfg.Proxies, p)
	}
	if lvl := strings.TrimSpace(opts.Level); lvl != "" {
		cfg.LogLevel = lvl
	}
	if opts.Entries != nil {
		cfg.LogEntries = *opts.Entries
	}
	if opts.Days != nil {
		cfg.LogDays = *opts.Days
	}
	return m.SaveConfig(cfg)
}

// SetProxyEnabled 启用/停用单条代理（frp 逐代理 enabled 开关）。
func (m *Manager) SetProxyEnabled(name string, enabled bool) error {
	cfg := m.LoadConfig()
	idx := -1
	for i, x := range cfg.Proxies {
		if x.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("代理「%s」不存在", name)
	}
	cfg.Proxies[idx].Enabled = enabled
	return m.SaveConfig(cfg)
}

// renderTOML 根据配置（激活服务器）生成 frpc.toml 文本（frpc 0.5x+ 使用 TOML 格式）。
func renderTOML(cfg Config) (string, error) {
	srv, _ := cfg.Active()
	port := srv.Port
	if port <= 0 {
		port = DefaultPort
	}
	lvl := strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	if lvl == "" {
		lvl = "info"
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("serverAddr = %s\n", tomlStr(srv.Addr)))
	b.WriteString(fmt.Sprintf("serverPort = %d\n", port))
	if strings.TrimSpace(srv.Token) != "" {
		b.WriteString("\nauth.method = \"token\"\n")
		b.WriteString(fmt.Sprintf("auth.token = %s\n", tomlStr(srv.Token)))
	}
	b.WriteString(fmt.Sprintf("\nlog.level = %s\n", tomlStr(lvl)))
	// 登录失败不退出：由本管理器保持进程常驻（等价 systemd Restart=always）
	b.WriteString("\nloginFailExit = false\n")
	// frpc 管理 API（仅本地回环）：供 UI 查询各代理实时连接状态（running / connecting / error）
	b.WriteString("\nwebServer.addr = \"127.0.0.1\"\n")
	adminPort := srv.AdminPort
	if adminPort <= 0 {
		adminPort = AdminPortBase
	}
	b.WriteString(fmt.Sprintf("webServer.port = %d\n", adminPort))

	// 用户名称：未填写时默认使用宿主机名称（去除非法字符，避免 frpc 校验失败）
	user := strings.TrimSpace(srv.User)
	if user == "" {
		if hn, err := os.Hostname(); err == nil {
			user = strings.TrimSpace(hostnameRe.ReplaceAllString(hn, ""))
		}
	}
	if user != "" {
		b.WriteString(fmt.Sprintf("user = %s\n", tomlStr(user)))
	}
	// 传输协议 / 连接池 / QUIC / STUN / TCP 多路复用 / 日志保留天数
	proto := strings.ToLower(strings.TrimSpace(srv.Protocol))
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" {
		b.WriteString(fmt.Sprintf("transport.protocol = %s\n", tomlStr(proto)))
	}
	if srv.PoolCount > 0 {
		b.WriteString(fmt.Sprintf("transport.poolCount = %d\n", srv.PoolCount))
	}
	if proto == "quic" {
		if srv.QuicKeepalivePeriod > 0 {
			b.WriteString(fmt.Sprintf("transport.quic.keepalivePeriod = %d\n", srv.QuicKeepalivePeriod))
		}
		if srv.QuicMaxIdleTimeout > 0 {
			b.WriteString(fmt.Sprintf("transport.quic.maxIdleTimeout = %d\n", srv.QuicMaxIdleTimeout))
		}
		if srv.QuicMaxIncomingStreams > 0 {
			b.WriteString(fmt.Sprintf("transport.quic.maxIncomingStreams = %d\n", srv.QuicMaxIncomingStreams))
		}
	}
	// STUN 服务器：frp 的合法键为客户端顶级配置 natHoleStunServer（xtcp 打洞等 NAT 穿透场景），
	// 写为 transport.stunServer 会导致 frpc 严格校验失败（json: unknown field "stunServer"）而无法启动。
	if stun := strings.TrimSpace(srv.StunServer); stun != "" {
		b.WriteString(fmt.Sprintf("natHoleStunServer = %s\n", tomlStr(stun)))
	}
	if srv.TcpMux != nil && !*srv.TcpMux {
		b.WriteString("transport.tcpMux = false\n")
	}
	// log.maxDays：客户端级配置优先，其次服务器级（均未设置则 frp 默认不清理）
	maxDays := 0
	if cfg.LogDays > 0 {
		maxDays = cfg.LogDays
	} else if srv.LogDays > 0 {
		maxDays = srv.LogDays
	}
	if maxDays > 0 {
		b.WriteString(fmt.Sprintf("log.maxDays = %d\n", maxDays))
	}

	for _, p := range cfg.Proxies {
		// 只渲染归属当前渲染服务器（srv）的代理；空归属（旧数据）视为激活服务器
		if p.Server != "" && p.Server != srv.Name {
			continue
		}
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(p.Type))
		if typ == "" {
			typ = "tcp"
		}
		lip := strings.TrimSpace(p.LocalIP)
		if lip == "" {
			lip = "127.0.0.1"
		}
		b.WriteString("\n[[proxies]]\n")
		b.WriteString(fmt.Sprintf("name = %s\n", tomlStr(name)))
		b.WriteString(fmt.Sprintf("type = %s\n", tomlStr(typ)))
		if !p.Enabled {
			b.WriteString("enabled = false\n")
		}
		b.WriteString(fmt.Sprintf("localIP = %s\n", tomlStr(lip)))
		if p.LocalPort > 0 {
			b.WriteString(fmt.Sprintf("localPort = %d\n", p.LocalPort))
		}
		if typ != "http" && typ != "https" && typ != "stcp" && typ != "xtcp" && p.RemotePort > 0 {
			b.WriteString(fmt.Sprintf("remotePort = %d\n", p.RemotePort))
		}
		if typ == "http" || typ == "https" {
			if strings.TrimSpace(p.CustomDomains) != "" {
				var parts []string
				for _, d := range strings.Split(p.CustomDomains, ",") {
					d = strings.TrimSpace(d)
					if d != "" {
						parts = append(parts, tomlStr(d))
					}
				}
				if len(parts) > 0 {
					b.WriteString("customDomains = [" + strings.Join(parts, ", ") + "]\n")
				}
			}
			if strings.TrimSpace(p.Subdomain) != "" {
				b.WriteString(fmt.Sprintf("subdomain = %s\n", tomlStr(strings.TrimSpace(p.Subdomain))))
			}
			// HTTP Basic 认证仅 http 类型支持；https 类型 frp 不接受 httpUser/httpPassword，忽略以免 verify 失败
			if typ == "http" && strings.TrimSpace(p.HTTPUser) != "" {
				b.WriteString(fmt.Sprintf("httpUser = %s\n", tomlStr(strings.TrimSpace(p.HTTPUser))))
				b.WriteString(fmt.Sprintf("httpPassword = %s\n", tomlStr(p.HTTPPassword)))
			}
		}
		// STCP/XTCP：仅需 secretKey（无远程端口），访问端配置相同密钥后经 frps 中转 / P2P 打洞直连
		if (typ == "stcp" || typ == "xtcp") && strings.TrimSpace(p.SecretKey) != "" {
			b.WriteString(fmt.Sprintf("secretKey = %s\n", tomlStr(strings.TrimSpace(p.SecretKey))))
		}
		// 进阶选项：传输加密/压缩/带宽限制（服务器级默认开启时优先，单条代理仍可单独启用）
		enc := p.Encryption
		comp := p.Compression
		if !enc && srv.UseEncryption {
			enc = true
		}
		if !comp && srv.UseCompression {
			comp = true
		}
		if enc || comp || strings.TrimSpace(p.BandwidthLimit) != "" {
			b.WriteString("transport.useEncryption = " + strconv.FormatBool(enc) + "\n")
			b.WriteString("transport.useCompression = " + strconv.FormatBool(comp) + "\n")
			if bl := strings.TrimSpace(p.BandwidthLimit); bl != "" {
				b.WriteString(fmt.Sprintf("transport.bandwidthLimit = %s\n", tomlStr(bl)))
			}
			if bm := strings.ToLower(strings.TrimSpace(p.BandwidthLimitMode)); bm != "" {
				b.WriteString(fmt.Sprintf("transport.bandwidthLimitMode = %s\n", tomlStr(bm)))
			}
		}
		// 服务器级默认 proxy protocol 版本（转发到本地服务时携带原始客户端地址）。
		// 仅对 tcp 代理写入：frp 的 PROXY protocol 只对 tcp/udp 流式代理有意义，
		// 而 UDP 无连接概念也不适用；http 代理的访客 IP 经 X-Real-IP 记录，不需也不应携带 PROXY 头。
		if typ == "tcp" {
			if pp := strings.ToLower(strings.TrimSpace(srv.ProxyProtocol)); pp != "" {
				b.WriteString(fmt.Sprintf("transport.proxyProtocolVersion = %s\n", tomlStr(pp)))
			}
		}
		// 健康检查
		if p.HealthCheck != nil && strings.TrimSpace(p.HealthCheck.Type) != "" {
			hc := p.HealthCheck
			b.WriteString(fmt.Sprintf("healthCheck.type = %s\n", tomlStr(strings.ToLower(strings.TrimSpace(hc.Type)))))
			if hc.IntervalSeconds > 0 {
				b.WriteString(fmt.Sprintf("healthCheck.intervalSeconds = %d\n", hc.IntervalSeconds))
			}
			if hc.TimeoutSeconds > 0 {
				b.WriteString(fmt.Sprintf("healthCheck.timeoutSeconds = %d\n", hc.TimeoutSeconds))
			}
			if hc.MaxFailed > 0 {
				b.WriteString(fmt.Sprintf("healthCheck.maxFailed = %d\n", hc.MaxFailed))
			}
			if strings.ToLower(strings.TrimSpace(hc.Type)) == "http" && strings.TrimSpace(hc.Path) != "" {
				b.WriteString(fmt.Sprintf("healthCheck.path = %s\n", tomlStr(strings.TrimSpace(hc.Path))))
			}
		}
	}
	return b.String(), nil
}

// writeTOML 根据配置生成 frpc.toml 并写入指定路径。
func writeTOML(cfg Config, path string) error {
	content, err := renderTOML(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}

func tomlStr(s string) string {
	return strconv.Quote(s)
}

// ==================== 进程管理（多实例） ====================

// Start 启动所有已配置有效地址的 frpc 进程（已在运行的跳过）。
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startAllLocked()
}

// StartServer 启动指定服务器的 frpc 进程（已在运行则直接返回）。
func (m *Manager) StartServer(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startServerLocked(name)
}

// startAllLocked 启动所有已配置有效地址的服务器进程（须持有 m.mu）。
func (m *Manager) startAllLocked() error {
	var firstErr error
	for _, s := range m.LoadConfig().Servers {
		if strings.TrimSpace(s.Addr) == "" {
			continue
		}
		if err := m.startServerLocked(s.Name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *Manager) startServerLocked(name string) error {
	cfg := m.LoadConfig()
	srv, ok := serverByName(cfg, name)
	if !ok {
		return fmt.Errorf("服务器「%s」不存在", name)
	}
	if strings.TrimSpace(srv.Addr) == "" {
		return fmt.Errorf("服务器「%s」未配置地址", name)
	}
	if m.cmdAliveFor(name) || m.pidAliveFor(name) {
		return nil // 已在运行
	}
	bin := m.BinPath()
	if _, err := os.Stat(bin); err != nil {
		return errors.New("frpc 未安装，请先安装")
	}
	tomlPath, err := m.prepareConfigFileLocked(cfg, name)
	if err != nil {
		return err
	}
	return m.startWithFileLocked(name, tomlPath)
}

// prepareConfigFileLocked 生成指定服务器本次运行使用的 TOML 并返回其路径（须持有 m.mu）。
// 启动与热加载共用：热加载必须写回 frpc 当前正在读取的同一份文件，否则改了也不生效。
func (m *Manager) prepareConfigFileLocked(cfg Config, name string) (string, error) {
	if err := os.MkdirAll(m.dir, 0755); err != nil {
		return "", err
	}
	if err := m.ensureConfigDir(); err != nil {
		return "", err
	}
	tomlPath := m.configPath(m.configFileNameFor(name)) // 激活=frpc.toml；非激活=frpc-<key>.toml
	srcPath := ""
	if name == cfg.ActiveServer {
		// 激活服务器：若该服务器此前通过「配置文件」保存过独立原始配置，切换为激活后优先沿用，
		// 避免被结构化配置重新生成覆盖（用户手动编辑的内容应保留）。
		if prev := m.configPath(configRawFileName(name)); prev != tomlPath {
			if _, err := os.Stat(prev); err == nil {
				if err := os.Rename(prev, tomlPath); err == nil {
					return tomlPath, nil
				}
			}
		}
		if _, err := os.Stat(tomlPath); err == nil {
			srcPath = tomlPath
		}
	} else {
		// 非激活服务器：以用户保存的原始配置（正式独立文件）为源合并，输出到临时文件，
		// 保留用户手动配置的连接参数（serverAddr/user/metadatas 等），仅替换代理段，
		// 使 UI 的启停/编辑/删除立即生效且不破坏连接配置。
		if _, err := os.Stat(tomlPath); err == nil {
			srcPath = tomlPath
			tomlPath = m.configPath(".frpc-" + serverKey(name) + ".toml")
		}
	}
	if srcPath != "" {
		if data, rerr := os.ReadFile(srcPath); rerr == nil {
			merged, merr := m.mergeProxySection(cfg, name, string(data))
			if merr == nil {
				merged = m.syncWebServer(merged, name)
				if err := os.WriteFile(tomlPath, []byte(merged), 0644); err != nil {
					return "", fmt.Errorf("写入配置失败: %w", err)
				}
				return tomlPath, nil
			}
		}
	}
	if err := writeTOMLFor(cfg, name, tomlPath); err != nil {
		return "", fmt.Errorf("生成配置失败: %w", err)
	}
	return tomlPath, nil
}

// managedConnKeys 结构化配置（frpc.json）负责管理、UI 可编辑的顶层键。
// 合并时必须先从原始配置中移除这些键，改由 renderTOML 生成，
// 否则 UI 改地址/token 会「保存成功但不生效」——
// 原始配置里的旧值被原样保留，运行中的 frpc 仍用旧凭据连接。
// 不在此列表的键（metadatas、plugin、dnsServer 等用户手写内容）一律保留。
var managedConnKeys = []string{
	"serverAddr", "serverPort", "user", "loginFailExit", "natHoleStunServer",
	"auth.method", "auth.token",
	"log.level", "log.maxDays",
	"webServer.addr", "webServer.port",
	"transport.protocol", "transport.poolCount", "transport.tcpMux",
	"transport.quic.keepalivePeriod", "transport.quic.maxIdleTimeout",
	"transport.quic.maxIncomingStreams",
}

// authInlineRe 匹配单行内联表形式的鉴权配置（auth = { method = "token", token = "x" }）。
var authInlineRe = regexp.MustCompile(`(?m)^[ \t]*auth[ \t]*=[ \t]*\{.*\}[ \t]*$`)

// removeManagedKeys 移除结构化配置负责管理的顶层键（含 auth 单行内联表），
// 只删「键名完全匹配」的整行，保留用户手写的其它配置。
func removeManagedKeys(content string) string {
	out := authInlineRe.ReplaceAllString(content, "")
	for _, k := range managedConnKeys {
		re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(k) + `[ \t]*=.*\n?`)
		out = re.ReplaceAllString(out, "")
	}
	return out
}

// mergeProxySection 把结构化配置（frpc.json）合并进原始配置文本：
//   - UI 可管理的连接参数与代理段：完全以结构化配置为准（移除原始配置中的旧值后写入新值）；
//   - UI 不可管理的键（metadatas/plugin 等）：保留原始配置中用户手写的内容。
//
// 为什么连接参数也必须覆盖：Server 结构里的地址/端口/token/user 等都能在 UI 编辑，
// 若保留原始配置里的旧值，就会出现「保存成功、界面显示新值、实际连接用旧值」的静默失效
// （token 改不掉、地址改不掉，用户完全无从察觉）。保留手写内容的目的仅是护住
// 结构化配置根本无法表达的键，两者不能混为一谈。
func (m *Manager) mergeProxySection(cfg Config, server, rawTOML string) (string, error) {
	c := cfg
	if server != "" {
		c.ActiveServer = server
	}
	generated, err := renderTOML(c)
	if err != nil {
		return "", err
	}
	// 生成内容拆成「头部（连接参数）」与「代理段」两部分：
	// 头部覆盖原始配置的同名键，代理段整段替换，其余原始内容保留。
	head, proxySection := generated, ""
	if idx := strings.Index(generated, "[[proxies]]"); idx >= 0 {
		head, proxySection = generated[:idx], generated[idx:]
	}
	cleaned := removeManagedKeys(removeProxySections(rawTOML))
	cleaned = strings.TrimRight(cleaned, "\n") + "\n\n" + strings.TrimLeft(head, "\n")
	if proxySection != "" {
		cleaned = strings.TrimRight(cleaned, "\n") + "\n\n" + proxySection
	}
	return cleaned, nil
}

// removeProxySections 移除 TOML 文本中的所有 [[proxies]] 段（含其 [proxies.*] 子表），
// 保留其余配置（顶部键与其他 [表]）。
func removeProxySections(content string) string {
	lines := strings.Split(content, "\n")
	var out []string
	inProxy := false
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "[[proxies]]"):
			inProxy = true
		case inProxy && strings.HasPrefix(t, "[proxies"):
			// [proxies.transport] 等代理子表：仍属代理段，跳过
		case inProxy && strings.HasPrefix(t, "["):
			// 其他 [表]：代理段结束，保留该行
			inProxy = false
			out = append(out, ln)
		case inProxy:
			// 代理段内普通行，跳过
		default:
			out = append(out, ln)
		}
	}
	return strings.Join(out, "\n")
}

// writeTOMLFor 按指定服务器生成 frpc.toml 并写入指定路径（临时把 ActiveServer 指向该服务器）。
func writeTOMLFor(cfg Config, name string, path string) error {
	c := cfg
	if name != "" {
		c.ActiveServer = name
	}
	return writeTOML(c, path)
}

// configFileNameFor 返回指定服务器对应的原始配置文件文件名：
// 激活服务器固定为 frpc.toml；其余服务器使用独立文件 frpc-<name>-<hash>.toml 保存。
func (m *Manager) configFileNameFor(name string) string {
	cfg := m.LoadConfig()
	if name == "" || name == cfg.ActiveServer {
		return ConfigFile
	}
	return configRawFileName(name)
}

// ActiveServerName 返回当前激活（默认）服务器名称。
func (m *Manager) ActiveServerName() string {
	return m.LoadConfig().ActiveServer
}

// RenderConfigFor 按指定服务器生成 frpc.toml 内容预览（不写盘）；服务器不存在时回退为激活服务器。
func (m *Manager) RenderConfigFor(name string) (string, error) {
	cfg := m.LoadConfig()
	c := cfg
	if name != "" {
		c.ActiveServer = name
	}
	return renderTOML(c)
}

// ReadRawConfig 读取指定服务器的原始 frpc.toml 内容：
// 该服务器存在独立配置文件时直接返回文件内容；否则按结构化配置实时生成预览（不写盘）。
// isActive 表示该服务器是否为当前激活（默认）服务器。
func (m *Manager) ReadRawConfig(name string) (content string, isActive bool, err error) {
	cfg := m.LoadConfig()
	active := cfg.ActiveServer
	isActive = name == "" || name == active
	path := m.configPath(m.configFileNameFor(name))
	if data, rerr := os.ReadFile(path); rerr == nil {
		return string(data), isActive, nil
	}
	c := cfg
	if !isActive {
		c.ActiveServer = name
	}
	content, err = renderTOML(c)
	if err != nil {
		return "", isActive, err
	}
	return content, isActive, nil
}

// ==================== 原始 frpc.toml 代理解析 ====================

// tomlProxy 与 frp 生成的 frpc.toml [[proxies]] 段对应的解析结构。
type tomlProxy struct {
	Name          string   `toml:"name"`
	Type          string   `toml:"type"`
	Enabled       *bool    `toml:"enabled"`
	LocalIP       string   `toml:"localIP"`
	LocalPort     int      `toml:"localPort"`
	RemotePort    int      `toml:"remotePort"`
	CustomDomains []string `toml:"customDomains"`
	Subdomain     string   `toml:"subdomain"`
	HTTPUser      string   `toml:"httpUser"`
	HTTPPassword  string   `toml:"httpPassword"`
	SecretKey     string   `toml:"secretKey"`
	Transport     struct {
		UseEncryption        *bool  `toml:"useEncryption"`
		UseCompression       *bool  `toml:"useCompression"`
		BandwidthLimit       string `toml:"bandwidthLimit"`
		BandwidthLimitMode   string `toml:"bandwidthLimitMode"`
		ProxyProtocolVersion string `toml:"proxyProtocolVersion"`
	} `toml:"transport"`
	HealthCheck *struct {
		Type            string `toml:"type"`
		IntervalSeconds int    `toml:"intervalSeconds"`
		TimeoutSeconds  int    `toml:"timeoutSeconds"`
		MaxFailed       int    `toml:"maxFailed"`
		Path            string `toml:"path"`
	} `toml:"healthCheck"`
}

// ParseProxiesFromTOML 解析 frpc.toml 中的 [[proxies]] 代理通道列表，
// 供用户手动编辑配置文件后同步回结构化配置（frpc.json），使界面能识别并管理这些通道。
// 解析失败返回错误；frp 特有的字段（metadatas/plugin 等）不在 Proxy 结构中，将被忽略。
func ParseProxiesFromTOML(content string) ([]Proxy, error) {
	var doc struct {
		Proxies []tomlProxy `toml:"proxies"`
	}
	if err := toml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, err
	}
	out := make([]Proxy, 0, len(doc.Proxies))
	for _, tp := range doc.Proxies {
		if strings.TrimSpace(tp.Name) == "" {
			continue
		}
		enabled := true
		if tp.Enabled != nil {
			enabled = *tp.Enabled
		}
		enc := false
		if tp.Transport.UseEncryption != nil {
			enc = *tp.Transport.UseEncryption
		}
		comp := false
		if tp.Transport.UseCompression != nil {
			comp = *tp.Transport.UseCompression
		}
		p := Proxy{
			Name:               strings.TrimSpace(tp.Name),
			Type:               strings.ToLower(strings.TrimSpace(tp.Type)),
			Enabled:            enabled,
			LocalIP:            strings.TrimSpace(tp.LocalIP),
			LocalPort:          tp.LocalPort,
			RemotePort:         tp.RemotePort,
			CustomDomains:      strings.Join(tp.CustomDomains, ","),
			Subdomain:          strings.TrimSpace(tp.Subdomain),
			HTTPUser:           strings.TrimSpace(tp.HTTPUser),
			HTTPPassword:       tp.HTTPPassword,
			Encryption:         enc,
			Compression:        comp,
			BandwidthLimit:     strings.TrimSpace(tp.Transport.BandwidthLimit),
			BandwidthLimitMode: strings.ToLower(strings.TrimSpace(tp.Transport.BandwidthLimitMode)),
			SecretKey:          strings.TrimSpace(tp.SecretKey),
		}
		if tp.HealthCheck != nil && strings.TrimSpace(tp.HealthCheck.Type) != "" {
			p.HealthCheck = &HealthCheck{
				Type:            strings.ToLower(strings.TrimSpace(tp.HealthCheck.Type)),
				IntervalSeconds: tp.HealthCheck.IntervalSeconds,
				TimeoutSeconds:  tp.HealthCheck.TimeoutSeconds,
				MaxFailed:       tp.HealthCheck.MaxFailed,
				Path:            strings.TrimSpace(tp.HealthCheck.Path),
			}
		}
		out = append(out, normalizeProxy(p))
	}
	return out, nil
}

// ==================== 原始 frpc.toml 保存 ====================

// webServerPortRe / webServerAddrRe 匹配原始配置里的顶层 webServer 键（捕获缩进，便于原地替换）。
var (
	webServerPortRe = regexp.MustCompile(`(?m)^([ \t]*)webServer\.port\s*=.*$`)
	webServerAddrRe = regexp.MustCompile(`(?m)^[ \t]*webServer\.addr\s*=`)
)

// syncWebServer 把原始配置里的管理 API 端口对齐为该服务器在结构化配置中的 AdminPort，
// 缺失 webServer 段时补全，保证界面能通过管理 API 实时查询各代理状态。
//
// 端口由程序独占决定，而不是「缺失才注入」：管理 API 是程序与 frpc 之间的内部约定，
// 旧版本按列表位置分配端口时写进 toml 的值一旦被当成用户自定义永久保留，
// 配置侧的端口变化后就再也不会同步，查询全部落空（前端表现为代理一直显示「连接中」）。
// addr 等其他自定义项保持原样；顶层键必须位于任何 [表] 之前（TOML 规范），缺失时前置注入。
func (m *Manager) syncWebServer(content, server string) string {
	port := AdminPortBase
	if s, ok := serverByName(m.LoadConfig(), server); ok && s.AdminPort > 0 {
		port = s.AdminPort
	}
	line := fmt.Sprintf("webServer.port = %d", port)
	if webServerPortRe.MatchString(content) {
		return webServerPortRe.ReplaceAllString(content, "${1}"+line)
	}
	head := line + "\n"
	if !webServerAddrRe.MatchString(content) {
		head = "webServer.addr = \"127.0.0.1\"\n" + head
	}
	return head + "\n" + strings.TrimLeft(content, "\n")
}

// 激活服务器保存后若运行中则重启立即生效；非激活服务器仅写入独立文件，切换为激活时生效。
// 保存时自动解析 toml 中的 [[proxies]] 代理通道，同步回结构化配置（frpc.json），
// 使界面能识别并管理用户手动编辑的代理通道。
func (m *Manager) SaveRawConfigFor(name, content string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(content) == "" {
		return errors.New("配置内容不能为空")
	}
	if _, err := os.Stat(m.BinPath()); err != nil {
		return errors.New("frpc 未安装，请先安装")
	}
	if err := os.MkdirAll(m.dir, 0755); err != nil {
		return err
	}
	if err := m.ensureConfigDir(); err != nil {
		return err
	}
	// 解析并同步代理到结构化配置：该服务器归属的代理以 toml 为准完全替换，
	// 其他服务器的代理保留（仅持久化 frpc.json，不触发重启/覆盖刚保存的 toml）
	cfg := m.LoadConfig()
	server := name
	if server == "" {
		server = cfg.ActiveServer
	}
	// 确保管理 API 端口与配置一致：用户手动编辑的配置可能缺失 webServer 段或残留旧端口，
	// 否则 frpc 管理 API 不可用或查错端口，界面无法实时获取代理状态（表现为一直显示「连接中」）
	content = m.syncWebServer(content, server)
	if parsed, perr := ParseProxiesFromTOML(content); perr == nil {
		for i := range parsed {
			parsed[i].Server = server
		}
		var others []Proxy
		for _, p := range cfg.Proxies {
			if p.Server != server {
				others = append(others, p)
			}
		}
		cfg.Proxies = append(others, parsed...)
		cfg = NormalizeConfig(cfg)
		if err := m.persistConfig(cfg); err != nil && m.logger != nil {
			m.logger.Warn("同步配置文件代理到结构化配置失败", zap.Error(err))
		}
	} else if m.logger != nil {
		m.logger.Warn("解析 frpc.toml 代理失败（界面无法同步手动编辑的通道）", zap.Error(perr))
	}
	tomlPath := m.configPath(m.configFileNameFor(name))
	if err := os.WriteFile(tomlPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}
	// 保存后若该服务器运行中则重启，直接用新配置启动（激活/非激活均生效）
	if m.cmdAliveFor(name) || m.pidAliveFor(name) {
		if err := m.stopServerLocked(name); err != nil {
			return err
		}
		return m.startWithFileLocked(name, tomlPath)
	}
	return nil
}

// startWithFileLocked 使用指定配置文件启动指定服务器的 frpc 子进程（须持有 m.mu）。
func (m *Manager) startWithFileLocked(name, tomlPath string) error {
	bin := m.BinPath()
	if _, err := os.Stat(bin); err != nil {
		return errors.New("frpc 未安装，请先安装")
	}
	logPath := m.logPathFor(name)
	logF, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %w", err)
	}

	cmd := exec.Command(bin, "-c", tomlPath)
	cmd.Stdout = logF
	cmd.Stderr = logF
	// 独立进程组 + 父进程退出时自动终止，避免残留
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		logF.Close()
		return fmt.Errorf("启动 frpc 失败: %w", err)
	}
	m.cmds[name] = cmd
	m.writePIDFor(name, cmd.Process.Pid)
	if m.logger != nil {
		m.logger.Info("frpc 已启动", zap.String("server", name), zap.Int("pid", cmd.Process.Pid))
	}
	go func(c *exec.Cmd, f *os.File) {
		_ = c.Wait()
		f.Close()
		m.mu.Lock()
		if m.cmds[name] == c {
			delete(m.cmds, name)
		}
		m.mu.Unlock()
		if m.readPIDFor(name) == c.Process.Pid {
			m.clearPIDFor(name)
		}
	}(cmd, logF)
	return nil
}

// Stop 停止所有运行中的 frpc 进程。
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for _, s := range m.LoadConfig().Servers {
		if err := m.stopServerLocked(s.Name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// StopServer 停止指定服务器的 frpc 进程（不存在则返回 nil）。
func (m *Manager) StopServer(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopServerLocked(name)
}

func (m *Manager) stopServerLocked(name string) error {
	// 无论进程是否实际存在，先清除进程记录：否则紧随其后的 startServerLocked 会
	// 因 cmdAliveFor 读到旧 cmd（Wait goroutine 尚未清理）误判「已在运行」而跳过重启，
	// 导致删除代理等配置变更后 frpc.toml 不重新生成、进程不重启。
	defer delete(m.cmds, name)
	pid := m.readPIDFor(name)
	if pid <= 0 {
		return nil
	}
	// pid 文件残留时该 PID 可能已被无关进程复用：必须确认是本程序的 frpc 才发信号，
	// 否则会误杀无关进程（本函数还向整个进程组发信号，波及面更大）。
	if !m.pidIsOurs(name) {
		m.clearPIDFor(name)
		return nil
	}
	// 优先向整个进程组发信号（子进程也被终止）
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	for i := 0; i < 30; i++ {
		if err := syscall.Kill(pid, 0); err != nil {
			m.clearPIDFor(name)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	// 超时强杀
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
	m.clearPIDFor(name)
	if m.logger != nil {
		m.logger.Warn("frpc 停止超时，已强制终止", zap.String("server", name), zap.Int("pid", pid))
	}
	return nil
}

// Restart 重启所有已配置有效地址的 frpc 进程（未运行的仅启动）。
func (m *Manager) Restart() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restartAllLocked()
}

// RestartServer 重启指定服务器的 frpc 进程（未运行时仅启动）。
func (m *Manager) RestartServer(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.stopServerLocked(name)
	return m.startServerLocked(name)
}

// restartAllLocked 重启所有已配置有效地址的服务器进程（须持有 m.mu）。
func (m *Manager) restartAllLocked() error {
	var firstErr error
	for _, s := range m.LoadConfig().Servers {
		if strings.TrimSpace(s.Addr) == "" {
			continue
		}
		_ = m.stopServerLocked(s.Name)
		if err := m.startServerLocked(s.Name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// scheduleApply 延迟应用 frpc 配置（异步，去抖合并）：
// 配置保存后把应用动作推迟到当前 HTTP 请求响应完整写回之后执行，
// 避免经 frp 隧道管理自身配置时同步重启把请求响应打断（公网反代场景表现为 400/502）。
// 短时间内多次保存只触发一次应用；restart=true 时整进程重启，否则走热加载。
// 应用失败仅记录日志，不阻断配置保存。
func (m *Manager) scheduleApply(restart bool) {
	m.restartMu.Lock()
	if restart {
		m.restartForce = true
	}
	if m.restartPending {
		m.restartMu.Unlock()
		return
	}
	m.restartPending = true
	m.restartMu.Unlock()
	go func() {
		time.Sleep(800 * time.Millisecond) // 等当前请求响应经隧道写回
		m.restartMu.Lock()
		force := m.restartForce
		m.restartForce = false
		m.restartPending = false
		m.restartMu.Unlock()
		m.mu.Lock()
		var err error
		if force {
			err = m.restartAllLocked()
		} else {
			err = m.reloadAllLocked()
		}
		m.mu.Unlock()
		if err != nil {
			m.logger.Warn("frpc 延迟应用配置失败", zap.Bool("restart", force), zap.Error(err))
		}
	}()
}

// reloadAllLocked 写回各实例的 TOML 并通过 frpc 管理 API 热加载代理配置（须持有 m.mu）。
// 任一实例热加载失败时回退为该实例的整进程重启，保证配置最终生效。
func (m *Manager) reloadAllLocked() error {
	cfg := m.LoadConfig()
	var firstErr error
	for _, s := range cfg.Servers {
		if strings.TrimSpace(s.Addr) == "" {
			continue
		}
		if !m.cmdAliveFor(s.Name) && !m.pidAliveFor(s.Name) {
			continue // 未运行：下次启动自然会读取新配置
		}
		if _, err := m.prepareConfigFileLocked(cfg, s.Name); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := m.reloadServerLocked(s); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			_ = m.stopServerLocked(s.Name)
			if err := m.startServerLocked(s.Name); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// reloadServerLocked 调用 frpc 管理 API 热加载代理配置（GET /api/reload）。
// 该接口只重读代理段，不会断开已建立的隧道；连接级参数变更必须走重启。
func (m *Manager) reloadServerLocked(s Server) error {
	port := s.AdminPort
	if port <= 0 {
		port = AdminPortBase
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/reload", port), nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("frpc 热加载失败(%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// AutoStart 开机自启：启动所有「开机自启」开启的服务器（默认服务器无条件自启；延迟由调用方控制）。
// 若 frpc 未安装但存在内置离线包，则先自动安装再启动（自愈：避免重装 fnOS / 重置数据后无法自启）。
func (m *Manager) AutoStart() error {
	if !m.Installed() {
		// 尝试用内置离线包自动安装一次（应用包自带 frp tar.gz）
		if m.findBundle() == "" {
			if m.logger != nil {
				m.logger.Warn("frpc 未安装且未找到内置安装包，跳过自动启动")
			}
			return nil
		}
		if m.logger != nil {
			m.logger.Info("frpc 未安装，使用内置包自动安装后自启")
		}
		if err := m.Install(); err != nil {
			return fmt.Errorf("自动安装 frpc 失败: %w", err)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.LoadConfig()
	var firstErr error
	for _, s := range cfg.Servers {
		if strings.TrimSpace(s.Addr) == "" {
			continue
		}
		autoOn := s.AutoStartOn != nil && *s.AutoStartOn
		if !autoOn && s.Name != cfg.ActiveServer {
			continue // 关闭了开机自启的非默认服务器不自动启动
		}
		if err := m.startServerLocked(s.Name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Installed 是否已安装 frpc。
func (m *Manager) Installed() bool {
	_, err := os.Stat(m.BinPath())
	return err == nil
}

// Version 当前安装的 frpc 版本号。
func (m *Manager) Version() string {
	if v, err := os.ReadFile(filepath.Join(m.dir, VersionFile)); err == nil {
		if s := strings.TrimSpace(string(v)); s != "" {
			return s
		}
	}
	if v, err := m.binVersion(); err == nil && v != "" {
		return v
	}
	return ""
}

func (m *Manager) binVersion() (string, error) {
	bin := m.BinPath()
	if _, err := os.Stat(bin); err != nil {
		return "", err
	}
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "frpc")), nil
}

// Status 返回当前状态快照（含各服务器运行状态）。
func (m *Manager) Status() Status {
	st := Status{ConfigPath: m.configPath(ConfigFile)}
	if m.Installed() {
		st.Installed = true
		st.Version = m.Version()
	}
	st.Running = m.isRunning()
	st.BundleAvailable = m.findBundle() != ""
	st.Progress = m.snapshotProgress()
	cfg := m.LoadConfig()
	for _, s := range cfg.Servers {
		autoOn := s.AutoStartOn != nil && *s.AutoStartOn
		if s.Name == cfg.ActiveServer {
			autoOn = true // 默认服务器强制开机自启
		}
		st.Servers = append(st.Servers, ServerStatus{
			Name:        s.Name,
			Configured:  strings.TrimSpace(s.Addr) != "",
			Running:     m.ServerRunning(s.Name),
			PID:         m.pidIfOurs(s.Name),
			AdminPort:   s.AdminPort,
			AutoStartOn: autoOn,
			// 进程活着 ≠ 登录成功：write timeout / authorization failed 只写在日志里，
			// 不带出来的话界面只能显示「运行中」，用户看不到真正失败原因。
			LastError: m.LastErrorFor(s.Name),
			// 连续登录失败次数：达阈值后看门狗会自动重启实例，
			// 界面据此提示「正在自动恢复」，避免用户只看到一个不动的「运行中」。
			WatchdogFails: m.WatchdogFails(s.Name),
		})
	}
	return st
}

// PID 返回激活服务器 frpc 进程 PID（未运行或无 pid 文件时为 0）。
func (m *Manager) PID() int {
	return m.pidIfOurs(m.activeServerName())
}

// PIDFor 返回指定服务器 frpc 进程 PID。
func (m *Manager) PIDFor(name string) int {
	return m.pidIfOurs(name)
}

// LogTail 返回激活服务器 frpc.log 末尾 n 行（n<=0 时默认 200）。
func (m *Manager) LogTail(n int) string {
	return m.LogTailFor(m.activeServerName(), n)
}

// LogTailFor 返回指定服务器 frpc 日志末尾 n 行（n<=0 时默认 200）。
//
// 纯读操作，不修改日志文件——裁剪由 TrimLogs 在低频维护周期里执行。
// 此前这里顺带按 cfg.LogEntries 裁剪日志，但本方法会被登录看门狗每 2 秒调用一次，
// 每次读都变成「读全文 + 可能重写全文」，等于把只读接口变成了高频写盘。
func (m *Manager) LogTailFor(name string, n int) string {
	if n <= 0 {
		n = 200
	}
	data, err := os.ReadFile(m.logPathFor(name))
	if err != nil {
		return ""
	}
	s := strings.TrimRight(string(data), "\n")
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// trimLog 将激活服务器 frpc.log 截断为末尾 maxLines 行。
func (m *Manager) trimLog(maxLines int) {
	m.trimLogFor(maxLines, m.activeServerName())
}

// trimLogFor 将指定服务器 frpc 日志截断为末尾 maxLines 行（maxLines<=0 不操作；文件不存在/行数不足时跳过）。
func (m *Manager) trimLogFor(maxLines int, name string) {
	if maxLines <= 0 {
		return
	}
	path := m.logPathFor(name)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) <= maxLines {
		return
	}
	kept := strings.Join(lines[len(lines)-maxLines:], "\n") + "\n"
	_ = os.WriteFile(path, []byte(kept), 0644)
}

// TrimLogs 按配置的 frpc.log 保留行数（cfg.LogEntries，0=不限制）裁剪各服务器日志，防止无限增长。
// 这是日志裁剪的唯一入口，与读取路径解耦：读取必须保持纯读，
// 否则被高频调用者（登录看门狗每 2s 一次）连带触发整份日志重写。
func (m *Manager) TrimLogs() {
	cfg := m.LoadConfig()
	if cfg.LogEntries <= 0 {
		return
	}
	for _, s := range cfg.Servers {
		m.trimLogFor(cfg.LogEntries, s.Name)
	}
}

// ansiRe 匹配 ANSI 颜色转义序列。frpc 日志行首带颜色码（如 \x1b[0m\x1b[1;34m），
// 不剥离会让级别正则整体错位，把 [I] 普通日志误判成错误。
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// frpcErrRe 匹配 frpc 日志中的级别标记与正文（调用前须已剥离 ANSI 转义）。
// frpc 日志形如：2026-10-16 10:05:35.793 [W] [client/service.go:323] connect to server error: connection write timeout
var frpcErrRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\[([WE])\]\s*(?:\[[^\]]*\]\s*)?(.*)$`)

// LastErrorFor 返回指定服务器 frpc 日志中最近一条警告/错误的原因文本（无则返回空串）。
// 界面用它把「连不上」具体化：frpc 进程启动成功不代表登录成功，
// connection write timeout / authorization failed 等原因只出现在日志里，
// 状态接口的 running 字段无法区分，必须从日志取。
func (m *Manager) LastErrorFor(name string) string {
	lines := strings.Split(m.LogTailFor(name, 500), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		ln := strings.TrimRight(ansiRe.ReplaceAllString(lines[i], ""), "\r")
		if strings.TrimSpace(ln) == "" {
			continue
		}
		sub := frpcErrRe.FindStringSubmatch(ln)
		if sub == nil {
			continue // 非 [W]/[E] 行（[I] 普通日志等），不算错误
		}
		reason := strings.TrimSpace(sub[2])
		if reason == "" {
			continue
		}
		return reason
	}
	return ""
}

// ==================== 升级 ====================

// LatestRelease 查询 frp 最新版本号。
//
// 不使用 GitHub API：api.github.com 未认证每小时仅 60 次且按出口 IP 计数，
// 国内/共享出口环境频繁返回 403。改用 releases/latest/download 的第一次 302：
// Location 形如 /releases/download/v0.71.0/<file>，取其中 tag 即最新版。
// 官方源与国内镜像并发探测，谁先返回合法 tag 就用谁，整体 8s 兜底。
func (m *Manager) LatestRelease() (string, error) {
	type probeResult struct {
		version string
		mirror  string
	}
	results := make(chan probeResult, len(frpGitHubMirrors))
	// 禁止自动跟随重定向：拿到第一次 302 的 Location 即可，跟随后续跳到对象存储就看不到 tag 了
	client := &http.Client{
		Timeout:       latestProbeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, mir := range frpGitHubMirrors {
		go func(mir frpMirror) {
			probeURL := mir.prefix + frpGitHubRaw + "/releases/latest/download/" + frpLatestProbeFile
			results <- probeResult{version: probeFrpLatest(client, probeURL), mirror: mir.name}
		}(mir)
	}
	deadline := time.NewTimer(latestProbeTotal)
	defer deadline.Stop()
	for i := 0; i < len(frpGitHubMirrors); i++ {
		select {
		case r := <-results:
			if r.version == "" {
				continue
			}
			if m.logger != nil {
				m.logger.Info("frp 最新版已确认", zap.String("version", r.version), zap.String("mirror", r.mirror))
			}
			return r.version, nil
		case <-deadline.C:
			return "", errors.New("检查最新版本超时，请稍后重试或使用离线安装")
		}
	}
	return "", errors.New("检查最新版本失败：官方及镜像源均不可用，请使用离线安装")
}

// probeFrpLatest 请求单个源并从 302 Location（或最终请求路径）中解析版本号，失败返回空串。
func probeFrpLatest(client *http.Client, probeURL string) string {
	req, err := http.NewRequest(http.MethodGet, probeURL, nil)
	if err != nil {
		return ""
	}
	// 只要响应头，不下载正文
	req.Header.Set("Range", "bytes=0-0")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if v := frpTagFromURL(resp.Header.Get("Location")); v != "" {
		return v
	}
	// 个别镜像会自行跟随重定向后透传 200，退回从最终请求地址中解析
	return frpTagFromURL(resp.Request.URL.String())
}

// frpTagFromURL 从 URL 中定位 releases/download/<tag>/ 段并取出 x.y.z 版本号（去掉 v 前缀）。
// 镜像返回的 Location 可能是相对路径（/https://github.com/...），按路径段扫描即可兼容。
func frpTagFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "releases" && parts[i+1] == "download" {
			v := strings.TrimPrefix(parts[i+2], "v")
			if versionRe.MatchString(v) {
				return v
			}
		}
	}
	return ""
}

// DownloadUpgrade 下载指定版本并升级：官方源优先，失败按镜像列表顺序回退。
func (m *Manager) DownloadUpgrade(version string) error {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if !versionRe.MatchString(version) {
		return errors.New("无效的版本号: " + version)
	}
	pkgDir := filepath.Join(m.dir, PackagesDir)
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		m.clearProgress()
		return err
	}
	part := filepath.Join(pkgDir, ".frp_"+version+".tar.gz.part")
	final := filepath.Join(pkgDir, fmt.Sprintf("frp_%s_linux_amd64.tar.gz", version))
	assetPath := fmt.Sprintf("/releases/download/v%s/frp_%s_linux_amd64.tar.gz", version, version)

	var lastErr error
	for _, mir := range frpGitHubMirrors {
		dlURL := mir.prefix + frpGitHubRaw + assetPath
		if m.logger != nil {
			m.logger.Info("下载 frp 安装包", zap.String("mirror", mir.name), zap.String("url", dlURL))
		}
		m.setProgress(0, 0, "正在连接"+mir.name+"…")
		if err := m.downloadUpgradeFromURL(dlURL, part); err != nil {
			lastErr = fmt.Errorf("%s: %v", mir.name, err)
			if m.logger != nil {
				m.logger.Warn("frp 安装包下载失败，尝试下一源", zap.String("mirror", mir.name), zap.Error(err))
			}
			os.Remove(part)
			continue
		}
		m.setProgress(0, 0, "正在替换内核…")
		if err := os.Rename(part, final); err != nil {
			os.Remove(part)
			m.clearProgress()
			return err
		}
		return m.installFromArchive(final, false)
	}
	m.clearProgress()
	return fmt.Errorf("所有下载源均失败：%v", lastErr)
}

// downloadUpgradeFromURL 从单个源下载到 part 文件，并按 Content-Length 校验完整性。
// 服务端提前断开时 io.Copy 可能返回 nil，必须比对已获取字节数。
func (m *Manager) downloadUpgradeFromURL(dlURL, part string) error {
	client := &http.Client{Timeout: downloadTimeout}
	resp, err := client.Get(dlURL)
	if err != nil {
		return fmt.Errorf("下载失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("下载失败: HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(part)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(f, &progressReader{r: resp.Body, m: m, total: resp.ContentLength, stage: "正在下载内核包…"})
	f.Close()
	if copyErr != nil {
		os.Remove(part)
		return fmt.Errorf("下载失败: %v", copyErr)
	}
	if resp.ContentLength > 0 && n != resp.ContentLength {
		os.Remove(part)
		return fmt.Errorf("下载不完整: 已获取 %d / %d 字节", n, resp.ContentLength)
	}
	return nil
}

// ==================== 内部工具 ====================

// isRunning 是否有任一 frpc 进程在运行。
func (m *Manager) isRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.anyRunningLocked()
}

// anyRunningLocked 任一服务器进程运行中（须持有 m.mu）。
func (m *Manager) anyRunningLocked() bool {
	for _, s := range m.LoadConfig().Servers {
		if m.cmdAliveFor(s.Name) || m.pidAliveFor(s.Name) {
			return true
		}
	}
	return false
}

// ServerRunning 指定服务器是否运行中。
func (m *Manager) ServerRunning(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cmdAliveFor(name) || m.pidAliveFor(name)
}

// RunningPIDs 返回所有运行中的服务器及其 pid（服务器名 → pid）。
func (m *Manager) RunningPIDs() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for _, s := range m.LoadConfig().Servers {
		if pid := m.livePIDFor(s.Name); pid > 0 {
			out[s.Name] = pid
		}
	}
	return out
}

// livePIDFor 运行中服务器的 PID：优先用内存中的进程记录（刚启动时 pid 文件可能还没落盘），
// 否则读 pid 文件并校验归属。调用方需持有 m.mu。
func (m *Manager) livePIDFor(name string) int {
	if c := m.cmds[name]; c != nil && c.Process != nil && c.ProcessState == nil {
		return c.Process.Pid
	}
	return m.pidIfOurs(name)
}

func (m *Manager) cmdAliveFor(name string) bool {
	c := m.cmds[name]
	if c == nil || c.Process == nil {
		return false
	}
	return c.ProcessState == nil
}

func (m *Manager) pidAliveFor(name string) bool {
	return m.pidIsOurs(name)
}

// pidIsOurs pid 文件中记录的进程是否存活且确实是本程序的 frpc。
// 只做存活探测是不够的：pid 文件在进程被强杀/断电后会残留，残留 PID 可能被系统
// 复用给无关进程，导致状态误报「运行中」，甚至让 Stop 误杀无关进程。
func (m *Manager) pidIsOurs(name string) bool {
	return procutil.AliveAs(m.readPIDFor(name), m.BinPath())
}

// pidIfOurs 仅当 pid 文件对应的是本程序的 frpc 时返回 PID，否则返回 0。
func (m *Manager) pidIfOurs(name string) int {
	pid := m.readPIDFor(name)
	if !procutil.AliveAs(pid, m.BinPath()) {
		return 0
	}
	return pid
}

func (m *Manager) readPIDFor(name string) int {
	data, err := os.ReadFile(m.pidPath(name))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}

func (m *Manager) writePIDFor(name string, pid int) {
	_ = os.WriteFile(m.pidPath(name), []byte(strconv.Itoa(pid)), 0644)
}

func (m *Manager) clearPIDFor(name string) {
	_ = os.Remove(m.pidPath(name))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// ==================== 升级进度 ====================

func (m *Manager) setProgress(done, total int64, stage string) {
	m.progressMu.Lock()
	defer m.progressMu.Unlock()
	pct := 0
	if total > 0 {
		pct = int(float64(done) / float64(total) * 100)
		if pct > 100 {
			pct = 100
		}
	}
	m.progress = &Progress{Done: done, Total: total, Percent: pct, Stage: stage}
}

func (m *Manager) clearProgress() {
	m.progressMu.Lock()
	m.progress = nil
	m.progressMu.Unlock()
}

func (m *Manager) snapshotProgress() *Progress {
	m.progressMu.Lock()
	defer m.progressMu.Unlock()
	if m.progress == nil {
		return nil
	}
	p := *m.progress
	return &p
}

// progressReader 包装下载流，实时向进度快照写入已下载字节数。
type progressReader struct {
	r     io.Reader
	m     *Manager
	total int64
	done  int64
	stage string
}

func (p *progressReader) Read(buf []byte) (int, error) {
	n, err := p.r.Read(buf)
	if n > 0 {
		p.done += int64(n)
		p.m.setProgress(p.done, p.total, p.stage)
	}
	return n, err
}
