package web

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"tunhook/errpage"
)

// ============= Web 服务（本地静态站点托管） =============
//
// 每个站点独立监听一个 TCP 端口，用 net/http 提供指定目录下的静态文件：
//   - 首页文件可配置（默认 index.html），目录是否允许浏览可开关；
//   - 可选 HTTP Basic Auth；
//   - 运行状态、请求数、字节数与最近访问日志仅保存在内存中，重启后清零。
//
// 站点配置持久化到 settings KV（webserver.sites），跨浏览器/设备共享；
// 与 WAF / 网络唤醒一致，不进入备份包。

const (
	webSitesKey       = "webserver.sites" // 站点列表在 settings KV 中的键名
	webSiteLogLimit   = 300               // 每个站点保留的访问日志条数
	webSiteDefaultIdx = "index.html"      // 默认首页文件
)

// 站点类型。
const (
	WebTypeStatic   = "static"   // 静态站点
	WebTypeShare    = "share"    // 文件分享
	WebTypeProxy    = "proxy"    // 反向代理
	WebTypeRedirect = "redirect" // 重定向
	WebTypeText     = "text"     // 固定文本
)

// WebSite 一个 Web 服务站点配置。
// 一个站点独立监听一个端口；类型决定请求如何被处理。
type WebSite struct {
	ID        string `json:"id"`         // 站点唯一标识（新建时后端补齐）
	Name      string `json:"name"`       // 展示名称
	Type      string `json:"type"`       // static / share / proxy / redirect / text
	Addr      string `json:"addr"`       // 监听地址，0.0.0.0 表示全部网卡
	Port      int    `json:"port"`       // 监听端口
	AutoStart bool   `json:"auto_start"` // 随应用启动自启
	// 访问方式：port=独立端口；path=挂在统一 HTTP 端口的路径前缀下
	AccessMode string `json:"access_mode,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`

	// 静态站点 / 文件分享：站点根目录（文件分享允许指向单个文件）
	Root   string `json:"root,omitempty"`
	Index  string `json:"index,omitempty"`  // 首页文件（默认 index.html）
	Browse bool   `json:"browse,omitempty"` // 是否允许目录浏览

	// 固定文本
	Text            string `json:"text,omitempty"`
	TextContentType string `json:"text_content_type,omitempty"`
	TextStatus      int    `json:"text_status,omitempty"`

	// 重定向
	RedirectTo        string `json:"redirect_to,omitempty"`
	RedirectCode      int    `json:"redirect_code,omitempty"`
	RedirectKeepPath  bool   `json:"redirect_keep_path,omitempty"`
	RedirectKeepQuery bool   `json:"redirect_keep_query,omitempty"`

	// 反向代理
	Proxy WebProxyConfig `json:"proxy,omitempty"`

	// 文件分享
	Share WebShareConfig `json:"share,omitempty"`

	// 认证与访问控制
	Security   WebSecurityConfig `json:"security,omitempty"`
	TempShares []WebTempShare    `json:"temp_shares,omitempty"`

	// 通用 HTTP 行为
	AccessLog   bool   `json:"access_log,omitempty"`
	CORS        bool   `json:"cors,omitempty"`
	ReqHeaders  string `json:"req_headers,omitempty"`  // 每行一个 Key: Value
	RespHeaders string `json:"resp_headers,omitempty"` // 每行一个 Key: Value

	// 兼容旧版静态站点的 Basic Auth 字段（新配置请使用 Security.Users）
	AuthUser string `json:"auth_user,omitempty"`
	AuthPass string `json:"auth_pass,omitempty"`

	// 配置版本：0 表示旧版站点配置（加载时迁移）
	ConfigVersion int `json:"config_version,omitempty"`
}

// WebProxyBackend 一个反向代理后端。
type WebProxyBackend struct {
	URL    string `json:"url"`
	Weight int    `json:"weight,omitempty"`
	Backup bool   `json:"backup,omitempty"`
}

// WebHealthCheck 主动健康检查配置。
type WebHealthCheck struct {
	Enabled  bool   `json:"enabled"`
	Mode     string `json:"mode,omitempty"`     // http / tcp
	Path     string `json:"path,omitempty"`     // http 模式的检查路径
	Interval int    `json:"interval,omitempty"` // 秒
	Timeout  int    `json:"timeout,omitempty"`  // 秒
	Fails    int    `json:"fails,omitempty"`    // 连续失败判定
	Passes   int    `json:"passes,omitempty"`   // 连续成功恢复
}

// WebPathRule 反向代理的路径重写 / 重定向规则。
type WebPathRule struct {
	Pattern  string `json:"pattern"`            // 正则，匹配请求路径
	To       string `json:"to"`                 // 替换结果，支持 $1
	Redirect bool   `json:"redirect,omitempty"` // true=重定向，false=内部重写
	Code     int    `json:"code,omitempty"`     // 重定向状态码
}

// WebProxyConfig 反向代理配置。
type WebProxyConfig struct {
	Backends         []WebProxyBackend `json:"backends,omitempty"`
	LBPolicy         string            `json:"lb_policy,omitempty"` // round_robin / random / ip_hash / least_conn
	UseBackendHost   bool              `json:"use_backend_host,omitempty"`
	SkipTLSVerify    bool              `json:"skip_tls_verify,omitempty"`
	DisableKeepAlive bool              `json:"disable_keep_alive,omitempty"`
	PROXYProtocol    bool              `json:"proxy_protocol,omitempty"`
	XForwarded       bool              `json:"x_forwarded,omitempty"`
	Compression      bool              `json:"compression,omitempty"`
	RateLimit        int               `json:"rate_limit,omitempty"` // 每 IP 每秒请求数
	Burst            int               `json:"burst,omitempty"`
	MaxConns         int               `json:"max_conns,omitempty"` // 每 IP 最大并发
	CacheTTL         int               `json:"cache_ttl,omitempty"` // 秒，0=仅缓存上游显式允许的响应
	CacheMaxMB       int               `json:"cache_max_mb,omitempty"`
	HealthCheck      WebHealthCheck    `json:"health_check,omitempty"`
	PathRules        []WebPathRule     `json:"path_rules,omitempty"`
}

// WebShareConfig 文件分享配置。
type WebShareConfig struct {
	Slug            string `json:"slug,omitempty"`             // 访问路径（/s/{slug}）
	AccessCode      string `json:"access_code,omitempty"`      // 提取码，空=不需要
	ExpiresAt       string `json:"expires_at,omitempty"`       // RFC3339 或 2006-01-02 15:04:05
	MaxDownloads    int    `json:"max_downloads,omitempty"`    // 总下载上限，0=不限
	PerIPDaily      int    `json:"per_ip_daily,omitempty"`     // 每 IP 每日下载上限，0=不限
	Preview         bool   `json:"preview,omitempty"`          // 允许在线预览
	DisableDownload bool   `json:"disable_download,omitempty"` // 禁止下载，仅允许在线查看
	PackageDownload bool   `json:"package_download,omitempty"` // 允许打包下载
	ShowDownloads   bool   `json:"show_downloads,omitempty"`   // 页面显示下载次数
	LogDownloads    bool   `json:"log_downloads,omitempty"`    // 记录下载日志
	OfficePreview   bool   `json:"office_preview,omitempty"`   // Office 外部预览
	Subtitle        string `json:"subtitle,omitempty"`         // 副标题，显示在分享页标题上方的小字
	Description     string `json:"description,omitempty"`
}

// WebSecurityPathRule 按路径前缀覆盖认证 / IP 控制。
type WebSecurityPathRule struct {
	Prefix   string `json:"prefix"`
	AuthMode string `json:"auth_mode,omitempty"` // 空=继承；off / on
	IPMode   string `json:"ip_mode,omitempty"`   // 空=继承；off / allow / deny
	IPList   string `json:"ip_list,omitempty"`
}

// WebSecurityConfig 认证与访问控制配置。
type WebSecurityConfig struct {
	AuthMode       string                `json:"auth_mode,omitempty"` // none / basic / web
	Users          string                `json:"users,omitempty"`     // 每行 username:password（支持 bcrypt）
	IPMode         string                `json:"ip_mode,omitempty"`   // off / allow / deny
	IPList         string                `json:"ip_list,omitempty"`
	IPAllow        string                `json:"ip_allow,omitempty"`        // 放行名单：优先于黑白名单、地区过滤与自动封禁
	TrustedProxies string                `json:"trusted_proxies,omitempty"` // 可信反代 IP / 网段，仅这些来源的 X-Real-IP / X-Forwarded-For 会被采信
	PathRules      []WebSecurityPathRule `json:"path_rules,omitempty"`
	FailLimit      int                   `json:"fail_limit,omitempty"`       // 失败次数阈值
	FailWindow     int                   `json:"fail_window,omitempty"`      // 统计窗口（分钟）
	AutoBanMinutes int                   `json:"auto_ban_minutes,omitempty"` // 自动封禁时长（分钟），0=只限流
	GeoMode        string                `json:"geo_mode,omitempty"`         // off / allow / deny
	GeoCountries   string                `json:"geo_countries,omitempty"`    // 逗号分隔的两位国家码
}

// WebTempShare 临时分享链接（开启认证后可免登录访问）。
type WebTempShare struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Token      string `json:"token"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	MaxUses    int    `json:"max_uses,omitempty"`
	Used       int    `json:"used,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
}

// webSiteAccess 一条访问日志。
type webSiteAccess struct {
	Time   string `json:"time"`
	IP     string `json:"ip"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Bytes  int64  `json:"bytes"`
	MS     int64  `json:"ms"`
	// Kind 标记请求性质，例如 crawler：正常响应但被识别为爬虫。
	// 安全事件页据此把非 401/403/429 的爬虫访问也列出来。
	Kind string `json:"kind,omitempty"`
}

// webSiteRun 一个运行中的站点实例。
type webSiteRun struct {
	id        string
	srv       *http.Server
	ln        net.Listener
	handler   http.Handler
	pathMode  bool
	startedAt time.Time
	requests  atomic.Uint64
	bytes     atomic.Int64

	mu      sync.Mutex
	logs    []webSiteAccess
	lastErr string

	// 认证失败计数与封禁（按站点、按 IP，内存态）
	secMu sync.Mutex
	fails map[string]*wsAuthFail
	bans  map[string]time.Time

	// 反代 / 文件分享运行时
	proxy *webProxyRuntime
	share *webShareRuntime

	// 站点级取消信号：停止站点时终止健康检查等后台任务
	ctx    context.Context
	cancel context.CancelFunc
}

func (r *webSiteRun) addLog(e webSiteAccess) {
	r.mu.Lock()
	if len(r.logs) >= webSiteLogLimit {
		// 环形保留：丢掉最旧的一条，避免日志无上限增长
		r.logs = append(r.logs[:0], r.logs[1:]...)
	}
	r.logs = append(r.logs, e)
	r.mu.Unlock()
}

func (r *webSiteRun) siteLogs() []webSiteAccess {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]webSiteAccess(nil), r.logs...)
}

func (r *webSiteRun) errText() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

func (r *webSiteRun) setErr(msg string) {
	r.mu.Lock()
	r.lastErr = msg
	r.mu.Unlock()
}

// webSiteView 站点配置 + 运行时状态（返回给前端）。
type webSiteView struct {
	WebSite
	Running     bool            `json:"running"`
	StartedAt   string          `json:"started_at,omitempty"`
	Requests    uint64          `json:"requests"`
	Bytes       int64           `json:"bytes"`
	Error       string          `json:"error,omitempty"`
	ProxyStatus *webProxyStatus `json:"proxy_status,omitempty"`
	ShareStats  *webShareView   `json:"share_stats,omitempty"`
}

// webProxyStatus 反代后端实时状态。
type webProxyStatus struct {
	Backends []webProxyBackendView `json:"backends"`
}

type webProxyBackendView struct {
	URL     string `json:"url"`
	Weight  int    `json:"weight"`
	Backup  bool   `json:"backup"`
	Healthy bool   `json:"healthy"`
	Paused  bool   `json:"paused,omitempty"`
	Active  int64  `json:"active"`
}

// normalizeWebSite 校验并规范化站点配置：所有来自界面的字段都必须在这里兜底，
// 直接调接口可以绕过前端校验。
func normalizeWebSite(site WebSite) (WebSite, error) {
	site.Name = strings.TrimSpace(site.Name)
	if site.Name == "" {
		return site, fmt.Errorf("站点名称不能为空")
	}
	if len([]rune(site.Name)) > 64 {
		return site, fmt.Errorf("站点名称不能超过 64 个字符")
	}

	site.Type = strings.ToLower(strings.TrimSpace(site.Type))
	if site.Type == "" {
		site.Type = WebTypeStatic
	}
	switch site.Type {
	case WebTypeStatic, WebTypeShare, WebTypeProxy, WebTypeRedirect, WebTypeText:
	default:
		return site, fmt.Errorf("站点类型无效：%s", site.Type)
	}

	site.AccessMode = strings.ToLower(strings.TrimSpace(site.AccessMode))
	if site.AccessMode == "" {
		site.AccessMode = "port"
	}
	switch site.AccessMode {
	case "port":
		addr := strings.TrimSpace(site.Addr)
		if addr == "" {
			addr = "0.0.0.0"
		}
		ip := net.ParseIP(addr)
		if ip == nil {
			return site, fmt.Errorf("监听地址无效：%s（填 0.0.0.0 表示全部网卡）", addr)
		}
		// 统一 IPv6 写法，避免「::」与「0:0:0:0:0:0:0:0」被当成两个不同站点配置
		site.Addr = ip.String()
		if site.Port < 1 || site.Port > 65535 {
			return site, fmt.Errorf("端口范围应为 1-65535")
		}
		site.PathPrefix = ""
	case "path":
		// 路径模式挂在统一 HTTP 端口下，路径必须是 / 开头的非根前缀；
		// 分享站点的对外路径固定由 slug 生成（/s/{slug}），保证同域名下不重复。
		if site.Type == WebTypeShare {
			slug := strings.Trim(strings.TrimSpace(site.Share.Slug), "/")
			if slug == "" {
				slug = "share"
			}
			site.PathPrefix = "/s/" + slug
		} else {
			p := "/" + strings.Trim(strings.TrimSpace(site.PathPrefix), "/")
			if p == "/" {
				return site, fmt.Errorf("路径模式必须填写非根路径，例如 /docs")
			}
			if strings.ContainsAny(p, " ?#") || strings.Contains(p, "//") {
				return site, fmt.Errorf("路径前缀不能包含空格、?、# 或连续斜杠")
			}
			site.PathPrefix = p
		}
		site.Addr = "0.0.0.0"
		site.Port = 0
	default:
		return site, fmt.Errorf("访问方式无效：%s", site.AccessMode)
	}

	// 旧版字段迁移：auth_user/auth_pass → security
	if strings.TrimSpace(site.Security.AuthMode) == "" && strings.TrimSpace(site.AuthUser) != "" {
		if site.AuthPass == "" {
			return site, fmt.Errorf("启用基础认证时密码不能为空")
		}
		site.Security.AuthMode = "basic"
		site.Security.Users = strings.TrimSpace(site.AuthUser) + ":" + site.AuthPass
		site.AuthUser, site.AuthPass = "", ""
	}
	site.AuthUser, site.AuthPass = "", ""

	// 各类型的专属校验
	switch site.Type {
	case WebTypeStatic, WebTypeShare:
		if site.Type == WebTypeShare {
			if strings.TrimSpace(site.Share.Slug) == "" {
				site.Share.Slug = "share"
			}
			site.Share.Slug = strings.Trim(strings.TrimSpace(site.Share.Slug), "/")
			if site.Share.Slug == "" {
				site.Share.Slug = "share"
			}
			if strings.ContainsAny(site.Share.Slug, " ?#&/") {
				return site, fmt.Errorf("访问路径不能包含空格、?、#、& 或斜杠")
			}
			// 副标题只保留一行小字，超长直接截断。
			site.Share.Subtitle = strings.TrimSpace(site.Share.Subtitle)
			if r := []rune(site.Share.Subtitle); len(r) > 64 {
				site.Share.Subtitle = string(r[:64])
			}
			// 禁止下载时打包下载没有意义。
			// 允许「禁止下载 + 禁止预览」：此时 /raw 全部关闭，访客只能看到文件列表，
			// 这是唯一能真正阻止可预览格式被抓取的服务端组合。
			if site.Share.DisableDownload {
				site.Share.PackageDownload = false
			}
		}
		root, isDir, err := normalizeWebRoot(site.Root, site.Type == WebTypeShare)
		if err != nil {
			return site, err
		}
		site.Root = root
		if site.Type == WebTypeStatic && !isDir {
			return site, fmt.Errorf("静态站点目录必须是文件夹")
		}
		idx := strings.TrimSpace(site.Index)
		if idx == "" {
			idx = webSiteDefaultIdx
		}
		if idx == "." || idx == ".." || strings.ContainsAny(idx, `/\`) {
			return site, fmt.Errorf("首页文件只能是文件名，不能包含路径分隔符")
		}
		site.Index = idx
	case WebTypeText:
		site.TextContentType = strings.TrimSpace(site.TextContentType)
		if site.TextContentType == "" {
			site.TextContentType = "text/plain; charset=utf-8"
		}
		if site.TextStatus == 0 {
			site.TextStatus = http.StatusOK
		}
		if site.TextStatus < 100 || site.TextStatus > 599 {
			return site, fmt.Errorf("固定文本状态码范围应为 100-599")
		}
	case WebTypeRedirect:
		target := strings.TrimSpace(site.RedirectTo)
		u, err := url.Parse(target)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return site, fmt.Errorf("重定向目标必须是完整的 http/https 地址")
		}
		site.RedirectTo = target
		if site.RedirectCode == 0 {
			site.RedirectCode = http.StatusFound
		}
		switch site.RedirectCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		default:
			return site, fmt.Errorf("重定向状态码只能是 301 / 302 / 307 / 308")
		}
	case WebTypeProxy:
		proxy, err := normalizeWebProxy(site.Proxy)
		if err != nil {
			return site, err
		}
		site.Proxy = proxy
	}

	sec, err := normalizeWebSecurity(site.Security)
	if err != nil {
		return site, err
	}
	site.Security = sec

	shares, err := normalizeWebTempShares(site.TempShares)
	if err != nil {
		return site, err
	}
	site.TempShares = shares

	site.ReqHeaders, err = normalizeHeaderLines(site.ReqHeaders)
	if err != nil {
		return site, fmt.Errorf("请求头配置无效：%v", err)
	}
	site.RespHeaders, err = normalizeHeaderLines(site.RespHeaders)
	if err != nil {
		return site, fmt.Errorf("响应头配置无效：%v", err)
	}
	site.ConfigVersion = 1
	return site, nil
}

// normalizeWebRoot 校验根路径；allowFile 为真时允许指向单个文件（文件分享）。
func normalizeWebRoot(raw string, allowFile bool) (string, bool, error) {
	root := strings.TrimSpace(raw)
	if root == "" {
		return "", false, fmt.Errorf("站点目录不能为空")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", false, fmt.Errorf("站点目录无效：%v", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", false, fmt.Errorf("站点目录不存在：%s", abs)
	}
	if st.IsDir() {
		return filepath.Clean(abs), true, nil
	}
	if !allowFile {
		return "", false, fmt.Errorf("站点目录不是文件夹：%s", abs)
	}
	return filepath.Clean(abs), false, nil
}

// normalizeWebProxy 校验反代配置。
func normalizeWebProxy(p WebProxyConfig) (WebProxyConfig, error) {
	if len(p.Backends) == 0 {
		return p, fmt.Errorf("反向代理至少需要一个后端")
	}
	out := make([]WebProxyBackend, 0, len(p.Backends))
	for i, b := range p.Backends {
		raw := strings.TrimSpace(b.URL)
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return p, fmt.Errorf("第 %d 个后端地址无效，应为 http(s)://host:port", i+1)
		}
		weight := b.Weight
		if weight == 0 {
			weight = 1
		}
		if weight < 1 || weight > 100 {
			return p, fmt.Errorf("第 %d 个后端权重应为 1-100", i+1)
		}
		out = append(out, WebProxyBackend{URL: strings.TrimRight(raw, "/"), Weight: weight, Backup: b.Backup})
	}
	p.Backends = out

	p.LBPolicy = strings.ToLower(strings.TrimSpace(p.LBPolicy))
	if p.LBPolicy == "" {
		p.LBPolicy = "round_robin"
	}
	switch p.LBPolicy {
	case "round_robin", "random", "ip_hash", "least_conn":
	default:
		return p, fmt.Errorf("负载均衡策略无效：%s", p.LBPolicy)
	}

	hc := p.HealthCheck
	hc.Mode = strings.ToLower(strings.TrimSpace(hc.Mode))
	if hc.Mode == "" {
		hc.Mode = "http"
	}
	if hc.Mode != "http" && hc.Mode != "tcp" {
		return p, fmt.Errorf("健康检查模式只能是 http 或 tcp")
	}
	if hc.Path == "" {
		hc.Path = "/"
	}
	if !strings.HasPrefix(hc.Path, "/") {
		return p, fmt.Errorf("健康检查路径必须以 / 开头")
	}
	if hc.Interval <= 0 {
		hc.Interval = 10
	}
	if hc.Timeout <= 0 {
		hc.Timeout = 3
	}
	if hc.Fails <= 0 {
		hc.Fails = 3
	}
	if hc.Passes <= 0 {
		hc.Passes = 2
	}
	if hc.Interval > 3600 || hc.Timeout > 60 || hc.Fails > 20 || hc.Passes > 20 {
		return p, fmt.Errorf("健康检查参数超出范围")
	}
	p.HealthCheck = hc

	if p.RateLimit < 0 || p.Burst < 0 || p.MaxConns < 0 {
		return p, fmt.Errorf("限流参数不能为负数")
	}
	if p.RateLimit > 0 && p.Burst == 0 {
		p.Burst = p.RateLimit + 1
	}
	if p.CacheTTL < 0 || p.CacheTTL > 30*86400 {
		return p, fmt.Errorf("缓存 TTL 范围应为 0-30 天")
	}
	if p.CacheMaxMB == 0 {
		p.CacheMaxMB = 64
	}
	if p.CacheMaxMB < 1 || p.CacheMaxMB > 4096 {
		return p, fmt.Errorf("缓存容量范围应为 1-4096 MB")
	}

	rules := make([]WebPathRule, 0, len(p.PathRules))
	for i, r := range p.PathRules {
		pattern := strings.TrimSpace(r.Pattern)
		to := strings.TrimSpace(r.To)
		if pattern == "" || to == "" {
			return p, fmt.Errorf("第 %d 条路径规则的匹配与替换不能为空", i+1)
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return p, fmt.Errorf("第 %d 条路径规则正则无效：%v", i+1, err)
		}
		if r.Redirect {
			if r.Code == 0 {
				r.Code = http.StatusFound
			}
			switch r.Code {
			case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			default:
				return p, fmt.Errorf("第 %d 条路径规则重定向码无效", i+1)
			}
		} else if !strings.HasPrefix(to, "/") {
			return p, fmt.Errorf("第 %d 条内部重写目标必须以 / 开头", i+1)
		}
		rules = append(rules, WebPathRule{Pattern: pattern, To: to, Redirect: r.Redirect, Code: r.Code})
	}
	p.PathRules = rules
	return p, nil
}

// normalizeWebSecurity 校验认证与访问控制配置。
func normalizeWebSecurity(sec WebSecurityConfig) (WebSecurityConfig, error) {
	sec.AuthMode = strings.ToLower(strings.TrimSpace(sec.AuthMode))
	if sec.AuthMode == "" {
		sec.AuthMode = "none"
	}
	switch sec.AuthMode {
	case "none", "basic", "web":
	default:
		return sec, fmt.Errorf("认证方式无效：%s", sec.AuthMode)
	}
	sec.Users = strings.TrimSpace(sec.Users)
	if sec.AuthMode != "none" && sec.Users == "" {
		return sec, fmt.Errorf("开启认证时至少需要配置一个用户")
	}
	if sec.Users != "" {
		for i, line := range strings.Split(sec.Users, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if !strings.Contains(line, ":") {
				return sec, fmt.Errorf("第 %d 行用户格式应为 username:password", i+1)
			}
			user, pass, _ := strings.Cut(line, ":")
			if strings.TrimSpace(user) == "" || pass == "" {
				return sec, fmt.Errorf("第 %d 行用户名和密码不能为空", i+1)
			}
		}
	}

	sec.IPMode = strings.ToLower(strings.TrimSpace(sec.IPMode))
	if sec.IPMode == "" {
		sec.IPMode = "off"
	}
	switch sec.IPMode {
	case "off", "allow", "deny":
	default:
		return sec, fmt.Errorf("IP 访问控制模式无效：%s", sec.IPMode)
	}
	sec.IPList = strings.TrimSpace(sec.IPList)
	if sec.IPMode != "off" {
		if sec.IPList == "" {
			return sec, fmt.Errorf("开启 IP 访问控制时 IP 列表不能为空")
		}
		if err := validateIPLines(sec.IPList); err != nil {
			return sec, err
		}
	}
	sec.IPAllow = strings.TrimSpace(sec.IPAllow)
	if sec.IPAllow != "" {
		if err := validateIPLines(sec.IPAllow); err != nil {
			return sec, fmt.Errorf("放行名单格式错误：%v", err)
		}
	}
	sec.TrustedProxies = strings.TrimSpace(sec.TrustedProxies)
	if sec.TrustedProxies != "" {
		if err := validateIPLines(sec.TrustedProxies); err != nil {
			return sec, fmt.Errorf("可信反代格式错误：%v", err)
		}
	}

	paths := make([]WebSecurityPathRule, 0, len(sec.PathRules))
	seen := map[string]bool{}
	for i, r := range sec.PathRules {
		prefix := strings.TrimSpace(r.Prefix)
		if prefix == "" || !strings.HasPrefix(prefix, "/") {
			return sec, fmt.Errorf("第 %d 条路径规则前缀必须以 / 开头", i+1)
		}
		if seen[prefix] {
			return sec, fmt.Errorf("路径规则前缀重复：%s", prefix)
		}
		seen[prefix] = true
		am := strings.ToLower(strings.TrimSpace(r.AuthMode))
		if am == "inherit" {
			am = ""
		}
		switch am {
		case "", "off", "on":
		default:
			return sec, fmt.Errorf("路径 %s 的认证覆盖只能是继承 / off / on", prefix)
		}
		im := strings.ToLower(strings.TrimSpace(r.IPMode))
		if im == "inherit" {
			im = ""
		}
		switch im {
		case "", "off", "allow", "deny":
		default:
			return sec, fmt.Errorf("路径 %s 的 IP 模式无效", prefix)
		}
		if im == "allow" || im == "deny" {
			if strings.TrimSpace(r.IPList) == "" {
				return sec, fmt.Errorf("路径 %s 的 IP 列表不能为空", prefix)
			}
			if err := validateIPLines(r.IPList); err != nil {
				return sec, err
			}
		}
		paths = append(paths, WebSecurityPathRule{Prefix: prefix, AuthMode: am, IPMode: im, IPList: strings.TrimSpace(r.IPList)})
	}
	sec.PathRules = paths

	if sec.FailLimit <= 0 {
		sec.FailLimit = 10
	}
	if sec.FailWindow <= 0 {
		sec.FailWindow = 15
	}
	if sec.AutoBanMinutes < 0 || sec.AutoBanMinutes > 43200 {
		return sec, fmt.Errorf("自动封禁时长范围应为 0-43200 分钟")
	}

	sec.GeoMode = strings.ToLower(strings.TrimSpace(sec.GeoMode))
	if sec.GeoMode == "" {
		sec.GeoMode = "off"
	}
	switch sec.GeoMode {
	case "off", "allow", "deny":
	default:
		return sec, fmt.Errorf("国家过滤模式无效：%s", sec.GeoMode)
	}
	sec.GeoCountries = strings.ToUpper(strings.TrimSpace(sec.GeoCountries))
	if sec.GeoMode != "off" {
		if sec.GeoCountries == "" {
			return sec, fmt.Errorf("开启国家过滤时国家代码不能为空")
		}
		parts := strings.Split(sec.GeoCountries, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if len(p) != 2 {
				return sec, fmt.Errorf("国家代码无效：%s", p)
			}
			out = append(out, p)
		}
		sec.GeoCountries = strings.Join(out, ",")
	}
	return sec, nil
}

// validateIPLines 校验每行 IP / CIDR。
func validateIPLines(raw string) error {
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if ipToNet(line) == nil {
			return fmt.Errorf("第 %d 行 IP / 网段无效：%s", i+1, line)
		}
	}
	return nil
}

// normalizeWebTempShares 校验并补齐临时分享链接。
func normalizeWebTempShares(list []WebTempShare) ([]WebTempShare, error) {
	out := make([]WebTempShare, 0, len(list))
	seen := map[string]bool{}
	for i, t := range list {
		t.Name = strings.TrimSpace(t.Name)
		if t.Name == "" {
			t.Name = fmt.Sprintf("临时链接 %d", i+1)
		}
		if t.ID == "" || seen[t.ID] {
			id, err := newWebSiteID()
			if err != nil {
				return nil, err
			}
			t.ID = id
		}
		seen[t.ID] = true
		if t.Token == "" {
			tok, err := newWebSiteID()
			if err != nil {
				return nil, err
			}
			t.Token = tok
		}
		if t.CreatedAt == "" {
			t.CreatedAt = time.Now().Format("2006-01-02 15:04:05")
		}
		if strings.TrimSpace(t.ExpiresAt) != "" {
			if _, err := parseWebTime(t.ExpiresAt); err != nil {
				return nil, fmt.Errorf("「%s」的到期时间无效，应为 2006-01-02 15:04:05", t.Name)
			}
		}
		if t.MaxUses < 0 || t.Used < 0 {
			return nil, fmt.Errorf("「%s」的使用次数不能为负数", t.Name)
		}
		t.PathPrefix = strings.TrimSpace(t.PathPrefix)
		if t.PathPrefix != "" && !strings.HasPrefix(t.PathPrefix, "/") {
			return nil, fmt.Errorf("「%s」的路径前缀必须以 / 开头", t.Name)
		}
		out = append(out, t)
	}
	return out, nil
}

// normalizeHeaderLines 规范化每行一个 Key: Value 的头部配置；空 Value 表示删除该头。
func normalizeHeaderLines(raw string) (string, error) {
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return "", fmt.Errorf("第 %d 行应为 Key: Value", i+1)
		}
		out = append(out, key+": "+strings.TrimSpace(value))
	}
	return strings.Join(out, "\n"), nil
}

// parseWebTime 解析前端传入的时间（RFC3339 或本地时间格式）。
func parseWebTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, raw, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("时间格式无效")
}

// wsLoad 从 settings KV 加载站点配置（启动时调用一次），并把旧版静态站点迁移到新结构。
func (s *Server) wsLoad() {
	var list []WebSite
	if raw, err := s.store.GetSetting(webSitesKey); err == nil && strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &list)
	}
	for i := range list {
		site := &list[i]
		if site.Type == "" {
			site.Type = WebTypeStatic
		}
		if site.ID == "" {
			if id, err := newWebSiteID(); err == nil {
				site.ID = id
			}
		}
		if site.Security.AuthMode == "" && site.AuthUser != "" && site.AuthPass != "" {
			site.Security.AuthMode = "basic"
			site.Security.Users = site.AuthUser + ":" + site.AuthPass
			site.AuthUser, site.AuthPass = "", ""
		}
		if site.ConfigVersion == 0 {
			// 旧版站点默认记录访问日志，保持升级前行为
			site.AccessLog = true
			site.ConfigVersion = 1
		}
	}
	s.wsMu.Lock()
	s.wsSites = list
	s.wsMu.Unlock()
}

// wsRestore 启动设置了「开机自启」的站点。
func (s *Server) wsRestore() {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	for _, site := range s.wsSites {
		if !site.AutoStart {
			continue
		}
		if err := s.wsStartLocked(site); err != nil {
			s.wsErrs[site.ID] = err.Error()
			s.logger.Warn("Web 服务自启失败",
				zap.String("id", site.ID), zap.String("name", site.Name), zap.Error(err))
			continue
		}
		s.logger.Info("Web 服务已自动启动",
			zap.String("id", site.ID), zap.String("name", site.Name),
			zap.String("addr", net.JoinHostPort(site.Addr, strconv.Itoa(site.Port))))
	}
	// 路径模式：只要配置了路径站点（即使全部停止）也保持统一端口监听，根路径返回 503 页面
	for _, site := range s.wsSites {
		if site.AccessMode == "path" {
			if err := s.wsEnsurePathServerLocked(); err != nil {
				s.logger.Warn("Web 服务路径模式统一端口启动失败", zap.Error(err))
			}
			break
		}
	}
}

// wsStopAll 停止全部站点（进程退出时调用；自启意图不改，重启后按 AutoStart 恢复）。
func (s *Server) wsStopAll() {
	s.wsMu.Lock()
	runs := make([]*webSiteRun, 0, len(s.wsRuns))
	for _, run := range s.wsRuns {
		runs = append(runs, run)
	}
	s.wsRuns = map[string]*webSiteRun{}
	s.wsMu.Unlock()
	for _, run := range runs {
		if run.cancel != nil {
			run.cancel()
		}
		_ = run.srv.Close()
	}
}

// wsPersistLocked 把站点列表写回 settings KV（调用方需持有 wsMu）。
func (s *Server) wsPersistLocked() error {
	return s.store.SetJSON(webSitesKey, s.wsSites)
}

func (s *Server) wsSiteByIDLocked(id string) (WebSite, bool) {
	for _, site := range s.wsSites {
		if site.ID == id {
			return site, true
		}
	}
	return WebSite{}, false
}

// wsStartLocked 启动单个站点（调用方需持有 wsMu）。
func (s *Server) wsStartLocked(site WebSite) error {
	if _, ok := s.wsRuns[site.ID]; ok {
		return nil
	}
	if site.Type == WebTypeStatic || site.Type == WebTypeShare {
		if _, err := os.Stat(site.Root); err != nil {
			return fmt.Errorf("站点目录不可用：%v", err)
		}
	}
	if site.AccessMode == "path" {
		// 路径模式：不单独监听端口，由统一 HTTP 监听按路径前缀分发
		ctx, cancel := context.WithCancel(context.Background())
		run := &webSiteRun{
			id:        site.ID,
			startedAt: time.Now(),
			logs:      make([]webSiteAccess, 0, 32),
			ctx:       ctx,
			cancel:    cancel,
			pathMode:  true,
		}
		run.handler = s.newWebSiteHandler(site, run)
		s.wsRuns[site.ID] = run
		if err := s.wsEnsurePathServerLocked(); err != nil {
			delete(s.wsRuns, site.ID)
			cancel()
			return err
		}
		return nil
	}
	// 端口模式：统一路径端口已被占用时禁止再监听同一端口
	if s.wsPathSrv != nil && site.Port == s.wsPathPort {
		return fmt.Errorf("端口 %d 已被路径模式统一监听占用", site.Port)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(site.Addr, strconv.Itoa(site.Port)))
	if err != nil {
		return fmt.Errorf("端口 %d 监听失败：%v", site.Port, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &webSiteRun{
		id:        site.ID,
		ln:        ln,
		startedAt: time.Now(),
		logs:      make([]webSiteAccess, 0, 32),
		ctx:       ctx,
		cancel:    cancel,
	}
	run.handler = s.newWebSiteHandler(site, run)
	srv := &http.Server{
		Handler:           run.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	run.srv = srv
	s.wsRuns[site.ID] = run

	go func() {
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			run.setErr(err.Error())
			s.logger.Warn("Web 服务异常退出",
				zap.String("id", site.ID), zap.String("name", site.Name), zap.Error(err))
		}
		s.wsMu.Lock()
		if s.wsRuns[site.ID] == run {
			delete(s.wsRuns, site.ID)
		}
		s.wsMu.Unlock()
	}()
	return nil
}

// wsUnifiedHTTPPort 返回路径模式统一使用的 HTTP 端口。
func (s *Server) wsUnifiedHTTPPort() int {
	p := s.cfg.Forward.HTTPDefaultPort
	if p < 1 || p > 65535 {
		p = 18080
	}
	return p
}

// wsEnsurePathServerLocked 根据是否存在路径模式站点启动或关闭统一 HTTP 监听。
// 站点即使已停止也保持监听：此时根路径与站点前缀都返回 503，而不是连接拒绝。
func (s *Server) wsEnsurePathServerLocked() error {
	hasPath := false
	for _, site := range s.wsSites {
		if site.AccessMode == "path" && site.PathPrefix != "" {
			hasPath = true
			break
		}
	}
	if !hasPath {
		s.wsClosePathServerLocked()
		return nil
	}
	port := s.wsUnifiedHTTPPort()
	if s.wsPathSrv != nil && s.wsPathPort == port {
		return nil
	}
	s.wsClosePathServerLocked()
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return fmt.Errorf("路径模式统一端口 %d 监听失败：%v", port, err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(s.wsPathHandler),
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.wsPathSrv = srv
	s.wsPathLn = ln
	s.wsPathPort = port
	go func() {
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			s.logger.Warn("Web 服务路径模式监听异常退出", zap.Int("port", port), zap.Error(err))
		}
		s.wsMu.Lock()
		if s.wsPathSrv == srv {
			s.wsPathSrv = nil
			s.wsPathLn = nil
			s.wsPathPort = 0
		}
		s.wsMu.Unlock()
	}()
	return nil
}

// wsClosePathServerLocked 关闭统一 HTTP 监听（调用方需持有 wsMu）。
func (s *Server) wsClosePathServerLocked() {
	if s.wsPathSrv != nil {
		_ = s.wsPathSrv.Close()
	}
	s.wsPathSrv = nil
	s.wsPathLn = nil
	s.wsPathPort = 0
}

// wsPathHandler 按最长路径前缀把请求分发给对应的路径模式站点。
// 根路径不归属任何站点；无匹配站点或站点已停止时返回自定义 503 页面（主页面禁止端口访问）。
func (s *Server) wsPathHandler(w http.ResponseWriter, r *http.Request) {
	s.wsMu.Lock()
	var matched WebSite
	var run *webSiteRun
	for i := range s.wsSites {
		site := s.wsSites[i]
		if site.AccessMode != "path" || site.PathPrefix == "" {
			continue
		}
		cr, ok := s.wsRuns[site.ID]
		if !ok || !cr.pathMode {
			continue
		}
		if r.URL.Path == site.PathPrefix || strings.HasPrefix(r.URL.Path, site.PathPrefix+"/") {
			if run == nil || len(site.PathPrefix) > len(matched.PathPrefix) {
				matched = site
				run = cr
			}
		}
	}
	s.wsMu.Unlock()
	if run == nil {
		errpage.Write(w, r, http.StatusServiceUnavailable, "服务暂不可用")
		return
	}
	rp := r.Clone(r.Context())
	rp.URL.Path = strings.TrimPrefix(r.URL.Path, matched.PathPrefix)
	if rp.URL.Path == "" {
		rp.URL.Path = "/"
	}
	rp.URL.RawPath = ""
	run.handler.ServeHTTP(&wsPrefixWriter{ResponseWriter: w, prefix: matched.PathPrefix}, rp)
}

// wsPrefixWriter 为路径模式站点补回重定向中的路径前缀：
// 静态文件服务与分享页会返回以 / 开头的 Location，若不补前缀会跳到统一端口根路径。
type wsPrefixWriter struct {
	http.ResponseWriter
	prefix string
}

func (w *wsPrefixWriter) WriteHeader(code int) {
	if loc := w.Header().Get("Location"); strings.HasPrefix(loc, "/") &&
		loc != w.prefix && !strings.HasPrefix(loc, w.prefix+"/") {
		w.Header().Set("Location", w.prefix+loc)
	}
	w.ResponseWriter.WriteHeader(code)
}

// wsStopLocked 停止单个站点（调用方需持有 wsMu）。
func (s *Server) wsStopLocked(id string) {
	run, ok := s.wsRuns[id]
	if !ok {
		return
	}
	delete(s.wsRuns, id)
	if run.cancel != nil {
		run.cancel()
	}
	if run.srv != nil {
		_ = run.srv.Close()
	}
	// 路径模式没有独立监听：站点全部停止后关闭统一 HTTP 监听
	if run.pathMode {
		_ = s.wsEnsurePathServerLocked()
	}
}

// wsViewLocked 组装站点视图（调用方需持有 wsMu）。
func (s *Server) wsViewLocked(site WebSite) webSiteView {
	v := webSiteView{WebSite: site}
	if run, ok := s.wsRuns[site.ID]; ok {
		v.Running = true
		v.StartedAt = run.startedAt.Format("2006-01-02 15:04:05")
		v.Requests = run.requests.Load()
		v.Bytes = run.bytes.Load()
		v.Error = run.errText()
		if run.proxy != nil {
			v.ProxyStatus = run.proxy.status()
		}
		if run.share != nil {
			v.ShareStats = run.share.view()
		}
	} else if msg := s.wsErrs[site.ID]; msg != "" {
		v.Error = msg
	}
	return v
}

// wsClientIP 取访问者 IP。
// 只有 TCP 直连对端属于可信反代（本机回环或 trustedProxies 列表）时，
// 才采信 X-Real-IP / X-Forwarded-For；否则一律使用直连地址，
// 避免客户端伪造反代头绕过封禁、限流与查看凭证绑定。
func wsClientIP(r *http.Request, trustedProxies string) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peer = host
	}
	if !wsTrustedProxyPeer(peer, trustedProxies) {
		return peer
	}
	if v := wsValidIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i > 0 {
			v = v[:i]
		}
		if v := wsValidIP(strings.TrimSpace(v)); v != "" {
			return v
		}
	}
	return peer
}

// wsTrustedProxyPeer 判断直连对端是否为可信反代；本机回环始终可信（frpc / 本机 Nginx）。
func wsTrustedProxyPeer(peer, trustedProxies string) bool {
	ip := net.ParseIP(peer)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	return wsIPInList(peer, trustedProxies)
}

// wsValidIP 归一化反代头中的地址，非法值直接丢弃。
func wsValidIP(s string) string {
	if s == "" {
		return ""
	}
	if ip := net.ParseIP(strings.Trim(s, "[]")); ip != nil {
		return ip.String()
	}
	return ""
}

// wsAuthOK 常量时间比较用户名与密码，避免按响应时间逐字符探测。
func wsAuthOK(user, pass, wantUser, wantPass string) bool {
	u := subtle.ConstantTimeCompare([]byte(user), []byte(wantUser)) == 1
	p := subtle.ConstantTimeCompare([]byte(pass), []byte(wantPass)) == 1
	return u && p
}

// wsResponseWriter 记录状态码与响应字节数，供访问日志使用。
type wsResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
	kind   string
}

// wsMarkCrawler 给当前请求打上爬虫标记，访问日志会带上 kind=crawler。
func wsMarkCrawler(w http.ResponseWriter) {
	if rec, ok := w.(*wsResponseWriter); ok {
		rec.kind = "crawler"
	}
}

func (w *wsResponseWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *wsResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// Flush 透传 http.Flusher，保证 SSE / 流式响应可用。
func (w *wsResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack 透传 http.Hijacker，保证 WebSocket 升级可用。
func (w *wsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("底层连接不支持 Hijack")
}

// newWebSiteHandler 按站点类型构造处理器，并在最外层包裹访问日志、在业务层包裹认证与访问控制。
func (s *Server) newWebSiteHandler(site WebSite, run *webSiteRun) http.Handler {
	var base http.Handler
	switch site.Type {
	case WebTypeText:
		base = s.newTextHandler(site)
	case WebTypeRedirect:
		base = s.newRedirectHandler(site)
	case WebTypeProxy:
		base = s.newProxyHandler(site, run)
	case WebTypeShare:
		base = s.newShareHandler(site, run)
	default:
		base = s.newStaticHandler(site)
	}
	base = s.wrapWebSecurity(site, run, base)
	if site.CORS {
		base = s.wrapWebCORS(base)
	}
	if site.Type != WebTypeProxy {
		base = s.wrapWebRespHeaders(site.RespHeaders, base)
	}
	if site.AccessLog {
		base = s.wrapWebAccessLog(site, run, base)
	}
	return base
}

// wrapWebCORS 为所有站点类型统一添加 CORS 头并处理预检请求。
func (s *Server) wrapWebCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// wrapWebRespHeaders 为非反代站点统一应用自定义响应头。
func (s *Server) wrapWebRespHeaders(raw string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applyHeaderLines(w.Header(), raw)
		next.ServeHTTP(w, r)
	})
}

// newTextHandler 固定文本站点。
func (s *Server) newTextHandler(site WebSite) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := site.TextContentType
		if ct == "" {
			ct = "text/plain; charset=utf-8"
		}
		status := site.TextStatus
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Length", strconv.Itoa(len(site.Text)))
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(site.Text))
		}
	})
}

// newRedirectHandler 重定向站点：可选保留原始路径与查询串。
func (s *Server) newRedirectHandler(site WebSite) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := site.RedirectTo
		if site.RedirectKeepPath {
			target = strings.TrimRight(target, "/") + "/" + strings.TrimLeft(r.URL.Path, "/")
		}
		if site.RedirectKeepQuery && r.URL.RawQuery != "" {
			if strings.Contains(target, "?") {
				target += "&" + r.URL.RawQuery
			} else {
				target += "?" + r.URL.RawQuery
			}
		}
		code := site.RedirectCode
		if code == 0 {
			code = http.StatusFound
		}
		http.Redirect(w, r, target, code)
	})
}

// newStaticHandler 静态文件处理器（不含认证 / 日志，由外层统一包裹）。
func (s *Server) newStaticHandler(site WebSite) http.Handler {
	fileServer := http.FileServer(http.Dir(site.Root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 目录请求：优先返回配置的首页文件；没有首页且未开启目录浏览时返回 404。
		clean := path.Clean("/" + r.URL.Path)
		full := filepath.Join(site.Root, filepath.FromSlash(clean))
		if st, err := os.Stat(full); err == nil && st.IsDir() {
			// 与 http.FileServer 行为一致：目录路径补斜杠，否则相对路径资源会解析错误
			if !strings.HasSuffix(r.URL.Path, "/") {
				target := r.URL.Path + "/"
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}
			if fi, err := os.Stat(filepath.Join(full, site.Index)); err == nil && !fi.IsDir() {
				// 保持目录路径（以 / 结尾），用 ServeFile 显式提供首页文件：
				// 若把 URL.Path 改写成 /index.html，http.FileServer 会把它 301 回 ./，
				// 又与「目录 → 首页」重写叠加成无限重定向。
				r2 := r.Clone(r.Context())
				http.ServeFile(w, r2, filepath.Join(full, site.Index))
				return
			}
			if !site.Browse {
				http.Error(w, "目录浏览已关闭", http.StatusNotFound)
				return
			}
		}
		fileServer.ServeHTTP(w, r)
	})
}

// wrapWebAccessLog 记录请求数、响应字节与最近访问日志。
func (s *Server) wrapWebAccessLog(site WebSite, run *webSiteRun, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &wsResponseWriter{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		run.requests.Add(1)
		run.bytes.Add(rec.bytes)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		pathText := r.URL.RequestURI()
		if len(pathText) > 512 {
			pathText = pathText[:512]
		}
		run.addLog(webSiteAccess{
			Time:   start.Format("2006-01-02 15:04:05"),
			IP:     wsClientIP(r, site.Security.TrustedProxies),
			Method: r.Method,
			Path:   pathText,
			Status: rec.status,
			Bytes:  rec.bytes,
			MS:     time.Since(start).Milliseconds(),
			Kind:   rec.kind,
		})
	})
}

// ============= API =============

// handleWebSitesGet 返回全部站点（含运行状态与实时统计）。
func (s *Server) handleWebSitesGet(w http.ResponseWriter, r *http.Request) {
	s.wsMu.Lock()
	views := make([]webSiteView, 0, len(s.wsSites))
	for _, site := range s.wsSites {
		views = append(views, s.wsViewLocked(site))
	}
	s.wsMu.Unlock()
	accessMode := strings.ToLower(strings.TrimSpace(s.cfg.Forward.WebAccessMode))
	if accessMode != "domain" {
		accessMode = "ip"
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"sites":         views,
		"http_port":     s.wsUnifiedHTTPPort(),
		"access_mode":   accessMode,
		"access_domain": strings.TrimSpace(s.cfg.Forward.WebAccessDomain),
		"access_ip":     strings.TrimSpace(s.cfg.Forward.WebAccessIP),
		"local_ips":     wsLocalIPv4List(),
	}))
}

// wsLocalIPv4List 返回本机可用作监听出口的 IPv4 地址，主用地址排在最前。
func wsLocalIPv4List() []string {
	seen := make(map[string]bool)
	out := make([]string, 0, 4)
	add := func(ip string) {
		if ip == "" || seen[ip] {
			return
		}
		seen[ip] = true
		out = append(out, ip)
	}
	add(primaryLocalIPv4())
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipNet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip4 := ipNet.IP.To4()
				if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsMulticast() {
					continue
				}
				add(ip4.String())
			}
		}
	}
	return out
}

// handleWebSiteSave 新建或更新站点：保存成功后自动启动（新建）或按原运行状态重启（编辑）。
func (s *Server) handleWebSiteSave(w http.ResponseWriter, r *http.Request) {
	var req WebSite
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	site, err := normalizeWebSite(req)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}

	isNew := strings.TrimSpace(site.ID) == ""
	var wasRunning bool
	if isNew {
		id, err := newWebSiteID()
		if err != nil {
			s.writeJSON(w, http.StatusInternalServerError, apiErr("生成站点标识失败："+err.Error()))
			return
		}
		site.ID = id
	}

	s.wsMu.Lock()
	// 路径模式：路径前缀必须唯一，且统一端口不能被端口模式站点占用
	if site.AccessMode == "path" {
		for _, other := range s.wsSites {
			if other.ID == site.ID {
				continue
			}
			if other.AccessMode == "path" && other.PathPrefix == site.PathPrefix {
				s.wsMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr("路径前缀已被其他站点使用："+site.PathPrefix))
				return
			}
		}
		if s.wsPathSrv == nil {
			for _, other := range s.wsSites {
				if other.ID != site.ID && other.AccessMode != "path" && other.Port == s.wsUnifiedHTTPPort() {
					s.wsMu.Unlock()
					s.writeJSON(w, http.StatusBadRequest, apiErr(fmt.Sprintf("统一端口 %d 已被端口模式站点「%s」占用", other.Port, other.Name)))
					return
				}
			}
		}
	} else {
		if s.wsPathSrv != nil && site.Port == s.wsPathPort {
			s.wsMu.Unlock()
			s.writeJSON(w, http.StatusBadRequest, apiErr(fmt.Sprintf("端口 %d 已被路径模式统一监听占用", site.Port)))
			return
		}
		// 端口模式：同一监听地址上端口不能重复；0.0.0.0 与任何地址都冲突。
		for _, other := range s.wsSites {
			if other.ID == site.ID || other.AccessMode == "path" || other.Port != site.Port {
				continue
			}
			if other.Addr == site.Addr || other.Addr == "0.0.0.0" || site.Addr == "0.0.0.0" {
				s.wsMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr(fmt.Sprintf("端口 %d 已被站点「%s」占用", site.Port, other.Name)))
				return
			}
		}
		// 端口被系统或其他程序占用时尽早拒绝；编辑运行中的站点且端口不变时，
		// 端口仍被它自己的监听占着，跳过预检。
		selfRunningPort := 0
		if s.wsRuns[site.ID] != nil {
			for _, other := range s.wsSites {
				if other.ID == site.ID {
					selfRunningPort = other.Port
					break
				}
			}
		}
		if selfRunningPort != site.Port {
			ln, err := net.Listen("tcp", net.JoinHostPort(site.Addr, strconv.Itoa(site.Port)))
			if err != nil {
				s.wsMu.Unlock()
				s.writeJSON(w, http.StatusBadRequest, apiErr(fmt.Sprintf("端口 %d 无法监听，可能已被系统或其他程序占用", site.Port)))
				return
			}
			_ = ln.Close()
		}
	}
	var oldSite WebSite
	idx := -1
	if isNew {
		s.wsSites = append(s.wsSites, site)
	} else {
		for i := range s.wsSites {
			if s.wsSites[i].ID == site.ID {
				idx = i
				break
			}
		}
		if idx < 0 {
			s.wsMu.Unlock()
			s.writeJSON(w, http.StatusNotFound, apiErr("站点不存在"))
			return
		}
		wasRunning = s.wsRuns[site.ID] != nil
		oldSite = s.wsSites[idx]
		s.wsSites[idx] = site
		if wasRunning {
			s.wsStopLocked(site.ID)
		}
	}
	if err := s.wsPersistLocked(); err != nil {
		// 落库失败时回滚内存状态，避免「界面显示已改、重启后丢失」
		if isNew {
			s.wsSites = s.wsSites[:len(s.wsSites)-1]
		} else {
			s.wsSites[idx] = oldSite
			if wasRunning {
				_ = s.wsStartLocked(oldSite)
			}
		}
		s.wsMu.Unlock()
		s.writeJSON(w, http.StatusInternalServerError, apiErr("保存站点失败："+err.Error()))
		return
	}
	delete(s.wsErrs, site.ID)
	// 路径模式统一端口随「是否存在路径站点」开合，保存后立即按最新配置调整
	if err := s.wsEnsurePathServerLocked(); err != nil {
		s.logger.Warn("Web 服务路径模式统一端口调整失败", zap.String("id", site.ID), zap.Error(err))
	}
	s.wsMu.Unlock()

	// 新建站点直接启动；编辑时只有原本在运行的站点才重启，避免「改一个字段把服务拉起来」。
	if isNew || wasRunning {
		if err := s.wsStart(site.ID); err != nil {
			s.logger.Warn("Web 服务启动失败", zap.String("id", site.ID), zap.String("name", site.Name), zap.Error(err))
		}
	}

	s.wsMu.Lock()
	view := s.wsViewLocked(site)
	s.wsMu.Unlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"site": view}))
}

// handleWebSiteStart 启动指定站点。
func (s *Server) handleWebSiteStart(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.wsStart(id); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(s.wsViewByID(id)))
}

// handleWebSiteStop 停止指定站点。
func (s *Server) handleWebSiteStop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.wsMu.Lock()
	site, ok := s.wsSiteByIDLocked(id)
	if !ok {
		s.wsMu.Unlock()
		s.writeJSON(w, http.StatusNotFound, apiErr("站点不存在"))
		return
	}
	s.wsStopLocked(id)
	delete(s.wsErrs, id)
	view := s.wsViewLocked(site)
	s.wsMu.Unlock()
	s.writeJSON(w, http.StatusOK, apiOK(view))
}

// handleWebSiteDelete 停止并删除站点（只删配置，不触碰站点目录内的文件）。
func (s *Server) handleWebSiteDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.wsMu.Lock()
	idx := -1
	for i := range s.wsSites {
		if s.wsSites[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.wsMu.Unlock()
		s.writeJSON(w, http.StatusNotFound, apiErr("站点不存在"))
		return
	}
	s.wsStopLocked(id)
	s.wsSites = append(s.wsSites[:idx], s.wsSites[idx+1:]...)
	delete(s.wsErrs, id)
	// 删除最后一个路径站点后关闭统一端口监听
	if err := s.wsEnsurePathServerLocked(); err != nil {
		s.logger.Warn("Web 服务路径模式统一端口调整失败", zap.String("id", id), zap.Error(err))
	}
	if err := s.wsPersistLocked(); err != nil {
		s.wsMu.Unlock()
		s.writeJSON(w, http.StatusInternalServerError, apiErr("删除站点失败："+err.Error()))
		return
	}
	s.wsMu.Unlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"id": id}))
}

// handleWebSiteLogs 返回站点最近访问日志（按时间正序，前端可反转展示）。
func (s *Server) handleWebSiteLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.wsMu.Lock()
	run := s.wsRuns[id]
	_, exists := s.wsSiteByIDLocked(id)
	s.wsMu.Unlock()
	if !exists {
		s.writeJSON(w, http.StatusNotFound, apiErr("站点不存在"))
		return
	}
	if run == nil {
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"logs": []webSiteAccess{}}))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"logs":     run.siteLogs(),
		"requests": run.requests.Load(),
		"bytes":    run.bytes.Load(),
	}))
}

// handleWebSiteLogsClear 清空站点访问日志（请求数/流量累计不受影响）。
func (s *Server) handleWebSiteLogsClear(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.wsMu.Lock()
	run := s.wsRuns[id]
	_, exists := s.wsSiteByIDLocked(id)
	s.wsMu.Unlock()
	if !exists {
		s.writeJSON(w, http.StatusNotFound, apiErr("站点不存在"))
		return
	}
	if run != nil {
		run.mu.Lock()
		run.logs = nil
		run.mu.Unlock()
	}
	s.writeJSON(w, http.StatusOK, apiOK(nil))
}

// wsBrowseEntry 目录浏览条目。
type wsBrowseEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
}

// handleWebSiteBrowse 浏览服务器目录，供站点目录选择使用。
func (s *Server) handleWebSiteBrowse(w http.ResponseWriter, r *http.Request) {
	dir := strings.TrimSpace(r.URL.Query().Get("path"))
	if dir == "" {
		dir = string(filepath.Separator)
	}
	if !filepath.IsAbs(dir) {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请使用绝对路径"))
		return
	}
	dir = filepath.Clean(dir)
	st, err := os.Stat(dir)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("目录不可访问："+err.Error()))
		return
	}
	if !st.IsDir() {
		s.writeJSON(w, http.StatusBadRequest, apiErr("不是文件夹："+dir))
		return
	}
	items, err := os.ReadDir(dir)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("读取目录失败："+err.Error()))
		return
	}
	entries := make([]wsBrowseEntry, 0, len(items))
	for _, it := range items {
		entries = append(entries, wsBrowseEntry{
			Name:  it.Name(),
			Path:  filepath.Join(dir, it.Name()),
			IsDir: it.IsDir(),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	if len(entries) > 1000 {
		entries = entries[:1000]
	}
	parent := ""
	if dir != string(filepath.Separator) {
		parent = filepath.Dir(dir)
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"path":    dir,
		"parent":  parent,
		"entries": entries,
	}))
}

// handleWebShareStats 返回文件分享统计（下载数 / 流量 / 按文件 / 近 7 天 / 最近记录）。
func (s *Server) handleWebShareStats(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.wsMu.Lock()
	site, ok := s.wsSiteByIDLocked(id)
	run := s.wsRuns[id]
	s.wsMu.Unlock()
	if !ok {
		s.writeJSON(w, http.StatusNotFound, apiErr("站点不存在"))
		return
	}
	if site.Type != WebTypeShare || run == nil || run.share == nil {
		s.writeJSON(w, http.StatusOK, apiOK(&webShareView{Files: map[string]*webShareStat{}, Daily: map[string]int64{}, Recent: []webShareEvent{}}))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(run.share.view()))
}

// handleWebTempShareCreate 新建临时分享链接。
func (s *Server) handleWebTempShareCreate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req WebTempShare
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	list, err := normalizeWebTempShares([]WebTempShare{req})
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	link := list[0]
	s.wsMu.Lock()
	_, ok := s.wsSiteByIDLocked(id)
	if !ok {
		s.wsMu.Unlock()
		s.writeJSON(w, http.StatusNotFound, apiErr("站点不存在"))
		return
	}
	for i := range s.wsSites {
		if s.wsSites[i].ID != id {
			continue
		}
		s.wsSites[i].TempShares = append(s.wsSites[i].TempShares, link)
		break
	}
	if err := s.wsPersistLocked(); err != nil {
		// 回滚本次追加，避免内存与落库不一致
		for i := range s.wsSites {
			if s.wsSites[i].ID == id && len(s.wsSites[i].TempShares) > 0 {
				s.wsSites[i].TempShares = s.wsSites[i].TempShares[:len(s.wsSites[i].TempShares)-1]
				break
			}
		}
		s.wsMu.Unlock()
		s.writeJSON(w, http.StatusInternalServerError, apiErr("保存临时链接失败："+err.Error()))
		return
	}
	s.wsMu.Unlock()
	// 处理器在启动时持有站点配置快照；新增链接后重启站点使其立即生效
	s.wsRestartIfRunning(id)
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"share": link}))
}

// handleWebTempShareDelete 删除临时分享链接。
func (s *Server) handleWebTempShareDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	shareID := r.PathValue("shareID")
	s.wsMu.Lock()
	found := false
	for i := range s.wsSites {
		if s.wsSites[i].ID != id {
			continue
		}
		for j := range s.wsSites[i].TempShares {
			if s.wsSites[i].TempShares[j].ID == shareID {
				s.wsSites[i].TempShares = append(s.wsSites[i].TempShares[:j], s.wsSites[i].TempShares[j+1:]...)
				found = true
				break
			}
		}
		break
	}
	if !found {
		s.wsMu.Unlock()
		s.writeJSON(w, http.StatusNotFound, apiErr("临时链接不存在"))
		return
	}
	if err := s.wsPersistLocked(); err != nil {
		s.wsMu.Unlock()
		s.writeJSON(w, http.StatusInternalServerError, apiErr("删除临时链接失败："+err.Error()))
		return
	}
	s.wsMu.Unlock()
	// 处理器在启动时持有站点配置快照；删除链接后重启站点使其立即失效
	s.wsRestartIfRunning(id)
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"id": shareID}))
}

// wsRestartIfRunning 若站点正在运行则重启，使新的认证 / 临时链接配置立即生效。
func (s *Server) wsRestartIfRunning(id string) {
	s.wsMu.Lock()
	wasRunning := s.wsRuns[id] != nil
	if wasRunning {
		s.wsStopLocked(id)
	}
	s.wsMu.Unlock()
	if !wasRunning {
		return
	}
	if err := s.wsStart(id); err != nil {
		s.logger.Warn("Web 服务重启失败", zap.String("id", id), zap.Error(err))
	}
}

// handleWebBansGet 返回站点当前的封禁列表。
func (s *Server) handleWebBansGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.wsMu.Lock()
	run := s.wsRuns[id]
	_, ok := s.wsSiteByIDLocked(id)
	s.wsMu.Unlock()
	if !ok {
		s.writeJSON(w, http.StatusNotFound, apiErr("站点不存在"))
		return
	}
	bans := []map[string]interface{}{}
	if run != nil {
		bans = run.wsBanSnapshot()
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"bans": bans}))
}

// handleWebBanDelete 解除指定 IP 的封禁。
func (s *Server) handleWebBanDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少 IP"))
		return
	}
	s.wsMu.Lock()
	run := s.wsRuns[id]
	_, ok := s.wsSiteByIDLocked(id)
	s.wsMu.Unlock()
	if !ok {
		s.writeJSON(w, http.StatusNotFound, apiErr("站点不存在"))
		return
	}
	if run != nil {
		run.wsUnban(ip)
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"ip": ip}))
}

// wsStart 启动站点并记录最近一次启动错误（启动失败时界面可看到原因）。
func (s *Server) wsStart(id string) error {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	site, ok := s.wsSiteByIDLocked(id)
	if !ok {
		return fmt.Errorf("站点不存在")
	}
	if err := s.wsStartLocked(site); err != nil {
		s.wsErrs[id] = err.Error()
		return err
	}
	delete(s.wsErrs, id)
	return nil
}

// wsViewByID 返回单个站点视图（不存在时返回空视图）。
func (s *Server) wsViewByID(id string) webSiteView {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	if site, ok := s.wsSiteByIDLocked(id); ok {
		return s.wsViewLocked(site)
	}
	return webSiteView{}
}

// newWebSiteID 生成站点标识（16 位十六进制随机串）。
func newWebSiteID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
