package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Log             LogConfig             `mapstructure:"log"`
	Forward         ForwardConfig         `mapstructure:"forward"`
	Tunnel          TunnelConfig          `mapstructure:"tunnel"`
	Webhook         WebhookConfig         `mapstructure:"webhook"`
	WebhookReceiver WebhookReceiverConfig `mapstructure:"wh_receiver"`
	WebhookTemplate WebhookTemplateConfig `mapstructure:"wh_template"` // Webhook 模板（请求方法/请求头/请求体/成功字符）
	IPFilter        IPFilterConfig        `mapstructure:"ip_filter"`
	MEFRP           MEFRPConfig           `mapstructure:"mefrp"`      // MEFrp 云端隧道集成（访问密钥）
	Lolia           LoliaConfig           `mapstructure:"lolia"`      // LoliaFrp 云端隧道集成（访问密钥）
	Cloudflare      CloudflareConfig      `mapstructure:"cloudflare"` // Cloudflare Tunnel 接入（隧道 Token 托管）
	Modules         ModulesConfig         `mapstructure:"modules"`    // 模块管理（关闭指定功能模块的入口）
	Dashboard       DashboardConfig       `mapstructure:"dashboard"`  // 仪表盘布局（卡片顺序与显隐）
	Hook            HookConfig            `mapstructure:"hook"`       // 导航页（/hook）
}

// DashboardConfig 仪表盘布局：KPI 概览与卡片各自的顺序与显隐。
// 项目清单由前端定义（卡片内容在前端 markup 中），此处只保存顺序与显隐状态；
// 前端在加载时把「已保存布局」与「当前已知项」合并，新增项自动追加并默认可见，
// 因此新增卡片无需迁移既有配置。空配置即「全部可见、默认顺序」。
type DashboardConfig struct {
	KPIs  []DashboardItem `mapstructure:"kpis"`  // KPI 概览项（顺序即展示顺序）
	Cards []DashboardItem `mapstructure:"cards"` // 卡片项（顺序即展示顺序）
}

// DashboardItem 仪表盘布局中的一项。
// HiddenFields 记录该项内部被隐藏的行 id（例如某张卡片里的「系统时间」一行），为空表示全部显示。
// FieldOrder 记录该项内部各行的显示顺序；未列出的行按默认顺序追加在后，为空表示默认顺序。
// 与模块管理同理，用「已隐藏列表」而非「已显示列表」：新增字段默认显示，无需迁移既有配置。
type DashboardItem struct {
	ID           string   `mapstructure:"id" json:"id"`
	Visible      bool     `mapstructure:"visible" json:"visible"`
	HiddenFields []string `mapstructure:"hiddenFields" json:"hiddenFields,omitempty"`
	FieldOrder   []string `mapstructure:"fieldOrder" json:"fieldOrder,omitempty"`
}

// ModulesConfig 模块管理配置。
// 用「已关闭列表」而非「已启用列表」：新增模块时默认即为启用，无需迁移既有配置。
// 仪表盘与系统设置（含模块管理本身）为常驻模块，不在可关闭范围内。
type ModulesConfig struct {
	Disabled []string `mapstructure:"disabled"` // 已关闭的模块 id（见 web 层 allowDisableModules）
}

// Cloudflare Tunnel 托管方式。
const (
	// CloudflareModeToken 手动 Token 托管：隧道与路由在 Cloudflare 后台维护，本程序只运行连接器。
	CloudflareModeToken = "token"
	// CloudflareModeAPI API 全托管：隧道、Public Hostname 路由与 DNS 记录均由本程序通过 API 维护。
	CloudflareModeAPI = "api"
	// CloudflareModeQuick 临时入口：匿名 quick tunnel，免账号免 Token，
	// 由 cloudflared 自行向 trycloudflare.com 注册并随机下发一个临时域名（每次启动都变）。
	CloudflareModeQuick = "quick"
)

// CloudflareConfig Cloudflare Tunnel 接入配置。
// 以「实例」为基本单位：一条实例 = 一份凭证 + 一个 cloudflared 进程 + 一张路由表，
// 多条实例可同时运行（各自独立启停、独立日志、独立本地回源与连接协议）。
type CloudflareConfig struct {
	Instances []CloudflareInstance `mapstructure:"instances"`

	// ---- 以下为旧版单实例字段，仅用于首次迁移（MigrateLegacy 之后不再使用） ----
	Mode        string            `mapstructure:"mode"`
	Token       string            `mapstructure:"token"`
	Protocol    string            `mapstructure:"protocol"`
	AutoStart   bool              `mapstructure:"auto_start"`
	QuickTarget string            `mapstructure:"quick_target"`
	LocalScheme string            `mapstructure:"local_scheme"`
	LocalAddr   string            `mapstructure:"local_addr"`
	LocalPort   int               `mapstructure:"local_port"`
	DNSAccount  string            `mapstructure:"dns_account"`
	AccountID   string            `mapstructure:"account_id"`
	ZoneID      string            `mapstructure:"zone_id"`
	ZoneName    string            `mapstructure:"zone_name"`
	TunnelID    string            `mapstructure:"tunnel_id"`
	TunnelName  string            `mapstructure:"tunnel_name"`
	TunnelToken string            `mapstructure:"tunnel_token"`
	Routes      []CloudflareRoute `mapstructure:"routes"`
}

// CloudflareInstance 一条隧道实例。
// ID 是本程序生成的稳定标识（进程目录、日志、接口寻址都用它），与 Cloudflare 的隧道 ID 无关。
//
// 标签约定：json 标签必须与 mapstructure 标签一致（同为 snake_case）。
// 配置持久化是「json 序列化写库 → 启动时 viper.Unmarshal（走 mapstructure）读回」，
// 两套标签写法不同就会写进去读不出来（camelCase 的 localAddr 匹配不上 local_addr），
// 表现为重启后实例的本地回源地址与凭证全部丢失。
// 另外 json 标签必须可完整往返：任何 json:"-" 都会让该字段在重启后静默消失。
// 对外接口不直接序列化本结构体，而是由 cfInstanceView 逐字段构造并脱敏。
type CloudflareInstance struct {
	ID   string `mapstructure:"id" json:"id"`
	Name string `mapstructure:"name" json:"name"` // 展示名；api 模式下同时作为隧道名
	Mode string `mapstructure:"mode" json:"mode"` // token（默认）| api | quick

	// token 模式：用户粘贴的隧道 Token
	Token string `mapstructure:"token" json:"token"`

	// api 模式（凭证复用「域名解析」模块的 Cloudflare 账号，不另存 API Token）
	DNSAccount  string `mapstructure:"dns_account" json:"dns_account"`
	AccountID   string `mapstructure:"account_id" json:"account_id"`
	ZoneID      string `mapstructure:"zone_id" json:"zone_id"`
	ZoneName    string `mapstructure:"zone_name" json:"zone_name"`
	TunnelID    string `mapstructure:"tunnel_id" json:"tunnel_id"`
	TunnelToken string `mapstructure:"tunnel_token" json:"tunnel_token"` // API 创建隧道时取得，运行时使用

	// 本地回源：本实例要发布的本机服务（如 127.0.0.1:5666）。
	// 每条实例各有一套：多隧道的典型用法就是多个本地服务各自一个域名。
	LocalScheme string `mapstructure:"local_scheme" json:"local_scheme"`
	LocalAddr   string `mapstructure:"local_addr" json:"local_addr"`
	LocalPort   int    `mapstructure:"local_port" json:"local_port"`
	// QuickTarget 仅用于兼容早期配置（完整 URL，如 http://127.0.0.1:5666），新配置用上面的 Local* 字段。
	QuickTarget string `mapstructure:"quick_target" json:"quick_target"`

	Protocol  string `mapstructure:"protocol" json:"protocol"`     // 连接协议：http2（默认）| quic | auto
	AutoStart bool   `mapstructure:"auto_start" json:"auto_start"` // 随应用启动自启
	// Paused 运行中暂停：隧道连接与访问地址都保持不动，只把回源闸门切到 503 页面。
	// 仅临时入口（quick）有意义——它的域名每次启动都会变；域名固定的隧道直接停止即可。
	Paused bool              `mapstructure:"paused" json:"paused"`
	Routes []CloudflareRoute `mapstructure:"routes" json:"routes"` // 本实例的 Public Hostname 路由表
}

// CloudflareRoute 一条 Public Hostname 路由（ingress 规则）。
type CloudflareRoute struct {
	Hostname string `mapstructure:"hostname" json:"hostname"`
	Service  string `mapstructure:"service" json:"service"`
	Path     string `mapstructure:"path,omitempty" json:"path,omitempty"`
}

// NewInstanceID 生成实例 ID：8 位十六进制随机串（用于进程目录名与接口寻址，不做安全用途）。
func NewInstanceID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// 随机源不可用时退化为时间戳，保证 ID 仍然唯一可用
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

// MigrateLegacy 把旧版单实例配置迁移成一条实例（幂等：已有实例时不做任何事）。
// 返回是否发生了迁移，供调用方决定是否落盘。
func (c *CloudflareConfig) MigrateLegacy() bool {
	if len(c.Instances) > 0 || !c.hasLegacy() {
		return false
	}
	name := strings.TrimSpace(c.TunnelName)
	if name == "" {
		name = "默认隧道"
	}
	c.Instances = []CloudflareInstance{{
		ID:          NewInstanceID(),
		Name:        name,
		Mode:        c.Mode,
		Token:       c.Token,
		DNSAccount:  c.DNSAccount,
		AccountID:   c.AccountID,
		ZoneID:      c.ZoneID,
		ZoneName:    c.ZoneName,
		TunnelID:    c.TunnelID,
		TunnelToken: c.TunnelToken,
		LocalScheme: c.LocalScheme,
		LocalAddr:   c.LocalAddr,
		LocalPort:   c.LocalPort,
		QuickTarget: c.QuickTarget,
		Protocol:    c.Protocol,
		AutoStart:   c.AutoStart,
		Routes:      c.Routes,
	}}
	c.clearLegacy()
	return true
}

// hasLegacy 旧字段是否被填过（用于判断要不要迁移）。
// 注意 mode 有默认值 token：只有「非默认的 mode」才算用户配过，
// 否则全新安装也会凭默认值迁移出一条空实例。
func (c CloudflareConfig) hasLegacy() bool {
	return c.Token != "" || c.TunnelID != "" || c.DNSAccount != "" ||
		c.LocalAddr != "" || c.LocalPort > 0 || c.QuickTarget != "" || len(c.Routes) > 0 ||
		(c.Mode != "" && c.Mode != CloudflareModeToken)
}

// clearLegacy 清空旧字段（迁移后避免与新结构重复）。
func (c *CloudflareConfig) clearLegacy() {
	c.Mode, c.Token, c.Protocol, c.AutoStart = "", "", "", false
	c.QuickTarget, c.LocalScheme, c.LocalAddr, c.LocalPort = "", "", "", 0
	c.DNSAccount, c.AccountID, c.ZoneID, c.ZoneName = "", "", "", ""
	c.TunnelID, c.TunnelName, c.TunnelToken = "", "", ""
	c.Routes = nil
}

// Index 按 ID 查找实例下标（不存在返回 -1）。
func (c CloudflareConfig) Index(id string) int {
	for i := range c.Instances {
		if c.Instances[i].ID == id {
			return i
		}
	}
	return -1
}

// NormalizeMode 归一化托管方式，非白名单值回落 token 模式。
func (c CloudflareInstance) NormalizeMode() string {
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case CloudflareModeAPI:
		return CloudflareModeAPI
	case CloudflareModeQuick:
		return CloudflareModeQuick
	default:
		return CloudflareModeToken
	}
}

// RuntimeToken 本实例运行时使用的隧道 Token（api 模式用 API 取得的 Token；quick 模式无 Token）。
func (c CloudflareInstance) RuntimeToken() string {
	if c.NormalizeMode() == CloudflareModeAPI {
		return strings.TrimSpace(c.TunnelToken)
	}
	return strings.TrimSpace(c.Token)
}

// LocalOrigin 本实例的本地服务协议、地址与端口。
// 取 LocalScheme + LocalAddr + LocalPort；旧配置只存了 quick_target 时从其 URL 中解析回填。
// 协议缺省 http、地址缺省 127.0.0.1；端口为 0 表示未配置。
func (c CloudflareInstance) LocalOrigin() (scheme, addr string, port int) {
	scheme = strings.ToLower(strings.TrimSpace(c.LocalScheme))
	addr = strings.TrimSpace(c.LocalAddr)
	port = c.LocalPort
	if port <= 0 {
		if ls, la, lp, ok := ParseLocalTarget(c.QuickTarget); ok {
			if scheme == "" {
				scheme = ls
			}
			if addr == "" {
				addr = la
			}
			port = lp
		}
	}
	if scheme != "https" {
		scheme = "http"
	}
	if addr == "" {
		addr = "127.0.0.1"
	}
	if port <= 0 {
		return scheme, addr, 0
	}
	return scheme, addr, port
}

// LocalURL 本实例的完整回源地址（如 http://127.0.0.1:5666）；未配置端口时返回空。
func (c CloudflareInstance) LocalURL() string {
	scheme, addr, port := c.LocalOrigin()
	if port <= 0 {
		return ""
	}
	return scheme + "://" + net.JoinHostPort(addr, strconv.Itoa(port))
}

// RuntimeTarget 临时入口（quick）实际生效的本地目标地址（cloudflared 的 origin URL）。
func (c CloudflareInstance) RuntimeTarget() string {
	return c.LocalURL()
}

// Ready 本实例是否具备启动条件：quick 看本地目标地址，其余看隧道 Token。
func (c CloudflareInstance) Ready() bool {
	if c.NormalizeMode() == CloudflareModeQuick {
		return c.RuntimeTarget() != ""
	}
	return c.RuntimeToken() != ""
}

// ProtocolOrDefault 本实例的连接协议（留空取全局默认值）。
func (c CloudflareInstance) ProtocolOrDefault(def string) string {
	if p := strings.TrimSpace(c.Protocol); p != "" {
		return p
	}
	return def
}

// DisplayName 展示名（未命名时按模式给个兜底名）。
func (c CloudflareInstance) DisplayName() string {
	if n := strings.TrimSpace(c.Name); n != "" {
		return n
	}
	if c.NormalizeMode() == CloudflareModeQuick {
		return "临时入口"
	}
	if c.NormalizeMode() == CloudflareModeAPI {
		return "API 隧道"
	}
	return "Token 托管隧道"
}

// ParseLocalTarget 从历史 quick_target（完整 URL，如 http://127.0.0.1:5666）解析出协议、地址与端口。
func ParseLocalTarget(target string) (scheme, addr string, port int, ok bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", 0, false
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", "", 0, false
	}
	host, portStr := u.Hostname(), u.Port()
	if host == "" || portStr == "" {
		return "", "", 0, false
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return "", "", 0, false
	}
	return strings.ToLower(u.Scheme), host, p, true
}

// MEFRPConfig ME Frp 幻缘映射接入配置。
type MEFRPConfig struct {
	Token        string  `mapstructure:"token"`         // 账户访问密钥（官网获取，Bearer 鉴权用）
	AutostartIDs []int64 `mapstructure:"autostart_ids"` // 开机自启的隧道 ID 列表（最近一次启动的隧道，停止时清空）
}

// LoliaConfig LoliaFrp（lolia.link）接入配置。
// 采用 OAuth2 授权码模式：用户在 LoliaFrp 面板自建 OAuth 应用并把 Webhook 端口回调地址
// （http(s)://IP或域名[:端口]/api/lolia）填入应用回调白名单；授权完成后服务端保存 access_token。
// 隧道启动不需要 OAuth 凭据：使用隧道详情里的 tunnel_token（节点 TOKEN）调免鉴权配置接口。
type LoliaConfig struct {
	// OAuth 应用凭据（用户在 https://dash.lolia.link 创建应用获得）
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	// RedirectBase 回调外部基址（可选覆盖，如 http://1.2.3.4:19520）；
	// 留空时自动按 Webhook 接收器的 IP/域名模式推导。
	RedirectBase string `mapstructure:"redirect_base"`

	// OAuth 授权结果
	AccessToken  string `mapstructure:"access_token"` // Bearer access_token（调用 /user/* 接口）
	RefreshToken string `mapstructure:"refresh_token"`
	TokenExpire  int64  `mapstructure:"token_expire"` // access_token 过期时间（Unix 秒，0=未知）

	AutostartNames []string `mapstructure:"autostart_names"` // 开机自启的隧道 name 列表（手动停止时清空）
}

// RegionRule IP 地址库中的地区规则（白/黑名单按 IP 归属地匹配）。
type RegionRule struct {
	Category string `json:"category"` // country/china/province/city/isp/cloud…
	Name     string `json:"name"`     // 归属名称（美国 / 广东 / 广州 / 中国内地 …）
}

type IPFilterConfig struct {
	Enabled          bool         `mapstructure:"enabled"`
	Mode             string       `mapstructure:"mode"`              // 过滤模式：blacklist（默认，黑名单模式，拦截名单内地址）| whitelist（白名单模式，仅放行名单内地址）
	AllowLAN         bool         `mapstructure:"allow_lan"`         // 放行局域网（内网）地址（默认开，关闭后内网设备将无法访问）
	AutoRecord       bool         `mapstructure:"auto_record"`       // 自动记录被拦截的 IP（默认关闭）
	WhitelistRegions []RegionRule `mapstructure:"whitelist_regions"` // 白名单地区（按归属地匹配）
	BlacklistRegions []RegionRule `mapstructure:"blacklist_regions"` // 黑名单地区（按归属地匹配）
}

// SearchEngineConfig 导航页搜索引擎项（回车搜索使用）
type SearchEngineConfig struct {
	ID    string `mapstructure:"id" json:"id"`
	Title string `mapstructure:"title" json:"title"`
	URL   string `mapstructure:"url" json:"url"`
	Icon  string `mapstructure:"icon" json:"icon"` // 图标链接（可选）
}

// HookConfig 导航页（/hook）配置：集中展示已注册通道的公开导航页。
type HookConfig struct {
	Enabled       bool                 `mapstructure:"enabled"`        // 导航页开关（关闭后 /hook 返回 404）
	Title         string               `mapstructure:"title"`          // 页面标题（默认 通道导航）
	SearchEngine  string               `mapstructure:"search_engine"`  // 默认搜索引擎 id（bing/google/bilibili/douyin）
	SearchEngines []SearchEngineConfig `mapstructure:"search_engines"` // 搜索引擎列表（可编辑）
	ShowSearch    bool                 `mapstructure:"show_search"`    // 显示搜索栏（默认开）
	Icon          string               `mapstructure:"icon"`           // 导航页图标文件名（icons/ 目录，空=未设置）
	ShowWebhook   bool                 `mapstructure:"show_webhook"`   // 显示 Webhook 通道列表（默认开）
	ShowForwards  bool                 `mapstructure:"show_forwards"`  // 显示转发列表（默认开）
	ShowProxies   bool                 `mapstructure:"show_proxies"`   // 显示代理列表（默认开）
	AdminPass     string               `mapstructure:"admin_pass"`     // 导航页管理密码（登录入口与设置接口校验，默认 TunHook）
	// ---- 自定义 UI（时钟 / 壁纸 / 页脚 / 内容布局 / 统计条） ----
	ClockEnabled    bool   `mapstructure:"clock_enabled"`     // 显示时钟（默认开）
	ClockFormat     string `mapstructure:"clock_format"`      // 时间格式：24h | 24h-ns | 12h
	WallSource      string `mapstructure:"wall_source"`       // 壁纸来源：api | url | upload
	WallAPI         string `mapstructure:"wall_api"`          // 壁纸 API 地址
	WallURL         string `mapstructure:"wall_url"`          // 壁纸图片链接
	WallUpload      string `mapstructure:"wall_upload"`       // 本地上传壁纸（dataURL）
	WallBlur        int    `mapstructure:"wall_blur"`         // 壁纸模糊程度（像素）
	WallMask        bool   `mapstructure:"wall_mask"`         // 壁纸遮罩层（默认开）
	WallMaskOpacity int    `mapstructure:"wall_mask_opacity"` // 遮罩透明度（0-100）
	FooterText      string `mapstructure:"footer_text"`       // 自定义页脚文字（空=默认）
	ContentMaxWidth int    `mapstructure:"content_max_width"` // 内容区域最大宽度（vw，默认 90）
	SideMargin      int    `mapstructure:"side_margin"`       // 两侧边距（px）
	TopMargin       int    `mapstructure:"top_margin"`        // 顶部边距（vh）
	BottomMargin    int    `mapstructure:"bottom_margin"`     // 底部边距（vh）
	ShowStats       bool   `mapstructure:"show_stats"`        // 显示统计条（默认开）
}

type LogConfig struct {
	Level                  string `mapstructure:"level"`
	Format                 string `mapstructure:"format"`
	File                   string `mapstructure:"file"`
	MaxEntries             int    `mapstructure:"max_entries"`
	TunnelMaxEntries       int    `mapstructure:"tunnel_max_entries"`        // 每条通道独立运行日志的最大条数
	TunnelAccessMaxEntries int    `mapstructure:"tunnel_access_max_entries"` // 每条通道独立访问日志的最大条数
	ExpireDays             int    `mapstructure:"expire_days"`
	TrafficRetentionDays   int    `mapstructure:"traffic_retention_days"` // 仪表盘流量统计数据保存天数（默认 31）
}

type ForwardConfig struct {
	Rules            []ForwardRule `mapstructure:"rules"`
	HTTPDefaultPort  int           `mapstructure:"http_default_port"`  // HTTP 协议默认监听端口
	HTTPSDefaultPort int           `mapstructure:"https_default_port"` // HTTPS 协议默认监听端口
	// Web 服务路径模式对外展示的访问方式：ip=统一端口 + 本机 IP；domain=域名（按 443 展示）
	WebAccessMode   string `mapstructure:"web_access_mode"`
	WebAccessDomain string `mapstructure:"web_access_domain"`
	WebAccessIP     string `mapstructure:"web_access_ip"`
}

type ForwardRule struct {
	Protocol     string `mapstructure:"protocol"`
	LocalAddr    string `mapstructure:"local_addr"`
	LocalPort    int    `mapstructure:"local_port"`
	RemoteAddr   string `mapstructure:"remote_addr"`
	RemotePort   int    `mapstructure:"remote_port"`
	Domain       string `mapstructure:"domain,omitempty"`        // HTTP 域名，用于 Host 路由
	Name         string `mapstructure:"name,omitempty"`          // 统一网关子路径名称（/proxy/{name}）
	SourcePrefix string `mapstructure:"source_prefix,omitempty"` // 统一网关：后端应用的原始路径前缀（如 /app/canvasboard），响应内容中替换为代理前缀
	RootPrefixes string `mapstructure:"root_prefixes,omitempty"` // 统一网关：逗号分隔的根相对路径前缀（如 /sac,/locales），响应内容中拼上代理前缀
	PathPrefix   string `mapstructure:"path_prefix,omitempty"`   // 统一网关：后端路径前缀（请求转发到后端时拼接，如 /app/canvasboard）
	AutoDetect   bool   `mapstructure:"auto_detect,omitempty"`   // 统一网关：保存时自动探测远端路径前缀并应用
	CertPEM      string `mapstructure:"cert_pem,omitempty"`      // HTTPS 转发：PEM 证书内容（为空时自动生成自签名证书）
	KeyPEM       string `mapstructure:"key_pem,omitempty"`       // HTTPS 转发：PEM 私钥内容（为空时自动生成自签名证书）
	TLSEnable    bool   `mapstructure:"tls_enable,omitempty"`    // TCP 转发：开启 HTTPS（自签名证书，访问端 TLS）
	// TCP 进阶设置
	RateLimit      int  `mapstructure:"rate_limit,omitempty"`      // 访问限速（KB/s/每连接，0=不限速）
	MaxConnections int  `mapstructure:"max_connections,omitempty"` // TCP 单端口最大连接数（0=不限制）
	ProxyProtocol  bool `mapstructure:"proxy_protocol,omitempty"`  // 连接源站时发送 PROXY protocol v2 头
	TLSSource      bool `mapstructure:"tls_source,omitempty"`      // 源端 TLS：以 TLS 方式连接源站
	// UDP 进阶设置
	UDPSessionTimeout int `mapstructure:"udp_session_timeout,omitempty"` // UDP 会话超时（毫秒，默认 30000）
	UDPMaxSessions    int `mapstructure:"udp_max_sessions,omitempty"`    // UDP 单端口最大会话数（默认 32）
	UDPMaxBlockLen    int `mapstructure:"udp_max_block_len,omitempty"`   // UDP 最大块长度（默认 1500）
	// 日志设置（仅记录不低于该级别的日志；条数 0=跟随全局）
	LogLevel          string `mapstructure:"log_level,omitempty"`
	ChannelLogEntries int    `mapstructure:"channel_log_entries,omitempty"`
	AccessLogEntries  int    `mapstructure:"access_log_entries,omitempty"`
	// 日志存储时间（小时，0=跟随全局），前端以 天/小时 为单位录入
	LogRetentionHours int `mapstructure:"log_retention_hours,omitempty"`
	// 进阶设置（访问链接配置）
	CustomID       string `mapstructure:"custom_id,omitempty"`       // 自定义ID（仅字母/数字，不区分大小写）
	CustomDomain   string `mapstructure:"custom_domain,omitempty"`   // 自定义域名（保存成功后自动在内网穿透模块创建对应代理通道）
	LinkKey        string `mapstructure:"link_key,omitempty"`        // 链接密钥（自动生成/手动重置）
	AccessPassword string `mapstructure:"access_password,omitempty"` // 访问密码（留空则禁用访问密码保护）
}

type TunnelConfig struct {
	PortRange         string `mapstructure:"port_range"`
	CheckInterval     int    `mapstructure:"check_interval"`
	StartupDelay      int    `mapstructure:"startup_delay"`
	RetryInterval     int    `mapstructure:"retry_interval"`
	ValidityTimeout   int    `mapstructure:"validity_timeout"`
	HeartbeatInterval int    `mapstructure:"heartbeat_interval"`
}

type WebhookConfig struct {
	URL      string            `mapstructure:"url"`
	Method   string            `mapstructure:"method"`
	Callback string            `mapstructure:"callback"` // 默认回调字符（创建通道时预填，服务端返回的匹配字符串）
	Headers  map[string]string `mapstructure:"headers"`
}

// WebhookReceiverConfig Webhook 接收器（接收 STUN 客户端上报的公网地址，
// 并对外提供「访问地址 → 公网地址」的重定向/反向代理入口）。
type WebhookReceiverConfig struct {
	Enabled      bool   `mapstructure:"enabled"`       // 接收器总开关
	Secret       string `mapstructure:"secret"`        // 接收鉴权密钥（可选，客户端需携带 X-Webhook-Secret 或 body.secret）
	AddrMode     string `mapstructure:"addr_mode"`     // 地址模式: ip（使用系统地址）| domain（使用访问域名）
	ReceiveAddr  string `mapstructure:"receive_addr"`  // 接收地址（客户端上报用的地址，如 1.2.3.4 或 wh.example.com）
	ReceivePort  int    `mapstructure:"receive_port"`  // Webhook 端口（接收+访问共用，默认 19520；0/80/443 省略显示）
	AccessIP     string `mapstructure:"access_ip"`     // IP 模式下的访问 IP（留空自动使用解析到的本机 IP）
	AccessDomain string `mapstructure:"access_domain"` // 访问域名（domain 模式下使用）
	AccessPort   int    `mapstructure:"access_port"`   // 访问端口（与接收端口合并，保存时同步为同一值）
	Mode         string `mapstructure:"mode"`          // 访问方式: redirect（302 重定向）| proxy（反向代理）
	Callback     string `mapstructure:"callback"`      // 接收成功回写的字符（客户端按此判断同步成功）
}

// WebhookTemplateConfig Webhook 模板（系统设置 → 默认参数 → Webhook 模板）：
// 定义 Webhook 请求的默认请求方法、请求头、请求体模板与成功判断字符。
type WebhookTemplateConfig struct {
	Method        string            `mapstructure:"method"`         // 请求方法（GET/POST/PUT/DELETE 等，默认 POST）
	Headers       map[string]string `mapstructure:"headers"`        // 请求头键值对
	Body          string            `mapstructure:"body"`           // 请求体模板（JSON 等，多行）
	SuccessString string            `mapstructure:"success_string"` // 接口调用成功包含的字符串（验证接口响应）
}

func setDefaults() {
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.file", "")
	viper.SetDefault("log.max_entries", 128)
	viper.SetDefault("log.tunnel_max_entries", 128)
	viper.SetDefault("log.tunnel_access_max_entries", 128)
	viper.SetDefault("log.expire_days", 7)
	viper.SetDefault("log.traffic_retention_days", 31)

	viper.SetDefault("forward.rules", []ForwardRule{})
	viper.SetDefault("forward.http_default_port", 18080)
	viper.SetDefault("forward.https_default_port", 14430)
	viper.SetDefault("forward.web_access_mode", "ip")

	viper.SetDefault("tunnel.check_interval", 30)
	viper.SetDefault("tunnel.startup_delay", 3000)
	viper.SetDefault("tunnel.retry_interval", 3000)
	viper.SetDefault("tunnel.validity_timeout", 5000)
	viper.SetDefault("tunnel.heartbeat_interval", 30000)

	viper.SetDefault("webhook.url", "")
	viper.SetDefault("webhook.method", "POST")
	viper.SetDefault("webhook.callback", "")
	viper.SetDefault("webhook.headers", map[string]string{})

	viper.SetDefault("wh_receiver.enabled", false)
	viper.SetDefault("wh_receiver.secret", "")
	viper.SetDefault("wh_receiver.addr_mode", "ip")
	viper.SetDefault("wh_receiver.receive_addr", "")
	viper.SetDefault("wh_receiver.receive_port", 19520) // Webhook 端口（接收+访问共用）
	viper.SetDefault("wh_receiver.access_ip", "")
	viper.SetDefault("wh_receiver.access_domain", "")
	viper.SetDefault("wh_receiver.access_port", 19520) // 访问端口（与接收端口合并，同步为同一值）
	viper.SetDefault("wh_receiver.mode", "redirect")
	viper.SetDefault("wh_receiver.callback", "更新成功")

	viper.SetDefault("wh_template.method", "POST")
	viper.SetDefault("wh_template.headers", map[string]string{})
	// 默认请求体模板：channel_id=通道id / host=公网ip / password=链接密钥 / port=公网端口（变量由客户端按实际值替换）
	viper.SetDefault("wh_template.body", `{
  "channel_id": "{channel_id}",
  "host": "{ip}",
  "password": "{link_key}",
  "port": {port}
}`)
	viper.SetDefault("wh_template.success_string", "更新成功")

	viper.SetDefault("ip_filter.enabled", false)
	viper.SetDefault("ip_filter.mode", "blacklist")
	viper.SetDefault("ip_filter.allow_lan", true)
	viper.SetDefault("ip_filter.auto_record", false)
	viper.SetDefault("ip_filter.whitelist_regions", []RegionRule{})
	viper.SetDefault("ip_filter.blacklist_regions", []RegionRule{})

	viper.SetDefault("mefrp.token", "")
	viper.SetDefault("mefrp.autostart_ids", []int64{})

	viper.SetDefault("lolia.client_id", "")
	viper.SetDefault("lolia.client_secret", "")
	viper.SetDefault("lolia.redirect_base", "")
	viper.SetDefault("lolia.access_token", "")
	viper.SetDefault("lolia.refresh_token", "")
	viper.SetDefault("lolia.token_expire", 0)
	viper.SetDefault("lolia.autostart_names", []string{})

	viper.SetDefault("cloudflare.token", "")
	viper.SetDefault("cloudflare.protocol", "http2")
	viper.SetDefault("cloudflare.auto_start", false)
	viper.SetDefault("cloudflare.mode", CloudflareModeToken)
	viper.SetDefault("cloudflare.dns_account", "")
	viper.SetDefault("cloudflare.account_id", "")
	viper.SetDefault("cloudflare.zone_id", "")
	viper.SetDefault("cloudflare.zone_name", "")
	viper.SetDefault("cloudflare.tunnel_id", "")
	viper.SetDefault("cloudflare.tunnel_name", "")
	viper.SetDefault("cloudflare.tunnel_token", "")
	viper.SetDefault("cloudflare.routes", []CloudflareRoute{})

	viper.SetDefault("modules.disabled", []string{})

	viper.SetDefault("dashboard.kpis", []DashboardItem{})
	viper.SetDefault("dashboard.cards", []DashboardItem{})

	viper.SetDefault("hook.enabled", true)
	viper.SetDefault("hook.title", "通道导航")
	viper.SetDefault("hook.search_engine", "bing")
	viper.SetDefault("hook.show_search", true)
	viper.SetDefault("hook.icon", "")
	viper.SetDefault("hook.show_webhook", true)
	viper.SetDefault("hook.show_forwards", true)
	viper.SetDefault("hook.show_proxies", true)
	viper.SetDefault("hook.admin_pass", "TunHook")
	// 搜索引擎列表（可在导航页设置中编辑；图标使用本地 static/ 下的 SVG）
	viper.SetDefault("hook.search_engines", []SearchEngineConfig{
		{ID: "bing", Title: "必应", URL: "https://www.bing.com/search?q=", Icon: "/static/bing.svg"},
		{ID: "google", Title: "Google", URL: "https://www.google.com/search?q=", Icon: "/static/Google.svg"},
		{ID: "bilibili", Title: "BILIBILI", URL: "https://search.bilibili.com/all?keyword=", Icon: "/static/bilibili.svg"},
		{ID: "douyin", Title: "抖音", URL: "https://www.douyin.com/search/", Icon: "/static/douyin.svg"},
	})
	// 自定义 UI（时钟 / 壁纸 / 页脚 / 内容布局 / 统计条）
	viper.SetDefault("hook.clock_enabled", true)
	viper.SetDefault("hook.clock_format", "24h")
	viper.SetDefault("hook.wall_source", "api")
	viper.SetDefault("hook.wall_api", "https://api.bimg.cc/random?w=1920&h=1080&mkt=zh-CN")
	viper.SetDefault("hook.wall_url", "")
	viper.SetDefault("hook.wall_upload", "")
	viper.SetDefault("hook.wall_blur", 5)
	viper.SetDefault("hook.wall_mask", true)
	viper.SetDefault("hook.wall_mask_opacity", 20)
	viper.SetDefault("hook.footer_text", "")
	viper.SetDefault("hook.content_max_width", 90)
	viper.SetDefault("hook.side_margin", 24)
	viper.SetDefault("hook.top_margin", 16)
	viper.SetDefault("hook.bottom_margin", 0)
	viper.SetDefault("hook.show_stats", true)
}

func Load(configPath string) (*Config, error) {
	setDefaults()

	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.tunhook")
	}

	viper.SetEnvPrefix("TUNHOOK")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		// 配置文件的 Key 已迁移到数据库后文件会被删除，缺失时视为可接受（使用默认值 + DB 覆盖）
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok && !os.IsNotExist(err) {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &cfg, nil
}
