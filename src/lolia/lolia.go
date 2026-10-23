// Package lolia 实现 LoliaFrp（https://lolia.link）开放 API 的客户端。
// 鉴权采用 OAuth2 授权码模式（授权页在 dash.lolia.link，token 端点在 api.lolia.link）；
// 隧道启动配置走免 OAuth 的节点 TOKEN 接口（/tunnel/frpc/config），返回 Base64 编码的
// 标准 frp v1 TOML，多隧道由服务端按 id 逗号拼接一次合并返回（与官方 CLI 行为一致）。
//
// API 文档：https://api-docs.lolia.link/ ；OAuth 说明：https://docs.lolia.link/developers/oauth
package lolia

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// BaseURL LoliaFrp 开放 API 根地址。
	BaseURL = "https://api.lolia.link/api/v1"
	// authorizeURL OAuth2 授权页基础地址（浏览器跳转，用户登录并同意授权）；
	// 不导出：外部统一通过 AuthorizeURL() 函数拼接完整跳转参数
	authorizeURL = "https://dash.lolia.link/oauth/authorize"
	// TokenURL OAuth2 令牌端点（授权码换取 access_token）。
	TokenURL = BaseURL + "/oauth2/token"
	// OAuthScope 申请的权限：账户/隧道/流量/节点只读 + 隧道编辑/删除（tunnel:write）
	// + 域名白名单读/写（domain:read/domain:write）。
	OAuthScope = "user:read tunnel:read tunnel:write traffic:read node:read domain:read domain:write"
	// UserAgent 客户端标识（与 MEFrp 客户端保持同一套 UA 约定）。
	UserAgent = "TunHook/0.6.6.172 github.com/YUNXI-fi/TunHook"
	// pageSize 列表分页拉取时的每页条数（节点接口文档示例用 1000，隧道用较大值减少翻页）。
	pageSize = 100
)

// ErrEmptyConfig 服务端返回的 frpc 配置为空。
var ErrEmptyConfig = errors.New("LoliaFrp 返回的隧道配置为空")

// ErrAuthRejected 令牌端点**明确拒绝**授权（refresh_token 过期/被吊销、客户端认证失败）。
// 与之相对，网络中断、5xx、429 属于可重试的临时失败——调用方必须区别对待：
// 只有确定性的拒绝才应清空本地凭证（引导重新授权），临时失败必须保留凭证，否则一次网络抖动就会把用户踢下线。
var ErrAuthRejected = errors.New("LoliaFrp 拒绝授权")

// oauthRejectedCodes 令牌端点明确表示「凭证不可用」的 OAuth 错误码。
var oauthRejectedCodes = map[string]bool{
	"invalid_grant":          true,
	"invalid_client":         true,
	"invalid_request":        true,
	"unauthorized_client":    true,
	"unsupported_grant_type": true,
}

// Client LoliaFrp API 客户端（Bearer Token 鉴权）。
type Client struct {
	baseURL string
	token   string
	hc      *http.Client
	// onUnauthorized 由上层注入：API 返回 401 时触发强制续期，返回新 access_token。
	// 每个 Client 只重试一次（Client 为按请求创建，无需长期状态）。
	onUnauthorized func() (string, bool)
}

// NewClient 创建客户端；token 为账户访问密钥。
func NewClient(token string) *Client {
	return &Client{token: strings.TrimSpace(token), hc: &http.Client{Timeout: 20 * time.Second}}
}

// SetUnauthorizedHandler 注入 401 续期回调（access_token 过期时用 refresh_token 换新）。
func (c *Client) SetUnauthorizedHandler(h func() (string, bool)) { c.onUnauthorized = h }

// apiResp LoliaFrp 统一响应结构。code 真实成功为 200（创建域名 201），
// 部分文档示例写 0，因此成功判定以 HTTP 状态码为准、code 仅在非 2xx 时取 msg。
type apiResp struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// call 发起请求并解析统一响应；HTTP 非 2xx 时以 msg 构造错误。
// 收到 401 时若注入了续期回调，则用 refresh_token 换新 access_token 后重试一次。
func (c *Client) call(method, fullURL string, body any) (*apiResp, error) {
	// 本地无 token 时直接给出可操作的提示，避免发出注定 401 的请求、
	// 让用户看到「authorization header is missing」这种无从下手的报错
	if strings.TrimSpace(c.token) == "" {
		return nil, errors.New("LoliaFrp 未授权：请先在本页完成授权；若授权已过期，请重新授权")
	}
	ar, status, err := c.doRequest(method, fullURL, body)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized && c.onUnauthorized != nil {
		if newToken, ok := c.onUnauthorized(); ok && strings.TrimSpace(newToken) != "" {
			c.token = strings.TrimSpace(newToken)
			ar2, st2, err2 := c.doRequest(method, fullURL, body)
			if err2 != nil {
				return nil, err2
			}
			ar, status = ar2, st2
		}
	}
	if status < 200 || status >= 300 {
		msg := ""
		if ar != nil {
			msg = strings.TrimSpace(ar.Msg)
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", status)
		}
		return nil, fmt.Errorf("LoliaFrp 错误(%d): %s", status, msg)
	}
	return ar, nil
}

// doRequest 执行单次 HTTP 请求；err 仅表示传输/解析失败，HTTP 状态（含非 2xx）
// 通过 status 返回，由 call 统一决定是否续期重试、构造业务错误。
func (c *Client) doRequest(method, fullURL string, body any) (*apiResp, int, error) {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		payload = b
	}
	// 跨境链路偶发「连接被重置 / 读取中途 EOF」。只对幂等的 GET 重试一次：
	// POST（建隧道 / 建域名 / 刷新令牌）重发可能产生副作用，宁可报错交给用户手动重试。
	attempts := 1
	if method == http.MethodGet {
		attempts = 2
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequest(method, fullURL, rd)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", UserAgent)
		req.Header.Set("Content-Type", "application/json")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("LoliaFrp 请求失败: %w", err)
			continue
		}
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		status := resp.StatusCode
		resp.Body.Close()
		if rerr != nil {
			lastErr = fmt.Errorf("读取 LoliaFrp 响应失败: %w", rerr)
			continue
		}
		var ar apiResp
		// 个别接口（如删除域名）成功时返回 text/plain，无 JSON 体：按 HTTP 状态直接判定
		if jerr := json.Unmarshal(data, &ar); jerr != nil && len(bytes.TrimSpace(data)) > 0 {
			if status >= 200 && status < 300 {
				return &apiResp{Code: status, Msg: strings.TrimSpace(string(data))}, status, nil
			}
			return nil, status, nil
		}
		return &ar, status, nil
	}
	return nil, 0, lastErr
}

// do 发起 GET/POST 等 JSON 请求，把 data 解码到 out（out 为 nil 时跳过）。
func (c *Client) do(method, path string, body any, out any) error {
	ar, err := c.call(method, BaseURL+path, body)
	if err != nil {
		return err
	}
	if out != nil && len(ar.Data) > 0 {
		if err := json.Unmarshal(ar.Data, out); err != nil {
			return fmt.Errorf("解析 LoliaFrp 数据失败: %w", err)
		}
	}
	return nil
}

// UserInfo 账户信息（GET /user/info）。字段严格对照文档：
// 流量额度为字节数，bandwidth_limit 为 Mbps，文档同时出现 is_banned/is_baned 两种拼写，全部兼容。
type UserInfo struct {
	ID             int64  `json:"id"`
	Username       string `json:"username"`
	Email          string `json:"email"`
	Avatar         string `json:"avatar"`
	Role           string `json:"role"`
	IsBanned       bool   `json:"is_banned"`
	IsBannedLegacy bool   `json:"is_baned"` // 文档示例中同时存在的历史拼写
	HasKYC         bool   `json:"has_kyc"`
	KYCStatus      string `json:"kyc_status"` // 如 certifying
	KYCCount       int    `json:"kyc_count"`
	MaxTunnelCount int    `json:"max_tunnel_count"`
	BandwidthLimit int    `json:"bandwidth_limit"` // Mbps
	TrafficLimit   int64  `json:"traffic_limit"`   // 字节
	TrafficUsed    int64  `json:"traffic_used"`    // 字节
	TodayChecked   bool   `json:"today_checked"`
	CreatedAt      string `json:"created_at"`
}

// Banned 统一封禁判定（兼容两种字段拼写）。
func (u *UserInfo) Banned() bool { return u.IsBanned || u.IsBannedLegacy }

// UserInfo 获取账户信息（同时用于验证访问密钥有效性）。
func (c *Client) UserInfo() (*UserInfo, error) {
	var u UserInfo
	if err := c.do(http.MethodGet, "/user/info", nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// Tunnel 云端隧道（列表与详情共用，详情独有字段允许空值）。
type Tunnel struct {
	ID             int64         `json:"id"`
	Name           string        `json:"name"` // 32 位十六进制，隧道主键（启动/删除/取配置均用它）
	Type           string        `json:"type"` // tcp/udp/http/https
	NodeID         int64         `json:"node_id"`
	NodeName       string        `json:"node_name"`
	NodeAddress    string        `json:"node_address"`
	LocalIP        string        `json:"local_ip"`
	LocalPort      int           `json:"local_port"`
	RemotePort     int           `json:"remote_port"`
	CustomDomain   string        `json:"custom_domain"`
	Remark         string        `json:"remark"`
	Status         string        `json:"status"` // active / inactive
	AutoTLS        bool          `json:"auto_tls"` // 兼容部分接口的顶层返回；详情以 Config.AutoTLS 为准
	Config         *TunnelConfig `json:"config,omitempty"`
	BandwidthLimit int           `json:"bandwidth_limit"` // Mbps
	ClientVersion  string        `json:"client_version"`
	CreatedAt      string        `json:"created_at"`
	TunnelToken    string        `json:"tunnel_token"`
}

// TunnelConfig 隧道高级配置（详情接口位于 config 字段内）。
type TunnelConfig struct {
	AutoTLS              bool   `json:"auto_tls"`
	Protocol             string `json:"protocol"`                 // 传输协议：tcp（默认）/ kcp
	ProxyProtocolVersion string `json:"proxy_protocol_version"`   // 关闭为 ""，可选 v1 / v2
	HTTPRedirect         bool   `json:"http_redirect"`            // 仅 https：HTTP 自动跳转 HTTPS
}

// EffectiveAutoTLS 统一取 AutoTLS（详情的 config 优先，回退顶层）。
func (t *Tunnel) EffectiveAutoTLS() bool {
	if t.Config != nil {
		return t.Config.AutoTLS
	}
	return t.AutoTLS
}

// tunnelListPage /user/tunnel 分页响应。
type tunnelListPage struct {
	List      []Tunnel `json:"list"`
	Total     int      `json:"total"`
	Page      int      `json:"page"`
	Limit     int      `json:"limit"`
	TotalPage int      `json:"total_page"`
}

// TunnelPage 获取隧道列表单页（GET /user/tunnel）。
func (c *Client) TunnelPage(page, limit int) (*tunnelListPage, error) {
	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = pageSize
	}
	path := "/user/tunnel?page=" + url.QueryEscape(fmt.Sprint(page)) +
		"&limit=" + url.QueryEscape(fmt.Sprint(limit))
	var p tunnelListPage
	if err := c.do(http.MethodGet, path, nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// AllTunnels 翻页拉取账户下全部隧道（隧道数量受 max_tunnel_count 约束，页数很少）。
func (c *Client) AllTunnels() ([]Tunnel, error) {
	var all []Tunnel
	for page := 1; ; page++ {
		p, err := c.TunnelPage(page, pageSize)
		if err != nil {
			return nil, err
		}
		all = append(all, p.List...)
		if page >= p.TotalPage || len(p.List) == 0 {
			break
		}
	}
	return all, nil
}

// Node 节点（POST /user/nodes 返回）。lolia 独有：支持协议、KYC/备案要求、
// frps/agent 版本、赞助方、带宽与实时负载，创建/启动隧道时据此筛选与提示。
type Node struct {
	ID                 int64    `json:"id"`
	Name               string   `json:"name"`
	RegionCode         string   `json:"region_code"`
	Status             string   `json:"status"` // online / offline
	SupportedProtocols []string `json:"supported_protocols"`
	NeedKYC            bool     `json:"need_kyc"`
	BeianRequired      bool     `json:"beian_required"`
	FrpsVersion        string   `json:"frps_version"`
	AgentVersion       string   `json:"agent_version"`
	Sponsor            string   `json:"sponsor"`
	Bandwidth          int      `json:"bandwidth"` // Mbps
	Load               float64  `json:"load"`      // 百分比
	Remark             string   `json:"remark"`
}

// nodeListPage /user/nodes 分页响应（注意该接口为 POST + JSON body 分页）。
type nodeListPage struct {
	Nodes []Node `json:"nodes"`
	Total int    `json:"total"`
	Page  int    `json:"page"`
	Limit int    `json:"limit"`
}

// NodePage 获取节点列表单页（POST /user/nodes）。
func (c *Client) NodePage(page, limit int) ([]Node, int, error) {
	var p nodeListPage
	if err := c.do(http.MethodPost, "/user/nodes", map[string]any{"page": page, "limit": limit}, &p); err != nil {
		return nil, 0, err
	}
	return p.Nodes, p.Total, nil
}

// AllNodes 拉取全部节点（limit 给大值，正常一页即可取完）。
func (c *Client) AllNodes() ([]Node, error) {
	var all []Node
	for page := 1; ; page++ {
		nodes, total, err := c.NodePage(page, pageSize)
		if err != nil {
			return nil, err
		}
		all = append(all, nodes...)
		if len(all) >= total || len(nodes) == 0 {
			break
		}
	}
	return all, nil
}

// TunnelDetail 获取隧道详情（GET /user/tunnel/{name}），比列表多出 tunnel_token
// （节点 TOKEN，免鉴权拉取 frpc 配置的凭据）与 created_at 等字段。
func (c *Client) TunnelDetail(name string) (*Tunnel, error) {
	var t Tunnel
	if err := c.do(http.MethodGet, "/user/tunnel/"+url.PathEscape(strings.TrimSpace(name)), nil, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// CreateTunnelReq 创建隧道请求（POST /user/tunnel）。
// RemotePort 留 0 时省略该字段，由服务端自动分配可用公网端口（官方控制台同机制）。
type CreateTunnelReq struct {
	NodeID       int64  `json:"node_id"`
	Type         string `json:"type"` // tcp / udp / http
	LocalIP      string `json:"local_ip"`
	LocalPort    int    `json:"local_port"`
	RemotePort   int    `json:"remote_port,omitempty"` // 0 = 服务端自动分配
	CustomDomain string `json:"custom_domain"`
	Remark       string `json:"remark"`
}

// CreateTunnel 创建隧道（POST /user/tunnel）。成功后可通过返回的 Tunnel 拿到 name。
func (c *Client) CreateTunnel(req CreateTunnelReq) (*Tunnel, error) {
	var t Tunnel
	if err := c.do(http.MethodPost, "/user/tunnel", req, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// TunnelUpdate 编辑隧道请求（PUT /user/tunnel/{name}）。
// 按官方控制台行为：节点、隧道类型、远程端口、名称不可改；
// config 携带传输协议、Proxy Protocol、（HTTP/HTTPS）AutoTLS/HTTP 跳转。
type TunnelUpdate struct {
	LocalIP      string             `json:"local_ip"`
	LocalPort    int                `json:"local_port"`
	CustomDomain string             `json:"custom_domain,omitempty"`
	Remark       string             `json:"remark"`
	Config       *TunnelUpdateExtra `json:"config,omitempty"`
}

// TunnelUpdateExtra 编辑隧道的 config 段。
// ProxyProtocolVersion 不用 omitempty：关闭需显式发 ""（v1/v2 为开启）；
// AutoTLS/HTTPRedirect 用指针：nil=不涉及该隧道类型，false=显式关闭。
type TunnelUpdateExtra struct {
	Protocol             string `json:"protocol,omitempty"` // tcp（默认）/ kcp
	ProxyProtocolVersion string `json:"proxy_protocol_version"`
	AutoTLS              *bool  `json:"auto_tls,omitempty"`
	HTTPRedirect         *bool  `json:"http_redirect,omitempty"`
}

// UpdateTunnel 编辑隧道（PUT /user/tunnel/{name}）。
func (c *Client) UpdateTunnel(name string, u TunnelUpdate) error {
	return c.do(http.MethodPut, "/user/tunnel/"+url.PathEscape(strings.TrimSpace(name)), u, nil)
}

// DeleteTunnel 删除隧道（DELETE /user/tunnel/{name}）。
func (c *Client) DeleteTunnel(name string) error {
	return c.do(http.MethodDelete, "/user/tunnel/"+url.PathEscape(strings.TrimSpace(name)), nil, nil)
}

// Domain 域名白名单条目（GET /user/domain 返回；添加/验证接口也返回该结构的部分字段）。
// 添加域名后状态为 pending，需按 VerificationSubdomain/VerificationToken 在 DNS 配置验证记录
// （或使用 DomainConnectURL 走 Cloudflare Domain Connect 一键验证），再调用 VerifyDomain 完成校验。
type Domain struct {
	ID                    int64  `json:"id"`
	Domain                string `json:"domain"`
	Remark                string `json:"remark"`
	IsVerified            bool   `json:"is_verified"`
	Status                string `json:"status"` // pending / verified 等
	VerificationSubdomain string `json:"verification_subdomain"`
	VerificationToken     string `json:"verification_token"`
	DomainConnectURL      string `json:"domain_connect_url"`
	HasBeian              bool   `json:"has_beian"`
	ExpiresAt             string `json:"expires_at"`
	CreatedAt             string `json:"created_at"`
	VerifiedAt            string `json:"verified_at"`
}

// domainListPage 域名列表分页响应。
type domainListPage struct {
	Domains []Domain `json:"domains"`
	Total   int      `json:"total"`
	Page    int      `json:"page"`
	Limit   int      `json:"limit"`
}

// AllDomains 拉取全部域名白名单（GET /user/domain，带分页参数直到取完）。
func (c *Client) AllDomains() ([]Domain, error) {
	var all []Domain
	for page := 1; ; page++ {
		var p domainListPage
		path := "/user/domain?page=" + strconv.Itoa(page) + "&limit=" + strconv.Itoa(pageSize)
		if err := c.do(http.MethodGet, path, nil, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Domains...)
		if len(all) >= p.Total || len(p.Domains) == 0 {
			break
		}
	}
	return all, nil
}

// AddDomain 添加域名到白名单（POST /user/domain）。
// 成功后返回的 Domain 含验证所需的子域/Token 与 Cloudflare 一键验证链接。
func (c *Client) AddDomain(domain, remark string) (*Domain, error) {
	var d Domain
	body := map[string]string{"domain": strings.TrimSpace(domain), "remark": strings.TrimSpace(remark)}
	if err := c.do(http.MethodPost, "/user/domain", body, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// DomainVerifyResult 验证域名结果（POST /user/domain/verify 的 data 段）。
type DomainVerifyResult struct {
	Domain     string `json:"domain"`
	IsVerified bool   `json:"is_verified"`
	Status     string `json:"status"`
	VerifiedAt string `json:"verified_at"`
}

// VerifyDomain 请求服务端校验域名的 DNS 验证记录（POST /user/domain/verify）。
// 记录尚未生效时服务端会在 msg 中说明，结果由返回值体现。
func (c *Client) VerifyDomain(domain string) (*DomainVerifyResult, error) {
	var r DomainVerifyResult
	body := map[string]string{"domain": strings.TrimSpace(domain)}
	if err := c.do(http.MethodPost, "/user/domain/verify", body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// DeleteDomain 删除域名白名单条目（DELETE /user/domain/{id}，成功返回 text/plain）。
func (c *Client) DeleteDomain(id int64) error {
	if id <= 0 {
		return errors.New("无效的域名 ID")
	}
	return c.do(http.MethodDelete, "/user/domain/"+strconv.FormatInt(id, 10), nil, nil)
}

// frpcConfigResp /tunnel/frpc/config 响应：config 为 Base64 编码的 frpc TOML。
type frpcConfigResp struct {
	Config string `json:"config"`
}

// FrpcConfig 通过节点 TOKEN 免鉴权拉取 frpc 配置（GET /tunnel/frpc/config，与官方 CLI 同源）。
// nodeToken 为隧道详情中的 tunnel_token；ids 为数字隧道 ID 列表，
// 同节点（同 nodeToken）多条隧道可逗号拼接，服务端一次返回合并好的整份 TOML。
// 返回值为 Base64 解码后的明文配置。
func (c *Client) FrpcConfig(nodeToken string, ids []string) (string, error) {
	nodeToken = strings.TrimSpace(nodeToken)
	if nodeToken == "" || len(ids) == 0 {
		return "", errors.New("缺少节点 TOKEN 或隧道 ID")
	}
	path := "/tunnel/frpc/config?token=" + url.QueryEscape(nodeToken) +
		"&id=" + url.QueryEscape(strings.Join(ids, ","))
	var out frpcConfigResp
	if err := c.do(http.MethodGet, path, nil, &out); err != nil {
		return "", err
	}
	// 官方 CLI 对 config 做标准 Base64 解码后直接交给 frpc 解析
	raw := strings.TrimSpace(out.Config)
	if raw == "" {
		return "", ErrEmptyConfig
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("解码 frpc 配置失败: %w", err)
	}
	if len(bytes.TrimSpace(decoded)) == 0 {
		return "", ErrEmptyConfig
	}
	return string(decoded), nil
}

// ============= OAuth2 授权码模式 =============

// TokenResult /oauth2/token 响应（标准 OAuth2 字段，按实际返回宽松解析）。
type TokenResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"` // 秒
}

// AuthorizeURL 构造浏览器授权跳转地址。state 由调用方生成并在回调时校验（防 CSRF）。
func AuthorizeURL(clientID, redirectURI, state string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", strings.TrimSpace(clientID))
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", OAuthScope)
	q.Set("state", state)
	return authorizeURL + "?" + q.Encode()
}

// ExchangeCode 用授权码向令牌端点换取 access_token（application/x-www-form-urlencoded，
// 标准 RFC 6749 §4.1.3）。redirectURI 必须与发起授权时完全一致，否则服务端拒绝。
func ExchangeCode(httpClient *http.Client, clientID, clientSecret, code, redirectURI string) (*TokenResult, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", strings.TrimSpace(code))
	form.Set("client_id", strings.TrimSpace(clientID))
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", redirectURI)
	return postTokenForm(httpClient, form)
}

// RefreshAccessToken 用 refresh_token 续期 access_token（RFC 6749 §6）。
// 服务端可能轮换 refresh_token，响应中携带新值时调用方应一并替换保存。
func RefreshAccessToken(httpClient *http.Client, clientID, clientSecret, refreshToken string) (*TokenResult, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", strings.TrimSpace(refreshToken))
	form.Set("client_id", strings.TrimSpace(clientID))
	form.Set("client_secret", clientSecret)
	return postTokenForm(httpClient, form)
}

// postTokenForm 令牌端点统一表单 POST（授权码换发与刷新共用）。
func postTokenForm(hc *http.Client, form url.Values) (*TokenResult, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	req, err := http.NewRequest(http.MethodPost, TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("LoliaFrp 令牌请求失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("读取 LoliaFrp 令牌响应失败: %w", err)
	}
	// 错误响应同样解析 body 中的 error/error_description 或 {code,msg}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
			Msg              string `json:"msg"`
		}
		_ = json.Unmarshal(data, &errBody)
		code := strings.TrimSpace(errBody.Error)
		msg := errBody.ErrorDescription
		if msg == "" {
			msg = code
		}
		if msg == "" {
			msg = errBody.Msg
		}
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		// 只有「明确拒绝」才要求重新授权（400/401/403 或 OAuth 拒绝码）；
		// 5xx、429 等临时失败保留凭证，交由调用方稍后重试
		if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || oauthRejectedCodes[code] {
			return nil, fmt.Errorf("%w：%s", ErrAuthRejected, msg)
		}
		return nil, fmt.Errorf("LoliaFrp 授权失败(HTTP %d): %s", resp.StatusCode, msg)
	}
	var tr TokenResult
	if err := json.Unmarshal(data, &tr); err != nil {
		return nil, fmt.Errorf("解析 LoliaFrp 令牌响应失败: %w", err)
	}
	if strings.TrimSpace(tr.AccessToken) == "" {
		return nil, errors.New("LoliaFrp 未返回 access_token")
	}
	return &tr, nil
}
