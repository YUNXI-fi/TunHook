// Package mefrp 实现 ME Frp 幻缘映射（https://www.mefrp.com）开放 API 的客户端
// 与独立 frpc 进程管理器，用于在 TunHook 内同步云端隧道并一键启动。
// API 文档：https://apidoc.mefrp.com
package mefrp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// BaseURL MEFrp 开放 API 根地址
	BaseURL = "https://api.mefrp.com/api"
	// UserAgent 接入文档硬性要求：客户端名称/版本 + 联系信息。
	// 禁止使用 MEFrp-Client 开头或 curl 等默认 UA，否则会被 CDN/WAF 拦截。
	UserAgent = "TunHook/0.6.6.172 github.com/YUNXI-fi/TunHook"
)

// ErrBlocked 请求被 MEFrp CDN/WAF 拦截（响应为 HTML 而非 JSON，首字符为 '<'）。
var ErrBlocked = errors.New("请求被 MEFrp 防护拦截，请稍后重试或更换网络")

// Client MEFrp API 客户端（Bearer Token 鉴权）。
type Client struct {
	token string
	hc    *http.Client
}

// NewClient 创建客户端；token 为账户访问密钥。
func NewClient(token string) *Client {
	return &Client{token: strings.TrimSpace(token), hc: &http.Client{Timeout: 20 * time.Second}}
}

// apiResp MEFrp 统一响应结构 {code, data, message}，code==200 表示成功。
type apiResp struct {
	Code    int             `json:"code"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
}

// call 发起请求并解析统一响应，code!=200 时以 message 构造错误。
func (c *Client) call(method, path string, body any) (*apiResp, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, BaseURL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MEFrp 请求失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("读取 MEFrp 响应失败: %w", err)
	}
	// WAF 拦截判定（文档约定）：返回 HTML 时首字符为 '<'，此时 JSON 解析必然出错
	if trimmed := strings.TrimSpace(string(data)); strings.HasPrefix(trimmed, "<") {
		return nil, ErrBlocked
	}
	var ar apiResp
	if err := json.Unmarshal(data, &ar); err != nil {
		return nil, fmt.Errorf("解析 MEFrp 响应失败(HTTP %d): %w", resp.StatusCode, err)
	}
	if ar.Code != 200 {
		return &ar, fmt.Errorf("MEFrp 错误(%d): %s", ar.Code, ar.Message)
	}
	return &ar, nil
}

// do 发起 API 请求并解析统一响应，把 data 解码到 out（out 为 nil 时跳过）。
func (c *Client) do(method, path string, body any, out any) error {
	ar, err := c.call(method, path, body)
	if err != nil {
		return err
	}
	if out != nil && len(ar.Data) > 0 {
		if err := json.Unmarshal(ar.Data, out); err != nil {
			return fmt.Errorf("解析 MEFrp 数据失败: %w", err)
		}
	}
	return nil
}

// UserInfo 账户信息（/auth/user/info）。
type UserInfo struct {
	UserID        int64  `json:"userId"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	Group         string `json:"group"`
	FriendlyGroup string `json:"friendlyGroup"`
	IsRealname    bool   `json:"isRealname"`
	MaxProxies    int    `json:"maxProxies"`
	UsedProxies   int    `json:"usedProxies"`
	// InBound/OutBound 带宽限速，接口原始单位 KB/s，换算 Mbps：值×8÷1024（与官方客户端一致）；
	// InBound 为入站（下行），OutBound 为出站（上行）
	InBound       int64  `json:"inBound"`
	OutBound      int64  `json:"outBound"`
	Traffic       int64  `json:"traffic"`
	Status        int    `json:"status"` // 0-正常 1-封禁 2-流量超限
	TodaySigned   bool   `json:"todaySigned"`
	RegTime       int64  `json:"regTime"`
}

// UserInfo 获取账户信息（同时用于验证访问密钥有效性）。
func (c *Client) UserInfo() (*UserInfo, error) {
	var u UserInfo
	if err := c.do(http.MethodGet, "/auth/user/info", nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// Node 隧道所在节点（/auth/proxy/list 返回的精简节点结构）。
type Node struct {
	NodeID   int64  `json:"nodeId"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
}

// Proxy 云端隧道（/auth/proxy/list 返回结构中与本功能相关的字段）。
type Proxy struct {
	ProxyID       int64  `json:"proxyId"`
	ProxyName     string `json:"proxyName"`
	ProxyType     string `json:"proxyType"`
	NodeID        int64  `json:"nodeId"`
	LocalIP       string `json:"localIp"`
	LocalPort     int    `json:"localPort"`
	RemotePort    int    `json:"remotePort"`
	Domain        string `json:"domain"`
	IsOnline      bool   `json:"isOnline"`
	IsBanned      bool   `json:"isBanned"`
	IsDisabled    bool   `json:"isDisabled"`
	LastStartTime int64  `json:"lastStartTime"`
	// 进阶设置：修改隧道接口（/auth/proxy/update）要求这些字段必需，
	// 且前端编辑时按列表值原样回填回传——解析缺失会导致每次保存都被重置为默认值
	HostHeaderRewrite    string `json:"hostHeaderRewrite"`
	ProxyProtocolVersion string `json:"proxyProtocolVersion"`
	UseEncryption        bool   `json:"useEncryption"`
	UseCompression       bool   `json:"useCompression"`
}

// ProxyList 隧道列表（节点 + 隧道）。
type ProxyList struct {
	Nodes   []Node  `json:"nodes"`
	Proxies []Proxy `json:"proxies"`
}

// ProxyList 获取隧道列表。
func (c *Client) ProxyList() (*ProxyList, error) {
	var l ProxyList
	if err := c.do(http.MethodGet, "/auth/proxy/list", nil, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// ProxyConfig 获取隧道 frpc 配置文本（/auth/proxy/config/multiple）。
// 多隧道仅支持同一节点；format 取 toml/json/ini（MEFrp 暂不支持 YAML）。
func (c *Client) ProxyConfig(proxyIDs []int64, format string) (string, error) {
	var out struct {
		Config string `json:"config"`
		Type   string `json:"type"`
	}
	body := map[string]any{"proxyIds": proxyIDs, "format": format}
	if err := c.do(http.MethodPost, "/auth/proxy/config/multiple", body, &out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.Config) == "" {
		return "", errors.New("MEFrp 返回的隧道配置为空")
	}
	return out.Config, nil
}

// Sign 签到（POST /auth/user/sign），返回服务端提示文案。
// 服务端要求人机验证时：引导用户在官方页面完成后回传 Base64 文本，
// 此处解码出 captchaToken（格式 `token||client`）随请求提交。
func (c *Client) Sign(captchaToken string) (string, error) {
	body := map[string]any{"captchaToken": decodeCaptcha(captchaToken)}
	ar, err := c.call(http.MethodPost, "/auth/user/sign", body)
	if err != nil {
		if ar != nil && strings.TrimSpace(ar.Message) != "" {
			return "", errors.New(ar.Message)
		}
		return "", err
	}
	return ar.Message, nil
}

// decodeCaptcha 把用户回传的 Base64 文本解码为 captchaToken（`token||client` 取前段）；
// 解析失败或不含分隔符时按原文使用。
func decodeCaptcha(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		if parts := strings.SplitN(string(b), "||", 2); len(parts) == 2 {
			return strings.TrimSpace(parts[0])
		}
	}
	return s
}

// LotteryInfo 查询抽奖次数信息（GET /auth/user/luckydraw）。
// 实测响应为 {"count":每日总次数,"remaining":剩余次数}，remaining=-1 表示服务端未提供具体剩余；
// 兼容 data 为纯数字的旧形态（此时视为剩余次数）。
func (c *Client) LotteryInfo() (count, remaining int, err error) {
	raw, err := c.LotteryRaw()
	if err != nil {
		return 0, -1, err
	}
	if len(raw) == 0 {
		return 0, -1, nil
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return n, n, nil
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil {
		return 0, -1, nil
	}
	if v, ok := obj["count"].(float64); ok {
		count = int(v)
	}
	if v, ok := obj["remaining"].(float64); ok {
		remaining = int(v)
	} else {
		// 旧形态兜底：left/remaining 等常见字段
		for _, k := range []string{"left", "remain", "surplus"} {
			if v, ok := obj[k].(float64); ok {
				remaining = int(v)
				break
			}
		}
	}
	return count, remaining, nil
}

// LotteryRaw 返回剩余抽奖次数接口的原始 data（用于调试确认真实结构）。
func (c *Client) LotteryRaw() (json.RawMessage, error) {
	ar, err := c.call(http.MethodGet, "/auth/user/luckydraw", nil)
	if err != nil {
		return nil, err
	}
	return ar.Data, nil
}

// LotteryDraw 单次抽奖（POST /auth/user/luckydraw，仅单抽），返回原始 data 与提示文案。
func (c *Client) LotteryDraw() (json.RawMessage, string, error) {
	ar, err := c.call(http.MethodPost, "/auth/user/luckydraw", nil)
	if err != nil {
		if ar != nil && strings.TrimSpace(ar.Message) != "" {
			return nil, ar.Message, errors.New(ar.Message)
		}
		return nil, "", err
	}
	return ar.Data, ar.Message, nil
}

// CreateProxyData 获取创建隧道所需数据（GET /auth/createProxyData：节点/用户组/当前组）。
func (c *Client) CreateProxyData() (json.RawMessage, error) {
	ar, err := c.call(http.MethodGet, "/auth/createProxyData", nil)
	if err != nil {
		return nil, err
	}
	return ar.Data, nil
}

// NodeStatus 获取节点实时状态列表（GET /auth/node/status，含负载 loadPercent）。
func (c *Client) NodeStatus() (json.RawMessage, error) {
	ar, err := c.call(http.MethodGet, "/auth/node/status", nil)
	if err != nil {
		return nil, err
	}
	return ar.Data, nil
}

// NodeAddress 节点连接地址（GET /auth/node/nameList）。
type NodeAddress struct {
	NodeID   int64  `json:"nodeId"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"` // 节点连接地址：可能是域名，也可能是 IP
}

// NodeAddressList 获取节点连接地址列表（GET /auth/node/nameList）。
// 与 /auth/createProxyData 不同：创建数据里的 hostname 恒为空，节点连接地址只在这个接口返回；
// 且仅包含「已创建过隧道」的节点，未建过隧道的节点查不到地址。
func (c *Client) NodeAddressList() ([]NodeAddress, error) {
	var out []NodeAddress
	if err := c.do(http.MethodGet, "/auth/node/nameList", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateProxy 创建隧道（POST /auth/proxy/create，新版 0.65.0+ 接口），返回服务端提示。
// 完整字段由后端构造，未使用的可选项传空值。
func (c *Client) CreateProxy(body map[string]any) (string, error) {
	ar, err := c.call(http.MethodPost, "/auth/proxy/create", body)
	if err != nil {
		if ar != nil && strings.TrimSpace(ar.Message) != "" {
			return "", errors.New(ar.Message)
		}
		return "", err
	}
	return ar.Message, nil
}

// ToggleProxy 启用/禁用隧道（POST /auth/proxy/toggle）。
func (c *Client) ToggleProxy(proxyID int64, disabled bool) (string, error) {
	ar, err := c.call(http.MethodPost, "/auth/proxy/toggle", map[string]any{"proxyId": proxyID, "isDisabled": disabled})
	if err != nil {
		if ar != nil && strings.TrimSpace(ar.Message) != "" {
			return "", errors.New(ar.Message)
		}
		return "", err
	}
	return ar.Message, nil
}

// DeleteProxy 删除隧道（POST /auth/proxy/delete）。
func (c *Client) DeleteProxy(proxyID int64) (string, error) {
	ar, err := c.call(http.MethodPost, "/auth/proxy/delete", map[string]any{"proxyId": proxyID})
	if err != nil {
		if ar != nil && strings.TrimSpace(ar.Message) != "" {
			return "", errors.New(ar.Message)
		}
		return "", err
	}
	return ar.Message, nil
}

// KickProxy 强制下线隧道（POST /auth/proxy/kick）。
func (c *Client) KickProxy(proxyID int64) (string, error) {
	ar, err := c.call(http.MethodPost, "/auth/proxy/kick", map[string]any{"proxyId": proxyID})
	if err != nil {
		if ar != nil && strings.TrimSpace(ar.Message) != "" {
			return "", errors.New(ar.Message)
		}
		return "", err
	}
	return ar.Message, nil
}

// UpdateProxy 修改隧道（POST /auth/proxy/update，按 proxyName 定位），返回服务端提示。
func (c *Client) UpdateProxy(body map[string]any) (string, error) {
	ar, err := c.call(http.MethodPost, "/auth/proxy/update", body)
	if err != nil {
		if ar != nil && strings.TrimSpace(ar.Message) != "" {
			return "", errors.New(ar.Message)
		}
		return "", err
	}
	return ar.Message, nil
}
