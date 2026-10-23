package cloudflared

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ============= Cloudflare REST API 客户端（API 全托管模式） =============
//
// 与 Token 托管模式的差异：隧道本身、Public Hostname 路由（ingress）与对应 DNS 记录
// 都由本程序通过 Cloudflare API 维护，用户不必进 Zero Trust 后台。
//
// 凭证复用「域名解析」模块的 Cloudflare 账号（dns_accounts 表），不另存一份 API Token：
// 同一把 Key 存两处必然产生“改了这处忘了那处”的隐患。
//
// 所需权限（Cloudflare API Token）：Zone:Read（列域名并取所属账号）、Zone:DNS:Edit（维护 CNAME）、
// Account:Cloudflare Tunnel:Edit（创建/查询隧道、下发 ingress）。
const apiEndpoint = "https://api.cloudflare.com/client/v4"

// APIClient Cloudflare REST API 客户端（Bearer Token 鉴权）。
type APIClient struct {
	token string
	hc    *http.Client
}

// NewAPIClient 创建 API 客户端。
func NewAPIClient(token string) *APIClient {
	return &APIClient{
		token: strings.TrimSpace(token),
		hc:    &http.Client{Timeout: 30 * time.Second},
	}
}

// apiErrorItem Cloudflare 错误项。
type apiErrorItem struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// apiEnvelope Cloudflare 统一响应外壳。
type apiEnvelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []apiErrorItem  `json:"errors"`
}

// do 发起请求并把 result 解码到 out（out 为 nil 时跳过）。
func (c *APIClient) do(ctx context.Context, method, path string, body any, out any) error {
	if c.token == "" {
		return errors.New("缺少 Cloudflare API Token")
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiEndpoint+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("Cloudflare API 请求失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("读取 Cloudflare 响应失败: %w", err)
	}
	var env apiEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("解析 Cloudflare 响应失败 (HTTP %d)", resp.StatusCode)
	}
	if !env.Success {
		return formatAPIError(resp.StatusCode, env.Errors)
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("解析 Cloudflare 数据失败: %w", err)
		}
	}
	return nil
}

// formatAPIError 组装可读错误：鉴权类失败额外给出可操作提示（用户最常卡在这里）。
func formatAPIError(status int, items []apiErrorItem) error {
	msg := ""
	if len(items) > 0 {
		parts := make([]string, 0, len(items))
		for _, it := range items {
			parts = append(parts, fmt.Sprintf("[%d] %s", it.Code, it.Message))
		}
		msg = strings.Join(parts, "; ")
	} else {
		msg = fmt.Sprintf("HTTP %d", status)
	}
	if status == http.StatusForbidden || status == http.StatusUnauthorized {
		return fmt.Errorf("Cloudflare 鉴权失败（%s）；请确认 API Token 有效且具备权限：Zone:Read、Zone:DNS:Edit、Account:Cloudflare Tunnel:Edit", msg)
	}
	// 6003 Invalid request headers / 10000 Authentication error：多为 Token 本身不可用
	for _, it := range items {
		if it.Code == 6003 || it.Code == 10000 {
			return fmt.Errorf("Cloudflare 拒绝该凭证（%s）；请确认填的是 API Token（Bearer 鉴权）而不是 Global API Key，且令牌未被禁用", msg)
		}
	}
	return errors.New("Cloudflare API 错误: " + msg)
}

// Zone 域名（含所属账号）。
type Zone struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AccountID string `json:"-"`
}

// ZoneByName 按域名查询 zone（同时校验凭证的 Zone:Read 权限，并取出所属账号 ID）。
func (c *APIClient) ZoneByName(ctx context.Context, name string) (*Zone, error) {
	var out []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones?name="+strings.TrimSpace(name), nil, &out); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("该账号下未找到域名 %s（请确认域名已托管在 Cloudflare 且 API Token 可访问）", name)
	}
	return &Zone{ID: out[0].ID, Name: out[0].Name, AccountID: out[0].Account.ID}, nil
}

// Tunnel 隧道。
type Tunnel struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// CreateTunnel 创建远程托管隧道（config_src=cloudflare），返回隧道与隧道 Token。
func (c *APIClient) CreateTunnel(ctx context.Context, accountID, name string) (*Tunnel, string, error) {
	var out struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	body := map[string]any{"name": name, "config_src": "cloudflare"}
	if err := c.do(ctx, http.MethodPost, "/accounts/"+accountID+"/cfd_tunnel", body, &out); err != nil {
		return nil, "", err
	}
	if out.ID == "" {
		return nil, "", errors.New("Cloudflare 未返回隧道 ID")
	}
	token := out.Token
	if token == "" {
		// 创建响应未带 token 时单独取一次（接口支持按隧道 ID 查询）
		t, err := c.GetTunnelToken(ctx, accountID, out.ID)
		if err != nil {
			return nil, "", err
		}
		token = t
	}
	return &Tunnel{ID: out.ID, Name: out.Name}, token, nil
}

// ListTunnels 列出账号下未删除的隧道（用于复用同名隧道）。
func (c *APIClient) ListTunnels(ctx context.Context, accountID string) ([]Tunnel, error) {
	var out []Tunnel
	if err := c.do(ctx, http.MethodGet, "/accounts/"+accountID+"/cfd_tunnel?is_deleted=false", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetTunnel 查询隧道（校验是否仍存在）。
func (c *APIClient) GetTunnel(ctx context.Context, accountID, tunnelID string) (*Tunnel, error) {
	var out Tunnel
	if err := c.do(ctx, http.MethodGet, "/accounts/"+accountID+"/cfd_tunnel/"+tunnelID, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetTunnelToken 获取隧道 Token（远程托管隧道运行所需）。
func (c *APIClient) GetTunnelToken(ctx context.Context, accountID, tunnelID string) (string, error) {
	var out string
	if err := c.do(ctx, http.MethodGet, "/accounts/"+accountID+"/cfd_tunnel/"+tunnelID+"/token", nil, &out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out) == "" {
		return "", errors.New("Cloudflare 未返回隧道 Token")
	}
	return out, nil
}

// IngressRule 一条 Public Hostname 路由（ingress 规则）。
// 注意：ingress 是整份覆盖式配置，且末尾必须存在 catch-all 规则（不带 hostname）。
type IngressRule struct {
	Hostname string `json:"hostname,omitempty"`
	Path     string `json:"path,omitempty"`
	Service  string `json:"service"`
}

// catchAllIngress ingress 末尾必须存在的兜底规则。
var catchAllIngress = IngressRule{Service: "http_status:404"}

// ValidService 校验 ingress 的 service 取值。
// 只接受浏览器可直接访问的 HTTP 类服务：Cloudflare 公网域名的 TCP/SSH/RDP/SMB 类型
// 要求访问方本地安装 cloudflared，与本功能的定位（HTTP(S) 域名入口）不符，故不放行。
func ValidService(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, prefix := range []string{"http://", "https://", "unix:", "unix+tls:"} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// HostnameInZone 判断 hostname 是否属于该 zone（等于 zone 或为其子域名）。
func HostnameInZone(hostname, zone string) bool {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	zone = strings.ToLower(strings.TrimSpace(zone))
	if hostname == "" || zone == "" {
		return false
	}
	return hostname == zone || strings.HasSuffix(hostname, "."+zone)
}

// GetIngress 读取远端 ingress 配置（忽略 catch-all 规则）。
func (c *APIClient) GetIngress(ctx context.Context, accountID, tunnelID string) ([]IngressRule, error) {
	var out struct {
		Config struct {
			Ingress []IngressRule `json:"ingress"`
		} `json:"config"`
	}
	if err := c.do(ctx, http.MethodGet, "/accounts/"+accountID+"/cfd_tunnel/"+tunnelID+"/configurations", nil, &out); err != nil {
		return nil, err
	}
	rules := make([]IngressRule, 0, len(out.Config.Ingress))
	for _, r := range out.Config.Ingress {
		if strings.TrimSpace(r.Hostname) == "" { // catch-all
			continue
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// PutIngress 整份下发 ingress 配置（自动在末尾补 catch-all 规则）。
func (c *APIClient) PutIngress(ctx context.Context, accountID, tunnelID string, rules []IngressRule) error {
	all := make([]IngressRule, 0, len(rules)+1)
	all = append(all, rules...)
	all = append(all, catchAllIngress)
	body := map[string]any{"config": map[string]any{"ingress": all}}
	return c.do(ctx, http.MethodPut, "/accounts/"+accountID+"/cfd_tunnel/"+tunnelID+"/configurations", body, nil)
}

// dnsRecord DNS 记录。
type dnsRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func (c *APIClient) listCNAMEs(ctx context.Context, zoneID, hostname string) ([]dnsRecord, error) {
	var out []dnsRecord
	path := "/zones/" + zoneID + "/dns_records?type=CNAME&name=" + hostname
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// EnsureTunnelCNAME 保证 hostname 存在一条指向本隧道的 CNAME 记录。
// 必须为代理记录（proxied=true, ttl=1）：否则流量不经过 Cloudflare 边缘，隧道无法命中。
func (c *APIClient) EnsureTunnelCNAME(ctx context.Context, zoneID, hostname, tunnelID string) error {
	content := tunnelID + ".cfargotunnel.com"
	existing, err := c.listCNAMEs(ctx, zoneID, hostname)
	if err != nil {
		return err
	}
	for _, r := range existing {
		if strings.EqualFold(r.Content, content) {
			return nil // 已是本隧道的记录
		}
		// 同名记录指向别处：改为本隧道（用户此前手工指向了别的隧道/地址）
		body := map[string]any{"type": "CNAME", "name": hostname, "content": content, "proxied": true, "ttl": 1}
		if err := c.do(ctx, http.MethodPut, "/zones/"+zoneID+"/dns_records/"+r.ID, body, nil); err != nil {
			return fmt.Errorf("更新 DNS 记录失败: %w", err)
		}
		return nil
	}
	body := map[string]any{"type": "CNAME", "name": hostname, "content": content, "proxied": true, "ttl": 1}
	if err := c.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", body, nil); err != nil {
		return fmt.Errorf("创建 DNS 记录失败: %w", err)
	}
	return nil
}

// DeleteTunnelCNAME 删除 hostname 上指向本隧道的 CNAME 记录（不存在或指向别处时不做任何事）。
func (c *APIClient) DeleteTunnelCNAME(ctx context.Context, zoneID, hostname, tunnelID string) error {
	content := tunnelID + ".cfargotunnel.com"
	existing, err := c.listCNAMEs(ctx, zoneID, hostname)
	if err != nil {
		return err
	}
	for _, r := range existing {
		if !strings.EqualFold(r.Content, content) {
			continue
		}
		if err := c.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+r.ID, nil, nil); err != nil {
			return fmt.Errorf("删除 DNS 记录失败: %w", err)
		}
	}
	return nil
}
