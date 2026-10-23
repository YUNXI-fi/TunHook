// DNS-01 验证支持：通过各 DNS 服务商 API 自动添加/删除 _acme-challenge TXT 记录。
// 支持阿里云 DNS、腾讯云 DNSPod、华为云 DNS、Cloudflare；其他服务商需自行添加 TXT 记录。
package forward

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// dns01Provider 一个 DNS-01 验证提供方（添加/删除 TXT 记录）。
type dns01Provider interface {
	// AddTXTRecord 添加 _acme-challenge TXT 记录（recordName 为完整记录名，如 _acme-challenge.example.com）。
	AddTXTRecord(ctx context.Context, recordName, value string) error
	// RemoveTXTRecord 删除本次申请添加的全部 TXT 记录（申请结束后清理）。
	RemoveTXTRecord(ctx context.Context) error
}

// newDNS01Provider 根据服务商与凭证创建 DNS-01 提供方。
func newDNS01Provider(provider string, creds map[string]string) (dns01Provider, error) {
	switch provider {
	case "阿里云 DNS":
		if strings.TrimSpace(creds["access_key"]) == "" || strings.TrimSpace(creds["secret_key"]) == "" {
			return nil, fmt.Errorf("阿里云 DNS 账户缺少 Access Key / Secret Key")
		}
		return &aliyunDNS{accessKey: strings.TrimSpace(creds["access_key"]), secretKey: strings.TrimSpace(creds["secret_key"])}, nil
	case "腾讯云 DNSPod":
		if strings.TrimSpace(creds["secret_id"]) == "" || strings.TrimSpace(creds["secret_key"]) == "" {
			return nil, fmt.Errorf("腾讯云 DNSPod 账户缺少 Secret ID / Secret Key")
		}
		return &tencentDNS{secretID: strings.TrimSpace(creds["secret_id"]), secretKey: strings.TrimSpace(creds["secret_key"])}, nil
	case "华为云 DNS":
		if strings.TrimSpace(creds["access_key"]) == "" || strings.TrimSpace(creds["secret_key"]) == "" {
			return nil, fmt.Errorf("华为云 DNS 账户缺少 Access Key / Secret Key")
		}
		return &huaweiDNS{accessKey: strings.TrimSpace(creds["access_key"]), secretKey: strings.TrimSpace(creds["secret_key"]), region: strings.TrimSpace(creds["region"])}, nil
	case "Cloudflare":
		if strings.TrimSpace(creds["email"]) == "" || strings.TrimSpace(creds["api_token"]) == "" {
			return nil, fmt.Errorf("cloudflare 账户缺少 EMAIL / API Token")
		}
		return &cloudflareDNS{email: strings.TrimSpace(creds["email"]), apiToken: strings.TrimSpace(creds["api_token"])}, nil
	case "GoDaddy":
		if strings.TrimSpace(creds["api_key"]) == "" || strings.TrimSpace(creds["api_secret"]) == "" {
			return nil, fmt.Errorf("GoDaddy 账户缺少 API Key / API Secret")
		}
		return &goDaddyDNS{apiKey: strings.TrimSpace(creds["api_key"]), apiSecret: strings.TrimSpace(creds["api_secret"])}, nil
	case "Vercel":
		if strings.TrimSpace(creds["api_token"]) == "" {
			return nil, fmt.Errorf("Vercel 账户缺少 API Token")
		}
		return &vercelDNS{apiToken: strings.TrimSpace(creds["api_token"])}, nil
	case "DNSPod 国际站":
		if strings.TrimSpace(creds["login_id"]) == "" || strings.TrimSpace(creds["api_token"]) == "" {
			return nil, fmt.Errorf("DNSPod 国际站账户缺少 Token ID / API Token")
		}
		return &dnspodIntlDNS{loginID: strings.TrimSpace(creds["login_id"]), apiToken: strings.TrimSpace(creds["api_token"])}, nil
	default:
		return nil, fmt.Errorf("不支持的 DNS 服务商：%s（可先用 Acme 账户 HTTP-01 方式申请）", provider)
	}
}

// acmeChallengePrefix 各服务商创建的 TXT 记录统一此前缀。
const acmeChallengePrefix = "_acme-challenge."

// splitDNSBase 把待验证的基域名拆分为「注册域 + 子域前缀」：
// myunxi.top → (myunxi.top, "")；sub.example.com → (example.com, "sub")。
// 阿里云/腾讯云 API 的 DomainName/Domain 需要注册域，子域放 RR/SubDomain。
func splitDNSBase(base string) (domain, sub string) {
	parts := strings.Split(base, ".")
	if len(parts) <= 2 {
		return base, ""
	}
	domain = strings.Join(parts[len(parts)-2:], ".")
	sub = strings.Join(parts[:len(parts)-2], ".")
	return domain, sub
}

// acmeRR 返回 TXT 记录的 RR 部分（_acme-challenge，子域时追加 .sub）。
func acmeRR(sub string) string {
	rr := strings.TrimSuffix(acmeChallengePrefix, ".")
	if sub != "" {
		rr += "." + sub
	}
	return rr
}

// 幂等 ID（SignatureNonce / RecordId 等）
func randomNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func httpDo(req *http.Request) ([]byte, int, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// ============= 阿里云 DNS（RPC 签名 HMAC-SHA1） =============

const aliyunEndpoint = "https://dns.aliyuncs.com/"

type aliyunDNS struct {
	accessKey string
	secretKey string
	recordIDs []string // 本次申请添加的记录 ID
}

// aliyunEncode 阿里云规范化的 URL 编码（字母数字与 -_.~ 不编码，其余 %XX 大写）。
func aliyunEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

func (p *aliyunDNS) request(ctx context.Context, params map[string]string) ([]byte, error) {
	params["Format"] = "JSON"
	params["Version"] = "2015-01-09"
	params["AccessKeyId"] = p.accessKey
	params["SignatureMethod"] = "HMAC-SHA1"
	params["SignatureVersion"] = "1.0"
	params["SignatureNonce"] = randomNonce()
	params["Timestamp"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonical.WriteByte('&')
		}
		canonical.WriteString(aliyunEncode(k))
		canonical.WriteByte('=')
		canonical.WriteString(aliyunEncode(params[k]))
	}
	strToSign := "GET&" + aliyunEncode("/") + "&" + aliyunEncode(canonical.String())
	mac := hmac.New(sha1.New, []byte(p.secretKey+"&"))
	mac.Write([]byte(strToSign))
	params["Signature"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))

	values := url.Values{}
	for k, v := range params {
		values.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, aliyunEndpoint+"?"+values.Encode(), nil)
	if err != nil {
		return nil, err
	}
	body, _, err := httpDo(req)
	if err != nil {
		return nil, err
	}
	// 阿里云错误返回 {"Code":"...","Message":"..."}，统一转成 error
	var e struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal(body, &e); err == nil && e.Code != "" {
		return nil, fmt.Errorf("阿里云 DNS API 错误 %s: %s", e.Code, e.Message)
	}
	return body, nil
}

func (p *aliyunDNS) AddTXTRecord(ctx context.Context, recordName, value string) error {
	// recordName = _acme-challenge.{base} → 注册域放 DomainName，RR 放 _acme-challenge(.sub)
	base := strings.TrimPrefix(recordName, acmeChallengePrefix)
	domain, sub := splitDNSBase(base)
	body, err := p.request(ctx, map[string]string{
		"Action":     "AddDomainRecord",
		"DomainName": domain,
		"RR":         acmeRR(sub),
		"Type":       "TXT",
		"Value":      value,
		"TTL":        "600",
	})
	if err != nil {
		return err
	}
	var resp struct {
		RecordID string `json:"RecordId"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("阿里云 DNS 添加记录响应解析失败: %v", err)
	}
	if resp.RecordID == "" {
		return fmt.Errorf("阿里云 DNS 未返回记录 ID: %s", string(body))
	}
	p.recordIDs = append(p.recordIDs, resp.RecordID)
	return nil
}

func (p *aliyunDNS) RemoveTXTRecord(ctx context.Context) error {
	var lastErr error
	for _, id := range p.recordIDs {
		if _, err := p.request(ctx, map[string]string{"Action": "DeleteDomainRecord", "RecordId": id}); err != nil {
			lastErr = err
		}
	}
	p.recordIDs = nil
	return lastErr
}

// ============= 腾讯云 DNSPod（TC3-HMAC-SHA256 签名） =============

const tencentEndpoint = "https://dnspod.tencentcloudapi.com"

type tencentDNS struct {
	secretID  string
	secretKey string
	recordIDs []string
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func (p *tencentDNS) request(ctx context.Context, action string, payload map[string]interface{}) ([]byte, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	timestamp := time.Now().Unix()
	date := time.Now().UTC().Format("2006-01-02")
	hashedPayload := sha256.Sum256(bodyBytes)
	canonical := strings.Join([]string{
		"POST",
		"/",
		"",
		"content-type:application/json; charset=utf-8",
		"host:dnspod.tencentcloudapi.com",
		"x-tc-action:" + strings.ToLower(action),
		"",
		"content-type;host;x-tc-action",
		hex.EncodeToString(hashedPayload[:]),
	}, "\n")
	hashedCanonical := sha256.Sum256([]byte(canonical))
	strToSign := strings.Join([]string{
		"TC3-HMAC-SHA256",
		fmt.Sprintf("%d", timestamp),
		date + "/dnspod/tc3_request",
		hex.EncodeToString(hashedCanonical[:]),
	}, "\n")
	secretDate := hmacSHA256([]byte("TC3"+p.secretKey), []byte(date))
	secretService := hmacSHA256(secretDate, []byte("dnspod"))
	secretSigning := hmacSHA256(secretService, []byte("tc3_request"))
	signature := hex.EncodeToString(hmacSHA256(secretSigning, []byte(strToSign)))
	authorization := fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s/dnspod/tc3_request, SignedHeaders=content-type;host;x-tc-action, Signature=%s",
		p.secretID, date, signature)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tencentEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", "dnspod.tencentcloudapi.com")
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-TC-Version", "2021-03-23")
	req.Header.Set("Authorization", authorization)
	body, status, err := httpDo(req)
	if err != nil {
		return nil, err
	}
	var e struct {
		Response struct {
			Error struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(body, &e); err == nil && e.Response.Error.Code != "" {
		return nil, fmt.Errorf("腾讯云 DNSPod API 错误 %s (HTTP %d): %s", e.Response.Error.Code, status, e.Response.Error.Message)
	}
	return body, nil
}

func (p *tencentDNS) AddTXTRecord(ctx context.Context, recordName, value string) error {
	// recordName = _acme-challenge.{base} → Domain 放注册域，SubDomain 放 _acme-challenge(.sub)
	base := strings.TrimPrefix(recordName, acmeChallengePrefix)
	domain, sub := splitDNSBase(base)
	body, err := p.request(ctx, "CreateRecord", map[string]interface{}{
		"Domain":     domain,
		"SubDomain":  acmeRR(sub),
		"RecordType": "TXT",
		"RecordLine": "默认",
		"Value":      value,
		"TTL":        600,
	})
	if err != nil {
		return err
	}
	var resp struct {
		Response struct {
			Record struct {
				Id int64 `json:"Id"`
			} `json:"Record"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("腾讯云 DNSPod 添加记录响应解析失败: %v", err)
	}
	if resp.Response.Record.Id == 0 {
		return fmt.Errorf("腾讯云 DNSPod 未返回记录 ID: %s", string(body))
	}
	p.recordIDs = append(p.recordIDs, fmt.Sprintf("%d|%s", resp.Response.Record.Id, domain))
	return nil
}

func (p *tencentDNS) RemoveTXTRecord(ctx context.Context) error {
	var lastErr error
	for _, id := range p.recordIDs {
		parts := strings.SplitN(id, "|", 2)
		if len(parts) != 2 {
			continue
		}
		if _, err := p.request(ctx, "DeleteRecord", map[string]interface{}{"Domain": parts[1], "RecordId": parts[0]}); err != nil {
			lastErr = err
		}
	}
	p.recordIDs = nil
	return lastErr
}

// ============= 华为云 DNS（SDK-HMAC-SHA256 签名） =============

const huaweiDefaultEndpoint = "https://dns.myhuaweicloud.com"

type huaweiDNS struct {
	accessKey   string
	secretKey   string
	region      string
	zoneID      string
	recordsetID string
}

func huaweiEndpoint(region string) string {
	if region != "" {
		return "https://dns." + region + ".myhuaweicloud.com"
	}
	return huaweiDefaultEndpoint
}

func (p *huaweiDNS) sign(req *http.Request, bodyBytes []byte) {
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	date := time.Now().UTC().Format("20060102")
	hashedPayload := sha256.Sum256(bodyBytes)
	req.Header.Set("X-Sdk-Date", timestamp)
	req.Header.Set("Content-Type", "application/json")

	canonical := strings.Join([]string{
		req.Method,
		req.URL.RequestURI(),
		"",
		"content-type:application/json",
		"x-sdk-date:" + timestamp,
		"",
		"content-type;x-sdk-date",
		hex.EncodeToString(hashedPayload[:]),
	}, "\n")
	hashedCanonical := sha256.Sum256([]byte(canonical))
	strToSign := "SDK-HMAC-SHA256\n" + timestamp + "\n" + hex.EncodeToString(hashedCanonical[:])
	kDate := hmacSHA256([]byte(p.secretKey), []byte(date))
	region := p.region
	if region == "" {
		region = "cn-north-1"
	}
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("dns"))
	kSigning := hmacSHA256(kService, []byte("sdk-hmac-sha256"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(strToSign)))
	req.Header.Set("Authorization", fmt.Sprintf("SDK-HMAC-SHA256 Access=%s, SignedHeaders=content-type;x-sdk-date, Signature=%s",
		p.accessKey, signature))
}

func (p *huaweiDNS) doJSON(ctx context.Context, method, path, query string, payload interface{}) ([]byte, error) {
	var bodyBytes []byte
	var err error
	if payload != nil {
		bodyBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}
	u := huaweiEndpoint(p.region) + path
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	p.sign(req, bodyBytes)
	body, status, err := httpDo(req)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
			return nil, fmt.Errorf("华为云 DNS API 错误 (HTTP %d): %s", status, e.Error.Message)
		}
		return nil, fmt.Errorf("华为云 DNS API 错误 (HTTP %d): %s", status, string(body))
	}
	return body, nil
}

// zoneIDFor 逐级向上查找域名所属 zone。
func (p *huaweiDNS) zoneIDFor(ctx context.Context, domain string) (string, error) {
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		name := strings.Join(parts[i:], ".")
		body, err := p.doJSON(ctx, http.MethodGet, "/v2/zones", "name="+url.QueryEscape(name), nil)
		if err != nil {
			return "", err
		}
		var resp struct {
			Zones []struct {
				ID string `json:"id"`
			} `json:"zones"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", err
		}
		if len(resp.Zones) > 0 && resp.Zones[0].ID != "" {
			return resp.Zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("华为云 DNS 未找到域名 %s 所属的 zone", domain)
}

func (p *huaweiDNS) AddTXTRecord(ctx context.Context, recordName, value string) error {
	domain := strings.TrimPrefix(recordName, acmeChallengePrefix)
	zoneID, err := p.zoneIDFor(ctx, domain)
	if err != nil {
		return err
	}
	p.zoneID = zoneID
	body, err := p.doJSON(ctx, http.MethodPost, "/v2/zones/"+zoneID+"/recordsets", "", map[string]interface{}{
		"name":    recordName + ".",
		"type":    "TXT",
		"ttl":     600,
		"records": []string{`"` + value + `"`},
	})
	if err != nil {
		return err
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("华为云 DNS 添加记录响应解析失败: %v", err)
	}
	if resp.ID == "" {
		return fmt.Errorf("华为云 DNS 未返回 recordset ID: %s", string(body))
	}
	p.recordsetID = resp.ID
	return nil
}

func (p *huaweiDNS) RemoveTXTRecord(ctx context.Context) error {
	if p.zoneID == "" || p.recordsetID == "" {
		return nil
	}
	_, err := p.doJSON(ctx, http.MethodDelete, "/v2/zones/"+p.zoneID+"/recordsets/"+p.recordsetID, "", nil)
	p.zoneID, p.recordsetID = "", ""
	return err
}

// ============= Cloudflare（REST API，Bearer Token） =============

const cloudflareEndpoint = "https://api.cloudflare.com/client/v4"

type cloudflareDNS struct {
	email     string
	apiToken  string
	zoneID    string
	recordIDs []string
}

func (p *cloudflareDNS) doJSON(ctx context.Context, method, path string, payload interface{}) ([]byte, int, error) {
	var bodyBytes []byte
	var err error
	if payload != nil {
		bodyBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, cloudflareEndpoint+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	if p.email != "" {
		req.Header.Set("X-Auth-Email", p.email)
	}
	req.Header.Set("Content-Type", "application/json")
	body, status, err := httpDo(req)
	if err != nil {
		return nil, status, err
	}
	return body, status, nil
}

func (p *cloudflareDNS) zoneIDFor(ctx context.Context, domain string) (string, error) {
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		name := strings.Join(parts[i:], ".")
		body, status, err := p.doJSON(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(name), nil)
		if err != nil {
			return "", err
		}
		if status != 200 {
			return "", fmt.Errorf("cloudflare API 错误 (HTTP %d): %s", status, string(body))
		}
		var resp struct {
			Success bool `json:"success"`
			Errors  []struct {
				Message string `json:"message"`
			} `json:"errors"`
			Result []struct {
				ID string `json:"id"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", err
		}
		if !resp.Success {
			return "", fmt.Errorf("cloudflare API 错误: %+v", resp.Errors)
		}
		if len(resp.Result) > 0 && resp.Result[0].ID != "" {
			return resp.Result[0].ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare 未找到域名 %s 所属的 zone", domain)
}

func (p *cloudflareDNS) AddTXTRecord(ctx context.Context, recordName, value string) error {
	domain := strings.TrimPrefix(recordName, acmeChallengePrefix)
	zoneID, err := p.zoneIDFor(ctx, domain)
	if err != nil {
		return err
	}
	p.zoneID = zoneID
	body, status, err := p.doJSON(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", map[string]interface{}{
		"type":    "TXT",
		"name":    recordName,
		"content": value,
		"ttl":     120,
	})
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("cloudflare API 错误 (HTTP %d): %s", status, string(body))
	}
	var resp struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return err
	}
	if !resp.Success || resp.Result.ID == "" {
		return fmt.Errorf("cloudflare 添加记录失败: %+v", resp.Errors)
	}
	p.recordIDs = append(p.recordIDs, resp.Result.ID)
	return nil
}

func (p *cloudflareDNS) RemoveTXTRecord(ctx context.Context) error {
	var lastErr error
	for _, id := range p.recordIDs {
		body, status, err := p.doJSON(ctx, http.MethodDelete, "/zones/"+p.zoneID+"/dns_records/"+id, nil)
		if err != nil {
			lastErr = err
			continue
		}
		if status != 200 {
			lastErr = fmt.Errorf("cloudflare 删除记录失败 (HTTP %d): %s", status, string(body))
		}
	}
	p.recordIDs = nil
	return lastErr
}

// ============= 通用解析记录管理（域名解析面板 / DDNS） =============

// DNSRecord 一条通用解析记录。Name 统一为「主机记录」（根记录为 @），
// 例如 aliasyun 的 RR、腾讯云的 SubDomain、华为云记录名去掉 zone 后缀后的部分。
type DNSRecord struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl"`
	Status string `json:"status"`
	Updated string `json:"updated"` // 服务商返回的记录更新时间（无则空）
}

// DNSDomain 一个域名及归属记录数。
type DNSDomain struct {
	Name      string `json:"name"`
	RecordCnt int    `json:"record_count"`
}

// DNSRecordManager 通用解析记录管理器（新增/查询/修改/删除记录，列域名）。
type DNSRecordManager interface {
	// ListDomains 列出账户下全部域名。
	ListDomains(ctx context.Context) ([]DNSDomain, error)
	// ListRecords 列出指定域名（注册域）下的全部记录。
	ListRecords(ctx context.Context, domain string) ([]DNSRecord, error)
	// AddRecord 新增一条记录，返回记录 ID。rr 为「主机记录」（根记录传 @）。
	AddRecord(ctx context.Context, domain, rr, rtype, value string, ttl int) (string, error)
	// UpdateRecord 修改一条记录。
	UpdateRecord(ctx context.Context, domain, recordID, rr, rtype, value string, ttl int) error
	// DeleteRecord 删除一条记录。
	DeleteRecord(ctx context.Context, domain, recordID string) error
}

// NewDNSRecordManager 根据服务商与凭证创建通用记录管理器（凭证字段与 newDNS01Provider 一致）。
func NewDNSRecordManager(provider string, creds map[string]string) (DNSRecordManager, error) {
	return newDNSRecordManager(provider, creds)
}

// UpdateRecordValue 更新某域名下「主机记录 = rr 且类型 = rtype」的记录值为 value（DDNS 用）。
func UpdateRecordValue(ctx context.Context, m DNSRecordManager, domain, rr, rtype, value string) (string, error) {
	return updateRecordValue(ctx, m, domain, rr, rtype, value)
}

// newDNSRecordManager 根据服务商与凭证创建通用记录管理器（凭证字段与 newDNS01Provider 一致）。
func newDNSRecordManager(provider string, creds map[string]string) (DNSRecordManager, error) {
	switch provider {
	case "阿里云 DNS":
		if strings.TrimSpace(creds["access_key"]) == "" || strings.TrimSpace(creds["secret_key"]) == "" {
			return nil, fmt.Errorf("阿里云 DNS 账户缺少 Access Key / Secret Key")
		}
		return &aliyunDNS{accessKey: strings.TrimSpace(creds["access_key"]), secretKey: strings.TrimSpace(creds["secret_key"])}, nil
	case "腾讯云 DNSPod":
		if strings.TrimSpace(creds["secret_id"]) == "" || strings.TrimSpace(creds["secret_key"]) == "" {
			return nil, fmt.Errorf("腾讯云 DNSPod 账户缺少 Secret ID / Secret Key")
		}
		return &tencentDNS{secretID: strings.TrimSpace(creds["secret_id"]), secretKey: strings.TrimSpace(creds["secret_key"])}, nil
	case "华为云 DNS":
		if strings.TrimSpace(creds["access_key"]) == "" || strings.TrimSpace(creds["secret_key"]) == "" {
			return nil, fmt.Errorf("华为云 DNS 账户缺少 Access Key / Secret Key")
		}
		return &huaweiDNS{accessKey: strings.TrimSpace(creds["access_key"]), secretKey: strings.TrimSpace(creds["secret_key"]), region: strings.TrimSpace(creds["region"])}, nil
	case "Cloudflare":
		if strings.TrimSpace(creds["api_token"]) == "" && strings.TrimSpace(creds["email"]) == "" {
			return nil, fmt.Errorf("Cloudflare 账户缺少 API Token / EMAIL")
		}
		return &cloudflareDNS{email: strings.TrimSpace(creds["email"]), apiToken: strings.TrimSpace(creds["api_token"])}, nil
	case "GoDaddy":
		if strings.TrimSpace(creds["api_key"]) == "" || strings.TrimSpace(creds["api_secret"]) == "" {
			return nil, fmt.Errorf("GoDaddy 账户缺少 API Key / API Secret")
		}
		return &goDaddyDNS{apiKey: strings.TrimSpace(creds["api_key"]), apiSecret: strings.TrimSpace(creds["api_secret"])}, nil
	case "Vercel":
		if strings.TrimSpace(creds["api_token"]) == "" {
			return nil, fmt.Errorf("Vercel 账户缺少 API Token")
		}
		return &vercelDNS{apiToken: strings.TrimSpace(creds["api_token"])}, nil
	case "DNSPod 国际站":
		if strings.TrimSpace(creds["login_id"]) == "" || strings.TrimSpace(creds["api_token"]) == "" {
			return nil, fmt.Errorf("DNSPod 国际站账户缺少 Token ID / API Token")
		}
		return &dnspodIntlDNS{loginID: strings.TrimSpace(creds["login_id"]), apiToken: strings.TrimSpace(creds["api_token"])}, nil
	default:
		return nil, fmt.Errorf("不支持的 DNS 服务商：%s", provider)
	}
}

// normalizedHostName 规范化主机记录：去掉首尾点，空与根（@/""）统一返回 @。
func normalizedHostName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(strings.TrimSuffix(name, "."), ".")
	if name == "" || name == "@" || name == "root" {
		return "@"
	}
	return name
}

// TrimDNSHost 去除主机记录首尾空白与点，供跨服务商比较（外包导出）。
func TrimDNSHost(name string) string {
	return normalizedHostName(name)
}

// updateRecordValue 更新某域名下「主机记录 = rr 且类型 = rtype」的记录值为 value（DDNS 用）。
// 从 ListRecords 定位到记录后调用 UpdateRecord；返回更新到的记录 ID。
func updateRecordValue(ctx context.Context, m DNSRecordManager, domain, rr, rtype, value string) (string, error) {
	recs, err := m.ListRecords(ctx, domain)
	if err != nil {
		return "", err
	}
	rr = normalizedHostName(rr)
	for _, rec := range recs {
		if normalizedHostName(rec.Name) == rr && strings.EqualFold(rec.Type, rtype) {
			id := rec.ID
			if err := m.UpdateRecord(ctx, domain, id, rec.Name, rec.Type, value, rec.TTL); err != nil {
				return "", err
			}
			return id, nil
		}
	}
	return "", fmt.Errorf("未找到 %s 的 %s 类型记录（域名 %s）", rr, rtype, domain)
}

// ============= 阿里云通用记录管理（RPC 签名 HMAC-SHA1） =============

func (p *aliyunDNS) ListDomains(ctx context.Context) ([]DNSDomain, error) {
	body, err := p.request(ctx, map[string]string{"Action": "DescribeDomains", "PageSize": "100"})
	if err != nil {
		return nil, err
	}
	resp := struct {
		Domains struct {
			Domain []struct {
				DomainName string `json:"DomainName"`
				RecordCount int   `json:"RecordCount"`
			} `json:"Domain"`
		} `json:"Domains"`
	}{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("阿里云 DNS 解析域名列表失败: %v", err)
	}
	var out []DNSDomain
	for _, d := range resp.Domains.Domain {
		out = append(out, DNSDomain{Name: d.DomainName, RecordCnt: d.RecordCount})
	}
	return out, nil
}

func (p *aliyunDNS) ListRecords(ctx context.Context, domain string) ([]DNSRecord, error) {
	body, err := p.request(ctx, map[string]string{
		"Action": "DescribeDomainRecords", "DomainName": domain, "PageSize": "500",
	})
	if err != nil {
		return nil, err
	}
	resp := struct {
		DomainRecords struct {
			Record []struct {
				RecordId        string `json:"RecordId"`
				RR              string `json:"RR"`
				Type            string `json:"Type"`
				Value           string `json:"Value"`
				TTL             int    `json:"TTL"`
				Status          string `json:"Status"`
				UpdateTimestamp int64  `json:"UpdateTimestamp"`
			} `json:"Record"`
		} `json:"DomainRecords"`
	}{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("阿里云 DNS 解析记录列表失败: %v", err)
	}
	var out []DNSRecord
	for _, r := range resp.DomainRecords.Record {
		out = append(out, DNSRecord{ID: r.RecordId, Name: normalizedHostName(r.RR), Type: r.Type, Value: r.Value, TTL: r.TTL, Status: r.Status, Updated: unixTimeStr(r.UpdateTimestamp)})
	}
	return out, nil
}

func (p *aliyunDNS) AddRecord(ctx context.Context, domain, rr, rtype, value string, ttl int) (string, error) {
	if ttl <= 0 {
		ttl = 600
	}
	body, err := p.request(ctx, map[string]string{
		"Action": "AddDomainRecord", "DomainName": domain, "RR": rr, "Type": rtype, "Value": value, "TTL": itoa(ttl),
	})
	if err != nil {
		return "", err
	}
	var resp struct {
		RecordID string `json:"RecordId"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.RecordID == "" {
		return "", fmt.Errorf("阿里云 DNS 添加记录响应异常: %s", string(body))
	}
	return resp.RecordID, nil
}

func (p *aliyunDNS) UpdateRecord(ctx context.Context, domain, recordID, rr, rtype, value string, ttl int) error {
	if ttl <= 0 {
		ttl = 600
	}
	_, err := p.request(ctx, map[string]string{
		"Action": "UpdateDomainRecord", "RecordId": recordID, "RR": rr, "Type": rtype, "Value": value, "TTL": itoa(ttl),
	})
	return err
}

func (p *aliyunDNS) DeleteRecord(ctx context.Context, domain, recordID string) error {
	_, err := p.request(ctx, map[string]string{"Action": "DeleteDomainRecord", "RecordId": recordID})
	return err
}

// ============= 腾讯云 DNSPod 通用记录管理（TC3-HMAC-SHA256 签名） =============

func (p *tencentDNS) ListDomains(ctx context.Context) ([]DNSDomain, error) {
	body, err := p.request(ctx, "DescribeDomainList", map[string]interface{}{"Limit": 100, "Offset": 0})
	if err != nil {
		return nil, err
	}
	resp := struct {
		Response struct {
			DomainList []struct {
				Name        string `json:"Name"`
				Status      string `json:"Status"`
				RecordCount int    `json:"RecordCount"`
			} `json:"DomainList"`
		} `json:"Response"`
	}{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("腾讯云 DNSPod 解析域名列表失败: %v", err)
	}
	var out []DNSDomain
	for _, d := range resp.Response.DomainList {
		out = append(out, DNSDomain{Name: d.Name, RecordCnt: d.RecordCount})
	}
	return out, nil
}

func (p *tencentDNS) ListRecords(ctx context.Context, domain string) ([]DNSRecord, error) {
	body, err := p.request(ctx, "DescribeRecordList", map[string]interface{}{
		"Domain": domain, "Limit": 100, "Offset": 0,
	})
	if err != nil {
		return nil, err
	}
	resp := struct {
		Response struct {
			RecordList []struct {
				Id         int64  `json:"Id"`
				Name       string `json:"Name"`
				Type       string `json:"Type"`
				Value      string `json:"Value"`
				Line       string `json:"Line"`
				TTL        int    `json:"TTL"`
				Status     string `json:"Status"`
				UpdateTime int64  `json:"UpdateTime"`
			} `json:"RecordList"`
		} `json:"Response"`
	}{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("腾讯云 DNSPod 解析记录列表失败: %v", err)
	}
	var out []DNSRecord
	for _, r := range resp.Response.RecordList {
		ttl := r.TTL
		if ttl <= 0 {
			ttl = 600
		}
		out = append(out, DNSRecord{ID: fmt.Sprintf("%d", r.Id), Name: normalizedHostName(r.Name), Type: r.Type, Value: r.Value, TTL: ttl, Status: r.Status, Updated: unixTimeStr(r.UpdateTime)})
	}
	return out, nil
}

func (p *tencentDNS) AddRecord(ctx context.Context, domain, rr, rtype, value string, ttl int) (string, error) {
	if ttl <= 0 {
		ttl = 600
	}
	body, err := p.request(ctx, "CreateRecord", map[string]interface{}{
		"Domain": domain, "SubDomain": rr, "RecordType": rtype, "RecordLine": "默认", "Value": value, "TTL": ttl,
	})
	if err != nil {
		return "", err
	}
	resp := struct {
		Response struct {
			Record struct {
				Id int64 `json:"Id"`
			} `json:"Record"`
		} `json:"Response"`
	}{}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Response.Record.Id == 0 {
		return "", fmt.Errorf("腾讯云 DNSPod 添加记录响应异常: %s", string(body))
	}
	return fmt.Sprintf("%d", resp.Response.Record.Id), nil
}

func (p *tencentDNS) UpdateRecord(ctx context.Context, domain, recordID, rr, rtype, value string, ttl int) error {
	if ttl <= 0 {
		ttl = 600
	}
	_, err := p.request(ctx, "ModifyRecord", map[string]interface{}{
		"Domain": domain, "RecordId": recordID, "SubDomain": rr, "RecordType": rtype, "RecordLine": "默认", "Value": value, "TTL": ttl,
	})
	return err
}

func (p *tencentDNS) DeleteRecord(ctx context.Context, domain, recordID string) error {
	_, err := p.request(ctx, "DeleteRecord", map[string]interface{}{"Domain": domain, "RecordId": recordID})
	return err
}

// ============= 华为云 DNS 通用记录管理（SDK-HMAC-SHA256 签名） =============

func (p *huaweiDNS) ListDomains(ctx context.Context) ([]DNSDomain, error) {
	body, err := p.doJSON(ctx, http.MethodGet, "/v2/zones", "limit=100", nil)
	if err != nil {
		return nil, err
	}
	resp := struct {
		Zones []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Status  string `json:"status"`
			Records int    `json:"record_num"`
		} `json:"zones"`
	}{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("华为云 DNS 解析域名列表失败: %v", err)
	}
	var out []DNSDomain
	for _, z := range resp.Zones {
		out = append(out, DNSDomain{Name: strings.TrimSuffix(z.Name, "."), RecordCnt: z.Records})
	}
	return out, nil
}

// huaweiRR 华为云记录名 → 主机记录：www.example.com. → www；example.com. → @
func huaweiRR(recordName, domain string) string {
	n := strings.TrimSuffix(strings.TrimSuffix(recordName, "."), ".")
	n = strings.TrimSuffix(n, "."+strings.TrimSuffix(domain, "."))
	return normalizedHostName(n)
}

func (p *huaweiDNS) ListRecords(ctx context.Context, domain string) ([]DNSRecord, error) {
	zoneID, err := p.zoneIDFor(ctx, domain)
	if err != nil {
		return nil, err
	}
	body, err := p.doJSON(ctx, http.MethodGet, "/v2/zones/"+zoneID+"/recordsets", "limit=500", nil)
	if err != nil {
		return nil, err
	}
	resp := struct {
		Recordsets []struct {
			ID        string   `json:"id"`
			Name      string   `json:"name"`
			Type      string   `json:"type"`
			TTL       int      `json:"ttl"`
			Records   []string `json:"records"`
			Status    string   `json:"status"`
			UpdatedAt string   `json:"updated_at"`
		} `json:"recordsets"`
	}{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("华为云 DNS 解析记录列表失败: %v", err)
	}
	var out []DNSRecord
	for _, r := range resp.Recordsets {
		val := ""
		if len(r.Records) > 0 {
			val = strings.Trim(r.Records[0], `"`)
		}
		out = append(out, DNSRecord{ID: r.ID, Name: huaweiRR(r.Name, domain), Type: r.Type, Value: val, TTL: r.TTL, Status: r.Status, Updated: dateTimeStr(r.UpdatedAt)})
	}
	return out, nil
}

func (p *huaweiDNS) AddRecord(ctx context.Context, domain, rr, rtype, value string, ttl int) (string, error) {
	if ttl <= 0 {
		ttl = 600
	}
	zoneID, err := p.zoneIDFor(ctx, domain)
	if err != nil {
		return "", err
	}
	name := fullRecordName(domain, rr)
	body, err := p.doJSON(ctx, http.MethodPost, "/v2/zones/"+zoneID+"/recordsets", "", map[string]interface{}{
		"name": name + ".", "type": rtype, "ttl": ttl, "records": []string{value},
	})
	if err != nil {
		return "", err
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.ID == "" {
		return "", fmt.Errorf("华为云 DNS 添加记录响应异常: %s", string(body))
	}
	return resp.ID, nil
}

func (p *huaweiDNS) UpdateRecord(ctx context.Context, domain, recordID, rr, rtype, value string, ttl int) error {
	if ttl <= 0 {
		ttl = 600
	}
	zoneID, err := p.zoneIDFor(ctx, domain)
	if err != nil {
		return err
	}
	body, err := p.doJSON(ctx, http.MethodPut, "/v2/zones/"+zoneID+"/recordsets/"+recordID, "", map[string]interface{}{
		"name": fullRecordName(domain, rr) + ".", "type": rtype, "ttl": ttl, "records": []string{value},
	})
	if err != nil {
		return err
	}
	// PUT 返回空体 + 204 属正常
	if len(body) == 0 {
		return nil
	}
	return nil
}

func (p *huaweiDNS) DeleteRecord(ctx context.Context, domain, recordID string) error {
	zoneID, err := p.zoneIDFor(ctx, domain)
	if err != nil {
		return err
	}
	_, err = p.doJSON(ctx, http.MethodDelete, "/v2/zones/"+zoneID+"/recordsets/"+recordID, "", nil)
	return err
}

// ============= Cloudflare 通用记录管理（REST API，Bearer Token） =============

func (p *cloudflareDNS) ListDomains(ctx context.Context) ([]DNSDomain, error) {
	body, status, err := p.doJSON(ctx, http.MethodGet, "/zones?per_page=100", nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("cloudflare 列域名失败 (HTTP %d): %s", status, string(body))
	}
	resp := struct {
		Success bool `json:"success"`
		Result  []struct {
			Name string `json:"name"`
		} `json:"result"`
	}{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	var out []DNSDomain
	for _, z := range resp.Result {
		out = append(out, DNSDomain{Name: z.Name})
	}
	return out, nil
}

func (p *cloudflareDNS) ListRecords(ctx context.Context, domain string) ([]DNSRecord, error) {
	zoneID, err := p.zoneIDFor(ctx, domain)
	if err != nil {
		return nil, err
	}
	body, status, err := p.doJSON(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?per_page=500", nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("cloudflare 列记录失败 (HTTP %d): %s", status, string(body))
	}
	resp := struct {
		Success bool `json:"success"`
		Result  []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Type       string `json:"type"`
			Content    string `json:"content"`
			TTL        int    `json:"ttl"`
			ModifiedOn string `json:"modified_on"`
		} `json:"result"`
	}{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	var out []DNSRecord
	for _, r := range resp.Result {
		out = append(out, DNSRecord{ID: r.ID, Name: normalizedHostName(strings.TrimSuffix(r.Name, "."+domain)), Type: r.Type, Value: r.Content, TTL: r.TTL, Status: "running", Updated: dateTimeStr(r.ModifiedOn)})
	}
	return out, nil
}

func (p *cloudflareDNS) AddRecord(ctx context.Context, domain, rr, rtype, value string, ttl int) (string, error) {
	if ttl <= 0 {
		ttl = 120
	}
	zoneID, err := p.zoneIDFor(ctx, domain)
	if err != nil {
		return "", err
	}
	body, status, err := p.doJSON(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", map[string]interface{}{
		"type": rtype, "name": fullRecordName(domain, rr), "content": value, "ttl": ttl,
	})
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("cloudflare 添加记录失败 (HTTP %d): %s", status, string(body))
	}
	resp := struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
	}{}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Result.ID == "" {
		return "", fmt.Errorf("cloudflare 添加记录响应异常: %s", string(body))
	}
	return resp.Result.ID, nil
}

func (p *cloudflareDNS) UpdateRecord(ctx context.Context, domain, recordID, rr, rtype, value string, ttl int) error {
	if ttl <= 0 {
		ttl = 120
	}
	zoneID, err := p.zoneIDFor(ctx, domain)
	if err != nil {
		return err
	}
	body, status, err := p.doJSON(ctx, http.MethodPut, "/zones/"+zoneID+"/dns_records/"+recordID, map[string]interface{}{
		"type": rtype, "name": fullRecordName(domain, rr), "content": value, "ttl": ttl,
	})
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("cloudflare 修改记录失败 (HTTP %d): %s", status, string(body))
	}
	return nil
}

func (p *cloudflareDNS) DeleteRecord(ctx context.Context, domain, recordID string) error {
	zoneID, err := p.zoneIDFor(ctx, domain)
	if err != nil {
		return err
	}
	body, status, err := p.doJSON(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+recordID, nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("cloudflare 删除记录失败 (HTTP %d): %s", status, string(body))
	}
	return nil
}

// fullRecordName 由「主机记录 + 注册域」拼接完整记录名（不含尾点）。
// rr 为 @ 时返回注册域本身。
func fullRecordName(domain, rr string) string {
	rr = strings.TrimSpace(rr)
	domain = strings.TrimSuffix(domain, ".")
	if rr == "" || rr == "@" {
		return domain
	}
	return rr + "." + domain
}

func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}

// unixTimeStr 把 Unix 秒/毫秒时间戳格式化为本地时间字符串；无效返回空。
func unixTimeStr(ts int64) string {
	if ts <= 0 {
		return ""
	}
	// 毫秒级（>1e12）转为秒
	if ts > 1e12 {
		ts /= 1000
	}
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
}

// dateTimeStr 把 ISO8601 / RFC3339 时间字符串格式化为本地时间，无效原样返回。
func dateTimeStr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Local().Format("2006-01-02 15:04:05")
		}
	}
	return s
}

// ============= GoDaddy（REST API，sso-key 鉴权） =============

const goDaddyEndpoint = "https://api.godaddy.com"

type goDaddyDNS struct {
	apiKey    string
	apiSecret string
	dns01     []string // 本次申请添加的 TXT 记录：domain|rr
}

func (p *goDaddyDNS) do(ctx context.Context, method, path string, payload any) ([]byte, error) {
	var rd io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, goDaddyEndpoint+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "sso-key "+p.apiKey+":"+p.apiSecret)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	body, status, err := httpDo(req)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("GoDaddy API 失败 (HTTP %d): %s", status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// goDaddyRecordPath 记录路径：name 使用相对主机记录（根记录为 @）。
func goDaddyRecordPath(domain, rtype, rr string) string {
	return "/v1/domains/" + url.PathEscape(domain) + "/records/" + url.PathEscape(strings.ToUpper(rtype)) + "/" + url.PathEscape(normalizedHostName(rr))
}

// putGoDaddyRecord 以 PUT 覆盖「指定类型 + 主机记录」的全部记录（GoDaddy 官方语义）。
func (p *goDaddyDNS) putGoDaddyRecord(ctx context.Context, domain, rtype, rr, value string, ttl int) error {
	if ttl < 600 {
		ttl = 600
	}
	_, err := p.do(ctx, http.MethodPut, goDaddyRecordPath(domain, rtype, rr), []map[string]any{{"data": value, "ttl": ttl}})
	return err
}

func (p *goDaddyDNS) ListDomains(ctx context.Context) ([]DNSDomain, error) {
	body, err := p.do(ctx, http.MethodGet, "/v1/domains?limit=1000&statuses=ACTIVE", nil)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("GoDaddy 域名列表解析失败: %w", err)
	}
	out := make([]DNSDomain, 0, len(rows))
	for _, r := range rows {
		out = append(out, DNSDomain{Name: r.Domain})
	}
	return out, nil
}

func (p *goDaddyDNS) ListRecords(ctx context.Context, domain string) ([]DNSRecord, error) {
	body, err := p.do(ctx, http.MethodGet, "/v1/domains/"+url.PathEscape(domain)+"/records?limit=500", nil)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Type string `json:"type"`
		Name string `json:"name"`
		Data string `json:"data"`
		TTL  int    `json:"ttl"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("GoDaddy 记录列表解析失败: %w", err)
	}
	out := make([]DNSRecord, 0, len(rows))
	for _, r := range rows {
		name := normalizedHostName(r.Name)
		out = append(out, DNSRecord{
			ID:     strings.ToUpper(r.Type) + "/" + name,
			Name:   name,
			Type:   strings.ToUpper(r.Type),
			Value:  r.Data,
			TTL:    r.TTL,
			Status: "running",
		})
	}
	return out, nil
}

func (p *goDaddyDNS) AddRecord(ctx context.Context, domain, rr, rtype, value string, ttl int) (string, error) {
	if err := p.putGoDaddyRecord(ctx, domain, rtype, rr, value, ttl); err != nil {
		return "", err
	}
	return strings.ToUpper(rtype) + "/" + normalizedHostName(rr), nil
}

func (p *goDaddyDNS) UpdateRecord(ctx context.Context, domain, recordID, rr, rtype, value string, ttl int) error {
	oldType, oldName, ok := strings.Cut(recordID, "/")
	if !ok {
		oldType, oldName = rtype, rr
	}
	// 类型或主机记录变化时，先删除旧记录再写入新记录（PUT 只覆盖同类型同名记录）
	if !strings.EqualFold(oldType, rtype) || !strings.EqualFold(normalizedHostName(oldName), normalizedHostName(rr)) {
		if _, err := p.do(ctx, http.MethodDelete, goDaddyRecordPath(domain, oldType, oldName), nil); err != nil {
			return err
		}
	}
	return p.putGoDaddyRecord(ctx, domain, rtype, rr, value, ttl)
}

func (p *goDaddyDNS) DeleteRecord(ctx context.Context, domain, recordID string) error {
	rtype, rr, ok := strings.Cut(recordID, "/")
	if !ok {
		return fmt.Errorf("GoDaddy 记录 ID 格式异常: %s", recordID)
	}
	_, err := p.do(ctx, http.MethodDelete, goDaddyRecordPath(domain, rtype, rr), nil)
	return err
}

func (p *goDaddyDNS) AddTXTRecord(ctx context.Context, recordName, value string) error {
	base := strings.TrimPrefix(recordName, acmeChallengePrefix)
	domain, sub := splitDNSBase(base)
	rr := acmeRR(sub)
	if err := p.putGoDaddyRecord(ctx, domain, "TXT", rr, value, 600); err != nil {
		return err
	}
	p.dns01 = append(p.dns01, domain+"|"+rr)
	return nil
}

func (p *goDaddyDNS) RemoveTXTRecord(ctx context.Context) error {
	var lastErr error
	for _, it := range p.dns01 {
		domain, rr, ok := strings.Cut(it, "|")
		if !ok {
			continue
		}
		if _, err := p.do(ctx, http.MethodDelete, goDaddyRecordPath(domain, "TXT", rr), nil); err != nil {
			lastErr = err
		}
	}
	p.dns01 = nil
	return lastErr
}

// ============= Vercel（REST API，Bearer Token 鉴权） =============

const vercelEndpoint = "https://api.vercel.com"

type vercelDNS struct {
	apiToken string
	dns01    []string // 本次申请添加的 TXT 记录：domain|recordID
}

func (p *vercelDNS) do(ctx context.Context, method, path string, payload any) ([]byte, error) {
	var rd io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, vercelEndpoint+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	body, status, err := httpDo(req)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("Vercel API 失败 (HTTP %d): %s", status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (p *vercelDNS) ListDomains(ctx context.Context) ([]DNSDomain, error) {
	var out []DNSDomain
	until := ""
	for {
		path := "/v5/domains?limit=100"
		if until != "" {
			path += "&until=" + url.QueryEscape(until)
		}
		body, err := p.do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Domains []struct {
				Name string `json:"name"`
			} `json:"domains"`
			Pagination struct {
				Next *int64 `json:"next"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("Vercel 域名列表解析失败: %w", err)
		}
		for _, d := range resp.Domains {
			out = append(out, DNSDomain{Name: d.Name})
		}
		if resp.Pagination.Next == nil || len(resp.Domains) < 100 {
			break
		}
		until = strconv.FormatInt(*resp.Pagination.Next, 10)
	}
	return out, nil
}

type vercelRecord struct {
	ID    string `json:"id"`
	UID   string `json:"uid"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// vercelRecordName 主机记录转 Vercel 名称：根记录用空字符串。
func vercelRecordName(rr string) string {
	if n := normalizedHostName(rr); n != "@" {
		return n
	}
	return ""
}

func (p *vercelDNS) ListRecords(ctx context.Context, domain string) ([]DNSRecord, error) {
	body, err := p.do(ctx, http.MethodGet, "/v4/domains/"+url.PathEscape(domain)+"/records?limit=100", nil)
	if err != nil {
		return nil, err
	}
	var rows []vercelRecord
	if err := json.Unmarshal(body, &rows); err != nil {
		var wrap struct {
			Records []vercelRecord `json:"records"`
		}
		if err2 := json.Unmarshal(body, &wrap); err2 != nil {
			return nil, fmt.Errorf("Vercel 记录列表解析失败: %w", err)
		}
		rows = wrap.Records
	}
	out := make([]DNSRecord, 0, len(rows))
	for _, r := range rows {
		id := r.ID
		if id == "" {
			id = r.UID
		}
		out = append(out, DNSRecord{
			ID:     id,
			Name:   normalizedHostName(r.Name),
			Type:   strings.ToUpper(r.Type),
			Value:  r.Value,
			TTL:    r.TTL,
			Status: "running",
		})
	}
	return out, nil
}

func (p *vercelDNS) AddRecord(ctx context.Context, domain, rr, rtype, value string, ttl int) (string, error) {
	if ttl <= 0 {
		ttl = 60
	}
	body, err := p.do(ctx, http.MethodPost, "/v2/domains/"+url.PathEscape(domain)+"/records", map[string]any{
		"name": vercelRecordName(rr), "type": strings.ToUpper(rtype), "value": value, "ttl": ttl,
	})
	if err != nil {
		return "", err
	}
	var resp vercelRecord
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("Vercel 添加记录响应解析失败: %w", err)
	}
	if resp.ID == "" {
		resp.ID = resp.UID
	}
	return resp.ID, nil
}

func (p *vercelDNS) UpdateRecord(ctx context.Context, domain, recordID, rr, rtype, value string, ttl int) error {
	if ttl <= 0 {
		ttl = 60
	}
	_, err := p.do(ctx, http.MethodPatch, "/v1/domains/records/"+url.PathEscape(recordID), map[string]any{
		"name": vercelRecordName(rr), "type": strings.ToUpper(rtype), "value": value, "ttl": ttl,
	})
	return err
}

func (p *vercelDNS) DeleteRecord(ctx context.Context, domain, recordID string) error {
	_, err := p.do(ctx, http.MethodDelete, "/v2/domains/"+url.PathEscape(domain)+"/records/"+url.PathEscape(recordID), nil)
	return err
}

func (p *vercelDNS) AddTXTRecord(ctx context.Context, recordName, value string) error {
	base := strings.TrimPrefix(recordName, acmeChallengePrefix)
	domain, sub := splitDNSBase(base)
	id, err := p.AddRecord(ctx, domain, acmeRR(sub), "TXT", value, 60)
	if err != nil {
		return err
	}
	p.dns01 = append(p.dns01, domain+"|"+id)
	return nil
}

func (p *vercelDNS) RemoveTXTRecord(ctx context.Context) error {
	var lastErr error
	for _, it := range p.dns01 {
		domain, id, ok := strings.Cut(it, "|")
		if !ok {
			continue
		}
		if err := p.DeleteRecord(ctx, domain, id); err != nil {
			lastErr = err
		}
	}
	p.dns01 = nil
	return lastErr
}

// ============= DNSPod 国际站（api.dnspod.com，login_token 鉴权） =============

const dnspodIntlEndpoint = "https://api.dnspod.com"

type dnspodIntlDNS struct {
	loginID  string
	apiToken string
	dns01    []dnspodIntlRecord
}

type dnspodIntlRecord struct {
	domain string
	id     string
}

// anyString 把 JSON 中可能是字符串或数字的字段统一为字符串。
func anyString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case json.Number:
		return t.String()
	}
	return ""
}

func (p *dnspodIntlDNS) do(ctx context.Context, action string, params map[string]string) ([]byte, error) {
	form := url.Values{}
	form.Set("login_token", p.loginID+","+p.apiToken)
	form.Set("format", "json")
	for k, v := range params {
		form.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dnspodIntlEndpoint+"/"+action, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	body, status, err := httpDo(req)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("DNSPod 国际站 API 失败 (HTTP %d): %s", status, strings.TrimSpace(string(body)))
	}
	var resp struct {
		Status struct {
			Code    any    `json:"code"`
			Message string `json:"message"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("DNSPod 国际站响应解析失败: %w", err)
	}
	if code := anyString(resp.Status.Code); code != "" && code != "1" {
		return nil, fmt.Errorf("DNSPod 国际站 API 错误 %s: %s", code, resp.Status.Message)
	}
	return body, nil
}

func (p *dnspodIntlDNS) domainIDFor(ctx context.Context, domain string) (string, error) {
	body, err := p.do(ctx, "Domain.Info", map[string]string{"domain": domain})
	if err != nil {
		return "", err
	}
	var resp struct {
		Domain struct {
			ID any `json:"id"`
		} `json:"domain"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("DNSPod 国际站域名信息解析失败: %w", err)
	}
	id := anyString(resp.Domain.ID)
	if id == "" {
		return "", fmt.Errorf("DNSPod 国际站未返回域名 ID: %s", domain)
	}
	return id, nil
}

func (p *dnspodIntlDNS) ListDomains(ctx context.Context) ([]DNSDomain, error) {
	var out []DNSDomain
	for offset := 0; ; offset += 500 {
		body, err := p.do(ctx, "Domain.List", map[string]string{"type": "all", "offset": strconv.Itoa(offset), "length": "500"})
		if err != nil {
			return nil, err
		}
		var resp struct {
			Domains []struct {
				Name    string `json:"name"`
				Records string `json:"records"`
			} `json:"domains"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("DNSPod 国际站域名列表解析失败: %w", err)
		}
		for _, d := range resp.Domains {
			n, _ := strconv.Atoi(d.Records)
			out = append(out, DNSDomain{Name: d.Name, RecordCnt: n})
		}
		if len(resp.Domains) < 500 {
			break
		}
	}
	return out, nil
}

func (p *dnspodIntlDNS) ListRecords(ctx context.Context, domain string) ([]DNSRecord, error) {
	domainID, err := p.domainIDFor(ctx, domain)
	if err != nil {
		return nil, err
	}
	body, err := p.do(ctx, "Record.List", map[string]string{"domain_id": domainID, "offset": "0", "length": "500"})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Records []struct {
			ID        any    `json:"id"`
			Name      string `json:"name"`
			Type      string `json:"type"`
			Value     string `json:"value"`
			TTL       any    `json:"ttl"`
			Status    string `json:"status"`
			UpdatedOn string `json:"updated_on"`
		} `json:"records"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("DNSPod 国际站记录列表解析失败: %w", err)
	}
	out := make([]DNSRecord, 0, len(resp.Records))
	for _, r := range resp.Records {
		ttl, _ := strconv.Atoi(anyString(r.TTL))
		out = append(out, DNSRecord{
			ID:      anyString(r.ID),
			Name:    normalizedHostName(r.Name),
			Type:    strings.ToUpper(r.Type),
			Value:   r.Value,
			TTL:     ttl,
			Status:  r.Status,
			Updated: dateTimeStr(r.UpdatedOn),
		})
	}
	return out, nil
}

func (p *dnspodIntlDNS) AddRecord(ctx context.Context, domain, rr, rtype, value string, ttl int) (string, error) {
	domainID, err := p.domainIDFor(ctx, domain)
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = 600
	}
	body, err := p.do(ctx, "Record.Create", map[string]string{
		"domain_id":   domainID,
		"sub_domain":  normalizedHostName(rr),
		"record_type": strings.ToUpper(rtype),
		"record_line": "default",
		"value":       value,
		"ttl":         strconv.Itoa(ttl),
	})
	if err != nil {
		return "", err
	}
	var resp struct {
		Record struct {
			ID any `json:"id"`
		} `json:"record"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("DNSPod 国际站添加记录响应解析失败: %w", err)
	}
	id := anyString(resp.Record.ID)
	if id == "" {
		return "", fmt.Errorf("DNSPod 国际站未返回记录 ID: %s", string(body))
	}
	return id, nil
}

func (p *dnspodIntlDNS) UpdateRecord(ctx context.Context, domain, recordID, rr, rtype, value string, ttl int) error {
	domainID, err := p.domainIDFor(ctx, domain)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = 600
	}
	_, err = p.do(ctx, "Record.Modify", map[string]string{
		"domain_id":   domainID,
		"record_id":   recordID,
		"sub_domain":  normalizedHostName(rr),
		"record_type": strings.ToUpper(rtype),
		"record_line": "default",
		"value":       value,
		"ttl":         strconv.Itoa(ttl),
	})
	return err
}

func (p *dnspodIntlDNS) DeleteRecord(ctx context.Context, domain, recordID string) error {
	domainID, err := p.domainIDFor(ctx, domain)
	if err != nil {
		return err
	}
	_, err = p.do(ctx, "Record.Remove", map[string]string{"domain_id": domainID, "record_id": recordID})
	return err
}

func (p *dnspodIntlDNS) AddTXTRecord(ctx context.Context, recordName, value string) error {
	base := strings.TrimPrefix(recordName, acmeChallengePrefix)
	domain, sub := splitDNSBase(base)
	id, err := p.AddRecord(ctx, domain, acmeRR(sub), "TXT", value, 600)
	if err != nil {
		return err
	}
	p.dns01 = append(p.dns01, dnspodIntlRecord{domain: domain, id: id})
	return nil
}

func (p *dnspodIntlDNS) RemoveTXTRecord(ctx context.Context) error {
	var lastErr error
	for _, r := range p.dns01 {
		if err := p.DeleteRecord(ctx, r.domain, r.id); err != nil {
			lastErr = err
		}
	}
	p.dns01 = nil
	return lastErr
}
