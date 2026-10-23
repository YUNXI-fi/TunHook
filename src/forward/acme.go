package forward

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"tunhook/store"

	"go.uber.org/zap"
)

// letsEncryptDir 生产环境 ACME 目录。
const letsEncryptDir = "https://acme-v02.api.letsencrypt.org/directory"

// zeroSSLDir ZeroSSL 生产环境 ACME 目录（需 EAB 凭据）。
const zeroSSLDir = "https://acme.zerossl.com/v2/DV90"

// CertApplyOptions 一次证书申请/续签的完整参数。
type CertApplyOptions struct {
	Domain      string
	Email       string
	DNSProvider string
	DNSCreds    map[string]string
	DNSAccount  string // DNS 账户名称（写入证书记录，续签时复用）
	CAType      string // 证书颁发机构：Let's Encrypt / ZeroSSL
	KeyAlg      string // 密钥类型：EC 256 / EC 384 / RSA 2048 / RSA 3072 / RSA 4096
	EABKID      string // ZeroSSL EAB KID
	EABHMAC     string // ZeroSSL EAB HMAC Key（Base64）
	Renewal     bool   // 是否由自动续签触发（仅用于提示文案）
}

// normalizedCAType 规范化 CA 名称，空值默认 Let's Encrypt。
func normalizedCAType(ca string) string {
	if strings.EqualFold(strings.TrimSpace(ca), "ZeroSSL") {
		return "ZeroSSL"
	}
	return "Let's Encrypt"
}

// acmeDirectory 按 CA 返回 ACME 目录地址。
func acmeDirectory(ca string) string {
	if normalizedCAType(ca) == "ZeroSSL" {
		return zeroSSLDir
	}
	return letsEncryptDir
}

// CertApplyStatus 证书申请任务状态（前端轮询用）。
type CertApplyStatus struct {
	State     string            `json:"state"` // running / done / error
	Step      int               `json:"step"`  // 申请步骤：1 提交申请 / 2 申请授权 / 3 等待验证 / 4 签发证书 / 5 完成
	Message   string            `json:"message"`
	Domain    string            `json:"domain,omitempty"`
	Email     string            `json:"email,omitempty"`
	CAType    string            `json:"ca_type,omitempty"`
	KeyAlg    string            `json:"key_alg,omitempty"`
	Renewal   bool              `json:"renewal,omitempty"`
	CreatedAt string            `json:"created_at,omitempty"`
	Cert      *store.CertRecord `json:"cert,omitempty"`
}

// CertApplier 管理 Let's Encrypt 证书申请任务（HTTP-01 挑战，异步执行）。
type CertApplier struct {
	mu       sync.Mutex
	tasks    map[string]*CertApplyStatus
	store    *store.Store
	logger   *zap.Logger
	onFinish func(taskID string) // 任务到达终态（done/error）时回调（异步调用）
}

func NewCertApplier(st *store.Store, logger *zap.Logger) *CertApplier {
	return &CertApplier{tasks: make(map[string]*CertApplyStatus), store: st, logger: logger}
}

// StartApply 启动证书申请任务，返回任务 ID。校验通过后立即返回（异步执行）。
// opts.DNSProvider 非空时走 DNS-01 验证（通过所选 DNS 服务商自动添加 TXT 记录），否则走 HTTP-01。
func (a *CertApplier) StartApply(opts CertApplyOptions) (string, error) {
	domain := strings.TrimSpace(strings.ToLower(opts.Domain))
	email := strings.TrimSpace(opts.Email)
	if domain == "" {
		return "", fmt.Errorf("域名不能为空")
	}
	if isWildcardDomain(domain) {
		if opts.DNSProvider == "" {
			return "", fmt.Errorf("通配域名（*.example.com）必须使用 DNS-01 验证，请选择 DNS 账户")
		}
		if !ValidDomain(strings.TrimPrefix(domain, "*.")) {
			return "", fmt.Errorf("域名格式非法: %s", domain)
		}
	} else if !ValidDomain(domain) {
		return "", fmt.Errorf("域名格式非法: %s", domain)
	}
	if opts.DNSProvider == "" && !strings.Contains(email, "@") {
		return "", fmt.Errorf("请填写有效的联系人邮箱地址")
	}
	caType := normalizedCAType(opts.CAType)
	if caType == "ZeroSSL" {
		if strings.TrimSpace(opts.EABKID) == "" || strings.TrimSpace(opts.EABHMAC) == "" {
			return "", fmt.Errorf("ZeroSSL 需要填写 EAB KID 与 EAB HMAC Key")
		}
		if _, err := decodeEABKey(opts.EABHMAC); err != nil {
			return "", err
		}
	}
	keyAlg := normalizeKeyAlg(opts.KeyAlg)
	opts.Domain, opts.Email, opts.CAType, opts.KeyAlg = domain, email, caType, keyAlg

	taskID := generateUUID()
	a.mu.Lock()
	// 防止任务无限累积：清理已完成任务
	if len(a.tasks) > 100 {
		for k, v := range a.tasks {
			if v.State != "running" {
				delete(a.tasks, k)
			}
		}
	}
	msg := "正在向 " + caType + " 提交申请..."
	if opts.Renewal {
		msg = "证书即将到期，正在向 " + caType + " 自动续签..."
	}
	a.tasks[taskID] = &CertApplyStatus{
		State:     "running",
		Step:      1,
		Message:   msg,
		Domain:    domain,
		Email:     email,
		CAType:    caType,
		KeyAlg:    keyAlg,
		Renewal:   opts.Renewal,
		CreatedAt: FormatDateTime(time.Now()),
	}
	a.mu.Unlock()

	go a.runApply(taskID, opts)
	return taskID, nil
}

// IsApplying 判断某域名是否已有进行中的申请/续签任务（自动续签去重用）。
func (a *CertApplier) IsApplying(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, t := range a.tasks {
		if t.State == "running" && strings.ToLower(t.Domain) == domain {
			return true
		}
	}
	return false
}

// Status 查询任务状态；任务不存在时返回 ok=false。
func (a *CertApplier) Status(taskID string) (CertApplyStatus, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.tasks[taskID]
	if !ok {
		return CertApplyStatus{}, false
	}
	return *s, true
}

func (a *CertApplier) setState(taskID, state, msg string, step int, cert *store.CertRecord) {
	a.mu.Lock()
	n := &CertApplyStatus{State: state, Step: step, Message: msg, Cert: cert}
	if cur, ok := a.tasks[taskID]; ok {
		n.Domain = cur.Domain
		n.Email = cur.Email
		n.CAType = cur.CAType
		n.KeyAlg = cur.KeyAlg
		n.Renewal = cur.Renewal
		n.CreatedAt = cur.CreatedAt
	}
	a.tasks[taskID] = n
	cb := a.onFinish
	a.mu.Unlock()
	// 终态（done/error）时异步通知（如恢复证书申请期间的临时路由）
	if (state == "done" || state == "error") && cb != nil {
		go cb(taskID)
	}
}

// SetOnFinish 注册任务到达终态时的回调（done/error，异步调用）。
func (a *CertApplier) SetOnFinish(cb func(taskID string)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onFinish = cb
}

// Tasks 返回全部申请任务（最新的在前），供前端展示申请记录列表。
func (a *CertApplier) Tasks() []map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]map[string]interface{}, 0, len(a.tasks))
	for id, t := range a.tasks {
		out = append(out, map[string]interface{}{
			"task_id":    id,
			"domain":     t.Domain,
			"email":      t.Email,
			"ca_type":    t.CAType,
			"key_alg":    t.KeyAlg,
			"renewal":    t.Renewal,
			"state":      t.State,
			"step":       t.Step,
			"message":    t.Message,
			"created_at": t.CreatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["created_at"].(string) > out[j]["created_at"].(string)
	})
	return out
}

func (a *CertApplier) runApply(taskID string, opts CertApplyOptions) {
	domain := opts.Domain
	email := opts.Email
	dnsProvider := opts.DNSProvider
	dnsCreds := opts.DNSCreds
	caType := opts.CAType
	defer func() {
		if r := recover(); r != nil {
			a.setState(taskID, "error", fmt.Sprintf("申请异常: %v", r), 0, nil)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	acctKey, err := a.loadOrCreateAccountKey()
	if err != nil {
		a.setState(taskID, "error", err.Error(), 0, nil)
		return
	}

	client := &acme.Client{
		Key:          acctKey,
		DirectoryURL: acmeDirectory(caType),
		UserAgent:    "TunHook/0.6.6.172",
	}
	// 注册 ACME 账号（已存在则恢复；邮箱可为空，由 DNS-01 场景支持）
	acct := &acme.Account{}
	if email != "" {
		acct.Contact = []string{"mailto:" + email}
	}
	// ZeroSSL 等 CA 要求外部账户绑定（EAB），Let's Encrypt 不需要
	if caType == "ZeroSSL" {
		eabKey, err := decodeEABKey(opts.EABHMAC)
		if err != nil {
			a.setState(taskID, "error", err.Error(), 1, nil)
			return
		}
		acct.ExternalAccountBinding = &acme.ExternalAccountBinding{KID: strings.TrimSpace(opts.EABKID), Key: eabKey}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && err != acme.ErrAccountAlreadyExists {
		a.setState(taskID, "error", "ACME 账号注册失败: "+err.Error(), 1, nil)
		return
	}

	step2 := "正在向 " + caType + " 申请授权（HTTP-01 验证，通过系统 HTTP 转发链路响应，无需本机 80 端口）..."
	if dnsProvider != "" {
		step2 = "正在向 " + caType + " 申请授权（DNS-01 验证，通过 DNS 服务商自动添加 TXT 记录）..."
	}
	a.setState(taskID, "running", step2, 2, nil)
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		a.setState(taskID, "error", "申请授权失败: "+err.Error(), 2, nil)
		return
	}

	// 收集所有验证挑战（HTTP-01 或 DNS-01）
	var auths []*acme.Authorization
	challenges := make([]*acme.Challenge, 0, len(order.AuthzURLs))
	var dnsProv dns01Provider
	dnsAdded := false
	if dnsProvider != "" {
		prov, err := newDNS01Provider(dnsProvider, dnsCreds)
		if err != nil {
			a.setState(taskID, "error", err.Error(), 2, nil)
			return
		}
		dnsProv = prov
		// 申请结束后清理自动添加的 TXT 记录
		defer func() {
			ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel2()
			if err := dnsProv.RemoveTXTRecord(ctx2); err != nil {
				a.logger.Warn("清理 DNS-01 TXT 记录失败", zap.Error(err))
			}
		}()
	}
	chalType := "http-01"
	if dnsProvider != "" {
		chalType = "dns-01"
	}
	for _, u := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, u)
		if err != nil {
			a.setState(taskID, "error", "获取域名授权失败: "+err.Error(), 2, nil)
			return
		}
		var chal *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == chalType {
				chal = c
				break
			}
		}
		if chal == nil {
			if dnsProvider != "" {
				a.setState(taskID, "error", "获取 DNS-01 挑战失败（请确认域名已托管在所选 DNS 服务商）", 2, nil)
			} else {
				a.setState(taskID, "error", "获取 HTTP-01 挑战失败", 2, nil)
			}
			return
		}
		if dnsProvider != "" {
			// DNS-01：计算 TXT 记录值并调用服务商 API 添加记录
			value, err := client.DNS01ChallengeRecord(chal.Token)
			if err != nil {
				a.setState(taskID, "error", "生成 DNS-01 挑战响应失败: "+err.Error(), 2, nil)
				return
			}
			base := strings.TrimPrefix(domain, "*.")
			if err := dnsProv.AddTXTRecord(ctx, acmeChallengePrefix+base, value); err != nil {
				a.setState(taskID, "error", "添加 TXT 解析记录失败: "+err.Error(), 2, nil)
				return
			}
			dnsAdded = true
		} else {
			ka, err := client.HTTP01ChallengeResponse(chal.Token)
			if err != nil {
				a.setState(taskID, "error", "生成挑战响应失败: "+err.Error(), 2, nil)
				return
			}
			// 注册挑战响应：Let's Encrypt 通过公网访问 http://域名/.well-known/acme-challenge/{token}，
			// 该请求经系统已有 HTTP/HTTPS 转发规则到达本机并由转发器直接响应。
			RegisterACMEChallenge(chal.Token, ka)
			defer UnregisterACMEChallenge(chal.Token)
		}
		challenges = append(challenges, chal)
		auths = append(auths, auth)
	}

	// DNS-01：等待解析生效后再提交验证
	if dnsAdded {
		a.setState(taskID, "running", "TXT 解析记录已添加，等待 DNS 生效后提交验证...", 3, nil)
		time.Sleep(10 * time.Second)
	}

	// 接受所有挑战
	for _, chal := range challenges {
		if _, err := client.Accept(ctx, chal); err != nil {
			a.setState(taskID, "error", "接受验证挑战失败: "+err.Error(), 3, nil)
			return
		}
	}
	// 等待 CA 完成验证
	if dnsProvider != "" {
		a.setState(taskID, "running", "挑战已提交，等待 "+caType+" 完成 DNS-01 验证（自动添加的 TXT 记录将在申请结束后删除）...", 3, nil)
	} else {
		a.setState(taskID, "running", "挑战已提交，等待 "+caType+" 验证（请确保域名已通过 HTTP/HTTPS 转发规则可公网访问）...", 3, nil)
	}
	for _, auth := range auths {
		if _, err := client.WaitAuthorization(ctx, auth.URI); err != nil {
			msg := "域名验证失败（请确认该域名已有 HTTP/HTTPS 转发规则且公网可访问，域名解析指向转发服务）: " + err.Error()
			if dnsProvider != "" {
				msg = "域名验证失败（DNS-01，请确认所选 DNS 账户可管理该域名解析且 TXT 记录已生效）: " + err.Error()
			}
			a.setState(taskID, "error", msg, 3, nil)
			return
		}
	}

	a.setState(taskID, "running", "域名验证通过，正在签发证书...", 4, nil)
	// 生成独立的证书私钥（公钥算法按申请的密钥类型选择）
	certKey, err := generatePrivateKey(opts.KeyAlg)
	if err != nil {
		a.setState(taskID, "error", "生成证书私钥失败: "+err.Error(), 4, nil)
		return
	}
	// 授权全部通过后订单变为 ready/valid：刷新订单状态以获取 finalize/证书地址
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		a.setState(taskID, "error", "等待订单就绪失败: "+err.Error(), 4, nil)
		return
	}
	var der [][]byte
	switch order.Status {
	case acme.StatusReady:
		// 订单就绪：提交 CSR 完成 finalize 并取证书
		csrDER, err := createCertRequest(certKey, domain)
		if err != nil {
			a.setState(taskID, "error", "生成证书签名请求失败: "+err.Error(), 4, nil)
			return
		}
		der, _, err = client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
		if err != nil {
			a.setState(taskID, "error", "获取证书失败: "+err.Error(), 4, nil)
			return
		}
	case acme.StatusValid:
		der, err = client.FetchCert(ctx, order.CertURL, true)
		if err != nil {
			a.setState(taskID, "error", "获取证书失败: "+err.Error(), 4, nil)
			return
		}
	default:
		a.setState(taskID, "error", "订单状态异常: "+order.Status, 4, nil)
		return
	}
	certPEM := pemEncodeChain(der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		a.setState(taskID, "error", "序列化证书私钥失败: "+err.Error(), 4, nil)
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	_, notBefore, notAfter, issuer, err := ParseCertInfo(certPEM)
	if err != nil {
		a.setState(taskID, "error", "解析签发的证书失败: "+err.Error(), 4, nil)
		return
	}
	rec := store.CertRecord{
		Domain:     domain,
		Email:      email,
		Issuer:     issuer,
		CertPEM:    certPEM,
		KeyPEM:     string(keyPEM),
		NotBefore:  FormatDate(notBefore),
		NotAfter:   FormatDate(notAfter),
		CreatedAt:  FormatDateTime(time.Now()),
		CAType:     caType,
		KeyAlg:     opts.KeyAlg,
		DNSAccount: opts.DNSAccount,
		EABKID:     opts.EABKID,
		EABHMAC:    opts.EABHMAC,
	}
	if err := a.store.SaveCertificate(rec); err != nil {
		a.setState(taskID, "error", "保存证书失败: "+err.Error(), 4, nil)
		return
	}
	a.logger.Info("ACME 证书签发成功",
		zap.String("domain", domain),
		zap.String("ca", caType),
		zap.String("key_alg", opts.KeyAlg),
		zap.String("issuer", issuer),
		zap.String("not_after", rec.NotAfter),
	)
	doneMsg := "证书申请成功"
	if opts.Renewal {
		doneMsg = "证书自动续签成功"
	}
	a.setState(taskID, "done", doneMsg, 5, &rec)
}

// loadOrCreateAccountKey 加载持久化的 ACME 账号私钥，不存在时生成并保存。
func (a *CertApplier) loadOrCreateAccountKey() (*ecdsa.PrivateKey, error) {
	if v, err := a.store.GetSetting("acme:account-key"); err == nil && strings.TrimSpace(v) != "" {
		if block, _ := pem.Decode([]byte(v)); block != nil {
			if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return k, nil
			}
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if ek, ok := k.(*ecdsa.PrivateKey); ok {
					return ek, nil
				}
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 ACME 账号密钥失败: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("序列化 ACME 账号密钥失败: %w", err)
	}
	if err := a.store.SetSetting("acme:account-key", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))); err != nil {
		a.logger.Warn("保存 ACME 账号密钥失败", zap.Error(err))
	}
	return key, nil
}

// pemEncodeChain 将 DER 证书链编码为 PEM（多张证书拼接，供 Nginx/TLS 使用）。
func pemEncodeChain(der [][]byte) string {
	var b strings.Builder
	for _, d := range der {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}))
	}
	return b.String()
}

// createCertRequest 生成域名的证书签名请求（CSR），私钥按申请时选择的密钥类型生成。
func createCertRequest(key crypto.Signer, domain string) ([]byte, error) {
	template := &x509.CertificateRequest{
		DNSNames: []string{domain},
	}
	return x509.CreateCertificateRequest(rand.Reader, template, key)
}

// normalizeKeyAlg 规范化密钥类型；未知值回退 EC 256。
func normalizeKeyAlg(k string) string {
	switch strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(k), " ", "")) {
	case "EC384":
		return "EC 384"
	case "RSA2048":
		return "RSA 2048"
	case "RSA3072":
		return "RSA 3072"
	case "RSA4096":
		return "RSA 4096"
	default:
		return "EC 256"
	}
}

// generatePrivateKey 按密钥类型生成证书私钥。
func generatePrivateKey(keyAlg string) (crypto.Signer, error) {
	switch normalizeKeyAlg(keyAlg) {
	case "EC 384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "RSA 2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "RSA 3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "RSA 4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}

// decodeEABKey 解码 ZeroSSL 的 EAB HMAC Key（官网提供 Base64URL，兼容标准 Base64）。
func decodeEABKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("ZeroSSL EAB HMAC Key 不能为空")
	}
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("ZeroSSL EAB HMAC Key 不是合法的 Base64 字符串")
}

// ValidDomain 校验域名格式（字母/数字/连字符/点，至少包含一个点，不以点开头/结尾）。
func ValidDomain(d string) bool {
	d = strings.TrimSpace(d)
	if d == "" || strings.ContainsAny(d, " /\\*") {
		return false
	}
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, ch := range p {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
