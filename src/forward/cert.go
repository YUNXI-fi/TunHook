package forward

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"tunhook/store"
)

// generateSelfSignedCert 为 HTTPS 转发生成自签名证书（ECDSA P-256，有效期 10 年）。
// 证书 SAN 包含规则域名；若为通配域名（*.example.com）则同时包含基础域名（example.com）。
// 返回 PEM 格式的证书与私钥。用户未提供证书时调用，保证开箱即用。
func generateSelfSignedCert(domain string) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("生成私钥失败: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", fmt.Errorf("生成证书序号失败: %w", err)
	}
	dnsNames := []string{domain}
	// 通配域名附带基础域名，保证 example.com 也能访问
	if strings.HasPrefix(domain, "*.") {
		dnsNames = append(dnsNames, strings.TrimPrefix(domain, "*."))
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: strings.TrimPrefix(domain, "*.")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("生成证书失败: %w", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("序列化私钥失败: %w", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, nil
}

// loadTLSCert 加载用户提供的 PEM 证书与私钥，解析为 tls.Certificate。
// certPEM 或 keyPEM 为空时自动生成自签名证书并返回（生成的证书同时回写到 certPEM/keyPEM）。
func loadTLSCert(domain, certPEM, keyPEM string) (cert *tls.Certificate, outCert, outKey string, err error) {
	if strings.TrimSpace(certPEM) == "" || strings.TrimSpace(keyPEM) == "" {
		genCert, genKey, gerr := generateSelfSignedCert(domain)
		if gerr != nil {
			return nil, "", "", gerr
		}
		certPEM, keyPEM = genCert, genKey
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, "", "", fmt.Errorf("证书解析失败（需 PEM 格式证书+私钥）: %w", err)
	}
	return &pair, certPEM, keyPEM, nil
}

// localIPs 返回本机所有非回环网卡的 IP 地址（IPv4/IPv6）。
func localIPs() []net.IP {
	var ips []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && !ip.IsLoopback() {
			ips = append(ips, ip)
		}
	}
	return ips
}

// generateSelfSignedCertForListener 为「TCP + HTTPS 开关」生成自签名证书（ECDSA P-256，有效期 10 年）。
// SAN 同时包含：本机所有网卡 IP、127.0.0.1、localhost，以及目标主机（IP 走 IPAddresses，域名走 DNSNames），
// 保证通过本机或局域网 IP 访问 https://<ip>:<port> 时证书与地址匹配。
// 自签名的信任问题由用户在浏览器安装证书或放行解决（参考内网自签名证书使用流程）。
func generateSelfSignedCertForListener(targetHost string) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("生成私钥失败: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", fmt.Errorf("生成证书序号失败: %w", err)
	}

	dnsNames := []string{"localhost"}
	ipAddrs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	ipAddrs = append(ipAddrs, localIPs()...)
	if host := strings.TrimSpace(targetHost); host != "" {
		if ip := net.ParseIP(host); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "TunHook 自签名证书"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("生成证书失败: %w", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("序列化私钥失败: %w", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, nil
}

// loadTLSCertForListener 加载 TCP+HTTPS 监听所需的 PEM 证书与私钥。
// 证书为空时自动生成自签名证书（SAN 含本机 IP 与目标主机），生成的证书同时回写到 outCert/outKey。
func loadTLSCertForListener(targetHost, certPEM, keyPEM string) (cert *tls.Certificate, outCert, outKey string, err error) {
	if strings.TrimSpace(certPEM) == "" || strings.TrimSpace(keyPEM) == "" {
		genCert, genKey, gerr := generateSelfSignedCertForListener(targetHost)
		if gerr != nil {
			return nil, "", "", gerr
		}
		certPEM, keyPEM = genCert, genKey
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, "", "", fmt.Errorf("证书解析失败（需 PEM 格式证书+私钥）: %w", err)
	}
	return &pair, certPEM, keyPEM, nil
}

// parseX509Cert 解析 PEM 格式证书（支持多证书链，取第一张）。
func parseX509Cert(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("无效的 PEM 证书内容")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("证书解析失败: %w", err)
	}
	return cert, nil
}

// ParseCertInfo 解析 PEM 证书信息：SAN 域名列表、生效/到期时间、发证机构。
func ParseCertInfo(certPEM string) (domains []string, notBefore, notAfter time.Time, issuer string, err error) {
	cert, err := parseX509Cert(certPEM)
	if err != nil {
		return nil, time.Time{}, time.Time{}, "", err
	}
	domains = cert.DNSNames
	if len(domains) == 0 && cert.Subject.CommonName != "" {
		domains = []string{cert.Subject.CommonName}
	}
	issuer = issuerName(cert)
	return domains, cert.NotBefore, cert.NotAfter, issuer, nil
}

// issuerName 提取发证机构可读名称（Let's Encrypt / 自定义 CA 等）。
func issuerName(cert *x509.Certificate) string {
	for _, org := range cert.Issuer.Organization {
		if strings.Contains(org, "Let's Encrypt") {
			return "Let's Encrypt"
		}
	}
	if strings.Contains(cert.Issuer.CommonName, "Let's Encrypt") {
		return "Let's Encrypt"
	}
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}
	if len(cert.Issuer.Organization) > 0 {
		return cert.Issuer.Organization[0]
	}
	return "自定义CA"
}

// FormatDate 格式化日期为 YYYY-MM-DD。
func FormatDate(t time.Time) string {
	return t.Format("2006-01-02")
}

// FormatDateTime 格式化时间为 YYYY-MM-DD HH:MM:SS。
func FormatDateTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

// isWildcardDomain 判断域名是否为通配域名（*.example.com）。
func isWildcardDomain(domain string) bool {
	return strings.HasPrefix(strings.TrimSpace(domain), "*.")
}

// FindCertificateForDomain 从证书库查找匹配指定域名的证书：
// 1) 精确匹配；2) 通配匹配（*.example.com 可匹配任意具体子域名，逐级尝试）。
// 未找到时返回 nil。
func FindCertificateForDomain(st *store.Store, domain string) (*store.CertRecord, error) {
	if st == nil {
		return nil, nil
	}
	domain = strings.TrimSpace(domain)
	if rec, err := st.GetCertificate(domain); err == nil {
		return &rec, nil
	}
	// 通配匹配：从最左标签开始逐级剥除，尝试 "*.剩余部分"
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		wild := "*." + strings.Join(parts[i:], ".")
		if rec, err := st.GetCertificate(wild); err == nil {
			return &rec, nil
		}
	}
	return nil, nil
}

// ============= ACME HTTP-01 挑战注册表 =============
// Let's Encrypt 验证时通过公网访问 http://域名/.well-known/acme-challenge/{token}，
// 该请求经系统已有的 HTTP/HTTPS 转发规则到达本机，由 httpProxy 查询本注册表直接响应，
// 无需在本机监听 80 端口（内网穿透场景下 80 端口通常不可达）。

var (
	acmeChallengesMu sync.RWMutex
	acmeChallenges   = make(map[string]string) // token -> keyAuth
)

// RegisterACMEChallenge 注册 HTTP-01 挑战响应（申请期间有效）。
func RegisterACMEChallenge(token, keyAuth string) {
	acmeChallengesMu.Lock()
	acmeChallenges[token] = keyAuth
	acmeChallengesMu.Unlock()
}

// UnregisterACMEChallenge 移除挑战响应（申请结束清理）。
func UnregisterACMEChallenge(token string) {
	acmeChallengesMu.Lock()
	delete(acmeChallenges, token)
	acmeChallengesMu.Unlock()
}

// LookupACMEChallenge 查询挑战响应；未注册时返回 ok=false。
func LookupACMEChallenge(token string) (string, bool) {
	acmeChallengesMu.RLock()
	defer acmeChallengesMu.RUnlock()
	ka, ok := acmeChallenges[token]
	return ka, ok
}
