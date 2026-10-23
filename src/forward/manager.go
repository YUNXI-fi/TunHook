package forward

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"tunhook/config"
	"tunhook/store"

	"go.uber.org/zap"
)

const uuidChars = "abcdefghijklmnopqrstuvwxyz0123456789"

// healthCheckInterval 目标端口可达性探测间隔。
const healthCheckInterval = 8 * time.Second

func generateUUID() string {
	b := make([]byte, 4)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(uuidChars))))
		if err != nil {
			b[i] = uuidChars[time.Now().UnixNano()%int64(len(uuidChars))]
		} else {
			b[i] = uuidChars[n.Int64()]
		}
	}
	return string(b)
}

type SavedRule struct {
	UUID        string `json:"uuid"`
	Key         string `json:"key"`
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	LocalPort   int    `json:"local_port"`
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  int    `json:"remote_port"`
	Domain      string `json:"domain,omitempty"`
	Description string `json:"description,omitempty"`
}

type Manager struct {
	rules     map[string]Forwarder
	mu        sync.Mutex
	logger    *zap.Logger
	store     *store.Store // 可为 nil（无持久化）
	ruleUUIDs map[string]string
	// rulePrefixes 记录每条转发规则的源路径前缀（gateway 模式），key 与 ruleUUIDs 一致
	rulePrefixes map[string]string
	// ruleRootPrefixes 记录每条转发规则的根相对路径前缀列表（gateway 模式）
	ruleRootPrefixes map[string]string
	// rulePathPrefixes 记录每条转发规则的后端路径前缀（gateway 模式）
	rulePathPrefixes map[string]string
	// ruleAutoDetect 记录每条转发规则是否开启自动检测路径（gateway 模式）
	ruleAutoDetect map[string]bool
	// ruleCustomCerts 记录每条 HTTPS 转发规则是否使用了用户上传的证书（false=自动生成自签名证书）
	ruleCustomCerts map[string]bool
	// ruleTLSSet 记录每条 TCP 转发规则是否开启了 HTTPS（自签名证书）监听
	ruleTLSSet map[string]bool

	// ruleAdvanced 记录每条转发规则的进阶/日志设置（访问限速/最大连接数/PROXY v2/
	// 源端TLS/UDP 会话参数/日志级别与条数），供列表接口回传（key 与 rules 一致）。
	ruleAdvanced map[string]*RuleAdvanced

	// 目标端口可达性缓存（后台 goroutine 周期性探测运行中的规则）。
	// 前端据此区分「转发中(绿)」与「转发失败/目标端口不通(红)」。
	healthMu   sync.RWMutex
	health     map[string]bool
	healthStop chan struct{}

	// gatewayPrefix 统一网关访问前缀（如 /app/TunHook），
	// 网关转发规则用它拼接对外完整访问路径，便于重定向回写。
	gatewayPrefix string
}

// SetGatewayPrefix 设置统一网关访问前缀（web 服务启动时调用；CLI 模式无需设置）。
func (m *Manager) SetGatewayPrefix(prefix string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gatewayPrefix = prefix
}

// SourcePrefix 返回指定转发规则的源路径前缀（后端应用原始路径前缀）。
func (m *Manager) SourcePrefix(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rulePrefixes[key]
}

// RootPrefixes 返回指定转发规则的根相对路径前缀列表。
func (m *Manager) RootPrefixes(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ruleRootPrefixes[key]
}

// PathPrefix 返回指定转发规则的后端路径前缀（gateway 模式）。
func (m *Manager) PathPrefix(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rulePathPrefixes[key]
}

// AutoDetect 返回指定转发规则是否开启自动检测路径（gateway 模式）。
func (m *Manager) AutoDetect(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ruleAutoDetect[key]
}

// HasCustomCert 返回指定 HTTPS 转发规则是否使用了用户上传的证书
// （false 表示自动生成的自签名证书）。非 HTTPS 规则返回 false。
func (m *Manager) HasCustomCert(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ruleCustomCerts[key]
}

// IsTLS 返回指定转发规则是否以 TLS（HTTPS 自签名证书）方式监听（TCP+HTTPS 开关）。
func (m *Manager) IsTLS(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ruleTLSSet[key]
}

// RuleAdvanced 一条转发规则的进阶/日志设置。
type RuleAdvanced struct {
	RateLimit         int
	MaxConnections    int
	ProxyProtocol     bool
	TLSSource         bool
	UDPSessionTimeout int
	UDPMaxSessions    int
	UDPMaxBlockLen    int
	LogLevel          string
	ChannelLogEntries int
	AccessLogEntries  int
}

// Advanced 返回指定转发规则的进阶/日志设置（规则未启动或不存在时返回 nil）。
func (m *Manager) Advanced(key string) *RuleAdvanced {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ruleAdvanced[key]
}

type Forwarder interface {
	Start() error
	Stop()
	TXBytes() int64
	RXBytes() int64
	ConnCount() int
	GetClients() []ClientInfo
}

func NewManager(logger *zap.Logger, st *store.Store) *Manager {
	m := &Manager{
		rules:            make(map[string]Forwarder),
		logger:           logger,
		store:            st,
		ruleUUIDs:        make(map[string]string),
		rulePrefixes:     make(map[string]string),
		ruleRootPrefixes: make(map[string]string),
		rulePathPrefixes: make(map[string]string),
		ruleAutoDetect:   make(map[string]bool),
		ruleCustomCerts:  make(map[string]bool),
		ruleTLSSet:       make(map[string]bool),
		ruleAdvanced:     make(map[string]*RuleAdvanced),
		health:           make(map[string]bool),
	}
	m.startHealthChecker()
	return m
}

// startHealthChecker 启动目标端口可达性探测（每 healthCheckInterval 探测一次），
// 运行中的转发规则若目标端口不通，前端据此显示为「转发失败」。
func (m *Manager) startHealthChecker() {
	m.healthStop = make(chan struct{})
	go func() {
		t := time.NewTicker(healthCheckInterval)
		defer t.Stop()
		for {
			select {
			case <-m.healthStop:
				return
			case <-t.C:
				m.refreshTargetHealth()
			}
		}
	}()
}

// Close 停止后台健康探测（服务退出时调用）。
func (m *Manager) Close() {
	if m.healthStop != nil {
		select {
		case <-m.healthStop:
		default:
			close(m.healthStop)
		}
	}
}

// TargetReachable 返回指定转发规则目标端口是否可达（known=false 表示尚未探测，按可达处理）。
func (m *Manager) TargetReachable(key string) (reachable, known bool) {
	m.healthMu.RLock()
	v, ok := m.health[key]
	m.healthMu.RUnlock()
	return v, ok
}

// refreshTargetHealth 探测所有运行中规则的目标端口并更新缓存。
func (m *Manager) refreshTargetHealth() {
	for _, key := range m.RunningRules() {
		reachable := m.probeTarget(key)
		m.healthMu.Lock()
		m.health[key] = reachable
		m.healthMu.Unlock()
	}
}

// clearHealth 清除规则的目标可达性缓存（规则停止/删除时调用）。
func (m *Manager) clearHealth(key string) {
	m.healthMu.Lock()
	delete(m.health, key)
	m.healthMu.Unlock()
}

// probeTarget 探测规则目标端口是否可达：TCP 短连接握手（约 900ms 超时）。
// 对 UDP 规则同样以 TCP 探测同一端口（大多数同时提供 TCP 的服务可直接判定，
// 未监听 TCP 端口时通常连接被拒，与「目标端口不通」语义一致）。
func (m *Manager) probeTarget(key string) bool {
	addr, ok := targetAddrFromKey(key)
	if !ok {
		return true
	}
	conn, err := net.DialTimeout("tcp", addr, 900*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// targetAddrFromKey 从转发规则 key 解析出目标地址 host:port（用于可达性探测）。
func targetAddrFromKey(key string) (string, bool) {
	idx := strings.Index(key, "://")
	if idx < 0 {
		return "", false
	}
	rest := key[idx+3:]
	arrowIdx := strings.Index(rest, "->")
	if arrowIdx < 0 {
		return "", false
	}
	remotePart := rest[arrowIdx+2:]
	lastColon := strings.LastIndex(remotePart, ":")
	if lastColon < 0 {
		return "", false
	}
	host := remotePart[:lastColon]
	port := remotePart[lastColon+1:]
	if host == "" || port == "" {
		return "", false
	}
	return net.JoinHostPort(host, port), true
}

func (m *Manager) StartRule(rule config.ForwardRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := ruleKey(rule)
	if _, exists := m.rules[key]; exists {
		return fmt.Errorf("forwarding rule already exists: %s", key)
	}

	localAddr := fmt.Sprintf("%s:%d", rule.LocalAddr, rule.LocalPort)
	remoteAddr := fmt.Sprintf("%s:%d", rule.RemoteAddr, rule.RemotePort)

	var fwd Forwarder
	fwdLogger := m.logger.With(zap.String("forward", key))
	switch rule.Protocol {
	case "http", "HTTP":
		if rule.Domain == "" {
			return fmt.Errorf("HTTP protocol requires a domain")
		}
		fwd = NewHTTPForwarder(localAddr, remoteAddr, rule.Domain, fwdLogger)
	case "https", "HTTPS":
		if rule.Domain == "" {
			return fmt.Errorf("HTTPS protocol requires a domain")
		}
		// HTTPS 转发：无证书时自动生成自签名证书，证书随规则持久化
		hasCustomCert := rule.CertPEM != ""
		hf, err := NewHTTPSForwarder(localAddr, remoteAddr, rule.Domain, rule.CertPEM, rule.KeyPEM, fwdLogger)
		if err != nil {
			return err
		}
		rule.CertPEM = hf.CertPEM()
		rule.KeyPEM = hf.KeyPEM()
		m.ruleCustomCerts[key] = hasCustomCert
		fwd = hf
	case "tcp", "TCP":
		// 开启 HTTPS（自签名证书）：以 TLS 方式监听，解密后转发到内网 HTTP 服务；
		// 直连模式（本机端口一致）依赖服务已在本机监听，TLS 监听需要真实转发，故跳过直连
		tcpOpts := TCPOpts{
			RateLimit:   rule.RateLimit,
			MaxConns:    rule.MaxConnections,
			ProxyProto:  rule.ProxyProtocol,
			TLSUpstream: rule.TLSSource,
		}
		if rule.TLSEnable {
			hasCustomCert := rule.CertPEM != ""
			tf, outCert, outKey, err := NewTLSTCPForwarderOpts(localAddr, remoteAddr, rule.RemoteAddr, rule.CertPEM, rule.KeyPEM, fwdLogger, tcpOpts)
			if err != nil {
				return err
			}
			rule.CertPEM = outCert
			rule.KeyPEM = outKey
			m.ruleCustomCerts[key] = hasCustomCert
			m.ruleTLSSet[key] = true
			fwd = tf
		} else if IsLocalDirectTarget(rule) {
			fwd = NewDirectForwarder(rule)
		} else {
			fwd = NewTCPForwarderOpts(localAddr, remoteAddr, fwdLogger, tcpOpts)
		}
	case "udp", "UDP":
		if IsLocalDirectTarget(rule) {
			fwd = NewDirectForwarder(rule)
		} else {
			fwd = NewUDPForwarderOpts(localAddr, remoteAddr, fwdLogger, UDPOpts{
				SessionTimeoutMs: rule.UDPSessionTimeout,
				MaxSessions:      rule.UDPMaxSessions,
				MaxBlockLen:      rule.UDPMaxBlockLen,
			})
		}
	case "gateway", "GATEWAY":
		if rule.Name == "" {
			return fmt.Errorf("统一网关模式必须填写路径名称")
		}
		if !validGatewayName(rule.Name) {
			return fmt.Errorf("网关路径名称非法: %s（仅允许字母、数字、下划线、连字符）", rule.Name)
		}
		for _, existing := range m.rules {
			if gf, ok := existing.(*GatewayForwarder); ok && gf.Name() == rule.Name {
				return fmt.Errorf("网关路径名称已存在: %s", rule.Name)
			}
		}
		gf, err := NewGatewayForwarder(rule.Name, remoteAddr, m.gatewayPrefix, rule.SourcePrefix, rule.RootPrefixes, rule.PathPrefix, fwdLogger)
		if err != nil {
			return fmt.Errorf("create gateway forwarder: %w", err)
		}
		fwd = gf
	default:
		return fmt.Errorf("unsupported protocol: %s", rule.Protocol)
	}

	if err := fwd.Start(); err != nil {
		return fmt.Errorf("start forwarder: %w", err)
	}

	m.rules[key] = fwd
	if m.ruleUUIDs[key] == "" {
		m.ruleUUIDs[key] = generateUUID()
	}
	m.rulePrefixes[key] = rule.SourcePrefix
	m.ruleRootPrefixes[key] = rule.RootPrefixes
	m.rulePathPrefixes[key] = rule.PathPrefix
	m.ruleAutoDetect[key] = rule.AutoDetect
	m.ruleAdvanced[key] = &RuleAdvanced{
		RateLimit:         rule.RateLimit,
		MaxConnections:    rule.MaxConnections,
		ProxyProtocol:     rule.ProxyProtocol,
		TLSSource:         rule.TLSSource,
		UDPSessionTimeout: rule.UDPSessionTimeout,
		UDPMaxSessions:    rule.UDPMaxSessions,
		UDPMaxBlockLen:    rule.UDPMaxBlockLen,
		LogLevel:          rule.LogLevel,
		ChannelLogEntries: rule.ChannelLogEntries,
		AccessLogEntries:  rule.AccessLogEntries,
	}
	m.saveRule(key, rule)
	m.logger.Info("转发规则已启动",
		zap.String("protocol", rule.Protocol),
		zap.String("local", localAddr),
		zap.String("remote", remoteAddr),
	)
	// 启动后立即异步探测一次目标端口，避免红/绿状态延迟一个探测周期
	go m.refreshTargetHealth()
	return nil
}

func (m *Manager) StopRule(rule config.ForwardRule) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := ruleKey(rule)
	if fwd, ok := m.rules[key]; ok {
		fwd.Stop()
		delete(m.rules, key)
		m.logger.Info("转发规则已停止", zap.String("rule", key))
	}
	// 无论规则当前是否运行，都从存储与索引中移除（前端「删除」使用本接口）
	m.removeRule(key)
	delete(m.ruleAdvanced, key)
	m.clearHealth(key)
}

// StopRuleKeepConfig 仅停止转发器，保留存储记录与 TLS 等索引（前端「暂停」使用）。
// 暂停后再次「启动」时，可从存储恢复 TLSEnable/证书，保证 HTTPS 标记不丢失。
func (m *Manager) StopRuleKeepConfig(rule config.ForwardRule) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := ruleKey(rule)
	if fwd, ok := m.rules[key]; ok {
		fwd.Stop()
		delete(m.rules, key)
		m.logger.Info("转发规则已暂停（保留配置）", zap.String("rule", key))
	}
	// 不删除存储记录，保留 ruleTLSSet 等索引，列表仍展示 HTTPS 标记；
	// 暂停时保留 ruleAdvanced 缓存，保证编辑弹窗仍能回填进阶/日志配置
	m.clearHealth(key)
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, fwd := range m.rules {
		fwd.Stop()
		delete(m.rules, key)
		m.logger.Info("转发规则已停止", zap.String("rule", key))
	}
	m.healthMu.Lock()
	m.health = make(map[string]bool)
	m.healthMu.Unlock()
	m.ruleAdvanced = make(map[string]*RuleAdvanced)
}

func (m *Manager) RunningRules() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var keys []string
	for k := range m.rules {
		keys = append(keys, k)
	}
	return keys
}

func (m *Manager) StartAll(rules []config.ForwardRule) error {
	for _, rule := range rules {
		if err := m.StartRule(rule); err != nil {
			m.StopAll()
			return fmt.Errorf("start rule %s: %w", ruleKey(rule), err)
		}
	}
	return nil
}

func (m *Manager) saveRule(key string, rule config.ForwardRule) {
	if m.store == nil {
		return
	}
	uuid := m.ruleUUIDs[key]
	if uuid == "" {
		uuid = generateUUID()
		m.ruleUUIDs[key] = uuid
	}
	m.store.SaveForwardRule(store.RuleRecord{
		UUID: uuid, Key: key, Protocol: rule.Protocol, LocalAddr: rule.LocalAddr,
		LocalPort: rule.LocalPort, RemoteAddr: rule.RemoteAddr, RemotePort: rule.RemotePort,
		Domain: rule.Domain, Name: rule.Name, SourcePrefix: rule.SourcePrefix,
		RootPrefixes: rule.RootPrefixes, PathPrefix: rule.PathPrefix,
		AutoDetect: rule.AutoDetect, CertPEM: rule.CertPEM, KeyPEM: rule.KeyPEM,
		TLSEnable: rule.TLSEnable,
		RateLimit: rule.RateLimit, MaxConnections: rule.MaxConnections,
		ProxyProtocol: rule.ProxyProtocol, TLSSource: rule.TLSSource,
		UDPSessionTimeout: rule.UDPSessionTimeout, UDPMaxSessions: rule.UDPMaxSessions,
		UDPMaxBlockLen: rule.UDPMaxBlockLen,
		LogLevel:       rule.LogLevel, ChannelLogEntries: rule.ChannelLogEntries,
		AccessLogEntries:  rule.AccessLogEntries,
		LogRetentionHours: rule.LogRetentionHours,
		CustomID:          rule.CustomID, CustomDomain: rule.CustomDomain,
		LinkKey: rule.LinkKey, AccessPassword: rule.AccessPassword,
	})
}

func (m *Manager) GetUUID(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if uuid, ok := m.ruleUUIDs[key]; ok {
		return uuid
	}
	return ""
}

func (m *Manager) removeRule(key string) {
	delete(m.rulePrefixes, key)
	delete(m.ruleRootPrefixes, key)
	delete(m.rulePathPrefixes, key)
	delete(m.ruleAutoDetect, key)
	delete(m.ruleTLSSet, key)
	if m.store != nil {
		m.store.DeleteForwardRule(key)
	}
}

func (m *Manager) LoadSavedRules() []config.ForwardRule {
	if m.store == nil {
		return nil
	}
	records, err := m.store.ListForwardRules()
	if err != nil {
		m.logger.Warn("load saved rules from db failed", zap.Error(err))
		return nil
	}
	var rules []config.ForwardRule
	for _, sr := range records {
		m.mu.Lock()
		m.ruleUUIDs[sr.Key] = sr.UUID
		m.rulePrefixes[sr.Key] = sr.SourcePrefix
		m.ruleRootPrefixes[sr.Key] = sr.RootPrefixes
		m.rulePathPrefixes[sr.Key] = sr.PathPrefix
		m.ruleAutoDetect[sr.Key] = sr.AutoDetect
		if strings.EqualFold(sr.Protocol, "https") {
			m.ruleCustomCerts[sr.Key] = sr.CertPEM != ""
		}
		if sr.TLSEnable {
			m.ruleTLSSet[sr.Key] = true
			// 恢复「是否使用用户上传证书」标记（false=自动生成的自签名证书）
			m.ruleCustomCerts[sr.Key] = sr.CertPEM != ""
		}
		m.mu.Unlock()
		rules = append(rules, config.ForwardRule{
			Protocol: sr.Protocol, LocalAddr: sr.LocalAddr,
			LocalPort: sr.LocalPort, RemoteAddr: sr.RemoteAddr, RemotePort: sr.RemotePort,
			Domain: sr.Domain, Name: sr.Name, SourcePrefix: sr.SourcePrefix,
			RootPrefixes: sr.RootPrefixes, PathPrefix: sr.PathPrefix,
			AutoDetect: sr.AutoDetect, CertPEM: sr.CertPEM, KeyPEM: sr.KeyPEM,
			TLSEnable: sr.TLSEnable,
			// 进阶/日志设置
			RateLimit: sr.RateLimit, MaxConnections: sr.MaxConnections,
			ProxyProtocol: sr.ProxyProtocol, TLSSource: sr.TLSSource,
			UDPSessionTimeout: sr.UDPSessionTimeout, UDPMaxSessions: sr.UDPMaxSessions,
			UDPMaxBlockLen: sr.UDPMaxBlockLen,
			LogLevel:       sr.LogLevel, ChannelLogEntries: sr.ChannelLogEntries,
			AccessLogEntries:  sr.AccessLogEntries,
			LogRetentionHours: sr.LogRetentionHours,
			CustomID:          sr.CustomID, CustomDomain: sr.CustomDomain,
			LinkKey: sr.LinkKey, AccessPassword: sr.AccessPassword,
		})
	}
	return rules
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
	return fmt.Sprintf("%s://%s:%d->%s:%d",
		r.Protocol, r.LocalAddr, r.LocalPort, r.RemoteAddr, r.RemotePort)
}

// GatewayHandler 返回指定子路径名称对应的统一网关转发器（http.Handler）。
// Web 服务器在 /proxy/{name} 下调用；未找到时返回 nil。
func (m *Manager) GatewayHandler(name string) http.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range m.rules {
		if gf, ok := f.(*GatewayForwarder); ok && gf.Name() == name {
			return gf
		}
	}
	return nil
}

func (m *Manager) GetStats(key string) (txBytes, rxBytes int64, connCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if fwd, ok := m.rules[key]; ok {
		return fwd.TXBytes(), fwd.RXBytes(), fwd.ConnCount()
	}
	return 0, 0, 0
}

func (m *Manager) GetClients(key string) []ClientInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	if fwd, ok := m.rules[key]; ok {
		return fwd.GetClients()
	}
	return []ClientInfo{}
}
