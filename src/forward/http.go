package forward

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"tunhook/errpage"

	"go.uber.org/zap"
)

// httpProxy 是一个共享的 HTTP/HTTPS 反向代理，在指定端口监听并基于 Host 头路由到不同后端。
// 多个 httpForwarder 可共享同一个 httpProxy（相同端口不同域名）。
// 任意路由为 HTTPS 时，整个端口以 TLS 方式监听（SNI 按域名选择证书）。
type httpProxy struct {
	localAddr string
	logger    *zap.Logger

	mu         sync.RWMutex
	routes     map[string]*httpRoute // key: domain
	server     *http.Server
	listener   net.Listener
	stopCh     chan struct{}
	servingTLS bool // listener 的实际协议模式；启动后不允许原地切换

	// TLS 支持：任一 HTTPS 路由注册时生成 tlsConfig；共享端口按 SNI 域名选择证书
	tlsCerts  map[string]*tls.Certificate // key: domain
	tlsConfig *tls.Config

	txBytes int64
	rxBytes int64
}

type httpRoute struct {
	domain     string
	backendURL *url.URL
	forwarder  *httpForwarder // owner
	connCount  int32
	mu         sync.Mutex
	clients    map[string]*httpClientStat
}

type httpClientStat struct {
	txBytes    int64
	rxBytes    int64
	lastTx     int64
	lastRx     int64
	lastSample time.Time
}

// httpForwarder 实现 Forwarder 接口，代表单条 HTTP/HTTPS 转发规则。
// 同一端口的多个 httpForwarder 共享底层 httpProxy。
type httpForwarder struct {
	localAddr  string
	remoteAddr string
	domain     string
	proxy      *httpProxy
	logger     *zap.Logger
	isTLS      bool
	tlsCert    *tls.Certificate
	certPEM    string // 持久化用：PEM 证书内容（可能为自动生成的自签名证书）
	keyPEM     string // 持久化用：PEM 私钥内容

	started bool
}

// httpProxy 全局注册表，按 localAddr:localPort 索引
var (
	httpProxyReg   = make(map[string]*httpProxy)
	httpProxyRegMu sync.Mutex
)

func getOrCreateHTTPProxy(localAddr string, logger *zap.Logger) *httpProxy {
	httpProxyRegMu.Lock()
	defer httpProxyRegMu.Unlock()

	if p, ok := httpProxyReg[localAddr]; ok {
		return p
	}

	p := &httpProxy{
		localAddr: localAddr,
		logger:    logger,
		routes:    make(map[string]*httpRoute),
		tlsCerts:  make(map[string]*tls.Certificate),
		stopCh:    make(chan struct{}),
	}
	httpProxyReg[localAddr] = p
	return p
}

func removeHTTPProxy(localAddr string) {
	httpProxyRegMu.Lock()
	defer httpProxyRegMu.Unlock()
	delete(httpProxyReg, localAddr)
}

func NewHTTPForwarder(localAddr, remoteAddr, domain string, logger *zap.Logger) *httpForwarder {
	return &httpForwarder{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		domain:     domain,
		logger:     logger,
	}
}

// NewHTTPSForwarder 创建 HTTPS 转发规则。
// certPEM/keyPEM 为空时自动生成自签名证书（生成的证书通过 CertPEM()/KeyPEM() 获取以持久化）。
func NewHTTPSForwarder(localAddr, remoteAddr, domain, certPEM, keyPEM string, logger *zap.Logger) (*httpForwarder, error) {
	cert, outCert, outKey, err := loadTLSCert(domain, certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &httpForwarder{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		domain:     domain,
		logger:     logger,
		isTLS:      true,
		tlsCert:    cert,
		certPEM:    outCert,
		keyPEM:     outKey,
	}, nil
}

// CertPEM 返回该规则持久化的 PEM 证书内容（自动生成的证书也包含在内）。
func (f *httpForwarder) CertPEM() string { return f.certPEM }

// KeyPEM 返回该规则持久化的 PEM 私钥内容。
func (f *httpForwarder) KeyPEM() string { return f.keyPEM }

// ========== httpForwarder (Forwarder interface) ==========

func (f *httpForwarder) Start() error {
	if f.started {
		return fmt.Errorf("http forwarder already started")
	}

	f.proxy = getOrCreateHTTPProxy(f.localAddr, f.logger)

	backendURL, err := url.Parse("http://" + f.remoteAddr)
	if err != nil {
		return fmt.Errorf("parse backend url: %w", err)
	}

	route := &httpRoute{
		domain:     f.domain,
		backendURL: backendURL,
		forwarder:  f,
		clients:    make(map[string]*httpClientStat),
	}

	f.proxy.mu.Lock()
	// 底层 listener 只在首条路由启动时创建。运行中仅更新 tlsConfig
	// 无法把明文 listener 切换成 TLS（或反过来），因此明确拒绝混用。
	if f.proxy.listener != nil && f.proxy.servingTLS != f.isTLS {
		mode := "HTTP"
		if f.proxy.servingTLS {
			mode = "HTTPS"
		}
		f.proxy.mu.Unlock()
		return fmt.Errorf("listen address %s is already serving %s; HTTP and HTTPS routes cannot share one listener", f.localAddr, mode)
	}
	if _, exists := f.proxy.routes[f.domain]; exists {
		f.proxy.mu.Unlock()
		return fmt.Errorf("domain route already exists on %s: %s", f.localAddr, f.domain)
	}
	// HTTPS 规则注册证书（SNI 按域名选择）
	if f.isTLS {
		if f.tlsCert != nil {
			f.proxy.tlsCerts[f.domain] = f.tlsCert
		}
		f.proxy.rebuildTLSConfigLocked()
	}
	f.proxy.routes[f.domain] = route
	routeCount := len(f.proxy.routes)
	f.proxy.mu.Unlock()

	// 如果这是第一个路由，启动服务器（有 TLS 证书则 TLS 监听）
	if routeCount == 1 {
		if err := f.proxy.start(); err != nil {
			f.proxy.mu.Lock()
			delete(f.proxy.routes, f.domain)
			if f.isTLS {
				delete(f.proxy.tlsCerts, f.domain)
				f.proxy.rebuildTLSConfigLocked()
			}
			f.proxy.mu.Unlock()
			removeHTTPProxy(f.localAddr)
			return fmt.Errorf("start http proxy: %w", err)
		}
	}

	f.started = true
	proto := "HTTP"
	if f.isTLS {
		proto = "HTTPS"
	}
	f.logger.Info(proto+"转发已添加",
		zap.String("domain", f.domain),
		zap.String("listen", f.localAddr),
		zap.String("backend", f.remoteAddr),
	)
	return nil
}

func (f *httpForwarder) Stop() {
	if !f.started {
		return
	}
	f.started = false

	if f.proxy == nil {
		return
	}

	f.proxy.mu.Lock()
	delete(f.proxy.routes, f.domain)
	if f.isTLS {
		delete(f.proxy.tlsCerts, f.domain)
		f.proxy.rebuildTLSConfigLocked()
	}
	remaining := len(f.proxy.routes)
	f.proxy.mu.Unlock()

	f.logger.Info("HTTP转发已移除",
		zap.String("domain", f.domain),
		zap.Int("remaining_routes", remaining),
	)

	// 没有剩余路由则停止 HTTP 服务器
	if remaining == 0 {
		f.proxy.stop()
		removeHTTPProxy(f.localAddr)
	}
}

func (f *httpForwarder) TXBytes() int64 {
	if f.proxy == nil {
		return 0
	}
	return atomic.LoadInt64(&f.proxy.txBytes)
}

func (f *httpForwarder) RXBytes() int64 {
	if f.proxy == nil {
		return 0
	}
	return atomic.LoadInt64(&f.proxy.rxBytes)
}

func (f *httpForwarder) ConnCount() int {
	if f.proxy == nil {
		return 0
	}
	f.proxy.mu.RLock()
	defer f.proxy.mu.RUnlock()
	if r, ok := f.proxy.routes[f.domain]; ok {
		return int(atomic.LoadInt32(&r.connCount))
	}
	return 0
}

func (f *httpForwarder) GetClients() []ClientInfo {
	if f.proxy == nil {
		return nil
	}
	f.proxy.mu.RLock()
	r, ok := f.proxy.routes[f.domain]
	f.proxy.mu.RUnlock()
	if !ok {
		return nil
	}
	// route.clients 由 route.mu 保护（见 serveHTTP），此处必须用 route.mu 遍历
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	clients := make([]ClientInfo, 0, len(r.clients))
	for addr, st := range r.clients {
		ci := ClientInfo{
			Addr:    addr,
			TxBytes: st.txBytes,
			RxBytes: st.rxBytes,
		}
		ci.TxRate, ci.RxRate = rateTick(&st.lastTx, &st.lastRx, &st.lastSample, st.txBytes, st.rxBytes, now)
		clients = append(clients, ci)
	}
	return clients
}

// ========== httpProxy ==========

// rebuildTLSConfigLocked 根据当前注册的证书重建 TLS 配置（调用方需持有 p.mu 写锁）。
// 通过 GetCertificate 按 SNI 域名选择对应证书，通配域名（*.example.com）亦可匹配子域。
func (p *httpProxy) rebuildTLSConfigLocked() {
	if len(p.tlsCerts) == 0 {
		p.tlsConfig = nil
		return
	}
	certs := make(map[string]*tls.Certificate, len(p.tlsCerts))
	for k, v := range p.tlsCerts {
		certs[k] = v
	}
	// 默认证书：优先精确域名，否则取第一个
	var def *tls.Certificate
	for _, c := range certs {
		def = c
		break
	}
	p.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.ToLower(strings.TrimSpace(hello.ServerName))
			if c, ok := certs[name]; ok {
				return c, nil
			}
			for domain, c := range certs {
				if matchDomain(domain, name) {
					return c, nil
				}
			}
			return def, nil
		},
	}
}

func (p *httpProxy) start() error {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			c.Control(func(fd uintptr) {
				opErr = setReuseAddr(fd)
			})
			return opErr
		},
	}
	listener, err := lc.Listen(context.Background(), "tcp", p.localAddr)
	if err != nil {
		return fmt.Errorf("listen HTTP: %w", err)
	}
	p.listener = listener
	p.servingTLS = p.tlsConfig != nil

	mux := http.NewServeMux()
	mux.HandleFunc("/", p.serveHTTP)

	p.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return ctx
		},
	}

	// 有 HTTPS 证书时以 TLS 方式监听
	if p.tlsConfig != nil {
		listener = tls.NewListener(listener, p.tlsConfig)
		p.logger.Info("HTTPS代理服务已启动", zap.String("listen", p.localAddr))
	} else {
		p.logger.Info("HTTP代理服务已启动", zap.String("listen", p.localAddr))
	}

	go func() {
		if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			p.logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	return nil
}

func (p *httpProxy) stop() {
	if p.server != nil {
		p.server.Close()
	}
	removeHTTPProxy(p.localAddr)
	p.logger.Info("HTTP代理服务已停止", zap.String("listen", p.localAddr))
}

func (p *httpProxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	// Let's Encrypt HTTP-01 挑战：经公网 http://域名/.well-known/acme-challenge/{token}
	// 通过本转发规则到达，直接响应挑战内容（无需本机监听 80 端口）。
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		if token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/"); token != "" {
			if ka, ok := LookupACMEChallenge(token); ok {
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte(ka))
				return
			}
		}
	}

	host := r.Host
	// 去掉端口号（Host 头可能包含端口）
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	p.mu.RLock()
	route, ok := p.routes[host]
	// 如果精确域名不匹配，尝试通配符匹配
	if !ok {
		for domain, rt := range p.routes {
			if matchDomain(domain, host) {
				route = rt
				ok = true
				break
			}
		}
	}
	p.mu.RUnlock()

	if !ok {
		// TunHook 自身产生的错误（域名没有对应转发规则）：可按配置替换为自定义错误页
		errpage.Write(w, r, http.StatusBadGateway, "502 网关错误：无匹配路由")
		p.logger.Warn("HTTP请求无匹配路由", zap.String("host", host))
		return
	}

	clientIP := r.RemoteAddr

	route.mu.Lock()
	st, ok := route.clients[clientIP]
	if !ok {
		st = &httpClientStat{}
		route.clients[clientIP] = st
	}
	route.mu.Unlock()
	atomic.AddInt32(&route.connCount, 1)
	defer func() {
		route.mu.Lock()
		delete(route.clients, clientIP)
		route.mu.Unlock()
		atomic.AddInt32(&route.connCount, -1)
	}()

	p.logger.Info(fmt.Sprintf("HTTP访问: %s %s -> %s (域名: %s)", r.Method, r.URL.Path, route.backendURL.Host, host))

	// 使用 countingResponseWriter 统计流量（全局 + 每客户端）
	cw := &countingResponseWriter{ResponseWriter: w, count: &p.rxBytes, stat: st, mu: &route.mu}
	cr := &countingReader{ReadCloser: r.Body, count: &p.txBytes, stat: st, mu: &route.mu}
	r.Body = cr

	rp := httputil.NewSingleHostReverseProxy(route.backendURL)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		p.logger.Error("HTTP反向代理错误",
			zap.String("host", host),
			zap.String("backend", route.backendURL.Host),
			zap.Error(err),
		)
		// 后端不可达（TunHook 自身产生的错误）：可按配置替换为自定义错误页
		errpage.Write(w, r, http.StatusBadGateway, "502 网关错误")
	}
	rp.ServeHTTP(cw, r)
}

// matchDomain 检查请求域名是否匹配路由域名（支持通配符 *）
func matchDomain(routeDomain, requestHost string) bool {
	if routeDomain == requestHost {
		return true
	}
	// 通配符匹配：*.example.com
	if len(routeDomain) > 2 && routeDomain[0] == '*' && routeDomain[1] == '.' {
		suffix := routeDomain[1:] // .example.com
		return len(requestHost) >= len(suffix) &&
			requestHost[len(requestHost)-len(suffix):] == suffix
	}
	return false
}

// ---- 流量统计 wrapper ----

type countingResponseWriter struct {
	http.ResponseWriter
	count *int64
	stat  *httpClientStat
	mu    *sync.Mutex
}

func (w *countingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	atomic.AddInt64(w.count, int64(n))
	if w.stat != nil {
		w.mu.Lock()
		w.stat.rxBytes += int64(n)
		w.mu.Unlock()
	}
	return n, err
}

// Hijack 支持 WebSocket / 长连接升级：底层 ResponseWriter 实现 http.Hijacker 时透传。
// 否则 ReverseProxy 的 101 Switching Protocols 升级会因类型断言失败而返回 502。
func (w *countingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}

// Flush 支持流式响应（SSE / 分块传输）透传。
func (w *countingResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap 支持 http.ResponseController 访问底层 ResponseWriter。
func (w *countingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

type countingReader struct {
	io.ReadCloser
	count *int64
	stat  *httpClientStat
	mu    *sync.Mutex
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	atomic.AddInt64(r.count, int64(n))
	if r.stat != nil {
		r.mu.Lock()
		r.stat.txBytes += int64(n)
		r.mu.Unlock()
	}
	return n, err
}
