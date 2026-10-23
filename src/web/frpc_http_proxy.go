package web

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"tunhook/errpage"
	"tunhook/frpc"

	"go.uber.org/zap"
)

// ============= frpc http 代理经 TunHook 反代层 =============
//
// 背景：frp 的 http/https 代理由 frps 直接路由给 frpc，frpc 再把请求转发到本地后端，
// 全程不经过 TunHook，导致「连接统计」弹窗无法得知访客真实 IP/端口（显示 -）。
//
// 方案：对启用了访客记录的 http 代理，TunHook 在本地启动一个反代层：
//   - frpc 代理的 localPort 指向该反代监听端口（localPort 被改写为反代端口）；
//   - 反代层从 frpc 注入的 X-Forwarded-For / X-Real-IP 解析访客真实 IP，记录到
//     connVisitorsByProxy[代理名]，供「连接统计」弹窗按代理名关联展示；
//   - 反代层再把请求反向代理到真实后端（localIP:realLocalPort）。
//
// 说明：目前仅支持 http 类型（明文转发可直接用 httputil.ReverseProxy）；
// https 类型是 TLS 隧道原样转发，需 TLS 透传，暂不改写 localPort。

// frpcHTTPProxy 单个 frpc http 代理经 TunHook 反代时的本地反代层。
type frpcHTTPProxy struct {
	name    string
	backend string // 真实后端 host:port（localIP:realLocalPort）
	lis     net.Listener
	server  *http.Server
	// rp 反代器：ReverseProxy 本身无状态、可并发调用，构造一次即可复用。
	// 原先在 serveHTTP 里每个请求都 NewSingleHostReverseProxy，等于每请求重复分配
	// 代理器与错误处理闭包，纯属浪费。
	rp     *httputil.ReverseProxy
	rec    func(name, ip, port string)
	logger *zap.Logger
	// waf 请求检查（命中且拦截模式时已写好响应并返回 true）
	waf func(w http.ResponseWriter, r *http.Request) bool

	mu      sync.Mutex
	started bool
}

// startFRPCHTTPProxy 为给定 http 代理启动本地反代层，返回实际监听端口。
//   - listenPort：反代要监听的本地端口，0=由系统自动分配（返回实际端口）；
//   - 真实后端 = p.LocalIP:p.RealLocalPort（RealLocalPort 为 0 时回退 p.LocalPort）。
func (s *Server) startFRPCHTTPProxy(p frpc.Proxy, listenPort int) (int, error) {
	lip := strings.TrimSpace(p.LocalIP)
	if lip == "" || lip == "0.0.0.0" {
		lip = "127.0.0.1"
	}
	realPort := p.RealLocalPort
	if realPort <= 0 {
		realPort = p.LocalPort
	}
	if realPort <= 0 {
		return 0, fmt.Errorf("代理「%s」未配置本地端口", p.Name)
	}
	backend := net.JoinHostPort(lip, strconv.Itoa(realPort))

	// 反代器在启动时构造一次（含错误处理），供本代理的全部请求复用
	target, err := url.Parse("http://" + backend)
	if err != nil {
		return 0, fmt.Errorf("后端地址无效: %w", err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, rerr error) {
		s.logger.Error("frpc http 反代失败",
			zap.String("proxy", p.Name),
			zap.String("backend", backend),
			zap.Error(rerr))
		errpage.Write(w, r, http.StatusBadGateway, "502 网关错误：后端不可达")
	}

	lis, err := net.Listen("tcp", net.JoinHostPort(lip, strconv.Itoa(listenPort)))
	if err != nil {
		return 0, fmt.Errorf("监听反代端口失败: %w", err)
	}
	port := listenPort
	if port <= 0 {
		port = lis.Addr().(*net.TCPAddr).Port
	}

	hp := &frpcHTTPProxy{
		name:    p.Name,
		backend: backend,
		lis:     lis,
		rp:      rp,
		rec:     s.recordVisitorByProxy,
		logger:  s.logger,
		waf: func(w http.ResponseWriter, r *http.Request) bool {
			return s.wafGuardHTTP(w, r, "frpc")
		},
	}
	hp.mu.Lock()
	hp.started = true
	hp.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", hp.serveHTTP)
	hp.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	s.httpProxyMu.Lock()
	s.httpProxyByProxy[p.Name] = hp
	s.httpProxyMu.Unlock()

	go func() {
		if err := hp.server.Serve(lis); err != nil && err != http.ErrServerClosed {
			s.logger.Error("frpc http 反代服务错误",
				zap.String("proxy", p.Name),
				zap.String("backend", backend),
				zap.Error(err))
		}
	}()

	s.logger.Info("frpc http 反代已启动",
		zap.String("proxy", p.Name),
		zap.Int("listen_port", port),
		zap.String("backend", backend),
	)
	return port, nil
}

// stopFRPCHTTPProxy 停止指定代理的本地反代层。
func (s *Server) stopFRPCHTTPProxy(name string) {
	s.httpProxyMu.Lock()
	hp := s.httpProxyByProxy[name]
	delete(s.httpProxyByProxy, name)
	s.httpProxyMu.Unlock()
	if hp == nil {
		return
	}
	hp.mu.Lock()
	hp.started = false
	hp.mu.Unlock()
	if hp.server != nil {
		hp.server.Close()
	}
	if hp.lis != nil {
		hp.lis.Close()
	}
	s.logger.Info("frpc http 反代已停止", zap.String("proxy", name))
}

// syncFrpcHTTPProxy 为 http 代理同步本地反代层，返回应持久化的 proxy。
//   - 先停止旧代理名（origName）的反代，避免改名/改类型后残留；
//   - http 且 ViaTunHook 时：改写 localPort 为反代端口、记录真实后端端口 realLocalPort，并启动反代；
//   - 非 http 或未启用反代时：清空 realLocalPort 保持直连。
func (s *Server) syncFrpcHTTPProxy(p frpc.Proxy, origName string) frpc.Proxy {
	if origName != "" {
		s.stopFRPCHTTPProxy(origName)
	}
	typ := strings.ToLower(strings.TrimSpace(p.Type))
	if typ != "http" || !p.ViaTunHook || p.LocalPort <= 0 {
		p.RealLocalPort = 0
		return p
	}
	realPort := p.LocalPort
	p.RealLocalPort = realPort
	port, err := s.startFRPCHTTPProxy(p, 0) // 自动分配反代端口
	if err != nil {
		s.logger.Warn("frpc http 反代启动失败，回退直连",
			zap.String("proxy", p.Name), zap.Error(err))
		p.ViaTunHook = false
		p.RealLocalPort = 0
		return p
	}
	p.LocalPort = port
	return p
}

// startFRPCHTTPProxies 启动时为所有已启用反代的 http 代理恢复本地反代层。
func (s *Server) startFRPCHTTPProxies() {
	for _, p := range s.frpcMgr.LoadConfig().Proxies {
		typ := strings.ToLower(strings.TrimSpace(p.Type))
		if typ != "http" || !p.ViaTunHook || !p.Enabled || p.RealLocalPort <= 0 {
			continue
		}
		// 复用已持久化的反代端口（localPort）
		if _, err := s.startFRPCHTTPProxy(p, p.LocalPort); err != nil {
			s.logger.Warn("frpc http 反代恢复失败",
				zap.String("proxy", p.Name), zap.Error(err))
		}
	}
}

// serveHTTP 处理经 frpc 转发来的 HTTP 请求：记录访客 IP 后反代到真实后端。
func (hp *frpcHTTPProxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	// WAF：对经隧道暴露的 HTTP 流量做检测（拦截模式下直接返回 403）
	if hp.waf != nil && hp.waf(w, r) {
		return
	}
	// 访客真实 IP 来自 frpc 注入的 X-Forwarded-For / X-Real-IP
	visitorIP := clientIP(r)
	visitorPort := strings.TrimSpace(r.Header.Get("X-Real-Port"))
	if hp.rec != nil {
		hp.rec(hp.name, visitorIP, visitorPort)
	}

	hp.logger.Info("frpc http 反代访问",
		zap.String("proxy", hp.name),
		zap.String("visitor_ip", visitorIP),
		zap.String("visitor_port", visitorPort),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("backend", hp.backend),
	)
	// 复用启动时构造好的反代器：ReverseProxy 无状态、可并发调用，
	// 原先每请求 NewSingleHostReverseProxy 会重复分配代理器与错误处理闭包
	hp.rp.ServeHTTP(w, r)
}
