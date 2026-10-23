package web

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"tunhook/frpc"

	"go.uber.org/zap"
)

// ============= frpc tcp/proxy-protocol 代理经 TunHook 反代层 =============
//
// 背景：frp 的 tcp 型代理由 frps 直接透传给 frpc，frpc 再把数据转发到本地服务，
// 全程不经过 TunHook，且 frpc 连到的是 frps 服务器，导致「连接统计」弹窗无法得知访客真实 IP。
//
// 方案：frps 端与 frpc 端均开启 proxy_protocol_version=v2 后，frpc 在转发到本地服务的
// 连接数据流开头会注入 PROXY v2 头（携带访客真实 IP:port）。TunHook 据此为 tcp 代理
// 启动一个本地反代层：
//   - frpc 代理的 localPort 指向该反代监听端口（localPort 被改写为反代端口）；
//   - 反代层解析 PROXY v1/v2 头得到访客真实 IP/端口，记录到 connVisitorsByProxy[代理名]，
//     供「连接统计」弹窗按代理名关联展示；
//   - 反代层再建立到真实后端（localIP:realLocalPort）的连接，把剥离 PROXY 头后的业务
//     数据双向转发，本地服务无需感知 PROXY protocol。

// proxyV2Signature 是 PROXY protocol v2 的 12 字节固定签名。
var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// proxyHeaderTimeout 等待读取 PROXY 头的超时；超时视为无头（直接转发已读字节）。
const proxyHeaderTimeout = 3 * time.Second

// frpcTCPProxy 单个 frpc tcp 代理经 TunHook 反代时的本地 PROXY 解析层。
type frpcTCPProxy struct {
	name    string
	backend string // 真实后端 host:port（localIP:realLocalPort）
	lis     net.Listener
	rec     func(name, ip, port string)
	logger  *zap.Logger

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// parseProxyHeader 从连接流的开头读取并消费 PROXY v1/v2 头，返回访客真实 IP/端口。
//   - 识别到 PROXY 头时消费头后返回 (ip, port, true, nil)（该行为不消费业务数据）；
//   - 未识别到任何 PROXY 头时返回 ("", "", false, nil)，此时 buf 中未消费字节仍属于业务数据；
//   - 仅支持 TCP 传输（PROXY 协议 v2 的 TCP-over-IPv4/IPv6 地址族）。
func parseProxyHeader(br *bufio.Reader) (ip, port string, hasProxy bool, err error) {
	// PROXY v2：固定 12 字节签名
	if sig, e := br.Peek(12); e == nil && bytes.Equal(sig, proxyV2Signature) {
		// Peek 不消费字节，需先消费掉 12 字节签名，再读取 4 字节头
		sigBuf := make([]byte, 12)
		if _, err = io.ReadFull(br, sigBuf); err != nil {
			return "", "", false, fmt.Errorf("read proxy v2 signature: %w", err)
		}
		hdr := make([]byte, 4)
		if _, err = io.ReadFull(br, hdr); err != nil {
			return "", "", false, fmt.Errorf("read proxy v2 header: %w", err)
		}
		famProto := hdr[1]
		ln := int(binary.BigEndian.Uint16(hdr[2:4]))
		addr := make([]byte, ln)
		if _, err = io.ReadFull(br, addr); err != nil {
			return "", "", false, fmt.Errorf("read proxy v2 addr(len=%d): %w", ln, err)
		}
		if hdr[0]&0x0F == 0x01 { // PROXY 命令（0x01），非 LOCAL（0x00）
			switch famProto {
			case 0x11: // TCP over IPv4：srcAddr(4)+srcPort(2)+dstAddr(4)+dstPort(2)
				srcIP := net.IP(addr[0:4]).String()
				srcPort := int(binary.BigEndian.Uint16(addr[4:6]))
				return srcIP, strconv.Itoa(srcPort), true, nil
			case 0x21: // TCP over IPv6：srcAddr(16)+srcPort(2)+dstAddr(16)+dstPort(2)
				srcIP := net.IP(addr[0:16]).String()
				srcPort := int(binary.BigEndian.Uint16(addr[16:18]))
				return srcIP, strconv.Itoa(srcPort), true, nil
			}
		}
		// LOCAL 命令或未知地址族：头已消费，无访客地址
		return "", "", true, nil
	}
	// PROXY v1：文本行 "PROXY TCP4 srcIP dstIP srcPort dstPort\r\n"
	if b, e := br.Peek(6); e == nil && bytes.Equal(b, []byte("PROXY ")) {
		line, rerr := br.ReadString('\n')
		if rerr != nil && rerr != io.EOF {
			return "", "", false, rerr
		}
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) >= 6 && parts[0] == "PROXY" {
			return parts[2], parts[4], true, nil
		}
		return "", "", true, nil
	}
	return "", "", false, nil
}

// startFRPCTCPProxy 为给定 tcp 代理启动本地 PROXY 解析反代层，返回实际监听端口。
//   - listenPort：反代要监听的本地端口，0=由系统自动分配（返回实际端口）；
//   - 真实后端 = p.LocalIP:p.RealLocalPort（RealLocalPort 为 0 时回退 p.LocalPort）。
func (s *Server) startFRPCTCPProxy(p frpc.Proxy, listenPort int) (int, error) {
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

	lis, err := net.Listen("tcp", net.JoinHostPort(lip, strconv.Itoa(listenPort)))
	if err != nil {
		return 0, fmt.Errorf("监听反代端口失败: %w", err)
	}
	port := listenPort
	if port <= 0 {
		port = lis.Addr().(*net.TCPAddr).Port
	}

	tp := &frpcTCPProxy{
		name:    p.Name,
		backend: backend,
		lis:     lis,
		rec:     s.recordVisitorByProxy,
		logger:  s.logger,
		conns:   map[net.Conn]struct{}{},
		stopCh:  make(chan struct{}),
	}

	s.tcpProxyMu.Lock()
	s.tcpProxyByProxy[p.Name] = tp
	s.tcpProxyMu.Unlock()

	tp.wg.Add(1)
	go func() {
		defer tp.wg.Done()
		tp.acceptLoop()
	}()

	s.logger.Info("frpc tcp 反代已启动",
		zap.String("proxy", p.Name),
		zap.Int("listen_port", port),
		zap.String("backend", backend),
	)
	return port, nil
}

// stopFRPCTCPProxy 停止指定代理的本地反代层。
func (s *Server) stopFRPCTCPProxy(name string) {
	s.tcpProxyMu.Lock()
	tp := s.tcpProxyByProxy[name]
	delete(s.tcpProxyByProxy, name)
	s.tcpProxyMu.Unlock()
	if tp == nil {
		return
	}
	close(tp.stopCh)
	if tp.lis != nil {
		tp.lis.Close()
	}
	// 关闭所有活跃连接，让双向复制立即结束
	tp.mu.Lock()
	for c := range tp.conns {
		c.Close()
	}
	tp.mu.Unlock()
	tp.wg.Wait()
	s.logger.Info("frpc tcp 反代已停止", zap.String("proxy", name))
}

// syncFrpcTCPProxy 为 tcp 代理同步本地反代层，返回应持久化的 proxy（逻辑同 http 反代）。
func (s *Server) syncFrpcTCPProxy(p frpc.Proxy, origName string) frpc.Proxy {
	if origName != "" {
		s.stopFRPCTCPProxy(origName)
	}
	typ := strings.ToLower(strings.TrimSpace(p.Type))
	if typ != "tcp" || !p.ViaTunHook || p.LocalPort <= 0 {
		p.RealLocalPort = 0
		return p
	}
	realPort := p.LocalPort
	p.RealLocalPort = realPort
	port, err := s.startFRPCTCPProxy(p, 0) // 自动分配反代端口
	if err != nil {
		s.logger.Warn("frpc tcp 反代启动失败，回退直连",
			zap.String("proxy", p.Name), zap.Error(err))
		p.ViaTunHook = false
		p.RealLocalPort = 0
		return p
	}
	p.LocalPort = port
	return p
}

// startFRPCTCPProxies 启动时为所有已启用反代的 tcp 代理恢复本地反代层。
func (s *Server) startFRPCTCPProxies() {
	for _, p := range s.frpcMgr.LoadConfig().Proxies {
		typ := strings.ToLower(strings.TrimSpace(p.Type))
		if typ != "tcp" || !p.ViaTunHook || !p.Enabled || p.RealLocalPort <= 0 {
			continue
		}
		// 复用已持久化的反代端口（localPort）
		if _, err := s.startFRPCTCPProxy(p, p.LocalPort); err != nil {
			s.logger.Warn("frpc tcp 反代恢复失败",
				zap.String("proxy", p.Name), zap.Error(err))
		}
	}
}

// acceptLoop 接受 frpc 转发来的连接并逐个处理。
func (tp *frpcTCPProxy) acceptLoop() {
	for {
		conn, err := tp.lis.Accept()
		if err != nil {
			select {
			case <-tp.stopCh:
				return
			default:
				tp.logger.Error("frpc tcp 反代 accept 错误",
					zap.String("proxy", tp.name), zap.Error(err))
				continue
			}
		}
		tp.mu.Lock()
		tp.conns[conn] = struct{}{}
		tp.mu.Unlock()
		tp.wg.Add(1)
		go func(c net.Conn) {
			defer tp.wg.Done()
			tp.handleConn(c)
		}(conn)
	}
}

// handleConn 解析 PROXY 头，记录访客 IP，并把业务数据双向转发到真实后端。
func (tp *frpcTCPProxy) handleConn(conn net.Conn) {
	defer func() {
		conn.Close()
		tp.mu.Lock()
		delete(tp.conns, conn)
		tp.mu.Unlock()
	}()

	// 在固定超时内读取 PROXY 头
	conn.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
	br := bufio.NewReaderSize(conn, 4096)
	ip, port, hasProxy, err := parseProxyHeader(br)
	conn.SetReadDeadline(time.Time{})

	if err != nil || !hasProxy {
		// 无头（未配置 PROXY）或读取失败：直接转发已读数据，访客信息缺省（展示 -）
		tp.logger.Debug("frpc tcp 反代未解析到 PROXY 头",
			zap.String("proxy", tp.name),
			zap.Bool("has_proxy", hasProxy), zap.Error(err))
	} else if ip != "" {
		if tp.rec != nil {
			tp.rec(tp.name, ip, port)
		}
		tp.logger.Info("frpc tcp 反代访问",
			zap.String("proxy", tp.name),
			zap.String("visitor_ip", ip),
			zap.String("visitor_port", port),
			zap.String("backend", tp.backend),
		)
	}

	backend, derr := net.Dial("tcp", tp.backend)
	if derr != nil {
		tp.logger.Error("frpc tcp 反代连接后端失败",
			zap.String("proxy", tp.name),
			zap.String("backend", tp.backend), zap.Error(derr))
		return
	}
	defer backend.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(backend, br)
		backend.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, backend)
		conn.Close()
	}()
	wg.Wait()
}

// syncFrpcReverseProxy 按代理类型选择对应的反代层同步逻辑，返回应持久化的 proxy。
//   - http → http 反代层（读 X-Real-IP）；tcp → PROXY 解析反代层（读 PROXY v2 头）；
//   - 其余类型清空反代字段并停用可能残留的反代层。
func (s *Server) syncFrpcReverseProxy(p frpc.Proxy, origName string) frpc.Proxy {
	switch strings.ToLower(strings.TrimSpace(p.Type)) {
	case "http":
		return s.syncFrpcHTTPProxy(p, origName)
	case "tcp":
		return s.syncFrpcTCPProxy(p, origName)
	default:
		if origName != "" {
			s.stopFRPCHTTPProxy(origName)
			s.stopFRPCTCPProxy(origName)
		}
		p.RealLocalPort = 0
		return p
	}
}

// stopFRPCReverseProxy 停止指定代理的本地反代层（http 与 tcp 一并停止）。
func (s *Server) stopFRPCReverseProxy(name string) {
	if name == "" {
		return
	}
	s.stopFRPCHTTPProxy(name)
	s.stopFRPCTCPProxy(name)
}
