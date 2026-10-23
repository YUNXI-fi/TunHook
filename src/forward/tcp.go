package forward

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type tcpClientStat struct {
	conn       net.Conn
	txBytes    int64
	rxBytes    int64
	lastTx     int64
	lastRx     int64
	lastSample time.Time
}

type TCPForwarder struct {
	localAddr  string
	remoteAddr string
	logger     *zap.Logger

	listener net.Listener
	mu       sync.Mutex
	conns    map[net.Conn]*tcpClientStat
	stopCh   chan struct{}
	stopped  bool
	txBytes  int64
	rxBytes  int64

	// tlsConfig 非空时以 TLS 方式监听（TCP + HTTPS 开关场景），解密后转发到后端
	tlsConfig *tls.Config

	// 进阶设置
	rateLimit   int  // 访问限速（KB/s/每连接，0=不限速）
	maxConns    int  // 单端口最大连接数（0=不限制）
	proxyProto  bool // 连接源站时发送 PROXY protocol v2 头
	tlsUpstream bool // 源端 TLS：以 TLS 方式连接源站
}

// TCPOpts TCP 转发器进阶选项。
type TCPOpts struct {
	RateLimit   int  // 访问限速（KB/s/每连接，0=不限速）
	MaxConns    int  // 单端口最大连接数（0=不限制）
	ProxyProto  bool // 连接源站时发送 PROXY protocol v2 头
	TLSUpstream bool // 源端 TLS：以 TLS 方式连接源站
}

// NewTCPForwarderOpts 按进阶选项创建 TCP 转发器。
func NewTCPForwarderOpts(localAddr, remoteAddr string, logger *zap.Logger, opts TCPOpts) *TCPForwarder {
	return &TCPForwarder{
		localAddr:   localAddr,
		remoteAddr:  remoteAddr,
		logger:      logger,
		conns:       make(map[net.Conn]*tcpClientStat),
		stopCh:      make(chan struct{}),
		rateLimit:   opts.RateLimit,
		maxConns:    opts.MaxConns,
		proxyProto:  opts.ProxyProto,
		tlsUpstream: opts.TLSUpstream,
	}
}

// compactListen 把监听地址 0.0.0.0:port 简写为 :port，用于通道日志展示。
func compactListen(addr string) string {
	if strings.HasPrefix(addr, "0.0.0.0:") {
		return addr[len("0.0.0.0"):]
	}
	return addr
}

// NewTLSTCPForwarderOpts 创建以 TLS 监听的 TCP 转发器（TCP + 自签名证书开启 HTTPS，访问端 TLS）。
func NewTLSTCPForwarderOpts(localAddr, remoteAddr, targetHost, certPEM, keyPEM string, logger *zap.Logger, opts TCPOpts) (f *TCPForwarder, outCert, outKey string, err error) {
	cert, outCert, outKey, err := loadTLSCertForListener(targetHost, certPEM, keyPEM)
	if err != nil {
		return nil, "", "", err
	}
	f = NewTCPForwarderOpts(localAddr, remoteAddr, logger, opts)
	f.tlsConfig = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
	}
	return f, outCert, outKey, nil
}

func (f *TCPForwarder) TXBytes() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.txBytes
}

func (f *TCPForwarder) RXBytes() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rxBytes
}

func (f *TCPForwarder) ConnCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.conns)
}

func (f *TCPForwarder) GetClients() []ClientInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	clients := make([]ClientInfo, 0, len(f.conns))
	for _, st := range f.conns {
		ci := ClientInfo{
			Addr:    st.conn.RemoteAddr().String(),
			TxBytes: st.txBytes,
			RxBytes: st.rxBytes,
		}
		ci.TxRate, ci.RxRate = rateTick(&st.lastTx, &st.lastRx, &st.lastSample, st.txBytes, st.rxBytes, now)
		clients = append(clients, ci)
	}
	return clients
}

type countingWriter struct {
	w     io.Writer
	count *int64
	extra *int64 // 可选：额外累加的计数器（per-client 统计）
	mu    *sync.Mutex
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.mu.Lock()
	*w.count += int64(n)
	if w.extra != nil {
		*w.extra += int64(n)
	}
	w.mu.Unlock()
	return n, err
}

func (f *TCPForwarder) Start() error {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			c.Control(func(fd uintptr) {
				// SO_REUSEPORT：允许与同端口穿透保活连接（出站连接）共享端口
				opErr = setReuseAddrPort(fd)
			})
			return opErr
		},
	}
	listener, err := lc.Listen(context.Background(), "tcp", f.localAddr)
	if err != nil {
		return err
	}
	if f.tlsConfig != nil {
		listener = tls.NewListener(listener, f.tlsConfig)
		f.logger.Info(fmt.Sprintf("转发服务开启(HTTPS) [tcp4@%s ===> %s]", compactListen(f.localAddr), f.remoteAddr))
	} else {
		f.logger.Info(fmt.Sprintf("转发服务开启 [tcp4@%s ===> %s]", compactListen(f.localAddr), f.remoteAddr))
	}
	f.listener = listener

	go f.acceptLoop()
	return nil
}

func (f *TCPForwarder) Stop() {
	f.mu.Lock()
	if f.stopped {
		f.mu.Unlock()
		return
	}
	f.stopped = true
	f.mu.Unlock()

	close(f.stopCh)

	if f.listener != nil {
		f.listener.Close()
	}

	f.mu.Lock()
	for conn := range f.conns {
		conn.Close()
	}
	f.mu.Unlock()
}

func (f *TCPForwarder) acceptLoop() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			select {
			case <-f.stopCh:
				return
			default:
				f.logger.Error(fmt.Sprintf("accept error: %v", err))
				continue
			}
		}

		f.mu.Lock()
		if f.maxConns > 0 && len(f.conns) >= f.maxConns {
			// 超过单端口最大连接数：拒绝新连接
			f.mu.Unlock()
			conn.Close()
			f.logger.Warn(fmt.Sprintf("已达最大连接数(%d)，拒绝新连接 [tcp4@%s]%s", f.maxConns, compactListen(f.localAddr), conn.RemoteAddr().String()))
			continue
		}
		st := &tcpClientStat{conn: conn}
		f.conns[conn] = st
		f.mu.Unlock()

		f.logger.Info(fmt.Sprintf("连接建立 [tcp4@%s]%s", compactListen(f.localAddr), conn.RemoteAddr().String()))

		go f.handleConn(conn, st)
	}
}

// rateLimiter 简单令牌桶：按速率发放字节预算，预算不足时 Sleep 限速。
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64 // bytes/sec
	budget float64
	last   time.Time
}

// newRateLimiter 按 KB/s 创建限速器（kbps<=0 返回 nil，表示不限速）。
func newRateLimiter(kbps int) *rateLimiter {
	if kbps <= 0 {
		return nil
	}
	return &rateLimiter{rate: float64(kbps) * 1024, budget: float64(kbps) * 1024, last: time.Now()}
}

// wait 为写入 n 字节预留配额，配额不足时阻塞至充足。
func (l *rateLimiter) wait(n int) {
	if l == nil || l.rate <= 0 {
		return
	}
	l.mu.Lock()
	now := time.Now()
	l.budget += now.Sub(l.last).Seconds() * l.rate
	if l.budget > l.rate {
		l.budget = l.rate
	}
	l.last = now
	if l.budget >= float64(n) {
		l.budget -= float64(n)
		l.mu.Unlock()
		return
	}
	sleep := time.Duration((float64(n) - l.budget) / l.rate * float64(time.Second))
	l.budget = 0
	l.mu.Unlock()
	time.Sleep(sleep)
	l.mu.Lock()
	l.last = time.Now()
	l.mu.Unlock()
}

// rateLimitedWriter 对写入做限速（每连接共享同一个限速器，限制连接总吞吐）。
type rateLimitedWriter struct {
	w io.Writer
	l *rateLimiter
}

func (rw *rateLimitedWriter) Write(p []byte) (int, error) {
	rw.l.wait(len(p))
	return rw.w.Write(p)
}

// writeProxyV2 向源站写入 PROXY protocol v2 头（携带客户端真实 IP:端口与本地监听 IP:端口）。
func writeProxyV2(conn net.Conn, clientAddr, localAddr net.Addr) error {
	var srcIP, dstIP net.IP
	var srcPort, dstPort int
	if ta, ok := clientAddr.(*net.TCPAddr); ok {
		srcIP, srcPort = ta.IP, ta.Port
	}
	if ta, ok := localAddr.(*net.TCPAddr); ok {
		dstIP, dstPort = ta.IP, ta.Port
	}
	if srcIP == nil || dstIP == nil {
		return nil // 取不到地址时不发送（不阻断转发）
	}
	hdr := make([]byte, 16)
	copy(hdr[0:12], []byte("\r\n\r\n\x00\r\nQUIT\n"))
	hdr[12] = 0x21 // PROXY protocol v2，PROXY 命令
	if v4 := srcIP.To4(); v4 != nil && dstIP.To4() != nil {
		hdr[13] = 0x11 // TCP over IPv4
		hdr[14], hdr[15] = 0, 12
		hdr = append(hdr, v4...)
		hdr = append(hdr, dstIP.To4()...)
		hdr = append(hdr, byte(srcPort>>8), byte(srcPort), byte(dstPort>>8), byte(dstPort))
	} else {
		hdr[13] = 0x21 // TCP over IPv6
		hdr[14], hdr[15] = 0, 36
		src16, dst16 := srcIP.To16(), dstIP.To16()
		if src16 == nil || dst16 == nil {
			return nil
		}
		hdr = append(hdr, src16...)
		hdr = append(hdr, dst16...)
		hdr = append(hdr, byte(srcPort>>8), byte(srcPort), byte(dstPort>>8), byte(dstPort))
	}
	_, err := conn.Write(hdr)
	return err
}

func (f *TCPForwarder) handleConn(clientConn net.Conn, st *tcpClientStat) {
	clientAddr := clientConn.RemoteAddr().String()
	defer func() {
		clientConn.Close()
		f.mu.Lock()
		delete(f.conns, clientConn)
		f.mu.Unlock()
		f.logger.Info(fmt.Sprintf("连接断开 [tcp4@%s]%s", compactListen(f.localAddr), clientAddr))
	}()

	remoteConn, err := net.Dial("tcp", f.remoteAddr)
	if err != nil {
		f.logger.Error(fmt.Sprintf("dial remote failed [%s]: %v", f.remoteAddr, err))
		return
	}
	defer remoteConn.Close()

	// 源端 TLS：以 TLS 方式连接源站（服务端证书不做校验，适配自签名/任意证书）
	if f.tlsUpstream {
		remoteConn = tls.Client(remoteConn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		if err := remoteConn.(*tls.Conn).Handshake(); err != nil {
			f.logger.Error(fmt.Sprintf("源端TLS握手失败 [%s]: %v", f.remoteAddr, err))
			return
		}
	}

	// PROXY protocol v2：向源站发送客户端真实地址（需在业务数据之前）
	if f.proxyProto {
		if err := writeProxyV2(remoteConn, clientConn.RemoteAddr(), clientConn.LocalAddr()); err != nil {
			f.logger.Warn(fmt.Sprintf("发送PROXY v2头失败 [%s]: %v", f.remoteAddr, err))
		}
	}

	f.logger.Debug("connection established",
		zap.String("client", clientConn.RemoteAddr().String()),
		zap.String("remote", f.remoteAddr),
	)

	// 访问限速：每连接共享令牌桶，限制连接总吞吐
	limiter := newRateLimiter(f.rateLimit)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(&countingWriter{w: &rateLimitedWriter{w: remoteConn, l: limiter}, count: &f.txBytes, extra: &st.txBytes, mu: &f.mu}, clientConn)
		remoteConn.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(&countingWriter{w: &rateLimitedWriter{w: clientConn, l: limiter}, count: &f.rxBytes, extra: &st.rxBytes, mu: &f.mu}, remoteConn)
		clientConn.Close()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-f.stopCh:
	}
}

func (f *TCPForwarder) Addr() net.Addr {
	if f.listener != nil {
		return f.listener.Addr()
	}
	return nil
}
