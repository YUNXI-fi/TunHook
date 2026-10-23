package forward

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type UDPForwarder struct {
	localAddr  string
	remoteAddr string
	logger     *zap.Logger

	conn     *net.UDPConn
	sessions map[string]*udpSession
	mu       sync.Mutex
	stopCh   chan struct{}
	stopped  bool
	txBytes  int64
	rxBytes  int64

	// 进阶设置
	sessionTimeout time.Duration // 会话超时（默认 30s）
	maxSessions    int           // 单端口最大会话数（默认 32）
	maxBlockLen    int           // 最大块长度（默认 1500）
}

// UDPOpts UDP 转发器进阶选项。
type UDPOpts struct {
	SessionTimeoutMs int // 会话超时（毫秒，默认 30000）
	MaxSessions      int // 单端口最大会话数（默认 32）
	MaxBlockLen      int // 最大块长度（默认 1500）
}

type udpSession struct {
	remoteConn *net.UDPConn
	lastActive time.Time
	txBytes    int64
	rxBytes    int64
	lastTx     int64
	lastRx     int64
	lastSample time.Time
}

// NewUDPForwarderOpts 按进阶选项创建 UDP 转发器。
func NewUDPForwarderOpts(localAddr, remoteAddr string, logger *zap.Logger, opts UDPOpts) *UDPForwarder {
	sessionTimeout := 30 * time.Second
	if opts.SessionTimeoutMs > 0 {
		sessionTimeout = time.Duration(opts.SessionTimeoutMs) * time.Millisecond
	}
	maxSessions := 32
	if opts.MaxSessions > 0 {
		maxSessions = opts.MaxSessions
	}
	maxBlockLen := 1500
	if opts.MaxBlockLen > 0 {
		maxBlockLen = opts.MaxBlockLen
	}
	return &UDPForwarder{
		localAddr:      localAddr,
		remoteAddr:     remoteAddr,
		logger:         logger,
		sessions:       make(map[string]*udpSession),
		stopCh:         make(chan struct{}),
		sessionTimeout: sessionTimeout,
		maxSessions:    maxSessions,
		maxBlockLen:    maxBlockLen,
	}
}

func (f *UDPForwarder) TXBytes() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.txBytes
}

func (f *UDPForwarder) RXBytes() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rxBytes
}

func (f *UDPForwarder) ConnCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sessions)
}

func (f *UDPForwarder) GetClients() []ClientInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	clients := make([]ClientInfo, 0, len(f.sessions))
	for key, s := range f.sessions {
		ci := ClientInfo{
			Addr:    key,
			TxBytes: s.txBytes,
			RxBytes: s.rxBytes,
		}
		ci.TxRate, ci.RxRate = rateTick(&s.lastTx, &s.lastRx, &s.lastSample, s.txBytes, s.rxBytes, now)
		clients = append(clients, ci)
	}
	return clients
}

func (f *UDPForwarder) Start() error {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			c.Control(func(fd uintptr) {
				// SO_REUSEPORT：允许与同端口穿透保活 socket 共享端口
				opErr = setReuseAddrPort(fd)
			})
			return opErr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", f.localAddr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return fmt.Errorf("unexpected connection type: %T", pc)
	}
	f.conn = conn

	f.logger.Info(fmt.Sprintf("转发服务开启 [udp4@%s ===> %s]", compactListen(f.localAddr), f.remoteAddr))

	go f.readLoop()
	go f.cleanupLoop()

	return nil
}

func (f *UDPForwarder) Stop() {
	f.mu.Lock()
	if f.stopped {
		f.mu.Unlock()
		return
	}
	f.stopped = true
	f.mu.Unlock()

	close(f.stopCh)

	if f.conn != nil {
		f.conn.Close()
	}

	f.mu.Lock()
	for _, s := range f.sessions {
		s.remoteConn.Close()
	}
	f.mu.Unlock()
}

func (f *UDPForwarder) readLoop() {
	buf := make([]byte, f.maxBlockLen)
	for {
		n, clientAddr, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-f.stopCh:
				return
			default:
				f.logger.Error(fmt.Sprintf("read error: %v", err))
				continue
			}
		}

		key := clientAddr.String()
		session, err := f.getOrCreateSession(key)
		if err != nil {
			f.logger.Error(fmt.Sprintf("create session failed [%s]: %v", key, err))
			continue
		}

		// remoteConn 是已连接 socket（见 getOrCreateSession），只发往目标远端，直接用 Write
		if _, err := session.remoteConn.Write(buf[:n]); err != nil {
			f.logger.Error(fmt.Sprintf("write to remote failed: %v", err))
		}
		f.mu.Lock()
		f.txBytes += int64(n)
		session.txBytes += int64(n)
		f.mu.Unlock()
	}
}

func (f *UDPForwarder) getOrCreateSession(key string) (*udpSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if s, ok := f.sessions[key]; ok {
		s.lastActive = time.Now()
		return s, nil
	}

	// 超过单端口最大会话数：拒绝新会话
	if f.maxSessions > 0 && len(f.sessions) >= f.maxSessions {
		return nil, fmt.Errorf("已达最大会话数(%d)，拒绝新会话 [%s]", f.maxSessions, key)
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", f.remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve remote address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, err
	}

	s := &udpSession{
		remoteConn: conn,
		lastActive: time.Now(),
	}
	f.sessions[key] = s

	f.logger.Info(fmt.Sprintf("UDP会话建立 [udp4@%s]%s", compactListen(f.localAddr), key))

	go f.relayBack(key, s)

	return s, nil
}

func (f *UDPForwarder) relayBack(key string, session *udpSession) {
	buf := make([]byte, f.maxBlockLen)
	for {
		n, err := session.remoteConn.Read(buf)
		if err != nil {
			return
		}

		clientAddr, err := net.ResolveUDPAddr("udp", key)
		if err != nil {
			return
		}

		if _, err := f.conn.WriteToUDP(buf[:n], clientAddr); err != nil {
			return
		}

		f.mu.Lock()
		f.rxBytes += int64(n)
		session.rxBytes += int64(n)
		session.lastActive = time.Now()
		f.mu.Unlock()
	}
}

func (f *UDPForwarder) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-f.stopCh:
			return
		case <-ticker.C:
			f.mu.Lock()
			now := time.Now()
			for key, s := range f.sessions {
				if now.Sub(s.lastActive) > f.sessionTimeout {
					s.remoteConn.Close()
					delete(f.sessions, key)
					f.logger.Info(fmt.Sprintf("UDP会话超时 [udp4@%s]%s", compactListen(f.localAddr), key))
				}
			}
			f.mu.Unlock()
		}
	}
}

func (f *UDPForwarder) Addr() net.Addr {
	if f.conn != nil {
		return f.conn.LocalAddr()
	}
	return nil
}
