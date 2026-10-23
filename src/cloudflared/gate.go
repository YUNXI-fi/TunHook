package cloudflared

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tunhook/errpage"

	"go.uber.org/zap"
)

// Gate 本地转发闸门：cloudflared 指向闸门，闸门再转发到真实本地服务。
//
// 为什么需要它：临时入口（quick）的域名由 Cloudflare 每次启动随机下发，
// 重启 cloudflared 就会换域名。要做到「暂停但不断开隧道、也不换访问地址」，
// 只能在回源链路上插一层本程序可控的转发：暂停时它直接返回 503 页面，
// 而 cloudflared 进程与它对 Cloudflare 的连接完全不动。
//
// 只监听 127.0.0.1，不对局域网暴露。
type Gate struct {
	target string // 真实本地服务地址（如 http://127.0.0.1:19094）
	logger *zap.Logger
	proxy  *httputil.ReverseProxy

	mu     sync.RWMutex
	paused bool
	port   int
	srv    *http.Server

	// 流量与连接计数：转发列表（STUN/frpc 同口径）按两次轮询的差值算实时速率。
	// 用原子量而不是走锁：计数发生在每个请求的热路径上。
	txBytes atomic.Int64 // 发往真实本地服务的字节（上行）
	rxBytes atomic.Int64 // 从真实本地服务收到的字节（下行）
	active  atomic.Int64 // 正在处理的请求数
}

// NewGate 创建闸门（此时尚未监听），target 为真实本地服务地址。
func NewGate(target string, logger *zap.Logger) *Gate {
	return &Gate{target: target, logger: logger, proxy: newReverseProxy(target)}
}

// newReverseProxy 构造到 target 的反向代理；地址不合法时返回 nil（由 Start 报错）。
//
// 用 ReverseProxy 而不是自己 copy：它天然支持流式响应与 WebSocket 升级，
// 隧道里跑着的东西不一定是普通页面请求。
func newReverseProxy(target string) *httputil.ReverseProxy {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.SetXForwarded()
		},
	}
}

// Start 在 127.0.0.1 的空闲端口上监听，返回闸门地址（如 http://127.0.0.1:7453）。
func (g *Gate) Start() (string, error) {
	if g.proxy == nil {
		return "", fmt.Errorf("本地服务地址不合法: %q", g.target)
	}
	// 与内核 metrics 端口共用同一套分配登记：闸门同样长期监听，必须避免重复分配
	port, err := freePort()
	if err != nil {
		return "", err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		releasePort(port)
		return "", err
	}
	srv := &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second}
	g.mu.Lock()
	g.port, g.srv = port, srv
	g.mu.Unlock()

	go func() {
		if err := srv.Serve(countingListener{Listener: ln, up: &g.txBytes, down: &g.rxBytes}); err != nil &&
			!errors.Is(err, http.ErrServerClosed) && g.logger != nil {
			g.logger.Warn("本地转发闸门退出", zap.Int("port", port), zap.Error(err))
		}
	}()
	if g.logger != nil {
		g.logger.Info("本地转发闸门已就绪",
			zap.Int("port", port), zap.String("target", g.target))
	}
	return fmt.Sprintf("http://127.0.0.1:%d", port), nil
}

// Stop 关闭闸门并释放端口（可重复调用）。
func (g *Gate) Stop() {
	g.mu.Lock()
	srv, port := g.srv, g.port
	g.srv, g.port = nil, 0
	g.mu.Unlock()
	if srv == nil {
		return
	}
	// Close 而非 Shutdown：闸门没有需要等待的长连接，立即断开即可，不阻塞调用方
	_ = srv.Close()
	releasePort(port)
	if g.logger != nil {
		g.logger.Info("本地转发闸门已关闭", zap.Int("port", port))
	}
}

// Addr 闸门监听地址（如 127.0.0.1:7451）；未监听时为空。
func (g *Gate) Addr() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.port == 0 {
		return ""
	}
	return "127.0.0.1:" + strconv.Itoa(g.port)
}

// Counters 闸门的累计上行/下行字节与当前活跃请求数。
func (g *Gate) Counters() (tx, rx, active int64) {
	return g.txBytes.Load(), g.rxBytes.Load(), g.active.Load()
}

// SetTarget 就地替换转发目标（仅临时入口有闸门）。
//
// 有了它，「改本地回源」不必重启 cloudflared——临时入口的访问地址由 Cloudflare 每次启动重新下发，
// 重启就会换域名，而改动回源其实只是闸门往哪转发的问题。
func (g *Gate) SetTarget(target string) error {
	proxy := newReverseProxy(strings.TrimSpace(target))
	if proxy == nil {
		return fmt.Errorf("本地服务地址不合法: %q", target)
	}
	g.mu.Lock()
	g.target, g.proxy = target, proxy
	g.mu.Unlock()
	if g.logger != nil {
		g.logger.Info("本地转发闸门已切换回源", zap.String("target", target))
	}
	return nil
}

// Paused 闸门当前是否处于暂停。
func (g *Gate) Paused() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.paused
}

// SetPaused 切换暂停状态：暂停后所有请求直接回 503 页面。
func (g *Gate) SetPaused(v bool) {
	g.mu.Lock()
	changed := g.paused != v
	g.paused = v
	g.mu.Unlock()
	if changed && g.logger != nil {
		g.logger.Info("本地转发闸门状态变更", zap.Bool("paused", v))
	}
}

// ServeHTTP 暂停时回 503，否则透传到真实本地服务。
func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 代理对象在 SetTarget 时会被整体替换，必须与读锁配对取用
	g.mu.RLock()
	paused, proxy := g.paused, g.proxy
	g.mu.RUnlock()
	if paused {
		// 复用「错误页面」模块里用户自定义的 503：非浏览器请求自动回落为纯文本
		errpage.Write(w, r, http.StatusServiceUnavailable, "隧道已暂停")
		return
	}
	g.active.Add(1)
	defer g.active.Add(-1)
	proxy.ServeHTTP(w, r)
}

// countingListener 在连接层统计字节。
//
// 放在连接层而不是包装请求体/响应体：只有这样才能把报文头、流式响应、
// WebSocket 帧都算进去（按请求体统计时，GET 的上行恒为 0，看着像坏了）。
// 统计口径与「端口转发」列表里 STUN / frpc 的 socket 字节数一致。
type countingListener struct {
	net.Listener
	up   *atomic.Int64 // 上行：访客 → 本地服务
	down *atomic.Int64 // 下行：本地服务 → 访客
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return countingConn{Conn: c, up: l.up, down: l.down}, nil
}

type countingConn struct {
	net.Conn
	up   *atomic.Int64
	down *atomic.Int64
}

// Read 是从访客方向读入 = 上行；Write 是写回访客 = 下行。
func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.up.Add(int64(n))
	return n, err
}

func (c countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.down.Add(int64(n))
	return n, err
}
