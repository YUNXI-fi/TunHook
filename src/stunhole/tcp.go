// TCP 打洞暴露：基于 go-reuseport 端口复用（借鉴 LinkStar 思路，独立实现）。
//
// 结构：
//   - reuseport.Listen 本地转发监听（接收公网入站连接 → 转发到目标）
//   - reuseport.Dial 建立到 STUN 服务器的 TCP 保活连接（维持 NAT 映射），
//     两者经 SO_REUSEPORT 共存于同一本地端口；保活连接断开自动重拨。
package stunhole

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-reuseport"
	"github.com/pion/stun/v3"
)

// rateLimiter 简单令牌桶限速器（字节/秒，双向转发共享；rate<=0 时不限速）。
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64   // 令牌生成速率（字节/秒）
	tokens float64   // 当前令牌数
	last   time.Time // 上次补充时间
}

// newRateLimiter 创建限速器；rate<=0 表示不限速（wait 直接返回）。
func newRateLimiter(rate int64) *rateLimiter {
	return &rateLimiter{rate: float64(rate), last: time.Now()}
}

// wait 阻塞直到获取 n 字节令牌。
func (l *rateLimiter) wait(n int) {
	if l == nil || l.rate <= 0 {
		return
	}
	for {
		l.mu.Lock()
		now := time.Now()
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		if max := l.rate; l.tokens > max {
			l.tokens = max // 桶容量 = 1 秒配额
		}
		l.last = now
		if l.tokens >= float64(n) {
			l.tokens -= float64(n)
			l.mu.Unlock()
			return
		}
		needSec := (float64(n) - l.tokens) / l.rate
		l.mu.Unlock()
		time.Sleep(time.Duration(needSec * float64(time.Second)))
	}
}

// startTCP 启动 TCP 转发监听与 STUN-over-TCP 保活探测。
func (r *runtime) startTCP(ctx context.Context) error {
	ln, err := reuseport.Listen("tcp4", net.JoinHostPort(r.bindAddr().String(), strconv.Itoa(r.cfg.ListenPort)))
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.ln = ln
	r.mu.Unlock()
	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.tcpAcceptLoop(ln) }()
	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.tcpProbeLoop(ctx) }()
	return nil
}

// tcpAcceptLoop 接受外部连接并转发到目标；超过通道 MaxConns 上限时直接拒绝（0=不限）。
func (r *runtime) tcpAcceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return // 监听已关闭
		}
		if max := r.maxConns(); max > 0 && r.conns.Load() >= int64(max) {
			c.Close() // 超出最大连接数，拒绝
			continue
		}
		r.wg.Add(1)
		go func(conn net.Conn) { defer r.wg.Done(); r.tcpRelay(conn) }(c)
	}
}

// maxConns 返回通道最大连接数（锁内读取，0=不限）。
func (r *runtime) maxConns() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg.MaxConns
}

// tcpRelay 在外部连接与目标之间双向转发。
func (r *runtime) tcpRelay(conn net.Conn) {
	defer conn.Close()
	defer r.conns.Add(-1)
	r.conns.Add(1)
	dst, err := net.Dial("tcp", r.cfg.Target)
	if err != nil {
		return
	}
	defer dst.Close()
	done := make(chan struct{}, 2)
	// 外部→目标 计下行，目标→外部 计上行（双向共享通道限速器）
	go func() { relayCopy(dst, conn, &r.rx, r.limiter); dst.Close(); done <- struct{}{} }()
	go func() { relayCopy(conn, dst, &r.tx, r.limiter); conn.Close(); done <- struct{}{} }()
	<-done
	<-done
}

// relayCopy 单方向复制直到出错/关闭，统计转发的字节数；通道配置限速时按令牌桶节流。
func relayCopy(dst, src net.Conn, count *atomic.Int64, limiter *rateLimiter) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			limiter.wait(n)
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			count.Add(int64(n))
		}
		if err != nil {
			return
		}
	}
}

// tcpProbeLoop 维持一条 STUN-over-TCP 保活连接（复用监听端口），周期发 Binding
// 刷新映射；保活失败自动切换到下一个支持 TCP 的 STUN 服务器重拨。
func (r *runtime) tcpProbeLoop(ctx context.Context) {
	localAddr := net.JoinHostPort(r.bindAddr().String(), strconv.Itoa(r.cfg.ListenPort))
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		server := r.currentServer()
		if err := r.tcpKeepaliveOnce(ctx, localAddr, server); err != nil {
			fails := r.bumpFailure()
			limit := r.maxFailures()
			if fails >= limit {
				// 连续失败达上限：熔断停止，不再重拨（autoStopByFailure 会取消 ctx 并回收资源）
				if r.owner != nil {
					r.owner.addLogL(r.cfg.ID, "error", "STUN 服务器 %s 保活失败（%v），连续失败 %d/%d 已达上限", server, err, fails, limit)
					r.owner.autoStopByFailure(r.cfg.ID, fails)
				}
				return
			}
			r.setStatus("error", "TCP STUN 保活失败: "+err.Error())
			next := r.rotateServer()
			// 服务器轮换是正常流转，切换目标已在上面的 warn 事件日志中；清空 LastError
			// 避免「已切换 STUN 服务器」作为错误常驻状态列
			r.setStatus("starting", "")
			if r.owner != nil {
				r.owner.addLogL(r.cfg.ID, "warn", "STUN 服务器 %s 保活失败（%v），自动切换 → %s（连续失败 %d/%d）", server, err, next, fails, limit)
			}
		}
		// 等待重拨间隔或退出
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// probeTimeout 单次 STUN 探测的等待上限；超时即放弃本轮并让上层重拨。
// 启动阶段不在单个坏服务器上久等，3 秒足够覆盖正常公网 RTT。
const probeTimeout = 3 * time.Second

// stunTCPBinding 在一条已建立的 TCP 连接上完成一次 STUN Binding 事务
//（RFC 5389 §7.2.2：STUN over TCP 直接用消息自身的 20 字节头做分帧，不是 RFC 4571），
// 返回服务器观测到的公网映射 ip:port。
//
// 刻意不使用 pion/stun 的 Client：stun.NewClient 会启动一个常驻后台读循环 readUntilClosed，
// 该循环在 Read 返回任何错误（对端断开导致的 EOF/RST、以及读超时都算）时既不退出也不退让，
// 于是全速空转、每轮还分配一个消息对象——公网 STUN 服务器一旦主动断开空闲保活连接，
// 每条 TCP 通道就会吃满一个 CPU 核（实测连接保持时 1 秒 12ms、对端断开后 1 秒 915ms）。
// 保活连接空闲期本就不需要读任何东西，因此这里直接在裸连接上收发：连接平时没有任何读
// goroutine，只在每个保活点做一次请求/响应；任何读写错误立即返回交由上层重连，
// 结构上不存在忙转窗口。
func stunTCPBinding(conn net.Conn, timeout time.Duration) (string, error) {
	req := stun.MustBuild(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	defer conn.SetDeadline(time.Time{}) // 超时仅作用于本轮事务，结束后恢复阻塞语义

	// 请求即裸 STUN 报文（pion 库在 TCP 上同样不加任何长度前缀）。
	// 注意：RFC 4571 的 2 字节长度前缀是 RTP-over-TCP 的分帧，与 STUN 无关；
	// STUN-over-TCP 的消息边界由消息头里的 message length 字段决定。
	if _, err := conn.Write(req.Raw); err != nil {
		return "", fmt.Errorf("发送 Binding 请求: %w", err)
	}

	// 先读 20 字节固定头：类型(2)+长度(2)+magic cookie(4)+transactionID(12)
	var head [20]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return "", fmt.Errorf("读取响应头: %w", err)
	}
	n := int(binary.BigEndian.Uint16(head[2:4]))
	if n == 0 || n > 4096 {
		return "", fmt.Errorf("响应消息长度非法: %d", n)
	}
	// 读出剩余部分并与头部拼成完整报文，交给 pion 解码（含 magic cookie / 指纹校验）
	raw := make([]byte, 20+n)
	copy(raw, head[:])
	if _, err := io.ReadFull(conn, raw[20:]); err != nil {
		return "", fmt.Errorf("读取响应体: %w", err)
	}
	msg := new(stun.Message)
	msg.Raw = raw
	if err := msg.Decode(); err != nil {
		return "", fmt.Errorf("解析 STUN 响应: %w", err)
	}
	if msg.TransactionID != req.TransactionID {
		return "", errors.New("响应事务 ID 不匹配")
	}
	if msg.Type != stun.BindingSuccess {
		return "", fmt.Errorf("非 BindingSuccess 响应: %s", msg.Type)
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(msg); err != nil {
		return "", fmt.Errorf("读取公网映射地址: %w", err)
	}
	if xor.IP == nil {
		return "", errors.New("公网映射地址为空")
	}
	return net.JoinHostPort(xor.IP.String(), strconv.Itoa(xor.Port)), nil
}

// tcpKeepaliveOnce 建立一次到 server 的保活连接并在其上周期发送 Binding，直到出错或 ctx 结束。
func (r *runtime) tcpKeepaliveOnce(ctx context.Context, localAddr, server string) error {
	// 带超时的拨号：STUN 服务器不响应时中止连接（否则内核级 SYN 重试会挂起约 2 分钟，
	// 卡死状态更新与 Stop/删除）。DialTimeout 不感知 ctx，超时后循环会在下一轮检查 ctx。
	conn, err := reuseport.DialTimeout("tcp4", localAddr, server, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	// 连接全程复用、且没有任何常驻读 goroutine：只在保活点做一次 STUN 事务。
	// 连接被对端断开时，下一次事务的读/写立即报错，本函数返回后由 tcpProbeLoop 重连
	//（必要时切换 STUN 服务器），不会出现后台读循环空转。
	checked := false
	probe := func() error {
		addr, err := stunTCPBinding(conn, probeTimeout)
		if err != nil {
			return err
		}
		r.rememberServer(server)
		r.applyPublic(addr)
		if !checked {
			checked = true
			go func(pub string) {
				d := net.Dialer{Timeout: 3 * time.Second}
				c, err := d.Dial("tcp4", pub)
				if err != nil {
					if r.owner != nil {
						r.owner.addLogL(r.cfg.ID, "warn", "公网自检未通过（部分 NAT 不支持回环，可忽略）：%v", err)
					}
					return
				}
				c.Close()
			}(addr)
		}
		return nil
	}

	if err := probe(); err != nil {
		return err
	}
	// 保活：同一连接上周期重发 Binding
	t := time.NewTicker(r.owner.Keepalive())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := probe(); err != nil {
				return err // 连接断开/超时 → 重拨
			}
		}
	}
}
