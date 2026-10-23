// Package stunprobe 基于 STUN 实现 NAT 行为与公网映射探测。
//
// 采用 RFC 5780 的方法判定 NAT 的映射行为（mapping behavior）与过滤行为
// （filtering behavior），据此推断本机是否处于 CGNAT、能否被公网直连。
// 依赖栈：github.com/pion/stun/v3。
package stunprobe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/pion/stun/v3"
	"go.uber.org/zap"
)

// Behavior NAT 行为（RFC 4787 术语）。
type Behavior string

const (
	BehaviorUnknown             Behavior = "unknown"
	BehaviorEndpointIndependent  Behavior = "endpoint independent"
	BehaviorAddressDependent     Behavior = "address dependent"
	BehaviorAddressPortDependent Behavior = "address and port dependent"
)

// Result STUN 探测结果（直接作为 /api/stun/probe 的成功 data 返回）。
type Result struct {
	LocalIP          string   `json:"local_ip"`           // 本机出站 IPv4
	Server           string   `json:"server"`             // 使用的 STUN 服务器
	PublicIP         string   `json:"public_ip"`          // NAT 分配的公网映射地址
	PublicPort       int      `json:"public_port"`        // NAT 分配的公网映射端口
	MappingBehavior  Behavior `json:"mapping_behavior"`   // 映射行为
	FilteringBehavior Behavior `json:"filtering_behavior"` // 过滤行为
	IsCGNAT          bool     `json:"is_cgnat"`           // 是否为 CGNAT/私有映射（公网无法直连）
	DirectOK         bool     `json:"direct_ok"`          // 是否可能被公网直连
	FullSupport      bool     `json:"full_support"`       // 服务器是否支持完整 RFC5780 行为检测
	Error            string   `json:"error,omitempty"`    // 检测过程中的非致命提示
}

// errNoResponse 等待 STUN 响应超时（配合过滤行为判定）。
var errNoResponse = errors.New("等待 STUN 响应超时")

// errNoOtherAddress 服务器不支持 OTHER-ADDRESS，无法判定完整 NAT 行为。
var errNoOtherAddress = errors.New("该 STUN 服务器不支持 RFC5780 OTHER-ADDRESS")

// txn 一次 STUN UDP 事务通道：固定本地端口，用于连续绑定请求。
type txn struct {
	conn   *net.UDPConn
	remote *net.UDPAddr
}

// newTxn 解析服务器地址并建立 UDP 连接。
func newTxn(server string) (*txn, error) {
	raddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, fmt.Errorf("解析 STUN 服务器失败: %w", err)
	}
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("创建 UDP 连接失败: %w", err)
	}
	return &txn{conn: c, remote: raddr}, nil
}

// roundTrip 发送绑定请求并等待响应；超时返回 errNoResponse。
func (t *txn) roundTrip(msg *stun.Message, addr net.Addr, timeout time.Duration) (*stun.Message, error) {
	if _, err := t.conn.WriteTo(msg.Raw, addr); err != nil {
		return nil, fmt.Errorf("发送 STUN 请求失败: %w", err)
	}
	_ = t.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	n, _, err := t.conn.ReadFrom(buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, errNoResponse
		}
		return nil, fmt.Errorf("读取 STUN 响应失败: %w", err)
	}
	m := new(stun.Message)
	m.Raw = buf[:n]
	if err := m.Decode(); err != nil {
		return nil, fmt.Errorf("STUN 响应解析失败: %w", err)
	}
	return m, nil
}

// bindingReq 构造一次绑定请求（每次新事务 ID）。
func bindingReq() *stun.Message {
	return stun.MustBuild(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
}

// changeReq 构造带 CHANGE-REQUEST 的绑定请求。
// RFC 5780：属性后 4 字节中 0x04 表示 change IP，0x02 表示 change port。
func changeReq(changeIP, changePort bool) *stun.Message {
	m := stun.MustBuild(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
	v := byte(0)
	if changeIP {
		v |= 0x04
	}
	if changePort {
		v |= 0x02
	}
	m.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, v})
	return m
}

// xorAddr 从响应中提取 XOR-MAPPED-ADDRESS，缺少返回 nil。
func xorAddr(m *stun.Message) *stun.XORMappedAddress {
	var a stun.XORMappedAddress
	if err := a.GetFrom(m); err != nil {
		return nil
	}
	return &a
}

// otherAddr 从响应中提取 OTHER-ADDRESS，缺少返回 nil。
func otherAddr(m *stun.Message) *stun.OtherAddress {
	var a stun.OtherAddress
	if err := a.GetFrom(m); err != nil {
		return nil
	}
	return &a
}

// Probe 对单个 STUN 服务器执行 NAT 行为与公网映射探测。
// timeout 为单次等待响应超时，logger 用于调试日志（可为 nil 调整内部）。
func Probe(server string, timeout time.Duration, logger *zap.Logger) (*Result, error) {
	t, err := newTxn(server)
	if err != nil {
		return nil, err
	}
	defer t.conn.Close()

	outIP, err := outboundIP()
	if err != nil {
		outIP = "127.0.0.1"
	}
	res := &Result{
		LocalIP:          outIP,
		Server:           server,
		MappingBehavior:  BehaviorUnknown,
		FilteringBehavior: BehaviorUnknown,
	}

	// Test I：普通绑定请求，拿公网映射地址，并尝试获取 OTHER-ADDRESS。
	resp, err := t.roundTrip(bindingReq(), t.remote, timeout)
	if err != nil {
		return nil, fmt.Errorf("STUN 绑定请求失败: %w", err)
	}
	mapped := xorAddr(resp)
	if mapped == nil {
		return nil, errors.New("STUN 响应缺少 XOR-MAPPED-ADDRESS")
	}
	res.PublicIP = mapped.IP.String()
	res.PublicPort = mapped.Port

	other := otherAddr(resp)
	if other == nil {
		// 服务器不支持完整 RFC5780：仅返回映射 + CGNAT 判定，行为标记 unknown。
		res.FullSupport = false
		res.Error = errNoOtherAddress.Error()
		res.IsCGNAT, res.DirectOK = ClassifyPublicIP(res.PublicIP)
		if logger != nil {
			logger.Debug("STUN 服务器不支持 OTHER-ADDRESS，跳过 NAT 行为判定", zap.String("server", server))
		}
		return res, nil
	}
	res.FullSupport = true

	// 无 NAT 时映射地址等于本地地址（需校验非通配/非回环）。
	if !isUnboundLocal(res.PublicIP) && res.PublicIP == res.LocalIP {
		res.MappingBehavior = BehaviorEndpointIndependent
		res.FilteringBehavior = BehaviorEndpointIndependent
		res.IsCGNAT, res.DirectOK = ClassifyPublicIP(res.PublicIP)
		return res, nil
	}

	// ---- 映射行为（RFC5780 4.3）----
	// Test II：发到 OTHER 地址但保持主端口。
	oaddr := &net.UDPAddr{IP: other.IP, Port: t.remote.Port}
	resp2, err := t.roundTrip(bindingReq(), oaddr, timeout)
	if err == nil && xorAddr(resp2) != nil {
		if xorAddr(resp2).String() == mapped.String() {
			res.MappingBehavior = BehaviorEndpointIndependent
		} else {
			// Test III：发到 OTHER 地址与端口。
			resp3, err3 := t.roundTrip(bindingReq(), &net.UDPAddr{IP: other.IP, Port: other.Port}, timeout)
			if err3 == nil && xorAddr(resp3) != nil {
				if xorAddr(resp3).String() == xorAddr(resp2).String() {
					res.MappingBehavior = BehaviorAddressDependent
				} else {
					res.MappingBehavior = BehaviorAddressPortDependent
				}
			} else {
				res.Error = "映射行为第三测试失败: " + errNoOtherAddress.Error()
			}
		}
	} else {
		res.Error = "映射行为第二测试失败: " + errNoOtherAddress.Error()
	}

	// ---- 过滤行为（RFC5780 4.4）----
	if _, err := t.roundTrip(changeReq(true, true), t.remote, timeout); err == nil {
		res.FilteringBehavior = BehaviorEndpointIndependent
	} else if errors.Is(err, errNoResponse) {
		// Test III：仅改端口。
		if _, err2 := t.roundTrip(changeReq(false, true), t.remote, timeout); err2 == nil {
			res.FilteringBehavior = BehaviorAddressDependent
		} else if errors.Is(err2, errNoResponse) {
			res.FilteringBehavior = BehaviorAddressPortDependent
		} else {
			res.Error = "过滤行为第三测试失败: " + err2.Error()
		}
	} else {
		res.Error = "过滤行为第二测试失败: " + err.Error()
	}

	res.IsCGNAT, res.DirectOK = ClassifyPublicIP(res.PublicIP)
	return res, nil
}

// outboundIP 探测本机出站 IPv4（经 UDP 探路，强制 IPv4 路径）。
func outboundIP() (string, error) {
	c, err := net.Dial("udp4", "119.29.29.29:53")
	if err != nil {
		return "", err
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP.To4()
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1)
	}
	return ip.String(), nil
}

// ClassifyPublicIP 判断地址是否为 CGNAT/私有（无法公网直连）以及理论可直连性。
// 供 STUN 探测与公网地址检测（web 层 NAT 状态）共用。
func ClassifyPublicIP(ipStr string) (isCGNAT, directOK bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, false
	}
	v4 := ip.To4()
	if v4 == nil {
		// IPv6：以非本地/非 ULA 视为可直连，这里主要服务 IPv4。
		return false, !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	}
	// 100.64.0.0/10：CGNAT 共享地址段（RFC 6598）。
	if v4[0] == 100 && v4[1]&0xc0 == 0x40 {
		return true, false
	}
	if v4.IsPrivate() || v4.IsLoopback() || v4.IsLinkLocalUnicast() || v4.IsMulticast() {
		return true, false
	}
	return false, true
}

// isUnboundLocal 判断地址是否为 0.0.0.0 等非具体地址。
func isUnboundLocal(s string) bool {
	ip := net.ParseIP(s)
	return ip == nil || ip.IsUnspecified()
}

// Ping 快速检测 STUN 服务器连通性：发送一次 Binding 请求并等待 BindingSuccess
// 响应，返回往返耗时与是否可达（仅判可达，不做行为检测）。耗时不含 DNS 解析；
// 超时/解析失败/无响应均视为不可达。
func Ping(server string, timeout time.Duration) (time.Duration, bool) {
	t, err := newTxn(server)
	if err != nil {
		return 0, false
	}
	defer t.conn.Close()
	start := time.Now() // 仅计 STUN 往返，DNS 解析耗时另计
	m, err := t.roundTrip(bindingReq(), t.remote, timeout)
	if err != nil || m.Type != stun.BindingSuccess {
		return 0, false
	}
	return time.Since(start), true
}

// PingTCP TCP 版连通检测：按 RFC 5389 §7.2.2 在裸 TCP 上做一次 Binding 事务
//（STUN-over-TCP 用消息自带的 20 字节头分帧，没有 RFC 4571 那种 2 字节长度前缀）。
//
// 直接在裸连接上收发，不使用 pion/stun 的 Client：后者会启动常驻读循环
// readUntilClosed，在 Read 返回任何错误（对端断开的 EOF/RST、读超时）时既不退出也
// 不退让，会全速空转直到 Close。一次性连通检测同样避免引入该行为。
func PingTCP(server string, timeout time.Duration) (time.Duration, bool) {
	conn, err := net.DialTimeout("tcp", server, timeout)
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, false
	}
	req := bindingReq()
	start := time.Now()
	// 直接写裸 STUN 报文
	if _, err := conn.Write(req.Raw); err != nil {
		return 0, false
	}
	// 读 20 字节固定头，再按 message length 读剩余部分
	var head [20]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return 0, false
	}
	n := int(binary.BigEndian.Uint16(head[2:4]))
	if n == 0 || n > 4096 {
		return 0, false
	}
	raw := make([]byte, 20+n)
	copy(raw, head[:])
	if _, err := io.ReadFull(conn, raw[20:]); err != nil {
		return 0, false
	}
	msg := new(stun.Message)
	msg.Raw = raw
	if err := msg.Decode(); err != nil {
		return 0, false
	}
	if msg.TransactionID != req.TransactionID || msg.Type != stun.BindingSuccess {
		return 0, false
	}
	return time.Since(start), true
}

