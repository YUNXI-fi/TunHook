// UPnP IGD 端口映射：打洞通道启动后自动在网关（家用路由器）上添加端口转发，
// 让公网入站流量能穿过 NAT 到达本机监听端口；通道停止时自动删除映射。
//
// 背景：单端 STUN 保活只能维持 NAT 出向映射，端口受限锥 / 对称 NAT 下公网入站
// SYN 仍被丢弃。在网关上做端口转发是确定性的入站打通方式（要求本机与公网出口
// 之间只有这一层家用 NAT；运营商侧再 NAT 时需联系运营商获取公网 IP）。
//
// 依赖 github.com/huin/goupnp（UPnP 事实标准库，仅做 SSDP 发现与 SOAP 调用）。
// 映射采用有限租期 + 周期续约：程序异常退出后残留映射会由网关自动过期回收。

package stunhole

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
)

// errNoIGD 局域网内未发现 UPnP IGD 网关（路由器未开启 UPnP 或不支持）。
var errNoIGD = errors.New("未发现支持 UPnP IGD 的网关")

// isUPnPConflict 判断是否为网关返回的 718 ConflictInMappingEntry
// （该外部端口已被局域网内其他设备 / 其他程序映射）。
func isUPnPConflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), "718")
}

const (
	upnpLease    = 10 * time.Minute // 向网关申请的映射租期
	upnpRenew    = 5 * time.Minute  // 续约间隔（租期一半，留足重试余量）
	upnpRetry    = 30 * time.Second // 发现 / 添加失败后的重试间隔
	upnpCallTO   = 6 * time.Second  // 单次 SSDP / SOAP 调用超时
	upnpDeleteTO = 3 * time.Second  // 停止时删除映射的最长等待（避免卡住 Stop）
	upnpDescMax  = 40               // 映射描述最大长度（部分网关有长度限制）
)

// portMapper UPnP IGD 连接服务的最小抽象，WANIPConnection 与 WANPPPConnection
// 生成客户端的同名方法签名一致，天然满足该接口。
type portMapper interface {
	AddPortMapping(newRemoteHost string, newExternalPort uint16, newProtocol string,
		newInternalPort uint16, newInternalClient string, newEnabled bool,
		newPortMappingDescription string, newLeaseDuration uint32) error
	DeletePortMapping(newRemoteHost string, newExternalPort uint16, newProtocol string) error
	GetExternalIPAddress() (newExternalIPAddress string, err error)
}

// upnpDesc 生成网关侧映射描述，截断并去除换行（防止 XML 注入与网关长度限制）。
func upnpDesc(name string) string {
	r := strings.NewReplacer("\r", " ", "\n", " ")
	s := strings.TrimSpace(r.Replace(name))
	if s == "" {
		s = "stunhole"
	}
	if len(s) > upnpDescMax {
		s = s[:upnpDescMax]
	}
	return "TunHook:" + s
}

// igdLocationHost 提取 IGD 描述地址的主机部分（网关 IP），两类连接客户端都内嵌
// goupnp.ServiceClient（含 Location）。
func igdLocationHost(m portMapper) string {
	switch c := m.(type) {
	case *internetgateway2.WANIPConnection1:
		return c.Location.Hostname()
	case *internetgateway2.WANPPPConnection1:
		return c.Location.Hostname()
	}
	return ""
}

// discoverIGD 通过 SSDP 发现局域网内的 IGD 并返回 WAN 连接服务客户端与网关地址。
// 优先 WANIPConnection（路由 / 动态 IP 上网），回退 WANPPPConnection（PPPoE）。
func discoverIGD(ctx context.Context) (portMapper, string, error) {
	dctx, cancel := context.WithTimeout(ctx, upnpCallTO)
	defer cancel()

	if clients, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(dctx); err == nil {
		for _, c := range clients {
			if c != nil {
				return c, igdLocationHost(c), nil
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}

	pctx, pcancel := context.WithTimeout(ctx, upnpCallTO)
	defer pcancel()
	if clients, _, err := internetgateway2.NewWANPPPConnection1ClientsCtx(pctx); err == nil {
		for _, c := range clients {
			if c != nil {
				return c, igdLocationHost(c), nil
			}
		}
	}
	return nil, "", errNoIGD
}

// sourceIPv4 返回与 dst 通信时内核选用的本机源 IPv4（UDP 探路，不实际发包）。
// 多网卡同子网时网卡枚举顺序不可靠，必须以路由表选择为准。
func sourceIPv4(dst string) net.IP {
	c, err := net.Dial("udp4", dst)
	if err != nil {
		return nil
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.To4()
}

// chooseInternalIP 选择 AddPortMapping 的内网客户端地址：
// 通道显式绑定了具体网卡 / IP 时用绑定地址（用户意图）；
// 0.0.0.0 全网卡监听时取访问网关的实际源 IPv4；探测失败再回退网卡枚举。
func chooseInternalIP(bind net.IP, gateway string) string {
	if bind != nil && !bind.IsUnspecified() {
		if v4 := bind.To4(); v4 != nil {
			return v4.String()
		}
	}
	if net.ParseIP(gateway) != nil {
		if src := sourceIPv4(net.JoinHostPort(gateway, "1900")); src != nil {
			return src.String()
		}
	}
	if lan := autoLocalIPv4(); lan != nil {
		return lan.String()
	}
	if bind != nil {
		return bind.String()
	}
	return ""
}

// upnpInternalIP 返回当前通道添加映射时使用的内网客户端地址。
func (r *runtime) upnpInternalIP(gateway string) string {
	return chooseInternalIP(r.bindAddr(), gateway)
}

// upnpLoop 维护一条与通道同端口、同协议的网关端口映射：发现 IGD → 添加 →
// 周期续约 → 停止时删除。失败均为非致命（不影响本地转发），按 upnpRetry 重试。
func (r *runtime) upnpLoop(ctx context.Context) {
	proto := strings.ToUpper(r.cfg.Proto)
	port := uint16(r.cfg.ListenPort)
	desc := upnpDesc(r.cfg.Name)
	leaseSec := uint32(upnpLease / time.Second)

	var active portMapper // 当前已成功添加映射的客户端（停止时用于删除）
	gateway := ""         // 当前 IGD 网关地址（用于选择内网源 IP）
	ok := false           // 上一轮是否已成功（状态边沿控制日志，避免重试刷屏）
	warned := false       // 当前失败阶段是否已记录过告警（避免重试刷屏）

	// add 在指定客户端上添加 / 续约映射。
	add := func(m portMapper) error {
		return m.AddPortMapping("", port, proto, port, r.upnpInternalIP(gateway), true, desc, leaseSec)
	}
	// remove 删除网关映射，超时即放弃（网关可能已离线；映射有租期也会自动过期）。
	remove := func(m portMapper) {
		if m == nil {
			return
		}
		done := make(chan struct{})
		go func() {
			_ = m.DeletePortMapping("", port, proto)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(upnpDeleteTO):
		}
	}
	defer func() { remove(active) }()

	for ctx.Err() == nil {
		m, gw, err := discoverIGD(ctx)
		if err != nil {
			if !warned {
				r.owner.addLogL(r.cfg.ID, "warn", "UPnP：未发现可用网关（%v），将重试", err)
				warned = true
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(upnpRetry):
			}
			continue
		}
		gateway = gw
		if err := add(m); err != nil {
			if !warned {
				if isUPnPConflict(err) {
					r.owner.addLogL(r.cfg.ID, "warn",
						"UPnP：网关拒绝映射端口 %d（端口已被其他设备占用，或网关安全模式要求内网地址与请求来源 IP 一致）", port)
				} else {
					r.owner.addLogL(r.cfg.ID, "warn", "UPnP：添加 %s %d 端口映射失败（%v），将重试", proto, port, err)
				}
				warned = true
			}
			active = nil
			select {
			case <-ctx.Done():
				return
			case <-time.After(upnpRetry):
			}
			continue
		}
		active = m
		if !ok {
			r.owner.addLogL(r.cfg.ID, "info", "UPnP：已在网关添加 %s 端口映射（%d → %s:%d），公网可经打洞状态页地址访问",
				proto, port, r.upnpInternalIP(gateway), port)
			ok = true
		}
		warned = false

		t := time.NewTicker(upnpRenew)
		renewFail := false
		for !renewFail {
			select {
			case <-ctx.Done():
				t.Stop()
				return // defer 中删除映射
			case <-t.C:
				if err := add(m); err != nil {
					r.owner.addLogL(r.cfg.ID, "warn", "UPnP：映射续约失败（%v），重新发现网关", err)
					remove(active)
					active = nil
					ok = false
					warned = true
					renewFail = true
				}
			}
		}
		t.Stop()
	}
}
