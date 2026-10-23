package web

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// netInterface 一个本机网卡（友好名称 + 接口名 + 主用 IPv4/IPv6 + MAC 物理地址 + 是否有公网 IP）。
type netInterface struct {
	Name       string `json:"name"`        // 系统接口名（如 wlo1 / enxc84d442992d2）
	Label      string `json:"label"`       // 友好名称（如 无线网卡 / USB 有线网卡）
	MAC        string `json:"mac"`         // 物理地址（MAC）
	IPv4       string `json:"ipv4"`        // 主用 IPv4（内网或公网）
	PublicIPv4 string `json:"public_ipv4"` // 公网 IPv4（网卡上真有的，NAT 后为空）
	IPv6       string `json:"ipv6"`
}

// friendlyIfaceLabel 生成网卡友好名称：按接口名前缀与设备路径（USB/PCI）推断类型。
func friendlyIfaceLabel(name string) string {
	if name == "lo" {
		return "回环"
	}
	// 设备路径含 usb 说明是 USB 网卡
	usb := false
	if p, err := os.Readlink("/sys/class/net/" + name); err == nil {
		usb = strings.Contains(p, "/usb")
	}
	switch {
	case strings.HasPrefix(name, "w"):
		return "无线网卡"
	case usb:
		return "USB 有线网卡"
	case strings.HasPrefix(name, "en"), strings.HasPrefix(name, "eth"):
		if usb {
			return "USB 有线网卡"
		}
		return "有线网卡"
	case strings.HasPrefix(name, "br-"), strings.HasPrefix(name, "docker"), strings.HasPrefix(name, "veth"), strings.HasPrefix(name, "tun"), strings.HasPrefix(name, "tap"):
		return "虚拟网卡"
	default:
		return name
	}
}

// handleNetworkInterfaces 枚举本机网卡及其主用 IPv4/IPv6 地址
// （跳过未启用、回环、链路本地、组播/未指定地址），供域名解析「选择地址来源」使用。
// 同时识别每个网卡上是否有公网 IPv4（排除私有、CGNAT、回环等）。
func (s *Server) handleNetworkInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := net.Interfaces()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("读取网卡列表失败: "+err.Error()))
		return
	}
	var out []netInterface
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		var v4, v6, pubV4 string
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				if ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsMulticast() || ip4.IsUnspecified() {
					continue
				}
				isPrivate := ip4.IsPrivate() // Go 1.21+ 已包含 RFC 1918 + CGNAT + 回环
				if !ip4.IsGlobalUnicast() || isPrivate {
					// 内网 IPv4（10/172.16-31/192.168/100.64-127 等）
					if v4 == "" {
						v4 = ip4.String()
					}
				} else {
					// 公网 IPv4（网卡上真有的）
					if pubV4 == "" {
						pubV4 = ip4.String()
					}
				}
			} else if ip6 := ip.To16(); ip6 != nil {
				if ip6.IsLinkLocalUnicast() || ip6.IsMulticast() || ip6.IsUnspecified() {
					continue
				}
				if v6 == "" {
					v6 = ip6.String()
				}
			}
		}
		// 如果网卡上只有公网 IPv4（直连 ISP 的 PPPoE 网卡），把公网 IP 也作为主 IPv4
		if v4 == "" && pubV4 != "" {
			v4 = pubV4
		}
		if v4 == "" && v6 == "" {
			continue
		}
		out = append(out, netInterface{
			Name:       ifc.Name,
			Label:      friendlyIfaceLabel(ifc.Name),
			MAC:        ifc.HardwareAddr.String(),
			IPv4:       v4,
			PublicIPv4: pubV4,
			IPv6:       v6,
		})
	}
	if out == nil {
		out = []netInterface{}
	}
	s.writeJSON(w, http.StatusOK, apiOK(out))
}
