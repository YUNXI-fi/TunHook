package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// PortScanItem 一条扫描到的端口信息（本机监听或局域网主机开放端口）。
type PortScanItem struct {
	Port      int     `json:"port"`       // 监听端口
	Protocol  string  `json:"protocol"`   // 协议: tcp / tcp6 / udp / udp6
	LocalAddr string  `json:"local_addr"` // 监听地址（本机模式为监听 IP，局域网模式为对端主机 IP）
	PID       int     `json:"pid"`        // 占用进程 PID（无权限时为 0，局域网扫描恒为 0）
	Process   string  `json:"process"`    // 进程名称（无权限时为空，局域网扫描为空）
	Service   string  `json:"service"`    // 服务名称（由 /etc/services 或内置表推断）
	WebTitle  string  `json:"web_title"`  // 探测到的网页标题（非 Web 服务或探测失败时为空）
	LatencyMS float64 `json:"latency_ms"` // TCP 建连延时（毫秒，仅局域网/远程主机探测有值；本机监听扫描恒为 0）
}

// procNetFile 各协议对应的 /proc/net 文件与协议标签。
var procNetFiles = []struct {
	file     string
	protocol string
}{
	{"/proc/net/tcp", "tcp"},
	{"/proc/net/tcp6", "tcp6"},
	{"/proc/net/udp", "udp"},
	{"/proc/net/udp6", "udp6"},
}

// commonServices 常见服务端口 → 服务名称（/etc/services 缺失或未覆盖时的兜底）。
var commonServices = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
	110: "pop3", 111: "rpcbind", 123: "ntp", 137: "netbios", 138: "netbios",
	139: "netbios", 143: "imap", 161: "snmp", 443: "https", 445: "smb",
	465: "smtps", 514: "syslog", 548: "afp", 587: "smtp", 631: "ipp",
	873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
	1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
	5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
	8443: "https-alt", 9000: "php-fpm", 9090: "cockpit", 27017: "mongodb",
	5000: "upnp", 5001: "synology-ssl", 6690: "syncthing", 8384: "syncthing-web",
	8096: "jellyfin", 8920: "jellyfin-ssl", 32400: "plex",
}

// handlePortScan 扫描端口并返回结果。
// 支持参数：
//
//	mode=local（默认）：扫描本机监听端口，并探测网页标题；
//	mode=lan（可带 range=起始IP-结束IP）：自动识别宿主机所在局域网网段并扫描常见开放端口；
//	mode=ip&host=IP：扫描指定 IP（本机 IP 返回全部监听端口，其他主机探测常见开放端口）。
func (s *Server) handlePortScan(w http.ResponseWriter, r *http.Request) {
	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
	if mode == "" {
		mode = "local"
	}
	// 默认只扫描/显示 IPv4；勾选「包含 IPv6」后本地扫描才包含 tcp6/udp6 监听地址
	includeV6 := r.URL.Query().Get("ipv6") == "1" || strings.EqualFold(r.URL.Query().Get("ipv6"), "true")
	// ports 参数：逗号分隔的端口列表（前端按服务分组选择后传入）；为空则用默认常见端口集
	ports := parsePortList(r.URL.Query().Get("ports"))
	// hosts=1：仅探测网段内哪些 IP 被使用（主机在线），不扫描端口（「扫描IP」）
	hostsOnly := r.URL.Query().Get("hosts") == "1" || strings.EqualFold(r.URL.Query().Get("hosts"), "true")
	switch mode {
	case "lan":
		ipRange := strings.TrimSpace(r.URL.Query().Get("range"))
		if ipRange == "" {
			// 未指定范围时自动识别宿主机所在局域网网段并扫描
			det, err := detectLanRange()
			if err != nil {
				s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
				return
			}
			ipRange = det.Start + "-" + det.End
		}
		// hosts=1：仅探测在线主机（「扫描IP」），不推端口明细
		if hostsOnly {
			if flusher, ok := w.(http.Flusher); ok {
				w.Header().Set("Content-Type", "application/x-ndjson")
				w.WriteHeader(http.StatusOK)
				enc := json.NewEncoder(w)
				var mu sync.Mutex
				push := func(v map[string]interface{}) {
					mu.Lock()
					defer mu.Unlock()
					_ = enc.Encode(v)
					flusher.Flush()
				}
				err := scanLanHostsStream(ipRange, func(ip string) {
					push(map[string]interface{}{"type": "host", "data": ip})
				}, func(ip string) {
					push(map[string]interface{}{"type": "checked", "data": ip})
				}, func(done, total int64) {
					push(map[string]interface{}{"type": "progress", "data": map[string]interface{}{"done": done, "total": total}})
				})
				if err != nil {
					push(map[string]interface{}{"type": "error", "message": err.Error()})
					return
				}
				push(map[string]interface{}{"type": "done"})
				return
			}
			s.writeJSON(w, http.StatusOK, apiErr("当前连接不支持流式响应"))
			return
		}
		// 流式返回（NDJSON）：每发现一个开放端口立即推送一条 {"type":"item","data":{...}}，
		// 扫描结束推送 {"type":"done"}，出错推送 {"type":"error","message":...}。
		// 前端据此实时渲染已扫描到的端口，无需等待整个扫描完成。
		// 网页标题探测异步执行（全局限流 lanTitleProbeWorkers），完成后推送
		// {"type":"update","data":{...}} 回填，避免阻塞端口探测主流程。
		if flusher, ok := w.(http.Flusher); ok {
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.WriteHeader(http.StatusOK)
			enc := json.NewEncoder(w)
			var mu sync.Mutex
			push := func(v map[string]interface{}) {
				mu.Lock()
				defer mu.Unlock()
				_ = enc.Encode(v)
				flusher.Flush()
			}
			var (
				titleWG  sync.WaitGroup
				titleSem = make(chan struct{}, lanTitleProbeWorkers)
			)
			err := scanLanPortsStream(ipRange, ports, func(it PortScanItem) {
				push(map[string]interface{}{"type": "item", "data": it})
				titleWG.Add(1)
				titleSem <- struct{}{}
				go func(it PortScanItem) {
					defer titleWG.Done()
					defer func() { <-titleSem }()
					if title := probeWebTitle(it.LocalAddr, it.Port); title != "" {
						it.WebTitle = title
						push(map[string]interface{}{"type": "update", "data": it})
					}
				}(it)
			}, func(ip string) {
				push(map[string]interface{}{"type": "checked", "data": ip})
			}, func(done, total int64) {
				push(map[string]interface{}{"type": "progress", "data": map[string]interface{}{"done": done, "total": total}})
			}, func(start, end string) {
				push(map[string]interface{}{"type": "scanning", "data": map[string]interface{}{"start": start, "end": end}})
			})
			titleWG.Wait() // 等全部标题回填完成再推 done，避免前端提前收尾
			if err != nil {
				push(map[string]interface{}{"type": "error", "message": err.Error()})
				return
			}
			push(map[string]interface{}{"type": "done"})
			return
		}
		// 不支持流式（非 HTTP 场景）时回退为一次性返回
		items, err := scanLanPorts(ipRange, ports)
		if err != nil {
			s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
			return
		}
		s.writeJSON(w, http.StatusOK, apiOK(items))
	case "docker":
		s.streamDockerPorts(w)
	case "ip":
		// 单 IP 扫描：目标为本机时返回全部监听端口（含进程信息），否则探测该主机的常见开放端口。
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		if host == "" {
			s.writeJSON(w, http.StatusOK, apiErr("请输入要扫描的 IP 地址"))
			return
		}
		// 目标为本机/回环/网卡地址：复用本机监听端口流式扫描（先推端口再回填网页标题，与 mode=local 一致）
		if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified() || isLocalInterfaceIP(ip)) {
			s.streamLocalPorts(w, includeV6)
			return
		}
		// 远程主机：NDJSON 流式返回，每发现一个开放端口立即推送，网页标题异步回填 update，
		// 全端口（ports=all，65535 个）扫描耗时较长，流式可边扫边看并支持中途停止。
		flusher, ok := w.(http.Flusher)
		if !ok {
			// 不支持流式（非 HTTP 场景）时回退为一次性返回
			items, err := scanHostPorts(host, includeV6, ports)
			if err != nil {
				s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
				return
			}
			s.writeJSON(w, http.StatusOK, apiOK(items))
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		var emitMu sync.Mutex
		push := func(v map[string]interface{}) {
			emitMu.Lock()
			defer emitMu.Unlock()
			_ = enc.Encode(v)
			flusher.Flush()
		}
		_, err := scanHostPortsStream(host, ports,
			func(it PortScanItem) { push(map[string]interface{}{"type": "item", "data": it}) },
			func(it PortScanItem) { push(map[string]interface{}{"type": "update", "data": it}) },
			func(done, total int64) {
				push(map[string]interface{}{"type": "progress", "data": map[string]interface{}{"done": done, "total": total}})
			},
		)
		if err != nil {
			push(map[string]interface{}{"type": "error", "message": err.Error()})
			return
		}
		push(map[string]interface{}{"type": "done"})
	default:
		s.streamLocalPorts(w, includeV6)
	}
}

// portSnapshot 本机端口扫描的持久化快照（数据库 KV 覆盖式保存，每次扫描完成自动更新）。
type portSnapshot struct {
	UpdatedAt string         `json:"updated_at"` // 快照生成时间
	Items     []PortScanItem `json:"items"`      // 扫描结果（含网页标题）
}

// portSnapshotKey 本机端口快照在 settings KV 中的键名。
const portSnapshotKey = "portscan.local_snapshot"

// saveLocalPortSnapshot 把本机端口扫描结果写入数据库，供下次进入页面时立即展示；
// 写库失败仅丢弃快照（属锦上添花数据），不影响本次扫描响应。
func (s *Server) saveLocalPortSnapshot(items []PortScanItem) {
	snap := portSnapshot{UpdatedAt: time.Now().Format("2006-01-02 15:04:05"), Items: items}
	if err := s.store.SetJSON(portSnapshotKey, snap); err != nil && s.logger != nil {
		s.logger.Warn("保存本机端口快照失败", zap.Error(err))
	}
}

// handlePortSnapshot 返回上次本机端口扫描的持久化快照（无快照或解析失败时 data 为 null）。
func (s *Server) handlePortSnapshot(w http.ResponseWriter, r *http.Request) {
	raw, err := s.store.GetSetting(portSnapshotKey)
	if err != nil || raw == "" {
		s.writeJSON(w, http.StatusOK, apiOK(nil))
		return
	}
	var snap portSnapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		s.writeJSON(w, http.StatusOK, apiOK(nil))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(snap))
}

// streamLocalPorts 本机监听端口扫描流式返回：
// 先推送全部监听端口（NDJSON item），再并发探测网页标题，每条探测完成即推送
// update 事件（按 端口+协议+监听地址 匹配），前端据此实时刷新对应条目的网页标题。
// 扫描完成后把最终结果持久化到数据库（用户每次进入自动刷新快照）。
func (s *Server) streamLocalPorts(w http.ResponseWriter, includeV6 bool) {
	items := scanListeningPorts(includeV6)
	flusher, ok := w.(http.Flusher)
	if !ok {
		// 不支持流式（非 HTTP 场景）时回退一次性返回
		probeLocalWebTitles(items)
		s.saveLocalPortSnapshot(items)
		s.writeJSON(w, http.StatusOK, apiOK(items))
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	var mu sync.Mutex
	emit := func(typ string, data interface{}) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(map[string]interface{}{"type": typ, "data": data})
		flusher.Flush()
	}
	// 先推送全部监听端口（扫描本身很快，网页标题探测才是耗时项）
	for _, it := range items {
		emit("item", it)
	}
	// 并发探测网页标题，完成一条推送一条 update
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i := range items {
		if !strings.HasPrefix(items[i].Protocol, "tcp") {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			items[i].WebTitle = probeWebTitle(items[i].LocalAddr, items[i].Port)
			emit("update", items[i])
		}(i)
	}
	wg.Wait()
	s.saveLocalPortSnapshot(items)
	emit("done", nil)
}

// streamDockerPorts Docker 端口映射扫描流式返回：解析到一条映射即推送一条 item，
// 完成后推送 done；扫描出错推送 error。
func (s *Server) streamDockerPorts(w http.ResponseWriter) {
	items, err := scanDockerPorts()
	flusher, ok := w.(http.Flusher)
	if !ok {
		if err != nil {
			s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
			return
		}
		s.writeJSON(w, http.StatusOK, apiOK(items))
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	var mu sync.Mutex
	emit := func(typ string, data interface{}) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(map[string]interface{}{"type": typ, "data": data})
		flusher.Flush()
	}
	if err != nil {
		// 与局域网扫描一致：error 事件携带 message 字段，前端直接展示
		mu.Lock()
		_ = enc.Encode(map[string]interface{}{"type": "error", "message": err.Error()})
		flusher.Flush()
		mu.Unlock()
		return
	}
	for _, it := range items {
		emit("item", it)
	}
	emit("done", nil)
}

// handleLanInfo 返回宿主机所在局域网的自动识别结果（网段/起始-结束地址/数量），供前端展示。
func (s *Server) handleLanInfo(w http.ResponseWriter, r *http.Request) {
	info, err := detectLanRange()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(info))
}

// lanRangeInfo 宿主机局域网网段信息（自动识别结果）。
type lanRangeInfo struct {
	IP      string `json:"ip"`      // 本机局域网 IPv4
	Netmask string `json:"netmask"` // 子网掩码（如 255.255.255.0）
	CIDR    string `json:"cidr"`    // 网段 CIDR（如 192.168.1.0/24）
	Start   string `json:"start"`   // 可用起始地址（网络号 +1）
	End     string `json:"end"`     // 可用结束地址（广播地址 -1）
	Count   int    `json:"count"`   // 实际扫描地址数
	Capped  bool   `json:"capped"`  // 网段过大被截断到 lanScanMaxIPs
}

// detectLanRange 自动识别宿主机所在局域网的 IPv4 网段：
// 遍历本机已启用的非回环网卡地址，优先选择承载默认路由的真实局域网网卡；
// 其次选择 RFC1918 私网地址，并跳过 docker 网桥/veth/隧道等虚拟网卡
// （这类网段不是宿主机所在局域网）；网段过大时从起始地址截断到 lanScanMaxIPs。
func detectLanRange() (lanRangeInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return lanRangeInfo{}, fmt.Errorf("读取网卡信息失败: %v", err)
	}
	defRoute := defaultRouteIface() // 默认路由所在网卡 = 真实上联局域网网卡
	type cand struct {
		info  lanRangeInfo
		ones  int
		score int
	}
	var best *cand
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		virtual := isVirtualIface(ifc.Name)
		isDefRoute := defRoute != "" && ifc.Name == defRoute
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil {
				continue
			}
			ones, bits := ipn.Mask.Size()
			if bits != 32 || ones <= 0 || ones >= 32 {
				continue
			}
			// 跳过链路本地（169.254/16）
			if ip4[0] == 169 && ip4[1] == 254 {
				continue
			}
			network := ip4ToUint32(ip4.Mask(ipn.Mask))
			broadcast := network | ^ipMaskToUint32(ipn.Mask)
			if broadcast <= network+1 {
				continue // 无可用主机地址
			}
			startU, endU := network+1, broadcast-1
			count := int(endU - startU + 1)
			capped := false
			if count > lanScanMaxIPs {
				capped = true
				count = lanScanMaxIPs
				endU = startU + uint32(lanScanMaxIPs-1)
			}
			// 候选优先级：默认路由网卡 > 私网非虚拟 > 私网虚拟 > 其他非虚拟 > 其余；
			// 同级时优先选择网段更小（前缀更长）的地址，避免 docker 等大网段抢占真实局域网。
			score := lanRangeScore(isDefRoute, virtual, isPrivateIPv4(ip4))
			info := lanRangeInfo{
				IP:      ip4.String(),
				Netmask: net.IP(ipn.Mask).String(),
				CIDR:    fmt.Sprintf("%s/%d", net.IP(ip4.Mask(ipn.Mask)).String(), ones),
				Start:   uint32ToIP4(startU).String(),
				End:     uint32ToIP4(endU).String(),
				Count:   count,
				Capped:  capped,
			}
			if best == nil || score < best.score || (score == best.score && ones > best.ones) {
				b := info
				best = &cand{info: b, ones: ones, score: score}
			}
		}
	}
	if best == nil {
		return lanRangeInfo{}, fmt.Errorf("未检测到可用的局域网网段，请手动指定 IP 范围")
	}
	return best.info, nil
}

// defaultRouteIface 返回承载默认路由（0.0.0.0/0）的网卡名，用于确定真实上联局域网网卡。
func defaultRouteIface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

// isVirtualIface 判断网卡是否为虚拟接口（docker 网桥/容器网卡、隧道、VPN 等），
// 这类接口上的网段不应作为「宿主机所在局域网」的自动识别结果。
func isVirtualIface(name string) bool {
	name = strings.ToLower(name)
	for _, p := range []string{
		"docker", "veth", "vnet", "virbr", "tun", "tap", "wg", "tailscale",
		"zt", "utun", "lxc", "cni", "flannel", "kube", "podman", "br-",
	} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	switch name {
	case "lo", "docker0", "docker_gwbridge":
		return true
	}
	return false
}

// lanRangeScore 计算网段候选的优先级分数（越小越优先）：
// 默认路由真实网卡 0 < 默认路由虚拟网卡 1 < 私网真实网卡 2 < 私网虚拟网卡 3 < 公网真实网卡 4 < 公网虚拟网卡 5。
func lanRangeScore(isDefRoute, virtual, priv bool) int {
	switch {
	case isDefRoute && !virtual:
		return 0
	case isDefRoute:
		return 1
	case priv && !virtual:
		return 2
	case priv:
		return 3
	case !virtual:
		return 4
	default:
		return 5
	}
}

// ip4ToUint32 把 IPv4 转为 uint32（小端网络序换算为大端数值）。
func ip4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIP4 把 uint32 数值还原为 IPv4 地址。
func uint32ToIP4(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// ipMaskToUint32 把 IPv4 掩码转为 uint32。
func ipMaskToUint32(m net.IPMask) uint32 {
	if len(m) < 4 {
		return 0
	}
	return uint32(m[0])<<24 | uint32(m[1])<<16 | uint32(m[2])<<8 | uint32(m[3])
}

// isPrivateIPv4 判断是否为 RFC1918 私网地址（10/8、172.16/12、192.168/16）。
func isPrivateIPv4(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	return ip[0] == 10 ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168)
}

// handlePortCheck 检查指定端口是否被本机占用（TCP/UDP，含 IPv4/IPv6）。
// 通过读取 /proc/net 下各协议文件的监听状态判断，供前端实时显示端口占用情况。
func (s *Server) handlePortCheck(w http.ResponseWriter, r *http.Request) {
	portStr := r.URL.Query().Get("port")
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的端口号"))
		return
	}
	occupied := isPortListening(port)
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"port":      port,
		"occupied":  occupied,
		"available": !occupied,
	}))
}

// isPortListening 判断指定端口是否已被本机任意进程监听（TCP/UDP 各协议族）。
func isPortListening(port int) bool {
	for _, pf := range procNetFiles {
		data, err := os.ReadFile(pf.file)
		if err != nil {
			continue
		}
		isUDP := strings.HasPrefix(pf.protocol, "udp")
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			state := fields[3]
			// TCP 仅统计 LISTEN(0A)；UDP 无监听状态，取所有已绑定套接字(07)
			if (isUDP && state != "07") || (!isUDP && state != "0A") {
				continue
			}
			_, p := parseProcNetAddr(fields[1])
			if p == port {
				return true
			}
		}
	}
	return false
}

// handlePortFree 返回一个未被占用的端口：
//   - 指定 prefer 端口空闲时直接返回；
//   - 否则在 50000-60000 范围内随机选择一个未被占用的端口；
//   - 该范围全部被占用时回退为随机端口（不做占用校验）。
//
// 供前端在「指定端口被占用时自动选择空闲端口」使用。
func (s *Server) handlePortFree(w http.ResponseWriter, r *http.Request) {
	prefer := 0
	if p, err := strconv.Atoi(r.URL.Query().Get("prefer")); err == nil && p >= 1 && p <= 65535 {
		prefer = p
	}
	if prefer > 0 && !isPortListening(prefer) {
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"port": prefer, "from_range": false}))
		return
	}
	// 随机选 50000-60000 范围内的空闲端口，最多尝试 40 次
	for i := 0; i < 40; i++ {
		p := 50000 + rand.Intn(10001)
		if !isPortListening(p) {
			s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"port": p, "from_range": true}))
			return
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"port": 50000 + rand.Intn(10001), "from_range": true, "unchecked": true}))
}

// scanDockerPorts 读取本机 Docker 容器及其 host 端口映射，输出为端口列表。
// 通过 `docker ps -a` 获取所有容器（含已停止）的端口映射；
// 未安装 Docker 或当前用户无权限访问 Docker 时返回错误。
func scanDockerPorts() ([]PortScanItem, error) {
	out, err := exec.Command("docker", "ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}").Output()
	if err != nil {
		return nil, fmt.Errorf("无法读取 Docker 容器：%v（请确认已安装 Docker 且当前用户有权限访问）", err)
	}
	var items []PortScanItem
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		name, image, ports := fields[1], fields[2], fields[3]
		if strings.TrimSpace(ports) == "" {
			continue
		}
		seen := map[string]bool{}
		for _, m := range strings.Split(ports, ", ") {
			// 仅解析带 host 端口映射的项（如 "0.0.0.0:8080->80/tcp"）；仅 "80/tcp"（EXPOSE）无 host 端口，跳过
			sep := strings.Index(m, "->")
			if sep < 0 {
				continue
			}
			hostPart := strings.TrimSpace(m[:sep])
			containerPart := strings.TrimSpace(m[sep+2:])
			proto := "tcp"
			if p := strings.SplitN(containerPart, "/", 2); len(p) == 2 {
				proto = p[1]
			}
			hostIP, hostPort := "0.0.0.0", 0
			if hp := strings.Split(hostPart, ":"); len(hp) >= 2 {
				if p, err := strconv.Atoi(hp[len(hp)-1]); err == nil {
					hostPort = p
				}
				ip := strings.Join(hp[:len(hp)-1], ":")
				if ip != "" && ip != ":::" && ip != "::" {
					hostIP = ip
				}
			}
			if hostPort == 0 {
				continue
			}
			key := strconv.Itoa(hostPort) + "/" + proto + "/" + hostIP // 双栈映射（0.0.0.0 与 :::）去重
			if seen[key] {
				continue
			}
			seen[key] = true
			items = append(items, PortScanItem{
				Port:      hostPort,
				Protocol:  proto,
				LocalAddr: hostIP,
				Process:   name,
				Service:   name + " (" + image + ")", // 容器名（镜像名），便于在列表中区分容器
			})
		}
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("未发现映射了 host 端口的 Docker 容器")
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Port != items[j].Port {
			return items[i].Port < items[j].Port
		}
		return items[i].Protocol < items[j].Protocol
	})
	return items, nil
}

// ============= 局域网扫描 =============

const (
	lanScanMaxIPs = 1024 // 单次局域网扫描最大 IP 数量（防误填超大范围）

	lanHostConcurrency   = 96                     // 少端口模式：主机间并发上限（主机内端口串行，避免同主机 ARP/SYN 风暴丢包漏报）
	lanSerialPortMax     = 64                     // 待检端口数不超过该值时用少端口模式（主机间并发 + 主机内串行），否则用全局任务池模式
	lanGlobalWorkers     = 1536                   // 全端口模式：全局探测 worker 数
	lanTCPTimeout        = 300 * time.Millisecond // 单次 TCP 探测超时（SYN-ACK/RST 均由内核亚毫秒响应，裕量充足）
	lanTimeoutSkip       = 8                      // 未确认在线的主机连续「不确定」次数达到该值即跳过剩余端口
	lanTitleProbeWorkers = 64                     // 网页标题异步探测的全局并发上限
)

// allTCPPorts 全部 TCP 端口 1-65535（包级共享只读切片，ports=all 时使用）。
var allTCPPorts = func() []int {
	ps := make([]int, 65535)
	for i := range ps {
		ps[i] = i + 1
	}
	return ps
}()

// commonLanPorts 局域网扫描探测的常见开放端口：Web/远程管理、文件共享（Windows SMB、
// NetBIOS、NFS、AFP）、数据库、NAS（群晖 DSM、fnOS）、虚拟化（Docker、Proxmox）、
// 智能家居（Home Assistant）、VNC、UPnP 等局域网高价值服务。
var commonLanPorts = []int{
	22, 53, 80, 443, // SSH / DNS / HTTP / HTTPS
	21, 111, 139, 445, 548, 2049, // FTP / rpcbind / NetBIOS / SMB / AFP / NFS
	3000, 5000, 5001, 61208, 8006, 8080, 8081, 8443, 8888, 9000, 9090, 9443, // Web / NAS / 虚拟化 / 管理面板
	1433, 3306, 5432, 6379, 9200, 27017, // SQL Server / MySQL / PostgreSQL / Redis / ES / Mongo
	3389, 5900, 5666, // 远程桌面 / VNC / NRPE 监控
	2375, 2376, // Docker API
	1080, 631, 8123, 49152, // SOCKS / IPP 打印 / Home Assistant / UPnP
}

// hostProbePorts 主机在线探测的少量高价值端口：命中任意一个（开放或明确拒绝=主机可达）即判定该 IP 被使用。
// 仅用于「扫描IP」快速判定哪些地址在线，不做全量端口扫描。
var hostProbePorts = []int{80, 22, 443, 445, 3389, 8080, 9090, 53}

// parsePortList 解析逗号分隔的端口列表（去重、剔除非法值，0 表示空）；
// "all"（不区分大小写）表示扫描全部 TCP 端口 1-65535。
func parsePortList(s string) []int {
	if strings.EqualFold(strings.TrimSpace(s), "all") {
		return allTCPPorts
	}
	var out []int
	seen := map[int]bool{}
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err == nil && n > 0 && n <= 65535 && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// effectivePorts 返回实际要探测的端口列表：未指定时用默认常见端口集。
func effectivePorts(ports []int) []int {
	if len(ports) == 0 {
		return commonLanPorts
	}
	return ports
}

// probeResult 单次 TCP 探测的结论。
type probeResult int

const (
	probeOpen        probeResult = iota // 端口开放（SYN-ACK）
	probeRefused                        // 明确拒绝（RST）= 主机在线、端口关闭
	probeTimeout                        // 超时 = 结果不确定（丢包 / 设备慢响应 / 防火墙 DROP）
	probeUnreachable                    // 主机不可达（EHOSTUNREACH 等，通常为 ARP 解析失败 = 主机不在线）
)

// probeTCP 三态探测目标端口，区分「明确拒绝 / 不可达 / 超时」：
// 只有超时属于结果不确定（值得重试），明确拒绝与不可达可直接下结论。
func probeTCP(host string, port int) (probeResult, float64) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), lanTCPTimeout)
	if err == nil {
		conn.Close()
		// 保留 1 位小数（同 ping/HTTP 探测口径），同网段通常为亚毫秒~几毫秒
		ms := math.Round(float64(time.Since(start).Microseconds())/100) / 10
		return probeOpen, ms
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		if oe.Timeout() {
			return probeTimeout, 0
		}
		if errors.Is(oe.Err, syscall.ECONNREFUSED) {
			return probeRefused, 0
		}
	}
	return probeUnreachable, 0
}

// probePortWithRetry 探测端口：超时（结果不确定）时重试一次以消除偶发丢包漏报。
// 重试时 ARP 已解析完成，成本极低；明确拒绝/不可达不重试。
func probePortWithRetry(host string, port int) (probeResult, float64) {
	res, ms := probeTCP(host, port)
	if res == probeTimeout {
		res, ms = probeTCP(host, port)
	}
	return res, ms
}

// probePortForHost 带主机在线状态的探测决策：
// 已确认在线的主机超时不重试——防火墙 DROP 是确定性行为（同一端口重试仍会超时），
// 全端口扫描下重试会让 DROP 型主机的耗时直接翻倍；未确认在线的主机保持重试，
// 覆盖 ARP 冷启动与偶发丢包（重试时 ARP 已热，成本极低）。
func probePortForHost(host string, port int, online bool) (probeResult, float64) {
	res, ms := probeTCP(host, port)
	if res == probeTimeout && !online {
		res, ms = probeTCP(host, port)
	}
	return res, ms
}

// lanTask 局域网扫描任务（某主机的某个端口）。
type lanTask struct {
	host string
	idx  int // 主机在 IP 列表中的下标，用于定位 per-host 状态
	port int
}

// lanHostState 全端口模式下每台主机的共享状态（atomic 访问）。
type lanHostState struct {
	uncertain atomic.Int32 // 连续「不确定」（超时/不可达）计数，仅未确认在线时累计
	online    atomic.Bool  // 收到过 SYN-ACK/RST，已确认主机在线
	skipped   atomic.Bool  // 已判定不可达/全过滤，剩余任务直接丢弃
	remaining atomic.Int64 // 剩余待处理任务数，减到 0 触发 onChecked
}

// scanLanPortsStream 对 IP 范围内的主机探测端口，每发现一个开放端口即调用
// onFound 回调（回调由多个 goroutine 并发调用，调用方需自行保证并发安全）；
// 某主机全部待检端口处理完毕（或被判定不可达提前跳过）后调用 onChecked(host)
// （可传 nil 忽略），供流式客户端实时把「未发现主机」的卡片从待检翻转为未使用。
// 返回参数校验类错误；探测本身不中断。
//
// 双模式调度：
//   - 端口数 ≤ lanSerialPortMax：主机间并发、主机内端口串行——首个端口完成 ARP 解析后，
//     同主机后续端口直接命中内核 ARP 缓存（快且准），不在线主机靠 ARP negative cache 秒返不可达；
//   - 端口数更多（含全端口 1-65535）：全局任务池 lanGlobalWorkers 并发，
//     任务按 IP 主序、端口升序产出，跳过判定发生在最早的几个端口上，效率高。
//
// 跳过策略（两种模式一致）：收到 SYN-ACK/RST 即确认主机在线，此后永不跳过（防火墙
// 过滤的端口超时也不影响后续可能开放的端口）；未确认在线的主机连续 lanTimeoutSkip
// 次「不确定」才判定不可达/全过滤并跳过——被过滤的端口即使继续探测也无法得出有效结果。
func scanLanPortsStream(ipRange string, ports []int, onFound func(PortScanItem), onChecked func(ip string), onProgress func(done, total int64), onScanning func(start, end string)) error {
	ips, err := parseScanTargets(ipRange)
	if err != nil {
		return err
	}
	if len(ips) > lanScanMaxIPs {
		return fmt.Errorf("IP 范围过大（最多支持 %d 个地址，当前 %d 个），请缩小范围", lanScanMaxIPs, len(ips))
	}
	// 分批并发扫描：按 IP 顺序每批 lanBatchSize 台，批内用全局任务池并发探测端口（保留速度），
	// 批间按序推进（可感知进度）。每批开始通过 onScanning 推送该批 IP 范围，前端据此高亮「当前批次」。
	const lanBatchSize = 32
	services := loadServiceNames()
	ePorts := effectivePorts(ports)
	for start := 0; start < len(ips); start += lanBatchSize {
		end := start + lanBatchSize
		if end > len(ips) {
			end = len(ips)
		}
		batch := ips[start:end]
		if onScanning != nil {
			onScanning(batch[0].String(), batch[len(batch)-1].String())
		}
		if err := scanLanPool(batch, ePorts, services, onFound, onChecked, onProgress); err != nil {
			return err
		}
	}
	return nil
}

// scanLanHostsStream 仅探测网段内哪些 IP 被使用（主机在线），不做端口扫描。
// 对每个 IP 依次探测 hostProbePorts 中少量高价值端口：命中开放或明确拒绝即判定在线并回调 onHost；
// 全部端口均无响应则判定未使用并回调 onChecked。用于「扫描IP」快速获知在线主机。
func scanLanHostsStream(ipRange string, onHost func(ip string), onChecked func(ip string), onProgress func(done, total int64)) error {
	ips, err := parseScanTargets(ipRange)
	if err != nil {
		return err
	}
	if len(ips) > lanScanMaxIPs {
		return fmt.Errorf("IP 范围过大（最多支持 %d 个地址，当前 %d 个），请缩小范围", lanScanMaxIPs, len(ips))
	}
	var (
		wg  sync.WaitGroup
		sem = make(chan struct{}, lanHostConcurrency)
	)
	total := int64(len(ips))
	var doneVal atomic.Int64
	progressPush := func() {
		if onProgress == nil {
			return
		}
		d := doneVal.Load()
		step := total / 200
		if step < 1 {
			step = 1
		}
		if d%step == 0 || d >= total {
			onProgress(d, total)
		}
	}
	for _, ip := range ips {
		host := ip.String()
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			alive := false
			for _, port := range hostProbePorts {
				switch res, _ := probePortForHost(host, port, alive); res {
				case probeOpen, probeRefused:
					alive = true
				}
				if alive {
					break
				}
			}
			if alive {
				if onHost != nil {
					onHost(host)
				}
			} else if onChecked != nil {
				onChecked(host)
			}
			doneVal.Add(1)
			progressPush()
		}(host)
	}
	wg.Wait()
	if onProgress != nil {
		onProgress(doneVal.Load(), total)
	}
	return nil
}

// scanLanSerial 少端口模式：主机间并发 lanHostConcurrency，主机内端口串行。
func scanLanSerial(ips []net.IP, ports []int, services map[int]string, onFound func(PortScanItem), onChecked func(ip string), onProgress func(done, total int64)) error {
	var (
		wg  sync.WaitGroup
		sem = make(chan struct{}, lanHostConcurrency)
	)
	total := int64(len(ips)) * int64(len(ports))
	var doneVal atomic.Int64
	// 节流：每完成约 total/200 个任务推送一次进度，避免刷爆 NDJSON；末尾保证推满 100%
	progressPush := func() {
		if onProgress == nil {
			return
		}
		d := doneVal.Load()
		step := total / 200
		if step < 1 {
			step = 1
		}
		if d%step == 0 || d >= total {
			onProgress(d, total)
		}
	}
	for _, ip := range ips {
		host := ip.String()
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			uncertain := 0
			online := false // 收到过 SYN-ACK/RST 即确认在线，不再跳过、超时不重试
			for i, port := range ports {
				switch res, ms := probePortForHost(host, port, online); res {
				case probeOpen:
					uncertain, online = 0, true
					onFound(PortScanItem{Port: port, Protocol: "tcp", LocalAddr: host, Service: services[port], LatencyMS: ms})
				case probeRefused:
					uncertain, online = 0, true // RST = 主机在线
				default: // probeTimeout / probeUnreachable
					uncertain++
					if !online && uncertain >= lanTimeoutSkip {
						// 主机始终无响应：判定不可达/全过滤，把剩余未扫端口一并计入，进度拉到满
						doneVal.Add(int64(len(ports) - i))
						goto done
					}
				}
				doneVal.Add(1)
				progressPush()
			}
		done:
			if onChecked != nil {
				onChecked(host)
			}
		}(host)
	}
	wg.Wait()
	if onProgress != nil {
		onProgress(doneVal.Load(), total)
	}
	return nil
}

// scanLanPool 大端口集模式：全局任务池 lanGlobalWorkers 并发探测，两阶段执行。
//
// 阶段 1（主机发现）：全量探测常见端口集 commonLanPorts——**禁用任何跳过逻辑**。
// Windows 等设备的授权监听端口（135/139/445/3389）之前的端口全部被防火墙 DROP，
// 若按「前几个端口全超时即跳过」会漏掉整台主机；常见端口集本身包含这些高信号端口，
// 能可靠确认在线。阶段 1 中命中用户端口集的结果照常推送，其余仅用于在线判定。
//
// 阶段 2（完整扫描）：对全部主机扫描剩余端口（用户端口集扣除阶段 1 已探测的常见端口）。
// 阶段 1 已确认在线的主机由 online 标记保护，永不跳过——防火墙 DROP 是确定性行为，
// 某个端口超时不代表后续端口关闭。未被阶段 1 确认在线的主机（离线 / 全 DROP / 仅开放
// 非常用端口）不直接放弃：它们在阶段 2 用「连续不确定跳过」止损，一旦其放行的非常用端口
// 被探测到（SYN-ACK/RST）即确认在线并转全量扫完，从而覆盖「仅开放非常用端口」的在网主机，
// 确保全端口扫描不遗漏。
func scanLanPool(ips []net.IP, ports []int, services map[int]string, onFound func(PortScanItem), onChecked func(ip string), onProgress func(done, total int64)) error {
	total := len(ips)
	states := make([]lanHostState, total)
	hosts := make([]string, total)
	for i, ip := range ips {
		hosts[i] = ip.String()
	}
	var (
		doneSum    atomic.Int64 // 已完成的探测任务数（跨两阶段累计）
		grandTotal atomic.Int64 // 本次扫描目标总任务数（两阶段之和）
	)
	// 节流：每完成约 total/200 个任务推送一次进度，避免刷爆 NDJSON；末尾保证推满 100%
	progressTick := func() {
		if onProgress == nil {
			return
		}
		d := doneSum.Add(1)
		gt := grandTotal.Load()
		step := gt / 200
		if step < 1 {
			step = 1
		}
		if d%step == 0 || d >= gt {
			onProgress(d, gt)
		}
	}
	runPool := func(idxList []int, taskPorts []int, found func(PortScanItem), checked func(ip string), skip bool) error {
		var (
			wg    sync.WaitGroup
			tasks = make(chan lanTask, 4096)
		)
		go func() { // 任务生成器：按端口轮次交错产出（每轮所有主机的同一序号端口），避免队头阻塞
			defer close(tasks)
			for _, port := range taskPorts {
				for _, i := range idxList {
					states[i].remaining.Add(1)
					tasks <- lanTask{host: hosts[i], idx: i, port: port}
				}
			}
		}()
		for w := 0; w < lanGlobalWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for t := range tasks {
					st := &states[t.idx]
					// 已判定不可达/全过滤的主机（仅跳过模式）：剩余任务直接结清，不再探测
					if skip && st.skipped.Load() {
						progressTick()
						if checked != nil && st.remaining.Add(-1) == 0 {
							checked(t.host)
						}
						continue
					}
					// 阶段 1 主机未确认在线：超时重试（覆盖 ARP 冷启动/偶发丢包）；
					// 已确认在线（阶段 2）：DROP 为防火墙确定性行为，超时不重试
					switch res, ms := probePortForHost(t.host, t.port, st.online.Load()); res {
					case probeOpen:
						st.uncertain.Store(0)
						st.online.Store(true)
						if found != nil {
							found(PortScanItem{Port: t.port, Protocol: "tcp", LocalAddr: t.host, Service: services[t.port], LatencyMS: ms})
						}
					case probeRefused:
						st.uncertain.Store(0)
						st.online.Store(true) // RST = 主机在线
					default: // probeTimeout / probeUnreachable
						if skip && !st.online.Load() && st.uncertain.Add(1) >= lanTimeoutSkip {
							st.skipped.Store(true) // 连续不确定达阈值：判定不可达/全过滤，跳过后序端口
						}
					}
					progressTick()
					if checked != nil && st.remaining.Add(-1) == 0 {
						checked(t.host)
					}
				}
			}()
		}
		wg.Wait()
		return nil
	}

	// 常见端口集与剩余端口：阶段 1 全量探测常见端口（主机发现），阶段 2 扫剩余端口
	commonSet := make(map[int]bool, len(commonLanPorts))
	for _, p := range commonLanPorts {
		commonSet[p] = true
	}
	restPorts := make([]int, 0, len(ports))
	for _, p := range ports {
		if !commonSet[p] {
			restPorts = append(restPorts, p)
		}
	}
	// 进度总量预置为「完整任务数」（阶段1 常见端口 + 阶段2 剩余端口，均按全部主机估算），
	// 使分母恒定（如单机全端口 = 65535）、done 单调递增；离线主机未进阶段 2 时进度由 done 收尾。
	grandTotal.Add(int64(total) * int64(len(commonLanPorts)+len(restPorts)))

	// 阶段 1：主机发现（常见端口集全量探测，不跳过）
	wanted := make(map[int]bool, len(ports))
	for _, p := range ports {
		wanted[p] = true
	}
	allIdx := make([]int, total)
	for i := range allIdx {
		allIdx[i] = i
	}
	stage1Found := func(it PortScanItem) {
		if wanted[it.Port] && onFound != nil {
			onFound(it) // 仅推送用户要求探测的端口
		}
	}
	if err := runPool(allIdx, commonLanPorts, stage1Found, nil, false); err != nil {
		return err
	}

	// 阶段 2：对全部主机扫描剩余端口。
	// 说明：阶段 1 已把「对常见端口有响应」的主机标记为 online，这类主机本阶段永不跳过，
	// 扫完剩余端口（online 保护）。而被阶段 1 未确认在线的主机（离线 / 防火墙全 DROP /
	// 仅开放非常用端口）不再直接放弃——它们在阶段 2 通过「连续不确定跳过」止损；一旦其放行的
	// 非常用端口在本阶段被探测到（SYN-ACK/RST），即确认在线并转入全量扫完，从而覆盖
	// 「仅开放非常用端口」的在网主机，真正做到全端口不遗漏。
	if len(restPorts) == 0 {
		for i := range hosts {
			if onChecked != nil {
				onChecked(hosts[i]) // 无剩余端口：阶段 1 已探测完用户端口集，直接结清
			}
		}
		if onProgress != nil {
			onProgress(doneSum.Load(), grandTotal.Load())
		}
		return nil
	}
	// 重置未确认在线主机的「不确定」计数：给它们在阶段 2 一个独立的跳过窗口
	//（阶段 1 禁跳过已累计的不确定值不延续，避免一进阶段 2 就立即被跳过）。
	for i := range hosts {
		if !states[i].online.Load() {
			states[i].uncertain.Store(0)
		}
	}
	return runPool(allIdx, restPorts, onFound, onChecked, true)
}

// scanLanPorts 对 IP 范围逐台主机探测常见开放端口，并探测开放端口的网页标题（一次性返回）。
func scanLanPorts(ipRange string, ports []int) ([]PortScanItem, error) {
	var (
		mu    sync.Mutex
		items []PortScanItem
	)
	err := scanLanPortsStream(ipRange, ports, func(it PortScanItem) {
		mu.Lock()
		it.WebTitle = probeWebTitle(it.LocalAddr, it.Port) // 非流式回退场景：同步补标题
		items = append(items, it)
		mu.Unlock()
	}, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LocalAddr != items[j].LocalAddr {
			return items[i].LocalAddr < items[j].LocalAddr
		}
		return items[i].Port < items[j].Port
	})
	return items, nil
}

// scanHostPorts 扫描指定 IP（或主机名）的开放端口：
//   - 目标为本机（回环 / 本机网卡 IP / 未指定地址）时返回本机全部监听端口（含进程与服务名）；
//   - 其他主机则对指定端口（默认常见端口集，支持 all 全端口 1-65535）做 TCP 连通性探测，
//     并尝试识别服务与网页标题（全端口时单机高并发，同网段 RST 秒回实测 65535 端口约 1 秒）。
//
// includeV6=false 时本机扫描仅返回 IPv4 监听地址（默认）。
func scanHostPorts(host string, includeV6 bool, ports []int) ([]PortScanItem, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("请输入要扫描的 IP 地址")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified() || isLocalInterfaceIP(ip)) {
		items := scanListeningPorts(includeV6)
		probeLocalWebTitles(items)
		return items, nil
	}
	// 远程主机：复用流式实现收集最终结果（回调传 nil，标题探测在返回前已等待完成）
	items, err := scanHostPortsStream(host, ports, nil, nil, nil)
	return items, err
}

// scanHostPortsStream 扫描指定远程主机的开放端口（流式）：
// 每探测到一个开放端口立即通过 onFound 回调推送（此时不含网页标题）；
// 网页标题异步探测，完成一条即通过 onUpdate 回填（与局域网扫描同一策略，避免拖慢端口探测）；
// 每完成一个端口探测回调一次 onProgress(done,total)，供前端展示进度。
// 返回值为标题回填完成、按端口排序后的最终结果（供非流式回退路径使用）。
func scanHostPortsStream(host string, ports []int, onFound func(PortScanItem), onUpdate func(PortScanItem), onProgress func(done, total int64)) ([]PortScanItem, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("请输入要扫描的 IP 地址")
	}
	services := loadServiceNames()
	list := effectivePorts(ports)
	total := int64(len(list))
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		sem      = make(chan struct{}, lanGlobalWorkers)
		items    []PortScanItem
		online   atomic.Bool // 收到过 SYN-ACK/RST 即确认在线，超时不重试（DROP 为确定性行为）
		doneN    atomic.Int64
		titleWG  sync.WaitGroup
		titleSem = make(chan struct{}, lanTitleProbeWorkers)
	)
	for _, port := range list {
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			if res, ms := probePortForHost(host, port, online.Load()); res == probeOpen {
				online.Store(true)
				it := PortScanItem{
					Port:      port,
					Protocol:  "tcp",
					LocalAddr: host,
					Service:   services[port],
					LatencyMS: ms,
				}
				mu.Lock()
				items = append(items, it)
				mu.Unlock()
				if onFound != nil {
					onFound(it)
				}
				// 网页标题异步探测，完成后推 update 回填，不占用端口探测 worker
				titleWG.Add(1)
				titleSem <- struct{}{}
				go func(it PortScanItem) {
					defer titleWG.Done()
					defer func() { <-titleSem }()
					if title := probeWebTitle(it.LocalAddr, it.Port); title != "" {
						it.WebTitle = title
						mu.Lock()
						for i := range items {
							if items[i].Port == it.Port && items[i].Protocol == it.Protocol {
								items[i].WebTitle = title
								break
							}
						}
						mu.Unlock()
						if onUpdate != nil {
							onUpdate(it)
						}
					}
				}(it)
			}
			if onProgress != nil {
				onProgress(doneN.Add(1), total)
			}
		}(port)
	}
	wg.Wait()
	titleWG.Wait() // 等全部标题回填完成，保证返回值与 update 事件一致
	sort.Slice(items, func(i, j int) bool { return items[i].Port < items[j].Port })
	return items, nil
}

// isLocalInterfaceIP 判断 IP 是否属于本机任意网卡地址。
func isLocalInterfaceIP(ip net.IP) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ipn net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ipn = v.IP
			case *net.IPAddr:
				ipn = v.IP
			}
			if ipn != nil && ipn.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// parseIPRange 解析 IP 范围，支持三种形式：
//
//  1. CIDR 网段（如 192.168.1.0/24）；
//  2. 单个 IP（如 192.168.1.5，仅扫描该主机）；
//  3. 起始IP-结束IP（如 192.168.1.1-192.168.1.255）。
//
// 返回展开后的 IPv4 地址列表；地址数超过 lanScanMaxIPs 时返回错误。
func parseIPRange(s string) ([]net.IP, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("请输入要扫描的 IP 范围")
	}
	// CIDR 网段（如 192.168.1.0/24）
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		if ipnet.IP.To4() == nil {
			return nil, fmt.Errorf("仅支持 IPv4 网段: %s", s)
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 || ones <= 0 {
			return nil, fmt.Errorf("无效的 IPv4 网段: %s", s)
		}
		start := ip4ToUint32(ipnet.IP.To4())
		count := uint32(1) << uint(bits-ones)
		return expandIPv4Range(start, start+count-1)
	}
	// 单个 IP（如 192.168.1.5）
	if ip := net.ParseIP(s); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("仅支持 IPv4 地址: %s", s)
		}
		u := ip4ToUint32(ip4)
		return expandIPv4Range(u, u)
	}
	// 起始IP-结束IP（如 192.168.1.1-192.168.1.255）
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("IP 范围格式应为「起始IP-结束IP」「CIDR 网段」或「单个 IP」，例如 192.168.1.1-192.168.1.255 / 192.168.1.0/24 / 192.168.1.5")
	}
	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))
	start, end := startIP.To4(), endIP.To4()
	if start == nil || end == nil {
		return nil, fmt.Errorf("IP 地址无效：%s - %s", strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	if bytes.Compare(start, end) > 0 {
		return nil, fmt.Errorf("结束 IP 不能小于起始 IP")
	}
	return expandIPv4Range(ip4ToUint32(start), ip4ToUint32(end))
}

// parseScanTargets 解析扫描目标：先按 IP/CIDR/IP范围解析，失败则当作域名解析（支持公网扫描输入域名）。
func parseScanTargets(s string) ([]net.IP, error) {
	if ips, err := parseIPRange(s); err == nil {
		return ips, nil
	}
	host := strings.TrimSpace(s)
	ips, err := lookupDomainIPv4(host)
	if err != nil {
		return nil, err
	}
	if len(ips) > lanScanMaxIPs {
		ips = ips[:lanScanMaxIPs]
	}
	return ips, nil
}

// lookupDomainIPv4 解析域名 IPv4：系统 resolver 失败时依次尝试多个公共 DNS（阿里/腾讯/114/谷歌/Cloudflare）。
func lookupDomainIPv4(host string) ([]net.IP, error) {
	var (
		ips  []net.IP
		last error
	)
	if addrs, err := net.LookupHost(host); err == nil {
		ips = domainsToIPv4(addrs)
	}
	if len(ips) == 0 {
		for _, ns := range []string{"223.5.5.5:53", "119.29.29.29:53", "114.114.114.114:53", "8.8.8.8:53", "1.1.1.1:53"} {
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 3 * time.Second}
					return d.DialContext(ctx, "udp", ns)
				},
			}
			addrs, err := r.LookupHost(context.Background(), host)
			if err != nil {
				last = err
				continue
			}
			ips = domainsToIPv4(addrs)
			if len(ips) > 0 {
				break
			}
		}
	}
	if len(ips) == 0 {
		_ = last
		return nil, fmt.Errorf("无法解析域名 %q 的 IPv4 地址（请确认域名存在且已配置 A 记录，或稍后重试）", host)
	}
	return ips, nil
}

// handlePortResolve 解析域名的 IPv4 地址列表，供端口扫描在开扫前确认目标：
// 前端拿到结果后，只有一个地址直接扫描，多个地址则展示给用户选择。
// 请求: GET /api/ports/resolve?host=example.com
func (s *Server) handlePortResolve(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	// 兼容误粘贴完整 URL：剥离协议前缀与路径
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请输入域名"))
		return
	}
	ips, err := lookupDomainIPv4(host)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	list := make([]string, 0, len(ips))
	seen := map[string]bool{}
	for _, ip := range ips {
		if v := ip.String(); !seen[v] {
			seen[v] = true
			list = append(list, v)
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"host": host, "ips": list}))
}

// domainsToIPv4 从主机记录里过滤出 IPv4 地址。
func domainsToIPv4(addrs []string) []net.IP {
	var ips []net.IP
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// expandIPv4Range 展开 [start, end]（含两端）为 IPv4 地址列表；数量超过 lanScanMaxIPs 时返回错误。
func expandIPv4Range(start, end uint32) ([]net.IP, error) {
	count := end - start + 1
	if count > lanScanMaxIPs {
		return nil, fmt.Errorf("IP 范围过大（最多支持 %d 个地址，当前 %d 个），请缩小范围", lanScanMaxIPs, count)
	}
	ips := make([]net.IP, 0, count)
	for cur := start; ; cur++ {
		ips = append(ips, uint32ToIP4(cur))
		if cur == end {
			break
		}
	}
	return ips, nil
}

// ============= 网页标题探测 =============

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// probeLocalWebTitles 对本机扫描结果中 TCP 端口的条目并发探测网页标题。
func probeLocalWebTitles(items []PortScanItem) {
	var (
		wg  sync.WaitGroup
		sem = make(chan struct{}, 16)
	)
	for i := range items {
		if !strings.HasPrefix(items[i].Protocol, "tcp") {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			items[i].WebTitle = probeWebTitle(items[i].LocalAddr, items[i].Port)
		}(i)
	}
	wg.Wait()
}

// probeWebTitle 请求目标端口首页并提取 <title>。端口 443 使用 https，其余端口先尝试 http。
func probeWebTitle(host string, port int) string {
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	title := fetchTitle(scheme, host, port)
	if title == "" && scheme == "http" {
		title = fetchTitle("https", host, port) // http 失败时兜底尝试 https
	}
	return title
}

// fetchTitle 发起一次 HTTP/HTTPS GET，解析响应中的 <title> 文本。
func fetchTitle(scheme, host string, port int) string {
	host = titleProbeHost(host) // 通配监听地址(0.0.0.0/::)不可直接作为请求目标，映射到回环
	u := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
	client := &http.Client{
		Timeout: 2 * time.Second,
		// 局域网/内网设备(路由器、NAS、Home Assistant 等)普遍使用自签名证书；
		// 标题探测属可用性判断，不校验证书链，否则自签 HTTPS 的标题全部抓不到。
		// TLSHandshakeTimeout 必须显式设置：自建 Transport 零值不带握手超时。
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: 2 * time.Second,
		},
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "TunHook-TitleProbe/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return ""
	}
	m := titleRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := strings.TrimSpace(html.UnescapeString(string(m[1])))
	t = strings.Join(strings.Fields(t), " ") // 折叠空白
	// 过滤无法按 UTF-8 解码（如 GBK 乱码）或过长的标题
	if strings.ContainsRune(t, '\uFFFD') || len([]rune(t)) == 0 {
		return ""
	}
	if r := []rune(t); len(r) > 100 {
		t = string(r[:100])
	}
	return t
}

// titleProbeHost 规范化标题探测用的主机地址：
// 监听在通配地址(0.0.0.0 / ::)的服务实际可从本机回环访问，直接请求通配地址会失败或不可靠。
func titleProbeHost(host string) string {
	switch strings.TrimSpace(host) {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::", "::0":
		return "::1"
	}
	return host
}

// scanListeningPorts 扫描本机所有监听中的 TCP/UDP 端口（含 IPv4/IPv6），
// 关联进程名称（通过 socket inode → PID 映射）与服务名称。
// includeV6=false 时跳过 IPv6（tcp6/udp6）监听条目。
func scanListeningPorts(includeV6 bool) []PortScanItem {
	pidByInode := buildInodePIDMap()
	services := loadServiceNames()

	// 同一端口+协议只保留一条（同一服务监听多个本机地址时避免重复计数）
	seen := map[string]bool{}
	var items []PortScanItem
	for _, pf := range procNetFiles {
		if !includeV6 && (pf.protocol == "tcp6" || pf.protocol == "udp6") {
			continue
		}
		data, err := os.ReadFile(pf.file)
		if err != nil {
			continue
		}
		isUDP := strings.HasPrefix(pf.protocol, "udp")
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			local := fields[1] // 格式: HEXIP:HEXPORT
			state := fields[3]
			inode := fields[9]
			ip, port := parseProcNetAddr(local)
			if port == 0 || ip == "" {
				continue
			}
			// TCP 仅统计 LISTEN(0A)；UDP 无监听状态，取所有已绑定套接字(07)
			if (isUDP && state != "07") || (!isUDP && state != "0A") {
				continue
			}
			key := pf.protocol + ":" + strconv.Itoa(port)
			if seen[key] {
				continue
			}
			seen[key] = true
			item := PortScanItem{
				Port:      port,
				Protocol:  pf.protocol,
				LocalAddr: ip,
				PID:       pidByInode[inode],
				Service:   services[port],
			}
			if item.PID > 0 {
				item.Process = processName(item.PID)
			}
			items = append(items, item)
		}
	}

	// 排序：先按端口升序，再按协议名
	sort.Slice(items, func(i, j int) bool {
		if items[i].Port != items[j].Port {
			return items[i].Port < items[j].Port
		}
		return items[i].Protocol < items[j].Protocol
	})
	return items
}

// buildInodePIDMap 遍历 /proc/<pid>/fd 下的 socket 符号链接，建立
// socket inode → PID 的映射（权限不足时部分进程不可读，跳过即可）。
func buildInodePIDMap() map[string]int {
	m := map[string]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
				if _, ok := m[inode]; !ok {
					m[inode] = pid
				}
			}
		}
	}
	return m
}

// processName 读取进程名称（/proc/<pid>/comm）。
func processName(pid int) string {
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

// loadServiceNames 从 /etc/services 读取端口 → 服务名映射，并用内置表补充缺失项。
func loadServiceNames() map[int]string {
	m := map[int]string{}
	if data, err := os.ReadFile("/etc/services"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			portStr := strings.SplitN(fields[1], "/", 2)[0]
			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}
			if _, ok := m[port]; !ok {
				m[port] = fields[0]
			}
		}
	}
	for port, name := range commonServices {
		if _, ok := m[port]; !ok {
			m[port] = name
		}
	}
	return m
}

// parseProcNetAddr 解析 /proc/net/tcp(6) 中的 local_address 字段
// （如 "0100007F:1F90" 或 "00000000000000000000000001000000:0050"），
// 返回可读 IP 字符串与端口号。
func parseProcNetAddr(local string) (string, int) {
	idx := strings.LastIndex(local, ":")
	if idx < 0 {
		return "", 0
	}
	hexIP := local[:idx]
	hexPort := local[idx+1:]
	port64, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return "", 0
	}
	port := int(port64)

	var ip net.IP
	switch len(hexIP) {
	case 8: // IPv4（字节序反转）
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(hexIP[i*2:i*2+2], 16, 8)
			if err != nil {
				return "", 0
			}
			b[3-i] = byte(v)
		}
		ip = net.IPv4(b[0], b[1], b[2], b[3])
	case 32: // IPv6（每个 16 位组内字节反转）
		raw := make(net.IP, 16)
		for i := 0; i < 8; i++ {
			group := hexIP[i*4 : i*4+4]
			b0, err0 := strconv.ParseUint(group[0:2], 16, 8)
			b1, err1 := strconv.ParseUint(group[2:4], 16, 8)
			if err0 != nil || err1 != nil {
				return "", 0
			}
			raw[i*2] = byte(b1)
			raw[i*2+1] = byte(b0)
		}
		ip = raw
	default:
		return "", 0
	}
	return ip.String(), port
}

// frpcConnStats 统计各 frpc 代理的当前活跃连接数（代理名 → 连接数）。
// 原理：frpc 转发到本地服务时会在 frpc 进程内建立到 localIP:localPort 的 TCP 连接；
// 通过 /proc/net/tcp(+6) 统计 ESTABLISHED/CLOSE_WAIT 且远端端点命中某代理本地端点的连接数。
// 优先按 frpc 进程 socket inode 精确过滤（frpc.pid → /proc/<pid>/fd）；
// 容器/权限受限导致 /proc/<pid>/fd 不可读时，回退为仅按目标端点匹配（只依赖 /proc/net）。
// frpc 未运行或无可统计代理时返回空映射；UDP 代理无连接概念，不计入。
func (s *Server) frpcConnStats() map[string]int {
	// 预置所有已启用代理为 0：无活跃连接时也返回 0（而非缺项），
	// 否则前端会把「无连接」误显示为「—」，看起来像统计不可用
	counts := map[string]int{}
	for _, p := range s.frpcMgr.LoadConfig().Proxies {
		typ := strings.ToLower(strings.TrimSpace(p.Type))
		if p.Enabled && typ != "udp" && p.LocalPort > 0 {
			counts[p.Name] = 0
		}
	}
	pids := s.frpcMgr.RunningPIDs()
	if len(pids) == 0 {
		return counts
	}
	targets := s.frpcTargets()
	if len(targets) == 0 {
		return counts
	}
	// 聚合所有运行中 frpc 实例持有的 socket inode（多实例同时运行）
	inodes := map[string]bool{}
	for _, pid := range pids {
		for k, v := range s.frpcSocketInodes(pid) {
			inodes[k] = v
		}
	}
	var scanned map[string]int
	if len(inodes) > 0 {
		scanned = s.scanProcNetConns(targets, inodes)
	} else {
		// 无法读取 frpc 进程 fd（沙箱/容器限制）：按目标端点匹配统计（尽力而为）
		scanned = s.scanProcNetConns(targets, nil)
	}
	for name, n := range scanned {
		counts[name] += n
	}
	return counts
}

// scanProcNetConns 扫描 /proc/net/tcp(+6) 统计各代理的活跃转发连接数。
// inodeFilter 非空时仅统计属于 frpc 进程的连接；为空时按目标端点匹配（尽力而为）。
func (s *Server) scanProcNetConns(targets map[string][]string, inodeFilter map[string]bool) map[string]int {
	counts := map[string]int{}
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			state := fields[3]
			if state != "01" && state != "08" { // ESTABLISHED / CLOSE_WAIT
				continue
			}
			if inodeFilter != nil && !inodeFilter[fields[9]] {
				continue
			}
			ip, port := parseProcNetAddr(fields[2]) // rem_address = 本地服务端点
			if port <= 0 || ip == "" {
				continue
			}
			key := net.JoinHostPort(ip, strconv.Itoa(port))
			for _, name := range targets[key] {
				counts[name]++
			}
		}
	}
	return counts
}

// frpcTargets 构建 本地服务端点 → 代理名 映射（UDP 代理无连接概念，跳过）。
// 同一本地服务可被多个代理共用，故值为代理名列表。
func (s *Server) frpcTargets() map[string][]string {
	targets := map[string][]string{}
	for _, p := range s.frpcMgr.LoadConfig().Proxies {
		typ := strings.ToLower(strings.TrimSpace(p.Type))
		if typ == "udp" || p.LocalPort <= 0 {
			continue
		}
		lip := strings.TrimSpace(p.LocalIP)
		if lip == "" || lip == "0.0.0.0" {
			lip = "127.0.0.1"
		} else if lip == "::" {
			lip = "::1"
		}
		key := net.JoinHostPort(lip, strconv.Itoa(p.LocalPort))
		targets[key] = append(targets[key], p.Name)
	}
	return targets
}

// frpcSocketInodes 返回 frpc 进程持有的 socket inode 集合（仅读一个进程的 fd，开销很小）。
func (s *Server) frpcSocketInodes(pid int) map[string]bool {
	inodes := map[string]bool{}
	if fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid)); err == nil {
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
			}
		}
	}
	return inodes
}

// frpcConnDetail 单个活跃转发连接详情（frpc ↔ 本地服务），并关联访客真实 IP/端口。
type frpcConnDetail struct {
	Local       string `json:"local"`        // frpc 侧端点（IP:端口）
	Remote      string `json:"remote"`       // 本地服务端点（IP:端口）
	VisitorIP   string `json:"visitor_ip"`   // 访客真实 IP（HTTP 头关联），无则 "-"
	VisitorPort string `json:"visitor_port"` // 访客源端口（X-Real-Port），无则 "-"
	RX          int64  `json:"rx"`           // 累计接收字节（来自 ss/TCP_INFO；不可得时为 -1）
	TX          int64  `json:"tx"`           // 累计发送字节（来自 ss/TCP_INFO；不可得时为 -1）
}

// frpcConnDetail 返回各代理当前活跃连接的详细信息（连接双方端点 + 累计流量），
// 供「连接统计」弹窗展示。UDP 代理不参与。
func (s *Server) frpcConnDetail() map[string][]frpcConnDetail {
	result := map[string][]frpcConnDetail{}
	pids := s.frpcMgr.RunningPIDs()
	if len(pids) == 0 {
		return result
	}
	inodes := map[string]bool{}
	for _, pid := range pids {
		for k, v := range s.frpcSocketInodes(pid) {
			inodes[k] = v
		}
	}
	targets := s.frpcTargets()
	if len(targets) == 0 {
		return result
	}
	// 各连接累计收发字节（TCP_INFO）；ss 缺失/解析失败时对应连接流量为 -1
	bytesByInode := ssTCPInfo()
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			state := fields[3]
			if state != "01" && state != "08" {
				continue
			}
			inode := fields[9]
			// 能读取 frpc 进程 fd 时按 inode 精确过滤；读取失败（沙箱/容器限制）
			// 回退为仅按目标端点匹配（尽力而为），与 frpcConnStats 保持一致
			if len(inodes) > 0 && !inodes[inode] {
				continue
			}
			localIP, localPort := parseProcNetAddr(fields[1])
			remIP, remPort := parseProcNetAddr(fields[2])
			if localPort <= 0 || remPort <= 0 || localIP == "" || remIP == "" {
				continue
			}
			key := net.JoinHostPort(remIP, strconv.Itoa(remPort))
			names, ok := targets[key]
			if !ok {
				continue
			}
			d := frpcConnDetail{
				Local:  net.JoinHostPort(localIP, strconv.Itoa(localPort)),
				Remote: key,
				RX:     -1,
				TX:     -1,
			}
			// 关联访客真实 IP/端口：优先由 HTTP 请求 RemoteAddr 精确匹配 frpc 转发连接
			//（仅经本应用 Web 服务直接承接的代理能精确命中）；网关/反代场景 frpc 与访客
			// 没有同一 socket 端点，回退按「访客 IP 归属到代理名」补齐，避免展示 -。
			// 普通 TCP/UDP 代理无法得知访客 IP，两种方式都命中不到时展示 -（连接本身仍是一并展示）。
			d.VisitorIP, d.VisitorPort = s.connVisitorFor(d.Local, names)
			if b, ok := bytesByInode[inode]; ok {
				d.RX = b.rx
				d.TX = b.tx
			}
			for _, name := range names {
				result[name] = append(result[name], d)
			}
		}
	}
	return result
}

var (
	ssInoRe = regexp.MustCompile(`\bino:(\d+)`)
	ssTxRe  = regexp.MustCompile(`\bbytes_acked:(\d+)`)
	ssRxRe  = regexp.MustCompile(`\bbytes_received:(\d+)`)

	// ss 扫描结果缓存：ss -tine 要遍历系统全部 socket 并逐个读 TCP_INFO，连接数多时
	// 单次输出可达上万行、解析开销数百毫秒；而 /api/forward/list 与 /api/frpc/conns
	// 各自都会调用一次，前端轮询下就是对同一份数据的重复扫描。
	// 加短 TTL 共享缓存后，同一时间窗内的多次调用共用一次扫描结果。
	ssCacheMu  sync.Mutex
	ssCacheMap = map[string]tcpBytes{}
	ssCacheAt  time.Time
)

// ssCacheTTL ss 扫描结果的缓存时长，需小于前端最快轮询间隔，使速率显示滞后不超过一个采样周期。
const ssCacheTTL = 1500 * time.Millisecond

// tcpBytes 单个 TCP 连接的累计收发字节数（TCP_INFO）。
type tcpBytes struct {
	rx int64
	tx int64
}

// ssTCPInfo 通过 `ss -tine` 读取系统内各 TCP 连接的累计收发字节数（TCP_INFO），
// 按 socket inode 索引。ss 不可用或解析失败时返回空映射。
// 结果带 ssCacheTTL 短缓存，供同一轮询周期内的多个接口共享，避免重复扫描。
func ssTCPInfo() map[string]tcpBytes {
	ssCacheMu.Lock()
	defer ssCacheMu.Unlock()
	if !ssCacheAt.IsZero() && time.Since(ssCacheAt) < ssCacheTTL {
		return ssCacheMap
	}
	m := map[string]tcpBytes{}
	out, err := exec.Command("ss", "-tine").Output()
	if err != nil {
		// 失败同样写入缓存：避免每次轮询都重新 fork 一个必然失败的子进程
		ssCacheMap, ssCacheAt = m, time.Now()
		return m
	}
	curIno := ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			// 信息行（缩进）：归属上一个主行，含 bytes_acked / bytes_received
			if curIno == "" {
				continue
			}
			var b tcpBytes
			if mm := ssTxRe.FindStringSubmatch(line); len(mm) == 2 {
				if v, err := strconv.ParseInt(mm[1], 10, 64); err == nil {
					b.tx = v
				}
			}
			if mm := ssRxRe.FindStringSubmatch(line); len(mm) == 2 {
				if v, err := strconv.ParseInt(mm[1], 10, 64); err == nil {
					b.rx = v
				}
			}
			m[curIno] = b
			curIno = ""
		} else if mm := ssInoRe.FindStringSubmatch(line); len(mm) == 2 {
			curIno = mm[1]
		} else {
			curIno = ""
		}
	}
	ssCacheMap, ssCacheAt = m, time.Now()
	return m
}

// handlePortProbe TCP 端口探测：对 地址:端口 发起一次带 3 秒超时的 TCP 连接，返回可达性与耗时。
// 请求体: {"addr":"127.0.0.1","port":80}
func (s *Server) handlePortProbe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Addr string `json:"addr"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求"))
		return
	}
	addr := strings.TrimSpace(req.Addr)
	if addr == "" || req.Port < 1 || req.Port > 65535 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的地址或端口"))
		return
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(req.Port)), 3*time.Second)
	// 用微秒换算并保留 1 位小数：局域网握手常不足 1ms，整数毫秒会截断成 0
	latency := math.Round(float64(time.Since(start).Microseconds())/100) / 10
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"ok": false, "latency_ms": latency, "error": err.Error()}))
		return
	}
	_ = conn.Close()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"ok": true, "latency_ms": latency}))
}

// handlePortDNS 查询域名的常用 DNS 记录（A / AAAA / CNAME / MX / NS / TXT），
// 并做 CNAME 链路与 CDN 识别、A 记录 PTR 反查、NS 服务商识别。
// 请求: GET /api/ports/dns?host=example.com
func (s *Server) handlePortDNS(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	// 兼容误粘贴完整 URL：剥离协议前缀与路径
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请输入域名"))
		return
	}
	// 记录类型（type 省略或 all → 查全部常用类型；其余按指定类型精确查询）
	recType := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))
	if recType == "" {
		recType = "ALL"
	}
	switch recType {
	case "ALL", "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA":
	default:
		s.writeJSON(w, http.StatusBadRequest, apiErr("不支持的记录类型："+recType+"（可选 all/A/AAAA/CNAME/MX/NS/TXT/SOA）"))
		return
	}
	all := recType == "ALL"
	want := func(t string) bool { return all || recType == t }
	start := time.Now()
	type dnsMX struct {
		Host string `json:"host"`
		Pref int    `json:"pref"`
	}
	type dnsCnameHop struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	type dnsCDN struct {
		Detected bool   `json:"detected"`
		Vendor   string `json:"vendor"`
		Via      string `json:"via"`
	}
	type dnsPtrRec struct {
		IP  string `json:"ip"`
		PTR string `json:"ptr"`
	}
	res := struct {
		Host       string            `json:"host"`
		A          []string          `json:"a"`
		AAAA       []string          `json:"aaaa"`
		CNAME      string            `json:"cname"`
		CnameChain []dnsCnameHop     `json:"cname_chain"`
		CDN        *dnsCDN           `json:"cdn"`
		MX         []dnsMX           `json:"mx"`
		NS         []string          `json:"ns"`
		NSVendor   map[string]string `json:"ns_vendor"`
		TXT        []string          `json:"txt"`
		SOA        []string          `json:"soa"`
		PTR        []dnsPtrRec       `json:"ptr"`
		DurationMs float64           `json:"duration_ms"`
	}{Host: host, A: []string{}, AAAA: []string{}, CnameChain: []dnsCnameHop{}, MX: []dnsMX{}, NS: []string{}, NSVendor: map[string]string{}, TXT: []string{}, SOA: []string{}, PTR: []dnsPtrRec{}}
	ok := false
	resolver := newDNSResolver()
	qctx, qcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer qcancel()
	// CNAME 链递归解析（最多 6 跳防环），逐跳做 CDN 特征识别
	chain := []dnsCnameHop{}
	cdnVendor, cdnVia := "", ""
	cur := host
	seen := map[string]bool{host: true}
	if want("CNAME") {
		for i := 0; i < 6; i++ {
			cn, err := resolver.LookupCNAME(qctx, cur)
			if err != nil || cn == "" {
				break
			}
			cn = strings.TrimSuffix(cn, ".")
			if strings.EqualFold(cn, cur) || seen[cn] {
				break
			}
			chain = append(chain, dnsCnameHop{From: cur, To: cn})
			seen[cn] = true
			if cdnVendor == "" {
				if v := matchDNSVendor(cn, cdnSignatures); v != "" {
					cdnVendor, cdnVia = v, cn
				}
			}
			cur = cn
		}
	}
	res.CnameChain = chain
	if len(chain) > 0 {
		res.CNAME = chain[0].To
		ok = true
	}
	if cdnVendor != "" {
		res.CDN = &dnsCDN{Detected: true, Vendor: cdnVendor, Via: cdnVia}
	}
	if want("A") || want("AAAA") {
		if ips, err := resolver.LookupIPAddr(qctx, host); err == nil && len(ips) > 0 {
			for _, ip := range ips {
				if v4 := ip.IP.To4(); v4 != nil {
					if want("A") {
						res.A = append(res.A, v4.String())
						ok = true
					}
				} else if ip.IP.To16() != nil {
					if want("AAAA") {
						res.AAAA = append(res.AAAA, ip.IP.String())
						ok = true
					}
				}
			}
		}
	}
	if want("MX") {
		if mxs, err := resolver.LookupMX(qctx, host); err == nil && len(mxs) > 0 {
			for _, mx := range mxs {
				res.MX = append(res.MX, dnsMX{Host: strings.TrimSuffix(mx.Host, "."), Pref: int(mx.Pref)})
			}
			ok = true
		}
	}
	if want("NS") {
		if nss, err := resolver.LookupNS(qctx, host); err == nil && len(nss) > 0 {
			for _, ns := range nss {
				if ns.Host != "" {
					h := strings.TrimSuffix(ns.Host, ".")
					res.NS = append(res.NS, h)
					if v := matchDNSVendor(h, nsSignatures); v != "" {
						res.NSVendor[h] = v
					}
				}
			}
			ok = true
		}
	}
	if want("TXT") {
		if txts, err := resolver.LookupTXT(qctx, host); err == nil && len(txts) > 0 {
			res.TXT = append(res.TXT, txts...)
			ok = true
		}
	}
	// SOA 仅在选择该类型时查询（net 包无 LookupSOA，只能走 DoH）
	if recType == "SOA" {
		dohClient := &http.Client{Timeout: 5 * time.Second}
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		if arr := dohQuery(dctx, dohClient, host, "SOA"); len(arr) > 0 {
			res.SOA = append(res.SOA, arr...)
			ok = true
		}
		dcancel()
	}
	// UDP 直连 53 不可达/超时（如本机网络环境）时，回退阿里 DoH（HTTPS）补齐所选记录类型。
	// 仅当所选类型都未从 UDP 解析出来时才走 DoH，正常环境不产生冗余请求。
	if !ok && recType != "SOA" {
		dohClient := &http.Client{Timeout: 5 * time.Second}
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		if want("A") {
			if as := dohQuery(dctx, dohClient, host, "A"); len(as) > 0 {
				res.A = append(res.A, as...)
				ok = true
			}
		}
		if want("AAAA") {
			if as := dohQuery(dctx, dohClient, host, "AAAA"); len(as) > 0 {
				res.AAAA = append(res.AAAA, as...)
				ok = true
			}
		}
		if want("MX") {
			if arr := dohQuery(dctx, dohClient, host, "MX"); len(arr) > 0 {
				for _, raw := range arr {
					// DoH 返回形如 "10 mail.example.com."；无 MX 时可能为 RFC7505 的 "0 ."
					parts := strings.Fields(raw)
					if len(parts) == 2 {
						mxHost := strings.TrimSuffix(parts[1], ".")
						if mxHost != "" {
							pref := 0
							fmt.Sscanf(parts[0], "%d", &pref)
							res.MX = append(res.MX, dnsMX{Host: mxHost, Pref: pref})
						}
					}
				}
				if len(res.MX) > 0 {
					ok = true
				}
			}
		}
		if want("NS") {
			if arr := dohQuery(dctx, dohClient, host, "NS"); len(arr) > 0 {
				for _, raw := range arr {
					h := strings.TrimSuffix(strings.TrimSpace(raw), ".")
					if h != "" {
						res.NS = append(res.NS, h)
						if v := matchDNSVendor(h, nsSignatures); v != "" {
							res.NSVendor[h] = v
						}
					}
				}
				if len(res.NS) > 0 {
					ok = true
				}
			}
		}
		if want("TXT") {
			if arr := dohQuery(dctx, dohClient, host, "TXT"); len(arr) > 0 {
				for _, raw := range arr {
					v := strings.Trim(strings.TrimSpace(raw), `"`)
					if v != "" {
						res.TXT = append(res.TXT, v)
					}
				}
				if len(res.TXT) > 0 {
					ok = true
				}
			}
		}
	}
	if !ok {
		if all {
			s.writeJSON(w, http.StatusOK, apiErr("未查询到任何 DNS 记录（域名可能不存在）"))
		} else {
			s.writeJSON(w, http.StatusOK, apiErr("未查询到 "+recType+" 记录（域名可能不存在，或该域名没有此类型记录）"))
		}
		return
	}
	// A 记录反查 PTR（并发 5——本机 53 端口并发限速，单个 2s 超时）
	ptrs := make([]dnsPtrRec, len(res.A))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	for i, ip := range res.A {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			names, err := resolver.LookupAddr(ctx, ip)
			if err == nil && len(names) > 0 && names[0] != "" {
				ptrs[i] = dnsPtrRec{IP: ip, PTR: strings.TrimSuffix(names[0], ".")}
			}
		}(i, ip)
	}
	wg.Wait()
	for _, p := range ptrs {
		if p.IP != "" {
			res.PTR = append(res.PTR, p)
		}
	}
	res.DurationMs = math.Round(float64(time.Since(start).Microseconds())/100) / 10
	s.writeJSON(w, http.StatusOK, apiOK(res))
}

// handleHTTPProbe 批量 HTTP(S) 探测主机 Web 服务可达性并测量延迟：
// 每个主机先尝试 HTTPS（3s 超时、忽略证书校验），传输层失败再回退 HTTP；
// 收到任意 HTTP 响应（含 4xx/5xx）即判定在线，延迟为整次请求耗时（不跟随跳转，测首个响应）。
// 请求: GET /api/ports/http-probe?hosts=a.com,b.com （最多 32 个，自动去重）
func (s *Server) handleHTTPProbe(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get("hosts"))
	if raw == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请提供 hosts 参数"))
		return
	}
	seen := map[string]bool{}
	hosts := []string{}
	for _, h := range strings.Split(raw, ",") {
		h = strings.TrimSuffix(strings.TrimSpace(h), ".")
		if h == "" || len(h) > 253 || seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
		if len(hosts) >= 32 {
			break
		}
	}
	type httpProbeRes struct {
		OK      bool    `json:"ok"`
		Latency float64 `json:"ms"`
		Code    int     `json:"code"`
	}
	probes := make(map[string]httpProbeRes, len(hosts))
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 可用性探测，不校验证书链
			// 自建 Transport 零值不带握手超时，目标 TLS 挂起时探测会长期滞留
			TLSHandshakeTimeout: 3 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, h := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := httpProbeRes{}
			for _, scheme := range []string{"https", "http"} {
				start := time.Now()
				req, err := http.NewRequest(http.MethodGet, scheme+"://"+h+"/", nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", "TunHook-Probe/1.0")
				resp, err := client.Do(req)
				if err != nil {
					continue // HTTPS 传输层失败 → 回退 HTTP
				}
				io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
				resp.Body.Close()
				res = httpProbeRes{OK: true, Latency: math.Round(float64(time.Since(start).Microseconds())/100) / 10, Code: resp.StatusCode}
				break
			}
			mu.Lock()
			probes[h] = res
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"probes": probes}))
}

// dnsSignature：域名特征 → 服务商名称
type dnsSignature struct{ key, vendor string }

// cdnSignatures：常见 CDN/云防护厂商的 CNAME 特征域名
var cdnSignatures = []dnsSignature{
	{"cloudflare", "Cloudflare"},
	{"cloudfront.net", "AWS CloudFront"},
	{"akamai", "Akamai"},
	{"edgesuite.net", "Akamai"},
	{"edgekey.net", "Akamai"},
	{"fastly.net", "Fastly"},
	{"azureedge.net", "Azure CDN"},
	{"alicdn.com", "阿里云 CDN"},
	{"aliyuncs.com", "阿里云"},
	{"kunlun", "阿里云 CDN"},
	{"dnsv1.com", "腾讯云 CDN"},
	{"cdnhwc", "华为云 CDN"},
	{"bsgslb.cn", "白山云"},
	{"wscdns.com", "网宿 CDN"},
	{"lxdns.com", "网宿 CDN"},
	{"cdn20.com", "网宿 CDN"},
	{"bdyd.com", "百度云 CDN"},
	{"jomodns.com", "百度云 CDN"},
	{"aicdn.com", "又拍云"},
	{"qiniudns.com", "七牛云"},
	{"volces.com", "火山引擎"},
	{"incapdns.net", "Imperva"},
	{"sucuri.net", "Sucuri"},
}

// nsSignatures：常见权威 DNS 服务商的 NS 域名特征
var nsSignatures = []dnsSignature{
	{"dnspod.net", "DNSPod（腾讯云）"},
	{"hichina.com", "阿里云"},
	{"alibabadns.com", "阿里云"},
	{"aliyun.com", "阿里云"},
	{"awsdns", "AWS Route 53"},
	{"cloudflare.com", "Cloudflare"},
	{"azure-dns", "Azure DNS"},
	{"googledomains.com", "Google Cloud"},
	{"googledns", "Google Cloud"},
	{"huaweicloud-dns", "华为云"},
}

// matchDNSVendor 按特征关键词匹配服务商（不区分大小写）
func matchDNSVendor(domain string, sigs []dnsSignature) string {
	d := strings.ToLower(domain)
	for _, s := range sigs {
		if strings.Contains(d, s.key) {
			return s.vendor
		}
	}
	return ""
}

// containsStr 列表包含判断
func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// randToken 生成指定长度的随机小写字母数字串（用于泛解析检测的随机前缀）
func randToken(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// isNoiseIP 判断子域名解析出的 IP 是否为泛解析噪声：
// 公网 DNS 返回私有 IP（RFC1918）对子域名枚举无价值，是泛解析/随机应答的典型特征
func isNoiseIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && isPrivateIPv4(ip)
}

// newDNSResolver 构建域名查询用的解析器。
// 根因：纯 Go resolver 会轮询 resolv.conf 里的全部 nameserver，
// 当列表含多个 IPv6（尤其链路本地）地址时整体易 i/o timeout；
// 这里固定 dial 到第一个 IPv4 nameserver，读取失败则回退系统默认。
// 注意：本机对 53 端口并发新建连接有限速，使用方应控制并发 ≤5。
func newDNSResolver() *net.Resolver {
	server := ""
	if f, err := os.Open("/etc/resolv.conf"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "nameserver ") {
				ns := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
				if ip := net.ParseIP(ns); ip != nil && ip.To4() != nil {
					server = ns
					break
				}
			}
		}
		// resolv.conf 读取异常（如超长行触发 bufio.ErrTooLong）时丢弃已解析结果，
		// 让下方 server == "" 分支回退系统默认解析器，避免静默使用不完整读取
		if err := sc.Err(); err != nil {
			server = ""
		}
	}
	if server == "" {
		return &net.Resolver{}
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		},
	}
}

// dohResolve 通过阿里 DoH（DNS over HTTPS）查询域名 A 记录，返回 IP 列表。
// Status 0（NOERROR）即视为节点存在——包括无 A 记录但有 TXT 等其他记录的节点（如 _dmarc）；
// NXDOMAIN（Status 3）返回错误。
func dohResolve(ctx context.Context, client *http.Client, name string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://dns.alidns.com/resolve?name="+url.QueryEscape(name)+"&type=A", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh http %d", resp.StatusCode)
	}
	var out struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	if out.Status != 0 {
		return nil, fmt.Errorf("doh status %d", out.Status)
	}
	var ips []string
	for _, a := range out.Answer {
		if a.Type == 1 { // A 记录
			ips = append(ips, a.Data)
		}
	}
	return ips, nil
}

// dohResolveMulti 连续查询 2 次合并去重：DNS 轮询/CDN 每次可能返回不同 IP 子集，
// 单次查询只能拿到部分地址，两次合并更接近真实解析集
func dohResolveMulti(ctx context.Context, client *http.Client, name string) ([]string, bool) {
	seen := map[string]bool{}
	var ips []string
	exists := false
	for i := 0; i < 2; i++ {
		if r, err := dohResolve(ctx, client, name); err == nil {
			exists = true
			for _, ip := range r {
				if !seen[ip] {
					seen[ip] = true
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips, exists
}

// dohQuery 通过阿里 DoH 查询指定类型 DNS 记录，返回 Answer 数据（已按类型过滤）。
// 用于主域 NS/SOA/TXT 等记录详情展示；查询失败或无记录返回 nil
func dohQuery(ctx context.Context, client *http.Client, name, typ string) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://dns.alidns.com/resolve?name="+url.QueryEscape(name)+"&type="+typ, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var out struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out) != nil || out.Status != 0 {
		return nil
	}
	var typeNum int
	switch typ {
	case "A":
		typeNum = 1
	case "NS":
		typeNum = 2
	case "SOA":
		typeNum = 6
	case "MX":
		typeNum = 15
	case "TXT":
		typeNum = 16
	case "AAAA":
		typeNum = 28
	default:
		return nil
	}
	var vals []string
	for _, a := range out.Answer {
		if a.Type == typeNum {
			vals = append(vals, a.Data)
		}
	}
	return vals
}

// subdDict 子域名枚举字典：常见业务/运维/服务前缀 + DNS 特殊节点（DMARC/DKIM/自动发现等）
var subdDict = []string{
	"www", "mail", "ftp", "api", "api2", "ns1", "ns2", "ns3", "ns4", "smtp",
	"pop", "pop3", "imap", "exchange", "owa", "webmail", "email", "mx", "mx1", "mx2",
	"relay", "smpt2", "blog", "shop", "store", "mall", "pay", "billing", "order", "b2b",
	"b2c", "app", "m", "mobile", "wap", "h5", "mini", "admin", "manage", "manager",
	"portal", "console", "dashboard", "sso", "auth", "login", "id", "oauth", "passport", "account",
	"dev", "devel", "test", "testing", "uat", "sit", "staging", "stage", "beta", "alpha",
	"demo", "pre", "gray", "release", "git", "github", "gitlab", "svn", "jenkins", "ci",
	"cd", "build", "deploy", "wiki", "docs", "doc", "confluence", "jira", "oa", "crm",
	"erp", "hr", "bpm", "ehr", "fin", "office", "corp", "intranet", "internal", "gw",
	"gateway", "router", "nas", "home", "vpn", "vpn2", "remote", "proxy", "cache", "cdn",
	"img", "img2", "images", "image", "pic", "photo", "static", "assets", "asset", "media",
	"video", "live", "stream", "dl", "dl2", "download", "down", "file", "files", "pan",
	"share", "cloud", "pan2", "bbs", "forum", "community", "club", "help", "support", "faq",
	"news", "news2", "game", "g", "play", "db", "mysql", "mariadb", "postgres", "pgsql",
	"redis", "mongo", "mongodb", "es", "elasticsearch", "kibana", "grafana", "prometheus", "zabbix", "monitor",
	"status", "log", "logs", "syslog", "task", "job", "cron", "scheduler", "queue", "mq",
	"kafka", "rabbitmq", "rocketmq", "zookeeper", "consul", "nacos", "sentinel", "vault", "k8s", "kube",
	"docker", "registry", "harbor", "mirror", "apt", "yum", "pypi", "npm", "update", "upgrade",
	"_dmarc", "_domainkey", "dkim", "autoconfig", "autodiscover",
}

// subdCache 子域名查询结果内存缓存：crt.sh 对同域名连续查询限流严重（502/超时），
// 短期内重复查询直接返回缓存结果，保证展示稳定
var subdCache = struct {
	sync.Mutex
	m map[string]subdCacheEntry
}{m: map[string]subdCacheEntry{}}

type subdCacheEntry struct {
	data []byte
	at   time.Time
}

const subdCacheTTL = 15 * time.Minute

func subdCacheGet(host string) []byte {
	subdCache.Lock()
	defer subdCache.Unlock()
	if e, ok := subdCache.m[host]; ok && time.Since(e.at) < subdCacheTTL {
		return e.data
	}
	delete(subdCache.m, host)
	return nil
}

func subdCacheSet(host string, data []byte) {
	subdCache.Lock()
	defer subdCache.Unlock()
	subdCache.m[host] = subdCacheEntry{data: data, at: time.Now()}
}

// handleSubdomains 子域名发现：内置字典 DNS 枚举 + crt.sh 证书透明度日志，合并去重并解析 IP。
// 请求: GET /api/ports/subdomains?host=example.com
func (s *Server) handleSubdomains(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" || !strings.Contains(host, ".") {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请输入合法域名"))
		return
	}
	host = strings.ToLower(host)
	start := time.Now()
	// 命中缓存直接返回（crt.sh 限流期内重复查询保证结果稳定）
	if cached := subdCacheGet(host); cached != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		w.Write(cached)
		return
	}
	type subdInfo struct {
		Name     string   `json:"name"`
		IPs      []string `json:"ips"`
		Sources  []string `json:"sources"`
		Wildcard bool     `json:"wildcard"`
	}
	var mu sync.Mutex
	found := map[string]*subdInfo{}
	addIP := func(name, src string, ips []string) {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		// 仅保留主域的子域名，排除主域自身与通配符
		if name == "" || name == host || strings.HasPrefix(name, "*") || !strings.HasSuffix(name, "."+host) {
			return
		}
		if f, ok := found[name]; ok {
			if !containsStr(f.Sources, src) {
				f.Sources = append(f.Sources, src)
			}
			if len(ips) > 0 && len(f.IPs) == 0 {
				f.IPs = append(f.IPs, ips...)
			}
			return
		}
		found[name] = &subdInfo{Name: name, IPs: append([]string{}, ips...), Sources: []string{src}}
	}
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 5 * time.Second}
	// 0) 泛解析检测：查询 3 个随机前缀，若能解析说明域名启用了泛解析（* 记录）。
	// 占位 IP 用于过滤字典枚举的误报——泛解析下任意前缀都可解析，会全量命中。
	// 有的泛解析（如 jd.com）每次返回随机 IP，单靠占位 IP 对比拦不住，
	// 因此同时把私有地址（RFC1918/CGNAT/环回）视为噪声：公网 DNS 返回内网 IP 对外部探测无价值
	hasWildcard := false
	wildcardIPs := map[string]bool{}
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		rname := "tunhook-" + randToken(12) + "." + host
		if ips, err := dohResolve(ctx, client, rname); err == nil {
			hasWildcard = true
			for _, ip := range ips {
				wildcardIPs[ip] = true
			}
		}
		cancel()
	}
	// 1) 字典枚举：DoH 查询 prefix.host（节点存在即记录，含无 A 记录的 TXT 节点如 _dmarc）。
	// 根因规避：本机对 53 端口新建连接限速（并发即整体超时），DoH 走 443 不受影响
	sem := make(chan struct{}, 20)
	for _, p := range subdDict {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			name := p + "." + host
			if ips, ok := dohResolveMulti(ctx, client, name); ok {
				mu.Lock()
				addIP(name, "dict", ips)
				mu.Unlock()
			}
		}(p)
	}
	// 2) 证书透明度日志（crt.sh）：历史签发记录中的子域名，失败静默降级。
	// crt.sh 大查询响应慢且对连续查询限流，故流式解析（截断保留已读记录）+ 失败重试 1 次
	wg.Add(1)
	go func() {
		defer wg.Done()
		for attempt := 0; attempt < 2; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://crt.sh/?q=%25."+host+"&output=json", nil)
			if err != nil {
				cancel()
				return
			}
			req.Header.Set("User-Agent", "TunHook")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				cancel()
				time.Sleep(2 * time.Second)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				cancel()
				time.Sleep(2 * time.Second)
				continue
			}
			dec := json.NewDecoder(resp.Body)
			if _, err := dec.Token(); err != nil { // 数组开括号
				resp.Body.Close()
				cancel()
				time.Sleep(2 * time.Second)
				continue
			}
			broken := false
			for dec.More() {
				var it struct {
					NameValue string `json:"name_value"`
				}
				if err := dec.Decode(&it); err != nil {
					broken = true // 响应被截断，保留已解析部分
					break
				}
				for _, n := range strings.Split(it.NameValue, "\n") {
					if n = strings.TrimSpace(n); n != "" {
						mu.Lock()
						addIP(n, "crt", nil)
						mu.Unlock()
					}
				}
			}
			resp.Body.Close()
			cancel()
			if !broken { // 完整响应，无需重试
				return
			}
			time.Sleep(2 * time.Second)
		}
	}()
	wg.Wait()
	// 3) 对缺 IP 的证书来源子域名解析当前 IP（字典来源已在枚举时拿到；DoH，并发 20）
	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	need := make([]string, 0, len(names))
	for _, n := range names {
		if len(found[n].IPs) == 0 && containsStr(found[n].Sources, "crt") {
			need = append(need, n)
		}
	}
	if len(need) > 100 {
		need = need[:100]
	}
	sem2 := make(chan struct{}, 20)
	var wg2 sync.WaitGroup
	for _, n := range need {
		wg2.Add(1)
		go func(n string) {
			defer wg2.Done()
			sem2 <- struct{}{}
			defer func() { <-sem2 }()
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			if ips, ok := dohResolveMulti(ctx, client, n); ok && len(ips) > 0 {
				mu.Lock()
				found[n].IPs = append(found[n].IPs, ips...)
				mu.Unlock()
			}
		}(n)
	}
	wg2.Wait()
	// 4) 泛解析过滤：泛解析启用时，命中占位 IP 或私有 IP 的子域名是噪声——
	// 纯字典来源直接丢弃，证书来源保留并标注（证书记录证明该子域真实存在过）
	isNoise := func(ips []string) bool {
		if !hasWildcard || len(ips) == 0 {
			return false
		}
		for _, ip := range ips {
			if wildcardIPs[ip] || isNoiseIP(ip) {
				continue
			}
			return false
		}
		return true
	}
	out := struct {
		Host        string     `json:"host"`
		Count       int        `json:"count"`
		Wildcard    bool       `json:"wildcard"`
		WildcardIPs []string   `json:"wildcard_ips"`
		NS          []string   `json:"ns"`
		SOA         string     `json:"soa"`
		TXT         []string   `json:"txt"`
		DmarcTXT    []string   `json:"dmarc_txt"`
		Found       []subdInfo `json:"found"`
		DurationMs  float64    `json:"duration_ms"`
	}{Host: host, Found: make([]subdInfo, 0, len(names)), WildcardIPs: []string{}}
	// 5) 主域 NS/SOA/TXT 与 _dmarc TXT 记录（对齐子域名面板的"DNS记录详情"展示）
	q := func(name, typ string) []string {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		return dohQuery(ctx, client, name, typ)
	}
	out.NS = q(host, "NS")
	if soa := q(host, "SOA"); len(soa) > 0 {
		if fields := strings.Fields(soa[0]); len(fields) > 0 {
			out.SOA = fields[0] // SOA 首字段为 MNAME 主 NS
		}
	}
	for _, t := range q(host, "TXT") {
		out.TXT = append(out.TXT, strings.Trim(t, `"`))
	}
	if _, ok := found["_dmarc."+host]; ok {
		for _, t := range q("_dmarc."+host, "TXT") {
			out.DmarcTXT = append(out.DmarcTXT, strings.Trim(t, `"`))
		}
	}
	out.Wildcard = hasWildcard
	for _, n := range names {
		f := found[n]
		// 证书来源始终可信（TLS 证书记录证明该子域名真实签发过），不做泛解析标注；
		// 纯字典来源命中泛解析（占位 IP / 内网 IP）时标注 wildcard，可信结果排前
		if !containsStr(f.Sources, "crt") && isNoise(f.IPs) {
			f.Wildcard = true
		}
		out.Found = append(out.Found, *f)
	}
	// 泛解析条目（对齐参考站展示）：通配记录本身作为一行，IP 为占位 IP 池
	if hasWildcard {
		wl := make([]string, 0, len(wildcardIPs))
		for ip := range wildcardIPs {
			wl = append(wl, ip)
		}
		sort.Strings(wl)
		out.WildcardIPs = wl
		out.Found = append(out.Found, subdInfo{Name: "*." + host, IPs: wl, Sources: []string{"wildcard"}, Wildcard: true})
	}
	sort.SliceStable(out.Found, func(i, j int) bool {
		if out.Found[i].Wildcard != out.Found[j].Wildcard {
			return !out.Found[i].Wildcard
		}
		return out.Found[i].Name < out.Found[j].Name
	})
	out.Count = len(out.Found)
	out.DurationMs = math.Round(float64(time.Since(start).Microseconds())/100) / 10
	if payload, err := json.Marshal(apiOK(out)); err == nil {
		subdCacheSet(host, payload)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		w.Write(payload)
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(out))
}

// handlePortPing 调用系统 ping 对目标地址发送 4 个探测包，返回可达性、平均延迟与丢包率。
// IPv6 地址自动加 -6 参数；输出原文一并返回。
// 请求体: {"addr":"192.168.1.1"}
func (s *Server) handlePortPing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Addr string `json:"addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求"))
		return
	}
	addr := strings.TrimSpace(req.Addr)
	if addr == "" || len(addr) > 253 || strings.ContainsAny(addr, " \t\r\n;&|'\"") {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的地址"))
		return
	}
	args := []string{"-c", "4", "-W", "2"}
	if strings.Contains(addr, ":") {
		args = append(args, "-6")
	}
	args = append(args, addr)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "ping", args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	// ping 退出码非 0 时可能仍有部分成功输出，以解析结果为准：有丢包率且非 100% 即视为可达
	res := map[string]interface{}{"output": text, "ok": false}
	if m := regexp.MustCompile(`([\d.]+)% packet loss`).FindStringSubmatch(text); len(m) > 1 {
		if v, e := strconv.ParseFloat(m[1], 64); e == nil {
			res["loss"] = v
			res["ok"] = v < 100
		}
	}
	if m := regexp.MustCompile(`= [\d.]+/([\d.]+)/[\d.]+/[\d.]+`).FindStringSubmatch(text); len(m) > 1 {
		if v, e := strconv.ParseFloat(m[1], 64); e == nil {
			res["avg_ms"] = v
		}
	}
	// TTL 反推目标系统：观测值是初始 TTL 减去路由跳数，
	// 取标准初始值 64 / 128 / 255 中最接近且不小于观测值的一档。
	if ttl := parsePingTTL(text); ttl > 0 {
		res["ttl"] = ttl
		res["os_hint"] = guessOSByTTL(ttl)
	}
	s.writeJSON(w, http.StatusOK, apiOK(res))
}

// pingTTLRe 匹配 ping 输出中的 ttl 字段（Linux: ttl=64 / Windows: TTL=128）。
var pingTTLRe = regexp.MustCompile(`(?i)\bttl=(\d+)`)

// parsePingTTL 从 ping 输出中取 TTL（多包回复时取最小值，避免个别异常包干扰）。
// 无有效 TTL 时返回 0。
func parsePingTTL(text string) int {
	best := 0
	for _, g := range pingTTLRe.FindAllStringSubmatch(text, -1) {
		if v, e := strconv.Atoi(g[1]); e == nil && v > 0 && (best == 0 || v < best) {
			best = v
		}
	}
	return best
}

// guessOSByTTL 依据初始 TTL 档位粗略推断目标系统：
//   - 观测值 ≤ 64：初始 64 → Linux/Unix（含路由器等网络设备）
//   - 65 ~ 128：初始 128 → Windows
//   - > 128：初始 255 → 网络设备/Unix
func guessOSByTTL(ttl int) string {
	switch {
	case ttl <= 64:
		return "Linux/Unix"
	case ttl <= 128:
		return "Windows"
	default:
		return "网络设备/Unix"
	}
}

// handlePortKill 结束占用端口的进程：按 PID 发送 SIGTERM（正常终止，进程可自行清理）。
// 禁止结束自身与 PID 1；无权限时返回错误（如目标进程属于其他用户/root）。
// 请求体: {"pid":1234}
func (s *Server) handlePortKill(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PID int `json:"pid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求"))
		return
	}
	if req.PID <= 1 || req.PID == os.Getpid() {
		s.writeJSON(w, http.StatusBadRequest, apiErr("不允许结束该进程"))
		return
	}
	if err := syscall.Kill(req.PID, syscall.SIGTERM); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("结束进程失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"ok": true}))
}
