package web

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"go.uber.org/zap"
)

// WolDevice 网络唤醒设备（持久化到 settings KV，跨浏览器/设备共享）。
type WolDevice struct {
	ID        string `json:"id"`        // 设备唯一标识（保存时后端补齐）
	Name      string `json:"name"`      // 设备名称
	MAC       string `json:"mac"`       // 目标网卡 MAC，规范化为 AA:BB:CC:DD:EE:FF
	Broadcast string `json:"broadcast"` // 广播地址（如 192.168.1.255），默认 255.255.255.255
	Port      int    `json:"port"`      // WOL UDP 端口，默认 9
}

// wolDevicesKey 设备列表在 settings KV 中的键名。
const wolDevicesKey = "wol.devices"

// wolDefaultBroadcast 未指定广播地址时使用的全网广播地址。
const wolDefaultBroadcast = "255.255.255.255"

// wolDefaultPort WOL 默认端口（discard 服务端口，行业惯例 9 或 7）。
const wolDefaultPort = 9

// wolDeviceStore 设备列表的持久化结构。
type wolDeviceStore struct {
	Devices []WolDevice `json:"devices"`
}

// normalizeWolMAC 规范化 MAC 地址：支持 AA:BB:CC:DD:EE:FF / AA-BB-... / AABBCCDDEEFF。
// 返回统一的大写冒号分隔形式；格式非法时返回错误。
func normalizeWolMAC(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	// 无分隔符的 12 位十六进制补上冒号后再交给 net.ParseMAC
	if len(s) == 12 && !strings.ContainsAny(s, ":-.") {
		parts := make([]string, 0, 6)
		for i := 0; i < 12; i += 2 {
			parts = append(parts, s[i:i+2])
		}
		s = strings.Join(parts, ":")
	}
	mac, err := net.ParseMAC(s)
	if err != nil || len(mac) != 6 {
		return "", fmt.Errorf("MAC 地址格式无效，应为 AA:BB:CC:DD:EE:FF")
	}
	return strings.ToUpper(mac.String()), nil
}

// normalizeWolBroadcast 校验广播地址：留空使用全网广播，仅接受 IPv4。
func normalizeWolBroadcast(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return wolDefaultBroadcast, nil
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("广播地址无效，应为 IPv4 地址（如 192.168.1.255）")
	}
	return ip.To4().String(), nil
}

// loadWolDevices 读取已保存的设备列表（无记录或解析失败时返回空列表）。
func (s *Server) loadWolDevices() []WolDevice {
	raw, err := s.store.GetSetting(wolDevicesKey)
	if err != nil || raw == "" {
		return []WolDevice{}
	}
	var st wolDeviceStore
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return []WolDevice{}
	}
	if st.Devices == nil {
		return []WolDevice{}
	}
	return st.Devices
}

// handleWolDevicesGet 返回全部网络唤醒设备。
func (s *Server) handleWolDevicesGet(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"devices": s.loadWolDevices()}))
}

// handleWolDevicesSave 整体保存设备列表（新增/编辑/删除均由前端提交完整列表）。
// 后端统一校验并补齐 ID / 默认广播地址 / 默认端口，避免界面被绕过写入非法数据。
func (s *Server) handleWolDevicesSave(w http.ResponseWriter, r *http.Request) {
	var req wolDeviceStore
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	out := make([]WolDevice, 0, len(req.Devices))
	seen := map[string]bool{}
	for _, d := range req.Devices {
		name := strings.TrimSpace(d.Name)
		if name == "" {
			s.writeJSON(w, http.StatusBadRequest, apiErr("设备名称不能为空"))
			return
		}
		if len([]rune(name)) > 64 {
			s.writeJSON(w, http.StatusBadRequest, apiErr("设备名称不能超过 64 个字符"))
			return
		}
		mac, err := normalizeWolMAC(d.MAC)
		if err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiErr("「"+name+"」"+err.Error()))
			return
		}
		broadcast, err := normalizeWolBroadcast(d.Broadcast)
		if err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiErr("「"+name+"」"+err.Error()))
			return
		}
		port := d.Port
		if port == 0 {
			port = wolDefaultPort
		}
		if port < 1 || port > 65535 {
			s.writeJSON(w, http.StatusBadRequest, apiErr("「"+name+"」端口范围为 1-65535"))
			return
		}
		id := strings.TrimSpace(d.ID)
		if id == "" || seen[id] {
			id = strconv.FormatInt(time.Now().UnixNano(), 36)
		}
		seen[id] = true
		out = append(out, WolDevice{ID: id, Name: name, MAC: mac, Broadcast: broadcast, Port: port})
	}
	if err := s.store.SetJSON(wolDevicesKey, wolDeviceStore{Devices: out}); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("保存设备列表失败: "+err.Error()))
		return
	}
	wolStatusCacheInvalidate() // 设备集合变化，旧的开机状态不再适用
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"devices": out}))
}

// handleWolWake 向指定设备发送 WOL 魔术包。
// 请求体: {"id":"设备ID"}
func (s *Server) handleWolWake(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求"))
		return
	}
	id := strings.TrimSpace(req.ID)
	if id == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请选择要唤醒的设备"))
		return
	}
	var target *WolDevice
	for _, d := range s.loadWolDevices() {
		if d.ID == id {
			dev := d
			target = &dev
			break
		}
	}
	if target == nil {
		s.writeJSON(w, http.StatusOK, apiErr("设备不存在，请刷新后重试"))
		return
	}
	mac, err := normalizeWolMAC(target.MAC)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	hw, _ := net.ParseMAC(mac)
	if err := sendWOLMagicPacket(hw, target.Broadcast, target.Port); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("发送魔术包失败: "+err.Error()))
		return
	}
	wolStatusCacheInvalidate() // 唤醒后设备状态可能变化，下次查询需重新检测
	if s.logger != nil {
		s.logger.Info("已发送网络唤醒魔术包",
			zap.String("name", target.Name),
			zap.String("mac", mac),
			zap.String("broadcast", target.Broadcast),
			zap.Int("port", target.Port))
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"name":      target.Name,
		"mac":       mac,
		"broadcast": target.Broadcast,
		"port":      target.Port,
	}))
}

// sendWOLMagicPacket 构造并发送 WOL 魔术包：6 字节 0xFF + 目标 MAC 重复 16 次，共 102 字节。
// UDP 默认由 Go 在 IPv4 套接字上开启 SO_BROADCAST，可直接发往广播地址。
func sendWOLMagicPacket(mac net.HardwareAddr, broadcast string, port int) error {
	ip := net.ParseIP(broadcast)
	if ip == nil {
		return fmt.Errorf("广播地址无效: %s", broadcast)
	}
	pkt := make([]byte, 102)
	for i := 0; i < 6; i++ {
		pkt[i] = 0xFF
	}
	for i := 1; i <= 16; i++ {
		copy(pkt[i*6:], mac)
	}
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip.To4(), Port: port})
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(pkt)
	return err
}

// wolScanHost 局域网扫描发现的设备。
type wolScanHost struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`          // 反向 DNS / NetBIOS / mDNS / UPnP 查到的名称，查不到为空
	OSHint   string `json:"os_hint,omitempty"` // 按 ping TTL 推断的系统类型，禁 ping 时为空
}

// handleWolScan 扫描本机所在局域网，返回在线主机的 IP / MAC / 主机名。
// 实现路径：向网段内每个地址发一个 UDP 空包触发内核 ARP 解析，随后读 /proc/net/arp
// 取已解析条目（离线地址保持 incomplete、MAC 全 0，被过滤）。
func (s *Server) handleWolScan(w http.ResponseWriter, r *http.Request) {
	info, err := detectLanRange()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	ips, err := parseIPRange(info.Start + "-" + info.End)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	// 并发触发 ARP（仅发包，不等待响应）
	triggerARPEntries(ips)
	// 等 ARP 应答回流后再读表（局域网 ARP 往返通常 <10ms，留足余量）
	time.Sleep(500 * time.Millisecond)

	arp := readARPTable()
	hosts := make([]wolScanHost, 0, len(arp))
	for _, ip := range ips {
		mac, ok := arp[ip.String()]
		if !ok {
			continue
		}
		hosts = append(hosts, wolScanHost{IP: ip.String(), MAC: mac})
	}
	// 系统推断与名称解析并行：两者互不依赖，避免串行叠加扫描耗时
	var osWG sync.WaitGroup
	osWG.Add(1)
	go func() {
		defer osWG.Done()
		probeWolOS(hosts)
	}()
	resolveWolHostnames(hosts)
	applyUPnPNames(hosts)
	osWG.Wait()
	sort.Slice(hosts, func(i, j int) bool {
		return ip4ToUint32(net.ParseIP(hosts[i].IP)) < ip4ToUint32(net.ParseIP(hosts[j].IP))
	})
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"range": info.CIDR,
		"hosts": hosts,
		"count": len(hosts),
	}))
}

// triggerARPEntries 向给定地址各发一个 UDP 空包，触发内核完成 ARP 解析。
func triggerARPEntries(ips []net.IP) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip.To4(), Port: wolDefaultPort})
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte{0})
			_ = conn.Close()
		}(ip)
	}
	wg.Wait()
}

// wolStatusResult 已保存设备的开机状态与系统推断结果（均为 设备ID → 值）。
type wolStatusResult struct {
	Statuses map[string]bool   `json:"statuses"`
	OS       map[string]string `json:"os"`
}

// handleWolStatus 检测已保存设备的开机状态与系统类型：
// 先主动触发本网段 ARP 解析，按 MAC 匹配到 IP 判断在线，再对在线设备 ping 取 TTL 推断系统。
// 结果缓存 wolStatusCacheTTL：短时间内的重复请求（多标签页/页面切换）直接复用，
// 避免每次都做一遍全网段 ARP；设备列表变更与发送唤醒后主动失效。
func (s *Server) handleWolStatus(w http.ResponseWriter, r *http.Request) {
	if cached, ok := wolStatusCacheGet(); ok {
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
			"statuses": cached.Statuses, "os": cached.OS, "cached": true,
		}))
		return
	}
	devices := s.loadWolDevices()
	res := &wolStatusResult{Statuses: map[string]bool{}, OS: map[string]string{}}
	if len(devices) == 0 {
		wolStatusCacheSet(res)
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
			"statuses": res.Statuses, "os": res.OS, "cached": false,
		}))
		return
	}
	if info, err := detectLanRange(); err == nil {
		if ips, err := parseIPRange(info.Start + "-" + info.End); err == nil {
			triggerARPEntries(ips)
			time.Sleep(600 * time.Millisecond)
		}
	}
	ipByMAC := map[string]string{}
	for ip, mac := range readARPTable() {
		ipByMAC[strings.ToUpper(mac)] = ip
	}
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	for _, d := range devices {
		mac, err := normalizeWolMAC(d.MAC)
		if err != nil {
			res.Statuses[d.ID] = false
			continue
		}
		ip, online := ipByMAC[mac]
		res.Statuses[d.ID] = online
		if !online {
			continue
		}
		// 在线设备才做 TTL 探测：设备数量通常很少，开销可忽略
		wg.Add(1)
		go func(id, ip string) {
			defer wg.Done()
			if ttl := pingTTL(ip); ttl > 0 {
				mu.Lock()
				res.OS[id] = guessOSByTTL(ttl)
				mu.Unlock()
			}
		}(d.ID, ip)
	}
	wg.Wait()
	wolStatusCacheSet(res)
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"statuses": res.Statuses, "os": res.OS, "cached": false,
	}))
}

// wolStatusCacheTTL 开机状态缓存时长：需明显小于「唤醒后 5 秒刷新」的等待，
// 且唤醒接口会主动失效，故不会返回唤醒前的旧状态。
const wolStatusCacheTTL = 10 * time.Second

var (
	wolStatusCacheMu sync.Mutex
	wolStatusCache   *wolStatusResult
	wolStatusCacheAt time.Time
)

// wolStatusCacheGet 读取未过期的状态缓存。
func wolStatusCacheGet() (*wolStatusResult, bool) {
	wolStatusCacheMu.Lock()
	defer wolStatusCacheMu.Unlock()
	if wolStatusCache != nil && time.Since(wolStatusCacheAt) < wolStatusCacheTTL {
		return wolStatusCache, true
	}
	return nil, false
}

// wolStatusCacheSet 写入状态缓存。
func wolStatusCacheSet(res *wolStatusResult) {
	wolStatusCacheMu.Lock()
	wolStatusCache = res
	wolStatusCacheAt = time.Now()
	wolStatusCacheMu.Unlock()
}

// wolStatusCacheInvalidate 使缓存失效（设备列表变更、发送唤醒后调用）。
func wolStatusCacheInvalidate() {
	wolStatusCacheMu.Lock()
	wolStatusCache = nil
	wolStatusCacheAt = time.Time{}
	wolStatusCacheMu.Unlock()
}

// readARPTable 读取 /proc/net/arp，返回 IP → MAC（跳过 incomplete 条目）。
func readARPTable() map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ip, mac := fields[0], fields[3]
		if net.ParseIP(ip) == nil || mac == "00:00:00:00:00:00" {
			continue
		}
		out[ip] = strings.ToUpper(mac)
	}
	return out
}

// probeWolOS 对每台设备发送 1 个 ping 包，按 TTL 推断系统类型（禁 ping 的设备保持为空）。
func probeWolOS(hosts []wolScanHost) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if ttl := pingTTL(hosts[i].IP); ttl > 0 {
				hosts[i].OSHint = guessOSByTTL(ttl)
			}
		}(i)
	}
	wg.Wait()
}

// pingTTL 发送 1 个 ICMP 探测包并返回 TTL；目标不可达或禁 ping 时返回 0。
func pingTTL(ip string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip).CombinedOutput()
	return parsePingTTL(string(out))
}

// resolveWolHostnames 并发解析主机名。
func resolveWolHostnames(hosts []wolScanHost) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			hosts[i].Hostname = lookupHostname(hosts[i].IP)
		}(i)
	}
	wg.Wait()
}

// lookupHostname 并行执行三种局域网名称查询，返回最先拿到的非空结果。
// 普通局域网基本没有反向 DNS 记录，NetBIOS(NBSTAT) 与 mDNS 才是获取设备名的有效途径。
func lookupHostname(ip string) string {
	ch := make(chan string, 3)
	go func() { ch <- lookupPTR(ip) }()
	go func() { ch <- lookupNetBIOSName(ip) }()
	go func() { ch <- lookupMDNSName(ip) }()
	deadline := time.After(1200 * time.Millisecond)
	for i := 0; i < 3; i++ {
		select {
		case n := <-ch:
			if n = sanitizeWolHostname(n); n != "" {
				return n
			}
		case <-deadline:
			return ""
		}
	}
	return ""
}

// sanitizeWolHostname 清理名称：去掉 mDNS 后缀与设备自报的占位名（如 "(none).local"）。
func sanitizeWolHostname(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimSuffix(name, ".local")
	name = strings.TrimSuffix(name, ".lan")
	name = strings.TrimSpace(name)
	if name == "" || strings.HasPrefix(strings.ToLower(name), "(none)") {
		return ""
	}
	return name
}

// lookupPTR 反向 DNS 查询（系统 resolver）。
func lookupPTR(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// lookupNetBIOSName 通过 NetBIOS 名称服务（NBSTAT，UDP 137）查询 Windows/NAS 设备名。
func lookupNetBIOSName(ip string) string {
	conn, err := net.DialTimeout("udp4", net.JoinHostPort(ip, "137"), 300*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write(buildNBSTATQuery()); err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return ""
	}
	return parseNBSTATNames(buf[:n])
}

// buildNBSTATQuery 构造 NBSTAT 查询包（查询名 "*" 编码后为 32 字节半角字符）。
func buildNBSTATQuery() []byte {
	pkt := []byte{
		0x82, 0x1C, // 事务 ID
		0x00, 0x00, // flags
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // QDCOUNT=1，其余 0
		0x20, 'C', 'K', // 编码后的 "*"：长度 32，首两字符 "CK"
	}
	for i := 0; i < 30; i++ {
		pkt = append(pkt, 'A')
	}
	pkt = append(pkt,
		0x00,       // 名称结束
		0x00, 0x21, // QTYPE=NBSTAT
		0x00, 0x01, // QCLASS=IN
	)
	return pkt
}

// parseNBSTATNames 从 NBSTAT 响应中取工作站名称（跳过组名与无效编码）。
func parseNBSTATNames(buf []byte) string {
	off := 12
	off = skipDNSName(buf, off) // 问题名
	off += 4                    // QTYPE + QCLASS
	if off+10 > len(buf) {
		return ""
	}
	off = skipDNSName(buf, off) // 答案名
	off += 8                    // TYPE + CLASS + TTL
	if off+2 > len(buf) {
		return ""
	}
	rdlen := int(binary.BigEndian.Uint16(buf[off:]))
	off += 2
	if off+rdlen > len(buf) || rdlen < 1 {
		return ""
	}
	data := buf[off : off+rdlen]
	count := int(data[0])
	for i := 0; i < count; i++ {
		start := 1 + i*18
		if start+18 > len(data) {
			break
		}
		raw := data[start : start+16]
		flags := binary.BigEndian.Uint16(data[start+16 : start+18])
		if flags&0x8000 != 0 { // 组名（WORKGROUP 等），不是设备名
			continue
		}
		name := strings.TrimSpace(strings.TrimRight(string(raw), "\x00"))
		if name == "" || !utf8.ValidString(name) || strings.ContainsRune(name, '\x00') {
			continue
		}
		// 名称列表首项为计算机名（<00> workstation），取第一个唯一名即可
		return name
	}
	return ""
}

// lookupMDNSName 通过 mDNS（UDP 5353）反向 PTR 查询 hostname.local（Apple/Linux/IoT 设备）。
func lookupMDNSName(ip string) string {
	conn, err := net.DialTimeout("udp4", net.JoinHostPort(ip, "5353"), 350*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(350 * time.Millisecond))
	if _, err := conn.Write(buildMDNSPTRQuery(ip)); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}
	return parseMDNSPTR(buf[:n])
}

// buildMDNSPTRQuery 构造反向 PTR 查询（QU 位请求单播响应）。
func buildMDNSPTRQuery(ip string) []byte {
	p := strings.Split(ip, ".")
	name := p[3] + "." + p[2] + "." + p[1] + "." + p[0] + ".in-addr.arpa"
	buf := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00, 0x00, 0x0C, 0x80, 0x01) // 结束 + QTYPE=PTR + QU/IN
	return buf
}

// skipDNSName 跳过 DNS 名称（含压缩指针），返回后续字段偏移。
func skipDNSName(buf []byte, off int) int {
	for off < len(buf) {
		l := int(buf[off])
		if l == 0 {
			return off + 1
		}
		if l&0xC0 == 0xC0 {
			return off + 2
		}
		off += 1 + l
	}
	return off
}

// dnsReadName 解析 DNS 名称（处理压缩指针），返回名称与后续偏移。
func dnsReadName(buf []byte, off int) (string, int) {
	var parts []string
	next := off
	jumped := false
	for steps := 0; steps < 20 && off < len(buf); steps++ {
		l := int(buf[off])
		if l == 0 {
			if !jumped {
				next = off + 1
			}
			break
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(buf) {
				break
			}
			if !jumped {
				next = off + 2
			}
			jumped = true
			off = int(binary.BigEndian.Uint16(buf[off:]) & 0x3FFF)
			continue
		}
		if off+1+l > len(buf) {
			break
		}
		parts = append(parts, string(buf[off+1:off+1+l]))
		off += 1 + l
		if !jumped {
			next = off
		}
	}
	return strings.Join(parts, "."), next
}

// parseMDNSPTR 从 mDNS 响应中取第一条 PTR 记录。
func parseMDNSPTR(buf []byte) string {
	qd := int(binary.BigEndian.Uint16(buf[4:6]))
	an := int(binary.BigEndian.Uint16(buf[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		_, off = dnsReadName(buf, off)
		off += 4
		if off > len(buf) {
			return ""
		}
	}
	for i := 0; i < an; i++ {
		_, off = dnsReadName(buf, off)
		if off+10 > len(buf) {
			return ""
		}
		typ := binary.BigEndian.Uint16(buf[off:])
		off += 8 // TYPE + CLASS + TTL
		rdlen := int(binary.BigEndian.Uint16(buf[off:]))
		off += 2
		if off+rdlen > len(buf) {
			return ""
		}
		if typ == 12 {
			name, _ := dnsReadName(buf, off)
			if name != "" {
				return strings.TrimSuffix(name, ".")
			}
		}
		off += rdlen
	}
	return ""
}

// applyUPnPNames 对仍未解析出名称的设备补充 UPnP friendlyName（SSDP 发现 + 描述文档抓取）。
// 全部设备都已有名称时跳过，避免无谓的多播等待。
func applyUPnPNames(hosts []wolScanHost) {
	need := false
	for _, h := range hosts {
		if h.Hostname == "" {
			need = true
			break
		}
	}
	if !need {
		return
	}
	names := discoverUPnPNames(1500 * time.Millisecond)
	if len(names) == 0 {
		return
	}
	for i := range hosts {
		if hosts[i].Hostname != "" {
			continue
		}
		if n, ok := names[hosts[i].IP]; ok {
			hosts[i].Hostname = n
		}
	}
}

// discoverUPnPNames 通过 SSDP M-SEARCH 发现局域网 UPnP 设备，抓取描述文档中的
// friendlyName（如「客厅电视」「小米路由器」），返回 IP → 名称。
func discoverUPnPNames(timeout time.Duration) map[string]string {
	out := map[string]string{}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return out
	}
	defer conn.Close()
	req := []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: ssdp:all\r\n\r\n")
	if _, err := conn.WriteToUDP(req, &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}); err != nil {
		return out
	}
	// 收集响应：LOCATION 指向设备描述文档，优先用其中的 IP（与响应源地址不一致时更可靠）
	locations := map[string]string{}
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(deadline)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		loc := ssdpLocation(string(buf[:n]))
		if loc == "" {
			continue
		}
		ip := ssdpHostIP(loc, addr.IP.String())
		if _, ok := locations[ip]; !ok {
			locations[ip] = loc
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for ip, loc := range locations {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip, loc string) {
			defer wg.Done()
			defer func() { <-sem }()
			if name := fetchUPnPFriendlyName(loc); name != "" {
				mu.Lock()
				out[ip] = name
				mu.Unlock()
			}
		}(ip, loc)
	}
	wg.Wait()
	return out
}

// ssdpLocation 从 SSDP 响应头中提取 LOCATION 字段。
func ssdpLocation(resp string) string {
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 9 && strings.EqualFold(line[:9], "location:") {
			return strings.TrimSpace(line[9:])
		}
	}
	return ""
}

// ssdpHostIP 取 LOCATION URL 中的 IP；不是 IP（如域名）时回退到响应源地址。
func ssdpHostIP(location, fallback string) string {
	u, err := url.Parse(location)
	if err == nil {
		if ip := net.ParseIP(u.Hostname()); ip != nil && ip.To4() != nil {
			return ip.To4().String()
		}
	}
	return fallback
}

var friendlyNameRe = regexp.MustCompile(`(?is)<friendlyname[^>]*>(.*?)</friendlyname>`)

// fetchUPnPFriendlyName 抓取 UPnP 设备描述文档并提取 friendlyName。
func fetchUPnPFriendlyName(location string) string {
	client := &http.Client{Timeout: 800 * time.Millisecond}
	resp, err := client.Get(location)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return ""
	}
	m := friendlyNameRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	name := strings.TrimSpace(html.UnescapeString(string(m[1])))
	name = strings.Join(strings.Fields(name), " ")
	if name == "" || !utf8.ValidString(name) {
		return ""
	}
	if r := []rune(name); len(r) > 64 {
		name = string(r[:64])
	}
	return name
}
