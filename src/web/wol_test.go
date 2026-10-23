package web

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeWolMAC(t *testing.T) {
	cases := map[string]string{
		"aa:bb:cc:dd:ee:ff": "AA:BB:CC:DD:EE:FF",
		"AA-BB-CC-DD-EE-FF": "AA:BB:CC:DD:EE:FF",
		"aabbccddeeff":      "AA:BB:CC:DD:EE:FF",
	}
	for in, want := range cases {
		got, err := normalizeWolMAC(in)
		if err != nil || got != want {
			t.Fatalf("normalizeWolMAC(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := normalizeWolMAC("aa:bb:cc"); err == nil {
		t.Fatal("非法 MAC 应报错")
	}
}

func TestNormalizeWolBroadcast(t *testing.T) {
	if got, _ := normalizeWolBroadcast(""); got != wolDefaultBroadcast {
		t.Fatalf("空广播地址应回退默认值，得到 %q", got)
	}
	if _, err := normalizeWolBroadcast("::1"); err == nil {
		t.Fatal("IPv6 应被拒绝")
	}
}

func TestSanitizeWolHostname(t *testing.T) {
	cases := map[string]string{
		"DS6989.local":  "DS6989",
		"iPhone.lan":    "iPhone",
		"(none).local":  "",
		"(none)-2.lan":  "",
		"  nas.local  ": "nas",
	}
	for in, want := range cases {
		if got := sanitizeWolHostname(in); got != want {
			t.Fatalf("sanitizeWolHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParseNBSTATNames 用构造的 NBSTAT 响应验证名称提取（含组名跳过）。
func TestParseNBSTATNames(t *testing.T) {
	rdata := []byte{2} // 2 条名称
	name1 := make([]byte, 16)
	copy(name1, "WORKGROUP")
	rdata = append(rdata, name1...)
	rdata = append(rdata, 0x84, 0x00) // 组名（G 位）
	name2 := make([]byte, 16)
	copy(name2, "MY-PC")
	rdata = append(rdata, name2...)
	rdata = append(rdata, 0x04, 0x00) // 唯一名

	buf := []byte{0x82, 0x1C, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0} // QD=1, AN=1
	buf = append(buf, 0x20, 'C', 'K')
	for i := 0; i < 30; i++ {
		buf = append(buf, 'A')
	}
	buf = append(buf, 0x00, 0x00, 0x21, 0x00, 0x01) // 问题名结束 + NBSTAT + IN
	buf = append(buf, 0xC0, 0x0C)                   // 答案名压缩指针
	buf = append(buf, 0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, byte(len(rdata)>>8), byte(len(rdata)))
	buf = append(buf, rdata...)
	if got := parseNBSTATNames(buf); got != "MY-PC" {
		t.Fatalf("parseNBSTATNames = %q, want MY-PC", got)
	}
}

// TestParseMDNSPTR 用构造的响应验证 PTR 记录解析。
func TestParseMDNSPTR(t *testing.T) {
	buf := []byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0} // 无问题、1 条回答
	buf = append(buf, 1, '1', 1, '1', 3, '1', '6', '8', 3, '1', '9', '2', 7, 'i', 'n', '-', 'a', 'd', 'd', 'r', 4, 'a', 'r', 'p', 'a', 0)
	buf = append(buf, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0C)
	buf = append(buf, 4, 't', 'e', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0)
	if got := parseMDNSPTR(buf); got != "test.local" {
		t.Fatalf("parseMDNSPTR = %q, want test.local", got)
	}
}

// TestSSDPHelpers 验证 SSDP 响应头解析与 LOCATION IP 提取。
func TestSSDPHelpers(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.20:8080/desc.xml\r\nST: upnp:rootdevice\r\n\r\n"
	loc := ssdpLocation(resp)
	if loc != "http://192.168.1.20:8080/desc.xml" {
		t.Fatalf("ssdpLocation = %q", loc)
	}
	if got := ssdpHostIP(loc, "192.168.1.99"); got != "192.168.1.20" {
		t.Fatalf("ssdpHostIP = %q, want 192.168.1.20", got)
	}
	if got := ssdpHostIP("http://router.lan/desc.xml", "192.168.1.99"); got != "192.168.1.99" {
		t.Fatalf("域名 LOCATION 应回退源地址，得到 %q", got)
	}
}

// TestFetchUPnPFriendlyName 用本地 HTTP 服务验证描述文档解析。
func TestFetchUPnPFriendlyName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<root><device><friendlyName>客厅电视 &amp; 音箱</friendlyName></device></root>`))
	}))
	defer srv.Close()
	if got := fetchUPnPFriendlyName(srv.URL); got != "客厅电视 & 音箱" {
		t.Fatalf("fetchUPnPFriendlyName = %q", got)
	}
}

// TestWolStatusCache 验证开机状态缓存的命中、失效与空结果缓存。
func TestWolStatusCache(t *testing.T) {
	wolStatusCacheInvalidate()
	defer wolStatusCacheInvalidate()

	if _, ok := wolStatusCacheGet(); ok {
		t.Fatal("初始不应命中缓存")
	}
	wolStatusCacheSet(&wolStatusResult{Statuses: map[string]bool{"a": true}, OS: map[string]string{"a": "Linux/Unix"}})
	if m, ok := wolStatusCacheGet(); !ok || !m.Statuses["a"] || m.OS["a"] != "Linux/Unix" {
		t.Fatalf("缓存应命中，得到 %+v, %v", m, ok)
	}
	wolStatusCacheInvalidate()
	if _, ok := wolStatusCacheGet(); ok {
		t.Fatal("失效后不应命中缓存")
	}
	// 空结果也应缓存，避免无设备时反复触发 ARP 扫描
	wolStatusCacheSet(&wolStatusResult{Statuses: map[string]bool{}, OS: map[string]string{}})
	if m, ok := wolStatusCacheGet(); !ok || len(m.Statuses) != 0 {
		t.Fatalf("空结果应命中缓存，得到 %+v, %v", m, ok)
	}
}

func TestSendWOLMagicPacket(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	if err := sendWOLMagicPacket(mac, "127.0.0.1", conn.LocalAddr().(*net.UDPAddr).Port); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 102 {
		t.Fatalf("魔术包长度 = %d, want 102", n)
	}
	if !bytes.Equal(buf[:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Fatal("前 6 字节应为 0xFF")
	}
	for i := 1; i <= 16; i++ {
		if !bytes.Equal(buf[i*6:i*6+6], mac) {
			t.Fatalf("第 %d 组 MAC 不匹配", i)
		}
	}
}
