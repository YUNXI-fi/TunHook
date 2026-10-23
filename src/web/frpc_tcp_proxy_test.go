package web

import (
	"bufio"
	"bytes"
	"testing"
)

// TestParseProxyHeaderV2TCP4 验证 PROXY protocol v2（TCP over IPv4）头解析：
// 能取到访客 IP/端口，且不误消费头之后的业务数据。
func TestParseProxyHeaderV2TCP4(t *testing.T) {
	var b bytes.Buffer
	b.Write(proxyV2Signature)
	b.Write([]byte{0x21, 0x11, 0x00, 0x0C}) // PROXY 命令 + TCP over IPv4 + 12 字节地址
	addr := []byte{
		1, 2, 3, 4, // src IP 1.2.3.4
		0x1F, 0x90, // src port 8080
		5, 6, 7, 8, // dst IP
		0x00, 0x50, // dst port
	}
	b.Write(addr)
	b.WriteString("HELLO") // 业务数据

	br := bufio.NewReader(&b)
	ip, port, hasProxy, err := parseProxyHeader(br)
	if err != nil {
		t.Fatalf("parseProxyHeader: %v", err)
	}
	if !hasProxy {
		t.Fatal("应识别为 PROXY 头")
	}
	if ip != "1.2.3.4" || port != "8080" {
		t.Errorf("访客地址错误: got %s:%s", ip, port)
	}
	rest, _ := br.ReadString('O')
	if rest != "HELLO" {
		t.Errorf("头之后的业务数据被误消费: got %q", rest)
	}
}

// TestParseProxyHeaderV2TCP6 验证 PROXY protocol v2（TCP over IPv6）头解析。
func TestParseProxyHeaderV2TCP6(t *testing.T) {
	var b bytes.Buffer
	b.Write(proxyV2Signature)
	b.Write([]byte{0x21, 0x21, 0x00, 0x24}) // PROXY 命令 + TCP over IPv6 + 36 字节地址
	addr := make([]byte, 36)
	// src IP 2001:db8::1 写入前 16 字节
	copy(addr[0:16], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	addr[16] = 0x1F // src port 高字节（srcAddr 之后）
	addr[17] = 0x90 // src port 低字节 8080
	b.Write(addr)

	br := bufio.NewReader(&b)
	ip, port, hasProxy, err := parseProxyHeader(br)
	if err != nil {
		t.Fatalf("parseProxyHeader: %v", err)
	}
	if !hasProxy || ip != "2001:db8::1" || port != "8080" {
		t.Errorf("IPv6 访客地址错误: got %s:%s hasProxy=%v", ip, port, hasProxy)
	}
}

// TestParseProxyHeaderV1 验证 PROXY protocol v1 文本头解析。
func TestParseProxyHeaderV1(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("PROXY TCP4 203.0.113.9 192.168.1.2 54321 80\r\n")
	b.WriteString("STATUS")

	br := bufio.NewReader(&b)
	ip, port, hasProxy, err := parseProxyHeader(br)
	if err != nil {
		t.Fatalf("parseProxyHeader: %v", err)
	}
	if !hasProxy || ip != "203.0.113.9" || port != "54321" {
		t.Errorf("v1 访客地址错误: got %s:%s hasProxy=%v", ip, port, hasProxy)
	}
}

// TestParseProxyHeaderNone 验证无 PROXY 头（纯业务数据）时返回 hasProxy=false 且不消费数据。
func TestParseProxyHeaderNone(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("GET / HTTP/1.1\r\n")

	br := bufio.NewReader(&b)
	ip, port, hasProxy, err := parseProxyHeader(br)
	if err != nil {
		t.Fatalf("parseProxyHeader: %v", err)
	}
	if hasProxy || ip != "" || port != "" {
		t.Errorf("无头数据应返回 hasProxy=false: got %s:%s hasProxy=%v", ip, port, hasProxy)
	}
	line, _ := br.ReadString('\n')
	if line != "GET / HTTP/1.1\r\n" {
		t.Errorf("无头时业务数据应保持完整: got %q", line)
	}
}
