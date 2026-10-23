// NAT 链路解析的单元测试：覆盖 traceroute 输出解析（parseNATChain）、
// IP 分类（classifyIPType）与描述生成（NatChainDesc）。
// 修复背景：旧逻辑丢弃公网出口跳与星号（不响应）跳，导致链路只显示一层。
package stunprobe

import (
	"bufio"
	"reflect"
	"strings"
	"testing"
)

// parse 测试辅助：喂入模拟的 traceroute 输出（目标固定为测试地址）。
func parse(t *testing.T, output string) []NatHop {
	t.Helper()
	return parseNATChain("114.114.114.114", bufio.NewScanner(strings.NewReader(output)))
}

func TestParseNATChain_PublicHopRecorded(t *testing.T) {
	// 家宽典型两层：hop2 是运营商公网网关，必须记录「公网出口」后再终止（修复点），
	// 且 hop3（目标地址行）应被跳过。
	chain := parse(t, `traceroute to 114.114.114.114 (114.114.114.114), 15 hops max, 60 byte packets
 1  192.168.1.1  0.512 ms  0.480 ms
 2  116.1.202.129  3.120 ms  3.088 ms
 3  114.114.114.114  5.001 ms
`)
	want := []NatHop{
		{Level: 1, IP: "192.168.1.1", Type: "private"},
		{Level: 2, IP: "116.1.202.129", Type: "public"},
	}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("got %+v, want %+v", chain, want)
	}
}

func TestParseNATChain_HiddenHopsKept(t *testing.T) {
	// 运营商设备对 traceroute 静默：星号跳必须记录为 hidden（修复点），不得丢弃。
	chain := parse(t, ` 1  192.168.1.1  0.500 ms
 2  * * *
 3  * * *
 4  116.1.202.129  3.100 ms
`)
	want := []NatHop{
		{Level: 1, IP: "192.168.1.1", Type: "private"},
		{Level: 2, IP: "*", Type: "hidden"},
		{Level: 3, IP: "*", Type: "hidden"},
		{Level: 4, IP: "116.1.202.129", Type: "public"},
	}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("got %+v, want %+v", chain, want)
	}
}

func TestParseNATChain_CGNStopsScan(t *testing.T) {
	// CGNAT 层记录后终止，其后不再解析。
	chain := parse(t, ` 1  192.168.1.1  0.500 ms
 2  100.64.0.1  4.000 ms
 3  59.100.1.1  5.000 ms
`)
	want := []NatHop{
		{Level: 1, IP: "192.168.1.1", Type: "private"},
		{Level: 2, IP: "100.64.0.1", Type: "cgn"},
	}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("got %+v, want %+v", chain, want)
	}
}

func TestParseNATChain_SkipsNoiseAndDuplicateHops(t *testing.T) {
	// 头部信息行 / 空行应忽略；同一跳号重复行只记一次。
	chain := parse(t, `traceroute to 114.114.114.114 (114.114.114.114), 15 hops max

 1  192.168.1.1  0.500 ms
 1  192.168.1.1  0.480 ms
 2  8.8.8.8  3.000 ms
`)
	want := []NatHop{
		{Level: 1, IP: "192.168.1.1", Type: "private"},
		{Level: 2, IP: "8.8.8.8", Type: "public"},
	}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("got %+v, want %+v", chain, want)
	}
}

func TestParseNATChain_AllHiddenUntilEnd(t *testing.T) {
	// 全程无响应：全部记为 hidden，层级连续编号。
	chain := parse(t, ` 1  * * *
 2  * * *
 3  * * *
`)
	want := []NatHop{
		{Level: 1, IP: "*", Type: "hidden"},
		{Level: 2, IP: "*", Type: "hidden"},
		{Level: 3, IP: "*", Type: "hidden"},
	}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("got %+v, want %+v", chain, want)
	}
}

func TestParseNATChain_EmptyOutput(t *testing.T) {
	chain := parse(t, "")
	if len(chain) != 0 {
		t.Fatalf("want empty chain, got %+v", chain)
	}
}

func TestClassifyIPType(t *testing.T) {
	cases := []struct {
		ip   string
		want string
	}{
		{"192.168.1.1", "private"},     // RFC1918
		{"10.0.0.1", "private"},        // RFC1918
		{"172.16.0.1", "private"},      // RFC1918
		{"100.64.0.1", "cgn"},          // RFC6598 起始
		{"100.127.255.255", "cgn"},     // RFC6598 末尾
		{"100.128.0.1", "public"},      // 100.64/10 之外
		{"8.8.8.8", "public"},          // 公网
		{"116.1.202.129", "public"},    // 公网
		{"127.0.0.1", "private"},       // 回环
		{"169.254.10.1", "private"},    // 链路本地
		{"::1", "public"},              // IPv6 跳点不做细分，按公网处理
		{"not-an-ip", "private"},       // 非法输入兜底
	}
	for _, c := range cases {
		if got := classifyIPType(c.ip); got != c.want {
			t.Errorf("classifyIPType(%q) = %q, want %q", c.ip, got, c.want)
		}
	}
}

func TestNatChainDesc(t *testing.T) {
	cases := []struct {
		name  string
		chain []NatHop
		want  string
	}{
		{"空链路", nil, "未检测到内网 NAT 层级（可能直连公网）"},
		{
			"完整家宽链路",
			[]NatHop{
				{Level: 1, IP: "192.168.1.1", Type: "private"},
				{Level: 2, IP: "*", Type: "hidden"},
				{Level: 3, IP: "100.64.0.1", Type: "cgn"},
			},
			"第1层 内网（192.168.1.1） → 第2层 不响应（*） → 第3层 运营商 CGNAT（100.64.0.1）",
		},
		{
			"含公网出口",
			[]NatHop{
				{Level: 1, IP: "192.168.1.1", Type: "private"},
				{Level: 2, IP: "116.1.202.129", Type: "public"},
			},
			"第1层 内网（192.168.1.1） → 第2层 公网出口（116.1.202.129）",
		},
	}
	for _, c := range cases {
		if got := NatChainDesc(c.chain); got != c.want {
			t.Errorf("%s: NatChainDesc() = %q, want %q", c.name, got, c.want)
		}
	}
}
