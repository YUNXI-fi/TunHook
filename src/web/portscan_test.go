package web

import "testing"

// TestLanRangeScore 验证局域网网段自动识别的优先级：
// 真实上联网卡必须优先于 docker 网桥等虚拟网卡，防止 172.22.0.0/16 之类的大网段抢占真实局域网。
func TestLanRangeScore(t *testing.T) {
	cases := []struct {
		isDefRoute bool // 是否承载默认路由
		virtual    bool // 是否虚拟网卡
		priv       bool // 是否 RFC1918 私网地址
		want       int
	}{
		{true, false, true, 0},  // 真实上联私网网卡（最常见场景）
		{true, false, false, 0}, // 真实上联公网网卡
		{true, true, true, 1},   // 默认路由挂在虚拟网卡（罕见）
		{false, false, true, 2}, // 无默认路由的私网真实网卡
		{false, true, true, 3},  // docker 网桥等私网虚拟网卡（如 172.22.0.0/16）
		{false, false, false, 4},
		{false, true, false, 5},
	}
	for _, c := range cases {
		if got := lanRangeScore(c.isDefRoute, c.virtual, c.priv); got != c.want {
			t.Errorf("lanRangeScore(%v,%v,%v)=%d, want %d", c.isDefRoute, c.virtual, c.priv, got, c.want)
		}
	}
}

// TestIsVirtualIface 验证虚拟网卡识别：docker 网桥/veth/隧道应判定为虚拟，
// 真实网卡（含常见物理网桥名 br0）不应误判。
func TestIsVirtualIface(t *testing.T) {
	virtual := []string{"docker0", "docker_gwbridge", "br-3f2a1b0c", "vethabc123", "tun0", "tailscale0", "wg0", "virbr0", "vnet0", "lxcbr0"}
	for _, n := range virtual {
		if !isVirtualIface(n) {
			t.Errorf("isVirtualIface(%q)=false, want true", n)
		}
	}
	real := []string{"eth0", "wlo1", "enp3s0", "br0", "ovs0", "bond0", "ens33"}
	for _, n := range real {
		if isVirtualIface(n) {
			t.Errorf("isVirtualIface(%q)=true, want false", n)
		}
	}
}

// TestParsePingTTL 验证从 Linux/Windows 两种 ping 输出中提取 TTL，多包取最小值。
func TestParsePingTTL(t *testing.T) {
	cases := []struct {
		out  string
		want int
	}{
		{"64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.4 ms\n64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.5 ms", 64},
		{"Reply from 10.0.0.5: bytes=32 time<1ms TTL=128", 128},
		{"64 bytes from 1.1.1.1: icmp_seq=1 ttl=56 time=3 ms\n64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=3 ms", 56},
		{"Request timeout for icmp_seq 0", 0},
	}
	for _, c := range cases {
		if got := parsePingTTL(c.out); got != c.want {
			t.Errorf("parsePingTTL(%q)=%d, want %d", c.out, got, c.want)
		}
	}
}

// TestGuessOSByTTL 验证按初始 TTL 档位推断目标系统。
func TestGuessOSByTTL(t *testing.T) {
	cases := map[int]string{
		64:  "Linux/Unix",
		63:  "Linux/Unix",
		128: "Windows",
		65:  "Windows",
		255: "网络设备/Unix",
		129: "网络设备/Unix",
	}
	for ttl, want := range cases {
		if got := guessOSByTTL(ttl); got != want {
			t.Errorf("guessOSByTTL(%d)=%q, want %q", ttl, got, want)
		}
	}
}
