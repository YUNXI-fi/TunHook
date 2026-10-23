// NAT 链路扫描：用 traceroute 逐跳识别本机到公网之间的 NAT 层级
// （借鉴 LinkStar 思路，独立实现）。仅支持 Linux（TunHook 运行环境为 fnOS）。
package stunprobe

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// NatHop NAT 链路中的一跳。
type NatHop struct {
	Level int    `json:"level"` // NAT 层级（从 1 开始）
	IP    string `json:"ip"`    // 该跳路由器 IP（不响应跳为 "*"）
	Type  string `json:"type"`  // private / cgn / public / hidden
}

var (
	ipRe = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	// traceroute 行首跳号（过滤噪声）
	hopRe = regexp.MustCompile(`^\s*(\d+)\s`)
)

// ScanNATChain 扫描到 target 的 NAT 链路，逐跳分类，遇公网或 CGN 即停止。
// 运营商设备普遍对 traceroute 静默（星号跳），此类跳记为 hidden 展示为「不响应」，
// 避免链路看起来只有一层；首个公网跳作为「公网出口」记录后终止。
func ScanNATChain(target string, timeout time.Duration) ([]NatHop, error) {
	if _, err := exec.LookPath("traceroute"); err != nil {
		return nil, fmt.Errorf("系统缺少 traceroute 命令，无法扫描 NAT 链路")
	}
	// -n 不解析域名 -m 15 最大跳数 -w 1 每跳等待 1s -q 2 每跳两个探测包提高响应率
	cmd := exec.Command("traceroute", "-n", "-m", "15", "-w", "1", "-q", "2", target)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("创建输出管道失败: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 traceroute 失败: %w", err)
	}
	go func() {
		time.Sleep(timeout)
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	var chain []NatHop
	sc := bufio.NewScanner(stdout)
	chain = parseNATChain(target, sc)
	_ = cmd.Wait()
	return chain, nil
}

// parseNATChain 解析 traceroute 输出为 NAT 跳列表（从 ScanNATChain 抽出以便单元测试）。
// 规则：星号跳记为 hidden；目标行跳过；首个 public / cgn 跳记录后终止。
func parseNATChain(target string, sc *bufio.Scanner) []NatHop {
	var chain []NatHop
	lastHop := -1
	for sc.Scan() {
		line := sc.Text()
		m := hopRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		hop, _ := strconv.Atoi(m[1])
		if hop == lastHop {
			continue // 同一跳重复行
		}
		lastHop = hop
		ips := ipRe.FindStringSubmatch(line)
		if ips == nil {
			// 星号跳：该跳路由器不响应 TTL exceeded（运营商常见），记录占位继续
			chain = append(chain, NatHop{Level: len(chain) + 1, IP: "*", Type: "hidden"})
			continue
		}
		ip := ips[1]
		if ip == target {
			continue
		}
		t := classifyIPType(ip)
		chain = append(chain, NatHop{Level: len(chain) + 1, IP: ip, Type: t})
		if t == "public" || t == "cgn" {
			break
		}
	}
	return chain
}

// classifyIPType IP 分类：private（RFC1918）/ cgn（RFC6598）/ public。
func classifyIPType(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "private"
	}
	v4 := ip.To4()
	if v4 == nil {
		return "public" // IPv6 跳点不做细分
	}
	if v4[0] == 100 && v4[1]&0xc0 == 0x40 {
		return "cgn"
	}
	if v4.IsPrivate() || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
		return "private"
	}
	return "public"
}

// NatChainDesc 把链路转成人类可读描述。
func NatChainDesc(chain []NatHop) string {
	if len(chain) == 0 {
		return "未检测到内网 NAT 层级（可能直连公网）"
	}
	parts := make([]string, 0, len(chain))
	for _, h := range chain {
		name := "内网"
		switch h.Type {
		case "cgn":
			name = "运营商 CGNAT"
		case "public":
			name = "公网出口"
		case "hidden":
			name = "不响应"
		}
		parts = append(parts, fmt.Sprintf("第%d层 %s（%s）", h.Level, name, h.IP))
	}
	return strings.Join(parts, " → ")
}
