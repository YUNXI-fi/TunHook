package geoloc

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"tunhook/store"
)

// 数据源设置键。
const (
	KeyLastUpdate = "geoloc.last_update" // 最近一次成功更新的时间（RFC3339）
)

// maxParseRanges 单源解析的 IP 段条数上限（防御异常数据，避免内存暴涨；包级变量以便测试调整）。
var maxParseRanges = 5_000_000

// ParseData 解析归属地文本数据为 IP 段列表并做校验与去重。
// 兼容三种格式（按行识别）：
//   - CIDR：1.0.1.0/24（metowolf/iplist 主格式）
//   - ip2region 管道：start|end|国家|区域|省份|城市|运营商
//   - 简单格式：start-end 名称 或 start end 名称
//
// 校验规则：IPv4 合法、start<=end、名称非空；重复段（category+class+start+end）去重。
// 返回解析后的段列表与跳过的非法行数；全部行非法时返回错误。
func ParseData(data string, category, name, class string) ([]store.GeoRange, int64, error) {
	seen := make(map[string]bool)
	out := make([]store.GeoRange, 0, 4096)
	var skipped int64
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lo, hi, ok := parseLine(line)
		if !ok {
			skipped++
			continue
		}
		key := category + "|" + class + "|" + strconv.FormatUint(uint64(lo), 10) + "-" + strconv.FormatUint(uint64(hi), 10)
		if seen[key] {
			skipped++
			continue
		}
		seen[key] = true
		out = append(out, store.GeoRange{
			Category: category,
			Class:    class,
			Name:     name,
			Start:    lo,
			End:      hi,
		})
		if len(out) >= maxParseRanges {
			return nil, skipped, fmt.Errorf("IP 段数量超过上限 %d", maxParseRanges)
		}
	}
	if len(out) == 0 {
		if skipped > 0 {
			return nil, skipped, fmt.Errorf("未解析到有效 IP 段（跳过 %d 行）", skipped)
		}
		return nil, skipped, fmt.Errorf("数据为空")
	}
	sortRanges(out)
	return out, skipped, nil
}

// parseLine 解析单行为起始/结束 IP；非法返回 ok=false。
func parseLine(line string) (lo, hi uint32, ok bool) {
	// 1) CIDR 格式：1.0.1.0/24
	if strings.Contains(line, "/") {
		return parseCIDRLine(line)
	}
	// 2) ip2region 管道格式：start|end|...
	if strings.Contains(line, "|") {
		fields := strings.Split(line, "|")
		if len(fields) >= 4 {
			loU, err1 := parseIPOrInt(fields[0])
			hiU, err2 := parseIPOrInt(fields[1])
			if err1 == nil && err2 == nil && loU <= hiU {
				return loU, hiU, true
			}
		}
		return 0, 0, false
	}
	// 3) 简单格式：start-end name / start end name
	idx := strings.IndexAny(line, " \t,")
	if idx < 0 {
		return 0, 0, false
	}
	rest := strings.TrimSpace(line[:idx])
	sep := strings.Index(rest, "-")
	if sep < 0 {
		return 0, 0, false
	}
	loU, err1 := parseIPOrInt(rest[:sep])
	hiU, err2 := parseIPOrInt(rest[sep+1:])
	if err1 != nil || err2 != nil || loU > hiU {
		return 0, 0, false
	}
	return loU, hiU, true
}

// parseCIDRLine 解析 CIDR 行，计算起始/结束 IP（结束 = 起始 + 2^(32-mask) - 1）。
func parseCIDRLine(line string) (lo, hi uint32, ok bool) {
	ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(line))
	if err != nil {
		return 0, 0, false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, 0, false // 仅支持 IPv4
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return 0, 0, false
	}
	lo = uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	hosts := uint64(1) << uint(32-ones)
	hi = lo + uint32(hosts-1)
	return lo, hi, true
}

// parseIPOrInt 把 IP（点分十进制）或十进制整数解析为 uint32。
func parseIPOrInt(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]), nil
		}
		return 0, fmt.Errorf("仅支持 IPv4")
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err
}

// CountIPAddresses 计算一组 IP 段的地址总数（网段覆盖的 IP 数量，用于展示）。
func CountIPAddresses(rs []store.GeoRange) int64 {
	var total int64
	for _, r := range rs {
		total += int64(r.End) - int64(r.Start) + 1
	}
	return total
}
