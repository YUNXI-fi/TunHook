package geoloc

import (
	"fmt"
	"strings"
	"testing"

	"tunhook/store"
)

func TestParseDataCIDR(t *testing.T) {
	data := `# comment
1.0.1.0/24
1.0.2.0/23
2.0.0.0-2.0.0.255 中国
invalid-line
`
	rs, skipped, err := ParseData(data, CatCountry, "中国", "中国国家IP段")
	if err != nil {
		t.Fatalf("ParseData: %v", err)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1（invalid-line）", skipped)
	}
	if len(rs) != 3 {
		t.Fatalf("len = %d, want 3", len(rs))
	}
	// 1.0.1.0/24
	if rs[0].Start != 16777472 || rs[0].End != 16777727 {
		t.Errorf("1.0.1.0/24 = %d-%d, want 16777472-16777727", rs[0].Start, rs[0].End)
	}
	// 1.0.2.0/23 → 1.0.2.0-1.0.3.255
	if rs[1].Start != 16777728 || rs[1].End != 16778239 {
		t.Errorf("1.0.2.0/23 = %d-%d, want 16777728-16778239", rs[1].Start, rs[1].End)
	}
	// 2.0.0.0-2.0.0.255
	if rs[2].Name != "中国" || rs[2].Class != "中国国家IP段" {
		t.Errorf("simple line name/class = %q/%q", rs[2].Name, rs[2].Class)
	}
	// 排序保证
	for i := 1; i < len(rs); i++ {
		if rs[i].Start < rs[i-1].Start {
			t.Fatal("未按 start 排序")
		}
	}
}

func TestParseDataDedup(t *testing.T) {
	data := "1.0.1.0/24\n1.0.1.0/24\n1.0.2.0/23\n"
	rs, skipped, err := ParseData(data, CatCountry, "中国", "中国国家IP段")
	if err != nil {
		t.Fatalf("ParseData: %v", err)
	}
	if len(rs) != 2 {
		t.Errorf("len = %d, want 2（重复段已去重）", len(rs))
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

func TestParseDataIP2Region(t *testing.T) {
	data := "1.0.1.0|1.0.3.255|中国|华南|广东|广州|电信\n"
	rs, _, err := ParseData(data, CatProvince, "广东", "广东省IP段")
	if err != nil || len(rs) != 1 {
		t.Fatalf("ip2region 解析失败: %v (len=%d)", err, len(rs))
	}
	if rs[0].Start != 16777472 || rs[0].End != 16778239 {
		t.Errorf("ip2region range = %d-%d", rs[0].Start, rs[0].End)
	}
}

func TestParseDataErrors(t *testing.T) {
	// 空数据
	if _, _, err := ParseData("", CatCountry, "中国", "中国国家IP段"); err == nil {
		t.Error("空数据应返回错误")
	}
	// 全为非法行
	_, _, err := ParseData("foo\nbar\n", CatCountry, "中国", "中国国家IP段")
	if err == nil {
		t.Error("全非法行应返回错误")
	}
	if !strings.Contains(err.Error(), "未解析到有效") {
		t.Errorf("错误信息不符合预期: %v", err)
	}
	// IPv6 不支持
	_, _, err = ParseData("::1/128\n", CatCountry, "中国", "中国国家IP段")
	if err == nil {
		t.Error("IPv6 应被拒绝")
	}
}

func TestCountIPAddresses(t *testing.T) {
	rs := []store.GeoRange{
		{Start: 16777472, End: 16777727}, // /24 → 256
		{Start: 16777728, End: 16778239}, // /23 → 512
		{Start: 1, End: 10},              // 10
	}
	want := int64(256 + 512 + 10)
	if got := CountIPAddresses(rs); got != want {
		t.Errorf("CountIPAddresses = %d, want %d", got, want)
	}
}

func TestParseCIDRLine(t *testing.T) {
	lo, hi, ok := parseCIDRLine("10.0.0.0/8")
	if !ok || lo != 167772160 || hi != 184549375 { // 10.0.0.0 - 10.255.255.255
		t.Errorf("10.0.0.0/8 = %d-%d ok=%v", lo, hi, ok)
	}
	lo, hi, ok = parseCIDRLine("192.168.1.1/32")
	if !ok || lo != hi {
		t.Errorf("192.168.1.1/32 lo=%d hi=%d ok=%v", lo, hi, ok)
	}
	if _, _, ok = parseCIDRLine("not-an-ip/24"); ok {
		t.Error("非法 CIDR 应返回 ok=false")
	}
}

func TestMaxParseRangesLimit(t *testing.T) {
	old := maxParseRanges
	maxParseRanges = 100
	defer func() { maxParseRanges = old }()

	var sb strings.Builder
	for i := 0; i < 110; i++ {
		sb.WriteString(fmt.Sprintf("%d.0.0.0/32\n", i)) // 唯一段
	}
	_, _, err := ParseData(sb.String(), CatCountry, "中国", "中国国家IP段")
	if err == nil {
		t.Error("超过上限应返回错误")
	}
}
