package geoloc

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"tunhook/store"
)

// seedTestDB 构造各分类 IP 段数据并加载到 DB。
func seedTestDB(t *testing.T) *DB {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	ranges := []store.GeoRange{
		{Category: CatCountry, Class: "美国国家IP段", Name: "美国", Start: ip("8.0.0.0"), End: ip("8.255.255.255")},
		{Category: CatChina, Class: "中国内地IP段", Name: "中国", Start: ip("1.0.0.0"), End: ip("1.255.255.255")},
		{Category: CatProvince, Class: "广东省IP段", Name: "广东", Start: ip("1.1.0.0"), End: ip("1.1.255.255")},
		{Category: CatCity, Class: "广州市IP段", Name: "广州", Start: ip("1.1.1.0"), End: ip("1.1.1.255")},
		{Category: CatISP, Class: "中国电信运营商IP段", Name: "中国电信", Start: ip("1.1.0.0"), End: ip("1.1.255.255")},
		{Category: CatCloud, Class: "阿里云公有云IP段", Name: "阿里云", Start: ip("1.1.2.0"), End: ip("1.1.2.255")},
	}
	if _, err := st.InsertGeoRanges(ranges); err != nil {
		t.Fatalf("InsertGeoRanges: %v", err)
	}
	d := New(t.TempDir(), st)
	d.Load()
	if !d.Ready() {
		t.Fatal("数据未就绪")
	}
	return d
}

func ip(s string) uint32 { return ipToUint32(s) }

func TestLookupLayered(t *testing.T) {
	d := seedTestDB(t)

	cases := []struct{ ip, want string }{
		{"1.1.1.5", "中国 广东 广州 中国电信"}, // 内地兜底 + 省 + 市 + 运营商
		{"1.1.2.5", "中国 广东 中国电信"},    // 阿里云被运营商命中遮蔽
		{"1.2.3.4", "中国"},            // 仅内地
		{"8.8.8.8", "美国"},            // 仅国家
		{"203.0.113.5", ""},          // 未匹配
		{"invalid-ip", ""},           // 非法 IP
	}
	for _, c := range cases {
		if got := d.Lookup(c.ip); got != c.want {
			t.Errorf("Lookup(%s) = %q, want %q", c.ip, got, c.want)
		}
	}
}

func TestStats(t *testing.T) {
	d := seedTestDB(t)
	stats := d.Stats()
	if stats["total"].(int64) != 6 {
		t.Errorf("total = %v, want 6", stats["total"])
	}
	if stats["country"].(int) != 1 || stats["china"].(int) != 1 {
		t.Errorf("country/china = %v/%v", stats["country"], stats["china"])
	}
	if stats["ready"].(bool) != true {
		t.Error("ready 应为 true")
	}
	if !d.Updating() == false {
		t.Error("updating 应为 false")
	}
}

func TestSearchRange(t *testing.T) {
	entries := []rangeEntry{
		{name: "a", lo: 1, hi: 10},
		{name: "b", lo: 20, hi: 30},
		{name: "c", lo: 100, hi: 200},
	}
	if v := searchRange(entries, 5); v != "a" {
		t.Errorf("5 -> %q, want a", v)
	}
	if v := searchRange(entries, 15); v != "" {
		t.Errorf("15 -> %q, want empty", v)
	}
	if v := searchRange(entries, 150); v != "c" {
		t.Errorf("150 -> %q, want c", v)
	}
	if v := searchRange(nil, 5); v != "" {
		t.Errorf("nil -> %q, want empty", v)
	}
}

func TestLookupIPv6Rejected(t *testing.T) {
	d := seedTestDB(t)
	if got := d.Lookup("::1"); got != "" {
		t.Errorf("IPv6 应返回空: %q", got)
	}
}

func TestTotalIPCount(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.UpsertGeoSource(store.GeoSource{Category: CatCountry, Class: "美国国家IP段", URL: "u1", IPCount: 1_000_000}); err != nil {
		t.Fatal(err)
	}
	d := New(t.TempDir(), st)
	total, err := d.TotalIPCount()
	if err != nil {
		t.Fatalf("TotalIPCount: %v", err)
	}
	if total != 1_000_000 {
		t.Errorf("TotalIPCount = %d, want 1000000", total)
	}
}

func TestLoadFromCacheFallback(t *testing.T) {
	// 数据库为空但存在缓存文件 → Load 导入缓存并 ready
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	dir := t.TempDir()

	// 模拟一个数据源与其缓存文件
	id, err := st.UpsertGeoSource(store.GeoSource{Category: CatCountry, Class: "美国国家IP段", Name: "美国", URL: "http://x/us.txt"})
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(dir, "geoloc", "cache", fmt.Sprintf("%d.txt", id))
	if err := os.MkdirAll(filepath.Dir(cachePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("8.0.0.0/8\n"), 0644); err != nil {
		t.Fatal(err)
	}

	d := New(dir, st)
	d.Load()
	if !d.Ready() {
		t.Fatal("缓存导入后应 ready")
	}
	if got := d.Lookup("8.8.8.8"); got != "美国" {
		t.Errorf("Lookup = %q, want 美国", got)
	}
}
