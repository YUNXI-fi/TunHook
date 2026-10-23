package store

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsKV(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	if err := st.SetSetting("admin.pwd", "hash1"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if v, _ := st.GetSetting("admin.pwd"); v != "hash1" {
		t.Errorf("GetSetting = %q, want hash1", v)
	}
	// 覆盖更新
	if err := st.SetSetting("admin.pwd", "hash2"); err != nil {
		t.Fatalf("SetSetting update: %v", err)
	}
	if v, _ := st.GetSetting("admin.pwd"); v != "hash2" {
		t.Errorf("GetSetting after update = %q, want hash2", v)
	}
	if err := st.DeleteSetting("admin.pwd"); err != nil {
		t.Fatalf("DeleteSetting: %v", err)
	}
	if v, _ := st.GetSetting("admin.pwd"); v != "" {
		t.Errorf("GetSetting after delete = %q, want empty", v)
	}
}

func TestSettingsByPrefix(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	st.SetSetting("desc.tunnel:a", "t1")
	st.SetSetting("desc.forward:k", "f1")
	st.SetSetting("other", "x")

	kv, err := st.SettingsByPrefix("desc.")
	if err != nil {
		t.Fatalf("SettingsByPrefix: %v", err)
	}
	if len(kv) != 2 {
		t.Errorf("expected 2 desc entries, got %d", len(kv))
	}
	if kv["desc.tunnel:a"] != "t1" || kv["desc.forward:k"] != "f1" {
		t.Errorf("unexpected values: %v", kv)
	}
}

func TestForwardRules(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	r := RuleRecord{UUID: "u1", Key: "tcp://0.0.0.0:8080->1.2.3.4:80",
		Protocol: "tcp", LocalAddr: "0.0.0.0", LocalPort: 8080, RemoteAddr: "1.2.3.4", RemotePort: 80}
	if err := st.SaveForwardRule(r); err != nil {
		t.Fatalf("SaveForwardRule: %v", err)
	}
	// 同 key upsert
	r.UUID = "u2"
	if err := st.SaveForwardRule(r); err != nil {
		t.Fatalf("SaveForwardRule upsert: %v", err)
	}
	list, err := st.ListForwardRules()
	if err != nil {
		t.Fatalf("ListForwardRules: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(list))
	}
	if list[0].UUID != "u2" {
		t.Errorf("expected uuid u2 after upsert, got %s", list[0].UUID)
	}
	if err := st.DeleteForwardRule(r.Key); err != nil {
		t.Fatalf("DeleteForwardRule: %v", err)
	}
	list, _ = st.ListForwardRules()
	if len(list) != 0 {
		t.Errorf("expected 0 rules after delete, got %d", len(list))
	}
}

func TestMigrateFromFiles(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	os.MkdirAll(rulesDir, 0755)

	// 旧版文件
	os.WriteFile(filepath.Join(dir, "admin.pwd"), []byte("$2a$10$legacyhash"), 0600)
	os.WriteFile(filepath.Join(dir, "jwt.secret"), []byte("abcdef0123456789"), 0600)
	os.WriteFile(filepath.Join(rulesDir, "r1.json"), []byte(`{"uuid":"ru1","key":"tcp://0.0.0.0:1->2.2.2.2:2","protocol":"tcp","local_addr":"0.0.0.0","local_port":1,"remote_addr":"2.2.2.2","remote_port":2}`), 0644)

	st, err := Open(filepath.Join(dir, "tunhook.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	if err := st.MigrateFromFiles(dir, rulesDir); err != nil {
		t.Fatalf("MigrateFromFiles: %v", err)
	}
	// 幂等：再次执行不报错、不重复
	if err := st.MigrateFromFiles(dir, rulesDir); err != nil {
		t.Fatalf("MigrateFromFiles second run: %v", err)
	}

	if v, _ := st.GetSetting("admin.pwd"); v != "$2a$10$legacyhash" {
		t.Errorf("admin.pwd not migrated, got %q", v)
	}
	if v, _ := st.GetSetting("jwt.secret"); v != "abcdef0123456789" {
		t.Errorf("jwt.secret not migrated, got %q", v)
	}
	rules, err := st.ListForwardRules()
	if err != nil || len(rules) != 1 {
		t.Fatalf("expected 1 migrated rule, got %d (err=%v)", len(rules), err)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return st
}

func TestGeoRangesCRUD(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	rs := []GeoRange{
		{Category: "country", Class: "美国国家IP段", Name: "美国", Start: 1, End: 10},
		{Category: "country", Class: "美国国家IP段", Name: "美国", Start: 20, End: 30},
		{Category: "isp", Class: "中国电信运营商IP段", Name: "中国电信", Start: 5, End: 15},
	}
	n, err := st.InsertGeoRanges(rs)
	if err != nil || n != 3 {
		t.Fatalf("InsertGeoRanges n=%d err=%v", n, err)
	}
	// 去重：相同唯一标识符（category+class+start+end）不重复插入
	n, _ = st.InsertGeoRanges(rs[:1])
	if n != 0 {
		t.Errorf("重复插入应去重, n=%d", n)
	}
	// 按分类加载
	got, err := st.LoadGeoRanges("country", "")
	if err != nil || len(got) != 2 {
		t.Fatalf("LoadGeoRanges(country) len=%d err=%v", len(got), err)
	}
	// 按 class 过滤
	got, _ = st.LoadGeoRanges("country", "美国国家IP段")
	if len(got) != 2 {
		t.Errorf("按 class 过滤 len=%d, want 2", len(got))
	}
	got, _ = st.LoadGeoRanges("country", "不存在")
	if len(got) != 0 {
		t.Errorf("按不存在 class 过滤 len=%d, want 0", len(got))
	}
	// 按源替换（先删后插，事务）
	srcID, _ := st.UpsertGeoSource(GeoSource{Category: "country", Class: "美国国家IP段", URL: "u1"})
	if err := st.ReplaceGeoRangesBySource(srcID, rs[:2]); err != nil {
		t.Fatalf("ReplaceGeoRangesBySource: %v", err)
	}
	bySource, _ := st.LoadGeoRanges("country", "美国国家IP段")
	if len(bySource) != 2 || bySource[0].SourceID != srcID {
		t.Errorf("bySource len=%d srcID=%d", len(bySource), bySource[0].SourceID)
	}
}

func TestGeoSourceCRUD(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	id, err := st.UpsertGeoSource(GeoSource{Category: "city", Class: "广州市IP段", URL: "http://u/gz.txt", Enabled: true})
	if err != nil {
		t.Fatalf("UpsertGeoSource: %v", err)
	}
	// upsert 幂等（按 category+class 冲突更新）
	id2, err := st.UpsertGeoSource(GeoSource{Category: "city", Class: "广州市IP段", URL: "http://u/gz2.txt", Enabled: true})
	if err != nil || id2 != id {
		t.Fatalf("upsert 应返回同一 id: %d vs %d (err=%v)", id2, id, err)
	}
	src, ok, err := st.GeoSourceByKey("city", "广州市IP段")
	if err != nil || !ok || src.URL != "http://u/gz2.txt" {
		t.Fatalf("GeoSourceByKey = %+v ok=%v err=%v", src, ok, err)
	}
	byID, ok, _ := st.GeoSourceByID(id)
	if !ok || byID.Class != "广州市IP段" {
		t.Fatalf("GeoSourceByID = %+v ok=%v", byID, ok)
	}
	// 元数据与状态
	if err := st.SetGeoSourceMeta(id, 16777216, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetGeoSourceStatus(id, "ok", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetGeoSourceEnabled(id, false); err != nil {
		t.Fatal(err)
	}
	src, _, _ = st.GeoSourceByID(id)
	if src.IPCount != 16777216 || src.Status != "ok" || src.Enabled {
		t.Errorf("meta 更新失败: %+v", src)
	}
	// 列表
	list, err := st.ListGeoSources()
	if err != nil || len(list) != 1 {
		t.Fatalf("ListGeoSources len=%d err=%v", len(list), err)
	}
}

// 构造旧版 geo_ip_ranges 表（无 id/class/source_id 列）并插入历史数据。
func seedLegacyGeoTable(t *testing.T, st *Store) {
	t.Helper()
	if _, err := st.db.Exec(`DROP TABLE IF EXISTS geo_ip_ranges;
		CREATE TABLE geo_ip_ranges (
			category TEXT NOT NULL,
			name     TEXT NOT NULL,
			start_ip INTEGER NOT NULL,
			end_ip   INTEGER NOT NULL
		)`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	for _, r := range []struct {
		cat, name string
		s, e      int64
	}{
		{"country", "美国", 1, 10},
		{"country", "中国", 100, 200},
		{"cncity", "广东", 300, 400},
		{"cncity", "广州", 500, 600},
		{"isp", "电信", 700, 800},
	} {
		if _, err := st.db.Exec(`INSERT INTO geo_ip_ranges(category,name,start_ip,end_ip) VALUES(?,?,?,?)`,
			r.cat, r.name, r.s, r.e); err != nil {
			t.Fatalf("insert legacy: %v", err)
		}
	}
}

func TestMigrateGeoClasses(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	seedLegacyGeoTable(t, st)

	if err := st.MigrateGeoClasses(); err != nil {
		t.Fatalf("MigrateGeoClasses: %v", err)
	}

	// 旧分类重映射 + 分类标签
	cases := []struct{ cat, cls, name string }{
		{"country", "美国国家IP段", "美国"},
		{"country", "中国国家IP段", "中国"},
		{"province", "广东省IP段", "广东"},
		{"city", "广州市IP段", "广州"},
		{"isp", "电信运营商IP段", "电信"},
	}
	for _, c := range cases {
		rs, err := st.LoadGeoRanges(c.cat, c.cls)
		if err != nil || len(rs) != 1 || rs[0].Name != c.name {
			t.Errorf("迁移结果 %s/%s = %+v err=%v", c.cat, c.cls, rs, err)
		}
	}
	// 幂等：再次执行不改变数据（各分类仍各 1 条）
	if err := st.MigrateGeoClasses(); err != nil {
		t.Fatalf("MigrateGeoClasses 二次执行: %v", err)
	}
	total := 0
	for _, c := range cases {
		rs, _ := st.LoadGeoRanges(c.cat, c.cls)
		total += len(rs)
	}
	if total != 5 {
		t.Errorf("迁移后总条数 = %d, want 5", total)
	}
}

func TestMigrateGeoClassesFreshSchema(t *testing.T) {
	// 新库已有 class 列：迁移应无操作不报错
	st := openTestStore(t)
	defer st.Close()
	if _, err := st.InsertGeoRanges([]GeoRange{
		{Category: "city", Class: "广州市IP段", Name: "广州", Start: 1, End: 2},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.MigrateGeoClasses(); err != nil {
		t.Fatalf("新库迁移应无操作: %v", err)
	}
	rs, _ := st.LoadGeoRanges("city", "广州市IP段")
	if len(rs) != 1 || rs[0].Class != "广州市IP段" {
		t.Errorf("新库数据不应被改动: %+v", rs)
	}
}

func TestGeoLegacyLabel(t *testing.T) {
	cases := []struct {
		name, cat string
		province  bool
		want      string
	}{
		{"美国", "country", false, "美国国家IP段"},
		{"电信", "isp", false, "电信运营商IP段"},
		{"广东", "cncity", true, "广东省IP段"},
		{"北京", "cncity", true, "北京市IP段"},
		{"广州", "cncity", false, "广州市IP段"},
		{"未知", "other", false, "未知IP段"},
	}
	for _, c := range cases {
		if got := geoLegacyLabel(c.name, c.cat, c.province); got != c.want {
			t.Errorf("geoLegacyLabel(%q,%q,%v) = %q, want %q", c.name, c.cat, c.province, got, c.want)
		}
	}
}

func TestReplaceGeoRangesBySourceEmpty(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	if err := st.ReplaceGeoRangesBySource(1, nil); err != nil {
		t.Fatalf("空 ranges 不应报错: %v", err)
	}
	if err := st.ReplaceGeoRangesBySource(1, []GeoRange{}); err != nil {
		t.Fatalf("空切片不应报错: %v", err)
	}
}

func TestInsertGeoRangesEmpty(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	n, err := st.InsertGeoRanges(nil)
	if err != nil || n != 0 {
		t.Fatalf("空 ranges n=%d err=%v", n, err)
	}
}

// TestIPFilterEntriesManualOnly 验证 ip_filter_entries 仅支持手动录入（增/删）。
func TestIPFilterEntriesManualOnly(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	if err := st.AddCustomIP("192.168.1.0/24"); err != nil {
		t.Fatalf("AddCustomIP: %v", err)
	}
	if err := st.AddCustomIP("10.0.0.1"); err != nil {
		t.Fatalf("AddCustomIP: %v", err)
	}
	list, err := st.ListCustomIPs()
	if err != nil || len(list) != 2 {
		t.Fatalf("ListCustomIPs len=%d err=%v", len(list), err)
	}
	// 重复添加去重
	if err := st.AddCustomIP("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	list, _ = st.ListCustomIPs()
	if len(list) != 2 {
		t.Errorf("重复添加应去重, len=%d", len(list))
	}
	if err := st.DeleteCustomIP("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	list, _ = st.ListCustomIPs()
	if len(list) != 1 {
		t.Errorf("删除后 len=%d, want 1", len(list))
	}
}

func TestIsIPInGeoRanges(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	if _, err := st.InsertGeoRanges([]GeoRange{
		{Category: "country", Class: "美国国家IP段", Name: "美国", Start: testIP4("8.8.8.0"), End: testIP4("8.8.8.255")},
	}); err != nil {
		t.Fatal(err)
	}
	ok, err := st.IsIPInGeoRanges(testIP4("8.8.8.8"))
	if err != nil || !ok {
		t.Fatalf("8.8.8.8 应命中, ok=%v err=%v", ok, err)
	}
	ok, err = st.IsIPInGeoRanges(testIP4("9.9.9.9"))
	if err != nil || ok {
		t.Fatalf("9.9.9.9 不应命中, ok=%v err=%v", ok, err)
	}
}

// TestMigrateIPFilterV2 验证一次性清理：清空 ip_filter_entries、删除 domestic 数据源及其 IP 段、删除旧订阅配置键。
func TestMigrateIPFilterV2(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	if err := st.AddCustomIP("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	id, err := st.UpsertGeoSource(GeoSource{Category: "domestic", Class: "公网IP段", URL: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertGeoRanges([]GeoRange{{Category: "domestic", Class: "公网IP段", Name: "国内", Start: 1, End: 2}}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("cfg.ip_filter.ip_range_url", `"https://example.com"`); err != nil {
		t.Fatal(err)
	}
	// 重置迁移标记后执行
	if err := st.DeleteSetting("migrated:ipfilter-v2"); err != nil {
		t.Fatal(err)
	}
	if err := st.migrateIPFilterV2(); err != nil {
		t.Fatalf("migrateIPFilterV2: %v", err)
	}
	list, _ := st.ListCustomIPs()
	if len(list) != 0 {
		t.Errorf("ip_filter_entries 未清空: %v", list)
	}
	if _, ok, _ := st.GeoSourceByID(id); ok {
		t.Error("domestic 数据源未删除")
	}
	rs, _ := st.LoadGeoRanges("domestic", "")
	if len(rs) != 0 {
		t.Errorf("domestic IP 段未删除: %d", len(rs))
	}
	if v, _ := st.GetSetting("cfg.ip_filter.ip_range_url"); v != "" {
		t.Error("旧订阅配置键未删除")
	}
	// 幂等：再次执行不报错
	if err := st.migrateIPFilterV2(); err != nil {
		t.Fatalf("二次执行 migrateIPFilterV2: %v", err)
	}
}

// testIP4 把点分十进制 IPv4 转为 uint32。
func testIP4(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
