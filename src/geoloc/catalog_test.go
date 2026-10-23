package geoloc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"tunhook/store"
)

func TestCNCityCategory(t *testing.T) {
	cases := map[string]string{
		"110000": CatProvince,
		"440000": CatProvince,
		"440100": CatCity,
		"441900": CatCity,
		"310000": CatProvince,
	}
	for code, want := range cases {
		if got := cncityCategory(code); got != want {
			t.Errorf("cncityCategory(%s) = %s, want %s", code, got, want)
		}
	}
}

func TestParseDocsTable(t *testing.T) {
	md := `| 中国 (CN) | https://example.com/data/country/CN.txt |
| 美国 (US) | https://example.com/data/country/US.txt |
| 暂无细分 | 无 |
|正文行|
`
	rows := parseDocsTable(md)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].name != "中国 (CN)" || rows[0].code != "CN" {
		t.Errorf("row0 = %+v", rows[0])
	}
	if rows[1].code != "US" {
		t.Errorf("row1 code = %s", rows[1].code)
	}
}

func TestCleanDocName(t *testing.T) {
	cases := map[string]string{
		"中国 (CN)":  "中国",
		"省直辖县(*)":  "省直辖县",
		"广东省":      "广东省",
		"  北京市  ":  "北京市",
		"延边朝鲜族自治州": "延边朝鲜族自治州",
	}
	for in, want := range cases {
		if got := cleanDocName(in); got != want {
			t.Errorf("cleanDocName(%q) = %q, want %q", in, got, want)
		}
	}
}

// mockGitHubServer 模拟 metowolf/iplist 的 docs 文档与 GitHub API 目录。
func mockGitHubServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/docs/country.md", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "| 美国 (US) | https://data.local/country/US.txt |")
		fmt.Fprintln(w, "| 日本 (JP) | https://data.local/country/JP.txt |")
	})
	mux.HandleFunc("/docs/cncity.md", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "|广东省|https://data.local/cncity/440000.txt|")
		fmt.Fprintln(w, "|广州市|https://data.local/cncity/440100.txt|")
		fmt.Fprintln(w, "|中国|https://data.local/cncity/100000.txt|")
	})
	mux.HandleFunc("/api/repos/metowolf/iplist/contents/data/isp", func(w http.ResponseWriter, r *http.Request) {
		entries := []githubDirEntry{
			{Name: "chinatelecom.txt", Type: "file"},
			{Name: "chinamobile.txt", Type: "file"},
			{Name: "aliyun.txt", Type: "file"},
			{Name: "tencent.txt", Type: "file"},
			{Name: "README.md", Type: "file"},
		}
		json.NewEncoder(w).Encode(entries)
	})
	return httptest.NewServer(mux)
}

func TestFetchSources(t *testing.T) {
	srv := mockGitHubServer(t)
	defer srv.Close()
	oldBase, oldAPI, oldChina := iplistRawBase, iplistAPIFmt, chinaSourceURL
	iplistRawBase, iplistAPIFmt, chinaSourceURL = srv.URL, srv.URL+"/api/repos/metowolf/iplist/contents/%s", srv.URL+"/data/special/china.txt"
	defer func() { iplistRawBase, iplistAPIFmt, chinaSourceURL = oldBase, oldAPI, oldChina }()

	c := NewCatalog(nil, srv.Client())
	sources, err := c.FetchSources(context.Background())
	if err != nil {
		t.Fatalf("FetchSources: %v", err)
	}

	// 国家 2 + 省/市 2（100000 跳过）+ 运营商 2 + 公有云 2 + 内地 1 = 9
	if len(sources) != 9 {
		t.Fatalf("sources = %d, want 9: %+v", len(sources), namesOf(sources))
	}
	byClass := map[string]store.GeoSource{}
	for _, s := range sources {
		byClass[s.Class] = s
	}
	if s, ok := byClass["美国国家IP段"]; !ok || s.Category != CatCountry {
		t.Errorf("美国国家IP段 = %+v", s)
	}
	if s, ok := byClass["广东省IP段"]; !ok || s.Category != CatProvince {
		t.Errorf("广东省IP段 = %+v", s)
	}
	if s, ok := byClass["广州市IP段"]; !ok || s.Category != CatCity {
		t.Errorf("广州市IP段 = %+v", s)
	}
	if s, ok := byClass["中国电信运营商IP段"]; !ok || s.Category != CatISP {
		t.Errorf("中国电信运营商IP段 = %+v", s)
	}
	if s, ok := byClass["阿里云公有云IP段"]; !ok || s.Category != CatCloud {
		t.Errorf("阿里云公有云IP段 = %+v", s)
	}
	if s, ok := byClass["中国内地IP段"]; !ok || s.Category != CatChina {
		t.Errorf("中国内地IP段 = %+v", s)
	}
	// 已移除「国内 / 公网IP段」订阅源
	if _, ok := byClass["公网IP段"]; ok {
		t.Errorf("不应再包含公网IP段订阅源: %+v", byClass["公网IP段"])
	}
}

func TestFetchSourcesFallbackCountry(t *testing.T) {
	// docs/country.md 返回错误 → 走 GitHub API + 内置名
	oldBase, oldAPI, oldChina := iplistRawBase, iplistAPIFmt, chinaSourceURL
	defer func() { iplistRawBase, iplistAPIFmt, chinaSourceURL = oldBase, oldAPI, oldChina }()

	mux := http.NewServeMux()
	mux.HandleFunc("/docs/country.md", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/docs/cncity.md", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "|北京市|https://data.local/cncity/110000.txt|")
	})
	mux.HandleFunc("/api/repos/metowolf/iplist/contents/data/country", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]githubDirEntry{{Name: "US.txt", Type: "file"}, {Name: "JP.txt", Type: "file"}})
	})
	mux.HandleFunc("/api/repos/metowolf/iplist/contents/data/isp", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]githubDirEntry{{Name: "chinatelecom.txt", Type: "file"}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	iplistRawBase, iplistAPIFmt, chinaSourceURL = srv.URL, srv.URL+"/api/repos/metowolf/iplist/contents/%s", srv.URL+"/data/special/china.txt"

	c := NewCatalog(nil, srv.Client())
	sources, err := c.FetchSources(context.Background())
	if err != nil {
		t.Fatalf("FetchSources: %v", err)
	}
	found := false
	for _, s := range sources {
		if s.Class == "美国国家IP段" {
			found = true
		}
	}
	if !found {
		t.Errorf("未找到美国国家IP段（应使用内置名称兜底）: %v", namesOf(sources))
	}
}

func TestCatalogRefreshPersists(t *testing.T) {
	srv := mockGitHubServer(t)
	defer srv.Close()
	oldBase, oldAPI, oldChina := iplistRawBase, iplistAPIFmt, chinaSourceURL
	iplistRawBase, iplistAPIFmt, chinaSourceURL = srv.URL, srv.URL+"/api/repos/metowolf/iplist/contents/%s", srv.URL+"/data/special/china.txt"
	defer func() { iplistRawBase, iplistAPIFmt, chinaSourceURL = oldBase, oldAPI, oldChina }()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	c := NewCatalog(st, srv.Client())
	n, err := c.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if n != 9 {
		t.Fatalf("Refresh 写入 %d 条, want 9", n)
	}
	list, err := st.ListGeoSources()
	if err != nil || len(list) != 9 {
		t.Fatalf("ListGeoSources len=%d err=%v", len(list), err)
	}
	// 幂等刷新不重复
	n2, err := c.Refresh(context.Background())
	if err != nil || n2 != 9 {
		t.Fatalf("二次 Refresh n=%d err=%v", n2, err)
	}
	// 新源默认启用
	for _, s := range list {
		if !s.Enabled {
			t.Errorf("新同步的数据源应默认启用: %+v", s)
		}
	}
	// 启用状态保留
	if err := st.SetGeoSourceEnabled(list[0].ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, _ := st.ListGeoSources()
	if after[0].Enabled != false {
		t.Error("刷新后应保留停用状态")
	}
}

func TestCheckLinks(t *testing.T) {
	var headOK, headNotAllowed, getOK int
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			headOK++
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/head-unsupported", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			headNotAllowed++
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		getOK++
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/bad", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id1, _ := st.UpsertGeoSource(store.GeoSource{Category: CatCountry, Class: "美国国家IP段", URL: srv.URL + "/ok"})
	id2, _ := st.UpsertGeoSource(store.GeoSource{Category: CatCity, Class: "广州市IP段", URL: srv.URL + "/head-unsupported"})
	id3, _ := st.UpsertGeoSource(store.GeoSource{Category: CatISP, Class: "中国电信运营商IP段", URL: srv.URL + "/bad"})

	c := NewCatalog(st, srv.Client())
	checked, failed, err := c.CheckLinks(context.Background())
	if err != nil {
		t.Fatalf("CheckLinks: %v", err)
	}
	if checked != 3 || failed != 1 {
		t.Errorf("checked=%d failed=%d, want 3/1", checked, failed)
	}
	for _, id := range []int64{id1, id2, id3} {
		src, ok, _ := st.GeoSourceByID(id)
		if !ok {
			t.Fatalf("source %d 不存在", id)
		}
		if src.Status == "" || src.LastCheck == "" {
			t.Errorf("source %d status/last_check 未更新: %+v", id, src)
		}
		if id == id3 && src.Status != "error" {
			t.Errorf("source %d 应为 error, got %q", id, src.Status)
		}
	}
	if headNotAllowed == 0 || getOK == 0 {
		t.Error("HEAD 不支持时应降级 GET 采样")
	}
}

func namesOf(srcs []store.GeoSource) string {
	out := make([]string, 0, len(srcs))
	for _, s := range srcs {
		out = append(out, s.Class)
	}
	return strings.Join(out, ",")
}
