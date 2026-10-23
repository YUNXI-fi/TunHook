package geoloc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"tunhook/store"
)

// mockDataSource 返回按路径区分的 IP 段数据（CIDR 格式）。
func mockDataSource(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/country/us.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "8.0.0.0/8")
	})
	mux.HandleFunc("/country/jp.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "126.0.0.0/8")
	})
	mux.HandleFunc("/broken.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	return httptest.NewServer(mux)
}

func newTestDB(t *testing.T, srv *httptest.Server) (*DB, *store.Store, []int64) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	ids := make([]int64, 0, 3)
	for _, src := range []store.GeoSource{
		{Category: CatCountry, Class: "美国国家IP段", Name: "美国", URL: srv.URL + "/country/us.txt", Enabled: true},
		{Category: CatCountry, Class: "日本国家IP段", Name: "日本", URL: srv.URL + "/country/jp.txt", Enabled: true},
		{Category: CatCity, Class: "广州市IP段", Name: "广州", URL: srv.URL + "/broken.txt", Enabled: true},
	} {
		id, err := st.UpsertGeoSource(src)
		if err != nil {
			t.Fatalf("UpsertGeoSource: %v", err)
		}
		ids = append(ids, id)
	}
	d := New(t.TempDir(), st)
	d.Load()
	return d, st, ids
}

func TestUpdateIncremental(t *testing.T) {
	srv := mockDataSource(t)
	defer srv.Close()
	d, st, ids := newTestDB(t, srv)

	// 仅更新第 1 个源
	if err := d.UpdateSources(context.Background(), ids[:1]); err != nil {
		t.Fatalf("UpdateSources: %v", err)
	}
	rs, err := st.LoadGeoRanges(CatCountry, "")
	if err != nil || len(rs) != 1 {
		t.Fatalf("country ranges = %d, want 1 (err=%v)", len(rs), err)
	}
	if rs[0].Name != "美国" || rs[0].Start != 134217728 { // 8.0.0.0
		t.Errorf("range = %+v", rs[0])
	}
	if !d.Ready() {
		t.Error("Ready 应为 true")
	}
	if d.LastUpdate().IsZero() {
		t.Error("LastUpdate 应已设置")
	}
	// 源元数据更新（IP数量 = /8 = 16777216）
	src, _, _ := st.GeoSourceByID(ids[0])
	if src.IPCount != 16777216 || src.UpdatedAt == "" {
		t.Errorf("source meta = %+v", src)
	}
	if src.Status != "ok" {
		t.Errorf("source status = %q, want ok", src.Status)
	}
	// 未被更新的源保持未更新
	src2, _, _ := st.GeoSourceByID(ids[1])
	if src2.UpdatedAt != "" {
		t.Errorf("未选中的源不应被更新: %+v", src2)
	}
}

func TestUpdateFullAndIdempotent(t *testing.T) {
	srv := mockDataSource(t)
	defer srv.Close()
	d, st, ids := newTestDB(t, srv)
	// 停用故意配置的失败源，保证全量更新只处理可用源
	if err := st.SetGeoSourceEnabled(ids[2], false); err != nil {
		t.Fatal(err)
	}

	// 全量更新（空 ids = 全部启用源）
	if err := d.Update(context.Background()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	rs, _ := st.LoadGeoRanges(CatCountry, "")
	if len(rs) != 2 {
		t.Fatalf("country ranges = %d, want 2", len(rs))
	}
	// 再次全量更新：ReplaceGeoRangesBySource 先删后插，条数不变（幂等）
	if err := d.Update(context.Background()); err != nil {
		t.Fatalf("第二次 Update: %v", err)
	}
	rs2, _ := st.LoadGeoRanges(CatCountry, "")
	if len(rs2) != 2 {
		t.Fatalf("重复更新后 country ranges = %d, want 2", len(rs2))
	}
	// 其余分类不应有数据
	for _, cat := range []string{CatChina, CatProvince, CatCity, CatISP, CatCloud} {
		if rs, _ := st.LoadGeoRanges(cat, ""); len(rs) != 0 {
			t.Errorf("%s 分类不应有数据, len=%d", cat, len(rs))
		}
	}
}

func TestUpdateSingleSourceFailure(t *testing.T) {
	srv := mockDataSource(t)
	defer srv.Close()
	d, st, ids := newTestDB(t, srv)

	// 3 个源里第 3 个（broken.txt）返回 500 → 整体返回错误，但前两个成功
	err := d.UpdateSources(context.Background(), ids)
	if err == nil {
		t.Fatal("存在失败源时应返回错误")
	}
	rs, _ := st.LoadGeoRanges(CatCountry, "")
	if len(rs) != 2 {
		t.Errorf("country ranges = %d, want 2（失败源不影响其他源）", len(rs))
	}
	// 失败源状态记为 error
	bad, _, _ := st.GeoSourceByID(ids[2])
	if bad.Status != "error" {
		t.Errorf("失败源 status = %q, want error", bad.Status)
	}
}

func TestUpdateRejectsWhileUpdating(t *testing.T) {
	srv := mockDataSource(t)
	defer srv.Close()
	d, _, _ := newTestDB(t, srv)
	d.mu.Lock()
	d.updating = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.updating = false
		d.mu.Unlock()
	}()
	if err := d.UpdateSources(context.Background(), nil); err == nil {
		t.Error("更新中应拒绝并发更新")
	}
}

func TestUpdateNoSources(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	d := New(t.TempDir(), st)
	d.Load()
	if err := d.Update(context.Background()); err == nil {
		t.Error("无数据源时应返回错误")
	}
}
