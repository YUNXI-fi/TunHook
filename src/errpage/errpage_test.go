package errpage

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestInitWritesDefaultFiles 验证初始化会把九份模板文件落地，且内容为内置默认模板。
func TestInitWritesDefaultFiles(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init 失败：%v", err)
	}
	for _, code := range Codes {
		p := filepath.Join(dir, strconv.Itoa(code)+".html")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s 模板文件应存在：%v", p, err)
		}
		if !strings.Contains(string(b), defaults[code].title) {
			t.Fatalf("%d 默认模板应含标题 %q", code, defaults[code].title)
		}
	}
	if got := File(404); got != filepath.Join(dir, "404.html") {
		t.Fatalf("File(404) = %q，期望 %q", got, filepath.Join(dir, "404.html"))
	}
}

// TestContentPrefersFileAndPicksUpExternalEdit 验证「文件即真相」：
// 保存后立即生效；用户直接用编辑器改文件（mtime 变化）后无需重启即生效。
func TestContentPrefersFileAndPicksUpExternalEdit(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init 失败：%v", err)
	}

	自定义 := "<html>自定义错误页</html>"
	if err := Save(404, 自定义); err != nil {
		t.Fatalf("Save 失败：%v", err)
	}
	if got, _ := Content(404); got != 自定义 {
		t.Fatalf("保存后 Content = %q，期望 %q", got, 自定义)
	}

	手工 := "<html>用户在编辑器里改过的内容，长度不同以便缓存失效</html>"
	if err := os.WriteFile(filepath.Join(dir, "404.html"), []byte(手工), 0o644); err != nil {
		t.Fatalf("写入文件失败：%v", err)
	}
	if got, _ := Content(404); got != 手工 {
		t.Fatalf("外部修改文件后 Content = %q，期望 %q", got, 手工)
	}
}

// TestContentFallsBackToDefault 验证文件被删除时回退内置默认内容，错误页不至于不可用。
func TestContentFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init 失败：%v", err)
	}
	if err := os.Remove(filepath.Join(dir, "404.html")); err != nil {
		t.Fatalf("删除模板文件失败：%v", err)
	}
	got, ok := Content(404)
	if !ok {
		t.Fatal("404 为受支持状态码，Content 应返回 true")
	}
	if !strings.Contains(got, defaults[404].title) {
		t.Fatalf("文件缺失时应回退内置默认模板，实际 %q", got)
	}
}

// TestSaveResetAndUnsupportedCode 验证恢复默认语义与非法状态码拒绝。
func TestSaveResetAndUnsupportedCode(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init 失败：%v", err)
	}
	if err := Save(418, "<html>teapot</html>"); err == nil {
		t.Fatal("418 不在 Codes 内，Save 应报错")
	}
	if _, ok := Content(418); ok {
		t.Fatal("418 不在 Codes 内，Content 应返回 false")
	}

	if err := Save(500, "<html>自定义 500</html>"); err != nil {
		t.Fatalf("Save 失败：%v", err)
	}
	if err := Reset(); err != nil {
		t.Fatalf("Reset 失败：%v", err)
	}
	got, _ := Content(500)
	if !strings.Contains(got, defaults[500].title) {
		t.Fatalf("Reset 后应恢复内置默认模板，实际 %q", got)
	}
}

// TestHandlerInterceptionBoundary 验证替换边界：
// 只替换浏览器页面请求，机器调用（无 Accept）与 /api/、/proxy/ 路径原样透传；
// 经统一网关访问带前缀时，上述判断同样成立。
func TestHandlerInterceptionBoundary(t *testing.T) {
	if err := Init(t.TempDir()); err != nil {
		t.Fatalf("Init 失败：%v", err)
	}
	h := Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "原始错误正文", http.StatusNotFound)
	}), "/app/TunHook")

	cases := []struct {
		name     string
		path     string
		accept   string
		replaced bool
	}{
		{name: "浏览器页面请求", path: "/nope", accept: "text/html,application/xhtml+xml", replaced: true},
		{name: "机器调用无 Accept", path: "/nope", accept: "", replaced: false},
		{name: "接口路径", path: "/api/nope", accept: "text/html", replaced: false},
		{name: "统一网关透传路径", path: "/proxy/nope", accept: "text/html", replaced: false},
		{name: "网关前缀下的页面请求", path: "/app/TunHook/nope", accept: "text/html", replaced: true},
		{name: "网关前缀下的接口路径", path: "/app/TunHook/api/nope", accept: "text/html", replaced: false},
		{name: "网关前缀下的透传路径", path: "/app/TunHook/proxy/nope", accept: "text/html", replaced: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, c.path, nil)
			if c.accept != "" {
				r.Header.Set("Accept", c.accept)
			}
			h.ServeHTTP(w, r)

			body := w.Body.String()
			if w.Code != http.StatusNotFound {
				t.Fatalf("状态码应保持 404，实际 %d", w.Code)
			}
			if c.replaced {
				if !strings.Contains(body, defaults[404].title) {
					t.Fatalf("应替换为自定义错误页，实际正文：%q", body)
				}
				if strings.Contains(body, "原始错误正文") {
					t.Fatalf("原始错误正文不应残留：%q", body)
				}
				return
			}
			if strings.Contains(body, defaults[404].title) {
				t.Fatalf("不应被替换为自定义错误页，实际正文：%q", body)
			}
			if !strings.Contains(body, "原始错误正文") {
				t.Fatalf("应保持原有错误响应，实际正文：%q", body)
			}
		})
	}
}

// TestPreviewRendersTemplate 验证预览输出与真实错误页一致：同样的状态码与内容。
func TestPreviewRendersTemplate(t *testing.T) {
	if err := Init(t.TempDir()); err != nil {
		t.Fatalf("Init 失败：%v", err)
	}
	w := httptest.NewRecorder()
	if !Preview(w, 503) {
		t.Fatal("503 为受支持状态码，Preview 应返回 true")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("预览状态码应为 503，实际 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), defaults[503].title) {
		t.Fatalf("预览应输出当前模板内容，实际 %q", w.Body.String())
	}
}
