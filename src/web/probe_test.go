package web

import "testing"

func TestDetectSourcePrefix(t *testing.T) {
	cases := []struct {
		html string
		want string
	}{
		// 子路径部署：资源都挂在 /app/canvasboard 下 → 公共前缀
		{`<script src="/app/canvasboard/js/app.js"></script><link href="/app/canvasboard/css/app.css"><img src="/app/canvasboard/logo.png">`, "/app/canvasboard"},
		// 根路径部署：/js、/css 等 → 公共前缀为空（按根路径处理）
		{`<script src="/js/app.js"></script><link href="/css/app.css">`, ""},
		// 子路径与 /api 混合 → 公共前缀退化为空（避免误判）
		{`<script src="/app/x/js/a.js"></script><img src="/api/icon.png">`, ""},
		// 单一路径 /api → 过滤为空
		{`<img src="/api/icon.png"><img src="/api/x.png">`, ""},
		// 无资源引用 → 空
		{`<html><body>hello</body></html>`, ""},
		// 相对路径不参与 → 空
		{`<script src="js/app.js"></script>`, ""},
		// 协议相对地址不参与 → 空
		{`<script src="//cdn.example.com/app.js"></script>`, ""},
		// Next.js 资源目录前缀（/_next/static）→ 空（不是应用部署前缀）
		{`<script src="/_next/static/chunks/a.js"></script><link href="/_next/static/chunks/b.css"><img src="/_next/static/media/x.png">`, ""},
		// Vue/Vite 资源目录前缀（/assets）→ 空
		{`<script src="/assets/index.js"></script><link href="/assets/index.css">`, ""},
	}
	for i, c := range cases {
		if got := detectSourcePrefix(c.html); got != c.want {
			t.Errorf("case %d: detectSourcePrefix() = %q, want %q", i, got, c.want)
		}
	}
}

func TestDetectRootPrefixes(t *testing.T) {
	cases := []struct {
		name   string
		html   string
		jsBody string
		want   string
	}{
		{"无资源无接口", `<html></html>`, "", ""},
		{"Next.js 资源+接口", `<script src="/_next/static/chunks/a.js"></script><script src="/_next/static/chunks/b.js"></script>`, `fetch("/api/users");fetch("/api/settings");fetch("/api/auth");`, "/_next,/api"},
		{"JS 高频接口", `<html></html>`, `xhr("/api/a");xhr("/api/b");xhr("/api/c");`, "/api"},
		{"模板字符串接口", `<html></html>`, "fetch(`/${o.BASE_URL}/ping`);fetch(`/${o.BASE_URL}/ping`);fetch(`/${o.BASE_URL}/download?count=16`);", "/ping"},
		{"出现次数不足不推荐", `<html></html>`, `xhr("/api/a");xhr("/log");`, ""},
		{"登录路径不改写", `<html></html>`, `location="/login";location="/login";`, ""},
	}
	for _, c := range cases {
		if got := detectRootPrefixes(c.html, c.jsBody); got != c.want {
			t.Errorf("%s: detectRootPrefixes() = %q, want %q", c.name, got, c.want)
		}
	}
}
