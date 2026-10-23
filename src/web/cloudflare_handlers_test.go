package web

import (
	"testing"

	"tunhook/cloudflared"
	"tunhook/config"
)

// TestUpsertRoute 同 (域名, 路径) 覆盖、不同路径并列。
func TestUpsertRoute(t *testing.T) {
	list := upsertRoute(nil, config.CloudflareRoute{Hostname: "a.example.com", Service: "http://127.0.0.1:80"})
	list = upsertRoute(list, config.CloudflareRoute{Hostname: "a.example.com", Path: "/api", Service: "http://127.0.0.1:81"})
	if len(list) != 2 {
		t.Fatalf("不同路径应并列，实际 %d 条", len(list))
	}
	list = upsertRoute(list, config.CloudflareRoute{Hostname: "a.example.com", Service: "http://127.0.0.1:90"})
	if len(list) != 2 {
		t.Fatalf("同域名同路径应覆盖，实际 %d 条", len(list))
	}
	if list[0].Service != "http://127.0.0.1:90" {
		t.Errorf("覆盖后服务地址 = %q", list[0].Service)
	}
}

// TestRemoveRouteAndHostnameUse 删除指定 (域名, 路径)，并判断域名是否仍被其它路由占用。
func TestRemoveRouteAndHostnameUse(t *testing.T) {
	list := []config.CloudflareRoute{
		{Hostname: "a.example.com", Service: "http://127.0.0.1:80"},
		{Hostname: "a.example.com", Path: "/api", Service: "http://127.0.0.1:81"},
		{Hostname: "b.example.com", Service: "http://127.0.0.1:82"},
	}
	rest := removeRoute(list, "a.example.com", "")
	if len(rest) != 2 {
		t.Fatalf("应删除 1 条，剩余 %d 条", len(rest))
	}
	if !routeUsesHostname(rest, "a.example.com") {
		t.Error("a.example.com 仍有 /api 路由，应判定为占用")
	}
	rest = removeRoute(rest, "a.example.com", "/api")
	if routeUsesHostname(rest, "a.example.com") {
		t.Error("a.example.com 已无路由，不应判定为占用（DNS 记录才会被清理）")
	}
}

// TestToIngress 本地路由表转换为 ingress 规则（保留 hostname/path/service）。
func TestToIngress(t *testing.T) {
	rules := toIngress([]config.CloudflareRoute{
		{Hostname: "a.example.com", Service: "http://127.0.0.1:80"},
		{Hostname: "a.example.com", Path: "/api", Service: "http://127.0.0.1:81"},
	})
	if len(rules) != 2 {
		t.Fatalf("规则数 = %d", len(rules))
	}
	want := cloudflared.IngressRule{Hostname: "a.example.com", Path: "/api", Service: "http://127.0.0.1:81"}
	if rules[1] != want {
		t.Errorf("规则 = %+v，期望 %+v", rules[1], want)
	}
}

// TestCfAccessURL 访问地址按模式取值：quick 用临时域名、api 用路由表首个域名、token 无从得知。
func TestCfAccessURL(t *testing.T) {
	quick := config.CloudflareInstance{Mode: config.CloudflareModeQuick}
	if got := cfAccessURL(quick, "https://x-y.trycloudflare.com"); got != "https://x-y.trycloudflare.com" {
		t.Errorf("quick 访问地址 = %q", got)
	}
	api := config.CloudflareInstance{
		Mode:   config.CloudflareModeAPI,
		Routes: []config.CloudflareRoute{{Hostname: "a.example.com"}},
	}
	if got := cfAccessURL(api, ""); got != "https://a.example.com" {
		t.Errorf("api 访问地址 = %q", got)
	}
	if got := cfAccessURL(config.CloudflareInstance{Mode: config.CloudflareModeAPI}, ""); got != "" {
		t.Errorf("没有路由时 api 访问地址应为空，实际 %q", got)
	}
	if got := cfAccessURL(config.CloudflareInstance{Mode: config.CloudflareModeToken}, "https://ignored"); got != "" {
		t.Errorf("token 托管的访问地址本程序无从得知，应为空，实际 %q", got)
	}
}

// TestNormalizeCfInstance 本地回源与连接协议的归一化与校验。
func TestNormalizeCfInstance(t *testing.T) {
	inst := config.CloudflareInstance{LocalScheme: "HTTPS ", LocalAddr: " ", LocalPort: 5666, Protocol: "QUIC"}
	if err := normalizeCfInstance(&inst); err != nil {
		t.Fatalf("归一化不应报错: %v", err)
	}
	if inst.LocalScheme != "https" || inst.LocalAddr != "127.0.0.1" || inst.Protocol != "quic" {
		t.Errorf("归一化结果 = %+v", inst)
	}
	if err := normalizeCfInstance(&config.CloudflareInstance{LocalScheme: "ftp"}); err == nil {
		t.Error("非 http/https 的本地协议应报错")
	}
	if err := normalizeCfInstance(&config.CloudflareInstance{LocalPort: 70000}); err == nil {
		t.Error("越界端口应报错")
	}
}

// TestCfNotReadyReason 三种模式的启动前置条件不同，提示需按模式给出。
func TestCfNotReadyReason(t *testing.T) {
	if got := cfNotReadyReason(config.CloudflareInstance{Mode: config.CloudflareModeQuick}); got == "" {
		t.Error("quick 模式应给出「先填本地地址端口」的提示")
	}
	if got := cfNotReadyReason(config.CloudflareInstance{Mode: config.CloudflareModeAPI}); got == "" {
		t.Error("api 模式应给出「重新绑定」的提示")
	}
	if got := cfNotReadyReason(config.CloudflareInstance{Mode: config.CloudflareModeToken}); got == "" {
		t.Error("token 模式应给出「先保存 Token」的提示")
	}
}
