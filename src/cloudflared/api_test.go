package cloudflared

import "testing"

// TestValidService 校验 ingress service 白名单：只放行浏览器可直接访问的 HTTP 类服务。
func TestValidService(t *testing.T) {
	valid := []string{"http://127.0.0.1:8080", "https://nas.local:443", "unix:/run/app.sock", "unix+tls:/run/app.sock", "HTTP://127.0.0.1:80"}
	for _, s := range valid {
		if !ValidService(s) {
			t.Errorf("ValidService(%q) 应为 true", s)
		}
	}
	invalid := []string{"", "127.0.0.1:8080", "tcp://127.0.0.1:22", "ssh://127.0.0.1:22", "rdp://127.0.0.1:3389", "http_status:404"}
	for _, s := range invalid {
		if ValidService(s) {
			t.Errorf("ValidService(%q) 应为 false", s)
		}
	}
}

// TestHostnameInZone 校验域名归属判断（等于 zone 或为其子域名）。
func TestHostnameInZone(t *testing.T) {
	cases := []struct {
		hostname string
		zone     string
		want     bool
	}{
		{"example.com", "example.com", true},
		{"App.Example.com", "example.com", true},
		{"a.b.example.com", "example.com", true},
		{"example.com.evil.com", "example.com", false},
		{"notexample.com", "example.com", false},
		{"other.com", "example.com", false},
		{"", "example.com", false},
		{"example.com", "", false},
	}
	for _, c := range cases {
		if got := HostnameInZone(c.hostname, c.zone); got != c.want {
			t.Errorf("HostnameInZone(%q, %q) = %v, 期望 %v", c.hostname, c.zone, got, c.want)
		}
	}
}
