package frpc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteTOMLAuth(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Servers: []Server{{Name: "s", Addr: "1.2.3.4", Port: 7000}},
		Proxies: []Proxy{
			{Name: "web", Type: "http", Enabled: true, LocalIP: "127.0.0.1", LocalPort: 8080,
				CustomDomains: "web.example.com", HTTPUser: "admin", HTTPPassword: "secret123"},
		},
	}
	path := filepath.Join(dir, "frpc.toml")
	if err := writeTOML(cfg, path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	t.Logf("generated toml:\n%s", string(data))
	for _, want := range []string{"httpUser = \"admin\"", "httpPassword = \"secret123\""} {
		if !strings.Contains(string(data), want) {
			t.Errorf("toml 缺少 %q", want)
		}
	}
}
