package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tunhook/store"

	"github.com/spf13/viper"
)

// TestDBConfigRoundTrip 模拟 Web 端保存设置（SetJSON）→ 重启加载（SettingsByPrefix + viper.Set + Unmarshal）全过程。
func TestDBConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	yaml := `log:
  level: info
  file: ""
nat:
  method: auto
  gateway: ""
forward:
  rules: []
tunnel:
  startup_delay: 3000
  heartbeat_interval: 30000
  retry_interval: 3000
  validity_timeout: 5000
  check_interval: 30
webhook:
  url: ""
  method: POST
  headers: {}
  callback: ""
ip_filter:
  enabled: false
`
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	// —— 第一次启动：加载 yaml ——
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("首次加载: check_interval=%d webhook.url=%q",
		cfg.Tunnel.CheckInterval, cfg.Webhook.URL)

	// —— Web 端保存设置：模拟 persistConfig → SetJSON ——
	st, err := store.Open(filepath.Join(dir, "tunhook.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	write := func(key string, v interface{}) {
		b, _ := json.Marshal(v)
		if err := st.SetSetting("cfg."+key, string(b)); err != nil {
			t.Fatalf("SetSetting %s: %v", key, err)
		}
	}
	write("tunnel.check_interval", 60)
	write("webhook.url", "https://example.com/hook")
	write("webhook.method", "POST")
	write("webhook.callback", "ok")
	write("log.max_entries", 256)

	// —— 第二次启动（模拟重启）：重新 Load + applyDBConfig 逻辑 ——
	cfg2, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := st.SettingsByPrefix("cfg.")
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range kv {
		var val interface{}
		if err := json.Unmarshal([]byte(v), &val); err != nil {
			t.Logf("跳过无法解析的 key %s: %v", k, err)
			continue
		}
		viper.Set(strings.TrimPrefix(k, "cfg."), val)
	}
	if err := viper.Unmarshal(cfg2); err != nil {
		t.Fatal(err)
	}

	t.Logf("重启后: check_interval=%d webhook.url=%q method=%q callback=%q max_entries=%d",
		cfg2.Tunnel.CheckInterval, cfg2.Webhook.URL,
		cfg2.Webhook.Method, cfg2.Webhook.Callback, cfg2.Log.MaxEntries)

	if cfg2.Tunnel.CheckInterval != 60 {
		t.Errorf("check_interval 未持久化: %d", cfg2.Tunnel.CheckInterval)
	}
	if cfg2.Webhook.URL != "https://example.com/hook" {
		t.Errorf("webhook.url 未持久化: %q", cfg2.Webhook.URL)
	}
	if cfg2.Webhook.Callback != "ok" {
		t.Errorf("webhook.callback 未持久化: %q", cfg2.Webhook.Callback)
	}
	if cfg2.Log.MaxEntries != 256 {
		t.Errorf("log.max_entries 未持久化: %d", cfg2.Log.MaxEntries)
	}
}
