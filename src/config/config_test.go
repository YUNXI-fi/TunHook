package config

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/spf13/viper"
)

// TestCloudflareInstanceJSONRoundTrip 实例必须能 JSON 完整往返。
// 配置持久化走的正是 JSON（store.SetJSON("cfg.cloudflare.instances", …)），
// 一旦有字段被标成 json:"-"，重启后该字段就会静默丢失——本地回源地址与凭证都曾因此丢过。
func TestCloudflareInstanceJSONRoundTrip(t *testing.T) {
	in := CloudflareInstance{
		ID: "abc12345", Name: "nas", Mode: CloudflareModeToken,
		Token: "tok-value", TunnelToken: "tunnel-tok",
		DNSAccount: "cf-main", AccountID: "acc1", ZoneID: "zone1", ZoneName: "example.com",
		TunnelID: "tid1", LocalScheme: "https", LocalAddr: "10.0.0.5", LocalPort: 8443,
		QuickTarget: "http://127.0.0.1:8080",
		Protocol:    "http2", AutoStart: true,
		Routes: []CloudflareRoute{{Hostname: "a.example.com", Service: "http://127.0.0.1:1", Path: "/x"}},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var out CloudflareInstance
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("JSON 往返后字段不一致，持久化会丢数据:\n  写入 %+v\n  读回 %+v", in, out)
	}
}

// TestCloudflareInstancePersistRoundTrip 走一遍真实的持久化往返：
// 写库用 json 序列化（store.SetJSON），启动恢复用 viper.Unmarshal（走 mapstructure 标签）。
// 两套标签写法不一致时字段会被静默丢弃——「隧道没保存到数据库」的根因就在这。
func TestCloudflareInstancePersistRoundTrip(t *testing.T) {
	in := []CloudflareInstance{{
		ID: "abc12345", Name: "nas", Mode: CloudflareModeQuick,
		Token: "tok-value", TunnelToken: "tunnel-tok",
		DNSAccount: "cf-main", AccountID: "acc1", ZoneID: "zone1", ZoneName: "example.com",
		TunnelID: "tid1", LocalScheme: "https", LocalAddr: "10.0.0.5", LocalPort: 8443,
		QuickTarget: "http://127.0.0.1:8080", Protocol: "quic", AutoStart: true,
		Routes: []CloudflareRoute{{Hostname: "a.example.com", Service: "http://127.0.0.1:1", Path: "/x"}},
	}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	// 与 cli.applyDBConfig 一致的恢复路径
	var val interface{}
	if err := json.Unmarshal(raw, &val); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	v := viper.New()
	v.Set("cloudflare.instances", val)
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(cfg.Cloudflare.Instances) != 1 {
		t.Fatalf("实例数量不符，实际 %d 条", len(cfg.Cloudflare.Instances))
	}
	if !reflect.DeepEqual(in[0], cfg.Cloudflare.Instances[0]) {
		t.Errorf("持久化往返后字段不一致:\n  写入 %+v\n  读回 %+v", in[0], cfg.Cloudflare.Instances[0])
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Log.Level != "info" {
		t.Errorf("expected default log level 'info', got %q", cfg.Log.Level)
	}

	if cfg.Tunnel.CheckInterval != 30 {
		t.Errorf("expected default check interval 30, got %d", cfg.Tunnel.CheckInterval)
	}

	if cfg.Webhook.Method != "POST" {
		t.Errorf("expected default webhook method POST, got %q", cfg.Webhook.Method)
	}
}

func TestLoadFromFile(t *testing.T) {
	content := `
log:
  level: debug
  file: /tmp/tunhook.log

tunnel:
  check_interval: 60

forward:
  rules:
    - protocol: tcp
      local_addr: 0.0.0.0
      local_port: 8080
      remote_addr: 192.168.1.100
      remote_port: 80
`

	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Log.Level != "debug" {
		t.Errorf("expected log level 'debug', got %q", cfg.Log.Level)
	}

	if cfg.Tunnel.CheckInterval != 60 {
		t.Errorf("expected check interval 60, got %d", cfg.Tunnel.CheckInterval)
	}

	if len(cfg.Forward.Rules) != 1 {
		t.Fatalf("expected 1 forward rule, got %d", len(cfg.Forward.Rules))
	}

	rule := cfg.Forward.Rules[0]
	if rule.Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %q", rule.Protocol)
	}
	if rule.LocalPort != 8080 {
		t.Errorf("expected local port 8080, got %d", rule.LocalPort)
	}
	if rule.RemotePort != 80 {
		t.Errorf("expected remote port 80, got %d", rule.RemotePort)
	}
}

// TestCloudflareMigrateLegacy 旧版单实例配置应原样迁移成一条实例（含本地回源/协议/自启/路由），
// 迁移后旧字段清空，且重复调用不再迁移（幂等）。
func TestCloudflareMigrateLegacy(t *testing.T) {
	cf := CloudflareConfig{
		Mode: CloudflareModeAPI, Protocol: "quic", AutoStart: true,
		LocalScheme: "https", LocalAddr: "10.0.0.5", LocalPort: 8443,
		DNSAccount: "cf-main", AccountID: "acc1", ZoneID: "zone1", ZoneName: "example.com",
		TunnelID: "tid1", TunnelName: "nas", TunnelToken: "ttok",
		Routes: []CloudflareRoute{{Hostname: "a.example.com", Service: "http://127.0.0.1:8080"}},
	}
	if !cf.MigrateLegacy() {
		t.Fatal("旧配置应发生迁移")
	}
	if len(cf.Instances) != 1 {
		t.Fatalf("应迁移为 1 条实例，实际 %d", len(cf.Instances))
	}
	inst := cf.Instances[0]
	if inst.ID == "" || inst.Name != "nas" || inst.NormalizeMode() != CloudflareModeAPI {
		t.Errorf("实例迁移结果不符: %+v", inst)
	}
	if inst.RuntimeToken() != "ttok" || inst.LocalURL() != "https://10.0.0.5:8443" {
		t.Errorf("凭证/本地回源迁移不符: token=%q local=%q", inst.RuntimeToken(), inst.LocalURL())
	}
	if inst.Protocol != "quic" || !inst.AutoStart || len(inst.Routes) != 1 || !inst.Ready() {
		t.Errorf("协议/自启/路由/可启动迁移不符: %+v", inst)
	}
	if cf.TunnelID != "" || cf.Mode != "" || len(cf.Routes) != 0 {
		t.Errorf("迁移后旧字段应清空: %+v", cf)
	}
	if cf.MigrateLegacy() {
		t.Error("已有实例时不应再次迁移")
	}
	if cf.Index(inst.ID) != 0 {
		t.Error("Index 应按 ID 找到实例")
	}
	if cf.Index("不存在") != -1 {
		t.Error("Index 对不存在的 ID 应返回 -1")
	}
}

// TestCloudflareMigrateLegacySkipsDefaults 全新安装（只有 mode 默认值 token）不应迁移出空实例。
func TestCloudflareMigrateLegacySkipsDefaults(t *testing.T) {
	cf := CloudflareConfig{Mode: CloudflareModeToken, Protocol: "http2"}
	if cf.hasLegacy() {
		t.Fatal("只有默认值时应视为未配置")
	}
	if cf.MigrateLegacy() {
		t.Fatal("未配置过的旧结构不应迁移")
	}
	if len(cf.Instances) != 0 {
		t.Fatalf("不应产生实例，实际 %d 条", len(cf.Instances))
	}
}

// TestCloudflareInstanceOriginPerInstance 每条实例各有自己的本地回源；兼容旧 quick_target。
func TestCloudflareInstanceOriginPerInstance(t *testing.T) {
	legacy := CloudflareInstance{Mode: CloudflareModeQuick, QuickTarget: "https://127.0.0.1:19094"}
	if got := legacy.RuntimeTarget(); got != "https://127.0.0.1:19094" {
		t.Errorf("旧 quick_target 应解析为回源地址，实际 %q", got)
	}
	plain := CloudflareInstance{Mode: CloudflareModeToken}
	if plain.Ready() {
		t.Error("没有 Token 的 token 模式实例不应可启动")
	}
	if _, addr, port := plain.LocalOrigin(); addr != "127.0.0.1" || port != 0 {
		t.Errorf("未配置时应回落 127.0.0.1:0，实际 %s:%d", addr, port)
	}
	if plain.LocalURL() != "" {
		t.Errorf("未配置端口时回源地址应为空，实际 %q", plain.LocalURL())
	}
}
