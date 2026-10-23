package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestDeskAppInstallTemplate 验证桌面图标空应用的模板展开/占位符替换与 fnpack 打包链路。
// 本地无 appcenter-cli 时 install 会在安装步骤报错，但打包产物与替换结果必须正确。
func TestDeskAppInstallTemplate(t *testing.T) {
	m := newDeskAppManager(t.TempDir(), zap.NewNop())
	err := m.install(nil, "demo", "我的影视库", "url", true, "", "gateway", 0, false, "")
	if err != nil {
		// 允许"安装失败"（本地无 appcenter-cli），但前序步骤必须已执行
		t.Logf("install 返回（预期为安装步骤报错）: %v", err)
	}

	projDir := filepath.Join(m.dataDir, "desk-apps", "TunHook-demo")

	// 1. manifest 替换
	manifest, rerr := os.ReadFile(filepath.Join(projDir, "manifest"))
	if rerr != nil {
		t.Fatalf("manifest 未生成: %v", rerr)
	}
	for _, want := range []string{
		"appname=TunHook-demo",
		"display_name=我的影视库",
		"distributor=TunHook",
	} {
		if !strings.Contains(string(manifest), want) {
			t.Errorf("manifest 缺少 %q，实际:\n%s", want, manifest)
		}
	}

	// 2. app/ui/config 替换（type/allUsers/title/url）
	cfg, rerr := os.ReadFile(filepath.Join(projDir, "app", "ui", "config"))
	if rerr != nil {
		t.Fatalf("ui/config 未生成: %v", rerr)
	}
	for _, want := range []string{
		`"title": "我的影视库"`,
		`"type": "url"`,
		`"allUsers": true`,
		`"/app/TunHook/proxy/demo"`,
	} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf("ui/config 缺少 %q，实际:\n%s", want, cfg)
		}
	}
	// 网关入口直接使用路径访问，不注册网关/CGI（无 gatewaySocket/gatewayPrefix/index.cgi）
	if strings.Contains(string(cfg), "gatewaySocket") || strings.Contains(string(cfg), "gatewayPrefix") ||
		strings.Contains(string(cfg), "/cgi/") {
		t.Errorf("ui/config 不应包含网关/CGI 入口字段，实际:\n%s", cfg)
	}
	if _, ferr := os.Stat(filepath.Join(projDir, "app", "ui", "index.cgi")); !os.IsNotExist(ferr) {
		t.Errorf("模板不应再生成 app/ui/index.cgi")
	}

	// 3. config/privilege 用户名替换
	priv, rerr := os.ReadFile(filepath.Join(projDir, "config", "privilege"))
	if rerr != nil {
		t.Fatalf("privilege 未生成: %v", rerr)
	}
	if !strings.Contains(string(priv), `"username": "tunhook-demo"`) {
		t.Errorf("privilege 用户名未替换，实际:\n%s", priv)
	}

	// 4. 生命周期脚本可执行
	mainInfo, serr := os.Stat(filepath.Join(projDir, "cmd", "main"))
	if serr != nil || mainInfo.Mode()&0111 == 0 {
		t.Errorf("cmd/main 不存在或不可执行: %v", serr)
	}

	// 5. 本地有 fnpack 时应已生成 fpk（appcenter-cli 缺失才会失败）
	fpk := filepath.Join(projDir, "TunHook-demo.fpk")
	if _, ferr := os.Stat(fpk); ferr != nil {
		t.Logf("fpk 未生成（本地无 fnpack 或 build 失败）: %v", ferr)
	} else {
		t.Logf("fpk 已生成: %s", fpk)
	}
}

// TestDeskAppRejectBadName 校验非法规则名被拒绝。
func TestDeskAppRejectBadName(t *testing.T) {
	m := newDeskAppManager(t.TempDir(), zap.NewNop())
	if err := m.install(nil, "bad-name", "t", "iframe", false, "", "gateway", 0, false, ""); err == nil {
		t.Error("含连字符的规则名应被拒绝")
	}
	if err := m.uninstall(nil, "bad-name"); err != nil {
		t.Errorf("非法规则名 uninstall 应直接返回 nil，实际: %v", err)
	}
}

// TestDeskAppPortMode 验证 TCP/UDP/HTTP 转发的端口入口模式：ui/config 使用端口入口（protocol/port），
// 而非网关前缀入口（gatewaySocket/gatewayPrefix）。
func TestDeskAppPortMode(t *testing.T) {
	m := newDeskAppManager(t.TempDir(), zap.NewNop())
	err := m.install(nil, "tcp8080", "我的服务", "iframe", true, "", "port", 8080, false, "")
	if err != nil {
		t.Logf("install 返回（预期为安装步骤报错）: %v", err)
	}

	projDir := filepath.Join(m.dataDir, "desk-apps", "TunHook-tcp8080")
	cfg, rerr := os.ReadFile(filepath.Join(projDir, "app", "ui", "config"))
	if rerr != nil {
		t.Fatalf("ui/config 未生成: %v", rerr)
	}
	for _, want := range []string{
		`"title": "我的服务"`,
		`"type": "iframe"`,
		`"protocol": "http"`,
		`"port": "8080"`,
		`"allUsers": true`,
	} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf("端口模式 ui/config 缺少 %q，实际:\n%s", want, cfg)
		}
	}
	if strings.Contains(string(cfg), "gatewaySocket") || strings.Contains(string(cfg), "gatewayPrefix") {
		t.Errorf("端口模式 ui/config 不应包含网关入口字段，实际:\n%s", cfg)
	}
}

// TestDeskAppURLMode 验证外部地址入口（frpc 代理 / Webhook 通道）：
// ui/config 直接写入完整外部 URL，且强制使用「浏览器标签页（url）」打开方式
// （iframe 桌面窗口会把 url 当作 NAS 相对路径解析，外部地址打不开），不生成 index.cgi。
func TestDeskAppURLMode(t *testing.T) {
	m := newDeskAppManager(t.TempDir(), zap.NewNop())
	err := m.install(nil, "ab12cd34", "我的站点", "iframe", true, "", "url", 0, false, "http://ddd.myunxi.top")
	if err != nil {
		t.Logf("install 返回（预期为安装步骤报错）: %v", err)
	}

	projDir := filepath.Join(m.dataDir, "desk-apps", "TunHook-ab12cd34")
	cfg, rerr := os.ReadFile(filepath.Join(projDir, "app", "ui", "config"))
	if rerr != nil {
		t.Fatalf("ui/config 未生成: %v", rerr)
	}
	for _, want := range []string{
		`"title": "我的站点"`,
		`"type": "url"`, // 外部地址强制浏览器标签页打开
		`"allUsers": true`,
		`"url": "http://ddd.myunxi.top"`,
	} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf("外部地址模式 ui/config 缺少 %q，实际:\n%s", want, cfg)
		}
	}
	// 不依赖系统 index.cgi
	if _, ferr := os.Stat(filepath.Join(projDir, "app", "ui", "index.cgi")); !os.IsNotExist(ferr) {
		t.Errorf("外部地址模式不应生成 index.cgi")
	}
}

// TestDeskTaskProgress 验证 install 期间任务会记录步骤/进度/日志，且任务可查询。
func TestDeskTaskProgress(t *testing.T) {
	m := newDeskAppManager(t.TempDir(), zap.NewNop())
	task := m.newTask("install")
	if task.Status != TaskRunning {
		t.Errorf("新任务状态应为 running，实际: %s", task.Status)
	}
	// 本地可能无 fnpack/appcenter-cli，install 报错不阻断断言
	_ = m.install(task, "demo", "t", "iframe", false, "", "gateway", 0, false, "")
	if task.Step == "" {
		t.Error("任务应记录当前步骤")
	}
	if task.Percent < 5 {
		t.Errorf("任务进度应至少到 5，实际: %d", task.Percent)
	}
	// 快照查询
	snap := m.task(task.ID)
	if snap == nil {
		t.Fatal("任务应可通过 ID 查询")
	}
	if snap.Step != task.Step || snap.Percent != task.Percent {
		t.Error("任务快照与实时状态不一致")
	}
}
