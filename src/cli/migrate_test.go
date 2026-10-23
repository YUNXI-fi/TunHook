package cli

import (
	"testing"
)

// TestDataDirFnOSNeverFallsBackToAppDir 验证在 fnOS 环境（TRIM_APPDEST 已设置）但
// TUNHOOK_DATA_DIR / TRIM_PKGVAR 缺失时，dataDir 按标准布局推导 @appdata，
// 绝不回退到会被升级替换的应用目录（@appcenter/TunHook）。
func TestDataDirFnOSNeverFallsBackToAppDir(t *testing.T) {
	t.Setenv("TUNHOOK_DATA_DIR", "")
	t.Setenv("TRIM_PKGVAR", "")
	t.Setenv("TUNHOOK_CONFIG_DIR", "")
	t.Setenv("TRIM_PKGETC", "")
	t.Setenv("TRIM_APPDEST", "/vol1/@appcenter/TunHook")
	t.Setenv("TRIM_APPDEST_VOL", "/vol1")
	t.Setenv("TRIM_APPNAME", "TunHook")

	if got := dataDir(); got != "/vol1/@appdata/TunHook" {
		t.Errorf("dataDir() = %q, want /vol1/@appdata/TunHook（不得回退到应用目录）", got)
	}
	if got := frpcConfigDir(); got != "/vol1/@appconf/TunHook" {
		t.Errorf("frpcConfigDir() = %q, want /vol1/@appconf/TunHook", got)
	}
	if got := etcDir(); got != "/vol1/@appconf/TunHook" {
		t.Errorf("etcDir() = %q, want /vol1/@appconf/TunHook", got)
	}
}

// TestDataDirFnOSDeriveFromAppDest 无 TRIM_APPDEST_VOL 时，从 TRIM_APPDEST 反推卷路径。
func TestDataDirFnOSDeriveFromAppDest(t *testing.T) {
	t.Setenv("TUNHOOK_DATA_DIR", "")
	t.Setenv("TRIM_PKGVAR", "")
	t.Setenv("TUNHOOK_CONFIG_DIR", "")
	t.Setenv("TRIM_PKGETC", "")
	t.Setenv("TRIM_APPDEST", "/vol2/@appcenter/TunHook")
	t.Setenv("TRIM_APPDEST_VOL", "")
	t.Setenv("TRIM_APPNAME", "")

	if got := dataDir(); got != "/vol2/@appdata/TunHook" {
		t.Errorf("dataDir() = %q, want /vol2/@appdata/TunHook", got)
	}
}