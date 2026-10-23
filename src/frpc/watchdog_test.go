package frpc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeWatchdogLog 写入指定内容的 frpc 日志（走生产同一路径规则）。
func writeWatchdogLog(t *testing.T, m *Manager, content string) {
	t.Helper()
	if err := os.MkdirAll(m.logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.logPathFor(DefaultServerName), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestLoginSucceededDetectsMarkers 覆盖登录结果判定：日志中最后一条「登录尝试」决定结果。
func TestLoginSucceededDetectsMarkers(t *testing.T) {
	const (
		successLine = "2026-10-16 10:57:26.145 [I] [client/service.go:355] [ee535791e60ae1ab] login to server success, get run id [ee535791e60ae1ab]"
		failLine    = "2026-10-16 10:44:47.285 [W] [client/service.go:346] connect to server error: connection write timeout"
		oldSuccess  = "2026-10-16 10:57:26.145 [I] [client/service.go:355] login to server success, get run id [ee535791e60ae1ab]"
	)

	cases := []struct {
		name    string
		log     string
		wantOK  bool
		wantLog bool
	}{
		{"仅成功", successLine, true, true},
		{"仅失败", failLine, false, true},
		{"成功后失败（最后一条为失败）", successLine + "\n" + failLine, false, true},
		{"失败后成功（最后一条为成功）", failLine + "\n" + successLine, true, true},
		{"无登录记录", "2026-10-16 10:57:26.079 [I] [sub/root.go:194] start frpc service\n", false, false},
		{"ANSI 颜色码不应影响判定", "\x1b[0m\x1b[1;34m" + successLine, true, true},
		{"登录失败后的启动日志不应掩盖失败", failLine + "\n2026-10-16 10:57:26.080 [I] [client/service.go:268] admin server listen on 127.0.0.1:7400", false, true},
		{"早期版本措辞", oldSuccess, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(t.TempDir(), nil)
			m.logDir = t.TempDir()
			writeWatchdogLog(t, m, tc.log)
			ok, logged := m.loginSucceeded(DefaultServerName)
			if ok != tc.wantOK || logged != tc.wantLog {
				t.Errorf("loginSucceeded = (%v, %v)，want (%v, %v)", ok, logged, tc.wantOK, tc.wantLog)
			}
		})
	}
}

// TestWatchdogGraceElapsed 覆盖启动宽限期：首次见到实例应返回false（不判定），
// 宽限期未到不判定；进程重启（PID 变化）应重置宽限期。
func TestWatchdogGraceElapsed(t *testing.T) {
	m := NewManager(t.TempDir(), nil)
	m.watchdogFail = map[string]int{}
	m.watchdogStarted = map[string]time.Time{}
	m.watchdogPID = map[string]int{}

	// 无进程时 PIDFor 返回 0；模拟「首次见到该实例」
	if m.watchdogGraceElapsed("s1") {
		t.Error("首次见到实例应处于宽限期，不应判定")
	}
	// 人为把宽限期起点前移，模拟宽限期已过
	m.watchdogMu.Lock()
	m.watchdogStarted["s1"] = time.Now().Add(-watchdogStartWindow - time.Second)
	m.watchdogMu.Unlock()
	if !m.watchdogGraceElapsed("s1") {
		t.Error("宽限期已过，应返回 true")
	}
	// PID 变化视为进程重启，宽限期应重置
	m.watchdogMu.Lock()
	m.watchdogPID["s1"] = 12345
	m.watchdogMu.Unlock()
	if m.watchdogGraceElapsed("s1") {
		t.Error("进程重启后应重置宽限期，不应立即判定")
	}
}

// TestWatchdogCountAndReset 覆盖失败计数累加与清零。
func TestWatchdogCountAndReset(t *testing.T) {
	m := NewManager(t.TempDir(), nil)
	m.watchdogFail = map[string]int{}
	for i := 1; i <= watchdogFailLimit; i++ {
		if got := m.bumpWatchdog("s1"); got != i {
			t.Fatalf("第 %d 次计数 = %d，want %d", i, got, i)
		}
	}
	if got := m.WatchdogFails("s1"); got != watchdogFailLimit {
		t.Errorf("WatchdogFails = %d，want %d", got, watchdogFailLimit)
	}
	m.resetWatchdog("s1")
	if got := m.WatchdogFails("s1"); got != 0 {
		t.Errorf("reset 后 WatchdogFails = %d，want 0", got)
	}
}

// TestLogPathForLogDir 确保日志写入配置指定的 logDir（看门狗依赖 LogTailFor 读到日志）。
func TestLogPathForLogDir(t *testing.T) {
	dir := t.TempDir()
	logDir := t.TempDir()
	m := NewManager(dir, nil)
	m.SetPaths("", logDir)
	got := m.logPathFor(DefaultServerName)
	if filepath.Dir(got) != logDir {
		t.Errorf("日志路径 = %s，应位于 %s 下", got, logDir)
	}
}

// writeTestConfig 写入 frpc.json（指定日志保留行数 + 一个默认服务器），
// 使 LoadConfig 能读到 LogEntries 配置。
func writeTestConfig(t *testing.T, m *Manager, logEntries int) {
	t.Helper()
	if err := os.MkdirAll(m.configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"log_entries":%d,"servers":[{"name":%q,"addr":"127.0.0.1","port":7000}]}`,
		logEntries, DefaultServerName)
	if err := os.WriteFile(filepath.Join(m.configDir, ConfigJSON), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// newLogTrimManager 构造配好日志目录与 LogEntries 的管理器，并写入 lines 行日志。
func newLogTrimManager(t *testing.T, logEntries, lines int) (*Manager, string) {
	t.Helper()
	m := NewManager(t.TempDir(), nil)
	m.SetPaths(t.TempDir(), t.TempDir())
	writeTestConfig(t, m, logEntries)

	var sb strings.Builder
	for i := 1; i <= lines; i++ {
		fmt.Fprintf(&sb, "line-%d\n", i)
	}
	content := sb.String()
	writeWatchdogLog(t, m, content)
	return m, content
}

// TestLogTailForIsPureRead 回归测试：LogTailFor 必须是纯读——
// 即使配置了 LogEntries 且日志已超限，也不得改写日志文件。
// 背景：该方法被登录看门狗每 2 秒调用一次，此前内部顺带裁剪，
// 等于每 2 秒「读全文 + 可能重写全文」。
func TestLogTailForIsPureRead(t *testing.T) {
	m, content := newLogTrimManager(t, 3, 10)

	got := strings.Split(m.LogTailFor(DefaultServerName, 5), "\n")
	if len(got) != 5 || got[0] != "line-6" || got[4] != "line-10" {
		t.Errorf("应返回末尾 5 行（line-6..line-10），实际: %q", got)
	}

	after, err := os.ReadFile(m.logPathFor(DefaultServerName))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != content {
		t.Errorf("LogTailFor 不得改写日志文件\n期望:\n%s实际:\n%s", content, string(after))
	}
}

// TestTrimLogsTrimsToConfiguredLimit 确认裁剪仍由显式入口 TrimLogs 生效
// ——修掉读写副作用时，不能把「防日志无限增长」这个功能一起丢掉。
func TestTrimLogsTrimsToConfiguredLimit(t *testing.T) {
	m, _ := newLogTrimManager(t, 3, 10)

	m.TrimLogs()

	data, err := os.ReadFile(m.logPathFor(DefaultServerName))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("裁剪后应保留 3 行，实际 %d 行: %q", len(lines), string(data))
	}
	if lines[len(lines)-1] != "line-10" {
		t.Errorf("应保留末尾行，实际末行 %q", lines[len(lines)-1])
	}
}
