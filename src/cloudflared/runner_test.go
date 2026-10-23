package cloudflared

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// TestRunnerIdentityRecognizesOwnProcess 保证身份校验不会把真实内核进程误判为「不是我们」：
// 以 <dir>/cloudflared 身份启动子进程并只留下 pid 文件（等同应用重启后再读该文件），
// 仍应识别为运行中，且 Stop 能真正停掉它。
func TestRunnerIdentityRecognizesOwnProcess(t *testing.T) {
	if os.Getenv("TUNHOOK_FAKE_CLOUDFLARED") == "1" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}

	dir := t.TempDir()
	binDir := t.TempDir() // 内核单独一份（全局共用），实例目录只放 pid 与日志
	bin := filepath.Join(binDir, BinName)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, data, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "TUNHOOK_FAKE_CLOUDFLARED=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	time.Sleep(200 * time.Millisecond)

	r := NewRunner(dir, bin, nil)
	if err := os.WriteFile(filepath.Join(dir, PidFile), []byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
		t.Fatal(err)
	}
	if !r.Running() {
		t.Error("真实的内核进程应被识别为运行中（身份校验不得误判自己）")
	}
	if got := r.PID(); got != cmd.Process.Pid {
		t.Errorf("PID 应为 %d，实际 %d", cmd.Process.Pid, got)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("停止失败: %v", err)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Error("真实的内核进程应已被停止")
	}
}

// TestPIDGuardAgainstRecycledPID 覆盖 pid 文件残留 + PID 被无关进程复用的场景：
// 不得误判「运行中」，Stop 不得向该进程发信号（避免误杀用户的其他服务），
// 且残留的 pid 文件应被清理。
func TestPIDGuardAgainstRecycledPID(t *testing.T) {
	dir := t.TempDir()
	r := NewRunner(dir, filepath.Join(t.TempDir(), BinName), nil)

	decoy := exec.Command("sleep", "30")
	if err := decoy.Start(); err != nil {
		t.Fatalf("启动诱饵进程失败: %v", err)
	}
	defer func() { _ = decoy.Process.Kill() }()
	time.Sleep(100 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(dir, PidFile), []byte(strconv.Itoa(decoy.Process.Pid)), 0644); err != nil {
		t.Fatal(err)
	}

	if r.Running() {
		t.Error("无关进程的 PID 不应被判定为隧道运行中")
	}
	if got := r.PID(); got != 0 {
		t.Errorf("PID 应返回 0（不展示无关进程），实际 %d", got)
	}

	if err := r.Stop(); err != nil {
		t.Fatalf("停止不应报错: %v", err)
	}
	if err := decoy.Process.Signal(syscall.Signal(0)); err != nil {
		t.Error("无关进程被误杀（发信号给了复用的 PID）")
	}
	if _, err := os.Stat(filepath.Join(dir, PidFile)); !os.IsNotExist(err) {
		t.Errorf("残留 pid 文件应被清理，stat 结果: %v", err)
	}
}

// TestRunnersIsolated 多实例互不干扰：两个 runner 各有工作目录与 PID 文件，
// 一个实例的 pid 文件不得影响另一个实例的运行判定。
func TestRunnersIsolated(t *testing.T) {
	base := t.TempDir()
	bin := filepath.Join(t.TempDir(), BinName)
	a := NewRunner(filepath.Join(base, "a"), bin, nil)
	b := NewRunner(filepath.Join(base, "b"), bin, nil)
	if a.Dir() == b.Dir() {
		t.Fatal("实例工作目录应彼此独立")
	}
	if err := os.MkdirAll(a.Dir(), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.Dir(), PidFile), []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
		t.Fatal(err)
	}
	if b.Running() {
		t.Error("另一个实例的 pid 文件不应被判为本实例运行中")
	}
	if err := b.Stop(); err != nil {
		t.Errorf("未运行时停止不应报错: %v", err)
	}
}

// TestFreePortUniqueUntilReleased 同一进程内连续分配不得拿到同一个端口：
// 端口探测与实际绑定之间有窗口期（多实例先后启动必然命中），
// 只有「分配即登记、退出才释放」才能保证互不重复。
func TestFreePortUniqueUntilReleased(t *testing.T) {
	p1, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	if p1 == p2 {
		t.Fatalf("两次分配得到同一端口 %d，后启动的实例会绑定失败", p1)
	}
	releasePort(p1)
	p3, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	if p3 != p1 {
		t.Errorf("已释放的端口 %d 应可再次分配，实际 %d", p1, p3)
	}
	releasePort(p2)
	releasePort(p3)
	releasePort(0) // 未分配端口时释放应为空操作
}

// TestFindQuickURL 临时域名从日志尾部解析：offset 之后的内容才是本次启动的输出，
// 不得把上一次运行残留的 trycloudflare 地址当成本次地址。
func TestFindQuickURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), LogFile)
	old := "2026-09-17T13:00:00Z INF |  https://old-tunnel-name.trycloudflare.com  |\n"
	if err := os.WriteFile(path, []byte(old), 0644); err != nil {
		t.Fatal(err)
	}
	offset, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := findQuickURL(path, 0); got != "https://old-tunnel-name.trycloudflare.com" {
		t.Fatalf("从头解析应得到历史地址，实际 %q", got)
	}
	if got := findQuickURL(path, offset.Size()); got != "" {
		t.Errorf("本次启动尚无输出时不应解析出地址，实际 %q", got)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("2026-09-17T13:10:00Z INF Requesting new quick Tunnel on trycloudflare.com...\n" +
		"2026-09-17T13:10:09Z INF |  https://new-fresh-tunnel.trycloudflare.com  |\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if got := findQuickURL(path, offset.Size()); got != "https://new-fresh-tunnel.trycloudflare.com" {
		t.Errorf("应解析出本次启动的临时域名，实际 %q", got)
	}
}
