package frpc

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// 子进程模式：以 <dir>/frpc 身份长时间存活，模拟真实的 frpc 进程。
func TestFrpcIdentityRecognizesOwnProcess(t *testing.T) {
	if os.Getenv("TUNHOOK_FAKE_FRPC") == "1" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}

	dir := t.TempDir()
	binPath := filepath.Join(dir, BinName)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, data, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binPath, 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(), "TUNHOOK_FAKE_FRPC=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // 与生产一致：frpc 以独立进程组启动
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	// 与生产一致：父进程异步回收，避免子进程退出后成为僵尸进程影响存活探测
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	time.Sleep(200 * time.Millisecond)

	// 只写 pid 文件、不保留内存进程记录：等同于应用重启后再看这个 pid 文件
	m := NewManager(dir, nil)
	m.writePIDFor(DefaultServerName, cmd.Process.Pid)

	if !m.ServerRunning(DefaultServerName) {
		t.Error("真实的 frpc 进程应被识别为运行中（身份校验不得误判自己）")
	}
	if got := m.PIDFor(DefaultServerName); got != cmd.Process.Pid {
		t.Errorf("PID 应为 %d，实际 %d", cmd.Process.Pid, got)
	}
	if pids := m.RunningPIDs(); pids[DefaultServerName] != cmd.Process.Pid {
		t.Errorf("RunningPIDs 应包含真实 frpc，实际 %v", pids)
	}

	if err := m.StopServer(DefaultServerName); err != nil {
		t.Fatalf("停止失败: %v", err)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Error("真实 frpc 进程应已被停止")
	}
	if _, err := os.Stat(m.pidPath(DefaultServerName)); !os.IsNotExist(err) {
		t.Errorf("停止后 pid 文件应被清理，stat 结果: %v", err)
	}
}

// TestPIDGuardAgainstRecycledPID 覆盖 pid 文件残留 + PID 被无关进程复用的场景：
//   - 不得把无关进程误判为「运行中」（状态误报）；
//   - Stop 不得向该进程发信号（否则会误杀用户的其他服务，本实现还向整个进程组发信号）；
//   - 残留的 pid 文件应被清理，避免下次继续误判。
//
// 构造方式：启动一个与 frpc 无关的 sleep 进程，把它的 PID 写进 frpc 的 pid 文件。
func TestPIDGuardAgainstRecycledPID(t *testing.T) {
	m := NewManager(t.TempDir(), nil)

	decoy := exec.Command("sleep", "30")
	if err := decoy.Start(); err != nil {
		t.Fatalf("启动诱饵进程失败: %v", err)
	}
	defer func() { _ = decoy.Process.Kill() }()
	time.Sleep(100 * time.Millisecond)

	const name = DefaultServerName
	m.writePIDFor(name, decoy.Process.Pid)

	if m.pidAliveFor(name) {
		t.Error("无关进程的 PID 不应被判定为 frpc 运行中")
	}
	if m.ServerRunning(name) {
		t.Error("状态不应显示运行中")
	}
	if got := m.PIDFor(name); got != 0 {
		t.Errorf("PID 应返回 0（不展示无关进程），实际 %d", got)
	}
	if pids := m.RunningPIDs(); len(pids) != 0 {
		t.Errorf("RunningPIDs 应为空，实际 %v", pids)
	}

	if err := m.StopServer(name); err != nil {
		t.Fatalf("停止不应报错: %v", err)
	}
	if err := decoy.Process.Signal(syscall.Signal(0)); err != nil {
		t.Error("无关进程被误杀（发信号给了复用的 PID）")
	}
	if _, err := os.Stat(m.pidPath(name)); !os.IsNotExist(err) {
		t.Errorf("残留 pid 文件应被清理，stat 结果: %v", err)
	}
}
