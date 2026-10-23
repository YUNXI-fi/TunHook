package mefrp

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// ProxyNames：解析本地 frpc.toml 中的代理名（单引号/双引号/多隧道/无配置）。
func TestRunnerProxyNames(t *testing.T) {
	dir := t.TempDir()
	r := NewRunner(dir, filepath.Join(dir, "frpc"), nil)

	// 配置不存在 → nil
	if names := r.ProxyNames(); names != nil {
		t.Fatalf("无配置时 ProxyNames() 应为 nil，实际 %v", names)
	}

	content := `serverAddr = 'frp.viokor.cc'
serverPort = 2333
user = 'u'

[auth]
method = 'token'
token = 'x'

[[proxies]]
name = 'canvasboard-ser'
type = 'tcp'
localIP = '127.0.0.1'
localPort = 3001

[[proxies]]
name = "web-http"
type = "http"
`
	if err := os.WriteFile(filepath.Join(dir, "frpc.toml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	names := r.ProxyNames()
	if len(names) != 2 {
		t.Fatalf("期望解析出 2 个代理名，实际 %v", names)
	}
	if !names["canvasboard-ser"] || !names["web-http"] {
		t.Errorf("代理名解析错误: %v", names)
	}
}

// TestRunnerIdentityRecognizesOwnProcess 保证身份校验不会把真实 frpc 误判为「不是我们」：
// 以 <dir>/frpc 身份启动子进程并只留下 pid 文件（等同应用重启后再读该文件），仍应识别为运行中，
// 且 Stop 能真正停掉它。
func TestRunnerIdentityRecognizesOwnProcess(t *testing.T) {
	if os.Getenv("TUNHOOK_FAKE_MEFRP_FRPC") == "1" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "frpc")
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
	cmd.Env = append(os.Environ(), "TUNHOOK_FAKE_MEFRP_FRPC=1")
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
	if err := os.WriteFile(r.pidPath(), []byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
		t.Fatal(err)
	}
	if !r.Running() {
		t.Error("真实的 frpc 进程应被识别为运行中（身份校验不得误判自己）")
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
		t.Error("真实的 frpc 进程应已被停止")
	}
}

// TestPIDGuardAgainstRecycledPID 覆盖 pid 文件残留 + PID 被无关进程复用的场景：
// 不得误判「运行中」，Stop 不得向该进程发信号（避免误杀用户的其他服务），
// 且残留的 pid 文件应被清理。
func TestPIDGuardAgainstRecycledPID(t *testing.T) {
	dir := t.TempDir()
	r := NewRunner(dir, filepath.Join(dir, "frpc"), nil)

	decoy := exec.Command("sleep", "30")
	if err := decoy.Start(); err != nil {
		t.Fatalf("启动诱饵进程失败: %v", err)
	}
	defer func() { _ = decoy.Process.Kill() }()
	time.Sleep(100 * time.Millisecond)

	if err := os.WriteFile(r.pidPath(), []byte(strconv.Itoa(decoy.Process.Pid)), 0644); err != nil {
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
	if _, err := os.Stat(r.pidPath()); !os.IsNotExist(err) {
		t.Errorf("残留 pid 文件应被清理，stat 结果: %v", err)
	}
}
