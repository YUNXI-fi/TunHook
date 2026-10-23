package lolia

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"tunhook/procutil"

	"go.uber.org/zap"
)

// Runner LoliaFrp 独立 frpc 进程管理器。
// 刻意不复用 frpc.Manager：LoliaFrp 隧道由服务端生成整份配置，与「内网穿透」页的
// 自建 frps 服务器互不干扰，使用独立的配置/日志/PID 目录（<dataDir>/lolia）。
type Runner struct {
	dir    string // 工作目录：frpc.toml / frpc.pid / frpc.log
	bin    string // frpc 二进制路径（复用 frpc.Manager 安装的内核；用于校验 pid 归属）
	logger *zap.Logger

	mu  sync.Mutex
	cmd *exec.Cmd
}

// NewRunner 创建 Runner；dir 通常为 <dataDir>/lolia，bin 为 frpc 二进制路径。
func NewRunner(dir, bin string, logger *zap.Logger) *Runner {
	return &Runner{dir: dir, bin: bin, logger: logger}
}

// configPath 当前 frpc 配置路径。
func (r *Runner) configPath() string { return filepath.Join(r.dir, "frpc.toml") }

// proxyNameRe 匹配 frpc.toml 中 [[proxies]] 段的 name 字段（行首 `name = 'x'` 或 `name = "x"`）。
var proxyNameRe = regexp.MustCompile(`(?m)^name\s*=\s*['"]([^'"]+)['"]`)

// ProxyNames 读取当前 frpc 配置中包含的代理名集合（即本地进程实际加载的隧道）。
// 配置不存在（从未启动）时返回 nil。
func (r *Runner) ProxyNames() map[string]bool {
	b, err := os.ReadFile(r.configPath())
	if err != nil {
		return nil
	}
	names := map[string]bool{}
	for _, m := range proxyNameRe.FindAllSubmatch(b, -1) {
		names[string(m[1])] = true
	}
	return names
}
func (r *Runner) pidPath() string { return filepath.Join(r.dir, "frpc.pid") }
func (r *Runner) logPath() string { return filepath.Join(r.dir, "frpc.log") }

// PID 当前记录的 frpc 进程 PID（不活跃返回 0）。
func (r *Runner) PID() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil && r.cmd.Process != nil {
		return r.cmd.Process.Pid
	}
	return r.livePID()
}

// filePID 读取 pid 文件中的原始值（不做存活校验，供清理与比对用）。
func (r *Runner) filePID() int { return procutil.PIDFromFile(r.pidPath()) }

// livePID 读取 pid 文件并确认「进程存活且确实是本程序」（不存在、已退出或被复用均返回 0）。
// 身份校验用的是 frpc 二进制路径：pid 文件残留且 PID 被无关进程复用时，
// 若不校验会把无关进程误判成 frpc（状态误报「运行中」，Stop 还会误杀它）。
func (r *Runner) livePID() int {
	pid := r.filePID()
	if !procutil.AliveAs(pid, r.bin) {
		return 0
	}
	return pid
}

// Running frpc 进程是否在运行。
func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil && r.cmd.Process != nil {
		return true
	}
	return r.livePID() > 0
}

// Start 写入配置并启动 frpc 进程（已在运行则返回错误，需先 Stop）。
// bin 为 frpc 二进制路径（复用 frpc.Manager 安装的二进制）。
func (r *Runner) Start(bin, tomlContent string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil && r.cmd.Process != nil {
		return errors.New("LoliaFrp 隧道已在运行中，请先停止")
	}
	if r.livePID() > 0 {
		return errors.New("LoliaFrp 隧道已在运行中，请先停止")
	}
	if _, err := os.Stat(bin); err != nil {
		return errors.New("frpc 未安装，请先在「内网穿透」页安装 frpc")
	}
	// 以本次实际启动的内核为准记录路径（pid 身份校验用），避免与构造时的路径不一致
	r.bin = bin
	if err := os.MkdirAll(r.dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	cfgPath := r.configPath()
	if err := os.WriteFile(cfgPath, []byte(tomlContent), 0644); err != nil {
		return fmt.Errorf("写入隧道配置失败: %w", err)
	}
	logF, err := os.OpenFile(r.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %w", err)
	}
	cmd := exec.Command(bin, "-c", cfgPath)
	cmd.Stdout = logF
	cmd.Stderr = logF
	// 独立进程组 + 父进程退出时自动终止，避免残留（与 frpc.Manager / mefrp.Runner 一致）
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		logF.Close()
		return fmt.Errorf("启动 frpc 失败: %w", err)
	}
	r.cmd = cmd
	_ = os.WriteFile(r.pidPath(), []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644)
	if r.logger != nil {
		r.logger.Info("LoliaFrp frpc 已启动", zap.Int("pid", cmd.Process.Pid))
	}
	go func(c *exec.Cmd, f *os.File) {
		_ = c.Wait()
		f.Close()
		r.mu.Lock()
		if r.cmd == c {
			r.cmd = nil
		}
		r.mu.Unlock()
		// 用文件中的原始 PID 比对（不能用存活校验后的值：进程已退出时它返回 0，
		// 会导致 pid 文件残留，残留 PID 被系统复用还会误判为「运行中」）
		if p := r.filePID(); p == c.Process.Pid {
			_ = os.Remove(r.pidPath())
		}
	}(cmd, logF)
	return nil
}

// Stop 停止 frpc 进程（未运行返回 nil）。
func (r *Runner) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	if r.cmd != nil && r.cmd.Process != nil {
		if err := r.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			_ = r.cmd.Process.Kill()
		}
		r.cmd = nil
	}
	// 兜底：按 pid 文件清理（覆盖父进程重启后残留的进程与 pid 文件）。
	// 只用 AliveAs 判断是否发信号：pid 文件残留时该 PID 可能已被无关进程复用，
	// 此时绝不能对它发信号（只会清理本程序的 pid 文件）。
	if pid := r.filePID(); pid > 0 {
		if procutil.AliveAs(pid, r.bin) {
			if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
				if err2 := syscall.Kill(pid, syscall.SIGKILL); err2 != nil {
					firstErr = err
				}
			}
		}
		_ = os.Remove(r.pidPath())
	}
	if r.logger != nil && firstErr == nil {
		r.logger.Info("LoliaFrp frpc 已停止")
	}
	return firstErr
}

// LogTail 读取 frpc 日志末尾 n 行。
func (r *Runner) LogTail(n int) string {
	b, err := os.ReadFile(r.logPath())
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if n <= 0 || n > len(lines) {
		n = len(lines)
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
