package cloudflared

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"tunhook/procutil"

	"go.uber.org/zap"
)

const (
	// metricsPortBase 本地健康检测（--metrics）端口起始值：
	// frpc 管理 API 占用 7400-7450，此处从 7451 起探测空闲端口。
	// 多实例下每条隧道各占一个（freePort 逐个探测空闲），故预留 50 个槽位。
	metricsPortBase = 7451
	metricsPortMax  = 7501
	readyTimeout    = 1500 * time.Millisecond
	// logMaxBytes 日志文件体积上限，超过则在启动前滚动为 .1（避免长期运行无限增长）。
	logMaxBytes = 5 << 20
	// quickURLTimeout / quickURLPoll 临时域名出现的时间上限与轮询间隔：
	// quick tunnel 注册成功后会在日志里打印 trycloudflare 地址，实测数秒内出现。
	quickURLTimeout = 45 * time.Second
	quickURLPoll    = 500 * time.Millisecond
)

// quickURLRe quick tunnel 下发的临时域名（形如 https://xxx-yyy-zzz.trycloudflare.com）。
var quickURLRe = regexp.MustCompile(`https://[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com`)

// 进程内 metrics 端口登记表：多实例共享（同一进程内所有 Runner 都从这里分配）。
var (
	portMu    sync.Mutex
	portTaken = map[int]bool{}
)

// Runner cloudflared 独立进程管理器（每条隧道实例一个）。
// 刻意不复用 frpc.Manager：cloudflared 既非 frp 生态、也不生成/解析 frpc 配置，
// 且要求不出现在「内网穿透」页面的服务器列表中，因此使用独立的启动参数、日志与 PID 目录。
//
// 多实例：每条实例有自己的工作目录（日志 / PID 文件）与内核进程，互不影响；
// 内核二进制本身是全局共用的一份（bin）。
//
// 隧道 Token 通过环境变量 TUNNEL_TOKEN 传入而非命令行参数：避免 Token 出现在 ps 进程列表与命令行日志中。
// 连接协议默认 http2（实测大陆链路 TCP/7844 的小请求延迟与吞吐均明显优于 quic/UDP/7844）。
type Runner struct {
	dir    string // 本实例的工作目录：cloudflared.log / cloudflared.pid
	bin    string // 内核二进制路径（全局共用，用于进程身份校验）
	logger *zap.Logger

	mu          sync.Mutex
	cmd         *exec.Cmd
	metricsPort int    // 本次运行的健康检测端口（0=未运行）
	quickURL    string // 本次运行解析到的临时域名（仅 quick tunnel 模式，未取得时为空）
	gate        *Gate  // 临时入口的本地转发闸门（仅 quick 模式，随进程同生命周期）
}

// NewRunner 创建 Runner；dir 为该实例的工作目录（如 <dataDir>/cloudflared/instances/<id>），
// bin 为全局共用的内核二进制路径。
func NewRunner(dir, bin string, logger *zap.Logger) *Runner {
	return &Runner{dir: dir, bin: bin, logger: logger}
}

// Dir 本实例的工作目录（日志与 PID 文件所在处；删除实例时整目录清理）。
func (r *Runner) Dir() string { return r.dir }

func (r *Runner) logPath() string { return filepath.Join(r.dir, LogFile) }
func (r *Runner) pidPath() string { return filepath.Join(r.dir, PidFile) }

// binPath 连接器内核路径：读取 pid 文件判断运行状态时用它做身份校验，
// 避免 pid 文件残留且 PID 被无关进程复用时误判为「运行中」。
func (r *Runner) binPath() string { return r.bin }

// filePID 读取 pid 文件中的原始值（不做存活校验，供清理与比对用）。
func (r *Runner) filePID() int { return procutil.PIDFromFile(r.pidPath()) }

// livePID 读取 pid 文件并确认「进程存活且确实是本程序」（不存在、已退出或被复用均返回 0）。
func (r *Runner) livePID() int {
	pid := r.filePID()
	if !procutil.AliveAs(pid, r.binPath()) {
		return 0
	}
	return pid
}

// PID 当前内核进程 PID（不活跃返回 0）。
func (r *Runner) PID() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil && r.cmd.Process != nil {
		return r.cmd.Process.Pid
	}
	return r.livePID()
}

// Running 内核进程是否在运行。
func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil && r.cmd.Process != nil {
		return true
	}
	return r.livePID() > 0
}

// MetricsPort 本次运行的本地健康检测端口（未运行返回 0）。
func (r *Runner) MetricsPort() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil || r.cmd.Process == nil {
		return 0
	}
	return r.metricsPort
}

// Ready 通过本地 metrics 端口的 /ready 判断连接器是否已连上 Cloudflare 边缘。
// 进程未运行或探测失败均返回 false（该探测只用于展示，不参与启停决策）。
func (r *Runner) Ready() bool {
	port := r.MetricsPort()
	if port == 0 {
		return false
	}
	client := &http.Client{Timeout: readyTimeout}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/ready", port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// QuickURL 本次运行解析到的临时域名（非 quick 模式或尚未取得时为空）。
func (r *Runner) QuickURL() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil || r.cmd.Process == nil {
		return ""
	}
	return r.quickURL
}

// Start 启动 cloudflared 连接器（命名为隧道 + Token 托管，已在运行则返回错误，需先 Stop）。
// bin 为内核路径，token 为隧道 Token，protocol 取 http2/quic/auto（空值回落 http2）。
func (r *Runner) Start(bin, token, protocol string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("隧道 Token 不能为空，请先保存 Token")
	}
	return r.spawn(bin, protocol, []string{"run"}, []string{"TUNNEL_TOKEN=" + token}, false)
}

// StartQuick 启动 cloudflared 临时入口（匿名 quick tunnel，免账号免 Token）。
// target 为本地目标地址（如 http://127.0.0.1:5666），临时域名由 Cloudflare 每次启动随机下发。
//
// 回源不直连 target，而是先经过本地闸门（详见 Gate）：这样「暂停」只需切换闸门状态，
// 隧道进程与临时域名都保持不动，而停止再启动会换域名。
func (r *Runner) StartQuick(bin, target, protocol string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return errors.New("临时入口的本地目标地址不能为空，请先保存目标地址")
	}
	gate := NewGate(target, r.logger)
	gateURL, err := gate.Start()
	if err != nil {
		return fmt.Errorf("启动本地转发闸门失败: %w", err)
	}
	r.mu.Lock()
	if r.gate != nil {
		r.mu.Unlock()
		gate.Stop()
		return errors.New("Cloudflare 隧道已在运行中，请先停止")
	}
	r.gate = gate
	r.mu.Unlock()

	if err := r.spawn(bin, protocol, []string{"--url", gateURL}, nil, true); err != nil {
		r.stopGate() // 进程没起来，闸门不能留
		return err
	}
	return nil
}

// GateAddr 闸门监听地址（非临时入口或未运行时为空）。
func (r *Runner) GateAddr() string {
	r.mu.Lock()
	g := r.gate
	r.mu.Unlock()
	if g == nil {
		return ""
	}
	return g.Addr()
}

// GateCounters 闸门累计上行/下行字节与活跃请求数（无闸门时全 0）。
func (r *Runner) GateCounters() (tx, rx, active int64) {
	r.mu.Lock()
	g := r.gate
	r.mu.Unlock()
	if g == nil {
		return 0, 0, 0
	}
	return g.Counters()
}

// SetTarget 就地切换转发闸门的回源目标，返回是否已生效。
// 生效返回 true 表示无需重启内核（重启会换掉临时入口的访问地址）；
// 没有闸门（非 quick 模式、未运行）时返回 false，由调用方决定后续处理。
func (r *Runner) SetTarget(target string) bool {
	r.mu.Lock()
	g := r.gate
	r.mu.Unlock()
	if g == nil {
		return false
	}
	if err := g.SetTarget(target); err != nil {
		if r.logger != nil {
			r.logger.Warn("本地转发闸门切换回源失败", zap.String("target", target), zap.Error(err))
		}
		return false
	}
	return true
}

// SetPaused 切换暂停状态（仅临时入口有闸门；其余模式没有闸门，为空操作）。
func (r *Runner) SetPaused(v bool) {
	r.mu.Lock()
	g := r.gate
	r.mu.Unlock()
	if g != nil {
		g.SetPaused(v)
	}
}

// Paused 当前是否处于暂停（没有闸门时恒为 false）。
func (r *Runner) Paused() bool {
	r.mu.Lock()
	g := r.gate
	r.mu.Unlock()
	return g != nil && g.Paused()
}

// stopGate 关闭当前闸门（无闸门时为空操作，可重复调用）。
func (r *Runner) stopGate() {
	r.mu.Lock()
	g := r.gate
	r.gate = nil
	r.mu.Unlock()
	if g != nil {
		g.Stop()
	}
}

// spawn 组装并拉起 cloudflared 进程（各模式共用：固定参数 + tunnelArgs 差异部分）。
func (r *Runner) spawn(bin, protocol string, tunnelArgs, extraEnv []string, quick bool) error {
	protocol = NormalizeProtocol(protocol)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil && r.cmd.Process != nil {
		return errors.New("Cloudflare 隧道已在运行中，请先停止")
	}
	if r.livePID() > 0 {
		return errors.New("Cloudflare 隧道已在运行中，请先停止")
	}
	if _, err := os.Stat(bin); err != nil {
		return errors.New("cloudflared 内核未安装，请先下载内核或上传离线包")
	}
	if err := os.MkdirAll(r.dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	port, err := freePort()
	if err != nil {
		return err
	}
	r.rotateLogIfLarge()
	// quick 模式的临时域名要从日志里解析，先记下本次启动前的日志长度：
	// 日志是追加写入的，否则会把上一次运行残留的 trycloudflare 地址当成本次地址。
	offset := int64(0)
	if st, err := os.Stat(r.logPath()); err == nil {
		offset = st.Size()
	}

	logF, err := os.OpenFile(r.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		releasePort(port)
		return fmt.Errorf("打开日志文件失败: %w", err)
	}
	// 不传 --logfile：日志统一由 stdout/stderr 重定向落盘，保持人类可读格式（与 frpc/MEFrp 一致），
	// 同时保证 Token 无效等启动期报错也能进日志。
	args := append([]string{
		"tunnel",
		"--no-autoupdate", // 内核由本程序管理，禁止 cloudflared 自更新
		"--protocol", protocol,
		"--metrics", fmt.Sprintf("127.0.0.1:%d", port),
		"--loglevel", "info",
	}, tunnelArgs...)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdout = logF
	cmd.Stderr = logF
	// 独立进程组 + 父进程退出时自动终止，避免残留（与 frpc.Manager / mefrp.Runner 一致）
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		logF.Close()
		releasePort(port)
		return fmt.Errorf("启动 cloudflared 失败: %w", err)
	}
	r.cmd = cmd
	r.metricsPort = port
	r.quickURL = ""
	_ = os.WriteFile(r.pidPath(), []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644)
	if r.logger != nil {
		r.logger.Info("cloudflared 已启动",
			zap.Int("pid", cmd.Process.Pid), zap.String("protocol", protocol),
			zap.Bool("quick", quick), zap.Int("metricsPort", port))
	}
	if quick {
		go r.watchQuickURL(cmd, offset)
	}
	go func(c *exec.Cmd, f *os.File, port int) {
		_ = c.Wait()
		f.Close()
		// 进程退出即释放端口：按本次运行的端口释放，与 r.cmd 是否已被 Stop 置空无关
		releasePort(port)
		r.mu.Lock()
		if r.cmd == c {
			r.cmd = nil
			r.metricsPort = 0
			r.quickURL = ""
		}
		r.mu.Unlock()
		// 用文件中的原始 PID 比对（不能用 readPID：进程已退出时它返回 0，会导致 pid 文件残留，
		// 残留 PID 若被系统复用还会误判为“运行中”）
		if p := r.filePID(); p == c.Process.Pid {
			_ = os.Remove(r.pidPath())
		}
	}(cmd, logF, port)
	return nil
}

// watchQuickURL 从内核日志中解析本次 quick tunnel 的临时域名（进程退出或超时即停止等待）。
func (r *Runner) watchQuickURL(c *exec.Cmd, offset int64) {
	deadline := time.Now().Add(quickURLTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(quickURLPoll)
		r.mu.Lock()
		alive := r.cmd == c
		r.mu.Unlock()
		if !alive {
			return
		}
		url := findQuickURL(r.logPath(), offset)
		if url == "" {
			continue
		}
		r.mu.Lock()
		if r.cmd == c {
			r.quickURL = url
		}
		r.mu.Unlock()
		if r.logger != nil {
			r.logger.Info("cloudflared 临时入口已就绪", zap.String("url", url))
		}
		return
	}
}

// findQuickURL 在日志文件 offset 之后的内容中查找临时域名（找不到返回空串）。
func findQuickURL(path string, offset int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return ""
		}
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return ""
	}
	return quickURLRe.FindString(string(b))
}

// Stop 停止内核进程（未运行返回 nil）。
func (r *Runner) Stop() error {
	// 闸门与内核进程同生命周期：先关掉本地入口，再停进程
	r.stopGate()
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	if r.cmd != nil && r.cmd.Process != nil {
		if err := r.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			_ = r.cmd.Process.Kill()
		}
		r.cmd = nil
		r.metricsPort = 0
		r.quickURL = ""
	}
	// 兜底：按 pid 文件清理（覆盖父进程重启后残留的进程与 pid 文件）。
	// 只用 AliveAs 判断是否发信号：pid 文件残留时该 PID 可能已被无关进程复用，
	// 此时绝不能对它发信号（只会清理本程序的 pid 文件）。
	if pid := r.filePID(); pid > 0 {
		if procutil.AliveAs(pid, r.binPath()) {
			if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
				if err2 := syscall.Kill(pid, syscall.SIGKILL); err2 != nil {
					firstErr = err
				}
			}
		}
		_ = os.Remove(r.pidPath())
	}
	if r.logger != nil && firstErr == nil {
		r.logger.Info("cloudflared 已停止")
	}
	return firstErr
}

// LogTail 读取内核日志末尾 n 行。
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

// rotateLogIfLarge 日志滚动：超过上限时把当前日志改名保留一份（.1），避免长期运行无限增长。
func (r *Runner) rotateLogIfLarge() {
	st, err := os.Stat(r.logPath())
	if err != nil || st.Size() < logMaxBytes {
		return
	}
	_ = os.Rename(r.logPath(), r.logPath()+".1")
}

// freePort 在 metricsPortBase..metricsPortMax 内探测一个空闲的本地回环端口。
//
// 只用「监听再关闭」探测是不够的：探测与实际使用（cloudflared 绑定）之间存在时间窗口，
// 同一进程内先后启动多条实例时会双双探到同一个端口，后启动的那条因绑定失败而反复重启。
// 因此探测到后立即在进程内登记，直到该进程退出才释放，保证同进程内的分配互不重复。
func freePort() (int, error) {
	portMu.Lock()
	defer portMu.Unlock()
	for p := metricsPortBase; p < metricsPortMax; p++ {
		if portTaken[p] {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
		ln.Close()
		portTaken[p] = true
		return p, nil
	}
	return 0, fmt.Errorf("本地 %d-%d 端口均被占用，无法启动健康检测", metricsPortBase, metricsPortMax-1)
}

// releasePort 释放进程内登记的端口（内核进程退出或启动失败时调用）。
func releasePort(p int) {
	if p <= 0 {
		return
	}
	portMu.Lock()
	delete(portTaken, p)
	portMu.Unlock()
}
