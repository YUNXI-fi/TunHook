// Package cloudflared 提供 Cloudflare Tunnel 客户端（cloudflared）的集成管理：
// 内核按需下载/离线包安装，以及隧道 Token 托管运行（启动/停止/日志/健康检测）。
//
// 与 MEFrp 集成的差异（刻意为之）：
//   - 隧道与 Public Hostname 路由由 Cloudflare Zero Trust 后台配置（config_src=cloudflare），
//     本地只需用隧道 Token 建立出站连接，因此没有“拉取配置写入本地”这一步；
//   - cloudflared 是单文件二进制（非 tar.gz 压缩包）且体积约 40MB，故按需下载而非内置到安装包。
//
// 运行数据统一存放在 dataDir/cloudflared/（二进制、版本、pid、日志、离线包留档）。
package cloudflared

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// BinName 内核文件名。
	BinName = "cloudflared"
	// LogFile 内核运行日志（stdout/stderr 重定向写入）。
	LogFile = "cloudflared.log"
	// PidFile 运行中的内核 PID。
	PidFile = "cloudflared.pid"
	// VersionFile 已安装内核版本缓存。
	VersionFile = "version"
	// PackagesDir 离线包留档目录（下载的内核在此留档，便于离线重装）。
	PackagesDir = "packages"
	// ArchiveName 官方 Linux amd64 单文件内核的留档名。
	ArchiveName = "cloudflared-linux-amd64"

	// DownloadURL 官方最新版 linux/amd64 内核下载地址（实测 2026.9.1 约 39.8MB）。
	DownloadURL = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
	// downloadTimeout 内核下载超时（实测国内 1.9MB/s 约 27s，留足余量）。
	downloadTimeout = 10 * time.Minute
	// minBinarySize 内核体积下限：防止把错误页/空文件当成内核安装。
	minBinarySize = 8 << 20
	// mirrorProbeTimeout 单个下载源的测速超时：超时的源直接淘汰，不参与排序。
	mirrorProbeTimeout = 6 * time.Second
	// 测速采样按「时间窗」而不是「固定字节数」：
	// 固定取 64KB 时，这个量恰好落在 HTTP/2 初始流控窗口 + TLS 接收缓冲 + CDN 边缘缓存里，
	// 数据早已在内存中，测出来的是内存搬运速度（实测出现 1088.5MB/s 这种荒谬值）。
	// 改成限定时间窗后，首段 burst 在总量里权重很低，测到的才是真实吞吐。
	mirrorProbeWindow  = 500 * time.Millisecond
	mirrorProbeCeiling = 1 << 20
	// mirrorProbeMinBytes 采样下限：连上却几乎不给数据的源按不可用处理。
	mirrorProbeMinBytes = 8 << 10
	// latestVersionTTL 最新版号缓存时长：版本探测要走外网，不能每次状态轮询都打。
	latestVersionTTL = 30 * time.Minute
	// latestVersionTimeout 单个源解析最新版号的超时。
	// 取 3s 而非更长：解析要逐个源回退，单源超时 × 源数量就是按钮状态的最长延迟。
	latestVersionTimeout = 3 * time.Second
)

// downloadMirror 一个 GitHub 加速下载源。国内镜像均为「URL 前缀代理」形式，
// 把原始 GitHub 链接原样拼在其后即可，故这里只登记域名前缀。
type downloadMirror struct {
	name string
	url  string
}

// downloadMirrors 内核实测下载源候选表：官方 + 国内公益加速镜像。
//
// 为什么每次都测速而不是固定用某一个：这类公益代理域名会不定期失效或变慢，
// 写死单个源迟早会下载失败。候选表只负责登记，实际用哪个由 probeMirrors 实测决定。
// 表内均为公网公开代理，只用于拉取公开发布的内核文件，不涉及任何凭据。
var downloadMirrors = []downloadMirror{
	{"官方 GitHub", DownloadURL},
	{"gh.catmak.name", "https://gh.catmak.name/" + DownloadURL},
	{"fastgit.cc", "https://fastgit.cc/" + DownloadURL},
	{"gh-proxy.com", "https://gh-proxy.com/" + DownloadURL},
	{"gh.dpik.top", "https://gh.dpik.top/" + DownloadURL},
	{"gh.acmsz.top", "https://gh.acmsz.top/" + DownloadURL},
	{"ghfast.top", "https://ghfast.top/" + DownloadURL},
	{"gh.idayer.com", "https://gh.idayer.com/" + DownloadURL},
	{"ghproxy.net", "https://ghproxy.net/" + DownloadURL},
}

// elfMagic Linux 可执行文件头：用来识别「代理返回的其实是错误页」。
var elfMagic = []byte{0x7F, 'E', 'L', 'F'}

// pickedMirror 测速通过的下载源（speed 为采样吞吐，仅用于排序与展示）。
type pickedMirror struct {
	mirror downloadMirror
	speed  float64 // 采样吞吐（字节/秒）
}

// label 下载源展示名（形如「gh-proxy.com · 3.2MB/s」）。
func (p pickedMirror) label() string {
	if p.speed <= 0 {
		return p.mirror.name
	}
	return p.mirror.name + " · " + fmtRate(p.speed)
}

// fmtRate 吞吐展示（≥1MB/s 用 MB/s，否则用 KB/s）。
func fmtRate(bps float64) string {
	if bps >= 1<<20 {
		return fmt.Sprintf("%.1fMB/s", bps/float64(1<<20))
	}
	return fmt.Sprintf("%.0fKB/s", bps/float64(1<<10))
}

// probeMirror 探测单个下载源：在时间窗内尽量取数据，返回采样吞吐（字节/秒）。
//
// 为什么按吞吐而不是首字节延迟排序：延迟只说明「连得上」，而实际要下 40MB。
// 实测过延迟最快却只有 ~24KB/s 的源（下完要 25 分钟），按延迟选它反而最慢。
// 采样同时兼作可用性校验：内容不是 ELF（代理返回错误页/限流页）、或连上却几乎不给数据，都判为不可用。
func probeMirror(ctx context.Context, client *http.Client, url string) (float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	// 只取采样上限内的数据：既不白拉 40MB，也顺带验证服务端支持范围请求
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", mirrorProbeCeiling-1))
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// 先校验文件头，再从此刻起计时：测的是持续传输速度，不含建连与首字节延迟
	head := make([]byte, len(elfMagic))
	if _, err := io.ReadFull(resp.Body, head); err != nil {
		return 0, err
	}
	if !bytes.Equal(head, elfMagic) {
		return 0, errors.New("返回的内容不是 Linux 可执行文件")
	}
	start := time.Now()
	deadline := start.Add(mirrorProbeWindow)
	n := 0
	buf := make([]byte, 32<<10)
	for n < mirrorProbeCeiling && time.Now().Before(deadline) {
		read, err := resp.Body.Read(buf)
		n += read
		if err != nil {
			// EOF 是采样结束的正常路径；其余错误按「采到多少算多少」处理，
			// 由下面的采样下限决定它是否可用，避免个别源的边界行为误判
			break
		}
	}
	elapsed := time.Since(start)
	if n < mirrorProbeMinBytes {
		return 0, fmt.Errorf("采样 %d 字节即中断，速度过慢", n)
	}
	if elapsed <= 0 {
		elapsed = time.Millisecond
	}
	return float64(n) / elapsed.Seconds(), nil
}

// probeMirrors 并发测速全部下载源，按吞吐从高到低返回可用源。
// 全部不可用时回落到官方源——测速失败可能只是探测请求被拦，下载仍值得一试。
func (m *Manager) probeMirrors() []pickedMirror {
	m.setStage(0, 0, "正在测速下载源…")
	ctx, cancel := context.WithTimeout(context.Background(), mirrorProbeTimeout)
	defer cancel()
	client := &http.Client{Timeout: mirrorProbeTimeout}

	probed := make([]pickedMirror, len(downloadMirrors))
	errs := make([]error, len(downloadMirrors))
	var wg sync.WaitGroup
	for i, mir := range downloadMirrors {
		wg.Add(1)
		go func(i int, mir downloadMirror) {
			defer wg.Done()
			speed, err := probeMirror(ctx, client, mir.url)
			probed[i] = pickedMirror{mirror: mir, speed: speed}
			errs[i] = err
		}(i, mir)
	}
	wg.Wait()

	ok := make([]pickedMirror, 0, len(probed))
	for i, p := range probed {
		if errs[i] != nil {
			if m.logger != nil {
				m.logger.Info("下载源不可用，已跳过",
					zap.String("mirror", p.mirror.name), zap.String("error", errs[i].Error()))
			}
			continue
		}
		if m.logger != nil {
			m.logger.Info("下载源测速完成",
				zap.String("mirror", p.mirror.name), zap.String("speed", fmtRate(p.speed)))
		}
		ok = append(ok, p)
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i].speed > ok[j].speed })
	if len(ok) == 0 {
		return []pickedMirror{{mirror: downloadMirror{name: "官方 GitHub", url: DownloadURL}}}
	}
	return ok
}

// 支持的连接协议（VALUE 直接透传给 cloudflared --protocol）。
const (
	// ProtocolHTTP2 走 TCP/7844（默认；实测大陆链路小请求延迟与吞吐均优于 quic）。
	ProtocolHTTP2 = "http2"
	// ProtocolQUIC 走 UDP/7844。
	ProtocolQUIC = "quic"
	// ProtocolAuto 由 cloudflared 自行协商。
	ProtocolAuto = "auto"
)

// NormalizeProtocol 归一化协议取值，非白名单值一律回落 http2。
func NormalizeProtocol(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case ProtocolQUIC:
		return ProtocolQUIC
	case ProtocolAuto:
		return ProtocolAuto
	default:
		return ProtocolHTTP2
	}
}

// Progress 内核下载/安装实时进度（仅下载过程中非空）。
type Progress struct {
	Done    int64  `json:"done"`
	Total   int64  `json:"total"`
	Percent int    `json:"percent"`
	Stage   string `json:"stage"`
}

// Manager 管理 cloudflared 内核的下载、离线安装与版本探测。
// 刻意不管进程生命周期（进程由 Runner 负责）：内核替换走“临时文件 + 原子 rename”，
// 运行中的进程持有旧 inode 不受影响，因此安装内核无需先停隧道。
type Manager struct {
	dir    string
	logger *zap.Logger

	mu       sync.Mutex
	busy     bool // 是否正在下载/安装
	progress *Progress
	lastErr  string

	// 最新版号缓存（可能为空 = 尚未探测到）
	latestVer  string
	latestAt   time.Time
	latestBusy bool
}

// NewManager 创建 Manager；dir 通常为 <dataDir>/cloudflared。
func NewManager(dir string, logger *zap.Logger) *Manager {
	return &Manager{dir: dir, logger: logger}
}

// Dir 运行数据目录。
func (m *Manager) Dir() string { return m.dir }

// BinPath 内核二进制路径。
func (m *Manager) BinPath() string { return filepath.Join(m.dir, BinName) }

// PackagesPath 离线包留档路径。
func (m *Manager) PackagesPath() string { return filepath.Join(m.dir, PackagesDir, ArchiveName) }

// Installed 内核是否已安装（存在且体积合理）。
func (m *Manager) Installed() bool {
	st, err := os.Stat(m.BinPath())
	return err == nil && st.Mode().IsRegular() && st.Size() >= minBinarySize
}

// Version 已安装内核版本；未安装返回空串。
// 优先读版本缓存文件，缓存缺失时执行 --version 探测并落盘。
func (m *Manager) Version() string {
	if !m.Installed() {
		return ""
	}
	if b, err := os.ReadFile(filepath.Join(m.dir, VersionFile)); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v
		}
	}
	v, err := binVersionOf(m.BinPath())
	if err != nil {
		return ""
	}
	_ = os.WriteFile(filepath.Join(m.dir, VersionFile), []byte(v), 0644)
	return v
}

// Latest 官方最新版版本号（尚未探测到或探测失败时返回空串）。
//
// 只读缓存、绝不阻塞调用方：状态接口会被前端每几秒轮询一次，一旦在这里同步打网络就会拖慢整个页面。
// 缓存过期或为空时顺带触发一次后台刷新，结果由后续轮询自然拿到。
func (m *Manager) Latest() string {
	m.mu.Lock()
	ver := m.latestVer
	stale := time.Since(m.latestAt) > latestVersionTTL
	trigger := (ver == "" || stale) && !m.latestBusy
	if trigger {
		m.latestBusy = true
	}
	m.mu.Unlock()
	if trigger {
		go m.refreshLatest()
	}
	return ver
}

// refreshLatest 解析官方最新版版本号。
//
// 不用 GitHub API（免限流、免 Token），而是利用下载地址的第一次重定向：
// releases/latest/download/<file> 会 302 到 releases/download/<tag>/<file>，取其中 tag 即最新版。
// 必须禁止自动跟随重定向——后续还会再跳到带签名的对象存储域名，那里已看不出标签。
func (m *Manager) refreshLatest() {
	defer func() {
		m.mu.Lock()
		m.latestBusy = false
		m.mu.Unlock()
	}()
	client := &http.Client{
		Timeout:       latestVersionTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, mir := range downloadMirrors {
		req, err := http.NewRequest(http.MethodGet, mir.url, nil)
		if err != nil {
			continue
		}
		// 只要响应头，不读正文
		req.Header.Set("Range", "bytes=0-0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		// 优先看 Location；代理直接透传不重定向时退回看最终请求地址
		tag := releaseTag(strings.TrimSpace(resp.Header.Get("Location")))
		if tag == "" {
			tag = releaseTag(resp.Request.URL.Path)
		}
		resp.Body.Close()
		if tag == "" {
			continue
		}
		m.mu.Lock()
		m.latestVer = tag
		m.latestAt = time.Now()
		m.mu.Unlock()
		if m.logger != nil {
			m.logger.Info("cloudflared 最新版已确认", zap.String("version", tag), zap.String("mirror", mir.name))
		}
		return
	}
	// 全部失败也记录时间：TTL 内不反复重试，避免每次状态轮询都打一遍网络
	m.mu.Lock()
	m.latestAt = time.Now()
	m.mu.Unlock()
	if m.logger != nil {
		m.logger.Warn("未能解析 cloudflared 最新版号，本次跳过（稍后重试）")
	}
}

// releaseTag 从 releases 下载地址中取出标签
// （形如 /releases/download/2026.9.1/cloudflared-linux-amd64 或镜像代理前缀后的同构路径）。
func releaseTag(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "releases" && parts[i+1] == "download" {
			return parts[i+2]
		}
	}
	return ""
}

// State 当前下载/安装状态：progress（busy 时有效）、busy、最近一次错误。
func (m *Manager) State() (Progress, bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := Progress{}
	if m.progress != nil {
		p = *m.progress
	}
	return p, m.busy, m.lastErr
}

// Download 下载最新版内核并安装（留档为离线包）。
//
// 流程：先并发测速全部候选源 → 从延迟最低的源开始下载 → 失败则回退到次快的源。
// 这样既拿到最快链路，又不会因为某个公益镜像临时抽风而整个下载失败。
func (m *Manager) Download() error {
	if err := m.begin(); err != nil {
		return err
	}
	defer m.end()

	candidates := m.probeMirrors()
	var lastErr error
	for _, p := range candidates {
		err := m.downloadFrom(p)
		if err == nil {
			return nil
		}
		lastErr = err
		if m.logger != nil {
			m.logger.Warn("下载源失败，回退到下一个源",
				zap.String("mirror", p.mirror.name), zap.Error(err))
		}
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的下载源")
	}
	return m.fail("下载内核失败: " + lastErr.Error())
}

// downloadFrom 从指定源下载内核并安装，成功后留档为离线包（供离线重装/升级）。
func (m *Manager) downloadFrom(p pickedMirror) error {
	stage := "正在下载内核（" + p.label() + "）…"
	m.setStage(0, 0, "正在连接"+p.mirror.name+"…")
	client := &http.Client{Timeout: downloadTimeout}
	resp, err := client.Get(p.mirror.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s 返回 HTTP %d", p.mirror.name, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Join(m.dir, PackagesDir), 0755); err != nil {
		return err
	}
	part := filepath.Join(m.dir, PackagesDir, "."+BinName+".part")
	f, err := os.Create(part)
	if err != nil {
		return errors.New("创建临时文件失败: " + err.Error())
	}
	n, err := io.Copy(f, &progressReader{r: resp.Body, m: m, total: resp.ContentLength, stage: stage})
	if err != nil {
		f.Close()
		os.Remove(part)
		return err
	}
	// 服务端提前断开时 io.Copy 可能返回 nil，需按 Content-Length 校验完整性
	if resp.ContentLength > 0 && n != resp.ContentLength {
		f.Close()
		os.Remove(part)
		return fmt.Errorf("下载不完整: 已获取 %d / %d 字节", n, resp.ContentLength)
	}
	f.Close()

	m.setStage(n, n, "正在安装内核…")
	ver, err := m.installFromFile(part)
	if err != nil {
		os.Remove(part)
		return err
	}
	// 留档为离线包（供后续离线重装/离线升级）
	if err := os.Rename(part, m.PackagesPath()); err != nil {
		os.Remove(part)
	}
	if m.logger != nil {
		m.logger.Info("cloudflared 内核安装完成",
			zap.String("version", ver), zap.String("mirror", p.mirror.name))
	}
	return nil
}

// InstallFromFile 使用本地文件（用户上传的离线包）安装内核，返回安装后的版本。
func (m *Manager) InstallFromFile(src string) (string, error) {
	if err := m.begin(); err != nil {
		return "", err
	}
	defer m.end()
	m.setStage(0, 0, "正在校验内核文件…")
	ver, err := m.installFromFile(src)
	if err != nil {
		return "", m.fail(err.Error())
	}
	// 留档：上传的离线包复制到 packages 目录（下次可离线重装）
	if err := os.MkdirAll(filepath.Join(m.dir, PackagesDir), 0755); err == nil {
		if filepath.Clean(src) != filepath.Clean(m.PackagesPath()) {
			_ = copyFile(src, m.PackagesPath())
		}
	}
	if m.logger != nil {
		m.logger.Info("cloudflared 内核离线安装完成", zap.String("version", ver))
	}
	return ver, nil
}

// installFromFile 校验并安装内核：先写入 <bin>.tmp 并执行 --version 验证可执行，再原子替换。
// 原子替换保证运行中的旧进程不受影响（持有旧 inode），也避免半截文件损坏现有安装。
func (m *Manager) installFromFile(src string) (string, error) {
	st, err := os.Stat(src)
	if err != nil {
		return "", fmt.Errorf("读取内核文件失败: %w", err)
	}
	if st.Size() < minBinarySize {
		return "", fmt.Errorf("内核文件体积异常（%d 字节），可能下载不完整", st.Size())
	}
	if err := os.MkdirAll(m.dir, 0755); err != nil {
		return "", fmt.Errorf("创建目录失败: %w", err)
	}
	tmp := m.BinPath() + ".tmp"
	if err := copyFile(src, tmp); err != nil {
		return "", fmt.Errorf("写入内核失败: %w", err)
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("设置内核权限失败: %w", err)
	}
	ver, err := binVersionOf(tmp)
	if err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("内核不可执行（请上传官方 cloudflared-linux-amd64 单文件二进制）: %w", err)
	}
	if err := os.Rename(tmp, m.BinPath()); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("替换内核失败: %w", err)
	}
	if ver != "" {
		_ = os.WriteFile(filepath.Join(m.dir, VersionFile), []byte(ver), 0644)
	}
	return ver, nil
}

// begin 抢占安装任务（同一时刻只允许一个下载/安装）。
func (m *Manager) begin() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.busy {
		return errors.New("内核正在下载/安装中，请稍候")
	}
	m.busy = true
	m.lastErr = ""
	m.progress = &Progress{Stage: "准备中…"}
	return nil
}

// end 结束安装任务并清除进度。
func (m *Manager) end() {
	m.mu.Lock()
	m.busy = false
	m.progress = nil
	m.mu.Unlock()
}

// fail 记录失败原因并返回该错误。
func (m *Manager) fail(msg string) error {
	m.mu.Lock()
	m.lastErr = msg
	m.mu.Unlock()
	if m.logger != nil {
		m.logger.Warn("cloudflared 内核安装失败", zap.String("error", msg))
	}
	return errors.New(msg)
}

func (m *Manager) setStage(done, total int64, stage string) {
	m.mu.Lock()
	m.progress = &Progress{Done: done, Total: total, Percent: percentOf(done, total), Stage: stage}
	m.mu.Unlock()
}

// percentOf 计算百分比，总长未知时返回 -1（前端按不确定进度展示）。
func percentOf(done, total int64) int {
	if total <= 0 {
		return -1
	}
	p := int(done * 100 / total)
	if p > 100 {
		p = 100
	}
	return p
}

// progressReader 下载进度上报（每读取一块更新一次）。
type progressReader struct {
	r     io.Reader
	m     *Manager
	total int64
	done  int64
	stage string
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.done += int64(n)
		p.m.setStage(p.done, p.total, p.stage)
	}
	return n, err
}

// copyFile 复制文件（目标先截断，权限 0755 由调用方设置）。
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// binVersionOf 执行 <bin> --version 解析版本号（形如 `cloudflared version 2026.9.1 (built ...)`），
// 非 cloudflared 可执行文件一律视为校验失败。
func binVersionOf(bin string) (string, error) {
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 || !strings.Contains(strings.ToLower(fields[0]), BinName) {
		return "", errors.New("不是有效的 cloudflared 可执行文件")
	}
	for i, f := range fields {
		if f == "version" && i+1 < len(fields) {
			return strings.TrimSpace(fields[i+1]), nil
		}
	}
	return "", nil
}
