package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

//go:embed desk_template
var deskTemplateFS embed.FS

// DeskTaskStatus 桌面图标任务的实时状态。
type DeskTaskStatus string

const (
	TaskRunning DeskTaskStatus = "running"
	TaskDone    DeskTaskStatus = "done"
	TaskFailed  DeskTaskStatus = "failed"
)

// deskTaskLogLimit 任务日志最多保留的行数（滚动截断，防止内存膨胀）。
const deskTaskLogLimit = 200

// DeskTask 记录一次桌面图标打包/安装/卸载操作的实时进度，供前端轮询展示。
type DeskTask struct {
	ID      string         `json:"task_id"`
	Status  DeskTaskStatus `json:"status"`
	Step    string         `json:"step,omitempty"`    // 当前步骤名
	Percent int            `json:"percent"`           // 0-100
	Message string         `json:"message,omitempty"` // 最近一条输出
	Logs    []string       `json:"logs,omitempty"`    // 累积输出（保留最近 N 行）
	Error   string         `json:"error,omitempty"`
	mu      sync.Mutex
}

func (t *DeskTask) setProgress(step string, percent int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Step = step
	t.Percent = percent
}

func (t *DeskTask) setPercentMin(p int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p > t.Percent {
		t.Percent = p
	}
}

// addLog 追加一行输出到任务日志（自动按换行拆分并滚动截断）。
func (t *DeskTask) addLog(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for len(s) > 0 {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			if s != "" {
				t.appendLineLocked(strings.TrimRight(s, "\r"))
			}
			return
		}
		line := strings.TrimRight(s[:i], "\r")
		if line != "" {
			t.appendLineLocked(line)
		}
		s = s[i+1:]
	}
}

func (t *DeskTask) appendLineLocked(line string) {
	t.Logs = append(t.Logs, line)
	if len(t.Logs) > deskTaskLogLimit {
		t.Logs = t.Logs[len(t.Logs)-deskTaskLogLimit:]
	}
	t.Message = line
}

func (t *DeskTask) setDone() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Status = TaskDone
	t.Percent = 100
}

func (t *DeskTask) setFailed(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Status = TaskFailed
	t.Error = err.Error()
}

// taskLineWriter 将命令实时输出写入任务日志；from/to 表示输出行驱动的进度递增区间
// （to > from 时每产生一行输出进度 +1，封顶 to-1）。
type taskLineWriter struct {
	task      *DeskTask
	from, to  int
	lineCount int
}

func (w *taskLineWriter) Write(p []byte) (int, error) {
	w.task.addLog(string(p))
	if w.to > w.from {
		w.lineCount++
		p := w.from + w.lineCount
		if p >= w.to {
			p = w.to - 1
		}
		w.task.setPercentMin(p)
	}
	return len(p), nil
}

// deskAppManager 负责把一条统一网关转发规则的桌面图标配置生成并安装为 fnOS 空应用
// （appname=TunHook-<规则名>），使图标真正出现在 fnOS 桌面。
// 主应用以 root 运行后可直接调用 fnpack / appcenter-cli 完成打包与安装/卸载。
type deskAppManager struct {
	dataDir string // 应用数据目录（<dataDir>/desk-apps 下生成项目）
	logger  *zap.Logger

	tasks  map[string]*DeskTask // 运行中的任务（含已完成，超出上限后清理）
	taskMu sync.Mutex
}

func newDeskAppManager(dataDir string, logger *zap.Logger) *deskAppManager {
	return &deskAppManager{
		dataDir: dataDir,
		logger:  logger,
		tasks:   make(map[string]*DeskTask),
	}
}

// newTask 创建并注册一个任务，返回任务句柄（op 用于区分操作类型，如 install/uninstall）。
func (m *deskAppManager) newTask(op string) *DeskTask {
	t := &DeskTask{
		ID:     op + "-" + fmt.Sprintf("%x", time.Now().UnixNano()),
		Status: TaskRunning,
		Logs:   make([]string, 0, 16),
	}
	m.taskMu.Lock()
	// 防止任务表无限增长：超上限时先清理已结束的任务
	if len(m.tasks) >= 50 {
		for id, old := range m.tasks {
			old.mu.Lock()
			done := old.Status != TaskRunning
			old.mu.Unlock()
			if done {
				delete(m.tasks, id)
			}
		}
	}
	m.tasks[t.ID] = t
	m.taskMu.Unlock()
	return t
}

// task 返回任务的快照（拷贝）；不存在时返回 nil。
func (m *deskAppManager) task(id string) *DeskTask {
	m.taskMu.Lock()
	t := m.tasks[id]
	m.taskMu.Unlock()
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return &DeskTask{
		ID:      t.ID,
		Status:  t.Status,
		Step:    t.Step,
		Percent: t.Percent,
		Message: t.Message,
		Logs:    append([]string(nil), t.Logs...),
		Error:   t.Error,
	}
}

var deskNameRe = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

// appName 返回规则名对应的 fnOS 空应用 appname。
func (m *deskAppManager) appName(name string) string { return "TunHook-" + name }

// install 为指定转发规则/外部地址生成空应用并安装到 fnOS：
// 展开内嵌模板 → 替换占位符 → 复制图标 → fnpack build → appcenter-cli install-fpk。
// task 非空时将每步进度与命令实时输出写入任务（供前端轮询展示）。
// mode: "gateway" 统一网关转发规则入口（桌面入口直接用路径打开主应用的网关转发地址
//
//	/app/TunHook/proxy/{规则名}，流量由主应用 TunHook 转发，本应用不注册网关/CGI）；
//
// "port" 端口入口（http://{NAS_IP}:{localPort}，适用于 TCP/UDP/HTTP 转发规则；tls=true 时以 https:// 打开）；
// "url" 外部地址入口（frpc 代理 / Webhook 通道等：externalURL 必填，直接写入完整外部 URL）。
// 注意：fnOS 桌面窗口（iframe）会把 url 当作 NAS 相对路径解析（前面补 '/'），打不开外部地址；
// 因此外部地址入口强制使用「浏览器标签页（url）」打开方式（install 内将 typ 固定为 "url"）。
func (m *deskAppManager) install(task *DeskTask, name, title, typ string, allUsers bool, iconSrc string, mode string, localPort int, tls bool, externalURL string) error {
	if !deskNameRe.MatchString(name) {
		return fmt.Errorf("网关规则名仅支持字母和数字: %s", name)
	}
	if typ != "iframe" && typ != "url" {
		return fmt.Errorf("打开方式仅支持 iframe 或 url: %s", typ)
	}
	appName := m.appName(name)
	projDir := filepath.Join(m.dataDir, "desk-apps", appName)

	step := func(s string, p int) {
		if task != nil {
			task.setProgress(s, p)
		}
		m.logger.Info("桌面图标安装步骤: "+s, zap.String("app", appName))
	}

	// 1. 展开模板（每次重建，保证干净可重复）
	step("清理旧项目", 5)
	if err := os.RemoveAll(projDir); err != nil {
		return fmt.Errorf("清理旧项目失败: %v", err)
	}
	step("展开应用模板", 10)
	if err := fs.WalkDir(deskTemplateFS, "desk_template", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dst := filepath.Join(projDir, strings.TrimPrefix(p, "desk_template"))
		if d.IsDir() {
			return os.MkdirAll(dst, 0755)
		}
		data, err := fs.ReadFile(deskTemplateFS, p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0755)
	}); err != nil {
		return fmt.Errorf("展开模板失败: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(projDir, "wizard"), 0755); err != nil {
		return fmt.Errorf("创建 wizard 目录失败: %v", err)
	}

	// 2. 替换占位符（manifest / app/ui/config / config/privilege / cmd 脚本）
	step("生成应用配置", 20)
	allUsersStr := "false"
	if allUsers {
		allUsersStr = "true"
	}
	repl := strings.NewReplacer(
		"__NAME_LOWER__", strings.ToLower(name),
		"__NAME__", name,
		"__TITLE__", title,
		"__TYPE__", typ,
		"__ALLUSERS__", allUsersStr,
	)
	for _, f := range []string{
		filepath.Join(projDir, "manifest"),
		filepath.Join(projDir, "app", "ui", "config"),
		filepath.Join(projDir, "config", "privilege"),
		filepath.Join(projDir, "cmd", "install_callback"),
		filepath.Join(projDir, "cmd", "main"),
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("读取模板文件失败 %s: %v", f, err)
		}
		if err := os.WriteFile(f, []byte(repl.Replace(string(b))), 0755); err != nil {
			return fmt.Errorf("写入模板文件失败 %s: %v", f, err)
		}
	}

	// 端口模式（TCP/UDP/HTTP 转发）：桌面入口直接指向 http://{NAS_IP}:{localPort}，
	// 无需网关 socket 软链；覆写 ui/config 为端口入口。
	// TCP 开启 HTTPS（自签名证书）时以 https://{NAS_IP}:{localPort} 打开。
	if mode == "port" {
		step("写入端口入口配置", 25)
		proto := "http"
		if tls {
			proto = "https"
		}
		portCfg := fmt.Sprintf(`{
    ".url": {
        "TunHook-%s.main": {
            "title": "%s",
            "desc": "TunHook 转发规则 %s",
            "icon": "images/icon-{0}.png",
            "type": "%s",
            "protocol": "%s",
            "port": "%d",
            "url": "/",
            "allUsers": %s
        }
    }
}`, name, title, name, typ, proto, localPort, allUsersStr)
		if err := os.WriteFile(filepath.Join(projDir, "app", "ui", "config"), []byte(portCfg), 0755); err != nil {
			return fmt.Errorf("写入端口入口配置失败: %v", err)
		}
	} else if mode == "url" {
		// 外部地址入口（frpc 代理 / Webhook 通道等）：桌面入口直接打开完整外部 URL。
		// 外部地址仅支持「浏览器标签页（url）」打开：fnOS 桌面窗口（iframe）会把 url
		// 当作 NAS 相对路径解析（前面补 '/'），导致 /http://ddd.myunxi.top 打不开。
		step("写入外部地址入口配置", 25)
		typ = "url"
		titleJSON, _ := json.Marshal(title)
		urlJSON, _ := json.Marshal(externalURL)
		urlCfg := fmt.Sprintf(`{
    ".url": {
        "TunHook-%s.main": {
            "title": %s,
            "desc": "TunHook 快捷入口 %s",
            "icon": "images/icon-{0}.png",
            "type": "%s",
            "url": %s,
            "allUsers": %s
        }
    }
}`, name, titleJSON, name, typ, urlJSON, allUsersStr)
		if err := os.WriteFile(filepath.Join(projDir, "app", "ui", "config"), []byte(urlCfg), 0755); err != nil {
			return fmt.Errorf("写入外部地址入口配置失败: %v", err)
		}
	}

	// 3. 图标（原图直接使用，不裁剪）：应用中心图标 + 桌面入口图标
	if iconSrc != "" {
		step("复制图标", 30)
		for _, dst := range []string{
			filepath.Join(projDir, "ICON.PNG"),
			filepath.Join(projDir, "ICON_256.PNG"),
			filepath.Join(projDir, "app", "ui", "images", "icon-64.png"),
			filepath.Join(projDir, "app", "ui", "images", "icon-256.png"),
		} {
			if err := copyFile(iconSrc, dst); err != nil {
				return fmt.Errorf("复制图标失败: %v", err)
			}
		}
	}

	// 4. fnpack build 生成 fpk（在项目目录内执行，产物输出到项目目录）
	step("打包应用（fnpack build）", 35)
	out, err := m.runCmd(task, 35, 78, projDir, "fnpack", "build")
	if err != nil {
		return fmt.Errorf("打包失败: %v", err)
	}
	fpk := filepath.Join(projDir, appName+".fpk")
	if _, err := os.Stat(fpk); err != nil {
		// fnpack 校验/打包失败时仍返回退出码 0（如缺少必需文件），产物检查兜底并附上打包输出便于定位
		return fmt.Errorf("打包完成但未找到 fpk 产物（fnpack 可能未真正成功，输出：%s）", cmdOutTail(out, 5))
	}

	// 5. 若已安装旧版本，先卸载（同 appname 覆盖安装更稳妥）
	step("卸载旧版本", 80)
	_, _ = m.runCmd(task, 80, 88, "", "appcenter-cli", "uninstall", appName)

	// 6. 安装
	step("安装应用", 90)
	if _, err := m.runCmd(task, 90, 99, "", "appcenter-cli", "install-fpk", fpk); err != nil {
		return fmt.Errorf("安装失败: %v", err)
	}

	if task != nil {
		task.setDone()
	}
	return nil
}

// uninstall 卸载规则对应的桌面图标空应用（幂等），并清理生成的项目目录。
// task 非空时写入实时进度。
func (m *deskAppManager) uninstall(task *DeskTask, name string) error {
	if !deskNameRe.MatchString(name) {
		return nil
	}
	if task != nil {
		task.setProgress("卸载桌面图标应用", 20)
	}
	if _, err := m.runCmd(task, 20, 90, "", "appcenter-cli", "uninstall", m.appName(name)); err != nil {
		if task != nil {
			task.setFailed(err)
		}
		return err
	}
	if task != nil {
		task.setProgress("清理项目文件", 95)
	}
	_ = os.RemoveAll(filepath.Join(m.dataDir, "desk-apps", m.appName(name)))
	if task != nil {
		task.setDone()
	}
	return nil
}

// copyFile 复制单个文件。
func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0644)
}

// runCmd 执行系统命令（root 运行主应用，可直接调用 fnpack/appcenter-cli）。
// dir 非空时在该目录执行。带 180s 超时，输出实时写入任务日志（task 可为 nil）。
// from/to 表示输出行驱动的进度递增区间（to <= from 时不递增）。
// 返回命令输出（即使命令失败也返回，便于错误提示定位）。
func (m *deskAppManager) runCmd(task *DeskTask, from, to int, dir, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var buf bytes.Buffer
	var w io.Writer = &buf
	if task != nil {
		w = io.MultiWriter(&buf, &taskLineWriter{task: task, from: from, to: to})
	}
	cmd.Stdout = w
	cmd.Stderr = w
	err := cmd.Run()
	out := buf.String()
	if err != nil {
		m.logger.Error("命令执行失败",
			zap.String("cmd", name+" "+strings.Join(args, " ")),
			zap.ByteString("output", []byte(out)),
			zap.Error(err),
		)
		return out, fmt.Errorf("%s: %s", err, strings.TrimSpace(out))
	}
	m.logger.Info("命令执行成功",
		zap.String("cmd", name+" "+strings.Join(args, " ")),
		zap.ByteString("output", []byte(out)),
	)
	return out, nil
}

// cmdOutTail 取命令输出末尾最多 max 行非空内容，用于错误提示中快速定位失败原因。
func cmdOutTail(out string, max int) string {
	if max <= 0 {
		max = 1
	}
	lines := strings.Split(out, "\n")
	var tail []string
	for i := len(lines) - 1; i >= 0 && len(tail) < max; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			tail = append([]string{t}, tail...)
		}
	}
	return strings.Join(tail, " | ")
}
