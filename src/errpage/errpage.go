// Package errpage 统一渲染 TunHook 自身产生的 HTTP 错误页。
//
// 定位：400/401/403/404/405/410/500/502/503 九个状态码各对应一份完整 HTML 模板文件，
// 存放在 <dataDir>/errorpages/<状态码>.html，整页 HTML/CSS 由用户自由编辑（设置页弹窗或直接改文件），
// 三处 HTTP 入口共用同一份模板：
//   - TunHook Web 服务（管理界面 / 导航页 / 通道访问）
//   - 域名 HTTP(S) 转发（forward）
//   - frpc http 代理反代层
//
// 文件即真相：模板按修改时间（mtime + 大小）缓存，手工改文件无需重启即生效；
// 文件缺失或读取失败时回退到内置默认模板，保证错误页始终可用。
//
// 边界（决定「改哪里、不改哪里」）：
//   - 只替换 TunHook 自己写的错误响应；反向代理透传的上游状态码一律原样返回，
//     避免把用户后端自己的 404/500 页面盖掉；
//   - 只接管浏览器页面请求（Accept 含 text/html，且不在 /api/、/proxy/ 路径下），
//     API/JSON、静态资源、WebSocket 与流式响应不受影响。
package errpage

import (
	"errors"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Codes 支持自定义的错误状态码，顺序即「错误页面」设置页的展示顺序。
var Codes = []int{400, 401, 403, 404, 405, 410, 500, 502, 503}

// errUnsupported 状态码不在 Codes 内（无法定制的错误码）。
var errUnsupported = errors.New("不支持的错误状态码")

// page 一份模板的内置默认文案（用于生成首次落地的默认 HTML 文件）。
// 文案为「复古终端故障」口气：tag 是终端标识（英文大写，显示在标题下方），
// body 按行书写，每行以 "> " 开头，模板按原样换行展示。
type page struct {
	tag   string
	title string
	body  string
}

// defaults 内置默认文案：模板文件缺失时也用它兜底渲染。
var defaults = map[int]page{
	400: {
		tag:   "BAD_REQUEST",
		title: "请求无法解析",
		body: "> 数据包格式异常，服务器无法理解本次请求。\n" +
			"> 可能原因：地址拼写错误、参数缺失或编码不规范。\n" +
			"> 系统建议：检查访问地址后重试。",
	},
	401: {
		tag:   "AUTH_REQUIRED",
		title: "需要身份验证",
		body: "> 该坐标受保护，本次请求未通过身份校验。\n" +
			"> 可能原因：登录状态已过期，或缺少访问凭据。\n" +
			"> 系统建议：完成身份验证后重新发起请求。",
	},
	403: {
		tag:   "ACCESS_DENIED",
		title: "访问被拒绝",
		body: "> 权限校验未通过，本次请求已被拦截。\n" +
			"> 可能原因：当前网络不在允许名单内，或该资源不对你开放。\n" +
			"> 系统建议：确认访问权限，或联系管理员处理。",
	},
	404: {
		tag:   "SIGNAL_LOST",
		title: "页面信号丢失",
		body: "> 坐标偏移，页面信号已脱离轨道。\n" +
			"> 可能原因：链接损坏、路由漂移，或目标已被移除。\n" +
			"> 系统建议：重新校准航向。",
	},
	405: {
		tag:   "METHOD_BLOCKED",
		title: "请求方式不允许",
		body: "> 该地址不接受当前的访问方式。\n" +
			"> 可能原因：使用了不受支持的请求方法。\n" +
			"> 系统建议：改用正确的请求方式重试。",
	},
	410: {
		tag:   "CONTENT_GONE",
		title: "内容已永久下线",
		body: "> 目标内容已被永久移除，不会再上线。\n" +
			"> 可能原因：资源被作者主动下线或迁移。\n" +
			"> 系统建议：返回首页或寻找替代入口。",
	},
	500: {
		tag:   "CORE_FAULT",
		title: "服务器内部异常",
		body: "> 内核在处理请求时发生异常，本次任务已中止。\n" +
			"> 可能原因：内部逻辑错误或依赖组件异常。\n" +
			"> 系统建议：稍后重试；若持续出现，请查看服务日志。",
	},
	502: {
		tag:   "UPLINK_DOWN",
		title: "上游连接中断",
		body: "> 网关无法连接上游服务，链路已断开。\n" +
			"> 可能原因：本地服务未启动、端口未监听或正在重启。\n" +
			"> 系统建议：确认目标服务运行状态后重试。",
	},
	503: {
		tag:   "SERVICE_OFFLINE",
		title: "服务暂时离线",
		body: "> 服务正在维护或负载过载，暂时无法响应。\n" +
			"> 可能原因：维护窗口、资源不足或过载保护已触发。\n" +
			"> 系统建议：稍后重试。",
	},
}

var (
	mu    sync.RWMutex
	dir   string                 // 模板目录（<dataDir>/errorpages），未 Init 时为空
	cache = map[int]cachedPage{} // 文件内容缓存，按 mtime + 大小判断是否过期
)

type cachedPage struct {
	content string
	mtime   time.Time
	size    int64
}

// Init 初始化模板目录：目录不存在则创建，九个状态码缺哪份补哪份（写入内置默认模板）。
// 会切换模板目录并清空缓存；目录不可用时返回错误，此时错误页回退为内置默认内容。
func Init(dirPath string) error {
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		return err
	}
	mu.Lock()
	dir = dirPath
	cache = map[int]cachedPage{}
	mu.Unlock()
	for _, code := range Codes {
		p := filePath(code)
		if _, err := os.Stat(p); err == nil {
			continue
		}
		if err := writeFileAtomic(p, DefaultHTML(code)); err != nil {
			return err
		}
	}
	return nil
}

// File 返回某状态码模板文件的绝对路径（未 Init 时为空）。
func File(code int) string {
	return filePath(code)
}

// filePath 取模板文件路径；模板目录未初始化时返回空串。
func filePath(code int) string {
	mu.RLock()
	d := dir
	mu.RUnlock()
	if d == "" {
		return ""
	}
	return filepath.Join(d, strconv.Itoa(code)+".html")
}

// Content 返回某状态码当前生效的模板内容：优先读模板文件（带 mtime 缓存），
// 文件缺失/读取失败时回退内置默认模板；状态码不在 Codes 内时返回 false。
func Content(code int) (string, bool) {
	if _, ok := defaults[code]; !ok {
		return "", false
	}
	p := File(code)
	if p == "" {
		return DefaultHTML(code), true
	}
	fi, err := os.Stat(p)
	if err != nil {
		return DefaultHTML(code), true
	}
	mu.RLock()
	c, ok := cache[code]
	mu.RUnlock()
	if ok && c.size == fi.Size() && c.mtime.Equal(fi.ModTime()) {
		return c.content, true
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return DefaultHTML(code), true
	}
	content := string(b)
	mu.Lock()
	cache[code] = cachedPage{content: content, mtime: fi.ModTime(), size: fi.Size()}
	mu.Unlock()
	return content, true
}

// Save 写入某状态码的模板文件并立即生效（原子写，避免半截文件）。
func Save(code int, content string) error {
	if _, ok := defaults[code]; !ok {
		return errUnsupported
	}
	p := filePath(code)
	if p == "" {
		return errors.New("模板目录未初始化")
	}
	if err := writeFileAtomic(p, content); err != nil {
		return err
	}
	if fi, err := os.Stat(p); err == nil {
		mu.Lock()
		cache[code] = cachedPage{content: content, mtime: fi.ModTime(), size: fi.Size()}
		mu.Unlock()
	}
	return nil
}

// Reset 把全部状态码的模板文件恢复为内置默认内容。
func Reset() error {
	for _, code := range Codes {
		if err := Save(code, DefaultHTML(code)); err != nil {
			return err
		}
	}
	return nil
}

// DefaultHTML 生成某状态码的内置默认模板（首次落地默认文件与恢复默认共用）。
func DefaultHTML(code int) string {
	p, ok := defaults[code]
	if !ok {
		return ""
	}
	return strings.NewReplacer(
		"{{code}}", strconv.Itoa(code),
		"{{tag}}", html.EscapeString(p.tag),
		"{{title}}", html.EscapeString(p.title),
		"{{body}}", html.EscapeString(p.body),
	).Replace(defaultTemplate)
}

// writeFileAtomic 先写临时文件再改名，避免写入中断留下半截模板。
func writeFileAtomic(path, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Write 输出错误响应：命中模板且为浏览器页面请求时渲染自定义错误页，
// 否则回退为原有的纯文本错误（fallback 文案与替换前的行为保持一致）。
//
// 用于调用方明确知道「这个错误是 TunHook 自己产生的」的场景（如反代层连不上本地服务）。
// 这里不看请求路径：域名转发/反代层的 URL 空间属于用户自己的站点。
func Write(w http.ResponseWriter, r *http.Request, code int, fallback string) {
	if content, ok := Content(code); ok && wantsHTML(r) {
		render(w, code, content)
		return
	}
	http.Error(w, fallback, code)
}

// Preview 按指定状态码渲染当前模板（设置页「访问」按钮用，与访客看到的响应完全一致）；
// 状态码不受支持时返回 false。
func Preview(w http.ResponseWriter, code int) bool {
	content, ok := Content(code)
	if !ok {
		return false
	}
	render(w, code, content)
	return true
}

// Handler 包装处理器：把本次请求中 TunHook 自身写出的错误状态码替换为自定义错误页。
// 只有浏览器页面请求才包装，其余请求原样透传（不触碰 WebSocket 升级与流式响应）。
//
// gatewayPrefix 为统一网关访问前缀（如 /app/TunHook，无则传空）：经网关访问时请求路径带该前缀，
// 判断「是否本服务接口/透传路径」前先剥掉，避免前缀导致判断失效。
func Handler(next http.Handler, gatewayPrefix string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !wantsPage(r, gatewayPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		iw := &interceptWriter{ResponseWriter: w}
		next.ServeHTTP(iw, r)
		if iw.intercept {
			if content, ok := Content(iw.code); ok {
				render(w, iw.code, content)
			}
		}
	})
}

// wantsPage 判断是否 TunHook 自身路径下的浏览器页面请求：
// 除「期望 HTML」外，还要求不在 /api/（本服务接口，保持 JSON 契约）与
// /proxy/（统一网关透传上游，状态码可能来自用户后端）路径下。
func wantsPage(r *http.Request, gatewayPrefix string) bool {
	path := r.URL.Path
	if gatewayPrefix != "" {
		path = strings.TrimPrefix(path, gatewayPrefix)
	}
	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/proxy/") {
		return false
	}
	return wantsHTML(r)
}

// wantsHTML 判断客户端是否在请求一个浏览器页面（Accept 含 text/html）。
// 本服务前端的 fetch、curl/wget 与各类机器调用均不满足，因此不会被替换。
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// interceptWriter 拦截错误状态码：命中自定义错误页时吞掉原始错误响应，
// 由 Handler 在处理器返回后统一输出页面（此时响应头尚未写出，可整体替换）。
type interceptWriter struct {
	http.ResponseWriter
	code      int
	wrote     bool
	intercept bool
}

func (w *interceptWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	if _, ok := defaults[code]; ok {
		w.intercept = true
		w.code = code
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *interceptWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.intercept {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// render 输出自定义错误页：禁止缓存，模板改动后立即生效。
func render(w http.ResponseWriter, code int, content string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(content))
}

// defaultTemplate 默认错误页模板（自包含，无外部依赖）：复古终端故障风格，
// 扫描线 / 屏幕闪烁 / 光标均由纯 CSS 实现，无需任何外部资源。
// {{code}}/{{tag}}/{{title}}/{{body}} 仅用于生成默认文件，
// 用户编辑后的文件按原样输出，不再做任何替换。
const defaultTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=yes">
<title>{{code}} · {{title}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0c0f;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem;color:#b3ffb3;font-family:'Courier New','Fira Code','Consolas',monospace;position:relative;overflow-x:hidden}
body::after{content:"";position:fixed;inset:0;background:repeating-linear-gradient(0deg,rgba(0,255,65,.02) 0px,rgba(0,0,0,.03) 2px,transparent 3px);pointer-events:none;z-index:999}
.crt-container{width:100%;max-width:680px;background:#0e1116;border:2px solid #2a3a2a;border-radius:16px;padding:2rem 1.8rem;position:relative;box-shadow:0 0 25px rgba(0,180,30,.25),inset 0 0 20px rgba(0,0,0,.7)}
.glitch-block{position:absolute;top:18px;right:24px;width:55px;height:28px;background:rgba(0,255,100,.08);border:1px solid #1f4f1f;border-radius:4px;color:#7eff7e;font-size:.7rem;display:flex;align-items:center;justify-content:center;letter-spacing:1px;text-transform:uppercase}
.terminal-header{display:flex;align-items:center;gap:.5rem;margin-bottom:2rem;border-bottom:1px dashed #2d4a2d;padding-bottom:.8rem}
.dot{width:10px;height:10px;border-radius:50%;background:#2f6b2f;box-shadow:0 0 8px #1f4f1f}
.dot.active{background:#3fe03f;box-shadow:0 0 14px #1aff1a}
.header-text{margin-left:auto;font-size:.8rem;color:#5b8c5b;letter-spacing:2px;text-transform:uppercase}
.error-code{font-size:clamp(4.5rem,18vw,8rem);font-weight:900;color:#c7ffc7;text-shadow:0 0 18px #1f9c1f,0 0 40px #0b4b0b;line-height:1;letter-spacing:8px;margin-bottom:.25rem;display:inline-block;animation:flickerText 4s infinite}
@keyframes flickerText{0%,19%,21%,23%,25%,54%,56%,100%{opacity:1;transform:translate(0,0)}20%,24%{opacity:.7;transform:translate(-2px,1px)}55%{opacity:.85;transform:translate(1px,-1px)}}
.sub-glitch{display:flex;align-items:baseline;flex-wrap:wrap;gap:.8rem;margin-bottom:1.8rem}
.message{font-size:1.4rem;font-weight:bold;color:#b3ffb3;background:rgba(0,20,0,.6);padding:.3rem 1rem;border-left:4px solid #31b431;letter-spacing:1px}
.description{color:#7fa07f;font-size:1rem;line-height:1.7;background:#0a0e0a;padding:.9rem 1.2rem;border-radius:10px;border:1px solid #1f3a1f;white-space:pre-wrap;word-break:break-word}
.command-line{display:flex;flex-wrap:wrap;align-items:center;gap:.4rem;margin:1.5rem 0 0;font-size:.95rem;color:#8bc34a}
.prompt{color:#5cd65c;font-weight:bold;margin-right:.2rem}
.cursor{display:inline-block;width:10px;height:1.2em;background:#a3f7a3;animation:blink 1s step-end infinite;vertical-align:middle;margin-left:2px;box-shadow:0 0 8px #33cc33}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
.cmd-out{color:#578657;font-size:.8rem;margin:.4rem 0 0 1.2rem}
.coords{margin-top:1.8rem;font-size:.75rem;color:#476647;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem;border-top:1px dotted #1f3a1f;padding-top:1rem}
.led{display:inline-block;width:8px;height:8px;border-radius:50%;background:#e04b4b;box-shadow:0 0 8px #a02020;margin-right:.4rem;vertical-align:middle}
.blink-slow{animation:softBlink 2.5s infinite}
@keyframes softBlink{0%,100%{opacity:.7}50%{opacity:.3}}
@media (max-width:480px){.crt-container{padding:1.5rem 1.2rem}.coords{flex-direction:column;align-items:flex-start;gap:.3rem}}
</style>
</head>
<body>
<div class="crt-container">
<div class="glitch-block">ERR</div>
<div class="terminal-header">
<span class="dot active"></span>
<span class="dot"></span>
<span class="dot"></span>
<span class="header-text">NODE_{{code}}</span>
</div>
<div class="error-code">{{code}}</div>
<div class="sub-glitch">
<span class="message">{{tag}}</span>
</div>
<div class="description">{{body}}</div>
<div class="command-line">
<span class="prompt">guest@tunhook:~$</span>
<span>status --code {{code}}</span>
<span class="cursor"></span>
</div>
<div class="cmd-out">[错误] {{title}}。连接已中断。</div>
<div class="coords">
<span class="blink-slow"><span class="led"></span>连接中断</span>
<span>REF: {{code}}-{{tag}}</span>
<span>信号: 微弱</span>
</div>
</div>
</body>
</html>
<!-- 本文件为 {{code}} 错误页模板，整页 HTML/CSS 可自由修改，保存后立即生效（无需重启）。 -->
`
