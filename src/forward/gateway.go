package forward

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tunhook/errpage"

	"go.uber.org/zap"
)

// GatewayForwarder 实现 Forwarder 接口，代表一条“统一网关”转发规则。
// 该模式不监听独立 TCP/UDP 端口：由 Web 服务器在 /proxy/{name} 路径下
// 将经飞牛统一网关鉴权后的请求反向代理到远端目标（RemoteAddr:RemotePort）。
// 访问路径为 {gatewayPrefix}/proxy/{name}，天然获得 NAS 登录态保护，并支持 WebSocket。
type GatewayForwarder struct {
	name       string
	remoteAddr string
	logger     *zap.Logger

	backendURL *url.URL
	// proxyPrefix 是内部处理路径（/proxy/{name}），publicBase 是对外完整访问路径
	// （{gatewayPrefix}/proxy/{name}）。后端返回的重定向（Location）必须拼接 publicBase，
	// 否则浏览器会跳到 NAS 根路径下，导致转发地址的子路径/跳转无法正常访问。
	proxyPrefix string
	publicBase  string
	// sourcePrefix 是后端应用自身运行的原始路径前缀（如 /app/canvasboard）。
	// 配置后，响应内容（HTML/JS/CSS）中的该前缀会被替换为 publicBase，
	// 使写死绝对路径的前端应用也能通过网关子路径访问。
	sourcePrefix string
	// rootPrefixes 是后端应用使用的根相对路径前缀列表（如 /sac、/locales），
	// 常见于以 window.location 拼接接口地址的系统级前端（如 fnOS 系统 UI）。
	// 配置后，响应内容（HTML/JS/CSS）中这些前缀会被拼上 publicBase，
	// 使根相对 API/WebSocket 请求改走代理子路径。
	rootPrefixes []string
	// pathPrefix 是后端路径前缀（如 /app/canvasboard）：请求转发到后端时，
	// 在剥离 /proxy/{name} 后拼接该前缀，使部署在子路径下的后端服务能正确响应；
	// 同时 ModifyResponse 会把后端返回的以 pathPrefix 开头的 Location 剥离后回写网关路径。
	pathPrefix string
	rp         *httputil.ReverseProxy
	started    bool

	txBytes   int64
	rxBytes   int64
	connCount int32
	mu        sync.Mutex
	clients   map[string]*httpClientStat
}

// validGatewayName 校验统一网关子路径名称：仅允许字母、数字、下划线、连字符，长度 1-64。
// 禁止点号/斜杠等 URL 不安全字符，路径规则与 fnOS 网关前缀要求保持一致。
func validGatewayName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func NewGatewayForwarder(name, remoteAddr, gatewayPrefix, sourcePrefix, rootPrefixes, pathPrefix string, logger *zap.Logger) (*GatewayForwarder, error) {
	backendURL, err := url.Parse("http://" + remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("parse backend url: %w", err)
	}
	proxyPrefix := "/proxy/" + name
	publicBase := gatewayPrefix + proxyPrefix

	f := &GatewayForwarder{
		name:         name,
		remoteAddr:   remoteAddr,
		logger:       logger,
		backendURL:   backendURL,
		proxyPrefix:  proxyPrefix,
		publicBase:   publicBase,
		sourcePrefix: sourcePrefix,
		rootPrefixes: parseRootPrefixes(rootPrefixes),
		pathPrefix:   normalizePathPrefix(pathPrefix),
		clients:      make(map[string]*httpClientStat),
	}

	f.rp = &httputil.ReverseProxy{
		// 跟随后端 3xx 重定向（服务端跟进，浏览器不经历 302）
		Transport: newGatewayTransport(),
		Rewrite: func(pr *httputil.ProxyRequest) {
			// 剥离子路径前缀，再拼接后端路径前缀，让部署在子路径下的后端按
			// {pathPrefix} 工作（与网关前缀剥离逻辑一致）
			path := strings.TrimPrefix(pr.In.URL.Path, proxyPrefix)
			rel := strings.TrimPrefix(path, "/")
			out := f.pathPrefix
			if rel != "" {
				out += "/" + rel
			}
			if out == "" {
				out = "/"
			}
			pr.Out.URL.Scheme = backendURL.Scheme
			pr.Out.URL.Host = backendURL.Host
			pr.Out.URL.Path = out
			pr.Out.URL.RawPath = ""
			// 保留原始 Host 并补充 X-Forwarded-*，避免后端基于 Host 生成错误地址，
			// 同时保证 WebSocket 的 Host/Origin 一致性校验通过。
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			// 去掉出站 Accept-Encoding：Go 传输层会自行添加 gzip 并透明解压，
			// 使 ModifyResponse 能对 text/html 做路径改写（压缩响应无法改写内容）。
			pr.Out.Header.Del("Accept-Encoding")
		},
		ModifyResponse: func(resp *http.Response) error {
			// 兜底：未在服务端跟进的 3xx（POST、跨主机、超过跳数上限），
			// 其 Location 需要拼接完整网关访问路径，否则浏览器会跳到 NAS 根路径
			// （如 /login），转发地址无法正常访问。
			loc := resp.Header.Get("Location")
			if loc != "" {
				// 协议相对地址（//host/...）与已带前缀的路径不做处理
				if strings.HasPrefix(loc, "//") {
					return nil
				}
				if strings.HasPrefix(loc, "/") {
					// 后端返回的路径以 pathPrefix 开头时先剥离（外部表现为 /proxy/{name} 子路径）
					if strings.HasPrefix(loc, f.pathPrefix) {
						loc = strings.TrimPrefix(loc, f.pathPrefix)
						if loc == "" {
							loc = "/"
						}
					}
					if !strings.HasPrefix(loc, publicBase) {
						resp.Header.Set("Location", publicBase+loc)
					}
					return nil
				}
				// 相对路径（login、./login）：按网关路径拼接
				if !strings.Contains(loc, "://") {
					resp.Header.Set("Location", publicBase+"/"+loc)
					return nil
				}
				// 指向后端自身的绝对重定向同样改写为网关路径
				if u, err := url.Parse(loc); err == nil && u.Host == backendURL.Host {
					p := u.Path
					if strings.HasPrefix(p, f.pathPrefix) {
						p = strings.TrimPrefix(p, f.pathPrefix)
						if p == "" {
							p = "/"
						}
					}
					newLoc := publicBase + p
					if u.RawQuery != "" {
						newLoc += "?" + u.RawQuery
					}
					resp.Header.Set("Location", newLoc)
				}
				return nil
			}
			// 页面/脚本里的路径改写：根相对资源路径、写死的绝对前缀（sourcePrefix）、
			// 以及以 window.location 拼接的根相对接口前缀（rootPrefixes）。
			if resp.StatusCode == http.StatusOK &&
				resp.Header.Get("Content-Encoding") == "" &&
				needsContentRewrite(resp, f.sourcePrefix, f.rootPrefixes) {
				if err := rewriteContentBody(resp, f.publicBase, f.sourcePrefix, f.rootPrefixes); err != nil {
					f.logger.Warn("内容路径改写失败",
						zap.String("name", f.name),
						zap.String("backend", f.remoteAddr),
						zap.Error(err),
					)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			f.logger.Error("网关反向代理错误",
				zap.String("name", f.name),
				zap.String("backend", f.remoteAddr),
				zap.Error(err),
			)
			// 后端不可达（TunHook 自身产生的错误）：可按配置替换为自定义错误页
			errpage.Write(w, r, http.StatusBadGateway, "502 网关错误")
		},
	}
	return f, nil
}

// Name 返回该规则在 /proxy/{name} 下的子路径名称。
func (f *GatewayForwarder) Name() string { return f.name }

func (f *GatewayForwarder) Start() error {
	if f.started {
		return fmt.Errorf("gateway forwarder already started")
	}
	f.started = true
	f.logger.Info("统一网关转发已启用",
		zap.String("name", f.name),
		zap.String("backend", f.remoteAddr),
		zap.String("path", f.publicBase),
	)
	return nil
}

func (f *GatewayForwarder) Stop() {
	f.started = false
	f.logger.Info("统一网关转发已停用", zap.String("name", f.name))
}

func (f *GatewayForwarder) TXBytes() int64 { return atomic.LoadInt64(&f.txBytes) }
func (f *GatewayForwarder) RXBytes() int64 { return atomic.LoadInt64(&f.rxBytes) }
func (f *GatewayForwarder) ConnCount() int { return int(atomic.LoadInt32(&f.connCount)) }

func (f *GatewayForwarder) GetClients() []ClientInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	clients := make([]ClientInfo, 0, len(f.clients))
	for addr, st := range f.clients {
		ci := ClientInfo{
			Addr:    addr,
			TxBytes: st.txBytes,
			RxBytes: st.rxBytes,
		}
		ci.TxRate, ci.RxRate = rateTick(&st.lastTx, &st.lastRx, &st.lastSample, st.txBytes, st.rxBytes, now)
		clients = append(clients, ci)
	}
	return clients
}

// ServeHTTP 由 Web 服务器的 /proxy/{name} 处理器调用，把请求反向代理到后端目标。
// 反向代理内部剥离 /proxy/{name} 前缀，使后端收到根相对路径的请求，
// 并把后端返回的 Location 重定向拼接回完整网关访问路径。
func (f *GatewayForwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr

	f.mu.Lock()
	st, ok := f.clients[clientIP]
	if !ok {
		st = &httpClientStat{}
		f.clients[clientIP] = st
	}
	f.mu.Unlock()
	atomic.AddInt32(&f.connCount, 1)
	defer func() {
		f.mu.Lock()
		delete(f.clients, clientIP)
		f.mu.Unlock()
		atomic.AddInt32(&f.connCount, -1)
	}()

	f.logger.Info(fmt.Sprintf("网关代理访问: %s %s -> %s (名称: %s)", r.Method, r.URL.Path, f.remoteAddr, f.name))

	cw := &countingResponseWriter{ResponseWriter: w, count: &f.rxBytes, stat: st, mu: &f.mu}
	cr := &countingReader{ReadCloser: r.Body, count: &f.txBytes, stat: st, mu: &f.mu}
	r.Body = cr

	f.rp.ServeHTTP(cw, r)
}

// maxHTMLRewriteSize 参与路径改写的响应体大小上限。
// 超过上限的响应不做改写、原样流式透传（避免大文件/流式响应被整体缓存甚至截断）。
const maxHTMLRewriteSize = 16 << 20 // 16MB

// bodyAndCloser 组合已读前缀与剩余响应流用于透传，同时保留原始 Close，
// 保证后端连接的响应体可被正常关闭回收。
type bodyAndCloser struct {
	io.Reader
	io.Closer
}

// urlAttrRe 匹配 HTML 中 src/href/action/poster 属性且值为根相对路径（"/..."）的情况。
var urlAttrRe = regexp.MustCompile(`(src|href|action|poster)\s*=\s*("|')(/[^"']*)("|')`)

// parseRootPrefixes 解析逗号分隔的根相对路径前缀列表（过滤空项并规范化以 / 开头）。
func parseRootPrefixes(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		out = append(out, strings.TrimRight(p, "/"))
	}
	return out
}

// normalizePathPrefix 规范化后端路径前缀：空值返回 ""；确保以 / 开头并去除尾部斜杠
// （如 "app/foo/" → "/app/foo"）。
func normalizePathPrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

// prependRootPrefix 把字符串中出现的根相对前缀 p 拼上 base，但若该处已紧跟 base
// （已拼过），则跳过，保证幂等不重复拼接。
func prependRootPrefix(s, p, base string) string {
	var sb strings.Builder
	for {
		idx := strings.Index(s, p)
		if idx < 0 {
			sb.WriteString(s)
			break
		}
		sb.WriteString(s[:idx])
		prev := idx - len(base)
		if prev >= 0 && s[prev:idx] == base {
			sb.WriteString(p) // 已带 base，不再拼
		} else {
			sb.WriteString(base)
			sb.WriteString(p)
		}
		s = s[idx+len(p):]
	}
	return sb.String()
}

// needsContentRewrite 判断响应是否需要内容路径改写：
// text/html 总是需要（根相对资源路径拼接）；配置了 sourcePrefix/rootPrefixes 时，
// JS/CSS 等文本内容中的绝对/根相对前缀也需要改写。
func needsContentRewrite(resp *http.Response, sourcePrefix string, rootPrefixes []string) bool {
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		return true
	}
	if sourcePrefix == "" && len(rootPrefixes) == 0 {
		return false
	}
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "text/css")
}

// rewriteContentBody 改写响应体中的路径引用：
//   - sourcePrefix 非空时，先把其中出现的 {sourcePrefix} 整体替换为 {publicBase}
//     （解决前端写死 /app/xxx 绝对前缀的问题，对 HTML/JS/CSS 均生效）；
//   - rootPrefixes 非空时，把其中出现的每个根相对前缀 {p} 拼上 {publicBase}
//     （解决以 window.location 拼接接口地址的问题，如 /sac → {publicBase}/sac）；
//   - text/html 额外拼接根相对资源路径（src/href="/assets/..." 加 {publicBase} 前缀）。
//
// 同时修正 Content-Length。仅处理未压缩的响应，压缩响应跳过。
func rewriteContentBody(resp *http.Response, publicBase, sourcePrefix string, rootPrefixes []string) error {
	if publicBase == "" {
		return nil
	}
	// 已知 Content-Length 且超过改写上限：无需读入判断，直接原样流式透传，
	// 避免大文件下载被整体缓存或截断。
	if resp.ContentLength > maxHTMLRewriteSize {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTMLRewriteSize+1))
	if err != nil {
		return err
	}
	// 读满上限说明响应超过改写上限（分块传输、长度未知场景）：
	// 不能截断丢弃，把已读部分与剩余未读流合并后原样透传，并保留 Close。
	if len(body) > maxHTMLRewriteSize {
		resp.Body = bodyAndCloser{
			Reader: io.MultiReader(bytes.NewReader(body), resp.Body),
			Closer: resp.Body,
		}
		return nil
	}
	resp.Body.Close()

	b := string(body)
	if sourcePrefix != "" && strings.Contains(b, sourcePrefix) {
		b = strings.ReplaceAll(b, sourcePrefix, publicBase)
	}
	for _, p := range rootPrefixes {
		if strings.Contains(b, p) {
			b = prependRootPrefix(b, p, publicBase)
		}
	}
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		b = urlAttrRe.ReplaceAllStringFunc(b, func(m string) string {
			sub := urlAttrRe.FindStringSubmatch(m)
			if len(sub) != 5 {
				return m
			}
			u := sub[3]
			// 跳过协议相对地址（//cdn.xxx）、锚点与已带前缀的路径，避免改写破坏
			if strings.HasPrefix(u, "//") || strings.HasPrefix(u, publicBase) {
				return m
			}
			return sub[1] + "=" + sub[2] + publicBase + u + sub[4]
		})
		// 内联样式中的 url(/...) 同样拼接
		for _, q := range []string{"url(/", "url('/", "url(\"/"} {
			b = strings.ReplaceAll(b, q, q[:4]+publicBase+"/")
		}
	}

	out := []byte(b)
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	// 清除分块传输标记，改用新的 Content-Length 定长发送，避免双重帧格式
	resp.TransferEncoding = nil
	resp.Header.Del("Transfer-Encoding")
	return nil
}

// redirectMaxHops 服务端跟随后端重定向的最大跳数。
const redirectMaxHops = 5

// newGatewayTransport 返回一个会在服务端跟随后端 3xx 重定向的 RoundTripper：
// GET/HEAD 请求在同一主机内的重定向（如 / 跳转 /login）由代理直接跟进并把最终
// 内容返回给浏览器，浏览器不经历 302；中间跳转返回的 Set-Cookie 会带到下一跳，
// 保证登录等流程的会话不被丢失。
func newGatewayTransport() *gatewayTransport {
	return &gatewayTransport{base: http.DefaultTransport, maxHops: redirectMaxHops}
}

type gatewayTransport struct {
	base    http.RoundTripper
	maxHops int
}

func (t *gatewayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	cur := req
	var cookies []*http.Cookie
	for hop := 0; ; hop++ {
		resp, err := base.RoundTrip(cur)
		if err != nil {
			return nil, err
		}
		loc := resp.Header.Get("Location")
		if !isRedirectCode(resp.StatusCode) || loc == "" {
			return resp, nil
		}
		// 非 GET/HEAD 不自动跟进（避免 POST 重复提交），交还 3xx 由浏览器处理
		if cur.Method != http.MethodGet && cur.Method != http.MethodHead {
			return resp, nil
		}
		next, err := cur.URL.Parse(loc)
		if err != nil {
			return resp, nil
		}
		// 仅跟随同主机重定向，避免被引到外部地址（跨主机交还浏览器）
		if !strings.EqualFold(next.Hostname(), cur.URL.Hostname()) {
			return resp, nil
		}
		cookies = append(cookies, resp.Cookies()...)
		if hop >= t.maxHops {
			// 达到跳数上限：返回当前 3xx（ModifyResponse 会改写其 Location）
			return resp, nil
		}
		// 复用连接：读完并关闭 body 后再发起下一跳
		if resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		nextReq := cur.Clone(cur.Context())
		nextReq.URL = next
		nextReq.RequestURI = ""
		for _, c := range cookies {
			nextReq.AddCookie(c)
		}
		cur = nextReq
	}
}

// isRedirectCode 判断是否为需要处理的 3xx 重定向状态码。
func isRedirectCode(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}
