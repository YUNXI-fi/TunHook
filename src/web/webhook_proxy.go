package web

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ============= Webhook 代理模式 =============
// 通道访问方式的四类代理实现（对应「访问方式」选项）：
//   - proxy：反向代理 —— 服务网关透明转发，保持请求头信息完整性，支持路径重写与 WebSocket 升级
//   - html：  HTML 重写代理 —— 完整网页内嵌，HTML 内容解析 + 资源路径重写 + 运行时 XHR/fetch 路径适配
//   - cors：  CORS 接口代理 —— 前端跨域接口中转，自定义 CORS 响应头 + 请求/响应数据透传
//   - ws：    WebSocket 隧道代理 —— 长连接通用流量转发（复用 ReverseProxy 的 Upgrade 隧道机制）

// whProxyClient 代理上游请求的 HTTP 客户端（忽略自签名证书；30s 超时；连接复用）。
var whProxyClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		// 上游多为穿透设备的公网地址，可能使用自签名/过期证书，忽略校验
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		// 自建 Transport 的零值不设握手超时，上游 TLS 握手挂起时会长期滞留 goroutine
		TLSHandshakeTimeout: 10 * time.Second,
	},
}

// whProxyError 代理失败统一错误处理：记录失败、输出友好提示（超时/连接失败/无效响应等）。
func (s *Server) whProxyError(w http.ResponseWriter, channelID string, err error) {
	s.whRecv.recordAccess(channelID, false)
	s.logger.Warn("[Webhook代理] "+channelID+" 代理失败", zap.Error(err))
	s.writeJSON(w, http.StatusBadGateway, map[string]any{
		"error":      "代理请求失败: " + err.Error(),
		"hint":       "请检查目标服务是否在线、网络是否可达，稍后重试",
		"channel_id": channelID,
	})
}

// whHopHeaders 逐跳头（不应透传给上游/下游）。
var whHopHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true,
}

// isWhHopHeader 判断是否为逐跳头。
func isWhHopHeader(k string) bool {
	return whHopHeaders[strings.ToLower(k)]
}

// copyHeaders 复制响应头（排除逐跳头）。
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		if isWhHopHeader(k) {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// whReverseProxy 构建反向代理（透明转发 + 路径重写，支持 WebSocket Upgrade）。
// 返回代理实例与「是否已记录结果」标记（ErrorHandler 记失败后，调用方据此避免重复记成功）。
func (s *Server) whReverseProxy(channelID, scheme, host, subpath string) (*httputil.ReverseProxy, *bool) {
	target, err := url.Parse(scheme + "://" + host)
	if err != nil {
		return nil, nil
	}
	proxied := false
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// 保留原始请求路径与查询串，仅把监听前缀替换为目标子路径
			pr.SetURL(target)
			pr.Out.URL.Path = subpath
			pr.Out.Host = host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if !proxied {
				proxied = true
				s.whRecv.recordAccess(channelID, false)
			}
			s.logger.Warn("[Webhook代理] "+channelID+" 代理失败", zap.Error(err))
			s.writeJSON(w, http.StatusBadGateway, map[string]any{
				"error":      "代理请求失败: " + err.Error(),
				"hint":       "请检查目标服务是否在线、网络是否可达，稍后重试",
				"channel_id": channelID,
			})
		},
	}
	return proxy, &proxied
}

// ============= HTML 重写代理 =============

// whSkipURLRe 不需要重写的 URL 前缀（外部协议 / 锚点 / 协议相对地址）。
var whSkipURLRe = regexp.MustCompile(`(?i)^(https?:|data:|javascript:|mailto:|tel:|#|//)`)

// whAttrURLRe 匹配 HTML 属性中的 URL（href/src/action/poster）。
var whAttrURLRe = regexp.MustCompile(`(?i)(\s(?:href|src|action|poster)\s*=\s*["'])([^"'\s>]*)(["'])`)

// whSrcsetAttrRe 匹配 srcset 属性（响应式图片）。
var whSrcsetAttrRe = regexp.MustCompile(`(?i)(\ssrcset\s*=\s*["'])([^"']+)(["'])`)
var whSrcsetURLRe = regexp.MustCompile(`(/\S*[^\s,])|([^\s,"']+)`)

// whDirOf 返回路径所在目录（用于解析相对 URL）："/dir/page" -> "/dir/"；根路径返回 "/"。
func whDirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i+1]
	}
	return "/"
}

// whRewriteHTML 重写 HTML 内所有资源 URL：根相对路径与相对路径统一加上代理前缀，
// 使页面引用的 css/js/图片/接口都经由 /wh/{channel_id}/ 加载，实现完整网页内嵌。
func whRewriteHTML(html, proxyBase, baseDir string) string {
	if proxyBase == "" {
		return html
	}
	html = whAttrURLRe.ReplaceAllStringFunc(html, func(match string) string {
		sm := whAttrURLRe.FindStringSubmatch(match)
		if len(sm) != 4 {
			return match
		}
		before, rawURL, after := sm[1], strings.TrimSpace(sm[2]), sm[3]
		if rawURL == "" || whSkipURLRe.MatchString(rawURL) {
			return match
		}
		if strings.HasPrefix(rawURL, proxyBase) {
			return match // 已重写，避免重复前缀
		}
		var newPath string
		if strings.HasPrefix(rawURL, "/") {
			newPath = rawURL
		} else {
			// 相对路径：相对当前页面目录解析，并规范化 ../ 等段
			newPath = path.Clean(baseDir + rawURL)
			if !strings.HasPrefix(newPath, "/") {
				newPath = "/" + newPath
			}
		}
		return before + proxyBase + newPath + after
	})
	html = whSrcsetAttrRe.ReplaceAllStringFunc(html, func(match string) string {
		sm := whSrcsetAttrRe.FindStringSubmatch(match)
		if len(sm) != 4 {
			return match
		}
		before, srcset, after := sm[1], sm[2], sm[3]
		rewritten := whSrcsetURLRe.ReplaceAllStringFunc(srcset, func(u string) string {
			u = strings.TrimSpace(u)
			if u == "" || whSkipURLRe.MatchString(u) {
				return u
			}
			if strings.HasPrefix(u, proxyBase) {
				return u
			}
			var newPath string
			if strings.HasPrefix(u, "/") {
				newPath = u
			} else {
				newPath = path.Clean(baseDir + u)
				if !strings.HasPrefix(newPath, "/") {
					newPath = "/" + newPath
				}
			}
			return proxyBase + newPath
		})
		return before + rewritten + after
	})
	return html
}

// whAdaptationScript 运行时交互适配脚本：页面内通过 XHR/fetch 动态请求的根相对路径
// 同样改写为代理路径，保证内嵌页面交互（接口调用）也能穿透。
func whAdaptationScript(proxyBase string) string {
	return `<script>(function(){var p="` + proxyBase + `";function f(u){if(typeof u==="string"&&u.charAt(0)==="/"&&u.indexOf(p)!==0)return p+u;return u}var x=window.XMLHttpRequest&&XMLHttpRequest.prototype.open;if(x)XMLHttpRequest.prototype.open=function(m,u){arguments[1]=f(u);return x.apply(this,arguments)};var y=window.fetch;if(y)window.fetch=function(i,o){if(typeof i==="string")i=f(i);return y.call(this,i,o)}})();</script>`
}

// whServeHTMLProxy HTML 重写代理入口：抓取目标 HTML 并重写资源路径，其余内容流式透传。
func (s *Server) whServeHTMLProxy(w http.ResponseWriter, r *http.Request, channelID, scheme, host, subpath string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.whProxyError(w, channelID, fmt.Errorf("HTML 重写代理仅支持 GET/HEAD 请求"))
		return
	}
	target := scheme + "://" + host + subpath
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		s.whProxyError(w, channelID, err)
		return
	}
	if ua := r.UserAgent(); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := whProxyClient.Do(req)
	if err != nil {
		s.whProxyError(w, channelID, err)
		return
	}
	defer resp.Body.Close()

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	// 上游返回 5xx：视为无效响应，给出友好提示
	if resp.StatusCode >= 500 {
		s.whProxyError(w, channelID, fmt.Errorf("目标服务返回 %d", resp.StatusCode))
		return
	}
	// 非 HTML（css/js/图片/字体等）：流式透传
	if !strings.Contains(contentType, "text/html") {
		copyHeaders(w.Header(), resp.Header)
		w.Header().Set("X-Webhook-Proxy", "html")
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			s.logger.Warn("[Webhook代理] "+channelID+" 透传失败", zap.Error(err))
		}
		s.whRecv.recordAccess(channelID, true)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.whProxyError(w, channelID, err)
		return
	}
	proxyBase := "/wh/" + channelID
	baseDir := whDirOf(subpath)
	rewritten := whRewriteHTML(string(body), proxyBase, baseDir)
	// 注入运行时路径适配脚本（放在 </body> 前；无则追加到末尾）
	adapt := whAdaptationScript(proxyBase)
	if idx := strings.LastIndex(rewritten, "</body>"); idx >= 0 {
		rewritten = rewritten[:idx] + adapt + rewritten[idx:]
	} else {
		rewritten += adapt
	}
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("X-Webhook-Proxy", "html-rewrite")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(rewritten)); err != nil {
		s.logger.Warn("[Webhook代理] "+channelID+" 响应写入失败", zap.Error(err))
	}
	s.whRecv.recordAccess(channelID, true)
}

// ============= CORS 接口代理 =============

// whWriteCORSHeaders 写入 CORS 响应头（允许任意来源跨域访问该代理接口）。
func whWriteCORSHeaders(h http.Header) {
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, Origin, X-Webhook-Secret")
	h.Set("Access-Control-Max-Age", "86400")
}

// whServeCORSProxy CORS 接口代理：跨域中转，附加 CORS 响应头，透传请求方法/请求头/响应体。
func (s *Server) whServeCORSProxy(w http.ResponseWriter, r *http.Request, channelID, scheme, host, subpath string) {
	// 浏览器跨域预检请求：直接返回 CORS 头
	if r.Method == http.MethodOptions {
		whWriteCORSHeaders(w.Header())
		w.WriteHeader(http.StatusNoContent)
		s.whRecv.recordAccess(channelID, true)
		return
	}
	target := scheme + "://" + host + subpath
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	out, err := http.NewRequest(r.Method, target, r.Body)
	if err != nil {
		s.whProxyError(w, channelID, err)
		return
	}
	// 透传关键请求头（Content-Type、Authorization、自定义头等），排除逐跳头
	for k, vv := range r.Header {
		if isWhHopHeader(k) {
			continue
		}
		for _, v := range vv {
			out.Header.Add(k, v)
		}
	}
	resp, err := whProxyClient.Do(out)
	if err != nil {
		s.whProxyError(w, channelID, err)
		return
	}
	defer resp.Body.Close()

	whWriteCORSHeaders(w.Header())
	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("X-Webhook-Proxy", "cors")
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		s.logger.Warn("[Webhook代理] "+channelID+" CORS 转发失败", zap.Error(err))
	}
	s.whRecv.recordAccess(channelID, true)
}
