package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"hash/fnv"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============= Web 服务：反向代理 =============
//
// 支持多后端（权重 / 备用）、四种负载均衡策略、主动+被动健康检查、
// gzip 压缩、每 IP 令牌桶限流与并发限制、内存响应缓存、路径重写/重定向、
// Host 策略、WebSocket、X-Forwarded-* 与可选的 PROXY protocol v2。

const wsProxyMaxCacheEntry = 4 << 20 // 单条缓存最大 4MB

// webProxyRuntime 一个站点的反代运行时。
type webProxyRuntime struct {
	proxy     WebProxyConfig
	backends  []*webProxyBackendState
	rules     []webCompiledPathRule
	transport *http.Transport
	cache     *wsProxyCache
	limiter   *wsRateLimiter
	rr        atomic.Uint64
}

type webCompiledPathRule struct {
	rule WebPathRule
	re   *regexp.Regexp
}

// webProxyBackendState 单个后端的状态。
type webProxyBackendState struct {
	cfg         WebProxyBackend
	url         *url.URL
	mu          sync.Mutex
	fails       int
	passes      int
	pausedUntil time.Time
	healthy     bool
	active      atomic.Int64
}

func (b *webProxyBackendState) available() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.healthy {
		return false
	}
	if !b.pausedUntil.IsZero() && time.Now().Before(b.pausedUntil) {
		return false
	}
	return true
}

func (b *webProxyBackendState) recordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fails++
	b.passes = 0
	if b.fails >= 3 {
		b.fails = 0
		b.healthy = false
		b.pausedUntil = time.Now().Add(30 * time.Second)
	}
}

func (b *webProxyBackendState) recordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fails = 0
	b.passes++
	if b.passes >= 1 {
		b.healthy = true
		b.pausedUntil = time.Time{}
	}
}

func (b *webProxyBackendState) setHealth(ok bool, fails, passes int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ok {
		b.passes++
		b.fails = 0
		if b.passes >= passes {
			b.healthy = true
			b.pausedUntil = time.Time{}
			b.passes = 0
		}
		return
	}
	b.fails++
	b.passes = 0
	if b.fails >= fails {
		b.healthy = false
		b.fails = 0
	}
}

// newProxyHandler 构造反向代理处理器。
func (s *Server) newProxyHandler(site WebSite, run *webSiteRun) http.Handler {
	rt := newWebProxyRuntime(site, run)
	run.proxy = rt
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := wsClientIP(r, site.Security.TrustedProxies)

		// 路径规则：内部重写或重定向
		reqPath := r.URL.Path
		for _, rule := range rt.rules {
			if !rule.re.MatchString(reqPath) {
				continue
			}
			target := rule.re.ReplaceAllString(reqPath, rule.rule.To)
			if rule.rule.Redirect {
				if r.URL.RawQuery != "" {
					if strings.Contains(target, "?") {
						target += "&" + r.URL.RawQuery
					} else {
						target += "?" + r.URL.RawQuery
					}
				}
				code := rule.rule.Code
				if code == 0 {
					code = http.StatusFound
				}
				http.Redirect(w, r, target, code)
				return
			}
			if !strings.HasPrefix(target, "/") {
				http.Error(w, "路径重写目标无效", http.StatusInternalServerError)
				return
			}
			r = r.Clone(r.Context())
			r.URL.Path = target
			r.URL.RawPath = ""
			reqPath = target
			break
		}

		// 限流 / 并发限制
		if rt.limiter != nil {
			release, ok := rt.limiter.allow(ip)
			if !ok {
				http.Error(w, "请求过于频繁", http.StatusTooManyRequests)
				return
			}
			defer release()
		}

		upgrade := strings.EqualFold(r.Header.Get("Connection"), "upgrade") && r.Header.Get("Upgrade") != ""
		sse := strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
		cacheKey := ""
		if rt.cache != nil && !upgrade && !sse && r.Method == http.MethodGet &&
			r.Header.Get("Authorization") == "" && r.Header.Get("Cookie") == "" && r.Header.Get("Range") == "" {
			cacheKey = wsCacheKey(r)
			if entry := rt.cache.get(cacheKey); entry != nil {
				entry.write(w)
				return
			}
		}

		backend := rt.pick(ip)
		if backend == nil {
			http.Error(w, "没有可用的后端", http.StatusBadGateway)
			return
		}
		backend.active.Add(1)
		defer backend.active.Add(-1)

		target := backend.url
		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = target.Scheme
				req.URL.Host = target.Host
				req.URL.Path = wsJoinURLPath(target.Path, req.URL.Path)
				req.URL.RawPath = ""
				if site.Proxy.UseBackendHost {
					req.Host = target.Host
				}
				if site.Proxy.XForwarded {
					origHost := req.Header.Get("X-Forwarded-Host")
					if origHost == "" {
						origHost = req.Host
					}
					req.Header.Set("X-Forwarded-Host", origHost)
					req.Header.Set("X-Forwarded-Proto", wsRequestScheme(req))
					prior := req.Header.Get("X-Forwarded-For")
					if prior != "" {
						req.Header.Set("X-Forwarded-For", prior+", "+ip)
					} else {
						req.Header.Set("X-Forwarded-For", ip)
					}
				}
				applyHeaderLines(req.Header, site.ReqHeaders)
			},
			Transport: rt.transport,
			ModifyResponse: func(resp *http.Response) error {
				applyHeaderLines(resp.Header, site.RespHeaders)
				if rt.cache != nil {
					resp.Header.Set("X-Cache", "MISS")
				}
				if resp.StatusCode < 500 {
					backend.recordSuccess()
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				backend.recordFailure()
				http.Error(w, "后端不可用", http.StatusBadGateway)
			},
			FlushInterval: 100 * time.Millisecond,
		}

		// WebSocket / SSE 直接透传，避免缓存与压缩破坏流式语义
		if upgrade || sse {
			proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), wsClientIPKey{}, ip)))
			return
		}

		cw := &wsProxyCacheWriter{ResponseWriter: w, limit: wsProxyMaxCacheEntry}
		var out http.ResponseWriter = cw
		var gz *wsGzipWriter
		if site.Proxy.Compression {
			gz = &wsGzipWriter{ResponseWriter: cw, req: r}
			out = gz
		}
		proxy.ServeHTTP(out, r.WithContext(context.WithValue(r.Context(), wsClientIPKey{}, ip)))
		if gz != nil {
			_ = gz.Close()
		}
		if cacheKey != "" && rt.cache != nil {
			rt.cache.store(cacheKey, cw, site.Proxy.CacheTTL)
		}
	})
}

// status 返回后端实时状态（供前端展示）。
func (rt *webProxyRuntime) status() *webProxyStatus {
	out := &webProxyStatus{Backends: make([]webProxyBackendView, 0, len(rt.backends))}
	for _, b := range rt.backends {
		b.mu.Lock()
		paused := !b.pausedUntil.IsZero() && time.Now().Before(b.pausedUntil)
		healthy := b.healthy && !paused
		b.mu.Unlock()
		out.Backends = append(out.Backends, webProxyBackendView{
			URL: b.cfg.URL, Weight: b.cfg.Weight, Backup: b.cfg.Backup,
			Healthy: healthy, Paused: paused, Active: b.active.Load(),
		})
	}
	return out
}

// newWebProxyRuntime 构建反代运行时并启动健康检查。
func newWebProxyRuntime(site WebSite, run *webSiteRun) *webProxyRuntime {
	rt := &webProxyRuntime{proxy: site.Proxy}
	for _, b := range site.Proxy.Backends {
		u, err := url.Parse(b.URL)
		if err != nil {
			continue
		}
		rt.backends = append(rt.backends, &webProxyBackendState{cfg: b, url: u, healthy: true})
	}
	for _, r := range site.Proxy.PathRules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		rt.rules = append(rt.rules, webCompiledPathRule{rule: r, re: re})
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = site.Proxy.DisableKeepAlive
	transport.ForceAttemptHTTP2 = true
	if site.Proxy.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if site.Proxy.PROXYProtocol {
		transport.DialContext = wsDialProxyProtocol
	}
	rt.transport = transport

	if site.Proxy.CacheTTL > 0 {
		maxMB := site.Proxy.CacheMaxMB
		if maxMB <= 0 {
			maxMB = 64
		}
		rt.cache = newWSProxyCache(int64(maxMB) << 20)
	}
	if site.Proxy.RateLimit > 0 || site.Proxy.MaxConns > 0 {
		rt.limiter = newWSRateLimiter(site.Proxy.RateLimit, site.Proxy.Burst, site.Proxy.MaxConns)
	}
	if site.Proxy.HealthCheck.Enabled {
		go rt.healthLoop(run.ctx, site.Proxy.HealthCheck)
	}
	return rt
}

// pick 按策略选择一个可用后端。
func (rt *webProxyRuntime) pick(ip string) *webProxyBackendState {
	normal := rt.availableBackends(false)
	backup := rt.availableBackends(true)
	list := normal
	if len(list) == 0 {
		list = backup
	}
	if len(list) == 0 {
		// 全部不可用时，按 Gately 的语义重新尝试非备用后端
		list = rt.availableBackendsForce(false)
		if len(list) == 0 {
			list = rt.availableBackendsForce(true)
		}
	}
	if len(list) == 0 {
		return nil
	}

	// 展开权重
	weighted := make([]*webProxyBackendState, 0, len(list)*2)
	for _, b := range list {
		w := b.cfg.Weight
		if w <= 0 {
			w = 1
		}
		for i := 0; i < w; i++ {
			weighted = append(weighted, b)
		}
	}
	switch rt.proxy.LBPolicy {
	case "random":
		return weighted[rand.Intn(len(weighted))]
	case "ip_hash":
		h := fnv.New32a()
		_, _ = h.Write([]byte(ip))
		return weighted[int(h.Sum32())%len(weighted)]
	case "least_conn":
		best := weighted[0]
		bestVal := float64(best.active.Load()) / float64(maxInt(best.cfg.Weight, 1))
		for _, b := range weighted[1:] {
			v := float64(b.active.Load()) / float64(maxInt(b.cfg.Weight, 1))
			if v < bestVal {
				best = b
				bestVal = v
			}
		}
		return best
	default:
		idx := rt.rr.Add(1) - 1
		return weighted[int(idx)%len(weighted)]
	}
}

func (rt *webProxyRuntime) availableBackends(backup bool) []*webProxyBackendState {
	out := make([]*webProxyBackendState, 0, len(rt.backends))
	for _, b := range rt.backends {
		if b.cfg.Backup == backup && b.available() {
			out = append(out, b)
		}
	}
	return out
}

func (rt *webProxyRuntime) availableBackendsForce(backup bool) []*webProxyBackendState {
	out := make([]*webProxyBackendState, 0, len(rt.backends))
	for _, b := range rt.backends {
		if b.cfg.Backup == backup {
			out = append(out, b)
		}
	}
	return out
}

// healthLoop 主动健康检查。
func (rt *webProxyRuntime) healthLoop(ctx context.Context, hc WebHealthCheck) {
	interval := time.Duration(hc.Interval) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	rt.checkAll(hc)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rt.checkAll(hc)
		}
	}
}

func (rt *webProxyRuntime) checkAll(hc WebHealthCheck) {
	timeout := time.Duration(hc.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	for _, b := range rt.backends {
		ok := wsHealthCheck(b.url, hc, timeout)
		b.setHealth(ok, maxInt(hc.Fails, 1), maxInt(hc.Passes, 1))
	}
}

func wsHealthCheck(u *url.URL, hc WebHealthCheck, timeout time.Duration) bool {
	if hc.Mode == "tcp" {
		conn, err := net.DialTimeout("tcp", u.Host, timeout)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	client := &http.Client{Timeout: timeout}
	target := *u
	target.Path = hc.Path
	resp, err := client.Get(target.String())
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode < 400
}

// ---- 路径 / Header 工具 ----

func wsJoinURLPath(base, reqPath string) string {
	if base == "" {
		return reqPath
	}
	if reqPath == "" {
		return base
	}
	if strings.HasSuffix(base, "/") && strings.HasPrefix(reqPath, "/") {
		return base + reqPath[1:]
	}
	if !strings.HasSuffix(base, "/") && !strings.HasPrefix(reqPath, "/") {
		return base + "/" + reqPath
	}
	return base + reqPath
}

func wsRequestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		return v
	}
	return "http"
}

// applyHeaderLines 应用 Key: Value 头；空 Value 表示删除该头。
func applyHeaderLines(h http.Header, raw string) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if value == "" {
			h.Del(key)
		} else {
			h.Set(key, value)
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ---- 响应缓存 ----

type wsProxyCache struct {
	mu      sync.Mutex
	entries map[string]*wsProxyCacheEntry
	total   int64
	max     int64
}

type wsProxyCacheEntry struct {
	status  int
	header  http.Header
	body    []byte
	expires time.Time
}

func newWSProxyCache(max int64) *wsProxyCache {
	return &wsProxyCache{entries: map[string]*wsProxyCacheEntry{}, max: max}
}

func wsCacheKey(r *http.Request) string {
	h := sha256.Sum256([]byte(r.Host + "|" + r.URL.RequestURI() + "|" + r.Header.Get("Accept-Encoding")))
	return string(h[:])
}

func (c *wsProxyCache) get(key string) *wsProxyCacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e == nil {
		return nil
	}
	if time.Now().After(e.expires) {
		c.total -= int64(len(e.body))
		delete(c.entries, key)
		return nil
	}
	return e
}

func (c *wsProxyCache) store(key string, cw *wsProxyCacheWriter, ttl int) {
	if cw == nil || cw.overflow || cw.status != http.StatusOK || cw.body.Len() == 0 {
		return
	}
	if cw.header.Get("Set-Cookie") != "" {
		return
	}
	cc := strings.ToLower(cw.header.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") || strings.Contains(cc, "no-cache") {
		return
	}
	if strings.TrimSpace(cw.header.Get("Vary")) == "*" {
		return
	}
	seconds := ttl
	if seconds <= 0 {
		seconds = wsCacheTTLFromHeader(cw.header.Get("Cache-Control"))
	}
	if seconds <= 0 {
		return
	}
	body := append([]byte(nil), cw.body.Bytes()...)
	if int64(len(body)) > c.max/4 || int64(len(body)) > wsProxyMaxCacheEntry {
		return
	}
	entry := &wsProxyCacheEntry{
		status:  cw.status,
		header:  cw.header.Clone(),
		body:    body,
		expires: time.Now().Add(time.Duration(seconds) * time.Second),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.entries[key]; old != nil {
		c.total -= int64(len(old.body))
	}
	for c.total+int64(len(body)) > c.max && len(c.entries) > 0 {
		for k, e := range c.entries {
			c.total -= int64(len(e.body))
			delete(c.entries, k)
			break
		}
	}
	c.entries[key] = entry
	c.total += int64(len(body))
}

func wsCacheTTLFromHeader(cc string) int {
	cc = strings.ToLower(cc)
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		for _, prefix := range []string{"s-maxage=", "max-age="} {
			if strings.HasPrefix(part, prefix) {
				if n, err := strconv.Atoi(strings.TrimPrefix(part, prefix)); err == nil && n > 0 {
					return n
				}
			}
		}
	}
	return 0
}

func (e *wsProxyCacheEntry) write(w http.ResponseWriter) {
	for k, vv := range e.header {
		w.Header()[k] = append([]string(nil), vv...)
	}
	w.Header().Set("X-Cache", "HIT")
	if e.header.Get("Age") == "" {
		w.Header().Set("Age", "0")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(e.body)))
	w.WriteHeader(e.status)
	_, _ = w.Write(e.body)
}

// wsProxyCacheWriter 透传响应，同时最多捕获 4MB 用于缓存。
type wsProxyCacheWriter struct {
	http.ResponseWriter
	status   int
	header   http.Header
	body     bytes.Buffer
	overflow bool
	limit    int
	wrote    bool
}

func (w *wsProxyCacheWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.status = code
	w.header = w.ResponseWriter.Header().Clone()
	w.ResponseWriter.WriteHeader(code)
}

func (w *wsProxyCacheWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if !w.overflow {
		if w.body.Len()+len(b) <= w.limit {
			w.body.Write(b)
		} else {
			w.overflow = true
			w.body.Reset()
		}
	}
	return w.ResponseWriter.Write(b)
}

func (w *wsProxyCacheWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ---- gzip ----

type wsGzipWriter struct {
	http.ResponseWriter
	req     *http.Request
	gz      *gzip.Writer
	enabled bool
	wrote   bool
}

func (w *wsGzipWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	if code == http.StatusOK && w.shouldCompress() {
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		w.enabled = true
		w.gz = gzip.NewWriter(w.ResponseWriter)
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *wsGzipWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.enabled {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *wsGzipWriter) Close() error {
	if w.gz != nil {
		return w.gz.Close()
	}
	return nil
}

func (w *wsGzipWriter) Flush() {
	if w.gz != nil {
		_ = w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *wsGzipWriter) shouldCompress() bool {
	if !strings.Contains(strings.ToLower(w.req.Header.Get("Accept-Encoding")), "gzip") {
		return false
	}
	if w.Header().Get("Content-Encoding") != "" {
		return false
	}
	ct := strings.ToLower(w.Header().Get("Content-Type"))
	if ct == "" {
		return false
	}
	if strings.HasPrefix(ct, "text/") || strings.Contains(ct, "json") || strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "xml") || strings.Contains(ct, "svg") || strings.Contains(ct, "wasm") {
		if cl := w.Header().Get("Content-Length"); cl != "" {
			if n, err := strconv.Atoi(cl); err == nil && n < 256 {
				return false
			}
		}
		return true
	}
	return false
}

// ---- 限流 ----

type wsRateLimiter struct {
	rate     int
	burst    int
	maxConns int
	mu       sync.Mutex
	buckets  map[string]*wsTokenBucket
	conns    map[string]int
}

type wsTokenBucket struct {
	tokens float64
	last   time.Time
}

func newWSRateLimiter(rate, burst, maxConns int) *wsRateLimiter {
	if burst <= 0 {
		burst = rate + 1
	}
	return &wsRateLimiter{
		rate: rate, burst: burst, maxConns: maxConns,
		buckets: map[string]*wsTokenBucket{}, conns: map[string]int{},
	}
}

func (l *wsRateLimiter) allow(ip string) (func(), bool) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.maxConns > 0 && l.conns[ip] >= l.maxConns {
		return nil, false
	}
	if l.rate > 0 {
		b := l.buckets[ip]
		if b == nil {
			b = &wsTokenBucket{tokens: float64(l.burst), last: now}
			l.buckets[ip] = b
		}
		elapsed := now.Sub(b.last).Seconds()
		b.tokens += elapsed * float64(l.rate)
		if b.tokens > float64(l.burst) {
			b.tokens = float64(l.burst)
		}
		b.last = now
		if b.tokens < 1 {
			return nil, false
		}
		b.tokens--
	}
	if l.maxConns > 0 {
		l.conns[ip]++
	}
	return func() {
		if l.maxConns <= 0 {
			return
		}
		l.mu.Lock()
		if l.conns[ip] > 0 {
			l.conns[ip]--
		}
		if l.conns[ip] == 0 {
			delete(l.conns, ip)
		}
		l.mu.Unlock()
	}, true
}

// ---- PROXY protocol v2 ----

type wsClientIPKey struct{}

func wsDialProxyProtocol(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	srcIP, _ := ctx.Value(wsClientIPKey{}).(string)
	dstHost, dstPort, err := net.SplitHostPort(addr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	dstIP := net.ParseIP(dstHost)
	src := net.ParseIP(srcIP)
	if src == nil || dstIP == nil {
		return conn, nil
	}
	srcPort := 0
	dstPortN, _ := strconv.Atoi(dstPort)
	if _, err := conn.Write(wsProxyV2Header(src, dstIP, srcPort, dstPortN)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func wsProxyV2Header(src, dst net.IP, srcPort, dstPort int) []byte {
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	buf := bytes.NewBuffer(nil)
	buf.Write(sig)
	buf.WriteByte(0x21) // version 2, proxy command
	src4, dst4 := src.To4(), dst.To4()
	if src4 != nil && dst4 != nil {
		buf.WriteByte(0x11) // TCP over IPv4
		_ = binary.Write(buf, binary.BigEndian, uint16(12))
		buf.Write(src4)
		buf.Write(dst4)
		_ = binary.Write(buf, binary.BigEndian, uint16(srcPort))
		_ = binary.Write(buf, binary.BigEndian, uint16(dstPort))
		return buf.Bytes()
	}
	buf.WriteByte(0x21) // TCP over IPv6
	_ = binary.Write(buf, binary.BigEndian, uint16(36))
	buf.Write(src.To16())
	buf.Write(dst.To16())
	_ = binary.Write(buf, binary.BigEndian, uint16(srcPort))
	_ = binary.Write(buf, binary.BigEndian, uint16(dstPort))
	return buf.Bytes()
}
