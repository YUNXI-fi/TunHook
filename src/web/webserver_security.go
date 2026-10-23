package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"html"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ============= Web 服务：认证与访问控制 =============
//
// 每个站点独立维护认证失败计数与封禁列表（内存态，站点重启后清零）。
// 认证方式：none / basic / web。web 登录使用 HMAC 签名的 Cookie，不依赖服务端会话表。
// 临时分享链接可在开启认证后让特定访客免登录访问，支持有效期、使用次数与路径前缀。

// wsCookieKey 进程级 Cookie 签名密钥；重启后旧会话自动失效。
var wsCookieKey = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败属于系统级异常；退回固定值只影响会话签名强度，不应阻断启动
		return []byte("tunhook-webserver-cookie-key")
	}
	return b
}()

// wsAuthFail 单个 IP 的认证失败计数。
type wsAuthFail struct {
	Count int
	First time.Time
}

// wrapWebSecurity 对站点请求执行封禁、IP / 国家过滤与认证。
func (s *Server) wrapWebSecurity(site WebSite, run *webSiteRun, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := wsClientIP(r, site.Security.TrustedProxies)
		clean := path.Clean("/" + r.URL.Path)
		authMode, ipMode, ipList := wsEffectiveSecurity(site.Security, clean)
		// 放行名单优先：跳过封禁、IP 黑白名单与地区过滤，但不跳过认证。
		allowIP := wsIPInList(ip, site.Security.IPAllow)

		if !allowIP && run.wsBanned(ip) {
			http.Error(w, "访问已被暂时禁止", http.StatusForbidden)
			return
		}
		if !wsIPAllowed(ip, ipMode, ipList, site.Security.IPAllow) {
			http.Error(w, "访问被拒绝", http.StatusForbidden)
			return
		}
		if !allowIP && !s.wsGeoAllowed(site.Security, ip) {
			http.Error(w, "当前地区不允许访问", http.StatusForbidden)
			return
		}
		if authMode == "" || authMode == "none" {
			next.ServeHTTP(w, r)
			return
		}

		// 临时分享链接：查询参数兑换后重定向；Cookie 已持有则直接放行
		bypass, handled := s.wsTempShareBypass(site, r, w)
		if handled {
			return
		}
		if bypass {
			next.ServeHTTP(w, r)
			return
		}

		switch authMode {
		case "basic":
			if s.wsCheckBasicAuth(site, run, ip, r) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="TunHook Web 服务"`)
			http.Error(w, "需要认证", http.StatusUnauthorized)
		case "web":
			s.wsHandleWebAuth(site, run, ip, w, r, next)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// wsEffectiveSecurity 按最长路径前缀覆盖站点的认证 / IP 设置。
func wsEffectiveSecurity(sec WebSecurityConfig, reqPath string) (authMode, ipMode, ipList string) {
	authMode = sec.AuthMode
	ipMode = sec.IPMode
	ipList = sec.IPList
	if authMode == "" {
		authMode = "none"
	}
	if ipMode == "" {
		ipMode = "off"
	}

	best := -1
	for _, rule := range sec.PathRules {
		if !wsPathPrefixMatch(reqPath, rule.Prefix) {
			continue
		}
		if len(rule.Prefix) <= best {
			continue
		}
		best = len(rule.Prefix)
		if rule.AuthMode != "" {
			if rule.AuthMode == "on" {
				authMode = sec.AuthMode
				if authMode == "" {
					authMode = "none"
				}
			} else {
				authMode = rule.AuthMode
			}
		}
		if rule.IPMode != "" {
			ipMode = rule.IPMode
			ipList = rule.IPList
		}
	}
	return authMode, ipMode, ipList
}

// wsPathPrefixMatch 按路径段边界匹配前缀：/admin 匹配 /admin 与 /admin/x，不匹配 /administrator。
func wsPathPrefixMatch(reqPath, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	prefix = strings.TrimRight(prefix, "/")
	if !strings.HasPrefix(reqPath, prefix) {
		return false
	}
	return len(reqPath) == len(prefix) || reqPath[len(prefix)] == '/'
}

// wsIPAllowed 按白名单 / 黑名单判断 IP 是否放行；放行名单始终优先。
func wsIPAllowed(rawIP, mode, list, allowList string) bool {
	if wsIPInList(rawIP, allowList) {
		return true
	}
	if mode == "" || mode == "off" {
		return true
	}
	ip := net.ParseIP(rawIP)
	if ip == nil {
		return mode != "allow"
	}
	for _, line := range strings.Split(list, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if n := ipToNet(line); n != nil && n.Contains(ip) {
			return mode == "allow"
		}
	}
	return mode == "deny"
}

// wsIPInList 判断 IP 是否命中列表；支持单个 IP 与 CIDR 网段。
func wsIPInList(rawIP, list string) bool {
	if strings.TrimSpace(list) == "" {
		return false
	}
	ip := net.ParseIP(rawIP)
	if ip == nil {
		return false
	}
	for _, line := range strings.Split(list, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if n := ipToNet(line); n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// wsCountryNames 两位 ISO 码 → 中文国家名（与 geoloc 国家库的命名保持一致）。
var wsCountryNames = map[string]string{
	"CN": "中国", "US": "美国", "JP": "日本", "KR": "韩国", "GB": "英国",
	"DE": "德国", "FR": "法国", "RU": "俄罗斯", "IN": "印度", "SG": "新加坡",
	"HK": "中国香港", "TW": "中国台湾", "MO": "中国澳门", "CA": "加拿大",
	"AU": "澳大利亚", "BR": "巴西", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
	"IT": "意大利", "ES": "西班牙", "AE": "阿联酋", "SA": "沙特阿拉伯",
	"ID": "印度尼西亚", "TH": "泰国", "MY": "马来西亚", "VN": "越南",
	"PH": "菲律宾", "TR": "土耳其", "PL": "波兰", "UA": "乌克兰",
	"AR": "阿根廷", "MX": "墨西哥", "ZA": "南非", "EG": "埃及",
}

// wsGeoAllowed 按国家 / 地区过滤；数据库未就绪、私网地址或无法识别的地址一律放行。
func (s *Server) wsGeoAllowed(sec WebSecurityConfig, rawIP string) bool {
	if sec.GeoMode == "" || sec.GeoMode == "off" {
		return true
	}
	if s.geo == nil || !s.geo.Ready() {
		return true
	}
	ip := net.ParseIP(rawIP)
	if ip == nil || isPrivateIP(ip) {
		return true
	}
	loc := s.geo.Lookup(ip.String())
	if loc == "" {
		return true
	}
	country := strings.Fields(loc)[0]
	allowed := map[string]bool{}
	for _, code := range strings.Split(sec.GeoCountries, ",") {
		code = strings.TrimSpace(code)
		if name, ok := wsCountryNames[code]; ok {
			allowed[name] = true
		} else {
			allowed[code] = true
		}
	}
	in := allowed[country]
	if sec.GeoMode == "allow" {
		return in
	}
	return !in
}

// wsCheckBasicAuth 校验 HTTP Basic 认证；失败时计入失败次数。
func (s *Server) wsCheckBasicAuth(site WebSite, run *webSiteRun, ip string, r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok || !wsValidateUser(site.Security.Users, user, pass) {
		run.wsRecordAuthFail(ip, site.Security)
		return false
	}
	run.wsClearAuthFail(ip)
	return true
}

// wsValidateUser 校验 username:password 列表；密码支持 bcrypt 哈希。
func wsValidateUser(users, user, pass string) bool {
	for _, line := range strings.Split(users, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		u, p, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(u) != user {
			continue
		}
		if strings.HasPrefix(p, "$2a$") || strings.HasPrefix(p, "$2b$") || strings.HasPrefix(p, "$2y$") {
			return bcrypt.CompareHashAndPassword([]byte(p), []byte(pass)) == nil
		}
		return subtle.ConstantTimeCompare([]byte(p), []byte(pass)) == 1
	}
	return false
}

// wsHandleWebAuth 处理 Web 登录页、登录提交、退出与已登录请求。
func (s *Server) wsHandleWebAuth(site WebSite, run *webSiteRun, ip string, w http.ResponseWriter, r *http.Request, next http.Handler) {
	if r.URL.Path == "/__tunhook/logout" {
		wsClearSession(w, site.ID)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if r.URL.Path == "/__tunhook/login" {
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			user := strings.TrimSpace(r.PostFormValue("username"))
			pass := r.PostFormValue("password")
			if wsValidateUser(site.Security.Users, user, pass) {
				run.wsClearAuthFail(ip)
				wsSetSession(w, site.ID, user)
				nextURL := r.PostFormValue("next")
				if nextURL == "" || !strings.HasPrefix(nextURL, "/") || strings.HasPrefix(nextURL, "//") {
					nextURL = "/"
				}
				http.Redirect(w, r, nextURL, http.StatusFound)
				return
			}
			run.wsRecordAuthFail(ip, site.Security)
			wsRenderLogin(w, site, r.URL.Query().Get("next"), "用户名或密码错误", http.StatusUnauthorized)
			return
		}
		wsRenderLogin(w, site, r.URL.Query().Get("next"), "", http.StatusOK)
		return
	}

	if user, ok := wsParseSession(site.ID, r); ok && user != "" {
		next.ServeHTTP(w, r)
		return
	}

	// API / JSON 请求直接返回 401，避免把登录页当接口响应
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"error":"需要登录"}`))
		return
	}
	wsRenderLogin(w, site, r.URL.RequestURI(), "", http.StatusOK)
}

// wsSitePathPrefix 返回路径模式站点的访问前缀；端口模式返回空串。
func wsSitePathPrefix(site WebSite) string {
	if site.AccessMode != "path" {
		return ""
	}
	return strings.TrimRight(site.PathPrefix, "/")
}

// wsRenderLogin 输出站点登录页。
func wsRenderLogin(w http.ResponseWriter, site WebSite, next, errMsg string, status int) {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	title := html.EscapeString(site.Name)
	// 路径模式下登录表单必须提交到带站点前缀的地址，否则会落到统一端口根路径。
	loginAction := html.EscapeString(wsSitePathPrefix(site) + "/__tunhook/login")
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="err">` + html.EscapeString(errMsg) + `</div>`
	}
	page := `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + title + ` · 登录</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#070c12;color:#e6eef8;font-family:'Segoe UI',system-ui,sans-serif}
.card{width:min(380px,calc(100vw - 32px));background:#0d151f;border:1px solid #1e2c3a;border-radius:14px;padding:28px 26px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:18px}.mark{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,#4dd6ff,#a78bfa);display:flex;align-items:center;justify-content:center;color:#04121a;font-weight:800}
h1{font-size:17px;margin:0}.sub{font-size:11px;color:#8094ab;margin-top:3px}
label{display:block;font-size:11.5px;color:#a3b4c8;margin:12px 0 5px}
input{width:100%;height:38px;border:1px solid #4a6075;border-radius:8px;background:#0a1119;color:#e6eef8;padding:0 11px;font-size:13px;outline:none}
input:focus{border-color:#4dd6ff;box-shadow:0 0 0 2px rgba(77,214,255,.12)}
button{width:100%;height:40px;margin-top:18px;border:none;border-radius:8px;background:#0b7e9c;color:#fff;font-size:13px;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.08)}
.err{margin-top:12px;padding:8px 10px;border:1px solid rgba(245,141,141,.35);background:rgba(245,141,141,.08);color:#f58d8d;border-radius:7px;font-size:12px}
.tip{margin-top:14px;font-size:10.5px;color:#8094ab;line-height:1.6}
</style></head><body><form class="card" method="post" action="` + loginAction + `">
<div class="brand"><div class="mark">T</div><div><h1>` + title + `</h1><div class="sub">TunHook Web 服务 · 需要登录</div></div></div>` + errHTML + `
<label for="u">用户名</label><input id="u" name="username" autocomplete="username" required autofocus>
<label for="p">密码</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<input type="hidden" name="next" value="` + html.EscapeString(next) + `">
<button type="submit">登录</button>
<div class="tip">此站点启用了访问认证。登录状态最多保持 24 小时。</div>
</form></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(page))
}

// wsSessionCookieName 单个站点的登录 Cookie 名。
func wsSessionCookieName(siteID string) string { return "tunhook_ws_" + siteID }

// wsSetSession 写入 HMAC 签名的登录 Cookie。
func wsSetSession(w http.ResponseWriter, siteID, user string) {
	exp := time.Now().Add(24 * time.Hour)
	payload := siteID + "|" + user + "|" + strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, wsCookieKey)
	_, _ = mac.Write([]byte(payload))
	value := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + hex.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{
		Name:     wsSessionCookieName(siteID),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
		MaxAge:   86400,
	})
}

// wsParseSession 校验登录 Cookie，返回用户名。
func wsParseSession(siteID string, r *http.Request) (string, bool) {
	c, err := r.Cookie(wsSessionCookieName(siteID))
	if err != nil || c.Value == "" {
		return "", false
	}
	raw, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return "", false
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, wsCookieKey)
	_, _ = mac.Write(data)
	if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig)) {
		return "", false
	}
	parts := strings.Split(string(data), "|")
	if len(parts) != 3 || parts[0] != siteID {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	return parts[1], true
}

// wsClearSession 清除登录 Cookie。
func wsClearSession(w http.ResponseWriter, siteID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     wsSessionCookieName(siteID),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// wsFailKey 归一化失败计数与封禁的键：IPv4 用单个地址，IPv6 聚合到 /64，
// 避免同一前缀下的地址轮换绕过自动封禁。
func wsFailKey(rawIP string) string {
	ip := net.ParseIP(strings.TrimSpace(rawIP))
	if ip == nil {
		return rawIP
	}
	if ip.To4() != nil {
		return ip.String()
	}
	mask := net.CIDRMask(64, 128)
	return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
}

// wsBanned 判断 IP 是否在封禁期内。
func (r *webSiteRun) wsBanned(rawIP string) bool {
	ip := wsFailKey(rawIP)
	r.secMu.Lock()
	defer r.secMu.Unlock()
	until, ok := r.bans[ip]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(r.bans, ip)
		return false
	}
	return true
}

// wsRecordAuthFail 记录认证失败，达到阈值后按配置自动封禁。
func (r *webSiteRun) wsRecordAuthFail(rawIP string, sec WebSecurityConfig) {
	// 放行名单中的 IP 不计失败次数，避免被自动封禁。
	if wsIPInList(rawIP, sec.IPAllow) {
		return
	}
	ip := wsFailKey(rawIP)
	now := time.Now()
	limit := sec.FailLimit
	if limit <= 0 {
		limit = 10
	}
	window := time.Duration(sec.FailWindow) * time.Minute
	if window <= 0 {
		window = 15 * time.Minute
	}
	r.secMu.Lock()
	defer r.secMu.Unlock()
	if r.fails == nil {
		r.fails = map[string]*wsAuthFail{}
	}
	if r.bans == nil {
		r.bans = map[string]time.Time{}
	}
	f := r.fails[ip]
	if f == nil || now.Sub(f.First) > window {
		f = &wsAuthFail{First: now}
		r.fails[ip] = f
	}
	f.Count++
	if f.Count >= limit {
		if sec.AutoBanMinutes > 0 {
			r.bans[ip] = now.Add(time.Duration(sec.AutoBanMinutes) * time.Minute)
		}
		delete(r.fails, ip)
	}
}

// wsClearAuthFail 认证成功后清除失败计数。
func (r *webSiteRun) wsClearAuthFail(rawIP string) {
	ip := wsFailKey(rawIP)
	r.secMu.Lock()
	if r.fails != nil {
		delete(r.fails, ip)
	}
	r.secMu.Unlock()
}

// wsBanSnapshot 返回当前封禁列表。
func (r *webSiteRun) wsBanSnapshot() []map[string]interface{} {
	r.secMu.Lock()
	defer r.secMu.Unlock()
	now := time.Now()
	out := make([]map[string]interface{}, 0, len(r.bans))
	for ip, until := range r.bans {
		if now.After(until) {
			delete(r.bans, ip)
			continue
		}
		out = append(out, map[string]interface{}{
			"ip":           ip,
			"until":        until.Format("2006-01-02 15:04:05"),
			"seconds_left": int(time.Until(until).Seconds()),
		})
	}
	return out
}

// wsUnban 解除指定 IP 的封禁。
func (r *webSiteRun) wsUnban(rawIP string) {
	ip := wsFailKey(rawIP)
	r.secMu.Lock()
	if r.bans != nil {
		delete(r.bans, ip)
	}
	r.secMu.Unlock()
}

// wsTempShareBypass 处理临时分享链接：返回 (是否放行, 是否已处理并写出响应)。
func (s *Server) wsTempShareBypass(site WebSite, r *http.Request, w http.ResponseWriter) (bool, bool) {
	if len(site.TempShares) == 0 {
		return false, false
	}
	clean := path.Clean("/" + r.URL.Path)
	if token := strings.TrimSpace(r.URL.Query().Get("_gs")); token != "" {
		link := wsFindTempShare(site, token)
		if link == nil || !wsTempShareActive(*link, clean, true) {
			return false, false
		}
		s.wsConsumeTempShare(site.ID, link.ID)
		wsSetTempShareCookie(w, site.ID, token, link.ExpiresAt)
		q := r.URL.Query()
		q.Del("_gs")
		target := r.URL.Path
		if enc := q.Encode(); enc != "" {
			target += "?" + enc
		}
		http.Redirect(w, r, target, http.StatusFound)
		return false, true
	}
	if c, err := r.Cookie(wsTempShareCookieName(site.ID)); err == nil && c.Value != "" {
		link := wsFindTempShare(site, c.Value)
		if link != nil && wsTempShareActive(*link, clean, false) {
			return true, false
		}
	}
	return false, false
}

// wsFindTempShare 按 token 查找临时分享链接。
func wsFindTempShare(site WebSite, token string) *WebTempShare {
	for i := range site.TempShares {
		if subtle.ConstantTimeCompare([]byte(site.TempShares[i].Token), []byte(token)) == 1 {
			return &site.TempShares[i]
		}
	}
	return nil
}

// wsTempShareActive 判断临时分享链接是否可用（有效期 / 次数 / 路径前缀）。
func wsTempShareActive(link WebTempShare, reqPath string, enforceUses bool) bool {
	if enforceUses && link.MaxUses > 0 && link.Used >= link.MaxUses {
		return false
	}
	if strings.TrimSpace(link.ExpiresAt) != "" {
		exp, err := parseWebTime(link.ExpiresAt)
		if err != nil || time.Now().After(exp) {
			return false
		}
	}
	if link.PathPrefix != "" && !wsPathPrefixMatch(reqPath, link.PathPrefix) {
		return false
	}
	return true
}

// wsConsumeTempShare 增加临时链接使用次数并持久化。
func (s *Server) wsConsumeTempShare(siteID, shareID string) {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	for i := range s.wsSites {
		if s.wsSites[i].ID != siteID {
			continue
		}
		for j := range s.wsSites[i].TempShares {
			if s.wsSites[i].TempShares[j].ID == shareID {
				s.wsSites[i].TempShares[j].Used++
				_ = s.wsPersistLocked()
				return
			}
		}
	}
}

// wsTempShareCookieName 临时分享 Cookie 名。
func wsTempShareCookieName(siteID string) string { return "tunhook_share_" + siteID }

// wsSetTempShareCookie 写入临时分享 Cookie。
func wsSetTempShareCookie(w http.ResponseWriter, siteID, token, expiresAt string) {
	exp := time.Now().Add(24 * time.Hour)
	if strings.TrimSpace(expiresAt) != "" {
		if t, err := parseWebTime(expiresAt); err == nil && t.Before(exp) {
			exp = t
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     wsTempShareCookieName(siteID),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
		MaxAge:   int(time.Until(exp).Seconds()),
	})
}

// wsBuildURL 保留原始查询参数并拼接路径，用于登录回跳。
func wsBuildURL(u *url.URL) string {
	out := u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}
