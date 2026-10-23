package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tunhook/lolia"

	"go.uber.org/zap"
)

// ============= LoliaFrp（OAuth2 授权码模式）=============
//
// 用户在 LoliaFrp 面板自建 OAuth 应用，把 Webhook 端口回调地址
// （http(s)://IP或域名[:端口]/api/lolia）填入应用回调白名单，录入 client_id/secret 后
// 浏览器跳转授权页；LoliaFrp 带 code 回跳 Webhook 端口，服务端用 code 换 access_token 落库，
// 随后 302 回 TunHook 主界面。隧道启动走节点 TOKEN 免鉴权接口，不依赖 OAuth 令牌。

// loliaListTTL 隧道列表客户端缓存：云端状态存在缓存滞后，短缓存减少请求量，refresh=1 强刷。
const loliaListTTL = 60 * time.Second

// loliaNodesTTL 节点列表变化频率很低（上下线/负载除外），缓存 5 分钟。
const loliaNodesTTL = 5 * time.Minute

// loliaOAuthStateTTL 授权 state 有效期：覆盖「跳转授权页 → 登录同意 → 回跳」全过程。
const loliaOAuthStateTTL = 10 * time.Minute

// loliaAuthState 一次进行中的 OAuth 授权（state 防 CSRF，并记住授权完成后回跳的主界面地址）。
type loliaAuthState struct {
	ReturnURL string
	CreatedAt time.Time
}

// loliaTokenRefreshAhead access_token 到期前的提前续期窗口，避免临界点请求失败。
const loliaTokenRefreshAhead = 10 * time.Minute

// loliaClient 构造 API 客户端：先确保 access_token 有效（临近过期自动用 refresh_token 续期），
// 并注入 401 强制续期回调（时钟偏差/服务端提前失效时仍能自愈一次）。
func (s *Server) loliaClient() *lolia.Client {
	token, _ := s.ensureLoliaToken(false)
	c := lolia.NewClient(token)
	c.SetUnauthorizedHandler(func() (string, bool) {
		t, err := s.ensureLoliaToken(true)
		return t, err == nil
	})
	return c
}

// ensureLoliaToken 返回有效的 access_token。
//   - 非强制且剩余有效期 > 10 分钟：直接返回当前 token；
//   - 否则用 refresh_token 向令牌端点续期并落库（响应若轮换 refresh_token 也一并替换）；
//   - 续期失败（refresh_token 同样过期/被吊销）时清空全部凭证，前端下次拉配置即回到授权页。
//
// 由 loliaTokenMu 串行化：refresh_token 通常单次有效，并发刷新只会有一次成功。
func (s *Server) ensureLoliaToken(force bool) (string, error) {
	s.loliaTokenMu.Lock()
	defer s.loliaTokenMu.Unlock()

	s.cfgMu.RLock()
	access := s.cfg.Lolia.AccessToken
	refresh := s.cfg.Lolia.RefreshToken
	expire := s.cfg.Lolia.TokenExpire
	clientID := s.cfg.Lolia.ClientID
	clientSecret := s.cfg.Lolia.ClientSecret
	s.cfgMu.RUnlock()

	if !force && strings.TrimSpace(access) != "" &&
		expire-time.Now().Unix() > int64(loliaTokenRefreshAhead/time.Second) {
		return access, nil
	}
	if strings.TrimSpace(refresh) == "" {
		return access, errors.New("LoliaFrp 授权已失效，请重新授权")
	}
	tr, err := lolia.RefreshAccessToken(nil, clientID, clientSecret, refresh)
	if err != nil {
		// 只有令牌端点「明确拒绝」才清空凭证（refresh_token 确实失效，必须重新授权）；
		// 网络抖动、5xx、限流等临时失败必须保留凭证，否则一次连接重置就会把用户踢下线。
		if !errors.Is(err, lolia.ErrAuthRejected) {
			s.logger.Warn("LoliaFrp 令牌续期临时失败，保留现有凭证", zap.Error(err))
			return access, fmt.Errorf("LoliaFrp 令牌续期临时失败，请稍后重试：%v", err)
		}
		s.cfgMu.Lock()
		s.cfg.Lolia.AccessToken = ""
		s.cfg.Lolia.RefreshToken = ""
		s.cfg.Lolia.TokenExpire = 0
		s.cfgMu.Unlock()
		s.persistConfig("lolia.access_token", "")
		s.persistConfig("lolia.refresh_token", "")
		s.persistConfig("lolia.token_expire", 0)
		s.logger.Warn("LoliaFrp 授权已被拒绝，需要重新授权", zap.Error(err))
		return "", fmt.Errorf("LoliaFrp 登录已过期，请重新授权（%v）", err)
	}
	expireAt := expire
	if tr.ExpiresIn > 0 {
		expireAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).Unix()
	}
	newRefresh := refresh
	if strings.TrimSpace(tr.RefreshToken) != "" {
		newRefresh = strings.TrimSpace(tr.RefreshToken)
	}
	s.cfgMu.Lock()
	s.cfg.Lolia.AccessToken = tr.AccessToken
	s.cfg.Lolia.RefreshToken = newRefresh
	s.cfg.Lolia.TokenExpire = expireAt
	s.cfgMu.Unlock()
	s.persistConfig("lolia.access_token", tr.AccessToken)
	s.persistConfig("lolia.refresh_token", newRefresh)
	s.persistConfig("lolia.token_expire", expireAt)
	s.logger.Info("LoliaFrp 令牌已自动续期", zap.Int64("expiresIn", tr.ExpiresIn))
	return tr.AccessToken, nil
}

// loliaRedirectURI 推导 OAuth 回调地址（必须与 LoliaFrp 应用里登记的 redirect_uri 完全一致）。
// 优先使用用户手填的 redirect_base；否则复用 Webhook 接收器对外地址的推导规则
// （域名模式 https://域名/api/lolia；IP 模式 http://IP[:端口]/api/lolia）。
// webhook 接收端口未启用（<=0）且未手填基址时返回 ok=false。
func (s *Server) loliaRedirectURI() (string, bool) {
	s.cfgMu.RLock()
	base := strings.TrimSpace(s.cfg.Lolia.RedirectBase)
	wh := s.cfg.WebhookReceiver
	s.cfgMu.RUnlock()
	if base != "" {
		return strings.TrimRight(base, "/") + "/api/lolia", true
	}
	host := ""
	switch wh.AddrMode {
	case "domain":
		host = strings.TrimSpace(wh.AccessDomain)
		if host == "" {
			host = strings.TrimSpace(wh.ReceiveAddr)
		}
	default:
		host = strings.TrimSpace(wh.AccessIP)
		if host == "" {
			host = strings.TrimSpace(wh.ReceiveAddr)
		}
		if host == "" {
			host = strings.TrimSpace(s.localIP)
		}
	}
	if host == "" || wh.ReceivePort <= 0 {
		return "", false
	}
	if wh.AddrMode == "domain" {
		// 域名模式经 frpc 域名代理访问，端口由代理决定
		return "https://" + host + "/api/lolia", true
	}
	if wh.ReceivePort == 80 {
		return "http://" + host + "/api/lolia", true
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(wh.ReceivePort)) + "/api/lolia", true
}

// handleLoliaConfigGet 读取接入状态：OAuth 应用是否配置、是否已授权、回调地址（供复制到面板）。
func (s *Server) handleLoliaConfigGet(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	c := s.cfg.Lolia
	s.cfgMu.RUnlock()
	redirectURI, redirectOK := s.loliaRedirectURI()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"appConfigured": strings.TrimSpace(c.ClientID) != "" && strings.TrimSpace(c.ClientSecret) != "",
		"authorized":    strings.TrimSpace(c.AccessToken) != "",
		"clientId":      c.ClientID,
		"hasSecret":     strings.TrimSpace(c.ClientSecret) != "",
		"redirectBase":  c.RedirectBase,
		"redirectUri":   redirectURI,
		"redirectOk":    redirectOK,
		"tokenExpire":   c.TokenExpire,
	}))
}

// handleLoliaConfigSave 保存 OAuth 应用凭据（client_id/secret 不是账户凭据，无法远程校验，
// 仅做非空与形态校验；真正的有效性在授权换 token 时由 LoliaFrp 验证）。
func (s *Server) handleLoliaConfigSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		RedirectBase string `json:"redirectBase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("Client ID 不能为空"))
		return
	}
	base := strings.TrimSpace(req.RedirectBase)
	if base != "" {
		u, err := url.Parse(base)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			s.writeJSON(w, http.StatusBadRequest, apiErr("回调基址须为 http(s)://IP或域名[:端口] 形式"))
			return
		}
		base = strings.TrimRight(base, "/")
	}
	s.cfgMu.Lock()
	clientSecret := strings.TrimSpace(req.ClientSecret)
	// Secret 留空且此前已保存过时沿用原值（编辑其他项时无需重复输入密钥）
	if clientSecret == "" {
		clientSecret = strings.TrimSpace(s.cfg.Lolia.ClientSecret)
	}
	if clientSecret == "" {
		s.cfgMu.Unlock()
		s.writeJSON(w, http.StatusBadRequest, apiErr("Client Secret 不能为空"))
		return
	}
	s.cfg.Lolia.ClientID = clientID
	s.cfg.Lolia.ClientSecret = clientSecret
	s.cfg.Lolia.RedirectBase = base
	s.cfgMu.Unlock()
	s.persistConfig("lolia.client_id", clientID)
	s.persistConfig("lolia.client_secret", clientSecret)
	s.persistConfig("lolia.redirect_base", base)
	s.logger.Info("LoliaFrp OAuth 应用凭据已保存", zap.String("clientId", clientID))
	redirectURI, redirectOK := s.loliaRedirectURI()
	s.cfgMu.RLock()
	authorizedNow := strings.TrimSpace(s.cfg.Lolia.AccessToken) != ""
	s.cfgMu.RUnlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"appConfigured": true,
		"authorized":    authorizedNow,
		"clientId":      clientID,
		"hasSecret":     true,
		"redirectBase":  base,
		"redirectUri":   redirectURI,
		"redirectOk":    redirectOK,
	}))
}

// handleLoliaOAuthStart 生成一次性 state 并返回授权页 URL，前端用该 URL 打开新窗口/跳转。
// return_url 为授权完成后的回跳地址（前端传当前主界面地址），与 state 绑定，不经过 LoliaFrp。
func (s *Server) handleLoliaOAuthStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReturnURL string `json:"returnUrl"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.cfgMu.RLock()
	clientID := strings.TrimSpace(s.cfg.Lolia.ClientID)
	clientSecret := strings.TrimSpace(s.cfg.Lolia.ClientSecret)
	s.cfgMu.RUnlock()
	if clientID == "" || clientSecret == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请先填写 OAuth 应用的 Client ID / Secret"))
		return
	}
	redirectURI, ok := s.loliaRedirectURI()
	if !ok {
		s.writeJSON(w, http.StatusBadRequest, apiErr("回调地址不可用：请先在「Webhook」中开启接收端口，或手动填写回调基址"))
		return
	}
	// 校验 return_url 仅限同源相对路径或 http(s)，避免开放重定向
	ret := strings.TrimSpace(req.ReturnURL)
	if ret != "" {
		if u, err := url.Parse(ret); err != nil || (!strings.HasPrefix(ret, "/") && u.Scheme != "http" && u.Scheme != "https") {
			ret = ""
		}
	}
	state, err := loliaNewState()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("生成授权状态失败"))
		return
	}
	now := time.Now()
	s.loliaAuthMu.Lock()
	// 顺手清扫过期 state（用户偶尔发起，残留量极小但避免无限积累）
	for k, v := range s.loliaAuthStates {
		if now.Sub(v.CreatedAt) > loliaOAuthStateTTL {
			delete(s.loliaAuthStates, k)
		}
	}
	s.loliaAuthStates[state] = loliaAuthState{ReturnURL: ret, CreatedAt: now}
	s.loliaAuthMu.Unlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"url":         lolia.AuthorizeURL(clientID, redirectURI, state),
		"state":       state,
		"redirectUri": redirectURI,
	}))
}

// loliaNewState 生成 32 字符随机十六进制 state。
func loliaNewState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// handleLoliaOAuthCallback OAuth 授权回调（挂在 Webhook 端口的 GET /api/lolia）：
// 校验一次性 state → 用 code 换 access_token → 落库 → 302 回主界面。
// 任何失败都返回用户可读的简短 HTML 页（此时浏览器停在 webhook 端口，无前端框架可用）。
func (s *Server) handleLoliaOAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := strings.TrimSpace(q.Get("state"))
	code := strings.TrimSpace(q.Get("code"))
	if oauthErr := strings.TrimSpace(q.Get("error")); oauthErr != "" {
		desc := q.Get("error_description")
		s.loliaOAuthResultPage(w, false, "授权被拒绝："+oauthErr+" "+desc)
		return
	}
	if state == "" || code == "" {
		s.loliaOAuthResultPage(w, false, "回调参数缺失（state/code）")
		return
	}
	s.loliaAuthMu.Lock()
	st, ok := s.loliaAuthStates[state]
	if ok {
		// 一次性：无论后续成败都移除，杜绝重放
		delete(s.loliaAuthStates, state)
	}
	s.loliaAuthMu.Unlock()
	if !ok {
		s.loliaOAuthResultPage(w, false, "授权状态无效或已过期，请回到 TunHook 重新发起授权")
		return
	}
	if time.Since(st.CreatedAt) > loliaOAuthStateTTL {
		s.loliaOAuthResultPage(w, false, "授权已超时（10 分钟内有效），请重新发起")
		return
	}
	s.cfgMu.RLock()
	clientID := s.cfg.Lolia.ClientID
	clientSecret := s.cfg.Lolia.ClientSecret
	s.cfgMu.RUnlock()
	redirectURI, ok := s.loliaRedirectURI()
	if !ok {
		s.loliaOAuthResultPage(w, false, "回调地址已不可用（Webhook 端口可能已关闭）")
		return
	}
	token, err := lolia.ExchangeCode(nil, clientID, clientSecret, code, redirectURI)
	if err != nil {
		s.logger.Warn("LoliaFrp OAuth 换 token 失败", zap.Error(err))
		s.loliaOAuthResultPage(w, false, err.Error())
		return
	}
	var expireAt int64
	if token.ExpiresIn > 0 {
		expireAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).Unix()
	}
	s.cfgMu.Lock()
	s.cfg.Lolia.AccessToken = token.AccessToken
	s.cfg.Lolia.RefreshToken = token.RefreshToken
	s.cfg.Lolia.TokenExpire = expireAt
	s.cfgMu.Unlock()
	s.persistConfig("lolia.access_token", token.AccessToken)
	s.persistConfig("lolia.refresh_token", token.RefreshToken)
	s.persistConfig("lolia.token_expire", expireAt)
	// 换账户后旧列表缓存作废
	s.loliaMu.Lock()
	s.loliaList, s.loliaListAt = nil, time.Time{}
	s.loliaNodes, s.loliaNodesAt = nil, time.Time{}
	s.loliaMu.Unlock()
	s.logger.Info("LoliaFrp OAuth 授权成功", zap.String("clientId", clientID), zap.Int64("expiresIn", token.ExpiresIn))

	// 回调后必须 302 回主界面，不能把 token/JSON 留在浏览器地址栏或页面上
	target := strings.TrimSpace(st.ReturnURL)
	if target == "" {
		s.loliaOAuthResultPage(w, true, "授权成功，请回到 TunHook 的 LoliaFrp 页面刷新")
		return
	}
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	http.Redirect(w, r, target+sep+"lolia_oauth=1", http.StatusFound)
}

// loliaOAuthResultPage 输出极简结果页。回调挂在 Webhook 端口（最外层套了自定义错误页中间件，
// 非 2xx 会被替换成通用错误模板），且这是给终端用户看的页面而非 API，
// 故失败也返回 HTTP 200，由页面文案与颜色表达结果。
func (s *Server) loliaOAuthResultPage(w http.ResponseWriter, ok bool, msg string) {
	title, color := "授权成功", "var(--green,#16a34a)"
	if !ok {
		title, color = "授权失败", "#dc2626"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tip := ""
	if ok {
		tip = "授权已完成，TunHook 页面将自动识别并加载隧道列表；本窗口即将自动关闭。"
	}
	fmt.Fprintf(w, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s · TunHook × LoliaFrp</title>
<style>body{margin:0;font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#0f1115;color:#e5e7eb;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#171a21;border:1px solid #262b36;border-radius:14px;padding:34px 38px;max-width:440px;text-align:center;box-shadow:0 12px 40px rgba(0,0,0,.4)}
h2{margin:0 0 10px;font-size:18px;color:%s}.m{font-size:13px;color:#9aa3b2;line-height:1.7;word-break:break-all}
.t{font-size:12px;color:#6b7280;margin-top:10px;line-height:1.6}
a{display:inline-block;margin-top:16px;color:#6ea8fe;text-decoration:none;font-size:13px}</style></head>
<body><div class="card"><h2>%s</h2><div class="m">%s</div><div class="t">%s</div>
<script>if(window.opener){try{window.opener.postMessage({type:'lolia-oauth',ok:%t},'*')}catch(e){}setTimeout(function(){window.close()},1200)}else{setTimeout(function(){window.close()},4000)}</script>
</div></body></html>`, title, color, title, msg, tip, ok)
}

// handleLoliaOAuthDisconnect 清除授权令牌（保留 OAuth 应用凭据，便于重新授权）。
func (s *Server) handleLoliaOAuthDisconnect(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.Lock()
	s.cfg.Lolia.AccessToken = ""
	s.cfg.Lolia.RefreshToken = ""
	s.cfg.Lolia.TokenExpire = 0
	s.cfgMu.Unlock()
	s.persistConfig("lolia.access_token", "")
	s.persistConfig("lolia.refresh_token", "")
	s.persistConfig("lolia.token_expire", 0)
	s.writeJSON(w, http.StatusOK, apiMsg("已解除 LoliaFrp 授权"))
}

// handleLoliaUser 获取当前授权账户信息（流量额度 / KYC / 隧道配额，页面加载与刷新用）。
func (s *Server) handleLoliaUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.loliaClient().UserInfo()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("获取用户信息失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(user))
}

// handleLoliaTunnels 获取隧道列表（60s 缓存，refresh=1 强刷；本地在跑的 inactive 隧道兜底修正为 active）。
func (s *Server) handleLoliaTunnels(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("refresh") == "1"
	s.loliaMu.Lock()
	list, at := s.loliaList, s.loliaListAt
	if force || list == nil || time.Since(at) > loliaListTTL {
		tunnels, err := s.loliaClient().AllTunnels()
		if err != nil {
			s.loliaMu.Unlock()
			s.writeJSON(w, http.StatusOK, apiErr("获取隧道列表失败: "+err.Error()))
			return
		}
		s.loliaList, s.loliaListAt = tunnels, time.Now()
		list, at = s.loliaList, s.loliaListAt
	}
	s.loliaMu.Unlock()

	tunnels := make([]lolia.Tunnel, len(list))
	copy(tunnels, list)
	running := s.loliaRun.Running()
	var localNames map[string]bool
	if running {
		localNames = s.loliaRun.ProxyNames()
	}
	for i := range tunnels {
		t := &tunnels[i]
		if running && t.Status != "active" && localNames[t.Name] {
			t.Status = "active"
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"tunnels":  tunnels,
		"cachedAt": at.UnixMilli(),
	}))
}

// handleLoliaNodes 获取节点列表（5 分钟缓存，refresh=1 强刷；含负载/协议/KYC/备案等 lolia 独有字段）。
func (s *Server) handleLoliaNodes(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("refresh") == "1"
	s.loliaMu.Lock()
	nodes, at := s.loliaNodes, s.loliaNodesAt
	if force || nodes == nil || time.Since(at) > loliaNodesTTL {
		ns, err := s.loliaClient().AllNodes()
		if err != nil {
			s.loliaMu.Unlock()
			s.writeJSON(w, http.StatusOK, apiErr("获取节点列表失败: "+err.Error()))
			return
		}
		s.loliaNodes, s.loliaNodesAt = ns, time.Now()
		nodes, at = s.loliaNodes, s.loliaNodesAt
	}
	s.loliaMu.Unlock()
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"nodes":    nodes,
		"cachedAt": at.UnixMilli(),
	}))
}

// loliaStartWithNames 拉取最新隧道列表，补齐节点 TOKEN 后拉配置启动（手动启动与自启共用）。
// 同节点（node_id 相同）还必须同 tunnel_token——服务端按 token 分组合并配置。
func (s *Server) loliaStartWithNames(names []string) error {
	s.cfgMu.RLock()
	accessToken := s.cfg.Lolia.AccessToken
	s.cfgMu.RUnlock()
	if strings.TrimSpace(accessToken) == "" {
		return fmt.Errorf("尚未授权 LoliaFrp 账户")
	}
	cli := lolia.NewClient(accessToken)
	tunnels, err := cli.AllTunnels()
	if err != nil {
		return err
	}
	byName := map[string]lolia.Tunnel{}
	for _, t := range tunnels {
		byName[t.Name] = t
	}
	picked := make([]lolia.Tunnel, 0, len(names))
	for _, name := range names {
		t, ok := byName[name]
		if !ok {
			return fmt.Errorf("隧道 %s 不存在或已被删除", name)
		}
		picked = append(picked, t)
	}
	return s.loliaStartTunnels(cli, picked)
}

// loliaStartTunnels 校验同节点/同节点 TOKEN、拉取服务端合并配置并启动 frpc。
// 列表未带 tunnel_token 时逐条调详情补取（列表接口不保证返回该字段）。
func (s *Server) loliaStartTunnels(cli *lolia.Client, picked []lolia.Tunnel) error {
	nodeID := picked[0].NodeID
	for _, t := range picked[1:] {
		if t.NodeID != nodeID {
			return fmt.Errorf("所选隧道分布在不同节点，frpc 单进程只能连接一个节点")
		}
	}
	ids := make([]string, 0, len(picked))
	nodeToken := ""
	for i := range picked {
		t := picked[i]
		token := strings.TrimSpace(t.TunnelToken)
		if token == "" {
			detail, err := cli.TunnelDetail(t.Name)
			if err != nil {
				return fmt.Errorf("获取隧道 %s 的节点 TOKEN 失败: %w", t.Name, err)
			}
			token = strings.TrimSpace(detail.TunnelToken)
			t = *detail
			picked[i] = t
		}
		if token == "" {
			return fmt.Errorf("隧道 %s 缺少节点 TOKEN，无法启动", t.Name)
		}
		if nodeToken == "" {
			nodeToken = token
		} else if token != nodeToken {
			return fmt.Errorf("所选隧道的节点 TOKEN 不一致（非同节点凭据），无法合并启动")
		}
		ids = append(ids, strconv.FormatInt(t.ID, 10))
	}
	config, err := cli.FrpcConfig(nodeToken, ids)
	if err != nil {
		return err
	}
	if s.loliaRun.Running() {
		if err := s.loliaRun.Stop(); err != nil {
			return err
		}
	}
	return s.loliaRun.Start(s.frpcMgr.BinPath(), config)
}

// handleLoliaStart 启动选中的隧道：强刷列表 → 存在性/同节点校验 → 并入同节点旧隧道 → 拉配置启动。
func (s *Server) handleLoliaStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Names []string `json:"names"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	req.Names = normalizeNames(req.Names)
	if len(req.Names) == 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请先选择要启动的隧道"))
		return
	}
	tunnels, err := s.loliaClient().AllTunnels()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("获取隧道列表失败: "+err.Error()))
		return
	}
	s.loliaMu.Lock()
	s.loliaList, s.loliaListAt = tunnels, time.Now()
	s.loliaMu.Unlock()

	byName := map[string]lolia.Tunnel{}
	for _, t := range tunnels {
		byName[t.Name] = t
	}
	picked := make([]lolia.Tunnel, 0, len(req.Names))
	nodeID := int64(-1)
	for _, name := range req.Names {
		t, ok := byName[name]
		if !ok {
			s.writeJSON(w, http.StatusOK, apiErr("隧道不存在或已被删除，请刷新后重试"))
			return
		}
		if nodeID < 0 {
			nodeID = t.NodeID
		} else if t.NodeID != nodeID {
			s.writeJSON(w, http.StatusOK, apiErr("所选隧道分布在不同节点，frpc 单进程只能连接一个节点，请选择同一节点的隧道"))
			return
		}
		picked = append(picked, t)
	}
	// 已在运行：并入同节点的旧隧道，避免重启丢掉其他在跑隧道
	wasRunning := s.loliaRun.Running()
	if wasRunning {
		s.cfgMu.RLock()
		existing := append([]string(nil), s.cfg.Lolia.AutostartNames...)
		s.cfgMu.RUnlock()
		inSet := map[string]bool{}
		for _, t := range picked {
			inSet[t.Name] = true
		}
		for _, name := range existing {
			if inSet[name] {
				continue
			}
			if t, ok := byName[name]; ok && t.NodeID == nodeID {
				picked = append(picked, t)
				inSet[name] = true
			}
		}
	}
	if err := s.loliaStartTunnels(s.loliaClient(), picked); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("启动失败: "+err.Error()))
		return
	}
	names := make([]string, 0, len(picked))
	for _, t := range picked {
		names = append(names, t.Name)
	}
	s.cfgMu.Lock()
	s.cfg.Lolia.AutostartNames = names
	s.cfgMu.Unlock()
	s.persistConfig("lolia.autostart_names", names)
	msg := "LoliaFrp 隧道已启动"
	if wasRunning {
		msg = "LoliaFrp frpc 已重启，正在重新注册隧道"
	}
	s.writeJSON(w, http.StatusOK, apiMsg(msg))
}

// normalizeNames 去空白、去重并保序。
func normalizeNames(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, n := range in {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// handleLoliaTunnelDetail 隧道详情（GET /api/lolia/tunnel/{name}）。
// 编辑弹窗用它拿到列表接口不返回的 config 高级配置（传输协议/Proxy Protocol/AutoTLS 等）。
func (s *Server) handleLoliaTunnelDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if strings.TrimSpace(name) == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少隧道名称"))
		return
	}
	t, err := s.loliaClient().TunnelDetail(name)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(t))
}

// handleLoliaTunnelCreate 创建隧道（POST /api/lolia/tunnels）。
// 节点是否支持该协议、KYC/备案要求、远程端口占用等均由 LoliaFrp 服务端校验，错误原样透传。
func (s *Server) handleLoliaTunnelCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID       int64  `json:"node_id"`
		Type         string `json:"type"`
		LocalIP      string `json:"local_ip"`
		LocalPort    int    `json:"local_port"`
		RemotePort   int    `json:"remote_port"`
		CustomDomain string `json:"custom_domain"`
		Remark       string `json:"remark"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	req.LocalIP = strings.TrimSpace(req.LocalIP)
	if req.NodeID <= 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请选择节点"))
		return
	}
	switch req.Type {
	case "tcp", "udp", "http":
	default:
		s.writeJSON(w, http.StatusBadRequest, apiErr("隧道类型仅支持 tcp / udp / http"))
		return
	}
	if req.LocalIP == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("本地地址不能为空"))
		return
	}
	if req.LocalPort < 1 || req.LocalPort > 65535 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("本地端口须在 1-65535 之间"))
		return
	}
	// 远程端口：留空(0)由服务端自动分配可用端口（lolia 官方机制，已实测）；
	// 用户显式填写时校验范围，占用/超范围等由服务端二次校验并原样返回错误。
	if req.RemotePort < 0 || req.RemotePort > 65535 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("远程端口须在 1-65535 之间，或留空自动分配"))
		return
	}
	t, err := s.loliaClient().CreateTunnel(lolia.CreateTunnelReq{
		NodeID:       req.NodeID,
		Type:         req.Type,
		LocalIP:      req.LocalIP,
		LocalPort:    req.LocalPort,
		RemotePort:   req.RemotePort,
		CustomDomain: strings.TrimSpace(req.CustomDomain),
		Remark:       strings.TrimSpace(req.Remark),
	})
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(s.loliaWriteErr(err)))
		return
	}
	s.loliaMu.Lock()
	s.loliaList, s.loliaListAt = nil, time.Time{}
	s.loliaMu.Unlock()
	s.logger.Info("LoliaFrp 隧道已创建", zap.Int64("id", t.ID), zap.String("name", t.Name), zap.String("type", t.Type))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"message": "隧道创建成功", "tunnel": t}))
}

// handleLoliaTunnelUpdate 编辑隧道（PUT）：可改本地地址/端口、域名、备注、AutoTLS；
// 节点/类型/远程端口/名称服务端不支持修改。403/权限不足时提示重新授权（需 tunnel:write）。
func (s *Server) handleLoliaTunnelUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if strings.TrimSpace(name) == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少隧道名称"))
		return
	}
	var req struct {
		LocalIP              string `json:"local_ip"`
		LocalPort            int    `json:"local_port"`
		CustomDomain         string `json:"custom_domain"`
		Remark               string `json:"remark"`
		Type                 string `json:"type"` // 隧道类型，决定哪些高级配置可提交
		Protocol             string `json:"protocol"`
		ProxyProtocolVersion string `json:"proxy_protocol_version"`
		AutoTLS              *bool  `json:"auto_tls"`
		HTTPRedirect         *bool  `json:"http_redirect"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	req.LocalIP = strings.TrimSpace(req.LocalIP)
	if req.LocalIP == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("本地地址不能为空"))
		return
	}
	if req.LocalPort < 1 || req.LocalPort > 65535 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("本地端口须在 1-65535 之间"))
		return
	}
	ttype := strings.ToLower(strings.TrimSpace(req.Type))
	// 高级配置：传输协议（tcp/kcp）与 Proxy Protocol（关闭/v1/v2）对所有隧道类型适用
	proto := strings.ToLower(strings.TrimSpace(req.Protocol))
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "kcp" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("传输协议仅支持 tcp / kcp"))
		return
	}
	pp := strings.ToLower(strings.TrimSpace(req.ProxyProtocolVersion))
	if pp != "" && pp != "v1" && pp != "v2" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("Proxy Protocol 仅支持关闭 / v1 / v2"))
		return
	}
	cfg := &lolia.TunnelUpdateExtra{Protocol: proto, ProxyProtocolVersion: pp}
	// AutoTLS 仅 http/https 可设置；HTTP 自动跳转仅 https（均需 lolia 定制内核）
	if ttype == "http" || ttype == "https" {
		cfg.AutoTLS = req.AutoTLS
	}
	if ttype == "https" {
		cfg.HTTPRedirect = req.HTTPRedirect
	}
	up := lolia.TunnelUpdate{
		LocalIP:      req.LocalIP,
		LocalPort:    req.LocalPort,
		CustomDomain: strings.TrimSpace(req.CustomDomain),
		Remark:       strings.TrimSpace(req.Remark),
		Config:       cfg,
	}
	if err := s.loliaClient().UpdateTunnel(name, up); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(s.loliaWriteErr(err)))
		return
	}
	// 列表缓存立即作废，保证下次刷新拿到新值
	s.loliaMu.Lock()
	s.loliaList, s.loliaListAt = nil, time.Time{}
	s.loliaMu.Unlock()
	s.logger.Info("LoliaFrp 隧道已更新", zap.String("name", name))
	s.writeJSON(w, http.StatusOK, apiMsg("隧道已更新，云端状态同步可能有短暂延迟"))
}

// handleLoliaTunnelDelete 删除隧道（DELETE）。若本地 frpc 正在运行且配置含该隧道，
// 不强行打断进程，仅在响应中提示重启后生效（下次启动集合已不再包含已删除隧道）。
func (s *Server) handleLoliaTunnelDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if strings.TrimSpace(name) == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少隧道名称"))
		return
	}
	if err := s.loliaClient().DeleteTunnel(name); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(s.loliaWriteErr(err)))
		return
	}
	s.loliaMu.Lock()
	s.loliaList, s.loliaListAt = nil, time.Time{}
	s.loliaMu.Unlock()
	stillRunning := false
	if s.loliaRun.Running() && s.loliaRun.ProxyNames()[name] {
		stillRunning = true
		// 从自启集合移除，避免下次自动启动时引用已删除隧道导致整体启动失败
		s.cfgMu.Lock()
		kept := s.cfg.Lolia.AutostartNames[:0]
		for _, n := range s.cfg.Lolia.AutostartNames {
			if n != name {
				kept = append(kept, n)
			}
		}
		s.cfg.Lolia.AutostartNames = kept
		s.cfgMu.Unlock()
		s.persistConfig("lolia.autostart_names", kept)
	}
	msg := "隧道已删除"
	if stillRunning {
		msg += "；本地 frpc 仍加载着旧配置，停止后重新启动即生效"
	}
	s.logger.Info("LoliaFrp 隧道已删除", zap.String("name", name), zap.Bool("stillRunning", stillRunning))
	s.writeJSON(w, http.StatusOK, apiMsg(msg))
}

// handleLoliaDomainsGet 获取域名白名单（GET /api/lolia/domains）。
func (s *Server) handleLoliaDomainsGet(w http.ResponseWriter, r *http.Request) {
	domains, err := s.loliaClient().AllDomains()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("获取域名列表失败: "+s.loliaAuthHint(err)))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"domains": domains}))
}

// loliaAuthHint 对 401/403/权限类错误附加可操作的重新授权引导（读、写接口通用）。
func (s *Server) loliaAuthHint(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "403") || strings.Contains(msg, "401") ||
		strings.Contains(strings.ToLower(msg), "scope") || strings.Contains(msg, "权限") {
		return msg + "（当前授权缺少所需权限，请点击「OAuth 配置」重新授权一次）"
	}
	return msg
}

// handleLoliaDomainAdd 添加域名（POST /api/lolia/domains）。
// 返回服务端生成的验证信息（子域/Token/Cloudflare 一键链接），前端据此引导用户完成 DNS 验证。
func (s *Server) handleLoliaDomainAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Remark string `json:"remark"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	if req.Domain == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请填写域名"))
		return
	}
	if !loliaDomainRe.MatchString(req.Domain) {
		s.writeJSON(w, http.StatusBadRequest, apiErr("域名格式不正确（示例：example.com，无需 http:// 前缀）"))
		return
	}
	d, err := s.loliaClient().AddDomain(req.Domain, strings.TrimSpace(req.Remark))
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(s.loliaWriteErr(err)))
		return
	}
	s.logger.Info("LoliaFrp 域名已添加", zap.String("domain", d.Domain), zap.Int64("id", d.ID))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"message": "域名已添加，请按提示完成 DNS 验证", "domain": d}))
}

// handleLoliaDomainVerify 请求服务端校验域名 DNS 记录（POST /api/lolia/domains/verify）。
// 记录尚未生效等业务结果通过 msg 透传；is_verified 为最终是否通过。
func (s *Server) handleLoliaDomainVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体解析失败"))
		return
	}
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	if req.Domain == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少域名"))
		return
	}
	res, err := s.loliaClient().VerifyDomain(req.Domain)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(s.loliaWriteErr(err)))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"result": res}))
}

// handleLoliaDomainDelete 删除域名（DELETE /api/lolia/domain/{id}）。
func (s *Server) handleLoliaDomainDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的域名 ID"))
		return
	}
	if err := s.loliaClient().DeleteDomain(id); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(s.loliaWriteErr(err)))
		return
	}
	s.logger.Info("LoliaFrp 域名已删除", zap.Int64("id", id))
	s.writeJSON(w, http.StatusOK, apiMsg("域名已删除"))
}

// loliaDomainRe 宽松的域名格式校验：两级以上、标签为字母数字连字符、无协议/路径/端口。
var loliaDomainRe = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

// loliaWriteErr 写接口（编辑/删除/域名管理）失败时，对权限不足给出可操作的重新授权提示。
func (s *Server) loliaWriteErr(err error) string {
	return s.loliaAuthHint(err)
}

// handleLoliaStop 停止隧道：
//   - 不带 names（或为空）：停止整个 frpc 进程并清空自启列表（手动停止 = 不随服务自启）；
//   - 带 names：仅从当前运行集合摘除指定隧道。剩余为空等价整体停止；剩余非空则用剩余隧道重启 frpc。
//
// 摘除不能复用 handleLoliaStart 的"并入同节点旧隧道"逻辑——那会把要停的隧道重新加回来，
// 故这里直接基于自启集合做差集，再走 loliaStartWithNames 重启。
func (s *Server) handleLoliaStop(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Names []string `json:"names"`
	}
	// 兼容无 body 的全局停止（旧前端行为），忽略解析错误
	_ = json.NewDecoder(r.Body).Decode(&req)
	req.Names = normalizeNames(req.Names)

	if len(req.Names) == 0 {
		if err := s.loliaRun.Stop(); err != nil {
			s.writeJSON(w, http.StatusOK, apiErr("停止失败: "+err.Error()))
			return
		}
		s.cfgMu.Lock()
		s.cfg.Lolia.AutostartNames = nil
		s.cfgMu.Unlock()
		s.persistConfig("lolia.autostart_names", []string{})
		s.writeJSON(w, http.StatusOK, apiMsg("LoliaFrp 隧道已停止"))
		return
	}

	// 单条/多条摘除：仅对当前运行集合中的隧道生效
	if !s.loliaRun.Running() {
		s.writeJSON(w, http.StatusOK, apiErr("隧道未在运行"))
		return
	}
	remove := make(map[string]bool, len(req.Names))
	for _, n := range req.Names {
		remove[n] = true
	}
	s.cfgMu.Lock()
	kept := make([]string, 0, len(s.cfg.Lolia.AutostartNames))
	hit := false
	for _, n := range s.cfg.Lolia.AutostartNames {
		if remove[n] {
			hit = true
			continue
		}
		kept = append(kept, n)
	}
	s.cfgMu.Unlock()
	if !hit {
		s.writeJSON(w, http.StatusOK, apiErr("隧道未在运行"))
		return
	}

	if len(kept) == 0 {
		if err := s.loliaRun.Stop(); err != nil {
			s.writeJSON(w, http.StatusOK, apiErr("停止失败: "+err.Error()))
			return
		}
		s.cfgMu.Lock()
		s.cfg.Lolia.AutostartNames = nil
		s.cfgMu.Unlock()
		s.persistConfig("lolia.autostart_names", []string{})
		s.writeJSON(w, http.StatusOK, apiMsg("隧道已停止"))
		return
	}

	if err := s.loliaStartWithNames(kept); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("停止失败: "+err.Error()))
		return
	}
	s.cfgMu.Lock()
	s.cfg.Lolia.AutostartNames = append([]string(nil), kept...)
	s.cfgMu.Unlock()
	s.persistConfig("lolia.autostart_names", kept)
	s.logger.Info("LoliaFrp 隧道已摘除并重启剩余隧道", zap.Strings("kept", kept))
	s.writeJSON(w, http.StatusOK, apiMsg("隧道已停止，frpc 已重启加载剩余隧道"))
}

// handleLoliaStatus 本地 frpc 进程状态 + 当前加载的隧道 name 列表（前端勾选状态用）。
func (s *Server) handleLoliaStatus(w http.ResponseWriter, r *http.Request) {
	names := []string{}
	if s.loliaRun.Running() {
		for n := range s.loliaRun.ProxyNames() {
			names = append(names, n)
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"running": s.loliaRun.Running(),
		"pid":     s.loliaRun.PID(),
		"names":   names,
	}))
}

// handleLoliaLog 返回 frpc 日志末尾 n 行（默认 200，上限 2000）。
func (s *Server) handleLoliaLog(w http.ResponseWriter, r *http.Request) {
	n := 200
	if v := r.URL.Query().Get("lines"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 2000 {
			n = parsed
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"log": s.loliaRun.LogTail(n),
	}))
}
