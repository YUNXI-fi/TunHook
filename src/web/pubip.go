package web

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// 公网 IP 获取方式配置：方式（curl/http）与各版本的回显 URL。
// 默认使用内置 HTTP 客户端 + icanhazip 服务（不依赖系统 curl），用户可改。
type publicIPSrcCfg struct {
	Method string `json:"method"` // curl | http
	V4URL  string `json:"v4_url"`
	V6URL  string `json:"v6_url"`
}

const (
	pubipMethodKey   = "dns:pubip_method"
	pubipV4URLKey    = "dns:pubip_v4_url"
	pubipV6URLKey    = "dns:pubip_v6_url"
	defaultPubMethod = "http"
	defaultV4URL     = "https://ipv4.icanhazip.com"
	defaultV6URL     = "https://ipv6.icanhazip.com/"
)

// loadPubIPSrcCfg 读取公网 IP 获取方式配置（缺失时用默认值）。
func (s *Server) loadPubIPSrcCfg() publicIPSrcCfg {
	cfg := publicIPSrcCfg{Method: defaultPubMethod, V4URL: defaultV4URL, V6URL: defaultV6URL}
	if m, err := s.store.GetSetting(pubipMethodKey); err == nil && strings.TrimSpace(m) != "" {
		cfg.Method = strings.TrimSpace(m)
	}
	if u, err := s.store.GetSetting(pubipV4URLKey); err == nil && strings.TrimSpace(u) != "" {
		cfg.V4URL = strings.TrimSpace(u)
	}
	if u, err := s.store.GetSetting(pubipV6URLKey); err == nil && strings.TrimSpace(u) != "" {
		cfg.V6URL = strings.TrimSpace(u)
	}
	return cfg
}

// handlePublicIPConfigGet 返回当前公网 IP 获取方式配置。
func (s *Server) handlePublicIPConfigGet(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, apiOK(s.loadPubIPSrcCfg()))
}

// handlePublicIPConfigSet 保存公网 IP 获取方式配置。
func (s *Server) handlePublicIPConfigSet(w http.ResponseWriter, r *http.Request) {
	var req publicIPSrcCfg
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.Method = strings.TrimSpace(req.Method)
	if req.Method != "curl" && req.Method != "http" {
		req.Method = defaultPubMethod
	}
	req.V4URL = strings.TrimSpace(req.V4URL)
	req.V6URL = strings.TrimSpace(req.V6URL)
	if req.V4URL == "" {
		req.V4URL = defaultV4URL
	}
	if req.V6URL == "" {
		req.V6URL = defaultV6URL
	}
	_ = s.store.SetSetting(pubipMethodKey, req.Method)
	_ = s.store.SetSetting(pubipV4URLKey, req.V4URL)
	_ = s.store.SetSetting(pubipV6URLKey, req.V6URL)
	// 保存后立即刷新一次缓存结果
	s.pubIPTime = time.Time{}
	s.writeJSON(w, http.StatusOK, apiOK(req))
}

// curlFetch 用 curl 命令抓取 URL 返回的纯文本（首行），失败返回空。
// 系统不存在 curl 时（精简/容器环境常见）自动回退内置 HTTP 客户端，
// 避免「配置选了 curl 但机器没装」导致探测整体失败。
func curlFetch(url string, timeout time.Duration) string {
	if _, err := exec.LookPath("curl"); err != nil {
		return httpFetch(url, timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "curl", "-s", "--max-time", strconv.Itoa(int(timeout.Seconds())), url)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// httpFetch 用 HTTP GET 抓取 URL 返回的纯文本（首行），失败返回空。
func httpFetch(url string, timeout time.Duration) string {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	return strings.TrimSpace(string(body))
}

// validIPText 校验字符串是否为有效 IP（可选仅 IP 族），是则原样返回，否则空。
func validIPText(text string, wantV6 bool) string {
	t := strings.TrimSpace(text)
	// 兼容 curl 可能输出多行/带前缀，取首个纯 IP
	for _, tok := range strings.Fields(t) {
		ip := net.ParseIP(tok)
		if ip == nil {
			continue
		}
		if wantV6 && ip.To4() != nil {
			continue
		}
		return tok
	}
	return ""
}
