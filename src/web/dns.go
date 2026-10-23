// 域名解析模块：通过已配置的 DNS 服务商账户（阿里云/腾讯云 DNSPod/华为云/Cloudflare）
// 进行解析记录的统一管理（列域名、列/增/改/删记录），并提供 DDNS 动态解析。
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"tunhook/forward"
	"tunhook/store"
)

// dnsManagerFor 按账户名取出该账户，并创建对应服务商的通用记录管理器。
func (s *Server) dnsManagerFor(account string) (*store.DNSAccount, *forward.DNSRecordManager, error) {
	accounts, err := s.store.ListDNSAccounts()
	if err != nil {
		return nil, nil, fmt.Errorf("读取 DNS 账户失败: %w", err)
	}
	for i := range accounts {
		if strings.EqualFold(accounts[i].Name, account) {
			m, err := forward.NewDNSRecordManager(accounts[i].Provider, accounts[i].Credentials)
			if err != nil {
				return &accounts[i], nil, err
			}
			return &accounts[i], &m, nil
		}
	}
	return nil, nil, fmt.Errorf("DNS 账户不存在: %s", account)
}

// handleDNSDomains 列出某账户下全部域名。
func (s *Server) handleDNSDomains(w http.ResponseWriter, r *http.Request) {
	account := strings.TrimSpace(r.URL.Query().Get("account"))
	if account == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少账户名"))
		return
	}
	_, mgr, err := s.dnsManagerFor(account)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	domains, err := (*mgr).ListDomains(ctx)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(domains))
}

// handleDNSAllDomains 汇总所有 DNS 账户下的域名，返回 [{account, provider, name}]。
// 供「绑定域名」下拉跨账户挑选：/api/dns/domains 必须逐个账户请求，前端不便聚合。
// 单个账户不可用（凭据失效/接口报错）时跳过该账户，不影响其余账户的结果。
func (s *Server) handleDNSAllDomains(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.store.ListDNSAccounts()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("读取 DNS 账户失败: "+err.Error()))
		return
	}
	out := []map[string]string{}
	for i := range accounts {
		mgr, err := forward.NewDNSRecordManager(accounts[i].Provider, accounts[i].Credentials)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		domains, err := mgr.ListDomains(ctx)
		cancel()
		if err != nil {
			continue
		}
		for _, d := range domains {
			name := strings.TrimSpace(d.Name)
			if name == "" {
				continue
			}
			out = append(out, map[string]string{
				"account":  accounts[i].Name,
				"provider": accounts[i].Provider,
				"name":     name,
			})
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(out))
}

// handleDNSDomainPicks 返回“解析到指定 frp 服务器 IP”的域名列表，
// 供转发隧道弹窗快捷选择根域名（选择后用户输入的内容作为子域名）。
// server 参数为 frps 服务器地址（IP 或域名）；无 DNS 账号或无可匹配域名时返回空数组。
func (s *Server) handleDNSDomainPicks(w http.ResponseWriter, r *http.Request) {
	server := strings.TrimSpace(r.URL.Query().Get("server"))
	if server == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少服务器地址"))
		return
	}
	// 期望命中的服务器 IP 集合：IP 直接使用，域名先解析为 IP
	targets := map[string]bool{}
	if net.ParseIP(server) != nil {
		targets[server] = true
	} else {
		ips, err := net.LookupHost(server)
		if err != nil {
			s.writeJSON(w, http.StatusOK, apiOK([]map[string]string{}))
			return
		}
		for _, ip := range ips {
			if ip = strings.TrimSpace(ip); ip != "" {
				targets[ip] = true
			}
		}
	}
	if len(targets) == 0 {
		s.writeJSON(w, http.StatusOK, apiOK([]map[string]string{}))
		return
	}
	accounts, err := s.store.ListDNSAccounts()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("读取 DNS 账户失败: "+err.Error()))
		return
	}
	out := []map[string]string{}
	for i := range accounts {
		mgr, err := forward.NewDNSRecordManager(accounts[i].Provider, accounts[i].Credentials)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		domains, err := mgr.ListDomains(ctx)
		if err != nil {
			cancel()
			continue
		}
		for _, d := range domains {
			name := strings.TrimSpace(d.Name)
			if name == "" {
				continue
			}
			// 全部域名都返回并附带解析状态：已解析的排前面，未解析的明确标注但同样可选，
			// 选中后由前端在创建代理时补写「该隧道实际用到的那条主机记录」
			out = append(out, map[string]string{
				"account":  accounts[i].Name,
				"provider": accounts[i].Provider,
				"name":     name,
				"status":   domainMatchStatus(ctx, mgr, name, targets),
			})
		}
		cancel()
	}
	// 排序：泛域名解析 > 主域名解析 > 暂未解析；同状态按域名升序，便于查找
	rank := map[string]int{"wildcard": 0, "root": 1, "pending": 2}
	sort.SliceStable(out, func(a, b int) bool {
		ra, rb := rank[out[a]["status"]], rank[out[b]["status"]]
		if ra != rb {
			return ra < rb
		}
		return out[a]["name"] < out[b]["name"]
	})
	s.writeJSON(w, http.StatusOK, apiOK(out))
}

// domainMatchStatus 返回该域名相对目标 frp 服务器地址（targets）的解析状态：
//
//	"wildcard" 存在启用态的 * 记录指向目标 —— 该域名下任意子域名都开箱可用
//	"root"     只有 @ 记录指向目标 —— 主域名可用，子域名需另行解析
//	"pending"  两者都没有 —— 由 TunHook 在创建代理时补写实际用到的那条主机记录
//
// 以本模块的解析记录为准：frp 虚拟主机的典型配置是把 *.example.com 泛解析到 frps，
// 此时根域名自身并不解析到 frps —— 只查根域名的公网解析会把这类（正确）配置整批漏掉。
// 记录接口不可用（凭据失效/权限不足/网络异常）时退回公网解析根域名，命中按 "root" 处理。
func domainMatchStatus(ctx context.Context, mgr forward.DNSRecordManager, domain string, targets map[string]bool) string {
	recs, err := mgr.ListRecords(ctx, domain)
	if err == nil {
		hasRoot := false
		for _, rec := range recs {
			rr := strings.TrimSpace(rec.Name)
			if rr != "@" && rr != "*" {
				continue
			}
			switch strings.ToUpper(strings.TrimSpace(rec.Status)) {
			case "DISABLE", "DISABLED":
				continue
			}
			matched := false
			switch strings.ToUpper(strings.TrimSpace(rec.Type)) {
			case "A", "AAAA":
				matched = targets[strings.TrimSpace(rec.Value)]
			case "CNAME":
				v := strings.TrimSuffix(strings.TrimSpace(rec.Value), ".")
				if ips, e := net.LookupHost(v); e == nil {
					for _, ip := range ips {
						if targets[ip] {
							matched = true
							break
						}
					}
				}
			}
			if !matched {
				continue
			}
			if rr == "*" {
				return "wildcard"
			}
			hasRoot = true
		}
		if hasRoot {
			return "root"
		}
		return "pending"
	}
	if ips, e := net.LookupHost(domain); e == nil {
		for _, ip := range ips {
			if targets[ip] {
				return "root"
			}
		}
	}
	return "pending"
}

// handleDNSRecords 列出某账户下指定域名的全部记录。
func (s *Server) handleDNSRecords(w http.ResponseWriter, r *http.Request) {
	account := strings.TrimSpace(r.URL.Query().Get("account"))
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if account == "" || domain == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少账户名或域名"))
		return
	}
	_, mgr, err := s.dnsManagerFor(account)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	recs, err := (*mgr).ListRecords(ctx, domain)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(recs))
}

// handleDNSRecordAdd 新增解析记录。
func (s *Server) handleDNSRecordAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
		Domain  string `json:"domain"`
		RR      string `json:"rr"`
		Type    string `json:"type"`
		Value   string `json:"value"`
		TTL     int    `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.Account = strings.TrimSpace(req.Account)
	req.Domain = strings.TrimSpace(req.Domain)
	req.RR = strings.TrimSpace(req.RR)
	req.Type = strings.ToUpper(strings.TrimSpace(req.Type))
	req.Value = strings.TrimSpace(req.Value)
	if req.Account == "" || req.Domain == "" || req.Value == "" {
		s.writeJSON(w, http.StatusOK, apiErr("请填写账户、域名与记录值"))
		return
	}
	if req.Type == "" {
		req.Type = "A"
	}
	_, mgr, err := s.dnsManagerFor(req.Account)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id, err := (*mgr).AddRecord(ctx, req.Domain, req.RR, req.Type, req.Value, req.TTL)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]string{"id": id}))
}

// handleDNSRecordUpdate 修改解析记录。
func (s *Server) handleDNSRecordUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
		Domain  string `json:"domain"`
		ID      string `json:"id"`
		RR      string `json:"rr"`
		Type    string `json:"type"`
		Value   string `json:"value"`
		TTL     int    `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.Account = strings.TrimSpace(req.Account)
	req.Domain = strings.TrimSpace(req.Domain)
	req.RR = strings.TrimSpace(req.RR)
	req.Type = strings.ToUpper(strings.TrimSpace(req.Type))
	if req.Account == "" || req.Domain == "" || req.ID == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少账户、域名或记录 ID"))
		return
	}
	if req.Type == "" {
		req.Type = "A"
	}
	_, mgr, err := s.dnsManagerFor(req.Account)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := (*mgr).UpdateRecord(ctx, req.Domain, req.ID, req.RR, req.Type, req.Value, req.TTL); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]string{"id": req.ID}))
}

// handleDNSRecordDelete 删除解析记录。
func (s *Server) handleDNSRecordDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
		Domain  string `json:"domain"`
		ID      string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.Account = strings.TrimSpace(req.Account)
	req.Domain = strings.TrimSpace(req.Domain)
	if req.Account == "" || req.Domain == "" || req.ID == "" {
		s.writeJSON(w, http.StatusOK, apiErr("缺少账户、域名或记录 ID"))
		return
	}
	_, mgr, err := s.dnsManagerFor(req.Account)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := (*mgr).DeleteRecord(ctx, req.Domain, req.ID); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]string{"id": req.ID}))
}

// ============= DDNS 任务管理 =============

func (s *Server) handleDDNSList(w http.ResponseWriter, r *http.Request) {
	tasks, err := s.store.ListDDNSTasks()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("读取 DDNS 任务失败: "+err.Error()))
		return
	}
	if tasks == nil {
		tasks = []store.DDNSTask{}
	}
	s.writeJSON(w, http.StatusOK, apiOK(tasks))
}

func (s *Server) handleDDNSAdd(w http.ResponseWriter, r *http.Request) {
	var t store.DDNSTask
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	// 校验：账户存在 + 域名合法
	if _, _, err := s.dnsManagerFor(t.Account); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	if t.Domain == "" {
		s.writeJSON(w, http.StatusOK, apiErr("请填写域名"))
		return
	}
	id, err := s.store.AddDDNSTask(t)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("保存 DDNS 任务失败: "+err.Error()))
		return
	}
	s.logger.Info("DDNS 任务已添加", zap.String("id", strconv.FormatInt(id, 10)), zap.String("domain", t.Domain))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]int64{"id": id}))
}

func (s *Server) handleDDNSUpdate(w http.ResponseWriter, r *http.Request) {
	var t store.DDNSTask
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if t.ID == 0 {
		s.writeJSON(w, http.StatusOK, apiErr("缺少任务 ID"))
		return
	}
	if _, _, err := s.dnsManagerFor(t.Account); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	if t.Domain == "" {
		s.writeJSON(w, http.StatusOK, apiErr("请填写域名"))
		return
	}
	if err := s.store.UpdateDDNSTask(t); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("保存 DDNS 任务失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]int64{"id": t.ID}))
}

func (s *Server) handleDDNSToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      int64 `json:"id"`
		Enabled bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if err := s.store.SetDDNSTaskEnabled(req.ID, req.Enabled); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("更新任务状态失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]int64{"id": req.ID}))
}

func (s *Server) handleDDNSDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	if err := s.store.DeleteDDNSTask(req.ID); err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("删除 DDNS 任务失败: "+err.Error()))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]int64{"id": req.ID}))
}

// handleDDNSNow 立即执行一次所有启用任务的同步（前端「立即更新」按钮）。
func (s *Server) handleDDNSNow(w http.ResponseWriter, r *http.Request) {
	tasks, err := s.store.ListDDNSTasks()
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr("读取 DDNS 任务失败: "+err.Error()))
		return
	}
	res := map[string]string{}
	for _, t := range tasks {
		if !t.Enabled {
			continue
		}
		res[t.Name+":"+strconv.FormatInt(t.ID, 10)] = s.runDDNSTask(t)
	}
	s.writeJSON(w, http.StatusOK, apiOK(res))
}

// resolveSourceIP 计算指定来源（public=公网 / local=本机网卡）的 IP 地址。
func (s *Server) resolveSourceIP(ipSrc, iface, addrMode string) string {
	mode := strings.ToLower(addrMode)
	if mode == "" {
		mode = "v4"
	}
	if strings.ToLower(ipSrc) == "local" {
		name := strings.TrimSpace(iface)
		if name == "" {
			if mode == "v6" {
				return primaryLocalIPv6()
			}
			return primaryLocalIPv4()
		}
		if mode == "v6" {
			return interfaceIPv6(name)
		}
		return interfaceIPv4(name)
	}
	// 公网来源
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.pubIPTime) >= publicIPTTL {
		nv4, nv6 := s.detectPublicIP()
		got := nv4 != "" || nv6 != ""
		if got || (s.pubIPv4 == "" && s.pubIPv6 == "") {
			s.pubIPv4, s.pubIPv6 = nv4, nv6
		}
		if got {
			s.pubIPTime = time.Now()
		}
	}
	if mode == "v6" {
		return s.pubIPv6
	}
	return s.pubIPv4
}

// handleDDNSRecordBind 把域名的解析记录绑定到指定来源的 IP（公网/本机网卡地址），
// 并创建/更新一个动态解析任务，使该 IP 变动时自动更新解析记录。
func (s *Server) handleDDNSRecordBind(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account  string `json:"account"`
		Domain   string `json:"domain"`
		RR       string `json:"rr"`
		Type     string `json:"type"`
		TTL      int    `json:"ttl"`
		IPSrc    string `json:"ip_src"`    // public | local
		Iface    string `json:"iface"`     // local 时网卡名
		RecordID string `json:"record_id"` // 已有记录 id（更新），为空表示新增
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	req.Account = strings.TrimSpace(req.Account)
	req.Domain = strings.TrimSpace(req.Domain)
	req.RR = strings.TrimSpace(req.RR)
	req.Type = strings.ToUpper(strings.TrimSpace(req.Type))
	if req.Account == "" || req.Domain == "" {
		s.writeJSON(w, http.StatusOK, apiErr("请填写账户与域名"))
		return
	}
	if req.Type == "" {
		req.Type = "A"
	}
	if req.RR == "" {
		req.RR = "@"
	}
	if req.IPSrc != "local" {
		req.IPSrc = "public"
	}
	if req.TTL <= 0 {
		req.TTL = 600
	}

	ip := s.resolveSourceIP(req.IPSrc, req.Iface, req.Type)
	if ip == "" {
		s.writeJSON(w, http.StatusOK, apiErr("未获取到地址（本地网卡无该类型的 IP 或无法探测公网地址）"))
		return
	}

	_, mgr, err := s.dnsManagerFor(req.Account)
	if err != nil {
		s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	addrMode := "v4"
	if strings.EqualFold(req.Type, "AAAA") {
		addrMode = "v6"
	}
	if req.RecordID != "" {
		// 更新已有记录
		if err := (*mgr).UpdateRecord(ctx, req.Domain, req.RecordID, req.RR, req.Type, ip, req.TTL); err != nil {
			s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
			return
		}
	} else {
		// 新增记录
		if _, err := (*mgr).AddRecord(ctx, req.Domain, req.RR, req.Type, ip, req.TTL); err != nil {
			s.writeJSON(w, http.StatusOK, apiErr(err.Error()))
			return
		}
	}

	// 创建/更新动态解析任务：ip_src + iface + addr_mode，默认启用
	task := store.DDNSTask{
		Account:  req.Account,
		Domain:   req.Domain,
		RR:       req.RR,
		RRType:   req.Type,
		AddrMode: addrMode,
		IPSrc:    req.IPSrc,
		Iface:    req.Iface,
		TTL:      req.TTL,
		Enabled:  true,
	}
	// 已存在同 account+domain+rr+type 的任务则更新，否则新建
	var taskID int64
	tasks, _ := s.store.ListDDNSTasks()
	found := false
	for _, t := range tasks {
		if strings.EqualFold(t.Account, req.Account) &&
			strings.EqualFold(t.Domain, req.Domain) &&
			strings.EqualFold(t.RR, req.RR) &&
			strings.EqualFold(t.RRType, req.Type) {
			task.ID = t.ID
			found = true
			break
		}
	}
	if found {
		if err := s.store.UpdateDDNSTask(task); err != nil {
			s.logger.Warn("更新 DDNS 任务失败", zap.String("err", err.Error()))
		}
		taskID = task.ID
	} else {
		id, err := s.store.AddDDNSTask(task)
		if err != nil {
			s.logger.Warn("创建 DDNS 任务失败", zap.String("err", err.Error()))
		} else {
			taskID = id
		}
	}

	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"ip":        ip,
		"task_id":   taskID,
		"record_id": req.RecordID,
	}))
}

// runDDNSTask 同步单个 DDNS 任务：读取指定来源的 IP 并更新对应解析记录，返回结果描述。
// ip_src=public 读取公网地址；ip_src=local 读取本机指定网卡的地址。
func (s *Server) runDDNSTask(t store.DDNSTask) string {
	rtype := strings.ToUpper(t.RRType)
	if rtype == "" {
		rtype = "A"
	}
	mode := strings.ToLower(t.AddrMode)
	if mode == "" {
		mode = "v4"
	}
	var ip string
	if strings.ToLower(t.IPSrc) == "local" {
		// 本地网卡来源：直接读取该网卡的主用 IPv4/IPv6
		name := strings.TrimSpace(t.Iface)
		if name == "" {
			if mode == "v6" {
				ip = primaryLocalIPv6()
			} else {
				ip = primaryLocalIPv4()
			}
		} else {
			if mode == "v6" {
				ip = interfaceIPv6(name)
			} else {
				ip = interfaceIPv4(name)
			}
		}
	} else {
		// 公网来源：探测公网地址（v4/v6）；detectPublicIP 一次返回两者，同时刷新缓存
		s.mu.Lock()
		if time.Since(s.pubIPTime) >= publicIPTTL {
			nv4, nv6 := s.detectPublicIP()
			got := nv4 != "" || nv6 != ""
			if got || (s.pubIPv4 == "" && s.pubIPv6 == "") {
				s.pubIPv4, s.pubIPv6 = nv4, nv6
			}
			if got {
				s.pubIPTime = time.Now()
			}
		}
		if mode == "v6" {
			ip = s.pubIPv6
		} else {
			ip = s.pubIPv4
		}
		s.mu.Unlock()
	}
	if ip == "" {
		s.store.SetDDNSTaskResult(t.ID, "")
		return "未探测到地址"
	}
	_, mgr, err := s.dnsManagerFor(t.Account)
	if err != nil {
		return err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// 比对当前记录值：若已是最新则跳过
	if recs, err := (*mgr).ListRecords(ctx, t.Domain); err == nil {
		rr := strings.TrimSpace(t.RR)
		for _, rec := range recs {
			if strings.EqualFold(forward.TrimDNSHost(rec.Name), forward.TrimDNSHost(rr)) &&
				strings.EqualFold(rec.Type, rtype) && strings.TrimSpace(rec.Value) == ip {
				s.store.SetDDNSTaskResult(t.ID, ip)
				return "已是最新 " + ip
			}
		}
	}
	if _, err := forward.UpdateRecordValue(ctx, *mgr, t.Domain, t.RR, rtype, ip); err != nil {
		return err.Error()
	}
	s.store.SetDDNSTaskResult(t.ID, ip)
	return "已更新为 " + ip
}

// interfaceIPv6 返回指定网卡上第一个非回环/链路本地的 IPv6 地址。
func interfaceIPv6(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		ip6 := ip.To16()
		if ip6 == nil {
			continue
		}
		if ip6.IsLinkLocalUnicast() || ip6.IsMulticast() || ip6.IsUnspecified() {
			continue
		}
		return ip6.String()
	}
	return ""
}

// startDDNSEngine 后台定期扫描启用中的 DDNS 任务（默认间隔 5 分钟）。
func (s *Server) startDDNSEngine() {
	s.bgWG.Add(1)
	go func() {
		defer s.bgWG.Done()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.runAllDDNS()
			}
		}
	}()
}

// runAllDDNS 执行所有启用任务的同步。
func (s *Server) runAllDDNS() {
	tasks, err := s.store.ListDDNSTasks()
	if err != nil {
		return
	}
	for _, t := range tasks {
		if !t.Enabled {
			continue
		}
		if msg := s.runDDNSTask(t); strings.HasPrefix(msg, "已更新") {
			s.logger.Info("DDNS 同步完成", zap.String("domain", t.Domain), zap.String("result", msg))
		} else if !strings.HasPrefix(msg, "已是最新") && !strings.HasPrefix(msg, "未探测") {
			s.logger.Warn("DDNS 同步失败", zap.String("domain", t.Domain), zap.String("err", msg))
		}
	}
}
