package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"tunhook/config"
	"tunhook/frpc"
	"tunhook/stunhole"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ============= Webhook 接收器 =============
// 接收 STUN 客户端上报的公网地址（channel_id -> public_ip:public_port），
// 并对外提供「访问地址 /{channel_id} → 公网地址」的重定向（302/301/307/308）
// 或反向代理入口，实现公网地址重定向/代理到系统域名（访问域名）上。
// 通道支持按分组组织（参考 STUN 面板的通道分组），并可手动注册/编辑。

// whRecord 一条通道的公网地址注册记录。
type whRecord struct {
	ChannelID       string `json:"channel_id"`
	CustomID        string `json:"custom_id,omitempty"`   // 自定义访问ID（可选，/{custom_id} 亦可访问本通道）
	Description     string `json:"description,omitempty"` // 描述（可选）
	Group           string `json:"group,omitempty"`       // 所属分组（空=默认分组）
	PublicIP        string `json:"public_ip"`
	PublicPort      int    `json:"public_port"`
	HTTPS           bool   `json:"https"`
	RedirectType    string `json:"redirect_type,omitempty"` // ""=跟随全局 | 301/302/307/308 | proxy/html/cors/ws
	AccessKey       string `json:"access_key,omitempty"`
	Password        string `json:"password,omitempty"`          // 连接密码（留空=禁用密码保护）
	CustomDomain    string `json:"custom_domain,omitempty"`     // 自定义域名（验证后创建 frpc 代理指向本服务）
	ProxyName       string `json:"proxy_name,omitempty"`        // 已创建的 frpc 代理名称（Webhook-通道描述/通道id）
	LinkKey         string `json:"link_key,omitempty"`          // 链接密钥（可选，访问鉴权）
	WebhookURL      string `json:"webhook_url,omitempty"`       // Webhook 接口地址（URL 格式）
	CallbackChar    string `json:"callback_char,omitempty"`     // 回调字符（用于请求验证）
	WebhookMethod   string `json:"webhook_method,omitempty"`    // 请求方式 GET/POST/PUT/DELETE/PATCH/HEAD
	WebhookBody     string `json:"webhook_body,omitempty"`      // 请求体（JSON 模板）
	WebhookHeaders  string `json:"webhook_headers,omitempty"`   // 回调请求头（每行一条 Key: Value）
	NoCallbackCheck bool   `json:"no_callback_check,omitempty"` // 禁用回调字符检测（true=上报不校验 callback_char）
	LogLevel        string `json:"log_level,omitempty"`         // 日志级别 error/warn/info/debug
	LogEntries      int    `json:"log_entries,omitempty"`       // 日志存储条数（100-10000）
	LogDays         int    `json:"log_days,omitempty"`          // 日志存储时间（7/30/90/180/365 天）
	UpdatedAt       string `json:"updated_at"`
	Hits            int64  `json:"hits"`           // 访问次数
	OK              int64  `json:"ok,omitempty"`   // 访问成功次数（每通道统计，状态页可用性）
	Fail            int64  `json:"fail,omitempty"` // 访问失败次数（每通道统计，状态页可用性）
}

// whReceiver 通道公网地址注册表（内存 + 落库持久化）。
type whReceiver struct {
	s          *Server
	mu         sync.RWMutex
	records    map[string]*whRecord
	groups     map[string]bool         // 分组名称（默认分组恒存在）
	okCount    int64                   // 跳转/代理成功次数
	failCount  int64                   // 通道未注册 / 代理失败次数
	lastActive int64                   // 最近一次活动时间（Unix 秒，供仪表盘展示）
	logs       map[string]*LogBuffer   // 每通道运行/访问日志缓冲（channel_id -> 环形缓冲）
	days       []whDayStat             // 近 90 天每日访问统计（最新在前，状态页柱状图数据源）
	hist       map[string]*compHistory // 各系统组件可用性采样（frpc/server/forward/whrecv）
	whAddrLast string                  // 上次连通性测试的接收地址（变化时重置 whrecv 采样环）
}

// whDayStat 一天的通道访问成功/失败统计（状态页「Webhook 通道」柱状图数据源）。
type whDayStat struct {
	Day  string `json:"day"` // YYYY-MM-DD
	OK   int64  `json:"ok"`
	Fail int64  `json:"fail"`
}

// whDayMax 每日统计保留天数（柱状图宽度，与状态页一致）。
const whDayMax = 90

// whPersist 注册表持久化结构（含分组与成功率统计）。
type whPersist struct {
	Records []*whRecord                   `json:"records"`
	Groups  []string                      `json:"groups"`
	OK      int64                         `json:"ok"`
	Fail    int64                         `json:"fail"`
	Days    []whDayStat                   `json:"days,omitempty"`    // 近 90 天每日访问统计（最新在前）
	Hist    map[string]compHistoryPersist `json:"hist,omitempty"`    // 各组件可用性采样环（重启后延续）
	WhAddr  string                        `json:"wh_addr,omitempty"` // 上次连通性测试的接收地址（变化时重置 whrecv 采样环）
}

// 通道 ID 校验：小写字母/数字/连字符，1-32 位（与导航页后缀规则一致；数字池自动分配可能产生 1 位 ID）。
var whChannelRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// whAuthMaxAge 密码验证通过的免验证时长（秒）：12 小时内访问无需再次验证。
const whAuthMaxAge = 12 * 3600

// whReserved 保留名称：与现有路由/静态资源冲突的名称一律拒绝注册。
var whReserved = map[string]bool{
	"api": true, "admin": true, "register": true, "login": true, "static": true,
	"assets": true, "proxy": true, "receive": true, "health": true, "settings": true,
	"records": true, "wh": true, "favicon": true, "d": true, "hook": true,
}

const whRecordsKey = "wh_receiver.records"

// defaultGroupName Webhook 通道默认分组名（恒存在，不可删除/重命名，空分组归入）。
const defaultGroupName = "Webhook 通道"

// validWhRedirectType 校验每通道访问方式：
// 空=跟随全局；301/302/307/308=客户端跳转；proxy/html/cors/ws=四类代理。
func validWhRedirectType(t string) bool {
	switch t {
	case "", "301", "302", "307", "308", "proxy", "html", "cors", "ws":
		return true
	}
	return false
}

// newWhReceiver 创建接收器并从数据库加载已注册通道。
func newWhReceiver(s *Server) *whReceiver {
	r := &whReceiver{
		s:       s,
		records: map[string]*whRecord{},
		groups:  map[string]bool{defaultGroupName: true},
		logs:    map[string]*LogBuffer{},
		hist:    map[string]*compHistory{},
	}
	if v, err := s.store.GetSetting(whRecordsKey); err == nil && v != "" {
		var p whPersist
		if json.Unmarshal([]byte(v), &p) == nil && p.Records != nil {
			for _, rec := range p.Records {
				if rec != nil && rec.ChannelID != "" {
					r.records[rec.ChannelID] = rec
					if g := rec.Group; g != "" {
						r.groups[g] = true
					}
				}
			}
			for _, g := range p.Groups {
				r.groups[g] = true
			}
			r.okCount = p.OK
			r.failCount = p.Fail
			if len(p.Days) > whDayMax {
				p.Days = p.Days[:whDayMax]
			}
			r.days = p.Days
			r.whAddrLast = p.WhAddr
			// 恢复组件可用性采样环（重启后柱状图从断点继续累积）
			for id, hp := range p.Hist {
				h := &compHistory{}
				h.loadPersist(hp)
				r.hist[id] = h
			}
		} else {
			// 兼容旧版持久化格式（裸记录数组）
			var recs []*whRecord
			if json.Unmarshal([]byte(v), &recs) == nil {
				for _, rec := range recs {
					if rec != nil && rec.ChannelID != "" {
						r.records[rec.ChannelID] = rec
						if g := rec.Group; g != "" {
							r.groups[g] = true
						}
					}
				}
			}
		}
	}

	// 迁移历史默认分组名：把持久化中的旧名 "default" 归一化为默认分组名（幂等，仅一次生效）。
	// 早期版本默认分组写作 "default"，改名后若不迁移，界面上会残留旧分组。
	migrated := false
	for _, rec := range r.records {
		if rec.Group == "default" {
			rec.Group = defaultGroupName
			migrated = true
		}
	}
	if r.groups["default"] {
		delete(r.groups, "default")
		migrated = true
	}
	if migrated {
		r.persist()
	}
	s.logger.Info("Webhook 接收器已加载",
		zap.Int("records", len(r.records)),
		zap.Int("groups", len(r.groups)))
	return r
}

// persist 将注册表（记录 + 分组 + 成功率统计 + 每日统计 + 组件采样环）落库（重启后恢复）。
func (r *whReceiver) persist() {
	r.mu.RLock()
	p := whPersist{
		Records: make([]*whRecord, 0, len(r.records)),
		Groups:  make([]string, 0, len(r.groups)),
		OK:      r.okCount,
		Fail:    r.failCount,
		Days:    r.days,
		Hist:    make(map[string]compHistoryPersist, len(r.hist)),
		WhAddr:  r.whAddrLast,
	}
	for _, rec := range r.records {
		p.Records = append(p.Records, rec)
	}
	for g := range r.groups {
		p.Groups = append(p.Groups, g)
	}
	for id, h := range r.hist {
		p.Hist[id] = h.snapPersist()
	}
	r.mu.RUnlock()
	sort.Strings(p.Groups)
	if b, err := json.Marshal(p); err == nil {
		if err := r.s.store.SetSetting(whRecordsKey, string(b)); err != nil {
			r.s.logger.Warn("Webhook 接收记录保存失败", zap.Error(err))
		}
	}
}

// restorePersist 用备份的持久化快照整体替换注册表并落库（备份恢复用）。
// 通道记录/分组为内容数据，成功率与每日统计等运行时状态随快照一并恢复。
func (r *whReceiver) restorePersist(v string) error {
	var p whPersist
	if err := json.Unmarshal([]byte(v), &p); err != nil {
		return err
	}
	r.mu.Lock()
	records := make(map[string]*whRecord, len(p.Records))
	groups := map[string]bool{defaultGroupName: true}
	for _, rec := range p.Records {
		if rec != nil && rec.ChannelID != "" {
			records[rec.ChannelID] = rec
			if g := rec.Group; g != "" {
				groups[g] = true
			}
		}
	}
	for _, g := range p.Groups {
		groups[g] = true
	}
	r.records = records
	r.groups = groups
	r.okCount = p.OK
	r.failCount = p.Fail
	if len(p.Days) > whDayMax {
		p.Days = p.Days[:whDayMax]
	}
	r.days = p.Days
	hist := make(map[string]*compHistory, len(p.Hist))
	for id, hp := range p.Hist {
		h := &compHistory{}
		h.loadPersist(hp)
		hist[id] = h
	}
	r.hist = hist
	r.whAddrLast = p.WhAddr
	r.mu.Unlock()
	r.persist()
	return nil
}

// list 返回全部记录（按更新时间倒序）。
func (r *whReceiver) list() []*whRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*whRecord, 0, len(r.records))
	for _, rec := range r.records {
		cp := *rec
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt > out[j].UpdatedAt })
	return out
}

// count 返回已注册通道数。
func (r *whReceiver) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.records)
}

func (r *whReceiver) get(id string) *whRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if rec, ok := r.records[id]; ok {
		cp := *rec
		return &cp
	}
	return nil
}

// getByAccess 按访问段解析通道：优先通道ID，其次自定义ID（根路径 /{id}、/tun/{id} 或 /wh/{id} 均可）。
func (r *whReceiver) getByAccess(seg string) *whRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if rec, ok := r.records[seg]; ok {
		cp := *rec
		return &cp
	}
	for _, rec := range r.records {
		if rec.CustomID == seg {
			cp := *rec
			return &cp
		}
	}
	return nil
}

// getByDomain 按自定义域名解析通道（忽略大小写），供自定义域名直达访问（域名根路径即跳转/代理）。
func (r *whReceiver) getByDomain(host string) *whRecord {
	if host == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, rec := range r.records {
		if strings.EqualFold(rec.CustomDomain, host) {
			cp := *rec
			return &cp
		}
	}
	return nil
}

// customIDUsed 判断自定义ID 是否已被其他通道占用。
func (r *whReceiver) customIDUsed(except, customID string) bool {
	if customID == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, rec := range r.records {
		if rec.ChannelID != except && rec.CustomID == customID {
			return true
		}
	}
	return false
}

// domainUsed 判断自定义域名是否已被其他通道占用（忽略大小写）。
func (r *whReceiver) domainUsed(except, domain string) bool {
	if domain == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, rec := range r.records {
		if rec.ChannelID != except && strings.EqualFold(rec.CustomDomain, domain) {
			return true
		}
	}
	return false
}

// allocateID 从数字ID池分配最小可用ID：从 1 开始，取未占用（不在 records 中）的最小正整数。
// 通道删除后其数字ID自动回到池中，可被再次分配。
func (r *whReceiver) allocateID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 1
	for {
		id := strconv.Itoa(n)
		if _, used := r.records[id]; !used {
			return id
		}
		n++
	}
}

// upsert 创建或更新一条记录（保留访问统计等既有字段）。
func (r *whReceiver) upsert(rec *whRecord) {
	r.mu.Lock()
	old, ok := r.records[rec.ChannelID]
	if ok {
		rec.Hits = old.Hits
	}
	if rec.Group == "" {
		rec.Group = defaultGroupName
	}
	r.groups[rec.Group] = true
	r.records[rec.ChannelID] = rec
	r.mu.Unlock()
	r.persist()
}

func (r *whReceiver) delete(id string) bool {
	r.mu.Lock()
	if _, ok := r.records[id]; !ok {
		r.mu.Unlock()
		return false
	}
	delete(r.records, id)
	r.mu.Unlock()
	r.persist()
	return true
}

func (r *whReceiver) clear() int {
	r.mu.Lock()
	n := len(r.records)
	r.records = map[string]*whRecord{}
	r.mu.Unlock()
	r.persist()
	return n
}

// addGroup 新建分组（已存在则忽略）。
func (r *whReceiver) addGroup(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || !whGroupRe.MatchString(name) {
		return false
	}
	r.mu.Lock()
	if r.groups[name] {
		r.mu.Unlock()
		return true
	}
	r.groups[name] = true
	r.mu.Unlock()
	r.persist()
	return true
}

// delGroup 删除分组，该分组下的通道移动到 moveTo（空 = 默认分组）。
func (r *whReceiver) delGroup(name, moveTo string) bool {
	if name == defaultGroupName {
		return false
	}
	if moveTo == "" {
		moveTo = defaultGroupName
	}
	if moveTo == name || (moveTo != defaultGroupName && !r.groups[moveTo]) {
		return false
	}
	r.mu.Lock()
	if !r.groups[name] {
		r.mu.Unlock()
		return false
	}
	delete(r.groups, name)
	for _, rec := range r.records {
		if rec.Group == name {
			rec.Group = moveTo
		}
	}
	r.mu.Unlock()
	r.persist()
	return true
}

// renameGroup 重命名分组：更新分组名与该分组下全部通道的归属（默认分组不可重命名）。
func (r *whReceiver) renameGroup(oldName, newName string) bool {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if oldName == defaultGroupName || oldName == "" || newName == "" || !whGroupRe.MatchString(newName) {
		return false
	}
	r.mu.Lock()
	if !r.groups[oldName] || r.groups[newName] {
		r.mu.Unlock()
		return false
	}
	delete(r.groups, oldName)
	r.groups[newName] = true
	for _, rec := range r.records {
		if rec.Group == oldName {
			rec.Group = newName
		}
	}
	r.mu.Unlock()
	r.persist()
	return true
}

// groupViews 返回分组列表（含各分组通道数，按名称排序，默认分组优先）。
func (r *whReceiver) groupViews() []map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	counts := map[string]int{}
	for _, rec := range r.records {
		g := rec.Group
		if g == "" {
			g = defaultGroupName
		}
		counts[g]++
	}
	names := make([]string, 0, len(r.groups))
	for g := range r.groups {
		names = append(names, g)
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i] == defaultGroupName {
			return true
		}
		if names[j] == defaultGroupName {
			return false
		}
		return names[i] < names[j]
	})
	out := make([]map[string]interface{}, 0, len(names))
	for _, g := range names {
		out = append(out, map[string]interface{}{"name": g, "count": counts[g]})
	}
	return out
}

// stats 返回成功率统计（count 已注册通道数，rate 跳转/代理成功率）。
func (r *whReceiver) stats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	total := r.okCount + r.failCount
	rate := 0.0
	if total > 0 {
		rate = float64(r.okCount) / float64(total) * 100
	}
	return map[string]interface{}{
		"enabled":     r.s.whReceiverEnabled(),
		"count":       len(r.records),
		"success":     r.okCount,
		"failed":      r.failCount,
		"rate":        mathRound1(rate),
		"last_active": r.lastActive,
	}
}

// recordAccess 记录一次访问结果（成功/失败），每 20 次落库一次，避免频繁写库。
// 同时累计每通道成功/失败次数与每日访问统计（状态页可用性/柱状图数据源）。
func (r *whReceiver) recordAccess(id string, ok bool) {
	r.mu.Lock()
	r.lastActive = time.Now().Unix()
	if ok {
		r.okCount++
	} else {
		r.failCount++
	}
	if rec, found := r.records[id]; found {
		rec.Hits++
		if ok {
			rec.OK++
		} else {
			rec.Fail++
		}
	}
	// 每日统计（柱状图）：今天无记录则新增，有则累加；超过 90 天丢弃最旧一天。
	today := time.Now().Format("2006-01-02")
	if n := len(r.days); n > 0 && r.days[0].Day == today {
		if ok {
			r.days[0].OK++
		} else {
			r.days[0].Fail++
		}
	} else {
		d := whDayStat{Day: today}
		if ok {
			d.OK = 1
		} else {
			d.Fail = 1
		}
		r.days = append([]whDayStat{d}, r.days...)
		if len(r.days) > whDayMax {
			r.days = r.days[:whDayMax]
		}
	}
	persistNow := (r.okCount+r.failCount)%20 == 0
	r.mu.Unlock()
	if persistNow {
		r.persist()
	}
}

// ============= 状态页：组件可用性采样 =============

// compHistoryLen 组件可用性采样环长度（柱状图柱数）。
const compHistoryLen = 90

// compHistoryPersist 组件采样环的持久化形态（避免直接序列化含互斥锁的结构）。
type compHistoryPersist struct {
	Bars  []int    `json:"bars"`
	Times []string `json:"times"`
	Last  int64    `json:"last,omitempty"` // 上次采样时间（UnixNano），用于重启后延续节流
}

// compHistory 单个系统组件的可用性采样环（持久化，重启后从断点继续累积）：
// 0=失败 1=正常；最新采样在右，用于渲染柱状图与可用性百分比。
type compHistory struct {
	mu    sync.Mutex
	bars  []int     // 采样结果（0=失败 1=正常，最新在右）
	times []string  // 与 bars 对齐的采样时间（MM-DD HH:MM）
	last  time.Time // 上次采样时间（节流：每分钟至多一次）
}

// sample 记录一次采样（节流：同一分钟内的重复采样忽略，返回是否记录了新采样）。
// 仅记录真实采样，不做预填充；未采样部分由 snapFixed 以「无数据」填充左侧，
// 保证各组件柱状图视觉宽度一致。
func (c *compHistory) sample(ok bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if !c.last.IsZero() && now.Sub(c.last) < time.Minute {
		return false
	}
	c.last = now
	v := 0
	if ok {
		v = 1
	}
	c.bars = append(c.bars, v)
	c.times = append(c.times, now.Format("01-02 15:04"))
	if len(c.bars) > compHistoryLen {
		c.bars = c.bars[len(c.bars)-compHistoryLen:]
		c.times = c.times[len(c.times)-compHistoryLen:]
	}
	return true
}

// snapPersist 导出持久化副本。
func (c *compHistory) snapPersist() compHistoryPersist {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := compHistoryPersist{
		Bars:  make([]int, len(c.bars)),
		Times: make([]string, len(c.times)),
	}
	copy(p.Bars, c.bars)
	copy(p.Times, c.times)
	if !c.last.IsZero() {
		p.Last = c.last.UnixNano()
	}
	return p
}

// loadPersist 从持久化副本恢复。
func (c *compHistory) loadPersist(p compHistoryPersist) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bars = p.Bars
	c.times = p.Times
	if p.Last > 0 {
		c.last = time.Unix(0, p.Last)
	}
}

// reset 清空采样环（接收地址变化时使用，从新地址重新统计）。
func (c *compHistory) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bars = nil
	c.times = nil
	c.last = time.Time{}
}

// snapFixed 返回固定长度的柱状图与时间数组（未采样部分用 3=无数据 填充左侧，
// 时间置空），使各组件柱状图宽度一致：真实采样右对齐，最新在最右。
func (c *compHistory) snapFixed() ([]int, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	bars := make([]int, compHistoryLen)
	times := make([]string, compHistoryLen)
	for i := range bars {
		bars[i] = 3
	}
	n := len(c.bars)
	if n > compHistoryLen {
		n = compHistoryLen
	}
	start := compHistoryLen - n
	for i := 0; i < n; i++ {
		bars[start+i] = c.bars[len(c.bars)-n+i]
		times[start+i] = c.times[len(c.times)-n+i]
	}
	return bars, times
}

// rate 返回采样成功率（0-100，保留 1 位小数）；无采样返回 0。
func (c *compHistory) rate() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.bars) == 0 {
		return 0
	}
	ok := 0
	for _, v := range c.bars {
		if v == 1 {
			ok++
		}
	}
	return mathRound1(float64(ok) / float64(len(c.bars)) * 100)
}

// histGet 获取组件采样环（不存在时创建）。
func (r *whReceiver) histGet(id string) *compHistory {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.hist[id]; ok {
		return h
	}
	h := &compHistory{}
	r.hist[id] = h
	return h
}

// histSample 记录组件采样；记录了新采样时立即落库（重启后延续）。
func (r *whReceiver) histSample(id string, ok bool) {
	if r.histGet(id).sample(ok) {
		r.persist()
	}
}

// histRate 返回组件采样成功率。
func (r *whReceiver) histRate(id string) float64 { return r.histGet(id).rate() }

// histFixed 返回组件固定长度柱状图与时间数组。
func (r *whReceiver) histFixed(id string) ([]int, []string) { return r.histGet(id).snapFixed() }

// whSetAddr 记录当前接收地址；与上次不同（含变为空/从空变有）时清空 whrecv 采样环，
// 使连通性统计只反映新地址，返回是否有变化（调用方可决定立即落库）。
func (r *whReceiver) whSetAddr(addr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if addr == r.whAddrLast {
		return false
	}
	r.whAddrLast = addr
	if h, ok := r.hist["whrecv"]; ok {
		h.reset()
	}
	return true
}

// logAdd 记录一条通道运行/访问日志（按通道配置的日志级别与存储条数过滤）。
// level 取值 debug/info/warn/error；未记录到具体通道时写入到 id 缓冲（如删除前最后一条）。
func (r *whReceiver) logAdd(id, level, msg string) {
	if id == "" {
		return
	}
	r.mu.RLock()
	rec := r.records[id]
	r.mu.RUnlock()
	// 级别过滤：通道配置了日志级别时，低于该级别的日志不记录
	lvl := strings.ToUpper(level)
	if rec != nil && rec.LogLevel != "" {
		threshold, ok := logLevelThresholds[strings.ToUpper(rec.LogLevel)]
		if !ok {
			threshold = zapcore.InfoLevel
		}
		cur, ok := logLevelThresholds[lvl]
		if !ok {
			cur = zapcore.InfoLevel
		}
		if cur < threshold {
			return
		}
	}
	// 存储条数：通道配置（100-10000），未配置默认 500
	cap := 500
	if rec != nil && rec.LogEntries >= 100 {
		cap = rec.LogEntries
	}
	r.mu.Lock()
	buf := r.logs[id]
	if buf == nil {
		buf = NewLogBuffer(cap)
		r.logs[id] = buf
	} else if buf.Cap() != cap {
		buf.SetCap(cap)
	}
	r.mu.Unlock()
	buf.Append(LogEntry{
		Level:   lvl,
		Time:    time.Now().Format("2006-01-02 15:04:05"),
		Message: msg,
	})
}

// logQuery 查询指定通道的日志（倒序：最新在前）。
func (r *whReceiver) logQuery(id string, limit int) []LogEntry {
	if id == "" {
		return nil
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	r.mu.RLock()
	buf := r.logs[id]
	r.mu.RUnlock()
	if buf == nil {
		return nil
	}
	entries, _ := buf.Query(1, limit, "", "", "", "", "", "")
	// 倒序：最新在前
	out := make([]LogEntry, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		out = append(out, entries[i])
	}
	return out
}

// mathRound1 保留 1 位小数。
func mathRound1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

// isEnabled 接收器是否开启。
func (s *Server) whReceiverEnabled() bool {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg.WebhookReceiver.Enabled
}

// whReceiverCfg 返回接收器配置副本。
func (s *Server) whReceiverCfg() config.WebhookReceiverConfig {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg.WebhookReceiver
}

// whReceiveURL 返回 Webhook 接收地址的完整 URL（供状态页连通性检测），跟随地址模式：
// 域名模式经 frpc 域名代理访问，为 https://域名/api/channel/update（不带端口）；
// IP 模式为 http(s)://IP:端口/api/channel/update（本机探测用 http）。
func (s *Server) whReceiveURL() (string, bool) {
	cfg := s.whReceiverCfg()
	host := ""
	switch cfg.AddrMode {
	case "domain":
		host = strings.TrimSpace(cfg.AccessDomain)
		if host == "" {
			host = strings.TrimSpace(cfg.ReceiveAddr)
		}
	default: // ip
		host = strings.TrimSpace(cfg.AccessIP)
		if host == "" {
			host = strings.TrimSpace(cfg.ReceiveAddr)
		}
		if host == "" {
			host = strings.TrimSpace(s.localIP)
		}
	}
	if host == "" {
		return "", false
	}
	port := cfg.ReceivePort
	if port <= 0 {
		port = 19520
	}
	// 域名模式：经 frpc 域名代理（http/https 型代理）访问，端口由代理决定，不显式携带
	if cfg.AddrMode == "domain" {
		return "https://" + host + "/api/channel/update", true
	}
	return fmt.Sprintf("http://%s/api/channel/update", net.JoinHostPort(host, strconv.Itoa(port))), true
}

// whGroupRe 分组名校验：1-16 位中英文/数字/下划线/连字符。
var whGroupRe = regexp.MustCompile(`^[\p{L}\p{N}_-]{1,16}$`)

// whCustomIDRe 自定义访问ID 校验：2-16 位小写字母/数字/下划线/连字符。
// 根路径访问（IP:端口/{自定义ID}）直接位于系统接口同一层级，长度上限收紧至 16 位。
var whCustomIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,15}$`)

// whShortLetterRe 4 位及以内纯字母自定义ID 拒绝注册：
// 与系统接口/路由（如 api、tun、wh、nav 等）在根路径下存在冲突风险。
var whShortLetterRe = regexp.MustCompile(`^[a-z]{1,4}$`)

// whAccessRe 访问路径段校验：通道ID（1-32 位）或自定义ID（含下划线，2-16 位）均可用根路径访问。
var whAccessRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// whDomainRe 自定义域名校验：标准域名（至少两级，字母/数字/连字符/点）。
var whDomainRe = regexp.MustCompile(`(?i)^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// whWebhookMethods 通道 Webhook 请求方式白名单。
var whWebhookMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true, "HEAD": true, "OPTIONS": true}

// whLogLevels 通道日志输出级别白名单。
var whLogLevels = map[string]bool{"error": true, "warn": true, "info": true, "debug": true}

// validHTTPURL 校验 http/https URL。
func validHTTPURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// whStr 从 JSON body 中按多个候选 key 提取字符串值。
func whStr(body map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := body[k]; ok {
			if str, ok := v.(string); ok {
				return strings.TrimSpace(str)
			}
			if num, ok := v.(float64); ok {
				return strings.TrimSpace(fmt.Sprintf("%.0f", num))
			}
		}
	}
	return ""
}

func whInt(body map[string]any, keys ...string) int {
	for _, k := range keys {
		if v, ok := body[k]; ok {
			switch t := v.(type) {
			case float64:
				return int(t)
			case string:
				var n int
				fmt.Sscanf(strings.TrimSpace(t), "%d", &n)
				return n
			}
		}
	}
	return 0
}

func whBool(body map[string]any, keys ...string) bool {
	for _, k := range keys {
		if v, ok := body[k]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
	}
	return false
}

// whUnwrapData 兼容两种上报格式：
//  1. 扁平格式 {clientId, publicIp, publicPort, ...}（STUN 客户端旧版 / Lanjmp）
//  2. 事件格式 {type, timestamp, data:{...}}（客户端 notify 模块新版）
func whUnwrapData(body map[string]any) map[string]any {
	if _, ok := body["clientId"]; ok {
		return body
	}
	if _, ok := body["channel_id"]; ok {
		return body
	}
	if d, ok := body["data"].(map[string]any); ok {
		return d
	}
	return body
}

// handleWhReceive Webhook 接收接口（POST /wh/receive）。
// 成功回写配置的回调字符（默认「更新成功」），客户端据此判断同步成功。
func (s *Server) handleWhReceive(w http.ResponseWriter, r *http.Request) {
	if !s.whReceiverEnabled() {
		s.writeJSON(w, http.StatusForbidden, apiErr("Webhook 接收未启用，请先在设置中开启"))
		return
	}
	body, err := parseWhBody(r)
	if err != nil {
		s.logger.Warn("Webhook 接收请求体解析失败", zap.Error(err))
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体格式错误"))
		return
	}
	payload := whUnwrapData(body)

	cfg := s.whReceiverCfg()
	// 接收密钥校验（配置后必填：X-Webhook-Secret 请求头或 body.secret）
	if cfg.Secret != "" {
		if r.Header.Get("X-Webhook-Secret") != cfg.Secret && whStr(body, "secret") != cfg.Secret {
			s.logger.Warn("Webhook 接收鉴权失败", zap.String("remote", r.RemoteAddr))
			s.writeJSON(w, http.StatusUnauthorized, apiErr("接收密钥不正确"))
			return
		}
	}

	channelID := strings.ToLower(whStr(payload, "channel_id", "clientId", "channelId"))
	if channelID == "" || whReserved[channelID] || !whChannelRe.MatchString(channelID) {
		s.writeJSON(w, http.StatusBadRequest, apiErr("channel_id 无效（1-32 位小写字母/数字/连字符，不能为保留名称）"))
		return
	}
	publicIP := whStr(payload, "public_ip", "publicIp", "host")
	publicPort := whInt(payload, "public_port", "publicPort", "port")
	ipValid := net.ParseIP(publicIP) != nil
	portValid := publicPort >= 1 && publicPort <= 65535
	if !ipValid || !portValid {
		// 客户端可能尚未完成公网探测（模板占位符 {ip}/{port} 未替换或为空）：
		// 先登记通道为「等待客户端上报」状态，待后续有效上报自动补全公网地址，不阻塞注册。
		s.logger.Warn("[Webhook接收] 公网地址暂不可用，通道登记为等待状态",
			zap.String("channel", channelID), zap.String("ip", publicIP), zap.Int("port", publicPort))
	}

	s.whRecv.mu.Lock()
	rec, ok := s.whRecv.records[channelID]
	if !ok {
		rec = &whRecord{ChannelID: channelID, Group: defaultGroupName}
		s.whRecv.records[channelID] = rec
	}
	// 回调字符检测：通道配置了回调字符且未禁用检测时，上报必须携带匹配的 callback_char
	if rec.CallbackChar != "" && !rec.NoCallbackCheck && whStr(payload, "callback_char") != rec.CallbackChar {
		s.whRecv.mu.Unlock()
		s.whRecv.logAdd(channelID, "warn", "上报被拒绝：回调字符不正确（来源 "+clientIP(r)+"）")
		s.writeJSON(w, http.StatusUnauthorized, apiErr("回调字符不正确"))
		return
	}
	if ipValid && portValid {
		rec.PublicIP = publicIP
		rec.PublicPort = publicPort
		rec.HTTPS = whBool(payload, "https")
	}
	if v := whStr(payload, "access_key", "accessKey"); v != "" {
		rec.AccessKey = v
	}
	// 注意：不把上报 payload 的 password 写入 rec.Password（连接密码）。
	// 客户端上报模板默认用 {link_key} 填充 password 字段，若在此写入会把连接密码
	// 覆盖成链接密钥。连接密码仅由通道配置（/api/wh/records）管理。
	rec.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
	s.whRecv.mu.Unlock()
	s.whRecv.persist()

	if !ipValid || !portValid {
		s.whRecv.logAdd(channelID, "warn", "客户端上报公网地址暂不可用（host="+publicIP+", port="+strconv.Itoa(publicPort)+"），通道保持等待状态")
	} else {
		s.whRecv.logAdd(channelID, "info", "客户端上报公网地址 "+publicIP+":"+strconv.Itoa(publicPort)+"（来源 "+clientIP(r)+"）")
	}
	s.logger.Info("[Webhook接收] "+channelID+" -> "+publicIP+":"+strconv.Itoa(publicPort),
		zap.String("channel", channelID), zap.String("ip", publicIP), zap.Int("port", publicPort))

	callback := cfg.Callback
	if callback == "" {
		callback = "更新成功"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(callback))
}

// systemPublicIP 返回接收到的最近一次有效公网地址（来自 STUN 客户端上报记录，
// 仅取非私网/非回环/非组播的公网 IP，按上报时间取最新）。
// 无有效公网记录时返回空字符串（调用方回退到本机局域网地址）。
func (s *Server) systemPublicIP() string {
	if s.whRecv == nil {
		return ""
	}
	s.whRecv.mu.RLock()
	defer s.whRecv.mu.RUnlock()
	best := ""
	bestAt := ""
	for _, rec := range s.whRecv.records {
		ip := net.ParseIP(strings.TrimSpace(rec.PublicIP))
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
			continue
		}
		if rec.UpdatedAt > bestAt {
			bestAt = rec.UpdatedAt
			best = rec.PublicIP
		}
	}
	return best
}

// handleWhAccess 通道访问入口（/tun/{channel_id}、/wh/{channel_id} 或根路径 /{channel_id} 及其子路径）。
// 访问方式：优先每通道 RedirectType，其次全局 Mode（redirect 或 proxy）。
func (s *Server) handleWhAccess(w http.ResponseWriter, r *http.Request) {
	seg := r.PathValue("channel_id")
	if seg == "" || whReserved[seg] || !whAccessRe.MatchString(seg) {
		s.whRecv.recordAccess("", false)
		http.NotFound(w, r)
		return
	}
	rec := s.whRecv.getByAccess(seg)
	if rec == nil {
		s.whRecv.recordAccess(seg, false)
		s.writeJSON(w, http.StatusNotFound, map[string]any{"error": "通道未注册或暂无连接数据", "channel_id": seg})
		return
	}
	// 兼容 /tun/{id}、/wh/{id} 与根路径 /{id} 三种访问方式，取访问段之后的子路径
	subpath := r.URL.Path
	stripped := false
	for _, prefix := range []string{"/tun/", "/wh/"} {
		if strings.HasPrefix(subpath, prefix+seg) {
			subpath = strings.TrimPrefix(subpath, prefix+seg)
			stripped = true
			break
		}
	}
	if !stripped {
		subpath = strings.TrimPrefix(subpath, "/"+seg)
	}
	if subpath == "" {
		subpath = "/"
	}
	if !strings.HasPrefix(subpath, "/") {
		subpath = "/" + subpath
	}
	s.whServeAccess(w, r, rec, subpath)
}

// whServeAccess 通道访问公共处理：密码门禁 + 公网地址校验 + 重定向/代理。
// 供根路径 /{id}、/tun/{id} 路径访问与自定义域名访问（whDomainAccessMiddleware）共用。
func (s *Server) whServeAccess(w http.ResponseWriter, r *http.Request, rec *whRecord, subpath string) {
	channelID := rec.ChannelID // 统计与日志使用真实通道ID（自定义ID/域名访问时归一到真实ID）
	// 密码保护：通道设置了连接密码时，未通过验证的访问先进入密码验证页
	if rec.Password != "" && !whAccessAuthed(r, channelID, rec.Password) {
		if r.Method == http.MethodPost {
			pwd := r.FormValue("password")
			if subtle.ConstantTimeCompare([]byte(pwd), []byte(rec.Password)) == 1 {
				http.SetCookie(w, &http.Cookie{
					Name:     "wh_auth_" + channelID,
					Value:    whAuthToken(channelID, rec.Password),
					Path:     "/",
					HttpOnly: true,
					MaxAge:   whAuthMaxAge,
				})
				s.whRecv.recordAccess(channelID, false)
				s.whRecv.logAdd(channelID, "info", "访问密码验证通过（来自 "+clientIP(r)+"）")
				s.logger.Info("[Webhook访问] 通道密码验证通过", zap.String("channel", channelID), zap.String("remote", clientIP(r)))
				http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)
				return
			}
			s.whRecv.recordAccess(channelID, false)
			s.whRecv.logAdd(channelID, "warn", "访问密码验证失败（来自 "+clientIP(r)+"）")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(whPasswordPage(channelID, r.URL.RequestURI(), "密码错误，请重新输入")))
			return
		}
		s.whRecv.recordAccess(channelID, false)
		s.whRecv.logAdd(channelID, "info", "访问通道需密码验证（来自 "+clientIP(r)+"）")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(whPasswordPage(channelID, r.URL.RequestURI(), "")))
		return
	}
	// 通道已注册但客户端尚未上报公网地址（手动注册后等待上报）
	if rec.PublicIP == "" || rec.PublicPort == 0 {
		s.whRecv.recordAccess(channelID, false)
		s.whRecv.logAdd(channelID, "warn", "访问通道但公网地址尚未上报（来自 "+clientIP(r)+"）")
		s.writeJSON(w, http.StatusNotFound, map[string]any{"error": "通道暂无连接数据，等待客户端上报", "channel_id": channelID})
		return
	}

	scheme := "http"
	if rec.HTTPS {
		scheme = "https"
	}
	host := net.JoinHostPort(rec.PublicIP, strconv.Itoa(rec.PublicPort))

	// 访问方式解析：每通道覆盖 > 全局。
	// 空（跟随全局）时按全局 Mode 决定：redirect -> 302 跳转；proxy -> 反向代理。
	redirectType := rec.RedirectType
	if redirectType == "" {
		if s.whReceiverCfg().Mode == "proxy" {
			redirectType = "proxy"
		} else {
			redirectType = "302"
		}
	}

	switch redirectType {
	case "proxy", "ws":
		// 反向代理 / WebSocket 隧道：透明转发，支持 Upgrade 长连接
		s.whRecv.logAdd(channelID, "info", "反向代理 → "+scheme+"://"+host+subpath+"（来自 "+clientIP(r)+"）")
		s.logger.Info("[Webhook代理] "+channelID+" "+r.URL.Path+" -> "+scheme+"://"+host+subpath,
			zap.String("mode", redirectType), zap.String("remote", clientIP(r)))
		proxy, done := s.whReverseProxy(channelID, scheme, host, subpath)
		if proxy == nil {
			s.whRecv.recordAccess(channelID, false)
			s.whRecv.logAdd(channelID, "error", "反向代理目标地址解析失败")
			s.writeJSON(w, http.StatusBadGateway, apiErr("目标地址解析失败"))
			return
		}
		proxy.ServeHTTP(w, r)
		if !*done {
			s.whRecv.recordAccess(channelID, true)
		}
	case "html":
		s.whServeHTMLProxy(w, r, channelID, scheme, host, subpath)
	case "cors":
		s.whServeCORSProxy(w, r, channelID, scheme, host, subpath)
	case "301", "302", "307", "308":
		// 客户端跳转：302/301 允许方法变更；307/308 严格保留请求方法
		target := scheme + "://" + host + subpath
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		code, _ := strconv.Atoi(redirectType)
		s.whRecv.recordAccess(channelID, true)
		s.whRecv.logAdd(channelID, "info", "重定向 "+strconv.Itoa(code)+" → "+target+"（来自 "+clientIP(r)+"）")
		s.logger.Info("[Webhook重定向] "+channelID+" "+strconv.Itoa(code)+" -> "+target,
			zap.String("remote", clientIP(r)))
		http.Redirect(w, r, target, code)
	default:
		// 重定向（跟随全局 redirect）：默认 302（GET/HEAD）/ 307（其余方法，保留请求体与方法）
		target := scheme + "://" + host + subpath
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		code := http.StatusFound
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			code = http.StatusTemporaryRedirect
		}
		s.whRecv.recordAccess(channelID, true)
		s.whRecv.logAdd(channelID, "info", "重定向 "+strconv.Itoa(code)+" → "+target+"（来自 "+clientIP(r)+"）")
		s.logger.Info("[Webhook重定向] "+channelID+" "+strconv.Itoa(code)+" -> "+target,
			zap.String("remote", clientIP(r)))
		http.Redirect(w, r, target, code)
	}
}

// whDomainAccessMiddleware 自定义域名直达：请求 Host 匹配某通道的自定义域名时，
// 直接按该通道处理（跳转/代理到其公网地址），域名根路径即可访问，无需 /{id} 路径。
func (s *Server) whDomainAccessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		rec := s.whRecv.getByDomain(host)
		if rec == nil {
			next.ServeHTTP(w, r)
			return
		}
		s.whServeAccess(w, r, rec, r.URL.Path)
	})
}

// whAuthToken 生成通道访问会话令牌（channelID+密码 的哈希，无需服务端会话存储）。
func whAuthToken(channelID, password string) string {
	h := sha256.Sum256([]byte("tunhook-wh:" + channelID + ":" + password))
	return hex.EncodeToString(h[:])
}

// whAccessAuthed 校验访问者是否已通过该通道的密码验证（基于 Cookie 中的会话令牌）。
func whAccessAuthed(r *http.Request, channelID, password string) bool {
	if password == "" {
		return true
	}
	c, err := r.Cookie("wh_auth_" + channelID)
	if err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(whAuthToken(channelID, password))) == 1
}

// whPasswordPage 返回通道访问密码验证页（HTML）。
func whPasswordPage(channelID, action, errMsg string) string {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<p class="err">` + html.EscapeString(errMsg) + `</p>`
	}
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>访问验证 · 通道 ` + channelID + `</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f1115;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:#e5e7eb}
.card{width:340px;background:#171a21;border:1px solid #262b36;border-radius:12px;padding:32px 28px;box-shadow:0 8px 30px rgba(0,0,0,.4)}
h1{font-size:18px;font-weight:600;text-align:center;margin-bottom:6px}
.sub{font-size:12px;color:#8b93a1;text-align:center;margin-bottom:24px}
label{display:block;font-size:12px;color:#aab3c0;margin-bottom:6px}
input{width:100%;height:40px;border:1px solid #2c3340;border-radius:8px;background:#0f1115;color:#e5e7eb;padding:0 12px;font-size:14px;outline:none;margin-bottom:16px}
input:focus{border-color:#4f8cff}
button{width:100%;height:40px;border:none;border-radius:8px;background:#4f8cff;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
button:hover{background:#3d78e6}
.err{color:#f87171;font-size:12px;text-align:center;margin-top:12px}
</style>
</head>
<body>
<div class="card">
<h1>访问验证</h1>
<div class="sub">` + channelID + ` 已启用密码保护</div>
<form method="post" action="` + html.EscapeString(action) + `" autocomplete="off">
<label for="pwd">访问密码</label>
<input type="password" id="pwd" name="password" placeholder="请输入访问密码" autofocus required>
<button type="submit">确认</button>
` + errHTML + `
</form>
</div>
</body>
</html>`
}

// serveWhIndexPage 外部访问 Webhook 端口/域名根路径时的通道查找页：
// 输入通道ID/自定义ID 直达，或从已注册通道列表选择（数据经 /api/wh/records 动态加载）。
func (s *Server) serveWhIndexPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Write([]byte(whIndexPageHTML))
}

// whIndexPageHTML 状态页（内联）：参考 DeepSeek 状态页（https://status.deepseek.com/）设计，
// 顶部为总体状态徽章 + 通道直达搜索框，下方为「服务运行情况」组件列表（可用性 + 柱状图），
// 数据由前端 fetch /api/status/overview 动态加载，每 60s 自动刷新。
const whIndexPageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>内网穿透 · 服务状态</title>
<link rel="icon" type="image/svg+xml" href="/static/icon.svg">
<style>
:root{--bg:#0f1115;--card:#171a21;--border:#262b36;--text:#e5e7eb;--muted:#8b93a1;--muted2:#4b5260;--tipbg:#0b0d11;--footbg:rgba(15,17,21,.85);--bar-empty:#2c3340}
:root[data-theme="light"]{--bg:#f6f7f9;--card:#fff;--border:#e2e5ea;--text:#1c2026;--muted:#69707c;--muted2:#9aa1ac;--tipbg:#fff;--footbg:rgba(255,255,255,.88);--bar-empty:#e2e5ea}
@media (prefers-color-scheme:light){
  :root[data-theme="auto"]{--bg:#f6f7f9;--card:#fff;--border:#e2e5ea;--text:#1c2026;--muted:#69707c;--muted2:#9aa1ac;--tipbg:#fff;--footbg:rgba(255,255,255,.88);--bar-empty:#e2e5ea}
}
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;transition:background .2s,color .2s}
.wrap{width:100%;max-width:880px;margin:0 auto;padding:48px 20px 88px}
header{text-align:center;margin-bottom:24px}
.logo{width:52px;height:52px;margin:0 auto 14px;border-radius:14px;object-fit:cover;box-shadow:0 8px 24px rgba(79,140,255,.35)}
h1{font-size:22px;font-weight:700;letter-spacing:.5px}
.sub{font-size:13px;color:var(--muted);margin-top:6px}
.badge{display:inline-flex;align-items:center;gap:8px;margin-top:14px;padding:7px 14px;border-radius:999px;font-size:13px;font-weight:600;border:1px solid var(--border);background:var(--card)}
.badge .dot{width:8px;height:8px;border-radius:50%}
.badge.ok{color:#22c55e;border-color:rgba(34,197,94,.35)}
.badge.ok .dot{background:#22c55e;box-shadow:0 0 10px rgba(34,197,94,.7)}
.badge.warn{color:#f97316;border-color:rgba(249,115,22,.35)}
.badge.warn .dot{background:#f97316;box-shadow:0 0 10px rgba(249,115,22,.7)}
.badge.error{color:#ef4444;border-color:rgba(239,68,68,.35)}
.badge.error .dot{background:#ef4444;box-shadow:0 0 10px rgba(239,68,68,.7)}
.search{position:relative;max-width:600px;margin:28px auto 36px}
.search input{display:block;width:min(100%,400px);margin:0 auto;height:44px;border:1px solid var(--border);border-radius:10px;background:var(--card);color:var(--text);padding:0 16px;font-size:14px;outline:none;text-align:center}
.search input:focus{border-color:#4f8cff}
.search button{position:absolute;top:0;left:50%;margin-left:calc(200px + 10px);height:44px;padding:0 22px;border:none;border-radius:10px;background:#4f8cff;color:#fff;font-size:14px;font-weight:600;cursor:pointer;white-space:nowrap}
.search button:hover{background:#3d78e6}
@media (max-width:540px){
  .search{display:flex;gap:10px}
  .search input{margin:0;flex:1;min-width:0}
  .search button{position:static;margin-left:0}
}
.sec-title{font-size:16px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.sec-title .upd{font-size:12px;color:var(--muted2);font-weight:400}
.svc{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:16px 18px;margin-bottom:12px}
.svc-top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.svc-ic{width:18px;height:18px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}
.svc-ic svg{width:10px;height:10px;stroke:#fff;fill:none;stroke-width:3;stroke-linecap:round;stroke-linejoin:round}
.svc-ic.ok{background:#22c55e}
.svc-ic.warn{background:#f97316}
.svc-ic.error{background:#ef4444}
.svc-name{font-size:14px;font-weight:600;white-space:nowrap}
.svc-rate{margin-left:auto;font-size:13px;color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}
.svc-rate b{color:var(--text);font-weight:600}
.svc-cnt{font-size:12px;color:var(--muted);margin-left:2px}
.svc-chev{width:16px;height:16px;stroke:var(--muted);fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0;transition:transform .2s}
.svc.expandable{cursor:pointer}
.svc.expandable.open .svc-chev{transform:rotate(180deg)}
.svc-bars{margin-top:12px}
.svc-bars svg{display:block;width:100%;height:16px}
.svc-detail{display:none;margin-top:12px;border-top:1px solid var(--border);padding-top:12px}
.svc.expandable.open .svc-detail{display:block}
.d-item{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:13px}
.d-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.d-dot.ok{background:#22c55e}
.d-dot.fail{background:#ef4444}
.d-name{font-weight:500;white-space:nowrap}
.d-tag{font-size:11px;color:#4f8cff;background:rgba(79,140,255,.12);border-radius:6px;padding:2px 6px;margin-left:6px}
.d-addr{margin-left:auto;color:var(--muted);font-variant-numeric:tabular-nums;text-align:right}
.d-bars{margin:-2px 0 8px;padding-left:16px}
.d-bars svg{display:block;width:100%;height:16px}
#tip{position:fixed;z-index:99;display:none;pointer-events:none;background:var(--tipbg);border:1px solid var(--border);color:var(--text);font-size:12px;padding:4px 9px;border-radius:6px;white-space:nowrap;box-shadow:0 4px 16px rgba(0,0,0,.4)}
footer{position:fixed;left:0;right:0;bottom:0;text-align:center;padding:14px 0;font-size:12px;color:var(--muted2);background:var(--footbg)}
.empty{text-align:center;color:var(--muted);font-size:13px;padding:24px 0}
.topbar{position:fixed;top:14px;right:16px;display:flex;gap:8px;z-index:50}
.tb-btn{width:36px;height:36px;display:inline-flex;align-items:center;justify-content:center;border-radius:10px;border:1px solid var(--border);background:var(--card);color:var(--text);cursor:pointer;transition:.15s}
.tb-btn:hover{border-color:#4f8cff}
.tb-btn svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
</style>
</head>
<body>
<div class="topbar">
<button class="tb-btn" id="langBtn" type="button" title="Language"><svg viewBox="0 0 24 24"><path d="m5 8 6 6"></path><path d="m4 14 6-6 2-3"></path><path d="M2 5h12"></path><path d="M7 2h1"></path><path d="m22 22-5-10-5 10"></path><path d="M14 18h6"></path></svg></button>
<button class="tb-btn" id="themeBtn" type="button" title="Theme"><svg class="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2"></path><path d="M12 20v2"></path><path d="m4.93 4.93 1.41 1.41"></path><path d="m17.66 17.66 1.41 1.41"></path><path d="M2 12h2"></path><path d="M20 12h2"></path><path d="m6.34 17.66-1.41 1.41"></path><path d="m19.07 4.93-1.41 1.41"></path></svg><svg class="i-moon" viewBox="0 0 24 24" style="display:none"><path d="M20.985 12.486a9 9 0 1 1-9.473-9.472c.405-.022.617.46.402.803a6 6 0 0 0 8.268 8.268c.344-.215.825-.004.803.401"></path></svg></button>
</div>
<div class="wrap">
<header>
<img class="logo" src="/static/icon.svg" alt="TunHook">
<h1 id="h1">内网穿透 · 服务状态</h1>
<div class="sub" id="sub">输入通道 ID 或自定义 ID 直达，或查看下方服务运行情况</div>
<div class="badge" id="badge"><span class="dot"></span><span id="badgeTxt">加载中…</span></div>
</header>
<div class="search">
<input id="q" placeholder="输入通道 ID 或自定义 ID" autocomplete="off" autofocus>
<button id="go">访问通道</button>
</div>
<div class="sec-title"><span id="secLbl">服务运行情况</span> <span class="upd" id="upd"></span></div>
<div id="list"></div>
<div id="tip"></div>
<footer id="foot">TunHook 内网穿透</footer>
</div>
<script>
(function(){
var q=document.getElementById('q'),go=document.getElementById('go'),list=document.getElementById('list'),
    badge=document.getElementById('badge'),badgeTxt=document.getElementById('badgeTxt'),upd=document.getElementById('upd'),
    h1=document.getElementById('h1'),subEl=document.getElementById('sub'),secLbl=document.getElementById('secLbl'),
    foot=document.getElementById('foot'),
    langBtn=document.getElementById('langBtn'),themeBtn=document.getElementById('themeBtn'),
    themeSun=themeBtn.querySelector('.i-sun'),themeMoon=themeBtn.querySelector('.i-moon');
var LANG='auto',THEME='auto',lastData=null,curOverall=null;
try{LANG=localStorage.getItem('wh_lang')||'auto'}catch(e){}
try{THEME=localStorage.getItem('wh_theme')||'auto'}catch(e){}
var I18N={
title:{zh:'内网穿透 · 服务状态',en:'Intranet Tunnel · Service Status'},
sub:{zh:'输入通道 ID 或自定义 ID 直达，或查看下方服务运行情况',en:'Enter a channel ID or custom ID to open it, or view the service status below'},
badgeLoad:{zh:'加载中…',en:'Loading…'},
badge:{ok:{zh:'所有系统运行正常',en:'All systems operational'},warn:{zh:'部分服务运行异常',en:'Partial service disruption'},error:{zh:'服务不可用',en:'Service unavailable'}},
ph:{zh:'输入通道 ID 或自定义 ID',en:'Enter channel ID or custom ID'},
go:{zh:'访问通道',en:'Open'},
sec:{zh:'服务运行情况',en:'Service Status'},
upd:{zh:'更新于 ',en:'Updated '},
avail:{zh:'可用性',en:'availability'},
servers:{zh:' 个服务器',en:' servers'},
current:{zh:'当前',en:'active'},
offline:{zh:'离线',en:'offline'},
status:{'1':{zh:'正常',en:'Operational'},'0':{zh:'故障',en:'Outage'},'2':{zh:'部分异常',en:'Partial'},'3':{zh:'无数据',en:'No data'}},
empty:{zh:'暂无状态数据',en:'No status data'},
loadFail:{zh:'状态加载失败',en:'Failed to load status'},
footer:{zh:'TunHook 内网穿透',en:'TunHook Intranet Tunnel'},
name:{frpc:{zh:'frpc 客户端',en:'frpc Client'},server:{zh:'frps 服务器',en:'frps Server'},webhook:{zh:'Webhook 通道',en:'Webhook Channel'},forward:{zh:'转发规则',en:'Forward Rules'}},
langAuto:{zh:'自动 · 跟随浏览器',en:'Auto · follow browser'},
langZh:{zh:'中文',en:'Chinese'},
langEn:{zh:'English',en:'English'},
themeAuto:{zh:'自动 · 跟随系统',en:'Auto · follow system'},
themeLight:{zh:'浅色',en:'Light'},
themeDark:{zh:'深色',en:'Dark'}
};
function curLang(){return LANG==='auto'?((navigator.language||'').toLowerCase().indexOf('zh')===0?'zh':'en'):LANG;}
function T(k){var v=I18N[k];if(!v)return k;var l=curLang();return v[l]||v['zh'];}
function T3(g,k){var v=I18N[g];if(!v||!v[k])return k;var l=curLang();return v[k][l]||v[k]['zh'];}
function jump(v){v=(v||'').trim().toLowerCase();if(v)location.href='/'+encodeURIComponent(v);}
go.onclick=function(){jump(q.value)};
q.onkeydown=function(e){if(e.key==='Enter')jump(q.value)};
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function emptyColor(){var c=getComputedStyle(document.documentElement).getPropertyValue('--bar-empty').trim();return c||'#2c3340';}
var COLORS={'1':'#22c55e','0':'#ef4444','2':'#f97316','3':'#2c3340'};
var ICONS={
'ok':'<svg viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"></path></svg>',
'warn':'<svg viewBox="0 0 24 24"><path d="M12 9v4"></path><path d="M12 17h.01"></path></svg>',
'error':'<svg viewBox="0 0 24 24"><path d="M18 6 6 18"></path><path d="M6 6l12 12"></path></svg>'};
function barsSVG(bars,times){
  var tAttr=(times&&times.length)?times.join('|'):'';
  var step=6.5,bw=5,h=16,rx=2,x=0,s='';
  for(var i=0;i<bars.length;i++){
    var v=bars[i];if(v==null||isNaN(v))v=3;
    var c=(v===3)?emptyColor():(COLORS[String(v)]||COLORS['3']);
    var op=(v===3)?0.45:1;
    var t=(times&&times[i])||'';
    s+='<rect data-i="'+i+'" data-t="'+esc(t)+'" data-v="'+v+'" x="'+x+'" y="0" width="'+bw+'" height="'+h+'" rx="'+rx+'" ry="'+rx+'" fill="'+c+'" opacity="'+op+'"></rect>';
    x+=step;
  }
  var w=Math.max(bars.length*step-step+bw,100);
  return '<svg data-times="'+tAttr+'" viewBox="0 0 '+w+' 16" preserveAspectRatio="none" width="100%" height="16">'+s+'</svg>';
}
function nameFor(c){var m=I18N.name[c.id];if(m){var l=curLang();return m[l]||m['zh'];}return c.name;}
function detailHTML(detail){
  var s='';
  for(var i=0;i<detail.length;i++){
    var d=detail[i];
    var dot=d.online?'<span class="d-dot ok"></span>':'<span class="d-dot fail"></span>';
    var right=d.online?((d.latency_ms==null||d.latency_ms<0?'—':d.latency_ms)+' ms'):(d.error||T('offline'));
    s+='<div class="d-item">'+dot+'<span class="d-name">'+esc(d.name)+'</span>'+
       (d.active?'<span class="d-tag">'+esc(T('current'))+'</span>':'')+
       '<span class="d-addr">'+esc(d.addr)+' · '+esc(right)+'</span></div>'+
       (d.bars&&d.bars.length?'<div class="d-bars">'+barsSVG(d.bars,d.times)+'</div>':'');
  }
  return s;
}
function render(d){
  lastData=d;
  var comps=(d&&d.data&&d.data.components)||[];
  if(!comps.length){list.innerHTML='<div class="empty">'+esc(T('empty'))+'</div>';return;}
  var html='';
  for(var i=0;i<comps.length;i++){
    var c=comps[i],st=c.status||'ok';
    var rate=(c.rate==null)?'—':(Number(c.rate).toFixed(1)+'%');
    var hasDetail=c.detail&&c.detail.length;
    html+='<div class="svc'+(hasDetail?' expandable':'')+'">'+
      '<div class="svc-top">'+
        '<span class="svc-ic '+esc(st)+'">'+ICONS[st]+'</span>'+
        '<span class="svc-name">'+esc(nameFor(c))+'</span>'+
        (hasDetail?'<span class="svc-cnt">'+c.detail.length+esc(T('servers'))+'</span>':'')+
        (hasDetail?'<svg class="svc-chev" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"></path></svg>':'')+
        '<span class="svc-rate"><b>'+rate+'</b> '+esc(T('avail'))+'</span>'+
      '</div>'+
      '<div class="svc-bars">'+barsSVG(c.bars||[],c.times||[])+'</div>'+
      (hasDetail?'<div class="svc-detail">'+detailHTML(c.detail)+'</div>':'')+
    '</div>';
  }
  list.innerHTML=html;
}
function setBadge(o){
  curOverall=o;
  var map={'ok':'ok','warn':'warn','error':'error'};
  badge.className='badge '+(map[o]||'error');
  badgeTxt.textContent=o?(T3('badge',o)):(T('badgeLoad'));
}
function load(){
  fetch('/api/status/overview').then(function(r){return r.json()}).then(function(d){
    render(d);
    setBadge(d&&d.data&&d.data.overall);
    if(d&&d.data&&d.data.updated){
      upd.textContent=T('upd')+new Date(d.data.updated).toLocaleTimeString(curLang()==='zh'?'zh-CN':'en-US',{hour12:false});
    }
  }).catch(function(){
    list.innerHTML='<div class="empty">'+esc(T('loadFail'))+'</div>';
    setBadge('error');
  });
}
// ===== 语言 / 主题（点击按钮切换；默认 auto，点击后可固定） =====
function applyLang(){
  h1.textContent=T('title');
  document.title=T('title');
  subEl.textContent=T('sub');
  q.placeholder=T('ph');
  go.textContent=T('go');
  secLbl.textContent=T('sec');
  foot.textContent=T('footer');
  if(lastData&&lastData.data&&lastData.data.updated){
    upd.textContent=T('upd')+new Date(lastData.data.updated).toLocaleTimeString(curLang()==='zh'?'zh-CN':'en-US',{hour12:false});
  }
  if(curOverall){badgeTxt.textContent=T3('badge',curOverall);}else{badgeTxt.textContent=T('badgeLoad');}
}
// 主题按钮：点击脱离 auto，在 light↔dark 间固定切换（首次从当前生效主题取反，产生可见变化）
function nextTheme(v){
  var dark=(window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').matches);
  if(v==='auto')return dark?'light':'dark';
  if(v==='dark')return 'light';
  if(v==='light')return 'dark';
  return v;
}
function applyTheme(){
  document.documentElement.setAttribute('data-theme',THEME);
  var dark=(THEME==='dark')||(THEME==='auto'&&window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').matches);
  themeSun.style.display=dark?'none':'';
  themeMoon.style.display=dark?'':'none';
  if(lastData)render(lastData); // 刷新无数据柱色
}
// 语言按钮：点击脱离 auto，在 zh↔en 间固定切换（首次从当前生效语言取反，产生可见变化）
langBtn.onclick=function(e){
  e.stopPropagation();
  var cur=(LANG==='auto')?curLang():LANG;
  LANG=(cur==='zh')?'en':'zh';
  try{localStorage.setItem('wh_lang',LANG)}catch(_){}
  applyLang();
};
// 主题按钮：auto → dark → light → auto
themeBtn.onclick=function(e){
  e.stopPropagation();
  THEME=nextTheme(THEME);
  try{localStorage.setItem('wh_theme',THEME)}catch(_){}
  applyTheme();
};
if(window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').addEventListener){
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change',function(){if(THEME==='auto')applyTheme();});
}
// 点击可展开的服务行（如多 frps 服务器）切换详情显示
list.addEventListener('click',function(e){
  var row=e.target.closest('.svc.expandable');
  if(!row)return;
  row.classList.toggle('open');
});
// 悬停柱状图格子显示对应时间与状态
var tip=document.getElementById('tip');
list.addEventListener('mousemove',function(e){
  var r=e.target.closest('rect[data-v]');
  if(!r){tip.style.display='none';return;}
  var t=r.getAttribute('data-t')||'';
  var v=r.getAttribute('data-v')||'3';
  var st=T3('status',v);
  tip.textContent=t?(t+' · '+st):st;
  tip.style.display='block';
  var x=e.clientX+12,y=e.clientY+14;
  var tw=tip.offsetWidth,th=tip.offsetHeight;
  if(x+tw>window.innerWidth-8)x=window.innerWidth-tw-8;
  if(y+th>window.innerHeight-8)y=window.innerHeight-th-8;
  tip.style.left=x+'px';
  tip.style.top=y+'px';
});
list.addEventListener('mouseleave',function(){tip.style.display='none';});
applyTheme();
applyLang();
load();
setInterval(load,60000);
})();
</script>
</body>
</html>`

// handleWhPublicRecords 通道查找页数据源（Webhook 端口公开接口）：
// 仅返回公开信息（通道ID/自定义ID/描述/分组/是否有密码），不含密码、链接密钥等敏感字段。
func (s *Server) handleWhPublicRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	recs := s.whRecv.list()
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		out = append(out, map[string]any{
			"channel_id":  rec.ChannelID,
			"custom_id":   rec.CustomID,
			"description": rec.Description,
			"group":       rec.Group,
			"password":    rec.Password != "", // 仅标记是否启用密码，不暴露密码本身
		})
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]any{"records": out}))
}

// whComponent 状态页单个系统组件。
type whComponent struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Status string   `json:"status"`           // ok | warn | error
	Meta   string   `json:"meta"`             // 组件摘要（代理数/延迟/通道数等）
	Rate   float64  `json:"rate"`             // 可用性 %
	Bars   []int    `json:"bars"`             // 柱状图：0=失败 1=正常 2=部分异常 3=无数据（最新在右）
	Times  []string `json:"times,omitempty"`  // 与 bars 对齐的每格时间/日期（未采样为空）
	Detail []any    `json:"detail,omitempty"` // 展开详情（如多 frps 服务器列表）
}

// whServerDetail 状态页 frps 服务器详情（多服务器时可展开查看）。
type whServerDetail struct {
	Name      string   `json:"name"`
	Addr      string   `json:"addr"`
	Active    bool     `json:"active"`
	Online    bool     `json:"online"`
	LatencyMS int64    `json:"latency_ms"`
	Error     string   `json:"error,omitempty"`
	Bars      []int    `json:"bars,omitempty"`  // 该服务器独立可用性采样（0=失败 1=正常 3=无数据，最新在右）
	Times     []string `json:"times,omitempty"` // 与 bars 对齐的采样时间（MM-DD HH:MM）
}

// httpRTT 对目标主机做一次 HTTP 往返（80 走 http，443 走 https，2s 超时），
// 返回首响应耗时 ms 与是否成功。TCP connect 经本地隧道（如 FlClash TUN）时
// 无法反映真实 RTT（常为 0ms），必须用应用层往返才能测出真实延迟。
func httpRTT(host string, port int) (int64, bool) {
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		return 0, false
	}
	resp.Body.Close()
	return time.Since(start).Milliseconds(), true
}

// probeFrpServer 探测单个 frp 服务器：TCP 连通性（单次连接，2s 超时），
// 延迟用 HTTP 往返测量（80 → 443），两者皆无 HTTP 时回退 connect 耗时。
// 返回延迟 ms（-1=不可达）与错误。
func probeFrpServer(host string, port int) (int64, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return -1, err.Error()
	}
	conn.Close()
	connectMS := time.Since(start).Milliseconds()
	for _, p := range []int{80, 443} {
		if ms, ok := httpRTT(host, p); ok {
			return ms, ""
		}
	}
	return connectMS, ""
}

// handleWhStatusOverview 状态页公开接口（Webhook 端口）：
// 返回系统组件运行情况（frpc 客户端 / frps 服务器 / Webhook 通道 / 转发规则）与总体状态，
// 供状态页参考 DeepSeek 状态页样式渲染「服务运行情况」。
func (s *Server) handleWhStatusOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	comps := s.whComponentStatus()
	overall := "ok"
	for _, c := range comps {
		switch c.Status {
		case "error":
			overall = "error"
		case "warn":
			if overall != "error" {
				overall = "warn"
			}
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]any{
		"overall":    overall,
		"updated":    time.Now().Format(time.RFC3339),
		"components": comps,
	}))
}

// whComponentStatus 汇总各系统组件当前状态。
func (s *Server) whComponentStatus() []whComponent {
	out := make([]whComponent, 0, 4)

	// ---- frpc 客户端 ----
	st := s.frpcMgr.Status()
	states, _, _ := s.frpcProxyRuntime()
	frpcOK := st.Running
	frpcStatus := "ok"
	if !frpcOK {
		frpcStatus = "error"
	} else {
		for _, v := range states {
			if v == "error" {
				frpcStatus = "warn"
				break
			}
		}
	}
	s.whRecv.histSample("frpc", frpcOK)
	frpcMeta := fmt.Sprintf("%d 个代理", len(states))
	if !frpcOK {
		frpcMeta = "未连接"
	} else if st.Version != "" {
		frpcMeta += " · v" + st.Version
	}
	frpcBars, frpcTimes := s.whRecv.histFixed("frpc")
	out = append(out, whComponent{
		ID: "frpc", Name: "frpc 客户端", Status: frpcStatus, Meta: frpcMeta,
		Rate: s.whRecv.histRate("frpc"), Bars: frpcBars, Times: frpcTimes,
	})

	// ---- frps 服务器（延迟探测） ----
	ms, _, lastErr := s.measureFrpcLatency("")
	srvOK := ms >= 0
	s.whRecv.histSample("server", srvOK)
	srvStatus := "ok"
	if !srvOK {
		srvStatus = "error"
	}
	srvBars, srvTimes := s.whRecv.histFixed("server")
	srvComp := whComponent{
		ID: "server", Name: "frps 服务器", Status: srvStatus,
		Rate: s.whRecv.histRate("server"), Bars: srvBars, Times: srvTimes,
	}
	// 服务器详情（可展开查看）：始终返回，1 个或多个服务器均可展开，激活服务器复用上面的测量结果
	if cfg := s.frpcMgr.LoadConfig(); len(cfg.Servers) > 0 {
		for _, sv := range cfg.Servers {
			port := sv.Port
			if port <= 0 {
				port = frpc.DefaultPort
			}
			sAddr := net.JoinHostPort(strings.TrimSpace(sv.Addr), strconv.Itoa(port))
			det := whServerDetail{Name: sv.Name, Addr: sAddr, Active: sv.Name == cfg.ActiveServer}
			if det.Active {
				det.Online = srvOK
				if srvOK {
					det.LatencyMS = ms
				} else {
					det.Error = lastErr
				}
			} else {
				if l, e := probeFrpServer(strings.TrimSpace(sv.Addr), port); l >= 0 {
					det.Online = true
					det.LatencyMS = l
				} else {
					det.Error = e
				}
			}
			// 每台服务器独立可用性采样（按服务器名建环，重启后延续）
			srvKey := "server:" + det.Name
			s.whRecv.histSample(srvKey, det.Online)
			det.Bars, det.Times = s.whRecv.histFixed(srvKey)
			srvComp.Detail = append(srvComp.Detail, det)
		}
	}
	out = append(out, srvComp)

	// ---- Webhook 通道（接收地址连通性测试） ----
	// 有效性 = 客户端上报用的「接收地址」能否连通，采样环与 frpc/服务器一致；
	// 跟随 Webhook 接收设置（地址模式/访问域名/访问IP/接收端口），按完整接收地址做 HTTP 探测，
	// 而非仅 TCP 连 host:port（域名模式经 frpc 代理走 443，不含接收端口）。
	// 接收地址可在设置中修改，变化时自动清空旧采样、从新地址重新统计。
	recvURL, addrOK := s.whReceiveURL()
	whStatus := "ok"
	whMeta := ""
	if !addrOK {
		if s.whRecv.whSetAddr("") {
			s.whRecv.persist()
		}
		whStatus = "warn"
		whMeta = "未配置接收地址"
	} else {
		if s.whRecv.whSetAddr(recvURL) {
			s.whRecv.persist()
		}
		start := time.Now()
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(recvURL)
		whOK := err == nil
		if resp != nil {
			resp.Body.Close()
		}
		s.whRecv.histSample("whrecv", whOK)
		whMeta = "接收地址 " + recvURL
		if !whOK {
			whStatus = "error"
			whMeta += " · 无法连接"
		} else {
			whMeta += fmt.Sprintf(" · 延迟 %d ms", time.Since(start).Milliseconds())
		}
	}
	whBars, whTimes := s.whRecv.histFixed("whrecv")
	out = append(out, whComponent{
		ID: "webhook", Name: "Webhook 通道", Status: whStatus,
		Meta: whMeta,
		Rate: s.whRecv.histRate("whrecv"), Bars: whBars, Times: whTimes,
	})

	// ---- 转发规则 ----
	var ruleN, runN int
	if s.fwdMgr != nil {
		ruleN = len(s.fwdMgr.LoadSavedRules())
		runN = len(s.fwdMgr.RunningRules())
	}
	fwdStatus := "ok"
	switch {
	case ruleN > 0 && runN == 0:
		fwdStatus = "error"
	case runN < ruleN:
		fwdStatus = "warn"
	}
	s.whRecv.histSample("forward", runN > 0 || ruleN == 0)
	fwdMeta := fmt.Sprintf("%d 条规则", ruleN)
	if runN > 0 {
		fwdMeta = fmt.Sprintf("%d 条运行中 · %d 条规则", runN, ruleN)
	}
	fwdBars, fwdTimes := s.whRecv.histFixed("forward")
	out = append(out, whComponent{
		ID: "forward", Name: "转发规则", Status: fwdStatus, Meta: fwdMeta,
		Rate: s.whRecv.histRate("forward"), Bars: fwdBars, Times: fwdTimes,
	})

	return out
}

// deleteWhChannelCascade 删除 Webhook 通道并级联清理其 frpc 自定义域名代理。
// 通道不存在返回 false。Webhook 页面删除与 STUN 打洞联动删除共用此入口，
// 保证两条路径的清理口径一致（联动通道可能已被用户配置自定义域名代理，
// 只删记录会留下指向失效地址的孤儿 frpc 代理）。
func (s *Server) deleteWhChannelCascade(id string) bool {
	var domain, proxyName string
	if rec := s.whRecv.get(id); rec != nil {
		domain = rec.CustomDomain
		proxyName = rec.ProxyName
	}
	if !s.whRecv.delete(id) {
		return false
	}
	if proxyName == "" {
		proxyName = whProxyNameForDomain(domain)
	}
	if proxyName != "" && s.frpcMgr != nil {
		if err := s.frpcMgr.DeleteProxy(proxyName); err != nil {
			s.logger.Warn("删除通道时清理 frpc 域名代理失败", zap.String("channel", id), zap.String("proxy", proxyName), zap.Error(err))
		}
	}
	s.logger.Info("Webhook 接收记录已删除", zap.String("channel", id))
	s.whRecv.logAdd(id, "info", "通道已删除")
	return true
}

// handleWhRecords 管理接口：
//   - GET    列表
//   - POST   手动注册/编辑通道（body: channel_id/description/group/public_ip/public_port/https/redirect_type）
//   - DELETE 删除（?channel_id= 单条，否则清空）
func (s *Server) handleWhRecords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"records": s.whRecv.list()}))
	case http.MethodPost:
		body, err := parseJSONBodyLimit(r, 16<<10)
		if err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiErr("请求体格式错误"))
			return
		}
		// 通道ID：未提供时从数字ID池分配最小可用ID（从 1 开始，删除后自动回池可再次分配）；
		// 提供时（客户端/兼容场景）校验合法性并按该ID注册/更新。
		channelID := strings.ToLower(whStr(body, "channel_id"))
		isNew := false
		if channelID == "" {
			channelID = s.whRecv.allocateID()
			isNew = true
		} else if whReserved[channelID] || !whChannelRe.MatchString(channelID) {
			s.writeJSON(w, http.StatusBadRequest, apiErr("通道ID 无效（1-32 位小写字母/数字/连字符，不能为保留名称）"))
			return
		}
		// 合并式更新：仅应用请求中提供的字段，缺省保留既有值（避免编辑时清空客户端上报的地址）
		rec := s.whRecv.get(channelID)
		if rec == nil {
			rec = &whRecord{ChannelID: channelID}
			isNew = true
		}
		if _, ok := body["description"]; ok {
			rec.Description = truncateStr(whStr(body, "description"), 60)
		}
		if _, ok := body["custom_id"]; ok {
			customID := strings.ToLower(whStr(body, "custom_id"))
			if customID != "" && (whReserved[customID] || whShortLetterRe.MatchString(customID) || !whCustomIDRe.MatchString(customID)) {
				s.writeJSON(w, http.StatusBadRequest, apiErr("自定义ID 无效（2-16 位小写字母/数字/下划线/连字符；4 位及以内纯字母不可用，避免与系统接口冲突）"))
				return
			}
			if s.whRecv.customIDUsed(channelID, customID) {
				s.writeJSON(w, http.StatusConflict, apiErr("自定义ID 已被其他通道使用"))
				return
			}
			rec.CustomID = customID
		}
		if _, ok := body["custom_domain"]; ok {
			domain := strings.ToLower(whStr(body, "custom_domain"))
			if domain != "" && !whDomainRe.MatchString(domain) {
				s.writeJSON(w, http.StatusBadRequest, apiErr("自定义域名格式无效，例如 tun.example.com"))
				return
			}
			if s.whRecv.domainUsed(channelID, domain) {
				s.writeJSON(w, http.StatusConflict, apiErr("自定义域名已被其他通道使用"))
				return
			}
			rec.CustomDomain = domain
		}
		if _, ok := body["link_key"]; ok {
			lk := whStr(body, "link_key")
			if lk != "" && (len(lk) < 4 || len(lk) > 64) {
				s.writeJSON(w, http.StatusBadRequest, apiErr("链接密钥需为 4-64 位"))
				return
			}
			rec.LinkKey = lk
		}
		if _, ok := body["password"]; ok {
			rec.Password = whStr(body, "password")
		}
		if _, ok := body["webhook_url"]; ok {
			wu := whStr(body, "webhook_url")
			if wu != "" && !validHTTPURL(wu) {
				s.writeJSON(w, http.StatusBadRequest, apiErr("接口地址必须为合法的 http(s) URL"))
				return
			}
			rec.WebhookURL = wu
		}
		if _, ok := body["callback_char"]; ok {
			rec.CallbackChar = truncateStr(whStr(body, "callback_char"), 64)
		}
		if _, ok := body["webhook_method"]; ok {
			m := strings.ToUpper(whStr(body, "webhook_method"))
			if m != "" && !whWebhookMethods[m] {
				s.writeJSON(w, http.StatusBadRequest, apiErr("请求方式仅支持 GET/POST/PUT/DELETE/PATCH/HEAD"))
				return
			}
			rec.WebhookMethod = m
		}
		if _, ok := body["webhook_body"]; ok {
			rec.WebhookBody = truncateStr(whStr(body, "webhook_body"), 4096)
		}
		if _, ok := body["log_level"]; ok {
			lv := strings.ToLower(whStr(body, "log_level"))
			if lv != "" && !whLogLevels[lv] {
				s.writeJSON(w, http.StatusBadRequest, apiErr("日志级别仅支持 error/warn/info/debug"))
				return
			}
			rec.LogLevel = lv
		}
		if _, ok := body["log_entries"]; ok {
			n := whInt(body, "log_entries")
			if n != 0 && (n < 100 || n > 10000) {
				s.writeJSON(w, http.StatusBadRequest, apiErr("日志存储条数需在 100-10000 之间"))
				return
			}
			rec.LogEntries = n
		}
		if _, ok := body["log_days"]; ok {
			d := whInt(body, "log_days")
			if d != 0 && d != 7 && d != 30 && d != 90 && d != 180 && d != 365 {
				s.writeJSON(w, http.StatusBadRequest, apiErr("日志存储时间仅支持 7/30/90/180/365 天"))
				return
			}
			rec.LogDays = d
		}
		if _, ok := body["group"]; ok {
			rec.Group = whStr(body, "group")
			if rec.Group == "" {
				rec.Group = defaultGroupName
			}
		}
		if _, ok := body["public_ip"]; ok {
			ip := whStr(body, "public_ip")
			if ip != "" && net.ParseIP(ip) == nil {
				s.writeJSON(w, http.StatusBadRequest, apiErr("公网IP 必须为合法 IP 地址"))
				return
			}
			rec.PublicIP = ip
		}
		if _, ok := body["public_port"]; ok {
			port := whInt(body, "public_port")
			if port != 0 && (port < 1 || port > 65535) {
				s.writeJSON(w, http.StatusBadRequest, apiErr("公网端口必须为 1-65535"))
				return
			}
			rec.PublicPort = port
		}
		if _, ok := body["https"]; ok {
			rec.HTTPS = whBool(body, "https")
		}
		if _, ok := body["redirect_type"]; ok {
			rt := strings.ToLower(whStr(body, "redirect_type"))
			if !validWhRedirectType(rt) {
				s.writeJSON(w, http.StatusBadRequest, apiErr("访问方式仅支持 301/302/307/308/proxy 或留空跟随全局"))
				return
			}
			rec.RedirectType = rt
		}
		rec.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
		s.whRecv.upsert(rec)
		s.logger.Info("Webhook 通道已注册/更新", zap.String("channel", channelID),
			zap.Bool("new", isNew), zap.String("group", rec.Group), zap.String("ip", rec.PublicIP))
		// 创建/更新通道后自动开启 Webhook 接收（存在通道时必须保持开启，否则上报接口不可用）
		if !s.whReceiverEnabled() {
			s.cfgMu.Lock()
			s.cfg.WebhookReceiver.Enabled = true
			s.cfgMu.Unlock()
			if err := s.store.SetJSON("cfg.wh_receiver.enabled", true); err != nil {
				s.logger.Warn("自动开启 Webhook 接收持久化失败", zap.Error(err))
			}
			s.logger.Info("检测到通道存在，Webhook 接收已自动开启")
		}
		action := "通道已更新"
		if isNew {
			action = "通道已注册"
		}
		s.whRecv.logAdd(channelID, "info", action+"（描述「"+rec.Description+"」，分组「"+rec.Group+"」）")
		s.writeJSON(w, http.StatusOK, apiOK(rec))
	case http.MethodDelete:
		if id := strings.TrimSpace(r.URL.Query().Get("channel_id")); id != "" {
			if s.deleteWhChannelCascade(id) {
				s.writeJSON(w, http.StatusOK, apiOK(nil))
			} else {
				s.writeJSON(w, http.StatusNotFound, apiErr("通道不存在: "+id))
			}
			return
		}
		n := s.whRecv.clear()
		s.logger.Info("Webhook 接收记录已清空", zap.Int("count", n))
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"cleared": n}))
	default:
		http.NotFound(w, r)
	}
}

// frpcProxyByDomain 查找已占用该自定义域名的 frpc 代理名称（未占用返回空字符串）。
// 只有「已启用」且「归属当前激活服务器」的代理才会向 frps 注册该域名：
// 停用的代理在 frpc.toml 中为 enabled=false，frpc 不会注册；其它服务器上的代理由各自的
// frpc 实例注册，都不占用本服务器的域名。否则停用通道后该域名会被永久判定为占用，
// 关闭通道、重启 frpc 都无法释放。
func (s *Server) frpcProxyByDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	cfg := s.frpcMgr.LoadConfig()
	for _, p := range cfg.Proxies {
		if !p.Enabled || p.Server != cfg.ActiveServer {
			continue
		}
		for _, d := range strings.Split(p.CustomDomains, ",") {
			if strings.ToLower(strings.TrimSpace(d)) == domain {
				return p.Name
			}
		}
	}
	return ""
}

// frpcProxyUsingDomain 查找配置中使用该自定义域名的 frpc 代理名称（忽略启用状态与归属服务器）。
// 供清理旧域名代理等「按域名定位代理」的场景使用；判断域名是否被占用必须用 frpcProxyByDomain。
func (s *Server) frpcProxyUsingDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	for _, p := range s.frpcMgr.LoadConfig().Proxies {
		for _, d := range strings.Split(p.CustomDomains, ",") {
			if strings.ToLower(strings.TrimSpace(d)) == domain {
				return p.Name
			}
		}
	}
	return ""
}

// systemDomainProxyName 系统「访问域名」frpc 代理的固定名称（域名模式创建代理时使用）。
const systemDomainProxyName = "Webhook 接口"

// whProxyNameForDomain 自定义域名对应的 frpc 代理名称（旧版命名，基于域名生成，兼容已创建记录）。
func whProxyNameForDomain(domain string) string {
	return "wh-" + strings.ToLower(strings.NewReplacer(".", "-", "*", "x").Replace(domain))
}

// migrateSystemDomainProxy 将旧版系统域名代理（wh-{domain}）改名为固定名称，避免域名冲突。
func (s *Server) migrateSystemDomainProxy(oldName, newName string) error {
	cfg := s.frpcMgr.LoadConfig()
	for i := range cfg.Proxies {
		if cfg.Proxies[i].Name == oldName {
			cfg.Proxies[i].Name = newName
			return s.frpcMgr.SaveConfig(cfg)
		}
	}
	return fmt.Errorf("代理「%s」不存在", oldName)
}

// whSanitizeName 将名称清洗为 frpc 代理名可用的字符（小写字母/数字/下划线/连字符），
// 其余字符替换为连字符，去除首尾连字符并限制长度；清洗后为空返回空字符串。
func whSanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	name := strings.Trim(b.String(), "-")
	if len(name) > 40 {
		name = name[:40]
	}
	return name
}

// frpcProxyByName 按名称查找 frpc 代理（不存在返回空字符串）。
func (s *Server) frpcProxyByName(name string) string {
	if name == "" {
		return ""
	}
	for _, p := range s.frpcMgr.LoadConfig().Proxies {
		if p.Name == name {
			return p.Name
		}
	}
	return ""
}

// ensureWhDomainProxy 在默认（激活）服务器上创建/更新自定义域名的 http 代理：
// 将域名流量经 frps → frpc 回落本服务，使 /{channel_id} 可通过该域名访问。
func (s *Server) ensureWhDomainProxy(domain, name string) error {
	webAddr := s.webTCPAddr()
	if webAddr == "" {
		return fmt.Errorf("本服务未监听 TCP 端口，无法创建域名通道")
	}
	host, portStr, err := net.SplitHostPort(webAddr)
	if err != nil {
		return fmt.Errorf("无法解析本服务监听地址: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	if host == "::" || host == "" {
		host = "127.0.0.1"
	}
	if port <= 0 {
		return fmt.Errorf("本服务监听端口无效")
	}
	if name == "" {
		name = whProxyNameForDomain(domain)
	}
	proxy := frpc.Proxy{
		Name:          name,
		Type:          "http",
		Enabled:       true,
		LocalIP:       host,
		LocalPort:     port,
		CustomDomains: domain,
	}
	// 幂等创建/更新：代理已存在则按名称更新，否则新建。
	// 更新时只覆盖同步管理的路由字段，保留用户已配置的访问认证/加密压缩/带宽/健康检查等，
	// 否则域名/设置保存会覆盖代理上手动开启的 HTTP Basic 认证（表现为认证不生效）。
	exists := false
	for _, p := range s.frpcMgr.LoadConfig().Proxies {
		if p.Name == name {
			exists = true
			proxy.HTTPUser = p.HTTPUser
			proxy.HTTPPassword = p.HTTPPassword
			proxy.Encryption = p.Encryption
			proxy.Compression = p.Compression
			proxy.BandwidthLimit = p.BandwidthLimit
			proxy.SecretKey = p.SecretKey
			proxy.HealthCheck = p.HealthCheck
			break
		}
	}
	if exists {
		if err := s.frpcMgr.SaveProxyWithLog(proxy, name, frpc.LogOpts{}); err != nil {
			return fmt.Errorf("frpc 代理更新失败: %v", err)
		}
	} else if err := s.frpcMgr.SaveProxyWithLog(proxy, "", frpc.LogOpts{}); err != nil {
		return fmt.Errorf("frpc 代理创建失败: %v", err)
	}
	return nil
}

// handleWhDomainVerify 自定义域名验证 + frpc 代理通道创建：
// 校验域名格式与占用情况后，调用 frpc 代理模块在默认（激活）服务器创建域名通道。
// 代理名称规则：Webhook-通道描述（无描述使用通道ID；创建模式无通道ID时回退自定义ID）。
func (s *Server) handleWhDomainVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChannelID    string `json:"channel_id"`
		CustomID     string `json:"custom_id"`
		Description  string `json:"description"`
		CustomDomain string `json:"custom_domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体格式错误"))
		return
	}
	channelID := strings.ToLower(strings.TrimSpace(req.ChannelID))
	customID := strings.ToLower(strings.TrimSpace(req.CustomID))
	desc := strings.TrimSpace(req.Description)
	domain := strings.ToLower(strings.TrimSpace(req.CustomDomain))
	if channelID != "" && (whReserved[channelID] || !whChannelRe.MatchString(channelID)) {
		s.writeJSON(w, http.StatusBadRequest, apiErr("通道ID 无效（1-32 位小写字母/数字/连字符）"))
		return
	}
	if domain == "" || !whDomainRe.MatchString(domain) {
		s.writeJSON(w, http.StatusBadRequest, apiErr("自定义域名格式无效，例如 tun.example.com"))
		return
	}
	if channelID != "" && s.whRecv.domainUsed(channelID, domain) {
		s.writeJSON(w, http.StatusConflict, apiErr("自定义域名已被其他通道使用"))
		return
	}
	// 代理名称：Webhook-通道描述（无描述或清洗后为空时依次回退通道ID、自定义ID）
	namePart := whSanitizeName(desc)
	if namePart == "" {
		namePart = whSanitizeName(channelID)
	}
	if namePart == "" {
		namePart = whSanitizeName(customID)
	}
	if namePart == "" {
		namePart = "channel"
	}
	proxyName := "Webhook-" + namePart
	// 与其它代理重名时追加通道ID 区分（如创建模式无通道ID则用自定义ID）
	if p := s.frpcProxyByName(proxyName); p != "" {
		suffix := whSanitizeName(channelID)
		if suffix == "" {
			suffix = whSanitizeName(customID)
		}
		if suffix == "" {
			suffix = "channel"
		}
		proxyName = "Webhook-" + namePart + "-" + suffix
	}
	if p := s.frpcProxyByDomain(domain); p != "" && p != proxyName {
		s.writeJSON(w, http.StatusConflict, apiErr("该域名已被 frpc 代理「"+p+"」使用"))
		return
	}
	if err := s.ensureWhDomainProxy(domain, proxyName); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	// 记录已创建的代理名称，便于通道删除时清理
	if channelID != "" {
		if rec := s.whRecv.get(channelID); rec != nil {
			rec.ProxyName = proxyName
			rec.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
			s.whRecv.upsert(rec)
		}
	}
	s.logger.Info("Webhook 通道域名验证通过，已创建 frpc 代理", zap.String("channel", channelID),
		zap.String("domain", domain), zap.String("proxy", proxyName))
	if channelID != "" {
		s.whRecv.logAdd(channelID, "info", "已创建自定义域名代理 "+domain+"（frpc 代理 "+proxyName+"）")
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"ok":         true,
		"channel_id": channelID,
		"domain":     domain,
		"proxy_name": proxyName,
	}))
}

// handleWhSystemProxy 为系统「访问域名」（域名模式）创建/更新 frpc 域名代理：
// 将域名流量经 frps → frpc 回落本服务，使 Webhook 接收接口（/api/channel/update）与
// 通道访问（/{id}）可通过该域名使用。代理固定命名为「Webhook 接口」，幂等：已存在时按名称更新。
func (s *Server) handleWhSystemProxy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体格式错误"))
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" || !whDomainRe.MatchString(domain) {
		s.writeJSON(w, http.StatusBadRequest, apiErr("自定义域名格式无效，例如 wh.example.com"))
		return
	}
	proxyName, err := s.applySystemDomainProxy(domain)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr(err.Error()))
		return
	}
	s.logger.Info("已为系统访问域名创建 frpc 代理", zap.String("domain", domain), zap.String("proxy", proxyName))
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{
		"ok":         true,
		"domain":     domain,
		"proxy_name": proxyName,
	}))
}

// applySystemDomainProxy 为系统「访问域名」创建/更新 frpc 域名代理（幂等，供手动创建与设置保存自动同步共用）。
// 旧版 wh-{domain} 代理自动迁移为固定名称「Webhook 接口」。
func (s *Server) applySystemDomainProxy(domain string) (string, error) {
	proxyName := systemDomainProxyName
	if p := s.frpcProxyByDomain(domain); p != "" && p != proxyName {
		if p == whProxyNameForDomain(domain) {
			// 旧版系统域名代理（wh-{domain}）迁移为固定名称，避免域名冲突
			if err := s.migrateSystemDomainProxy(p, proxyName); err != nil {
				return "", err
			}
		} else {
			return "", fmt.Errorf("该域名已被 frpc 代理「%s」使用", p)
		}
	}
	if err := s.ensureWhDomainProxy(domain, proxyName); err != nil {
		return "", err
	}
	return proxyName, nil
}

// handleWhGroups 分组管理接口：GET 列表 / POST 创建 / DELETE 删除（?name=）。
func (s *Server) handleWhGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"groups": s.whRecv.groupViews()}))
	case http.MethodPost:
		body, err := parseJSONBodyLimit(r, 4<<10)
		if err != nil {
			s.writeJSON(w, http.StatusBadRequest, apiErr("请求体格式错误"))
			return
		}
		name := whStr(body, "name")
		if !s.whRecv.addGroup(name) {
			s.writeJSON(w, http.StatusBadRequest, apiErr("分组名无效（1-16 位中文/字母/数字/下划线/连字符）"))
			return
		}
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"name": name}))
	case http.MethodDelete:
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		moveTo := strings.TrimSpace(r.URL.Query().Get("moveTo"))
		if !s.whRecv.delGroup(name, moveTo) {
			s.writeJSON(w, http.StatusBadRequest, apiErr("分组不存在、不允许删除或目标分组无效"))
			return
		}
		s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"name": name, "moved_to": moveTo}))
	default:
		http.NotFound(w, r)
	}
}

// handleWhGroupRename 重命名分组（POST /api/wh/groups/rename）。
func (s *Server) handleWhGroupRename(w http.ResponseWriter, r *http.Request) {
	body, err := parseJSONBodyLimit(r, 4<<10)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("请求体格式错误"))
		return
	}
	oldName := whStr(body, "old_name")
	newName := whStr(body, "new_name")
	if !s.whRecv.renameGroup(oldName, newName) {
		s.writeJSON(w, http.StatusBadRequest, apiErr("重命名失败：名称无效、已存在或默认分组不可重命名"))
		return
	}
	s.writeJSON(w, http.StatusOK, apiOK(map[string]interface{}{"name": newName}))
}

// handleWhStats 成功率统计（供仪表盘 KPI 展示）。
func (s *Server) handleWhStats(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, apiOK(s.whRecv.stats()))
}

// groupExists 判断分组是否存在（空名称 = 默认分组，恒存在）。
func (r *whReceiver) groupExists(name string) bool {
	if name == "" {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.groups[name]
}

// stunWhOpts STUN 联动创建 Webhook 通道时的附加配置（auto=分组；custom=回调接口配置）。
type stunWhOpts struct {
	Group    string
	URL      string
	Method   string
	Body     string
	Headers  string
	Callback string
	NoCheck  bool
}

// onStunholePublicChange STUN 打洞通道公网映射变化回调（stunhole.OnPublicChange 钩子）：
// 按联动模式把可直连的公网映射地址注册到 Webhook 通道（/api/wh/records）：
//   - auto：首次自动创建新通道（数字池分配 ID，归入所选分组）并回写通道 ID，后续跟随更新
//   - select：仅更新用户选择的已有通道（通道不存在则忽略）
//   - custom：自动创建新通道并由用户自定义回调接口（URL/Method/Body），后续跟随更新
//
// CGNAT / 私有地址（stunhole 内已过滤，仅可直连时触发）不会到达此处。
func (s *Server) onStunholePublicChange(h stunhole.Hole) {
	if h.Public == "" {
		return
	}
	host, portStr, err := net.SplitHostPort(h.Public)
	if err != nil {
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return
	}
	switch h.WebhookMode {
	case "auto":
		if h.WebhookChannel != "" { // 首次联动已分配通道：跟随更新
			s.whRecv.updateStunPublic(h.WebhookChannel, h.Name, host, port)
			return
		}
		opts := stunWhOpts{Group: h.WebhookGroup}
		if cid := s.whRecv.ensureStunChannel("", h.Name, host, port, opts, s.whRecv.allocateID); cid != "" {
			s.stunholeMgr.SetWebhookChannel(h.ID, cid)
		}
	case "custom":
		if h.WebhookChannel != "" { // 首次联动已分配通道：跟随更新
			s.whRecv.updateStunPublic(h.WebhookChannel, h.Name, host, port)
			return
		}
		opts := stunWhOpts{URL: h.WebhookURL, Method: h.WebhookMethod, Body: h.WebhookBody, Headers: h.WebhookHeaders, Callback: h.WebhookCallback, NoCheck: h.WebhookNoCheck}
		if cid := s.whRecv.ensureStunChannel("", h.Name, host, port, opts, s.whRecv.allocateID); cid != "" {
			s.stunholeMgr.SetWebhookChannel(h.ID, cid)
		}
	default: // select / 空（兼容旧数据）
		if h.WebhookChannel == "" {
			return
		}
		s.whRecv.updateStunPublic(h.WebhookChannel, h.Name, host, port)
	}
}

// ensureStunChannel 确保 Webhook 通道存在并把 STUN 公网地址注册进去：
// 通道已存在则更新地址；不存在时创建（id 为空且提供 allocate 时自动分配），
// 新通道按 opts 写入分组与回调接口配置。返回实际通道 ID（校验失败返回空）。
// 仅供 STUN 打洞联动使用。
// 注意：allocate 在锁外调用，避免与持有写锁时的 RLock 重入死锁。
func (r *whReceiver) ensureStunChannel(id, stunName, ip string, port int, opts stunWhOpts, allocate func() string) string {
	// 已存在：锁内更新地址
	r.mu.Lock()
	if rec, ok := r.records[id]; ok {
		changed := rec.PublicIP != ip || rec.PublicPort != port
		if changed {
			rec.PublicIP = ip
			rec.PublicPort = port
			rec.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
		}
		r.mu.Unlock()
		if changed {
			r.persist()
		}
		return id
	}
	r.mu.Unlock()

	// 锁外分配 ID（allocateID 内部需 RLock，避免重入死锁）
	cid := id
	if cid == "" && allocate != nil {
		cid = allocate()
	}
	if cid == "" || whReserved[cid] || !whChannelRe.MatchString(cid) {
		return ""
	}
	if opts.Method == "" {
		opts.Method = "POST"
	}

	// 再次锁内创建（处理并发：可能已被其他请求抢先创建，则改为更新地址）
	r.mu.Lock()
	if rec, ok := r.records[cid]; ok {
		changed := rec.PublicIP != ip || rec.PublicPort != port
		if changed {
			rec.PublicIP = ip
			rec.PublicPort = port
			rec.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
		}
		r.mu.Unlock()
		if changed {
			r.persist()
		}
		return cid
	}
	r.records[cid] = &whRecord{
		ChannelID:       cid,
		Description:     "STUN · " + stunName,
		Group:           opts.Group,
		PublicIP:        ip,
		PublicPort:      port,
		WebhookURL:      opts.URL,
		WebhookMethod:   opts.Method,
		WebhookBody:     opts.Body,
		WebhookHeaders:  opts.Headers,
		CallbackChar:    opts.Callback,
		NoCallbackCheck: opts.NoCheck,
		UpdatedAt:       time.Now().Format("2006-01-02 15:04:05"),
	}
	r.mu.Unlock()
	r.persist()
	r.logAdd(cid, "info", "STUN 联动注册：公网地址 "+net.JoinHostPort(ip, strconv.Itoa(port))+"（通道 "+stunName+"）")
	return cid
}

// updateStunPublic 把 STUN 打洞公网映射写入指定 Webhook 通道记录（记录不存在则忽略）。
// 仅地址变化时持久化并记日志，避免 STUN 保活周期重复刷写。
func (r *whReceiver) updateStunPublic(id, stunName, ip string, port int) {
	r.mu.Lock()
	rec, ok := r.records[id]
	if !ok {
		r.mu.Unlock()
		return
	}
	changed := rec.PublicIP != ip || rec.PublicPort != port
	if changed {
		rec.PublicIP = ip
		rec.PublicPort = port
		rec.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
	}
	r.mu.Unlock()
	if changed {
		r.persist()
		r.logAdd(id, "info", "STUN 联动注册：公网地址 "+net.JoinHostPort(ip, strconv.Itoa(port))+"（通道 "+stunName+"）")
	}
}

// handleWhLog 返回指定通道的运行/访问日志（倒序，最新在前）。
func (s *Server) handleWhLog(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("channel_id")))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	logs := s.whRecv.logQuery(id, limit)
	s.writeJSON(w, http.StatusOK, apiOK(map[string]any{
		"logs":  logs,
		"total": len(logs),
	}))
}

// parseJSONBodyLimit 读取并解析 JSON 请求体（带大小上限）。
func parseJSONBodyLimit(r *http.Request, limit int64) (map[string]any, error) {
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("body too large")
	}
	if len(data) == 0 {
		return map[string]any{}, nil
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, err
	}
	return body, nil
}

// parseWhBody 解析 Webhook 接收请求体（带 64KB 上限），兼容两种编码：
//  1. JSON（application/json，主流客户端）
//  2. 表单编码 application/x-www-form-urlencoded（LanJMP 等旧客户端，如 channel_id=1&host=1.2.3.4&port=51820）
func parseWhBody(r *http.Request) (map[string]any, error) {
	const limit = 64 << 10
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("body too large")
	}
	if len(data) == 0 {
		return map[string]any{}, nil
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err == nil {
		return body, nil
	}
	// 非 JSON：按表单编码解析（LanJMP 旧客户端兼容）
	vals, err := url.ParseQuery(string(data))
	if err != nil {
		return nil, err
	}
	m := make(map[string]any, len(vals))
	for k, vs := range vals {
		m[k] = vs[0]
	}
	return m, nil
}
