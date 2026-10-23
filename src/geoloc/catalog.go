package geoloc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"tunhook/store"

	"go.uber.org/zap"
)

// metowolf/iplist 数据源项目地址（包级变量以便测试注入 mock 地址）。
var (
	iplistRawBase = "https://raw.githubusercontent.com/metowolf/iplist/master"
	iplistAPIFmt  = "https://api.github.com/repos/metowolf/iplist/contents/%s"
	// chinaSourceURL 中国内地 IP 段固定链接。
	chinaSourceURL = iplistRawBase + "/data/special/china.txt"
)

// 内置名称映射表（类别 ↔ 分类 的对应关系兜底；优先使用 docs 在线数据）。
var (
	// 两位 ISO 码 → 中文国家名（常用国家，docs/country.md 解析失败时兜底）。
	builtinCountryNames = map[string]string{
		"CN": "中国", "US": "美国", "JP": "日本", "KR": "韩国", "GB": "英国",
		"DE": "德国", "FR": "法国", "RU": "俄罗斯", "IN": "印度", "SG": "新加坡",
		"HK": "中国香港", "TW": "中国台湾", "MO": "中国澳门", "CA": "加拿大",
		"AU": "澳大利亚", "BR": "巴西", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
		"IT": "意大利", "ES": "西班牙", "AE": "阿联酋", "SA": "沙特阿拉伯",
		"ID": "印度尼西亚", "TH": "泰国", "MY": "马来西亚", "VN": "越南",
		"PH": "菲律宾", "TR": "土耳其", "PL": "波兰", "UA": "乌克兰",
		"AR": "阿根廷", "MX": "墨西哥", "ZA": "南非", "EG": "埃及",
	}

	// ISP/公有云文件名 → 中文名称（GitHub API 目录解析后的兜底）。
	builtinISPNames = map[string]string{
		"chinatelecom": "中国电信", "chinamobile": "中国移动", "chinaunicom": "中国联通",
		"drpeng": "彭博士", "cernet": "中国教育网", "cstnet": "中国科技网",
		"aliyun": "阿里云", "tencent": "腾讯云", "bytedance": "字节跳动",
		"huawei": "华为云", "googlecloud": "Google Cloud", "cloudflare": "Cloudflare",
		"digitalocean": "DigitalOcean", "microsoft": "Microsoft", "volcengine": "火山引擎",
	}

	// ispFiles 官方运营商名单（isp 目录中属于「运营商」的文件；其余视为公有云厂商）。
	ispFiles = map[string]bool{
		"chinatelecom": true, "chinamobile": true, "chinaunicom": true,
		"drpeng": true, "cernet": true, "cstnet": true,
	}
)

// githubDirEntry GitHub API contents 目录项。
type githubDirEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// docRow docs 表格行：名称、代码、链接。
type docRow struct {
	name string
	code string
	url  string
}

// Catalog 负责数据源目录的提取、数据库同步与链接有效性定期检测。
type Catalog struct {
	mu     sync.Mutex
	client *http.Client
	st     *store.Store
	logger *zap.Logger
}

// NewCatalog 创建目录管理器。
func NewCatalog(st *store.Store, client *http.Client) *Catalog {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Catalog{client: client, st: st, logger: zap.NewNop()}
}

// SetLogger 注入日志器。
func (c *Catalog) SetLogger(l *zap.Logger) {
	if l != nil {
		c.logger = l
	}
}

// Refresh 从 metowolf/iplist 程序化提取全部类别的数据源并同步到数据库
// （保留已存在源的启用状态与下载元数据）。返回同步条数。
func (c *Catalog) Refresh(ctx context.Context) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sources, err := c.FetchSources(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, src := range sources {
		ex, found, _ := c.st.GeoSourceByKey(src.Category, src.Class)
		if found {
			// 已存在：保留启用状态与历史下载元数据（链接变化时同样保留）
			src.Enabled = ex.Enabled
			src.IPCount = ex.IPCount
			src.UpdatedAt = ex.UpdatedAt
			if ex.URL == src.URL {
				src.Status = ex.Status
				src.LastCheck = ex.LastCheck
			}
		} else {
			// 新数据源默认启用
			src.Enabled = true
		}
		if _, err := c.st.UpsertGeoSource(src); err != nil {
			c.logger.Warn("同步数据源目录失败", zap.String("class", src.Class), zap.Error(err))
			continue
		}
		n++
	}
	c.logger.Info("IP段数据源目录已同步", zap.Int("sources", n))
	return n, nil
}

// FetchSources 提取数据源目录（metowolf/iplist 六类 + 中国内地）。
// 单类失败不影响其他类（降级返回已获取部分）。
func (c *Catalog) FetchSources(ctx context.Context) ([]store.GeoSource, error) {
	var out []store.GeoSource
	var firstErr error
	add := func(srcs []store.GeoSource, err error) {
		out = append(out, srcs...)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	add(c.fetchCountrySources(ctx))
	add(c.fetchCNCitySources(ctx))
	add(c.fetchISPSources(ctx))
	// 中国内地固定源
	out = append(out, store.GeoSource{
		Category: CatChina,
		Class:    "中国内地IP段",
		Name:     "中国内地",
		URL:      chinaSourceURL,
	})
	return out, firstErr
}

// fetchCountrySources 国家 IP 段：解析 docs/country.md（失败则用 GitHub API + 内置名）。
func (c *Catalog) fetchCountrySources(ctx context.Context) ([]store.GeoSource, error) {
	rows, err := c.fetchDocsRows(ctx, iplistRawBase+"/docs/country.md")
	if err != nil {
		c.logger.Warn("解析 docs/country.md 失败，降级为 GitHub API 目录", zap.Error(err))
		return c.fetchISPLikeSources(ctx, "data/country", CatCountry, builtinCountryNames)
	}
	var out []store.GeoSource
	for _, r := range rows {
		if r.code == "" || r.url == "" {
			continue
		}
		name := cleanDocName(r.name)
		out = append(out, store.GeoSource{
			Category: CatCountry,
			Class:    name + CategorySuffix[CatCountry],
			Name:     name,
			URL:      r.url,
		})
	}
	if len(out) == 0 {
		return c.fetchISPLikeSources(ctx, "data/country", CatCountry, builtinCountryNames)
	}
	return out, nil
}

// fetchCNCitySources 省级/市级 IP 段：解析 docs/cncity.md（含名称与链接）。
// 行政区划代码后四位为 0000 视为省级，否则市级。
func (c *Catalog) fetchCNCitySources(ctx context.Context) ([]store.GeoSource, error) {
	rows, err := c.fetchDocsRows(ctx, iplistRawBase+"/docs/cncity.md")
	if err != nil {
		return nil, fmt.Errorf("解析 docs/cncity.md 失败: %w", err)
	}
	var out []store.GeoSource
	for _, r := range rows {
		if r.code == "" || r.url == "" || r.code == "100000" {
			continue // 100000 为中国整体（无细分），使用 special/china.txt
		}
		cat := cncityCategory(r.code)
		name := cleanDocName(r.name)
		out = append(out, store.GeoSource{
			Category: cat,
			Class:    name + "IP段",
			Name:     name,
			URL:      r.url,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("docs/cncity.md 未解析到有效数据源")
	}
	return out, nil
}

// fetchISPSources 运营商/公有云 IP 段：枚举 GitHub API isp 目录，
// 官方运营商名单归为 isp，其余归为公有云。
func (c *Catalog) fetchISPSources(ctx context.Context) ([]store.GeoSource, error) {
	return c.fetchISPLikeSources(ctx, "data/isp", "", nil)
}

// fetchISPLikeSources 枚举 GitHub API 目录生成数据源；kind 指定固定类别（如 country），
// names 提供名称映射。kind 为空时按 isp/cloud 分类。
func (c *Catalog) fetchISPLikeSources(ctx context.Context, dir, kind string, names map[string]string) ([]store.GeoSource, error) {
	entries, err := c.githubDir(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("枚举 %s 目录失败: %w", dir, err)
	}
	var out []store.GeoSource
	for _, e := range entries {
		if e.Type != "file" || !strings.HasSuffix(e.Name, ".txt") {
			continue
		}
		base := strings.TrimSuffix(e.Name, ".txt")
		cat := kind
		var suffix string
		if kind == "" {
			if ispFiles[base] {
				cat = CatISP
				suffix = CategorySuffix[CatISP]
			} else {
				cat = CatCloud
				suffix = CategorySuffix[CatCloud]
			}
		} else {
			suffix = CategorySuffix[kind]
		}
		display := base
		if names != nil {
			if n, ok := names[base]; ok {
				display = n
			}
		} else if n, ok := builtinISPNames[base]; ok {
			display = n
		}
		out = append(out, store.GeoSource{
			Category: cat,
			Class:    display + suffix,
			Name:     display,
			URL:      iplistRawBase + "/" + dir + "/" + e.Name,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s 目录为空", dir)
	}
	return out, nil
}

// githubDir 调用 GitHub API 列出目录内容。
func (c *Catalog) githubDir(ctx context.Context, dir string) ([]githubDirEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(iplistAPIFmt, dir), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "tunhook-geoloc")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var entries []githubDirEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// fetchDocsRows 拉取 docs 文档并解析 `|名称|链接|` 表格行。
func (c *Catalog) fetchDocsRows(ctx context.Context, url string) ([]docRow, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return parseDocsTable(string(body)), nil
}

// docURLRe 匹配 `|名称|https://.../xxx.txt|` 表格行。
var docURLRe = regexp.MustCompile(`^\|([^|]+)\|\s*(https?://\S+\.txt)\s*\|`)

// parseDocsTable 解析 docs 文档中的名称→链接表格。
func parseDocsTable(data string) []docRow {
	var out []docRow
	for _, line := range strings.Split(data, "\n") {
		m := docURLRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(m) != 3 {
			continue
		}
		code := docCodeFromURL(m[2])
		if code == "" {
			continue
		}
		out = append(out, docRow{name: strings.TrimSpace(m[1]), code: code, url: strings.TrimSpace(m[2])})
	}
	return out
}

// docCodeRe 提取链接末段的文件名代码（如 country/CN.txt → CN）。
var docCodeRe = regexp.MustCompile(`/([^/]+)\.txt$`)

// docCodeFromURL 从下载链接提取文件代码。
func docCodeFromURL(u string) string {
	m := docCodeRe.FindStringSubmatch(u)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

// cncityCategory 由行政区划代码判定省级/市级（后四位为 0000 即省级）。
func cncityCategory(code string) string {
	if len(code) == 6 && code[2:] == "0000" {
		return CatProvince
	}
	return CatCity
}

// cleanDocName 清理文档中的名称（去除括号备注与首尾空白）。
func cleanDocName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "("); i > 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "（"); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// CheckLinks 定期检测全部数据源下载链接的有效性（HEAD 优先，兜底 GET 采样），
// 更新 status/last_check。返回检测条数与失败条数。
// ctx 取消时提前结束本轮检测（数据源有数百条，逐条请求耗时较长）。
func (c *Catalog) CheckLinks(ctx context.Context) (int, int, error) {
	sources, err := c.st.ListGeoSources()
	if err != nil {
		return 0, 0, err
	}
	now := time.Now().Format(time.RFC3339)
	checked, failed := 0, 0
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			c.logger.Info("IP段数据源链接检测已中断", zap.Int("checked", checked))
			return checked, failed, err
		}
		status := "ok"
		if err := c.checkLink(ctx, src.URL); err != nil {
			status = "error"
			failed++
			c.logger.Warn("数据源链接无效", zap.String("class", src.Class), zap.String("url", src.URL), zap.Error(err))
		}
		if err := c.st.SetGeoSourceStatus(src.ID, status, now); err != nil {
			return checked, failed, err
		}
		checked++
	}
	c.logger.Info("IP段数据源链接检测完成", zap.Int("checked", checked), zap.Int("failed", failed))
	return checked, failed, nil
}

// checkLink 校验单个链接（HEAD 失败时降级 GET 采样 1KB）。
func (c *Catalog) checkLink(ctx context.Context, u string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "tunhook-geoloc")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotImplemented {
		return fmt.Errorf("HEAD HTTP %d", resp.StatusCode)
	}
	// 服务器不支持 HEAD：GET 采样
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	getReq.Header.Set("User-Agent", "tunhook-geoloc")
	getResp, err := c.client.Do(getReq)
	if err != nil {
		return err
	}
	defer getResp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(getResp.Body, 1024))
	if getResp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET HTTP %d", getResp.StatusCode)
	}
	return nil
}

// strconvParseID 解析缓存文件名（"123.txt" → 123）。
func strconvParseID(name string) (int64, error) {
	base := strings.TrimSuffix(name, ".txt")
	return strconv.ParseInt(base, 10, 64)
}
