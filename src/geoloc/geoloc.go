// Package geoloc 管理 IP 归属地数据：数据源目录（metowolf/iplist）、
// 下载（重试/退避）、解析（CIDR/ip2region）、去重写入与按 IP 二分查询。
package geoloc

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"tunhook/store"

	"go.uber.org/zap"
)

// 归属地分类（与 store.GeoRange.Category 对应）。
const (
	CatCountry  = "country"  // 国家 IP 段
	CatChina    = "china"    // 中国内地 IP 段
	CatProvince = "province" // 省级 IP 段
	CatCity     = "city"     // 市级 IP 段
	CatISP      = "isp"      // 运营商 IP 段
	CatCloud    = "cloud"    // 公有云厂商 IP 段
)

// AllCategories 全部类别（加载顺序即查询优先级）。
var AllCategories = []string{CatCountry, CatChina, CatProvince, CatCity, CatISP, CatCloud}

// CategorySuffix 类别 → 分类标签后缀（分类 = 归属名称 + 后缀，如「美国」+「国家IP段」）。
var CategorySuffix = map[string]string{
	CatCountry:  "国家IP段",
	CatChina:    "内地IP段",
	CatProvince: "省级IP段",
	CatCity:     "市级IP段",
	CatISP:      "运营商IP段",
	CatCloud:    "公有云IP段",
}

// CategoryLabels 类别 → 弹窗展示的中文短标签。
var CategoryLabels = map[string]string{
	CatCountry:  "国家",
	CatChina:    "内地",
	CatProvince: "省级",
	CatCity:     "市级",
	CatISP:      "运营商",
	CatCloud:    "公有云",
}

// rangeEntry 一条内存中的 IP 段归属记录（IPv4 段以 uint32 表示）。
type rangeEntry struct {
	name string
	lo   uint32
	hi   uint32
}

// DB 管理 IP 归属地数据：启动时从 SQLite 加载各分类 IP 段到内存，
// 支持按 IP 二分查询归属地与按需更新数据。
type DB struct {
	mu         sync.RWMutex
	byCategory map[string][]rangeEntry // 各分类的内存索引（按 start 排序）
	ready      bool
	updating   bool
	progDone   int64 // 当前更新已完成的数据源数（updating 时有效）
	progTotal  int64 // 当前更新需处理的数据源总数（updating 时有效）
	lastUpdate time.Time
	dataDir    string
	st         *store.Store
	logger     *zap.Logger
}

// New 创建一个归属地数据库实例（数据从 SQLite 加载，dataDir 仅用于缓存下载的原始数据）。
func New(dataDir string, st *store.Store) *DB {
	return &DB{
		byCategory: make(map[string][]rangeEntry, len(AllCategories)),
		dataDir:    dataDir,
		st:         st,
		logger:     zap.NewNop(),
	}
}

// SetLogger 注入日志器（便于调用方统一日志输出）。
func (d *DB) SetLogger(l *zap.Logger) {
	if l != nil {
		d.logger = l
	}
}

// Load 从 SQLite 加载归属地数据到内存索引。数据库为空时尝试导入缓存文件
// （新版 dataDir/geoloc/cache/{id}.txt 与旧版 dataDir/geoloc/{cat}/data.txt）。
func (d *DB) Load() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.st != nil && d.st.HasGeoData() {
		for _, cat := range AllCategories {
			d.byCategory[cat] = d.loadCategory(cat)
		}
	} else {
		// 缓存文件兜底：将缓存数据导入数据库
		d.importCached()
		if d.st != nil && d.st.HasGeoData() {
			for _, cat := range AllCategories {
				d.byCategory[cat] = d.loadCategory(cat)
			}
		}
	}

	total := d.totalLocked()
	d.ready = total > 0
	d.lastUpdate = d.loadLastUpdate()
	d.logger.Info("IP归属地数据加载完成",
		zap.Int64("total", total),
		zap.Bool("ready", d.ready),
	)
}

// loadCategory 读取某个分类的全部 IP 段并排序（LoadGeoRanges 已按 start 排序）。
func (d *DB) loadCategory(cat string) []rangeEntry {
	rs, err := d.st.LoadGeoRanges(cat, "")
	if err != nil {
		d.logger.Warn("加载归属地分类失败", zap.String("category", cat), zap.Error(err))
		return nil
	}
	out := make([]rangeEntry, 0, len(rs))
	for _, r := range rs {
		out = append(out, rangeEntry{name: r.Name, lo: r.Start, hi: r.End})
	}
	return out
}

// reloadCategoryLocked 重新加载单个分类的内存索引（更新中单源成功后调用，
// 使统计数字实时变化；调用方需持写锁）。
func (d *DB) reloadCategoryLocked(cat string) {
	if d.st == nil {
		return
	}
	d.byCategory[cat] = d.loadCategory(cat)
	d.ready = d.totalLocked() > 0
}

// importCached 把缓存文件导入数据库：新格式按源缓存，旧格式按分类缓存。
func (d *DB) importCached() {
	base := filepath.Join(d.dataDir, "geoloc")
	// 新格式：dataDir/geoloc/cache/{sourceId}.txt
	cacheDir := filepath.Join(base, "cache")
	if entries, err := os.ReadDir(cacheDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			id, err := strconvParseID(e.Name())
			if err != nil {
				continue
			}
			src, ok, err := d.st.GeoSourceByID(id)
			if err != nil || !ok {
				continue
			}
			data, err := os.ReadFile(filepath.Join(cacheDir, e.Name()))
			if err != nil {
				continue
			}
			if err := d.importSourceData(src, data); err != nil {
				d.logger.Warn("导入缓存归属地数据失败", zap.Int64("source", id), zap.Error(err))
			}
		}
	}
	// 旧格式：dataDir/geoloc/{cat}/data.txt（ip2region 管道格式）
	for _, cat := range AllCategories {
		path := filepath.Join(base, cat, "data.txt")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		ranges, _, err := ParseData(string(data), cat, legacyCategoryName(cat), "")
		if err != nil || len(ranges) == 0 {
			continue
		}
		if _, err := d.st.InsertGeoRanges(ranges); err != nil {
			d.logger.Warn("导入旧版缓存归属地数据失败", zap.String("category", cat), zap.Error(err))
		}
	}
}

// importSourceData 解析源数据并写入数据库（去重后）。
func (d *DB) importSourceData(src store.GeoSource, data []byte) error {
	ranges, _, err := ParseData(string(data), src.Category, src.Name, src.Class)
	if err != nil {
		return err
	}
	_, err = d.st.InsertGeoRanges(ranges)
	return err
}

// Ready 报告归属地数据是否已加载可用。
func (d *DB) Ready() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.ready
}

// Updating 报告当前是否正在更新数据。
func (d *DB) Updating() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.updating
}

// LastUpdate 返回最近一次成功更新的时间。
func (d *DB) LastUpdate() time.Time {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.lastUpdate
}

// loadLastUpdate 从设置读取最近更新时间的持久化值。
func (d *DB) loadLastUpdate() time.Time {
	v, err := d.st.GetSetting(KeyLastUpdate)
	if err != nil || v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// Lookup 查询 IP 的归属地，返回形如「中国 广东 广州 电信」的组合字符串；未匹配返回空串。
// 分层匹配：国家 →（兜底）内地 → 省级 → 市级 → 运营商 →（兜底）公有云。
func (d *DB) Lookup(ip string) string {
	ipInt := ipToUint32(ip)
	if ipInt == 0 {
		return ""
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	parts := make([]string, 0, 5)
	if v := searchRange(d.byCategory[CatCountry], ipInt); v != "" {
		parts = append(parts, v)
	} else if v := searchRange(d.byCategory[CatChina], ipInt); v != "" {
		parts = append(parts, "中国")
	}
	if v := searchRange(d.byCategory[CatProvince], ipInt); v != "" {
		parts = append(parts, v)
	}
	if v := searchRange(d.byCategory[CatCity], ipInt); v != "" {
		parts = append(parts, v)
	}
	if v := searchRange(d.byCategory[CatISP], ipInt); v != "" {
		parts = append(parts, v)
	} else if v := searchRange(d.byCategory[CatCloud], ipInt); v != "" {
		parts = append(parts, v)
	}
	return strings.Join(parts, " ")
}

// searchRange 在按 start 排序的段数组中二分查找包含 ip 的段，返回其归属名称。
func searchRange(entries []rangeEntry, ip uint32) string {
	lo, hi := 0, len(entries)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		e := entries[mid]
		if ip < e.lo {
			hi = mid - 1
		} else if ip > e.hi {
			lo = mid + 1
		} else {
			return e.name
		}
	}
	return ""
}

// ContainsIP 报告该 IP 是否命中任意分类的 IP 段
// （IP 过滤第二步：确认 IP 属于允许使用的公网 IP/IP 段）。
func (d *DB) ContainsIP(ip string) bool {
	ipInt := ipToUint32(ip)
	if ipInt == 0 {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, cat := range AllCategories {
		if searchRange(d.byCategory[cat], ipInt) != "" {
			return true
		}
	}
	return false
}

// RegionContains 报告某分类下指定归属名称的 IP 段是否包含该 IP（用于白/黑名单地区规则匹配）。
func (d *DB) RegionContains(category, name, ip string) bool {
	ipInt := ipToUint32(ip)
	if ipInt == 0 {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	entries := d.byCategory[category]
	if len(entries) == 0 {
		return false
	}
	// 二分查找最后一个 lo <= ipInt 的条目
	lo, hi := 0, len(entries)-1
	idx := -1
	for lo <= hi {
		mid := (lo + hi) / 2
		if entries[mid].lo <= ipInt {
			idx = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if idx < 0 {
		return false
	}
	// 向前检查覆盖该 IP 的条目（段可能重叠）
	for i := idx; i >= 0 && entries[i].hi >= ipInt; i-- {
		if entries[i].name == name {
			return true
		}
	}
	// 向后检查覆盖该 IP 的条目
	for i := idx + 1; i < len(entries) && entries[i].lo <= ipInt; i++ {
		if entries[i].name == name {
			return true
		}
	}
	return false
}

// totalLocked 统计内存中的 IP 段总条数（调用方需持锁）。
func (d *DB) totalLocked() int64 {
	var n int64
	for _, v := range d.byCategory {
		n += int64(len(v))
	}
	return n
}

// Stats 返回归属地数据库统计信息（供 Web 界面展示）。
func (d *DB) Stats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := map[string]interface{}{
		"ready":          d.ready,
		"updating":       d.updating,
		"last_update":    "",
		"total":          d.totalLocked(),
		"progress_done":  d.progDone,
		"progress_total": d.progTotal,
	}
	for _, cat := range AllCategories {
		stats[cat] = len(d.byCategory[cat])
	}
	if !d.lastUpdate.IsZero() {
		stats["last_update"] = d.lastUpdate.Format(time.RFC3339)
	}
	return stats
}

// TotalIPCount 返回全部数据源已下载的 IP 地址总数（geo_sources.ip_count 之和，
// 含国内公网订阅等自定义源）。
func (d *DB) TotalIPCount() (int64, error) {
	if d.st == nil {
		return 0, nil
	}
	sources, err := d.st.ListGeoSources()
	if err != nil {
		return 0, err
	}
	var n int64
	for _, s := range sources {
		n += s.IPCount
	}
	return n, nil
}

// rebuildIndex 在更新完成后重新加载全部内存索引（调用方需持写锁）。
func (d *DB) rebuildIndexLocked() {
	for _, cat := range AllCategories {
		d.byCategory[cat] = d.loadCategory(cat)
	}
	d.ready = d.totalLocked() > 0
}

// sortRanges 按 start 升序排序（解析后、写入前调用）。
func sortRanges(rs []store.GeoRange) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Start != rs[j].Start {
			return rs[i].Start < rs[j].Start
		}
		return rs[i].End < rs[j].End
	})
}

// legacyCategoryName 旧版按分类缓存导入时使用的归属名称。
func legacyCategoryName(cat string) string {
	switch cat {
	case CatCountry:
		return "中国"
	case CatChina:
		return "中国"
	case CatProvince, CatCity:
		return "未知"
	case CatISP:
		return "未知"
	}
	return cat
}

// ipToUint32 把 IPv4 地址字符串转为 uint32；非法或 IPv6 返回 0。
func ipToUint32(s string) uint32 {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}
