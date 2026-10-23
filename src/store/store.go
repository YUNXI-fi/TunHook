package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store 统一持久化层：所有业务数据存 SQLite（单文件，位于 dataDir/tunhook.db）。
// 旧版的文件存储（admin.pwd、rules/*.json 等）由 MigrateFromFiles 一次性导入。
type Store struct {
	db *sql.DB
}

type RuleRecord struct {
	UUID         string `json:"uuid"`
	Key          string `json:"key"`
	Protocol     string `json:"protocol"`
	LocalAddr    string `json:"local_addr"`
	LocalPort    int    `json:"local_port"`
	RemoteAddr   string `json:"remote_addr"`
	RemotePort   int    `json:"remote_port"`
	Domain       string `json:"domain,omitempty"`
	Name         string `json:"name,omitempty"`
	SourcePrefix string `json:"source_prefix,omitempty"` // 统一网关：后端应用原始路径前缀
	RootPrefixes string `json:"root_prefixes,omitempty"` // 统一网关：根相对路径前缀列表（逗号分隔）
	PathPrefix   string `json:"path_prefix,omitempty"`   // 统一网关：后端路径前缀（请求转发到后端时拼接）
	AutoDetect   bool   `json:"auto_detect,omitempty"`   // 统一网关：保存时自动探测远端路径前缀并应用
	CertPEM      string `json:"cert_pem,omitempty"`      // HTTPS 转发：PEM 证书内容（为空时自动生成自签名证书）
	KeyPEM       string `json:"key_pem,omitempty"`       // HTTPS 转发：PEM 私钥内容（为空时自动生成自签名证书）
	TLSEnable    bool   `json:"tls_enable,omitempty"`    // TCP 转发：开启 HTTPS（自签名证书，访问端 TLS）
	// TCP 进阶设置
	RateLimit      int  `json:"rate_limit,omitempty"`      // 访问限速（KB/s/每连接，0=不限速）
	MaxConnections int  `json:"max_connections,omitempty"` // TCP 单端口最大连接数（0=不限制）
	ProxyProtocol  bool `json:"proxy_protocol,omitempty"`  // 连接源站时发送 PROXY protocol v2 头
	TLSSource      bool `json:"tls_source,omitempty"`      // 源端 TLS：以 TLS 方式连接源站
	// UDP 进阶设置
	UDPSessionTimeout int `json:"udp_session_timeout,omitempty"` // UDP 会话超时（毫秒，默认 30000）
	UDPMaxSessions    int `json:"udp_max_sessions,omitempty"`    // UDP 单端口最大会话数（默认 32）
	UDPMaxBlockLen    int `json:"udp_max_block_len,omitempty"`   // UDP 最大块长度（默认 1500）
	// 日志设置
	LogLevel          string `json:"log_level,omitempty"`
	ChannelLogEntries int    `json:"channel_log_entries,omitempty"`
	AccessLogEntries  int    `json:"access_log_entries,omitempty"`
	// 日志存储时间（小时，0=跟随全局）
	LogRetentionHours int `json:"log_retention_hours,omitempty"`
	// 进阶设置（访问链接配置）
	CustomID       string `json:"custom_id,omitempty"`       // 自定义ID（仅字母/数字，不区分大小写）
	CustomDomain   string `json:"custom_domain,omitempty"`   // 自定义域名（保存成功后自动创建 frpc 代理通道）
	LinkKey        string `json:"link_key,omitempty"`        // 链接密钥（自动生成/手动重置）
	AccessPassword string `json:"access_password,omitempty"` // 访问密码（留空则禁用访问密码保护）
	// 累计流量统计（每 5 分钟与关闭时写入数据库，重启后从基线续算，防止丢失）
	TxBytes int64 `json:"tx_bytes,omitempty"`
	RxBytes int64 `json:"rx_bytes,omitempty"`
}

// CertRecord 表示证书库中的一条证书（按域名唯一）。
// 证书内容仅在内部使用（签发/转发时加载），不通过 API 暴露给前端。
type CertRecord struct {
	ID        int64  `json:"id"`
	Domain    string `json:"domain"`     // 主域名，支持通配符（*.example.com）
	Email     string `json:"email"`      // 证书联系人邮箱（Let's Encrypt 账号邮箱）
	Issuer    string `json:"issuer"`     // 发证机构（Let's Encrypt / 自定义CA / 自签名）
	CertPEM   string `json:"-"`          // PEM 证书内容
	KeyPEM    string `json:"-"`          // PEM 私钥内容
	NotBefore string `json:"not_before"` // 生效日期 YYYY-MM-DD
	NotAfter  string `json:"not_after"`  // 到期日期 YYYY-MM-DD
	CreatedAt string `json:"created_at"` // 导入/申请时间 YYYY-MM-DD HH:MM:SS
	// 自动续签参数：仅通过本服务 ACME 签发的证书才有值；导入证书为空（不参与续签）
	CAType     string `json:"ca_type,omitempty"`
	KeyAlg     string `json:"key_alg,omitempty"`
	DNSAccount string `json:"dns_account,omitempty"`
	EABKID     string `json:"-"` // ZeroSSL EAB KID
	EABHMAC    string `json:"-"` // ZeroSSL EAB HMAC Key（Base64）
}

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// 单写者串行化，WAL 容忍读并发；busy_timeout 避免锁冲突直接失败
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, err
	}
	// 旧版 forward_rules 表无 name 列（统一网关子路径名称），补齐列（幂等）
	if err := s.migrateForwardRuleName(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate forward rule name column failed: %v\n", err)
	}
	// 旧版 forward_rules 表无 source_prefix 列（统一网关源路径前缀），补齐列（幂等）
	if err := s.migrateForwardRuleSourcePrefix(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate forward rule source_prefix column failed: %v\n", err)
	}
	// 旧版 forward_rules 表无 root_prefixes 列（统一网关根路径前缀列表），补齐列（幂等）
	if err := s.migrateForwardRuleRootPrefixes(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate forward rule root_prefixes column failed: %v\n", err)
	}
	// 旧版 forward_rules 表无 path_prefix 列（统一网关后端路径前缀），补齐列（幂等）
	if err := s.migrateForwardRulePathPrefix(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate forward rule path_prefix column failed: %v\n", err)
	}
	// 旧版 forward_rules 表无 auto_detect 列（统一网关自动检测路径开关），补齐列（幂等）
	if err := s.migrateForwardRuleAutoDetect(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate forward rule auto_detect column failed: %v\n", err)
	}
	// 旧版 forward_rules 表无 cert_pem / key_pem 列（HTTPS 转发证书），补齐列（幂等）
	if err := s.migrateForwardRuleCert(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate forward rule cert columns failed: %v\n", err)
	}
	// 旧版 forward_rules 表无 tls_enable 列（TCP+HTTPS 开关），补齐列（幂等）
	if err := s.migrateForwardRuleTLS(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate forward rule tls column failed: %v\n", err)
	}
	// 旧版 forward_rules 表无进阶/日志列（访问限速/最大连接数/PROXY v2/源端TLS/UDP参数/日志设置），补齐列（幂等）
	if err := s.migrateForwardRuleAdvanced(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate forward rule advanced columns failed: %v\n", err)
	}
	// 旧版 forward_rules 表无进阶访问链接列（自定义ID/自定义域名/链接密钥/访问密码/日志存储时间），补齐列（幂等）
	if err := s.migrateForwardRuleAccess(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate forward rule access columns failed: %v\n", err)
	}
	// 旧版 forward_rules 表无 tx_bytes / rx_bytes 列（累计流量统计，每 5 分钟与关闭时写入），补齐列（幂等）
	if err := s.migrateForwardRuleTraffic(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate forward rule traffic columns failed: %v\n", err)
	}
	// 一次性清理旧版 IP 过滤数据：清空 ip_filter_entries、
	// 删除「国内/公网IP段」数据源及其 IP 段、清除旧订阅配置键（幂等，失败不阻断启动）
	if err := s.migrateIPFilterV2(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate ip filter v2 failed: %v\n", err)
	}
	// 旧版 geo_ip_ranges 迁移到新分类体系（id/class/source_id 列 + 分类重映射，幂等）
	if err := s.MigrateGeoClasses(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate geo classes failed: %v\n", err)
	}
	// 旧版联系人邮箱存于 settings KV（email:contacts），迁移到 email_contacts 表（幂等）
	if err := s.migrateEmailContacts(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate email contacts failed: %v\n", err)
	}
	// 旧版 email_contacts 表无账号类型/密钥算法列（ACME 账户属性），补齐列（幂等）
	if err := s.migrateACMEContactColumns(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate acme contact columns failed: %v\n", err)
	}
	// 旧版 certificates 表无 CA/密钥类型/续签参数列，补齐（幂等）
	if err := s.migrateCertificateColumns(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate certificate columns failed: %v\n", err)
	}
	// 旧版 dns_accounts 表只有单个 api_key 列，升级为 credentials（JSON 多字段，幂等）
	if err := s.migrateDNSAccountCredentials(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate dns account credentials failed: %v\n", err)
	}
	// 旧版 ddns_tasks 表无 ip_src/iface 列（IP 来源扩展），补齐列（幂等）
	if err := s.migrateDDNSTaskSource(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: migrate ddns task source columns failed: %v\n", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) initSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS forward_rules (
	uuid        TEXT PRIMARY KEY,
	key         TEXT NOT NULL UNIQUE,
	protocol    TEXT NOT NULL,
	local_addr  TEXT NOT NULL,
	local_port  INTEGER NOT NULL,
	remote_addr TEXT NOT NULL,
	remote_port INTEGER NOT NULL,
	domain      TEXT NOT NULL DEFAULT '',
	name        TEXT NOT NULL DEFAULT '',
	source_prefix TEXT NOT NULL DEFAULT '',
	root_prefixes TEXT NOT NULL DEFAULT '',
	path_prefix  TEXT NOT NULL DEFAULT '',
	auto_detect  INTEGER NOT NULL DEFAULT 0,
	cert_pem     TEXT NOT NULL DEFAULT '',
	key_pem      TEXT NOT NULL DEFAULT '',
	tls_enable   INTEGER NOT NULL DEFAULT 0,
	rate_limit       INTEGER NOT NULL DEFAULT 0,
	max_connections  INTEGER NOT NULL DEFAULT 0,
	proxy_protocol   INTEGER NOT NULL DEFAULT 0,
	tls_source       INTEGER NOT NULL DEFAULT 0,
	udp_session_timeout INTEGER NOT NULL DEFAULT 0,
	udp_max_sessions    INTEGER NOT NULL DEFAULT 0,
	udp_max_block_len   INTEGER NOT NULL DEFAULT 0,
	log_level        TEXT NOT NULL DEFAULT '',
	channel_log_entries INTEGER NOT NULL DEFAULT 0,
	access_log_entries  INTEGER NOT NULL DEFAULT 0,
	log_retention_hours INTEGER NOT NULL DEFAULT 0,
	custom_id        TEXT NOT NULL DEFAULT '',
	custom_domain    TEXT NOT NULL DEFAULT '',
	link_key         TEXT NOT NULL DEFAULT '',
	access_password  TEXT NOT NULL DEFAULT '',
	tx_bytes        INTEGER NOT NULL DEFAULT 0,
	rx_bytes        INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS certificates (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	domain     TEXT NOT NULL UNIQUE,
	email      TEXT NOT NULL DEFAULT '',
	issuer     TEXT NOT NULL DEFAULT '',
	cert_pem   TEXT NOT NULL DEFAULT '',
	key_pem    TEXT NOT NULL DEFAULT '',
	not_before TEXT NOT NULL DEFAULT '',
	not_after  TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT '',
	ca_type    TEXT NOT NULL DEFAULT '',
	key_alg    TEXT NOT NULL DEFAULT '',
	dns_account TEXT NOT NULL DEFAULT '',
	eab_kid    TEXT NOT NULL DEFAULT '',
	eab_hmac   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS email_contacts (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	email      TEXT NOT NULL COLLATE NOCASE UNIQUE,
	ca_type    TEXT NOT NULL DEFAULT 'Let''s Encrypt',
	key_alg    TEXT NOT NULL DEFAULT 'EC 256',
	created_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS dns_accounts (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL COLLATE NOCASE UNIQUE,
	provider    TEXT NOT NULL DEFAULT '',
	credentials TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS ddns_tasks (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	name      TEXT NOT NULL DEFAULT '',
	account   TEXT NOT NULL,
	domain    TEXT NOT NULL,
	rr        TEXT NOT NULL DEFAULT '@',
	rrtype    TEXT NOT NULL DEFAULT 'A',
	addr_mode TEXT NOT NULL DEFAULT 'v4',
	ip_src    TEXT NOT NULL DEFAULT 'public',
	iface     TEXT NOT NULL DEFAULT '',
	ttl       INTEGER NOT NULL DEFAULT 600,
	enabled   INTEGER NOT NULL DEFAULT 0,
	last_ip   TEXT NOT NULL DEFAULT '',
	last_time TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS ip_filter_entries (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ip         TEXT NOT NULL,
	source     TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT '',
	UNIQUE(ip, source)
);
CREATE TABLE IF NOT EXISTS geo_sources (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	category   TEXT NOT NULL,
	class      TEXT NOT NULL,
	name       TEXT NOT NULL DEFAULT '',
	url        TEXT NOT NULL DEFAULT '',
	ip_count   INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL DEFAULT '',
	enabled    INTEGER NOT NULL DEFAULT 1,
	status     TEXT NOT NULL DEFAULT '',
	last_check TEXT NOT NULL DEFAULT '',
	UNIQUE(category, class)
);
CREATE TABLE IF NOT EXISTS geo_ip_ranges (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	category  TEXT NOT NULL,
	class     TEXT NOT NULL DEFAULT '',
	name      TEXT NOT NULL,
	start_ip  INTEGER NOT NULL,
	end_ip    INTEGER NOT NULL,
	source_id INTEGER NOT NULL DEFAULT 0,
	UNIQUE(category, class, start_ip, end_ip)
);
CREATE TABLE IF NOT EXISTS traffic_samples (
	ts  INTEGER PRIMARY KEY,  -- 采样时间（unix 秒）
	rx  INTEGER NOT NULL,     -- 该采样点接收速率（bytes/s）
	tx  INTEGER NOT NULL      -- 该采样点发送速率（bytes/s）
);
CREATE TABLE IF NOT EXISTS traffic_query_history (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	mode   TEXT NOT NULL,
	ts     INTEGER NOT NULL,
	detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_traffic_query_history_ts ON traffic_query_history(ts);
CREATE INDEX IF NOT EXISTS idx_geo_ranges_lookup ON geo_ip_ranges(category, start_ip);
CREATE INDEX IF NOT EXISTS idx_geo_ranges_class ON geo_ip_ranges(class);
CREATE INDEX IF NOT EXISTS idx_geo_ranges_source ON geo_ip_ranges(source_id);
`)
	return err
}

// ============= geo IP ranges（IP 归属地数据） =============

// GeoRange 表示一条 IP 段归属记录（IPv4 段以 uint32 整数表示）。
// 唯一标识符为 (category, class, start_ip, end_ip)，用于去重。
type GeoRange struct {
	ID       int64  `json:"id"`       // 数据库自增 ID
	Category string `json:"category"` // country/china/province/city/isp/cloud
	Class    string `json:"class"`    // 分类标签，如「美国国家IP段」「广东省IP段」
	Name     string `json:"name"`     // 归属名称（美国 / 广东 / 广州 / 中国电信 …）
	Start    uint32 `json:"start"`    // 起始 IP
	End      uint32 `json:"end"`      // 结束 IP
	SourceID int64  `json:"source_id"`
}

// InsertGeoRanges 事务内批量写入 IP 段（INSERT OR IGNORE 基于唯一标识符去重），
// 返回实际新增条数。
func (s *Store) InsertGeoRanges(ranges []GeoRange) (int64, error) {
	if len(ranges) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO geo_ip_ranges(category,class,name,start_ip,end_ip,source_id) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	var inserted int64
	for _, r := range ranges {
		res, err := stmt.Exec(r.Category, r.Class, r.Name, r.Start, r.End, r.SourceID)
		if err != nil {
			return 0, err
		}
		if n, err := res.RowsAffected(); err == nil {
			inserted += n
		}
	}
	return inserted, tx.Commit()
}

// ReplaceGeoRangesBySource 事务内全量替换某个数据源的 IP 段（数据重新下载后重建）。
// 同时清理该 (category, class) 下无 source_id 的历史数据，避免 UNIQUE 约束阻止新数据生效。
func (s *Store) ReplaceGeoRangesBySource(sourceID int64, ranges []GeoRange) error {
	if len(ranges) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM geo_ip_ranges WHERE source_id=? OR (category=? AND class=?)`,
		sourceID, ranges[0].Category, ranges[0].Class); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO geo_ip_ranges(category,class,name,start_ip,end_ip,source_id) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range ranges {
		if _, err := stmt.Exec(r.Category, r.Class, r.Name, r.Start, r.End, sourceID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadGeoRanges 按起始 IP 排序返回某个分类的 IP 段；class 为空时返回该分类全部。
func (s *Store) LoadGeoRanges(category, class string) ([]GeoRange, error) {
	query := `SELECT id, category, class, name, start_ip, end_ip, source_id FROM geo_ip_ranges WHERE category=?`
	args := []interface{}{category}
	if class != "" {
		query += ` AND class=?`
		args = append(args, class)
	}
	query += ` ORDER BY start_ip, end_ip`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GeoRange
	for rows.Next() {
		var r GeoRange
		if err := rows.Scan(&r.ID, &r.Category, &r.Class, &r.Name, &r.Start, &r.End, &r.SourceID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LoadAllGeoRanges 返回全部 IP 段（用于备份导出，不排序保证效率）。
func (s *Store) LoadAllGeoRanges() ([]GeoRange, error) {
	rows, err := s.db.Query(`SELECT id, category, class, name, start_ip, end_ip, source_id FROM geo_ip_ranges`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GeoRange
	for rows.Next() {
		var r GeoRange
		if err := rows.Scan(&r.ID, &r.Category, &r.Class, &r.Name, &r.Start, &r.End, &r.SourceID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LoadGeoRangesByRegion 返回某分类下指定归属名称的全部 IP 段（按起始 IP 排序）。
func (s *Store) LoadGeoRangesByRegion(category, name string) ([]GeoRange, error) {
	rows, err := s.db.Query(`SELECT id, category, class, name, start_ip, end_ip, source_id FROM geo_ip_ranges WHERE category=? AND name=? ORDER BY start_ip, end_ip`,
		category, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GeoRange
	for rows.Next() {
		var r GeoRange
		if err := rows.Scan(&r.ID, &r.Category, &r.Class, &r.Name, &r.Start, &r.End, &r.SourceID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GeoRegion IP 地址库中按「分类 + 归属名称」聚合的地区统计（供白/黑名单从地区批量添加）。
type GeoRegion struct {
	Category string `json:"category"`
	Label    string `json:"label"`  // 分类中文标签（展示用，由调用方填充）
	Name     string `json:"name"`   // 归属名称（美国 / 广东 / 广州 / 中国电信 …）
	Ranges   int64  `json:"ranges"` // IP 段条数
	IPs      int64  `json:"ips"`    // IP 地址总数
}

// ListGeoRegions 返回 IP 地址库全部地区（按分类、名称聚合），无数据时返回空列表。
func (s *Store) ListGeoRegions() ([]GeoRegion, error) {
	rows, err := s.db.Query(`SELECT category, name, COUNT(*) AS ranges, SUM(end_ip - start_ip + 1) AS ips
		FROM geo_ip_ranges GROUP BY category, name ORDER BY category, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GeoRegion
	for rows.Next() {
		var g GeoRegion
		if err := rows.Scan(&g.Category, &g.Name, &g.Ranges, &g.IPs); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// HasGeoData 报告数据库中是否已存有归属地数据。
func (s *Store) HasGeoData() bool {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM geo_ip_ranges`).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// IsIPInGeoRanges 判断 IP（uint32）是否存在于任一归属地 IP 段中
// （IP 过滤第二步：确认获取到的公网 IP 属于允许使用的公网 IP/IP 段）。
func (s *Store) IsIPInGeoRanges(ip uint32) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM geo_ip_ranges WHERE start_ip<=? AND end_ip>=?`, ip, ip).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ============= geo sources（IP 段数据源目录） =============

// GeoSource 表示一个 IP 段数据源（对应 metowolf/iplist 中一个文件）。
// 弹窗列表中的 ID / 类别 / 分类 / IP数量 / 更新时间 即来源于此表。
type GeoSource struct {
	ID        int64  `json:"id"`
	Category  string `json:"category"`   // 类别：country/china/province/city/isp/cloud
	Class     string `json:"class"`      // 分类：如「美国国家IP段」
	Name      string `json:"name"`       // 归属名称：如「美国」（查询结果展示用）
	URL       string `json:"url"`        // 下载链接
	IPCount   int64  `json:"ip_count"`   // 网段覆盖的 IP 地址总数
	UpdatedAt string `json:"updated_at"` // 该源数据最后更新时间
	Enabled   bool   `json:"enabled"`
	Status    string `json:"status"`     // ok / error / ""（未检测）
	LastCheck string `json:"last_check"` // 最近一次链接有效性检测时间
}

// UpsertGeoSource 按 (category, class) 幂等写入数据源，返回其 ID。
func (s *Store) UpsertGeoSource(src GeoSource) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO geo_sources(category,class,name,url,ip_count,updated_at,enabled,status,last_check)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(category,class) DO UPDATE SET
			name=excluded.name, url=excluded.url, ip_count=excluded.ip_count, updated_at=excluded.updated_at,
			enabled=excluded.enabled, status=excluded.status, last_check=excluded.last_check`,
		src.Category, src.Class, src.Name, src.URL, src.IPCount, src.UpdatedAt, boolToInt(src.Enabled), src.Status, src.LastCheck)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if id == 0 { // 冲突更新路径不返回新 ID，需回查
		if sid, ok, err := s.GeoSourceByKey(src.Category, src.Class); err == nil && ok {
			return sid.ID, nil
		}
	}
	return id, nil
}

// ListGeoSources 返回全部数据源（按类别、分类排序）。
func (s *Store) ListGeoSources() ([]GeoSource, error) {
	rows, err := s.db.Query(`SELECT id,category,class,name,url,ip_count,updated_at,enabled,status,last_check FROM geo_sources ORDER BY category, class`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GeoSource
	for rows.Next() {
		var src GeoSource
		var enabled int
		if err := rows.Scan(&src.ID, &src.Category, &src.Class, &src.Name, &src.URL, &src.IPCount, &src.UpdatedAt, &enabled, &src.Status, &src.LastCheck); err != nil {
			return nil, err
		}
		src.Enabled = enabled == 1
		out = append(out, src)
	}
	return out, rows.Err()
}

// GeoSourceByKey 按 (category, class) 查找数据源。
func (s *Store) GeoSourceByKey(category, class string) (GeoSource, bool, error) {
	var src GeoSource
	var enabled int
	err := s.db.QueryRow(`SELECT id,category,class,name,url,ip_count,updated_at,enabled,status,last_check FROM geo_sources WHERE category=? AND class=?`,
		category, class).Scan(&src.ID, &src.Category, &src.Class, &src.Name, &src.URL, &src.IPCount, &src.UpdatedAt, &enabled, &src.Status, &src.LastCheck)
	if err == sql.ErrNoRows {
		return src, false, nil
	}
	if err != nil {
		return src, false, err
	}
	src.Enabled = enabled == 1
	return src, true, nil
}

// GeoSourceByID 按主键查找数据源。
func (s *Store) GeoSourceByID(id int64) (GeoSource, bool, error) {
	var src GeoSource
	var enabled int
	err := s.db.QueryRow(`SELECT id,category,class,name,url,ip_count,updated_at,enabled,status,last_check FROM geo_sources WHERE id=?`,
		id).Scan(&src.ID, &src.Category, &src.Class, &src.Name, &src.URL, &src.IPCount, &src.UpdatedAt, &enabled, &src.Status, &src.LastCheck)
	if err == sql.ErrNoRows {
		return src, false, nil
	}
	if err != nil {
		return src, false, err
	}
	src.Enabled = enabled == 1
	return src, true, nil
}

// SetGeoSourceMeta 更新数据源的 IP 数量与最后更新时间。
func (s *Store) SetGeoSourceMeta(id, ipCount int64, updatedAt string) error {
	_, err := s.db.Exec(`UPDATE geo_sources SET ip_count=?, updated_at=? WHERE id=?`, ipCount, updatedAt, id)
	return err
}

// SetGeoSourceStatus 更新数据源链接有效性检测结果。
func (s *Store) SetGeoSourceStatus(id int64, status, lastCheck string) error {
	_, err := s.db.Exec(`UPDATE geo_sources SET status=?, last_check=? WHERE id=?`, status, lastCheck, id)
	return err
}

// SetGeoSourceEnabled 启用/停用数据源。
func (s *Store) SetGeoSourceEnabled(id int64, enabled bool) error {
	_, err := s.db.Exec(`UPDATE geo_sources SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}

// geoLegacyCategory 旧分类到新类别的重映射（迁移用）。
// 旧数据来源：country（国家）/ cncity（中国省份/城市）/ isp（运营商）。
var geoLegacyCategories = map[string]string{
	"country": "country",
	"cncity":  "", // 需按名称启发式拆分为 province / city
	"isp":     "isp",
}

// 省份/直辖市/自治区名单（迁移时用于区分省级与市级）。
var geoProvinceNames = map[string]string{
	"北京": "北京市", "天津": "天津市", "河北": "河北省", "山西": "山西省",
	"内蒙古": "内蒙古自治区", "辽宁": "辽宁省", "吉林": "吉林省", "黑龙江": "黑龙江省",
	"上海": "上海市", "江苏": "江苏省", "浙江": "浙江省", "安徽": "安徽省",
	"福建": "福建省", "江西": "江西省", "山东": "山东省", "河南": "河南省",
	"湖北": "湖北省", "湖南": "湖南省", "广东": "广东省", "广西": "广西壮族自治区",
	"海南": "海南省", "重庆": "重庆市", "四川": "四川省", "贵州": "贵州省",
	"云南": "云南省", "西藏": "西藏自治区", "陕西": "陕西省", "甘肃": "甘肃省",
	"青海": "青海省", "宁夏": "宁夏回族自治区", "新疆": "新疆维吾尔自治区",
	"台湾": "台湾省", "香港": "香港特别行政区", "澳门": "澳门特别行政区",
}

// classSuffix 由 (旧分类, 是否省级) 推导 分类标签 后缀。
func geoClassSuffix(category string, isProvince bool) string {
	switch category {
	case "country":
		return "国家IP段"
	case "isp":
		return "运营商IP段"
	case "cncity":
		// 名称已含 省/市 后缀（如 广东省 / 广州市），直接补「IP段」
		return "IP段"
	}
	return "IP段"
}

// MigrateGeoClasses 为旧版 geo_ip_ranges 表补齐 id/class/source_id 列，
// 并将历史数据重映射到新分类体系（country/china/province/city/isp/cloud）。
// 幂等：已迁移（存在 class 列且非空）时直接返回。
func (s *Store) MigrateGeoClasses() error {
	hasClass, err := s.hasGeoColumn("class")
	if err != nil {
		return err
	}
	if !hasClass {
		// 旧表结构（无 id/class/source_id）：重建表并拷贝数据
		if err := s.rebuildGeoRangesTable(); err != nil {
			return err
		}
	}
	// 将旧分类重映射到新分类体系并填充 分类 标签
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id, category, name FROM geo_ip_ranges WHERE class=''`)
	if err != nil {
		return err
	}
	type upd struct {
		id       int64
		category string
		class    string
	}
	var updates []upd
	for rows.Next() {
		var id int64
		var category, name string
		if err := rows.Scan(&id, &category, &name); err != nil {
			rows.Close()
			return err
		}
		newCat, ok := geoLegacyCategories[category]
		if !ok {
			continue
		}
		isProvince := false
		if category == "cncity" {
			if _, ok := geoProvinceNames[name]; ok {
				isProvince = true
				newCat = "province"
			} else {
				newCat = "city"
			}
		}
		label := geoLegacyLabel(name, category, isProvince)
		updates = append(updates, upd{id: id, category: newCat, class: label})
	}
	rows.Close()
	stmt, err := tx.Prepare(`UPDATE geo_ip_ranges SET category=?, class=? WHERE id=? AND class=''`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, u := range updates {
		if _, err := stmt.Exec(u.category, u.class, u.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// geoLegacyLabel 由历史名称推导 分类 标签（如 广东 → 广东省IP段）。
func geoLegacyLabel(name, category string, isProvince bool) string {
	switch category {
	case "country", "isp":
		return name + geoClassSuffix(category, false)
	case "cncity":
		if isProvince {
			if full, ok := geoProvinceNames[name]; ok {
				name = full
			}
		} else if !strings.HasSuffix(name, "市") {
			name += "市"
		}
		return name + geoClassSuffix(category, isProvince)
	}
	return name + "IP段"
}

func (s *Store) hasGeoColumn(col string) (bool, error) {
	rows, err := s.db.Query(`SELECT COUNT(*) FROM pragma_table_info('geo_ip_ranges') WHERE name=?`, col)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var cnt int
	if rows.Next() {
		if err := rows.Scan(&cnt); err != nil {
			return false, err
		}
	}
	return cnt > 0, nil
}

// rebuildGeoRangesTable 重建 geo_ip_ranges 表以补齐 id/class/source_id 列（数据全量拷贝）。
func (s *Store) rebuildGeoRangesTable() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE geo_ip_ranges_new (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		category  TEXT NOT NULL,
		class     TEXT NOT NULL DEFAULT '',
		name      TEXT NOT NULL,
		start_ip  INTEGER NOT NULL,
		end_ip    INTEGER NOT NULL,
		source_id INTEGER NOT NULL DEFAULT 0,
		UNIQUE(category, class, start_ip, end_ip)
	)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO geo_ip_ranges_new(category,class,name,start_ip,end_ip,source_id)
		SELECT category,'',name,start_ip,end_ip,0 FROM geo_ip_ranges`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE geo_ip_ranges`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE geo_ip_ranges_new RENAME TO geo_ip_ranges`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_geo_ranges_lookup ON geo_ip_ranges(category, start_ip);
		CREATE INDEX IF NOT EXISTS idx_geo_ranges_class ON geo_ip_ranges(class);
		CREATE INDEX IF NOT EXISTS idx_geo_ranges_source ON geo_ip_ranges(source_id);`); err != nil {
		return err
	}
	return tx.Commit()
}

// ============= IP 过滤条目 =============

// IPSourceCustom 用户手动录入的禁止使用 IP/IP 段来源标记。
// ip_filter_entries 表仅通过 Web 界面的「添加自定义 IP/网段」手动维护。
const IPSourceCustom = "custom"

// IPSourceWhitelist 用户手动录入的白名单 IP/IP 段来源标记（优先放行）。
const IPSourceWhitelist = "whitelist"

// IPSourceBlocked 自动记录的被拦截 IP 来源标记（记录日志，不参与过滤判定）。
const IPSourceBlocked = "blocked"

// AddCustomIP 追加一条自定义 IP/网段（禁止列表，已存在则忽略）。
func (s *Store) AddCustomIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO ip_filter_entries(ip, source, created_at) VALUES(?,?,?)`,
		ip, IPSourceCustom, time.Now().Format(time.RFC3339))
	return err
}

// DeleteCustomIP 删除一条自定义 IP/网段。
func (s *Store) DeleteCustomIP(ip string) error {
	_, err := s.db.Exec(`DELETE FROM ip_filter_entries WHERE source=? AND ip=?`, IPSourceCustom, ip)
	return err
}

// ListCustomIPs 返回全部自定义 IP/网段（禁止列表）。
func (s *Store) ListCustomIPs() ([]string, error) {
	rows, err := s.db.Query(`SELECT ip FROM ip_filter_entries WHERE source=? ORDER BY id`, IPSourceCustom)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// ============= 白名单 / 拦截记录 =============

// AddIPEntry 追加一条指定来源的 IP/网段（已存在则忽略）。
func (s *Store) AddIPEntry(source, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO ip_filter_entries(ip, source, created_at) VALUES(?,?,?)`,
		ip, source, time.Now().Format(time.RFC3339))
	return err
}

// DeleteIPEntry 删除一条指定来源的 IP/网段。
func (s *Store) DeleteIPEntry(source, ip string) error {
	_, err := s.db.Exec(`DELETE FROM ip_filter_entries WHERE source=? AND ip=?`, source, ip)
	return err
}

// ListIPEntries 返回指定来源的全部 IP/网段（按录入先后排序）。
func (s *Store) ListIPEntries(source string) ([]string, error) {
	rows, err := s.db.Query(`SELECT ip FROM ip_filter_entries WHERE source=? ORDER BY id`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// ListWhitelistIPs 返回全部白名单 IP/网段。
func (s *Store) ListWhitelistIPs() ([]string, error) { return s.ListIPEntries(IPSourceWhitelist) }

// AddWhitelistIP 追加一条白名单 IP/网段。
func (s *Store) AddWhitelistIP(ip string) error { return s.AddIPEntry(IPSourceWhitelist, ip) }

// DeleteWhitelistIP 删除一条白名单 IP/网段。
func (s *Store) DeleteWhitelistIP(ip string) error { return s.DeleteIPEntry(IPSourceWhitelist, ip) }

// ListBlockedIPs 返回自动记录的全部被拦截 IP。
func (s *Store) ListBlockedIPs() ([]string, error) { return s.ListIPEntries(IPSourceBlocked) }

// RecordBlockedIP 记录一个被拦截的 IP（已存在则忽略）。
func (s *Store) RecordBlockedIP(ip string) error { return s.AddIPEntry(IPSourceBlocked, ip) }

// DeleteBlockedIP 删除一条被拦截 IP 记录。
func (s *Store) DeleteBlockedIP(ip string) error { return s.DeleteIPEntry(IPSourceBlocked, ip) }

// ClearBlockedIPs 清空全部被拦截 IP 记录。
func (s *Store) ClearBlockedIPs() error {
	_, err := s.db.Exec(`DELETE FROM ip_filter_entries WHERE source=?`, IPSourceBlocked)
	return err
}

// migrateIPFilterV2 一次性清理旧版 IP 过滤数据（订阅机制移除后执行）：
//   - 清空 ip_filter_entries 表（旧版订阅 + 自定义条目）
//   - 删除「国内/公网IP段」数据源（geo_sources）及其 IP 段（geo_ip_ranges）
//   - 删除旧订阅配置键 cfg.ip_filter.ip_range_url / cfg.ip_filter.custom_ips
//
// 幂等：执行成功后写入 migrated:ipfilter-v2 标记，后续重启不再重复清理。
func (s *Store) migrateIPFilterV2() error {
	if v, _ := s.GetSetting("migrated:ipfilter-v2"); v == "1" {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM ip_filter_entries`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM geo_sources WHERE category=?`, "domestic"); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM geo_ip_ranges WHERE category=?`, "domestic"); err != nil {
		return err
	}
	for _, k := range []string{"cfg.ip_filter.ip_range_url", "cfg.ip_filter.custom_ips"} {
		if _, err := tx.Exec(`DELETE FROM settings WHERE key=?`, k); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.SetSetting("migrated:ipfilter-v2", "1")
}

// ============= settings (KV) =============

func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) DeleteSetting(key string) error {
	_, err := s.db.Exec(`DELETE FROM settings WHERE key=?`, key)
	return err
}

// SettingsByPrefix 返回所有以 prefix 开头的 KV（用于加载 desc.* / cfg.*）。
func (s *Store) SettingsByPrefix(prefix string) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key,value FROM settings WHERE key LIKE ?`, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SetJSON 把任意值序列化后写入 KV（读取时用 JSON 解码）。
func (s *Store) SetJSON(key string, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.SetSetting(key, string(b))
}

// ============= forward rules =============

// migrateForwardRuleName 为旧版 forward_rules 表补齐 name 列（统一网关子路径名称）。
func (s *Store) migrateForwardRuleName() error {
	rows, err := s.db.Query(`SELECT COUNT(*) FROM pragma_table_info('forward_rules') WHERE name='name'`)
	if err != nil {
		return err
	}
	var cnt int
	rows.Next()
	if err := rows.Scan(&cnt); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if cnt > 0 {
		return nil
	}
	_, err = s.db.Exec(`ALTER TABLE forward_rules ADD COLUMN name TEXT NOT NULL DEFAULT ''`)
	return err
}

// migrateForwardRuleSourcePrefix 为旧版 forward_rules 表补齐 source_prefix 列
// （统一网关源路径前缀）。
func (s *Store) migrateForwardRuleSourcePrefix() error {
	rows, err := s.db.Query(`SELECT COUNT(*) FROM pragma_table_info('forward_rules') WHERE name='source_prefix'`)
	if err != nil {
		return err
	}
	var cnt int
	rows.Next()
	if err := rows.Scan(&cnt); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if cnt > 0 {
		return nil
	}
	_, err = s.db.Exec(`ALTER TABLE forward_rules ADD COLUMN source_prefix TEXT NOT NULL DEFAULT ''`)
	return err
}

// migrateForwardRuleRootPrefixes 为旧版 forward_rules 表补齐 root_prefixes 列
// （统一网关根相对路径前缀列表）。
func (s *Store) migrateForwardRuleRootPrefixes() error {
	rows, err := s.db.Query(`SELECT COUNT(*) FROM pragma_table_info('forward_rules') WHERE name='root_prefixes'`)
	if err != nil {
		return err
	}
	var cnt int
	rows.Next()
	if err := rows.Scan(&cnt); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if cnt > 0 {
		return nil
	}
	_, err = s.db.Exec(`ALTER TABLE forward_rules ADD COLUMN root_prefixes TEXT NOT NULL DEFAULT ''`)
	return err
}

// migrateForwardRulePathPrefix 为旧版 forward_rules 表补齐 path_prefix 列
// （统一网关后端路径前缀）。
func (s *Store) migrateForwardRulePathPrefix() error {
	rows, err := s.db.Query(`SELECT COUNT(*) FROM pragma_table_info('forward_rules') WHERE name='path_prefix'`)
	if err != nil {
		return err
	}
	var cnt int
	rows.Next()
	if err := rows.Scan(&cnt); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if cnt > 0 {
		return nil
	}
	_, err = s.db.Exec(`ALTER TABLE forward_rules ADD COLUMN path_prefix TEXT NOT NULL DEFAULT ''`)
	return err
}

// migrateForwardRuleAutoDetect 为旧版 forward_rules 表补齐 auto_detect 列
// （统一网关自动检测路径开关）。
func (s *Store) migrateForwardRuleAutoDetect() error {
	rows, err := s.db.Query(`SELECT COUNT(*) FROM pragma_table_info('forward_rules') WHERE name='auto_detect'`)
	if err != nil {
		return err
	}
	var cnt int
	rows.Next()
	if err := rows.Scan(&cnt); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if cnt > 0 {
		return nil
	}
	_, err = s.db.Exec(`ALTER TABLE forward_rules ADD COLUMN auto_detect INTEGER NOT NULL DEFAULT 0`)
	return err
}

// migrateForwardRuleCert 为旧版 forward_rules 表补齐 cert_pem / key_pem 列
// （HTTPS 转发证书，为空时自动生成自签名证书）。
func (s *Store) migrateForwardRuleCert() error {
	for _, col := range []string{"cert_pem", "key_pem"} {
		rows, err := s.db.Query(`SELECT COUNT(*) FROM pragma_table_info('forward_rules') WHERE name=?`, col)
		if err != nil {
			return err
		}
		var cnt int
		if rows.Next() {
			if err := rows.Scan(&cnt); err != nil {
				rows.Close()
				return err
			}
		}
		rows.Close()
		if cnt > 0 {
			continue
		}
		if _, err := s.db.Exec(`ALTER TABLE forward_rules ADD COLUMN ` + col + ` TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

// migrateForwardRuleTLS 为旧版 forward_rules 表补齐 tls_enable 列
// （TCP 转发开启 HTTPS 开关）。
func (s *Store) migrateForwardRuleTLS() error {
	rows, err := s.db.Query(`SELECT COUNT(*) FROM pragma_table_info('forward_rules') WHERE name='tls_enable'`)
	if err != nil {
		return err
	}
	var cnt int
	if rows.Next() {
		if err := rows.Scan(&cnt); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	if cnt > 0 {
		return nil
	}
	_, err = s.db.Exec(`ALTER TABLE forward_rules ADD COLUMN tls_enable INTEGER NOT NULL DEFAULT 0`)
	return err
}

// migrateForwardRuleAdvanced 为旧版 forward_rules 表补齐进阶设置列
// （访问限速/单端口最大连接数/PROXY v2/源端TLS/UDP 会话参数/日志设置），幂等。
func (s *Store) migrateForwardRuleAdvanced() error {
	intCols := []string{
		"rate_limit", "max_connections", "proxy_protocol", "tls_source",
		"udp_session_timeout", "udp_max_sessions", "udp_max_block_len",
		"channel_log_entries", "access_log_entries",
	}
	for _, col := range intCols {
		exists, err := s.hasForwardRuleColumn(col)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := s.db.Exec(`ALTER TABLE forward_rules ADD COLUMN ` + col + ` INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	exists, err := s.hasForwardRuleColumn("log_level")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := s.db.Exec(`ALTER TABLE forward_rules ADD COLUMN log_level TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

// hasForwardRuleColumn 检查 forward_rules 表是否已存在指定列。
func (s *Store) hasForwardRuleColumn(col string) (bool, error) {
	rows, err := s.db.Query(`SELECT COUNT(*) FROM pragma_table_info('forward_rules') WHERE name=?`, col)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var cnt int
	if rows.Next() {
		if err := rows.Scan(&cnt); err != nil {
			return false, err
		}
	}
	return cnt > 0, nil
}

// migrateForwardRuleAccess 为旧版 forward_rules 表补齐进阶访问链接列
// （自定义ID/自定义域名/链接密钥/访问密码/日志存储时间），幂等。
func (s *Store) migrateForwardRuleAccess() error {
	for _, col := range []string{"custom_id", "custom_domain", "link_key", "access_password"} {
		exists, err := s.hasForwardRuleColumn(col)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := s.db.Exec(`ALTER TABLE forward_rules ADD COLUMN ` + col + ` TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	exists, err := s.hasForwardRuleColumn("log_retention_hours")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := s.db.Exec(`ALTER TABLE forward_rules ADD COLUMN log_retention_hours INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	return nil
}

// migrateForwardRuleTraffic 为旧版 forward_rules 表补齐 tx_bytes / rx_bytes 列
// （累计流量统计，每 5 分钟与关闭时写入数据库，防止重启后丢失）。
func (s *Store) migrateForwardRuleTraffic() error {
	for _, col := range []string{"tx_bytes", "rx_bytes"} {
		exists, err := s.hasForwardRuleColumn(col)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := s.db.Exec(`ALTER TABLE forward_rules ADD COLUMN ` + col + ` INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SaveForwardRule(r RuleRecord) error {
	_, err := s.db.Exec(`INSERT INTO forward_rules
		(uuid,key,protocol,local_addr,local_port,remote_addr,remote_port,domain,name,source_prefix,root_prefixes,path_prefix,auto_detect,cert_pem,key_pem,tls_enable,
		 rate_limit,max_connections,proxy_protocol,tls_source,udp_session_timeout,udp_max_sessions,udp_max_block_len,log_level,channel_log_entries,access_log_entries,
		 log_retention_hours,custom_id,custom_domain,link_key,access_password)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET
			uuid=excluded.uuid, protocol=excluded.protocol, local_addr=excluded.local_addr,
			local_port=excluded.local_port, remote_addr=excluded.remote_addr,
			remote_port=excluded.remote_port, domain=excluded.domain, name=excluded.name,
			source_prefix=excluded.source_prefix, root_prefixes=excluded.root_prefixes,
			path_prefix=excluded.path_prefix, auto_detect=excluded.auto_detect,
			cert_pem=excluded.cert_pem, key_pem=excluded.key_pem,
			tls_enable=excluded.tls_enable,
			rate_limit=excluded.rate_limit, max_connections=excluded.max_connections,
			proxy_protocol=excluded.proxy_protocol, tls_source=excluded.tls_source,
			udp_session_timeout=excluded.udp_session_timeout, udp_max_sessions=excluded.udp_max_sessions,
			udp_max_block_len=excluded.udp_max_block_len, log_level=excluded.log_level,
			channel_log_entries=excluded.channel_log_entries, access_log_entries=excluded.access_log_entries,
			log_retention_hours=excluded.log_retention_hours,
			custom_id=excluded.custom_id, custom_domain=excluded.custom_domain,
			link_key=excluded.link_key, access_password=excluded.access_password`,
		r.UUID, r.Key, r.Protocol, r.LocalAddr, r.LocalPort,
		r.RemoteAddr, r.RemotePort, r.Domain, r.Name, r.SourcePrefix, r.RootPrefixes, r.PathPrefix, boolToInt(r.AutoDetect),
		r.CertPEM, r.KeyPEM, boolToInt(r.TLSEnable),
		r.RateLimit, r.MaxConnections, boolToInt(r.ProxyProtocol), boolToInt(r.TLSSource),
		r.UDPSessionTimeout, r.UDPMaxSessions, r.UDPMaxBlockLen, r.LogLevel, r.ChannelLogEntries, r.AccessLogEntries,
		r.LogRetentionHours, r.CustomID, r.CustomDomain, r.LinkKey, r.AccessPassword)
	return err
}

func (s *Store) ListForwardRules() ([]RuleRecord, error) {
	rows, err := s.db.Query(`SELECT uuid,key,protocol,local_addr,local_port,remote_addr,remote_port,domain,name,source_prefix,root_prefixes,path_prefix,auto_detect,cert_pem,key_pem,tls_enable,
		rate_limit,max_connections,proxy_protocol,tls_source,udp_session_timeout,udp_max_sessions,udp_max_block_len,log_level,channel_log_entries,access_log_entries,
		log_retention_hours,custom_id,custom_domain,link_key,access_password,tx_bytes,rx_bytes FROM forward_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleRecord
	for rows.Next() {
		var r RuleRecord
		var autoDetect, tlsEnable, proxyProto, tlsSource int
		if err := rows.Scan(&r.UUID, &r.Key, &r.Protocol, &r.LocalAddr, &r.LocalPort,
			&r.RemoteAddr, &r.RemotePort, &r.Domain, &r.Name, &r.SourcePrefix, &r.RootPrefixes, &r.PathPrefix, &autoDetect, &r.CertPEM, &r.KeyPEM, &tlsEnable,
			&r.RateLimit, &r.MaxConnections, &proxyProto, &tlsSource, &r.UDPSessionTimeout, &r.UDPMaxSessions, &r.UDPMaxBlockLen, &r.LogLevel, &r.ChannelLogEntries, &r.AccessLogEntries,
			&r.LogRetentionHours, &r.CustomID, &r.CustomDomain, &r.LinkKey, &r.AccessPassword, &r.TxBytes, &r.RxBytes); err != nil {
			return nil, err
		}
		r.AutoDetect = autoDetect != 0
		r.TLSEnable = tlsEnable != 0
		r.ProxyProtocol = proxyProto != 0
		r.TLSSource = tlsSource != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteForwardRule(key string) error {
	_, err := s.db.Exec(`DELETE FROM forward_rules WHERE key=?`, key)
	return err
}

// GetForwardRule 按 key 查询单条转发规则（不存在时返回 ErrNoRows）。
func (s *Store) GetForwardRule(key string) (RuleRecord, error) {
	var r RuleRecord
	var autoDetect, tlsEnable, proxyProto, tlsSource int
	err := s.db.QueryRow(`SELECT uuid,key,protocol,local_addr,local_port,remote_addr,remote_port,domain,name,source_prefix,root_prefixes,path_prefix,auto_detect,cert_pem,key_pem,tls_enable,
		rate_limit,max_connections,proxy_protocol,tls_source,udp_session_timeout,udp_max_sessions,udp_max_block_len,log_level,channel_log_entries,access_log_entries,
		log_retention_hours,custom_id,custom_domain,link_key,access_password,tx_bytes,rx_bytes FROM forward_rules WHERE key=?`, key).
		Scan(&r.UUID, &r.Key, &r.Protocol, &r.LocalAddr, &r.LocalPort,
			&r.RemoteAddr, &r.RemotePort, &r.Domain, &r.Name, &r.SourcePrefix, &r.RootPrefixes, &r.PathPrefix, &autoDetect, &r.CertPEM, &r.KeyPEM, &tlsEnable,
			&r.RateLimit, &r.MaxConnections, &proxyProto, &tlsSource, &r.UDPSessionTimeout, &r.UDPMaxSessions, &r.UDPMaxBlockLen, &r.LogLevel, &r.ChannelLogEntries, &r.AccessLogEntries,
			&r.LogRetentionHours, &r.CustomID, &r.CustomDomain, &r.LinkKey, &r.AccessPassword, &r.TxBytes, &r.RxBytes)
	if err != nil {
		return r, err
	}
	r.AutoDetect = autoDetect != 0
	r.TLSEnable = tlsEnable != 0
	r.ProxyProtocol = proxyProto != 0
	r.TLSSource = tlsSource != 0
	return r, nil
}

// UpdateForwardTraffic 仅更新转发规则的累计流量统计（tx/rx），不影响其他配置列。
func (s *Store) UpdateForwardTraffic(key string, tx, rx int64) error {
	_, err := s.db.Exec(`UPDATE forward_rules SET tx_bytes=?, rx_bytes=? WHERE key=?`, tx, rx, key)
	return err
}

// ============= certificates（证书库） =============

// migrateCertificateColumns 为旧版 certificates 表补齐 CA/密钥类型/续签参数列（幂等）。
func (s *Store) migrateCertificateColumns() error {
	cols := map[string]bool{}
	rows, err := s.db.Query(`PRAGMA table_info(certificates)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		cols[name] = true
	}
	rows.Close()
	for _, c := range []struct{ name, ddl string }{
		{"ca_type", `ALTER TABLE certificates ADD COLUMN ca_type TEXT NOT NULL DEFAULT ''`},
		{"key_alg", `ALTER TABLE certificates ADD COLUMN key_alg TEXT NOT NULL DEFAULT ''`},
		{"dns_account", `ALTER TABLE certificates ADD COLUMN dns_account TEXT NOT NULL DEFAULT ''`},
		{"eab_kid", `ALTER TABLE certificates ADD COLUMN eab_kid TEXT NOT NULL DEFAULT ''`},
		{"eab_hmac", `ALTER TABLE certificates ADD COLUMN eab_hmac TEXT NOT NULL DEFAULT ''`},
	} {
		if cols[c.name] {
			continue
		}
		if _, err := s.db.Exec(c.ddl); err != nil {
			return err
		}
	}
	return nil
}

// SaveCertificate 保存一条证书（按 domain 唯一，已存在则覆盖）。
func (s *Store) SaveCertificate(c CertRecord) error {
	_, err := s.db.Exec(`INSERT INTO certificates
		(domain,email,issuer,cert_pem,key_pem,not_before,not_after,created_at,ca_type,key_alg,dns_account,eab_kid,eab_hmac)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(domain) DO UPDATE SET
			email=excluded.email, issuer=excluded.issuer, cert_pem=excluded.cert_pem,
			key_pem=excluded.key_pem, not_before=excluded.not_before,
			not_after=excluded.not_after, created_at=excluded.created_at,
			ca_type=excluded.ca_type, key_alg=excluded.key_alg,
			dns_account=excluded.dns_account, eab_kid=excluded.eab_kid, eab_hmac=excluded.eab_hmac`,
		c.Domain, c.Email, c.Issuer, c.CertPEM, c.KeyPEM, c.NotBefore, c.NotAfter, c.CreatedAt,
		c.CAType, c.KeyAlg, c.DNSAccount, c.EABKID, c.EABHMAC)
	return err
}

// ListCertificates 返回证书库全部证书（按域名升序），不含证书内容与 EAB 密钥。
func (s *Store) ListCertificates() ([]CertRecord, error) {
	rows, err := s.db.Query(`SELECT id,domain,email,issuer,not_before,not_after,created_at,ca_type,key_alg,dns_account FROM certificates ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertRecord
	for rows.Next() {
		var c CertRecord
		if err := rows.Scan(&c.ID, &c.Domain, &c.Email, &c.Issuer, &c.NotBefore, &c.NotAfter, &c.CreatedAt,
			&c.CAType, &c.KeyAlg, &c.DNSAccount); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListCertificatesWithContent 返回证书库全部证书（含 PEM 证书/私钥，用于备份导出）。
func (s *Store) ListCertificatesWithContent() ([]CertRecord, error) {
	rows, err := s.db.Query(`SELECT id,domain,email,issuer,cert_pem,key_pem,not_before,not_after,created_at,ca_type,key_alg,dns_account FROM certificates ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertRecord
	for rows.Next() {
		var c CertRecord
		if err := rows.Scan(&c.ID, &c.Domain, &c.Email, &c.Issuer, &c.CertPEM, &c.KeyPEM, &c.NotBefore, &c.NotAfter, &c.CreatedAt,
			&c.CAType, &c.KeyAlg, &c.DNSAccount); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCertificate 按域名查询证书（含证书内容与续签所需的 EAB 参数，用于转发加载与自动续签）。
func (s *Store) GetCertificate(domain string) (CertRecord, error) {
	var c CertRecord
	err := s.db.QueryRow(`SELECT id,domain,email,issuer,cert_pem,key_pem,not_before,not_after,created_at,ca_type,key_alg,dns_account,eab_kid,eab_hmac FROM certificates WHERE domain=?`, domain).
		Scan(&c.ID, &c.Domain, &c.Email, &c.Issuer, &c.CertPEM, &c.KeyPEM, &c.NotBefore, &c.NotAfter, &c.CreatedAt,
			&c.CAType, &c.KeyAlg, &c.DNSAccount, &c.EABKID, &c.EABHMAC)
	if err != nil {
		return c, err
	}
	return c, nil
}

// DeleteCertificate 按域名删除证书。
func (s *Store) DeleteCertificate(domain string) error {
	_, err := s.db.Exec(`DELETE FROM certificates WHERE domain=?`, domain)
	return err
}

// ============= email contacts（联系人邮箱管理） =============

const emailContactsKey = "email:contacts"

// migrateEmailContacts 旧版联系人邮箱存于 settings KV（email:contacts，JSON 数组），
// 一次性迁移到 email_contacts 表（幂等），迁移后清除旧 KV 键。
func (s *Store) migrateEmailContacts() error {
	if v, _ := s.GetSetting("migrated:email-contacts"); v == "1" {
		return nil
	}
	raw, err := s.GetSetting(emailContactsKey)
	if err != nil {
		return err
	}
	var list []string
	if strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), &list); err != nil {
			return err
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, em := range list {
		em = strings.TrimSpace(em)
		if em == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO email_contacts(email, created_at) VALUES(?,?)`, em, time.Now().Format("2006-01-02 15:04:05")); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM settings WHERE key=?`, emailContactsKey); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.SetSetting("migrated:email-contacts", "1")
}

// migrateACMEContactColumns 为旧版 email_contacts 表补齐 ca_type/key_alg 列（幂等）。
func (s *Store) migrateACMEContactColumns() error {
	cols := map[string]bool{}
	rows, err := s.db.Query(`PRAGMA table_info(email_contacts)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		cols[name] = true
	}
	rows.Close()
	if !cols["ca_type"] {
		if _, err := s.db.Exec(`ALTER TABLE email_contacts ADD COLUMN ca_type TEXT NOT NULL DEFAULT 'Let''s Encrypt'`); err != nil {
			return err
		}
	}
	if !cols["key_alg"] {
		if _, err := s.db.Exec(`ALTER TABLE email_contacts ADD COLUMN key_alg TEXT NOT NULL DEFAULT 'EC 256'`); err != nil {
			return err
		}
	}
	return nil
}

// ACMEContact 一个 ACME 账户（联系人邮箱 + 签发机构 + 密钥算法）。
type ACMEContact struct {
	Email     string `json:"email"`
	CAType    string `json:"ca_type"`
	KeyAlg    string `json:"key_alg"`
	CreatedAt string `json:"created_at"`
}

// ListEmails 返回 ACME 账户列表（email_contacts 表，按添加顺序）。
func (s *Store) ListEmails() ([]ACMEContact, error) {
	rows, err := s.db.Query(`SELECT email, ca_type, key_alg, created_at FROM email_contacts ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ACMEContact
	for rows.Next() {
		var c ACMEContact
		if err := rows.Scan(&c.Email, &c.CAType, &c.KeyAlg, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddEmail 添加 ACME 账户（email 列 COLLATE NOCASE，大小写不敏感去重）。
func (s *Store) AddEmail(email, caType, keyAlg string) error {
	if strings.TrimSpace(caType) == "" {
		caType = "Let's Encrypt"
	}
	if strings.TrimSpace(keyAlg) == "" {
		keyAlg = "EC 256"
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO email_contacts(email, ca_type, key_alg, created_at) VALUES(?,?,?,?)`,
		email, caType, keyAlg, time.Now().Format("2006-01-02 15:04:05"))
	return err
}

// DeleteEmail 删除联系人邮箱（大小写不敏感）。
func (s *Store) DeleteEmail(email string) error {
	_, err := s.db.Exec(`DELETE FROM email_contacts WHERE email=?`, email)
	return err
}

// migrateDNSAccountCredentials 为旧版 dns_accounts 表补齐 credentials 列
// （api_key 单字段升级为 JSON 多字段），并把旧 api_key 迁移为 {"token": ...}（幂等）。
func (s *Store) migrateDNSAccountCredentials() error {
	cols := map[string]bool{}
	rows, err := s.db.Query(`PRAGMA table_info(dns_accounts)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		cols[name] = true
	}
	rows.Close()
	hasAPIKey := cols["api_key"]
	if !cols["credentials"] {
		if _, err := s.db.Exec(`ALTER TABLE dns_accounts ADD COLUMN credentials TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	// 旧数据迁移：api_key 非空且 credentials 为空 → 包装为 {"token": api_key}
	if hasAPIKey {
		if _, err := s.db.Exec(`UPDATE dns_accounts SET credentials = json_object('token', api_key) WHERE credentials = '' AND api_key != ''`); err != nil {
			return err
		}
	}
	return nil
}

// migrateDDNSTaskSource 为旧版 ddns_tasks 表补齐 ip_src/iface 列（IP 来源扩展，幂等）。
func (s *Store) migrateDDNSTaskSource() error {
	cols := map[string]bool{}
	rows, err := s.db.Query(`PRAGMA table_info(ddns_tasks)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		cols[name] = true
	}
	rows.Close()
	if !cols["ip_src"] {
		if _, err := s.db.Exec(`ALTER TABLE ddns_tasks ADD COLUMN ip_src TEXT NOT NULL DEFAULT 'public'`); err != nil {
			return err
		}
	}
	if !cols["iface"] {
		if _, err := s.db.Exec(`ALTER TABLE ddns_tasks ADD COLUMN iface TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

// DNSAccount 一个 DNS 服务商账户（用于 Let's Encrypt DNS-01 验证）。
// Credentials 为服务商相关的多字段凭证，例如阿里云 {"access_key","secret_key"}、Cloudflare {"email","api_token"}。
type DNSAccount struct {
	ID          int64             `json:"id"`
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`
	Credentials map[string]string `json:"credentials"`
	CreatedAt   string            `json:"created_at"`
}

// ListDNSAccounts 返回 DNS 账户列表（按添加顺序）。
func (s *Store) ListDNSAccounts() ([]DNSAccount, error) {
	rows, err := s.db.Query(`SELECT id, name, provider, credentials, created_at FROM dns_accounts ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSAccount
	for rows.Next() {
		var a DNSAccount
		var creds string
		if err := rows.Scan(&a.ID, &a.Name, &a.Provider, &creds, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Credentials = map[string]string{}
		if strings.TrimSpace(creds) != "" {
			_ = json.Unmarshal([]byte(creds), &a.Credentials)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AddDNSAccount 添加 DNS 账户（name 大小写不敏感去重；credentials 以 JSON 存储）。
func (s *Store) AddDNSAccount(name, provider string, credentials map[string]string) error {
	raw := ""
	if len(credentials) > 0 {
		if b, err := json.Marshal(credentials); err == nil {
			raw = string(b)
		}
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO dns_accounts(name, provider, credentials, created_at) VALUES(?,?,?,?)`,
		name, provider, raw, time.Now().Format("2006-01-02 15:04:05"))
	return err
}

// DeleteDNSAccount 删除 DNS 账户（按名称）。
func (s *Store) DeleteDNSAccount(name string) error {
	_, err := s.db.Exec(`DELETE FROM dns_accounts WHERE name=?`, name)
	return err
}

// ============= DDNS 任务（动态域名解析） =============

// DDNSTask 一个动态 DNS 任务：把某域名（main/子域）的 A/AAAA 记录值
// 定时同步为指定来源的 IP 地址。addr_mode 取值 v4/v6，rrtype 对应 A/AAAA。
// ip_src 取值 public（公网地址）/ local（本机指定的网卡地址），iface 为 local 时的网卡名。
type DDNSTask struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Account   string `json:"account"`
	Domain    string `json:"domain"`
	RR        string `json:"rr"`
	RRType    string `json:"rrtype"`
	AddrMode  string `json:"addr_mode"`
	IPSrc     string `json:"ip_src"`
	Iface     string `json:"iface"`
	TTL       int    `json:"ttl"`
	Enabled   bool   `json:"enabled"`
	LastIP    string `json:"last_ip"`
	LastTime  string `json:"last_time"`
	CreatedAt string `json:"created_at"`
}

func scanDDNSTask(scan func(dest ...interface{}) error) (DDNSTask, error) {
	var t DDNSTask
	var enabled int
	if err := scan(&t.ID, &t.Name, &t.Account, &t.Domain, &t.RR, &t.RRType,
		&t.AddrMode, &t.IPSrc, &t.Iface, &t.TTL, &enabled, &t.LastIP, &t.LastTime, &t.CreatedAt); err != nil {
		return t, err
	}
	t.Enabled = enabled == 1
	return t, nil
}

// ListDDNSTasks 返回全部 DDNS 任务。
func (s *Store) ListDDNSTasks() ([]DDNSTask, error) {
	rows, err := s.db.Query(`SELECT id, name, account, domain, rr, rrtype, addr_mode, ip_src, iface, ttl, enabled, last_ip, last_time, created_at FROM ddns_tasks ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DDNSTask
	for rows.Next() {
		t, err := scanDDNSTask(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AddDDNSTask 添加 DDNS 任务（name 可为空，此时用 domain 标识）。
func (s *Store) AddDDNSTask(t DDNSTask) (int64, error) {
	if t.TTL <= 0 {
		t.TTL = 600
	}
	if t.RR == "" {
		t.RR = "@"
	}
	if t.AddrMode == "" {
		t.AddrMode = "v4"
	}
	if t.RRType == "" {
		t.RRType = "A"
	}
	if t.IPSrc != "local" {
		t.IPSrc = "public"
	}
	res, err := s.db.Exec(`INSERT INTO ddns_tasks(name, account, domain, rr, rrtype, addr_mode, ip_src, iface, ttl, enabled, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		t.Name, t.Account, t.Domain, t.RR, t.RRType, t.AddrMode, t.IPSrc, t.Iface, t.TTL, boolToInt(t.Enabled), time.Now().Format("2006-01-02 15:04:05"))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateDDNSTask 更新任务（不含 enabled/last_ip/last_time），并保留 id。
func (s *Store) UpdateDDNSTask(t DDNSTask) error {
	if t.TTL <= 0 {
		t.TTL = 600
	}
	if t.RR == "" {
		t.RR = "@"
	}
	if t.AddrMode == "" {
		t.AddrMode = "v4"
	}
	if t.RRType == "" {
		t.RRType = "A"
	}
	if t.IPSrc != "local" {
		t.IPSrc = "public"
	}
	_, err := s.db.Exec(`UPDATE ddns_tasks SET name=?, account=?, domain=?, rr=?, rrtype=?, addr_mode=?, ip_src=?, iface=?, ttl=? WHERE id=?`,
		t.Name, t.Account, t.Domain, t.RR, t.RRType, t.AddrMode, t.IPSrc, t.Iface, t.TTL, t.ID)
	return err
}

// SetDDNSTaskEnabled 启停 DDNS 任务。
func (s *Store) SetDDNSTaskEnabled(id int64, enabled bool) error {
	_, err := s.db.Exec(`UPDATE ddns_tasks SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}

// SetDDNSTaskResult 记录某任务的最近一次同步结果（IP + 时间）。
func (s *Store) SetDDNSTaskResult(id int64, ip string) error {
	_, err := s.db.Exec(`UPDATE ddns_tasks SET last_ip=?, last_time=? WHERE id=?`,
		ip, time.Now().Format("2006-01-02 15:04:05"), id)
	return err
}

// DeleteDDNSTask 删除 DDNS 任务。
func (s *Store) DeleteDDNSTask(id int64) error {
	_, err := s.db.Exec(`DELETE FROM ddns_tasks WHERE id=?`, id)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ============= 旧文件迁移 =============

// MigrateFromFiles 将旧版文件存储的数据一次性导入数据库（幂等，仅执行一次）。
// dataDir 下为账号类文件，rulesDir 为规则 JSON 目录。
func (s *Store) MigrateFromFiles(dataDir, rulesDir string) error {
	if v, _ := s.GetSetting("migrated:v1"); v == "1" {
		return nil
	}

	// 旧版账号类文件（历史版本遗留，仅迁移保留，账号系统已移除）
	for _, f := range []struct{ file, key string }{
		{filepath.Join(dataDir, "admin.pwd"), "admin.pwd"},
		{filepath.Join(dataDir, "admin.user"), "admin.user"},
		{filepath.Join(dataDir, "admin.nas"), "admin.nas"},
		{filepath.Join(dataDir, "jwt.secret"), "jwt.secret"},
	} {
		if b, err := os.ReadFile(f.file); err == nil && len(b) > 0 {
			if err := s.SetSetting(f.key, strings.TrimSpace(string(b))); err != nil {
				return err
			}
		}
	}

	failCount := 0

	// 转发规则
	if files, err := filepath.Glob(filepath.Join(rulesDir, "*.json")); err == nil {
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			var r RuleRecord
			if json.Unmarshal(b, &r) == nil && r.Key != "" {
				if err := s.SaveForwardRule(r); err != nil {
					failCount++
					fmt.Fprintf(os.Stderr, "migrate forward rule %s: %v\n", f, err)
				}
			}
		}
	}

	if failCount > 0 {
		return fmt.Errorf("migrate legacy files: %d item(s) failed", failCount)
	}

	return s.SetSetting("migrated:v1", "1")
}

// ============= 系统流量统计（traffic_samples） =============

// TrafficSample 表示一个流量统计采样点（速率 bytes/s）。
type TrafficSample struct {
	TS int64 `json:"ts"`
	RX int64 `json:"rx"`
	TX int64 `json:"tx"`
}

// InsertTrafficSamplesBatch 批量写入秒级流量采样（同 ts 覆盖，幂等）。
func (s *Store) InsertTrafficSamplesBatch(samples []TrafficSample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO traffic_samples(ts,rx,tx) VALUES(?,?,?) ON CONFLICT(ts) DO UPDATE SET rx=excluded.rx,tx=excluded.tx`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, sp := range samples {
		if _, err := stmt.Exec(sp.TS, sp.RX, sp.TX); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// QueryTrafficSamples 查询 [from,to) 区间内的流量采样，按 bucketSec 秒聚合（桶内取平均速率），时间升序。
func (s *Store) QueryTrafficSamples(from, to, bucketSec int64) ([]TrafficSample, error) {
	rows, err := s.db.Query(`
SELECT ((ts/?)*?) AS bucket, CAST(AVG(rx) AS INTEGER) AS rx, CAST(AVG(tx) AS INTEGER) AS tx
FROM traffic_samples
WHERE ts>=? AND ts<?
GROUP BY bucket
ORDER BY bucket`, bucketSec, bucketSec, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficSample
	for rows.Next() {
		var sp TrafficSample
		if err := rows.Scan(&sp.TS, &sp.RX, &sp.TX); err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

// DeleteTrafficSamplesBefore 清理早于 ts 的流量采样，返回删除条数。
func (s *Store) DeleteTrafficSamplesBefore(ts int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM traffic_samples WHERE ts<?`, ts)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ============= 流量查询历史（traffic_query_history） =============

// TrafficQueryRecord 表示一条流量统计查询历史记录。
type TrafficQueryRecord struct {
	ID     int64  `json:"id"`
	Mode   string `json:"mode"`
	TS     int64  `json:"ts"`
	Detail string `json:"detail"`
}

// InsertTrafficQueryRecord 记录一条流量统计查询历史。
func (s *Store) InsertTrafficQueryRecord(mode string, ts int64, detail string) error {
	_, err := s.db.Exec(`INSERT INTO traffic_query_history(mode,ts,detail) VALUES(?,?,?)`, mode, ts, detail)
	return err
}

// ListTrafficQueryRecords 返回最近 limit 条查询历史（新→旧）。
func (s *Store) ListTrafficQueryRecords(limit int) ([]TrafficQueryRecord, error) {
	rows, err := s.db.Query(`SELECT id,mode,ts,detail FROM traffic_query_history ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficQueryRecord
	for rows.Next() {
		var rec TrafficQueryRecord
		if err := rows.Scan(&rec.ID, &rec.Mode, &rec.TS, &rec.Detail); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// TrimTrafficQueryHistory 仅保留最近 keep 条查询历史，其余删除。
func (s *Store) TrimTrafficQueryHistory(keep int) error {
	_, err := s.db.Exec(`DELETE FROM traffic_query_history WHERE id NOT IN (SELECT id FROM traffic_query_history ORDER BY id DESC LIMIT ?)`, keep)
	return err
}
