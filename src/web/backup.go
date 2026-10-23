package web

// 备份 / 恢复：导出配置为 ZIP 包（支持模块选择与 AES-GCM 加密），
// 导入时自动检测加密：优先使用设备编号自动解密，失败则提示用户输入密码。
// 恢复采用「合并模式」：备份中的配置覆盖当前同名配置，当前已有但备份未包含的配置保留。

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"

	"tunhook/config"
	"tunhook/errpage"
	"tunhook/frpc"
	"tunhook/store"
)

const backupAppName = "TunHook"

// backupMaxUpload 备份导入允许的最大上传体积（含全量地理 IP 段数据，512MB 余量充足）。
const backupMaxUpload = 512 << 20

// errNeedPassword 加密备份需要用户输入密码（设备编号自动解密失败）。
var errNeedPassword = errors.New("need password")

// 备份模块（导出时可选择）
const (
	modSettings = "settings" // 系统设置（cfg.*）
	modRules    = "rules"    // 转发规则 + 描述
	modFrpc     = "frpc"     // FRP 服务器与代理
	modIPFilter = "ipfilter" // IP 过滤条目
	modDNS      = "dns"      // 域名解析：DNS 账户与 DDNS 任务
	modHook     = "hook"     // 自定义UI：导航页（/hook）配置（cfg.hook.*）
	modCert     = "cert"     // 证书库 + ACME 联系人
	modGeo      = "geo"      // 地理数据源 + IP 段
	modIcons    = "icons"    // 桌面图标配置 + 图标文件
	modWH       = "wh"       // Webhook 通道记录
)

// 导出加密方式
const (
	encNone     = "none"     // 不加密
	encAuto     = "auto"     // 使用设备编号（CPU 序列号）自动加密
	encPassword = "password" // 手动输入密码加密
	encAESGCM   = "aes-gcm"  // 备份文件中的加密标记
	kdfIter     = 200000     // PBKDF2 迭代次数
)

// backupPayload 备份内容（导出时按所选模块收集，恢复时按字段合并）。
type backupPayload struct {
	App          string                 `json:"app"`
	Version      string                 `json:"version"`
	ExportedAt   string                 `json:"exported_at"`
	Config       map[string]interface{} `json:"config"`                 // 系统设置（key 不含 cfg. 前缀）
	Hook         map[string]interface{} `json:"hook"`                   // 自定义UI：导航页配置（key 不含 cfg.hook. 前缀）
	ForwardRules []store.RuleRecord     `json:"forward_rules"`          // 转发规则
	Descriptions map[string]string      `json:"descriptions"`           // 描述（key 不含 desc. 前缀）
	Frpc         *frpc.Config           `json:"frpc,omitempty"`         // FRP 配置
	IPFilter     backupIPFilter         `json:"ip_filter"`              // IP 过滤条目
	DNSAccounts  []store.DNSAccount     `json:"dns_accounts"`           // 域名解析：DNS 账户
	DDNSTasks    []store.DDNSTask       `json:"ddns_tasks"`             // 域名解析：DDNS 任务
	Certificates []backupCert           `json:"certificates,omitempty"` // 证书库（含 PEM 证书/私钥）
	Emails       []store.ACMEContact    `json:"emails,omitempty"`       // ACME 联系人
	GeoSources   []store.GeoSource      `json:"geo_sources,omitempty"`  // 地理数据源
	GeoRanges    []store.GeoRange       `json:"geo_ranges,omitempty"`   // 地理 IP 段
	DeskConfig   map[string]string      `json:"desk_config,omitempty"`  // 桌面图标配置（desk.* 原始 JSON）
	WHRecords    string                 `json:"wh_records,omitempty"`   // Webhook 通道记录快照
	Icons        map[string][]byte      `json:"icons,omitempty"`        // 图标文件名 -> 内容
	ErrorPages   map[string]string      `json:"error_pages,omitempty"`  // 错误页模板（状态码 -> 整页 HTML 文件内容）
}

// backupCert 备份用的证书条目（CertRecord 的 PEM 字段 json tag 为 -，需独立结构显式携带内容）。
type backupCert struct {
	Domain    string `json:"domain"`
	Email     string `json:"email"`
	Issuer    string `json:"issuer"`
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	CreatedAt string `json:"created_at"`
}

type backupIPFilter struct {
	Custom    []string `json:"custom"`
	Whitelist []string `json:"whitelist"`
	Blocked   []string `json:"blocked"`
}

// backupManifest ZIP 内明文清单（记录加密方式与模块）。
type backupManifest struct {
	App        string   `json:"app"`
	Version    string   `json:"version"`
	ExportedAt string   `json:"exported_at"`
	Encryption string   `json:"encryption"`         // none | aes-gcm
	AutoKey    bool     `json:"auto_key,omitempty"` // 是否使用设备编号加密
	Modules    []string `json:"modules"`            // 本次备份包含的模块
}

// backupExportReq 导出请求参数。
type backupExportReq struct {
	Modules    []string `json:"modules"`    // 空 = 全量
	Encryption string   `json:"encryption"` // none | auto | password
	Password   string   `json:"password"`   // 手动加密密码
}

// backupRestoreResult 恢复操作的结果摘要。
type backupRestoreResult struct {
	ConfigKeys    int    `json:"config_keys"`   // 已合并的系统设置项数
	HookKeys      int    `json:"hook_keys"`     // 已合并的自定义UI（导航页配置）项数
	RulesStarted  int    `json:"rules_started"` // 已启动/更新的转发规则数
	RulesSkipped  int    `json:"rules_skipped"` // 启动失败的转发规则数
	FrpcMerged    bool   `json:"frpc_merged"`   // FRP 配置是否已合并
	FrpcError     string `json:"frpc_error,omitempty"`
	IPCustom      int    `json:"ip_custom"`
	IPWhitelist   int    `json:"ip_whitelist"`
	IPBlocked     int    `json:"ip_blocked"`
	DNSAccounts   int    `json:"dns_accounts"`   // 已合并的 DNS 账户数
	DDNSTasks     int    `json:"ddns_tasks"`     // 已合并的 DDNS 任务数
	CertsMerged   int    `json:"certs_merged"`   // 已恢复的证书数
	EmailsMerged  int    `json:"emails_merged"`  // 已恢复的 ACME 邮箱数
	GeoSources    int    `json:"geo_sources"`    // 已恢复的地理数据源数
	GeoRanges     int    `json:"geo_ranges"`     // 已恢复的 IP 段数
	IconsFiles    int    `json:"icons_files"`    // 已恢复的图标文件数
	DeskConfigs   int    `json:"desk_configs"`   // 已恢复的桌面图标配置数
	WHRestored    bool   `json:"wh_restored"`    // Webhook 通道记录是否已恢复
	ErrorPages    int    `json:"error_pages"`    // 已恢复的错误页模板数
	AutoDecrypted bool   `json:"auto_decrypted"` // 是否已用设备编号自动解密
}

// backupPreviewSummary 恢复预览：解析备份包后返回的内容摘要（供用户勾选恢复模块）。
type backupPreviewSummary struct {
	Manifest      backupManifestView   `json:"manifest"`
	Content       backupPreviewContent `json:"content"`
	AutoDecrypted bool                 `json:"auto_decrypted"`
}

type backupManifestView struct {
	App        string   `json:"app"`
	Version    string   `json:"version"`
	ExportedAt string   `json:"exported_at"`
	Encryption string   `json:"encryption"`         // none | aes-gcm
	AutoKey    bool     `json:"auto_key,omitempty"` // 是否使用设备编号加密
	Modules    []string `json:"modules"`            // 备份时包含的模块
}

type backupPreviewContent struct {
	Settings map[string]interface{} `json:"settings"` // {keys: 项数}
	Hook     map[string]interface{} `json:"hook"`     // 自定义UI：导航页配置 {keys: 项数}
	Rules    []backupPreviewRule    `json:"rules"`    // 转发规则（含描述）
	Frpc     *backupPreviewFrpc     `json:"frpc,omitempty"`
	IPFilter backupPreviewIPFilter  `json:"ip_filter"`
	DNS      backupPreviewDNS       `json:"dns"`   // 域名解析：账户与任务数
	Cert     backupPreviewCert      `json:"cert"`  // 证书库 + ACME 邮箱
	Geo      backupPreviewGeo       `json:"geo"`   // 地理数据源 + IP 段
	Icons    int                    `json:"icons"` // 图标文件数
	Desk     int                    `json:"desk"`  // 桌面图标配置数
	WH       bool                   `json:"wh"`    // 是否包含 Webhook 通道记录
}

type backupPreviewCert struct {
	Certs  int `json:"certs"`  // 证书数
	Emails int `json:"emails"` // ACME 邮箱数
}

type backupPreviewGeo struct {
	Sources int `json:"sources"` // 数据源数
	Ranges  int `json:"ranges"`  // IP 段数
}

type backupPreviewDNS struct {
	Accounts int `json:"accounts"` // DNS 账户数
	Tasks    int `json:"tasks"`    // DDNS 任务数
}

type backupPreviewRule struct {
	Key      string `json:"key"`
	Protocol string `json:"protocol"`
	Local    string `json:"local"`  // 本地监听 地址:端口
	Remote   string `json:"remote"` // 远端目标 地址:端口
	Domain   string `json:"domain,omitempty"`
	Desc     string `json:"desc,omitempty"`
}

type backupPreviewFrpc struct {
	Servers []string `json:"servers"`
	Proxies []string `json:"proxies"`
}

type backupPreviewIPFilter struct {
	Custom    int `json:"custom"`
	Whitelist int `json:"whitelist"`
	Blocked   int `json:"blocked"`
}

// apiErrCode 带错误码的错误响应（前端据此区分需要输入密码等场景）。
func apiErrCode(msg, code string) map[string]interface{} {
	return map[string]interface{}{"success": false, "error": msg, "error_code": code}
}

// deviceSerialKey 返回设备唯一编号（作为自动加密密钥的来源）：
// 优先 CPU 序列号（/proc/cpuinfo serial，ARM 等），其次 DMI 主板/产品序列号（x86），
// 最后回退到 /etc/machine-id（保证同设备稳定）。
func deviceSerialKey() string {
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.ToLower(line), "serial") {
				if _, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(v) != "" {
					return strings.TrimSpace(v)
				}
			}
		}
	}
	for _, p := range []string{
		"/sys/class/dmi/id/product_uuid",
		"/sys/class/dmi/id/board_serial",
		"/sys/class/dmi/id/product_serial",
	} {
		if v, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(v)) != "" {
			return strings.TrimSpace(string(v))
		}
	}
	if v, err := os.ReadFile("/etc/machine-id"); err == nil && strings.TrimSpace(string(v)) != "" {
		return strings.TrimSpace(string(v))
	}
	return ""
}

// cryptoEnvelope 加密数据封装（AES-256-GCM + PBKDF2-SHA256）。
type cryptoEnvelope struct {
	KDF   string `json:"kdf"`
	Iter  int    `json:"iter"`
	Salt  string `json:"salt"`
	Nonce string `json:"nonce"`
	Data  string `json:"data"`
}

func deriveKey(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, kdfIter, 32)
}

// encryptPayload 用密码加密明文数据。
func encryptPayload(plain []byte, password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plain, nil)
	return json.Marshal(cryptoEnvelope{
		KDF:   "pbkdf2-sha256",
		Iter:  kdfIter,
		Salt:  base64.StdEncoding.EncodeToString(salt),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		Data:  base64.StdEncoding.EncodeToString(ct),
	})
}

// decryptPayload 用密码解密数据。
func decryptPayload(cipherData []byte, password string) ([]byte, error) {
	var env cryptoEnvelope
	if err := json.Unmarshal(cipherData, &env); err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, nil)
}

// normalizeModules 规范化模块列表：空列表或全部非法项时返回全量模块。
func normalizeModules(mods []string) []string {
	all := []string{modSettings, modRules, modFrpc, modIPFilter, modDNS, modHook, modCert, modGeo, modIcons, modWH}
	if len(mods) == 0 {
		return all
	}
	valid := make(map[string]bool)
	for _, m := range all {
		valid[m] = true
	}
	out := make([]string, 0, len(mods))
	seen := make(map[string]bool)
	for _, m := range mods {
		if valid[m] && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return all
	}
	return out
}

// buildBackupPayload 按所选模块收集备份数据。
func (s *Server) buildBackupPayload(modules []string) backupPayload {
	has := func(m string) bool {
		for _, x := range modules {
			if x == m {
				return true
			}
		}
		return false
	}
	payload := backupPayload{
		App:        backupAppName,
		Version:    "0.6.6.172",
		ExportedAt: time.Now().Format(time.RFC3339),
	}
	if has(modSettings) {
		if kv, err := s.store.SettingsByPrefix("cfg."); err == nil {
			cfgMap := make(map[string]interface{}, len(kv))
			for k, v := range kv {
				key := strings.TrimPrefix(k, "cfg.")
				var val interface{}
				if err := json.Unmarshal([]byte(v), &val); err == nil {
					cfgMap[key] = val
				}
			}
			payload.Config = cfgMap
		}
		// 错误页模板为 <dataDir>/errorpages 下的磁盘文件，不在 cfg.* 里，随「系统设置」一并导出
		tpls := make(map[string]string, len(errpage.Codes))
		for _, code := range errpage.Codes {
			if content, ok := errpage.Content(code); ok {
				tpls[strconv.Itoa(code)] = content
			}
		}
		payload.ErrorPages = tpls
	}
	if has(modHook) {
		if kv, err := s.store.SettingsByPrefix("cfg.hook."); err == nil {
			hookMap := make(map[string]interface{}, len(kv))
			for k, v := range kv {
				key := strings.TrimPrefix(k, "cfg.hook.")
				var val interface{}
				if err := json.Unmarshal([]byte(v), &val); err == nil {
					hookMap[key] = val
				}
			}
			payload.Hook = hookMap
		}
	}
	if has(modRules) {
		if recs, err := s.store.ListForwardRules(); err == nil {
			payload.ForwardRules = recs
		}
		if kv, err := s.store.SettingsByPrefix("desc."); err == nil {
			desc := make(map[string]string, len(kv))
			for k, v := range kv {
				desc[strings.TrimPrefix(k, "desc.")] = v
			}
			payload.Descriptions = desc
		}
	}
	if has(modFrpc) {
		fc := s.frpcMgr.LoadConfig()
		payload.Frpc = &fc
	}
	if has(modIPFilter) {
		if list, err := s.store.ListCustomIPs(); err == nil {
			payload.IPFilter.Custom = list
		}
		if list, err := s.store.ListWhitelistIPs(); err == nil {
			payload.IPFilter.Whitelist = list
		}
		if list, err := s.store.ListBlockedIPs(); err == nil {
			payload.IPFilter.Blocked = list
		}
	}
	if has(modDNS) {
		if accounts, err := s.store.ListDNSAccounts(); err == nil {
			payload.DNSAccounts = accounts
		}
		if tasks, err := s.store.ListDDNSTasks(); err == nil {
			payload.DDNSTasks = tasks
		}
	}
	if has(modCert) {
		if certs, err := s.store.ListCertificatesWithContent(); err == nil {
			payload.Certificates = make([]backupCert, 0, len(certs))
			for _, c := range certs {
				payload.Certificates = append(payload.Certificates, backupCert{
					Domain: c.Domain, Email: c.Email, Issuer: c.Issuer,
					CertPEM: c.CertPEM, KeyPEM: c.KeyPEM,
					NotBefore: c.NotBefore, NotAfter: c.NotAfter, CreatedAt: c.CreatedAt,
				})
			}
		}
		if emails, err := s.store.ListEmails(); err == nil {
			payload.Emails = emails
		}
	}
	if has(modGeo) {
		if srcs, err := s.store.ListGeoSources(); err == nil {
			payload.GeoSources = srcs
		}
		if ranges, err := s.store.LoadAllGeoRanges(); err == nil {
			payload.GeoRanges = ranges
		}
	}
	if has(modIcons) {
		if kv, err := s.store.SettingsByPrefix("desk."); err == nil {
			payload.DeskConfig = kv
		}
		payload.Icons = s.collectIcons()
	}
	if has(modWH) {
		if v, err := s.store.GetSetting(whRecordsKey); err == nil {
			payload.WHRecords = v
		}
	}
	return payload
}

// collectIcons 读取 icons 目录下全部图标文件（hook 导航页图标 + 桌面规则图标）。
func (s *Server) collectIcons() map[string][]byte {
	icons := map[string][]byte{}
	entries, err := os.ReadDir(s.iconsDir())
	if err != nil {
		return icons
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.iconsDir(), e.Name()))
		if err == nil && len(b) > 0 {
			icons[e.Name()] = b
		}
	}
	return icons
}

// handleBackupExport 导出备份：POST JSON（模块 + 加密选项），返回 ZIP 包。
// 自动加密时通过 X-Backup-Password 响应头返回设备编号密码供用户复制。
func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	var req backupExportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("无效的请求参数"))
		return
	}
	switch req.Encryption {
	case "", encNone:
		req.Encryption = encNone
	case encAuto, encPassword:
	default:
		s.writeJSON(w, http.StatusBadRequest, apiErr("不支持的加密方式"))
		return
	}
	if req.Encryption == encPassword && strings.TrimSpace(req.Password) == "" {
		s.writeJSON(w, http.StatusBadRequest, apiErr("手动加密必须填写密码"))
		return
	}

	password := ""
	autoKey := false
	switch req.Encryption {
	case encAuto:
		password = deviceSerialKey()
		if password == "" {
			s.writeJSON(w, http.StatusBadRequest, apiErr("无法获取设备编号，请改用手动密码加密"))
			return
		}
		autoKey = true
	case encPassword:
		password = req.Password
	}

	modules := normalizeModules(req.Modules)
	plain, err := json.Marshal(s.buildBackupPayload(modules))
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("生成备份失败"))
		return
	}

	data := plain
	if req.Encryption != encNone {
		if data, err = encryptPayload(plain, password); err != nil {
			s.writeJSON(w, http.StatusInternalServerError, apiErr("加密备份失败"))
			return
		}
	}

	// ZIP 打包：manifest.json（明文清单）+ data.bin（内容，可能加密）
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	manifest := backupManifest{
		App:        backupAppName,
		Version:    "0.6.6.172",
		ExportedAt: time.Now().Format(time.RFC3339),
		Encryption: encNone,
		Modules:    modules,
	}
	if req.Encryption != encNone {
		manifest.Encryption = encAESGCM
		manifest.AutoKey = autoKey
	}
	mj, err := json.MarshalIndent(manifest, "", "  ")
	if err == nil {
		if mf, err := zw.Create("manifest.json"); err == nil {
			mf.Write(mj)
		}
	}
	if df, err := zw.Create("data.bin"); err == nil {
		df.Write(data)
	}
	if err := zw.Close(); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, apiErr("打包备份失败"))
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="tunhook-backup-%s.zip"`, time.Now().Format("20060102-150405")))
	if autoKey {
		w.Header().Set("X-Backup-Password", password)
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	w.Write(buf.Bytes())
}

// handleBackupImport 导入备份：multipart（file + 可选 password + 可选 modules）。
// 加密备份优先用设备编号自动解密，失败且未提供密码时返回 BACKUP_NEED_PASSWORD。
// modules 为空时恢复全部模块；指定时仅恢复所选模块（由前端预览后勾选）。
func (s *Server) handleBackupImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, backupMaxUpload)
	if err := r.ParseMultipartForm(backupMaxUpload); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("读取上传文件失败"))
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少备份文件"))
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(file)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("读取备份文件失败"))
		return
	}

	_, payload, autoDecrypted, derr := readAndDecryptBackup(raw, r.FormValue("password"))
	if derr != nil {
		if errors.Is(derr, errNeedPassword) {
			s.writeJSON(w, http.StatusOK, apiErrCode("备份文件已加密，请输入密码", "BACKUP_NEED_PASSWORD"))
			return
		}
		s.writeJSON(w, http.StatusBadRequest, apiErr(derr.Error()))
		return
	}
	result := backupRestoreResult{AutoDecrypted: autoDecrypted}

	// 模块过滤：仅恢复用户勾选的模块（空 = 全部）
	var mods map[string]bool
	if m := r.FormValue("modules"); strings.TrimSpace(m) != "" {
		mods = make(map[string]bool)
		for _, x := range strings.Split(m, ",") {
			if x = strings.TrimSpace(x); x != "" {
				mods[x] = true
			}
		}
	}
	s.applyBackupPayload(payload, &result, mods, w)
}

// handleBackupPreview 预览备份包内容（不落盘）：返回清单与内容摘要，
// 供前端展示给用户勾选要恢复的模块。
func (s *Server) handleBackupPreview(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, backupMaxUpload)
	if err := r.ParseMultipartForm(backupMaxUpload); err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("读取上传文件失败"))
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("缺少备份文件"))
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(file)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, apiErr("读取备份文件失败"))
		return
	}

	manifest, payload, autoDecrypted, derr := readAndDecryptBackup(raw, r.FormValue("password"))
	if derr != nil {
		if errors.Is(derr, errNeedPassword) {
			s.writeJSON(w, http.StatusOK, apiErrCode("备份文件已加密，请输入密码", "BACKUP_NEED_PASSWORD"))
			return
		}
		s.writeJSON(w, http.StatusBadRequest, apiErr(derr.Error()))
		return
	}

	summary := backupPreviewSummary{
		Manifest: backupManifestView{
			App:        backupAppName,
			Encryption: "none",
			Modules:    nil,
		},
		Content:       buildBackupPreview(payload),
		AutoDecrypted: autoDecrypted,
	}
	if manifest != nil {
		summary.Manifest = backupManifestView{
			App:        manifest.App,
			Version:    manifest.Version,
			ExportedAt: manifest.ExportedAt,
			Encryption: manifest.Encryption,
			AutoKey:    manifest.AutoKey,
			Modules:    manifest.Modules,
		}
	}
	s.writeJSON(w, http.StatusOK, apiOK(summary))
}

// readAndDecryptBackup 统一读取备份：解析 ZIP（兼容旧版 JSON），
// 加密时先尝试设备编号自动解密，失败再尝试用户提供的密码。
func readAndDecryptBackup(raw []byte, password string) (*backupManifest, *backupPayload, bool, error) {
	manifest, data, err := readBackupZip(raw)
	if err != nil {
		// 兼容旧版 JSON 备份（未加密）
		var payload backupPayload
		if jerr := json.Unmarshal(raw, &payload); jerr != nil || !strings.EqualFold(payload.App, backupAppName) {
			return nil, nil, false, errors.New("不是有效的 TunHook 备份文件")
		}
		return nil, &payload, false, nil
	}
	if !strings.EqualFold(manifest.App, backupAppName) {
		return nil, nil, false, errors.New("不是 TunHook 的备份文件")
	}

	var payload backupPayload
	autoDecrypted := false
	if manifest.Encryption == encAESGCM {
		plain, derr := []byte(nil), error(nil)
		if serial := deviceSerialKey(); serial != "" {
			plain, derr = decryptPayload(data, serial)
			if derr == nil {
				autoDecrypted = true
			}
		}
		if derr != nil && password != "" {
			plain, derr = decryptPayload(data, password)
		}
		if derr != nil {
			if password == "" {
				return nil, nil, false, errNeedPassword
			}
			return nil, nil, false, errors.New("解密失败：密码错误或备份文件已损坏")
		}
		if err := json.Unmarshal(plain, &payload); err != nil {
			return nil, nil, false, errors.New("备份内容解析失败")
		}
	} else if err := json.Unmarshal(data, &payload); err != nil {
		return nil, nil, false, errors.New("备份内容解析失败")
	}
	return &manifest, &payload, autoDecrypted, nil
}

// buildBackupPreview 汇总备份内容摘要（供恢复前勾选）。
func buildBackupPreview(payload *backupPayload) backupPreviewContent {
	content := backupPreviewContent{}
	if len(payload.Config) > 0 {
		content.Settings = map[string]interface{}{"keys": len(payload.Config)}
	} else {
		content.Settings = map[string]interface{}{"keys": 0}
	}
	if len(payload.Hook) > 0 {
		content.Hook = map[string]interface{}{"keys": len(payload.Hook)}
	} else {
		content.Hook = map[string]interface{}{"keys": 0}
	}
	content.Rules = make([]backupPreviewRule, 0, len(payload.ForwardRules))
	for _, r := range payload.ForwardRules {
		pr := backupPreviewRule{
			Key:      r.Key,
			Protocol: r.Protocol,
			Local:    fmt.Sprintf("%s:%d", r.LocalAddr, r.LocalPort),
			Remote:   fmt.Sprintf("%s:%d", r.RemoteAddr, r.RemotePort),
			Domain:   r.Domain,
			Desc:     payload.Descriptions["forward:"+r.Key],
		}
		content.Rules = append(content.Rules, pr)
	}
	if payload.Frpc != nil {
		f := &backupPreviewFrpc{}
		for _, s := range payload.Frpc.Servers {
			f.Servers = append(f.Servers, s.Name)
		}
		for _, p := range payload.Frpc.Proxies {
			f.Proxies = append(f.Proxies, p.Name)
		}
		content.Frpc = f
	}
	content.IPFilter = backupPreviewIPFilter{
		Custom:    len(payload.IPFilter.Custom),
		Whitelist: len(payload.IPFilter.Whitelist),
		Blocked:   len(payload.IPFilter.Blocked),
	}
	content.DNS = backupPreviewDNS{
		Accounts: len(payload.DNSAccounts),
		Tasks:    len(payload.DDNSTasks),
	}
	content.Cert = backupPreviewCert{
		Certs:  len(payload.Certificates),
		Emails: len(payload.Emails),
	}
	content.Geo = backupPreviewGeo{
		Sources: len(payload.GeoSources),
		Ranges:  len(payload.GeoRanges),
	}
	content.Icons = len(payload.Icons)
	content.Desk = len(payload.DeskConfig)
	content.WH = strings.TrimSpace(payload.WHRecords) != ""
	return content
}

// applyBackupPayload 按合并模式恢复备份内容（系统设置 / 转发规则 / FRP / IP 过滤 / 域名解析）。
// modules 非空时仅恢复勾选的模块。
func (s *Server) applyBackupPayload(payload *backupPayload, result *backupRestoreResult, modules map[string]bool, w http.ResponseWriter) {
	want := func(m string) bool {
		if modules == nil {
			return true
		}
		return modules[m]
	}
	// 1. 系统设置
	if want(modSettings) && len(payload.Config) > 0 {
		result.ConfigKeys = s.applyBackupConfig(payload.Config)
	}
	// 1.2 错误页模板（磁盘文件）
	if want(modSettings) && len(payload.ErrorPages) > 0 {
		result.ErrorPages = applyBackupErrorPages(payload.ErrorPages, s.logger)
	}
	// 1.5 自定义UI（导航页配置，cfg.hook.*）
	if want(modHook) && len(payload.Hook) > 0 {
		result.HookKeys = s.applyBackupHook(payload.Hook)
	}
	// 2. 转发规则 + 描述
	if want(modRules) {
		result.RulesStarted, result.RulesSkipped = s.applyBackupForwardRules(payload.ForwardRules, payload.Descriptions)
	}
	// 3. FRP 配置
	if want(modFrpc) && payload.Frpc != nil {
		if err := s.applyBackupFrpc(payload.Frpc); err != nil {
			s.logger.Warn("备份恢复 FRP 配置失败", zap.Error(err))
			result.FrpcError = err.Error()
		} else {
			result.FrpcMerged = true
		}
	}
	// 4. IP 过滤条目
	if want(modIPFilter) {
		result.IPCustom, result.IPWhitelist, result.IPBlocked = s.applyBackupIPFilter(payload.IPFilter)
	}
	// 5. 域名解析（DNS 账户 + DDNS 任务）
	if want(modDNS) {
		result.DNSAccounts, result.DDNSTasks = s.applyBackupDNS(payload.DNSAccounts, payload.DDNSTasks)
	}
	// 6. 证书库 + ACME 联系人
	if want(modCert) {
		result.CertsMerged, result.EmailsMerged = s.applyBackupCert(payload.Certificates, payload.Emails)
	}
	// 7. 地理数据源 + IP 段
	if want(modGeo) {
		result.GeoSources, result.GeoRanges = s.applyBackupGeo(payload.GeoSources, payload.GeoRanges)
	}
	// 8. 图标与桌面图标（desk.* 配置 + icons/ 文件）
	if want(modIcons) {
		result.IconsFiles, result.DeskConfigs = s.applyBackupIcons(payload.Icons, payload.DeskConfig)
	}
	// 9. Webhook 通道记录
	if want(modWH) && strings.TrimSpace(payload.WHRecords) != "" {
		if err := s.whRecv.restorePersist(payload.WHRecords); err != nil {
			s.logger.Warn("备份恢复 Webhook 通道记录失败", zap.Error(err))
		} else {
			result.WHRestored = true
		}
	}

	s.writeJSON(w, http.StatusOK, apiOK(result))
}

// readBackupZip 解包 ZIP，读取 manifest.json 与 data.bin。
func readBackupZip(raw []byte) (backupManifest, []byte, error) {
	var manifest backupManifest
	if len(raw) < 4 || !bytes.Equal(raw[:4], []byte("PK\x03\x04")) {
		return manifest, nil, errors.New("not a zip backup")
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return manifest, nil, err
	}
	var dataBin []byte
	foundManifest := false
	for _, f := range zr.File {
		switch f.Name {
		case "manifest.json":
			rc, err := f.Open()
			if err != nil {
				continue
			}
			mj, rerr := io.ReadAll(rc)
			rc.Close()
			if rerr != nil {
				continue
			}
			if json.Unmarshal(mj, &manifest) != nil {
				continue
			}
			foundManifest = true
		case "data.bin":
			rc, err := f.Open()
			if err != nil {
				continue
			}
			dataBin, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}
		}
	}
	if !foundManifest || dataBin == nil {
		return manifest, nil, errors.New("invalid backup zip")
	}
	return manifest, dataBin, nil
}

// applyBackupErrorPages 把备份中的错误页模板写回 <dataDir>/errorpages 磁盘文件并立即生效。
// 键为状态码字符串，值为该状态码的整页 HTML；无法识别的状态码跳过。
func applyBackupErrorPages(tpls map[string]string, logger *zap.Logger) int {
	count := 0
	for codeStr, content := range tpls {
		code, err := strconv.Atoi(codeStr)
		if err != nil {
			continue
		}
		if err := errpage.Save(code, content); err != nil {
			logger.Warn("备份恢复错误页模板失败", zap.String("code", codeStr), zap.Error(err))
			continue
		}
		count++
	}
	return count
}

// applyBackupConfig 把备份中的 cfg.* 设置合并到当前配置：备份中的键覆盖当前，
// 其余键保留；同时写入 DB（重启后依然生效）并即时应用到内存配置。
func (s *Server) applyBackupConfig(cfgMap map[string]interface{}) int {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	keys := make([]string, 0, len(cfgMap))
	for k := range cfgMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	count := 0
	for _, key := range keys {
		val := cfgMap[key]
		if val == nil {
			continue
		}
		if err := s.store.SetJSON("cfg."+key, val); err != nil {
			s.logger.Warn("备份恢复配置持久化失败", zap.String("key", key), zap.Error(err))
			continue
		}
		count++
	}
	// 应用内存配置：viper.Set 覆盖各 key 后重新 Unmarshal（与启动 applyDBConfig 一致）
	for _, key := range keys {
		if cfgMap[key] == nil {
			continue
		}
		viper.Set(key, cfgMap[key])
	}
	_ = viper.Unmarshal(s.cfg)
	// 即时应用部分运行期配置（其余设置重启后完全生效）
	if s.cfg.Log.MaxEntries > 0 {
		s.logBuf.SetCap(s.cfg.Log.MaxEntries)
	}
	s.forwardLogs.setCapsAll(s.cfg.Log.TunnelMaxEntries, s.cfg.Log.TunnelAccessMaxEntries)
	return count
}

// applyBackupHook 把备份中的自定义UI（导航页配置，cfg.hook.*）合并到当前配置：
// 键不含 cfg.hook. 前缀，恢复时补齐前缀写回 DB 并应用到内存配置（与 applyBackupConfig 一致）。
func (s *Server) applyBackupHook(hookMap map[string]interface{}) int {
	cfgMap := make(map[string]interface{}, len(hookMap))
	for k, v := range hookMap {
		cfgMap["hook."+k] = v
	}
	return s.applyBackupConfig(cfgMap)
}

// applyBackupForwardRules 按 key 合并转发规则并启动/更新，同时恢复描述。
func (s *Server) applyBackupForwardRules(records []store.RuleRecord, desc map[string]string) (started, skipped int) {
	running := make(map[string]bool)
	for _, k := range s.fwdMgr.RunningRules() {
		running[k] = true
	}
	for _, sr := range records {
		rule := recordToForwardRule(sr)
		key := sr.Key
		if key == "" {
			key = ruleKey(rule)
		}
		// 合并模式：key 已存在则先停止旧规则（更新），否则直接启动
		if running[key] {
			s.fwdMgr.StopRule(rule)
		}
		if err := s.fwdMgr.StartRule(rule); err != nil {
			s.logger.Warn("备份恢复启动转发规则失败",
				zap.String("key", key), zap.Error(err))
			skipped++
			continue
		}
		if d, ok := desc["forward:"+key]; ok && d != "" {
			s.setDescription("forward", key, d)
		}
		s.forwardLogs.setRuleConfig(key, rule.LogLevel, rule.ChannelLogEntries, rule.AccessLogEntries)
		started++
	}
	return started, skipped
}

// recordToForwardRule 把数据库中的转发规则记录转换为运行配置。
func recordToForwardRule(sr store.RuleRecord) config.ForwardRule {
	return config.ForwardRule{
		Protocol: sr.Protocol, LocalAddr: sr.LocalAddr,
		LocalPort: sr.LocalPort, RemoteAddr: sr.RemoteAddr, RemotePort: sr.RemotePort,
		Domain: sr.Domain, Name: sr.Name, SourcePrefix: sr.SourcePrefix,
		RootPrefixes: sr.RootPrefixes, PathPrefix: sr.PathPrefix,
		AutoDetect: sr.AutoDetect, CertPEM: sr.CertPEM, KeyPEM: sr.KeyPEM,
		TLSEnable: sr.TLSEnable,
		RateLimit: sr.RateLimit, MaxConnections: sr.MaxConnections,
		ProxyProtocol: sr.ProxyProtocol, TLSSource: sr.TLSSource,
		UDPSessionTimeout: sr.UDPSessionTimeout, UDPMaxSessions: sr.UDPMaxSessions,
		UDPMaxBlockLen: sr.UDPMaxBlockLen,
		LogLevel:       sr.LogLevel, ChannelLogEntries: sr.ChannelLogEntries,
		AccessLogEntries:  sr.AccessLogEntries,
		LogRetentionHours: sr.LogRetentionHours,
		CustomID:          sr.CustomID, CustomDomain: sr.CustomDomain,
		LinkKey: sr.LinkKey, AccessPassword: sr.AccessPassword,
	}
}

// applyBackupFrpc 合并 frpc 配置：服务器/代理按名称合并（备份覆盖同名），
// 当前存在但备份未包含的保留；激活服务器与客户端级日志设置仅在备份有值时覆盖。
func (s *Server) applyBackupFrpc(bk *frpc.Config) error {
	cur := s.frpcMgr.LoadConfig()

	// 服务器：按名称合并，保持当前顺序，新增的备份服务器追加在后
	byName := make(map[string]frpc.Server, len(cur.Servers)+len(bk.Servers))
	for _, sv := range cur.Servers {
		byName[sv.Name] = sv
	}
	var newServers []string
	for _, sv := range bk.Servers {
		if _, ok := byName[sv.Name]; !ok {
			newServers = append(newServers, sv.Name)
		}
		byName[sv.Name] = sv
	}
	servers := make([]frpc.Server, 0, len(byName))
	for _, sv := range cur.Servers {
		servers = append(servers, byName[sv.Name])
	}
	for _, name := range newServers {
		servers = append(servers, byName[name])
	}
	cur.Servers = servers
	if bk.ActiveServer != "" {
		cur.ActiveServer = bk.ActiveServer
	}

	// 代理：按名称合并
	byP := make(map[string]frpc.Proxy, len(cur.Proxies)+len(bk.Proxies))
	for _, p := range cur.Proxies {
		byP[p.Name] = p
	}
	var newProxies []string
	for _, p := range bk.Proxies {
		if _, ok := byP[p.Name]; !ok {
			newProxies = append(newProxies, p.Name)
		}
		byP[p.Name] = p
	}
	proxies := make([]frpc.Proxy, 0, len(byP))
	for _, p := range cur.Proxies {
		proxies = append(proxies, byP[p.Name])
	}
	for _, name := range newProxies {
		proxies = append(proxies, byP[name])
	}
	cur.Proxies = proxies

	// 客户端级日志设置
	if bk.LogLevel != "" {
		cur.LogLevel = bk.LogLevel
	}
	if bk.LogEntries > 0 {
		cur.LogEntries = bk.LogEntries
	}
	if bk.LogDays > 0 {
		cur.LogDays = bk.LogDays
	}
	return s.frpcMgr.SaveConfig(cur)
}

// applyBackupIPFilter 追加备份中的 IP 过滤条目（幂等），返回各类新增数量。
func (s *Server) applyBackupIPFilter(bk backupIPFilter) (custom, whitelist, blocked int) {
	for _, ip := range bk.Custom {
		if strings.TrimSpace(ip) != "" {
			if err := s.store.AddCustomIP(ip); err == nil {
				custom++
			}
		}
	}
	for _, ip := range bk.Whitelist {
		if strings.TrimSpace(ip) != "" {
			if err := s.store.AddWhitelistIP(ip); err == nil {
				whitelist++
			}
		}
	}
	for _, ip := range bk.Blocked {
		if strings.TrimSpace(ip) != "" {
			if err := s.store.RecordBlockedIP(ip); err == nil {
				blocked++
			}
		}
	}
	// 更新 IP 过滤运行时缓存（自定义条目参与过滤判定）
	if custom > 0 || whitelist > 0 {
		s.loadBlocklist()
	}
	return custom, whitelist, blocked
}

// applyBackupDNS 合并恢复域名解析数据（合并覆盖，当前未在备份中的保留）：
//   - DNS 账户按名称覆盖（先删同名再插入，保证 provider/credentials 更新）；
//   - DDNS 任务按 (账户+域名+主机+类型) 匹配更新，无匹配则新增。
//
// 返回 (恢复的账户数, 恢复的任务数)。
func (s *Server) applyBackupDNS(accounts []store.DNSAccount, tasks []store.DDNSTask) (int, int) {
	nAccount := 0
	for _, a := range accounts {
		if strings.TrimSpace(a.Name) == "" {
			continue
		}
		// 同名先删再插（INSERT OR IGNORE 无法更新已有行）
		_ = s.store.DeleteDNSAccount(a.Name)
		if err := s.store.AddDNSAccount(strings.TrimSpace(a.Name), a.Provider, a.Credentials); err == nil {
			nAccount++
		}
	}

	nTask := 0
	existing, _ := s.store.ListDDNSTasks()
	for _, t := range tasks {
		if strings.TrimSpace(t.Account) == "" || strings.TrimSpace(t.Domain) == "" {
			continue
		}
		match := int64(0)
		for _, e := range existing {
			if strings.EqualFold(e.Account, t.Account) &&
				strings.EqualFold(e.Domain, t.Domain) &&
				strings.EqualFold(e.RR, t.RR) &&
				strings.EqualFold(e.RRType, t.RRType) {
				match = e.ID
				break
			}
		}
		if match > 0 {
			t.ID = match
			if err := s.store.UpdateDDNSTask(t); err == nil {
				nTask++
			}
		} else {
			if _, err := s.store.AddDDNSTask(t); err == nil {
				nTask++
			}
		}
	}
	return nAccount, nTask
}

// applyBackupCert 合并恢复证书库与 ACME 联系人：
//   - 证书按域名覆盖（SaveCertificate 基于 domain 唯一 UPSERT）；
//   - 邮箱先删同名再插入（AddEmail 为 INSERT OR IGNORE，无法更新已有行）。
//
// 返回 (恢复的证书数, 恢复的邮箱数)。
func (s *Server) applyBackupCert(certs []backupCert, emails []store.ACMEContact) (int, int) {
	nCert := 0
	for _, c := range certs {
		if strings.TrimSpace(c.Domain) == "" {
			continue
		}
		if err := s.store.SaveCertificate(store.CertRecord{
			Domain: c.Domain, Email: c.Email, Issuer: c.Issuer,
			CertPEM: c.CertPEM, KeyPEM: c.KeyPEM,
			NotBefore: c.NotBefore, NotAfter: c.NotAfter, CreatedAt: c.CreatedAt,
		}); err == nil {
			nCert++
		}
	}

	nEmail := 0
	for _, e := range emails {
		if strings.TrimSpace(e.Email) == "" {
			continue
		}
		_ = s.store.DeleteEmail(e.Email)
		if err := s.store.AddEmail(e.Email, e.CAType, e.KeyAlg); err == nil {
			nEmail++
		}
	}
	return nCert, nEmail
}

// applyBackupGeo 合并恢复地理数据源与 IP 段：
// 数据源按 (category,class) 幂等 upsert（拿到恢复后的新 ID），
// 再把备份 IP 段的旧 source_id 映射为新 ID 后全量替换该源数据。
// 返回 (恢复的数据源数, 恢复的 IP 段数)。
func (s *Server) applyBackupGeo(sources []store.GeoSource, ranges []store.GeoRange) (int, int) {
	bySource := make(map[int64][]store.GeoRange, len(sources))
	for _, r := range ranges {
		bySource[r.SourceID] = append(bySource[r.SourceID], r)
	}
	nSource := 0
	nRanges := 0
	for _, src := range sources {
		newID, err := s.store.UpsertGeoSource(src)
		if err != nil {
			continue
		}
		nSource++
		rs := bySource[src.ID]
		if len(rs) == 0 {
			continue
		}
		for i := range rs {
			rs[i].SourceID = newID
		}
		if err := s.store.ReplaceGeoRangesBySource(newID, rs); err == nil {
			nRanges += len(rs)
		}
	}
	return nSource, nRanges
}

// applyBackupIcons 恢复图标文件（icons/ 目录）与桌面图标配置（desk.*）。
// 文件名仅接受纯文件名（防路径穿越）。返回 (恢复的图标文件数, 恢复的桌面配置数)。
func (s *Server) applyBackupIcons(icons map[string][]byte, desk map[string]string) (int, int) {
	nFiles := 0
	if len(icons) > 0 {
		if err := os.MkdirAll(s.iconsDir(), 0755); err == nil {
			for name, data := range icons {
				base := filepath.Base(name)
				if base == "" || base == "." || base != name || len(data) == 0 {
					continue
				}
				if err := os.WriteFile(filepath.Join(s.iconsDir(), base), data, 0644); err == nil {
					nFiles++
				}
			}
		}
	}
	nDesk := 0
	for k, v := range desk {
		if !strings.HasPrefix(k, "desk.") {
			continue
		}
		if err := s.store.SetSetting(k, v); err == nil {
			nDesk++
		}
	}
	return nFiles, nDesk
}
