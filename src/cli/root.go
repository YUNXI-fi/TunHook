package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"tunhook/config"
	"tunhook/errpage"
	"tunhook/forward"
	"tunhook/store"
	"tunhook/web"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	cfgFile  string
	logLevel string
	logFile  string
	version  = "0.6.6.172"
)

const (
	// mainLogMaxBytes 自动日志单文件体积上限，超过则在启动前滚动为 .1（与 cloudflared 同策略）。
	mainLogMaxBytes = 20 << 20
	// mainLogMaxAge 自动日志保留时长，启动时清理更早的 tunhook-*.log（含 .1 滚动文件）。
	mainLogMaxAge = 7 * 24 * time.Hour
)

// maintainMainLog 自动日志维护：当前日志超限时滚动为 .1，并清理超过保留期的历史日志。
// 仅在启动时执行（无后台开销）；日志风暴时最坏只占用 20MB 当天文件 + 一份 .1。
func maintainMainLog(logDir, logFile string) {
	if st, err := os.Stat(logFile); err == nil && st.Size() >= mainLogMaxBytes {
		_ = os.Rename(logFile, logFile+".1")
	}
	cutoff := time.Now().Add(-mainLogMaxAge)
	matches, _ := filepath.Glob(filepath.Join(logDir, "tunhook-*.log*"))
	for _, p := range matches {
		if p == logFile {
			continue
		}
		if st, err := os.Stat(p); err == nil && st.ModTime().Before(cutoff) {
			_ = os.Remove(p)
		}
	}
}

var rootCmd = &cobra.Command{
	Use:     "TunHook",
	Short:   "内网穿透与端口转发工具",
	Long:    "一款支持跨平台的端口转发与内网穿透工具，支持TCP/UDP端口映射、frp 内网穿透（frpc 客户端）、转发规则管理与 Web 管理界面。",
	Version: version,
}

var forwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "仅启动端口转发服务",
	RunE:  runForward,
}

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "启动Web管理界面",
	Long:  "启动Web管理界面。生产环境仅通过飞牛统一网关访问；--addr/--port 仅用于本地开发预览。",
	RunE:  runWeb,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "配置文件路径")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "", "日志级别 (debug/info/warn/error)")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", "", "日志文件路径")

	forwardCmd.Flags().String("protocol", "tcp", "转发协议 (tcp/udp)")
	forwardCmd.Flags().String("local-addr", "0.0.0.0", "本地监听地址")
	forwardCmd.Flags().Int("local-port", 0, "本地监听端口")
	forwardCmd.Flags().String("remote-addr", "", "远程目标地址")
	forwardCmd.Flags().Int("remote-port", 0, "远程目标端口")

	rootCmd.AddCommand(forwardCmd)
	rootCmd.AddCommand(webCmd)

	webCmd.Flags().Int("port", 0, "本地开发Web端口（与 --addr 配合，生产不传）")
	webCmd.Flags().String("addr", "", "本地开发监听地址（与 --port 配合，生产不传）")
	webCmd.Flags().String("socket", "", "fnOS网关Unix Socket路径")
	webCmd.Flags().String("gateway-prefix", "/app/TunHook", "fnOS网关访问前缀")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// fnOSPathDerive 在 fnOS 环境（TRIM_APPDEST 已设置）但持久目录环境变量缺失时，
// 按标准布局推导 /vol{n}/@appdata/{appname} 或 /vol{n}/@appconf/{appname}，
// 绝不回退到应用目录（@appcenter/{appname}，升级会被替换导致数据/配置重置）。
// 推导顺序与 shell _derive_persist_dir / cmd/main derive_dir 完全一致：
//  1. TRIM_APPDEST_VOL + sub + appname    （平台注入卷根）
//  2. TRIM_APPDEST 含 /@appcenter/ → marker 替换
//  3. TRIM_APPDEST 提取首个路径段作为卷根 （等价于 shell sed 's|/.*||'）
func fnOSPathDerive(sub string) string {
	appname := os.Getenv("TRIM_APPNAME")
	if appname == "" {
		appname = "TunHook" // shell fallback 用硬编码 TunHook
	}
	// 1. 平台注入卷根
	if vol := os.Getenv("TRIM_APPDEST_VOL"); vol != "" {
		return filepath.Join(vol, sub, appname)
	}
	// 2. TRIM_APPDEST 形如 /vol{n}/@appcenter/{appname}，替换 @appcenter 段为 @appdata/@appconf
	marker := "/@appcenter/"
	if appDest := os.Getenv("TRIM_APPDEST"); appDest != "" {
		if i := strings.LastIndex(appDest, marker); i >= 0 {
			return appDest[:i+1] + sub + "/" + appDest[i+len(marker):]
		}
	}
	// 3. 从 TRIM_APPDEST 提取卷根（首个路径段），等价于 shell sed 's|/.*||'
	if appDest := os.Getenv("TRIM_APPDEST"); appDest != "" {
		trimmed := strings.TrimPrefix(appDest, "/")
		if idx := strings.Index(trimmed, "/"); idx > 0 {
			return filepath.Join("/", trimmed[:idx], sub, appname)
		}
	}
	return ""
}

func dataDir() string {
	if d := os.Getenv("TUNHOOK_DATA_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("TRIM_PKGVAR"); d != "" {
		return d
	}
	// fnOS 下 TRIM_PKGVAR 缺失：按标准布局推导 @appdata，避免回退到会被升级替换的应用目录
	if d := fnOSPathDerive("@appdata"); d != "" {
		return d
	}
	// 回退：本地开发通过可执行文件路径推导
	if exePath, err := os.Executable(); err == nil {
		return filepath.Dir(exePath)
	}
	return "data"
}

// frpcConfigDir 返回 frpc 配置文件目录（@appconf/TunHook，升级保留）；
// 未显式指定时回退 TRIM_PKGETC，本地开发跟随数据根 frp/ 目录保持原布局。
func frpcConfigDir() string {
	if d := os.Getenv("TUNHOOK_CONFIG_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("TRIM_PKGETC"); d != "" {
		return d
	}
	// fnOS 下 TRIM_PKGETC 缺失：按标准布局推导 @appconf，避免回退到应用目录
	if d := fnOSPathDerive("@appconf"); d != "" {
		return d
	}
	return filepath.Join(dataDir(), "frp")
}

func etcDir() string {
	// TRIM_PKGETC: fnOS 配置文件目录（/vol1/@appconf/TunHook）
	if d := os.Getenv("TRIM_PKGETC"); d != "" {
		return d
	}
	// fnOS 下 TRIM_PKGETC 缺失：按标准布局推导 @appconf，避免回退到应用目录
	if d := fnOSPathDerive("@appconf"); d != "" {
		return d
	}
	// 回退：本地开发可执行文件同目录
	if exePath, err := os.Executable(); err == nil {
		return filepath.Dir(exePath)
	}
	return "."
}

// sharePaths 返回 fnOS 数据共享目录路径（/vol1/@appshare/TunHook/...）
type sharePaths struct {
	Log   string
	Rules string
}

func getSharePaths() sharePaths {
	dd := dataDir()
	return sharePaths{
		Log:   envOr("TUNHOOK_SHARE_LOG", filepath.Join(dd, "log")),
		Rules: envOr("TUNHOOK_SHARE_RULES", filepath.Join(dd, "rules")),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// openStore 打开 SQLite 数据存储（dataDir/db/tunhook.db）。
func openStore() (*store.Store, error) {
	st, err := store.Open(filepath.Join(dataDir(), "db", "tunhook.db"))
	if err != nil {
		return nil, err
	}
	return st, nil
}

// resolveConfigPath 返回实际生效的配置文件路径（与 loadConfigAndLogger 保持一致）。
func resolveConfigPath() string {
	if cfgFile != "" {
		return cfgFile
	}
	etcPath := filepath.Join(etcDir(), "config.yaml")
	if _, err := os.Stat(etcPath); err == nil {
		return etcPath
	}
	return ""
}

// applyDBConfig 用 DB 中持久化的配置项覆盖 yaml 配置
// （Web 端保存的设置，重启后依然生效；优先级 yaml < DB < 环境变量）。
func applyDBConfig(cfg *config.Config, st *store.Store) error {
	kv, err := st.SettingsByPrefix("cfg.")
	if err != nil {
		return err
	}
	for k, v := range kv {
		var val interface{}
		if err := json.Unmarshal([]byte(v), &val); err != nil {
			continue
		}
		viper.Set(strings.TrimPrefix(k, "cfg."), val)
	}
	return viper.Unmarshal(cfg)
}

func buildLogger(level, file string) *zap.Logger {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zap.DebugLevel
	case "warn":
		zapLevel = zap.WarnLevel
	case "error":
		zapLevel = zap.ErrorLevel
	default:
		zapLevel = zap.InfoLevel
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	var cores []zapcore.Core

	cores = append(cores, zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderCfg),
		zapcore.AddSync(os.Stderr),
		zapLevel,
	))

	// Auto log file
	logDir := getSharePaths().Log
	os.MkdirAll(logDir, 0755)
	logFile := filepath.Join(logDir, "tunhook-"+time.Now().Format("2006-01-02")+".log")
	maintainMainLog(logDir, logFile)
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		fileEncoderCfg := zap.NewProductionEncoderConfig()
		fileEncoderCfg.TimeKey = "ts"
		fileEncoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
		cores = append(cores, zapcore.NewCore(
			zapcore.NewJSONEncoder(fileEncoderCfg),
			zapcore.AddSync(f),
			zapLevel,
		))
	}

	if file != "" && file != logFile {
		f2, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			fileEncoderCfg := zap.NewProductionEncoderConfig()
			fileEncoderCfg.TimeKey = "ts"
			fileEncoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
			cores = append(cores, zapcore.NewCore(
				zapcore.NewJSONEncoder(fileEncoderCfg),
				zapcore.AddSync(f2),
				zapLevel,
			))
		}
	}

	return zap.New(zapcore.NewTee(cores...), zap.AddCaller())
}

func loadConfigAndLogger() (*config.Config, *zap.Logger, error) {
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}

	lvl := cfg.Log.Level
	if logLevel != "" {
		lvl = logLevel
	}
	lf := cfg.Log.File
	if logFile != "" {
		lf = logFile
	}

	logger := buildLogger(lvl, lf)
	return cfg, logger, nil
}

func runForward(cmd *cobra.Command, args []string) error {
	cfg, logger, err := loadConfigAndLogger()
	if err != nil {
		return err
	}
	defer logger.Sync()

	protocol, _ := cmd.Flags().GetString("protocol")
	localAddr, _ := cmd.Flags().GetString("local-addr")
	localPort, _ := cmd.Flags().GetInt("local-port")
	remoteAddr, _ := cmd.Flags().GetString("remote-addr")
	remotePort, _ := cmd.Flags().GetInt("remote-port")

	st, err := openStore()
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if err := applyDBConfig(cfg, st); err != nil {
		return fmt.Errorf("apply db config: %w", err)
	}

	rules := cfg.Forward.Rules

	// 统一网关转发规则仅在 Web 管理界面（/proxy/{name}）下生效，CLI 模式直接跳过
	filtered := make([]config.ForwardRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Protocol == "gateway" || rule.Protocol == "GATEWAY" {
			logger.Warn("统一网关转发规则仅在 Web 管理界面下生效，CLI 模式已跳过",
				zap.String("rule", ruleKey(rule)))
			continue
		}
		filtered = append(filtered, rule)
	}
	rules = filtered

	if localPort > 0 && remoteAddr != "" && remotePort > 0 {
		rules = append(rules, config.ForwardRule{
			Protocol:   protocol,
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
		})
	}

	if len(rules) == 0 {
		return fmt.Errorf("no forwarding rules configured, use flags or config file")
	}

	// 自定义错误页：CLI 独立转发模式同样按模板文件渲染（与 Web 服务共用同一份模板）
	if err := errpage.Init(filepath.Join(dataDir(), "errorpages")); err != nil {
		logger.Warn("init error page templates failed", zap.Error(err))
	}

	mgr := forward.NewManager(logger, st)
	if err := mgr.StartAll(rules); err != nil {
		return fmt.Errorf("start forwarding: %w", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("port forwarding is running, press Ctrl+C to stop")
	for _, r := range rules {
		logger.Info("forwarding rule",
			zap.String("protocol", r.Protocol),
			zap.String("local", fmt.Sprintf("%s:%d", r.LocalAddr, r.LocalPort)),
			zap.String("remote", fmt.Sprintf("%s:%d", r.RemoteAddr, r.RemotePort)),
		)
	}

	<-sigCh
	logger.Info("shutting down...")
	mgr.StopAll()
	return nil
}

func runWeb(cmd *cobra.Command, args []string) error {
	cfg, logger, err := loadConfigAndLogger()
	if err != nil {
		return err
	}
	defer logger.Sync()

	dataDir := dataDir()

	st, err := openStore()
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if err := applyDBConfig(cfg, st); err != nil {
		return fmt.Errorf("apply db config: %w", err)
	}

	socketPath, _ := cmd.Flags().GetString("socket")
	gatewayPrefix, _ := cmd.Flags().GetString("gateway-prefix")
	addr, _ := cmd.Flags().GetString("addr")
	port, _ := cmd.Flags().GetInt("port")

	listenAddr := ""
	if addr != "" {
		listenAddr = fmt.Sprintf("%s:%d", addr, port)
	}
	if socketPath == "" && listenAddr == "" {
		return fmt.Errorf("--socket（生产网关）或 --addr/--port（本地开发）必须提供一个")
	}

	sp := getSharePaths()

	srv := web.NewServer(listenAddr, cfg, logger, st, dataDir, sp.Log, sp.Rules, frpcConfigDir(), socketPath, gatewayPrefix)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		if listenAddr != "" {
			fmt.Printf("  本地预览: http://%s\n", listenAddr)
		} else {
			fmt.Println("  统一网关入口: /app/TunHook")
		}
		fmt.Println("  按 Ctrl+C 停止服务")
		fmt.Println()

		if err := srv.Start(); err != nil {
			logger.Error("web server failed", zap.Error(err))
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		srv.Stop()
		return err
	case <-sigCh:
		logger.Info("shutting down web server...")
		srv.Stop()
		return nil
	}
}

func ruleKey(r config.ForwardRule) string {
	return fmt.Sprintf("%s://%s:%d->%s:%d",
		r.Protocol, r.LocalAddr, r.LocalPort, r.RemoteAddr, r.RemotePort)
}
