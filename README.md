# TunHook

TunHook 是一款自托管的端口转发与内网穿透工具，主要面向飞牛 fnOS / Linux NAS。它把端口映射、frp 穿透、Cloudflare Tunnel、STUN 打洞、证书与域名管理、监控通知集中到一个 Web 控制台里。

- 官网：<https://tunhook.top>
- 仓库：<https://github.com/YUNXI-fi/TunHook>
- 更新日志：[CHANGELOG.md](CHANGELOG.md)

## 功能

### 端口转发

- TCP / UDP / HTTP / HTTPS 端口映射与统一网关
- 每条规则可独立设置限速、最大连接数、PROXY protocol v2、源端 TLS、UDP 会话参数与日志
- 监听网卡选择、端口占用自动处理、本机直连优化、目标 favicon 抓取

### 内网穿透

- frpc 客户端，兼容 FRP、MEFrp、LoliaFrp
- Cloudflare Tunnel 多实例托管（Token 托管 / API 全托管）
- TCP STUN 打洞与 NAT 类型探测
- 隧道健康检查、frpc 登录看门狗、断线自动恢复

### 证书与域名

- Let's Encrypt 证书申请与自动续期（HTTP-01 / DNS-01）
- 多 DNS 服务商账户与解析记录管理
- 通道域名绑定与解析记录自动补写、清理

### 运维与安全

- IP 黑白名单、归属地过滤、局域网放行
- 访问密码、Webhook 通知、通道访问日志
- 日志轮转与历史清理、全量备份恢复
- 错误页自定义、通道导航页、仪表盘布局与模块开关

### 管理界面

- 简体中文 / 繁体中文 / English / 日本語，切换即时生效
- 响应式布局，适配桌面与移动端
- 浅色 / 深色主题与多套配色

### ROOT 版增强

- 桌面图标一键打包安装
- Docker 端口扫描
- 服务器连通性测试
- 本机直连优化

## 技术栈

| 层 | 技术 |
| --- | --- |
| 后端 | Go 1.25、Cobra、Viper、Zap、SQLite（modernc.org/sqlite，无 cgo） |
| 前端 | Svelte 4、Vite 5 |
| 打包 | fnOS fpk（fnpack） |

运行环境：fnOS / Linux x86_64。当前代码仅在 Linux 上构建与验证，未适配 Windows / macOS。

## 目录结构

```text
.
├── src/                 Go 源码与前端工程
│   ├── web/ui/          Svelte 控制台（源码）
│   └── web/static/      前端构建产物（不入库，由 go:embed 嵌入二进制）
├── TunHook/             fnOS 打包目录（manifest / app / cmd / config / wizard / i18n）
│   ├── build.sh         打包脚本
│   └── app/frp/         frp 离线安装包与客户端
├── dev-data/            开发运行时数据与本地二进制（不入库）
├── 编译产物/             打包输出（不入库）
├── dev-restart.sh       开发迭代脚本
└── CHANGELOG.md
```

## 本地开发

### 环境要求

- Go 1.25+
- Node.js 18+
- fnpack（仅打包需要）

### 首次构建

```bash
cd src/web/ui
npm ci
npm run build

cd ../../..
./dev-restart.sh
```

`dev-restart.sh` 会依次构建前端、重新编译二进制，并重启本机正在运行的实例；首次没有运行实例时只执行构建。

### 启动

```bash
./dev-data/tunhook web --addr 127.0.0.1 --port 19094
```

浏览器访问 <http://127.0.0.1:19094>。如需指定配置或日志位置：

```bash
./dev-data/tunhook web --addr 127.0.0.1 --port 19094 -c dev-data/config.yaml --log-file dev-data/tunhook.log
```

生产环境由 fnOS 统一网关通过 Unix Socket 访问，不需要 `--addr` / `--port`。

## 打包 fnOS 应用

```bash
cd src/web/ui
npm ci
npm run build

cd ../../..
cd TunHook
./build.sh
```

输出：`编译产物/TunHook_v<版本>.fpk`，安装包文件名取自 `TunHook/manifest` 的 `version`。

打包前确认：

- `fnpack` 与 `go` 在 PATH 中
- `src/web/static/index.html` 已生成
- `TunHook/app/frp` 内的 frp 离线包存在；`frpc` 可执行文件仓库默认忽略，可按需从离线包解压放入

安装时将 `.fpk` 上传到飞牛应用中心即可。

## 版本管理

版本号需要保持一致，涉及以下位置：

- `TunHook/manifest` 的 `version`
- `src/cli/root.go`、`src/web/web.go`、`src/web/backup.go`
- `src/forward/acme.go`、`src/mefrp/mefrp.go`、`src/lolia/lolia.go` 的 UserAgent
- `src/web/ui/package.json` / `package-lock.json`

发布前同步更新 [CHANGELOG.md](CHANGELOG.md) 与应用内「关于」页的更新日志。

## 贡献

欢迎提交 Issue 与 Pull Request。提交前请确保前端构建与 `go build ./...` 通过，并同步更新更新日志。

## 许可

[Apache License 2.0](LICENSE)。请仅将本项目用于合法的网络调试、设备远程访问与学习研究。

## 支持

如果 TunHook 对你有帮助，可以在应用内「关于 → 支持开发者」扫码支持。
