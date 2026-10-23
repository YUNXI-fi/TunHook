<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  import { onMount } from 'svelte';
  import { status } from '../lib/stores.js';
  import { api } from '../lib/api.js';
  import Modal from '../components/Modal.svelte';
  import supportQr from '../assets/support-yunxi.png';

  // 免责声明确认状态（存服务端 SQLite、全局共享）：卡片下方展示「已同意」与确认时间
  let disclaimer = null;
  let showSupport = false;

  // 更新日志：版本目录 + 搜索（按版本/条目过滤，命中文字高亮）
  const CHANGELOG = [
    { version: "v0.6.6.172", items: [
        "管理界面全站国际化：新增简体中文 / 繁体中文 / English / 日本語 四种语言，切换即时生效无需刷新；全部页面、弹窗、表单校验、Toast 与无障碍标签均已接入（3037 条词条）",
        "「关于」页更新日志支持版本目录与搜索：左侧版本列表可点击跳转并高亮当前版本，搜索框按版本号或条目内容过滤并高亮命中文字",
        "「关于」页新增「支持开发者」入口，点击弹出赞赏码；免责声明与开发者信息卡片等高，声明正文内部滚动且隐藏滚动条",
        "项目链接更新：项目主页改为 https://tunhook.top，联系方式与开源地址指向 https://github.com/YUNXI-fi/TunHook",
        "版本号统一为 0.6.6.172（CLI、Web 状态、备份清单、UserAgent、前端包与安装包）"
    ] },
    { version: "v0.6.6.171", items: [
        "修复 frpc 日志查看接口带写副作用：LogTailFor 此前会按配置的日志保留行数顺带裁剪日志（即重写整个文件），上一版新增的登录看门狗每 2 秒调用一次，使只读接口变成高频写盘。现将裁剪与读取解耦：LogTailFor 改为纯读，裁剪收敛到新的唯一入口 TrimLogs，由看门狗按 60 秒间隔节流执行，防止日志无限增长的原有能力不变；仅当 LogEntries > 0 时才会触发裁剪，默认 0（不限制）不受影响"
    ] },
    { version: "v0.6.6.170", items: [
        "新增 frpc 登录看门狗，穿透断连后能自行恢复：按日志中最后一条登录结果判定，连续 10 次失败（约 20 秒）自动重启该实例并清零计数；进程重启后有 30 秒启动宽限期，避免旧日志残留触发连续重启。判定依据是登录日志而非管理 API——管理 API 只反映 frpc 进程存活，不反映隧道是否连通",
        "FRP 管理 API 查询失败不再静默丢弃：/api/frpc/conns 新增 failed 字段，返回查询失败的服务器及原因（无应答 / HTTP 状态码 / 响应解析失败），界面可区分「隧道断开」与「查不到状态」",
        "服务器状态新增 watchdog_fails 字段，展示连续登录失败次数，便于确认是否正在自动恢复"
    ] },
    { version: "v0.6.6.169", items: [
        "端口转发通道表单的「绑定域名」同步改造为「域名选择 + 主机记录」（与上一版 MEFrp / LoliaFrp 隧道一致）：域名从「域名解析」模块已有域名中下拉（跨账户聚合、优先展示已解析到所选 Frps 服务器 IP 的域名、未解析的标注「暂未解析」但同样可选），主机记录可选 @（主域名）或子域名（填前缀并实时显示完整域名）；新增「自定义域名」选项，选中后就地变为手动输入完整域名的输入框",
        "修正候选域名的「已解析」判定为读取本模块解析记录中的 @ 与 *（启用态）：此前拿根域名去公网解析，而 frp 虚拟主机的标准配置是「*.域名」泛解析到 frps、根域名本身不解析，这类正确配置被误判为「未解析」、候选几乎只剩「自定义域名」；现已解析的排前、未解析的明确标注但依然可选",
        "保存通道后按需补写解析记录：只写该通道实际用到的那条主机记录，已解析到目标的跳过、同名同值跳过，同名不同值绝不覆盖（只回报冲突）；删除通道 / 代理时按值匹配清理，只删「主机记录 + 类型 + 值」三者都对得上的那一条，手工改过的记录不误删",
        "系统设置侧栏子分区顺序调整，并删除与「系统日志」页重复的「日志管理」分区；把设置页子分区清单提为唯一来源，侧栏子菜单与页头副标题由同一份清单生成（此前两份手工清单已漂移、副标题漏两项）；主侧栏标签顺序调整",
        "修复提示图标嵌入表单标签后点击会误触发关联控件（点击事件冒泡到 label 被转发给输入框，现阻止冒泡）；解析记录弹窗无障碍告警清零；端口转发侧栏图标替换",
        "「系统设置 → 模块管理」的模块清单按侧栏顺序排列（此前两份顺序不一致）；字节与速率的单位显示统一到共享格式化函数，并新增「80% 提前进位」规则——当前单位数值达到下一单位最小值的 80%（1024×0.8 = 819.2）即进位，不再出现「819 GB」这类逼近四位数的读法（819.2 GB 显示为 0.8 TB），全站口径一致并删除 LoliaFrp 页面、两个流量图表与 Cloudflare 页面里各自手写的同名实现",
        "修复 MEFrp 流量的两处单位错误：剩余流量此前写死 GB 单位（TB 量级仍显示为「10826.9 GB」），现按量级自动进位；权益抽取把接口返回的 MB 数值直接标成 GB，实际相差 1024 倍（抽到 512 MB 显示成「512.0 GB」），现统一按 MB 口径换算"
    ] },
    { version: "v0.6.6.168", items: [
        "MEFrp / LoliaFrp 隧道「绑定域名」改造为「域名选择 + 主机记录」：域名从「域名解析」模块已有域名中下拉选择，主机记录可选 @（主域名）或子域名（填前缀并实时显示完整域名），不再手输完整域名；隧道创建成功后自动把节点连接地址解析到该域名（解析出 IPv4 写 A 记录，解析不到才退化为 CNAME），删除隧道时同步删除指向该节点的解析记录（只删「主机记录 + 类型 + 值」都对得上的那条，避免误删手工改过的记录）；编辑弹窗提供「写入解析」按钮，并显示解析目标（记录类型 + 实际写入的地址）。LoliaFrp 的候选域名取「域名解析里的域名 ∩ 已在 Lolia 完成归属验证的域名」，避免选出建不成隧道的域名。新增跨账户聚合域名接口与 MEFrp 节点连接地址接口支撑该功能",
        "修复 MEFrp 节点连接地址恒为空导致的「服务器地址」框与 TCP 隧道访问地址一直空白：MEFrp 的连接地址只在节点地址列表接口返回（且只包含已建过隧道的节点），创建数据接口的 hostname 本就为空、此前取错了来源；现改由新接口获取，进入页面与建/删隧道后都会自动刷新。同时按接口语义解释「新建隧道时地址必然为空」的原因",
        "修复 LoliaFrp 端口扫描「添加」后本地地址、端口、备注全部填不进去：借别名（const t = createForm; t.x = ...）修改组件变量属性不会触发 Svelte 更新，界面因此不刷新；现改为整体重新赋值。并补充「扫描选中即用网页标题/进程名/服务名填充备注」（已有备注不覆盖，其余扫描入口的既有规则保持一致）",
        "修复 LoliaFrp 令牌自动续期失败即清空授权、被迫重新授权：此前不区分「refresh_token 确实失效」与「网络抖动 / 服务端 5xx / 限流」，一次连接重置就会把本地凭证（含 refresh_token）一并抹掉；现只有令牌端点明确拒绝才清空凭证并引导重新授权，临时失败保留凭证、提示稍后重试。跨境链路偶发的连接重置另加一次 GET 自动重试（POST 不重试，避免重复建隧道或重复轮换 refresh_token）；本地无凭证时直接提示「请先完成授权」，不再抛出无从下手的 401",
        "解析记录弹窗无障碍改进：表单标签与输入控件建立真实关联，可点击卡片补齐按钮语义与键盘操作（Enter / 空格）；同步调整仪表盘页头按钮顺序与端口转发图标"
    ] },
    { version: "v0.6.6.167", items: [
        "管理控制台移动端排版全面适配：各弹窗多列统计卡与双列表单窄屏自动单列堆叠、弹窗内固定 min-width 窄屏归零，消除横向溢出；STUN 探测弹窗控制行换行；端口扫描模式切换条可换行、DNS 结果表横向滚动；Cloudflare 弹窗固定宽控件改弹性填充；仪表盘弹窗与布局编辑预览降列；「输入框+按钮」操作行统一为放得下就同一行、放不下才折行（桌面端布局全部不变）",
        "STUN 服务器配置移除「名称」字段，仅保留地址与协议，探测/打洞下拉直接显示地址；数据库旧 name 字段在服务启动时自动检测并回写清理，恢复旧备份后重启亦自愈",
        "修复 STUN 设置页服务器列表在手机端散成三行：列表行任何屏宽保持单行，地址框占剩余宽度、协议下拉 108px、删除按钮保持 44px 触控热区"
    ] },
    { version: "v0.6.6.166", items: [
        "主日志新增自动轮转与历史清理：当天日志超过 20MB 时，下次启动自动滚动为 .1 备份、新日志从零开始，日志风暴时磁盘占用封顶；同时启动时自动清理 7 天前的 tunhook-*.log 历史日志（含 .1），避免长期运行日志无限增长写满 fnOS 系统分区（此前 busy-loop 期间曾刷出单日 90MB+ 且永久堆积）。仅在启动时执行，无任何后台开销"
    ] },
    { version: "v0.6.6.165", items: [
        "修复 TCP STUN 探测全部失败、通道在服务器列表里无限轮换：163 手工实现 STUN-over-TCP 时误加了 RFC4571 两字节长度前缀（那是 RTP-over-TCP 的分帧，与 STUN 无关），服务器校验失败后严格者直接 reset、另一些超时——表现为能连上但请求一发就被拒。现改为 RFC5389 原生分帧，已对 cope.es/signalwire/siptrunk 等真实服务器验证正常返回"
    ] },
    { version: "v0.6.6.164", items: [
        "浅色主题底色改为无彩中性灰阶 + 纯白表面（参考 PriTime）：页面底 #fafafa、卡片/侧边栏/输入框纯白、内层 #f5f5f5、边框 #e5e5e5；六套配色的浅色底统一为中性底、不再带淡彩染色，层次靠边框与阴影承担，亮环境下更柔和，强调色与深色主题不变"
    ] },
    { version: "v0.6.6.163", items: [
        "彻底修复 TCP 打洞通道满载 CPU 的根因：除读超时外，公网 STUN 服务器/NAT 主动断开空闲保活连接时，第三方 STUN 库的常驻读循环会因反复读到 EOF/reset 而全速空转（这才是真实环境启动即阵发性满载、而本机难以复现的触发路径）。本版彻底弃用该库的 Client，改在裸连接上手工收发 STUN 事务，空闲时无后台读循环、连接断开即立即重连，从结构上消除忙转"
    ] },
    { version: "v0.6.6.162", items: [
        "彻底修复 TCP 打洞通道持续满载 CPU（每条启用中的通道约吃掉一个核）：上一版把「清除连接读超时」放在了 client.Do() 之后，而 Do 的等待由第三方 STUN 库自身的重传序列驱动、可能远超探测超时——Do 不返回则清除永不执行，连接长期停留在「读超时已过期」状态，库的常驻读循环对读错误既不退出也不退让，于是全速空转并连带拉满 GC（因 Read 属系统调用，表现为系统态高企）。本版改为连接全程不设读超时、探测超时由 select 兜底，从结构上消除该状态"
    ] },
    { version: "v0.6.6.161", items: [
        "大幅降低空闲时 CPU 占用：系统连接表扫描（转发列表与 frpc 连接统计都会触发）加 1.5 秒共享缓存，同一轮询周期内只扫描一次（此前单次解析可达数百毫秒）",
        "前端轮询统一为「可见性感知」并按下游开销分级：页面不可见时自动暂停、回到前台立即补一次；重接口由 3 秒放宽到 10 秒，其余统一到 5 秒",
        "修复 TCP 打洞通道持续满载 CPU（每条启用中的通道约吃掉一个核）：保活探测设置的读超时在探测完成后未清除，第三方 STUN 库的常驻读循环在超时过期后每次 Read 都立即失败且既不退出也不退让，退化为全速空转并连带拉满 GC——表现为设备空闲、无流量、日志零增长但 CPU 长期满载；现改为探测完成即清除本轮超时",
        "为 Webhook 代理与端口扫描的自建 HTTP Transport 补齐 TLS 握手超时，避免上游 TLS 握手挂起时拨号 goroutine 长期滞留"
    ] },
    { version: "v0.6.6.160", items: [
        "新增「错误页面」自定义：400/401/403/404/405/410/500/502/503 九个状态码各一份完整 HTML 模板（内置复古终端故障风格），可在设置页编辑保存即时生效，也可直接修改模板文件；支持按真实状态码预览与一键恢复内置默认（当前自定义内容会被覆盖）。仅接管浏览器页面请求，接口与上游后端自己返回的错误页不受影响；模板随备份导出/恢复",
        "Cloudflare Tunnel 支持多隧道实例：每条实例独立凭证、内核进程、路由表与日志，可分别启停/重启/删除，内核二进制全局共用；旧单实例配置自动迁移；新增「从云端刷新路由表」把 Cloudflare 后台改动同步回本页。临时入口新增「暂停/恢复」——暂停不断线、不换访问地址（访客看到 503），改本地回源无需重启内核",
        "内核下载前并发测速官方源与 8 个国内加速镜像，按实际吞吐择优并逐源回退；无外网时可上传离线内核包兜底安装",
        "仪表盘布局自定义：KPI 概览与卡片可拖动排序、收起恢复（收起项在同组底部列出），卡片内各行的显隐与顺序也可单独编辑（齿轮或右键卡片），带实时布局预览；KPI 最多显示 8 项，支持一键恢复默认布局，改动即时保存且随备份保留",
        "系统设置新增模块管理：可关闭暂不使用的模块（STUN/内网穿透/端口转发/Webhook/MEFrp/Cloudflare Tunnel/端口扫描），关闭后导航入口隐藏、直接访问其页面被拦下、仪表盘对应卡片一并隐藏，已启动的隧道与转发规则照常工作",
        "全站配色与主题体系重构：对比度全面达标、图表随主题即时重绘、主题切换改为从点击处圆形扩散；移动端列表改为卡片视图并新增抽屉导航；frpc 通道日志过滤管理接口轮询噪声"
    ] },
    { version: "v0.6.6.150", items: [
        "新增 Cloudflare Tunnel 接入（第三种穿透方式）：把本地 Web 服务以自有域名的固定 HTTPS 地址发布到公网，无需公网 IP 与自行申请证书；仅支持 HTTP/HTTPS 域名入口（UDP 不支持，TCP/SSH/RDP 需对端安装 cloudflared），需要任意端口映射请继续使用 FRP",
        "两种托管方式：Token 托管（在 Cloudflare 后台建隧道与路由，本页只托管连接器）与 API 全托管（在本页创建隧道、配置域名路由并自动写入 DNS 解析；凭证复用「域名解析」模块的 Cloudflare 账号，账号 ID 由所选域名自动推导）",
        "连接器内核按需下载（约 40MB 不随安装包内置，带下载进度与离线包上传兜底、原子替换升级不中断隧道）、/ready 连接状态与内核日志查看、随应用启动自启；连接协议默认 HTTP/2（实测大陆链路延迟与吞吐明显优于 QUIC）",
        "修复残留 pid 文件且 PID 被系统复用时的「运行中」误报与停止时误杀无关进程的问题（frpc / MEFrp / cloudflared 三处统一改为按进程归属校验）"
    ] },
    { version: "v0.6.6.140", items: [
        "端口扫描新增域名目标：输入域名后自动解析 IPv4 地址，仅解析出一个地址时直接开始扫描，多个地址时在输入框下方列出全部 IP 由用户选择（点击即按当前动作执行「扫描端口」/「扫描IP」，并可随时切换地址重扫）；新增 /api/ports/resolve 解析接口（多公共 DNS 兜底、地址去重、兼容误粘贴完整 URL）",
        "修复端口扫描无法扫描域名的问题：此前输入域名界面只提示「IP 范围格式应为…」，解析出的端口结果因没有对应地址卡片而无处渲染；现域名不再误报格式错误，扫描目标改为「解析后选定的 IP」，切换 IP 时「未使用 / 在线」状态同步重置"
    ] },
    { version: "v0.6.6.130", items: [
        "仪表盘「系统信息」卡新增设备名称、系统版本、系统时间：设备时间按服务端时间校正后每秒走字，远程访问时显示的仍是设备本地时间（不受浏览器时区影响）",
        "仪表盘「frp 服务器」卡改版为客户端/服务端视角：客户端版本、客户端状态、服务端地址、服务端状态、网络延迟、通道数量、通道在线率",
        "流量统计图表新增「全屏查看」按钮：一键全屏并自动锁定横屏（移动端），退出时自动解除横屏锁定",
        "仪表盘 KPI 概览移动端改为两列紧凑布局（6 张卡 3 行），并隐藏进程协程数、TCP/UDP 明细、转发总数等次要信息",
        "图标风格统一：流量统计图表的「刷新」由实心图标改为线性描边、「历史记录」描边加粗至全站标准",
        "修复服务停止（SIGTERM）可能长时间卡死无法退出的问题：IP 归属地数据源的目录刷新、链接检测与数据下载现可被取消，关服时立即中断在途请求（此前须等整轮跑完，实测卡住约 4 分钟）"
    ] },
    { version: "v0.6.6.120", items: [
        "转发规则弹窗新增「监听网卡」选择，基础配置表单重构为等宽双列布局（描述/协议、监听网卡/监听端口、目标地址/目标端口）",
        "网卡下拉自动识别网卡上真实绑定的公网 IP：PPPoE 直连等双 IP 场景可分别选择绑定公网或内网地址，NAT 后无公网 IP 的网卡不显示公网选项",
        "修复编辑转发规则时修改监听地址与监听端口不生效的问题（后端更新接口遗漏字段），变更后规则自动重启并迁移桌面图标配置",
        "转发列表地址按规则实际绑定地址展示：绑定公网 IP 显示公网地址，通配/内网监听显示局域网直达地址"
    ] },
    { version: "v0.6.6.110", items: [
        "修复从端口扫描结果一键创建转发规则时，局域网扫描到的主机 IP 被误当作本机监听地址，导致规则启动失败（bind: cannot assign requested address）的问题；现主机 IP 正确填入目标地址，监听地址统一为 0.0.0.0"
    ] },
    { version: "v0.6.6.100", items: [
        "备份/恢复覆盖全部内容模块：新增证书库与 ACME 联系人、地理数据源与已下载 IP 段（含 36 万级数据）、图标与桌面图标、Webhook 通道记录 4 个模块；导入上限提升至 512MB（容纳全量地理数据）",
        "通道导航页壁纸本地固化：接口随机图/图片链接壁纸抓取后固化为本地 dataURL，不再每次访问依赖外网图床，并支持每日自动换新",
        "仪表盘新增 Webhook 状态卡（通道数/最近活动/重定向次数/成功率）与「通道导航」「服务状态」页头快捷入口",
        "流量统计按时间区间累计：切换 1h/7h/12h/24h/历史 时显示区间累计，实时模式显示总累计，顶栏时间切换与图例一行展示",
        "MEFrp 权益抽取修复（只能抽 9 次问题）、人机验证窗口与本地工具栏布局优化、图标风格统一"
    ] },
    { version: "v0.6.5", items: [
        "修复「升级/覆盖安装后数据被重置」根因：卸载脚本改为默认保留数据（仅向导显式选择删除才清理），配合 v0.6.4.1 起的数据迁移逻辑，升级不再丢数据",
        "MEFrp 权益抽取流量单位显示修复：按数值自动换算正确单位（GB/MB），不再一律按 MB 展示",
        "列表「流量统计」列改为当前实时速率（无连接显示 0），frpc 代理新增持久累计流量（无连接不再归零），累计与连接详情在弹窗查看",
        "修复初次使用欢迎弹窗与通道导航页（/hook）搜索引擎图标加载失败：图标补回 public 目录，接口增加内置兜底图标（绝不 404）；图标引用改为统一网关前缀并追加缓存失效参数（?v=），自定义域名/独立域名下也不再 404（搜索引擎图标内嵌 data-URI SVG）"
    ] },
    { version: "v0.6.4.7.1", items: [
        "MEFrp 电源按钮状态灯语义：隧道在线=绿色（点击强制下线）、离线=红色（点击启用隧道），上下线一键闭环",
        "MEFrp 启用/强制下线本地同步：点启用时云端已禁用的隧道自动启用后再拉起、本地 frpc 已在运行自动重启并保留其他隧道；强制下线时云端踢下线并同时从本地 frpc 移除该隧道（移出自启列表、按剩余隧道重启或停止进程），下线保持离线不自动回连",
        "MEFrp 状态实时刷新：进入页面强制拉取最新通道数据，并结合本地 frpc 运行状态兜底修正，不再显示云端缓存滞后导致的陈旧「离线」",
        "MEFrp 权益抽取状态完善：剩余次数 x/10 展示；次数用完后显示「已抽取」；按天记录当日已抽完状态（跨天自动重置）",
        "MEFrp 节点权限控制：「无权限」筛选改为筛掉无权限节点；点击无权限节点（如正式用户点 VIP 节点）提示「无权使用此节点，请开通 VIP 会员」",
        "MEFrp 界面改进：账户卡信息合并为一行；签到/权益抽取改为竖排；移动端适配（账户信息每项一行）；frpc 运行日志常驻显示并每 15 秒自动刷新（移除查看/隐藏日志按钮）；页面副标题更新"
    ] },
    { version: "v0.6.4.6", items: [
        "转发规则弹窗「域名」布局优化：移除「从证书库选择」标签，将证书域名选择器移至域名输入框同一行并排展示，采用标准表单项等宽布局（5:5），界面更紧凑统一",
        "申请证书弹窗「Acme 账户」「DNS 账户」两列表单高度对齐（等高），底部保持一致",
        "修复导入证书 / 申请证书弹窗点击「取消」后未真正关闭、停留在旧弹窗/旧列表视图的问题：取消现在会同时关闭外层弹窗，不再残留旧视图"
    ] },
    { version: "v0.6.4.5", items: [
        "Webhook 通道分组管理增强：删除分组时弹窗选择目标分组移动通道（仅剩 default 分组时自动移入 default）；创建通道后自动展开对应分组；空分组不再显示；分组列表超 5 个启用滚动条，避免撑开页面",
        "Webhook 接收自动管理：创建通道后自动开启接收；存在通道时接收始终保持开启（设置页移除开关行，后端拒绝关闭请求），避免用户误关导致通道失效",
        "访问密码验证 12 小时免验证：密码验证通过后 12 小时内再次访问同一通道无需重新验证（基于 Cookie 会话令牌），提升高频访问体验",
        "细节改进：密码验证页文案精简；域名模式访问接口地址不再携带端口、统一经 frpc 域名代理；打开密码验证页记录访问日志；系统设置「证书管理」标签精简为 TLS"
    ] },
    { version: "v0.6.4.4", items: [
        "安装/升级时检测并复用上一版本数据，防止新建覆盖：安装与升级预处理检查数据目录（@appdata/TunHook）与配置目录（@appconf/TunHook）是否已有数据，齐全则直接复用，部分缺失只补迁移缺失项，迁移目标已存在则跳过，绝不新建默认数据覆盖已有数据"
    ] },
    { version: "v0.6.4.3", items: [
        "修复卸载「保留数据」只保留数据库、丢失配置与日志的问题：选择「保留数据」时不再删除任何持久目录（数据库/配置/日志全部保留），仅「不保留数据」时才完整清理，并补齐配置目录在环境变量缺失时的标准布局推导"
    ] },
    { version: "v0.6.4.2", items: [
        "修复运行数据/配置被写入应用目录（@appcenter/TunHook）导致升级后被重置的问题：启动脚本与程序在 fnOS 下按标准布局推导 @appdata/@appconf 持久目录，绝不回退到应用目录",
        "安装覆盖与升级共用同一套旧数据全位置迁移逻辑，覆盖安装同样不丢数据；修复卸载「保留数据」时数据库备份/恢复路径（数据库位于 @appdata/db/ 子目录）"
    ] },
    { version: "v0.6.4.1", items: [
        "修复升级后旧数据被覆盖的问题：升级预处理改为从所有候选位置迁移运行数据（db/frp/geoloc/icons/desk-apps/rules 及根级 tunhook.db）与配置（config.yaml/frpc.json/frpc.toml）到 @appdata/@appconf，迁移目标已存在则跳过（不覆盖、幂等），mv 失败自动回退为复制；安装覆盖与升级共用同一套迁移逻辑",
        "修复配置/数据回落应用目录被重置的问题：启动脚本与程序在 fnOS 下按标准布局推导持久目录；启动脚本工作目录改用数据目录变量"
    ] },
    { version: "v0.6.4", items: [
        "IP 过滤（拦截）重构升级：新增白名单/黑名单模式（白名单仅放行名单内地址，黑名单默认拦截名单内地址）、局域网地址放行开关（默认开启，关闭前弹出风险提示）、按归属地（国家/省/市/运营商/公有云）直接加入黑白名单、白名单防误锁保护、本机回环固定放行、默认关闭",
        "本地地址自动替换为本机 IPv4：代理列表「本地地址」与转发列表「转发地址」中的回环/通配地址（127.0.0.1/0.0.0.0/::）自动替换为本地 IPv4，局域网内其他设备可直接访问",
        "界面优化：黑白名单地区条目直接展示、网段条目隐藏明文（悬停查看）超 6 条自动滚动；系统设置子菜单重命名（FRP服务器/自定义UI）并调整排序",
        "修复端口转发页面部分场景空白的问题（列表响应式构建方式调整）"
    ] },
    { version: "v0.6.2.2", items: [
        "修复 frpc 代理「访问认证（HTTP Basic）」不生效：转发通道/Webhook 接收器自动创建或同步 frpc 域名代理时，只更新路由字段并保留手动配置的访问认证（此前会把认证覆盖掉）"
    ] },
    { version: "v0.6.2.1", items: [
        "修复连接统计无法显示：隧道/代理列表「当前连接数」空闲时显示 0（此前显示 —）；连接统计弹窗展示所有活跃转发连接（普通 TCP/UDP 代理无法获取访客 IP 时显示 -）；frpc 进程信息不可读时自动回退为按目标端点统计"
    ] },
    { version: "v0.6.2.0", items: [
        "新增通道导航页（/hook）：集中展示已注册通道（按分组卡片）、转发规则与 frpc 代理（可分别开关）；内置搜索栏（可切换搜索引擎、通道搜索过滤与高亮）、实时时钟、壁纸（API 随机图/图片链接/本地上传）、自定义页脚与内容布局、统计条；支持管理密码登录与自定义 LOGO（PNG/JPG/ICO/SVG）",
        "新增 frpc 增强：QUIC 传输配置、服务器连通性/延迟测试、多服务器管理、代理管理、frpc.toml 原始配置编辑（保存前语法校验）",
        "新增 Webhook 通道分组管理、自定义域名验证与自动建域、成功率统计与每通道访问日志、组件可用性采样",
        "端口扫描新增 Docker 扫描模式与局域网自定义范围（CIDR/单IP/起止IP，支持 IPv6）；隧道/代理列表新增当前连接数与运行状态显示",
        "持续强化 ROOT 版专属能力（桌面图标一键打包安装、Docker端口扫描、服务器连通性测试）"
    ] },
    { version: "v0.6.1.110", items: [
        "仪表盘网络信息增强：将「本地地址」拆分为 IPv4/IPv6 两行分别显示，原生读取网卡信息按优先级筛选（优先全局单播、其次 ULA），过滤回环/链路本地/组播等无效地址",
        "新增公网地址探测与展示：在本地地址下方新增「公网 IPv4」「公网 IPv6」两行分别显示，探测结果后端缓存 10 分钟减少外部请求，探测失败保留旧地址、1 分钟后重试，避免网络抖动清空地址",
        "公网 IPv6 探测增加地址族校验：出站经 NAT64 时回显服务可能误返回 IPv4，检测到期望 IPv6 得到 IPv4 会自动跳过，保证存储的确实是 IPv6",
        "精简行标签：删除所有地址标签中冗余的「地址」二字，仅保留 IPv4/IPv6，界面更简洁"
    ] },
    { version: "v0.6.1.105", items: [
        "修复用户关闭通道后 Webhook 状态被强制改为「同步错误」：「已启动」事件改为隧道真正激活取得公网地址的瞬间触发，隧道停止后不再补发，杜绝滞后事件覆盖用户「已停止」结果"
    ] },
    { version: "v0.6.0", items: [
        "新增 TCP 转发进阶设置：访问限速（KB/s）、单端口最大连接数、PROXY protocol v2、源端 TLS",
        "新增 UDP 转发进阶设置：会话超时、单端口最大会话数、最大块长度",
        "新增每通道日志设置：日志级别、通道日志条数、访问日志条数（0=跟随全局）",
        "新增每通道独立「IP 过滤」开关：创建/编辑穿透通道时可选，默认开启；关闭后该通道跳过 IP 过滤",
        "IP 过滤黑名单升级为「自定义内网IP/网段」并全面生效",
        "稳定性与细节优化"
    ] },
    { version: "v0.5.9", items: [
        "新增 HTTPS 转发：默认端口 14430，未配置证书时自动生成自签名证书",
        "新增 TLS 证书管理：证书库查看/导入/删除、Let's Encrypt 自动申请（HTTP-01 验证经转发链路响应域名）",
        "新增本机直连转发优化、目标网页图标（favicon）抓取",
        "端口占用自动处理（自动选择 50000-60000 空闲端口）"
    ] },
    { version: "v0.5.8", items: [
        "仪表盘全新改版：KPI 概览条、系统/隧道/转发实时速率图、连接状态网格展示",
        "界面与体验优化：响应式布局、键盘焦点可见、尊重系统减少动态效果偏好"
    ] },
    { version: "v0.5.7", items: [
        "端口扫描增强：隧道创建与转发弹窗内置「扫描端口」入口，结果一键填入",
        "IP 过滤重构升级、归属地数据源目录自动提取、桌面图标应用自动打包安装"
    ] },
    { version: "v0.5.0", items: [
        "支持 TCP / UDP / HTTP 端口转发与统一网关转发",
        "集成 frp 内网穿透（frpc 客户端，支持 TCP / UDP / HTTP / HTTPS 代理）"
    ] }
  ];
  let clQuery = '';
  let clScroll;
  let activeVersion = CHANGELOG[0].version;

  $: clFiltered = filterChangelog(CHANGELOG, clQuery);
  $: if (clFiltered.length && !clFiltered.some((v) => v.version === activeVersion)) {
    activeVersion = clFiltered[0].version;
  }

  function filterChangelog(list, query) {
    const q = String(query || '').trim().toLowerCase();
    if (!q) return list;
    const out = [];
    for (const v of list) {
      if (v.version.toLowerCase().includes(q)) { out.push(v); continue; }
      const items = v.items.filter((it) => i18nTr(it).toLowerCase().includes(q));
      if (items.length) out.push({ version: v.version, items });
    }
    return out;
  }

  function highlight(text, query) {
    const q = String(query || '').trim();
    if (!q) return [{ t: text, hit: false }];
    const lower = text.toLowerCase();
    const lq = q.toLowerCase();
    const out = [];
    let i = 0;
    while (i <= text.length) {
      const j = lower.indexOf(lq, i);
      if (j < 0) { if (i < text.length) out.push({ t: text.slice(i), hit: false }); break; }
      if (j > i) out.push({ t: text.slice(i, j), hit: false });
      out.push({ t: text.slice(j, j + q.length), hit: true });
      i = j + q.length;
    }
    return out;
  }

  function jumpToVersion(version) {
    if (!clScroll) return;
    const el = clScroll.querySelector(`[data-version="${CSS.escape(version)}"]`);
    if (!el) return;
    const top = el.getBoundingClientRect().top - clScroll.getBoundingClientRect().top + clScroll.scrollTop;
    clScroll.scrollTo({ top, behavior: 'smooth' });
    activeVersion = version;
  }

  function updateActiveVersion() {
    if (!clScroll) return;
    const st = clScroll.scrollTop;
    const base = clScroll.getBoundingClientRect().top;
    let cur = '';
    for (const n of clScroll.querySelectorAll('[data-version]')) {
      const top = n.getBoundingClientRect().top - base + st;
      if (top <= st + 14) cur = n.dataset.version;
      else break;
    }
    if (cur && cur !== activeVersion) activeVersion = cur;
  }

  // 版本号统一带 v 前缀（服务端返回的版本号可能不含前缀）
  $: appVersion = $status && $status.version
    ? (String($status.version).startsWith('v') ? $status.version : 'v' + $status.version)
    : 'v0.6.6.172';

  onMount(async () => {
    try {
      disclaimer = await api('/api/disclaimer');
    } catch (e) {
      /* 取不到就不展示状态行，不影响页面其余内容 */
    }
  });

  // 免责声明卡片与右侧「开发者信息」卡片等高：以开发者卡片的内容高度为基准，
  // 超出部分在声明正文内滚动（窄屏单列时不锁定高度，保持自然排版）。
  let devCard;
  let pairHeight = 0;

  onMount(() => {
    const mq = window.matchMedia('(max-width: 860px)');
    const update = () => {
      pairHeight = mq.matches || !devCard ? 0 : Math.round(devCard.getBoundingClientRect().height);
    };
    const ro = new ResizeObserver(update);
    if (devCard) ro.observe(devCard);
    mq.addEventListener('change', update);
    update();
    return () => {
      ro.disconnect();
      mq.removeEventListener('change', update);
    };
  });

  // agreed_at 为服务端写入的 RFC3339（含时区偏移）。截取前 19 字符直接展示，
  // 与仪表盘「显示设备本地时间、不受浏览器时区影响」的口径保持一致。
  function fmtAgreedAt(s) {
    return s ? s.slice(0, 19).replace('T', ' ') : '';
  }
</script>

<div class="container">
  <div class="page-hdr">
    <div>
      <h2>{$i18n("关于")}</h2>
      <span class="page-hdr-sub">{$i18n("软件信息 · 更新日志 · 开源声明")}</span>
    </div>
  </div>

  <!-- 软件信息 -->
  <div class="ab-hero">
    <div class="ab-logo">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="19" r="2.5"/><circle cx="18" cy="5" r="2.5"/><path d="M8.5 19h3.5a3 3 0 0 0 3-3V8"/><path d="M15 8H8.5"/></svg>
    </div>
    <div class="ab-hero-main">
      <h2>TunHook <span class="badge badge-info">{appVersion}</span></h2>
      <p>{$i18n("内网穿透 · 端口转发 · 隧道管理 · 一站式自托管控制台")}</p>
    </div>
    <div class="ab-hero-actions">
      <a class="btn btn-sm" href="https://tunhook.top" target="_blank" rel="noopener noreferrer">{$i18n("项目主页")}</a>
    </div>
  </div>

  <div class="ab-grid">
    <!-- 使用免责声明 -->
    <div class="ab-card ab-disclaimer" style={pairHeight ? `height:${pairHeight}px` : ''}>
      <h3><span class="about-dot" style="background:var(--yellow)"></span> {$i18n("使用免责声明")}</h3>
      <div class="ab-notice">{$i18n("请仔细阅读以下条款，使用本软件即视为同意并遵守本声明。")}</div>
      <div class="about-text">
        <p>{$i18n("1. 本软件仅用于合法的网络调试、个人设备远程访问及学习研究等正当用途，禁止用于任何违反中华人民共和国法律法规及当地法律的活动，包括但不限于：未经授权的系统入侵、绕过访问控制、侵犯他人隐私、传播恶意内容等。")}</p>
        <p>{$i18n("2. 用户应对使用本软件产生的全部行为及后果自行承担责任。因使用本软件导致的任何直接或间接损失（包括但不限于数据丢失、服务中断、财产损失、法律纠纷等），开发者不承担任何责任。")}</p>
        <p>{$i18n("3. 本软件按\"现状\"提供，不附带任何明示或暗示的担保。开发者不保证软件的准确性、完整性、稳定性或无差错性，亦不对软件的适用性作任何承诺。")}</p>
        <p>{$i18n("4. 通过本软件对外开放的网络服务，请务必采取必要的安全措施（如强密码、访问控制、及时更新补丁等）。因配置不当导致的任何安全问题由用户自行负责。")}</p>
        <p>{$i18n("5. 本声明可能随软件版本更新而调整，更新后的声明将在\"关于\"页面公布，恕不另行通知。")}</p>
      </div>
      {#if disclaimer && disclaimer.agreed}
        <div class="about-agreed">
          <span class="about-dot" style="background:var(--green)"></span> {$i18n("已同意 ·")} {fmtAgreedAt(disclaimer.agreed_at)}
        </div>
      {/if}
    </div>

    <!-- 软件更新日志 -->
    <div class="ab-card ab-changelog">
      <h3><span class="about-dot" style="background:var(--accent)"></span> {$i18n("软件更新日志")}</h3>
      <div class="ab-changelog-body">
        <aside class="ab-cl-toc">
          <div class="ab-cl-search">
            <input type="search" bind:value={clQuery} placeholder={$i18n("搜索更新日志")} aria-label={$i18n("搜索更新日志")} />
            {#if clQuery}<button type="button" class="ab-cl-clear" on:click={() => (clQuery = '')} aria-label={$i18n("清除")}>&times;</button>{/if}
          </div>
          <div class="ab-cl-versions">
            {#each clFiltered as v (v.version)}
              <button type="button" class:active={activeVersion === v.version} on:click={() => jumpToVersion(v.version)}>{v.version}</button>
            {/each}
            {#if !clFiltered.length}<div class="ab-cl-empty">{$i18n("没有匹配的版本")}</div>{/if}
          </div>
        </aside>
        <div class="about-text ab-scroll" bind:this={clScroll} on:scroll={updateActiveVersion}>
          {#each clFiltered as v (v.version)}
            <div class="ab-cl-entry" data-version={v.version}>
              <p><b>{v.version}</b></p>
              <ol class="about-ol">
                {#each v.items as it}<li>{#each highlight($i18n(it), clQuery) as seg}{#if seg.hit}<mark>{seg.t}</mark>{:else}{seg.t}{/if}{/each}</li>{/each}
              </ol>
            </div>
          {/each}
        </div>
      </div>
    </div>

    <!-- 开发者信息 -->
    <div class="ab-card ab-dev" bind:this={devCard}>
      <h3><span class="about-dot" style="background:var(--green)"></span> {$i18n("开发者信息")}</h3>
      <div class="about-row"><span>{$i18n("软件名称")}</span><span>{$i18n("TunHook（内网穿透客户端）")}</span></div>
      <div class="about-row"><span>{$i18n("当前版本")}</span><span>{appVersion}</span></div>
      <div class="about-row"><span>{$i18n("开发语言")}</span><span>Go 1.25</span></div>
      <div class="about-row"><span>{$i18n("前端技术")}</span><span>Svelte / Vite</span></div>
      <div class="about-row"><span>{$i18n("支持平台")}</span><span>fnOS / Linux / Windows / macOS</span></div>
      <div class="about-row"><span>{$i18n("开发者")}</span><span>YUNXI</span></div>
      <div class="about-row"><span>{$i18n("联系方式")}</span><a class="about-link" href="https://github.com/YUNXI-fi/TunHook" target="_blank" rel="noopener noreferrer">YUNXI</a></div>
      <div class="about-row"><span>{$i18n("开源地址")}</span><a class="about-link" href="https://github.com/YUNXI-fi/TunHook" target="_blank" rel="noopener noreferrer">Github</a></div>
      <button type="button" class="about-row about-row-btn" on:click={() => (showSupport = true)}>
        <span>{$i18n("支持开发者")}</span>
        <span class="about-link">{$i18n("查看赞赏码")}</span>
      </button>
    </div>

    <!-- 使用的开源库 -->
    <div class="ab-card ab-oss">
      <h3><span class="about-dot" style="background:var(--violet)"></span> {$i18n("使用的开源库")}</h3>
      <div style="font-size:12px;color:var(--text3);line-height:1.8;margin-bottom:12px">
        {$i18n("本软件基于以下开源项目构建，全部依赖保持上游官方许可协议，感谢所有作者与开源社区的无私贡献。点击各库条目可展开查看详细说明。")}
      </div>
      <div class="table-wrap" style="margin-bottom:14px">
        <table class="lib-table">
          <thead><tr><th style="width:280px">{$i18n("库名")}</th><th style="width:100px">{$i18n("版本")}</th><th style="width:120px">{$i18n("许可证")}</th><th>{$i18n("用途")}</th></tr></thead>
          <tbody>
            <tr><td class="mono">github.com/spf13/cobra</td><td class="mono">v1.10.2</td><td>Apache-2.0</td><td>{$i18n("命令行框架")}</td></tr>
            <tr><td class="mono">github.com/spf13/viper</td><td class="mono">v1.21.0</td><td>MIT</td><td>{$i18n("配置解析与管理")}</td></tr>
            <tr><td class="mono">go.uber.org/zap</td><td class="mono">v1.28.0</td><td>MIT</td><td>{$i18n("高性能结构化日志")}</td></tr>
            <tr><td class="mono">modernc.org/sqlite</td><td class="mono">v1.55.0</td><td>BSD-3-Clause</td><td>{$i18n("纯 Go 实现的 SQLite 数据库驱动")}</td></tr>
          </tbody>
        </table>
      </div>
      <div style="margin-top:10px;font-size:11px;color:var(--text3);line-height:1.8">
        {$i18n("其余间接依赖：go.yaml.in/yaml/v3、github.com/fsnotify/fsnotify、github.com/google/uuid、github.com/pelletier/go-toml/v2、github.com/spf13/afero、golang.org/x/sync、golang.org/x/sys、golang.org/x/text、modernc.org/libc 等。感谢以上开源项目及其作者的无私贡献。")}
      </div>
    </div>
  </div>
</div>

{#if showSupport}
  <Modal title={$i18n("支持开发者")} onClose={() => (showSupport = false)} width={380}>
    <div class="ab-support">
      <img src={supportQr} alt={$i18n("YUNXI 的赞赏码")} />
      <p>{$i18n("扫码赞赏，感谢你的支持。")}</p>
    </div>
  </Modal>
{/if}

<style>
  /* 软件信息横幅 */
  .ab-hero{position:relative;display:flex;align-items:center;gap:16px;padding:16px 18px;margin-bottom:14px;overflow:hidden;background:var(--bg3);border:1px solid var(--bd);border-radius:calc(var(--radius) + 4px);box-shadow:var(--shadow-card)}
  .ab-hero::after{content:'';position:absolute;inset:0;pointer-events:none;background:radial-gradient(120% 160% at 100% 0%,rgba(var(--accent-rgb),.10),transparent 55%)}
  .ab-logo{position:relative;z-index:1;width:52px;height:52px;flex:none;display:flex;align-items:center;justify-content:center;border-radius:calc(var(--radius) + 4px);border:1px solid rgba(var(--accent-rgb),.3);background:linear-gradient(140deg,rgba(var(--accent-rgb),.18),rgba(var(--accent-2-rgb),.12));color:var(--accent)}
  .ab-hero-main{position:relative;z-index:1;min-width:0}
  .ab-hero-main h2{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:19px;font-weight:700;letter-spacing:-.02em;color:var(--text)}
  .ab-hero-main p{margin-top:4px;font-size:11.5px;color:var(--text3)}
  .ab-hero-actions{position:relative;z-index:1;display:flex;gap:8px;flex:none;margin-left:auto}

  /* 信息卡片 */
  .ab-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px;align-items:start}
  .ab-card{min-width:0;padding:16px 18px;background:var(--bg3);border:1px solid var(--bd);border-radius:calc(var(--radius) + 4px);box-shadow:var(--shadow-card)}
  .ab-card h3{display:flex;align-items:center;gap:8px;margin-bottom:11px;font-size:12.5px;font-weight:600;color:var(--text)}
  .ab-disclaimer{order:1;display:flex;flex-direction:column;min-height:0}
  .ab-disclaimer > h3,.ab-disclaimer > .ab-notice,.ab-disclaimer > .about-agreed{flex:none}
  /* 完全隐藏滚动条，保留滚轮 / 触摸板滚动；滚到边界不带动页面滚动 */
  .ab-disclaimer .about-text{
    flex:1 1 auto;min-height:0;overflow-y:auto;padding-right:4px;
    scrollbar-width:none;overscroll-behavior:contain;
  }
  .ab-disclaimer .about-text::-webkit-scrollbar{display:none}
  .ab-dev{order:2}
  .ab-changelog{order:3;grid-column:1/-1}
  .ab-oss{order:4;grid-column:1/-1}
  .ab-notice{margin-bottom:12px;padding:9px 12px;border:1px solid rgba(var(--yellow-rgb),.3);border-radius:var(--radius);background:rgba(var(--yellow-rgb),.08);color:var(--yellow);font-size:12px;line-height:1.7}
  /* 滚动条隐藏，保留滚轮 / 触摸板滚动 */
  .ab-scroll{max-height:460px;overflow-y:auto;padding-right:4px;scrollbar-width:none}
  .ab-scroll::-webkit-scrollbar{display:none}
  /* 更新日志：左侧版本目录 + 搜索，右侧内容区独立滚动 */
  .ab-changelog-body{display:grid;grid-template-columns:132px minmax(0,1fr);gap:14px;align-items:start}
  .ab-cl-toc{display:flex;flex-direction:column;gap:8px;min-width:0}
  .ab-cl-search{position:relative}
  .ab-cl-search input{width:100%;box-sizing:border-box;padding:6px 24px 6px 9px;font-size:12px;color:var(--text);background:var(--bg2);border:1px solid var(--bd);border-radius:var(--radius)}
  .ab-cl-search input:focus{outline:none;border-color:var(--accent)}
  .ab-cl-search input::-webkit-search-cancel-button{display:none}
  .ab-cl-clear{position:absolute;right:2px;top:50%;transform:translateY(-50%);width:20px;height:20px;border:0;background:none;color:var(--text3);font-size:15px;line-height:1;cursor:pointer}
  .ab-cl-clear:hover{color:var(--text)}
  .ab-cl-versions{display:flex;flex-direction:column;gap:2px;max-height:380px;overflow-y:auto;padding-right:2px;scrollbar-width:none}
  .ab-cl-versions::-webkit-scrollbar{display:none}
  .ab-cl-versions button{width:100%;text-align:left;border:0;background:none;color:var(--text3);font-size:11.5px;font-family:var(--mono);padding:4px 8px;border-radius:calc(var(--radius) - 2px);cursor:pointer}
  .ab-cl-versions button:hover{color:var(--text);background:rgba(128,128,128,.08)}
  .ab-cl-versions button.active{color:var(--accent);background:rgba(var(--accent-rgb),.10);font-weight:600}
  .ab-cl-empty{font-size:11.5px;color:var(--text3);padding:6px 8px}
  .ab-cl-entry + .ab-cl-entry{margin-top:10px}
  .ab-changelog mark{background:rgba(var(--yellow-rgb),.35);color:inherit;border-radius:2px;padding:0 1px}
  .ab-oss .table-wrap{background:var(--bg2);box-shadow:none}
  .lib-table th:last-child,.lib-table td:last-child{text-align:left}
  .ab-dev .about-row{padding:8px 0;font-size:12px}
  .ab-dev .about-row:last-child{border-bottom:none}
  /* 「支持开发者」整行可点击：复位按钮默认样式，保持与其它信息行一致 */
  .about-row-btn{width:100%;background:none;border:0;border-bottom:1px dashed rgba(128,128,128,.2);font:inherit;color:inherit;text-align:left;cursor:pointer}
  .about-row-btn .about-link{color:var(--accent)}
  .about-row-btn:hover .about-link{text-decoration:underline}
  .ab-support{display:flex;flex-direction:column;align-items:center;gap:10px}
  .ab-support img{display:block;width:100%;max-width:320px;border-radius:10px;background:#fff}
  .ab-support p{font-size:12.5px;color:var(--text3);text-align:center;line-height:1.7}

  @media (max-width:860px){
    .ab-grid{grid-template-columns:1fr}
    .ab-changelog,.ab-oss{grid-column:auto}
    .ab-changelog-body{grid-template-columns:1fr}
    .ab-cl-versions{flex-direction:row;flex-wrap:wrap;max-height:88px}
    .ab-cl-versions button{width:auto}
  }
  @media (max-width:600px){
    .ab-hero{align-items:flex-start;flex-wrap:wrap;padding:14px}
    .ab-hero-main h2{font-size:17px}
    .ab-hero-actions{width:100%;margin-left:0}
    .ab-hero-actions .btn{flex:1}
    .ab-card{padding:14px}
    .ab-scroll{max-height:360px}
  }
</style>
