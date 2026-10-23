// 全局 Svelte stores：应用状态共享

import { writable } from 'svelte/store';
import { makePalette } from './utils.js';

// 当前激活标签页
export const activeTab = writable('dashboard');

// ---- 模块管理（系统设置 → 模块管理）----
// 可关闭的功能模块清单：id 需与后端 web.allowDisableModules 白名单一致（后端一并返回 allow 便于核对）。
// label 与侧边栏导航文案保持一致，顺序也与 App.svelte 的 tabs 逐一对应（导航渲染仍在 tabs 中定义）。
export const MODULES = [
  { id: 'tunnel', label: 'FRPC', desc: 'FRP 内网穿透（自建或第三方 frps 服务器）' },
  { id: 'stun', label: 'STUN', desc: 'NAT 类型探测与 UDP 端口映射暴露' },
  { id: 'mefrp', label: 'MEFrp', desc: 'ME Frp 幻缘映射 · 云端隧道' },
  { id: 'lolia', label: 'LoliaFrp', desc: 'LoliaFrp · 云端隧道（流量/KYC/节点负载）' },
  { id: 'webhook', label: 'Webhook', desc: '公网地址上报与通道导航入口' },
  { id: 'cloudflare', label: 'Cloudflare Tunnel', desc: 'Cloudflare Tunnel 接入（HTTPS 域名入口）' },
  { id: 'dns', label: '域名解析', desc: 'DNS 账户与解析记录 · 动态解析 · TLS 证书申请与自动续签' },
  { id: 'forward', label: '端口转发', desc: '本机 TCP / UDP / HTTP 端口转发与统一网关' },
  { id: 'portscan', label: '端口扫描', desc: '本机与网段端口扫描' },
  { id: 'wol', label: '网络唤醒', desc: 'Wake-on-LAN · 局域网设备一键唤醒' },
  { id: 'waf', label: 'WAF 防火墙', desc: 'HTTP 流量检测 · 内置规则与自定义规则' },
  { id: 'webserver', label: 'Web 服务', desc: '本地静态站点托管 · 目录浏览与基础认证' }
];

// 常驻模块：不提供关闭开关。仪表盘与系统设置必须常驻——模块管理在系统设置内，关掉便无法再开启。
export const FIXED_MODULES = [
  { id: 'dashboard', label: '仪表盘', desc: '运行总览' },
  { id: 'settings', label: '系统设置', desc: '含本页，必须常驻' },
  { id: 'logs', label: '系统日志', desc: '全局日志查看' },
  { id: 'about', label: '关于', desc: '软件信息与更新日志' }
];

// 已关闭的模块 id 列表（GET /api/modules）
export const disabledModules = writable([]);

// 仪表盘布局（KPI 概览与卡片的顺序与显隐）：{ kpis: [{id, visible}], cards: [{id, visible}] }
// 由 GET /api/dashboard/layout 加载、编辑后 POST 回服务端（跨浏览器/设备一致）
export const dashLayout = writable({ kpis: [], cards: [] });

// 系统设置页的子分区清单（唯一来源）：侧栏子菜单与页头副标题都由它生成，
// 避免两处各写一份而随增删/拖拽走样
const sIcon = (body) => '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + body + '</svg>';
export const settingsTabs = [
  { id: 'default', label: '默认参数', desc: '默认端口与基础运行参数', icon: sIcon('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>') },
  { id: 'stun', label: 'STUN设置', desc: 'STUN 探测与 UDP 打洞参数', icon: sIcon('<circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/>') },
  { id: 'frpc', label: 'FRP服务器', desc: 'FRP 服务器与运行配置', icon: sIcon('<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>') },
  { id: 'ipfilter', label: 'IP地址库', desc: 'IP 地址库数据源与更新', icon: sIcon('<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>') },
  { id: 'ipdb', label: 'IP过滤', desc: 'IP 过滤规则与黑白名单', icon: sIcon('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>') },
  { id: 'ui', label: '自定义UI', desc: '主题配色与界面自定义', icon: sIcon('<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>') },
  { id: 'modules', label: '模块管理', desc: '功能模块启用与关闭', icon: sIcon('<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>') },
  { id: 'errorpage', label: '错误页面', desc: '自定义错误页面模板', icon: sIcon('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8"/><path d="M8 17h8"/>') },
  { id: 'backup', label: '备份恢复', desc: '配置备份与恢复', icon: sIcon('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>') }
];

// 系统设置页当前子分区（取值见上面的 settingsTabs）
export const settingsSect = writable('default');

// TLS 证书管理面板初始视图（供「域名解析 → DNS 账号」跳转直达 DNS 账户列表）
export const certInitialView = writable('list');

// 全局设置（GET /api/settings）
export const settings = writable(null);

// 系统状态（GET /api/status）
export const status = writable(null);

// 系统资源统计（GET /api/system/stats）
export const sysStats = writable(null);

// 系统实时速率（GET /api/system/net，单位 B/s）
export const netRate = writable({ rx: 0, tx: 0 });

// 转发规则列表
export const forwards = writable([]);

// 跨页预填：端口扫描页「创建转发规则」→ 转发页自动打开创建弹窗
export const forwardPrefill = writable(null);

// 跨页预填：端口扫描页「创建穿透隧道」→ 内网穿透页自动打开创建弹窗
export const tunnelPrefill = writable(null);

// 主题
export const theme = writable(localStorage.getItem('tunhook-theme') || 'dark');

// 主题/配色版本号：每次主题切换或界面配色改动后自增。
// 存在的理由：CSS 变量能让 DOM 自动换肤，但 canvas 是命令式绘制、读不到 CSS 变量，
// 改变量后必须靠 JS 主动重绘才会更新配色。此前图表只在「新数据到达 / 尺寸变化 / 鼠标移动」时重绘，
// 于是切主题后画布要等下一个采样点才变色（网络空闲时可能长期不变）——这就是「慢半拍」。
// 用一个共享版本号让所有 canvas 订阅，比每个组件各自监听 DOM 属性更可靠，也避免三份重复逻辑。
export const themeVersion = writable(0);
export function bumpThemeVersion() {
  themeVersion.update((v) => v + 1);
}

// ---- 界面自定义（系统UI设置，localStorage 持久化） ----
// 配色预设：六套主色与演示页一致，主色只影响高亮/按钮/图表，页面背景由 applyUI 使用固定中性色阶。
// 每套主色在下方 ACCENT_SECONDARY 中自动搭配辅助色；key 保持不变，兼容老用户 localStorage。
export const ACCENTS = {
  // 新版配色：与演示页一致，主色只影响高亮与图表，页面背景使用中性色阶。
  cyan:   makePalette('#4dd6ff', '冰蓝',   { accentD: '#4dd6ff', accentL: '#0b7a99', bgBase: '#081a18' }),
  blue:   makePalette('#6aa8ff', '蔚蓝',   { accentD: '#6aa8ff', accentL: '#2563eb', bgBase: '#1e293b' }),
  purple: makePalette('#a78bfa', '紫罗兰', { accentD: '#a78bfa', accentL: '#6d4fd4', bgBase: '#170b2a' }),
  green:  makePalette('#3ddc97', '薄荷',   { accentD: '#3ddc97', accentL: '#12855a', bgBase: '#216e39' }),
  orange: makePalette('#f5b544', '琥珀',   { accentD: '#f5b544', accentL: '#a86205', bgBase: '#1a1811' }),
  rose:   makePalette('#ff7f8e', '珊瑚',   { accentD: '#ff7f8e', accentL: '#c0394f', bgBase: '#2a0f1e' })
};
// 辅助色：每套主色自动搭配一个协调的第二色，用于图表第二数据系列、渐变与次级强调。
// 与主色分开维护而不是由主色旋转色相推导，避免自动生成出与语义色（在线绿/警告黄/错误红）撞色的组合。
const ACCENT_SECONDARY = {
  cyan:   { secName: '紫罗兰', secDark: '#a78bfa', secLight: '#6d4fd4', secRgb: '167,139,250', secRgbL: '109,79,212' },
  blue:   { secName: '紫罗兰', secDark: '#a78bfa', secLight: '#6d4fd4', secRgb: '167,139,250', secRgbL: '109,79,212' },
  purple: { secName: '冰蓝',   secDark: '#4dd6ff', secLight: '#0b7a99', secRgb: '77,214,255',  secRgbL: '11,122,153' },
  green:  { secName: '冰蓝',   secDark: '#4dd6ff', secLight: '#0b7a99', secRgb: '77,214,255',  secRgbL: '11,122,153' },
  orange: { secName: '紫罗兰', secDark: '#a78bfa', secLight: '#6d4fd4', secRgb: '167,139,250', secRgbL: '109,79,212' },
  rose:   { secName: '冰蓝',   secDark: '#4dd6ff', secLight: '#0b7a99', secRgb: '77,214,255',  secRgbL: '11,122,153' }
};
Object.entries(ACCENT_SECONDARY).forEach(([key, sec]) => {
  if (ACCENTS[key]) Object.assign(ACCENTS[key], sec);
});
// 默认界面配置：缩放% / 配色 / 自定义基础色 / 圆角px / 背景类型 / 背景色 / 背景图 / 面板透明度% / 背景模糊px
export const UI_DEFAULTS = {
  scale: 100, accent: 'cyan', customColor: '#4dd6ff', radius: 8,
  bgType: 'default', bgColor: '#070c12', bgImage: '',
  opacity: 80, blur: 12
};
function loadUI() {
  try {
    const raw = localStorage.getItem('tunhook-ui');
    if (raw) return Object.assign({}, UI_DEFAULTS, JSON.parse(raw));
  } catch (e) { /* 忽略损坏数据 */ }
  return Object.assign({}, UI_DEFAULTS);
}
export const uiCfg = writable(loadUI());
// 持久化（图片 dataURL 过大时忽略保存，不影响内存中的实时效果）
uiCfg.subscribe((v) => {
  try {
    localStorage.setItem('tunhook-ui', JSON.stringify(v));
  } catch (e) { /* 超出 localStorage 配额时跳过 */ }
});

// 全局 Toast 消息队列
export const toasts = writable([]);

let toastId = 0;
export function toast(msg, type = 'info') {
  const id = ++toastId;
  toasts.update((l) => [...l.slice(-4), { id, msg, type }]);
  setTimeout(() => {
    toasts.update((l) => l.filter((t) => t.id !== id));
  }, 3500);
}

// 页面加载中状态
export const pageLoading = writable(false);
