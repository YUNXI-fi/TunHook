<script>
  import { onMount } from 'svelte';
  import { activeTab, settingsSect, status, theme, toasts, ACCENTS, uiCfg, disabledModules, bumpThemeVersion, toast } from './lib/stores.js';
  import { t as i18n, tr as i18nTr, locale, LOCALES } from './lib/i18n.js';
  import { makePalette, pollVisible } from './lib/utils.js';
  import { apiBase, api } from './lib/api.js';
  import CustomSelect from './components/CustomSelect.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Tunnels from './pages/Tunnels.svelte';
  import Forwards from './pages/Forwards.svelte';
  import Mefrp from './pages/Mefrp.svelte';
  import Lolia from './pages/Lolia.svelte';
  import Cloudflare from './pages/Cloudflare.svelte';
  import PortScan from './pages/PortScan.svelte';
  import Wol from './pages/Wol.svelte';
  import Waf from './pages/Waf.svelte';
  import WebServer from './pages/WebServer.svelte';
  import Webhook from './pages/Webhook.svelte';
  import DnsPanel from './components/DnsPanel.svelte';
  import Settings from './pages/Settings.svelte';
  import Logs from './pages/Logs.svelte';
  import About from './pages/About.svelte';
  import Stun from './pages/Stun.svelte';
  import DisclaimerModal from './components/DisclaimerModal.svelte';

  const tabs = [
    { id: 'dashboard', label: i18nTr("仪表盘"), icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>' },
    { id: 'tunnel', label: 'FRPC', icon: '<svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><path d="M24 36V30"/><path d="M20 40H6"/><path d="M28 40H42"/><path d="M28 40C28 42.2091 26.2091 44 24 44C21.7909 44 20 42.2091 20 40C20 37.7909 21.7909 36 24 36C26.2091 36 28 37.7909 28 40Z" fill="none"/><path d="M37 17C37 24.1797 31.1797 30 24 30C16.8203 30 11 24.1797 11 17M37 17C37 9.8203 31.1797 4 24 4C16.8203 4 11 9.8203 11 17M37 17H11"/><path d="M29 17C29 24.1797 26.7614 30 24 30C21.2386 30 19 24.1797 19 17C19 9.8203 21.2386 4 24 4C26.7614 4 29 9.8203 29 17Z" fill="none"/><path d="M37 17H11"/></svg>' },
    { id: 'stun', label: 'STUN', icon: '<svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="34" width="8" height="8" fill="none" stroke="currentColor" stroke-width="4"/><rect x="8" y="6" width="32" height="12" fill="none" stroke="currentColor" stroke-width="4"/><path d="M24 34V18" fill="none" stroke="currentColor" stroke-width="4"/><path d="M8 34V26H40V34" fill="none" stroke="currentColor" stroke-width="4"/><rect x="36" y="34" width="8" height="8" fill="none" stroke="currentColor" stroke-width="4"/><rect x="20" y="34" width="8" height="8" fill="none" stroke="currentColor" stroke-width="4"/><path d="M14 12H16" fill="none" stroke="currentColor" stroke-width="4"/></svg>' },
    { id: 'mefrp', label: 'MEFrp', icon: '<svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg" style="vertical-align:-2px"><g transform="rotate(45 24 24)"><path d="M24.489 8.3975C24.2457 8.35865 24.2742 8 24.5205 8H39.5C39.7761 8 40 8.22386 40 8.5V23.4795C40 23.7258 39.6414 23.7543 39.6025 23.511L37.6355 11.1943C37.5673 10.7674 37.2326 10.4327 36.8057 10.3645L24.489 8.3975Z"/><path d="M6.489 26.3975C6.24574 26.3586 6.2742 26 6.52054 26H21.5C21.7761 26 22 26.2239 22 26.5V41.4795C22 41.7258 21.6414 41.7543 21.6025 41.511L19.6355 29.1943C19.5673 28.7674 19.2326 28.4327 18.8057 28.3645L6.489 26.3975Z"/><path d="M15.489 17.3975C15.2457 17.3586 15.2742 17 15.5205 17H30.5C30.7761 17 31 17.2239 31 17.5V32.4795C31 32.7258 30.6414 32.7543 30.6025 32.511L28.7498 20.9098C28.6134 20.0561 27.9439 19.3866 27.0902 19.2502L15.489 17.3975Z"/></g></svg>' },
    { id: 'lolia', label: 'LoliaFrp', icon: '<svg width="16" height="16" viewBox="0 0 62.57 62.57" fill="currentColor"><path d="M36.84,31.63l11.74-11.73c1.13.46,2.36.72,3.66.72,5.32,0,9.63-4.31,9.63-9.63S57.55,1.36,52.24,1.36s-9.63,4.31-9.63,9.63c0,1.3.26,2.55.73,3.68l-11.72,11.72L13.99,8.76h10.69c2.04,0,3.7-1.66,3.7-3.7s-1.66-3.7-3.7-3.7H5.08c-1.28,0-2.4.65-3.07,1.63-.4.59-.63,1.3-.63,2.07h0v19.6c0,2.04,1.66,3.7,3.7,3.7s3.7-1.66,3.7-3.7v-10.65l17.61,17.61-11.02,11.02c-1.22-.53-2.56-.82-3.98-.82-5.53,0-10.01,4.48-10.01,10.01s4.48,10.01,10.01,10.01,10.01-4.48,10.01-10.01c0-1.4-.29-2.74-.81-3.95l11.02-11.02,23.09,23.09c1.45,1.45,3.79,1.45,5.23,0,1.45-1.45,1.45-3.79,0-5.23l-23.09-23.09h0Z"/></svg>' },
    { id: 'webhook', label: 'Webhook', icon: '<svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><path d="M37 44C39.2091 44 41 42.2091 41 40C41 37.7909 39.2091 36 37 36C34.7909 36 33 37.7909 33 40C33 42.2091 34.7909 44 37 44Z" fill="none"/><path d="M11 12C13.2091 12 15 10.2091 15 8C15 5.79086 13.2091 4 11 4C8.79086 4 7 5.79086 7 8C7 10.2091 8.79086 12 11 12Z" fill="none"/><path d="M11 44C13.2091 44 15 42.2091 15 40C15 37.7909 13.2091 36 11 36C8.79086 36 7 37.7909 7 40C7 42.2091 8.79086 44 11 44Z" fill="none"/><path d="M11 12V36"/><path d="M24 10H33C35.2091 10 37 11.7909 37 14V36"/><path d="M30 16L24 10L30 4"/></svg>' },
    { id: 'cloudflare', label: 'Cloudflare Tunnel', icon: '<svg width="16" height="16" viewBox="0 0 128 128" fill="currentColor"><path d="M87.295 89.022c.763-2.617.472-5.015-.8-6.796c-1.163-1.635-3.125-2.58-5.488-2.689l-44.737-.581c-.291 0-.545-.145-.691-.363s-.182-.509-.109-.8c.145-.436.581-.763 1.054-.8l45.137-.581c5.342-.254 11.157-4.579 13.192-9.885l2.58-6.723c.109-.291.145-.581.073-.872c-2.906-13.158-14.644-22.97-28.672-22.97c-12.938 0-23.913 8.359-27.838 19.952a13.35 13.35 0 0 0-9.267-2.58c-6.215.618-11.193 5.597-11.811 11.811c-.145 1.599-.036 3.162.327 4.615C10.104 70.051 2 78.337 2 88.549c0 .909.073 1.817.182 2.726a.895.895 0 0 0 .872.763h82.57c.472 0 .909-.327 1.054-.8zm14.247-28.747c-.4 0-.836 0-1.236.036c-.291 0-.545.218-.654.509l-1.744 6.069c-.763 2.617-.472 5.015.8 6.796c1.163 1.635 3.125 2.58 5.488 2.689l9.522.581c.291 0 .545.145.691.363s.182.545.109.8c-.145.436-.581.763-1.054.8l-9.924.582c-5.379.254-11.157 4.579-13.192 9.885l-.727 1.853c-.145.363.109.727.509.727h34.089c.4 0 .763-.254.872-.654c.581-2.108.909-4.325.909-6.614c0-13.447-10.975-24.422-24.458-24.422"></path></svg>' },
    { id: 'forward', label: i18nTr("端口转发"), icon: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"><path fill="currentColor" d="M18.21 9.21C15.93 10.78 13.45 13.3 13 17h2v2H9v-2h2c-.5-4.5-4.37-8-9-8V7c4.39 0 8.22 2.55 10 6.3c1.13-2.43 2.99-4.25 4.78-5.52L14 5h7v7z"></path></svg>' },
    { id: 'dns', label: i18nTr("域名解析"), icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>' },
    { id: 'portscan', label: i18nTr("端口扫描"), icon: '<svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 24L43 24"/><path d="M28 4H20C18.8954 4 18 4.89543 18 6V14C18 15.1046 18.8954 16 20 16H28C29.1046 16 30 15.1046 30 14V6C30 4.89543 29.1046 4 28 4Z" fill="none"/><path d="M16 32H8C6.89543 32 6 32.8954 6 34V42C6 43.1046 6.89543 44 8 44H16C17.1046 44 18 43.1046 18 42V34C18 32.8954 17.1046 32 16 32Z" fill="none"/><path d="M40 32H32C30.8954 32 30 32.8954 30 34V42C30 43.1046 30.8954 44 32 44H40C41.1046 44 42 43.1046 42 42V34C42 32.8954 41.1046 32 40 32Z" fill="none"/><path d="M24 24V16"/><path d="M36 32V24"/><path d="M12 32V24"/></svg>' },
    { id: 'wol', label: i18nTr("网络唤醒"), icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>' },
    { id: 'waf', label: i18nTr("WAF 防火墙"), icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>' },
    { id: 'webserver', label: i18nTr("Web 服务"), icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="4" width="19" height="16" rx="2"/><path d="M2.5 9h19"/><path d="M5.5 6.5h.01"/><path d="M7.8 6.5h.01"/></svg>' },
    { id: 'settings', label: i18nTr("系统设置"), icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>' },
    { id: 'logs', label: i18nTr("系统日志"), icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8"/><path d="M8 17h8"/></svg>' },
    { id: 'about', label: i18nTr("关于"), icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>' }
  ];

  // 首次使用强制免责声明：同意状态以服务端数据库为准（全局共享，与设备/浏览器无关），
  // 任何设备同意一次后不再弹出。初始为 false，接口确认「未同意」后才展示，
  // 避免已同意设备页面加载瞬间闪现弹窗。
  let showDisclaimer = false;

  // 已关闭的模块不出现在导航中（在「系统设置 → 模块管理」里开关）
  $: visibleTabs = tabs.filter((t) => !$disabledModules.includes(t.id));
  // 直接访问已被关闭的模块（如手工改地址）时不渲染该页，改为提示入口已关闭
  $: closedTab = $disabledModules.includes($activeTab);

  // 导航分类：分组值使用 i18n key，渲染时通过 $i18n() 翻译
  const TAB_GROUPS = {
    tunnel: 'group.tunnel',
    stun: 'group.tunnel',
    mefrp: 'group.tunnel',
    lolia: 'group.tunnel',
    webhook: 'group.tunnel',
    cloudflare: 'group.tunnel',
    portscan: 'group.network',
    wol: 'group.network',
    forward: 'group.network',
    waf: 'group.network',
    webserver: 'group.network',
    dns: 'group.network',
    logs: 'group.system',
    settings: 'group.system',
    about: 'group.system'
  };
  const GROUP_ORDER = ['group.tunnel', 'group.network', 'group.system'];
  const TAB_ORDER = {
    'group.tunnel': ['tunnel', 'stun', 'mefrp', 'lolia', 'webhook', 'cloudflare'],
    'group.network': ['forward', 'portscan', 'dns', 'wol', 'webserver', 'waf'],
    'group.system': ['logs', 'settings', 'about']
  };
  function sortByTabOrder(list, order) {
    const rank = (t) => {
      const i = order.indexOf(t.id);
      return i < 0 ? Number.MAX_SAFE_INTEGER : i;
    };
    return [...list].sort((a, b) => rank(a) - rank(b));
  }
  $: tabGroups = [
    { label: '', tabs: visibleTabs.filter((t) => !TAB_GROUPS[t.id]) },
    ...GROUP_ORDER.map((g) => ({
      label: g,
      tabs: sortByTabOrder(visibleTabs.filter((t) => TAB_GROUPS[t.id] === g), TAB_ORDER[g])
    }))
  ].filter((g) => g.tabs.length);

  // 移动端底部导航 / 更多面板 / 桌面端快速跳转
  let moreOpen = false;
  let searchOpen = false;
  let searchQuery = '';
  const MOBILE_MAIN = ['dashboard', 'tunnel', 'forward', 'logs'];
  const MOBILE_LABEL = { tunnel: 'mobile.tunnel', forward: 'mobile.forward', logs: 'mobile.logs' };
  const moreIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="5" cy="12" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="19" cy="12" r="1.5"/></svg>';
  $: currentTab = tabs.find((t) => t.id === $activeTab) || tabs[0];
  $: mobileMain = MOBILE_MAIN.map((id) => visibleTabs.find((t) => t.id === id)).filter(Boolean);
  $: moreTabs = visibleTabs.filter((t) => !MOBILE_MAIN.includes(t.id));
  $: searchResults = visibleTabs
    .filter((tab) => !searchQuery.trim() || $i18n('nav.' + tab.id).toLowerCase().includes(searchQuery.trim().toLowerCase()))
    .slice(0, 8);
  $: moreActive = moreOpen || !MOBILE_MAIN.includes($activeTab);
  function goTab(id) {
    activeTab.set(id);
    moreOpen = false;
    searchOpen = false;
    searchQuery = '';
  }

  // 同意免责声明：确认时间由服务端落库，成功后才关闭弹窗；
  // 请求失败时保持弹窗可再次点击，避免漏掉同意记录
  async function agreeDisclaimer() {
    try {
      await api('/api/disclaimer/agree', { method: 'POST' });
      showDisclaimer = false;
    } catch (e) {
      toast(i18nTr("确认失败：") + e.message, 'error');
    }
  }

  // 主题应用
  $: {
    const t = $theme;
    document.documentElement.setAttribute('data-theme', t);
    localStorage.setItem('tunhook-theme', t);
  }

  // 界面自定义应用：缩放 / 配色 / 圆角 / 自定义背景（透明度 + 模糊）
  // 注意：Svelte 响应式语句只追踪语句内“显式出现”的依赖，
  // 因此必须把 $uiCfg / $theme 作为实参传入，函数内部读取不会触发重新执行。
  function applyUI(cfg, t) {
    const root = document.documentElement;
    // 自定义基础色：实时由 makePalette 生成整套配色（参考 tusij.com 在线配色）
    const a = cfg.accent === 'custom'
      ? makePalette(cfg.customColor || '#06b6d4')
      : (ACCENTS[cfg.accent] || ACCENTS.cyan);
    const isL = t === 'light';
    // 辅助色：预设配色自带搭配；自定义基础色暂时回退到紫罗兰，保证图表第二系列始终有协调色。
    const sec = a.secDark
      ? a
      : { secDark: '#a78bfa', secLight: '#6d4fd4', secRgb: '167,139,250', secRgbL: '109,79,212' };
    root.style.setProperty('--accent', isL ? a.light : a.dark);
    root.style.setProperty('--accent-rgb', isL ? a.rgbL : a.rgb);
    // 淡底透明度两套主题统一取 0.08。深色原为 0.12，实测会让「强调色文字压自身淡底」的场景
    // （.badge-info / .sidebar-item.active）对比跌到 4.25~4.26，低于 4.5；
    // 淡底更贴近纯面后对比回到 4.5 以上，两套主题也不必各写一个值。
    root.style.setProperty('--accent-glow', `rgba(${isL ? a.rgbL : a.rgb},0.08)`);
    root.style.setProperty('--accent-2', isL ? sec.secLight : sec.secDark);
    root.style.setProperty('--accent-2-rgb', isL ? sec.secRgbL : sec.secRgb);
    root.style.setProperty('--accent-2-glow', `rgba(${isL ? sec.secRgbL : sec.secRgb},0.08)`);
    // 悬停色随主题取不同档，但两套都是「从实心底色再深一档」的实色（见 makePalette 注释）
    root.style.setProperty('--accent-hover', isL ? a.hoverL : a.hoverD);
    // 实心底色：实心按钮 / 激活胶囊 / 开关滑块配白字专用。
    // 与文字色 --accent 分离是因为两者数学上冲突——深底文字要够亮、配白字的实心底要够暗，
    // 同一个色值无法兼顾（改预设前默认青的白字按钮实测仅 1.59:1）。
    root.style.setProperty('--accent-solid', isL ? a.solidL : a.solid);
    // 中性背景与强调色解耦：主色只影响高亮、按钮与图表，页面/卡片/输入框使用固定中性色阶。
    // 这样六套配色切换时不会整页换底色，层次更稳定；强调色文字仍由 makePalette 按对比度推导。
    const n = isL
      ? { bg: '#f4f7fa', bg2: '#ffffff', bg3: '#ffffff', bg4: '#f1f5f9', bd: '#e1e8f0', text2: '#4c6078', text3: '#5f738a', sep: '#eef2f7', tipBg: '#ffffff', tipBd: '#e1e8f0', toastBg: '#ffffff', bdStrong: '#7d93a9' }
      : { bg: '#070c12', bg2: '#0a1119', bg3: '#0d151f', bg4: '#111b27', bd: '#1e2c3a', text2: '#a3b4c8', text3: '#8094ab', sep: '#16222f', tipBg: '#111b27', tipBd: '#1e2c3a', toastBg: '#111b27', bdStrong: '#4a6075' };
    root.style.setProperty('--bg', n.bg);
    root.style.setProperty('--bg2', n.bg2);
    root.style.setProperty('--bg3', n.bg3);
    root.style.setProperty('--bg4', n.bg4);
    root.style.setProperty('--bd', n.bd);
    root.style.setProperty('--text2', n.text2);
    root.style.setProperty('--text3', n.text3);
    root.style.setProperty('--sep', n.sep);
    root.style.setProperty('--tip-bg', n.tipBg);
    root.style.setProperty('--tip-bd', n.tipBd);
    root.style.setProperty('--toast-bg', n.toastBg);
    // 控件边界（输入框/下拉框/开关）与装饰性边框分开：前者受 WCAG 1.4.11 约束，需对相邻面 ≥3:1
    root.style.setProperty('--bd-strong', n.bdStrong);
    root.style.setProperty('--radius', cfg.radius + 'px');
    root.style.setProperty('--ui-alpha', (cfg.opacity / 100).toFixed(2));
    root.style.setProperty('--ui-blur', cfg.blur + 'px');
    // 界面缩放：zoom 缩放渲染，--ui-scale 用于补偿 vh/fixed，保证侧边栏等全屏元素始终填满视口
    const s = cfg.scale / 100;
    root.style.setProperty('--ui-scale', String(s));
    document.documentElement.style.zoom = String(s);
    // 自定义背景
    if (cfg.bgType === 'image' && cfg.bgImage) {
      root.classList.add('ui-custom-bg');
      root.style.setProperty('--ui-bg-img', `url("${cfg.bgImage}")`);
      root.style.removeProperty('--ui-bg-color');
    } else if (cfg.bgType === 'color') {
      root.classList.add('ui-custom-bg');
      root.style.setProperty('--ui-bg-color', cfg.bgColor);
      root.style.removeProperty('--ui-bg-img');
    } else {
      root.classList.remove('ui-custom-bg');
      root.style.removeProperty('--ui-bg-img');
      root.style.removeProperty('--ui-bg-color');
    }
    // 通知 canvas 重绘：CSS 变量改写后 DOM 会自动换肤，但画布是命令式绘制、读不到变量，
    // 必须由 JS 主动重绘才会跟着变色。放在 applyUI 末尾——主题切换与配色风格改动都会走这里，
    // 两条路径共用一次自增，不用在主题块里再记一笔。
    bumpThemeVersion();
  }
  $: applyUI($uiCfg, $theme);

  // 主题切换：新主题以圆形从点击处扩散揭开（View Transitions）。
  // 为什么用原生 API 而不是手写一个放大遮罩：这个效果需要呈现「旧主题画面 → 新主题画面」的过渡，
  // 手写遮罩只能盖住已经切完的界面（底下已是新主题），起不到「揭开」的作用；
  // View Transitions 由浏览器对切换前后各截一帧，圆形扩散只是在这两帧之间做揭露。
  function toggleTheme(e) {
    const flip = () => theme.update((t) => (t === 'dark' ? 'light' : 'dark'));
    // 动画走 Web Animations API，不受 app.css 里那条 prefers-reduced-motion
    //「animation-duration:.01ms」的影响（那条只覆盖 CSS 动画），故这里单独判断一次
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce || !document.startViewTransition) { flip(); return; }
    // 圆心取点击处而不是按钮的 rect：界面缩放（zoom）下 getBoundingClientRect 的返回值
    // 与视口坐标不同源，而 clientX/clientY 始终是视口 CSS 像素，与 mask 渐变的坐标系一致
    const x = e.clientX, y = e.clientY;
    // 半径取到视口最远角的距离，这是「覆盖全屏所需的最小半径」，不要乘系数收小：
    // 一旦小于它，距最远角最后一段的角部区域就不会被新主题覆盖（mask 在那里已完全透明），
    // 动画收尾时会露出旧主题、并在伪元素移除的瞬间跳成新主题。
    // 对角若想收得快，该调的是时间分配（缓动曲线），不是半径。
    const r = Math.hypot(Math.max(x, window.innerWidth - x), Math.max(y, window.innerHeight - y));
    const root = document.documentElement;
    // 圆心写给伪元素用（app.css 里 ::view-transition-new(root) 的径向渐变要拿它做渐变中心）
    root.style.setProperty('--vt-x', `${x}px`);
    root.style.setProperty('--vt-y', `${y}px`);
    // 快照是在切换动作之后立刻截取的，必须先关掉元素自身的过渡：
    // body 上有 background/color 的 .3s 过渡，否则新快照会定格在「旧底色 + 新文字」的渐变中途
    root.classList.add('vt-no-transition');
    const vt = document.startViewTransition(flip);
    const target = { pseudoElement: '::view-transition-new(root)', fill: 'forwards' };
    vt.ready.then(() => {
      // 半径从 0 扩到视口最远角。
      // 缓动用 Material 标准曲线：同样是「先快后慢」，但它的收尾比 easeOutQuint 短得多——
      // 实测最后 10% 半径的耗时从 351ms 降到 205ms。旧曲线 63% 的时间都耗在收尾那一小段上，
      // 而半径锚的又是视口最远角，于是「变慢」恰好出现在最显眼的对角。
      root.animate(
        { '--vt-r': ['0px', `${r}px`] },
        { ...target, duration: 560, easing: 'cubic-bezier(.4,0,.2,1)' }
      );
    }).catch(() => { /* 过渡被跳过（如连续快速点击）时 ready 会 reject，忽略即可 */ });
    vt.finished.finally(() => root.classList.remove('vt-no-transition'));
  }

  // 主题切换图标：浅色主题显示太阳、深色主题显示月亮（跟随当前主题状态）
  const moonIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  const sunIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="m5.64 17l-.71.71a1 1 0 0 0 0 1.41a1 1 0 0 0 1.41 0l.71-.71A1 1 0 0 0 5.64 17M5 12a1 1 0 0 0-1-1H3a1 1 0 0 0 0 2h1a1 1 0 0 0 1-1m7-7a1 1 0 0 0 1-1V3a1 1 0 0 0-2 0v1a1 1 0 0 0 1 1M5.64 7.05a1 1 0 0 0 .7.29a1 1 0 0 0 .71-.29a1 1 0 0 0 0-1.41l-.71-.71a1 1 0 0 0-1.41 1.41Zm12 .29a1 1 0 0 0 .7-.29l.71-.71a1 1 0 1 0-1.41-1.41l-.64.71a1 1 0 0 0 0 1.41a1 1 0 0 0 .66.29ZM21 11h-1a1 1 0 0 0 0 2h1a1 1 0 0 0 0-2m-9 8a1 1 0 0 0-1 1v1a1 1 0 0 0 2 0v-1a1 1 0 0 0-1-1m6.36-2A1 1 0 0 0 17 18.36l.71.71a1 1 0 0 0 1.41 0a1 1 0 0 0 0-1.41ZM12 6.5a5.5 5.5 0 1 0 5.5 5.5A5.51 5.51 0 0 0 12 6.5m0 9a3.5 3.5 0 1 1 3.5-3.5a3.5 3.5 0 0 1-3.5 3.5"/></svg>';

  // 面板 ↔ 宿主机实时延迟：一次最小请求的往返耗时，5 秒一次（页面隐藏时跳过）
  let hostRTT = null;
  $: rttLevel = hostRTT == null ? 'off' : hostRTT < 60 ? 'ok' : hostRTT < 150 ? 'warn' : 'bad';
  $: rttText = hostRTT == null ? '-' : hostRTT + ' ms';

  async function probeHostRTT() {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    const t0 = performance.now();
    try {
      const r = await fetch(apiBase + '/api/ping', { cache: 'no-store', signal: ctrl.signal });
      hostRTT = r.ok ? Math.round(performance.now() - t0) : null;
    } catch (e) {
      hostRTT = null;
    } finally {
      clearTimeout(timer);
    }
  }

  onMount(async () => {
    probeHostRTT();
    pollVisible(probeHostRTT, 5000);
    // 外部入口定位标签页（如 LoliaFrp OAuth 授权完成回跳 /?tab=lolia），按导航白名单校验后清除参数
    try {
      const q = new URLSearchParams(window.location.search);
      const tab = q.get('tab');
      if (tab && tabs.some((t) => t.id === tab)) {
        activeTab.set(tab);
        q.delete('tab');
        const qs = q.toString();
        window.history.replaceState(null, '', window.location.pathname + (qs ? '?' + qs : '') + window.location.hash);
      }
    } catch (e) { /* ignore */ }
    // 初始化系统状态
    try {
      const [st] = await Promise.all([
        fetch(apiBase + '/api/status', { cache: 'no-store' }).then((r) => r.json())
      ]);
      if (st && st.success) status.set(st.data);
    } catch (e) {
      /* ignore */
    }
    // 模块启用状态（决定导航展示哪些入口）
    try {
      const m = await fetch(apiBase + '/api/modules', { cache: 'no-store' }).then((r) => r.json());
      if (m && m.success) disabledModules.set((m.data && m.data.disabled) || []);
    } catch (e) {
      /* ignore */
    }
    // 免责声明：服务端记录未同意时才弹窗（首次查询时后端顺带记录弹窗时间）
    try {
      const d = await api('/api/disclaimer');
      if (d && !d.agreed) showDisclaimer = true;
    } catch (e) {
      /* ignore：查询失败不弹窗，下次加载再查，避免服务不可达时锁死界面 */
    }
  });
</script>

<svelte:head>
  <title>{$i18n('app.title')}</title>
</svelte:head>

<svelte:window on:keydown={(e) => { if (e.key === 'Escape') { moreOpen = false; searchOpen = false; searchQuery = ''; } }} />

<div class="app-shell">
  <!-- 移动端顶栏（≤600px 显示）：品牌 + 运行状态 + 主题切换 -->
  <header class="mobile-bar">
    <div class="mobile-brand">
      <img src={apiBase + '/static/icon.png'} alt="TunHook" style="width:22px;height:22px">
      <span>TunHook</span>
      {#if $status && $status.version}<em class="mobile-ver">v{$status.version}</em>{/if}
    </div>
    <span class="topbar-status"><i class="status-dot" class:off={!$status}></i>{$status ? $i18n('status.runningShort') : $i18n('status.connecting')}</span>
    <button class="mobile-theme-btn" on:click={toggleTheme} title={$i18n('misc.theme')} aria-label={$i18n('misc.theme')}>
      {@html $theme === 'light' ? sunIcon : moonIcon}
    </button>
  </header>
  <aside class="sidebar" id="app-sidebar">
    <div class="sidebar-brand">
      <div class="logo">
        <img src={apiBase + '/static/icon.png'} alt="TunHook" style="width:26px;height:26px">
      </div>
      <div class="sidebar-brand-t">
        <h1>TunHook</h1>
        <span class="header-v">{$status && $status.version ? 'v' + $status.version : 'v—'}</span>
      </div>
    </div>
    <nav class="sidebar-nav">
      {#each tabGroups as g}
        {#if g.label}
          <div class="sidebar-group-title">{$i18n(g.label)}</div>
        {/if}
        {#each g.tabs as tab}
          <button class="sidebar-item" class:active={$activeTab === tab.id} aria-current={$activeTab === tab.id ? 'page' : undefined} on:click={() => goTab(tab.id)}>
            {@html tab.icon}
            <span>{$i18n('nav.' + tab.id)}</span>
          </button>
        {/each}
      {/each}
    </nav>
    <div class="sidebar-ft">
      <div class="sidebar-status" title={hostRTT == null ? '面板与宿主机延迟：探测中' : '面板 ↔ 宿主机 ' + hostRTT + ' ms'}>
        <i class="status-dot" class:off={!$status || hostRTT == null} class:warn={$status && rttLevel === 'warn'} class:bad={$status && rttLevel === 'bad'}></i>
        <div class="sidebar-status-t">
          <b>{$status ? $i18n('status.running') : $i18n('status.connecting')}</b>
          <span>{$status && $status.version ? 'v' + $status.version : $i18n('status.waiting')}</span>
        </div>
        <span class="sidebar-rtt" class:ok={rttLevel === 'ok'} class:warn={rttLevel === 'warn'} class:bad={rttLevel === 'bad'}>{rttText}</span>
      </div>
    </div>
  </aside>
  <div class="app-main">
    <!-- 桌面端全局顶栏：面包屑 + 快速跳转 + 运行状态 + 主题切换 -->
    <header class="desktop-topbar">
      <div class="topbar-crumb">
        <span>{$i18n('topbar.console')}</span>
        <span class="crumb-sep">/</span>
        <b>{$i18n('nav.' + (currentTab ? currentTab.id : 'dashboard'))}</b>
      </div>
      <div class="topbar-right">
        <div class="topbar-search">
          <span class="topbar-search-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
          </span>
          <input
            type="text"
            placeholder={$i18n('topbar.search')}
            bind:value={searchQuery}
            on:focus={() => (searchOpen = true)}
            on:blur={() => setTimeout(() => (searchOpen = false), 120)}
            aria-label={$i18n('topbar.search')}
          />
          {#if searchOpen}
            <div class="search-results">
              {#if !searchQuery.trim()}<div class="search-hint">{$i18n('topbar.quickJump')}</div>{/if}
              {#if searchResults.length}
                {#each searchResults as tab}
                  <button class="search-result" on:mousedown|preventDefault on:click={() => goTab(tab.id)}>
                    <span class="search-result-ico">{@html tab.icon}</span>
                    <span>{$i18n('nav.' + tab.id)}</span>
                  </button>
                {/each}
              {:else}
                <div class="search-empty">{$i18n('topbar.noMatch')}</div>
              {/if}
            </div>
          {/if}
        </div>
        <div class="topbar-lang" title={$i18n('lang.label')}>
          <CustomSelect bind:value={$locale} options={LOCALES} width="120px" />
        </div>
        <button class="topbar-icon" on:click={toggleTheme} title={$i18n('misc.theme')} aria-label={$i18n('misc.theme')}>
          {@html $theme === 'light' ? sunIcon : moonIcon}
        </button>
      </div>
    </header>
    <main class="app-content">
      {#key $locale}
      {#if closedTab}
        <div class="container">
          <div class="page-hdr">
            <div>
              <h2>{$i18n('misc.moduleClosed')}</h2>
              <span class="page-hdr-sub">{$i18n('misc.moduleClosedSub')}</span>
            </div>
          </div>
          <div class="empty">
            <div class="empty-t">{$i18n('misc.moduleClosedEmpty')}</div>
            <button class="btn btn-primary btn-sm" style="margin-top:12px" on:click={() => { settingsSect.set('modules'); activeTab.set('settings'); }}>{$i18n('misc.goModules')}</button>
          </div>
        </div>
      {:else if $activeTab === 'dashboard'}        <Dashboard />
      {:else if $activeTab === 'stun'}         <Stun />
      {:else if $activeTab === 'tunnel'}        <Tunnels />
      {:else if $activeTab === 'forward'}      <Forwards />
      {:else if $activeTab === 'mefrp'}        <Mefrp />
      {:else if $activeTab === 'lolia'}        <Lolia />
      {:else if $activeTab === 'cloudflare'}   <Cloudflare />
      {:else if $activeTab === 'dns'}
        <div class="container">
          <DnsPanel />
        </div>
      {:else if $activeTab === 'portscan'}     <PortScan />
      {:else if $activeTab === 'wol'}         <Wol />
      {:else if $activeTab === 'waf'}         <Waf />
      {:else if $activeTab === 'webserver'}   <WebServer />
      {:else if $activeTab === 'webhook'}      <Webhook />
      {:else if $activeTab === 'settings'}     <Settings />
      {:else if $activeTab === 'logs'}         <Logs />
      {:else if $activeTab === 'about'}        <About />
      {/if}
      {/key}
    </main>
  </div>

  <!-- 移动端底部导航：四个主入口 + 更多 -->
  <nav class="mobile-bottom-nav" aria-label={$i18n("底部导航")}>
    {#each mobileMain as tab}
      <button class="mbn-item" class:active={$activeTab === tab.id} on:click={() => goTab(tab.id)}>
        {@html tab.icon}
        <span>{$i18n(MOBILE_LABEL[tab.id] || 'nav.' + tab.id)}</span>
      </button>
    {/each}
    <button class="mbn-item" class:active={moreActive} on:click={() => (moreOpen = true)} aria-expanded={moreOpen} aria-controls="more-sheet">
      {@html moreIcon}
      <span>{$i18n('mobile.more')}</span>
    </button>
  </nav>

  {#if moreOpen}
    <div class="sheet-overlay" on:click={() => (moreOpen = false)} aria-hidden="true"></div>
    <div class="more-sheet" id="more-sheet" role="dialog" aria-label={$i18n("更多功能")}>
      <div class="sheet-handle"></div>
      <div class="more-grid">
        {#each moreTabs as tab}
          <button class="more-item" class:active={$activeTab === tab.id} on:click={() => goTab(tab.id)}>
            <span class="more-ico">{@html tab.icon}</span>
            <span>{$i18n('nav.' + tab.id)}</span>
          </button>
        {/each}
      </div>
    </div>
  {/if}
</div>

{#if showDisclaimer}
  <DisclaimerModal onAgree={agreeDisclaimer} />
{/if}

<div class="toast-wrap">
  {#each $toasts as t}
    <div class="toast {t.type}">{t.msg}</div>
  {/each}
</div>
