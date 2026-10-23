// 轻量 i18n：语种状态持久化到 localStorage，词条按 key 组织。
// key 约定：
//   - 外壳/导航等少量固定文案使用点分 key（如 nav.dashboard）；
//   - 页面正文直接使用简体中文原文作为 key（中文即 key），zh-CN 因此无需维护词条表，
//     zh-TW / en / ja-JP 只需提供「中文原文 -> 译文」的映射。
// 使用方式：
//   - 模板里 {$t('文案')}（t 必须是脚本里 import 进来的 store）
//   - 脚本/事件处理里 tr('文案')（按调用时的当前语种即时取词）
//   - 带变量：tr('已删除 {0} 条记录', [n]) 或 $t('已删除 {0} 条记录', [n])
import { derived, get, writable } from 'svelte/store';
import zhTW from './i18n/zh-TW.js';
import en from './i18n/en.js';
import jaJP from './i18n/ja-JP.js';

export const LOCALES = [
  { value: 'zh-CN', label: '简体中文' },
  { value: 'zh-TW', label: '繁體中文' },
  { value: 'en', label: 'English' },
  { value: 'ja-JP', label: '日本語' }
];

const STORAGE_KEY = 'tunhook-locale';

function initialLocale() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && LOCALES.some((l) => l.value === saved)) return saved;
  } catch (e) {
    /* 忽略存储不可用 */
  }
  // 首次访问跟随浏览器语言：繁体（台湾/香港/澳门/繁体）优先，日文次之，其余中文为简体
  const nav = String((typeof navigator !== 'undefined' && navigator.language) || '').toLowerCase();
  if (nav.startsWith('zh-tw') || nav.startsWith('zh-hk') || nav.startsWith('zh-mo') || nav.includes('hant')) return 'zh-TW';
  if (nav.startsWith('ja')) return 'ja-JP';
  if (nav.startsWith('zh')) return 'zh-CN';
  return nav ? 'en' : 'zh-CN';
}

export const locale = writable(initialLocale());

// 持久化并同步 <html lang>
locale.subscribe((v) => {
  try {
    localStorage.setItem(STORAGE_KEY, v);
  } catch (e) {
    /* 忽略存储不可用 */
  }
  if (typeof document !== 'undefined') document.documentElement.lang = v;
});

// 简体中文基准词条：点分 key 在这里维护；正文中文原文 key 直接返回自身
const zhCN = {
  'app.title': 'TunHook 管理控制台',
  'lang.label': '语言',
  'topbar.console': '控制台',
  'topbar.search': '搜索页面或功能',
  'topbar.quickJump': '快速跳转',
  'topbar.noMatch': '没有匹配的页面',
  'status.running': '服务运行中',
  'status.runningShort': '运行中',
  'status.connecting': '连接中',
  'status.waiting': '等待状态',
  'group.tunnel': '穿透与转发',
  'group.network': '网络工具',
  'group.system': '系统',
  'nav.dashboard': '仪表盘',
  'nav.tunnel': 'FRPC',
  'nav.stun': 'STUN',
  'nav.mefrp': 'MEFrp',
  'nav.lolia': 'LoliaFrp',
  'nav.webhook': 'Webhook',
  'nav.cloudflare': 'Cloudflare Tunnel',
  'nav.forward': '端口转发',
  'nav.dns': '域名解析',
  'nav.portscan': '端口扫描',
  'nav.wol': '网络唤醒',
  'nav.waf': 'WAF 防火墙',
  'nav.webserver': 'Web 服务',
  'nav.settings': '系统设置',
  'nav.logs': '系统日志',
  'nav.about': '关于',
  'mobile.tunnel': 'FRPC',
  'mobile.forward': '转发',
  'mobile.logs': '日志',
  'mobile.more': '更多',
  'misc.theme': '切换主题',
  'misc.moduleClosed': '模块已关闭',
  'misc.moduleClosedSub': '该模块的入口已在「系统设置 → 模块管理」中关闭',
  'misc.moduleClosedEmpty': '该模块已关闭，不再展示其页面；已运行的服务不受影响',
  'misc.goModules': '前往模块管理开启',
  'dns.title': '域名解析',
  'dns.sub': 'DNS 账户与解析记录 · 动态解析 · TLS 证书申请与自动续签'
};

const messages = { 'zh-TW': zhTW, en, 'ja-JP': jaJP };

// 支持 {0} 数组占位与 {name} 命名占位
function format(text, vars) {
  if (vars == null) return text;
  if (Array.isArray(vars)) return text.replace(/\{(\d+)\}/g, (m, i) => (vars[i] ?? m));
  return text.replace(/\{(\w+)\}/g, (m, k) => (vars[k] ?? m));
}

function translate(current, key, vars) {
  const dict = messages[current];
  const text = dict && Object.prototype.hasOwnProperty.call(dict, key) ? dict[key] : (zhCN[key] ?? key);
  return format(text, vars);
}

// 事件/脚本里使用：按调用时的当前语种立即取词
export function tr(key, vars) {
  return translate(get(locale), key, vars);
}

// 模板里使用：$t(...)
export const t = derived(locale, ($locale) => (key, vars) => translate($locale, key, vars));
