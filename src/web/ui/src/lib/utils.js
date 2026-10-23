import { tr } from './i18n.js';
// 通用工具函数：格式化、状态判断等

// 字节数格式化（自动单位）
// 单位阶梯按 1024：当前单位下的数值达到「下一单位最小值的 80%」（1024×0.8 = 819.2）即提前进位，
// 避免出现「819 GB」「1000 MB」这类逼近四位数的读法（819.2 GB 显示为 0.8 TB）。
export function fmtBytes(n, decimals = 1) {
  if (n === null || n === undefined || isNaN(n) || n < 0) return '-';
  if (n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const CARRY = 1024 * 0.8; // 提前进位阈值：下一单位最小值的 80%
  let i = Math.floor(Math.log(n) / Math.log(1024));
  if (!(i >= 0)) i = 0;                          // n<1（亚字节）时单位索引为负 → 归零显示为 B，避免输出 undefined 单位
  if (i >= units.length) i = units.length - 1;   // 超出最大单位时钳制到最大单位
  let v = n / Math.pow(1024, i);
  while (v >= CARRY && i < units.length - 1) { v /= 1024; i++; }
  return (v >= 100 ? v.toFixed(0) : v.toFixed(decimals)) + ' ' + units[i];
}

// 速率格式化（B/s -> KB/s 等）：无效值按 0 处理，避免图表与列表出现「-/s」
export function fmtRate(n) {
  if (n === null || n === undefined || isNaN(n) || n < 0) return '0 B/s';
  return fmtBytes(n, 1) + '/s';
}

// 以 MB 为单位的数值格式化（MEFrp 等接口口径）：折算为字节后复用 fmtBytes 自动定单位
export function fmtMB(mb, decimals = 1) {
  if (mb === null || mb === undefined || isNaN(mb) || mb < 0) return '-';
  if (mb === 0) return '0 B';
  return fmtBytes(mb * 1024 * 1024, decimals);
}

// 秒数转可读时长
export function fmtDuration(sec) {
  if (sec === null || sec === undefined || isNaN(sec)) return '-';
  sec = Math.floor(sec);
  if (sec < 60) return sec + tr(" 秒");
  if (sec < 3600) return Math.floor(sec / 60) + tr(" 分钟 ") + (sec % 60) + tr(" 秒");
  if (sec < 86400) return Math.floor(sec / 3600) + tr(" 小时 ") + Math.floor((sec % 3600) / 60) + tr(" 分钟");
  return Math.floor(sec / 86400) + tr(" 天 ") + Math.floor((sec % 86400) / 3600) + tr(" 小时");
}

// 协议显示
export function protoLabel(p) {
  const map = { tcp: 'TCP', udp: 'UDP', http: 'HTTP', https: 'HTTPS', gateway: tr("网关") };
  return map[String(p).toLowerCase()] || String(p).toUpperCase();
}

// 把任意文本清理为 frp 代理名称（仅保留字母/数字/_- .，压缩连续分隔符，截断到 32 字符）。
export function sanitizeProxyName(raw) {
  if (!raw) return '';
  let s = String(raw).trim();
  s = s.replace(/[^A-Za-z0-9_.\-]/g, '-').replace(/-+/g, '-').replace(/^[-_.]+|[-_.]+$/g, '');
  return s.slice(0, 32);
}

// 从端口扫描结果项建议代理名称：网页标题 > 进程名 > 服务名。
// 严格按优先级依次尝试：仅当前一来源缺失、为错误页或清理后为空时才使用下一个。
export function suggestProxyName(it) {
  if (!it) return '';
  const cands = [];
  if (it.web_title && !/^\d{3}\b/.test(String(it.web_title).trim())) cands.push(it.web_title);
  if (it.process) cands.push(it.process);
  if (it.service) cands.push(it.service);
  for (const c of cands) {
    const s = sanitizeProxyName(c);
    if (s) return s;
  }
  return '';
}

// 从端口扫描结果项建议描述文本：网页标题 > 进程名 > 服务名。
// 与建议代理名称（需 ASCII 合法名）不同，描述保留原始文本（允许中文），仅折叠空白并截断。
export function suggestDescription(it) {
  if (!it) return '';
  let raw = '';
  if (it.web_title && !/^\d{3}\b/.test(String(it.web_title).trim())) raw = it.web_title;
  if (!raw && it.process) raw = it.process;
  if (!raw && it.service) raw = it.service;
  raw = String(raw || '').trim().replace(/\s+/g, ' ');
  const r = [...raw];
  return r.length > 60 ? r.slice(0, 60).join('') : raw;
}

// 深拷贝（避免 Svelte 响应式误判引用）
export function clone(v) {
  return JSON.parse(JSON.stringify(v));
}

// 本机回环/通配地址（空、127.0.0.1、localhost、0.0.0.0、::、::0）在展示与点击时替换为本地 IPv4，
// 便于局域网内其他设备直接访问；本地 IPv4 不可用时回退 127.0.0.1。其他地址（局域网 IP / IPv6）原样返回。
export function localHost(ip, localIPv4) {
  const s = String(ip || '').trim();
  if (!s || s === '127.0.0.1' || s === 'localhost' || s === '0.0.0.0' || s === '::' || s === '::0') {
    return localIPv4 || '127.0.0.1';
  }
  return s;
}

// 构造端口服务可访问的网页地址（http://host:port）。
// 回环/通配监听地址（空、0.0.0.0、::、::0、127.0.0.1、::1、localhost）无法被本机外部设备直接访问，
// 替换为调用方给定的 accessHost（即当前访问管理界面的主机地址）；其他地址（局域网 IP / IPv6）原样拼接。
// IPv6 地址自动加方括号。端口扫描页面与内网穿透/转发/Stun/Mefrp 等扫描弹窗共用同一套逻辑。
export function portWebUrl(addr, port, accessHost) {
  const a = String(addr || '').trim();
  const loopback = !a || a === '0.0.0.0' || a === '::' || a === '::0' || a === '127.0.0.1' || a === '::1' || a === 'localhost';
  const h = loopback ? (accessHost || '127.0.0.1') : a;
  const host = h.includes(':') ? '[' + h + ']' : h;
  return 'http://' + host + ':' + port;
}

// 从转发规则 key 解析展示信息（key 格式 tcp://addr:port->addr:port / gateway://name->... / http://addr:port/domain->...）
export function parseFwdKey(key) {
  const out = { protocol: '', local: '', remote: '', name: '', domain: '', addr: '' };
  const idx = key.indexOf('://');
  if (idx < 0) return out;
  out.protocol = key.slice(0, idx);
  const rest = key.slice(idx + 3);
  const arrow = rest.indexOf('->');
  if (arrow < 0) return out;
  const local = rest.slice(0, arrow);
  const remote = rest.slice(arrow + 2);
  out.remote = remote;
  if (out.protocol === 'gateway') {
    out.name = local;
    out.addr = 'proxy/' + local;
  } else if (out.protocol === 'http' || out.protocol === 'https') {
    const slash = local.indexOf('/');
    if (slash >= 0) {
      out.domain = local.slice(slash + 1);
      out.local = local.slice(0, slash);
    } else {
      out.local = local;
    }
    out.addr = out.local;
  } else {
    out.local = local;
    out.addr = local;
  }
  return out;
}

// 毫秒时间戳 -> 本地时间字符串
export function fmtTime(ms) {
  if (!ms) return '-';
  const d = new Date(ms);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// 时间字符串 -> 分钟（用于日志导出等）
export function parseLogTime(s) {
  const d = new Date(s.replace(' ', 'T'));
  return isNaN(d.getTime()) ? 0 : d.getTime();
}

// 行首时间戳：2026-09-18T08:41:18Z / 2026-09-18 15:56:41.123 / 2026/09/18 15:56:41+08:00
const LOG_TS_RE = /^\d{4}[-/]\d{1,2}[-/]\d{1,2}[T ]\d{1,2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?/;
// 日志级别标记：方括号缩写（frpc 的 [I]/[W]/[E]）与全称/三字母缩写（cloudflared 的 INF/WRN/ERR）
const LOG_LV_RE = /\[([IWEDTFP])\]|\b(FATAL|PANIC|ERROR|ERR|WARN|WRN|INFO|INF|DEBUG|DBG|TRACE)\b/g;
// 级别 -> 高亮类；未列出的（INFO/INF/I）保持常规色，不加标记
const LOG_LV_CLASS = {
  FATAL: 'hl-err', PANIC: 'hl-err', ERROR: 'hl-err', ERR: 'hl-err', E: 'hl-err', F: 'hl-err', P: 'hl-err',
  WARN: 'hl-warn', WRN: 'hl-warn', W: 'hl-warn',
  DEBUG: 'hl-debug', DBG: 'hl-debug', D: 'hl-debug', TRACE: 'hl-debug', T: 'hl-debug'
};

// 日志高亮：按级别着色并淡化时间戳，返回可直接交给 {@html} 的 HTML 串。
//   错误=红 / 警告=黄 / 调试与追踪=灰 / 信息保持常规色，整行仍按原样可读。
// 安全：日志内容来自外部进程输出与 HTTP 请求，必须先整体转义再插入标记，
// 否则 {@html} 会把日志里的尖括号当成标签执行（XSS）。级别标记本身不含这些字符，转义不影响匹配。
export function highlightLog(text) {
  const escaped = String(text == null ? '' : text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  return escaped
    .split('\n')
    .map((line) =>
      line
        .replace(LOG_TS_RE, (m) => `<span class="hl-ts">${m}</span>`)
        .replace(LOG_LV_RE, (m, bracket, word) => {
          const cls = LOG_LV_CLASS[(word || bracket).toUpperCase()];
          return cls ? `<span class="${cls}">${m}</span>` : m;
        })
    )
    .join('\n');
}

// 日志按行倒序：日志文件按旧→新追加，界面统一展示为最新行在顶部
export function reverseLines(text) {
  return String(text == null ? '' : text).split('\n').reverse().join('\n');
}

// ---- 配色方案（参考 tusij.com 在线配色：基础色 → 明暗梯度整套色板） ----
// HEX -> HSL（h: 0-360, s/l: 0-1）
function hexToHsl(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(String(hex || '').trim());
  if (!m) return { h: 190, s: 0.9, l: 0.5 };
  const n = parseInt(m[1], 16);
  const r = ((n >> 16) & 255) / 255, g = ((n >> 8) & 255) / 255, b = (n & 255) / 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b);
  const l = (max + min) / 2;
  let h = 0, s = 0;
  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case r: h = (g - b) / d + (g < b ? 6 : 0); break;
      case g: h = (b - r) / d + 2; break;
      default: h = (r - g) / d + 4;
    }
    h *= 60;
  }
  return { h, s, l };
}
// HSL -> HEX
function hslToHex(h, s, l) {
  s = Math.min(1, Math.max(0, s)); l = Math.min(1, Math.max(0, l));
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
  const m = l - c / 2;
  let r = 0, g = 0, b = 0;
  if (h < 60) { r = c; g = x; }
  else if (h < 120) { r = x; g = c; }
  else if (h < 180) { g = c; b = x; }
  else if (h < 240) { g = x; b = c; }
  else if (h < 300) { r = x; b = c; }
  else { r = c; b = x; }
  const to = (v) => Math.round((v + m) * 255).toString(16).padStart(2, '0');
  return '#' + to(r) + to(g) + to(b);
}
// HEX -> "r,g,b"（供 rgba(var(--accent-rgb), α) 使用）
function rgbStr(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(String(hex || '').trim());
  const n = m ? parseInt(m[1], 16) : 0;
  return `${(n >> 16) & 255},${(n >> 8) & 255},${n & 255}`;
}
// 相对亮度 / 对比度（WCAG 2.1）：配色按可读性反解，而不是凭感觉挑明度
function relLum(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(String(hex || '').trim());
  if (!m) return 0;
  const n = parseInt(m[1], 16);
  const ch = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
  return 0.2126 * ch((n >> 16) & 255) + 0.7152 * ch((n >> 8) & 255) + 0.0722 * ch(n & 255);
}
export function contrastRatio(a, b) {
  const l1 = relLum(a), l2 = relLum(b);
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}
// 颜色叠加：把 fg 以 alpha 盖在 bg 上，得到实际显示出来的合成色。
// 用于校验「同色相淡底」这类叠加后的可读性——叠加后的底比纯底色更接近前景色，是最不利组合。
function mixHex(fg, alpha, bg) {
  const parse = (h) => { const n = parseInt(String(h).slice(1), 16); return [(n >> 16) & 255, (n >> 8) & 255, n & 255]; };
  const [r1, g1, b1] = parse(fg), [r2, g2, b2] = parse(bg);
  const to = (v) => Math.round(v).toString(16).padStart(2, '0');
  return '#' + to(r1 * alpha + r2 * (1 - alpha)) + to(g1 * alpha + g2 * (1 - alpha)) + to(b1 * alpha + b2 * (1 - alpha));
}
// 浅色主题强调色的明度不能写死：HSL 的 L 不是感知亮度，同一 L 下青/绿远比蓝/紫亮，
// 写死会让青/绿系在浅底上对比不足（曾实测白字按钮仅 2.7:1）。
// 这里按可读性反解，需同时满足三条约束——
//   强调色 vs 最深的浅色面（内层 bg4）≥ 4.5（要能当正文/链接色）
//   白字 vs 强调色 ≥ 4.5（要能当实心按钮底色）
//   强调色 vs 自身 12% 淡底 ≥ 4.5（要能当淡底徽章的文字，如 .badge-info）
//
// 但只满足这三条还不够：靛蓝/紫的感知亮度天生低于青/绿，同样扫到「第一个达标档」，
// 青落在白字对比 5.6 而靛蓝落在 8.2——六档观感参差。因此再收一道目标区间，
// 优先取白字对比度落在 [LIGHT_W_LO, LIGHT_W_HI] 且最鲜艳的一档，让六档视觉重量一致。
// 区间内无解（极深或极浅的自定义色）时退化为「达标即取」，保证一定有值。
const LIGHT_W_LO = 5.2, LIGHT_W_HI = 6.2;
function solveLightL(h, s, refDeep, refCard, min = 4.5) {
  const ok = (c) =>
    contrastRatio(c, refDeep) >= min &&
    contrastRatio('#ffffff', c) >= min &&
    contrastRatio(c, mixHex(c, 0.12, refCard)) >= min;
  // 上限取 0.78 而非 0.50：蓝/紫在 L=0.50 时仍过深，需允许取更浅的档位才能落进目标区间；
  // 更浅会先撞上「vs bg4 ≥ 4.5」这条，不会失控。
  for (let l = 0.78; l >= 0.12; l -= 0.005) {
    const c = hslToHex(h, s, l);
    if (!ok(c)) continue;
    const w = contrastRatio('#ffffff', c);
    if (w >= LIGHT_W_LO && w <= LIGHT_W_HI) return l;
  }
  for (let l = 0.78; l >= 0.12; l -= 0.005) {
    if (ok(hslToHex(h, s, l))) return l;
  }
  return 0.12;
}
// 实心底色（实心按钮/激活胶囊/开关滑块）专用强调色，独立于作为文字色的 --accent。
// 根因：--accent 同时承担两个数学上冲突的角色——深色背景上的文字要够亮，配白字的实心底要够暗，
// 同一个中频色无法兼顾（实测默认青白字按钮仅 1.59:1，远低于 4.5）。
// 这里保留强调色的色相与饱和度只压明度：从文字色起向下取第一个让白字 ≥4.5 的明度，
// 取最浅的一档以尽量贴近原配色的色感。
function solveSolid(accent, min = 4.5) {
  const { h, s, l } = hexToHsl(accent);
  for (let ll = l; ll >= 0.1; ll -= 0.005) {
    const c = hslToHex(h, s, ll);
    if (contrastRatio('#ffffff', c) >= min) return c;
  }
  return hslToHex(h, s, 0.1);
}
// 中性件（二级/三级文字、分隔线、气泡与 Toast 表面、控件边界）按目标对比度反解明度。
// 存在的理由：这些 token 原先在 app.css 里写死为冷灰，而背景色板会随配色改变色相与明度，
// 于是暖色配色下出现「冷灰压暖底」的发灰观感，对比度也随底色漂移——
// 实测三级文字在青/绿配色下只有 3.99 / 4.03，低于 4.5。改为色相跟随背景基色、明度反解后，
// 六套配色的中性件对比度落在同一水平，不再各自漂移。
// 扫描方向由主题决定：深色主题底暗、前景亮，明度越高对比越高，从暗往亮扫；
// 浅色主题底亮、前景暗，反之。（对比度对明度单调，故只需单向扫描）
function solveNeutral(h, s, surf, min, dark) {
  for (let i = 0; i <= 420; i++) {
    const l = dark ? 0.30 + i * 0.002 : 0.92 - i * 0.002;
    if (l < 0.04 || l > 0.96) break;
    const c = hslToHex(h, s, l);
    if (contrastRatio(c, surf) >= min) return c;
  }
  return hslToHex(h, s, dark ? 0.92 : 0.25);
}
// 中性件的染色饱和度：极低。只求让冷灰带上底色的倾向，避免暖色配色下「冷灰压暖底」的脏感；
// 再高就会让「灰色」变成「有色」，与语义色抢注意力。
const NEUTRAL_SAT = 0.10;
// 深色强调色的对比度上限。浅色侧由 solveLightL 的目标区间统一，深色侧原先直接用原方案成品值，
// 导致六套之间最亮与最暗相差过大（实测青 9.41 / 靛 5.86），切换配色时亮度「跳」的程度不一致。
// 只压超过上限的离群值，不做整体重排，尽量保留原配色的色感。
const DARK_CR_MAX = 8.4;
// 由基础色生成整套配色方案：
//   dark/light 强调色 + 悬停色（按主题保证对比度）+ bgD/bgL 明暗背景色板（同色相梯度）
// opts（预设配色专用，自定义基础色时不传）：
//   accentD —— 直接给定暗色强调色。预设取自真实配色方案，强调色本就是成品色值，
//              再走 hsl 统一提亮会丢掉原方案的色感，因此原样采用；
//              仅当它与背景的对比超出 DARK_CR_MAX 时才压暗一档（见该常量说明）。
//   bgBase  —— 背景色板改用独立基色。真实配色方案里强调色与背景往往不同色相
//              （例：近黑底 + 荧光绿），单一基础色推导不出这种组合。
//   accentL —— 直接给定浅色主题强调色。预设配色可保留原方案的成品浅色值；
//              未提供时仍按对比度反解明度。给定值用于 solidL / hoverL 推导，避免与 --accent 脱节。
export function makePalette(base, name = '', opts = {}) {
  const { h, s } = hexToHsl(base);
  const bgBase = opts.bgBase || base;                      // 背景色板基色（可与强调色不同色相）
  const bgS = hexToHsl(bgBase).s, bgH = hexToHsl(bgBase).h;
  const bgSat = Math.min(bgS, 0.55);                       // 背景饱和度压到 55% 内，避免刺眼
  const bgSatL = Math.min(bgS, 0.45);
  // 深色色板先算：强调色收敛与中性件反解都要以它作基准面
  const bgD = {
    bg: hslToHex(bgH, bgSat, 0.06),
    bg2: hslToHex(bgH, bgSat, 0.11),
    bg3: hslToHex(bgH, bgSat, 0.16),
    bg4: hslToHex(bgH, bgSat, 0.08),
    bd: hslToHex(bgH, bgSat, 0.30)
  };
  // 浅色面参考 PriTime（pritime.com）：无彩中性灰阶 + 纯白表面，强调色才带色相。
  // 页面底 #fafafa 微灰，卡片/侧边栏/输入框纯白「浮」在灰底上，层次靠 #e5e5e5 边框与阴影。
  // 内层/hover 用 #f5f5f5；六套配色浅色底统一、不随强调色染色（中性底+彩色强调）。
  // 强调色与中性文字仍由 solveLightL / solveNeutral 以最暗面 bg4 反解，对比度阈值自动保持。
  // 层次方向：卡片/侧边(白) > 页面(#fafafa) > 内层(#f5f5f5)。

  const bgL = {
    bg: '#fafafa',
    bg2: '#ffffff',
    bg3: '#ffffff',
    bg4: '#f5f5f5',
    bd: '#e5e5e5'
  };
  // 暗色主题强调色：预设直接给定成品色值（accentD），再走 hsl 统一提亮会丢掉原方案的色感。
  // 但原值之间的亮度差很大，切换配色时「跳」的程度不一致（见 DARK_CR_MAX 说明），
  // 故对超上限的离群值压暗一档——只动明度，色相与饱和度保持原样。
  let dark = opts.accentD || hslToHex(h, s, 0.62);
  if (contrastRatio(dark, bgD.bg2) > DARK_CR_MAX) {
    const dh = hexToHsl(dark);
    for (let l = dh.l; l >= 0.30; l -= 0.002) {
      const c = hslToHex(dh.h, dh.s, l);
      if (contrastRatio(c, bgD.bg2) <= DARK_CR_MAX) { dark = c; break; }
    }
  }
  // 强调色的色相/饱和度一律以最终 dark 为准：浅色档由它反解，预设与自定义两条路径才一致
  const dSat = hexToHsl(dark).s;
  const dH = opts.accentD ? hexToHsl(dark).h : h;
  const acSat = Math.min(1, dSat * 0.9);
  const solvedLightL = solveLightL(dH, acSat, bgL.bg4, bgL.bg3);
  const light = opts.accentL || hslToHex(dH, acSat, solvedLightL); // 亮色主题强调色：预设可直接给定成品值
  const lightHsl = hexToHsl(light);
  const lightL = lightHsl.l;
  // 实心底色（实心按钮 / 激活胶囊 / 开关滑块）配白字专用：与文字色 --accent 分离，
  // 由强调色按「白字 ≥4.5:1」反解明度得出。
  // 浅色档无需反解——solveLightL 已约束白字对比度落在目标区间，light 本身就是合法实心底，
  // 再压暗反而会让激活胶囊跟文字色脱节，故两套主题共用同一推导函数、各取一端。
  const solid = solveSolid(dark), solidL = solveSolid(light);
  const solidH = hexToHsl(solid);
  return {
    name, base,
    dark, light, rgb: rgbStr(dark), rgbL: rgbStr(light),
    solid, solidL,
    // 悬停态：两套主题都是「从实心底色再深一档」的实色。
    // 深色侧原先是 rgba(dark, 0.85)——拿「文字色」当「实心底」，绕过了 solveSolid 的白字反解，
    // 且 85% 叠加后比 solid 更亮，实测六套的白字对比全部跌破（2.03~3.70）。
    // 改为实色后比 solid 更深，白字对比只会更高，同时与浅色侧公式对称。
    hoverD: hslToHex(solidH.h, solidH.s, Math.max(0.10, solidH.l - 0.05)),
    hoverL: hslToHex(lightHsl.h, lightHsl.s, Math.max(0.12, lightL - 0.06)),
    bgD,
    bgL,
    // 控件边界色（输入框/下拉框/开关）：WCAG 1.4.11 要求承载交互语义的组件边界对相邻色 ≥3:1。
    // 输入框底色是 bg2、容器是 bg3/bg4，两者明度差极小（深色下 0.11 vs 0.16），边界几乎全靠边框识别，
    // 因此必须达标。卡片与分隔线的边框属装饰、不受此约束，故与 --bd 分开——一并提亮会让整站边框发硬。
    bdStrong: solveNeutral(bgH, bgSat, bgD.bg3, 3.0, true),
    bdStrongL: solveNeutral(bgH, bgSatL, bgL.bg4, 3.0, false),
    // 中性件：色相跟随背景基色（低饱和染色），明度按目标对比度反解。
    // 深色基准面取 bg3（六套中最亮的面，最不利）；浅色取 bg4（最暗的面，最不利）。
    // 浅色侧的目标比深色高：浅底上的文字需要更大反差才清晰，且原先已达这一水平，不应做差。
    text2: solveNeutral(bgH, NEUTRAL_SAT, bgD.bg3, 6.0, true),
    text3: solveNeutral(bgH, NEUTRAL_SAT, bgD.bg3, 4.5, true),
    text2L: solveNeutral(bgH, NEUTRAL_SAT, bgL.bg4, 7.5, false),
    text3L: solveNeutral(bgH, NEUTRAL_SAT, bgL.bg4, 5.2, false),
    // 分隔线：比边框再弱一档，仅用于表格行与卡片内部分隔（明度在 bd 基础上向背景方向退一步）
    sep: hslToHex(bgH, bgSat, 0.26),
    sepL: '#eeeeee',
    // 浮起表面（Tooltip / Toast）：需要比卡片面亮一档才有「浮起」感，故明度直接在 bg2 上加一档。
    // 用加档而非反解：这里要保证的是「六套的层次差一致」，不是某个对比度阈值。
    tipBg: hslToHex(bgH, NEUTRAL_SAT, Math.min(0.30, hexToHsl(bgD.bg2).l + 0.05)),
    tipBd: hslToHex(bgH, NEUTRAL_SAT, Math.min(0.38, hexToHsl(bgD.bg2).l + 0.11)),
    toastBg: hslToHex(bgH, NEUTRAL_SAT, Math.min(0.32, hexToHsl(bgD.bg2).l + 0.06)),
    tipBgL: '#ffffff',
    tipBdL: '#e5e5e5',
    toastBgL: '#ffffff'
  };
}

// Canvas 图表用的主题色：canvas 读不到 CSS 变量，绘制前须从根元素取当前主题的实际值。
// 主题切换与自定义配色都会改写这些变量，因此每次重绘前都要重新读取一次。
// 提示框表面随主题反转（深色主题深底浅字 / 浅色主题柔白底深字），框内文字用同一套系列色，两种主题下都可读。
export function chartColors() {
  const cs = getComputedStyle(document.documentElement);
  const v = (name, fallback) => cs.getPropertyValue(name).trim() || fallback;
  return {
    accent: v('--accent', '#06b6d4'),
    accent2: v('--accent-2', '#a78bfa'),
    red: v('--red', '#ef4444'),
    green: v('--green', '#22c55e'),
    yellow: v('--yellow', '#f59e0b'),
    violet: v('--violet', '#8b5cf6'),
    text3: v('--text3', '#90a4a2'),
    // canvas 里不能写 rgba(var(--x-rgb),α)（变量形式不是 canvas 能解析的颜色），
    // 故把半透明的网格/悬停指示线在 JS 侧合成为 rgba() 字符串，保证与主题配色同步
    gridSoft: `rgba(${rgbStr(v('--text3', '#90a4a2'))},.45)`,
    // 提示框表面同样跟随配色：原先深色主题写死冷蓝（rgba(15,23,42,.94)），
    // 在暖色配色下与页面底色相差近 180°，是同一个「中性件不跟随」的问题，故一并改读变量。
    tipBg: v('--tip-bg', '#252d2c'),
    tipBd: v('--tip-bd', '#323e3c'),
    tipText: v('--text', '#e2e8f0')
  };
}

// ===================== 输入校验 =====================
// 约定：所有校验函数返回 '' 表示合法；返回非空字符串即为面向用户的错误提示。
// 空值统一报「请输入…」；选填字段用 optional() 包裹。

// 选填字段：空值直接合法，非空时走给定校验
export function optional(check) {
  return (v) => (String(v == null ? '' : v).trim() === '' ? '' : check(v));
}

// IPv4：4 段点分十进制，每段 0-255，禁止前导零（单独的 0 除外）
export function validateIPv4(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return tr("请输入 IPv4 地址");
  const parts = s.split('.');
  if (parts.length !== 4) return tr("IPv4 应为 4 段点分格式，如 192.168.1.1");
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return tr("IPv4 每段只能包含数字");
    if (p.length > 1 && p[0] === '0') return tr("IPv4 每段不能有前导零（如 01 应写为 1）");
    if (Number(p) > 255) return tr("IPv4 每段取值范围为 0-255");
  }
  return '';
}

// IPv6：符合 RFC 4291——8 组 1-4 位十六进制；:: 压缩至多出现一次；末尾可内嵌 IPv4
export function validateIPv6(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return tr("请输入 IPv6 地址");
  if (/\s/.test(s)) return tr("IPv6 地址不能包含空格");
  if (s.length > 45) return tr("IPv6 地址长度超出限制");
  if (s.includes('%')) return tr("IPv6 地址不支持区域标识（%scope）");

  // 末尾内嵌 IPv4：最后一个冒号之后含点号，拆出后按 IPv4 校验，它占 2 组
  let head = s;
  let embedded = 0;
  const lastColon = s.lastIndexOf(':');
  if (lastColon !== -1 && s.slice(lastColon + 1).includes('.')) {
    if (validateIPv4(s.slice(lastColon + 1))) return tr("内嵌的 IPv4 地址不合法");
    // 该冒号前也是冒号时，它属于 ::（如 ::192.168.0.1），两个冒号都要保留在 head 中
    const cut = s[lastColon - 1] === ':' ? lastColon + 1 : lastColon;
    head = s.slice(0, cut);
    embedded = 2;
  } else if (s.includes('.')) {
    return tr("IPv6 地址格式不正确");
  }

  const compressed = head.includes('::');
  if ((head.match(/::/g) || []).length > 1) return tr("IPv6 中 :: 压缩标记只能出现一次");

  let groups;
  if (compressed) {
    const [l, r] = head.split('::');
    const left = l ? l.split(':') : [];
    const right = r ? r.split(':') : [];
    // 压缩至少省略 1 组：显式组数上限为 7（内嵌 IPv4 时为 5）
    if (left.length + right.length > 7 - embedded) return tr("IPv6 地址组数超过 8 组");
    groups = left.concat(right);
  } else {
    groups = head.split(':');
    if (groups.length !== 8 - embedded) return tr("IPv6 需为 8 组十六进制，或使用 :: 压缩");
  }
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return tr("IPv6 每段应为 1-4 位十六进制字符（0-9、a-f）");
  }
  return '';
}

// 端口：纯数字，1-65535；allowZero=true 时额外允许 0（用于「0=自动分配」字段）
export function validatePort(raw, allowZero = false) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return tr("请输入端口号");
  if (!/^\d+$/.test(s)) return tr("端口号只能包含数字");
  const n = Number(s);
  if (allowZero && n === 0) return '';
  if (n < 1 || n > 65535) return allowZero ? tr("端口号应为 0 或 1-65535") : tr("端口号范围为 1-65535");
  return '';
}

// 域名：至少一个点，每段 LDH 规则（字母/数字/连字符，不以连字符开头结尾），
// 后缀为 2 位以上字母或 xn-- 开头的国际化域名。wildcard=true 允许 *. 前缀；
// allowUnderscore=true 额外允许下划线（DNS 记录名，如 _dmarc.example.com、mefrp_tunnel.atxa.top）
export function validateDomain(raw, opts = {}) {
  let s = String(raw == null ? '' : raw).trim().toLowerCase();
  if (!s) return tr("请输入域名");
  if (opts.wildcard && s.startsWith('*.')) s = s.slice(2);
  if (s.includes('*')) return tr("通配符只能出现在最前面，格式如 *.example.com");
  if (s.length > 253) return tr("域名总长度不能超过 253 个字符");
  const labels = s.split('.');
  if (labels.length < 2) return tr("域名需包含有效后缀，如 example.com");
  for (const lb of labels) {
    if (!lb) return tr("域名中不能包含连续的点");
    if (lb.length > 63) return tr("域名每段长度不能超过 63 个字符");
    const ok = opts.allowUnderscore
      ? /^[a-z0-9_-]+$/.test(lb) && !lb.startsWith('-') && !lb.endsWith('-')
      : /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(lb);
    if (!ok) {
      return opts.allowUnderscore
        ? tr("域名只能包含字母、数字、连字符和下划线，且不能以连字符开头或结尾")
        : tr("域名只能包含字母、数字和连字符，且不能以连字符开头或结尾");
    }
  }
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,}$/.test(tld) && !/^xn--[a-z0-9-]{2,}$/.test(tld)) {
    return tr("域名后缀无效，应为 2 位以上字母（如 .com、.cn）");
  }
  return '';
}

// 纯 IP：IPv4 或 IPv6（不含域名）
export function validateIP(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return tr("请输入 IP 地址");
  if (validateIPv4(s) === '' || validateIPv6(s) === '') return '';
  return tr("请输入合法的 IPv4 或 IPv6 地址");
}

// 主机地址：IPv4 / IPv6 / 域名 三者任一合法
export function validateHost(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return tr("请输入 IP 地址或域名");
  if (s[0] === '[' || s.includes(']')) return tr("请输入不带方括号的地址");
  if (validateIPv4(s) === '' || validateIPv6(s) === '' || validateDomain(s) === '') return '';
  return tr("请输入合法的 IP 地址或域名");
}

// IP 或 CIDR 网段（v4 后缀 0-32，v6 后缀 0-128）；allowRange=true 额外允许「起始IP-结束IP」（同版本 IPv4）
export function validateCIDR(raw, opts = {}) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return tr("请输入 IP 地址或网段");
  if (s.includes('/')) {
    const idx = s.indexOf('/');
    const ip = s.slice(0, idx);
    const bits = s.slice(idx + 1);
    const isV6 = ip.includes(':');
    if (isV6) {
      if (validateIPv6(ip)) return tr("网段中的 IPv6 地址不合法");
      if (!/^\d{1,3}$/.test(bits) || Number(bits) > 128) return tr("IPv6 网段前缀范围为 0-128");
    } else {
      if (validateIPv4(ip)) return tr("网段中的 IPv4 地址不合法");
      if (!/^\d{1,2}$/.test(bits) || Number(bits) > 32) return tr("IPv4 网段前缀范围为 0-32");
    }
    return '';
  }
  if (opts.allowRange && s.includes('-')) {
    const [a, b] = s.split('-');
    if (s.split('-').length !== 2 || validateIPv4(a) || validateIPv4(b)) return tr("起止 IP 格式应为 192.168.1.1-192.168.1.20");
    return '';
  }
  return validateIPv6(s) === '' ? '' : validateIPv4(s);
}

// 主机:端口：domain:port / IPv4:port / [IPv6]:port
export function validateHostPort(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return tr("请输入 主机:端口，如 stun.example.com:3478");
  let host, port;
  if (s[0] === '[') {
    const end = s.indexOf(']');
    if (end === -1) return tr("IPv6 地址缺少右方括号 ]");
    host = s.slice(1, end);
    if (s[end + 1] !== ':') return tr("方括号后需跟 :端口");
    port = s.slice(end + 2);
    if (validateIPv6(host)) return tr("方括号内不是合法的 IPv6 地址");
  } else {
    const idx = s.lastIndexOf(':');
    if (idx === -1) return tr("缺少端口，格式应为 主机:端口");
    host = s.slice(0, idx);
    port = s.slice(idx + 1);
    if (host.includes(':') || host.includes('[')) return tr("IPv6 地址需用方括号，如 [2001:db8::1]:3478");
    if (validateIPv4(host) && validateDomain(host)) return tr("主机部分不是合法的 IP 或域名");
  }
  return validatePort(port);
}

// http/https URL：协议合法且其中主机名（IP 或域名）、端口合法
export function validateURL(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return tr("请输入 URL");
  let u;
  try {
    u = new URL(s);
  } catch {
    return tr("URL 格式不正确，应以 http:// 或 https:// 开头");
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return tr("URL 必须使用 http:// 或 https:// 协议");
  const host = u.hostname.startsWith('[') ? u.hostname.slice(1, -1) : u.hostname;
  if (validateIPv4(host) && validateIPv6(host) && validateDomain(host)) return tr("URL 中的主机名不合法");
  if (u.port && validatePort(u.port)) return tr("URL 中的端口不合法（范围 1-65535）");
  return '';
}

// 逗号分隔的域名列表（兼容中文逗号），每项按域名校验，wildcard=true 允许 *. 前缀
export function validateDomainList(raw, opts = {}) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return tr("请输入域名（多个域名用逗号分隔）");
  const list = s.split(/[,，]/).map((x) => x.trim()).filter(Boolean);
  if (!list.length) return tr("请输入域名（多个域名用逗号分隔）");
  for (const d of list) {
    const e = validateDomain(d, opts);
    if (e) return `「${d}」${e}`;
  }
  return '';
}

// DNS 主机记录名：@（根记录）、*（泛解析）、单段或多段 LDH 名称（不要求后缀）
export function validateRecordName(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return tr("请输入主机记录名（@ 表示根记录）");
  if (s === '@' || s === '*') return '';
  let name = s;
  if (name.startsWith('*.')) name = name.slice(2);
  if (name.length > 253) return tr("记录名总长度不能超过 253 个字符");
  for (const lb of name.split('.')) {
    if (!lb || lb.length > 63) return tr("记录名每段长度为 1-63 个字符");
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(lb)) {
      return tr("记录名只能包含字母、数字和连字符，且不能以连字符开头或结尾");
    }
  }
  return '';
}

// 端口扫描目标：IPv4/IPv6、CIDR 网段、IPv4 起止范围、域名 任一合法
export function validateScanTarget(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return tr("请输入 IP、网段或域名");
  if (s.includes('-') && !s.includes(':') && s.split('-').length === 2) {
    return validateCIDR(s, { allowRange: true });
  }
  if (validateIPv4(s) === '' || validateIPv6(s) === '' || validateDomain(s) === '') return '';
  return validateCIDR(s);
}

// 可见性感知的轮询：页面不可见（切标签 / 最小化 / 锁屏）时跳过请求，回到前台立即补一次。
// 为什么需要：浏览器不会对后台标签页的 setInterval 自动降频，而这些轮询拉的多是服务端
// 状态接口（其中 /api/forward/list 等要重扫系统连接表），后台常驻会让服务端 CPU 白烧。
// 返回值是停止函数，调用方在 onDestroy 时执行即可（替代 clearInterval）。
// 注意：本函数不负责首次加载，调用方保留自己的首次调用，避免引入重复请求。
export function pollVisible(fn, ms) {
  let stopped = false;
  const run = () => {
    if (!stopped && !document.hidden) fn();
  };
  const timer = setInterval(run, ms);
  // 可见性变化时也走一次 run：从隐藏转为可见会立即补一次请求（隐藏时 run 内自会跳过）
  document.addEventListener('visibilitychange', run);
  return () => {
    stopped = true;
    clearInterval(timer);
    document.removeEventListener('visibilitychange', run);
  };
}
