import { tr } from './i18n.js';
// API 客户端：自动识别飞牛统一网关前缀，所有请求走同源相对路径
// 服务端 gatewayStripMiddleware 会剥离 /app/TunHook 前缀，因此直接以根路径拼接即可

// 当前页面路径形如 /app/TunHook/ 或 /（本地开发）
const m = window.location.pathname.match(/^(\/app\/[^/]+)/);
export const apiBase = m ? m[1] : '';

// 通用 JSON 请求：自动携带 JSON body、解析 {success,data,error} 结构
export async function api(url, options = {}) {
  const init = {
    method: options.method || 'GET',
    headers: { 'Cache-Control': 'no-store' }
  };
  if (options.signal) init.signal = options.signal;
  if (options.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(options.body);
  }
  let resp;
  try {
    resp = await fetch(apiBase + url, init);
  } catch (e) {
    // 主动中断（超时/取消）时原样抛出，交由调用方区分 AbortError 与真实网络错误
    if (e && e.name === 'AbortError') throw e;
    throw new Error(tr("网络请求失败: ") + e.message);
  }
  let data = null;
  const text = await resp.text();
  try {
    data = text ? JSON.parse(text) : null;
  } catch (e) {
    data = null;
  }
  if (!resp.ok) {
    const msg = (data && data.error) || ('HTTP ' + resp.status);
    throw new Error(msg);
  }
  if (data && data.success === false) {
    throw new Error(data.error || tr("请求失败"));
  }
  return data ? data.data : null;
}

// 读取 NDJSON 流（端口扫描、批量检测等场景）：每行一个 JSON 对象，onLine 回调逐行处理。
// 第三个参数兼容两种形式：AbortSignal（旧调用）或 { signal, method, body } 请求配置。
export async function streamNDJSON(url, onLine, opts = {}) {
  const signal = (typeof AbortSignal !== 'undefined' && opts instanceof AbortSignal) ? opts : opts.signal;
  const init = { headers: { 'Cache-Control': 'no-cache' }, signal };
  if (opts.method) init.method = opts.method;
  if (opts.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.body);
  }
  const resp = await fetch(apiBase + url, init);
  if (!resp.ok || !resp.body) {
    throw new Error('HTTP ' + resp.status);
  }
  const reader = resp.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let buf = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      try {
        onLine(JSON.parse(line));
      } catch (e) {
        /* 忽略解析失败行 */
      }
    }
  }
  if (buf.trim()) {
    try {
      onLine(JSON.parse(buf.trim()));
    } catch (e) {
      /* ignore */
    }
  }
}
