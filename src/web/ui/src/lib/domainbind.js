// 「绑定域名 → 自动写解析」通用能力（MEFrp / LoliaFrp 共用）。
//
// 依赖的接口：
//   GET  /api/dns/all-domains       跨账户聚合「域名解析」模块里已有的域名
//   GET  /api/dns/records           列某账户某域名下的记录
//   POST /api/dns/record/add        新增记录
//   POST /api/dns/record/delete     删除记录
//   GET  /api/ports/dns             端口扫描模块的 DNS 查询（把域名解析成 IPv4）
//
// 为什么单独成模块：域名下拉、主机记录拆分、写记录、删记录这套逻辑两个页面完全一致，
// 各自实现会走样（例如删除时的「值必须匹配」这条安全约束只在一处生效）。
import { api } from './api.js';
import { tr } from './i18n.js';

// 主机记录方式下拉项：@ = 直接用根域名，子域名 = 前缀 + 根域名
export const HOST_MODE_OPTIONS = [
  { value: '@', label: '@（主域名）' },
  { value: 'sub', label: '子域名' }
];

// 拼完整域名：@ 直接用根域名；子域名需前缀（未填前缀视为未配置，返回空串）
export function composeFullDomain(root, mode, prefix) {
  const r = String(root || '').trim();
  if (!r) return '';
  if (mode !== 'sub') return r;
  const p = String(prefix || '').trim();
  return p ? `${p}.${r}` : '';
}

// 拉取「域名解析」模块全部账户下的域名，产出 CustomSelect 选项
export async function fetchDomainOptions() {
  const doms = await api('/api/dns/all-domains');
  return (doms || []).map((x) => ({
    value: x.name,
    label: x.account && x.account !== x.name ? `${x.name}（${x.account}）` : x.name,
    account: x.account
  }));
}

// 找出完整域名所属的根域名选项（多重后缀时取最长匹配），找不到返回 null
export function matchRootOption(full, options) {
  const v = String(full || '').trim().toLowerCase();
  if (!v) return null;
  return (
    (options || [])
      .filter((o) => {
        const d = String(o.value || '').toLowerCase();
        return d && (v === d || v.endsWith('.' + d));
      })
      .sort((a, b) => b.value.length - a.value.length)[0] || null
  );
}

// 完整域名 + 根域名 → 主机记录（根域名本身为 '@'）
export function hostRecordOf(full, rootValue) {
  const f = String(full || '').trim();
  const r = String(rootValue || '').trim();
  if (!f || !r || f.length <= r.length) return '@';
  return f.slice(0, f.length - r.length - 1);
}

// 把完整域名拆成「根域名 / 主机记录方式 / 前缀」供编辑态回填；
// 不在候选列表里时不强行改写，原值放 orphan 里由调用方原样保留。
export function splitFullDomain(full, options) {
  const f = String(full || '').trim();
  if (!f) return { root: '', mode: '@', prefix: '', orphan: '' };
  const opt = matchRootOption(f, options);
  if (!opt) return { root: '', mode: '@', prefix: '', orphan: f };
  if (f.toLowerCase() === opt.value.toLowerCase()) return { root: opt.value, mode: '@', prefix: '', orphan: '' };
  return { root: opt.value, mode: 'sub', prefix: f.slice(0, f.length - opt.value.length - 1), orphan: '' };
}

// 节点连接地址 → 记录类型与值：
//   IPv4 → A、IPv6 → AAAA；若是域名，先用端口扫描的 DNS 查询拿 IPv4（拿到就写 A），拿不到退化为 CNAME
export async function resolveRecordTarget(addr) {
  const a = String(addr || '').trim();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(a)) return { type: 'A', value: a };
  if (a.includes(':')) return { type: 'AAAA', value: a };
  const r = await api('/api/ports/dns?host=' + encodeURIComponent(a)).catch(() => null);
  const v4 = (r && r.a && r.a[0]) || '';
  return v4 ? { type: 'A', value: v4 } : { type: 'CNAME', value: a };
}

// 写入解析记录，返回实际写入的 { type, value }
export async function writeBindRecord({ account, root, rr, addr }) {
  const t = await resolveRecordTarget(addr);
  await api('/api/dns/record/add', {
    method: 'POST',
    body: { account, domain: root, rr, type: t.type, value: t.value, ttl: 600 }
  });
  return t;
}

// 供界面显示「解析目标」：把节点连接地址解析成最终会写进记录的类型与值。
// 拿不到就先返回 null，界面显示「正在解析…」，避免把节点域名误当成将要写入的地址。
export async function resolveDisplayTarget(addr) {
  const a = String(addr || '').trim();
  if (!a) return null;
  try {
    return await resolveRecordTarget(a);
  } catch (e) {
    return null;
  }
}

// 删除解析记录（隧道删除时清理）。安全约束：只删「主机记录 + 类型(A/AAAA/CNAME) + 值」都对得上的那条，
// 值须等于节点连接地址（CNAME）或它解析出的 IPv4/AAAA（A/AAAA），避免误删用户手工改过的记录。
// 返回：null = 该域名不归本模块管理，无需处理；{ notfound } = 归本模块但没匹配到；{ removed } = 已删除。
export async function removeBindRecord({ full, addr, options }) {
  const f = String(full || '').trim();
  if (!f) return null;
  const opt = matchRootOption(f, options);
  if (!opt) return null;
  const rr = hostRecordOf(f, opt.value);
  const a = String(addr || '').trim();
  const t = a ? await resolveRecordTarget(a) : { type: '', value: '' };
  const recs = await api(
    `/api/dns/records?account=${encodeURIComponent(opt.account)}&domain=${encodeURIComponent(opt.value)}`
  );
  const rec = (recs || []).find((r) => {
    if (String(r.name || '').toLowerCase() !== rr.toLowerCase()) return false;
    if (!/^(A|AAAA|CNAME)$/i.test(r.type || '')) return false;
    const rv = String(r.value || '').trim().toLowerCase();
    return (a && rv === a.toLowerCase()) || (t.value && rv === t.value.toLowerCase());
  });
  if (!rec) return { notfound: f };
  await api('/api/dns/record/delete', {
    method: 'POST',
    body: { account: opt.account, domain: opt.value, id: rec.id }
  });
  return { removed: `${f}（${rec.type} ${rec.value}）` };
}

// 拉取指定 frps 服务器地址对应的候选域名（含解析状态），后端已按「已解析在前」排序。
// 状态：wildcard = 该域名有泛解析指向该服务器（任意子域名开箱可用）；
//       root = 主域名指向该服务器；pending = 尚未指向该服务器。
export async function fetchServerDomainPicks(server) {
  const list = await api('/api/dns/domain-picks?server=' + encodeURIComponent(server));
  return (list || []).map((x) => ({
    value: x.name,
    label: pickLabel(x),
    account: x.account,
    status: x.status || 'pending'
  }));
}

// 候选选项文案：把解析状态直接写在选项里，避免用户选完才发现该域名没解析到这台服务器
export function pickLabel(x) {
  const s = x && x.status;
  const suffix = s === 'wildcard' ? tr('已解析') : s === 'root' ? tr('已解析（主域名）') : tr('暂未解析');
  return tr('{0}（{1}）', [(x && x.name) || '', suffix]);
}

// 该完整域名当前是否已解析到目标值（含被泛解析覆盖）——用于避免在已有泛解析的域名下重复写具体记录
async function hostResolvesTo(full, target) {
  const r = (await api('/api/ports/dns?host=' + encodeURIComponent(full)).catch(() => null)) || {};
  if (target.type === 'CNAME') {
    const want = String(target.value).replace(/\.$/, '').toLowerCase();
    return [r.cname, ...(r.cname_chain || [])]
      .filter(Boolean)
      .some((x) => String(x).replace(/\.$/, '').toLowerCase() === want);
  }
  const want = String(target.value).trim().toLowerCase();
  return [...(r.a || []), ...(r.aaaa || [])].some((x) => String(x).trim().toLowerCase() === want);
}

// 按需补写解析记录：域名没解析到该 frps 时，只写「这条隧道实际用到的那条主机记录」
// （@ = 主域名，子域名 = 该前缀），而不是泛解析——泛解析是多隧道共享的，删单个隧道时
// 无法安全回收，也会影响该域名下其它子域名。
// 已解析（含被泛解析覆盖）或已存在同名同值记录 → 跳过；同名但值不同 → 绝不覆盖，如实回报冲突。
// 返回 null 表示该域名不在本项目「域名解析」里（外部托管，无从写入）。
export async function ensureBindRecord({ full, addr, options }) {
  const f = String(full || '').trim();
  const a = String(addr || '').trim();
  if (!f || !a) return null;
  const opt = matchRootOption(f, options);
  if (!opt) return null;
  const rr = hostRecordOf(f, opt.value);
  const t = await resolveRecordTarget(a);
  if (await hostResolvesTo(f, t)) {
    return { skipped: 'resolved', root: opt.value, rr, type: t.type, value: t.value };
  }
  const recs =
    (await api(
      `/api/dns/records?account=${encodeURIComponent(opt.account)}&domain=${encodeURIComponent(opt.value)}`
    )) || [];
  const sameName = recs.filter(
    (r) => String(r.name || '').toLowerCase() === rr.toLowerCase() && /^(A|AAAA|CNAME)$/i.test(r.type || '')
  );
  if (sameName.some((r) => String(r.value || '').trim().toLowerCase() === t.value.toLowerCase())) {
    return { skipped: 'exists', root: opt.value, rr, type: t.type, value: t.value };
  }
  if (sameName.length) {
    const o = sameName[0];
    return { skipped: 'conflict', root: opt.value, rr, existType: o.type, existValue: o.value };
  }
  await api('/api/dns/record/add', {
    method: 'POST',
    body: { account: opt.account, domain: opt.value, rr, type: t.type, value: t.value, ttl: 600 }
  });
  return { written: { root: opt.value, rr, type: t.type, value: t.value } };
}
