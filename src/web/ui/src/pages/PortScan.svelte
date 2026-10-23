<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 端口扫描页面：本机端口占用 / IP·网段·域名扫描，展示端口·协议·服务·网页标题
  import { onMount, onDestroy, tick } from 'svelte';
  import { api, streamNDJSON } from '../lib/api.js';
  import { toast, activeTab, forwardPrefill, tunnelPrefill } from '../lib/stores.js';
  import { suggestDescription, suggestProxyName, portWebUrl, validateDomain, validateScanTarget, optional } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';
  import ConfirmModal from '../components/ConfirmModal.svelte';
  import Modal from '../components/Modal.svelte';
  import CustomSelect from '../components/CustomSelect.svelte';

  const MODES = [
    { id: 'local', label: i18nTr("本机端口") },
    { id: 'lan', label: i18nTr("IP扫描") },
    { id: 'dns', label: i18nTr("DNS查询") },
    { id: 'subd', label: i18nTr("子域名") }
  ];
  // DNS 记录类型（下拉选择）：all 走后端默认的常用类型集合，其余精确查询单一类型
  const DNS_RECORD_TYPES = [
    { value: 'all', label: i18nTr("全部") },
    { value: 'a', label: 'A' },
    { value: 'aaaa', label: 'AAAA' },
    { value: 'cname', label: 'CNAME' },
    { value: 'mx', label: 'MX' },
    { value: 'ns', label: 'NS' },
    { value: 'txt', label: 'TXT' },
    { value: 'soa', label: 'SOA' }
  ];
  // 端口范围分类（下拉选择）：各分类对应一组端口；common 不传端口→走后端默认常见端口集，all 传 ports=all
  // 全部端口列在第一位便于首选；默认选中仍是「常见端口」（portMode 初始值 common，见下方声明）
  const PORT_CATEGORIES = [
    { value: 'all', label: i18nTr("全部端口"), ports: [] },
    { value: 'common', label: i18nTr("常见端口"), ports: [] },
    { value: 'web', label: i18nTr("Web/面板"), ports: [80, 443, 3000, 5000, 5001, 8006, 8080, 8081, 8443, 8888, 9000, 9090, 9443, 2082, 2083, 10000] },
    { value: 'mail', label: i18nTr("邮件"), ports: [25, 110, 143, 465, 587, 993, 995] },
    { value: 'file', label: i18nTr("文件/共享"), ports: [20, 21, 22, 69, 139, 445, 548, 873, 989, 990, 2049] },
    { value: 'remote', label: i18nTr("远程访问"), ports: [22, 23, 3389, 5900, 5985, 5986, 1723, 1194] },
    { value: 'db', label: i18nTr("数据库"), ports: [1433, 1521, 3306, 5432, 6379, 9200, 27017, 11211, 9042, 8086, 9092, 2181] },
    { value: 'net', label: i18nTr("网络/监控"), ports: [53, 67, 68, 69, 123, 161, 162, 514, 830, 6653] },
    { value: 'game', label: i18nTr("游戏"), ports: [25565, 27015, 3074, 3724, 6112, 7777] }
  ];
  const WEB_PORTS = new Set([80, 443, 3000, 5000, 7000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 10000]);
  const DB_PORTS = new Set([1433, 1521, 3306, 5432, 6379, 11211, 27017, 9200]);
  const DOCKER_PORTS = new Set([2375, 2376, 2377, 4243]);

  let mode = 'local';
  let range = '';
  let items = [];
  let filter = 'all'; // 结果筛选：all / web / db / docker（点击统计卡片切换）
  let scanning = false;
  let lanInfo = null; // { start, end, cidr, ip } 自动识别局域网段
  let abort = null;
  let snapTime = '';   // 数据库快照的生成时间（仅在展示快照数据时显示，新扫描数据到达后清除）
  let lastScanAt = ''; // 本轮扫描完成时间（用于工具栏「上次扫描」提示）
  let lastScanMs = 0;  // 本轮扫描耗时（毫秒）
  let showScanSettings = false; // 扫描设置弹窗
  let lanScanned = false;  // 局域网：当前网段是否已执行过扫描（用于区分「未扫描」与「未发现在线主机」）
  let lanChecked = {};     // 局域网：已检查完且未发现主机的 IP → 1（扫描中实时把地址卡片翻转为「未使用」）
  let hostAlive = {};      // 局域网：「扫描IP」发现被使用（在线）的 IP → 1，无端口明细
  let lanScanning = null;  // 局域网：当前正在扫描的批次范围 {start,end}（后端分批推送，用于高亮当前批次卡片）
  let lanRangeKey = '';    // 网段扫描：上次生成地址卡片所用的网段标识（网段变化时重置扫描状态）
  let portMode = 'common';  // 端口范围分类（下拉选择）：common / web / mail / file / remote / db / net / game / all
  // 生成的扫描端口查询参数：common 不传走后端默认常见端口；分类传对应端口列表；all 传 ports=all
  $: portsParam = portMode === 'all' ? '&ports=all' : (portMode === 'common' ? '' : '&ports=' + (PORT_CATEGORIES.find((c) => c.value === portMode) || { ports: [] }).ports.join(','));
  let firstBatch = true; // 本次扫描是否尚未收到首条数据（true 时首条 item 会清掉列表，替换掉快照占位数据）
  let scanProgress = null; // IP 扫描进度 { done, total }（扫描中按钮显示「当前端口/总端口」）
  let scanStartT = 0;      // 本次扫描开始时间戳（用于估算扫描速度）
  // 域名扫描目标：输入的域名解析出的 IPv4 列表 { host, ips, chosen, action }；
  // 仅一个地址时自动选定并直接扫描，多个地址时展示出来由用户选择（action 记录触发解析的动作）
  let domainTarget = null;
  let resolving = false;   // 域名解析中（解析未完成前不进入扫描）
  // DNS 查询
  let dnsHost = '';     // 待查域名
  let dnsType = 'all';  // 记录类型（下拉选择）：all 查常用类型集合，其余精确查询单一类型
  let dnsLoading = false;
  let dnsResult = null; // { host, a, aaaa, cname, cname_chain, cdn, mx, ns, ns_vendor, txt, soa, ptr, duration_ms }
  // 子域名查询
  let subdHost = '';
  let subdLoading = false;
  let subdResult = null; // { host, count, found: [{name, ips, sources}], duration_ms }

  // 控制行容器：输入框都在横向 flex 行（.lan-controls）内，错误渲染到行外的 errAt 节点
  let dnsCtlEl;             // DNS/子域名查询控制行容器
  let subdErr;              // 子域名主机输入错误节点
  let dnsErr;               // DNS 主机输入错误节点
  let lanCtlEl;             // IP 扫描控制行容器
  let rangeErrLan;          // range 输入错误节点
  // range 校验口径：留空时自动识别本机所在网段（选填），手动输入时校验 IP/网段/域名格式
  $: rangeCheck = optional(validateScanTarget);

  function applyUpdate(u) {
    items = items.map((it) =>
      it.port === u.port && (it.protocol || u.protocol) === (u.protocol || it.protocol) && (it.local_addr || '') === (u.local_addr || '') ? { ...it, ...u } : it
    );
  }
  function onLine(o) {
    if (!o) return;
    if (o.type === 'item') {
      if (firstBatch) { items = []; snapTime = ''; firstBatch = false; }
      items = [...items, o.data];
    } else if (o.type === 'update') {
      applyUpdate(o.data);
    } else if (o.type === 'progress') {
      scanProgress = o.data; // { done, total } —— 更新扫描中按钮的进度
    } else if (o.type === 'scanning') {
      lanScanning = o.data; // 后端按 IP 顺序分批推送当前批次范围 {start,end}，用于高亮当前批次卡片
    } else if (o.type === 'checked') {
      // 某 IP 全部待检端口已检完且未发现主机 → 标记为「未使用」
      if (o.data) { lanChecked[o.data] = 1; lanChecked = lanChecked; }
    } else if (o.type === 'host') {
      // 「扫描IP」：该 IP 被使用（主机在线），并无端口明细
      if (o.data) { hostAlive[o.data] = 1; hostAlive = hostAlive; }
    } else if (o.type === 'error') {
      toast(o.message || i18nTr("扫描出错"), 'error');
    } else if (o.type === 'done') {
      scanning = false;
      lanScanned = true;
      lanScanning = null; // 扫描结束清除「当前批次」高亮
    }
  }

  // 输入是否为域名（排除单个 IPv4 / CIDR 网段 / 起始-结束 IP 范围）
  function isDomainName(t) {
    if (!t || t.includes('/')) return false;
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(t)) return false;
    if (/^\d{1,3}(?:\.\d{1,3}){3}\s*-\s*\d{1,3}(?:\.\d{1,3}){3}$/.test(t)) return false;
    return /^[a-zA-Z0-9_](?:[a-zA-Z0-9_-]*[a-zA-Z0-9_])?(?:\.[a-zA-Z0-9_](?:[a-zA-Z0-9_-]*[a-zA-Z0-9_])?)+\.?$/.test(t);
  }

  // 输入是否为单个 IPv4（各段 1-255/0 合法）：单主机直接进入端口扫描形态（无需扫存活、结果按端口展示）
  function isSingleIPv4(t) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((t || '').trim());
    return !!m && m.slice(1).every((n) => +n >= 0 && +n <= 255);
  }

  // 解析域名目标：返回可用于扫描的 IP——仅一个地址时自动选定，多个地址时返回空（等用户在面板中选择）。
  // action 记录本次解析由哪个动作触发（ports=扫描端口 / hosts=扫描IP），供选中地址后继续同一动作。
  async function resolveDomainTarget(t, action) {
    // 输入阶段已预解析（onRangeInput 防抖触发）：直接复用结果，避免点扫描时重复发起 DNS 请求
    if (domainTarget && domainTarget.host === t && Array.isArray(domainTarget.ips) && domainTarget.ips.length) {
      domainTarget = { ...domainTarget, action };
      if (domainTarget.ips.length === 1) domainTarget.chosen = domainTarget.ips[0];
      return domainTarget.chosen;
    }
    resolving = true;
    try {
      const res = await api('/api/ports/resolve?host=' + encodeURIComponent(t));
      const ips = (res && res.ips) || [];
      if (!ips.length) { domainTarget = null; toast(i18nTr("域名未解析到 IPv4 地址：") + t, 'error'); return ''; }
      domainTarget = { host: t, ips, chosen: ips.length === 1 ? ips[0] : '', action };
      if (ips.length > 1) toast(i18nTr("域名解析到 {0} 个 IP，请选择要扫描的地址", [ips.length]), 'info');
      return domainTarget.chosen;
    } catch (e) {
      domainTarget = null;
      toast(i18nTr("域名解析失败：") + e.message, 'error');
      return '';
    } finally {
      resolving = false;
    }
  }

  // 输入框内容变化：清除旧解析结果；若当前是域名则防抖 500ms 自动预解析（无需点扫描即可看到 A 记录 IP）。
  // 预解析失败静默处理（内网域名/无 DNS 时不弹错误，用户仍可点扫描触发带提示的解析）。
  let domainPreviewTimer = null;
  function onRangeInput() {
    domainTarget = null;
    if (domainPreviewTimer) clearTimeout(domainPreviewTimer);
    const t = (range || '').trim();
    if (!isDomainName(t)) return;
    domainPreviewTimer = setTimeout(async () => {
      domainPreviewTimer = null;
      if ((range || '').trim() !== t || !isDomainName(range)) return; // 输入已变化/不再是域名
      resolving = true;
      try {
        const res = await api('/api/ports/resolve?host=' + encodeURIComponent(t));
        if ((range || '').trim() !== t) return;
        const ips = (res && res.ips) || [];
        // 仅展示不自动扫描：单 IP 预选（点扫描时直接用），多 IP 留空等用户在面板中点选
        domainTarget = ips.length ? { host: t, ips, chosen: ips.length === 1 ? ips[0] : '', action: 'ports' } : null;
      } catch (e) { /* 预解析失败静默 */ } finally {
        resolving = false;
      }
    }, 500);
  }

  // 选择域名解析出的某个地址，并按触发解析时的动作立即开始扫描
  function pickDomainIP(ip) {
    if (!domainTarget) return;
    const action = domainTarget.action;
    domainTarget = { ...domainTarget, chosen: ip };
    if (action === 'hosts') scanHosts(); else scanIP();
  }

  function markScanDone() {
    lastScanAt = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    lastScanMs = scanStartT ? Date.now() - scanStartT : 0;
  }

  // 扫描耗时（秒，保留 1 位小数）：0 表示未知
  $: lastScanSec = lastScanMs > 0 ? (lastScanMs / 1000).toFixed(1) : '';
  // 端口范围下拉当前项文案（用于扫描控制行的范围摘要）
  $: portModeLabel = (PORT_CATEGORIES.find((c) => c.value === portMode) || { label: i18nTr("常见端口") }).label;

  // 扫描 IP：扫描目标（本机 / IP·网段·域名）的开放端口列表，网段扫描用服务端默认常见端口
  async function scanIP() {
    if (scanning) return;
    // 格式校验：当前控制行内 range 输入拦截（本机模式没有 range 控制行，跳过）
    if (lanCtlEl && !validateAll(lanCtlEl)) return;
    if (abort) abort.abort();
    abort = new AbortController();
    const my = abort; // 代际标识：切换模块/发起新扫描后，旧扫描的回调与收尾全部作废，避免「扫描中」状态串扰
    items = [];
    firstBatch = true;
    scanProgress = null;
    lanScanning = null;
    scanStartT = Date.now();
    scanning = true;
    lanScanned = false;
    lanChecked = {};
    hostAlive = {};
    try {
      if (mode === 'lan') {
        let r = range.trim();
        if (!r && lanInfo) r = `${lanInfo.start}-${lanInfo.end}`;
        if (!r) { toast(i18nTr("请输入 IP、网段或域名（留空将自动识别局域网网段）"), 'error'); scanning = false; return; }
        // 域名输入：先解析出 IPv4——仅一个地址直接扫描，多个地址等用户在面板中选择
        if (isDomainName(r)) {
          const ip = await resolveDomainTarget(r, 'ports');
          if (abort !== my) return;
          if (!ip) { scanning = false; return; }
          r = ip;
        }
        await streamNDJSON(`/api/ports/scan?mode=lan&range=${encodeURIComponent(r)}${portsParam}`, (o) => { if (abort === my) onLine(o); }, abort.signal);
        if (abort !== my) return;
        scanning = false;
        lanScanned = true; // 标记本轮扫描结束（单 IP 无结果时据此显示「未发现开放端口」）
        markScanDone();
      } else {
        // 本机扫描默认包含全部协议（ipv6=1 时服务端把 tcp6/udp6 监听也计入）
        await streamNDJSON(`/api/ports/scan?mode=local&ipv6=1`, (o) => { if (abort === my) onLine(o); }, abort.signal);
        if (abort !== my) return;
        scanning = false;
        markScanDone();
      }
    } catch (e) {
      if (abort !== my) return; // 旧扫描的收尾不触碰新扫描的状态
      if (e && e.name !== 'AbortError') toast(i18nTr("扫描 IP 失败：") + e.message, 'error');
      scanning = false;
    }
  }

  // 仅扫描被使用的 IP：探测网段内哪些主机在线（命中少量高价值端口即判定被使用），不扫描端口明细
  async function scanHosts() {
    if (scanning) return;
    // 格式校验：当前控制行内 range 输入拦截（本机模式没有 range 控制行，跳过）
    if (lanCtlEl && !validateAll(lanCtlEl)) return;
    if (abort) abort.abort();
    abort = new AbortController();
    const my = abort;
    items = [];
    hostAlive = {};
    firstBatch = true;
    scanProgress = null;
    lanScanning = null;
    scanStartT = Date.now();
    scanning = true;
    lanScanned = false;
    lanChecked = {};
    try {
      let r = range.trim();
      if (!r && lanInfo) r = `${lanInfo.start}-${lanInfo.end}`;
      if (!r) { toast(i18nTr("请输入 IP、网段或域名（留空将自动识别局域网网段）"), 'error'); scanning = false; return; }
      // 域名输入：先解析出 IPv4——仅一个地址直接扫描，多个地址等用户在面板中选择
      if (isDomainName(r)) {
        const ip = await resolveDomainTarget(r, 'hosts');
        if (abort !== my) return;
        if (!ip) { scanning = false; return; }
        r = ip;
      }
      await streamNDJSON(`/api/ports/scan?mode=lan&range=${encodeURIComponent(r)}&hosts=1`, (o) => { if (abort === my) onLine(o); }, abort.signal);
      if (abort !== my) return;
      scanning = false;
      lanScanned = true;
      markScanDone();
    } catch (e) {
      if (abort !== my) return;
      if (e && e.name !== 'AbortError') toast(i18nTr("扫描 IP 失败：") + e.message, 'error');
      scanning = false;
    }
  }

  function stopScan() {
    if (abort) abort.abort();
    scanning = false;
    lanScanned = true;
    lanScanning = null; // 停止扫描清除「当前批次」高亮
  }

  // DNS 查询：查询域名常用记录（A / AAAA / CNAME / MX / NS / TXT）
  async function lookupDNS() {
    if (dnsLoading) return;
    // 格式校验：控制行内域名输入拦截
    if (!validateAll(dnsCtlEl)) return;
    const h = dnsHost.trim();
    if (!h) { toast(i18nTr("请输入域名"), 'error'); return; }
    dnsLoading = true;
    dnsResult = null;
    try {
      dnsResult = await api('/api/ports/dns?host=' + encodeURIComponent(h) + '&type=' + dnsType);
    } catch (e) {
      toast(i18nTr("DNS 查询失败：") + e.message, 'error');
    } finally {
      dnsLoading = false;
    }
  }

  // DNS 结果辅助视图：PTR 反查映射（IP → PTR）、NS 服务商映射（域名 → 厂商）
  $: ptrMap = dnsResult ? Object.fromEntries((dnsResult.ptr || []).map((p) => [p.ip, p.ptr])) : {};
  $: nsVendorMap = dnsResult ? dnsResult.ns_vendor || {} : {};
  // 记录详情表格行：类型 / 值 / 附加信息（参考 srclab.cn 的表格布局）
  $: dnsRows = dnsResult ? buildDNSRows(dnsResult, ptrMap, nsVendorMap) : [];
  $: dnsTypeCount = new Set(dnsRows.map((r) => r.type)).size;
  // 各记录类型的服务状态探测目标：A/AAAA → 查询域；CNAME/MX/NS/SOA → 记录值主机；TXT 不可探测
  function buildDNSRows(res, pm, nv) {
    const host0 = (res.host || '').replace(/\.$/, '');
    const rows = [];
    for (const v of res.a || []) rows.push({ type: 'A', cls: 't-a', value: v, extra: pm[v] ? 'PTR ' + pm[v] : '', probe: host0 });
    for (const v of res.aaaa || []) rows.push({ type: 'AAAA', cls: 't-aaaa', value: v, extra: '', probe: host0 });
    for (const h of res.cname_chain || []) rows.push({ type: 'CNAME', cls: 't-cname', value: h.to, extra: i18nTr("来自 ") + h.from, probe: h.to });
    for (const m of res.mx || []) rows.push({ type: 'MX', cls: 't-mx', value: m.host, extra: i18nTr("优先级 ") + m.pref, probe: m.host });
    for (const v of res.ns || []) rows.push({ type: 'NS', cls: 't-ns', value: v, extra: nv[v] || '', probe: v });
    for (const v of res.txt || []) rows.push({ type: 'TXT', cls: 't-txt', value: v, extra: '', probe: '' });
    for (const v of res.soa || []) rows.push({ type: 'SOA', cls: 't-soa', value: v, extra: '', probe: '' });
    return rows;
  }
  // 服务状态探测：host → {ok: true 延迟ms / false 离线 / null 探测中}
  let probeMap = {};
  // 批量探测（结果合并进 probeMap，两张 DNS 表共用同一份结果）
  async function runProbe(hosts) {
    hosts = [...new Set(hosts.map((h) => (h || '').trim().replace(/\.$/, '')).filter(Boolean))].slice(0, 32);
    if (!hosts.length) return;
    const add = {};
    for (const h of hosts) add[h] = { ok: null, ms: 0, code: 0 };
    probeMap = { ...probeMap, ...add };
    try {
      const res = await api('/api/ports/http-probe?hosts=' + encodeURIComponent(hosts.join(',')));
      const merged = { ...probeMap };
      for (const h of hosts) if (res && res.probes && res.probes[h]) merged[h] = res.probes[h];
      probeMap = merged;
    } catch (e) {
      const merged = { ...probeMap };
      for (const h of hosts) if (merged[h] && merged[h].ok === null) merged[h] = { ok: false, ms: 0, code: 0 };
      probeMap = merged;
    }
  }
  // DNS 查询结果 → 待探测主机集合
  function probeTargetsOfDNS(res) {
    const hosts = [];
    const h = (res.host || '').replace(/\.$/, '');
    if ((res.a || []).length || (res.aaaa || []).length) hosts.push(h);
    for (const c of res.cname_chain || []) hosts.push(c.to);
    for (const m of res.mx || []) hosts.push(m.host);
    for (const n of res.ns || []) hosts.push(n);
    return hosts.map((x) => (x || '').trim().replace(/\.$/, '')).filter((x) => x && !x.startsWith('*.'));
  }
  // 子域名结果 → 待探测主机集合（解析出 IP 的子域名 + NS + SOA）
  function probeTargetsOfSubd(res) {
    const hosts = [];
    for (const f of res.found || []) {
      if (f.ips && f.ips.length && !f.name.startsWith('*.')) hosts.push(f.name);
    }
    for (const n of res.ns || []) hosts.push(n);
    if (res.soa) hosts.push(res.soa);
    return hosts.map((x) => (x || '').trim().replace(/\.$/, '')).filter((x) => x && !x.startsWith('*.'));
  }
  // 复制 CNAME 链路（from → to 逐级换行）
  function copyDNSChain(chain) {
    if (!chain || !chain.length) return;
    const lines = [chain[0].from];
    for (const h of chain) lines.push(h.to);
    copyText(lines.join('\n'), i18nTr("CNAME 链路"));
  }

  // 子域名查询：字典枚举 + 证书透明度日志
  async function lookupSubd() {
    if (subdLoading) return;
    // 格式校验：控制行内域名输入拦截
    if (!validateAll(dnsCtlEl)) return;
    const h = subdHost.trim();
    if (!h) { toast(i18nTr("请输入域名"), 'error'); return; }
    subdLoading = true;
    subdResult = null;
    try {
      subdResult = await api('/api/ports/subdomains?host=' + encodeURIComponent(h));
      runProbe(probeTargetsOfSubd(subdResult));
    } catch (e) {
      toast(i18nTr("子域名查询失败：") + e.message, 'error');
    } finally {
      subdLoading = false;
    }
  }
  // 子域名表格行：来源徽章（字典 / 证书 / 字典+证书 / 泛解析通配记录）
  function subdSource(f) {
    const s = f.sources || [];
    if (s[0] === 'wildcard') return { label: i18nTr("泛解析"), cls: 't-txt' };
    if (s.length > 1) return { label: i18nTr("字典+证书"), cls: 't-aaaa' };
    if (s[0] === 'crt') return { label: i18nTr("证书"), cls: 't-ns' };
    return { label: i18nTr("字典"), cls: 't-a' };
  }
  let showWildcard = false; // 是否显示泛解析命中的字典噪声行
  $: subdAll = subdResult ? (subdResult.found || []).map((f) => ({ ...f, src: subdSource(f) })) : [];
  $: subdWildCount = subdAll.filter((r) => r.wildcard && !(r.sources || []).includes('wildcard')).length;
  // 可信集（非泛解析噪声 + 通配条目），用于概览 chips；通配条目 *.host 始终展示
  $: subdClean = subdAll.filter((r) => !r.wildcard || (r.sources || []).includes('wildcard'));
  // chips 展示顺序：通配条目排最前，其余按名称排序
  $: subdChips = [...subdClean].sort((a, b) => {
    const wa = a.name.startsWith('*.') ? 0 : 1;
    const wb = b.name.startsWith('*.') ? 0 : 1;
    if (wa !== wb) return wa - wb;
    return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  });
  // 表格行集：默认仅可信，开关打开后加入泛解析噪声
  $: subdShown = showWildcard ? subdAll : subdClean;
  // 记录详情行（对齐参考站）：每个子域名每个 IP 一行，主域 NS/SOA/TXT 与 _dmarc TXT 各成行
  $: subdTableRows = (() => {
    if (!subdResult) return [];
    const h = subdResult.host;
    const rows = [];
    for (const r of subdShown) {
      if (r.ips && r.ips.length) {
        const tgt = r.name.startsWith('*.') ? '' : r.name; // 泛解析通配条目无法探测
        for (const ip of r.ips) rows.push({ name: r.name, badge: 'A', type: 'A', cls: 't-a', val: ip, probe: tgt });
      } else {
        rows.push({ name: r.name, badge: 'A', type: 'A', cls: 't-a', val: r.wildcard ? i18nTr("泛解析") : i18nTr("未解析"), dim: true, probe: '' });
      }
    }
    for (const ns of subdResult.ns || []) rows.push({ name: h, badge: 'N', type: 'NS', cls: 't-ns', val: ns, probe: ns });
    if (subdResult.soa) rows.push({ name: h, badge: 'S', type: 'SOA', cls: 't-soa', val: subdResult.soa, probe: subdResult.soa });
    for (const t of subdResult.txt || []) rows.push({ name: h, badge: 'T', type: 'TXT', cls: 't-txt', val: t, probe: '' });
    for (const t of subdResult.dmarc_txt || []) rows.push({ name: '_dmarc.' + h, badge: 'T', type: 'TXT', cls: 't-txt', val: t, probe: '' });
    // 排序对齐参考站：主域最前，其余按名称（* < 数字字母 < _）
    rows.sort((a, b) => {
      const ka = a.name === h ? '' : a.name;
      const kb = b.name === h ? '' : b.name;
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
    return rows;
  })();
  $: dnsTotal = subdTableRows.length;
  $: subdDnsTypeCount = new Set(subdTableRows.map((r) => r.type)).size;
  $: subdTypeStats = ['A', 'NS', 'SOA', 'TXT']
    .map((t) => ({ t, n: subdTableRows.filter((r) => r.type === t).length }))
    .filter((x) => x.n);

  // ---- 卡片右上角「⋯」常用功能菜单 ----
  let menuKey = null;      // 当前展开菜单的卡片标识
  // 菜单统一用 fixed 定位（逃出 .ps-cards 与 .modal-body 的 overflow 裁剪），按点击按钮的屏幕坐标摆放
  let menuPos = { top: 0, right: 0 };
  // 切换「⋯」菜单：同一按钮再次点击收起；坐标取按钮矩形右下角，避免被滚动容器裁掉
  function toggleMenu(key, e) {
    if (menuKey === key) {
      menuKey = null;
      return;
    }
    const r = e.currentTarget.getBoundingClientRect();
    menuPos = { top: r.bottom + 4, right: Math.max(4, window.innerWidth - r.right - 4) };
    menuKey = key;
  }
  // 菜单为 fixed 定位（不随内容滚动），滚动时直接收起，避免菜单与按钮错位
  function closeMenuOnScroll() {
    if (menuKey) menuKey = null;
  }
  let killTarget = null;   // 待确认结束的进程
  let portView = null;     // 查看端口弹窗：当前查看主机的端口列表（{port,protocols,service,web_title}[]）
  let portViewIp = '';     // 查看端口弹窗对应的主机 IP
  // 打开「查看端口」弹窗：展示某主机的全部开放端口
  function openPortView(ip, ports) {
    menuKey = null; // 打开弹窗前关闭可能展开的「⋯」菜单
    portViewIp = ip;
    portView = ports;
  }
  let killBusy = false;

  // 卡片唯一键：首地址+端口（合并后的卡片在本机模式按端口唯一、局域网模式按主机+端口唯一）
  function itemKey(it) {
    return (it.addrs && it.addrs[0] ? it.addrs[0] : '') + ':' + it.port;
  }
  // 访问/探测用的主机地址：通配监听地址替换为回环
  function probeHost(it) {
    const a = (it.addrs && it.addrs[0] ? it.addrs[0] : '').trim();
    if (!a || a === '0.0.0.0') return '127.0.0.1';
    if (a === '::' || a === '::0') return '::1';
    return a;
  }
  function copyText(t, label) {
    navigator.clipboard.writeText(t)
      .then(() => toast(i18nTr("已复制") + label + ': ' + t, 'success'))
      .catch(() => toast(i18nTr("复制失败"), 'error'));
    menuKey = null;
  }
  // 浏览器打开：用当前访问 TunHook 的主机地址打开（回环/通配监听不再映射为 127.0.0.1，
  // 否则从其他机器访问管理界面时 127.0.0.1 会指向用户自己的机器导致打不开）；
  // 监听在具体地址（如 192.168.1.5）时仍用该地址。
  function openBrowser(it) {
    const url = portWebUrl((it.addrs && it.addrs[0]) || '', it.port, window.location.hostname);
    window.open(url, '_blank');
    menuKey = null;
  }
  // 跳转「端口转发」页并预填创建表单
  function createForward(it) {
    forwardPrefill.set({
      protocol: it.protocols.some((p) => p.startsWith('tcp')) ? 'tcp' : 'udp',
      local_port: it.port,
      local_addr: (it.addrs && it.addrs[0]) || '',
      description: suggestDescription(it)
    });
    menuKey = null;
    activeTab.set('forward');
  }
  // 跳转「内网穿透」页并预填创建隧道表单（本地地址/端口/建议名称）
  function createTunnel(it) {
    tunnelPrefill.set({
      ip: probeHost(it),
      port: it.port,
      name: suggestProxyName(it)
    });
    menuKey = null;
    activeTab.set('tunnel');
  }
  // ---- 命令窗口弹窗：端口探测 / Ping 以类终端形式展示命令与输出 ----
  let term = null; // { title, lines: [{ text, cls, cmd }], running }
  let termScroll;

  // 追加一行输出并滚动到底部
  function termLine(text, cls = '', cmd = false) {
    term = { ...term, lines: [...term.lines, { text, cls, cmd }] };
    tick().then(() => { if (termScroll) termScroll.scrollTop = termScroll.scrollHeight; });
  }

  // 端口探测：显示 nc 风格命令行与 TCP 探测结果（后端为 Go 原生探测，输出行仿照 nc）
  async function probePort(it) {
    menuKey = null;
    const addr = probeHost(it);
    term = { title: i18nTr("端口探测 {0}:{1}", [addr, it.port]), lines: [], running: true };
    termLine(`nc -zv -w 3 ${addr} ${it.port}`, 't-cmd', true);
    try {
      const d = await api('/api/ports/probe', { method: 'POST', body: { addr, port: it.port } });
      if (d && d.ok) {
        termLine(i18nTr("Connection to {0} {1} port [tcp/*] succeeded!（耗时 {2}ms）", [addr, it.port, d.latency_ms]), 't-ok');
      } else {
        termLine(`nc: connect to ${addr} port ${it.port} (tcp) failed: ${d && d.error ? d.error : i18nTr("超时")}`, 't-err');
      }
    } catch (e) {
      termLine(i18nTr("探测失败：") + e.message, 't-err');
    }
    term = { ...term, running: false };
  }

  // Ping：显示真实执行的 ping 命令与原文输出（后端返回 output）
  async function pingHost(it) {
    menuKey = null;
    const addr = probeHost(it);
    term = { title: `Ping ${addr}`, lines: [], running: true };
    termLine(`ping -c 4 -W 2 ${addr}`, 't-cmd', true);
    try {
      const d = await api('/api/ports/ping', { method: 'POST', body: { addr } });
      if (d && d.output) d.output.split(/\r?\n/).forEach((l) => l.trim() !== '' && termLine(l));
      if (d && d.ok) {
        termLine(i18nTr("--- 统计：平均 {0}，丢包 {1} ---", [d.avg_ms != null ? d.avg_ms + 'ms' : '-', d.loss != null ? d.loss + '%' : '-']), 't-ok');
        if (d.ttl != null) {
          termLine(i18nTr("--- TTL {0} · 推断系统 {1} ---", [d.ttl, d.os_hint || '未知']), 't-ok');
        }
      } else {
        termLine(i18nTr("--- {0} Ping 不通", [addr]) + (d && d.loss != null ? i18nTr("（丢包 {0}%）", [d.loss]) : '') + ' ---', 't-err');
      }
    } catch (e) {
      termLine(i18nTr("Ping 失败：") + e.message, 't-err');
    }
    term = { ...term, running: false };
  }
  async function confirmKill() {
    killBusy = true;
    try {
      await api('/api/ports/kill', { method: 'POST', body: { pid: killTarget.pid } });
      toast(i18nTr("已结束进程 PID ") + killTarget.pid + (killTarget.process ? ' (' + killTarget.process + ')' : ''), 'success');
      killTarget = null;
      if (mode === 'local') scanIP(); // 重新扫描刷新列表
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      killBusy = false;
    }
  }

  function switchMode(m) {
    if (abort) abort.abort(); // 切换模块即取消进行中的扫描：结果对新视图无意义，也避免「扫描中」串扰显示
    scanning = false;
    mode = m;
    items = [];
    filter = 'all';
    if (m === 'local') scanIP();
  }

  // 同端口多条记录合并为一张卡片，协议（tcp/tcp6/udp/udp6）以标签并列展示。
  // 本机模式按端口合并；局域网模式按 主机:端口 合并（不同主机同端口不能混在一张卡）。
  function mergeByPort(list, m) {
    const byKey = new Map();
    for (const it of list) {
      const key = m === 'lan' ? (it.local_addr || '') + ':' + it.port : String(it.port);
      let g = byKey.get(key);
      if (!g) {
        g = { port: it.port, protocols: [], addrs: [], pids: [], service: '', web_title: '', process: '' };
        byKey.set(key, g);
      }
      const proto = it.protocol || 'tcp';
      if (!g.protocols.includes(proto)) g.protocols.push(proto);
      if (it.local_addr && !g.addrs.includes(it.local_addr)) g.addrs.push(it.local_addr);
      if (!g.service && it.service) g.service = it.service;
      if (!g.web_title && it.web_title) g.web_title = it.web_title;
      if (!g.process && it.process) g.process = it.process;
      if (it.pid > 0 && !g.pids.some((p) => p.pid === it.pid)) g.pids.push({ pid: it.pid, process: it.process || '' });
    }
    return [...byKey.values()];
  }
  $: sorted = mergeByPort(items, mode).sort((a, b) => (a.port || 0) - (b.port || 0));
  $: filtered = sorted.filter((it) => matchGroup(it, filter));
  // 剩余可用端口：总量按 1~65535，按唯一端口号去重（TCP/UDP 同端口算一个），不受筛选影响
  $: usedPortCount = new Set(items.map((i) => i.port).filter(Boolean)).size;
  $: freePorts = 65535 - usedPortCount;
  $: freePct = ((freePorts / 65535) * 100).toFixed(2);
  // 本机端口分类统计（与筛选页签口径一致）
  $: webCount = sorted.filter((it) => matchGroup(it, 'web')).length;
  $: dbCount = sorted.filter((it) => matchGroup(it, 'db')).length;
  $: dockerCount = sorted.filter((it) => matchGroup(it, 'docker')).length;

  // 端口卡片：服务类型徽章配色（对齐演示页的 HTTP/HTTPS、数据库、Docker、SSH 分类）
  function portBadge(it) {
    const s = (it.service || '').toLowerCase();
    const p = it.port || 0;
    if (s.includes('https') || s.includes('ssl') || s.includes('tls')) return 'badge-on';
    if (s.includes('mysql') || s.includes('postgres') || s.includes('redis') || s.includes('mongo') || DB_PORTS.has(p)) return 'badge-violet';
    if (s.includes('docker') || DOCKER_PORTS.has(p)) return 'badge-blue';
    if (s.includes('ssh') || p === 22) return 'badge-off';
    return 'badge-info';
  }
  function portBadgeText(it) {
    return it.service || (it.protocols || []).map((x) => String(x).toUpperCase()).join(' / ') || 'TCP';
  }
  // 进程信息优先；无进程名时退回网页标题 / 监听地址，保证卡片信息行不为空
  function portProc(it) {
    return it.process || it.web_title || (it.addrs || []).join(', ') || '-';
  }

  // 按页签归类：Docker 按进程名或 Docker 常用端口，数据库按常用端口，WEB 按常用端口或探测到网页标题
  // 注意：filter 必须由响应式语句显式传入，写在函数体内 Svelte 追踪不到依赖
  function matchGroup(it, f) {
    if (f === 'all') return true;
    const p = it.port || 0;
    if (f === 'docker') return (it.process || '').toLowerCase().includes('docker') || DOCKER_PORTS.has(p);
    if (f === 'db') return DB_PORTS.has(p);
    if (f === 'web') return WEB_PORTS.has(p) || !!it.web_title;
    return true;
  }

  // ---- 局域网地址卡片：按输入网段（CIDR / 起始-结束 / 单IP）或自动识别网段生成全部地址 ----
  function ipToUint(v) {
    const p = String(v).trim().split('.');
    if (p.length !== 4) return null;
    let u = 0;
    for (const x of p) {
      const n = Number(x);
      if (!/^\d{1,3}$/.test(x) || n > 255) return null;
      u = u * 256 + n;
    }
    return u >>> 0;
  }
  // 判断 IP 是否落在「当前批次」范围内（后端按 IP 顺序分批推进，前端据此高亮当前批次）
  function inScanningRange(ip) {
    if (!lanScanning || !lanScanning.start || !lanScanning.end) return false;
    const u = ipToUint(ip), s = ipToUint(lanScanning.start), e = ipToUint(lanScanning.end);
    return u != null && s != null && e != null && u >= s && u <= e;
  }
  function uintToIp(u) {
    return [(u >>> 24) & 255, (u >>> 16) & 255, (u >>> 8) & 255, u & 255].join('.');
  }
  // 与后端 parseIPRange 同口径：CIDR 展开含网络/广播地址，最多 1024 个（lanScanMaxIPs）
  function buildLanIPs(rangeStr, info) {
    let t = (rangeStr || '').trim();
    if (!t && info) t = `${info.start}-${info.end}`;
    if (!t) return { ips: [] };
    const cidr = t.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (cidr) {
      const base = ipToUint(cidr[1]);
      const bits = Number(cidr[2]);
      if (base === null || bits < 1 || bits > 32) return { error: i18nTr("无效的 IPv4 网段：") + t, ips: [] };
      const mask = (bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0);
      const start = (base & mask) >>> 0;
      const count = 2 ** (32 - bits);
      return buildLanIPList(start, start + count - 1);
    }
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(t)) {
      const u = ipToUint(t);
      return u === null ? { error: i18nTr("无效的 IPv4 地址：") + t, ips: [] } : buildLanIPList(u, u);
    }
    // 域名：本身无法展开为地址卡片，解析出 IP 后按选定的地址生成（此处不报错）
    if (isDomainName(t)) return { ips: [] };
    const parts = t.split('-');
    if (parts.length === 2) {
      const a = ipToUint(parts[0]);
      const b = ipToUint(parts[1]);
      if (a === null || b === null) return { error: i18nTr("IP 地址无效：") + t, ips: [] };
      if (a > b) return { error: i18nTr("结束 IP 不能小于起始 IP"), ips: [] };
      return buildLanIPList(a, b);
    }
    return { error: i18nTr("IP 范围格式应为「起始IP-结束IP」「CIDR 网段」或「单个 IP」"), ips: [] };
  }
  function buildLanIPList(start, end) {
    const count = end - start + 1;
    if (count > 1024) return { error: i18nTr("IP 范围过大（最多支持 1024 个地址，当前 {0} 个），请缩小范围", [count]), ips: [] };
    const ips = [];
    for (let u = start; u <= end; u++) ips.push(uintToIp(u >>> 0));
    return { ips };
  }
  // 扫描发现结果按 IP 归组（在线主机 → 端口/协议/标题汇总）
  function buildLanFound(list) {
    const m = {};
    for (const it of list) {
      const ip = (it.local_addr || '').trim();
      if (!ip) continue;
      let g = m[ip];
      if (!g) g = m[ip] = { ip, addrs: [ip], port: it.port || 0, ports: [], protocols: [], service: '', web_title: '', process: '', pids: [] };
      if (it.port > 0 && !g.ports.includes(it.port)) g.ports.push(it.port);
      const proto = it.protocol || 'tcp';
      if (!g.protocols.includes(proto)) g.protocols.push(proto);
      if (!g.service && it.service) g.service = it.service;
      if (!g.web_title && it.web_title) g.web_title = it.web_title;
      if (!g.process && it.process) g.process = it.process;
      if (it.pid > 0 && !g.pids.some((x) => x.pid === it.pid)) g.pids.push({ pid: it.pid, process: it.process || '' });
    }
    return m;
  }
  // 网段扫描按「主机」聚合：一台主机（IP）一份，内含其全部开放端口（供一台一卡渲染）
  function buildLanHostCards(list) {
    const m = {};
    for (const it of list) {
      const ip = (it.local_addr || '').trim();
      if (!ip || !(it.port > 0)) continue;
      let h = m[ip];
      if (!h) h = m[ip] = { ip, ports: [], service: '', web_title: '' };
      let e = h.ports.find((x) => x.port === it.port);
      if (!e) { e = { port: it.port, protocols: [], service: '', web_title: '', latency_ms: it.latency_ms || 0 }; h.ports.push(e); }
      const proto = it.protocol || 'tcp';
      if (!e.protocols.includes(proto)) e.protocols.push(proto);
      if (!e.service && it.service) e.service = it.service;
      if (!e.web_title && it.web_title) e.web_title = it.web_title;
      if ((!e.latency_ms || e.latency_ms <= 0) && it.latency_ms > 0) e.latency_ms = it.latency_ms;
      if (!h.service && it.service) h.service = it.service;
      if (!h.web_title && it.web_title) h.web_title = it.web_title;
    }
    for (const ip in m) m[ip].ports.sort((a, b) => a.port - b.port);
    return Object.values(m);
  }
  $: isRangeMode = mode === 'lan';
  // 输入为单个 IPv4 时进入单主机端口扫描形态（隐藏「扫描IP」、结果按端口号卡片展示）
  $: singleIP = isRangeMode && isSingleIPv4(range);
  // IP 扫描：输入框留空时自动填充识别到的本网段（CIDR 如 192.168.1.0/24；无 cidr 时回退 start-end）
  $: if (mode === 'lan' && !range && lanInfo) {
    if (lanInfo.cidr) { range = lanInfo.cidr; }
    else if (lanInfo.start && lanInfo.end) { range = `${lanInfo.start}-${lanInfo.end}`; }
  }
  // 扫描实际目标：输入域名时用解析后选定的 IP，否则用输入框内容（域名本身无法展开为地址卡片）
  $: scanTarget = domainTarget && domainTarget.chosen ? domainTarget.chosen : range;
  $: lanIPs = isRangeMode ? buildLanIPs(scanTarget, lanInfo) : { ips: [] };
  $: lanFound = isRangeMode ? buildLanFound(items) : {};
  $: lanHostCards = isRangeMode ? buildLanHostCards(items) : [];
  $: lanHostMap = Object.fromEntries(lanHostCards.map((h) => [h.ip, h]));
  // IP 扫描统计：在线主机 / 开放端口 / 未使用 / 待检。
  // 与卡片渲染口径一致：有主机卡片或「扫描IP」判定的在线 IP 计「在线」，无主机且（已检完或扫描结束）计「未使用」，其余计「待检」
  $: lanOnlineCount = lanIPs.ips.filter((ip) => !!lanHostMap[ip] || !!hostAlive[ip]).length;
  $: lanUnusedCount = lanIPs.ips.filter((ip) => !(!!lanHostMap[ip] || !!hostAlive[ip]) && (lanChecked[ip] === 1 || (lanScanned && !scanning))).length;
  $: lanPendingCount = lanIPs.ips.length - lanOnlineCount - lanUnusedCount;
  $: lanPortCount = lanHostCards.reduce((n, h) => n + h.ports.length, 0);
  // 扫描速度（TPS，每秒完成的探测任务数）：用进度 done 与耗时估算；连接延时后端未下发，暂无法计算
  $: lanScanSpeed = scanProgress && scanStartT && scanProgress.done > 0 ? Math.round(scanProgress.done / ((Date.now() - scanStartT) / 1000)) : 0;
  // 模式或扫描目标（网段 / 自动识别结果 / 域名选定的 IP）变化时重置「已扫描」状态
  $: {
    const k = (isRangeMode ? (scanTarget || '').trim() + '|' + (lanInfo ? lanInfo.start + '-' + lanInfo.end : '') : '') + '|' + mode;
    if (k !== lanRangeKey) { lanRangeKey = k; lanScanned = false; lanChecked = {}; hostAlive = {}; }
  }

  async function loadLanInfo() {
    try {
      lanInfo = await api('/api/ports/laninfo', { method: 'GET' });
    } catch (e) { /* 忽略 */ }
  }

  // 进入页面先展示数据库中的上次扫描快照（立即有数据），新扫描数据到达后自动替换
  async function loadSnapshot() {
    try {
      const d = await api('/api/ports/snapshot', { method: 'GET' });
      // 仅在尚未收到本次扫描数据时填充（items 非空说明新数据已先到达，快照过期无需展示）
      if (d && Array.isArray(d.items) && d.items.length && !items.length) {
        items = d.items;
        snapTime = d.updated_at || '';
      }
    } catch (e) { /* 忽略 */ }
  }

  onMount(() => {
    loadLanInfo();
    loadSnapshot(); // 先展示上次扫描快照
    scanIP(); // 进入即自动重扫本机端口占用（扫描完成服务端自动更新快照）
    // 捕获阶段监听，内层滚动容器（.ps-cards）滚动也能收到
    window.addEventListener('scroll', closeMenuOnScroll, true);
  });
  onDestroy(() => {
    if (abort) abort.abort();
    window.removeEventListener('scroll', closeMenuOnScroll, true);
  });
</script>

<div class="container">
  <div class="page-hdr">
    <div>
      <h2>{$i18n("端口扫描")}</h2>
      <span class="page-hdr-sub">{$i18n("本机端口占用 · IP / 网段 / 域名扫描 · TCP 连通性探测 · 服务识别与网页标题 · DNS 记录与子域名查询")}</span>
    </div>
    <div class="page-hdr-actions">
      <button class="btn" on:click={() => (showScanSettings = true)} title={$i18n("扫描设置")}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3"/><path d="M1 14h6M9 8h6M17 16h6"/></svg>
        <span class="sm-hide">{$i18n("扫描设置")}</span>
      </button>
    </div>
  </div>

  <div class="scan-toolbar">
    <div class="mode-switch">
      {#each MODES as m}
        <button class="mode-btn" class:active={mode === m.id} on:click={() => switchMode(m.id)}>{m.label}</button>
      {/each}
    </div>
    {#if mode === 'dns' && dnsResult}
      <span class="scan-count">{$i18n("查询耗时")} {dnsResult.duration_ms} ms</span>
    {:else if mode === 'subd' && subdResult}
      <span class="scan-count">{$i18n("查询耗时")} {subdResult.duration_ms} ms</span>
    {/if}
  </div>

  {#if mode === 'dns' || mode === 'subd'}
    <div class="lan-controls" bind:this={dnsCtlEl}>
      {#if mode === 'subd'}
        <input type="text" bind:value={subdHost} placeholder={$i18n("域名 如 example.com")} style="width:220px" on:keydown={(e) => e.key === 'Enter' && lookupSubd()} use:field={{ check: (v) => validateDomain(v, { allowUnderscore: true }), errAt: () => subdErr }} />
        {#if !subdLoading}
          <button class="btn btn-primary" on:click={lookupSubd}>{$i18n("查询")}</button>
        {:else}
          <button class="btn scanning-btn" title={$i18n("查询中")}>
            <span class="spinner"></span>{$i18n("查询中")}
          </button>
        {/if}
      {:else}
        <input type="text" bind:value={dnsHost} placeholder={$i18n("域名 如 example.com")} style="width:220px" on:keydown={(e) => e.key === 'Enter' && lookupDNS()} use:field={{ check: (v) => validateDomain(v, { allowUnderscore: true }), errAt: () => dnsErr }} />
        <CustomSelect bind:value={dnsType} options={DNS_RECORD_TYPES} width="96px" />
        {#if !dnsLoading}
          <button class="btn btn-primary" on:click={lookupDNS}>{$i18n("查询")}</button>
        {:else}
          <button class="btn scanning-btn" title={$i18n("查询中")}>
            <span class="spinner"></span>{$i18n("查询中")}
          </button>
        {/if}
      {/if}
    </div>
    <div class="field-err" bind:this={subdErr} style="display:none"></div>
    <div class="field-err" bind:this={dnsErr} style="display:none"></div>
  {/if}

  {#if mode === 'subd'}
    {#if subdLoading}
      <div class="ps-empty">{$i18n("正在查询")} {subdHost.trim()} {$i18n("的子域名（字典 + 证书日志），最长约 15 秒…")}</div>
    {:else if subdResult}
      <!-- 域名概览 -->
      <div class="dns-panel">
        <div class="panel-title">{$i18n("域名概览")}</div>
        <div class="dns-overview">
          <div class="dns-stat"><span class="dns-stat-label">{$i18n("主域名")}</span><span class="dns-stat-val cell-mono">{subdResult.host}</span></div>
          <div class="dns-stat"><span class="dns-stat-label">{$i18n("子域名数量")}</span><span class="dns-stat-val">{subdClean.length} {$i18n("个")}</span></div>
          <div class="dns-stat"><span class="dns-stat-label">{$i18n("DNS记录")}</span><span class="dns-stat-val">{dnsTotal} {$i18n("条")}</span></div>
          <div class="dns-stat"><span class="dns-stat-label">{$i18n("记录类型")}</span><span class="dns-stat-val">{subdDnsTypeCount} {$i18n("种")}</span></div>
        </div>
        <div class="subd-chips-label">{$i18n("发现的子域名")}</div>
        <div class="subd-chips">
          {#each subdChips as r (r.name)}
            <button class="subd-chip" on:click={() => copyText(r.name, '子域名')} title={(r.ips && r.ips.length ? 'IP：' + r.ips.join('、') : i18nTr("未解析")) + i18nTr("｜点击复制")}>{r.name}</button>
          {/each}
        </div>
      </div>
      <!-- 记录统计 -->
      <div class="dns-panel">
        <div class="panel-title">{$i18n("记录统计")}</div>
        <div class="dns-overview">
          {#each subdTypeStats as s (s.t)}
            <div class="dns-stat"><span class="dns-stat-label">{s.t} {$i18n("记录")}</span><span class="dns-stat-val">{s.n} {$i18n("条")}</span></div>
          {/each}
        </div>
      </div>
      <!-- DNS记录详情 -->
      <div class="dns-panel">
        <div class="panel-title">{$i18n("DNS记录详情")}</div>
        {#if subdWildCount}
          <div class="subd-bar">
            <span class="scan-count">{$i18n("泛解析命中")} {subdWildCount} {$i18n("条（泛解析域名的字典枚举无法与真实子域名区分，仅供参考）")}</span>
            <button class="ps-copy" on:click={() => showWildcard = !showWildcard}>{showWildcard ? i18nTr("隐藏") : i18nTr("显示")}</button>
          </div>
        {/if}
        {#if subdTableRows.length}
          <div class="dns-table-wrap">
            <table class="dns-table">
              <thead>
                <tr><th>{$i18n("域名")}</th><th>{$i18n("类型")}</th><th>{$i18n("值")}</th></tr>
              </thead>
              <tbody>
                {#each subdTableRows as r}
                  <tr>
                    <td>
                      <div class="dns-dom">
                        <span class="dns-dom-badge {r.cls}">{r.badge}</span>
                        <span class="cell-mono">{r.name}</span>
                      </div>
                    </td>
                    <td><span class="dns-badge {r.cls}">{r.type}</span></td>
                    <td class="dns-val cell-mono" class:dns-extra={r.dim}>{r.val}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {:else}
          <div class="ps-empty">{$i18n("未发现记录")}</div>
        {/if}
      </div>
    {:else}
      <div class="ps-empty">{$i18n("输入域名后点击「查询」")}</div>
    {/if}
  {:else if mode === 'dns'}
    {#if dnsLoading}
      <div class="ps-empty">{$i18n("正在查询")} {dnsHost.trim()} …</div>
    {:else if dnsResult}
      <!-- 域名概览：查询域名 / 记录总数 / 记录类型 / CDN 识别 -->
      <div class="dns-overview">
        <div class="dns-stat"><span class="dns-stat-label">{$i18n("查询域名")}</span><span class="dns-stat-val cell-mono">{dnsResult.host}</span></div>
        <div class="dns-stat"><span class="dns-stat-label">{$i18n("记录总数")}</span><span class="dns-stat-val">{dnsRows.length} {$i18n("条")}</span></div>
        <div class="dns-stat"><span class="dns-stat-label">{$i18n("记录类型")}</span><span class="dns-stat-val">{dnsTypeCount} {$i18n("种")}</span></div>
        <div class="dns-stat"><span class="dns-stat-label">CDN</span><span class="dns-stat-val" class:dns-cdn-on={dnsResult.cdn && dnsResult.cdn.detected}>{dnsResult.cdn && dnsResult.cdn.detected ? dnsResult.cdn.vendor : i18nTr("未检出")}</span></div>
      </div>
      <!-- CNAME 链路 -->
      {#if dnsResult.cname_chain && dnsResult.cname_chain.length}
        <div class="dns-chain-card">
          <div class="dns-chain-head">
            <span class="ps-port dns-type">{$i18n("CNAME 链")}</span>
            <span class="ps-service">{dnsResult.cname_chain.length} {$i18n("跳")}</span>
            <button class="ps-copy" on:click={() => copyDNSChain(dnsResult.cname_chain)}>{$i18n("复制")}</button>
          </div>
          <div class="dns-chain cell-mono">
            {#each dnsResult.cname_chain as h, i}
              {#if i > 0}<div class="dns-chain-arrow">↓</div>{/if}
              <div title={h.from}>{h.from}</div>
              <div class="dns-chain-arrow">↓</div>
              <div title={h.to}>{h.to}</div>
            {/each}
          </div>
        </div>
      {/if}
      <!-- 记录详情表格 -->
      <div class="dns-table-wrap">
        <table class="dns-table">
          <thead>
            <tr><th>{$i18n("类型")}</th><th>{$i18n("值")}</th><th>{$i18n("附加信息")}</th><th>{$i18n("状态")}</th></tr>
          </thead>
          <tbody>
            {#each dnsRows as r (r.type + r.value)}
              <tr>
                <td><span class="dns-badge {r.cls}">{r.type}</span></td>
                <td class="dns-val cell-mono">{r.value}</td>
                <td class="dns-extra">{r.extra || '-'}</td>
                <td class="probe-cell">
                  {#if r.probe}
                    {@const p = probeMap[r.probe]}
                    {#if !p}<span class="probe-na">—</span>
                    {:else if p.ok === null}<span class="probe-badge pb-pending">{$i18n("检测中")}</span>
                    {:else if p.ok}<span class="probe-badge pb-on" title="HTTP {p.code}">{p.ms} ms</span>
                    {:else}<span class="probe-badge pb-off">{$i18n("离线")}</span>
                    {/if}
                  {:else}
                    <span class="probe-na">—</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <div class="ps-empty">{$i18n("输入域名后点击「查询」")}</div>
    {/if}
  {:else if isRangeMode}
    <div class="lan-controls" bind:this={lanCtlEl}>
      <input type="text" bind:value={range} style="width:260px" placeholder={$i18n("IP / 网段 / 域名（留空自动识别本网段）")} on:input={onRangeInput} on:keydown={(e) => e.key === 'Enter' && scanIP()} use:field={{ check: rangeCheck, errAt: () => rangeErrLan }} />
      <CustomSelect bind:value={portMode} options={PORT_CATEGORIES.map((c) => ({ value: c.value, label: c.label }))} width="112px" />
      {#if !scanning}
        {#if !singleIP}
          <button class="btn" on:click={scanHosts}>{$i18n("扫描IP")}</button>
        {/if}
        <button class="btn" on:click={scanIP}>{$i18n("扫描端口")}</button>
      {:else}
        <button class="btn scanning-btn" on:click={stopScan} title={$i18n("点击停止扫描")}>
          <span class="spinner"></span>{$i18n("扫描中")}{#if scanProgress} {scanProgress.done}/{scanProgress.total}{/if}
        </button>
      {/if}
      {#if lastScanAt}
        <span class="scan-last">{$i18n("上次扫描")} {lastScanAt}{#if lastScanSec} {$i18n("· 耗时")} {lastScanSec}s{/if}</span>
      {:else if snapTime}
        <span class="scan-last">{$i18n("快照更新于")} {snapTime}</span>
      {/if}
    </div>
    <div class="scan-control-meta">
      <span>{$i18n("扫描范围")}</span>
      <span class="right">{portModeLabel}{#if lastScanAt} {$i18n("· 上次")} {lastScanAt}{/if}</span>
    </div>
    <div class="field-err" bind:this={rangeErrLan} style="display:none"></div>
    <div class="dns-overview">
      <div class="dns-stat"><span class="dns-stat-label">{$i18n("开放端口")}</span><span class="dns-stat-val">{lanPortCount}</span></div>
      {#if !singleIP}
        <div class="dns-stat"><span class="dns-stat-label">{$i18n("未使用")}</span><span class="dns-stat-val">{lanUnusedCount}</span></div>
        <div class="dns-stat"><span class="dns-stat-label">{$i18n("待检")}</span><span class="dns-stat-val">{lanPendingCount}</span></div>
        <div class="dns-stat"><span class="dns-stat-label">{$i18n("连接延时")}</span><span class="dns-stat-val">—</span></div>
      {/if}
      <div class="dns-stat"><span class="dns-stat-label">{$i18n("扫描速度")}</span><span class="dns-stat-val">{lanScanSpeed} TPS</span></div>
    </div>
    {#if resolving && isDomainName(range)}
      <div class="ps-empty">{$i18n("正在解析域名")} {range.trim()} …</div>
    {:else if domainTarget && domainTarget.ips.length && domainTarget.host === range.trim()}
      <!-- 输入域名后自动预解析：列出 A 记录地址（单个也显示），点击任意地址即对其扫描端口 -->
      <div class="domain-pick">
        <span class="domain-pick-label">{domainTarget.host} {$i18n("解析到")} {domainTarget.ips.length} {$i18n("个 IP，点击地址开始扫描：")}</span>
        {#each domainTarget.ips as ip (ip)}
          <button class="domain-pick-ip" class:active={domainTarget.chosen === ip} on:click={() => pickDomainIP(ip)}>{ip}</button>
        {/each}
      </div>
    {/if}
    {#if singleIP}
      {@const sip = range.trim()}
      {@const shost = lanHostMap[sip]}
      {#if !shost || !shost.ports.length}
        <div class="ps-empty">{scanning ? i18nTr("正在扫描…") : lanScanned ? i18nTr("未发现开放端口") : i18nTr("点击「扫描端口」检测该主机的开放端口")}</div>
      {:else}
        <!-- 单主机：直接按端口号平铺卡片，流式到达即渲染 -->
        <div class="ps-cards">
          {#each shost.ports as p (sip + ':' + p.port)}
            {@const mk = 'lan:' + sip + ':' + p.port}
            <div class="ps-card port-card" class:scanning={scanning && inScanningRange(sip)}>
              <div class="ps-card-head port-top">
                <span class="ps-port port-num">{p.port}</span>
                <span class="port-proto"><span class="badge {portBadge(p)}">{portBadgeText(p)}</span></span>
                {#if scanning && inScanningRange(sip)}
                  <span class="proto-tag lan-tag-scanning">{$i18n("扫描中")}</span>
                {/if}
                <button class="ps-more" title={$i18n("常用功能")} on:click={(e) => toggleMenu(mk, e)}>
                  <svg width="14" height="14" viewBox="0 0 48 48" fill="currentColor"><circle cx="24" cy="12" r="4"/><circle cx="24" cy="24" r="4"/><circle cx="24" cy="35" r="4"/></svg>
                </button>
              </div>
              <div class="port-svc">{p.service || (p.protocols || []).join(' / ')}</div>
              <div class="port-proc" title={p.web_title || sip}>{p.web_title || sip}</div>
              <div class="port-foot">
                <span class="status-inline">
                  <i class="status-dot"></i>{$i18n("运行中")}
                  {#if p.latency_ms > 0}<span class="port-lat" title={$i18n("TCP 建连延时")}>{p.latency_ms} ms</span>{/if}
                </span>
                {#if p.protocols.some((x) => x.startsWith('tcp'))}
                  <button class="port-ext" title={$i18n("浏览器打开")} aria-label={$i18n("浏览器打开")} on:click={() => openBrowser({ port: p.port, addrs: [sip], protocols: p.protocols })}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/></svg>
                  </button>
                {/if}
              </div>
              {#if menuKey === mk}
                <div class="ps-menu" style="top:{menuPos.top}px;right:{menuPos.right}px" on:click|stopPropagation={() => {}}>
                  <button on:click={() => copyText(sip, '地址')}>{$i18n("复制地址")}</button>
                  <button on:click={() => copyText(String(p.port), '端口')}>{$i18n("复制端口")}</button>
                  {#if p.protocols.some((x) => x.startsWith('tcp'))}
                    <button on:click={() => openBrowser({ port: p.port, addrs: [sip], protocols: p.protocols })}>{$i18n("浏览器打开")}</button>
                  {/if}
                  <button on:click={() => createForward({ port: p.port, addrs: [sip], protocols: p.protocols, service: p.service, web_title: p.web_title })}>{$i18n("创建转发规则")}</button>
                  <button on:click={() => createTunnel({ port: p.port, addrs: [sip], protocols: p.protocols, service: p.service, web_title: p.web_title })}>{$i18n("创建穿透隧道")}</button>
                  {#if p.protocols.some((x) => x.startsWith('tcp'))}
                    <button on:click={() => probePort({ port: p.port, addrs: [sip], protocols: p.protocols })}>{$i18n("端口探测")}</button>
                  {/if}
                  <button on:click={() => pingHost({ addrs: [sip], port: p.port, protocols: p.protocols })}>Ping</button>
                </div>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
    {:else if lanIPs.error}
      <div class="ps-empty">{lanIPs.error}</div>
    {:else if !lanIPs.ips.length}
      <div class="ps-empty">{lanInfo ? i18nTr("暂无结果") : i18nTr("正在识别局域网网段…")}</div>
    {:else}
      {#if lanIPs.ips.length}
        <div class="ps-cards">
          {#each lanIPs.ips as ip (ip)}
            {@const host = lanHostMap[ip]}
            {#if host}
              <div class="ps-card lan-card" class:clickable={true} class:scanning={scanning && inScanningRange(ip)} on:click={() => openPortView(ip, host.ports)}>
                  <div class="ps-card-head">
                    <span class="ps-port ip-copy" title={$i18n("点击复制 IP")} on:click|stopPropagation={() => copyText(ip, '地址')}>{ip}</span>
                    {#if scanning && inScanningRange(ip)}
                      <span class="proto-tag lan-tag-scanning">{$i18n("扫描中")}</span>
                    {/if}
                    <button class="ps-more" title={$i18n("常用功能")} on:click|stopPropagation={(e) => toggleMenu('lan:' + ip, e)}>
                      <svg width="14" height="14" viewBox="0 0 48 48" fill="currentColor"><circle cx="24" cy="12" r="4"/><circle cx="24" cy="24" r="4"/><circle cx="24" cy="35" r="4"/></svg>
                    </button>
                  </div>
                  {#if host.web_title}<div class="ps-card-title" title={host.web_title}>{host.web_title}</div>{/if}
                  <div class="ps-card-foot">
                    <span class="proto-tag">{host.ports.length} {$i18n("端口")}</span>
                    {#if host.service}<span class="ps-service" title={host.service}>{host.service}</span>{/if}
                  </div>
                  {#if menuKey === ('lan:' + ip)}
                    <div class="ps-menu" style="top:{menuPos.top}px;right:{menuPos.right}px" on:click|stopPropagation={() => {}}>
                      <button on:click={() => openPortView(ip, host.ports)}>{$i18n("查看端口")}</button>
                      <button on:click={() => pingHost({ addrs: [ip], port: 0, protocols: [] })}>Ping</button>
                    </div>
                  {/if}
                </div>
            {:else if hostAlive[ip]}
              <div class="ps-card lan-card" on:contextmenu={(e) => { e.preventDefault(); toggleMenu('alive:' + ip, e); }}>
                <div class="ps-card-head">
                  <span class="ps-port ip-copy" title={$i18n("点击复制 IP")} on:click|stopPropagation={() => copyText(ip, '地址')}>{ip}</span>
                  <span class="proto-tag">{$i18n("在线")}</span>
                </div>
                {#if menuKey === ('alive:' + ip)}
                  <div class="ps-menu" style="top:{menuPos.top}px;right:{menuPos.right}px" on:click|stopPropagation={() => {}}>
                    <button on:click={() => copyText(ip, '地址')}>{$i18n("复制地址")}</button>
                    <button on:click={() => pingHost({ addrs: [ip], port: 0, protocols: [] })}>Ping</button>
                    <button on:click={() => { menuKey = null; domainTarget = null; range = ip; scanIP(); }}>{$i18n("扫描端口")}</button>
                  </div>
                {/if}
              </div>
            {:else}
              <div class="ps-card lan-card" class:pending={!lanChecked[ip] && (scanning || !lanScanned)} class:off={lanChecked[ip] || (lanScanned && !scanning)}>
                <div class="ps-card-head">
                  <span class="ps-port ip-copy" title={$i18n("点击复制 IP")} on:click|stopPropagation={() => copyText(ip, '地址')}>{ip}</span>
                  <span class="proto-tag {lanChecked[ip] || (lanScanned && !scanning) ? 'lan-tag-off' : 'lan-tag-wait'}">{lanChecked[ip] || (lanScanned && !scanning) ? i18nTr("未使用") : i18nTr("待检")}</span>
                </div>
              </div>
            {/if}
          {/each}
        </div>
      {/if}
    {/if}
  {:else}
    <div class="scan-control-card">
      <div class="scan-control-main">
        <div class="scan-target">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
          <span>{$i18n("本机 · 全部监听端口")}</span>
        </div>
        {#if !scanning}
          <button class="btn btn-primary" on:click={scanIP}>{$i18n("重新扫描")}</button>
        {:else}
          <button class="btn scanning-btn" on:click={stopScan} title={$i18n("点击停止扫描")}>
            <span class="spinner"></span>{$i18n("扫描中")}{#if scanProgress} {scanProgress.done}/{scanProgress.total}{/if}
          </button>
        {/if}
        {#if lastScanAt}
          <span class="scan-last">{$i18n("上次扫描")} {lastScanAt}{#if lastScanSec} {$i18n("· 耗时")} {lastScanSec}s{/if}</span>
        {:else if snapTime}
          <span class="scan-last">{$i18n("快照更新于")} {snapTime}</span>
        {/if}
      </div>
      <div class="scan-control-meta">
        <span>{$i18n("扫描范围")}</span>
        <span class="right">{$i18n("本机全部端口")}{#if lastScanAt} {$i18n("· 上次")} {lastScanAt}{/if}</span>
      </div>
    </div>
    <div class="dns-overview scan-stats">
      <!-- 统计卡片即筛选器：点击卡片切换下方端口列表的分类，当前选中卡片高亮；本机扫描中在「开放端口」卡内显示加载图标 -->
      <div class="dns-stat stat-filter stat-cyan" class:active={filter === 'all'} on:click={() => (filter = 'all')} title={scanning ? i18nTr("本机端口扫描中…") : i18nTr("显示全部开放端口")}><span class="dns-stat-label">{$i18n("开放端口")}{#if scanning}&nbsp;<span class="spinner stat-spinner"></span>{/if}</span><span class="dns-stat-val">{usedPortCount}</span></div>
      <div class="dns-stat stat-filter stat-green" class:active={filter === 'web'} on:click={() => (filter = 'web')} title={$i18n("仅显示 WEB 端口")}><span class="dns-stat-label">{$i18n("WEB 服务")}</span><span class="dns-stat-val">{webCount}</span></div>
      <div class="dns-stat stat-filter stat-violet" class:active={filter === 'db'} on:click={() => (filter = 'db')} title={$i18n("仅显示数据库端口")}><span class="dns-stat-label">{$i18n("数据库")}</span><span class="dns-stat-val">{dbCount}</span></div>
      <div class="dns-stat stat-filter stat-blue" class:active={filter === 'docker'} on:click={() => (filter = 'docker')} title={$i18n("仅显示 Docker 端口")}><span class="dns-stat-label">Docker</span><span class="dns-stat-val">{dockerCount}</span></div>
      <div class="dns-stat stat-slate stat-free"><span class="dns-stat-label">{$i18n("剩余端口")}</span><span class="dns-stat-val">{freePorts}</span></div>
    </div>
    <div class="ps-cards">
      {#each filtered as it}
        <div class="ps-card port-card">
          <div class="ps-card-head port-top">
            <span class="ps-port port-num">{it.port}</span>
            <span class="port-proto"><span class="badge {portBadge(it)}">{portBadgeText(it)}</span></span>
            <button class="ps-more" title={$i18n("常用功能")} on:click={(e) => toggleMenu(itemKey(it), e)}>
              <svg width="14" height="14" viewBox="0 0 48 48" fill="currentColor"><circle cx="24" cy="12" r="4"/><circle cx="24" cy="24" r="4"/><circle cx="24" cy="35" r="4"/></svg>
            </button>
          </div>
          <div class="port-svc">{it.service || (it.protocols || []).join(' / ')}</div>
          <div class="port-proc" title={portProc(it)}>{portProc(it)}</div>
          <div class="port-foot">
            <span class="status-inline"><i class="status-dot"></i>{$i18n("运行中")}</span>
            {#if it.protocols.some((p) => p.startsWith('tcp'))}
              <button class="port-ext" title={$i18n("浏览器打开")} aria-label={$i18n("浏览器打开")} on:click={() => openBrowser(it)}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/></svg>
              </button>
            {/if}
          </div>
          {#if menuKey === itemKey(it)}
            <div class="ps-menu" style="top:{menuPos.top}px;right:{menuPos.right}px">
              <button on:click={() => copyText(String(it.port), '端口')}>{$i18n("复制端口")}</button>
              <button on:click={() => copyText((it.addrs || []).join(', '), '地址')}>{$i18n("复制地址")}</button>
              {#if it.protocols.some((p) => p.startsWith('tcp'))}
                <button on:click={() => openBrowser(it)}>{$i18n("浏览器打开")}</button>
              {/if}
              <button on:click={() => createForward(it)}>{$i18n("创建转发规则")}</button>
              <button on:click={() => createTunnel(it)}>{$i18n("创建穿透隧道")}</button>
              {#if it.protocols.some((p) => p.startsWith('tcp'))}
                <button on:click={() => probePort(it)}>{$i18n("端口探测")}</button>
              {/if}
              <button on:click={() => pingHost(it)}>Ping</button>
              {#each it.pids as kp}
                <button class="danger" on:click={() => { menuKey = null; killTarget = { pid: kp.pid, process: kp.process, port: it.port }; }}>
                  {it.pids.length > 1 ? i18nTr("结束进程 ") + kp.pid : i18nTr("结束进程")}
                </button>
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}

  {#if menuKey}
    <div class="ps-menu-backdrop" on:click={() => (menuKey = null)}></div>
  {/if}

  {#if killTarget}
    <ConfirmModal
      title={$i18n("结束进程")}
      message={i18nTr("确认结束占用端口 ") + killTarget.port + i18nTr(" 的进程") + (killTarget.process ? '「' + killTarget.process + '」' : '') + '（PID ' + killTarget.pid + '）？'}
      confirmText={$i18n("结束进程")}
      busy={killBusy}
      onConfirm={confirmKill}
      onClose={() => (killTarget = null)}
    />
  {/if}

  {#if portView}
    <Modal title={`${portViewIp} 的开放端口（${portView.length} 个）`} width={600} onClose={() => (portView = null)}>
      <div class="pv-ports">
        {#each portView as p (portViewIp + ':' + p.port)}
          {@const mk = 'pvp:' + portViewIp + ':' + p.port}
          <div class="ps-card">
            <div class="ps-card-head">
              <span class="ps-port">{p.port}</span>
              {#each p.protocols as pr}<span class="proto-tag">{pr}</span>{/each}
              {#if p.service}<span class="ps-service">{p.service}</span>{/if}
              <button class="ps-more" title={$i18n("常用功能")} on:click={(e) => toggleMenu(mk, e)}>
                <svg width="14" height="14" viewBox="0 0 48 48" fill="currentColor"><circle cx="24" cy="12" r="4"/><circle cx="24" cy="24" r="4"/><circle cx="24" cy="35" r="4"/></svg>
              </button>
            </div>
            {#if p.web_title}<div class="ps-card-title" title={p.web_title}>{p.web_title}</div>{/if}
            {#if menuKey === mk}
              <div class="ps-menu" style="top:{menuPos.top}px;right:{menuPos.right}px">
                <button on:click={() => copyText(portViewIp, '地址')}>{$i18n("复制地址")}</button>
                <button on:click={() => copyText(String(p.port), '端口')}>{$i18n("复制端口")}</button>
                {#if p.protocols.some((x) => x.startsWith('tcp'))}
                  <button on:click={() => openBrowser({ port: p.port, addrs: [portViewIp], protocols: p.protocols })}>{$i18n("浏览器打开")}</button>
                {/if}
                <button on:click={() => createForward({ port: p.port, addrs: [portViewIp], protocols: p.protocols, service: p.service, web_title: p.web_title })}>{$i18n("创建转发规则")}</button>
                <button on:click={() => createTunnel({ port: p.port, addrs: [portViewIp], protocols: p.protocols, service: p.service, web_title: p.web_title })}>{$i18n("创建穿透隧道")}</button>
                {#if p.protocols.some((x) => x.startsWith('tcp'))}
                  <button on:click={() => probePort({ port: p.port, addrs: [portViewIp], protocols: p.protocols })}>{$i18n("端口探测")}</button>
                {/if}
                <button on:click={() => pingHost({ addrs: [portViewIp], port: p.port, protocols: p.protocols })}>Ping</button>
              </div>
            {/if}
          </div>
        {/each}
      </div>
    </Modal>
  {/if}

  {#if term}
    <Modal title={term.title} width={560} onClose={() => (term = null)}>
      <div class="term" bind:this={termScroll}>
        {#each term.lines as l}
          <div class="term-line {l.cls}">
            {#if l.cmd}<span class="t-prompt">$</span>{/if}{l.cmd ? ' ' + l.text : l.text}
          </div>
        {/each}
        {#if term.running}
          <div class="term-line"><span class="term-cursor"></span></div>
        {/if}
      </div>
    </Modal>
  {/if}

  {#if showScanSettings}
    <Modal title={$i18n("扫描设置")} width={480} onClose={() => (showScanSettings = false)}>
      <div class="form-group">
        <label class="form-label">{$i18n("端口范围（IP / 网段扫描）")}</label>
        <CustomSelect bind:value={portMode} options={PORT_CATEGORIES.map((c) => ({ value: c.value, label: c.label }))} width="100%" />
        <div class="tip-text">{$i18n("本机端口扫描始终读取当前系统监听端口，不受此设置影响。")}</div>
      </div>
      <div class="tip-text">{$i18n("扫描并发与超时由服务端自动控制；扫描过程中可点击扫描按钮停止。")}</div>
      <div slot="footer" style="display:flex;justify-content:flex-end">
        <button class="btn btn-primary" on:click={() => (showScanSettings = false)}>{$i18n("完成")}</button>
      </div>
    </Modal>
  {/if}
</div>

<style>
  /* 模块切换条：与演示页一致的页签式导航 */
  .scan-toolbar {
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    margin-bottom: 14px; padding: 0 0 2px;
    border-bottom: 1px solid var(--bd);
  }
  /* 局域网控件行：独立显示在工具栏下方 */
  .lan-controls {
    display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
    margin-bottom: 12px;
  }
  /* 域名解析结果选择行：域名解析出多个 IP 时列出全部地址供用户选择 */
  .domain-pick {
    display: flex; align-items: center; justify-content: center; gap: 8px; flex-wrap: wrap;
    margin: -4px 0 12px; font-size: 13px; color: var(--text3);
  }
  .domain-pick-ip {
    background: var(--bg3); border: 1px solid var(--bd); color: var(--text2);
    border-radius: var(--radius); padding: 4px 12px; font-size: 13px; cursor: pointer;
  }
  .domain-pick-ip:hover { color: var(--text); border-color: var(--accent); }
  .domain-pick-ip.active { background: var(--accent-solid); border-color: var(--accent-solid); color: #fff; font-weight: 600; }
  .mode-switch {
    display: flex; align-items: center; gap: 4px; flex-wrap: wrap;
    background: transparent; border: none; border-radius: 0; padding: 0;
  }
  .mode-btn {
    border: none; background: none; color: var(--text3); font-size: 13.5px;
    padding: 9px 14px; border-bottom: 2px solid transparent; border-radius: 0;
    cursor: pointer; white-space: nowrap; transition: color .15s ease, border-color .15s ease;
  }
  .mode-btn:hover { color: var(--text2); }
  .mode-btn.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; background: none; }
  /* 扫描统计：按分类给数字上色，与演示页一致 */
  .scan-stats .stat-cyan .dns-stat-val { color: var(--accent); }
  .scan-stats .stat-green .dns-stat-val { color: var(--green); }
  .scan-stats .stat-violet .dns-stat-val { color: var(--violet); }
  .scan-stats .stat-blue .dns-stat-val { color: var(--blue); }
  .scan-stats .stat-slate .dns-stat-val { color: var(--text2); }
  /* 扫描控制行：本机扫描展示只读目标 + 重新扫描；局域网由 .lan-controls 承担 */
  .scan-control-card { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
  .scan-control-main { display: flex; align-items: center; gap: 8px; flex: 1; min-width: 0; flex-wrap: wrap; }
  .scan-target {
    display: flex; align-items: center; gap: 8px; flex: 1; min-width: 200px;
    height: 38px; padding: 0 12px; border: 1px solid var(--bd); border-radius: var(--radius);
    background: var(--bg3); color: var(--text2); font-size: 12px;
  }
  .scan-target svg { color: var(--text3); flex: none; }
  .scan-target span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .scan-last { margin-left: auto; font-size: 11px; color: var(--text3); white-space: nowrap; }
  .scan-control-meta { display: none; }
  .scan-control-meta .right { margin-left: auto; }
  /* 端口卡片：端口号 + 服务徽章 + 服务名 + 进程 + 状态页脚 */
  .port-card { padding: 11px 12px; gap: 0; }
  .port-top { align-items: flex-start; }
  .port-num { font-size: 18px; line-height: 1; letter-spacing: -.03em; }
  .port-proto { margin-left: auto; }
  .port-proto .badge { text-transform: uppercase; letter-spacing: .02em; }
  .port-svc { font-size: 10.5px; color: var(--text2); margin-top: 5px; }
  .port-proc {
    font-size: 9.5px; color: var(--text3); font-family: var(--mono); margin-top: 3px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .port-foot {
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
    margin-top: 9px; padding-top: 8px; border-top: 1px dashed var(--bd);
  }
  .status-inline { display: inline-flex; align-items: center; gap: 6px; font-size: 10px; color: var(--text3); }
  .port-lat { font-family: var(--mono); font-size: 9.5px; color: var(--text3); }
  .port-ext {
    width: 24px; height: 24px; display: grid; place-items: center;
    border: none; background: none; color: var(--text3); border-radius: 6px; cursor: pointer;
  }
  .port-ext:hover { color: var(--accent); background: var(--bg4); }
  .badge-blue { background: rgba(var(--blue-rgb), .08); color: var(--blue); border: 1px solid rgba(var(--blue-rgb), .25); }
  /* 统计卡片即筛选器（本机端口模式）：点击卡片按分类筛选，选中卡片高亮 */
  .dns-stat.stat-filter {
    cursor: pointer; transition: border-color .15s ease, background .15s ease;
  }
  .dns-stat.stat-filter:hover { border-color: var(--accent); }
  .dns-stat.stat-filter.active {
    border-color: var(--accent); background: rgba(var(--accent-rgb), .08);
  }
  /* 「开放端口」卡内的扫描中加载图标：小号 spinner，与卡片标签同行 */
  .stat-spinner {
    width: 10px; height: 10px; vertical-align: -1px;
    border-width: 1.5px;
  }
  .scan-count { margin-left: auto; font-size: 12px; color: var(--text3); white-space: nowrap; }
  /* 扫描中指示器按钮：旋转 spinner + 文字，点击可停止扫描 */
  .scanning-btn {
    display: inline-flex; align-items: center; gap: 7px;
    color: var(--text2); cursor: pointer; white-space: nowrap;
    border: none; background: transparent;
  }
  .spinner {
    display: inline-block; width: 12px; height: 12px; flex: none;
    border: 2px solid var(--bd); border-top-color: var(--accent);
    border-radius: 50%; animation: ps-spin .8s linear infinite;
  }
  @keyframes ps-spin { to { transform: rotate(360deg); } }
  .proto-tag {
    display: inline-block; padding: 1px 7px; border-radius: 999px;
    background: rgba(var(--accent-rgb), .12); color: var(--accent); font-size: 11px;
  }
  /* TCP 建连延时标签：等宽数字、低饱和中性色，与协议标签区分 */
  .ps-latency {
    background: var(--bg4);
    color: var(--text3);
    font-family: var(--mono);
    font-variant-numeric: tabular-nums;
  }
  .ps-empty {
    text-align: center; color: var(--text3); padding: 24px 0; font-size: 13px;
  }
  .ps-cards {
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    max-height: calc(100vh - 320px);
    min-height: 120px;
    overflow-y: auto;
    padding-right: 4px;
  }
  @media (max-width:1100px){ .ps-cards{grid-template-columns:repeat(3,minmax(0,1fr))} }
  @media (max-width:860px){ .ps-cards{grid-template-columns:repeat(2,minmax(0,1fr))} }
  .ps-card {
    position: relative;
    background: var(--bg3); border: 1px solid var(--bd);
    border-radius: calc(var(--radius) + 4px); padding: 14px 16px;
    display: flex; flex-direction: column; gap: 5px; min-width: 0;
    box-shadow: var(--shadow-card); transition: border-color .15s ease;
  }
  .ps-more {
    margin-left: auto; display: inline-flex; align-items: center;
    border: none; background: transparent; color: var(--text3);
    cursor: pointer; padding: 2px; border-radius: 4px;
  }
  .ps-more:hover { color: var(--text); background: var(--bg3); }
  .ps-menu-backdrop { position: fixed; inset: 0; z-index: 90; }
  /* 菜单统一 fixed 定位（坐标由 toggleMenu 按按钮矩形写入内联样式），
     避免被 .ps-cards / .modal-body 的 overflow 裁剪；超出视口高度时自身滚动兜底 */
  .ps-menu {
    position: fixed; z-index: 1300;
    display: flex; flex-direction: column; min-width: 132px; padding: 4px;
    max-height: calc(100dvh - 24px); overflow-y: auto;
    background: var(--bg2); border: 1px solid var(--bd); border-radius: var(--radius);
    box-shadow: var(--shadow-md);
  }
  .ps-menu button {
    border: none; background: transparent; color: var(--text2); font-size: 12px;
    text-align: left; padding: 7px 10px; border-radius: calc(var(--radius) - 2px);
    cursor: pointer; white-space: nowrap;
  }
  .ps-menu button:hover { background: var(--bg3); color: var(--text); }
  .ps-menu button.danger { color: var(--red); }
  .ps-card:hover { border-color: var(--accent); }
  /* 局域网主机卡片：整卡可点打开端口弹窗 */
  .lan-card.clickable { cursor: pointer; }
  /* IP 可点击复制，悬停提亮提示 */
  .ip-copy { cursor: pointer; transition: filter .15s ease; }
  .ip-copy:hover { filter: brightness(1.25); }
  .ps-card-head {
    display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  }
  .ps-port {
    font-family: var(--mono); font-size: 19px; font-weight: 700; color: var(--accent);
    font-variant-numeric: tabular-nums;
  }
  .ps-service { font-size: 12px; color: var(--text2); }
  .ps-card-addr { font-size: 12px; color: var(--text3); }
  /* 卡片底部信息行：悬浮到卡片最底（配合网格等高布局让底部对齐），端口数与服务名同一行 */
  .ps-card-foot {
    margin-top: auto; display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
  }
  .ps-card-title {
    font-size: 12px; color: var(--text2);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  /* 局域网地址卡片：对齐本机端口卡片（头部 + 地址 + 标题），一台主机一张卡 */
  .pv-ports { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; }
  /* 弹窗内卡片：弹窗底已是卡片面，内层降为 bg4 以保留层次 */
  .pv-ports .ps-card { background: var(--bg4); box-shadow: none; }
  .lan-card.pending { opacity: .8; }
  .lan-card.off { opacity: .45; }
  .lan-card.scanning { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
  .lan-tag-wait, .lan-tag-off { color: var(--text3); }
  .lan-tag-scanning { background: rgba(var(--yellow-rgb),.08); color: var(--yellow); animation: ps-scan-pulse 1s ease-in-out infinite; }
  @keyframes ps-scan-pulse { 50% { opacity: .55; } }
  /* 命令窗口弹窗：固定深色终端风格，不随主题切换 */
  .term {
    background: #0d1117; border: 1px solid var(--bd); border-radius: var(--radius);
    padding: 12px 14px; min-height: 120px; max-height: 320px; overflow-y: auto;
    font-family: var(--mono); font-size: 12.5px; line-height: 1.7;
  }
  .term-line { color: #c9d1d9; white-space: pre-wrap; word-break: break-all; }
  .term-line.t-cmd { color: #e2e8f0; }
  /* 终端底色固定为深色且不随主题切换，故状态色也用固定亮色，不能用随主题变深的 --green/--red */
  .term-line.t-ok { color: #4ade80; }
  .term-line.t-err { color: #f87171; }
  .t-prompt { color: #4ade80; font-weight: 700; }
  .term-cursor {
    display: inline-block; width: 8px; height: 14px; vertical-align: -2px;
    background: #c9d1d9; animation: term-blink 1s step-end infinite;
  }
  @keyframes term-blink { 50% { opacity: 0; } }
  /* DNS 查询结果：概览统计 + 记录表格 */
  .dns-type { font-size: 14px; }
  .dns-overview {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px;
    margin-bottom: 12px;
  }
  .dns-stat {
    display: flex; flex-direction: column; gap: 6px;
    background: var(--bg3); border: 1px solid var(--bd); border-radius: calc(var(--radius) + 4px);
    padding: 16px 18px; box-shadow: var(--shadow-card);
  }
  .dns-stat-label { font-size: 12px; color: var(--text3); }
  .dns-stat-val { font-size: 18px; font-weight: 600; color: var(--text); word-break: break-all; font-variant-numeric: tabular-nums; }
  /* 子域名面板内的统计块：面板本身已是卡片面，内层降为 bg4 以保留层次 */
  .dns-panel .dns-stat {
    background: var(--bg4); box-shadow: none;
    border-radius: var(--radius); padding: 12px 14px;
  }
  .dns-panel .dns-stat-val { font-size: 15px; }
  .dns-cdn-on { color: var(--accent); }
  .ps-copy {
    margin-left: auto; font-size: 12px; color: var(--text2);
    background: none; border: none; cursor: pointer; padding: 2px 4px;
    border-radius: 4px; transition: color .15s ease;
  }
  .ps-copy:hover { color: var(--accent); }
  .dns-chain-card {
    background: var(--bg4); border: 1px solid var(--bd); border-radius: var(--radius);
    padding: 10px 12px; margin-bottom: 12px;
  }
  .dns-chain-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
  .dns-chain {
    display: flex; flex-direction: column; gap: 4px;
    font-size: 12px; color: var(--text2); word-break: break-all;
  }
  .dns-chain-arrow { color: var(--text3); font-size: 11px; line-height: 1; padding-left: 2px; }
  /* 子域名结果三段式面板：域名概览 / DNS记录详情 / 记录统计 */
  .dns-panel {
    background: var(--bg3); border: 1px solid var(--bd); border-radius: calc(var(--radius) + 4px);
    padding: 16px 18px; margin-bottom: 16px; box-shadow: var(--shadow-card);
  }
  .panel-title {
    font-size: 13.5px; font-weight: 600; color: var(--text);
    padding-bottom: 10px; border-bottom: 1px solid var(--bd); margin-bottom: 14px;
  }
  /* 发现的子域名 chips */
  .subd-chips-label { font-size: 13px; color: var(--text2); margin: 16px 0 10px; }
  .subd-chips { display: flex; flex-wrap: wrap; gap: 8px; }
  /* chips 视觉对齐类型徽章（dns-badge）：淡底紫、紫字小徽章（浓度与其他淡底统一为 8%） */
  .subd-chip {
    padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600;
    background: rgba(var(--violet-rgb),.08); color: var(--violet); white-space: nowrap;
    font-family: var(--mono); border: none; cursor: pointer;
  }
  .subd-chip:hover { filter: brightness(1.2); }
  /* 记录详情：域名圆形字母徽章 */
  .dns-dom { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .dns-dom-badge {
    width: 22px; height: 22px; border-radius: 999px; flex: none;
    display: inline-flex; align-items: center; justify-content: center;
    font-size: 11px; font-weight: 700;
  }
  .t-soa { background: rgba(var(--indigo-rgb),.08); color: var(--indigo); }
  /* 泛解析命中开关条 */
  .subd-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
  }
  .dns-table-wrap {
    background: var(--bg4); border: 1px solid var(--bd); border-radius: var(--radius);
    overflow-x: auto;
  }
  .dns-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .dns-table th {
    text-align: center; padding: 9px 14px; font-size: 11px; font-weight: 500;
    color: var(--text3); text-transform: uppercase; letter-spacing: .5px;
    border-bottom: 1px solid var(--bd);
  }
  .dns-table td { padding: 9px 14px; border-bottom: 1px solid var(--bd); vertical-align: top; }
  .dns-table tbody tr:last-child td { border-bottom: none; }
  .dns-table tbody tr:hover { background: var(--bg3); }
  .dns-val { color: var(--text); word-break: break-all; }
  .dns-extra { color: var(--text3); font-size: 12px; word-break: break-all; }
  .dns-badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; white-space: nowrap; }
  /* 记录类型徽章：淡底用色相 token 的 rgb 变量 + 统一 8% 浓度（浓度越高、淡底越接近文字色，对比越低），
     文字色取色相 token —— 暗色主题给偏亮一档、浅色主题给偏深一档，两种底色下都可读 */
  .t-a { background: rgba(var(--blue-rgb),.08); color: var(--blue); }
  .t-aaaa { background: rgba(var(--cyan-rgb),.08); color: var(--cyan); }
  .t-cname { background: rgba(var(--green-rgb),.08); color: var(--green); }
  .t-mx { background: rgba(var(--yellow-rgb),.08); color: var(--yellow); }
  .t-ns { background: rgba(var(--violet-rgb),.08); color: var(--violet); }
  .t-txt { background: rgba(var(--slate-rgb),.08); color: var(--slate); }
  .t-soa { background: rgba(var(--orange-rgb),.08); color: var(--orange); }
  /* 服务状态列：在线绿（含延迟，悬停显示 HTTP 状态码）/ 离线灰 / 探测中黄 */
  .probe-cell { white-space: nowrap; }
  .probe-badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; white-space: nowrap; }
  .pb-on { background: rgba(var(--green-rgb),.08); color: var(--green); }
  .pb-off { background: rgba(var(--slate-rgb),.08); color: var(--slate); }
  .pb-pending { background: rgba(var(--yellow-rgb),.08); color: var(--yellow); }
  .probe-na { color: var(--text3); opacity: .6; }

  /* 移动端：模块切换为胶囊页签，端口卡片两列铺排 */
  @media (max-width:600px){
    /* 页头：标题与操作同排，操作靠右（对齐演示页移动端） */
    .page-hdr{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:start;gap:10px}
    .page-hdr-actions{width:auto;flex-wrap:nowrap}
    .scan-toolbar{gap:8px;border-bottom:none;margin-bottom:10px;padding:0}
    .mode-switch{display:flex;flex-wrap:nowrap;width:100%;overflow-x:auto;scrollbar-width:none;gap:5px}
    .mode-switch::-webkit-scrollbar{display:none}
    .mode-btn{
      flex:0 0 auto;text-align:center;height:30px;padding:0 11px;font-size:10.5px;
      border:1px solid var(--bd);border-radius:8px;background:var(--bg3);color:var(--text3);
    }
    .mode-btn.active{
      background:rgba(var(--accent-rgb),.10);border-color:rgba(var(--accent-rgb),.35);
      color:var(--accent);font-weight:600;
    }
    /* 扫描控制行卡片化：只读目标 + 主按钮 + 范围摘要 */
    .scan-control-card{
      display:block;background:var(--bg3);border:1px solid var(--bd);
      border-radius:calc(var(--radius) + 4px);padding:10px 12px;margin-bottom:11px;
    }
    .scan-control-main{flex-wrap:nowrap}
    .scan-target{height:36px;background:var(--bg2);min-width:0}
    .scan-last{display:none}
    .scan-control-meta{display:flex;align-items:center;justify-content:space-between;margin-top:8px;font-size:10.5px;color:var(--text3)}
    .lan-controls{
      flex-wrap:wrap;background:var(--bg3);border:1px solid var(--bd);
      border-radius:calc(var(--radius) + 4px);padding:10px 12px;margin-bottom:0;
    }
    .lan-controls + .scan-control-meta{margin:8px 2px 12px}
    .lan-controls input{flex:1 1 140px;width:auto}
    .scan-count{margin-left:0;flex:1 1 100%;text-align:left}
    /* 移动端统计只保留 4 张分类卡 */
    .scan-stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
    .scan-stats .dns-stat{padding:10px 11px;border-radius:10px}
    .scan-stats .dns-stat-label{font-size:9px;margin-bottom:4px}
    .scan-stats .dns-stat-val{font-size:14px}
    .stat-free{display:none}
    .dns-stat{padding:14px 16px}
    .dns-stat-val{font-size:16px}
    .dns-panel{padding:14px 16px}
    .ps-cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;max-height:none;overflow:visible;padding-right:0}
    .ps-card{padding:12px}
    .port-card{padding:11px}
    .ps-port,.port-num{font-size:17px}
  }
</style>