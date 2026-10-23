<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import CustomSelect from '../components/CustomSelect.svelte';
  import Toggle from '../components/Toggle.svelte';
  import PortScanModal from '../components/PortScanModal.svelte';
  import ConfirmModal from '../components/ConfirmModal.svelte';
  import { suggestProxyName, highlightLog, pollVisible, reverseLines, validateHost, validatePort, fmtMB } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';
  import { fetchDomainOptions, splitFullDomain, writeBindRecord, removeBindRecord, composeFullDomain, HOST_MODE_OPTIONS, resolveDisplayTarget } from '../lib/domainbind.js';

  let loading = true;
  let configured = false;
  let tokenMasked = '';
  let tokenInput = '';
  let showTokenForm = false;
  let saving = false;

  let user = null;
  let nodes = [];
  let proxies = [];
  let running = false;
  let pid = 0;
  let loadedNames = []; // 本地 frpc 当前加载的隧道名（编辑拦截真值源，与 Lolia 同规则）
  let logText = '';
  let refreshing = false;

  // 签到 / 权益抽取
  let signing = false;
  let showCaptcha = false;
  let captchaInput = '';
  let drawing = false;
  let drawDone = 0;
  let drawTotal = 0;
  let drawLines = [];
  let showDrawResult = false;
  let todayDrawMB = 0;
  let drawCount = 0;   // 每日抽奖总次数
  let drawRemaining = -1; // 剩余次数；-1 = 服务端未提供具体剩余
  let drawExhausted = false; // 当日次数已抽完（服务端 remaining 恒为 -1，按天记 localStorage）

  // 创建隧道弹窗
  let showCreate = false;
  let creating = false;
  let editingProxy = null; // 非 null 时弹窗为编辑模式
  let showScan = false; // 本地端口扫描弹窗
  let delTarget = null; // 删除确认目标（非 null 时弹出 ConfirmModal）
  let delBusy = false;
  let showStopConfirm = false; // 停止全部隧道二次确认弹窗
  let stopping = false;
  let createNodes = [];
  let currentGroup = '';
  let pickStep = true; // true=节点选择列表，false=创建表单
  // 节点筛选：地区 + 协议 + 可建站 / 大流量 / 未过载 / 无权限（同时勾选为 AND 语义）
  let regionFilter = '';
  const regionOptions = [
    { value: '', label: i18nTr("全部地区") },
    { value: 'cn', label: i18nTr("中国大陆地区") },
    { value: 'cnos', label: i18nTr("港澳台地区") },
    { value: 'oversea', label: i18nTr("海外") }
  ];
  let protoFilter = '';
  const protoOptions = [
    { value: '', label: i18nTr("全部协议") },
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
    { value: 'http', label: 'HTTP' },
    { value: 'https', label: 'HTTPS' }
  ];
  let fCanSite = false;
  let fBigTraffic = false;
  let fNotOverload = false;
  let fNoPerm = false;
  let form = { nodeId: '', proxyName: '', proxyType: 'tcp', localIp: '127.0.0.1', localPort: null, remotePort: null, domain: '', autoStart: true,
    hostHeaderRewrite: '', httpPlugin: '', crtPath: '', keyPath: '', requestHeadersText: '', responseHeadersText: '', httpUser: '', httpPassword: '',
    accessKey: '', locations: '', proxyProtocolVersion: '', transportProtocol: 'tcp', useEncryption: false, useCompression: false };

  // 创建表单容器与横向行内输入的错误节点
  let formEl;          // 创建/编辑表单容器，提交时统一校验内部字段
  let localPortErr;    // 本地端口错误节点（输入在 .mf-input-btn 横向行内）
  let remotePortErr;   // 远程端口错误节点（同上）

  // 「绑定域名」：从 DNS 解析模块里已有的域名中选根域名，再选主机记录方式，拼出完整域名
  let nodeAddrs = {};      // nodeId -> 节点连接地址（仅「已创建过隧道」的节点才有）
  let bindDomainOpts = []; // DNS 解析模块已有域名 [{ value, label, account }]
  let bindDomain = '';     // 选中的根域名
  let hostMode = '@';      // 主机记录方式：'@' 主域名 | 'sub' 子域名
  let subPrefix = '';      // 子域名前缀（hostMode==='sub' 时使用）
  let orphanDomain = '';   // 编辑时原域名不在 DNS 模块列表中的值（保留回传，避免静默清空）
  let writing = false;     // 写入解析中
  let bindTarget = null;   // 节点地址解析后的记录（类型+值），供界面显示「解析目标」
  const hostModeOpts = HOST_MODE_OPTIONS.map((o) => ({ value: o.value, label: i18nTr(o.label) }));

  const pluginOpts = [
    { value: '', label: i18nTr("不使用") },
    { value: 'http2https', label: i18nTr("http2https · 本地HTTPS经HTTP穿透") },
    { value: 'https2http', label: i18nTr("https2http · 本地HTTP经HTTPS穿透") },
    { value: 'https2https', label: i18nTr("https2https · 本地HTTPS经HTTPS穿透") }
  ];
  const transportOpts = [
    { value: 'tcp', label: 'TCP' },
    { value: 'quic', label: 'QUIC' },
    { value: 'websocket', label: 'WebSocket' }
  ];
  const ppOpts = [
    { value: '', label: i18nTr("不启用") },
    { value: 'v1', label: 'PROXY v1' },
    { value: 'v2', label: 'PROXY v2' }
  ];

  // 把「每行 Key: Value」文本解析为请求/响应头对象
  function parseHeaders(t) {
    const out = {};
    for (const line of (t || '').split('\n')) {
      const i = line.indexOf(':');
      if (i > 0) {
        const k = line.slice(0, i).trim();
        const v = line.slice(i + 1).trim();
        if (k) out[k] = v;
      }
    }
    return out;
  }

  $: currentNode = createNodes.find((n) => n.nodeId === form.nodeId) || null;
  $: typeOptions = currentNode?.allowType ? currentNode.allowType.split(';').filter(Boolean) : ['tcp', 'udp', 'http', 'https'];
  $: typeOpts = typeOptions.map((t) => ({ value: t, label: typeLabel(t) }));

  // 完整域名：@ 直接用根域名；子域名需拼接前缀（未填前缀则为空，视为未配置）
  $: fullDomain = composeFullDomain(bindDomain, hostMode, subPrefix);
  // 当前节点的连接地址。创建数据接口的 hostname 恒为空，地址只来自 /api/mefrp/node-addresses；
  // 按 form.nodeId 取而不是按 currentNode——节点下架后不在可建列表里，但地址仍可能拿得到
  $: nodeAddr = form.nodeId ? (nodeAddrs[String(form.nodeId)] || '') : '';
  $: bindHint = !bindDomain
    ? (editingProxy ? i18nTr("选择域名后，可把该节点的连接地址写进解析") : i18nTr("选择域名后，隧道创建成功即自动写入解析"))
    : (!editingProxy
      ? i18nTr("创建成功后自动写入解析：{0}", [fullDomain || '（请填子域名前缀）'])
      : (!nodeAddr
        ? i18nTr("该节点暂无连接地址（仅已创建过隧道的节点才有），无法写入解析")
        : (bindTarget
          ? i18nTr("解析目标：{0} → {1} {2}", [fullDomain || '（请填子域名前缀）', bindTarget.type, bindTarget.value])
          : i18nTr("解析目标：{0} → 正在解析节点地址…", [fullDomain || '（请填子域名前缀）']))));
  // 删除确认文案：该隧道域名归「域名解析」模块管理时，提示会一并删除解析记录
  $: delDnsHint = (() => {
    const full = (delTarget?.domain || '').trim().toLowerCase();
    if (!full) return '';
    return bindDomainOpts.some((o) => {
      const d = o.value.toLowerCase();
      return full === d || full.endsWith('.' + d);
    }) ? i18nTr("该隧道绑定了域名 {0}，将一并删除指向本节点地址的解析记录。", [delTarget.domain]) : '';
  })();

  function mbps(bw) {
    const m = /(\d+(?:\.\d+)?)\s*(gbps|mbps)/i.exec(bw || '');
    if (!m) return 0;
    return parseFloat(m[1]) * (m[2].toLowerCase() === 'gbps' ? 1000 : 1);
  }

  // 用户带宽限速（inBound 入站/下行、outBound 出站/上行）接口单位为 KB/s，
  // 按 MEFrp 官方客户端口径换算为 Mbps：整数档显示整数，其余保留 1 位小数（25Mbps 档原始值 3200）
  function fmtBw(kBps) {
    const v = (kBps || 0) * 8 / 1024;
    return `${Number.isInteger(v) ? v : v.toFixed(1)} Mbps`;
  }

  // 节点是否对当前用户组开放（无 allowGroup 视为开放）
  function hasPerm(n) {
    return !n.allowGroup || n.allowGroup.split(';').includes(currentGroup);
  }

  function loadColor(p) {
    return (p || 0) >= 100 ? 'var(--red)' : (p || 0) >= 60 ? 'var(--yellow)' : 'var(--green)';
  }

  $: filteredNodes = createNodes.filter((n) => {
    if (regionFilter && (n.region || '') !== regionFilter) return false;
    // 协议筛选：allowType 为分号分隔（如 tcp;udp;http;https），须按段精确比对，
    // 不能用 includes('http')——那会把仅支持 https 的节点误判为支持 http
    if (protoFilter && !(n.allowType || '').split(';').map((s) => s.trim().toLowerCase()).includes(protoFilter)) return false;
    if (fCanSite && !(n.allowType || '').includes('http')) return false;
    if (fBigTraffic && mbps(n.bandwidth) < 100) return false;
    if (fNotOverload && (n.loadPercent || 0) >= 100) return false;
    if (fNoPerm && !hasPerm(n)) return false; // 勾选「无权限」= 筛掉无权限节点（如正式用户用不了的 VIP 节点）
    return true;
  });

  function pickNode(n) {
    if (!hasPerm(n)) {
      // 无权限节点（如正式用户点击 VIP 节点）不允许选择，给出明确提示
      toast(i18nTr("无权使用此节点，请开通 VIP 会员。"), 'error');
      return;
    }
    form.nodeId = n.nodeId;
    const types = (n.allowType || '').split(';').filter(Boolean);
    if (types.length && !types.includes(form.proxyType)) form.proxyType = types[0];
    pickStep = false;
  }

  function typeLabel(t) {
    return { tcp: i18nTr("TCP · 通用转发"), udp: i18nTr("UDP · 通用转发"), http: i18nTr("HTTP · 网站建站"), https: i18nTr("HTTPS · 网站建站") }[t] || t.toUpperCase();
  }

  // 在节点允许端口范围内随机挑一个空闲远程端口（避开该节点上已有隧道占用的端口）
  function autoRemotePort() {
    const n = currentNode;
    if (!n) { toast(i18nTr("请先选择节点"), 'error'); return; }
    const ranges = [];
    for (const part of (n.allowPort || '').split(/[,;，；\s]+/)) {
      const m = part.trim().match(/^(\d+)-(\d+)$/);
      if (m) ranges.push([parseInt(m[1]), parseInt(m[2])]);
      else if (/^\d+$/.test(part.trim())) { const p = parseInt(part.trim()); ranges.push([p, p]); }
    }
    if (!ranges.length) ranges.push([10000, 65535]);
    const used = new Set(proxies.filter((p) => p.nodeId === n.nodeId).map((p) => p.remotePort));
    for (let i = 0; i < 300; i++) {
      const [lo, hi] = ranges[Math.floor(Math.random() * ranges.length)];
      const port = lo + Math.floor(Math.random() * (hi - lo + 1));
      if (!used.has(port)) {
        form.remotePort = port;
        return;
      }
    }
    toast(i18nTr("未找到空闲端口，请手动填写"), 'error');
  }

  const nodeName = (id) => (nodes.find((n) => n.nodeId === id) || {}).name || (i18nTr("节点 ") + id);

  function proxyState(p) {
    if (p.isBanned) return { text: i18nTr("已封禁"), cls: 'badge-error' };
    if (p.isDisabled) return { text: i18nTr("已禁用"), cls: 'badge-off' };
    if (p.isOnline) return { text: i18nTr("在线"), cls: 'badge-on' };
    return { text: i18nTr("离线"), cls: 'badge-off' };
  }

  // 解析 domain 字段：MEFrp 可能返回文本化列表（如 ["mefrp.com"]），取首个域名
  function parseDomain(d) {
    if (!d) return '';
    let s = String(d).trim();
    try {
      const arr = JSON.parse(s);
      if (Array.isArray(arr)) s = arr.filter(Boolean)[0] || '';
    } catch (e) { /* 非 JSON 按原文处理 */ }
    return s.replace(/^[\["'\s]+|[\]"'\s]+$/g, '');
  }

  // 代理访问地址：HTTP(S) 用绑定域名（缺省回退节点连接地址）；TCP/UDP 用 节点地址:远程端口。
  // 节点地址只来自 /api/mefrp/node-addresses——隧道/创建数据接口里的 hostname 恒为空字符串。
  function proxyAddr(p) {
    const addr = nodeAddrs[String(p.nodeId)] || '';
    if (p.proxyType === 'http' || p.proxyType === 'https') {
      const host = parseDomain(p.domain) || addr;
      return (p.proxyType === 'https' ? 'https://' : 'http://') + host;
    }
    return addr ? addr + ':' + p.remotePort : '';
  }

  async function loadTunnels(force = false) {
    refreshing = true;
    try {
      const d = await api('/api/mefrp/tunnels' + (force ? '?refresh=1' : ''), { cache: 'no-store' });
      nodes = d.nodes || [];
      proxies = d.proxies || [];
      // 连接地址只对「已建过隧道的节点」提供，隧道增删后必须重取，否则地址一直是空的
      loadNodeAddrs();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      refreshing = false;
    }
  }

  async function loadStatus() {
    try {
      const d = await api('/api/mefrp/status');
      running = !!d.running;
      pid = d.pid || 0;
      loadedNames = d.names || [];
    } catch (e) { /* ignore */ }
  }

  async function loadUser() {
    try {
      user = await api('/api/mefrp/user');
    } catch (e) { /* ignore */ }
  }

  async function loadLottery() {
    try {
      const d = await api('/api/mefrp/lottery');
      drawCount = d.count || 0;
      drawRemaining = typeof d.remaining === 'number' ? d.remaining : -1;
      todayDrawMB = d.todayMB || 0;
      drawExhausted = drawRemaining === 0 || localStorage.getItem(drawFlagKey()) === '1';
    } catch (e) { /* ignore */ }
  }

  // 「当日已抽完」标记的存储键（按天隔离，跨天自动失效）
  function drawFlagKey() {
    const d = new Date();
    return 'mefrp.drawdone.' + d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
  }
  function setDrawExhausted() {
    if (drawExhausted) return;
    drawExhausted = true;
    try { localStorage.setItem(drawFlagKey(), '1'); } catch (e) { /* ignore */ }
  }

  // 签到：默认直签；被服务端要求人机验证时弹出验证窗口引导用户完成后携带 token 重试
  async function sign(captchaToken = '') {
    signing = true;
    try {
      const d = await api('/api/mefrp/sign', { method: 'POST', body: captchaToken ? { captchaToken } : {} });
      toast(d.message || i18nTr("签到成功"), 'success');
      if (d.user) user = d.user;
      else await loadUser();
      showCaptcha = false;
      captchaInput = '';
    } catch (e) {
      const msg = e.message || i18nTr("签到失败");
      if (/验证|captcha|人机/i.test(msg)) {
        showCaptcha = true;
      } else {
        toast(msg, 'error');
      }
    } finally {
      signing = false;
    }
  }

  // 点击权益抽取：按每日总次数抽满。服务端 remaining 时常少算（历史多为 -1/偏小），
  // 不能作为抽取次数基准；以每日总次数为准，真实上限由服务端在循环内校验（remaining===0 / 报错即停）。
  async function draw() {
    drawing = true;
    drawLines = [];
    try {
      if (drawCount <= 0) await loadLottery(); // 每日总次数未知时先拉取
      const target = drawCount > 0 ? drawCount : 10; // 每日总次数兜底 10
      if (target <= 0) {
        toast(i18nTr("暂无剩余抽奖次数"), 'info');
        return;
      }
      drawDone = 0;
      drawTotal = target;
      for (let i = 0; i < drawTotal; i++) {
        const d = await api('/api/mefrp/draw', { method: 'POST' });
        drawDone++;
        if (typeof d.todayMB === 'number') todayDrawMB = d.todayMB;
        if (typeof d.count === 'number' && d.count > 0) drawCount = d.count;
        drawRemaining = typeof d.remaining === 'number' ? d.remaining : Math.max(0, drawCount - drawDone);
        const reward = d.rewardMB > 0 ? `（+${fmtMB(d.rewardMB)}）` : '';
        // 抽到优惠码时追加展示码值，方便直接复制使用
        const coupon = typeof d.coupon === 'string' && d.coupon ? i18nTr("，优惠码：{0}", [d.coupon]) : '';
        drawLines = [...drawLines, i18nTr("第 {0} 抽：{1}{2}{3}", [drawDone, d.message || '已完成', reward, coupon])];
        if (d.remaining === 0) break;
      }
      // remaining 未知时按上限抽满即视为当日已抽完（防止按钮一直停留在可抽取状态）
      if (drawRemaining === 0 || (drawRemaining < 0 && drawDone >= drawTotal)) setDrawExhausted();
      toast(i18nTr("已抽完 {0} 次", [drawDone]), 'success');
      await loadUser(); // 抽奖增加流量后刷新账户信息
    } catch (e) {
      const msg = e.message || i18nTr("抽奖失败");
      drawLines = [...drawLines, i18nTr("已中断：{0}", [msg])];
      toast(drawDone > 0 ? i18nTr("已抽 {0} 次后中断：{1}", [drawDone, msg]) : msg, 'error');
      // 服务端明确报次数已达上限（如「今日抽奖次数已达上限」）→ 记当日已抽完
      if (/上限|用完|次数已/.test(msg)) setDrawExhausted();
      await loadUser();
    } finally {
      drawing = false;
      if (drawDone > 0) showDrawResult = true; // 抽取结束后弹窗展示收到的内容
    }
  }

  async function init() {
    loading = true;
    try {
      const c = await api('/api/mefrp/config');
      configured = !!c.configured;
      tokenMasked = c.token || '';
      if (configured) {
        // 进入页面强制拉取一次最新通道数据（refresh=1 绕过服务端 60s 缓存）
        await Promise.all([loadTunnels(true), loadStatus(), loadUser(), loadLottery()]);
        loadLog();
      }
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      loading = false;
    }
  }

  async function saveToken() {
    if (!tokenInput.trim()) { toast(i18nTr("请输入访问密钥"), 'error'); return; }
    saving = true;
    try {
      const d = await api('/api/mefrp/config', { method: 'POST', body: { token: tokenInput.trim() } });
      configured = true;
      tokenMasked = d.token;
      user = d.user;
      tokenInput = '';
      showTokenForm = false;
      toast(i18nTr("MEFrp 密钥已保存"), 'success');
      await loadTunnels(true);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      saving = false;
    }
  }

  async function openCreate() {
    editingProxy = null;
    showCreate = true;
    pickStep = true;
    bindDomain = ''; hostMode = '@'; subPrefix = ''; orphanDomain = '';
    try {
      const d = await api('/api/mefrp/createdata');
      createNodes = d.nodes || [];
      currentGroup = d.currentGroup || '';
    } catch (e) {
      toast(e.message, 'error');
    }
    loadNodeAddrs();
    loadBindDomains();
  }

  // 编辑隧道：复用创建弹窗表单（名称锁定，走 update 接口；进阶字段仅支持 Host 重写/PROXY/加密/压缩）
  async function editProxy(p) {
    // 运行中的隧道本地 frpc 仍加载旧配置，云端改动不会热同步，必须先停止再编辑（与 Lolia 同规则）
    if (loadedNames.includes(p.proxyName)) {
      toast(i18nTr("该隧道暂未关闭，请关闭后修改"), 'error');
      return;
    }
    editingProxy = p;
    form = { ...form, nodeId: p.nodeId, proxyName: p.proxyName, proxyType: (p.proxyType || 'tcp').toLowerCase(), localIp: p.localIp, localPort: p.localPort, remotePort: p.remotePort, domain: p.domain || '', autoStart: false,
      hostHeaderRewrite: p.hostHeaderRewrite || '', proxyProtocolVersion: p.proxyProtocolVersion || '', useEncryption: !!p.useEncryption, useCompression: !!p.useCompression };
    showCreate = true;
    pickStep = false;
    if (!createNodes.length) {
      try {
        const d = await api('/api/mefrp/createdata');
        createNodes = d.nodes || [];
        currentGroup = d.currentGroup || '';
      } catch (e) {
        toast(e.message, 'error');
      }
    }
    // 域名回填依赖「DNS 模块已有域名」列表与「节点连接地址」，先取到位再拆分
    await Promise.all([loadNodeAddrs(), loadBindDomains()]);
    fillBindDomain(p.domain || '');
    // 解析目标展示的是「实际会写进解析的记录」——把节点地址解析成 IP，避免把节点域名误当目标
    bindTarget = await resolveDisplayTarget(nodeAddrs[String(p.nodeId)] || '');
  }

  async function createProxy() {
    // 格式校验：表单内地址/端口/域名字段统一拦截并就地提示
    if (!validateAll(formEl)) return;
    if (!form.nodeId) { toast(i18nTr("请选择服务器（节点）"), 'error'); return; }
    if (!form.proxyName.trim()) { toast(i18nTr("请填写隧道名称"), 'error'); return; }
    if (!form.localPort || form.localPort < 1 || form.localPort > 65535) { toast(i18nTr("请填写本地端口（1-65535）"), 'error'); return; }
    // HTTP/HTTPS 隧道无远程端口概念，自动按协议补 80/443（服务端要求该字段必填）
    if (form.proxyType === 'http' || form.proxyType === 'https') {
      if (!form.remotePort) form.remotePort = form.proxyType === 'https' ? 443 : 80;
    } else if (!form.remotePort || form.remotePort < 1 || form.remotePort > 65535) {
      toast(i18nTr("请填写远程端口（1-65535）"), 'error'); return;
    }
    // 绑定域名由「域名选择 + 主机记录」拼出：选了域名就必须能拼出完整域名
    if ((form.proxyType === 'http' || form.proxyType === 'https') && bindDomain && !fullDomain) {
      toast(i18nTr("请填写子域名前缀"), 'error'); return;
    }
    // 未选择域名时，若原隧道域名不在 DNS 模块列表里则照旧回传（避免编辑时被静默清空）
    form.domain = fullDomain || orphanDomain;
    creating = true;
    try {
      if (editingProxy) {
        const d = await api('/api/mefrp/proxy/update', { method: 'POST', body: {
          proxyId: editingProxy.proxyId,
          proxyName: form.proxyName.trim(), proxyType: form.proxyType, nodeId: form.nodeId,
          localIp: form.localIp.trim(), localPort: form.localPort, remotePort: form.remotePort, domain: form.domain,
          hostHeaderRewrite: form.hostHeaderRewrite, proxyProtocolVersion: form.proxyProtocolVersion,
          useEncryption: form.useEncryption, useCompression: form.useCompression
        } });
        toast(d.message || i18nTr("隧道已修改"), 'success');
        showCreate = false;
        await loadTunnels(true);
        return;
      }
      const { requestHeadersText, responseHeadersText, ...payload } = form;
      payload.proxyName = form.proxyName.trim();
      payload.requestHeaders = parseHeaders(requestHeadersText);
      payload.responseHeaders = parseHeaders(responseHeadersText);
      const d = await api('/api/mefrp/proxy/create', { method: 'POST', body: payload });
      toast(d.message || i18nTr("隧道创建成功"), 'success');
      showCreate = false;
      await loadTunnels(true);
      // 隧道建好后 MEFrp 才会提供该节点的连接地址：此时按所选域名写入解析
      await writeDNSAfterCreate(form.nodeId);
      if (form.autoStart) {
        const p = proxies.find((x) => x.proxyName === form.proxyName.trim());
        if (p) {
          try {
            await api('/api/mefrp/start', { method: 'POST', body: { proxyIds: [p.proxyId] } });
            toast(i18nTr("隧道已启动"), 'success');
            await loadStatus();
          } catch (e2) {
            toast(e2.message, 'error');
          }
        } else {
          toast(i18nTr("列表尚未同步到新隧道，请稍后刷新后再启动"), 'info');
        }
      }
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      creating = false;
    }
  }

  // HTTP/HTTPS 隧道无远程端口概念，展示节点服务器地址供用户做域名解析
  function copyServerAddr() {
    const host = nodeAddr;
    if (!host) { toast(i18nTr("该节点暂无连接地址（仅已创建过隧道的节点才有）"), 'error'); return; }
    if (navigator.clipboard) {
      navigator.clipboard.writeText(host).then(() => toast(i18nTr("服务器地址已复制：") + host, 'success'), () => toast(host, 'info'));
    } else {
      toast(host, 'info');
    }
  }

  // 加载节点连接地址（/auth/node/nameList：只含已创建过隧道的节点）
  async function loadNodeAddrs() {
    try {
      const addrs = await api('/api/mefrp/node-addresses');
      nodeAddrs = Object.fromEntries((addrs || []).map((x) => [String(x.nodeId), x.hostname || '']));
    } catch (e) { /* 地址获取失败不阻塞表单，相关入口置灰即可 */ }
  }

  // 加载「域名解析」模块里已有的全部域名（跨账户聚合，供下拉选择）
  async function loadBindDomains() {
    try {
      bindDomainOpts = await fetchDomainOptions();
    } catch (e) { bindDomainOpts = []; }
  }

  // 编辑回填：把隧道已有的域名拆成「根域名 + 主机记录方式 + 前缀」。
  // 匹配不到「域名解析」里的根域名时不强行改写，原值留在 orphanDomain 里照旧回传。
  function fillBindDomain(full) {
    const s = splitFullDomain(full, bindDomainOpts);
    bindDomain = s.root;
    hostMode = s.mode;
    subPrefix = s.prefix;
    orphanDomain = s.orphan;
  }

  // 把当前选择转成共用模块需要的参数（账户 / 根域名 / 主机记录）
  function bindParams(addr) {
    const opt = bindDomainOpts.find((o) => o.value === bindDomain);
    if (!opt) throw new Error(i18nTr("未找到该域名所属的 DNS 账户"));
    return { account: opt.account, root: bindDomain, rr: hostMode === '@' ? '@' : subPrefix.trim(), addr };
  }

  // 「写入解析」按钮（编辑态）：用当前节点的连接地址写记录
  async function writeDNSRecord() {
    if (!bindDomain) { toast(i18nTr("请先选择域名"), 'error'); return; }
    if (!fullDomain) { toast(i18nTr("请填写子域名前缀"), 'error'); return; }
    if (!nodeAddr) { toast(i18nTr("该节点暂无连接地址（仅已创建过隧道的节点才有）"), 'error'); return; }
    writing = true;
    try {
      const t = await writeBindRecord(bindParams(nodeAddr));
      toast(i18nTr("解析已写入：{0} {1} {2}", [fullDomain, t.type, t.value]), 'success');
    } catch (e) {
      toast(i18nTr("写入解析失败：") + e.message, 'error');
    } finally {
      writing = false;
    }
  }

  // 隧道创建成功后自动写入解析：MEFrp 只在隧道建好之后才会给出该节点的连接地址
  async function writeDNSAfterCreate(nodeId) {
    if (!bindDomain || !fullDomain) return; // 未配置自定义域名则跳过
    await loadNodeAddrs();
    const addr = nodeAddrs[String(nodeId)] || '';
    if (!addr) {
      toast(i18nTr("隧道已创建，但尚未取到节点连接地址；可在编辑弹窗中点「写入解析」重试"), 'info');
      return;
    }
    try {
      const t = await writeBindRecord(bindParams(addr));
      toast(i18nTr("解析已写入：{0} {1} {2}", [fullDomain, t.type, t.value]), 'success');
    } catch (e) {
      toast(i18nTr("隧道已创建，但写入解析失败：") + e.message, 'error');
    }
  }

  // 删除隧道时同步移除它绑定的解析记录（安全匹配逻辑见 lib/domainbind.js）
  function cleanBindRecord(proxy) {
    return removeBindRecord({
      full: proxy?.domain || '',
      addr: nodeAddrs[String(proxy?.nodeId)] || '',
      options: bindDomainOpts
    });
  }

  // 列表操作：启停 / 删除 / 强制下线
  // 注意：MEFrp 服务端列表有约 5 分钟缓存，操作成功后状态可能不会立刻反映，稍后自动补刷
  async function proxyAction(p, action, extra = {}) {
    try {
      const msg = await api('/api/mefrp/proxy/' + action, { method: 'POST', body: { proxyId: p.proxyId, ...extra } });
      toast((msg || i18nTr("操作成功")) + i18nTr("，云端状态同步有延迟"), 'success');
      await Promise.all([loadTunnels(true), loadStatus()]);
      setTimeout(() => { loadTunnels(true); loadStatus(); }, 8000);
      return true;
    } catch (e) {
      toast(e.message, 'error');
      return false;
    }
  }
  function deleteProxy(p) {
    delTarget = p;
    // 清理解析记录需要「域名解析」的域名列表与节点连接地址，先补齐（异步到位后确认文案会更新）
    loadNodeAddrs();
    loadBindDomains();
  }
  async function confirmDeleteProxy() {
    if (!delTarget) return;
    delBusy = true;
    try {
      // 失败时保留弹窗，便于用户重试（删除未成功则不触碰解析记录）
      if (!(await proxyAction(delTarget, 'delete'))) return;
    } finally {
      delBusy = false;
    }
    // 隧道已删除：同步移除它绑定的解析记录
    try {
      const r = await cleanBindRecord(delTarget);
      if (r?.removed) toast(i18nTr("已同步删除解析记录：") + r.removed, 'success');
      else if (r?.notfound) toast(i18nTr("未找到指向本节点的解析记录，已跳过（{0} 的记录可能已被手工修改）", [r.notfound]), 'info');
    } catch (e) {
      toast(i18nTr("隧道已删除，但解析记录清理失败：") + e.message, 'error');
    }
    delTarget = null;
  }
  function kickProxy(p) { proxyAction(p, 'kick'); }

  // 启动单条隧道（拉起本地 frpc，仅包含该隧道，并更新自启列表）
  async function startProxy(p) {
    try {
      const msg = await api('/api/mefrp/start', { method: 'POST', body: { proxyIds: [p.proxyId] } });
      toast((msg || i18nTr("隧道已启动")) + i18nTr("，云端状态同步有延迟"), 'success');
      await Promise.all([loadTunnels(true), loadStatus()]);
      setTimeout(() => { loadTunnels(true); loadStatus(); }, 8000);
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  function stop() {
    showStopConfirm = true;
  }

  async function confirmStop() {
    stopping = true;
    try {
      const msg = await api('/api/mefrp/stop', { method: 'POST' });
      toast(msg || i18nTr("MEFrp 隧道已停止"), 'success');
      showStopConfirm = false;
      await Promise.all([loadStatus(), loadTunnels(true)]);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      stopping = false;
    }
  }

  async function loadLog() {
    try {
      const d = await api('/api/mefrp/log?lines=200');
      logText = reverseLines(d.log || i18nTr("（暂无日志）"));
    } catch (e) {
      logText = i18nTr("读取日志失败: ") + e.message;
    }
  }

  onMount(() => {
    init();
    // 日志常驻展示，定时刷新（15s 与列表刷新节奏错开，日志尾部读取开销很小）
    const t = pollVisible(loadLog, 15000);
    return () => t();
  });
</script>

<div class="container page-list">
  <div class="page-hdr">
    <div>
      <h2>MEFrp</h2>
      <span class="page-hdr-sub">{$i18n("ME Frp 幻缘映射 · 稳定高效的内网穿透利器")}</span>
    </div>
    <div class="page-hdr-actions hdr-actions-wrap">
      {#if configured}
        <button class="btn btn-sm" on:click={() => (showTokenForm = !showTokenForm)}>{$i18n("更换密钥")}</button>
        <button class="btn btn-sm" disabled={refreshing} on:click={() => loadTunnels(true)}>{refreshing ? i18nTr("刷新中…") : i18nTr("刷新列表")}</button>
        <button class="btn btn-primary btn-sm" on:click={openCreate}>{$i18n("创建隧道")}</button>
      {/if}
    </div>
  </div>

  {#if loading}
    <div class="empty"><div class="empty-t">{$i18n("加载中…")}</div></div>
  {:else}
    <!-- 密钥配置卡片：未绑定或点击「更换密钥」时显示 -->
    {#if !configured || showTokenForm}
      <div class="mf-card">
        <h3>{$i18n("绑定 MEFrp 账户")}</h3>
        <div class="mf-tip">{$i18n("登录 MEFrp 官网 → 控制台 → 访问密钥，复制后粘贴到下方。保存时会自动验证密钥有效性。")}</div>
        <div class="mf-token-row">
          <input type="password" placeholder={$i18n("粘贴访问密钥")} bind:value={tokenInput} on:keydown={(e) => e.key === 'Enter' && saveToken()} />
          <button class="btn btn-primary" disabled={saving} on:click={saveToken}>{saving ? i18nTr("验证中…") : i18nTr("保存并验证")}</button>
          {#if configured}
            <button class="btn" on:click={() => (showTokenForm = false)}>{$i18n("取消")}</button>
          {/if}
        </div>
        <div class="mf-tip" style="margin-top:8px">
          <a href="https://www.mefrp.com" target="_blank" rel="noopener noreferrer" style="color:var(--accent)">{$i18n("前往 MEFrp 官网获取密钥 ↗")}</a>
        </div>
      </div>
      {#if !configured}
        <div class="mf-card mf-guide">
          <h3>{$i18n("绑定后可用")}</h3>
          <div class="mf-guide-grid">
            <div class="mf-guide-item"><b>{$i18n("云端隧道")}</b><span>{$i18n("同步 MEFrp 控制台创建的隧道，支持启停、编辑与强制下线")}</span></div>
            <div class="mf-guide-item"><b>{$i18n("本地 frpc")}</b><span>{$i18n("一键启动 / 停止，实时查看 PID 与已加载隧道数量")}</span></div>
            <div class="mf-guide-item"><b>{$i18n("账户权益")}</b><span>{$i18n("隧道配额、带宽上限、剩余流量、每日签到与权益抽取")}</span></div>
          </div>
        </div>
      {/if}
    {/if}

    {#if configured}
      <!-- 账户信息 -->
      {#if user}
        <div class="mf-card mf-acct">
          <div class="mf-avatar">{(user.username || 'M').charAt(0).toUpperCase()}</div>
          <div class="mf-acct-id">
            <b>{user.username} <span class="badge badge-on">{$i18n("已绑定")}</span></b>
            <span>{$i18n("密钥")} <code class="mf-mono">{tokenMasked}</code>{#if user.friendlyGroup} {$i18n("· 分组")} {user.friendlyGroup}{/if}</span>
          </div>
          <div class="mf-acct-stats">
            <div class="mf-acct-stat"><span>{$i18n("隧道配额")}</span><b>{user.usedProxies} / {user.maxProxies}</b></div>
            <div class="mf-acct-stat"><span>{$i18n("剩余流量")}</span><b style="color:var(--green)">{fmtMB(user.traffic)}</b></div>
            <div class="mf-acct-stat"><span>{$i18n("入站带宽")}</span><b>{fmtBw(user.inBound)}</b></div>
            <div class="mf-acct-stat"><span>{$i18n("出站带宽")}</span><b>{fmtBw(user.outBound)}</b></div>
          </div>
          <div class="mf-acct-actions">
            <span class="mf-k">{$i18n("今日签到")}</span>
            {#if user.todaySigned}
              <span class="badge badge-on">{$i18n("已签到")}</span>
            {:else}
              <span
                class="badge badge-warn mf-clickable"
                role="button"
                tabindex="0"
                title={$i18n("点击签到")}
                on:click={() => !signing && !drawing && sign()}
                on:keydown={(e) => e.key === 'Enter' && !signing && !drawing && sign()}
              >{signing ? i18nTr("签到中…") : i18nTr("未签到，点击签到")}</span>
            {/if}
            <span class="mf-k" style="margin-left:14px">{$i18n("权益抽取")}</span>
            {#if drawing}
              <button class="btn btn-sm" disabled>{$i18n("抽取中")} {drawDone}/{drawTotal}</button>
            {:else if drawRemaining === 0 || drawExhausted}
              <span class="badge badge-on">{$i18n("已抽取")}</span>
              {#if todayDrawMB > 0}
                <span class="badge badge-on">{$i18n("今日已抽 +")}{fmtMB(todayDrawMB)}</span>
              {/if}
            {:else}
              <button class="btn btn-sm" on:click={draw}>{$i18n("抽取")}</button>
            {/if}
          </div>
        </div>
      {/if}

      <!-- 本地运行状态 + 操作 -->
      <div class="mf-card mf-statusbar">
        <span class="mf-status">
          <span class="mf-dot" style="background:{running ? 'var(--green)' : 'var(--text3)'};box-shadow:{running ? '0 0 0 3px rgba(var(--green-rgb),.12)' : 'none'}"></span>
          <b>{running ? i18nTr("本地 frpc 运行中") : i18nTr("本地 frpc 未运行")}</b>
          {#if running}<span class="mf-status-meta">PID {pid} {$i18n("· 已加载")} {loadedNames.length} {$i18n("条隧道")}</span>{/if}
        </span>
        <div class="mf-actions">
          <button class="btn btn-danger btn-sm" disabled={stopping || !running} on:click={stop}>{stopping ? i18nTr("停止中…") : i18nTr("停止")}</button>
        </div>
      </div>

      <!-- 隧道列表 -->
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{$i18n("隧道名称")}</th>
              <th>{$i18n("类型")}</th>
              <th>{$i18n("节点")}</th>
              <th>{$i18n("本地地址")}</th>
              <th>{$i18n("代理地址")}</th>
              <th>{$i18n("云端状态")}</th>
              <th>{$i18n("操作")}</th>
            </tr>
          </thead>
          <tbody>
            {#each proxies as p (p.proxyId)}
              <tr>
                <td>
                  <span class="mf-name">
                    <span class="mf-dot" style="background:{p.isBanned ? 'var(--red)' : p.isOnline ? 'var(--green)' : 'var(--text3)'}"></span>
                    {p.proxyName}
                  </span>
                </td>
                <td><span class="badge" class:badge-blue={p.proxyType === 'tcp'} class:badge-warn={p.proxyType === 'udp'} class:badge-info={p.proxyType === 'http'} class:badge-on={p.proxyType === 'https'}>{p.proxyType.toUpperCase()}</span></td>
                <td class="mf-muted">{nodeName(p.nodeId)}</td>
                <td class="cell-mono">{p.localIp}:{p.localPort}</td>
                <td>
                  {#if p.proxyType === 'http' || p.proxyType === 'https'}
                    <a class="cell-link cell-mono" href={proxyAddr(p)} target="_blank" rel="noopener noreferrer" title={$i18n("点击打开")}>{proxyAddr(p)}</a>
                  {:else}
                    <a class="cell-link cell-mono" href={'http://' + proxyAddr(p)} target="_blank" rel="noopener noreferrer" title={$i18n("点击打开（浏览器可能无法直接访问 TCP 服务）")}>{proxyAddr(p)}</a>
                  {/if}
                </td>
                <td><span class="badge {proxyState(p).cls}">{proxyState(p).text}</span></td>
                <td>
                  <div class="mf-ops">
                    <!-- 电源按钮：只有真的在线才是绿色（点击强制下线）；离线为灰色（点击启用隧道）——
                         与「代理列表」「端口转发」「打洞通道」保持同一套状态着色规则 -->
                    {#if p.isOnline}
                      <button class="btn-icon" style="color: var(--green);" title={$i18n("强制下线")} aria-label={$i18n("强制下线")} on:click={() => kickProxy(p)}>
                        <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M24 4V24" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
                      </button>
                    {:else}
                      <button class="btn-icon" style="color: var(--text3);" title={$i18n("启用隧道")} aria-label={$i18n("启用隧道")} on:click={() => startProxy(p)}>
                        <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M24 4V24" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
                      </button>
                    {/if}
                    <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑")} on:click={() => editProxy(p)}>
                      <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M10 44H38C39.1046 44 40 43.1046 40 42V14H30V4H10C8.89543 4 8 4.89543 8 6V42C8 43.1046 8.89543 44 10 44Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M30 4L40 14" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M21 35L31 25L27 21L17 31V35H21Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
                    </button>
                    <button class="btn-icon" style="color: var(--red);" title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => deleteProxy(p)}>
                      <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"></path><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
                    </button>
                  </div>
                </td>
              </tr>
            {:else}
              <tr><td colspan="7"><div class="empty" style="padding:24px 0"><div class="empty-t">{refreshing ? i18nTr("加载中…") : i18nTr("MEFrp 账户下暂无隧道，点击「创建隧道」新建")}</div></div></td></tr>
            {/each}
          </tbody>
        </table>
        <div class="mf-table-foot">
          <span>{$i18n("共")} {proxies.length} {$i18n("条隧道 ·")} <span style="color:var(--green)">{proxies.filter((p) => p.isOnline).length} {$i18n("条在线")}</span></span>
          <span class="mf-foot-meta">{$i18n("节点由 MEFrp 云端下发")}</span>
        </div>
      </div>

      <!-- 隧道列表卡片：仅移动端显示（桌面端由 app.css 隐藏，表格保持原样） -->
      <div class="list-cards">
        {#if proxies.length === 0}
          <div class="list-cards-empty">{refreshing ? i18nTr("加载中…") : i18nTr("MEFrp 账户下暂无隧道，点击「创建隧道」新建")}</div>
        {/if}
        {#each proxies as p (p.proxyId)}
          <div class="list-card" on:click={() => editProxy(p)}>
            <div class="list-card-top">
              <span class="mf-dot" style="background:{p.isBanned ? 'var(--red)' : p.isOnline ? 'var(--green)' : 'var(--text3)'}"></span>
              <div class="list-card-title">{p.proxyName}</div>
              <span class="badge" class:badge-blue={p.proxyType === 'tcp'} class:badge-warn={p.proxyType === 'udp'} class:badge-info={p.proxyType === 'http'} class:badge-on={p.proxyType === 'https'}>{p.proxyType.toUpperCase()}</span>
              <span class="badge {proxyState(p).cls}" style="margin-left:auto;flex-shrink:0">{proxyState(p).text}</span>
            </div>
            <div class="list-card-sub">{nodeName(p.nodeId)}</div>
            <div class="list-card-rows" on:click={(e) => e.stopPropagation()}>
              <div class="list-card-row"><span class="k">{$i18n("本地")}</span><span class="v cell-mono ellip">{p.localIp}:{p.localPort}</span></div>
              <div class="list-card-row"><span class="k">{$i18n("代理")}</span>
                <span class="v">
                  {#if p.proxyType === 'http' || p.proxyType === 'https'}
                    <a class="cell-link ellip" href={proxyAddr(p)} target="_blank" rel="noopener noreferrer" title={$i18n("点击打开")}>{proxyAddr(p)}</a>
                  {:else}
                    <a class="cell-link ellip" href={'http://' + proxyAddr(p)} target="_blank" rel="noopener noreferrer" title={$i18n("点击打开（浏览器可能无法直接访问 TCP 服务）")}>{proxyAddr(p)}</a>
                  {/if}
                </span>
              </div>
            </div>
            <div class="list-card-actions" on:click={(e) => e.stopPropagation()}>
              <span class="mf-foot-note">{$i18n("MEFrp 云端")}</span>
              <!-- 电源按钮：只有真的在线才是绿色（点击强制下线）；离线为灰色（点击启用隧道）——
                   与「代理列表」「端口转发」「打洞通道」保持同一套状态着色规则 -->
              {#if p.isOnline}
                <button class="btn-icon" style="color: var(--green);" title={$i18n("强制下线")} aria-label={$i18n("强制下线")} on:click={() => kickProxy(p)}>
                  <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M24 4V24" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
                </button>
              {:else}
                <button class="btn-icon" style="color: var(--text3);" title={$i18n("启用隧道")} aria-label={$i18n("启用隧道")} on:click={() => startProxy(p)}>
                  <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M24 4V24" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
                </button>
              {/if}
              <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑")} on:click={() => editProxy(p)}>
                <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M10 44H38C39.1046 44 40 43.1046 40 42V14H30V4H10C8.89543 4 8 4.89543 8 6V42C8 43.1046 8.89543 44 10 44Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M30 4L40 14" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M21 35L31 25L27 21L17 31V35H21Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
              </button>
              <button class="btn-icon" style="color: var(--red);" title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => deleteProxy(p)}>
                <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"></path><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
              </button>
            </div>
          </div>
        {/each}
      </div>

      <!-- frpc 运行日志：常驻展示，与隧道列表保持间距 -->
      <div class="mf-card" style="margin-top:14px">
        <h3>{$i18n("frpc 运行日志")}</h3>
        <pre class="mf-log">{@html highlightLog(logText)}</pre>
      </div>
    {/if}
  {/if}
</div>

{#if showCreate}
  <div class="modal-overlay" on:click|self={() => (showCreate = false)} role="presentation">
    <div class="modal" style="max-width:{pickStep ? '960px' : '560px'}">
      <div class="modal-hdr">
        <h3>{pickStep ? i18nTr("选择节点") : (editingProxy ? i18nTr("编辑隧道") : i18nTr("创建 MEFrp 隧道"))}</h3>
        <button class="modal-close" on:click={() => (showCreate = false)} aria-label={$i18n("关闭")}>×</button>
      </div>
      <div class="modal-body">
        {#if pickStep}
          <!-- 步骤一：节点列表 -->
          <div class="mf-filters">
            <CustomSelect bind:value={regionFilter} options={regionOptions} width="150px" />
            <CustomSelect bind:value={protoFilter} options={protoOptions} width="120px" />
            <label class="mf-fcheck"><input type="checkbox" bind:checked={fCanSite} /> {$i18n("可建站")}</label>
            <label class="mf-fcheck"><input type="checkbox" bind:checked={fBigTraffic} /> {$i18n("大流量")}</label>
            <label class="mf-fcheck"><input type="checkbox" bind:checked={fNotOverload} /> {$i18n("未过载")}</label>
            <label class="mf-fcheck"><input type="checkbox" bind:checked={fNoPerm} /> {$i18n("无权限")}</label>
            <span class="mf-fcount">{filteredNodes.length} / {createNodes.length} {$i18n("个节点")}</span>
          </div>
          <div class="mf-nodes">
            {#each filteredNodes as n (n.nodeId)}
              <div
                class="mf-node"
                class:mf-node-off={n.isDisabled}
                class:mf-node-sel={form.nodeId === n.nodeId}
                role="button"
                tabindex="0"
                on:click={() => pickNode(n)}
                on:keydown={(e) => e.key === 'Enter' && pickNode(n)}
              >
                <div class="mf-node-hd">
                  <span class="mf-node-name">#{n.nodeId} {n.name}</span>
                  <span class="mf-node-tags-hd">
                    {#if !hasPerm(n)}
                      {#if (n.allowGroup || '').includes('vip')}
                        <span class="mf-tag mf-tag-vip" title={$i18n("VIP 用户组专属节点")}>VIP</span>
                      {:else}
                        <span class="mf-tag mf-tag-noperm" title={$i18n("当前用户组无权使用该节点")}>{$i18n("无权限")}</span>
                      {/if}
                    {/if}
                    {#if (n.loadPercent || 0) >= 100}
                      <span class="mf-tag mf-tag-load">{$i18n("过载")}</span>
                    {/if}
                    {#if n.isDisabled}
                      <span class="mf-tag mf-tag-load">{$i18n("禁用")}</span>
                    {/if}
                  </span>
                </div>
                <div class="mf-node-tags">
                  {#each (n.allowType || '').split(';').filter(Boolean) as t}
                    <span class="mf-badge">{t.toUpperCase()}</span>
                  {/each}
                  <span class="mf-badge mf-badge-bw">{n.bandwidth || '—'}</span>
                </div>
                <div class="mf-node-desc" title={n.description || ''}>{n.description || i18nTr("暂无节点描述")}</div>
                <div class="mf-node-ft">
                  <div class="mf-loadbar">
                    <div class="mf-loadbar-in" style="width:{Math.min(n.loadPercent || 0, 100)}%;background:{loadColor(n.loadPercent)}"></div>
                  </div>
                  <span class="mf-loadtxt">{n.loadPercent || 0}{$i18n("% 负载")}</span>
                </div>
              </div>
            {:else}
              <div class="empty" style="grid-column:1/-1"><div class="empty-t">{$i18n("没有符合筛选条件的节点")}</div></div>
            {/each}
          </div>
        {:else}
          <!-- 步骤二：创建表单 -->
          <div bind:this={formEl}>
          <div class="form-group">
            <label class="form-label">{$i18n("服务器（节点）")}</label>
            <div class="mf-picked">
              <div class="mf-picked-hd">
                <span>{$i18n("节点")} <b>{currentNode ? `#${currentNode.nodeId} ${currentNode.name}` : i18nTr("未选择")}</b></span>
                {#if !editingProxy}
                  <button class="btn btn-sm" on:click={() => (pickStep = true)}>{$i18n("重新选择")}</button>
                {/if}
              </div>
              {#if currentNode}
                <div class="mf-node-tags">
                  {#each (currentNode.allowType || '').split(';').filter(Boolean) as t}
                    <span class="mf-badge">{t.toUpperCase()}</span>
                  {/each}
                  <span class="mf-badge mf-badge-port" title={$i18n("允许使用的远程端口范围")}>{currentNode.allowPort || '—'}</span>
                  <span class="mf-badge mf-badge-bw">{currentNode.bandwidth || '—'}</span>
                </div>
              {/if}
              {#if editingProxy}
                <!-- MEFrp 的修改接口会对 nodeId 返回成功但并不生效（服务端不支持换节点），
                     因此编辑模式下不提供换节点入口，避免误以为已切换 -->
                <div class="mf-tip">{$i18n("MEFrp 不支持修改隧道节点，如需更换节点请删除该隧道后按新节点重建")}</div>
              {/if}
            </div>
          </div>
          <div class="form-row">
            <div class="form-group" style="flex:1.6">
              <label class="form-label">{$i18n("隧道名称")}</label>
              <input type="text" bind:value={form.proxyName} placeholder={$i18n("账户内唯一，如 my-web")} disabled={!!editingProxy} title={editingProxy ? i18nTr("MEFrp 按名称定位隧道，编辑时名称不可更改") : undefined} />
            </div>
            <div class="form-group" style="flex:1;max-width:210px">
              <label class="form-label">{$i18n("类型")}</label>
              <CustomSelect bind:value={form.proxyType} options={typeOpts} />
            </div>
          </div>
          <div class="form-row">
            <div class="form-group" style="flex:1.6">
              <label class="form-label">{$i18n("本地地址")}</label>
              <input type="text" bind:value={form.localIp} placeholder="127.0.0.1" use:field={{ check: validateHost }} />
              <div class="mf-tip">{$i18n("本机服务填 127.0.0.1，局域网设备填对应内网 IP")}</div>
            </div>
            <div class="form-group" style="flex:1;max-width:210px">
              <label class="form-label">{$i18n("本地端口")}</label>
              <div class="mf-input-btn">
                <input type="number" min="1" max="65535" bind:value={form.localPort} placeholder={$i18n("本机服务端口")} use:field={{ check: validatePort, errAt: () => localPortErr }} />
                <button class="btn btn-sm" type="button" title={$i18n("扫描本机/局域网开放端口")} on:click={() => (showScan = true)}>{$i18n("扫描")}</button>
              </div>
              <div class="field-err" bind:this={localPortErr} style="display:none"></div>
            </div>
          </div>
          {#if form.proxyType === 'http' || form.proxyType === 'https'}
            <!-- 连接地址由 MEFrp 只在「已建过隧道」的节点上提供，新建时必然为空，故仅编辑态展示 -->
            {#if editingProxy}
              <div class="form-row">
                <div class="form-group" style="flex:1">
                  <label class="form-label">{$i18n("服务器地址")}</label>
                  <div class="mf-input-btn">
                    <input type="text" value={nodeAddr} readonly tabindex="-1" placeholder={$i18n("该节点暂无连接地址")} />
                    <button class="btn btn-sm" type="button" on:click={copyServerAddr}>{$i18n("复制")}</button>
                  </div>
                  <div class="mf-tip">{$i18n("HTTP/HTTPS 隧道无需远程端口：把该服务器地址解析到你的域名即可访问")}</div>
                </div>
              </div>
            {/if}
          {:else}
            <div class="form-row">
              <div class="form-group" style="flex:1">
                <label class="form-label">{$i18n("远程端口")}</label>
                <div class="mf-input-btn">
                  <input type="number" min="1" max="65535" bind:value={form.remotePort} placeholder={$i18n("公网访问端口")} use:field={{ check: validatePort, errAt: () => remotePortErr }} />
                  <button class="btn btn-sm" type="button" title={$i18n("在节点允许范围内自动挑选空闲端口")} on:click={autoRemotePort}>{$i18n("自动获取")}</button>
                </div>
                <div class="field-err" bind:this={remotePortErr} style="display:none"></div>
                <div class="mf-tip">{currentNode?.allowPort ? i18nTr("节点允许范围 {0}", [currentNode.allowPort]) : i18nTr("未选择节点，请先选择以查看允许范围")}</div>
              </div>
            </div>
          {/if}
          {#if form.proxyType === 'http' || form.proxyType === 'https'}
            <div class="form-group">
              <div class="form-row">
                <div class="form-group" style="flex:1;margin-bottom:0">
                  <label class="form-label" for="mf-bind-domain">{$i18n("域名选择")}</label>
                  <CustomSelect id="mf-bind-domain" bind:value={bindDomain} options={bindDomainOpts}
                    placeholder={bindDomainOpts.length ? i18nTr("留空则使用节点域名") : i18nTr("请先在「域名解析」中添加域名")} />
                </div>
                <div class="form-group" style="flex:1;max-width:210px;margin-bottom:0">
                  <label class="form-label" for="mf-host-mode">{$i18n("主机记录")}</label>
                  <CustomSelect id="mf-host-mode" bind:value={hostMode} options={hostModeOpts} />
                </div>
              </div>
              {#if bindDomain && hostMode === 'sub'}
                <div class="form-row" style="margin-top:8px">
                  <div class="form-group" style="flex:1;margin-bottom:0">
                    <label class="form-label" for="mf-sub-prefix">{$i18n("子域名")}</label>
                    <input id="mf-sub-prefix" type="text" bind:value={subPrefix} placeholder={$i18n("如 web（仅字母/数字/连字符）")} />
                  </div>
                  <div class="form-group" style="flex:1;margin-bottom:0">
                    <label class="form-label" for="mf-picked-domain">{$i18n("域名")}</label>
                    <input id="mf-picked-domain" type="text" value={bindDomain} readonly tabindex="-1" placeholder={$i18n("未选择域名")} />
                  </div>
                </div>
              {/if}
              {#if orphanDomain}
                <div class="mf-tip">{$i18n("原域名")} {orphanDomain} {$i18n("不在「域名解析」的域名列表中：不重新选择则保持原样，选择后将替换它。")}</div>
              {/if}
              <div class="mf-tip" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                {#if editingProxy}
                  <button class="btn btn-sm" type="button" disabled={writing || !bindDomain || !nodeAddr || !fullDomain} on:click={writeDNSRecord}>
                    {writing ? i18nTr("写入中…") : i18nTr("写入解析")}
                  </button>
                {/if}
                <span>{bindHint}</span>
              </div>
            </div>
            {#if !editingProxy}
              <details class="mf-adv">
                <summary>{$i18n("HTTP 进阶设置（Host 重写 / 插件 / 认证 / 路径路由 / 自定义头）")}</summary>
                <div class="mf-adv-body">
                  <div class="form-row">
                    <div class="form-group" style="flex:1.6">
                      <label class="form-label">{$i18n("Host 头重写")}</label>
                      <input type="text" bind:value={form.hostHeaderRewrite} placeholder={$i18n("留空不重写")} />
                    </div>
                    <div class="form-group" style="flex:1;max-width:210px">
                      <label class="form-label">{$i18n("HTTP 插件")}</label>
                      <CustomSelect bind:value={form.httpPlugin} options={pluginOpts} />
                    </div>
                  </div>
                  {#if form.httpPlugin === 'https2http' || form.httpPlugin === 'https2https'}
                    <div class="form-row">
                      <div class="form-group" style="flex:1">
                        <label class="form-label">{$i18n("TLS 证书路径")}</label>
                        <input type="text" bind:value={form.crtPath} placeholder="/path/fullchain.pem" />
                      </div>
                      <div class="form-group" style="flex:1">
                        <label class="form-label">{$i18n("TLS 私钥路径")}</label>
                        <input type="text" bind:value={form.keyPath} placeholder="/path/privkey.pem" />
                      </div>
                    </div>
                  {/if}
                  <div class="form-row">
                    <div class="form-group" style="flex:1">
                      <label class="form-label">{$i18n("路径路由（locations）")}</label>
                      <input type="text" bind:value={form.locations} placeholder={$i18n("多个路径以逗号分隔，如 /api,/web")} />
                    </div>
                    <div class="form-group" style="flex:1">
                      <label class="form-label">{$i18n("访问密钥（accessKey）")}</label>
                      <input type="text" bind:value={form.accessKey} placeholder={$i18n("与基础认证互斥，二选一")} />
                    </div>
                  </div>
                  <div class="form-row">
                    <div class="form-group" style="flex:1">
                      <label class="form-label">{$i18n("BasicAuth 用户名")}</label>
                      <input type="text" bind:value={form.httpUser} placeholder={$i18n("留空禁用基础认证（与访问密钥互斥）")} />
                    </div>
                    <div class="form-group" style="flex:1">
                      <label class="form-label">{$i18n("BasicAuth 密码")}</label>
                      <input type="password" bind:value={form.httpPassword} placeholder={$i18n("配合用户名使用")} />
                    </div>
                  </div>
                  <div class="form-row">
                    <div class="form-group" style="flex:1">
                      <label class="form-label">{$i18n("自定义请求头")}</label>
                      <textarea rows="3" bind:value={form.requestHeadersText} placeholder={$i18n("每行一条：X-From: TunHook")}></textarea>
                    </div>
                    <div class="form-group" style="flex:1">
                      <label class="form-label">{$i18n("自定义响应头")}</label>
                      <textarea rows="3" bind:value={form.responseHeadersText} placeholder={$i18n("每行一条：X-Cache: none")}></textarea>
                    </div>
                  </div>
                </div>
              </details>
            {/if}
          {/if}
          {#if !editingProxy}
            <details class="mf-adv">
              <summary>{$i18n("传输与加密")}</summary>
              <div class="mf-adv-body">
                <div class="form-row">
                  <div class="form-group" style="flex:1">
                    <label class="form-label">{$i18n("传输协议")}</label>
                    <CustomSelect bind:value={form.transportProtocol} options={transportOpts} />
                  </div>
                  <div class="form-group" style="flex:1">
                    <label class="form-label">PROXY protocol</label>
                    <CustomSelect bind:value={form.proxyProtocolVersion} options={ppOpts} />
                  </div>
                </div>
                <div class="mf-check-row">
                  <div class="mf-switch"><Toggle bind:checked={form.useEncryption} /><span on:click={() => (form.useEncryption = !form.useEncryption)}>{$i18n("传输加密")}</span></div>
                  <div class="mf-switch"><Toggle bind:checked={form.useCompression} /><span on:click={() => (form.useCompression = !form.useCompression)}>{$i18n("数据压缩")}</span></div>
                </div>
              </div>
            </details>
          {:else}
            <details class="mf-adv">
              <summary>{$i18n("进阶设置（Host 重写 / PROXY protocol / 加密压缩）")}</summary>
              <div class="mf-adv-body">
                <div class="form-group">
                  <label class="form-label">{$i18n("Host 头重写")}</label>
                  <input type="text" bind:value={form.hostHeaderRewrite} placeholder={$i18n("留空不重写")} />
                </div>
                <div class="form-row">
                  <div class="form-group" style="flex:1">
                    <label class="form-label">PROXY protocol</label>
                    <CustomSelect bind:value={form.proxyProtocolVersion} options={ppOpts} />
                  </div>
                  <!-- 加密/压缩开关移至 PROXY protocol 右侧，与下拉同一行 -->
                  <div class="mf-switches">
                    <div class="mf-switch"><Toggle bind:checked={form.useEncryption} /><span on:click={() => (form.useEncryption = !form.useEncryption)}>{$i18n("传输加密")}</span></div>
                    <div class="mf-switch"><Toggle bind:checked={form.useCompression} /><span on:click={() => (form.useCompression = !form.useCompression)}>{$i18n("数据压缩")}</span></div>
                  </div>
                </div>
                <div class="mf-tip">{$i18n("HTTP 插件 / 自定义头 / 传输协议不支持在线修改")}</div>
              </div>
            </details>
          {/if}
          {#if !editingProxy}
            <label class="mf-check">
              <input type="checkbox" bind:checked={form.autoStart} />
              <span>{$i18n("创建后立即启动该隧道")}</span>
            </label>
          {/if}
          </div>
        {/if}
      </div>
      <div class="modal-ftr">
        {#if !pickStep}
          <button class="btn" on:click={() => (pickStep = true)}>{$i18n("上一步")}</button>
        {/if}
        <button class="btn" on:click={() => (showCreate = false)}>{$i18n("取消")}</button>
        {#if !pickStep}
          <button class="btn btn-primary" disabled={creating} on:click={createProxy}>{creating ? i18nTr("提交中…") : (editingProxy ? i18nTr("保存修改") : i18nTr("创建"))}</button>
        {/if}
      </div>
    </div>
  </div>
{/if}

{#if showCaptcha}
  <div class="modal-overlay" on:click|self={() => (showCaptcha = false)} role="presentation">
    <div class="modal" style="max-width:520px">
      <div class="modal-hdr">
        <h3>{$i18n("人机验证")}</h3>
        <button class="modal-close" on:click={() => (showCaptcha = false)} aria-label={$i18n("关闭")}>×</button>
      </div>
      <div class="modal-body">
        <div class="mf-tip">
          {$i18n("MEFrp 要求签到前完成人机验证：在下方官方验证页面中完成验证，\n          然后把页面返回的验证码文本完整粘贴到输入框提交。")}
        </div>
        <div class="mf-captcha-frame">
          <iframe src="https://www.mefrp.com/3rdparty/captcha?client=TunHook" title={$i18n("MEFrp 人机验证")} allow="clipboard-write"></iframe>
        </div>
        <a class="mf-captcha-ext" href="https://www.mefrp.com/3rdparty/captcha?client=TunHook" target="_blank" rel="noopener noreferrer">{$i18n("页面无法显示？在新标签页打开 ↗")}</a>
        <div class="form-group" style="margin-top:12px">
          <label class="form-label">{$i18n("验证码文本")}</label>
          <input type="text" bind:value={captchaInput} placeholder={$i18n("粘贴验证完成后返回的文本")} autofocus on:keydown={(e) => e.key === 'Enter' && captchaInput.trim() && !signing && sign(captchaInput.trim())} />
        </div>
      </div>
      <div class="modal-ftr">
        <button class="btn" on:click={() => (showCaptcha = false)}>{$i18n("取消")}</button>
        <button class="btn btn-primary" disabled={signing || !captchaInput.trim()} on:click={() => sign(captchaInput.trim())}>
          {signing ? i18nTr("提交中…") : i18nTr("提交并签到")}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if showDrawResult}
  <div class="modal-overlay" on:click|self={() => (showDrawResult = false)} role="presentation">
    <div class="modal" style="max-width:440px">
      <div class="modal-hdr">
        <h3>{$i18n("权益抽取结果")}</h3>
        <button class="modal-close" on:click={() => (showDrawResult = false)} aria-label={$i18n("关闭")}>×</button>
      </div>
      <div class="modal-body">
        {#if todayDrawMB > 0}
          <div style="font-size:13px;font-weight:600;color:var(--green);margin-bottom:10px">{$i18n("今日累计抽到 +")}{fmtMB(todayDrawMB)} {$i18n("流量")}</div>
        {/if}
        <div class="mf-draw-list">
          {#each drawLines as line}
            <div class="mf-draw-item">{line}</div>
          {/each}
        </div>
      </div>
      <div class="modal-ftr">
        <button class="btn btn-primary" on:click={() => (showDrawResult = false)}>{$i18n("知道了")}</button>
      </div>
    </div>
  </div>
{/if}

{#if showScan}
  <PortScanModal
    targetIP={form.localIp || '127.0.0.1'}
    onClose={() => (showScan = false)}
    onPick={(it) => {
      form.localPort = it.port;
      if (!form.proxyName.trim()) form.proxyName = suggestProxyName(it);
      if (it.local_addr && it.local_addr !== '0.0.0.0' && it.local_addr !== '::') form.localIp = it.local_addr;
      showScan = false;
    }}
  />
{/if}

{#if showStopConfirm}
  <ConfirmModal
    title={$i18n("停止全部隧道")}
    message={$i18n("确定停止本地 frpc 吗？所有 MEFrp 隧道将立即中断，外部无法继续访问，可随时重新启动。")}
    confirmText={$i18n("停止")}
    onConfirm={confirmStop}
    onClose={() => { if (!stopping) showStopConfirm = false; }}
    busy={stopping}
  />
{/if}

{#if delTarget}
  <ConfirmModal
    title={$i18n("删除隧道")}
    message={`确定删除隧道「${delTarget.proxyName}」吗？此操作不可恢复。${delDnsHint}`}
    onConfirm={confirmDeleteProxy}
    onClose={() => { if (!delBusy) delTarget = null; }}
    busy={delBusy}
  />
{/if}

<style>
  .mf-card {
    border: 1px solid var(--bd);
    border-radius: calc(var(--radius) + 4px);
    background: var(--bg3);
    padding: 16px 18px;
    margin-bottom: 14px;
    box-shadow: var(--shadow-card);
  }
  .mf-card h3 {
    font-size: 13.5px;
    font-weight: 600;
    color: var(--text);
    margin-bottom: 10px;
  }
  /* 未绑定状态的功能引导：填充留白并说明绑定后的能力 */
  .mf-guide-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
  .mf-guide-item { background: var(--bg4); border: 1px solid var(--bd); border-radius: var(--radius); padding: 10px 12px; min-width: 0; }
  .mf-guide-item b { display: block; font-size: 12px; font-weight: 600; color: var(--text); margin-bottom: 4px; }
  .mf-guide-item span { display: block; font-size: 11px; color: var(--text3); line-height: 1.6; }

  /* 账户卡片：头像 + 账号信息 + 4 项配额 + 签到/抽取操作 */
  .mf-acct { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
  .mf-avatar {
    width: 40px; height: 40px; flex-shrink: 0; border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    background: rgba(var(--accent-rgb), .12); color: var(--accent);
    font-size: 17px; font-weight: 700;
  }
  .mf-acct-id { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .mf-acct-id b { font-size: 13.5px; font-weight: 600; color: var(--text); display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .mf-acct-id > span { font-size: 11px; color: var(--text3); font-family: var(--mono); word-break: break-all; }
  .mf-acct-id code { font-family: var(--mono); color: var(--text2); }
  .mf-acct-stats { display: flex; align-items: center; gap: 22px; margin-left: auto; flex-wrap: wrap; }
  .mf-acct-stat { min-width: 66px; }
  .mf-acct-stat span { display: block; font-size: 10px; color: var(--text3); margin-bottom: 3px; }
  .mf-acct-stat b { font-family: var(--mono); font-size: 13px; font-weight: 600; color: var(--text); font-variant-numeric: tabular-nums; }
  .mf-acct-actions {
    flex-basis: 100%; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
    padding-top: 10px; border-top: 1px dashed rgba(128, 128, 128, .18); font-size: 12px;
  }

  /* 本地 frpc 运行状态条 */
  .mf-statusbar { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; padding-top: 12px; padding-bottom: 12px; }
  .mf-status { display: inline-flex; align-items: center; gap: 8px; flex-wrap: wrap; min-width: 0; }
  .mf-status b { font-size: 13.5px; font-weight: 600; color: var(--text); }
  .mf-status-meta { font-size: 11px; color: var(--text3); font-family: var(--mono); }
  .mf-dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
  .mf-name { display: inline-flex; align-items: center; gap: 7px; min-width: 0; }
  .mf-muted { color: var(--text3); }
  .badge-blue { color: var(--blue); background: rgba(var(--blue-rgb), .08); border: 1px solid rgba(var(--blue-rgb), .25); }
  .mf-table-foot {
    display: flex; align-items: center; justify-content: space-between; gap: 10px;
    padding: 10px 12px; border-top: 1px solid var(--bd);
    font-size: 11px; color: var(--text3); flex-wrap: wrap;
  }
  .mf-foot-meta { font-family: var(--mono); }
  .mf-foot-note { margin-right: auto; font-size: 10.5px; color: var(--text3); font-family: var(--mono); }
  .mf-tip { font-size: 12px; color: var(--text3); line-height: 1.6; }
  /* 人机验证：官方验证页以 iframe 内嵌在弹窗中（对方无 X-Frame-Options/CSP 限制）。
     验证页自身为白底卡片，容器固定白底并裁切圆角；iframe 默认按 477:355 比例随宽缩放，
     移动端（≤600px）改用 477:360 略高比例，保证窄屏视口下验证按钮完整可见 */
  .mf-captcha-frame { margin-top: 10px; border: 1px solid var(--bd); border-radius: var(--radius); overflow: hidden; background: #fff; }
  .mf-captcha-frame iframe { display: block; width: 100%; height: auto; aspect-ratio: 477 / 355; border: 0; }
  @media (max-width: 600px) {
    .mf-captcha-frame iframe { aspect-ratio: 477 / 360; }
  }
  .mf-captcha-ext { display: inline-block; margin-top: 8px; font-size: 11px; color: var(--text3); }
  .mf-captcha-ext:hover { color: var(--accent); }
  .mf-check { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text2); cursor: pointer; }
  .mf-check-row { display: flex; gap: 18px; margin: 4px 0; }
  /* 滑动开关 + 文案（替代原 checkbox；Toggle 根元素是 label，外层不再嵌套 label） */
  .mf-switch { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text2); white-space: nowrap; }
  .mf-switch span { cursor: pointer; }
  /* PROXY protocol 右侧开关组：margin-top 对齐 form-label 之下的下拉控件，窄屏自动换行 */
  .mf-switches { flex: 1; display: flex; align-items: center; gap: 18px; flex-wrap: wrap; margin-top: 26px; margin-bottom: 14px; min-width: 0; }
  .mf-adv { border: 1px solid var(--bd); border-radius: var(--radius); margin-bottom: 12px; background: var(--bg4); }
  .mf-adv summary { font-size: 12px; font-weight: 600; color: var(--text2); padding: 8px 12px; cursor: pointer; user-select: none; }
  .mf-adv summary:hover { color: var(--accent); }
  .mf-adv-body { padding: 4px 12px 12px; border-top: 1px solid var(--bd); padding-top: 10px; }
  /* 节点选择列表（参考 MEFrp 官网样式） */
  .mf-filters { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; margin-bottom: 12px; }
  .mf-fcheck { display: flex; align-items: center; gap: 5px; font-size: 12px; color: var(--text2); cursor: pointer; }
  .mf-fcount { margin-left: auto; font-size: 11px; color: var(--text3); font-family: var(--mono); }
  .mf-nodes {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 10px;
    max-height: 58vh;
    overflow-y: auto;
    padding: 2px;
  }
  .mf-node {
    border: 1px solid var(--bd);
    border-radius: calc(var(--radius) + 2px);
    background: var(--bg4);
    padding: 12px;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    gap: 7px;
    transition: border-color 0.15s;
  }
  .mf-node:hover { border-color: rgba(var(--accent-rgb), 0.5); }
  .mf-node-sel { border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent-glow); }
  .mf-node-off { opacity: 0.55; }
  .mf-node-hd { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
  .mf-node-name { font-size: 13px; font-weight: 600; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .mf-node-tags-hd { display: flex; gap: 4px; flex-shrink: 0; }
  .mf-tag { font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 4px; }
  .mf-tag-vip { background: rgba(var(--yellow-rgb), 0.08); color: var(--yellow); border: 1px solid rgba(var(--yellow-rgb), 0.35); }
  .mf-tag-noperm { background: rgba(var(--red-rgb), 0.08); color: var(--red); border: 1px solid rgba(var(--red-rgb), 0.3); }
  .mf-tag-load { background: rgba(var(--slate-rgb), 0.08); color: var(--text3); border: 1px solid rgba(var(--slate-rgb), 0.3); }
  .mf-node-tags { display: flex; gap: 4px; flex-wrap: wrap; }
  .mf-badge {
    font-size: 10px;
    font-weight: 600;
    padding: 1px 7px;
    border-radius: 4px;
    color: var(--green);
    background: rgba(var(--green-rgb), 0.08);
    border: 1px solid rgba(var(--green-rgb), 0.25);
  }
  .mf-badge-bw { color: var(--yellow); background: rgba(var(--yellow-rgb), 0.08); border-color: rgba(var(--yellow-rgb), 0.25); }
  .mf-badge-port { color: var(--accent); background: rgba(var(--accent-rgb), 0.08); border-color: rgba(var(--accent-rgb), 0.3); font-family: var(--mono); }
  .mf-node-desc {
    font-size: 11px;
    color: var(--text3);
    line-height: 1.55;
    min-height: 34px;
    display: -webkit-box;
    -webkit-line-clamp: 3;
    -webkit-box-orient: vertical;
    overflow: hidden;
    flex: 1;
  }
  .mf-node-ft { display: flex; align-items: center; gap: 8px; }
  .mf-loadbar { flex: 1; height: 4px; border-radius: 2px; background: rgba(var(--slate-rgb), 0.25); overflow: hidden; }
  .mf-loadbar-in { height: 100%; border-radius: 2px; transition: width 0.3s; }
  .mf-loadtxt { font-size: 10px; color: var(--text3); font-family: var(--mono); white-space: nowrap; }
  .mf-picked { display: flex; flex-direction: column; gap: 6px; font-size: 12px; color: var(--text2); line-height: 1.8; padding: 10px 12px; border: 1px solid var(--bd); border-radius: var(--radius); background: var(--bg4); }
  .mf-picked-hd { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .mf-picked-hd b { color: var(--text); font-weight: 600; }
  .mf-picked .mf-tip { line-height: 1.5; }
  .mf-input-btn { display: flex; gap: 6px; align-items: stretch; }
  .mf-input-btn input { flex: 1; }
  .mf-input-btn .btn { white-space: nowrap; }
  .mf-token-row { display: flex; gap: 8px; margin-top: 10px; }
  .mf-token-row input { flex: 1; }
  @media (max-width: 640px) {
    /* 输入框+按钮组（本地端口/服务器地址/远程端口）：放得下时按钮留在输入框同一行，
       输入框占剩余宽度；basis 120px 保证空间不足时才折行，按钮不被压缩 */
    .mf-input-btn { flex-wrap: wrap; }
    .mf-input-btn input { flex: 1 1 120px; min-width: 0; }
    .mf-input-btn .btn { flex: 0 0 auto; }
    .mf-guide-grid { grid-template-columns: 1fr; }
  }
  .mf-clickable { cursor: pointer; user-select: none; }
  .mf-clickable:hover { filter: brightness(1.1); }
  .mf-draw-list { display: flex; flex-direction: column; gap: 4px; max-height: 40vh; overflow-y: auto; }
  .mf-draw-item { font-size: 12px; color: var(--text2); font-family: var(--mono); line-height: 1.6; }
  .mf-k { color: var(--text3); flex-shrink: 0; }
  .mf-mono { font-family: var(--mono); }
  .mf-actions { display: flex; gap: 8px; }
  .mf-ops { display: flex; align-items: center; justify-content: center; gap: 2px; }
  .mf-warn {
    font-size: 12px;
    color: var(--yellow);
    background: rgba(var(--yellow-rgb), 0.08);
    border: 1px solid rgba(var(--yellow-rgb), 0.3);
    border-radius: var(--radius);
    padding: 8px 12px;
    margin-bottom: 14px;
  }
  .mf-log {
    font-family: var(--mono);
    font-size: 11px;
    line-height: 1.6;
    color: var(--text2);
    background: var(--bg4);
    border-radius: 6px;
    padding: 10px 12px;
    max-height: 320px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-all;
    margin: 0;
  }

  @media (max-width: 600px) {
    .mf-acct { gap: 10px; }
    .mf-acct-stats { margin-left: 0; gap: 14px 18px; width: 100%; }
    .mf-acct-actions { margin-top: 2px; }
    .list-card {
      background: var(--bg3);
      border-radius: calc(var(--radius) + 4px);
      box-shadow: var(--shadow-card);
      padding: 14px;
    }
    .list-card-title { font-size: 13.5px; }
  }
</style>
