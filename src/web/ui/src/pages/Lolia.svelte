<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  import { onMount } from 'svelte';
  import { api, apiBase } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import { highlightLog, pollVisible, reverseLines, validateHost, validatePort, validateDomain, optional, suggestDescription, fmtBytes } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';
  import { fetchDomainOptions, splitFullDomain, writeBindRecord, removeBindRecord, composeFullDomain, HOST_MODE_OPTIONS, resolveDisplayTarget } from '../lib/domainbind.js';
  import CustomSelect from '../components/CustomSelect.svelte';
  import PortScanModal from '../components/PortScanModal.svelte';
  import ConfirmModal from '../components/ConfirmModal.svelte';
  import Modal from '../components/Modal.svelte';
  import LoliaOAuthAppForm from '../components/LoliaOAuthAppForm.svelte';

  let loading = true;
  let cfg = null; // /api/lolia/config
  let showAppForm = false;
  let authorizing = false;
  let disconnecting = false;
  let showDisconnectConfirm = false; // 解除授权二次确认弹窗
  let showStopConfirm = false; // 停止全部隧道二次确认弹窗
  // 隧道/域名删除目标（非 null 时弹出 ConfirmModal）
  let delTunnel = null;
  let delTunnelBusy = false;
  let delDomain = null;
  let delDomainBusy = false;

  let user = null;
  let tunnels = [];
  let nodes = [];
  let nodesLoaded = false;
  let nodesLoading = false;
  let running = false;
  let pid = 0;
  let logText = '';
  let refreshing = false;
  let starting = false;
  let stopping = false;
  let busyName = ''; // 单条隧道电源按钮操作中的隧道名（防重复点击）

  // 本地 frpc 实际加载的隧道名称（来自 status 接口：运行数量展示 + 电源按钮启停态判定）
  let loadedNames = [];

  // 「绑定域名」：从「域名解析」模块里已有的域名中选根域名，再选主机记录方式，拼出完整域名。
  // Lolia 的 HTTP 隧道只允许绑定在其「域名管理」里通过归属验证的域名，因此候选取
  // 「域名解析里的域名 ∩ Lolia 已验证域名」——只列一侧会出现「选了却建不成隧道」。
  let bindDomainOpts = [];
  let bindDomain = '';     // 选中的根域名
  let hostMode = '@';      // 主机记录方式：'@' 主域名 | 'sub' 子域名
  let subPrefix = '';      // 子域名前缀
  let orphanDomain = '';   // 编辑时原域名不在候选里的值（保留回传，避免静默清空）
  let binding = false;     // 写入解析中
  let editNodeAddr = '';   // 编辑态该隧道的节点连接地址（取自隧道详情，Lolia 只在详情/列表给出）
  let bindTarget = null;   // 节点地址解析后的记录（类型+值），供界面显示「解析目标」
  const hostModeOpts = HOST_MODE_OPTIONS.map((o) => ({ value: o.value, label: i18nTr(o.label) }));

  $: fullDomain = composeFullDomain(bindDomain, hostMode, subPrefix);
  $: bindHint = !bindDomain
    ? (editing ? i18nTr("选择域名后，可把该隧道的节点地址写进解析") : i18nTr("选择域名后，隧道创建成功即自动写入解析"))
    : (editing
      ? (!editNodeAddr
        ? i18nTr("该隧道暂未提供节点地址，无法写入解析")
        : (bindTarget
          ? i18nTr("解析目标：{0} → {1} {2}", [fullDomain || '（请填子域名前缀）', bindTarget.type, bindTarget.value])
          : i18nTr("解析目标：{0} → 正在解析节点地址…", [fullDomain || '（请填子域名前缀）'])))
      : i18nTr("创建成功后自动写入解析：{0}", [fullDomain || '（请填子域名前缀）']));
  // 删除确认文案：该隧道域名归本模块管理时，提示会一并删除解析记录
  $: delDnsHint = (() => {
    const full = String(delTunnel?.custom_domain || '').trim().toLowerCase();
    if (!full) return '';
    return bindDomainOpts.some((o) => {
      const d = o.value.toLowerCase();
      return full === d || full.endsWith('.' + d);
    }) ? i18nTr("该隧道绑定了域名 {0}，将一并删除指向该节点的解析记录。", [delTunnel.custom_domain]) : '';
  })();

  // 三个弹窗的容器 ref 与横向行内输入的错误节点
  let editFormEl;        // 编辑隧道弹窗容器，保存时统一校验
  let createFormEl;      // 创建隧道弹窗容器，提交时统一校验
  let domainModalEl;     // 域名管理弹窗容器，添加域名时统一校验
  let createLocalPortErr; // 创建表单本地端口错误节点（输入在 .lo-input-btn 横向行内）
  let createRemotePortErr; // 创建表单远程端口错误节点（同上）
  let domainErr;         // 域名管理添加域名错误节点（输入在 .lo-domain-add 横向行内）

  $: configured = !!(cfg && cfg.appConfigured);
  $: authorized = !!(cfg && cfg.authorized);

  // ---- 展示辅助（lolia 独有字段）----

  function pct(used, limit) {
    if (!limit || limit <= 0) return 0;
    return Math.min(100, Math.round((used / limit) * 100));
  }

  function barColor(p) {
    return p >= 90 ? 'var(--red)' : p >= 70 ? 'var(--yellow)' : 'var(--green)';
  }

  function fmtDate(s) { return s ? String(s).slice(0, 10) : '—'; }

  // LoliaFrp 接口的 bandwidth_limit 单位为 MB/s（官方限速 80Mbps 即返回 10），展示换算为 Mbps。
  // 依据官方 FAQ：限速以 Mbps 标注，内部按 MB/s 换算，10 MB/s ≈ 80 Mbps。
  function fmtMbpsLimit(mbPerSec) {
    if (!mbPerSec || mbPerSec <= 0) return '—';
    return mbPerSec * 8 + ' Mbps';
  }

  function kycState(u) {
    if (u.has_kyc) return { text: i18nTr("已实名"), cls: 'badge-on' };
    const map = { certifying: i18nTr("认证中"), rejected: i18nTr("未通过"), pending: i18nTr("待审核") };
    return { text: map[u.kyc_status] || (u.kyc_status ? u.kyc_status : i18nTr("未实名")), cls: 'badge-warn' };
  }

  function tunnelState(t) {
    return t.status === 'active' ? { text: i18nTr("在线"), cls: 'badge-on' } : { text: i18nTr("离线"), cls: 'badge-off' };
  }

  function tunnelAddr(t) {
    if (t.type === 'http') {
      const host = t.custom_domain || t.node_address || '';
      return (t.auto_tls ? 'https://' : 'http://') + host;
    }
    return (t.node_address || '—') + ':' + t.remote_port;
  }

  function tunnelTitle(t) { return t.remark || t.name; }
  function nodeNameOf(t) { return t.node_name || (i18nTr("节点 ") + t.node_id); }

  function copyRedirect() {
    const v = cfg?.redirectUri || '';
    if (!v) { toast(i18nTr("回调地址不可用"), 'error'); return; }
    if (navigator.clipboard) {
      navigator.clipboard.writeText(v).then(() => toast(i18nTr("回调地址已复制：") + v, 'success'), () => toast(v, 'info'));
    } else {
      toast(v, 'info');
    }
  }

  // ---- 数据加载 ----

  async function loadConfig() {
    cfg = await api('/api/lolia/config');
  }

  // 候选域名 =「域名解析」里的域名 ∩ Lolia 已通过归属验证的域名（只列一侧会出现「选了却建不成隧道」）
  async function loadBindDomains() {
    try {
      const [dnsOpts, ld] = await Promise.all([
        fetchDomainOptions(),
        api('/api/lolia/domains').catch(() => null)
      ]);
      const verified = new Set(((ld && ld.domains) || []).map((d) => String(d.domain || '').toLowerCase()));
      bindDomainOpts = dnsOpts.filter((o) => verified.has(o.value.toLowerCase()));
    } catch (e) { bindDomainOpts = []; }
  }

  // 编辑回填：把隧道已有域名拆成「根域名 + 主机记录方式 + 前缀」
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

  // 写入解析：按钮与「创建成功后自动写入」共用一条链路
  async function writeBind(addr) {
    const t = await writeBindRecord(bindParams(addr));
    toast(i18nTr("解析已写入：{0} {1} {2}", [fullDomain, t.type, t.value]), 'success');
  }

  // 取新建隧道的节点连接地址：创建接口的响应里没有 node_address
  // （Lolia 只在「隧道详情 / 隧道列表」里给出该字段），所以缺了就用详情接口补齐。
  async function resolveTunnelAddr(name, created) {
    const fromCreate = String((created && created.tunnel && created.tunnel.node_address) || '').trim();
    if (fromCreate || !name) return fromCreate;
    const det = await api('/api/lolia/tunnel/' + encodeURIComponent(name)).catch(() => null);
    return String((det && det.node_address) || '').trim();
  }

  // 「写入解析」按钮（编辑态）：用该隧道的节点地址写记录
  async function writeEditBind() {
    if (!bindDomain) { toast(i18nTr("请先选择域名"), 'error'); return; }
    if (!fullDomain) { toast(i18nTr("请填写子域名前缀"), 'error'); return; }
    if (!editNodeAddr) { toast(i18nTr("该隧道暂未提供节点地址，无法写入解析"), 'error'); return; }
    binding = true;
    try {
      await writeBind(editNodeAddr);
    } catch (e) {
      toast(i18nTr("写入解析失败：") + e.message, 'error');
    } finally {
      binding = false;
    }
  }

  // 删除隧道时同步清理解析记录（「值必须匹配」的安全约束见 lib/domainbind.js）
  function cleanBindRecord(t) {
    return removeBindRecord({
      full: t?.custom_domain || '',
      addr: t?.node_address || '',
      options: bindDomainOpts
    });
  }

  async function loadTunnels(force = false) {
    refreshing = true;
    try {
      const d = await api('/api/lolia/tunnels' + (force ? '?refresh=1' : ''));
      tunnels = d.tunnels || [];
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      refreshing = false;
    }
  }

  async function loadStatus() {
    try {
      const d = await api('/api/lolia/status');
      running = !!d.running;
      pid = d.pid || 0;
      loadedNames = d.names || [];
    } catch (e) { /* ignore */ }
  }

  async function loadUser() {
    try { user = await api('/api/lolia/user'); } catch (e) { /* ignore */ }
  }

  async function loadNodes(force = false) {
    if (nodesLoading) return;
    nodesLoading = true;
    try {
      const d = await api('/api/lolia/nodes' + (force ? '?refresh=1' : ''));
      nodes = d.nodes || [];
      nodesLoaded = true;
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      nodesLoading = false;
    }
  }

  async function loadLog() {
    try {
      const d = await api('/api/lolia/log?lines=200');
      logText = reverseLines(d.log || i18nTr("（暂无日志）"));
    } catch (e) {
      logText = i18nTr("读取日志失败: ") + e.message;
    }
  }

  async function init() {
    loading = true;
    try {
      await loadConfig();
      if (authorized) {
        await Promise.all([loadTunnels(true), loadStatus(), loadUser()]);
        loadLog();
      }
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      loading = false;
    }
  }

  // ---- OAuth 应用配置 / 授权 ----

  // 已配置状态下点击「OAuth 配置/修改配置」：以弹窗打开表单（首次配置仍走内联向导）
  function openAppForm() {
    showAppForm = true;
  }

  // 同窗口跳转会卸载主页面（进行中的请求被中断报 Failed to fetch），且授权后 302 回
  // 127.0.0.1 这类仅本机/IDE 转发可达的地址在外部浏览器无法闭环。改为弹窗授权：
  // 主页面保留，回调结果页（由公网 Webhook 域名承载）postMessage 通知本页；
  // 跨浏览器（系统默认浏览器打开弹窗）收不到消息时，靠窗口聚焦事件兜底轮询授权状态。
  let authWin = null;

  async function startAuth() {
    authorizing = true;
    try {
      // 不传 returnUrl：回调统一展示独立结果页（公网 Webhook 域名即可承载，无需回跳主站）
      const d = await api('/api/lolia/oauth/start', { method: 'POST', body: {} });
      // 注意：不能加 noopener，否则回调页无法 postMessage 回主页面
      authWin = window.open(d.url, 'lolia_oauth', 'width=720,height=720');
      if (!authWin) {
        // 弹窗被拦截：回退为当前页跳转，并提示用户在系统浏览器场景手动返回
        window.location.href = d.url;
        return;
      }
      // 弹窗模式下保留按钮状态，由 focus / message / 轮询任一通道收尾
      pollAuthResult();
    } catch (e) {
      authorizing = false;
      toast(e.message, 'error');
    }
  }

  let authPollTimer = null;
  let authCleanup = null;
  function stopAuthPoll() {
    if (authPollTimer) { clearInterval(authPollTimer); authPollTimer = null; }
    if (authCleanup) { authCleanup(); authCleanup = null; }
  }

  // 弹窗打开期间轮询授权状态（1.5s 一次，最多 ~2 分钟）；窗口聚焦时立即查一次
  async function checkAuthResult() {
    try {
      await loadConfig();
      if (authorized) {
        authorizing = false;
        stopAuthPoll();
        if (authWin && !authWin.closed) { try { authWin.close(); } catch (e) { /* ignore */ } }
        authWin = null;
        toast(i18nTr("LoliaFrp 授权成功"), 'success');
        await Promise.all([loadTunnels(true), loadStatus(), loadUser()]);
        loadLog();
        return true;
      }
    } catch (e) { /* ignore */ }
    return false;
  }

  function pollAuthResult() {
    stopAuthPoll();
    let ticks = 0;
    const maxTicks = 80; // 1.5s × 80 ≈ 2 分钟
    const onFocus = () => checkAuthResult();
    window.addEventListener('focus', onFocus);
    const onMessage = (e) => {
      if (e && e.data && e.data.type === 'lolia-oauth') {
        if (e.data.ok) checkAuthResult();
        else { authorizing = false; toast(i18nTr("授权未完成"), 'error'); }
      }
    };
    window.addEventListener('message', onMessage);
    authCleanup = () => {
      window.removeEventListener('focus', onFocus);
      window.removeEventListener('message', onMessage);
    };
    authPollTimer = setInterval(async () => {
      ticks++;
      const done = await checkAuthResult();
      const winClosed = authWin && authWin.closed;
      if (done || ticks >= maxTicks || winClosed) {
        authorizing = false;
        stopAuthPoll();
        if (winClosed && !done) {
          // 弹窗关闭但没授权成功：再查一次配置（可能结果消息漏收）
          await checkAuthResult();
          if (!authorized) toast(i18nTr("授权窗口已关闭"), 'info');
        }
        authWin = null;
      }
    }, 1500);
  }

  function disconnect() {
    showDisconnectConfirm = true;
  }

  async function confirmDisconnect() {
    disconnecting = true;
    try {
      await api('/api/lolia/oauth/disconnect', { method: 'POST' });
      await loadConfig();
      user = null;
      tunnels = [];
      showDisconnectConfirm = false;
      toast(i18nTr("已解除授权"), 'success');
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      disconnecting = false;
    }
  }

  // ---- 隧道启停 ----

  // 单条隧道启动（同节点隧道依次点击会被后端并入同一运行集合）
  async function start(name) {
    if (!name) { toast(i18nTr("缺少隧道"), 'error'); return; }
    starting = true;
    busyName = name;
    try {
      const d = await api('/api/lolia/start', { method: 'POST', body: { names: [name] } });
      toast(d || i18nTr("隧道已启动"), 'success');
      await Promise.all([loadStatus(), loadTunnels(true)]);
      loadLog();
      setTimeout(() => { loadTunnels(true); loadStatus(); }, 8000);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      starting = false;
      busyName = '';
    }
  }

  // 单条隧道停止：后端从运行集合摘除该隧道，剩余非空时重启 frpc 加载剩余隧道
  async function stopOne(name) {
    if (!name) { toast(i18nTr("缺少隧道"), 'error'); return; }
    busyName = name;
    try {
      const d = await api('/api/lolia/stop', { method: 'POST', body: { names: [name] } });
      toast(d || i18nTr("隧道已停止"), 'success');
      await Promise.all([loadStatus(), loadTunnels(true)]);
      loadLog();
      setTimeout(() => { loadTunnels(true); loadStatus(); }, 8000);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      busyName = '';
    }
  }

  function stop() {
    showStopConfirm = true;
  }

  async function confirmStop() {
    stopping = true;
    try {
      const d = await api('/api/lolia/stop', { method: 'POST' });
      toast(d || i18nTr("LoliaFrp 隧道已停止"), 'success');
      showStopConfirm = false;
      await Promise.all([loadStatus(), loadTunnels(true)]);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      stopping = false;
    }
  }

  // ---- 隧道创建（两步式：先选节点卡片，再填表单，流程对齐 MEFrp）----
  let showCreate = false;
  let creating = false;
  let pickStep = true; // true=节点选择列表，false=创建表单
  let showScan = false; // 本地端口扫描弹窗
  let scanTarget = 'create'; // 扫描结果回填目标：'create' 创建表单 / 'edit' 编辑弹窗
  let createForm = { nodeId: '', type: 'tcp', localIp: '127.0.0.1', localPort: null, remotePort: null, customDomain: '', remark: '', proxyProto: '' };

  // 节点卡片筛选：地区（按节点 region_code 动态聚合）+ 协议 + 未过载
  let nodeRegionFilter = '';
  let nodeProtoFilter = '';
  let fNodeNotOverload = false;
  const nodeProtoOptions = [
    { value: '', label: i18nTr("全部协议") },
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
    { value: 'http', label: 'HTTP' }
  ];
  // 只列出 Lolia 创建接口支持的类型（supported_protocols 中即使出现 https 也不能建）
  const CREATE_TYPES = ['tcp', 'udp', 'http'];
  // 编辑隧道：传输协议（Lolia 仅支持 tcp/kcp）与 Proxy Protocol 版本（空串=关闭）
  const PROTO_OPTIONS = [
    { value: 'tcp', label: i18nTr("TCP（默认）") },
    { value: 'kcp', label: i18nTr("KCP（弱网更优，节点需支持）") }
  ];
  const PROXY_PROTO_OPTIONS = [
    { value: '', label: i18nTr("关闭") },
    { value: 'v1', label: 'v1' },
    { value: 'v2', label: 'v2' }
  ];
  // Lolia 节点 region_code（ISO 国家/地区代码）→ 中文显示名；未收录的新代码兜底显示原代码，不丢信息
  const REGION_LABELS = {
    CN: i18nTr("中国大陆"), HK: i18nTr("中国香港"), TW: i18nTr("中国台湾"),
    JP: i18nTr("日本"), KR: i18nTr("韩国"), SG: i18nTr("新加坡"), US: i18nTr("美国"),
    CA: i18nTr("加拿大"), GB: i18nTr("英国"), DE: i18nTr("德国"), FR: i18nTr("法国"), IT: i18nTr("意大利"),
    RU: i18nTr("俄罗斯"), AU: i18nTr("澳大利亚"), NL: i18nTr("荷兰")
  };
  const regionLabel = (code) => REGION_LABELS[code.toUpperCase()] || code;
  $: nodeRegionOptions = [{ value: '', label: i18nTr("全部地区") }].concat(
    [...new Set(nodes.map((n) => (n.region_code || '').trim()).filter(Boolean))]
      .sort()
      .map((c) => ({ value: c, label: regionLabel(c) }))
  );
  $: filteredCreateNodes = nodes.filter((n) => {
    if (n.status && n.status !== 'online') return false;
    if (nodeRegionFilter && (n.region_code || '').trim() !== nodeRegionFilter) return false;
    const protos = (n.supported_protocols || []).map((p) => String(p).toLowerCase());
    if (nodeProtoFilter && !protos.includes(nodeProtoFilter)) return false;
    if (fNodeNotOverload && (n.load || 0) >= 100) return false;
    return true;
  });
  // 步骤二当前选中的节点与该节点可创建的类型（与 tcp/udp/http 取交集）
  $: currentCreateNode = nodes.find((n) => String(n.id) === createForm.nodeId) || null;
  // 编辑弹窗顶部信息条：按隧道 node_id 匹配节点对象（展示协议/带宽/地区标签，与节点卡片同源）
  $: editNode = editing ? (nodes.find((n) => String(n.id) === String(editing.node_id)) || null) : null;
  $: createTypeOptions = (() => {
    const protos = (currentCreateNode?.supported_protocols || []).map((p) => String(p).toLowerCase());
    const allow = protos.length ? CREATE_TYPES.filter((t) => protos.includes(t)) : CREATE_TYPES;
    return allow.map((t) => ({ value: t, label: t.toUpperCase() + (t === 'http' ? i18nTr(" · 网站") : i18nTr(" · 通用转发")) }));
  })();

  function nodeLoadColor(load) {
    return (load || 0) >= 100 ? 'var(--red)' : (load || 0) >= 60 ? 'var(--yellow)' : 'var(--green)';
  }
  function nodeBwText(n) {
    // 后端 bandwidth 单位 Mbps，>=1000 换算 Gbps 显示
    const mb = Number(n.bandwidth) || 0;
    return mb >= 1000 ? `${(mb / 1000).toFixed(mb % 1000 === 0 ? 0 : 1)} Gbps` : mb > 0 ? `${mb} Mbps` : '—';
  }

  async function openCreate() {
    createForm = { nodeId: '', type: 'tcp', localIp: '127.0.0.1', localPort: null, remotePort: null, customDomain: '', remark: '', proxyProto: '' };
    bindDomain = ''; hostMode = '@'; subPrefix = ''; orphanDomain = '';
    nodeRegionFilter = '';
    nodeProtoFilter = '';
    fNodeNotOverload = false;
    pickStep = true;
    showCreate = true;
    if (!nodesLoaded) await loadNodes(true);
    loadBindDomains();
  }

  function pickNode(n) {
    createForm.nodeId = String(n.id);
    // 类型限定为该节点实际支持且创建接口允许的协议；当前选择不在列表时回退第一个
    const protos = (n.supported_protocols || []).map((p) => String(p).toLowerCase());
    const allow = protos.length ? CREATE_TYPES.filter((t) => protos.includes(t)) : CREATE_TYPES;
    if (!allow.includes(createForm.type)) createForm.type = allow[0];
    // 选中节点即进入"自动分配端口"态（lolia 无预获取接口，留空创建时由服务端分配）
    createForm.remotePort = null;
    pickStep = false;
  }

  // 「随机」按钮：本地预填一个高端口，仅给想自行指定端口的用户；
  // 不保证未被节点占用（占用时服务端报错，可再点一次或清空留空走自动分配）。
  function randomRemotePort() {
    createForm.remotePort = 20000 + Math.floor(Math.random() * 40001); // 20000-60000
  }

  async function submitCreate() {
    // 格式校验：弹窗内本地地址/端口/域名字段统一拦截并就地提示
    if (!validateAll(createFormEl)) return;
    const nodeId = Number(createForm.nodeId);
    const localPort = Number(createForm.localPort);
    const remotePort = Number(createForm.remotePort) || 0;
    if (!nodeId) { toast(i18nTr("请选择节点"), 'error'); return; }
    if (!createForm.localIp.trim()) { toast(i18nTr("请填写本地地址"), 'error'); return; }
    if (!localPort || localPort < 1 || localPort > 65535) { toast(i18nTr("请填写正确的本地端口（1-65535）"), 'error'); return; }
    // 远程端口选填：留空(0)由 lolia 服务端自动分配可用端口；仅校验用户显式填写的值
    if (remotePort !== 0 && (remotePort < 1 || remotePort > 65535)) {
      toast(i18nTr("远程端口须为 1-65535，或留空自动分配"), 'error');
      return;
    }
    // 绑定域名由「域名选择 + 主机记录」拼出：选了域名就必须能拼出完整域名
    if (createForm.type === 'http' && bindDomain && !fullDomain) {
      toast(i18nTr("请填写子域名前缀"), 'error');
      return;
    }
    // 未选择域名时保留原值（编辑回填场景），否则用拼出的完整域名
    const createDomain = createForm.type === 'http' ? (fullDomain || orphanDomain) : '';
    creating = true;
    try {
      const d = await api('/api/lolia/tunnels', {
        method: 'POST',
        body: {
          node_id: nodeId,
          type: createForm.type,
          local_ip: createForm.localIp.trim(),
          local_port: localPort,
          remote_port: remotePort,
          custom_domain: createDomain,
          remark: createForm.remark.trim()
        }
      });
      const createdName = d && d.tunnel && d.tunnel.name;
      const assignedPort = d && d.tunnel && d.tunnel.remote_port;
      // 官方 POST /user/tunnel 不接收 Proxy Protocol：创建后、首次启动前用编辑接口补设，
      // 保证首次启动加载的就是带 PP 的配置；补设失败则不自动启动，交由用户编辑后手动启动。
      // PP 选择框仅在 tcp/udp 表单提供，http 分支不走这里（避免 PUT 覆盖已绑定的域名）
      if (createdName && createForm.type !== 'http' && createForm.proxyProto) {
        try {
          await api('/api/lolia/tunnel/' + encodeURIComponent(createdName), {
            method: 'PUT',
            body: {
              type: createForm.type,
              local_ip: createForm.localIp.trim(),
              local_port: localPort,
              custom_domain: '',
              remark: createForm.remark.trim(),
              protocol: 'tcp',
              proxy_protocol_version: createForm.proxyProto
            }
          });
        } catch (e) {
          showCreate = false;
          await loadTunnels(true);
          toast(i18nTr("隧道已创建，但 Proxy Protocol 设置失败：") + e.message + i18nTr("，请在隧道编辑中手动设置后再启动"), 'error');
          return;
        }
      }
      const ppSuffix = createForm.proxyProto ? i18nTr("，Proxy Protocol 已设为 {0}", [createForm.proxyProto.toUpperCase()]) : '';
      toast(
        assignedPort && createForm.type !== 'http'
          ? i18nTr("隧道创建成功，服务端分配的公网端口：{0}{1}", [assignedPort, ppSuffix])
          : ((d && d.message) || i18nTr("隧道创建成功")) + ppSuffix,
        'success'
      );
      showCreate = false;
      await loadTunnels(true);
      // 隧道建好后才有节点地址：创建响应不含该字段，用详情接口补齐
      if (createForm.type === 'http' && createDomain) {
        const addr = await resolveTunnelAddr(createdName, d);
        if (!addr) {
          toast(i18nTr("隧道已创建，但未取到节点地址；请在隧道编辑中点「写入解析」"), 'info');
        } else {
          try { await writeBind(addr); } catch (e) { toast(i18nTr("隧道已创建，但写入解析失败：") + e.message, 'error'); }
        }
      }
      // 创建成功后固定自动启动（同节点隧道由后端并入同一 frpc 进程）
      if (createdName) {
        try {
          const msg = await api('/api/lolia/start', { method: 'POST', body: { names: [createdName] } });
          toast(msg || i18nTr("隧道已启动"), 'success');
          await Promise.all([loadStatus(), loadTunnels(true)]);
          loadLog();
        } catch (e) {
          toast(i18nTr("隧道已创建，但启动失败：") + e.message, 'error');
        }
      }
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      creating = false;
    }
  }

  // ---- 隧道编辑 / 删除（可改本地地址/端口、域名、备注、高级配置；节点/类型/远程端口不可改）----
  let showEdit = false;
  let editing = null;
  let savingTunnel = false;
  let editLoading = false;
  let editForm = {
    localIp: '', localPort: null, customDomain: '', remark: '',
    protocol: 'tcp', proxyProto: '', autoTls: false, httpRedirect: false
  };

  // 编辑前拉详情：列表接口不返回 config（传输协议 / Proxy Protocol / AutoTLS / HTTP 跳转）
  async function openEdit(t) {
    // 运行中的隧道本地 frpc 仍加载旧配置，云端改动不会热同步，必须先停止再编辑（与 MEFrp 同规则）
    if (loadedNames.includes(t.name)) {
      toast(i18nTr("该隧道暂未关闭，请关闭后修改"), 'error');
      return;
    }
    editing = t;
    // 先用列表里的值垫底，详情拉到后再以详情为准（列表可能来自缓存）
    editNodeAddr = String(t.node_address || '').trim();
    editForm = {
      localIp: t.local_ip || '127.0.0.1',
      localPort: t.local_port || null,
      customDomain: t.custom_domain || '',
      remark: t.remark || '',
      protocol: 'tcp',
      proxyProto: '',
      autoTls: !!t.auto_tls,
      httpRedirect: false
    };
    showEdit = true;
    editLoading = true;
    // 顶部信息条要展示该节点的协议/带宽/地区标签：页面默认不加载节点列表，此处按需拉取（不阻塞弹窗）
    if (!nodesLoaded) loadNodes(true);
    try {
      const d = await api('/api/lolia/tunnel/' + encodeURIComponent(t.name));
      const c = (d && d.config) || {};
      editForm.protocol = (c.protocol || 'tcp').toLowerCase();
      editForm.proxyProto = (c.proxy_protocol_version || '').toLowerCase();
      editForm.autoTls = !!(c.auto_tls ?? d.auto_tls);
      editForm.httpRedirect = !!c.http_redirect;
      if (d.local_ip) editForm.localIp = d.local_ip;
      if (d.local_port) editForm.localPort = d.local_port;
      if (d.custom_domain) editForm.customDomain = d.custom_domain;
      if (d.remark) editForm.remark = d.remark;
      editNodeAddr = String(d.node_address || t.node_address || '').trim();
      // 解析目标展示的是「实际会写进解析的记录」——把节点地址解析成 IP，避免把节点域名误当目标
      bindTarget = await resolveDisplayTarget(editNodeAddr);
      // 域名回填依赖候选列表（域名解析 ∩ Lolia 已验证域名），先取到位再拆分
      await loadBindDomains();
      fillBindDomain(d.custom_domain || t.custom_domain || '');
    } catch (e) {
      toast(i18nTr("加载隧道高级配置失败：") + e.message, 'error');
    } finally {
      editLoading = false;
    }
  }

  async function saveEdit() {
    if (!editing) return;
    // 格式校验：弹窗内本地地址/端口/域名字段统一拦截并就地提示
    if (!validateAll(editFormEl)) return;
    if (!editForm.localIp.trim()) { toast(i18nTr("请填写本地地址"), 'error'); return; }
    const port = Number(editForm.localPort);
    if (!port || port < 1 || port > 65535) { toast(i18nTr("请填写正确的本地端口（1-65535）"), 'error'); return; }
    // 绑定域名由「域名选择 + 主机记录」拼出：选了域名就必须能拼出完整域名
    const isHttpEdit = ['http', 'https'].includes(String(editing.type || '').toLowerCase());
    if (isHttpEdit && bindDomain && !fullDomain) { toast(i18nTr("请填写子域名前缀"), 'error'); return; }
    // 未选择域名时保留原值（不在候选里的域名照旧回传，避免静默清空）
    if (isHttpEdit) editForm.customDomain = fullDomain || orphanDomain;
    savingTunnel = true;
    try {
      const body = {
        type: editing.type,
        local_ip: editForm.localIp.trim(),
        local_port: port,
        custom_domain: editForm.customDomain.trim(),
        remark: editForm.remark.trim(),
        protocol: editForm.protocol || 'tcp',
        proxy_protocol_version: editForm.proxyProto || '',
      };
      // AutoTLS 仅 http/https、HTTP 跳转仅 https（后端同样按类型过滤）
      const tt = String(editing.type || '').toLowerCase();
      if (tt === 'http' || tt === 'https') body.auto_tls = !!editForm.autoTls;
      if (tt === 'https') body.http_redirect = !!editForm.httpRedirect;
      const d = await api('/api/lolia/tunnel/' + encodeURIComponent(editing.name), { method: 'PUT', body });
      toast(d || i18nTr("隧道已更新"), 'success');
      showEdit = false;
      editing = null;
      await loadTunnels(true);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      savingTunnel = false;
    }
  }

  function deleteTunnel(t) {
    delTunnel = t;
    // 清理解析记录需要候选域名列表，先补齐（异步到位后确认文案会更新）
    loadBindDomains();
  }

  async function confirmDeleteTunnel() {
    if (!delTunnel) return;
    delTunnelBusy = true;
    try {
      const d = await api('/api/lolia/tunnel/' + encodeURIComponent(delTunnel.name), { method: 'DELETE' });
      toast(d || i18nTr("隧道已删除"), 'success');
    } catch (e) {
      toast(e.message, 'error');
      return; // 删除失败：保留弹窗便于重试，且不触碰解析记录
    } finally {
      delTunnelBusy = false;
    }
    // 隧道已删除：同步移除它绑定的解析记录
    try {
      const r = await cleanBindRecord(delTunnel);
      if (r?.removed) toast(i18nTr("已同步删除解析记录：") + r.removed, 'success');
      else if (r?.notfound) toast(i18nTr("未找到指向该节点的解析记录，已跳过（{0} 的记录可能已被手工修改）", [r.notfound]), 'info');
    } catch (e) {
      toast(i18nTr("隧道已删除，但解析记录清理失败：") + e.message, 'error');
    }
    delTunnel = null;
    await Promise.all([loadTunnels(true), loadStatus()]);
  }

  // ---- 域名白名单管理 ----
  let showDomains = false;
  let domains = [];
  let domainsLoading = false;
  let domainForm = { domain: '', remark: '' };
  let addingDomain = false;
  let domainBusyName = ''; // 验证操作中的域名（防重复点击）

  function domainState(d) {
    if (d.is_verified || d.status === 'verified') return { text: i18nTr("已验证"), cls: 'badge-on' };
    if (d.status === 'pending') return { text: i18nTr("待验证"), cls: 'badge-warn' };
    return { text: d.status || i18nTr("未知"), cls: 'badge-off' };
  }

  async function openDomains() {
    showDomains = true;
    domainForm = { domain: '', remark: '' };
    await loadDomains();
  }

  async function loadDomains() {
    domainsLoading = true;
    try {
      const d = await api('/api/lolia/domains');
      domains = d.domains || [];
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      domainsLoading = false;
    }
  }

  async function addDomain() {
    // 格式校验：弹窗内域名输入拦截并就地提示
    if (!validateAll(domainModalEl)) return;
    const domain = domainForm.domain.trim().toLowerCase();
    if (!domain) { toast(i18nTr("请填写域名"), 'error'); return; }
    addingDomain = true;
    try {
      const d = await api('/api/lolia/domains', {
        method: 'POST',
        body: { domain, remark: domainForm.remark.trim() }
      });
      toast((d && d.message) || i18nTr("域名已添加"), 'success');
      domainForm = { domain: '', remark: '' };
      await loadDomains();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      addingDomain = false;
    }
  }

  async function verifyDomainEntry(d) {
    domainBusyName = d.domain;
    try {
      const res = await api('/api/lolia/domains/verify', { method: 'POST', body: { domain: d.domain } });
      if (res && res.result && res.result.is_verified) {
        toast(i18nTr("域名验证成功"), 'success');
        await loadDomains();
      } else {
        toast(i18nTr("域名暂未通过验证：请确认 DNS 记录已添加并已生效后重试"), 'info');
      }
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      domainBusyName = '';
    }
  }

  function deleteDomainEntry(d) {
    delDomain = d;
  }

  async function confirmDeleteDomain() {
    if (!delDomain) return;
    delDomainBusy = true;
    try {
      const msg = await api('/api/lolia/domain/' + encodeURIComponent(delDomain.id), { method: 'DELETE' });
      toast(msg || i18nTr("域名已删除"), 'success');
      delDomain = null;
      await loadDomains();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      delDomainBusy = false;
    }
  }

  function copyDomainText(text, label) {
    if (!text) return;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(() => toast(label + i18nTr("已复制"), 'success'), () => toast(text, 'info'));
    } else {
      toast(text, 'info');
    }
  }

  onMount(() => {
    init();
    const t = pollVisible(loadLog, 15000);
    // OAuth 回跳完成标记（服务端 302 回主界面时携带，同窗口回退场景使用）
    try {
      if (new URLSearchParams(window.location.search).get('lolia_oauth') === '1') {
        setTimeout(() => toast(i18nTr("LoliaFrp 授权成功"), 'success'), 300);
      }
    } catch (e) { /* ignore */ }
    return () => { t(); stopAuthPoll(); };
  });
</script>

<div class="container page-list">
  <div class="page-hdr">
    <div>
      <h2>LoliaFrp</h2>
      <span class="page-hdr-sub">{$i18n("LoliaFrp 洛链映射 · OAuth 授权接入（lolia.link）")}</span>
    </div>
    <div class="page-hdr-actions hdr-actions-wrap">
      {#if authorized}
        <button class="btn btn-sm" on:click={openDomains}>{$i18n("域名管理")}</button>
        <button class="btn btn-sm" on:click={openAppForm}>{$i18n("OAuth 配置")}</button>
        <button class="btn btn-sm" disabled={disconnecting} on:click={disconnect}>{disconnecting ? i18nTr("解除中…") : i18nTr("解除授权")}</button>
        <button class="btn btn-sm" disabled={refreshing} on:click={() => loadTunnels(true)}>{refreshing ? i18nTr("刷新中…") : i18nTr("刷新列表")}</button>
        {#if configured}
          <button class="btn btn-primary btn-sm" on:click={openCreate}>{$i18n("创建隧道")}</button>
        {/if}
      {/if}
    </div>
  </div>

  {#if loading}
    <div class="empty"><div class="empty-t">{$i18n("加载中…")}</div></div>
  {:else}
    <!-- 步骤一：OAuth 应用未配置（首次向导，内联展示；已配置后的修改走弹窗） -->
    {#if !configured}
      <div class="lo-card">
        <h3>{$i18n("第一步 · 创建 OAuth 应用")}</h3>
        <div class="lo-steps">
          <div class="lo-step">
            <span class="lo-step-n">1</span>
            <div>
              {$i18n("打开")} <a href="https://dash.lolia.link" target="_blank" rel="noopener noreferrer" style="color:var(--accent)">{$i18n("LoliaFrp 控制台")}</a>
              {$i18n("（OAuth2 → 应用管理 → 创建应用），把下面这个")}<b>{$i18n("回调地址")}</b>{$i18n("完整填入应用的「重定向 URI / Redirect URIs」：")}
              <div class="lo-redirect">
                <code>{cfg?.redirectOk ? cfg.redirectUri : i18nTr("（回调地址不可用）")}</code>
                <button class="btn btn-sm" disabled={!cfg?.redirectOk} on:click={copyRedirect}>{$i18n("复制")}</button>
              </div>
              {#if cfg && !cfg.redirectOk}
                <div class="lo-warn">{$i18n("回调地址暂不可用：请先在「Webhook」页开启接收端口（默认 19520）并确保设备 IP/域名可从浏览器访问；也可以在下方手动指定回调基址。")}</div>
              {/if}
              <div class="lo-tip">{$i18n("该地址复用 TunHook 的 Webhook 端口接收授权回调，路径固定为")} <code>/api/lolia</code>{$i18n("，需与控制台填写的完全一致（含端口）。")}</div>
            </div>
          </div>
          <div class="lo-step">
            <span class="lo-step-n">2</span>
            <div>{$i18n("把应用的")} <b>Client ID</b> {$i18n("与")} <b>Client Secret</b> {$i18n("填入下方保存，随后点击「前往授权」。")}</div>
          </div>
        </div>
        <LoliaOAuthAppForm {cfg} onSaved={(d) => (cfg = d)} />
      </div>
    {/if}

    <!-- 步骤二：已配置应用但尚未授权 -->
    {#if configured && !authorized}
      <div class="lo-card">
        <h3>{$i18n("第二步 · 授权登录 LoliaFrp")}</h3>
        <div class="lo-user-row">
          <span class="lo-k">{$i18n("应用 Client ID")}</span><span class="lo-mono">{cfg.clientId}</span>
          <span class="lo-spacer"></span>
          <button class="btn btn-sm" on:click={openAppForm}>{$i18n("修改配置")}</button>
        </div>
        <div class="lo-tip" style="margin:8px 0">
          {$i18n("授权将跳转至 LoliaFrp 官方页面登录并同意权限（读取账户、隧道、流量、节点）。\n          授权完成会自动跳回本页，TunHook 不会接触你的账号密码。\n          访问令牌有效期 24 小时，到期前 TunHook 会用刷新令牌自动续期，正常使用无需重复授权。")}
        </div>
        <div class="lo-redirect">
          <code>{cfg.redirectUri}</code>
          <button class="btn btn-sm" disabled={!cfg.redirectOk} on:click={copyRedirect}>{$i18n("复制回调地址")}</button>
        </div>
        <div class="lo-actions" style="margin-top:12px">
          {#if cfg.redirectOk}
            <button class="btn btn-primary" disabled={authorizing} on:click={startAuth}>{authorizing ? i18nTr("正在跳转…") : i18nTr("前往 LoliaFrp 授权")}</button>
          {:else}
            <button class="btn btn-primary" disabled title={$i18n("回调地址不可用")}>{$i18n("回调地址不可用")}</button>
          {/if}
        </div>
      </div>
    {/if}

    <!-- 步骤三：已授权，展示隧道管理 -->
    {#if configured && authorized}
      {#if user}
        <div class="lo-card lo-acct">
          <div class="lo-avatar">{(user.username || 'L').charAt(0).toUpperCase()}</div>
          <div class="lo-acct-id">
            <b>{user.username}
              <span class="badge badge-on">{$i18n("已授权")}</span>
              {#if user.role}<span class="badge badge-info">{user.role}</span>{/if}
              <span class="badge {kycState(user).cls}">{kycState(user).text}</span>
              {#if user.is_banned || user.is_baned}<span class="badge badge-error">{$i18n("已封禁")}</span>{/if}
            </b>
            <span>OAuth Client {cfg.clientId} {$i18n("· 注册于")} {fmtDate(user.created_at)}</span>
          </div>
          <div class="lo-acct-stats">
            <div class="lo-acct-stat"><span>{$i18n("隧道配额")}</span><b>{tunnels.length} / {user.max_tunnel_count}</b></div>
            <div class="lo-acct-stat"><span>{$i18n("流量配额")}</span><b>{fmtBytes(user.traffic_limit)}</b></div>
            <div class="lo-acct-stat"><span>{$i18n("剩余流量")}</span><b style="color:var(--green)">{fmtBytes(Math.max(0, (user.traffic_limit || 0) - (user.traffic_used || 0)))}</b></div>
            <div class="lo-acct-stat"><span>{$i18n("带宽")}</span><b>{fmtMbpsLimit(user.bandwidth_limit)}</b></div>
          </div>
          <div class="lo-quota">
            <div class="lo-quota-hd">
              <span>{$i18n("本月已用")}</span>
              <span class="lo-mono">{fmtBytes(user.traffic_used)} / {fmtBytes(user.traffic_limit)}</span>
            </div>
            <div class="lo-bar"><div class="lo-bar-in" style="width:{pct(user.traffic_used, user.traffic_limit)}%;background:{barColor(pct(user.traffic_used, user.traffic_limit))}"></div></div>
            <div class="lo-quota-foot"><span>{pct(user.traffic_used, user.traffic_limit)}%</span></div>
          </div>
        </div>
      {/if}

      <!-- 本地运行状态 + 操作 -->
      <div class="lo-card lo-statusbar">
        <span class="lo-status">
          <span class="lo-dot" style="background:{running ? 'var(--green)' : 'var(--text3)'};box-shadow:{running ? '0 0 0 3px rgba(var(--green-rgb),.12)' : 'none'}"></span>
          <b>{running ? i18nTr("本地 frpc 运行中") : i18nTr("本地 frpc 未运行")}</b>
          {#if running}<span class="lo-status-meta">PID {pid} {$i18n("· 已加载")} {loadedNames.length || 0} {$i18n("条隧道")}</span>{/if}
        </span>
        <div class="lo-actions">
          <button class="btn btn-danger btn-sm" disabled={stopping || !running} on:click={stop}>{stopping ? i18nTr("停止中…") : i18nTr("停止")}</button>
        </div>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{$i18n("隧道")}</th>
              <th>{$i18n("类型")}</th>
              <th>{$i18n("节点")}</th>
              <th>{$i18n("本地地址")}</th>
              <th>{$i18n("访问地址")}</th>
              <th>{$i18n("云端状态")}</th>
              <th>{$i18n("操作")}</th>
            </tr>
          </thead>
          <tbody>
            {#each tunnels as t (t.name)}
              <tr>
                <td>
                  <span class="lo-name-wrap">
                    <span class="lo-dot" style="background:{t.status === 'active' ? 'var(--green)' : 'var(--text3)'}"></span>
                    <span class="lo-name" title={t.name}>{tunnelTitle(t)}</span>
                  </span>
                </td>
                <td><span class="badge" class:badge-blue={t.type === 'tcp'} class:badge-warn={t.type === 'udp'} class:badge-info={t.type === 'http'} class:badge-on={t.type === 'https'}>{(t.type || '').toUpperCase()}</span></td>
                <td class="lo-muted">{nodeNameOf(t)}</td>
                <td class="lo-mono">{t.local_ip}:{t.local_port}</td>
                <td>
                  {#if t.type === 'http'}
                    <a class="cell-link" href={tunnelAddr(t)} target="_blank" rel="noopener noreferrer" title={$i18n("点击打开")}>{tunnelAddr(t)}</a>
                  {:else}
                    <a class="cell-link lo-mono" href={'http://' + tunnelAddr(t)} target="_blank" rel="noopener noreferrer" title={$i18n("点击打开（浏览器可能无法直接访问 TCP 服务）")}>{tunnelAddr(t)}</a>
                  {/if}
                </td>
                <td><span class="badge {tunnelState(t).cls}">{tunnelState(t).text}</span></td>
                <td>
                  <div class="lo-ops">
                    <!-- 电源按钮：本地已加载该隧道为绿色（点击摘除停止）；未加载为灰色（点击启动），
                         与「代理列表」「MEFrp」保持同一套状态着色规则 -->
                    {#if loadedNames.includes(t.name)}
                      <button class="btn-icon" style="color: var(--green);" title={$i18n("停止此隧道")} aria-label={$i18n("停止此隧道")} disabled={busyName === t.name || starting} on:click={() => stopOne(t.name)}>
                        <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M24 4V24" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
                      </button>
                    {:else}
                      <button class="btn-icon" style="color: var(--text3);" title={$i18n("启动此隧道")} aria-label={$i18n("启动此隧道")} disabled={busyName === t.name || starting} on:click={() => start(t.name)}>
                        <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M24 4V24" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
                      </button>
                    {/if}
                    <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑")} on:click={() => openEdit(t)}>
                      <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M10 44H38C39.1046 44 40 43.1046 40 42V14H30V4H10C8.89543 4 8 4.89543 8 6V42C8 43.1046 8.89543 44 10 44Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M30 4L40 14" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M21 35L31 25L27 21L17 31V35H21Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
                    </button>
                    <button class="btn-icon" style="color: var(--red);" title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => deleteTunnel(t)}>
                      <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
                    </button>
                  </div>
                </td>
              </tr>
            {:else}
              <tr><td colspan="7"><div class="empty" style="padding:24px 0"><div class="empty-t">{refreshing ? i18nTr("加载中…") : i18nTr("LoliaFrp 账户下暂无隧道，请前往控制台创建")}</div></div></td></tr>
            {/each}
          </tbody>
        </table>
        <div class="lo-table-foot">
          <span>{$i18n("共")} {tunnels.length} {$i18n("条隧道 · 已加载")} {loadedNames.length || 0} {$i18n("条")}</span>
          <span class="lo-foot-meta">{$i18n("OAuth 授权有效")}</span>
        </div>
      </div>

      <div class="list-cards">
        {#if tunnels.length === 0}
          <div class="list-cards-empty">{refreshing ? i18nTr("加载中…") : i18nTr("LoliaFrp 账户下暂无隧道")}</div>
        {/if}
        {#each tunnels as t (t.name)}
          <div class="list-card">
            <div class="list-card-top">
              <span class="lo-dot" style="background:{t.status === 'active' ? 'var(--green)' : 'var(--text3)'}"></span>
              <div class="list-card-title">{tunnelTitle(t)}</div>
              <span class="badge" class:badge-blue={t.type === 'tcp'} class:badge-warn={t.type === 'udp'} class:badge-info={t.type === 'http'} class:badge-on={t.type === 'https'}>{(t.type || '').toUpperCase()}</span>
              <span class="badge {tunnelState(t).cls}" style="margin-left:auto;flex-shrink:0">{tunnelState(t).text}</span>
            </div>
            <div class="list-card-sub">{nodeNameOf(t)}</div>
            <div class="list-card-rows">
              <div class="list-card-row"><span class="k">{$i18n("本地")}</span><span class="v cell-mono ellip">{t.local_ip}:{t.local_port}</span></div>
              <div class="list-card-row"><span class="k">{$i18n("访问")}</span>
                <span class="v">
                  {#if t.type === 'http'}
                    <a class="cell-link ellip" href={tunnelAddr(t)} target="_blank" rel="noopener noreferrer">{tunnelAddr(t)}</a>
                  {:else}
                    <a class="cell-link cell-mono ellip" href={'http://' + tunnelAddr(t)} target="_blank" rel="noopener noreferrer" title={$i18n("点击打开（浏览器可能无法直接访问 TCP 服务）")}>{tunnelAddr(t)}</a>
                  {/if}
                </span>
              </div>
            </div>
            <div class="list-card-actions">
              <span class="lo-foot-note">{$i18n("Lolia 云端")}</span>
              <!-- 电源按钮：本地已加载为绿色（停止），未加载为灰色（启动），与桌面端/MEFrp 一致 -->
              {#if loadedNames.includes(t.name)}
                <button class="btn-icon" style="color: var(--green);" title={$i18n("停止此隧道")} aria-label={$i18n("停止此隧道")} disabled={busyName === t.name || starting} on:click={() => stopOne(t.name)}>
                  <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M24 4V24" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
                </button>
              {:else}
                <button class="btn-icon" style="color: var(--text3);" title={$i18n("启动此隧道")} aria-label={$i18n("启动此隧道")} disabled={busyName === t.name || starting} on:click={() => start(t.name)}>
                  <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M24 4V24" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
                </button>
              {/if}
              <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑")} on:click={() => openEdit(t)}>
                <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M10 44H38C39.1046 44 40 43.1046 40 42V14H30V4H10C8.89543 4 8 4.89543 8 6V42C8 43.1046 8.89543 44 10 44Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M30 4L40 14" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M21 35L31 25L27 21L17 31V35H21Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
              </button>
              <button class="btn-icon" style="color: var(--red);" title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => deleteTunnel(t)}>
                <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
              </button>
            </div>
          </div>
        {/each}
      </div>

      <div class="lo-card" style="margin-top:14px">
        <h3>{$i18n("frpc 运行日志")}</h3>
        <pre class="lo-log">{@html highlightLog(logText)}</pre>
      </div>

      {#if tunnels.some((t) => t.auto_tls)}
        <div class="lo-warn" style="margin-top:10px">
          {$i18n("检测到开启 AutoTLS 的隧道：官方通过定制 frpc 内核在本地自动申请证书，TunHook 内置的官方 frpc 可能无法直接运行该隧道，如启动失败请先关闭 AutoTLS（后续版本将支持 lolia 定制内核）。")}
        </div>
      {/if}
    {/if}
  {/if}
</div>

{#if showEdit && editing}
  <div class="modal-overlay" on:click|self={() => (showEdit = false)} role="presentation">
    <div class="modal" style="max-width:520px">
      <div class="modal-hdr">
        <h3>{$i18n("编辑隧道")}</h3>
        <button class="modal-close" on:click={() => (showEdit = false)} aria-label={$i18n("关闭")}>×</button>
      </div>
      <div class="modal-body" bind:this={editFormEl}>
        <div class="lo-edit-readonly">
          {$i18n("节点")} <b>{nodeNameOf(editing)}</b> {$i18n("· 类型")} <b>{(editing.type || '').toUpperCase()}</b> {$i18n("·\n          远程端口")} <b>{editing.remote_port || '—'}</b>
          {#if editNode}
            <div class="lo-node-tags" style="margin-top:6px">
              {#each (editNode.supported_protocols || []) as p}
                <span class="lo-badge">{String(p).toUpperCase()}</span>
              {/each}
              <span class="lo-badge lo-badge-bw">{nodeBwText(editNode)}</span>
              {#if editNode.region_code}<span class="lo-badge lo-badge-region">{regionLabel(editNode.region_code)}</span>{/if}
            </div>
          {/if}
          <div class="lo-tip">{$i18n("LoliaFrp 不支持修改节点、类型、远程端口与隧道名称，如需更换请删除后重建。")}</div>
        </div>
        <div class="form-group">
          <label class="form-label">{$i18n("备注")}</label>
          <input type="text" bind:value={editForm.remark} placeholder={$i18n("便于识别的名称，如 my-web")} maxlength="64" disabled={editLoading} />
        </div>
        <div class="form-row">
          <div class="form-group" style="flex:2">
            <label class="form-label">{$i18n("本地地址")}</label>
            <input type="text" bind:value={editForm.localIp} placeholder="127.0.0.1" disabled={editLoading} use:field={{ check: validateHost }} />
          </div>
          <div class="form-group" style="flex:1">
            <label class="form-label">{$i18n("本地端口")}</label>
            <div class="lo-input-btn">
              <input type="number" min="1" max="65535" bind:value={editForm.localPort} placeholder="8080" disabled={editLoading} use:field={{ check: validatePort }} />
              <button class="btn btn-sm" type="button" title={$i18n("扫描本机/局域网开放端口")} disabled={editLoading} on:click={() => { scanTarget = 'edit'; showScan = true; }}>{$i18n("扫描")}</button>
            </div>
          </div>
        </div>
        {#if ['http', 'https'].includes((editing.type || '').toLowerCase())}
          <div class="form-group">
            <div class="form-row">
              <div class="form-group" style="flex:1;margin-bottom:0">
                <label class="form-label" for="lo-edit-bind-domain">{$i18n("域名选择")}</label>
                <CustomSelect id="lo-edit-bind-domain" bind:value={bindDomain} options={bindDomainOpts} disabled={editLoading}
                  placeholder={bindDomainOpts.length ? i18nTr("留空则通过节点地址访问") : i18nTr("需先在「域名解析」添加域名，并在「域名管理」通过验证")} />
              </div>
              <div class="form-group" style="flex:1;max-width:210px;margin-bottom:0">
                <label class="form-label" for="lo-edit-host-mode">{$i18n("主机记录")}</label>
                <CustomSelect id="lo-edit-host-mode" bind:value={hostMode} options={hostModeOpts} disabled={editLoading} />
              </div>
            </div>
            {#if bindDomain && hostMode === 'sub'}
              <div class="form-row" style="margin-top:8px">
                <div class="form-group" style="flex:1;margin-bottom:0">
                  <label class="form-label" for="lo-edit-sub-prefix">{$i18n("子域名")}</label>
                  <input id="lo-edit-sub-prefix" type="text" bind:value={subPrefix} placeholder={$i18n("如 web（仅字母/数字/连字符）")} disabled={editLoading} />
                </div>
                <div class="form-group" style="flex:1;margin-bottom:0">
                  <label class="form-label" for="lo-edit-picked-domain">{$i18n("域名")}</label>
                  <input id="lo-edit-picked-domain" type="text" value={bindDomain} readonly tabindex="-1" placeholder={$i18n("未选择域名")} />
                </div>
              </div>
            {/if}
            {#if orphanDomain}
              <div class="lo-tip">{$i18n("原域名")} {orphanDomain} {$i18n("不在候选列表中：不重新选择则保持原样，选择后将替换它。")}</div>
            {/if}
            <div class="lo-tip" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
              <button class="btn btn-sm" type="button" disabled={binding || !bindDomain || !editNodeAddr || !fullDomain} on:click={writeEditBind}>
                {binding ? i18nTr("写入中…") : i18nTr("写入解析")}
              </button>
              <span>{bindHint}</span>
            </div>
          </div>
        {/if}

        <!-- 与官方控制台一致：所有类型均可改传输协议与 Proxy Protocol；比例 2:1 与上方地址行对齐 -->
        <div class="form-row">
          <div class="form-group" style="flex:2">
            <label class="form-label">{$i18n("连接协议")}</label>
            <CustomSelect bind:value={editForm.protocol} options={PROTO_OPTIONS} disabled={editLoading} />
          </div>
          <div class="form-group" style="flex:1">
            <label class="form-label">Proxy Protocol</label>
            <CustomSelect bind:value={editForm.proxyProto} options={PROXY_PROTO_OPTIONS} disabled={editLoading} />
          </div>
        </div>
        {#if editForm.proxyProto}
          <div class="lo-warn" style="margin:0 0 10px">
            {$i18n("注意：若映射的本地服务不支持 Proxy Protocol，启用后将无法连接到该服务，请确认后端已开启对应支持。")}
          </div>
        {/if}

        {#if ['http', 'https'].includes((editing.type || '').toLowerCase())}
          <label class="lo-check-inline">
            <input type="checkbox" bind:checked={editForm.autoTls} disabled={editLoading} />
            <span>{$i18n("启用 AutoTLS（自动申请 HTTPS 证书，仅支持 LoliaFRP-CLI ≥ 0.67.1 快捷启动；TunHook 内置官方 frpc 可能无法运行）")}</span>
          </label>
        {/if}
        {#if (editing.type || '').toLowerCase() === 'https'}
          <label class="lo-check-inline" style="margin-top:8px">
            <input type="checkbox" bind:checked={editForm.httpRedirect} disabled={editLoading} />
            <span>{$i18n("HTTP 自动跳转 HTTPS（仅支持 LoliaFRP-CLI ≥ 0.69.2 快捷启动）")}</span>
          </label>
        {/if}
      </div>
      <div class="modal-ftr">
        <button class="btn" on:click={() => (showEdit = false)}>{$i18n("取消")}</button>
        <button class="btn btn-primary" disabled={savingTunnel || editLoading} on:click={saveEdit}>{editLoading ? i18nTr("加载中…") : savingTunnel ? i18nTr("保存中…") : i18nTr("保存修改")}</button>
      </div>
    </div>
  </div>
{/if}

{#if showCreate}
  <div class="modal-overlay" on:click|self={() => (showCreate = false)} role="presentation">
    <div class="modal" style="max-width:{pickStep ? '960px' : '560px'}">
      <div class="modal-hdr">
        <h3>{pickStep ? i18nTr("选择节点") : i18nTr("创建 LoliaFrp 隧道")}</h3>
        <button class="modal-close" on:click={() => (showCreate = false)} aria-label={$i18n("关闭")}>×</button>
      </div>
      <div class="modal-body" bind:this={createFormEl}>
        {#if pickStep}
          <!-- 步骤一：节点卡片列表 -->
          <div class="lo-filters">
            <CustomSelect bind:value={nodeRegionFilter} options={nodeRegionOptions} width="150px" />
            <CustomSelect bind:value={nodeProtoFilter} options={nodeProtoOptions} width="120px" />
            <label class="lo-fcheck"><input type="checkbox" bind:checked={fNodeNotOverload} /> {$i18n("未过载")}</label>
            <span class="lo-fcount">{filteredCreateNodes.length} / {nodes.filter((n) => !n.status || n.status === 'online').length} {$i18n("个节点")}</span>
          </div>
          <div class="lo-node-grid">
            {#each filteredCreateNodes as n (n.id)}
              <div
                class="lo-node"
                class:lo-node-sel={createForm.nodeId === String(n.id)}
                role="button"
                tabindex="0"
                on:click={() => pickNode(n)}
                on:keydown={(e) => e.key === 'Enter' && pickNode(n)}
              >
                <div class="lo-node-hd">
                  <span class="lo-node-name">#{n.id} {n.name}</span>
                  <span class="lo-node-tags-hd">
                    {#if n.need_kyc}<span class="lo-tag lo-tag-warn" title={$i18n("使用该节点需完成实名认证")}>{$i18n("实名")}</span>{/if}
                    {#if n.beian_required}<span class="lo-tag lo-tag-warn" title={$i18n("建站域名需完成备案")}>{$i18n("备案")}</span>{/if}
                    {#if (n.load || 0) >= 100}<span class="lo-tag lo-tag-load">{$i18n("过载")}</span>{/if}
                  </span>
                </div>
                <div class="lo-node-tags">
                  {#each (n.supported_protocols || []) as p}
                    <span class="lo-badge">{String(p).toUpperCase()}</span>
                  {/each}
                  <span class="lo-badge lo-badge-bw">{nodeBwText(n)}</span>
                  {#if n.region_code}<span class="lo-badge lo-badge-region">{regionLabel(n.region_code)}</span>{/if}
                </div>
                <div class="lo-node-desc" title={n.remark || ''}>{n.remark || i18nTr("暂无节点描述")}</div>
                <div class="lo-node-ft">
                  <div class="lo-loadbar">
                    <div class="lo-loadbar-in" style="width:{Math.min(n.load || 0, 100)}%;background:{nodeLoadColor(n.load)}"></div>
                  </div>
                  <span class="lo-loadtxt">{Number(n.load || 0).toFixed(0)}{$i18n("% 负载")}</span>
                </div>
              </div>
            {:else}
              <div class="empty" style="grid-column:1/-1"><div class="empty-t">{nodesLoading ? i18nTr("节点加载中…") : i18nTr("没有符合筛选条件的节点")}</div></div>
            {/each}
          </div>
        {:else}
          <!-- 步骤二：创建表单 -->
          <div class="form-group">
            <label class="form-label">{$i18n("服务器（节点）")}</label>
            <div class="lo-picked">
              <span>{currentCreateNode ? `#${currentCreateNode.id} ${currentCreateNode.name}` : i18nTr("未选择")}</span>
              <button class="btn btn-sm" on:click={() => (pickStep = true)}>{$i18n("重新选择")}</button>
            </div>
            {#if currentCreateNode}
              <div class="lo-tip" style="margin-top:6px">
                {$i18n("支持协议")} {(currentCreateNode.supported_protocols || []).join(' · ') || '—'} {$i18n("· 带宽")} {nodeBwText(currentCreateNode)} {$i18n("·\n                负载")} {Number(currentCreateNode.load || 0).toFixed(0)}%
                {#if currentCreateNode.need_kyc} · <span style="color:var(--yellow)">{$i18n("需实名认证")}</span>{/if}
                {#if currentCreateNode.beian_required} · <span style="color:var(--yellow)">{$i18n("需域名备案")}</span>{/if}
              </div>
            {/if}
          </div>
          <div class="form-row">
            <div class="form-group" style="flex:1.6">
              <label class="form-label">{$i18n("备注")}</label>
              <input type="text" bind:value={createForm.remark} placeholder={$i18n("便于识别的名称，如 my-web（可选）")} maxlength="64" />
            </div>
            <div class="form-group" style="flex:1;max-width:210px">
              <label class="form-label">{$i18n("类型")}</label>
              <CustomSelect bind:value={createForm.type} options={createTypeOptions} />
            </div>
          </div>
          <div class="form-row">
            <div class="form-group" style="flex:1.6">
              <label class="form-label">{$i18n("本地地址")}</label>
              <input type="text" bind:value={createForm.localIp} placeholder="127.0.0.1" use:field={{ check: validateHost }} />
              <div class="lo-tip">{$i18n("本机服务填 127.0.0.1，局域网设备填对应内网 IP")}</div>
            </div>
            <div class="form-group" style="flex:1;max-width:210px">
              <label class="form-label">{$i18n("本地端口")}</label>
              <div class="lo-input-btn">
                <input type="number" min="1" max="65535" bind:value={createForm.localPort} placeholder={$i18n("本机服务端口")} use:field={{ check: validatePort, errAt: () => createLocalPortErr }} />
                <button class="btn btn-sm" type="button" title={$i18n("扫描本机/局域网开放端口")} on:click={() => { scanTarget = 'create'; showScan = true; }}>{$i18n("扫描")}</button>
              </div>
              <div class="field-err" bind:this={createLocalPortErr} style="display:none"></div>
            </div>
          </div>
          {#if createForm.type === 'http'}
            <div class="form-group">
              <div class="form-row">
                <div class="form-group" style="flex:1;margin-bottom:0">
                  <label class="form-label" for="lo-create-bind-domain">{$i18n("域名选择")}</label>
                  <CustomSelect id="lo-create-bind-domain" bind:value={bindDomain} options={bindDomainOpts}
                    placeholder={bindDomainOpts.length ? i18nTr("留空则通过节点地址访问") : i18nTr("需先在「域名解析」添加域名，并在「域名管理」通过验证")} />
                </div>
                <div class="form-group" style="flex:1;max-width:210px;margin-bottom:0">
                  <label class="form-label" for="lo-create-host-mode">{$i18n("主机记录")}</label>
                  <CustomSelect id="lo-create-host-mode" bind:value={hostMode} options={hostModeOpts} />
                </div>
              </div>
              {#if bindDomain && hostMode === 'sub'}
                <div class="form-row" style="margin-top:8px">
                  <div class="form-group" style="flex:1;margin-bottom:0">
                    <label class="form-label" for="lo-create-sub-prefix">{$i18n("子域名")}</label>
                    <input id="lo-create-sub-prefix" type="text" bind:value={subPrefix} placeholder={$i18n("如 web（仅字母/数字/连字符）")} />
                  </div>
                  <div class="form-group" style="flex:1;margin-bottom:0">
                    <label class="form-label" for="lo-create-picked-domain">{$i18n("域名")}</label>
                    <input id="lo-create-picked-domain" type="text" value={bindDomain} readonly tabindex="-1" placeholder={$i18n("未选择域名")} />
                  </div>
                </div>
              {/if}
              <div class="lo-tip">{$i18n("境内节点通常禁止 HTTP 建站，请优先选择境外节点；AutoTLS 可在创建后通过编辑开启。")}</div>
              <div class="lo-tip">{bindHint}</div>
            </div>
          {:else}
            <div class="form-row">
              <div class="form-group" style="flex:1.6">
                <label class="form-label">{$i18n("远程端口（选填）")}</label>
                <div class="lo-input-btn">
                  <input type="number" min="1" max="65535" bind:value={createForm.remotePort} placeholder={$i18n("留空由服务端自动分配")} use:field={{ check: optional((v) => validatePort(v, true)), errAt: () => createRemotePortErr }} />
                  <button class="btn btn-sm" type="button" title={$i18n("随机预填一个高端口（不保证未被占用）")} on:click={randomRemotePort}>{$i18n("随机")}</button>
                </div>
                <div class="field-err" bind:this={createRemotePortErr} style="display:none"></div>
                <div class="lo-tip">{$i18n("推荐留空，创建时由 LoliaFrp 自动分配可用公网端口；「随机」仅为本地预填，占用时可再点一次或清空")}</div>
              </div>
              <!-- 官方创建接口不接收 PP，提交时在创建后、启动前自动 PUT 补设 -->
              <div class="form-group" style="flex:1;max-width:210px">
                <label class="form-label">Proxy Protocol</label>
                <CustomSelect bind:value={createForm.proxyProto} options={PROXY_PROTO_OPTIONS} />
              </div>
            </div>
            {#if createForm.proxyProto}
              <div class="lo-warn">
                {$i18n("注意：若映射的本地服务不支持 Proxy Protocol，启用后将无法连接到该服务，请确认后端已开启对应支持。")}
              </div>
            {/if}
          {/if}
        {/if}
      </div>
      <div class="modal-ftr">
        {#if !pickStep}
          <button class="btn" on:click={() => (pickStep = true)}>{$i18n("上一步")}</button>
        {/if}
        <button class="btn" on:click={() => (showCreate = false)}>{$i18n("取消")}</button>
        {#if !pickStep}
          <button class="btn btn-primary" disabled={creating || !currentCreateNode} on:click={submitCreate}>{creating ? i18nTr("创建中…") : i18nTr("创建隧道")}</button>
        {/if}
      </div>
    </div>
  </div>
{/if}

{#if showScan}
  <PortScanModal
    targetIP={(scanTarget === 'edit' ? editForm.localIp : createForm.localIp) || '127.0.0.1'}
    onClose={() => (showScan = false)}
    onPick={(it) => {
      // 回填必须整体重新赋值：Svelte 只对「组件级变量」的直接赋值做失效处理，
      // 借别名改属性（const t = createForm; t.x = ...）不会触发更新，表现就是「点了没填充」。
      const src = scanTarget === 'edit' ? editForm : createForm;
      const patch = { localPort: it.port };
      // 备注留空时用扫描结果建议一个便于识别的名称（Lolia 无隧道名字段，备注即标识）；
      // 已有备注不覆盖——扫描只是为了换端口时不该顺手改掉用户写的说明
      if (!String(src.remark || '').trim()) patch.remark = suggestDescription(it);
      if (it.local_addr && it.local_addr !== '0.0.0.0' && it.local_addr !== '::') patch.localIp = it.local_addr;
      if (scanTarget === 'edit') editForm = { ...editForm, ...patch };
      else createForm = { ...createForm, ...patch };
      showScan = false;
    }}
  />
{/if}

{#if showDomains}
  <div class="modal-overlay" on:click|self={() => (showDomains = false)} role="presentation">
    <div class="modal" style="max-width:660px">
      <div class="modal-hdr">
        <h3>{$i18n("域名管理")}</h3>
        <button class="modal-close" on:click={() => (showDomains = false)} aria-label={$i18n("关闭")}>×</button>
      </div>
      <div class="modal-body" bind:this={domainModalEl}>
        <!-- 添加域名 -->
        <div class="lo-domain-add">
          <div class="form-group" style="flex:1.4">
            <label class="form-label">{$i18n("添加域名（不带 http:// 前缀）")}</label>
            <input type="text" bind:value={domainForm.domain} placeholder="example.com" on:keydown={(e) => e.key === 'Enter' && !addingDomain && addDomain()} use:field={{ check: validateDomain, errAt: () => domainErr }} />
          </div>
          <div class="form-group" style="flex:1">
            <label class="form-label">{$i18n("备注（可选）")}</label>
            <input type="text" bind:value={domainForm.remark} placeholder={$i18n("便于识别")} maxlength="64" on:keydown={(e) => e.key === 'Enter' && !addingDomain && addDomain()} />
          </div>
          <div class="form-group" style="flex:0 0 auto">
            <label class="form-label">&nbsp;</label>
            <button class="btn btn-primary" disabled={addingDomain} on:click={addDomain}>{addingDomain ? i18nTr("添加中…") : i18nTr("添加")}</button>
          </div>
        </div>
        <div class="field-err" bind:this={domainErr} style="display:none"></div>

        <!-- 域名列表 -->
        <div class="lo-domain-list">
          {#if domainsLoading}
            <div class="empty"><div class="empty-t">{$i18n("加载中…")}</div></div>
          {:else if domains.length === 0}
            <div class="empty"><div class="empty-t">{$i18n("暂无域名，添加并完成归属验证后即可在 HTTP 隧道中绑定")}</div></div>
          {:else}
            {#each domains as d (d.id)}
              <div class="lo-domain-item">
                <div class="lo-domain-hd">
                  <span class="lo-domain-name">{d.domain}</span>
                  <span class="badge {domainState(d).cls}">{domainState(d).text}</span>
                  {#if d.has_beian}<span class="badge badge-on">{$i18n("已备案")}</span>{/if}
                  <button class="btn btn-sm lo-domain-del" on:click={() => deleteDomainEntry(d)}>{$i18n("删除")}</button>
                </div>
                {#if d.remark}<div class="lo-domain-remark">{d.remark}</div>{/if}
                <div class="lo-domain-meta">
                  {#if d.expires_at}<span>{$i18n("有效期至")} {fmtDate(d.expires_at)}</span>{/if}
                  {#if d.created_at}<span>{$i18n("添加于")} {fmtDate(d.created_at)}</span>{/if}
                  {#if d.verified_at}<span>{$i18n("验证于")} {fmtDate(d.verified_at)}</span>{/if}
                </div>
                {#if !d.is_verified && d.status !== 'verified'}
                  <!-- 待验证：给出 DNS 记录值 + Cloudflare 一键验证 + 手动复验 -->
                  <div class="lo-verify-box">
                    <div class="lo-tip" style="color:var(--yellow)">{$i18n("域名添加后需完成归属验证：在域名 DNS 服务商添加以下记录，全球生效后点击「重新验证」。")}</div>
                    {#if d.verification_subdomain && d.verification_token}
                      <div class="lo-verify-rows">
                        <div class="lo-verify-row">
                          <span class="lo-k">{$i18n("记录类型")}</span><b>TXT</b>
                        </div>
                        <div class="lo-verify-row">
                          <span class="lo-k">{$i18n("主机记录")}</span>
                          <code>{d.verification_subdomain}</code>
                          <button class="btn btn-sm" type="button" on:click={() => copyDomainText(d.verification_subdomain, '主机记录')}>{$i18n("复制")}</button>
                        </div>
                        <div class="lo-verify-row">
                          <span class="lo-k">{$i18n("记录值")}</span>
                          <code>{d.verification_token}</code>
                          <button class="btn btn-sm" type="button" on:click={() => copyDomainText(d.verification_token, '记录值')}>{$i18n("复制")}</button>
                        </div>
                      </div>
                    {/if}
                    <div class="lo-verify-actions">
                      <button class="btn btn-primary btn-sm" disabled={domainBusyName === d.domain} on:click={() => verifyDomainEntry(d)}>{domainBusyName === d.domain ? i18nTr("验证中…") : i18nTr("重新验证")}</button>
                      {#if d.domain_connect_url}
                        <a class="btn btn-sm" href={d.domain_connect_url} target="_blank" rel="noopener noreferrer">{$i18n("使用 Cloudflare 一键验证 ↗")}</a>
                      {/if}
                    </div>
                  </div>
                {/if}
              </div>
            {/each}
          {/if}
        </div>
      </div>
      <div class="modal-ftr">
        <button class="btn" on:click={() => loadDomains()} disabled={domainsLoading}>{domainsLoading ? i18nTr("刷新中…") : i18nTr("刷新")}</button>
        <button class="btn btn-primary" on:click={() => (showDomains = false)}>{$i18n("完成")}</button>
      </div>
    </div>
  </div>
{/if}

{#if configured && showAppForm}
  <Modal title={$i18n("修改 OAuth 应用配置")} onClose={() => (showAppForm = false)} width={520}>
    <div class="lo-tip" style="margin-bottom:12px">
      {$i18n("更新 Client ID / Client Secret 或回调基址。回调地址需与 LoliaFrp 控制台填写的「重定向 URI」完全一致（含端口）；\n      Client Secret 留空表示沿用已保存的值。当前回调地址：")}<code style="font-family:var(--mono);font-size:11px">{cfg?.redirectUri || i18nTr("（不可用）")}</code>
    </div>
    <LoliaOAuthAppForm
      {cfg}
      showCancel
      onCancel={() => (showAppForm = false)}
      onSaved={(d) => { cfg = d; showAppForm = false; }}
    />
  </Modal>
{/if}

{#if showStopConfirm}
  <ConfirmModal
    title={$i18n("停止全部隧道")}
    message={$i18n("确定停止本地 frpc 吗？所有 LoliaFrp 隧道将立即中断，外部无法继续访问，可随时重新启动。")}
    confirmText={$i18n("停止")}
    onConfirm={confirmStop}
    onClose={() => { if (!stopping) showStopConfirm = false; }}
    busy={stopping}
  />
{/if}

{#if showDisconnectConfirm}
  <ConfirmModal
    title={$i18n("解除 LoliaFrp 授权")}
    message={$i18n("确定解除 LoliaFrp 授权？解除后将停止同步隧道（OAuth 应用配置会保留，可重新授权）。")}
    confirmText={$i18n("解除授权")}
    onConfirm={confirmDisconnect}
    onClose={() => { if (!disconnecting) showDisconnectConfirm = false; }}
    busy={disconnecting}
  />
{/if}

{#if delTunnel}
  <ConfirmModal
    title={$i18n("删除隧道")}
    message={`确定删除隧道「${tunnelTitle(delTunnel)}」吗？此操作不可恢复。${delDnsHint}`}
    onConfirm={confirmDeleteTunnel}
    onClose={() => { if (!delTunnelBusy) delTunnel = null; }}
    busy={delTunnelBusy}
  />
{/if}

{#if delDomain}
  <ConfirmModal
    title={$i18n("删除域名")}
    message={`确定删除域名「${delDomain.domain}」吗？此操作不可恢复。`}
    onConfirm={confirmDeleteDomain}
    onClose={() => { if (!delDomainBusy) delDomain = null; }}
    busy={delDomainBusy}
  />
{/if}

<style>
  .lo-card {
    border: 1px solid var(--bd);
    border-radius: calc(var(--radius) + 4px);
    background: var(--bg3);
    padding: 16px 18px;
    margin-bottom: 14px;
    box-shadow: var(--shadow-card);
  }
  .lo-card h3 { font-size: 13.5px; font-weight: 600; color: var(--text); margin-bottom: 10px; }

  /* 账户卡片：头像 + 账号信息 + 4 项配额 + 流量进度 */
  .lo-acct { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
  .lo-avatar {
    width: 40px; height: 40px; flex-shrink: 0; border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    background: rgba(var(--accent-rgb), .12); color: var(--accent);
    font-size: 17px; font-weight: 700;
  }
  .lo-acct-id { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .lo-acct-id b { font-size: 13.5px; font-weight: 600; color: var(--text); display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .lo-acct-id > span { font-size: 11px; color: var(--text3); font-family: var(--mono); word-break: break-all; }
  .lo-acct-stats { display: flex; align-items: center; gap: 22px; margin-left: auto; flex-wrap: wrap; }
  .lo-acct-stat { min-width: 66px; }
  .lo-acct-stat span { display: block; font-size: 10px; color: var(--text3); margin-bottom: 3px; }
  .lo-acct-stat b { font-family: var(--mono); font-size: 13px; font-weight: 600; color: var(--text); font-variant-numeric: tabular-nums; }
  .lo-quota { width: 170px; flex-shrink: 0; display: flex; flex-direction: column; gap: 6px; }
  .lo-quota-hd { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 10.5px; color: var(--text3); }
  .lo-quota-foot { font-size: 10px; color: var(--text3); font-family: var(--mono); }

  /* 本地 frpc 运行状态条 */
  .lo-statusbar { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; padding-top: 12px; padding-bottom: 12px; }
  .lo-status { display: inline-flex; align-items: center; gap: 8px; flex-wrap: wrap; min-width: 0; }
  .lo-status b { font-size: 13.5px; font-weight: 600; color: var(--text); }
  .lo-status-meta { font-size: 11px; color: var(--text3); font-family: var(--mono); }
  .lo-dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
  .lo-name-wrap { display: inline-flex; align-items: center; gap: 7px; min-width: 0; }
  .lo-muted { color: var(--text3); }
  .badge-blue { color: var(--blue); background: rgba(var(--blue-rgb), .08); border: 1px solid rgba(var(--blue-rgb), .25); }
  .lo-table-foot {
    display: flex; align-items: center; justify-content: space-between; gap: 10px;
    padding: 10px 12px; border-top: 1px solid var(--bd);
    font-size: 11px; color: var(--text3); flex-wrap: wrap;
  }
  .lo-foot-meta { font-family: var(--mono); }
  .lo-foot-note { margin-right: auto; font-size: 10.5px; color: var(--text3); font-family: var(--mono); }
  .lo-tip { font-size: 12px; color: var(--text3); line-height: 1.6; }
  .lo-tip code, .lo-step code { background: var(--bg4); padding: 1px 5px; border-radius: 4px; font-family: var(--mono); font-size: 11px; }
  .lo-steps { display: flex; flex-direction: column; gap: 12px; margin-bottom: 12px; }
  .lo-step { display: flex; gap: 10px; font-size: 12px; color: var(--text2); line-height: 1.7; }
  .lo-step-n {
    flex: 0 0 20px; width: 20px; height: 20px; border-radius: 50%;
    background: rgba(var(--accent-rgb), 0.12); color: var(--accent);
    font-size: 11px; font-weight: 700; display: flex; align-items: center; justify-content: center; margin-top: 1px;
  }
  .lo-redirect {
    display: flex; align-items: center; gap: 8px; margin: 8px 0;
    background: var(--bg4); border: 1px solid var(--bd); border-radius: 6px; padding: 8px 10px;
  }
  .lo-redirect code {
    flex: 1; font-family: var(--mono); font-size: 12px; color: var(--text);
    word-break: break-all; user-select: all;
  }
  .lo-warn {
    font-size: 12px; color: var(--yellow);
    background: rgba(var(--yellow-rgb), 0.08);
    border: 1px solid rgba(var(--yellow-rgb), 0.3);
    border-radius: var(--radius);
    padding: 8px 12px; margin: 8px 0;
  }
  .lo-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
  .lo-run { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .lo-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .lo-user { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px 20px; }
  .lo-user-row { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; font-size: 12px; color: var(--text); }
  .lo-strong { font-weight: 600; color: var(--text); }
  .lo-k { color: var(--text3); flex-shrink: 0; }
  .lo-mono { font-family: var(--mono); }
  .lo-spacer { flex: 1; }
  .lo-traffic { display: flex; flex-direction: column; gap: 6px; }
  .lo-traffic-hd { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 12px; }
  .lo-bar { height: 6px; border-radius: 3px; background: rgba(var(--slate-rgb), 0.25); overflow: hidden; }
  .lo-bar-sm { width: 90px; height: 4px; border-radius: 2px; }
  .lo-bar-in { height: 100%; border-radius: inherit; transition: width 0.3s; }
  .lo-name { font-size: 13px; color: var(--text); font-weight: 500; max-width: 220px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .lo-sub { font-size: 10px; color: var(--text3); max-width: 220px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .lo-tags { display: flex; gap: 4px; flex-wrap: wrap; }
  .lo-mini {
    font-size: 10px; font-weight: 600; padding: 1px 6px; border-radius: 4px;
    color: var(--green); background: rgba(var(--green-rgb), 0.08); border: 1px solid rgba(var(--green-rgb), 0.25);
  }
  .lo-mini-tls { color: var(--accent); background: rgba(var(--accent-rgb), 0.08); border-color: rgba(var(--accent-rgb), 0.3); }
  .lo-mini-warn { color: var(--yellow); background: rgba(var(--yellow-rgb), 0.08); border-color: rgba(var(--yellow-rgb), 0.3); }
  .lo-loadcell { display: flex; align-items: center; gap: 8px; }
  .lo-ops { display: flex; align-items: center; justify-content: center; gap: 4px; }
  .lo-check-inline { display: flex; align-items: flex-start; gap: 8px; font-size: 12px; color: var(--text2); cursor: pointer; line-height: 1.6; }
  .lo-edit-readonly {
    font-size: 12px; color: var(--text2); background: var(--bg4);
    border: 1px solid var(--bd); border-radius: var(--radius);
    padding: 10px 12px; margin-bottom: 14px; line-height: 1.8;
  }
  /* 创建隧道：节点筛选条 + 节点卡片网格（样式对齐 MEFrp） */
  .lo-filters { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; margin-bottom: 12px; }
  .lo-fcheck { display: flex; align-items: center; gap: 5px; font-size: 12px; color: var(--text2); cursor: pointer; }
  .lo-fcount { margin-left: auto; font-size: 11px; color: var(--text3); font-family: var(--mono); }
  .lo-node-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 10px;
    max-height: 58vh;
    overflow-y: auto;
    padding: 2px;
  }
  .lo-node {
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
  .lo-node:hover { border-color: rgba(var(--accent-rgb), 0.5); }
  .lo-node-sel { border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent-glow); }
  .lo-node-hd { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
  .lo-node-name { font-size: 13px; font-weight: 600; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .lo-node-tags-hd { display: flex; gap: 4px; flex-shrink: 0; }
  .lo-tag { font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 4px; }
  .lo-tag-warn { background: rgba(var(--yellow-rgb), 0.08); color: var(--yellow); border: 1px solid rgba(var(--yellow-rgb), 0.35); }
  .lo-tag-load { background: rgba(var(--slate-rgb), 0.08); color: var(--text3); border: 1px solid rgba(var(--slate-rgb), 0.3); }
  .lo-node-tags { display: flex; gap: 4px; flex-wrap: wrap; }
  .lo-badge {
    font-size: 10px;
    font-weight: 600;
    padding: 1px 7px;
    border-radius: 4px;
    color: var(--green);
    background: rgba(var(--green-rgb), 0.08);
    border: 1px solid rgba(var(--green-rgb), 0.25);
  }
  .lo-badge-bw { color: var(--yellow); background: rgba(var(--yellow-rgb), 0.08); border-color: rgba(var(--yellow-rgb), 0.25); }
  .lo-badge-region { color: var(--accent); background: rgba(var(--accent-rgb), 0.08); border-color: rgba(var(--accent-rgb), 0.3); }
  .lo-node-desc {
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
  .lo-node-ft { display: flex; align-items: center; gap: 8px; }
  .lo-loadbar { flex: 1; height: 4px; border-radius: 2px; background: rgba(var(--slate-rgb), 0.25); overflow: hidden; }
  .lo-loadbar-in { height: 100%; border-radius: 2px; transition: width 0.3s; }
  .lo-loadtxt { font-size: 10px; color: var(--text3); font-family: var(--mono); white-space: nowrap; }
  .lo-picked { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 13px; color: var(--text); padding: 8px 12px; border: 1px solid var(--bd); border-radius: var(--radius); background: var(--bg4); }
  .lo-input-btn { display: flex; gap: 6px; align-items: stretch; }
  .lo-input-btn input { flex: 1; }
  .lo-input-btn .btn { white-space: nowrap; }

  /* 域名管理弹窗 */
  .lo-domain-add { display: flex; gap: 10px; align-items: flex-end; flex-wrap: wrap; margin-bottom: 14px; }
  .lo-domain-add .form-group { margin-bottom: 0; }
  .lo-domain-list { display: flex; flex-direction: column; gap: 10px; max-height: 56vh; overflow-y: auto; padding-right: 2px; }
  .lo-domain-item {
    border: 1px solid var(--bd); border-radius: var(--radius);
    background: var(--bg4); padding: 10px 12px; display: flex; flex-direction: column; gap: 6px;
  }
  .lo-domain-hd { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .lo-domain-name { font-size: 13px; font-weight: 600; color: var(--text); }
  /* 删除按钮置于标题行右侧 */
  .lo-domain-del { margin-left: auto; color: var(--red); white-space: nowrap; }
  .lo-domain-remark { font-size: 11px; color: var(--text3); }
  .lo-domain-meta { display: flex; gap: 14px; flex-wrap: wrap; font-size: 11px; color: var(--text3); }
  .lo-verify-box {
    border: 1px solid rgba(var(--yellow-rgb), 0.3); border-radius: var(--radius);
    background: rgba(var(--yellow-rgb), 0.06); padding: 10px 12px;
    display: flex; flex-direction: column; gap: 8px;
  }
  .lo-verify-rows { display: flex; flex-direction: column; gap: 6px; }
  .lo-verify-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 12px; }
  .lo-verify-row .lo-k { flex: 0 0 56px; }
  .lo-verify-row code {
    font-family: var(--mono); font-size: 11px; color: var(--text);
    background: var(--bg3); border: 1px solid var(--bd); border-radius: 4px;
    padding: 2px 6px; user-select: all; word-break: break-all;
  }
  .lo-verify-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
  @media (max-width: 640px) {
    .lo-domain-add .form-group { flex-basis: 100%; }
    /* 输入框+按钮组（本地端口）：窄屏放不下时按钮换行，输入框占满剩余宽度，不被压缩 */
    .lo-input-btn { flex-wrap: wrap; }
    .lo-input-btn input { flex: 1 1 120px; min-width: 0; }
    .lo-input-btn .btn { flex: 0 0 auto; }
  }
  .lo-nodes {
    border: 1px solid var(--bd); border-radius: var(--radius);
    background: var(--bg3); padding: 12px 16px; margin-bottom: 14px;
  }
  .lo-nodes summary { font-size: 13px; font-weight: 600; color: var(--text2); cursor: pointer; user-select: none; }
  .lo-nodes summary:hover { color: var(--accent); }
  .lo-nodes-body { padding-top: 12px; }
  .lo-log {
    font-family: var(--mono); font-size: 11px; line-height: 1.6; color: var(--text2);
    background: var(--bg4); border-radius: 6px; padding: 10px 12px;
    max-height: 320px; overflow: auto; white-space: pre-wrap; word-break: break-all; margin: 0;
  }
  @media (max-width: 640px) {
    .lo-user { grid-template-columns: 1fr; row-gap: 8px; }
    .lo-user-row { row-gap: 6px; }
    .lo-spacer { flex: 0; }
  }

  @media (max-width: 600px) {
    .lo-acct { gap: 10px; }
    .lo-acct-stats { margin-left: 0; gap: 14px 18px; width: 100%; }
    .lo-quota { width: 100%; }
    .list-card {
      background: var(--bg3);
      border-radius: calc(var(--radius) + 4px);
      box-shadow: var(--shadow-card);
      padding: 14px;
    }
    .list-card-title { font-size: 13.5px; }
  }
</style>
