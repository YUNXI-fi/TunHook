<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // STUN 页：本地端口打洞暴露到公网（尽力而为，底层 pion/stun）+ NAT 诊断。
  // 稳定公网入口 / 域名请使用「内网穿透」(frp)；本页为辅助，打洞成功率受 NAT 类型影响。
  import { onMount, onDestroy } from 'svelte';
  import Modal from '../components/Modal.svelte';
  import CustomSelect from '../components/CustomSelect.svelte';
  import Toggle from '../components/Toggle.svelte';
  import PortScanModal from '../components/PortScanModal.svelte';
  import ConfirmModal from '../components/ConfirmModal.svelte';
  import { api } from '../lib/api.js';
  import { toast, status } from '../lib/stores.js';
  import { fmtRate, fmtBytes, suggestProxyName, localHost, pollVisible, validateHost, validatePort, validateHostPort, optional, validateURL } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';

  // ---- STUN 探测（诊断）----
  let servers = [];
  let server = '';
  let probeLoading = false;
  let probeResult = null;
  let probeAbort = null;
  let showProbe = false;

  // ---- 打洞通道 ----
  let holes = [];
  let search = '';
  let timer = null;

  // 搜索过滤结果：桌面表格、移动端卡片与页脚统一使用，避免三处重复同一段过滤逻辑
  function matchesHole(h, q) {
    const s = (q || '').trim().toLowerCase();
    if (!s) return true;
    return (h.name || '').toLowerCase().includes(s)
      || (h.id || '').toLowerCase().includes(s)
      || (h.target || '').toLowerCase().includes(s)
      || (h.public || '').toLowerCase().includes(s)
      || (h.listen_addr || '').toLowerCase().includes(s)
      || String(h.listen_port || '').includes(s);
  }
  $: visibleHoles = holes.filter((h) => matchesHole(h, search));
  let showCreate = false;
  let editId = null; // 非 null 时创建弹窗变为编辑模式
  let busy = {};
  let form = { name: '', proto: 'tcp', targetHost: '', targetPort: '', listen_mode: 'ip', listen_ip: '', listen_iface: '', listen_port: 0, use_default_stun: true, stun_servers: '', webhook_mode: 'auto', webhook_trigger: 'addr_change', webhook_channel: '', webhook_group: '', webhook_url: '', webhook_method: 'POST', webhook_headers: '', webhook_body: '', webhook_callback: '', webhook_no_check: false, log_level: 'info', log_entries: 500 };
  let saving = false;
  let activePanel = 'basic'; // 创建/编辑弹窗标签页：basic / advanced / webhook / log
  let formEl;               // 弹窗表单容器，提交/切换标签时统一校验内部字段
  let delTarget = null;      // 待删除通道 {id, name}，非 null 时显示确认弹窗
  let delBusy = false;

  // ---- 端口扫描（选中端口回填到创建打洞弹窗的目标地址/目标端口）----
  let showPortScan = false;
  function openPortScan() {
    showPortScan = true;
  }
  function onPortPick(it) {
    showPortScan = false;
    openCreate(); // 先打开弹窗（重置表单），再回填选中的端口、地址与建议名称
    if (it && it.port) form.targetPort = String(it.port);
    if (it && it.local_addr && it.local_addr !== '0.0.0.0' && it.local_addr !== '::') form.targetHost = it.local_addr;
    const nm = suggestProxyName(it);
    form.name = nm || (it && it.port ? 'stun-' + it.port : '');
  }

  // ---- 进阶选项（按协议生效；rate_limit_on 仅前端 Toggle 状态，提交时折算 rate_limit_kb）----
  let adv = { rate_limit_on: false, rate_limit_kb: 1024, max_conns: 256, udp_timeout_ms: 30000, udp_max_sessions: 32, udp_block_size: 1500, max_failures: 30 };

  // ---- 监听通道（指定 IP / 指定网卡，radio 单选）----
  let ifaces = []; // 本机网卡列表（仅保留带 IPv4 的，打洞仅支持 IPv4）
  $: ifaceOptions = ifaces.map((i) => ({ value: i.name, label: `${i.name}（${i.ipv4}）` }));
  async function loadIfaces() {
    if (ifaces.length) return;
    try { ifaces = (await api('/api/network/interfaces') || []).filter((i) => i.ipv4); } catch (e) { /* 忽略，下拉显示空态 */ }
  }

  // ---- Webhook 联动（自动创建 / 选择已有 / 自定义回调）----
  let whChannels = []; // 已注册的 Webhook 通道列表（GET /api/wh/records）
  let whGroups = [];   // Webhook 分组列表（GET /api/wh/groups）
  let whLoaded = false; // 首次加载已完成（避免每次打开弹窗重复请求）
  $: whChannelOptions = [
    { value: '', label: i18nTr("不联动") },
    ...whChannels.map((c) => ({ value: c.channel_id, label: c.channel_id + (c.description ? ' · ' + c.description : '') }))
  ];
  $: whGroupOptions = whGroups.map((g) => ({ value: g.name, label: g.name }));
  const WEBHOOK_MODE_OPTIONS = [
    { value: 'auto', label: i18nTr("自动创建") },
    { value: 'select', label: i18nTr("选择已有") },
    { value: 'custom', label: i18nTr("自定义") }
  ];
  const WEBHOOK_TRIGGER_OPTIONS = [
    { value: 'addr_change', label: i18nTr("地址变化时") },
    { value: 'every_probe', label: i18nTr("每次打洞成功") },
    { value: 'first_time', label: i18nTr("仅首次获得地址") }
  ];
  const WEBHOOK_METHOD_OPTIONS = [
    { value: 'GET', label: 'GET' },
    { value: 'POST', label: 'POST' },
    { value: 'PUT', label: 'PUT' },
    { value: 'DELETE', label: 'DELETE' },
    { value: 'PATCH', label: 'PATCH' },
    { value: 'HEAD', label: 'HEAD' }
  ];
  const WH_BODY_SAMPLE = '{"event":"stun","public":"ip:port"}';
  async function loadWhChannels() {
    if (whLoaded) return;
    whLoaded = true;
    try {
      const [recs, groups] = await Promise.all([
        api('/api/wh/records').catch(() => ({})),
        api('/api/wh/groups').catch(() => ({}))
      ]);
      whChannels = (recs || {}).records || [];
      whGroups = (groups || {}).groups || [];
    } catch (e) { whLoaded = false; /* 失败允许下次重试 */ }
  }

  // ---- 通道日志弹窗 ----
  let showLog = false;
  let logId = '';
  let logName = '';
  let logRows = [];
  let logTimer = null;

  // ---- 通道统计详情弹窗（数据来自 holes 主轮询，随列表刷新实时更新）----
  let showStats = false;
  let statsId = '';
  $: statsHole = holes.find((x) => x.id === statsId) || null;

  function openStats(h) {
    statsId = h.id;
    showStats = true;
  }

  // ---- NAT 链路扫描 ----
  let chainLoading = false;
  let chainResult = null; // { chain: [{level,ip,type}], desc }

  // 下拉选项（CustomSelect）：探测服务器 / 协议 / 表单 STUN 服务器（含自定义值合并）
  // 协议仅 IPv4（后端固定 udp4 / tcp4 监听，仅 V4 打洞）
  const PROTO_OPTIONS = [{ value: 'tcp', label: 'IPv4-TCP' }, { value: 'udp', label: 'IPv4-UDP' }];
  const LOG_LEVEL_OPTIONS = [
    { value: 'debug', label: 'debug' },
    { value: 'info', label: 'info' },
    { value: 'warn', label: 'warn' },
    { value: 'error', label: 'error' }
  ];
  // NAT 行为探测走 UDP，TCP-only 服务器不放进探测下拉
  $: serverOptions = servers
    .filter((s) => (s.proto || 'udp') !== 'tcp')
    .map((s) => ({ value: s.addr, label: s.addr }));
  // 当前通道可用的默认服务器：按通道协议过滤（both 两边都可用）
  $: defaultServerLines = servers
    .filter((s) => {
      const p = s.proto || 'udp';
      return p === 'both' || p === form.proto;
    })
    .map((s) => s.addr);

  const BEHAVIOR_ZH = {
    'unknown': i18nTr("未知"),
    'endpoint independent': i18nTr("端点独立（无/锥形）"),
    'address dependent': i18nTr("地址相关"),
    'address and port dependent': i18nTr("地址与端口相关")
  };
  const PROBE_TIMEOUT = 15000;

  const STATUS_ZH = {
    running: { t: i18nTr("运行中"), cls: 'badge-on' },
    starting: { t: i18nTr("启动中"), cls: 'badge-info' },
    blocked: { t: i18nTr("受限"), cls: 'badge-warn' },
    error: { t: i18nTr("错误"), cls: 'badge-off' },
    off: { t: i18nTr("已停止"), cls: 'badge-off' }
  };

  async function runProbe() {
    if (probeLoading) return;
    probeLoading = true;
    probeResult = null;
    if (probeAbort) probeAbort.abort();
    const my = new AbortController();
    probeAbort = my;
    const t = setTimeout(() => { if (probeAbort === my) my.abort(); }, PROBE_TIMEOUT);
    try {
      probeResult = await api('/api/stun/probe?server=' + encodeURIComponent(server), { signal: my.signal });
      if (probeResult.error) toast(probeResult.error, 'info');
    } catch (e) {
      if (e && e.name === 'AbortError') toast(i18nTr("STUN 探测超时，请重试或更换服务器"), 'error');
      else toast(i18nTr("STUN 探测失败：") + e.message, 'error');
    } finally {
      clearTimeout(t);
      probeLoading = false;
    }
  }

  async function loadHoles() {
    try {
      holes = await api('/api/stunhole/list') || [];
    } catch (e) { /* ignore */ }
  }

  function openCreate() {
    editId = null;
    activePanel = 'basic';
    form = { name: '', proto: 'tcp', targetHost: '', targetPort: '', listen_mode: 'ip', listen_ip: '', listen_iface: '', listen_port: 0, use_default_stun: true, stun_servers: '', webhook_mode: 'auto', webhook_trigger: 'addr_change', webhook_channel: '', webhook_group: '', webhook_url: '', webhook_method: 'POST', webhook_headers: '', webhook_body: '', webhook_callback: '', webhook_no_check: false, log_level: 'info', log_entries: 500 };
    adv = { rate_limit_on: false, rate_limit_kb: 1024, max_conns: 256, udp_timeout_ms: 30000, udp_max_sessions: 32, udp_block_size: 1500, max_failures: 30 };
    showCreate = true;
    // 刷新默认服务器列表，确保“使用默认服务器”展示的是最新设置
    api('/api/stun/servers').then((d) => { servers = d || []; }).catch(() => {});
    loadIfaces();
    loadWhChannels();
  }

  // 编辑通道：复用创建弹窗，预填当前配置
  function openEdit(h) {
    editId = h.id;
    activePanel = 'basic';
    const t = (h.target || '').split(':');
    form = {
      name: h.name || '',
      proto: h.proto || 'tcp',
      targetHost: t.slice(0, -1).join(':'),
      targetPort: t.length > 1 ? t[t.length - 1] : '',
      listen_mode: h.listen_iface ? 'iface' : 'ip',
      listen_ip: h.listen_ip || '',
      listen_iface: h.listen_iface || '',
      listen_port: h.listen_port || 0,
      use_default_stun: h.use_default_stun !== false,
      stun_servers: (h.stun_servers || []).join('\n'),
      webhook_mode: h.webhook_mode || 'select',
      webhook_trigger: h.webhook_trigger || 'addr_change',
      webhook_channel: h.webhook_channel || '',
      webhook_group: h.webhook_group || '',
      webhook_url: h.webhook_url || '',
      webhook_method: h.webhook_method || 'POST',
      webhook_headers: h.webhook_headers || '',
      webhook_body: h.webhook_body || '',
      webhook_callback: h.webhook_callback || '',
      webhook_no_check: !!h.webhook_no_check,
      log_level: h.log_level || 'info',
      log_entries: h.log_entries || 500
    };
    adv = {
      rate_limit_on: (h.rate_limit_kb || 0) > 0,
      rate_limit_kb: h.rate_limit_kb > 0 ? h.rate_limit_kb : 1024,
      max_conns: h.max_conns || 0,
      udp_timeout_ms: h.udp_timeout_ms || 30000,
      udp_max_sessions: h.udp_max_sessions || 0,
      udp_block_size: h.udp_block_size || 1500,
      max_failures: h.max_failures || 30
    };
    showCreate = true;
    api('/api/stun/servers').then((d) => { servers = d || []; }).catch(() => {});
    loadIfaces();
    loadWhChannels();
  }

  // 启用/停用按钮：按运行状态着色（全站统一规则，与「代理列表」「端口转发」一致）
  //   运行中=绿 / 启动中、公网受限=黄（过渡或受限态）/ 启动失败=红 / 未运行=灰
  // 灰是「没开」，红是「开了但起不来」，两者必须一眼可分；具体原因仍由 title 区分
  function stateColor(h) {
    if (h.status === 'error') return 'var(--red)';
    if (!h.running) return 'var(--text3)';
    if (h.status === 'starting' || h.status === 'blocked') return 'var(--yellow)';
    return 'var(--green)';
  }
  function stateTitle(h) {
    if (busy[h.id]) return i18nTr("操作中…");
    if (!h.running) return h.status === 'error' ? i18nTr("启动失败（点击重试）") : i18nTr("启动");
    if (h.status === 'starting') return i18nTr("启动中…（点击停止）");
    if (h.status === 'blocked') return i18nTr("公网受限（点击停止）");
    return i18nTr("停止");
  }

  // NAT 链路扫描（traceroute 逐跳识别内网/CGN/公网）
  async function scanChain() {
    if (chainLoading) return;
    chainLoading = true;
    chainResult = null;
    try {
      chainResult = await api('/api/stun/natchain');
    } catch (e) {
      toast(i18nTr("NAT 链路扫描失败：") + e.message, 'error');
    } finally {
      chainLoading = false;
    }
  }

  // 切换标签前先校验当前标签内字段，防止错误值藏到其他标签后被直接提交
  function switchPanel(p) {
    if (validateAll(formEl)) activePanel = p;
  }

  async function submitCreate() {
    // 格式校验：当前标签内的地址/端口/URL 字段统一拦截并就地提示
    if (!validateAll(formEl)) return;
    const host = (form.targetHost || '').trim();
    const port = parseInt(form.targetPort, 10);
    if (!host) { toast(i18nTr("请填写目标地址"), 'error'); return; }
    if (!port || port < 1 || port > 65535) { toast(i18nTr("请填写目标端口"), 'error'); return; }
    const listenIP = (form.listen_ip || '').trim();
    if (form.listen_mode === 'ip' && listenIP && !/^\d{1,3}(\.\d{1,3}){3}$/.test(listenIP)) {
      toast(i18nTr("监听地址不是有效的 IPv4"), 'error'); return;
    }
    if (form.listen_mode === 'iface' && !form.listen_iface) { toast(i18nTr("请选择监听网卡"), 'error'); return; }
    // 监听端口：空/0 = 系统自动分配空闲高位端口（编辑时 0 = 保持不变）
    let listenPort = parseInt(form.listen_port, 10) || 0;
    if (listenPort < 0 || listenPort > 65535) { toast(i18nTr("监听端口无效（0-65535）"), 'error'); return; }
    // Webhook 联动：auto=自动创建（选分组）/ select=选择已有 / custom=自定义回调接口
    const whMode = form.webhook_mode || 'select';
    const whChannel = (form.webhook_channel || '').trim();
    const whURL = (form.webhook_url || '').trim();
    if (whMode === 'custom' && whURL && !/^https?:\/\//.test(whURL)) {
      toast(i18nTr("回调接口地址需为 http(s) 地址"), 'error'); return;
    }
    if (whMode === 'select' && whChannel && !/^[a-z0-9][a-z0-9-]{0,31}$/.test(whChannel)) {
      toast(i18nTr("所选 Webhook 通道无效"), 'error'); return;
    }
    // 日志存储条数：100-10000
    const logEntries = parseInt(form.log_entries, 10) || 500;
    if (logEntries < 100 || logEntries > 10000) { toast(i18nTr("日志存储条数需在 100-10000 之间"), 'error'); return; }
    // 进阶选项：限速开启时取输入值（KB/s），关闭时 0=不限；TCP/UDP 按协议各自生效
    const maxFailures = parseInt(adv.max_failures, 10) || 0;
    if (maxFailures < 1 || maxFailures > 1000) { toast(i18nTr("最大失败次数需在 1-1000 之间（默认 30）"), 'error'); return; }
    // 通道自定义 STUN 服务器：关闭“使用默认服务器”时至少一行，且每行必须是 host:port
    const customServers = (form.stun_servers || '').split('\n').map((s) => s.trim()).filter(Boolean);
    if (!form.use_default_stun) {
      if (!customServers.length) { toast(i18nTr("请至少填写一个 STUN 服务器地址"), 'error'); return; }
      for (const s of customServers) {
        const err = validateHostPort(s);
        if (err) { toast(i18nTr("STUN 服务器 {0} 格式错误：{1}", [s, err]), 'error'); return; }
      }
    }
    const advBody = {
      rate_limit_kb: form.proto === 'tcp' && adv.rate_limit_on ? (parseInt(adv.rate_limit_kb, 10) || 0) : 0,
      max_conns: form.proto === 'tcp' ? (parseInt(adv.max_conns, 10) || 0) : 0,
      udp_timeout_ms: form.proto === 'udp' ? (parseInt(adv.udp_timeout_ms, 10) || 0) : 0,
      udp_max_sessions: form.proto === 'udp' ? (parseInt(adv.udp_max_sessions, 10) || 0) : 0,
      udp_block_size: form.proto === 'udp' ? (parseInt(adv.udp_block_size, 10) || 0) : 0,
      max_failures: maxFailures
    };
    if (advBody.rate_limit_kb < 0) { toast(i18nTr("限速值无效"), 'error'); return; }
    saving = true;
    const my = new AbortController();
    const timer2 = setTimeout(() => my.abort(), 15000);
    const listenBody = {
      listen_ip: form.listen_mode === 'ip' ? listenIP : '',
      listen_iface: form.listen_mode === 'iface' ? form.listen_iface : '',
      listen_port: listenPort,
      use_default_stun: !!form.use_default_stun,
      stun_servers: form.use_default_stun ? [] : customServers,
      webhook_mode: whMode,
      webhook_trigger: form.webhook_trigger || 'addr_change',
      webhook_channel: whMode === 'select' ? whChannel : '',
      webhook_group: whMode === 'auto' ? (form.webhook_group || '').trim() : '',
      webhook_url: whMode === 'custom' ? whURL : '',
      webhook_method: whMode === 'custom' ? (form.webhook_method || 'POST') : '',
      webhook_headers: whMode === 'custom' ? (form.webhook_headers || '').trim() : '',
      webhook_body: whMode === 'custom' ? (form.webhook_body || '') : '',
      webhook_callback: whMode === 'custom' ? (form.webhook_callback || '').trim() : '',
      webhook_no_check: whMode === 'custom' ? !!form.webhook_no_check : false,
      log_level: form.log_level || 'info',
      log_entries: logEntries,
      ...advBody
    };
    try {
      if (editId) {
        await api('/api/stunhole/' + encodeURIComponent(editId) + '/update', { method: 'POST', body: {
          name: form.name, proto: form.proto, target: host + ':' + port, ...listenBody
        }, signal: my.signal });
        toast(i18nTr("已保存，配置生效"), 'success');
      } else {
        await api('/api/stunhole/create', { method: 'POST', body: {
          name: form.name, proto: form.proto,
          target: host + ':' + port, ...listenBody // STUN 服务器由系统按通道协议自动选择，失败自动轮换
        }, signal: my.signal });
        toast(i18nTr("打洞通道已创建"), 'success');
      }
      showCreate = false;
      editId = null;
      loadHoles();
    } catch (e) {
      if (e && e.name === 'AbortError') toast(editId ? i18nTr("保存超时，请重试") : i18nTr("创建超时，请重试"), 'error');
      else toast((editId ? i18nTr("保存失败：") : i18nTr("创建失败：")) + e.message, 'error');
    } finally {
      clearTimeout(timer2);
      saving = false;
    }
  }

  // 打开通道日志弹窗并轮询最新日志
  function openLog(h) {
    logId = h.id;
    logName = h.name || h.id;
    logRows = [];
    showLog = true;
    loadLogs();
    if (logTimer) logTimer();
    logTimer = pollVisible(loadLogs, 3000);
  }
  async function loadLogs() {
    if (!logId) return;
    try {
      logRows = await api('/api/stunhole/' + encodeURIComponent(logId) + '/logs') || [];
    } catch (e) { /* 弹窗轮询失败静默 */ }
  }
  function fmtLogTs(ts) {
    const d = new Date(ts * 1000);
    if (isNaN(d.getTime())) return '-';
    const p = (x) => String(x).padStart(2, '0');
    return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  async function toggle(h) {
    if (busy[h.id]) return;
    busy = { ...busy, [h.id]: true };
    const op = h.running ? 'stop' : 'start';
    try {
      await api('/api/stunhole/' + encodeURIComponent(h.id) + '/' + op, { method: 'POST' });
    } catch (e) {
      toast((op === 'start' ? i18nTr("启动") : i18nTr("停止")) + i18nTr("失败：") + e.message, 'error');
    } finally {
      busy = { ...busy, [h.id]: false };
      loadHoles();
    }
  }

  function openDelete(h) {
    // 两段式删除：仅打开确认弹窗，真正的删除请求只在 confirmDelete 中发起（防误删）
    delTarget = { id: h.id, name: h.name || h.id };
  }

  async function confirmDelete() {
    delBusy = true;
    try {
      await api('/api/stunhole/' + encodeURIComponent(delTarget.id), { method: 'DELETE' });
      toast(i18nTr("打洞通道已删除: ") + delTarget.name, 'success');
      delTarget = null;
      loadHoles();
    } catch (e) {
      toast(i18nTr("删除失败：") + e.message, 'error');
    } finally {
      delBusy = false;
    }
  }

  // 目标地址（host:port）-> 可直达的 http 地址；回环/空主机替换为局域网 IP，文本仍显示原值
  function targetWebUrl(t) {
    const s = String(t || '');
    const i = s.lastIndexOf(':');
    const host = i >= 0 ? s.slice(0, i) : s;
    const port = i >= 0 ? s.slice(i + 1) : '';
    return 'http://' + localHost(host, ($status && $status.local_ip) || '') + (port ? ':' + port : '');
  }

  onMount(async () => {
    try {
      servers = await api('/api/stun/servers') || [];
      const probeSrv = servers.find((s) => (s.proto || 'udp') !== 'tcp');
      if (probeSrv) server = probeSrv.addr;
    } catch (e) { /* ignore */ }
    loadHoles();
    timer = pollVisible(loadHoles, 5000);
  });
  onDestroy(() => {
    if (timer) timer();
    if (logTimer) logTimer();
  });
</script>

<div class="container page-full page-list">
  <div class="page-hdr">
    <div>
      <h2>{$i18n("STUN 打洞")}</h2>
      <span class="page-hdr-sub">{$i18n("本地端口经 STUN 打洞暴露到公网（尽力而为）· 底层 pion/stun")}</span>
    </div>
    <div class="page-hdr-actions">
      <div class="hdr-search-wrap">
        <svg class="hdr-search-icon" width="15" height="15" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M21 38C30.3888 38 38 30.3888 38 21C38 11.6112 30.3888 4 21 4C11.6112 4 4 11.6112 4 21C4 30.3888 11.6112 38 21 38Z"/><path d="M33.2216 33.2217L41.7069 41.707" stroke-linecap="round"/></svg>
        <input type="text" class="hdr-search" bind:value={search} placeholder={$i18n("搜索名称 / 目标 / 公网地址")} />
      </div>
      <div class="hdr-btn-group">
        <button class="btn" title={$i18n("STUN 探测")} on:click={() => (showProbe = true)}>
          <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="34" width="8" height="8"/><rect x="8" y="6" width="32" height="12"/><path d="M24 34V18"/><path d="M8 34V26H40V34"/><rect x="36" y="34" width="8" height="8"/><rect x="20" y="34" width="8" height="8"/><path d="M14 12H16"/></svg>
          <span class="sm-hide">{$i18n("STUN 探测")}</span>
        </button>
        <button class="btn" title={$i18n("扫描端口")} on:click={openPortScan}>
          <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="24" r="18"/><circle cx="24" cy="24" r="10"/><path d="M24 24L35 13"/><circle cx="24" cy="24" r="3" fill="currentColor" stroke="none"/><circle cx="32" cy="15" r="2.5" fill="currentColor" stroke="none"/></svg>
          <span class="sm-hide">{$i18n("扫描端口")}</span>
        </button>
        <button class="btn btn-primary" title={$i18n("创建打洞")} on:click={openCreate}>
          <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="24" r="20"/><path d="M24 16V32"/><path d="M16 24H32"/></svg>
          <span class="sm-hide">{$i18n("创建打洞")}</span>
        </button>
      </div>
    </div>
  </div>

  <!-- NAT 环境：近一次探测结果（未探测时保持占位，不伪造数据） -->
  <div class="st-card">
    <div class="st-card-hd">
      <span class="st-card-title">{$i18n("NAT 环境")}</span>
      <span class="st-card-sub">{probeResult ? i18nTr("最近一次探测结果") : i18nTr("尚未探测")}</span>
      <span class="st-card-right">
        <button class="btn btn-sm" on:click={() => (showProbe = true)}>{$i18n("STUN 探测")}</button>
      </span>
    </div>
    <div class="st-grid">
      <div class="st-cell">
        <span>{$i18n("公网映射")}</span>
        <b style="color:{probeResult ? 'var(--accent)' : 'var(--text3)'}">{probeResult && probeResult.public_ip ? `${probeResult.public_ip}:${probeResult.public_port}` : '—'}</b>
      </div>
      <div class="st-cell">
        <span>{$i18n("映射行为")}</span>
        <b style="color:{probeResult ? (probeResult.mapping_behavior === 'unknown' ? 'var(--text3)' : 'var(--text)') : 'var(--text3)'}">{probeResult ? (BEHAVIOR_ZH[probeResult.mapping_behavior] || probeResult.mapping_behavior) : '—'}</b>
      </div>
      <div class="st-cell">
        <span>{$i18n("过滤行为")}</span>
        <b style="color:{probeResult ? (probeResult.filtering_behavior === 'unknown' ? 'var(--text3)' : 'var(--text)') : 'var(--text3)'}">{probeResult ? (BEHAVIOR_ZH[probeResult.filtering_behavior] || probeResult.filtering_behavior) : '—'}</b>
      </div>
      <div class="st-cell">
        <span>{$i18n("CGNAT / 私有映射")}</span>
        <b style="color:{probeResult ? (probeResult.is_cgnat ? 'var(--red)' : 'var(--green)') : 'var(--text3)'}">{probeResult ? (probeResult.is_cgnat ? i18nTr("是") : i18nTr("否")) : '—'}</b>
      </div>
    </div>
  </div>

  <div class="table-wrap" class:st-empty={visibleHoles.length === 0}>
    <div style="overflow-y:auto;flex:1">
    <table>
      <thead>
        <tr>
          <th>{$i18n("名称")}</th>
          <th style="width:180px">{$i18n("监听地址")}</th>
          <th style="width:180px">{$i18n("目标地址")}</th>
          <th style="width:80px">{$i18n("协议")}</th>
          <th style="width:210px">{$i18n("公网映射")}</th>
          <th style="width:150px">{$i18n("实时速率")}</th>
          <th style="width:150px">{$i18n("状态")}</th>
          <th style="width:190px">{$i18n("操作")}</th>
        </tr>
      </thead>
      <tbody>
        {#each visibleHoles as h (h.id)}
          <tr>
            <td>
              <span class="st-name">
                <span class="st-dot" style="background:{stateColor(h)}"></span>
                <span class="cell-mono" style="color:var(--accent);font-size:11px">{h.name || h.id}</span>
              </span>
            </td>
            <td class="cell-mono">{h.listen_addr || ($status && $status.local_ip) || '0.0.0.0'}:{h.listen_port}</td>
            <td class="cell-mono">
              {#if h.target}
                <a class="cell-link cell-link-btn" href={targetWebUrl(h.target)} target="_blank" rel="noopener noreferrer" title={$i18n("点击新页面打开 {0}", [targetWebUrl(h.target)])}>{h.target}</a>
              {:else}
                <span class="cell-dim">-</span>
              {/if}
            </td>
            <td><span class="badge" class:badge-blue={h.proto === 'tcp'} class:badge-warn={h.proto === 'udp'}>{h.proto.toUpperCase()}</span></td>
            <td class="cell-mono">
              {#if h.public}
                <a class="cell-link cell-link-btn" href={'http://' + h.public} target="_blank" rel="noopener noreferrer" title={$i18n("点击新页面打开 http://{0}", [h.public])}>{h.public}</a>
              {:else}
                <span class="cell-dim">-</span>
              {/if}
            </td>
            <td>
              {#if h.running}
                <button type="button" class="cell-link-btn" style="display:flex;align-items:center;justify-content:center;gap:8px;font-size:11px" title={$i18n("点击查看流量统计详情")} on:click={() => openStats(h)}>
                  <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">↑</span><span style="color:var(--text2)">{fmtRate((h.rate && h.rate.tx) || 0)}</span></span>
                  <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">↓</span><span style="color:var(--text2)">{fmtRate((h.rate && h.rate.rx) || 0)}</span></span>
                  <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">⇄</span><span style="color:var(--text2)">{h.conns || 0} {$i18n("连接")}</span></span>
                </button>
              {:else}
                <span class="cell-dim">-</span>
              {/if}
            </td>
            <td>
              <span class="badge {(STATUS_ZH[h.status] || STATUS_ZH.off).cls}">{(STATUS_ZH[h.status] || STATUS_ZH.off).t}</span>
              {#if h.last_error}
                <div class="cell-dim" style="font-size:11px;margin-top:3px" title={h.last_error}>{h.last_error}</div>
              {/if}
            </td>
            <td>
              <div class="cell-actions">
                <button class="btn-icon" title={stateTitle(h)} aria-label={stateTitle(h)} on:click={() => toggle(h)}>
                  {#if busy[h.id]}<span class="spinner" style="width:14px;height:14px"></span>{:else}<svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke={stateColor(h)} stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M24 4V24" stroke={stateColor(h)} stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>{/if}
                </button>
                <button class="btn-icon" title={$i18n("通道日志")} aria-label={$i18n("查看通道日志")} on:click={() => openLog(h)}>
                  <svg width="15" height="15" viewBox="0 0 48 48" fill="none"><rect x="13" y="10" width="28" height="34" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M35 10V4H8C7.44772 4 7 4.44772 7 5V38H13" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 22H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 30H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>
                <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑")} on:click={() => openEdit(h)}>
                  <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M10 44H38C39.1046 44 40 43.1046 40 42V14H30V4H10C8.89543 4 8 4.89543 8 6V42C8 43.1046 8.89543 44 10 44Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M30 4L40 14" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 35L31 25L27 21L17 31V35H21Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>
                <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => openDelete(h)}>
                  <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>
              </div>
            </td>
          </tr>
        {:else}
          <tr>
            <td colspan="8"><div class="empty"><div class="empty-t">{$i18n("暂无打洞通道，点击「创建打洞」将本机端口暴露到公网")}</div></div></td>
          </tr>
        {/each}
      </tbody>
    </table>
    <div class="st-table-foot">
      <span>{$i18n("共")} {visibleHoles.length} {$i18n("条 ·")} <span style="color:var(--green)">{visibleHoles.filter((h) => h.running).length} {$i18n("条运行中")}</span></span>
      {#if server}<span class="st-foot-meta">{$i18n("STUN 服务器：")}{server}</span>{/if}
    </div>
    </div>
  </div>

  <div class="list-cards">
    {#if visibleHoles.length}
      <div class="st-mobile-summary">{$i18n("共")} {visibleHoles.length} {$i18n("条 ·")} {visibleHoles.filter((h) => h.running).length} {$i18n("条运行中")}</div>
    {/if}
    {#if visibleHoles.length === 0}
      <div class="list-cards-empty">{$i18n("暂无打洞通道，点击「创建打洞」将本机端口暴露到公网")}</div>
    {/if}
    {#each visibleHoles as h (h.id)}
      <div class="list-card" on:click={() => openEdit(h)}>
        <div class="list-card-top">
          <span class="st-dot" style="background:{stateColor(h)}"></span>
          <div class="list-card-title">{h.name || h.id}</div>
          <span class="badge" class:badge-blue={h.proto === 'tcp'} class:badge-warn={h.proto === 'udp'}>{h.proto.toUpperCase()}</span>
          <span class="badge {(STATUS_ZH[h.status] || STATUS_ZH.off).cls}" style="margin-left:auto;flex-shrink:0">{(STATUS_ZH[h.status] || STATUS_ZH.off).t}</span>
        </div>
        <div class="list-card-sub st-meta-line" on:click={(e) => e.stopPropagation()}>
          <span class="cell-mono ellip">{h.listen_addr || ($status && $status.local_ip) || '0.0.0.0'}:{h.listen_port}</span>
          <span class="st-arrow">→</span>
          {#if h.target}
            <a class="cell-link cell-link-btn cell-mono ellip" href={targetWebUrl(h.target)} target="_blank" rel="noopener noreferrer" title={$i18n("点击新页面打开 {0}", [targetWebUrl(h.target)])}>{h.target}</a>
          {:else}
            <span class="cell-dim">-</span>
          {/if}
        </div>
        {#if h.last_error}
          <div class="st-card-error" title={h.last_error}>{h.last_error}</div>
        {/if}
        <div class="list-card-rows" on:click={(e) => e.stopPropagation()}>
          <div class="list-card-row">
            <span class="k">{$i18n("公网映射")}</span>
            <span class="v">
              {#if h.public}
                <a class="cell-link cell-link-btn ellip" href={'http://' + h.public} target="_blank" rel="noopener noreferrer" title={$i18n("点击新页面打开 http://{0}", [h.public])}>{h.public}</a>
              {:else}
                <span class="cell-dim">-</span>
              {/if}
            </span>
          </div>
          {#if h.running}
            <div class="list-card-row">
              <span class="k">{$i18n("实时速率")}</span>
              <span class="v">
                <button type="button" class="cell-link-btn" style="display:flex;align-items:center;justify-content:center;gap:8px;font-size:11px" title={$i18n("点击查看流量统计详情")} on:click={(e) => { e.stopPropagation(); openStats(h); }}>
                  <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">↑</span><span style="color:var(--text2)">{fmtRate((h.rate && h.rate.tx) || 0)}</span></span>
                  <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">↓</span><span style="color:var(--text2)">{fmtRate((h.rate && h.rate.rx) || 0)}</span></span>
                  <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">⇄</span><span style="color:var(--text2)">{h.conns || 0} {$i18n("连接")}</span></span>
                </button>
              </span>
            </div>
          {/if}
        </div>
        <div class="list-card-actions" on:click={(e) => e.stopPropagation()}>
          <span class="st-foot-note">pion/stun</span>
          <button class="btn-icon" title={stateTitle(h)} aria-label={stateTitle(h)} on:click={() => toggle(h)}>
            {#if busy[h.id]}<span class="spinner" style="width:14px;height:14px"></span>{:else}<svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke={stateColor(h)} stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M24 4V24" stroke={stateColor(h)} stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>{/if}
          </button>
          <button class="btn-icon" title={$i18n("通道日志")} aria-label={$i18n("查看通道日志")} on:click={() => openLog(h)}>
            <svg width="15" height="15" viewBox="0 0 48 48" fill="none"><rect x="13" y="10" width="28" height="34" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M35 10V4H8C7.44772 4 7 4.44772 7 5V38H13" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 22H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 30H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </button>
          <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑")} on:click={() => openEdit(h)}>
            <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M10 44H38C39.1046 44 40 43.1046 40 42V14H30V4H10C8.89543 4 8 4.89543 8 6V42C8 43.1046 8.89543 44 10 44Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M30 4L40 14" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 35L31 25L27 21L17 31V35H21Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </button>
          <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => openDelete(h)}>
            <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </button>
        </div>
      </div>
    {/each}
  </div>
</div>

{#if showProbe}
  <Modal title={$i18n("STUN 探测")} onClose={() => (showProbe = false)} width={720}>
    <div class="probe-controls" style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
      <CustomSelect bind:value={server} options={serverOptions} width="320px" />
      {#if !probeLoading}<button class="btn" on:click={runProbe}>{$i18n("开始探测")}</button>{:else}<button class="btn scanning-btn" title={$i18n("探测中")}><span class="spinner"></span>{$i18n("探测中")}</button>{/if}
      <button class="btn" disabled={chainLoading} title={chainLoading ? i18nTr("扫描中") : i18nTr("逐跳识别内网 / CGNAT / 公网层级")} on:click={scanChain}>
        {#if chainLoading}<span class="spinner"></span>{$i18n("扫描中")}{:else}{chainResult ? i18nTr("重新扫描") : i18nTr("扫描 NAT 链路")}{/if}
      </button>
    </div>
    {#if probeLoading}
      <div style="text-align:center;padding:30px 0;color:var(--text3);font-size:13px">{$i18n("正在通过 STUN 服务器探测 NAT 行为，最长约 5 秒…")}</div>
    {:else if probeResult}
      <div style="margin-bottom:14px">
        <div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:10px">
          <div class="stat-card" style="grid-column:1/-1;padding:12px">
            <div class="stat-num">{probeResult.public_ip}:{probeResult.public_port}</div>
            <div class="stat-label">{$i18n("公网映射地址")}</div>
          </div>
          <div class="stat-card">
            <div class="stat-num" style="font-size:13px;color:{probeResult.mapping_behavior === 'unknown' ? 'var(--text3)' : 'var(--text)'}">{BEHAVIOR_ZH[probeResult.mapping_behavior] || probeResult.mapping_behavior}</div>
            <div class="stat-label">{$i18n("映射行为")}</div>
          </div>
          <div class="stat-card">
            <div class="stat-num" style="font-size:13px;color:{probeResult.filtering_behavior === 'unknown' ? 'var(--text3)' : 'var(--text)'}">{BEHAVIOR_ZH[probeResult.filtering_behavior] || probeResult.filtering_behavior}</div>
            <div class="stat-label">{$i18n("过滤行为")}</div>
          </div>
          <div class="stat-card">
            <div class="stat-num" style="font-size:13px;color:{probeResult.is_cgnat ? 'var(--red)' : 'var(--green)'}">{probeResult.is_cgnat ? i18nTr("是") : i18nTr("否")}</div>
            <div class="stat-label">{$i18n("CGNAT / 私有映射")}</div>
          </div>
          <div class="stat-card">
            <div class="stat-num" style="font-size:13px;color:{probeResult.direct_ok ? 'var(--green)' : 'var(--yellow)'}">{probeResult.direct_ok ? i18nTr("可行") : i18nTr("受限")}</div>
            <div class="stat-label">{$i18n("公网直连")}</div>
          </div>
        </div>
      </div>
    {:else}
      <div style="text-align:center;padding:30px 0;color:var(--text3);font-size:13px">{$i18n("选择服务器后点击「开始探测」。")}</div>
    {/if}

    <div>
      {#if chainLoading}
        <div style="text-align:center;padding:30px 0;color:var(--text3);font-size:13px">{$i18n("正在逐跳追踪到公网的 NAT 链路，最长约 15 秒…")}</div>
      {:else if chainResult}
        {#if (chainResult.chain || []).length}
          <div class="dns-table-wrap">
            <table class="dns-table">
              <thead><tr><th>{$i18n("层级")}</th><th>IP</th><th>{$i18n("类型")}</th></tr></thead>
              <tbody>
                {#each chainResult.chain as h (h.level)}
                  <tr>
                    <td>{$i18n("第 {0} 层", [h.level])}</td>
                    <td class="cell-mono">{h.ip}</td>
                    <td><span class="badge {h.type === 'cgn' ? 'badge-warn' : h.type === 'public' ? 'badge-on' : 'badge-off'}">{h.type === 'cgn' ? i18nTr("运营商 CGNAT") : h.type === 'public' ? i18nTr("公网出口") : h.type === 'hidden' ? i18nTr("不响应") : i18nTr("内网")}</span></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      {/if}
    </div>
  </Modal>
{/if}

{#if showCreate}
  <Modal title={editId ? i18nTr("编辑打洞通道") : i18nTr("创建打洞通道")} onClose={() => { showCreate = false; editId = null; }} width={560}>
    <div class="tunnel-tabs">
      <button type="button" class="tunnel-tab" class:active={activePanel === 'basic'} on:click={() => switchPanel('basic')}>{$i18n("基础设置")}</button>
      <button type="button" class="tunnel-tab" class:active={activePanel === 'advanced'} on:click={() => switchPanel('advanced')}>{$i18n("进阶选项")}</button>
      <button type="button" class="tunnel-tab" class:active={activePanel === 'webhook'} on:click={() => switchPanel('webhook')}>Webhook</button>
      <button type="button" class="tunnel-tab" class:active={activePanel === 'log'} on:click={() => switchPanel('log')}>{$i18n("日志设置")}</button>
    </div>

    <div bind:this={formEl}>
    {#if activePanel === 'basic'}
      <div class="form-row">
        <div class="form-group" style="flex:1;min-width:220px">
          <label class="form-label">{$i18n("名称")}</label>
          <input type="text" bind:value={form.name} placeholder={$i18n("如 stun-webhook")} />
        </div>
        <div class="form-group" style="min-width:120px">
          <label class="form-label">{$i18n("协议")}</label>
          <CustomSelect bind:value={form.proto} options={PROTO_OPTIONS} />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group" style="flex:1;min-width:180px">
          <label class="form-label">{$i18n("目标地址")}</label>
          <input type="text" bind:value={form.targetHost} placeholder={$i18n("如 127.0.0.1")} use:field={{ check: validateHost }} />
        </div>
        <div class="form-group" style="min-width:130px">
          <label class="form-label">{$i18n("目标端口")}</label>
          <input type="number" bind:value={form.targetPort} placeholder={$i18n("如 8080")} min="1" max="65535" use:field={{ check: validatePort }} />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group" style="min-width:150px">
          <label class="form-label">{$i18n("监听通道")}</label>
          <div class="listen-mode-switch" role="radiogroup" aria-label={$i18n("监听通道")}>
            <span class="listen-mode-thumb" class:right={form.listen_mode === 'iface'}></span>
            <button
              type="button"
              class="listen-mode-btn"
              class:active={form.listen_mode === 'ip'}
              role="radio"
              aria-checked={form.listen_mode === 'ip'}
              on:click={() => (form.listen_mode = 'ip')}
            >{$i18n("指定IP")}</button>
            <button
              type="button"
              class="listen-mode-btn"
              class:active={form.listen_mode === 'iface'}
              role="radio"
              aria-checked={form.listen_mode === 'iface'}
              on:click={() => (form.listen_mode = 'iface')}
            >{$i18n("指定网卡")}</button>
          </div>
        </div>
        <div class="form-group" style="flex:1;min-width:200px">
          {#if form.listen_mode === 'ip'}
            <label class="form-label">{$i18n("监听地址")}</label>
            <input type="text" bind:value={form.listen_ip} placeholder={$i18n("留空默认本机局域网 IPv4")} use:field={{ check: optional(validateHost) }} />
          {:else}
            <label class="form-label">{$i18n("网卡")}</label>
            {#if ifaceOptions.length}
              <CustomSelect bind:value={form.listen_iface} options={ifaceOptions} />
            {:else}
              <input type="text" value="未发现带 IPv4 的网卡" disabled />
            {/if}
          {/if}
        </div>
        <div class="form-group" style="min-width:130px">
          <label class="form-label">{$i18n("监听端口")}</label>
          <input type="number" bind:value={form.listen_port} placeholder={$i18n("0 = 自动")} min="0" max="65535" use:field={{ check: (v) => validatePort(v, true) }} />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group" style="min-width:160px">
          <label class="form-label">{$i18n("最大失败次数")}</label>
          <input type="number" bind:value={adv.max_failures} min="1" max="1000" placeholder={$i18n("默认 30")} />
        </div>
      </div>
      <div class="tip-text">{$i18n("STUN 服务器自动轮换，连续打洞失败达到此次数后通道自动停止（默认 30，范围 1-1000）；收到一次有效响应即重新计数。")}</div>
    {:else if activePanel === 'advanced'}
      {#if form.proto === 'tcp'}
        <!-- TCP 进阶选项（限速 / 最大连接数真实生效；TLS / ProxyProtocol / 流加密在打洞裸转发场景不适用） -->
        <div style="display:flex;flex-direction:column;gap:14px">
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">{$i18n("单端口限速")}</label>
              <div style="display:flex;align-items:center;gap:12px;height:38px">
                <Toggle bind:checked={adv.rate_limit_on} />
                <span style="font-size:13px;color:var(--text3)">{adv.rate_limit_on ? i18nTr("开启") : i18nTr("关闭")}</span>
                {#if adv.rate_limit_on}
                  <div style="display:flex;align-items:center;gap:6px;flex:1">
                    <input type="number" bind:value={adv.rate_limit_kb} min="1" style="flex:1" />
                    <span style="font-size:12px;color:var(--text3);white-space:nowrap">KB/s</span>
                  </div>
                {/if}
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">{$i18n("TCP 单端口最大连接数")}</label>
              <input type="number" bind:value={adv.max_conns} min="0" placeholder={$i18n("如 256，0=不限")} />
            </div>
          </div>
          <div class="tip-text">{$i18n("限速为该通道上下行合计速率；超出最大连接数的新连接将被直接拒绝。")}</div>
        </div>
      {:else}
        <!-- UDP 进阶选项（会话超时 / 最大会话数 / 块长度真实生效；块加密在打洞裸转发场景不适用） -->
        <div style="display:flex;flex-direction:column;gap:14px">
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">{$i18n("UDP 会话超时（毫秒）")}</label>
              <input type="number" bind:value={adv.udp_timeout_ms} min="0" placeholder={$i18n("如 30000，0=默认 30000")} />
            </div>
            <div class="form-group">
              <label class="form-label">{$i18n("UDP 单端口最大会话数")}</label>
              <input type="number" bind:value={adv.udp_max_sessions} min="0" placeholder={$i18n("如 32，0=不限")} />
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">{$i18n("UDP 最大块长度（字节）")}</label>
              <input type="number" bind:value={adv.udp_block_size} min="0" max="65000" placeholder={$i18n("如 1500，0=默认 1500")} />
            </div>
          </div>
          <div class="tip-text">{$i18n("会话空闲超过超时时间后自动回收；超出最大会话数的新来源数据包将被丢弃。")}</div>
        </div>
      {/if}
      <div style="margin-top:16px;padding-top:14px;border-top:1px dashed rgba(128,128,128,.18)">
        <div class="form-group">
          <label class="form-label">{$i18n("使用默认 STUN 服务器")}</label>
          <div style="display:flex;align-items:center;gap:12px;height:38px">
            <Toggle bind:checked={form.use_default_stun} />
            <span style="font-size:13px;color:var(--text3)">{form.use_default_stun ? i18nTr("开启（仅当前通道）") : i18nTr("关闭（使用下方自定义列表）")}</span>
          </div>
        </div>
        {#if form.use_default_stun}
          <div class="form-group">
            <label class="form-label">{$i18n("默认服务器列表")}</label>
            {#if defaultServerLines.length}
              <div style="border:1px solid var(--bd);border-radius:var(--radius);padding:8px 12px;background:var(--bg3);font-family:var(--mono);font-size:12px;line-height:1.9;color:var(--text2)">
                {#each defaultServerLines as s}
                  <div>{s}</div>
                {/each}
              </div>
            {:else}
              <div class="tip-text" style="color:var(--red)">{$i18n("当前默认列表没有支持")} {form.proto.toUpperCase()} {$i18n("的服务器，请关闭开关自定义，或到「系统设置 → STUN 设置」调整服务器协议。")}</div>
            {/if}
            <div class="tip-text">{$i18n("开启时列表只读；关闭开关后可为本通道单独编辑，不影响其他通道。")}</div>
          </div>
        {:else}
          <div class="form-group">
            <label class="form-label">{$i18n("本通道 STUN 服务器")}</label>
            <textarea bind:value={form.stun_servers} rows="5" placeholder={$i18n("每行一个 host:port，如 stun.nextcloud.com:3478")} style="font-family:var(--mono);resize:vertical"></textarea>
            <div class="tip-text">{$i18n("只对当前通道生效，按当前协议（")}{form.proto.toUpperCase()}{$i18n("）使用；至少填写一个。")}</div>
          </div>
        {/if}
      </div>
    {:else if activePanel === 'webhook'}
      <div style="display:flex;flex-direction:column;gap:14px">
        <div class="form-row">
          <div class="form-group" style="min-width:150px">
            <label class="form-label">{$i18n("联动方式")}</label>
            <CustomSelect bind:value={form.webhook_mode} options={WEBHOOK_MODE_OPTIONS} />
          </div>
          <div class="form-group" style="flex:1;min-width:180px">
            <label class="form-label">{$i18n("触发条件")}</label>
            <CustomSelect bind:value={form.webhook_trigger} options={WEBHOOK_TRIGGER_OPTIONS} />
          </div>
        </div>
        {#if form.webhook_mode === 'auto'}
          <div class="form-row">
            <div class="form-group" style="flex:1;min-width:200px">
              <label class="form-label">{$i18n("分组")}</label>
              {#if whGroupOptions.length}
                <CustomSelect bind:value={form.webhook_group} options={whGroupOptions} placeholder={$i18n("默认分组")} />
              {:else}
                <input type="text" value="默认分组" disabled />
              {/if}
            </div>
          </div>
          <div class="tip-text">{$i18n("打洞成功后自动创建新的 Webhook 通道（自动分配访问 ID，归入所选分组）并注册公网映射地址，地址变化时自动跟随更新。")}</div>
        {:else if form.webhook_mode === 'select'}
          <div class="form-row">
            <div class="form-group" style="flex:1;min-width:200px">
              <label class="form-label">{$i18n("Webhook 通道")}</label>
              {#if whChannels.length}
                <CustomSelect bind:value={form.webhook_channel} options={whChannelOptions} />
              {:else}
                <input type="text" value="暂无已注册通道" disabled />
              {/if}
            </div>
          </div>
          {#if !whChannels.length}
            <div class="tip-text" style="color:var(--yellow)">{$i18n("暂无已注册的 Webhook 通道。请先到「Webhook」页面注册，注册后重新打开本弹窗；或改用「自动创建 / 自定义」。")}</div>
          {:else}
            <div class="tip-text">{$i18n("打洞成功后把公网映射地址更新到所选通道（通道被删除后联动自动失效），地址变化时自动跟随更新。")}</div>
          {/if}
        {:else}
          <div class="form-row">
            <div class="form-group" style="min-width:150px">
              <label class="form-label">{$i18n("请求方法")}</label>
              <CustomSelect bind:value={form.webhook_method} options={WEBHOOK_METHOD_OPTIONS} />
            </div>
            <div class="form-group" style="flex:1;min-width:200px">
              <label class="form-label">{$i18n("接口地址")}</label>
              <input type="text" bind:value={form.webhook_url} placeholder="https://example.com/callback" use:field={{ check: optional(validateURL) }} />
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">{$i18n("请求头（每行一条 Key: Value，可选）")}</label>
            <textarea rows="3" bind:value={form.webhook_headers} spellcheck="false" style="font-family:var(--mono);font-size:12px" placeholder={'Authorization: Bearer token\nX-Source: tunhook'}></textarea>
          </div>
          <div class="form-group">
            <label class="form-label">{$i18n("请求体（JSON 模板，可选）")}</label>
            <textarea rows="4" bind:value={form.webhook_body} spellcheck="false" style="font-family:var(--mono);font-size:12px" placeholder={WH_BODY_SAMPLE}></textarea>
          </div>
          <div class="form-row">
            <div class="form-group" style="flex:1;min-width:180px">
              <label class="form-label">{$i18n("回调字符")}</label>
              <input type="text" bind:value={form.webhook_callback} placeholder={$i18n("客户端上报时需携带的验证字符")} maxlength="64" />
            </div>
            <div class="form-group" style="min-width:180px">
              <label class="form-label">{$i18n("禁用回调字符检测")}</label>
              <div style="display:flex;align-items:center;gap:12px;height:38px">
                <Toggle bind:checked={form.webhook_no_check} />
                <span style="font-size:13px;color:var(--text3)">{form.webhook_no_check ? i18nTr("开启（不校验）") : i18nTr("关闭（校验）")}</span>
              </div>
            </div>
          </div>
        {/if}
      </div>
    {:else}
      <div style="display:flex;flex-direction:column;gap:14px">
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">{$i18n("日志输出级别")}</label>
            <CustomSelect bind:value={form.log_level} options={LOG_LEVEL_OPTIONS} />
          </div>
          <div class="form-group">
            <label class="form-label">{$i18n("日志存储条数")}</label>
            <input type="number" bind:value={form.log_entries} min="100" max="10000" step="100" placeholder="100-10000" />
          </div>
        </div>
        <div class="tip-text">{$i18n("通道事件日志为内存环形缓冲，按级别过滤输出，超出存储条数自动截断，服务重启后清零。")}</div>
      </div>
    {/if}
    </div>

    <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:16px">
      <button class="btn" on:click={() => { showCreate = false; editId = null; }}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={submitCreate} disabled={saving}>{saving ? i18nTr("保存中…") : (editId ? i18nTr("保存") : i18nTr("创建并打洞"))}</button>
    </div>
  </Modal>
{/if}

{#if showLog}
  <Modal title={`通道日志 · ${logName}`} onClose={() => { showLog = false; logId = ''; if (logTimer) { logTimer(); logTimer = null; } }} width={640}>
    <div style="max-height:60vh;overflow-y:auto;border:1px solid var(--bd);border-radius:var(--radius);background:var(--bg2);padding:10px 12px;font-family:var(--mono);font-size:12px;line-height:1.9">
      {#if logRows.length === 0}
        <div style="color:var(--text3);text-align:center;padding:16px 0">{$i18n("暂无日志")}</div>
      {:else}
        {#each logRows as l}
          <div><span style="color:var(--text3)">{fmtLogTs(l.ts)}</span> <span style="color:var(--text2)">{l.msg}</span></div>
        {/each}
      {/if}
    </div>
    <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
      <button class="btn" on:click={loadLogs}>{$i18n("立即刷新")}</button>
      <button class="btn" on:click={() => { showLog = false; logId = ''; if (logTimer) { logTimer(); logTimer = null; } }}>{$i18n("关闭")}</button>
    </div>
  </Modal>
{/if}

{#if showStats && statsHole}
  <Modal title={$i18n("流量详情")} onClose={() => { showStats = false; statsId = ''; }} width={720}>
    <div slot="title-extra">
      <span class="cell-dim" style="font-size:12px;font-weight:400">{statsHole.name || statsHole.id}</span>
    </div>
    <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:16px">
      <div class="stat-card">
        <div class="stat-num">{fmtBytes(statsHole.tx_bytes || 0)}</div>
        <div class="stat-label">{$i18n("累计上行")}</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{fmtBytes(statsHole.rx_bytes || 0)}</div>
        <div class="stat-label">{$i18n("累计下行")}</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{statsHole.conns || 0}</div>
        <div class="stat-label">{$i18n("当前连接数")}</div>
      </div>
    </div>

    {#if (statsHole.conns || 0) === 0}
      <div style="text-align:center;padding:30px 0;color:var(--text3);font-size:13px">{$i18n("当前无活跃连接，有外部访问时自动显示")}</div>
    {/if}
  </Modal>
{/if}

{#if showPortScan}
  <PortScanModal onClose={() => (showPortScan = false)} onPick={onPortPick} />
{/if}

{#if delTarget}
  <ConfirmModal
    title={$i18n("删除打洞通道")}
    message={`确定删除打洞通道「${delTarget.name}」吗？删除后监听停止、网关 UPnP 端口映射同步移除，此操作不可恢复。`}
    onConfirm={confirmDelete}
    onClose={() => { if (!delBusy) delTarget = null; }}
    busy={delBusy}
  />
{/if}

<style>
  /* 新版卡片：NAT 环境（状态/统计区） */
  .st-card {
    background: var(--bg3);
    border: 1px solid var(--bd);
    border-radius: calc(var(--radius) + 4px);
    padding: 16px 18px;
    box-shadow: var(--shadow-card);
    margin-bottom: 14px;
  }
  .st-card-hd { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  .st-card-title { font-size: 13.5px; font-weight: 600; color: var(--text); letter-spacing: .1px; }
  .st-card-sub { font-size: 11px; color: var(--text3); font-family: var(--mono); }
  .st-card-right { margin-left: auto; display: flex; align-items: center; gap: 6px; }
  .st-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
  .st-cell { background: var(--bg4); border: 1px solid var(--bd); border-radius: var(--radius); padding: 10px 12px; min-width: 0; }
  .st-cell span { display: block; font-size: 10.5px; color: var(--text3); margin-bottom: 3px; }
  .st-cell b {
    display: block; font-family: var(--mono); font-size: 12.5px; font-weight: 600; color: var(--text);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  /* 列表首列状态点 / 协议徽章（TCP 蓝、UDP 黄，与演示页一致） */
  .st-name { display: inline-flex; align-items: center; gap: 7px; min-width: 0; }
  .st-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; display: inline-block; }
  .badge-blue { color: var(--blue); background: rgba(var(--blue-rgb), .08); border: 1px solid rgba(var(--blue-rgb), .25); }
  /* 无通道时表格按内容高度收缩，避免空状态在大屏上撑满整页 */
  .page-full .table-wrap.st-empty { flex: 0 0 auto; }
  .st-table-foot {
    display: flex; align-items: center; justify-content: space-between; gap: 10px;
    padding: 10px 12px; border-top: 1px solid var(--bd);
    font-size: 11px; color: var(--text3); flex-wrap: wrap;
  }
  .st-foot-meta { font-family: var(--mono); }
  .st-mobile-summary { font-size: 11px; color: var(--text3); padding: 0 2px 2px; font-family: var(--mono); }
  .st-meta-line { min-width: 0; flex-wrap: nowrap; overflow: hidden; }
  .st-meta-line > .cell-mono { min-width: 0; }
  .st-arrow { color: var(--text3); flex-shrink: 0; }
  .st-card-error { font-size: 11px; color: var(--text3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .st-foot-note { margin-right: auto; font-size: 11px; color: var(--text3); font-family: var(--mono); }

  @media (max-width: 600px) {
    .st-card { padding: 14px; }
    .st-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .st-card-hd { margin-bottom: 10px; }
    .list-card {
      background: var(--bg3);
      border-radius: calc(var(--radius) + 4px);
      box-shadow: var(--shadow-card);
      padding: 14px;
    }
    .list-card-title { font-size: 13.5px; }
    .st-foot-note { font-size: 10.5px; }
  }

  /* 监听通道：滑动胶囊（两个等宽选项 + 绝对定位的指示块） */
  .listen-mode-switch {
    position: relative;
    display: inline-flex;
    align-items: center;
    height: 38px;
    padding: 3px;
    border: 1px solid var(--bd);
    border-radius: 999px;
    background: var(--bg3);
    box-sizing: border-box;
  }
  .listen-mode-thumb {
    position: absolute;
    top: 3px;
    left: 3px;
    width: calc(50% - 3px);
    height: calc(100% - 6px);
    border-radius: 999px;
    background: var(--accent-solid);
    box-shadow: 0 1px 3px rgba(0, 0, 0, .18);
    transition: transform .22s cubic-bezier(.4, 0, .2, 1);
  }
  .listen-mode-thumb.right { transform: translateX(100%); }
  .listen-mode-btn {
    position: relative;
    z-index: 1;
    flex: 1 1 50%;
    min-width: 78px;
    height: 100%;
    padding: 0 12px;
    border: none;
    border-radius: 999px;
    background: transparent;
    color: var(--text3);
    font-size: 13px;
    white-space: nowrap;
    cursor: pointer;
    transition: color .18s ease;
  }
  .listen-mode-btn:hover { color: var(--text2); }
  .listen-mode-btn.active { color: #fff; font-weight: 600; }

  /* 移动端：探测弹窗控制行换行——服务器下拉占满整行，「开始探测/扫描链路」两按钮平分第二行。
     下拉是 CustomSelect 内联 width:320px，只能用 !important 覆盖；:global 穿透子组件作用域 */
  @media (max-width:600px){
    .probe-controls{flex-wrap:wrap}
    .probe-controls :global(.custom-select){width:100%!important;flex-basis:100%}
    .probe-controls .btn{flex:1 1 auto}
  }
</style>
