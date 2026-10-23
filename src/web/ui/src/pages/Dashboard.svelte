<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  import { onMount, onDestroy } from 'svelte';
  import { api, apiBase } from '../lib/api.js';
  import { forwards, status, sysStats, activeTab, toast, disabledModules, netRate } from '../lib/stores.js';
  import { fmtBytes, fmtRate, fmtDuration, parseFwdKey, pollVisible, validateURL } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';
  import TrafficStatChart from '../components/TrafficStatChart.svelte';
  import CustomSelect from '../components/CustomSelect.svelte';
  import Modal from '../components/Modal.svelte';

  let updated = '-';
  let timers = [];

  // 新版仪表盘为固定结构：4 个 KPI、实时流量、系统负载、活跃通道、最近日志。
  // ============= 状态数据 =============
  let sysConns = null;
  let connSeries = [];
  let tunnelSeries = [];
  let uptimeSeries = [];

  // 到 frp 服务器的往返延迟（GET /api/frpc/server/latency）
  let latency = { online: false, ms: 0, addr: '', error: '' };
  let latencyBusy = false;
  // 无固定量程指标的近期采样，用于把进度条按峰值归一化
  let netSeries = { rx: [], tx: [] };
  let latSeries = [];

  // 延迟检测地址（空=自动使用当前激活的 frp 服务器；非空时由后端探测该地址）
  let latencyTarget = '';
  try {
    latencyTarget = localStorage.getItem('tunhook.dashboard.latencyTarget') || '';
  } catch (e) { /* ignore */ }
  let showLatencyCfg = false;
  let latencyDraft = '';

  let frpcChannels = 0;
  let frpcRunningCount = 0;
  let frpcProxies = [];
  let frpcStates = {};
  let frpcRates = {};

  // 活跃通道：在端口转发 / 内网穿透 / MEFrp / LoliaFrp / Cloudflare 之间切换
  const CHANNEL_MODULES = [
    { value: 'forward', label: i18nTr("端口转发") },
    { value: 'tunnel', label: 'FRPC' },
    { value: 'mefrp', label: 'MEFrp' },
    { value: 'lolia', label: 'LoliaFrp' },
    { value: 'cloudflare', label: 'Cloudflare' }
  ];
  let channelModule = 'forward';
  try {
    const saved = localStorage.getItem('tunhook.dashboard.channelModule');
    if (CHANNEL_MODULES.some((m) => m.value === saved)) channelModule = saved;
  } catch (e) { /* ignore */ }
  let mefrpProxies = [];
  let mefrpNodes = [];
  let loliaTunnels = [];
  let cfInstances = [];

  // 今日流量（由 /api/traffic/stats?mode=24h 的分钟采样在本地按设备零点累计）
  let today = { rx: 0, tx: 0 };
  let trafficVals = [];
  let lastReboot = '-';

  // 最近日志
  let logs = [];
  let logsLoading = false;

  // 公网地址
  let pubIP = { ipv4: '', ipv6: '', cached_at: '' };

  // NAT 类型
  let natInfo = null;
  let natLoading = false;
  let natClass = '';
  const NAT_TYPES = [
    { key: 'full', en: 'Full Cone NAT', zh: i18nTr("完全锥形"), grade: i18nTr("最佳"), color: 'var(--green)',
      feat: i18nTr("一次映射，全网可达。任何外网服务器都能主动连接内网主机。"),
      scene: i18nTr("P2P下载、远程桌面、游戏联机、自建服务器") },
    { key: 'restricted', en: 'Restricted Cone NAT', zh: i18nTr("限制锥形"), grade: i18nTr("良好"), color: 'var(--accent)',
      feat: i18nTr("限制IP地址。只有客户端主动连接过的IP地址，才能反向连接客户端（端口不限）。"),
      scene: i18nTr("大部分P2P应用、视频通话、在线游戏") },
    { key: 'portrestricted', en: 'Port Restricted Cone NAT', zh: i18nTr("端口限制锥形"), grade: i18nTr("中等"), color: 'var(--yellow)',
      feat: i18nTr("限制IP+端口。只有客户端主动连接过的确切IP和端口组合，才能反向连接。"),
      scene: i18nTr("部分P2P应用可用，游戏NAT类型显示为中等，可能需要端口转发") },
    { key: 'symmetric', en: 'Symmetric NAT', zh: i18nTr("对称型"), grade: i18nTr("受限"), color: 'var(--red)',
      feat: i18nTr("每个连接独立映射。连接不同服务器时，NAT会分配不同的外网端口，导致P2P打洞失败。"),
      scene: i18nTr("P2P下载速度慢、游戏无法联机、远程桌面失败，通常需要中继服务器或安全组网方案") }
  ];

  function classifyNat(p) {
    if (!p) return '';
    const m = p.mapping_behavior, f = p.filtering_behavior;
    if (m === 'endpoint independent') {
      if (f === 'endpoint independent') return 'full';
      if (f === 'address dependent') return 'restricted';
      if (f === 'address and port dependent') return 'portrestricted';
      return 'partial';
    }
    if (m === 'address dependent' || m === 'address and port dependent') return 'symmetric';
    return '';
  }

  async function probeNat() {
    if (natLoading) return;
    natLoading = true;
    const my = new AbortController();
    const t = setTimeout(() => my.abort(), 25000);
    try {
      natInfo = await api('/api/stun/probe?server=' + encodeURIComponent('stun.miwifi.com:3478'), { signal: my.signal });
    } catch (e) {
      natInfo = null;
    } finally {
      clearTimeout(t);
      natLoading = false;
    }
    natClass = classifyNat(natInfo);
  }

  $: natType = NAT_TYPES.find((x) => x.key === natClass) || null;
  $: natCard = (() => {
    if (natLoading) return { val: i18nTr("检测中"), sub: i18nTr("STUN 探测中…"), color: 'var(--text3)' };
    if (natType) return { val: natType.zh, sub: natType.grade, color: natType.color };
    if (natClass === 'partial') return { val: i18nTr("锥形"), sub: i18nTr("良好 · 过滤行为未验证"), color: 'var(--accent)' };
    return { val: i18nTr("未识别"), sub: i18nTr("探测失败或 NAT 行为未知"), color: 'var(--text3)' };
  })();

  // 进程列表 / 连接列表弹窗
  let showProcModal = false;
  let procs = [];
  let procLoading = false;
  let procQuery = '';
  let procSort = { key: 'pid', dir: 'asc' };
  let showConnModal = false;
  let conns = [];
  let connLoading = false;
  let connQuery = '';
  let connSort = { key: 'proto', dir: 'asc' };
  let showNatModal = false;

  const PROC_STATE = {
    'R': i18nTr("运行中"), 'S': i18nTr("睡眠"), 'D': i18nTr("磁盘等待"), 'T': i18nTr("已停止"), 't': i18nTr("跟踪停止"), 'Z': i18nTr("僵尸"),
    'X': i18nTr("已死亡"), 'I': i18nTr("空闲"), 'K': i18nTr("唤醒杀死"), 'W': i18nTr("分页"), 'P': i18nTr("驻留")
  };
  function procStateLabel(state) {
    return PROC_STATE[state] || state || '-';
  }

  function makeMatcher(query) {
    const raw = (query || '').trim();
    if (!raw) return null;
    let re;
    if (raw.startsWith('/')) {
      const body = raw.endsWith('/') && raw.length > 2 ? raw.slice(1, -1) : raw.slice(1);
      try { re = new RegExp(body, 'i'); } catch (e) { return () => false; }
    } else {
      const esc = raw.split('*').map((seg) => seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
      try { re = new RegExp('^' + esc + '$', 'i'); } catch (e) { return () => false; }
    }
    return (v) => re.test(v || '');
  }

  $: procRows = (() => {
    const key = procSort.key;
    const dir = procSort.dir === 'asc' ? 1 : -1;
    let rows = procs;
    const match = makeMatcher(procQuery);
    if (match) {
      rows = rows.filter((p) => match(p.name) || match(String(p.pid)) || match(p.state) || match(procStateLabel(p.state)));
    }
    return [...rows].sort((a, b) => {
      const av = a[key], bv = b[key];
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
      return String(av ?? '').localeCompare(String(bv ?? '')) * dir;
    });
  })();

  $: connRows = (() => {
    const key = connSort.key;
    const dir = connSort.dir === 'asc' ? 1 : -1;
    let rows = conns;
    const match = makeMatcher(connQuery);
    if (match) rows = rows.filter((c) => match(c.proto) || match(c.state) || match(c.local) || match(c.remote));
    return [...rows].sort((a, b) => {
      const av = a[key], bv = b[key];
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
      return String(av ?? '').localeCompare(String(bv ?? '')) * dir;
    });
  })();

  function sortByProc(key) {
    procSort = { key, dir: procSort.key === key && procSort.dir === 'asc' ? 'desc' : 'asc' };
  }
  function sortByConn(key) {
    connSort = { key, dir: connSort.key === key && connSort.dir === 'asc' ? 'desc' : 'asc' };
  }
  function sortIcon(sort, key) {
    if (sort.key !== key) return '';
    return sort.dir === 'asc' ? ' ▲' : ' ▼';
  }

  async function openProcModal() {
    showProcModal = true;
    procLoading = true;
    procQuery = '';
    procs = [];
    try {
      const d = await api('/api/system/processes');
      procs = Array.isArray(d) ? d : [];
    } catch (e) {
      toast(i18nTr("获取进程列表失败"), 'error');
    } finally {
      procLoading = false;
    }
  }

  async function openConnModal() {
    showConnModal = true;
    connLoading = true;
    connQuery = '';
    conns = [];
    try {
      const d = await api('/api/system/conns/detail');
      conns = Array.isArray(d) ? d : [];
    } catch (e) {
      toast(i18nTr("获取连接列表失败"), 'error');
    } finally {
      connLoading = false;
    }
  }

  // 公网 IP 获取方式设置
  let showPubCfg = false;
  let pubCfg = { method: 'curl', v4_url: '', v6_url: '' };
  let pubCfgBusy = false;
  let pubCfgEl;

  async function openPubCfg() {
    showPubCfg = true;
    pubCfgBusy = true;
    try {
      const d = await api('/api/network/public/config');
      pubCfg = {
        method: d.method || 'http',
        v4_url: d.v4_url || 'https://ipv4.icanhazip.com',
        v6_url: d.v6_url || 'https://ipv6.icanhazip.com/'
      };
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      pubCfgBusy = false;
    }
  }

  async function savePubCfg() {
    if (!validateAll(pubCfgEl)) return;
    pubCfgBusy = true;
    try {
      await api('/api/network/public/config', { method: 'POST', body: pubCfg });
      toast(i18nTr("已保存，正在重新探测公网地址"), 'success');
      showPubCfg = false;
      await api('/api/network/public?refresh=1');
      refreshPublic();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      pubCfgBusy = false;
    }
  }

  // ============= 轮询 =============
  async function refreshStatus() {
    try {
      const st = await api('/api/status');
      if (st) {
        status.set(st);
        if (st.uptime != null && st.server_time) {
          const t = new Date((st.server_time - st.uptime) * 1000 + (st.utc_offset || 0) * 1000);
          const p = (x) => String(x).padStart(2, '0');
          lastReboot = `${p(t.getUTCMonth() + 1)}-${p(t.getUTCDate())} ${p(t.getUTCHours())}:${p(t.getUTCMinutes())}`;
          uptimeSeries = [...uptimeSeries.slice(-39), { t: Date.now(), v: st.uptime }];
        }
      }
    } catch (e) { /* ignore */ }
  }

  async function refreshStats() {
    try {
      const s = await api('/api/system/stats');
      if (s) sysStats.set(s);
    } catch (e) { /* ignore */ }
  }

  async function refreshConns() {
    try {
      const c = await api('/api/system/conns');
      if (c) {
        sysConns = c;
        connSeries = [...connSeries.slice(-59), { t: Date.now(), total: c.total || 0 }];
      }
    } catch (e) { /* ignore */ }
  }

  async function refreshNet() {
    try {
      const d = await api('/api/system/net');
      if (d) {
        const rx = d.rx || 0;
        const tx = d.tx || 0;
        netRate.set({ rx, tx });
        netSeries = { rx: [...netSeries.rx.slice(-19), rx], tx: [...netSeries.tx.slice(-19), tx] };
      }
    } catch (e) { /* ignore */ }
  }

  // 延迟探测含 3 次 TCP 建连与 HTTP 往返，耗时远高于普通接口：
  // 单独低频轮询并加忙碌锁，避免上一次未结束就叠加下一次。
  async function refreshLatency() {
    if (latencyBusy) return;
    latencyBusy = true;
    try {
      const q = latencyTarget ? '?addr=' + encodeURIComponent(latencyTarget) : '';
      const d = await api('/api/frpc/server/latency' + q);
      latency = {
        online: !!(d && d.online),
        ms: (d && d.latency_ms) || 0,
        addr: (d && d.addr) || '',
        error: (d && d.error) || ''
      };
    } catch (e) {
      latency = { online: false, ms: 0, addr: '', error: '' };
    } finally {
      latSeries = [...latSeries.slice(-19), latency.online ? latency.ms : 0];
      latencyBusy = false;
    }
  }

  function openLatencyCfg() {
    latencyDraft = latencyTarget;
    showLatencyCfg = true;
  }

  function saveLatencyCfg() {
    const raw = latencyDraft.trim();
    if (/\s/.test(raw)) {
      toast(i18nTr("检测地址不能包含空格"), 'error');
      return;
    }
    latencyTarget = raw;
    try {
      if (raw) localStorage.setItem('tunhook.dashboard.latencyTarget', raw);
      else localStorage.removeItem('tunhook.dashboard.latencyTarget');
    } catch (e) { /* ignore */ }
    showLatencyCfg = false;
    latSeries = []; // 目标变了，旧峰值不应再参与归一化
    latency = { online: false, ms: 0, addr: raw, error: '' };
    refreshLatency();
  }

  function resetLatencyCfg() {
    latencyDraft = '';
    saveLatencyCfg();
  }

  async function refreshFrpc() {
    try {
      const [cfg, st, connStatesWrap] = await Promise.all([
        api('/api/frpc/config'),
        api('/api/frpc/status'),
        api('/api/frpc/conns' + (channelModule === 'tunnel' ? '?detail=1' : ''))
      ]);
      if (cfg) {
        const list = cfg.proxies || [];
        frpcChannels = list.length;
        frpcProxies = list;
      }
      frpcStates = (connStatesWrap && connStatesWrap.states) || {};
      frpcRates = (connStatesWrap && connStatesWrap.rates) || {};
      frpcRunningCount = frpcProxies.filter((p) => frpcStates[p.name] === 'running').length;
      if (st && !st.running) frpcRunningCount = 0;
      tunnelSeries = [...tunnelSeries.slice(-39), { t: Date.now(), v: frpcRunningCount }];
    } catch (e) { /* ignore */ }
  }

  async function refreshMefrpTunnels() {
    try {
      const d = await api('/api/mefrp/tunnels');
      mefrpProxies = (d && d.proxies) || [];
      mefrpNodes = (d && d.nodes) || [];
    } catch (e) { /* ignore */ }
  }

  async function refreshLoliaTunnels() {
    try {
      const d = await api('/api/lolia/tunnels');
      loliaTunnels = (d && d.tunnels) || [];
    } catch (e) { /* ignore */ }
  }

  async function refreshCloudflare() {
    try {
      const d = await api('/api/cloudflare/status');
      cfInstances = (d && d.instances) || [];
    } catch (e) { /* ignore */ }
  }

  // 只刷新当前选中的通道模块，避免为未展示的模块持续请求云端接口
  function refreshChannelModule() {
    if (channelModule === 'mefrp') refreshMefrpTunnels();
    else if (channelModule === 'lolia') refreshLoliaTunnels();
    else if (channelModule === 'cloudflare') refreshCloudflare();
  }

  let lastChannelModule = '';
  $: if (channelModule !== lastChannelModule) {
    lastChannelModule = channelModule;
    if (channelModule === 'tunnel') refreshFrpc();
    refreshChannelModule();
    try { localStorage.setItem('tunhook.dashboard.channelModule', channelModule); } catch (e) { /* ignore */ }
  }

  // 设备本地零点（Unix 秒）：status.utc_offset 为设备时区偏移
  function deviceMidnightUnix(nowSec, offset) {
    const dev = new Date((nowSec + offset) * 1000);
    const pseudo = Date.UTC(dev.getUTCFullYear(), dev.getUTCMonth(), dev.getUTCDate()) / 1000;
    return pseudo - offset;
  }

  async function refreshToday() {
    try {
      const d = await api('/api/traffic/stats?mode=24h');
      const pts = (d && d.points) || [];
      const nowSec = (d && d.server_time) || Math.floor(Date.now() / 1000);
      const offset = ($status && $status.utc_offset) || 0;
      const mid = deviceMidnightUnix(nowSec, offset);
      let rx = 0, tx = 0;
      for (let i = 0; i < pts.length; i++) {
        const p = pts[i];
        if (!p || p.ts < mid) continue;
        const nxt = pts[i + 1];
        const dt = nxt && nxt.ts > p.ts ? Math.min(nxt.ts - p.ts, 60) : 60;
        rx += (p.rx || 0) * dt;
        tx += (p.tx || 0) * dt;
      }
      today = { rx, tx };
      const since = pts.filter((p) => p.ts >= mid).slice(-20);
      trafficVals = (since.length ? since : pts.slice(-20)).map((p) => (p.rx || 0) + (p.tx || 0));
    } catch (e) { /* ignore */ }
  }

  async function refreshLogs() {
    logsLoading = !logs.length;
    try {
      // 由后端在分页前排除 HTTP 访问日志（module=web），避免高频请求把业务日志挤出首页
      const d = await api('/api/logs?page=1&pageSize=5&exclude_module=web');
      logs = (d && d.entries) || [];
    } catch (e) { /* ignore */ }
    logsLoading = false;
  }

  async function refreshPublic() {
    try {
      const d = await api('/api/network/public');
      if (d) pubIP = { ipv4: d.ipv4 || '', ipv6: d.ipv6 || '', nat: d.nat || null, cached_at: d.cached_at || '' };
    } catch (e) { /* ignore */ }
  }

  async function refreshLists() {
    try {
      const f = await api('/api/forward/list');
      if (f) forwards.set(f);
      updated = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    } catch (e) { /* ignore */ }
  }

  async function refreshAll() {
    await refreshStatus();
    await Promise.all([refreshStats(), refreshConns(), refreshNet(), refreshLists(), refreshFrpc(), refreshToday(), refreshLogs(), refreshPublic(), refreshChannelModule()]);
  }

  function poll(fn, ms) {
    fn();
    timers.push(pollVisible(fn, ms));
  }

  onMount(() => {
    poll(refreshStatus, 5000);
    poll(refreshStats, 10000);
    poll(refreshConns, 10000);
    poll(refreshNet, 3000);
    poll(refreshLatency, 30000);
    poll(refreshLists, 10000);
    poll(refreshFrpc, 10000);
    poll(refreshToday, 60000);
    poll(refreshLogs, 10000);
    poll(refreshPublic, 30000);
    poll(refreshChannelModule, 30000);
    probeNat();
  });

  onDestroy(() => {
    timers.forEach((stop) => stop());
  });

  function gotoPage(tab) {
    activeTab.set(tab);
  }

  // ============= 派生展示值 =============
  function splitBytes(n) {
    const s = fmtBytes(n);
    const i = s.lastIndexOf(' ');
    return i < 0 ? { num: s, unit: '' } : { num: s.slice(0, i), unit: s.slice(i + 1) };
  }

  function splitUptime(sec) {
    if (sec == null || isNaN(sec)) return { d: 0, h: 0, m: 0, s: 0 };
    sec = Math.floor(sec);
    return {
      d: Math.floor(sec / 86400),
      h: Math.floor((sec % 86400) / 3600),
      m: Math.floor((sec % 3600) / 60),
      s: sec % 60
    };
  }

  function deltaOf(values, cur) {
    if (!values || values.length < 2) return '';
    const diff = cur - values[0];
    if (!diff) return '';
    return (diff > 0 ? '+' : '') + diff;
  }

  // 无固定量程指标（速率/延迟/连接数）的进度条：按最近采样峰值归一化，
  // 并保留 2% 最小宽度，避免非零值在栏内完全看不见。
  function pctOf(values, cur) {
    const c = Number(cur) || 0;
    if (c <= 0) return 0;
    const max = Math.max(c, ...(values && values.length ? values : [0]));
    return Math.max(2, Math.min(100, (c / max) * 100));
  }

  // 迷你走势图：把数值序列映射为 74×26 的折线与面积路径
  function spark(values, w = 74, h = 26) {
    const vals = (values && values.length ? values : [0]).map((v) => Number(v) || 0);
    while (vals.length < 2) vals.push(vals[0] || 0);
    const min = Math.min(...vals);
    const max = Math.max(...vals);
    const span = max - min || 1;
    const pad = 2;
    const pts = vals.map((v, i) => {
      const x = (i / (vals.length - 1)) * w;
      const y = h - pad - ((v - min) / span) * (h - pad * 2);
      return [x, y];
    });
    const line = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
    return { line, area: line + ` L ${w} ${h} L 0 ${h} Z` };
  }

  $: upParts = splitUptime($status && $status.uptime);
  $: uptimeText = $status && $status.uptime ? fmtDuration($status.uptime) : '';

  $: tunnelVals = tunnelSeries.map((x) => x.v);
  $: connVals = connSeries.map((x) => x.total);
  $: uptimeVals = uptimeSeries.map((x) => x.v);

  $: tunnelSpark = spark(tunnelVals);
  $: connSpark = spark(connVals);
  $: trafficSpark = spark(trafficVals);
  $: uptimeSpark = spark(uptimeVals);

  $: tunnelDelta = deltaOf(tunnelVals, frpcRunningCount);
  $: connDelta = deltaOf(connVals, sysConns ? sysConns.total : 0);

  $: tunnelNote = frpcChannels
    ? i18nTr("共 {0} 条 · {1} 条停用", [frpcChannels, Math.max(0, frpcChannels - frpcRunningCount)])
    : i18nTr("暂无隧道");

  $: trafficBytes = splitBytes(today.rx + today.tx);

  $: cpuPct = $sysStats ? Math.min(100, Math.max(0, $sysStats.cpu_percent || 0)) : 0;
  $: memPct = $sysStats ? Math.min(100, Math.max(0, $sysStats.mem_percent || 0)) : 0;
  $: diskPct = $sysStats ? Math.min(100, Math.max(0, $sysStats.disk_percent || 0)) : 0;
  $: loadBadge = (() => {
    const vals = [cpuPct, memPct, diskPct];
    if (vals.some((v) => v > 90)) return { text: i18nTr("告警"), cls: 'badge-error' };
    if (vals.some((v) => v > 70)) return { text: i18nTr("偏高"), cls: 'badge-warn' };
    return { text: i18nTr("正常"), cls: 'badge-on' };
  })();

  // 标题显示设备名称，副标题显示 1/5/15 分钟平均负载（后端读取 /proc/loadavg）
  $: devName = ($status && $status.hostname) || i18nTr("本机");
  $: loadText = $sysStats && $sysStats.load1 != null
    ? i18nTr("负载 {0} {1} {2}", [($sysStats.load1 || 0).toFixed(2), ($sysStats.load5 || 0).toFixed(2), ($sysStats.load15 || 0).toFixed(2)])
    : '';

  const rowSort = (a, b) => (b.on ? 1 : 0) - (a.on ? 1 : 0);

  $: forwardRows = [...($forwards || [])]
    .map((f) => {
      const pk = parseFwdKey(f.key);
      const proto = (f.protocol || pk.protocol || '').toUpperCase();
      const addr = pk.addr || pk.local || f.key;
      return {
        key: 'forward-' + f.key,
        name: f.description || pk.name || f.key,
        sub: proto ? proto + ' · ' + addr : addr,
        right: fmtRate((f.rx_rate || 0) + (f.tx_rate || 0)),
        rightSub: f.running ? i18nTr("运行中") : i18nTr("已暂停"),
        on: !!f.running,
        dot: f.running ? 'var(--green)' : 'var(--slate)'
      };
    })
    .sort(rowSort);

  $: frpRows = frpcProxies
    .map((p) => {
      const on = frpcStates[p.name] === 'running';
      const type = String(p.type || '').toUpperCase();
      const local = p.local_ip
        ? `${p.local_ip}:${p.local_port || ''}`
        : (p.local_port ? String(p.local_port) : '-');
      const remote = p.remote_port
        ? i18nTr("远程 ") + p.remote_port
        : (p.custom_domains || p.subdomain || '');
      const rate = frpcRates[p.name];
      return {
        key: 'tunnel-' + (p.name || local),
        name: p.name || local,
        sub: type ? type + ' · ' + local : local,
        right: !on ? i18nTr("已停止") : rate ? fmtRate((rate.rx || 0) + (rate.tx || 0)) : i18nTr("运行中"),
        rightSub: on && rate ? i18nTr("运行中") : (remote || i18nTr("本机 frp")),
        on,
        dot: on ? 'var(--green)' : 'var(--slate)'
      };
    })
    .sort(rowSort);

  // MEFrp 的 domain 可能是 JSON 文本（如 ["mefrp.com"]），取首个域名
  function parseDomain(d) {
    if (!d) return '';
    let s = String(d).trim();
    try {
      const arr = JSON.parse(s);
      if (Array.isArray(arr)) s = arr.filter(Boolean)[0] || '';
    } catch (e) { /* 非 JSON 按原文处理 */ }
    return s.replace(/^[\["'\s]+|[\]"'\s]+$/g, '');
  }

  $: mefrpRows = mefrpProxies
    .map((p) => {
      const on = !!p.isOnline && !p.isBanned;
      const type = String(p.proxyType || '').toUpperCase();
      const local = `${p.localIp || '127.0.0.1'}:${p.localPort || ''}`;
      const node = (mefrpNodes.find((n) => n.nodeId === p.nodeId) || {}).name || '';
      const domain = parseDomain(p.domain);
      const remote = (type === 'HTTP' || type === 'HTTPS')
        ? domain
        : (p.remotePort ? i18nTr("远程 ") + p.remotePort : '');
      return {
        key: 'mefrp-' + (p.proxyId || p.proxyName),
        name: p.proxyName || '-',
        sub: type ? type + ' · ' + local : local,
        right: p.isBanned ? i18nTr("已封禁") : on ? i18nTr("运行中") : i18nTr("已停止"),
        rightSub: remote || node || 'MEFrp',
        on,
        dot: p.isBanned ? 'var(--red)' : on ? 'var(--green)' : 'var(--slate)'
      };
    })
    .sort(rowSort);

  $: loliaRows = loliaTunnels
    .map((t) => {
      const on = t.status === 'active';
      const type = String(t.type || '').toUpperCase();
      const local = `${t.local_ip || '127.0.0.1'}:${t.local_port || ''}`;
      const remote = t.remote_port
        ? i18nTr("远程 ") + t.remote_port
        : (t.domain || '');
      return {
        key: 'lolia-' + t.name,
        name: t.remark || t.name || '-',
        sub: type ? type + ' · ' + local : local,
        right: on ? i18nTr("运行中") : i18nTr("已离线"),
        rightSub: remote || 'LoliaFrp',
        on,
        dot: on ? 'var(--green)' : 'var(--slate)'
      };
    })
    .sort(rowSort);

  function cfModeLabel(mode) {
    return mode === 'api' ? i18nTr("API 全托管") : mode === 'quick' ? i18nTr("临时入口") : i18nTr("Token 托管");
  }

  $: cfRows = cfInstances
    .flatMap((inst) => {
      const on = !!inst.running && !!inst.ready;
      const state = on ? i18nTr("运行中") : inst.running ? i18nTr("未就绪") : i18nTr("已停止");
      const dot = on ? 'var(--green)' : inst.running ? 'var(--yellow)' : 'var(--slate)';
      const routes = Array.isArray(inst.routes) ? inst.routes : [];
      if (routes.length) {
        return routes.map((r, i) => ({
          key: 'cf-' + inst.id + '-' + i,
          name: r.hostname || inst.name,
          sub: [r.service || '', r.path || ''].filter(Boolean).join(' · '),
          right: state,
          rightSub: inst.name || 'Cloudflare',
          on,
          dot
        }));
      }
      return [{
        key: 'cf-' + inst.id,
        name: inst.name || 'Cloudflare',
        sub: inst.accessURL || cfModeLabel(inst.mode),
        right: state,
        rightSub: cfModeLabel(inst.mode),
        on,
        dot
      }];
    })
    .sort(rowSort);

  $: channelOptions = CHANNEL_MODULES.filter((m) => !$disabledModules.includes(m.value));
  $: if (channelModule && !channelOptions.some((o) => o.value === channelModule)) {
    channelModule = channelOptions[0] ? channelOptions[0].value : 'forward';
  }

  $: channelRows = channelModule === 'tunnel' ? frpRows
    : channelModule === 'mefrp' ? mefrpRows
    : channelModule === 'lolia' ? loliaRows
    : channelModule === 'cloudflare' ? cfRows
    : forwardRows;
  $: channelRunning = channelRows.filter((r) => r.on).length;
  $: channelTotal = channelRows.length;
  $: channelEmpty = channelModule === 'tunnel' ? i18nTr("暂无穿透隧道")
    : channelModule === 'mefrp' ? i18nTr("暂无 MEFrp 隧道")
    : channelModule === 'lolia' ? i18nTr("暂无 LoliaFrp 隧道")
    : channelModule === 'cloudflare' ? i18nTr("暂无 Cloudflare 隧道")
    : i18nTr("暂无转发通道");

  function levelCls(level) {
    const l = String(level || '').toUpperCase();
    if (l === 'ERROR') return 'badge-error';
    if (l === 'WARN' || l === 'WARNING') return 'badge-warn';
    if (l === 'DEBUG') return 'badge-off';
    return 'badge-info';
  }
  function shortTime(t) {
    const s = String(t || '');
    return s.length >= 8 ? s.slice(-8) : s;
  }
</script>

<div class="container">
  <div class="page-hdr dash-hdr">
    <div>
      <h2>{$i18n("运行仪表盘")}</h2>
      <span class="page-hdr-sub">{$i18n("最后更新")} <span class="mono">{updated || '-'}</span>{#if uptimeText}&{$i18n("· 服务已稳定运行")} <span class="mono">{uptimeText}</span>{/if}</span>
    </div>
    <div class="page-hdr-actions hdr-actions-wrap">
      <button class="btn" on:click={refreshAll}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"><path d="M20.5 8c-1.392-3.179-4.823-5-8.522-5C7.299 3 3.453 6.552 3 11.1"/><path d="M16.489 8.4h3.97a.54.54 0 0 0 .54-.54V3.9"/><path d="M3.5 16c1.392 3.179 4.823 5 8.522 5c4.679 0 8.525-3.552 8.978-8.1"/><path d="M7.511 15.6h-3.97a.54.54 0 0 0-.541.54v3.96"/></svg> {$i18n("刷新")}
      </button>
      <button class="btn btn-primary" title={$i18n("打开通道导航页")} on:click={() => window.open(apiBase + '/hook', '_blank')}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3h7v7M21 3l-9 9M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg> {$i18n("打开通道页")}
      </button>
    </div>
  </div>

  <!-- KPI -->
  <div class="db-kpis">
    <div class="db-card db-kpi" role="button" tabindex="0" title={$i18n("点击进入 FRPC")} on:click={() => gotoPage('tunnel')} on:keydown={(e) => e.key === 'Enter' && gotoPage('tunnel')}>
      <div class="db-kpi-top">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/></svg>
        {$i18n("在线隧道")}
        {#if tunnelDelta}<span class="db-delta">{tunnelDelta}</span>{/if}
      </div>
      <div class="db-kpi-val">{frpcRunningCount}<em>{$i18n("条")}</em></div>
      <div class="db-kpi-foot">
        <span class="db-kpi-note">{tunnelNote}</span>
        <svg class="db-spark" viewBox="0 0 74 26" preserveAspectRatio="none"><path d={tunnelSpark.area} fill="var(--green)" opacity=".08"/><path d={tunnelSpark.line} fill="none" stroke="var(--green)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/></svg>
      </div>
    </div>

    <div class="db-card db-kpi" role="button" tabindex="0" title={$i18n("点击查看连接列表")} on:click={openConnModal} on:keydown={(e) => e.key === 'Enter' && openConnModal()}>
      <div class="db-kpi-top">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l2.5-7 4.5 14 2.5-7H21"/></svg>
        {$i18n("活跃连接")}
        {#if connDelta}<span class="db-delta">{connDelta}</span>{/if}
      </div>
      <div class="db-kpi-val">{sysConns ? sysConns.total : '-'}<em>{$i18n("个")}</em></div>
      <div class="db-kpi-foot">
        <span class="db-kpi-note">{sysConns ? `TCP ${sysConns.tcp} · UDP ${sysConns.udp}` : '-'}</span>
        <svg class="db-spark" viewBox="0 0 74 26" preserveAspectRatio="none"><path d={connSpark.area} fill="var(--accent)" opacity=".08"/><path d={connSpark.line} fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/></svg>
      </div>
    </div>

    <div class="db-card db-kpi db-static">
      <div class="db-kpi-top">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 4.5 13.5H11l-1 8.5L19.5 10H13z"/></svg>
        {$i18n("今日流量")}
      </div>
      <div class="db-kpi-val">{trafficBytes.num}<em>{trafficBytes.unit}</em></div>
      <div class="db-kpi-foot">
        <span class="db-kpi-note">{$i18n("接收")} {fmtBytes(today.rx)} {$i18n("· 发送")} {fmtBytes(today.tx)}</span>
        <svg class="db-spark" viewBox="0 0 74 26" preserveAspectRatio="none"><path d={trafficSpark.area} fill="var(--accent-2)" opacity=".08"/><path d={trafficSpark.line} fill="none" stroke="var(--accent-2)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/></svg>
      </div>
    </div>

    <div class="db-card db-kpi db-static">
      <div class="db-kpi-top">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></svg>
        {$i18n("运行时长")}
      </div>
      <div class="db-kpi-val">
        {#if upParts.d > 0}
          {upParts.d}<em>{$i18n("天")}</em>{upParts.h}<em>{$i18n("时")}</em>
        {:else if upParts.h > 0}
          {upParts.h}<em>{$i18n("时")}</em>{upParts.m}<em>{$i18n("分")}</em>
        {:else if upParts.m > 0}
          {upParts.m}<em>{$i18n("分")}</em>{upParts.s}<em>{$i18n("秒")}</em>
        {:else}
          {upParts.s}<em>{$i18n("秒")}</em>
        {/if}
      </div>
      <div class="db-kpi-foot">
        <span class="db-kpi-note">{$i18n("上次重启")} {lastReboot}</span>
        <svg class="db-spark" viewBox="0 0 74 26" preserveAspectRatio="none"><path d={uptimeSpark.area} fill="var(--blue)" opacity=".08"/><path d={uptimeSpark.line} fill="none" stroke="var(--blue)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/></svg>
      </div>
    </div>
  </div>

  <!-- 实时流量 + 系统负载 -->
  <div class="db-main">
    <div class="db-chart">
      <TrafficStatChart />
    </div>

    <div class="db-card db-card-pad db-sys">
      <div class="db-card-h db-sys-h">
        <span class="db-title"><span class="dash-dot" style="background:var(--accent)"></span>{devName}</span>
        {#if loadText}<span class="db-sub">{loadText}</span>{/if}
        <span class="right"><span class="badge {loadBadge.cls}">{loadBadge.text}</span></span>
      </div>

      <div class="db-sys-row">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/></svg>
        <span class="db-sys-lbl">CPU</span>
        <div class="db-progress"><i style="width:{cpuPct}%"></i></div>
        <span class="db-sys-val">{$sysStats ? cpuPct + '%' : '-'}</span>
      </div>
      <div class="db-sys-row">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 17v3M12 17v3M17 17v3M7 10v4M12 10v4M17 10v4"/></svg>
        <span class="db-sys-lbl">{$i18n("内存")}</span>
        <div class="db-progress green"><i style="width:{memPct}%"></i></div>
        <span class="db-sys-val">{$sysStats ? memPct + '%' : '-'}</span>
      </div>
      <div class="db-sys-row">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/></svg>
        <span class="db-sys-lbl">{$i18n("磁盘")}</span>
        <div class="db-progress"><i style="width:{diskPct}%"></i></div>
        <span class="db-sys-val">{$sysStats ? diskPct + '%' : '-'}</span>
      </div>
      <div class="db-sys-row db-sys-metric" title={$i18n("下行速率（进度条按最近采样峰值归一化）")}>
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v14M6 12l6 6 6-6"/></svg>
        <span class="db-sys-lbl">{$i18n("下行")}</span>
        <div class="db-progress"><i style="width:{pctOf(netSeries.rx, $netRate.rx)}%"></i></div>
        <span class="db-sys-val">{fmtRate($netRate.rx)}</span>
      </div>
      <div class="db-sys-row db-sys-metric" title={$i18n("上行速率（进度条按最近采样峰值归一化）")}>
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20V6M6 12l6-6 6 6"/></svg>
        <span class="db-sys-lbl">{$i18n("上行")}</span>
        <div class="db-progress"><i style="width:{pctOf(netSeries.tx, $netRate.tx)}%"></i></div>
        <span class="db-sys-val">{fmtRate($netRate.tx)}</span>
      </div>
      <div class="db-sys-row db-sys-metric db-click" role="button" tabindex="0"
        title={(latencyTarget ? i18nTr("自定义探测：") + latencyTarget + '；' : '') + (!latency.online && latency.error ? i18nTr("不可达：") + latency.error + '；' : '') + i18nTr("点击修改检测地址")}
        on:click={openLatencyCfg} on:keydown={(e) => e.key === 'Enter' && openLatencyCfg()}>
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
        <span class="db-sys-lbl">{$i18n("延迟")}</span>
        <div class="db-progress green"><i style="width:{pctOf(latSeries, latency.online ? latency.ms : 0)}%"></i></div>
        <span class="db-sys-val">{latency.online ? latency.ms + ' ms' : '-'}</span>
      </div>
      <div class="db-sys-row db-sys-metric db-click" role="button" tabindex="0" title={$i18n("当前连接数（进度条按近期峰值归一化），点击查看连接列表")} on:click={openConnModal} on:keydown={(e) => e.key === 'Enter' && openConnModal()}>
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
        <span class="db-sys-lbl">{$i18n("连接")}</span>
        <div class="db-progress"><i style="width:{pctOf(connVals, sysConns ? sysConns.total : 0)}%"></i></div>
        <span class="db-sys-val">{sysConns ? sysConns.total : '-'}</span>
      </div>

      <div class="db-sys-meta">
        <div class="db-sys-cell"><span>{$i18n("内网地址")}</span><b>{$status && $status.local_ip ? $status.local_ip : '-'}</b></div>
        <div class="db-sys-cell db-click" title={$i18n("点击设置公网 IP 获取方式")} role="button" tabindex="0" on:click={openPubCfg} on:keydown={(e) => e.key === 'Enter' && openPubCfg()}><span>{$i18n("公网地址")}</span><b>{pubIP.ipv4 || ($status && $status.public_ip) || '-'}</b></div>
        <div class="db-sys-cell db-click" title={$i18n("点击查看 NAT 类型说明")} role="button" tabindex="0" on:click={() => (showNatModal = true)} on:keydown={(e) => e.key === 'Enter' && (showNatModal = true)}><span>{$i18n("NAT 类型")}</span><b style="color:{natCard.color}">{natCard.val}</b></div>
        <div class="db-sys-cell db-click" title={$i18n("点击查看进程列表")} role="button" tabindex="0" on:click={openProcModal} on:keydown={(e) => e.key === 'Enter' && openProcModal()}><span>{$i18n("进程 / 协程")}</span><b>{$sysStats ? $sysStats.processes + ' / ' + $sysStats.goroutines : '-'}</b></div>
      </div>
    </div>
  </div>

  <!-- 活跃通道 + 最近日志 -->
  <div class="db-lower">
    <div class="db-card db-card-pad">
      <div class="db-card-h db-channel-h">
        <b>{$i18n("活跃通道")}</b>
        <CustomSelect bind:value={channelModule} options={channelOptions} width="108px" />
        <span class="db-sub">{channelRunning} / {channelTotal}</span>
        <span class="right">
          <button class="db-mini-btn" title={$i18n("前往对应模块页")} on:click={() => gotoPage(channelModule)}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg>
          </button>
        </span>
      </div>
      {#if channelRows.length === 0}
        <div class="db-empty">{channelEmpty}</div>
      {:else}
        {#each channelRows.slice(0, 4) as r (r.key)}
          <div class="db-tun-row">
            <span class="db-tun-dot" style="background:{r.dot}"></span>
            <div style="min-width:0">
              <div class="db-tun-name truncate">{r.name}</div>
              <div class="db-tun-sub truncate">{r.sub}</div>
            </div>
            <div class="db-tun-rate">{r.right}<span>{r.rightSub}</span></div>
          </div>
        {/each}
      {/if}
    </div>

    <div class="db-card db-card-pad">
      <div class="db-card-h">
        <b>{$i18n("最近日志")}</b>
        <span class="right">
          <span class="db-live"><span class="db-dot pulse"></span>{$i18n("实时")}</span>
          <button class="db-mini-btn" title={$i18n("前往系统日志")} on:click={() => gotoPage('logs')}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3h7v7M21 3l-9 9M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>
          </button>
        </span>
      </div>
      {#if logsLoading && logs.length === 0}
        <div class="db-empty">{$i18n("加载中…")}</div>
      {:else if logs.length === 0}
        <div class="db-empty">{$i18n("暂无日志")}</div>
      {:else}
        {#each logs as e, i (e.time + '-' + i)}
          <div class="db-log-line">
            <span class="db-log-time">{shortTime(e.time)}</span>
            <span class="db-log-level"><span class="badge {levelCls(e.level)}">{e.level}</span></span>
            <span class="db-log-msg">{#if e.module}<span class="db-log-key">{e.module}</span> {/if}{e.message}</span>
          </div>
        {/each}
      {/if}
    </div>
  </div>
</div>

{#if showPubCfg}
  <Modal title={$i18n("公网 IP 获取方式")} onClose={() => (showPubCfg = false)} width={520}>
    <div class="tip-text" style="margin-bottom:12px">{$i18n("配置探测本机公网 IPv4 / IPv6 地址的方式。默认使用内置 HTTP 请求访问下方的回显服务（无需系统安装 curl）。")}</div>
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px">
      <label style="display:inline-flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
        <input type="radio" bind:group={pubCfg.method} value="curl" /> {$i18n("Curl 命令")}
      </label>
      <label style="display:inline-flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
        <input type="radio" bind:group={pubCfg.method} value="http" /> {$i18n("HTTP 请求")}
      </label>
    </div>
    <div class="form-row" bind:this={pubCfgEl}>
      <div class="form-group" style="margin-bottom:0;flex:1;min-width:220px">
        <label class="form-label">{$i18n("IPv4 回显 URL")}</label>
        <input type="text" bind:value={pubCfg.v4_url} placeholder="https://ipv4.icanhazip.com" use:field={{ check: validateURL }} />
      </div>
      <div class="form-group" style="margin-bottom:0;flex:1;min-width:220px">
        <label class="form-label">{$i18n("IPv6 回显 URL")}</label>
        <input type="text" bind:value={pubCfg.v6_url} placeholder="https://ipv6.icanhazip.com/" use:field={{ check: validateURL }} />
      </div>
    </div>
    <div class="tip-text" style="margin-top:10px">{$i18n("回显服务需返回纯文本 IP 地址。保存后立即重新探测并刷新显示。")}</div>
    <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
      <button class="btn" on:click={() => (showPubCfg = false)} disabled={pubCfgBusy}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={savePubCfg} disabled={pubCfgBusy}>{pubCfgBusy ? i18nTr("保存中…") : i18nTr("保存并刷新")}</button>
    </div>
  </Modal>
{/if}

{#if showLatencyCfg}
  <Modal title={$i18n("延迟检测地址")} width={480} onClose={() => (showLatencyCfg = false)}>
    <div class="form-group">
      <label class="form-label" for="latency-target">{$i18n("地址")}</label>
      <input id="latency-target" type="text" bind:value={latencyDraft} placeholder={latency.addr || i18nTr("host 或 host:port")} on:keydown={(e) => e.key === 'Enter' && saveLatencyCfg()} />
    </div>
    <div class="tip-text" style="margin-top:10px">
      {$i18n("留空则自动使用当前激活的 frp 服务器")}{latency.addr ? i18nTr("（当前探测：{0}）", [latency.addr]) : ''}{$i18n("。\n      支持域名 / IPv4 / IPv6；未写端口按 80 处理，IPv6 带端口请写成 [::1]:443。")}
    </div>
    <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
      <button class="btn" on:click={() => (showLatencyCfg = false)}>{$i18n("取消")}</button>
      <button class="btn" on:click={resetLatencyCfg}>{$i18n("恢复默认")}</button>
      <button class="btn btn-primary" on:click={saveLatencyCfg}>{$i18n("保存")}</button>
    </div>
  </Modal>
{/if}

{#if showProcModal}
  <Modal title={$i18n("进程列表")} width={720} onClose={() => (showProcModal = false)}>
    <div class="proc-hdr" style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px">
      <div class="tip-text" style="margin:0;flex:1">{$i18n("共")} {procs.length} {$i18n("个进程（读取自 /proc，内存为常驻集 RSS）。")}{procQuery ? i18nTr("筛选出 {0} 个", [procRows.length]) : ''}</div>
      <input type="text" class="hdr-search" bind:value={procQuery} placeholder={$i18n("搜索进程名 / PID / 状态（* 通配，/正则/）")} style="width:220px" />
    </div>
    <div style="max-height:60vh;overflow-y:auto;border:1px solid var(--bd);border-radius:var(--radius)">
      <table style="width:100%;border-collapse:collapse;font-size:12px">
        <thead>
          <tr style="text-align:left;color:var(--text3);border-bottom:1px solid var(--bd)">
            <th style="padding:8px 10px;cursor:pointer;user-select:none;white-space:nowrap" role="button" tabindex="0" on:click={() => sortByProc('pid')} on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortByProc('pid'); } }}>PID{sortIcon(procSort, 'pid')}</th>
            <th style="padding:8px 10px;cursor:pointer;user-select:none;white-space:nowrap" role="button" tabindex="0" on:click={() => sortByProc('name')} on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortByProc('name'); } }}>{$i18n("进程名")}{sortIcon(procSort, 'name')}</th>
            <th style="padding:8px 10px;cursor:pointer;user-select:none;white-space:nowrap" role="button" tabindex="0" on:click={() => sortByProc('state')} on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortByProc('state'); } }}>{$i18n("状态")}{sortIcon(procSort, 'state')}</th>
            <th style="padding:8px 10px;text-align:right;cursor:pointer;user-select:none;white-space:nowrap" role="button" tabindex="0" on:click={() => sortByProc('mem_mb')} on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortByProc('mem_mb'); } }}>{$i18n("内存 (MB)")}{sortIcon(procSort, 'mem_mb')}</th>
          </tr>
        </thead>
        <tbody>
          {#if procLoading}
            <tr><td colspan="4" style="padding:20px;text-align:center;color:var(--text3)">{$i18n("加载中…")}</td></tr>
          {:else if procRows.length === 0}
            <tr><td colspan="4" style="padding:20px;text-align:center;color:var(--text3)">{procs.length === 0 ? i18nTr("暂无进程数据") : i18nTr("无匹配进程")}</td></tr>
          {:else}
            {#each procRows as p}
              <tr style="border-bottom:1px solid var(--bd)">
                <td style="padding:6px 10px;font-family:var(--mono)">{p.pid}</td>
                <td style="padding:6px 10px;font-family:var(--mono)">{p.name}</td>
                <td style="padding:6px 10px">{procStateLabel(p.state)}</td>
                <td style="padding:6px 10px;text-align:right;font-family:var(--mono)">{p.mem_mb}</td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
    <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
      <button class="btn" on:click={() => (showProcModal = false)}>{$i18n("关闭")}</button>
    </div>
  </Modal>
{/if}

{#if showConnModal}
  <Modal title={$i18n("连接列表")} width={780} onClose={() => (showConnModal = false)}>
    <div class="proc-hdr" style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px">
      <div class="tip-text" style="margin:0;flex:1">{$i18n("共")} {conns.length} {$i18n("条 TCP/UDP 连接（读取自 /proc/net）。")}{connQuery ? i18nTr("筛选出 {0} 条", [connRows.length]) : ''}</div>
      <input type="text" class="hdr-search" bind:value={connQuery} placeholder={$i18n("搜索协议 / 状态 / 地址（* 通配，/正则/）")} style="width:220px" />
    </div>
    <div style="max-height:60vh;overflow-y:auto;border:1px solid var(--bd);border-radius:var(--radius)">
      <table style="width:100%;border-collapse:collapse;font-size:12px">
        <thead>
          <tr style="text-align:left;color:var(--text3);border-bottom:1px solid var(--bd)">
            <th style="padding:8px 10px;cursor:pointer;user-select:none;white-space:nowrap" role="button" tabindex="0" on:click={() => sortByConn('proto')} on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortByConn('proto'); } }}>{$i18n("协议")}{sortIcon(connSort, 'proto')}</th>
            <th style="padding:8px 10px;cursor:pointer;user-select:none;white-space:nowrap" role="button" tabindex="0" on:click={() => sortByConn('state')} on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortByConn('state'); } }}>{$i18n("状态")}{sortIcon(connSort, 'state')}</th>
            <th style="padding:8px 10px;cursor:pointer;user-select:none;white-space:nowrap" role="button" tabindex="0" on:click={() => sortByConn('local')} on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortByConn('local'); } }}>{$i18n("本地地址")}{sortIcon(connSort, 'local')}</th>
            <th style="padding:8px 10px;cursor:pointer;user-select:none;white-space:nowrap" role="button" tabindex="0" on:click={() => sortByConn('remote')} on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortByConn('remote'); } }}>{$i18n("远端地址")}{sortIcon(connSort, 'remote')}</th>
          </tr>
        </thead>
        <tbody>
          {#if connLoading}
            <tr><td colspan="4" style="padding:20px;text-align:center;color:var(--text3)">{$i18n("加载中…")}</td></tr>
          {:else if connRows.length === 0}
            <tr><td colspan="4" style="padding:20px;text-align:center;color:var(--text3)">{conns.length === 0 ? i18nTr("暂无连接数据") : i18nTr("无匹配连接")}</td></tr>
          {:else}
            {#each connRows as c}
              <tr style="border-bottom:1px solid var(--bd)">
                <td style="padding:6px 10px">{c.proto}</td>
                <td style="padding:6px 10px">{c.state}</td>
                <td style="padding:6px 10px;font-family:var(--mono)">{c.local}</td>
                <td style="padding:6px 10px;font-family:var(--mono)">{c.remote || '—'}</td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
    <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
      <button class="btn" on:click={() => (showConnModal = false)}>{$i18n("关闭")}</button>
    </div>
  </Modal>
{/if}

{#if showNatModal}
  <Modal title={$i18n("NAT 类型说明")} width={640} onClose={() => (showNatModal = false)}>
    <div class="tip-text" style="margin-bottom:12px">
      {$i18n("当前检测：")}<span style="color:{natCard.color};font-weight:600">{natCard.val}</span>{#if natType}{$i18n("（等级：")}{natType.grade}{$i18n("，公网映射")} {natInfo?.public_ip || '-'}）{:else}{$i18n("——可点击「重新检测」获取最新结果")}{/if}
    </div>
    <div class="nat-list">
      {#each NAT_TYPES as t (t.key)}
        <div class="nat-item" class:cur={natType && natType.key === t.key}>
          <div class="nat-item-h">
            <span class="nat-name">{t.en}<span class="nat-zh">（{t.zh}）</span></span>
            <span class="nat-grade" style="color:{t.color}">{t.grade}</span>
          </div>
          <div class="nat-row"><span class="nat-k">{$i18n("特点")}</span><span>{t.feat}</span></div>
          <div class="nat-row"><span class="nat-k">{$i18n("适用")}</span><span>{t.scene}</span></div>
        </div>
      {/each}
    </div>
    <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
      <button class="btn" disabled={natLoading} on:click={probeNat}>{natLoading ? i18nTr("检测中…") : i18nTr("重新检测")}</button>
      <button class="btn" on:click={() => (showNatModal = false)}>{$i18n("关闭")}</button>
    </div>
  </Modal>
{/if}

<style>
  /* KPI */
  .db-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:14px}
  .db-card{background:var(--bg3);border:1px solid var(--bd);border-radius:calc(var(--radius) + 4px);box-shadow:var(--shadow-card);min-width:0}
  .db-kpi{padding:14px 15px 12px;overflow:hidden;cursor:pointer;transition:border-color .2s,transform .2s}
  .db-kpi:hover{border-color:rgba(var(--accent-rgb),.4);transform:translateY(-1px)}
  .db-kpi:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
  .db-kpi.db-static{cursor:default}
  .db-kpi.db-static:hover{border-color:var(--bd);transform:none}
  .db-kpi-top{display:flex;align-items:center;gap:7px;color:var(--text3);font-size:11px}
  .db-kpi-top :global(svg){width:14px;height:14px;opacity:.8;flex-shrink:0}
  .db-delta{margin-left:auto;font-family:var(--mono);font-size:9.5px;padding:2px 5px;border-radius:4px;color:var(--green);background:rgba(var(--green-rgb),.09)}
  .db-kpi-val{display:flex;align-items:baseline;gap:5px;margin-top:8px;font-family:var(--mono);font-size:24px;font-weight:600;letter-spacing:-.02em;line-height:1}
  .db-kpi-val em{font-style:normal;font-size:11px;font-weight:500;color:var(--text3);font-family:var(--font)}
  .db-kpi-foot{display:flex;align-items:flex-end;justify-content:space-between;gap:8px;margin-top:9px}
  .db-kpi-note{font-size:10.5px;color:var(--text3);font-family:var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .db-spark{width:74px;height:26px;flex-shrink:0;opacity:.9}

  /* 主区域 */
  .db-main{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:14px;margin-bottom:14px;align-items:stretch}
  .db-chart{display:flex;min-width:0}
  .db-chart :global(.traffic-stat){flex:1;min-width:0}
  .db-card-pad{padding:16px 16px 15px}
  .db-card-h{display:flex;align-items:center;gap:8px;margin-bottom:12px;min-width:0}
  .db-card-h b{font-size:12.5px;font-weight:600;letter-spacing:-.01em;color:var(--text);white-space:nowrap}
  .db-card-h .db-sub{font-size:10.5px;color:var(--text3);font-family:var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .db-card-h .right{margin-left:auto;display:flex;align-items:center;gap:6px;flex-shrink:0}
  /* 系统负载标题：与流量统计卡片统一为「圆点 + 13.5px 标题 + 11px 副标题」 */
  .db-sys-h .db-title{display:flex;align-items:center;gap:8px;font-size:13.5px;font-weight:600;color:var(--text);white-space:nowrap;flex-shrink:0}
  .db-sys-h .db-sub{font-size:11px;font-weight:400;color:var(--text3);font-family:inherit}
  .db-channel-h{gap:6px}
  .db-channel-h b{flex-shrink:0}
  .db-channel-h .db-sub{flex-shrink:0}
  .db-channel-h :global(.custom-select){flex-shrink:0}
  .db-channel-h :global(.cs-trigger){padding:4px 8px;font-size:11.5px;border-radius:6px}
  .db-channel-h :global(.cs-arrow){width:13px;height:13px}
  .db-sys{display:flex;flex-direction:column}
  .db-sys-row{display:flex;align-items:center;gap:10px;padding:8px 0}
  .db-sys-row+.db-sys-row{border-top:1px dashed var(--bd)}
  .db-sys-row :global(svg){width:15px;height:15px;color:var(--text3);flex-shrink:0}
  .db-sys-lbl{width:52px;font-size:11px;color:var(--text2);flex-shrink:0}
  .db-progress{flex:1;height:6px;border-radius:99px;background:var(--bg4);overflow:hidden}
  .db-progress i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--accent),var(--blue));transition:width .5s}
  .db-progress.green i{background:linear-gradient(90deg,var(--green),var(--accent))}
  .db-sys-val{width:44px;text-align:right;font-family:var(--mono);font-size:11px;color:var(--text);flex-shrink:0}
  /* 速率/延迟/连接数带单位，数值列比百分比略宽 */
  .db-sys-metric .db-sys-val{width:64px}
  .db-sys-meta{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:auto;padding-top:12px;border-top:1px solid var(--bd)}
  .db-sys-cell{background:var(--bg2);border:1px solid var(--bd);border-radius:7px;padding:7px 9px;min-width:0}
  .db-sys-cell span{display:block;font-size:9.5px;color:var(--text3);margin-bottom:2px}
  .db-sys-cell b{font-size:10.5px;font-weight:500;font-family:var(--mono);color:var(--text2);display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .db-click{cursor:pointer}
  .db-click:hover{border-color:rgba(var(--accent-rgb),.45)}
  .db-click:focus-visible{outline:2px solid var(--accent);outline-offset:2px}

  /* 下半区 */
  .db-lower{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,2fr);gap:14px}
  .db-tun-row{display:flex;align-items:center;gap:9px;padding:8px 0}
  .db-tun-row+.db-tun-row{border-top:1px dashed var(--bd)}
  .db-tun-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
  .db-tun-name{font-size:11.5px;font-weight:600;color:var(--text);min-width:0}
  .db-tun-sub{font-size:9.5px;color:var(--text3);font-family:var(--mono);margin-top:1px}
  .db-tun-rate{margin-left:auto;font-family:var(--mono);font-size:10.5px;color:var(--text2);text-align:right;flex-shrink:0}
  .db-tun-rate span{display:block;font-size:9px;color:var(--text3);margin-top:1px}
  .db-log-line{display:flex;align-items:flex-start;gap:8px;padding:6px 0;font-size:10.5px;line-height:1.55}
  .db-log-line+.db-log-line{border-top:1px dashed var(--bd)}
  .db-log-time{font-family:var(--mono);color:var(--text3);font-size:9.5px;width:56px;flex-shrink:0;padding-top:1px}
  .db-log-level{width:40px;flex-shrink:0}
  .db-log-msg{color:var(--text2);min-width:0;word-break:break-word}
  .db-log-key{color:var(--accent)}
  .db-live{display:inline-flex;align-items:center;gap:6px;font-size:11px;color:var(--text2)}
  .db-dot{width:6px;height:6px;border-radius:50%;display:inline-block;background:var(--green);box-shadow:0 0 0 3px rgba(var(--green-rgb),.12)}
  .db-dot.pulse{animation:db-pulse 1.8s ease-in-out infinite}
  @keyframes db-pulse{0%,100%{opacity:1}50%{opacity:.35}}
  .db-mini-btn{width:24px;height:24px;border-radius:6px;border:1px solid transparent;background:none;color:var(--text3);display:grid;place-items:center;transition:.14s}
  .db-mini-btn:hover{color:var(--accent);background:var(--bg4);border-color:var(--bd)}
  .db-empty{font-size:12px;color:var(--text3);padding:12px 2px}

  /* NAT 弹窗 */
  .nat-list{display:flex;flex-direction:column;gap:10px;max-height:56vh;overflow-y:auto}
  .nat-item{border:1px solid var(--bd);border-radius:var(--radius);padding:10px 12px;background:var(--bg3)}
  .nat-item.cur{border-color:var(--accent);background:var(--accent-glow)}
  .nat-item-h{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:6px}
  .nat-name{font-weight:600;font-size:13px}
  .nat-zh{color:var(--text2);font-weight:500}
  .nat-grade{font-size:12px;font-weight:700;flex-shrink:0}
  .nat-row{display:flex;gap:8px;font-size:12px;color:var(--text2);line-height:1.6}
  .nat-k{color:var(--text3);flex-shrink:0}

  @media (max-width:1100px){
    .db-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}
    .db-main,.db-lower{grid-template-columns:minmax(0,1fr)}
  }
  @media (max-width:600px){
    .db-kpis{gap:8px}
    .db-kpi{padding:12px 13px}
    .db-kpi-val{font-size:20px}
    .db-spark{display:none}
    .db-card-pad{padding:14px}
    .db-sys-meta{grid-template-columns:1fr 1fr}
    .proc-hdr{flex-wrap:wrap}
    .proc-hdr .tip-text{flex:1 1 100%}
    .proc-hdr .hdr-search{width:100%!important}
  }
</style>
