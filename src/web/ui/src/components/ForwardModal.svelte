<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 创建/编辑转发规则弹窗（TCP/UDP/HTTP/HTTPS/统一网关 + 进阶/日志/创建桌面图标）
  import Modal from './Modal.svelte';
  import Toggle from './Toggle.svelte';
  import CustomSelect from './CustomSelect.svelte';
  import InfoTip from './InfoTip.svelte';
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import { parseFwdKey, validatePort, validateDomain, validateHost } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';
  import { onDestroy } from 'svelte';

  const protocolOptions = [
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
    { value: 'http', label: 'HTTP' },
    { value: 'https', label: 'HTTPS' },
    { value: 'gateway', label: i18nTr("统一网关") }
  ];
  const logLevelOptions = [
    { value: '', label: i18nTr("跟随全局") },
    { value: 'DEBUG', label: 'DEBUG' },
    { value: 'INFO', label: 'INFO' },
    { value: 'WARN', label: 'WARN' },
    { value: 'ERROR', label: 'ERROR' }
  ];
  const retentionUnitOptions = [
    { value: 'days', label: i18nTr("天") },
    { value: 'hours', label: i18nTr("小时") }
  ];
  const deskTypeOptions = [
    { value: 'iframe', label: i18nTr("桌面窗口（iframe）") },
    { value: 'url', label: i18nTr("浏览器标签页（url）") }
  ];
  const deskVisibilityOptions = [
    { value: true, label: i18nTr("所有用户可见") },
    { value: false, label: i18nTr("仅管理员可见") }
  ];
  $: certDomainOptions = [{ value: '', label: i18nTr("-- 选择已导入/申请的证书域名 --") }, ...certList.map((c) => ({ value: c.domain, label: i18nTr("{0}（{1}，至 {2}）", [c.domain, c.issuer || '未知', c.not_after]) }))];

  export let mode = 'create';
  export let rule = null; // edit 时的转发规则对象
  export let settingsData = null;
  export let prefill = null; // create 模式初始值（来自端口扫描）：{protocol, local_port, local_addr, description}；注意 local_addr 是「服务所在主机 IP」=转发目标，不是本机监听地址
  export let onClose = () => {};
  export let onSaved = () => {};

  let saving = false;
  let activePanel = 'basic';
  let formEl; // 表单根元素，提交/切换面板时对其内部字段统一校验
  let portOccupied = false; // 手动输入目标端口时本机端口被占用提示
  let checkTimer = null;    // 目标端口占用检查防抖
  let listenPortOccupied = false; // 监听端口已被本机其他程序占用（占用则规则启动失败）
  let listenPortTimer = null;     // 监听端口占用检查防抖
  let origLocalPort = 0;          // 编辑时的原监听端口，用于跳过「被自己占用」的误报

  // 判断是否为回环地址（127.0.0.1 / ::1 / localhost）
  function isLoopback(ip) {
    const s = String(ip || '').trim().toLowerCase();
    return s === '127.0.0.1' || s === '::1' || s === 'localhost';
  }

  // 表单状态
  let f = {
    description: '',
    protocol: 'tcp',
    local_addr: '0.0.0.0',
    local_port: 0,
    remote_addr: '',
    remote_port: 0,
    domain: '',
    name: '',
    source_prefix: '',
    root_prefixes: '',
    path_prefix: '',
    auto_detect: false,
    tls_enable: false,
    cert_pem: '',
    key_pem: '',
    rate_limit: 0,
    max_connections: 0,
    proxy_protocol: false,
    tls_source: false,
    udp_session_timeout: 0,
    udp_max_sessions: 0,
    udp_max_block_len: 0,
    log_level: '',
    channel_log_entries: 0,
    access_log_entries: 0,
    // 日志存储时间（小时，0=跟随全局；前端以 天/小时 录入）
    log_retention_hours: 0,
    // 进阶设置（访问密码保护）
    access_password: ''
  };
  // 日志存储时间录入单位（天/小时），与 log_retention_hours 双向换算
  let retentionUnit = 'hours';
  let retentionValue = 0;

  // 桌面图标
  let desk = { enabled: false, name: '', type: 'iframe', all_users: true, icon: '' };
  let deskLoaded = false;
  let deskTask = null;      // {task_id}
  let deskProgress = null;  // 任务进度快照
  let deskIconFile = null;  // 待上传的文件
  let deskIconPrev = '';    // 待上传文件的本地预览 URL
  let faviconList = [];
  let faviconWarnings = [];

  // 监听网卡列表（仅 TCP/UDP 协议生效）
  let ifaces = [];
  // 选项展开规则：
  // - 纯内网网卡：eth0（192.168.1.5）
  // - 纯公网网卡（PPPoE 直连，ipv4 被后端回填为公网 IP）：eth0（公网 1.2.3.4）
  // - 公网+内网双 IP 网卡：展开为两个选项，允许绑定任一地址
  $: ifaceOptions = [
    { value: '0.0.0.0', label: i18nTr("自动（所有网卡 0.0.0.0）") },
    ...ifaces.flatMap((i) => {
      const pub = i.public_ipv4 || '';
      const priv = i.ipv4 && i.ipv4 !== pub ? i.ipv4 : '';
      const opts = [];
      if (pub) opts.push({ value: pub, label: i18nTr("{0}（公网 {1}）", [i.name, pub]) });
      if (priv) opts.push({ value: priv, label: pub ? i18nTr("{0}（内网 {1}）", [i.name, priv]) : `${i.name}（${priv}）` });
      return opts;
    })
  ];
  async function loadIfaces() {
    try { ifaces = (await api('/api/network/interfaces') || []).filter((i) => i.ipv4); } catch (e) { /* 忽略 */ }
  }
  loadIfaces();

  // 证书库（HTTPS 协议选择）
  let certList = [];
  let certDomainSelect = '';
  let subDomain = '';
  let subDomainError = '';

  $: isEdit = mode === 'edit';
  $: isTcp = f.protocol === 'tcp';
  $: isUdp = f.protocol === 'udp';
  $: isHttp = f.protocol === 'http';
  $: isHttps = f.protocol === 'https';
  $: isGateway = f.protocol === 'gateway';
  $: needPort = isTcp || isUdp;
  $: needDomain = isHttp || isHttps;
  $: isTlsTunnel = isTcp && f.tls_enable;
  // 目标地址/端口仅 TCP/UDP 必填（与旧校验口径一致）；HTTP/HTTPS/网关留空走后端默认
  $: remoteAddrCheck = needPort ? validateHost : optional(validateHost);
  $: remotePortCheck = needPort ? validatePort : optional(validatePort);

  // 默认端口
  $: httpDefault = (settingsData && settingsData.forward && settingsData.forward.http_default_port) || 18080;
  $: httpsDefault = (settingsData && settingsData.forward && settingsData.forward.https_default_port) || 14430;
  // HTTP/HTTPS 协议不手动填监听端口（只读显示默认端口）
  $: displayLocalPort = needPort ? f.local_port : (isHttps ? httpsDefault : isHttp ? httpDefault : 0);

  // 日志存储时间：录入值（retentionValue + retentionUnit）→ 小时（log_retention_hours）
  $: f.log_retention_hours = retentionUnit === 'days' ? (Number(retentionValue) || 0) * 24 : (Number(retentionValue) || 0);

  // 编辑时预填
  onMountEdit();

  // 端口扫描结果预填（create 模式，同步执行保证首帧生效）
  function applyPrefill() {
    if (mode !== 'create' || !prefill) return;
    const p = prefill;
    if (p.protocol === 'tcp' || p.protocol === 'udp') f.protocol = p.protocol;
    if (p.local_port) f.local_port = p.local_port;
    // 扫描条目的 local_addr 语义是「服务所在主机 IP」（即转发目标）：本机扫描为监听 IP，
    // 局域网/固定 IP 扫描为对端主机 IP。监听地址必须恒为 0.0.0.0（与手动新建一致），
    // 否则把对端主机 IP（如 192.168.1.11）当成本机监听地址会导致 bind: cannot assign requested address
    const host = (p.local_addr || '').trim();
    if (host && host !== '0.0.0.0' && host !== '::' && host !== '::0') {
      f.remote_addr = host;
    } else if (host) {
      // 本机通配监听的服务，目标走回环即可
      f.remote_addr = '127.0.0.1';
    }
    // 描述自动填充：优先级 网页标题 → 进程 → 服务（保留原始文本，允许中文）
    if (p.description && !f.description.trim()) f.description = p.description;
    autoFillTarget();
    scheduleListenPortCheck(); // 预填的监听端口也要检查（autoFillTarget 可能刚把它换掉）
  }
  applyPrefill();

  // 自动填充目标地址/目标端口，并处理端口占用：
  // - 目标地址：监听地址为回环 → 127.0.0.1；其他局域网地址 → 对应地址
  // - 目标端口：使用监听端口（回环直连场景直接使用本地端口，不检查占用）
  // - 非回环（真实转发）：目标端口在本机被占用时，自动将监听端口换为高位随机端口
  // 注意：不能用 $: 响应式的 needPort（脚本同步阶段尚未求值），需直接按 f.protocol 判断
  async function autoFillTarget() {
    if (mode !== 'create') return;
    const proto = String(f.protocol || '').toLowerCase();
    if (proto !== 'tcp' && proto !== 'udp') return;
    const la = (f.local_addr || '').trim();
    if (la && la !== '0.0.0.0' && la !== '::' && la !== '::0') {
      if (!f.remote_addr.trim()) f.remote_addr = isLoopback(la) ? '127.0.0.1' : la;
    }
    if (!f.remote_port && f.local_port) f.remote_port = f.local_port;
    if (isLoopback(f.remote_addr) || !f.remote_port || f.local_port !== f.remote_port) return;
    try {
      const d = await api('/api/ports/check?port=' + f.remote_port);
      if (d && d.occupied) {
        const fr = await api('/api/ports/free?prefer=' + f.remote_port);
        if (fr && fr.port && fr.port !== f.remote_port) {
          const old = f.local_port;
          f.local_port = fr.port;
          toast(i18nTr("端口 {0} 已被占用，监听端口已自动调整为 {1}", [old, fr.port]), 'success');
        }
      }
    } catch (e) { /* ignore */ }
  }

  // 手动输入目标端口：防抖检查本机端口占用（回环直连模式不检查）
  function onRemotePortInput(e) {
    const v = e.target.value;
    clearTimeout(checkTimer);
    if (!v || !needPort || isLoopback(f.remote_addr)) {
      portOccupied = false;
      return;
    }
    checkTimer = setTimeout(() => checkOccupied(Number(v)), 400);
  }

  async function checkOccupied(port) {
    if (!port || port < 1 || port > 65535 || isLoopback(f.remote_addr)) {
      portOccupied = false;
      return;
    }
    try {
      const d = await api('/api/ports/check?port=' + port);
      portOccupied = !!(d && d.occupied);
    } catch (e) {
      portOccupied = false;
    }
  }

  // 监听端口占用检查：该端口已被任意进程监听时，规则启动会失败。
  // 编辑态且端口未改动时必须跳过——此时端口正由本规则自己监听，检查必然判为「占用」。
  function scheduleListenPortCheck() {
    clearTimeout(listenPortTimer);
    listenPortTimer = setTimeout(() => checkListenPort(Number(f.local_port)), 400);
  }

  async function checkListenPort(port) {
    if (!port || port < 1 || port > 65535 || (isEdit && port === origLocalPort)) {
      listenPortOccupied = false;
      return;
    }
    try {
      const d = await api('/api/ports/check?port=' + port);
      listenPortOccupied = !!(d && d.occupied);
    } catch (e) {
      listenPortOccupied = false;
    }
  }

  onDestroy(() => {
    clearTimeout(checkTimer);
    clearTimeout(listenPortTimer);
  });

  async function onMountEdit() {
    if (mode !== 'edit' || !rule) return;
    // 先等网卡选项加载完，保证规则里的绑定地址能在下拉中命中选中项
    await loadIfaces();
    const r = rule;
    const pk = parseFwdKey(r.key);
    f.description = r.description || '';
    f.protocol = pk.protocol || 'tcp';
    // pk.local 对 tcp/udp/http/https 是 "addr:port"，对 gateway 是纯名字
    if (pk.protocol === 'gateway' || !pk.local) {
      f.local_addr = pk.protocol === 'gateway' ? '' : '0.0.0.0';
    } else {
      // IPv4 取 : 前的 IP 部分，IPv6 用方括号包裹
      const m = pk.local.match(/^\[(.+)\]:(\d+)$/);
      if (m) f.local_addr = m[1];
      else f.local_addr = pk.local.split(':')[0];
    }
    // local_addr 保持原样——网卡有公网 IP 的选项 value 就是公网 IP，
    // edit 时 pk.local 里解出来的地址直接命中对应选项，不需要特殊映射
    f.remote_addr = pk.remote ? pk.remote.split(':')[0] : '';
    f.remote_port = pk.remote ? parseInt(pk.remote.split(':')[1] || '0') : 0;
    f.domain = r.domain || pk.domain || '';
    f.name = r.name || pk.name || '';
    f.source_prefix = r.source_prefix || '';
    f.root_prefixes = r.root_prefixes || '';
    f.path_prefix = r.path_prefix || '';
    f.auto_detect = !!r.auto_detect;
    f.tls_enable = !!r.tls_enable;
    f.rate_limit = r.rate_limit || 0;
    f.max_connections = r.max_connections || 0;
    f.proxy_protocol = !!r.proxy_protocol;
    f.tls_source = !!r.tls_source;
    f.udp_session_timeout = r.udp_session_timeout || 0;
    f.udp_max_sessions = r.udp_max_sessions || 0;
    f.udp_max_block_len = r.udp_max_block_len || 0;
    f.log_level = r.log_level || '';
    f.channel_log_entries = r.channel_log_entries || 0;
    f.access_log_entries = r.access_log_entries || 0;
    f.log_retention_hours = r.log_retention_hours || 0;
    f.access_password = r.access_password || '';
    // 日志存储时间换算为录入单位（优先 天）
    retentionUnit = (f.log_retention_hours % 24 === 0) ? 'days' : 'hours';
    retentionValue = retentionUnit === 'days' ? (f.log_retention_hours / 24) : f.log_retention_hours;
    if (pk.local && pk.local.includes(':')) f.local_port = parseInt(pk.local.split(':')[1] || '0');
    else f.local_port = 0;
    origLocalPort = f.local_port; // 记下原端口：等于该值时说明端口未改动，无需做占用检查
    // 桌面图标配置
    try {
      const d = await api('/api/desktop/icon?key=' + encodeURIComponent(r.key));
      if (d) {
        desk = { enabled: !!d.enabled, name: d.name || '', type: d.type || 'iframe', all_users: d.all_users !== false, icon: d.icon || '' };
      }
      deskLoaded = true;
    } catch (e) { /* ignore */ }
  }

  function onProtocolChange() {
    f.local_port = 0;
    f.tls_enable = false;
  }

  // HTTP/HTTPS 从证书库选择
  $: if (isHttps) loadCerts();
  async function loadCerts() {
    if (certList.length) return;
    try {
      const d = await api('/api/cert/list');
      if (d) certList = d || [];
    } catch (e) { /* ignore */ }
  }
  function onCertSelect() {
    const c = certList.find((x) => x.domain === certDomainSelect);
    if (c) {
      f.domain = c.domain;
      if (c.domain.startsWith('*.')) {
        subDomain = '';
        subDomainError = '';
      }
    }
  }
  function validateSubDomain() {
    const c = certList.find((x) => x.domain === certDomainSelect);
    if (c && c.domain.startsWith('*.')) {
      const base = c.domain.slice(2);
      if (!subDomain.endsWith('.' + base)) {
        subDomainError = i18nTr("子域名必须以 ") + base + i18nTr(" 结尾");
      } else {
        subDomainError = '';
      }
    }
  }

  // ---- 桌面图标 ----
  function onDeskEnabledChange() {
    if (!desk.enabled) {
      deskTask = null;
      deskProgress = null;
    }
  }

  async function fetchFavicons() {
    try {
      const d = await api('/api/desktop/favicon', { method: 'POST', body: { addr: f.remote_addr, port: f.remote_port } });
      faviconList = (d && d.icons) || [];
      faviconWarnings = (d && d.warnings) || [];
      toast(i18nTr("已获取 ") + faviconList.length + i18nTr(" 个网页图标"));
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  function chooseFavicon(ic) {
    // data URI → Blob/File，作为图标文件随表单上传（服务端统一裁剪压缩）
    try {
      const m = ic.data.match(/^data:([^;]+);base64,(.+)$/);
      if (m) {
        const bin = atob(m[2]);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        deskIconFile = new File([bytes], 'favicon.png', { type: m[1] });
      }
    } catch (e) { /* ignore */ }
    desk.icon = ic.source || i18nTr("已选择网页图标");
  }

  function onIconFileChange(e) {
    const file = e.target.files && e.target.files[0];
    if (file) {
      deskIconFile = file;
      if (deskIconPrev) URL.revokeObjectURL(deskIconPrev);
      deskIconPrev = URL.createObjectURL(file);
    }
  }

  let deskTimer = null;
  async function pollDeskTask() {
    if (!deskTask || !deskTask.task_id) return;
    try {
      const d = await api('/api/desktop/task?task_id=' + encodeURIComponent(deskTask.task_id));
      if (d) {
        deskProgress = d;
        if (d.status === 'running') {
          clearTimeout(deskTimer);
          deskTimer = setTimeout(pollDeskTask, 1500);
        } else if (d.status === 'done') {
          toast(i18nTr("桌面图标操作完成"), 'success');
        } else if (d.status === 'failed') {
          toast(i18nTr("桌面图标操作失败: ") + (d.error || ''), 'error');
        }
      }
    } catch (e) { /* ignore */ }
  }

  async function saveDeskIcon() {
    if (!isEdit || !rule) return;
    const fd = new FormData();
    fd.append('key', rule.key);
    fd.append('enabled', String(desk.enabled));
    fd.append('name', desk.name);
    fd.append('type', desk.type);
    fd.append('all_users', String(desk.all_users));
    if (deskIconFile) fd.append('icon', deskIconFile);
    try {
      const resp = await fetch(apiBaseOf() + '/api/desktop/icon', { method: 'POST', body: fd });
      const j = await resp.json();
      if (!j || j.success === false) throw new Error((j && j.error) || i18nTr("保存桌面图标失败"));
      const d = j.data || {};
      if (d.task_id) {
        deskTask = { task_id: d.task_id };
        deskProgress = null;
        pollDeskTask();
      } else {
        toast(d.install_msg || i18nTr("桌面图标配置已保存"), 'success');
      }
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  function apiBaseOf() {
    return typeof window !== 'undefined' && window.location.pathname.match(/^(\/app\/[^/]+)/) ? window.location.pathname.match(/^(\/app\/[^/]+)/)[1] : '';
  }

  // ---- 保存 ----
  // 切换设置面板前先校验当前面板内的字段，防止错误值藏在其他面板被直接提交
  function switchPanel(p) {
    if (validateAll(formEl)) activePanel = p;
  }

  async function submit(e) {
    e.preventDefault();
    if (saving) return;
    // 格式校验：已挂载面板中的地址/端口/域名字段统一拦截并就地提示
    if (!validateAll(formEl)) return;
    if (isGateway && !f.name.trim()) {
      toast(i18nTr("统一网关模式必须填写路径名称"), 'error');
      return;
    }
    if (isGateway && f.path_prefix && !f.path_prefix.startsWith('/')) {
      toast(i18nTr("后端路径前缀必须以 / 开头（如 /app/canvasboard）"), 'error');
      return;
    }
    // 进阶设置校验（与服务端一致）
    if ((f.access_password || '').length > 128) { toast(i18nTr("访问密码长度不能超过 128 个字符"), 'error'); return; }
    saving = true;
    const body = {
      protocol: f.protocol,
      local_addr: f.local_addr || '0.0.0.0',
      local_port: needPort ? f.local_port : 0,
      remote_addr: f.remote_addr,
      remote_port: f.remote_port,
      domain: f.domain,
      name: f.name,
      source_prefix: f.source_prefix,
      root_prefixes: f.root_prefixes,
      path_prefix: f.path_prefix,
      auto_detect: f.auto_detect,
      description: f.description,
      tls_enable: isTlsTunnel,
      cert_pem: f.cert_pem,
      key_pem: f.key_pem,
      rate_limit: f.rate_limit,
      max_connections: f.max_connections,
      proxy_protocol: f.proxy_protocol,
      tls_source: f.tls_source,
      udp_session_timeout: f.udp_session_timeout,
      udp_max_sessions: f.udp_max_sessions,
      udp_max_block_len: f.udp_max_block_len,
      log_level: f.log_level,
      channel_log_entries: f.channel_log_entries,
      access_log_entries: f.access_log_entries,
      log_retention_hours: f.log_retention_hours,
      access_password: f.access_password || ''
    };
    try {
      if (isEdit) {
        body.key = rule.key;
        await api('/api/forward/update', { method: 'POST', body });
        toast(i18nTr("转发规则已更新"));
      } else {
        await api('/api/forward/start', { method: 'POST', body });
        toast(i18nTr("转发规则已创建"));
      }
      if (isEdit && deskLoaded) {
        await saveDeskIcon();
      }
      onSaved();
      onClose();
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      saving = false;
    }
  }
</script>

<Modal title={isEdit ? i18nTr("编辑转发规则") : i18nTr("添加转发规则")} onClose={onClose} width={780}>
  <form on:submit={submit} bind:this={formEl}>
    <div class="tunnel-tabs">
      <button type="button" class="tunnel-tab" class:active={activePanel==='basic'} on:click={() => switchPanel('basic')}>{$i18n("基础配置")}</button>
      {#if needPort || isTcp}
        <button type="button" class="tunnel-tab" class:active={activePanel==='advanced'} on:click={() => switchPanel('advanced')}>{$i18n("进阶设置")}</button>
      {/if}
      <button type="button" class="tunnel-tab" class:active={activePanel==='log'} on:click={() => switchPanel('log')}>{$i18n("日志设置")}</button>
      {#if isEdit}
        <button type="button" class="tunnel-tab" class:active={activePanel==='desktop'} on:click={() => switchPanel('desktop')}>{$i18n("创建图标")}</button>
      {/if}
    </div>

    {#if activePanel === 'basic'}
      <!-- 统一两列布局：左右各 flex:1 五五开，gap 使用全局 14px -->
      <div class="form-row">
        <div class="form-group" style="flex:1;min-width:0">
          <label class="form-label">{$i18n("描述")}</label>
          <input type="text" bind:value={f.description} placeholder={$i18n("输入描述信息")} />
        </div>
        <div class="form-group" style="flex:1;min-width:0">
          <label class="form-label">{$i18n("协议")}</label>
          <CustomSelect bind:value={f.protocol} options={protocolOptions} on:change={onProtocolChange} />
        </div>
      </div>
      {#if needPort}
        <div class="form-row">
          <div class="form-group" style="flex:1;min-width:0">
            <label class="form-label">{$i18n("监听网卡")}</label>
            {#if ifaces.length}
              <CustomSelect bind:value={f.local_addr} options={ifaceOptions} />
            {:else}
              <input type="text" value="自动（未发现网卡）" disabled style="background:var(--bg3);color:var(--text3)" />
            {/if}
          </div>
          <div class="form-group" style="flex:1;min-width:0">
            <label class="form-label">{$i18n("监听端口")}{#if listenPortOccupied}<span style="color:var(--red);font-weight:700">{$i18n("（端口占用）")}</span>{/if}</label>
            <input type="number" bind:value={f.local_port} min="0" max="65535" placeholder={$i18n("监听端口")} style={listenPortOccupied ? 'border-color:var(--red)' : ''} on:input={scheduleListenPortCheck} use:field={{ check: (v) => validatePort(v, true) }} />
            {#if listenPortOccupied}
              <div class="tip-text" style="color:var(--red)">{$i18n("该端口已被本机其他程序占用，转发规则将启动失败")}</div>
            {/if}
          </div>
        </div>
      {:else if isGateway}
        <div class="form-row">
          <div class="form-group" style="flex:1;min-width:180px">
            <label class="form-label">{$i18n("网关路径名称")}</label>
            <input type="text" bind:value={f.name} maxlength="64" placeholder={$i18n("仅字母和数字")} />
            <div class="tip-text">{$i18n("访问路径: /app/TunHook/proxy/")}{f.name || i18nTr("名称")}</div>
          </div>
        </div>
      {:else}
        <div class="form-row">
          <div class="form-group" style="flex:1;min-width:0">
            <label class="form-label">{$i18n("描述")}</label>
            <input type="text" bind:value={f.description} placeholder={$i18n("输入描述信息")} />
          </div>
          <div class="form-group" style="flex:1;min-width:0">
            <label class="form-label">{$i18n("监听端口")}</label>
            <input type="number" value={displayLocalPort} readonly style="background:var(--bg3);color:var(--text3)" />
          </div>
        </div>
      {/if}

      {#if needDomain}
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">{$i18n("域名")}</label>
            <input type="text" bind:value={f.domain} placeholder={$i18n("例如 example.com 或 *.example.com")} use:field={{ check: (v) => validateDomain(v, { wildcard: true }) }} />
          </div>
          {#if isHttps}
            <div class="form-group">
              <label class="form-label">{$i18n("证书域名")}</label>
              <CustomSelect bind:value={certDomainSelect} options={certDomainOptions} on:change={onCertSelect} />
            </div>
          {/if}
        </div>
      {/if}

      <div class="form-row">
        <div class="form-group" style="flex:1;min-width:0">
          <label class="form-label">{$i18n("目标地址")}</label>
          <input type="text" bind:value={f.remote_addr} placeholder="127.0.0.1" use:field={{ check: remoteAddrCheck }} />
        </div>
        <div class="form-group" style="flex:1;min-width:0">
          <label class="form-label">
            {$i18n("目标端口")}
            {#if portOccupied}<span style="color:var(--red);font-weight:700">{$i18n("（端口占用）")}</span>{/if}
          </label>
          <input type="number" bind:value={f.remote_port} min="1" max="65535" placeholder={$i18n("端口")} style={portOccupied ? 'border-color:var(--red)' : ''} on:input={onRemotePortInput} use:field={{ check: remotePortCheck }} />
        </div>
      </div>

      {#if isGateway}
        <div class="form-group">
          <label class="form-label">{$i18n("源路径前缀")}</label>
          <input type="text" bind:value={f.source_prefix} placeholder={$i18n("可选，如 /app/canvasboard（自动检测时自动填充）")} />
        </div>
        <div class="form-group">
          <label class="form-label">{$i18n("根相对路径前缀")}</label>
          <input type="text" bind:value={f.root_prefixes} placeholder={$i18n("可选，逗号分隔，如 /api,/_next")} />
        </div>
        <div class="form-row">
          <div class="form-group" style="flex:1">
            <label class="form-label">{$i18n("后端路径前缀")}</label>
            <input type="text" bind:value={f.path_prefix} placeholder={$i18n("可选，如 /app/canvasboard")} />
          </div>
          <div class="form-group" style="display:flex;justify-content:flex-end;margin-bottom:0">
            <label class="form-label" style="margin-right:8px;align-self:center">{$i18n("自动检测路径")}</label>
            <Toggle bind:checked={f.auto_detect} />
          </div>
        </div>
      {/if}

      {#if isTcp}
        <div class="form-row" style="align-items:center">
          <div class="form-group" style="flex:1">
            <label class="form-label">{$i18n("访问端 TLS（HTTPS 自签名证书）")}</label>
            <div class="tip-text">{$i18n("监听端口以 HTTPS(TLS) 方式监听，自动生成自签名证书，解密后转发到内网 HTTP 服务")}</div>
          </div>
          <div class="form-group" style="display:flex;justify-content:flex-end;margin-bottom:0">
            <Toggle bind:checked={f.tls_enable} />
          </div>
        </div>
      {/if}
    {:else if activePanel === 'advanced'}
      {#if isTcp}
        <div class="form-group">
          <label class="form-label">{$i18n("访问限速")}</label>
          <div style="display:flex;gap:8px;align-items:center">
            <input type="number" bind:value={f.rate_limit} min="0" max="1048576" placeholder={$i18n("0=不限速")} style="flex:1" />
            <span style="color:var(--text3);font-size:12px;white-space:nowrap">{$i18n("KB/s / 每连接")}</span>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">{$i18n("TCP 单端口最大连接数")}</label>
          <input type="number" bind:value={f.max_connections} min="0" max="1000000" placeholder={$i18n("默认 256")} />
        </div>
        <div class="form-row" style="align-items:center;margin-top:8px">
          <div class="form-group" style="flex:1;margin-bottom:0">
            <label class="form-label">{$i18n("源端 TLS")}</label>
            <div class="tip-text">{$i18n("以 TLS 方式连接源站（内网目标服务为 HTTPS 时开启）")}</div>
          </div>
          <div class="form-group" style="margin-bottom:0"><Toggle bind:checked={f.tls_source} /></div>
        </div>
      {:else if isUdp}
        <div class="form-group">
          <label class="form-label">{$i18n("会话超时（毫秒）")}</label>
          <input type="number" bind:value={f.udp_session_timeout} min="0" max="3600000" placeholder={$i18n("默认 30000（30 秒）")} />
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">{$i18n("单端口最大会话数")}</label>
            <input type="number" bind:value={f.udp_max_sessions} min="0" max="65535" placeholder={$i18n("默认 32")} />
          </div>
          <div class="form-group">
            <label class="form-label">{$i18n("最大块长度")}</label>
            <input type="number" bind:value={f.udp_max_block_len} min="1" max="65507" placeholder={$i18n("默认 1500")} />
          </div>
        </div>
      {/if}

      <!-- ===== 进阶设置区域：访问密码 ===== -->
      <div class="divider" style="margin-top:16px"></div>
      <div class="form-group">
        <label class="form-label">{$i18n("访问密码")}</label>
        <input type="password" bind:value={f.access_password} placeholder={$i18n("留空则禁用访问密码保护")} />
        <div class="tip-text">{$i18n("留空则禁用访问密码保护；设置后访问该通道链接需输入密码")}</div>
      </div>
    {:else if activePanel === 'log'}
      <div class="form-row">
        <div class="form-group">
          <div class="form-label-row">
            <label class="form-label">{$i18n("日志输出级别")}</label>
            <InfoTip text={$i18n("仅记录不低于该级别的通道日志；选择「跟随全局」则不限制。")} />
          </div>
          <CustomSelect bind:value={f.log_level} options={logLevelOptions} />
        </div>
        <div class="form-group">
          <div class="form-label-row">
            <label class="form-label">{$i18n("日志存储时间")}</label>
            <InfoTip text={$i18n("该通道日志的保留时间，支持以 天/小时 为单位；0=跟随全局（保存时自动换算为小时）。")} />
          </div>
          <div style="display:flex;gap:6px;align-items:center">
            <input type="number" bind:value={retentionValue} min="0" max="3650" placeholder={$i18n("0=跟随全局")} style="flex:1" />
            <CustomSelect bind:value={retentionUnit} options={retentionUnitOptions} width="auto" />
          </div>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">{$i18n("通道日志存储条数")}</label>
          <input type="number" bind:value={f.channel_log_entries} min="0" max="100000" placeholder={$i18n("0=跟随全局")} />
        </div>
        <div class="form-group">
          <label class="form-label">{$i18n("访问日志存储条数")}</label>
          <input type="number" bind:value={f.access_log_entries} min="0" max="100000" placeholder={$i18n("0=跟随全局")} />
        </div>
      </div>
    {:else}
      <!-- 创建桌面图标 -->
      <div class="form-row" style="align-items:center">
        <div class="form-group" style="flex:1">
          <label class="form-label">{$i18n("创建桌面图标")}</label>
          <div class="tip-text">{$i18n("在 fnOS 桌面生成该转发规则的快捷入口")}</div>
        </div>
        <div class="form-group" style="display:flex;justify-content:flex-end;margin-bottom:0">
          <Toggle bind:checked={desk.enabled} on:change={onDeskEnabledChange} />
        </div>
      </div>
      {#if desk.enabled}
        <div class="desk-form-grid" style="display:flex;gap:16px;flex-wrap:wrap">
          <div style="flex:1;display:flex;flex-direction:column;gap:12px;min-width:240px">
            <div class="form-group" style="margin-bottom:0">
              <label class="form-label">{$i18n("打开方式")}</label>
              <CustomSelect bind:value={desk.type} options={deskTypeOptions} />
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label class="form-label">{$i18n("桌面访问（即可见性）")}</label>
              <CustomSelect bind:value={desk.all_users} options={deskVisibilityOptions} />
            </div>
            <div class="form-group" style="margin-bottom:0">
              <label class="form-label">{$i18n("图标名称")}</label>
              <input type="text" bind:value={desk.name} placeholder={$i18n("例如: 我的影视库")} />
            </div>
          </div>
          <div style="flex:1;min-width:240px">
            <label class="form-label">{$i18n("图标")}</label>
            <div class="desk-icon-pick">
              <label class="desk-icon-preview" title={$i18n("点击选择图标（PNG/JPG）")}>
                <input type="file" accept="image/png,image/jpeg" on:change={onIconFileChange} hidden />
                {#if deskIconPrev}
                  <img src={deskIconPrev} alt={$i18n("图标预览")} />
                {:else if desk.icon}
                  <img src={apiBaseOf() + '/desk/icon/' + encodeURIComponent(desk.icon)} alt={$i18n("图标预览")} />
                {:else}
                  <img src={apiBaseOf() + '/static/fnos.svg'} alt={$i18n("默认图标")} />
                {/if}
              </label>
              <div class="desk-icon-actions">
                <label class="desk-icon-btn">
                  <input type="file" accept="image/png,image/jpeg" on:change={onIconFileChange} hidden />
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                  {$i18n("选择图标")}
                </label>
                <button type="button" class="btn btn-sm" on:click={fetchFavicons} disabled={!f.remote_addr}>{$i18n("获取图标")}</button>
              </div>
            </div>
            {#if faviconList.length > 0}
              <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
                {#each faviconList as ic}
                  <button type="button" class="btn btn-sm" style="padding:4px" on:click={() => chooseFavicon(ic)} title={ic.source || i18nTr("使用该图标")}>
                    <img src={ic.data} alt="favicon" style="width:24px;height:24px;border-radius:4px" />
                  </button>
                {/each}
              </div>
            {/if}
            {#if faviconWarnings.length > 0}
              <div style="margin-top:6px;font-size:11px;color:var(--yellow)">{faviconWarnings.join('；')}</div>
            {/if}
            {#if desk.icon}
              <div style="margin-top:8px;font-size:12px;color:var(--text3)">{$i18n("已选择图标:")} {desk.icon}</div>
            {/if}
          </div>
        </div>
        {#if deskTask}
          <div style="margin-top:12px;padding:10px 14px;background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius)">
            <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--text2);margin-bottom:6px">
              <span>{deskProgress ? (deskProgress.step || i18nTr("执行中...")) : i18nTr("等待任务...")}</span>
              <span class="mono">{deskProgress ? deskProgress.percent + '%' : ''}</span>
            </div>
            <div class="progress-track"><div class="progress-fill" style="width:{deskProgress ? deskProgress.percent : 0}%"></div></div>
            {#if deskProgress && deskProgress.logs && deskProgress.logs.length}
              <div style="margin-top:8px;font-family:var(--mono);font-size:11px;color:var(--text3);max-height:120px;overflow-y:auto">
                {#each deskProgress.logs.slice(-8) as l}<div>{l}</div>{/each}
              </div>
            {/if}
          </div>
        {/if}
      {/if}
    {/if}

    <div style="margin-top:16px;display:flex;justify-content:flex-end;gap:8px">
      <button type="button" class="btn" on:click={onClose}>{$i18n("取消")}</button>
      <button type="submit" class="btn btn-primary" disabled={saving}>{saving ? i18nTr("保存中...") : (isEdit ? i18nTr("保存修改") : i18nTr("添加规则"))}</button>
    </div>
  </form>
</Modal>

