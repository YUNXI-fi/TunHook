<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 创建/编辑 frpc 代理通道弹窗（参考 frp 官方文档：基础设置 / 进阶选项 / 日志设置）
  import Modal from './Modal.svelte';
  import Toggle from './Toggle.svelte';
  import PortScanModal from './PortScanModal.svelte';
  import CustomSelect from './CustomSelect.svelte';
  import InfoTip from './InfoTip.svelte';
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import {
    suggestProxyName,
    optional,
    validateHost,
    validatePort,
    validateDomainList
  } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';
  import { HOST_MODE_OPTIONS, composeFullDomain, splitFullDomain, ensureBindRecord, fetchServerDomainPicks } from '../lib/domainbind.js';
  import { onDestroy } from 'svelte';

  const proxyTypeOptions = [
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
    { value: 'http', label: 'HTTP' },
    { value: 'https', label: 'HTTPS' },
    { value: 'xtcp', label: i18nTr("XTCP（P2P 点对点）") },
    { value: 'stcp', label: i18nTr("STCP（安全加密）") }
  ];
  const hcTypeOptions = [
    { value: 'tcp', label: i18nTr("TCP（连接成功即健康）") },
    { value: 'http', label: i18nTr("HTTP（返回 2xx 即健康）") }
  ];
  const logLevelOptions = [
    { value: 'debug', label: 'debug' },
    { value: 'info', label: 'info' },
    { value: 'warn', label: 'warn' },
    { value: 'error', label: 'error' }
  ];
  const logDaysOptions = [
    { value: 7, label: i18nTr("7 天") },
    { value: 30, label: i18nTr("30 天") },
    { value: 90, label: i18nTr("90 天") },
    { value: 180, label: i18nTr("180 天") },
    { value: 365, label: i18nTr("365 天") }
  ];
  $: serverOptions = servers.length === 0
    ? [{ value: '', label: i18nTr("未配置服务器") }]
    : servers.map((s) => ({ value: s.name, label: `${s.name}${s.addr ? `（${s.addr}）` : ''}` }));

  export let mode = 'create'; // create | edit
  export let proxy = null;    // edit 时的 frpc 代理对象
  export let onClose = () => {};
  export let onSaved = () => {};
  export let initialIP = '';   // 创建时预填的本地 IP（来自端口扫描选择）
  export let initialPort = 0;  // 创建时预填的本地端口（来自端口扫描选择）
  export let initialName = ''; // 创建时预填的代理名称（来自端口扫描建议）
  export let servers = [];     // 已配置的 frps 服务器列表
  export let activeServer = ''; // 当前激活 frps 服务器名称

  let saving = false;
  let activePanel = 'basic';
  let showPortScan = false;
  let serverName = ''; // 表单中选择的 frps 服务器名称
  let domainPicks = []; // 解析到 frp 服务器 IP 的 DNS 域名（下拉选项）
  let dnsBase = '';     // 域名选择：候选根域名；CUSTOM_DOMAIN 表示「自定义域名」手动输入
  let hostMode = '@';   // 主机记录：'@' 直接用根域名，'sub' = 子域名前缀 + 根域名
  let subPrefix = '';   // 子域名前缀（仅 hostMode === 'sub'）
  let bodyEl;           // 表单内容容器，提交/切换面板时对其内部字段统一校验
  let localPortErr;     // 本地端口错误容器（输入在横向行内，错误显示在下方）
  let domainsErr;       // 自定义域名错误容器

  // 候选域名只覆盖「已解析到该 frp 服务器」的域名，用户自有但不在本项目
  // 「域名解析」里的域名（外部托管）必须留出口，故固定追加「自定义域名」项。
  const CUSTOM_DOMAIN = '__custom__';
  let picksLoaded = false; // 域名候选是否已拉取完成（无候选时据此回退「自定义域名」）
  $: domainOptions = [...domainPicks, { value: CUSTOM_DOMAIN, label: i18nTr("自定义域名（手动输入）") }];

  // 域名校验：自定义模式校验完整域名（可逗号分隔多个、支持通配）；
  // 候选 + 子域名模式校验前缀合法性；候选 + @ 模式无需输入
  function validateDomainsInput(raw) {
    if (dnsBase === CUSTOM_DOMAIN) return validateDomainList(raw, { wildcard: true });
    if (dnsBase && hostMode === 'sub') {
      const p = String(raw == null ? '' : raw).trim();
      if (!p) return i18nTr("请输入子域名前缀，如 web");
      if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(p)) {
        return i18nTr("「{0}」不是合法的子域名前缀（仅字母、数字、连字符）", [p]);
      }
      return '';
    }
    return '';
  }

  // frpc 代理表单（基础 / 进阶 / 日志）
  let fp = {
    name: '',
    type: 'tcp',
    local_ip: '127.0.0.1',
    local_port: 0,
    remote_port: 0,
    custom_domains: '',
    subdomain: '',
    http_user: '',
    http_password: '',
    secret_key: '',
    via_tunhook: true, // http 代理经 TunHook 反代，记录访客真实 IP（默认开启，关闭时直连）
    encryption: true,
    compression: true,
    bandwidth_limit: '',
    hc_enabled: false,
    hc_type: 'tcp',
    hc_interval: 10,
    hc_timeout: 3,
    hc_max_failed: 1,
    hc_path: '/',
    log_level: 'info',
    log_entries: 250, // frpc.log 保留行数（0=不限制）
    log_days: 30      // 客户端级日志保留天数（log.maxDays）
  };
  let proxyNameOriginal = '';

  // 就地冲突提示（GET /api/frpc/proxy/check）：保存时后端同样会拦截，这里只是让用户当场看见。
  let domainConflicts = [];    // 与既有代理重复的自定义域名（跨服务器比对）
  let portConflicts = [];      // 同一 frps 服务器内重复的远程端口
  let localPortListening = false; // 本地端口是否有本机服务监听（localPortChecked=false 时无意义）
  let localPortChecked = false;
  let conflictTimer = null;

  $: isEdit = mode === 'edit';
  $: frpcHttp = fp.type === 'http' || fp.type === 'https';
  $: frpcP2P = fp.type === 'stcp' || fp.type === 'xtcp';

  // 按「根域名 + 主机记录」拼完整域名写回 fp.custom_domains，让冲突检测与提交只依赖这一个字段。
  // 刻意不用响应式语句：它会与下面的「编辑态回填」互相依赖（回填读该字段、拼接写该字段），
  // 显式在变更处调用既无环，也更容易看出什么时候会改写用户输入。
  function syncComposedDomain() {
    if (!dnsBase || dnsBase === CUSTOM_DOMAIN) return;
    fp.custom_domains = composeFullDomain(dnsBase, hostMode, subPrefix);
    scheduleProxyCheck();
  }

  // 编辑态候选域名是异步到达的：拿到候选后把原域名拆成「根域名 + 主机记录」回填。
  // 匹配不到候选（域名不在本项目「域名解析」里）、或旧数据绑了多个域名（含逗号）时，
  // 落到「自定义域名」并原样保留，绝不静默改写用户原有域名
  $: if (domainPicks.length && !dnsBase && (fp.custom_domains || '').trim()) {
    const raw = fp.custom_domains.trim();
    const s = raw.includes(',') ? { root: '', mode: '@', prefix: '' } : splitFullDomain(raw, domainPicks);
    if (s.root) {
      dnsBase = s.root;
      hostMode = s.mode;
      subPrefix = s.prefix;
    } else {
      dnsBase = CUSTOM_DOMAIN;
    }
  }

  // 候选拉取完成却一个都没有（未配置「域名解析」，或该服务器地址下没有域名解析到它）时，
  // 只要已有域名就直接进「自定义域名」模式，避免原有域名藏在不可见处
  $: if (picksLoaded && !domainPicks.length && !dnsBase && (fp.custom_domains || '').trim()) {
    dnsBase = CUSTOM_DOMAIN;
  }

  // 编辑时预填 / 创建时应用扫描选择
  onMountEdit();

  async function onMountEdit() {
    // 初始化 Frps服务器 下拉：优先父级传入的激活服务器，其次从配置读取
    let cfgServers = servers;
    let cfgActive = activeServer;
    try {
      const d = await api('/api/frpc/config');
      if (d) {
        if (d.servers && d.servers.length > 0 && cfgServers.length === 0) cfgServers = d.servers;
        if (d.active_server) cfgActive = d.active_server;
        if (d.log_level) fp.log_level = d.log_level;
        if (d.log_entries > 0) fp.log_entries = d.log_entries;
        if (d.log_days > 0) fp.log_days = d.log_days;
      }
    } catch (e) { /* ignore */ }
    if (servers.length === 0 && cfgServers.length > 0) servers = cfgServers;
    const s0 = cfgServers.find((x) => x.name === cfgActive) || cfgServers[0];
    serverName = (s0 && s0.name) || cfgActive || '';

    if (mode === 'create') {
      if (initialIP) fp.local_ip = initialIP;
      if (initialPort) fp.local_port = initialPort;
      if (initialName && !fp.name.trim()) fp.name = initialName;
      scheduleProxyCheck();
      return;
    }
    if (!proxy) return;
    const p = proxy;
    fp.name = p.name || '';
    proxyNameOriginal = p.name || '';
    fp.type = p.type || 'tcp';
    fp.local_ip = p.local_ip || '127.0.0.1';
    fp.local_port = (p.real_local_port > 0 ? p.real_local_port : p.local_port) || 0;
    fp.remote_port = p.remote_port || 0;
    fp.custom_domains = p.custom_domains || '';
    fp.subdomain = p.subdomain || '';
    fp.http_user = p.http_user || '';
    fp.http_password = p.http_password || '';
    fp.secret_key = p.secret_key || '';
    fp.via_tunhook = !!p.via_tunhook;
    fp.encryption = p.encryption !== false;
    fp.compression = p.compression !== false;
    fp.bandwidth_limit = p.bandwidth_limit || '';
    // 编辑时按代理归属服务器预填（旧数据无归属=激活服务器）
    serverName = p.server || activeServer || serverName;
    const hc = p.health_check;
    fp.hc_enabled = !!(hc && hc.type);
    fp.hc_type = (hc && hc.type) || 'tcp';
    fp.hc_interval = (hc && hc.interval_seconds) || 10;
    fp.hc_timeout = (hc && hc.timeout_seconds) || 3;
    fp.hc_max_failed = (hc && hc.max_failed) || 1;
    fp.hc_path = (hc && hc.path) || '/';
    // HTTP/HTTPS 代理：按当前服务器地址加载“已解析到该服务器 IP”的域名候选
    if (fp.type === 'http' || fp.type === 'https') loadDomainPicks();
    scheduleProxyCheck();
  }

  // 加载“已解析到当前 frp 服务器 IP”的域名，作为域名候选
  async function loadDomainPicks() {
    domainPicks = [];
    picksLoaded = false;
    dnsBase = '';
    hostMode = '@';
    subPrefix = '';
    const cur = servers.find((x) => x.name === serverName);
    const addr = (cur && cur.addr) || '';
    if (!addr) {
      picksLoaded = true;
      return;
    }
    try {
      domainPicks = await fetchServerDomainPicks(addr);
    } catch (e) { /* ignore */ }
    picksLoaded = true;
  }

  // 切换「域名选择」：选到候选域名时重置主机记录为「主域名」并立即拼出完整域名；
  // 切到「自定义域名」时清空输入框——这是用户的显式选择，期待从空开始输入自己的域名。
  // （编辑态原域名匹配不到候选时的预填走「自动回填」分支，不经过这里，因此不会被清掉）
  function onDomainChange(e) {
    const v = (e && e.detail && e.detail.value) || '';
    hostMode = '@';
    subPrefix = '';
    if (v !== CUSTOM_DOMAIN) {
      syncComposedDomain();
    } else {
      fp.custom_domains = '';
      scheduleProxyCheck();
    }
  }

  // 切换 frps 服务器后重新加载域名候选（代理归属变了，远程端口冲突范围也随之变化）
  function onServerChange() {
    loadDomainPicks();
    scheduleProxyCheck();
  }

  // 切换代理类型：进入 HTTP/HTTPS 时加载域名候选，否则清空
  function onTypeChange(e) {
    const isHttp = e.detail.value === 'http' || e.detail.value === 'https';
    if (isHttp) {
      loadDomainPicks();
    } else {
      domainPicks = [];
      picksLoaded = true;
      dnsBase = '';
      hostMode = '@';
      subPrefix = '';
    }
    scheduleProxyCheck();
  }

  // 域名 / 远程端口 / 本地端口任一变化后防抖查询冲突。
  // 走防抖是因为自定义域名是逐字符输入的，无需每击键都请求。
  function scheduleProxyCheck() {
    clearTimeout(conflictTimer);
    conflictTimer = setTimeout(checkProxyConflicts, 400);
  }

  async function checkProxyConflicts() {
    // 域名选择/自定义输入与主机记录已就位，冲突检测与提交统一使用完整域名
    const domain = (fp.custom_domains || '').trim();
    const remotePort = Number(fp.remote_port) || 0;
    const localPort = Number(fp.local_port) || 0;
    if (!domain && !remotePort && !localPort) {
      domainConflicts = [];
      portConflicts = [];
      localPortChecked = false;
      return;
    }
    try {
      const qs = new URLSearchParams({
        domain,
        remote_port: String(remotePort),
        local_port: String(localPort),
        local_ip: (fp.local_ip || '').trim(),
        server: serverName || '',
        exclude: proxyNameOriginal || ''
      });
      const d = await api('/api/frpc/proxy/check?' + qs.toString());
      const cs = (d && d.conflicts) || [];
      domainConflicts = cs.filter((c) => c.kind === 'domain');
      portConflicts = cs.filter((c) => c.kind === 'remote_port');
      localPortListening = !!(d && d.local_port_listening);
      localPortChecked = !!(d && d.local_port_checked);
    } catch (e) { /* ignore：提示失败不影响正常填写 */ }
  }

  onDestroy(() => clearTimeout(conflictTimer));

  // 切换面板前先校验当前面板，防止错误值藏在其他面板被直接提交
  function switchPanel(name) {
    if (validateAll(bodyEl)) activePanel = name;
  }

  async function submit() {
    if (saving) return;
    // 格式校验：当前已挂载面板的地址/端口/域名字段统一拦截并就地提示
    if (!validateAll(bodyEl)) return;
    if (!fp.name.trim()) {
      toast(i18nTr("请填写代理名称"), 'error');
      return;
    }
    if (frpcHttp && !(fp.custom_domains || '').trim() && !(fp.subdomain || '').trim()) {
      toast(i18nTr("HTTP/HTTPS 代理需配置自定义域名或子域名"), 'error');
      return;
    }
    if (frpcP2P && !(fp.secret_key || '').trim()) {
      toast(i18nTr("STCP/XTCP 代理需填写 SecretKey 密钥"), 'error');
      return;
    }
    saving = true;
    const body = {
      proxy: {
        name: fp.name.trim(),
        type: fp.type,
        enabled: true,
        server: serverName || '', // 代理归属服务器（多实例：写入选中服务器的配置）
        local_ip: (fp.local_ip || '').trim() || '127.0.0.1',
        local_port: Number(fp.local_port) || 0,
        remote_port: Number(fp.remote_port) || 0,
        custom_domains: (fp.custom_domains || '').trim(),
        subdomain: (fp.subdomain || '').trim(),
        http_user: (fp.http_user || '').trim(),
        http_password: fp.http_password || '',
        secret_key: (fp.secret_key || '').trim(),
        via_tunhook: !!fp.via_tunhook,
        encryption: !!fp.encryption,
        compression: !!fp.compression,
        bandwidth_limit: (fp.bandwidth_limit || '').trim(),
        health_check: fp.hc_enabled
          ? {
              type: fp.hc_type,
              interval_seconds: Number(fp.hc_interval) || 10,
              timeout_seconds: Number(fp.hc_timeout) || 3,
              max_failed: Number(fp.hc_max_failed) || 1,
              path: (fp.hc_path || '/').trim()
            }
          : null
      },
      log_level: fp.log_level || 'info',
      log_entries: Number(fp.log_entries) || 0,
      log_days: Number(fp.log_days) || 0
    };
    try {
      // 多实例模式下代理直接写入所选服务器的配置（server 字段），不再切换默认服务器
      if (isEdit) {
        body.name = proxyNameOriginal;
        await api('/api/frpc/proxy/update', { method: 'POST', body });
        toast(i18nTr("frpc 代理已更新"));
      } else {
        await api('/api/frpc/proxy/create', { method: 'POST', body });
        toast(i18nTr("frpc 代理已创建"));
      }
      // HTTP/HTTPS 代理：域名若没解析到这台 frps，保存后自动补写「该隧道实际用到的那条主机记录」。
      // 写入失败不影响代理已创建/已更新的事实，单独提示
      if (frpcHttp) await ensureDomainRecord();
      onSaved();
      onClose();
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      saving = false;
    }
  }

  // 保存成功后按需补写解析记录：已解析（含被泛解析覆盖）、已存在同名同值记录都静默跳过；
  // 同名但值不同绝不覆盖（用户手工改过的东西不能悄悄改掉），只如实提示；
  // 域名不归本项目「域名解析」管理（外部托管）时什么都不做。
  async function ensureDomainRecord() {
    const full = (fp.custom_domains || '').trim();
    if (!full) return;
    const cur = servers.find((x) => x.name === serverName);
    const addr = (cur && cur.addr) || '';
    if (!addr) return;
    try {
      const r = await ensureBindRecord({ full, addr, options: domainPicks });
      if (r && r.written) {
        toast(i18nTr("已自动写入解析：{0} {1} {2}（{3}）", [r.written.rr, r.written.type, r.written.value, r.written.root]), 'success');
      } else if (r && r.skipped === 'conflict') {
        toast(i18nTr("未改写解析：{0} 已存在 {1} {2}，与本隧道目标不一致，请自行确认", [r.rr, r.existType, r.existValue]), 'error');
      }
    } catch (e) {
      toast(i18nTr("代理已保存，但解析记录写入失败：") + e.message, 'error');
    }
  }
</script>

<Modal title={isEdit ? i18nTr("编辑 frpc 代理") : i18nTr("创建 frpc 代理")} onClose={onClose}>
  <div class="tunnel-tabs">
    <button type="button" class="tunnel-tab" class:active={activePanel==='basic'} on:click={() => switchPanel('basic')}>{$i18n("基础设置")}</button>
    <button type="button" class="tunnel-tab" class:active={activePanel==='advanced'} on:click={() => switchPanel('advanced')}>{$i18n("进阶选项")}</button>
    <button type="button" class="tunnel-tab" class:active={activePanel==='log'} on:click={() => switchPanel('log')}>{$i18n("日志设置")}</button>
  </div>

  <div bind:this={bodyEl}>
  {#if activePanel === 'basic'}
    <div class="form-row">
      <div class="form-group">
        <span class="form-label">{$i18n("代理名称")} <span style="color:var(--red)">*</span></span>
        <input type="text" bind:value={fp.name} placeholder={$i18n("唯一标识，如 web / ssh")} />
      </div>
      <div class="form-group">
        <span class="form-label">{$i18n("Frps服务器")}</span>
        <CustomSelect bind:value={serverName} options={serverOptions} on:change={onServerChange} />
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <span class="form-label">{$i18n("本地 IP")}</span>
        <input type="text" bind:value={fp.local_ip} placeholder="127.0.0.1" on:input={scheduleProxyCheck} use:field={{ check: optional(validateHost) }} />
      </div>
      <div class="form-group">
        <span class="form-label">{$i18n("本地端口")} <span style="color:var(--red)">*</span></span>
        <div class="input-action-row">
          <input type="number" bind:value={fp.local_port} min="1" max="65535" placeholder={$i18n("例如 8080")} style="flex:1" on:input={scheduleProxyCheck} use:field={{ check: validatePort, errAt: () => localPortErr }} />
          <button type="button" class="btn btn-sm" on:click={() => (showPortScan = true)} title={$i18n("扫描本机端口")} style="white-space:nowrap">{$i18n("扫描")}</button>
        </div>
        <div class="field-err" bind:this={localPortErr} style="display:none"></div>
        {#if localPortChecked && !localPortListening}
          <div class="tip-text" style="color:var(--yellow)">{$i18n("本地端口当前无服务监听，代理可能启动失败（仅检查本机回环地址）")}</div>
        {/if}
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <span class="form-label">{$i18n("代理类型")}</span>
        <CustomSelect bind:value={fp.type} options={proxyTypeOptions} on:change={onTypeChange} />
      </div>
      {#if fp.type === 'tcp' || fp.type === 'udp'}
        <div class="form-group">
          <span class="form-label">{$i18n("远程端口（0=服务端自动分配）")}</span>
          <input type="number" bind:value={fp.remote_port} min="0" max="65535" placeholder={$i18n("0=自动分配，例如 6000")} style={portConflicts.length ? 'border-color:var(--red)' : ''} on:input={scheduleProxyCheck} use:field={{ check: (v) => validatePort(v, true) }} />
          {#if portConflicts.length}
            <div class="tip-text" style="color:var(--red)">
              {$i18n("该远程端口已被占用：")}{portConflicts.map((c) => `「${c.name}」`).join('、')}{$i18n("（同一 frps 服务器内不能重复）")}
            </div>
          {/if}
        </div>
      {/if}
      {#if fp.type === 'http'}
        <div class="form-group">
          <span class="form-label">{$i18n("访问认证（HTTP Basic）")}</span>
          <div style="display:flex;gap:6px">
            <input type="text" bind:value={fp.http_user} placeholder={$i18n("用户名")} />
            <input type="text" bind:value={fp.http_password} placeholder={$i18n("密码")} />
          </div>
        </div>
      {/if}
    </div>
    {#if frpcHttp}
      <div class="form-group">
        <div class="form-row">
          <div class="form-group" style="flex:1;margin-bottom:0">
            <label class="form-label" for="tm-bind-domain">{$i18n("域名选择")} <InfoTip text={$i18n("域名需解析到 frp 服务器（HTTP/HTTPS 代理必须配置域名或子域名）。候选只列出「已解析到该服务器」的域名；若域名不在本项目「域名解析」里（外部托管），请选「自定义域名」手动填写。")} /></label>
            <CustomSelect id="tm-bind-domain" bind:value={dnsBase} options={domainOptions} placeholder={$i18n("请选择域名")} on:change={onDomainChange} />
          </div>
          <!-- 右格常驻显示：与「代理类型 / 访问认证」等表单项同一套两列对齐；
               未选域名时也保留（选中候选后才有意义），选「自定义域名」时就地变成输入框，
               避免控件随模式增删导致整行塌陷、左右不对齐 -->
          <div class="form-group" style="flex:1;margin-bottom:0">
            {#if dnsBase === CUSTOM_DOMAIN}
              <label class="form-label" for="tm-custom-domain">{$i18n("域名")}</label>
              <input id="tm-custom-domain" type="text" bind:value={fp.custom_domains} placeholder={$i18n("例如 web.example.com")} style="{domainConflicts.length ? 'border-color:var(--red)' : ''}" on:input={scheduleProxyCheck} use:field={{ check: validateDomainsInput, errAt: () => domainsErr }} />
            {:else}
              <label class="form-label" for="tm-host-mode">{$i18n("主机记录")}</label>
              <CustomSelect id="tm-host-mode" bind:value={hostMode} options={HOST_MODE_OPTIONS.map((o) => ({ value: o.value, label: i18nTr(o.label) }))} on:change={syncComposedDomain} />
            {/if}
          </div>
        </div>
        {#if dnsBase && dnsBase !== CUSTOM_DOMAIN && hostMode === 'sub'}
          <div class="form-row">
            <div class="form-group" style="flex:1;margin-bottom:0">
              <label class="form-label" for="tm-sub-prefix">{$i18n("子域名前缀")}</label>
              <input id="tm-sub-prefix" type="text" bind:value={subPrefix} placeholder={$i18n("如 web")} style="{domainConflicts.length ? 'border-color:var(--red)' : ''}" on:input={syncComposedDomain} use:field={{ check: validateDomainsInput, errAt: () => domainsErr }} />
            </div>
            <div class="form-group" style="flex:1;margin-bottom:0">
              <label class="form-label" for="tm-picked-domain">{$i18n("域名")}</label>
              <input type="text" id="tm-picked-domain" readonly tabindex="-1" value={dnsBase} />
            </div>
          </div>
        {/if}
        <div class="field-err" bind:this={domainsErr} style="display:none"></div>
        {#if domainConflicts.length}
          <div class="tip-text" style="color:var(--red)">
            {$i18n("该域名已被占用：")}{domainConflicts.map((c) => `「${c.name}」`).join('、')}{$i18n("（frps 按域名路由，同域名会导致代理启动失败）")}
          </div>
        {/if}
      </div>
    {:else if frpcP2P}
      <div class="form-group">
        <span class="form-label">{$i18n("SecretKey 密钥")} <span style="color:var(--red)">*</span></span>
        <input type="text" bind:value={fp.secret_key} placeholder={$i18n("访问端需配置相同密钥，例如 abc123")} />
        <div class="tip-text">
          {fp.type === 'xtcp'
            ? i18nTr("XTCP：P2P 打洞穿透，成功后流量不经 frps 直接通信（受 NAT 类型影响，成功率不保证）")
            : i18nTr("STCP：经 frps 中转的安全加密通道，更稳定可靠")}
          {$i18n("，访问端 frpc 需以相同类型与密钥配置 visitor 访问本代理")}
        </div>
      </div>
    {/if}
  {:else if activePanel === 'advanced'}
    <div class="divider" style="border-top:none;margin-top:0;padding-top:0">
      {#if fp.type === 'http'}
        <div class="form-group">
          <span class="form-label">{$i18n("开启 TunHook 转发")}</span>
          <div class="toggle-line">
            <div class="tip-text">{$i18n("开启后流量先经 TunHook 反代层，读取访客真实 IP；关闭时 frpc 直连本地服务（无法记录访客 IP）。")}</div>
            <Toggle bind:checked={fp.via_tunhook} />
          </div>
        </div>
      {/if}
      <div class="form-group">
        <span class="form-label">{$i18n("健康检查")}</span>
        <div class="toggle-line">
          <div class="tip-text">{$i18n("定期探测本地服务可用性，连续失败后将代理标记为不可用")}</div>
          <Toggle bind:checked={fp.hc_enabled} />
        </div>
      </div>
      {#if fp.hc_enabled}
        <div class="form-row" style="margin-top:14px">
          <div class="form-group">
            <span class="form-label">{$i18n("检查类型")}</span>
            <CustomSelect bind:value={fp.hc_type} options={hcTypeOptions} />
          </div>
          <div class="form-group">
            <span class="form-label">{$i18n("检查间隔（秒）")}</span>
            <input type="number" bind:value={fp.hc_interval} min="1" max="3600" />
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <span class="form-label">{$i18n("超时（秒）")}</span>
            <input type="number" bind:value={fp.hc_timeout} min="1" max="60" />
          </div>
          <div class="form-group">
            <span class="form-label">{$i18n("连续失败次数")}</span>
            <input type="number" bind:value={fp.hc_max_failed} min="1" max="100" />
          </div>
        </div>
        {#if fp.hc_type === 'http'}
          <div class="form-group">
            <span class="form-label">{$i18n("HTTP 检查路径")}</span>
            <input type="text" bind:value={fp.hc_path} placeholder="/health" />
          </div>
        {/if}
      {/if}
    </div>
    <div style="margin-top:14px">
      <div class="form-group">
        <span class="form-label">{$i18n("传输加密")}</span>
        <div class="toggle-line">
          <div class="tip-text">{$i18n("与 frp 服务端通信内容加密传输")}</div>
          <Toggle bind:checked={fp.encryption} />
        </div>
      </div>
      <div class="form-group">
        <span class="form-label">{$i18n("传输压缩")}</span>
        <div class="toggle-line">
          <div class="tip-text">{$i18n("与 frp 服务端通信内容压缩传输")}</div>
          <Toggle bind:checked={fp.compression} />
        </div>
      </div>
    </div>
    <div class="form-group">
      <div class="form-label-row">
        <span class="form-label">{$i18n("带宽限制（该代理）")}</span>
        <InfoTip text={$i18n("transport.bandwidthLimit：单位 MB 或 KB，0 表示不限制")} />
      </div>
      <input type="text" bind:value={fp.bandwidth_limit} placeholder={$i18n("如 10MB / 512KB，空=不限速")} />
    </div>
  {:else}
    <div class="form-row">
      <div class="form-group">
        <div class="form-label-row">
          <span class="form-label">{$i18n("日志输出级别（frpc 全局）")}</span>
          <InfoTip text={$i18n("frp 客户端全局日志级别（log.level），运行日志可在 FRP服务器 页面查看。")} />
        </div>
        <CustomSelect bind:value={fp.log_level} options={logLevelOptions} />
      </div>
      <div class="form-group">
        <div class="form-label-row">
          <span class="form-label">{$i18n("日志存储条数")}</span>
          <InfoTip text={$i18n("frpc.log 日志文件保留的行数，超出后自动截断；0=不限制。")} />
        </div>
        <input type="number" bind:value={fp.log_entries} min="0" max="100000" placeholder={$i18n("0=不限制")} />
      </div>
    </div>
    <div class="form-group">
      <div class="form-label-row">
        <span class="form-label">{$i18n("日志存储时间")}</span>
        <InfoTip text={$i18n("超出保存时间的日志将被自动清理。")} />
      </div>
      <CustomSelect bind:value={fp.log_days} options={logDaysOptions} />
    </div>
  {/if}
  </div>

  <div style="margin-top:16px;display:flex;justify-content:flex-end;gap:8px">
    <button type="button" class="btn" on:click={onClose}>{$i18n("取消")}</button>
    <button type="button" class="btn btn-primary" on:click={submit} disabled={saving}>
      {saving ? i18nTr("保存中...") : (isEdit ? i18nTr("保存修改") : i18nTr("创建代理"))}
    </button>
  </div>
</Modal>

{#if showPortScan}
  <PortScanModal targetIP={fp.local_ip || '127.0.0.1'} onClose={() => (showPortScan = false)} onPick={(it) => {
    fp.local_port = it.port;
    if (!fp.name.trim()) fp.name = suggestProxyName(it);
    if (it.local_addr && it.local_addr !== '0.0.0.0' && it.local_addr !== '::') fp.local_ip = it.local_addr;
    showPortScan = false;
    scheduleProxyCheck();
  }} />
{/if}

<style>
  /* 进阶选项中的开关：与提示文字同一行，靠右对齐 */
  .toggle-line {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .toggle-line .tip-text {
    flex: 1;
    min-width: 0;
    margin-top: 0;
  }
  .toggle-line :global(.toggle-switch) {
    flex-shrink: 0;
    margin-left: auto;
  }
</style>
