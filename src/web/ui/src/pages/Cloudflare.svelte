<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // Cloudflare Tunnel 接入页（多隧道实例）
  //
  // 定位：第三种接入方式，只做 HTTP(S) 域名入口。一条「实例」= 一份凭证 + 一个 cloudflared 进程
  // + 一张路由表，多条实例可同时运行，各自独立启停、独立日志、独立本地回源与连接协议。
  // 三种托管方式，区别在隧道凭证/目标的来源：
  //   - token 模式：用户在 Cloudflare 后台建隧道、配路由，本页只托管连接器；
  //   - api 模式：隧道、Public Hostname 路由与 DNS 记录都由本页通过 Cloudflare API 维护；
  //   - quick 模式（临时入口）：匿名 tunnel，免账号免 Token，域名由 Cloudflare 每次启动随机下发。
  import { onMount, onDestroy } from 'svelte';
  import { api, apiBase } from '../lib/api.js';
  import { highlightLog, pollVisible, reverseLines, validateDomain, validateURL, validateHost, validatePort, fmtBytes } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';
  import { toast } from '../lib/stores.js';
  import Modal from '../components/Modal.svelte';
  import ConfirmModal from '../components/ConfirmModal.svelte';
  import CustomSelect from '../components/CustomSelect.svelte';
  import DnsAccountsModal from '../components/DnsAccountsModal.svelte';

  let loading = true;
  // 后端统一状态对象：内核 + 全部实例（所有写接口都回吐它，前端一次拿全）
  let st = { installed: false, version: '', instances: [] };

  // 能力边界提示：用户主动关闭后记住，不再每次进入页面都展示
  const BOUNDARY_DISMISS_KEY = 'tunhook-cf-boundary-dismissed';
  let showBoundary = !localStorage.getItem(BOUNDARY_DISMISS_KEY);
  function dismissBoundary() {
    showBoundary = false;
    localStorage.setItem(BOUNDARY_DISMISS_KEY, '1');
  }

  // ---- 弹窗 A：新建 / 编辑隧道 ----
  let showModal = false;
  let editId = '';        // 空=新建；非空=编辑该实例（托管方式不可改，见弹窗内注释）
  let editInst = null;    // 编辑时的实例快照：用于回显与「是否需要重启」的判断
  let cfgMode = 'token';
  let rebindOpen = false; // 编辑 api 实例时，「账号/发布域名/隧道」行是否展开为重新绑定
  let nameInput = '';
  let tokenInput = '';
  let protocol = 'http2';
  let local = { scheme: 'http', addr: '127.0.0.1', port: 0 };
  let bindAccount = '';
  let zones = [];
  let bindZone = '';
  let tunnelId = '';      // 空=新建云端隧道；非空=复用该隧道
  let tunnels = [];
  let loadingZones = false;
  let loadingTunnels = false;
  let formErr = '';
  let saving = false;
  let cfAccounts = [];    // 「域名解析」中的 Cloudflare 账号
  let showAccounts = false; // 「新增账号」：复用域名解析的账户管理弹窗

  // ---- 弹窗 B：日志 ----
  let logInst = null;
  let logText = '';
  let logBusy = false;

  // ---- 停止 / 删除确认 ----
  // 停止会断开与 Cloudflare 的连接，临时入口还会因此换掉访问地址，需要二次确认
  let stopTarget = null;
  let stopBusy = false;
  let delInst = null;
  let delBusy = false;

  // ---- 卡片 3：域名路由 ----
  let routeInstId = '';
  let routeForm = { hostname: '', service: '', path: '' };
  let routePrefillFor = '';  // 已用哪个实例的本地地址预填过「本地服务」，避免轮询覆盖用户输入
  let routeBusy = false;
  let refreshing = false;
  // 输入框都在横向 flex 行内，错误渲染到行外 errAt 节点
  let routeRowEl;    // 域名路由横向行容器，添加路由时统一校验
  let routeHostErr;  // 路由域名错误节点
  let routeSvcErr;   // 本地服务错误节点
  let modalFormEl;   // 新建/编辑隧道弹窗表单容器，提交时统一校验
  let localAddrErr;  // 本地地址错误节点
  let localPortErr;  // 本地端口错误节点

  // ---- 内核（全局共用一份二进制） ----
  let installing = false;
  let uploading = false;
  let progress = { percent: -1, stage: '', done: 0, total: 0 };
  let installErr = '';
  let fileInput;
  let actingId = '';        // 正在启停的实例 ID：防止同一行重复点击

  let pollTimer = null;

  const protocolOpts = [
    { value: 'http2', label: i18nTr("HTTP/2（TCP 7844 · 推荐）") },
    { value: 'quic', label: 'QUIC（UDP 7844）' },
    { value: 'auto', label: i18nTr("自动协商") }
  ];

  const modeOpts = [
    { value: 'token', label: i18nTr("Token 托管") },
    { value: 'api', label: i18nTr("API 全托管") },
    { value: 'quick', label: i18nTr("临时入口") }
  ];

  const schemeOpts = [
    { value: 'http', label: 'HTTP' },
    { value: 'https', label: 'HTTPS' }
  ];

  // modeLabel 托管方式中文名（徽章 / 弹窗标题共用）
  function modeLabel(m) {
    if (m === 'api') return i18nTr("API 全托管");
    if (m === 'quick') return i18nTr("临时入口");
    return i18nTr("Token 托管");
  }

  // 三种托管方式用不同色徽章区分：api=信息色 / token=中性色 / quick=警示色
  function modeBadge(m) {
    if (m === 'api') return 'badge-info';
    if (m === 'quick') return 'badge-warn';
    return 'badge-off';
  }

  // urlHost 访问地址的展示文本：去掉协议前缀，列表里只保留主机名
  function urlHost(u) {
    return String(u || '').replace(/^https?:\/\//, '');
  }

  // protocolLabel 连接协议短名（表格列用，取值与 protocolOpts 一致）
  function protocolLabel(p) {
    if (p === 'quic') return 'QUIC';
    if (p === 'auto') return i18nTr("自动");
    return 'HTTP/2';
  }

  // accessHint 访问地址为空时的说明（鼠标悬停可见），按托管方式给出不同缘由
  function accessHint(inst) {
    if (inst.mode === 'quick') return i18nTr("连接器尚未拿到临时域名（启动后由 Cloudflare 下发）");
    if (inst.mode === 'api') return i18nTr("该隧道还没有域名路由，可在下方「域名路由」中添加");
    return i18nTr("Token 托管的访问域名在 Cloudflare 后台配置，本页无从得知");
  }

  // stateColor 启停按钮着色：全站统一规则（与「内网穿透」「端口转发」「STUN」一致）
  //   运行中且已连上边缘=绿 / 运行中未连上边缘、已暂停=黄（过渡或受限态）/ 未运行=灰
  // 与状态列的 badge 配色同源，避免同一行出现两套颜色语义；未运行的具体原因由 title 区分
  function stateColor(inst) {
    if (!inst.running) return 'var(--text3)';
    if (inst.paused) return 'var(--yellow)';
    return inst.ready ? 'var(--green)' : 'var(--yellow)';
  }

  // localServiceOf 实例本地回源拼成的服务地址（端口未配置时为空）
  function localServiceOf(inst) {
    const l = (inst && inst.local) || {};
    const port = Number(l.port) || 0;
    if (port <= 0) return '';
    return (l.scheme || 'http') + '://' + (l.addr || '127.0.0.1') + ':' + port;
  }

  // ---- 状态轮询 ----
  // 注意：load 只写 st，绝不回写弹窗表单（表单字段都是独立变量），
  // 因此轮询不会覆盖用户尚未保存的输入，但列表与状态照常刷新。
  async function load() {
    try {
      const d = await api('/api/cloudflare/status');
      if (d) st = d;
    } catch (e) {
      /* 轮询失败静默 */
    } finally {
      loading = false;
    }
  }

  // ---- 派生值 ----
  $: instances = st.instances || [];
  $: runningCount = instances.filter((i) => i.running).length;
  $: readyCount = instances.filter((i) => i.running && i.ready).length;
  // 已装版本 == 官方最新版：此时没有可下载的内容，按钮转为状态展示并禁用
  $: kernelUpToDate = !!(st.installed && st.version && st.latest && st.version === st.latest);
  $: apiInstances = instances.filter((i) => i.mode === 'api' && i.api && i.api.bound);
  // 选中的实例被删除或不再是 api 实例时，回落到第一条，避免下拉框停在空值上
  $: if (apiInstances.length && !apiInstances.some((i) => i.id === routeInstId)) routeInstId = apiInstances[0].id;
  $: routeInst = apiInstances.find((i) => i.id === routeInstId) || null;
  $: routeList = routeInst ? routeInst.routes || [] : [];
  $: accountOpts = cfAccounts.map((a) => ({ value: a.name, label: a.name }));
  $: zoneOpts = zones.map((z) => ({ value: z.name, label: z.name }));
  $: tunnelOpts = buildTunnelOpts(tunnels, editInst);

  // 切换实例时用它的本地地址预填一次「本地服务」，之后不再覆盖用户输入
  $: if (routeInst && routePrefillFor !== routeInst.id) {
    routeForm = { hostname: '', service: localServiceOf(routeInst), path: '' };
    routePrefillFor = routeInst.id;
  }

  // 隧道下拉：新建 + 账号下的已有隧道；已被其它实例接管的禁用，本实例自己占用的标注为「当前隧道」并可继续复用
  function buildTunnelOpts(list, editing) {
    const cur = editing && editing.api ? editing.api.tunnelId : '';
    return [{ value: '', label: i18nTr("新建隧道") }].concat((list || []).map((t) => {
      if (t.id === cur) return { value: t.id, label: i18nTr("当前隧道（") + t.name + '）' };
      if (t.usedBy) return { value: t.id, label: t.name + i18nTr("（已被 ") + t.usedBy + i18nTr(" 使用）"), disabled: true };
      return { value: t.id, label: t.name };
    }));
  }

  // ---- 弹窗 A：打开与提交 ----

  function resetForm() {
    nameInput = '';
    tokenInput = '';
    protocol = 'http2';
    local = { scheme: 'http', addr: '127.0.0.1', port: 0 };
    bindAccount = '';
    zones = [];
    bindZone = '';
    tunnelId = '';
    tunnels = [];
    formErr = '';
  }

  function openCreate() {
    editId = '';
    editInst = null;
    cfgMode = 'token';
    rebindOpen = false;
    resetForm();
    showModal = true;
    loadAccounts();
  }

  function openEdit(inst) {
    editId = inst.id;
    editInst = inst;
    cfgMode = inst.mode || 'token';
    rebindOpen = false;   // 重新绑定需用户显式展开，默认收起
    resetForm();
    nameInput = inst.name || '';
    protocol = inst.protocol || 'http2';
    const l = inst.local || {};
    local = { scheme: l.scheme || 'http', addr: l.addr || '127.0.0.1', port: Number(l.port) || 0 };
    bindAccount = (inst.api && inst.api.dnsAccount) || '';
    bindZone = (inst.api && inst.api.zoneName) || '';
    showModal = true;
    loadAccounts();
  }

  // openRebind 展开 api 实例的重新绑定区域：拉账号域名与云端隧道，并把当前隧道设为默认选中项
  async function openRebind() {
    rebindOpen = true;
    tunnelId = (editInst && editInst.api && editInst.api.tunnelId) || '';
    await loadAccounts();
    await loadZones();
  }

  async function loadAccounts() {
    try {
      const list = await api('/api/dns/list');
      cfAccounts = (list || []).filter((a) => a.provider === 'Cloudflare');
      // 只有一个账号时直接选中，省去一次无意义的选择
      if (!bindAccount && cfAccounts.length === 1) bindAccount = cfAccounts[0].name;
    } catch (e) {
      /* 账号列表读不到时由弹窗内的提示文案兜底，不打断弹窗 */
    }
  }

  // 账户管理弹窗关闭后回填：新增的账号可能正是要选的那个，重拉列表并按需加载域名
  async function onAccountsChanged() {
    await loadAccounts();
    if (bindAccount) await loadZones();
  }

  // loadZones 拉取所选账号下的域名列表；域名尽量保留已选值（其次编辑实例的绑定值）
  async function loadZones(want = '') {
    zones = [];
    tunnels = [];
    if (!bindAccount) {
      bindZone = '';
      return;
    }
    const keep = want || bindZone || ((editInst && editInst.api && editInst.api.zoneName) || '');
    loadingZones = true;
    try {
      zones = (await api('/api/dns/domains?account=' + encodeURIComponent(bindAccount))) || [];
    } catch (e) {
      toast(i18nTr("读取域名列表失败: ") + e.message, 'error');
    } finally {
      loadingZones = false;
    }
    if (keep && zones.some((z) => z.name === keep)) bindZone = keep;
    else bindZone = zones.length === 1 ? zones[0].name : '';
    if (bindZone) await loadTunnels();
  }

  function onAccountChange(v) {
    bindAccount = v;
    bindZone = '';   // 换账号后旧域名必然失效
    loadZones();
  }

  function onZoneChange(v) {
    bindZone = v;
    loadTunnels();
  }

  function onModeChange(v) {
    cfgMode = v;
    if (v === 'api' && bindAccount) loadZones();
  }

  async function loadTunnels() {
    tunnels = [];
    if (!bindAccount || !bindZone) return;
    loadingTunnels = true;
    try {
      const d = await api('/api/cloudflare/tunnels?account=' + encodeURIComponent(bindAccount) + '&zone=' + encodeURIComponent(bindZone));
      tunnels = (d && d.tunnels) || [];
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      loadingTunnels = false;
    }
    // 待复用的隧道已不在云端列表里（被删除）：回落到「新建隧道」，避免提交一个不存在的隧道
    if (tunnelId && !tunnels.some((t) => t.id === tunnelId)) tunnelId = '';
  }

  // submit 新建 / 更新实例；失败时错误留在弹窗内（不关弹窗，便于就地修改重试）
  async function submit() {
    formErr = '';
    // 格式校验：弹窗内本地地址/端口统一拦截并就地提示
    if (!validateAll(modalFormEl)) return;
    const port = Number(local.port) || 0;
    // 重新绑定只在「新建 api 实例」或「编辑 api 且已展开重新绑定」时发生
    const rebind = cfgMode === 'api' && (!editId || rebindOpen);

    if (cfgMode === 'quick' && (port < 1 || port > 65535)) {
      formErr = i18nTr("请填写本地端口（1-65535）：临时入口以它为回源");
      return;
    }
    if (!editId && cfgMode === 'token' && !tokenInput.trim()) {
      formErr = i18nTr("请粘贴隧道 Token（Cloudflare Zero Trust → Networks → Tunnels）");
      return;
    }
    if (rebind) {
      if (!cfAccounts.length) {
        formErr = i18nTr("尚未配置 Cloudflare 账号，请先点击「新增账号」添加一个");
        return;
      }
      if (!bindAccount) {
        formErr = i18nTr("请选择 Cloudflare 账号");
        return;
      }
      if (!bindZone) {
        formErr = i18nTr("请选择发布域名");
        return;
      }
    }

    saving = true;
    try {
      if (!editId) {
        const body = {
          name: nameInput.trim(),
          mode: cfgMode,
          protocol,
          localScheme: local.scheme,
          localAddr: local.addr,
          localPort: port,
          autoStart: true,
          start: true
        };
        if (cfgMode === 'token') body.token = tokenInput.trim();
        if (rebind) {
          body.account = bindAccount;
          body.zone = bindZone;
          body.tunnelId = tunnelId;
          body.tunnelName = nameInput.trim();
        }
        const d = await api('/api/cloudflare/instances', { method: 'POST', body });
        if (d && d.status) st = d.status;
        const name = nameInput.trim() || i18nTr("未命名");
        showModal = false;
        if (d && d.warning) toast(d.warning, 'error');
        else toast(i18nTr("隧道实例「") + name + i18nTr("」已创建并启用"), 'success');
      } else {
        const body = {
          name: nameInput.trim(),
          protocol,
          localScheme: local.scheme,
          localAddr: local.addr,
          localPort: port
        };
        // 留空表示不修改 Token：显式提交空串会被后端当成「清空凭证」
        if (cfgMode === 'token' && tokenInput.trim()) body.token = tokenInput.trim();
        if (rebind) {
          body.account = bindAccount;
          body.zone = bindZone;
          body.tunnelId = tunnelId;
          body.tunnelName = nameInput.trim();
        }
        const d = await api('/api/cloudflare/instances/' + editId + '/update', { method: 'POST', body });
        if (d && d.status) st = d.status;
        showModal = false;
        // 是否需要重启由后端判定并回吐（applied），前端不再自己重算一遍规则
        if (d && d.warning) {
          toast(d.warning, 'error');
        } else if (d && d.applied === 'restart') {
          toast(i18nTr("已保存，实例已重启生效") + (cfgMode === 'quick' ? i18nTr("（临时入口会拿到新访问地址）") : ''), 'success');
        } else if (d && d.applied === 'origin') {
          toast(i18nTr("已保存，回源已即时切换（访问地址不变）"), 'success');
        } else {
          toast(i18nTr("已保存"), 'success');
        }
      }
    } catch (e) {
      formErr = e.message;
    } finally {
      saving = false;
    }
  }

  // ---- 启停 / 删除 ----

  async function startInst(inst) {
    if (actingId) return;
    actingId = inst.id;
    try {
      const d = await api('/api/cloudflare/instances/' + inst.id + '/start', { method: 'POST' });
      if (d) st = d;
      toast(i18nTr("已启动：") + inst.name + i18nTr("，正在连接 Cloudflare 边缘…"));
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      actingId = '';
    }
  }

  // togglePause 暂停/恢复：隧道进程与访问地址都不动，只把回源切到 503 页面
  // （停止再启动会拿到新的 trycloudflare 域名，所以才需要这个中间状态）
  async function togglePause(inst) {
    if (actingId) return;
    actingId = inst.id;
    const resume = !!inst.paused;
    try {
      const d = await api('/api/cloudflare/instances/' + inst.id + (resume ? '/resume' : '/pause'), { method: 'POST' });
      if (d) st = d;
      toast((resume ? i18nTr("已恢复访问：") : i18nTr("已暂停访问：")) + inst.name + (resume ? '' : i18nTr("，访客将看到 503 页面")));
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      actingId = '';
    }
  }

  // stopInst 真正执行停止（按钮直连与确认弹窗共用），返回是否成功
  async function stopInst(inst) {
    if (actingId) return false;
    actingId = inst.id;
    try {
      const d = await api('/api/cloudflare/instances/' + inst.id + '/stop', { method: 'POST' });
      if (d) st = d;
      toast(i18nTr("已停止：") + inst.name);
      return true;
    } catch (e) {
      toast(e.message, 'error');
      return false;
    } finally {
      actingId = '';
    }
  }

  async function confirmStop() {
    const inst = stopTarget;
    if (!inst || stopBusy) return;
    stopBusy = true;
    const ok = await stopInst(inst);
    stopBusy = false;
    // 失败时保留弹窗，让用户看到错误后自己决定重试还是取消
    if (ok) stopTarget = null;
  }

  async function confirmDelete() {
    delBusy = true;
    try {
      const d = await api('/api/cloudflare/instances/' + delInst.id, { method: 'DELETE' });
      if (d) st = d;
      toast(i18nTr("已删除实例：") + delInst.name);
      delInst = null;
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      delBusy = false;
    }
  }

  // ---- 日志 ----

  async function openLog(inst) {
    logInst = inst;
    logText = i18nTr("加载中…");
    await refreshLog();
  }

  async function refreshLog() {
    if (!logInst) return;
    logBusy = true;
    try {
      const d = await api('/api/cloudflare/instances/' + logInst.id + '/log');
      logText = reverseLines((d && d.log) || i18nTr("暂无日志"));
    } catch (e) {
      logText = i18nTr("读取日志失败: ") + e.message;
    } finally {
      logBusy = false;
    }
  }

  // ---- 域名路由（仅 API 全托管实例） ----

  async function addRoute() {
    if (!routeInst || routeBusy) return;
    // 格式校验：路由行内域名/本地服务输入统一拦截并就地提示
    if (!validateAll(routeRowEl)) return;
    const hostname = routeForm.hostname.trim().toLowerCase();
    if (!hostname || !routeForm.service.trim()) {
      toast(i18nTr("请填写域名与本地服务地址"), 'error');
      return;
    }
    routeBusy = true;
    try {
      const d = await api('/api/cloudflare/instances/' + routeInst.id + '/routes', {
        method: 'POST',
        body: { hostname, service: routeForm.service.trim(), path: routeForm.path.trim() }
      });
      if (d && d.status) st = d.status;
      routeForm = { hostname: '', service: routeForm.service, path: '' };
      if (d && d.warning) toast(d.warning, 'error');
      else toast(i18nTr("路由已下发：") + hostname, 'success');
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      routeBusy = false;
    }
  }

  async function delRoute(r) {
    if (!routeInst || routeBusy) return;
    routeBusy = true;
    try {
      const d = await api('/api/cloudflare/instances/' + routeInst.id + '/routes/delete', {
        method: 'POST',
        body: { hostname: r.hostname, path: r.path || '' }
      });
      if (d && d.status) st = d.status;
      if (d && d.warning) toast(d.warning, 'error');
      else toast(i18nTr("已删除：") + r.hostname);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      routeBusy = false;
    }
  }

  // importRoutes 从云端拉取 ingress 覆盖本页路由表（在后台手工改过路由时用它同步回来）
  async function importRoutes() {
    if (!routeInst || refreshing) return;
    refreshing = true;
    try {
      const d = await api('/api/cloudflare/instances/' + routeInst.id + '/routes/import', { method: 'POST' });
      if (d) st = d;
      toast(i18nTr("已从云端刷新路由表"));
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      refreshing = false;
    }
  }

  // ---- 内核安装 ----

  async function install() {
    if (installing) return;
    installing = true;
    installErr = '';
    progress = { percent: -1, stage: i18nTr("正在准备…"), done: 0, total: 0 };
    try {
      await api('/api/cloudflare/install', { method: 'POST' });
      await pollProgress();
    } catch (e) {
      installing = false;
      installErr = e.message;
      toast(e.message, 'error');
    }
  }

  function pollProgress() {
    return new Promise((resolve) => {
      const timer = setInterval(async () => {
        try {
          const p = await api('/api/cloudflare/install/progress');
          if (p) {
            progress = p;
            if (p.error) installErr = p.error;
            if (!p.busy) {
              clearInterval(timer);
              installing = false;
              await load();
              if (p.error) toast(p.error, 'error');
              else toast(i18nTr("内核已就绪") + (p.version ? '（' + p.version + '）' : ''));
              resolve();
            }
          }
        } catch (e) {
          clearInterval(timer);
          installing = false;
          installErr = e.message;
          resolve();
        }
      }, 800);
    });
  }

  // uploadKernel 上传离线内核包：multipart 请求需要用原始 fetch（api 帮助函数只发 JSON）
  async function uploadKernel(ev) {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    uploading = true;
    installErr = '';
    try {
      const fd = new FormData();
      fd.append('file', file);
      const resp = await fetch(apiBase + '/api/cloudflare/install/upload', { method: 'POST', body: fd });
      const body = await resp.json().catch(() => null);
      if (!resp.ok || !body || body.success === false) {
        throw new Error((body && body.error) || ('HTTP ' + resp.status));
      }
      const d = body.data || {};
      if (d.status) st = d.status;
      toast(i18nTr("内核已安装") + (d.version ? '（' + d.version + '）' : ''));
    } catch (e) {
      installErr = e.message;
      toast(e.message, 'error');
    } finally {
      uploading = false;
      ev.target.value = '';
    }
  }

  onMount(async () => {
    await load();
    await loadAccounts();
    pollTimer = pollVisible(load, 5000);
  });
  onDestroy(() => { if (pollTimer) pollTimer(); });
</script>

<div class="container page-list">
  <div class="page-hdr">
    <div>
      <h2>Cloudflare Tunnel</h2>
      <span class="page-hdr-sub">{$i18n("免费 HTTPS 域名入口 · 仅发布 HTTP/HTTPS 域名 · 支持多隧道并行")}</span>
    </div>
    <div class="page-hdr-actions">
      <button class="btn btn-primary" on:click={openCreate}>
        <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="24" r="20"/><path d="M24 16V32"/><path d="M16 24H32"/></svg>
        <span class="sm-hide">{$i18n("新建隧道")}</span>
      </button>
    </div>
  </div>

  {#if showBoundary}
    <div class="about-warn cf-boundary">
      <span>{$i18n("能力边界：Cloudflare Tunnel 只发布 HTTP/HTTPS 域名（走 443，无端口号概念），UDP 不支持；\n      TCP/SSH/RDP 类服务需要访问方本地安装 cloudflared 才能连接。\n      需要 TCP/UDP 任意端口映射，请继续用「FRPC」或「MEFrp」。\n      Token 托管与 API 全托管需自有域名并托管在 Cloudflare，且大陆访问通常绕道境外节点，延迟偏高，适合 Webhook 回调与低频网页访问。")}</span>
      <button class="cf-boundary-x" on:click={dismissBoundary} aria-label={$i18n("关闭提示")} title={$i18n("关闭提示")}>&times;</button>
    </div>
  {/if}

  {#if loading}
    <div class="empty"><div class="empty-t">{$i18n("加载中…")}</div></div>
  {:else}
    <!-- 1. 连接器：cloudflared 内核（全局共用一份，与实例无关） -->
    <div class="cf-card">
      <div class="cf-card-h">
        <span class="cf-card-title">{$i18n("连接器")}</span>
        {#if st.version}<span class="cf-card-sub">cloudflared {st.version}</span>{/if}
        <div class="cf-card-h-actions">
          {#if st.installed}
            <span class="badge badge-on">{$i18n("内核已就绪")}</span>
          {:else}
            <span class="badge badge-warn">{$i18n("内核未安装")}</span>
          {/if}
          {#if kernelUpToDate}
            <button class="btn btn-sm" disabled title={$i18n("已安装 {0}，与官方最新版一致，无需重复下载", [st.version])}>{$i18n("已是最新版")}</button>
          {:else}
            <button class="btn btn-primary btn-sm" disabled={installing} on:click={install}>
              {installing ? i18nTr("下载中…") : (st.installed ? i18nTr("下载最新版内核") : i18nTr("下载并安装内核"))}
            </button>
          {/if}
          <button class="btn btn-sm" disabled={uploading || installing} on:click={() => fileInput.click()}>
            {uploading ? i18nTr("上传中…") : i18nTr("上传离线包")}
          </button>
          <!-- 隐藏的原生文件选择器：离线安装走 multipart，不能用 JSON 封装 -->
          <input class="cf-file" type="file" aria-label={$i18n("上传离线内核包")} bind:this={fileInput} on:change={uploadKernel} />
        </div>
      </div>

      <!-- 统计区：全部取自 /api/cloudflare/status 的实时状态，不展示无来源数据 -->
      <div class="cf-stat-grid">
        <div class="cf-stat">
          <span>{$i18n("内核状态")}</span>
          <b style="color:{st.installed ? 'var(--green)' : 'var(--yellow)'}">{st.installed ? i18nTr("已安装") : i18nTr("未安装")}</b>
        </div>
        <div class="cf-stat">
          <span>{$i18n("运行中隧道")}</span>
          <b>{runningCount} / {instances.length}</b>
        </div>
        <div class="cf-stat">
          <span>{$i18n("边缘连接")}</span>
          <b style="color:{readyCount ? 'var(--green)' : 'var(--text3)'}">{readyCount} {$i18n("条已连接")}</b>
        </div>
        <div class="cf-stat">
          <span>{$i18n("内核版本")}</span>
          <b>{st.version || '—'}</b>
        </div>
      </div>

      <div class="cf-actions">
        <span class="tip-text" style="margin:0">
          {st.installed
            ? i18nTr("内核为所有隧道实例共用；各条实例的启动 / 停止 / 日志在下方列表中分别操作。")
            : i18nTr("官方内核约 40MB，按需下载（不随 TunHook 安装包内置）；无外网时可先下载离线包再上传。")}
        </span>
      </div>

      <!-- 进度条只在本次安装进行中显示：不能用 percent 判断——后端空闲时返回零值（percent=0、
           stage 为空），按 percent>=0 判断会让进度条在完成后一直残留成「0%」 -->
      {#if installing}
        <div class="cf-progress">
          <div class="cf-progress-head">
            <span>{progress.stage || i18nTr("正在处理…")}</span>
            {#if progress.percent >= 0}
              <span class="mono">{progress.percent}% {fmtBytes(progress.done)}{progress.total ? ' / ' + fmtBytes(progress.total) : ''}</span>
            {:else}
              <span class="mono">{$i18n("连接中…")}</span>
            {/if}
          </div>
          <div class="progress-track">
            <div class="progress-fill" class:indeterminate={progress.percent < 0}
                 style="width:{progress.percent >= 0 ? progress.percent + '%' : '35%'}"></div>
          </div>
        </div>
      {/if}

      {#if installErr}
        <div class="cf-err">{installErr}</div>
      {/if}
    </div>

    <!-- 2. 隧道实例：主控台，每行一条实例（独立进程 / 独立启停 / 独立日志） -->
    <div class="cf-card">
      <div class="cf-card-h">
        <span class="cf-card-title">{$i18n("隧道实例")}</span>
        <span class="cf-card-sub">{instances.length} {$i18n("个")}</span>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th style="width:90px">PID</th>
              <th>{$i18n("名称")}</th>
              <th style="width:110px">{$i18n("托管方式")}</th>
              <th style="width:100px">{$i18n("连接协议")}</th>
              <th style="width:180px">{$i18n("本地地址")}</th>
              <th>{$i18n("访问地址")}</th>
              <th style="width:200px">{$i18n("状态")}</th>
              <th style="width:280px">{$i18n("操作")}</th>
            </tr>
          </thead>
          <tbody>
            {#each instances as inst (inst.id)}
              <tr>
                <td class="cell-mono" style="color:var(--text3)">{inst.running && inst.pid ? inst.pid : '—'}</td>
                <td><span class="cf-name"><span class="cf-dot" style="background:{stateColor(inst)}"></span>{inst.name}</span></td>
                <td><span class="badge {modeBadge(inst.mode)}">{modeLabel(inst.mode)}</span></td>
                <td class="cell-mono">{protocolLabel(inst.protocol)}</td>
                <td class="cell-mono">
                  {#if inst.local && inst.local.port > 0}
                    {inst.local.addr}:{inst.local.port}
                  {:else}
                    <span title={$i18n("尚未配置本地服务地址，可在「编辑」里填写")}>—</span>
                  {/if}
                </td>
                <td class="cell-mono">
                  {#if inst.accessURL}
                    <!-- 列表里只显示主机名：https:// 前缀在这张表里没有信息量，完整地址放 title 里 -->
                    <a class="cell-link" href={inst.accessURL} target="_blank" rel="noreferrer" title={inst.accessURL}>{urlHost(inst.accessURL)}</a>
                  {:else}
                    <span title={accessHint(inst)}>—</span>
                  {/if}
                </td>
                <td>
                  {#if inst.paused}
                    <span class="badge badge-warn" title={$i18n("隧道连接与访问地址保持不变，访客当前会看到 503 页面")}><span class="badge-dot" style="background:var(--yellow)"></span>{$i18n("运行中 · 已暂停")}</span>
                  {:else if inst.running && inst.ready}
                    <span class="badge badge-on"><span class="badge-dot" style="background:var(--green)"></span>{$i18n("运行中 · 已连上")}</span>
                  {:else if inst.running}
                    <span class="badge badge-warn"><span class="badge-dot" style="background:var(--yellow)"></span>{$i18n("运行中 · 未连上边缘")}</span>
                  {:else}
                    <span class="badge badge-off">{$i18n("未运行")}</span>
                  {/if}
                </td>
                <td>
                  <div class="cell-actions">
                    {#if inst.mode === 'quick'}
                      <!-- 暂停只对临时入口有意义：它的域名每次启动都会变，暂停可在保留连接与域名的前提下停止对外服务 -->
                      <button class="btn-icon" disabled={actingId === inst.id || !inst.running}
                              title={!inst.running ? i18nTr("隧道未运行，无需暂停") : (inst.paused ? i18nTr("恢复访问：回源切回真实本地服务") : i18nTr("暂停访问：访客将看到 503 页面，隧道连接与访问地址保持不变"))}
                              aria-label={inst.paused ? i18nTr("恢复访问") : i18nTr("暂停访问")}
                              style={inst.paused ? 'color:var(--yellow)' : ''}
                              on:click={() => togglePause(inst)}>
                        {#if actingId === inst.id}
                          <span class="spinner"></span>
                        {:else if inst.paused}
                          <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M16 10L38 24L16 38V10Z" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                        {:else}
                          <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M16 10V38" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M32 10V38" stroke="currentColor" stroke-width="4" stroke-linecap="round"/></svg>
                        {/if}
                      </button>
                    {/if}
                    {#if inst.running}
                      <button class="btn-icon" style="color:{stateColor(inst)}" disabled={actingId === inst.id} title={$i18n("停止")} aria-label={$i18n("停止")} on:click={() => (stopTarget = inst)}>
                        {#if actingId === inst.id}
                          <span class="spinner"></span>
                        {:else}
                          <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M24 4V24" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                        {/if}
                      </button>
                    {:else}
                      <button class="btn-icon" style="color:{stateColor(inst)}" disabled={actingId === inst.id || !st.installed || !inst.configured}
                              title={!st.installed ? i18nTr("需要先安装 cloudflared 内核") : (!inst.configured ? i18nTr("该实例尚未配置完成，请点「编辑」补全凭证或本地服务地址") : i18nTr("启动"))}
                              aria-label={$i18n("启动")}
                              on:click={() => startInst(inst)}>
                        {#if actingId === inst.id}
                          <span class="spinner"></span>
                        {:else}
                          <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M24 4V24" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                        {/if}
                      </button>
                    {/if}
                    <button class="btn-icon" title={$i18n("日志")} aria-label={$i18n("日志")} on:click={() => openLog(inst)}>
                      <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><rect x="13" y="10" width="28" height="34" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M35 10V4H8C7.44772 4 7 4.44772 7 5V38H13" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 22H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 30H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                    </button>
                    <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑")} on:click={() => openEdit(inst)}>
                      <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M10 44H38C39.1046 44 40 43.1046 40 42V14H30V4H10C8.89543 4 8 4.89543 8 6V42C8 43.1046 8.89543 44 10 44Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M30 4L40 14" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 35L31 25L27 21L17 31V35H21Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                    </button>
                    <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => (delInst = inst)}>
                      <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                    </button>
                  </div>
                </td>
              </tr>
            {:else}
              <tr>
                <td colspan="8">
                  <div class="empty" style="padding:24px 0">
                    <div class="empty-t">{$i18n("还没有隧道实例，点右上角「新建隧道」创建第一条")}</div>
                    <button class="btn btn-primary btn-sm" style="margin-top:10px" on:click={openCreate}>{$i18n("新建隧道")}</button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      <!-- 移动端实例卡片：窄屏下替代表格（.page-list 会隐藏 .table-wrap） -->
      <div class="list-cards">
        {#if instances.length === 0}
          <div class="list-cards-empty">
            <div>{$i18n("还没有隧道实例，点「新建隧道」创建第一条")}</div>
            <button class="btn btn-primary btn-sm" style="margin-top:10px" on:click={openCreate}>{$i18n("新建隧道")}</button>
          </div>
        {/if}
        {#each instances as inst (inst.id)}
          <div class="list-card">
            <div class="list-card-top">
              <div class="list-card-avatar">{(inst.name || '?').charAt(0).toUpperCase()}</div>
              <div class="list-card-title">{inst.name}</div>
              <span class="badge {modeBadge(inst.mode)}" style="margin-left:auto;flex-shrink:0">{modeLabel(inst.mode)}</span>
            </div>
            <div class="list-card-sub">
              <span class="cell-mono">PID {inst.running && inst.pid ? inst.pid : '—'}</span>
              <span class="badge badge-off">{protocolLabel(inst.protocol)}</span>
              {#if inst.paused}
                <span class="badge badge-warn" title={$i18n("隧道连接与访问地址保持不变，访客当前会看到 503 页面")}><span class="badge-dot" style="background:var(--yellow)"></span>{$i18n("运行中 · 已暂停")}</span>
              {:else if inst.running && inst.ready}
                <span class="badge badge-on"><span class="badge-dot" style="background:var(--green)"></span>{$i18n("运行中 · 已连上")}</span>
              {:else if inst.running}
                <span class="badge badge-warn"><span class="badge-dot" style="background:var(--yellow)"></span>{$i18n("运行中 · 未连上边缘")}</span>
              {:else}
                <span class="badge badge-off">{$i18n("未运行")}</span>
              {/if}
            </div>
            <div class="list-card-rows">
              <div class="list-card-row">
                <span class="k">{$i18n("本地地址")}</span>
                <span class="v cell-mono">
                  {#if inst.local && inst.local.port > 0}
                    {inst.local.addr}:{inst.local.port}
                  {:else}
                    <span title={$i18n("尚未配置本地服务地址，可在「编辑」里填写")}>—</span>
                  {/if}
                </span>
              </div>
              <div class="list-card-row">
                <span class="k">{$i18n("访问地址")}</span>
                <span class="v cell-mono">
                  {#if inst.accessURL}
                    <a class="cell-link" href={inst.accessURL} target="_blank" rel="noreferrer" title={inst.accessURL}>{urlHost(inst.accessURL)}</a>
                  {:else}
                    <span title={accessHint(inst)}>—</span>
                  {/if}
                </span>
              </div>
            </div>
            <div class="list-card-actions">
              {#if inst.mode === 'quick'}
                <button class="btn-icon" disabled={actingId === inst.id || !inst.running}
                        title={!inst.running ? i18nTr("隧道未运行，无需暂停") : (inst.paused ? i18nTr("恢复访问：回源切回真实本地服务") : i18nTr("暂停访问：访客将看到 503 页面，隧道连接与访问地址保持不变"))}
                        aria-label={inst.paused ? i18nTr("恢复访问") : i18nTr("暂停访问")}
                        style={inst.paused ? 'color:var(--yellow)' : ''}
                        on:click={() => togglePause(inst)}>
                  {#if actingId === inst.id}
                    <span class="spinner"></span>
                  {:else if inst.paused}
                    <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M16 10L38 24L16 38V10Z" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                  {:else}
                    <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M16 10V38" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M32 10V38" stroke="currentColor" stroke-width="4" stroke-linecap="round"/></svg>
                  {/if}
                </button>
              {/if}
              {#if inst.running}
                <button class="btn-icon" style="color:{stateColor(inst)}" disabled={actingId === inst.id} title={$i18n("停止")} aria-label={$i18n("停止")} on:click={() => (stopTarget = inst)}>
                  {#if actingId === inst.id}
                    <span class="spinner"></span>
                  {:else}
                    <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M24 4V24" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                  {/if}
                </button>
              {:else}
                <button class="btn-icon" style="color:{stateColor(inst)}" disabled={actingId === inst.id || !st.installed || !inst.configured}
                        title={!st.installed ? i18nTr("需要先安装 cloudflared 内核") : (!inst.configured ? i18nTr("该实例尚未配置完成，请点「编辑」补全凭证或本地服务地址") : i18nTr("启动"))}
                        aria-label={$i18n("启动")}
                        on:click={() => startInst(inst)}>
                  {#if actingId === inst.id}
                    <span class="spinner"></span>
                  {:else}
                    <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M24 4V24" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                  {/if}
                </button>
              {/if}
              <button class="btn-icon" title={$i18n("日志")} aria-label={$i18n("日志")} on:click={() => openLog(inst)}>
                <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><rect x="13" y="10" width="28" height="34" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M35 10V4H8C7.44772 4 7 4.44772 7 5V38H13" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 22H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 30H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
              </button>
              <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑")} on:click={() => openEdit(inst)}>
                <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M10 44H38C39.1046 44 40 43.1046 40 42V14H30V4H10C8.89543 4 8 4.89543 8 6V42C8 43.1046 8.89543 44 10 44Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M30 4L40 14" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 35L31 25L27 21L17 31V35H21Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
              </button>
              <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => (delInst = inst)}>
                <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
              </button>
            </div>
          </div>
        {/each}
      </div>
    </div>

    <!-- 3. 域名路由：只对 API 全托管实例有意义（Token 托管的路由在 Cloudflare 后台） -->
    <div class="cf-card">
      <div class="cf-card-h">
        <span class="cf-card-title">{$i18n("域名路由")}</span>
        <span class="cf-card-sub">{$i18n("仅 API 全托管实例")}</span>
        {#if apiInstances.length}
          <div class="cf-card-h-actions">
            <div class="cf-card-sel">
              <CustomSelect bind:value={routeInstId} options={apiInstances.map((i) => ({ value: i.id, label: i.name }))} />
            </div>
            <button class="btn btn-sm" disabled={refreshing || !routeInst} title={$i18n("从 Cloudflare 拉取该实例的 ingress，覆盖本页路由表")}
                    on:click={importRoutes}>{refreshing ? i18nTr("刷新中…") : i18nTr("刷新")}</button>
            <span class="badge badge-off">{routeList.length} {$i18n("条")}</span>
          </div>
        {:else}
          <div class="cf-card-h-actions">
            <span class="badge badge-off">{$i18n("0 条")}</span>
          </div>
        {/if}
      </div>

      {#if !apiInstances.length || !routeInst}
        <div class="tip-text">{$i18n("路由由 API 全托管的实例维护；请先创建 / 绑定一个 API 全托管实例。")}</div>
      {:else}
        <div class="tip-text">
          {$i18n("ingress 为整份覆盖式配置，本页始终保有该实例的完整路由表，避免清掉你在 Cloudflare 后台手工添加的规则。\n          新增路由会自动补建指向隧道的 CNAME 记录。")}
        </div>

        <div class="cf-row" style="margin-top:10px" bind:this={routeRowEl}>
          <span class="cf-k">{$i18n("域名")}</span>
          <input type="text" placeholder={'app.' + (routeInst.api.zoneName || 'example.com')} bind:value={routeForm.hostname} style="width:220px" use:field={{ check: validateDomain, errAt: () => routeHostErr }} />
          <span class="cf-k">{$i18n("本地服务")}</span>
          <input type="text" placeholder="http://127.0.0.1:8080" bind:value={routeForm.service} style="width:240px" use:field={{ check: validateURL, errAt: () => routeSvcErr }} />
          <span class="cf-k">{$i18n("路径")}</span>
          <input type="text" placeholder={$i18n("可留空")} bind:value={routeForm.path} style="width:110px" />
          <button class="btn btn-primary btn-sm" disabled={routeBusy} on:click={addRoute}>{routeBusy ? i18nTr("下发中…") : i18nTr("添加")}</button>
        </div>
        <div class="field-err" bind:this={routeHostErr} style="display:none"></div>
        <div class="field-err" bind:this={routeSvcErr} style="display:none"></div>

        <div class="table-wrap" style="margin-top:10px">
          <table>
            <thead>
              <tr><th>{$i18n("域名")}</th><th>{$i18n("本地服务")}</th><th style="width:140px">{$i18n("路径")}</th><th style="width:110px">{$i18n("操作")}</th></tr>
            </thead>
            <tbody>
              {#each routeList as r (r.hostname + '|' + (r.path || ''))}
                <tr>
                  <td class="cell-mono">{r.hostname}</td>
                  <td class="cell-mono">{r.service}</td>
                  <td class="cell-mono">{r.path || '—'}</td>
                  <td>
                    <div class="cell-actions">
                      <button class="btn-icon" style="color:var(--red)" disabled={routeBusy} title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => delRoute(r)}>
                        <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                      </button>
                    </div>
                  </td>
                </tr>
              {:else}
                <tr><td colspan="4" style="text-align:center;color:var(--text3);padding:20px 0">{$i18n("暂无路由，添加后即可通过域名访问本地服务")}</td></tr>
              {/each}
            </tbody>
          </table>
        </div>

        <!-- 移动端路由卡片：窄屏下替代表格 -->
        <div class="list-cards">
          {#each routeList as r (r.hostname + '|' + (r.path || ''))}
            <div class="list-card">
              <div class="list-card-top">
                <div class="list-card-title">{r.hostname}</div>
                <button class="btn-icon" style="color:var(--red);margin-left:auto;flex-shrink:0" disabled={routeBusy} title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => delRoute(r)}>
                  <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>
              </div>
              <div class="list-card-rows">
                <div class="list-card-row">
                  <span class="k">{$i18n("本地服务")}</span>
                  <span class="v cell-mono ellip">{r.service}</span>
                </div>
                <div class="list-card-row">
                  <span class="k">{$i18n("路径")}</span>
                  <span class="v cell-mono">{r.path || '—'}</span>
                </div>
              </div>
            </div>
          {:else}
            <div class="list-cards-empty">{$i18n("暂无路由，添加后即可通过域名访问本地服务")}</div>
          {/each}
        </div>
      {/if}
    </div>

    {#if showModal}
      <!-- 弹窗 A：新建 / 编辑隧道。编辑模式下托管方式只读（改方式等于整套凭证与运行模型都变，删除后重建更干净） -->
      <Modal title={editId ? i18nTr("编辑隧道") : i18nTr("新建隧道")} onClose={() => (showModal = false)} width={640}>
        <div class="cf-form" bind:this={modalFormEl}>
          <div class="cf-form-row">
            <span class="cf-k">{$i18n("托管方式")}</span>
            <div class="cf-form-ctl">
              {#if editId}
                <!-- 编辑不允许切换托管方式：换方式等于换一整套凭证与运行模型，删除后重建才能保证状态干净 -->
                <input type="text" value={modeLabel(cfgMode)} disabled />
              {:else}
                <CustomSelect bind:value={cfgMode} options={modeOpts} on:change={(e) => onModeChange(e.detail.value)} />
              {/if}
            </div>
            <span class="cf-k">{$i18n("连接协议")}</span>
            <div class="cf-form-ctl">
              <CustomSelect bind:value={protocol} options={protocolOpts} />
            </div>
          </div>

          {#if cfgMode === 'api' && (!editId || rebindOpen)}
            <div class="cf-form-row">
              <span class="cf-k">{$i18n("Cloudflare 账号")}</span>
              <div class="cf-form-ctl">
                <CustomSelect bind:value={bindAccount} options={accountOpts} placeholder={$i18n("请选择账号")}
                              on:change={(e) => onAccountChange(e.detail.value)} />
              </div>
              <button class="btn btn-sm" on:click={() => (showAccounts = true)}>{$i18n("新增账号")}</button>
              {#if loadingZones}<span class="cf-k">{$i18n("读取域名中…")}</span>{/if}
            </div>
          {/if}

          <div class="cf-form-row">
            <span class="cf-k">{$i18n("隧道名称")}</span>
            <div class="cf-form-ctl">
              <!-- 复用已有隧道时隧道名由云端决定，本地不再单独填 -->
              <input type="text" placeholder={cfgMode === 'api' ? i18nTr("留空自动生成") : i18nTr("如 nas-web")}
                     bind:value={nameInput} disabled={cfgMode === 'api' && !!tunnelId} />
            </div>
            <span class="cf-k">{$i18n("协议")}</span>
            <div class="cf-form-ctl">
              <CustomSelect bind:value={local.scheme} options={schemeOpts} />
            </div>
          </div>

          <div class="cf-form-row">
            <span class="cf-k">{$i18n("本地地址")}</span>
            <div class="cf-form-ctl">
              <input type="text" bind:value={local.addr} placeholder="127.0.0.1" use:field={{ check: validateHost, errAt: () => localAddrErr }} />
            </div>
            <span class="cf-k">{$i18n("端口")}</span>
            <div class="cf-form-ctl">
              <input type="number" bind:value={local.port} min="1" max="65535" placeholder="5666" use:field={{ check: validatePort, errAt: () => localPortErr }} />
            </div>
          </div>
          <div class="field-err" bind:this={localAddrErr} style="display:none"></div>
          <div class="field-err" bind:this={localPortErr} style="display:none"></div>

          {#if cfgMode === 'api' && (!editId || rebindOpen)}
            <div class="cf-form-row">
              <span class="cf-k">{$i18n("发布域名")}</span>
              <div class="cf-form-ctl">
                <CustomSelect bind:value={bindZone} options={zoneOpts} placeholder={bindAccount ? i18nTr("请选择域名") : i18nTr("请先选账号")}
                              on:change={(e) => onZoneChange(e.detail.value)} />
              </div>
              <span class="cf-k">{$i18n("隧道")}</span>
              <div class="cf-form-ctl">
                <CustomSelect bind:value={tunnelId} options={tunnelOpts} placeholder={$i18n("新建隧道")} />
              </div>
              {#if loadingTunnels}<span class="cf-k">{$i18n("读取中…")}</span>{/if}
            </div>
          {/if}

          {#if cfgMode === 'token'}
            <div class="cf-form-row">
              <span class="cf-k">{$i18n("隧道 Token")}</span>
              <div class="cf-form-ctl cf-form-ctl-wide">
                <input type="password" placeholder={editId ? i18nTr("留空则不修改") : i18nTr("粘贴隧道 Token（eyJhIj…）")} bind:value={tokenInput} />
              </div>
            </div>
          {/if}

          {#if cfgMode === 'api' && editId && !rebindOpen}
            <!-- 重新绑定会换隧道 / 换域名并触发云端变更，属高风险动作：默认收起，需用户显式点击才展开 -->
            <div class="cf-form-row">
              <span class="cf-k">{$i18n("当前绑定")}</span>
              <span class="mono">{editInst.api.zoneName || '—'}{editInst.api.tunnelId ? i18nTr(" · 隧道已绑定") : i18nTr(" · 未绑定隧道")}</span>
              <button class="btn btn-sm" on:click={openRebind}>{$i18n("重新绑定")}</button>
            </div>
          {/if}

          {#if formErr}
            <div class="cf-err">{formErr}</div>
          {:else if cfgMode === 'api' && !cfAccounts.length}
            <div class="cf-hint">{$i18n("尚未配置 Cloudflare 账号：点击上方「新增账号」添加一个（需要 API Token）。")}</div>
          {/if}

          <div class="cf-form-actions">
            <button class="btn btn-primary btn-sm" disabled={saving} on:click={submit}>
              {saving ? i18nTr("保存中…") : (editId ? i18nTr("保存") : i18nTr("创建并启用"))}
            </button>
          </div>
        </div>
      </Modal>
    {/if}
  {/if}
</div>

{#if logInst}
  <!-- 弹窗 B：单条实例的内核日志 -->
  <Modal title={i18nTr("内核日志 · ") + logInst.name} onClose={() => (logInst = null)} width={900}>
    <pre class="cf-log">{@html highlightLog(logText)}</pre>
    <div class="cf-form-actions" style="margin-top:10px">
      <button class="btn btn-sm" disabled={logBusy} on:click={refreshLog}>{logBusy ? i18nTr("刷新中…") : i18nTr("刷新")}</button>
    </div>
  </Modal>
{/if}

<!-- 账户管理弹窗：与「系统设置 → 域名解析」共用，避免两处各写一套账号增删 -->
{#if showAccounts}
  <DnsAccountsModal onClose={() => (showAccounts = false)} onChanged={onAccountsChanged} />
{/if}

<!-- 停止确认：停止会断开与 Cloudflare 的连接；临时入口的访问地址由 Cloudflare 在启动时重新下发，停止后域名会变 -->
{#if stopTarget}
  <ConfirmModal
    title={$i18n("停止隧道")}
    message={i18nTr("将断开「") + stopTarget.name + i18nTr("」与 Cloudflare 的连接。")
      + (stopTarget.mode === 'quick'
        ? i18nTr("临时入口的访问地址由 Cloudflare 在启动时重新下发，下次启动会拿到新域名；若只是想临时停止对外服务，用「暂停」可保留连接与访问地址。")
        : i18nTr("再次启动后访问地址不变。"))}
    confirmText={$i18n("停止")}
    busy={stopBusy}
    onConfirm={confirmStop}
    onClose={() => (stopTarget = null)}
  />
{/if}

{#if delInst}
  <ConfirmModal
    title={$i18n("删除隧道实例")}
    message={i18nTr("将停止「") + delInst.name + i18nTr("」并删除本机运行目录。只解除本机接管，不会删除 Cloudflare 云端隧道与 DNS 记录。")}
    confirmText={$i18n("删除")}
    busy={delBusy}
    onConfirm={confirmDelete}
    onClose={() => (delInst = null)}
  />
{/if}

<style>
  .cf-card {
    background: var(--bg3);
    border: 1px solid var(--bd);
    border-radius: calc(var(--radius) + 4px);
    padding: 16px 18px;
    margin-bottom: 14px;
    box-shadow: var(--shadow-card);
  }
  .cf-card-h {
    display: flex;
    align-items: center;
    gap: 9px;
    flex-wrap: wrap;
    margin-bottom: 12px;
  }
  .cf-card-title {
    font-size: 13.5px;
    font-weight: 600;
    color: var(--text);
    letter-spacing: .1px;
  }
  .cf-card-sub {
    font-family: var(--mono);
    font-size: 10.5px;
    color: var(--text3);
  }
  .cf-card-h-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-left: auto;
    flex-wrap: wrap;
  }
  /* 连接器统计区：全部来自实时状态接口 */
  .cf-stat-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
  }
  .cf-stat {
    background: var(--bg4);
    border: 1px solid var(--bd);
    border-radius: var(--radius);
    padding: 10px 12px;
    min-width: 0;
  }
  .cf-stat span {
    display: block;
    font-size: 10.5px;
    color: var(--text3);
    margin-bottom: 4px;
  }
  .cf-stat b {
    display: block;
    font-family: var(--mono);
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  /* 实例名称前的运行状态圆点 */
  .cf-name {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-weight: 600;
  }
  .cf-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    display: inline-block;
    flex-shrink: 0;
  }
  /* 移动端卡片标题占满剩余宽度，长实例名/域名省略而不挤走右侧状态 */
  .cf-card .list-card-title {
    flex: 1;
    min-width: 0;
  }
  /* 卡片头内的实例选择器：定宽，避免长实例名把按钮挤走 */
  .cf-card-sel {
    width: 190px;
    flex: none;
  }
  .cf-row {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    font-size: 13px;
  }
  .cf-k {
    color: var(--text3);
    font-size: 12px;
    flex-shrink: 0;
  }
  .cf-file {
    display: none;
  }
  /* 配置弹窗表单：标签定宽 + 控件等宽，保证各行选择框与输入框左右对齐 */
  .cf-form {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .cf-form-row {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }
  .cf-form-row > .cf-k {
    width: 72px;
    flex: none;
    /* 超长标签（如「Cloudflare 账号」）不换行，避免与控件错位 */
    white-space: nowrap;
  }
  .cf-form-ctl {
    width: 190px;
    flex: none;
  }
  .cf-form-ctl-wide {
    width: 330px;
  }
  .cf-form-actions {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 10px;
    flex-wrap: wrap;
  }
  .cf-form-actions .btn {
    flex: none;
  }
  .cf-actions {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 10px;
  }
  .cf-progress {
    margin: 10px 0;
  }
  .cf-progress-head {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    color: var(--text2);
    margin-bottom: 6px;
  }
  .cf-err {
    background: rgba(var(--red-rgb), 0.08);
    border: 1px solid rgba(var(--red-rgb), 0.3);
    color: var(--red);
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 12.5px;
    margin: 10px 0;
    word-break: break-all;
  }
  /* 弹窗内的黄色提示（非错误，但需要用户先处理才能继续） */
  .cf-hint {
    color: var(--yellow);
    font-size: 12.5px;
    line-height: 1.7;
  }
  /* 页顶能力边界提示：文本自适应宽度，× 固定在右侧 */
  .cf-boundary {
    display: flex;
    align-items: flex-start;
    gap: 10px;
  }
  .cf-boundary > span {
    flex: 1;
    line-height: 1.7;
  }
  .cf-boundary-x {
    all: unset;
    cursor: pointer;
    flex-shrink: 0;
    color: var(--yellow);
    font-size: 18px;
    line-height: 1;
    padding: 0 2px;
    opacity: .65;
  }
  .cf-boundary-x:hover {
    opacity: 1;
  }
  /* 操作列图标按钮组：本页一行有 5 个图标按钮，全局的 8px 间距偏松，这里收紧到 4px
     （只作用于本页，全局 .cell-actions 保持 8px，其他页面不受影响） */
  .cell-actions {
    gap: 4px;
  }
  .cf-log {
    max-height: 56vh;
    overflow: auto;
    background: var(--bg2);
    border: 1px solid var(--bd);
    border-radius: var(--radius);
    padding: 12px 14px;
    font-family: var(--mono);
    font-size: 12px;
    line-height: 1.6;
    white-space: pre-wrap;
    word-break: break-all;
    margin: 0;
  }
  /* 操作列图标按钮的加载态：处理中的操作显示转圈，避免按钮内一片空白 */
  .spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    flex: none;
    border: 2px solid var(--bd);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: cf-spin .8s linear infinite;
  }
  @keyframes cf-spin {
    to {
      transform: rotate(360deg);
    }
  }

  /* 移动端：卡片头允许换行（长标题不再挤走实例选择器）；定宽控件改为弹性填充。
     cf-form-row 本身可换行，窄屏保持「72px 标签 + 控件」同行，控件占剩余宽度 */
  @media (max-width:600px){
    .cf-card{padding:14px}
    .cf-card-h-actions{width:100%;margin-left:0;justify-content:flex-end}
    .cf-stat-grid{grid-template-columns:1fr 1fr}
    .cf-card-sel{width:auto;min-width:140px;flex:1 1 140px}
    .cf-form-ctl,.cf-form-ctl-wide{width:auto;min-width:0;flex:1 1 0}
  }
</style>
