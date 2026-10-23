<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // Webhook 接收模块：接收 STUN 客户端上报的公网地址，
  // 提供「访问地址 /wh/{channel_id} → 公网地址」的重定向 / 反向代理入口。
  // 页面布局参考「转发列表」（搜索 + 创建分组/注册通道），通道列表参考 STUN 面板（分组卡片）。
  import { onMount, onDestroy } from 'svelte';
  import { toast } from '../lib/stores.js';
  import { api, apiBase } from '../lib/api.js';
  import { pollVisible, validateDomain, optional } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';
  import Modal from '../components/Modal.svelte';
  import ConfirmModal from '../components/ConfirmModal.svelte';
  import CustomSelect from '../components/CustomSelect.svelte';
  import Toggle from '../components/Toggle.svelte';
  import InfoTip from '../components/InfoTip.svelte';

  // 默认分组名（恒存在、不可删除/重命名；与后端一致）
  const DEFAULT_GROUP = i18nTr("Webhook 通道");

  $: groupOptions = groups.map((g) => ({ value: g.name, label: g.name }));

  // 接收器配置（仅读取用于生成访问地址；完整配置在系统设置 → 默认参数 → Webhook 接收）
  // 接收与访问共用单一 Webhook 端口（receive_port），默认 19520
  let cfg = { enabled: false, addr_mode: 'ip', access_domain: '', access_ip: '', receive_port: 19520, mode: 'redirect' };
  // Webhook 模板（只读展示用）：在系统设置 → Webhook 模板 中配置，本模块仅展示系统自动生成的结果供复制
  let whTmpl = { method: 'POST', headers: {}, body: '', success_string: '' };
  let records = [];
  let groups = [];
  let search = '';
  let collapsed = {};   // 分组折叠状态
  let loading = true;
  let timer = null;
  let showAccessLinks = null; // 展示通道全部访问地址（自定义ID/域名时弹出选择）
  let showChannelInfo = null; // 展示通道日志/信息
  let showWhConfig = null;    // 展示通道 Webhook 配置（只读）
  let channelLogs = [];       // 当前查看通道的运行/访问日志（最新在前）
  let channelLogsLoading = false;

  // 注册/编辑通道弹窗（参考隧道弹窗：基础配置 / 进阶设置 / Webhook配置 / 日志设置 四个 Tab 模块）
  let showChannel = false;
  let editId = '';
  let activeTab = 'basic';          // basic | advanced | webhook | log
  let form = {
    group: DEFAULT_GROUP,
    description: '',
    custom_id: '',
    custom_domain: '',
    redirect_type: '',
    link_key: '',
    password: '',
    webhook_url: '',
    callback_char: '',
    webhook_method: 'POST',
    webhook_body: '',
    log_level: 'info',
    log_entries: 500,
    log_days: 30
  };
  let formErr = '';       // 整体错误（保存接口错误）
  let fieldErr = {};      // 字段级错误 { field: message }
  let formEl;             // 弹窗表单容器，提交时统一校验内部字段
  let domainErr;          // 自定义域名错误容器（输入在横向行内，错误显示在下方）
  let saving = false;
  let domainVerifying = false;   // 域名验证中
  let domainStatus = '';         // 域名验证状态: '' | 'ok' | 'err'
  let domainMsg = '';            // 域名验证提示信息
  let resetKeyConfirm = false;   // 重置链接密钥确认弹窗

  // 桌面图标（进阶设置 → 创建桌面图标）：默认访问地址为通道访问地址（外部地址，仅支持浏览器标签页打开）
  const deskVisibilityOptions = [
    { value: true, label: i18nTr("所有用户可见") },
    { value: false, label: i18nTr("仅管理员可见") }
  ];
  let desk = { enabled: false, name: '', type: 'url', all_users: true, icon: '' };
  let deskLoaded = false;
  let deskTask = null;
  let deskProgress = null;
  let deskIconFile = null;
  let deskIconPrev = '';
  let faviconList = [];
  let faviconWarnings = [];
  let deskTimer = null;
  let curPublicIP = '';          // 当前编辑通道的公网 IP（用于 Webhook 模板占位符替换）
  let curPublicPort = 0;         // 当前编辑通道的公网端口

  // 请求方式 / 日志级别 / 日志存储时间选项
  const logLevelOptions = [
    { value: 'error', label: 'ERROR' },
    { value: 'warn', label: 'WARN' },
    { value: 'info', label: 'INFO' },
    { value: 'debug', label: 'DEBUG' }
  ];
  const logDaysOptions = [
    { value: 7, label: i18nTr("7 天") },
    { value: 30, label: i18nTr("30 天") },
    { value: 90, label: i18nTr("90 天") },
    { value: 180, label: i18nTr("180 天") },
    { value: 365, label: i18nTr("365 天") }
  ];
  // 校验正则（与后端一致）
  const reCustomID = /^[a-z0-9][a-z0-9_-]{1,15}$/;
  function validURL(s) {
    try {
      const u = new URL(s);
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch (e) { return false; }
  }

  // 创建分组弹窗
  let showGroup = false;
  let groupName = '';
  let groupBusy = false;
  let renameGroupName = ''; // 正在重命名的分组（非空=编辑态）

  let delTarget = null; // 待删除通道
  let delGroup = null;  // 待删除分组（有通道时需选择目标分组）
  let delGroupMove = null; // 删除分组时选择的目标分组
  let showDelGroupMove = false; // 是否显示「移动通道到」选择弹窗

  // ==================== 数据加载 ====================
  async function loadCfg() {
    try {
      const d = await api('/api/settings');
      if (d && d.wh_receiver) cfg = Object.assign(cfg, d.wh_receiver);
      if (d && d.wh_template) whTmpl = Object.assign({ method: 'POST', headers: {}, body: '', success_string: '' }, d.wh_template);
    } catch (e) { /* ignore */ }
  }
  async function loadRecords() {
    try {
      const d = await api('/api/wh/records');
      records = (d && d.records) || [];
    } catch (e) { /* ignore */ }
    loading = false;
  }
  async function loadGroups() {
    try {
      const d = await api('/api/wh/groups');
      groups = (d && d.groups) || [];
    } catch (e) { /* ignore */ }
  }
  function loadAll() { loadCfg(); loadRecords(); loadGroups(); }

  // ==================== 通道日志 ====================
  // 打开通道日志弹窗并拉取该通道的运行/访问日志（后端 /api/wh/log 倒序返回，最新在前）
  function openChannelLogs(rec) {
    showChannelInfo = rec;
    loadChannelLogs(rec.channel_id);
  }
  async function loadChannelLogs(id) {
    if (!id) { channelLogs = []; return; }
    channelLogsLoading = true;
    try {
      const d = await api('/api/wh/log?channel_id=' + encodeURIComponent(id) + '&limit=200');
      channelLogs = (d && d.logs) || [];
    } catch (e) {
      channelLogs = [];
    }
    channelLogsLoading = false;
  }

  onMount(() => {
    loadAll();
    timer = pollVisible(() => { loadRecords(); loadGroups(); if (showChannelInfo) loadChannelLogs(showChannelInfo.channel_id); }, 5000);
  });
  onDestroy(() => { if (timer) timer(); });

  // ==================== 分组视图 ====================
  $: kw = search.trim().toLowerCase();
  $: groupList = groups
    .map(g => ({
      name: g.name,
      count: g.count || 0,
      channels: records
        .filter(r => (r.group || DEFAULT_GROUP) === g.name)
        .filter(r => !kw ||
          (r.description || '').toLowerCase().includes(kw) ||
          r.channel_id.toLowerCase().includes(kw))
    }))
    // 无搜索时隐藏空分组；搜索时仅显示有匹配通道的分组
    .filter(g => g.channels.length > 0);

  function toggleGroup(name) {
    collapsed[name] = !collapsed[name];
    collapsed = { ...collapsed };
  }

  // ==================== 分组管理（创建/重命名/删除） ====================
  function openCreateGroup() {
    showGroup = true;
    renameGroupName = '';
    groupName = '';
  }
  function startRenameGroup(name) {
    renameGroupName = name;
    groupName = name;
  }
  async function submitGroup() {
    groupBusy = true;
    try {
      if (renameGroupName) {
        await api('/api/wh/groups/rename', { method: 'POST', body: { old_name: renameGroupName, new_name: groupName } });
        toast(i18nTr("分组已重命名为「") + groupName + '」', 'success');
      } else {
        await api('/api/wh/groups', { method: 'POST', body: { name: groupName } });
        toast(i18nTr("分组「") + groupName + i18nTr("」已创建"), 'success');
      }
      groupName = '';
      renameGroupName = '';
      showGroup = false;
      loadGroups();
      loadRecords();
    } catch (e) {
      toast(e.message, 'error');
    }
    groupBusy = false;
  }
  // 删除分组：分组内有通道时弹出「移动到哪个分组」选择；仅剩默认分组可选时自动移至默认分组并直接删除
  function askDelGroup(name) {
    const count = (groups.find(g => g.name === name) || {}).count || 0;
    if (count === 0) {
      delGroup = name;
      delGroupMove = DEFAULT_GROUP;
      showDelGroupMove = false;
      return;
    }
    const others = groups.filter(g => g.name !== name && g.name !== DEFAULT_GROUP).map(g => g.name);
    if (others.length <= 1) {
      // 只有一个可选目标分组（或仅剩默认分组）：自动移动到默认分组
      delGroup = name;
      delGroupMove = DEFAULT_GROUP;
      showDelGroupMove = false;
      return;
    }
    delGroup = name;
    delGroupMove = '';
    showDelGroupMove = true;
  }
  async function confirmDelGroup() {
    if (!delGroupMove) return;
    const target = delGroupMove || DEFAULT_GROUP;
    try {
      await api('/api/wh/groups?name=' + encodeURIComponent(delGroup) + '&moveTo=' + encodeURIComponent(target), { method: 'DELETE' });
      toast(i18nTr("已删除分组「") + delGroup + i18nTr("」（其通道移至 ") + target + '）', 'success');
      delGroup = null;
      delGroupMove = null;
      showDelGroupMove = false;
      loadGroups();
      loadRecords();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  // ==================== 访问地址 ====================
  // 系统主机：domain 模式用设置中配置的访问域名；IP 模式优先用设置中配置的系统 IP（access_ip），
  // 回退当前页面主机名。接收与访问共用同一 Webhook 端口（receive_port），默认 19520。
  function systemHost() {
    if (cfg.addr_mode === 'domain') {
      const d = (cfg.access_domain || '').trim();
      if (d) return d;
    }
    return (cfg.access_ip || '').trim() || window.location.hostname;
  }
  function portSuffix(p) {
    // 域名模式不带端口：域名已含解析/反代（HTTPS 443 隐含）；仅 IP 地址模式按实际端口显示
    if (cfg.addr_mode === 'domain') return '';
    return p > 0 && p !== 80 && p !== 443 ? ':' + p : '';
  }
  function systemScheme() {
    // 域名模式经 frpc 域名代理（http/https 型代理）访问，默认按 https 展示；IP 模式跟随当前访问协议
    if (cfg.addr_mode === 'domain') return 'https';
    return window.location.protocol === 'https:' ? 'https' : 'http';
  }
  // 访问地址：系统地址（Webhook 端口）/ {通道id}（自定义ID 亦可访问）；域名模式即 域名/{通道id}
  function accessUrl(id) {
    return systemScheme() + '://' + systemHost() + portSuffix(cfg.receive_port) + '/' + id;
  }
  // 接收地址：系统地址（Webhook 端口）/api/channel/update（客户端上报接口）
  function receiveUrl() {
    return systemScheme() + '://' + systemHost() + portSuffix(cfg.receive_port) + '/api/channel/update';
  }

  // ==================== Webhook 配置（完全只读展示） ====================
  // 以下内容由系统根据「Webhook 模板 + 通道信息」自动生成，仅提供复制；变量由客户端按实际值替换
  // 默认请求体模板：channel_id=通道id / host=公网IP或域名 / password=链接密钥 / port=公网端口（变量由客户端按实际值替换）
  const DEFAULT_WH_BODY = `{
  "channel_id": "{channel_id}",
  "host": "{ip}",
  "password": "{link_key}",
  "port": {port}
}`;
  $: whApiUrl = cfg ? receiveUrl() : ''; // 依赖 cfg：配置异步加载后重新计算接口地址
  $: whMethod = (whTmpl.method || 'POST').toUpperCase();
  $: whCallback = (whTmpl.success_string || '').trim() || i18nTr("更新成功");
  $: whHeadersText = Object.keys(whTmpl.headers || {})
    .map((k) => k + ': ' + whTmpl.headers[k])
    .join('\n');
  // Webhook 请求体：channel_id/password 填入当前通道实际值（便于直接复制到客户端）；
  // host/port 保留变量形态 {ip}/{port}（由客户端上报时按实际值替换），不填入具体值
  $: whBody = (whTmpl.body && whTmpl.body.trim() ? whTmpl.body : DEFAULT_WH_BODY)
    .replace(/\{channel_id\}/g, editId || form.custom_id.trim() || '{channel_id}')
    .replace(/\{link_key\}/g, form.link_key.trim() || '{link_key}');
  // 按指定通道记录生成 Webhook 请求体（卡片「Webhook 配置」弹窗用）
  function whBodyFor(rec) {
    const cid = (rec && rec.channel_id) || (rec && rec.custom_id) || '{channel_id}';
    const lk = (rec && rec.link_key) || '{link_key}';
    return (whTmpl.body && whTmpl.body.trim() ? whTmpl.body : DEFAULT_WH_BODY)
      .replace(/\{channel_id\}/g, cid)
      .replace(/\{link_key\}/g, lk);
  }

  async function copy(text) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      toast(i18nTr("已复制到剪贴板"), 'success');
    } catch (e) {
      toast(i18nTr("复制失败，请手动复制"), 'error');
    }
  }

  // ==================== 桌面图标（进阶设置 → 创建桌面图标） ====================
  // 默认应用访问地址：通道ID 对应的访问地址（系统地址 + /{channel_id}）
  function deskKey() { return 'wh.' + (editId || ''); }
  function deskDefaultUrl() { return editId ? accessUrl(editId) : ''; }
  function onDeskEnabledChange() {
    if (!desk.enabled) { deskTask = null; deskProgress = null; }
  }
  async function loadDeskConfig() {
    if (!editId) { deskLoaded = true; return; }
    try {
      const d = await api('/api/desktop/icon?key=' + encodeURIComponent(deskKey()));
      if (d) desk = { enabled: !!d.enabled, name: d.name || '', type: 'url', all_users: d.all_users !== false, icon: d.icon || '' };
    } catch (e) { /* ignore */ }
    deskLoaded = true;
  }
  async function fetchFavicons() {
    const u = deskDefaultUrl();
    if (!u) { toast(i18nTr("暂无可抓取的目标地址"), 'error'); return; }
    try {
      const m = u.match(/^https?:\/\/([^/:]+)(?::(\d+))?/);
      const addr = m ? m[1] : '';
      const port = (m && m[2]) ? Number(m[2]) : (u.startsWith('https') ? 443 : 80);
      const d = await api('/api/desktop/favicon', { method: 'POST', body: { addr, port } });
      faviconList = (d && d.icons) || [];
      faviconWarnings = (d && d.warnings) || [];
      toast(i18nTr("已获取 ") + faviconList.length + i18nTr(" 个网页图标"));
    } catch (e) {
      toast(e.message, 'error');
    }
  }
  function chooseFavicon(ic) {
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
  function apiBaseOf() {
    return typeof window !== 'undefined' && window.location.pathname.match(/^(\/app\/[^/]+)/) ? window.location.pathname.match(/^(\/app\/[^/]+)/)[1] : '';
  }
  async function saveDeskIcon() {
    if (!editId) return;
    const fd = new FormData();
    fd.append('key', deskKey());
    fd.append('enabled', String(desk.enabled));
    fd.append('name', desk.name);
    fd.append('type', desk.type);
    fd.append('all_users', String(desk.all_users));
    fd.append('url', deskDefaultUrl() || '');
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
      }
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  // 弹窗内访问地址列表（基础配置 → 访问地址只读项）：
  // 始终展示通道ID地址；设置自定义ID / 自定义域名时追加对应地址
  $: accessList = (() => {
    const items = [];
    const base = systemScheme() + '://' + systemHost() + portSuffix(cfg.receive_port);
    const cid = editId || i18nTr("{自动分配}");
    const cus = form.custom_id.trim();
    const dom = form.custom_domain.trim().toLowerCase();
    items.push({ tag: i18nTr("通道ID"), url: base + '/' + cid });
    if (cus) items.push({ tag: i18nTr("自定义ID"), url: base + '/' + cus });
    // 自定义域名：域名本身直达通道（根路径即跳转/代理到公网地址），无需 /{id} 路径
    if (dom) items.push({ tag: i18nTr("自定义域名"), url: 'http://' + dom + '/' });
    return items;
  })();

  // 通道的全部访问地址列表（供卡片「访问/复制」使用，含自定义ID 与自定义域名）
  function channelAccessList(rec) {
    const items = [];
    const base = systemScheme() + '://' + systemHost() + portSuffix(cfg.receive_port);
    const cid = rec.channel_id || '';
    const cus = (rec.custom_id || '').trim();
    const dom = (rec.custom_domain || '').trim().toLowerCase();
    if (cid) items.push({ tag: i18nTr("通道ID"), url: base + '/' + cid });
    if (cus) items.push({ tag: i18nTr("自定义ID"), url: base + '/' + cus });
    if (dom) items.push({ tag: i18nTr("自定义域名"), url: 'http://' + dom + '/' });
    return items;
  }
  // 通道是否设置了自定义ID 或自定义域名（有多个访问地址）
  function multiAccess(rec) {
    return !!(rec.custom_id || rec.custom_domain);
  }

  // ==================== 注册/编辑通道 ====================
  function openCreate() {
    editId = '';
    activeTab = 'basic';
    form = {
      group: DEFAULT_GROUP,
      description: '',
      custom_id: '',
      custom_domain: '',
      redirect_type: '',
      link_key: '',
      password: '',
      webhook_url: '',
      callback_char: '',
      webhook_method: 'POST',
      webhook_body: '',
      log_level: 'info',
      log_entries: 500,
      log_days: 30
    };
    formErr = '';
    fieldErr = {};
    domainStatus = '';
    domainMsg = '';
    curPublicIP = '';
    curPublicPort = 0;
    generateKey(); // 创建通道时自动生成唯一链接密钥
    showChannel = true;
  }
  function openEdit(rec) {
    editId = rec.channel_id;
    activeTab = 'basic';
    form = {
      group: rec.group || DEFAULT_GROUP,
      description: rec.description || '',
      custom_id: rec.custom_id || '',
      custom_domain: rec.custom_domain || '',
      redirect_type: rec.redirect_type || '',
      link_key: rec.link_key || '',
      password: rec.password || '',
      webhook_url: rec.webhook_url || '',
      callback_char: rec.callback_char || '',
      webhook_method: rec.webhook_method || 'POST',
      webhook_body: rec.webhook_body || '',
      log_level: rec.log_level || 'info',
      log_entries: rec.log_entries || 500,
      log_days: rec.log_days || 30
    };
    formErr = '';
    fieldErr = {};
    domainStatus = '';
    domainMsg = '';
    curPublicIP = rec.public_ip || '';
    curPublicPort = rec.public_port || 0;
    // 重置桌面图标状态并加载该通道的图标配置
    desk = { enabled: false, name: '', type: 'url', all_users: true, icon: '' };
    deskLoaded = false;
    deskTask = null;
    deskProgress = null;
    deskIconFile = null;
    deskIconPrev = '';
    faviconList = [];
    faviconWarnings = [];
    loadDeskConfig();
    showChannel = true;
  }

  // 表单校验：返回是否通过，错误写入 fieldErr
  function validateForm() {
    const errs = {};
    const cid = form.custom_id.trim().toLowerCase();
    if (cid && (!reCustomID.test(cid) || /^[a-z]{1,4}$/.test(cid))) {
      errs.custom_id = i18nTr("2-16 位小写字母/数字/下划线/连字符，且 4 位及以内纯字母不可用（避免与系统接口冲突）");
    }
    // 自定义域名格式已由输入框 use:field（validateDomain）就地校验，提交时 validateAll 统一拦截
    if (form.webhook_url.trim() && !validURL(form.webhook_url.trim())) {
      errs.webhook_url = i18nTr("请输入合法的 http(s) 地址");
    }
    if (!form.link_key.trim()) {
      errs.link_key = i18nTr("链接密钥为必填项");
    } else if (form.link_key.trim().length < 4 || form.link_key.trim().length > 64) {
      errs.link_key = i18nTr("链接密钥需为 4-64 位");
    }
    if (!form.log_entries || form.log_entries < 100 || form.log_entries > 10000) {
      errs.log_entries = i18nTr("日志存储条数需在 100-10000 之间");
    }
    fieldErr = errs;
    return Object.keys(errs).length === 0;
  }

  // 生成随机链接密钥
  function generateKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let s = '';
    for (let i = 0; i < 24; i++) s += chars[Math.floor(Math.random() * chars.length)];
    form.link_key = s;
    fieldErr = { ...fieldErr, link_key: undefined };
  }

  // 自定义域名验证：校验格式/占用后调用 frpc 代理模块创建域名通道
  async function verifyDomain() {
    domainStatus = '';
    domainMsg = '';
    const d = form.custom_domain.trim().toLowerCase();
    if (!d) {
      domainStatus = 'err';
      domainMsg = i18nTr("请先填写自定义域名");
      return;
    }
    const fmtErr = validateDomain(d);
    if (fmtErr) {
      domainStatus = 'err';
      domainMsg = fmtErr;
      return;
    }
    domainVerifying = true;
    try {
      const res = await api('/api/wh/domain/verify', {
        method: 'POST',
        body: { channel_id: editId, custom_id: form.custom_id, description: form.description, custom_domain: d }
      });
      domainStatus = 'ok';
      domainMsg = i18nTr("代理通道创建成功（frpc 代理 ") + (res && res.proxy_name) + '）';
      form.custom_domain = d;
    } catch (e) {
      domainStatus = 'err';
      domainMsg = e.message;
    }
    domainVerifying = false;
  }

  // 切换标签前校验当前标签字段，防止非法域名随标签隐藏后绕过提交校验
  function switchTab(tab) {
    if (validateAll(formEl)) activeTab = tab;
  }

  async function submitChannel() {
    formErr = '';
    // 格式校验：当前标签内 use:field 字段（自定义域名）统一拦截并就地提示
    if (!validateAll(formEl)) return;
    if (!validateForm()) return;
    saving = true;
    try {
      const body = {
        channel_id: editId || '',
        description: form.description,
        group: form.group,
        custom_id: form.custom_id.trim().toLowerCase(),
        custom_domain: form.custom_domain.trim().toLowerCase(),
        redirect_type: form.redirect_type,
        link_key: form.link_key.trim(),
        password: form.password,
        webhook_url: form.webhook_url.trim(),
        callback_char: form.callback_char.trim(),
        webhook_method: form.webhook_method,
        webhook_body: form.webhook_body,
        log_level: form.log_level,
        log_entries: Number(form.log_entries) || 0,
        log_days: Number(form.log_days) || 0
      };
      const d = await api('/api/wh/records', {
        method: 'POST',
        body
      });
      toast(editId ? i18nTr("通道 ") + editId + i18nTr(" 已更新") : i18nTr("通道 ") + (d && d.channel_id) + i18nTr(" 已注册"), 'success');
      if (editId && deskLoaded) {
        await saveDeskIcon();
      }
      showChannel = false;
      // 创建/更新通道后自动展开其所属分组，便于立即查看新通道
      collapsed = { ...collapsed, [form.group || DEFAULT_GROUP]: false };
      loadAll();
    } catch (e) {
      formErr = e.message;
    }
    saving = false;
  }

  // ==================== 删除 ====================
  // 删除确认提示：通道创建了自定义域名代理时（custom_domain / proxy_name 任一存在），
  // 明确提示删除通道将一并删除该 frpc 域名代理
  function delProxyTip(rec) {
    const base = i18nTr("确定删除通道 ") + rec.channel_id + i18nTr(" 吗？其访问链接将立即失效。");
    const dom = rec.custom_domain ? i18nTr("自定义域名「") + rec.custom_domain + '」' : '';
    const proxy = rec.proxy_name ? i18nTr("frpc 代理「") + rec.proxy_name + '」' : '';
    if (dom || proxy) {
      return base + i18nTr(" 该通道已创建") + [dom, proxy].filter(Boolean).join('、') + i18nTr("，删除通道将一并删除该域名代理。");
    }
    return base;
  }
  async function confirmDelRecord() {
    try {
      await api('/api/wh/records?channel_id=' + encodeURIComponent(delTarget.channel_id), { method: 'DELETE' });
      toast(i18nTr("已删除通道 ") + delTarget.channel_id, 'success');
      delTarget = null;
      loadRecords();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  function initialOf(rec) {
    const t = (rec.description || rec.channel_id || '?').trim();
    return t.charAt(0).toUpperCase();
  }
  // 通道公网地址 → 网站图标地址（/favicon.ico）；通道上报公网地址后即可获取
  function faviconUrl(rec) {
    const scheme = rec.https ? 'https' : 'http';
    const host = rec.public_ip;
    const port = rec.public_port;
    const base = (port && port !== 80 && port !== 443)
      ? scheme + '://' + host + ':' + port
      : scheme + '://' + host;
    return base + '/favicon.ico';
  }
  function typeLabel(rec) {
    switch (rec.redirect_type) {
      case 'proxy': return { text: i18nTr("反向代理"), cls: 'badge badge-info' };
      case 'html': return { text: i18nTr("HTML重写"), cls: 'badge badge-violet' };
      case 'cors': return { text: i18nTr("CORS代理"), cls: 'badge badge-off' };
      case 'ws': return { text: i18nTr("WS隧道"), cls: 'badge badge-info' };
      case '301': case '302': case '307': case '308': return { text: rec.redirect_type, cls: 'badge badge-warn' };
      default: return { text: cfg.mode === 'proxy' ? i18nTr("代理") : i18nTr("重定向"), cls: 'badge badge-off' };
    }
  }
</script>

<div class="container page-full">
  <div class="page-hdr">
    <div>
      <h2>{$i18n("Webhook 通道")}</h2>
      <span class="page-hdr-sub">{$i18n("Webhook 接收 · 公网地址重定向 / 代理到访问域名")}</span>
    </div>
    <div class="page-hdr-actions">
      <div class="hdr-search-wrap">
        <svg class="hdr-search-icon" width="15" height="15" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M21 38C30.3888 38 38 30.3888 38 21C38 11.6112 30.3888 4 21 4C11.6112 4 4 11.6112 4 21C4 30.3888 11.6112 38 21 38Z"/><path d="M33.2216 33.2217L41.7069 41.707" stroke-linecap="round"/></svg>
        <input type="text" class="hdr-search" bind:value={search} placeholder={$i18n("搜索描述 / 通道ID")} />
      </div>
      <div class="hdr-btn-group">
        <button class="btn" title={$i18n("创建分组")} on:click={openCreateGroup}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
          <span class="sm-hide">{$i18n("创建分组")}</span>
        </button>
        <button class="btn btn-primary" title={$i18n("注册通道")} on:click={openCreate}>
          <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="24" r="20"/><path d="M24 16V32"/><path d="M16 24H32"/></svg>
          <span class="sm-hide">{$i18n("注册通道")}</span>
        </button>
      </div>
    </div>
  </div>

  {#if loading}
    <div style="font-size:12px;color:var(--text3);padding:40px;text-align:center">{$i18n("加载中...")}</div>
  {:else if records.length === 0 && !kw}
    <div class="table-wrap wh-empty-wrap">
      <div class="empty">
        <svg width="40" height="40" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="margin:0 auto 10px;display:block;color:var(--text3)"><path d="M5 24L43 24"/><path d="M28 4H20C18.8954 4 18 4.89543 18 6V14C18 15.1046 18.8954 16 20 16H28C29.1046 16 30 15.1046 30 14V6C30 4.89543 29.1046 4 28 4Z"/><path d="M16 32H8C6.89543 32 6 32.8954 6 34V42C6 43.1046 6.89543 44 8 44H16C17.1046 44 18 43.1046 18 42V34C18 32.8954 17.1046 32 16 32Z"/><path d="M40 32H32C30.8954 32 30 32.8954 30 34V42C30 43.1046 30.8954 44 32 44H40C41.1046 44 42 43.1046 42 42V34C42 32.8954 41.1046 32 40 32Z"/><path d="M24 24V16"/><path d="M36 32V24"/><path d="M12 32V24"/></svg>
        <div class="empty-t">{$i18n("暂无通道，等待 STUN 客户端上报，或点击\"注册通道\"手动添加")}</div>
      </div>
    </div>
  {:else}
    <div class="wh-groups">
      {#each groupList as g}
        <section class="wh-group">
          <div class="wh-group-hdr" on:click={() => toggleGroup(g.name)}>
            <span class="wh-arrow">{collapsed[g.name] ? '▸' : '▾'}</span>
            <span class="wh-group-name">{g.name}</span>
            <span class="wh-group-count">{g.channels.length} {$i18n("个通道")}</span>
            {#if g.name !== DEFAULT_GROUP}
              <button
                class="btn-icon wh-group-del"
                style="color:var(--red)"
                title={$i18n("删除分组")}
                aria-label={$i18n("删除分组")}
                on:click={(e) => { e.stopPropagation(); askDelGroup(g.name); }}
              >
                <svg width="15" height="15" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/></svg>
              </button>
            {/if}
          </div>
          {#if !collapsed[g.name]}
            <div class="wh-grid">
              {#each g.channels as rec}
                <div class="wh-card" on:click={() => openEdit(rec)} title={$i18n("点击编辑通道")}>
                  <div class="wh-card-top">
                    <div class="wh-avatar">
                      <span>{initialOf(rec)}</span>
                      {#if rec.public_ip}
                        <img class="wh-favicon" src={faviconUrl(rec)} alt="" loading="lazy" on:error={(e) => (e.target.style.display = 'none')} />
                      {/if}
                    </div>
                    <div class="wh-card-head">
                      <div class="wh-card-title">
                        <span class="wh-card-name">{rec.description || rec.channel_id}</span>
                        <span class="wh-dot" style="background:{rec.public_ip ? 'var(--green)' : 'var(--yellow)'}" title={rec.public_ip ? i18nTr("已上报公网地址") : i18nTr("等待客户端上报")}></span>
                      </div>
                      <div class="wh-card-desc">{$i18n("通道ID-")}{rec.channel_id}</div>
                    </div>
                  </div>
                  <div class="wh-card-addr">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                    <span class="wh-addr-mono">{accessUrl(rec.channel_id)}</span>
                  </div>
                  <div class="wh-card-tags">
                    <div class="tag-list">
                      {#if rec.public_ip}
                        <span class="badge {rec.https ? 'badge-on' : 'badge-info'}">{rec.https ? 'HTTPS' : 'HTTP'}</span>
                      {:else}
                        <span class="badge badge-warn">{$i18n("等待客户端上报")}</span>
                      {/if}
                      <span class="{typeLabel(rec).cls}">{typeLabel(rec).text}</span>
                    </div>
                    <div class="wh-card-actions" on:click={(e) => e.stopPropagation()}>
                      <a
                        class="btn-icon"
                        title={$i18n("访问通道")}
                        aria-label={$i18n("访问通道")}
                        href={accessUrl(rec.channel_id)}
                        target="_blank"
                        rel="noopener"
                        on:click={(e) => { if (multiAccess(rec)) { e.preventDefault(); showAccessLinks = rec; } }}
                      >
                        <svg width="14" height="14" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M28 6H42V20" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M42 29.4737V39C42 40.6569 40.6569 42 39 42H9C7.34315 42 6 40.6569 6 39V9C6 7.34315 7.34315 6 9 6L18 6" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M25.7998 22.1999L41.0998 6.8999" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                      </a>
                      <button class="btn-icon" title={$i18n("Webhook 配置")} aria-label={$i18n("Webhook 配置")} on:click={() => (showWhConfig = rec)}>
                        <svg width="15" height="15" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M17 6C13.6863 6 11 8.68629 11 12C11 15.3137 8.31371 18 5 18V30C8.31371 30 11 32.6863 11 36C11 39.3137 13.6863 42 17 42" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M31 6C34.3137 6 37 8.68629 37 12C37 15.3137 39.6863 18 43 18V30C39.6863 30 37 32.6863 37 36C37 39.3137 34.3137 42 31 42" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                      </button>
                      <button class="btn-icon" title={$i18n("通道日志")} aria-label={$i18n("通道日志")} on:click={() => openChannelLogs(rec)}>
                        <svg width="14" height="14" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="13" y="10" width="28" height="34" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M35 10V4H8C7.44772 4 7 4.44772 7 5V38H13" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 22H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 30H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                      </button>
                      <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑通道")} on:click={() => openEdit(rec)}>
                        <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M10 44H38C39.1046 44 40 43.1046 40 42V14H30V4H10C8.89543 4 8 4.89543 8 6V42C8 43.1046 8.89543 44 10 44Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M30 4L40 14" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 35L31 25L27 21L17 31V35H21Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                      </button>
                      <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} aria-label={$i18n("删除通道")} on:click={() => (delTarget = rec)}>
                        <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                      </button>
                    </div>
                  </div>
                  <div class="wh-card-meta">
                    <span>{rec.public_ip ? i18nTr("公网 ") + rec.public_ip + ':' + rec.public_port : i18nTr("公网地址待上报")} {$i18n("· 更新于")} {rec.updated_at || '-'}</span>
                    <span>{rec.hits || 0} {$i18n("次访问")}</span>
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        </section>
      {/each}
    </div>
  {/if}
</div>

<!-- ===== 注册 / 编辑通道弹窗（参考隧道弹窗：基础配置/进阶设置/Webhook配置/日志设置 四 Tab） ===== -->
{#if showChannel}
  <Modal title={editId ? i18nTr("编辑通道-") + editId : i18nTr("注册通道")} width={540} onClose={() => (showChannel = false)}>
    <div class="tunnel-tabs">
      <button type="button" class="tunnel-tab" class:active={activeTab === 'basic'} on:click={() => switchTab('basic')}>{$i18n("基础配置")}</button>
      <button type="button" class="tunnel-tab" on:click={() => switchTab('advanced')} class:active={activeTab === 'advanced'}>{$i18n("进阶设置")}</button>
      {#if editId}
        <button type="button" class="tunnel-tab" class:active={activeTab === 'desk'} on:click={() => switchTab('desk')}>{$i18n("创建图标")}</button>
      {/if}
      <button type="button" class="tunnel-tab" class:active={activeTab === 'webhook'} on:click={() => switchTab('webhook')}>{$i18n("Webhook配置")}</button>
      <button type="button" class="tunnel-tab" class:active={activeTab === 'log'} on:click={() => switchTab('log')}>{$i18n("日志设置")}</button>
    </div>

    <div bind:this={formEl}>
    {#if activeTab === 'basic'}
      <!-- 基础配置模块 -->
      <div style="display:flex;flex-direction:column;gap:14px">
        <div class="form-group">
          <label class="form-label">{$i18n("描述（可选）")}</label>
          <input type="text" bind:value={form.description} placeholder={$i18n("例如: 家庭NAS穿透")} />
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">{$i18n("所属分组")} <span style="color:var(--red)">*</span></label>
            <CustomSelect bind:value={form.group} options={groupOptions} />
          </div>
          <div class="form-group">
            <label class="form-label">{$i18n("自定义ID")}</label>
            <input type="text" bind:value={form.custom_id} maxlength="16" placeholder={$i18n("支持小写字母/数字/下划线/连字符（2-16 位）")} on:input={(e) => (form.custom_id = e.target.value.toLowerCase())} />
            {#if fieldErr.custom_id}
              <div class="field-err">{fieldErr.custom_id}</div>
            {/if}
          </div>
        </div>
        <div class="form-group">
          <div class="form-label-row">
            <label class="form-label">{$i18n("自定义域名（可选）")}</label>
            <InfoTip text={$i18n("输入后点击「创建代理」，将调用代理模块自动创建代理通道。")} />
          </div>
          <div class="input-action-row">
            <input type="text" bind:value={form.custom_domain} placeholder={$i18n("例如 tun.example.com")} style="flex:1" on:input={() => { if (domainStatus === 'ok') { domainStatus = ''; domainMsg = ''; } }} use:field={{ check: optional(validateDomain), errAt: () => domainErr }} />
            <button class="btn btn-sm" on:click={verifyDomain} disabled={domainVerifying} style="white-space:nowrap" title={$i18n("调用代理模块自动创建代理通道")}>
              {domainVerifying ? i18nTr("创建中…") : i18nTr("创建代理")}
            </button>
          </div>
          <div class="field-err" bind:this={domainErr} style="display:none"></div>
          {#if domainStatus === 'ok'}
            <div class="tip-text" style="color:var(--green, #4ade80)">✓ {domainMsg}</div>
          {:else if domainStatus === 'err'}
            <div class="field-err">{domainMsg}</div>
          {/if}
        </div>
        <div class="form-group">
          <label class="form-label">{$i18n("访问地址（只读）")}</label>
          <div style="display:flex;flex-direction:column;gap:6px">
            {#each accessList as it}
              <div class="wh-addr-row">
                <span class="wh-addr-tag">{it.tag}</span>
                <input type="text" value={it.url} readonly style="flex:1;font-family:var(--mono);font-size:12px;color:var(--text3)" />
                <button class="btn-icon" title={$i18n("复制访问链接")} on:click={() => copy(it.url)}>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                </button>
              </div>
            {/each}
          </div>
        </div>
      </div>
    {:else if activeTab === 'advanced'}
      <!-- 进阶设置模块 -->
      <div style="display:flex;flex-direction:column;gap:14px">
        <div class="form-group">
          <div class="form-label-row">
            <label class="form-label">{$i18n("链接密钥")}</label>
            <InfoTip text={$i18n("创建通道时自动生成唯一密钥；重置后将导致当前通道通讯中断。")} />
          </div>
          <div class="input-action-row">
            <input type="text" bind:value={form.link_key} placeholder={$i18n("访问链接鉴权密钥")} readonly style="flex:1;font-family:var(--mono);font-size:12px" />
            <button class="btn btn-sm" on:click={() => (resetKeyConfirm = true)} style="white-space:nowrap" title={$i18n("重新生成链接密钥，重置后当前通道通讯将中断")}>{$i18n("重置")}</button>
          </div>
          {#if fieldErr.link_key}
            <div class="field-err">{fieldErr.link_key}</div>
          {/if}
        </div>
        <div class="form-group">
          <div class="form-label-row">
            <label class="form-label">{$i18n("连接密码（可选）")}</label>
            <InfoTip text={$i18n("访问通道时需要输入的密码，留空时自动禁用密码保护。")} />
          </div>
          <input type="text" bind:value={form.password} placeholder={$i18n("访问时需要输入的密码")} autocomplete="off" />
          {#if form.password}
            <div class="tip-text"><span style="color:var(--green, #4ade80)">{$i18n("● 已启用密码保护")}</span>{$i18n("（留空即可禁用）")}</div>
          {/if}
        </div>
        <div class="form-group">
          <label class="form-label">{$i18n("访问方式（请求类型）")}</label>
          <div class="wh-type-grid">
            <div class="wh-type-opt" class:sel={form.redirect_type === ''} on:click={() => (form.redirect_type = '')} title={$i18n("跟随全局设置")}>
              <div class="wh-type-name">{$i18n("跟随全局")}</div>
              <div class="wh-type-desc">{cfg.mode === 'proxy' ? i18nTr("反向代理") : i18nTr("重定向")}</div>
            </div>
            <div class="wh-type-opt" class:sel={form.redirect_type === '302'} on:click={() => (form.redirect_type = '302')} title={$i18n("临时重定向，可缓存，方法可能从 POST 变更为 GET")}>
              <div class="wh-type-name">302 Found</div>
              <div class="wh-type-desc">{$i18n("临时重定向 · 可缓存")}</div>
            </div>
            <div class="wh-type-opt" class:sel={form.redirect_type === '301'} on:click={() => (form.redirect_type = '301')} title={$i18n("永久重定向，强制缓存，方法可能从 POST 变更为 GET")}>
              <div class="wh-type-name">301 Moved</div>
              <div class="wh-type-desc">{$i18n("永久重定向 · 强缓存")}</div>
            </div>
            <div class="wh-type-opt" class:sel={form.redirect_type === '307'} on:click={() => (form.redirect_type = '307')} title={$i18n("临时重定向，禁止缓存，严格保留原始请求方法")}>
              <div class="wh-type-name">307 Temporary</div>
              <div class="wh-type-desc">{$i18n("临时重定向 · 保留方法")}</div>
            </div>
            <div class="wh-type-opt" class:sel={form.redirect_type === '308'} on:click={() => (form.redirect_type = '308')} title={$i18n("永久重定向，强制缓存，严格保留原始请求方法")}>
              <div class="wh-type-name">308 Permanent</div>
              <div class="wh-type-desc">{$i18n("永久重定向 · 保留方法")}</div>
            </div>
            <div class="wh-type-opt" class:sel={form.redirect_type === 'proxy'} on:click={() => (form.redirect_type = 'proxy')} title={$i18n("服务网关透明转发，保持请求头完整性，支持路径重写")}>
              <div class="wh-type-name">{$i18n("反向代理")}</div>
              <div class="wh-type-desc">{$i18n("透明转发 · 保持请求头")}</div>
            </div>
            <div class="wh-type-opt" class:sel={form.redirect_type === 'html'} on:click={() => (form.redirect_type = 'html')} title={$i18n("完整网页内嵌，资源路径重写 + 运行时接口适配")}>
              <div class="wh-type-name">{$i18n("HTML重写代理")}</div>
              <div class="wh-type-desc">{$i18n("网页内嵌 · 路径重写")}</div>
            </div>
            <div class="wh-type-opt" class:sel={form.redirect_type === 'cors'} on:click={() => (form.redirect_type = 'cors')} title={$i18n("前端跨域接口中转，自定义响应头 + 数据透传")}>
              <div class="wh-type-name">{$i18n("CORS接口代理")}</div>
              <div class="wh-type-desc">{$i18n("跨域中转 · 自定义响应头")}</div>
            </div>
            <div class="wh-type-opt" class:sel={form.redirect_type === 'ws'} on:click={() => (form.redirect_type = 'ws')} title={$i18n("WebSocket 长连接隧道，稳定转发，数据完整")}>
              <div class="wh-type-name">{$i18n("WebSocket隧道")}</div>
              <div class="wh-type-desc">{$i18n("长连接 · 稳定转发")}</div>
            </div>
          </div>
        </div>

      </div>
    {:else if activeTab === 'desk'}
      <!-- 创建桌面图标（独立 Tab）：默认访问地址为通道访问地址 -->
      <div style="display:flex;flex-direction:column;gap:14px">
        <div class="form-row" style="align-items:center">
          <div class="form-group" style="flex:1">
            <label class="form-label">{$i18n("创建桌面图标")}</label>
            <div class="tip-text">{$i18n("在 fnOS 桌面生成该通道的快捷入口（默认访问地址：")}{deskDefaultUrl() || i18nTr("未配置访问地址")}{$i18n("，点击后在浏览器新标签页打开）")}</div>
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
                <div class="tip-text" style="padding:7px 0;line-height:1.5">{$i18n("浏览器标签页（url）")}<br>{$i18n("外部访问地址仅支持在新标签页打开")}</div>
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
                  <button type="button" class="btn btn-sm" on:click={fetchFavicons}>{$i18n("获取图标")}</button>
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
      </div>
    {:else if activeTab === 'webhook'}
      <!-- Webhook 配置模块（完全只读）：内容由系统根据「Webhook 模板 + 通道信息」自动生成，仅提供复制 -->
      <div style="display:flex;flex-direction:column;gap:14px">
        <div class="form-group">
          <label class="form-label">{$i18n("接口地址")}</label>
          <div class="wh-ro-row">
            <input type="text" value={whApiUrl} readonly style="font-family:var(--mono);font-size:12px" />
            <button type="button" class="btn btn-sm" on:click={() => copy(whApiUrl)}>{$i18n("复制")}</button>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">{$i18n("请求方式")}</label>
            <div class="wh-ro-row">
              <input type="text" value={whMethod} readonly style="font-family:var(--mono);font-size:12px" />
              <button type="button" class="btn btn-sm" on:click={() => copy(whMethod)}>{$i18n("复制")}</button>
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">{$i18n("回调字符")}</label>
            <div class="wh-ro-row">
              <input type="text" value={whCallback} readonly />
              <button type="button" class="btn btn-sm" on:click={() => copy(whCallback)}>{$i18n("复制")}</button>
            </div>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">{$i18n("请求头")}</label>
          <div class="wh-ro-row">
            <input type="text" value={whHeadersText} readonly style="font-family:var(--mono);font-size:12px" />
            <button type="button" class="btn btn-sm" on:click={() => copy(whHeadersText)}>{$i18n("复制")}</button>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">{$i18n("请求体（JSON 模板）")}</label>
          <div class="wh-ro-row" style="align-items:stretch">
            <textarea rows="6" value={whBody} readonly spellcheck="false" style="font-family:var(--mono);font-size:12px"></textarea>
            <button type="button" class="btn btn-sm" style="align-self:flex-start" on:click={() => copy(whBody)}>{$i18n("复制")}</button>
          </div>
        </div>
      </div>
    {:else}
      <!-- 日志设置模块 -->
      <div style="display:flex;flex-direction:column;gap:14px">
        <div class="form-row">
          <div class="form-group">
            <div class="form-label-row">
              <label class="form-label">{$i18n("日志输出级别")}</label>
              <InfoTip text={$i18n("该通道运行日志的过滤级别。")} />
            </div>
            <CustomSelect bind:value={form.log_level} options={logLevelOptions} />
          </div>
          <div class="form-group">
            <div class="form-label-row">
              <label class="form-label">{$i18n("日志存储条数")}</label>
              <InfoTip text={$i18n("该通道独立存储的日志最大条数（100-10000）。")} />
            </div>
            <input type="number" bind:value={form.log_entries} min="100" max="10000" step="100" placeholder="100-10000" />
            {#if fieldErr.log_entries}
              <div class="field-err">{fieldErr.log_entries}</div>
            {/if}
          </div>
        </div>
        <div class="form-group">
          <div class="form-label-row">
            <label class="form-label">{$i18n("日志存储时间")}</label>
            <InfoTip text={$i18n("超出保存时间的日志将被自动清理。")} />
          </div>
          <CustomSelect bind:value={form.log_days} options={logDaysOptions} />
        </div>
      </div>
    {/if}
    </div>

    {#if formErr}
      <div class="tip-text" style="color:var(--red);margin-top:12px">{formErr}</div>
    {/if}
    <div slot="footer" style="display:flex;gap:8px">
      <button class="btn" on:click={() => (showChannel = false)} disabled={saving}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={submitChannel} disabled={saving}>
        {saving ? i18nTr("保存中…") : editId ? i18nTr("保存") : i18nTr("注册")}
      </button>
    </div>
  </Modal>
{/if}

<!-- ===== 创建/编辑分组弹窗 ===== -->
{#if showGroup}
  <Modal title={renameGroupName ? i18nTr("编辑分组") : i18nTr("创建分组")} width={460} onClose={() => (showGroup = false)}>
    <div class="form-group">
      <div class="form-label-row">
        <label class="form-label">{$i18n("分组名称")}</label>
        <InfoTip text={$i18n("1-16 位中文/字母/数字/下划线/连字符；创建后可在注册/编辑通道时选择")} />
      </div>
      <input type="text" bind:value={groupName} placeholder={$i18n("例如: 家庭 / 办公 / 测试")} on:keydown={(e) => { if (e.key === 'Enter' && groupName.trim() && !groupBusy) submitGroup(); }} />
    </div>
    {#if !renameGroupName}
      <div style="font-size:12px;font-weight:600;color:var(--text3);margin:14px 0 8px;letter-spacing:.5px">{$i18n("已有分组（点击名称可重命名）")}</div>
      <div class="wh-group-mgr-list" class:many={groups.length > 5}>
        {#each groups as g}
          <div class="wh-group-mgr-item">
            <span class="wh-group-mgr-name" title={$i18n("点击重命名")} on:click={() => startRenameGroup(g.name)}>{g.name}</span>
            <span class="wh-group-mgr-count">{g.count} {$i18n("项")}</span>
            <span class="wh-group-mgr-actions">
              {#if g.name !== DEFAULT_GROUP}
                <button class="btn-icon" title={$i18n("重命名")} aria-label={$i18n("重命名分组")} on:click={() => startRenameGroup(g.name)}>
                  <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M10 44H38C39.1046 44 40 43.1046 40 42V14H30V4H10C8.89543 4 8 4.89543 8 6V42C8 43.1046 8.89543 44 10 44Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M30 4L40 14" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 35L31 25L27 21L17 31V35H21Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>
                <button class="btn-icon" style="color:var(--red)" title={$i18n("删除分组")} aria-label={$i18n("删除分组")} on:click={() => { showGroup = false; askDelGroup(g.name); }}>
                  <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/></svg>
                </button>
              {/if}
            </span>
          </div>
        {/each}
      </div>
    {/if}
    <div slot="footer" style="display:flex;gap:8px">
      <button class="btn" on:click={() => (showGroup = false)} disabled={groupBusy}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={submitGroup} disabled={groupBusy || !groupName.trim()}>
        {groupBusy ? i18nTr("保存中…") : renameGroupName ? i18nTr("保存") : i18nTr("创建")}
      </button>
    </div>
  </Modal>
{/if}

{#if delTarget}
  <ConfirmModal
    title={$i18n("删除通道")}
    message={delProxyTip(delTarget)}
    confirmText={$i18n("删除")}
    onConfirm={confirmDelRecord}
    onClose={() => (delTarget = null)}
  />
{/if}
{#if delGroup && !showDelGroupMove}
  <ConfirmModal
    title={$i18n("删除分组")}
    message={i18nTr("确定删除分组「") + delGroup + i18nTr("」吗？") + (delGroupMove === DEFAULT_GROUP && (groups.find(g => g.name === delGroup) || {}).count > 0 ? i18nTr("该分组下的通道将移至 Webhook 通道分组。") : '')}
    confirmText={$i18n("删除")}
    onConfirm={confirmDelGroup}
    onClose={() => (delGroup = null)}
  />
{/if}
{#if showDelGroupMove && delGroup}
  <Modal title={$i18n("删除分组")} width={420} onClose={() => { showDelGroupMove = false; delGroup = null; }}>
    <div style="font-size:13px;color:var(--text2);line-height:1.8;margin-bottom:12px">
      {$i18n("分组「")}{delGroup}{$i18n("」下存在")} {(groups.find(g => g.name === delGroup) || {}).count} {$i18n("个通道，请选择删除后这些通道要移动到的分组：")}
    </div>
    <div class="wh-move-list">
      {#each groups.filter(g => g.name !== delGroup) as g}
        <label class="wh-move-item">
          <input type="radio" bind:group={delGroupMove} value={g.name} />
          <span>{g.name}</span>
          <span style="font-size:11px;color:var(--text3)">{g.count} {$i18n("项")}</span>
        </label>
      {/each}
    </div>
    <div slot="footer" style="display:flex;gap:8px">
      <button class="btn" on:click={() => { showDelGroupMove = false; delGroup = null; }}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={confirmDelGroup} disabled={!delGroupMove}>{$i18n("确认删除并移动")}</button>
    </div>
  </Modal>
{/if}
{#if resetKeyConfirm}
  <ConfirmModal
    title={$i18n("重置链接密钥")}
    message={$i18n("重置后当前通道通讯将中断，客户端需使用新的密钥重新连接。确定要重置链接密钥吗？")}
    confirmText={$i18n("重置")}
    onConfirm={() => { generateKey(); resetKeyConfirm = false; }}
    onClose={() => (resetKeyConfirm = false)}
  />
{/if}
{#if showAccessLinks}
  <Modal title={i18nTr("通道访问地址 · ") + (showAccessLinks.channel_id || '')} width={540} onClose={() => (showAccessLinks = null)}>
    <div style="display:flex;flex-direction:column;gap:8px">
      {#each channelAccessList(showAccessLinks) as it}
        <div class="wh-addr-row">
          <span class="wh-addr-tag">{it.tag}</span>
          <input type="text" value={it.url} readonly style="flex:1;font-family:var(--mono);font-size:12px;color:var(--text3)" />
          <a class="btn btn-sm btn-primary" href={it.url} target="_blank" rel="noopener" style="white-space:nowrap;text-decoration:none">{$i18n("访问")}</a>
          <button class="btn-icon" title={$i18n("复制该地址")} aria-label={$i18n("复制该地址")} on:click={() => copy(it.url)}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
      {/each}
    </div>
    <div class="tip-text" style="margin-top:12px;line-height:1.7">{$i18n("自定义域名根路径即直达通道（跳转/代理到公网地址）；设置了访问密码的通道需先通过密码验证。")}</div>
  </Modal>
{/if}
{#if showChannelInfo}
  <Modal title={i18nTr("通道日志 · ") + (showChannelInfo.channel_id || '')} width={640} onClose={() => (showChannelInfo = null)}>
    <div class="wh-log-info">
      <span class="wh-log-meta">{$i18n("公网地址：")}{showChannelInfo.public_ip ? showChannelInfo.public_ip + ':' + showChannelInfo.public_port : i18nTr("等待客户端上报")}</span>
      <span class="wh-log-meta">{$i18n("日志级别：")}{(showChannelInfo.log_level || 'info').toUpperCase()}</span>
      <span class="wh-log-meta">{$i18n("存储条数：")}{showChannelInfo.log_entries || 500}</span>
      <button type="button" class="btn btn-sm" on:click={() => loadChannelLogs(showChannelInfo.channel_id)}>{$i18n("刷新")}</button>
    </div>
    <div class="wh-log-list">
      {#if channelLogsLoading && channelLogs.length === 0}
        <div class="wh-log-empty">{$i18n("加载中…")}</div>
      {:else if channelLogs.length === 0}
        <div class="wh-log-empty">{$i18n("暂无日志记录。客户端上报公网地址、访问通道（跳转/代理/密码验证）、通道注册/编辑/删除等操作会记录在这里。")}</div>
      {:else}
        {#each channelLogs as lg}
          <div class="wh-log-row">
            <span class="wh-log-level {lg.level.toLowerCase()}">{lg.level}</span>
            <span class="wh-log-time">{lg.time}</span>
            <span class="wh-log-msg">{lg.message}</span>
          </div>
        {/each}
      {/if}
    </div>
    <div class="tip-text" style="margin-top:10px;line-height:1.7">{$i18n("日志按最新在前展示，弹窗打开期间每 3 秒自动刷新；日志级别与存储条数可在 通道编辑 → 日志设置 中配置。")}</div>
  </Modal>
{/if}
{#if showWhConfig}
  <Modal title={i18nTr("通道 Webhook 配置 · ") + (showWhConfig.channel_id || '')} width={620} onClose={() => (showWhConfig = null)}>
    <div style="display:flex;flex-direction:column;gap:14px">
      <div class="form-group">
        <label class="form-label">{$i18n("接口地址")}</label>
        <div class="wh-ro-row">
          <input type="text" value={receiveUrl()} readonly style="font-family:var(--mono);font-size:12px" />
          <button type="button" class="btn btn-sm" on:click={() => copy(receiveUrl())}>{$i18n("复制")}</button>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">{$i18n("请求方式")}</label>
          <div class="wh-ro-row">
            <input type="text" value={whMethod} readonly style="font-family:var(--mono);font-size:12px" />
            <button type="button" class="btn btn-sm" on:click={() => copy(whMethod)}>{$i18n("复制")}</button>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">{$i18n("回调字符")}</label>
          <div class="wh-ro-row">
            <input type="text" value={whCallback} readonly />
            <button type="button" class="btn btn-sm" on:click={() => copy(whCallback)}>{$i18n("复制")}</button>
          </div>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">{$i18n("请求头")}</label>
        <div class="wh-ro-row">
          <input type="text" value={whHeadersText} readonly style="font-family:var(--mono);font-size:12px" />
          <button type="button" class="btn btn-sm" on:click={() => copy(whHeadersText)}>{$i18n("复制")}</button>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">{$i18n("请求体（JSON 模板）")}</label>
        <div class="wh-ro-row" style="align-items:stretch">
          <textarea rows="6" value={whBodyFor(showWhConfig)} readonly spellcheck="false" style="font-family:var(--mono);font-size:12px"></textarea>
          <button type="button" class="btn btn-sm" style="align-self:flex-start" on:click={() => copy(whBodyFor(showWhConfig))}>{$i18n("复制")}</button>
        </div>
      </div>
    </div>
    <div class="tip-text" style="margin-top:10px;line-height:1.7">{$i18n("以上为客户端上报所需配置，host/port 保留变量")} {'{ip}'}/{'{port}'}{$i18n("，由客户端按实际值替换；供直接复制到客户端使用。")}</div>
  </Modal>
{/if}

<style>
  /* 分组容器（参考 STUN 面板通道列表的分组布局） */
  .wh-groups { display: flex; flex-direction: column; gap: 14px; flex: 1 1 auto; min-height: 0; overflow-y: auto; }
  /* 无通道时空状态卡片按内容高度收缩，避免撑满整页 */
  .page-full .table-wrap.wh-empty-wrap{flex:0 0 auto}
  /* 创建分组弹窗：已有分组管理列表 */
  .wh-group-mgr-list {
    display: flex; flex-direction: column; gap: 6px;
    overflow-y: auto;
    padding-right: 4px;
    max-height: none;
  }
  /* 超过 5 个分组时限制高度启用滚动条（约 5 行） */
  .wh-group-mgr-list.many { max-height: 246px; }
  .wh-group-mgr-item {
    display: flex; align-items: center; gap: 10px;
    padding: 7px 10px;
    background: var(--bg4); border: 1px solid var(--bd);
    border-radius: var(--radius);
  }
  .wh-group-mgr-name {
    flex: 1; min-width: 0; font-size: 13px; color: var(--text);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    cursor: pointer;
  }
  .wh-group-mgr-name:hover { color: var(--accent); }
  .wh-group-mgr-count { font-size: 11px; color: var(--text3); white-space: nowrap; }
  .wh-group-mgr-actions { display: inline-flex; gap: 2px; flex-shrink: 0; }
  /* 删除分组：选择目标分组列表 */
  .wh-move-list {
    display: flex; flex-direction: column; gap: 8px;
    max-height: 220px; overflow-y: auto; padding-right: 4px;
  }
  .wh-move-item {
    display: flex; align-items: center; gap: 10px;
    padding: 9px 12px;
    background: var(--bg4); border: 1px solid var(--bd);
    border-radius: var(--radius); cursor: pointer; font-size: 13px; color: var(--text);
  }
  .wh-move-item:hover { border-color: var(--accent); }
  .wh-group {
    background: var(--bg3); border: 1px solid var(--bd);
    border-radius: calc(var(--radius) + 4px); overflow: hidden;
    box-shadow: var(--shadow-card);
  }
  .wh-group-hdr {
    display: flex; align-items: center; gap: 8px; padding: 11px 16px;
    background: var(--bg4); border-bottom: 1px solid var(--bd);
    cursor: pointer; user-select: none;
  }
  .wh-group-hdr:hover { background: rgba(var(--accent-rgb), .06); }
  .wh-arrow { font-size: 11px; color: var(--text3); transition: transform .15s; }
  .wh-group-name { font-weight: 600; font-size: 13.5px; color: var(--text); }
  .wh-group-count {
    margin-left: auto; font-family: var(--mono); font-size: 10px; color: var(--text3);
    border: 1px solid var(--bd); border-radius: 4px; padding: 1px 6px;
  }
  .wh-group-del { width: 28px; height: 28px; flex-shrink: 0; }

  /* 卡片网格：桌面两列，移动端单列 */
  .wh-grid {
    display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px; padding: 14px 16px 16px;
  }
  .wh-card {
    display: flex; flex-direction: column; gap: 9px; min-width: 0;
    background: var(--bg4); border: 1px solid var(--bd); border-radius: var(--radius);
    padding: 13px 14px; cursor: pointer; transition: border-color .15s, transform .15s;
  }
  .wh-card:hover { border-color: rgba(var(--accent-rgb), .45); transform: translateY(-1px); }
  .wh-card-top { display: flex; align-items: flex-start; gap: 9px; min-width: 0; }
  .wh-avatar {
    width: 30px; height: 30px; border-radius: 8px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
    background: rgba(var(--accent-rgb), .15); color: var(--accent);
    font-size: 13px; font-weight: 700;
    position: relative; overflow: hidden;
  }
  /* 公网地址网站图标：覆盖在首字符上，加载失败时隐藏回退到首字符 */
  .wh-favicon {
    position: absolute; inset: 0; width: 100%; height: 100%;
    border-radius: 8px; object-fit: cover; background: var(--bg4); padding: 3px;
  }
  .wh-card-head { flex: 1; min-width: 0; }
  .wh-card-title { display: flex; align-items: center; gap: 6px; min-width: 0; }
  .wh-card-name {
    flex: 1; min-width: 0;
    font-size: 13px; font-weight: 600; color: var(--text);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .wh-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
  .wh-card-desc {
    margin-top: 3px; font-family: var(--mono); font-size: 10.5px; color: var(--text3);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .wh-card-addr { display: flex; align-items: center; gap: 6px; min-width: 0; color: var(--text2); }
  .wh-card-addr svg { flex-shrink: 0; color: var(--text3); }
  .wh-addr-mono { font-family: var(--mono); font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .wh-card-tags { display: flex; align-items: center; gap: 6px; min-width: 0; flex-wrap: wrap; }
  .tag-list { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; min-width: 0; }
  .wh-card-actions { display: flex; align-items: center; gap: 2px; margin-left: auto; flex-shrink: 0; }
  .wh-card-meta {
    display: flex; justify-content: space-between; gap: 8px;
    border-top: 1px dashed rgba(128,128,128,.16); padding-top: 8px;
    font-size: 10px; color: var(--text3);
  }
  .wh-card-meta span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .wh-card-meta span:last-child { flex-shrink: 0; }

  /* Webhook 配置（只读展示）：输入框拉伸 + 复制按钮固定 */
  .wh-ro-row { display: flex; align-items: center; gap: 8px; }
  .wh-ro-row > input,
  .wh-ro-row > textarea { flex: 1; min-width: 0; }

  /* 访问地址（只读）行：标签 + 地址 + 复制按钮 */
  .wh-addr-row { display: flex; align-items: center; gap: 6px; }
  .wh-addr-tag { flex-shrink: 0; font-size: 11px; color: var(--text3); padding: 1px 6px; border: 1px solid var(--bd); border-radius: 4px; background: var(--bg3); white-space: nowrap; }
  .wh-ro-row > .btn { flex-shrink: 0; }

  /* 访问方式选项网格：一行三个（参考 STUN 面板请求类型选择器） */
  .wh-type-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; }
  .wh-type-opt {
    border: 1px solid var(--bd); border-radius: 8px; padding: 8px 10px;
    background: var(--bg4); cursor: pointer;
    transition: border-color .15s, background .15s;
  }
  .wh-type-opt:hover { border-color: rgba(var(--accent-rgb), .5); }
  .wh-type-opt.sel { border-color: var(--accent); background: rgba(var(--accent-rgb), .1); }
  .wh-type-name { font-size: 12px; font-weight: 600; color: var(--text); }
  .wh-type-desc { font-size: 10px; color: var(--text3); margin-top: 2px; }

  /* 移动端：卡片单列铺满，访问方式选项两列 */
  @media (max-width:600px){
    .wh-grid{grid-template-columns:1fr;padding:10px 12px 12px;gap:9px}
    .wh-card{padding:12px}
    .wh-card-tags{flex-wrap:wrap}
    .wh-type-grid{grid-template-columns:1fr 1fr}
    .wh-group-hdr{flex-wrap:wrap;padding:10px 12px}
    .wh-addr-row{flex-wrap:wrap}
  }
  /* 字段级错误提示 */
  .field-err { font-size: 12px; color: var(--red); margin-top: 4px; }

  /* 通道日志弹窗 */
  .wh-log-info { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 10px; }
  .wh-log-meta { font-size: 12px; color: var(--text3); }
  .wh-log-meta + .btn { margin-left: auto; }
  .wh-log-list {
    display: flex; flex-direction: column; gap: 2px;
    max-height: 420px; overflow-y: auto;
    border: 1px solid var(--bd); border-radius: 8px;
    background: var(--bg3); padding: 8px;
    font-size: 12px;
  }
  .wh-log-row { display: flex; align-items: baseline; gap: 8px; padding: 4px 6px; border-radius: 4px; }
  .wh-log-row:hover { background: rgba(var(--accent-rgb), .05); }
  .wh-log-level {
    flex-shrink: 0; width: 46px; text-align: center;
    font-size: 10px; font-weight: 700; letter-spacing: .5px;
    padding: 1px 0; border-radius: 3px; font-family: var(--mono);
  }
  .wh-log-level.error { color: var(--red); background: rgba(var(--red-rgb), .08); }
  .wh-log-level.warn  { color: var(--yellow); background: rgba(var(--yellow-rgb), .08); }
  .wh-log-level.info  { color: var(--blue); background: rgba(var(--blue-rgb), .08); }
  .wh-log-level.debug { color: var(--slate); background: rgba(var(--slate-rgb), .08); }
  .wh-log-time { flex-shrink: 0; font-family: var(--mono); font-size: 11px; color: var(--text3); }
  .wh-log-msg { color: var(--text2); word-break: break-all; line-height: 1.6; }
  .wh-log-empty { padding: 24px 12px; text-align: center; color: var(--text3); font-size: 12px; line-height: 1.8; }
</style>
