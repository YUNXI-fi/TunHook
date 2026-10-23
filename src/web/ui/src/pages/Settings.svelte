<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 系统设置页：子分区清单的唯一来源是 lib/stores.js 的 settingsTabs
  import { onMount, onDestroy, tick } from 'svelte';
  import { settings, settingsSect, settingsTabs, toast, theme, ACCENTS, uiCfg, UI_DEFAULTS, MODULES, FIXED_MODULES, disabledModules } from '../lib/stores.js';
  import { api, streamNDJSON } from '../lib/api.js';
  import GeoModal from '../components/GeoModal.svelte';
  import BackupExportModal from '../components/BackupExportModal.svelte';
  import BackupRestoreModal from '../components/BackupRestoreModal.svelte';
  import FrpcUpgradeModal from '../components/FrpcUpgradeModal.svelte';
  import AddServerModal from '../components/AddServerModal.svelte';
  import EditServerNameModal from '../components/EditServerNameModal.svelte';
  import ConfirmModal from '../components/ConfirmModal.svelte';
  import Modal from '../components/Modal.svelte';
  import Toggle from '../components/Toggle.svelte';
  import CustomSelect from '../components/CustomSelect.svelte';
  import InfoTip from '../components/InfoTip.svelte';
  import TomlEditor from '../components/TomlEditor.svelte';
  import ErrorPagesPanel from '../components/ErrorPagesPanel.svelte';
  import {
    fmtTime, highlightLog, pollVisible, reverseLines,
    validatePort, validateHost, validateDomain, validateHostPort,
    validateCIDR, validateIP, validateRecordName, optional
  } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';

  // 页头副标题跟随当前分区
  $: currentSect = settingsTabs.find((t) => t.id === $settingsSect) || settingsTabs[0];
  $: sectDesc = currentSect.desc;

  // 页头操作：仅在有真实保存 / 重置动作的分区展示，避免出现无效按钮
  $: canSaveSect = ['default', 'stun', 'frpc'].includes($settingsSect);
  $: canResetSect = $settingsSect === 'ui';
  function saveCurrent() {
    if ($settingsSect === 'default') saveSettings();
    else if ($settingsSect === 'stun') saveStunSettings();
    else if ($settingsSect === 'frpc') frpcSave();
  }

  // 当前主色 / 辅助色配对（与 App.svelte 的 applyUI 取值口径一致）
  $: uiPair = ACCENTS[$uiCfg.accent] || null;
  $: uiPrimary = uiPair ? ($theme === 'light' ? uiPair.light : uiPair.dark) : $uiCfg.customColor;
  $: uiSecondary = uiPair
    ? ($theme === 'light' ? uiPair.secLight : uiPair.secDark)
    : ($theme === 'light' ? '#6d4fd4' : '#a78bfa');
  $: uiPairName = uiPair ? uiPair.name : i18nTr("自定义");
  $: uiSecName = uiPair ? uiPair.secName : i18nTr("紫罗兰");

  // 顶部分区 Tabs：活动下划线指示条跟随当前分区。
  // 必须先 tick 等 DOM 更新后再测量，否则新增/切换分区时宽度会拿到旧值。
  let sectTabsEl;
  let barX = 0;
  let barW = 0;
  let canScrollLeft = false;
  let canScrollRight = false;
  $: if ($settingsSect) tick().then(updateSectBar);

  function updateSectBar() {
    if (!sectTabsEl) return;
    const idx = settingsTabs.findIndex((t) => t.id === $settingsSect);
    const el = sectTabsEl.querySelectorAll('.sect-tab')[idx];
    if (el) {
      barX = el.offsetLeft;
      barW = el.offsetWidth;
    }
    updateScrollState();
  }

  // 标签溢出时显示左右滚动箭头
  function updateScrollState() {
    if (!sectTabsEl) return;
    const max = sectTabsEl.scrollWidth - sectTabsEl.clientWidth;
    canScrollLeft = sectTabsEl.scrollLeft > 1;
    canScrollRight = max > 1 && sectTabsEl.scrollLeft < max - 1;
  }

  function scrollTabs(dir) {
    if (!sectTabsEl) return;
    sectTabsEl.scrollBy({ left: dir * Math.max(160, sectTabsEl.clientWidth * 0.6), behavior: 'smooth' });
  }

  function selectSect(id, i) {
    settingsSect.set(id);
    // 窄屏 Tabs 可横向滚动：切换时把目标标签带入可视区
    const el = sectTabsEl && sectTabsEl.querySelectorAll('.sect-tab')[i];
    if (el) el.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'smooth' });
  }

  // 下拉选项
  const addrModeOptions = [
    { value: 'ip', label: i18nTr("使用 IP") },
    { value: 'domain', label: i18nTr("使用域名") }
  ];
  const methodOptions = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'].map((m) => ({ value: m, label: m }));
  const protocolOptions = ['tcp', 'kcp', 'quic', 'websocket'].map((p) => ({ value: p, label: p }));
  const logLevelOptions = ['debug', 'info', 'warn', 'error'].map((l) => ({ value: l, label: l }));
  // IP 地址库分类中文标签（与后端 geoloc.CategoryLabels 对应）
  const ipfRegionLabels = { country: i18nTr("国家"), china: i18nTr("内地"), province: i18nTr("省级"), city: i18nTr("市级"), isp: i18nTr("运营商"), cloud: i18nTr("公有云") };

  // 表单字段
  let fwd = { http_default_port: 18080, https_default_port: 14430 };
  // Web 服务路径模式对外访问方式：ip=本机 IP + 统一 HTTP 端口；domain=域名（按 443 展示）
  let webAccess = { mode: 'ip', ip: '', domain: '' };
  let log = { tunnel_max_entries: 128, tunnel_access_max_entries: 128, expire_days: 31, traffic_retention_days: 31 };
  // Webhook 接收（地址模式：使用IP/可选域名；接收与访问共用单一端口）
  let wh = { enabled: false, addr_mode: 'ip', access_domain: '', access_ip: '', receive_port: 19520 };
  // 本机局域网 IP / 公网地址（IP 模式下系统地址解析：优先公网地址，回退本机局域网地址，来自 /api/status）
  let localIP = '';
  let publicIP = '';
  async function loadLocalIP() {
    try {
      const d = await api('/api/status');
      if (d && d.local_ip) localIP = d.local_ip;
      if (d && d.public_ip) publicIP = d.public_ip;
      // 访问IP 留空时自动填入解析到的系统地址（优先公网，其次本机局域网），随保存写入配置
      fillAccessIPIfEmpty();
      fillWebAccessIPIfEmpty();
    } catch (e) { /* ignore */ }
  }
  // 访问IP 留空时自动填入解析到的地址，避免输入框空白
  function fillAccessIPIfEmpty() {
    if (!(wh.access_ip || '').trim() && (publicIP || localIP)) {
      wh.access_ip = publicIP || localIP;
    }
  }
  // 路径访问 IP 同理：留空时填入解析到的地址
  function fillWebAccessIPIfEmpty() {
    if (!(webAccess.ip || '').trim() && (publicIP || localIP)) {
      webAccess.ip = publicIP || localIP;
    }
  }
  // 是否存在 Webhook 通道：存在通道时接收必须保持开启，开关禁用
  let whChannelCount = 0;
  $: whHasChannels = whChannelCount > 0;
  async function loadWhChannelCount() {
    try {
      const d = await api('/api/wh/records');
      whChannelCount = (d && d.records || []).length;
    } catch (e) { /* ignore */ }
  }
  // 用户尝试切换开关：存在通道时后端会拒绝关闭并保持开启
  async function onWhEnabledChange() {
    if (!wh.enabled && whHasChannels) {
      toast(i18nTr("存在通道时必须保持开启，已自动恢复为开启"), 'error');
      wh.enabled = true;
    }
  }
  // 系统地址预览：domain 模式用访问域名；IP 模式优先用填写的访问IP，其次解析到的公网地址，最后回退本机局域网 IP
  $: sysBase = wh.addr_mode === 'domain'
    ? (wh.access_domain || '').trim()
    : ((wh.access_ip || '').trim() || publicIP || localIP || (typeof window !== 'undefined' ? window.location.hostname : ''));
  // 端口后缀：接收与访问共用同一 Webhook 端口；域名模式不加端口（域名经 frpc 代理映射到本机端口，
  // 域名本身不带端口、通常走 443），0/80/443 省略显示
  $: whReceivePortSuffix = wh.addr_mode !== 'domain' && wh.receive_port > 0 && wh.receive_port !== 80 && wh.receive_port !== 443 ? (':' + wh.receive_port) : '';
  // 协议前缀：域名模式经 frpc 域名代理（http/https 型代理）访问，默认按 https 展示；IP 模式跟随当前访问协议
  $: whScheme = wh.addr_mode === 'domain'
    ? 'https'
    : (typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'https' : 'http');
  $: receivePreview = sysBase ? whScheme + '://' + sysBase + whReceivePortSuffix + '/api/channel/update' : '—';
  $: accessPreview = sysBase ? whScheme + '://' + sysBase + whReceivePortSuffix + i18nTr("/{通道id}") : '—';
  // 导航页访问地址预览（/hook 与通道访问同源）
  $: hookPreview = sysBase ? whScheme + '://' + sysBase + whReceivePortSuffix + '/hook' : '—';
  // Web 服务路径基础地址预览（跟随「访问方式」设置）
  $: webPathPreview = (() => {
    if (webAccess.mode === 'domain') {
      const d = (webAccess.domain || '').trim();
      return d ? 'https://' + d + i18nTr("/<路径前缀>") : '—';
    }
    let ip = (webAccess.ip || '').trim() || publicIP || localIP;
    if (!ip) return '—';
    if (ip.includes(':')) ip = '[' + ip + ']';
    return 'http://' + ip + ':' + fwd.http_default_port + i18nTr("/<路径前缀>");
  })();
  // Webhook 模板（请求方法/请求头/请求体/成功字符）；请求头以数组编辑，保存时转对象
  let whTmpl = { method: 'POST', headers: [], body: '', success_string: '' };
  // 默认请求体模板：channel_id=通道id / host=公网IP或域名 / password=链接密钥 / port=公网端口（变量由客户端按实际值替换）
  const DEFAULT_WH_BODY = `{
  "channel_id": "{channel_id}",
  "host": "{ip}",
  "password": "{link_key}",
  "port": {port}
}`;

  // IP 归属地
  let geo = null;
  let geoSources = [];
  let geoUpdating = false;
  let geoLookupResult = '';
  let geoAutoHours = 24;
  let geoTimer = null;

  // IP 过滤（黑名单 / 白名单 / 拦截记录）
  let ipfEnabled = true;
  let ipfMode = 'blacklist'; // 过滤模式：blacklist 黑名单 / whitelist 白名单
  let ipfAllowLAN = true;    // 局域网地址放行（默认开）
  let lanConfirm = false;    // 关闭局域网放行前的确认弹窗
  let ipfAutoRecord = false;
  let whitelistRegions = []; // 白名单地区规则（按 IP 归属地匹配）
  let blacklistRegions = []; // 黑名单地区规则（按 IP 归属地匹配）
  let blackIPs = [];
  let whiteIPs = [];
  let blockedIPs = [];
  let blackInput = '';
  let whiteInput = '';
  let editBlackIdx = -1;
  let editBlackVal = '';
  let editWhiteIdx = -1;
  let editWhiteVal = '';
  // 从 IP 地址库按地区批量添加白/黑名单
  let regionPick = null;     // { list: 'blacklist' | 'whitelist' }
  let geoRegions = [];
  let geoRegionsError = '';
  let regionBusy = false;
  let regionSearch = '';
  // 名单条目删除确认：{ kind: 'region'|'black'|'white', list?, reg?, ip? }
  let delIPFTarget = null;
  let delIPFBusy = false;
  let showClearBlocked = false; // 清空拦截记录确认弹窗
  let clearBlockedBusy = false;

  // 数据源管理弹窗
  let showGeoModal = false;

  // 备份 / 恢复
  let backupFile = null;
  let backupFileInput = null;
  let showBackupExport = null;  // { full: true|false } 导出弹窗
  let showBackupRestore = false; // 恢复预览弹窗

  function onBackupFilePick(e) {
    backupFile = e.target.files[0] || null;
  }
  function clearBackupFile() {
    backupFile = null;
    if (backupFileInput) backupFileInput.value = '';
  }

  // 备份导出按钮图标（云备份）
  const backupIcon = '<svg width="16" height="16" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M44 31C44 36.5228 39.5228 41 34 41C32.2091 41 30.5281 40.5292 29.0741 39.7046C26.5143 38.2529 24.6579 35.7046 24.1436 32.6983C24.0492 32.1463 24 31.5789 24 31C24 28.4323 24.9678 26.0906 26.5585 24.3198C28.3892 22.2818 31.0449 21 34 21C39.5228 21 44 25.4772 44 31Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M34 12V20V21C31.0449 21 28.3892 22.2818 26.5585 24.3198C24.9678 26.0906 24 28.4323 24 31C24 31.5789 24.0492 32.1463 24.1436 32.6983C24.6579 35.7046 26.5143 38.2529 29.0741 39.7046C26.4116 40.5096 22.8776 41 19 41C10.7157 41 4 38.7614 4 36V28V20V12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M34 12C34 14.7614 27.2843 17 19 17C10.7157 17 4 14.7614 4 12C4 9.23858 10.7157 7 19 7C27.2843 7 34 9.23858 34 12Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 28C4 30.7614 10.7157 33 19 33C20.807 33 22.5393 32.8935 24.1436 32.6983" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 20C4 22.7614 10.7157 25 19 25C21.7563 25 24.339 24.7522 26.5585 24.3198" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M34 26V36M34 36L38 32M34 36L30 32" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  // 备份恢复按钮图标（云恢复/下载）
  const restoreIcon = '<svg width="16" height="16" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M44 31C44 36.5228 39.5228 41 34 41C32.2091 41 30.5281 40.5292 29.0741 39.7046C26.5143 38.2529 24.6579 35.7046 24.1436 32.6983C24.0492 32.1463 24 31.5789 24 31C24 28.4323 24.9678 26.0906 26.5585 24.3198C28.3892 22.2818 31.0449 21 34 21C39.5228 21 44 25.4772 44 31Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M34 12V20V21C31.0449 21 28.3892 22.2818 26.5585 24.3198C24.9678 26.0906 24 28.4323 24 31C24 31.5789 24.0492 32.1463 24.1436 32.6983C24.6579 35.7046 26.5143 38.2529 29.0741 39.7046C26.4116 40.5096 22.8776 41 19 41C10.7157 41 4 38.7614 4 36V28V20V12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M34 12C34 14.7614 27.2843 17 19 17C10.7157 17 4 14.7614 4 12C4 9.23858 10.7157 7 19 7C27.2843 7 34 9.23858 34 12Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 28C4 30.7614 10.7157 33 19 33C20.807 33 22.5393 32.8935 24.1436 32.6983" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 20C4 22.7614 10.7157 25 19 25C21.7563 25 24.339 24.7522 26.5585 24.3198" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M39 31L35 27M39 31L35 35M39 31L29 31" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  // 导航页（/hook）设置：服务端持久化（默认开启）
  let hookCfg = {
    enabled: true, title: i18nTr("通道导航"), search_engine: 'bing', icon: '',
    show_search: true,
    show_webhook: true, show_forwards: true, show_proxies: true
  };
  let hookAdminPass = ''; // 导航页管理密码输入（不参与回显，保存时仅在非空时提交）

  let timer;

  // 表单校验容器与错误节点：横向 flex 行（.input-action-row）内的输入用 errAt 把错误渲染到行外
  let defaultFormEl;  // 默认参数分组
  let stunFormEl;     // STUN 设置分组
  let frpcFormEl;     // frpc 服务器配置分组
  let bindFormEl;     // 「绑定到域名」弹窗
  let blackAddEl;     // 黑名单添加区
  let whiteAddEl;     // 白名单添加区
  let geoQueryEl;     // IP 归属地查询区
  let accessDomainErr; // Webhook 访问域名错误
  let blackInputErr;   // 黑名单添加框错误
  let editBlackErr;    // 黑名单行内编辑错误
  let whiteInputErr;   // 白名单添加框错误
  let editWhiteErr;    // 白名单行内编辑错误
  let geoLookupErr;    // 归属地查询输入错误

  async function loadSettings() {
    try {
      const d = await api('/api/settings');
      if (!d) return;
      settings.set(d);
      const lc = d.log || {};
      if (lc.tunnel_max_entries != null) log.tunnel_max_entries = lc.tunnel_max_entries;
      if (lc.tunnel_access_max_entries != null) log.tunnel_access_max_entries = lc.tunnel_access_max_entries;
      if (lc.expire_days != null) log.expire_days = lc.expire_days;
      if (lc.traffic_retention_days != null) log.traffic_retention_days = lc.traffic_retention_days;
      const fc = d.forward || {};
      if (fc.http_default_port != null) fwd.http_default_port = fc.http_default_port;
      if (fc.https_default_port != null) fwd.https_default_port = fc.https_default_port;
      webAccess.mode = fc.web_access_mode === 'domain' ? 'domain' : 'ip';
      webAccess.domain = fc.web_access_domain || '';
      webAccess.ip = fc.web_access_ip || '';
      fillWebAccessIPIfEmpty();
      const wr = d.wh_receiver || {};
      if (wr.enabled != null) wh.enabled = wr.enabled === true;
      if (wr.addr_mode != null) wh.addr_mode = wr.addr_mode === 'domain' ? 'domain' : 'ip';
      if (wr.access_domain != null) wh.access_domain = wr.access_domain;
      if (wr.access_ip != null) wh.access_ip = wr.access_ip;
      if (wr.receive_port != null) wh.receive_port = wr.receive_port;
      // 访问IP 留空时自动填入解析到的地址（IP 可能尚未加载完，加载完成后 loadLocalIP 会再补一次）
      fillAccessIPIfEmpty();
      const wt = d.wh_template || {};
      if (wt.method != null) whTmpl.method = wt.method || 'POST';
      // 请求体：配置为空时自动填充默认模板，确保编辑区有可直接使用的内容
      whTmpl.body = (wt.body || '').trim() ? wt.body : DEFAULT_WH_BODY;
      if (wt.success_string != null) whTmpl.success_string = wt.success_string || '';
      // 请求头对象 → 可编辑数组（保留原顺序）
      const hdrs = wt.headers || {};
      whTmpl.headers = Object.keys(hdrs).map((k) => ({ key: k, value: hdrs[k] }));
      if (whTmpl.headers.length === 0) whTmpl.headers = [{ key: '', value: '' }];
      const ipf = d.ip_filter || {};
      ipfEnabled = ipf.enabled === true;
      ipfMode = ipf.mode === 'whitelist' ? 'whitelist' : 'blacklist';
      ipfAllowLAN = ipf.allow_lan !== false;
      ipfAutoRecord = !!ipf.auto_record;
      whitelistRegions = ipf.whitelist_regions || [];
      blacklistRegions = ipf.blacklist_regions || [];
      blackIPs = ipf.custom_ips || [];
      whiteIPs = ipf.whitelist_ips || [];
      blockedIPs = ipf.blocked_ips || [];
      const hk = d.hook || {};
      hookCfg.enabled = hk.enabled !== false;
      hookCfg.title = hk.title || i18nTr("通道导航");
      hookCfg.search_engine = hk.search_engine || 'bing';
      hookCfg.icon = hk.icon || '';
      hookCfg.show_search = hk.show_search !== false;
      hookCfg.show_webhook = hk.show_webhook !== false;
      hookCfg.show_forwards = hk.show_forwards !== false;
      hookCfg.show_proxies = hk.show_proxies !== false;
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  onMount(() => {
    loadSettings();
    loadLocalIP();
    loadWhChannelCount();
    timer = pollVisible(() => {
      if ($settingsSect === 'ipfilter') loadGeoStats();
    }, 5000);
  });
  onDestroy(() => {
    if (timer) timer();
    if (geoTimer) clearInterval(geoTimer);
    if (frpcTimer) frpcTimer();
    if (frpcLatestTimer) clearInterval(frpcLatestTimer);
  });

  // ---- frpc 客户端 ----
  let frpcStatus = { installed: false, version: '', running: false, bundle_available: false };
  let frpcCfg = { servers: [{ name: i18nTr("默认服务器"), addr: '', port: 7000, token: '' }], active_server: i18nTr("默认服务器"), log_level: 'info', proxies: [] };
  let frpcLog = '';
  let frpcBusy = false;
  let showFrpcUpgrade = false;
  let showAddServer = false;
  let addServerBusy = false;
  let delServerName = '';
  let editSrvName = '';    // 待重命名的服务器名称
  let editSrvBusy = false;
  let frpcSaving = false;  // 保存配置中
  let frpcTimer = null;
  let frpcLatest = '';
  let frpcLatestTimer = null;
  // 各服务器连接延时：{ [名称]: {online, latency_ms, addr, error} }
  // 启动/重启后主动测一次并常驻展示，让「启动成功」与「真的连上了」可见地区分开。
  let frpcLat = {};
  let frpcLatBusy = {};

  // 默认（激活）服务器在列表中的索引
  $: activeSrvIdx = Math.max(0, frpcCfg.servers.findIndex((s) => s.name === frpcCfg.active_server));
  // 当前表单显示的服务器索引（点击胶囊切换查看，与默认服务器解耦）
  let viewSrvIdx = 0;
  $: activeSrv = frpcCfg.servers[viewSrvIdx] || { name: '', addr: '', port: 7000, token: '' };

  // 服务器实例上限
  const MAX_SERVERS = 6;

  // 胶囊按钮：切换显示的服务器配置（不改变默认服务器）
  function showServer(i) {
    viewSrvIdx = i;
  }
  // 「修改服务器名称」弹窗内：将当前编辑的服务器设为唯一默认服务器
  async function editSrvSetDefault() {
    const name = editSrvName;
    if (!name || name === frpcCfg.active_server) return;
    frpcCfg.active_server = name;
    await frpcSwitchServer();
  }

  async function loadFrpcStatus() {
    try {
      const d = await api('/api/frpc/status');
      if (d) frpcStatus = d;
    } catch (e) { /* ignore */ }
  }
  async function loadFrpcConfig() {
    try {
      const d = await api('/api/frpc/config');
      if (d) {
        frpcCfg = d;
        // 数据刷新后回到默认服务器视图
        viewSrvIdx = Math.max(0, d.servers.findIndex((s) => s.name === d.active_server));
      }
    } catch (e) { /* ignore */ }
  }
  async function loadFrpcLog() {
    try {
      const d = await api('/api/frpc/log?lines=300');
      if (d) frpcLog = reverseLines(d.log || '');
    } catch (e) { /* ignore */ }
  }
  function pollFrpc() {
    loadFrpcStatus();
    loadFrpcLog();
  }
  // 拉取 GitHub 最新内核版本（进入页面时立即执行，之后每小时自动刷新）
  async function frpcFetchLatest() {
    try {
      const d = await api('/api/frpc/upgrade/check', { method: 'POST' });
      if (d && d.latest) frpcLatest = d.latest;
    } catch (e) { /* 网络不可用时保留上次结果 */ }
  }
  // 进入 FPRC 页时加载数据并轮询；离开时停止轮询
  $: {
    if ($settingsSect === 'frpc') {
      loadFrpcStatus();
      loadFrpcConfig();
      loadFrpcLog();
      if (!frpcTimer) frpcTimer = pollVisible(pollFrpc, 5000);
      if (!frpcLatestTimer) {
        frpcFetchLatest();
        frpcLatestTimer = setInterval(frpcFetchLatest, 3600000); // 每小时更新一次
      }
    } else if (frpcTimer) {
      frpcTimer();
      frpcTimer = null;
      clearInterval(frpcLatestTimer);
      frpcLatestTimer = null;
    }
  }

  // 测量某台服务器的连通性与延时；结果按服务器名缓存，供实例行渲染。
  // 失败时把后端返回的 error 原样带出（connection write timeout / 认证失败等），不吞掉原因。
  async function measureLatency(name) {
    if (!name) return null;
    frpcLatBusy = { ...frpcLatBusy, [name]: true };
    try {
      const d = await api(`/api/frpc/server/latency?name=${encodeURIComponent(name)}`);
      if (d) frpcLat = { ...frpcLat, [d.name || name]: d };
      return d;
    } catch (e) {
      frpcLat = { ...frpcLat, [name]: { online: false, latency_ms: 0, error: e.message } };
      return null;
    } finally {
      const b = { ...frpcLatBusy };
      delete b[name];
      frpcLatBusy = b;
    }
  }

  // 启动/重启后测量目标服务器的延时。
  // server 为空表示「全部」：逐台测量，让每个实例行都拿到自己的延时与失败原因，
  // 而不是只测激活服务器、把其它实例的错误藏起来。
  async function measureTargets(server) {
    if (server) return [await measureLatency(server)];
    const names = (frpcStatus.servers || []).filter((x) => x.configured).map((x) => x.name);
    return Promise.all(names.map(measureLatency));
  }

  // server 可选：指定启动单台服务器（缺省=全部已配置地址的服务器）
  async function frpcStart(server) {
    frpcBusy = true;
    try {
      await api('/api/frpc/start', { method: 'POST', body: server ? { server } : {} });
      // 启动成功≠登录成功：等 frpc 首次登录完成（最多 ~6s）再测，测出的才是真实延时
      await waitFrpcLogin(server);
      const ds = await measureTargets(server);
      reportConnectResult(i18nTr("启动"), server, ds);
      await loadFrpcStatus();
    } catch (e) {
      toast(e.message, 'error');
    }
    frpcBusy = false;
  }
  // 汇总启停结果为一条提示：全部成功报延时，有失败则把原因原样带出。
  // 只在确实测到结果时才提示延时/失败（未测到就退回原来的「已启动」文案）。
  function reportConnectResult(action, server, ds) {
    const list = (ds || []).filter(Boolean);
    if (!list.length) {
      toast(server ? i18nTr("frpc「{0}」已{1}", [server, action]) : i18nTr("frpc 已全部{0}", [action]), 'success');
      return;
    }
    const bad = list.filter((d) => !d.online);
    if (!bad.length) {
      const detail = list.map((d) => `${d.addr || i18nTr("frp 服务器")} ${d.latency_ms} ms`).join('，');
      toast(i18nTr("{0} 已{1}，连接延时 {2}", [server || 'frpc', action, detail]), 'success');
      return;
    }
    const reason = bad.length === 1 ? frpcErrorTextFor(bad[0].name || server) : i18nTr("{0} 台连接失败", [bad.length]);
    toast(i18nTr("{0} 进程已{1}，但连接失败：{2}", [server || 'frpc', action, reason]), 'error');
  }
  // 轮询等待 frpc 登录成功（管理 API 的 /api/status 出现代理即视为已连上）；超时返回 false
  async function waitFrpcLogin(server, tries = 6, gap = 1000) {
    for (let i = 0; i < tries; i++) {
      try {
        const d = await api('/api/frpc/conns');
        if (d && d.states && Object.keys(d.states).length > 0) return true;
      } catch (e) { /* 忽略，下轮重试 */ }
      await new Promise((r) => setTimeout(r, gap));
    }
    return false;
  }
  // 实例行的失败原因：优先延时探测的 error，其次后端状态里带的 last_error（frpc 日志解析）
  function frpcErrorTextFor(server) {
    const lat = server ? frpcLat[server] : null;
    const st = server ? (frpcStatus.servers || []).find((x) => x.name === server) : null;
    return (lat && lat.error) || (st && st.last_error) || i18nTr("无法连接 frp 服务器");
  }
  async function frpcStop(server) {
    frpcBusy = true;
    try {
      await api('/api/frpc/stop', { method: 'POST', body: server ? { server } : {} });
      // 停止后延时不再有意义，清理避免残留旧值误导
      if (server) {
        const l = { ...frpcLat };
        delete l[server];
        frpcLat = l;
      }
      toast(server ? i18nTr("frpc「{0}」已停止", [server]) : i18nTr("frpc 已全部停止"), 'success');
      await loadFrpcStatus();
    } catch (e) {
      toast(e.message, 'error');
    }
    frpcBusy = false;
  }
  async function frpcRestart(server) {
    frpcBusy = true;
    try {
      await api('/api/frpc/restart', { method: 'POST', body: server ? { server } : {} });
      await waitFrpcLogin(server);
      const ds = await measureTargets(server);
      reportConnectResult(i18nTr("重启"), server, ds);
      await loadFrpcStatus();
    } catch (e) {
      toast(e.message, 'error');
    }
    frpcBusy = false;
  }
  // 启动/停止/重启 操作确认弹窗（frpcConfirm: '' 关闭 | 'start' | 'stop' | 'restart'，作用于全部服务器）
  let frpcConfirm = '';
  function frpcConfirmAction() {
    const op = frpcConfirm;
    frpcConfirm = '';
    if (op === 'start') frpcStart();
    else if (op === 'stop') frpcStop();
    else if (op === 'restart') frpcRestart();
  }
  // 设置单台服务器的开机自启标志（默认服务器由后端强制开启）
  async function setServerAutoStart(name, val) {
    try {
      await api('/api/frpc/server/autostart', { method: 'POST', body: { name, enabled: val } });
      toast(val ? i18nTr("「{0}」已开启开机自启", [name]) : i18nTr("「{0}」已关闭开机自启", [name]), 'success');
      await loadFrpcStatus();
    } catch (e) {
      toast(e.message, 'error');
      await loadFrpcStatus();
    }
  }
  // 配置文件查看/编辑弹窗（直接读写对应服务器的 frpc.toml 原始内容）
  let showFrpcCfgFile = false;
  let frpcCfgFile = '';
  let frpcCfgFileName = '';      // 当前查看的服务器名
  let frpcCfgFileIsActive = false; // 该服务器是否为默认服务器
  let frpcCfgFileLoading = false;
  let frpcCfgFileSaving = false;

  async function openFrpcConfigFile() {
    // 始终跟随当前选中（胶囊切换）的服务器显示其配置
    const name = (frpcCfg.servers[viewSrvIdx] || {}).name || '';
    showFrpcCfgFile = true;
    frpcCfgFileLoading = true;
    frpcCfgFileName = name;
    try {
      const d = await api('/api/frpc/configfile?name=' + encodeURIComponent(name));
      frpcCfgFile = (d && d.content) || '';
      frpcCfgFileIsActive = !!(d && d.is_active);
    } catch (e) {
      toast(e.message, 'error');
      showFrpcCfgFile = false;
    }
    frpcCfgFileLoading = false;
  }

  async function saveFrpcConfigFile() {
    frpcCfgFileSaving = true;
    try {
      await api('/api/frpc/configfile', { method: 'POST', body: { content: frpcCfgFile, name: frpcCfgFileName } });
      toast(frpcCfgFileIsActive ? i18nTr("配置文件已保存并应用") : i18nTr("配置已保存到服务器「") + frpcCfgFileName + i18nTr("」，设为默认后生效"), 'success');
      await loadFrpcStatus();
    } catch (e) {
      toast(e.message, 'error');
    }
    frpcCfgFileSaving = false;
  }
  async function frpcSave() {
    if (frpcSaving) return;
    // 格式校验：服务器地址/端口/STUN 服务器统一拦截并就地提示
    if (!validateAll(frpcFormEl)) return;
    frpcSaving = true;
    try {
      await api('/api/frpc/config', { method: 'POST', body: frpcCfg });
      toast(i18nTr("frpc 配置已保存"), 'success');
      await loadFrpcStatus();
    } catch (e) {
      toast(e.message, 'error');
    }
    frpcSaving = false;
  }
  // 切换激活（默认）服务器（按名称，即时生效，无需刷新页面）
  async function frpcSwitchServer() {
    const name = frpcCfg.active_server;
    if (!name) return;
    try {
      await api('/api/frpc/server/switch', { method: 'POST', body: { name } });
      toast(i18nTr("已将「") + name + i18nTr("」设为默认服务器"), 'success');
      await loadFrpcConfig();
      await loadFrpcStatus();
    } catch (e) {
      toast(e.message, 'error');
      await loadFrpcConfig();
    }
  }
  // 添加服务器：新增唯一命名的实例并自动切换
  async function frpcAddServer(data) {
    addServerBusy = true;
    try {
      await api('/api/frpc/server/add', { method: 'POST', body: data });
      toast(i18nTr("服务器「") + data.name + i18nTr("」已添加并切换"), 'success');
      showAddServer = false;
      await loadFrpcConfig();
      await loadFrpcStatus();
    } catch (e) {
      toast(e.message, 'error');
    }
    addServerBusy = false;
  }
  // ---- 添加域名：把当前服务器地址解析到指定 DNS 域名 ----
  let showBindDns = false;
  let bindBusy = false;
  let bindAccounts = [];
  let bindAccount = '';
  let bindDomains = [];
  let bindDomain = '';
  let bindRR = '@';
  let bindTypeOptions = ['A', 'AAAA', 'CNAME'].map((t) => ({ value: t, label: t }));
  let bindType = 'A';
  let bindValue = '';
  let bindTTL = 600;

  // 依据服务器地址推测记录类型：IP 用 A/AAAA，域名用 CNAME
  function peekRecordType(v) {
    const s = (v || '').trim();
    if (/^([0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:]+$/.test(s)) return 'AAAA';
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return 'A';
    return 'CNAME';
  }
  // 打开「添加域名」弹窗：加载 DNS 账号并预填当前服务器地址
  async function openBindDns() {
    showBindDns = true;
    bindBusy = false;
    bindValue = (activeSrv.addr || '').trim();
    bindRR = '@';
    bindType = peekRecordType(bindValue);
    bindDomain = '';
    try {
      const d = await api('/api/dns/list');
      bindAccounts = d || [];
      bindAccount = bindAccounts.length ? bindAccounts[0].name : '';
      await loadBindDomains();
    } catch (e) {
      toast(e.message, 'error');
    }
  }
  // 加载所选 DNS 账号下的域名
  async function loadBindDomains() {
    if (!bindAccount) { bindDomains = []; bindDomain = ''; return; }
    try {
      const d = await api('/api/dns/domains?account=' + encodeURIComponent(bindAccount));
      bindDomains = d || [];
      bindDomain = bindDomains.length ? bindDomains[0].name : '';
    } catch (e) { /* ignore */ }
  }
  // 提交：添加解析记录，把服务器地址指向所选域名
  async function submitBindDns() {
    // 格式校验：主机记录名与记录值（IP/域名）就地提示
    if (!validateAll(bindFormEl)) return;
    if (!bindAccount || !bindDomain) { toast(i18nTr("请选择 DNS 账号与域名"), 'error'); return; }
    if (!(bindRR || '').trim()) { toast(i18nTr("请填写主机记录"), 'error'); return; }
    if (!(bindValue || '').trim()) { toast(i18nTr("请填写记录值（服务器地址）"), 'error'); return; }
    bindBusy = true;
    try {
      await api('/api/dns/record/add', { method: 'POST', body: {
        account: bindAccount, domain: bindDomain, rr: bindRR.trim(),
        type: bindType, value: bindValue.trim(), ttl: Number(bindTTL) || 600
      } });
      toast(i18nTr("已将 {0}{1}{2} 解析到 {3}", [bindRR.trim(), bindRR.trim() === '@' ? '' : '.', bindDomain, bindValue.trim()]), 'success');
      showBindDns = false;
    } catch (e) {
      toast(e.message, 'error');
    }
    bindBusy = false;
  }
  // 删除服务器
  async function frpcDelServer() {
    const name = delServerName;
    if (!name) return;
    try {
      await api('/api/frpc/server/delete', { method: 'POST', body: { name } });
      toast(i18nTr("服务器「") + name + i18nTr("」已删除"), 'success');
      delServerName = '';
      await loadFrpcConfig();
      await loadFrpcStatus();
    } catch (e) {
      toast(e.message, 'error');
      delServerName = '';
    }
  }

  // 修改服务器名称（双击 / 右键胶囊触发）
  async function frpcRenameServer(newName) {
    if (!editSrvName || !newName) return;
    editSrvBusy = true;
    try {
      await api('/api/frpc/server/rename', { method: 'POST', body: { name: editSrvName, new_name: newName } });
      toast(i18nTr("服务器「") + editSrvName + i18nTr("」已更名为「") + newName + '」', 'success');
      editSrvName = '';
      await loadFrpcConfig();
      await loadFrpcStatus();
    } catch (e) {
      toast(e.message, 'error');
    }
    editSrvBusy = false;
  }

  // ---- Webhook 模板：请求头键值对编辑 ----
  function addHeaderRow() {
    whTmpl.headers = [...whTmpl.headers, { key: '', value: '' }];
  }
  function delHeaderRow(i) {
    whTmpl.headers = whTmpl.headers.filter((_, idx) => idx !== i);
    if (whTmpl.headers.length === 0) whTmpl.headers = [{ key: '', value: '' }];
  }

  // ---- 访问域名（域名模式）创建 frpc 代理：使 Webhook 接收与通道访问可通过该域名使用 ----
  const reDomain = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;
  let domainProxyBusy = false;
  async function createDomainProxy() {
    const d = (wh.access_domain || '').trim().toLowerCase();
    if (!d) {
      toast(i18nTr("请先填写访问域名"), 'error');
      return;
    }
    if (!reDomain.test(d)) {
      toast(i18nTr("域名格式无效，例如 wh.example.com"), 'error');
      return;
    }
    domainProxyBusy = true;
    try {
      const res = await api('/api/wh/system/proxy', { method: 'POST', body: { domain: d } });
      toast(i18nTr("域名代理已创建：") + d + (res && res.proxy_name ? '（' + res.proxy_name + '）' : ''), 'success');
      wh.access_domain = d;
    } catch (e) {
      toast(e.message, 'error');
    }
    domainProxyBusy = false;
  }

  // ---- Webhook 模板：请求体 JSON 语法高亮（textarea 覆盖层实现） ----
  // 必须转义双引号：正则用 &quot; 匹配 JSON 字符串，缺此转义则键名/字符串无法高亮
  function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function highlightJson(code) {
    const esc = escapeHtml(code || '');
    return esc.replace(
      /(&quot;(?:[^&]|&(?!quot;))*?&quot;)(?=\s*:)|(&quot;(?:[^&]|&(?!quot;))*?&quot;)|(\b(?:true|false|null)\b)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}\[\],:])/g,
      (m, key, str, kw, num, punc) => {
        if (key) return '<span class="jv-k">' + key + '</span>';
        if (str) return '<span class="jv-s">' + str + '</span>';
        if (kw) return '<span class="jv-b">' + kw + '</span>';
        if (num) return '<span class="jv-n">' + num + '</span>';
        if (punc) return '<span class="jv-p">' + punc + '</span>';
        return m;
      }
    );
  }
  // 编辑区滚动时同步高亮层
  function onCodeScroll(e) {
    const pre = e.currentTarget.parentElement && e.currentTarget.parentElement.querySelector('.code-hl');
    if (pre) {
      pre.scrollTop = e.currentTarget.scrollTop;
      pre.scrollLeft = e.currentTarget.scrollLeft;
    }
  }

  // ---- 保存默认参数 ----
  async function saveSettings() {
    // 从「默认参数」分组保存时校验地址/端口/域名；日志分组无此类字段（defaultFormEl 未挂载）则跳过
    if (defaultFormEl && !validateAll(defaultFormEl)) return;
    // 请求头数组 → 对象（去空行）
    const headers = {};
    for (const h of whTmpl.headers) {
      const k = (h.key || '').trim();
      if (k) headers[k] = h.value || '';
    }
    try {
      const d = await api('/api/settings', {
        method: 'POST',
        body: {
          forward: {
            ...fwd,
            web_access_mode: webAccess.mode,
            web_access_ip: (webAccess.ip || '').trim(),
            web_access_domain: (webAccess.domain || '').trim()
          },
          log: log,
          wh_receiver: wh,
          wh_template: {
            method: whTmpl.method,
            headers,
            body: whTmpl.body,
            success_string: whTmpl.success_string
          }
        }
      });
      if (d && d.close_disabled) {
        toast(i18nTr("存在通道时 Webhook 接收必须保持开启，已忽略关闭操作"), 'error');
        wh.enabled = true;
      } else {
        toast(i18nTr("设置已保存"));
      }
      loadSettings();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  // ---- IP 归属地 ----
  async function loadGeoStats() {
    try {
      const d = await api('/api/geoloc/stats');
      if (d) {
        geo = d;
        geoAutoHours = d.auto_update_hours != null ? d.auto_update_hours : 24;
      }
    } catch (e) { /* ignore */ }
  }
  onMount(() => { loadGeoStats(); });
  // 进入 IP 地址库分区时读取数据源列表
  $: if ($settingsSect === 'ipfilter') loadGeoSources();
  async function loadGeoSources() {
    try {
      const d = await api('/api/geoloc/sources');
      geoSources = (d && d.sources) || [];
    } catch (e) { /* ignore */ }
  }
  async function geoLookup() {
    // 格式校验：查询框内必须为合法 IP
    if (!validateAll(geoQueryEl)) return;
    const ip = document.getElementById('geoLookupInput').value;
    try {
      const d = await api('/api/geoloc/lookup?ip=' + encodeURIComponent(ip));
      geoLookupResult = d && d.ready ? (d.location || i18nTr("未收录该 IP")) : i18nTr("IP 地址库未就绪，请先更新数据");
    } catch (e) {
      geoLookupResult = e.message;
    }
  }
  async function geoSaveAutoUpdate() {
    try {
      await api('/api/geoloc/autoupdate', { method: 'POST', body: { hours: geoAutoHours } });
      toast(i18nTr("自动更新间隔已保存"), 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
  }
  // ---- IP 过滤（黑名单 / 白名单 / 拦截记录） ----
  async function loadIPRules() {
    try {
      const d = await api('/api/settings');
      if (!d) return;
      const ipf = d.ip_filter || {};
      ipfEnabled = ipf.enabled === true;
      ipfMode = ipf.mode === 'whitelist' ? 'whitelist' : 'blacklist';
      ipfAllowLAN = ipf.allow_lan !== false;
      ipfAutoRecord = !!ipf.auto_record;
      whitelistRegions = ipf.whitelist_regions || [];
      blacklistRegions = ipf.blacklist_regions || [];
      blackIPs = ipf.custom_ips || [];
      whiteIPs = ipf.whitelist_ips || [];
      blockedIPs = ipf.blocked_ips || [];
    } catch (e) { /* ignore */ }
  }
  // 进入「IP 过滤」页时刷新规则与拦截记录
  $: if ($settingsSect === 'ipdb') loadIPRules();

  // ---- 模块管理：关闭指定模块的入口（即时生效；已运行的服务不受影响）----
  let modSaving = false;
  $: if ($settingsSect === 'modules') loadModules();
  $: enabledModuleCount = MODULES.filter((m) => !$disabledModules.includes(m.id)).length;

  // 全部启用：清空已关闭列表
  async function enableAllModules() {
    if (modSaving) return;
    modSaving = true;
    try {
      const d = await api('/api/modules', { method: 'POST', body: { disabled: [] } });
      disabledModules.set((d && d.disabled) || []);
      toast(i18nTr("已启用全部模块"), 'success');
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      modSaving = false;
    }
  }

  async function loadModules() {
    try {
      const d = await api('/api/modules');
      disabledModules.set((d && d.disabled) || []);
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  // enabled 为 true 表示启用该模块（即从已关闭列表中移除）
  async function toggleModule(id, enabled) {
    const next = enabled
      ? $disabledModules.filter((x) => x !== id)
      : [...$disabledModules, id];
    modSaving = true;
    try {
      const d = await api('/api/modules', { method: 'POST', body: { disabled: next } });
      disabledModules.set((d && d.disabled) || next);
      toast(enabled ? i18nTr("模块已启用") : i18nTr("模块已关闭"));
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      modSaving = false;
    }
  }

  async function setIPFilterEnabled() {
    try {
      await api('/api/ipfilter/enabled', { method: 'POST', body: { enabled: ipfEnabled } });
      toast(ipfEnabled ? i18nTr("拦截功能已开启") : i18nTr("拦截功能已关闭"), 'success');
    } catch (e) {
      toast(e.message, 'error');
      ipfEnabled = !ipfEnabled;
    }
  }

  async function setIPFilterMode() {
    try {
      await api('/api/ipfilter/mode', { method: 'POST', body: { mode: ipfMode } });
      toast(ipfMode === 'whitelist' ? i18nTr("已切换为白名单模式（仅放行白名单与内网地址）") : i18nTr("已切换为黑名单模式（拦截名单内地址）"), 'success');
    } catch (e) {
      toast(e.message, 'error');
      ipfMode = ipfMode === 'whitelist' ? 'blacklist' : 'whitelist';
    }
  }

  // 局域网放行：关闭前弹出风险提示（关闭后局域网设备将无法访问）
  function onAllowLANChange() {
    if (!ipfAllowLAN) {
      lanConfirm = true;
    } else {
      saveAllowLAN(true);
    }
  }
  function confirmDisableLAN() {
    lanConfirm = false;
    saveAllowLAN(false);
  }
  function cancelDisableLAN() {
    lanConfirm = false;
    ipfAllowLAN = true;
  }
  async function saveAllowLAN(v) {
    try {
      await api('/api/ipfilter/allowlan', { method: 'POST', body: { enabled: v } });
      toast(v ? i18nTr("已开启局域网地址放行") : i18nTr("已关闭局域网地址放行"), 'success');
    } catch (e) {
      toast(e.message, 'error');
      ipfAllowLAN = !v;
    }
  }

  // ---- 从 IP 地址库按地区批量添加白/黑名单 ----
  function regionFiltered() {
    const q = regionSearch.trim().toLowerCase();
    if (!q) return geoRegions;
    return geoRegions.filter((g) => (g.name || '').toLowerCase().includes(q) || (g.label || '').toLowerCase().includes(q));
  }
  function regionIPs(ips) {
    if (ips >= 10000) return (ips / 10000).toFixed(1) + i18nTr("万");
    return String(ips);
  }
  async function openRegionPick(list) {
    regionPick = { list };
    regionSearch = '';
    geoRegionsError = '';
    regionBusy = true;
    try {
      const d = await api('/api/geoloc/regions');
      geoRegions = (d && d.regions) || [];
    } catch (e) {
      geoRegionsError = e.message;
    }
    regionBusy = false;
  }
  async function addRegion(reg) {
    regionBusy = true;
    try {
      await api('/api/ipfilter/region', { method: 'POST', body: { list: regionPick.list, category: reg.category, name: reg.name } });
      toast(i18nTr("已将「{0}」加入{1}", [reg.name, regionPick.list === 'blacklist' ? '黑名单' : '白名单']), 'success');
      regionPick = null;
      loadIPRules();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      regionBusy = false;
    }
  }
  function delRegion(list, reg) {
    delIPFTarget = { kind: 'region', list, reg };
  }

  async function confirmDelIPF() {
    if (!delIPFTarget) return;
    delIPFBusy = true;
    try {
      const t = delIPFTarget;
      if (t.kind === 'region') {
        await api('/api/ipfilter/region?list=' + encodeURIComponent(t.list) + '&category=' + encodeURIComponent(t.reg.category) + '&name=' + encodeURIComponent(t.reg.name), { method: 'DELETE' });
        toast(i18nTr("已从{0}移除「{1}」", [t.list === 'blacklist' ? '黑名单' : '白名单', t.reg.name]), 'success');
      } else if (t.kind === 'black') {
        await api('/api/ipfilter/custom?ip=' + encodeURIComponent(t.ip), { method: 'DELETE' });
        toast(i18nTr("已移出黑名单: ") + t.ip, 'success');
      } else {
        await api('/api/ipfilter/whitelist?ip=' + encodeURIComponent(t.ip), { method: 'DELETE' });
        toast(i18nTr("已移出白名单: ") + t.ip, 'success');
      }
      delIPFTarget = null;
      loadIPRules();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      delIPFBusy = false;
    }
  }

  async function setAutoRecord() {
    try {
      await api('/api/ipfilter/autorecord', { method: 'POST', body: { enabled: ipfAutoRecord } });
      toast(ipfAutoRecord ? i18nTr("自动记录已开启") : i18nTr("自动记录已关闭"), 'success');
    } catch (e) {
      toast(e.message, 'error');
      ipfAutoRecord = !ipfAutoRecord;
    }
  }

  async function addBlack() {
    // 格式校验：IP 或 CIDR 网段，错误显示在添加行下方
    if (!validateAll(blackAddEl)) return;
    const ip = blackInput.trim();
    if (!ip) return;
    try {
      await api('/api/ipfilter/custom', { method: 'POST', body: { ip } });
      blackInput = '';
      toast(i18nTr("已加入黑名单: ") + ip, 'success');
      loadIPRules();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  function delBlack(ip) {
    delIPFTarget = { kind: 'black', ip };
  }

  async function saveEditBlack(ip) {
    const v = editBlackVal.trim();
    if (!v || v === ip) {
      editBlackIdx = -1;
      return;
    }
    // 格式校验：IP 或 CIDR 网段，错误显示在条目下方（与输入框 errAt 同一节点）
    const err = validateCIDR(v);
    if (err) {
      editBlackErr.textContent = err;
      editBlackErr.style.display = '';
      return;
    }
    try {
      await api('/api/ipfilter/custom?ip=' + encodeURIComponent(ip), { method: 'DELETE' });
      await api('/api/ipfilter/custom', { method: 'POST', body: { ip: v } });
      editBlackIdx = -1;
      toast(i18nTr("黑名单已更新: ") + v, 'success');
      loadIPRules();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function addWhite() {
    // 格式校验：IP 或 CIDR 网段，错误显示在添加行下方
    if (!validateAll(whiteAddEl)) return;
    const ip = whiteInput.trim();
    if (!ip) return;
    try {
      await api('/api/ipfilter/whitelist', { method: 'POST', body: { ip } });
      whiteInput = '';
      toast(i18nTr("已加入白名单: ") + ip, 'success');
      loadIPRules();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  function delWhite(ip) {
    delIPFTarget = { kind: 'white', ip };
  }

  async function saveEditWhite(ip) {
    const v = editWhiteVal.trim();
    if (!v || v === ip) {
      editWhiteIdx = -1;
      return;
    }
    // 格式校验：IP 或 CIDR 网段，错误显示在条目下方（与输入框 errAt 同一节点）
    const err = validateCIDR(v);
    if (err) {
      editWhiteErr.textContent = err;
      editWhiteErr.style.display = '';
      return;
    }
    try {
      await api('/api/ipfilter/whitelist?ip=' + encodeURIComponent(ip), { method: 'DELETE' });
      await api('/api/ipfilter/whitelist', { method: 'POST', body: { ip: v } });
      editWhiteIdx = -1;
      toast(i18nTr("白名单已更新: ") + v, 'success');
      loadIPRules();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function addBlackFromRecord(ip) {
    try {
      await api('/api/ipfilter/custom', { method: 'POST', body: { ip } });
      await api('/api/ipfilter/blocked?ip=' + encodeURIComponent(ip), { method: 'DELETE' });
      toast(i18nTr("已加入黑名单: ") + ip, 'success');
      loadIPRules();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function delBlocked(ip) {
    try {
      await api('/api/ipfilter/blocked?ip=' + encodeURIComponent(ip), { method: 'DELETE' });
      loadIPRules();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  function clearBlocked() {
    showClearBlocked = true;
  }

  async function confirmClearBlocked() {
    clearBlockedBusy = true;
    try {
      await api('/api/ipfilter/blocked', { method: 'DELETE' });
      toast(i18nTr("拦截记录已清空"), 'success');
      showClearBlocked = false;
      loadIPRules();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      clearBlockedBusy = false;
    }
  }

  // ---- 系统UI：界面自定义 ----
  function setUI(patch) {
    uiCfg.update((v) => ({ ...v, ...patch }));
  }
  function resetUI() {
    uiCfg.set({ ...UI_DEFAULTS });
    toast(i18nTr("界面设置已恢复默认"), 'success');
  }
  // 导航页设置：服务端持久化，即时生效（关闭后 /hook 返回 404）
  async function saveHookSettings(msg) {
    try {
      const payload = { ...hookCfg };
      // 管理密码仅在输入框非空时提交（服务端不回传密码，避免回显）
      if ((hookAdminPass || '').trim()) payload.admin_pass = hookAdminPass.trim();
      await api('/api/settings', { method: 'POST', body: { hook: payload } });
      if (payload.admin_pass) hookAdminPass = ''; // 保存成功后清空输入框
      toast(msg || i18nTr("导航页设置已保存"), 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
  }
  // 上传背景图片：压缩到最大 1920px 宽并转 JPEG，避免超出 localStorage 配额
  function onBgFile(e) {
    const file = e.target.files && e.target.files[0];
    e.target.value = '';
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const img = new Image();
      img.onload = () => {
        const maxW = 1920;
        let w = img.width, h = img.height;
        if (w > maxW) { h = Math.round((h * maxW) / w); w = maxW; }
        const c = document.createElement('canvas');
        c.width = w; c.height = h;
        c.getContext('2d').drawImage(img, 0, 0, w, h);
        setUI({ bgImage: c.toDataURL('image/jpeg', 0.85), bgType: 'image' });
        toast(i18nTr("背景图片已应用"), 'success');
      };
      img.onerror = () => toast(i18nTr("图片加载失败，请更换文件"), 'error');
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  }

  // ===== STUN 设置（服务器列表 + 打洞保活间隔）=====
  let stunCfg = { servers: [{ addr: '', proto: 'udp' }], keepalive_sec: 5 };
  let stunSaving = false;
  // 服务器支持的协议（both=已确认 UDP+TCP 均可用；连通检测会同时验证两种协议）
  const SRV_PROTO_OPTIONS = [
    { value: 'both', label: 'UDP+TCP' },
    { value: 'udp', label: i18nTr("仅 UDP") },
    { value: 'tcp', label: i18nTr("仅 TCP") }
  ];

  // 连通检测：批量 Ping 服务器列表（Binding 单次往返），支持一键移除不可用项
  let chkLoading = false;
  let chkResult = {}; // addr → { ok, ms }
  $: chkFailCount = Object.values(chkResult).filter((x) => !x.ok).length;
  async function checkServers() {
    if (chkLoading) return;
    const items = stunCfg.servers
      .map((x) => ({ addr: (x.addr || '').trim(), proto: x.proto || 'udp' })) // both 同时验证 UDP 与 TCP
      .filter((x) => x.addr);
    if (!items.length) { toast(i18nTr("没有可检测的服务器地址"), 'error'); return; }
    chkLoading = true;
    chkResult = {};
    let done = 0;
    try {
      // NDJSON 流式：每测完一个立即更新该行结果
      await streamNDJSON('/api/stun/check', (line) => {
        if (!line || !line.addr) return;
        chkResult = { ...chkResult, [line.addr]: { ok: !!line.ok, ms: line.ms || 0 } };
        done++;
      }, { method: 'POST', body: { items } });
      const okN = Object.values(chkResult).filter((x) => x.ok).length;
      toast(i18nTr("检测完成（{0} 个）：{1} 个可用，{2} 个不可用", [done, okN, done - okN]), okN ? 'success' : 'error');
    } catch (e) {
      toast(i18nTr("检测失败：") + e.message, 'error');
    } finally {
      chkLoading = false;
    }
  }
  function removeUnavailable() {
    const before = stunCfg.servers.length;
    stunCfg = { ...stunCfg, servers: stunCfg.servers.filter((x) => !chkResult[x.addr] || chkResult[x.addr].ok) };
    const removed = before - stunCfg.servers.length;
    chkResult = {};
    toast(i18nTr("已移除 {0} 个不可用服务器，点击「保存设置」持久化", [removed]), 'success');
  }
  function clearChkOf(addr) {
    if (!(addr in chkResult)) return;
    const c = { ...chkResult };
    delete c[addr];
    chkResult = c;
  }
  async function loadStunSettings() {
    try {
      const d = await api('/api/stun/settings');
      if (d && Array.isArray(d.servers) && d.servers.length) {
        stunCfg = {
          servers: d.servers.map((x) => ({ addr: x.addr || '', proto: x.proto || 'udp' })),
          keepalive_sec: d.keepalive_sec || 5
        };
      }
    } catch (e) { /* 保留默认 */ }
  }
  $: if ($settingsSect === 'stun') loadStunSettings();
  function addStunSrv() {
    stunCfg = { ...stunCfg, servers: [...stunCfg.servers, { addr: '', proto: 'udp' }] };
  }
  function rmStunSrv(i) {
    stunCfg = { ...stunCfg, servers: stunCfg.servers.filter((_, idx) => idx !== i) };
  }
  async function saveStunSettings() {
    // 格式校验：每个服务器地址必须为合法 主机:端口（空行需先删除，不再静默丢弃）
    if (!validateAll(stunFormEl)) return;
    const servers = stunCfg.servers.filter((x) => (x.addr || '').trim());
    if (!servers.length) { toast(i18nTr("至少填写一个 STUN 服务器地址"), 'error'); return; }
    const ka = parseInt(stunCfg.keepalive_sec, 10);
    if (!ka || ka < 5 || ka > 300) { toast(i18nTr("保活间隔需在 5-300 秒之间"), 'error'); return; }
    stunSaving = true;
    try {
      await api('/api/stun/settings', { method: 'POST', body: { servers, keepalive_sec: ka } });
      toast(i18nTr("STUN 设置已保存并生效"), 'success');
      await loadStunSettings();
    } catch (e) {
      toast(i18nTr("保存失败：") + e.message, 'error');
    } finally {
      stunSaving = false;
    }
  }
</script>

<svelte:window on:resize={updateSectBar} />

<div class="container settings-page">
  <div class="page-hdr">
    <div>
      <h2>{$i18n("系统设置")}</h2>
      <span class="page-hdr-sub">{$i18n("当前分区：")}{$i18n(currentSect.label)} · {$i18n(sectDesc)}</span>
    </div>
    <div class="page-hdr-actions">
      {#if canResetSect}
        <button class="btn" on:click={resetUI} title={$i18n("恢复默认外观")}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/></svg>
          <span class="sm-hide">{$i18n("恢复默认")}</span>
        </button>
      {/if}
      {#if canSaveSect}
        <button class="btn btn-primary" on:click={saveCurrent} title={$i18n("保存更改")}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m5 13 4 4L19 7"/></svg>
          <span class="sm-hide">{$i18n("保存更改")}</span>
        </button>
      {/if}
    </div>
  </div>

  <div class="sect-tabs">
    {#if canScrollLeft}
      <button class="sect-tabs-arrow" on:click={() => scrollTabs(-1)} aria-label={$i18n("向左滚动")}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      </button>
    {/if}
    <div class="sect-tabs-scroll" role="tablist" aria-label={$i18n("系统设置分区")} bind:this={sectTabsEl} on:scroll={updateScrollState}>
      {#each settingsTabs as st, i}
        <button
          class="sect-tab"
          class:active={$settingsSect === st.id}
          role="tab"
          aria-selected={$settingsSect === st.id}
          aria-current={$settingsSect === st.id ? 'page' : undefined}
          on:click={() => selectSect(st.id, i)}
        >{@html st.icon}<span>{$i18n(st.label)}</span></button>
      {/each}
      <span class="sect-tab-bar" style="width:{barW}px;transform:translateX({barX}px)"></span>
    </div>
    {#if canScrollRight}
      <button class="sect-tabs-arrow" on:click={() => scrollTabs(1)} aria-label={$i18n("向右滚动")}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
      </button>
    {/if}
  </div>

  <!-- ===== 默认参数 ===== -->
  {#if $settingsSect === 'default'}
    <div class="section-card" bind:this={defaultFormEl}>
      <div class="set-cols">
        <div class="set-stack">
      <div class="settings-group">
        <div class="settings-group-title">{$i18n("端口配置")}<span class="sub">{$i18n("HTTP / HTTPS / Webhook 监听端口")}</span></div>
        <div class="form-row">
          <div class="form-group">
            <div class="form-label-row">
              <label class="form-label">{$i18n("HTTP 默认端口")}</label>
              <InfoTip text={$i18n("HTTP 转发的默认监听端口，创建 HTTP 转发规则且未指定端口时自动使用此端口。")} />
            </div>
            <input type="number" bind:value={fwd.http_default_port} min="1" max="65535" use:field={{ check: validatePort }} />
          </div>
          <div class="form-group">
            <div class="form-label-row">
              <label class="form-label">{$i18n("HTTPS 默认端口")}</label>
              <InfoTip text={$i18n("HTTPS 转发的默认监听端口，未配置证书时自动生成自签名证书。")} />
            </div>
            <input type="number" bind:value={fwd.https_default_port} min="1" max="65535" use:field={{ check: validatePort }} />
          </div>
          <div class="form-group">
            <div class="form-label-row">
              <label class="form-label">{$i18n("Webhook 端口")}</label>
              <InfoTip text={$i18n("Webhook 接收（STUN 客户端上报公网地址）与通道访问共用端口，默认 19520；0/80/443 省略端口显示。")} />
            </div>
            <input type="number" bind:value={wh.receive_port} min="0" max="65535" use:field={{ check: (v) => validatePort(v, true) }} />
          </div>
        </div>
      </div>

      <div class="settings-group">
        <div class="settings-group-title">{$i18n("访问方式")}<span class="sub">{$i18n("Web 服务路径模式对外地址")}</span></div>
        <div class="form-row">
          <div class="form-group">
            <div class="form-label-row">
              <label class="form-label">{$i18n("访问方式")}</label>
              <InfoTip text={$i18n("仅影响 Web 服务中「路径」模式生成的访问地址：使用 IP 时为本机 IP + HTTP 默认端口；使用域名时按 https 443 展示，需自行把域名解析并经反向代理转发到 HTTP 默认端口。")} />
            </div>
            <CustomSelect bind:value={webAccess.mode} options={addrModeOptions} />
          </div>
          {#if webAccess.mode === 'domain'}
            <div class="form-group">
              <div class="form-label-row">
                <label class="form-label">{$i18n("访问域名")}</label>
                <InfoTip text={$i18n("用于生成路径模式站点的访问地址，例如 https://web.example.com/docs；不会自动创建域名代理。")} />
              </div>
              <input type="text" bind:value={webAccess.domain} placeholder={$i18n("如 web.example.com")} use:field={{ check: validateDomain }} />
            </div>
          {:else}
            <div class="form-group">
              <div class="form-label-row">
                <label class="form-label">{$i18n("访问IP")}</label>
                <InfoTip text={$i18n("IP 模式下生成的访问地址，留空时自动填入匹配地址：优先公网地址，没有则使用本机局域网地址。")} />
              </div>
              <input type="text" bind:value={webAccess.ip} placeholder={$i18n("本机IP，如 192.168.1.70")} use:field={{ check: validateHost }} />
            </div>
          {/if}
        </div>
      </div>

      <div class="settings-group">
        <div class="settings-group-title">{$i18n("Webhook 地址")}<span class="sub">{$i18n("公网访问方式")}</span></div>
        <div class="form-row">
          <div class="form-group">
            <div class="form-label-row">
              <label class="form-label">{$i18n("地址模式")}</label>
              <InfoTip text={$i18n("选择客户端上报与通道访问使用的系统地址方式：使用 IP（本机地址），可选域名。")} />
            </div>
            <CustomSelect bind:value={wh.addr_mode} options={addrModeOptions} />
          </div>
          {#if wh.addr_mode === 'ip'}
            <div class="form-group">
              <div class="form-label-row">
                <label class="form-label">{$i18n("访问IP")}</label>
                <InfoTip text={$i18n("IP 模式下的系统地址，留空时自动填入匹配地址：优先公网地址，没有则使用本机局域网地址。")} />
              </div>
              <input type="text" bind:value={wh.access_ip} placeholder={$i18n("本机IP，如 192.168.1.70")} use:field={{ check: validateHost }} />
            </div>
          {:else if wh.addr_mode === 'domain'}
            <div class="form-group">
              <div class="form-label-row">
                <label class="form-label">{$i18n("访问域名")}</label>
                <InfoTip text={$i18n("域名模式下的系统地址，需自行解析到本机；点击「创建代理」自动创建域名通道")} />
              </div>
              <div class="input-action-row">
                <input type="text" bind:value={wh.access_domain} placeholder={$i18n("访问域名，如 wh.example.com")} style="flex:1" use:field={{ check: validateDomain, errAt: () => accessDomainErr }} />
                <button class="btn btn-sm" on:click={createDomainProxy} disabled={domainProxyBusy} style="white-space:nowrap" title={$i18n("创建 frpc 域名代理，使 Webhook 接收与通道访问可通过该域名使用")}>
                  {domainProxyBusy ? i18nTr("创建中…") : i18nTr("创建代理")}
                </button>
              </div>
              <div class="field-err" bind:this={accessDomainErr} style="display:none"></div>
            </div>
          {/if}
        </div>
      </div>
      <div class="settings-group">
        <div class="settings-group-title">{$i18n("Webhook 回调模板")}<span class="sub">{$i18n("客户端上报后的请求格式")}</span></div>
        <div class="tip-text" style="margin-bottom:10px">{$i18n("定义 Webhook 请求的默认模板：请求方法、请求头、请求体与接口调用成功判断字符")}</div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">{$i18n("请求方法")}</label>
            <CustomSelect bind:value={whTmpl.method} options={methodOptions} />
          </div>
          <div class="form-group">
            <div class="form-label-row">
              <label class="form-label">{$i18n("接口调用成功包含的字符串")}</label>
              <InfoTip text={$i18n("接口响应中包含该字符串时视为调用成功，用于验证接口响应。")} />
            </div>
            <input type="text" bind:value={whTmpl.success_string} placeholder={$i18n("例如: 更新成功")} />
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">{$i18n("请求头")}</label>
          <div style="display:flex;flex-direction:column;gap:6px">
            {#each whTmpl.headers as h, i}
              <div style="display:flex;gap:6px;align-items:center">
                <input type="text" bind:value={h.key} placeholder={$i18n("请求头名称，如 Content-Type")} style="flex:1;font-family:var(--mono);font-size:12px" />
                <span style="color:var(--text3)">:</span>
                <input type="text" bind:value={h.value} placeholder={$i18n("值")} style="flex:2;font-family:var(--mono);font-size:12px" />
                <button type="button" class="btn-icon" title={$i18n("删除请求头")} aria-label={$i18n("删除请求头")} style="color:var(--red)" on:click={() => delHeaderRow(i)}>
                  <svg width="15" height="15" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>
              </div>
            {/each}
          </div>
          <button type="button" class="btn btn-sm" style="margin-top:8px" on:click={addHeaderRow}>{$i18n("＋ 添加请求头")}</button>
        </div>
        <div class="form-group">
          <div class="form-label-row">
            <label class="form-label">{$i18n("请求体")}</label>
            <InfoTip text={'支持 {变量} 占位符；保存后作为 Webhook 请求体模板。'} />
          </div>
          <div class="code-editor">
            <pre class="code-hl" aria-hidden="true">{@html highlightJson(whTmpl.body) + '\n'}</pre>
            <textarea bind:value={whTmpl.body} spellcheck="false" on:scroll={onCodeScroll} placeholder={'{\n  "channel_id": "{channel_id}",\n  "host": "{ip}",\n  "password": "{link_key}",\n  "port": {port}\n}'}></textarea>
          </div>
        </div>
      </div>

        </div>
        <div class="set-stack">
          <div class="settings-group">
            <div class="settings-group-title">{$i18n("地址预览")}<span class="right"><span class="badge badge-info">{$i18n("实时")}</span></span></div>
            <div class="preview-field">
              <div class="preview-label">{$i18n("Webhook 接收")}</div>
              <div class="wh-addr" title={receivePreview}>{receivePreview}</div>
            </div>
            <div class="preview-field">
              <div class="preview-label">{$i18n("Webhook 访问")}</div>
              <div class="wh-addr" title={accessPreview}>{accessPreview}</div>
            </div>
            <div class="preview-field">
              <div class="preview-label">{$i18n("导航页访问")}</div>
              <div class="wh-addr" title={hookPreview}>{hookPreview}</div>
            </div>
            <div class="preview-field">
              <div class="preview-label">{$i18n("Web 服务路径")}</div>
              <div class="wh-addr" title={webPathPreview}>{webPathPreview}</div>
            </div>
          </div>
          <div class="settings-group">
            <div class="settings-group-title">{$i18n("生效状态")}</div>
            <div class="about-row"><span>{$i18n("HTTP 端口")}</span><b>{fwd.http_default_port}</b></div>
            <div class="about-row"><span>{$i18n("HTTPS 端口")}</span><b>{fwd.https_default_port}</b></div>
            <div class="about-row"><span>{$i18n("Webhook 端口")}</span><b>{wh.receive_port}</b></div>
            <button class="btn btn-primary" style="width:100%;margin-top:12px" on:click={saveSettings}>{$i18n("保存并应用")}</button>
            <div class="tip-text" style="margin-top:10px;line-height:1.6">{$i18n("修改端口后会立即重建监听，已建立的连接会短暂中断。")}</div>
          </div>
        </div>
      </div>
    </div>
  {/if}

  <!-- ===== 模块管理 ===== -->
  {#if $settingsSect === 'modules'}
    <div class="set-stack">
      <div class="settings-group">
        <div class="settings-group-title">
          {$i18n("可关闭模块")}
          <span class="sub">{MODULES.length} {$i18n("个 ·")} {enabledModuleCount} {$i18n("个启用")}</span>
          <span class="right">
            {#if enabledModuleCount < MODULES.length}
              <button class="btn btn-sm" disabled={modSaving} on:click={enableAllModules}>{$i18n("全部启用")}</button>
            {/if}
          </span>
        </div>
        <div class="tip-text" style="margin-bottom:12px;line-height:1.8">
          {$i18n("关闭后该模块的导航入口会被隐藏，直接访问其页面也会被拦下，")}<b>{$i18n("仪表盘上该模块的卡片会一并隐藏")}</b>。<b>{$i18n("已运行的服务不受影响")}</b>{$i18n("，开关即时生效。")}
        </div>
        <div class="mod-grid">
          {#each MODULES as m (m.id)}
            <div class="mod-item">
              <div class="mod-info">
                <div class="mod-name">{$i18n(m.label)}</div>
                <div class="mod-desc">{$i18n(m.desc)}</div>
              </div>
              <Toggle
                checked={!$disabledModules.includes(m.id)}
                disabled={modSaving}
                on:change={(e) => toggleModule(m.id, e.detail)}
              />
            </div>
          {/each}
        </div>
      </div>

      <div class="settings-group">
        <div class="settings-group-title">{$i18n("常驻模块")}<span class="sub">{FIXED_MODULES.length} {$i18n("个 · 不可关闭")}</span></div>
        <div class="mod-grid">
          {#each FIXED_MODULES as m (m.id)}
            <div class="mod-item mod-fixed">
              <div class="mod-info">
                <div class="mod-name">{$i18n(m.label)}</div>
                <div class="mod-desc">{$i18n(m.desc)}</div>
              </div>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text3);flex-shrink:0"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
            </div>
          {/each}
        </div>
        <div class="tip-text" style="margin-top:10px">
          {$i18n("仪表盘与系统设置必须常驻：模块管理位于系统设置内，若允许关闭将再也无法开启任何模块。")}
        </div>
      </div>
    </div>
  {/if}

  <!-- ===== STUN 设置 ===== -->
  {#if $settingsSect === 'stun'}
    <div class="section-card" bind:this={stunFormEl}>
      <div class="set-cols">
        <div class="set-stack">
      <div class="settings-group">
        <div class="settings-group-title">{$i18n("STUN 探测")}<span class="sub">{$i18n("UDP 打洞基础参数")}</span></div>
        <div class="tip-text" style="margin-bottom:12px;line-height:1.8">{$i18n("STUN 服务器列表用于「STUN 探测」与开启「使用默认 STUN 服务器」的打洞通道；通道关闭该开关后可使用自己的列表，不影响其他通道。保活间隔为打洞通道维持 NAT 映射的周期，保存后立即生效（无需重启）。")}</div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">{$i18n("保活间隔（秒）")}</label>
            <input type="number" bind:value={stunCfg.keepalive_sec} min="5" max="300" style="max-width:160px" />
            <div class="tip-text">{$i18n("打洞通道周期向 STUN 服务器发送 Binding 维持 NAT 映射的间隔（5-300 秒，默认 5）；调整后对运行中的通道热生效")}</div>
          </div>
        </div>
      </div>

      <div class="settings-group">
        <div class="settings-group-title">{$i18n("STUN 服务器列表")}<span class="sub">{stunCfg.servers.length} {$i18n("个")}</span></div>
        {#each stunCfg.servers as srv, i}
          <div class="form-row stun-srv-row" style="align-items:center">
            <div class="form-group stun-srv-addr" style="flex:2;min-width:200px">
              <input type="text" bind:value={srv.addr} placeholder={$i18n("地址（如 stun.l.google.com:19302）")} style="font-family:var(--mono)" on:input={() => clearChkOf(srv.addr)} use:field={{ check: validateHostPort }} />
            </div>
            <div class="form-group stun-srv-proto" style="width:120px;flex-shrink:0" title={$i18n("该服务器支持的协议；UDP+TCP 会同时验证 UDP 与 TCP 均可用")}>
              <CustomSelect bind:value={srv.proto} options={SRV_PROTO_OPTIONS} />
            </div>
            {#if chkLoading}
              <span class="spinner" style="width:13px;height:13px;flex-shrink:0" title={$i18n("检测中")}></span>
            {:else if chkResult[srv.addr]}
              {#if chkResult[srv.addr].ok}
                <span style="font-size:11px;color:var(--green);flex-shrink:0;white-space:nowrap" title={$i18n("STUN 响应正常")}>{chkResult[srv.addr].ms} ms</span>
              {:else}
                <span style="font-size:11px;color:var(--red);flex-shrink:0;white-space:nowrap" title={$i18n("无 STUN 响应")}>{$i18n("不可用")}</span>
              {/if}
            {/if}
            <button class="btn-icon" style="color:var(--red);flex-shrink:0" title={$i18n("删除")} aria-label={$i18n("删除服务器")} on:click={() => rmStunSrv(i)}>
              <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </button>
          </div>
        {/each}
        <div style="margin-top:4px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <button class="btn" on:click={addStunSrv}>{$i18n("＋ 添加服务器")}</button>
          <button class="btn" on:click={checkServers} disabled={chkLoading} title={$i18n("对列表中的服务器发送 STUN Binding 请求验证连通性")}>
            {#if chkLoading}<span class="spinner"></span>{$i18n("检测中…")}{:else}{$i18n("连通检测")}{/if}
          </button>
          {#if !chkLoading && chkFailCount > 0}
            <button class="btn" style="color:var(--red)" title={$i18n("从列表中移除所有检测不可用的服务器")} on:click={removeUnavailable}>{$i18n("移除不可用（")}{chkFailCount}）</button>
          {/if}
        </div>
      </div>

        </div>
        <div class="set-stack">
          <div class="settings-group">
            <div class="settings-group-title">{$i18n("服务器概览")}</div>
            <div class="about-row"><span>{$i18n("服务器数量")}</span><b>{stunCfg.servers.length}</b></div>
            <div class="about-row"><span>{$i18n("检测可用")}</span><b class="on">{Object.keys(chkResult).length ? Object.values(chkResult).filter((x) => x.ok).length + ' / ' + stunCfg.servers.length : i18nTr("未检测")}</b></div>
            <div class="about-row"><span>{$i18n("保活间隔")}</span><b>{stunCfg.keepalive_sec || 5} {$i18n("秒")}</b></div>
          </div>
          <div class="settings-group">
            <div class="settings-group-title">{$i18n("应用设置")}</div>
            <button class="btn btn-primary" style="width:100%" on:click={saveStunSettings} disabled={stunSaving}>{stunSaving ? i18nTr("保存中…") : i18nTr("保存并应用")}</button>
            <div class="tip-text" style="margin-top:10px;line-height:1.6">{$i18n("保存后立即生效，运行中的打洞通道会按新参数保活。")}</div>
          </div>
        </div>
      </div>
    </div>
  {/if}

  <!-- ===== FPRC (frpc 客户端) ===== -->
  {#if $settingsSect === 'frpc'}
    <div class="section-card" bind:this={frpcFormEl}>
      <div class="set-cols">
        <div class="set-stack">
      <div class="settings-group">
        <div class="settings-group-title">{$i18n("运行状态")}<span class="sub">{$i18n("frpc 客户端")}</span></div>
        <div class="tip-text" style="margin-bottom:12px;line-height:1.8">{$i18n("集成 frp 客户端：使用内置安装包一键安装，配置 frp 服务器并管理内核版本。frpc 代理通道请在 FRPC 页统一创建。")}</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:14px">
          <div class="stat-card"><div class="stat-num">{frpcStatus.installed ? frpcStatus.version || i18nTr("已安装") : '-'}</div><div class="stat-label">{$i18n("frpc 版本")}</div></div>
          <div class="stat-card"><div class="stat-num">{frpcStatus.running ? i18nTr("运行中") : i18nTr("已停止")}</div><div class="stat-label">{$i18n("整体状态")}</div></div>
          <button class="upgrade-card" on:click={() => (showFrpcUpgrade = true)} title={frpcStatus.installed ? i18nTr("升级 frpc 内核版本") : i18nTr("安装 frpc 内核（在线下载或上传离线包）")} style="width:100%;height:100%;min-height:56px;background:var(--bg3);border:1px solid var(--bd);border-radius:var(--radius);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px;padding:12px 10px;cursor:pointer;color:var(--accent);transition:border-color .15s ease,transform .15s ease,box-shadow .15s ease">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/></svg>
            <span style="font-size:14px;font-weight:600;font-family:var(--mono)">{frpcStatus.installed ? i18nTr("内核升级") : i18nTr("安装内核")}</span>
            <span style="font-size:11px;color:var(--text3);font-weight:400">{$i18n("最新")} {frpcLatest ? 'v' + frpcLatest : '--'}</span>
          </button>
        </div>
        <!-- 各服务器独立运行状态与启停（多实例可同时运行） -->
        <div class="frpc-server-list">
          {#each frpcStatus.servers || [] as ss}
            {@const lat = frpcLat[ss.name]}
            <div class="frpc-server-item">
              <div style="display:flex;align-items:center;gap:8px;min-width:0;flex:1">
                <span class="dash-live-dot" style="background:{ss.running ? 'var(--green)' : 'var(--text3)'}"></span>
                <span style="font-size:13px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{ss.name}</span>
                <span style="font-size:11px;color:var(--text3);white-space:nowrap">{ss.running ? i18nTr("运行中") : i18nTr("已停止")}</span>
                <!-- 连接延时：仅在已测量过时展示，避免未测就显示 0 造成「已连通」的错觉 -->
                {#if lat && !frpcLatBusy[ss.name]}
                  {#if lat.online}
                    <span style="font-size:11px;color:var(--green);white-space:nowrap;font-family:var(--mono)" title={$i18n("到 {0} 的往返延时", [lat.addr || i18nTr("frp 服务器")])}>{lat.latency_ms} ms</span>
                  {:else}
                    <span style="font-size:11px;color:var(--red);white-space:nowrap" title={lat.error || ''}>{$i18n("连接失败")}</span>
                  {/if}
                {:else if frpcLatBusy[ss.name]}
                  <span style="font-size:11px;color:var(--text3);white-space:nowrap">{$i18n("测量中…")}</span>
                {/if}
                {#if ss.name === frpcCfg.active_server}<span class="badge badge-on">{$i18n("默认")}</span>{/if}
                {#if !ss.configured}<span class="badge badge-off">{$i18n("未配置地址")}</span>{/if}
              </div>
              <div style="display:flex;gap:6px;flex-shrink:0;flex-wrap:wrap;align-items:center">
                <button class="btn btn-sm" on:click={() => frpcStart(ss.name)} disabled={frpcBusy || !ss.configured || ss.running} style="white-space:nowrap">{$i18n("启动")}</button>
                <button class="btn btn-sm" on:click={() => frpcStop(ss.name)} disabled={frpcBusy || !ss.running} style="white-space:nowrap">{$i18n("停止")}</button>
                <button class="btn btn-sm" on:click={() => frpcRestart(ss.name)} disabled={frpcBusy || !ss.configured} style="white-space:nowrap">{$i18n("重启")}</button>
                <span style="display:inline-flex;align-items:center;gap:5px;font-size:12px;color:var(--text3);white-space:nowrap" title={ss.name === frpcCfg.active_server ? i18nTr("默认服务器必须保持开机自启（锁定开启）") : i18nTr("开机自启：本应用启动时自动运行该服务器")}>
                  <Toggle checked={ss.name === frpcCfg.active_server ? true : !!ss.auto_start} disabled={ss.name === frpcCfg.active_server} on:change={(e) => setServerAutoStart(ss.name, e.detail)} />
                  {$i18n("自启")}
                </span>
              </div>
              <!-- 失败原因：进程「运行中」不代表登录成功，真实原因只在日志/探测错误里，必须显式呈现。
                   已测得连通时不展示 last_error——它是日志里的最近一条告警，
                   故障恢复后仍是旧内容，留着会让界面显示已经解决的报错。 -->
              {#if lat && lat.online}
                <!-- 已连通：不显示任何错误 -->
              {:else if lat && lat.error}
                <div style="flex-basis:100%;font-size:11px;color:var(--red);opacity:.85;word-break:break-all;line-height:1.5">{lat.error}</div>
              {:else if ss.last_error}
                <div style="flex-basis:100%;font-size:11px;color:var(--red);opacity:.85;word-break:break-all;line-height:1.5">{ss.last_error}</div>
              {/if}
            </div>
          {/each}
        </div>
        <!-- 未安装时不在此放置安装按钮：统一由上方「安装内核」卡片进入内核安装/升级弹窗（在线下载或离线上传） -->
        {#if frpcStatus.installed}
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
            <button class="btn btn-primary" on:click={() => (frpcConfirm = 'start')} disabled={frpcBusy || (frpcStatus.servers || []).every((x) => x.running)} style="white-space:nowrap">{$i18n("全部启动")}</button>
            <button class="btn" on:click={() => (frpcConfirm = 'stop')} disabled={frpcBusy || !frpcStatus.running} style="white-space:nowrap">{$i18n("全部停止")}</button>
            <button class="btn" on:click={() => (frpcConfirm = 'restart')} disabled={frpcBusy} style="white-space:nowrap">{$i18n("全部重启")}</button>
          </div>
        {/if}
      </div>

      <div class="settings-group">
        <div class="settings-group-title" style="justify-content:flex-start">
          <span>{$i18n("服务器配置")}</span><span class="sub">{$i18n("多实例与连接参数")}</span>
          <span style="display:flex;gap:6px;margin-left:auto">
            <button class="btn btn-sm" on:click={openFrpcConfigFile} style="white-space:nowrap">{$i18n("配置文件")}</button>
            <button class="btn btn-primary btn-sm" on:click={frpcSave} disabled={frpcSaving} style="white-space:nowrap">
              {frpcSaving ? i18nTr("保存中…") : i18nTr("保存配置")}
            </button>
          </span>
        </div>
        <div class="form-group">
          <label class="form-label">{$i18n("服务器配置")}</label>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            {#each frpcCfg.servers as s, i}
              <button
                class="capsule-btn"
                class:active={i === viewSrvIdx}
                title={$i18n("{0}点击切换显示的配置 · 双击或右键修改名称/设为默认", [s.name === frpcCfg.active_server ? i18nTr("默认服务器 · ") : ''])}
                on:click={() => showServer(i)}
                on:dblclick={() => (editSrvName = s.name)}
                on:contextmenu={(e) => { e.preventDefault(); editSrvName = s.name; }}
              >
                {#if s.name === frpcCfg.active_server}
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                {/if}
                {s.name}
              </button>
            {/each}
            <button class="capsule-btn" on:click={() => (showAddServer = true)} disabled={frpcCfg.servers.length >= MAX_SERVERS} title={frpcCfg.servers.length >= MAX_SERVERS ? i18nTr("最多添加 ") + MAX_SERVERS + i18nTr(" 台服务器") : i18nTr("添加服务器")}>{$i18n("＋ 添加服务器")}</button>
            {#if frpcCfg.servers.length > 1}
              <button class="btn-icon" title={$i18n("删除当前显示的服务器")} aria-label={$i18n("删除当前显示的服务器")} on:click={() => (delServerName = frpcCfg.servers[viewSrvIdx].name)} style="color:var(--red)">
                <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
              </button>
            {/if}
          </div>
          <div class="tip-text">{$i18n("点击胶囊切换显示的服务器配置（不改变默认服务器，星标为当前默认服务器）；双击或右键胶囊可修改名称 / 设为默认服务器；「＋ 添加服务器」可新增实例，最多")} {MAX_SERVERS} {$i18n("台")}</div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">{$i18n("服务器地址")}</label>
            <input type="text" bind:value={activeSrv.addr} placeholder={$i18n("frp 服务器 IP 或域名")} use:field={{ check: validateHost }} />
          </div>
          <div class="form-group">
            <label class="form-label">{$i18n("服务器端口")}</label>
            <input type="number" bind:value={activeSrv.port} min="1" max="65535" use:field={{ check: validatePort }} />
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">{$i18n("认证令牌（Token）")}</label>
            <input type="password" bind:value={activeSrv.token} placeholder={$i18n("与服务器 auth.token 一致，可为空")} />
          </div>
          <div class="form-group">
            <label class="form-label">{$i18n("用户名称")}</label>
            <input type="text" bind:value={activeSrv.user} />
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">{$i18n("传输协议")}</label>
            <CustomSelect bind:value={activeSrv.protocol} options={protocolOptions} />
          </div>
          <div class="form-group">
            <label class="form-label">{$i18n("预建立连接池数量")}</label>
            <input type="number" bind:value={activeSrv.pool_count} min="0" max="1000" placeholder={$i18n("默认 5")} />
          </div>
        </div>
        {#if (activeSrv.protocol || 'tcp') === 'quic'}
          <div class="form-group">
            <label class="form-label">{$i18n("QUIC 协议配置")}</label>
            <div class="quic-grid">
              <div style="flex:1;display:flex;flex-direction:column;gap:4px;min-width:0">
                <span style="font-size:12px;color:var(--text3)">{$i18n("保活周期（QUIC 心跳检查间隔，秒）")}</span>
                <input type="number" bind:value={activeSrv.quic_keepalive_period} min="0" placeholder={$i18n("默认 10")} />
              </div>
              <div style="flex:1;display:flex;flex-direction:column;gap:4px">
                <span style="font-size:12px;color:var(--text3)">{$i18n("最大空闲超时（无数据则断开，秒）")}</span>
                <input type="number" bind:value={activeSrv.quic_max_idle_timeout} min="0" placeholder={$i18n("默认 30")} />
              </div>
              <div style="flex:1;display:flex;flex-direction:column;gap:4px">
                <span style="font-size:12px;color:var(--text3)">{$i18n("最大流入流数（并发流入流上限）")}</span>
                <input type="number" bind:value={activeSrv.quic_max_incoming_streams} min="0" placeholder={$i18n("默认 100000")} />
              </div>
            </div>
          </div>
        {/if}
        <div class="form-row frpc-stun-row">
          <div class="form-group" style="margin-bottom:0;flex:1 1 480px;max-width:50%;min-width:0">
            <label class="form-label">{$i18n("STUN 服务器")}</label>
            <input type="text" bind:value={activeSrv.stun_server} placeholder="stun.miwifi.com:3478" style="width:auto;min-width:0" use:field={{ check: optional(validateHostPort) }} />
          </div>
          <div class="frpc-stun-controls">
            <div class="form-group frpc-stun-ctrl" style="margin-bottom:0;flex:0 0 120px;min-width:0">
              <label class="form-label">{$i18n("日志级别")}</label>
              <CustomSelect bind:value={frpcCfg.log_level} options={logLevelOptions} width="100%" />
            </div>
            <div class="form-group frpc-stun-ctrl" style="margin-bottom:0;flex:0 0 120px;min-width:0">
              <label class="form-label">{$i18n("保留天数")}</label>
              <input type="number" bind:value={activeSrv.log_days} min="0" max="365" placeholder={$i18n("默认 7")} style="width:100%;min-width:0" />
            </div>
            <div class="form-group frpc-stun-ctrl" style="margin-bottom:0;flex:0 1 220px;min-width:0;flex-direction:row;flex-wrap:wrap;gap:8px 20px;align-items:center">
              <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex:1 1 190px;min-width:0">
                <label class="form-label" style="margin:0;font-weight:400;color:var(--text3);letter-spacing:normal;white-space:nowrap">{$i18n("TCP 多路复用（")}{activeSrv.tcp_mux !== false ? i18nTr("开启") : i18nTr("关闭")}）</label>
                <Toggle checked={activeSrv.tcp_mux !== false} on:change={(e) => (activeSrv.tcp_mux = !!e.detail)} />
              </div>
            </div>
            <div class="form-group frpc-stun-ctrl" style="margin-bottom:0;flex:0 0 auto;min-width:0">
              <button class="btn btn-sm" on:click={openBindDns} title={$i18n("添加域名：选择 DNS 账号与域名，将 frp 服务器地址解析到该域名")} style="white-space:nowrap">{$i18n("添加域名")}</button>
            </div>
          </div>
        </div>
      </div>
        </div>
        <div class="set-stack">
          <div class="settings-group">
            <div class="settings-group-title">{$i18n("内核与运行")}</div>
            <div class="about-row"><span>{$i18n("frpc 版本")}</span><b>{frpcStatus.installed ? frpcStatus.version || i18nTr("已安装") : i18nTr("未安装")}</b></div>
            <div class="about-row"><span>{$i18n("整体状态")}</span><b class:on={frpcStatus.running} class:off={!frpcStatus.running}>{frpcStatus.running ? i18nTr("运行中") : i18nTr("已停止")}</b></div>
            <div class="about-row"><span>{$i18n("默认服务器")}</span><b>{frpcCfg.active_server || '-'}</b></div>
            <div class="about-row"><span>{$i18n("服务器数量")}</span><b>{(frpcStatus.servers || []).length}</b></div>
          </div>
          <div class="settings-group">
            <div class="settings-group-title">{$i18n("应用设置")}</div>
            <button class="btn btn-primary" style="width:100%" on:click={frpcSave} disabled={frpcSaving}>{frpcSaving ? i18nTr("保存中…") : i18nTr("保存配置")}</button>
            <button class="btn" style="width:100%;margin-top:8px" on:click={openFrpcConfigFile}>{$i18n("打开配置文件")}</button>
            <div class="tip-text" style="margin-top:10px;line-height:1.6">{$i18n("切换默认服务器或修改连接池后，已建立的代理会重新连接。")}</div>
          </div>
          <div class="settings-group">
            <div class="settings-group-title">
              <span>{$i18n("运行日志")}</span><span class="sub">{$i18n("最近输出")}</span>
              <span style="display:flex;gap:6px;margin-left:auto">
                <button class="btn btn-sm" on:click={loadFrpcLog} style="white-space:nowrap">{$i18n("刷新")}</button>
                <button class="btn btn-sm" on:click={() => (frpcLog = '')} style="white-space:nowrap">{$i18n("清空显示")}</button>
              </span>
            </div>
            <pre style="background:var(--bg4);border:1px solid var(--bd);border-radius:8px;padding:10px;max-height:300px;overflow:auto;font-size:12px;color:var(--text2);white-space:pre-wrap;word-break:break-all;margin:0">{@html highlightLog(frpcLog || i18nTr("暂无日志"))}</pre>
          </div>
        </div>
      </div>
    </div>
  {/if}

  <!-- ===== 错误页面 ===== -->
  {#if $settingsSect === 'errorpage'}
    <ErrorPagesPanel />
  {/if}

  <!-- ===== IP 过滤 ===== -->
  {#if $settingsSect === 'ipdb'}
    <div class="section-card">
      <div class="set-cols">
        <div class="set-stack">
      <div class="settings-group">
        <div class="settings-group-title">{$i18n("过滤设置")}<span class="sub">{$i18n("黑白名单与放行策略")}</span></div>
        <div class="tip-text" style="margin-bottom:12px;line-height:1.8">{$i18n("按 IP 地址 / 网段（CIDR）进行过滤：本机回环地址（127.0.0.1 / localhost）固定放行；命中白名单的地址优先放行；命中黑名单的地址直接拒绝；其余地址需通过公网 IP 段校验（内网 / 保留地址将被拦截）。")}</div>
        <div class="set-row">
          <div class="info"><div class="name">{$i18n("启用 IP 过滤")}</div><div class="desc">{$i18n("命中黑名单或不在白名单中的来源将被拒绝")}</div></div>
          <Toggle bind:checked={ipfEnabled} on:change={setIPFilterEnabled} />
        </div>
        <div class="set-row">
          <div class="info"><div class="name">{$i18n("过滤模式")}</div><div class="desc">{$i18n("黑名单拦截指定来源；白名单仅放行指定来源")}</div></div>
          <div class="seg-mini">
            <button class:on={ipfMode === 'blacklist'} on:click={() => { ipfMode = 'blacklist'; setIPFilterMode(); }}>{$i18n("黑名单")}</button>
            <button class:on={ipfMode === 'whitelist'} on:click={() => { ipfMode = 'whitelist'; setIPFilterMode(); }}>{$i18n("白名单")}</button>
          </div>
        </div>
        <div class="set-row">
          <div class="info"><div class="name">{$i18n("局域网放行")}</div><div class="desc">{$i18n("允许 192.168.0.0/16 与 10.0.0.0/8")}</div></div>
          <Toggle bind:checked={ipfAllowLAN} on:change={onAllowLANChange} />
        </div>
        <div class="set-row">
          <div class="info"><div class="name">{$i18n("自动记录")}</div><div class="desc">{$i18n("记录被拦截的请求来源")}</div></div>
          <Toggle bind:checked={ipfAutoRecord} on:change={setAutoRecord} />
        </div>
      </div>

      <div class="settings-group">
        <div class="settings-group-title">{$i18n("黑名单")}<span class="sub">{blackIPs.length + blacklistRegions.length} {$i18n("条")}</span></div>
        <div class="form-group" bind:this={blackAddEl} style="margin-bottom:10px">
          <div class="input-action-row">
            <input type="text" bind:value={blackInput} placeholder={$i18n("例如: 192.168.1.0/24 或 8.8.8.8")} style="flex:1" on:keydown={(e) => { if (e.key === 'Enter') addBlack(); }} use:field={{ check: validateCIDR, errAt: () => blackInputErr }} />
            <button class="btn btn-primary" on:click={addBlack} style="white-space:nowrap">{$i18n("添加")}</button>
            <button class="btn" on:click={() => openRegionPick('blacklist')} style="white-space:nowrap">{$i18n("从 IP 地址库添加")}</button>
          </div>
          <div class="field-err" bind:this={blackInputErr} style="display:none"></div>
        </div>
        {#if blacklistRegions.length === 0 && blackIPs.length === 0}
          <div class="ipf-empty">{$i18n("暂无黑名单条目")}</div>
        {:else}
          <div class="table-wrap ipf-table">
            <table>
              <thead><tr><th>{$i18n("IP / 地区")}</th><th>{$i18n("来源")}</th><th>{$i18n("添加时间")}</th><th>{$i18n("操作")}</th></tr></thead>
              <tbody>
                {#each blacklistRegions as reg}
                  <tr>
                    <td class="cell-mono">{reg.name}</td>
                    <td><span class="badge badge-off">{$i18n("地区库 ·")} {ipfRegionLabels[reg.category] || reg.category}</span></td>
                    <td class="cell-dim">—</td>
                    <td><button class="btn btn-sm btn-danger" on:click={() => delRegion('blacklist', reg)}>{$i18n("移除")}</button></td>
                  </tr>
                {/each}
                {#each blackIPs as ip, i}
                  <tr>
                    <td class="cell-mono" style="word-break:break-all">
                      {#if editBlackIdx === i}
                        <input type="text" bind:value={editBlackVal} style="width:100%;font-family:var(--mono);font-size:12px" on:keydown={(e) => { if (e.key === 'Enter') saveEditBlack(ip); if (e.key === 'Escape') editBlackIdx = -1; }} use:field={{ check: validateCIDR, errAt: () => editBlackErr }} />
                      {:else}{ip}{/if}
                    </td>
                    <td><span class="badge badge-off">{$i18n("手动")}</span></td>
                    <td class="cell-dim">—</td>
                    <td>
                      {#if editBlackIdx === i}
                        <button class="btn btn-sm btn-primary" on:click={() => saveEditBlack(ip)}>{$i18n("保存")}</button>
                        <button class="btn btn-sm" on:click={() => (editBlackIdx = -1)}>{$i18n("取消")}</button>
                      {:else}
                        <button class="btn btn-sm" on:click={() => { editBlackIdx = i; editBlackVal = ip; }}>{$i18n("编辑")}</button>
                        <button class="btn btn-sm btn-danger" on:click={() => delBlack(ip)}>{$i18n("删除")}</button>
                      {/if}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
            <div class="ipf-foot">
              <span>{$i18n("黑名单")} {blackIPs.length + blacklistRegions.length} {$i18n("条")}</span>
              <button class="btn btn-sm" on:click={() => openRegionPick('blacklist')}>{$i18n("从 IP 地址库添加")}</button>
            </div>
          </div>
        {/if}
        <div class="field-err" bind:this={editBlackErr} style="display:none"></div>
      </div>

      <div class="settings-group">
        <div class="settings-group-title">{$i18n("白名单")}<span class="sub">{whiteIPs.length + whitelistRegions.length} {$i18n("条")}</span></div>
        <div class="form-group" bind:this={whiteAddEl} style="margin-bottom:10px">
          <div class="input-action-row">
            <input type="text" bind:value={whiteInput} placeholder={$i18n("例如: 192.168.1.0/24 或 8.8.8.8")} style="flex:1" on:keydown={(e) => { if (e.key === 'Enter') addWhite(); }} use:field={{ check: validateCIDR, errAt: () => whiteInputErr }} />
            <button class="btn btn-primary" on:click={addWhite} style="white-space:nowrap">{$i18n("添加")}</button>
            <button class="btn" on:click={() => openRegionPick('whitelist')} style="white-space:nowrap">{$i18n("从 IP 地址库添加")}</button>
          </div>
          <div class="field-err" bind:this={whiteInputErr} style="display:none"></div>
        </div>
        {#if whitelistRegions.length === 0 && whiteIPs.length === 0}
          <div class="ipf-empty">{$i18n("暂无白名单条目")}</div>
        {:else}
          <div class="table-wrap ipf-table">
            <table>
              <thead><tr><th>{$i18n("IP / 地区")}</th><th>{$i18n("来源")}</th><th>{$i18n("添加时间")}</th><th>{$i18n("操作")}</th></tr></thead>
              <tbody>
                {#each whitelistRegions as reg}
                  <tr>
                    <td class="cell-mono">{reg.name}</td>
                    <td><span class="badge badge-on">{$i18n("地区库 ·")} {ipfRegionLabels[reg.category] || reg.category}</span></td>
                    <td class="cell-dim">—</td>
                    <td><button class="btn btn-sm btn-danger" on:click={() => delRegion('whitelist', reg)}>{$i18n("移除")}</button></td>
                  </tr>
                {/each}
                {#each whiteIPs as ip, i}
                  <tr>
                    <td class="cell-mono" style="word-break:break-all">
                      {#if editWhiteIdx === i}
                        <input type="text" bind:value={editWhiteVal} style="width:100%;font-family:var(--mono);font-size:12px" on:keydown={(e) => { if (e.key === 'Enter') saveEditWhite(ip); if (e.key === 'Escape') editWhiteIdx = -1; }} use:field={{ check: validateCIDR, errAt: () => editWhiteErr }} />
                      {:else}{ip}{/if}
                    </td>
                    <td><span class="badge badge-off">{$i18n("手动")}</span></td>
                    <td class="cell-dim">—</td>
                    <td>
                      {#if editWhiteIdx === i}
                        <button class="btn btn-sm btn-primary" on:click={() => saveEditWhite(ip)}>{$i18n("保存")}</button>
                        <button class="btn btn-sm" on:click={() => (editWhiteIdx = -1)}>{$i18n("取消")}</button>
                      {:else}
                        <button class="btn btn-sm" on:click={() => { editWhiteIdx = i; editWhiteVal = ip; }}>{$i18n("编辑")}</button>
                        <button class="btn btn-sm btn-danger" on:click={() => delWhite(ip)}>{$i18n("删除")}</button>
                      {/if}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
            <div class="ipf-foot">
              <span>{$i18n("白名单")} {whiteIPs.length + whitelistRegions.length} {$i18n("条")}</span>
              <button class="btn btn-sm" on:click={() => openRegionPick('whitelist')}>{$i18n("从 IP 地址库添加")}</button>
            </div>
          </div>
        {/if}
        <div class="field-err" bind:this={editWhiteErr} style="display:none"></div>
      </div>

        </div>
        <div class="set-stack">
      <div class="settings-group">
        <div class="settings-group-title">{$i18n("拦截统计")}</div>
        <div class="ipdb-stats" style="grid-template-columns:1fr 1fr;margin-top:0">
          <div class="sys-cell"><span>{$i18n("拦截记录")}</span><b>{blockedIPs.length}</b></div>
          <div class="sys-cell"><span>{$i18n("黑名单")}</span><b>{blackIPs.length + blacklistRegions.length}</b></div>
        </div>
      </div>
      <div class="settings-group">
        <div class="settings-group-title">
          {$i18n("最近拦截")}
          <span class="right">
            {#if blockedIPs.length}
              <button class="btn btn-sm btn-danger" on:click={clearBlocked} disabled={clearBlockedBusy}>{clearBlockedBusy ? i18nTr("清空中…") : i18nTr("清空")}</button>
            {/if}
          </span>
        </div>
        {#if blockedIPs.length === 0}
          <div class="ipf-empty">{$i18n("暂无拦截记录")}</div>
        {:else}
          <div class="ipf-log">
            {#each blockedIPs as ip}
              <div class="ipf-log-row">
                <span class="cell-mono">{ip}</span>
                <button class="btn btn-sm" on:click={() => addBlackFromRecord(ip)}>{$i18n("加入黑名单")}</button>
                <button class="btn btn-sm btn-danger" on:click={() => delBlocked(ip)}>{$i18n("删除")}</button>
              </div>
            {/each}
          </div>
        {/if}
      </div>
        </div>
      </div>
    </div>
  {/if}

  <!-- ===== IP 地址库 ===== -->
  {#if $settingsSect === 'ipfilter'}
    <div class="section-card">
      <div class="set-cols">
        <div class="set-stack">
          <div class="settings-group">
            <div class="settings-group-title">
              {$i18n("数据源状态")}
              <span class="sub">GeoLite2 + IP2Location</span>
              <span class="right"><span class="badge {geo && geo.ready ? 'badge-on' : 'badge-off'}">{geo && geo.ready ? i18nTr("已就绪") : i18nTr("未就绪")}</span></span>
            </div>
            <div class="about-row"><span>{$i18n("总 IP 数量")}</span><b>{geo ? geo.total_ips || 0 : '-'}</b></div>
            <div class="ipdb-stats">
              <div class="sys-cell"><span>{$i18n("国家段")}</span><b>{geo ? geo.country || '-' : '-'}</b></div>
              <div class="sys-cell"><span>{$i18n("中国内地段")}</span><b>{geo ? geo.china || '-' : '-'}</b></div>
              <div class="sys-cell"><span>{$i18n("省/市级段")}</span><b>{geo ? ((geo.province || 0) + (geo.city || 0)) : '-'}</b></div>
              <div class="sys-cell"><span>{$i18n("运营商段")}</span><b>{geo ? geo.isp || '-' : '-'}</b></div>
              <div class="sys-cell"><span>{$i18n("公有云段")}</span><b>{geo ? geo.cloud || '-' : '-'}</b></div>
              <div class="sys-cell"><span>{$i18n("总段数")}</span><b>{geo ? geo.total || '-' : '-'}</b></div>
            </div>
          </div>

          <div class="settings-group">
            <div class="settings-group-title">{$i18n("IP 归属查询")}<span class="right"><span class="badge badge-info">{$i18n("本地查询")}</span></span></div>
            <div class="form-group" bind:this={geoQueryEl}>
              <div class="input-action-row">
                <input type="text" id="geoLookupInput" placeholder={$i18n("输入 IP 地址，例如 8.8.8.8")} style="flex:1" on:keydown={(e) => { if (e.key === 'Enter') geoLookup(); }} use:field={{ check: validateIP, errAt: () => geoLookupErr }} />
                <button class="btn btn-primary" on:click={geoLookup} style="white-space:nowrap">{$i18n("查询")}</button>
              </div>
              <div class="field-err" bind:this={geoLookupErr} style="display:none"></div>
              {#if geoLookupResult}
                <div class="wh-addr" style="margin-top:10px">{geoLookupResult}</div>
              {/if}
            </div>
          </div>
        </div>

        <div class="set-stack">
          <div class="settings-group">
            <div class="settings-group-title">{$i18n("自动更新")}</div>
            <div class="form-group">
              <label class="form-label">{$i18n("更新间隔（小时，0 = 关闭）")}</label>
              <input type="number" bind:value={geoAutoHours} min="0" />
            </div>
            <button class="btn btn-primary" style="width:100%" on:click={geoSaveAutoUpdate}>{$i18n("保存自动更新")}</button>
          </div>
          <div class="settings-group">
            <div class="settings-group-title">
              {$i18n("数据源")}<span class="sub">{geoSources.length} {$i18n("个")}</span>
              <span class="right"><button class="btn btn-sm" on:click={() => (showGeoModal = true)}>{$i18n("管理")}</button></span>
            </div>
            {#if geoSources.length === 0}
              <div class="ipf-empty">{$i18n("暂无数据源，点击「管理」刷新目录")}</div>
            {:else}
              <div class="geo-src-list">
                {#each geoSources.slice(0, 8) as s (s.id)}
                  <div class="geo-src">
                    <div class="geo-src-main">
                      <div class="geo-src-name">{s.name || s.id}</div>
                      <div class="geo-src-sub">{s.category}{#if s.class} · {s.class}{/if} · {s.ip_count || 0} IP</div>
                    </div>
                    <span class="badge {s.status === 'ok' ? 'badge-on' : s.status === 'error' ? 'badge-error' : 'badge-off'}">{s.status === 'ok' ? i18nTr("正常") : s.status === 'error' ? i18nTr("异常") : i18nTr("未检测")}</span>
                  </div>
                {/each}
              </div>
              {#if geoSources.length > 8}
                <div class="geo-src-more">{$i18n("共")} {geoSources.length} {$i18n("个数据源，点击「管理」查看全部")}</div>
              {/if}
            {/if}
            <div class="about-row" style="margin-top:8px"><span>{$i18n("上次更新")}</span><b>{geo && geo.last_update ? fmtTime(geo.last_update) : '-'}</b></div>
            <div class="tip-text" style="margin-top:8px;line-height:1.6">{$i18n("数据源更新后按分类重建索引。")}</div>
          </div>
        </div>
      </div>
    </div>
  {/if}

  <!-- ===== 系统UI：界面自定义 ===== -->
  {#if $settingsSect === 'ui'}
    <div class="section-card">
      <div class="set-cols">
        <div class="set-stack">
      <div class="settings-group nav-card">
        <div class="form-label-row">
          <div class="settings-group-title">{$i18n("导航页")}<span class="sub">{$i18n("通道导航入口")}</span></div>
          <InfoTip text={$i18n("启用后可通过 {0} 访问通道导航页：集中展示已注册通道 / 转发规则 / 代理列表。关闭后 /hook 将无法访问。", [hookPreview])} />
        </div>

        <!-- 启用开关 + 地址预览靠右 -->
        <div class="form-group">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
            <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
              <div style="display:flex;align-items:center;gap:12px">
                <Toggle bind:checked={hookCfg.enabled} on:change={() => saveHookSettings(hookCfg.enabled ? '导航页已启用' : '导航页已停用')} />
                <span style="font-size:13px;color:var(--text2)">{hookCfg.enabled ? i18nTr("已启用") : i18nTr("已停用")}</span>
              </div>
            </div>
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
              {#if hookCfg.enabled}
                <button class="btn btn-sm" on:click={() => window.open(hookPreview, '_blank')} style="white-space:nowrap">{$i18n("打开")}</button>
              {/if}
            </div>
          </div>
        </div>

        {#if hookCfg.enabled}
          <div class="form-row">
            <div class="form-group">
              <div class="form-label-row">
                <label class="form-label">{$i18n("导航页管理密码")}</label>
                <InfoTip text={$i18n("导航页右上角登录入口的校验密码，默认 TunHook。留空保存时保持当前密码。")} />
              </div>
              <input type="password" bind:value={hookAdminPass} maxlength="64" placeholder={$i18n("留空保持当前密码")} autocomplete="new-password" on:change={() => saveHookSettings('管理密码已更新')} />
            </div>
          </div>

          <div class="hook-sec-title">{$i18n("显示内容")}</div>
          <div class="hook-toggle-grid">
            <div class="hook-toggle-cell">
              <div class="hook-toggle-label">
                <span>{$i18n("显示 Webhook 通道")}</span>
                <InfoTip text={$i18n("导航页展示 STUN 客户端上报注册的通道（按分组卡片，点击直达访问地址）。")} />
              </div>
              <Toggle bind:checked={hookCfg.show_webhook} on:change={() => saveHookSettings('导航页设置已保存')} />
            </div>
            <div class="hook-toggle-cell">
              <div class="hook-toggle-label">
                <span>{$i18n("显示转发列表")}</span>
                <InfoTip text={$i18n("导航页展示转发规则列表（网关 / TCP / UDP / HTTP 等）。")} />
              </div>
              <Toggle bind:checked={hookCfg.show_forwards} on:change={() => saveHookSettings('导航页设置已保存')} />
            </div>
            <div class="hook-toggle-cell">
              <div class="hook-toggle-label">
                <span>{$i18n("显示代理列表")}</span>
                <InfoTip text={$i18n("导航页展示 frpc 代理通道列表。")} />
              </div>
              <Toggle bind:checked={hookCfg.show_proxies} on:change={() => saveHookSettings('导航页设置已保存')} />
            </div>
            <div class="hook-toggle-cell">
              <div class="hook-toggle-label">
                <span>{$i18n("显示搜索栏")}</span>
                <InfoTip text={$i18n("导航页顶部搜索框：过滤通道 + 回车网页搜索。")} />
              </div>
              <Toggle bind:checked={hookCfg.show_search} on:change={() => saveHookSettings('导航页设置已保存')} />
            </div>
          </div>
        {/if}
      </div>

      <div class="settings-group theme-card">
        <div class="form-label-row">
          <div class="settings-group-title">{$i18n("主题与配色")}<span class="sub">{$i18n("实时生效")}</span></div>
          <InfoTip text={$i18n("切换主色时自动搭配辅助色；辅助色用于图表第二数据系列、渐变与次级强调。页面背景保持中性，不再随主色换肤。")} />
        </div>
        <div class="set-row">
          <div class="info"><div class="name">{$i18n("主题模式")}</div><div class="desc">{$i18n("深色 / 浅色两套完整主题")}</div></div>
          <div class="seg-mini">
            <button class:on={$theme === 'dark'} on:click={() => theme.set('dark')}>{$i18n("深色")}</button>
            <button class:on={$theme === 'light'} on:click={() => theme.set('light')}>{$i18n("浅色")}</button>
          </div>
        </div>
        <div class="set-row">
          <div class="info">
            <div class="name">{$i18n("强调色")}</div>
            <div class="desc">{$i18n("用于主按钮、链接与激活状态 ·")} <span class="ui-current">{uiPairName} · {uiPrimary.toUpperCase()}</span></div>
          </div>
          <div class="ui-swatches">
            {#each Object.entries(ACCENTS) as [key, a]}
              <button type="button" class="ui-swatch" class:on={$uiCfg.accent === key}
                style="--sw:{$theme === 'light' ? a.light : a.dark}"
                title="{a.name} {($theme === 'light' ? a.light : a.dark).toUpperCase()}"
                on:click={() => setUI({ accent: key })}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 13 4 4L19 7"/></svg>
              </button>
            {/each}
            <label class="ui-swatch custom" class:on={$uiCfg.accent === 'custom'} title={$i18n("自定义主色")}>
              <input type="color" value={$uiCfg.customColor} on:input={(e) => setUI({ customColor: e.target.value, accent: 'custom' })} />
            </label>
          </div>
        </div>
        <div class="set-row">
          <div class="info">
            <div class="name">{$i18n("辅助色")}</div>
            <div class="desc">{$i18n("与主色自动搭配 · 用于图表第二系列、渐变与次级强调 ·")} <span class="ui-current">{uiSecName} · {uiSecondary.toUpperCase()}</span></div>
          </div>
          <div class="ui-pair">
            <span class="ui-pair-dot" style="background:{uiPrimary}"></span>
            <span class="ui-pair-plus">+</span>
            <span class="ui-pair-dot" style="background:{uiSecondary}"></span>
          </div>
        </div>
        <div class="form-grid two mt-12">
          <div class="form-group" style="margin-bottom:0">
            <label class="form-label">{$i18n("组件圆角")}</label>
            <div class="range-line">
              <input type="range" min="4" max="20" step="any" value={$uiCfg.radius} on:input={(e) => setUI({ radius: +e.target.value })} />
              <span class="range-val">{Math.round($uiCfg.radius)}px</span>
            </div>
            <div class="tip-text">4 – 20px</div>
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label class="form-label">{$i18n("界面缩放")}</label>
            <div class="range-line">
              <input type="range" min="80" max="120" step="any" value={$uiCfg.scale} on:input={(e) => setUI({ scale: +e.target.value })} />
              <span class="range-val">{Math.round($uiCfg.scale)}%</span>
            </div>
            <div class="tip-text">80% – 120%</div>
          </div>
        </div>
      </div>

      <div class="settings-group bg-card">
        <div class="settings-group-title">{$i18n("背景与材质")}<span class="sub">{$i18n("自定义背景与面板透明度")}</span></div>
        <div class="set-row">
          <div class="info"><div class="name">{$i18n("背景来源")}</div><div class="desc">{$i18n("跟随主题 / 纯色 / 图片")}</div></div>
          <div class="seg-mini">
            <button class:on={$uiCfg.bgType === 'default'} on:click={() => setUI({ bgType: 'default' })}>{$i18n("跟随主题")}</button>
            <button class:on={$uiCfg.bgType === 'color'} on:click={() => setUI({ bgType: 'color' })}>{$i18n("纯色")}</button>
            <button class:on={$uiCfg.bgType === 'image'} on:click={() => setUI({ bgType: 'image' })}>{$i18n("图片")}</button>
          </div>
        </div>
        {#if $uiCfg.bgType === 'color'}
          <div class="form-group">
            <label class="form-label" for="ui-bg-color">{$i18n("背景颜色")}</label>
            <div style="display:flex;align-items:center;gap:10px">
              <input id="ui-bg-color" type="color" value={$uiCfg.bgColor} on:input={(e) => setUI({ bgColor: e.target.value })} style="width:44px;height:32px;padding:2px;border:1px solid var(--bd);border-radius:6px;background:var(--bg2);cursor:pointer" />
              <span class="mono" style="font-size:12px;color:var(--text2)">{$uiCfg.bgColor}</span>
            </div>
          </div>
        {/if}
        {#if $uiCfg.bgType === 'image'}
          <div class="form-group">
            <label class="form-label">{$i18n("背景图片")}</label>
            <input type="text" value={$uiCfg.bgImage} placeholder={$i18n("粘贴图片 URL（https://...）")} on:input={(e) => setUI({ bgImage: e.target.value })} />
            <div style="display:flex;gap:6px;align-items:center;margin-top:8px;flex-wrap:wrap">
              <label class="btn btn-sm" style="cursor:pointer">
                {$i18n("上传本地图片")}
                <input type="file" accept="image/*" style="display:none" on:change={onBgFile} />
              </label>
              {#if $uiCfg.bgImage}
                <button class="btn btn-sm" on:click={() => setUI({ bgImage: '' })}>{$i18n("清除图片")}</button>
              {/if}
            </div>
            <div class="tip-text">{$i18n("建议使用 1920×1080 左右的图片；上传会自动压缩后保存到本地浏览器。")}</div>
          </div>
        {/if}
        <div class="form-grid two mt-12">
          <div class="form-group" style="margin-bottom:0">
            <label class="form-label">{$i18n("面板透明度：")}{Math.round($uiCfg.opacity)}%</label>
            <div class="range-line">
              <input type="range" min="40" max="100" step="any" value={$uiCfg.opacity} on:input={(e) => setUI({ opacity: +e.target.value })} disabled={$uiCfg.bgType === 'default'} />
            </div>
            <div class="tip-text">{$i18n("数值越低，内容面板越透明。")}</div>
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label class="form-label">{$i18n("背景模糊度：")}{Math.round(($uiCfg.blur / 24) * 100)}%</label>
            <div class="range-line">
              <input type="range" min="0" max="24" step="any" value={$uiCfg.blur} on:input={(e) => setUI({ blur: +e.target.value })} disabled={$uiCfg.bgType === 'default'} />
            </div>
            <div class="tip-text">{$i18n("模糊背景图片本身，UI 面板保持清晰。")}</div>
          </div>
        </div>
      </div>

        </div>
        <div class="set-stack">
          <div class="settings-group">
            <div class="settings-group-title">{$i18n("实时预览")}<span class="right"><span class="badge badge-info">{$i18n("当前主题")}</span></span></div>
            <div class="ui-preview">
              <div class="up-card">
                <div class="up-head"><span class="up-title">{$i18n("预览面板")}</span><span class="badge badge-on">{$i18n("在线")}</span></div>
                <div class="up-sub">{$i18n("当前配色、圆角与阴影下的组件效果")}</div>
                <div class="up-bar"><i style="width:64%"></i></div>
                <div class="up-actions">
                  <button class="btn btn-sm btn-primary" type="button">{$i18n("主要操作")}</button>
                  <button class="btn btn-sm" type="button">{$i18n("次要操作")}</button>
                  <span class="up-switch"></span>
                </div>
              </div>
            </div>
          </div>
          <div class="settings-group">
            <div class="settings-group-title">{$i18n("恢复默认")}</div>
            <div class="tip-text" style="line-height:1.6">{$i18n("恢复默认不会修改当前主题的深浅，只重置强调色、圆角与背景。")}</div>
            <button class="btn" style="width:100%;margin-top:12px" on:click={resetUI}>{$i18n("恢复默认外观")}</button>
          </div>
        </div>
      </div>
    </div>
  {/if}

  <!-- ===== 备份 / 恢复 ===== -->
  {#if $settingsSect === 'backup'}
    <div class="section-card">
      <div class="set-cols">
        <div class="set-stack">
      <div class="settings-group">
        <div class="settings-group-title">
          {$i18n("全量备份")}<span class="sub">{$i18n("配置、规则、模块数据")}</span>
          <span class="right">
            <button class="btn btn-sm btn-primary" on:click={() => (showBackupExport = { full: true })}>{@html backupIcon}{$i18n("导出全部")}</button>
          </span>
        </div>
        <div class="tip-text" style="line-height:1.7">{$i18n("导出包含全部模块配置、DNS 账户、WAF 规则与系统参数；不包含日志与流量历史。")}</div>
      </div>

      <div class="settings-group">
        <div class="settings-group-title">
          {$i18n("模块备份")}<span class="sub">{$i18n("选择需要导出的模块")}</span>
          <span class="right">
            <button class="btn btn-sm" on:click={() => (showBackupExport = { full: false })}>{@html backupIcon}{$i18n("导出所选模块")}</button>
          </span>
        </div>
        <div class="tip-text" style="line-height:1.7">{$i18n("在弹窗中勾选要备份的模块，适合只迁移部分功能配置。")}</div>
      </div>

      <div class="settings-group">
        <div class="settings-group-title">{$i18n("恢复配置")}<span class="sub">{$i18n("导入备份文件")}</span></div>
        <label class="drop-zone">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 21V9"/><path d="m7 14 5-5 5 5"/><path d="M4 3h16"/></svg>
          <span>{$i18n("点击选择备份文件")}</span>
          <span class="mono" style="font-size:9px">{$i18n("支持 .zip / .json")}</span>
          <input
            type="file"
            accept=".zip,.json,application/zip,application/json"
            style="display:none"
            bind:this={backupFileInput}
            on:change={onBackupFilePick}
          />
        </label>
        {#if backupFile}
          <div class="bk-file-row">
            <span class="bk-file-name" title={backupFile.name}>{backupFile.name}</span>
            <button class="btn btn-sm" on:click={clearBackupFile}>{$i18n("清除")}</button>
          </div>
        {/if}
        <div class="set-row" style="padding-bottom:0">
          <div class="info"><div class="name">{$i18n("合并模式")}</div><div class="desc">{$i18n("保留现有配置，仅合并备份中的条目")}</div></div>
          <span class="badge badge-on">{$i18n("已启用")}</span>
        </div>
        <button class="btn btn-primary" style="width:100%;margin-top:12px" on:click={() => { if (!backupFile) { toast('请先选择备份文件', 'error'); return; } showBackupRestore = true; }} disabled={!backupFile}>{$i18n("开始恢复")}</button>
        <div class="tip-text" style="margin-top:10px;line-height:1.6">{$i18n("加密备份优先使用设备编号自动解密，失败则提示输入密码；部分系统设置需重启服务完全生效。")}</div>
      </div>
        </div>
        <div class="set-stack">
          <div class="settings-group">
            <div class="settings-group-title">{$i18n("备份说明")}</div>
            <div class="about-row"><span>{$i18n("文件格式")}</span><b>ZIP</b></div>
            <div class="about-row"><span>{$i18n("加密方式")}</span><b>{$i18n("设备 / 密码 / 无")}</b></div>
            <div class="about-row"><span>{$i18n("恢复模式")}</span><b>{$i18n("合并覆盖")}</b></div>
            <div class="about-row"><span>{$i18n("包含内容")}</span><b>{$i18n("配置与规则")}</b></div>
            <div class="tip-text" style="margin-top:12px;line-height:1.7">{$i18n("备份会导出系统设置、自定义 UI、转发规则、FRP 服务器与代理、IP 过滤、域名解析等配置；不包含日志与流量历史。")}</div>
          </div>
          <div class="settings-group">
            <div class="settings-group-title">{$i18n("恢复说明")}</div>
            <div class="about-row"><span>{$i18n("加密检测")}</span><b>{$i18n("自动")}</b></div>
            <div class="about-row"><span>{$i18n("恢复后生效")}</span><b>{$i18n("转发 / FRP 立即")}</b></div>
            <div class="tip-text" style="margin-top:12px;line-height:1.7">{$i18n("恢复采用合并模式：备份中的配置覆盖当前同名配置，当前已有但备份未包含的配置保留。")}</div>
          </div>
        </div>
      </div>
    </div>
  {/if}
</div>

{#if showFrpcUpgrade}
  <FrpcUpgradeModal onClose={() => (showFrpcUpgrade = false)} onUpgraded={() => loadFrpcStatus()} />
{/if}
{#if showBindDns}
  <Modal title={$i18n("添加域名（解析到 frp 服务器）")} onClose={() => (showBindDns = false)} width={480}>
    <div bind:this={bindFormEl}>
    <div class="tip-text" style="margin-bottom:12px;line-height:1.7">{$i18n("选择 DNS 账号与域名，将当前服务器地址「")}{activeSrv.addr}{$i18n("」解析到该域名（添加一条解析记录）。")}</div>
    <div class="form-group">
      <label class="form-label">{$i18n("DNS 账号")}</label>
      <CustomSelect bind:value={bindAccount} options={bindAccounts.map((a) => ({ value: a.name, label: `${a.name}（${a.provider}）` }))} on:change={loadBindDomains} />
    </div>
    <div class="form-group">
      <label class="form-label">{$i18n("域名")}</label>
      <CustomSelect bind:value={bindDomain} options={bindDomains.map((d) => ({ value: d.name, label: d.name }))} />
    </div>
    <div class="form-row">
      <div class="form-group" style="margin-bottom:0;flex:1;min-width:120px">
        <label class="form-label">{$i18n("主机记录")}</label>
        <input type="text" bind:value={bindRR} placeholder={$i18n("@ 表示根域名，如 web")} use:field={{ check: validateRecordName }} />
      </div>
      <div class="form-group" style="margin-bottom:0;width:130px">
        <label class="form-label">{$i18n("记录类型")}</label>
        <CustomSelect bind:value={bindType} options={bindTypeOptions} width="100%" />
      </div>
    </div>
    <div class="form-row">
      <div class="form-group" style="margin-bottom:0;flex:1;min-width:120px">
        <label class="form-label">{$i18n("记录值（服务器地址）")}</label>
        <input type="text" bind:value={bindValue} placeholder={$i18n("frp 服务器 IP 或域名")} use:field={{ check: validateHost }} />
      </div>
      <div class="form-group" style="margin-bottom:0;width:90px">
        <label class="form-label">TTL</label>
        <input type="number" bind:value={bindTTL} min="1" max="86400" />
      </div>
    </div>
    </div>
    <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
      <button class="btn" on:click={() => (showBindDns = false)} disabled={bindBusy}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={submitBindDns} disabled={bindBusy}>{bindBusy ? i18nTr("绑定中…") : i18nTr("绑定到域名")}</button>
    </div>
  </Modal>
{/if}
{#if showAddServer}
  <AddServerModal
    onClose={() => (showAddServer = false)}
    onConfirm={frpcAddServer}
    exists={frpcCfg.servers.map((s) => s.name)}
    busy={addServerBusy}
  />
{/if}
{#if editSrvName}
  <EditServerNameModal
    name={editSrvName}
    exists={frpcCfg.servers.filter((s) => s.name !== editSrvName).map((s) => s.name)}
    isDefault={editSrvName === frpcCfg.active_server}
    onSetDefault={editSrvSetDefault}
    onClose={() => (editSrvName = '')}
    onConfirm={frpcRenameServer}
    busy={editSrvBusy}
  />
{/if}
{#if delServerName}
  <ConfirmModal
    title={$i18n("删除服务器")}
    message={i18nTr("确定删除服务器「") + delServerName + i18nTr("」吗？删除后需重新添加才能使用。")}
    confirmText={$i18n("删除")}
    onConfirm={frpcDelServer}
    onClose={() => (delServerName = '')}
  />
{/if}
{#if frpcConfirm}
  <ConfirmModal
    title={$i18n("操作确认")}
    message={i18nTr("确定要") + (frpcConfirm === 'start' ? i18nTr("启动") : frpcConfirm === 'stop' ? i18nTr("停止") : i18nTr("重启")) + i18nTr(" frpc 客户端吗？")}
    confirmText={$i18n("确定")}
    onConfirm={frpcConfirmAction}
    onClose={() => (frpcConfirm = '')}
  />
{/if}
{#if lanConfirm}
  <ConfirmModal
    title={$i18n("关闭局域网地址放行")}
    message={$i18n("关闭后，局域网内其他设备将无法通过 IP 过滤访问（本机回环地址 127.0.0.1 / localhost 仍固定放行）。确认关闭吗？")}
    confirmText={$i18n("确认关闭")}
    onConfirm={confirmDisableLAN}
    onClose={cancelDisableLAN}
  />
{/if}
{#if delIPFTarget}
  <ConfirmModal
    title={delIPFTarget.kind === 'region' ? i18nTr("移除地区规则") : delIPFTarget.kind === 'black' ? i18nTr("移出黑名单") : i18nTr("移出白名单")}
    message={
      delIPFTarget.kind === 'region'
        ? `确定从${delIPFTarget.list === 'blacklist' ? i18nTr("黑名单") : i18nTr("白名单")}移除地区「${delIPFTarget.reg.name}」吗？${delIPFTarget.list === 'blacklist' ? i18nTr("移除后该地区 IP 将恢复访问。") : i18nTr("若同时启用了黑名单或地区限制，该地区 IP 可能被拦截。")}`
        : delIPFTarget.kind === 'black'
          ? `确定从黑名单移除「${delIPFTarget.ip}」吗？移除后该地址将恢复访问。`
          : `确定从白名单移除「${delIPFTarget.ip}」吗？若同时启用了黑名单或地区限制，该地址可能被拦截。`
    }
    confirmText={$i18n("移除")}
    onConfirm={confirmDelIPF}
    onClose={() => { if (!delIPFBusy) delIPFTarget = null; }}
    busy={delIPFBusy}
  />
{/if}
{#if showClearBlocked}
  <ConfirmModal
    title={$i18n("清空拦截记录")}
    message={$i18n("将清空全部自动记录的被拦截 IP，仅清理历史记录，不影响黑白名单与地区规则。确定清空吗？")}
    confirmText={$i18n("清空")}
    onConfirm={confirmClearBlocked}
    onClose={() => { if (!clearBlockedBusy) showClearBlocked = false; }}
    busy={clearBlockedBusy}
  />
{/if}
{#if showBackupExport}
  <BackupExportModal full={showBackupExport.full} onClose={() => (showBackupExport = null)} />
{/if}
{#if showBackupRestore && backupFile}
  <BackupRestoreModal file={backupFile} onClose={() => (showBackupRestore = false)} />
{/if}
{#if showFrpcCfgFile}
  <Modal title={$i18n("frpc 配置文件（frpc.toml）")} width={780} onClose={() => (showFrpcCfgFile = false)}>
    <div style="font-size:12px;color:var(--text3);margin-bottom:8px;line-height:1.6">
      {#if frpcCfgFileIsActive}{$i18n("当前查看：默认服务器「")}<span style="font-family:var(--mono)">{frpcCfgFileName}</span>{$i18n("」的配置（frpc 当前使用的配置，路径")} <span style="font-family:var(--mono)">{frpcStatus.config_path || '-'}</span>{$i18n("）。\n        保存时将先执行 frpc 语法校验，通过后写入并重启 frpc 立即生效；此后若在页面表单中保存设置，会重新生成该文件。")}{:else}{$i18n("当前查看：服务器「")}<span style="font-family:var(--mono)">{frpcCfgFileName}</span>{$i18n("」的配置（非默认服务器，按该服务器参数实时生成的预览）。\n        保存将写入该服务器独立的原始配置，不影响当前运行的 frpc；将其设为默认服务器后自动启用。")}{/if}
    </div>
    {#if frpcCfgFileLoading}
      <div style="font-size:12px;color:var(--text3);padding:20px;text-align:center">{$i18n("加载中...")}</div>
    {:else}
      <TomlEditor bind:value={frpcCfgFile} minHeight="340px" maxHeight="480px" />
    {/if}
    <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
      <button class="btn" on:click={() => (showFrpcCfgFile = false)} disabled={frpcCfgFileSaving}>{$i18n("关闭")}</button>
      <button class="btn btn-primary" on:click={saveFrpcConfigFile} disabled={frpcCfgFileLoading || frpcCfgFileSaving}>
        {frpcCfgFileSaving ? i18nTr("保存中…") : i18nTr("保存并应用")}
      </button>
    </div>
  </Modal>
{/if}
{#if showGeoModal}
  <GeoModal onClose={() => (showGeoModal = false)} onUpdated={() => { loadGeoStats(); loadGeoSources(); }} />
{/if}
{#if regionPick}
  <Modal title={`从 IP 地址库添加地区（${regionPick.list === 'blacklist' ? i18nTr("黑名单") : i18nTr("白名单")}）`} onClose={() => (regionPick = null)} width={560}>
    <div style="font-size:12px;color:var(--text3);margin-bottom:10px;line-height:1.6">
      {$i18n("选择地区后直接加入")}{regionPick.list === 'blacklist' ? i18nTr("黑名单（该地区访问将被拒绝）") : i18nTr("白名单（该地区访问将被放行）")}{$i18n("，匹配时按访问 IP 的归属地判定。")}
    </div>
    <input type="text" bind:value={regionSearch} placeholder={$i18n("搜索地区名称 / 分类，如 美国 / 广东 / 广州 / 电信")} style="width:100%;box-sizing:border-box;margin-bottom:10px" />
    <div style="max-height:320px;overflow-y:auto;display:flex;flex-direction:column;gap:6px;padding-right:4px">
      {#if regionBusy}
        <div style="font-size:12px;color:var(--text3);padding:16px;text-align:center">{$i18n("加载中...")}</div>
      {:else if geoRegionsError}
        <div style="font-size:12px;color:var(--red);padding:16px;text-align:center;line-height:1.8">
          {geoRegionsError}<br />
          <span style="color:var(--text3)">{$i18n("请先在「IP地址库」页面导入或更新归属地数据。")}</span>
        </div>
      {:else if regionFiltered().length === 0}
        <div style="font-size:12px;color:var(--text3);padding:16px;text-align:center;line-height:1.8">
          {geoRegions.length === 0 ? i18nTr("IP 地址库暂无地区数据，请先在「IP地址库」页面导入或更新归属地数据。") : i18nTr("未找到匹配的地区")}
        </div>
      {:else}
        {#each regionFiltered() as reg}
          <button
            class="region-item"
            on:click={() => addRegion(reg)}
            disabled={regionBusy}
            title={`${reg.label} ${reg.name}：${reg.ranges} 段 / ${regionIPs(reg.ips)} IP`}
          >
            <span class="badge badge-off" style="flex-shrink:0">{reg.label || reg.category}</span>
            <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{reg.name}</span>
            <span style="font-size:11px;color:var(--text3);white-space:nowrap">{reg.ranges} {$i18n("段 ·")} {regionIPs(reg.ips)} IP</span>
          </button>
        {/each}
      {/if}
    </div>
  </Modal>
{/if}

<style>
  /* 面板外壳只作为布局容器，不再画整块大卡片（分区各自成卡） */
  .section-card,
  .settings-page :global(.section-card){background:transparent;border:none;border-radius:0;padding:0;margin:0;box-shadow:none}
  .section-card h3,
  .settings-page :global(.section-card h3){color:var(--text)}
  /* 分区卡片：与演示页的 card-pad 结构一致 */
  .settings-group{background:var(--bg3);border:1px solid var(--bd);border-radius:calc(var(--radius) + 4px);padding:15px 16px;margin-bottom:0;box-shadow:var(--shadow-card)}
  .settings-group-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px;font-size:12.5px;font-weight:600;color:var(--text);letter-spacing:-.01em}
  .settings-group-title .sub{font-size:10.5px;font-weight:400;color:var(--text3);font-family:var(--mono)}
  .settings-group-title .right{margin-left:auto;display:flex;align-items:center;gap:6px}
  /* 标题与 InfoTip 同一行时，标题自身不再额外留白 */
  .settings-group > .form-label-row{align-items:center}
  .settings-group > .form-label-row .settings-group-title{margin-bottom:0}
  /* 两列布局：左主表单、右摘要/预览 */
  .set-cols{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(0,1fr);gap:14px;align-items:start}
  .set-stack{display:flex;flex-direction:column;gap:14px;min-width:0}
  .about-row{display:flex;align-items:baseline;justify-content:space-between;gap:10px;padding:6px 0;font-size:11.5px;color:var(--text3)}
  .about-row+.about-row{border-top:1px solid var(--sep)}
  .about-row b{font-family:var(--mono);font-size:11.5px;font-weight:500;color:var(--text2);text-align:right;word-break:break-all}
  .about-row b.on{color:var(--green)}
  .about-row b.off{color:var(--text3)}
  .preview-field+.preview-field{margin-top:10px}
  .preview-label{font-size:10px;color:var(--text3);margin-bottom:4px}
  .wh-addr{display:flex;align-items:center;gap:6px;padding:7px 9px;background:var(--bg2);border:1px solid var(--bd);border-radius:8px;font-family:var(--mono);font-size:10.5px;color:var(--text2);word-break:break-all}
  .ipdb-stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:10px}
  /* IP 过滤：黑白名单表格与拦截记录 */
  .ipf-empty{padding:14px 0;font-size:12px;color:var(--text3)}
  .ipf-table{margin:0 -16px -15px;border:none;border-radius:0;box-shadow:none;background:transparent}
  .ipf-table table{min-width:520px}
  .ipf-table th{text-align:left;white-space:nowrap}
  .ipf-table td{white-space:nowrap}
  .ipf-table td:first-child{white-space:normal;word-break:break-all}
  .ipf-foot{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 16px 0;border-top:1px solid var(--bd);font-size:10.5px;color:var(--text3);font-family:var(--mono)}
  .ipf-log{display:flex;flex-direction:column}
  .ipf-log-row{display:flex;align-items:center;gap:6px;padding:7px 0;border-bottom:1px solid var(--sep)}
  .ipf-log-row:last-child{border-bottom:none}
  .ipf-log-row .cell-mono{flex:1;min-width:0;word-break:break-all;font-size:11px;color:var(--text2)}
  /* IP 地址库：数据源列表 */
  .geo-src-list{display:flex;flex-direction:column;max-height:300px;overflow-y:auto}
  .geo-src{display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--sep)}
  .geo-src:last-child{border-bottom:none}
  .geo-src-main{flex:1;min-width:0}
  .geo-src-name{font-size:11.5px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .geo-src-sub{font-size:9.5px;color:var(--text3);margin-top:2px;font-family:var(--mono)}
  .geo-src-more{margin-top:8px;font-size:9.5px;color:var(--text3);font-family:var(--mono)}
  .sys-cell{min-width:0;padding:7px 9px;background:var(--bg4);border:1px solid var(--bd);border-radius:calc(var(--radius) + 1px)}
  .sys-cell span{display:block;margin-bottom:2px;font-size:10px;color:var(--text3)}
  .sys-cell b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;font-weight:500;font-family:var(--mono);color:var(--text2)}
  /* 设置行：设计稿的 set-row（左侧说明、右侧控件） */
  .set-row{display:flex;align-items:center;gap:12px;padding:10px 0;min-width:0}
  .set-row+.set-row{border-top:1px solid var(--sep)}
  .settings-group>.set-row:first-of-type{padding-top:0}
  .set-row .info{flex:1;min-width:0}
  .set-row .name{font-size:11.5px;font-weight:600;color:var(--text)}
  .set-row .desc{font-size:10px;color:var(--text3);margin-top:2px;line-height:1.5}
  .ui-current{color:var(--accent);font-family:var(--mono)}
  .seg-mini{display:inline-flex;padding:2px;border:1px solid var(--bd);border-radius:7px;background:var(--bg2);gap:2px;flex-shrink:0}
  .seg-mini button{border:none;background:none;color:var(--text3);font-size:10.5px;padding:3px 8px;border-radius:5px;cursor:pointer;font-family:var(--font);white-space:nowrap}
  .seg-mini button.on{background:var(--bg4);color:var(--text)}
  .ui-swatches{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}
  .ui-swatch{position:relative;width:22px;height:22px;border-radius:50%;border:1px solid rgba(255,255,255,.16);background:var(--sw);color:#07121c;display:grid;place-items:center;cursor:pointer;padding:0;flex-shrink:0;transition:transform .15s}
  .ui-swatch svg{opacity:0;transition:.15s}
  .ui-swatch.on{box-shadow:0 0 0 2px var(--bg3),0 0 0 3px var(--accent)}
  .ui-swatch.on svg{opacity:1}
  .ui-swatch:hover{transform:translateY(-1px) scale(1.06)}
  .ui-swatch.custom{background:conic-gradient(from 0deg,#ff7f8e,#f5b544,#3ddc97,#4dd6ff,#a78bfa,#ff7f8e)}
  .ui-swatch.custom input{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer;border:none;padding:0}
  .ui-pair{display:flex;align-items:center;gap:7px;flex-shrink:0}
  .ui-pair .ui-pair-dot{width:14px;height:14px;border-radius:50%;display:inline-block;box-shadow:0 0 0 1px rgba(255,255,255,.12) inset}
  .ui-pair-plus{font-size:11px;color:var(--text3)}
  .range-line{display:flex;align-items:center;gap:10px;min-width:0}
  .range-line input[type=range]{flex:1;min-width:0;accent-color:var(--accent)}
  .range-val{font-family:var(--mono);font-size:11px;color:var(--text2);min-width:44px;text-align:right}
  .form-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
  .form-grid.two{grid-template-columns:repeat(2,minmax(0,1fr))}
  /* 左列视觉顺序：主题与配色 → 背景与材质 → 导航页 */
  .theme-card{order:1}
  .bg-card{order:2}
  .nav-card{order:3}

  /* 界面预览卡 */
  .ui-preview{background:var(--bg);border:1px solid var(--bd);border-radius:11px;padding:11px}
  .up-card{background:var(--bg3);border:1px solid var(--bd);border-radius:var(--radius);padding:11px}
  .up-head{display:flex;align-items:center;gap:8px;margin-bottom:6px}
  .up-title{font-size:12px;font-weight:600;color:var(--text)}
  .up-head .badge{margin-left:auto}
  .up-sub{font-size:10px;color:var(--text3);margin-bottom:9px}
  .up-bar{height:5px;background:var(--bg4);border-radius:999px;overflow:hidden;margin-bottom:10px}
  .up-bar i{display:block;height:100%;background:var(--accent);border-radius:999px}
  .up-actions{display:flex;align-items:center;gap:6px}
  .up-switch{margin-left:auto;width:26px;height:15px;border-radius:999px;background:var(--accent);position:relative;flex-shrink:0}
  .up-switch::after{content:"";position:absolute;right:2px;top:2px;width:11px;height:11px;border-radius:50%;background:#fff}

  /* 模块管理：卡片网格 */
  .mod-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
  .mod-item{display:flex;align-items:center;justify-content:space-between;gap:12px;min-width:0;padding:10px 12px;background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius)}
  .mod-item.mod-fixed{opacity:.78}
  .mod-info{min-width:0}
  .mod-name{font-size:13px;font-weight:600;color:var(--text)}
  .mod-desc{margin-top:2px;font-size:11.5px;color:var(--text3);line-height:1.5}

  /* 主色 / 辅助色配对展示 */
  .ui-pair-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:12px;padding:8px 10px;background:var(--bg2);border:1px solid var(--bd);border-radius:var(--radius)}
  .ui-pair-dot{width:14px;height:14px;border-radius:50%;flex-shrink:0;box-shadow:0 0 0 1px rgba(255,255,255,.12) inset}
  .ui-pair-name{font-size:11px;color:var(--text2);font-family:var(--mono);white-space:nowrap}
  .ui-pair-plus{font-size:11px;color:var(--text3);padding:0 2px}

  /* 顶部分区 Tabs：横向排列，窄屏可滚动；活动项用滑动下划线指示 */
  .sect-tabs{position:relative;margin-bottom:14px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:2px}
  .sect-tabs-scroll{flex:1;min-width:0;display:flex;gap:1px;overflow-x:auto;position:relative;scrollbar-width:none}
  .sect-tabs-scroll::-webkit-scrollbar{display:none}
  .sect-tabs-arrow{flex:0 0 auto;width:26px;height:26px;display:flex;align-items:center;justify-content:center;border:none;background:none;color:var(--text3);cursor:pointer;padding:0;border-radius:6px;transition:.2s}
  .sect-tabs-arrow:hover{color:var(--text2);background:var(--bg4)}
  .sect-tabs-arrow:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
  .sect-tab{flex:0 0 auto;display:inline-flex;align-items:center;gap:5px;height:42px;padding:0 12px;border:none;background:none;color:var(--text3);font-size:12px;font-weight:500;font-family:var(--font);cursor:pointer;white-space:nowrap;transition:color .2s;border-radius:6px 6px 0 0}
  .sect-tab :global(svg){width:14px;height:14px;flex-shrink:0}
  .sect-tab:hover{color:var(--text2);background:var(--bg4)}
  .sect-tab.active{color:var(--accent);font-weight:600}
  .sect-tab:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
  .sect-tab-bar{position:absolute;left:0;bottom:-1px;height:2px;background:var(--accent);border-radius:1px;pointer-events:none;transition:transform .25s cubic-bezier(.4,0,.2,1),width .25s cubic-bezier(.4,0,.2,1)}

  /* 备份恢复：文件选择区 */
  .drop-zone{display:flex;flex-direction:column;align-items:center;gap:6px;padding:18px 12px;margin-top:2px;border:1px dashed var(--bd);border-radius:10px;background:var(--bg2);color:var(--text3);font-size:10.5px;text-align:center;cursor:pointer}
  .drop-zone svg{opacity:.5}
  .drop-zone:hover{border-color:rgba(var(--accent-rgb),.45);color:var(--text2)}
  .bk-file-row{display:flex;align-items:center;gap:8px;margin-top:8px}
  /* 备份恢复：已选择的备份文件名 */
  .bk-file-name {
    font-size: 12px; color: var(--text3); font-family: var(--mono);
    max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  /* 从 IP 地址库选择地区的列表项 */
  .region-item {
    display: flex; align-items: center; gap: 10px;
    padding: 8px 12px; border: 1px solid var(--bd); border-radius: var(--radius);
    background: var(--bg2); color: var(--text); font-size: 13px; cursor: pointer;
    transition: border-color .15s, background .15s;
  }
  .region-item:hover:not(:disabled) { border-color: var(--accent); background: var(--bg3); }
  .region-item:disabled { opacity: .5; cursor: not-allowed; }

  /* 导航页开关分组：小标题 + 统一卡片网格，标签左 / 开关右对齐 */
  .hook-sec-title {
    font-size: 12px; font-weight: 600; color: var(--text3);
    margin: 16px 0 8px; letter-spacing: .5px;
  }
  .hook-toggle-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 8px;
  }
  .hook-toggle-cell {
    display: flex; align-items: center; justify-content: space-between;
    gap: 10px; padding: 10px 12px;
    background: var(--bg4); border: 1px solid var(--bd);
    border-radius: var(--radius);
  }
  .hook-toggle-label {
    display: flex; align-items: center; gap: 6px;
    font-size: 13px; color: var(--text); min-width: 0;
  }
  .hook-toggle-label span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  /* FPRC 统计卡片：内容（数字/状态）在卡片内水平垂直居中 */
  .stat-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }
  /* 内核升级卡片按钮：颜色与统计卡片（stat-card）统一，悬停反馈 */
  .upgrade-card:hover {
    border-color: rgba(var(--accent-rgb), .5) !important;
    transform: translateY(-1px);
    box-shadow: var(--shadow-xs);
  }
  .upgrade-card:active {
    transform: translateY(0);
  }

  /* ---- Webhook 模板：请求体代码编辑器（高亮层 + 透明 textarea） ---- */
  .code-editor {
    position: relative;
    border: 1px solid var(--bd);
    border-radius: var(--radius);
    background: var(--bg4);
    overflow: hidden;
  }
  .code-editor pre,
  .code-editor textarea {
    margin: 0;
    padding: 10px;
    font-family: var(--mono);
    font-size: 12px;
    line-height: 1.55;
    min-height: 150px;
    max-height: 320px;
    white-space: pre;
    word-break: normal;
    box-sizing: border-box;
    tab-size: 2;
  }
  .code-editor pre {
    overflow: hidden;
    /* 基础文字用主题色而非透明：未命中高亮的字符（输入中的残缺 JSON、空格、普通文本）也始终可见 */
    color: var(--text);
    background: var(--bg4);
  }
  .code-editor textarea {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    background: transparent;
    color: transparent;
    caret-color: var(--text);
    border: none;
    outline: none;
    resize: vertical;
    overflow: auto;
  }
  /* JSON 语法高亮配色（@html 注入的 span 无组件作用域类，需用 :global 才能命中并保留） */
  :global(.jv-k) { color: #7dd3fc; }  /* 键名 */
  :global(.jv-s) { color: #86efac; }  /* 字符串值 */
  :global(.jv-b) { color: #fca5a5; }  /* true/false/null */
  :global(.jv-n) { color: #fdba74; }  /* 数字 */
  :global(.jv-p) { color: #94a3b8; }  /* 标点 */
  /* 亮色主题下改用深色高亮，保证对比度（html[data-theme=light] 由 App 切换）。
     编辑器底色是内层 bg4，故取语义色 token —— 它们对 bg4 与同色相淡底都已按 ≥4.5:1 标定 */
  :global([data-theme="light"] .jv-k) { color: var(--cyan); }
  :global([data-theme="light"] .jv-s) { color: var(--green); }
  :global([data-theme="light"] .jv-b) { color: var(--red); }
  :global([data-theme="light"] .jv-n) { color: var(--orange); }
  :global([data-theme="light"] .jv-p) { color: var(--slate); }

  /* ---- 移动端适配：STUN 配置行 / QUIC 网格 ---- */
  .frpc-stun-row{display:flex;align-items:flex-end;flex-wrap:wrap;justify-content:space-between;gap:14px}
  .frpc-stun-controls{display:flex;flex-wrap:nowrap;gap:14px;align-items:flex-end;justify-content:flex-end}
  .quic-grid{display:flex;gap:8px}
  /* 多服务器独立状态列表 */
  .frpc-server-list{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
  .frpc-server-item{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 12px;background:var(--bg4);border:1px solid var(--bd);border-radius:8px;flex-wrap:wrap}
  /* 窄屏（平板）：两列布局改为单列，避免表单被挤压 */
  @media (max-width:960px){
    .set-cols{grid-template-columns:minmax(0,1fr)}
  }
  @media (max-width:600px){
    /* 页头：标题与操作同排，操作靠右（对齐演示页移动端） */
    .page-hdr{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:start;gap:10px}
    .page-hdr-actions{width:auto;flex-wrap:nowrap}
    .section-card{padding:0}
    .set-cols{grid-template-columns:minmax(0,1fr)}
    .settings-group{padding:14px 15px}
    .settings-group-title{font-size:12px}
    .ipdb-stats{grid-template-columns:repeat(2,minmax(0,1fr))}
    .ipf-table{margin-left:-15px;margin-right:-15px;margin-bottom:-14px}
    .ipf-foot{padding-left:15px;padding-right:15px}
    .set-row{flex-wrap:wrap}
    .ui-swatches{justify-content:flex-start}
    .form-grid,.form-grid.two{grid-template-columns:1fr}
    .mod-grid{grid-template-columns:1fr}
    .sect-tab{height:38px;padding:0 10px;font-size:11.5px}
    .frpc-stun-row{flex-direction:column;align-items:stretch}
    .frpc-stun-row > .form-group{max-width:100%!important;flex-basis:auto!important}
    .frpc-stun-controls{flex-wrap:wrap;justify-content:flex-start}
    .frpc-stun-controls .frpc-stun-ctrl{flex:1 1 100%!important}
    .quic-grid{flex-direction:column}
  }

  /* STUN 服务器行：全局 .form-row 在 ≤960px 会被强制纵向堆叠，导致地址/协议/删除各占一行。
     这行是可重复的「列表项」，窄屏也必须保持单行：地址输入框占剩余宽度，
     协议下拉收窄到内容宽度（108px 足够显示 UDP+TCP），删除按钮保持 44px 触控热区。
     内联 flex/width 特异性高于 class，必须 !important；桌面端（>960px）不进入本规则 */
  @media (max-width:960px){
    .stun-srv-row{flex-direction:row!important;flex-wrap:nowrap;align-items:center;gap:8px}
    .stun-srv-row .form-group{margin-bottom:0}
    .stun-srv-addr{flex:1 1 auto!important;min-width:0!important}
    .stun-srv-proto{flex:0 0 108px!important;width:108px!important;max-width:none!important}
    .stun-srv-row .btn-icon{flex:0 0 44px;margin-left:0}
  }
</style>

