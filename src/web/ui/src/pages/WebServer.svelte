<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // Web 服务：静态站点 / 文件分享 / 反向代理 / 重定向 / 固定文本
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { toast, status } from '../lib/stores.js';
  import { fmtBytes, portWebUrl, pollVisible } from '../lib/utils.js';
  import { qrSvg } from '../lib/qr.js';
  import Toggle from '../components/Toggle.svelte';
  import Modal from '../components/Modal.svelte';
  import ConfirmModal from '../components/ConfirmModal.svelte';

  const TYPES = [
    { id: 'static', label: i18nTr("静态站点"), desc: i18nTr("目录发布为网页或文件直链") },
    { id: 'share', label: i18nTr("文件分享"), desc: i18nTr("分享页 · 预览 · 下载统计") },
    { id: 'proxy', label: i18nTr("反向代理"), desc: i18nTr("多后端 · 负载均衡 · 缓存") },
    { id: 'redirect', label: i18nTr("重定向"), desc: '301 / 302 / 307 / 308' },
    { id: 'text', label: i18nTr("固定文本"), desc: i18nTr("公告 / 维护页 / 状态码") }
  ];
  const TYPE_META = {
    static: { label: i18nTr("静态站点"), cls: 'badge-info' },
    share: { label: i18nTr("文件分享"), cls: 'badge-violet' },
    proxy: { label: i18nTr("反向代理"), cls: 'badge-info' },
    redirect: { label: i18nTr("重定向"), cls: 'badge-warn' },
    text: { label: i18nTr("固定文本"), cls: 'badge-off' }
  };
  const AUTH_OPTIONS = [
    { value: 'none', label: i18nTr("关闭") },
    { value: 'basic', label: i18nTr("Basic 认证") },
    { value: 'web', label: i18nTr("Web 登录") }
  ];
  const IP_OPTIONS = [
    { value: 'off', label: i18nTr("关闭") },
    { value: 'allow', label: i18nTr("白名单") },
    { value: 'deny', label: i18nTr("黑名单") }
  ];
  const GEO_OPTIONS = [
    { value: 'off', label: i18nTr("关闭") },
    { value: 'allow', label: i18nTr("仅允许") },
    { value: 'deny', label: i18nTr("拒绝") }
  ];
  const LB_OPTIONS = [
    { value: 'round_robin', label: i18nTr("轮询（加权）") },
    { value: 'random', label: i18nTr("随机（加权）") },
    { value: 'ip_hash', label: i18nTr("IP Hash（会话保持）") },
    { value: 'least_conn', label: i18nTr("最少连接") }
  ];
  const REDIRECT_OPTIONS = [
    { value: 301, label: i18nTr("301 永久") },
    { value: 302, label: i18nTr("302 临时") },
    { value: 307, label: i18nTr("307 临时（保留方法）") },
    { value: 308, label: i18nTr("308 永久（保留方法）") }
  ];
  const PATH_AUTH_OPTIONS = [
    { value: '', label: i18nTr("继承") },
    { value: 'on', label: i18nTr("必须认证") },
    { value: 'off', label: i18nTr("关闭认证") }
  ];

  let sites = [];
  let httpPort = 18080; // 路径模式统一使用的 HTTP 端口（来自系统默认参数）
  let httpAccessMode = 'ip'; // 路径模式对外访问方式：ip / domain（来自系统设置）
  let httpAccessDomain = ''; // 域名模式使用的访问域名
  let httpAccessIP = ''; // IP 模式使用的访问地址（留空回退本机地址）
  let localIPs = []; // 本机可用作监听出口的 IPv4 列表
  let loading = true;
  let typeFilter = 'all';
  let search = '';

  let view = 'list'; // list | security | stats
  let showForm = false;
  let proxyPane = 'backend';
  let configPane = 'basic';
  let editing = null;
  let form = emptySite('static');
  let saving = false;

  let showLogs = false;
  let logTarget = null;
  let logs = [];
  let logsLoading = false;

  let statsTarget = null;
  let stats = null;
  let statsLoading = false;
  let statsRange = '7';
  let codeMode = 'off';
  let expiryMode = 'permanent';

  let securitySiteId = '';
  let securityPinned = false; // 从配置弹窗进入时锁定站点，不显示站点选择器
  let securityForm = null;
  let securityEvents = [];
  let securityLoading = false;

  let showAccess = false;
  let accessTarget = null;
  let accessLogs = [];
  let accessLoading = false;

  let delTarget = null;
  let deleting = false;

  let showBrowse = false;
  let browse = { path: '', parent: '', entries: [] };
  let browseInput = '';
  let browseError = '';
  let browseLoading = false;

  let bans = [];
  let bansLoading = false;

  $: runningCount = sites.filter((s) => s.running).length;
  $: filtered = sites.filter((s) => {
    if (typeFilter !== 'all' && s.type !== typeFilter) return false;
    const q = search.trim().toLowerCase();
    if (!q) return true;
    return [s.name, s.root, s.redirect_to, s.text, s.share && s.share.subtitle]
      .filter(Boolean).join(' ').toLowerCase().includes(q);
  });
  $: typeCounts = {
    all: sites.length,
    static: sites.filter((s) => s.type === 'static').length,
    share: sites.filter((s) => s.type === 'share').length,
    proxy: sites.filter((s) => s.type === 'proxy').length,
    redirect: sites.filter((s) => s.type === 'redirect').length,
    text: sites.filter((s) => s.type === 'text').length
  };
  $: dirs = browse.entries.filter((e) => e.is_dir);
  $: statsDays = buildStatsDays(stats, statsRange);
  $: configQr = showForm && form.type !== 'proxy' ? qrSvg(publicUrl(form)) : '';
  $: proxyQr = showForm && form.type === 'proxy' ? qrSvg(siteUrl(form)) : '';
  // 分享站点选域名访问时，对外路径固定由 slug 生成（/s/{slug}），并检测与其他分享站点是否重复。
  $: if (form && form.type === 'share') {
    if (form.access_mode === 'path') {
      if (!String(form.share.slug || '').trim()) form.share.slug = autoSlug(form.name);
      const p = '/s/' + form.share.slug;
      if (form.path_prefix !== p) form.path_prefix = p;
    } else if (form.path_prefix) {
      form.path_prefix = '';
    }
  }
  // 监听 IP 候选：本机地址 + 当前已配置地址（兼容旧配置里的任意地址）。
  $: ipOptions = (() => {
    const list = localIPs.slice();
    const addr = String(form.addr || '').trim();
    if (addr && addr !== '0.0.0.0' && !list.includes(addr)) list.push(addr);
    return list;
  })();
  $: shareSlugTaken =
    form.type === 'share' &&
    form.access_mode === 'path' &&
    slugTaken(form.share.slug, form.id);
  // 端口占用提示：检测其他站点、路径模式统一监听与控制台自身端口。
  $: portConflict = portConflictOf(form);
  // 路径模式对外地址：域名模式按 https 443 展示；IP 模式使用配置的访问 IP（留空回退本机）+ 统一端口
  function pathAccess() {
    if (httpAccessMode === 'domain' && httpAccessDomain) {
      return { scheme: 'https', host: httpAccessDomain };
    }
    const host = httpAccessIP || ($status && $status.local_ip) || window.location.hostname;
    const shown = host.includes(':') ? '[' + host + ']' : host;
    return { scheme: 'http', host: shown + ':' + httpPort };
  }
  // 路径模式地址预览：统一端口 / 域名 + 路径前缀
  $: pathPreview = (() => {
    const a = pathAccess();
    const p = '/' + String(form.path_prefix || '').replace(/^\/+|\/+$/g, '');
    return a.scheme + '://' + a.host + (p === '/' ? i18nTr("/<路径>") : p);
  })();
  $: accessErrors = accessLogs.filter((l) => (l.status || 0) >= 400).length;
  $: accessAvgMs = accessLogs.length
    ? Math.round(accessLogs.reduce((a, l) => a + (l.ms || 0), 0) / accessLogs.length)
    : 0;
  // 禁止下载时打包下载无意义；预览可独立关闭（关闭后 /raw 全关，只留文件列表）
  $: if (form.share.disable_download) {
    if (form.share.package_download) form.share.package_download = false;
  }

  // 切换访问方式：路径模式不需要独立端口
  function setAccessMode(mode) {
    form.access_mode = mode;
    if (mode === 'port' && !(form.port > 0)) form.port = defaultPort(form.type);
    // 分享站点切到域名访问时，默认自动生成一个未被占用的路径。
    if (mode === 'path' && form.type === 'share') {
      const cur = String(form.share.slug || '').trim();
      if (!cur || cur === 'share') form.share.slug = autoSlug(form.name);
    }
  }

  // slugTaken 判断访问路径是否已被同域名下的其他分享站点占用。
  function slugTaken(slug, selfId) {
    const v = String(slug || '').trim();
    if (!v) return false;
    return sites.some(
      (s) =>
        s.id !== selfId &&
        s.type === 'share' &&
        s.access_mode === 'path' &&
        String((s.share && s.share.slug) || 'share').trim() === v
    );
  }

  // autoSlug 由分享名称生成可读路径（中文等非 ASCII 名称回退 share），重复时追加序号。
  function autoSlug(name) {
    const base =
      String(name || '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 24) || 'share';
    let slug = base;
    let n = 2;
    while (slugTaken(slug, form && form.id)) {
      slug = base + '-' + n;
      n += 1;
    }
    return slug;
  }

  // portConflictOf 返回端口占用提示：其他站点、路径模式统一监听、控制台自身端口。
  // 监听地址不同（且都不是 0.0.0.0）时同一端口可以共存，不算冲突。
  function portConflictOf(site) {
    if (!site || site.access_mode === 'path') return '';
    const port = Number(site.port);
    if (!port) return '';
    const addr = String(site.addr || '0.0.0.0');
    const adminPort = Number(window.location.port);
    if (adminPort && port === adminPort) return i18nTr("端口 ") + port + i18nTr(" 是 TunHook 控制台端口");
    if (sites.some((s) => s.access_mode === 'path') && port === Number(httpPort)) {
      return i18nTr("端口 ") + port + i18nTr(" 已被路径模式统一监听占用（域名访问共用该端口）");
    }
    const hit = sites.find((s) => {
      if (s.id === site.id || s.access_mode === 'path') return false;
      if (Number(s.port) !== port) return false;
      const other = String(s.addr || '0.0.0.0');
      return other === addr || other === '0.0.0.0' || addr === '0.0.0.0';
    });
    if (hit) return i18nTr("端口 ") + port + i18nTr(" 已被站点「") + hit.name + i18nTr("」占用");
    return '';
  }

  function emptySite(type = 'static') {
    return {
      id: '',
      name: '',
      type,
      addr: '0.0.0.0',
      port: defaultPort(type),
      access_mode: 'port',
      path_prefix: '',
      auto_start: true,
      access_log: true,
      cors: false,
      req_headers: '',
      resp_headers: '',
      root: '',
      index: 'index.html',
      browse: false,
      text: '',
      text_content_type: 'text/plain; charset=utf-8',
      text_status: 200,
      redirect_to: '',
      redirect_code: 302,
      redirect_keep_path: true,
      redirect_keep_query: true,
      proxy: {
        backends: [{ url: '', weight: 1, backup: false }],
        lb_policy: 'round_robin',
        use_backend_host: false,
        skip_tls_verify: false,
        disable_keep_alive: false,
        proxy_protocol: false,
        x_forwarded: true,
        compression: true,
        rate_limit: 0,
        burst: 0,
        max_conns: 0,
        cache_ttl: 0,
        cache_max_mb: 64,
        health_check: { enabled: false, mode: 'http', path: '/', interval: 10, timeout: 3, fails: 3, passes: 2 },
        path_rules: []
      },
      share: {
        slug: type === 'share' ? 'share' : '',
        access_code: '',
        expires_at: '',
        max_downloads: 0,
        per_ip_daily: 0,
        preview: true,
        disable_download: false,
        package_download: false,
        show_downloads: true,
        log_downloads: true,
        office_preview: false,
        subtitle: '',
        description: ''
      },
      security: {
        auth_mode: 'none',
        users: '',
        ip_mode: 'off',
        ip_list: '',
        ip_allow: '',
        trusted_proxies: '',
        path_rules: [],
        fail_limit: 10,
        fail_window: 15,
        auto_ban_minutes: 0,
        geo_mode: 'off',
        geo_countries: ''
      },
      temp_shares: []
    };
  }

  function defaultPort(type) {
    return { static: 8080, share: 8090, proxy: 8100, redirect: 8088, text: 8083 }[type] || 8080;
  }

  function clone(v) {
    return JSON.parse(JSON.stringify(v));
  }

  // 合并后端返回的配置与默认值，避免旧配置缺少嵌套字段
  function mergeSite(site) {
    const base = emptySite(site.type || 'static');
    const out = Object.assign({}, base, clone(site || {}));
    if (out.access_mode !== 'path') out.access_mode = 'port';
    out.path_prefix = out.path_prefix || '';
    out.proxy = Object.assign({}, base.proxy, clone(site.proxy || {}));
    out.proxy.health_check = Object.assign({}, base.proxy.health_check, (site.proxy && site.proxy.health_check) || {});
    out.proxy.backends = clone((site.proxy && site.proxy.backends) || []);
    out.proxy.path_rules = clone((site.proxy && site.proxy.path_rules) || []);
    out.share = Object.assign({}, base.share, clone(site.share || {}));
    out.security = Object.assign({}, base.security, clone(site.security || {}));
    out.security.path_rules = clone((site.security && site.security.path_rules) || []);
    out.temp_shares = clone(site.temp_shares || []);
    return out;
  }

  async function load(first = false) {
    if (first) loading = true;
    try {
      const d = await api('/api/webserver/sites');
      sites = (d && d.sites) || [];
      if (d && d.http_port) httpPort = d.http_port;
      if (d && d.access_mode) httpAccessMode = d.access_mode;
      if (d && d.access_domain != null) httpAccessDomain = d.access_domain;
      if (d && d.access_ip != null) httpAccessIP = d.access_ip;
      if (d && Array.isArray(d.local_ips)) localIPs = d.local_ips;
    } catch (e) {
      if (first) toast(i18nTr("加载 Web 服务失败：") + e.message, 'error');
    }
    loading = false;
  }

  onMount(() => {
    load(true);
    return pollVisible(() => load(false), 5000);
  });

  function typeLabel(t) {
    return (TYPE_META[t] || {}).label || t;
  }
  function typeClass(t) {
    return (TYPE_META[t] || {}).cls || 'badge-off';
  }
  function siteUrl(s) {
    if (s.access_mode === 'path' && s.path_prefix) {
      const a = pathAccess();
      return a.scheme + '://' + a.host + s.path_prefix;
    }
    const host = ($status && $status.local_ip) || window.location.hostname;
    return portWebUrl(s.addr, s.port, host);
  }
  function siteHost(s) {
    if (s.access_mode === 'path') {
      return pathAccess().host;
    }
    return String(s.addr).includes(':') ? '[' + s.addr + ']' : s.addr;
  }
  // 列表 / 详情里的监听信息：路径模式显示前缀，端口模式显示地址:端口
  function listenLabel(s) {
    return s.access_mode === 'path' ? i18nTr("路径 ") + (s.path_prefix || '-') : siteHost(s) + ':' + s.port;
  }
  function authOn(s) {
    return s.security && s.security.auth_mode && s.security.auth_mode !== 'none';
  }
  function authLabel(s) {
    const m = (s.security && s.security.auth_mode) || 'none';
    return m === 'basic' ? 'Basic' : m === 'web' ? i18nTr("Web 登录") : '';
  }
  function shareDl(s) {
    return (s.share_stats && s.share_stats.downloads) || 0;
  }
  function shareBytes(s) {
    return (s.share_stats && s.share_stats.bytes) || 0;
  }
  function proxyHealth(s) {
    const bs = (s.proxy_status && s.proxy_status.backends) || [];
    const configured = (s.proxy && s.proxy.backends) || [];
    const ok = bs.filter((b) => b.healthy).length;
    return { ok, total: bs.length || configured.length };
  }
  function summaryText(s) {
    switch (s.type) {
      case 'share':
        return s.root || '';
      case 'proxy': {
        const b = (s.proxy && s.proxy.backends) || [];
        return b.length ? b.map((x) => x.url).join(' · ') : '';
      }
      case 'redirect':
        return s.redirect_to || '';
      case 'text':
        return (s.text || '').slice(0, 60);
      default:
        return s.root || '';
    }
  }

  function openCreate(type = 'static') {
    editing = null;
    bans = [];
    form = emptySite(type);
    proxyPane = 'backend';
    configPane = 'basic';
    showForm = true;
    syncSharePickers();
  }

  function openEdit(s) {
    editing = s;
    bans = [];
    form = mergeSite(s);
    proxyPane = 'backend';
    configPane = 'basic';
    showForm = true;
    syncSharePickers();
  }

  function switchType(t) {
    if (t === form.type) return;
    selectType(t);
    if (t === 'proxy' && !form.proxy.backends.length) {
      form.proxy.backends = [{ url: '', weight: 1, backup: false }];
    }
    if (t === 'proxy') proxyPane = 'backend';
    if (t === 'share') syncSharePickers();
  }

  function selectType(t) {
    const oldDefault = defaultPort(form.type);
    form.type = t;
    if (!form.port || Number(form.port) === oldDefault) form.port = defaultPort(t);
    if (t === 'share' && !form.share.slug) form.share.slug = 'share';
    configPane = 'basic';
  }

  function buildPayload(src) {
    const payload = clone(src);
    payload.port = Number(payload.port);
    payload.text_status = Number(payload.text_status) || 200;
    payload.redirect_code = Number(payload.redirect_code) || 302;
    payload.proxy.rate_limit = Number(payload.proxy.rate_limit) || 0;
    payload.proxy.burst = Number(payload.proxy.burst) || 0;
    payload.proxy.max_conns = Number(payload.proxy.max_conns) || 0;
    payload.proxy.cache_ttl = Number(payload.proxy.cache_ttl) || 0;
    payload.proxy.cache_max_mb = Number(payload.proxy.cache_max_mb) || 64;
    payload.proxy.backends = (payload.proxy.backends || [])
      .filter((b) => (b.url || '').trim())
      .map((b) => ({ url: b.url.trim(), weight: Number(b.weight) || 1, backup: !!b.backup }));
    payload.proxy.health_check.interval = Number(payload.proxy.health_check.interval) || 10;
    payload.proxy.health_check.timeout = Number(payload.proxy.health_check.timeout) || 3;
    payload.proxy.health_check.fails = Number(payload.proxy.health_check.fails) || 3;
    payload.proxy.health_check.passes = Number(payload.proxy.health_check.passes) || 2;
    payload.proxy.path_rules = (payload.proxy.path_rules || [])
      .filter((r) => (r.pattern || '').trim() && (r.to || '').trim())
      .map((r) => ({ pattern: r.pattern.trim(), to: r.to.trim(), redirect: !!r.redirect, code: Number(r.code) || 302 }));
    payload.share.max_downloads = Number(payload.share.max_downloads) || 0;
    payload.share.per_ip_daily = Number(payload.share.per_ip_daily) || 0;
    payload.security.fail_limit = Number(payload.security.fail_limit) || 10;
    payload.security.fail_window = Number(payload.security.fail_window) || 15;
    payload.security.auto_ban_minutes = Number(payload.security.auto_ban_minutes) || 0;
    payload.security.path_rules = (payload.security.path_rules || []).filter((r) => (r.prefix || '').trim());
    payload.temp_shares = (payload.temp_shares || []).map((t) => ({
      ...t,
      max_uses: Number(t.max_uses) || 0,
      used: Number(t.used) || 0
    }));
    return payload;
  }

  async function save() {
    const err = validateForm();
    if (err) {
      toast(err, 'error');
      return;
    }
    const wasEdit = !!editing;
    saving = true;
    try {
      const d = await api('/api/webserver/sites', { method: 'POST', body: buildPayload(form) });
      showForm = false;
      await load();
      if (d && d.site && d.site.error) toast(i18nTr("站点已保存，但启动失败：") + d.site.error, 'error');
      else toast(wasEdit ? i18nTr("站点已更新") : i18nTr("站点已创建并启动"), 'success');
    } catch (e) {
      toast(i18nTr("保存失败：") + e.message, 'error');
    } finally {
      saving = false;
    }
  }

  async function saveSecurity() {
    if (await persistSecurity()) toast(i18nTr("安全设置已保存"), 'success');
  }

  // persistSecurity 只负责保存与刷新；放行等快捷操作复用同一套保存逻辑。
  async function persistSecurity() {
    if (!securityForm) return false;
    const err = validateFormFor(securityForm);
    if (err) {
      toast(err, 'error');
      return false;
    }
    saving = true;
    try {
      await api('/api/webserver/sites', { method: 'POST', body: buildPayload(securityForm) });
      await load();
      const updated = sites.find((s) => s.id === securityForm.id);
      if (updated) securityForm = mergeSite(updated);
      loadBans(securityForm.id);
      loadSecurityEvents(securityForm.id);
      return true;
    } catch (e) {
      toast(i18nTr("保存失败：") + e.message, 'error');
      return false;
    } finally {
      saving = false;
    }
  }

  // allowIP 把 IP 加入放行名单：跳过 IP 黑白名单、地区过滤与自动封禁，
  // 但不会改变当前黑白名单模式，也不影响其他访客。
  async function allowIP(ip) {
    if (!securityForm || !ip) return;
    const sec = securityForm.security;
    const prevList = sec.ip_allow;
    const lines = String(sec.ip_allow || '')
      .split('\n')
      .map((v) => v.trim())
      .filter(Boolean);
    if (!lines.includes(ip)) lines.push(ip);
    sec.ip_allow = lines.join('\n');
    if (await persistSecurity()) {
      toast(i18nTr("已放行 ") + ip, 'success');
    } else {
      // 保存失败时回滚，避免界面显示的放行名单与实际配置不一致。
      sec.ip_allow = prevList;
    }
  }

  function validateFormFor(site) {
    const sec = site.security || {};
    if (sec.auth_mode !== 'none' && !String(sec.users || '').trim()) return i18nTr("开启认证时至少填写一个用户");
    if (sec.ip_mode !== 'off' && !String(sec.ip_list || '').trim()) return i18nTr("开启 IP 访问控制时请填写 IP 列表");
    if (sec.geo_mode !== 'off' && !String(sec.geo_countries || '').trim()) return i18nTr("开启国家过滤时请填写国家代码");
    return '';
  }

  function validateForm() {
    if (!String(form.name || '').trim()) return i18nTr("请输入服务名称");
    if (form.access_mode === 'path') {
      // 分享站点的路径前缀由访问路径自动生成（/s/{slug}），无需手动填写。
      if (form.type !== 'share') {
        const p = String(form.path_prefix || '').trim();
        if (!p || p === '/') return i18nTr("路径模式请填写非根路径前缀，例如 /docs");
        if (!p.startsWith('/')) return i18nTr("路径前缀需以 / 开头");
      }
    } else {
      const port = Number(form.port);
      if (!port || port < 1 || port > 65535) return i18nTr("端口范围应为 1-65535");
      if (!String(form.addr || '').trim()) return i18nTr("请输入监听地址");
      if (portConflict) return portConflict;
    }
    if (form.type === 'static' || form.type === 'share') {
      if (!String(form.root || '').trim()) return i18nTr("请选择站点目录");
    }
    if (form.type === 'redirect' && !String(form.redirect_to || '').trim()) return i18nTr("请输入重定向目标");
    if (form.type === 'share') {
      const slug = String(form.share.slug || '').trim();
      if (!slug) return i18nTr("请填写访问路径");
      if (!/^[A-Za-z0-9._-]{1,32}$/.test(slug)) return i18nTr("访问路径只能包含字母、数字、-、_、.，最长 32 位");
      if (form.access_mode === 'path' && shareSlugTaken) return i18nTr("访问路径已被其他分享站点使用，请换一个");
    }
    if (form.type === 'proxy') {
      const bs = (form.proxy.backends || []).filter((b) => (b.url || '').trim());
      if (!bs.length) return i18nTr("反向代理至少需要一个后端地址");
      for (const b of bs) {
        if (!/^https?:\/\//i.test(b.url.trim())) return i18nTr("后端地址需以 http:// 或 https:// 开头");
      }
    }
    const sec = form.security || {};
    if (sec.auth_mode !== 'none' && !String(sec.users || '').trim()) return i18nTr("开启认证时至少填写一个用户");
    if (sec.ip_mode !== 'off' && !String(sec.ip_list || '').trim()) return i18nTr("开启 IP 访问控制时请填写 IP 列表");
    if (sec.geo_mode !== 'off' && !String(sec.geo_countries || '').trim()) return i18nTr("开启国家过滤时请填写国家代码");
    return '';
  }

  async function toggleSite(s) {
    const action = s.running ? 'stop' : 'start';
    try {
      await api('/api/webserver/sites/' + encodeURIComponent(s.id) + '/' + action, { method: 'POST' });
      await load();
      toast(s.running ? i18nTr("服务已停止") : i18nTr("服务已启动"), 'success');
    } catch (e) {
      toast((s.running ? i18nTr("停止失败：") : i18nTr("启动失败：")) + e.message, 'error');
      await load();
    }
  }

  async function confirmDelete() {
    deleting = true;
    try {
      await api('/api/webserver/sites/' + encodeURIComponent(delTarget.id), { method: 'DELETE' });
      toast(i18nTr("服务已删除：") + delTarget.name, 'success');
      delTarget = null;
      await load();
    } catch (e) {
      toast(i18nTr("删除失败：") + e.message, 'error');
    } finally {
      deleting = false;
    }
  }

  async function openLogs(s) {
    logTarget = s;
    logs = [];
    showLogs = true;
    await refreshLogs();
  }
  async function refreshLogs() {
    if (!logTarget) return;
    logsLoading = true;
    try {
      const d = await api('/api/webserver/sites/' + encodeURIComponent(logTarget.id) + '/logs');
      logs = ((d && d.logs) || []).slice().reverse();
    } catch (e) {
      toast(i18nTr("读取访问日志失败：") + e.message, 'error');
    } finally {
      logsLoading = false;
    }
  }
  async function clearLogs() {
    if (!logTarget) return;
    try {
      await api('/api/webserver/sites/' + encodeURIComponent(logTarget.id) + '/logs', { method: 'DELETE' });
      logs = [];
      toast(i18nTr("访问日志已清空"), 'success');
    } catch (e) {
      toast(i18nTr("清空失败：") + e.message, 'error');
    }
  }

  async function openStats(s) {
    statsTarget = s;
    stats = null;
    view = 'stats';
    statsLoading = true;
    try {
      stats = await api('/api/webserver/sites/' + encodeURIComponent(s.id) + '/share/stats');
    } catch (e) {
      toast(i18nTr("读取分享统计失败：") + e.message, 'error');
    } finally {
      statsLoading = false;
    }
  }

  function exportStats() {
    if (!stats) return;
    const rows = [[i18nTr("文件"), i18nTr("下载次数"), i18nTr("流量(bytes)"), i18nTr("最近下载")]];
    statsFiles().forEach((f) => rows.push([f.path, f.downloads, f.bytes || 0, f.last || '']));
    rows.push([]);
    rows.push([i18nTr("时间"), i18nTr("文件"), 'IP', i18nTr("流量(bytes)")]);
    (stats.recent || []).forEach((r) => rows.push([r.time, r.file, r.ip, r.bytes || 0]));
    const csv = rows.map((r) => r.map((v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (statsTarget ? statsTarget.name : 'share') + '-stats.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function openSecurity(id, pinned = false) {
    const s = sites.find((x) => x.id === id) || sites[0];
    securityPinned = pinned;
    view = 'security';
    if (!s) {
      securityForm = null;
      securitySiteId = '';
      bans = [];
      securityEvents = [];
      return;
    }
    securitySiteId = s.id;
    securityForm = mergeSite(s);
    loadBans(s.id);
    loadSecurityEvents(s.id);
  }

  async function loadSecurityEvents(id) {
    securityLoading = true;
    try {
      const d = await api('/api/webserver/sites/' + encodeURIComponent(id) + '/logs');
      securityEvents = ((d && d.logs) || [])
        .filter((l) => l.kind === 'crawler' || [401, 403, 429].includes(Number(l.status)))
        .slice()
        .reverse()
        .slice(0, 20);
    } catch (e) {
      securityEvents = [];
    } finally {
      securityLoading = false;
    }
  }

  function publicUrl(s) {
    if (!s) return '';
    const base = siteUrl(s);
    // 域名（路径）模式下 path_prefix 已经是 /s/{slug}，不能再拼一次。
    if (s.type === 'share') return s.access_mode === 'path' ? base : base + '/s/' + ((s.share && s.share.slug) || 'share');
    return base;
  }

  function proxyBackendRows() {
    if (editing && editing.proxy_status && editing.proxy_status.backends && editing.proxy_status.backends.length) {
      return editing.proxy_status.backends;
    }
    return ((form.proxy && form.proxy.backends) || []).map((b) => ({
      url: b.url,
      weight: b.weight || 1,
      backup: !!b.backup,
      healthy: false,
      paused: false,
      active: 0,
      configured: true
    }));
  }

  async function openAccess(s) {
    accessTarget = s;
    accessLogs = [];
    showAccess = true;
    await refreshAccess();
  }
  async function refreshAccess() {
    if (!accessTarget) return;
    accessLoading = true;
    try {
      const d = await api('/api/webserver/sites/' + encodeURIComponent(accessTarget.id) + '/logs');
      accessLogs = ((d && d.logs) || []).slice().reverse();
      const cur = sites.find((x) => x.id === accessTarget.id);
      if (cur) accessTarget = cur;
    } catch (e) {
      toast(i18nTr("读取访问记录失败：") + e.message, 'error');
    } finally {
      accessLoading = false;
    }
  }
  async function clearAccess() {
    if (!accessTarget) return;
    try {
      await api('/api/webserver/sites/' + encodeURIComponent(accessTarget.id) + '/logs', { method: 'DELETE' });
      accessLogs = [];
      toast(i18nTr("访问记录已清空"), 'success');
    } catch (e) {
      toast(i18nTr("清空失败：") + e.message, 'error');
    }
  }
  function buildStatsDays(data, range) {
    const out = [];
    const now = new Date();
    const n = range === 'today' ? 1 : range === '30' || range === 'all' ? 30 : 7;
    for (let i = n - 1; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 86400000);
      const key = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
      out.push({ key, label: key.slice(5), value: (data && data.daily && data.daily[key]) || 0 });
    }
    return out;
  }
  function statsMax() {
    return Math.max(1, ...statsDays.map((d) => d.value));
  }
  function statsPeak() {
    let peak = 0;
    let label = '-';
    statsDays.forEach((d) => {
      if (d.value > peak) {
        peak = d.value;
        label = d.label;
      }
    });
    return { peak, label };
  }
  function statsRangeTotal() {
    return statsDays.reduce((a, d) => a + d.value, 0);
  }
  function statsFiles() {
    if (!stats || !stats.files) return [];
    return Object.entries(stats.files).map(([path, v]) => ({ path, ...v })).sort((a, b) => b.downloads - a.downloads);
  }
  function statsFileMax() {
    const f = statsFiles();
    return Math.max(1, f.length ? f[0].downloads : 1);
  }
  function statsLast() {
    if (!stats) return { time: '', file: '' };
    if (stats.last_time) return { time: stats.last_time, file: stats.last_file || '' };
    const r = (stats.recent || [])[0];
    return r ? { time: r.time, file: r.file } : { time: '', file: '' };
  }
  function shortClock(t) {
    return String(t || '').slice(11);
  }
  function typeTone(t) {
    return { static: 'cyan', share: 'violet', proxy: 'blue', redirect: 'orange', text: 'slate' }[t] || 'slate';
  }
  function setCodeMode(mode) {
    codeMode = mode;
    if (mode === 'off') form.share.access_code = '';
    if (mode === 'auto') {
      const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      let code = '';
      for (let i = 0; i < 4; i++) code += alphabet[Math.floor(Math.random() * alphabet.length)];
      form.share.access_code = code;
    }
  }
  function setExpiryMode(mode) {
    expiryMode = mode;
    if (mode === 'permanent') {
      form.share.expires_at = '';
      return;
    }
    if (mode === '7' || mode === '30') {
      const d = new Date(Date.now() + (mode === '7' ? 7 : 30) * 86400000);
      form.share.expires_at = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0') + ' 23:59:59';
    }
  }
  function syncSharePickers() {
    codeMode = form.share.access_code ? 'custom' : 'off';
    expiryMode = form.share.expires_at ? 'custom' : 'permanent';
  }

  function openBrowse() {
    showBrowse = true;
    loadBrowse(String(form.root || '').trim() || '/');
  }
  async function loadBrowse(p) {
    browseLoading = true;
    browseError = '';
    try {
      const d = await api('/api/webserver/browse?path=' + encodeURIComponent(p || '/'));
      browse = { path: d.path, parent: d.parent || '', entries: d.entries || [] };
      browseInput = d.path;
    } catch (e) {
      browseError = e.message;
    } finally {
      browseLoading = false;
    }
  }
  function chooseDir() {
    form.root = browse.path;
    showBrowse = false;
  }

  async function loadBans(id) {
    bansLoading = true;
    try {
      const d = await api('/api/webserver/sites/' + encodeURIComponent(id) + '/bans');
      bans = (d && d.bans) || [];
    } catch (e) {
      bans = [];
    } finally {
      bansLoading = false;
    }
  }
  async function unban(ip) {
    const sid = (securityForm && securityForm.id) || (editing && editing.id);
    if (!sid) return;
    try {
      await api('/api/webserver/sites/' + encodeURIComponent(sid) + '/bans?ip=' + encodeURIComponent(ip), { method: 'DELETE' });
      bans = bans.filter((b) => b.ip !== ip);
      toast(i18nTr("已解除封禁：") + ip, 'success');
    } catch (e) {
      toast(i18nTr("解封失败：") + e.message, 'error');
    }
  }

  function addBackend() {
    form.proxy.backends = [...form.proxy.backends, { url: '', weight: 1, backup: false }];
  }
  function removeBackend(i) {
    form.proxy.backends = form.proxy.backends.filter((_, idx) => idx !== i);
  }
  function addProxyRule() {
    form.proxy.path_rules = [...form.proxy.path_rules, { pattern: '', to: '', redirect: false, code: 302 }];
  }
  function removeProxyRule(i) {
    form.proxy.path_rules = form.proxy.path_rules.filter((_, idx) => idx !== i);
  }
  function addSecurityRule(target) {
    target.security.path_rules = [...target.security.path_rules, { prefix: '', auth_mode: '', ip_mode: '', ip_list: '' }];
  }
  function removeSecurityRule(target, i) {
    target.security.path_rules = target.security.path_rules.filter((_, idx) => idx !== i);
  }
  function addTempShare(target) {
    target.temp_shares = [...target.temp_shares, {
      id: '', name: '', token: '', expires_at: '', max_uses: 0, used: 0, path_prefix: '', created_at: ''
    }];
  }
  function removeTempShare(target, i) {
    target.temp_shares = target.temp_shares.filter((_, idx) => idx !== i);
  }

  function copyText(text, label = i18nTr("链接")) {
    navigator.clipboard.writeText(text)
      .then(() => toast(i18nTr("已复制") + label + '：' + text, 'success'))
      .catch(() => toast(i18nTr("复制失败"), 'error'));
  }
  function copySiteLink(s) {
    copyText(publicUrl(s), i18nTr("地址"));
  }
  function copyTempShare(s, t) {
    if (!t.token) {
      toast(i18nTr("请先保存站点，保存后生成分享链接"), 'error');
      return;
    }
    copyText(siteUrl(s) + '?_gs=' + t.token, i18nTr("临时链接"));
  }
  function targetHost(s) {
    return s.addr === '0.0.0.0' || s.addr === '::' ? '127.0.0.1' : s.addr;
  }
  function statusTone(code) {
    if (code >= 500) return 'ws-red';
    if (code >= 400) return 'ws-amber';
    return '';
  }
  function typeIcon(t) {
    switch (t) {
      case 'static': return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18"/></svg>';
      case 'share': return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 5a2 2 0 0 1 2-2h5l2 2h5a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/><path d="M12 10v5M9.5 12.5h5"/></svg>';
      case 'proxy': return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 12h7M13 12h7M8 8l-4 4 4 4M16 8l4 4-4 4"/></svg>';
      case 'redirect': return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 4h6v6M20 4l-8 8"/><path d="M10 5H5a1 1 0 0 0-1 1v13a1 1 0 0 0 1 1h13a1 1 0 0 0 1-1v-5"/></svg>';
      default: return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 3h9l4 4v14H6z"/><path d="M9 12h7M9 16h7M9 8h3"/></svg>';
    }
  }
</script>

{#if view === 'list'}
<div class="container page-list">
  <div class="page-hdr">
    <div>
      <h2>{$i18n("Web 服务")}</h2>
      <span class="page-hdr-sub">{$i18n("静态站点 · 文件分享 · 反向代理 · 重定向 · 固定文本 ·")} {sites.length} {$i18n("个服务 ·")} {runningCount} {$i18n("个运行中")}</span>
    </div>
    <div class="page-hdr-actions">
      <button class="btn" on:click={() => openSecurity(securitySiteId || (sites[0] && sites[0].id))} title={$i18n("安全与分享")}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>
        <span class="sm-hide">{$i18n("安全")}</span>
      </button>
      <button class="btn" on:click={() => load(false)} disabled={loading} title={$i18n("刷新")}>
        <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><path d="M42 24C42 33.9411 33.9411 42 24 42C14.0589 42 6 33.9411 6 24C6 14.0589 14.0589 6 24 6C30.675 6 36.5033 9.63077 39.5 15"/><path d="M42 6V18H30"/></svg>
        <span class="sm-hide">{$i18n("刷新")}</span>
      </button>
      <button class="btn btn-primary" on:click={() => openCreate('static')}>
        <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="24" r="20"/><path d="M24 16V32"/><path d="M16 24H32"/></svg>
        <span class="sm-hide">{$i18n("新建服务")}</span>
      </button>
    </div>
  </div>

  <div class="ws-console-types">
    {#each TYPES as t (t.id)}
      <button class="ws-console-type t-{typeTone(t.id)}" on:click={() => openCreate(t.id)}>
        <span class="ws-console-ico">{@html typeIcon(t.id)}</span>
        <span class="ws-console-text"><b>{t.label}</b><span>{t.desc}</span></span>
        <svg class="ws-console-arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg>
      </button>
    {/each}
  </div>

  <div class="ws-filter-bar">
    <div class="chips">
      <button class="chip" class:active={typeFilter === 'all'} on:click={() => (typeFilter = 'all')}>{$i18n("全部")} <em>{typeCounts.all}</em></button>
      {#each TYPES as t (t.id)}
        <button class="chip" class:active={typeFilter === t.id} on:click={() => (typeFilter = t.id)}>{t.label} <em>{typeCounts[t.id]}</em></button>
      {/each}
    </div>
    <div class="hdr-search-wrap">
      <svg class="hdr-search-icon" width="15" height="15" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M21 38C30.3888 38 38 30.3888 38 21C38 11.6112 30.3888 4 21 4C11.6112 4 4 11.6112 4 21C4 30.3888 11.6112 38 21 38Z"/><path d="M33.2216 33.2217L41.7069 41.707" stroke-linecap="round"/></svg>
      <input type="text" class="hdr-search" bind:value={search} placeholder={$i18n("搜索名称 / 地址 / 目录")} />
    </div>
  </div>

  {#if loading}
    <div class="empty"><div class="empty-t">{$i18n("加载中…")}</div></div>
  {:else if !filtered.length}
    <div class="ws-card">
      <div class="empty">
        <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" style="margin:0 auto 12px;display:block;color:var(--text3)"><rect x="2.5" y="4" width="19" height="16" rx="2"/><path d="M2.5 9h19"/><circle cx="5.5" cy="6.5" r=".6"/><circle cx="7.8" cy="6.5" r=".6"/></svg>
        <div class="empty-t">{sites.length ? i18nTr("没有匹配的服务") : i18nTr("还没有 Web 服务，新建一个静态站点或文件分享开始")}</div>
        <button class="btn btn-primary btn-sm" style="margin-top:12px" on:click={() => openCreate('static')}>{$i18n("新建服务")}</button>
      </div>
    </div>
  {:else}
    <div class="table-wrap ws-table">
      <table>
        <thead>
          <tr>
            <th style="width:82px">{$i18n("状态")}</th>
            <th style="width:190px">{$i18n("服务")}</th>
            <th style="width:88px">{$i18n("类型")}</th>
            <th style="width:210px">{$i18n("入口地址")}</th>
            <th>{$i18n("目标 / 目录 / 内容")}</th>
            <th style="width:104px">{$i18n("统计")}</th>
            <th style="width:96px">{$i18n("流量")}</th>
            <th style="width:232px">{$i18n("操作")}</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as s (s.id)}
            <tr>
              <td>
                <span class="ws-state"><span class="dot" class:on={s.running}></span>{s.running ? i18nTr("运行中") : i18nTr("已停止")}</span>
                {#if s.error && !s.running}<span class="badge badge-error ws-err-badge" title={s.error}>{$i18n("启动失败")}</span>{/if}
              </td>
              <td>
                <div class="ws-name">{s.name}</div>
                <div class="ws-sub">{typeLabel(s.type)}{#if s.auto_start} {$i18n("· 自启")}{/if}</div>
                {#if s.error && !s.running}<div class="ws-error" title={s.error}>{s.error}</div>{/if}
              </td>
              <td><span class="badge {typeClass(s.type)}">{typeLabel(s.type)}</span></td>
              <td>
                <a class="ws-url" class:off={!s.running} href={publicUrl(s)} target="_blank" rel="noopener noreferrer" title={$i18n("打开 {0}", [publicUrl(s)])}>{publicUrl(s).replace(/^http:\/\//, '')}</a>
                <div class="ws-sub mono">{listenLabel(s)}</div>
              </td>
              <td>
                <div class="ws-target mono" title={summaryText(s)}>{summaryText(s) || '-'}</div>
                <div class="ws-badges">
                  {#if s.type === 'static' || s.type === 'share'}
                    {#if s.browse}<span class="badge badge-info">{$i18n("目录浏览")}</span>{/if}
                    {#if s.index && s.type === 'static'}<span class="badge badge-off">{s.index}</span>{/if}
                  {/if}
                  {#if s.type === 'share' && s.share}
                    {#if s.share.access_code}<span class="badge badge-violet">{$i18n("提取码")} {s.share.access_code}</span>{/if}
                    {#if s.share.disable_download}<span class="badge badge-warn">{$i18n("禁止下载")}</span>{/if}
                    {#if s.share.expires_at}<span class="badge badge-warn">{s.share.expires_at} {$i18n("到期")}</span>{/if}
                  {/if}
                  {#if s.type === 'proxy' && s.proxy}
                    <span class="badge badge-info">{(s.proxy.backends || []).length} {$i18n("后端")}</span>
                    {#if s.proxy.compression}<span class="badge badge-off">gzip</span>{/if}
                    {#if s.proxy.cache_ttl > 0}<span class="badge badge-off">{$i18n("缓存")} {s.proxy.cache_ttl}s</span>{/if}
                  {/if}
                  {#if s.type === 'redirect'}
                    <span class="badge badge-warn">{s.redirect_code || 302}</span>
                    {#if s.redirect_keep_path}<span class="badge badge-off">{$i18n("保留路径")}</span>{/if}
                    {#if s.redirect_keep_query}<span class="badge badge-off">{$i18n("保留查询")}</span>{/if}
                  {/if}
                  {#if s.type === 'text'}
                    <span class="badge badge-off">{s.text_content_type || 'text/plain'}</span>
                    <span class="badge badge-info">HTTP {s.text_status || 200}</span>
                  {/if}
                  {#if authOn(s)}<span class="badge badge-warn">{authLabel(s)}</span>{/if}
                  {#if authOn(s) && (s.temp_shares || []).length}<span class="badge badge-violet">{$i18n("临时链接")}</span>{/if}
                </div>
              </td>
              <td>
                {#if s.type === 'share'}
                  <div class="ws-stat"><b>{shareDl(s)}</b></div>
                {:else if s.type === 'proxy'}
                  <div class="ws-stat"><b>{s.requests || 0}</b> {$i18n("次请求")}<i>{proxyHealth(s).ok}/{proxyHealth(s).total} {$i18n("后端健康")}</i></div>
                {:else}
                  <div class="ws-stat"><b>{s.requests || 0}</b> {$i18n("次请求")}</div>
                {/if}
              </td>
              <td>
                <div class="ws-stat"><b>{s.type === 'share' ? fmtBytes(shareBytes(s)) : fmtBytes(s.bytes || 0)}</b></div>
              </td>
              <td>
                <div class="cell-actions">
                  <button class="btn-icon" title={s.running ? i18nTr("停止") : i18nTr("启动")} aria-label={s.running ? i18nTr("停止") : i18nTr("启动")} on:click={() => toggleSite(s)}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={s.running ? 'var(--green)' : 'var(--text3)'} stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v9"/><path d="M6.4 6.4a8 8 0 1 0 11.2 0"/></svg>
                  </button>
                  <button class="btn-icon" title={$i18n("访问日志")} aria-label={$i18n("访问日志")} on:click={() => openLogs(s)}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h9l4 4v14H6z"/><path d="M9 12h7M9 16h7M9 8h3"/></svg>
                  </button>
                  {#if s.type === 'share'}
                    <button class="btn-icon" title={$i18n("分享统计")} aria-label={$i18n("分享统计")} on:click={() => openStats(s)}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/></svg>
                    </button>
                  {:else}
                    <button class="btn-icon" title={$i18n("访问记录")} aria-label={$i18n("访问记录")} on:click={() => openAccess(s)}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/></svg>
                    </button>
                    <button class="btn-icon" title={$i18n("复制地址")} aria-label={$i18n("复制地址")} on:click={() => copySiteLink(s)}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
                    </button>
                  {/if}
                  <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑")} on:click={() => openEdit(s)}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h4L20 8l-4-4L4 16z"/></svg>
                  </button>
                  <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => (delTarget = s)}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14"/></svg>
                  </button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    <!-- 移动端卡片 -->
    <div class="list-cards">
      {#each filtered as s (s.id)}
        <div class="list-card">
          <div class="list-card-top">
            <span class="ws-state"><span class="dot" class:on={s.running}></span>{s.running ? i18nTr("运行中") : i18nTr("已停止")}</span>
            <span class="badge {typeClass(s.type)}">{typeLabel(s.type)}</span>
            <b class="list-card-title ellip" style="margin-left:auto">{s.name}</b>
          </div>
          <a class="ws-url" class:off={!s.running} href={publicUrl(s)} target="_blank" rel="noopener noreferrer">{publicUrl(s).replace(/^http:\/\//, '')}</a>
          <div class="ws-target mono ellip" title={summaryText(s)}>{summaryText(s) || '-'}</div>
          <div class="ws-badges">
            {#if s.type === 'share'}
              <span class="badge badge-violet">{shareDl(s)} {$i18n("次下载")}</span>
              <span class="badge badge-off">{fmtBytes(shareBytes(s))} {$i18n("流量")}</span>
              {#if s.share && s.share.access_code}<span class="badge badge-warn">{$i18n("提取码")}</span>{/if}
              {#if s.share && s.share.disable_download}<span class="badge badge-warn">{$i18n("禁止下载")}</span>{/if}
            {:else if s.type === 'proxy'}
              <span class="badge badge-info">{s.requests || 0} {$i18n("次请求")}</span>
              <span class="badge badge-off">{fmtBytes(s.bytes || 0)} {$i18n("流量")}</span>
              <span class="badge badge-info">{proxyHealth(s).ok}/{proxyHealth(s).total} {$i18n("后端健康")}</span>
            {:else}
              <span class="badge badge-off">{s.requests || 0} {$i18n("次请求")}</span>
              <span class="badge badge-off">{fmtBytes(s.bytes || 0)} {$i18n("流量")}</span>
            {/if}
            {#if authOn(s)}<span class="badge badge-warn">{authLabel(s)}</span>{/if}
          </div>
          {#if s.error && !s.running}<div class="ws-error">{s.error}</div>{/if}
          <div class="list-card-actions">
            <button class="btn btn-sm" on:click={() => toggleSite(s)}>{s.running ? i18nTr("停止") : i18nTr("启动")}</button>
            <button class="btn btn-sm" on:click={() => openLogs(s)}>{$i18n("日志")}</button>
            {#if s.type === 'share'}<button class="btn btn-sm" on:click={() => openStats(s)}>{$i18n("统计")}</button>{:else}<button class="btn btn-sm" on:click={() => openAccess(s)}>{$i18n("记录")}</button>{/if}
            <button class="btn btn-sm" on:click={() => openEdit(s)}>{$i18n("编辑")}</button>
            <button class="btn btn-sm btn-danger" on:click={() => (delTarget = s)}>{$i18n("删除")}</button>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>
{:else if view === 'security'}
  <div class="container">
    <div class="page-hdr">
      <div>
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <button class="btn btn-ghost" on:click={() => (view = 'list')}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>
            <span>{$i18n("返回列表")}</span>
          </button>
          <h2>{$i18n("安全与分享")}</h2>
        </div>
        <span class="page-hdr-sub">{$i18n("认证 · IP / 路径访问控制 · 临时分享链接 · 封禁与安全事件")}</span>
      </div>
      <div class="page-hdr-actions">
        {#if sites.length && !securityPinned}
          <select class="ws-select" bind:value={securitySiteId} on:change={() => openSecurity(securitySiteId)}>
            {#each sites as s (s.id)}<option value={s.id}>{s.name} · {typeLabel(s.type)}</option>{/each}
          </select>
        {/if}
        <button class="btn btn-primary" on:click={saveSecurity} disabled={!securityForm || saving}>{saving ? i18nTr("保存中…") : i18nTr("保存安全设置")}</button>
      </div>
    </div>

    {#if !securityForm}
      <div class="ws-card"><div class="empty"><div class="empty-t">{$i18n("暂无可配置的 Web 服务，请先在列表页创建")}</div></div></div>
    {:else}
      <div class="ws-sec-grid">
        <div class="ws-sec-col">
          <div class="ws-sec-card">
            <div class="ws-sec-head">
              <h3>{$i18n("认证方式")}<span class="ws-sec-right">{$i18n("当前：")}{authLabel(securityForm) || i18nTr("关闭")}</span></h3>
            </div>
            <div class="ws-seg">
              {#each AUTH_OPTIONS as o (o.value)}
                <button class:active={securityForm.security.auth_mode === o.value} on:click={() => (securityForm.security.auth_mode = o.value)}>{o.label}</button>
              {/each}
            </div>
            <div class="form-group" style="margin-top:10px">
              <label class="form-label">{$i18n("用户列表（每行 username:password）")}</label>
              <textarea class="ws-textarea mono" bind:value={securityForm.security.users} placeholder="username:password&#10;admin:$2a$10$...bcrypt" disabled={securityForm.security.auth_mode === 'none'}></textarea>
            </div>
            <div class="tip-text">{$i18n("每行一个 username:password；支持 bcrypt 哈希。")}</div>
          </div>

          <div class="ws-sec-card">
            <div class="ws-sec-head"><h3>{$i18n("IP 访问控制")}</h3></div>
            <div class="ws-seg">
              {#each IP_OPTIONS as o (o.value)}
                <button class:active={securityForm.security.ip_mode === o.value} on:click={() => (securityForm.security.ip_mode = o.value)}>{o.label}</button>
              {/each}
            </div>
            <div class="form-group" style="margin-top:10px">
              <label class="form-label">{$i18n("IP / 网段（每行一个）")}</label>
              <textarea class="ws-textarea mono" bind:value={securityForm.security.ip_list} placeholder="192.168.1.0/24&#10;10.0.0.8" disabled={securityForm.security.ip_mode === 'off'}></textarea>
            </div>
            <div class="form-group" style="margin-top:10px">
              <label class="form-label">{$i18n("放行名单（始终允许）")}</label>
              <textarea class="ws-textarea mono" bind:value={securityForm.security.ip_allow} placeholder="192.168.1.8&#10;10.0.0.0/24"></textarea>
            </div>
            <div class="tip-text">{$i18n("放行名单优先于 IP 黑白名单、地区过滤与自动封禁；安全事件和封禁列表中的「放行」会自动加入这里。")}</div>
            <div class="form-group" style="margin-top:10px">
              <label class="form-label">{$i18n("可信反代（每行一个 IP / 网段）")}</label>
              <textarea class="ws-textarea mono" bind:value={securityForm.security.trusted_proxies} placeholder="192.168.1.2&#10;10.0.0.0/24"></textarea>
            </div>
            <div class="tip-text">{$i18n("只有来自可信反代的请求才采信 X-Real-IP / X-Forwarded-For；本机回环（frpc、本机 Nginx）默认可信，留空即只信任本机。")}</div>
          </div>

          <div class="ws-sec-card">
            <div class="ws-sec-head">
              <h3>{$i18n("按路径覆盖")}<span class="ws-sec-right">{$i18n("最长前缀优先")}</span></h3>
            </div>
            <div class="ws-mini-head"><span>{$i18n("前缀")}</span><span>{$i18n("认证")}</span><span>{$i18n("IP 模式")}</span><span>{$i18n("IP 列表")}</span><span>{$i18n("操作")}</span></div>
            {#each securityForm.security.path_rules as r, i (i)}
              <div class="ws-rule-row ws-rule-row-sec">
                <input type="text" class="mono" bind:value={r.prefix} placeholder="/admin" title={$i18n("路径前缀")} />
                <select bind:value={r.auth_mode}>{#each PATH_AUTH_OPTIONS as o (o.value)}<option value={o.value}>{o.label}</option>{/each}</select>
                <select bind:value={r.ip_mode}>
                  <option value="">{$i18n("继承")}</option><option value="off">{$i18n("关闭")}</option><option value="allow">{$i18n("白名单")}</option><option value="deny">{$i18n("黑名单")}</option>
                </select>
                <input type="text" class="mono" bind:value={r.ip_list} placeholder={$i18n("IP 列表（可空）")} title={$i18n("IP 列表")} />
                <button class="btn btn-icon btn-sm" title={$i18n("删除")} on:click={() => removeSecurityRule(securityForm, i)}>×</button>
              </div>
            {/each}
            {#if !securityForm.security.path_rules.length}<div class="ws-empty-inline">{$i18n("暂无路径规则")}</div>{/if}
            <button class="btn btn-sm" style="margin-top:8px" on:click={() => addSecurityRule(securityForm)}>{$i18n("＋ 添加路径规则")}</button>
            <div class="tip-text" style="margin-top:8px">{$i18n("按路径段边界匹配：/admin 匹配 /admin 与 /admin/x，不匹配 /administrator。")}</div>
          </div>

          <div class="ws-sec-card">
            <div class="ws-sec-head"><h3>{$i18n("失败限流与自动封禁")}</h3></div>
            <div class="form-row">
              <div class="form-group"><label class="form-label">{$i18n("失败次数")}</label><input type="number" min="1" max="100" bind:value={securityForm.security.fail_limit} /></div>
              <div class="form-group"><label class="form-label">{$i18n("统计窗口（分钟）")}</label><input type="number" min="1" max="1440" bind:value={securityForm.security.fail_window} /></div>
              <div class="form-group"><label class="form-label">{$i18n("自动封禁（分钟）")}</label><input type="number" min="0" max="43200" bind:value={securityForm.security.auto_ban_minutes} placeholder={$i18n("0 = 只限流")} /></div>
            </div>
            <div class="tip-text">{$i18n("0 表示仅限流；IPv6 按 /64 统计；封禁列表在右侧统一管理。")}</div>
          </div>

          <div class="ws-sec-card">
            <div class="ws-sec-head"><h3>{$i18n("国家 / 地区过滤")}</h3></div>
            <div class="ws-seg">
              {#each GEO_OPTIONS as o (o.value)}
                <button class:active={securityForm.security.geo_mode === o.value} on:click={() => (securityForm.security.geo_mode = o.value)}>{o.label}</button>
              {/each}
            </div>
            <div class="form-group" style="margin-top:10px">
              <label class="form-label">{$i18n("国家代码（逗号分隔）")}</label>
              <input type="text" class="mono" bind:value={securityForm.security.geo_countries} placeholder="CN, HK, SG" disabled={securityForm.security.geo_mode === 'off'} />
            </div>
            <div class="tip-text">{$i18n("复用现有 IP 归属地数据库；无数据库时过滤不生效；私网地址始终放行。")}</div>
          </div>
        </div>

        <div class="ws-sec-col">
          <div class="ws-sec-card">
            <div class="ws-sec-head">
              <h3>{$i18n("临时分享链接")}<span class="ws-sec-right">{securityForm.temp_shares.length} {$i18n("条有效")}</span></h3>
              <button class="btn btn-sm" on:click={() => addTempShare(securityForm)} disabled={securityForm.security.auth_mode === 'none'}>{$i18n("＋ 新建临时链接")}</button>
            </div>
            <div class="tip-text" style="margin-bottom:8px">{$i18n("开启认证后，访客可通过带")} <code>?_gs=token</code> {$i18n("的链接免登录访问；支持有效期、次数与路径前缀。")}</div>
            {#if securityForm.security.auth_mode === 'none'}
              <div class="ws-empty-inline">{$i18n("请先开启 Basic 或 Web 登录后再配置临时链接。")}</div>
            {:else}
              {#each securityForm.temp_shares as t, i (i)}
                <div class="ws-temp-row">
                  <input type="text" bind:value={t.name} placeholder={$i18n("链接名称")} />
                  <input type="text" bind:value={t.expires_at} placeholder={$i18n("到期时间（可空）")} />
                  <input type="number" min="0" bind:value={t.max_uses} placeholder={$i18n("次数（0=不限）")} />
                  <input type="text" class="mono" bind:value={t.path_prefix} placeholder={$i18n("路径前缀 /")} />
                  <button class="btn btn-icon btn-sm" title={$i18n("删除")} on:click={() => removeTempShare(securityForm, i)}>×</button>
                  <div class="ws-temp-token mono">
                    {#if t.token}
                      <span>{t.used || 0} / {t.max_uses || '∞'} {$i18n("次 ·")} {t.token}</span>
                      <button class="btn btn-sm" on:click={() => copyTempShare(securityForm, t)}>{$i18n("复制链接")}</button>
                    {:else}
                      <span>{$i18n("保存后生成链接")}</span>
                    {/if}
                  </div>
                </div>
              {/each}
              {#if !securityForm.temp_shares.length}<div class="ws-empty-inline">{$i18n("还没有临时链接")}</div>{/if}
            {/if}
          </div>

          <div class="ws-sec-card">
            <div class="ws-sec-head">
              <h3>{$i18n("封禁列表")}<span class="ws-sec-right">{bans.length} {$i18n("条 · 自动 + 手动")}</span></h3>
            </div>
            {#if bansLoading}
              <div class="ws-empty-inline">{$i18n("加载中…")}</div>
            {:else if !bans.length}
              <div class="ws-empty-inline">{$i18n("暂无封禁记录")}</div>
            {:else}
              {#each bans as b (b.ip)}
                <div class="ws-ban-row">
                  <span class="mono">{b.ip}</span>
                  <span class="tip-text">{b.until} {$i18n("解封")}</span>
                  <button class="btn btn-sm" on:click={() => allowIP(b.ip)} disabled={saving}>{$i18n("放行")}</button>
                  <button class="btn btn-sm" on:click={() => unban(b.ip)}>{$i18n("解封")}</button>
                </div>
              {/each}
            {/if}
          </div>

          <div class="ws-sec-card">
            <div class="ws-sec-head">
              <h3>{$i18n("安全事件")}<span class="ws-sec-right">{$i18n("最近 401 / 403 / 429 · 爬虫")}</span></h3>
            </div>
            {#if securityLoading}
              <div class="ws-empty-inline">{$i18n("加载中…")}</div>
            {:else if !securityEvents.length}
              <div class="ws-empty-inline">{$i18n("暂无安全事件")}</div>
            {:else}
              {#each securityEvents as e, i (i)}
                <div class="ws-event-row">
                  <span class="cell-dim">{e.time}</span>
                  <span class="mono">{e.ip}</span>
                  <span class="mono ellip" title={e.path}>{e.path}</span>
                  <span class="badge badge-warn">{e.kind === 'crawler' ? i18nTr("爬虫") : e.status}</span>
                  <button class="btn btn-sm" on:click={() => allowIP(e.ip)} disabled={saving}>{$i18n("放行")}</button>
                </div>
              {/each}
            {/if}
          </div>
        </div>
      </div>
    {/if}
  </div>
{:else if view === 'stats'}
  <div class="container">
    <div class="page-hdr">
      <div>
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <button class="btn btn-ghost" on:click={() => (view = 'list')}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>
            <span>{$i18n("返回列表")}</span>
          </button>
          <h2>{$i18n("分享统计")}</h2>
        </div>
        <span class="page-hdr-sub">{statsTarget ? statsTarget.name : ''} · {statsTarget ? publicUrl(statsTarget).replace(/^https?:\/\//, '') : ''} · {statsRange === 'today' ? i18nTr("今天") : statsRange === '7' ? i18nTr("7 天") : statsRange === '30' ? i18nTr("30 天") : i18nTr("全部")}</span>
      </div>
      <div class="page-hdr-actions">
        <div class="ws-seg ws-seg-inline">
          <button class:active={statsRange === 'today'} on:click={() => (statsRange = 'today')}>{$i18n("今天")}</button>
          <button class:active={statsRange === '7'} on:click={() => (statsRange = '7')}>{$i18n("7 天")}</button>
          <button class:active={statsRange === '30'} on:click={() => (statsRange = '30')}>{$i18n("30 天")}</button>
          <button class:active={statsRange === 'all'} on:click={() => (statsRange = 'all')}>{$i18n("全部")}</button>
        </div>
        <button class="btn" on:click={exportStats} disabled={!stats}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12M7 10l5 5 5-5M4 21h16"/></svg>
          {$i18n("导出 CSV")}
        </button>
      </div>
    </div>

    {#if statsLoading}
      <div class="empty"><div class="empty-t">{$i18n("加载中…")}</div></div>
    {:else if !stats}
      <div class="ws-card"><div class="empty"><div class="empty-t">{$i18n("暂无统计数据")}</div></div></div>
    {:else}
      <div class="ws-stats-kpis">
        <div class="ws-stat-card"><span>{$i18n("总下载")}</span><b>{stats.downloads || 0}</b><i>{$i18n("累计")}</i></div>
        <div class="ws-stat-card"><span>{$i18n("独立访客")}</span><b>{stats.visitors || 0}</b><i>{$i18n("按 IP 去重")}</i></div>
        <div class="ws-stat-card"><span>{$i18n("下载流量")}</span><b>{fmtBytes(stats.bytes || 0)}</b><i>{stats.downloads ? i18nTr("平均 ") + fmtBytes(Math.round((stats.bytes || 0) / stats.downloads)) + i18nTr(" / 次") : i18nTr("累计")}</i></div>
        <div class="ws-stat-card"><span>{$i18n("最近下载")}</span><b style="font-size:15px">{statsLast().time ? shortClock(statsLast().time) : '—'}</b><i>{statsLast().file || i18nTr("暂无记录")}</i></div>
      </div>

      <div class="ws-stats-card">
        <div class="ws-sec-head">
          <h3>{$i18n("近")} {statsDays.length} {$i18n("天下载趋势")}</h3>
          <span class="ws-sec-right">{$i18n("合计")} {statsRangeTotal()} {$i18n("次 · 峰值")} {statsPeak().peak} {$i18n("次（")}{statsPeak().label}）</span>
        </div>
        <div class="ws-bars">
          {#each statsDays as d (d.key)}
            <div class="ws-bar-item" title={$i18n("{0}：{1} 次", [d.label, d.value])}>
              <div class="ws-bar-val">{d.value}</div>
              <div class="ws-bar" style="height:{Math.max(4, Math.round(d.value / statsMax() * 100))}%"></div>
              <div class="ws-bar-label">{d.label}</div>
            </div>
          {/each}
        </div>
      </div>

      <div class="ws-stats-grid2">
        <div class="ws-stats-card">
          <div class="ws-sec-head"><h3>{$i18n("文件下载排行")}</h3><span class="ws-sec-right">{$i18n("按下载次数")}</span></div>
          {#if !statsFiles().length}
            <div class="empty" style="padding:18px 0"><div class="empty-t">{$i18n("暂无下载记录")}</div></div>
          {:else}
            {#each statsFiles() as f, i (f.path)}
              <div class="ws-rank-row">
                <span class="ws-rank-no">{i + 1}</span>
                <span class="ws-rank-name ellip" title={f.path}>{f.path}</span>
                <span class="ws-rank-bar"><i style="width:{Math.max(6, Math.round(f.downloads / statsFileMax() * 100))}%"></i></span>
                <span class="ws-rank-num">{f.downloads} {$i18n("次")}</span>
              </div>
            {/each}
          {/if}
        </div>

        <div class="ws-stats-card">
          <div class="ws-sec-head"><h3>{$i18n("最近下载")}</h3><span class="ws-sec-right">{$i18n("实时")}</span></div>
          {#if !(stats.recent && stats.recent.length)}
            <div class="empty" style="padding:18px 0"><div class="empty-t">{$i18n("暂无记录")}</div></div>
          {:else}
            <div class="table-wrap">
              <table>
                <thead><tr><th style="width:74px">{$i18n("时间")}</th><th>{$i18n("文件")}</th><th style="width:110px">{$i18n("访客")}</th><th style="width:58px">{$i18n("结果")}</th></tr></thead>
                <tbody>
                  {#each stats.recent as r, i (i)}
                    <tr><td class="cell-mono" style="font-size:10px">{shortClock(r.time)}</td><td class="ellip" title={r.file} style="max-width:130px">{r.file}</td><td class="cell-mono" style="font-size:10px">{r.ip}</td><td><span class="ws-result-ok">{$i18n("成功")}</span></td></tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </div>
      </div>
    {/if}
  </div>
{/if}

<!-- 新建 / 编辑 -->
{#if showForm}
  <Modal title={(editing ? i18nTr("编辑") : i18nTr("新建")) + (form.type === 'proxy' ? i18nTr("反向代理") : i18nTr(" Web 服务"))} width={1120} bodyClass="ws-proxy-body" onClose={() => (showForm = false)} closable={!saving}>
    <span slot="title-extra" class="badge {typeClass(form.type)}">{typeLabel(form.type)}</span>
    <div class="ws-proxy-shell">
      {#if !editing}
        <div class="ws-type-tabs">
          {#each TYPES as t (t.id)}
            <button class:active={form.type === t.id} on:click={() => switchType(t.id)}>
              <span class="ws-dot-t t-{typeTone(t.id)}"></span>{t.label}
            </button>
          {/each}
        </div>
      {/if}

      {#if form.type === 'proxy'}
<div class="ws-proxy-grid">
      <nav class="ws-proxy-nav">
        <button class:active={proxyPane === 'basic'} on:click={() => (proxyPane = 'basic')}>{$i18n("基础信息")}</button>
        <button class:active={proxyPane === 'backend'} on:click={() => (proxyPane = 'backend')}>{$i18n("后端与负载均衡")}</button>
        <button class:active={proxyPane === 'health'} on:click={() => (proxyPane = 'health')}>{$i18n("健康检查")}</button>
        <button class:active={proxyPane === 'traffic'} on:click={() => (proxyPane = 'traffic')}>{$i18n("流量与缓存")}</button>
        <button class:active={proxyPane === 'rules'} on:click={() => (proxyPane = 'rules')}>{$i18n("路径规则")}</button>
        <button class:active={proxyPane === 'security'} on:click={() => (proxyPane = 'security')}>{$i18n("认证与访问控制")}</button>
      </nav>

      <div class="ws-proxy-main">
        {#if proxyPane === 'basic'}
          <div class="ws-cfg-card">
          <h4>{$i18n("基础信息")}</h4>
          <div class="form-group">
            <label class="form-label" for="px-name">{$i18n("服务名称")}</label>
            <input id="px-name" type="text" bind:value={form.name} placeholder={$i18n("如 NAS 面板 / API 网关")} maxlength="64" />
          </div>
          <div class="form-group">
            <label class="form-label">{$i18n("访问方式")}</label>
            <div class="ws-seg">
              <button class:active={form.access_mode !== 'path'} on:click={() => setAccessMode('port')}>{$i18n("端口")}</button>
              <button class:active={form.access_mode === 'path'} on:click={() => setAccessMode('path')}>{$i18n("路径")}</button>
            </div>
            <div class="tip-text">
              {form.access_mode === 'path'
                ? i18nTr("路径模式复用统一 HTTP 端口，通过路径前缀区分站点；统一端口根路径不提供访问。")
                : i18nTr("每个站点使用独立监听端口。")}
            </div>
          </div>
          {#if form.access_mode === 'path'}
            <div class="form-row">
              <div class="form-group">
                <label class="form-label" for="px-path">{$i18n("路径前缀")}</label>
                <input id="px-path" type="text" bind:value={form.path_prefix} placeholder="/api" />
                <div class="tip-text">{$i18n("访问地址：")}<span class="mono">{pathPreview}</span></div>
              </div>
              <div class="form-group">
                <label class="form-label" for="px-unified-port">{$i18n("统一端口")}</label>
                <input id="px-unified-port" type="text" value={httpPort} readonly />
                <div class="tip-text">
                  {httpAccessMode === 'domain' && httpAccessDomain
                    ? i18nTr("监听端口不变；对外地址按域名 443 展示，需外部反向代理到该端口。")
                    : i18nTr("来自「系统设置 → 默认参数 → HTTP 默认端口」。")}
                </div>
              </div>
            </div>
          {:else}
            <div class="form-row">
              <div class="form-group">
                <label class="form-label" for="px-addr">{$i18n("监听地址")}</label>
                <input id="px-addr" type="text" bind:value={form.addr} placeholder="0.0.0.0" />
              </div>
              <div class="form-group">
                <label class="form-label" for="px-port">{$i18n("端口")}</label>
                <input id="px-port" type="number" min="1" max="65535" bind:value={form.port} />
              </div>
            </div>
          {/if}
          <div class="ws-switch-row">
            <div><div class="ws-switch-title">{$i18n("开机自启")}</div><div class="ws-switch-sub">{$i18n("TunHook 启动时自动拉起该服务")}</div></div>
            <Toggle bind:checked={form.auto_start} />
          </div>
          </div>
          <div class="ws-cfg-card">
          <h4>{$i18n("HTTP 行为")}</h4>
          <div class="ws-switch-row">
            <div><div class="ws-switch-title">{$i18n("记录访问日志")}</div><div class="ws-switch-sub">{$i18n("保留最近 300 条请求记录")}</div></div>
            <Toggle bind:checked={form.access_log} />
          </div>
          <div class="ws-switch-row">
            <div><div class="ws-switch-title">{$i18n("CORS 跨域")}</div><div class="ws-switch-sub">{$i18n("允许浏览器跨域访问该服务")}</div></div>
            <Toggle bind:checked={form.cors} />
          </div>
          <div class="form-row" style="margin-top:12px">
            <div class="form-group">
              <label class="form-label">{$i18n("自定义请求头")}</label>
              <textarea class="ws-textarea mono" bind:value={form.req_headers} placeholder={$i18n("X-Example: value 空 Value 表示删除该头")}></textarea>
            </div>
            <div class="form-group">
              <label class="form-label">{$i18n("自定义响应头")}</label>
              <textarea class="ws-textarea mono" bind:value={form.resp_headers} placeholder="X-Robots-Tag: noindex"></textarea>
            </div>
          </div>
          </div>
        {:else if proxyPane === 'backend'}
          <div class="ws-cfg-card">
          <h4>{$i18n("后端列表")}<span class="ws-cfg-right">{$i18n("支持加权与备用")}</span></h4>
          <div class="tip-text" style="margin-bottom:8px">{$i18n("权重越高分配到的请求越多；备用后端仅在主后端全部不可用时启用。")}</div>
          {#each form.proxy.backends as b, i (i)}
            <div class="ws-backend-row">
              <input type="text" class="mono" bind:value={b.url} placeholder="http://10.0.0.2:8080" />
              <input type="number" min="1" max="100" bind:value={b.weight} title={$i18n("权重")} />
              <label class="ws-check"><input type="checkbox" bind:checked={b.backup} /> {$i18n("备用")}</label>
              <button class="btn btn-icon btn-sm" title={$i18n("删除")} on:click={() => removeBackend(i)}>×</button>
            </div>
          {/each}
          <button class="btn btn-sm" on:click={addBackend}>{$i18n("＋ 添加后端")}</button>
          </div>

          <div class="ws-cfg-card">
          <h4>{$i18n("负载均衡与协议")}</h4>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">{$i18n("负载均衡策略")}</label>
              <select bind:value={form.proxy.lb_policy}>
                {#each LB_OPTIONS as o (o.value)}<option value={o.value}>{o.label}</option>{/each}
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">{$i18n("Host 处理")}</label>
              <div class="ws-toggle-line"><Toggle bind:checked={form.proxy.use_backend_host} /><span>{$i18n("改写为后端 Host")}</span></div>
              <div class="tip-text">{$i18n("关闭时保留客户端 Host")}</div>
            </div>
          </div>
          <div class="ws-switch-row"><div><div class="ws-switch-title">{$i18n("跳过后端证书校验")}</div><div class="ws-switch-sub">{$i18n("后端为自签名 HTTPS 时开启")}</div></div><Toggle bind:checked={form.proxy.skip_tls_verify} /></div>
          <div class="ws-switch-row"><div><div class="ws-switch-title">{$i18n("禁用 Keep-Alive")}</div><div class="ws-switch-sub">{$i18n("每次请求新建后端连接")}</div></div><Toggle bind:checked={form.proxy.disable_keep_alive} /></div>
          <div class="ws-switch-row"><div><div class="ws-switch-title">{$i18n("发送 PROXY protocol v2")}</div><div class="ws-switch-sub">{$i18n("向后端传递真实客户端 IP，需后端支持")}</div></div><Toggle bind:checked={form.proxy.proxy_protocol} /></div>
          <div class="ws-switch-row"><div><div class="ws-switch-title">{$i18n("添加 X-Forwarded-*")}</div><div class="ws-switch-sub">X-Forwarded-For / Proto / Host</div></div><Toggle bind:checked={form.proxy.x_forwarded} /></div>
          </div>

          <div class="ws-cfg-card">
          <h4>{$i18n("当前后端状态")}</h4>
          {#each proxyBackendRows() as b, i (i)}
            <div class="ws-backend-status">
              <span class="mono ellip" style="flex:1;min-width:0" title={b.url}>{b.url || i18nTr("未填写地址")}</span>
              <span class="badge" class:badge-info={b.healthy} class:badge-warn={!b.healthy && b.paused} class:badge-error={!b.healthy && !b.paused && editing && editing.running}>
                {b.healthy ? i18nTr("健康") : b.paused ? i18nTr("暂停") : (editing && editing.running ? i18nTr("不可用") : i18nTr("未启动"))}
              </span>
              <span>{$i18n("权重")} {b.weight}{b.backup ? i18nTr(" · 备用") : ''}</span>
              <span>{$i18n("连接")} {b.active || 0}</span>
            </div>
          {/each}
          </div>
        {:else if proxyPane === 'health'}
          <div class="ws-cfg-card">
          <h4>{$i18n("主动健康检查")}</h4>
          <div class="ws-switch-row">
            <div><div class="ws-switch-title">{$i18n("启用主动检查")}</div><div class="ws-switch-sub">{$i18n("被动检查始终生效：连续 3 次连接失败暂停 30 秒")}</div></div>
            <Toggle bind:checked={form.proxy.health_check.enabled} />
          </div>
          {#if form.proxy.health_check.enabled}
            <div class="form-row">
              <div class="form-group"><label class="form-label">{$i18n("模式")}</label><select bind:value={form.proxy.health_check.mode}><option value="http">HTTP</option><option value="tcp">TCP</option></select></div>
              <div class="form-group"><label class="form-label">{$i18n("检查路径")}</label><input type="text" class="mono" bind:value={form.proxy.health_check.path} placeholder="/" /></div>
            </div>
            <div class="form-row">
              <div class="form-group"><label class="form-label">{$i18n("间隔（秒）")}</label><input type="number" min="1" max="3600" bind:value={form.proxy.health_check.interval} /></div>
              <div class="form-group"><label class="form-label">{$i18n("超时（秒）")}</label><input type="number" min="1" max="60" bind:value={form.proxy.health_check.timeout} /></div>
            </div>
            <div class="form-row">
              <div class="form-group"><label class="form-label">{$i18n("连续失败判定")}</label><input type="number" min="1" max="20" bind:value={form.proxy.health_check.fails} /></div>
              <div class="form-group"><label class="form-label">{$i18n("连续成功恢复")}</label><input type="number" min="1" max="20" bind:value={form.proxy.health_check.passes} /></div>
            </div>
          {/if}
          </div>
          <div class="ws-cfg-card">
          <h4>{$i18n("后端健康状态")}</h4>
          {#each proxyBackendRows() as b, i (i)}
            <div class="ws-backend-status">
              <span class="mono ellip" style="flex:1;min-width:0" title={b.url}>{b.url || i18nTr("未填写地址")}</span>
              <span class="badge" class:badge-info={b.healthy} class:badge-warn={!b.healthy && b.paused} class:badge-error={!b.healthy && !b.paused && editing && editing.running}>
                {b.healthy ? i18nTr("健康") : b.paused ? i18nTr("暂停") : (editing && editing.running ? i18nTr("不可用") : i18nTr("未启动"))}
              </span>
              <span>{$i18n("权重")} {b.weight}{b.backup ? i18nTr(" · 备用") : ''}</span>
            </div>
          {/each}
          </div>
        {:else if proxyPane === 'traffic'}
          <div class="ws-cfg-card">
          <h4>{$i18n("压缩")}</h4>
          <div class="ws-switch-row"><div><div class="ws-switch-title">{$i18n("gzip 压缩")}</div><div class="ws-switch-sub">{$i18n("文本类响应超过 256 字节时压缩")}</div></div><Toggle bind:checked={form.proxy.compression} /></div>
          </div>

          <div class="ws-cfg-card">
          <h4>{$i18n("每 IP 限流")}</h4>
          <div class="form-row">
            <div class="form-group"><label class="form-label">{$i18n("每秒请求数")}</label><input type="number" min="0" bind:value={form.proxy.rate_limit} placeholder={$i18n("0 = 不限")} /></div>
            <div class="form-group"><label class="form-label">{$i18n("突发容量")}</label><input type="number" min="0" bind:value={form.proxy.burst} placeholder={$i18n("0 = 自动")} /></div>
          </div>
          <div class="form-group"><label class="form-label">{$i18n("每 IP 最大并发")}</label><input type="number" min="0" bind:value={form.proxy.max_conns} placeholder={$i18n("0 = 不限")} /></div>
          </div>

          <div class="ws-cfg-card">
          <h4>{$i18n("内存响应缓存")}</h4>
          <div class="form-row">
            <div class="form-group"><label class="form-label">{$i18n("缓存 TTL（秒）")}</label><input type="number" min="0" max="2592000" bind:value={form.proxy.cache_ttl} placeholder={$i18n("0 = 关闭缓存")} /></div>
            <div class="form-group"><label class="form-label">{$i18n("缓存容量（MB）")}</label><input type="number" min="1" max="4096" bind:value={form.proxy.cache_max_mb} /></div>
          </div>
          <div class="tip-text">{$i18n("仅缓存 GET / HEAD 的成功响应；带 Cookie 或 Authorization 的请求不缓存。")}</div>
          </div>
        {:else if proxyPane === 'rules'}
          <div class="ws-cfg-card">
          <h4>{$i18n("路径重写 / 重定向")}<span class="ws-cfg-right">{$i18n("按顺序匹配，首个命中生效")}</span></h4>
          <div class="tip-text" style="margin-bottom:8px">{$i18n("内部重写目标必须以 / 开头；重定向支持 301 / 302 / 307 / 308，并保留原始查询串。")}</div>
          {#each form.proxy.path_rules as r, i (i)}
            <div class="ws-rule-row">
              <input type="text" class="mono" bind:value={r.pattern} placeholder="^/old/(.*)$" title={$i18n("匹配正则")} />
              <input type="text" class="mono" bind:value={r.to} placeholder="/new/$1" title={$i18n("替换为")} />
              <select bind:value={r.redirect}><option value={false}>{$i18n("内部重写")}</option><option value={true}>{$i18n("重定向")}</option></select>
              <input type="number" min="301" max="308" bind:value={r.code} title={$i18n("状态码")} />
              <button class="btn btn-icon btn-sm" title={$i18n("删除")} on:click={() => removeProxyRule(i)}>×</button>
            </div>
          {/each}
          <button class="btn btn-sm" on:click={addProxyRule}>{$i18n("＋ 添加规则")}</button>
          </div>
        {:else if proxyPane === 'security'}
          <div class="ws-cfg-card">
          <h4>{$i18n("认证与访问控制")}</h4>
          <div class="tip-text">{$i18n("认证、IP / 路径规则、临时分享链接与封禁列表统一在「安全与分享」页面配置。")}</div>
          <div class="ws-kv"><span>{$i18n("认证")}</span><b>{authLabel(form) || i18nTr("关闭")}</b></div>
          <div class="ws-kv"><span>{$i18n("IP 控制")}</span><b>{form.security.ip_mode === 'off' ? i18nTr("关闭") : (form.security.ip_mode === 'allow' ? i18nTr("白名单") : i18nTr("黑名单"))}</b></div>
          <div class="ws-kv"><span>{$i18n("路径规则")}</span><b>{form.security.path_rules.length} {$i18n("条")}</b></div>
          <div class="ws-kv"><span>{$i18n("临时链接")}</span><b>{form.temp_shares.length} {$i18n("条")}</b></div>
          {#if editing}
            <button class="btn" style="margin-top:14px" on:click={() => { showForm = false; openSecurity(form.id, true); }}>{$i18n("打开安全与分享")}</button>
          {:else}
            <div class="ws-empty-inline">{$i18n("保存后可在「安全与分享」中配置。")}</div>
          {/if}
          </div>
        {/if}
      </div>

      <aside class="ws-config-side">
        <div class="ws-side-card">
          <h4>{$i18n("入口地址")}</h4>
          <div class="ws-link-box mono">{siteUrl(form)}</div>
          <div class="ws-side-actions">
            <button class="btn btn-sm" style="flex:1" on:click={() => copyText(siteUrl(form), '地址')}>{$i18n("复制链接")}</button>
            <a class="btn btn-sm" style="flex:1" href={siteUrl(form)} target="_blank" rel="noopener noreferrer">{$i18n("打开")}</a>
          </div>
          {#if proxyQr}<div class="ws-qr">{@html proxyQr}</div>{:else}<div class="ws-qr ws-qr-empty">{$i18n("地址过长，无法生成二维码")}</div>{/if}
          <div class="ws-qr-hint">{$i18n("扫码在手机上打开")}</div>
        </div>
        <div class="ws-side-card">
          <h4>{$i18n("概览")}</h4>
          <div class="ws-kv"><span>{$i18n("类型")}</span><b>{$i18n("反向代理")}</b></div>
          <div class="ws-kv"><span>{$i18n("监听")}</span><b>{listenLabel(form)}</b></div>
          <div class="ws-kv"><span>{$i18n("后端")}</span><b>{form.proxy.backends.filter((b) => (b.url || '').trim()).length} {$i18n("个")}</b></div>
          <div class="ws-kv"><span>{$i18n("负载均衡")}</span><b>{LB_OPTIONS.find((o) => o.value === form.proxy.lb_policy)?.label || '-'}</b></div>
          <div class="ws-kv"><span>{$i18n("健康检查")}</span><b>{form.proxy.health_check.enabled ? i18nTr("主动") : i18nTr("被动")}</b></div>
          <div class="ws-kv"><span>{$i18n("缓存")}</span><b>{form.proxy.cache_ttl > 0 ? form.proxy.cache_ttl + 's' : i18nTr("关闭")}</b></div>
          <div class="ws-kv"><span>{$i18n("认证")}</span><b>{authLabel(form) || i18nTr("关闭")}</b></div>
        </div>
        <div class="ws-side-card">
          <h4>{$i18n("说明")}</h4>
          <div class="tip-text">{$i18n("HTTP / HTTPS 后端均可；WebSocket 自动透传。路径规则按顺序匹配，首个命中生效。")}</div>
        </div>
      </aside>
    </div>
      {:else}
<div class="ws-proxy-grid ws-config-layout">
        <nav class="ws-proxy-nav">
          <button class:active={configPane === 'basic'} on:click={() => (configPane = 'basic')}>{$i18n("基础信息")}</button>
          {#if form.type === 'static'}
            <button class:active={configPane === 'site'} on:click={() => (configPane = 'site')}>{$i18n("目录与首页")}</button>
          {:else if form.type === 'share'}
            <button class:active={configPane === 'share'} on:click={() => (configPane = 'share')}>{$i18n("分享设置")}</button>
          {:else if form.type === 'redirect'}
            <button class:active={configPane === 'redirect'} on:click={() => (configPane = 'redirect')}>{$i18n("跳转设置")}</button>
          {:else if form.type === 'text'}
            <button class:active={configPane === 'text'} on:click={() => (configPane = 'text')}>{$i18n("响应内容")}</button>
          {/if}
          <button class:active={configPane === 'runtime'} on:click={() => (configPane = 'runtime')}>{$i18n("运行与日志")}</button>
          <button class:active={configPane === 'access'} on:click={() => (configPane = 'access')}>{$i18n("访问控制")}</button>
          <button class:active={configPane === 'headers'} on:click={() => (configPane = 'headers')}>{$i18n("自定义请求头")}</button>
        </nav>

        <div class="ws-proxy-main">
          {#if configPane === 'basic'}
            <div class="ws-cfg-card">
              <h4>{$i18n("基础信息")}</h4>
              <div class="form-group">
                <label class="form-label" for="ws-name">{form.type === 'share' ? i18nTr("分享名称") : i18nTr("服务名称")}</label>
                <input id="ws-name" type="text" bind:value={form.name} placeholder={$i18n("如 产品文档 / 团队素材库 / NAS 面板")} maxlength="64" />
                {#if form.type === 'share'}
                  <div class="tip-text">{$i18n("分享页的大标题直接使用该名称。")}</div>
                {/if}
              </div>
              {#if form.type === 'share'}
                <div class="form-group">
                  <label class="form-label" for="ws-share-subtitle">{$i18n("副标题")}</label>
                  <input id="ws-share-subtitle" type="text" bind:value={form.share.subtitle} placeholder="TunHook" maxlength="64" />
                  <div class="tip-text">{$i18n("显示在分享页标题上方的小字，留空时显示 TunHook。")}</div>
                </div>
              {/if}
              {#if form.type === 'static' || form.type === 'share'}
                <div class="form-group">
                  <label class="form-label" for="ws-root">{form.type === 'share' ? i18nTr("分享目录 / 文件") : i18nTr("站点目录")}</label>
                  <div class="input-action-row">
                    <input id="ws-root" type="text" bind:value={form.root} placeholder="/vol1/www" />
                    <button class="btn" on:click={openBrowse}>{$i18n("浏览")}</button>
                  </div>
                  <div class="tip-text">{form.type === 'share' ? i18nTr("支持选择整个目录或单个文件；目录内的子文件夹会自动聚合到分享页。") : i18nTr("目录需为服务器上的绝对路径。")}</div>
                </div>
              {/if}
              {#if form.type !== 'share'}
                <div class="form-group">
                  <label class="form-label">{$i18n("访问方式")}</label>
                  <div class="ws-seg">
                    <button class:active={form.access_mode !== 'path'} on:click={() => setAccessMode('port')}>{$i18n("端口")}</button>
                    <button class:active={form.access_mode === 'path'} on:click={() => setAccessMode('path')}>{$i18n("路径")}</button>
                  </div>
                  <div class="tip-text">
                    {form.access_mode === 'path'
                      ? i18nTr("路径模式复用统一 HTTP 端口，通过路径前缀区分站点；统一端口根路径不提供访问。")
                      : i18nTr("每个站点使用独立监听端口。")}
                  </div>
                </div>
                {#if form.access_mode === 'path'}
                  <div class="form-row">
                    <div class="form-group">
                      <label class="form-label" for="ws-path">{$i18n("路径前缀")}</label>
                      <input id="ws-path" type="text" bind:value={form.path_prefix} placeholder="/docs" />
                      <div class="tip-text">{$i18n("访问地址：")}<span class="mono">{pathPreview}</span></div>
                    </div>
                    <div class="form-group">
                      <label class="form-label" for="ws-unified-port">{$i18n("统一端口")}</label>
                      <input id="ws-unified-port" type="text" value={httpPort} readonly />
                      <div class="tip-text">
                        {httpAccessMode === 'domain' && httpAccessDomain
                          ? i18nTr("监听端口不变；对外地址按域名 443 展示，需外部反向代理到该端口。")
                          : i18nTr("来自「系统设置 → 默认参数 → HTTP 默认端口」。")}
                      </div>
                    </div>
                  </div>
                {:else}
                  <div class="form-row">
                    <div class="form-group">
                      <label class="form-label" for="ws-addr">{$i18n("监听地址")}</label>
                      <input id="ws-addr" type="text" bind:value={form.addr} placeholder="0.0.0.0" />
                    </div>
                    <div class="form-group">
                      <label class="form-label" for="ws-port">{$i18n("端口")}</label>
                      <input id="ws-port" type="number" min="1" max="65535" bind:value={form.port} />
                      {#if portConflict}
                        <div class="tip-text" style="color:var(--red)">{portConflict}</div>
                      {/if}
                    </div>
                  </div>
                {/if}
              {:else}
                <div class="form-group">
                  <label class="form-label" for="ws-share-desc">{$i18n("分享说明")}</label>
                  <textarea id="ws-share-desc" class="ws-textarea" bind:value={form.share.description} placeholder={$i18n("展示在分享页标题下方")}></textarea>
                </div>
              {/if}
            </div>
          {:else if configPane === 'site' && form.type === 'static'}
            <div class="ws-cfg-card">
              <h4>{$i18n("目录与首页")}</h4>
              <div class="form-row">
                <div class="form-group">
                  <label class="form-label" for="ws-index">{$i18n("首页文件")}</label>
                  <input id="ws-index" type="text" bind:value={form.index} placeholder="index.html" />
                </div>
                <div class="form-group">
                  <div class="form-label">{$i18n("目录浏览")}</div>
                  <div class="ws-toggle-line"><Toggle bind:checked={form.browse} /><span>{$i18n("无首页时列出目录内容")}</span></div>
                </div>
              </div>
            </div>
          {:else if configPane === 'share' && form.type === 'share'}
            <div class="ws-cfg-card">
              <h4>{$i18n("访问方式")}</h4>
              <div class="form-group">
                <div class="ws-seg">
                  <button class:active={form.access_mode !== 'path'} on:click={() => setAccessMode('port')}>{$i18n("端口访问")}</button>
                  <button class:active={form.access_mode === 'path'} on:click={() => setAccessMode('path')}>{$i18n("域名访问")}</button>
                </div>
                <div class="tip-text">
                  {form.access_mode === 'path'
                    ? i18nTr("通过已绑定域名访问统一端口，多个分享用不同路径区分。")
                    : i18nTr("使用独立端口直接访问，可选择本机某个 IP 作为监听出口。")}
                </div>
              </div>
              {#if form.access_mode === 'path'}
                <div class="form-row">
                  <div class="form-group">
                    <label class="form-label" for="ws-share-domain">{$i18n("访问域名")}</label>
                    <input id="ws-share-domain" type="text" value={httpAccessDomain || i18nTr("未绑定域名")} readonly />
                    <div class="tip-text">{$i18n("域名在「系统设置 → 默认参数」中配置，此处不可修改。")}</div>
                  </div>
                  <div class="form-group">
                    <label class="form-label" for="ws-slug">{$i18n("访问路径")}</label>
                    <input id="ws-slug" type="text" bind:value={form.share.slug} placeholder="share" />
                    {#if shareSlugTaken}
                      <div class="tip-text" style="color:var(--red)">{$i18n("该路径已被其他分享站点使用，请换一个")}</div>
                    {:else}
                      <div class="tip-text">{$i18n("最终地址：")}{publicUrl(form)}</div>
                    {/if}
                  </div>
                </div>
              {:else}
                <div class="form-row">
                  <div class="form-group">
                    <label class="form-label" for="ws-addr-share">{$i18n("监听 IP")}</label>
                    <select id="ws-addr-share" bind:value={form.addr}>
                      <option value="0.0.0.0">{$i18n("0.0.0.0（全部网卡）")}</option>
                      {#each ipOptions as ip (ip)}
                        <option value={ip}>{ip}</option>
                      {/each}
                    </select>
                    <div class="tip-text">{$i18n("选择本机 IP 时只接受该网卡进来的请求。")}</div>
                  </div>
                  <div class="form-group">
                    <label class="form-label" for="ws-port-share">{$i18n("端口")}</label>
                    <input id="ws-port-share" type="number" min="1" max="65535" bind:value={form.port} />
                    {#if portConflict}
                      <div class="tip-text" style="color:var(--red)">{portConflict}</div>
                    {:else}
                      <div class="tip-text">{$i18n("最终地址：")}{publicUrl(form)}</div>
                    {/if}
                  </div>
                </div>
              {/if}
            </div>
            <div class="ws-cfg-card">
              <h4>{$i18n("提取码与有效期")}</h4>
              <div class="form-row">
                <div class="form-group">
                  <label class="form-label" for="ws-code">{$i18n("提取码")}</label>
                  <div class="ws-seg">
                    <button class:active={codeMode === 'off'} on:click={() => setCodeMode('off')}>{$i18n("关闭")}</button>
                    <button class:active={codeMode === 'auto'} on:click={() => setCodeMode('auto')}>{$i18n("自动生成")}</button>
                    <button class:active={codeMode === 'custom'} on:click={() => setCodeMode('custom')}>{$i18n("自定义")}</button>
                  </div>
                  {#if codeMode !== 'off'}
                    <div class="input-action-row" style="margin-top:7px">
                      <input id="ws-code" type="text" class="ws-code-input mono" bind:value={form.share.access_code} readonly={codeMode === 'auto'} placeholder={$i18n("4 位提取码")} maxlength="16" />
                      <button class="btn btn-sm" on:click={() => setCodeMode('auto')}>{$i18n("重新生成")}</button>
                    </div>
                  {/if}
                </div>
                <div class="form-group">
                  <label class="form-label" for="ws-expire">{$i18n("有效期")}</label>
                  <div class="ws-seg">
                    <button class:active={expiryMode === 'permanent'} on:click={() => setExpiryMode('permanent')}>{$i18n("永久")}</button>
                    <button class:active={expiryMode === '7'} on:click={() => setExpiryMode('7')}>{$i18n("7 天")}</button>
                    <button class:active={expiryMode === '30'} on:click={() => setExpiryMode('30')}>{$i18n("30 天")}</button>
                    <button class:active={expiryMode === 'custom'} on:click={() => setExpiryMode('custom')}>{$i18n("自定义")}</button>
                  </div>
                  {#if expiryMode === 'custom'}
                    <input id="ws-expire" type="text" class="mono" style="margin-top:7px" bind:value={form.share.expires_at} placeholder="2026-12-31 23:59:59" />
                  {:else if form.share.expires_at}
                    <div class="tip-text" style="margin-top:7px">{$i18n("到期时间：")}{form.share.expires_at} {$i18n("· 到期后自动停止分享")}</div>
                  {:else}
                    <div class="tip-text" style="margin-top:7px">{$i18n("永久有效，不会自动停止")}</div>
                  {/if}
                </div>
              </div>
            </div>
            <div class="ws-cfg-card">
              <h4>{$i18n("下载限制")}</h4>
              <div class="form-row">
                <div class="form-group">
                  <label class="form-label">{$i18n("每个 IP 每日下载上限")}</label>
                  <input type="number" min="0" bind:value={form.share.per_ip_daily} placeholder={$i18n("0 = 不限")} />
                </div>
                <div class="form-group">
                  <label class="form-label">{$i18n("总下载次数上限")}</label>
                  <input type="number" min="0" bind:value={form.share.max_downloads} placeholder={$i18n("0 = 不限")} />
                </div>
              </div>
            </div>
            <div class="ws-cfg-card">
              <h4>{$i18n("分享页面")}</h4>
              <div class="ws-switch-row"><div><div class="ws-switch-title">{$i18n("允许在线预览")}</div><div class="ws-switch-sub">{$i18n("图片 / 视频 / 音频 / PDF / 文本 / Markdown；关闭后访客只能浏览文件列表")}</div></div><Toggle bind:checked={form.share.preview} /></div>
              <div class="ws-switch-row"><div><div class="ws-switch-title">{$i18n("允许打包下载")}</div><div class="ws-switch-sub">{$i18n("整目录 ZIP 下载")}</div></div><Toggle bind:checked={form.share.package_download} disabled={form.share.disable_download} /></div>
              <div class="ws-switch-row"><div><div class="ws-switch-title">{$i18n("禁止下载（仅允许在线查看）")}</div><div class="ws-switch-sub">{$i18n("隐藏下载与打包按钮，服务端拒绝下载请求；可配合关闭在线预览彻底禁止获取文件内容")}</div></div><Toggle bind:checked={form.share.disable_download} /></div>
              <div class="ws-switch-row"><div><div class="ws-switch-title">{$i18n("显示下载次数")}</div><div class="ws-switch-sub">{$i18n("在分享页与卡片上展示")}</div></div><Toggle bind:checked={form.share.show_downloads} /></div>
              <div class="ws-switch-row"><div><div class="ws-switch-title">{$i18n("记录下载日志")}</div><div class="ws-switch-sub">{$i18n("用于统计与最近下载列表")}</div></div><Toggle bind:checked={form.share.log_downloads} /></div>
              <div class="ws-switch-row"><div><div class="ws-switch-title">{$i18n("Office 文档在线预览（外部服务）")}</div><div class="ws-switch-sub">{$i18n("需要分享地址可被公网访问；本轮暂未接入")}</div></div><Toggle bind:checked={form.share.office_preview} disabled /></div>
            </div>
          {:else if configPane === 'redirect' && form.type === 'redirect'}
            <div class="ws-cfg-card">
              <h4>{$i18n("跳转设置")}</h4>
              <div class="form-group">
                <label class="form-label" for="ws-redir">{$i18n("重定向目标")}</label>
                <input id="ws-redir" type="text" bind:value={form.redirect_to} placeholder="https://example.com/new" />
              </div>
              <div class="form-row">
                <div class="form-group">
                  <label class="form-label">{$i18n("状态码")}</label>
                  <select bind:value={form.redirect_code}>
                    {#each REDIRECT_OPTIONS as o (o.value)}<option value={o.value}>{o.label}</option>{/each}
                  </select>
                </div>
                <div class="form-group">
                  <div class="form-label">{$i18n("跳转行为")}</div>
                  <div class="ws-toggle-line"><Toggle bind:checked={form.redirect_keep_path} /><span>{$i18n("保留原始路径")}</span></div>
                  <div class="ws-toggle-line" style="height:30px"><Toggle bind:checked={form.redirect_keep_query} /><span>{$i18n("保留查询串")}</span></div>
                </div>
              </div>
            </div>
          {:else if configPane === 'text' && form.type === 'text'}
            <div class="ws-cfg-card">
              <h4>{$i18n("响应内容")}</h4>
              <div class="form-row">
                <div class="form-group">
                  <label class="form-label" for="ws-ct">Content-Type</label>
                  <input id="ws-ct" type="text" bind:value={form.text_content_type} placeholder="text/plain; charset=utf-8" />
                </div>
                <div class="form-group">
                  <label class="form-label" for="ws-cs">{$i18n("状态码")}</label>
                  <input id="ws-cs" type="number" min="100" max="599" bind:value={form.text_status} />
                </div>
              </div>
              <div class="form-group">
                <label class="form-label">{$i18n("响应正文")}</label>
                <textarea class="ws-textarea mono" bind:value={form.text} placeholder={$i18n("<h1>系统维护中</h1>")} style="min-height:240px"></textarea>
              </div>
            </div>
          {:else if configPane === 'runtime'}
            <div class="ws-cfg-card">
              <h4>{$i18n("运行与日志")}</h4>
              <div class="ws-switch-row">
                <div><div class="ws-switch-title">{$i18n("开机自启")}</div><div class="ws-switch-sub">{$i18n("TunHook 启动时自动拉起该服务")}</div></div>
                <Toggle bind:checked={form.auto_start} />
              </div>
              <div class="ws-switch-row">
                <div><div class="ws-switch-title">{$i18n("记录访问日志")}</div><div class="ws-switch-sub">{$i18n("保留最近 300 条请求记录")}</div></div>
                <Toggle bind:checked={form.access_log} />
              </div>
              <div class="ws-switch-row">
                <div><div class="ws-switch-title">{$i18n("CORS 跨域")}</div><div class="ws-switch-sub">{$i18n("允许浏览器跨域访问该服务")}</div></div>
                <Toggle bind:checked={form.cors} />
              </div>
            </div>
          {:else if configPane === 'access'}
            <div class="ws-cfg-card">
              <h4>{$i18n("访问控制")}</h4>
              <div class="tip-text">{$i18n("认证方式、IP / 路径访问控制、临时分享链接与封禁列表统一在「安全与分享」页面配置。")}</div>
              {#if editing}
                <button class="btn btn-sm" style="margin-top:12px" on:click={() => { showForm = false; openSecurity(form.id, true); }}>{$i18n("打开安全与分享")}</button>
              {:else}
                <div class="ws-empty-inline">{$i18n("保存后可在「安全与分享」中配置。")}</div>
              {/if}
            </div>
          {:else if configPane === 'headers'}
            <div class="ws-cfg-card">
              <h4>{$i18n("自定义请求头")}</h4>
              <div class="form-row">
                <div class="form-group">
                  <label class="form-label">{$i18n("请求头")}</label>
                  <textarea class="ws-textarea mono" bind:value={form.req_headers} placeholder={$i18n("X-Example: value 空 Value 表示删除该头")}></textarea>
                </div>
                <div class="form-group">
                  <label class="form-label">{$i18n("响应头")}</label>
                  <textarea class="ws-textarea mono" bind:value={form.resp_headers} placeholder="X-Robots-Tag: noindex"></textarea>
                </div>
              </div>
            </div>
          {/if}
        </div>

        <aside class="ws-config-side">
          <div class="ws-side-card">
            <h4>{form.type === 'share' ? i18nTr("分享链接") : i18nTr("入口地址")}</h4>
            <div class="ws-link-box mono">{publicUrl(form)}</div>
            <div class="ws-side-actions">
              <button class="btn btn-sm" style="flex:1" on:click={() => copyText(publicUrl(form), '地址')}>{$i18n("复制链接")}</button>
              <a class="btn btn-sm" style="flex:1" href={publicUrl(form)} target="_blank" rel="noopener noreferrer">{$i18n("打开预览")}</a>
            </div>
            {#if configQr}<div class="ws-qr">{@html configQr}</div>{:else}<div class="ws-qr ws-qr-empty">{$i18n("地址过长，无法生成二维码")}</div>{/if}
            <div class="ws-qr-hint">{$i18n("扫码在手机上打开")}</div>
          </div>
          <div class="ws-side-card">
            <h4>{$i18n("概览")}</h4>
            <div class="ws-kv"><span>{$i18n("类型")}</span><b>{typeLabel(form.type)}</b></div>
            <div class="ws-kv"><span>{$i18n("监听")}</span><b>{listenLabel(form)}</b></div>
            {#if form.type === 'static' || form.type === 'share'}
              <div class="ws-kv"><span>{$i18n("目录")}</span><b class="ellip" title={form.root}>{form.root || '-'}</b></div>
            {/if}
            {#if form.type === 'share'}
              <div class="ws-kv"><span>{$i18n("访问路径")}</span><b>/s/{form.share.slug || 'share'}</b></div>
              <div class="ws-kv"><span>{$i18n("提取码")}</span><b>{form.share.access_code || i18nTr("无")}</b></div>
              <div class="ws-kv"><span>{$i18n("下载")}</span><b>{form.share.disable_download ? i18nTr("仅查看") : i18nTr("允许")}</b></div>
            {/if}
            {#if form.type === 'redirect'}
              <div class="ws-kv"><span>{$i18n("目标")}</span><b class="ellip" title={form.redirect_to}>{form.redirect_to || '-'}</b></div>
              <div class="ws-kv"><span>{$i18n("状态码")}</span><b>{form.redirect_code}</b></div>
            {/if}
            {#if form.type === 'text'}
              <div class="ws-kv"><span>{$i18n("状态码")}</span><b>{form.text_status}</b></div>
            {/if}
            {#if editing}
              <div class="ws-kv"><span>{$i18n("认证")}</span><b>{authLabel(editing) || i18nTr("关闭")}</b></div>
            {/if}
          </div>
          <div class="ws-side-card">
            <h4>{$i18n("说明")}</h4>
            <div class="tip-text">
              {#if form.type === 'share'}{$i18n("分享页会自动生成，支持在线预览、下载限制与统计。禁止下载时访客只能在线查看。")}{:else if form.type === 'static'}{$i18n("目录会直接发布为静态站点，可配置首页与目录浏览。")}{:else if form.type === 'redirect'}{$i18n("按状态码跳转，可选择保留原始路径与查询串。")}{:else}{$i18n("返回固定文本内容，适合公告、维护页或自定义状态码。")}{/if}
            </div>
          </div>
        </aside>
      </div>
      {/if}
    </div>

    <div slot="footer" style="display:flex;gap:8px;align-items:center">
      <span class="tip-text" style="margin-right:auto">
        {#if form.type === 'proxy'}
          {editing ? i18nTr("保存后如正在运行会自动重启；后端变更会立即生效") : i18nTr("保存后自动启动；后端变更会立即生效")}
        {:else}
          {editing ? i18nTr("保存后如正在运行会自动重启") : (form.type === 'share' ? i18nTr("保存后自动启动并生成分享页") : i18nTr("保存后自动启动"))}
        {/if}
      </span>
      <button class="btn" on:click={() => (showForm = false)} disabled={saving}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={save} disabled={saving}>{saving ? i18nTr("保存中…") : (form.type === 'proxy' ? i18nTr("保存并启动") : form.type === 'share' ? i18nTr("保存并发布") : i18nTr("保存"))}</button>
    </div>
  </Modal>
{/if}

<!-- 目录选择 -->
{#if showBrowse}
  <Modal title={$i18n("选择站点目录")} width={640} onClose={() => (showBrowse = false)}>
    <div class="ws-browse-bar">
      <button class="btn btn-sm" disabled={!browse.parent} on:click={() => loadBrowse(browse.parent)}>{$i18n("上级")}</button>
      <input class="ws-grow" type="text" bind:value={browseInput} on:keydown={(e) => { if (e.key === 'Enter') loadBrowse(browseInput); }} placeholder="/" />
      <button class="btn btn-sm" on:click={() => loadBrowse(browseInput)}>{$i18n("前往")}</button>
    </div>
    <div class="ws-browse-path mono">{browse.path || '/'}</div>
    {#if browseError}<div class="ws-error" style="margin-bottom:8px">{browseError}</div>{/if}
    <div class="ws-browse-list">
      {#if browseLoading}
        <div class="empty"><div class="empty-t">{$i18n("读取中…")}</div></div>
      {:else if !dirs.length}
        <div class="empty"><div class="empty-t">{$i18n("当前目录下没有子文件夹")}</div></div>
      {:else}
        {#each dirs as e (e.path)}
          <button class="ws-browse-item" on:click={() => loadBrowse(e.path)}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/></svg>
            <span class="ellip">{e.name}</span>
          </button>
        {/each}
      {/if}
    </div>
    <div slot="footer" style="display:flex;gap:8px;align-items:center">
      <span class="tip-text">{$i18n("将使用当前目录")}</span>
      <button class="btn" style="margin-left:auto" on:click={() => (showBrowse = false)}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={chooseDir} disabled={browseLoading || !browse.path}>{$i18n("选择当前目录")}</button>
    </div>
  </Modal>
{/if}

<!-- 访问日志 -->
{#if showLogs && logTarget}
  <Modal title={i18nTr("访问日志 · ") + logTarget.name} width={900} onClose={() => (showLogs = false)}>
    <div class="ws-logs-bar">
      <span class="tip-text" style="margin-right:auto">{$i18n("最近")} {logs.length} {$i18n("条 · 仅保存在内存中")}</span>
      <button class="btn btn-sm" on:click={refreshLogs} disabled={logsLoading}>{$i18n("刷新")}</button>
      <button class="btn btn-sm btn-danger" on:click={clearLogs} disabled={!logs.length}>{$i18n("清空")}</button>
    </div>
    {#if logsLoading}
      <div class="empty"><div class="empty-t">{$i18n("加载中…")}</div></div>
    {:else if !logs.length}
      <div class="empty"><div class="empty-t">{$i18n("暂无访问记录")}</div></div>
    {:else}
      <div class="table-wrap ws-log-table">
        <table>
          <thead><tr><th>{$i18n("时间")}</th><th>{$i18n("来源 IP")}</th><th>{$i18n("方法")}</th><th>{$i18n("路径")}</th><th>{$i18n("状态")}</th><th>{$i18n("大小")}</th><th>{$i18n("耗时")}</th></tr></thead>
          <tbody>
            {#each logs as l, i (i)}
              <tr>
                <td class="cell-dim">{l.time}</td>
                <td class="cell-mono">{l.ip}</td>
                <td class="cell-mono">{l.method}</td>
                <td class="cell-mono ws-log-path" title={l.path}>{l.path}</td>
                <td class={statusTone(l.status)}>{l.status}</td>
                <td class="cell-mono">{fmtBytes(l.bytes || 0)}</td>
                <td class="cell-mono">{l.ms || 0} ms</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </Modal>
{/if}

<!-- 访问记录（静态 / 反代 / 重定向 / 固定文本） -->
{#if showAccess && accessTarget}
  <Modal title={i18nTr("访问记录 · ") + accessTarget.name} width={960} onClose={() => (showAccess = false)}>
    <div class="ws-stats-kpis">
      <div class="ws-stat-card"><span>{$i18n("总请求")}</span><b>{accessTarget.requests || 0}</b><i>{$i18n("次")}</i></div>
      <div class="ws-stat-card"><span>{$i18n("总流量")}</span><b>{fmtBytes(accessTarget.bytes || 0)}</b><i>{$i18n("累计")}</i></div>
      <div class="ws-stat-card"><span>{$i18n("最近错误")}</span><b>{accessErrors}</b><i>4xx / 5xx</i></div>
      <div class="ws-stat-card"><span>{$i18n("平均耗时")}</span><b>{accessAvgMs}</b><i>ms</i></div>
    </div>

    {#if accessTarget.type === 'proxy' && accessTarget.proxy_status}
      <div class="ws-stats-card">
        <div class="ws-section-h" style="margin-top:0">{$i18n("后端健康状态")}</div>
        {#each accessTarget.proxy_status.backends as b (b.url)}
          <div class="ws-backend-status">
            <span class="mono ellip" style="flex:1;min-width:0" title={b.url}>{b.url}</span>
            <span class="badge" class:badge-info={b.healthy} class:badge-warn={!b.healthy && b.paused} class:badge-error={!b.healthy && !b.paused}>
              {b.healthy ? i18nTr("健康") : b.paused ? i18nTr("暂停") : i18nTr("不可用")}
            </span>
            <span>{$i18n("权重")} {b.weight}{b.backup ? i18nTr(" · 备用") : ''}</span>
            <span>{$i18n("连接")} {b.active}</span>
          </div>
        {/each}
      </div>
    {/if}

    {#if !accessTarget.access_log}
      <div class="ws-empty-inline">{$i18n("该服务未开启访问日志，仅显示累计请求数与流量。")}</div>
    {/if}

    <div class="ws-logs-bar">
      <span class="tip-text" style="margin-right:auto">{$i18n("最近")} {accessLogs.length} {$i18n("条 · 仅保存在内存中")}</span>
      <button class="btn btn-sm" on:click={refreshAccess} disabled={accessLoading}>{$i18n("刷新")}</button>
      <button class="btn btn-sm btn-danger" on:click={clearAccess} disabled={!accessLogs.length}>{$i18n("清空")}</button>
    </div>

    {#if accessLoading}
      <div class="empty"><div class="empty-t">{$i18n("加载中…")}</div></div>
    {:else if !accessLogs.length}
      <div class="empty"><div class="empty-t">{$i18n("暂无访问记录")}</div></div>
    {:else}
      <div class="table-wrap ws-log-table">
        <table>
          <thead><tr><th>{$i18n("时间")}</th><th>{$i18n("来源 IP")}</th><th>{$i18n("方法")}</th><th>{$i18n("路径")}</th><th>{$i18n("状态")}</th><th>{$i18n("大小")}</th><th>{$i18n("耗时")}</th></tr></thead>
          <tbody>
            {#each accessLogs as l, i (i)}
              <tr>
                <td class="cell-dim">{l.time}</td>
                <td class="cell-mono">{l.ip}</td>
                <td class="cell-mono">{l.method}</td>
                <td class="cell-mono ws-log-path" title={l.path}>{l.path}</td>
                <td class={statusTone(l.status)}>{l.status}</td>
                <td class="cell-mono">{fmtBytes(l.bytes || 0)}</td>
                <td class="cell-mono">{l.ms || 0} ms</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </Modal>
{/if}

{#if delTarget}
  <ConfirmModal
    title={$i18n("删除服务")}
    message={`确定删除「${delTarget.name}」？将停止该服务并删除配置，站点目录内的文件不会被删除。`}
    confirmText={$i18n("删除")}
    busy={deleting}
    onConfirm={confirmDelete}
    onClose={() => (delTarget = null)}
  />
{/if}

<style>
  .ws-filter-bar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px}
  .chips{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
  .chip{border:1px solid var(--bd);background:var(--bg3);color:var(--text3);border-radius:99px;padding:4px 11px;font-size:11.5px;display:inline-flex;align-items:center;gap:6px}
  .chip em{font-style:normal;font-family:var(--mono);font-size:10.5px;color:var(--text3)}
  .chip.active{color:var(--accent);border-color:rgba(var(--accent-rgb),.4);background:var(--accent-glow)}
  .chip.active em{color:var(--accent)}
  .hdr-search-wrap{margin-left:auto}
  .ws-card{background:var(--bg3);border:1px solid var(--bd);border-radius:calc(var(--radius) + 4px);padding:16px 18px;margin-bottom:16px;box-shadow:var(--shadow-card)}
  .ws-table{margin-bottom:16px}
  .ws-state{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--text2);white-space:nowrap}
  .dot{width:7px;height:7px;border-radius:50%;background:var(--text3);flex:none}
  .dot.on{background:var(--green);box-shadow:0 0 6px rgba(var(--green-rgb),.5)}
  .ws-name{font-size:13px;font-weight:600;color:var(--text);word-break:break-all}
  .ws-sub{font-size:10.5px;color:var(--text3);margin-top:3px;line-height:1.45}
  .ws-badges{display:flex;align-items:center;gap:5px;flex-wrap:wrap;margin-top:5px}
  .ws-url{font-family:var(--mono);font-size:11.5px;color:var(--accent);text-decoration:none;word-break:break-all}
  .ws-url:hover{text-decoration:underline}
  .ws-url.off{color:var(--text3)}
  .ws-target{display:block;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text2);font-size:11px}
  .ws-stat{display:flex;flex-direction:column;gap:2px;font-size:11px;color:var(--text2);font-family:var(--mono)}
  .ws-stat b{font-size:14px;color:var(--text)}
  .ws-stat i{font-style:normal;color:var(--text3);font-size:10px;font-family:var(--font)}
  .ws-error{font-size:11px;color:var(--red);margin-top:4px;word-break:break-all}
  .ws-err-badge{margin-top:4px}
  .ws-red{color:var(--red)}
  .ws-amber{color:var(--yellow)}

  .ws-form-tabs{display:flex;align-items:center;gap:4px;border-bottom:1px solid var(--bd);margin:-4px 0 16px;padding-bottom:8px}
  .ws-form-tabs button{border:1px solid transparent;background:none;color:var(--text3);font-size:12px;padding:6px 12px;border-radius:7px}
  .ws-form-tabs button.active{background:var(--accent-glow);color:var(--accent);border-color:rgba(var(--accent-rgb),.25)}
  .ws-type-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin-bottom:16px}
  .ws-type-card{display:flex;flex-direction:column;align-items:flex-start;gap:4px;padding:10px;border:1px solid var(--bd);border-radius:9px;background:var(--bg4);text-align:left;transition:.15s}
  .ws-type-card:hover{border-color:rgba(var(--accent-rgb),.4)}
  .ws-type-card.active{border-color:rgba(var(--accent-rgb),.55);background:var(--accent-glow)}
  .ws-type-ico{color:var(--accent);display:flex}
  .ws-type-card b{font-size:11.5px;color:var(--text)}
  .ws-type-card span{font-size:9.5px;color:var(--text3);line-height:1.4}
  .ws-section-h{font-size:12px;font-weight:650;color:var(--text2);margin:16px 0 9px;padding-top:12px;border-top:1px solid var(--sep)}
  .ws-section-h:first-child{margin-top:0;padding-top:0;border-top:none}
  .ws-textarea{width:100%;min-height:70px;border:1px solid var(--bd-strong);border-radius:7px;background:var(--bg2);padding:8px 10px;color:var(--text);font-size:12px;outline:none;resize:vertical;font-family:var(--font)}
  .ws-textarea:focus{border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-glow)}
  .ws-textarea.mono{font-family:var(--mono);font-size:11.5px}
  .ws-switch-row{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:10px 0;border-bottom:1px solid var(--sep)}
  .ws-switch-row:last-child{border-bottom:none}
  .ws-switch-title{font-size:12.5px;font-weight:600;color:var(--text)}
  .ws-switch-sub{font-size:11px;color:var(--text3);margin-top:2px;line-height:1.5}
  .ws-toggle-line{display:flex;align-items:center;gap:8px;height:34px;font-size:11.5px;color:var(--text3)}
  .ws-backend-row{display:grid;grid-template-columns:minmax(0,1fr) 74px 80px 30px;gap:7px;align-items:center;margin-bottom:7px}
  .ws-backend-row input[type=text],.ws-backend-row input[type=number]{height:32px;font-size:11.5px}
  .ws-check{display:flex;align-items:center;gap:5px;font-size:10.5px;color:var(--text3);white-space:nowrap}
  .ws-rule-row{display:grid;grid-template-columns:1.2fr 1fr 96px 66px 30px;gap:7px;align-items:center;margin-bottom:7px}
  .ws-rule-row input,.ws-rule-row select{height:32px;font-size:11px}
  .ws-rule-row-sec{grid-template-columns:1.1fr 100px 96px 1fr 30px}
  .ws-temp-row{display:grid;grid-template-columns:1.1fr 1fr 90px 100px 30px;gap:7px;align-items:center;margin-bottom:7px}
  .ws-temp-row input{height:32px;font-size:11px}
  .ws-temp-token{grid-column:1/-1;display:flex;align-items:center;gap:8px;font-size:10px;color:var(--text3);padding:0 2px 4px;flex-wrap:wrap}
  .ws-ban-row{display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--sep);font-size:11px}
  .ws-empty-inline{font-size:11px;color:var(--text3);padding:8px 0}
  .ws-browse-bar{display:flex;align-items:center;gap:8px;margin-bottom:10px}
  .ws-grow{flex:1;min-width:0}
  .ws-browse-path{padding:6px 10px;background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius);color:var(--text2);margin-bottom:10px;word-break:break-all;font-size:11px}
  .ws-browse-list{max-height:340px;overflow-y:auto;display:flex;flex-direction:column;gap:4px}
  .ws-browse-item{display:flex;align-items:center;gap:8px;width:100%;text-align:left;padding:9px 10px;border:1px solid transparent;border-radius:6px;background:none;color:var(--text2);font-size:13px}
  .ws-browse-item:hover{background:var(--bg4);border-color:var(--bd);color:var(--accent)}
  .ws-logs-bar{display:flex;align-items:center;gap:8px;margin-bottom:12px}
  .ws-log-table{max-height:420px;overflow:auto;border-radius:var(--radius)}
  .ws-log-path{max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .ws-stats-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:14px}
  .ws-stat-card{background:var(--bg3);border:1px solid var(--bd);border-radius:10px;padding:13px 14px;box-shadow:var(--shadow-card)}
  .ws-stat-card span{display:block;font-size:10.5px;color:var(--text3)}
  .ws-stat-card b{display:block;font-size:22px;font-family:var(--mono);font-weight:700;margin-top:6px;letter-spacing:-.02em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .ws-stat-card i{display:block;font-style:normal;font-size:10.5px;color:var(--text3);margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .ws-stats-card{background:var(--bg3);border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-bottom:14px;box-shadow:var(--shadow-card)}
  .ws-rank-row{display:flex;align-items:center;gap:9px;padding:8px 0;border-bottom:1px solid var(--sep);font-size:11.5px}
  .ws-rank-row:last-child{border-bottom:none}
  .ws-rank-no{width:18px;height:18px;border-radius:5px;background:var(--bg4);color:var(--text3);font-family:var(--mono);font-size:10px;display:flex;align-items:center;justify-content:center;flex:none}
  .ws-rank-name{flex:0 1 36%;min-width:0;color:var(--text2)}
  .ws-rank-bar{flex:1;height:5px;border-radius:3px;background:var(--bg4);overflow:hidden;min-width:30px}
  .ws-rank-bar i{display:block;height:100%;border-radius:3px;background:linear-gradient(90deg,rgba(var(--accent-rgb),.5),var(--accent))}
  .ws-rank-num{font-family:var(--mono);font-size:10.5px;color:var(--text3);white-space:nowrap}
  .ws-result-ok{color:var(--green);font-size:10.5px}
  .ws-seg-inline{width:auto;flex:none}
  .ws-seg-inline button{flex:none;padding:5px 11px;font-size:12px}
  .ws-bars{display:flex;align-items:flex-end;gap:10px;height:130px;padding-top:8px}
  .ws-bar-item{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%;gap:3px;min-width:0}
  .ws-bar-val{font-size:9px;color:var(--text3);font-family:var(--mono)}
  .ws-bar{width:100%;max-width:42px;background:linear-gradient(180deg,var(--accent),rgba(var(--accent-rgb),.2));border-radius:3px 3px 0 0;min-height:4px}
  .ws-bar-label{font-size:9px;color:var(--text3);font-family:var(--mono)}
  .ws-stats-list{display:flex;flex-direction:column}
  .ws-stats-row{display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--sep);font-size:10.5px;color:var(--text3)}
  .ws-stats-row:last-child{border-bottom:none}
  .ws-backend-status{display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--sep);font-size:10.5px;color:var(--text3)}
  .ws-backend-status:last-child{border-bottom:none}
  .ws-console-types{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin-bottom:14px}
  .ws-console-type{display:flex;align-items:flex-start;gap:10px;padding:11px 12px;border:1px solid var(--bd);border-radius:10px;background:var(--bg3);text-align:left;transition:.16s}
  .ws-console-type:hover{border-color:rgba(var(--accent-rgb),.45);transform:translateY(-1px);box-shadow:var(--shadow-card)}
  .ws-console-ico{width:30px;height:30px;border-radius:8px;background:var(--accent-glow);color:var(--accent);display:flex;align-items:center;justify-content:center;flex:none}
  .ws-console-type.t-cyan .ws-console-ico{background:rgba(var(--cyan-rgb),.1);color:var(--cyan)}
  .ws-console-type.t-violet .ws-console-ico{background:rgba(var(--violet-rgb),.1);color:var(--violet)}
  .ws-console-type.t-blue .ws-console-ico{background:rgba(var(--blue-rgb),.1);color:var(--blue)}
  .ws-console-type.t-orange .ws-console-ico{background:rgba(var(--orange-rgb),.1);color:var(--orange)}
  .ws-console-type.t-slate .ws-console-ico{background:rgba(var(--slate-rgb),.1);color:var(--slate)}
  .ws-console-text{min-width:0;display:flex;flex-direction:column;gap:2px}
  .ws-console-text b{font-size:12px;color:var(--text);white-space:nowrap}
  .ws-console-text span{font-size:10px;color:var(--text3);line-height:1.4}
  .ws-console-arrow{margin-left:auto;color:var(--text3);flex:none;align-self:center}
  .ws-console-type:hover .ws-console-arrow{color:var(--accent)}
  .ws-type-tabs{display:flex;align-items:center;gap:6px;border-bottom:1px solid var(--sep);margin:-4px 0 16px;padding-bottom:0;overflow-x:auto}
  .ws-type-tabs button{display:flex;align-items:center;gap:7px;border:1px solid transparent;border-bottom:none;border-radius:8px 8px 0 0;background:none;color:var(--text3);font-size:11.5px;font-weight:600;padding:8px 12px;white-space:nowrap;position:relative;top:1px}
  .ws-type-tabs button.active{background:var(--bg3);border-color:var(--bd);border-bottom-color:var(--bg3);color:var(--text)}
  .ws-dot-t{width:6px;height:6px;border-radius:50%;background:var(--text3);flex:none}
  .ws-dot-t.t-cyan{background:var(--cyan)}
  .ws-dot-t.t-violet{background:var(--violet)}
  .ws-dot-t.t-blue{background:var(--blue)}
  .ws-dot-t.t-orange{background:var(--orange)}
  .ws-dot-t.t-slate{background:var(--slate)}
  .ws-config-grid{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:18px;align-items:start}
  .ws-config-form{min-width:0}
  .ws-config-side{min-width:0;display:flex;flex-direction:column;gap:12px}
  .ws-side-card{background:var(--bg3);border:1px solid var(--bd);border-radius:10px;padding:13px}
  .ws-side-card h4{margin:0 0 9px;font-size:11.5px;color:var(--text2);font-weight:650}
  .ws-link-box{background:var(--bg2);border:1px solid var(--bd);border-radius:7px;padding:8px 10px;font-size:10.5px;color:var(--accent);word-break:break-all;line-height:1.5}
  .ws-side-actions{display:flex;gap:6px;margin-top:8px}
  .ws-qr{width:104px;height:104px;margin:12px auto 0;border-radius:8px;background:#fff;padding:5px;display:flex;align-items:center;justify-content:center;overflow:hidden}
  .ws-qr :global(svg){width:100%;height:100%;display:block}
  .ws-qr-empty{background:var(--bg3);border:1px dashed var(--bd);color:var(--text3);font-size:10px;line-height:1.5;text-align:center;padding:10px}
  .ws-qr-hint{text-align:center;margin-top:6px;font-size:10px;color:var(--text3)}
  .ws-seg{display:flex;border:1px solid var(--bd);border-radius:7px;overflow:hidden;width:100%}
  .ws-seg button{flex:1;border:none;background:var(--bg2);color:var(--text3);font-size:11px;padding:7px 4px;white-space:nowrap}
  .ws-seg button + button{border-left:1px solid var(--bd)}
  .ws-seg button.active{background:var(--accent-glow);color:var(--accent);font-weight:600}
  .ws-code-input{letter-spacing:3px;text-align:center;text-transform:uppercase;font-family:var(--mono)}
  .ws-kv{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;padding:5px 0;border-bottom:1px solid var(--sep);font-size:10.5px;color:var(--text3)}
  .ws-kv:last-child{border-bottom:none}
  .ws-kv b{color:var(--text2);font-weight:500;text-align:right;max-width:170px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  :global(.modal-body.ws-proxy-body){padding:0}
  .ws-proxy-shell{display:flex;flex-direction:column;min-height:0}
  .ws-proxy-shell .ws-type-tabs{margin:0;padding:12px 18px 0;border-bottom:1px solid var(--sep)}
  .ws-proxy-grid{display:grid;grid-template-columns:164px minmax(0,1fr) 274px;grid-template-rows:minmax(0,1fr);gap:0;align-items:stretch;height:clamp(420px,calc(86vh - 160px),592px)}
  .ws-config-layout{grid-template-columns:164px minmax(0,1fr) 300px}
  .ws-proxy-nav{display:flex;flex-direction:column;gap:3px;padding:12px 8px;background:var(--bg2);border:none;border-right:1px solid var(--bd);border-radius:0;overflow-y:auto}
  .ws-proxy-nav button{display:flex;align-items:center;gap:8px;width:100%;text-align:left;background:none;border:none;border-radius:7px;padding:8px 10px;color:var(--text3);font-size:11.5px;line-height:1.4}
  .ws-proxy-nav button:hover{background:var(--bg4);color:var(--text2)}
  .ws-proxy-nav button.active{background:var(--accent-glow);color:var(--accent);font-weight:600}
  .ws-proxy-main{min-width:0;padding:15px 17px;overflow-y:auto}
  .ws-proxy-grid .ws-config-side{padding:15px 17px 8px;gap:10px;overflow-y:auto}
  .ws-proxy-main .ws-section-h:first-child{margin-top:0;padding-top:0;border-top:none}
  .ws-cfg-card{background:var(--bg3);border:1px solid var(--bd);border-radius:9px;padding:13px;margin-bottom:11px}
  .ws-cfg-card:last-child{margin-bottom:0}
  .ws-cfg-card h4{font-size:11.5px;font-weight:650;color:var(--text2);margin:0 0 9px;display:flex;align-items:center;gap:7px}
  .ws-cfg-right{margin-left:auto;font-size:10px;color:var(--text3);font-weight:400}
  .ws-sec-grid{display:grid;grid-template-columns:1.08fr .92fr;gap:14px;align-items:start}
  .ws-sec-col{display:flex;flex-direction:column;gap:12px;min-width:0}
  .ws-sec-card{background:var(--bg3);border:1px solid var(--bd);border-radius:10px;padding:14px;box-shadow:var(--shadow-card)}
  .ws-sec-head{display:flex;align-items:center;gap:8px;margin-bottom:10px}
  .ws-sec-head h3{font-size:12.5px;font-weight:650;color:var(--text);margin:0;display:flex;align-items:center;gap:7px;flex:1;min-width:0}
  .ws-sec-right{margin-left:auto;font-size:10px;color:var(--text3);font-weight:400;white-space:nowrap}
  .ws-mini-head{display:grid;grid-template-columns:1.1fr 100px 96px 1fr 30px;gap:7px;padding:6px 0 8px;border-bottom:1px solid var(--sep);margin-bottom:6px;font-size:9.5px;color:var(--text3)}
  .ws-sec-head .btn{margin-left:auto}
  .ws-event-row{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--sep);font-size:10.5px;color:var(--text3)}
  .ws-event-row:last-child{border-bottom:none}
  .ws-stats-grid2{display:grid;grid-template-columns:1.15fr .85fr;gap:14px}
  .ws-stats-grid2 .ws-stats-card{margin-bottom:0}
  .ws-select{height:34px;min-width:190px;border:1px solid var(--bd-strong);border-radius:7px;background-color:var(--bg2);color:var(--text);font-size:11.5px;padding:0 30px 0 10px;outline:none;max-width:280px;cursor:pointer;color-scheme:dark;-webkit-appearance:none;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%238094ab' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 9px center;transition:border-color .15s,box-shadow .15s}
  .ws-select:hover{border-color:rgba(77,214,255,.45)}
  .ws-select:focus{border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-glow)}
  .ws-select option{background:#0d151f;color:#e6eef8}
  .ws-select option:checked{background:rgba(77,214,255,.18);color:#e6eef8}
  .list-cards{display:none}
  @media (max-width:1100px){
    .ws-console-types{grid-template-columns:repeat(3,minmax(0,1fr))}
    .ws-proxy-grid{grid-template-columns:140px minmax(0,1fr);grid-template-rows:auto;height:auto;max-height:none}
    .ws-proxy-grid .ws-config-side{grid-column:1/-1;display:grid;grid-template-columns:1fr 1fr}
  }
  @media (max-width:900px){
    .ws-type-grid{grid-template-columns:repeat(3,minmax(0,1fr))}
    .ws-config-grid{grid-template-columns:1fr}
    .ws-config-side{display:grid;grid-template-columns:1fr 1fr}
    .ws-sec-grid{grid-template-columns:1fr}
    .ws-proxy-grid{grid-template-columns:1fr;grid-template-rows:auto;height:auto;max-height:none}
    .ws-proxy-nav{flex-direction:row;overflow-x:auto;border-right:none;border-bottom:1px solid var(--bd)}
    .ws-proxy-nav button{min-width:130px}
    .ws-proxy-grid .ws-config-side{display:flex;grid-column:auto;padding:0 17px 17px}
  }
  @media (max-width:600px){
    .ws-console-types{grid-template-columns:1fr 1fr}
    .ws-config-side{display:flex}
    .ws-stats-grid2{grid-template-columns:1fr}
    .ws-proxy-nav button{min-width:110px}
    .ws-select{max-width:100%}
    .ws-filter-bar{gap:8px}
    .hdr-search-wrap{margin-left:0;width:100%}
    .ws-table{display:none}
    .list-cards{display:grid;grid-template-columns:1fr;gap:10px}
    .ws-type-grid{grid-template-columns:1fr 1fr}
    .ws-backend-row{grid-template-columns:1fr 1fr 26px}
    .ws-backend-row input:first-child{grid-column:1/-1}
    .ws-rule-row,.ws-rule-row-sec{grid-template-columns:1fr 1fr 26px}
    .ws-rule-row input:first-child,.ws-rule-row-sec input:first-child{grid-column:1/-1}
    .ws-temp-row{grid-template-columns:1fr 1fr 26px}
    .ws-temp-row input:first-child{grid-column:1/-1}
    .ws-temp-row .ws-temp-token{grid-column:1/-1}
    .ws-mini-head{display:none}
    .ws-stats-kpis{grid-template-columns:1fr 1fr}
  }
</style>
