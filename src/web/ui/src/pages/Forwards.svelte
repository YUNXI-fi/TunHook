<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 端口转发列表页
  import { onMount, onDestroy } from 'svelte';
  import { forwards, settings, status, toast, forwardPrefill } from '../lib/stores.js';
  import { api, apiBase } from '../lib/api.js';
  import { fmtBytes, fmtRate, protoLabel, parseFwdKey, suggestDescription, localHost, highlightLog, pollVisible, reverseLines } from '../lib/utils.js';
  import ForwardModal from '../components/ForwardModal.svelte';
  import PortScanModal from '../components/PortScanModal.svelte';
  import LogModal from '../components/LogModal.svelte';
  import FrpcLogModal from '../components/FrpcLogModal.svelte';
  import Modal from '../components/Modal.svelte';
  import TrafficModal from '../components/TrafficModal.svelte';
  import ConfirmModal from '../components/ConfirmModal.svelte';

  let search = '';
  let protoFilter = 'all';
  const PROTO_FILTERS = [
    { value: 'all', label: i18nTr("全部协议") },
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
    { value: 'http', label: 'HTTP / HTTPS' },
    { value: 'gateway', label: i18nTr("统一网关") }
  ];

  let showCreate = false;
  let showEdit = false;
  let editingRule = null;
  let showPortScan = false;
  let createPrefill = null; // 端口扫描结果 → 创建表单预填
  let logTarget = null;
  let trafficTarget = null;
  let delTarget = null;
  let delBusy = false;
  let timer;

  function ruleProto(r) {
    return String(r.protocol || parseFwdKey(r.key).protocol || '').toLowerCase();
  }

  // status 作为依赖参数：本地 IPv4 变化时重建列表，同步刷新转发地址中替换后的本地 IPv4
  $: list = buildList($forwards || [], search, $status).filter((r) => {
    if (protoFilter === 'all') return true;
    const p = ruleProto(r);
    return protoFilter === 'http' ? (p === 'http' || p === 'https') : p === protoFilter;
  });
  $: runningCount = list.filter((r) => r.running).length;

  // 端口扫描页「创建转发规则」跳转：取到预填即打开创建弹窗并清空来源，避免重复触发
  $: if ($forwardPrefill) {
    createPrefill = $forwardPrefill;
    forwardPrefill.set(null);
    showCreate = true;
  }

  function buildList(fwds, q, st) {
    const qq = q.trim().toLowerCase();
    return (fwds || []).filter((r) => {
      if (qq && !r.key.toLowerCase().includes(qq) && !(r.description || '').toLowerCase().includes(qq)) return false;
      return true;
    }).sort((a, b) => String(a.key).localeCompare(String(b.key)));
  }

  // 判断一个 IPv4 字符串是否为公网可路由地址
  // 排除：0.0.0.0、127.x、10.x、172.16-31.x、192.168.x、169.254.x、100.64-127.x(CGNAT)
  function isPublicIPv4(s) {
    const m = String(s || '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return false;
    const a = parseInt(m[1]), b = parseInt(m[2]);
    if (a === 0 || a === 127) return false;
    if (a === 10) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT 100.64.0.0/10（首字节恒 100）
    return true;
  }

  function fwdUrl(r) {
    const pk = parseFwdKey(r.key);
    if (pk.protocol === 'gateway') return apiBase + '/proxy/' + pk.name;
    if (pk.protocol === 'http' || pk.protocol === 'https') return pk.protocol + '://' + pk.local + '/' + pk.domain;
    // Cloudflare 回源闸门只监听回环，不能被局域网其他设备直连，因此不做局域网 IP 替换（换掉就指向了一个没人监听的地址）
    if (pk.protocol === 'cloudflare') return pk.local;
    // TCP/UDP
    const i = pk.local.lastIndexOf(':');
    const host = i > 0 ? pk.local.slice(0, i) : pk.local;
    const port = i > 0 ? pk.local.slice(i + 1) : '';
    // 公网 IP 直接用（用户明确绑的有公网 IP 的网卡）；通配/回环/内网 IP 按原逻辑替换为局域网 IP
    const addr = (isPublicIPv4(host) ? host : localHost(host, ($status && $status.local_ip) || '')) + ':' + port;
    // TCP+HTTPS（自签名证书）规则以 TLS 方式监听，地址需带 https:// 前缀才能直达
    return r.tls ? 'https://' + addr : addr;
  }

  // 目标地址列：pk.remote 形如 host:port（host 可能省略，如 :1314 表示本机），
  // 回环/空主机替换为局域网 IP 后拼可直达的 http 地址
  function remoteUrl(r) {
    const pk = parseFwdKey(r.key);
    if (!pk.remote) return '';
    const i = pk.remote.lastIndexOf(':');
    const host = i >= 0 ? pk.remote.slice(0, i) : pk.remote;
    const port = i >= 0 ? pk.remote.slice(i + 1) : '';
    return 'http://' + localHost(host, ($status && $status.local_ip) || '') + (port ? ':' + port : '');
  }

  async function load() {
    try {
      const d = await api('/api/forward/list');
      if (d) forwards.set(d);
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function toggleRule(r) {
    try {
      await api('/api/forward/toggle', { method: 'POST', body: { key: r.key } });
      toast(r.running ? i18nTr("转发已暂停: ") + r.key : i18nTr("转发已启动: ") + r.key, 'success');
      load();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function confirmDelete() {
    delBusy = true;
    try {
      await api('/api/forward/stop', { method: 'POST', body: { key: delTarget.key } });
      toast(i18nTr("转发已删除: ") + delTarget.key, 'success');
      delTarget = null;
      load();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      delBusy = false;
    }
  }

  function openEdit(r) {
    editingRule = r;
    showEdit = true;
  }

  // 系统转发的来源标识（徽章样式 / 文案 / 指路提示）：以后新增来源只改这一处
  const SOURCE_META = {
    stun: { label: 'STUN', badge: 'badge-on', tip: i18nTr("系统自动生成的 STUN 打洞转发，请到「STUN」页面管理"), logTitle: i18nTr("查看 STUN 通道日志") },
    frpc: { label: 'FRPC', badge: 'badge-warn', tip: i18nTr("系统自动生成的内网穿透转发，请到「代理列表」页面管理"), logTitle: i18nTr("查看 frpc 通道日志") },
    cloudflare: { label: 'Cloudflare', badge: 'badge-info', tip: i18nTr("系统自动生成的 Cloudflare 隧道回源转发，请到「Cloudflare Tunnel」页面管理"), logTitle: i18nTr("查看该实例的内核日志") }
  };
  function srcMeta(r) { return SOURCE_META[r.source] || SOURCE_META.frpc; }
  function sysTip(r) { return r.system ? srcMeta(r).tip : ''; }

  // Cloudflare 回源闸门没有走持久化日志库，它的日志是内核日志，单独取
  let cfLog = null;
  let cfLogText = '';
  let cfLogBusy = false;
  async function loadCfLog() {
    if (!cfLog) return;
    cfLogBusy = true;
    try {
      const d = await api('/api/cloudflare/instances/' + cfLog.id + '/log');
      cfLogText = reverseLines((d && d.log) || i18nTr("（暂无日志）"));
    } catch (e) {
      cfLogText = i18nTr("加载失败：") + e.message;
    } finally {
      cfLogBusy = false;
    }
  }

  // 打开日志：用户规则走转发日志；系统转发按来源打开对应通道日志
  // （STUN 走 /api/logs?stunhole=通道ID，内网穿透走 frpc.log，Cloudflare 走该实例的内核日志）
  function openLog(r) {
    if (r.system && r.source === 'frpc') {
      logTarget = { kind: 'frpc', id: r.ref };
      return;
    }
    if (r.system && r.source === 'cloudflare') {
      cfLog = { id: r.ref, title: r.description || i18nTr("Cloudflare 隧道回源") };
      cfLogText = '';
      loadCfLog();
      return;
    }
    logTarget = { kind: r.system ? 'stunhole' : 'forward', id: r.system ? r.ref : r.key };
  }

  // 启停按钮着色：运行中=绿 / 未运行=灰（与 Tunnels 页面的启停按钮保持一致）
  function ruleColor(r) {
    return r.running ? 'var(--green)' : 'var(--text3)';
  }

  onMount(() => {
    load();
    timer = pollVisible(load, 5000);
  });
  onDestroy(() => timer && timer());
</script>

<div class="container page-full page-list">
  <div class="page-hdr">
    <div>
      <h2>{$i18n("转发列表")}</h2>
      <span class="page-hdr-sub">{$i18n("TCP / UDP / HTTP 端口转发与统一网关规则")}</span>
    </div>
    <div class="page-hdr-actions">
      <div class="hdr-search-wrap">
        <svg class="hdr-search-icon" width="15" height="15" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M21 38C30.3888 38 38 30.3888 38 21C38 11.6112 30.3888 4 21 4C11.6112 4 4 11.6112 4 21C4 30.3888 11.6112 38 21 38Z"/><path d="M33.2216 33.2217L41.7069 41.707" stroke-linecap="round"/></svg>
        <input type="text" class="hdr-search" bind:value={search} placeholder={$i18n("搜索描述 / 转发地址")} />
      </div>
      <div class="hdr-btn-group">
        <button class="btn" title={$i18n("扫描端口")} on:click={() => (showPortScan = true)}>
          <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="24" r="18"/><circle cx="24" cy="24" r="10"/><path d="M24 24L35 13"/><circle cx="24" cy="24" r="3" fill="currentColor" stroke="none"/><circle cx="32" cy="15" r="2.5" fill="currentColor" stroke="none"/></svg>
          <span class="sm-hide">{$i18n("扫描端口")}</span>
        </button>
        <button class="btn btn-primary" title={$i18n("添加规则")} on:click={() => { createPrefill = null; showCreate = true; }}>
          <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="24" r="20"/><path d="M24 16V32"/><path d="M16 24H32"/></svg>
          <span class="sm-hide">{$i18n("添加规则")}</span>
        </button>
      </div>
    </div>
  </div>

  <div class="proto-chips">
    {#each PROTO_FILTERS as f (f.value)}
      <button class="proto-chip" class:active={protoFilter === f.value} on:click={() => (protoFilter = f.value)}>{f.label}</button>
    {/each}
  </div>

  <div class="table-wrap">
    <div style="overflow-y:auto;flex:1">
    <table>
      <thead>
        <tr>
          <th style="width:50px">ID</th>
          <th>{$i18n("描述")}</th>
          <th>{$i18n("转发地址")}</th>
          <th>{$i18n("目标地址")}</th>
          <th style="width:70px">{$i18n("协议")}</th>
          <th style="width:90px">{$i18n("来源")}</th>
          <th>{$i18n("实时速率")}</th>
          <th style="width:190px">{$i18n("操作")}</th>
        </tr>
      </thead>
      <tbody>
        {#each list as r}
          {@const pk = parseFwdKey(r.key)}
          <tr>
            <td class="cell-id">{r.key.split('://')[0] === 'gateway' ? pk.name : (r.uuid ? r.uuid.slice(0, 6) : '-')}</td>
            <td>
              <span class="fwd-name">
                <span class="fwd-dot" style="background:{r.running ? 'var(--green)' : 'var(--text3)'}" title={r.running ? i18nTr("运行中") : i18nTr("已停止")}></span>
                {#if r.description}{r.description}{:else}<span style="color:var(--text3)">-</span>{/if}
              </span>
            </td>
            <td>
              <!-- 转发地址是转发规则的本机监听地址，仅作展示：不做成链接，
                   回环/通配监听与系统行的内部地址点开未必可达，对外出口在「代理地址」列 -->
              <span class="cell-addr">
                {#if pk.protocol === 'http' || pk.protocol === 'https'}
                  {pk.protocol + '://' + pk.local + '/' + pk.domain}
                {:else}
                  {fwdUrl(r)}
                {/if}
              </span>
            </td>
            <td class="cell-mono">
              {#if pk.remote}
                {@const rUrl = remoteUrl(r)}
                <a class="cell-link cell-link-btn" href={rUrl} target="_blank" rel="noopener noreferrer" title={$i18n("点击新页面打开 {0}", [rUrl])}>{rUrl.replace(/^http:\/\//, '')}</a>
              {:else}
                -
              {/if}
            </td>
            <td>
              <span class="badge badge-off">{protoLabel(r.protocol || pk.protocol)}{r.tls ? ' TLS' : ''}</span>
            </td>
            <td>
              {#if r.system}
                <span class="badge {srcMeta(r).badge}">{srcMeta(r).label}</span>
              {:else}
                <span style="color:var(--text3)">{$i18n("手动")}</span>
              {/if}
            </td>
            <td class="cell-mono">
              <button type="button" class="cell-stats-btn" title={$i18n("点击查看流量统计详情")} on:click={() => (trafficTarget = r)}>
                <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">↑</span><span style="color:var(--text2)">{fmtRate(r.tx_rate || 0)}</span></span>
                <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">↓</span><span style="color:var(--text2)">{fmtRate(r.rx_rate || 0)}</span></span>
                <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">⇄</span><span style="color:var(--text2)">TCP {r.tcp_conns || 0} UDP {r.udp_conns || 0}</span></span>
              </button>
            </td>
            <td>
              <div class="cell-actions">
                <button class="btn-icon" title={r.system ? sysTip(r) : (r.running ? i18nTr("暂停") : i18nTr("启动"))} aria-label={r.running ? i18nTr("暂停") : i18nTr("启动")} disabled={r.system} on:click={() => toggleRule(r)}>
                  <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke={ruleColor(r)} stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M24 4V24" stroke={ruleColor(r)} stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>
                <button class="btn-icon" title={r.system ? srcMeta(r).logTitle : i18nTr("查看日志")} aria-label={$i18n("查看日志")} on:click={() => openLog(r)}>
                  <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><rect x="13" y="10" width="28" height="34" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M35 10V4H8C7.44772 4 7 4.44772 7 5V38H13" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 22H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 30H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>
                <button class="btn-icon" title={r.system ? sysTip(r) : i18nTr("编辑")} aria-label={$i18n("编辑")} disabled={r.system} on:click={() => openEdit(r)}>
                  <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M10 44H38C39.1046 44 40 43.1046 40 42V14H30V4H10C8.89543 4 8 4.89543 8 6V42C8 43.1046 8.89543 44 10 44Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M30 4L40 14" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 35L31 25L27 21L17 31V35H21Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>
                <button class="btn-icon" style="color:var(--red)" title={r.system ? sysTip(r) : i18nTr("删除")} aria-label={$i18n("删除")} disabled={r.system} on:click={() => (delTarget = r)}>
                  <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>
              </div>
            </td>
          </tr>
        {:else}
          <tr>
            <td colspan="8">
              <div class="empty">
                <svg width="40" height="40" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="margin:0 auto 10px;display:block;color:var(--text3)"><path d="M5 24L43 24"/><path d="M28 4H20C18.8954 4 18 4.89543 18 6V14C18 15.1046 18.8954 16 20 16H28C29.1046 16 30 15.1046 30 14V6C30 4.89543 29.1046 4 28 4Z"/><path d="M16 32H8C6.89543 32 6 32.8954 6 34V42C6 43.1046 6.89543 44 8 44H16C17.1046 44 18 43.1046 18 42V34C18 32.8954 17.1046 32 16 32Z"/><path d="M40 32H32C30.8954 32 30 32.8954 30 34V42C30 43.1046 30.8954 44 32 44H40C41.1046 44 42 43.1046 42 42V34C42 32.8954 41.1046 32 40 32Z"/><path d="M24 24V16"/><path d="M36 32V24"/><path d="M12 32V24"/></svg>
                <div class="empty-t">{$i18n("暂无转发规则，点击\"添加规则\"创建")}</div>
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
  </div>

  <div class="list-cards">
    {#if list.length === 0}
      <div class="list-cards-empty">{$i18n("暂无转发规则，点击\"添加规则\"创建")}</div>
    {/if}
    {#each list as r}
      {@const pk = parseFwdKey(r.key)}
      {@const idText = r.key.split('://')[0] === 'gateway' ? pk.name : (r.uuid ? r.uuid.slice(0, 6) : '-')}
      {@const title = r.description || idText}
      <div class="list-card" on:click={() => { if (!r.system) openEdit(r); }}>
        <div class="list-card-top">
          <div class="list-card-avatar">{(title || '?').charAt(0).toUpperCase()}</div>
          <div class="list-card-title"><span class="fwd-dot" style="background:{r.running ? 'var(--green)' : 'var(--text3)'}"></span><span class="ellip">{title}</span></div>
        </div>
        <div class="list-card-sub">
          <span class="cell-mono" style="color:var(--accent);font-size:11px">{idText}</span>
          <span class="badge badge-off">{protoLabel(r.protocol || pk.protocol)}{r.tls ? ' TLS' : ''}</span>
          {#if r.system}
            <span class="badge {srcMeta(r).badge}">{srcMeta(r).label}</span>
          {:else}
            <span style="color:var(--text3)">{$i18n("手动")}</span>
          {/if}
        </div>
        <div class="list-card-rows" on:click={(e) => e.stopPropagation()}>
          <div class="list-card-row">
            <span class="k">{$i18n("转发地址")}</span>
            <span class="v">
              {#if pk.protocol === 'http' || pk.protocol === 'https'}
                <span class="ellip">{pk.protocol + '://' + pk.local + '/' + pk.domain}</span>
              {:else}
                <span class="ellip">{fwdUrl(r)}</span>
              {/if}
            </span>
          </div>
          <div class="list-card-row">
            <span class="k">{$i18n("目标地址")}</span>
            <span class="v cell-mono">
              {#if pk.remote}
                {@const rUrl = remoteUrl(r)}
                <span class="ellip"><a class="cell-link cell-link-btn" href={rUrl} target="_blank" rel="noopener noreferrer" title={$i18n("点击新页面打开 {0}", [rUrl])}>{rUrl.replace(/^http:\/\//, '')}</a></span>
              {:else}
                -
              {/if}
            </span>
          </div>
          <div class="list-card-row">
            <span class="k">{$i18n("实时速率")}</span>
            <span class="v">
              <button type="button" class="cell-stats-btn" title={$i18n("点击查看流量统计详情")} on:click={() => (trafficTarget = r)}>
                <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">↑</span><span style="color:var(--text2)">{fmtRate(r.tx_rate || 0)}</span></span>
                <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">↓</span><span style="color:var(--text2)">{fmtRate(r.rx_rate || 0)}</span></span>
                <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">⇄</span><span style="color:var(--text2)">TCP {r.tcp_conns || 0} UDP {r.udp_conns || 0}</span></span>
              </button>
            </span>
          </div>
        </div>
        <div class="list-card-actions" on:click={(e) => e.stopPropagation()}>
          <button class="btn-icon" title={r.system ? sysTip(r) : (r.running ? i18nTr("暂停") : i18nTr("启动"))} aria-label={r.running ? i18nTr("暂停") : i18nTr("启动")} disabled={r.system} on:click={() => toggleRule(r)}>
            <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M14.5 8C13.8406 8.37652 13.2062 8.79103 12.6 9.24051C11.5625 10.0097 10.6074 10.8814 9.75 11.8402C6.79377 15.1463 5 19.4891 5 24.2455C5 34.6033 13.5066 43 24 43C34.4934 43 43 34.6033 43 24.2455C43 19.4891 41.2062 15.1463 38.25 11.8402C37.3926 10.8814 36.4375 10.0097 35.4 9.24051C34.7938 8.79103 34.1594 8.37652 33.5 8" stroke={ruleColor(r)} stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M24 4V24" stroke={ruleColor(r)} stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </button>
          <!-- 日志按钮与表格操作列同序（启停 → 日志 → 编辑 → 删除），title 按来源给出对应通道 -->
          <button class="btn-icon" title={r.system ? srcMeta(r).logTitle : i18nTr("查看日志")} aria-label={$i18n("查看日志")} on:click={() => openLog(r)}>
            <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><rect x="13" y="10" width="28" height="34" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M35 10V4H8C7.44772 4 7 4.44772 7 5V38H13" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 22H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 30H33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </button>
          <button class="btn-icon" title={r.system ? sysTip(r) : i18nTr("编辑")} aria-label={$i18n("编辑")} disabled={r.system} on:click={() => openEdit(r)}>
            <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M10 44H38C39.1046 44 40 43.1046 40 42V14H30V4H10C8.89543 4 8 4.89543 8 6V42C8 43.1046 8.89543 44 10 44Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M30 4L40 14" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 35L31 25L27 21L17 31V35H21Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </button>
          <button class="btn-icon" style="color:var(--red)" title={r.system ? sysTip(r) : i18nTr("删除")} aria-label={$i18n("删除")} disabled={r.system} on:click={() => (delTarget = r)}>
            <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/><path d="M20 25L28 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 25L20 33" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </button>
        </div>
      </div>
    {/each}
  </div>

  <div class="fwd-foot">
    <span>{$i18n("共")} {list.length} {$i18n("条 ·")} <span style="color:var(--green)">{runningCount} {$i18n("条运行中")}</span></span>
    <span class="fwd-foot-note">{$i18n("统一网关规则由系统托管")}</span>
  </div>
</div>

{#if showCreate}
  <ForwardModal mode="create" prefill={createPrefill} settingsData={$settings} onClose={() => (showCreate = false)} onSaved={load} />
{/if}
{#if showEdit && editingRule}
  <ForwardModal mode="edit" rule={editingRule} settingsData={$settings} onClose={() => { showEdit = false; editingRule = null; }} onSaved={load} />
{/if}
{#if showPortScan}
  <PortScanModal onClose={() => (showPortScan = false)} onPick={(it) => {
    createPrefill = {
      protocol: it.protocol && String(it.protocol).toLowerCase().startsWith('udp') ? 'udp' : 'tcp',
      local_port: it.port,
      local_addr: it.local_addr,
      description: suggestDescription(it)
    };
    showPortScan = false;
    showCreate = true;
  }} />
{/if}
{#if logTarget}
  {#if logTarget.kind === 'frpc'}
    <FrpcLogModal proxyName={logTarget.id} onClose={() => (logTarget = null)} />
  {:else}
    <LogModal kind={logTarget.kind} id={logTarget.id} title={logTarget.kind === 'stunhole' ? i18nTr("STUN 通道日志") : i18nTr("转发日志")} onClose={() => (logTarget = null)} />
  {/if}
{/if}
{#if cfLog}
  <!-- Cloudflare 回源闸门的内核日志：不进持久化日志库，直接取该实例的内核日志尾部 -->
  <Modal title={i18nTr("内核日志 · ") + cfLog.title} onClose={() => (cfLog = null)} width={900}>
    <pre class="cf-log-pre">{@html highlightLog(cfLogText || i18nTr("加载中…"))}</pre>
    <div style="display:flex;justify-content:flex-end;margin-top:10px">
      <button class="btn btn-sm" disabled={cfLogBusy} on:click={loadCfLog}>{cfLogBusy ? i18nTr("刷新中…") : i18nTr("刷新")}</button>
    </div>
  </Modal>
{/if}
{#if trafficTarget}
  <TrafficModal item={trafficTarget} kind="forward" onClose={() => (trafficTarget = null)} />
{/if}
{#if delTarget}
  <ConfirmModal
    title={$i18n("删除转发规则")}
    message={`确定删除转发规则 ${delTarget.key}？删除后该规则将停止并移除，此操作不可恢复。`}
    onConfirm={confirmDelete}
    onClose={() => (delTarget = null)}
    busy={delBusy}
  />
{/if}

<style>
  /* Cloudflare 回源闸门的内核日志（与 Cloudflare 页的日志样式一致） */
  .cf-log-pre {
    background: var(--bg4);
    border: 1px solid var(--bd);
    border-radius: 8px;
    padding: 10px;
    max-height: 52vh;
    overflow: auto;
    font-size: 12px;
    color: var(--text2);
    white-space: pre-wrap;
    word-break: break-all;
    margin: 0;
  }
  /* 表格内可点击的流量统计按钮：去掉原生 button 默认样式，视觉上与原 div 一致 */
  .cell-stats-btn {
    all: unset;          /* 重置浏览器默认 button 样式 */
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    font-size: 11px;
    cursor: pointer;
    box-sizing: border-box;
    width: 100%;
  }
  .cell-stats-btn:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
    border-radius: 4px;
  }
  /* 描述列：运行状态圆点 + 描述文字 */
  .fwd-name {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    min-width: 0;
  }
  .fwd-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex: none;
    display: inline-block;
  }
  /* 转发地址：与演示页一致使用强调色等宽字体 */
  .cell-addr {
    color: var(--accent);
    font-family: var(--mono);
    font-size: 12px;
    word-break: break-all;
  }
  /* 协议筛选胶囊：与内网穿透的服务器筛选保持同一交互 */
  .proto-chips{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:12px;flex-shrink:0}
  .proto-chip{
    display:inline-flex;align-items:center;padding:6px 12px;border:1px solid var(--bd);
    border-radius:999px;background:var(--bg3);color:var(--text3);
    font-size:12px;font-family:var(--font);white-space:nowrap;cursor:pointer;transition:.2s;
  }
  .proto-chip:hover{color:var(--text2);border-color:rgba(var(--accent-rgb),.35)}
  .proto-chip.active{background:var(--accent-glow);border-color:rgba(var(--accent-rgb),.45);color:var(--accent);font-weight:600}
  .fwd-foot{
    display:flex;align-items:center;justify-content:space-between;gap:10px;
    margin-top:10px;flex-shrink:0;font-size:11.5px;color:var(--text3);font-family:var(--mono);
  }
  .fwd-foot-note{font-size:10.5px;color:var(--text3)}
  /* 移动端卡片对齐新版设计令牌 */
  @media (max-width: 600px) {
    .list-card {
      background: var(--bg3);
      border-radius: calc(var(--radius) + 4px);
      padding: 14px 16px;
      box-shadow: var(--shadow-card);
    }
    .list-card-title {
      display: flex;
      align-items: center;
      gap: 7px;
      min-width: 0;
    }
    .proto-chips{flex-wrap:nowrap;overflow-x:auto;padding-bottom:2px}
    .proto-chip{flex:0 0 auto;min-height:36px;padding:8px 14px}
    .fwd-foot{font-size:10.5px}
  }
</style>
