<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // frpc 代理通道列表页
  import { onMount, onDestroy } from 'svelte';
  import { toast, status, tunnelPrefill } from '../lib/stores.js';
  import { api } from '../lib/api.js';
  import { suggestProxyName, fmtBytes, fmtRate, localHost, pollVisible } from '../lib/utils.js';
  import { fetchServerDomainPicks, removeBindRecord } from '../lib/domainbind.js';
  import TunnelModal from '../components/TunnelModal.svelte';
  import PortScanModal from '../components/PortScanModal.svelte';
  import ConnStatsModal from '../components/ConnStatsModal.svelte';
  import FrpcLogModal from '../components/FrpcLogModal.svelte';
  import ConfirmModal from '../components/ConfirmModal.svelte';

  let search = '';
  let serverFilter = 'all';

  let showCreate = false;
  let showEdit = false;
  let editingProxy = null;
  let showPortScan = false;
  let showStats = false;
  let statsProxy = null; // 流量详情弹窗的代理对象
  let logTarget = null;  // frpc 通道日志弹窗的代理名
  let createPrefill = { ip: '', port: 0, name: '' }; // 从端口扫描「添加」带入创建弹窗的本地 IP/端口/名称
  let delTarget = null;      // {id, name}
  let delBusy = false;
  let timer;

  let proxies = [];
  let servers = []; // 已配置的 frps 服务器列表
  let connStats = {}; // 代理名 → 实时连接数（frpc 管理 API）
  let proxyStates = {}; // 代理名 → running/connecting/error（frpc 管理 API 实时状态）
  let trafficStats = {}; // 代理名 → {rx, tx} 实时速率（字节/秒，后端按轮询差值计算）
  let trafficCum = {};   // 代理名 → {rx, tx} 持久累计流量（无连接也保留，供弹窗展示）
  let activeServer = ''; // 当前激活 frps 服务器名称
  let remotePorts = {};  // 代理名 → frps 实际分配端口（remote_port=0 自动分配时由 admin API 回填）

  async function load() {
    try {
      const d = await api('/api/frpc/config');
      if (d) {
        proxies = d.proxies || [];
        servers = d.servers || [];
        const name = d.active_server;
        const s = servers.find((x) => x.name === name) || servers[0];
        activeServer = (s && s.name) || name || '';
      }
    } catch (e) { /* ignore */ }
  }

  async function loadConns() {
    try {
      // detail=1 额外返回各代理活跃连接详情（连接累计流量）、持久累计（cumulative）与实时速率（rates）
      const d = await api('/api/frpc/conns?detail=1');
      if (d) {
        if (d.conns) connStats = d.conns;
        if (d.states) proxyStates = d.states;
        if (d.remote_ports) remotePorts = d.remote_ports; // 自动分配端口的实际值
        trafficStats = d.rates || {};     // 列表「实时速率」列
        trafficCum = d.cumulative || {};  // 弹窗「累计上行/下行」
      }
    } catch (e) { /* ignore */ }
  }

  $: localIPv4 = ($status && $status.local_ip) || '';
  $: rows = buildRows(proxies, search, connStats, servers, activeServer, proxyStates, trafficStats, localIPv4, remotePorts);
  // 服务器筛选：与演示页的服务器胶囊一致；搜索与服务器筛选叠加生效
  $: serverNames = [...new Set(servers.map((s) => s.name).filter(Boolean))];
  $: if (serverFilter !== 'all' && !serverNames.includes(serverFilter)) serverFilter = 'all';
  $: filteredRows = serverFilter === 'all' ? rows : rows.filter((r) => r.srv === serverFilter);
  $: enabledCount = filteredRows.filter((r) => r.isOn).length;

  const MODE_NAMES = {
    tcp: i18nTr("TCP 端口转发"),
    udp: i18nTr("UDP 端口转发"),
    http: 'HTTP',
    https: 'HTTPS',
    stcp: i18nTr("STCP 内联穿透"),
    xtcp: i18nTr("XTCP 点对点（P2P）")
  };
  const PROTO_NAMES = { tcp: 'TCP', udp: 'UDP', http: 'HTTP', https: 'HTTPS', stcp: 'TCP', xtcp: 'TCP' };

  function buildRows(list, q, cs, srvList, actSrv, states, traffic, localIPv4, remotePorts) {
    const out = [];
    for (const p of list) {
      const type = (p.type || 'tcp').toLowerCase();
      const en = p.enabled !== false;
      const isHttp = type === 'http' || type === 'https';
      const isP2P = type === 'stcp' || type === 'xtcp';
      // 连接状态：正常连接(running) / 连接中(connecting) / 连接错误(error) / 未开(off) / 状态未知(unknown)
      // 优先取 frpc 管理 API 实时状态；查不到时绝不猜测成「连接中」——
      // 「连接中」是 frpc 明确回报的过渡态，查不到只说明管理 API 没应答（端口不通等）；
      // 若确有活跃连接则反证代理在跑，此时仍按正常连接显示，其余如实呈现为「状态未知」
      let state = 'off';
      if (en) {
        if (states[p.name]) state = states[p.name];
        else if (cs[p.name] > 0) state = 'running';
        else state = 'unknown';
      }
      // 代理归属服务器 → 纯主机（域名或 IP，不含 frps 监听端口）；IPv6 显示加方括号
      const srv = srvList.find((x) => x.name === p.server) || srvList.find((x) => x.name === actSrv) || srvList[0];
      const rawHost = srv && srv.addr ? srv.addr.trim() : '';
      const host = rawHost && rawHost.indexOf(':') >= 0 && !rawHost.startsWith('[') && !/^[\w.-]+$/.test(rawHost)
        ? '[' + rawHost + ']' : rawHost;
      // 本地地址：本机回环/通配监听地址替换为本地 IPv4（便于局域网访问与点击直达），始终可点击（浏览器默认加 http 前缀）
      // 经 TunHook 反代的 http 代理显示真实后端端口（real_local_port）
      const local = `${localHost(p.local_ip, localIPv4)}:${(p.real_local_port > 0 ? p.real_local_port : p.local_port)}`;
      // 代理地址：http/https 用域名；tcp/udp 用「归属服务器主机:远端端口」（remote_port=0 自动分配时
      // 取 frpc admin API 回传的实际端口）；stcp/xtcp 无可直达地址
      let remote = '-';
      let remoteOpen = '';
      if (isHttp) {
        const dom = p.custom_domains || p.subdomain || '';
        remote = dom || '-';
        remoteOpen = dom;
      } else if (isP2P) {
        remote = type === 'xtcp' ? i18nTr("XTCP 访问端（P2P）") : i18nTr("STCP 访问端");
      } else {
        const rp = p.remote_port > 0 ? p.remote_port : (remotePorts[p.name] || 0);
        if (rp > 0) {
          remote = host ? `${host}:${rp}` : ':' + rp;
          remoteOpen = remote;
        } else {
          remote = i18nTr("自动");
        }
      }
      out.push({
        id: p.name,
        type,
        mode: MODE_NAMES[type] || type.toUpperCase(),
        proto: PROTO_NAMES[type] || type.toUpperCase(),
        srv: p.server || actSrv || '—', // 代理归属服务器（旧数据空=激活服务器）
        state,
        local,
        remote,
        remoteOpen,
        conns: en ? cs[p.name] : undefined,
        traffic: (traffic && traffic[p.name]) || { rx: 0, tx: 0 },
        isOn: en,
        raw: p
      });
    }
    const qq = (q || '').trim().toLowerCase();
    const filtered = qq
      ? out.filter((r) => String(r.id).toLowerCase().includes(qq) || String(r.local).toLowerCase().includes(qq) || String(r.remote).toLowerCase().includes(qq) || String(r.mode).toLowerCase().includes(qq))
      : out;
    return filtered.sort((a, b) => String(a.id).localeCompare(String(b.id)));
  }

  // frpc 代理：启用/停用
  async function toggleProxy(p) {
    const en = p.enabled !== false;
    try {
      await api('/api/frpc/proxy/toggle', { method: 'POST', body: { name: p.name, enabled: !en } });
      toast(en ? i18nTr("代理已停用: ") + p.name : i18nTr("代理已启用: ") + p.name, 'success');
      load();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function confirmDelete() {
    delBusy = true;
    try {
      const p = proxies.find((x) => x.name === delTarget.id);
      await api('/api/frpc/proxy/delete', { method: 'POST', body: { name: delTarget.id } });
      toast(i18nTr("frpc 代理已删除: ") + delTarget.id, 'success');
      await cleanupDomainRecord(p);
      delTarget = null;
      load();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      delBusy = false;
    }
  }

  // 删除代理后清理该域名的解析记录：只删「主机记录 + 类型 + 值」都对得上的那条，
  // 用户手工改过目标的记录不动（removeBindRecord 内部保证）。
  // 域名被泛解析覆盖时本就没有为它写过具体记录，此时无记录可删，静默通过即可。
  async function cleanupDomainRecord(p) {
    const full = (p && (p.custom_domains || '').trim()) || '';
    if (!full || (p.type !== 'http' && p.type !== 'https')) return;
    const cur = servers.find((x) => x.name === (p.server || activeServer)) || servers[0];
    const addr = (cur && cur.addr) || '';
    if (!addr) return;
    try {
      const options = await fetchServerDomainPicks(addr);
      const r = await removeBindRecord({ full, addr, options });
      if (r && r.removed) toast(i18nTr("已同步删除解析记录：{0}", [r.removed]), 'success');
    } catch (e) {
      toast(i18nTr("解析记录清理失败：") + e.message, 'error');
    }
  }

  function openEdit(p) {
    editingProxy = p;
    showEdit = true;
  }

  function openStats(r) {
    statsProxy = r.raw;
    showStats = true;
  }

  // 启用/停用按钮：按运行状态着色（全站统一规则）
  //   运行中=绿 / 连接中=黄（过渡态，避免看着像已经跑起来了）/ 连接错误=红 / 未启用、状态未知=灰
  // 灰色只表示「没开」，红色表示「开了但连不上」，两者必须一眼可分；具体原因仍由 title 区分
  function stateColor(r) {
    if (!r.isOn) return 'var(--text3)';
    if (r.state === 'error') return 'var(--red)';
    if (r.state === 'running') return 'var(--green)';
    if (r.state === 'connecting') return 'var(--yellow)';
    return 'var(--text3)'; // 状态未知：管理 API 没应答，按「不在提供服务」呈灰，而不是黄
  }
  function stateTitle(r) {
    if (!r.isOn) return i18nTr("启用");
    if (r.state === 'connecting') return i18nTr("连接中…（点击停用）");
    if (r.state === 'error') return i18nTr("连接错误（点击停用）");
    if (r.state === 'unknown') return i18nTr("状态未知：frpc 管理 API 未应答（点击停用）");
    return i18nTr("停用");
  }
  // 代理方式徽章：协议色区分（停用统一灰色），与演示页的协议标签一致
  function protoBadgeClass(r) {
    if (!r.isOn) return 'badge-off';
    return {
      tcp: 'badge-info',
      udp: 'badge-warn',
      http: 'badge-on',
      https: 'badge-info',
      stcp: 'badge-violet',
      xtcp: 'badge-violet'
    }[r.type] || 'badge-off';
  }

  onMount(() => {
    load();
    loadConns();
    timer = pollVisible(() => {
      load();
      loadConns();
    }, 5000);
    // 端口扫描页「创建穿透隧道」跳转：预填并自动打开创建弹窗
    const unsubPrefill = tunnelPrefill.subscribe((v) => {
      if (v) {
        createPrefill = { ip: v.ip || '', port: v.port || 0, name: v.name || '' };
        tunnelPrefill.set(null);
        showCreate = true;
      }
    });
    return unsubPrefill;
  });
  onDestroy(() => timer && timer());
</script>

<div class="container page-full page-list">
  <div class="page-hdr">
    <div>
      <h2>FRPC</h2>
      <span class="page-hdr-sub">{$i18n("frpc 代理 ·")} {proxies.length} {$i18n("条通道")}{#if activeServer}<span>&{$i18n("· 当前服务器")} {activeServer}</span>{/if}</span>
    </div>
    <div class="page-hdr-actions">
      <div class="hdr-search-wrap">
        <svg class="hdr-search-icon" width="15" height="15" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M21 38C30.3888 38 38 30.3888 38 21C38 11.6112 30.3888 4 21 4C11.6112 4 4 11.6112 4 21C4 30.3888 11.6112 38 21 38Z"/><path d="M33.2216 33.2217L41.7069 41.707" stroke-linecap="round"/></svg>
        <input type="text" class="hdr-search" bind:value={search} placeholder={$i18n("搜索代理名称 / 转发规则")} />
      </div>
      <div class="hdr-btn-group">
        <button class="btn" title={$i18n("扫描端口")} on:click={() => (showPortScan = true)}>
          <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="24" r="18"/><circle cx="24" cy="24" r="10"/><path d="M24 24L35 13"/><circle cx="24" cy="24" r="3" fill="currentColor" stroke="none"/><circle cx="32" cy="15" r="2.5" fill="currentColor" stroke="none"/></svg>
          <span class="sm-hide">{$i18n("扫描端口")}</span>
        </button>
        <button class="btn btn-primary" title={$i18n("创建通道")} on:click={() => { createPrefill = { ip: '', port: 0, name: '' }; showCreate = true; }}>
          <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="24" r="20"/><path d="M24 16V32"/><path d="M16 24H32"/></svg>
          <span class="sm-hide">{$i18n("创建通道")}</span>
        </button>
      </div>
    </div>
  </div>

  {#if serverNames.length}
    <div class="server-chips">
      <button class="server-chip" class:active={serverFilter === 'all'} on:click={() => (serverFilter = 'all')}>{$i18n("全部服务器")}</button>
      {#each serverNames as s}
        <button class="server-chip" class:active={serverFilter === s} on:click={() => (serverFilter = s)}>{s}</button>
      {/each}
    </div>
  {/if}

  <div class="table-wrap">
    <div style="overflow-y:auto;flex:1">
    <table class="tunnel-table">
      <thead>
        <tr>
          <th>{$i18n("代理名称")}</th>
          <th style="width:110px">{$i18n("服务器名称")}</th>
          <th style="width:150px">{$i18n("代理方式")}</th>
          <th style="width:180px">{$i18n("本地地址")}</th>
          <th style="width:220px">{$i18n("代理地址")}</th>
          <th style="width:170px">{$i18n("实时速率")}</th>
          <th style="width:190px">{$i18n("操作")}</th>
        </tr>
      </thead>
      <tbody>
        {#each filteredRows as r}
          <tr>
            <td class="cell-mono">
              <span class="proxy-name"><span class="proxy-state" style="background:{stateColor(r)}"></span>{r.id}</span>
            </td>
            <td><span class="badge badge-off">{r.srv}</span></td>
            <td>
              <span class="badge {protoBadgeClass(r)}">{r.mode}</span>
            </td>
            <td class="cell-mono">
              <a class="cell-link cell-link-btn" href="http://{r.local}" target="_blank" rel="noopener noreferrer" title={$i18n("点击新页面打开 http://{0}", [r.local])}>{r.local}</a>
            </td>
            <td class="cell-mono">
              {#if r.remoteOpen}
                <a class="cell-link cell-link-btn" href="{r.type === 'https' ? 'https' : 'http'}://{r.remoteOpen}" target="_blank" rel="noopener noreferrer" title={$i18n("点击新页面打开 {0}://{1}", [r.type === 'https' ? 'https' : 'http', r.remoteOpen])}>{r.remote}</a>
              {:else}
                {r.remote}
              {/if}
            </td>
            <td>
              {#if !r.isOn}
                <span class="cell-dim">{$i18n("已停用")}</span>
              {:else}
                <button type="button" class="cell-stats-btn" title={$i18n("点击查看连接与流量统计详情")} on:click={() => openStats(r)}>
                  <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">↑</span><span style="color:var(--text2)">{fmtRate(r.traffic.tx || 0)}</span></span>
                  <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">↓</span><span style="color:var(--text2)">{fmtRate(r.traffic.rx || 0)}</span></span>
                  <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">⇄</span><span style="color:var(--text2)">{r.conns || 0} {$i18n("连接")}</span></span>
                </button>
              {/if}
            </td>
            <td>
              <div class="cell-actions">
                <button class="btn-icon" title={stateTitle(r)} aria-label={stateTitle(r)} on:click={() => toggleProxy(r.raw)}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={stateColor(r)} stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v9"/><path d="M6.4 6.4a8 8 0 1 0 11.2 0"/></svg>
                </button>
                <button class="btn-icon" title={$i18n("通道日志")} aria-label={$i18n("查看通道日志")} on:click={() => (logTarget = r.id)}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h9l4 4v14H6z"/><path d="M9 12h7M9 16h7M9 8h3"/></svg>
                </button>
                <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑")} on:click={() => openEdit(r.raw)}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h4L20 8l-4-4L4 16z"/></svg>
                </button>
                <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => (delTarget = { id: r.id })}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14"/></svg>
                </button>
              </div>
            </td>
          </tr>
        {:else}
          <tr>
            <td colspan="7">
              <div class="empty">
                <svg width="40" height="40" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="margin:0 auto 10px;display:block;color:var(--text3)"><path d="M24 36V30"/><path d="M20 40H6"/><path d="M28 40H42"/><path d="M28 40C28 42.2091 26.2091 44 24 44C21.7909 44 20 42.2091 20 40C20 37.7909 21.7909 36 24 36C26.2091 36 28 37.7909 28 40Z"/><path d="M37 17C37 24.1797 31.1797 30 24 30C16.8203 30 11 24.1797 11 17M37 17C37 9.8203 31.1797 4 24 4C16.8203 4 11 9.8203 11 17M37 17H11"/><path d="M29 17C29 24.1797 26.7614 30 24 30C21.2386 30 19 24.1797 19 17C19 9.8203 21.2386 4 24 4C26.7614 4 29 9.8203 29 17Z"/><path d="M37 17H11"/></svg>
                <div class="empty-t">{rows.length === 0 ? i18nTr("暂无 frpc 代理，点击\"创建通道\"添加") : i18nTr("没有匹配的代理，请调整搜索或服务器筛选")}</div>
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
  </div>

  <!-- 代理列表卡片：仅移动端显示（桌面端由 app.css 隐藏，表格保持原样） -->
  <div class="list-cards">
    {#if filteredRows.length === 0}
      <div class="list-cards-empty">{rows.length === 0 ? i18nTr("暂无 frpc 代理，点击\"创建通道\"添加") : i18nTr("没有匹配的代理，请调整搜索或服务器筛选")}</div>
    {/if}
    {#each filteredRows as r}
      <div class="list-card" on:click={() => openEdit(r.raw)}>
        <div class="list-card-top">
          <div class="list-card-avatar">{(r.id || '?').charAt(0).toUpperCase()}</div>
          <div class="list-card-title"><span class="proxy-state" style="background:{stateColor(r)}"></span>{r.id}</div>
        </div>
        <div class="list-card-sub">
          <span class="badge badge-off">{r.srv}</span>
          <span class="badge {protoBadgeClass(r)}">{r.mode}</span>
        </div>
        <div class="list-card-rows" on:click={(e) => e.stopPropagation()}>
          <div class="list-card-row">
            <span class="k">{$i18n("本地地址")}</span>
            <span class="v"><span class="cell-mono ellip">{r.local}</span></span>
          </div>
          <div class="list-card-row">
            <span class="k">{$i18n("代理地址")}</span>
            <span class="v">
              {#if r.remoteOpen}
                <a class="cell-link cell-link-btn ellip" href="{r.type === 'https' ? 'https' : 'http'}://{r.remoteOpen}" target="_blank" rel="noopener noreferrer" title={$i18n("点击新页面打开 {0}://{1}", [r.type === 'https' ? 'https' : 'http', r.remoteOpen])}>{r.remote}</a>
              {:else}
                <span class="ellip">{r.remote}</span>
              {/if}
            </span>
          </div>
          <div class="list-card-row">
            <span class="k">{$i18n("实时速率")}</span>
            <span class="v">
              {#if !r.isOn}
                <span class="cell-dim">{$i18n("已停用")}</span>
              {:else}
                <button type="button" class="cell-stats-btn" title={$i18n("点击查看连接与流量统计详情")} on:click|stopPropagation={() => openStats(r)}>
                  <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">↑</span><span style="color:var(--text2)">{fmtRate(r.traffic.tx || 0)}</span></span>
                  <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">↓</span><span style="color:var(--text2)">{fmtRate(r.traffic.rx || 0)}</span></span>
                  <span style="display:flex;align-items:center;gap:3px"><span style="color:var(--text3)">⇄</span><span style="color:var(--text2)">{r.conns || 0} {$i18n("连接")}</span></span>
                </button>
              {/if}
            </span>
          </div>
        </div>
        <div class="list-card-actions" on:click={(e) => e.stopPropagation()}>
          <button class="btn-icon" title={stateTitle(r)} aria-label={stateTitle(r)} on:click={() => toggleProxy(r.raw)}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={stateColor(r)} stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v9"/><path d="M6.4 6.4a8 8 0 1 0 11.2 0"/></svg>
          </button>
          <button class="btn-icon" title={$i18n("通道日志")} aria-label={$i18n("查看通道日志")} on:click={() => (logTarget = r.id)}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h9l4 4v14H6z"/><path d="M9 12h7M9 16h7M9 8h3"/></svg>
          </button>
          <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑")} on:click={() => openEdit(r.raw)}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h4L20 8l-4-4L4 16z"/></svg>
          </button>
          <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} aria-label={$i18n("删除")} on:click={() => (delTarget = { id: r.id })}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14"/></svg>
          </button>
        </div>
      </div>
    {/each}
  </div>

  <div class="tunnel-foot">
    <span>{$i18n("共")} {filteredRows.length} {$i18n("条 ·")} <span style="color:var(--green)">{enabledCount} {$i18n("条已启用")}</span></span>
    {#if serverFilter !== 'all'}
      <span class="mono">{$i18n("筛选")} {serverFilter}</span>
    {:else if activeServer}
      <span class="mono">{$i18n("当前服务器")} {activeServer}</span>
    {/if}
  </div>
</div>

{#if showCreate}
  <TunnelModal mode="create" servers={servers} activeServer={activeServer} initialIP={createPrefill.ip} initialPort={createPrefill.port} initialName={createPrefill.name} onClose={() => (showCreate = false)} onSaved={load} />
{/if}
{#if showEdit && editingProxy}
  <TunnelModal mode="edit" proxy={editingProxy} servers={servers} activeServer={activeServer} onClose={() => { showEdit = false; editingProxy = null; }} onSaved={load} />
{/if}
{#if showPortScan}
  <PortScanModal onClose={() => (showPortScan = false)} onPick={(it) => {
    createPrefill = {
      ip: (it.local_addr && it.local_addr !== '0.0.0.0' && it.local_addr !== '::') ? it.local_addr : '',
      port: it.port,
      name: suggestProxyName(it)
    };
    showPortScan = false;
    showCreate = true;
  }} />
{/if}
{#if showStats && statsProxy}
  <ConnStatsModal proxy={statsProxy} onClose={() => { showStats = false; statsProxy = null; }} />
{/if}
{#if logTarget !== null}
  <FrpcLogModal proxyName={logTarget} onClose={() => (logTarget = null)} />
{/if}
{#if delTarget}
  <ConfirmModal
    title={$i18n("删除 frpc 代理")}
    message={`确定删除 frpc 代理「${delTarget.id}」吗？此操作不可恢复。`}
    onConfirm={confirmDelete}
    onClose={() => (delTarget = null)}
    busy={delBusy}
  />
{/if}

<style>
  /* cell-link-btn 的样式复位已提升至全局 app.css（Stun 页也使用） */
  .proxy-name{display:inline-flex;align-items:center;gap:7px;min-width:0;font-family:var(--mono);font-size:11px;color:var(--accent)}
  .proxy-state{width:7px;height:7px;border-radius:50%;flex-shrink:0}
  /* 数据表左对齐名称/地址，速率居中，操作右对齐，长地址更易扫读 */
  .tunnel-table th:nth-child(-n+5),.tunnel-table td:nth-child(-n+5){text-align:left}
  .tunnel-table th:last-child,.tunnel-table td:last-child{text-align:right}
  .list-card-title{display:flex;align-items:center;gap:6px;min-width:0}
  /* 服务器筛选胶囊：与演示页的服务器切换行一致 */
  .server-chips{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:12px;flex-shrink:0}
  .server-chip{
    display:inline-flex;align-items:center;padding:6px 12px;border:1px solid var(--bd);
    border-radius:999px;background:var(--bg3);color:var(--text3);
    font-size:12px;font-family:var(--font);white-space:nowrap;cursor:pointer;transition:.2s;
  }
  .server-chip:hover{color:var(--text2);border-color:rgba(var(--accent-rgb),.35)}
  .server-chip.active{background:var(--accent-glow);border-color:rgba(var(--accent-rgb),.45);color:var(--accent);font-weight:600}
  /* 页脚统计：总数 / 已启用 / 当前服务器 */
  .tunnel-foot{
    display:flex;align-items:center;justify-content:space-between;gap:10px;
    margin-top:10px;flex-shrink:0;font-size:11.5px;color:var(--text3);font-family:var(--mono);
  }
  /* 表格内可点击的流量统计按钮（同 Forwards 页面） */
  .cell-stats-btn {
    all: unset;
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
  @media (max-width:600px){
    .server-chips{flex-wrap:nowrap;overflow-x:auto;padding-bottom:2px}
    .server-chip{flex:0 0 auto;min-height:36px;padding:8px 14px}
    .tunnel-foot{font-size:10.5px}
  }
</style>
