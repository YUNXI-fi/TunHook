<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 网络唤醒（Wake-on-LAN）：保存局域网设备，一键发送 WOL 魔术包。
  // 设备列表持久化在服务端（settings KV），跨浏览器/设备共享。
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import { field, validateAll } from '../lib/field.js';
  import { optional, validateIPv4, validatePort } from '../lib/utils.js';
  import Modal from '../components/Modal.svelte';
  import ConfirmModal from '../components/ConfirmModal.svelte';

  const DEFAULT_BROADCAST = '255.255.255.255';
  const DEFAULT_PORT = 9;

  let devices = [];
  let loading = true;
  let waking = {}; // 设备 id → 是否正在发送唤醒包
  let statuses = {}; // 设备 id → 是否开机（true/false，未检测为 undefined）
  let osHints = {}; // 设备 id → 系统推断（Linux/Unix、Windows 等，禁 ping 时为空）
  let statusLoading = false;
  let statusSeq = 0; // 状态请求序号：只让最新一次请求的结果生效

  // 添加/编辑弹窗
  let showForm = false;
  let editingId = null;
  let form = { name: '', mac: '', broadcast: DEFAULT_BROADCAST, port: DEFAULT_PORT };
  let formEl;
  let saving = false;

  // 删除确认
  let delTarget = null;
  let deleting = false;

  // 局域网扫描（发现设备并一键加入唤醒列表）
  let showScan = false;
  let scanning = false;
  let scanHosts = [];
  let scanRange = '';
  let scanError = '';
  let addingMac = '';
  // 已保存设备的 MAC 集合：扫描结果据此显示「已添加」
  let addedMacs = new Set();
  $: addedMacs = new Set(devices.map((d) => (d.mac || '').toUpperCase()));

  // 最近一次局域网扫描（页脚摘要）
  let lastScanAt = '';
  let lastScanCount = 0;
  $: onlineCount = devices.filter((d) => statuses[d.id] === true).length;
  $: scanDeviceCount = lastScanCount || devices.length;
  $: firstDevice = devices[0] || { broadcast: DEFAULT_BROADCAST, port: DEFAULT_PORT };

  const broadcastCheck = optional(validateIPv4);

  function validateName(v) {
    return (v || '').trim() ? '' : i18nTr("请输入设备名称");
  }
  // MAC 支持 AA:BB:CC:DD:EE:FF / AA-BB-... / AABBCCDDEEFF（与后端一致）
  function validateMAC(v) {
    const s = (v || '').trim();
    if (!s) return i18nTr("请输入 MAC 地址");
    if (/^[0-9A-Fa-f]{12}$/.test(s)) return '';
    if (/^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(s)) return '';
    return i18nTr("MAC 格式应为 AA:BB:CC:DD:EE:FF（也支持 - 分隔或无分隔）");
  }

  async function load() {
    try {
      const d = await api('/api/wol/devices');
      devices = (d && d.devices) || [];
    } catch (e) {
      toast(i18nTr("加载设备失败：") + e.message, 'error');
    }
    loading = false;
    refreshStatus();
  }

  // 开机状态：后端主动触发本网段 ARP 后按 MAC 匹配
  async function refreshStatus() {
    if (!devices.length) {
      statuses = {};
      osHints = {};
      return;
    }
    const seq = ++statusSeq;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 8000); // 超时兜底：避免异常时一直停留在“检测中”
    statusLoading = true;
    try {
      const d = await api('/api/wol/status', { signal: ac.signal });
      if (seq !== statusSeq) return; // 已有更新的请求，丢弃本次结果
      statuses = (d && d.statuses) || {};
      osHints = (d && d.os) || {};
    } catch (e) {
      /* 状态检测失败/超时不影响设备列表，保持“未知” */
    } finally {
      clearTimeout(timer);
      if (seq === statusSeq) statusLoading = false;
    }
  }

  // 开机状态展示：必须用响应式派生并在模板中直接引用。
  // Svelte 只追踪模板里直接出现的变量；若在模板中调用 stateLabel() 间接读取 statuses，
  // 请求返回后的赋值不会触发表格文本更新，状态会永远停在首次渲染值。
  $: statusViews = Object.fromEntries(
    devices.map((d) => {
      const online = statuses[d.id];
      return [
        d.id,
        {
          label: online === true ? i18nTr("已开机") : online === false ? i18nTr("已关机") : statusLoading ? i18nTr("检测中…") : i18nTr("未知"),
          cls: online === true ? 'badge-on' : 'badge-off'
        }
      ];
    })
  );
  onMount(load);

  function openAdd() {
    editingId = null;
    form = { name: '', mac: '', broadcast: DEFAULT_BROADCAST, port: DEFAULT_PORT };
    showForm = true;
  }
  function openEdit(d) {
    editingId = d.id;
    form = { name: d.name, mac: d.mac, broadcast: d.broadcast, port: d.port };
    showForm = true;
  }

  // 编辑弹窗中的删除入口：关闭编辑弹窗，转入删除确认
  function deleteFromEdit() {
    const d = devices.find((x) => x.id === editingId);
    if (!d) return;
    showForm = false;
    delTarget = d;
  }

  // 保存整份列表（新增/编辑都由后端统一校验并规范化 MAC/广播地址）
  async function persist(list) {
    const d = await api('/api/wol/devices', { method: 'POST', body: { devices: list } });
    devices = (d && d.devices) || list;
    refreshStatus(); // 设备变化后更新开机状态
  }

  async function save() {
    if (!validateAll(formEl)) return;
    saving = true;
    const item = {
      id: editingId || Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
      name: form.name.trim(),
      mac: form.mac.trim(),
      broadcast: (form.broadcast || '').trim() || DEFAULT_BROADCAST,
      port: Number(form.port) || DEFAULT_PORT
    };
    const list = editingId ? devices.map((d) => (d.id === editingId ? item : d)) : [...devices, item];
    try {
      await persist(list);
      showForm = false;
      toast(editingId ? i18nTr("设备已更新") : i18nTr("设备已添加"), 'success');
    } catch (e) {
      toast(i18nTr("保存失败：") + e.message, 'error');
    }
    saving = false;
  }

  async function remove() {
    if (!delTarget) return;
    deleting = true;
    try {
      await persist(devices.filter((d) => d.id !== delTarget.id));
      toast(i18nTr("设备已删除"), 'success');
      delTarget = null;
    } catch (e) {
      toast(i18nTr("删除失败：") + e.message, 'error');
    }
    deleting = false;
  }

  async function wake(d) {
    waking = { ...waking, [d.id]: true };
    try {
      await api('/api/wol/wake', { method: 'POST', body: { id: d.id } });
      toast(i18nTr("已向「") + d.name + i18nTr("」发送唤醒魔术包"), 'success');
      setTimeout(refreshStatus, 5000); // 给设备开机留出时间后刷新状态
    } catch (e) {
      toast(i18nTr("唤醒失败：") + e.message, 'error');
    }
    waking = { ...waking, [d.id]: false };
  }

  async function openScan() {
    showScan = true;
    await scanLan();
  }

  async function scanLan() {
    scanning = true;
    scanError = '';
    scanHosts = [];
    try {
      const d = await api('/api/wol/scan');
      scanHosts = (d && d.hosts) || [];
      scanRange = (d && d.range) || '';
      lastScanAt = new Date().toLocaleTimeString('zh-CN', { hour12: false });
      lastScanCount = scanHosts.length;
    } catch (e) {
      scanError = e.message || i18nTr("扫描失败");
    }
    scanning = false;
  }

  async function addScanned(h) {
    addingMac = h.mac;
    const item = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
      name: h.hostname || h.ip,
      mac: h.mac,
      broadcast: DEFAULT_BROADCAST,
      port: DEFAULT_PORT
    };
    try {
      await persist([...devices, item]);
      toast(i18nTr("已添加「") + item.name + '」', 'success');
    } catch (e) {
      toast(i18nTr("添加失败：") + e.message, 'error');
    }
    addingMac = '';
  }
</script>

<div class="container">
  <div class="page-hdr">
    <div>
      <h2>{$i18n("网络唤醒")}</h2>
      <span class="page-hdr-sub">{$i18n("Wake-on-LAN · 向局域网设备发送魔术包")}</span>
    </div>
    <div class="page-hdr-actions">
      <button class="btn" on:click={openScan} disabled={scanning} title={$i18n("扫描设备")}>
        <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="24" r="18"/><circle cx="24" cy="24" r="10"/><path d="M24 24L35 13"/><circle cx="24" cy="24" r="3" fill="currentColor" stroke="none"/><circle cx="32" cy="15" r="2.5" fill="currentColor" stroke="none"/></svg>
        <span class="sm-hide">{$i18n("扫描设备")}</span>
      </button>
      <button class="btn btn-primary" on:click={openAdd} title={$i18n("添加设备")}>
        <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="24" r="20"/><path d="M24 16V32"/><path d="M16 24H32"/></svg>
        <span class="sm-hide">{$i18n("添加设备")}</span>
      </button>
    </div>
  </div>

  {#if loading}
    <div class="empty"><div class="empty-t">{$i18n("加载中…")}</div></div>
  {:else if !devices.length}
    <div class="empty">
      <div class="empty-t">{$i18n("还没有设备，点击「添加设备」保存 MAC 地址后即可一键唤醒")}</div>
    </div>
  {:else}
    <div class="wol-grid">
      {#each devices as d (d.id)}
        {@const st = statusViews[d.id] || { label: i18nTr("未知"), cls: 'badge-off' }}
        {@const os = osHints[d.id] || ''}
        {@const on = statuses[d.id] === true}
        <div class="wol-card">
          <div class="wol-top">
            <div class="wol-ico">
              {#if os === 'Linux/Unix'}
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>
              {:else}
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
              {/if}
            </div>
            <div class="wol-info">
              <div class="wol-name" title={st.label}>
                <span class="wol-dot" style="background:{on ? 'var(--green)' : statuses[d.id] === false ? 'var(--text3)' : 'var(--yellow)'}"></span>
                <span class="wol-name-t">{d.name}</span>
              </div>
              <div class="wol-sub">{st.label}{#if os}&nbsp;· {os}{/if}</div>
            </div>
            <span class="right">
              {#if os}
                <span class="badge {os === 'Windows' ? 'badge-info' : os === 'Linux/Unix' ? 'badge-on' : 'badge-warn'}">{os}</span>
              {:else}
                <span class="badge {st.cls}">{st.label}</span>
              {/if}
            </span>
          </div>
          <div class="wol-rows">
            <div class="wol-row"><span class="wol-k">MAC</span><span class="wol-v">{d.mac}</span></div>
            <div class="wol-row"><span class="wol-k">{$i18n("广播")}</span><span class="wol-v">{d.broadcast}:{d.port}</span></div>
          </div>
          <div class="wol-foot">
            <button class="btn btn-sm" class:btn-primary={!on} disabled={waking[d.id] || on}
              title={on ? i18nTr("设备已开机，无需唤醒") : i18nTr("发送 WOL 魔术包")}
              on:click={() => wake(d)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>
              <span>{waking[d.id] ? i18nTr("发送中…") : (on ? i18nTr("已开机") : i18nTr("唤醒"))}</span>
            </button>
            <button class="btn btn-sm btn-icon-only" title={$i18n("编辑设备")} aria-label={$i18n("编辑设备")} on:click={() => openEdit(d)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
            </button>
          </div>
        </div>
      {/each}
    </div>
    <div class="wol-summary">
      <span>{$i18n("上一次扫描：")}{lastScanAt || i18nTr("尚未扫描")} {$i18n("· 发现")} {scanDeviceCount} {$i18n("台设备，")}{onlineCount} {$i18n("台在线")}</span>
      <span class="right">{$i18n("魔术包端口")} {firstDevice.port} {$i18n("· 广播地址")} {firstDevice.broadcast}</span>
    </div>
  {/if}
</div>

{#if showForm}
  <Modal title={editingId ? i18nTr("编辑设备") : i18nTr("添加设备")} width={480} onClose={() => (showForm = false)} closable={!saving}>
    <div bind:this={formEl}>
      <div class="form-group">
        <label class="form-label">{$i18n("设备名称")}</label>
        <input type="text" bind:value={form.name} placeholder={$i18n("如 书房台式机")} use:field={{ check: validateName }} />
      </div>
      <div class="form-group">
        <label class="form-label">{$i18n("MAC 地址")}</label>
        <input type="text" bind:value={form.mac} placeholder="AA:BB:CC:DD:EE:FF" use:field={{ check: validateMAC }} />
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">{$i18n("广播地址")}</label>
          <input type="text" bind:value={form.broadcast} placeholder={DEFAULT_BROADCAST} use:field={{ check: broadcastCheck }} />
        </div>
        <div class="form-group" style="max-width:120px">
          <label class="form-label">{$i18n("端口")}</label>
          <input type="text" bind:value={form.port} placeholder={String(DEFAULT_PORT)} use:field={{ check: (v) => validatePort(v) }} />
        </div>
      </div>
    </div>
    <div slot="footer" style="display:flex;gap:8px;align-items:center">
      {#if editingId}
        <button class="btn btn-danger" style="margin-right:auto" on:click={deleteFromEdit} disabled={saving}>{$i18n("删除设备")}</button>
      {/if}
      <button class="btn" style="margin-left:auto" on:click={() => (showForm = false)} disabled={saving}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={save} disabled={saving}>{saving ? i18nTr("保存中…") : i18nTr("保存")}</button>
    </div>
  </Modal>
{/if}

{#if showScan}
  <Modal title={$i18n("扫描局域网设备")} width={680} onClose={() => (showScan = false)} closable={!scanning}>
    {#if scanning}
      <div class="empty" style="padding:32px 0"><div class="empty-t">{$i18n("正在扫描局域网，请稍候…")}</div></div>
    {:else if scanError}
      <div class="empty" style="padding:32px 0"><div class="empty-t">{scanError}</div></div>
    {:else if !scanHosts.length}
      <div class="empty" style="padding:32px 0"><div class="empty-t">{$i18n("未发现在线设备（需与本机处于同一局域网）")}</div></div>
    {:else}
      <div class="scan-hint">{$i18n("网段")} {scanRange} {$i18n("· 发现")} {scanHosts.length} {$i18n("台设备")}</div>
      <div class="scan-grid">
        {#each scanHosts as h (h.ip)}
          <div class="scan-card">
            <div class="scan-name" class:unknown={!h.hostname} title={h.hostname || i18nTr("未知设备")}>
              {h.hostname || i18nTr("未知设备")}
            </div>
            <div class="scan-ip">{h.ip}</div>
            <div class="scan-mac">{h.mac}</div>
            <div class="scan-actions">
              {#if h.os_hint}
                <span class="badge {h.os_hint === 'Windows' ? 'badge-info' : h.os_hint === 'Linux/Unix' ? 'badge-on' : 'badge-warn'}">{h.os_hint}</span>
              {/if}
              {#if addedMacs.has(h.mac)}
                <span class="scan-action badge badge-off">{$i18n("已添加")}</span>
              {:else}
                <button class="scan-action btn btn-sm btn-primary" disabled={addingMac === h.mac} on:click={() => addScanned(h)}>
                  {addingMac === h.mac ? i18nTr("添加中…") : i18nTr("添加")}
                </button>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {/if}
    <div slot="footer" style="display:flex;gap:8px">
      <button class="btn" on:click={() => (showScan = false)} disabled={scanning}>{$i18n("关闭")}</button>
      <button class="btn btn-primary" on:click={scanLan} disabled={scanning}>{scanning ? i18nTr("扫描中…") : i18nTr("重新扫描")}</button>
    </div>
  </Modal>
{/if}

{#if delTarget}
  <ConfirmModal
    title={$i18n("删除设备")}
    message={`确定删除「${delTarget.name}」？`}
    busy={deleting}
    onConfirm={remove}
    onClose={() => (delTarget = null)}
  />
{/if}

<style>
  .wol-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
  .wol-card{background:var(--bg3);border:1px solid var(--bd);border-radius:calc(var(--radius) + 4px);padding:16px 18px;display:flex;flex-direction:column;gap:12px;box-shadow:var(--shadow-card)}
  .wol-top{display:flex;align-items:center;gap:10px;min-width:0}
  .wol-ico{width:36px;height:36px;flex:none;display:flex;align-items:center;justify-content:center;border-radius:9px;background:var(--bg4);border:1px solid var(--bd);color:var(--text2)}
  .wol-info{min-width:0;flex:1}
  .wol-name{display:flex;align-items:center;gap:7px;font-size:13.5px;font-weight:600;color:var(--text);min-width:0}
  .wol-name-t{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .wol-sub{font-size:10.5px;color:var(--text3);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .wol-top .right{margin-left:auto;flex-shrink:0}
  .wol-dot{width:7px;height:7px;border-radius:50%;flex:none;display:inline-block}
  .wol-rows{display:flex;flex-direction:column;gap:4px}
  .wol-row{display:flex;gap:8px;align-items:baseline;font-size:12px}
  .wol-k{width:32px;flex-shrink:0;color:var(--text3)}
  .wol-v{font-family:var(--mono);color:var(--text2);word-break:break-all}
  .wol-foot{display:flex;align-items:center;gap:6px;margin-top:auto;padding-top:10px;border-top:1px solid var(--sep)}
  .wol-foot .btn:first-child{flex:1;min-width:0}
  /* 底部扫描摘要：与演示页的设备列表页脚一致 */
  .wol-summary{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-top:16px;font-size:11.5px;color:var(--text3)}
  /* 移动端：设备卡片两列铺排，收紧内边距；顶部系统徽章隐藏，状态已写入副标题 */
  @media (max-width:600px){
    /* 页头：标题与操作同排，操作靠右（对齐演示页移动端） */
    .page-hdr{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:start;gap:10px}
    .page-hdr-actions{width:auto;flex-wrap:nowrap}
    .wol-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
    .wol-card{padding:12px;gap:8px}
    .wol-ico{width:32px;height:32px}
    .wol-name{font-size:12.5px}
    .wol-sub{font-size:9.5px}
    .wol-top .right{display:none}
    .wol-row{font-size:11px;gap:6px}
    /* 移动端只保留 MAC，广播地址收进页脚摘要 */
    .wol-row:nth-child(2){display:none}
    .wol-k{width:28px}
    .wol-summary{font-size:10.5px;margin-top:14px;gap:6px}
  }
  .scan-hint{font-size:12px;color:var(--text3);margin-bottom:10px}
  .scan-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;max-height:55vh;overflow-y:auto}
  .scan-card{background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius);padding:12px;display:flex;flex-direction:column;gap:6px;min-width:0}
  .scan-name{font-size:13px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .scan-name.unknown{color:var(--text3);font-weight:500}
  .scan-ip{font-family:var(--mono);font-size:12px;color:var(--text2)}
  .scan-mac{font-family:var(--mono);font-size:11px;color:var(--text3);word-break:break-all}
  .scan-actions{display:flex;align-items:center;gap:6px;margin-top:auto;padding-top:4px}
  .scan-action{margin-left:auto}
</style>
