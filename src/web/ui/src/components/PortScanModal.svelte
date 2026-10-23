<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 端口扫描弹窗：本机 / 局域网（流式）/ Docker 三种模式，结果一键填入。
  // 传入 targetIP 时固定扫描该 IP（本地 IP 返回全部监听端口，其他主机探测常见端口）。
  import { onMount } from 'svelte';
  import Modal from './Modal.svelte';
  import { api, streamNDJSON, apiBase } from '../lib/api.js';
  import { optional, validateScanTarget } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';

  export let onClose = () => {};
  export let onPick = null;   // 可选回调 (port) => void
  export let targetIP = '';   // 指定扫描的 IP（非空时忽略模式选择，只扫描该 IP）

  let scanMode = 'local';
  let lanInfo = null; // 自动识别的宿主机局域网网段
  let lanRange = ''; // 局域网扫描范围（可编辑：CIDR 网段 / 单个 IP / 起始IP-结束IP，空=自动识别）
  let items = [];
  let scanning = false;
  let scanStatus = '';
  let abortCtrl = null;
  let scanV6 = false; // 局域网扫描默认不开启 IPv6（可手动勾选）；本机/Docker 扫描固定开启且不显示该选项
  let optsEl;  // 扫描模式选项行容器，发起局域网扫描前对其内部字段统一校验
  let lanErr;  // 局域网范围错误容器（输入框在横向 flex 行内，错误显示在行外）

  // 表头排序：sortKey 为 null 时保持原始顺序（流式到达顺序），
  // 点击同一列循环：未排序 → 升序 → 降序 → 未排序
  let sortKey = null; // 'port' | 'protocol' | 'local_addr' | 'service' | 'web_title'
  let sortAsc = true;

  function toggleSort(key) {
    if (sortKey !== key) {
      sortKey = key;
      sortAsc = true;
    } else if (sortAsc) {
      sortAsc = false;
    } else {
      sortKey = null;
      sortAsc = true;
    }
  }

  function sortArrow(key) {
    if (sortKey !== key) return '';
    return sortAsc ? ' ▲' : ' ▼';
  }

  function compareValue(it, key) {
    switch (key) {
      case 'port':
        return it.port || 0;
      case 'protocol':
        return (it.protocol || '').toLowerCase();
      case 'local_addr':
        return (it.local_addr || '').toLowerCase();
      case 'service':
        return (it.service || '').toLowerCase();
      case 'web_title':
        return (it.web_title || '').toLowerCase();
      default:
        return 0;
    }
  }

  $: sortedItems = (() => {
    if (!sortKey) return items;
    const copy = items.slice();
    copy.sort((a, b) => {
      const va = compareValue(a, sortKey);
      const vb = compareValue(b, sortKey);
      if (va < vb) return sortAsc ? -1 : 1;
      if (va > vb) return sortAsc ? 1 : -1;
      // 主列相等时用端口号兜底保持稳定
      return (a.port || 0) - (b.port || 0);
    });
    return copy;
  })();

  $: fixedIP = (targetIP || '').trim();

  onMount(() => {
    if (fixedIP) scan();
    loadLanInfo();
  });

  // 进入「局域网扫描」模式时刷新自动识别的网段
  $: if (scanMode === 'lan') loadLanInfo();

  async function loadLanInfo() {
    try {
      const d = await api('/api/ports/laninfo');
      lanInfo = d || null;
      // 识别成功后回填为默认扫描范围（用户已手动修改过则保留其输入）
      if (d && d.cidr && !lanRange) lanRange = d.cidr;
    } catch (e) {
      lanInfo = null;
    }
  }

  async function scan() {
    if (scanning) return;
    // 局域网扫描前先校验范围输入（空值合法，交由后端自动识别网段）
    if (!fixedIP && scanMode === 'lan' && !validateAll(optsEl)) return;
    items = [];
    scanStatus = '';
    scanning = true;
    try {
      if (fixedIP) {
        // 固定 IP 扫描（本机地址返回全部监听端口）恒包含 IPv6；NDJSON 流式返回：
        // 发现开放端口即渲染、网页标题异步 update 回填、进度实时刷新，并支持点「停止」中止。
        abortCtrl = new AbortController();
        await streamNDJSON('/api/ports/scan?mode=ip&host=' + encodeURIComponent(fixedIP) + '&ipv6=1&ports=all', (line) => {
          if (line.type === 'item') items = [...items, line.data];
          else if (line.type === 'update') items = items.map(it => scanItemMatch(it, line.data) ? { ...it, ...line.data } : it);
          else if (line.type === 'progress') scanStatus = i18nTr("端口探测 {0} / {1}", [line.data.done, line.data.total]);
          else if (line.type === 'error') scanStatus = line.message || i18nTr("扫描出错");
          else if (line.type === 'done') scanStatus = i18nTr("扫描完成");
        }, abortCtrl.signal);
        if (!scanStatus) scanStatus = i18nTr("扫描完成");
      } else if (scanMode === 'lan') {
        abortCtrl = new AbortController();
        // 使用用户编辑的范围（CIDR / 单个 IP / 起始IP-结束IP），为空时交由后端自动识别
        const range = (lanRange || '').trim() || (lanInfo ? lanInfo.cidr : '');
        const rangeQS = range ? '&range=' + encodeURIComponent(range) : '';
        await streamNDJSON('/api/ports/scan?mode=lan' + rangeQS + (scanV6 ? '&ipv6=1' : '') + '&ports=all', (line) => {
          if (line.type === 'item') items = [...items, line.data];
          else if (line.type === 'update') items = items.map(it => scanItemMatch(it, line.data) ? { ...it, ...line.data } : it);
          else if (line.type === 'error') scanStatus = line.message || i18nTr("扫描出错");
          else if (line.type === 'done') scanStatus = i18nTr("扫描完成");
        }, abortCtrl.signal);
        if (!scanStatus) scanStatus = i18nTr("扫描完成");
      } else if (scanMode === 'docker') {
        abortCtrl = new AbortController();
        await streamNDJSON('/api/ports/scan?mode=docker', (line) => {
          if (line.type === 'item') items = [...items, line.data];
          else if (line.type === 'error') scanStatus = line.message || i18nTr("扫描出错");
          else if (line.type === 'done') scanStatus = i18nTr("扫描完成");
        }, abortCtrl.signal);
        if (!scanStatus) scanStatus = i18nTr("扫描完成");
      } else {
        // 本机扫描恒包含 IPv6：先流式显示全部监听端口，网页标题探测完成实时刷新对应条目
        abortCtrl = new AbortController();
        await streamNDJSON('/api/ports/scan?mode=local&ipv6=1', (line) => {
          if (line.type === 'item') items = [...items, line.data];
          else if (line.type === 'update') items = items.map(it => scanItemMatch(it, line.data) ? line.data : it);
          else if (line.type === 'error') scanStatus = line.message || i18nTr("扫描出错");
          else if (line.type === 'done') scanStatus = i18nTr("扫描完成");
        }, abortCtrl.signal);
        if (!scanStatus) scanStatus = i18nTr("扫描完成");
      }
    } catch (e) {
      if (e.name !== 'AbortError') scanStatus = e.message;
    } finally {
      scanning = false;
      abortCtrl = null;
    }
  }

  function usePort(it) {
    if (onPick) onPick(it);
    onClose();
  }

  // 判断两条扫描条目是否为同一项（按 端口+协议+监听地址 匹配），用于流式 update 刷新
  function scanItemMatch(a, b) {
    return !!(a && b && a.port === b.port && a.protocol === b.protocol && a.local_addr === b.local_addr);
  }

  function stopScan() {
    if (abortCtrl) abortCtrl.abort();
  }
</script>

<Modal title={$i18n("端口扫描")} onClose={onClose} width={1100} fitContent minWidth={500}>
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap">
    <button class="btn btn-primary" on:click={scanning ? stopScan : scan} disabled={scanning && !abortCtrl}>
      {scanning ? i18nTr("停止") : i18nTr("一键扫描")}
    </button>
    <span style="font-size:12px;color:var(--text3)">{scanStatus}{scanning ? i18nTr(" 正在扫描...") : ''} {$i18n("· 共")} {items.length} {$i18n("个端口")}</span>
    <span style="margin-left:auto;font-size:12px;color:var(--text3)">
      {fixedIP ? i18nTr("正在扫描 ") + fixedIP + i18nTr(" 的开放端口") : i18nTr("扫描本机所有对外监听端口及占用进程")}
    </span>
  </div>

  {#if fixedIP}
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px;padding:10px 12px;background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius)">
      <span class="form-label" style="margin:0;text-transform:none;letter-spacing:0">{$i18n("目标 IP")}</span>
      <span style="font-family:var(--mono);font-size:13px;color:var(--accent);font-weight:600">{fixedIP}</span>
      <span style="font-size:12px;color:var(--text3)">
        {fixedIP === '127.0.0.1' || fixedIP === '::1' ? i18nTr("本机地址，返回全部监听端口及占用进程") : i18nTr("探测该主机的开放端口（默认全端口，可关闭仅扫常见端口）")}
      </span>
    </div>
  {:else}
  <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:10px;padding:10px 12px;background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius)" bind:this={optsEl}>
    <span class="form-label" style="margin:0;text-transform:none;letter-spacing:0">{$i18n("扫描模式")}</span>
    <label style="display:flex;align-items:center;gap:4px;font-size:13px;cursor:pointer;color:var(--text2)">
      <input type="radio" bind:group={scanMode} value="local" style="width:auto;margin:0"> {$i18n("本机扫描")}
    </label>
    <label style="display:flex;align-items:center;gap:4px;font-size:13px;cursor:pointer;color:var(--text2)">
      <input type="radio" bind:group={scanMode} value="lan" style="width:auto;margin:0"> {$i18n("局域网扫描")}
    </label>
    <label style="display:flex;align-items:center;gap:4px;font-size:13px;cursor:pointer;color:var(--text2)">
      <input type="radio" bind:group={scanMode} value="docker" style="width:auto;margin:0"> {$i18n("Docker 扫描")}
    </label>
    {#if scanMode === 'lan'}
      <div style="flex:1;min-width:280px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        {#if lanInfo}
          <input type="text" bind:value={lanRange} style="width:220px;font-family:var(--mono);font-size:13px" placeholder={$i18n("192.168.1.0/24 或 192.168.1.5")} use:field={{ check: optional(validateScanTarget), errAt: () => lanErr }} />
        {/if}
      </div>
    {/if}
    {#if scanMode === 'lan'}
      <label style="margin-left:auto;display:flex;align-items:center;gap:4px;font-size:13px;cursor:pointer;color:var(--text2)" title={$i18n("局域网扫描默认仅探测 IPv4 主机，勾选后扫描结果包含 IPv6")}>
        <input type="checkbox" bind:checked={scanV6} style="width:auto;margin:0"> IPV6
      </label>
    {/if}
  </div>
  <div class="field-err" bind:this={lanErr} style="display:none"></div>
  {/if}

  {#if !fixedIP && scanMode === 'lan' && items.length === 0 && !scanning}
    <div style="text-align:center;padding:30px 0;color:var(--text3);font-size:13px">
      {$i18n("点击「一键扫描」自动扫描宿主机所在局域网内的开放端口")}
    </div>
  {:else if items.length === 0 && !scanning}
    <div style="text-align:center;padding:30px 0;color:var(--text3);font-size:13px">
      {fixedIP ? i18nTr("该 IP 暂无开放端口") : scanMode === 'local' ? i18nTr("本机暂无对外监听端口") : scanMode === 'docker' ? i18nTr("未发现 Docker 端口映射") : i18nTr("暂无扫描结果")}
    </div>
  {:else}
    <div class="table-wrap" style="max-height:46vh;overflow-y:auto">
      <table>
        <thead>
          <tr>
            <th class="sortable-th" on:click={() => toggleSort('port')} title={$i18n("点击按端口排序")}>{$i18n("端口")}{sortArrow('port')}</th>
            <th class="sortable-th" on:click={() => toggleSort('protocol')} title={$i18n("点击按协议排序")}>{$i18n("协议")}{sortArrow('protocol')}</th>
            <th class="sortable-th" on:click={() => toggleSort('local_addr')} title={$i18n("点击按监听地址排序")}>{$i18n("监听地址")}{sortArrow('local_addr')}</th>
            <th class="sortable-th" on:click={() => toggleSort('service')} title={$i18n("点击按服务排序")}>{$i18n("服务")}{sortArrow('service')}</th>
            <th class="sortable-th" on:click={() => toggleSort('web_title')} title={$i18n("点击按网页标题排序")}>{$i18n("网页标题")}{sortArrow('web_title')}</th>
            <th style="cursor:default">{$i18n("操作")}</th>
          </tr>
        </thead>
        <tbody>
          {#each sortedItems as it (it.port + '|' + it.protocol + '|' + it.local_addr)}
            <tr>
              <td class="cell-mono" style="color:var(--accent);font-weight:600">{it.port}</td>
              <td class="cell-mono">{it.protocol}</td>
              <td class="cell-mono">{it.local_addr}</td>
              <td>{it.service || '-'}</td>
              <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis">{it.web_title || '-'}</td>
              <td>
                <button class="btn btn-sm btn-primary" on:click={() => usePort(it)}>{$i18n("添加")}</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <div slot="footer">
    <button class="btn" on:click={onClose}>{$i18n("关闭")}</button>
  </div>
</Modal>

<style>
  .sortable-th {
    cursor: pointer;
    user-select: none;
    transition: background 0.15s ease, color 0.15s ease;
  }
  .sortable-th:hover {
    background: var(--bg4);
    color: var(--accent);
  }
</style>
