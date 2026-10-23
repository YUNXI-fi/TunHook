<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // IP 段数据源管理弹窗：目录刷新 / 勾选更新 / 全量更新 / 导入 / 启用停用
  import Modal from './Modal.svelte';
  import CustomSelect from './CustomSelect.svelte';
  import { api, apiBase } from '../lib/api.js';
  import { toast } from '../lib/stores.js';

  const categoryOptions = [
    { value: 'country', label: i18nTr("country（国家）") },
    { value: 'province', label: i18nTr("province（省份）") },
    { value: 'city', label: i18nTr("city（城市）") },
    { value: 'isp', label: i18nTr("isp（运营商）") },
    { value: 'cloud', label: i18nTr("cloud（公有云）") }
  ];

  export let onClose = () => {};
  export let onUpdated = () => {};

  let sources = [];
  let selected = new Set();
  let loading = false;
  let updating = false;
  let progress = null; // {done, total, percent, label}
  let timer = null;

  // 导入本地 IP 段数据
  let showImport = false;
  let importFile = null;
  let impCat = 'country';
  let impClass = '';
  let impName = '';
  let importing = false;

  async function doImport() {
    if (!importFile) { toast(i18nTr("请选择要导入的数据文件"), 'error'); return; }
    if (!impClass.trim() || !impName.trim()) { toast(i18nTr("请填写分类与归属名称"), 'error'); return; }
    importing = true;
    try {
      const fd = new FormData();
      fd.append('file', importFile);
      fd.append('category', impCat);
      fd.append('class', impClass.trim());
      fd.append('name', impName.trim());
      const resp = await fetch(apiBase + '/api/geoloc/import', { method: 'POST', body: fd });
      const data = await resp.json().catch(() => null);
      if (!resp.ok || (data && data.success === false)) {
        throw new Error((data && data.error) || 'HTTP ' + resp.status);
      }
      toast(i18nTr("导入成功：{0} 段（跳过 {1} 行）", [data.data.imported, data.data.skipped]), 'success');
      showImport = false;
      importFile = null;
      load();
      if (onUpdated) onUpdated();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      importing = false;
    }
  }

  async function load() {
    loading = true;
    try {
      const d = await api('/api/geoloc/sources');
      sources = (d && d.sources) || [];
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      loading = false;
    }
  }

  async function refreshCatalog() {
    try {
      await api('/api/geoloc/catalog/refresh', { method: 'POST' });
      toast(i18nTr("数据源目录刷新已开始"), 'success');
      setTimeout(load, 2500);
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function updateSelected() {
    const ids = [...selected];
    if (!ids.length) { toast(i18nTr("请先勾选要更新的数据源"), 'error'); return; }
    await startUpdate('/api/geoloc/sources/update', { ids });
  }

  async function fullUpdate() {
    await startUpdate('/api/geoloc/update', {});
  }

  async function startUpdate(url, body) {
    updating = true;
    progress = { done: 0, total: 0, percent: 0, label: i18nTr("正在准备更新...") };
    try {
      await api(url, { method: 'POST', body });
      pollProgress();
    } catch (e) {
      toast(e.message, 'error');
      updating = false;
    }
  }

  async function pollProgress() {
    if (timer) clearTimeout(timer);
    try {
      const d = await api('/api/geoloc/stats');
      if (d) {
        const done = d.progress_done || 0;
        const total = d.progress_total || 0;
        progress = {
          done,
          total,
          percent: total > 0 ? Math.round((done / total) * 100) : 0,
          label: total > 0 ? i18nTr("正在更新数据源（{0}/{1}）...", [done, total]) : i18nTr("正在准备更新...")
        };
        if (d.updating) {
          timer = setTimeout(pollProgress, 1500);
        } else {
          updating = false;
          toast(i18nTr("更新完成"), 'success');
          load();
          if (onUpdated) onUpdated();
        }
      }
    } catch (e) {
      updating = false;
    }
  }

  async function toggleSource(s) {
    try {
      await api('/api/geoloc/sources/toggle', { method: 'POST', body: { id: s.id, enabled: !s.enabled } });
      load();
    } catch (e) {
      toast(e.message, 'error');
    }
  }
</script>

<Modal title={$i18n("IP 段数据源管理")} onClose={onClose} width={880}>
  <div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap">
    <button class="btn btn-sm" on:click={refreshCatalog}>{$i18n("刷新目录")}</button>
    <button class="btn btn-sm" on:click={() => (showImport = true)}>{$i18n("导入")}</button>
    <button class="btn btn-sm" on:click={updateSelected} disabled={updating || selected.size === 0}>{$i18n("更新所选（")}{selected.size}）</button>
    <button class="btn btn-sm" on:click={fullUpdate} disabled={updating}>{$i18n("全量更新")}</button>
    <span style="margin-left:auto;font-size:12px;color:var(--text3);align-self:center">{$i18n("共")} {sources.length} {$i18n("个数据源")}</span>
  </div>

  {#if updating && progress}
    <div style="margin-bottom:14px;padding:10px 14px;background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius)">
      <div style="display:flex;justify-content:space-between;align-items:center;font-size:12px;color:var(--text2);margin-bottom:6px">
        <span>{progress.label}</span>
        <span class="mono" style="color:var(--accent);font-weight:600">{progress.done}/{progress.total} · {progress.percent}%</span>
      </div>
      <div class="progress-track"><div class="progress-fill" style="width:{progress.percent}%"></div></div>
    </div>
  {/if}

  <div class="table-wrap" style="max-height:50vh;overflow-y:auto">
    <table>
      <thead>
        <tr>
          <th style="width:44px"><input type="checkbox" on:change={(e) => { if (e.target.checked) sources.forEach((s) => selected.add(s.id)); else selected.clear(); }} style="width:auto;margin:0" /></th>
          <th>ID</th>
          <th>{$i18n("类别")}</th>
          <th>{$i18n("分类")}</th>
          <th>{$i18n("归属名称")}</th>
          <th>{$i18n("IP 数量")}</th>
          <th>{$i18n("更新时间")}</th>
          <th>{$i18n("状态")}</th>
          <th style="width:64px">{$i18n("启用")}</th>
        </tr>
      </thead>
      <tbody>
        {#each sources as s}
          <tr>
            <td><input type="checkbox" checked={selected.has(s.id)} on:change={(e) => { if (e.target.checked) selected.add(s.id); else selected.delete(s.id); }} style="width:auto;margin:0" /></td>
            <td class="cell-id">{s.id}</td>
            <td>{s.category}</td>
            <td>{s.class}</td>
            <td>{s.name}</td>
            <td class="cell-mono">{s.ip_count || 0}</td>
            <td class="cell-mono" style="font-size:11px">{s.updated_at || '-'}</td>
            <td>
              <span class="badge {s.status === 'ok' ? 'badge-on' : s.status === 'error' ? 'badge-error' : 'badge-off'}">{s.status === 'ok' ? i18nTr("正常") : s.status === 'error' ? i18nTr("异常") : i18nTr("未检测")}</span>
            </td>
            <td>
              <input type="checkbox" checked={s.enabled} on:change={() => toggleSource(s)} style="width:auto;margin:0;cursor:pointer" />
            </td>
          </tr>
        {:else}
          <tr><td colspan="9" style="text-align:center;color:var(--text3);padding:24px 0">{loading ? i18nTr("加载中...") : i18nTr("暂无数据源，请先刷新目录")}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>

  <div slot="footer">
    <button class="btn" on:click={onClose}>{$i18n("关闭")}</button>
  </div>
</Modal>

{#if showImport}
  <Modal title={$i18n("导入 IP 段数据")} onClose={() => (showImport = false)} width={560}>
    <div style="display:flex;flex-direction:column;gap:4px">
      <div class="form-group">
        <label class="form-label">{$i18n("数据文件")} <span style="color:var(--red)">*</span></label>
        <input type="file" accept=".txt,.csv,.list,text/plain" on:change={(e) => (importFile = e.target.files[0])} />
        <div class="tip-text">{$i18n("每行一条 IP 段，支持 CIDR（1.0.1.0/24）、ip2region 管道（start|end|...）、起始IP-结束IP 名称 三种格式；# 开头为注释行")}</div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">{$i18n("类别")}</label>
          <CustomSelect bind:value={impCat} options={categoryOptions} />
        </div>
        <div class="form-group">
          <label class="form-label">{$i18n("分类")} <span style="color:var(--red)">*</span></label>
          <input type="text" bind:value={impClass} placeholder={$i18n("例如 广州市IP段")} />
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">{$i18n("归属名称")} <span style="color:var(--red)">*</span></label>
        <input type="text" bind:value={impName} placeholder={$i18n("例如 广州（查询结果展示的名称）")} />
        <div class="tip-text">{$i18n("按「类别 + 分类」唯一标识，重复导入同一分类会覆盖原有 IP 段")}</div>
      </div>
    </div>
    <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px;width:100%">
      <button class="btn" on:click={() => (showImport = false)}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={doImport} disabled={importing}>{importing ? i18nTr("导入中...") : i18nTr("开始导入")}</button>
    </div>
  </Modal>
{/if}
