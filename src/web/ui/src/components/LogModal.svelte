<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 通道/转发日志弹窗
  import { onMount } from 'svelte';
  import Modal from './Modal.svelte';
  import CustomSelect from './CustomSelect.svelte';
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import ConfirmModal from './ConfirmModal.svelte';

  const levelOptions = [
    { value: '', label: i18nTr("全部级别") },
    { value: 'info', label: 'INFO' },
    { value: 'warn', label: 'WARN' },
    { value: 'error', label: 'ERROR' },
    { value: 'debug', label: 'DEBUG' }
  ];
  const categoryOptions = [
    { value: '', label: i18nTr("全部日志") },
    { value: 'channel', label: i18nTr("仅运行日志") },
    { value: 'access', label: i18nTr("仅访问日志") }
  ];

  export let kind = 'tunnel'; // tunnel | forward
  export let id = '';
  export let title = i18nTr("通道日志");
  export let onClose = () => {};

  let page = 1;
  let pageSize = 50;
  let level = '';
  let search = '';
  let category = '';
  let entries = [];
  let total = 0;
  let loading = false;

  async function load() {
    loading = true;
    try {
      const q = new URLSearchParams({ page, pageSize, level, search, category });
      q.set(kind, id);
      const d = await api('/api/logs?' + q.toString());
      if (d) {
        entries = d.entries || [];
        total = d.total || 0;
      }
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      loading = false;
    }
  }

  let showClearConfirm = false;
  let clearing = false;

  function clearLogs() {
    showClearConfirm = true;
  }

  async function confirmClearLogs() {
    clearing = true;
    try {
      await api('/api/settings/logs/cleanup?all=true', { method: 'POST' });
      toast(i18nTr("日志已清空"));
      showClearConfirm = false;
      page = 1;
      load();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      clearing = false;
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  onMount(load);
</script>

<Modal {title} onClose={onClose} width={860}>
  <div class="log-filters">
    <input type="text" bind:value={search} placeholder={$i18n("搜索日志内容...")} on:keydown={(e) => { if (e.key === 'Enter') load(); }} />
    <CustomSelect bind:value={level} options={levelOptions} on:change={load} />
    <CustomSelect bind:value={category} options={categoryOptions} on:change={load} />
    <button class="btn" on:click={load}>{$i18n("搜索")}</button>
    <button class="btn btn-danger" on:click={clearLogs} disabled={clearing}>{clearing ? i18nTr("清空中…") : i18nTr("清空")}</button>
  </div>

  <div class="table-wrap" style="max-height:46vh;overflow-y:auto">
    <table class="log-table">
      <thead>
        <tr><th style="width:70px">{$i18n("级别")}</th><th style="width:170px">{$i18n("时间")}</th><th>{$i18n("消息")}</th></tr>
      </thead>
      <tbody>
        {#each entries as e}
          <tr>
            <td style="text-align:center"><span class="badge badge-{e.level==='error'?'error':e.level==='warn'?'warn':e.level==='debug'?'off':'on'}">{e.level}</span></td>
            <td>{e.time}</td>
            <td>{e.message}</td>
          </tr>
        {:else}
          <tr><td colspan="3" style="text-align:center;color:var(--text3);padding:24px 0">{$i18n("暂无日志")}{loading ? i18nTr("，加载中...") : ''}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>

  <div class="pagination">
    <button class="btn btn-sm" disabled={page <= 1} on:click={() => { page--; load(); }}>{$i18n("上一页")}</button>
    <span>{$i18n("第")} {page} / {totalPages} {$i18n("页 · 共")} {total} {$i18n("条")}</span>
    <button class="btn btn-sm" disabled={page >= totalPages} on:click={() => { page++; load(); }}>{$i18n("下一页")}</button>
  </div>
</Modal>

{#if showClearConfirm}
  <ConfirmModal
    title={$i18n("清空全部日志")}
    message={$i18n("将清空所有通道与转发的运行/访问历史日志，此操作不可恢复。确定清空吗？")}
    confirmText={$i18n("清空")}
    onConfirm={confirmClearLogs}
    onClose={() => { if (!clearing) showClearConfirm = false; }}
    busy={clearing}
  />
{/if}
