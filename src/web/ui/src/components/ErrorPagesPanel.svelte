<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 错误页面面板：每个状态码对应一份完整 HTML 模板文件（<dataDir>/errorpages/<状态码>.html）。
  // 点「编辑」在弹窗内直接改整页 HTML/CSS，点「访问」打开该错误页的真实渲染结果。
  // 模板被三处 HTTP 入口共用：管理界面 / 通道访问页 / 导航页 / 域名转发 / frpc 反代。
  import { onMount } from 'svelte';
  import { api, apiBase } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import ConfirmModal from './ConfirmModal.svelte';
  import ErrorPageEditModal from './ErrorPageEditModal.svelte';

  // 状态码说明（用于标识，模板内容可整页改写）
  const CODE_LABELS = {
    400: i18nTr("请求无效"),
    401: i18nTr("需要身份验证"),
    403: i18nTr("访问被拒绝"),
    404: i18nTr("页面不存在"),
    405: i18nTr("请求方式不允许"),
    410: i18nTr("内容已失效"),
    500: i18nTr("服务器内部错误"),
    502: i18nTr("网关错误"),
    503: i18nTr("服务暂不可用")
  };

  let pages = []; // [{ code, file, html }]
  let loading = true;
  let showReset = false;
  let resetBusy = false;
  let editing = null; // 正在编辑的模板

  async function load() {
    try {
      pages = (await api('/api/errorpages')) || [];
    } catch (e) {
      toast(i18nTr("读取错误页面模板失败：") + e.message, 'error');
    } finally {
      loading = false;
    }
  }

  async function reset() {
    resetBusy = true;
    try {
      const d = await api('/api/errorpages', { method: 'POST', body: { reset: true } });
      if (d) pages = d;
      showReset = false;
      toast(i18nTr("已恢复内置默认错误页"));
    } catch (e) {
      toast(i18nTr("恢复失败：") + e.message, 'error');
    } finally {
      resetBusy = false;
    }
  }

  // 预览：与访客看到的错误页完全一致（同样的状态码与响应头）
  function preview(code) {
    window.open(apiBase + '/api/errorpages/preview?code=' + code, '_blank');
  }

  function onSaved() {
    editing = null;
    load();
  }

  onMount(load);
</script>

{#if loading}
  <div class="empty"><div class="empty-t">{$i18n("加载中…")}</div></div>
{:else}
  <div class="ep-card">
    <div class="ep-hdr">
      <b>{$i18n("错误页面模板")}</b>
      <span class="ep-sub">{pages.length} {$i18n("个状态码")}</span>
      <span class="right">
        <button class="btn btn-sm" on:click={() => (showReset = true)} disabled={resetBusy}>{$i18n("恢复全部默认")}</button>
      </span>
    </div>

    <div class="ep-grid">
      {#each pages as p (p.code)}
        <div class="ep-item">
          <div class="ep-head">
            <span class="ep-code">{p.code}</span>
            <span class="ep-label">{CODE_LABELS[p.code] || i18nTr("HTTP 错误")}</span>
          </div>
          <div class="ep-file mono" title={p.file}>{p.file}</div>
          <div class="ep-actions">
            <button class="btn btn-sm" on:click={() => (editing = p)}>{$i18n("编辑")}</button>
            <button class="btn btn-sm" on:click={() => preview(p.code)}>{$i18n("预览")}</button>
          </div>
        </div>
      {/each}
    </div>

    <div class="ep-notice">
      {$i18n("错误页面由统一网关与 Webhook 共用，支持直接编辑 HTML；恢复默认会覆盖当前模板。保存即生效。")}
    </div>
  </div>
{/if}

{#if editing}
  <ErrorPageEditModal page={editing} onClose={() => (editing = null)} onSaved={onSaved} />
{/if}

{#if showReset}
  <ConfirmModal
    title={$i18n("恢复默认错误页面")}
    message={$i18n("将九个状态码的 HTML 模板恢复为内置默认页面，当前自定义内容会被覆盖。")}
    confirmText={$i18n("恢复默认")}
    busy={resetBusy}
    onConfirm={reset}
    onClose={() => (showReset = false)}
  />
{/if}

<style>
  .ep-card {
    background: var(--bg3);
    border: 1px solid var(--bd);
    border-radius: calc(var(--radius) + 4px);
    padding: 15px 16px;
    box-shadow: var(--shadow-card);
  }
  .ep-hdr {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 14px;
  }
  .ep-hdr b { font-size: 12.5px; font-weight: 600; color: var(--text); }
  .ep-sub { font-size: 10.5px; color: var(--text3); font-family: var(--mono); }
  .ep-hdr .right { margin-left: auto; }
  .ep-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
  }
  .ep-item {
    display: flex;
    flex-direction: column;
    gap: 6px;
    background: var(--bg4);
    border: 1px solid var(--bd);
    border-radius: 10px;
    padding: 12px 13px;
  }
  .ep-head {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .ep-code {
    font-family: var(--mono);
    font-size: 17px;
    font-weight: 600;
    color: var(--text);
    line-height: 1;
  }
  .ep-label {
    font-size: 10px;
    color: var(--text3);
  }
  .ep-file {
    font-size: 9.5px;
    color: var(--text3);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ep-actions {
    display: flex;
    gap: 6px;
    margin-top: 8px;
  }
  .ep-notice {
    margin-top: 12px;
    padding: 10px 12px;
    border: 1px solid var(--bd);
    border-radius: var(--radius);
    background: var(--bg4);
    font-size: 10.5px;
    color: var(--text3);
    line-height: 1.6;
  }
  @media (max-width: 600px) {
    .ep-card { padding: 14px 16px; }
    .ep-grid { grid-template-columns: 1fr 1fr; }
  }
</style>
