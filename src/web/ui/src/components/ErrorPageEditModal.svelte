<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 错误页模板编辑弹窗：直接编辑该状态码对应的整页 HTML 文件内容。
  // 保存即写入 <dataDir>/errorpages/<状态码>.html 并立即对所有 HTTP 入口生效。
  import Modal from './Modal.svelte';
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';

  export let page; // { code, file, html }
  export let onClose = () => {};
  export let onSaved = () => {};

  let html = page.html;
  let saving = false;

  async function save() {
    saving = true;
    try {
      await api('/api/errorpages', { method: 'POST', body: { code: page.code, html } });
      toast(page.code + i18nTr(" 错误页已保存并生效"));
      onSaved();
    } catch (e) {
      toast(i18nTr("保存失败：") + e.message, 'error');
    } finally {
      saving = false;
    }
  }
</script>

<Modal title={$i18n("编辑 {0} 错误页", [page.code])} width={900} onClose={onClose} closable={!saving}>
  <div class="tip-text" style="margin-bottom:8px;line-height:1.7">
    {$i18n("正在编辑模板文件")} <span class="mono" style="color:var(--accent)">{page.file}</span>{$i18n("，\n    整页 HTML / CSS 可自由修改，保存后立即生效（也可直接用编辑器改该文件）。")}
  </div>
  <textarea class="ep-editor" bind:value={html} spellcheck="false"></textarea>
  <div slot="footer">
    <button class="btn" on:click={onClose} disabled={saving}>{$i18n("取消")}</button>
    <button class="btn btn-primary" on:click={save} disabled={saving}>{saving ? i18nTr("保存中…") : i18nTr("保存")}</button>
  </div>
</Modal>

<style>
  .ep-editor {
    width: 100%;
    min-height: 56vh;
    max-height: 62vh;
    font-family: var(--mono);
    font-size: 12.5px;
    line-height: 1.65;
    tab-size: 2;
    white-space: pre;
    resize: vertical;
  }
</style>
