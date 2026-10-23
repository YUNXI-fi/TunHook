<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 通用删除确认弹窗；传入 requireText 时需在输入框内输入与 requireText 完全一致的文本才能确认。
  import Modal from './Modal.svelte';

  export let title = i18nTr("确认删除");
  export let message = '';
  export let confirmText = i18nTr("删除");
  export let onConfirm = () => {};
  export let onClose = () => {};
  export let busy = false;
  export let requireText = '';  // 需输入匹配的文本（如主机记录名），为空则无需输入

  let input = '';
  $: matched = !requireText || input.trim() === requireText.trim();
</script>

<Modal {title} onClose={onClose} width={420} closable={!busy}>
  <div style="font-size:13px;color:var(--text2);line-height:1.8">{message}</div>
  {#if requireText}
    <div style="margin-top:12px">
      <label class="form-label">{$i18n("请输入「")}<span style="font-family:var(--mono);color:var(--accent)">{requireText}</span>{$i18n("」以确认")}</label>
      <input
        type="text"
        bind:value={input}
        placeholder={requireText}
        style="margin-top:4px"
        on:keydown={(e) => { if (e.key === 'Enter' && matched && !busy) onConfirm(); }}
      />
    </div>
  {/if}
  <div slot="footer" style="display:flex;gap:8px">
    <button class="btn" on:click={onClose} disabled={busy}>{$i18n("取消")}</button>
    <button class="btn btn-danger" on:click={onConfirm} disabled={busy || (requireText ? !matched : false)}>{busy ? i18nTr("处理中...") : confirmText}</button>
  </div>
</Modal>
