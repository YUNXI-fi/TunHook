<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 修改服务器名称弹窗：重命名校验唯一性
  import Modal from './Modal.svelte';

  export let onClose = () => {};
  export let onConfirm = () => {};
  export let onSetDefault = () => {};
  export let busy = false;
  export let name = '';   // 原名称
  export let exists = []; // 其他服务器名称列表（重名校验）
  export let isDefault = false; // 该服务器是否为默认服务器

  let newName = name;

  $: nameTaken = exists.includes(newName.trim());
  $: errMsg = nameTaken ? i18nTr("该名称已被占用，请更换一个唯一名称") : '';

  function submit() {
    const n = newName.trim();
    if (!n) {
      errMsg = i18nTr("请填写服务器名称");
      return;
    }
    if (nameTaken) return;
    if (onConfirm) onConfirm(n);
  }
</script>

<Modal title={$i18n("修改服务器名称")} onClose={onClose} width={440} closable={!busy}>
  <div style="display:flex;flex-direction:column;gap:14px">
    <div class="form-group" style="margin-bottom:0">
      <label class="form-label" for="edit-server-name">{$i18n("服务器名称")} <span style="color:var(--red)">*</span></label>
      <input id="edit-server-name" type="text" bind:value={newName} placeholder={$i18n("唯一标识，如：腾讯云 / 家庭NAS / 办公网络")} on:keydown={(e) => { if (e.key === 'Enter' && !busy) submit(); }} />
      {#if errMsg}
        <div class="tip-text" style="color:var(--red)">{errMsg}</div>
      {:else}
        <div class="tip-text">{$i18n("原名称：")}{name}{$i18n("，修改后立即生效并同步切换")}</div>
      {/if}
    </div>
  </div>

  <div slot="footer">
    <button class="btn" on:click={onClose} disabled={busy}>{$i18n("取消")}</button>
    <button
      class="btn"
      on:click={onSetDefault}
      disabled={busy || isDefault}
      title={isDefault ? i18nTr("该服务器已是默认服务器（系统仅允许一个默认服务器）") : i18nTr("将该服务器设为默认服务器")}
      style="white-space:nowrap"
    >
      {isDefault ? i18nTr("已是默认服务器") : i18nTr("设为默认服务器")}
    </button>
    <button class="btn btn-primary" on:click={submit} disabled={busy} style="white-space:nowrap">
      {busy ? i18nTr("保存中…") : i18nTr("保存")}
    </button>
  </div>
</Modal>
