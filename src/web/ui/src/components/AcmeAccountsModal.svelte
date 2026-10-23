<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // Acme 账户管理弹窗：邮箱 + 账号类型 + 密钥算法，供「域名解析 → Acme 账户」直接管理。
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import Modal from './Modal.svelte';
  import CustomSelect from './CustomSelect.svelte';
  import ConfirmModal from './ConfirmModal.svelte';

  export let onClose = () => {};

  let emails = [];
  let delTarget = ''; // 待删除邮箱（非空时弹出 ConfirmModal）
  let delBusy = false;
  let newAcct = { email: '', ca_type: "Let's Encrypt", key_alg: 'EC 256' };
  const CA_TYPES = ["Let's Encrypt", 'ZeroSSL'];
  const KEY_ALGS = ['EC 256', 'EC 384', 'RSA 2048', 'RSA 3072', 'RSA 4096'];
  const caTypeOptions = CA_TYPES.map((t) => ({ value: t, label: t }));
  const keyAlgOptions = KEY_ALGS.map((k) => ({ value: k, label: k }));

  async function loadEmails() {
    try {
      const d = await api('/api/email/list');
      emails = d || [];
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function addEmail(e) {
    e.preventDefault();
    try {
      await api('/api/email/add', { method: 'POST', body: newAcct });
      newAcct = { email: '', ca_type: "Let's Encrypt", key_alg: 'EC 256' };
      toast(i18nTr("Acme 账户已添加"), 'success');
      loadEmails();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  function delEmail(email) {
    delTarget = email;
  }

  async function confirmDelete() {
    if (!delTarget) return;
    delBusy = true;
    try {
      await api('/api/email/delete', { method: 'POST', body: { email: delTarget } });
      toast(i18nTr("Acme 账户已删除"), 'success');
      delTarget = '';
      loadEmails();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      delBusy = false;
    }
  }

  onMount(loadEmails);
</script>

<Modal title={$i18n("Acme 账户")} onClose={onClose} width={620}>
  <form on:submit={addEmail}>
    <div class="input-action-row" style="margin-bottom:6px">
      <input type="email" bind:value={newAcct.email} placeholder="cert@example.com" style="flex:1" required />
      <CustomSelect bind:value={newAcct.ca_type} options={caTypeOptions} width="130px" />
      <CustomSelect bind:value={newAcct.key_alg} options={keyAlgOptions} width="110px" />
      <button type="submit" class="btn btn-primary">{$i18n("添加")}</button>
    </div>
    <div class="tip-text" style="margin-bottom:14px">{$i18n("Acme 账户 = 联系人邮箱 + 签发机构（账号类型）+ 证书密钥算法，用于 Let's Encrypt / ZeroSSL 免费证书申请")}</div>
  </form>
  <div class="table-wrap" style="max-height:45vh;overflow-y:auto">
    <table>
      <thead><tr><th>{$i18n("联系人邮箱")}</th><th style="width:130px">{$i18n("账号类型")}</th><th style="width:110px">{$i18n("密钥算法")}</th><th style="width:80px">{$i18n("操作")}</th></tr></thead>
      <tbody>
        {#each emails as em}
          <tr>
            <td class="cell-mono">{em.email}</td>
            <td>{em.ca_type}</td>
            <td class="cell-mono">{em.key_alg}</td>
            <td>
              <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} on:click={() => delEmail(em.email)}>
                <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/></svg>
              </button>
            </td>
          </tr>
        {:else}
          <tr><td colspan="4" style="text-align:center;color:var(--text3);padding:20px 0">{$i18n("暂无 Acme 账户，添加后可用于免费证书申请")}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</Modal>

{#if delTarget}
  <ConfirmModal
    title={$i18n("删除 Acme 账户")}
    message={`确定删除 Acme 账户「${delTarget}」吗？使用该账户申请的证书到期自动续签可能失败，此操作不可恢复。`}
    onConfirm={confirmDelete}
    onClose={() => { if (!delBusy) delTarget = ''; }}
    busy={delBusy}
  />
{/if}
