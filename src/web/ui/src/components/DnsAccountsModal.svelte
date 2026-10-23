<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // DNS 账户管理弹窗：服务商账户的增删，供「域名解析 → DNS 账号」直接管理。
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import Modal from './Modal.svelte';
  import CustomSelect from './CustomSelect.svelte';
  import ConfirmModal from './ConfirmModal.svelte';
  import { DNS_PROVIDER_OPTIONS, DNS_FIELDS, dnsProviderLabel } from '../lib/dnsProviders.js';

  export let onClose = () => {};
  export let onChanged = () => {}; // 账户变动后通知父组件刷新

  let dnsAccounts = [];
  let delTarget = null; // 待删除账户（非 null 时弹出 ConfirmModal）
  let delBusy = false;
  let newDns = { name: '', provider: '', credentials: {} };
  const dnsProviderOptions = DNS_PROVIDER_OPTIONS.map((p) => ({ value: p.value, label: i18nTr(p.label) }));

  function onDnsProviderChange() {
    const creds = {};
    (DNS_FIELDS[newDns.provider] || []).forEach((f) => { creds[f.key] = ''; });
    newDns.credentials = creds;
  }

  async function loadDNSAccounts() {
    try {
      const d = await api('/api/dns/list');
      dnsAccounts = d || [];
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function addDNSAccount(e) {
    e.preventDefault();
    try {
      await api('/api/dns/add', { method: 'POST', body: newDns });
      newDns = { name: '', provider: '', credentials: {} };
      toast(i18nTr("DNS 账户已添加"), 'success');
      loadDNSAccounts();
      onChanged && onChanged();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  function delDNSAccount(a) {
    delTarget = a;
  }

  async function confirmDelete() {
    if (!delTarget) return;
    delBusy = true;
    try {
      await api('/api/dns/delete', { method: 'POST', body: { name: delTarget.name } });
      toast(i18nTr("DNS 账户已删除"), 'success');
      if (newDns.name === delTarget.name) newDns = { name: '', provider: '', credentials: {} };
      delTarget = null;
      loadDNSAccounts();
      onChanged && onChanged();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      delBusy = false;
    }
  }

  onMount(loadDNSAccounts);
</script>

<Modal title={$i18n("DNS 账户")} onClose={onClose} width={620}>
  <form on:submit={addDNSAccount}>
    <div class="input-action-row" style="margin-bottom:12px">
      <input type="text" bind:value={newDns.name} placeholder={$i18n("账户名称，如 aliyun-dns")} style="flex:1" required />
      <CustomSelect bind:value={newDns.provider} options={dnsProviderOptions} width="150px" on:change={onDnsProviderChange} />
      <button type="submit" class="btn btn-primary">{$i18n("添加")}</button>
    </div>
    {#if newDns.provider}
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px 14px;margin-bottom:14px">
        {#each DNS_FIELDS[newDns.provider] || [] as f}
          <div class="form-group">
            <label class="form-label">{f.label}</label>
            {#if f.type === 'password'}
              <input type="password" bind:value={newDns.credentials[f.key]} placeholder={f.label} required autocomplete="new-password" />
            {:else}
              <input type="text" bind:value={newDns.credentials[f.key]} placeholder={f.label} required autocomplete="off" />
            {/if}
          </div>
        {/each}
      </div>
    {:else}
      <div class="tip-text" style="margin-bottom:14px">{$i18n("请先选择 DNS 服务商，再填写对应的 API 凭证")}</div>
    {/if}
  </form>
  <div class="tip-text" style="margin-bottom:10px">{$i18n("DNS 账户用于 ACME 证书的通配符（*.example.com）DNS-01 验证：申请时自动添加 TXT 解析记录，验证后自动删除。")}</div>
  <div class="table-wrap" style="max-height:45vh;overflow-y:auto">
    <table>
      <thead><tr><th>{$i18n("账户名称")}</th><th style="width:150px">{$i18n("服务商")}</th><th style="width:80px">{$i18n("操作")}</th></tr></thead>
      <tbody>
        {#each dnsAccounts as a}
          <tr>
            <td class="cell-mono">{a.name}</td>
            <td>{dnsProviderLabel(a.provider)}</td>
            <td>
              <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} on:click={() => delDNSAccount(a)}>
                <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/></svg>
              </button>
            </td>
          </tr>
        {:else}
          <tr><td colspan="3" style="text-align:center;color:var(--text3);padding:20px 0">{$i18n("暂无 DNS 账户，添加后可用于通配符证书的 DNS-01 验证")}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</Modal>

{#if delTarget}
  <ConfirmModal
    title={$i18n("删除 DNS 账户")}
    message={`确定删除 DNS 账户「${delTarget.name}」吗？依赖该账户的 DNS-01 验证与通配符证书续签将失败，此操作不可恢复。`}
    onConfirm={confirmDelete}
    onClose={() => { if (!delBusy) delTarget = null; }}
    busy={delBusy}
  />
{/if}
