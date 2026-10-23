<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // LoliaFrp OAuth 应用凭据表单：首次配置内联向导与「OAuth 配置」修改弹窗共用。
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';

  export let cfg = null;          // /api/lolia/config 返回值
  export let showCancel = false;  // 是否显示取消按钮（修改弹窗需要，首次向导不需要）
  export let onSaved = () => {};  // 保存成功回调，参数为最新 config
  export let onCancel = () => {};

  // 组件随 {#if} 每次挂载时按当前配置初始化；secret 不回显，留空表示沿用已保存值
  let form = {
    clientId: cfg?.clientId || '',
    clientSecret: '',
    redirectBase: cfg?.redirectBase || ''
  };
  let saving = false;

  async function saveApp() {
    if (!form.clientId.trim()) { toast(i18nTr("请填写 Client ID"), 'error'); return; }
    if (!form.clientSecret.trim() && !cfg?.hasSecret) { toast(i18nTr("请填写 Client Secret"), 'error'); return; }
    saving = true;
    try {
      const d = await api('/api/lolia/config', {
        method: 'POST',
        body: {
          clientId: form.clientId.trim(),
          clientSecret: form.clientSecret.trim(),
          redirectBase: form.redirectBase.trim()
        }
      });
      toast(i18nTr("OAuth 应用配置已保存，请点击「前往授权」"), 'success');
      onSaved(d);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      saving = false;
    }
  }
</script>

<div class="lo-form">
  <div class="form-group">
    <label class="form-label">Client ID</label>
    <input type="text" bind:value={form.clientId} placeholder={$i18n("应用创建后获得，如 6ftlh75kf780f5k4")} autocomplete="off" />
  </div>
  <div class="form-group">
    <label class="form-label">Client Secret</label>
    <input type="password" bind:value={form.clientSecret} placeholder={cfg?.hasSecret ? i18nTr("已保存（修改请重新输入新的 Secret）") : i18nTr("应用密钥，仅保存时使用")} autocomplete="new-password" />
  </div>
  <div class="form-group">
    <label class="form-label">{$i18n("回调基址（可选，覆盖自动推导）")}</label>
    <input type="text" bind:value={form.redirectBase} placeholder={cfg?.redirectOk ? cfg.redirectUri.replace(/\/api\/lolia$/, '') : i18nTr("如 http://1.2.3.4:19520")} autocomplete="off" />
    <div class="lo-tip">{$i18n("留空时自动使用「Webhook」页配置的 IP/域名与端口；只有自动推导不对（如经过反向代理）时才需要手填。")}</div>
  </div>
</div>
<div class="lo-actions" style="margin-top:12px">
  <button class="btn btn-primary" disabled={saving} on:click={saveApp}>{saving ? i18nTr("保存中…") : i18nTr("保存应用配置")}</button>
  {#if showCancel}
    <button class="btn" on:click={onCancel}>{$i18n("取消")}</button>
  {/if}
  <a class="lo-doc" href="https://docs.lolia.link/developers/oauth" target="_blank" rel="noopener noreferrer">{$i18n("查看 OAuth 文档 ↗")}</a>
</div>

<style>
  .lo-form { display: flex; flex-direction: column; gap: 10px; }
  .lo-tip { font-size: 12px; color: var(--text3); line-height: 1.6; }
  .lo-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .lo-doc { font-size: 12px; color: var(--text3); margin-left: auto; }
  .lo-doc:hover { color: var(--accent); }
  @media (max-width: 640px) {
    .lo-doc { margin-left: 0; width: 100%; }
  }
</style>
