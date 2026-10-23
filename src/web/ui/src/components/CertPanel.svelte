<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // TLS 证书管理面板（内联版）：证书库 / 导入 / Let's Encrypt 申请 / Acme 账户 / DNS 账户
  import { api } from '../lib/api.js';
  import { toast, certInitialView } from '../lib/stores.js';
  import { onMount } from 'svelte';
  import { validateDomain } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';

  let certs = [];
  // 初始视图：外部跳转（如「域名解析 → DNS 账号」）可指定直达某个子视图
  export let initialView = 'list';
  // 取消时由外层处理（如外层是一个需关闭的弹窗）；未传时回退到内部列表视图
  export let onCancel = () => {};
  let view = initialView; // list | import | apply | emails | dns
  let loading = false;
  // 一次性消费初始视图（避免下次正常进入 TLS 时仍停留在该视图）
  onMount(() => {
    if (view !== 'list') {
      certInitialView.set('list');
    }
  });

  // 导入
  let imp = { domain: '', email: '', cert_pem: '', key_pem: '' };
  let importFormEl; // 导入表单容器，提交时对其内部字段统一校验
  // 申请
  let app = { domain: '', email: '', dns_account: '', ca_type: "Let's Encrypt", key_alg: 'EC 256', eab_kid: '', eab_hmac: '' };
  let applyFormEl;  // 申请表单容器，提交时对其内部字段统一校验
  let applyTaskId = '';
  let applyStatus = null;
  let applyTimer = null;
  // 全局自动续签（对所有通过本服务 ACME 签发的证书生效）
  let autoRenew = false;
  let autoRenewDays = 30;
  let autoRenewBusy = false;
  // 邮箱
  let emails = [];
  let newAcct = { email: '', ca_type: "Let's Encrypt", key_alg: 'EC 256' };
  const CA_TYPES = ["Let's Encrypt", 'ZeroSSL'];
  const KEY_ALGS = ['EC 256', 'EC 384', 'RSA 2048', 'RSA 3072', 'RSA 4096'];
  // DNS 账户（DNS-01 验证用）
  let dnsAccounts = [];
  let newDns = { name: '', provider: '', credentials: {} };

  import CustomSelect from './CustomSelect.svelte';
  import ConfirmModal from './ConfirmModal.svelte';
  import { DNS_PROVIDER_OPTIONS, DNS_FIELDS, dnsProviderLabel } from '../lib/dnsProviders.js';
  const caTypeOptions = CA_TYPES.map((t) => ({ value: t, label: t }));
  const keyAlgOptions = KEY_ALGS.map((k) => ({ value: k, label: k }));
  const dnsProviderOptions = DNS_PROVIDER_OPTIONS.map((p) => ({ value: p.value, label: i18nTr(p.label) }));
  $: emailOptions = [{ value: '', label: i18nTr("不使用（可选 DNS 账户走 DNS-01）") }, ...emails.map((em) => ({ value: em.email, label: `${em.email}（${em.ca_type} · ${em.key_alg}）` }))];
  $: dnsAccountOptions = [{ value: '', label: i18nTr("不使用") }, ...dnsAccounts.map((a) => ({ value: a.name, label: `${a.name}（${dnsProviderLabel(a.provider)}）` }))];

  // 切换服务商时初始化对应的凭证字段
  function onDnsProviderChange() {
    const creds = {};
    (DNS_FIELDS[newDns.provider] || []).forEach((f) => { creds[f.key] = ''; });
    newDns.credentials = creds;
  }

  // 证书申请步骤
  const APPLY_STEPS = [i18nTr("提交申请"), i18nTr("申请授权"), i18nTr("等待验证"), i18nTr("签发证书"), i18nTr("完成")];
  const STEP_STYLES = {
    done:   { dot: 'background:rgba(var(--green-rgb),.08);color:var(--green);border:1px solid rgba(var(--green-rgb),.4)', line: 'background:rgba(var(--green-rgb),.4)', label: 'color:var(--green)' },
    active: { dot: 'background:rgba(var(--accent-rgb),.15);color:var(--accent);border:1px solid var(--accent)', line: 'background:var(--bd)', label: 'color:var(--accent);font-weight:600' },
    error:  { dot: 'background:rgba(var(--red-rgb),.08);color:var(--red);border:1px solid var(--red)',      line: 'background:var(--bd)', label: 'color:var(--red);font-weight:600' },
    todo:   { dot: 'background:var(--bg3);color:var(--text3);border:1px solid var(--bd)',                line: 'background:var(--bd)', label: 'color:var(--text3)' }
  };
  // 根据后端返回的 state/step 计算第 i 步（0 起）的展示状态
  function stepUI(i, st, step) {
    const state = st || (applyStatus ? applyStatus.state : 'running');
    const cur = (step > 0 ? step : (applyStatus && applyStatus.step > 0 ? applyStatus.step : 1));
    if (state === 'error') {
      if (i + 1 < cur) return STEP_STYLES.done;
      if (i + 1 === cur) return STEP_STYLES.error;
      return STEP_STYLES.todo;
    }
    if (state === 'done') return STEP_STYLES.done;
    if (i + 1 < cur) return STEP_STYLES.done;
    if (i + 1 === cur) return STEP_STYLES.active;
    return STEP_STYLES.todo;
  }

  // 申请记录列表（域名 + 进度）
  let applyTasks = [];
  async function loadApplyTasks() {
    try {
      const d = await api('/api/cert/apply/list');
      applyTasks = d || [];
    } catch (e) { /* ignore */ }
  }

  async function load() {
    loading = true;
    try {
      const d = await api('/api/cert/list');
      certs = d || [];
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      loading = false;
    }
  }

  // 全局自动续签开关：保存到服务端，所有已签发证书共用
  async function loadAutoRenew() {
    try {
      const d = await api('/api/cert/auto-renew');
      autoRenew = !!(d && d.enabled);
      autoRenewDays = Number(d && d.days) || 30;
    } catch (e) { /* ignore */ }
  }
  async function toggleAutoRenew() {
    if (autoRenewBusy) return;
    autoRenewBusy = true;
    try {
      const d = await api('/api/cert/auto-renew', { method: 'POST', body: { enabled: !autoRenew } });
      autoRenew = !!(d && d.enabled);
      autoRenewDays = Number(d && d.days) || autoRenewDays;
      toast(autoRenew ? i18nTr("已开启全局自动续签（到期前 {0} 天自动申请）", [autoRenewDays]) : i18nTr("已关闭全局自动续签"), 'success');
    } catch (e) {
      toast(i18nTr("设置自动续签失败：") + e.message, 'error');
    } finally {
      autoRenewBusy = false;
    }
  }

  // 选择 Acme 账户时带出该账户的 CA / 密钥类型（仍可手动修改）
  function onEmailChange(e) {
    const email = e && e.detail ? e.detail.value : app.email;
    const em = emails.find((x) => x.email === email);
    if (!em) return;
    if (em.ca_type) app.ca_type = em.ca_type;
    if (em.key_alg) app.key_alg = em.key_alg;
  }

  // 取消：优先交由外层处理（如关闭弹窗），否则回退到内部列表视图
  function cancel() {
    if (onCancel) onCancel();
    view = 'list';
  }

  async function importCert(e) {
    e.preventDefault();
    // 格式校验：域名（支持 *. 通配）非法时就地提示并拦截
    if (!validateAll(importFormEl)) return;
    try {
      await api('/api/cert/import', { method: 'POST', body: imp });
      toast(i18nTr("证书已导入"), 'success');
      imp = { domain: '', email: '', cert_pem: '', key_pem: '' };
      view = 'list';
      load();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  async function applyCert(e) {
    e.preventDefault();
    // 格式校验：域名（支持 *. 通配）非法时就地提示并拦截
    if (!validateAll(applyFormEl)) return;
    try {
      const d = await api('/api/cert/apply', { method: 'POST', body: app });
      applyTaskId = d.task_id;
      applyStatus = { state: 'running', step: 1, message: i18nTr("申请已提交，等待 ACME 验证...") };
      loadApplyTasks();
      pollApply();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  async function pollApply() {
    if (applyTimer) clearTimeout(applyTimer);
    try {
      const d = await api('/api/cert/apply/status?task_id=' + encodeURIComponent(applyTaskId));
      applyStatus = d;
      loadApplyTasks();
      if (d && (d.state === 'running' || d.state === 'pending')) {
        applyTimer = setTimeout(pollApply, 1500);
      } else if (d && d.state === 'done') {
        toast(i18nTr("证书申请成功"), 'success');
        setTimeout(() => { view = 'list'; load(); }, 800);
      }
    } catch (e) {
      /* ignore */
    }
  }

  // 删除确认目标：{ kind: 'cert'|'email'|'dns', label }
  let delItem = null;
  let delItemBusy = false;

  async function deleteCert(c) {
    delItem = { kind: 'cert', label: c.domain };
  }

  async function confirmDeleteItem() {
    if (!delItem) return;
    delItemBusy = true;
    try {
      if (delItem.kind === 'cert') {
        await api('/api/cert/delete', { method: 'POST', body: { domain: delItem.label } });
        toast(i18nTr("证书已删除: ") + delItem.label, 'success');
        load();
      } else if (delItem.kind === 'email') {
        await api('/api/email/delete', { method: 'POST', body: { email: delItem.label } });
        toast(i18nTr("Acme 账户已删除"), 'success');
        loadEmails();
      } else {
        await api('/api/dns/delete', { method: 'POST', body: { name: delItem.label } });
        toast(i18nTr("DNS 账户已删除"), 'success');
        loadDNSAccounts();
      }
      delItem = null;
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      delItemBusy = false;
    }
  }

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

  function delEmail(em) {
    delItem = { kind: 'email', label: em };
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
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  function delDNSAccount(a) {
    delItem = { kind: 'dns', label: a.name };
  }

  // 进入列表视图时刷新数据
  load();
  loadAutoRenew();
</script>

{#if view === 'list'}
  <div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap">
    <button class="btn btn-sm btn-primary" on:click={() => { view = 'apply'; loadApplyTasks(); loadEmails().then(() => { if (!app.email && emails.length) app.email = emails[0]; }); loadDNSAccounts(); }}>{$i18n("申请证书")}</button>
    <button class="btn btn-sm" on:click={() => { view = 'emails'; loadEmails(); }}>{$i18n("Acme 账户")}</button>
    <button class="btn btn-sm" on:click={() => { view = 'dns'; loadDNSAccounts(); }}>{$i18n("DNS 账户")}</button>
    <button class="btn btn-sm" on:click={() => { view = 'import'; }}>{$i18n("导入证书")}</button>
    <button class="btn btn-sm {autoRenew ? 'btn-primary' : ''}" on:click={toggleAutoRenew} disabled={autoRenewBusy} title={$i18n("全局生效：到期前 {0} 天自动重新申请（仅限通过本服务 ACME 签发的证书）", [autoRenewDays])}>{$i18n("自动续签：")}{autoRenew ? i18nTr("开 · 提前 ") + autoRenewDays + i18nTr(" 天") : i18nTr("关")}</button>
    <span style="margin-left:auto;font-size:12px;color:var(--text3);align-self:center">{$i18n("证书库共")} {certs.length} {$i18n("条")}</span>
  </div>
  <div class="table-wrap" style="max-height:50vh;overflow-y:auto">
    <table>
      <thead>
        <tr><th>{$i18n("域名")}</th><th>{$i18n("发证机构")}</th><th>{$i18n("生效日期")}</th><th>{$i18n("到期日期")}</th><th>{$i18n("导入时间")}</th><th>{$i18n("操作")}</th></tr>
      </thead>
      <tbody>
        {#each certs as c}
          <tr>
            <td class="cell-mono" style="color:var(--accent)">{c.domain}</td>
            <td>{c.issuer || '-'}</td>
            <td class="cell-mono">{c.not_before || '-'}</td>
            <td class="cell-mono">{c.not_after || '-'}</td>
            <td class="cell-mono">{c.created_at || '-'}</td>
            <td>
              <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} on:click={() => deleteCert(c)}>
                <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/></svg>
              </button>
            </td>
          </tr>
        {:else}
          <tr><td colspan="6" style="text-align:center;color:var(--text3);padding:20px 0">{loading ? i18nTr("加载中...") : i18nTr("暂无证书，可导入已有证书或申请 Let's Encrypt 免费证书")}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
{:else if view === 'import'}
  <form on:submit={importCert} bind:this={importFormEl}>
    <div class="form-group">
      <label class="form-label">{$i18n("域名")}</label>
      <input type="text" bind:value={imp.domain} placeholder={$i18n("例如 example.com 或 *.example.com")} required use:field={{ check: (v) => validateDomain(v, { wildcard: true }) }} />
    </div>
    <div class="form-group">
      <label class="form-label">{$i18n("联系人邮箱（可选）")}</label>
      <input type="email" bind:value={imp.email} placeholder="cert@example.com" />
    </div>
    <div class="form-group">
      <label class="form-label">{$i18n("证书内容（PEM）")}</label>
      <textarea bind:value={imp.cert_pem} rows="6" style="font-family:var(--mono);font-size:12px" placeholder="-----BEGIN CERTIFICATE-----" required></textarea>
    </div>
    <div class="form-group">
      <label class="form-label">{$i18n("私钥内容（PEM）")}</label>
      <textarea bind:value={imp.key_pem} rows="6" style="font-family:var(--mono);font-size:12px" placeholder="-----BEGIN PRIVATE KEY-----" required></textarea>
    </div>
    <div style="display:flex;justify-content:flex-end;gap:8px">
      <button type="button" class="btn" on:click={cancel}>{$i18n("取消")}</button>
      <button type="submit" class="btn btn-primary">{$i18n("导入证书")}</button>
    </div>
  </form>
{:else if view === 'apply'}
  <form on:submit={applyCert} bind:this={applyFormEl}>
    <div class="form-group">
      <label class="form-label">{$i18n("域名")}</label>
      <input type="text" bind:value={app.domain} placeholder={$i18n("例如 example.com 或 *.example.com")} required use:field={{ check: (v) => validateDomain(v, { wildcard: true }) }} />
      <div class="tip-text">{$i18n("HTTP-01 验证经转发链路响应域名，无需本机 80 端口")}</div>
    </div>
    <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:stretch">
      <div class="form-group" style="flex:1;min-width:200px">
        <label class="form-label">{$i18n("证书颁发机构")}</label>
        <CustomSelect bind:value={app.ca_type} options={caTypeOptions} />
        <div class="tip-text">{$i18n("ZeroSSL 需要填写 EAB 凭据；Let's Encrypt 无需额外配置")}</div>
      </div>
      <div class="form-group" style="flex:1;min-width:200px">
        <label class="form-label">{$i18n("密钥类型")}</label>
        <CustomSelect bind:value={app.key_alg} options={keyAlgOptions} />
        <div class="tip-text">{$i18n("EC 更小更快，RSA 兼容性更广")}</div>
      </div>
    </div>
    {#if app.ca_type === 'ZeroSSL'}
      <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:stretch">
        <div class="form-group" style="flex:1;min-width:200px">
          <label class="form-label">EAB KID</label>
          <input type="text" bind:value={app.eab_kid} placeholder="ZeroSSL EAB Key ID" required autocomplete="off" />
        </div>
        <div class="form-group" style="flex:1;min-width:200px">
          <label class="form-label">EAB HMAC Key</label>
          <input type="password" bind:value={app.eab_hmac} placeholder={$i18n("Base64 编码的 HMAC Key")} required autocomplete="new-password" />
        </div>
      </div>
      <div class="tip-text" style="margin-top:-4px;margin-bottom:10px">{$i18n("在 ZeroSSL 控制台的 Developer → EAB Credentials 中生成 KID 与 HMAC Key")}</div>
    {/if}
    <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:stretch">
      <div class="form-group" style="flex:1;min-width:200px">
        <label class="form-label">{$i18n("Acme 账户（HTTP-01）")}</label>
        <CustomSelect bind:value={app.email} options={emailOptions} on:change={onEmailChange} />
        <div class="tip-text">{$i18n("HTTP-01 验证经转发链路响应域名，无需本机 80 端口；无账户请先在「Acme 账户」中添加")}</div>
      </div>
      <div class="form-group" style="flex:1;min-width:200px">
        <label class="form-label">{$i18n("DNS 账户（DNS-01）")}</label>
        <CustomSelect bind:value={app.dns_account} options={dnsAccountOptions} />
        <div class="tip-text">{$i18n("DNS-01 适用于通配符域名（*.example.com）或 80 端口不可达场景；选择后通过 DNS 服务商 API 自动添加 TXT 记录验证")}</div>
      </div>
    </div>
    <div style="display:flex;justify-content:flex-end;gap:8px">
      <button type="button" class="btn" on:click={cancel}>{$i18n("取消")}</button>
      <button type="submit" class="btn btn-primary">{$i18n("提交申请")}</button>
    </div>
  </form>
  {#if applyStatus}
    <div style="margin-top:14px;padding:12px 14px;background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius)">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;font-size:12px;color:var(--text2);margin-bottom:10px">
        <span>{applyStatus.message || (applyStatus.state === 'done' ? i18nTr("证书申请成功") : i18nTr("处理中..."))}</span>
        <span class="badge {applyStatus.state === 'done' ? 'badge-on' : applyStatus.state === 'error' ? 'badge-error' : 'badge-syncing'}">{applyStatus.state}</span>
      </div>
      <div style="display:flex;align-items:flex-start;gap:4px">
        {#each APPLY_STEPS as s, i}
          {#if i > 0}
            <div style="flex:1;height:2px;border-radius:1px;margin-top:10px;{stepUI(i - 1).line}"></div>
          {/if}
          <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;min-width:0">
            <div style="width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;{stepUI(i).dot}">{i + 1}</div>
            <div style="font-size:11px;text-align:center;white-space:nowrap;{stepUI(i).label}">{s}</div>
          </div>
        {/each}
      </div>
      {#if applyStatus.error}
        <div style="color:var(--red);font-size:12px;margin-top:8px">{applyStatus.error}</div>
      {/if}
      {#if applyStatus.detail}
        <div style="font-family:var(--mono);font-size:11px;color:var(--text3);max-height:140px;overflow-y:auto;margin-top:6px">{applyStatus.detail}</div>
      {/if}
    </div>
  {/if}
  <div style="margin-top:16px;display:flex;justify-content:space-between;align-items:center">
    <div style="font-size:13px;font-weight:600;color:var(--text2)">{$i18n("申请记录")}</div>
    <span style="font-size:11px;color:var(--text3)">{$i18n("最近")} {applyTasks.length} {$i18n("条申请（含进行中与已完成）")}</span>
  </div>
  <div class="table-wrap" style="max-height:32vh;overflow-y:auto;margin-top:8px">
    <table>
      <thead>
        <tr><th style="width:44px">{$i18n("序号")}</th><th>{$i18n("域名")}</th><th>{$i18n("邮箱")}</th><th style="width:110px">{$i18n("状态")}</th><th>{$i18n("申请进度")}</th><th style="width:150px">{$i18n("申请时间")}</th></tr>
      </thead>
      <tbody>
        {#each applyTasks as t, i}
          <tr>
            <td>{i + 1}</td>
            <td class="cell-mono" style="color:var(--accent)">{t.domain}</td>
            <td class="cell-mono">{t.email || '-'}</td>
            <td>
              <span class="badge {t.state === 'done' ? 'badge-on' : t.state === 'error' ? 'badge-error' : 'badge-syncing'}">{t.state}</span>
            </td>
            <td>
              <div style="display:flex;align-items:center;gap:5px">
                <div style="display:flex;gap:3px">
                  {#each APPLY_STEPS as _, si}
                    <span style="width:9px;height:9px;border-radius:50%;{stepUI(si, t.state, t.step).dot}"></span>
                  {/each}
                </div>
                <span style="font-size:11px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:220px" title={t.message}>{t.message}</span>
              </div>
            </td>
            <td class="cell-mono">{t.created_at}</td>
          </tr>
        {:else}
          <tr><td colspan="6" style="text-align:center;color:var(--text3);padding:18px 0">{$i18n("暂无申请记录，提交申请后将在这里显示域名与进度")}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
{:else if view === 'dns'}
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
  <div class="tip-text" style="margin-bottom:10px">{$i18n("DNS 账户用于 ACME 证书的通配符（*.example.com）DNS-01 验证：申请时自动添加 TXT 解析记录，验证后自动删除")}</div>
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
  <div style="display:flex;justify-content:flex-end;margin-top:12px">
    <button class="btn" on:click={() => (view = 'list')}>{$i18n("返回")}</button>
  </div>
{:else}
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
          <tr><td colspan="4" style="text-align:center;color:var(--text3);padding:20px 0">{$i18n("暂无 Acme 账户")}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
  <div style="display:flex;justify-content:flex-end;margin-top:12px">
    <button class="btn" on:click={() => (view = 'list')}>{$i18n("返回")}</button>
  </div>
{/if}

{#if delItem}
  <ConfirmModal
    title={delItem.kind === 'cert' ? i18nTr("删除证书") : delItem.kind === 'email' ? i18nTr("删除 Acme 账户") : i18nTr("删除 DNS 账户")}
    message={
      delItem.kind === 'cert'
        ? `确定删除证书「${delItem.label}」吗？删除后 HTTPS 服务将无法继续使用该证书，此操作不可恢复。`
        : delItem.kind === 'email'
          ? `确定删除 Acme 账户「${delItem.label}」吗？使用该账户申请的证书到期自动续签可能失败，此操作不可恢复。`
          : `确定删除 DNS 账户「${delItem.label}」吗？依赖该账户的 DNS-01 验证与通配符证书续签将失败，此操作不可恢复。`
    }
    onConfirm={confirmDeleteItem}
    onClose={() => { if (!delItemBusy) delItem = null; }}
    busy={delItemBusy}
  />
{/if}
