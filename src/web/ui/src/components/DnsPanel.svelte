<script>
  // 域名解析面板：选择 DNS 服务商账户 → 列域名 → 管理解析记录（增/改/删 + 一键指向公网IP）
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  import CustomSelect from './CustomSelect.svelte';
  import CertPanel from './CertPanel.svelte';
  import DnsAccountsModal from './DnsAccountsModal.svelte';
  import AcmeAccountsModal from './AcmeAccountsModal.svelte';
  import AddRecordModal from './AddRecordModal.svelte';
  import ConfirmModal from './ConfirmModal.svelte';
  import Modal from './Modal.svelte';
  import { validateURL } from '../lib/utils.js';
  import { dnsProviderLabel } from '../lib/dnsProviders.js';
  import { field, validateAll } from '../lib/field.js';

  // ===== DNS 账户 =====
  let accounts = [];
  let account = '';

  // ===== 账户弹窗 =====
  let showDnsAccounts = false;
  let showAcmeAccounts = false;

  // ===== 运行状态（公网地址 / 服务商数量 / 最近更新时间） =====
  let pubIPv4 = '';
  let pubIPv6 = '';
  let pubCachedAt = '';

  // ===== 域名 / 记录 =====
  let domains = [];
  let domain = '';
  let records = [];
  let loadingRecords = false;
  let loadingDomains = false;

  // ===== 新增/编辑记录弹窗 =====
  let showAddRecord = false;
  let editingRec = null; // 编辑时传入的记录对象，新增为 null

  // ===== 删除记录确认弹窗 =====
  let delRecord = null;    // 待删除记录
  let delBusy = false;

  // ===== 公网 IP 获取方式设置弹窗 =====
  let showPubSrc = false;
  let pubCfg = { method: 'curl', v4_url: '', v6_url: '' };
  let pubCfgEl; // 回显 URL 表单行容器，保存配置时对其内部字段统一校验
  let pubCfgBusy = false;

  // ===== 证书申请 / 导入弹窗 =====
  let showCert = false;
  let certMode = 'apply'; // apply | import

  // ===== 全局自动续签 =====
  let autoRenew = false;
  let autoRenewDays = 30;
  let showAutoRenew = false;
  let autoRenewForm = { enabled: true, days: 30 };
  let autoRenewBusy = false;

  // ===== 页签：解析记录 / 动态解析 / TLS 证书 =====
  let dnsTab = 'records'; // records | ddns | certs
  let ddnsTasks = [];
  let ddnsBusy = false;
  let ddnsDel = null;
  let ddnsDeleting = false;
  let certs = [];

  // 可选记录类型
  const REC_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'NS', 'SRV', 'CAA'];
  const recTypeOptions = REC_TYPES.map((t) => ({ value: t, label: t }));

  async function loadAccounts() {
    try {
      const d = await api('/api/dns/list');
      accounts = d || [];
      if (!account && accounts.length) account = accounts[0].name;
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function loadPublicIP() {
    // 不带 refresh：优先读取后端已缓存的结果（仪表盘/DDNS 都会定期更新），避免每次进入面板都强制重新探测
    try {
      const d = await api('/api/network/public');
      pubIPv4 = d.ipv4 || '';
      pubIPv6 = d.ipv6 || '';
      pubCachedAt = d.cached_at || '';
    } catch (e) {
      // 公网探测失败不阻断面板显示
      pubIPv4 = '';
      pubIPv6 = '';
      pubCachedAt = '';
    }
  }

  // 打开公网 IP 获取方式设置弹窗
  async function openPubCfg() {
    showPubSrc = true;
    pubCfgBusy = true;
    try {
      const d = await api('/api/network/public/config');
      pubCfg = {
        method: d.method || 'http',
        v4_url: d.v4_url || 'https://ipv4.icanhazip.com',
        v6_url: d.v6_url || 'https://ipv6.icanhazip.com/'
      };
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      pubCfgBusy = false;
    }
  }

  // 保存公网 IP 获取方式配置
  async function savePubCfg() {
    // 格式校验：回显 URL 非法时就地提示并拦截
    if (!validateAll(pubCfgEl)) return;
    pubCfgBusy = true;
    try {
      const d = await api('/api/network/public/config', { method: 'POST', body: pubCfg });
      toast(i18nTr("已保存，正在重新探测公网地址"), 'success');
      showPubSrc = false;
      // 强制刷新公网地址
      await api('/api/network/public?refresh=1');
      loadPublicIP();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      pubCfgBusy = false;
    }
  }

  // 复制文本到剪贴板
  async function copyText(text) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      toast(i18nTr("已复制: ") + text, 'success');
    } catch (e) {
      // 部分环境无 clipboard API，回退 execCommand
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        toast(i18nTr("已复制: ") + text, 'success');
      } catch (e2) {
        toast(i18nTr("复制失败"), 'error');
      }
    }
  }

  async function loadDomains() {
    if (!account) { domains = []; domain = ''; records = []; return; }
    loadingDomains = true;
    try {
      const d = await api('/api/dns/domains?account=' + encodeURIComponent(account));
      domains = d || [];
      domain = domains.length ? domains[0].name : '';
      loadRecords();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      loadingDomains = false;
    }
  }

  async function loadRecords() {
    if (!account || !domain) { records = []; return; }
    loadingRecords = true;
    try {
      const d = await api('/api/dns/records?account=' + encodeURIComponent(account) + '&domain=' + encodeURIComponent(domain));
      records = d || [];
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      loadingRecords = false;
    }
  }

  function onAccountChange() {
    loadDomains();
  }

  // 打开删除确认弹窗（需输入主机记录名确认）
  function askDelRecord(rec) {
    delRecord = rec;
    delBusy = false;
  }

  // 执行删除操作
  async function confirmDelRecord() {
    if (!delRecord) return;
    delBusy = true;
    try {
      await api('/api/dns/record/delete', { method: 'POST', body: { account, domain, id: delRecord.id } });
      toast(i18nTr("记录已删除"), 'success');
      delRecord = null;
      loadRecords();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      delBusy = false;
    }
  }

  // 打开新增记录弹窗
  function openAddRecord() {
    editingRec = null;
    showAddRecord = true;
  }

  // 打开编辑记录弹窗
  function openEditRecord(rec) {
    editingRec = rec;
    showAddRecord = true;
  }

  // 主机记录 + 域名 → 完整域名（@/空 表示根域名）
  function fullRecordName(rr) {
    const r = (rr || '@').trim();
    if (r === '@' || r === '') return domain;
    return r + '.' + domain;
  }

  // 打开 DNS 账户管理弹窗
  function goDNSAccounts() {
    showDnsAccounts = true;
  }

  // 打开 Acme 账户管理弹窗
  function goAcmeAccounts() {
    showAcmeAccounts = true;
  }

  // 打开「申请证书」弹窗
  function goApplyCert() {
    certMode = 'apply';
    showCert = true;
  }

  // 打开「导入证书」弹窗
  function goImportCert() {
    certMode = 'import';
    showCert = true;
  }

  // 弹窗关闭后刷新账户列表（可能新增/删除账户）
  function onAccountsChanged() {
    loadAccounts().then(() => {
      if (!account && accounts.length) account = accounts[0].name;
      if (account) loadDomains();
    });
  }

  // 全局自动续签开关（与证书面板共用同一服务端设置）
  async function loadAutoRenew() {
    try {
      const d = await api('/api/cert/auto-renew');
      autoRenew = !!(d && d.enabled);
      autoRenewDays = Number(d && d.days) || 30;
    } catch (e) { /* ignore */ }
  }
  // openAutoRenew 打开自动续签设置弹窗，表单初始值取当前配置。
  function openAutoRenew() {
    autoRenewForm = { enabled: autoRenew, days: autoRenewDays };
    showAutoRenew = true;
  }
  async function saveAutoRenew() {
    if (autoRenewBusy) return;
    const days = Number(autoRenewForm.days);
    if (!days || days < 1 || days > 90) {
      toast(i18nTr("提前续签天数应在 1-90 之间"), 'error');
      return;
    }
    autoRenewBusy = true;
    try {
      const d = await api('/api/cert/auto-renew', { method: 'POST', body: { enabled: !!autoRenewForm.enabled, days } });
      autoRenew = !!(d && d.enabled);
      autoRenewDays = Number(d && d.days) || days;
      showAutoRenew = false;
      toast(autoRenew ? i18nTr("已开启自动续签：到期前 {0} 天申请", [autoRenewDays]) : i18nTr("已关闭自动续签"), 'success');
    } catch (e) {
      toast(i18nTr("设置自动续签失败：") + e.message, 'error');
    } finally {
      autoRenewBusy = false;
    }
  }

  // ===== 动态解析任务 =====
  async function loadDDNS() {
    try {
      ddnsTasks = (await api('/api/ddns/list')) || [];
    } catch (e) {
      toast(i18nTr("读取动态解析任务失败：") + e.message, 'error');
    }
  }
  async function toggleDDNS(t) {
    if (ddnsBusy) return;
    ddnsBusy = true;
    try {
      await api('/api/ddns/toggle', { method: 'POST', body: { id: t.id, enabled: !t.enabled } });
      await loadDDNS();
      toast(t.enabled ? i18nTr("动态解析已停用") : i18nTr("动态解析已启用"), 'success');
    } catch (e) {
      toast(i18nTr("更新动态解析状态失败：") + e.message, 'error');
    } finally {
      ddnsBusy = false;
    }
  }
  async function updateAllDDNS() {
    if (ddnsBusy) return;
    ddnsBusy = true;
    try {
      await api('/api/ddns/now', { method: 'POST' });
      await loadDDNS();
      toast(i18nTr("已触发动态解析更新"), 'success');
    } catch (e) {
      toast(i18nTr("更新动态解析失败：") + e.message, 'error');
    } finally {
      ddnsBusy = false;
    }
  }
  async function removeDDNS() {
    if (!ddnsDel) return;
    ddnsDeleting = true;
    try {
      await api('/api/ddns/delete', { method: 'POST', body: { id: ddnsDel.id } });
      ddnsDel = null;
      await loadDDNS();
      toast(i18nTr("动态解析任务已删除"), 'success');
    } catch (e) {
      toast(i18nTr("删除动态解析任务失败：") + e.message, 'error');
    } finally {
      ddnsDeleting = false;
    }
  }
  $: if (dnsTab === 'ddns') loadDDNS();

  // ===== TLS 证书列表（摘要卡与 TLS 页签共用） =====
  async function loadCerts() {
    try {
      certs = (await api('/api/cert/list')) || [];
    } catch (e) { /* ignore */ }
  }
  $: if (dnsTab === 'certs') loadCerts();

  onMount(() => {
    loadPublicIP();
    loadAutoRenew();
    loadCerts();
    loadAccounts().then(() => {
      loadDomains();
    });
  });
</script>

<div class="dns-page page-list">
  <div class="page-hdr">
    <div>
      <h2>{$i18n('dns.title')}</h2>
      <span class="page-hdr-sub">{$i18n('dns.sub')}</span>
    </div>
    <div class="page-hdr-actions hdr-actions-wrap">
      <button class="btn" on:click={goDNSAccounts}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 8.8-8.8"/><path d="m15.5 7.5 2.5 2.5"/><path d="m18.5 4.5 2.5 2.5"/></svg>
        <span class="sm-hide">{$i18n("DNS 账号")}</span>
      </button>
      <button class="btn" on:click={goAcmeAccounts}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
        <span class="sm-hide">{$i18n("Acme 账户")}</span>
      </button>
      <button class="btn btn-primary" on:click={openAddRecord} disabled={!accounts.length}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/></svg>
        <span class="sm-hide">{$i18n("添加解析")}</span>
      </button>
    </div>
  </div>

  <!-- 运行状态：当前公网地址 + 关键指标 -->
  <div class="card dns-summary">
    <div class="dns-addr-block">
      <div class="dns-card-title">
        <span>{$i18n("当前公网地址")}</span>
        <button type="button" class="dns-link" on:click={openPubCfg} title={$i18n("设置公网 IP 获取方式")}>{$i18n("设置获取方式")}</button>
      </div>
      <div class="dns-addr-grid">
        <div class="dns-addr">
          <div class="dns-addr-label">IPv4</div>
          <button type="button" class="dns-addr-val accent" on:click={() => copyText(pubIPv4)} title={$i18n("点击复制 IPv4 地址")}>{pubIPv4 || i18nTr("未检测到地址")}</button>
          <div class="dns-addr-meta">{pubCachedAt ? i18nTr("最后检查 ") + pubCachedAt : i18nTr("尚未检查")}</div>
        </div>
        <div class="dns-addr">
          <div class="dns-addr-label">IPv6</div>
          <button type="button" class="dns-addr-val" on:click={() => copyText(pubIPv6)} title={$i18n("点击复制 IPv6 地址")}>{pubIPv6 || i18nTr("未检测到地址")}</button>
          <div class="dns-addr-meta">{$i18n("点击地址复制")}</div>
        </div>
      </div>
    </div>
    <div class="dns-metrics">
      <div class="sys-cell"><span>{$i18n("更新范围")}</span><b>IPv4 &amp; IPv6</b></div>
      <div class="sys-cell"><span>{$i18n("域名数量")}</span><b>{domains.length}</b></div>
      <div class="sys-cell"><span>{$i18n("DNS 账号")}</span><b>{accounts.length}</b></div>
      <div class="sys-cell"><span>{$i18n("TLS 证书")}</span><b>{certs.length} {$i18n("张")}</b></div>
    </div>
  </div>

  <!-- 页签：解析记录 / 动态解析 / TLS 证书 -->
  <div class="dns-tabs">
    <button class="dns-tab" class:active={dnsTab === 'records'} on:click={() => (dnsTab = 'records')}>{$i18n("解析记录")}</button>
    <button class="dns-tab" class:active={dnsTab === 'ddns'} on:click={() => (dnsTab = 'ddns')}>{$i18n("动态解析")}</button>
    <button class="dns-tab" class:active={dnsTab === 'certs'} on:click={() => (dnsTab = 'certs')}>{$i18n("TLS 证书")}</button>
  </div>

  <!-- 操作按钮：仅动态解析页需要独立的批量操作入口 -->
  {#if dnsTab === 'ddns'}
  <div class="dns-toolbar">
    <div class="dns-tool-group dns-tool-links">
      <span class="dns-tool-label">{$i18n("动态解析")}</span>
      <span class="dns-tool-hint">{$i18n("IP 变化时自动更新记录")}</span>
    </div>
    <div class="dns-tool-group">
      <button class="btn btn-sm" on:click={loadDDNS} disabled={ddnsBusy}>{$i18n("刷新")}</button>
      <button class="btn btn-sm btn-primary" on:click={updateAllDDNS} disabled={ddnsBusy}>{$i18n("立即更新")}</button>
    </div>
  </div>
  {/if}

  {#if dnsTab === 'records'}
  {#if !accounts.length}
    <div class="card dns-empty">
      {$i18n("暂无 DNS 账户，请先点击上方「DNS 账号」添加阿里云 / DNSPod（国内/国际）/ 华为云 / Cloudflare / GoDaddy / Vercel 账户")}
    </div>
  {:else}
    <!-- 账户选择 + 域名选择 -->
    <div class="card dns-picker">
      <div class="dns-field">
        <label class="form-label">{$i18n("DNS 账户")}</label>
        <CustomSelect bind:value={account} options={accounts.map((a) => ({ value: a.name, label: a.name + '（' + dnsProviderLabel(a.provider) + '）' }))} on:change={onAccountChange} />
      </div>
      <div class="dns-field dns-field-grow">
        <label class="form-label">{$i18n("域名")}</label>
        <CustomSelect bind:value={domain} options={domains.map((d) => ({ value: d.name, label: d.name + '（' + d.record_count + i18nTr(" 条）") }))} on:change={loadRecords} />
      </div>
    </div>

    <p class="dns-hint">
      {$i18n("选择 DNS 服务商账户后，可查看其名下域名并管理解析记录（A / AAAA / CNAME / TXT 等）；支持动态解析与 TLS 证书自动续签。账户请在「DNS 账号」中添加。")}
    </p>

    <!-- 记录列表：桌面表格 -->
    <div class="table-wrap dns-table-wrap">
      <table>
        <thead>
          <tr><th>{$i18n("域名")}</th><th>{$i18n("主机记录")}</th><th>{$i18n("类型")}</th><th>{$i18n("记录值")}</th><th>TTL</th><th>{$i18n("最近更新")}</th><th>{$i18n("操作")}</th></tr>
        </thead>
        <tbody>
          {#each records as rec}
            <tr>
              <td class="cell-mono dns-name" style="word-break:break-all">{fullRecordName(rec.name)}</td>
              <td class="cell-mono">{rec.name}</td>
              <td><span class="rec-type">{rec.type}</span></td>
              <td class="cell-mono" style="word-break:break-all">{rec.value || '-'}</td>
              <td class="cell-mono">{rec.ttl || '-'}</td>
              <td class="cell-mono" style="white-space:nowrap">{rec.updated || '-'}</td>
              <td>
                <span class="row-actions">
                  <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑记录")} on:click={() => openEditRecord(rec)}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
                  </button>
                  <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} aria-label={$i18n("删除记录")} on:click={(e) => { e.stopPropagation(); askDelRecord(rec); }}>
                    <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/></svg>
                  </button>
                </span>
              </td>
            </tr>
          {:else}
            <tr><td colspan="7" style="text-align:center;color:var(--text3);padding:20px 0">{loadingRecords ? i18nTr("加载中...") : i18nTr("该域名暂无记录")}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>

    <!-- 记录列表：移动端卡片 -->
    <div class="list-cards dns-cards">
      {#each records as rec}
        <div class="list-card">
          <div class="list-card-top">
            <div class="list-card-avatar">{(rec.type || '?').charAt(0)}</div>
            <div class="list-card-title">{fullRecordName(rec.name)}</div>
            <span class="rec-type right">{rec.type}</span>
          </div>
          <div class="list-card-rows">
            <div class="list-card-row"><span class="k">{$i18n("主机记录")}</span><span class="v">{rec.name}</span></div>
            <div class="list-card-row"><span class="k">{$i18n("记录值")}</span><span class="v mono">{rec.value || '-'}</span></div>
            <div class="list-card-row"><span class="k">TTL</span><span class="v">{rec.ttl || '-'}</span></div>
            <div class="list-card-row"><span class="k">{$i18n("最近更新")}</span><span class="v">{rec.updated || '-'}</span></div>
          </div>
          <div class="list-card-actions">
            <button class="btn-icon" title={$i18n("编辑")} aria-label={$i18n("编辑记录")} on:click={() => openEditRecord(rec)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
            </button>
            <button class="btn-icon" style="color:var(--red)" title={$i18n("删除")} aria-label={$i18n("删除记录")} on:click={() => askDelRecord(rec)}>
              <svg width="14" height="14" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/></svg>
            </button>
          </div>
        </div>
      {:else}
        <div class="list-cards-empty">{loadingRecords ? i18nTr("加载中...") : i18nTr("该域名暂无记录")}</div>
      {/each}
    </div>

    <div class="dns-record-foot">
      <span>{$i18n("共")} {records.length} {$i18n("条记录")}</span>
      <span class="dns-foot-meta">{$i18n("数据来自所选 DNS 服务商")}</span>
    </div>
  {/if}
  {:else if dnsTab === 'ddns'}
    <div class="card dns-tab-card">
      <div class="dns-tab-h">
        <b>{$i18n("动态解析")}</b>
        <span>{$i18n("IP 变化时自动更新 DNS 记录，适合动态公网 IP 场景")}</span>
      </div>
      {#if !ddnsTasks.length}
        <div class="dns-empty">{$i18n("暂无动态解析任务。请在「解析记录」中添加记录时选择「动态解析」，或先配置 DNS 账号。")}</div>
      {:else}
        <div class="table-wrap dns-table-wrap">
          <table>
            <thead>
              <tr><th>{$i18n("名称")}</th><th>{$i18n("域名")}</th><th>{$i18n("主机记录")}</th><th>{$i18n("类型")}</th><th>{$i18n("来源")}</th><th>{$i18n("最近 IP")}</th><th>{$i18n("最近更新")}</th><th>{$i18n("状态")}</th><th>{$i18n("操作")}</th></tr>
            </thead>
            <tbody>
              {#each ddnsTasks as t (t.id)}
                <tr>
                  <td>{t.name || '-'}</td>
                  <td class="cell-mono">{t.domain}</td>
                  <td class="cell-mono">{t.rr || '@'}</td>
                  <td><span class="rec-type">{t.rrtype}</span></td>
                  <td class="cell-dim">{t.ip_src === 'local' ? i18nTr("本机网卡") : i18nTr("公网")}{#if t.iface} · {t.iface}{/if}</td>
                  <td class="cell-mono">{t.last_ip || '-'}</td>
                  <td class="cell-mono">{t.last_time || '-'}</td>
                  <td><span class="badge {t.enabled ? 'badge-on' : 'badge-off'}">{t.enabled ? i18nTr("启用") : i18nTr("停用")}</span></td>
                  <td>
                    <div class="cell-actions">
                      <button class="btn btn-sm" disabled={ddnsBusy} on:click={() => toggleDDNS(t)}>{t.enabled ? i18nTr("停用") : i18nTr("启用")}</button>
                      <button class="btn btn-sm btn-danger" disabled={ddnsBusy} on:click={() => (ddnsDel = t)}>{$i18n("删除")}</button>
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <div class="list-cards">
          {#each ddnsTasks as t (t.id)}
            <div class="list-card">
              <div class="list-card-top">
                <span class="badge {t.enabled ? 'badge-on' : 'badge-off'}">{t.enabled ? i18nTr("启用") : i18nTr("停用")}</span>
                <div class="list-card-title">{t.name || t.domain}</div>
              </div>
              <div class="list-card-rows">
                <div class="list-card-row"><span class="k">{$i18n("域名")}</span><span class="v cell-mono">{t.domain}</span></div>
                <div class="list-card-row"><span class="k">{$i18n("记录")}</span><span class="v cell-mono">{t.rr || '@'} · {t.rrtype}</span></div>
                <div class="list-card-row"><span class="k">{$i18n("最近 IP")}</span><span class="v cell-mono">{t.last_ip || '-'}</span></div>
                <div class="list-card-row"><span class="k">{$i18n("最近更新")}</span><span class="v cell-mono">{t.last_time || '-'}</span></div>
              </div>
              <div class="list-card-actions">
                <button class="btn btn-sm" disabled={ddnsBusy} on:click={() => toggleDDNS(t)}>{t.enabled ? i18nTr("停用") : i18nTr("启用")}</button>
                <button class="btn btn-sm btn-danger" disabled={ddnsBusy} on:click={() => (ddnsDel = t)}>{$i18n("删除")}</button>
              </div>
            </div>
          {/each}
        </div>
        <div class="dns-record-foot">
          <span>{$i18n("共")} {ddnsTasks.length} {$i18n("个任务 ·")} <span style="color:var(--green)">{ddnsTasks.filter((t) => t.enabled).length} {$i18n("个启用")}</span></span>
          <span class="dns-foot-meta">{$i18n("IP 变化时自动同步")}</span>
        </div>
      {/if}
    </div>
  {:else}
    <div class="card dns-tab-card">
      <div class="dns-tab-h">
        <b>{$i18n("TLS 证书")}</b>
        <span>{$i18n("证书库 · 到期前自动续签")}</span>
        <span class="right">
          <button class="btn btn-sm {autoRenew ? 'btn-primary' : ''}" on:click={openAutoRenew} disabled={autoRenewBusy} title={$i18n("点击设置自动续签与提前续签天数")}>{$i18n("自动续签：")}{autoRenew ? i18nTr("开 · 提前 ") + autoRenewDays + i18nTr(" 天") : i18nTr("关")}</button>
          <button class="btn btn-sm" on:click={goApplyCert}>{$i18n("申请证书")}</button>
          <button class="btn btn-sm" on:click={goImportCert}>{$i18n("导入证书")}</button>
        </span>
      </div>
      {#if !certs.length}
        <div class="dns-empty">{$i18n("暂无证书。点击「申请证书」通过 ACME 签发，或「导入证书」上传已有 PEM。")}</div>
      {:else}
        <div class="table-wrap dns-table-wrap">
          <table>
            <thead><tr><th>{$i18n("域名")}</th><th>{$i18n("颁发机构")}</th><th>{$i18n("生效时间")}</th><th>{$i18n("到期时间")}</th><th>{$i18n("创建时间")}</th></tr></thead>
            <tbody>
              {#each certs as c (c.domain)}
                <tr>
                  <td class="cell-mono" style="color:var(--accent)">{c.domain}</td>
                  <td>{c.issuer || '-'}</td>
                  <td class="cell-mono">{c.not_before || '-'}</td>
                  <td class="cell-mono">{c.not_after || '-'}</td>
                  <td class="cell-mono">{c.created_at || '-'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <div class="list-cards">
          {#each certs as c (c.domain)}
            <div class="list-card">
              <div class="list-card-top">
                <div class="list-card-avatar">{(c.domain || '?').charAt(0)}</div>
                <div class="list-card-title">{c.domain}</div>
              </div>
              <div class="list-card-rows">
                <div class="list-card-row"><span class="k">{$i18n("颁发机构")}</span><span class="v">{c.issuer || '-'}</span></div>
                <div class="list-card-row"><span class="k">{$i18n("到期时间")}</span><span class="v cell-mono">{c.not_after || '-'}</span></div>
              </div>
            </div>
          {/each}
        </div>
        <div class="dns-record-foot">
          <span>{$i18n("共")} {certs.length} {$i18n("张证书")}</span>
          <span class="dns-foot-meta">{$i18n("自动续签：")}{autoRenew ? i18nTr("已开启") : i18nTr("已关闭")}</span>
        </div>
      {/if}
    </div>
  {/if}
</div>

{#if showDnsAccounts}
  <DnsAccountsModal onClose={() => (showDnsAccounts = false)} onChanged={onAccountsChanged} />
{/if}
{#if showAcmeAccounts}
  <AcmeAccountsModal onClose={() => (showAcmeAccounts = false)} />
{/if}
{#if showAddRecord}
  <AddRecordModal
    account={account}
    domain={domain}
    record={editingRec}
    onClose={() => (showAddRecord = false)}
    onSaved={loadRecords}
  />
{/if}
{#if delRecord}
  <ConfirmModal
    title={$i18n("确认删除")}
    message={i18nTr("确定删除记录 ") + delRecord.name + '.' + domain + '（' + delRecord.type + i18nTr("）吗？该操作不可撤销。")}
    confirmText={$i18n("删除")}
    requireText={delRecord.name}
    busy={delBusy}
    onConfirm={confirmDelRecord}
    onClose={() => (delRecord = null)}
  />
{/if}
{#if ddnsDel}
  <ConfirmModal
    title={$i18n("删除动态解析任务")}
    message={i18nTr("确定删除「") + (ddnsDel.name || ddnsDel.domain) + i18nTr("」的动态解析任务？记录本身不会被删除。")}
    confirmText={$i18n("删除")}
    busy={ddnsDeleting}
    onConfirm={removeDDNS}
    onClose={() => (ddnsDel = null)}
  />
{/if}
{#if showPubSrc}
  <Modal title={$i18n("公网 IP 获取方式")} onClose={() => (showPubSrc = false)} width={520}>
    <div class="tip-text" style="margin-bottom:12px">{$i18n("配置探测本机公网 IPv4 / IPv6 地址的方式。默认使用内置 HTTP 请求访问下方的回显服务（无需系统安装 curl）。")}</div>
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px">
      <label style="display:inline-flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
        <input type="radio" bind:group={pubCfg.method} value="curl" /> {$i18n("Curl 命令")}
      </label>
      <label style="display:inline-flex;align-items:center;gap:6px;font-size:13px;cursor:pointer">
        <input type="radio" bind:group={pubCfg.method} value="http" /> {$i18n("HTTP 请求")}
      </label>
    </div>
    <div class="form-row" bind:this={pubCfgEl}>
      <div class="form-group" style="margin-bottom:0;flex:1;min-width:220px">
        <label class="form-label">{$i18n("IPv4 回显 URL")}</label>
        <input type="text" bind:value={pubCfg.v4_url} placeholder="https://ipv4.icanhazip.com" use:field={{ check: validateURL }} />
      </div>
      <div class="form-group" style="margin-bottom:0;flex:1;min-width:220px">
        <label class="form-label">{$i18n("IPv6 回显 URL")}</label>
        <input type="text" bind:value={pubCfg.v6_url} placeholder="https://ipv6.icanhazip.com/" use:field={{ check: validateURL }} />
      </div>
    </div>
    <div class="tip-text" style="margin-top:10px">{$i18n("回显服务需返回纯文本 IP 地址。保存后立即重新探测并刷新显示。")}</div>
    <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
      <button class="btn" on:click={() => (showPubSrc = false)} disabled={pubCfgBusy}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={savePubCfg} disabled={pubCfgBusy}>{pubCfgBusy ? i18nTr("保存中…") : i18nTr("保存并刷新")}</button>
    </div>
  </Modal>
{/if}
{#if showAutoRenew}
  <Modal title={$i18n("自动续签设置")} onClose={() => (showAutoRenew = false)} width={460}>
    <div class="tip-text" style="margin-bottom:12px">{$i18n("仅对通过本服务 ACME 签发的证书生效；导入的证书没有签发参数，无法自动续签。")}</div>
    <div class="ws-toggle-line" style="display:flex;align-items:center;gap:8px;margin-bottom:14px">
      <input id="cert-auto-renew-switch" type="checkbox" bind:checked={autoRenewForm.enabled} />
      <label for="cert-auto-renew-switch" style="font-size:13px;cursor:pointer">{$i18n("开启自动续签")}</label>
    </div>
    <div class="form-group" style="margin-bottom:0">
      <label class="form-label" for="cert-renew-days">{$i18n("提前续签天数")}</label>
      <input id="cert-renew-days" type="number" min="1" max="90" bind:value={autoRenewForm.days} disabled={!autoRenewForm.enabled} />
      <div class="tip-text">{$i18n("证书到期前多少天开始自动申请新证书，范围 1-90 天，默认 30 天。")}</div>
    </div>
    <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
      <button class="btn" on:click={() => (showAutoRenew = false)} disabled={autoRenewBusy}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={saveAutoRenew} disabled={autoRenewBusy}>{autoRenewBusy ? i18nTr("保存中…") : i18nTr("保存")}</button>
    </div>
  </Modal>
{/if}
{#if showCert}
  <Modal title={certMode === 'apply' ? i18nTr("申请证书") : i18nTr("导入证书")} onClose={() => (showCert = false)} width={880}>
    <CertPanel initialView={certMode} onCancel={() => (showCert = false)} />
  </Modal>
{/if}

<style>
  .dns-page{display:flex;flex-direction:column;gap:12px;min-width:0}
  .card{background:var(--bg3);border:1px solid var(--bd);border-radius:calc(var(--radius) + 4px);box-shadow:var(--shadow-card)}

  /* 运行状态卡：左侧公网地址，右侧关键指标 */
  .dns-summary{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr);gap:18px;align-items:center;padding:15px 17px}
  .dns-card-title{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:600;color:var(--text3);letter-spacing:.2px}
  .dns-link{margin-left:auto;padding:2px 0;border:none;background:none;color:var(--accent);font-size:11px;font-family:var(--font);cursor:pointer}
  .dns-link:hover{text-decoration:underline}
  .dns-addr-grid{display:flex;gap:18px;margin-top:8px;flex-wrap:wrap}
  .dns-addr{flex:1 1 180px;min-width:0}
  .dns-addr-label{font-size:11px;color:var(--text3);margin-bottom:3px}
  .dns-addr-val{display:block;width:100%;padding:0;border:none;background:none;text-align:left;font-family:var(--mono);font-size:15px;font-weight:600;color:var(--text2);line-height:1.35;word-break:break-all;cursor:pointer;font-variant-numeric:tabular-nums}
  .dns-addr-val.accent{font-size:21px;letter-spacing:-.02em;color:var(--accent)}
  .dns-addr-val:hover{text-decoration:underline}
  .dns-addr-meta{margin-top:3px;font-size:11px;color:var(--text3);font-family:var(--mono)}
  .dns-metrics{display:grid;grid-template-columns:1fr 1fr;gap:8px}
  .sys-cell{min-width:0;padding:7px 9px;background:var(--bg4);border:1px solid var(--bd);border-radius:calc(var(--radius) + 1px)}
  .sys-cell span{display:block;margin-bottom:2px;font-size:10px;color:var(--text3)}
  .sys-cell b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;font-weight:500;font-family:var(--mono);color:var(--text2)}
  .sys-cell b.on{color:var(--green)}

  /* 工具栏 */
  /* 页签：与演示页的胶囊标签一致 */
  .dns-tabs{display:flex;gap:4px;padding:3px;background:var(--bg2);border:1px solid var(--bd);border-radius:9px;width:max-content;max-width:100%;overflow-x:auto}
  .dns-tab{border:none;background:none;color:var(--text3);font-size:12px;padding:6px 12px;border-radius:6px;white-space:nowrap;cursor:pointer;font-family:var(--font)}
  .dns-tab:hover{color:var(--text2)}
  .dns-tab.active{background:var(--bg3);color:var(--text);box-shadow:var(--shadow-sm)}
  .dns-tab-card{padding:14px 16px}
  .dns-tab-h{display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap}
  .dns-tab-h b{font-size:13px;font-weight:600;color:var(--text)}
  .dns-tab-h>span{font-size:11px;color:var(--text3)}
  .dns-tab-h .right{margin-left:auto;display:flex;align-items:center;gap:6px}
  .dns-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
  .dns-tool-group{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  /* 次级操作收成文字链接：账户 / 证书分组，避免与主操作抢视觉层级 */
  .dns-tool-links{gap:6px 10px}
  .dns-tool-links .dns-link{margin-left:0;font-size:12px}
  .dns-tool-label{font-size:11px;color:var(--text3);font-family:var(--mono)}
  .dns-tool-hint{font-size:11px;color:var(--text3)}

  /* 账户 / 域名选择 */
  .dns-empty{padding:28px 20px;text-align:center;font-size:13px;color:var(--text3)}
  .dns-picker{display:flex;align-items:flex-end;gap:14px;padding:12px 14px;flex-wrap:wrap}
  .dns-field{display:flex;flex-direction:column;gap:6px;min-width:200px}
  .dns-field-grow{flex:1;min-width:220px}
  .dns-hint{margin:0;font-size:11.5px;color:var(--text3);line-height:1.7}
  /* 记录表页脚：与内网穿透 / 端口转发的统计页脚同一结构 */
  .dns-record-foot{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:10px;font-size:11.5px;color:var(--text3);font-family:var(--mono)}
  .dns-foot-meta{font-size:10.5px;color:var(--text3)}

  /* 桌面表格 */
  .dns-table-wrap{max-height:46vh;overflow:auto;margin-top:2px}
  .dns-table-wrap td{white-space:nowrap}
  .dns-table-wrap td:nth-child(4){min-width:160px;white-space:normal}
  .dns-name{min-width:150px;color:var(--text);font-weight:600}
  .rec-type{display:inline-flex;align-items:center;padding:2px 7px;border-radius:4px;border:1px solid rgba(var(--accent-rgb),.22);background:rgba(var(--accent-rgb),.08);color:var(--accent);font-size:10.5px;font-weight:600;font-family:var(--mono)}
  .row-actions{display:inline-flex;align-items:center;justify-content:flex-end;gap:4px}
  .dns-table-wrap td:last-child .row-actions{justify-content:flex-end}

  /* 移动端卡片 */
  .dns-cards .list-card{background:var(--bg3);border-radius:calc(var(--radius) + 2px)}
  .dns-cards .list-card-avatar{font-family:var(--mono);font-weight:700;text-transform:uppercase}
  .dns-cards .list-card-title{flex:1;min-width:0}
  .dns-cards .list-card-row>.k{width:64px}
  .dns-cards .mono{font-family:var(--mono);font-size:11.5px;word-break:break-all;white-space:normal}
  .dns-cards .right{margin-left:auto}
  .dns-cards .list-card-actions{justify-content:flex-end}

  @media (max-width:760px){
    .dns-summary{grid-template-columns:1fr}
    .dns-addr-val.accent{font-size:19px}
  }
  @media (max-width:600px){
    .dns-tabs{width:100%}
    .dns-tab-h .right{width:100%;margin-left:0}
    .dns-tool-group{width:100%}
    .dns-tool-group .btn{flex:1 1 auto;padding-left:8px;padding-right:8px}
    .dns-tool-links .dns-link{min-height:36px;padding:6px 0}
    .dns-picker{padding:12px}
    .dns-field,.dns-field-grow{min-width:100%}
    .dns-record-foot{font-size:10.5px}
  }
</style>
