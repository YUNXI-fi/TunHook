<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 恢复备份弹窗：解析备份包内容并展示，用户勾选要恢复的模块后执行恢复
  import { onMount } from 'svelte';
  import Modal from './Modal.svelte';
  import { apiBase } from '../lib/api.js';
  import { toast } from '../lib/stores.js';

  export let file = null;
  export let onClose = () => {};

  let state = 'loading'; // loading | password | content | importing
  let summary = null;    // 预览结果
  let pwd = '';
  let selected = {};     // 模块 id -> bool
  let errMsg = '';

  const MODULES = [
    { id: 'settings', label: i18nTr("系统设置") },
    { id: 'hook', label: i18nTr("自定义UI") },
    { id: 'rules', label: i18nTr("转发规则") },
    { id: 'frpc', label: i18nTr("FRP 配置") },
    { id: 'ipfilter', label: i18nTr("IP 过滤") },
    { id: 'dns', label: i18nTr("域名解析") },
    { id: 'cert', label: i18nTr("证书与ACME") },
    { id: 'geo', label: i18nTr("地理数据源") },
    { id: 'icons', label: i18nTr("图标与桌面图标") },
    { id: 'wh', label: i18nTr("Webhook 通道") }
  ];

  function moduleCount(id, c) {
    if (!c) return 0;
    switch (id) {
      case 'settings': return (c.settings && c.settings.keys) || 0;
      case 'hook': return (c.hook && c.hook.keys) || 0;
      case 'rules': return (c.rules && c.rules.length) || 0;
      case 'frpc': return c.frpc ? (c.frpc.servers.length + c.frpc.proxies.length) : 0;
      case 'ipfilter': return c.ip_filter ? (c.ip_filter.custom + c.ip_filter.whitelist + c.ip_filter.blocked) : 0;
      case 'dns': return c.dns ? (c.dns.accounts + c.dns.tasks) : 0;
      case 'cert': return c.cert ? (c.cert.certs + c.cert.emails) : 0;
      case 'geo': return c.geo ? (c.geo.sources + c.geo.ranges) : 0;
      case 'icons': return (c.icons || 0) + (c.desk || 0);
      case 'wh': return c.wh ? 1 : 0;
      default: return 0;
    }
  }
  function moduleSummary(id, c) {
    if (!c) return '';
    switch (id) {
      case 'settings': {
        const n = (c.settings && c.settings.keys) || 0;
        return n > 0 ? n + i18nTr(" 项配置") : i18nTr("无");
      }
      case 'hook': {
        const n = (c.hook && c.hook.keys) || 0;
        return n > 0 ? n + i18nTr(" 项配置") : i18nTr("无");
      }
      case 'rules': {
        const n = (c.rules && c.rules.length) || 0;
        return n > 0 ? n + i18nTr(" 条规则") : i18nTr("无");
      }
      case 'frpc':
        return c.frpc && (c.frpc.servers.length + c.frpc.proxies.length) > 0
          ? c.frpc.servers.length + i18nTr(" 服务器 · ") + c.frpc.proxies.length + i18nTr(" 代理")
          : i18nTr("无");
      case 'ipfilter': {
        const f = c.ip_filter || {};
        return (f.custom + f.whitelist + f.blocked) > 0
          ? f.custom + i18nTr(" 自定义 · ") + f.whitelist + i18nTr(" 白名单 · ") + f.blocked + i18nTr(" 拦截")
          : i18nTr("无");
      }
      case 'dns': {
        const d = c.dns || {};
        const n = (d.accounts || 0) + (d.tasks || 0);
        return n > 0 ? (d.accounts || 0) + i18nTr(" 账户 · ") + (d.tasks || 0) + i18nTr(" 任务") : i18nTr("无");
      }
      case 'cert': {
        const d = c.cert || {};
        const n = (d.certs || 0) + (d.emails || 0);
        return n > 0 ? (d.certs || 0) + i18nTr(" 证书 · ") + (d.emails || 0) + i18nTr(" 邮箱") : i18nTr("无");
      }
      case 'geo': {
        const d = c.geo || {};
        const n = (d.sources || 0) + (d.ranges || 0);
        return n > 0 ? (d.sources || 0) + i18nTr(" 数据源 · ") + (d.ranges || 0) + i18nTr(" IP段") : i18nTr("无");
      }
      case 'icons': {
        const n = (c.icons || 0) + (c.desk || 0);
        return n > 0 ? (c.icons || 0) + i18nTr(" 图标文件 · ") + (c.desk || 0) + i18nTr(" 桌面配置") : i18nTr("无");
      }
      case 'wh':
        return c.wh ? i18nTr("含通道记录") : i18nTr("无");
      default: return '';
    }
  }

  async function parseResp(resp) {
    let data = null;
    const text = await resp.text();
    try { data = JSON.parse(text); } catch (e) { /* ignore */ }
    if (!resp.ok) throw new Error((data && data.error) || ('HTTP ' + resp.status));
    if (data && data.success === false) {
      const err = new Error(data.error || i18nTr("请求失败"));
      err.code = data.error_code;
      throw err;
    }
    return data ? data.data : null;
  }

  async function postPreview(password) {
    const fd = new FormData();
    fd.append('file', file);
    if (password) fd.append('password', password);
    const resp = await fetch(apiBase + '/api/backup/preview', { method: 'POST', body: fd });
    return parseResp(resp);
  }

  async function doPreview(password) {
    state = 'loading';
    try {
      const s = await postPreview(password);
      summary = s;
      // 默认勾选备份中包含的模块
      selected = {};
      const c = (s && s.content) || {};
      for (const m of MODULES) {
        selected[m.id] = moduleCount(m.id, c) > 0;
      }
      pwd = password || '';
      state = 'content';
    } catch (e) {
      if (e.code === 'BACKUP_NEED_PASSWORD') {
        state = 'password';
      } else {
        errMsg = e.message;
        state = 'error';
      }
    }
  }

  async function doRestore() {
    const mods = MODULES.filter((m) => selected[m.id]).map((m) => m.id);
    if (mods.length === 0) {
      toast(i18nTr("请至少选择一个要恢复的模块"), 'error');
      return;
    }
    state = 'importing';
    try {
      const fd = new FormData();
      fd.append('file', file);
      fd.append('modules', mods.join(','));
      if (pwd) fd.append('password', pwd);
      const resp = await fetch(apiBase + '/api/backup/import', { method: 'POST', body: fd });
      const res = await parseResp(resp);
      const parts = [];
      if (res) {
        if (res.auto_decrypted) parts.push(i18nTr("已使用设备编号自动解密"));
        if (res.config_keys > 0) parts.push(i18nTr("系统设置 {0} 项", [res.config_keys]));
        if (res.hook_keys > 0) parts.push(i18nTr("自定义UI {0} 项", [res.hook_keys]));
        if (res.rules_started > 0) parts.push(i18nTr("转发规则 {0} 条", [res.rules_started]));
        if (res.frpc_merged) parts.push(i18nTr("FRP 配置"));
        if (res.dns_accounts > 0 || res.ddns_tasks > 0) parts.push(i18nTr("域名解析 {0} 账户 · {1} 任务", [res.dns_accounts, res.ddns_tasks]));
        if (res.ip_custom > 0 || res.ip_whitelist > 0 || res.ip_blocked > 0) parts.push(i18nTr("IP 过滤条目"));
        if (res.rules_skipped > 0) parts.push(i18nTr("{0} 条规则启动失败", [res.rules_skipped]));
        if (res.frpc_error) parts.push(i18nTr("FRP 合并失败"));
        if (res.certs_merged > 0) parts.push(i18nTr("证书 {0} 张", [res.certs_merged]));
        if (res.emails_merged > 0) parts.push(i18nTr("ACME 邮箱 {0} 个", [res.emails_merged]));
        if (res.geo_sources > 0 || res.geo_ranges > 0) parts.push(i18nTr("地理数据 {0} 源 · {1} IP段", [res.geo_sources, res.geo_ranges]));
        if (res.icons_files > 0 || res.desk_configs > 0) parts.push(i18nTr("图标与桌面 {0} 文件 · {1} 配置", [res.icons_files, res.desk_configs]));
        if (res.wh_restored) parts.push(i18nTr("Webhook 通道记录"));
        if (res.error_pages > 0) parts.push(i18nTr("错误页模板 {0} 页", [res.error_pages]));
      }
      toast(i18nTr("恢复完成：") + (parts.join('、') || i18nTr("无变更")), 'success');
      onClose();
    } catch (e) {
      toast(i18nTr("恢复失败: ") + e.message, 'error');
      state = 'content';
    }
  }

  onMount(() => {
    if (!file) {
      errMsg = i18nTr("未选择备份文件");
      state = 'error';
      return;
    }
    doPreview('');
  });
</script>

<Modal title={$i18n("恢复备份")} width={560} onClose={onClose} closable={state !== 'importing'}>
  {#if state === 'loading'}
    <div class="bk-restore-center">{$i18n("正在解析备份文件…")}</div>
  {:else if state === 'error'}
    <div class="bk-restore-center" style="color:var(--red)">{errMsg}</div>
  {:else if state === 'password'}
    <div style="font-size:13px;color:var(--text2);line-height:1.8;margin-bottom:12px">
      {$i18n("该备份文件已加密，且无法使用当前设备编号自动解密。请输入备份时设置的密码查看并恢复。")}
    </div>
    <input
      type="password"
      bind:value={pwd}
      placeholder={$i18n("备份加密密码")}
      style="width:100%;box-sizing:border-box"
      on:keydown={(e) => { if (e.key === 'Enter' && pwd) doPreview(pwd); }}
    />
  {:else if state === 'content' && summary}
    <div class="bk-restore-info">
      {#if summary.manifest && summary.manifest.exported_at}
        <span>{$i18n("导出时间：")}{summary.manifest.exported_at}</span>
      {/if}
      {#if summary.manifest && summary.manifest.encryption === 'aes-gcm'}
        <span class="bk-badge">{$i18n("已加密")}</span>
        {#if summary.auto_decrypted}<span class="bk-badge bk-badge-ok">{$i18n("已自动解密")}</span>{/if}
      {/if}
    </div>
    <div style="font-size:12px;color:var(--text3);margin-bottom:10px;line-height:1.7">
      {$i18n("该备份包包含以下内容，请勾选要恢复的模块（合并模式：备份中的配置覆盖当前同名配置，未勾选的模块保持不变）：")}
    </div>
    <div class="bk-restore-list">
      {#each MODULES as m}
        {#if moduleCount(m.id, summary.content) > 0}
          <label class="bk-restore-item">
            <input type="checkbox" bind:checked={selected[m.id]} />
            <span class="bk-restore-main">
              <span class="bk-restore-row">
                <span class="bk-restore-label">{m.label}</span>
                <span class="bk-restore-desc">{moduleSummary(m.id, summary.content)}</span>
              </span>
              {#if m.id === 'frpc' && summary.content.frpc}
                <span class="bk-restore-detail">
                  {#if summary.content.frpc.servers.length > 0}
                    <span>{$i18n("服务器：")}{summary.content.frpc.servers.join('、')}</span>
                  {/if}
                  {#if summary.content.frpc.proxies.length > 0}
                    <span>{$i18n("代理：")}{summary.content.frpc.proxies.join('、')}</span>
                  {/if}
                </span>
              {/if}
              {#if m.id === 'rules' && (summary.content.rules || []).length > 0}
                <span class="bk-restore-detail bk-restore-detail-rules">
                  {#each summary.content.rules as r (r.key || (r.protocol + '://' + r.local + '->' + r.remote))}
                    <span class="bk-restore-rule-line">{r.key || (r.protocol + '://' + r.local + '->' + r.remote)}{#if r.desc} · {r.desc}{/if}</span>
                  {/each}
                </span>
              {/if}
            </span>
          </label>
        {/if}
      {/each}
    </div>
  {/if}

  <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
    {#if state === 'error'}
      <button class="btn btn-primary" on:click={onClose}>{$i18n("关闭")}</button>
    {:else if state === 'password'}
      <button class="btn" on:click={onClose}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={() => doPreview(pwd)} disabled={!pwd}>{$i18n("解密并预览")}</button>
    {:else if state === 'content'}
      <button class="btn" on:click={onClose} disabled={state === 'importing'}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={doRestore} disabled={state === 'importing'}>
        {state === 'importing' ? i18nTr("恢复中…") : i18nTr("恢复所选")}
      </button>
    {/if}
  </div>
</Modal>

<style>
  .bk-restore-center {
    font-size: 13px; color: var(--text2);
    padding: 28px 0; text-align: center;
  }
  .bk-restore-info {
    display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
    font-size: 12px; color: var(--text3); margin-bottom: 10px;
  }
  .bk-badge {
    padding: 1px 8px; border-radius: 999px;
    background: rgba(var(--yellow-rgb), .08); color: var(--yellow);
    border: 1px solid rgba(var(--yellow-rgb), .4);
    font-size: 11px;
  }
  .bk-badge-ok {
    background: rgba(var(--green-rgb), .08); color: var(--green);
    border-color: rgba(var(--green-rgb), .4);
  }
  .bk-restore-list {
    display: flex; flex-direction: column; gap: 8px;
    max-height: 300px; overflow-y: auto; padding-right: 4px;
  }
  .bk-restore-item {
    display: flex; align-items: flex-start; gap: 10px;
    padding: 10px 12px;
    background: var(--bg4); border: 1px solid var(--bd);
    border-radius: var(--radius); cursor: pointer;
  }
  .bk-restore-item:hover { border-color: var(--accent); }
  .bk-restore-item input { margin-top: 3px; }
  .bk-restore-main {
    flex: 1; min-width: 0;
    display: flex; flex-direction: column; gap: 6px;
  }
  .bk-restore-row {
    display: flex; align-items: baseline; justify-content: space-between; gap: 10px;
  }
  .bk-restore-label { font-size: 13px; color: var(--text); font-weight: 600; }
  .bk-restore-desc { font-size: 11px; color: var(--text3); white-space: nowrap; }
  .bk-restore-detail {
    display: flex; flex-direction: column; gap: 3px;
    font-size: 11px; color: var(--text2); line-height: 1.6;
    padding: 6px 8px;
    background: var(--bg2); border: 1px solid var(--bd);
    border-radius: calc(var(--radius) - 2px);
  }
  .bk-restore-rule-line {
    font-family: var(--mono); font-size: 11px; color: var(--text3);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
</style>
