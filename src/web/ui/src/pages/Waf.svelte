<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // WAF 防火墙：内置规则 + 自定义规则，观察/拦截两种模式，展示命中日志。
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import { field, validateAll } from '../lib/field.js';
  import Toggle from '../components/Toggle.svelte';
  import CustomSelect from '../components/CustomSelect.svelte';
  import Modal from '../components/Modal.svelte';
  import ConfirmModal from '../components/ConfirmModal.svelte';

  // 内置规则元信息（id 需与后端 wafBuiltinRules 一致）
  const BUILTIN = [
    { id: 'sqli', name: i18nTr("SQL 注入"), desc: i18nTr("union select、or 1=1、sleep()、information_schema 等") },
    { id: 'xss', name: i18nTr("XSS 跨站脚本"), desc: i18nTr("<script>、javascript:、onerror=、document.cookie 等") },
    { id: 'traversal', name: i18nTr("路径穿越"), desc: i18nTr("../、%2e%2e、/etc/passwd、/proc/self 等") },
    { id: 'cmdi', name: i18nTr("命令注入"), desc: i18nTr("; cat、| bash、$()、反引号执行等") },
    { id: 'scanner', name: i18nTr("恶意扫描器"), desc: i18nTr("sqlmap、nikto、nmap、gobuster 等扫描器 UA") },
    { id: 'sensitive_path', name: i18nTr("敏感路径探测"), desc: i18nTr("/wp-admin、/phpmyadmin、/.env、/.git 等") }
  ];

  const fieldOptions = [
    { value: 'url', label: i18nTr("URL / 查询串") },
    { value: 'body', label: i18nTr("请求体") },
    { value: 'ua', label: 'User-Agent' },
    { value: 'header', label: 'Cookie / Referer' },
    { value: 'method', label: i18nTr("请求方法") }
  ];
  const scopeLabels = { admin: i18nTr("管理界面"), webhook: 'Webhook', frpc: i18nTr("frpc 代理") };

  let cfg = { enabled: false, mode: 'observe', builtin: {} };
  let rules = [];
  let logs = [];
  let loading = true;
  let savingCfg = false;

  // 规则编辑弹窗
  let showRule = false;
  let editingId = '';
  let form = { name: '', field: 'url', pattern: '', enabled: true };
  let formEl;
  let savingRule = false;

  // 删除确认
  let delRule = null;
  let deleting = false;
  let showClear = false;
  let clearing = false;

  // 状态卡片统计：全部来自已加载的真实配置与命中日志，不做估算
  $: builtinOn = BUILTIN.filter((r) => !!cfg.builtin[r.id]).length;
  // 命中日志时间格式为 YYYY-MM-DD HH:MM:SS：按本地日期取「今日」计数
  $: todayKey = new Date().toLocaleDateString('sv-SE');
  $: todayLogs = logs.filter((l) => String(l.time || '').startsWith(todayKey));
  $: logBlocked = todayLogs.filter((l) => l.action === 'block').length;
  $: logRecorded = todayLogs.length - logBlocked;

  async function loadAll() {
    try {
      const [s, r] = await Promise.all([api('/api/waf/settings'), api('/api/waf/rules')]);
      cfg = { enabled: !!(s && s.enabled), mode: (s && s.mode) || 'observe', builtin: (s && s.builtin) || {} };
      rules = (r && r.rules) || [];
    } catch (e) {
      toast(i18nTr("加载 WAF 配置失败：") + e.message, 'error');
    }
    loading = false;
    loadLogs();
  }

  async function loadLogs() {
    try {
      const d = await api('/api/waf/logs?limit=200');
      logs = (d && d.logs) || [];
    } catch (e) {
      /* 日志读取失败不打断页面 */
    }
  }

  async function saveCfg() {
    savingCfg = true;
    try {
      const d = await api('/api/waf/settings', { method: 'POST', body: cfg });
      cfg = { enabled: !!(d && d.enabled), mode: (d && d.mode) || 'observe', builtin: (d && d.builtin) || {} };
      toast(i18nTr("WAF 设置已保存"), 'success');
    } catch (e) {
      toast(i18nTr("保存失败：") + e.message, 'error');
    }
    savingCfg = false;
  }

  function toggleBuiltin(id) {
    cfg.builtin = { ...cfg.builtin, [id]: !cfg.builtin[id] };
    saveCfg();
  }

  // 观察 / 拦截分段切换：与演示页的分段控件一致
  function setMode(m) {
    if (cfg.mode === m) return;
    cfg = { ...cfg, mode: m };
    saveCfg();
  }

  // 一键启用全部内置规则（与演示页的「全部启用」一致）
  function enableAllBuiltins() {
    cfg = { ...cfg, builtin: Object.fromEntries(BUILTIN.map((r) => [r.id, true])) };
    saveCfg();
  }

  // 页头「命中日志」快捷入口：定位到页面下方的日志卡片
  function scrollToLogs() {
    document.getElementById('waf-hit-logs')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function fieldLabel(v) {
    const f = fieldOptions.find((x) => x.value === v);
    return f ? f.label : v;
  }

  function openAdd() {
    editingId = '';
    form = { name: '', field: 'url', pattern: '', enabled: true };
    showRule = true;
  }
  function openEdit(r) {
    editingId = r.id;
    form = { name: r.name, field: r.field, pattern: r.pattern, enabled: r.enabled };
    showRule = true;
  }

  function validatePattern(v) {
    const s = (v || '').trim();
    if (!s) return i18nTr("请输入正则表达式");
    try {
      new RegExp(s);
      return '';
    } catch (e) {
      return i18nTr("正则无效：") + e.message;
    }
  }

  async function saveRule() {
    if (!validateAll(formEl)) return;
    savingRule = true;
    const item = {
      id: editingId || Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
      name: form.name.trim(),
      field: form.field,
      pattern: form.pattern.trim(),
      enabled: !!form.enabled
    };
    const list = editingId ? rules.map((r) => (r.id === editingId ? item : r)) : [...rules, item];
    try {
      const d = await api('/api/waf/rules', { method: 'POST', body: { rules: list } });
      rules = (d && d.rules) || list;
      showRule = false;
      toast(editingId ? i18nTr("规则已更新") : i18nTr("规则已添加"), 'success');
    } catch (e) {
      toast(i18nTr("保存失败：") + e.message, 'error');
    }
    savingRule = false;
  }

  async function removeRule() {
    if (!delRule) return;
    deleting = true;
    try {
      const d = await api('/api/waf/rules', {
        method: 'POST',
        body: { rules: rules.filter((r) => r.id !== delRule.id) }
      });
      rules = (d && d.rules) || [];
      toast(i18nTr("规则已删除"), 'success');
      delRule = null;
    } catch (e) {
      toast(i18nTr("删除失败：") + e.message, 'error');
    }
    deleting = false;
  }

  async function clearLogs() {
    clearing = true;
    try {
      await api('/api/waf/logs', { method: 'DELETE' });
      logs = [];
      showClear = false;
      toast(i18nTr("命中日志已清空"), 'success');
    } catch (e) {
      toast(i18nTr("清空失败：") + e.message, 'error');
    }
    clearing = false;
  }

  onMount(loadAll);
</script>

<div class="container">
  <div class="page-hdr">
    <div>
      <h2>{$i18n("WAF 防火墙")}</h2>
      <span class="page-hdr-sub">{$i18n("HTTP 流量检测 · 内置规则 + 自定义规则 · 观察 / 拦截模式")}</span>
    </div>
    <div class="page-hdr-actions">
      <button class="btn" on:click={scrollToLogs} title={$i18n("查看命中日志")}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8l-5-5Z"/><path d="M14 3v5h5M8 13h8M8 17h6"/></svg>
        <span class="sm-hide">{$i18n("命中日志")}</span>
      </button>
      <button class="btn" on:click={loadAll} disabled={loading} title={$i18n("刷新")}>
        <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><path d="M42 24C42 33.9411 33.9411 42 24 42C14.0589 42 6 33.9411 6 24C6 14.0589 14.0589 6 24 6C30.675 6 36.5033 9.63077 39.5 15"/><path d="M42 6V18H30"/></svg>
        <span class="sm-hide">{$i18n("刷新")}</span>
      </button>
      <button class="btn btn-primary" on:click={openAdd} title={$i18n("添加规则")}>
        <svg width="16" height="16" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="24" cy="24" r="20"/><path d="M24 16V32"/><path d="M16 24H32"/></svg>
        <span class="sm-hide">{$i18n("添加规则")}</span>
      </button>
    </div>
  </div>

  {#if loading}
    <div class="empty"><div class="empty-t">{$i18n("加载中…")}</div></div>
  {:else}
    <!-- WAF 状态：启用开关、处理模式与真实统计 -->
    <div class="waf-card">
      <div class="waf-status">
        <div class="waf-status-ico">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
        </div>
        <div class="waf-status-info">
          <div class="waf-status-title">
            {$i18n("WAF 防护")}{cfg.enabled ? i18nTr("已启用") : i18nTr("已停用")}
            <span class="badge {cfg.enabled ? 'badge-on' : 'badge-off'}">{cfg.mode === 'block' ? i18nTr("拦截模式") : i18nTr("观察模式")}</span>
          </div>
          <div class="waf-status-sub">{$i18n("保护管理界面 / API · Webhook · frpc HTTP 反代")}</div>
        </div>
        <div class="waf-status-stats">
          <div class="waf-stat"><span>{$i18n("今日命中")}</span><b>{todayLogs.length}</b></div>
          <div class="waf-stat"><span>{$i18n("已拦截")}</span><b class="waf-red">{logBlocked}</b></div>
          <div class="waf-stat"><span>{$i18n("仅记录")}</span><b class="waf-amber">{logRecorded}</b></div>
          <div class="waf-stat waf-stat-rules"><span>{$i18n("启用规则")}</span><b>{builtinOn} / {BUILTIN.length}</b></div>
        </div>
        <div class="waf-status-ctrl">
          <div class="seg-mini">
            <button class:on={cfg.mode === 'observe'} disabled={savingCfg} on:click={() => setMode('observe')}>{$i18n("观察")}</button>
            <button class:on={cfg.mode === 'block'} disabled={savingCfg} on:click={() => setMode('block')}>{$i18n("拦截")}</button>
          </div>
          <Toggle bind:checked={cfg.enabled} disabled={savingCfg} on:change={saveCfg} />
        </div>
      </div>
      <div class="waf-notice">
        {$i18n("TCP / UDP 与 HTTPS 隧道为透传，不经过 HTTP 检测。观察模式只记录日志；拦截模式命中规则后直接返回")} <b>403</b>。
      </div>
    </div>

    <div class="waf-card">
      <div class="waf-card-h">
        <h3>{$i18n("内置规则")}</h3>
        <span class="waf-sub">{builtinOn} / {BUILTIN.length} {$i18n("已启用")}</span>
        {#if builtinOn < BUILTIN.length}
          <div class="waf-h-actions">
            <button class="btn btn-sm" disabled={savingCfg} on:click={enableAllBuiltins}>{$i18n("全部启用")}</button>
          </div>
        {/if}
      </div>
      <div class="waf-rules">
        {#each BUILTIN as r (r.id)}
          <div class="waf-rule-row">
            <div class="waf-rule-info">
              <div class="waf-rule-name">{r.name}</div>
              <div class="waf-rule-desc">{r.desc}</div>
            </div>
            <Toggle checked={!!cfg.builtin[r.id]} disabled={savingCfg} on:change={() => toggleBuiltin(r.id)} />
          </div>
        {/each}
      </div>
    </div>

    <div class="waf-card">
      <div class="waf-card-h">
        <h3>{$i18n("自定义规则")}</h3>
        <span class="waf-sub">{rules.length} {$i18n("条")}</span>
        <div class="waf-h-actions">
          <button class="btn btn-sm btn-primary" on:click={openAdd}>{$i18n("添加规则")}</button>
        </div>
      </div>
      {#if !rules.length}
        <div class="empty" style="padding:24px 0"><div class="empty-t">{$i18n("还没有自定义规则")}</div></div>
      {:else}
        <div class="table-wrap waf-desktop-table">
          <table>
            <thead>
              <tr><th>{$i18n("名称")}</th><th>{$i18n("检测位置")}</th><th>{$i18n("正则表达式")}</th><th>{$i18n("状态")}</th><th>{$i18n("操作")}</th></tr>
            </thead>
            <tbody>
              {#each rules as r (r.id)}
                <tr>
                  <td>{r.name}</td>
                  <td class="cell-dim">{fieldLabel(r.field)}</td>
                  <td class="cell-mono waf-pattern" title={r.pattern}>{r.pattern}</td>
                  <td>
                    <span class="badge {r.enabled ? 'badge-on' : 'badge-off'}">{r.enabled ? i18nTr("启用") : i18nTr("停用")}</span>
                  </td>
                  <td>
                    <div class="cell-actions">
                      <button class="btn btn-sm" on:click={() => openEdit(r)}>{$i18n("编辑")}</button>
                      <button class="btn btn-sm btn-danger" on:click={() => (delRule = r)}>{$i18n("删除")}</button>
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <!-- 移动端：自定义规则卡片 -->
        <div class="waf-m-list">
          {#each rules as r (r.id)}
            <div class="waf-m-item">
              <div class="waf-m-item-top">
                <span class="waf-m-name">{r.name}</span>
                <span class="badge {r.enabled ? 'badge-on' : 'badge-off'}">{r.enabled ? i18nTr("启用") : i18nTr("停用")}</span>
              </div>
              <div class="waf-m-meta">{fieldLabel(r.field)}</div>
              <div class="waf-m-pattern cell-mono" title={r.pattern}>{r.pattern}</div>
              <div class="waf-m-actions">
                <button class="btn btn-sm" on:click={() => openEdit(r)}>{$i18n("编辑")}</button>
                <button class="btn btn-sm btn-danger" on:click={() => (delRule = r)}>{$i18n("删除")}</button>
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </div>

    <div class="waf-card" id="waf-hit-logs">
      <div class="waf-card-h">
        <h3>{$i18n("命中日志")}</h3>
        <span class="waf-sub">{$i18n("最近 200 条")}</span>
        <div class="waf-h-actions">
          <button class="btn btn-sm" on:click={loadLogs}>{$i18n("刷新")}</button>
          <button class="btn btn-sm btn-danger" disabled={!logs.length} on:click={() => (showClear = true)}>{$i18n("清空")}</button>
        </div>
      </div>
      {#if !logs.length}
        <div class="empty" style="padding:24px 0"><div class="empty-t">{$i18n("暂无命中记录")}</div></div>
      {:else}
        <div class="table-wrap waf-desktop-table">
          <table>
            <thead>
              <tr><th>{$i18n("时间")}</th><th>{$i18n("来源")}</th><th>{$i18n("客户端 IP")}</th><th>{$i18n("方法")}</th><th>{$i18n("路径")}</th><th>{$i18n("命中规则")}</th><th>{$i18n("动作")}</th></tr>
            </thead>
            <tbody>
              {#each logs as l, i (i)}
                <tr>
                  <td class="cell-dim" title={l.time}>{l.time.length > 8 ? l.time.slice(11) : l.time}</td>
                  <td class="cell-dim">{scopeLabels[l.scope] || l.scope}</td>
                  <td class="cell-mono">{l.ip}</td>
                  <td class="cell-mono">{l.method}</td>
                  <td class="cell-mono waf-pattern" title={l.path}>{l.path}</td>
                  <td>{l.rule}</td>
                  <td>
                    <span class="badge {l.action === 'block' ? 'badge-error' : 'badge-warn'}">{l.action === 'block' ? i18nTr("已拦截") : i18nTr("仅记录")}</span>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <!-- 移动端：命中日志卡片 -->
        <div class="waf-m-list">
          {#each logs as l, i (i)}
            <div class="waf-m-item">
              <div class="waf-m-item-top">
                <span class="badge badge-info">{scopeLabels[l.scope] || l.scope}</span>
                <span class="badge {l.action === 'block' ? 'badge-error' : 'badge-warn'}">{l.action === 'block' ? i18nTr("已拦截") : i18nTr("仅记录")}</span>
                <span class="waf-m-time" title={l.time}>{l.time.length > 8 ? l.time.slice(11) : l.time}</span>
              </div>
              <div class="waf-m-msg">
                <span class="waf-method">{l.method}</span> <span class="cell-mono">{l.path}</span>
              </div>
              <div class="waf-m-meta">{$i18n("客户端")} {l.ip} {$i18n("· 命中")} {l.rule}</div>
            </div>
          {/each}
        </div>
        <div class="waf-log-foot">
          <span>{$i18n("最近")} {logs.length} {$i18n("条命中记录")}</span>
          <span>{$i18n("日志按时间倒序")}</span>
        </div>
      {/if}
    </div>
  {/if}
</div>

{#if showRule}
  <Modal title={editingId ? i18nTr("编辑规则") : i18nTr("添加规则")} width={560} onClose={() => (showRule = false)} closable={!savingRule}>
    <div bind:this={formEl}>
      <div class="form-group">
        <label class="form-label">{$i18n("规则名称")}</label>
        <input type="text" bind:value={form.name} placeholder={$i18n("如 拦截异常下载参数")} use:field={{ check: (v) => ((v || '').trim() ? '' : '请输入规则名称') }} />
      </div>
      <div class="form-group">
        <label class="form-label">{$i18n("检测位置")}</label>
        <CustomSelect bind:value={form.field} options={fieldOptions} />
      </div>
      <div class="form-group">
        <label class="form-label">{$i18n("正则表达式")}</label>
        <input type="text" bind:value={form.pattern} placeholder={$i18n("如 (?i)(union\\s+select|or\\s+1=1)")} use:field={{ check: validatePattern }} />
        <div class="tip-text">{$i18n("使用 Go RE2 正则语法，区分大小写时可加 (?i) 前缀")}</div>
      </div>
      <div class="waf-switch-row" style="padding-bottom:0">
        <div>
          <div class="waf-switch-title">{$i18n("启用规则")}</div>
          <div class="waf-switch-sub">{$i18n("停用后保留规则但不参与检测")}</div>
        </div>
        <Toggle bind:checked={form.enabled} />
      </div>
    </div>
    <div slot="footer" style="display:flex;gap:8px;align-items:center">
      <button class="btn" style="margin-left:auto" on:click={() => (showRule = false)} disabled={savingRule}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={saveRule} disabled={savingRule}>{savingRule ? i18nTr("保存中…") : i18nTr("保存")}</button>
    </div>
  </Modal>
{/if}

{#if delRule}
  <ConfirmModal
    title={$i18n("删除规则")}
    message={`确定删除规则「${delRule.name}」？`}
    busy={deleting}
    onConfirm={removeRule}
    onClose={() => (delRule = null)}
  />
{/if}

{#if showClear}
  <ConfirmModal
    title={$i18n("清空命中日志")}
    message={$i18n("确定清空全部命中日志？该操作不可恢复。")}
    confirmText={$i18n("清空")}
    busy={clearing}
    onConfirm={clearLogs}
    onClose={() => (showClear = false)}
  />
{/if}

<style>
  .waf-card{
    background:var(--bg3);border:1px solid var(--bd);border-radius:calc(var(--radius) + 4px);
    padding:16px 18px;margin-bottom:16px;box-shadow:var(--shadow-card);
  }
  .waf-card-h{display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap}
  .waf-card-h h3{font-size:13.5px;font-weight:600;color:var(--text)}
  .waf-sub{font-size:12px;color:var(--text3)}
  .waf-h-actions{margin-left:auto;display:flex;align-items:center;gap:8px}
  /* 命中日志页脚：与其它列表页的统计页脚保持一致 */
  .waf-log-foot{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:10px;padding-top:9px;border-top:1px solid var(--bd);font-size:10.5px;color:var(--text3);font-family:var(--mono)}
  /* 状态区：图标 + 标题 + 真实统计 + 模式/开关，与演示页单行布局一致 */
  .waf-status{
    display:flex;align-items:center;gap:14px;flex-wrap:wrap;
  }
  .waf-status-ico{
    width:38px;height:38px;border-radius:10px;flex:none;
    display:flex;align-items:center;justify-content:center;
    background:rgba(var(--green-rgb),.10);border:1px solid rgba(var(--green-rgb),.28);color:var(--green);
  }
  .waf-status-info{flex:1;min-width:200px}
  .waf-status-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:13.5px;font-weight:600;color:var(--text)}
  .waf-status-sub{font-size:12px;color:var(--text3);margin-top:3px;line-height:1.6}
  .waf-status-stats{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
  .waf-stat{display:flex;flex-direction:column;gap:2px;min-width:60px}
  .waf-stat span{font-size:11px;color:var(--text3)}
  .waf-stat b{font-family:var(--mono);font-size:15px;font-weight:600;color:var(--text);font-variant-numeric:tabular-nums}
  .waf-red{color:var(--red)}
  .waf-amber{color:var(--yellow)}
  .waf-stat b.waf-red{color:var(--red)}
  .waf-stat b.waf-amber{color:var(--yellow)}
  /* 模式分段 + 启用开关：靠右与统计并排 */
  .waf-status-ctrl{margin-left:auto;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .seg-mini{display:inline-flex;padding:2px;border:1px solid var(--bd);border-radius:7px;background:var(--bg2);gap:2px}
  .seg-mini button{border:none;background:none;color:var(--text3);font-size:11px;padding:4px 9px;border-radius:5px;cursor:pointer;font-family:var(--font)}
  .seg-mini button.on{background:var(--bg4);color:var(--text);box-shadow:var(--shadow-sm)}
  .seg-mini button:disabled{opacity:.5;cursor:not-allowed}
  .waf-switch-row{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:12px 0;border-bottom:1px solid var(--sep)}
  .waf-switch-row.no-border{border-bottom:none;padding-bottom:0}
  .waf-switch-title{font-size:13px;font-weight:600;color:var(--text)}
  .waf-switch-sub{font-size:12px;color:var(--text3);margin-top:2px;line-height:1.6;max-width:760px}
  .waf-notice{
    margin-top:12px;padding:10px 12px;border:1px solid var(--bd);border-radius:var(--radius);
    background:var(--bg4);font-size:12px;color:var(--text3);line-height:1.6;
  }
  .waf-notice b{color:var(--text2)}
  .waf-rules{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
  .waf-rule-row{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:10px 12px;background:var(--bg4);border:1px solid var(--bd);border-radius:8px}
  .waf-rule-info{min-width:0}
  .waf-rule-name{font-size:13px;font-weight:600;color:var(--text)}
  .waf-rule-desc{font-size:12px;color:var(--text3);margin-top:2px;line-height:1.5}
  .waf-pattern{max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  /* 表格贴齐卡片边缘：去掉内层卡片的边框/底色，与演示页的卡内表格一致 */
  .waf-desktop-table{
    margin:2px -18px -16px;border:none;border-radius:0;box-shadow:none;background:transparent;
  }
  .waf-m-list{display:none}
  /* 移动端：规则/日志改用卡片，桌面表格保留 */
  @media (max-width:600px){
    /* 页头：标题与操作同排，操作靠右（对齐演示页移动端） */
    .page-hdr{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:start;gap:10px}
    .page-hdr-actions{width:auto;flex-wrap:nowrap}
    .waf-card{padding:14px 16px}
    .waf-desktop-table{display:none}
    .waf-rules{grid-template-columns:1fr}
    /* 移动端：模式/开关一行，统计三列（启用规则由内置规则卡头展示） */
    .waf-status-ctrl{order:1;width:100%;margin-left:0;justify-content:space-between}
    .waf-status-stats{
      order:2;width:100%;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;
    }
    .waf-stat-rules{display:none}
    .waf-stat{min-width:0}
    .waf-stat b{font-size:13px}
    .waf-switch-row{flex-wrap:wrap}
    .waf-m-list{display:flex;flex-direction:column;gap:8px;margin-top:2px}
    .waf-m-item{
      background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius);
      padding:10px 12px;display:flex;flex-direction:column;gap:6px;min-width:0;
    }
    .waf-m-item-top{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
    .waf-m-name{font-size:13px;font-weight:600;color:var(--text);min-width:0;word-break:break-all}
    .waf-m-time{margin-left:auto;font-size:11px;color:var(--text3);font-family:var(--mono)}
    .waf-m-meta{font-size:11.5px;color:var(--text3);word-break:break-all}
    .waf-m-pattern{
      max-width:none;white-space:normal;word-break:break-all;
      font-size:11px;color:var(--text2);background:var(--bg2);
      border:1px solid var(--bd);border-radius:6px;padding:5px 8px;
    }
    .waf-m-msg{font-size:12px;color:var(--text2);word-break:break-all;line-height:1.6}
    .waf-method{font-family:var(--mono);color:var(--accent);font-weight:600}
    .waf-m-actions{
      display:flex;gap:6px;justify-content:flex-end;
      padding-top:8px;border-top:1px solid var(--sep);
    }
  }
</style>
