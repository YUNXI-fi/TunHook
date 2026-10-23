<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 系统日志页：级别 / 模块 / 搜索 / 分页 / 日志设置
  import { onMount, onDestroy } from 'svelte';
  import { toast } from '../lib/stores.js';
  import { api, apiBase } from '../lib/api.js';
  import { pollVisible } from '../lib/utils.js';
  import CustomSelect from '../components/CustomSelect.svelte';
  import Toggle from '../components/Toggle.svelte';
  import Modal from '../components/Modal.svelte';
  import InfoTip from '../components/InfoTip.svelte';
  import ExportLogModal from '../components/ExportLogModal.svelte';

  const levelOptions = [
    { value: '', label: i18nTr("全部级别") },
    { value: 'info', label: 'INFO' },
    { value: 'warn', label: 'WARN' },
    { value: 'error', label: 'ERROR' },
    { value: 'debug', label: 'DEBUG' }
  ];
  // 移动端级别胶囊页签（与演示页一致，首项为「全部」）
  const LEVEL_TABS = [
    { value: '', label: i18nTr("全部") },
    { value: 'info', label: 'INFO' },
    { value: 'warn', label: 'WARN' },
    { value: 'error', label: 'ERROR' },
    { value: 'debug', label: 'DEBUG' }
  ];

  let level = '';
  let module = '';
  let modules = [];
  let search = '';
  let page = 1;
  let pageSize = 50;
  let entries = [];
  let total = 0;
  let follow = true;
  let timer;
  let showFilter = false; // 移动端筛选弹窗

  // 日志设置弹窗
  let showSettings = false;
  let saving = false;
  let showExport = false;
  let archiving = false;
  let logCfg = { max_entries: 20480, tunnel_max_entries: 128, tunnel_access_max_entries: 128, expire_days: 7, traffic_retention_days: 31 };

  $: totalPages = Math.max(1, Math.ceil(total / pageSize));
  $: moduleOptions = [{ value: '', label: i18nTr("全部模块") }].concat(
    modules.map((m) => ({ value: m, label: m }))
  );
  // 分页器页码：最多展示 5 个，居中跟随当前页
  $: pageList = (() => {
    const n = totalPages;
    const cur = page;
    if (n <= 5) return Array.from({ length: n }, (_, i) => i + 1);
    let start = Math.max(1, cur - 2);
    let end = Math.min(n, start + 4);
    start = Math.max(1, end - 4);
    return Array.from({ length: end - start + 1 }, (_, i) => start + i);
  })();

  function applyFilter() {
    page = 1;
    pageSize = 50;
    load();
  }
  function gotoPage(p) {
    if (p < 1 || p > totalPages || p === page) return;
    page = p;
    load();
  }
  // 移动端：每次多加载 50 条
  function loadMore() {
    pageSize += 50;
    load();
  }
  // 日志时间为 YYYY-MM-DD HH:MM:SS，表格只展示时分秒
  function shortTime(t) {
    const s = String(t || '');
    return s.length > 8 ? s.slice(11) : s;
  }

  async function load() {
    try {
      const q = new URLSearchParams({ page, pageSize, level, module, search });
      const d = await api('/api/logs?' + q.toString());
      if (d) {
        entries = d.entries || [];
        total = d.total || 0;
        if (Array.isArray(d.modules) && d.modules.length) modules = d.modules;
      }
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  async function openSettings() {
    try {
      const d = await api('/api/settings');
      if (d && d.log) logCfg = { ...logCfg, ...d.log };
    } catch (e) { /* ignore */ }
    showSettings = true;
  }

  async function saveSettings() {
    if (saving) return;
    saving = true;
    try {
      await api('/api/settings', { method: 'POST', body: { log: logCfg } });
      toast(i18nTr("日志设置已保存"), 'success');
      showSettings = false;
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      saving = false;
    }
  }

  // 下载日志归档：磁盘上的日志文件打包为 zip
  async function archiveLogs() {
    if (archiving) return;
    archiving = true;
    try {
      const resp = await fetch(apiBase + '/api/logs/archive');
      if (!resp.ok) {
        let msg = i18nTr("日志归档失败");
        try {
          const j = await resp.json();
          if (j && j.error) msg = j.error;
        } catch (e) { /* ignore */ }
        throw new Error(msg);
      }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'tunhook-logs-' + Date.now() + '.zip';
      a.click();
      URL.revokeObjectURL(url);
      toast(i18nTr("日志归档已下载"), 'success');
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      archiving = false;
    }
  }

  // ---- 日志消息高亮 ----
  const HTML_ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => HTML_ESC[c]);
  }
  // 高亮搜索词（在已转义文本上按转义后的词做拆分，避免破坏 HTML 结构）
  function mark(s) {
    const qq = (search || '').trim();
    if (!qq) return s;
    const eq = esc(qq);
    if (!eq) return s;
    return s.split(eq).join('<span class="log-hl">' + eq + '</span>');
  }
  // 将日志消息中的 key=value 字段着色：status 按状态码、method/ip/error 等特殊样式，其余保持原文
  function renderLog(msg) {
    const s = String(msg);
    const re = /([A-Za-z0-9_.-]+=)(.*?)(?=\s[A-Za-z0-9_.-]+=|\s*$)/g;
    let last = 0, out = '';
    let m;
    while ((m = re.exec(s)) !== null) {
      out += mark(esc(s.slice(last, m.index)));
      const key = m[1].slice(0, -1);
      const val = m[2];
      let cls = 'log-kv';
      if (key === 'status') {
        const code = parseInt(val, 10);
        cls = code >= 500 ? 'log-status-5' : code >= 400 ? 'log-status-4' : code >= 300 ? 'log-status-3' : code >= 200 ? 'log-status-2' : 'log-kv';
      } else if (key === 'method' && /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$/i.test(val.trim())) {
        cls = 'log-method';
      } else if (key === 'ip' || key === 'local' || key === 'remote') {
        cls = 'log-ip';
      } else if (key === 'error' || key === 'err') {
        cls = 'log-err';
      }
      out += '<span class="log-k">' + esc(key) + '</span><span class="log-eq">=</span><span class="' + cls + '">' + mark(esc(val)) + '</span>';
      last = re.lastIndex;
    }
    out += mark(esc(s.slice(last)));
    return out;
  }

  onMount(() => {
    load();
    // 实时跟随关闭时停止轮询，避免无意义的请求
    timer = pollVisible(() => { if (follow) load(); }, 3000);
  });
  onDestroy(() => timer && timer());
</script>

<div class="container page-full">
  <div class="page-hdr">
    <div>
      <h2>{$i18n("系统日志")}</h2>
      <span class="page-hdr-sub">
        <span class="sm-hide">{$i18n("实时查看系统运行与转发访问日志")}</span>
        <span class="sm-only">{follow ? i18nTr("实时跟随") : i18nTr("已暂停跟随")} {$i18n("· 共")} {total} {$i18n("条")}</span>
      </span>
    </div>
    <div class="page-hdr-actions">
      <button class="btn" on:click={() => (showExport = true)} title={$i18n("导出日志")}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M4 19h16"/></svg>
        <span class="sm-hide">{$i18n("导出日志")}</span>
      </button>
      <button class="btn" on:click={openSettings} title={$i18n("日志设置")}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3"/><path d="M1 14h6M9 8h6M17 16h6"/></svg>
        <span class="sm-hide">{$i18n("日志设置")}</span>
      </button>
    </div>
  </div>

  <div class="log-filters">
    <div class="log-search">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
      <input type="text" bind:value={search} placeholder={$i18n("搜索日志内容...")} aria-label={$i18n("搜索日志内容")} on:keydown={(e) => { if (e.key === 'Enter') applyFilter(); }} />
    </div>
    <button class="log-filter-btn" on:click={() => (showFilter = true)} title={$i18n("筛选")} aria-label={$i18n("筛选")}>
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 5h18l-7 8v6l-4-2v-4Z"/></svg>
    </button>
    <div class="log-filter-select"><CustomSelect bind:value={level} options={levelOptions} width="120px" on:change={applyFilter} /></div>
    <div class="log-filter-select"><CustomSelect bind:value={module} options={moduleOptions} width="130px" on:change={applyFilter} /></div>
    <span class="log-follow"><span>{$i18n("实时跟随")}</span><Toggle bind:checked={follow} /></span>
  </div>

  <div class="log-mobile-tabs">
    {#each LEVEL_TABS as t}
      <button class="log-chip" class:on={level === t.value} on:click={() => { level = t.value; applyFilter(); }}>{t.label}</button>
    {/each}
  </div>

  <div class="table-wrap log-table-wrap">
    <div class="log-scroll">
      <table class="log-table">
        <thead>
          <tr>
            <th style="width:64px">{$i18n("级别")}</th>
            <th style="width:74px">{$i18n("时间")}</th>
            <th style="width:92px">{$i18n("模块")}</th>
            <th>{$i18n("消息")}</th>
          </tr>
        </thead>
        <tbody>
          {#each entries as e}
            <tr>
              <td><span class="lvl chip {String(e.level).toLowerCase()}">{e.level}</span></td>
              <td class="log-time" title={e.time}>{shortTime(e.time)}</td>
              <td>{#if e.module}<span class="badge badge-off">{e.module}</span>{:else}<span style="color:var(--text3)">-</span>{/if}</td>
              <td>{@html renderLog(e.message)}</td>
            </tr>
          {:else}
            <tr>
              <td colspan="4">
                <div class="empty">
                  <div class="empty-t">{$i18n("暂无日志")}</div>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>

      <!-- 移动端日志卡片：单卡分组，与演示页一致 -->
      <div class="log-cards">
        {#each entries as e}
          <div class="log-card-item">
            <div class="log-card-top">
              <span class="lvl chip {String(e.level).toLowerCase()}">{e.level}</span>
              {#if e.module}<span class="badge badge-off">{e.module}</span>{/if}
              <span class="log-card-time" title={e.time}>{shortTime(e.time)}</span>
            </div>
            <div class="log-card-msg">{@html renderLog(e.message)}</div>
          </div>
        {:else}
          <div class="log-cards-empty">{$i18n("暂无日志")}</div>
        {/each}
      </div>
      {#if entries.length < total}
        <button class="log-more" on:click={loadMore}>{$i18n("加载更多日志")}</button>
      {/if}
    </div>

    <footer class="log-foot">
      <span>{$i18n("第")} {page} / {totalPages} {$i18n("页 · 共")} {total} {$i18n("条日志")}</span>
      <span class="log-pager">
        <button disabled={page <= 1} on:click={() => gotoPage(page - 1)} aria-label={$i18n("上一页")}>‹</button>
        {#each pageList as p (p)}
          <button class:on={p === page} on:click={() => gotoPage(p)}>{p}</button>
        {/each}
        <button disabled={page >= totalPages} on:click={() => gotoPage(page + 1)} aria-label={$i18n("下一页")}>›</button>
      </span>
    </footer>
  </div>
</div>

{#if showSettings}
  <Modal title={$i18n("日志设置")} width={560} onClose={() => (showSettings = false)}>
    <div class="settings-group">
      <div class="form-row">
        <div class="form-group">
          <div class="form-label-row">
            <label class="form-label">{$i18n("系统日志存储条数")}</label>
            <InfoTip text={$i18n("全局日志缓冲最大条数（超出后自动丢弃最早日志）")} />
          </div>
          <input type="number" bind:value={logCfg.max_entries} min="1" />
        </div>
        <div class="form-group">
          <div class="form-label-row">
            <label class="form-label">{$i18n("系统日志保存时间（天）")}</label>
            <InfoTip text={$i18n("全局系统日志保留天数，超出后每天凌晨自动清理")} />
          </div>
          <input type="number" bind:value={logCfg.expire_days} min="1" />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <div class="form-label-row">
            <label class="form-label">{$i18n("每规则日志存储条数")}</label>
            <InfoTip text={$i18n("每条转发规则独立记录的运行日志最大条数")} />
          </div>
          <input type="number" bind:value={logCfg.tunnel_max_entries} min="1" />
        </div>
        <div class="form-group">
          <div class="form-label-row">
            <label class="form-label">{$i18n("每规则访问日志存储条数")}</label>
            <InfoTip text={$i18n("每条转发规则独立记录的访问日志最大条数")} />
          </div>
          <input type="number" bind:value={logCfg.tunnel_access_max_entries} min="1" />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <div class="form-label-row">
            <label class="form-label">{$i18n("流量统计数据保存时间（天）")}</label>
            <InfoTip text={$i18n("仪表盘流量统计图表的原始采样数据保留天数")} />
          </div>
          <input type="number" bind:value={logCfg.traffic_retention_days} min="1" />
        </div>
      </div>
      <div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--bd)">
        <div style="font-size:13px;font-weight:600;margin-bottom:10px;color:var(--text2)">{$i18n("日志操作")}</div>
        <div class="form-row">
          <div class="form-group">
            <div class="form-label-row">
              <label class="form-label">{$i18n("导出日志")}</label>
              <InfoTip text={$i18n("选择日志模块与导出格式（TXT/JSON/CSV）后下载当前缓冲中的日志")} />
            </div>
            <button class="btn" on:click={() => (showExport = true)}>
              <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M6 24.0083V42H42V24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M33 23L24 32L15 23" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M23.9917 6V32" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg> {$i18n("导出日志")}
            </button>
          </div>
          <div class="form-group">
            <div class="form-label-row">
              <label class="form-label">{$i18n("日志归档")}</label>
              <InfoTip text={$i18n("将磁盘上的系统日志文件（tunhook-*.log 等）打包为 zip 下载")} />
            </div>
            <button class="btn" on:click={archiveLogs} disabled={archiving}>
              <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><rect x="6" y="12" width="36" height="30" rx="2" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M17.9497 24.0083L29.9497 24.0083" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M6 13L13 5H35L42 13" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg> {archiving ? i18nTr("归档中...") : i18nTr("日志归档")}
            </button>
          </div>
        </div>
      </div>
    </div>
    <div style="margin-top:16px;text-align:right;display:flex;gap:8px;justify-content:flex-end">
      <button class="btn" on:click={() => (showSettings = false)}>{$i18n("取消")}</button>
      <button class="btn btn-primary" disabled={saving} on:click={saveSettings}>{saving ? i18nTr("保存中...") : i18nTr("保存设置")}</button>
    </div>
  </Modal>
{/if}

{#if showExport}
  <ExportLogModal onClose={() => (showExport = false)} />
{/if}

{#if showFilter}
  <Modal title={$i18n("筛选日志")} width={420} onClose={() => (showFilter = false)}>
    <div class="form-group">
      <label class="form-label">{$i18n("级别")}</label>
      <CustomSelect bind:value={level} options={levelOptions} width="100%" />
    </div>
    <div class="form-group">
      <label class="form-label">{$i18n("模块")}</label>
      <CustomSelect bind:value={module} options={moduleOptions} width="100%" />
    </div>
    <div slot="footer" style="display:flex;gap:8px;justify-content:flex-end">
      <button class="btn" on:click={() => { level = ''; module = ''; showFilter = false; applyFilter(); }}>{$i18n("重置")}</button>
      <button class="btn btn-primary" on:click={() => { showFilter = false; applyFilter(); }}>{$i18n("应用")}</button>
    </div>
  </Modal>
{/if}

<style>
  /* 筛选行：不加卡片外壳，与演示页一致 */
  .log-filters{display:flex;align-items:center;gap:8px;flex-wrap:wrap;flex-shrink:0;margin-bottom:12px}
  .log-search{position:relative;display:flex;align-items:center;flex:1;min-width:200px}
  .log-search svg{position:absolute;left:11px;color:var(--text3);pointer-events:none}
  .log-search input{width:100%;padding-left:32px}
  .log-filter-select{display:flex;flex:0 0 auto}
  .log-filter-btn{display:none}
  .log-follow{margin-left:auto;display:inline-flex;align-items:center;gap:8px;font-size:11px;color:var(--text3);white-space:nowrap}
  .log-mobile-tabs{display:none}

  /* 级别 chip：与演示页的 INFO / WARN / ERROR / DEBUG 配色一致 */
  .lvl{font-family:var(--mono);font-size:9.5px;font-weight:600;letter-spacing:.03em}
  .lvl.info{color:var(--blue)}
  .lvl.warn{color:var(--yellow)}
  .lvl.error{color:var(--red)}
  .lvl.debug{color:var(--text3)}
  .lvl.chip{display:inline-flex;padding:1px 5px;border-radius:4px;border:1px solid transparent}
  .lvl.chip.info{background:rgba(var(--blue-rgb),.08);border-color:rgba(var(--blue-rgb),.18)}
  .lvl.chip.warn{background:rgba(var(--yellow-rgb),.08);border-color:rgba(var(--yellow-rgb),.18)}
  .lvl.chip.error{background:rgba(var(--red-rgb),.08);border-color:rgba(var(--red-rgb),.18)}
  .lvl.chip.debug{background:rgba(var(--slate-rgb),.08);border-color:rgba(var(--slate-rgb),.18)}

  /* 日志表格：消息列保持左对齐（覆盖全局“末列右对齐”规则） */
  .log-table-wrap{margin-bottom:0}
  .log-table th{text-align:left}
  .log-table th:last-child,.log-table td:last-child{text-align:left}
  .log-time{color:var(--text3);font-size:10px;font-family:var(--mono);white-space:nowrap}

  /* 分页脚：数字分页器 */
  .log-foot{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-shrink:0;padding:8px 12px;border-top:1px solid var(--bd);background:var(--bg3);font-size:11px;color:var(--text3)}
  .log-pager{display:inline-flex;align-items:center;gap:4px}
  .log-pager button{
    min-width:24px;height:22px;padding:0 6px;border:1px solid var(--bd);border-radius:5px;
    background:var(--bg3);color:var(--text3);font-size:10.5px;font-family:var(--mono);cursor:pointer;
  }
  .log-pager button:hover:not(:disabled){color:var(--text);border-color:rgba(var(--accent-rgb),.4)}
  .log-pager button.on{background:rgba(var(--accent-rgb),.12);border-color:rgba(var(--accent-rgb),.4);color:var(--accent)}
  .log-pager button:disabled{opacity:.45;cursor:not-allowed}

  /* 移动端日志卡片（桌面隐藏） */
  .log-cards{display:none}
  .log-more{display:none}

  @media (max-width:600px){
    /* 页头：标题与操作同排，操作靠右（对齐演示页移动端） */
    .page-hdr{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:start;gap:10px}
    .page-hdr-actions{width:auto;flex-wrap:nowrap}
    /* 筛选行：搜索 + 筛选按钮同一行（grid 固定两列，避免输入框固有宽度把按钮挤下去） */
    .log-filters{display:grid;grid-template-columns:minmax(0,1fr) 40px;align-items:stretch;gap:6px;margin-bottom:10px}
    .log-search{flex:none;min-width:0}
    .log-search input{min-width:0}
    .log-filter-select{display:none}
    .log-filter-btn{
      display:grid;place-items:center;width:40px;height:38px;flex:none;
      border:1px solid var(--bd);border-radius:var(--radius);background:var(--bg4);color:var(--text2);
    }
    .log-follow{display:none}
    .log-mobile-tabs{display:flex;gap:5px;overflow-x:auto;margin:0 0 12px;scrollbar-width:none}
    .log-mobile-tabs::-webkit-scrollbar{display:none}
    .log-chip{
      height:30px;padding:0 11px;border-radius:8px;border:1px solid var(--bd);background:var(--bg3);
      color:var(--text3);font-size:10.5px;white-space:nowrap;flex:none;cursor:pointer;font-family:var(--font);
    }
    .log-chip.on{background:rgba(var(--accent-rgb),.10);border-color:rgba(var(--accent-rgb),.35);color:var(--accent);font-weight:600}
    .log-table{display:none}
    /* 单卡分组：卡片之间用细分隔线 */
    .log-cards{
      display:flex;flex-direction:column;padding:0 12px;
      background:var(--bg3);border:1px solid var(--bd);border-radius:calc(var(--radius) + 4px);overflow:hidden;
    }
    .log-card-item{padding:9px 0;border-bottom:1px solid var(--sep)}
    .log-card-item:last-child{border-bottom:none}
    .log-card-top{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
    .log-card-time{margin-left:auto;font-size:10.5px;color:var(--text3);font-family:var(--mono);white-space:nowrap}
    .log-card-msg{margin-top:6px;font-size:11.5px;line-height:1.6;color:var(--text2);word-break:break-all;font-family:var(--mono)}
    .log-cards-empty{padding:24px 0;text-align:center;font-size:12px;color:var(--text3)}
    .log-more{
      display:flex;width:100%;justify-content:center;align-items:center;height:38px;margin-top:12px;
      border:1px solid var(--bd);border-radius:var(--radius);background:var(--bg3);
      color:var(--text2);font-size:12px;cursor:pointer;font-family:var(--font);flex-shrink:0;
    }
    .log-foot{display:none}
  }

  :global(.log-k) { color: var(--text3); }
  :global(.log-eq) { color: var(--text3); }
  :global(.log-kv) { color: var(--text2); }
  :global(.log-ip) { color: var(--accent); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
  :global(.log-method) { color: var(--blue); font-weight: 600; }
  :global(.log-err) { color: var(--red); font-weight: 600; }
  :global(.log-status-2) { color: var(--green); font-weight: 600; }
  :global(.log-status-3) { color: var(--yellow); }
  :global(.log-status-4) { color: var(--orange); font-weight: 600; }
  :global(.log-status-5) { color: var(--red); font-weight: 700; }
  :global(.log-hl) {
    background: rgba(var(--accent-rgb), 0.28);
    color: inherit;
    border-radius: 3px;
    padding: 0 2px;
  }
</style>
