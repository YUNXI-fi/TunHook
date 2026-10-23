<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // frpc 通道日志弹窗：读取 frpc 运行日志（frpc.log），默认过滤显示指定代理相关行。
  import { onMount, onDestroy, afterUpdate } from 'svelte';
  import Modal from './Modal.svelte';
  import InfoTip from './InfoTip.svelte';
  import { api } from '../lib/api.js';
  import { highlightLog, pollVisible, reverseLines } from '../lib/utils.js';

  export let proxyName = '';
  export let onClose = () => {};

  const LEVELS = [
    { value: 'all', label: i18nTr("全部") },
    { value: 'error', label: 'ERROR' },
    { value: 'warn', label: 'WARN' },
    { value: 'info', label: 'INFO' },
    { value: 'debug', label: 'DEBUG' }
  ];
  // frpc 日志级别标记：2026-08-19 11:38:36.482 [I] [service.go:35] ...
  const LEVEL_TAG = { error: '[E] ', warn: '[W] ', info: '[I] ', debug: '[D] ' };

  let rawLines = []; // 已按代理过滤的原始行（旧 → 新）
  let loading = true;
  let all = false; // false=仅该代理相关日志；true=全部日志
  let keyword = '';
  let level = 'all';
  let wrap = true; // 自动换行
  let follow = true; // 跟随最新（最新日志在顶部）
  let lastAt = '';
  let error = '';
  let logEl;
  let timer = null;

  let filtered = [];
  let log = '';
  let hasFilter = false;

  // 级别 + 关键字筛选；依赖在语句内直接引用，保证 Svelte 正确追踪。
  $: filtered = rawLines.filter((l) => {
    if (level !== 'all' && !l.includes(LEVEL_TAG[level])) return false;
    const k = keyword.trim().toLowerCase();
    return !k || l.toLowerCase().includes(k);
  });
  $: log = reverseLines(filtered.join('\n'));
  $: hasFilter = level !== 'all' || !!keyword.trim();

  // 转义正则特殊字符
  function esc(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function timeNow() {
    return new Date().toLocaleTimeString('zh-CN', { hour12: false });
  }

  async function load() {
    try {
      const d = await api('/api/frpc/log?lines=2000');
      // 过滤掉应用自身管理接口轮询产生的噪声行（[http/middleware.go] http request/response [/api/...]），
      // 否则每 3 秒一次的轮询会刷屏 frpc.log，把真实代理日志挤出显示窗口
      const lines = ((d && d.log) || '')
        .split('\n')
        .filter((l) => !/\[http\/middleware\.go:\d+\] http (request|response)/.test(l));
      let view = lines;
      if (!all && proxyName) {
        // frp 日志中代理名出现在 [代理名]（start proxy success 等）或模块标签 [proxy/<type>:代理名] 中
        const re = new RegExp('\\[' + esc(proxyName) + '\\]|:' + esc(proxyName) + '\\]');
        view = lines.filter((l) => re.test(l));
      }
      rawLines = view;
      lastAt = timeNow();
      error = '';
    } catch (e) {
      error = e.message || String(e);
    } finally {
      loading = false;
    }
  }

  function showAll() {
    all = true;
    load();
  }

  function clearFilters() {
    keyword = '';
    level = 'all';
  }

  function onScroll() {
    // 用户向上翻看历史时自动暂停跟随，避免每 3 秒被拉回顶部
    if (logEl && logEl.scrollTop > 24 && follow) follow = false;
  }

  function followLatest(e) {
    follow = e.currentTarget.checked;
    if (follow && logEl) logEl.scrollTop = 0;
  }

  afterUpdate(() => {
    if (follow && logEl && logEl.scrollTop > 0) logEl.scrollTop = 0;
  });

  function downloadLog() {
    if (!log) return;
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '');
    const name = `frpc${proxyName ? '-' + proxyName : ''}-${stamp}.log`;
    const blob = new Blob([log], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  onMount(() => {
    load();
    timer = pollVisible(() => load(), 3000);
  });
  onDestroy(() => timer && timer());
</script>

<Modal title={proxyName ? `frpc 通道日志：${proxyName}` : i18nTr("frpc 通道日志")} onClose={onClose} width={880}>
  <div slot="title-extra">
    <InfoTip size={14} text={all || !proxyName
      ? i18nTr("显示 frpc 全部运行日志（末尾 2000 行，自动刷新；已过滤管理接口轮询噪声 [http/middleware.go] http request/response）。")
      : `仅显示代理「${proxyName}」相关日志（匹配 [代理名] 或 [proxy/<类型>:代理名]）；无匹配时可点击「查看全部日志」。`} />
  </div>

  <div class="log-console">
    <div class="log-toolbar">
      <div class="log-ident">
        <span class="log-dot"></span>
        <span class="log-file">frpc.log</span>
        <span class="log-count">{filtered.length}{#if filtered.length !== rawLines.length}<i> / {rawLines.length}</i>{/if} {$i18n("行")}</span>
        {#if lastAt}<span class="log-time">{lastAt}</span>{/if}
      </div>
      <div class="log-seg" role="group" aria-label={$i18n("日志级别")}>
        {#each LEVELS as lv (lv.value)}
          <button
            class="log-seg-btn"
            class:active={level === lv.value}
            aria-pressed={level === lv.value}
            on:click={() => (level = lv.value)}
          >{lv.label}</button>
        {/each}
      </div>
    </div>

    <input
      type="search"
      class="log-search"
      bind:value={keyword}
      placeholder={$i18n("搜索日志内容")}
      aria-label={$i18n("搜索日志内容")}
    />

    <div class="log-filters">
      <div class="log-actions">
        <label class="chk-chip" class:on={wrap}>
          <input type="checkbox" bind:checked={wrap} /> {$i18n("自动换行")}
        </label>
        <label class="chk-chip" class:on={follow}>
          <input type="checkbox" checked={follow} on:change={followLatest} /> {$i18n("跟随最新")}
        </label>
        <button class="btn btn-sm log-btn" on:click={downloadLog} title={$i18n("下载当前显示的日志")}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/></svg>
          {$i18n("下载")}
        </button>
      </div>
    </div>

    {#if error && rawLines.length}
      <div class="log-err">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16.5v.5"/></svg>
        <span>{$i18n("刷新失败：")}{error}</span>
        <button class="btn btn-sm" on:click={load}>{$i18n("重试")}</button>
      </div>
    {/if}

    {#if loading && !rawLines.length}
      <div class="log-empty">
        <div class="log-empty-title">{$i18n("加载中…")}</div>
      </div>
    {:else if !rawLines.length && error}
      <div class="log-empty">
        <div class="log-empty-icon">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16.5v.5"/></svg>
        </div>
        <div class="log-empty-title">{$i18n("日志加载失败")}</div>
        <div class="log-empty-desc">{error}</div>
        <button class="btn btn-sm" on:click={load}>{$i18n("重试")}</button>
      </div>
    {:else if !filtered.length}
      <div class="log-empty">
        <div class="log-empty-icon">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 5h16v14H4z"/><path d="M7 9h10M7 12h10M7 15h6"/></svg>
        </div>
        {#if rawLines.length && hasFilter}
          <div class="log-empty-title">{$i18n("没有匹配的日志")}</div>
          <div class="log-empty-desc">{$i18n("当前级别或关键字过滤掉了全部")} {rawLines.length} {$i18n("行日志。")}</div>
          <button class="btn btn-sm" on:click={clearFilters}>{$i18n("清除筛选")}</button>
        {:else if all || !proxyName}
          <div class="log-empty-title">{$i18n("暂无日志")}</div>
          <div class="log-empty-desc">{$i18n("frpc 未运行或尚未输出日志，稍后会自动刷新。")}</div>
        {:else}
          <div class="log-empty-title">{$i18n("没有该代理的日志")}</div>
          <div class="log-empty-desc">{$i18n("最近 2000 行内没有代理「")}{proxyName}{$i18n("」的相关日志。该代理长时间无连接事件时属正常情况。")}</div>
          <button class="btn btn-sm" on:click={showAll}>{$i18n("查看全部日志")}</button>
        {/if}
      </div>
    {:else}
      <div class="log-pane">
        <div class="log-pane-hdr">
          <span class="log-pane-title">{$i18n("日志输出")}</span>
        </div>
        <pre class="log-pre" class:nowrap={!wrap} bind:this={logEl} on:scroll={onScroll}>{@html highlightLog(log)}</pre>
      </div>
    {/if}
  </div>
</Modal>

<style>
  .log-console { display: flex; flex-direction: column; gap: 10px; }

  /* ---- 顶部状态栏 ---- */
  .log-toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .log-ident { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .log-dot {
    width: 7px; height: 7px; border-radius: 50%; flex: none;
    background: var(--green); box-shadow: 0 0 0 3px rgba(var(--green-rgb), .12);
    animation: log-pulse 2s ease-in-out infinite;
  }
  @keyframes log-pulse { 50% { opacity: .45; } }
  .log-file { font-family: var(--mono); font-size: 12px; font-weight: 600; color: var(--text2); }
  .log-count {
    padding: 1px 8px; border-radius: 999px; border: 1px solid var(--bd);
    background: var(--bg4); color: var(--text3); font-size: 11px;
    font-variant-numeric: tabular-nums; white-space: nowrap;
  }
  .log-count i { font-style: normal; opacity: .6; }
  .log-time { font-family: var(--mono); font-size: 11px; color: var(--text3); opacity: .8; }

  /* ---- 筛选区 ---- */
  .log-filters {
    display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
    padding-bottom: 10px; border-bottom: 1px solid var(--bd);
  }
  .log-search {
    flex: 0 0 auto; width: 100%; min-width: 0; height: 32px; padding: 0 26px 0 31px;
    border: 1px solid var(--bd); border-radius: 8px;
    background-color: var(--bg2);
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%238094ab' stroke-width='2' stroke-linecap='round'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='M20 20l-3.5-3.5'/%3E%3C/svg%3E");
    background-repeat: no-repeat; background-position: 9px center;
    color: var(--text); font-size: 12.5px; font-family: var(--font);
    outline: none; appearance: none; -webkit-appearance: none;
    transition: border-color .15s, box-shadow .15s;
  }
  .log-search::placeholder { color: var(--text3); }
  .log-search:focus {
    border-color: rgba(var(--accent-rgb), .55);
    box-shadow: 0 0 0 3px var(--accent-glow);
  }
  .log-search::-webkit-search-cancel-button {
    -webkit-appearance: none; appearance: none;
    width: 14px; height: 14px; margin: 0 2px 0 0; cursor: pointer;
    background: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%238094ab' stroke-width='2' stroke-linecap='round'%3E%3Cpath d='M6 6l12 12M18 6L6 18'/%3E%3C/svg%3E") center / contain no-repeat;
  }

  .log-seg {
    display: inline-flex; gap: 2px; padding: 2px; margin-left: auto;
    background: var(--bg2); border: 1px solid var(--bd); border-radius: 8px;
  }
  .log-seg-btn {
    border: 0; background: transparent; color: var(--text3);
    font-family: var(--mono); font-size: 11px; font-weight: 600;
    padding: 4px 8px; border-radius: 6px; cursor: pointer;
    transition: color .15s, background .15s; white-space: nowrap;
  }
  .log-seg-btn:hover { color: var(--text2); background: var(--bg4); }
  .log-seg-btn.active { color: var(--accent); background: rgba(var(--accent-rgb), .12); }
  .log-seg-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }

  /* ---- 选项胶囊 ---- */
  .chk-chip {
    display: inline-flex; align-items: center; gap: 4px; height: 24px; padding: 0 7px;
    border: 1px solid var(--bd); border-radius: 6px; background: var(--bg4);
    color: var(--text3); font-size: 11px; line-height: 1; white-space: nowrap; cursor: pointer;
    flex: 0 0 auto; width: fit-content;
    user-select: none; transition: border-color .15s, background .15s, color .15s;
  }
  .chk-chip:hover { color: var(--text2); border-color: var(--bd-strong); }
  .chk-chip.on {
    color: var(--accent); border-color: rgba(var(--accent-rgb), .35);
    background: rgba(var(--accent-rgb), .08);
  }
  .chk-chip input {
    flex: 0 0 auto; width: 12px; height: 12px; min-width: 0; margin: 0;
    accent-color: var(--accent); cursor: pointer;
  }

  /* ---- 日志面板 ---- */
  .log-pane {
    border: 1px solid var(--bd); border-radius: 10px; overflow: hidden;
    background: var(--bg4); box-shadow: inset 0 1px 0 rgba(255, 255, 255, .02);
  }
  .log-pane-hdr {
    display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
    padding: 8px 10px; background: var(--bg3); border-bottom: 1px solid var(--bd);
  }
  .log-pane-title { font-size: 11.5px; font-weight: 600; color: var(--text2); letter-spacing: .3px; }
  .log-actions { display: flex; align-items: center; gap: 8px; margin-left: auto; flex-wrap: wrap; }

  .log-pre {
    margin: 0; padding: 12px; max-height: 52vh; overflow: auto;
    font-family: var(--mono); font-size: 12px; line-height: 1.65; color: var(--text2);
    white-space: pre-wrap; word-break: break-all;
    scrollbar-width: thin; scrollbar-color: var(--bd) transparent;
  }
  .log-pre.nowrap { white-space: pre; word-break: normal; }
  .log-pre::-webkit-scrollbar { width: 10px; height: 10px; }
  .log-pre::-webkit-scrollbar-track { background: transparent; }
  .log-pre::-webkit-scrollbar-thumb {
    background: var(--bd); border: 2px solid var(--bg4); border-radius: 6px;
  }
  .log-pre::-webkit-scrollbar-thumb:hover { background: var(--text3); }
  :global(.log-pre ::selection) { background: rgba(var(--accent-rgb), .25); }

  .log-btn { display: inline-flex; align-items: center; gap: 5px; }

  /* ---- 错误 / 空状态 ---- */
  .log-err {
    display: flex; align-items: center; gap: 9px; flex-wrap: wrap;
    padding: 8px 10px; border-radius: 8px;
    border: 1px solid rgba(var(--red-rgb), .25); border-left: 3px solid var(--red);
    background: rgba(var(--red-rgb), .07); color: var(--red); font-size: 12px;
  }
  .log-err button { margin-left: auto; }

  .log-empty {
    display: flex; flex-direction: column; align-items: center; gap: 9px;
    padding: 36px 20px; text-align: center;
    border: 1px dashed var(--bd); border-radius: 10px;
    background: linear-gradient(180deg, var(--bg4), var(--bg3));
  }
  .log-empty-icon {
    display: flex; align-items: center; justify-content: center;
    width: 46px; height: 46px; border-radius: 12px;
    border: 1px solid var(--bd); background: var(--bg2); color: var(--text3);
  }
  .log-empty-title { font-size: 13px; font-weight: 600; color: var(--text2); }
  .log-empty-desc { max-width: 560px; font-size: 12.5px; line-height: 1.7; color: var(--text3); }
  .log-empty .btn { margin-top: 3px; }
</style>
