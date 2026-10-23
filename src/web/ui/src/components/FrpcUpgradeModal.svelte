<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // frpc 内核安装/升级弹窗：说明 / 在线安装(升级) / 离线安装(升级) / 实时进度 / 确认与取消
  import { onMount, onDestroy } from 'svelte';
  import { fade } from 'svelte/transition';
  import Modal from './Modal.svelte';
  import { api, apiBase } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import { fmtBytes } from '../lib/utils.js';

  export let onClose = () => {};
  export let onUpgraded = () => {};

  let installed = false; // 打开弹窗时 frpc 是否已安装：未安装时全文案为「安装」，已安装为「升级」
  let current = '';
  let latest = '';
  let hasUpdate = false;
  let checking = false;
  // idle | downloading | installing | done | error
  let phase = 'idle';
  let stage = '';
  let percent = -1; // -1 = 不定进度（动画），>=0 = 具体百分比
  let errMsg = '';
  let busy = false;
  let pollTimer = null;
  let mode = 'online'; // online: 在线下载; upload: 离线上传
  let uploadInput = null;
  // 离线升级文件选择状态（自定义上传区）
  let selectedFile = null;
  let fileName = '';
  let fileSize = 0;
  let dragOver = false;

  onMount(async () => {
    await loadStatus();
    // 打开弹窗时静默检查：网络受限（如 GitHub API 403）只显示「未知/--」，不弹错误打扰
    checkLatest(true);
  });
  onDestroy(() => stopPolling());

  async function loadStatus() {
    try {
      const d = await api('/api/frpc/status');
      if (d) {
        current = d.version || '';
        installed = !!d.installed;
      }
    } catch (e) { /* ignore */ }
  }

  // silent=true（弹窗打开自动检查）时失败不弹 toast；手动点击「检查最新版本」仍提示错误
  async function checkLatest(silent = false) {
    checking = true;
    try {
      const d = await api('/api/frpc/upgrade/check', { method: 'POST' });
      latest = d.latest || '';
      hasUpdate = !!d.has_update;
    } catch (e) {
      latest = '';
      hasUpdate = false;
      if (!silent) toast(e.message, 'error');
    }
    checking = false;
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(async () => {
      try {
        const d = await api('/api/frpc/status');
        const p = d && d.progress;
        if (!p) return;
        if (p.stage) stage = p.stage;
        if (stage.indexOf(i18nTr("内核")) >= 0 || p.total <= 0) {
          percent = -1; // 替换阶段为不定进度
        } else if (p.total > 0 && p.percent >= 0) {
          percent = p.percent;
        }
      } catch (e) { /* ignore */ }
    }, 600);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  // 在线安装/升级：确认 → 下载最新内核包并替换
  async function onlineUpgrade() {
    if (!latest || !hasUpdate || busy) return;
    busy = true;
    mode = 'online';
    phase = 'downloading';
    stage = i18nTr("正在连接下载服务器…");
    percent = -1;
    errMsg = '';
    startPolling();
    try {
      await api('/api/frpc/upgrade/download', { method: 'POST', body: { version: latest } });
      phase = 'done';
      stage = installed ? i18nTr("升级完成") : i18nTr("安装完成");
      toast(installed ? i18nTr("内核升级成功") : i18nTr("内核安装成功"), 'success');
      await loadStatus();
      if (onUpgraded) onUpgraded();
    } catch (e) {
      phase = 'error';
      errMsg = e.message;
      toast(e.message, 'error');
    } finally {
      stopPolling();
      busy = false;
    }
  }

  // 离线安装/升级：上传 .tar.gz 内核包并替换（XHR 提供真实上传进度）
  function uploadUpgrade() {
    const file = selectedFile;
    if (!file) {
      toast(i18nTr("请先选择 .tar.gz 内核包"), 'error');
      return;
    }
    if (busy) return;
    busy = true;
    mode = 'upload';
    phase = 'downloading';
    stage = i18nTr("正在上传内核包…");
    percent = 0;
    errMsg = '';
    startPolling();

    const fd = new FormData();
    fd.append('file', file);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', apiBase + '/api/frpc/upgrade/upload');
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && mode === 'upload' && phase !== 'done') {
        percent = Math.round((e.loaded / e.total) * 100);
        stage = i18nTr("正在上传内核包…");
      }
    };
    xhr.upload.onload = () => {
      // 上传完成，进入服务端替换阶段（不定进度）
      if (phase !== 'done') {
        stage = i18nTr("正在替换内核…");
        percent = -1;
      }
    };
    xhr.onload = async () => {
      let data = null;
      try { data = JSON.parse(xhr.responseText); } catch (e) { /* ignore */ }
      if (xhr.status >= 200 && xhr.status < 300 && data && data.success !== false) {
        phase = 'done';
        stage = installed ? i18nTr("升级完成") : i18nTr("安装完成");
        toast(installed ? i18nTr("内核升级成功") : i18nTr("内核安装成功"), 'success');
        if (onUpgraded) onUpgraded();
        await loadStatus();
      } else {
        phase = 'error';
        errMsg = (data && data.error) || ('HTTP ' + xhr.status);
        toast(errMsg, 'error');
      }
      stopPolling();
      busy = false;
      if (uploadInput) uploadInput.value = '';
    };
    xhr.onerror = () => {
      phase = 'error';
      errMsg = i18nTr("网络请求失败，请重试");
      toast(errMsg, 'error');
      stopPolling();
      busy = false;
    };
    xhr.send(fd);
  }

  // ---- 离线升级文件选择 ----
  function onFileSelect(e) {
    const f = e.target.files && e.target.files[0];
    if (f) setFile(f);
  }

  function onDrop(e) {
    e.preventDefault();
    dragOver = false;
    if (busy) return;
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) setFile(f);
  }

  function setFile(f) {
    if (!/\.tar\.gz$/i.test(f.name)) {
      toast(i18nTr("内核包必须是 .tar.gz 格式"), 'error');
      clearFile();
      return;
    }
    selectedFile = f;
    fileName = f.name;
    fileSize = f.size;
  }

  function clearFile() {
    selectedFile = null;
    fileName = '';
    fileSize = 0;
    if (uploadInput) uploadInput.value = '';
  }
</script>

<Modal title={installed ? i18nTr("升级内核") : i18nTr("安装内核")} onClose={onClose} width={620}>
  <!-- 安装/升级说明 -->
  <div style="background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius);padding:12px 14px;margin-bottom:16px">
    <div style="display:flex;gap:8px;align-items:flex-start">
      <span style="color:var(--accent);margin-top:1px">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/></svg>
      </span>
      <div style="font-size:12px;color:var(--text2);line-height:1.7">
        {#if installed}{$i18n("升级将替换当前 frpc（frp 内网穿透客户端）内核为指定版本，期间 frpc 会短暂停止并在升级完成后自动恢复。升级前请确认服务器端 frps 与客户端版本兼容。")}{:else}{$i18n("安装 frpc（frp 内网穿透客户端）内核：可在线下载官方版本自动安装，网络受限时改用离线上传官方 .tar.gz 包。安装前请确认服务器端 frps 与客户端版本兼容。")}{/if}
      </div>
    </div>
  </div>

  <!-- 版本信息 -->
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px">
    <div class="stat-card">
      <div class="stat-num">{current ? 'v' + current : '-'}</div>
      <div class="stat-label">{$i18n("当前内核版本")}</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">{latest ? 'v' + latest : '-'}</div>
      <div class="stat-label">{$i18n("最新版本")}</div>
    </div>
    <div class="stat-card" style="display:flex;flex-direction:column;align-items:center;justify-content:center">
      {#if checking}
        <span class="badge badge-syncing">{$i18n("检查中…")}</span>
      {:else if latest}
        <span class="badge {hasUpdate ? 'badge-warn' : 'badge-on'}">{hasUpdate ? i18nTr("有新版本") : i18nTr("已是最新")}</span>
      {:else}
        <span class="badge badge-off">{$i18n("未知")}</span>
      {/if}
    </div>
  </div>

  <!-- 在线安装/升级 -->
  <div class="settings-group">
    <div class="settings-group-title">{$i18n("在线")}{installed ? i18nTr("升级") : i18nTr("安装")}</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <!-- 注意：必须箭头函数包裹，否则 Svelte 会把 MouseEvent 当作 silent 传入，导致失败提示被静默 -->
      <button class="btn btn-sm" on:click={() => checkLatest()} disabled={checking || busy} style="white-space:nowrap">{checking ? i18nTr("检查中…") : i18nTr("检查最新版本")}</button>
      <span style="font-size:12px;color:var(--text3)">{$i18n("官方开源地址：")}<a class="cell-link" href="https://github.com/fatedier/frp" target="_blank" rel="noopener noreferrer">github.com/fatedier/frp</a></span>
    </div>
  </div>

  <!-- 离线安装/升级 -->
  <div class="settings-group">
    <div class="settings-group-title">{$i18n("离线")}{installed ? i18nTr("升级") : i18nTr("安装")}</div>
    <div
      class="upload-zone"
      class:upload-drag={dragOver}
      class:upload-busy={busy}
      role="button"
      tabindex="0"
      title={$i18n("点击选择或拖拽 .tar.gz 内核包")}
      on:dragover={(e) => { e.preventDefault(); dragOver = true; }}
      on:dragleave={() => (dragOver = false)}
      on:drop={onDrop}
      on:click={() => { if (!busy && uploadInput) uploadInput.click(); }}
      on:keydown={(e) => { if (!busy && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); uploadInput && uploadInput.click(); } }}
    >
      <input type="file" bind:this={uploadInput} accept=".tar.gz" class="hidden" on:change={onFileSelect} disabled={busy} />
      {#if fileName}
        <div class="upload-file">
          <span class="upload-ico" style="color:var(--green)">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/></svg>
          </span>
          <div style="min-width:0;flex:1">
            <div class="upload-fname">{fileName}</div>
            <div class="upload-fmeta">{fmtBytes(fileSize)} {$i18n("· 点击或拖拽可更换文件")}</div>
          </div>
          <button class="btn-icon" title={$i18n("移除文件")} on:click|stopPropagation={clearFile} disabled={busy}>
            <svg width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M8 11L40 11" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M18 5L30 5" stroke="currentColor" stroke-width="4" stroke-linecap="round"/><path d="M12 17H36V40C36 41.6569 34.6569 43 33 43H15C13.3431 43 12 41.6569 12 40V17Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round"/></svg>
          </button>
        </div>
      {:else}
        <span class="upload-ico" style="color:var(--accent)">
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/></svg>
        </span>
        <div class="upload-tip">{$i18n("点击选择或拖拽 .tar.gz 内核包到此处")}</div>
        <div class="upload-sub">{$i18n("选择官方 frp linux_amd64 离线包")}</div>
      {/if}
    </div>
    <div style="display:flex;align-items:center;gap:10px;margin-top:10px;flex-wrap:wrap">
      <button class="btn btn-primary btn-sm" on:click={uploadUpgrade} disabled={busy || !fileName} style="white-space:nowrap">
        {busy ? i18nTr("上传中…") : installed ? i18nTr("上传并升级") : i18nTr("上传并安装")}
      </button>
      <span style="font-size:12px;color:var(--text3)">
        {fileName ? (installed ? i18nTr("将替换当前 frpc 内核为所选版本") : i18nTr("将安装所选版本的 frpc 内核")) : i18nTr("网络不可用时推荐使用离线") + (installed ? i18nTr("升级") : i18nTr("安装"))}
      </span>
    </div>
  </div>

  <!-- 进度指示 -->
  {#if phase === 'downloading' || phase === 'installing'}
    <div transition:fade={{ duration: 200 }} style="background:var(--bg4);border:1px solid var(--bd);border-radius:var(--radius);padding:12px 14px;margin-top:16px">
      <div style="display:flex;justify-content:space-between;align-items:center;font-size:12px;color:var(--text2);margin-bottom:8px">
        <span>{stage}</span>
        {#if percent >= 0}
          <span class="mono" style="color:var(--accent);font-weight:600">{percent}%</span>
        {/if}
      </div>
      <div class="progress-track">
        <div class="progress-fill" class:indeterminate={percent < 0} style="width:{percent >= 0 ? percent + '%' : '35%'}"></div>
      </div>
    </div>
  {:else if phase === 'done'}
    <div transition:fade={{ duration: 200 }} style="display:flex;gap:10px;align-items:center;background:rgba(var(--green-rgb),.08);border:1px solid rgba(var(--green-rgb),.25);border-radius:var(--radius);padding:14px;margin-top:16px">
      <span style="color:var(--green)">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4 12 14.01l-3-3"/></svg>
      </span>
      <div style="font-size:13px;color:var(--text2)">{installed ? i18nTr("升级完成") : i18nTr("安装完成")}{$i18n("，当前内核版本：")}<b style="color:var(--green)">{current ? 'v' + current : ''}</b></div>
    </div>
  {:else if phase === 'error'}
    <div transition:fade={{ duration: 200 }} style="display:flex;gap:10px;align-items:flex-start;background:rgba(var(--red-rgb),.08);border:1px solid rgba(var(--red-rgb),.25);border-radius:var(--radius);padding:14px;margin-top:16px">
      <span style="color:var(--red)">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
      </span>
      <div style="font-size:12px;color:var(--red)">{errMsg}</div>
    </div>
  {/if}

  <!-- 确认 / 取消 -->
  <div slot="footer">
    <button class="btn" on:click={onClose} disabled={busy}>{$i18n("取消")}</button>
    {#if phase === 'done'}
      <button class="btn btn-primary" on:click={onClose} style="white-space:nowrap">{$i18n("完成")}</button>
    {:else}
      <button class="btn btn-primary" on:click={onlineUpgrade} disabled={busy || !latest || !hasUpdate} title={!hasUpdate ? (installed ? i18nTr("当前已是最新版本") : i18nTr("未能获取最新版本，请使用离线安装")) : ''} style="white-space:nowrap">
        {busy ? (installed ? i18nTr("升级中…") : i18nTr("安装中…")) : installed ? i18nTr("确认升级") : i18nTr("确认安装")}
      </button>
    {/if}
  </div>
</Modal>

<style>
  .upload-zone {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 22px 16px;
    border: 1.5px dashed var(--bd);
    border-radius: var(--radius);
    background: var(--bg4);
    cursor: pointer;
    transition: border-color .15s ease, background .15s ease;
    outline: none;
    text-align: center;
  }
  .upload-zone:hover { border-color: var(--accent); background: rgba(var(--accent-rgb), .04); }
  .upload-zone.upload-drag { border-color: var(--accent); background: rgba(var(--accent-rgb), .08); }
  .upload-zone.upload-busy { opacity: .55; cursor: default; pointer-events: none; }
  .upload-ico { display: inline-flex; }
  .upload-tip { font-size: 13px; font-weight: 600; color: var(--text2); }
  .upload-sub { font-size: 11px; color: var(--text3); }
  .upload-file { display: flex; align-items: center; gap: 12px; width: 100%; }
  .upload-fname {
    font-family: var(--mono);
    font-size: 13px;
    color: var(--accent);
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .upload-fmeta { font-size: 11px; color: var(--text3); margin-top: 2px; }

  :global(.progress-fill.indeterminate) {
    background: linear-gradient(90deg, var(--accent), var(--green), var(--accent));
    background-size: 200% 100%;
    animation: kernel-progress-slide 1.2s linear infinite;
  }
  @keyframes kernel-progress-slide {
    0% { background-position: 0% 0; }
    100% { background-position: 200% 0; }
  }
</style>
