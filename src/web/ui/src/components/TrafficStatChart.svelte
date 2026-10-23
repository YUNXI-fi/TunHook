<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 流量统计图表：直观展示数据接收(RX)/发送(TX)速率曲线。
  // 支持三种时间维度切换：
  //   实时：最近 10 分钟，每秒 1 个采样点（内存环形缓冲）
  //   1小时：最近 1 小时，每分钟 1 个聚合点
  //   24小时：最近 24 小时，每分钟 1 个聚合点
  // 「历史记录」按钮弹出模态窗口展示 24 小时之前的历史流量数据（按天汇总）；
  // 数据保留天数在「系统日志」页中配置（默认 31 天）。
  import { onMount, onDestroy, tick } from 'svelte';
  import { api } from '../lib/api.js';
  import { fmtBytes, fmtRate, chartColors, pollVisible } from '../lib/utils.js';
  import { toast, themeVersion } from '../lib/stores.js';
  import Modal from './Modal.svelte';

  const MODES = [
    { id: 'realtime', label: i18nTr("实时"), desc: i18nTr("最近 10 分钟 · 每秒采样") },
    { id: '1h', label: i18nTr("1 小时"), desc: i18nTr("最近 1 小时 · 每分钟采样") },
    { id: '7h', label: i18nTr("7 小时"), desc: i18nTr("最近 7 小时 · 每分钟采样") },
    { id: '12h', label: i18nTr("12 小时"), desc: i18nTr("最近 12 小时 · 每分钟采样") },
    { id: '24h', label: i18nTr("24 小时"), desc: i18nTr("最近 24 小时 · 每分钟采样") }
  ];
  const LINES = [
    { key: 'rx', label: i18nTr("接收") },
    { key: 'tx', label: i18nTr("发送") }
  ];
  // 图表配色随主题切换（浅色主题的强调色/语义色是更深的另一档），每次绘制前取一次当前主题的实际取值
  let C = chartColors();
  // 系列线色：接收用主色（与图例同源）、发送用辅助色
  const seriesColor = (key) => (key === 'rx' ? C.accent : C.accent2);

  let mode = 'realtime';
  let points = [];
  let loading = false;
  let lastError = '';
  let retentionDays = 31;
  let rxTotal = 0;
  let txTotal = 0;
  let timer = null;

  // 历史记录（24 小时之前的流量数据，按天汇总）
  const HIST_RANGES = [
    { v: 3, label: i18nTr("近3天") },
    { v: 7, label: i18nTr("近7天") },
    { v: 30, label: i18nTr("近30天") }
  ];
  const HOUR = 3600;
  const DAY = 86400;
  let showHistory = false;
  let histRange = 7;
  let histLoading = false;
  let histError = '';
  let histPoints = [];

  let canvas, ctx, hover = -1;
  let dayCanvas, dayCtx, dayCtxEl = null, dayResizeObs = null; // 当日明细折线图

  // 按模式格式化坐标轴时间（传入毫秒时间戳；非法时间返回占位符，避免显示 NaN）
  function fmtAxis(ts) {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return '--:--';
    const p = (x) => String(x).padStart(2, '0');
    if (mode === 'realtime') return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    if (mode === '1h') return `${p(d.getHours())}:${p(d.getMinutes())}`;
    return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
  }

  async function load(record) {
    loading = true;
    try {
      const d = await api('/api/traffic/stats?mode=' + mode + (record ? '&record=1' : ''));
      if (d) {
        points = d.points || [];
        retentionDays = d.retention_days || 31;
        if (d.rx_total != null) rxTotal = d.rx_total;
        if (d.tx_total != null) txTotal = d.tx_total;
      }
      lastError = '';
    } catch (e) {
      lastError = e.message;
    }
    loading = false;
    await tick();
    draw();
  }

  function switchMode(m) {
    if (m === mode) return;
    mode = m;
    load(true);
    resetTimer();
  }

  async function refresh() {
    await load(true);
  }

  function resetTimer() {
    if (timer) timer();
    const ms = mode === 'realtime' ? 2000 : mode === '1h' ? 30000 : 60000;
    timer = pollVisible(() => load(false), ms);
  }

  // 打开「历史记录」弹窗：查询 24 小时之前的流量数据（按小时采样，前端按天汇总）
  function openHistory() {
    showHistory = true;
    histDay = null; // 重新打开时回到每日汇总视图，避免残留明细视图导致画布空白
    loadHistory();
  }
  function closeHistory() {
    showHistory = false;
    if (dayResizeObs) {
      dayResizeObs.disconnect();
      dayResizeObs = null;
    }
  }
  async function loadHistory() {
    histLoading = true;
    histError = '';
    const now = Math.floor(Date.now() / 1000);
    const from = now - histRange * DAY;
    try {
      const d = await api(`/api/traffic/stats?mode=history&from=${from}&to=${now}`);
      histPoints = (d && d.points) || [];
      if (d && d.retention_days) retentionDays = d.retention_days;
    } catch (e) {
      histPoints = [];
      histError = e.message;
    }
    histLoading = false;
  }
  function dayKey(ts) {
    const d = new Date(ts * 1000);
    const p = (x) => String(x).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
  }
  // 将每小时采样点按本地日期汇总为每日统计（平均速率 + 当日累计流量）
  $: histDays = (() => {
    const map = new Map();
    for (const p of histPoints) {
      const k = dayKey(p.ts);
      const e = map.get(k) || { key: k, ts: p.ts, rxRateSum: 0, txRateSum: 0, n: 0, rxBytes: 0, txBytes: 0 };
      e.rxRateSum += p.rx || 0;
      e.txRateSum += p.tx || 0;
      e.rxBytes += (p.rx || 0) * HOUR;
      e.txBytes += (p.tx || 0) * HOUR;
      e.n++;
      e.ts = Math.min(e.ts, p.ts);
      map.set(k, e);
    }
    return [...map.values()].sort((a, b) => a.ts - b.ts);
  })();

  // 某一天的按小时明细（点击每日表格行打开）
  let histDay = null; // 选中的日期（YYYY-MM-DD），null=每日列表
  let dayPoints = [];
  let dayLoading = false;
  let dayError = '';
  let dayFrom = 0, dayTo = 0; // 选中日期的查询区间（Unix 秒），用于按真实时间定位绘图
  function dayRange(key) {
    const [y, m, d] = key.split('-').map(Number);
    const start = Math.floor(new Date(y, m - 1, d).getTime() / 1000);
    return { start, end: start + DAY };
  }
  function fmtHour(ts) {
    const p = (x) => String(x).padStart(2, '0');
    return `${p(new Date(ts * 1000).getHours())}:00`;
  }
  async function openDay(key) {
    histDay = key;
    dayLoading = true;
    dayError = '';
    dayPoints = [];
    const { start, end } = dayRange(key);
    dayFrom = start;
    dayTo = end;
    try {
      const d = await api(`/api/traffic/stats?mode=history&from=${start}&to=${end}`);
      dayPoints = (d && d.points) || [];
    } catch (e) {
      dayError = e.message;
    }
    dayLoading = false;
    await tick();
    // 画布随数据挂载后（弹窗动画期间尺寸可能未就绪）：用 ResizeObserver + 双 rAF 兜底，
    // 确保尺寸可用时一定完成绘制，避免渲染失败/空白。
    if (dayResizeObs) dayResizeObs.disconnect();
    dayResizeObs = new ResizeObserver(() => drawDayChart());
    if (dayCanvas) dayResizeObs.observe(dayCanvas);
    requestAnimationFrame(() => requestAnimationFrame(drawDayChart));
  }
  function switchHistRange(v) {
    histRange = v;
    histDay = null;
    loadHistory();
  }
  // 补全当日 24 个小时数据点（无数据的时段显示为“—”）
  $: dayHours = (() => {
    const byHour = new Map();
    for (const p of dayPoints) {
      byHour.set(new Date(p.ts * 1000).getHours(), p);
    }
    const rows = [];
    for (let h = 0; h < 24; h++) {
      const p = byHour.get(h);
      rows.push({ hour: h, has: !!p, rx: p ? p.rx : 0, tx: p ? p.tx : 0 });
    }
    return rows;
  })();

  function draw() {
    if (!canvas) return;
    C = chartColors();
    ctx = ctx || canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    if (w === 0 || h === 0) return;
    if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
      canvas.width = w * dpr;
      canvas.height = h * dpr;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const bg = getComputedStyle(canvas).backgroundColor;
    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, w, h);

    const data = points;
    if (data.length < 2) {
      ctx.fillStyle = C.text3;
      ctx.font = '11px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(loading ? i18nTr("加载中...") : i18nTr("等待数据..."), w / 2, h / 2);
      return;
    }

    let max = 1;
    for (const p of data) {
      if (p.rx > max) max = p.rx;
      if (p.tx > max) max = p.tx;
    }
    max *= 1.15;

    const padL = 6, padR = 6, padT = 16, padB = 16;
    const plotW = w - padL - padR, plotH = h - padT - padB;

    // 网格线（3 条水平参考线）
    ctx.strokeStyle = 'rgba(128,128,128,.12)';
    ctx.lineWidth = 1;
    for (let i = 1; i <= 3; i++) {
      const y = padT + (plotH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(padL + plotW, y);
      ctx.stroke();
    }

    // 最大值标注（左上角）
    ctx.font = '10px sans-serif';
    ctx.fillStyle = C.text3;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText(fmtRate(max), padL, padT - 12);

    const line = (key, color) => {
      ctx.beginPath();
      for (let i = 0; i < data.length; i++) {
        const x = padL + (i / (data.length - 1)) * plotW;
        const y = padT + plotH - (data[i][key] / max) * plotH;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.6;
      ctx.stroke();
      const grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
      grad.addColorStop(0, color + '33');
      grad.addColorStop(1, color + '00');
      ctx.lineTo(padL + plotW, padT + plotH);
      ctx.lineTo(padL, padT + plotH);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
    };
    line('rx', C.accent);
    line('tx', C.accent2);

    // 底部时间轴刻度（4 个）
    ctx.font = '10px sans-serif';
    ctx.fillStyle = C.text3;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    for (let i = 0; i < 4; i++) {
      const idx = Math.round((i / 3) * (data.length - 1));
      const x = padL + (idx / (data.length - 1)) * plotW;
      ctx.fillText(fmtAxis(data[idx].ts * 1000), x, padT + plotH + 4);
    }

    // 悬停：竖线 + 数据点 + 提示框
    if (hover >= 0 && hover < data.length) {
      const x = padL + (hover / (data.length - 1)) * plotW;
      ctx.strokeStyle = C.gridSoft;
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 3]);
      ctx.beginPath();
      ctx.moveTo(x, padT);
      ctx.lineTo(x, padT + plotH);
      ctx.stroke();
      ctx.setLineDash([]);
      for (const l of LINES) {
        const y = padT + plotH - (data[hover][l.key] / max) * plotH;
        ctx.beginPath();
        ctx.arc(x, y, 3.2, 0, Math.PI * 2);
        ctx.fillStyle = seriesColor(l.key);
        ctx.fill();
        ctx.strokeStyle = 'rgba(0,0,0,.5)';
        ctx.lineWidth = 1;
        ctx.stroke();
      }
      drawTip(data[hover], x, padT, plotH);
    }
  }

  // 当日明细折线图：绘制选中日期的按小时接收/发送速率曲线
  function drawDayChart() {
    const cv = dayCanvas;
    if (!cv) return;
    C = chartColors();
    // canvas 卸载重挂后 getContext 句柄会失效，按元素身份重新获取，避免绘制到已分离的画布
    if (dayCtxEl !== cv) {
      dayCtxEl = cv;
      dayCtx = cv.getContext('2d');
    }
    const ctx = dayCtx;
    if (!ctx) return;
    const dpr = window.devicePixelRatio || 1;
    const w = cv.clientWidth, h = cv.clientHeight;
    if (!w || !h) return;
    if (cv.width !== w * dpr || cv.height !== h * dpr) {
      cv.width = w * dpr;
      cv.height = h * dpr;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const bg = getComputedStyle(cv).backgroundColor;
    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, w, h);

    const data = dayPoints;
    if (data.length === 0) {
      ctx.fillStyle = C.text3;
      ctx.font = '11px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(i18nTr("暂无数据"), w / 2, h / 2);
      return;
    }
    if (data.length === 1) {
      // 仅一个采样点：按真实时间绘制数据点而不是折线
      const padL0 = 6, padR0 = 6;
      const plotW0 = w - padL0 - padR0;
      const x = padL0 + ((data[0].ts - dayFrom) / (dayTo - dayFrom || DAY)) * plotW0;
      ctx.font = '10px sans-serif';
      ctx.fillStyle = C.text3;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(fmtHour(data[0].ts), x, h - 18);
      for (const l of LINES) {
        ctx.beginPath();
        ctx.arc(x, h / 2, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = seriesColor(l.key);
        ctx.fill();
        ctx.strokeStyle = 'rgba(0,0,0,.5)';
        ctx.lineWidth = 1;
        ctx.stroke();
      }
      return;
    }

    let max = 1;
    for (const p of data) {
      if (p.rx > max) max = p.rx;
      if (p.tx > max) max = p.tx;
    }
    max *= 1.15;

    const padL = 6, padR = 6, padT = 14, padB = 16;
    const plotW = w - padL - padR, plotH = h - padT - padB;
    // 按真实时间定位 X 坐标（无数据的时段留出空隙，避免稀疏数据被拉成整日曲线）
    const xOf = (ts) => {
      const span = dayTo - dayFrom > 0 ? dayTo - dayFrom : DAY;
      const t = Math.max(dayFrom, Math.min(dayTo, ts));
      return padL + ((t - dayFrom) / span) * plotW;
    };

    // 网格线
    ctx.strokeStyle = 'rgba(128,128,128,.12)';
    ctx.lineWidth = 1;
    for (let i = 1; i <= 3; i++) {
      const y = padT + (plotH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(padL + plotW, y);
      ctx.stroke();
    }
    // 最大值标注
    ctx.font = '10px sans-serif';
    ctx.fillStyle = C.text3;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText(fmtRate(max), padL, padT - 12);

    const line = (key, color) => {
      ctx.beginPath();
      for (let i = 0; i < data.length; i++) {
        const x = xOf(data[i].ts);
        const y = padT + plotH - (data[i][key] / max) * plotH;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.6;
      ctx.stroke();
      const grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
      grad.addColorStop(0, color + '33');
      grad.addColorStop(1, color + '00');
      ctx.lineTo(xOf(data[data.length - 1].ts), padT + plotH);
      ctx.lineTo(xOf(data[0].ts), padT + plotH);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
    };
    line('rx', C.accent);
    line('tx', C.accent2);

    // 底部时间轴刻度（4 个，按当日 00:00-24:00 分布）
    ctx.font = '10px sans-serif';
    ctx.fillStyle = C.text3;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    for (let i = 0; i < 4; i++) {
      const t = Math.round(dayFrom + (i / 3) * (dayTo - dayFrom));
      ctx.fillText(fmtHour(t), xOf(t), padT + plotH + 4);
    }
  }

  function drawTip(p, x, padT, plotH) {
    const rows = [{ label: fmtAxis(p.ts * 1000), color: C.text3, bold: true }];
    for (const l of LINES) {
      rows.push({ label: l.label, val: fmtRate(p[l.key]), color: seriesColor(l.key) });
    }
    ctx.font = '11px sans-serif';
    const pad = 8;
    let maxW = 0;
    for (const r of rows) {
      const txt = r.val !== undefined ? r.label + '  ' + r.val : r.label;
      const w = ctx.measureText(txt).width;
      if (w > maxW) maxW = w;
    }
    const bw = maxW + pad * 2;
    const bh = rows.length * 16 + pad;
    let bx = x + 12;
    if (bx + bw > canvas.clientWidth - 4) bx = x - 12 - bw;
    if (bx < 4) bx = 4;
    const by = padT + 4;
    ctx.fillStyle = C.tipBg;
    ctx.strokeStyle = C.tipBd;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(bx, by, bw, bh, 6);
    ctx.fill();
    ctx.stroke();
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'left';
    rows.forEach((r, i) => {
      const ty = by + pad + 8 + i * 16;
      const lw = ctx.measureText(r.label).width;
      ctx.fillStyle = r.color;
      ctx.font = (r.bold ? '600 ' : 'bold ') + '11px sans-serif';
      ctx.fillText(r.label, bx + pad, ty);
      if (r.val !== undefined) {
        ctx.fillStyle = C.tipText;
        ctx.font = '11px sans-serif';
        ctx.fillText(r.val, bx + pad + lw + 8, ty);
      }
    });
  }

  function onMove(e) {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    if (points.length < 2) return;
    const w = canvas.clientWidth;
    const padL = 6, padR = 6;
    const plotW = w - padL - padR;
    let idx = Math.round(((x - padL) / plotW) * (points.length - 1));
    idx = Math.max(0, Math.min(points.length - 1, idx));
    if (idx !== hover) {
      hover = idx;
      draw();
    }
  }

  function onLeave() {
    if (hover !== -1) {
      hover = -1;
      draw();
    }
  }

  // 最新采样点的速率（图例实时数值）
  $: latest = points.length ? points[points.length - 1] : null;

  // 主题/配色切换后重绘主图与当日明细图：画布读不到 CSS 变量，靠版本号驱动。
  // 当日图仅在弹窗打开时才有画布，drawDayChart 内部已有「无画布直接返回」的保护。
  $: if ($themeVersion) {
    tick().then(() => {
      draw();
      drawDayChart();
    });
  }

  // 全屏查看：以图表卡片为全屏元素，全屏后尝试锁定横屏（移动端）；桌面与不支持横屏的浏览器静默降级
  let statEl = null;
  let isFullscreen = false;

  async function toggleFullscreen() {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
      return;
    }
    if (!statEl) return;
    try {
      await statEl.requestFullscreen();
    } catch (e) {
      toast(i18nTr("浏览器阻止了全屏（内嵌框架可能未授权全屏）"), 'error');
      return;
    }
    // 横屏锁定要求已处于全屏；桌面浏览器与 iOS 不支持时会抛错，保持当前方向即可
    try {
      await screen.orientation.lock('landscape');
    } catch (e) { /* ignore */ }
  }

  // 同步全屏状态（含按 ESC / 系统手势退出），退出时解除横屏锁定
  function onFullscreenChange() {
    isFullscreen = !!document.fullscreenElement;
    if (!isFullscreen && screen.orientation && screen.orientation.unlock) {
      try { screen.orientation.unlock(); } catch (e) { /* ignore */ }
    }
  }

  onMount(() => {
    load(true);
    resetTimer();
    draw();
    const ro = new ResizeObserver(() => draw());
    if (canvas) ro.observe(canvas);
    document.addEventListener('fullscreenchange', onFullscreenChange);
    return () => {
      ro.disconnect();
      document.removeEventListener('fullscreenchange', onFullscreenChange);
    };
  });

  onDestroy(() => {
    if (timer) timer();
    if (dayResizeObs) dayResizeObs.disconnect();
  });
</script>

<div class="traffic-stat dash-card dash-card--chart" bind:this={statEl}>
  <div class="traffic-hdr">
    <div class="traffic-head">
      <div class="traffic-title"><span class="dash-dot" style="background:var(--accent)"></span>{$i18n("流量统计")}<span class="traffic-sub">{$i18n("接收 / 发送速率")}</span></div>
      <div class="traffic-ctrl">
        <div class="mode-switch">
          {#each MODES as m}
            <button class="mode-btn" class:active={mode === m.id} on:click={() => switchMode(m.id)} title={m.desc}>{m.label}</button>
          {/each}
        </div>
        <button class="btn-icon" title={$i18n("刷新")} on:click={refresh} disabled={loading}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/></svg>
        </button>
        <button class="btn-icon" title={$i18n("历史记录")} on:click={openHistory}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/></svg>
        </button>
        <button class="btn-icon" title={isFullscreen ? i18nTr("退出全屏") : i18nTr("全屏查看（自动横屏）")} on:click={toggleFullscreen}>
          {#if isFullscreen}
            <svg width="14" height="14" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><path d="M42 15H33V6"/><path d="M33 42V33H42"/><path d="M6 33V42H15"/><path d="M15 6V15H6"/></svg>
          {:else}
            <svg width="14" height="14" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><path d="M33 6H42V15"/><path d="M42 33V42H33"/><path d="M15 42H6V33"/><path d="M6 15V6H15"/></svg>
          {/if}
        </button>
      </div>
    </div>
    <div class="rate-legend traffic-legend">
      <div class="rate-row"><span class="legend-dot rx"></span>{$i18n("接收")}<span class="rate-now">{latest ? fmtRate(latest.rx) : '-'}</span><span class="rate-total">{$i18n("累计")} {fmtBytes(rxTotal)}</span></div>
      <div class="rate-row"><span class="legend-dot tx"></span>{$i18n("发送")}<span class="rate-now">{latest ? fmtRate(latest.tx) : '-'}</span><span class="rate-total">{$i18n("累计")} {fmtBytes(txTotal)}</span></div>
    </div>
  </div>

  <canvas
    bind:this={canvas}
    class="rate-chart-canvas"
    role="img"
    aria-label={$i18n("流量统计折线图：接收与发送速率")}
    style="cursor:crosshair"
    width="300"
    height="100"
    on:mousemove={onMove}
    on:mouseleave={onLeave}
  ></canvas>

  {#if lastError}
    <div style="font-size:11px;color:var(--red);margin-top:4px">{lastError}</div>
  {/if}

  <div class="chart-foot">
    <span>{mode === 'realtime' ? i18nTr("10分钟前") : mode === '1h' ? i18nTr("1小时前") : mode === '7h' ? i18nTr("7小时前") : mode === '12h' ? i18nTr("12小时前") : i18nTr("24小时前")}</span>
    <span>{$i18n("现在")}</span>
  </div>
</div>

{#if showHistory}
  <Modal title={$i18n("流量历史记录")} width={620} onClose={closeHistory}>
    <div style="display:flex;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px">
      <div class="mode-switch">
        {#each HIST_RANGES as r}
          <button class="mode-btn" class:active={histRange === r.v} on:click={() => switchHistRange(r.v)}>{r.label}</button>
        {/each}
      </div>
    </div>
    <div style="font-size:12px;color:var(--text3);margin-bottom:10px;line-height:1.7">{$i18n("24 小时之前的历史流量数据（按天汇总，数据保留")} {retentionDays} {$i18n("天）。点击日期行查看当日按小时的明细。")}</div>
    {#if histLoading}
      <div style="font-size:12px;color:var(--text3);padding:20px;text-align:center">{$i18n("加载中...")}</div>
    {:else if histError}
      <div style="font-size:12px;color:var(--red);padding:20px;text-align:center">{histError}</div>
    {:else if histDay}
      <div style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:10px">{histDay} {$i18n("流量明细")}</div>
      {#if dayLoading}
        <div style="font-size:12px;color:var(--text3);padding:20px;text-align:center">{$i18n("加载中...")}</div>
      {:else if dayError}
        <div style="font-size:12px;color:var(--red);padding:20px;text-align:center">{dayError}</div>
      {:else if dayPoints.length === 0}
        <div style="font-size:12px;color:var(--text3);padding:20px;text-align:center">{$i18n("该日期暂无流量数据")}</div>
      {:else}
        <div class="rate-legend traffic-legend" style="margin-bottom:6px">
          <div class="rate-row"><span class="legend-dot rx"></span>{$i18n("接收")}<span style="font-size:11px;color:var(--text3)">（{histDay}）</span></div>
          <div class="rate-row"><span class="legend-dot tx"></span>{$i18n("发送")}</div>
        </div>
        <canvas
          bind:this={dayCanvas}
          class="rate-chart-canvas"
          role="img"
          aria-label={$i18n("当日流量速率折线图")}
          style="height:180px;min-height:180px"
        ></canvas>
        <div style="margin-top:10px;max-height:220px;overflow-y:auto;border:1px solid var(--bd);border-radius:var(--radius)">
          <table class="hist-table">
            <thead>
              <tr><th style="width:90px">{$i18n("时间段")}</th><th>{$i18n("平均接收")}</th><th>{$i18n("平均发送")}</th><th>{$i18n("接收量")}</th><th>{$i18n("发送量")}</th></tr>
            </thead>
            <tbody>
              {#each dayHours as d}
                <tr>
                  <td style="font-family:var(--mono);font-size:12px">{String(d.hour).padStart(2, '0')}:00</td>
                  <td style="font-size:12px;color:var(--text2)">{d.has ? fmtRate(d.rx) : '—'}</td>
                  <td style="font-size:12px;color:var(--text2)">{d.has ? fmtRate(d.tx) : '—'}</td>
                  <td style="font-size:12px;color:var(--text2)">{d.has ? fmtBytes(d.rx * HOUR) : '—'}</td>
                  <td style="font-size:12px;color:var(--text2)">{d.has ? fmtBytes(d.tx * HOUR) : '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {:else if histDays.length === 0}
      <div style="font-size:12px;color:var(--text3);padding:20px;text-align:center">{$i18n("该时间段暂无历史数据（仅保留最近")} {retentionDays} {$i18n("天）")}</div>
    {:else}
      <table>
        <thead>
          <tr><th style="width:110px">{$i18n("日期")}</th><th>{$i18n("平均接收")}</th><th>{$i18n("平均发送")}</th><th>{$i18n("接收量")}</th><th>{$i18n("发送量")}</th><th></th></tr>
        </thead>
        <tbody>
          {#each histDays as d}
            <tr class="hist-day-row" on:click={() => openDay(d.key)} title={$i18n("点击查看当日流量明细")}>
              <td style="font-family:var(--mono);font-size:12px">{d.key}</td>
              <td style="font-size:12px;color:var(--text2)">{fmtRate(d.rxRateSum / d.n)}</td>
              <td style="font-size:12px;color:var(--text2)">{fmtRate(d.txRateSum / d.n)}</td>
              <td style="font-size:12px;color:var(--text2)">{fmtBytes(d.rxBytes)}</td>
              <td style="font-size:12px;color:var(--text2)">{fmtBytes(d.txBytes)}</td>
              <td style="text-align:right;font-size:11px;color:var(--accent);white-space:nowrap">{$i18n("明细 ›")}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </Modal>
{/if}

<style>
  .traffic-stat {
    /* 不再自带 margin-top：本卡片作为仪表盘网格的一项（跨整行），间距由网格 gap 提供，
       自带外边距会与 gap 叠加导致间距翻倍 */
    display: flex;
    flex-direction: column;
    /* 高度上限：任何标准屏幕尺寸下卡片高度均不超过可视区域（40vh < 100vh），
       并设置下限保证内容完整可读；内部 canvas 随容器弹性收缩而非溢出裁剪 */
    max-height: min(40vh, 460px);
    min-height: 240px;
  }
  /* 全屏查看：解除高度上下限铺满屏幕；界面缩放（zoom）下按 --ui-scale 补偿，
     与全站 fixed/vh 元素保持一致的换算方式 */
  .traffic-stat:fullscreen {
    max-height: none;
    min-height: 0;
    height: calc(100% / var(--ui-scale, 1));
    border: none;
    border-radius: 0;
  }
  .hist-day-row { cursor: pointer; }
  .hist-day-row:hover td { background: var(--bg4); }
  /* 小时明细表：滚动时固定表头 */
  :global(.hist-table) {
    border-collapse: separate;
    border-spacing: 0;
  }
  :global(.hist-table thead th) {
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--bg3);
  }
  .traffic-hdr {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 10px;
    margin-bottom: 10px;
    flex-shrink: 0;
  }
  .traffic-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
  }
  .traffic-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13.5px;
    font-weight: 600;
    color: var(--text);
    white-space: nowrap;
  }
  .traffic-sub {
    font-size: 11px;
    font-weight: 400;
    color: var(--text3);
  }
  .traffic-hdr :global(.dash-card-h) {
    margin-bottom: 0;
  }
  .traffic-ctrl {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .mode-switch {
    display: inline-flex;
    background: var(--bg4);
    border: 1px solid var(--bd);
    border-radius: var(--radius);
    padding: 2px;
    gap: 2px;
  }
  .mode-btn {
    border: none;
    background: transparent;
    color: var(--text3);
    font-size: 12px;
    padding: 5px 12px;
    border-radius: calc(var(--radius) - 2px);
    cursor: pointer;
    white-space: nowrap;
    transition: .2s;
    font-family: var(--font);
  }
  .mode-btn:hover {
    color: var(--text2);
  }
  .mode-btn.active {
    background: var(--accent-solid);
    color: #fff;
    font-weight: 600;
  }
  /* 刷新/历史记录：无框幽灵图标按钮，桌面与时间切换胶囊齐高，窄屏恢复触控尺寸 */
  .traffic-ctrl :global(.btn-icon) {
    width: 30px;
    height: 30px;
  }
  @media (max-width: 600px) {
    .traffic-sub {
      display: none;
    }
    /* 时间胶囊独占一行，刷新/历史/全屏图标换到下一行右对齐，避免窄屏裁切 */
    .traffic-ctrl {
      flex-wrap: wrap;
      justify-content: flex-end;
      gap: 6px;
    }
    .mode-switch {
      flex: 1 1 100%;
      min-width: 0;
    }
    .mode-btn {
      flex: 1 1 auto;
      min-width: 0;
      padding: 5px 6px;
    }
    .traffic-ctrl :global(.btn-icon) {
      width: 32px;
      height: 32px;
      flex: 0 0 auto;
    }
    .traffic-ctrl :global(.btn-icon svg) {
      width: 13px;
      height: 13px;
    }
  }
  /* 图例横向排布：接收/发送两个条目在同一水平行内，窄屏自动换行保持对齐 */
  .traffic-stat :global(.rate-legend) {
    flex-direction: row;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 24px;
  }
  .traffic-stat :global(.rate-legend .rate-row) {
    white-space: nowrap;
  }
  .traffic-stat :global(.rate-chart-canvas) {
    margin-top: 6px;
    flex: 1 1 auto;
    min-height: 96px;
  }
</style>
