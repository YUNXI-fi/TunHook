<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // Canvas 实时速率图：绘制 RX（青）与 TX（橙）两条折线，支持鼠标悬停查看数据
  import { onMount, tick } from 'svelte';
  import { fmtRate, chartColors } from '../lib/utils.js';
  import { themeVersion } from '../lib/stores.js';
  export let series = []; // [{t: ts, rx: bytes, tx: bytes}] 最新在末尾
  export let maxPoints = 60;

  const LINES = [
    { key: 'rx', label: i18nTr("接收") },
    { key: 'tx', label: i18nTr("发送") }
  ];
  // 图表配色随主题切换（浅色主题的强调色/语义色是更深的另一档），绘制前取一次当前主题的实际取值
  let C = chartColors();
  // 系列线色：接收用主色（与图例 .legend-dot.rx 同源，换主色时线与图例一起变）、发送用辅助色
  const seriesColor = (key) => (key === 'rx' ? C.accent : C.accent2);

  let canvas;
  let ctx;
  let hover = -1; // 悬停的采样点索引

  function fmtTime(ts) {
    const d = new Date(ts);
    const p = (x) => String(x).padStart(2, '0');
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

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

    const data = series.slice(-maxPoints);
    if (data.length < 2) {
      ctx.fillStyle = C.text3;
      ctx.font = '11px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(i18nTr("等待数据..."), w / 2, h / 2);
      return;
    }

    let max = 1;
    for (const p of data) {
      if (p.rx > max) max = p.rx;
      if (p.tx > max) max = p.tx;
    }
    max *= 1.15;

    const padL = 4, padR = 4, padT = 6, padB = 4;
    const plotW = w - padL - padR, plotH = h - padT - padB;

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

    ctx.strokeStyle = 'rgba(128,128,128,.12)';
    ctx.lineWidth = 1;
    for (let i = 1; i <= 3; i++) {
      const y = padT + (plotH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(padL + plotW, y);
      ctx.stroke();
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

  // 绘制悬停提示框（时间 + 接收/发送速率）
  function drawTip(p, x, padT, plotH) {
    const rows = [{ label: fmtTime(p.t), color: C.text3, bold: true }];
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
    const data = series.slice(-maxPoints);
    if (data.length < 2) return;
    const w = canvas.clientWidth;
    const padL = 4, padR = 4;
    const plotW = w - padL - padR;
    let idx = Math.round(((x - padL) / plotW) * (data.length - 1));
    idx = Math.max(0, Math.min(data.length - 1, idx));
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

  onMount(() => {
    draw();
    const ro = new ResizeObserver(() => draw());
    if (canvas) ro.observe(canvas);
    return () => ro.disconnect();
  });

  $: if (series) {
    tick().then(() => draw());
  }

  // 主题/配色切换后重绘：画布读不到 CSS 变量，变量改了不会自己刷新，靠版本号驱动
  $: if ($themeVersion) {
    tick().then(() => draw());
  }
</script>

<canvas
  bind:this={canvas}
  class="rate-chart-canvas"
  role="img"
  aria-label={$i18n("实时网络速率折线图：接收与发送速率（最近60秒）")}
  style="cursor:crosshair"
  width="300"
  height="100"
  on:mousemove={onMove}
  on:mouseleave={onLeave}
></canvas>
