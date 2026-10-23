<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // Canvas 宿主机连接实时图：TCP 会话（红）/ TCP 已建立（绿）/ UDP 会话（紫）三条折线，支持鼠标悬停查看数据
  import { onMount, tick } from 'svelte';
  import { chartColors } from '../lib/utils.js';
  import { themeVersion } from '../lib/stores.js';
  export let series = []; // [{t, total, tcp, tcp_established, udp}] 最新在末尾
  export let maxPoints = 60;
  export let current = 0; // 当前连接数（数据不足时显示）

  const LINES = [
    { key: 'tcp', label: i18nTr("TCP 会话") },
    { key: 'tcp_established', label: i18nTr("TCP 已建立") },
    { key: 'udp', label: i18nTr("UDP 会话") }
  ];
  // 图表配色随主题切换（浅色主题的语义色是更深的另一档），绘制前取一次当前主题的实际取值
  let C = chartColors();
  // 系列线色与图例一致：TCP 会话=红、已建立=绿、UDP=紫
  const seriesColor = (key) => (key === 'tcp' ? C.red : key === 'tcp_established' ? C.green : C.violet);

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
      // 数据不足：显示当前连接数（采样中）
      ctx.fillStyle = C.green;
      ctx.font = '600 28px sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(current > 0 ? String(current) : '-', w / 2, h / 2);
      ctx.fillStyle = C.text3;
      ctx.font = '11px sans-serif';
      ctx.fillText(i18nTr("采样中..."), w / 2, h / 2 + 22);
      return;
    }

    let max = 1;
    for (const p of data) {
      for (const l of LINES) {
        const v = p[l.key] || 0;
        if (v > max) max = v;
      }
    }
    max *= 1.15;

    const padL = 4, padR = 4, padT = 6, padB = 4;
    const plotW = w - padL - padR, plotH = h - padT - padB;

    // 网格
    ctx.strokeStyle = 'rgba(128,128,128,.12)';
    ctx.lineWidth = 1;
    for (let i = 1; i <= 3; i++) {
      const y = padT + (plotH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(padL + plotW, y);
      ctx.stroke();
    }

    // 折线（TCP 已建立带渐变填充，其余仅描线避免重叠遮挡）
    const line = (key, color, fill) => {
      ctx.beginPath();
      for (let i = 0; i < data.length; i++) {
        const x = padL + (i / (data.length - 1)) * plotW;
        const y = padT + plotH - ((data[i][key] || 0) / max) * plotH;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.6;
      ctx.stroke();
      if (fill) {
        const grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
        grad.addColorStop(0, color + '33');
        grad.addColorStop(1, color + '00');
        ctx.lineTo(padL + plotW, padT + plotH);
        ctx.lineTo(padL, padT + plotH);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();
      }
    };
    line('tcp', C.red, false);
    line('tcp_established', C.green, true);
    line('udp', C.violet, false);

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
        const y = padT + plotH - ((data[hover][l.key] || 0) / max) * plotH;
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

  // 绘制悬停提示框（时间 + 各指标数值）
  function drawTip(p, x, padT, plotH) {
    const rows = [{ label: fmtTime(p.t), color: C.text3, bold: true }];
    for (const l of LINES) {
      rows.push({ label: l.label, val: String(p[l.key] || 0), color: seriesColor(l.key) });
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

  $: if (series || current) {
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
  aria-label={$i18n("宿主机连接数折线图：TCP 会话、TCP 已建立、UDP 会话（最近60秒）")}
  style="cursor:crosshair"
  width="300"
  height="100"
  on:mousemove={onMove}
  on:mouseleave={onLeave}
></canvas>
