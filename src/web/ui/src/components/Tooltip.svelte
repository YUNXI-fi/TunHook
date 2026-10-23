<script>
  // 轻量 Tooltip：悬停/键盘焦点显示，边缘自动避让，适配减少动态效果偏好
  export let text = '';
  let tipEl;
  let showTip = false;
  let pos = { x: 0, y: 0 };
  let placement = 'top'; // top（默认上方）| bottom（避让后下方），用于渲染箭头
  let timer;

  function show(e) {
    if (!text) return;
    clearTimeout(timer);
    // 事件派发结束后 currentTarget 会被置空，需在进入延时回调前保存引用
    const el = e.currentTarget;
    timer = setTimeout(() => {
      const r = el.getBoundingClientRect();
      showTip = true;
      requestAnimationFrame(() => {
        if (!tipEl) return;
        const w = tipEl.offsetWidth;
        const h = tipEl.offsetHeight;
        let x = r.left + r.width / 2 - w / 2;
        let y = r.top - h - 8;
        if (x < 8) x = 8;
        if (x + w > window.innerWidth - 8) x = window.innerWidth - w - 8;
        if (y < 8) {
          y = r.bottom + 8;
          placement = 'bottom';
        } else {
          placement = 'top';
        }
        pos = { x, y };
      });
    }, 350);
  }
  function hide() {
    clearTimeout(timer);
    showTip = false;
  }
</script>

<span class="tip-wrap"
  on:mouseenter={show}
  on:mouseleave={hide}
  on:focus={show}
  on:blur={hide}
  on:click|stopPropagation
  role="presentation"
  tabindex="-1"
  style="display:inline-flex"
>
  <slot />
</span>

<div class="app-tip" class:show={showTip} bind:this={tipEl}
  data-placement={placement}
  style="left:{pos.x}px;top:{pos.y}px"
  aria-hidden="true">{text}</div>
