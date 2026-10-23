<script>import { tr as i18nTr } from '../lib/i18n.js';
  
  // 自定义下拉选择器：替代原生 select，统一主题、动画与交互
  // 层级策略：选项面板挂载到 <body>（脱离父级 overflow/z-index/层叠上下文限制），
  // 使用 position:fixed 按视口定位，z-index 取全站最高，滚动/缩放时跟随重定位，
  // 下方空间不足时自动翻转上方，保证任何屏幕尺寸下完整可见。
  import { createEventDispatcher, onMount, onDestroy, tick } from 'svelte';

  export let options = [];       // { value, label }[]
  export let value = '';
  export let placeholder = i18nTr("请选择");
  export let disabled = false;
  export let width = '100%';
  export let id = '';            // 外部指定时作为触发器 id，供 <label for> 关联

  const dispatch = createEventDispatcher();
  let open = false;
  let el;          // 组件根 .custom-select（用于取触发器位置）
  let panelHost;   // 面板宿主，挂载后移动到 <body>
  let panelEl;     // .cs-panel 元素（用于测量/定位）
  let bodyHost;    // <body> 下的挂载点
  let raf = 0;
  let triggerId = id || 'cs-' + Math.random().toString(36).slice(2, 9);

  $: selected = options.find((o) => o.value === value);
  $: displayLabel = selected ? selected.label : placeholder;

  // 面板宿主移动到 <body>，彻底脱离父级 overflow:hidden / z-index / 层叠上下文限制
  $: if (panelHost && bodyHost) bodyHost.appendChild(panelHost);

  // 按触发器视口位置定位面板（fixed 相对视口）；下方空间不足时翻转到上方
  async function positionPanel() {
    if (!open || !el || !panelEl) return;
    await tick();
    if (!open || !el || !panelEl) return; // tick 期间可能已关闭
    const tr = el.getBoundingClientRect();
    const vw = window.innerWidth || document.documentElement.clientWidth;
    const vh = window.innerHeight || document.documentElement.clientHeight;
    const w = tr.width;
    // 左右边界：面板最窄为触发器宽，最多不超出视口
    let left = Math.min(Math.max(4, tr.left), Math.max(4, vw - w - 4));
    panelEl.style.minWidth = w + 'px';
    panelEl.style.width = 'auto';
    panelEl.style.maxWidth = Math.max(w, vw - 16) + 'px';
    // 上/下边界：优先下方，空间不足翻转
    const spaceBelow = vh - tr.bottom - 8;
    let top, maxH;
    if (spaceBelow >= 120 || spaceBelow >= (panelEl.offsetHeight * 0.6)) {
      top = tr.bottom + 6;
      maxH = Math.min(280, Math.max(80, spaceBelow));
    } else {
      const above = tr.top - 8;
      top = Math.max(4, tr.top - panelEl.offsetHeight - 6);
      maxH = Math.min(280, Math.max(80, above));
    }
    panelEl.style.left = left + 'px';
    panelEl.style.top = top + 'px';
    panelEl.style.maxHeight = maxH + 'px';
  }

  function schedulePosition() {
    if (raf) cancelAnimationFrame(raf);
    raf = requestAnimationFrame(positionPanel);
  }

  function toggle() {
    if (disabled) return;
    open = !open;
    if (open) schedulePosition();
  }

  function selectOption(opt) {
    if (opt.disabled) return;
    value = opt.value;
    open = false;
    dispatch('change', { value: opt.value });
  }

  function onKeydown(e) {
    if (disabled) return;
    if (!open && (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown')) {
      e.preventDefault();
      open = true;
      schedulePosition();
      return;
    }
    if (open && e.key === 'Escape') {
      e.preventDefault();
      open = false;
      return;
    }
    if (open && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      e.preventDefault();
      const idx = options.findIndex((o) => o.value === value);
      const nextIdx = e.key === 'ArrowDown'
        ? (idx + 1 >= options.length ? 0 : idx + 1)
        : (idx - 1 < 0 ? options.length - 1 : idx - 1);
      const next = options[nextIdx];
      if (next && !next.disabled) {
        value = next.value;
        dispatch('change', { value: next.value });
      }
    }
  }

  // 点击面板/触发器外部才关闭（面板已挂载到 body，需单独判断）
  function onDocClick(e) {
    if (!open) return;
    if (el && el.contains(e.target)) return;
    if (panelEl && panelEl.contains(e.target)) return;
    open = false;
  }

  onMount(() => {
    bodyHost = document.createElement('div');
    bodyHost.className = 'cs-portal';
    document.body.appendChild(bodyHost);
    document.addEventListener('click', onDocClick, true);
    // capture 捕获内部容器滚动 + 窗口 resize，滚动/缩放时跟随重定位
    window.addEventListener('scroll', schedulePosition, true);
    window.addEventListener('resize', schedulePosition);
    return () => {
      if (bodyHost) bodyHost.remove();
      document.removeEventListener('click', onDocClick, true);
      window.removeEventListener('scroll', schedulePosition, true);
      window.removeEventListener('resize', schedulePosition);
      if (raf) cancelAnimationFrame(raf);
    };
  });
  onDestroy(() => { /* 清理已在 onMount 返回函数中完成 */ });
</script>

<div class="custom-select" bind:this={el} class:open class:disabled style:width={width}>
  <button
    type="button"
    class="cs-trigger"
    id={triggerId}
    aria-haspopup="listbox"
    aria-expanded={open}
    {disabled}
    on:click={toggle}
    on:keydown={onKeydown}
  >
    <span class="cs-label" class:placeholder={!selected}>{displayLabel}</span>
    <svg class="cs-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="m6 9 6 6 6-6"/>
    </svg>
  </button>

  <!-- 面板宿主：mount 后整体移动到 <body>，避免被父级 overflow/z-index 裁剪遮挡 -->
  <div class="cs-host" bind:this={panelHost}>
    {#if open}
      <ul class="cs-panel" bind:this={panelEl} role="listbox" aria-labelledby={triggerId} tabindex="-1">
        {#each options as opt}
          <li
            class="cs-option"
            class:selected={opt.value === value}
            class:disabled={opt.disabled}
            role="option"
            aria-selected={opt.value === value}
            tabindex="-1"
            on:click={() => selectOption(opt)}
            on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectOption(opt); } }}
          >
            <span class="cs-option-label">{opt.label}</span>
            {#if opt.value === value}
              <svg class="cs-check" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </div>
</div>

<style>
  .custom-select { position: relative; display: inline-block; }
  .cs-trigger {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 8px 12px;
    border: 1px solid var(--bd);
    border-radius: var(--radius);
    background: var(--bg2);
    color: var(--text);
    font-size: 13px;
    font-family: var(--font);
    outline: none;
    cursor: pointer;
    transition: border-color .2s, box-shadow .2s, background-color .2s;
    text-align: left;
  }
  .cs-trigger:hover:not(:disabled) { border-color: rgba(var(--accent-rgb), .5); }
  .cs-trigger:focus-visible:not(:disabled),
  .custom-select.open .cs-trigger {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-glow);
  }
  .cs-label { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .cs-label.placeholder { color: var(--text3); }
  .cs-arrow { flex-shrink: 0; color: var(--text3); transition: transform .2s; }
  .custom-select.open .cs-arrow { transform: rotate(180deg); color: var(--accent); }
  .custom-select.disabled .cs-trigger { opacity: .5; cursor: not-allowed; }

  /* 宿主在组件内时无布局影响（面板 fixed 脱离文档流） */
  .cs-host { display: contents; }

  .cs-panel {
    position: fixed;                 /* 相对视口定位，脱离父级 overflow 裁剪 */
    z-index: 999999;                 /* 全站最高层级：高于 modal(1000)/toast(2000)/tooltip(3000) */
    left: 0;
    top: 0;
    max-height: 280px;
    overflow-y: auto;
    margin: 0;
    padding: 6px;
    list-style: none;
    background: var(--bg2);
    border: 1px solid var(--bd);
    border-radius: var(--radius);
    box-shadow: var(--shadow-md);
    animation: cs-in .15s ease-out;
  }
  @keyframes cs-in {
    from { opacity: 0; transform: translateY(-4px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .cs-option {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 8px 10px;
    border-radius: 6px;
    cursor: pointer;
    color: var(--text);
    font-size: 13px;
    transition: background .15s, color .15s;
  }
  .cs-option:hover:not(.disabled) { background: rgba(var(--accent-rgb), .12); }
  .cs-option.selected { background: rgba(var(--accent-rgb), .18); color: var(--accent); font-weight: 500; }
  .cs-option.disabled { opacity: .4; cursor: not-allowed; }
  .cs-option-label { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .cs-check { flex-shrink: 0; }
</style>
