<script>import { t as i18n } from '../lib/i18n.js';
  
  // 通用弹窗外壳：点击遮罩/Esc/右上角 X 关闭
  // 可访问性：role=dialog + aria-modal、焦点陷阱、打开自动聚焦、关闭后还原焦点
  import { onMount } from 'svelte';

  export let title = '';
  export let width = 760;
  export let onClose = () => {};
  export let closable = true;
  export let fitContent = false; // 内容自适应宽度（按内容伸缩，最小 minWidth，最大 width）
  export let minWidth = 0;       // fitContent 时的最小宽度（0=回退到 width）
  export let bodyClass = '';     // 追加到 .modal-body 的类名（用于无内边距的全幅布局）

  let modalEl;
  let prevFocus = null;
  // 每个弹窗实例唯一 ID，用于 aria-labelledby
  const uid = Math.random().toString(36).slice(2, 8);

  function onKeydown(e) {
    if (e.key === 'Escape' && closable) {
      onClose();
      return;
    }
    // Tab 焦点陷阱：循环限制在弹窗内
    if (e.key !== 'Tab' || !modalEl) return;
    const focusables = modalEl.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (focusables.length === 0) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  onMount(() => {
    prevFocus = document.activeElement;
    // 优先聚焦正文第一个可输入控件，避免焦点落在右上角关闭按钮上
    let f = modalEl && modalEl.querySelector(
      '.modal-body input:not([type="hidden"]):not([disabled]), .modal-body select:not([disabled]), .modal-body textarea:not([disabled])'
    );
    if (!f && modalEl) {
      f = modalEl.querySelector(
        '.modal-body button:not([disabled]), .modal-body [href], .modal-body [tabindex]:not([tabindex="-1"])'
      );
    }
    if (!f && modalEl) f = modalEl.querySelector('button:not([disabled]):not(.modal-close)');
    if (f) f.focus();
    else if (modalEl) modalEl.focus();
    return () => {
      // 关闭后还原焦点到触发元素
      if (prevFocus && typeof prevFocus.focus === 'function') prevFocus.focus();
    };
  });
</script>

<svelte:window on:keydown={onKeydown} />

<div
  class="modal-overlay"
  role="presentation"
  on:click={(e) => { if (e.target === e.currentTarget && closable) onClose(); }}
>
  <div
    class="modal"
    style="max-width:{width}px{fitContent ? ';width:max-content;min-width:' + (minWidth || width) + 'px' : ''}"
    role="dialog"
    aria-modal="true"
    aria-labelledby={title ? 'mh-' + uid : undefined}
    tabindex="-1"
    bind:this={modalEl}
  >
    {#if title}
      <div class="modal-hdr">
        <div class="modal-hdr-t">
          <h3 id="mh-{uid}">{title}</h3>
          <slot name="title-extra" />
        </div>
        {#if closable}
          <button class="modal-close" on:click={onClose} aria-label={$i18n("关闭")}>&times;</button>
        {/if}
      </div>
    {/if}
    <div class="modal-body {bodyClass}">
      <slot />
    </div>
    {#if $$slots.footer}
      <div class="modal-ftr">
        <slot name="footer" />
      </div>
    {/if}
  </div>
</div>

<style>
  /* 标题区（h3 + 可选 title-extra 内容）左对齐排列 */
  .modal-hdr-t{display:flex;align-items:center;gap:6px;min-width:0;flex:1}
  .modal-hdr-t h3{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
</style>
