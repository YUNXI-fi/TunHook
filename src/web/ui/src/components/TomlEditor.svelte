<script>
  // TOML 语法高亮编辑器（frpc.toml 配置编辑用）：透明 textarea + 高亮覆盖层
  import { createEventDispatcher } from 'svelte';

  export let value = '';
  export let placeholder = '';
  export let minHeight = '130px';
  export let maxHeight = '320px';

  const dispatch = createEventDispatcher();

  function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // 单遍交替匹配高亮主语法（字符串先吞掉其中的 [ # 数字等，避免误着色）
  function hlMain(s) {
    return escapeHtml(s).replace(
      /(&quot;(?:[^&\n]|&(?!quot;))*?&quot;|&#39;(?:[^&\n]|&(?!&#39;))*?&#39;)|(\[\[?[^\]]*\]\]?)|(^[ \t]*[A-Za-z0-9_.-]+[ \t]*(?==))|(\btrue\b|\bfalse\b)|(\b\d+(?:\.\d+)?\b)/gm,
      (m, str, hdr, key, bool, num) => {
        if (str) return '<span class="tl-s">' + str + '</span>';
        if (hdr) return '<span class="tl-h">' + hdr + '</span>';
        if (key) return '<span class="tl-k">' + key + '</span>';
        if (bool) return '<span class="tl-b">' + bool + '</span>';
        if (num) return '<span class="tl-n">' + num + '</span>';
        return m;
      }
    );
  }

  // 逐行高亮：先分离注释（字符串内的 # 不视为注释），再高亮主语法
  function highlightToml(code) {
    return String(code || '').split('\n').map((line) => {
      let inStr = '';
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (inStr) {
          if (ch === inStr) inStr = '';
          continue;
        }
        if (ch === '"' || ch === "'") {
          inStr = ch;
          continue;
        }
        if (ch === '#') {
          return hlMain(line.slice(0, i)) + '<span class="tl-c">' + escapeHtml(line.slice(i)) + '</span>';
        }
      }
      return hlMain(line);
    }).join('\n');
  }

  // 编辑区滚动时同步高亮层
  function onScroll(e) {
    const pre = e.currentTarget.parentElement.querySelector('.toml-hl');
    if (pre) {
      pre.scrollTop = e.currentTarget.scrollTop;
      pre.scrollLeft = e.currentTarget.scrollLeft;
    }
  }

  // 转发 input 事件（父组件用于粘贴解析回填等）
  function onInput() {
    dispatch('input');
  }
</script>

<div class="toml-editor" style="min-height:{minHeight};max-height:{maxHeight}">
  <pre class="toml-hl" aria-hidden="true">{@html highlightToml(value) + '\n'}</pre>
  <textarea bind:value on:input={onInput} on:scroll={onScroll} spellcheck="false" placeholder={placeholder}></textarea>
</div>

<style>
  .toml-editor {
    position: relative;
    border: 1px solid var(--bd);
    border-radius: var(--radius);
    background: var(--bg4);
    overflow: hidden;
    resize: vertical;
  }
  .toml-editor pre,
  .toml-editor textarea {
    margin: 0;
    padding: 10px;
    font-family: var(--mono);
    font-size: 12px;
    line-height: 1.55;
    white-space: pre;
    word-break: normal;
    box-sizing: border-box;
    tab-size: 2;
    min-height: inherit;
    max-height: inherit;
  }
  .toml-editor pre {
    overflow: hidden;
    /* 基础文字用主题色：未命中高亮的字符（输入中的残缺 TOML、空格）也始终可见 */
    color: var(--text);
    background: var(--bg4);
  }
  .toml-editor textarea {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    background: transparent;
    color: transparent;
    caret-color: var(--text);
    border: none;
    outline: none;
    overflow: auto;
  }
  .toml-editor textarea::placeholder {
    color: var(--text3);
    opacity: 1;
  }
  /* TOML 语法高亮配色（@html 注入的 span 无组件作用域类，需用 :global 命中） */
  :global(.tl-k) { color: #7dd3fc; }  /* 键名 */
  :global(.tl-s) { color: #86efac; }  /* 字符串 */
  :global(.tl-n) { color: #fdba74; }  /* 数字 */
  :global(.tl-b) { color: #fca5a5; }  /* 布尔 */
  :global(.tl-h) { color: #c4b5fd; }  /* 表头 */
  :global(.tl-c) { color: #64748b; }  /* 注释 */
  /* 亮色主题下改用深色高亮，保证对比度（html[data-theme=light] 由 App 切换）。
     编辑器底色是内层 bg4，故取语义色 token —— 它们对 bg4 与同色相淡底都已按 ≥4.5:1 标定 */
  :global([data-theme="light"] .tl-k) { color: var(--cyan); }
  :global([data-theme="light"] .tl-s) { color: var(--green); }
  :global([data-theme="light"] .tl-n) { color: var(--orange); }
  :global([data-theme="light"] .tl-b) { color: var(--red); }
  :global([data-theme="light"] .tl-h) { color: var(--violet); }
  :global([data-theme="light"] .tl-c) { color: var(--slate); }
</style>
