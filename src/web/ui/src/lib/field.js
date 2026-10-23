// 字段校验 action + 提交前统一拦截
// 用法：
//   <input use:field={{ check: validateIPv4 }} bind:value={...} />
//   输入位于横向 flex 行时，可用 errAt 把错误渲染到指定元素：
//   <input use:field={{ check, errAt: () => errNode }} />
//   提交时：if (!validateAll(formEl)) return;
// 交互策略：首次失焦前不报错（避免输入第一个字符就被打断）；失焦后输入即实时校验；
// 错误信息以输入框下方 .field-err 红字展示，不弹窗、不阻断输入。

const registry = new WeakMap(); // node -> { check, touched, errEl, errAt }

// 渲染/清除某输入框的错误状态
function showError(node, msg) {
  const cfg = registry.get(node);
  if (!cfg) return;
  node.classList.toggle('input-err', !!msg);
  node.setAttribute('aria-invalid', msg ? 'true' : 'false');
  // errAt 指定外部错误容器（由调用方在模板中放置），否则在输入框后自动创建
  const external = typeof cfg.errAt === 'function' ? cfg.errAt() : null;
  if (external) {
    external.textContent = msg || '';
    external.style.display = msg ? '' : 'none';
    return;
  }
  if (!cfg.errEl) {
    const el = document.createElement('div');
    el.className = 'field-err';
    node.parentNode.insertBefore(el, node.nextSibling);
    cfg.errEl = el;
  }
  cfg.errEl.textContent = msg || '';
  cfg.errEl.style.display = msg ? '' : 'none';
}

// Svelte action：params.check 为校验函数（返回错误提示串，'' 表示合法）
export function field(node, params = {}) {
  const cfg = { check: params.check || (() => ''), touched: false, errEl: null, errAt: params.errAt || null };
  registry.set(node, cfg);

  const onInput = () => {
    const cur = registry.get(node);
    if (cur.touched) showError(node, cur.check(node.value));
  };
  const onBlur = () => {
    const cur = registry.get(node);
    cur.touched = true;
    showError(node, cur.check(node.value));
  };
  node.addEventListener('input', onInput);
  node.addEventListener('blur', onBlur);

  return {
    update(p = {}) {
      const cur = registry.get(node);
      if (p.check) cur.check = p.check;
      if (p.errAt !== undefined) cur.errAt = p.errAt;
      if (cur.touched) showError(node, cur.check(node.value));
    },
    destroy() {
      const cur = registry.get(node);
      node.removeEventListener('input', onInput);
      node.removeEventListener('blur', onBlur);
      if (cur && cur.errEl) cur.errEl.remove();
      registry.delete(node);
    }
  };
}

// 提交前统一校验容器内所有已注册字段。
// 全部合法返回 true；有错误时标记全部错误字段、滚动并聚焦第一个，返回 false。
export function validateAll(container) {
  let first = null;
  for (const node of container.querySelectorAll('input, textarea')) {
    const cfg = registry.get(node);
    if (!cfg || node.disabled) continue;
    if (node.type === 'hidden' || node.type === 'file' || node.type === 'submit') continue;
    const msg = cfg.check(node.value);
    cfg.touched = true;
    showError(node, msg);
    if (msg && !first) first = node;
  }
  if (first) {
    const target = first.closest('.form-group') || first;
    if (typeof target.scrollIntoView === 'function') {
      target.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
    first.focus();
    return false;
  }
  return true;
}
