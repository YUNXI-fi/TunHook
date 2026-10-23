<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 新增/编辑解析记录弹窗：类型 / 主机记录 / 记录值 / TTL。
  // 「动态解析」按钮弹出子弹窗，列出各网卡的 V4/V6 地址供选择；选择后绑定记录并启用动态解析（IP 变动自动更新记录值）。
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';
  import Modal from './Modal.svelte';
  import CustomSelect from './CustomSelect.svelte';
  import { validateIPv4, validateIPv6, validateDomain, validateRecordName } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';

  export let account = '';
  export let domain = '';
  export let record = null; // 编辑时传入记录对象，新增为 null
  export let onClose = () => {};
  export let onSaved = () => {};

  let rType = 'A';
  let rRR = '@';
  let rValue = '';
  let rTTL = 600;

  // 动态解析子弹窗
  let showSrc = false;
  let srcKind = 'public'; // public | local
  let pubV4 = '';
  let pubV6 = '';
  let ifaces = [];        // 本机网卡列表
  let selIface = '';      // 选中的网卡名
  let selMode = 'v4';     // v4 | v6
  let srcBusy = false;    // 加载中
  let bound = null;       // 已选动态解析来源 { ip_src, iface, type }
  let formEl;             // 表单行容器，提交时对其内部字段统一校验

  const REC_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'NS', 'SRV', 'CAA'];
  const recTypeOptions = REC_TYPES.map((t) => ({ value: t, label: t }));

  // 记录值按所选类型切换校验：A=IPv4，AAAA=IPv6，CNAME=域名；其余类型不做地址类格式校验
  $: valueCheck = (() => {
    switch (rType) {
      case 'A': return validateIPv4;
      case 'AAAA': return validateIPv6;
      case 'CNAME': return validateDomain;
      default: return () => '';
    }
  })();

  onMount(() => {
    if (record) {
      rType = record.type || 'A';
      rRR = record.name === '@' ? '@' : (record.name || '@');
      rValue = record.value || '';
      rTTL = record.ttl || 600;
    }
  });

  async function submit() {
    // 格式校验：主机记录名/记录值非法时就地提示并拦截
    if (!validateAll(formEl)) return;
    if (!account || !domain) { toast(i18nTr("请先选择账户与域名"), 'error'); return; }
    if (!rValue.trim()) { toast(i18nTr("请填写记录值"), 'error'); return; }
    try {
      // 已绑定动态解析来源：走 record-bind（写记录 + 创建/更新动态任务）
      if (bound) {
        await api('/api/ddns/record-bind', {
          method: 'POST',
          body: {
            account, domain, rr: rRR, type: bound.type, ttl: Number(rTTL) || 600,
            ip_src: bound.ip_src, iface: bound.iface,
            record_id: record ? record.id : ''
          }
        });
        toast(i18nTr("记录已添加并启用动态解析"), 'success');
      } else if (record) {
        await api('/api/dns/record/update', {
          method: 'POST',
          body: { account, domain, id: record.id, rr: rRR, type: rType, value: rValue, ttl: Number(rTTL) || 600 }
        });
        toast(i18nTr("记录已更新"), 'success');
      } else {
        await api('/api/dns/record/add', {
          method: 'POST',
          body: { account, domain, rr: rRR, type: rType, value: rValue, ttl: Number(rTTL) || 600 }
        });
        toast(i18nTr("记录已添加"), 'success');
      }
      onSaved && onSaved();
      onClose();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  // 当前选中的来源地址
  function chosenAddr() {
    if (srcKind === 'public') {
      return selMode === 'v6' ? pubV6 : pubV4;
    }
    const f = ifaces.find((i) => i.name === selIface);
    if (!f) return '';
    return selMode === 'v6' ? (f.ipv6 || '') : (f.ipv4 || '');
  }

  // 地址来源选择：鼠标点击与键盘触发共用同一入口，避免同一逻辑写两份
  function pickPublic(mode) {
    srcKind = 'public';
    if (mode) selMode = mode;
  }
  function pickLocal(name, mode) {
    srcKind = 'local';
    selIface = name;
    if (mode) selMode = mode;
  }
  // 可点击卡片需支持键盘操作：Enter/Space 等价于点击（Space 需阻止页面滚动）
  function onTileKey(e, act) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      e.stopPropagation();
      act();
    }
  }

  // 打开动态解析弹窗，加载公网 + 本机网卡
  async function openSrc() {
    showSrc = true;
    srcBusy = true;
    try {
      const [pub, ifs] = await Promise.all([
        api('/api/network/public?refresh=1').catch(() => null),
        api('/api/network/interfaces').catch(() => [])
      ]);
      pubV4 = (pub && pub.ipv4) || '';
      pubV6 = (pub && pub.ipv6) || '';
      ifaces = ifs || [];
      const firstWith = ifaces.find((i) => i.ipv4 || i.ipv6);
      if (firstWith) selIface = firstWith.name;
      selMode = rType === 'AAAA' ? 'v6' : 'v4';
    } finally {
      srcBusy = false;
    }
  }

  // 应用：把所选来源回填到记录值，返回「添加解析记录」弹窗（由用户点「添加记录」真正提交）
  function applySrc() {
    if (!account || !domain) { toast(i18nTr("请先选择账户与域名"), 'error'); return; }
    const addr = chosenAddr();
    if (!addr) { toast(i18nTr("当前来源无 ") + (selMode === 'v6' ? 'V6' : 'V4') + i18nTr(" 地址"), 'error'); return; }
    const type = selMode === 'v6' ? 'AAAA' : 'A';
    // 记录来源，供提交时走动态解析
    bound = { ip_src: srcKind === 'local' ? 'local' : 'public', iface: srcKind === 'local' ? selIface : '', type };
    // 回填记录值与类型
    rType = type;
    rValue = addr;
    showSrc = false;
    toast(i18nTr("已选择地址 ") + addr + i18nTr("，请点击「添加记录」提交并启用动态解析"), 'success');
  }
</script>

<Modal title={record ? i18nTr("编辑解析记录") : i18nTr("添加解析记录")} onClose={onClose} width={560}>
  <div class="form-row" bind:this={formEl}>
    <div class="form-group" style="margin-bottom:0">
      <label class="form-label" for="rec-type">{$i18n("类型")}</label>
      <CustomSelect id="rec-type" bind:value={rType} options={recTypeOptions} width="90px" />
    </div>
    <div class="form-group" style="margin-bottom:0">
      <label class="form-label" for="rec-rr">{$i18n("主机记录")}</label>
      <input id="rec-rr" type="text" bind:value={rRR} placeholder={$i18n("@ 表示根记录")} style="width:110px" use:field={{ check: validateRecordName }} />
    </div>
    <div class="form-group" style="margin-bottom:0;flex:1;min-width:180px">
      <label class="form-label" for="rec-value">{$i18n("记录值")}</label>
      <input id="rec-value" type="text" bind:value={rValue} placeholder={$i18n("如 IP 地址（A/AAAA）或目标域名（CNAME）")} use:field={{ check: valueCheck }} />
    </div>
    <div class="form-group" style="margin-bottom:0">
      <label class="form-label" for="rec-ttl">TTL</label>
      <input id="rec-ttl" type="number" bind:value={rTTL} min="1" style="width:90px" />
    </div>
  </div>
  <div class="tip-text" style="margin-top:10px">{$i18n("域名为「")}{domain}{$i18n("」，账户「")}{account}」。</div>
  <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
    <button class="btn" on:click={openSrc}>{$i18n("动态解析")}</button>
    <button class="btn" on:click={onClose}>{$i18n("取消")}</button>
    <button class="btn btn-primary" on:click={submit}>{record ? i18nTr("保存修改") : i18nTr("添加记录")}</button>
  </div>
</Modal>

{#if showSrc}
  <Modal title={$i18n("动态解析")} onClose={() => (showSrc = false)} width={520}>
    <div class="tip-text" style="margin-bottom:12px">{$i18n("选择地址来源（公网 IP 或本机网卡地址）作为解析记录值，IP 变动时自动更新解析记录。")}</div>
    {#if srcBusy}
      <div style="font-size:13px;color:var(--text3);padding:20px 0;text-align:center">{$i18n("加载地址中...")}</div>
    {:else}
      <div style="display:flex;flex-direction:column;gap:10px;max-height:46vh;overflow-y:auto">
        <!-- 公网 IP -->
        <div style="border:1px solid {srcKind === 'public' ? 'var(--accent)' : 'var(--bd)'};border-radius:var(--radius);padding:12px;background:var(--bg3);cursor:pointer;transition:border-color .15s ease" role="button" tabindex="0" on:click={() => pickPublic()} on:keydown={(e) => onTileKey(e, () => pickPublic())}>
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <span style="font-size:13px;font-weight:600;color:var(--text)">{$i18n("公网 IP")}</span>
            <span style="margin-left:auto;font-size:12px;color:var(--text3)">{$i18n("点击选择")}</span>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
            <div style="padding:8px;border-radius:var(--radius);background:{srcKind === 'public' && selMode === 'v4' ? 'rgba(var(--accent-rgb),.12)' : 'var(--bg4)'};border:1px solid {srcKind === 'public' && selMode === 'v4' ? 'var(--accent)' : 'var(--bd)'}" role="button" tabindex="0" on:click={(e) => { e.stopPropagation(); pickPublic('v4'); }} on:keydown={(e) => onTileKey(e, () => pickPublic('v4'))}>
              <div style="font-size:11px;color:var(--text3);margin-bottom:4px">{$i18n("V4 地址")}</div>
              <div style="font-size:12px;font-family:var(--mono);word-break:break-all">{pubV4 || i18nTr("（无）")}</div>
            </div>
            <div style="padding:8px;border-radius:var(--radius);background:{srcKind === 'public' && selMode === 'v6' ? 'rgba(var(--accent-rgb),.12)' : 'var(--bg4)'};border:1px solid {srcKind === 'public' && selMode === 'v6' ? 'var(--accent)' : 'var(--bd)'}" role="button" tabindex="0" on:click={(e) => { e.stopPropagation(); pickPublic('v6'); }} on:keydown={(e) => onTileKey(e, () => pickPublic('v6'))}>
              <div style="font-size:11px;color:var(--text3);margin-bottom:4px">{$i18n("V6 地址")}</div>
              <div style="font-size:12px;font-family:var(--mono);word-break:break-all">{pubV6 || i18nTr("（无）")}</div>
            </div>
          </div>
        </div>

        <!-- 本机网卡列表 -->
        {#each ifaces as ifc}
          <div style="border:1px solid {srcKind === 'local' && selIface === ifc.name ? 'var(--accent)' : 'var(--bd)'};border-radius:var(--radius);padding:12px;background:var(--bg3);cursor:pointer;transition:border-color .15s ease" role="button" tabindex="0" on:click={() => pickLocal(ifc.name)} on:keydown={(e) => onTileKey(e, () => pickLocal(ifc.name))}>
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
              <span style="font-size:13px;font-weight:600;color:var(--text)">{ifc.label || ifc.name}</span>
              <span style="margin-left:auto;font-size:12px;color:var(--text3)">{$i18n("点击选择")}</span>
            </div>
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:11px;color:var(--text3)">
              <span style="font-family:var(--mono)">{ifc.name}</span>
              {#if ifc.mac}<span style="font-family:var(--mono)">{ifc.mac}</span>{/if}
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
              <div style="padding:8px;border-radius:var(--radius);background:{srcKind === 'local' && selIface === ifc.name && selMode === 'v4' ? 'rgba(var(--accent-rgb),.12)' : 'var(--bg4)'};border:1px solid {srcKind === 'local' && selIface === ifc.name && selMode === 'v4' ? 'var(--accent)' : 'var(--bd)'}" role="button" tabindex="0" on:click={(e) => { e.stopPropagation(); pickLocal(ifc.name, 'v4'); }} on:keydown={(e) => onTileKey(e, () => pickLocal(ifc.name, 'v4'))}>
                <div style="font-size:11px;color:var(--text3);margin-bottom:4px">{$i18n("V4 地址")}</div>
                <div style="font-size:12px;font-family:var(--mono);word-break:break-all">{ifc.ipv4 || i18nTr("（无）")}</div>
              </div>
              <div style="padding:8px;border-radius:var(--radius);background:{srcKind === 'local' && selIface === ifc.name && selMode === 'v6' ? 'rgba(var(--accent-rgb),.12)' : 'var(--bg4)'};border:1px solid {srcKind === 'local' && selIface === ifc.name && selMode === 'v6' ? 'var(--accent)' : 'var(--bd)'}" role="button" tabindex="0" on:click={(e) => { e.stopPropagation(); pickLocal(ifc.name, 'v6'); }} on:keydown={(e) => onTileKey(e, () => pickLocal(ifc.name, 'v6'))}>
                <div style="font-size:11px;color:var(--text3);margin-bottom:4px">{$i18n("V6 地址")}</div>
                <div style="font-size:12px;font-family:var(--mono);word-break:break-all">{ifc.ipv6 || i18nTr("（无）")}</div>
              </div>
            </div>
          </div>
        {/each}

        {#if !ifaces.length && !pubV4 && !pubV6}
          <div style="font-size:13px;color:var(--text3);padding:20px 0;text-align:center">{$i18n("未发现可用的地址")}</div>
        {/if}
      </div>
    {/if}
    <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
      <button class="btn" on:click={() => (showSrc = false)}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={applySrc} disabled={srcBusy || !chosenAddr()}>{$i18n("应用并启用动态解析")}</button>
    </div>
  </Modal>
{/if}
