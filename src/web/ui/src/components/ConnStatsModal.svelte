<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 连接统计弹窗：展示代理的当前活跃连接（frpc 转发连接，断开即消失），
  // 每行关联访客真实 IP/端口 与连接累计流量。
  import { onMount, onDestroy } from 'svelte';
  import Modal from './Modal.svelte';
  import InfoTip from './InfoTip.svelte';
  import { api } from '../lib/api.js';
  import { fmtBytes, pollVisible } from '../lib/utils.js';

  export let proxy = null;
  export let onClose = () => {};

  let detail = [];    // [{visitor_ip, visitor_port, rx, tx}]
  let connCount = 0;  // 当前活跃连接数
  let cumulative = null; // {rx, tx} 代理累计流量（持久化，无连接也保留）
  let loading = true;
  let timer = null;

  $: totalRx = cumulative ? cumulative.rx : detail.reduce((s, c) => s + (c.rx > 0 ? c.rx : 0), 0);
  $: totalTx = cumulative ? cumulative.tx : detail.reduce((s, c) => s + (c.tx > 0 ? c.tx : 0), 0);

  // 过滤本机回环地址（127.0.0.1 / ::1）关联的连接，只展示外部访客
  function isLoopback(ip) {
    return ip === '::1' || (ip && ip.indexOf('127.') === 0);
  }

  async function load() {
    try {
      const d = await api('/api/frpc/conns?detail=1');
      const name = proxy ? proxy.name : '';
      detail = ((d && d.detail && d.detail[name]) || []).filter((c) => !isLoopback(c.visitor_ip));
      connCount = (d && d.conns && d.conns[name]) || 0;
      cumulative = (d && d.cumulative && d.cumulative[name]) || null;
    } catch (e) {
      /* 静默：保持上一次数据 */
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    load();
    timer = pollVisible(load, 3000);
  });
  onDestroy(() => timer && timer());
</script>

<Modal title={$i18n("流量详情")} onClose={onClose} width={720}>
  <div slot="title-extra">
    <InfoTip size={14} text={$i18n("列表为当前活跃的 frpc 转发连接（连接断开后自动消失，已过滤本机回环地址）。访客IP 来自 X-Real-IP / X-Forwarded-For（真实公网 IP）；普通 TCP/UDP 转发链路无法得知访客 IP，显示为 -。累计上下行为该代理的历史累计流量（持久化，无连接时也保留）；下方表格为各连接自建立以来的累计值。")} />
  </div>
  <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:16px">
    <div class="stat-card">
      <div class="stat-num">{fmtBytes(totalTx)}</div>
      <div class="stat-label">{$i18n("累计上行")}</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">{fmtBytes(totalRx)}</div>
      <div class="stat-label">{$i18n("累计下行")}</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">{connCount}</div>
      <div class="stat-label">{$i18n("当前连接数")}</div>
    </div>
  </div>

  {#if loading}
    <div style="text-align:center;padding:30px 0;color:var(--text3);font-size:13px">{$i18n("加载中...")}</div>
  {:else if detail.length === 0}
    <div style="text-align:center;padding:30px 0;color:var(--text3);font-size:13px">
      {connCount > 0 ? i18nTr("暂无活跃连接详情（外部访客）") : i18nTr("当前无活跃连接，有外部访问时自动显示")}
    </div>
  {:else}
    <div class="table-wrap" style="max-height:40vh;overflow-y:auto">
      <table>
        <thead>
          <tr>
            <th>{$i18n("访客IP")}</th>
            <th style="width:100px">{$i18n("累计下行")}</th>
            <th style="width:100px">{$i18n("累计上行")}</th>
            <th style="width:110px">{$i18n("合计")}</th>
          </tr>
        </thead>
        <tbody>
          {#each detail as c}
            <tr>
              <td class="cell-mono" style="color:var(--accent);font-weight:600">{c.visitor_ip}</td>
              <td class="cell-mono">{c.rx >= 0 ? fmtBytes(c.rx) : '-'}</td>
              <td class="cell-mono">{c.tx >= 0 ? fmtBytes(c.tx) : '-'}</td>
              <td class="cell-mono" style="font-weight:600">{c.rx >= 0 && c.tx >= 0 ? fmtBytes(c.rx + c.tx) : '-'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <div slot="footer">
    <button class="btn" on:click={onClose}>{$i18n("关闭")}</button>
  </div>
</Modal>
