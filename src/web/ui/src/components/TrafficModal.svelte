<script>import { t as i18n } from '../lib/i18n.js';
  
  // 流量详情弹窗：累计流量 + 客户端列表
  import Modal from './Modal.svelte';
  import { fmtBytes, fmtRate } from '../lib/utils.js';

  export let item = null;
  export let kind = 'tunnel';
  export let onClose = () => {};

  $: totalTx = item ? (item.tx_bytes || 0) : 0;
  $: totalRx = item ? (item.rx_bytes || 0) : 0;
  $: clients = (item && item.clients) || [];
</script>

<Modal title={$i18n("流量详情")} onClose={onClose} width={720}>
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
      <div class="stat-num">{clients.length}</div>
      <div class="stat-label">{$i18n("客户端数")}</div>
    </div>
  </div>

  <div class="table-wrap" style="max-height:40vh;overflow-y:auto">
    <table>
      <thead>
        <tr><th>{$i18n("客户端地址")}</th><th>{$i18n("归属地")}</th><th>{$i18n("上行速率")}</th><th>{$i18n("下行速率")}</th><th>{$i18n("累计上行")}</th><th>{$i18n("累计下行")}</th></tr>
      </thead>
      <tbody>
        {#each clients as c}
          <tr>
            <td class="cell-mono">{c.addr}</td>
            <td>{c.location || '-'}</td>
            <td class="cell-mono">{fmtRate(c.tx_rate || 0)}</td>
            <td class="cell-mono">{fmtRate(c.rx_rate || 0)}</td>
            <td class="cell-mono">{fmtBytes(c.tx_bytes || 0)}</td>
            <td class="cell-mono">{fmtBytes(c.rx_bytes || 0)}</td>
          </tr>
        {:else}
          <tr><td colspan="6" style="text-align:center;color:var(--text3);padding:20px 0">{$i18n("暂无连接客户端")}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</Modal>
