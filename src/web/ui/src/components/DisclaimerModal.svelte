<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 首次使用强制弹窗：使用免责声明
  // closable=false：无 ×、Esc/点遮罩均不可关闭；同意按钮强制停留 5 秒后才可点击
  import { onMount, onDestroy } from 'svelte';
  import Modal from './Modal.svelte';

  export let onAgree = () => {};

  const STAY_SECONDS = 5;
  let countdown = STAY_SECONDS;
  let timer = null;

  onMount(() => {
    timer = setInterval(() => {
      countdown -= 1;
      if (countdown <= 0) {
        clearInterval(timer);
        timer = null;
      }
    }, 1000);
  });
  onDestroy(() => timer && clearInterval(timer));
</script>

<Modal title={$i18n("使用免责声明")} onClose={() => {}} closable={false} width={560}>
  <div class="dc-tip">{$i18n("请仔细阅读以下条款，使用本软件即视为同意并遵守本声明。")}</div>
  <div class="dc-body">
    <p>{$i18n("1. 本软件仅用于合法的网络调试、个人设备远程访问及学习研究等正当用途，禁止用于任何违反中华人民共和国法律法规及当地法律的活动，包括但不限于：未经授权的系统入侵、绕过访问控制、侵犯他人隐私、传播恶意内容等。")}</p>
    <p>{$i18n("2. 用户应对使用本软件产生的全部行为及后果自行承担责任。因使用本软件导致的任何直接或间接损失（包括但不限于数据丢失、服务中断、财产损失、法律纠纷等），开发者不承担任何责任。")}</p>
    <p>{$i18n("3. 本软件按\"现状\"提供，不附带任何明示或暗示的担保。开发者不保证软件的准确性、完整性、稳定性或无差错性，亦不对软件的适用性作任何承诺。")}</p>
    <p>{$i18n("4. 通过本软件对外开放的网络服务，请务必采取必要的安全措施（如强密码、访问控制、及时更新补丁等）。因配置不当导致的任何安全问题由用户自行负责。")}</p>
    <p>{$i18n("5. 本声明可能随软件版本更新而调整，更新后的声明将在\"关于\"页面公布，恕不另行通知。")}</p>
  </div>
  <div slot="footer" style="display:flex;justify-content:flex-end;width:100%">
    <button class="btn btn-primary" disabled={countdown > 0} on:click={onAgree}>
      {countdown > 0 ? i18nTr("我已阅读并同意（{0}s）", [countdown]) : i18nTr("我已阅读并同意")}
    </button>
  </div>
</Modal>

<style>
  .dc-tip {
    background: rgba(var(--yellow-rgb), .08);
    border: 1px solid rgba(var(--yellow-rgb), .3);
    color: var(--yellow);
    border-radius: var(--radius);
    padding: 10px 14px;
    font-size: 12.5px;
    line-height: 1.7;
    margin-bottom: 12px;
  }
  .dc-body {
    max-height: 52vh;
    overflow-y: auto;
    padding-right: 6px;
  }
  .dc-body p {
    font-size: 13px;
    color: var(--text2);
    line-height: 1.9;
    margin: 0 0 10px;
  }
  .dc-body p:last-child {
    margin-bottom: 0;
  }
</style>
