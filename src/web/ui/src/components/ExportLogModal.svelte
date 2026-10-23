<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 导出系统日志弹窗：全部/通道/访问日志，TXT/JSON/CSV 格式
  import Modal from './Modal.svelte';
  import CustomSelect from './CustomSelect.svelte';
  import { api } from '../lib/api.js';
  import { toast } from '../lib/stores.js';

  const moduleOptions = [
    { value: '', label: i18nTr("全部日志") },
    { value: 'system', label: i18nTr("系统日志") },
    { value: 'channel', label: i18nTr("通道日志") },
    { value: 'access', label: i18nTr("访问日志") }
  ];
  const formatOptions = [
    { value: 'txt', label: i18nTr("TXT（纯文本）") },
    { value: 'json', label: 'JSON' },
    { value: 'csv', label: 'CSV' }
  ];

  export let onClose = () => {};

  let module = '';
  let format = 'txt';
  let exporting = false;

  async function doExport() {
    exporting = true;
    try {
      const q = new URLSearchParams({ page: 1, pageSize: 100000 });
      if (module) q.set('category', module);
      const d = await api('/api/logs?' + q.toString());
      // 接口按新→旧倒序返回，导出文件保持时间正序（旧→新）
      const entries = ((d && d.entries) || []).slice().reverse();
      let content = '';
      let mime = 'text/plain';
      let ext = 'txt';
      if (format === 'json') {
        content = JSON.stringify(entries, null, 2);
        mime = 'application/json';
        ext = 'json';
      } else if (format === 'csv') {
        content = 'level,time,message\n' + entries.map((e) => `"${e.level}","${e.time}","${(e.message || '').replace(/"/g, '""')}"`).join('\n');
        mime = 'text/csv';
        ext = 'csv';
      } else {
        content = entries.map((e) => `[${e.time}] [${e.level}] ${e.message}`).join('\n');
      }
      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `tunhook-logs-${module || 'all'}-${Date.now()}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
      toast(i18nTr("已导出 {0} 条日志", [entries.length]), 'success');
      onClose();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      exporting = false;
    }
  }
</script>

<Modal title={$i18n("导出系统日志")} onClose={onClose} width={480}>
  <div class="form-group">
    <label class="form-label">{$i18n("日志模块")}</label>
    <CustomSelect bind:value={module} options={moduleOptions} />
  </div>
  <div class="form-group">
    <label class="form-label">{$i18n("导出格式")}</label>
    <CustomSelect bind:value={format} options={formatOptions} />
  </div>
  <div slot="footer">
    <button class="btn" on:click={onClose}>{$i18n("取消")}</button>
    <button class="btn btn-primary" on:click={doExport} disabled={exporting}>{exporting ? i18nTr("导出中...") : i18nTr("导出")}</button>
  </div>
</Modal>
