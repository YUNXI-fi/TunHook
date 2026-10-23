<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 备份导出弹窗：全量备份 / 模块备份，支持加密方式选择（自动设备编号 / 手动密码 / 不加密）
  import Modal from './Modal.svelte';
  import { apiBase } from '../lib/api.js';
  import { toast } from '../lib/stores.js';

  export let onClose = () => {};
  export let full = true; // true=全量备份（模块固定全选，不可改）

  const allModules = [
    { id: 'settings', label: i18nTr("系统设置"), desc: i18nTr("默认参数、Webhook、IP 过滤、Hook 导航、错误页模板等") },
    { id: 'hook', label: i18nTr("自定义UI"), desc: i18nTr("导航页（/hook）壁纸、LOGO、搜索引擎、页脚、布局、统计条等") },
    { id: 'rules', label: i18nTr("转发规则"), desc: i18nTr("端口转发规则与描述") },
    { id: 'frpc', label: i18nTr("FRP 配置"), desc: i18nTr("FRP 服务器与代理通道") },
    { id: 'ipfilter', label: i18nTr("IP 过滤"), desc: i18nTr("自定义 / 白名单 / 拦截记录") },
    { id: 'dns', label: i18nTr("域名解析"), desc: i18nTr("DNS 账户与 DDNS 动态解析任务") },
    { id: 'cert', label: i18nTr("证书与ACME"), desc: i18nTr("证书库与 ACME 联系人邮箱") },
    { id: 'geo', label: i18nTr("地理数据源"), desc: i18nTr("IP 地址库数据源与已下载的 IP 段") },
    { id: 'icons', label: i18nTr("图标与桌面图标"), desc: i18nTr("导航页图标、桌面图标配置与图标文件") },
    { id: 'wh', label: i18nTr("Webhook 通道"), desc: i18nTr("统一网关 Webhook 通道记录") }
  ];

  let modules = allModules.map((m) => m.id);
  let encryption = 'auto'; // auto | password | none
  let password = '';
  let confirmPwd = '';
  let busy = false;
  let result = null; // 自动加密导出成功后展示 { password }

  function toggleModule(id) {
    if (full) return;
    modules = modules.includes(id) ? modules.filter((x) => x !== id) : [...modules, id];
  }

  async function copyAutoPassword() {
    if (!result || !result.password) return;
    try {
      await navigator.clipboard.writeText(result.password);
      toast(i18nTr("密码已复制"), 'success');
    } catch (e) {
      toast(i18nTr("复制失败，请手动选择复制"), 'error');
    }
  }

  async function doExport() {
    if (!full && modules.length === 0) {
      toast(i18nTr("请至少选择一个模块"), 'error');
      return;
    }
    if (encryption === 'password') {
      if (!password) {
        toast(i18nTr("请输入加密密码"), 'error');
        return;
      }
      if (password !== confirmPwd) {
        toast(i18nTr("两次输入的密码不一致"), 'error');
        return;
      }
    }
    busy = true;
    try {
      const resp = await fetch(apiBase + '/api/backup/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          modules: full ? [] : modules,
          encryption,
          password: encryption === 'password' ? password : ''
        })
      });
      if (!resp.ok) {
        let msg = i18nTr("导出失败: HTTP ") + resp.status;
        try {
          const d = await resp.json();
          if (d && d.error) msg = d.error;
        } catch (e) { /* ignore */ }
        toast(msg, 'error');
        return;
      }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'tunhook-backup-' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + '.zip';
      a.click();
      URL.revokeObjectURL(url);
      // 自动加密：读取响应头中的设备编号密码，展示给用户复制保存
      const pw = resp.headers.get('X-Backup-Password');
      if (pw) {
        result = { password: pw };
        return;
      }
      toast(i18nTr("备份已导出"), 'success');
      onClose();
    } catch (e) {
      toast(i18nTr("导出失败: ") + e.message, 'error');
    } finally {
      busy = false;
    }
  }
</script>

<Modal title={full ? i18nTr("全量备份") : i18nTr("模块备份")} width={520} onClose={onClose} closable={!busy}>
  {#if result}
    <div class="bk-success-tip">{$i18n("备份已加密导出，请保存以下自动加密密码（同一设备恢复时自动解密）：")}</div>
    <div class="bk-pwd-show">
      <input type="text" readonly value={result.password} style="font-family:var(--mono)" />
      <button class="btn" on:click={copyAutoPassword}>{$i18n("复制")}</button>
    </div>
    <div class="bk-tip">{$i18n("更换设备或重装系统后，需在恢复时手动输入该密码。")}</div>
  {:else}
    {#if !full}
      <div class="bk-title">{$i18n("选择备份模块")}</div>
      <div class="bk-mod-grid">
        {#each allModules as m}
          <label class="bk-mod-cell">
            <input type="checkbox" checked={modules.includes(m.id)} on:change={() => toggleModule(m.id)} />
            <span style="flex:1;min-width:0">
              <div class="bk-mod-label">{m.label}</div>
              <div class="bk-mod-desc">{m.desc}</div>
            </span>
          </label>
        {/each}
      </div>
    {/if}

    <div class="bk-title">{$i18n("备份加密")}</div>
    <div class="bk-enc-grid">
      <label class="bk-enc-cell">
        <input type="radio" bind:group={encryption} value="auto" />
        <span>{$i18n("自动加密")}</span>
      </label>
      <label class="bk-enc-cell">
        <input type="radio" bind:group={encryption} value="password" />
        <span>{$i18n("手动输入密码")}</span>
      </label>
      <label class="bk-enc-cell">
        <input type="radio" bind:group={encryption} value="none" />
        <span>{$i18n("不加密")}</span>
      </label>
    </div>

    {#if encryption === 'password'}
      <div class="bk-pwd-row">
        <input type="password" bind:value={password} placeholder={$i18n("设置加密密码")} />
        <input type="password" bind:value={confirmPwd} placeholder={$i18n("确认密码")} />
      </div>
      <div class="bk-tip">{$i18n("请牢记密码；恢复时需手动输入该密码解密。")}</div>
    {/if}
    {#if encryption === 'none'}
      <div class="bk-warn">{$i18n("备份文件包含访问密钥与证书私钥，不加密将以明文存储，任何获取文件的人都能读取，存在严重泄露风险！")}</div>
    {/if}
  {/if}

  <div slot="footer" style="display:flex;justify-content:flex-end;gap:8px">
    {#if result}
      <button class="btn btn-primary" on:click={onClose}>{$i18n("完成")}</button>
    {:else}
      <button class="btn" on:click={onClose} disabled={busy}>{$i18n("取消")}</button>
      <button class="btn btn-primary" on:click={doExport} disabled={busy}>{busy ? i18nTr("导出中…") : i18nTr("导出")}</button>
    {/if}
  </div>
</Modal>

<style>
  .bk-title {
    font-size: 12px; font-weight: 600; color: var(--text3);
    margin: 4px 0 8px; letter-spacing: .5px;
  }
  .bk-mod-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
    margin-bottom: 14px;
  }
  .bk-mod-cell {
    display: flex; align-items: center; gap: 8px;
    padding: 9px 11px;
    background: var(--bg4); border: 1px solid var(--bd);
    border-radius: var(--radius); cursor: pointer;
  }
  .bk-mod-cell:hover { border-color: var(--accent); }
  .bk-mod-label { font-size: 13px; color: var(--text); }
  .bk-mod-desc { font-size: 11px; color: var(--text3); margin-top: 2px; }
  .bk-enc-grid {
    display: flex; gap: 8px; flex-wrap: wrap;
  }
  .bk-enc-cell {
    display: flex; align-items: center; gap: 6px;
    padding: 8px 12px;
    background: var(--bg4); border: 1px solid var(--bd);
    border-radius: var(--radius); cursor: pointer; font-size: 13px; color: var(--text);
  }
  .bk-enc-cell:hover { border-color: var(--accent); }
  .bk-pwd-row {
    display: flex; gap: 10px; margin-top: 12px;
  }
  .bk-pwd-row input { flex: 1; min-width: 0; }
  .bk-tip {
    font-size: 12px; color: var(--text3); line-height: 1.7; margin-top: 10px;
  }
  .bk-warn {
    margin-top: 12px; padding: 10px 12px;
    font-size: 12px; line-height: 1.7; color: var(--yellow);
    background: rgba(var(--yellow-rgb), .08); border: 1px solid rgba(var(--yellow-rgb), .35);
    border-radius: var(--radius);
  }
  .bk-success-tip {
    font-size: 13px; color: var(--text2); line-height: 1.8; margin-bottom: 12px;
  }
  .bk-pwd-show {
    display: flex; gap: 8px;
  }
  .bk-pwd-show input {
    flex: 1; min-width: 0;
    padding: 8px 12px;
    border: 1px solid var(--bd); border-radius: var(--radius);
    background: var(--bg2); color: var(--accent);
    font-size: 13px; outline: none; transition: border-color .2s;
  }
  .bk-pwd-show input:focus {
    border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
  }
  @media (max-width: 600px) {
    .bk-mod-grid { grid-template-columns: 1fr; }
  }
</style>
