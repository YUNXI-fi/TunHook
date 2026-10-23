<script>import { t as i18n, tr as i18nTr } from '../lib/i18n.js';
  
  // 添加服务器弹窗：服务器名称（必填，唯一）＋ 可选地址/端口/令牌
  import { onMount } from 'svelte';
  import Modal from './Modal.svelte';
  import TomlEditor from './TomlEditor.svelte';
  import { optional, validateHost, validatePort } from '../lib/utils.js';
  import { field, validateAll } from '../lib/field.js';

  export let onClose = () => {};
  export let onConfirm = () => {};
  export let busy = false;
  // 已有服务器名称列表（用于重名校验）
  export let exists = [];

  let name = '';
  let addr = '';
  let port = 7000;
  let token = '';
  // 配置文件区：默认显示，与上方输入框双向同步（粘贴解析回填 / 上方编辑同步到配置）
  let rawConfig = '';
  let syncing = false; // 防止双向同步死循环
  let formEl; // 表单容器，提交时对其内部字段统一校验

  // 已存在名称实时提示
  $: nameTaken = exists.includes(name.trim());
  $: errMsg = nameTaken ? i18nTr("该名称已被占用，请更换一个唯一名称") : '';

  // 粘贴/修改配置 → 解析 serverAddr/serverPort/auth.token 回填上方输入框
  function onConfigInput() {
    if (syncing) return;
    const mAddr = rawConfig.match(/^\s*serverAddr\s*=\s*["']([^"']+)["']/m);
    const mPort = rawConfig.match(/^\s*serverPort\s*=\s*(\d+)/m);
    const mTok = rawConfig.match(/^\s*auth\.token\s*=\s*["']([^"']*)["']/m);
    if (mAddr) addr = mAddr[1];
    if (mPort) port = Number(mPort[1]) || 7000;
    if (mTok) token = mTok[1];
  }

  // 上方输入框编辑 → 同步更新配置文件对应行（不存在则追加到 auth 区前）
  function syncLine(pattern, value) {
    if (syncing) return;
    syncing = true;
    const re = new RegExp('^(\\s*' + pattern + '\\s*=\\s*).*$', 'm');
    const line = pattern + ' = ' + (typeof value === 'number' ? value : '"' + value + '"');
    if (re.test(rawConfig)) {
      rawConfig = rawConfig.replace(re, '$1' + (typeof value === 'number' ? value : '"' + value + '"'));
    } else if (value !== '' && value !== 7000) {
      // 未配置对应行时追加到顶部（TOML 顶层键需在表之前）
      rawConfig = line + '\n' + rawConfig;
    }
    syncing = false;
  }

  function submit() {
    // 格式校验：地址/端口非法时就地提示并拦截（地址允许留空，端口同步留空，提交回退默认 7000）
    if (!validateAll(formEl)) return;
    const n = name.trim();
    if (!n) {
      errMsg = i18nTr("请填写服务器名称");
      return;
    }
    if (nameTaken) return;
    if (onConfirm) onConfirm({
      name: n,
      addr: addr.trim(),
      port: Number(port) || 7000,
      token: token.trim(),
      raw_config: rawConfig
    });
  }
</script>

<Modal title={$i18n("添加服务器")} onClose={onClose} width={480} closable={!busy}>
  <div style="display:flex;flex-direction:column;gap:14px" bind:this={formEl}>
    <!-- 服务器名称：必填步骤 -->
    <div class="form-group" style="margin-bottom:0">
      <label class="form-label" for="add-server-name">{$i18n("服务器名称")} <span style="color:var(--red)">*</span></label>
      <input id="add-server-name" type="text" bind:value={name} placeholder={$i18n("唯一标识，如：腾讯云 / 家庭NAS / 办公网络")} on:keydown={(e) => { if (e.key === 'Enter' && !busy) submit(); }} />
      {#if errMsg}
        <div class="tip-text" style="color:var(--red)">{errMsg}</div>
      {:else}
        <div class="tip-text">{$i18n("每个服务器需有唯一的可识别名称，添加后可通过胶囊按钮快速切换")}</div>
      {/if}
    </div>

    <div class="form-group" style="margin-bottom:0">
      <label class="form-label" for="add-server-addr">{$i18n("服务器地址")}</label>
      <input id="add-server-addr" type="text" bind:value={addr} placeholder={$i18n("frp 服务器 IP 或域名（可稍后填写）")} on:input={() => syncLine('serverAddr', addr)} use:field={{ check: optional(validateHost) }} />
    </div>

    <div class="form-row">
      <div class="form-group" style="margin-bottom:0">
        <label class="form-label" for="add-server-port">{$i18n("服务器端口")}</label>
        <input id="add-server-port" type="number" bind:value={port} min="1" max="65535" on:input={() => syncLine('serverPort', Number(port) || 7000)} use:field={{ check: optional(validatePort) }} />
      </div>
      <div class="form-group" style="margin-bottom:0">
        <label class="form-label" for="add-server-token">{$i18n("认证令牌（Token）")}</label>
        <input id="add-server-token" type="text" bind:value={token} placeholder={$i18n("与服务器 auth.token 一致")} on:input={() => syncLine('auth.token', token)} />
      </div>
    </div>

    <!-- 配置文件：默认显示，与上方输入框同步 -->
    <div class="adv-body">
      <div class="adv-label">{$i18n("配置文件（frpc.toml）")}</div>
      <TomlEditor
        bind:value={rawConfig}
        on:input={onConfigInput}
        minHeight="130px"
        maxHeight="220px"
        placeholder={'serverAddr = "frp.example.com"\nserverPort = 7000\nuser = "你的用户名"\n\nauth.method = "token"\nauth.token = "xxxxxx"\n'}
      />
    </div>
  </div>

  <div slot="footer">
    <button class="btn" on:click={onClose} disabled={busy}>{$i18n("取消")}</button>
    <button class="btn btn-primary" on:click={submit} disabled={busy} style="white-space:nowrap">
      {busy ? i18nTr("添加中…") : i18nTr("添加服务器")}
    </button>
  </div>
</Modal>

<style>
  .adv-body{margin-top:4px}
  .adv-label{font-size:12px;font-weight:600;color:var(--text2);letter-spacing:.2px;margin-bottom:6px}
</style>
