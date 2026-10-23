// DNS 服务商清单与各服务商凭证字段（账户弹窗与证书面板共用，避免两处定义走样）。
// value 为后端存储/匹配用的服务商标识，不要随展示文案改动。
import { tr } from './i18n.js';

export const DNS_PROVIDERS = [
  { value: '阿里云 DNS', label: '阿里云 DNS', fields: [
    { key: 'access_key', label: 'Access Key', type: 'text' },
    { key: 'secret_key', label: 'Secret Key', type: 'password' }
  ] },
  { value: '腾讯云 DNSPod', label: 'DNSPod 国内站（腾讯云）', fields: [
    { key: 'secret_id', label: 'Secret ID', type: 'text' },
    { key: 'secret_key', label: 'Secret Key', type: 'password' }
  ] },
  { value: 'DNSPod 国际站', label: 'DNSPod 国际站', fields: [
    { key: 'login_id', label: 'Token ID', type: 'text' },
    { key: 'api_token', label: 'API Token', type: 'password' }
  ] },
  { value: '华为云 DNS', label: '华为云 DNS', fields: [
    { key: 'access_key', label: 'Access Key', type: 'text' },
    { key: 'secret_key', label: 'Secret Key', type: 'password' },
    { key: 'region', label: 'Region', type: 'text' }
  ] },
  { value: 'Cloudflare', label: 'Cloudflare', fields: [
    { key: 'email', label: 'EMAIL', type: 'text' },
    { key: 'api_token', label: 'API Token', type: 'password' }
  ] },
  { value: 'GoDaddy', label: 'GoDaddy', fields: [
    { key: 'api_key', label: 'API Key', type: 'text' },
    { key: 'api_secret', label: 'API Secret', type: 'password' }
  ] },
  { value: 'Vercel', label: 'Vercel', fields: [
    { key: 'api_token', label: 'API Token', type: 'password' }
  ] }
];

export const DNS_PROVIDER_OPTIONS = DNS_PROVIDERS.map((p) => ({ value: p.value, label: p.label }));

export const DNS_FIELDS = Object.fromEntries(DNS_PROVIDERS.map((p) => [p.value, p.fields]));

// 把后端存储的服务商标识转成界面展示名（如「腾讯云 DNSPod」→「DNSPod 国内站（腾讯云）」）
export function dnsProviderLabel(value) {
  const p = DNS_PROVIDERS.find((x) => x.value === value);
  return p ? tr(p.label) : value;
}
