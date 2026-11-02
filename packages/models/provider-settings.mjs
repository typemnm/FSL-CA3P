import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LOCAL_DEFAULTS, LOCAL_DISCOVERY_TIMEOUT_MS, LOCAL_RUNTIME_LABELS, localJson, safeLocalModelName } from './workspace-chat.mjs';

/**
 * Operator-managed model settings: AI API providers entered in the LLM module
 * and the local LLM chosen from discovery. Stored server-side in
 * `.runtime/llm-providers.json` (0600). API keys never leave this module
 * except inside the Authorization header of a provider request.
 */

export const PROVIDER_KINDS = Object.freeze({
  deepseek: Object.freeze({ label: 'DeepSeek (api.deepseek.com)', baseUrl: 'https://api.deepseek.com', tokenField: 'max_tokens',
    modelHint: 'deepseek-chat' }),
  // deploy.com serves hosted models (DeepSeek and others) behind an OpenAI-compatible gateway.
  deploy: Object.freeze({ label: 'Deploy (deploy.com)', baseUrl: 'https://api-sf1-cdn.deploy.com/api/v1', tokenField: 'max_tokens',
    modelHint: 'deepseek-ai/deepseek-v4.1-flash-1017' }),
  openai: Object.freeze({ label: 'OpenAI', baseUrl: 'https://api.openai.com/v1', tokenField: 'max_completion_tokens',
    modelHint: 'gpt-4o-mini' }),
  'openai-compatible': Object.freeze({ label: 'OpenAI 호환 API (직접 입력)', baseUrl: null, tokenField: 'max_tokens', modelHint: null }),
});
export const CUSTOM_MODEL_ID = /^custom-[a-f0-9]{12}$/u;
const MAX_PROVIDERS = 20;
const SCHEMA_VERSION = 1;
const fault = (status, code, message) => Object.assign(new Error(message), { status, code });
const CONTROL = /[\u0000-\u001f\u007f]/u;

/**
 * Settings location. An explicit CA3P_LLM_PROVIDERS_PATH wins ('' disables
 * operator settings); otherwise it follows the run store directory. A caller
 * that passes its own env object without either key gets no on-disk settings,
 * so isolated callers never read the developer's real configuration.
 */
export function providerSettingsPath(env = process.env) {
  if (Object.hasOwn(env, 'CA3P_LLM_PROVIDERS_PATH')) return env.CA3P_LLM_PROVIDERS_PATH ? resolve(env.CA3P_LLM_PROVIDERS_PATH) : null;
  if (env.CA3P_STORE_PATH) return join(dirname(resolve(env.CA3P_STORE_PATH)), 'llm-providers.json');
  if (env !== process.env) return null;
  return join(fileURLToPath(new URL('../../.runtime', import.meta.url)), 'llm-providers.json');
}

function emptySettings() { return { version: SCHEMA_VERSION, providers: [], local: null }; }

const cache = new Map();
/** Reads the settings; a missing file is an empty configuration. Cached by mtime and size. */
export function readProviderSettings({ env = process.env, path = providerSettingsPath(env) } = {}) {
  if (!path) return emptySettings();
  let info;
  try { info = statSync(path); }
  catch (error) { if (error.code === 'ENOENT') return emptySettings(); throw fault(503, 'LLM_SETTINGS_UNREADABLE', 'LLM 설정 파일을 읽지 못했습니다.'); }
  const key = `${info.mtimeMs}:${info.size}`;
  const cached = cache.get(path);
  if (cached?.key === key) return structuredClone(cached.value);
  let value;
  try { value = JSON.parse(readFileSync(path, 'utf8')); }
  catch { throw fault(503, 'LLM_SETTINGS_INVALID', 'LLM 설정 파일의 형식이 올바르지 않습니다.'); }
  if (!value || value.version !== SCHEMA_VERSION || !Array.isArray(value.providers)) {
    throw fault(503, 'LLM_SETTINGS_INVALID', 'LLM 설정 파일의 형식이 올바르지 않습니다.');
  }
  const settings = { version: SCHEMA_VERSION, providers: value.providers.filter(item => item && CUSTOM_MODEL_ID.test(item.id)),
    local: value.local && typeof value.local === 'object' ? value.local : null };
  cache.set(path, { key, value: settings });
  return structuredClone(settings);
}

function writeProviderSettings(settings, { env = process.env, path = providerSettingsPath(env) } = {}) {
  if (!path) throw fault(503, 'LLM_SETTINGS_UNAVAILABLE', 'LLM 설정을 저장할 위치가 지정되지 않았습니다.');
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomBytes(6).toString('hex')}.tmp`;
  writeFileSync(temporary, JSON.stringify(settings, null, 2), { mode: 0o600, flag: 'wx' });
  renameSync(temporary, path);
  cache.delete(path);
}

function text(value, field, { min = 1, max }) {
  if (typeof value !== 'string' || CONTROL.test(value) || value.trim().length < min || value.trim().length > max) {
    throw fault(400, 'LLM_PROVIDER_INVALID', `${field}을(를) 확인하세요.`);
  }
  return value.trim();
}

/** Remote providers must be HTTPS services; loopback servers belong in the local LLM section. */
export function normalizeProviderBaseUrl(raw) {
  let url;
  try { url = new URL(String(raw ?? '').trim()); } catch { throw fault(400, 'LLM_PROVIDER_INVALID', 'Base URL을 확인하세요.'); }
  const host = url.hostname.replace(/^\[|\]$/gu, '');
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
    || host === 'localhost' || host === '0.0.0.0' || host === '::1' || /^127\./u.test(host)) {
    throw fault(400, 'LLM_PROVIDER_INVALID', 'Base URL은 계정·쿼리 없는 https 주소여야 합니다. 이 장치의 서버는 로컬 LLM 탐지를 사용하세요.');
  }
  return url.toString().replace(/\/+$/u, '');
}

export function validateProviderInput(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)
    || Object.keys(body).some(key => !['name', 'kind', 'baseUrl', 'model', 'apiKey'].includes(key))) {
    throw fault(400, 'LLM_PROVIDER_INVALID', '이름, 종류, Base URL, 모델, API 키만 입력할 수 있습니다.');
  }
  const kind = PROVIDER_KINDS[body.kind] ? body.kind : null;
  if (!kind) throw fault(400, 'LLM_PROVIDER_INVALID', '지원하는 공급자 종류를 선택하세요.');
  const name = text(body.name, '이름', { max: 60 });
  const model = text(body.model, '모델 이름', { max: 160 });
  if (!safeLocalModelName(model)) throw fault(400, 'LLM_PROVIDER_INVALID', '모델 이름을 확인하세요.');
  if (typeof body.apiKey !== 'string' || body.apiKey.length < 8 || body.apiKey.length > 512 || /[\s\u0000-\u001f\u007f]/u.test(body.apiKey)) {
    throw fault(400, 'LLM_PROVIDER_INVALID', 'API 키를 확인하세요. 공백 없이 8자 이상이어야 합니다.');
  }
  const baseUrl = PROVIDER_KINDS[kind].baseUrl ?? normalizeProviderBaseUrl(body.baseUrl);
  return { name, kind, baseUrl, model, apiKey: body.apiKey };
}

const keyHint = key => (typeof key === 'string' && key.length >= 8 ? `…${key.slice(-4)}` : '…');
/** Browser-safe view of a provider. The key itself is never included. */
export function publicProvider(provider) {
  return { id: provider.id, name: provider.name, kind: provider.kind, kindLabel: PROVIDER_KINDS[provider.kind]?.label ?? provider.kind,
    baseUrl: provider.baseUrl, model: provider.model, keyHint: keyHint(provider.apiKey), keyConfigured: Boolean(provider.apiKey),
    createdAt: provider.createdAt ?? null };
}

export function listProviderSettings(options = {}) {
  const settings = readProviderSettings(options);
  return { providers: settings.providers.map(publicProvider), local: settings.local,
    kinds: Object.entries(PROVIDER_KINDS).map(([id, kind]) => ({ id, label: kind.label, baseUrl: kind.baseUrl, modelHint: kind.modelHint })) };
}

export function addProvider(body, options = {}) {
  const input = validateProviderInput(body);
  const settings = readProviderSettings(options);
  if (settings.providers.length >= MAX_PROVIDERS) throw fault(409, 'LLM_PROVIDER_LIMIT', `공급자는 최대 ${MAX_PROVIDERS}개까지 등록할 수 있습니다.`);
  if (settings.providers.some(item => item.name.toLowerCase() === input.name.toLowerCase())) {
    throw fault(409, 'LLM_PROVIDER_DUPLICATE', '같은 이름의 공급자가 이미 있습니다.');
  }
  const provider = { id: `custom-${randomBytes(6).toString('hex')}`, ...input, createdAt: new Date().toISOString() };
  settings.providers.push(provider);
  writeProviderSettings(settings, options);
  return publicProvider(provider);
}

export function removeProvider(id, options = {}) {
  if (!CUSTOM_MODEL_ID.test(String(id))) throw fault(404, 'LLM_PROVIDER_NOT_FOUND', '공급자를 찾을 수 없습니다.');
  const settings = readProviderSettings(options);
  const next = settings.providers.filter(item => item.id !== id);
  if (next.length === settings.providers.length) throw fault(404, 'LLM_PROVIDER_NOT_FOUND', '공급자를 찾을 수 없습니다.');
  writeProviderSettings({ ...settings, providers: next }, options);
  return { removed: id };
}

/** Server-only lookup including the key, for building a provider client. */
export function resolveProvider(modelId, options = {}) {
  if (!CUSTOM_MODEL_ID.test(String(modelId))) return null;
  return readProviderSettings(options).providers.find(item => item.id === modelId) ?? null;
}

/** Picks one discovered loopback runtime and model as the assessment's local LLM. */
export function setLocalSelection(body, options = {}) {
  const settings = readProviderSettings(options);
  if (body?.clear === true && Object.keys(body).length === 1) {
    writeProviderSettings({ ...settings, local: null }, options);
    return { local: null };
  }
  if (!body || typeof body !== 'object' || Object.keys(body).some(key => !['label', 'model'].includes(key))) {
    throw fault(400, 'LLM_LOCAL_INVALID', '로컬 runtime과 모델을 선택하세요.');
  }
  const server = LOCAL_DEFAULTS.find(item => item.label === body.label);
  if (!server) throw fault(400, 'LLM_LOCAL_INVALID', '탐지된 로컬 runtime을 선택하세요.');
  if (!safeLocalModelName(body.model)) throw fault(400, 'LLM_LOCAL_INVALID', '로컬 모델 이름을 확인하세요.');
  const local = { label: server.label, runtime: LOCAL_RUNTIME_LABELS[server.label], endpoint: server.endpoint,
    model: body.model.trim(), selectedAt: new Date().toISOString() };
  writeProviderSettings({ ...settings, local }, options);
  return { local };
}

/** Probes the well-known loopback ports of local LLM runtimes. Nothing is stored. */
export async function discoverLocalServers({ fetchImpl = globalThis.fetch, timeoutMs = LOCAL_DISCOVERY_TIMEOUT_MS } = {}) {
  return Promise.all(LOCAL_DEFAULTS.map(async server => {
    const row = { label: server.label, runtime: LOCAL_RUNTIME_LABELS[server.label], endpoint: server.endpoint };
    try {
      const value = await localJson(fetchImpl, `${server.endpoint}${server.protocol === 'ollama' ? '/api/tags' : '/models'}`,
        { timeoutMs, limit: 256 * 1024 });
      const candidates = server.protocol === 'ollama' ? value.models?.map(item => item?.name ?? item?.model) : value.data?.map(item => item?.id);
      if (!Array.isArray(candidates)) return { ...row, reachable: true, models: [], error: '모델 목록 형식을 읽지 못했습니다.' };
      return { ...row, reachable: true, models: [...new Set(candidates.filter(safeLocalModelName))].slice(0, 40) };
    } catch (error) {
      return { ...row, reachable: false, models: [],
        error: error.code === 'LOCAL_CHAT_AUTH_REQUIRED' ? '서버가 인증 키를 요구합니다.' : '응답 없음' };
    }
  }));
}

const REMOTE_MESSAGES = {
  LOCAL_CHAT_AUTH_REQUIRED: [503, 'LLM_PROVIDER_AUTH_FAILED', 'API 키가 거부되었습니다. 키와 권한을 확인하세요.'],
  LOCAL_CHAT_RATE_LIMITED: [429, 'LLM_PROVIDER_RATE_LIMITED', '공급자가 요청 한도를 초과했다고 응답했습니다.'],
  LOCAL_CHAT_REQUEST_REJECTED: [502, 'LLM_PROVIDER_REJECTED', '공급자가 요청을 거부했습니다. 모델 이름과 설정을 확인하세요.'],
  LOCAL_CHAT_TIMEOUT: [504, 'LLM_PROVIDER_TIMEOUT', '공급자 API 응답 시간이 초과되었습니다.'],
  LOCAL_CHAT_ABORTED: [499, 'LLM_PROVIDER_ABORTED', '공급자 요청이 취소되었습니다.'],
  CHAT_OUTPUT_INVALID: [502, 'LLM_PROVIDER_OUTPUT_INVALID', '공급자 응답의 형식이 올바르지 않습니다.'],
};
/** Same bounded transport as the local client, with provider-facing error messages. */
export async function remoteJson(fetchImpl, url, options) {
  try { return await localJson(fetchImpl, url, options); }
  catch (error) {
    const mapped = REMOTE_MESSAGES[error.code];
    if (mapped) throw fault(...mapped);
    throw fault(503, 'LLM_PROVIDER_UNAVAILABLE', '공급자 API에 연결할 수 없습니다. 주소와 네트워크를 확인하세요.');
  }
}

/**
 * Lists the provider's models with the stored key and reports whether the
 * configured model exists. Gateways without a model list endpoint are checked
 * with one minimal chat completion instead; a rejected key is reported as is.
 */
export async function testProvider(id, { fetchImpl = globalThis.fetch, ...options } = {}) {
  const provider = resolveProvider(id, options);
  if (!provider) throw fault(404, 'LLM_PROVIDER_NOT_FOUND', '공급자를 찾을 수 없습니다.');
  let listError;
  try {
    const value = await remoteJson(fetchImpl, `${provider.baseUrl}/models`, { apiKey: provider.apiKey, timeoutMs: 10_000, limit: 1024 * 1024 });
    const names = Array.isArray(value?.data) ? value.data.map(item => item?.id).filter(safeLocalModelName) : null;
    if (names) return { ok: true, method: 'models', modelFound: names.includes(provider.model), models: names.slice(0, 30) };
  } catch (error) {
    if (['LLM_PROVIDER_AUTH_FAILED', 'LLM_PROVIDER_RATE_LIMITED'].includes(error.code)) return { ok: false, code: error.code, error: error.message };
    listError = error;
  }
  const kind = PROVIDER_KINDS[provider.kind] ?? PROVIDER_KINDS['openai-compatible'];
  try {
    const value = await remoteJson(fetchImpl, `${provider.baseUrl}/chat/completions`, { method: 'POST', apiKey: provider.apiKey,
      timeoutMs: 30_000, limit: 256 * 1024,
      body: { model: provider.model, messages: [{ role: 'user', content: 'Reply with OK.' }], stream: false, [kind.tokenField]: 16 } });
    if (!Array.isArray(value?.choices)) throw fault(502, 'LLM_PROVIDER_OUTPUT_INVALID', '공급자 응답의 형식이 올바르지 않습니다.');
    return { ok: true, method: 'chat', modelFound: true, models: [] };
  } catch (error) {
    return { ok: false, code: error.code ?? listError?.code, error: error.message ?? listError?.message };
  }
}

/** Registry rows for operator-entered providers. */
export function customModelEntries(options = {}) {
  let settings;
  try { settings = readProviderSettings(options); }
  catch { return []; }
  return settings.providers.map(provider => ({ id: provider.id, name: `${provider.name} · ${provider.model}`, provider: 'custom',
    kind: provider.kind, mode: 'local-lab-general', available: Boolean(provider.apiKey),
    supportedModes: ['local-lab-general', 'external-general'],
    capabilities: ['json', 'cancel', 'general-evidence-planner'], modelRole: 'constrained-planner',
    settings: { kind: provider.kind, endpoint: new URL(provider.baseUrl).origin, model: provider.model } }));
}
