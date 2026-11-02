import { createRequire } from 'node:module';
import {
  localConfigs, localJson, safeLocalModelName, LOCAL_RUNTIME_LABELS,
  LOCAL_COMPLETION_TIMEOUT_MS, LOCAL_DISCOVERY_TIMEOUT_MS, LOCAL_MAX_OUTPUT_TOKENS,
} from './workspace-chat.mjs';
import { CUSTOM_MODEL_ID, PROVIDER_KINDS, readProviderSettings, remoteJson, resolveProvider } from './provider-settings.mjs';

const require = createRequire(import.meta.url);
const planner = require('../../agent/src/general-model-planner.js');

export const LOCAL_PLANNER_MODEL_ID = 'local-llm';
export const DEEPSEEK_PLANNER_MODELS = Object.freeze(['deepseek-flash', 'deepseek-v4-pro']);
const MAX_PROMPT_BYTES = 64 * 1024;
const MAX_CONTENT_BYTES = 64 * 1024;

const fault = (status, code, message) => Object.assign(new Error(message), { status, code });

export function isGeneralPlannerModel(modelId) {
  return DEEPSEEK_PLANNER_MODELS.includes(modelId) || modelId === LOCAL_PLANNER_MODEL_ID || CUSTOM_MODEL_ID.test(String(modelId));
}

/** Provider label recorded in run state, manifests and model-call metadata. */
export function plannerProvider(modelId) {
  return modelId === LOCAL_PLANNER_MODEL_ID ? 'local' : CUSTOM_MODEL_ID.test(String(modelId)) ? 'custom' : 'deepseek';
}

/** Models whose planner and verifier use the JSON client below instead of the DeepSeek transport. */
export function usesJsonClient(modelId) { return plannerProvider(modelId) !== 'deepseek'; }

export function parsePlannerJson(raw) {
  let text = String(raw ?? '').trim();
  text = text.replace(/<think\b[^>]*>[\s\S]*?<\/think>/giu, '').trim();
  const fence = /```(?:json)?\s*([\s\S]*?)```/iu.exec(text);
  if (fence) text = fence[1].trim();
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start < 0 || end <= start) throw fault(502, 'LOCAL_PLANNER_OUTPUT_INVALID', '로컬 LLM 응답의 JSON 객체를 찾지 못했습니다.');
  try { return JSON.parse(text.slice(start, end + 1)); }
  catch { throw fault(502, 'LOCAL_PLANNER_OUTPUT_INVALID', '로컬 LLM 응답의 JSON 형식이 올바르지 않습니다.'); }
}

// Environment configuration wins; otherwise the local LLM chosen in the LLM module is used.
function configuredServer(env, envFile) {
  const servers = localConfigs(env, envFile);
  const configured = servers.find(server => server.configured);
  if (configured) return configured;
  let selected;
  try { selected = readProviderSettings({ env }).local; } catch { selected = null; }
  if (!selected?.endpoint) return null;
  return localConfigs({ ...env, CA3P_CHAT_LOCAL_ENDPOINT: selected.endpoint, CA3P_CHAT_LOCAL_RUNTIME: selected.label,
    ...(selected.model ? { CA3P_CHAT_LOCAL_MODEL: selected.model } : {}) }, envFile).find(server => server.configured) ?? null;
}

export function listLocalPlannerModels({ env = process.env, envFile } = {}) {
  let server;
  try { server = configuredServer(env, envFile); }
  catch (error) {
    return [{ id: LOCAL_PLANNER_MODEL_ID, name: '로컬 LLM', provider: 'local', local: true,
      mode: 'local-lab-general', available: false, reason: error.message,
      supportedModes: ['local-lab-general', 'external-general'],
      capabilities: ['json', 'cancel', 'general-evidence-planner'], modelRole: 'constrained-planner' }];
  }
  if (!server) {
    return [{ id: LOCAL_PLANNER_MODEL_ID, name: '로컬 LLM', provider: 'local', local: true,
      mode: 'local-lab-general', available: false,
      reason: 'LLM 모듈에서 로컬 LLM을 탐지해 지정하거나 agent/.env의 CA3P_CHAT_LOCAL_ENDPOINT를 설정하세요.',
      supportedModes: ['local-lab-general', 'external-general'],
      capabilities: ['json', 'cancel', 'general-evidence-planner'], modelRole: 'constrained-planner' }];
  }
  const runtime = LOCAL_RUNTIME_LABELS[server.label] ?? server.label;
  const name = server.model ? `로컬 LLM · ${server.model}` : `로컬 LLM · ${runtime}`;
  return [{ id: LOCAL_PLANNER_MODEL_ID, name, provider: 'local', local: true, runtime,
    mode: 'local-lab-general', available: true, supportedModes: ['local-lab-general', 'external-general'],
    capabilities: ['json', 'cancel', 'general-evidence-planner'], modelRole: 'constrained-planner' }];
}

async function resolveLocalModel(server, fetchImpl) {
  if (safeLocalModelName(server.model)) return server.model;
  const value = await localJson(fetchImpl,
    `${server.endpoint}${server.protocol === 'ollama' ? '/api/tags' : '/models'}`,
    { apiKey: server.apiKey, timeoutMs: LOCAL_DISCOVERY_TIMEOUT_MS, limit: 256 * 1024 });
  const candidates = server.protocol === 'ollama'
    ? value.models?.map(row => row?.name ?? row?.model) : value.data?.map(row => row?.id);
  const name = Array.isArray(candidates) ? candidates.find(safeLocalModelName) : null;
  if (!name) throw fault(503, 'LOCAL_PLANNER_UNAVAILABLE', '로컬 LLM 서버에 사용할 수 있는 모델이 없습니다.');
  return name;
}

/** Bounded JSON completion over the Ollama or OpenAI-compatible chat API. */
function createJsonChatClient({ endpoint, protocol, apiKey, model, provider, requestedModel, runtime,
  contextWindowTokens = 8192, tokenField = 'max_tokens', temperature = true, transport = localJson,
  fetchImpl = globalThis.fetch, errorCode = 'LOCAL_PLANNER_OUTPUT_INVALID', label = '로컬 LLM' }) {
  const invalid = message => fault(502, errorCode, message);
  return {
    provider,
    requestedModel,
    reportedModel: model,
    runtime,
    async completeJson({ systemPrompt, userPayload, signal } = {}) {
      if (typeof systemPrompt !== 'string' || systemPrompt.trim().length === 0 || !/json/i.test(systemPrompt)) {
        throw fault(400, 'LOCAL_PLANNER_PROMPT_INVALID', 'Planner systemPrompt must request JSON.');
      }
      let serialized;
      try { serialized = JSON.stringify(userPayload); }
      catch { throw fault(400, 'LOCAL_PLANNER_PROMPT_INVALID', 'userPayload must be JSON serializable.'); }
      if (Buffer.byteLength(systemPrompt, 'utf8') + Buffer.byteLength(serialized, 'utf8') > MAX_PROMPT_BYTES) {
        throw fault(413, 'LOCAL_PLANNER_CONTEXT_TOO_LARGE', `Model context exceeds ${MAX_PROMPT_BYTES} bytes`);
      }
      const messages = [{ role: 'system', content: systemPrompt }, { role: 'user', content: serialized }];
      const body = protocol === 'ollama'
        ? { model, messages, format: 'json', stream: false,
          options: { num_predict: LOCAL_MAX_OUTPUT_TOKENS, num_ctx: contextWindowTokens, temperature: 0 } }
        : { model, messages, response_format: { type: 'json_object' }, stream: false,
          [tokenField]: LOCAL_MAX_OUTPUT_TOKENS, ...(temperature ? { temperature: 0 } : {}) };
      const started = performance.now();
      const send = payload => transport(fetchImpl,
        `${endpoint}${protocol === 'ollama' ? '/api/chat' : '/chat/completions'}`,
        { method: 'POST', body: payload, apiKey, signal, timeoutMs: LOCAL_COMPLETION_TIMEOUT_MS,
          limit: MAX_CONTENT_BYTES + 64 * 1024 });
      let value;
      try { value = await send(body); }
      catch (error) {
        // Some OpenAI-compatible gateways reject JSON mode; the prompt still asks for JSON and the parser extracts it.
        if (protocol === 'ollama' || !['LLM_PROVIDER_REJECTED', 'LOCAL_CHAT_REQUEST_REJECTED'].includes(error?.code)) throw error;
        const { response_format: _jsonMode, ...plain } = body;
        value = await send(plain);
      }
      const choice = value.choices?.[0];
      if (protocol === 'ollama' ? value.done !== true || (value.done_reason && value.done_reason !== 'stop')
        : !Array.isArray(value.choices) || value.choices.length !== 1 || choice?.finish_reason !== 'stop') {
        throw invalid(`${label}이 완전한 JSON 응답을 반환하지 않았습니다.`);
      }
      const raw = protocol === 'ollama' ? value.message?.content : choice?.message?.content;
      if (typeof raw !== 'string' || !raw.trim() || Buffer.byteLength(raw, 'utf8') > MAX_CONTENT_BYTES) {
        throw invalid(`${label} 응답 크기가 올바르지 않습니다.`);
      }
      const parsed = parsePlannerJson(raw);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw invalid(`${label} JSON 출력은 객체여야 합니다.`);
      }
      const usageSource = protocol === 'ollama'
        ? { prompt_tokens: value.prompt_eval_count, completion_tokens: value.eval_count,
          total_tokens: Number.isInteger(value.prompt_eval_count) && Number.isInteger(value.eval_count)
            ? value.prompt_eval_count + value.eval_count : null }
        : value.usage;
      const usage = usageSource && typeof usageSource === 'object'
        ? Object.fromEntries(['prompt_tokens', 'completion_tokens', 'total_tokens']
          .filter(key => Number.isSafeInteger(usageSource[key]) && usageSource[key] >= 0)
          .map(key => [key, usageSource[key]]))
        : null;
      return {
        value: parsed,
        metadata: {
          provider,
          model: requestedModel,
          requestedModel,
          reportedModel: safeLocalModelName(value.model) ? value.model : model,
          finishReason: 'stop',
          latencyMs: Math.round(performance.now() - started),
          ...(usage && Object.keys(usage).length ? { usage } : {}),
        },
      };
    },
  };
}

export async function createLocalJsonClient({ env = process.env, envFile, fetchImpl = globalThis.fetch } = {}) {
  const server = configuredServer(env, envFile);
  if (!server) throw fault(503, 'LOCAL_PLANNER_UNAVAILABLE', '로컬 LLM 서버 주소를 설정하세요.');
  const model = await resolveLocalModel(server, fetchImpl);
  return createJsonChatClient({ endpoint: server.endpoint, protocol: server.protocol, apiKey: server.apiKey, model,
    provider: 'local', requestedModel: LOCAL_PLANNER_MODEL_ID, runtime: LOCAL_RUNTIME_LABELS[server.label] ?? server.label,
    contextWindowTokens: server.contextWindowTokens, fetchImpl });
}

/** Client for an AI API provider entered in the LLM module. */
export async function createCustomJsonClient({ modelId, env = process.env, fetchImpl = globalThis.fetch } = {}) {
  const provider = resolveProvider(modelId, { env });
  if (!provider?.apiKey) throw fault(503, 'LLM_PROVIDER_UNAVAILABLE', '등록된 AI API 공급자를 찾을 수 없습니다. LLM 모듈 설정을 확인하세요.');
  const kind = PROVIDER_KINDS[provider.kind] ?? PROVIDER_KINDS['openai-compatible'];
  return createJsonChatClient({ endpoint: provider.baseUrl, protocol: 'openai', apiKey: provider.apiKey, model: provider.model,
    provider: 'custom', requestedModel: provider.id, runtime: kind.label, tokenField: kind.tokenField,
    temperature: provider.kind !== 'openai', transport: remoteJson, fetchImpl,
    errorCode: 'LLM_PROVIDER_OUTPUT_INVALID', label: provider.name });
}

/** JSON client for a non-DeepSeek planner model; used for both planning and verification. */
export async function createModelJsonClient({ modelId, env = process.env, envFile, fetchImpl = globalThis.fetch } = {}) {
  if (modelId === LOCAL_PLANNER_MODEL_ID) return createLocalJsonClient({ env, envFile, fetchImpl });
  if (CUSTOM_MODEL_ID.test(String(modelId))) return createCustomJsonClient({ modelId, env, fetchImpl });
  throw fault(400, 'PLANNER_MODEL_INVALID', 'JSON client is only used for local or registered provider models.');
}

export async function createAssessmentPlanner({ modelId, env = process.env, envFile, fetchImpl } = {}) {
  if (usesJsonClient(modelId)) {
    const client = await createModelJsonClient({ modelId, env, envFile, fetchImpl });
    return planner.createGeneralModelPlanner({ client });
  }
  return planner.createGeneralModelPlannerFromEnv({
    env: { ...env, DEEPSEEK_MODEL: modelId }, envFile, fetchImpl,
  });
}
