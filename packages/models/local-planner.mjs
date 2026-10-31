import { createRequire } from 'node:module';
import {
  localConfigs, localJson, safeLocalModelName, LOCAL_RUNTIME_LABELS,
  LOCAL_COMPLETION_TIMEOUT_MS, LOCAL_DISCOVERY_TIMEOUT_MS, LOCAL_MAX_OUTPUT_TOKENS,
} from './workspace-chat.mjs';

const require = createRequire(import.meta.url);
const planner = require('../../agent/src/general-model-planner.js');

export const LOCAL_PLANNER_MODEL_ID = 'local-llm';
export const DEEPSEEK_PLANNER_MODELS = Object.freeze(['deepseek-flash', 'deepseek-v4-pro']);
const MAX_PROMPT_BYTES = 64 * 1024;
const MAX_CONTENT_BYTES = 64 * 1024;

const fault = (status, code, message) => Object.assign(new Error(message), { status, code });

export function isGeneralPlannerModel(modelId) {
  return DEEPSEEK_PLANNER_MODELS.includes(modelId) || modelId === LOCAL_PLANNER_MODEL_ID;
}

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

function configuredServer(env, envFile) {
  const servers = localConfigs(env, envFile);
  return servers.find(server => server.configured) ?? null;
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
      reason: '이 장치의 로컬 LLM 주소를 agent/.env 또는 CA3P_CHAT_LOCAL_ENDPOINT로 설정하세요.',
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

export async function createLocalJsonClient({ env = process.env, envFile, fetchImpl = globalThis.fetch } = {}) {
  const server = configuredServer(env, envFile);
  if (!server) throw fault(503, 'LOCAL_PLANNER_UNAVAILABLE', '로컬 LLM 서버 주소를 설정하세요.');
  const model = await resolveLocalModel(server, fetchImpl);
  return {
    provider: 'local',
    requestedModel: LOCAL_PLANNER_MODEL_ID,
    reportedModel: model,
    runtime: LOCAL_RUNTIME_LABELS[server.label] ?? server.label,
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
      const body = server.protocol === 'ollama'
        ? { model, messages, format: 'json', stream: false,
          options: { num_predict: LOCAL_MAX_OUTPUT_TOKENS, num_ctx: server.contextWindowTokens, temperature: 0 } }
        : { model, messages, response_format: { type: 'json_object' }, stream: false,
          max_tokens: LOCAL_MAX_OUTPUT_TOKENS, temperature: 0 };
      const started = performance.now();
      const value = await localJson(fetchImpl,
        `${server.endpoint}${server.protocol === 'ollama' ? '/api/chat' : '/chat/completions'}`,
        { method: 'POST', body, apiKey: server.apiKey, signal, timeoutMs: LOCAL_COMPLETION_TIMEOUT_MS,
          limit: MAX_CONTENT_BYTES + 64 * 1024 });
      const choice = value.choices?.[0];
      if (server.protocol === 'ollama' ? value.done !== true || (value.done_reason && value.done_reason !== 'stop')
        : !Array.isArray(value.choices) || value.choices.length !== 1 || choice?.finish_reason !== 'stop') {
        throw fault(502, 'LOCAL_PLANNER_OUTPUT_INVALID', '로컬 LLM이 완전한 JSON 응답을 반환하지 않았습니다.');
      }
      const raw = server.protocol === 'ollama' ? value.message?.content : choice?.message?.content;
      if (typeof raw !== 'string' || !raw.trim() || Buffer.byteLength(raw, 'utf8') > MAX_CONTENT_BYTES) {
        throw fault(502, 'LOCAL_PLANNER_OUTPUT_INVALID', '로컬 LLM 응답 크기가 올바르지 않습니다.');
      }
      const parsed = parsePlannerJson(raw);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw fault(502, 'LOCAL_PLANNER_OUTPUT_INVALID', '로컬 LLM JSON 출력은 객체여야 합니다.');
      }
      const usageSource = server.protocol === 'ollama'
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
          provider: 'local',
          model: LOCAL_PLANNER_MODEL_ID,
          requestedModel: LOCAL_PLANNER_MODEL_ID,
          reportedModel: safeLocalModelName(value.model) ? value.model : model,
          finishReason: 'stop',
          latencyMs: Math.round(performance.now() - started),
          ...(usage && Object.keys(usage).length ? { usage } : {}),
        },
      };
    },
  };
}

export async function createAssessmentPlanner({ modelId, env = process.env, envFile, fetchImpl } = {}) {
  if (modelId === LOCAL_PLANNER_MODEL_ID) {
    const client = await createLocalJsonClient({ env, envFile, fetchImpl });
    return planner.createGeneralModelPlanner({ client });
  }
  return planner.createGeneralModelPlannerFromEnv({
    env: { ...env, DEEPSEEK_MODEL: modelId }, envFile, fetchImpl,
  });
}
