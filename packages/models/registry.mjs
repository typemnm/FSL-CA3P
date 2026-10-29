import { createHash } from 'node:crypto';
import reasoning from '../../agent/src/reasoning-engine.js';
import config from '../../agent/src/deepseek-config.js';
import adapter from '../../agent/src/deepseek-reasoning-engine.js';

const definitions = Object.freeze([
  { id: 'rule-baseline', name: '규칙 기반 · 실제 XSS 실습', provider: 'local', mode: 'local-lab-rule' },
  { id: 'deepseek-flash', name: 'DeepSeek Flash', provider: 'deepseek', mode: 'local-lab-deepseek' },
  { id: 'deepseek-v4-pro', name: 'DeepSeek V4 Pro', provider: 'deepseek', mode: 'local-lab-deepseek' },
]);
const digest = value => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');

export function listModels(options = {}) {
  return definitions.map(model => {
    if (model.provider === 'local') return { ...model, available: true,
      supportedModes: ['core-fixture', 'local-lab-rule', 'external-general'],
      capabilities: ['structured-action', 'deterministic-reflection'], modelRole: 'rule-baseline' };
    try {
      config.resolveDeepSeekOptions({ ...options, env: { ...(options.env ?? process.env), DEEPSEEK_MODEL: model.id } });
      return { ...model, available: true, supportedModes: ['local-lab-deepseek', 'local-lab-general', 'external-general'],
        capabilities: ['json', 'cancel', 'bounded-curl', 'general-evidence-planner'], modelRole: 'constrained-planner' };
    } catch {
      return { ...model, available: false, reason: 'agent/.env의 DeepSeek API 설정이 필요합니다.',
        supportedModes: ['local-lab-deepseek', 'local-lab-general', 'external-general'],
        capabilities: ['json', 'cancel', 'bounded-curl', 'general-evidence-planner'], modelRole: 'constrained-planner' };
    }
  });
}

function abortError() { return Object.assign(new Error('Model request cancelled.'), { name: 'AbortError' }); }

// Keep the run signal active while the client reads a streaming response body.
function fetchWithRunSignal(signal, fetchImpl = globalThis.fetch) {
  return async (url, init = {}) => {
    if (signal?.aborted || init.signal?.aborted) throw abortError();
    const controller = new AbortController();
    const signals = [signal, init.signal].filter(Boolean);
    const abort = () => controller.abort();
    const cleanup = () => signals.forEach(item => item.removeEventListener('abort', abort));
    for (const item of signals) item.addEventListener('abort', abort, { once: true });
    try {
      if (signals.some(item => item.aborted)) throw abortError();
      const response = await fetchImpl(url, { ...init, signal: controller.signal });
      const wrap = body => ({ getReader(...args) {
        const reader = body.getReader(...args);
        return {
          async read(...a) { try { const value = await reader.read(...a); if (value.done) cleanup(); return value; } catch (error) { cleanup(); throw error; } },
          async cancel(reason) { try { return await reader.cancel(reason); } finally { cleanup(); } },
          releaseLock() { reader.releaseLock(); },
        };
      }, async cancel(reason) { try { return await body.cancel(reason); } finally { cleanup(); } } });
      return {
        ok: response.ok, status: response.status, headers: response.headers,
        body: response.body?.getReader ? wrap(response.body) : response.body,
        async text() { try { return await response.text(); } finally { cleanup(); } },
      };
    } catch (error) { cleanup(); throw error; }
  };
}

export function createModelReasoning(modelId = 'rule-baseline', {
  signal, onModelCall, env = process.env, envFile, fetchImpl,
} = {}) {
  const id = modelId === 'rule' ? 'rule-baseline' : modelId;
  const model = definitions.find(row => row.id === id);
  if (!model) throw Object.assign(new Error('등록되지 않은 모델입니다.'), { status: 400 });
  if (model.provider === 'local') return new reasoning.RuleReasoningEngine();
  const settings = config.resolveDeepSeekOptions({ env: { ...env, DEEPSEEK_MODEL: id }, ...(envFile !== undefined ? { envFile } : {}) });
  const engine = config.createDeepSeekReasoningEngineFromEnv({
    env: { ...env, DEEPSEEK_MODEL: id }, ...(envFile !== undefined ? { envFile } : {}),
    curlMode: true, fetchImpl: fetchWithRunSignal(signal, fetchImpl),
  });
  const complete = engine.client.completeJson.bind(engine.client);
  engine.client.completeJson = async input => {
    const started = performance.now();
    const metadata = {
      provider: model.provider, requestedModel: id, reportedModel: null, adapterVersion: '1.0',
      promptTemplateDigest: digest(input.systemPrompt), promptDigest: digest(input),
      requestSettings: { maxTokens: settings.maxTokens, maxRetries: settings.maxRetries, timeoutMs: settings.timeoutMs },
    };
    try {
      const result = await complete({ ...input, signal });
      await onModelCall?.({ ...metadata, status: 'completed', usage: result.metadata?.usage ?? null,
        reportedModel: result.metadata?.reportedModel ?? null, latencyMs: performance.now() - started });
      return result;
    } catch (error) {
      await onModelCall?.({ ...metadata, status: 'failed', usage: null, latencyMs: performance.now() - started,
        error: { code: error.code ?? 'MODEL_FAILURE', message: '모델 호출에 실패했습니다.' } });
      throw error;
    }
  };
  return engine;
}

export const modelDefinitions = definitions;
export const promptTemplateDigest = digest(adapter.SYSTEM_PROMPT_CURL);
