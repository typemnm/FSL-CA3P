import { activeChatMessages, computeChatRequestMetrics, computeContext, estimateTokens, isLocalChatModelId } from '../../packages/models/workspace-chat.mjs';
import { redact } from '../../packages/contracts/index.mjs';

const fault = (status, code, message) => Object.assign(new Error(message), { status, code });
const MAX_FILES = 4;
const MAX_FILE_CONTEXT_CHARACTERS = 8000;
const MAX_SUMMARY_TOKENS = 2000;
const MAX_SUMMARY_CHARACTERS = 6000;
const KEEP_RECENT_MESSAGES = 4;
const MAX_COMPACTION_CALLS = 8;
const safeText = (value, limit = 600) => typeof value === 'string' ? redact(value).slice(0, limit) : null;

function safeRunContext(value) {
  const run = value?.run ?? value;
  if (!run || typeof run !== 'object') return null;
  const result = {};
  for (const key of ['id', 'status', 'mode', 'modelId', 'target', 'testProfile', 'fixtureId']) {
    if (typeof run[key] === 'string') result[key] = safeText(run[key]);
  }
  for (const key of ['simulated', 'targetContacted']) if (typeof run[key] === 'boolean') result[key] = run[key];
  result.events = (Array.isArray(run.events) ? run.events : []).slice(-12).map(event => ({
    type: safeText(event.type, 80), phase: safeText(event.phase, 80),
    status: safeText(event.status, 80), message: safeText(event.message, 500),
  }));
  const findings = run.findings ?? run.reviewItems;
  result.findings = (Array.isArray(findings) ? findings : []).slice(0, 12).map(item => ({
    id: safeText(item.id, 128), title: safeText(item.title, 160), status: safeText(item.status, 80),
    verdict: safeText(item.verdict, 80), severity: safeText(item.severity, 80), summary: safeText(item.summary, 500),
  }));
  return result;
}

function providerFailure(error, signal) {
  if (signal?.aborted || ['DEEPSEEK_ABORTED', 'LOCAL_CHAT_ABORTED'].includes(error?.code) || error?.name === 'AbortError') {
    return fault(499, 'CHAT_CANCELLED', '채팅 요청이 취소되었습니다. 기존 대화는 보존됩니다.');
  }
  if (['CHAT_CONTEXT_TOO_LARGE', 'CHAT_OUTPUT_INVALID', 'CHAT_SUMMARY_TOO_LARGE'].includes(error?.code)) return error;
  if (['DEEPSEEK_RATE_LIMITED', 'LOCAL_CHAT_RATE_LIMITED'].includes(error?.code)) return fault(429, 'CHAT_RATE_LIMITED', 'AI 제공자의 요청 한도에 도달했습니다. 잠시 후 다시 시도해 주세요.');
  if (error?.code === 'DEEPSEEK_BALANCE_ERROR') return fault(503, 'CHAT_BALANCE_ERROR', 'AI 제공자의 잔액을 확인해 주세요.');
  if (['DEEPSEEK_TIMEOUT', 'LOCAL_CHAT_TIMEOUT'].includes(error?.code)) return fault(504, 'CHAT_MODEL_TIMEOUT', 'AI 응답 시간이 초과되었습니다. 다시 시도해 주세요.');
  if (error?.code === 'LOCAL_CHAT_UNAVAILABLE') return fault(503, 'CHAT_MODEL_UNAVAILABLE', '로컬 AI 서버 또는 선택한 모델을 사용할 수 없습니다. 서버와 모델 실행 상태를 확인해 주세요.');
  if (error?.code === 'LOCAL_CHAT_AUTH_REQUIRED') return fault(503, 'CHAT_MODEL_AUTH_REQUIRED', '로컬 AI 서버의 인증 설정을 확인해 주세요.');
  return fault(502, 'CHAT_MODEL_FAILURE', 'AI 응답을 받지 못했습니다. 대화는 보존되었으며 다시 시도할 수 있습니다.');
}

function providerMetadata(value = {}) {
  const result = {};
  for (const key of ['provider', 'runtime']) {
    const pattern = key === 'provider' ? /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u : /^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,63}$/u;
    if (typeof value[key] === 'string' && pattern.test(value[key])) result[key] = value[key];
  }
  if (typeof value.local === 'boolean') result.local = value.local;
  return result;
}

/** Session orchestration; storage, provider transport and read-only files are separate ports. */
export function createWorkspaceChatService({ repository, model, files, runProvider, platformProvider } = {}) {
  if (!repository || !model || !files) throw new TypeError('Chat repository, model and files adapters are required.');
  const active = new Map(); let closing = false;
  const keyFor = (owner, id) => `${owner}\0${id}`;
  function open() { if (closing) throw fault(503, 'CHAT_CLOSED', '채팅 서비스를 종료하고 있습니다.'); }
  function unlocked(owner, id) {
    open();
    if (active.has(keyFor(owner, id))) throw fault(409, 'CHAT_SESSION_BUSY', '이 세션의 AI 응답을 기다려 주세요.');
  }
  async function requireSession(owner, id) {
    const session = await repository.getSession(owner, id);
    if (!session) throw fault(404, 'CHAT_SESSION_NOT_FOUND', '채팅 세션을 찾을 수 없습니다.');
    return session;
  }
  async function listModels() {
    open();
    let rows;
    try { rows = await model.listModels(); }
    catch { throw fault(503, 'CHAT_MODELS_UNAVAILABLE', 'AI 모델 목록을 불러오지 못했습니다. 잠시 후 다시 시도해 주세요.'); }
    if (!Array.isArray(rows)) throw fault(503, 'CHAT_MODELS_UNAVAILABLE', 'AI 모델 목록을 불러오지 못했습니다. 잠시 후 다시 시도해 주세요.');
    return rows;
  }
  async function availableModel(modelId) {
    const row = (await listModels()).find(item => item.id === modelId);
    if ((!row && isLocalChatModelId(modelId)) || (row && !row.available && row.provider === 'local')) {
      throw fault(503, 'CHAT_MODEL_UNAVAILABLE', '로컬 AI 서버 또는 선택한 모델을 사용할 수 없습니다. 서버와 모델 실행 상태를 확인해 주세요.');
    }
    if (!row) throw fault(400, 'CHAT_MODEL_INVALID', '등록된 채팅 모델을 선택해 주세요.');
    if (!row.available) throw fault(503, 'CHAT_MODEL_UNAVAILABLE', '서버의 AI 모델 설정을 확인해 주세요.');
    return row;
  }
  function contextFor(session, options = {}, selectedModel) {
    // Saved history remains readable while a runtime is offline. Budget lookup
    // uses only synchronous cached/configured metadata, never model discovery.
    let known = selectedModel;
    if (!known && typeof model.contextBudget === 'function') {
      try { known = model.contextBudget(session.modelId); } catch { /* Use the model-ID fallback. */ }
    }
    const budget = known?.applicationBudgetTokens;
    return computeContext(session, { ...options,
      ...(Number.isInteger(budget) && budget >= 512 && budget <= 8000 ? { applicationBudgetTokens: budget } : {}) });
  }
  const decorated = session => ({ ...session, context: contextFor(session) });
  async function getSession(owner, id) { return decorated(await requireSession(owner, id)); }

  async function managed(owner, id, externalSignal, action) {
    unlocked(owner, id);
    if (active.size >= 2) throw fault(429, 'CHAT_SERVICE_BUSY', '동시에 두 개의 AI 요청만 처리할 수 있습니다. 잠시 후 다시 시도해 주세요.');
    const controller = new AbortController();
    const abort = () => controller.abort(externalSignal?.reason);
    if (externalSignal?.aborted) abort();
    else externalSignal?.addEventListener('abort', abort, { once: true });
    // Register before invoking adapters, including synchronous or immediately rejected adapters.
    const entry = { controller, promise: null };
    const key = keyFor(owner, id); active.set(key, entry);
    entry.promise = Promise.resolve().then(() => {
      if (controller.signal.aborted) throw providerFailure(null, controller.signal);
      return action(controller.signal);
    });
    try { return await entry.promise; }
    finally { externalSignal?.removeEventListener('abort', abort); active.delete(key); }
  }

  async function requestContext({ files: paths = [], runId } = {}) {
    if (!Array.isArray(paths) || paths.length > MAX_FILES || paths.some(path => typeof path !== 'string')
      || new Set(paths).size !== paths.length) throw fault(400, 'CHAT_FILES_INVALID', '서로 다른 파일을 최대 네 개 선택해 주세요.');
    const result = { files: [] }; let totalCharacters = 0;
    for (const path of paths) {
      const file = await files.read(path);
      totalCharacters += file.content.length;
      if (totalCharacters > MAX_FILE_CONTEXT_CHARACTERS) {
        throw fault(413, 'CHAT_FILES_TOO_LARGE', '첨부 파일 내용은 합계 8000자까지 전달할 수 있습니다. 더 작은 파일을 선택해 주세요.');
      }
      result.files.push({ path: file.path, content: file.content, sha256: file.sha256, truncated: file.truncated });
    }
    if (runId !== undefined && runId !== null && runId !== '') {
      if (typeof runId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(runId)) {
        throw fault(400, 'CHAT_RUN_INVALID', '저장된 실행 ID를 선택해 주세요.');
      }
      if (!runProvider) throw fault(404, 'CHAT_RUN_NOT_FOUND', '저장된 실행을 찾을 수 없습니다.');
      let run;
      try { run = typeof runProvider === 'function' ? await runProvider(runId) : await runProvider.getRun(runId); }
      catch { throw fault(503, 'CHAT_RUN_UNAVAILABLE', '저장된 실행 정보를 읽지 못했습니다. 잠시 후 다시 시도해 주세요.'); }
      if (!run || !safeRunContext(run)?.id) throw fault(404, 'CHAT_RUN_NOT_FOUND', '저장된 실행을 찾을 수 없습니다.');
      result.run = safeRunContext(run);
    }
    if (platformProvider) {
      let platform;
      try { platform = await platformProvider(); }
      catch { throw fault(503, 'CHAT_CONTEXT_UNAVAILABLE', '프로젝트 정보를 읽지 못했습니다. 잠시 후 다시 시도해 주세요.'); }
      result.platform = { commitSha: safeText(platform?.source?.commitSha, 64),
        modules: (Array.isArray(platform?.modules) ? platform.modules : []).slice(0, 40)
          .map(item => ({ id: safeText(item.id, 80), status: safeText(item.status, 40), layer: safeText(item.layer, 40) })) };
    }
    return result;
  }

  async function compactInternal(owner, id, signal, { automatic = false, content = '', context = null, selectedModel } = {}) {
    const session = await requireSession(owner, id);
    const messages = session.messages.filter(message => message.sequence > session.compactedThroughSequence
      && ['user', 'assistant'].includes(message.role) && !['pending', 'failed', 'cancelled'].includes(message.status));
    let keep = KEEP_RECENT_MESSAGES;
    if (automatic) {
      // Reserve the largest allowed summary. Long CJK turns can
      // exhaust the application budget before four messages have accumulated.
      keep = [4, 2, 0].find(count => {
        if (messages.length <= count) return false;
        const retained = count ? messages.slice(-count) : [];
        const projection = contextFor({ ...session, messages: retained,
          summary: 'x'.repeat(MAX_SUMMARY_TOKENS * 4) }, { content, context }, selectedModel);
        return projection.estimatedInputTokens <= projection.applicationBudgetTokens && projection.promptBytes <= 63 * 1024;
      });
      if (keep === undefined) return session;
    }
    const old = keep ? messages.slice(0, -keep) : messages;
    if (!old.length) {
      if (automatic) return session;
      throw fault(409, 'CHAT_NOTHING_TO_COMPACT', '최근 네 개의 메시지를 보존하므로 대화가 더 쌓인 뒤 압축할 수 있습니다.');
    }
    const selected = selectedModel ?? await availableModel(session.modelId);
    if (signal.aborted) throw providerFailure(null, signal);
    const budget = contextFor(session, {}, selected).applicationBudgetTokens;
    const inputs = activeChatMessages({ messages: old, compactedThroughSequence: 0 });
    let offset = 0; let calls = 0; let summary = session.summary;
    while (offset < inputs.length) {
      if (calls >= MAX_COMPACTION_CALLS) {
        throw fault(413, 'CHAT_CONTEXT_TOO_LARGE', '한 번에 압축할 수 있는 대화 범위를 초과했습니다. 더 큰 문맥의 모델을 선택하거나 새 세션을 시작해 주세요. 기존 대화와 요약은 보존되었습니다.');
      }
      const batch = [];
      for (const message of inputs.slice(offset)) {
        const candidate = [...batch, message];
        const metrics = computeChatRequestMetrics({ purpose: 'compact', summary, messages: candidate });
        if (metrics.estimatedInputTokens > budget || metrics.promptBytes > 63 * 1024) break;
        batch.push(message);
      }
      if (!batch.length) {
        throw fault(413, 'CHAT_CONTEXT_TOO_LARGE', '단일 메시지와 기존 요약이 선택한 모델의 문맥 한도를 초과했습니다. 더 큰 문맥의 모델을 선택하거나 새 세션을 시작해 주세요.');
      }
      if (signal.aborted) throw providerFailure(null, signal);
      try {
        calls += 1;
        const response = await model.complete({ modelId: session.modelId, purpose: 'compact', summary, messages: batch, signal });
        if (signal.aborted) throw providerFailure(null, signal);
        const nextSummary = typeof response.content === 'string' ? redact(response.content.trim()) : '';
        if (!nextSummary || nextSummary.length > MAX_SUMMARY_CHARACTERS || estimateTokens(nextSummary) > MAX_SUMMARY_TOKENS) {
          throw fault(502, 'CHAT_SUMMARY_TOO_LARGE', '문맥 요약이 너무 크거나 비어 있습니다. 이전 대화와 요약은 보존되었습니다.');
        }
        summary = nextSummary;
      } catch (error) { throw providerFailure(error, signal); }
      offset += batch.length;
    }
    // Intermediate summaries exist only in memory: all chunks must finish before
    // advancing the stored boundary or replacing the previous summary.
    return repository.compactSession(owner, id, { summary,
      throughSequence: old.at(-1).sequence });
  }

  async function sendMessage(owner, id, body = {}, { signal } = {}) {
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).some(key => !['content', 'files', 'runId'].includes(key))
      || typeof body.content !== 'string' || !body.content.trim() || body.content.length > 6000) {
      throw fault(400, 'CHAT_MESSAGE_INVALID', '메시지는 1~6000자로 입력해 주세요.');
    }
    return managed(owner, id, signal, async requestSignal => {
      let session = await requireSession(owner, id);
      const selectedModel = await availableModel(session.modelId);
      const provider = providerMetadata(selectedModel);
      if (session.messages.length > 998) throw fault(409, 'CHAT_SESSION_FULL', '이 세션의 대화 저장 한도에 도달했습니다. 새 세션을 시작해 주세요.');
      const content = body.content.trim();
      const context = await requestContext(body);
      let metrics = contextFor(session, { content, context }, selectedModel);
      if (metrics.estimatedInputTokens >= metrics.compactionThresholdTokens || metrics.promptBytes > 60 * 1024) {
        session = await compactInternal(owner, id, requestSignal, { automatic: true, content, context, selectedModel });
        metrics = contextFor(session, { content, context }, selectedModel);
      }
      if (metrics.estimatedInputTokens > metrics.applicationBudgetTokens || metrics.promptBytes > 63 * 1024) {
        throw fault(413, 'CHAT_CONTEXT_TOO_LARGE', '문맥 예산을 초과했습니다. 첨부 파일을 줄이거나 더 짧게 입력해 주세요.');
      }
      if (requestSignal.aborted) throw providerFailure(null, requestSignal);
      await repository.appendMessage(owner, id, { role: 'user', content, status: 'completed',
        metadata: { files: context.files.map(({ path, sha256, truncated }) => ({ path, sha256, truncated })),
          ...(context.run ? { runId: context.run.id } : {}) } });
      const pending = await repository.appendMessage(owner, id, { role: 'assistant', content: '', status: 'pending',
        metadata: { modelId: session.modelId, ...provider, inputContext: metrics } });
      try {
        const response = await model.complete({ modelId: session.modelId, purpose: 'chat',
          summary: session.summary, messages: [...activeChatMessages(session), { role: 'user', content }], context, signal: requestSignal });
        if (requestSignal.aborted) throw providerFailure(null, requestSignal);
        if (typeof response.content !== 'string' || !response.content.trim() || response.content.length > 16000) {
          throw fault(502, 'CHAT_OUTPUT_INVALID', '모델의 응답 형식이 올바르지 않습니다. 다시 시도해 주세요.');
        }
        await repository.updateMessage(owner, id, pending.id, { content: redact(response.content), status: 'completed',
          metadata: { modelId: session.modelId, ...provider, ...providerMetadata(response), usage: response.usage ?? null, reportedModel: response.reportedModel ?? null,
            latencyMs: response.latencyMs ?? null, inputContext: metrics } });
      } catch (error) {
        const failure = providerFailure(error, requestSignal);
        await repository.updateMessage(owner, id, pending.id, { content: '', status: failure.code === 'CHAT_CANCELLED' ? 'cancelled' : 'failed',
          metadata: { modelId: session.modelId, ...provider, inputContext: metrics, error: { code: failure.code, message: failure.message } } });
        throw failure;
      }
      return getSession(owner, id);
    });
  }

  return {
    listModels,
    listSessions(owner) { open(); return repository.listSessions(owner, { limit: 100 }); },
    async createSession(owner, body = {}) {
      open();
      if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).some(key => !['title', 'modelId'].includes(key))) {
        throw fault(400, 'CHAT_SESSION_INVALID', '세션 이름과 모델을 입력해 주세요.');
      }
      const { title, modelId = 'deepseek-flash' } = body;
      await availableModel(modelId); open();
      return decorated(await repository.createSession({ owner, title, modelId }));
    },
    getSession,
    async updateSession(owner, id, body = {}) {
      unlocked(owner, id); await requireSession(owner, id);
      unlocked(owner, id);
      if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).some(key => !['title', 'modelId'].includes(key))) throw fault(400, 'CHAT_SESSION_INVALID', '세션 이름 또는 모델만 변경할 수 있습니다.');
      if (body.modelId !== undefined) await availableModel(body.modelId);
      // Discovery may wait for a local runtime; a send can acquire this session meanwhile.
      unlocked(owner, id);
      return decorated(await repository.updateSession(owner, id, body));
    },
    async deleteSession(owner, id) { unlocked(owner, id); await requireSession(owner, id); unlocked(owner, id); return repository.deleteSession(owner, id); },
    listFiles: path => files.list(path), readFile: path => files.read(path), sendMessage,
    compact(owner, id, { signal } = {}) {
      return managed(owner, id, signal, async requestSignal => decorated(await compactInternal(owner, id, requestSignal)));
    },
    async close() {
      closing = true;
      for (const entry of active.values()) entry.controller.abort();
      await Promise.allSettled([...active.values()].map(entry => entry.promise));
      repository.close?.();
    },
  };
}
