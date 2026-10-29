import test from 'node:test';
import assert from 'node:assert/strict';
import { createWorkspaceChatService } from '../workspace-chat.mjs';
import { computeChatRequestMetrics } from '../../../packages/models/workspace-chat.mjs';

function fixture({ complete, listModels, contextBudget, runProvider, platformProvider } = {}) {
  const sessions = new Map(); let serial = 0;
  const copy = value => structuredClone(value);
  const owned = (owner, id) => { const row = sessions.get(id); if (!row || row.owner !== owner) return null; return row; };
  const required = (owner, id) => { const row = owned(owner, id); if (!row) throw Object.assign(new Error('Missing'), { status: 404 }); return row; };
  const repository = {
    listSessions: owner => [...sessions.values()].filter(row => row.owner === owner).map(copy),
    createSession: ({ owner, title = '새 대화', modelId }) => { const row = { id: `s${++serial}`, owner, title, modelId,
      summary: '', compactedThroughSequence: 0, compactionCount: 0, messages: [] }; sessions.set(row.id, row); return copy(row); },
    getSession: (owner, id) => copy(owned(owner, id)),
    updateSession: (owner, id, changes) => Object.assign(required(owner, id), changes),
    deleteSession: (owner, id) => { required(owner, id); return sessions.delete(id); },
    appendMessage: (owner, id, message) => { const row = required(owner, id); const value = { ...copy(message),
      id: `m${++serial}`, sequence: row.messages.length + 1 }; row.messages.push(value); return copy(value); },
    updateMessage: (owner, id, messageId, changes) => Object.assign(required(owner, id).messages.find(row => row.id === messageId), copy(changes)),
    compactSession: (owner, id, changes) => { const row = required(owner, id); row.summary = changes.summary;
      row.compactedThroughSequence = changes.throughSequence; row.compactionCount += 1; return copy(row); },
    close() {},
  };
  const calls = [];
  const model = { listModels: listModels ?? (() => [{ id: 'deepseek-flash', provider: 'deepseek', available: true }, { id: 'missing-config', available: false }]),
    ...(contextBudget ? { contextBudget } : {}),
    complete: async input => { calls.push(input); return complete ? complete(input) : { content: input.purpose === 'compact' ? '확정된 결정과 남은 작업' : '답변',
      usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 }, latencyMs: 2 }; } };
  const files = { list: async path => ({ path, entries: [] }), read: async path => ({ path, content: `내용 ${path}`,
    sha256: 'a'.repeat(64), size: 20, truncated: false, language: 'text' }) };
  const service = createWorkspaceChatService({ repository, model, files, runProvider, platformProvider });
  return { service, repository, sessions, calls, files };
}

test('sessions are isolated, model availability validated, transcript and actual usage persist', async () => {
  const { service, calls } = fixture();
  const row = await service.createSession('alice', { title: '코드 검토' });
  await assert.rejects(() => service.getSession('bob', row.id), { status: 404 });
  await assert.rejects(() => service.createSession('alice', { modelId: 'rule-baseline' }), { status: 400 });
  await assert.rejects(() => service.createSession('alice', { modelId: 'missing-config' }), { status: 503 });
  const result = await service.sendMessage('alice', row.id, { content: '이 코드를 설명해 줘', files: ['README.md'] });
  assert.equal(result.messages.length, 2); assert.equal(result.messages[1].status, 'completed');
  assert.equal(result.context.previousProviderUsage.total_tokens, 15);
  assert.equal(calls[0].context.files[0].path, 'README.md');
  assert.equal(result.messages[0].metadata.files[0].sha256, 'a'.repeat(64));
  assert.equal(JSON.stringify(result).includes('내용 README.md'), false);
  await service.close();
});

test('run and platform context is allowlisted, credentials and raw requests are excluded', async () => {
  const { service, calls } = fixture({ runProvider: async () => ({ id: 'run-1', status: 'completed', simulated: true,
    target: 'https://user:secret@example.test/?api_key=secret', cookie: 'sensitive-cookie', requests: [{ body: 'sensitive-body' }],
    events: [{ type: 'evidence', message: 'Authorization: Bearer sensitive-token' }] }),
  platformProvider: async () => ({ source: { commitSha: 'a'.repeat(40), secret: 'sensitive-source' }, modules: [{ id: 'agent', status: 'active' }], secret: 'sensitive-platform' }) });
  const row = await service.createSession('alice', {});
  await service.sendMessage('alice', row.id, { content: '결과 검토', runId: 'run-1' });
  const context = JSON.stringify(calls[0].context);
  assert.equal(context.includes('sensitive-'), false); assert.equal(context.includes('user:secret'), false);
  assert.equal(calls[0].context.run.simulated, true); assert.equal(calls[0].context.platform.modules[0].id, 'agent');
  await service.close();
});

test('manual compaction retains recent four messages and full transcript, model receives summary thereafter', async () => {
  const { service, repository, calls } = fixture(); const row = await service.createSession('alice', {});
  for (let index = 0; index < 8; index += 1) repository.appendMessage('alice', row.id,
    { role: index % 2 ? 'assistant' : 'user', content: `메시지 ${index}`, status: 'completed' });
  const result = await service.compact('alice', row.id);
  assert.equal(result.messages.length, 8); assert.equal(result.compactedThroughSequence, 4); assert.equal(result.compactionCount, 1);
  assert.equal(calls[0].messages.length, 4);
  await service.sendMessage('alice', row.id, { content: '이어서' });
  assert.equal(calls[1].messages.length, 5); assert.match(calls[1].summary, /남은 작업/);
  assert.equal(calls[1].messages[0].content, '메시지 4');
  await service.close();
});

test('automatic compaction triggers at application threshold and preserves all stored messages', async () => {
  const { service, repository, calls } = fixture(); const row = await service.createSession('alice', {});
  for (let index = 0; index < 10; index += 1) repository.appendMessage('alice', row.id,
    { role: index % 2 ? 'assistant' : 'user', content: 'x'.repeat(2600), status: 'completed' });
  const result = await service.sendMessage('alice', row.id, { content: '다음 질문' });
  assert.deepEqual(calls.map(input => input.purpose), ['compact', 'chat']);
  assert.equal(result.messages.length, 12); assert.equal(result.compactionCount, 1);
  assert.ok(result.messages.at(-1).metadata.inputContext.estimatedInputTokens <= 8000);
  await service.close();
});

test('automatic compaction adapts to long CJK turns before four messages have accumulated', async () => {
  const { service, repository, calls } = fixture(); const row = await service.createSession('alice', {});
  repository.appendMessage('alice', row.id, { role: 'user', content: '한'.repeat(2400), status: 'completed' });
  repository.appendMessage('alice', row.id, { role: 'assistant', content: '답'.repeat(1500), status: 'completed' });
  const result = await service.sendMessage('alice', row.id, { content: '이어서 설명해 줘' });
  assert.deepEqual(calls.map(input => input.purpose), ['compact', 'compact', 'chat']);
  assert.equal(calls[0].messages.length, 1); assert.equal(calls[1].messages.length, 1); assert.equal(calls[2].messages.length, 1);
  assert.ok(calls.filter(input => input.purpose === 'compact').every(input => computeChatRequestMetrics(input).estimatedInputTokens <= 8000));
  assert.equal(result.compactedThroughSequence, 2); assert.equal(result.messages.length, 4);
  assert.ok(result.messages.at(-1).metadata.inputContext.estimatedInputTokens <= 8000);
  await service.close();
});

test('failed compaction never changes summary, sequence or transcript and exposes only safe errors', async () => {
  const { service, repository } = fixture({ complete: async () => { throw new Error('raw-private-provider-secret'); } });
  const row = await service.createSession('alice', {});
  for (let index = 0; index < 8; index += 1) repository.appendMessage('alice', row.id,
    { role: index % 2 ? 'assistant' : 'user', content: 'test', status: 'completed' });
  await assert.rejects(() => service.compact('alice', row.id), error => error.code === 'CHAT_MODEL_FAILURE'
    && !error.message.includes('raw-private'));
  const result = await service.getSession('alice', row.id);
  assert.equal(result.summary, ''); assert.equal(result.compactedThroughSequence, 0); assert.equal(result.messages.length, 8);
  await service.close();
});

test('provider failures leave a failed assistant marker, and new sends exclude that marker', async () => {
  let attempt = 0;
  const { service, calls } = fixture({ complete: async () => {
    if (++attempt === 1) throw Object.assign(new Error('secret'), { code: 'DEEPSEEK_TIMEOUT' });
    return { content: '재시도 응답' };
  } });
  const row = await service.createSession('alice', {});
  await assert.rejects(() => service.sendMessage('alice', row.id, { content: '질문' }), { status: 504, code: 'CHAT_MODEL_TIMEOUT' });
  const failed = await service.getSession('alice', row.id);
  assert.equal(failed.messages[1].status, 'failed'); assert.equal(failed.messages[1].content, '');
  assert.equal(JSON.stringify(failed).includes('secret'), false);
  const result = await service.sendMessage('alice', row.id, { content: '다시 설명해 줘' });
  assert.equal(calls[1].messages.length, 2); assert.equal(result.messages[3].status, 'completed');
  await service.close();
});

test('per-session and global concurrency bounds reject overlaps; shutdown cancels without publishing output', async () => {
  const { service } = fixture({ complete: ({ signal }) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => reject(Object.assign(new Error('cancelled'), { name: 'AbortError' })), { once: true });
  }) });
  const a = await service.createSession('alice', {}); const b = await service.createSession('alice', {}); const c = await service.createSession('alice', {});
  const first = service.sendMessage('alice', a.id, { content: 'a' });
  const second = service.sendMessage('alice', b.id, { content: 'b' });
  await assert.rejects(() => service.sendMessage('alice', a.id, { content: 'same' }), { status: 409 });
  await assert.rejects(() => service.sendMessage('alice', c.id, { content: 'third' }), { status: 429 });
  await assert.rejects(() => service.deleteSession('alice', a.id), { status: 409 });
  await new Promise(resolve => setImmediate(resolve));
  const stopped = Promise.allSettled([first, second]);
  await service.close();
  assert.ok((await stopped).every(result => result.status === 'rejected' && result.reason.code === 'CHAT_CANCELLED'));
  await assert.rejects(() => service.createSession('alice', {}), { status: 503 });
});

test('oversized new content, total attachments and uncompactable context are rejected before persistence', async () => {
  const { service, files } = fixture(); const row = await service.createSession('alice', {});
  await assert.rejects(() => service.sendMessage('alice', row.id, { content: 'x'.repeat(6001) }), { status: 400 });
  files.read = async path => ({ path, content: 'x'.repeat(5000) });
  await assert.rejects(() => service.sendMessage('alice', row.id, { content: 'text', files: ['a', 'b'] }), { status: 413 });
  await assert.rejects(() => service.sendMessage('alice', row.id, { content: '한'.repeat(5000) }), { code: 'CHAT_CONTEXT_TOO_LARGE' });
  assert.equal((await service.getSession('alice', row.id)).messages.length, 0);
  await service.close();
});

test('asynchronous local discovery supports selection, chat and compaction while publishing provider metadata', async () => {
  const local = { id: 'local:ollama:0123456789abcdef0123', name: 'Qwen 3', available: true, provider: 'local', runtime: 'ollama', local: true, applicationBudgetTokens: 5632 };
  const { service, repository, calls } = fixture({
    listModels: async () => { await new Promise(resolve => setImmediate(resolve)); return [local, { id: 'deepseek-flash', provider: 'deepseek', available: true }]; },
    complete: async input => ({ content: input.purpose === 'compact' ? '로컬 대화 요약' : '로컬 응답', provider: 'local', runtime: 'ollama' }),
  });
  const row = await service.createSession('alice', { modelId: local.id });
  assert.deepEqual((await service.listModels())[0], local);
  const answer = await service.sendMessage('alice', row.id, { content: '로컬 모델로 설명해 줘' });
  assert.equal(calls[0].modelId, local.id);
  assert.equal(answer.messages[1].metadata.provider, 'local');
  assert.equal(answer.messages[1].metadata.runtime, 'ollama');
  assert.equal(answer.messages[1].metadata.local, true);
  assert.equal(answer.context.applicationBudgetTokens, 5632);
  for (let index = 0; index < 6; index += 1) repository.appendMessage('alice', row.id, { role: index % 2 ? 'assistant' : 'user', content: `내용 ${index}`, status: 'completed' });
  const compacted = await service.compact('alice', row.id);
  assert.equal(compacted.compactionCount, 1); assert.equal(calls.at(-1).modelId, local.id);
  const updated = await service.updateSession('alice', row.id, { modelId: 'deepseek-flash' });
  assert.equal(updated.modelId, 'deepseek-flash');
  await service.close();
});

test('unavailable discovery cannot break saved session history, rename or context metrics', async () => {
  let offline = false;
  const { service, sessions } = fixture({ listModels: async () => {
    if (offline) throw new Error('private endpoint /Users/private configuration');
    return [{ id: 'local:llama-cpp:0123456789abcdef0123', provider: 'local', runtime: 'llama.cpp', available: true }];
  } });
  const row = await service.createSession('alice', { modelId: 'local:llama-cpp:0123456789abcdef0123' });
  offline = true;
  const restored = await service.getSession('alice', row.id);
  assert.equal(restored.context.applicationBudgetTokens, 5632);
  assert.equal((await service.listSessions('alice')).length, 1);
  assert.equal((await service.updateSession('alice', row.id, { title: '오프라인 대화' })).title, '오프라인 대화');
  await assert.rejects(() => service.sendMessage('alice', row.id, { content: '질문' }), failure => failure.code === 'CHAT_MODELS_UNAVAILABLE'
    && failure.status === 503 && !failure.message.includes('private'));
  assert.equal(sessions.get(row.id).messages.length, 0);
  await service.close();
});

test('local runtime errors become safe status messages and preserve provider metadata in failed markers', async () => {
  for (const [code, expectedStatus, expectedCode] of [
    ['LOCAL_CHAT_TIMEOUT', 504, 'CHAT_MODEL_TIMEOUT'], ['LOCAL_CHAT_UNAVAILABLE', 503, 'CHAT_MODEL_UNAVAILABLE'],
    ['LOCAL_CHAT_AUTH_REQUIRED', 503, 'CHAT_MODEL_AUTH_REQUIRED'], ['LOCAL_CHAT_ABORTED', 499, 'CHAT_CANCELLED'],
    ['LOCAL_CHAT_RATE_LIMITED', 429, 'CHAT_RATE_LIMITED'],
  ]) {
    const { service } = fixture({
      listModels: async () => [{ id: 'local:llama-cpp:0123456789abcdef0123', provider: 'local', runtime: 'llama.cpp', available: true }],
      complete: async () => { throw Object.assign(new Error('private configuration http://127.0.0.1:8080/secret'), { code }); },
    });
    const row = await service.createSession('alice', { modelId: 'local:llama-cpp:0123456789abcdef0123' });
    await assert.rejects(() => service.sendMessage('alice', row.id, { content: '질문' }), failure => failure.status === expectedStatus && failure.code === expectedCode
      && !failure.message.includes('private') && !failure.message.includes('127.0.0.1'));
    const result = await service.getSession('alice', row.id);
    assert.equal(result.messages[1].metadata.provider, 'local');
    assert.equal(result.messages[1].metadata.runtime, 'llama.cpp');
    assert.equal(result.messages[1].status, code === 'LOCAL_CHAT_ABORTED' ? 'cancelled' : 'failed');
    assert.equal(JSON.stringify(result).includes('private configuration'), false);
    await service.close();
  }
});

test('changing models rechecks the session lock after asynchronous runtime discovery', async () => {
  const rows = [{ id: 'deepseek-flash', provider: 'deepseek', available: true }, { id: 'local:ollama:qwen3', provider: 'local', runtime: 'ollama', available: true }];
  let waitForDiscovery = false; let discoveryStarted; let releaseDiscovery;
  const discovered = new Promise(resolve => { discoveryStarted = resolve; });
  let completionStarted; let releaseCompletion;
  const completing = new Promise(resolve => { completionStarted = resolve; });
  const { service } = fixture({
    listModels: async () => {
      if (waitForDiscovery) {
        waitForDiscovery = false; discoveryStarted();
        return new Promise(resolve => { releaseDiscovery = resolve; });
      }
      return rows;
    },
    complete: () => { completionStarted(); return new Promise(resolve => { releaseCompletion = resolve; }); },
  });
  const row = await service.createSession('alice', {});
  waitForDiscovery = true;
  const update = service.updateSession('alice', row.id, { modelId: 'local:ollama:qwen3' });
  const rejectedUpdate = assert.rejects(update, { status: 409, code: 'CHAT_SESSION_BUSY' });
  await discovered;
  const sending = service.sendMessage('alice', row.id, { content: '원래 모델로 답변해 줘' });
  await completing; releaseDiscovery(rows); await rejectedUpdate;
  releaseCompletion({ content: '답변', provider: 'deepseek' });
  assert.equal((await sending).modelId, 'deepseek-flash');
  await service.close();
});

test('shutdown during asynchronous model discovery does not create a session afterward', async () => {
  let discoveryStarted; let releaseDiscovery;
  const discovered = new Promise(resolve => { discoveryStarted = resolve; });
  const { service, sessions } = fixture({ listModels: () => { discoveryStarted(); return new Promise(resolve => { releaseDiscovery = resolve; }); } });
  const creating = service.createSession('alice', {});
  const rejectedCreate = assert.rejects(creating, { status: 503, code: 'CHAT_CLOSED' });
  await discovered; await service.close();
  releaseDiscovery([{ id: 'deepseek-flash', available: true }]);
  await rejectedCreate; assert.equal(sessions.size, 0);
});

test('local input budgeting reserves 2048 output tokens and 512 headroom while DeepSeek retains its existing budget', async () => {
  const localId = 'local:llama-cpp:0123456789abcdef0123';
  const { service, repository, calls } = fixture({ listModels: async () => [
    { id: localId, provider: 'local', runtime: 'llama.cpp', available: true, applicationBudgetTokens: 5632 },
    { id: 'deepseek-flash', provider: 'deepseek', available: true, applicationBudgetTokens: 8000 },
  ] });
  const local = await service.createSession('alice', { modelId: localId });
  assert.equal(local.context.applicationBudgetTokens, 5632);
  assert.equal(local.context.compactionThresholdTokens, Math.floor(5632 * 0.8));
  await assert.rejects(() => service.sendMessage('alice', local.id, { content: '한'.repeat(3000) }), { status: 413, code: 'CHAT_CONTEXT_TOO_LARGE' });
  assert.equal((await service.getSession('alice', local.id)).messages.length, 0);
  assert.equal(calls.length, 0);
  for (let index = 0; index < 10; index += 1) repository.appendMessage('alice', local.id,
    { role: index % 2 ? 'assistant' : 'user', content: 'x'.repeat(1800), status: 'completed' });
  const compacted = await service.sendMessage('alice', local.id, { content: '이어서' });
  assert.deepEqual(calls.map(input => input.purpose), ['compact', 'chat']);
  assert.equal(compacted.messages.at(-1).metadata.inputContext.applicationBudgetTokens, 5632);
  assert.ok(compacted.messages.at(-1).metadata.inputContext.estimatedInputTokens <= 5632);
  const cloud = await service.createSession('alice', { modelId: 'deepseek-flash' });
  assert.equal(cloud.context.applicationBudgetTokens, 8000);
  assert.equal((await service.sendMessage('alice', cloud.id, { content: '한'.repeat(3000) })).messages.length, 2);
  await service.close();
});

test('saved sessions use synchronous cached local budgets without running model discovery', async () => {
  const localId = 'local:lm-studio:0123456789abcdef0123';
  let discoveries = 0;
  const { service } = fixture({
    listModels: async () => { discoveries += 1; return [{ id: localId, provider: 'local', runtime: 'LM Studio', available: true, applicationBudgetTokens: 1536 }]; },
    contextBudget: () => ({ applicationBudgetTokens: 1536 }),
  });
  const row = await service.createSession('alice', { modelId: localId });
  assert.equal(row.context.applicationBudgetTokens, 1536);
  const restored = await service.getSession('alice', row.id);
  assert.equal(restored.context.applicationBudgetTokens, 1536);
  assert.equal(restored.context.compactionThresholdTokens, Math.floor(1536 * 0.8));
  assert.equal(discoveries, 1);
  await service.close();
});

test('a missing local runtime is unavailable while an unsupported provider is rejected without mutating history', async () => {
  const { service, repository, calls } = fixture();
  for (const [modelId, expectedStatus] of [
    ['local:ollama:0123456789abcdef0123', 503], ['local:unsupported:0123456789abcdef0123', 400],
  ]) {
    const row = repository.createSession({ owner: 'alice', modelId });
    assert.equal((await service.getSession('alice', row.id)).messages.length, 0);
    await assert.rejects(() => service.sendMessage('alice', row.id, { content: '질문' }), { status: expectedStatus });
    assert.equal((await service.getSession('alice', row.id)).messages.length, 0);
  }
  assert.equal(calls.length, 0); await service.close();
});

test('local automatic compaction splits oversized history into bounded chunks and commits only the final summary', async () => {
  const localId = 'local:llama-cpp:0123456789abcdef0123'; let summaries = 0;
  const { service, repository, calls } = fixture({
    listModels: async () => [{ id: localId, provider: 'local', runtime: 'llama.cpp', available: true, applicationBudgetTokens: 5632 }],
    complete: async input => {
      const metrics = computeChatRequestMetrics(input);
      assert.ok(metrics.estimatedInputTokens <= 5632, `model received ${metrics.estimatedInputTokens} tokens`);
      assert.ok(metrics.promptBytes <= 63 * 1024);
      return { content: input.purpose === 'compact' ? `중간 요약 ${++summaries}` : '최종 응답', provider: 'local' };
    },
  });
  const row = await service.createSession('alice', { modelId: localId });
  for (let index = 0; index < 8; index += 1) repository.appendMessage('alice', row.id,
    { role: index % 2 ? 'assistant' : 'user', content: `${index}:${'x'.repeat(4000)}`, status: 'completed' });
  const result = await service.sendMessage('alice', row.id, { content: '이어서 설명해 줘' });
  assert.deepEqual(calls.map(input => input.purpose), ['compact', 'compact', 'chat']);
  const chunks = calls.filter(input => input.purpose === 'compact');
  assert.deepEqual(chunks.flatMap(input => input.messages.map(message => message.content.slice(0, 2))), ['0:', '1:', '2:', '3:', '4:', '5:']);
  assert.equal(chunks[0].summary, ''); assert.equal(chunks[1].summary, '중간 요약 1');
  assert.equal(result.summary, '중간 요약 2'); assert.equal(result.compactionCount, 1);
  assert.equal(result.compactedThroughSequence, 6); assert.equal(result.messages.length, 10);
  assert.equal(calls.at(-1).summary, '중간 요약 2');
  await service.close();
});

test('a later compact-chunk failure preserves the previous summary, boundary and full transcript', async () => {
  const localId = 'local:llama-cpp:0123456789abcdef0123'; let summaries = 0;
  const { service, repository, sessions, calls } = fixture({
    listModels: async () => [{ id: localId, provider: 'local', runtime: 'llama.cpp', available: true, applicationBudgetTokens: 5632 }],
    complete: async () => {
      if (++summaries === 2) throw new Error('private local server error');
      return { content: '메모리에만 보존할 중간 요약' };
    },
  });
  const row = await service.createSession('alice', { modelId: localId });
  sessions.get(row.id).summary = '이전 요약'; sessions.get(row.id).compactionCount = 2;
  for (let index = 0; index < 8; index += 1) repository.appendMessage('alice', row.id,
    { role: index % 2 ? 'assistant' : 'user', content: 'x'.repeat(4000), status: 'completed' });
  const before = repository.getSession('alice', row.id);
  await assert.rejects(() => service.sendMessage('alice', row.id, { content: '이어서' }), failure => failure.code === 'CHAT_MODEL_FAILURE' && !failure.message.includes('private'));
  assert.deepEqual(repository.getSession('alice', row.id), before);
  assert.deepEqual(calls.map(input => input.purpose), ['compact', 'compact']);
  await service.close();
});

test('one oversized message is rejected before compaction and an eight-call cap bounds a huge history', async () => {
  const localId = 'local:llama-cpp:0123456789abcdef0123';
  const { service, repository, calls } = fixture({
    listModels: async () => [{ id: localId, provider: 'local', runtime: 'llama.cpp', available: true, applicationBudgetTokens: 5632 }],
    complete: async () => ({ content: '짧은 요약' }),
  });
  const one = await service.createSession('alice', { modelId: localId });
  repository.appendMessage('alice', one.id, { role: 'assistant', content: '한'.repeat(4000), status: 'completed' });
  await assert.rejects(() => service.sendMessage('alice', one.id, { content: '이어서' }), { status: 413, code: 'CHAT_CONTEXT_TOO_LARGE' });
  assert.equal(calls.length, 0); assert.equal(repository.getSession('alice', one.id).compactionCount, 0);
  const many = await service.createSession('alice', { modelId: localId });
  for (let index = 0; index < 30; index += 1) repository.appendMessage('alice', many.id,
    { role: index % 2 ? 'assistant' : 'user', content: 'x'.repeat(10000), status: 'completed' });
  const before = repository.getSession('alice', many.id);
  await assert.rejects(() => service.sendMessage('alice', many.id, { content: '이어서' }), { status: 413, code: 'CHAT_CONTEXT_TOO_LARGE' });
  assert.equal(calls.length, 8); assert.ok(calls.every(input => input.purpose === 'compact'));
  assert.deepEqual(repository.getSession('alice', many.id), before);
  await service.close();
});
