import test from 'node:test';
import assert from 'node:assert/strict';
import { createWorkspaceChatService } from '../workspace-chat.mjs';

function fixture({ complete, runProvider, platformProvider } = {}) {
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
  const model = { listModels: () => [{ id: 'deepseek-flash', available: true }, { id: 'missing-config', available: false }],
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
  assert.deepEqual(calls.map(input => input.purpose), ['compact', 'chat']);
  assert.equal(calls[0].messages.length, 2); assert.equal(calls[1].messages.length, 1);
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
