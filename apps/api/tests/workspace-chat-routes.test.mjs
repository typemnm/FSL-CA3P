import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { once } from 'node:events';
import { createDashboardServer } from '../server.mjs';
import { createAuthentication, hashAccount } from '../auth.mjs';

async function fixture(t, { paused = false, sendMessage, listModels } = {}) {
  const calls = [];
  const service = {
    listModels: listModels ?? (() => [{ id: 'deepseek-flash', available: true }]),
    listSessions: owner => [{ id: 'session-1', title: owner }],
    createSession: (owner, body) => { calls.push({ owner, body }); return { id: 'session-1', ...body }; },
    getSession: (owner, id) => ({ id, title: owner, messages: [] }),
    updateSession: (owner, id, body) => ({ id, title: owner, ...body }),
    deleteSession: (owner, id) => calls.push({ owner, deleted: id }),
    sendMessage: sendMessage ?? ((owner, id, body) => ({ id, title: owner, messages: [{ content: body.content }] })),
    compact: (owner, id) => ({ id, title: owner, summary: '요약', compactionCount: 1 }),
    listFiles: path => ({ path, entries: [] }), readFile: path => ({ path, content: 'fixture source' }),
    close: () => calls.push({ closed: true }),
  };
  const runtime = { close: async () => {}, getState: () => ({}), subscribe: () => () => {} };
  const auth = createAuthentication({ users: ['admin', 'operator', 'viewer'].map(role => hashAccount(role, 'test-password', role)) });
  const server = createDashboardServer({ runtime, auth, workspaceChat: service, maintenanceCheck: () => paused });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => server.shutdown());
  const base = `http://127.0.0.1:${server.address().port}`;
  const api = (path, { method = 'GET', body, headers = {} } = {}) => new Promise((resolve, reject) => {
    const req = request(base + path, { method, headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers }, agent: false }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, value: JSON.parse(Buffer.concat(chunks).toString()) }));
    });
    req.on('error', reject); req.end(body === undefined ? undefined : JSON.stringify(body));
  });
  const login = async username => {
    const r = await api('/api/auth/login', { method: 'POST', body: { username, password: 'test-password' } });
    return { Cookie: r.headers['set-cookie'][0].split(';')[0], 'X-CSRF-Token': r.value.csrfToken };
  };
  return { server, base, api, login, calls };
}

test('chat routes keep authentication, viewer permissions, CSRF and actor identity', async t => {
  const f = await fixture(t);
  assert.equal((await f.api('/api/chat/models')).status, 401);
  const viewer = await f.login('viewer');
  assert.deepEqual((await f.api('/api/chat/sessions', { headers: viewer })).value.sessions, [{ id: 'session-1', title: 'viewer' }]);
  assert.equal((await f.api('/api/chat/sessions', { method: 'POST', headers: viewer, body: { modelId: 'deepseek-flash' } })).status, 403);
  const operator = await f.login('operator');
  assert.equal((await f.api('/api/chat/sessions', { method: 'POST', headers: { Cookie: operator.Cookie }, body: { modelId: 'deepseek-flash' } })).status, 403);
  const created = await f.api('/api/chat/sessions', { method: 'POST', headers: operator, body: { modelId: 'deepseek-flash' } });
  assert.equal(created.status, 200); assert.equal(f.calls[0].owner, 'operator');
  assert.equal((await f.api('/api/chat/models', { headers: { ...operator, Origin: 'https://foreign.invalid' } })).status, 403);
  assert.equal((await f.api('/api/chat/sessions', { method: 'POST', headers: operator, body: { owner: 'admin', modelId: 'deepseek-flash' } })).status, 400);
});

test('chat transport exposes sessions, file context and compaction with bounded request shapes', async t => {
  const f = await fixture(t); const headers = await f.login('admin');
  assert.equal((await f.api('/api/chat/models', { headers })).value.models[0].id, 'deepseek-flash');
  assert.equal((await f.api('/api/chat/files?path=docs', { headers })).value.path, 'docs');
  assert.equal((await f.api('/api/chat/file?path=README.md', { headers })).value.content, 'fixture source');
  assert.equal((await f.api('/api/chat/sessions/session-1', { headers })).value.session.title, 'admin');
  assert.equal((await f.api('/api/chat/sessions/session-1', { method: 'PATCH', headers, body: { title: '새 제목' } })).value.session.title, '새 제목');
  assert.equal((await f.api('/api/chat/sessions/session-1/messages', { method: 'POST', headers, body: { content: '분석해줘', files: ['README.md'] } })).value.session.messages[0].content, '분석해줘');
  assert.equal((await f.api('/api/chat/sessions/session-1/compact', { method: 'POST', headers, body: {} })).value.session.compactionCount, 1);
  assert.equal((await f.api('/api/chat/sessions/session-1/messages', { headers })).status, 405);
  assert.equal((await f.api('/api/chat/sessions/session-1/compact', { method: 'POST', headers, body: { summary: 'forged' } })).status, 400);
  assert.equal((await f.api('/api/chat/sessions/session-1/messages', { method: 'POST', headers, body: { content: 'x'.repeat(40_000) } })).status, 413);
  assert.equal((await f.api('/api/chat/sessions/session-1', { method: 'DELETE', headers })).value.deleted, true);
});

test('deployment maintenance pauses chat mutations and leaves history readable', async t => {
  const f = await fixture(t, { paused: true }); const headers = await f.login('admin');
  assert.equal((await f.api('/api/chat/sessions', { headers })).status, 200);
  assert.equal((await f.api('/api/chat/sessions/session-1/messages', { method: 'POST', headers, body: { content: '질문' } })).status, 503);
});

test('asynchronous local model discovery and provider metadata pass through authenticated HTTP routes', async t => {
  const model = { id: 'local:ollama:0123456789abcdef0123', name: 'Qwen 3', provider: 'local', runtime: 'ollama',
    local: true, available: true, applicationBudgetTokens: 5632, contextWindowTokens: 8192, maxOutputTokens: 2048 };
  const f = await fixture(t, {
    listModels: async () => { await new Promise(resolve => setImmediate(resolve)); return [model]; },
    sendMessage: async (owner, id, body) => ({ id, title: owner, modelId: model.id,
      messages: [{ role: 'assistant', content: '로컬 응답', metadata: { provider: model.provider, runtime: model.runtime } }] }),
  });
  const headers = await f.login('admin');
  const result = await f.api('/api/chat/models', { headers });
  assert.equal(result.status, 200); assert.deepEqual(result.value.models, [model]);
  const created = await f.api('/api/chat/sessions', { method: 'POST', headers, body: { modelId: model.id } });
  assert.equal(created.status, 200); assert.equal(created.value.session.modelId, model.id);
  const answer = await f.api('/api/chat/sessions/session-1/messages', { method: 'POST', headers, body: { content: '로컬 모델로 설명해 줘' } });
  assert.equal(answer.status, 200); assert.equal(answer.value.session.messages[0].metadata.provider, 'local');
  assert.equal(answer.value.session.messages[0].metadata.runtime, 'ollama');
});

test('disconnecting a chat request aborts the provider signal', async t => {
  let started; const ready = new Promise(resolve => { started = resolve; });
  let cancelled; const aborted = new Promise(resolve => { cancelled = resolve; });
  const f = await fixture(t, { sendMessage: (owner, id, body, { signal }) => new Promise((resolve, reject) => {
    started(); signal.addEventListener('abort', () => { cancelled(); reject(Object.assign(new Error('취소됨'), { status: 499 })); }, { once: true });
  }) });
  const headers = await f.login('admin');
  const req = request(f.base + '/api/chat/sessions/session-1/messages', { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' } });
  req.on('error', () => {}); req.end(JSON.stringify({ content: '질문' }));
  await ready; req.destroy();
  await Promise.race([aborted, new Promise((_, reject) => { const timer = setTimeout(() => reject(new Error('provider was not cancelled')), 2000); timer.unref(); })]);
});
