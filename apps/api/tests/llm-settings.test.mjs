import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDashboardServer, createLlmSettings } from '../server.mjs';
import { createAuthentication, hashAccount } from '../auth.mjs';

const KEY = 'sk-live-secret-abcdef123456';
const state = { instanceId: 'llm-settings', mode: 'core-fixture', run: { id: 'run-a', mode: 'core-fixture', status: 'idle', events: [] }, lab: {} };

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-api-llm-'));
  const providerRequests = [];
  const fetchImpl = async (url, init) => {
    providerRequests.push({ url, authorization: init.headers.Authorization });
    const body = url === 'http://127.0.0.1:11434/api/tags' ? { models: [{ name: 'qwen3:8b' }] }
      : url.endsWith('/models') && init.headers.Authorization === `Bearer ${KEY}` ? { data: [{ id: 'deepseek-chat' }] } : null;
    if (!body) throw new Error('connection refused');
    return { ok: true, status: 200, headers: { get: () => null }, body: null, text: async () => JSON.stringify(body) };
  };
  const runtime = { getState: () => state, listModels: () => [], close: async () => {}, subscribe: () => () => {} };
  const auth = createAuthentication({ users: ['admin', 'operator', 'viewer'].map(role => hashAccount(role, 'test-password', role)) });
  const server = createDashboardServer({ runtime, auth, platformProvider: async () => ({ source: { commitSha: 'test-only' } }),
    llmSettings: createLlmSettings({ env: { CA3P_LLM_PROVIDERS_PATH: join(directory, 'llm-providers.json') }, fetchImpl }) });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { await server.shutdown(); await rm(directory, { recursive: true, force: true }); });
  return { base: `http://127.0.0.1:${server.address().port}`, providerRequests };
}
function api(base, path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = request(base + path, { method, headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers }, agent: false }, res => {
      let text = ''; res.setEncoding('utf8'); res.on('data', part => { text += part; });
      res.on('end', () => { let value; try { value = JSON.parse(text); } catch { value = text; } resolve({ status: res.statusCode, body: value, text }); });
    });
    req.on('error', reject);
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}
/** Logs in and returns the session cookie plus CSRF header. */
function login(base, username) {
  return new Promise((resolve, reject) => {
    const req = request(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, agent: false }, res => {
      let text = ''; res.on('data', part => { text += part; });
      res.on('end', () => resolve({ Cookie: res.headers['set-cookie'][0].split(';')[0], 'X-CSRF-Token': JSON.parse(text).csrfToken }));
    });
    req.on('error', reject); req.end(JSON.stringify({ username, password: 'test-password' }));
  });
}

test('only an administrator can register providers and the key is never returned', async t => {
  const { base } = await fixture(t);
  const route = '/api/modules/llm/providers';
  const body = { name: 'Team DeepSeek', kind: 'deepseek', model: 'deepseek-chat', apiKey: KEY };
  assert.equal((await api(base, route)).status, 401);
  const viewer = await login(base, 'viewer');
  assert.deepEqual((await api(base, route, { headers: viewer })).body.providers, []);
  assert.equal((await api(base, route, { method: 'POST', headers: viewer, body })).status, 403);
  assert.equal((await api(base, route, { method: 'POST', headers: await login(base, 'operator'), body })).status, 403);
  const admin = await login(base, 'admin');
  assert.equal((await api(base, route, { method: 'POST', headers: { Cookie: admin.Cookie }, body })).status, 403);
  assert.equal((await api(base, route, { method: 'POST', headers: admin, body: { ...body, apiKey: 'x' } })).status, 400);
  const created = await api(base, route, { method: 'POST', headers: admin, body });
  assert.equal(created.status, 201);
  assert.ok(!created.text.includes(KEY));
  assert.equal(created.body.provider.keyHint, '…3456');
  const listed = await api(base, route, { headers: viewer });
  assert.ok(!listed.text.includes(KEY));
  assert.equal(listed.body.providers.length, 1);
  const id = created.body.provider.id;
  assert.equal((await api(base, `${route}/${id}`, { method: 'DELETE', headers: viewer })).status, 403);
  assert.equal((await api(base, `${route}/${id}`, { method: 'DELETE', headers: admin })).body.providers.length, 0);
  assert.equal((await api(base, `${route}/${id}`, { method: 'DELETE', headers: admin })).status, 404);
});

test('connection test uses the stored key server-side; local discovery and selection follow roles', async t => {
  const { base, providerRequests } = await fixture(t);
  const admin = await login(base, 'admin');
  const viewer = await login(base, 'viewer');
  const created = await api(base, '/api/modules/llm/providers', { method: 'POST', headers: admin,
    body: { name: 'DS', kind: 'deepseek', model: 'deepseek-chat', apiKey: KEY } });
  const testRoute = `/api/modules/llm/providers/${created.body.provider.id}/test`;
  assert.equal((await api(base, testRoute, { method: 'POST', headers: viewer, body: {} })).status, 403);
  const tested = await api(base, testRoute, { method: 'POST', headers: admin, body: {} });
  assert.deepEqual(tested.body, { ok: true, modelFound: true, models: ['deepseek-chat'] });
  assert.ok(!tested.text.includes(KEY));
  assert.deepEqual(providerRequests.at(-1), { url: 'https://api.deepseek.com/models', authorization: `Bearer ${KEY}` });

  const discovered = await api(base, '/api/modules/llm/local/discover', { headers: viewer });
  assert.equal(discovered.status, 200);
  assert.deepEqual(discovered.body.servers.filter(item => item.reachable).map(item => [item.label, item.models]), [['ollama', ['qwen3:8b']]]);
  const select = { label: 'ollama', model: 'qwen3:8b' };
  assert.equal((await api(base, '/api/modules/llm/local', { method: 'PUT', headers: viewer, body: select })).status, 403);
  const selected = await api(base, '/api/modules/llm/local', { method: 'PUT', headers: admin, body: select });
  assert.equal(selected.body.local.model, 'qwen3:8b');
  assert.equal(selected.body.local.endpoint, 'http://127.0.0.1:11434');
  assert.equal((await api(base, '/api/modules/llm/local', { method: 'PUT', headers: admin, body: { label: 'ollama', model: 'm', endpoint: 'http://10.0.0.5' } })).status, 400);
});
