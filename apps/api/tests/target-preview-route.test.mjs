import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createDashboardServer } from '../server.mjs';
import { createAuthentication, hashAccount } from '../auth.mjs';

test('parser preview requires an operator, CSRF, explicit authorization and bounded requests', async t => {
  const calls = [];
  const server = createDashboardServer({
    runtime: { close: async () => {}, subscribe: () => () => {}, getState: () => ({}) },
    auth: createAuthentication({ users: ['viewer', 'operator'].map(role => hashAccount(role, 'password', role)) }),
    platformProvider: async () => ({ modules: [] }), maintenanceCheck: async () => false,
    targetPreview: async body => {
      calls.push(body);
      return { previewId: 'test-preview', targetKind: 'external', fixtureId: null,
        origin: 'https://example.org', entryUrl: 'https://example.org/', pages: [],
        discoveredPaths: [], expiresAt: '2026-10-30T12:00:00Z' };
    },
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => server.shutdown());
  const base = `http://127.0.0.1:${server.address().port}`;
  async function login(role) {
    const response = await fetch(`${base}/api/auth/login`, { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: role, password: 'password' }) });
    assert.equal(response.status, 200);
    return { Cookie: response.headers.get('set-cookie').split(';')[0],
      'X-CSRF-Token': (await response.json()).csrfToken, 'Content-Type': 'application/json' };
  }
  const endpoint = `${base}/api/targets/preview`;
  const body = { url: 'https://example.org/', authorizationConfirmed: true };
  const post = (headers, value = body) => fetch(endpoint, { method: 'POST', headers,
    body: JSON.stringify(value) });
  assert.equal((await post({ 'Content-Type': 'application/json' })).status, 401);
  const viewer = await login('viewer');
  assert.equal((await post(viewer)).status, 403);
  const operator = await login('operator');
  assert.equal((await post({ Cookie: operator.Cookie, 'Content-Type': 'application/json' })).status, 403);
  assert.equal((await post(operator, { url: body.url })).status, 400);
  assert.equal((await post(operator, { ...body, extra: true })).status, 400);
  assert.equal(calls.length, 0);
  const first = await post(operator);
  assert.equal(first.status, 200);
  assert.equal((await first.json()).previewId, 'test-preview');
  for (let i = 0; i < 11; i += 1) assert.equal((await post(operator, {
    ...body, previewId: 'test-preview' })).status, 200);
  const limited = await post(operator);
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers.get('retry-after')) > 0);
  assert.equal(calls.length, 12);
});
