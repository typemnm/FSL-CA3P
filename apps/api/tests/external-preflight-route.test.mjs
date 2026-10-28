import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createDashboardServer } from '../server.mjs';
import { createAuthentication, hashAccount } from '../auth.mjs';

test('external preflight requires an operator session, CSRF and authorization confirmation', async t => {
  const calls = [];
  const server = createDashboardServer({
    runtime: { close: async () => {}, subscribe: () => () => {}, getState: () => ({}) },
    auth: createAuthentication({ users: ['viewer', 'operator'].map(role => hashAccount(role, 'password', role)) }),
    platformProvider: async () => ({ modules: [] }), maintenanceCheck: async () => false,
    targetPreflight: async body => { calls.push(body); return { ready: true, allowed: true,
      normalizedUrl: 'https://example.org/', scope: { origin: 'https://example.org', pathPrefix: '/' }, token: 'test-token' }; },
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => server.shutdown());
  const base = `http://127.0.0.1:${server.address().port}`;
  async function login(role) {
    const response = await fetch(`${base}/api/auth/login`, { method: 'POST',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: role, password: 'password' }) });
    assert.equal(response.status, 200);
    return { Cookie: response.headers.get('set-cookie').split(';')[0],
      'X-CSRF-Token': (await response.json()).csrfToken, 'Content-Type': 'application/json' };
  }
  const endpoint = `${base}/api/targets/preflight`;
  const body = { target: 'https://example.org/', scope: { pathPrefix: '/' }, authorizationConfirmed: true };
  const anonymous = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal(anonymous.status, 401);
  const viewer = await login('viewer');
  assert.equal((await fetch(endpoint, { method: 'POST', headers: viewer, body: JSON.stringify(body) })).status, 403);
  const operator = await login('operator');
  const noConfirmation = await fetch(endpoint, { method: 'POST', headers: operator,
    body: JSON.stringify({ target: body.target }) });
  assert.equal(noConfirmation.status, 400);
  assert.equal(calls.length, 0);
  const success = await fetch(endpoint, { method: 'POST', headers: operator, body: JSON.stringify(body) });
  assert.equal(success.status, 200);
  assert.equal((await success.json()).normalizedUrl, body.target);
  for (let index = 0; index < 9; index += 1) {
    const response = await fetch(endpoint, { method: 'POST', headers: operator, body: JSON.stringify(body) });
    assert.equal(response.status, 200);
  }
  const limited = await fetch(endpoint, { method: 'POST', headers: operator, body: JSON.stringify(body) });
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers.get('retry-after')) > 0);
  assert.equal(calls.length, 10);
});
