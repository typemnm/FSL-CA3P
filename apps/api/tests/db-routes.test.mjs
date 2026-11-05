import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createDashboardServer } from '../server.mjs';
import { createAuthentication, hashAccount } from '../auth.mjs';

test('DB routes let viewers read while only administrators stage and change records', async t => {
  const calls = [];
  const dbManagement = {
    bootstrap: async () => { calls.push('bootstrap'); },
    listCases: async filters => ({ cases: [{ case_id: 'case-1' }], filters }),
    getCase: async id => ({ case: { case_id: id, revision: 1 } }),
    listIntakes: async () => ({ intakes: [] }),
    stageUpload: async (req, { actor }) => { for await (const _chunk of req) { /* drain */ } calls.push(['stage', actor]); return { intake: { id: 'draft' } }; },
    updateCase: async (id, body, actor) => { calls.push(['update', id, body, actor]); return { case: { case_id: id, revision: 2 } }; },
    archiveCase: async (id, body, actor) => { calls.push(['archive', id, body, actor]); return { archived: true }; },
  };
  const runtime = { close: async () => {}, subscribe: () => () => {}, getState: () => ({}) };
  const auth = createAuthentication({ users: ['admin', 'operator', 'viewer']
    .map(role => hashAccount(role, 'password', role)) });
  const server = createDashboardServer({ runtime, auth, dbManagement,
    platformProvider: async () => ({ modules: [] }), maintenanceCheck: async () => false });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => server.shutdown());
  const base = `http://127.0.0.1:${server.address().port}`;
  async function login(role) {
    const response = await fetch(`${base}/api/auth/login`, { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: role, password: 'password' }) });
    assert.equal(response.status, 200);
    return { Cookie: response.headers.get('set-cookie').split(';')[0],
      'X-CSRF-Token': (await response.json()).csrfToken };
  }
  const viewer = await login('viewer');
  const operator = await login('operator');
  const admin = await login('admin');
  const list = await fetch(`${base}/api/db/cases?q=xss&limit=10`, { headers: viewer });
  assert.equal(list.status, 200);
  assert.equal((await list.json()).filters.q, 'xss');
  assert.equal((await fetch(`${base}/api/db/intakes`, { headers: viewer })).status, 200);
  for (const headers of [viewer, operator]) {
    const response = await fetch(`${base}/api/db/cases/case-1`, { method: 'PATCH', headers: {
      ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ patch: { title: 'changed' }, expectedRevision: 1 }) });
    assert.equal(response.status, 403);
  }
  const noCsrf = await fetch(`${base}/api/db/cases/case-1`, { method: 'PATCH', headers: {
    Cookie: admin.Cookie, 'Content-Type': 'application/json' },
  body: JSON.stringify({ patch: { title: 'changed' }, expectedRevision: 1 }) });
  assert.equal(noCsrf.status, 403);
  const updated = await fetch(`${base}/api/db/cases/case-1`, { method: 'PATCH', headers: {
    ...admin, 'Content-Type': 'application/json' },
  body: JSON.stringify({ patch: { title: 'changed' }, expectedRevision: 1 }) });
  assert.equal(updated.status, 200);
  assert.deepEqual(calls.at(-1), ['update', 'case-1', { patch: { title: 'changed' }, expectedRevision: 1 }, 'admin']);
  const archived = await fetch(`${base}/api/db/cases/case-1`, { method: 'DELETE', headers: {
    ...admin, 'Content-Type': 'application/json' }, body: JSON.stringify({ reason: 'duplicate' }) });
  assert.equal(archived.status, 200);
  assert.deepEqual(calls.at(-1), ['archive', 'case-1', { reason: 'duplicate' }, 'admin']);
  const upload = await fetch(`${base}/api/db/intakes`, { method: 'POST', headers: admin,
    body: new FormData() });
  assert.equal(upload.status, 201);
  assert.deepEqual(calls.at(-1), ['stage', 'admin']);
  assert.equal(calls.filter(item => item === 'bootstrap').length, 1);
});
