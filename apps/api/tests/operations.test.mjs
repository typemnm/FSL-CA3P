import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createDashboardServer } from '../server.mjs';
import { createAuthentication, hashAccount } from '../auth.mjs';

test('deployment board is an authenticated read-only API available to viewers during maintenance', async t => {
  let revisionReads = 0; let deploymentReads = 0;
  const runtime = { getState: () => ({}), close: async () => {} };
  const auth = createAuthentication({ users: [hashAccount('viewer', 'board-test-password', 'viewer')] });
  const server = createDashboardServer({ runtime, auth, maintenanceCheck: async () => true,
    runningRevisionProvider: () => { revisionReads += 1; return 'a'.repeat(40); },
    deploymentStatusProvider: async () => { deploymentReads += 1; return { enabled: true, status: 'deploying', targetSha: 'b'.repeat(40) }; },
    ciResults: { getSnapshot: () => ({ status: 'unavailable', runs: [] }) } });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => server.shutdown());
  const origin = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(`${origin}/api/operations`)).status, 401);
  const login = await fetch(`${origin}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'viewer', password: 'board-test-password' }) });
  const session = await login.json();
  const headers = { Cookie: login.headers.get('set-cookie').split(';')[0] };
  const response = await fetch(`${origin}/api/operations`, { headers });
  assert.equal(response.status, 200); assert.match(response.headers.get('cache-control'), /no-store/);
  const state = await response.json();
  assert.equal(state.source.runningSha, 'a'.repeat(40)); assert.equal(state.deployment.status, 'deploying');
  assert.equal((await fetch(`${origin}/api/operations`, { headers: { ...headers, Origin: 'https://evil.test' } })).status, 403);
  assert.equal((await fetch(`${origin}/api/operations`, { method: 'POST', headers: { ...headers, 'X-CSRF-Token': session.csrfToken,
    'Content-Type': 'application/json' }, body: '{}' })).status, 403);
  await fetch(`${origin}/api/operations`, { headers });
  assert.equal(deploymentReads, 2); assert.equal(revisionReads, 1, 'polling must not repeatedly compute the source tree');
});
