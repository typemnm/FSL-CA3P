import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deploymentPaused, deploymentStatus } from '../deployment.mjs';
import { createDashboardServer } from '../server.mjs';
import { createAuthentication, hashAccount } from '../auth.mjs';

async function temporary(t) {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-deployment-api-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test('deployment status exposes only verified public metadata and constructs its own GitHub URL', async t => {
  const directory = await temporary(t), path = join(directory, 'status.json');
  const value = { status: 'deployed', deployedSha: 'a'.repeat(40), targetSha: 'b'.repeat(40), previousSha: 'c'.repeat(40),
    checkedAt: '2026-10-26T10:00:00.000Z', deployedAt: '2026-10-26T10:01:00.000Z', updatedAt: '2026-10-26T10:01:01.000Z', retryAt: '2026-10-26T10:03:00.000Z',
    phase: 'backup-and-migrate', runId: '40209727623', runUrl: 'https://untrusted.example/secret',
    error: 'private error with secret', message: 'private message with secret',
    backup: '/private/deployment/backup', previous: '/private/releases/old', target: '/private/releases/new',
    credentials: { password: 'secret' }, nested: { status: 'private' } };
  await writeFile(path, JSON.stringify(value));
  const output = await deploymentStatus(path);
  assert.deepEqual(output, { enabled: true, status: 'deployed', deployedSha: value.deployedSha,
    targetSha: value.targetSha, previousSha: value.previousSha, checkedAt: value.checkedAt,
    deployedAt: value.deployedAt, updatedAt: value.updatedAt, retryAt: value.retryAt, phase: value.phase,
    runUrl: 'https://github.com/typemnm/FSL-CA3P/actions/runs/40209727623' });
  assert.doesNotMatch(JSON.stringify(output), /secret|\/private|untrusted\.example/);
  await writeFile(path, JSON.stringify({ ...value, status: 'prepared' }));
  assert.equal((await deploymentStatus(path)).status, 'prepared');
});

test('deployment status sanitizes invalid metadata and handles missing or malformed state', async t => {
  const directory = await temporary(t), path = join(directory, 'status.json');
  assert.deepEqual(await deploymentStatus(''), { enabled: false });
  assert.deepEqual(await deploymentStatus(path), { enabled: true, status: 'unavailable' });
  for (const raw of ['not json', 'null']) {
    await writeFile(path, raw);
    assert.deepEqual(await deploymentStatus(path), { enabled: true, status: 'unavailable' });
  }
  await writeFile(path, JSON.stringify({ status: 'secret status', phase: 'private secret',
    deployedSha: 'https://untrusted.example/', targetSha: 'A'.repeat(40), previousSha: '../../private',
    checkedAt: '/private/secret', deployedAt: 'invalid-date', updatedAt: {}, runId: '1?token=secret',
    runUrl: 'https://untrusted.example/secret' }));
  assert.deepEqual(await deploymentStatus(path), { enabled: true, status: 'unknown', deployedSha: null,
    targetSha: null, previousSha: null, checkedAt: null, deployedAt: null, updatedAt: null, retryAt: null, phase: null, runUrl: null });
});

test('maintenance detection treats an existing marker as paused and fails closed on lookup errors', async t => {
  const directory = await temporary(t), marker = join(directory, 'maintenance.json');
  assert.equal(await deploymentPaused(''), false);
  assert.equal(await deploymentPaused(marker), false);
  await writeFile(marker, 'content is irrelevant to the maintenance latch');
  assert.equal(await deploymentPaused(marker), true);
  const loop = join(directory, 'loop'); await symlink(loop, loop);
  await assert.rejects(deploymentPaused(loop), /maintenance state is unavailable/);
});

async function serverFixture(t, { maintenanceCheck = async () => true } = {}) {
  const calls = { start: [], lab: [], stop: [], reset: 0 };
  const state = { instanceId: 'maintenance-test', run: { id: 'run-fixture', status: 'idle' } };
  const runtime = { getState: () => state, listRuns: () => [state.run], listModels: () => [],
    start: async body => { calls.start.push(body); return { run: { id: 'new-fixture' } }; },
    startLab: async body => { calls.lab.push(body); return state; },
    stop: async id => { calls.stop.push(id); return state; },
    reset: () => { calls.reset += 1; return state; }, close: async () => {} };
  const auth = createAuthentication({ users: ['operator', 'viewer'].map(role => hashAccount(role, 'fixture-password', role)) });
  const server = createDashboardServer({ runtime, auth, maintenanceCheck,
    deploymentStatusProvider: async () => ({ enabled: true, status: 'deploying' }) });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => server.shutdown());
  const base = `http://127.0.0.1:${server.address().port}`;
  const api = async (path, { headers = {}, body, method = body === undefined ? 'GET' : 'POST' } = {}) => {
    const response = await fetch(base + path, { method, signal: AbortSignal.timeout(5000),
      headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: response.status, headers: response.headers, body: await response.json() };
  };
  const login = async username => {
    const response = await api('/api/auth/login', { body: { username, password: 'fixture-password' } });
    assert.equal(response.status, 200);
    return { Cookie: response.headers.get('set-cookie').split(';')[0], 'X-CSRF-Token': response.body.csrfToken };
  };
  return { api, login, calls };
}

test('maintenance blocks authorized mutation before runtime dispatch while reads and login/logout remain available', async t => {
  const { api, login, calls } = await serverFixture(t);
  assert.equal((await api('/api/health')).status, 200);
  assert.equal((await api('/api/auth/session')).body.authenticated, false);
  assert.equal((await api('/api/deployment')).status, 401);
  const operator = await login('operator');
  for (const path of ['/api/state', '/api/runs', '/api/deployment']) {
    assert.equal((await api(path, { headers: operator })).status, 200);
  }
  assert.deepEqual((await api('/api/deployment', { headers: operator })).body, { enabled: true, status: 'deploying' });
  for (const path of ['/api/runs', '/api/lab-runs', '/api/reset', '/api/runs/run-fixture/cancel']) {
    const blocked = await api(path, { headers: operator, body: {} });
    assert.equal(blocked.status, 503);
    assert.equal(blocked.headers.get('retry-after'), '30');
  }
  assert.deepEqual(calls, { start: [], lab: [], stop: [], reset: 0 });
  assert.equal((await api('/api/auth/logout', { headers: operator, body: {} })).status, 200);
  assert.equal((await api('/api/auth/session', { headers: operator })).body.authenticated, false);
});

test('maintenance does not bypass viewer permissions, session authentication or CSRF', async t => {
  let checks = 0;
  const { api, login, calls } = await serverFixture(t, { maintenanceCheck: async () => { checks += 1; return true; } });
  assert.equal((await api('/api/runs', { body: {} })).status, 401);
  const viewer = await login('viewer');
  assert.equal((await api('/api/state', { headers: viewer })).status, 200);
  assert.equal((await api('/api/runs', { headers: viewer, body: {} })).status, 403);
  const operator = await login('operator');
  assert.equal((await api('/api/runs', { headers: { Cookie: operator.Cookie }, body: {} })).status, 403);
  assert.equal(checks, 0);
  assert.equal(calls.start.length, 0);
});

test('clearing maintenance allows the same authenticated operator to dispatch exactly one run', async t => {
  let paused = true;
  const { api, login, calls } = await serverFixture(t, { maintenanceCheck: async () => paused });
  const operator = await login('operator'), body = { mode: 'core-fixture', modelId: 'rule-baseline' };
  assert.equal((await api('/api/runs', { headers: operator, body })).status, 503);
  paused = false;
  assert.equal((await api('/api/runs', { headers: operator, body })).status, 202);
  assert.deepEqual(calls.start, [body]);
});

test('unavailable maintenance state rejects mutation with a retryable service error without leaking the lookup error', async t => {
  const { api, login, calls } = await serverFixture(t, { maintenanceCheck: async () => {
    throw new Error('private maintenance path /private/secret is inaccessible');
  } });
  const operator = await login('operator');
  const response = await api('/api/runs', { headers: operator, body: {} });
  assert.equal(response.status, 503);
  assert.equal(response.headers.get('retry-after'), '30');
  assert.doesNotMatch(JSON.stringify(response.body), /\/private|secret/);
  assert.equal(calls.start.length, 0);
  assert.equal((await api('/api/state', { headers: operator })).status, 200);
});
