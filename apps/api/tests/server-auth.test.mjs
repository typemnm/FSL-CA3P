import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createDashboardServer } from '../server.mjs';
import { createAuthentication, hashAccount } from '../auth.mjs';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const state = { instanceId: 'test-server', mode: 'core-fixture', run: { id: 'run-a', mode: 'core-fixture', status: 'idle', events: [] }, lab: {} };
async function fixture(t, { publicOrigins = [], runtimeState = state, artifactBytes } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-api-auth-'));
  const bytes = Buffer.from(artifactBytes ?? '{"runId":"run-a","evidence":"fixture"}');
  const artifactPath = join(directory, 'evidence.json'); await writeFile(artifactPath, bytes);
  const artifact = { id: sha256('artifact-id'), path: artifactPath, sha256: sha256(bytes), size: bytes.length };
  const listeners = new Set(); const calls = { start: 0, stop: 0 };
  const runtime = { getState: () => runtimeState, getRun: id => id === 'run-a' ? runtimeState.run : null,
    listRuns: () => [state.run], listModels: () => [], start: async () => { calls.start += 1; return state; },
    startLab: async () => state, stop: async () => { calls.stop += 1; return state; }, reset: () => state,
    close: async () => {}, subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); },
    store: { getArtifact: id => id === artifact.id ? artifact : null },
  };
  const auth = createAuthentication({ users: ['admin', 'operator', 'viewer'].map(role => hashAccount(role, 'test-password', role)) });
  const ciResults = { getSnapshot: () => ({ source: 'public-feed', status: 'fresh', runs: [{ runId: 101, status: 'passed' }] }), close() {} };
  const server = createDashboardServer({ runtime, auth, publicOrigins, ciResults, platformProvider: async () => ({ source: { commitSha: 'test-only' } }) });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { await server.shutdown(); await rm(directory, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, artifact, calls, listeners, async tamper() { await writeFile(artifactPath, '{"tampered":true}'); } };
}
function api(base, path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = request(base + path, { method, headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers }, agent: false }, res => {
      let text = ''; res.setEncoding('utf8'); res.on('data', part => { text += part; });
      res.on('end', () => { let value; try { value = JSON.parse(text); } catch { value = text; } resolve({ status: res.statusCode, headers: res.headers, body: value, text }); });
    });
    req.on('error', reject); req.setTimeout(5000, () => req.destroy(new Error('Loopback API timed out')));
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}
async function login(base, username, headers = {}) {
  const result = await api(base, '/api/auth/login', { method: 'POST', headers, body: { username, password: 'test-password' } });
  assert.equal(result.status, 200);
  return { result, headers: { ...headers, Cookie: result.headers['set-cookie'][0].split(';')[0], 'X-CSRF-Token': result.body.csrfToken } };
}

test('session API, viewer access, operator mutations and logout enforce authentication and CSRF', async t => {
  const { base, calls } = await fixture(t);
  const anonymous = await api(base, '/api/auth/session');
  assert.equal(anonymous.body.authRequired, true); assert.equal(anonymous.body.authenticated, false);
  assert.equal((await api(base, '/api/state')).status, 401);
  assert.equal((await api(base, '/api/runs')).status, 401);
  assert.equal((await api(base, '/api/ci-results')).status, 401);
  const viewer = await login(base, 'viewer');
  assert.equal((await api(base, '/api/state', { headers: viewer.headers })).status, 200);
  assert.equal((await api(base, '/api/ci-results', { headers: viewer.headers })).body.runs[0].runId, 101);
  assert.equal((await api(base, '/api/runs?limit=200&offset=0', { headers: viewer.headers })).status, 200);
  assert.equal((await api(base, '/api/runs?offset=-1', { headers: viewer.headers })).status, 400);
  assert.equal((await api(base, '/api/runs', { method: 'POST', headers: viewer.headers, body: {} })).status, 403);
  assert.equal((await api(base, '/api/runs/run-a/stop', { method: 'POST', headers: viewer.headers, body: {} })).status, 403);
  const operator = await login(base, 'operator');
  const noCsrf = { Cookie: operator.headers.Cookie };
  assert.equal((await api(base, '/api/runs', { method: 'POST', headers: noCsrf, body: {} })).status, 403);
  assert.equal((await api(base, '/api/runs', { method: 'POST', headers: { ...operator.headers, 'X-CSRF-Token': 'invalid' }, body: {} })).status, 403);
  assert.equal((await api(base, '/api/runs', { method: 'POST', headers: operator.headers, body: {} })).status, 202);
  assert.equal(calls.start, 1);
  assert.equal((await api(base, '/api/auth/logout', { method: 'POST', headers: noCsrf, body: {} })).status, 403);
  assert.equal((await api(base, '/api/auth/logout', { method: 'POST', headers: operator.headers, body: {} })).status, 200);
  assert.equal((await api(base, '/api/auth/session', { headers: operator.headers })).body.authenticated, false);
  assert.equal((await api(base, '/api/state', { headers: operator.headers })).status, 401);
});

test('configured public Host requires HTTPS origin, secure cookies and still rejects cross-origin or cross-site access', async t => {
  const { base } = await fixture(t, { publicOrigins: ['https://dashboard.example'] });
  const publicHeaders = { Host: 'dashboard.example', Origin: 'https://dashboard.example' };
  const administrator = await login(base, 'admin', publicHeaders);
  assert.match(administrator.result.headers['set-cookie'][0], /; Secure/);
  assert.match(administrator.result.headers['set-cookie'][0], /HttpOnly; SameSite=Strict/);
  assert.equal((await api(base, '/api/state', { headers: administrator.headers })).status, 200);
  assert.equal((await api(base, '/api/state', { headers: { ...administrator.headers, Origin: 'https://untrusted.example' } })).status, 403);
  assert.equal((await api(base, '/api/auth/login', { method: 'POST', headers: { ...publicHeaders, Origin: 'https://untrusted.example' }, body: { username: 'admin', password: 'test-password' } })).status, 403);
  assert.equal((await api(base, '/api/state', { headers: { ...administrator.headers, 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.equal((await api(base, '/api/state', { headers: { Host: 'unconfigured.example' } })).status, 403);
  assert.equal((await api(base, '/api/state', { headers: { ...administrator.headers, Origin: 'http://dashboard.example' } })).status, 403);
});

test('artifact retrieval requires a session and rejects altered original evidence', async t => {
  const { base, artifact, tamper } = await fixture(t);
  assert.equal((await api(base, `/api/artifacts/${artifact.id}`)).status, 401);
  const viewer = await login(base, 'viewer');
  const intact = await api(base, `/api/artifacts/${artifact.id}`, { headers: viewer.headers });
  assert.equal(intact.status, 200); assert.equal(sha256(Buffer.from(intact.text)), artifact.sha256);
  await tamper(); const changed = await api(base, `/api/artifacts/${artifact.id}`, { headers: viewer.headers });
  assert.ok(changed.status >= 400, `Altered evidence must be rejected, received ${changed.status}`);
  assert.doesNotMatch(changed.text, /"tampered":true/);
});

test('legacy evidence with a valid hash but secret fields is withheld instead of exposing raw bytes', async t => {
  const { base, artifact } = await fixture(t, { artifactBytes: '{"runId":"run-a","x-api-key":"private-legacy-key"}' });
  const viewer = await login(base, 'viewer');
  const response = await api(base, `/api/artifacts/${artifact.id}`, { headers: viewer.headers });
  assert.equal(response.status, 409);
  assert.doesNotMatch(response.text, /private-legacy-key/);
});

test('logging out revokes an existing SSE subscriber before the next state is sent', async t => {
  const { base, listeners } = await fixture(t); const operator = await login(base, 'operator');
  let content = ''; let ended = false; let req;
  const opened = new Promise((resolve, reject) => {
    req = request(base + '/api/events', { headers: operator.headers, agent: false }, res => {
      res.setEncoding('utf8'); res.on('data', value => { content += value; if (content.includes('event: state')) resolve(); });
      res.on('end', () => { ended = true; }); res.on('error', reject);
    }); req.on('error', reject); req.end();
  });
  t.after(() => req.destroy()); await opened;
  assert.equal((await api(base, '/api/auth/logout', { method: 'POST', headers: operator.headers, body: {} })).status, 200);
  for (const listener of listeners) listener({ ...state, privateMarker: 'after-session-revoked' });
  await pause(20); assert.equal(ended, true); assert.doesNotMatch(content, /after-session-revoked/);
});

test('HTTP state and run detail mask raw authentication text and credential keys before reaching the browser', async t => {
  const runtimeState = { ...state, run: { ...state.run, telemetry: {
    'x-api-key': 'fixture-private-key', session_token: 'fixture-private-session',
    rawHeaders: 'Authorization: Bearer fixture-private-token\nCookie: fixture-private-cookie',
    prompt_tokens: 100, target: 'https://metadata-only.invalid/?access_token=fixture-private-query',
  } } };
  const { base } = await fixture(t, { runtimeState }); const viewer = await login(base, 'viewer');
  for (const path of ['/api/state', '/api/runs/run-a']) {
    const value = await api(base, path, { headers: viewer.headers }); assert.equal(value.status, 200);
    assert.doesNotMatch(value.text, /fixture-private-/);
    const run = value.body.run; assert.equal(run.telemetry.prompt_tokens, 100);
  }
});
