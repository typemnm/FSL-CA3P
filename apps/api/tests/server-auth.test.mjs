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
  const listeners = new Set(); const calls = { start: 0, startBodies: [], stop: 0, lab: [], experimentReset: [], historyClear: [], loopBudget: [], approvals: [] };
  let loopBudget = { maxIterations: 6, maxProbes: 24, maxEvidenceItems: 128 };
  const runtime = { getState: () => runtimeState, getRun: id => id === 'run-a' ? runtimeState.run : null,
    listRuns: () => [state.run], listModels: () => [], start: async body => { calls.start += 1; calls.startBodies.push(body); return state; },
    getGeneralLoopBudget: () => loopBudget,
    setGeneralLoopBudget: limits => { loopBudget = limits; calls.loopBudget.push(limits); return limits; },
    startLab: async body => { calls.lab.push(body); return state; }, stop: async () => { calls.stop += 1; return state; }, reset: () => state,
    decideApproval: async (...args) => { calls.approvals.push(args); return {
      approval: { id: args[1], decision: args[2] === 'approve' ? 'approved' : 'rejected', actor: args[3] },
      run: runtimeState.run,
    }; },
    experimentResetPreview: () => ({ status: 'ready', runCount: 1, canReset: true }),
    resetExperiment: async body => { calls.experimentReset.push(body); return { ...state, experimentReset: { status: 'completed', epoch: 1 } }; },
    clearRunHistory: async body => { calls.historyClear.push(body); return { ...state, historyClear: { status: 'completed', epoch: 1 } }; },
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

test('pre-execution approval decisions require an admin session and CSRF token', async t => {
  const { base, calls } = await fixture(t);
  const route = '/api/runs/run-a/approvals/approval-1';
  assert.equal((await api(base, route, { method: 'POST', body: { decision: 'approve' } })).status, 401);
  const viewer = await login(base, 'viewer');
  assert.equal((await api(base, route, { method: 'POST', headers: viewer.headers,
    body: { decision: 'approve' } })).status, 403);
  const operator = await login(base, 'operator');
  assert.equal((await api(base, route, { method: 'POST', headers: operator.headers,
    body: { decision: 'approve' } })).status, 403);
  const admin = await login(base, 'admin');
  assert.equal((await api(base, route, { method: 'POST', headers: { Cookie: admin.headers.Cookie },
    body: { decision: 'approve' } })).status, 403);
  assert.equal((await api(base, route, { method: 'POST', headers: admin.headers,
    body: { decision: 'allow' } })).status, 400);
  assert.equal((await api(base, route, { method: 'GET', headers: admin.headers })).status, 405);
  const decided = await api(base, route, { method: 'POST', headers: admin.headers,
    body: { decision: 'reject' } });
  assert.equal(decided.status, 200);
  assert.equal(decided.body.approval.decision, 'rejected');
  assert.deepEqual(calls.approvals, [['run-a', 'approval-1', 'reject', 'admin']]);
});

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

test('complete experiment reset requires operator permission, CSRF and exact explicit confirmation', async t => {
  const { base, calls } = await fixture(t);
  assert.equal((await api(base, '/api/experiment-reset')).status, 401);
  const viewer = await login(base, 'viewer');
  assert.equal((await api(base, '/api/experiment-reset', { headers: viewer.headers })).body.runCount, 1);
  assert.equal((await api(base, '/api/experiment-reset', { method: 'POST', headers: viewer.headers, body: { confirmed: true } })).status, 403);
  const operator = await login(base, 'operator');
  assert.equal((await api(base, '/api/experiment-reset', { method: 'POST', headers: { Cookie: operator.headers.Cookie }, body: { confirmed: true } })).status, 403);
  for (const body of [{}, null, [], { confirmed: false }, { confirmed: 'true' }, { confirmed: true, path: '/tmp' }]) {
    assert.equal((await api(base, '/api/experiment-reset', { method: 'POST', headers: operator.headers, body })).status, 400);
  }
  assert.equal(calls.experimentReset.length, 0);
  const result = await api(base, '/api/experiment-reset', { method: 'POST', headers: operator.headers, body: { confirmed: true } });
  assert.equal(result.status, 200); assert.equal(result.body.experimentReset.status, 'completed');
  assert.deepEqual(calls.experimentReset, [{ confirmed: true }]);
  assert.equal((await api(base, '/api/experiment-reset', { method: 'DELETE', headers: operator.headers })).status, 405);
  assert.equal((await api(base, '/api/experiment-reset', { method: 'POST', headers: { ...operator.headers, Origin: 'http://foreign.invalid' }, body: { confirmed: true } })).status, 403);
});

test('LLM loop budget requires administrator and CSRF, and rejects incomplete or out-of-cap settings', async t => {
  const { base, calls } = await fixture(t);
  const endpoint = '/api/modules/llm/loop-budget';
  assert.equal((await api(base, endpoint)).status, 401);
  const viewer = await login(base, 'viewer');
  const defaults = await api(base, endpoint, { headers: viewer.headers });
  assert.equal(defaults.status, 200);
  assert.deepEqual(defaults.body.limits, { maxIterations: 6, maxProbes: 24, maxEvidenceItems: 128 });
  assert.deepEqual(defaults.body.caps, { maxIterations: 32, maxProbes: 128, maxEvidenceItems: 256 });
  const limits = { maxIterations: 12, maxProbes: 48, maxEvidenceItems: 200 };
  const payload = { limits };
  assert.equal((await api(base, endpoint, { method: 'PUT', headers: viewer.headers, body: payload })).status, 403);
  const operator = await login(base, 'operator');
  assert.equal((await api(base, endpoint, { method: 'PUT', headers: operator.headers, body: payload })).status, 403);
  const admin = await login(base, 'admin');
  assert.equal((await api(base, endpoint, { method: 'PUT', headers: { Cookie: admin.headers.Cookie }, body: payload })).status, 403);
  for (const invalid of [{}, { limits: { maxIterations: 12 } },
    { limits: { ...limits, extra: 1 } }, { limits: { ...limits, maxProbes: 129 } },
    { limits: { ...limits, maxIterations: 1.5 } }, { limits, extra: true }]) {
    assert.equal((await api(base, endpoint, { method: 'PUT', headers: admin.headers, body: invalid })).status, 400);
  }
  assert.equal(calls.loopBudget.length, 0);
  const saved = await api(base, endpoint, { method: 'PUT', headers: admin.headers, body: payload });
  assert.equal(saved.status, 200);
  assert.deepEqual(saved.body.limits, limits);
  assert.deepEqual(calls.loopBudget, [limits]);
  assert.deepEqual((await api(base, endpoint, { headers: operator.headers })).body.limits, limits);
});

test('history clear requires operator permission, CSRF and exact explicit confirmation', async t => {
  const { base, calls } = await fixture(t);
  assert.equal((await api(base, '/api/run-history/clear', { method: 'POST', body: { confirmed: true } })).status, 401);
  const viewer = await login(base, 'viewer');
  assert.equal((await api(base, '/api/run-history/clear', { method: 'POST', headers: viewer.headers, body: { confirmed: true } })).status, 403);
  const operator = await login(base, 'operator');
  assert.equal((await api(base, '/api/run-history/clear', { method: 'POST', headers: { Cookie: operator.headers.Cookie }, body: { confirmed: true } })).status, 403);
  for (const body of [{}, null, [], { confirmed: false }, { confirmed: 'true' }, { confirmed: true, target: '/' }]) {
    assert.equal((await api(base, '/api/run-history/clear', { method: 'POST', headers: operator.headers, body })).status, 400);
  }
  assert.equal(calls.historyClear.length, 0);
  const result = await api(base, '/api/run-history/clear', { method: 'POST', headers: operator.headers, body: { confirmed: true } });
  assert.equal(result.status, 200);
  assert.equal(result.body.historyClear.status, 'completed');
  assert.deepEqual(calls.historyClear, [{ confirmed: true }]);
  assert.equal((await api(base, '/api/run-history/clear', { method: 'GET', headers: operator.headers })).status, 405);
});

test('lab API forwards the university fixture and target selection but rejects extra run controls', async t => {
  const { base, calls } = await fixture(t);
  const operator = await login(base, 'operator');
  const selection = { modelId: 'rule-baseline', fixtureId: 'vul-web2-daehan', target: 'http://192.168.0.20:4101' };
  assert.equal((await api(base, '/api/lab-runs', { method: 'POST', headers: operator.headers, body: selection })).status, 202);
  assert.deepEqual(calls.lab, [selection]);
  for (const extra of [{ mode: 'core-fixture' }, { testProfile: 'stored_xss_canary' }]) {
    assert.equal((await api(base, '/api/lab-runs', { method: 'POST', headers: operator.headers, body: { ...selection, ...extra } })).status, 400);
  }
  for (const body of [
    { target: selection.target },
    { fixtureId: 'vul-web-1', target: selection.target },
    { fixtureId: 'unknown', target: selection.target },
  ]) {
    assert.equal((await api(base, '/api/lab-runs', { method: 'POST', headers: operator.headers, body })).status, 400);
  }
  assert.equal(calls.lab.length, 1);
});

test('authenticated run API forwards a general university assessment request unchanged', async t => {
  const { base, calls } = await fixture(t);
  const operator = await login(base, 'operator');
  const body = { mode: 'local-lab-general', modelId: 'deepseek-flash',
    fixtureId: 'vul-web2-daehan', target: 'http://192.168.0.20:4101' };
  assert.equal((await api(base, '/api/runs', { method: 'POST', headers: operator.headers, body })).status, 202);
  assert.deepEqual(calls.startBodies, [body]);
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
