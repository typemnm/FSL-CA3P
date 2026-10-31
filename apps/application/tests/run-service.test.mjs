import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRunService } from '../run-service.mjs';
import { createDashboardServer } from '../../api/server.mjs';
import { createAuthentication, hashAccount } from '../../api/auth.mjs';

function setup(t, options = {}) {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'ca3p-service-test-')); const storePath = join(directory, 'runs.sqlite');
  const service = createRunService({ storePath, envFile: null, env: { ...process.env, DEEPSEEK_API_KEY: '' }, ...options });
  const services = [service];
  t.after(async () => { for (const item of services.reverse()) await item.close(); rmSync(directory, { recursive: true, force: true }); });
  return { service, storePath, reopen(options = {}) {
    const restarted = createRunService({ storePath, autoStartWorker: false, envFile: null,
      env: { ...process.env, DEEPSEEK_API_KEY: '' }, ...options });
    services.push(restarted); return restarted;
  } };
}
async function waitFor(service, id, terminal = ['completed', 'failed', 'interrupted', 'cancelled']) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const state = service.getRun(id);
    if (terminal.includes(state.status)) return state;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('Worker did not finish the run.');
}
// Credential-free private-origin stand-in for the fixed daehan IDOR read (no model, no case DB).
async function universityTarget(t) {
  const server = createServer(async (req, res) => {
    if (req.method === 'POST' && req.url === '/login') {
      let body = ''; for await (const chunk of req) body += chunk;
      res.writeHead(302, { location: '/mypage', 'set-cookie': `sid=${new URLSearchParams(body).get('username')}; HttpOnly; Path=/` });
      res.end(); return;
    }
    const match = /^\/api\/admissions\/partner\/applications\/(1|3)$/.exec(req.url);
    if (req.method !== 'GET' || !match) { res.writeHead(404); res.end(); return; }
    const id = Number(match[1]);
    res.writeHead(req.headers.cookie === 'sid=student1' ? 403 : 200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ id, partner_user_id: id === 1 ? 4 : 5 }));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  return `http://127.0.0.1:${server.address().port}`;
}
test('a separate worker executes queued lab runs and history survives API restart', async t => {
  const { service, reopen } = setup(t);
  const started = await service.startLab({ fixtureId: 'vul-web2-daehan', target: await universityTarget(t) });
  assert.equal(started.run.status, 'queued');
  const final = await waitFor(service, started.run.id);
  assert.equal(final.status, 'completed', final.error);
  assert.equal(final.id, final.coreRunId); assert.equal(final.id, final.report.runId);
  assert.equal(final.events.length, 6); assert.equal(final.events.at(-1).sequence, 6);
  assert.ok(final.manifest.modules['apps/worker'].contentDigest); assert.ok(final.artifacts.some(item => item.kind === 'run-report'));
  await service.close();
  const restarted = reopen();
  assert.equal(restarted.getState().run.id, final.id); assert.equal(restarted.getRun(final.id).status, 'completed');
});
test('queued cancellation never reaches a worker; arbitrary lab targets are rejected', async t => {
  const { service } = setup(t, { autoStartWorker: false });
  await assert.rejects(service.start({ mode: 'local-lab-rule', target: 'https://remote.invalid' }), { status: 400 });
  const state = await service.startLab({ fixtureId: 'vul-web2-daehan' });
  assert.equal(service.stop(state.run.id).run.status, 'cancelled');
  assert.equal(service.store.claimNext('test-worker'), null); assert.equal(service.reset().run.status, 'idle');
});

test('university fixtures queue their known-record IDOR check without a case database', async t => {
  const { service } = setup(t, { autoStartWorker: false, importLegacy: false,
    env: { DEEPSEEK_API_KEY: '', CASPER_DB_PYTHON: 'unavailable-python-for-idor' } });
  assert.deepEqual(service.getState().lab.targetOrigins, {
    'vul-web2-daehan': 'http://127.0.0.1:4101',
    'vul-web2-wonchang': 'http://127.0.0.1:4102',
  });
  for (const [fixtureId, target] of [['vul-web2-daehan', 'http://127.0.0.1:4101'], ['vul-web2-wonchang', 'http://127.0.0.1:4102']]) {
    const state = await service.startLab({ fixtureId });
    assert.equal(state.run.status, 'queued');
    assert.equal(state.run.mode, 'local-lab-rule');
    assert.equal(state.run.modelId, 'rule-baseline');
    assert.equal(state.run.fixtureId, fixtureId);
    assert.equal(state.run.target, target);
    assert.equal(state.run.testProfile, 'known_record_idor_read');
    assert.equal(state.run.manifest.target.fixtureId, fixtureId);
    const lease = service.store.claimNext('idor-options-test');
    assert.equal(lease.options.fixtureId, fixtureId);
    assert.equal(lease.options.target, target);
    assert.equal(lease.options.testProfile, 'known_record_idor_read');
    assert.equal(lease.options.caseSnapshot, undefined);
    service.store.finish(lease, 'completed');
  }
});

test('configured university origins become lab defaults while an explicit internal target still wins', async t => {
  const { service, storePath } = setup(t, { autoStartWorker: false, importLegacy: false,
    env: { DEEPSEEK_API_KEY: '', CASPER_DB_PYTHON: 'unavailable-python-for-idor',
      CA3P_DAEHAN_ORIGIN: 'http://daehan:4101', CA3P_WONCHANG_ORIGIN: 'http://wonchang:4102' } });
  assert.deepEqual(service.getState().lab.targetOrigins, {
    'vul-web2-daehan': 'http://daehan:4101', 'vul-web2-wonchang': 'http://wonchang:4102',
  });
  const defaultRun = await service.startLab({ fixtureId: 'vul-web2-daehan' });
  assert.equal(defaultRun.run.target, 'http://daehan:4101');
  const defaultLease = service.store.claimNext('configured-default-test');
  assert.equal(defaultLease.options.target, 'http://daehan:4101');
  service.store.finish(defaultLease, 'completed');
  const explicitRun = await service.startLab({ fixtureId: 'vul-web2-wonchang', target: 'http://192.168.0.84:4102' });
  assert.equal(explicitRun.run.target, 'http://192.168.0.84:4102');
  const explicitLease = service.store.claimNext('explicit-origin-test');
  assert.equal(explicitLease.options.target, 'http://192.168.0.84:4102');
  service.store.finish(explicitLease, 'completed');
  assert.throws(() => createRunService({ storePath, autoStartWorker: false,
    env: { CA3P_DAEHAN_ORIGIN: 'https://public.example' } }), { status: 400 });
});

test('registered universities queue a model-backed general assessment without selecting an IDOR profile', async t => {
  const { service } = setup(t, { autoStartWorker: false, importLegacy: false,
    env: { DEEPSEEK_API_KEY: 'test-key', CASPER_DB_PYTHON: 'unavailable-python-for-general' } });
  assert.equal(service.getState().lab.generalSupported, true);
  assert.equal(service.getState().lab.generalAvailable, true);
  for (const [fixtureId, target] of [['vul-web2-daehan', 'http://127.0.0.1:4101'], ['vul-web2-wonchang', 'http://192.168.0.20:4102']]) {
    const state = await service.start({ mode: 'local-lab-general', modelId: 'deepseek-flash', fixtureId, target });
    assert.equal(state.run.status, 'queued');
    assert.equal(state.run.mode, 'local-lab-general');
    assert.equal(state.run.assessmentMode, 'general');
    assert.equal(state.run.testProfile, 'general');
    assert.equal(state.run.target, target);
    assert.equal(state.run.manifest.target.origin, target);
    assert.equal(state.run.manifest.execution.maxIterations, 6);
    assert.equal(state.run.manifest.model.executionRole, undefined);
    assert.deepEqual(state.run.manifest.data.unavailableInputs, ['casper-db']);
    const lease = service.store.claimNext('general-options-test');
    assert.equal(lease.options.mode, 'local-lab-general');
    assert.equal(lease.options.modelId, 'deepseek-flash');
    assert.equal(lease.options.testProfile, 'general');
    assert.equal(lease.options.fixtureId, fixtureId);
    assert.equal(lease.options.target, target);
    assert.equal(lease.options.caseSnapshot, undefined);
    assert.deepEqual(lease.options.unavailableInputs, ['casper-db']);
    service.store.finish(lease, 'completed');
  }
});

test('general run freezes configured loop limits in queued options and manifest', async t => {
  const { service, reopen } = setup(t, { autoStartWorker: false, importLegacy: false,
    env: { DEEPSEEK_API_KEY: 'test-key', CASPER_DB_PYTHON: 'unavailable-python-for-general' } });
  const limits = { maxIterations: 10, maxProbes: 40, maxEvidenceItems: 180 };
  assert.deepEqual(service.setGeneralLoopBudget(limits), limits);
  const state = await service.start({ mode: 'local-lab-general', modelId: 'deepseek-flash',
    fixtureId: 'vul-web2-daehan' });
  assert.deepEqual(state.run.manifest.execution.loopBudget, limits);
  assert.equal(state.run.manifest.execution.maxIterations, 10);
  assert.equal(state.run.manifest.policy.maxIterations, 10);
  const lease = service.store.claimNext('budget-options-test');
  assert.deepEqual(lease.options.loopBudget, limits);
  service.store.finish(lease, 'completed');
  await service.close();
  assert.deepEqual(reopen().getGeneralLoopBudget(), limits);
});

test('general assessment requires a real configured model and registered target scope', async t => {
  const { service } = setup(t, { autoStartWorker: false, importLegacy: false,
    env: { DEEPSEEK_API_KEY: '', CA3P_CHAT_LOCAL_ENDPOINT: '', LOCAL_LLM_BASE_URL: '', SLLM_ENDPOINT: '', OLLAMA_HOST: '' } });
  assert.equal(service.getState().lab.generalSupported, true);
  assert.equal(service.getState().lab.generalAvailable, false);
  await assert.rejects(service.start({ mode: 'local-lab-general', fixtureId: 'vul-web2-daehan', modelId: 'deepseek-flash' }), { status: 503 });
  const { service: configured } = setup(t, { autoStartWorker: false, importLegacy: false,
    env: { DEEPSEEK_API_KEY: 'test-key' } });
  for (const options of [
    { mode: 'local-lab-general', fixtureId: 'vul-web2-daehan', modelId: 'rule-baseline' },
    { mode: 'local-lab-general', fixtureId: 'vul-web2-daehan', modelId: 'deepseek-flash', target: 'https://external.invalid' },
    { mode: 'local-lab-general', fixtureId: 'unknown', modelId: 'deepseek-flash' },
    { mode: 'local-lab-general', fixtureId: 'vul-web-1', modelId: 'deepseek-flash', target: 'http://127.0.0.1:4101' },
    { mode: 'local-lab-general', fixtureId: 'vul-web2-daehan', modelId: 'deepseek-flash', testProfile: 'known_record_idor_read' },
    { fixtureId: 'vul-web-1', testProfile: 'known_record_idor_read' },
  ]) await assert.rejects(configured.start(options), { status: 400 });
  assert.equal(service.listRuns().total, 0);
  assert.equal(configured.listRuns().total, 0);
});

test('a configured local planner queues a general assessment without DeepSeek', async t => {
  const { service } = setup(t, { autoStartWorker: false, importLegacy: false, env: {
    DEEPSEEK_API_KEY: '', CA3P_CHAT_LOCAL_ENDPOINT: 'http://127.0.0.1:11434',
    CA3P_CHAT_LOCAL_RUNTIME: 'ollama', CA3P_CHAT_LOCAL_MODEL: 'qwen3',
  } });
  assert.equal(service.getState().lab.generalAvailable, true);
  const local = service.getState().lab.models.find(item => item.id === 'local-llm');
  assert.equal(local.available, true);
  const state = await service.start({ mode: 'local-lab-general', modelId: 'local-llm', fixtureId: 'vul-web-1' });
  assert.equal(state.run.status, 'queued');
  assert.equal(state.run.modelId, 'local-llm');
  assert.equal(state.run.manifest.model.provider, 'local');
  const lease = service.store.claimNext('local-planner-test');
  assert.equal(lease.modelId, 'local-llm');
  service.store.finish(lease, 'completed');
});

test('general board run records unavailable case history instead of failing to queue', async t => {
  const { service } = setup(t, { autoStartWorker: false, importLegacy: false,
    env: { DEEPSEEK_API_KEY: 'test-key', CASPER_DB_PYTHON: 'missing-python-for-general-board' } });
  const state = await service.start({ mode: 'local-lab-general', modelId: 'deepseek-v4-pro', fixtureId: 'vul-web-1' });
  assert.equal(state.run.status, 'queued');
  assert.equal(state.run.assessmentMode, 'general');
  assert.equal(state.run.manifest.data.caseSnapshotDigest, null);
  assert.deepEqual(state.run.manifest.data.unavailableInputs, ['casper-db']);
  const lease = service.store.claimNext('general-board-test');
  assert.equal(lease.options.fixtureId, 'vul-web-1');
  assert.equal(lease.options.caseSnapshot, undefined);
  assert.deepEqual(lease.options.unavailableInputs, ['casper-db']);
  service.store.finish(lease, 'completed');
});

test('university fixture selections forward approved private Docker target origins', async t => {
  const { service } = setup(t, { autoStartWorker: false, importLegacy: false });
  for (const target of ['http://192.168.0.20:4101', 'http://10.0.0.8:4102', 'http://host.docker.internal:4101', 'http://daehan:3000', 'http://wonchang:8080']) {
    const state = await service.startLab({ fixtureId: 'vul-web2-daehan', target });
    assert.equal(state.run.target, target);
    assert.equal(state.run.manifest.target.origin, target);
    const lease = service.store.claimNext('idor-target-test');
    assert.equal(lease.options.target, target);
    service.store.finish(lease, 'completed');
  }
});

test('university fixtures reject public or malformed targets, AI modes and incompatible profiles before queuing', async t => {
  const { service } = setup(t, { autoStartWorker: false, importLegacy: false });
  for (const options of [
    { fixtureId: 'not-registered' },
    { fixtureId: { toString: 'invalid' } },
    { fixtureId: 'vul-web2-daehan', target: 'http://8.8.8.8:4101' },
    { fixtureId: 'vul-web2-daehan', target: 'http://192.168.0.20:4101/api' },
    { fixtureId: 'vul-web2-daehan', target: 'http://192.168.0.20:4101/?probe=1' },
    { fixtureId: 'vul-web2-daehan', target: 'http://alice:password@192.168.0.20:4101' },
    { fixtureId: 'vul-web2-wonchang', target: 'https://remote.invalid' },
    { fixtureId: 'vul-web2-daehan', mode: 'local-lab-deepseek', modelId: 'deepseek-flash' },
    { fixtureId: 'vul-web2-daehan', mode: 'local-lab-rule', modelId: 'deepseek-flash' },
    { fixtureId: 'vul-web2-daehan', mode: 'core-fixture' },
    { fixtureId: 'vul-web2-daehan', testProfile: 'stored_xss_canary' },
  ]) await assert.rejects(service.start(options), { status: 400 });
  // A model-backed lab request is now a general assessment, which needs a configured model.
  await assert.rejects(service.startLab({ fixtureId: 'vul-web2-wonchang', modelId: 'deepseek-flash' }), { status: 503 });
  assert.equal(service.listRuns().total, 0);
});

test('retired single-check modes and profiles are rejected before queuing over the service and HTTP API', async t => {
  const { service } = setup(t, { autoStartWorker: false, importLegacy: false,
    env: { DEEPSEEK_API_KEY: 'test-key', CASPER_DB_PYTHON: 'unavailable-python-for-retired' } });
  for (const [options, code] of [
    [{ mode: 'core-fixture' }, 'RETIRED_MODE'],
    [{ mode: 'core-fixture', target: 'https://display.invalid', delayMs: 0 }, 'RETIRED_MODE'],
    [{ mode: 'local-lab-deepseek', modelId: 'deepseek-flash' }, 'RETIRED_MODE'],
    [{ mode: 'local-lab-rule' }, 'RETIRED_MODE'],
    [{ mode: 'local-lab-rule', fixtureId: 'vul-web-1', modelId: 'rule-baseline' }, 'RETIRED_MODE'],
    [{ testProfile: 'stored_xss_canary' }, 'RETIRED_PROFILE'],
    [{ testProfile: 'agent_cross_user_delete_canary' }, 'RETIRED_PROFILE'],
  ]) await assert.rejects(service.start(options), { status: 400, code }, JSON.stringify(options));
  await assert.rejects(service.startLab({ modelId: 'rule-baseline' }), { status: 400, code: 'RETIRED_MODE' });
  assert.equal(service.listRuns().total, 0);

  const server = createDashboardServer({ runtime: service,
    auth: createAuthentication({ users: [hashAccount('lab-operator', 'local-test-password', 'operator')] }) });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => server.shutdown());
  const base = `http://127.0.0.1:${server.address().port}`;
  const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'lab-operator', password: 'local-test-password' }) });
  const headers = { 'Content-Type': 'application/json', cookie: login.headers.get('set-cookie').split(';')[0],
    'X-CSRF-Token': (await login.json()).csrfToken };
  for (const body of [{ mode: 'core-fixture' }, { mode: 'local-lab-deepseek', modelId: 'deepseek-flash' },
    { mode: 'local-lab-rule', modelId: 'rule-baseline' }, { testProfile: 'stored_xss_canary' }]) {
    const response = await fetch(`${base}/api/runs`, { method: 'POST', headers, body: JSON.stringify(body) });
    assert.equal(response.status, 400, JSON.stringify(body));
  }
  const lab = await fetch(`${base}/api/lab-runs`, { method: 'POST', headers, body: JSON.stringify({ modelId: 'rule-baseline' }) });
  assert.equal(lab.status, 400);
  assert.equal(service.listRuns().total, 0);
});

test('the board lab defaults to a general assessment and the university rule lab still queues', async t => {
  const { service } = setup(t, { autoStartWorker: false, importLegacy: false,
    env: { DEEPSEEK_API_KEY: 'test-key', CASPER_DB_PYTHON: 'unavailable-python-for-default' } });
  for (const start of [() => service.start({}), () => service.start({ fixtureId: 'vul-web-1' }),
    () => service.startLab({ modelId: 'deepseek-flash' })]) {
    const state = await start();
    assert.equal(state.run.mode, 'local-lab-general');
    assert.equal(state.run.modelId, 'deepseek-flash');
    assert.equal(state.run.testProfile, 'general');
    assert.equal(state.run.fixtureId, 'vul-web-1');
    service.store.finish(service.store.claimNext('default-mode-test'), 'completed');
  }
  const idor = await service.startLab({ fixtureId: 'vul-web2-daehan' });
  assert.equal(idor.run.mode, 'local-lab-rule');
  assert.equal(idor.run.testProfile, 'known_record_idor_read');
  assert.equal(service.store.claimNext('idor-still-queues').options.testProfile, 'known_record_idor_read');
});

test('legacy imports remain in history without replacing the current interactive run', async t => {
  const { service, reopen } = setup(t, { autoStartWorker: false, importLegacy: false });
  const live = await service.startLab({ fixtureId: 'vul-web2-daehan' });
  service.store.importLegacyRun({ runId: 'legacy-after-live', report: {
    runId: 'legacy-after-live', status: 'completed', startedAt: new Date().toISOString(),
  }, events: [] });
  await service.close();

  const restarted = reopen({ importLegacy: false });
  assert.equal(restarted.getState().run.id, live.run.id);
  assert.equal(restarted.getRun('legacy-after-live').mode, 'legacy-import');
});

test('a store containing only legacy reports starts with an idle interactive state', async t => {
  const { service, reopen } = setup(t, { autoStartWorker: false, importLegacy: false });
  service.store.importLegacyRun({ runId: 'legacy-only', report: {
    runId: 'legacy-only', status: 'completed', startedAt: new Date().toISOString(),
  }, events: [] });
  await service.close();

  const restarted = reopen({ importLegacy: false });
  assert.equal(restarted.getState().run.status, 'idle');
  assert.equal(restarted.listRuns({ mode: 'legacy-import' }).items.length, 1);
});

test('a stored core-fixture run stays readable through the run API and remains the current run after restart', async t => {
  const { service, reopen } = setup(t, { autoStartWorker: false, importLegacy: false });
  const id = 'stored-core-fixture-run';
  service.store.createRun({ id, mode: 'core-fixture', modelId: 'rule-baseline', manifest: { runId: id },
    state: { id, mode: 'core-fixture', modelId: 'rule-baseline', status: 'queued', simulated: true, events: [] },
    options: { delayMs: 0 } });
  const lease = service.store.claimNext('stored-history-test');
  service.store.saveState(lease, { ...service.getRun(id), status: 'completed',
    report: { runId: id, finding: { status: 'confirmed' } } });
  service.store.finish(lease, 'completed');
  await service.close();

  const restarted = reopen({ importLegacy: false });
  assert.equal(restarted.getState().run.id, id);
  const server = createDashboardServer({ runtime: restarted,
    auth: createAuthentication({ users: [hashAccount('history-viewer', 'local-test-password', 'viewer')] }) });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => server.shutdown());
  const base = `http://127.0.0.1:${server.address().port}`;
  const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'history-viewer', password: 'local-test-password' }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const list = await fetch(`${base}/api/runs`, { headers: { cookie } });
  assert.equal(list.status, 200);
  assert.deepEqual((await list.json()).runs.map(item => [item.id, item.mode, item.status]), [[id, 'core-fixture', 'completed']]);
  const detail = await fetch(`${base}/api/runs/${id}`, { headers: { cookie } });
  assert.equal(detail.status, 200);
  const { run } = await detail.json();
  assert.equal(run.mode, 'core-fixture');
  assert.equal(run.report.finding.status, 'confirmed');
});
