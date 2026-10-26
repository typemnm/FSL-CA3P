import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRunService } from '../run-service.mjs';

function setup(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-service-test-')); const storePath = join(directory, 'runs.sqlite');
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
test('a separate worker executes queued fixture runs and history survives API restart', async t => {
  const { service, reopen } = setup(t);
  const started = await service.start({ mode: 'core-fixture', target: 'https://display.invalid', delayMs: 0 });
  assert.equal(started.run.status, 'queued');
  const final = await waitFor(service, started.run.id);
  assert.equal(final.status, 'completed', final.error);
  assert.equal(final.id, final.coreRunId); assert.equal(final.id, final.report.runId);
  assert.equal(final.events.length, 25); assert.equal(final.events.at(-1).sequence, 25);
  assert.ok(final.manifest.modules.agent.contentDigest); assert.ok(final.artifacts.some(item => item.kind === 'run-report'));
  await service.close();
  const restarted = reopen();
  assert.equal(restarted.getState().run.id, final.id); assert.equal(restarted.getRun(final.id).status, 'completed');
});
test('queued cancellation never reaches a worker; arbitrary lab targets are rejected', async t => {
  const { service } = setup(t, { autoStartWorker: false });
  await assert.rejects(service.start({ mode: 'local-lab-rule', target: 'https://remote.invalid' }), { status: 400 });
  const state = await service.start({ mode: 'core-fixture' });
  assert.equal(service.stop(state.run.id).run.status, 'cancelled');
  assert.equal(service.store.claimNext('test-worker'), null); assert.equal(service.reset().run.status, 'idle');
});

test('university fixtures queue their known-record IDOR check without a case database', async t => {
  const { service } = setup(t, { autoStartWorker: false, importLegacy: false,
    env: { DEEPSEEK_API_KEY: '', CASPER_DB_PYTHON: 'unavailable-python-for-idor' } });
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
    { fixtureId: 'vul-web-1', testProfile: 'known_record_idor_read' },
  ]) await assert.rejects(service.start(options), { status: 400 });
  await assert.rejects(service.startLab({ fixtureId: 'vul-web2-wonchang', modelId: 'deepseek-flash' }), { status: 400 });
  assert.equal(service.listRuns().total, 0);
});

test('legacy imports remain in history without replacing the current interactive run', async t => {
  const { service, reopen } = setup(t, { autoStartWorker: false, importLegacy: false });
  const live = await service.start({ mode: 'core-fixture' });
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
