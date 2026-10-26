import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRunRepository } from '../../../packages/run-store/index.mjs';
import { runWorker } from '../worker.mjs';

async function waitFor(check) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const value = check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail('general worker state did not settle');
}

async function setup(modelId = 'deepseek-flash') {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'general-worker-'));
  const storePath = join(directory, 'runs.sqlite');
  const id = 'general-worker-run';
  const store = createRunRepository({ path: storePath });
  store.createRun({ id, mode: 'local-lab-general', modelId,
    manifest: { runId: id, modules: {}, shared: {} },
    state: { id, mode: 'local-lab-general', assessmentMode: 'general', modelId,
      status: 'queued', events: [] },
    options: { mode: 'local-lab-general', testProfile: 'general', fixtureId: 'vul-web2-daehan',
      target: 'http://127.0.0.1:4101', delayMs: 0 } });
  store.close();
  return { id, storePath, directory };
}

test('general worker uses its own runtime and model, persists the multi-finding report, and skips legacy processors', async t => {
  const { id, storePath, directory } = await setup();
  let legacyInvoked = false; let closed = false; let factoryOptions;
  const report = { schemaVersion: 'general-assessment/1', assessmentMode: 'general',
    status: 'completed', findings: [{ id: 'f1', category: 'access_control', status: 'confirmed', evidenceIds: ['e1'] }],
    evidence: [{ id: 'e1', source: 'http-response', summary: 'role mismatch' }],
    coverage: { totalHypotheses: 2, confirmed: 1, notTested: 1 } };
  const generalRuntimeFactory = options => {
    factoryOptions = options;
    const listeners = new Set(); let state;
    return {
      subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
      async startLab() {
        options.onModelCall({ provider: 'deepseek', requestedModel: options.modelId,
          usage: { prompt_tokens: 8, completion_tokens: 5 } });
        const probe = { iteration: 1, tool: 'http', session: 'test', method: 'POST',
          url: 'http://127.0.0.1:4101/api/probe' };
        const reservation = await options.beforeProbe(probe);
        await options.afterProbe(probe, { status: 'completed', evidenceId: 'e1', body: 'PRIVATE_RESPONSE' }, reservation);
        state = { run: { id, mode: 'local-lab-general', assessmentMode: 'general',
          status: 'completed', events: [{ id: 'event-1', module: 'agent', stage: 'probe.verify', title: 'Verified' }],
          report, reviewItems: [] } };
        for (const listener of listeners) listener(structuredClone(state));
        return state;
      },
      getState() { return structuredClone(state); },
      stop() {},
      async close() { closed = true; },
    };
  };
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10,
    env: { DEEPSEEK_API_KEY: 'test-only' },
    runtimeFactory: () => { legacyInvoked = true; throw new Error('legacy runtime called'); },
    idorRuntimeFactory: () => { legacyInvoked = true; throw new Error('IDOR runtime called'); },
    generalRuntimeFactory,
    reportGenerator: () => assert.fail('generic findings must not go to the single-finding HWPX generator') });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  const final = await waitFor(() => { const state = worker.store.getRun(id); return state.status === 'completed' && closed && state; });
  assert.equal(legacyInvoked, false);
  assert.equal(factoryOptions.modelId, 'deepseek-flash');
  assert.equal(factoryOptions.fixtureId, 'vul-web2-daehan');
  assert.equal(factoryOptions.targetOrigin, 'http://127.0.0.1:4101');
  assert.equal(final.report.schemaVersion, 'general-assessment/1');
  assert.equal(final.report.findings.length, 1);
  assert.equal(final.historyWrite.status, 'skipped');
  assert.equal(final.reportDocument.errorCode, 'GENERAL_DOCUMENT_UNSUPPORTED');
  assert.equal(final.modelCalls.length, 1);
  assert.ok(final.artifacts.some(artifact => artifact.kind === 'run-report'));
  const actions = worker.store.listActions(id);
  assert.equal(actions.length, 1);
  assert.equal(actions[0].status, 'completed');
  assert.doesNotMatch(actions[0].result_json, /PRIVATE_RESPONSE/);
});

test('general worker rejects rule-baseline leases before creating a runtime', async t => {
  const { id, storePath, directory } = await setup('rule-baseline');
  let runtimeCreated = false;
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10, env: {},
    generalRuntimeFactory: () => { runtimeCreated = true; throw new Error('should not start'); } });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  const final = await waitFor(() => { const state = worker.store.getRun(id); return state.status === 'failed' && state; });
  assert.equal(runtimeCreated, false);
  assert.match(final.error, /INVALID_GENERAL_RUN/);
});

test('cancelling a general run aborts its model and closes the runtime', async t => {
  const { id, storePath, directory } = await setup();
  let stopCalls = 0; let closed = false; let signal;
  const generalRuntimeFactory = options => {
    signal = options.signal;
    const listeners = new Set();
    let state = { run: { id, mode: 'local-lab-general', assessmentMode: 'general',
      status: 'running', events: [] } };
    const publish = () => { for (const listener of listeners) listener(structuredClone(state)); };
    return {
      subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
      async startLab() { publish(); return state; },
      stop() { stopCalls += 1; state = { run: { ...state.run, status: 'stopped' } }; publish(); },
      getState() { return structuredClone(state); },
      async close() { closed = true; },
    };
  };
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10, env: {}, generalRuntimeFactory });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  await waitFor(() => worker.store.getRun(id).status === 'running');
  worker.store.requestCancel(id);
  const final = await waitFor(() => { const state = worker.store.getRun(id); return state.status === 'cancelled' && closed && state; });
  assert.ok(stopCalls >= 1);
  assert.equal(signal.aborted, true);
  assert.equal(final.reportDocument.status, 'skipped');
});
