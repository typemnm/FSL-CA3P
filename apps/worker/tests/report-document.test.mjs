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
  assert.fail('worker state did not settle');
}
async function setup(t, { status = 'completed', mode = 'local-lab-rule', reportGenerator } = {}) {
  const temporaryRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(temporaryRoot, { recursive: true });
  const directory = mkdtempSync(join(temporaryRoot, 'rw-'));
  const storePath = join(directory, 'runs.sqlite');
  const id = 'worker-report-run';
  const store = createRunRepository({ path: storePath });
  store.createRun({ id, mode, modelId: 'rule-baseline', manifest: { runId: id, modules: {}, shared: {} },
    state: { id, mode, modelId: 'rule-baseline', status: 'queued', events: [], simulated: mode === 'core-fixture' }, options: { delayMs: 0 } });
  store.close();
  const board = { alive: false, closed: 0 };
  const runtimeFactory = () => {
    let state; const listeners = new Set();
    const start = () => {
      board.alive = mode !== 'core-fixture';
      state = { run: { id, mode, status, events: [], simulated: mode === 'core-fixture',
        report: { schemaVersion: '1.0', runId: id, status: status === 'stopped' ? 'failed' : status,
          finding: { status: status === 'completed' ? 'confirmed' : 'not_confirmed' } } } };
      for (const listener of listeners) listener(structuredClone(state));
      return state;
    };
    return { subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
      start, startLab: async () => start(), getState: () => structuredClone(state), stop() {},
      async close() { board.alive = false; board.closed += 1; } };
  };
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10, envFile: null, env: {},
    runtimeFactory, ...(reportGenerator ? { reportGenerator: input => reportGenerator(input, board, worker) } : {}) });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  return { worker, board, id };
}

test('report generation reads the persisted core JSON while the board and lease remain alive', async t => {
  const { worker, board, id } = await setup(t, { reportGenerator: async ({ run, signal }, target, currentWorker) => {
    assert.equal(target.alive, true);
    assert.equal(signal.aborted, false);
    const saved = currentWorker.store.getRun(run.id);
    assert.equal(saved.report.finding.status, 'confirmed');
    assert.equal(saved.reportDocument.status, 'generating');
    assert.equal(saved.status, 'running');
    return { status: 'ready', filename: 'report.hwpx', bytes: Buffer.from('PK\x03\x04synthetic') };
  } });
  const run = await waitFor(() => { const value = worker.store.getRun(id); return value.status === 'completed' && !board.alive && value; });
  assert.equal(run.reportDocument.status, 'ready');
  assert.ok(run.reportDocument.artifactId);
  assert.equal(worker.store.getArtifact(run.reportDocument.artifactId).kind, 'hwpx-report');
  assert.equal(board.closed, 1);
});

test('failed inspections can produce documents; document failures do not fail successful inspections', async t => {
  for (const status of ['completed', 'failed']) {
    const { worker, board, id } = await setup(t, { status, reportGenerator: async () => {
      if (status === 'completed') throw new Error('PRIVATE RAW FAILURE');
      return { status: 'ready', filename: 'failed-inspection.hwpx', bytes: Buffer.from('PK\x03\x04synthetic') };
    } });
    const run = await waitFor(() => { const value = worker.store.getRun(id); return value.status === status && !board.alive && value.reportDocument && value; });
    assert.equal(run.reportDocument.status, status === 'completed' ? 'failed' : 'ready');
    assert.equal(run.report.status, status);
    assert.doesNotMatch(JSON.stringify(run.reportDocument), /PRIVATE/);
  }
});

test('fixture and stopped inspections skip generation, missing settings are unavailable', async t => {
  for (const options of [{ mode: 'core-fixture' }, { status: 'stopped' }, {}]) {
    const skip = options.mode || options.status;
    const { worker, board, id } = await setup(t, { ...options,
      ...(skip ? { reportGenerator: () => assert.fail('skipped runs must not invoke the report agent') } : {}) });
    const run = await waitFor(() => { const value = worker.store.getRun(id); return !board.alive && value.reportDocument && value; });
    assert.equal(run.reportDocument.status, skip ? 'skipped' : 'unavailable');
    assert.equal(run.status, options.status === 'stopped' ? 'cancelled' : 'completed');
  }
});

test('cancelling document generation aborts it and cleans up without changing the completed finding', async t => {
  const { worker, board, id } = await setup(t, { reportGenerator: ({ signal }) => new Promise(resolve => {
    signal.addEventListener('abort', () => resolve({ status: 'failed', errorCode: 'REPORT_CANCELLED', message: '취소됨' }), { once: true });
  }) });
  await waitFor(() => worker.store.getRun(id).reportDocument?.status === 'generating');
  worker.store.requestCancel(id);
  const run = await waitFor(() => { const value = worker.store.getRun(id); return value.status === 'completed' && !board.alive && value; });
  assert.equal(run.report.finding.status, 'confirmed');
  assert.equal(run.reportDocument.errorCode, 'REPORT_CANCELLED');
  assert.equal(board.closed, 1);
});
