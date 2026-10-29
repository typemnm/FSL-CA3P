import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
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
async function setup(t, { status = 'completed', reportGenerator } = {}) {
  const temporaryRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(temporaryRoot, { recursive: true });
  const directory = mkdtempSync(join(temporaryRoot, 'rw-'));
  const storePath = join(directory, 'runs.sqlite');
  const id = 'worker-report-run';
  const mode = 'local-lab-general';
  const store = createRunRepository({ path: storePath });
  store.createRun({ id, mode, modelId: 'deepseek-flash', manifest: { runId: id, modules: {}, shared: {} },
    state: { id, mode, assessmentMode: 'general', modelId: 'deepseek-flash', status: 'queued', events: [] },
    options: { mode, testProfile: 'general', fixtureId: 'vul-web-1', delayMs: 0 } });
  store.close();
  const board = { alive: false, closed: 0 };
  const generalRuntimeFactory = () => {
    let state; const listeners = new Set();
    return { subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
      async startLab() {
        board.alive = true;
        state = { run: { id, mode, assessmentMode: 'general', status, events: [],
          report: { schemaVersion: 'general-assessment/1', assessmentMode: 'general', runId: id,
            status: status === 'stopped' ? 'failed' : status,
            findings: [{ id: 'finding:h1', status: 'confirmed', evidenceIds: ['e1'] }] } } };
        for (const listener of listeners) listener(structuredClone(state));
      },
      getState: () => structuredClone(state), stop() {},
      async close() { board.alive = false; board.closed += 1; } };
  };
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10, envFile: null, env: {},
    generalRuntimeFactory, ...(reportGenerator ? { reportGenerator: input => reportGenerator(input, board, worker) } : {}) });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  return { worker, board, id };
}

test('report generation reads the persisted core JSON while the board and lease remain alive', async t => {
  const { worker, board, id } = await setup(t, { reportGenerator: async ({ run, signal }, target, currentWorker) => {
    assert.equal(target.alive, true);
    assert.equal(signal.aborted, false);
    const saved = currentWorker.store.getRun(run.id);
    assert.equal(saved.report.findings[0].status, 'confirmed');
    assert.equal(saved.reportDocuments.status, 'generating');
    assert.equal(saved.status, 'running');
    return { status: 'ready', filename: 'report.hwpx', bytes: Buffer.from('PK\x03\x04synthetic'),
      previewMarkdown: '# 검사 보고서\n\n전체 본문',
      previewHtml: '<!doctype html><html><body><table><tr><td>전체 본문</td></tr></table></body></html>' };
  } });
  const run = await waitFor(() => { const value = worker.store.getRun(id); return value.status === 'completed' && !board.alive && value; });
  const [document] = run.reportDocuments.items;
  assert.equal(run.reportDocuments.status, 'ready');
  assert.equal(document.status, 'ready');
  assert.equal(worker.store.getArtifact(document.artifactId).kind, 'hwpx-report');
  const preview = worker.store.getArtifact(document.previewArtifactId);
  assert.equal(preview.kind, 'report-preview');
  assert.equal(readFileSync(preview.path, 'utf8'), '# 검사 보고서\n\n전체 본문');
  const htmlPreview = worker.store.getArtifact(document.previewHtmlArtifactId);
  assert.equal(htmlPreview.kind, 'report-preview-html');
  assert.match(readFileSync(htmlPreview.path, 'utf8'), /<table>/);
  assert.equal(board.closed, 1);
});

test('failed inspections can produce documents; document failures do not fail successful inspections', async t => {
  for (const status of ['completed', 'failed']) {
    const { worker, board, id } = await setup(t, { status, reportGenerator: async () => {
      if (status === 'completed') throw new Error('PRIVATE RAW FAILURE');
      return { status: 'ready', filename: 'failed-inspection.hwpx', bytes: Buffer.from('PK\x03\x04synthetic') };
    } });
    const run = await waitFor(() => { const value = worker.store.getRun(id); return value.status === status && !board.alive && value.reportDocuments && value; });
    assert.equal(run.reportDocuments.status, status === 'completed' ? 'failed' : 'ready');
    assert.equal(run.report.status, status);
    assert.doesNotMatch(JSON.stringify(run.reportDocuments), /PRIVATE/);
  }
});

test('stopped inspections skip generation without invoking the report agent', async t => {
  const { worker, board, id } = await setup(t, { status: 'stopped',
    reportGenerator: () => assert.fail('skipped runs must not invoke the report agent') });
  const run = await waitFor(() => { const value = worker.store.getRun(id); return !board.alive && value.reportDocuments?.completedAt && value; });
  assert.equal(run.reportDocuments.status, 'skipped');
  assert.equal(run.reportDocuments.errorCode, 'RUN_STOPPED');
  assert.equal(run.status, 'cancelled');
});

test('runs queued in a retired single-check mode fail with RETIRED_MODE before any runtime or report work', async t => {
  const temporaryRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(temporaryRoot, { recursive: true });
  const directory = mkdtempSync(join(temporaryRoot, 'rw-'));
  const storePath = join(directory, 'runs.sqlite');
  const retired = [['core-fixture', 'agent_cross_user_delete_canary'], ['local-lab-deepseek', 'stored_xss_canary'],
    ['local-lab-rule', 'stored_xss_canary'], ['local-lab-rule', 'agent_cross_user_delete_canary']];
  const store = createRunRepository({ path: storePath });
  // A pre-upgrade manifest also froze the removed xss-parser lock; the retired code must still win.
  for (const [index, [mode, testProfile]] of retired.entries()) store.createRun({ id: `retired-${index}`, mode,
    modelId: 'rule-baseline', manifest: { runId: `retired-${index}`, modules: {}, shared: { lockDigest: 'stale-xss-parser-lock' } },
    state: { id: `retired-${index}`, mode, modelId: 'rule-baseline', status: 'queued', events: [] },
    options: { delayMs: 0, testProfile, fixtureId: 'vul-web-1' } });
  store.close();
  const unexpected = () => assert.fail('retired runs must not create a runtime');
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10, envFile: null, env: {},
    idorRuntimeFactory: unexpected, generalRuntimeFactory: unexpected, externalRuntimeFactory: unexpected,
    reportGenerator: () => assert.fail('retired runs must not invoke the report agent') });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  const runs = await waitFor(() => { const values = retired.map((_, index) => worker.store.getRun(`retired-${index}`));
    return values.every(value => value.status === 'failed') && values; });
  for (const run of runs) {
    assert.match(run.error, /^RETIRED_MODE: /);
    assert.equal(run.reportDocument, undefined);
    assert.equal(run.reportDocuments, undefined);
  }
});

test('cancelling document generation aborts it and cleans up without changing the completed finding', async t => {
  const { worker, board, id } = await setup(t, { reportGenerator: ({ signal }) => new Promise(resolve => {
    signal.addEventListener('abort', () => resolve({ status: 'failed', errorCode: 'REPORT_CANCELLED', message: '취소됨' }), { once: true });
  }) });
  await waitFor(() => worker.store.getRun(id).reportDocuments?.items[0]?.status === 'generating');
  worker.store.requestCancel(id);
  const run = await waitFor(() => { const value = worker.store.getRun(id); return value.status === 'completed' && !board.alive && value; });
  assert.equal(run.report.findings[0].status, 'confirmed');
  assert.equal(run.reportDocuments.items[0].errorCode, 'REPORT_CANCELLED');
  assert.equal(board.closed, 1);
});
