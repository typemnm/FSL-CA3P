import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRunRepository } from '../../../packages/run-store/index.mjs';
import { targetResetObligationsForRuns } from '../../application/experiment-targets.mjs';
import { normalizeExternalTarget } from '../../application/external-target.mjs';
import { runWorker } from '../worker.mjs';
import { digest } from '../../../packages/contracts/index.mjs';

async function waitFor(check, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail('external worker did not settle');
}

test('external worker observes public pages, stores the report, and skips HWPX without confirmed findings', async t => {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'ca3p-external-worker-'));
  const storePath = join(directory, 'runs.sqlite3');
  const { normalizedUrl, scope } = normalizeExternalTarget({ target: 'https://8.8.8.8/start',
    scope: { pathPrefix: '/start' } });
  const id = 'external-worker-run';
  const store = createRunRepository({ path: storePath });
  store.createRun({ id, mode: 'external-general', modelId: 'rule-baseline',
    manifest: { runId: id, modules: {}, shared: {}, target: { kind: 'external', origin: scope.origin } },
    state: { id, mode: 'external-general', assessmentMode: 'general', modelId: 'rule-baseline',
      status: 'queued', events: [] },
    options: { mode: 'external-general', modelId: 'rule-baseline', target: normalizedUrl, scope,
      testProfile: 'external-read-only', fixtureId: null, delayMs: 0 } });
  store.close();
  const requested = [];
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10,
    externalRequestImpl: async url => { requested.push(url); return {
      status: 200, contentType: 'text/html', durationMs: 1, truncated: false,
      body: '<title>Public</title><a href="/outside">outside</a>',
    }; },
    reportGenerator: () => { throw new Error('No document should be generated.'); } });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  const final = await waitFor(() => {
    const value = worker.store.getRun(id);
    return ['completed', 'failed', 'cancelled'].includes(value.status) && value;
  });
  assert.equal(final.status, 'completed', final.error);
  assert.ok(final.reportDocuments?.completedAt);
  assert.deepEqual(requested, [normalizedUrl]);
  assert.equal(final.targetContacted, true);
  assert.equal(final.report.inspectionMode, 'external-read-only');
  assert.deepEqual(targetResetObligationsForRuns([final]), []);
  assert.deepEqual(final.report.findings, []);
  assert.deepEqual(final.report.policyRejections,
    { total: 1, byReason: { out_of_scope_path: 1 } });
  assert.equal(final.events.some(event => event.policy?.reason === 'out_of_scope_path'), true);
  assert.equal(final.historyWrite.status, 'skipped');
  assert.equal(final.reportDocuments.status, 'skipped');
  assert.equal(final.reportDocuments.errorCode, 'NO_CONFIRMED_FINDINGS');
});

test('worker preserves reviewed parser pages in history and report and detects a changed snapshot', async t => {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'ca3p-reviewed-external-worker-'));
  const storePath = join(directory, 'runs.sqlite3');
  const { normalizedUrl, scope } = normalizeExternalTarget({ target: 'https://8.8.8.8/start',
    scope: { pathPrefix: '/start' } });
  const parserPreview = { previewId: 'worker-reviewed-1', targetKind: 'external', fixtureId: null,
    origin: scope.origin, entryUrl: normalizedUrl, expiresAt: '2099-01-01T00:00:00.000Z',
    discoveredPaths: [], pages: [normalizedUrl, `${scope.origin}/start/reviewed`].map(url => ({
      url, status: 200, contentType: 'text/html', technologies: [], libraries: [],
      forms: [], paths: [], errors: [], truncated: false, mode: 'http-response' })) };
  const store = createRunRepository({ path: storePath });
  for (const [id, expectedDigest] of [['reviewed-worker-valid', digest(parserPreview)],
    ['reviewed-worker-tampered', '0'.repeat(64)]]) {
    store.createRun({ id, mode: 'external-general', modelId: 'rule-baseline',
      manifest: { runId: id, modules: {}, shared: {}, data: { parserPreviewDigest: expectedDigest },
        target: { kind: 'external', origin: scope.origin } },
      state: { id, mode: 'external-general', assessmentMode: 'general', modelId: 'rule-baseline',
        status: 'queued', parserPreview, events: [] },
      options: { mode: 'external-general', modelId: 'rule-baseline', target: normalizedUrl, scope,
        testProfile: 'external-read-only', fixtureId: null, delayMs: 0, parserPreview } });
  }
  store.close();
  const requested = [];
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10,
    externalRequestImpl: async url => { requested.push(url); return {
      status: 200, contentType: 'text/html', durationMs: 1, truncated: false, body: '<title>Public</title>',
    }; },
    reportGenerator: () => { throw new Error('No document should be generated.'); } });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  const valid = await waitFor(() => {
    const value = worker.store.getRun('reviewed-worker-valid');
    return ['completed', 'failed', 'cancelled'].includes(value.status) && value;
  });
  const tampered = await waitFor(() => {
    const value = worker.store.getRun('reviewed-worker-tampered');
    return ['completed', 'failed', 'cancelled'].includes(value.status) && value;
  });
  assert.equal(valid.status, 'completed', valid.error);
  assert.deepEqual(valid.parserPreview, parserPreview);
  assert.deepEqual(valid.report.parserPreview, parserPreview);
  assert.deepEqual(requested, [normalizedUrl, `${scope.origin}/start/reviewed`]);
  assert.equal(tampered.status, 'failed');
  assert.match(tampered.error, /CONDITION_CHANGED/u);
  assert.deepEqual(tampered.parserPreview, parserPreview);
});

test('external worker rejects a changed Web Parser fingerprint dataset before requesting the target', async t => {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'ca3p-external-dataset-'));
  const storePath = join(directory, 'runs.sqlite3');
  const { normalizedUrl, scope } = normalizeExternalTarget('https://8.8.8.8/start');
  const id = 'external-stale-dataset';
  const store = createRunRepository({ path: storePath });
  store.createRun({ id, mode: 'external-general', modelId: 'rule-baseline',
    manifest: { runId: id, modules: {}, shared: {}, data: { datasetDigest: 'stale' },
      target: { kind: 'external', origin: scope.origin } },
    state: { id, mode: 'external-general', assessmentMode: 'general', modelId: 'rule-baseline',
      status: 'queued', events: [] },
    options: { mode: 'external-general', modelId: 'rule-baseline', target: normalizedUrl, scope,
      testProfile: 'external-read-only', fixtureId: null, delayMs: 0 } });
  store.close();
  let requests = 0;
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10,
    externalRequestImpl: async () => { requests += 1; throw new Error('unexpected request'); } });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  const final = await waitFor(() => {
    const value = worker.store.getRun(id);
    return ['completed', 'failed', 'cancelled'].includes(value.status) && value;
  });
  assert.equal(final.status, 'failed');
  assert.match(final.error, /CONDITION_CHANGED/);
  assert.equal(requests, 0);
});
