import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRunRepository } from '../../../packages/run-store/index.mjs';
import { targetResetObligationsForRuns } from '../../application/experiment-targets.mjs';
import { normalizeExternalTarget } from '../../application/external-target.mjs';
import { runWorker } from '../worker.mjs';

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

test('external worker persists a bounded model loop without confirming unverified hypotheses', async t => {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'ca3p-external-model-worker-'));
  const storePath = join(directory, 'runs.sqlite3');
  const { normalizedUrl, scope } = normalizeExternalTarget({ target: 'https://8.8.8.8/start',
    scope: { pathPrefix: '/start' } });
  const id = 'external-model-worker-run';
  const loopBudget = { maxIterations: 3, maxProbes: 7, maxEvidenceItems: 32 };
  const store = createRunRepository({ path: storePath });
  store.createRun({ id, mode: 'external-general', modelId: 'deepseek-flash',
    manifest: { runId: id, modules: {}, shared: {}, target: { kind: 'external', origin: scope.origin } },
    state: { id, mode: 'external-general', assessmentMode: 'general', modelId: 'deepseek-flash',
      status: 'queued', events: [] },
    options: { mode: 'external-general', modelId: 'deepseek-flash', target: normalizedUrl, scope,
      testProfile: 'external-general-read-only', fixtureId: null, delayMs: 0, loopBudget } });
  store.close();
  const requested = [];
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10,
    env: { DEEPSEEK_API_KEY: 'test-key' },
    externalRequestImpl: async url => { requested.push(url); return {
      status: 200, contentType: 'text/html', durationMs: 1, truncated: false,
      body: url === normalizedUrl ? '<title>Start</title><a href="/start/child">child</a>' : '<title>Child</title>',
    }; },
    generalPlannerFactory: () => ({ async propose(context) {
      const modelMetadata = { provider: 'deepseek', requestedModel: 'deepseek-flash', status: 'completed' };
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [], modelMetadata };
      return { done: false, hypotheses: [{ id: 'h-observe', category: 'unknown',
        asset: '/start/child', rationale: 'Review the discovered public page.',
        evidenceIds: [context.evidence[0].id] }],
      probes: [{ id: 'p-observe', hypothesisId: 'h-observe', tool: 'http_get',
        input: { path: '/start/child' } }], modelMetadata };
    } }),
    reportGenerator: () => assert.fail('unconfirmed external hypotheses must not generate HWPX') });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  const final = await waitFor(() => {
    const value = worker.store.getRun(id);
    return ['completed', 'failed', 'cancelled'].includes(value.status) && value;
  });
  assert.equal(final.status, 'completed', final.error);
  assert.deepEqual(requested, [normalizedUrl, 'https://8.8.8.8/start/child']);
  assert.equal(final.report.inspectionMode, 'external-general-read-only');
  assert.equal(final.report.findings.length, 1);
  assert.equal(final.report.findings[0].status, 'inconclusive');
  assert.equal(final.modelCalls.length, 2);
  assert.equal(final.reportDocuments.status, 'skipped');
});

test('external worker rejects queued model and profile mismatches before contacting the target', async t => {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'ca3p-external-invalid-worker-'));
  const storePath = join(directory, 'runs.sqlite3');
  const { normalizedUrl, scope } = normalizeExternalTarget({ target: 'https://8.8.8.8/start' });
  const loopBudget = { maxIterations: 3, maxProbes: 7, maxEvidenceItems: 32 };
  const invalid = [
    { id: 'wrong-baseline-profile', modelId: 'rule-baseline',
      testProfile: 'external-general-read-only', loopBudget: undefined },
    { id: 'wrong-model-profile', modelId: 'deepseek-flash',
      testProfile: 'external-read-only', loopBudget },
    { id: 'missing-model-budget', modelId: 'deepseek-flash',
      testProfile: 'external-general-read-only', loopBudget: undefined },
    { id: 'oversized-model-budget', modelId: 'deepseek-flash',
      testProfile: 'external-general-read-only',
      loopBudget: { ...loopBudget, maxProbes: scope.maxRequests } },
  ];
  const store = createRunRepository({ path: storePath });
  for (const item of invalid) store.createRun({ id: item.id, mode: 'external-general', modelId: item.modelId,
    manifest: { runId: item.id, modules: {}, shared: {}, target: { kind: 'external', origin: scope.origin } },
    state: { id: item.id, mode: 'external-general', modelId: item.modelId, status: 'queued', events: [] },
    options: { mode: 'external-general', modelId: item.modelId, target: normalizedUrl, scope,
      testProfile: item.testProfile, fixtureId: null, delayMs: 0,
      ...(item.loopBudget ? { loopBudget: item.loopBudget } : {}) } });
  store.close();
  let requestCount = 0;
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10,
    externalRequestImpl: async () => { requestCount += 1; throw new Error('unexpected external request'); } });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  await waitFor(() => invalid.every(item => worker.store.getRun(item.id).status === 'failed'));
  for (const item of invalid) assert.match(worker.store.getRun(item.id).error, /^INVALID_EXTERNAL_RUN:/u);
  assert.equal(requestCount, 0);
});
