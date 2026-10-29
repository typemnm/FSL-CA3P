import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRunRepository } from '../../../packages/run-store/index.mjs';
import { targetResetObligationsForRuns } from '../../application/experiment-targets.mjs';
import { normalizeExternalTarget } from '../../application/external-target.mjs';
import { createExternalGeneralRuntime } from '../../application/external-runtime.mjs';
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

test('external worker runs the general loop on a scoped public target and skips HWPX without confirmed findings', async t => {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'ca3p-external-worker-'));
  const storePath = join(directory, 'runs.sqlite3');
  const { normalizedUrl, scope } = normalizeExternalTarget({ target: 'https://8.8.8.8/start',
    scope: { pathPrefix: '/start' } });
  const id = 'external-worker-run';
  const store = createRunRepository({ path: storePath });
  store.createRun({ id, mode: 'external-general', modelId: 'deepseek-flash',
    manifest: { runId: id, modules: {}, shared: {}, target: { kind: 'external', origin: scope.origin },
      execution: { inspectionMode: 'external-general' }, policy: { methods: ['GET', 'HEAD'] } },
    state: { id, mode: 'external-general', assessmentMode: 'general', modelId: 'deepseek-flash',
      status: 'queued', events: [] },
    options: { mode: 'external-general', modelId: 'deepseek-flash', target: normalizedUrl, scope,
      testProfile: 'external-general', fixtureId: null, delayMs: 0,
      loopBudget: { maxIterations: 6, maxProbes: 24, maxEvidenceItems: 128 } } });
  store.close();
  const requested = [];
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10,
    generalPlannerFactory: () => ({ async propose() { return { done: true, hypotheses: [], probes: [],
      modelMetadata: { provider: 'deepseek', model: 'deepseek-flash' } }; } }),
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
  assert.equal(final.report.inspectionMode, 'external-general');
  assert.equal(final.report.iterations, 1);
  assert.equal(final.report.modelCalls.length, 1);
  assert.deepEqual(targetResetObligationsForRuns([final]), []);
  assert.deepEqual(final.report.findings, []);
  assert.deepEqual(final.report.policyRejections,
    { total: 1, byReason: { out_of_scope_path: 1 } });
  assert.equal(final.events.some(event => event.policy?.reason === 'out_of_scope_path'), true);
  assert.equal(final.historyWrite.status, 'skipped');
  assert.equal(final.reportDocuments.status, 'skipped');
  assert.equal(final.reportDocuments.errorCode, 'NO_CONFIRMED_FINDINGS');
});

test('external worker carries an independently confirmed finding into the HWPX handoff', async t => {
  const runtimeRoot = fileURLToPath(new URL('../../../.runtime/', import.meta.url));
  mkdirSync(runtimeRoot, { recursive: true });
  const directory = mkdtempSync(join(runtimeRoot, 'ca3p-external-confirmed-'));
  const storePath = join(directory, 'runs.sqlite3');
  const { normalizedUrl, scope } = normalizeExternalTarget({ target: 'https://8.8.8.8/start',
    scope: { pathPrefix: '/start' } });
  const id = 'external-worker-confirmed';
  const store = createRunRepository({ path: storePath });
  store.createRun({ id, mode: 'external-general', modelId: 'deepseek-flash',
    manifest: { runId: id, modules: {}, shared: {}, target: { kind: 'external', origin: scope.origin },
      execution: { inspectionMode: 'external-general' }, policy: { methods: ['GET', 'HEAD'] } },
    state: { id, mode: 'external-general', assessmentMode: 'general', modelId: 'deepseek-flash',
      status: 'queued', events: [] },
    options: { mode: 'external-general', modelId: 'deepseek-flash', target: normalizedUrl, scope,
      testProfile: 'external-general', fixtureId: null, delayMs: 0,
      loopBudget: { maxIterations: 6, maxProbes: 24, maxEvidenceItems: 128 } } });
  store.close();

  const requested = []; const reportArgs = []; const verdicts = [];
  let verificationRoot;
  const worker = await runWorker({ storePath, pollMs: 10, heartbeatMs: 10,
    generalPlannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [],
        modelMetadata: { provider: 'deepseek', model: 'deepseek-flash' } };
      return { done: false, hypotheses: [{ id: 'h-reflect', category: 'reflected_input',
        asset: '/start/search', rationale: 'Compare a marker with an ordinary value.',
        evidenceIds: [context.evidence[0].id] }],
      probes: [{ id: 'p-compare', hypothesisId: 'h-reflect', tool: 'http_compare',
        input: { path: '/start/search?probe=canary', controlPath: '/start/search?probe=ordinary' } }],
      modelMetadata: { provider: 'deepseek', model: 'deepseek-flash' } };
    } }),
    externalRequestImpl: async url => {
      requested.push(url);
      return { status: 200, contentType: 'text/html', durationMs: 1, truncated: false,
        body: url === normalizedUrl ? '<title>Start</title><a href="/start/search">Search</a>'
          : url.endsWith('/start/search') ? '<title>Search</title>'
            : url.includes('probe=canary') ? '<p>canary was reflected</p>' : '<p>ordinary result</p>' };
    },
    externalRuntimeFactory: options => {
      verificationRoot = options.verificationRoot;
      return createExternalGeneralRuntime({ ...options,
        verifyAttackImpl: async attack => {
          verdicts.push(attack);
          return { schemaVersion: 'verifier/1', attackId: attack.id, status: 'confirmed',
            reason: 'Only the candidate response reflects the marker.', artifacts: [] };
        } });
    },
    reportGenerator: args => {
      reportArgs.push(args);
      return { status: 'ready', filename: 'external-confirmed.hwpx',
        bytes: Buffer.from('PK\x03\x04external-confirmed') };
    } });
  t.after(async () => { await worker.shutdown(); rmSync(directory, { recursive: true, force: true }); });
  const final = await waitFor(() => {
    const value = worker.store.getRun(id);
    return value.status === 'completed' && value.reportDocuments?.completedAt && value;
  }, 10_000);
  assert.equal(final.report.inspectionMode, 'external-general');
  assert.equal(final.report.findings[0].id, 'finding:h-reflect');
  assert.equal(final.report.findings[0].status, 'confirmed');
  assert.equal(final.report.probes[0].status, 'confirmed');
  assert.equal(verdicts.length, 1);
  assert.deepEqual(requested, [normalizedUrl, `${scope.origin}/start/search`,
    `${scope.origin}/start/search?probe=ordinary`, `${scope.origin}/start/search?probe=canary`]);
  assert.deepEqual(reportArgs.map(args => args.findingId), ['finding:h-reflect']);
  assert.equal(reportArgs[0].verificationDir, join(verificationRoot, 'p-compare'));
  assert.equal(existsSync(join(reportArgs[0].verificationDir, 'verification.json')), true);
  assert.equal(final.reportDocuments.status, 'ready');
  assert.deepEqual(final.reportDocuments.items.map(item => [item.findingId, item.status, item.filename]),
    [['finding:h-reflect', 'ready', 'external-confirmed.hwpx']]);
  assert.equal(worker.store.getArtifact(final.reportDocuments.items[0].artifactId).kind, 'hwpx-report');
});
