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
