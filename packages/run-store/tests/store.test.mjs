import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createRunRepository, readArtifactBytes } from '../index.mjs';
import { spawnSync } from 'node:child_process';

function setup(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-store-test-'));
  const path = join(directory, 'runs.sqlite');
  const store = createRunRepository({ path, ...options });
  const handles = [store];
  t.after(() => { for (const handle of handles.reverse()) handle.close(); rmSync(directory, { recursive: true, force: true }); });
  return { store, path, directory, reopen() {
    const second = createRunRepository({ path }); handles.push(second); return second;
  } };
}
function enqueue(store, id = 'run-test') {
  return store.createRun({ id, mode: 'core-fixture', modelId: 'rule-baseline', manifest: { runId: id },
    state: { id, mode: 'core-fixture', modelId: 'rule-baseline', events: [], status: 'queued' }, options: { delayMs: 0 } });
}
test('runs, ordered events and redacted artifacts survive reopen; manifests do not change', t => {
  const { store, reopen } = setup(t);
  enqueue(store); const lease = store.claimNext('worker-a');
  const state = { id: 'run-test', status: 'running', events: [{ id: 'event-a', payload: { cookie: 'private', total_tokens: 13 } }] };
  store.saveState(lease, state); store.saveState(lease, state);
  assert.equal(store.listEvents('run-test').length, 1);
  assert.equal(store.listEvents('run-test')[0].sequence, 1);
  const artifact = store.writeArtifact('run-test', 'report', { authorization: 'private', value: 42 });
  assert.equal(JSON.parse(readArtifactBytes(artifact)).authorization, '[REDACTED]');
  store.finish(lease, 'completed');
  const second = reopen();
  assert.equal(second.getRun('run-test').status, 'completed');
  assert.deepEqual(second.getRun('run-test').manifest, { runId: 'run-test' });
  assert.equal(second.listEvents('run-test')[0].payload.cookie, '[REDACTED]');
  assert.equal(second.listEvents('run-test')[0].payload.total_tokens, 13);
  writeFileSync(artifact.path, '{}');
  assert.throws(() => readArtifactBytes(artifact), { code: 'ARTIFACT_CHANGED' });
});
test('lease expiry interrupts a mutation run and fences both stale completion and replay', t => {
  let time = 100; const { store } = setup(t, { clock: () => time });
  enqueue(store); const lease = store.claimNext('worker-a', { leaseMs: 10 });
  store.reserveAction(lease, { actionId: 'inject', request: { method: 'POST' } });
  assert.throws(() => store.reserveAction(lease, { actionId: 'inject', request: { method: 'POST' } }), { code: 'ACTION_ALREADY_RESERVED' });
  time = 111; assert.deepEqual(store.recoverExpired(), ['run-test']);
  assert.equal(store.getRun('run-test').status, 'interrupted');
  assert.equal(store.listActions('run-test')[0].status, 'unknown');
  assert.equal(store.claimNext('worker-b'), null);
  assert.throws(() => store.completeAction(lease, 'inject', {}), { code: 'LEASE_LOST' });
  assert.throws(() => store.saveState(lease, { id: 'run-test', status: 'completed' }), { code: 'LEASE_LOST' });
});
test('two repositories claim a job once; cancel blocks dispatch while preserving finalization', t => {
  const { store, reopen } = setup(t); enqueue(store);
  const second = reopen();
  const lease = store.claimNext('worker-a'); assert.equal(second.claimNext('worker-b'), null);
  second.requestCancel('run-test');
  assert.throws(() => store.reserveAction(lease, { actionId: 'delete', request: {} }), { code: 'RUN_CANCELLED' });
  assert.equal(store.heartbeat(lease).cancelRequested, true);
  store.saveState(lease, { id: 'run-test', status: 'cancelled', events: [] });
  store.finish(lease, 'cancelled'); assert.equal(second.getRun('run-test').status, 'cancelled');
});
test('legacy JSON import is idempotent and never invents code or model provenance', t => {
  const { store } = setup(t);
  const value = { runId: 'old-run', report: { report: { runId: 'old-run', status: 'completed' } },
    events: [{ messageId: 'old-message', event: { stage: 'loop.reflect' } }] };
  store.importLegacyRun(value); store.importLegacyRun(value);
  assert.equal(store.listRuns().total, 1);
  assert.equal(store.getRun('old-run').manifest.source.commitSha, null);
  assert.equal(store.getRun('old-run').provenanceIncomplete, true);
  assert.equal(store.getRun('old-run').events.length, 1);
});
test('review records update only linked checks and preserve a durable audit', t => {
  const { store } = setup(t); enqueue(store); const lease = store.claimNext('worker-a');
  store.saveState(lease, { id: 'run-test', status: 'completed', events: [],
    historyWrite: { status: 'synced', checks: [{ check_id: 'CHECK-a', run_id: 'run-test', review_status: 'draft' }] } });
  store.finish(lease, 'completed');
  const review = { check_id: 'CHECK-a', run_id: 'run-test', review_status: 'reviewed', reviewer: 'member-a' };
  const next = store.recordReview('run-test', review);
  assert.equal(next.historyWrite.checks[0].review_status, 'reviewed'); assert.equal(next.reviewAudit.length, 1);
  assert.throws(() => store.recordReview('run-test', { ...review, check_id: 'CHECK-other' }), { code: 'CHECK_NOT_LINKED' });
});

test('experiment reset fences every connection and removes complete run records and SQLite remnants', t => {
  const { store, reopen, path } = setup(t); enqueue(store);
  const lease = store.claimNext('worker-a');
  store.reserveAction(lease, { actionId: 'action-a', request: { marker: 'old-experiment-evidence-marker' } });
  store.completeAction(lease, 'action-a', { marker: 'old-experiment-evidence-marker' });
  store.recordModelCall(lease, { prompt: 'old-experiment-evidence-marker' });
  store.writeArtifact('run-test', 'report', { marker: 'old-experiment-evidence-marker' });
  store.saveState(lease, { id: 'run-test', status: 'completed', events: [{ id: 'old-event', marker: 'old-experiment-evidence-marker' }],
    historyWrite: { checks: [{ check_id: 'check-a', run_id: 'run-test' }] } });
  // A terminal public state is insufficient while the worker still owns its lease.
  assert.throws(() => store.beginExperimentReset('reset-a'), { code: 'RUN_ACTIVE' });
  store.finish(lease, 'completed');
  store.recordReview('run-test', { check_id: 'check-a', run_id: 'run-test', review_status: 'reviewed' });
  const second = reopen();
  store.beginExperimentReset('reset-a');
  assert.throws(() => enqueue(second, 'racing-run'), { code: 'EXPERIMENT_RESET_REQUIRED' });
  assert.equal(second.claimNext('worker-b'), null);
  assert.throws(() => second.beginExperimentReset('reset-b'), { code: 'EXPERIMENT_BUSY' });
  const result = store.completeExperimentReset('reset-a', { files: 1 });
  assert.equal(result.deleted.runs, 1); assert.equal(result.deleted.run_events, 1);
  assert.equal(result.deleted.action_intents, 1); assert.equal(result.deleted.model_calls, 1);
  assert.equal(result.deleted.review_audit, 1); assert.equal(result.deleted.artifacts, 1);
  assert.equal(second.getRun('run-test'), null); assert.equal(second.listRuns().total, 0);
  assert.equal(second.experimentState().status, 'ready'); assert.equal(second.experimentState().epoch, 1);
  assert.equal(readFileSync(path).includes(Buffer.from('old-experiment-evidence-marker')), false);
  enqueue(second, 'fresh-run');
});

test('failed reset remains fenced across reopen and permits an explicit retry', t => {
  const { store, reopen } = setup(t);
  store.beginExperimentReset('reset-a'); store.failExperimentReset('reset-a');
  const second = reopen();
  assert.equal(second.experimentState().status, 'failed');
  assert.throws(() => enqueue(second), { code: 'EXPERIMENT_RESET_REQUIRED' });
  second.beginExperimentReset('reset-b'); second.completeExperimentReset('reset-b');
  assert.equal(store.experimentState().epoch, 1); enqueue(store);
});

test('review mutation lock excludes reset until the external write finishes', t => {
  const { store, reopen } = setup(t); const second = reopen();
  store.beginExperimentMutation('review-a');
  assert.throws(() => second.beginExperimentReset('reset-a'), { code: 'EXPERIMENT_BUSY' });
  assert.throws(() => second.beginExperimentMutation('review-b'), { code: 'EXPERIMENT_RESET_REQUIRED' });
  store.endExperimentMutation('review-a');
  second.beginExperimentReset('reset-a'); second.completeExperimentReset('reset-a');
});

test('an abandoned process operation requires a fresh reset instead of silently resuming', t => {
  const { store } = setup(t);
  const exited = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' });
  assert.equal(exited.status, 0);
  store.beginExperimentReset(`api-${exited.stdout}-reset-test`);
  assert.equal(store.recoverAbandonedExperimentOperation(), true);
  assert.equal(store.experimentState().status, 'failed');
  assert.throws(() => enqueue(store), { code: 'EXPERIMENT_RESET_REQUIRED' });
});
