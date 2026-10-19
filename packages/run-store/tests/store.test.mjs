import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createRunRepository, readArtifactBytes } from '../index.mjs';

function setup(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-store-test-'));
  const path = join(directory, 'runs.sqlite');
  const store = createRunRepository({ path, ...options });
  t.after(() => { store.close(); rmSync(directory, { recursive: true, force: true }); });
  return { store, path, directory };
}
function enqueue(store, id = 'run-test') {
  return store.createRun({ id, mode: 'core-fixture', modelId: 'rule-baseline', manifest: { runId: id },
    state: { id, mode: 'core-fixture', modelId: 'rule-baseline', events: [], status: 'queued' }, options: { delayMs: 0 } });
}
test('runs, ordered events and redacted artifacts survive reopen; manifests do not change', t => {
  const { store, path } = setup(t);
  enqueue(store); const lease = store.claimNext('worker-a');
  const state = { id: 'run-test', status: 'running', events: [{ id: 'event-a', payload: { cookie: 'private', total_tokens: 13 } }] };
  store.saveState(lease, state); store.saveState(lease, state);
  assert.equal(store.listEvents('run-test').length, 1);
  assert.equal(store.listEvents('run-test')[0].sequence, 1);
  const artifact = store.writeArtifact('run-test', 'report', { authorization: 'private', value: 42 });
  assert.equal(JSON.parse(readArtifactBytes(artifact)).authorization, '[REDACTED]');
  store.finish(lease, 'completed');
  const second = createRunRepository({ path }); t.after(() => second.close());
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
  const { store, path } = setup(t); enqueue(store);
  const second = createRunRepository({ path }); t.after(() => second.close());
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
