import test from 'node:test';
import assert from 'node:assert/strict';
import { buildOperationsSnapshot } from '../operations.mjs';

const before = 'a'.repeat(40), target = 'b'.repeat(40);
const now = '2026-10-26T12:00:00Z';
const run = (overrides = {}) => ({ runId: 100, runAttempt: 1, commitSha: target, branch: 'develop', eventName: 'push',
  status: 'passed', createdAt: '2026-10-26T11:55:00Z', startedAt: '2026-10-26T11:55:00Z', completedAt: '2026-10-26T11:59:00Z', ...overrides });
const deployment = (overrides = {}) => ({ enabled: true, status: 'waiting-ci', targetSha: target, deployedSha: before,
  checkedAt: '2026-10-26T11:58:00Z', updatedAt: '2026-10-26T11:58:00Z', events: [], ...overrides });
const ci = (runs = [run()], overrides = {}) => ({ status: 'fresh', updatedAt: '2026-10-26T11:59:00Z',
  live: { status: 'fresh', checkedAt: '2026-10-26T11:59:00Z' }, runs, ...overrides });

test('CI success and device application remain distinct and match the same target SHA', () => {
  const snapshot = buildOperationsSnapshot({ deployment: deployment(), ci: ci(), runningSha: before, now });
  assert.equal(snapshot.source.applied, false); assert.equal(snapshot.ci.matched.commitSha, target);
  assert.equal(snapshot.deployment.status, 'waiting-ci');
  assert.equal(snapshot.events.find(event => event.kind === 'ci').severity, 'success');
  assert.match(snapshot.events.find(event => event.kind === 'ci').message, /별도로/);
  const applied = buildOperationsSnapshot({ deployment: deployment({ status: 'deployed', deployedSha: target }), ci: ci(), runningSha: target, now });
  assert.equal(applied.source.applied, true);
});

test('a newer merged develop CI appears even before the device observes the new SHA', () => {
  const snapshot = buildOperationsSnapshot({ deployment: deployment({ targetSha: before }),
    ci: ci([run({ createdAt: '2026-10-26T11:59:00Z', startedAt: '2026-10-26T11:59:00Z', completedAt: null, status: 'running', workflowStatus: 'in_progress' })]), runningSha: before, now });
  assert.equal(snapshot.source.targetSource, 'ci'); assert.equal(snapshot.source.targetSha, target);
  assert.equal(snapshot.source.applied, false); assert.equal(snapshot.ci.latest.status, 'running');
});

test('an older push starting late cannot revert the newer develop target to the running revision', () => {
  for (const createdAt of ['2026-10-26T11:57:00Z', null]) {
    const state = buildOperationsSnapshot({ deployment: deployment(), runningSha: before, now,
      ci: ci([run({ commitSha: before, createdAt, startedAt: '2026-10-26T11:59:00Z', status: 'running' })]) });
    assert.equal(state.source.targetSha, target);
    assert.equal(state.source.targetSource, 'device');
    assert.equal(state.source.applied, false);
    assert.equal(state.ci.matched, null);
  }
});

test('stale offline cached success is not a fresh confirmation of the device or CI', () => {
  const result = buildOperationsSnapshot({ deployment: deployment({ updatedAt: '2026-10-26T10:00:00Z', checkedAt: '2026-10-26T10:00:00Z' }),
    ci: ci([run()], { status: 'stale', live: { status: 'unavailable', checkedAt: '2026-10-26T10:00:00Z' } }), runningSha: target, now });
  assert.equal(result.freshness.device, 'stale'); assert.equal(result.freshness.ci, 'stale');
  assert.equal(result.ci.latest.status, 'passed', 'historical result stays readable');
});

test('stable event ids avoid poll duplicates and rollback events expose only safe fixed text', () => {
  const value = { id: 'rollback-a', at: '2026-10-26T11:59:00Z', status: 'failed', reasonCode: 'rollback-complete',
    targetSha: target, deployedSha: before, message: 'private-file-secret', error: 'secret', runUrl: 'https://evil.test/secret' };
  const input = { deployment: deployment({ events: [value, value] }), ci: ci(), runningSha: before, now };
  const a = buildOperationsSnapshot(input), b = buildOperationsSnapshot(input);
  assert.deepEqual(a.events.map(event => event.id), b.events.map(event => event.id));
  assert.equal(a.events.filter(event => event.id === 'rollback-a').length, 1);
  assert.match(a.events.find(event => event.id === 'rollback-a').title, /복원 완료/);
  assert.doesNotMatch(JSON.stringify(a.events), /secret|evil|private/);
});

test('unconfigured device and unavailable CI are explicit and do not invent an applied revision', () => {
  const value = buildOperationsSnapshot({ now });
  assert.equal(value.freshness.device, 'disabled'); assert.equal(value.freshness.ci, 'unknown');
  assert.equal(value.source.applied, null); assert.equal(value.source.runningSha, null);
  assert.deepEqual(value.events, []);
});

test('workflow metadata enrichment does not announce the same CI result twice', () => {
  const a = buildOperationsSnapshot({ ci: ci(), now });
  const b = buildOperationsSnapshot({ ci: ci([run({ workflowStatus: 'completed', workflowConclusion: 'success' })]), now });
  assert.equal(a.events.find(event => event.kind === 'ci').id, b.events.find(event => event.kind === 'ci').id);
});
