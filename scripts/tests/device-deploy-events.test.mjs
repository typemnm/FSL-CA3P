import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { appendDeploymentEvent, sanitizeDeploymentEvents } from '../device-deploy-events.mjs';
import { atomicJson, deploymentTransaction } from '../device-deploy.mjs';

const currentSha = 'a'.repeat(40); const nextSha = 'b'.repeat(40);
function writer(initial = {}) {
  let serial = 0; let state = initial;
  return { get state() { return state; }, update(status, extra = {}) {
    const next = { ...state, status, phase: null, reasonCode: null, ...extra,
      updatedAt: new Date(Date.UTC(2026, 9, 26, 12, 0, serial)).toISOString() };
    next.events = appendDeploymentEvent(state, next, { idFactory: () => `00000000-0000-4000-8000-${String(++serial).padStart(12, '0')}` });
    state = next; return state;
  } };
}

test('a release timeline survives atomic status writes without exposing private diagnostic fields', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-deploy-events-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const journal = writer();
  journal.update('checking', { targetSha: nextSha, deployedSha: currentSha, phase: 'ci-verification',
    message: 'private operator message', error: '/private/credentials', password: 'do-not-copy' });
  journal.update('preparing', { phase: 'dependencies', runId: '123' });
  journal.update('preparing', { phase: 'isolated-smoke' });
  journal.update('deploying', { phase: 'backup-and-migrate' });
  journal.update('deployed', { deployedSha: nextSha, previousSha: currentSha });
  const path = join(directory, 'status.json'); await atomicJson(path, journal.state);
  const stored = JSON.parse(await readFile(path, 'utf8'));
  const events = sanitizeDeploymentEvents(stored.events);
  assert.deepEqual(events.map(event => [event.status, event.phase]), [
    ['checking', 'ci-verification'], ['preparing', 'dependencies'], ['preparing', 'isolated-smoke'],
    ['deploying', 'backup-and-migrate'], ['deployed', null],
  ]);
  assert.equal(events.at(-1).reasonCode, 'deployment-complete');
  assert.equal(events.at(-1).targetSha, nextSha); assert.equal(events.at(-1).runId, '123');
  assert.doesNotMatch(JSON.stringify(events), /private|password|do-not-copy|message|error/);
  assert.deepEqual(sanitizeDeploymentEvents(events), events);
});

test('recurring same-HEAD checks do not emit checking or up-to-date notification spam', () => {
  const journal = writer();
  journal.update('checking', { targetSha: currentSha, deployedSha: currentSha });
  journal.update('up-to-date');
  const initial = structuredClone(journal.state.events);
  for (let count = 0; count < 5; count += 1) { journal.update('checking'); journal.update('up-to-date'); }
  assert.deepEqual(journal.state.events, initial);
  journal.update('checking', { targetSha: nextSha });
  journal.update('waiting-ci', { reasonCode: 'ci-summary-pending' });
  assert.equal(journal.state.events.length, initial.length + 2);
  const waiting = structuredClone(journal.state.events);
  for (let count = 0; count < 5; count += 1) { journal.update('checking'); journal.update('waiting-ci'); }
  assert.deepEqual(journal.state.events, waiting);
});

test('same status keeps real phase, reason and retry deadline changes', () => {
  const journal = writer({ targetSha: nextSha, deployedSha: currentSha });
  journal.update('waiting-ci', { reasonCode: 'ci-running', runId: '123' });
  journal.update('waiting-ci', { reasonCode: 'github-rate-limit', retryAt: '2026-10-26T13:00:00Z' });
  journal.update('waiting-ci', { reasonCode: 'github-rate-limit', retryAt: '2026-10-26T13:00:00Z' });
  journal.update('waiting-ci', { reasonCode: 'github-rate-limit', retryAt: '2026-10-26T14:00:00Z' });
  assert.deepEqual(journal.state.events.map(event => event.reasonCode), ['ci-running', 'github-rate-limit', 'github-rate-limit']);
  journal.update('preparing', { phase: 'dependencies', retryAt: null });
  journal.update('preparing', { phase: 'dependencies' });
  journal.update('preparing', { phase: 'fixtures' });
  assert.equal(journal.state.events.length, 5);
});

test('history is bounded and malformed imported events cannot become public data', () => {
  const journal = writer();
  for (let value = 0; value < 140; value += 1) journal.update(value % 2 ? 'deployed' : 'deploying');
  assert.equal(journal.state.events.length, 100);
  assert.equal(journal.state.events.at(-1).id.endsWith('000000000140'), true);
  const valid = journal.state.events[0];
  const rows = sanitizeDeploymentEvents([null, {}, { ...valid, status: 'untrusted' }, { ...valid, id: '../../file' },
    { ...valid, at: 'yesterday' }, { ...valid, message: 'private', targetSha: '/private/source', runId: '123/token',
      retryAt: '/private/time', phase: 'private', reasonCode: 'private' }, valid]);
  assert.equal(rows.length, 1); assert.equal(rows[0].targetSha, null); assert.equal(rows[0].runId, null);
  assert.equal(rows[0].retryAt, null); assert.equal(rows[0].phase, null);
  assert.doesNotMatch(JSON.stringify(rows), /private|message/);
  assert.equal(sanitizeDeploymentEvents(undefined).length, 0, 'old controllers without events remain compatible');
});

test('successful rollback is identified while retaining the original deployment error', async () => {
  const failure = new Error('private deployment problem');
  const noop = async () => {};
  await assert.rejects(deploymentTransaction({ stop: noop, backup: async () => 'snapshot', migrate: noop,
    activate: async () => { throw failure; }, start: noop, verify: noop, restore: noop, rollback: noop, verifyRollback: noop }), error => {
    assert.equal(error, failure); assert.equal(error.rollbackComplete, true); return true;
  });
  const journal = writer({ targetSha: nextSha, deployedSha: currentSha });
  journal.update('failed', { reasonCode: 'rollback-complete', error: failure.message });
  assert.equal(journal.state.events[0].reasonCode, 'rollback-complete');
  assert.doesNotMatch(JSON.stringify(journal.state.events), /private deployment/);
});

test('notification metadata cannot turn a successful rollback of a frozen error into recovery failure', async () => {
  const failure = Object.freeze(new Error('original frozen failure')); const noop = async () => {};
  await assert.rejects(deploymentTransaction({ stop: noop, backup: async () => 'snapshot', migrate: noop,
    activate: async () => { throw failure; }, start: noop, verify: noop, restore: noop, rollback: noop, verifyRollback: noop }),
  error => error === failure && error.recoveryFailed !== true);
});
