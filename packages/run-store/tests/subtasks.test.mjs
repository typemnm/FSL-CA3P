import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { createRunRepository } from '../index.mjs';

const sourceFindingDigest = 'a'.repeat(64);

function setup(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'ca3p-subtasks-test-'));
  const path = join(directory, 'runs.sqlite');
  const handles = [];
  const open = () => { const store = createRunRepository({ path, ...options }); handles.push(store); return store; };
  const store = open();
  t.after(() => { for (const handle of handles.reverse()) handle.close(); rmSync(directory, { recursive: true, force: true }); });
  const id = 'run-parent';
  store.createRun({ id, mode: 'local-lab-general', modelId: 'deepseek-flash',
    manifest: { runId: id }, state: { id, status: 'queued', events: [] } });
  return { store, open, path, lease: store.claimNext('worker-a') };
}

function task(id = 'task-a', sourceFindingId = 'finding:h-a', input = { objective: 'recheck' }) {
  return { id, sourceFindingId, sourceFindingDigest, kind: 'finding-followup',
    agentId: 'agent-a', input };
}

test('subtask assignment is durable and idempotent for one finding snapshot', t => {
  const { store, open, lease, path } = setup(t);
  const first = store.createSubtask(lease, task());
  assert.equal(first.parentRunId, lease.runId);
  assert.equal(first.status, 'queued');
  assert.deepEqual(store.createSubtask(lease, task()), first);
  const second = open();
  assert.deepEqual(second.listSubtasks(lease.runId), [first]);
  assert.throws(() => second.createSubtask(lease, task('task-b')), { code: 'SUBTASK_CONFLICT' });
  assert.throws(() => second.createSubtask(lease, task('task-a', 'finding:h-b')), { code: 'SUBTASK_CONFLICT' });
  assert.throws(() => second.createSubtask(lease, task('task-c', 'finding:h-c', { huge: 'x'.repeat(256 * 1024) })),
    { code: 'INVALID_SUBTASK' });
  const started = second.startSubtask(lease, first.id);
  assert.equal(started.status, 'running');
  assert.deepEqual(store.startSubtask(lease, first.id), started);
  assert.throws(() => store.finish(lease, 'completed'), { code: 'SUBTASKS_ACTIVE' });
  const finished = store.finishSubtask(lease, first.id, { status: 'completed', result: {
    status: 'inconclusive', cookie: 'private', detail: 'stored',
  } });
  assert.equal(finished.result.cookie, '[REDACTED]');
  assert.deepEqual(second.getSubtask(lease.runId, first.id), finished);
  assert.deepEqual(second.finishSubtask(lease, first.id, { status: 'completed', result: {
    status: 'inconclusive', cookie: 'private', detail: 'stored',
  } }), finished);
  assert.throws(() => store.finishSubtask(lease, first.id, { status: 'failed', errorCode: 'TASK_FAILED' }),
    { code: 'SUBTASK_ALREADY_FINISHED' });
  store.finish(lease, 'completed');
  const sqlite = new DatabaseSync(path, { readOnly: true });
  try { assert.equal(sqlite.prepare('PRAGMA user_version').get().user_version, 1); }
  finally { sqlite.close(); }
});

test('parent cancellation fences new work and a late successful result', t => {
  const { store, lease } = setup(t);
  store.createSubtask(lease, task());
  store.createSubtask(lease, task('task-b', 'finding:h-b'));
  store.startSubtask(lease, 'task-a');
  const stale = { id: lease.runId, status: 'running', events: [],
    multiAgent: { status: 'running', tasks: [{ id: 'task-a', status: 'running' },
      { id: 'task-b', status: 'queued' }] } };
  store.saveState(lease, stale);
  store.requestCancel(lease.runId);
  assert.equal(store.getSubtask(lease.runId, 'task-b').status, 'cancelled');
  assert.equal(store.getRun(lease.runId).multiAgent.tasks[1].status, 'cancelled');
  store.saveState(lease, stale);
  assert.equal(store.getRun(lease.runId).multiAgent.tasks[1].status, 'cancelled',
    'late runtime snapshots cannot restore a cancelled task in the parent state');
  assert.equal(store.getRun(lease.runId).status, 'stopping');
  assert.throws(() => store.createSubtask(lease, task('task-c', 'finding:h-c')), { code: 'RUN_CANCELLED' });
  assert.throws(() => store.finishSubtask(lease, 'task-a', { status: 'completed', result: {} }),
    { code: 'RUN_CANCELLED' });
  assert.equal(store.finishSubtask(lease, 'task-a', { status: 'cancelled' }).status, 'cancelled');
  store.finish(lease, 'cancelled');
  assert.deepEqual(store.listSubtasks(lease.runId).map(item => item.status), ['cancelled', 'cancelled']);
  assert.equal(store.getRun(lease.runId).multiAgent.status, 'cancelled');
  assert.deepEqual(store.getRun(lease.runId).multiAgent.tasks.map(item => item.status), ['cancelled', 'cancelled']);
});

test('lease expiry interrupts unfinished subtasks and blocks stale results', t => {
  let time = 100;
  const { store, lease } = setup(t, { clock: () => time });
  store.createSubtask(lease, task());
  store.startSubtask(lease, 'task-a');
  store.saveState(lease, { id: lease.runId, status: 'running', events: [],
    multiAgent: { status: 'running', tasks: [{ id: 'task-a', status: 'running' }] } });
  time = 15100;
  assert.deepEqual(store.recoverExpired(), [lease.runId]);
  assert.equal(store.getSubtask(lease.runId, 'task-a').status, 'interrupted');
  assert.equal(store.getRun(lease.runId).multiAgent.status, 'interrupted');
  assert.equal(store.getRun(lease.runId).multiAgent.tasks[0].status, 'interrupted');
  assert.throws(() => store.finishSubtask(lease, 'task-a', { status: 'completed', result: {} }),
    { code: 'LEASE_LOST' });
});

test('worker exit interrupts unfinished subtasks and prevents another worker from replaying them', t => {
  const { store, open, lease } = setup(t);
  store.createSubtask(lease, task());
  store.startSubtask(lease, 'task-a');
  assert.deepEqual(open().interruptOwner(lease.owner), [lease.runId]);
  assert.equal(store.getSubtask(lease.runId, 'task-a').status, 'interrupted');
  assert.equal(store.claimNext('worker-b'), null);
  assert.throws(() => store.finishSubtask(lease, 'task-a', { status: 'failed' }), { code: 'LEASE_LOST' });
});

test('history clear deletes subtasks before their parent run', t => {
  const { store, lease } = setup(t);
  store.createSubtask(lease, task());
  store.finish(lease, 'failed');
  assert.equal(store.getSubtask(lease.runId, 'task-a').status, 'interrupted');
  store.beginExperimentReset('reset-a');
  const result = store.completeRunHistoryClear('reset-a');
  assert.equal(result.deleted.run_subtasks, 1);
  assert.deepEqual(store.listSubtasks(lease.runId), []);
});
