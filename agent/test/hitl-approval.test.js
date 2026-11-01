'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createApprovalController } = require('../src/hitl-approval');

const actionDigest = 'a'.repeat(64);
const request = { kind: 'general-probe', probeId: 'probe-1',
  summary: { tool: 'http_get', path: '/records/1' }, actionDigest };

test('approval controller publishes one request and resolves only its matching decision', async () => {
  const events = [];
  const controller = createApprovalController({ runId: 'run-1',
    onPending: pending => events.push(['pending', pending.id]),
    onResolved: outcome => events.push(['resolved', outcome.decision]) });
  const wait = controller.request(request);
  const pending = controller.current();
  assert.match(pending.id, /^[a-f0-9-]{36}$/u);
  assert.equal(pending.runId, 'run-1');
  assert.equal(pending.actionDigest, actionDigest);
  assert.deepEqual(pending.summary, request.summary);
  assert.ok(Date.parse(pending.expiresAt) - Date.parse(pending.requestedAt) === 1_800_000);
  assert.throws(() => controller.request(request), error => error.code === 'APPROVAL_ALREADY_PENDING' && error.status === 409);
  assert.throws(() => controller.decide({ id: 'different', decision: 'approve', actor: 'admin' }),
    error => error.code === 'APPROVAL_NOT_PENDING' && error.status === 409);
  const accepted = controller.decide({ id: pending.id, decision: 'approve', actor: 'admin' });
  assert.equal(accepted.decision, 'approved');
  assert.deepEqual(await wait, accepted);
  assert.deepEqual(events, [['pending', pending.id], ['resolved', 'approved']]);
  assert.equal(controller.current(), null);
  assert.throws(() => controller.decide({ id: pending.id, decision: 'reject', actor: 'admin' }),
    error => error.code === 'APPROVAL_NOT_PENDING' && error.status === 409);
});

test('approval controller times out and rejects late decisions', async () => {
  const outcomes = [];
  const controller = createApprovalController({ runId: 'run-1', timeoutMs: 20,
    onPending() {}, onResolved: outcome => outcomes.push(outcome) });
  const wait = controller.request(request);
  const id = controller.current().id;
  const outcome = await wait;
  assert.equal(outcome.decision, 'timed_out');
  assert.equal(outcomes.length, 1);
  assert.equal(controller.current(), null);
  assert.throws(() => controller.decide({ id, decision: 'approve', actor: 'admin' }),
    error => error.code === 'APPROVAL_NOT_PENDING');
});

test('an overdue approval cannot win before a delayed timer callback', async () => {
  const outcomes = [];
  const controller = createApprovalController({ runId: 'run-1', timeoutMs: 10,
    onPending() {}, onResolved: outcome => outcomes.push(outcome) });
  const wait = controller.request(request);
  const pending = controller.current();
  // Keep the event loop occupied so the scheduled timeout cannot run first.
  while (Date.now() <= Date.parse(pending.expiresAt)) { /* wait for the deadline */ }
  assert.throws(() => controller.decide({ id: pending.id, decision: 'approve', actor: 'admin' }),
    error => error.code === 'APPROVAL_EXPIRED' && error.status === 409);
  assert.equal((await wait).decision, 'timed_out');
  assert.equal(outcomes.length, 1);
  assert.equal(outcomes[0].decision, 'timed_out');
});

test('abort clears an approval without approving the action', async () => {
  const abort = new AbortController();
  const outcomes = [];
  const controller = createApprovalController({ runId: 'run-1',
    onPending() {}, onResolved: outcome => outcomes.push(outcome) });
  const wait = controller.request({ ...request, signal: abort.signal });
  abort.abort();
  await assert.rejects(wait, error => error.name === 'AbortError');
  assert.equal(outcomes[0].decision, 'cancelled');
  assert.equal(controller.current(), null);
});

test('failed decision publication cannot release an approved action', async () => {
  const controller = createApprovalController({ runId: 'run-1',
    onPending() {}, onResolved() { throw new Error('store unavailable'); } });
  const wait = controller.request(request);
  const id = controller.current().id;
  assert.throws(() => controller.decide({ id, decision: 'approve', actor: 'admin' }), /store unavailable/u);
  await assert.rejects(wait, /store unavailable/u);
  assert.equal(controller.current(), null);
});
