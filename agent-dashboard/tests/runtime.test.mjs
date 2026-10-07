import test from 'node:test';
import assert from 'node:assert/strict';
import { Socket } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { createLocalRuntime } from '../local-runtime.mjs';

function waitForState(runtime, predicate, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let unsubscribe = () => {};
    let settled = false;
    const timer = setTimeout(() => {
      settled = true;
      unsubscribe();
      reject(new Error(`Runtime did not reach the expected state: ${JSON.stringify(runtime.getState())}`));
    }, timeoutMs);
    const check = state => {
      if (settled || !predicate(state)) return;
      settled = true;
      clearTimeout(timer);
      unsubscribe();
      resolve(state);
    };
    unsubscribe = runtime.subscribe(check);
    if (settled) unsubscribe();
    else check(runtime.getState());
  });
}

function assertHttpError(operation, status) {
  assert.throws(operation, error => {
    assert.equal(error.status, status);
    return true;
  });
}

test('the real core completes through fixture I/O without any network or provider connection', async t => {
  const runtime = createLocalRuntime({ defaultDelayMs: 0 });
  const originalFetch = globalThis.fetch;
  const originalConnect = Socket.prototype.connect;
  let connectionAttempts = 0;
  globalThis.fetch = () => {
    connectionAttempts += 1;
    throw new Error('Runtime must not call fetch');
  };
  Socket.prototype.connect = function () {
    connectionAttempts += 1;
    throw new Error('Runtime must not open sockets');
  };
  t.after(async () => {
    try { await runtime.close(); }
    finally {
      globalThis.fetch = originalFetch;
      Socket.prototype.connect = originalConnect;
    }
  });

  const states = [];
  const unsubscribe = runtime.subscribe(state => states.push(state));
  t.after(unsubscribe);
  const started = runtime.start({ target: ' https://metadata-only.invalid/path?note=dashboard#section ', delayMs: 0 });
  assert.equal(started.mode, 'core-fixture');
  assert.equal(started.run.status, 'running');
  assert.equal(started.run.target, 'https://metadata-only.invalid/path?note=dashboard#section');
  const completed = await waitForState(runtime, state => ['completed', 'failed'].includes(state.run?.status));
  const run = completed.run;

  assert.equal(connectionAttempts, 0);
  assert.equal(run.status, 'completed');
  assert.equal(run.simulated, true);
  assert.equal(run.targetContacted, false);
  assert.equal(run.totalSteps, 25);
  assert.equal(run.step, 25);
  assert.equal(run.events.length, 25);
  assert.equal(new Set(run.events.map(event => event.id)).size, 25);
  assert.equal(run.report.iterations, 1);
  assert.equal(run.report.target.origin, 'http://127.0.0.1:3000');
  assert.equal(run.report.simulated, true);
  assert.equal(run.report.targetContacted, false);
  assert.equal(run.reviewItems.every(item => item.simulated && !item.vulnerabilityConfirmed), true);

  const counts = {};
  for (const event of run.events) {
    counts[event.module] = (counts[event.module] ?? 0) + 1;
    assert.ok(event.correlationId);
    assert.ok(event.request && typeof event.request === 'object');
    assert.ok(event.response && typeof event.response === 'object');
    assert.equal(run.snapshots[event.module].module, event.module);
  }
  assert.deepEqual(counts, { attack: 4, guardrail: 4, pentest: 12, parser: 2, casper: 1, agent: 2 });
  assert.equal(run.events.some(event => event.module === 'policy'), false);
  assert.equal(run.events.some(event => event.module === 'browser'), false);
  const internal = run.events.filter(event => event.source === 'core-internal-event');
  assert.equal(internal.length, 2);
  assert.ok(internal.every(event => event.agentInput && event.agentOutput));
  assert.deepEqual(internal.map(event => event.stage), ['loop.think', 'loop.reflect']);
  assert.equal(internal[0].agentInput.operation, 'plan');
  assert.equal(internal[1].agentInput.operation, 'reflect');

  const gatewayEvents = run.events.filter(event => event.source === 'scripted-gateway');
  assert.equal(gatewayEvents.length, 23);
  for (const event of gatewayEvents) {
    if (event.module === 'guardrail') {
      assert.equal(event.response.payload.decision, 'ALLOW');
      assert.equal(event.request.receiver, 'guardrail');
      continue;
    }
    assert.equal(event.request.schemaVersion, '1.0');
    assert.equal(event.response.schemaVersion, '1.0');
    assert.equal(event.request.policyContext.targetOrigin, 'http://127.0.0.1:3000');
    assert.equal(event.response.correlationId, event.request.messageId);
    assert.equal(event.correlationId, event.request.messageId);
  }
  assert.equal(run.report.source, 'scripted-contract-fixture');
  assert.equal(run.coreTargetOrigin, 'http://127.0.0.1:3000');
  assert.equal(run.report.runId, run.coreRunId);
  assert.ok(states.some(state => state.run?.events.length > 0 && state.run.status === 'running'));
  assert.equal(states.at(-1).run.status, 'completed');
  assert.deepEqual(JSON.parse(JSON.stringify(completed)), completed);
});

test('an active run rejects replacement and reset, then stopping freezes its partial trace', async t => {
  const runtime = createLocalRuntime({ defaultDelayMs: 40 });
  t.after(() => runtime.close());
  const started = runtime.start({ target: 'https://metadata-only.invalid' });
  assertHttpError(() => runtime.start({ target: 'https://second.invalid' }), 409);
  assertHttpError(() => runtime.reset(), 409);
  await waitForState(runtime, state => state.run?.events.length >= 2);
  const stopping = runtime.stop(started.run.id);
  assert.ok(['stopping', 'stopped'].includes(stopping.run.status));
  const stopped = await waitForState(runtime, state => state.run?.status === 'stopped');
  assert.ok(stopped.run.events.length >= 2);
  assert.ok(stopped.run.events.length < stopped.run.totalSteps);
  assert.equal(stopped.run.targetContacted, false);
  await runtime.close();
  const frozen = runtime.getState();
  await delay(60);
  assert.deepEqual(runtime.getState(), frozen);
});

test('completion is stable, subscriptions can detach, and reset allows a fresh run', async t => {
  const runtime = createLocalRuntime({ defaultDelayMs: 0 });
  t.after(() => runtime.close());
  let notifications = 0;
  const unsubscribe = runtime.subscribe(() => { notifications += 1; });
  const first = runtime.start({ target: 'http://localhost:1234', delayMs: 0 });
  await waitForState(runtime, state => state.run?.status === 'completed');
  unsubscribe();
  const count = notifications;
  const completed = runtime.getState();
  await delay(20);
  assert.deepEqual(runtime.getState(), completed);
  const reset = runtime.reset();
  assert.equal(reset.mode, 'core-fixture');
  assert.equal(reset.instanceId, first.instanceId);
  assert.ok(!reset.run || reset.run.status === 'idle');
  const second = runtime.start({ target: 'https://another-metadata.invalid', delayMs: 0 });
  assert.notEqual(second.run.id, first.run.id);
  await waitForState(runtime, state => state.run?.status === 'completed');
  assert.equal(notifications, count);
});

test('malformed URLs and unsupported pacing are rejected before a run is created', async t => {
  const runtime = createLocalRuntime({ defaultDelayMs: 0 });
  t.after(() => runtime.close());
  const idle = runtime.getState();
  for (const target of ['', 'example.com', 'file:///tmp/example', 'javascript:alert(1)', 'https://user:secret@example.com', 'https://']) {
    assertHttpError(() => runtime.start({ target }), 400);
    assert.deepEqual(runtime.getState(), idle);
  }
  for (const delayMs of [-1, 3001, 1.5, '100', null, NaN, Infinity]) {
    assertHttpError(() => runtime.start({ target: 'https://metadata-only.invalid', delayMs }), 400);
    assert.deepEqual(runtime.getState(), idle);
  }
  for (const options of [null, [], { target: 'https://metadata-only.invalid', gateway: {} }, { target: 'https://metadata-only.invalid', maxIterations: 2 }]) {
    assertHttpError(() => runtime.start(options), 400);
    assert.deepEqual(runtime.getState(), idle);
  }
});
