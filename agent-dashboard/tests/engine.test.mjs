import test from 'node:test';
import assert from 'node:assert/strict';
import { MODULES, createRun, tickRun, validateTarget, formatElapsed } from '../dist/engine.js';

test('URL validation accepts HTTP(S) and rejects malformed or credential-bearing input', () => {
  for (const input of ['', 'example.com', 'javascript:alert(1)', 'file:///etc/passwd', 'https://user:secret@example.com', 'https://']) {
    assert.equal(validateTarget(input).ok, false, input);
  }
  assert.equal(validateTarget(' https://example.com/path?q=1 ').url, 'https://example.com/path?q=1');
  assert.equal(validateTarget('http://localhost:8080').ok, true);
  assert.throws(() => createRun('invalid'), TypeError);
});

test('simulation completes within the step budget and preserves paired trace IDs', () => {
  const run = createRun('https://example.com', { id: 'test-budget' });
  for (let i = 0; i < 30; i++) tickRun(run, 1000);
  assert.equal(run.step, 18);
  assert.equal(run.events.length, 18);
  assert.equal(run.status, 'completed');
  assert.equal(run.elapsedMs, 18000);
  assert.equal(run.reviewItems.length, 3);
  for (const module of MODULES) assert.equal(run.events.filter((event) => event.module === module.id).length, 3);
  for (const event of run.events) {
    assert.equal(event.correlationId, event.request.traceId);
    assert.equal(event.correlationId, event.response.traceId);
    assert.equal(event.request.simulated, true);
    assert.equal(event.response.simulated, true);
  }
  assert.equal(run.snapshots.reasoning.agentOutput.proposedNetworkActions, 0);
  assert.equal(run.snapshots.browser.response.targetContacted, false);
  assert.ok(run.reviewItems.every((item) => item.simulated && !item.vulnerabilityConfirmed));
  assert.deepEqual(JSON.parse(JSON.stringify(run)), run);
});

test('pause, stop and completion freeze events and elapsed time', () => {
  for (const status of ['paused','stopped','completed']) {
    const run = createRun('https://example.com', { initialSteps: 3 });
    run.status = status;
    const before = JSON.stringify(run);
    tickRun(run, 3000);
    assert.equal(JSON.stringify(run), before, status);
  }
  const run = createRun('https://example.com');
  run.status = 'paused'; tickRun(run,1000);
  run.status = 'running'; tickRun(run,1000);
  assert.equal(run.step, 1);
  assert.equal(run.elapsedMs, 1000);
});

test('initial demo events stay in the past and elapsed time formats consistently', () => {
  const run = createRun('https://demo.ca3p.local', { initialSteps: 8 });
  assert.equal(run.step, 8);
  assert.ok(Date.parse(run.events.at(-1).time) <= Date.now());
  assert.equal(formatElapsed(run.elapsedMs), '00:13');
  assert.equal(formatElapsed(125000), '02:05');
  assert.equal(formatElapsed(-1), '00:00');
});
