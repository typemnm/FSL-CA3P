import test from 'node:test';
import assert from 'node:assert/strict';
import { createIdorRuntime } from '../idor-runtime.mjs';

const evidence = [
  { check: 'firstOwner', recordId: 1, status: 200, ownerId: 4 },
  { check: 'secondOwner', recordId: 3, status: 200, ownerId: 5 },
  { check: 'crossOwner', recordId: 3, status: 200, ownerId: 5 },
  { check: 'studentRole', recordId: 3, status: 403, ownerId: null },
];
function waitForTerminal(runtime) {
  if (['completed', 'failed', 'stopped'].includes(runtime.getState().run.status)) return Promise.resolve(runtime.getState().run);
  return new Promise(resolve => {
    const detach = runtime.subscribe(({ run }) => {
      if (['completed', 'failed', 'stopped'].includes(run.status)) { detach(); resolve(run); }
    });
  });
}

test('registered university runs publish only bounded evidence and preserve non-confirmed outcomes', async t => {
  for (const [fixtureId, siteKey, origin] of [
    ['vul-web2-daehan', 'daehan', 'http://127.0.0.1:4101'],
    ['vul-web2-wonchang', 'wonchang', 'http://127.0.0.1:4102'],
  ]) {
    for (const status of ['confirmed', 'not_confirmed', 'inconclusive']) {
      let requested;
      const runtime = createIdorRuntime({ fixtureId, runIdFactory: () => 'test-idor', probe: async options => {
        requested = options;
        for (const item of evidence) options.onObservation({ ...item, password: 'PRIVATE PASSWORD', body: 'PRIVATE BODY' });
        return { finding: { status, password: 'PRIVATE PASSWORD' }, evidence: evidence.map(item => ({ ...item, body: 'PRIVATE BODY' })),
          cookie: 'PRIVATE COOKIE' };
      } });
      t.after(() => runtime.close());
      const started = runtime.startLab();
      assert.equal(started.run.status, 'preparing');
      assert.equal(started.run.targetContacted, false);
      const run = await waitForTerminal(runtime);
      assert.equal(requested.siteKey, siteKey); assert.equal(requested.origin, origin);
      assert.equal(requested.runId, run.id);
      assert.equal(run.mode, 'local-lab-rule'); assert.equal(run.testProfile, 'known_record_idor_read');
      assert.equal(run.status, 'completed'); assert.equal(run.targetContacted, true);
      assert.equal(run.report.finding.status, status); assert.equal(run.report.runId, run.id);
      assert.equal(run.report.fixtureId, fixtureId); assert.equal(run.report.target.origin, origin);
      assert.equal(run.reviewItems[0].vulnerabilityConfirmed, status === 'confirmed');
      assert.equal(run.events.length, 6); assert.equal(run.step, 6); assert.equal(run.totalSteps, 6);
      assert.equal(run.snapshots.attack.stage, 'idor.studentRole');
      for (const event of run.events) {
        for (const field of ['id', 'time', 'title', 'detail', 'correlationId']) assert.equal(typeof event[field], 'string');
        assert.ok(Number.isInteger(event.iteration)); assert.equal(event.latency, null);
        assert.equal(typeof event.request, 'object'); assert.equal(typeof event.response, 'object');
      }
      assert.doesNotMatch(JSON.stringify(run), /PRIVATE|password|cookie/);
    }
  }
});

test('an approved private target is frozen for the run and unsupported origins are rejected', async t => {
  let requested;
  const origin = 'http://192.168.0.84:4101';
  const runtime = createIdorRuntime({ fixtureId: 'vul-web2-daehan', targetOrigin: origin, probe: async options => {
    requested = options;
    for (const item of evidence) options.onObservation(item);
    return { finding: { status: 'confirmed' }, evidence };
  } });
  t.after(() => runtime.close());
  assert.throws(() => runtime.startLab({ target: 'http://192.168.0.85:4101' }), { status: 400 });
  runtime.startLab();
  const run = await waitForTerminal(runtime);
  assert.equal(requested.origin, origin); assert.equal(run.target, origin);
  assert.ok(run.events.filter(item => item.module === 'attack').every(item => item.request.url.startsWith(`${origin}/`)));
  for (const targetOrigin of ['http://example.com:4101', 'http://8.8.8.8:4101', 'http://127.0.0.1:4101/admin']) {
    assert.throws(() => createIdorRuntime({ fixtureId: 'vul-web2-daehan', targetOrigin }));
  }
  assert.throws(() => createIdorRuntime({ fixtureId: 'external-site' }));
});

test('execution failures have actionable safe messages; incomplete results cannot complete a run', async t => {
  for (const probe of [async () => { throw new Error('PRIVATE PASSWORD and PRIVATE BODY'); },
    async () => ({ finding: { status: 'confirmed' }, evidence: [] })]) {
    const runtime = createIdorRuntime({ fixtureId: 'vul-web2-daehan', probe });
    t.after(() => runtime.close()); runtime.startLab();
    const run = await waitForTerminal(runtime);
    assert.equal(run.status, 'failed'); assert.equal(run.targetContacted, false);
    assert.match(run.error, /vul-web2.*http:\/\/127\.0\.0\.1:4101/);
    assert.doesNotMatch(JSON.stringify(run), /PRIVATE/);
    assert.equal(run.report, undefined);
  }
});

test('stop aborts the in-flight probe and close waits for it without issuing later observations', async () => {
  let entered;
  const started = new Promise(resolve => { entered = resolve; });
  let aborted = false;
  const runtime = createIdorRuntime({ fixtureId: 'vul-web2-wonchang', runIdFactory: () => 'cancel-idor',
    probe: ({ signal, onObservation }) => new Promise((resolve, reject) => {
      signal.addEventListener('abort', () => {
        aborted = true;
        onObservation(evidence[0]);
        reject(new Error('PRIVATE CANCEL ERROR'));
      }, { once: true });
      entered();
    }) });
  runtime.startLab(); await started;
  assert.throws(() => runtime.startLab(), { status: 409 });
  assert.throws(() => runtime.stop('wrong-run'), { status: 404 });
  runtime.stop('cancel-idor');
  await runtime.close();
  const run = runtime.getState().run;
  assert.equal(aborted, true); assert.equal(run.status, 'stopped');
  assert.equal(run.targetContacted, false); assert.equal(run.events.length, 2);
  assert.doesNotMatch(JSON.stringify(run), /PRIVATE/);
  assert.throws(() => runtime.startLab(), { status: 503 });
});

test('a reachable site with a failed login is distinguished from an unreachable target', async t => {
  const runtime = createIdorRuntime({ fixtureId: 'vul-web2-daehan', probe: async ({ onContact }) => {
    onContact(); throw new Error('PRIVATE LOGIN BODY');
  } });
  t.after(() => runtime.close()); runtime.startLab();
  const run = await waitForTerminal(runtime);
  assert.equal(run.status, 'failed');
  assert.equal(run.targetContacted, true);
  assert.equal(run.events.length, 2);
  assert.doesNotMatch(JSON.stringify(run), /PRIVATE/);
});

test('stopping before startup does not contact the probe', async () => {
  let calls = 0;
  const runtime = createIdorRuntime({ fixtureId: 'vul-web2-daehan', probe: async () => { calls += 1; } });
  const state = runtime.startLab(); runtime.stop(state.run.id); await runtime.close();
  assert.equal(calls, 0); assert.equal(runtime.getState().run.status, 'stopped');
});
