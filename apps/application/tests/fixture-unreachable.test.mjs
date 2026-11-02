import test from 'node:test';
import assert from 'node:assert/strict';
import { createGeneralRuntime } from '../general-runtime.mjs';

test('a stopped university lab site fails with FIXTURE_UNREACHABLE before any model call', async () => {
  let plannerCreated = false;
  const runtime = createGeneralRuntime({ fixtureId: 'vul-web2-daehan', targetOrigin: 'http://127.0.0.1:4101',
    modelId: 'deepseek-flash', runIdFactory: () => 'run-unreachable',
    fetchImpl: async () => { throw new TypeError('fetch failed'); },
    plannerFactory: async () => { plannerCreated = true; return { propose: async () => ({ done: true }) }; } });
  const finished = new Promise(resolve => {
    const off = runtime.subscribe(({ run }) => { if (['failed', 'completed', 'stopped'].includes(run.status)) { off(); resolve(run); } });
  });
  runtime.startLab();
  const run = await finished;
  assert.equal(run.status, 'failed');
  assert.equal(run.error, 'FIXTURE_UNREACHABLE');
  assert.equal(run.targetContacted, false);
  assert.equal(plannerCreated, false);
  await runtime.close();
});
