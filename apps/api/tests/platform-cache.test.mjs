import test from 'node:test';
import assert from 'node:assert/strict';
import { createPlatformProvider } from '../platform.mjs';

test('platform snapshot is computed once for concurrent callers and refreshed in the background after the TTL', async () => {
  let clock = 0; let computed = 0; let release; let deploymentReads = 0;
  const compute = () => { computed += 1; const version = computed;
    return new Promise(resolve => { release = () => resolve({ source: { commitSha: `sha-${version}` }, modules: [] }); }); };
  const provider = createPlatformProvider({ ttlMs: 1000, compute, now: () => clock,
    deployment: async () => ({ enabled: true, read: ++deploymentReads }) });
  const tick = () => new Promise(resolve => setImmediate(resolve));
  const first = [provider(), provider(), provider()];
  await tick(); release();
  const values = await Promise.all(first);
  assert.equal(computed, 1);
  assert.deepEqual(values.map(value => value.source.commitSha), ['sha-1', 'sha-1', 'sha-1']);
  assert.equal(values[2].deployment.read, 3, 'deployment status is read on every call');

  clock = 500;
  assert.equal((await provider()).source.commitSha, 'sha-1');
  assert.equal(computed, 1, 'a fresh snapshot is served from the cache');

  clock = 1500;
  const stale = await provider();
  assert.equal(stale.source.commitSha, 'sha-1', 'an expired snapshot is returned at once');
  assert.equal(computed, 2, 'while one background refresh starts');
  await provider();
  assert.equal(computed, 2, 'and is not started twice');
  await tick(); release(); await tick();
  assert.equal((await provider()).source.commitSha, 'sha-2');

  stale.source.commitSha = 'mutated';
  assert.equal((await provider()).source.commitSha, 'sha-2', 'callers get a copy of the cached value');
});

test('a failed first computation is reported and retried; a failed refresh keeps the last snapshot', async () => {
  let clock = 0; let fail = true; let computed = 0;
  const provider = createPlatformProvider({ ttlMs: 10, now: () => clock, deployment: async () => ({ enabled: false }),
    compute: async () => { computed += 1; if (fail) throw new Error('git unavailable'); return { source: { commitSha: `sha-${computed}` }, modules: [] }; } });
  await assert.rejects(provider(), /git unavailable/u);
  fail = false;
  assert.equal((await provider()).source.commitSha, 'sha-2');
  fail = true; clock = 100;
  assert.equal((await provider()).source.commitSha, 'sha-2');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal((await provider()).source.commitSha, 'sha-2');
});
