import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareTargetReset, targetResetObligationsForRuns } from '../experiment-targets.mjs';

const token = 'private-reset-token-'.repeat(3);
const fixtureId = 'vul-web2-daehan';
const run = { fixtureId, mode: 'local-lab-rule', targetContacted: true, target: 'http://192.168.0.8:4101' };
const scopes = ['database', 'sessions', 'process', 'files'];
const targetOrigin = run.target;
const env = { CA3P_EXPERIMENT_RESET_TARGETS: JSON.stringify({ [fixtureId]: { origin: 'http://127.0.0.1:4900', targetOrigin, token } }) };
const json = data => new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
const readOnlyExternal = {
  mode: 'external-general', testProfile: 'external-read-only', fixtureId: null,
  targetKind: 'external', modelId: 'rule-baseline', simulated: false,
  targetContacted: true, target: 'https://example.org/start',
};

test('fresh per-run board and scripted fixtures need no management request', async () => {
  const plan = await prepareTargetReset({ runs: [{ fixtureId: 'vul-web-1', targetContacted: true },
    { mode: 'core-fixture', fixtureId, simulated: true }], env: {}, fetchImpl: () => assert.fail('isolated fixtures must not be reset remotely') });
  assert.deepEqual(await plan.execute(), { status: 'clean', targets: [], localLabs: { removed: 0 } });
});

test('the registered read-only external observer needs no remote reset hook', async () => {
  assert.deepEqual(targetResetObligationsForRuns([readOnlyExternal]), []);
  const plan = await prepareTargetReset({ runs: [readOnlyExternal], env: {},
    fetchImpl: () => assert.fail('read-only external observation must not request a remote reset') });
  assert.deepEqual(await plan.execute(), { status: 'clean', targets: [], localLabs: { removed: 0 } });
});

test('other contacted external executions still require managed restoration', async () => {
  for (const altered of [{ testProfile: 'active' }, { fixtureId: 'external' },
    { modelId: 'deepseek-flash' }, { targetKind: 'unknown' }]) {
    const run = { ...readOnlyExternal, ...altered };
    assert.equal(targetResetObligationsForRuns([run]).length, 1);
    await assert.rejects(prepareTargetReset({ runs: [run], env: {},
      fetchImpl: () => assert.fail('unmanaged targets must fail before networking') }),
    error => error.status === 409 && error.code === 'EXPERIMENT_TARGET_RESET_BLOCKED');
  }
});

test('all persistent target hooks are preflighted before any target is changed', async () => {
  let calls = 0;
  await assert.rejects(prepareTargetReset({ runs: [run, { ...run, fixtureId: 'vul-web2-wonchang' }], env,
    fetchImpl: () => { calls += 1; } }), error => error.status === 409);
  assert.equal(calls, 0);
  await assert.rejects(prepareTargetReset({ runs: [run], env: {} }), error => error.status === 409);
});

test('only the server configured origin receives a bounded authenticated reset request', async () => {
  const calls = [];
  const plan = await prepareTargetReset({ runs: [run, run], env, fetchImpl: async (url, options) => {
    calls.push({ url, options }); return json({ status: 'clean', fixtureId, targetOrigin, scopes, password: 'private response ignored' });
  } });
  assert.equal(calls.length, 0);
  const result = await plan.execute();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'http://127.0.0.1:4900/_ca3p/experiment-reset');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.redirect, 'error');
  assert.equal(calls[0].options.credentials, 'omit');
  assert.equal(calls[0].options.headers.Authorization, `Bearer ${token}`);
  assert.deepEqual(JSON.parse(calls[0].options.body), { confirmation: 'reset-experiment-target', fixtureId, targetOrigin });
  assert.deepEqual(result, { status: 'clean', targets: [{ fixtureId, status: 'clean', scopes }], localLabs: { removed: 0 } });
  assert.doesNotMatch(JSON.stringify(result), /private|4900|Bearer/);
  assert.deepEqual(await plan.execute(), result);
  assert.equal(calls.length, 1);
});

test('external targets and invalid management addresses are refused without networking', async () => {
  await assert.rejects(prepareTargetReset({ runs: [{ fixtureId: 'external', targetContacted: true }] }), error => error.status === 409);
  for (const origin of ['http://example.com', 'file:///tmp', 'http://user:pass@127.0.0.1:4101',
    'http://127.0.0.1:4101/path', 'https://example.com?key=secret']) {
    await assert.rejects(prepareTargetReset({ runs: [run], env: { CA3P_EXPERIMENT_RESET_TARGETS: JSON.stringify({ [fixtureId]: { origin, targetOrigin, token } }) } }),
      error => error.status === 409 && !error.message.includes(token));
  }
});

test('a target must attest the same fixture and every persistent scope', async () => {
  for (const result of [{ status: 'clean', fixtureId, targetOrigin, scopes: ['database', 'sessions'] },
    { status: 'clean', fixtureId: 'vul-web2-wonchang', targetOrigin, scopes }, { status: 'pending', fixtureId, targetOrigin, scopes },
    { status: 'clean', fixtureId, scopes }, { status: 'clean', fixtureId, targetOrigin: 'http://192.168.0.9:4101', scopes }]) {
    const plan = await prepareTargetReset({ runs: [run], env, fetchImpl: async () => json(result) });
    await assert.rejects(plan.execute(), error => error.status === 503 && !error.message.includes(token));
  }
});

test('a hook for one university instance cannot attest cleanup of another recorded instance', async () => {
  let calls = 0;
  for (const runs of [[{ ...run, target: 'http://192.168.0.9:4101' }],
    [run, { ...run, target: 'http://192.168.0.9:4101' }],
    [{ ...run, manifest: { target: { origin: 'http://192.168.0.9:4101' } } }]]) {
    await assert.rejects(prepareTargetReset({ runs, env, fetchImpl: () => { calls += 1; } }),
      error => error.status === 409 && error.code === 'EXPERIMENT_TARGET_RESET_BLOCKED');
  }
  assert.equal(calls, 0);
});

test('redirects, oversized bodies and private transport errors never count as cleanup', async () => {
  for (const fetchImpl of [async () => new Response(null, { status: 302 }),
    async () => new Response('x'.repeat(8193), { headers: { 'content-type': 'application/json' } }),
    async () => { throw new Error(`PRIVATE ${token}`); }]) {
    const plan = await prepareTargetReset({ runs: [run], env, fetchImpl });
    await assert.rejects(plan.execute(), error => error.status === 503 && !error.message.includes(token) && !error.message.includes('PRIVATE'));
  }
});
