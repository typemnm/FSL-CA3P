import assert from 'node:assert/strict';
import test from 'node:test';
import { changedModuleIds, mergeIndex, publish, selectChangedFromSha, summarizeReport } from '../publish-ci-summary.mjs';

const sha = 'a'.repeat(40);
const context = { sha, runId: '123', runAttempt: '1', repository: 'typemnm/FSL-CA3P',
  serverUrl: 'https://github.com', now: '2026-10-15T00:00:00.000Z',
  pipeline: { tests: 'success', containerSmoke: 'success', integrationGate: 'success' } };
const report = { schemaVersion: '1.0', source: 'github-actions', commitSha: sha, branch: 'develop',
  startedAt: '2026-10-14T23:00:00.000Z', completedAt: '2026-10-14T23:02:00.000Z',
  status: 'passed', completeSuite: true, tests: 12, passed: 12, failed: 0, skipped: 0,
  secret: 'must never publish', jobs: [{ id: 'xss-parser', status: 'passed', tests: 12, passed: 12,
    failed: 0, skipped: 0, log: 'private.log', error: 'private detail' }] };

test('public CI summary contains counts and pipeline conclusions but no logs or findings', () => {
  const summary = summarizeReport(report, context);
  assert.equal(summary.status, 'passed');
  assert.equal(summary.jobs[0].id, 'xss-parser');
  assert.equal(summary.jobs[0].tests, 12);
  const serialized = JSON.stringify(summary);
  assert.doesNotMatch(serialized, /secret|private|log|error|finding|modelOutput/);
});

test('failed suite remains a complete run; missing artifact is incomplete', () => {
  const failed = summarizeReport({ ...report, status: 'failed', failed: 1, completeSuite: true },
    { ...context, pipeline: { ...context.pipeline, tests: 'failure', integrationGate: 'failure' } });
  assert.equal(failed.status, 'failed');
  assert.equal(failed.completeSuite, true);
  const missing = summarizeReport(null, context);
  assert.equal(missing.status, 'incomplete');
  assert.equal(missing.completeSuite, false);
  assert.deepEqual([missing.tests, missing.passed, missing.failed, missing.skipped],
    [null, null, null, null]);
  assert.deepEqual(missing.jobs, []);
  const setupFailure = summarizeReport({ ...report, status: 'failed', completeSuite: false,
    tests: null, passed: null, failed: null, skipped: null,
    jobs: [{ id: 'ci-workflow', status: 'failed' }] }, context);
  assert.deepEqual([setupFailure.tests, setupFailure.passed, setupFailure.failed, setupFailure.skipped],
    [null, null, null, null]);
  assert.deepEqual([setupFailure.jobs[0].tests, setupFailure.jobs[0].passed,
    setupFailure.jobs[0].failed, setupFailure.jobs[0].skipped], [null, null, null, null]);
});

test('feed keeps newest 50 runs and replaces an existing run attempt', () => {
  const prior = { runs: Array.from({ length: 55 }, (_, index) => ({ runId: String(index + 100),
    runAttempt: 1, commitSha: sha, secret: 'must not persist' })) };
  const newest = summarizeReport(report, { ...context, runId: '200' });
  const index = mergeIndex(prior, newest, context.now);
  assert.equal(index.runs.length, 50);
  assert.equal(index.runs[0].runId, '200');
  assert.equal(index.runs.at(-1).runId, '106');
  assert.doesNotMatch(JSON.stringify(index), /secret/);
  const rerun = mergeIndex(index, { ...newest, status: 'failed' }, context.now);
  assert.equal(rerun.runs.length, 50);
  assert.equal(rerun.runs[0].status, 'failed');
  const unknown = mergeIndex(rerun, { ...newest, tests: null, passed: null,
    failed: null, skipped: null, changedFromSha: 'b'.repeat(40) }, context.now);
  assert.equal(unknown.runs[0].tests, null);
  assert.equal(unknown.runs[0].passed, null);
  assert.equal(unknown.runs[0].changedFromSha, 'b'.repeat(40));
});

test('diff baseline skips same-SHA runs and survives a retry of the same run', () => {
  const older = 'b'.repeat(40);
  const oldest = 'c'.repeat(40);
  const previous = { runs: [
    { runId: '124', runAttempt: 1, commitSha: sha, changedFromSha: older },
    { runId: '123', runAttempt: 1, commitSha: sha },
    { runId: '122', runAttempt: 1, commitSha: older },
    { runId: '121', runAttempt: 1, commitSha: oldest },
  ] };
  assert.equal(selectChangedFromSha(previous, '125', sha, oldest), older);
  assert.equal(selectChangedFromSha(previous, '124', sha, oldest), older);
  assert.equal(selectChangedFromSha({ runs: [previous.runs[0]] }, '124', sha, oldest), older);
  assert.equal(selectChangedFromSha({ runs: [previous.runs[0]] }, '125', sha, oldest), oldest);
  assert.equal(selectChangedFromSha(null, '125', sha, sha), null);
  assert.equal(selectChangedFromSha(null, '125', sha, '0'.repeat(40)), null);
});

test('changed module list uses source paths and manifest changes, excluding replaced modules', () => {
  const previous = { modules: [
    { id: 'agent', path: 'agent', status: 'active' },
    { id: 'guardrail', path: 'guardrail', status: 'active', dependencies: [] },
    { id: 'xss-fuzzer', path: 'xss-fuzzer', status: 'replaced' },
  ] };
  const current = { modules: [
    { id: 'agent', path: 'agent', status: 'active' },
    { id: 'guardrail', path: 'guardrail', status: 'active', dependencies: ['agent'] },
    { id: 'xss-fuzzer', path: 'xss-fuzzer', status: 'replaced' },
  ] };
  assert.deepEqual(changedModuleIds(current, previous, ['agent/src/main.js', 'xss-fuzzer/legacy.js']),
    ['agent', 'guardrail']);
});

test('publisher creates an isolated counts-only branch for a trusted develop push', async () => {
  const keys = ['GITHUB_TOKEN', 'GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_RUN_ID',
    'GITHUB_RUN_ATTEMPT', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'CA3P_TEST_RESULT',
    'CA3P_CONTAINER_RESULT', 'CA3P_GATE_RESULT', 'CA3P_BEFORE_SHA'];
  const prior = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  Object.assign(process.env, {
    GITHUB_TOKEN: 'test-token', GITHUB_REPOSITORY: 'typemnm/FSL-CA3P', GITHUB_SHA: sha,
    GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '1', GITHUB_EVENT_NAME: 'push',
    GITHUB_REF: 'refs/heads/develop', CA3P_TEST_RESULT: 'failure',
    CA3P_CONTAINER_RESULT: 'success', CA3P_GATE_RESULT: 'failure',
    CA3P_BEFORE_SHA: '0'.repeat(40),
  });
  const calls = [];
  const fakeFetch = async (url, options) => {
    calls.push({ url, ...options });
    const response = calls.length === 1 ? [404, null] : calls.length === 2 ? [201, { sha: 'b'.repeat(40) }]
      : calls.length === 3 ? [201, { sha: 'c'.repeat(40) }] : [201, { ref: 'refs/heads/ci-results' }];
    return { status: response[0], json: async () => response[1] };
  };
  try {
    await publish({ fetchImpl: fakeFetch, reportPath: '/no/ci/report.json' });
    assert.equal(calls.length, 4);
    assert.match(calls[0].url, /\/git\/ref\/heads\/ci-results$/);
    assert.match(calls[3].url, /\/git\/refs$/);
    const tree = JSON.parse(calls[1].body);
    const feed = JSON.parse(tree.tree[0].content);
    assert.equal(feed.runs[0].status, 'failed');
    assert.equal(feed.runs[0].completeSuite, false);
    assert.equal(feed.runs[0].changedModules, null);
    assert.equal(feed.runs[0].changedFromSha, null);
    assert.equal(feed.runs[0].tests, null);
    assert.deepEqual(Object.keys(feed), ['schemaVersion', 'generatedAt', 'runs']);
  } finally {
    for (const key of keys) prior[key] === undefined ? delete process.env[key] : process.env[key] = prior[key];
  }
});
