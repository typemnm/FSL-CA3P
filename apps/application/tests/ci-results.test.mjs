import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCiResultsService, sanitizeCiFeed } from '../ci-results.mjs';

const commitSha = 'a'.repeat(40);
const example = { runId: 101, runAttempt: 1, commitSha, branch: 'develop', eventName: 'push',
  status: 'passed', completeSuite: true, tests: 10, passed: 10, failed: 0, skipped: 0,
  startedAt: '2026-10-15T01:00:00Z', completedAt: '2026-10-15T01:05:00Z',
  pipeline: { tests: 'success', containerSmoke: 'success', integrationGate: 'success' },
  jobs: [{ id: 'agent', status: 'passed', tests: 10, passed: 10, failed: 0, skipped: 0 }],
  changedFromSha: 'b'.repeat(40), changedModules: ['agent'], privateNote: 'must-not-leak' };
const response = value => new Response(JSON.stringify(value), { status: 200 });
const workflow = (changes = {}) => ({ id: 101, run_attempt: 1, head_sha: commitSha,
  repository: { full_name: 'typemnm/FSL-CA3P' }, head_repository: { full_name: 'typemnm/FSL-CA3P' },
  path: '.github/workflows/ci.yml', html_url: 'https://github.com/typemnm/FSL-CA3P/actions/runs/101',
  head_branch: 'develop', event: 'push', status: 'completed', conclusion: 'success',
  created_at: '2026-10-15T01:00:00Z', updated_at: '2026-10-15T01:05:00Z', ...changes });
const listing = (...runs) => response({ total_count: runs.length, workflow_runs: runs });
async function serviceFixture(t, fetchImpl, extra = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'ca3p-ci-live-'));
  const service = createCiResultsService({ cachePath: join(dir, 'index.json'), autoStart: false, fetchImpl, ...extra });
  t.after(async () => { service.close(); await rm(dir, { recursive: true, force: true }); });
  return service;
}

test('public feed is allowlisted and cannot claim a passing gate with missing evidence', () => {
  const rows = sanitizeCiFeed({ schemaVersion: '1.0', runs: [example,
    { ...example, runId: 102, pipeline: { ...example.pipeline, integrationGate: 'failure' } },
    { ...example, runId: 103, branch: 'feature/untrusted' },
    { ...example, runId: 104, jobs: [{ id: '<script>', status: 'passed', tests: 1 }] }] });
  assert.deepEqual(rows.map(row => row.runId), [104, 102, 101]);
  assert.equal(rows[1].status, 'incomplete');
  assert.equal(rows[0].jobs.length, 0);
  assert.deepEqual(rows[2].changedModules, ['agent']);
  assert.equal(rows[2].changedFromSha, 'b'.repeat(40));
  assert.equal(sanitizeCiFeed({ schemaVersion: '1.0', runs: [{ ...example, changedFromSha: 'invalid' }] })[0].changedFromSha, null);
  assert.equal(sanitizeCiFeed({ schemaVersion: '1.0', runs: [{ ...example, tests: null, passed: null }] })[0].status, 'incomplete');
  assert.equal(JSON.stringify(rows).includes('must-not-leak'), false);
  assert.equal(rows[2].runUrl, 'https://github.com/typemnm/FSL-CA3P/actions/runs/101');
});

test('collector keeps the last verified feed during network failure', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'ca3p-ci-results-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const cachePath = join(dir, 'index.json');
  const service = createCiResultsService({ cachePath, autoStart: false, fetchImpl: async () => response({ schemaVersion: '1.0', runs: [example] }) });
  const fresh = await service.sync();
  assert.equal(fresh.source, 'public-feed'); assert.equal(fresh.status, 'fresh'); assert.equal(fresh.runs[0].status, 'passed');
  assert.equal(fresh.live.status, 'unavailable', 'the valid counts feed does not prove the latest workflow listing is available');
  service.close();
  const offline = createCiResultsService({ cachePath, autoStart: false, fetchImpl: async () => { throw new Error('offline secret'); } });
  assert.equal(offline.getSnapshot().status, 'cached');
  assert.equal(offline.getSnapshot().runs[0].changedFromSha, 'b'.repeat(40));
  const stale = await offline.sync();
  assert.equal(stale.status, 'stale'); assert.equal(stale.runs[0].runId, 101);
  assert.equal(JSON.stringify(stale).includes('offline secret'), false);
  offline.close();
});

test('when the summary branch is absent, public Actions jobs remain visible without invented module counts', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'ca3p-ci-results-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const calls = [];
  const service = createCiResultsService({ cachePath: join(dir, 'index.json'), autoStart: false, fetchImpl: async url => {
    calls.push(url);
    if (url.includes('raw.githubusercontent.com')) return new Response('', { status: 404 });
    if (url.includes('/runs?')) return listing(workflow());
    return response({ jobs: ['tests', 'container-smoke', 'integration-gate'].map(name => ({ name, conclusion: 'success',
      run_id: 101, run_attempt: 1, head_sha: commitSha, head_branch: 'develop' })) });
  } });
  const result = await service.sync();
  assert.equal(result.source, 'actions-api'); assert.equal(result.runs[0].status, 'incomplete');
  assert.equal(result.runs[0].tests, null); assert.deepEqual(result.runs[0].jobs, []);
  assert.equal(result.runs[0].changedFromSha, null);
  assert.equal(result.runs[0].pipeline.integrationGate, 'success');
  assert.equal(result.live.status, 'fresh');
  assert.equal(calls.length, 3);
  service.close();
});

test('a healthy counts feed still discovers the newer running develop push with one listing request', async t => {
  const calls = [];
  const service = await serviceFixture(t, async (url, options) => {
    calls.push(url);
    assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'omit');
    assert.equal(options.headers.Authorization, undefined);
    return url.includes('raw.githubusercontent.com') ? response({ schemaVersion: '1.0', runs: [example] })
      : listing(workflow({ id: 102, head_sha: 'b'.repeat(40), html_url: 'https://github.com/typemnm/FSL-CA3P/actions/runs/102', status: 'in_progress', conclusion: null }));
  });
  const result = await service.sync();
  assert.deepEqual(result.runs.map(run => [run.runId, run.status]), [[102, 'running'], [101, 'passed']]);
  assert.equal(result.runs[0].tests, null); assert.equal(result.runs[0].completeSuite, false);
  assert.equal(result.live.status, 'fresh'); assert.equal(result.live.runId, 102); assert.equal(result.live.workflowStatus, 'in_progress');
  assert.equal(calls.length, 2, 'normal polling uses only the feed and one public API listing');
});

test('a queued or rerun workflow keeps creation time distinct from its later start across cache reload', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'ca3p-ci-created-time-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const cachePath = join(dir, 'index.json');
  const service = createCiResultsService({ cachePath, autoStart: false, fetchImpl: async url => url.includes('raw.githubusercontent.com')
    ? response({ schemaVersion: '1.0', runs: [example] })
    : listing(workflow({ run_attempt: 2, status: 'in_progress', conclusion: null,
      created_at: '2026-10-15T01:00:00Z', run_started_at: '2026-10-15T03:00:00Z' })) });
  const fresh = await service.sync(); service.close();
  assert.equal(fresh.runs[0].createdAt, '2026-10-15T01:00:00.000Z');
  assert.equal(fresh.runs[0].startedAt, '2026-10-15T03:00:00.000Z');
  assert.equal(fresh.runs[1].createdAt, null, 'a summary without creation time must not substitute its start time');
  const cached = createCiResultsService({ cachePath, autoStart: false });
  t.after(() => cached.close());
  assert.equal(cached.getSnapshot().runs[0].createdAt, fresh.runs[0].createdAt);
  assert.equal(cached.getSnapshot().runs[0].startedAt, fresh.runs[0].startedAt);
});

test('a newer rerun attempt never inherits a previous successful attempt or stale feed status', async t => {
  let attempt = 2;
  const service = await serviceFixture(t, async url => url.includes('raw.githubusercontent.com')
    ? response({ schemaVersion: '1.0', runs: [example] }) : listing(workflow({ run_attempt: attempt, status: 'queued', conclusion: null })));
  let result = await service.sync();
  assert.deepEqual(result.runs.map(run => [run.runAttempt, run.status]), [[2, 'running'], [1, 'passed']]);
  assert.equal(result.runs[0].tests, null);
  attempt = 1; result = await service.sync();
  assert.equal(result.runs[0].status, 'running', 'live queued status is not overwritten by the same-attempt counts feed');
});

test('a workflow success is incomplete until the same attempt has verified suite counts', async t => {
  let feedRuns = [];
  let status = 'in_progress';
  const service = await serviceFixture(t, async url => url.includes('raw.githubusercontent.com')
    ? response({ schemaVersion: '1.0', runs: feedRuns }) : listing(workflow({ status, conclusion: status === 'completed' ? 'success' : null })));
  assert.equal((await service.sync()).runs[0].status, 'running');
  status = 'completed';
  assert.equal((await service.sync()).runs[0].status, 'incomplete');
  feedRuns = [example];
  const verified = await service.sync();
  assert.equal(verified.runs[0].status, 'passed'); assert.equal(verified.runs[0].tests, 10);
});

test('an API failure keeps the verified feed, advertises unknown live freshness and backs off rate limits', async t => {
  let apiCalls = 0;
  const service = await serviceFixture(t, async url => {
    if (url.includes('raw.githubusercontent.com')) return response({ schemaVersion: '1.0', runs: [example] });
    apiCalls += 1;
    return new Response('private rate-limit body', { status: 429, headers: { 'retry-after': '1200' } });
  });
  const result = await service.sync();
  assert.equal(result.status, 'fresh'); assert.equal(result.runs[0].status, 'passed'); assert.equal(result.live.status, 'unavailable');
  assert.ok(Date.parse(result.live.retryAt) > Date.now());
  assert.equal(JSON.stringify(result).includes('private rate-limit'), false);
  await service.sync(); assert.equal(apiCalls, 1, 'do not consume the shared IP quota again before retryAt');
});

test('a later live API outage cannot replace a known rerun with the older passing counts feed', async t => {
  let unavailable = false;
  const service = await serviceFixture(t, async url => {
    if (url.includes('raw.githubusercontent.com')) return response({ schemaVersion: '1.0', runs: [example] });
    return unavailable ? new Response('', { status: 429, headers: { 'retry-after': '1200' } })
      : listing(workflow({ run_attempt: 2, status: 'in_progress', conclusion: null }));
  });
  const initial = await service.sync();
  assert.equal(initial.runs[0].runAttempt, 2); assert.equal(initial.runs[0].status, 'running');
  unavailable = true;
  const outage = await service.sync();
  assert.equal(outage.live.status, 'unavailable');
  assert.deepEqual(outage.runs.map(run => [run.runAttempt, run.status]), [[2, 'running'], [1, 'passed']]);
  assert.equal(outage.live.runAttempt, 2); assert.equal(outage.live.checkedAt, initial.live.checkedAt);
});

test('a regressed successful listing cannot replace an already observed newer attempt or run', async t => {
  let current = workflow({ run_attempt: 2, status: 'in_progress', conclusion: null });
  const service = await serviceFixture(t, async url => url.includes('raw.githubusercontent.com')
    ? response({ schemaVersion: '1.0', runs: [example] }) : listing(current));
  await service.sync();
  current = workflow();
  const oldAttempt = await service.sync();
  assert.equal(oldAttempt.live.status, 'unavailable');
  assert.deepEqual(oldAttempt.runs.map(run => [run.runAttempt, run.status]), [[2, 'running'], [1, 'passed']]);
  current = workflow({ id: 102, html_url: 'https://github.com/typemnm/FSL-CA3P/actions/runs/102', status: 'queued', conclusion: null });
  assert.equal((await service.sync()).live.status, 'fresh');
  current = workflow();
  const oldRun = await service.sync();
  assert.equal(oldRun.live.status, 'unavailable');
  assert.equal(oldRun.runs[0].runId, 102); assert.equal(oldRun.runs[0].status, 'running');
});

test('mismatched repository, workflow, branch, event, identity and malformed listing are not live evidence', async t => {
  const invalid = [
    workflow({ repository: { full_name: 'other/repo' } }), workflow({ head_repository: { full_name: 'other/repo' } }),
    workflow({ path: '.github/workflows/other.yml' }), workflow({ head_branch: 'main' }), workflow({ event: 'pull_request' }),
    workflow({ html_url: 'https://example.invalid/private' }), workflow({ id: true }), workflow({ run_attempt: 0 }),
    workflow({ status: 'in_progress', conclusion: 'success' }),
  ];
  let current;
  const service = await serviceFixture(t, async url => url.includes('raw.githubusercontent.com')
    ? response({ schemaVersion: '1.0', runs: [example] }) : listing(current));
  for (current of invalid) {
    const result = await service.sync();
    assert.equal(result.live.status, 'unavailable'); assert.equal(result.runs[0].status, 'passed');
  }
});

test('stream limits and transport timeout keep existing counts and never publish raw response data', async t => {
  let mode = 'large';
  const service = await serviceFixture(t, async url => {
    if (url.includes('raw.githubusercontent.com')) return response({ schemaVersion: '1.0', runs: [example] });
    if (mode === 'large') return new Response('private'.repeat(80_000), { status: 200 });
    if (mode === 'redirect') return { status: 200, redirected: true };
    return new Promise(() => {});
  }, { requestTimeoutMs: 15 });
  for (mode of ['large', 'redirect', 'timeout']) {
    const result = await service.sync();
    assert.equal(result.live.status, 'unavailable'); assert.equal(result.runs[0].status, 'passed');
    assert.equal(JSON.stringify(result).includes('private'), false);
  }
});
