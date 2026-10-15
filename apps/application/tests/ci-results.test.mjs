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
  changedModules: ['agent'], privateNote: 'must-not-leak' };
const response = value => ({ ok: true, text: async () => JSON.stringify(value) });

test('public feed is allowlisted and cannot claim a passing gate with missing evidence', () => {
  const rows = sanitizeCiFeed({ schemaVersion: '1.0', runs: [example,
    { ...example, runId: 102, pipeline: { ...example.pipeline, integrationGate: 'failure' } },
    { ...example, runId: 103, branch: 'feature/untrusted' },
    { ...example, runId: 104, jobs: [{ id: '<script>', status: 'passed', tests: 1 }] }] });
  assert.deepEqual(rows.map(row => row.runId), [104, 102, 101]);
  assert.equal(rows[1].status, 'incomplete');
  assert.equal(rows[0].jobs.length, 0);
  assert.deepEqual(rows[2].changedModules, ['agent']);
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
  service.close();
  const offline = createCiResultsService({ cachePath, autoStart: false, fetchImpl: async () => { throw new Error('offline secret'); } });
  assert.equal(offline.getSnapshot().status, 'cached');
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
    if (url.includes('raw.githubusercontent.com')) return { ok: false, status: 404 };
    if (url.includes('/runs?')) return response({ workflow_runs: [{ id: 101, run_attempt: 1, head_sha: commitSha,
      head_branch: 'develop', event: 'push', status: 'completed', conclusion: 'success',
      created_at: '2026-10-15T01:00:00Z', updated_at: '2026-10-15T01:05:00Z' }] });
    return response({ jobs: [{ name: 'tests', conclusion: 'success' }, { name: 'container-smoke', conclusion: 'success' },
      { name: 'integration-gate', conclusion: 'success' }] });
  } });
  const result = await service.sync();
  assert.equal(result.source, 'actions-api'); assert.equal(result.runs[0].status, 'incomplete');
  assert.equal(result.runs[0].tests, null); assert.deepEqual(result.runs[0].jobs, []);
  assert.equal(result.runs[0].pipeline.integrationGate, 'success');
  assert.equal(calls.length, 3);
  service.close();
});
