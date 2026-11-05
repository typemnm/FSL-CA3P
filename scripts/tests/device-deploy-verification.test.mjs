import assert from 'node:assert/strict';
import test from 'node:test';
import { GitHubRateLimitError, WorkflowPendingError, selectVerifiedRelease, verifyWorkflowRun } from '../device-deploy-verification.mjs';

const repository = 'typemnm/FSL-CA3P';
const headSha = 'a'.repeat(40);
const candidate = { sha: headSha, runId: '40209727623', runAttempt: 1,
  runUrl: `https://github.com/${repository}/actions/runs/40209727623` };
const date = '2026-10-26T03:00:00.000Z';
function summary(overrides = {}) {
  return { runId: candidate.runId, runAttempt: 1, commitSha: headSha, branch: 'develop', eventName: 'push',
    startedAt: date, completedAt: date, status: 'passed', completeSuite: true,
    tests: 10, passed: 10, failed: 0, skipped: 0,
    jobs: [{ id: 'boundaries', status: 'passed', tests: null, passed: null, failed: null, skipped: null },
      { id: 'application', status: 'passed', tests: 10, passed: 10, failed: 0, skipped: 0 }],
    pipeline: { tests: 'success', containerSmoke: 'success', integrationGate: 'success' },
    runUrl: candidate.runUrl, changedFromSha: 'b'.repeat(40), changedModules: ['application'], ...overrides };
}
const feed = (...runs) => ({ schemaVersion: '1.0', generatedAt: date, runs });
const select = index => selectVerifiedRelease({ headSha, index });
function workflow(overrides = {}) {
  return { id: Number(candidate.runId), run_attempt: 1, repository: { full_name: repository },
    head_repository: { full_name: repository }, event: 'push', head_branch: 'develop', head_sha: headSha,
    path: '.github/workflows/ci.yml', html_url: candidate.runUrl, status: 'completed', conclusion: 'success', ...overrides };
}
function job(name, id, overrides = {}) {
  return { id, run_id: Number(candidate.runId), run_attempt: 1, head_sha: headSha, head_branch: 'develop',
    name, status: 'completed', conclusion: 'success', ...overrides };
}
const jobs = () => ['tests', 'container-smoke', 'integration-gate'].map((name, index) => job(name, index + 1));
const json = (value, options) => new Response(JSON.stringify(value), { status: 200, ...options });
function api({ runs = [workflow()], run = workflow(), allJobs = jobs(), response } = {}) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    if (response) return response(url, options, calls);
    if (url.includes('/actions/workflows/')) return json({ total_count: runs.length, workflow_runs: runs });
    if (url.includes('/jobs?')) {
      const page = Number(new URL(url).searchParams.get('page'));
      return json({ total_count: allJobs.length, jobs: allJobs.slice((page - 1) * 100, page * 100) });
    }
    return json(run);
  };
  return { calls, fetchImpl };
}

test('selection requires exact develop HEAD and returns only release identity', () => {
  assert.deepEqual(select(feed(summary())), { status: 'verified', candidate });
  assert.equal(select(feed(summary({ startedAt: '2026-10-26T03:00:00.123456+00:00' }))).status, 'verified');
  assert.equal(select(feed(summary({ commitSha: 'b'.repeat(40) }))).status, 'pending');
  assert.equal(select(feed()).status, 'pending');
  assert.equal(selectVerifiedRelease({ headSha: 'bad', index: feed(summary()) }).status, 'pending');
  assert.equal(selectVerifiedRelease({ headSha, index: feed(summary()), repository: '../bad' }).status, 'pending');
});

test('selection never falls back to success after a failed or unfinished newer attempt or run', () => {
  for (const latest of [summary({ runAttempt: 2, status: 'failed' }), summary({ runAttempt: 2, status: 'incomplete' }),
    summary({ runId: '40209727624', runUrl: `https://github.com/${repository}/actions/runs/40209727624`, status: 'failed' })]) {
    assert.equal(select(feed(summary(), latest)).status, 'pending');
    assert.equal(select(feed(latest, summary())).status, 'pending');
  }
  assert.equal(select(feed(summary({ runAttempt: 1, status: 'failed' }), summary({ runAttempt: 2 }))).status, 'verified');
});

test('selection rejects malformed, ambiguous, PR, cross-repository and evidence-bearing summaries', () => {
  const invalid = [null, {}, { ...feed(summary()), schemaVersion: '2.0' }, { ...feed(summary()), rawEvidence: 'private' },
    feed(summary(), summary()), feed(summary(), summary({ runAttempt: 2, commitSha: 'c'.repeat(40) })),
    feed(summary({ eventName: 'pull_request' })), feed(summary({ branch: 'main' })),
    feed(summary({ runUrl: 'https://github.com/attacker/repo/actions/runs/40209727623' })),
    feed(summary({ runId: '040209727623' })), feed(summary({ runAttempt: 0 })),
    feed(summary({ logs: 'secret' })), feed(summary({ pipeline: { tests: 'success' } })),
    feed(summary({ jobs: [{ ...summary().jobs[1], rawEvidence: 'secret' }] })),
    feed(summary({ jobs: [summary().jobs[1], summary().jobs[1]] }))];
  for (const value of invalid) assert.equal(select(value).status, 'pending', JSON.stringify(value));
});

test('selection rejects incomplete counts, skips, empty suites and any failed required pipeline', () => {
  const changes = [{ tests: 0, passed: 0 }, { tests: null }, { tests: '10' }, { tests: 10.5 }, { passed: 9 },
    { skipped: 1 }, { failed: 1 }, { completeSuite: false }, { completedAt: null }, { jobs: [] },
    { jobs: [{ ...summary().jobs[1], tests: 9, passed: 9 }] },
    { jobs: [{ ...summary().jobs[1], status: 'failed' }] },
    ...Object.keys(summary().pipeline).map(key => ({ pipeline: { ...summary().pipeline, [key]: 'failure' } }))];
  for (const change of changes) assert.equal(select(feed(summary(change))).status, 'pending', JSON.stringify(change));
});

test('GitHub verification is credential-free, pins attempt jobs and checks latest workflow twice', async () => {
  const fake = api();
  assert.deepEqual(await verifyWorkflowRun(candidate, fake), candidate);
  assert.equal(fake.calls.length, 5);
  assert.equal(fake.calls.filter(call => call.url.includes('/actions/workflows/')).length, 2);
  assert.match(fake.calls.find(call => call.url.includes('/jobs?')).url, /\/attempts\/1\/jobs\?per_page=100&page=1$/);
  for (const { url, options } of fake.calls) {
    assert.match(url, /^https:\/\/api\.github\.com\/repos\/typemnm\/FSL-CA3P\//);
    assert.equal(options.redirect, 'error');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.headers.Authorization, undefined);
    assert.ok(options.signal instanceof AbortSignal);
  }
});

test('GitHub verification rejects PRs, wrong repositories, SHAs, branches, workflow paths and attempts', async () => {
  const changes = [{ event: 'pull_request' }, { repository: { full_name: 'evil/repo' } },
    { head_repository: { full_name: 'evil/repo' } }, { head_repository: null },
    { head_sha: 'b'.repeat(40) }, { head_branch: 'main' }, { path: '.github/workflows/other.yml' },
    { run_attempt: 2 }, { id: 99 }, { html_url: 'https://evil.test/' }, { conclusion: 'failure' }];
  for (const change of changes) {
    await assert.rejects(verifyWorkflowRun(candidate, api({ run: workflow(change) })), /does not match/);
  }
});

test('an unfinished exact workflow is pending and never accepted before its overall success', async () => {
  for (const status of ['queued', 'in_progress', 'waiting', 'pending', 'requested']) {
    const fake = api({ runs: [workflow({ status, conclusion: null })] });
    await assert.rejects(verifyWorkflowRun(candidate, fake), error => {
      assert.ok(error instanceof WorkflowPendingError);
      assert.equal(error.code, 'CI_PENDING');
      assert.equal(error.sha, candidate.sha);
      assert.equal(error.runId, candidate.runId);
      assert.equal(error.runAttempt, candidate.runAttempt);
      return true;
    });
    assert.equal(fake.calls.length, 1, 'pending listing must stop before reading jobs');
    await assert.rejects(verifyWorkflowRun(candidate, api({ run: workflow({ status, conclusion: null }) })),
      error => error.code === 'CI_PENDING');
  }
});

test('pending status never hides a superseding run, rerun, invalid identity or failure', async () => {
  const unfinished = { status: 'in_progress', conclusion: null };
  for (const change of [{ id: Number(candidate.runId) + 1 }, { run_attempt: 2 },
    { event: 'pull_request' }, { repository: { full_name: 'evil/repo' } },
    { head_repository: null }, { head_sha: 'b'.repeat(40) }, { head_branch: 'main' },
    { path: '.github/workflows/other.yml' }, { html_url: 'https://evil.test/' },
    { conclusion: 'failure' }, { status: 'unknown' }]) {
    const run = workflow({ ...unfinished, ...change });
    await assert.rejects(verifyWorkflowRun(candidate, api({ runs: [run] })),
      error => error.code !== 'CI_PENDING');
    await assert.rejects(verifyWorkflowRun(candidate, api({ run })),
      error => error.code !== 'CI_PENDING');
  }
});

test('a workflow becoming pending during verification is not accepted after reading successful jobs', async () => {
  let runReads = 0;
  const fake = api({ response: url => {
    if (url.includes('/actions/workflows/')) return json({ total_count: 1, workflow_runs: [workflow()] });
    if (url.includes('/jobs?')) return json({ total_count: 3, jobs: jobs() });
    return json(workflow(++runReads === 2 ? { status: 'in_progress', conclusion: null } : {}));
  } });
  await assert.rejects(verifyWorkflowRun(candidate, fake), error => error.code === 'CI_PENDING');
  assert.equal(runReads, 2);
});

test('newer workflow run or rerun supersedes an old successful counts feed', async () => {
  for (const newer of [workflow({ id: Number(candidate.runId) + 1, conclusion: 'failure' }),
    workflow({ run_attempt: 2, status: 'in_progress', conclusion: null })]) {
    const runs = newer.id === Number(candidate.runId) ? [newer] : [workflow(), newer];
    await assert.rejects(verifyWorkflowRun(candidate, api({ runs })), /supersedes/);
  }
});

test('partial, mismatched or duplicate latest workflow listings fail closed', async () => {
  for (const listing of [{ total_count: 0, workflow_runs: [] }, { total_count: 1 },
    { total_count: 2, workflow_runs: [workflow()] },
    { total_count: 0, workflow_runs: [workflow()] },
    { total_count: 2, workflow_runs: [workflow(), workflow()] },
    { total_count: 1, workflow_runs: [workflow({ event: 'pull_request' })] }]) {
    await assert.rejects(verifyWorkflowRun(candidate, api({ response: () => json(listing) })), /listing/);
  }
});

test('GitHub verification rejects missing, duplicate, stale or unsuccessful gate jobs', async () => {
  const badJobs = [jobs().slice(1), [...jobs(), job('tests', 4)], [...jobs(), jobs()[0]],
    jobs().map((value, index) => index === 0 ? { ...value, conclusion: 'failure' } : value),
    jobs().map((value, index) => index === 0 ? { ...value, status: 'queued' } : value),
    jobs().map((value, index) => index === 0 ? { ...value, run_attempt: 2 } : value),
    jobs().map((value, index) => index === 0 ? { ...value, run_id: 7 } : value),
    jobs().map((value, index) => index === 0 ? { ...value, head_sha: 'b'.repeat(40) } : value)];
  for (const allJobs of badJobs) await assert.rejects(verifyWorkflowRun(candidate, api({ allJobs })), /job/i);
});

test('GitHub jobs are fully paginated and checked beyond page one', async () => {
  const allJobs = [...Array.from({ length: 100 }, (_, index) => job(`matrix-${index}`, index + 10)), ...jobs()];
  const fake = api({ allJobs });
  assert.deepEqual(await verifyWorkflowRun(candidate, fake), candidate);
  assert.equal(fake.calls.filter(call => call.url.includes('/jobs?')).length, 2);
  await assert.rejects(verifyWorkflowRun(candidate, api({ allJobs: [...allJobs, job('tests', 999)] })), /duplicated/);
});

test('partial pages, changing totals, duplicates across pages and excessive totals are rejected', async () => {
  const first = Array.from({ length: 100 }, (_, index) => job(`matrix-${index}`, index + 10));
  for (const pages of [
    [{ total_count: 4, jobs: jobs() }],
    [{ total_count: 103, jobs: first }, { total_count: 104, jobs: jobs() }],
    [{ total_count: 103, jobs: first }, { total_count: 103, jobs: [...jobs().slice(0, 2), first[0]] }],
    [{ total_count: 1001, jobs: first }],
  ]) {
    let page = 0;
    const fake = api({ response: url => url.includes('/actions/workflows/')
      ? json({ total_count: 1, workflow_runs: [workflow()] })
      : url.includes('/jobs?') ? json(pages[page++]) : json(workflow()) });
    await assert.rejects(verifyWorkflowRun(candidate, fake), /pagination|duplicate/i);
  }
});

test('a rerun or new workflow starting during the API read prevents deployment', async () => {
  let listingReads = 0; let runReads = 0;
  const fake = api({ response: url => {
    if (url.includes('/actions/workflows/')) {
      listingReads++;
      return json({ total_count: 1, workflow_runs: [workflow()] });
    }
    if (url.includes('/jobs?')) return json({ total_count: 3, jobs: jobs() });
    runReads++;
    return json(workflow(runReads === 2 ? { run_attempt: 2 } : {}));
  } });
  await assert.rejects(verifyWorkflowRun(candidate, fake), /does not match/);
  assert.equal(listingReads, 2);
  let reads = 0;
  await assert.rejects(verifyWorkflowRun(candidate, api({ response: url => {
    if (url.includes('/actions/workflows/')) return json({ total_count: 1,
      workflow_runs: [workflow(++reads === 2 ? { id: Number(candidate.runId) + 1, conclusion: 'failure' } : {})] });
    return json(url.includes('/jobs?') ? { total_count: 3, jobs: jobs() } : workflow());
  } })), /supersedes/);
});

test('redirects, unexpected statuses and response origins fail without following redirects', async () => {
  for (const response of [() => new Response('', { status: 302, headers: { location: 'https://evil.test/' } }),
    () => new Response('', { status: 403 }),
    () => ({ status: 200, redirected: true }), () => ({ status: 200, url: 'https://evil.test/' })]) {
    await assert.rejects(verifyWorkflowRun(candidate, api({ response })), /HTTP|redirect/);
  }
});

test('GitHub exhausted 403 and 429 return a bounded retry time without reading response bodies', async t => {
  const now = Date.parse('2026-10-26T09:00:00.000Z');
  t.mock.method(Date, 'now', () => now);
  for (const [status, headers, delay] of [
    [403, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String((now + 600_000) / 1000) }, 600_000],
    [429, { 'retry-after': '300' }, 300_000],
    [429, { 'retry-after': new Date(now + 900_000).toUTCString() }, 900_000],
    [429, { 'retry-after': '300', 'x-ratelimit-reset': String((now + 600_000) / 1000) }, 600_000],
    [429, { 'retry-after': '9999999999' }, 7_200_000],
    [429, { 'x-ratelimit-reset': '999999999999' }, 7_200_000],
    [429, { 'retry-after': '60', 'x-ratelimit-reset': String((now - 1000) / 1000) }, 120_000],
    [429, {}, 120_000],
  ]) {
    const fake = api({ response: () => ({ status, headers: new Headers(headers),
      get body() { assert.fail('rate-limit response body must not be read'); } }) });
    await assert.rejects(verifyWorkflowRun(candidate, fake), error => {
      assert.ok(error instanceof GitHubRateLimitError);
      assert.equal(error.code, 'GITHUB_RATE_LIMITED');
      assert.equal(error.retryAt, new Date(now + delay).toISOString());
      assert.equal(error.message.includes('secret-response'), false);
      return true;
    });
    assert.equal(fake.calls.length, 1);
  }
});

test('malformed rate-limit timing headers use the minimum delay and cannot enter error text', async t => {
  const now = Date.parse('2026-10-26T09:00:00.000Z');
  t.mock.method(Date, 'now', () => now);
  for (const invalid of ['secret-response', '-1', 'Infinity', '1e100', '0.5', '9'.repeat(100),
    '9999999999999', 'Tue, 31 Nov 2026 10:00:00 GMT']) {
    await assert.rejects(verifyWorkflowRun(candidate, api({ response: () => new Response('secret-response', {
      status: 429, headers: { 'x-ratelimit-reset': invalid, 'retry-after': invalid },
    }) })), error => error.code === 'GITHUB_RATE_LIMITED'
      && error.retryAt === new Date(now + 120_000).toISOString() && !error.message.includes('secret-response'));
  }
});

test('ordinary forbidden responses and rate-limited redirects remain fatal verification errors', async () => {
  for (const response of [
    () => new Response('secret-response', { status: 403 }),
    () => new Response('secret-response', { status: 403, headers: { 'x-ratelimit-remaining': '1', 'retry-after': '300' } }),
    () => ({ status: 429, redirected: true, headers: new Headers({ 'retry-after': '300' }) }),
    () => ({ status: 403, url: 'https://evil.test/', headers: new Headers({ 'x-ratelimit-remaining': '0' }) }),
  ]) {
    await assert.rejects(verifyWorkflowRun(candidate, api({ response })), error =>
      error.code !== 'GITHUB_RATE_LIMITED' && !error.message.includes('secret-response'));
  }
});

test('API response limits apply to declared and streamed size and malformed JSON', async () => {
  await assert.rejects(verifyWorkflowRun(candidate, api({ response: () => json(workflow(), {
    headers: { 'content-length': '9999999' } }) })), /size limit/);
  await assert.rejects(verifyWorkflowRun(candidate, { ...api({ response: () => json({ text: 'x'.repeat(1000) }) }), maxBytes: 100 }), /size limit/);
  await assert.rejects(verifyWorkflowRun(candidate, api({ response: () => new Response('{') })), /invalid JSON/);
  await assert.rejects(verifyWorkflowRun(candidate, api({ response: () => json([]) })), /invalid object/);
});

test('timeout covers fetch and a stalled body, even if a fake transport ignores abort', async () => {
  await assert.rejects(verifyWorkflowRun(candidate, { fetchImpl: () => new Promise(() => {}), timeoutMs: 10 }), /timed out/);
  const body = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('{')); } });
  await assert.rejects(verifyWorkflowRun(candidate, { fetchImpl: async () => new Response(body), timeoutMs: 10 }), /timed out/);
  assert.equal(body.locked, true);
});

test('invalid verifier input is rejected before networking', async () => {
  for (const bad of [{ ...candidate, runAttempt: 0 }, { ...candidate, runId: '../7' },
    { ...candidate, sha: '0'.repeat(40) }, { ...candidate, runUrl: 'https://evil.test/' }]) {
    await assert.rejects(verifyWorkflowRun(bad, { fetchImpl: () => assert.fail('must not request') }), /Invalid/);
  }
});
