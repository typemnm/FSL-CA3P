import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { once } from 'node:events';
import { createRequire } from 'node:module';
const { chromium } = createRequire(new URL('../../xss-parser/package.json', import.meta.url))('playwright');

const event = { id: 'event-a', time: '2026-10-14T10:00:00Z', module: 'agent', type: 'info', title: 'plan', detail: 'test evidence', iteration: 1, correlationId: 'correlation-a', latency: null, request: {}, response: {}, agentInput: {}, agentOutput: {} };
function snapshot(id, mode = 'core-fixture') {
  return { id, mode, target: 'http://127.0.0.1:3000/', status: 'completed', simulated: mode === 'core-fixture', targetContacted: mode !== 'core-fixture', startedAt: '2026-10-14T10:00:00Z', elapsedMs: 100, totalSteps: 1, step: 1, iterations: 1, events: [event], snapshots: { agent: event }, reviewItems: [], testProfile: 'stored_xss_canary', manifest: { source: { commit: '123abc' }, model: { id: mode === 'core-fixture' ? 'rule-fixture' : 'rule-baseline' } }, report: { status: 'completed' }, historyWrite: { status: 'synced', checks: [{ check_id: 'check-a', case_id: 'synthetic-fixture', case_revision: 1, result: 'confirmed', review_status: 'pending', evidence_metadata: { sha256: 'synthetic-test-hash', synthetic: true } }] } };
}
const idle = { ...snapshot('', 'core-fixture'), id: null, status: 'idle', events: [], snapshots: {}, totalSteps: 19, step: 0 };
const wrap = run => ({ instanceId: 'test-server', mode: run.mode, run, lab: { available: false } });
async function setup(t, role = 'operator', ciRuns = null) {
  const server = http.createServer(async (req, res) => {
    try {
      const filename = new URL(req.url, 'http://test').pathname.split('/').pop() || 'index.html';
      if (!/^[a-z-]+\.(?:html|js|css|svg)$/.test(filename)) { res.writeHead(404); return res.end(); }
      const body = await readFile(new URL(`../dist/${filename}`, import.meta.url));
      const mime = { html: 'text/html', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' };
      res.writeHead(200, { 'Content-Type': mime[filename.split('.').pop()] }); res.end(body);
    } catch { res.writeHead(404); res.end(); }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage(); const errors = []; const mutations = []; const reviews = [];
  page.on('pageerror', error => errors.push(error.message));
  let authenticated = false; let state = idle; let detailCalls = 0;
  const runs = [snapshot('candidate'), snapshot('baseline'), {
    id: 'legacy-record', mode: 'legacy-import', status: 'completed', startedAt: '2026-10-13T10:00:00Z',
    target: null, events: [{ module: 'parser', message: '<img src=x onerror=alert(1)>' }],
    report: { result: 'prior evidence <img src=x onerror=alert(1)>' },
    manifest: { source: { commitSha: null }, provenance: 'legacy-import' },
  }];
  await page.route('**/api/**', async route => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    const json = value => route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) });
    if (path === '/api/auth/session') return json({ authenticated, authRequired: true, csrfToken: authenticated ? 'csrf-live' : 'csrf-anon', user: authenticated ? { name: 'Test user', role } : null });
    if (path === '/api/auth/login') { authenticated = true; return json({ authenticated: true }); }
    if (!authenticated) return route.fulfill({ status: 401, contentType: 'application/json', body: '{"error":"Login required"}' });
    if (path === '/api/state') return json(wrap(state));
    if (path === '/api/events') return route.fulfill({ contentType: 'text/event-stream', body: `event: state\ndata: ${JSON.stringify(wrap(state))}\n\n` });
    if (path === '/api/models') return json({ models: [{ id: 'rule-baseline', name: '규칙 기반 · 실제 XSS 실습', provider: 'local', mode: 'local-lab-rule', available: true }, { id: 'deepseek-test', name: 'DeepSeek unavailable', provider: 'deepseek', mode: 'local-lab-deepseek', available: false }] });
    if (path === '/api/platform') return json({ source: { branch: 'develop', commit: 'test-commit' }, modules: [{ name: 'parser <img src=x onerror=alert(1)>', version: '1.0', status: 'verified' }], tests: { passed: 10 }, architecture: { api: 'application -> domain' } });
    if (path === '/api/ci-results') return json({ source: 'public-feed', status: 'fresh', updatedAt: '2026-10-15T01:30:00Z', runs: ciRuns ?? [
      { runId: 102, runAttempt: 1, commitSha: 'b'.repeat(40), branch: 'develop', status: 'failed', completeSuite: true,
        completedAt: '2026-10-15T01:20:00Z', runUrl: 'https://github.com/typemnm/FSL-CA3P/actions/runs/102',
        tests: 12, passed: 11, failed: 1, skipped: 0, changedFromSha: 'a'.repeat(40), changedModules: ['agent', 'xss-parser'],
        pipeline: { tests: 'failure', containerSmoke: 'success', integrationGate: 'failure' },
        jobs: [{ id: 'agent', status: 'failed', tests: 12, passed: 11, failed: 1, skipped: 0 },
          { id: 'xss-parser<img src=x onerror=alert(1)>', status: 'passed', tests: 0, passed: 0, failed: 0, skipped: 0 }] },
      { runId: 101, runAttempt: 1, commitSha: 'a'.repeat(40), branch: 'develop', status: 'passed', completeSuite: true,
        completedAt: '2026-10-14T01:20:00Z', runUrl: 'https://github.com/typemnm/FSL-CA3P/actions/runs/101',
        tests: 10, passed: 10, failed: 0, skipped: 0, changedModules: [],
        pipeline: { tests: 'success', containerSmoke: 'success', integrationGate: 'success' },
        jobs: [{ id: 'agent', status: 'passed', tests: 10, passed: 10, failed: 0, skipped: 0 }] },
    ] });
    if (path === '/api/comparisons') return json({ comparable: false, kind: 'code', baselineRunId: 'baseline', candidateRunId: 'candidate', conditions: [{ name: 'logicalInput', before: 'digest-a', after: 'digest-b', equal: false, available: true }], metrics: { baseline: { elapsedMs: 100, events: 1, modelCalls: 0, promptTokens: 0, tokenUsageAvailable: false }, candidate: { elapsedMs: 120, events: 2, modelCalls: 0, promptTokens: 0, tokenUsageAvailable: false } }, findingTransition: { before: 'not_reproduced', after: '<img src=x onerror=alert(1)>' }, moduleDiffs: [{ module: 'agent', changes: [{ path: '/value', before: 1, after: 2 }] }] });
    if (path === '/api/runs' && request.method() === 'GET') return json({ runs });
    if (path === '/api/runs' && request.method() === 'POST') { mutations.push({ body: request.postDataJSON(), csrf: request.headers()['x-csrf-token'] }); state = snapshot('new-rule', request.postDataJSON().mode); runs.unshift(state); return json(wrap(state)); }
    const review = /^\/api\/runs\/([^/]+)\/reviews\/([^/]+)$/.exec(path);
    if (review && request.method() === 'POST') {
      reviews.push({ body: request.postDataJSON(), csrf: request.headers()['x-csrf-token'] });
      const item = runs.find(row => row.id === review[1]); item.historyWrite.checks[0].review_status = 'reviewed'; item.historyWrite.checks[0].review_note = request.postDataJSON().note;
      return json({ reviewed: true });
    }
    if (path.startsWith('/api/runs/')) { detailCalls += 1; return json({ run: runs.find(item => item.id === path.split('/').pop()) }); }
    return json({});
  });
  t.after(async () => { await browser.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.locator('#login-dialog').waitFor({ state: 'visible' });
  await page.locator('#login-username').fill('test-user'); await page.locator('#login-password').fill('test-password'); await page.locator('#login-submit').click();
  await page.locator('#login-dialog').waitFor({ state: 'hidden' });
  await page.waitForFunction(() => document.querySelector('#connection-status').textContent.includes('연결됨'));
  return { page, mutations, reviews, errors, detailCalls: () => detailCalls };
}

test('authenticated workspace loads central runs, starts a selected rule lab, and safely renders comparisons and platform evidence', async t => {
  const { page, mutations, reviews, errors, detailCalls } = await setup(t);
  await page.waitForFunction(() => document.querySelector('#model-select').value === 'rule-baseline');
  assert.equal(await page.locator('#lab-run-button').isEnabled(), true);
  await page.locator('#lab-run-button').click();
  await page.waitForFunction(() => document.querySelector('#execution-label').textContent === 'REAL LAB / RULE');
  assert.deepEqual(mutations[0], { body: { mode: 'local-lab-rule', modelId: 'rule-baseline' }, csrf: 'csrf-live' });
  await page.locator('#history-review-panel [data-review-note]').fill('Synthetic evidence checked.');
  await page.locator('#history-review-panel [data-review-form] button').click();
  await page.locator('#history-review-panel .review-complete').waitFor();
  assert.deepEqual(reviews[0], { body: { note: 'Synthetic evidence checked.' }, csrf: 'csrf-live' });
  await page.locator('[data-view=sessions]').click(); await page.locator('[data-session=baseline]').click();
  await page.waitForFunction(() => !document.querySelector('#history-banner').hidden); assert.equal(detailCalls(), 2);
  await page.locator('[data-view=compare]').click();
  await page.locator('#baseline-select').selectOption('baseline'); await page.locator('#candidate-select').selectOption('candidate'); await page.locator('#compare-button').click();
  await page.locator('.comparison-summary').waitFor();
  assert.match(await page.locator('#comparison-content').textContent(), /조건 차이 확인 필요/);
  assert.match(await page.locator('.comparison-table').first().textContent(), /logicalInput/);
  assert.match(await page.locator('#comparison-content').textContent(), /미측정/);
  assert.match(await page.locator('#comparison-content').textContent(), /\+20/);
  assert.match(await page.locator('#comparison-content').textContent(), /<img src=x/);
  assert.equal(await page.locator('#comparison-content img').count(), 0);
  await page.locator('[data-view=platform]').click();
  await page.locator('.platform-source').waitFor(); assert.match(await page.locator('#platform-content').textContent(), /test-commit/);
  assert.equal(await page.locator('#platform-content img').count(), 0);
  assert.deepEqual(errors, []);
});

test('develop CI view shows merged-suite failure, changed modules, and previous-run deltas without rendering report HTML', async t => {
  const { page, errors } = await setup(t, 'viewer');
  await page.locator('[data-view=ci]').click();
  await page.locator('.ci-latest').waitFor();
  assert.match(await page.locator('#ci-content').textContent(), /실패/);
  assert.match(await page.locator('#ci-content').textContent(), /12/);
  assert.match(await page.locator('#ci-comparison').textContent(), /xss-parser/);
  assert.match(await page.locator('#ci-comparison').textContent(), /\+1/);
  assert.equal(await page.locator('#ci-content img').count(), 0);
  assert.equal(await page.locator('#ci-comparison img').count(), 0);
  assert.deepEqual(errors, []);
});

test('CI comparison treats same-SHA reruns as no code changes and skips them when finding the previous commit', async t => {
  const a = 'a'.repeat(40); const b = 'b'.repeat(40);
  const ciRuns = [
    { runId: 102, runAttempt: 2, commitSha: b, status: 'failed', tests: 12, passed: 11, failed: 1, skipped: 0,
      changedFromSha: a, changedModules: ['agent'], jobs: [] },
    { runId: 102, runAttempt: 1, commitSha: b, status: 'failed', tests: 12, passed: 11, failed: 1, skipped: 0,
      changedFromSha: a, changedModules: ['agent'], jobs: [] },
    { runId: 101, runAttempt: 1, commitSha: a, status: 'passed', tests: 10, passed: 10, failed: 0, skipped: 0,
      changedModules: null, jobs: [] },
  ];
  const { page, errors } = await setup(t, 'viewer', ciRuns);
  await page.locator('[data-view=ci]').click();
  await page.locator('.ci-latest').waitFor();
  assert.match(await page.locator('#ci-comparison').textContent(), /코드가 바뀐 모듈: 없음/);
  assert.doesNotMatch(await page.locator('#ci-comparison').textContent(), /코드가 바뀐 모듈: agent/);
  await page.locator('#ci-baseline').selectOption('101:1');
  assert.match(await page.locator('#ci-comparison').textContent(), /코드가 바뀐 모듈: agent/);
  await page.locator('#ci-candidate').selectOption('102:1');
  assert.match(await page.locator('#ci-comparison').textContent(), /코드가 바뀐 모듈: agent/);
  assert.deepEqual(errors, []);
});

test('CI comparison does not attribute a diff to a baseline that differs from its recorded source SHA', async t => {
  const ciRuns = [
    { runId: 102, runAttempt: 1, commitSha: 'b'.repeat(40), changedFromSha: 'c'.repeat(40),
      changedModules: ['agent'], jobs: [] },
    { runId: 101, runAttempt: 1, commitSha: 'a'.repeat(40), changedModules: [], jobs: [] },
  ];
  const { page, errors } = await setup(t, 'viewer', ciRuns);
  await page.locator('[data-view=ci]').click();
  await page.locator('.ci-latest').waitFor();
  assert.match(await page.locator('#ci-comparison').textContent(), /이 비교 구간의 변경 경로 정보 없음/);
  assert.doesNotMatch(await page.locator('#ci-comparison').textContent(), /코드가 바뀐 모듈: agent/);
  assert.deepEqual(errors, []);
});

test('CI view distinguishes missing test totals from an actual zero-test result', async t => {
  const ciRuns = [{ runId: 102, runAttempt: 1, commitSha: 'b'.repeat(40), status: 'incomplete', completeSuite: false,
    tests: null, passed: null, failed: null, skipped: null, changedModules: null, jobs: [] }];
  const { page, errors } = await setup(t, 'viewer', ciRuns);
  await page.locator('[data-view=ci]').click();
  await page.locator('.ci-latest').waitFor();
  assert.equal(await page.locator('.ci-totals strong').first().textContent(), '자료 없음');
  assert.match(await page.locator('.ci-verification').textContent(), /전체 suite 보고서가 없어/);
  assert.doesNotMatch(await page.locator('.ci-totals').textContent(), /0/);
  const actual = await setup(t, 'viewer', [{ ...ciRuns[0], runId: 103,
    tests: 0, passed: 0, failed: 0, skipped: 0 }]);
  await actual.page.locator('[data-view=ci]').click();
  await actual.page.locator('.ci-latest').waitFor();
  assert.equal(await actual.page.locator('.ci-totals strong').first().textContent(), '0');
  assert.deepEqual(errors, []);
  assert.deepEqual(actual.errors, []);
});

test('viewer session can inspect evidence while all mutation controls remain disabled', async t => {
  const { page, errors } = await setup(t, 'viewer');
  await page.waitForFunction(() => document.querySelector('#model-select').options.length > 1);
  for (const id of ['run-button', 'lab-run-button', 'new-session-button', 'stop-button', 'model-select']) assert.equal(await page.locator(`#${id}`).isDisabled(), true, id);
  await page.locator('[data-view=sessions]').click(); await page.locator('[data-session=candidate]').click();
  await page.waitForFunction(() => !document.querySelector('#history-banner').hidden);
  assert.match(await page.locator('#user-role').textContent(), /조회 전용/);
  assert.equal(await page.locator('#history-review-panel [data-review-form] button').isDisabled(), true);
  assert.deepEqual(errors, []);
});

test('imported legacy records appear as readable archival reports without executing stored HTML', async t => {
  const { page, errors } = await setup(t);
  await page.locator('[data-view=sessions]').click();
  await page.locator('[data-session=legacy-record]').waitFor();
  await page.locator('[data-session=legacy-record]').click();
  await page.locator('#legacy-detail').waitFor({ state: 'visible' });
  assert.match(await page.locator('#legacy-detail').textContent(), /prior evidence/);
  assert.match(await page.locator('#legacy-detail').textContent(), /입력 조건이 누락될 수/);
  assert.equal(await page.locator('#legacy-detail img').count(), 0);
  assert.deepEqual(errors, []);
});

test('dashboard reads and compares two actual persisted worker runs through the real API', async t => {
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os'); const { join } = await import('node:path');
  const { createRunService } = await import('../../apps/application/run-service.mjs');
  const { createDashboardServer } = await import('../../apps/api/server.mjs');
  const { createAuthentication, hashAccount } = await import('../../apps/api/auth.mjs');
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-ui-e2e-'));
  const service = createRunService({ storePath: join(directory, 'runs.sqlite'), envFile: false, defaultDelayMs: 0 });
  const server = createDashboardServer({ runtime: service, auth: createAuthentication({ users: [hashAccount('ui-operator', 'local-test-password', 'operator')] }) });
  let browser;
  t.after(async () => { await browser?.close(); await server.shutdown(); await rm(directory, { recursive: true, force: true }); });
  const finish = async () => {
    const state = await service.start({ mode: 'core-fixture', target: 'https://metadata-only.invalid', delayMs: 0 });
    const end = Date.now() + 15000;
    while (Date.now() < end) {
      const run = service.getRun(state.run.id);
      if (['completed', 'failed', 'interrupted'].includes(run.status)) { assert.equal(run.status, 'completed', run.error); return run; }
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.fail('Actual fixture worker did not complete');
  };
  const baseline = await finish(); const candidate = await finish();
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  browser = await chromium.launch({ headless: true }); const page = await browser.newPage(); const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.locator('#login-dialog').waitFor({ state: 'visible' });
  await page.locator('#login-username').fill('ui-operator'); await page.locator('#login-password').fill('local-test-password'); await page.locator('#login-submit').click();
  await page.locator('#login-dialog').waitFor({ state: 'hidden' });
  await page.locator('[data-view=sessions]').click();
  await page.locator(`[data-session="${baseline.id}"]`).waitFor();
  await page.locator('[data-view=compare]').click();
  await page.locator('#baseline-select').selectOption(baseline.id); await page.locator('#candidate-select').selectOption(candidate.id); await page.locator('#compare-button').click();
  await page.locator('.comparison-summary').waitFor();
  assert.match(await page.locator('#comparison-content').textContent(), /Finding/);
  assert.match(await page.locator('#comparison-content').textContent(), /실행 지표 차이/);
  assert.match(await page.locator('#comparison-content').textContent(), /동일 조건 비교 가능/);
  assert.deepEqual(errors, []);
});
