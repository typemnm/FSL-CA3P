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
const resetModels = [{ id: 'rule-baseline', name: '규칙 기반', provider: 'local', mode: 'local-lab-rule', available: true },
  { id: 'deepseek-flash', name: 'DeepSeek Flash', provider: 'deepseek', mode: 'local-lab-deepseek', available: true }];
async function setup(t, role = 'operator', ciRuns = null, reportOptions = {}) {
  const server = http.createServer(async (req, res) => {
    try {
      if (req.url === '/api/runs/candidate/report.hwpx') {
        const bytes = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 255]);
        res.writeHead(200, { 'Content-Type': 'application/hwp+zip', 'Content-Length': bytes.length,
          'Content-Disposition': `attachment; filename="report.hwpx"; filename*=UTF-8''${encodeURIComponent('검사 보고서.hwpx')}` });
        return res.end(bytes);
      }
      const filename = new URL(req.url, 'http://test').pathname.split('/').pop() || 'index.html';
      if (!/^[a-z-]+\.(?:html|js|css|svg)$/.test(filename)) { res.writeHead(404); return res.end(); }
      const body = await readFile(new URL(`../dist/${filename}`, import.meta.url));
      const mime = { html: 'text/html', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' };
      res.writeHead(200, { 'Content-Type': mime[filename.split('.').pop()] }); res.end(body);
    } catch { res.writeHead(404); res.end(); }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const browser = await chromium.launch({ headless: true,
    executablePath: process.env.CA3P_PLAYWRIGHT_EXECUTABLE || undefined });
  const page = await browser.newPage(); const errors = []; const mutations = []; const reviews = []; const resets = [];
  page.on('pageerror', error => errors.push(error.message));
  let authenticated = false; let state = reportOptions.state ?? idle; let detailCalls = 0; let resetError = reportOptions.resetError; let serverEpoch = 0;
  const stateEnvelope = () => ({ ...wrap(state), experiment: { epoch: serverEpoch,
    status: reportOptions.experimentStatus ?? 'ready' } });
  const runs = [snapshot('candidate'), snapshot('baseline'), {
    id: 'legacy-record', mode: 'legacy-import', status: 'completed', startedAt: '2026-10-13T10:00:00Z',
    target: null, events: [{ module: 'parser', message: '<img src=x onerror=alert(1)>' }],
    report: { result: 'prior evidence <img src=x onerror=alert(1)>' },
    manifest: { source: { commitSha: null }, provenance: 'legacy-import' },
  }];
  if (reportOptions.document) {
    runs[0] = { ...snapshot('candidate', 'local-lab-rule'), reportDocument: reportOptions.document };
    if (reportOptions.live) state = runs[0];
  }
  await page.route('**/api/**', async route => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    const json = value => route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) });
    if (path === '/api/auth/session') return json({ authenticated, authRequired: true, csrfToken: authenticated ? 'csrf-live' : 'csrf-anon', user: authenticated ? { name: 'Test user', role } : null });
    if (path === '/api/auth/login') { authenticated = true; return json({ authenticated: true }); }
    if (!authenticated) return route.fulfill({ status: 401, contentType: 'application/json', body: '{"error":"Login required"}' });
    if (path === '/api/state') return json(stateEnvelope());
    if (path === '/api/events') return route.fulfill({ contentType: 'text/event-stream', body: `event: state\ndata: ${JSON.stringify(stateEnvelope())}\n\n` });
    if (path === '/api/models') return json({ models: reportOptions.models ?? [{ id: 'rule-baseline', name: '규칙 기반 · 실제 XSS 실습', provider: 'local', mode: 'local-lab-rule', available: true }, { id: 'deepseek-test', name: 'DeepSeek unavailable', provider: 'deepseek', mode: 'local-lab-deepseek', available: false }] });
    if (path === '/api/experiment-reset' && request.method() === 'POST') {
      resets.push({ body: request.postDataJSON(), csrf: request.headers()['x-csrf-token'] });
      if (resetError) return route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ error: resetError }) });
      state = idle; runs.splice(0); serverEpoch += 1;
      return json({ ...stateEnvelope(), experimentReset: { status: 'completed', deletedRuns: 3 } });
    }
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
    if (path === '/api/runs' && request.method() === 'POST') {
      const body = request.postDataJSON();
      mutations.push({ body, csrf: request.headers()['x-csrf-token'] }); state = snapshot('new-rule', body.mode);
      if (body.fixtureId?.startsWith('vul-web2-')) {
        state = { ...state, fixtureId: body.fixtureId, testProfile: 'known_record_idor_read',
          target: body.target || `http://127.0.0.1:${body.fixtureId === 'vul-web2-daehan' ? 4101 : 4102}`,
          report: { fixtureId: body.fixtureId, testProfile: 'known_record_idor_read', finding: { category: 'CWE-639', status: 'not_confirmed' }, evidence: [{ check: 'cross-owner', status: 403 }] },
          reportDocument: { status: 'skipped', errorCode: 'IDOR_DOCUMENT_UNSUPPORTED' },
          reviewItems: [{ id: 'idor-review', title: 'IDOR · 접근 차단 확인', description: '다른 담당자의 레코드 조회가 차단되었습니다.', evidenceId: 'idor-evidence', evidence: 'cross-owner: 403', vulnerabilityConfirmed: false }] };
      }
      runs.unshift(state); return json(wrap(state));
    }
    if (/^\/api\/runs\/[^/]+\/report\.hwpx$/.test(path)) return route.continue();
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
  if (reportOptions.seedEpoch !== undefined) await page.addInitScript(epoch => {
    if (window !== window.top) return;
    localStorage.setItem('ca3p.loop.experiment.epoch.v1', JSON.stringify(epoch));
    localStorage.setItem('ca3p.loop.core.sessions.v1', '[{"previous":"server"}]');
  }, reportOptions.seedEpoch);
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.locator('#login-dialog').waitFor({ state: 'visible' });
  await page.locator('#login-username').fill('test-user'); await page.locator('#login-password').fill('test-password'); await page.locator('#login-submit').click();
  await page.locator('#login-dialog').waitFor({ state: 'hidden' });
  await page.waitForFunction(() => document.querySelector('#connection-status').textContent.includes('연결됨'));
  await page.locator('[data-view=assets]').click();
  await page.locator('#view-assets').waitFor({ state: 'visible' });
  return { page, mutations, reviews, resets, errors, detailCalls: () => detailCalls,
    setResetError(value) { resetError = value; },
    advanceExperiment() { state = idle; runs.splice(0); serverEpoch += 1; },
    setReportDocument(value) { runs[0].reportDocument = value; } };
}

test('model change requires Yes before deleting experimental history and owned browser cache', async t => {
  const { page, resets, errors } = await setup(t, 'operator', null, { models: resetModels });
  await page.evaluate(() => {
    localStorage.setItem('ca3p.loop.core.sessions.v1', '[{"old":"experiment"}]');
    localStorage.setItem('unrelated.preference', 'preserve');
  });
  assert.equal(await page.locator('#model-reset-toggle').isChecked(), true);
  if (process.env.CA3P_UI_PREVIEW) await page.screenshot({ path: process.env.CA3P_UI_PREVIEW.replace(/\.png$/i, '-controls.png') });
  await page.locator('#model-select').selectOption('deepseek-flash');
  await page.locator('#model-reset-dialog').waitFor({ state: 'visible' });
  if (process.env.CA3P_UI_PREVIEW) await page.screenshot({ path: process.env.CA3P_UI_PREVIEW });
  assert.equal(await page.locator('#model-select').inputValue(), 'rule-baseline');
  assert.equal(resets.length, 0);
  assert.match(await page.locator('#model-reset-scope').textContent(), /JSON·HWPX.*먼저 내보내/);
  await page.locator('#model-reset-yes').click();
  await page.locator('#model-reset-dialog').waitFor({ state: 'hidden' });
  assert.equal(await page.locator('#model-select').inputValue(), 'deepseek-flash');
  assert.deepEqual(resets, [{ body: { confirmed: true }, csrf: 'csrf-live' }]);
  assert.equal(await page.evaluate(() => localStorage.getItem('ca3p.loop.core.sessions.v1')), null);
  assert.equal(await page.evaluate(() => localStorage.getItem('unrelated.preference')), 'preserve');
  assert.equal(await page.locator('#model-reset-warning').isVisible(), false);
  await page.locator('[data-view=sessions]').click();
  assert.equal(await page.locator('[data-session]').count(), 0);
  assert.deepEqual(errors, []);
});

test('No and toggle Off switch models without a reset and keep an explicit contamination notice', async t => {
  const { page, resets, errors } = await setup(t, 'operator', null, { models: resetModels });
  await page.locator('#model-select').selectOption('deepseek-flash');
  await page.locator('#model-reset-no').click();
  assert.equal(await page.locator('#model-select').inputValue(), 'deepseek-flash');
  assert.equal(await page.locator('#model-reset-warning').isVisible(), true);
  assert.equal(resets.length, 0);
  await page.locator('#model-reset-toggle').uncheck();
  await page.locator('#model-select').selectOption('rule-baseline');
  assert.equal(await page.locator('#model-reset-dialog').isVisible(), false);
  assert.equal(await page.locator('#model-select').inputValue(), 'rule-baseline');
  assert.equal(resets.length, 0);
  await page.reload();
  await page.waitForFunction(() => document.querySelector('#connection-status').textContent.includes('연결됨'));
  assert.equal(await page.locator('#model-reset-toggle').isChecked(), false);
  assert.deepEqual(errors, []);
});

test('reset failure retains the old model and history until a successful retry; Escape cancels switching', async t => {
  const { page, resets, errors, setResetError } = await setup(t, 'operator', null,
    { models: resetModels, resetError: '관리되는 실습 초기화가 필요합니다.' });
  await page.locator('#model-select').selectOption('deepseek-flash');
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#model-select').inputValue(), 'rule-baseline');
  assert.equal(resets.length, 0);
  await page.locator('#model-select').selectOption('deepseek-flash');
  await page.locator('#model-reset-yes').click();
  await page.locator('#model-reset-error').waitFor({ state: 'visible' });
  assert.match(await page.locator('#model-reset-error').textContent(), /모델은 변경하지 않았습니다/);
  assert.equal(await page.locator('#model-select').inputValue(), 'rule-baseline');
  assert.equal(await page.locator('#model-reset-dialog').isVisible(), true);
  setResetError(null);
  await page.locator('#model-reset-yes').click();
  await page.locator('#model-reset-dialog').waitFor({ state: 'hidden' });
  assert.equal(await page.locator('#model-select').inputValue(), 'deepseek-flash');
  assert.equal(resets.length, 2);
  assert.deepEqual(errors, []);
});

test('failed experiment reset explains that a model-only change cannot unblock attacks', async t => {
  const { page, errors } = await setup(t, 'operator', null, { models: resetModels,
    experimentStatus: 'failed', resetError: 'vul-web2-daehan의 전체 초기화 관리 훅이 설정되지 않았습니다.' });
  await page.locator('#model-select').selectOption('deepseek-flash');
  await page.locator('#model-reset-dialog').waitFor({ state: 'visible' });
  assert.match(await page.locator('#model-reset-note').textContent(), /새 공격 실행은 차단/);
  await page.locator('#model-reset-yes').click();
  await page.locator('#model-reset-error').waitFor({ state: 'visible' });
  const message = await page.locator('#model-reset-error').textContent();
  assert.match(message, /CA3P_EXPERIMENT_RESET_TARGETS/);
  assert.match(message, /새 공격 실행은 전체 초기화가 완료될 때까지 차단/);
  await page.locator('#model-reset-no').click();
  assert.equal(await page.locator('#model-select').inputValue(), 'deepseek-flash');
  assert.equal(await page.locator('#run-button').isDisabled(), true);
  assert.equal(await page.locator('#lab-run-button').isDisabled(), true);
  assert.deepEqual(errors, []);
});

test('an active run keeps model selection disabled', async t => {
  const { page, resets, errors } = await setup(t, 'operator', null,
    { models: resetModels, state: { ...snapshot('active', 'local-lab-rule'), status: 'running' } });
  assert.equal(await page.locator('#model-select').isDisabled(), true);
  assert.equal(resets.length, 0);
  assert.deepEqual(errors, []);
});

test('manual experiment reset works with a single model and an epoch change clears another client cache', async t => {
  const { page, resets, errors, advanceExperiment } = await setup(t);
  await page.locator('#experiment-reset-button').click();
  await page.locator('#model-reset-no').click();
  assert.equal(resets.length, 0);
  await page.locator('#experiment-reset-button').click();
  await page.locator('#model-reset-yes').click();
  await page.locator('#model-reset-dialog').waitFor({ state: 'hidden' });
  assert.equal(await page.locator('#model-select').inputValue(), 'rule-baseline');
  assert.equal(resets.length, 1);
  await page.evaluate(() => localStorage.setItem('ca3p.loop.core.sessions.v1', '[{"old":"another-client"}]'));
  advanceExperiment();
  await page.waitForFunction(() => localStorage.getItem('ca3p.loop.core.sessions.v1') === null);
  assert.equal(resets.length, 1);
  assert.deepEqual(errors, []);
});

test('browser cache deletion failure blocks model switching and execution after the server reset', async t => {
  const { page, resets, errors } = await setup(t, 'operator', null, { models: resetModels });
  await page.evaluate(() => {
    const remove = Storage.prototype.removeItem;
    Storage.prototype.removeItem = function(key) {
      if (key === 'ca3p.loop.core.sessions.v1') throw new DOMException('Storage blocked', 'SecurityError');
      return remove.call(this, key);
    };
  });
  await page.locator('#model-select').selectOption('deepseek-flash');
  await page.locator('#model-reset-yes').click();
  await page.locator('#model-reset-error').waitFor({ state: 'visible' });
  assert.equal(resets.length, 1);
  assert.equal(await page.locator('#model-select').inputValue(), 'rule-baseline');
  assert.match(await page.locator('#model-reset-error').textContent(), /브라우저의 실행 캐시/);
  assert.equal(await page.locator('#run-button').isDisabled(), true);
  assert.equal(await page.locator('#lab-run-button').isDisabled(), true);
  assert.deepEqual(errors, []);
});

test('an IDOR fixture engine switch uses the same confirmation and keeps both selections on cancellation or failure', async t => {
  const { page, resets, errors, setResetError } = await setup(t, 'operator', null, { models: resetModels });
  await page.locator('#model-reset-toggle').uncheck();
  await page.locator('#model-select').selectOption('deepseek-flash');
  await page.locator('#model-reset-toggle').check();
  await page.locator('#fixture-select').selectOption('vul-web2-daehan');
  await page.locator('#model-reset-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#fixture-select').inputValue(), 'vul-web-1');
  assert.equal(await page.locator('#model-select').inputValue(), 'deepseek-flash');
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#fixture-select').inputValue(), 'vul-web-1');
  await page.locator('#fixture-select').selectOption('vul-web2-daehan');
  setResetError('관리 초기화 미설정');
  await page.locator('#model-reset-yes').click();
  await page.locator('#model-reset-error').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#fixture-select').inputValue(), 'vul-web-1');
  assert.equal(await page.locator('#model-select').inputValue(), 'deepseek-flash');
  await page.locator('#model-reset-no').click();
  assert.equal(await page.locator('#fixture-select').inputValue(), 'vul-web2-daehan');
  assert.equal(await page.locator('#model-select').inputValue(), 'rule-baseline');
  assert.equal(await page.locator('#model-reset-warning').isVisible(), true);
  assert.equal(resets.length, 1);
  assert.deepEqual(errors, []);
});

test('the first server handshake replaces a larger cached epoch after changing to a fresh database', async t => {
  const { page, errors } = await setup(t, 'operator', null, { models: resetModels, seedEpoch: 5 });
  await page.waitForFunction(() => localStorage.getItem('ca3p.loop.experiment.epoch.v1') === '0');
  assert.equal(await page.evaluate(() => localStorage.getItem('ca3p.loop.core.sessions.v1')), null);
  await page.waitForFunction(() => document.querySelector('#model-select').value === 'rule-baseline');
  assert.equal(await page.locator('#experiment-reset-button').isEnabled(), true);
  assert.deepEqual(errors, []);
});

test('a viewer downloads the saved HWPX after reopening central history and reloading', async t => {
  const { page, errors } = await setup(t, 'viewer', null, { document: { status: 'ready', artifactId: 'a'.repeat(64), filename: '검사 보고서.hwpx' } });
  await page.reload();
  await page.locator('[data-view=sessions]').click();
  await page.locator('[data-session=candidate]').click();
  await page.locator('#history-banner').waitFor({ state: 'visible' });
  await page.locator('[data-view=reports]').click();
  const link = page.locator('#report-download-button');
  await link.waitFor(); assert.equal(await link.getAttribute('href'), '/api/runs/candidate/report.hwpx');
  assert.match(await page.locator('#report-document-status').textContent(), /준비됨/);
  const downloading = page.waitForEvent('download'); await link.click();
  const download = await downloading;
  assert.equal(download.suggestedFilename(), '검사 보고서.hwpx');
  assert.equal(await download.failure(), null);
  assert.deepEqual(await readFile(await download.path()), Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 255]));
  assert.deepEqual(errors, []);
});

test('live report progress becomes downloadable, and failed or unconfigured reports stay disabled', async t => {
  const { page, errors, setReportDocument } = await setup(t, 'viewer', null, { live: true, document: { status: 'generating' } });
  await page.locator('[data-view=reports]').click();
  await page.waitForFunction(() => document.querySelector('#report-document-status').textContent.includes('생성 중'));
  assert.equal(await page.locator('#report-download-button').isDisabled(), true);
  for (const [status, label] of [['failed', '생성 실패'], ['unavailable', '설정 필요']]) {
    setReportDocument({ status, message: '<img src=x onerror=alert(1)>' });
    await page.waitForFunction(text => document.querySelector('#report-document-status').textContent.includes(text), label);
    assert.equal(await page.locator('#report-download-button').isDisabled(), true);
    assert.equal(await page.locator('.report-document img').count(), 0);
  }
  setReportDocument({ status: 'ready', artifactId: 'b'.repeat(64), filename: '완료.hwpx' });
  await page.waitForFunction(() => document.querySelector('#report-download-button').tagName === 'A');
  assert.equal(await page.locator('#report-download-button').getAttribute('href'), '/api/runs/candidate/report.hwpx');
  assert.deepEqual(errors, []);
});

test('fixture reports skip model generation while JSON export remains available', async t => {
  const { page } = await setup(t);
  await page.locator('[data-view=sessions]').click(); await page.locator('[data-session=candidate]').click();
  await page.locator('#history-banner').waitFor({ state: 'visible' });
  await page.locator('[data-view=reports]').click();
  assert.match(await page.locator('#report-document-status').textContent(), /보고서 생성 생략/);
  assert.equal(await page.locator('#report-download-button').isDisabled(), true);
  assert.equal(await page.locator('#export-button').isEnabled(), true);
});

test('authenticated workspace loads central runs, starts a selected rule lab, and safely renders comparisons and platform evidence', async t => {
  const { page, mutations, reviews, errors, detailCalls } = await setup(t);
  await page.waitForFunction(() => document.querySelector('#model-select').value === 'rule-baseline');
  assert.equal(await page.locator('#lab-run-button').isEnabled(), true);
  await page.locator('#lab-run-button').click();
  await page.locator('#view-dashboard').waitFor({ state: 'visible' });
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

test('vul-web2 site selection forwards its private origin to the rule IDOR lab and reopens evidence without XSS report claims', async t => {
  const { page, mutations, errors } = await setup(t);
  await page.locator('#fixture-select').selectOption('vul-web2-daehan');
  assert.match(await page.locator('#lab-title').textContent(), /vul-web2 대한대학교/);
  assert.doesNotMatch(await page.locator('#lab-title').textContent(), /XSS|IDOR/);
  assert.match(await page.locator('#lab-check-scope').textContent(), /IDOR 읽기 권한 비교만/);
  assert.match(await page.locator('#lab-run-label').textContent(), /IDOR 읽기 검사 시작/);
  assert.equal(await page.locator('#lab-target-origin').inputValue(), 'http://127.0.0.1:4101');
  assert.match(await page.locator('#lab-description').textContent(), /Compose/);
  assert.equal(await page.locator('#model-select').isDisabled(), true);
  assert.equal(await page.locator('#model-select').inputValue(), 'rule-baseline');
  assert.match(await page.locator('#model-scope').textContent(), /모델을 호출하지 않습니다/);
  await page.locator('#fixture-select').selectOption('vul-web2-wonchang');
  assert.equal(await page.locator('#lab-target-origin').inputValue(), 'http://127.0.0.1:4102');
  await page.locator('#lab-target-origin').fill('192.168.0.84:4102');
  if (process.env.CA3P_UI_SCREENSHOT_PATH) {
    await page.setViewportSize({ width: 1440, height: 1100 });
    await page.screenshot({ path: process.env.CA3P_UI_SCREENSHOT_PATH });
  }
  await page.locator('#lab-run-button').click();
  await page.locator('#view-dashboard').waitFor({ state: 'visible' });
  await page.waitForFunction(() => document.querySelector('#execution-label').textContent === 'REAL LAB / IDOR');
  assert.deepEqual(mutations[0], { body: { mode: 'local-lab-rule', modelId: 'rule-baseline', fixtureId: 'vul-web2-wonchang', target: 'http://192.168.0.84:4102' }, csrf: 'csrf-live' });
  assert.match(await page.locator('#run-context').textContent(), /원창대학교 IDOR/);
  await page.locator('[data-view=sessions]').click();
  assert.match(await page.locator('#session-list').textContent(), /원창대학교 IDOR 실습/);
  await page.locator('[data-session=new-rule]').click();
  await page.locator('#history-banner').waitFor({ state: 'visible' });
  await page.locator('[data-view=reports]').click();
  assert.match(await page.locator('#report-content').textContent(), /원창대학교 IDOR 실행 결과/);
  assert.match(await page.locator('#report-content').textContent(), /cross-owner: 403/);
  assert.match(await page.locator('.report-note').textContent(), /자율 CERT 조사 결과를 뜻하지 않습니다/);
  assert.doesNotMatch(await page.locator('.report-note').textContent(), /삭제 권한|XSS/);
  assert.match(await page.locator('.report-document').textContent(), /HWPX 보고서는 아직 지원하지 않습니다/);
  assert.doesNotMatch(await page.locator('.report-document').textContent(), /과금/);
  assert.equal(await page.locator('#report-download-button').isDisabled(), true);
  assert.equal(await page.locator('#export-button').isEnabled(), true);
  await page.locator('[data-view=assets]').click();
  await page.locator('#fixture-select').selectOption('vul-web-1');
  assert.equal(await page.locator('#model-select').isEnabled(), true);
  assert.match(await page.locator('#lab-title').textContent(), /vul-web-1 로컬 게시판/);
  assert.doesNotMatch(await page.locator('#lab-title').textContent(), /XSS|IDOR/);
  assert.match(await page.locator('#lab-check-scope').textContent(), /저장형 XSS canary 1회/);
  assert.match(await page.locator('#lab-run-label').textContent(), /저장형 XSS 검사 시작/);
  assert.equal(await page.locator('#lab-target-control').isHidden(), true);
  assert.deepEqual(errors, []);
});

test('IDOR launch rejects paths and credentials before submitting a run', async t => {
  const { page, mutations, errors } = await setup(t);
  await page.locator('#fixture-select').selectOption('vul-web2-daehan');
  for (const origin of ['http://127.0.0.1:4101/private', 'http://user:password@127.0.0.1:4101', 'https://127.0.0.1:4101']) {
    await page.locator('#lab-target-origin').fill(origin);
    await page.locator('#lab-run-button').click();
    assert.equal(await page.locator('#lab-target-origin').getAttribute('aria-invalid'), 'true');
    assert.match(await page.locator('#runtime-error').textContent(), /HTTP 원점/);
  }
  assert.equal(mutations.length, 0);
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
  for (const id of ['run-button', 'lab-run-button', 'new-session-button', 'stop-button', 'model-select', 'fixture-select']) assert.equal(await page.locator(`#${id}`).isDisabled(), true, id);
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
  browser = await chromium.launch({ headless: true,
    executablePath: process.env.CA3P_PLAYWRIGHT_EXECUTABLE || undefined });
  const page = await browser.newPage(); const errors = [];
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
