import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';

// Dashboard UI verification uses the report capture browser installation,
// independently of the deferred xss-parser integration.
const { chromium } = createRequire(new URL('../../packages/report/capture/package.json', import.meta.url))('playwright');

const report = {
  schemaVersion: 'general-assessment/1', assessmentMode: 'general', status: 'completed',
  target: { fixtureId: 'vul-web2-daehan', origin: 'http://127.0.0.1:4101' }, iterations: 2, stopReason: 'observer_unavailable',
  hypotheses: [{ id: 'h1', category: 'access_control', asset: '/records/1', status: 'confirmed' },
    { id: 'h2', category: 'xss', asset: '/posts', status: 'not_tested', reason: 'observer_unavailable' }],
  probes: [{ id: 'p1', hypothesisId: 'h1', tool: 'http', status: 'completed', evidenceIds: ['e1'] }],
  evidence: [{ id: 'e1', source: 'http-response', summary: 'owner mismatch observed' }],
  findings: [{ id: 'f1', hypothesisId: 'h1', category: 'access_control', asset: '/records/1', status: 'confirmed', evidenceIds: ['e1'], rationale: 'role comparison' },
    { id: 'f2', hypothesisId: 'h2', category: '<script>alert(1)</script>', asset: '/posts', status: 'not_tested', evidenceIds: [], reason: 'observer_unavailable' }],
  coverage: { totalHypotheses: 2, confirmed: 1, notReproduced: 0, inconclusive: 0, notTested: 1 },
  modelCalls: [{ requestedModel: 'deepseek-test', usage: { prompt_tokens: 8, completion_tokens: 4 } }],
};
const run = { id: 'general-run', mode: 'local-lab-general', assessmentMode: 'general', status: 'completed',
  target: 'http://127.0.0.1:4101', startedAt: '2026-10-26T00:00:00Z', elapsedMs: 4100,
  events: [{ stage: 'inventory.collect', title: 'Inventory', module: 'agent', time: '2026-10-26T00:00:00Z' },
    { stage: 'probe.verify', title: 'Verify', module: 'agent', time: '2026-10-26T00:00:01Z' },
    { stage: 'probe.observe', title: 'Untrusted channel', module: 'x"><img src=x onerror=alert(1)>', time: '2026-10-26T00:00:02Z' },
    { stage: 'probe.observe', title: 'Prototype-like channel', module: 'constructor', time: '2026-10-26T00:00:03Z' }],
  reportDocument: { status: 'skipped', errorCode: 'GENERAL_DOCUMENT_UNSUPPORTED' }, report };

test('general run renders and supported targets launch the bounded model assessment', async t => {
  let browser;
  t.after(async () => { await browser?.close(); });
  const localChrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  browser = await chromium.launch({ headless: true,
    ...(process.platform === 'win32' && !existsSync(chromium.executablePath()) && existsSync(localChrome)
      ? { executablePath: localChrome } : {}) });
  const page = await browser.newPage();
  const errors = []; const posts = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => { window.EventSource = undefined; });
  await page.route('**/*', async route => {
    try {
      const file = new URL(route.request().url()).pathname.split('/').pop() || 'index.html';
      if (!/^[a-z-]+\.(?:html|js|css|svg)$/.test(file)) return route.fulfill({ status: 404, body: '' });
      const bytes = await readFile(new URL(`../dist/${file}`, import.meta.url));
      return route.fulfill({ contentType: ({ html: 'text/html', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' })[file.split('.').pop()], body: bytes });
    } catch { return route.fulfill({ status: 404, body: '' }); }
  });
  await page.route('**/api/**', async route => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    const json = value => route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) });
    if (request.method() === 'POST') posts.push({ path, body: request.postDataJSON() });
    if (path === '/api/auth/session') return json({ authenticated: true, authRequired: false, user: { role: 'operator', name: 'Test' } });
    if (path === '/api/state') return json({ instanceId: 'general-ui-test', mode: run.mode, run,
      lab: { available: true, generalSupported: true, generalAvailable: true } });
    if (path === '/api/runs' && request.method() === 'POST') return json({ instanceId: 'general-ui-test', mode: run.mode, run,
      lab: { available: true, generalSupported: true, generalAvailable: true } });
    if (path === '/api/runs' && request.method() === 'GET') return json({ runs: [run], total: 1 });
    if (path === '/api/models') return json({ models: [
      { id: 'rule-baseline', name: 'Rule baseline', provider: 'local', mode: 'local-lab-rule', available: true },
      { id: 'deepseek-test', name: 'DeepSeek test', provider: 'deepseek', mode: 'local-lab-deepseek', available: true },
    ] });
    if (path === '/api/platform') return json({ source: {}, modules: [] });
    if (path === '/api/ci-results') return json({ runs: [] });
    if (path === '/api/runs/general-run') return json({ run });
    return json({});
  });
  await page.goto('http://ca3p.invalid/#dashboard');
  await page.waitForFunction(() => document.querySelector('#execution-label')?.textContent === 'GENERAL / EVIDENCE');
  assert.equal(await page.locator('#loop-graph').isHidden(), true);
  assert.equal(await page.locator('#general-run-summary').isVisible(), true);
  assert.equal(await page.locator('.general-loop-phase.is-observed').count(), 2);
  assert.equal(await page.locator('#general-live-results-panel').isVisible(), true);
  assert.equal(await page.locator('#general-live-results-panel').evaluate(
    element => element.previousElementSibling?.classList.contains('activity-panel')), true);
  assert.match(await page.locator('#general-live-results-panel').textContent(), /owner mismatch observed/);
  await page.locator('.general-loop-phase.is-observed').first().click();
  assert.match(await page.locator('#trace-code').textContent(), /probe.observe/);
  assert.match(await page.locator('#progress-number').textContent(), /4 events · 검사 1건/);
  assert.equal(await page.locator('.progress-track').isHidden(), true);
  assert.match(await page.locator('#general-run-summary').textContent(), /전체 취약점에 대한 완료율이 아닙니다/);
  await page.locator('[data-view=modules]').click();
  assert.equal(await page.locator('#module-grid img').count(), 0);
  assert.match(await page.locator('#module-grid').textContent(), /constructor/);
  await page.locator('[data-view=reports]').click();
  assert.match(await page.locator('#report-content').textContent(), /owner mismatch observed/);
  assert.match(await page.locator('#report-content').textContent(), /observer_unavailable/);
  assert.match(await page.locator('#report-content').textContent(), /모델 호출 1건/);
  assert.equal(await page.locator('#report-content script').count(), 0);
  assert.match(await page.locator('#report-content').textContent(), /미점검과 판정 불가는 안전하다는 뜻이 아닙니다/);
  assert.match(await page.locator('#report-document-status').textContent(), /범용 HWPX 미지원/);
  assert.match(await page.locator('.report-document').textContent(), /화면의 가설별 결과와 JSON 내보내기/);
  assert.equal(await page.locator('#report-download-button').isDisabled(), true);
  await page.locator('[data-view=sessions]').click();
  await page.locator('[data-session=general-run]').click();
  await page.locator('[data-view=reports]').click();
  assert.match(await page.locator('#report-content').textContent(), /owner mismatch observed/);
  assert.equal(await page.locator('#history-banner').isVisible(), true);
  await page.locator('[data-view=dashboard]').click();
  assert.equal(await page.locator('#fixture-select option').allTextContents().then(values => values.some(value => /XSS|IDOR/.test(value))), false);
  assert.equal(await page.locator('#assessment-mode').inputValue(), 'general');
  assert.match(await page.locator('#lab-title').textContent(), /vul-web-1 로컬 게시판/);
  assert.doesNotMatch(await page.locator('#lab-title').textContent(), /XSS|IDOR/);
  assert.match(await page.locator('#lab-check-scope').textContent(), /유형을 미리 한정하지 않고/);
  assert.match(await page.locator('#lab-run-label').textContent(), /범용 취약점 점검 시작/);
  await page.locator('#fixture-select').selectOption('vul-web2-daehan');
  assert.match(await page.locator('#lab-title').textContent(), /vul-web2 대한대학교/);
  assert.doesNotMatch(await page.locator('#lab-title').textContent(), /XSS|IDOR/);
  assert.equal(await page.locator('#model-select').isEnabled(), true);
  assert.equal(await page.locator('#model-select').inputValue(), 'deepseek-test');
  const launch = page.waitForResponse(response => response.url().endsWith('/api/runs') && response.request().method() === 'POST');
  await page.locator('#lab-run-button').click();
  await launch;
  assert.deepEqual(posts.at(-1), { path: '/api/runs', body: { mode: 'local-lab-general', modelId: 'deepseek-test',
    fixtureId: 'vul-web2-daehan', target: 'http://127.0.0.1:4101' } });
  await page.locator('#assessment-mode').selectOption('legacy');
  await page.locator('#model-reset-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#assessment-mode').inputValue(), 'general');
  assert.equal(await page.locator('#model-select').inputValue(), 'deepseek-test');
  await page.locator('#model-reset-no').click();
  assert.match(await page.locator('#lab-check-scope').textContent(), /IDOR 읽기 권한 비교만/);
  assert.match(await page.locator('#lab-run-label').textContent(), /IDOR 읽기 검사 시작/);
  assert.equal(await page.locator('#model-select').isDisabled(), true);
  assert.equal(await page.locator('#model-select').inputValue(), 'rule-baseline');
  await page.locator('#assessment-mode').selectOption('general');
  await page.locator('#model-reset-dialog').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#assessment-mode').inputValue(), 'legacy');
  await page.locator('#model-reset-no').click();
  assert.equal(await page.locator('#assessment-mode').inputValue(), 'general');
  assert.equal(await page.locator('#model-select').inputValue(), 'deepseek-test');
  assert.equal(posts.length, 1);

  const originalEvents = run.events;
  run.status = 'running'; run.report = null; run.iterations = 1;
  run.events = [
    { id: 'observed', stage: 'observe', iteration: 1, title: 'Observed', module: 'agent',
      response: { evidenceSummaries: [{ id: 'e-observed', kind: 'status-metadata', asset: '/search' }] },
      time: '2026-10-26T00:00:00Z' },
    { id: 'planned', stage: 'plan', iteration: 1, title: 'Planned', module: 'agent',
      request: { hypothesisSummaries: [{ id: 'h1', category: 'access_control', asset: '/api/item/:id' }],
        probeLinks: [{ probeId: 'p1', hypothesisId: 'h1', tool: 'known_record_idor_read' }] },
      response: { progress: { hypothesisCount: 1, probeCount: 0, evidenceCount: 1,
        confirmedProbeCount: 0, blockedProbeCount: 0, remainingProbeBudget: 3 } },
      time: '2026-10-26T00:00:00Z' },
    { id: 'allowed', stage: 'policy', iteration: 1, title: 'Policy allowed', detail: 'allowed',
      request: { probeId: 'p1', hypothesisId: 'h1', tool: 'known_record_idor_read' },
      response: { status: 'allowed', progress: { hypothesisCount: 1, probeCount: 1,
        evidenceCount: 1, confirmedProbeCount: 0, blockedProbeCount: 0, remainingProbeBudget: 2 } },
      module: 'agent', time: '2026-10-26T00:00:01Z' },
    { id: 'executed', stage: 'execute', iteration: 1, title: 'Execute', module: 'agent',
      response: { evidenceSummaries: [{ id: 'e1', kind: 'role-comparison', asset: '/api/item/:id' }] },
      time: '2026-10-26T00:00:02Z' },
    { id: 'verified', stage: 'verify', iteration: 1, title: 'Verify', detail: 'confirmed',
      request: { probeId: 'p1', hypothesisId: 'h1', tool: 'known_record_idor_read' },
      response: { status: 'confirmed', evidenceIds: ['e1'], progress: { hypothesisCount: 1,
        probeCount: 1, evidenceCount: 2, confirmedProbeCount: 1, blockedProbeCount: 0,
        remainingProbeBudget: 2 } }, module: 'agent', time: '2026-10-26T00:00:02Z' },
  ];
  await page.reload();
  await page.waitForFunction(() => document.querySelector('#execution-label')?.textContent === 'GENERAL / EVIDENCE');
  assert.match(await page.locator('#progress-label').textContent(), /결과 대기/);
  assert.match(await page.locator('#progress-number').textContent(), /기록된 검사 ID 1개/);
  assert.match(await page.locator('#general-live-results-panel').textContent(), /검사 p1/);
  assert.match(await page.locator('#general-run-summary').textContent(), /실행 검사 1/);
  assert.match(await page.locator('#general-live-results-panel').textContent(), /가설 h1 · 도구 known_record_idor_read/);
  assert.match(await page.locator('#general-live-results-panel').textContent(), /가설 내용: access_control · \/api\/item\/:id/);
  assert.match(await page.locator('#general-live-results-panel').textContent(), /증거 ID: e1/);
  assert.match(await page.locator('#general-live-results-panel').textContent(), /증거 e1: role-comparison · \/api\/item\/:id/);
  assert.match(await page.locator('#general-live-results-panel').textContent(), /확정 판정 검사 1/);
  assert.match(await page.locator('#general-live-results-panel').textContent(), /최종 보고서 전의 검사 이벤트/);
  assert.doesNotMatch(await page.locator('#general-live-results-panel').textContent(), /\/records\/1/);
  await page.locator('[data-general-event=verified]').click();
  assert.match(await page.locator('#trace-code').textContent(), /"stage": "verify"/);
  assert.match(await page.locator('#trace-code').textContent(), /"probeId": "p1"/);
  run.status = 'completed'; run.report = report; run.reportDocument = undefined;
  run.iterations = 2; run.events = originalEvents;
  await page.reload();
  await page.waitForFunction(() => document.querySelector('#execution-label')?.textContent === 'GENERAL / EVIDENCE');
  assert.match(await page.locator('#general-live-results-panel').textContent(), /owner mismatch observed/);
  await page.locator('[data-view=reports]').click();
  assert.match(await page.locator('#report-document-status').textContent(), /저장된 HWPX 보고서 없음/);
  assert.match(await page.locator('.report-document').textContent(), /화면의 가설별 결과와 JSON 내보내기/);
  assert.equal(await page.locator('#report-download-button').isDisabled(), true);
  assert.deepEqual(errors, []);
});
