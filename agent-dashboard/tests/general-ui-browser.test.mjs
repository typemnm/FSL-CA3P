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
  parserPreview: { pages: [{ url: 'http://127.0.0.1:4101/about', status: 200, contentType: 'text/html',
    title: '소개', mode: 'browser', technologies: [{ name: 'Bootstrap', version: '5' }],
    libraries: [{ name: 'jQuery', version: '3' }], forms: [{ method: 'GET', action: '/search', fields: [{ name: 'q', type: 'text' }] }],
    paths: [{ url: 'http://127.0.0.1:4101/search' }], errors: [{ code: '<img src=x onerror=alert(1)>' }], truncated: true }] },
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
  let stateUnavailable = false;
  let delayNextPreview = false;
  let previewBusyOnce = false;
  let delayedPreviewRelease;
  let delayedPreviewStarted;
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
    if (path === '/api/state') {
      if (stateUnavailable) return route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"Temporary state outage"}' });
      return json({ instanceId: 'general-ui-test', mode: run.mode, run,
        lab: { available: true, generalSupported: true, generalAvailable: true } });
    }
    if (path === '/api/runs/general-run/stop' && request.method() === 'POST') {
      run.status = 'stopped';
      return json({ instanceId: 'general-ui-test', mode: run.mode, run,
        lab: { available: true, generalSupported: true, generalAvailable: true } });
    }
    if (path === '/api/runs' && request.method() === 'POST') return json({ instanceId: 'general-ui-test', mode: run.mode, run,
      lab: { available: true, generalSupported: true, generalAvailable: true } });
    if (path === '/api/targets/preview' && request.method() === 'POST') {
      if (previewBusyOnce) {
        previewBusyOnce = false;
        return route.fulfill({ status: 429, contentType: 'application/json',
          body: JSON.stringify({ code: 'PREVIEW_BUSY', error: 'Previous preview is still stopping.' }) });
      }
      if (delayNextPreview) {
        delayNextPreview = false;
        await new Promise(resolve => { delayedPreviewRelease = resolve; delayedPreviewStarted?.(); });
      }
      try { return await json({ previewId: 'preview-ui', targetKind: 'lab', fixtureId: 'vul-web2-daehan',
        origin: 'http://127.0.0.1:4101', entryUrl: 'http://127.0.0.1:4101/', expiresAt: '2099-01-01T00:00:00Z',
        pages: [{ url: 'http://127.0.0.1:4101/', status: 200, contentType: 'text/html', title: '대한대학교',
          technologies: [{ name: 'Bootstrap', version: '5' }], libraries: [{ name: 'jQuery', version: '3' }],
          forms: [], paths: [{ url: 'http://127.0.0.1:4101/about', sources: ['link'] }], errors: [], truncated: false, mode: 'browser' },
          { url: 'http://127.0.0.1:4101/about', status: 200, contentType: 'text/html', title: '소개',
            technologies: [{ name: 'Vue' }], libraries: [], forms: [], paths: [], errors: [], truncated: false, mode: 'browser' },
          { url: 'http://127.0.0.1:4101/unavailable', status: null, contentType: null, title: null,
            technologies: [], libraries: [], forms: [], paths: [], errors: [{ code: 'PARSER_TIMEOUT' }], truncated: false, mode: 'browser' }],
        discoveredPaths: ['http://127.0.0.1:4101/about', 'http://127.0.0.1:4101/unavailable'],
        crawl: { maxPages: 48, visited: 3, queued: 2, truncated: true, stopReason: 'page-limit' } }); }
      catch { return; } // The delayed response may be cancelled by editing the start URL.
    }
    if (path === '/api/runs' && request.method() === 'GET') return json({ runs: [run], total: 1 });
    if (path === '/api/models') return json({ models: [
      { id: 'rule-baseline', name: 'Rule baseline', provider: 'local', mode: 'local-lab-rule', available: true },
      { id: 'deepseek-test', name: 'DeepSeek test', provider: 'deepseek', mode: 'local-lab-general', available: true },
    ] });
    if (path === '/api/platform') return json({ source: {}, modules: [] });
    if (path === '/api/ci-results') return json({ runs: [] });
    if (path === '/api/runs/general-run') return json({ run });
    return json({});
  });
  await page.goto('http://ca3p.invalid/#dashboard');
  await page.waitForFunction(() => document.querySelector('#execution-label')?.textContent === 'GENERAL / EVIDENCE');
  assert.equal(await page.locator('.loop-panel, #loop-graph, #general-run-summary, .general-loop').count(), 0);
  assert.equal(await page.locator('#general-live-results-panel').count(), 0);
  assert.equal(await page.locator('#view-dashboard .activity-panel').count(), 0);
  assert.equal(await page.locator('#view-dashboard .stat-card').count(), 0);
  await page.locator('#trace-event-select').selectOption('general-run:general-event:4');
  assert.match(await page.locator('#trace-code').textContent(), /probe.observe/);
  assert.match(await page.locator('#progress-number').textContent(), /4 events · 검사 1건/);
  assert.equal(await page.locator('.progress-track, #pause-button').count(), 0);
  await page.locator('[data-view=modules]').click();
  assert.equal(await page.locator('#module-grid img').count(), 0);
  assert.match(await page.locator('#module-grid').textContent(), /constructor/);
  await page.locator('[data-view=reports]').click();
  assert.match(await page.locator('#report-content').textContent(), /owner mismatch observed/);
  assert.match(await page.locator('#report-content').textContent(), /observer_unavailable/);
  assert.match(await page.locator('#report-content').textContent(), /모델 호출 1건/);
  assert.match(await page.locator('.parser-saved-preview').textContent(), /Bootstrap 5.*jQuery 3.*GET \/search.*\/search.*부분 결과/s);
  assert.equal(await page.locator('.parser-saved-preview img').count(), 0);
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
  await page.locator('[data-view=assets]').click();
  assert.equal(await page.locator('#view-assets').isVisible(), true);
  assert.match(await page.locator('#page-subtitle').textContent(), /URL을 파싱하고 경로별 결과를 확인한 뒤 판단 엔진을 선택해 진단을 시작합니다/);
  assert.match(await page.locator('#view-assets .external-scope-note').textContent(), /진행 상황은 공격 탭에 표시됩니다/);
  assert.equal(await page.locator('#engine-step').isHidden(), true);
  assert.equal(await page.locator('#model-select').isVisible(), false);
  assert.equal(await page.locator('#assessment-mode, #asset-mock-run, #target-form').count(), 0);
  assert.equal(await page.locator('#fixture-select').count(), 0);
  await page.locator('#start-url').fill('http://127.0.0.1:4101/');
  const delayedStart = new Promise(resolve => { delayedPreviewStarted = resolve; });
  delayNextPreview = true;
  await page.locator('#parse-start-button').click();
  await delayedStart;
  const cancellationState = await page.evaluate(() => {
    const input = document.querySelector('#start-url');
    input.value = 'http://127.0.0.1:4102/';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return { disabled: document.querySelector('#parse-start-button').disabled,
      status: document.querySelector('#target-preview-status').textContent };
  });
  assert.equal(cancellationState.disabled, true);
  assert.match(cancellationState.status, /중단하는 중/);
  delayedPreviewRelease();
  await page.waitForFunction(() => !document.querySelector('#parse-start-button').disabled);
  assert.equal(await page.locator('#target-preview-paths button').count(), 0);
  await page.locator('#start-url').fill('http://127.0.0.1:4101/');
  await page.locator('#parse-start-button').click();
  await page.locator('#target-preview-pages .parser-preview-card').first().waitFor();
  assert.match(await page.locator('#target-preview-pages .parser-preview-card').first().textContent(), /대한대학교.*Bootstrap 5.*jQuery 3/s);
  assert.equal(await page.locator('#target-preview-paths button').count(), 3);
  assert.match(await page.locator('#target-preview-coverage').textContent(), /등록 대학 · 브라우저 관찰.*방문 3개.*최대 48개 URL.*부분 수집.*미수집 후보 2개/);
  assert.equal(await page.locator('#engine-step').isVisible(), true);
  await page.locator('[data-preview-page-index="1"]').click();
  assert.equal(await page.locator('#target-preview-pages .parser-preview-card').count(), 1);
  assert.match(await page.locator('#target-preview-pages .parser-preview-card').textContent(), /소개.*Vue/s);
  await page.locator('[data-preview-page-index="2"]').click();
  assert.match(await page.locator('#target-preview-pages .parser-preview-card').textContent(), /PARSER_TIMEOUT/);
  assert.equal(posts.filter(item => item.path === '/api/targets/preview').length, 2);
  await page.locator('#start-url').fill('http://127.0.0.1:4102/');
  assert.equal(await page.locator('#engine-step').isHidden(), true);
  assert.equal(await page.locator('#target-preview-pages .parser-preview-card').count(), 0);
  await page.locator('#start-url').fill('http://127.0.0.1:4101/');
  previewBusyOnce = true;
  await page.locator('#parse-start-button').click();
  await page.locator('#target-preview-pages .parser-preview-card').first().waitFor();
  assert.equal(posts.filter(item => item.path === '/api/targets/preview').length, 4);
  assert.equal(await page.locator('#model-select').isEnabled(), true);
  await page.locator('#model-select').selectOption('deepseek-test');
  await page.locator('#model-reset-no').click();
  const launch = page.waitForResponse(response => response.url().endsWith('/api/runs') && response.request().method() === 'POST');
  await page.locator('#lab-run-button').click();
  await launch;
  await page.locator('#view-dashboard').waitFor({ state: 'visible' });
  assert.match(await page.locator('#asset-summary-detail').textContent(), /선택한 대상 URL · http:\/\/127\.0\.0\.1:4101\//);
  assert.doesNotMatch(await page.locator('#asset-summary-detail').textContent(), /파싱 결과/);
  assert.deepEqual(posts.at(-1), { path: '/api/runs', body: { mode: 'local-lab-general', modelId: 'deepseek-test',
    fixtureId: 'vul-web2-daehan', target: 'http://127.0.0.1:4101', previewId: 'preview-ui' } });
  await page.locator('[data-view=assets]').click();
  assert.equal(await page.locator('#model-select option[value="rule-baseline"]').count(), 1);
  assert.equal(await page.locator('#model-select').isEnabled(), true);
  assert.equal(await page.locator('#model-select').inputValue(), 'deepseek-test');
  assert.equal(posts.filter(item => item.path === '/api/runs').length, 1);
  await page.locator('[data-view=dashboard]').click();

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
  await page.locator('#trace-event-select').selectOption('verified');
  assert.match(await page.locator('#trace-code').textContent(), /"stage": "verify"/);
  assert.match(await page.locator('#trace-code').textContent(), /"probeId": "p1"/);
  // A later iteration extends the stream without a fixed loop/event total.
  run.iterations = 2;
  run.events.push({ id: 'observe-next', stage: 'observe', iteration: 2, title: 'Next observation',
    module: 'agent', response: { evidenceSummaries: [{ id: 'e2', kind: 'status-metadata', asset: '/next' }] },
    time: '2026-10-26T00:00:03Z' });
  await page.waitForFunction(() => document.querySelector('#progress-number')?.textContent.includes('6 events'));
  assert.doesNotMatch(await page.locator('#progress-number').textContent(), /\/\s*\d+|100%/);
  assert.equal(await page.locator('#trace-event-select').inputValue(), 'verified');
  await page.locator('#trace-event-select').selectOption('observe-next');
  assert.match(await page.locator('#trace-code').textContent(), /"iteration": 2/);
  assert.equal(await page.locator('#stop-button').isEnabled(), true);

  // Disconnection preserves evidence and prevents a stale stop request.
  stateUnavailable = true;
  await page.waitForFunction(() => document.querySelector('#connection-status')?.textContent.includes('연결 끊김'));
  assert.equal(await page.locator('#stop-button').isDisabled(), true);
  assert.equal(await page.locator('#trace-event-select').inputValue(), 'observe-next');
  assert.match(await page.locator('#trace-code').textContent(), /"iteration": 2/);
  stateUnavailable = false;
  await page.waitForFunction(() => document.querySelector('#connection-status')?.textContent.includes('연결됨'));
  assert.equal(await page.locator('#stop-button').isEnabled(), true);
  await page.locator('#stop-button').click();
  await page.waitForFunction(() => document.querySelector('#progress-label')?.textContent.includes('중지됨'));
  assert.equal(posts.at(-1).path, '/api/runs/general-run/stop');
  assert.equal(await page.locator('#stop-button').isDisabled(), true);
  run.status = 'completed'; run.report = report; run.reportDocument = undefined;
  run.iterations = 2; run.events = originalEvents;
  await page.reload();
  await page.waitForFunction(() => document.querySelector('#execution-label')?.textContent === 'GENERAL / EVIDENCE');
  assert.equal(await page.locator('#general-live-results-panel').count(), 0);
  await page.locator('[data-view=reports]').click();
  assert.match(await page.locator('#report-document-status').textContent(), /저장된 HWPX 보고서 없음/);
  assert.match(await page.locator('.report-document').textContent(), /화면의 가설별 결과와 JSON 내보내기/);
  assert.equal(await page.locator('#report-download-button').isDisabled(), true);
  assert.deepEqual(errors, []);
});

test('confirmed general findings have separate HWPX downloads and partial failures stay visible', async t => {
  const documentRun = structuredClone(run);
  documentRun.status = 'completed';
  documentRun.report = structuredClone(report);
  documentRun.report.findings = [
    { id: 'finding:h1', category: 'access_control', asset: '/records/1', status: 'confirmed', evidenceIds: ['e1'] },
    { id: 'finding:h3', category: '<img src=x onerror=alert(1)>', asset: '/posts', status: 'confirmed', evidenceIds: ['e1'] },
  ];
  documentRun.report.coverage = { totalHypotheses: 2, confirmed: 2, notReproduced: 0, inconclusive: 0, notTested: 0 };
  delete documentRun.reportDocument;
  const firstArtifact = 'a'.repeat(64); const secondArtifact = 'b'.repeat(64);
  documentRun.reportDocuments = { schemaVersion: 'general-report-documents/1', status: 'ready', items: [
    { findingId: 'finding:h1', status: 'ready', artifactId: firstArtifact, filename: '첫 번째.hwpx' },
    { findingId: 'finding:h3', status: 'ready', artifactId: secondArtifact, filename: '두 번째.hwpx' },
  ] };
  const localChrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const browser = await chromium.launch({ headless: true,
    ...(process.platform === 'win32' && !existsSync(chromium.executablePath()) && existsSync(localChrome)
      ? { executablePath: localChrome } : {}) });
  t.after(async () => browser.close());
  const page = await browser.newPage();
  await page.addInitScript(() => { window.EventSource = undefined; });
  await page.route('**/*', async route => {
    const file = new URL(route.request().url()).pathname.split('/').pop() || 'index.html';
    if (!/^[a-z-]+\.(?:html|js|css|svg)$/.test(file)) return route.fulfill({ status: 404, body: '' });
    const bytes = await readFile(new URL(`../dist/${file}`, import.meta.url));
    return route.fulfill({ contentType: ({ html: 'text/html', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' })[file.split('.').pop()], body: bytes });
  });
  await page.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname;
    const json = value => route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) });
    if (path === '/api/auth/session') return json({ authenticated: true, authRequired: false, user: { role: 'operator', name: 'Test' } });
    if (path === '/api/state') return json({ instanceId: 'general-documents-test', mode: documentRun.mode, run: documentRun,
      lab: { available: true, generalSupported: true, generalAvailable: true } });
    if (path === '/api/runs') return json({ runs: [documentRun], total: 1 });
    if (path === `/api/runs/${documentRun.id}`) return json({ run: documentRun });
    if (path === '/api/models') return json({ models: [] });
    if (path === '/api/platform') return json({ source: {}, modules: [] });
    if (path === '/api/ci-results') return json({ runs: [] });
    return json({});
  });
  await page.goto('http://ca3p.invalid/#dashboard');
  await page.locator('[data-view=reports]').click();
  assert.match(await page.locator('#report-document-status').textContent(), /HWPX 2건 준비됨/);
  assert.equal(await page.locator('.report-document-item').count(), 2);
  assert.equal(await page.locator('.report-document-download[href]').count(), 2);
  assert.equal(await page.locator('.report-document-download[href]').first().getAttribute('href'),
    `/api/runs/${documentRun.id}/reports/${firstArtifact}.hwpx`);
  assert.equal(await page.locator('.report-document-download[href]').last().getAttribute('href'),
    `/api/runs/${documentRun.id}/reports/${secondArtifact}.hwpx`);
  assert.deepEqual(await page.locator('.report-document-download[href]').evaluateAll(links =>
    links.map(link => link.getAttribute('download'))), ['첫 번째.hwpx', '두 번째.hwpx']);
  assert.equal(await page.locator('#report-content img').count(), 0);
  assert.equal(await page.locator('#report-content script').count(), 0);
  await page.locator('[data-view=sessions]').click();
  await page.locator(`[data-session=${documentRun.id}]`).click();
  await page.locator('[data-view=reports]').click();
  assert.equal(await page.locator('.report-document-download[href]').count(), 2);
  documentRun.reportDocuments.status = 'partial';
  documentRun.reportDocuments.items[1] = { findingId: 'finding:h3', status: 'failed', errorCode: 'REPORT_GENERATION_FAILED',
    message: '<script>alert(1)</script>' };
  await page.locator('[data-view=sessions]').click();
  const refresh = page.waitForResponse(response => new URL(response.url()).pathname === '/api/runs'
    && response.request().method() === 'GET');
  await page.locator('#refresh-history').click();
  await refresh;
  await page.locator('[data-view=reports]').click();
  await page.waitForFunction(() => document.querySelector('#report-document-status')?.textContent.includes('일부 생성 실패'));
  assert.match(await page.locator('#report-document-status').textContent(), /일부 생성 실패/);
  assert.equal(await page.locator('.report-document-download[href]').count(), 1);
  assert.equal(await page.locator('.report-document-download[disabled]').count(), 1);
  assert.equal(await page.locator('#report-content script').count(), 0);
  documentRun.report.findings = [{ id: 'finding:h2', category: 'xss', status: 'not_reproduced', evidenceIds: [] }];
  documentRun.report.coverage = { totalHypotheses: 1, confirmed: 0, notReproduced: 1, inconclusive: 0, notTested: 0 };
  documentRun.reportDocuments = { schemaVersion: 'general-report-documents/1', status: 'skipped', items: [] };
  await page.reload();
  await page.locator('[data-view=reports]').click();
  assert.match(await page.locator('#report-document-status').textContent(), /확정된 취약점 없음/);
  assert.equal(await page.locator('.report-document-download').count(), 0);
});
