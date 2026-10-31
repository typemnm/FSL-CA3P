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
  let stateUnavailable = false;
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
  assert.equal(await page.locator('#fixture-select option').allTextContents().then(values => values.some(value => /XSS|IDOR/.test(value))), false);
  assert.equal(await page.locator('#assessment-mode, #asset-mock-run, #target-form').count(), 0);
  assert.match(await page.locator('#lab-title').textContent(), /vul-web-1 로컬 게시판/);
  assert.doesNotMatch(await page.locator('#lab-title').textContent(), /XSS|IDOR/);
  assert.match(await page.locator('#lab-check-scope').textContent(), /반복 점검/);
  assert.match(await page.locator('#lab-run-label').textContent(), /범용 취약점 점검 시작/);
  await page.locator('#fixture-select').selectOption('vul-web2-daehan');
  assert.match(await page.locator('#lab-title').textContent(), /vul-web2 대한대학교/);
  assert.doesNotMatch(await page.locator('#lab-title').textContent(), /XSS|IDOR/);
  assert.equal(await page.locator('#model-select').isEnabled(), true);
  assert.equal(await page.locator('#model-select').inputValue(), 'deepseek-test');
  const launch = page.waitForResponse(response => response.url().endsWith('/api/runs') && response.request().method() === 'POST');
  await page.locator('#lab-run-button').click();
  await launch;
  await page.locator('#view-dashboard').waitFor({ state: 'visible' });
  assert.deepEqual(posts.at(-1), { path: '/api/runs', body: { mode: 'local-lab-general', modelId: 'deepseek-test',
    fixtureId: 'vul-web2-daehan', target: 'http://127.0.0.1:4101' } });
  await page.locator('[data-view=assets]').click();
  assert.equal(await page.locator('#model-select option[value="rule-baseline"]').count(), 0);
  assert.equal(await page.locator('#model-select').isEnabled(), true);
  assert.equal(await page.locator('#model-select').inputValue(), 'deepseek-test');
  assert.equal(posts.length, 1);
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

test('web-parser result cards load each artifact once and survive polling re-renders', async t => {
  const viewId = 'd'.repeat(64); const missingId = 'e'.repeat(64);
  const webEvent = (artifactId, overrides = {}) => ({ stage: 'web_info.collected', module: 'web-parser', source: 'web-parser',
    type: 'info', title: '웹 정보 수집', detail: 'GET /board → HTTP 200', probeId: `p-${artifactId?.[0] ?? 'x'}`, iteration: 1,
    asset: '/board?page=2', sessionRole: 'member', ok: true, status: 200, artifactId,
    counts: { technologies: 1, paths: 2, forms: 0, errors: 0 }, truncated: false, time: '2026-10-26T00:00:01Z', ...overrides });
  const webRun = { ...structuredClone(run), id: 'web-info-run', status: 'completed', report: structuredClone(report),
    reportDocument: { status: 'skipped', errorCode: 'GENERAL_DOCUMENT_UNSUPPORTED' },
    events: [{ stage: 'inventory.collect', title: 'Inventory', module: 'agent', time: '2026-10-26T00:00:00Z' },
      webEvent(viewId), webEvent(missingId, { asset: '/gone' }),
      webEvent(null, { asset: '/down', ok: false, status: null, type: 'warning', detail: '웹 정보 수집 실패',
        counts: { technologies: 0, paths: 0, forms: 0, errors: 1 } })] };
  // Raw TargetInfo as web-parser collected it (secrets included, shown as is).
  const view = { schemaVersion: 'web-parser-1',
    target: { requestedUrl: 'https://app.test/board?page=2', finalUrl: 'https://app.test/board?page=2', origin: 'https://app.test' },
    navigation: { status: 200, contentType: 'text/html', redirectChain: [], loadTimingMs: 12, securityDetails: null },
    headers: [{ name: 'Content-Type', value: 'text/html' }, { name: 'Set-Cookie', value: 'sid=raw-cookie-value' }],
    cookies: [{ name: 'sid', value: 'raw-cookie-value', domain: 'app.test', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' }],
    meta: [], html: '<title><img src=x onerror=alert(1)></title><p>hello</p>', body: `${'x'.repeat(20000)}BODY-TAIL-MARKER`,
    technologies: [{ name: 'jQuery', version: '3.6.0', categories: ['JavaScript libraries'], confidence: 100,
      evidence: [{ field: 'scriptSrc', match: 'jquery.min.js' }] }],
    libraries: [{ name: 'jQuery', version: '3.6.0', source: 'fingerprint', evidence: [] }],
    structure: { forms: [], links: [] }, resources: [], errors: [], truncated: false,
    paths: [
      { url: 'https://app.test/board/view', sources: ['link'], methods: ['GET'], sameOrigin: true, params: ['id'] },
      { url: 'https://cdn.example.net/lib.js', sources: ['request:script'], methods: ['GET'], sameOrigin: false, params: [] }] };
  const fetches = [];
  const localChrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const browser = await chromium.launch({ headless: true,
    ...(process.platform === 'win32' && !existsSync(chromium.executablePath()) && existsSync(localChrome)
      ? { executablePath: localChrome } : {}) });
  t.after(async () => browser.close());
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => { window.EventSource = undefined; });
  await page.route('**/*', async route => {
    const file = new URL(route.request().url()).pathname.split('/').pop() || 'index.html';
    if (!/^[a-z-]+\.(?:html|js|css|svg)$/.test(file)) return route.fulfill({ status: 404, body: '' });
    const bytes = await readFile(new URL(`../dist/${file}`, import.meta.url));
    return route.fulfill({ contentType: ({ html: 'text/html', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' })[file.split('.').pop()], body: bytes });
  });
  await page.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname;
    const json = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
    if (path.startsWith('/api/artifacts/')) {
      fetches.push(path);
      return path.endsWith(viewId) ? json(view) : json({ error: 'Artifact not found.' }, 404);
    }
    if (path === '/api/auth/session') return json({ authenticated: true, authRequired: false, user: { role: 'operator', name: 'Test' } });
    if (path === '/api/state') return json({ instanceId: 'web-info-test', mode: webRun.mode, run: webRun,
      lab: { available: true, generalSupported: true, generalAvailable: true } });
    if (path === '/api/runs') return json({ runs: [webRun], total: 1 });
    if (path === `/api/runs/${webRun.id}`) return json({ run: webRun });
    if (path === '/api/models') return json({ models: [] });
    if (path === '/api/platform') return json({ source: {}, modules: [] });
    if (path === '/api/ci-results') return json({ runs: [] });
    return json({});
  });
  await page.goto('http://ca3p.invalid/#dashboard');
  await page.locator('[data-view=reports]').click();
  const section = page.locator('#report-content .web-info-section');
  await section.waitFor();
  assert.equal(await page.locator('.web-info-card').count(), 3);
  assert.equal(await page.locator('details[data-web-info-artifact]').count(), 2);
  assert.match(await section.textContent(), /상세 정보 없음/);
  assert.deepEqual(fetches, []);
  // Placed after the findings and before the raw JSON section.
  assert.equal(await page.evaluate(() => {
    const web = document.querySelector('#report-content .web-info-section');
    const finding = document.querySelector('#report-content .general-finding');
    const raw = [...document.querySelectorAll('#report-content .core-report')].at(-1);
    return !!(finding.compareDocumentPosition(web) & Node.DOCUMENT_POSITION_FOLLOWING)
      && !!(web.compareDocumentPosition(raw) & Node.DOCUMENT_POSITION_FOLLOWING);
  }), true);

  const card = page.locator(`details[data-web-info-artifact="${viewId}"]`);
  await card.locator('summary').click();
  await card.locator('.web-info-table').first().waitFor();
  assert.match(await card.locator('.web-info-block').first().textContent(), /jQuery[\s\S]*3\.6\.0/);
  assert.equal(await card.getByText('https://app.test/board/view').isVisible(), true);
  assert.equal(await card.getByText('https://cdn.example.net/lib.js').isVisible(), false);
  await card.locator('.web-info-external > summary').click();
  assert.equal(await card.getByText('https://cdn.example.net/lib.js').isVisible(), true);
  assert.equal(await card.locator('.web-info-download').getAttribute('href'), `/api/artifacts/${viewId}`);
  const cookieFold = card.locator('details.web-info-fold', { hasText: '쿠키' });
  await cookieFold.locator('> summary').click();
  assert.equal(await cookieFold.getByText('raw-cookie-value', { exact: true }).isVisible(), true);
  const bodyFold = card.locator('details.web-info-fold', { hasText: '본문 원문 (body)' });
  await bodyFold.locator('> summary').click();
  assert.equal(await bodyFold.getByText('BODY-TAIL-MARKER').isVisible(), false);
  await bodyFold.locator('.web-info-rest > summary').click();
  assert.equal(await bodyFold.getByText('BODY-TAIL-MARKER').isVisible(), true);
  // Polling replaces the report every second; the open card, its nested toggle and its content stay.
  await page.waitForTimeout(1500);
  assert.equal(await card.evaluate(element => element.open), true);
  assert.equal(await card.locator('.web-info-external').evaluate(element => element.open), true);
  assert.equal(await card.getByText('https://cdn.example.net/lib.js').isVisible(), true);
  await card.locator('summary').first().click();
  await card.locator('summary').first().click();
  await card.locator('.web-info-table').first().waitFor();
  assert.deepEqual(fetches, [`/api/artifacts/${viewId}`]);

  const missing = page.locator(`details[data-web-info-artifact="${missingId}"]`);
  await missing.locator('summary').click();
  await missing.getByText('저장된 상세 정보를 찾을 수 없습니다.').waitFor();
  // Collected URLs stay text; the only link is the dashboard's own 원본 JSON download.
  assert.equal(await page.locator('#report-content script, .web-info-section img, .web-info-section a:not(.web-info-download)').count(), 0);
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  assert.deepEqual(errors, []);
});

test('web-parser module page shows a readable collection log and expands a row into the detail', async t => {
  const artifactId = 'f'.repeat(64);
  const runId = 'general-11111111-2222-3333-4444-aaaaaaaaaaaa';
  const collected = (id, overrides = {}) => ({ id, runId, sequence: 1, module: 'web-parser', stage: 'web_info.collected',
    status: 200, title: '웹 정보 수집', createdAt: '2026-11-01T06:01:05Z', detail: 'GET /board → HTTP 200', asset: '/board?page=2',
    sessionRole: 'member', probeId: `p-${id}`, iteration: 1, ok: true, httpStatus: 200, artifactId,
    counts: { technologies: 1, paths: 1, forms: 0, errors: 0 }, truncated: false, ...overrides });
  const logs = [collected('ok-row'),
    collected('fail-row', { createdAt: '2026-11-01T06:02:05Z', asset: '/down', ok: false, httpStatus: null, status: null,
      artifactId: undefined, detail: '웹 정보 수집 실패', counts: { technologies: 0, paths: 0, forms: 0, errors: 1 } }),
    { id: 'legacy-row', runId: 'run-legacy', module: 'xss-parser', stage: 'observe', status: 'completed',
      title: '<img src=x onerror=alert(1)>', createdAt: '2026-10-01T00:00:00Z' }];
  const view = { schemaVersion: 'web-parser-1', target: { requestedUrl: 'https://app.test/board?page=2' },
    navigation: { status: 200, contentType: 'text/html' }, html: '<title>게시판</title>',
    technologies: [{ name: 'jQuery', version: '3.6.0', categories: ['JavaScript libraries'], confidence: 100, evidence: [] }],
    paths: [{ url: 'https://app.test/board/view', sources: ['link'], methods: ['GET'], sameOrigin: true, params: ['id'] }] };
  const fetches = []; const moduleRequests = [];
  const localChrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const browser = await chromium.launch({ headless: true,
    ...(process.platform === 'win32' && !existsSync(chromium.executablePath()) && existsSync(localChrome)
      ? { executablePath: localChrome } : {}) });
  t.after(async () => browser.close());
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
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
    if (/^\/api\/modules\/[a-z-]+\/(?:config|logs)$/.test(path)) moduleRequests.push(path);
    if (path.startsWith('/api/artifacts/')) { fetches.push(path); return json(view); }
    if (path === '/api/auth/session') return json({ authenticated: true, authRequired: false, user: { role: 'operator', name: 'Test' } });
    if (path === '/api/state') return json({ instanceId: 'module-log-test', mode: run.mode, run,
      lab: { available: true, generalSupported: true, generalAvailable: true } });
    if (path === '/api/modules') return json({ modules: [{ id: 'attack', name: 'Attack Tool', status: 'active' },
      { id: 'web-parser', name: 'Web Parser', status: 'active' }] });
    if (path === '/api/modules/web-parser/config') return json({ config: { integrationId: 'web-parser', path: 'web-parser' },
      revision: 'digest', editable: false });
    if (path === '/api/modules/web-parser/logs') return json({ logs, total: 250, truncated: false });
    if (path === '/api/runs') return json({ runs: [], total: 0 });
    return json({});
  });
  await page.goto('http://ca3p.invalid/#modules/web-parser');
  const panel = page.locator('.web-parser-log');
  await panel.waitFor();
  // Startup loads the module twice (navigation, then session); let both finish before interacting.
  await page.waitForLoadState('networkidle');
  assert.match(await panel.locator('.web-parser-log-strip').textContent(), /수집 횟수2성공 \/ 실패1 \/ 1수집 페이지2포함된 실행1/);
  assert.match(await panel.textContent(), /최근 3건만 표시합니다 \(전체 로그 250건\)/);
  assert.equal(await page.locator('#module-detail-content .ops-log-list').count(), 0);
  // Operator decision: no MODULE OPERATIONS block or config JSON; 새로고침 lives in the log panel heading.
  assert.doesNotMatch(await page.locator('#module-detail-content').textContent(), /MODULE OPERATIONS|현재 유효 설정|모듈 ID|소스 경로|integrationId/);
  assert.equal(await page.locator('#module-detail-content .ops-panel, #module-detail-content pre').count(), 0);
  assert.ok(moduleRequests.length > 0 && moduleRequests.every(path => path === '/api/modules/web-parser/logs'));
  const loadsBefore = moduleRequests.length;
  assert.equal(await page.locator('#module-detail-content [data-action="refresh-module"]').count(), 1);
  assert.equal(await panel.locator('.panel-heading [data-action="refresh-module"]').count(), 1);
  const rows = panel.locator('.web-parser-log-row');
  assert.deepEqual(await rows.evaluateAll(items => items.map(item => item.dataset.logId)), ['fail-row', 'ok-row']);
  assert.deepEqual(fetches, []);

  const row = panel.locator('[data-log-id="ok-row"]');
  await row.locator('summary').click();
  await row.locator('.web-info-table').first().waitFor();
  assert.match(await row.locator('.web-info-detail').textContent(), /jQuery[\s\S]*3\.6\.0[\s\S]*https:\/\/app\.test\/board\/view/);
  // Filtering keeps the open row open and does not refetch it.
  await page.locator('#web-parser-log-search').fill('board');
  assert.deepEqual(await rows.evaluateAll(items => items.map(item => item.dataset.logId)), ['ok-row']);
  assert.equal(await panel.locator('[data-log-id="ok-row"]').evaluate(element => element.open), true);
  await panel.locator('[data-log-id="ok-row"] .web-info-table').first().waitFor();
  assert.equal(await page.locator('#web-parser-log-search').evaluate(element => element === document.activeElement), true);
  await page.locator('#web-parser-log-search').fill('');
  await page.locator('#web-parser-failed-only').check();
  assert.deepEqual(await rows.evaluateAll(items => items.map(item => item.dataset.logId)), ['fail-row']);
  await panel.locator('[data-log-id="fail-row"] summary').click();
  assert.match(await panel.locator('[data-log-id="fail-row"]').textContent(), /상세 정보 없음/);
  assert.deepEqual(fetches, [`/api/artifacts/${artifactId}`]);

  await panel.locator('.web-parser-other-logs > summary').click();
  assert.match(await panel.locator('.web-parser-other-logs').textContent(), /<img src=x onerror=alert\(1\)>/);
  assert.equal(await page.locator('#module-detail-content img, #module-detail-content script').count(), 0);
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);

  const reload = page.waitForResponse(response => new URL(response.url()).pathname === '/api/modules/web-parser/logs');
  await panel.locator('[data-action="refresh-module"]').click();
  await reload;
  await page.locator('.web-parser-log [data-action="refresh-module"]').waitFor();
  assert.equal(moduleRequests.length, loadsBefore + 1);
  assert.ok(moduleRequests.every(path => path === '/api/modules/web-parser/logs'));
  // Other module pages keep their operations block.
  await page.evaluate(() => { location.hash = 'modules/attack'; });
  await page.locator('#module-detail-content .ops-panel', { hasText: 'MODULE OPERATIONS' }).waitFor();
  assert.match(await page.locator('#module-detail-content').textContent(), /현재 유효 설정[\s\S]*모듈 로그/);
  assert.equal(await page.locator('#module-detail-content .web-parser-log').count(), 0);
  assert.equal(await page.locator('#module-detail-content .ops-panel-head [data-action="refresh-module"]').count(), 1);
  assert.ok(moduleRequests.includes('/api/modules/attack/config'));
  assert.deepEqual(errors, []);
});
