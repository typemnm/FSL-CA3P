import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
const { chromium } = createRequire(new URL('../../packages/report/capture/package.json', import.meta.url))('playwright');

const idle = { id: '', mode: 'core-fixture', status: 'idle', target: '', simulated: true, targetContacted: false,
  startedAt: null, elapsedMs: 0, step: 0, totalSteps: 19, iterations: 1, events: [], snapshots: {}, reviewItems: [] };
const run = { id: 'stored-report', mode: 'local-lab-general', assessmentMode: 'general', status: 'completed',
  target: 'http://127.0.0.1:4101', simulated: false, targetContacted: true, startedAt: '2026-10-28T00:00:00Z',
  elapsedMs: 123, events: [], snapshots: {}, reviewItems: [], report: { schemaVersion: 'general-assessment/1',
    assessmentMode: 'general', findings: [{ id: 'finding-1', status: 'confirmed', category: 'access_control', asset: '/sample', evidenceIds: [] }],
    coverage: { totalHypotheses: 1, confirmed: 1, notReproduced: 0, inconclusive: 0, notTested: 0 } },
  reportDocuments: { schemaVersion: 'general-report-documents/1', status: 'ready', items: [
    { findingId: 'finding-1', status: 'ready', artifactId: 'a'.repeat(64), filename: 'report.hwpx' },
  ] } };

test('workspace navigation, external target preflight and report preview use the new contracts', async t => {
  const localChrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const browser = await chromium.launch({ headless: true,
    ...(process.platform === 'win32' && !existsSync(chromium.executablePath()) && existsSync(localChrome)
      ? { executablePath: localChrome } : {}) });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const errors = []; const requests = []; const uploads = [];
  let role = 'admin';
  let activeRun = idle;
  const firstModelLog = { runId: 'stored-report', createdAt: '2026-10-28T00:00:00Z', title: 'deepseek-flash', stage: 'model.call', status: 'completed' };
  let llmLogs = [firstModelLog, { runId: 'stored-report', title: 'generic module event', stage: 'inventory' }];
  let loopBudget = { limits: { maxIterations: 6, maxProbes: 24, maxEvidenceItems: 128 },
    defaults: { maxIterations: 6, maxProbes: 24, maxEvidenceItems: 128 },
    caps: { maxIterations: 32, maxProbes: 128, maxEvidenceItems: 256 } };
  let caseRecord = { case_id: 'case-1', title: '첫 사례', target_id: 'target-1', revision: 1,
    vulnerability_type: 'access_control', status: 'ready', severity: 'medium', preconditions: ['로그인'], procedure: ['조회'] };
  let intakes = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => { window.EventSource = undefined; });
  await page.route('**/*', async route => {
    const file = new URL(route.request().url()).pathname.split('/').pop() || 'index.html';
    if (!/^[a-z-]+\.(?:html|js|css|svg)$/.test(file)) return route.fulfill({ status: 404, body: '' });
    const body = await readFile(new URL(`../dist/${file}`, import.meta.url));
    return route.fulfill({ contentType: ({ html: 'text/html', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' })[file.split('.').pop()], body });
  });
  await page.route('**/api/**', async route => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    const json = value => route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) });
    if (request.method() === 'POST' && path !== '/api/db/intakes') requests.push({ path, body: request.postDataJSON() });
    if (path === '/api/auth/session') return json({ authenticated: true, authRequired: false, user: { role, name: 'Test' }, csrfToken: 'csrf-test' });
    if (path === '/api/state') return json({ instanceId: 'workspace-test', mode: activeRun.mode, run: activeRun, lab: { available: true, generalSupported: true, generalAvailable: false } });
    if (path === '/api/models') return json({ models: [{ id: 'rule-baseline', name: 'Rule', provider: 'local', mode: 'local-lab-rule', available: true }] });
    if (path === '/api/platform') return json({ source: {}, modules: [] });
    if (path === '/api/ci-results') return json({ runs: [] });
    if (path === '/api/runs' && request.method() === 'GET') return json({ runs: [run], total: 1 });
    if (path === '/api/runs/stored-report') return json({ run });
    if (path === '/api/targets/preflight') {
      await new Promise(resolve => setTimeout(resolve, 100));
      return json({ ready: true, allowed: true, normalizedUrl: 'https://example.org/start',
        scope: { origin: 'https://example.org', pathPrefix: '/', methods: ['GET','HEAD'], maxRequests: 20 }, token: 'token-1', message: '준비 완료' });
    }
    if (path === '/api/runs' && request.method() === 'POST') return json({ instanceId: 'workspace-test', mode: idle.mode, run: idle, lab: { available: true, generalSupported: true, generalAvailable: false } });
    if (path === '/api/runs/stored-report/report-preview/finding-1') return json({
      markdown: '# 보고서 본문\n\n검증 근거', html: '<!doctype html><html><body><h1>보고서 본문</h1><table><tr><td>검증 근거</td></tr></table></body></html>',
      filename: 'report.md',
    });
    if (path === '/api/modules') return json({ modules: [{ id: 'llm', status: 'active', path: 'packages/models' }] });
    if (path === '/api/modules/llm/config') return json({ config: { defaultModel: 'rule-baseline' }, revision: 'v1', editable: false, source: 'deployment' });
    if (path === '/api/modules/llm/loop-budget') {
      if (request.method() === 'PUT') {
        const body = request.postDataJSON();
        requests.push({ path, body, method: 'PUT' });
        loopBudget = { ...loopBudget, limits: body.limits };
      }
      return json(loopBudget);
    }
    if (path === '/api/modules/llm/logs') return json({ logs: llmLogs });
    if (path === '/api/db/cases') return json({ cases: [caseRecord], total: 1, limit: 50, offset: 0 });
    if (path === '/api/db/cases/case-1' && request.method() === 'GET') return json({ case: caseRecord, archived: false, audit: [] });
    if (path === '/api/db/cases/case-1/versions') return json({ versions: [] });
    if (path === '/api/db/cases/case-1' && request.method() === 'PATCH') {
      const body = request.postDataJSON(); requests.push({ path, body });
      caseRecord = { ...caseRecord, ...body.patch, revision: caseRecord.revision + 1 };
      return json({ case: caseRecord });
    }
    if (path === '/api/db/intakes' && request.method() === 'POST') {
      uploads.push(request.postData());
      intakes = [{ draft_sha256: 'draft-1', source_filename: 'sample.hwpx', target_id: 'target-1', findings: [] }];
      return json({ intake: intakes[0] });
    }
    if (path === '/api/db/intakes' && request.method() === 'GET') return json({ intakes });
    if (path === '/api/db/intakes/draft-1') return json({ intake: intakes[0], draft: { findings: [] },
      review: { schema_version: 'case-review-1', draft_sha256: 'draft-1', reviewer: '', items: [] }, validation: {} });
    return json({});
  });

  await page.goto('http://ca3p.invalid/#workspace/attack');
  await page.waitForFunction(() => document.querySelector('#connection-status')?.textContent.includes('연결됨'));
  if (process.env.CA3P_UI_PREVIEW) await page.screenshot({ path: process.env.CA3P_UI_PREVIEW.replace(/\.png$/i, '-attack.png'), fullPage: true });
  assert.deepEqual(await page.locator('.sidebar .primary-nav .nav-item').allTextContents().then(values => values.map(value => value.trim())),
    ['자산', '공격1', '보고서', 'AI 채팅', 'DB', 'Attack Module', 'Web Parser', 'Guardrail', 'LLM', 'DB']);
  assert.equal(await page.locator('.external-target-panel').isHidden(), true);
  await page.locator('[data-view=assets]').click();
  assert.equal(new URL(page.url()).hash, '#workspace/assets');
  await page.reload();
  await page.locator('#view-assets').waitFor({ state: 'visible' });
  await page.locator('#target-kind-external').click();
  await page.locator('#external-url').fill('https://example.org/start');
  assert.equal(await page.locator('#external-authorization').count(), 0);
  await page.locator('#external-preflight-button').click();
  // The button is visible while preflight is pending; wait for its result.
  await page.waitForFunction(() => document.querySelector('#external-run-button')?.disabled === false);
  assert.equal(await page.locator('#external-run-button').isEnabled(), true);
  await page.locator('#external-run-button').click();
  await page.locator('#view-dashboard').waitFor({ state: 'visible' });
  assert.deepEqual(requests.filter(item => ['/api/targets/preflight','/api/runs'].includes(item.path)), [
    { path: '/api/targets/preflight', body: { target: 'https://example.org/start', scope: { pathPrefix: '/' }, authorizationConfirmed: true } },
    { path: '/api/runs', body: { mode: 'external-general', target: 'https://example.org/start', scope: { pathPrefix: '/' },
      preflightToken: 'token-1', authorizationConfirmed: true, modelId: 'rule-baseline' } },
  ]);
  await page.locator('[data-view=reports]').click();
  await page.locator('#report-run-select').selectOption('stored-report');
  await page.locator('[data-preview-finding=finding-1]').click();
  await page.locator('#report-preview-frame').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#report-preview-frame').getAttribute('sandbox'), '');
  assert.match(await page.frameLocator('#report-preview-frame').locator('table').textContent(), /검증 근거/);
  await page.locator('[data-view=module-llm]').click();
  assert.match(await page.locator('#module-detail-content').textContent(), /배포 설정 · 읽기 전용/);
  await page.locator('#llm-budget-form').waitFor();
  assert.deepEqual(await Promise.all(['maxIterations', 'maxProbes', 'maxEvidenceItems'].map(key =>
    page.locator(`#llm-budget-${key}`).inputValue())), ['6', '24', '128']);
  assert.match(await page.locator('.llm-budget-panel').textContent(), /다음 범용 실행부터 적용/);
  assert.match(await page.locator('.llm-budget-panel').textContent(), /기본 6 · 최대 32/);
  await page.locator('#llm-budget-maxIterations').fill('8');
  await page.locator('#llm-budget-maxProbes').fill('30');
  await page.locator('#llm-budget-maxEvidenceItems').fill('160');
  await page.locator('#llm-budget-form button[type=submit]').click();
  await page.locator('.llm-budget-notice').waitFor();
  assert.deepEqual(requests.find(item => item.path === '/api/modules/llm/loop-budget'),
    { path: '/api/modules/llm/loop-budget', method: 'PUT',
      body: { limits: { maxIterations: 8, maxProbes: 30, maxEvidenceItems: 160 } } });
  await page.locator('[data-action=refresh-module]').click();
  await page.waitForFunction(() => document.querySelector('#llm-budget-maxIterations')?.value === '8');
  assert.equal(await page.locator('#llm-call-log-panel').isVisible(), true);
  assert.match(await page.locator('#llm-call-log-panel').textContent(), /llm call log/);
  await page.locator('#llm-call-list .event-title').filter({ hasText: 'deepseek-flash' }).waitFor();
  assert.match(await page.locator('#llm-call-list').textContent(), /deepseek-flash/);
  assert.doesNotMatch(await page.locator('#llm-call-list').textContent(), /generic module event/);
  await page.locator('#llm-call-search').fill('missing model');
  assert.match(await page.locator('#llm-call-list').textContent(), /일치하는 호출 기록이 없습니다/);
  await page.locator('#llm-call-search').fill('deepseek-flash');
  assert.match(await page.locator('#llm-call-list').textContent(), /deepseek-flash/);
  await page.locator('#llm-call-search').fill('model.call');
  activeRun = { ...run, status: 'running', report: null, events: [] };
  llmLogs = [firstModelLog, { runId: 'live-run', createdAt: '2026-10-28T00:00:02Z',
    title: 'deepseek-v4-pro', stage: 'model.call', status: 'completed' }];
  await page.waitForFunction(() => document.querySelector('#llm-call-count')?.textContent === '02', null, { timeout: 7000 });
  assert.equal(await page.locator('#llm-call-search').inputValue(), 'model.call');
  assert.match(await page.locator('#llm-call-list').textContent(), /deepseek-v4-pro/);
  activeRun = idle;
  if (process.env.CA3P_UI_PREVIEW) await page.screenshot({ path: process.env.CA3P_UI_PREVIEW.replace(/\.png$/i, '-module.png'), fullPage: true });
  await page.locator('[data-view=db]').click();
  assert.match(await page.locator('#workspace-db-content').textContent(), /취약점 사례/);
  await page.locator('[data-case-id=case-1]').click();
  await page.locator('[data-case-field=title]').fill('수정한 사례');
  await page.locator('#case-edit-form button[type=submit]').click();
  await page.waitForFunction(() => document.querySelector('[data-case-field=title]')?.value === '수정한 사례');
  assert.deepEqual(requests.find(item => item.path === '/api/db/cases/case-1')?.body,
    { patch: { title: '수정한 사례' }, expectedRevision: 1 });
  await page.locator('[data-db-tab=intakes]').click();
  await page.locator('#intake-target-id').fill('target-1');
  await page.locator('#intake-file').setInputFiles({ name: 'sample.hwpx', mimeType: 'application/octet-stream', buffer: Buffer.from('test') });
  await page.locator('#intake-upload-form button[type=submit]').click();
  await page.waitForFunction(() => document.querySelector('#workspace-db-content')?.textContent.includes('draft-1'));
  assert.match(uploads[0], /name="file"/);
  assert.match(uploads[0], /name="targetId"/);
  if (process.env.CA3P_UI_PREVIEW) await page.screenshot({ path: process.env.CA3P_UI_PREVIEW.replace(/\.png$/i, '-db.png'), fullPage: true });
  await page.goto('http://ca3p.invalid/#sessions');
  await page.waitForFunction(() => location.hash === '#workspace/attack/history');
  assert.equal(await page.locator('#view-sessions').isVisible(), true);
  role = 'viewer';
  await page.reload();
  await page.waitForFunction(() => document.querySelector('#connection-status')?.textContent.includes('연결됨'));
  await page.locator('[data-view=assets]').click();
  await page.locator('#target-kind-external').click();
  assert.equal(await page.locator('#external-preflight-button').isDisabled(), true);
  await page.locator('[data-view=db]').click();
  await page.locator('[data-case-id=case-1]').click();
  assert.equal(await page.locator('#case-edit-form button[type=submit]').isDisabled(), true);
  await page.locator('[data-view=module-llm]').click();
  await page.locator('#llm-budget-form').waitFor();
  assert.equal(await page.locator('#llm-budget-maxIterations').inputValue(), '8');
  assert.equal(await page.locator('#llm-budget-form button[type=submit]').isDisabled(), true);
  assert.equal(await page.locator('#llm-budget-maxIterations').isDisabled(), true);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('#menu-button').click();
  assert.equal(await page.locator('#sidebar').evaluate(element => element.classList.contains('open')), true);
  assert.deepEqual(errors, []);
});
