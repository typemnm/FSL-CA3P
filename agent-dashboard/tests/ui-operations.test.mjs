import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { once } from 'node:events';
import { createRequire } from 'node:module';
const { chromium } = createRequire(new URL('../../xss-parser/package.json', import.meta.url))('playwright');

const shaA = 'a'.repeat(40); const shaB = 'b'.repeat(40);
const at = '2026-10-26T10:00:00Z';
const ciRun = { runId: 102, commitSha: shaB, status: 'passed', tests: 635, passed: 635, failed: 0, skipped: 0,
  runUrl: 'https://github.com/typemnm/FSL-CA3P/actions/runs/102' };
const initial = { schemaVersion: '1.0', generatedAt: at, source: { runningSha: shaA, targetSha: shaB, applied: false, targetSource: 'device' },
  deployment: { enabled: true, status: 'preparing', phase: 'dependencies', targetSha: shaB, checkedAt: at, updatedAt: at, events: [{}] },
  ci: { status: 'fresh', updatedAt: at, latest: ciRun, matched: ciRun }, freshness: { device: 'fresh', ci: 'fresh' },
  events: [
    { id: 'device-prepare', at, kind: 'deployment', status: 'preparing', severity: 'info', title: '새 버전 준비 중', message: '의존성을 준비하고 있습니다.', targetSha: shaB, phase: 'dependencies' },
    { id: 'ci-102-1-passed', at, kind: 'ci', status: 'passed', severity: 'success', title: '전체 CI 성공', message: 'CI 성공과 장치 반영은 별개입니다.', targetSha: shaB, runUrl: ciRun.runUrl },
  ] };
const idle = { id: null, target: '', status: 'idle', startedAt: null, elapsedMs: 0, step: 0, totalSteps: 19, iterations: 1,
  events: [], snapshots: {}, reviewItems: [], mode: 'core-fixture', simulated: true, targetContacted: false };

async function fixture(t, { fastPolling = false, operations = initial } = {}) {
  const server = http.createServer(async (req, res) => {
    try {
      const name = new URL(req.url, 'http://test').pathname.split('/').pop() || 'index.html';
      if (!/^[a-z-]+\.(?:html|js|css|svg)$/.test(name)) { res.writeHead(404); return res.end(); }
      const bytes = await readFile(new URL(`../dist/${name}`, import.meta.url));
      res.writeHead(200, { 'Content-Type': ({ html: 'text/html', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' })[name.split('.').pop()] }); res.end(bytes);
    } catch { res.writeHead(404); res.end(); }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const browser = await chromium.launch({ headless: true }); const page = await browser.newPage();
  const errors = []; const calls = []; let authenticated = true; let current = structuredClone(operations); let failure = null; let epoch = 0;
  page.on('pageerror', error => errors.push(error.message));
  if (fastPolling) await page.addInitScript(() => {
    const original = window.setTimeout;
    window.setTimeout = (callback, delay, ...args) => original(callback, delay === 20_000 ? 80 : delay, ...args);
  });
  await page.route('**/api/**', async route => {
    const req = route.request(); const path = new URL(req.url()).pathname;
    const json = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
    const envelope = () => ({ instanceId: 'operations-test', mode: 'core-fixture', run: idle, experiment: { epoch, status: 'ready' }, lab: { available: true } });
    if (path === '/api/auth/session') return json({ authRequired: true, authenticated, csrfToken: 'fixture-csrf', user: authenticated ? { name: 'Viewer', role: 'operator' } : null });
    if (path === '/api/auth/logout') { authenticated = false; return json({ authenticated: false }); }
    if (!authenticated) return json({ error: 'Login required' }, 401);
    if (path === '/api/operations') {
      calls.push({ method: req.method(), body: req.postData(), headers: req.headers() });
      return failure ? json({ error: failure }, 503) : json(current);
    }
    if (path === '/api/state') return json(envelope());
    if (path === '/api/events') return route.fulfill({ contentType: 'text/event-stream', body: `event: state\ndata: ${JSON.stringify(envelope())}\n\n` });
    if (path === '/api/models') return json({ models: [{ id: 'rule-baseline', name: '규칙 기반', mode: 'local-lab-rule', available: true }] });
    if (path === '/api/runs') return json({ runs: [], total: 0 });
    if (path === '/api/ci-results') return json({ status: 'fresh', runs: [] });
    if (path === '/api/platform') return json({ modules: [] });
    if (path === '/api/experiment-reset') { epoch += 1; return json({ ...envelope(), experimentReset: { status: 'completed' } }); }
    return json({});
  });
  t.after(async () => { await browser.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.waitForFunction(() => document.querySelector('#operations-count').textContent === '2');
  return { page, errors, calls, set(value) { current = structuredClone(value); }, fail(value) { failure = value; } };
}

test('deployment board distinguishes CI from actual device version, acknowledges unread events and survives experiment reset', async t => {
  const { page, calls, errors, set } = await fixture(t);
  assert.equal(await page.locator('#toast').isVisible(), false, 'historical events must not flood initial login with toasts');
  await page.locator('#notifications-button').click();
  assert.match(await page.locator('#operation-notification-list').textContent(), /새 버전 준비 중/);
  await page.locator('#open-operations').click();
  await page.waitForFunction(() => document.querySelector('#operations-count').textContent === '0');
  assert.match(await page.locator('#operations-content').textContent(), /의존성 준비/);
  assert.match(await page.locator('#operations-content').textContent(), /전체 CI 성공/);
  assert.match(await page.locator('#operations-content').textContent(), /적용 대기 \/ 버전 다름/);
  assert.equal(await page.locator('.operations-revisions code').first().textContent(), shaA);
  assert.equal(await page.locator('.operations-revisions code').last().textContent(), shaB);
  const next = structuredClone(initial); next.source.runningSha = shaB; next.source.applied = true;
  next.deployment.status = 'deployed'; next.deployment.phase = null; next.deployment.deployedAt = at;
  next.events.unshift({ id: 'device-deployed', at, kind: 'deployment', status: 'deployed', severity: 'success', title: '최신 버전 적용 완료', targetSha: shaB, deployedSha: shaB });
  set(next); await page.locator('#refresh-operations').click();
  await page.waitForFunction(() => document.querySelector('.operations-current h2').textContent.includes('최신 버전 적용 완료'));
  assert.equal(await page.locator('#operations-count').textContent(), '0');
  if (process.env.CA3P_OPERATIONS_PREVIEW) await page.screenshot({ path: process.env.CA3P_OPERATIONS_PREVIEW, fullPage: true });
  const readBefore = await page.evaluate(() => localStorage.getItem('ca3p.operations.read.v1'));
  await page.locator('[data-view=dashboard]').click();
  await page.locator('#experiment-reset-button').click(); await page.locator('#model-reset-yes').click();
  await page.locator('#model-reset-dialog').waitFor({ state: 'hidden' });
  await page.locator('[data-view=operations]').click();
  assert.match(await page.locator('#operations-content').textContent(), /최신 버전 적용 완료/);
  assert.equal(await page.evaluate(() => localStorage.getItem('ca3p.operations.read.v1')), readBefore);
  assert.ok(calls.every(call => call.method === 'GET' && call.body === null));
  assert.deepEqual(errors, []);
});

test('unmatched SHA and stale device evidence never claim a current verified deployment', async t => {
  const { page, set, fail, errors } = await fixture(t);
  const mismatch = structuredClone(initial); mismatch.ci.matched = null;
  set(mismatch); await page.locator('[data-view=operations]').click();
  await page.waitForFunction(() => document.querySelector('.operations-progress').textContent.includes('대상 SHA의 CI 결과 대기'));
  const stale = structuredClone(initial); stale.source.runningSha = shaB; stale.source.applied = true;
  stale.deployment.status = 'up-to-date'; stale.freshness.device = 'stale';
  set(stale); await page.locator('#refresh-operations').click();
  await page.waitForFunction(() => document.querySelector('.operations-current h2').textContent.startsWith('마지막 기록'));
  assert.match(await page.locator('.operations-warning').textContent(), /현재 완료 여부를 확정할 수 없습니다/);
  assert.match(await page.locator('.operation-state').textContent(), /마지막 확인 버전 일치/);
  fail('Temporary connection failure'); await page.locator('#refresh-operations').click();
  await page.waitForFunction(() => document.querySelector('#operations-source').textContent.includes('연결 오류'));
  assert.match(await page.locator('#operations-content').textContent(), /현재 완료 여부를 확정할 수 없습니다/);
  fail(null); const disabled = structuredClone(initial); disabled.deployment = { enabled: false }; disabled.events = [];
  set(disabled); await page.locator('#refresh-operations').click();
  await page.waitForFunction(() => document.querySelector('.operations-current h2').textContent.includes('자동 배포 미설정'));
  assert.deepEqual(errors, []);
});

test('operation event text is escaped and unsafe action links are not rendered', async t => {
  const { page, set, errors } = await fixture(t);
  const payload = structuredClone(initial);
  payload.events[0].title = '<img src=x onerror=alert(1)>'; payload.events[0].message = '<script>bad()</script>';
  payload.events[0].runUrl = 'javascript:alert(1)';
  set(payload); await page.locator('[data-view=operations]').click();
  await page.waitForFunction(() => document.querySelector('.operations-timeline').textContent.includes('<img'));
  assert.equal(await page.locator('#operations-content img,#operation-notification-list img').count(), 0);
  assert.equal(await page.locator('#operations-content a[href^="javascript:"]').count(), 0);
  assert.deepEqual(errors, []);
});

test('an older completed device target is not described as applying the newer CI target', async t => {
  const { page, set, errors } = await fixture(t);
  const newer = structuredClone(initial); newer.source.targetSource = 'ci';
  newer.deployment = { enabled: true, status: 'deployed', targetSha: shaA, deployedSha: shaA,
    checkedAt: at, updatedAt: at, deployedAt: at, historyAvailable: false };
  set(newer); await page.locator('[data-view=operations]').click();
  await page.waitForFunction(() => document.querySelector('.operations-current h2').textContent.includes('새 develop'));
  assert.equal(await page.locator('.operations-current h2').textContent(), '새 develop 검증·적용 대기');
  assert.match(await page.locator('.operations-progress').textContent(), /새 대상은 장치 확인 대기/);
  assert.match(await page.locator('.operations-progress').textContent(), /이전 대상 상태/);
  assert.match(await page.locator('.operations-history-note').textContent(), /새 controller/);
  assert.deepEqual(errors, []);
});

test('new significant server event notifies once and read acknowledgement persists across reload', async t => {
  const { page, set, errors } = await fixture(t, { fastPolling: true });
  await page.locator('[data-view=operations]').click();
  await page.locator('[data-view=dashboard]').click();
  await page.evaluate(() => {
    window.operationToastChanges = 0;
    new MutationObserver(() => { if (document.querySelector('#toast').textContent.includes('배포 알림')) window.operationToastChanges += 1; })
      .observe(document.querySelector('#toast'), { childList: true });
  });
  const next = structuredClone(initial);
  next.events.unshift({ id: 'device-failed', at, kind: 'deployment', status: 'failed', severity: 'error', title: '장치 적용 실패', targetSha: shaB });
  set(next);
  await page.waitForFunction(() => document.querySelector('#operations-count').textContent === '1');
  assert.match(await page.locator('#toast').textContent(), /장치 적용 실패/);
  await page.waitForTimeout(260);
  assert.equal(await page.evaluate(() => window.operationToastChanges), 1);
  await page.locator('[data-view=operations]').click();
  assert.equal(await page.locator('#operations-count').textContent(), '0');
  await page.reload();
  await page.waitForFunction(() => document.querySelector('#operations-content').textContent.includes('장치 적용 실패'));
  assert.equal(await page.locator('#operations-count').textContent(), '0');
  assert.deepEqual(errors, []);
});

test('automatic read polling pauses while hidden and stops on logout', async t => {
  const { page, calls, errors } = await fixture(t, { fastPolling: true });
  await page.waitForTimeout(230); assert.ok(calls.length >= 2);
  await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => true }); document.dispatchEvent(new Event('visibilitychange')); });
  const hiddenCount = calls.length; await page.waitForTimeout(250); assert.equal(calls.length, hiddenCount);
  await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => false }); document.dispatchEvent(new Event('visibilitychange')); });
  await page.waitForTimeout(180); assert.ok(calls.length > hiddenCount);
  await page.locator('#logout-button').click(); await page.locator('#login-dialog').waitFor({ state: 'visible' });
  const loggedOutCount = calls.length; await page.waitForTimeout(250); assert.equal(calls.length, loggedOutCount);
  assert.equal(await page.locator('#operation-notification-list').textContent(), '');
  assert.deepEqual(errors, []);
});
