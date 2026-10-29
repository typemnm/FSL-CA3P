import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
const { chromium } = createRequire(new URL('../../packages/report/capture/package.json', import.meta.url))('playwright');

const idle = { id: '', mode: 'core-fixture', status: 'idle', target: '', simulated: true, targetContacted: false,
  startedAt: null, elapsedMs: 0, step: 0, totalSteps: 19, iterations: 1, events: [], snapshots: {}, reviewItems: [] };
const malicious = '<img src=x onerror="window.chatInjected=true">';
const context = { applicationBudgetTokens: 8000, estimatedInputTokens: 5100, percentage: 64, approximate: true,
  compactionThresholdTokens: 6400, summaryTokens: 0, compactedThroughSequence: 0, compactionCount: 0,
  previousProviderUsage: { prompt_tokens: 4400, completion_tokens: 120, total_tokens: 4520 } };
const date = '2026-10-29T03:00:00Z';
const first = () => ({ id: 'session-1', title: '검증 계획', modelId: 'deepseek-chat', createdAt: date, updatedAt: date,
  summary: '', compactedThroughSequence: 0, compactionCount: 0, context: { ...context },
  messages: Array.from({ length: 6 }, (_, index) => ({ id: `message-${index + 1}`, sequence: index + 1,
    role: index % 2 ? 'assistant' : 'user', content: index === 1 ? malicious : `기록 ${index + 1}`, status: 'completed', metadata: {}, createdAt: date })) });

async function setup(t, options = {}) {
  const localChrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const browser = await chromium.launch({ headless: true,
    ...(process.platform === 'win32' && !existsSync(chromium.executablePath()) && existsSync(localChrome)
      ? { executablePath: localChrome } : {}) });
  t.after(() => browser.close());
  const page = await browser.newPage({ viewport: { width: 1450, height: 1050 } });
  const errors = []; const requests = []; let role = options.role || 'admin'; let count = 1;
  const sessions = new Map([['session-1', first()]]);
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => { window.EventSource = undefined; window.chatInjected = false; });
  await page.route('**/*', async route => {
    const file = new URL(route.request().url()).pathname.split('/').pop() || 'index.html';
    if (!/^[a-z-]+\.(?:html|js|css|svg)$/.test(file)) return route.fulfill({ status: 404, body: '' });
    const body = await readFile(new URL(`../dist/${file}`, import.meta.url));
    return route.fulfill({ contentType: ({ html: 'text/html', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' })[file.split('.').pop()], body });
  });
  await page.route('**/api/**', async route => {
    const request = route.request(); const url = new URL(request.url()); const path = url.pathname; const method = request.method();
    const json = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) }).catch(() => {});
    if (path.startsWith('/api/chat/')) requests.push({ path, query: url.searchParams.toString(), method, body: request.postData() ? request.postDataJSON() : undefined, csrf: request.headers()['x-csrf-token'] });
    if (path === '/api/auth/session') return json({ authenticated: true, authRequired: false, user: { role, name: 'Test' }, csrfToken: 'csrf-test' });
    if (path === '/api/state') return json({ instanceId: 'chat-test', mode: idle.mode, run: idle, lab: { available: false } });
    if (path === '/api/models') return json({ models: [{ id: 'rule-baseline', name: 'Rule', available: true }] });
    if (path === '/api/platform') return json({ source: {}, modules: [] });
    if (path === '/api/ci-results') return json({ runs: [] });
    if (path === '/api/runs') return json({ runs: [{ ...idle, status: 'completed', startedAt: date, target: 'http://lab.example/', id: 'run-1' }], total: 1 });
    if (path === '/api/chat/models') return json({ models: [
      { id: 'deepseek-chat', name: 'DeepSeek Chat', available: !options.unavailable, reason: options.unavailable ? 'API 키가 설정되지 않았습니다.' : null },
      { id: 'deepseek-reasoner', name: 'DeepSeek Reasoner', available: !options.unavailable },
    ] });
    if (path === '/api/chat/sessions' && method === 'GET') return json({ sessions: [...sessions.values()].map(session => ({ ...session, messages: undefined, messageCount: session.messages.length })) });
    if (path === '/api/chat/sessions' && method === 'POST') {
      const body = request.postDataJSON(); const session = { id: `session-${++count}`, title: '새 대화', modelId: body.modelId, createdAt: date, updatedAt: date, messages: [], context: { ...context, estimatedInputTokens: 0, percentage: 0 } };
      sessions.set(session.id, session); return json({ session });
    }
    const match = path.match(/^\/api\/chat\/sessions\/([^/]+)(?:\/(messages|compact))?$/);
    if (match) {
      const session = sessions.get(match[1]); if (!session) return json({ error: '대화가 없습니다.' }, 404);
      if (match[2] === 'messages') {
        if (options.messageDelay) await new Promise(resolve => setTimeout(resolve, options.messageDelay));
        if (options.failSend) return json({ error: '모델 요청이 지연되었습니다. 다시 시도하세요.' }, 504);
        const body = request.postDataJSON();
        session.messages.push({ id: `user-${session.messages.length}`, sequence: session.messages.length + 1, role: 'user', content: body.content, metadata: { files: body.files.map(path => ({ path })), runId: body.runId }, status: 'completed', createdAt: date });
        session.messages.push({ id: `assistant-${session.messages.length}`, sequence: session.messages.length + 1, role: 'assistant', content: `검토 결과\n\`\`\`html\n${malicious}\n\`\`\``, status: 'completed', createdAt: date });
        session.compactionCount = 1; session.compactedThroughSequence = 2; session.summary = '이전 대화 요약';
        session.context = { ...context, estimatedInputTokens: 3200, percentage: 40, compactionCount: 1, compactedThroughSequence: 2 };
      } else if (match[2] === 'compact') {
        session.compactionCount = 2; session.compactedThroughSequence = 4; session.summary = '수동 압축 요약';
        session.context = { ...context, estimatedInputTokens: 1400, percentage: 18, compactionCount: 2, compactedThroughSequence: 4 };
      } else if (method === 'PATCH') Object.assign(session, request.postDataJSON());
      else if (method === 'DELETE') { sessions.delete(session.id); return json({ deleted: true }); }
      return json({ session });
    }
    if (path === '/api/chat/files') {
      const folder = url.searchParams.get('path') || '';
      return json({ path: folder, rootLabel: 'CA3P', entries: folder ? [{ name: 'example.js', path: 'agent/example.js', type: 'file', size: 120 }] : [{ name: 'agent', path: 'agent', type: 'directory' }, { name: 'README.md', path: 'README.md', type: 'file', size: 33 }] });
    }
    if (path === '/api/chat/file') return json({ path: url.searchParams.get('path'), content: `const text = '${malicious}';`, size: 120, sha256: 'a'.repeat(64), language: 'javascript', truncated: false });
    return json({});
  });
  await page.goto('http://ca3p.invalid/#workspace/chat');
  await page.waitForFunction(() => document.querySelector('#chat-session-title')?.textContent === '검증 계획');
  return { page, requests, errors, sessions, setRole(value) { role = value; } };
}

test('workspace chat manages private sessions, models, context, safe file attachments and message history', async t => {
  const { page, requests, errors } = await setup(t);
  assert.equal(new URL(page.url()).hash, '#workspace/chat');
  assert.equal(await page.locator('#view-chat').isVisible(), true);
  assert.equal(await page.locator('#breadcrumb-group').textContent(), 'Workspace');
  assert.match(await page.locator('#chat-context-label').textContent(), /5,100 \/ 8,000.*64%/);
  assert.equal(await page.locator('#chat-context-meter').getAttribute('aria-valuenow'), '64');
  assert.match(await page.locator('#chat-provider-usage').textContent(), /실측.*4,400.*120/);
  assert.equal(await page.locator('#chat-messages img').count(), 0);
  assert.equal(await page.evaluate(() => window.chatInjected), false);
  assert.match(await page.locator('#chat-messages').textContent(), /<img src=x onerror=/);

  await page.locator('#chat-open-files').click();
  await page.locator('[data-file-path="agent"]').click();
  await page.locator('[data-file-path="agent/example.js"]').click();
  assert.match(await page.locator('#chat-file-breadcrumb').textContent(), /CA3P.*agent/);
  await page.waitForFunction(() => document.querySelector('#chat-file-content')?.textContent.includes('const text'));
  assert.equal(await page.locator('#chat-file-content img').count(), 0);
  assert.equal(await page.evaluate(() => window.chatInjected), false);
  if (process.env.CA3P_UI_PREVIEW) await page.screenshot({ path: process.env.CA3P_UI_PREVIEW.replace(/\.png$/i, '-files.png'), animations: 'disabled' });
  await page.locator('#chat-attach-file').click();
  assert.match(await page.locator('#chat-attachments').textContent(), /agent\/example.js/);
  await page.locator('#chat-run-select').selectOption('run-1');
  await page.locator('#chat-message-input').fill('코드를 검토해줘');
  await page.locator('#chat-message-input').press('Shift+Enter');
  assert.match(await page.locator('#chat-message-input').inputValue(), /\n$/);
  await page.locator('#chat-message-input').press('Enter');
  await page.waitForFunction(() => document.querySelectorAll('.chat-message').length === 8);
  const send = requests.find(item => item.path.endsWith('/messages'));
  assert.deepEqual(send.body, { content: '코드를 검토해줘', files: ['agent/example.js'], runId: 'run-1' });
  assert.equal(send.csrf, 'csrf-test');
  assert.equal(await page.locator('#chat-message-input').inputValue(), '');
  assert.match(await page.locator('#chat-attachments').textContent(), /agent\/example.js/);
  assert.equal(await page.locator('#chat-run-select').inputValue(), 'run-1');
  assert.match(await page.locator('#chat-summary-label').textContent(), /1회/);
  assert.equal(await page.locator('.chat-code img').count(), 0);
  assert.match(await page.locator('.chat-code').textContent(), /<img src=x/);
  await page.locator('#chat-compact').click();
  await page.waitForFunction(() => document.querySelector('#chat-summary')?.textContent === '수동 압축 요약');
  assert.equal(await page.locator('#chat-context-meter').getAttribute('aria-valuenow'), '18');
  assert.equal(await page.locator('.chat-compacted-label').count(), 4);

  await page.locator('#chat-model-select').selectOption('deepseek-reasoner');
  await page.waitForFunction(() => document.querySelector('#chat-model-select')?.value === 'deepseek-reasoner' && !document.querySelector('#chat-model-select').disabled);
  assert.deepEqual(requests.find(item => item.method === 'PATCH')?.body, { modelId: 'deepseek-reasoner' });
  await page.locator('#chat-rename-session').click();
  await page.locator('#chat-rename-input').fill(malicious);
  await page.locator('#chat-rename-form button[type=submit]').click();
  await page.waitForFunction(value => document.querySelector('#chat-session-title')?.textContent === value, malicious);
  assert.equal(await page.locator('#chat-session-title img').count(), 0);
  assert.equal(await page.locator('#chat-session-list img').count(), 0);
  await page.locator('#chat-rename-session').click();
  await page.locator('#chat-rename-input').fill('코드 입력 검증 검토');
  await page.locator('#chat-rename-form button[type=submit]').click();
  await page.waitForFunction(() => document.querySelector('#chat-session-title')?.textContent === '코드 입력 검증 검토');

  await page.locator('#chat-new-session').click();
  await page.waitForFunction(() => document.querySelector('#chat-session-title')?.textContent === '새 대화');
  assert.equal(await page.locator('#chat-attachments').textContent(), '');
  assert.equal(await page.locator('#chat-run-select').inputValue(), '');
  assert.equal(await page.locator('.chat-message').count(), 0);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  if (process.env.CA3P_UI_PREVIEW) {
    await page.setViewportSize({ width: 1450, height: 1450 });
    await page.evaluate(() => scrollTo(0, 0));
    await page.screenshot({ path: process.env.CA3P_UI_PREVIEW.replace(/\.png$/i, '-desktop.png'), animations: 'disabled' });
  }
  await page.locator('#chat-message-input').fill('아직 보내지 않은 초안');
  await page.locator('[data-chat-session="session-1"]').click();
  await page.waitForFunction(() => document.querySelectorAll('.chat-message').length === 8);
  assert.match(await page.locator('#chat-attachments').textContent(), /agent\/example.js/);
  await page.locator('[data-chat-session="session-2"]').click();
  await page.waitForFunction(() => document.querySelector('#chat-message-input')?.value === '아직 보내지 않은 초안');
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#chat-delete-session').click();
  await page.waitForFunction(() => document.querySelector('#chat-session-count')?.textContent === '1');
  assert.equal(requests.some(item => item.method === 'DELETE' && item.path.endsWith('session-2')), true);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('[data-chat-session="session-1"]').click();
  await page.waitForFunction(() => document.querySelectorAll('.chat-message').length === 8);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  if (process.env.CA3P_UI_PREVIEW) { await page.evaluate(() => scrollTo(0, 0)); await page.screenshot({ path: process.env.CA3P_UI_PREVIEW, fullPage: true, animations: 'disabled' }); }
  assert.deepEqual(errors, []);
});

test('chat viewer can read but cannot create, send, modify, compact or attach local files', async t => {
  const { page, requests, errors } = await setup(t, { role: 'viewer' });
  assert.equal(await page.locator('#chat-readonly').isVisible(), true);
  for (const id of ['chat-new-session', 'chat-send', 'chat-compact', 'chat-rename-session', 'chat-delete-session', 'chat-message-input', 'chat-model-select', 'chat-open-files', 'chat-run-select']) {
    assert.equal(await page.locator(`#${id}`).isDisabled(), true, `${id} must require operator access`);
  }
  assert.match(await page.locator('#chat-messages').textContent(), /기록 1/);
  assert.equal(requests.some(item => item.method !== 'GET'), false);
  assert.deepEqual(errors, []);
});

test('chat handles model availability, provider failures and cancellation without losing drafts', async t => {
  const failed = await setup(t, { failSend: true, messageDelay: 100 });
  await failed.page.locator('#chat-message-input').fill('재시도할 메시지');
  await failed.page.locator('#chat-send').click();
  await failed.page.locator('#chat-busy').waitFor({ state: 'visible' });
  assert.equal(await failed.page.locator('#chat-new-session').isDisabled(), true);
  await failed.page.waitForFunction(() => document.querySelector('#chat-error')?.textContent.includes('지연'));
  assert.equal(await failed.page.locator('#chat-message-input').inputValue(), '재시도할 메시지');
  assert.equal(await failed.page.locator('#chat-send').isEnabled(), true);
  await failed.page.locator('#chat-send').click();
  await failed.page.locator('#chat-busy').waitFor({ state: 'visible' });
  await failed.page.locator('#chat-cancel').click();
  await failed.page.waitForFunction(() => document.querySelector('#chat-error')?.textContent.includes('중지'));
  assert.equal(await failed.page.locator('#chat-message-input').inputValue(), '재시도할 메시지');
  assert.equal(await failed.page.locator('#chat-send').isEnabled(), true);
  const unavailable = await setup(t, { unavailable: true });
  await unavailable.page.locator('#chat-message-input').fill('메시지');
  assert.match(await unavailable.page.locator('#chat-model-status').textContent(), /API 키/);
  assert.equal(await unavailable.page.locator('#chat-send').isDisabled(), true);
  assert.equal(await unavailable.page.locator('#chat-new-session').isDisabled(), true);
  assert.deepEqual([...failed.errors, ...unavailable.errors], []);
});
