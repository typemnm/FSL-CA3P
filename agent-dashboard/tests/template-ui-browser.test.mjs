import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';

const { chromium } = createRequire(new URL('../../packages/report/capture/package.json', import.meta.url))('playwright');
const builtin = JSON.parse(await readFile(new URL('../../attack-tool/templates/sqli-like-tautology.json', import.meta.url), 'utf8'));

async function setup(t, role = 'admin') {
  const chrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const browser = await chromium.launch({ headless: true,
    ...(process.platform === 'win32' && !existsSync(chromium.executablePath()) && existsSync(chrome) ? { executablePath: chrome } : {}) });
  t.after(() => browser.close());
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [], writes = [];
  const reference = { ...builtin, templateId: 'reference-only', title: '<img src=x onerror=alert(1)>',
    description: '설명 <script>alert(1)</script>', payloads: ['<script>alert(1)</script>'], verify: { mode: 'responseText' } };
  const items = new Map([builtin, reference].map(item => [item.templateId, structuredClone(item)]));
  const revisions = new Map([...items.keys()].map(id => [id, 'revision-1']));
  let conflict = false;
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => { window.EventSource = undefined; });
  await page.route('**/*', async route => {
    try {
      const filename = new URL(route.request().url()).pathname.split('/').pop() || 'index.html';
      if (!/^[a-z-]+\.(?:html|js|css|svg)$/.test(filename)) return route.fulfill({ status: 404, body: '' });
      const body = await readFile(new URL(`../dist/${filename}`, import.meta.url));
      return route.fulfill({ contentType: ({ html: 'text/html', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' })[filename.split('.').pop()], body });
    } catch { return route.fulfill({ status: 404, body: '' }); }
  });
  await page.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    const reply = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
    const support = item => ({ supported: item.verify.mode === 'resultCount', reason: item.verify.mode === 'resultCount' ? '대상별 정책 적용' : '지원하지 않는 검증 방식입니다.' });
    if (request.method() !== 'GET') writes.push({ path, method: request.method(), body: request.postDataJSON(), csrf: request.headers()['x-csrf-token'] });
    if (path === '/api/auth/session') return reply({ authenticated: true, authRequired: true, user: { role, name: 'Template tester' }, csrfToken: 'csrf-template' });
    if (path === '/api/state') return reply({ instanceId: 'template-ui', mode: 'core-fixture', lab: { available: false },
      run: { id: null, mode: 'core-fixture', status: 'idle', events: [], snapshots: {}, reviewItems: [], totalSteps: 19, step: 0 } });
    if (path === '/api/runs') return reply({ runs: [], total: 0 });
    if (path === '/api/models') return reply({ models: [] });
    if (path === '/api/platform') return reply({ source: {}, modules: [] });
    if (path === '/api/ci-results') return reply({ runs: [] });
    if (path === '/api/attack-templates' && request.method() === 'GET') return reply({ templates: [...items.values()], total: items.size,
      executionSupport: Object.fromEntries([...items].map(([id, item]) => [id, support(item)])), revisions: Object.fromEntries(revisions) });
    if (path === '/api/attack-templates' && request.method() === 'POST') {
      const body = request.postDataJSON();
      if (body.templates.some(item => !Array.isArray(item.payloads) || !item.payloads.length)) return reply({ error: 'templates[0].payloads: 최소 1개의 payload가 필요합니다.' }, 400);
      const created = body.templates.filter(item => !items.has(item.templateId)).length;
      const total = items.size + created;
      if (!body.dryRun) for (const item of body.templates) { items.set(item.templateId, item); revisions.set(item.templateId, 'revision-1'); }
      return reply({ created, unchanged: body.templates.length - created, total, dryRun: body.dryRun });
    }
    const match = /^\/api\/attack-templates\/([^/]+)$/.exec(path);
    if (match) {
      const id = decodeURIComponent(match[1]);
      if (!items.has(id)) return reply({ error: 'Template not found.' }, 404);
      const body = request.method() === 'GET' ? null : request.postDataJSON();
      if (request.method() === 'PUT') {
        if (conflict) { conflict = false; revisions.set(id, 'revision-newer'); return reply({ error: '다른 사용자가 수정했습니다. 최신 템플릿을 다시 불러오세요.' }, 409); }
        assert.equal(body.expectedRevision, revisions.get(id));
        items.set(id, body.template); revisions.set(id, 'revision-2');
      }
      if (request.method() === 'DELETE') {
        assert.equal(body.expectedRevision, revisions.get(id));
        items.delete(id); revisions.delete(id); return reply({ deleted: true, templateId: id });
      }
      return reply({ template: items.get(id), executionSupport: support(items.get(id)), revision: revisions.get(id) });
    }
    return reply({});
  });
  await page.goto('http://ca3p.invalid/#workspace/templates');
  await page.locator('[data-template-id="sqli-like-tautology"]').waitFor();
  return { page, errors, writes, items, revisions, setConflict: () => { conflict = true; } };
}

test('Workspace templates support direct JSON batch import, unverified evidence, safe browsing, edit conflicts and deletion', async t => {
  const { page, errors, writes, items, revisions, setConflict } = await setup(t);
  assert.equal(await page.locator('.primary-nav[aria-label="주 메뉴"] [data-view="templates"]').textContent(), '템플릿');
  assert.equal(await page.locator('#breadcrumb-group').textContent(), 'Workspace');
  assert.equal(await page.locator('[data-view="templates"]').getAttribute('aria-current'), 'page');
  assert.match(await page.locator('[data-template-id="sqli-like-tautology"]').textContent(), /검증되지 않은 템플릿/);
  await page.locator('[data-template-id="reference-only"]').click();
  await page.locator('#template-detail-title').waitFor();
  assert.match(await page.locator('.template-detail').textContent(), /참고용.*지원하지 않는 검증/s);
  assert.match(await page.locator('.template-detail').textContent(), /검증되지 않은 템플릿/);
  assert.match(await page.locator('.template-detail').textContent(), /근거/);
  assert.match(await page.locator('.template-detail').textContent(), /실행.*검증|검증.*실행/s);
  assert.equal(await page.locator('#workspace-templates-content img, #workspace-templates-content script').count(), 0);
  assert.match(await page.locator('.template-payloads').textContent(), /<script>alert\(1\)<\/script>/);
  await page.locator('#template-query').fill('nonexistent');
  assert.match(await page.locator('#template-list').textContent(), /검색 조건에 맞는 템플릿이 없습니다/);
  await page.locator('#template-query').fill('');
  await page.locator('[data-template-action="new"]').click();
  assert.equal(await page.locator('[data-template-action="validate"]').count(), 0);
  assert.equal(await page.locator('#template-editor-form [type="submit"]').isDisabled(), true);
  await page.locator('#template-json-input').fill(' \n ');
  assert.equal(await page.locator('#template-editor-form [type="submit"]').isDisabled(), true);
  const batch = ['new-a', 'new-b'].map(templateId => ({ ...builtin, templateId }));
  await page.locator('#template-json-file').setInputFiles({ name: 'templates.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(batch)) });
  await page.waitForFunction(() => document.getElementById('template-json-input').value.includes('new-a'));
  assert.equal(writes.length, 0);
  assert.equal(await page.locator('#template-editor-form [type="submit"]').isDisabled(), false);
  assert.equal(items.size, 2);
  await page.locator('#template-json-input').fill(JSON.stringify(batch, null, 2) + '\n');
  assert.equal(await page.locator('#template-editor-form [type="submit"]').isDisabled(), false);
  await page.locator('#template-editor-form [type="submit"]').click();
  await page.locator('[data-template-id="new-a"]').waitFor();
  assert.equal(items.size, 4);
  assert.deepEqual(writes, [{ path: '/api/attack-templates', method: 'POST', body: { templates: batch, dryRun: false }, csrf: 'csrf-template' }]);
  assert.match(await page.locator('[data-template-id="new-a"]').textContent(), /검증되지 않은 템플릿/);
  await page.locator('[data-template-id="new-a"]').click();
  await page.locator('#template-detail-title').waitFor();
  assert.match(await page.locator('.template-detail').textContent(), /검증되지 않은 템플릿/);
  assert.match(await page.locator('.template-detail').textContent(), /근거/);
  await page.locator('[data-template-action="edit"]').click();
  const changed = { ...batch[0], title: '검토한 템플릿', description: '수정한 설명' };
  await page.locator('#template-json-input').fill(JSON.stringify(changed));
  await page.locator('[data-template-id="new-b"]').click();
  assert.match(await page.locator('#template-error').textContent(), /수정 내용을 저장하거나 편집기를 닫은 후/);
  assert.equal(await page.locator('[data-template-id="new-a"]').getAttribute('aria-pressed'), 'true');
  assert.equal(await page.locator('#template-detail-title').textContent(), 'new-a');
  assert.deepEqual(JSON.parse(await page.locator('#template-json-input').inputValue()), changed);
  setConflict();
  await page.locator('#template-editor-form [type="submit"]').click();
  await page.locator('#template-error').waitFor();
  assert.match(await page.locator('#template-error').textContent(), /다른 사용자가 수정/);
  assert.match(await page.locator('#template-error').textContent(), /입력 내용은 유지됩니다.*편집기를 닫고/);
  assert.deepEqual(JSON.parse(await page.locator('#template-json-input').inputValue()), changed);
  assert.equal(items.get('new-a').title, undefined);
  await page.locator('[data-template-action="refresh"]').click();
  await page.waitForFunction(() => !document.querySelector('[data-template-action="refresh"]').disabled);
  assert.deepEqual(JSON.parse(await page.locator('#template-json-input').inputValue()), changed);
  assert.equal(await page.locator('#template-detail-title').textContent(), 'new-a');
  await page.locator('[data-template-action="close-editor"]').click();
  await page.locator('[data-template-id="new-a"]').click();
  await page.locator('#template-detail-title').waitFor();
  await page.locator('[data-template-action="edit"]').click();
  await page.locator('#template-json-input').fill(JSON.stringify(changed));
  await page.locator('#template-editor-form [type="submit"]').click();
  await page.waitForFunction(() => document.getElementById('template-detail-title')?.textContent === '검토한 템플릿');
  assert.equal(writes.at(-1).body.expectedRevision, 'revision-newer');
  assert.equal(writes.at(-1).method, 'PUT');
  items.set('new-a', { ...changed, title: '다른 관리자가 갱신한 템플릿' });
  revisions.set('new-a', 'revision-3');
  await page.locator('[data-template-action="refresh"]').click();
  await page.waitForFunction(() => document.getElementById('template-detail-title')?.textContent === '다른 관리자가 갱신한 템플릿');
  assert.equal(await page.locator('[data-template-id="new-a"]').getAttribute('aria-pressed'), 'true');
  if (process.env.CA3P_TEMPLATE_UI_PREVIEW) {
    await page.evaluate(() => { document.activeElement?.blur(); window.scrollTo(0, 0); });
    await page.screenshot({ path: process.env.CA3P_TEMPLATE_UI_PREVIEW, fullPage: true });
  }
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.locator('[data-template-action="delete"]').click();
  assert.equal(items.size, 4);
  await page.locator('[data-template-action="confirm-delete"]').click();
  await page.waitForFunction(() => !document.querySelector('[data-template-id="new-a"]'));
  assert.equal(items.size, 3);
  assert.deepEqual(writes.at(-1), { path: '/api/attack-templates/new-a', method: 'DELETE', body: { expectedRevision: 'revision-3' }, csrf: 'csrf-template' });
  await page.locator('[data-view="module-attack"]').click();
  await page.locator('a[href="#workspace/templates"]').waitFor();
  await page.locator('a[href="#workspace/templates"]').click();
  await page.locator('#view-templates').waitFor({ state: 'visible' });
  assert.deepEqual(errors, []);
});

test('direct registration preserves invalid JSON for correction and viewers have browse controls only', async t => {
  const admin = await setup(t);
  await admin.page.locator('[data-template-action="new"]').click();
  const invalidSource = JSON.stringify({ ...builtin, templateId: 'correctable-template', payloads: [] });
  await admin.page.locator('#template-json-input').fill(invalidSource);
  assert.equal(await admin.page.locator('#template-editor-form [type="submit"]').isDisabled(), false);
  await admin.page.locator('#template-editor-form [type="submit"]').click();
  await admin.page.locator('#template-error').waitFor();
  assert.match(await admin.page.locator('#template-error').textContent(), /templates\[0\]\.payloads/);
  assert.equal(await admin.page.locator('#template-json-input').inputValue(), invalidSource);
  assert.equal(await admin.page.locator('#template-editor-form [type="submit"]').isDisabled(), false);
  assert.equal(admin.items.has('correctable-template'), false);
  const corrected = { ...builtin, templateId: 'correctable-template' };
  await admin.page.locator('#template-json-input').fill(JSON.stringify(corrected));
  await admin.page.locator('#template-editor-form [type="submit"]').click();
  await admin.page.locator('[data-template-id="correctable-template"]').waitFor();
  assert.deepEqual(admin.items.get('correctable-template'), corrected);
  assert.equal(admin.writes.length, 2);
  assert.equal(admin.writes.every(write => write.method === 'POST' && write.body.dryRun === false), true);
  const viewer = await setup(t, 'viewer');
  assert.equal(await viewer.page.locator('[data-template-action="new"]').count(), 0);
  await viewer.page.locator('[data-template-id="sqli-like-tautology"]').click();
  await viewer.page.locator('#template-detail-title').waitFor();
  assert.equal(await viewer.page.locator('[data-template-action="edit"], [data-template-action="delete"]').count(), 0);
  assert.equal(await viewer.page.locator('[data-template-action="download"]').count(), 1);
  assert.match(await viewer.page.locator('.template-detail').textContent(), /검증되지 않은 템플릿/);
  assert.deepEqual(viewer.writes, []);
  assert.deepEqual([...admin.errors, ...viewer.errors], []);
});

test('copying a template registers a new unverified template without a validation request', async t => {
  const { page, writes, items, errors } = await setup(t);
  await page.locator('[data-template-id="sqli-like-tautology"]').click();
  await page.locator('#template-detail-title').waitFor();
  await page.locator('[data-template-action="copy"]').click();
  assert.equal(await page.locator('[data-template-action="validate"]').count(), 0);
  assert.equal(await page.locator('#template-editor-form [type="submit"]').isDisabled(), false);
  const copied = { ...builtin, templateId: 'sqli-like-tautology-copy' };
  assert.deepEqual(JSON.parse(await page.locator('#template-json-input').inputValue()), [copied]);
  await page.locator('#template-editor-form [type="submit"]').click();
  await page.locator('[data-template-id="sqli-like-tautology-copy"]').waitFor();
  assert.deepEqual(writes, [{ path: '/api/attack-templates', method: 'POST', body: { templates: [copied], dryRun: false }, csrf: 'csrf-template' }]);
  assert.deepEqual(items.get(copied.templateId), copied);
  assert.match(await page.locator('[data-template-id="sqli-like-tautology-copy"]').textContent(), /검증되지 않은 템플릿/);
  assert.deepEqual(errors, []);
});
