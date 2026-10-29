import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';

const { chromium } = createRequire(new URL('../../packages/report/capture/package.json', import.meta.url))('playwright');

test('saved external Web Parser results appear in Reports and the module activity view', async t => {
  const browser = await chromium.launch({ headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => { window.EventSource = undefined; });
  const time = '2026-10-30T00:00:00.000Z';
  const run = {
    id: 'external-parser-ui', mode: 'external-general', status: 'completed',
    target: 'https://example.org/', startedAt: time, elapsedMs: 100,
    events: [{ id: 'parser-event', time, module: 'web-parser', stage: 'parser.observe',
      title: '웹 기술 식별' }], snapshots: {}, reviewItems: [],
    report: { schemaVersion: 'general-assessment/1', assessmentMode: 'general',
      inspectionMode: 'external-read-only', target: { kind: 'external', origin: 'https://example.org' },
      scope: { origin: 'https://example.org', pathPrefix: '/', methods: ['GET'], maxRequests: 8 },
      inventory: { pages: [{ url: 'https://example.org/', status: 200, contentType: 'text/html',
        parser: { status: 'observed', mode: 'http-response',
          technologies: [{ name: 'Express', version: '4', evidenceFields: ['headers'] }],
          libraries: [{ name: 'jQuery', version: '3.6.0', evidenceFields: ['scriptSrc'] }] } }] },
      coverage: { observedPages: 1, requestsUsed: 1, rejectedCandidates: 0 },
      findings: [], hypotheses: [], probes: [], evidence: [], modelCalls: [], observationErrors: [],
    },
  };
  await page.route('**/*', async route => {
    try {
      const file = new URL(route.request().url()).pathname.split('/').pop() || 'index.html';
      if (!/^[a-z-]+\.(?:html|js|css|svg)$/.test(file)) return route.fulfill({ status: 404, body: '' });
      const bytes = await readFile(new URL(`../dist/${file}`, import.meta.url));
      return route.fulfill({ contentType: ({ html: 'text/html', js: 'text/javascript',
        css: 'text/css', svg: 'image/svg+xml' })[file.split('.').pop()], body: bytes });
    } catch { return route.fulfill({ status: 404, body: '' }); }
  });
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    const json = value => route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) });
    if (path === '/api/auth/session') return json({ authenticated: true, authRequired: false,
      user: { role: 'operator', name: 'Test' } });
    if (path === '/api/state') return json({ instanceId: 'external-parser-ui', mode: run.mode, run,
      lab: { available: true, externalSupported: true } });
    if (path === '/api/runs') return json({ runs: [run], total: 1 });
    if (path === '/api/models') return json({ models: [] });
    if (path === '/api/platform') return json({ source: {}, modules: [] });
    if (path === '/api/ci-results') return json({ runs: [] });
    return json({});
  });
  await page.goto('http://ca3p.invalid/#workspace/reports');
  await page.getByText('Web Parser · HTTP 응답 지문').waitFor();
  assert.match(await page.locator('#report-content').textContent(), /jQuery 3\.6\.0/);
  assert.match(await page.locator('#report-content').textContent(), /Express 4/);
  await page.locator('[data-view=modules]').click();
  assert.match(await page.locator('#module-grid').textContent(), /Web Parser/);
  assert.match(await page.locator('#module-grid').textContent(), /EXTERNAL HTTP/);
  assert.deepEqual(errors, []);
});
