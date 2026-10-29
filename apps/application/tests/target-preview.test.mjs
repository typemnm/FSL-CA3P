import test from 'node:test';
import assert from 'node:assert/strict';
import { createTargetPreviewService } from '../target-preview.mjs';

const LAB = 'http://127.0.0.1:4101';

function labInfo(url) {
  return { target: { requestedUrl: url, finalUrl: url },
    navigation: { status: 200, contentType: 'text/html' },
    html: '<title>University</title><p>PRIVATE_BODY</p>',
    headers: [{ name: 'set-cookie', value: 'PRIVATE_COOKIE' }],
    cookies: [{ name: 'session', value: 'PRIVATE_COOKIE' }],
    technologies: [{ name: 'React', version: '19.0.0', categories: ['JavaScript frameworks'], confidence: 100,
      evidence: [{ value: 'PRIVATE_BODY' }] }],
    libraries: [{ name: 'jQuery', version: '3.6.0', evidence: [{ value: 'PRIVATE_BODY' }] }],
    structure: { forms: [{ action: '/apply?token=PRIVATE_VALUE', method: 'POST', fields: [{ name: 'name', type: 'text' }] }],
      links: [{ href: '/about' }, { href: 'http://169.254.169.254/latest' }] },
    paths: [{ url: `${LAB}/apply?token=PRIVATE_VALUE`, sources: ['form:action'] }], errors: [], truncated: false };
}

test('registered university preview returns a per-URL browser summary without raw body, cookies or cross-origin paths', async () => {
  const visited = [];
  const service = createTargetPreviewService({ universityOrigins: { 'vul-web2-daehan': LAB },
    labCollect: async url => { visited.push(url); return { info: labInfo(url) }; } });
  const first = await service.preview({ url: `${LAB}/` });
  assert.equal(first.targetKind, 'lab');
  assert.equal(first.fixtureId, 'vul-web2-daehan');
  assert.deepEqual(visited, [`${LAB}/`, `${LAB}/about`]);
  assert.equal(first.pages.length, 2);
  assert.deepEqual(first.crawl, { maxPages: 48, visited: 2, queued: 0,
    truncated: false, stopReason: null });
  assert.equal(first.pages[0].mode, 'browser');
  assert.equal(first.pages[0].status, 200);
  assert.equal(first.pages[0].technologies[0].name, 'React');
  assert.equal(first.pages[0].libraries[0].name, 'jQuery');
  assert.deepEqual(first.discoveredPaths.sort(), [`${LAB}/about`, `${LAB}/apply`].sort());
  assert.equal(JSON.stringify(first).includes('PRIVATE_BODY'), false);
  assert.equal(JSON.stringify(first).includes('PRIVATE_COOKIE'), false);
  assert.equal(JSON.stringify(first).includes('PRIVATE_VALUE'), false);
  const second = await service.preview({ url: `${LAB}/admissions`, previewId: first.previewId });
  assert.deepEqual(visited, [`${LAB}/`, `${LAB}/about`, `${LAB}/admissions`]);
  assert.equal(second.pages.length, 3);
  assert.equal((await service.preview({ url: `${LAB}/admissions`, previewId: first.previewId })).pages.length, 3);
  assert.deepEqual(visited, [`${LAB}/`, `${LAB}/about`, `${LAB}/admissions`]);
  await assert.rejects(service.preview({ url: 'http://127.0.0.1:4102/', previewId: first.previewId }),
    { code: 'PREVIEW_ORIGIN_MISMATCH' });
  second.pages[0].title = 'changed by caller';
  assert.equal(service.getPreview(first.previewId).pages[0].title, 'University');
});

test('preview shows indicator-only libraries without exposing resource URLs or bodies', async () => {
  const service = createTargetPreviewService({ universityOrigins: { 'vul-web2-daehan': LAB },
    labCollect: async url => {
      const info = labInfo(url);
      info.libraries = [{ name: 'Axios', version: '1.6.8', source: 'indicator',
        evidence: [{ field: 'resourceComment', key: `${LAB}/vendor.js?token=PRIVATE` }] }];
      return { info };
    } });
  const result = await service.preview({ url: `${LAB}/` });
  assert.deepEqual(result.pages[0].libraries, [{ name: 'Axios', version: '1.6.8', source: 'indicator',
    evidenceFields: ['resourceComment'] }]);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE|vendor\.js/u);
});

test('external preview fingerprints one pinned GET response without launching the browser', async () => {
  const requests = [];
  const service = createTargetPreviewService({ universityOrigins: { 'vul-web2-daehan': LAB },
    labCollect: () => { throw new Error('Browser must not run for external URLs.'); },
    externalRequest: async (url, options) => {
      requests.push({ url, method: options.method, scope: options.scope });
      return { status: 200, contentType: 'text/html', contentEncoding: 'identity', truncated: false,
        headers: [{ name: 'content-type', value: 'text/html' }],
        body: '<title>Public site</title><a href="/docs">Docs</a>'
          + '<a href="http://127.0.0.1/admin">internal</a>'
          + '<a href="/signed?token=PRIVATE">signed</a>PRIVATE_BODY' };
    },
    externalFingerprint: async () => ({ technologies: [{ name: 'Nginx', version: '1.25' }],
      libraries: [{ name: 'jQuery', version: '3.6.0', evidenceFields: ['scriptSrc'] }] }) });
  const result = await service.preview({ url: 'https://8.8.8.8/start' });
  assert.equal(result.targetKind, 'external');
  assert.equal(result.fixtureId, null);
  assert.equal(result.pages[0].mode, 'http-response');
  assert.equal(result.pages.length, 2);
  assert.deepEqual(result.crawl, { maxPages: 8, visited: 2, queued: 0,
    truncated: false, stopReason: null });
  assert.deepEqual(result.pages[0].forms, []);
  assert.deepEqual(result.discoveredPaths, ['https://8.8.8.8/docs']);
  assert.equal(result.pages[0].libraries[0].name, 'jQuery');
  assert.deepEqual(requests.map(item => [item.url, item.method, item.scope.origin]),
    [['https://8.8.8.8/start', 'GET', 'https://8.8.8.8'],
      ['https://8.8.8.8/docs', 'GET', 'https://8.8.8.8']]);
  assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
  await assert.rejects(service.preview({ url: 'http://127.0.0.1:4999/' }), { code: 'EXTERNAL_ADDRESS_BLOCKED' });
  assert.deepEqual(requests.map(item => item.url), ['https://8.8.8.8/start', 'https://8.8.8.8/docs']);
});

test('external forms and static links cannot fill the display cap before a later page link', async () => {
  const requested = [];
  const service = createTargetPreviewService({ universityOrigins: {},
    externalRequest: async url => {
      requested.push(url);
      return { status: 200, contentType: 'text/html', contentEncoding: 'identity', truncated: false,
        body: url.endsWith('/start')
          ? Array.from({ length: 70 }, (_, index) => `<form action="/submit/${index}"></form>`).join('')
            + Array.from({ length: 70 }, (_, index) => `<a href="/static/${index}.css">asset</a>`).join('')
            + '<a href="/docs">docs</a>'
          : '<title>docs</title>' };
    },
    externalFingerprint: async () => ({ technologies: [], libraries: [] }) });
  const result = await service.preview({ url: 'https://8.8.8.8/start' });
  assert.deepEqual(requested, ['https://8.8.8.8/start', 'https://8.8.8.8/docs']);
  assert.ok(result.pages[0].paths.some(path => path.url === 'https://8.8.8.8/docs'));
  assert.equal(result.pages[0].paths.length, 60);
  assert.equal(result.pages[0].truncated, true);
  assert.deepEqual(result.crawl, { maxPages: 8, visited: 2, queued: 0,
    truncated: false, stopReason: null });
});

test('out-of-scope lab redirects and unsupported external encodings stay visible as failed pages', async () => {
  const lab = createTargetPreviewService({ universityOrigins: { 'vul-web2-daehan': LAB },
    labCollect: async url => ({ info: { ...labInfo(url),
      target: { requestedUrl: url, finalUrl: 'https://elsewhere.example/' } } }) });
  const labResult = await lab.preview({ url: `${LAB}/` });
  assert.equal(labResult.pages.length, 1);
  assert.deepEqual(labResult.pages[0].errors, [{ code: 'REDIRECT_OUT_OF_SCOPE' }]);
  assert.deepEqual(labResult.crawl, { maxPages: 48, visited: 1, queued: 0,
    truncated: false, stopReason: null });

  const external = createTargetPreviewService({ universityOrigins: {},
    externalRequest: async () => ({ status: 200, contentType: 'text/html',
      contentEncoding: 'gzip', body: '<a href="/next">next</a>' }),
    externalFingerprint: () => { throw new Error('Fingerprint must not run.'); } });
  const externalResult = await external.preview({ url: 'https://8.8.8.8/start' });
  assert.equal(externalResult.pages.length, 1);
  assert.deepEqual(externalResult.pages[0].errors,
    [{ code: 'EXTERNAL_CONTENT_ENCODING_UNSUPPORTED' }]);
  assert.equal(externalResult.crawl.visited, 1);
});

test('a failed URL remains visible, a later successful path stays available, and sessions expire', async () => {
  let now = Date.parse('2026-10-30T00:00:00Z');
  let fail = true;
  const service = createTargetPreviewService({ universityOrigins: { 'vul-web2-daehan': LAB }, clock: () => now,
    labCollect: async url => {
      if (fail) throw Object.assign(new Error('navigation failed'), { code: 'NAVIGATION_FAILED' });
      return { info: labInfo(url) };
    } });
  const first = await service.preview({ url: `${LAB}/unavailable` });
  assert.equal(first.pages[0].status, null);
  assert.deepEqual(first.pages[0].errors, [{ code: 'NAVIGATION_FAILED' }]);
  fail = false;
  const second = await service.preview({ url: `${LAB}/about`, previewId: first.previewId });
  assert.deepEqual(second.pages.map(page => page.status), [null, 200]);
  now += 15 * 60_000;
  assert.equal(service.getPreview(first.previewId), null);
  await assert.rejects(service.preview({ url: `${LAB}/about`, previewId: first.previewId }),
    { code: 'PREVIEW_NOT_FOUND' });
});

test('one click crawls linked HTML paths but never auto-GETs forms, XHR, static assets or action links', async () => {
  const visited = [];
  const rootPaths = [
    ['view', 'link'], ['logout', 'link'], ['delete/1', 'link'], ['assets/app.js', 'link'],
    ['apply', 'form'], ['api/data', 'request:xhr'],
  ].map(([path, source]) => ({ url: `${LAB}/${path}`, sources: [source] }));
  const service = createTargetPreviewService({ universityOrigins: { 'vul-web2-daehan': LAB },
    labCollect: async url => {
      visited.push(url);
      const info = labInfo(url);
      info.structure.links = [];
      info.structure.forms = [{ action: `${LAB}/apply`, method: 'POST', fields: [] }];
      info.paths = url === `${LAB}/` ? rootPaths
        : url === `${LAB}/view` ? [{ url: `${LAB}/nested`, sources: ['link'] }] : [];
      return { info };
    } });
  const result = await service.preview({ url: `${LAB}/` });
  assert.deepEqual(visited, [`${LAB}/`, `${LAB}/view`, `${LAB}/nested`]);
  assert.deepEqual(result.pages.map(page => page.url), visited);
  assert.deepEqual(result.crawl, { maxPages: 48, visited: 3, queued: 0,
    truncated: false, stopReason: null });
});

test('repeated links and static resource display limits do not hide later page candidates', async () => {
  const visited = [];
  const service = createTargetPreviewService({ universityOrigins: { 'vul-web2-daehan': LAB },
    labCollect: async url => {
      visited.push(url);
      const info = labInfo(url);
      info.structure.forms = [];
      info.structure.links = url === `${LAB}/` ? [
        ...Array.from({ length: 100 }, () => ({ href: `${LAB}/same` })),
        { href: `${LAB}/late` },
      ] : [];
      info.paths = url === `${LAB}/` ? Array.from({ length: 60 }, (_, index) => ({
        url: `${LAB}/assets/${index}.css`, sources: ['request:stylesheet'],
      })) : [];
      return { info };
    } });
  const result = await service.preview({ url: `${LAB}/` });
  assert.deepEqual(visited, [`${LAB}/`, `${LAB}/same`, `${LAB}/late`]);
  assert.equal(result.pages[0].paths.length, 60);
  assert.ok(result.pages[0].paths.some(path => path.url === `${LAB}/late`));
  assert.equal(result.pages[0].truncated, true);
  assert.deepEqual(result.crawl, { maxPages: 48, visited: 3, queued: 0,
    truncated: false, stopReason: null });
});

test('a failed discovered page does not stop later pages, while a page limit leaves explicit partial coverage', async () => {
  const visited = [];
  const service = createTargetPreviewService({ universityOrigins: { 'vul-web2-daehan': LAB },
    labCollect: async url => {
      visited.push(url);
      if (url === `${LAB}/page/0`) throw Object.assign(new Error('failed'), { code: 'NAVIGATION_FAILED' });
      const info = labInfo(url);
      info.structure.links = [];
      info.structure.forms = [];
      info.paths = url === `${LAB}/` ? Array.from({ length: 60 }, (_, index) => ({
        url: `${LAB}/page/${index}`, sources: ['link'],
      })) : [];
      return { info };
    } });
  const result = await service.preview({ url: `${LAB}/` });
  assert.equal(result.pages.length, 48);
  assert.deepEqual(result.pages.slice(0, 3).map(page => page.status), [200, null, 200]);
  assert.deepEqual(result.pages[1].errors, [{ code: 'NAVIGATION_FAILED' }]);
  assert.equal(visited.at(-1), `${LAB}/page/46`);
  assert.deepEqual(result.crawl, { maxPages: 48, visited: 48, queued: 13,
    truncated: true, stopReason: 'page-limit' });
});

test('time and long URL limits are reported without saving oversized discovered paths', async () => {
  let now = 0;
  const service = createTargetPreviewService({ universityOrigins: { 'vul-web2-daehan': LAB },
    clock: () => now,
    labCollect: async url => {
      now += url === `${LAB}/` ? 40_000 : 20_000;
      const info = labInfo(url);
      info.structure.links = [];
      info.structure.forms = [];
      info.paths = url === `${LAB}/` ? [
        { url: `${LAB}/a`, sources: ['link'] }, { url: `${LAB}/b`, sources: ['link'] },
        { url: `${LAB}/${'x'.repeat(1000)}`, sources: ['link'] },
      ] : [];
      return { info };
    } });
  const result = await service.preview({ url: `${LAB}/` });
  assert.deepEqual(result.pages.map(page => page.url), [`${LAB}/`, `${LAB}/a`]);
  assert.equal(result.pages[0].truncated, true);
  assert.equal(result.discoveredPaths.some(path => path.length > 512), false);
  assert.deepEqual(result.crawl, { maxPages: 48, visited: 2, queued: 1,
    truncated: true, stopReason: 'time-limit' });
  assert.ok(Buffer.byteLength(JSON.stringify(result)) < 20_000);
});

test('external auto crawl stops safely on DNS rebinding and does not visit remaining candidates', async () => {
  const requested = [];
  const service = createTargetPreviewService({ universityOrigins: {},
    externalRequest: async url => {
      requested.push(url);
      if (url.endsWith('/blocked')) throw Object.assign(new Error('rebound'), { code: 'EXTERNAL_DNS_REBIND' });
      return { status: 200, contentType: 'text/html', contentEncoding: 'identity', truncated: false,
        headers: [{ name: 'content-type', value: 'text/html' }],
        body: url.endsWith('/start')
          ? '<a href="/ok">ok</a><a href="/blocked">blocked</a><a href="/later">later</a>' : '<title>ok</title>' };
    },
    externalFingerprint: async () => ({ technologies: [], libraries: [] }) });
  const result = await service.preview({ url: 'https://8.8.8.8/start' });
  assert.deepEqual(requested, ['https://8.8.8.8/start', 'https://8.8.8.8/ok', 'https://8.8.8.8/blocked']);
  assert.deepEqual(result.pages.map(page => page.status), [200, 200, null]);
  assert.deepEqual(result.pages[2].errors, [{ code: 'EXTERNAL_DNS_REBIND' }]);
  assert.deepEqual(result.crawl, { maxPages: 8, visited: 3, queued: 1,
    truncated: true, stopReason: 'safety-block' });
});

test('aborting a one-click crawl removes its temporary session', async () => {
  let began;
  const started = new Promise(resolve => { began = resolve; });
  const id = '00000000-0000-4000-8000-000000000001';
  const service = createTargetPreviewService({ universityOrigins: { 'vul-web2-daehan': LAB },
    idFactory: () => id,
    labCollect: async (_url, { signal }) => {
      began();
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      });
    } });
  const controller = new AbortController();
  const pending = service.preview({ url: `${LAB}/`, signal: controller.signal });
  await started;
  controller.abort();
  await assert.rejects(pending, { code: 'PREVIEW_ABORTED' });
  assert.equal(service.getPreview(id), null);
});

test('the starting URL is bounded before a preview session is created', async () => {
  const service = createTargetPreviewService({ universityOrigins: { 'vul-web2-daehan': LAB },
    labCollect: () => { throw new Error('No visit expected.'); } });
  await assert.rejects(service.preview({ url: `${LAB}/${'x'.repeat(500)}` }),
    { code: 'PREVIEW_URL_TOO_LONG', status: 400 });
});
