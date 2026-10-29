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
  assert.equal(first.pages[0].mode, 'browser');
  assert.equal(first.pages[0].status, 200);
  assert.equal(first.pages[0].technologies[0].name, 'React');
  assert.equal(first.pages[0].libraries[0].name, 'jQuery');
  assert.deepEqual(first.discoveredPaths.sort(), [`${LAB}/about`, `${LAB}/apply`].sort());
  assert.equal(JSON.stringify(first).includes('PRIVATE_BODY'), false);
  assert.equal(JSON.stringify(first).includes('PRIVATE_COOKIE'), false);
  assert.equal(JSON.stringify(first).includes('PRIVATE_VALUE'), false);
  const second = await service.preview({ url: `${LAB}/about`, previewId: first.previewId });
  assert.deepEqual(visited, [`${LAB}/`, `${LAB}/about`]);
  assert.equal(second.pages.length, 2);
  assert.equal((await service.preview({ url: `${LAB}/about`, previewId: first.previewId })).pages.length, 2);
  assert.deepEqual(visited, [`${LAB}/`, `${LAB}/about`]);
  await assert.rejects(service.preview({ url: 'http://127.0.0.1:4102/', previewId: first.previewId }),
    { code: 'PREVIEW_ORIGIN_MISMATCH' });
  second.pages[0].title = 'changed by caller';
  assert.equal(service.getPreview(first.previewId).pages[0].title, 'University');
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
  assert.deepEqual(result.pages[0].forms, []);
  assert.deepEqual(result.discoveredPaths, ['https://8.8.8.8/docs']);
  assert.equal(result.pages[0].libraries[0].name, 'jQuery');
  assert.deepEqual(requests.map(item => [item.url, item.method, item.scope.origin]),
    [['https://8.8.8.8/start', 'GET', 'https://8.8.8.8']]);
  assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
  await assert.rejects(service.preview({ url: 'http://127.0.0.1:4999/' }), { code: 'EXTERNAL_ADDRESS_BLOCKED' });
  assert.deepEqual(requests.map(item => item.url), ['https://8.8.8.8/start']);
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
