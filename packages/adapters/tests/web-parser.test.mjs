import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { collectWebInfo, summarizeTargetInfo, MAX_SUMMARY_BYTES } from '../integrations/web-parser.mjs';

function targetInfo(overrides = {}) {
  return {
    schemaVersion: 'web-parser-1',
    target: { requestedUrl: 'http://127.0.0.1/', finalUrl: 'http://127.0.0.1/app', origin: 'http://127.0.0.1' },
    navigation: { status: 200, contentType: 'text/html', redirectChain: [
      { from: 'http://127.0.0.1/', to: 'http://127.0.0.1/app', status: 302, kind: 'http' }], loadTimingMs: 12, securityDetails: null },
    headers: [{ name: 'Content-Type', value: 'text/html' }, { name: 'Set-Cookie', value: 'sid=secret123; HttpOnly' }],
    cookies: [{ name: 'sid', value: 'secret123', domain: '127.0.0.1', path: '/', httpOnly: true, secure: false, sameSite: 'Lax' }],
    meta: [{ name: 'generator', content: 'Test CMS' }],
    html: '<html><head><title>  Lab   Portal </title></head><body></body></html>',
    body: null,
    technologies: [{ name: 'React', categories: ['JavaScript frameworks'], version: '18.2.0', confidence: 100, evidence: [] }],
    libraries: [],
    structure: {
      forms: [{ selector: 'form', action: 'http://127.0.0.1/login', method: 'POST',
        fields: [{ name: 'user', type: 'text' }, { name: 'pass', type: 'password' }] }],
      links: [{ href: 'http://127.0.0.1/about', text: 'About' }],
      scripts: [], iframes: [], inputs: [], linkTags: [], areas: [], formActions: [],
      frames: [], embeds: [], objects: [], metaRefresh: [], media: [],
    },
    resources: [{ kind: 'document', method: 'GET', url: 'http://127.0.0.1/app', status: 200 }],
    paths: [{ url: 'http://127.0.0.1/about', sources: ['link'], methods: [], sameOrigin: true, params: [] }],
    errors: [],
    truncated: false,
    ...overrides,
  };
}

test('summary carries observed fields as-is and stays within the byte budget', () => {
  const summary = summarizeTargetInfo(targetInfo());
  assert.equal(summary.finalUrl, 'http://127.0.0.1/app');
  assert.equal(summary.status, 200);
  assert.equal(summary.title, 'Lab Portal');
  assert.deepEqual(summary.redirectChain, [{ from: 'http://127.0.0.1/', to: 'http://127.0.0.1/app', status: 302, kind: 'http' }]);
  // Values are not masked by the adapter; the core's redactSensitive owns that (CONTRACT §6).
  assert.equal(summary.cookies[0].value, 'secret123');
  assert.deepEqual(summary.technologies, [{ name: 'React', version: '18.2.0',
    categories: ['JavaScript frameworks'], confidence: 100 }]);
  assert.deepEqual(summary.forms[0].fields, [{ name: 'user', type: 'text' }, { name: 'pass', type: 'password' }]);
  assert.deepEqual(summary.links, ['http://127.0.0.1/about']);
  assert.deepEqual(summary.paths, [{ url: 'http://127.0.0.1/about', sources: ['link'], methods: [], sameOrigin: true, params: [] }]);
  assert.ok(Buffer.byteLength(JSON.stringify(summary), 'utf8') <= MAX_SUMMARY_BYTES);
});

test('a truncated section keeps { shown, total } so nothing is dropped silently', () => {
  const headers = Array.from({ length: 70 }, (_, i) => ({ name: 'X-H-' + i, value: 'v' + i }));
  const links = Array.from({ length: 120 }, (_, i) => ({ href: 'http://127.0.0.1/p' + i, text: 't' + i }));
  const summary = summarizeTargetInfo(targetInfo({ headers,
    structure: { ...targetInfo().structure, links } }));
  assert.equal(summary.headers.total, 70);
  assert.equal(summary.headers.shown, summary.headers.items.length);
  assert.ok(summary.headers.shown < 70);
  assert.equal(summary.links.total, 120);
  assert.ok(summary.links.shown < 120 && summary.links.items.length === summary.links.shown);
});

test('an oversized page is shrunk by count to fit 40KB while recording totals', () => {
  const paths = Array.from({ length: 2000 }, (_, i) => ({
    url: 'http://127.0.0.1/' + 'segment'.repeat(10) + '/' + i,
    sources: ['link'], methods: ['GET'], sameOrigin: true, params: ['a', 'b', 'c'] }));
  const summary = summarizeTargetInfo(targetInfo({ paths }));
  assert.ok(Buffer.byteLength(JSON.stringify(summary), 'utf8') <= MAX_SUMMARY_BYTES);
  assert.equal(summary.paths.total, 2000);
  assert.ok(summary.paths.shown < 2000);
});

test('collectWebInfo returns the raw TargetInfo and its summary, bounding timeoutMs at 15s', async () => {
  const seen = [];
  const info = targetInfo();
  const { info: returned, summary } = await collectWebInfo('http://127.0.0.1/app', {
    timeoutMs: 999_999, cookies: [{ name: 'sid', value: 'lab-1' }],
    collectImpl: async (url, opts) => { seen.push({ url, opts }); return info; } });
  assert.equal(returned, info);
  assert.equal(summary.status, 200);
  assert.equal(seen[0].opts.timeoutMs, 15000);
  assert.deepEqual(seen[0].opts.cookies, [{ name: 'sid', value: 'lab-1' }]);
});

test('collectWebInfo observes a real loopback page and forwards a cookie to it', async () => {
  const cookiesSeen = [];
  const server = createServer((req, res) => {
    cookiesSeen.push(req.headers.cookie ?? null);
    res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'server=set; Path=/' });
    res.end('<html><head><title>Loopback Fixture</title></head><body>'
      + '<a href="/next">next</a></body></html>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const { info, summary } = await collectWebInfo(`${base}/`, { cookies: [{ name: 'sid', value: 'lab-1' }] });
    assert.equal(info.schemaVersion, 'web-parser-1');
    assert.equal(summary.status, 200);
    assert.equal(summary.title, 'Loopback Fixture');
    assert.ok(cookiesSeen.some(cookie => cookie === 'sid=lab-1'), 'the server received the forwarded cookie');
    const paths = Array.isArray(summary.paths) ? summary.paths : summary.paths.items;
    assert.ok(paths.some(path => path.url === `${base}/next`), 'the same-origin link was indexed as a path');
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
