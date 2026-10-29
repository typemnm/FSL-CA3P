import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { collectWebInfo, fingerprintObservedResponse, summarizeTargetInfo, evidenceFromTargetInfo, MAX_SUMMARY_BYTES,
  EVIDENCE_SUMMARY_BYTES } from '../integrations/web-parser.mjs';
import { htmlFingerprintInputs } from '../../../web-parser/html-fingerprint-inputs.mjs';

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

test('model summary carries library versions and distinguishes indicator-only evidence', () => {
  const info = targetInfo({ libraries: [{ name: 'Axios', version: '1.6.8', source: 'indicator',
    evidence: [{ field: 'resourceComment', key: 'https://example.org/vendor.js?token=PRIVATE' }] }] });
  const summary = summarizeTargetInfo(info);
  assert.deepEqual(summary.libraries, [{ name: 'Axios', version: '1.6.8', source: 'indicator',
    evidenceFields: ['resourceComment'] }]);
  assert.doesNotMatch(JSON.stringify(summary.libraries), /PRIVATE/u);
  const overview = evidenceFromTargetInfo(info, evidenceOptions)[0].summary;
  assert.deepEqual(listIn(overview, 'libraries').items, [{ name: 'Axios', version: '1.6.8', source: 'indicator' }]);
});

test('web_info evidence keeps library indicators when technologies fill the byte budget', () => {
  const info = targetInfo({
    technologies: Array.from({ length: 20 }, (_, index) => ({
      name: `Technology ${index} ${'x'.repeat(90)}`, categories: ['JavaScript libraries'], version: null,
    })),
    libraries: [{ name: 'Axios', version: '1.6.8', source: 'indicator' }],
  });
  const overview = evidenceFromTargetInfo(info, evidenceOptions)[0].summary;
  assert.deepEqual(listIn(overview, 'libraries').items, [
    { name: 'Axios', version: '1.6.8', source: 'indicator' },
  ]);
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

const evidenceOptions = { idBase: 'probe-abc', source: 'web-parser/test', asset: '/app' };

/** `label shown/total: [...]` from an evidence summary; JSON.parse fails if an item was cut mid-way. */
function listIn(summary, label) {
  const head = summary.indexOf(label + ' ') + label.length + 1;
  const [match, shown, total] = /^(\d+)\/(\d+): /u.exec(summary.slice(head));
  const rest = summary.slice(head + match.length);
  for (let end = rest.indexOf(']'); end >= 0; end = rest.indexOf(']', end + 1)) {
    try { return { shown: Number(shown), total: Number(total), items: JSON.parse(rest.slice(0, end + 1)) }; } catch { /* keep scanning */ }
  }
  return assert.fail('no complete JSON list for ' + label);
}

test('evidence gives the model form fields, paths and technologies but no cookie or body values', () => {
  const info = targetInfo({ body: 'BODY-SECRET', html: targetInfo().html.replace('<body>', '<body>HTML-SECRET') });
  const evidence = evidenceFromTargetInfo(info, { ...evidenceOptions, sessionRole: 'owner' });
  assert.deepEqual(evidence.map(item => [item.id, item.kind, item.source, item.asset]), [
    ['probe-abc', 'web-info', 'web-parser/test', '/app'],
    ['probe-abc-paths', 'web-info-paths', 'web-parser/test', '/app'],
    ['probe-abc-surface', 'web-info-surface', 'web-parser/test', '/app']]);
  const [overview, paths, surface] = evidence.map(item => item.summary);
  assert.match(overview, /^web_info \/app as fixed owner: HTTP 200 text\/html; final http:\/\/127\.0\.0\.1\/app; title "Lab Portal"/u);
  assert.deepEqual(listIn(overview, 'technologies').items, [{ name: 'React', version: '18.2.0', categories: ['JavaScript frameworks'] }]);
  assert.deepEqual(listIn(overview, 'redirects').items, [{ kind: 'http', status: 302 }]);
  assert.deepEqual(listIn(paths, 'paths').items, [{ url: '/about', sources: ['link'] }]);
  assert.deepEqual(listIn(surface, 'forms').items, [{ action: '/login', method: 'POST',
    fields: [{ name: 'user', type: 'text' }, { name: 'pass', type: 'password' }] }]);
  assert.deepEqual(listIn(surface, 'headers').items, [{ name: 'Content-Type', value: 'text/html' }, { name: 'Set-Cookie' }]);
  assert.deepEqual(listIn(surface, 'cookies (names and attributes only)').items, [{ name: 'sid', httpOnly: true,
    secure: false, sameSite: 'Lax', path: '/', domain: '127.0.0.1' }]);
  assert.doesNotMatch(JSON.stringify(evidence), /secret123|BODY-SECRET|HTML-SECRET/u);
});

test('a large page stays within the core evidence limits and trims lists by whole items with shown/total', () => {
  const fields = Array.from({ length: 80 }, (_, i) => ({ name: '필드' + i, type: 'text' }));
  const info = targetInfo({
    html: '<title>' + '제목 "quoted"\u0001'.repeat(100) + '</title>',
    headers: Array.from({ length: 120 }, (_, i) => ({ name: 'X-Header-' + i, value: '값"'.repeat(200) })),
    cookies: Array.from({ length: 60 }, (_, i) => ({ name: 'c' + i, value: 'v', path: '/', domain: '127.0.0.1',
      httpOnly: false, secure: false, sameSite: 'Lax' })),
    technologies: Array.from({ length: 90 }, (_, i) => ({ name: 'Tech ' + i, version: '1.' + i, categories: ['Misc'] })),
    structure: { ...targetInfo().structure, forms: Array.from({ length: 40 }, (_, i) => ({
      action: 'http://127.0.0.1/f' + i, method: 'POST', fields })) },
    paths: [
      ...Array.from({ length: 500 }, (_, i) => ({ url: 'http://other.example/x' + i, sources: ['link'],
        methods: [], sameOrigin: false, params: [] })),
      ...Array.from({ length: 500 }, (_, i) => ({ url: 'http://127.0.0.1/경로/' + i + '?q=1',
        sources: ['robots:disallow'], methods: ['GET'], sameOrigin: true, params: ['q'] })),
    ],
  });
  const evidence = evidenceFromTargetInfo(info, evidenceOptions);
  assert.equal(evidence.length, 3);
  for (const item of evidence) {
    assert.ok(Buffer.byteLength(item.summary, 'utf8') <= EVIDENCE_SUMMARY_BYTES, item.kind);
    assert.ok(Buffer.byteLength(JSON.stringify(item), 'utf8') <= 4096, item.kind);
  }
  const lists = [listIn(evidence[0].summary, 'technologies'), listIn(evidence[1].summary, 'paths'),
    listIn(evidence[2].summary, 'forms'), listIn(evidence[2].summary, 'headers'),
    listIn(evidence[2].summary, 'cookies (names and attributes only)')];
  assert.deepEqual(lists.map(list => list.total), [90, 1000, 40, 120, 60]);
  for (const list of lists) assert.equal(list.items.length, list.shown);
  assert.ok(lists[0].shown > 0 && lists[0].shown < 90);
  assert.ok(lists[1].shown > 0 && lists[1].items.every(path => path.url.startsWith('/')), 'same-origin paths come first');
  assert.equal(lists[2].shown, 1);
  assert.equal(lists[2].items[0].fields.at(-1), '+50 more');
});

test('evidence respects the remaining budget and tolerates non-HTML or empty observations', () => {
  assert.deepEqual(evidenceFromTargetInfo(targetInfo(), { ...evidenceOptions, remaining: 1 }).map(item => item.kind), ['web-info']);
  assert.deepEqual(evidenceFromTargetInfo(targetInfo(), { ...evidenceOptions, remaining: 0 }), []);
  const json = evidenceFromTargetInfo(targetInfo({
    target: { requestedUrl: 'http://127.0.0.1/api', finalUrl: 'http://127.0.0.1/api', origin: 'http://127.0.0.1' },
    navigation: { status: 200, contentType: 'application/json', redirectChain: [] },
    html: null, body: '{"site":"BODY-VALUE"}', structure: {}, paths: [], cookies: [], technologies: [],
    headers: [{ name: 'Content-Type', value: 'application/json' }] }), evidenceOptions);
  assert.deepEqual(json.map(item => item.kind), ['web-info', 'web-info-surface']);
  assert.match(json[0].summary, /^web_info \/app: HTTP 200 application\/json; counts \{"headers":1,/u);
  assert.doesNotMatch(JSON.stringify(json), /BODY-VALUE/u);
  assert.match(evidenceFromTargetInfo({}, evidenceOptions)[0].summary, /^web_info \/app: HTTP no response unknown; counts/u);
});

test('masked values stay inside whole JSON items and are unchanged when the core masks the summary again', () => {
  // The runtime safeText and the core redactText use these same patterns.
  const mask = value => value.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*/giu, '$1 [redacted]')
    .replace(/\b(password|passwd|api[_-]?key|secret|token|session|cookie)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu, '$1=[redacted]');
  const info = targetInfo({
    headers: [{ name: 'Location', value: '/cb?token=abc' }, { name: 'X-A', value: 'ok' },
      { name: 'X-Debug-Set-Cookie', value: 'sid=raw' }],
    paths: [{ url: 'http://127.0.0.1/cb?token=abc', sources: ['link'], methods: [], sameOrigin: true, params: ['token'] }] });
  const [, paths, surface] = evidenceFromTargetInfo(info, { ...evidenceOptions, safeText: mask });
  for (const summary of [paths.summary, surface.summary]) assert.equal(mask(summary), summary);
  assert.deepEqual(listIn(paths.summary, 'paths').items, [{ url: '/cb?token [redacted]', sources: ['link'], params: ['token'] }]);
  assert.deepEqual(listIn(surface.summary, 'headers').items, [{ name: 'Location', value: '/cb?token [redacted]' },
    { name: 'X-A', value: 'ok' }, { name: 'X-Debug-Set-Cookie' }]);
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

test('an observed HTTP response identifies libraries without a second request or storing raw secrets', async () => {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('Unexpected network request'); };
  try {
    const result = await fingerprintObservedResponse('https://nonexistent.invalid/page?token=URL-SECRET', {
      contentType: 'text/html',
      headers: [
        { name: 'Content-Type', value: 'text/html' },
        { name: 'X-Powered-By', value: 'Express' },
        { name: 'Set-Cookie', value: 'sid=COOKIE-SECRET' },
      ],
      body: '<html><head><meta name="generator" content="WordPress 6.5">'
        + '<script src="/assets/jquery-3.6.0.min.js?token=SCRIPT-SECRET"></script>'
        + '<link rel="modulepreload" href="/axios-1.6.8.min.js?token=MODULE-SECRET">'
        + '</head><body>BODY-SECRET</body></html>',
    });
    assert.equal(result.mode, 'http-response');
    const jquery = result.libraries.find(item => item.name === 'jQuery');
    assert.deepEqual(jquery, { name: 'jQuery', version: '3.6.0', evidenceFields: ['scriptSrc'] });
    const axios = result.libraries.find(item => item.name === 'Axios');
    assert.deepEqual(axios, { name: 'Axios', version: '1.6.8', evidenceFields: ['scriptSrc'], source: 'indicator' });
    assert.ok(result.technologies.some(item => item.name === 'Express'
      && item.evidenceFields.includes('headers')));
    assert.ok(result.technologies.some(item => item.name === 'WordPress'
      && item.evidenceFields.includes('meta')));
    const serialized = JSON.stringify(result);
    assert.doesNotMatch(serialized, /URL-SECRET|COOKIE-SECRET|SCRIPT-SECRET|MODULE-SECRET|BODY-SECRET|Set-Cookie|X-Powered-By|match/u);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test('HTTP response fingerprint input is bounded and never evaluates page scripts', async () => {
  await assert.rejects(fingerprintObservedResponse('file:///tmp/x', { headers: [], body: '' }), /HTTP\(S\)/u);
  await assert.rejects(fingerprintObservedResponse('https://example.org/', { headers: [], body: 'x'.repeat(64 * 1024 + 1) }), /64 KiB/u);
  await assert.rejects(fingerprintObservedResponse('https://example.org/', { headers: [], body: '',
    contentType: 'text/html' }, { timeoutMs: 0 }), /positive integer/u);
  const result = await fingerprintObservedResponse('https://example.org/', { headers: [], contentType: 'text/html',
    body: '<script>window.jQuery = { fn: { jquery: "3.6.0" } }</script>' });
  assert.equal(result.libraries.some(item => item.name === 'jQuery'), false,
    'inline page JavaScript is never executed or supplied as a script signal');
});

test('a script URL inside an HTML comment is not reported as a loaded library', async () => {
  const result = await fingerprintObservedResponse('https://example.org/', {
    headers: [], contentType: 'text/html',
    body: '<!-- <script src="/jquery-3.6.0.min.js"></script> -->',
  });
  assert.equal(result.libraries.some(item => item.name === 'jQuery'), false);
});

test('resource-like text inside scripts, styles and templates is not a library reference', async () => {
  const result = await fingerprintObservedResponse('https://example.org/', {
    headers: [], contentType: 'text/html',
    body: '<script>const markup = "<link rel=modulepreload href=/axios-1.6.8.min.js>";</script>'
      + '<style>/* <script src="/moment-2.30.1.min.js"></script> */</style>'
      + '<template><script src="/react-dom-18.2.0.min.js"></script></template>',
  });
  assert.equal(result.libraries.some(item => ['Axios', 'Moment.js', 'ReactDOM'].includes(item.name)), false);
});

test('external HTML treats textarea and nested templates as inert content', async () => {
  const result = await fingerprintObservedResponse('https://example.org/page', {
    headers: [], contentType: 'text/html',
    body: '<textarea><link rel=modulepreload href=/axios-1.6.8.min.js></textarea>'
      + '<template><template><script src=/moment-2.30.1.min.js></script></template></template>',
  });
  assert.equal(result.libraries.some(item => ['Axios', 'Moment.js'].includes(item.name)), false);
});

test('external HTML handles deeply nested markup within the response size limit', () => {
  const body = '<div>'.repeat(10000) + '<script src="/jquery.js"></script>';
  assert.deepEqual(htmlFingerprintInputs(body, 'https://example.org/page').scriptSrc,
    ['https://example.org/jquery.js']);
});

test('external HTML resolves resource URLs against the first base href', async () => {
  const result = await fingerprintObservedResponse('https://example.org/page', {
    headers: [], contentType: 'text/html',
    body: '<base href="/vendor/axios/"><script src="bundle.js"></script>',
  });
  assert.ok(result.libraries.some(item => item.name === 'Axios' && item.source === 'indicator'));
  assert.ok(result.dependencies.assets.some(item => item.url === 'https://example.org/vendor/axios/bundle.js'));
});
