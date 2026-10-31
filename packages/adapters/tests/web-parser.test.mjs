import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { collectWebInfo, summarizeTargetInfo, evidenceFromTargetInfo, webInfoView, MAX_SUMMARY_BYTES,
  EVIDENCE_SUMMARY_BYTES, MAX_VIEW_BYTES } from '../integrations/web-parser.mjs';
import { redact } from '../../contracts/index.mjs';

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

test('page titles decode HTML entities once for the summary, the evidence and the view', () => {
  const info = targetInfo({ html: '<html><head><title>Q&amp;A &lt;beta&gt; &quot;x&quot; &#39;y&#39;&nbsp;&#169;'
    + ' &#x2603; &amp;lt; &#99999999;</title></head></html>' });
  const title = 'Q&A <beta> "x" \'y\' © ☃ &lt; �';
  assert.equal(summarizeTargetInfo(info).title, title);
  assert.equal(webInfoView(info).response.title, title);
  assert.match(evidenceFromTargetInfo(info, evidenceOptions)[0].summary, /; title "Q&A <beta> \\"x\\" 'y' © ☃ &lt; �";/u);
});

const many = (count, make) => Array.from({ length: count }, (_, index) => make(index));

test('webInfoView is the UI view of one probe without page content, cookie values or secret header values', () => {
  const base = targetInfo();
  const info = targetInfo({
    navigation: { ...base.navigation, securityDetails: { protocol: 'TLS 1.3', issuer: 'Lab CA',
      subjectName: '127.0.0.1', validFrom: 1700000000, validTo: 1800000000 } },
    html: '<html><head><title>Lab Portal</title><script>INLINE_MARKER()</script></head><body>HTML_MARKER</body></html>',
    body: 'BODY_MARKER',
    meta: [{ name: 'generator', content: 'META_MARKER' }],
    headers: [...base.headers, { name: 'X-Api-Key', value: 'HEADER_SECRET' }, { name: 'Server', value: 'nginx' }],
    technologies: [{ name: 'React', categories: ['JavaScript frameworks'], version: '18.2.0', confidence: 100,
      evidence: [{ field: 'scriptSrc', match: 'react.production.min.js' },
        { field: 'headers', key: 'x-powered-by', match: 'Next.js' },
        { field: 'cookies', key: 'sid', match: 'secret123' }] },
    { name: 'Nginx', categories: ['Web servers'], version: null, confidence: 50, evidence: [] }],
    libraries: [{ name: 'React', version: '18.2.0', source: 'fingerprint', evidence: [] }],
    structure: { ...base.structure, scripts: [{ inline: 'INLINE_MARKER()', type: null }],
      iframes: [{ src: 'http://127.0.0.1/frame', sandbox: 'allow-scripts' }, { src: null, sandbox: null }],
      frames: [{ src: 'http://127.0.0.1/legacy' }],
      media: [{ tag: 'img', src: 'http://127.0.0.1/MEDIA_MARKER.png', srcset: [] }] },
    resources: [...base.resources, { kind: 'script', method: 'GET', url: 'https://cdn.example/lib.js', status: 200 },
      { kind: 'xhr', method: 'POST', url: 'http://127.0.0.1/api', status: 201 }],
    paths: [...base.paths, { url: 'http://127.0.0.1/robots-hidden/*', sources: ['robots:disallow'], methods: [],
      sameOrigin: true, params: [], wildcard: true }],
    errors: [{ stage: 'fingerprint', message: 'timeout' }],
  });
  const view = webInfoView(info, { probeId: 'w-1', iteration: 2, sessionRole: 'owner' });
  assert.deepEqual(Object.keys(view), ['schemaVersion', 'probeId', 'iteration', 'sessionRole', 'target', 'response',
    'redirectChain', 'technologies', 'paths', 'forms', 'frames', 'headers', 'cookies', 'hosts', 'errors', 'truncated']);
  assert.equal(view.schemaVersion, 'web-info-view/1');
  assert.deepEqual([view.probeId, view.iteration, view.sessionRole], ['w-1', 2, 'owner']);
  assert.deepEqual(view.target, info.target);
  assert.deepEqual(view.response, { status: 200, contentType: 'text/html', loadTimingMs: 12, title: 'Lab Portal',
    tls: { protocol: 'TLS 1.3', issuer: 'Lab CA', subjectName: '127.0.0.1', validFrom: 1700000000, validTo: 1800000000 } });
  assert.deepEqual(view.redirectChain, [{ from: 'http://127.0.0.1/', to: 'http://127.0.0.1/app', status: 302, kind: 'http' }]);
  assert.deepEqual(view.technologies, [{ name: 'React', version: '18.2.0', categories: ['JavaScript frameworks'],
    confidence: 100, library: true, evidence: [{ field: 'scriptSrc', match: 'react.production.min.js' },
      { field: 'headers', name: 'x-powered-by', match: 'Next.js' }, { field: 'cookies', name: 'sid', match: null }] },
  { name: 'Nginx', version: null, categories: ['Web servers'], confidence: 50, library: false, evidence: [] }]);
  assert.deepEqual(view.paths, { total: 2, items: [
    { url: 'http://127.0.0.1/about', sources: ['link'], methods: [], sameOrigin: true, params: [] },
    { url: 'http://127.0.0.1/robots-hidden/*', sources: ['robots:disallow'], methods: [], sameOrigin: true,
      params: [], wildcard: true }] });
  assert.deepEqual(view.forms, { total: 1, items: [{ action: 'http://127.0.0.1/login', method: 'POST',
    fields: [{ name: 'user', type: 'text' }, { name: 'pass', type: 'password' }] }] });
  assert.deepEqual(view.frames, [{ tag: 'iframe', src: 'http://127.0.0.1/frame', sandbox: 'allow-scripts' },
    { tag: 'frame', src: 'http://127.0.0.1/legacy', sandbox: null }]);
  assert.deepEqual(view.headers, [{ name: 'Content-Type', value: 'text/html' }, { name: 'Set-Cookie' },
    { name: 'X-Api-Key' }, { name: 'Server', value: 'nginx' }]);
  assert.deepEqual(view.cookies, [{ name: 'sid', domain: '127.0.0.1', path: '/', expires: null, httpOnly: true,
    secure: false, sameSite: 'Lax' }]);
  assert.deepEqual(view.hosts, [{ host: '127.0.0.1', sameOrigin: true, requests: 2, kinds: ['document', 'xhr'] },
    { host: 'cdn.example', sameOrigin: false, requests: 1, kinds: ['script'] }]);
  assert.deepEqual(view.errors, [{ stage: 'fingerprint', message: 'timeout' }]);
  assert.deepEqual(view.truncated, { source: false, sections: [] });
  const json = JSON.stringify(view);
  for (const marker of ['INLINE_MARKER', 'HTML_MARKER', 'BODY_MARKER', 'META_MARKER', 'MEDIA_MARKER',
    'secret123', 'HEADER_SECRET', '"key"', '"html"', '"body"', '"meta"']) assert.ok(!json.includes(marker), marker);
  assert.deepEqual(redact(view), view);
});

test('webInfoView masks every string through the caller and stays unchanged by redact()', () => {
  const base = targetInfo();
  const info = targetInfo({
    target: { ...base.target, requestedUrl: 'http://lab:pw@127.0.0.1/?key=abc' },
    headers: [{ name: 'X-Echo', value: 'reflected SESSIONVALUE' }, { name: 'Location', value: '/cb?sig=abc' }],
    paths: [{ url: 'http://127.0.0.1/api?signature=SIG123&page=1', sources: ['link'], methods: [], sameOrigin: true,
      params: ['signature', 'page'] }],
    errors: [{ stage: 'load', message: 'http://127.0.0.1/?SESSIONVALUE=1: timeout' }],
  });
  // The runtime passes its session masking composed with redact().
  const safeText = value => redact(value.replaceAll('SESSIONVALUE', '[redacted]'));
  const view = webInfoView(info, { safeText, safeHeaderValue: value => value.replace(/sig=\w+/u, 'sig=hidden') });
  assert.equal(view.target.requestedUrl, 'http://127.0.0.1/?key=%5BREDACTED%5D');
  assert.deepEqual(view.headers, [{ name: 'X-Echo', value: 'reflected [redacted]' },
    { name: 'Location', value: '/cb?sig=hidden' }]);
  assert.equal(view.paths.items[0].url, 'http://127.0.0.1/api?signature=%5BREDACTED%5D&page=1');
  assert.deepEqual(view.paths.items[0].params, ['signature', 'page']);
  assert.ok(!JSON.stringify(view).includes('SESSIONVALUE'));
  assert.deepEqual(redact(view), view);
  // A string that masking makes longer is cut before masking, so it never exceeds 2000 characters.
  const long = webInfoView(targetInfo({ errors: [{ stage: 'load', message: 'a'.repeat(3000) }] }),
    { safeText: value => value.replaceAll('a', 'aaa') });
  assert.ok(long.errors[0].message.length <= 2000);
  assert.match(long.errors[0].message, /^a+$/u);
});

test('webInfoView caps each list and names every cap it hit', () => {
  const base = targetInfo();
  const info = targetInfo({
    navigation: { ...base.navigation, redirectChain: many(31, index => ({ from: 'http://127.0.0.1/r' + index,
      to: 'http://127.0.0.1/r' + (index + 1), status: 302, kind: 'http' })) },
    headers: many(101, index => ({ name: 'X-H' + index, value: 'v' })),
    cookies: many(101, index => ({ name: 'c' + index, value: 'v', domain: '127.0.0.1', path: '/' })),
    technologies: many(101, index => ({ name: 'T' + index, categories: [], version: null, confidence: 1,
      evidence: many(11, () => ({ field: 'html', match: 'm' })) })),
    structure: { ...base.structure, forms: many(101, index => ({ action: 'http://127.0.0.1/f' + index,
      method: 'post', fields: many(index ? 1 : 51, field => ({ name: 'f' + field, type: 'text' })) })) },
    resources: many(101, index => ({ kind: 'image', method: 'GET', url: 'http://h' + index + '.example/x', status: 200 })),
    paths: many(501, index => ({ url: 'http://127.0.0.1/p' + index, sources: ['link'], methods: [], sameOrigin: true,
      params: [] })),
    errors: many(51, index => ({ stage: 'js', message: 'e' + index })),
  });
  const view = webInfoView(info);
  assert.deepEqual([view.redirectChain.length, view.technologies.length, view.technologies[0].evidence.length,
    view.paths.items.length, view.forms.items.length, view.forms.items[0].fields.length, view.headers.length,
    view.cookies.length, view.hosts.length, view.errors.length], [30, 100, 10, 500, 100, 50, 100, 100, 100, 50]);
  assert.deepEqual([view.paths.total, view.forms.total], [501, 101]);
  assert.deepEqual(view.truncated, { source: false, sections: ['redirectChain', 'technologies',
    'technologies.evidence', 'paths', 'forms', 'forms.fields', 'headers', 'cookies', 'hosts', 'errors'] });
});

test('webInfoView halves the widest list until a huge page fits 256 KiB', () => {
  const long = 'x'.repeat(5000);
  const base = targetInfo();
  const info = targetInfo({
    headers: many(150, index => ({ name: 'X-H' + index, value: long })),
    technologies: many(150, index => ({ name: 'T' + index, categories: ['C'], version: null, confidence: 50,
      evidence: many(20, () => ({ field: 'html', match: long })) })),
    structure: { ...base.structure, frames: many(1000, index => ({ src: 'http://127.0.0.1/frame' + index + '/' + long })) },
    paths: many(2000, index => ({ url: 'http://127.0.0.1/p' + index + '?' + long, sources: ['link'],
      methods: ['GET'], sameOrigin: true, params: many(5, param => 'q' + param + long) })),
    truncated: true,
  });
  const view = webInfoView(info);
  const json = JSON.stringify(view);
  assert.ok(Buffer.byteLength(json, 'utf8') <= MAX_VIEW_BYTES);
  JSON.parse(json, (key, value) => {
    if (typeof value === 'string') assert.ok(value.length <= 2000, key);
    return value;
  });
  assert.equal(view.truncated.source, true);
  assert.equal(view.paths.total, 2000);
  assert.ok(view.paths.items.length < 500 && view.frames.length < 1000 && view.technologies.length < 100);
  for (const section of ['technologies', 'technologies.evidence', 'paths', 'frames', 'headers']) {
    assert.ok(view.truncated.sections.includes(section), section);
  }
  assert.deepEqual(redact(view), view);
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
