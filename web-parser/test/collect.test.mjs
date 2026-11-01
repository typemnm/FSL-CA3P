import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { getEventListeners } from 'node:events';
import { existsSync, mkdtempSync } from 'node:fs';
import { cp, mkdir, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import wt from 'node:worker_threads';
import { chromium } from 'playwright';
import {
  collect, collectEach, MAX_BODY_LENGTH, MAX_COOKIES, MAX_HTML_LENGTH, MAX_PATHS, MAX_RESOURCES, MAX_STRUCTURE_ITEMS, MAX_TEXT_LENGTH,
  PROFILE_PREFIX, SCHEMA_VERSION,
} from '../collect.mjs';

// Per-test limit travels with the file (not only with the npm script flag).
const T = { timeout: 90_000 };
// Private TMPDIR so profile counting can't see other processes' (or this suite's) temp dirs.
const TMP = mkdtempSync(join(tmpdir(), 'wp-test-tmp-'));
process.env.TMPDIR = TMP;
const profiles = async () => (await readdir(TMP)).filter((n) => n.startsWith(PROFILE_PREFIX)).length;
// Every message posted to a fingerprint Worker (html length only): pins that matching runs off the main thread (V5).
const posted = [];
wt.Worker = class extends wt.Worker {
  postMessage(m, ...rest) { posted.push(m?.html?.length ?? 0); return super.postMessage(m, ...rest); }
};
syncBuiltinESMExports(); // fingerprint.mjs's `Worker` import binding now points at the spy
// Every profile a browser was launched on: pins "no browser started" and identifies a call's own Chromium.
const launches = [];
const launch = chromium.launchPersistentContext;
chromium.launchPersistentContext = function (profile, ...rest) { launches.push(profile); return launch.call(this, profile, ...rest); };
const browsersOn = async (profile) => {
  const command = process.platform === 'win32' ? 'powershell.exe' : 'ps';
  const args = process.platform === 'win32'
    ? ['-NoProfile', '-NonInteractive', '-Command',
      'Get-CimInstance Win32_Process -Filter "Name = \'chrome.exe\' OR Name = \'chromium.exe\' OR Name = \'headless_shell.exe\' OR Name = \'chrome-headless-shell.exe\'" | Select-Object -ExpandProperty CommandLine']
    : ['-axww', '-o', 'command='];
  return (await promisify(execFile)(command, args, { maxBuffer: 64 << 20, windowsHide: true }))
    .stdout.split('\n').filter((line) => line.includes(profile));
};
// Small budgets can add a fingerprint timeout (cold Worker start); tests about other stages ignore it.
const core = (info) => info.errors.filter((e) => e.stage !== 'fingerprint');

const MODULE = new URL('..', import.meta.url);
const CLI = fileURLToPath(new URL('cli.mjs', MODULE));
const html = (body, head = '') => `<!doctype html><html><head>${head}</head><body>${body}</body></html>`;
const PAGES = {
  '/': html(
    `<form id="login" action="/login" method="POST"><input name="user"><input name="pw" type="password"></form>
     <a href="/a">A</a> <a href="/b#frag">B</a> <a href="https://example.invalid/x">ext</a>
     <iframe src="/frame" sandbox="allow-scripts"></iframe>
     <script src="/app.js"></script><script>window.inline = 1;</script>`,
    '<meta name="description" content="fixture"><meta property="og:title" content="Home">',
  ),
  '/a': html('<a href="/">home</a> <textarea name="note"></textarea>'),
  '/b': html('<a href="/a">A again</a>'),
  '/frame': html('<p>framed</p>'),
  '/dups': html('<a href="/a">same</a><a href="/a">same</a>'),
  '/client': html('<a href="/a">a</a>', "<script>location.replace('/landing')</script>"),
  '/landing': html('<form><input name="q"></form>', '<meta name="who" content="landing">'),
  '/to-json': html('', "<script>addEventListener('load', () => location.replace('/data.json'))</script>"),
  '/busy': html('<a href="/a">a</a>', "<script>addEventListener('load', () => setTimeout(() => { for (;;) {} }, 0))</script>"),
  '/slow-sub': html('<a href="/a">a</a><img src="/never">'),
  // networkidle: the link appears only after a fetch the server answers ~1 s after load.
  '/idle-wait': html('', `<script>addEventListener('load', () => fetch('/slow-json').then(() => {
    const a = document.createElement('a'); a.href = '/after-idle'; document.body.append(a); }))</script>`),
  '/clobber': html(
    `<form id="f" action=" /post "><input name="parentElement"><input name="elements"><input name="getAttribute">
       <input name="id"><input name="localName"></form>
     <img name="querySelectorAll"><img name="baseURI"><img name="documentElement">
     <a href="/ok">ok</a>
     <svg><a href="/svg-link"><text>s</text></a><script href="/svg.js"></script></svg>`,
    `<meta name="description" content="clobbered">
     <script>var CSS = {}; Element.prototype.getAttribute = () => 'forged'; Array.prototype.map = () => [];
       Document.prototype.querySelectorAll = () => [];</script>`,
  ),
  '/forms': html('<form id="none"></form><form id="empty" action=""></form><form id="rel" action="post"></form>',
    '<base href="/other/">'),
  '/fp': html('<p>fp</p>', `<meta name="generator" content="WordPress 6.5"><meta name="constructor" content="x">
    <script src="/vendor.js"></script>`),
  '/fp-src': html('', '<script src="/jquery-3.7.1.min.js"></script>'),
  '/proxy-hang': html('', '<script>window.jQuery = new Proxy(function () {}, { getOwnPropertyDescriptor() { for (;;) {} } });</script>'),
  '/many-links': html(Array.from({ length: MAX_STRUCTURE_ITEMS + 1 }, (_, i) => `<a href="https://example.invalid/${i}">x</a>`).join('')),
  '/many-imgs': html(Array.from({ length: MAX_RESOURCES + 1 }, (_, i) => `<img src="/img/${i}">`).join('')),
  '/big-html': html(`<p>${'x'.repeat(MAX_HTML_LENGTH)}</p>`),
  '/long-text': html(`<a href="/a">${'t'.repeat(MAX_TEXT_LENGTH + 1)}</a>`),
  // V4: 60M U+0001 chars (6 bytes each once CDP-escaped) in a div that the 'div' DOM probe also reads.
  '/huge': html('<div id="big"></div>', `<script>addEventListener('DOMContentLoaded', () => {
    document.getElementById('big').textContent = '\\u0001'.repeat(60_000_000); })</script>`),
  // V5: page-controlled worst case for the dataset's `<[^>]{1,250}` patterns, just under the html cap.
  '/lt': html(`<!-- ${'<'.repeat(4_990_000)} -->`),
  // V8: a small DOM (fast load and core extraction) that the slow-probe dataset (slowProbeModule) takes seconds to probe.
  '/probe-dom': html(`<a href="/a">a</a>${'<i></i>'.repeat(3000)}`, '<script>window.jQuery = { fn: { jquery: "3.7.1" } };</script>'),
  // W1: the landing document of a client redirect never reaches load.
  '/to-slow': html('<p>first</p>', "<script>addEventListener('load', () => location.replace('/slow-sub'))</script>"),
  // W2: a page-initiated navigation that never gets an answer, before load, after load, and as a POST form.
  '/stuck-load': html('<a href="/landed">landed</a><img src="/never">', "<script>setTimeout(() => { location.href = '/never'; }, 300)</script>"),
  '/stuck-after-load': html('<a href="/landed">landed</a>', "<script>addEventListener('load', () => { location.href = '/never'; })</script>"),
  // G1/G4: the same never-answered navigation started a few ms into extraction, and by a meta refresh.
  '/refresh-never': html('<a href="/landed">landed</a>', '<meta http-equiv="refresh" content="0;url=/never">'),
  // G0/G2: a client redirect to a landing document whose body arrives in two parts (/stream, below).
  '/to-stream': html('<p>first</p>', "<script>addEventListener('load', () => location.replace('/stream'))</script>"),
  '/form-autosubmit': html('<form id="f" method="post" action="/never"><input name="q" value="1"></form><a href="/landed">landed</a>',
    "<script>addEventListener('load', () => document.getElementById('f').submit())</script>"),
  // W4: the token sits past the DOM-probe text cap of the dataset's `style` selector; a JS global over its value cap.
  '/style-long': html('', `<style>/*${'c'.repeat(MAX_TEXT_LENGTH)}*/ :root{--bs-gutter-x:1rem}</style>`),
  '/js-long': html('', `<script>window.jQuery = { fn: { jquery: '3.7.1${'x'.repeat(1000)}' } };</script>`),
  // Every URL source the structure records; /a?x=1&y=2 appears three times (two fragments, one area).
  '/sources': html(
    `<a href="/a?x=1&amp;y=2#one">A</a><a href="/a?x=1&amp;y=2#two">A again</a>
     <map name="m"><area href="/a?x=1&amp;y=2" coords="0,0,1,1"></map>
     <form id="f" action="/submit?step=1" method="POST"><input name="user" value="alice-secret">
       <input name="pw" type="password" value="pw-secret"><button formaction="/alt" formmethod="GET">alt</button>
       <input type="submit" formaction="/alt2?mode=x"></form>
     <embed src="/movie.swf" type="application/x-shockwave-flash"><object data="/obj.svg" type="image/svg+xml"></object>
     <img src="/img.png" srcset="/img-1x.png 1x, /img-2x.png 2x">
     <picture><source srcset="/pic.webp" type="image/webp"><img src="/pic.png"></picture>
     <iframe src="/frame"></iframe><script src="/app.js"></script>
     <a href="https://example.invalid/ext">ext</a><a href="mailto:x@example.invalid">mail</a>`,
    `<link rel="canonical" href="/canon"><link rel="Alternate" type="application/rss+xml" href="/feed.xml">
     <link rel="manifest" href="/site.webmanifest"><link rel="next" href="/page/2"><link rel="prev" href="/page/0">
     <link rel="preload" as="image" href="/pre.png"><meta http-equiv="refresh" content="3600; url='/later?r=1'">`,
  ),
  '/frameset': '<!doctype html><html><frameset><frame src="/frame"><frame src="/a"></frameset></html>',
  '/post-fetch': html('', "<script>fetch('/api/save?id=7', { method: 'POST', body: 'x=1' })</script>"),
};
const ROBOTS = () => `# rules\nUser-agent: *\nDisallow: /admin/\nDisallow: /private/*.php$ # no php\nAllow: /admin/public?view=1\n`
  + `Disallow:\n\nSitemap: ${base}/sitemap.xml\n`;
const SITEMAP = () => `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${base}/</loc><lastmod>2026-10-01</lastmod></url>
  <url><loc>\n    ${base}/list?page=2&amp;sort=asc\n  </loc></url>
  <url><loc>https://example.invalid/elsewhere</loc></url>\n</urlset>\n`;
const SITEMAP_INDEX = () => `<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`
  + `<sitemap><loc>${base}/sitemap.xml</loc></sitemap><sitemap><loc>${base}/sitemap-2.xml.gz</loc></sitemap></sitemapindex>`;
const TEXTS = {
  '/robots.txt': ['text/plain', ROBOTS],
  '/sitemap.xml': ['application/xml', SITEMAP],
  '/sitemap-index.xml': ['text/xml', SITEMAP_INDEX],
  '/big.txt': ['text/plain', () => 'x'.repeat(MAX_BODY_LENGTH + 1)],
  // Content decides: robots-shaped text under any name, with more distinct paths than the index keeps.
  '/many-paths.txt': ['text/plain', () => `User-agent: *\n${Array.from({ length: MAX_PATHS }, (_, i) => `Disallow: /p/${i}`).join('\n')}\n`],
};

let server;
let base;
let deadPort;
let dead;
const cookieSeen = []; // [host, Cookie header] of each /cookie-probe and /to-localhost request
before(async () => {
  // A port this suite keeps owning (no check-then-use race with other processes): every connection is dropped unanswered.
  dead = createServer().on('connection', (socket) => socket.destroy());
  await new Promise((r) => dead.listen(0, '127.0.0.1', r));
  deadPort = dead.address().port;

  server = createServer((req, res) => {
    const { pathname, searchParams } = new URL(req.url, 'http://x');
    if (pathname === '/r1') return res.writeHead(302, { location: '/r2', 'X-Hop': 'one' }).end();
    if (pathname === '/r2') return res.writeHead(301, { location: '/' }).end();
    if (pathname === '/r-dead') {
      return res.writeHead(302, { location: `http://127.0.0.1:${deadPort}/`, 'Set-Cookie': 'hopc=1; Path=/', Server: 'fixture' }).end();
    }
    if (pathname === '/to-dead') {
      res.writeHead(200, { 'content-type': 'text/html', 'x-page': pathname });
      return res.end(html('<a href="/mine">mine</a>', `<meta name="who" content="to-dead">
        <script>addEventListener('load', () => { location.href = 'http://127.0.0.1:${deadPort}/'; })</script>`));
    }
    if (pathname === '/loop') return res.writeHead(302, { location: '/loop' }).end();
    // Same server under another host name: localhost.
    const local = `http://localhost:${server.address().port}`;
    if (pathname === '/cookie-probe' || pathname === '/to-localhost') cookieSeen.push([req.headers.host.split(':')[0], req.headers.cookie ?? null]);
    if (pathname === '/cookie-probe') return res.writeHead(204).end();
    if (pathname === '/to-localhost') return res.writeHead(302, { location: `${local}/echo` }).end();
    if (pathname === '/cross') {
      return res.writeHead(200, { 'content-type': 'text/html' }).end(html(`<img src="/cookie-probe"><img src="${local}/cookie-probe">`));
    }
    if (pathname === '/app.js') return res.writeHead(200, { 'content-type': 'text/javascript' }).end('window.app = 1;');
    if (pathname === '/vendor.js') {
      return res.writeHead(200, { 'content-type': 'text/javascript' }).end('window.jQuery = { fn: { jquery: "3.7.1" } };');
    }
    if (pathname === '/jquery-3.7.1.min.js') return res.writeHead(200, { 'content-type': 'text/javascript' }).end('');
    if (pathname === '/fp') {
      res.writeHead(200, { 'content-type': 'text/html', 'X-Powered-By': 'Express', 'set-cookie': 'PHPSESSID=abc123; Path=/' });
      return res.end(PAGES['/fp']);
    }
    if (pathname === '/reload') {
      // V1: same URL, two documents. The first sets a cookie and reloads d ms after load.
      const second = /(^|; )seen=1/.test(req.headers.cookie ?? '');
      const who = second ? 'second' : 'first';
      const reload = second ? '' : `<script>addEventListener('load', () => setTimeout(() => location.reload(), ${Number(searchParams.get('d'))}))</script>`;
      res.writeHead(200, { 'content-type': 'text/html', 'x-doc': who, ...(second ? {} : { 'set-cookie': 'seen=1; Path=/' }) });
      return res.end(html(`<p>${who}</p>`, `<meta name="who" content="${who}">${reload}`));
    }
    if (pathname === '/never') return; // never answers: load never fires
    if (pathname === '/slow-json') return setTimeout(() => res.writeHead(204).end(), 1000);
    if (pathname === '/stream') {
      res.writeHead(200, { 'content-type': 'text/html', 'x-page': pathname });
      res.write('<!doctype html><html><head></head><body><a href="/early">early</a>');
      return setTimeout(() => res.end('<a href="/late">late</a><form action="/late-form"></form></body></html>'), 1500);
    }
    if (pathname === '/late-nav') {
      // window.jQuery is the JS-global evidence; the never-answered navigation starts d ms after load.
      res.writeHead(200, { 'content-type': 'text/html', 'x-page': pathname });
      return res.end(html('<a href="/landed">landed</a>', `<script>window.jQuery = { fn: { jquery: "3.7.1" } };
        addEventListener('load', () => setTimeout(() => { location.href = '/never'; }, ${Number(searchParams.get('d'))}))</script>`));
    }
    if (pathname === '/asset-b') {
      res.writeHead(200, { 'content-type': 'text/html', 'X-Asset': 'b', 'set-cookie': 'bsid=2; Path=/' });
      return res.end(html('<a href="/b-only">b</a><form action="/b-form"><input name="bq"></form>',
        '<meta name="generator" content="Joomla! - Open Source Content Management">'));
    }
    if (pathname.startsWith('/img/') || pathname === '/api/save') return res.writeHead(204).end();
    if (TEXTS[pathname]) return res.writeHead(200, { 'content-type': TEXTS[pathname][0] }).end(TEXTS[pathname][1]());
    if (pathname === '/bin.png') return res.writeHead(200, { 'content-type': 'image/png' }).end(Buffer.from('89504e470d0a1a0a00', 'hex'));
    if (pathname === '/data.json') return res.writeHead(200, { 'content-type': 'application/json' }).end('{"a":"/a"}');
    if (pathname === '/plain') return res.writeHead(200).end('hello plain text body'); // no Content-Type
    if (pathname === '/download') {
      return res.writeHead(200, { 'content-type': 'text/plain', 'content-disposition': 'attachment; filename=x.txt' }).end('x');
    }
    if (pathname === '/missing') return res.writeHead(404, { 'content-type': 'text/html' }).end(html('<p>nope</p>'));
    if (pathname === '/set') {
      res.setHeader('Set-Cookie', ['sid=secret1; Path=/; HttpOnly', 'pref=dark; Path=/']);
      res.setHeader('X-Mixed-Case', 'v');
      res.setHeader('X-Dup', ['one', 'two']);
      res.setHeader('content-type', 'text/html');
      return res.writeHead(200).end(html('set'));
    }
    if (pathname === '/echo') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end(html('', `<meta name="seen-cookie" content="${req.headers.cookie ?? ''}">
        <meta name="seen-ua" content="${req.headers['user-agent']}">`));
    }
    if (PAGES[pathname]) {
      return res.writeHead(200, { 'content-type': 'text/html', 'X-Fixture': 'yes', 'x-page': pathname }).end(PAGES[pathname]);
    }
    res.writeHead(404).end();
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  server.closeAllConnections();
  server.close();
  dead.close();
  await rm(TMP, { recursive: true, force: true });
});

// A dropped connection surfaces as one of several net errors, depending on timing.
const DEAD_ERR = /net::ERR_(CONNECTION_[A-Z_]+|EMPTY_RESPONSE|SOCKET_NOT_CONNECTED)/;
const header = (headers, name) => headers.filter((h) => h.name === name).map((h) => h.value);
const onLoopback = (info) => info.resources.every((r) => r.url.startsWith(base));
const documents = (info) => info.resources.filter((r) => r.kind === 'document').map((r) => r.url);
const EMPTY_STRUCTURE = {
  forms: [], links: [], scripts: [], iframes: [], inputs: [],
  linkTags: [], areas: [], formActions: [], frames: [], embeds: [], objects: [], metaRefresh: [], media: [],
};
const pathsOf = (info) => Object.fromEntries(info.paths.map((p) => [p.url, p]));
const DOC = (url) => ({ url, sources: ['request:document'], methods: ['GET'], sameOrigin: true, params: [] });

test('returns TargetInfo shape with raw headers, meta, structure and resources', T, async () => {
  const info = await collect(`${base}/`);
  assert.equal(info.schemaVersion, SCHEMA_VERSION);
  assert.deepEqual(Object.keys(info).sort(), ['body', 'cookies', 'errors', 'headers', 'html', 'libraries', 'meta', 'navigation',
    'paths', 'resources', 'schemaVersion', 'structure', 'target', 'technologies', 'truncated']);
  assert.equal(info.body, null, 'an HTML document is reported as html only');
  assert.deepEqual(info.target, { requestedUrl: `${base}/`, finalUrl: `${base}/`, origin: base });
  assert.equal(info.navigation.status, 200);
  assert.equal(info.navigation.contentType, 'text/html');
  assert.equal(info.navigation.securityDetails, null);
  assert.deepEqual(info.navigation.redirectChain, []);
  assert.equal(typeof info.navigation.loadTimingMs, 'number');
  assert.deepEqual(header(info.headers, 'X-Fixture'), ['yes'], 'original header name case kept');
  assert.match(info.html, /^<html><head><meta name="description" content="fixture">.*<\/html>$/s, 'outerHTML as received');
  // Open Graph has no meta pattern in the dataset, only dom "meta[property*='og:']": this pins the DOM-probe path
  // and the technology entry shape.
  assert.deepEqual(info.technologies, [{ name: 'Open Graph', categories: ['Miscellaneous'], version: null, confidence: 100,
    evidence: [{ field: 'dom', key: "meta[property*='og:']", match: '' }] }]);
  assert.deepEqual(info.libraries, []);
  assert.deepEqual(info.errors, []);
  assert.equal(info.truncated, false);
  assert.deepEqual(info.meta, [{ name: 'description', content: 'fixture' }, { property: 'og:title', content: 'Home' }]);

  const { forms, links, scripts, iframes, inputs } = info.structure;
  assert.deepEqual(forms, [{ selector: '#login', action: `${base}/login`, raw: '/login', method: 'post',
    fields: [{ name: 'user', type: 'text' }, { name: 'pw', type: 'password' }] }]);
  assert.deepEqual(links.map((l) => [l.href, l.raw, l.text]), [
    [`${base}/a`, '/a', 'A'], [`${base}/b#frag`, '/b#frag', 'B'], ['https://example.invalid/x', undefined, 'ext']]);
  assert.deepEqual(scripts, [{ src: `${base}/app.js`, raw: '/app.js', type: null }, { inline: 'window.inline = 1;', type: null }]);
  assert.deepEqual(iframes, [{ src: `${base}/frame`, raw: '/frame', sandbox: 'allow-scripts' }]);
  assert.deepEqual(inputs.map((i) => [i.name, i.form]), [['user', '#login'], ['pw', '#login']]);

  const byUrl = Object.fromEntries(info.resources.map((r) => [r.url, r]));
  assert.deepEqual(byUrl[`${base}/`], { kind: 'document', method: 'GET', url: `${base}/`, status: 200 });
  assert.deepEqual(byUrl[`${base}/frame`], { kind: 'document', method: 'GET', url: `${base}/frame`, status: 200 });
  assert.deepEqual(byUrl[`${base}/app.js`], { kind: 'script', method: 'GET', url: `${base}/app.js`, status: 200 });
});

test('paths (a)/(d): every URL source is in structure and in one deduplicated paths entry per URL, names without values', T, async () => {
  const info = await collect(`${base}/sources`);
  assert.deepEqual(core(info), []);
  const s = info.structure;
  assert.deepEqual(s.linkTags.map((l) => [l.href, l.raw, l.rel, l.type]), [
    [`${base}/canon`, '/canon', 'canonical', null], [`${base}/feed.xml`, '/feed.xml', 'Alternate', 'application/rss+xml'],
    [`${base}/site.webmanifest`, '/site.webmanifest', 'manifest', null], [`${base}/page/2`, '/page/2', 'next', null],
    [`${base}/page/0`, '/page/0', 'prev', null], [`${base}/pre.png`, '/pre.png', 'preload', null]]);
  assert.deepEqual(s.areas, [{ href: `${base}/a?x=1&y=2`, raw: '/a?x=1&y=2' }]);
  assert.deepEqual(s.formActions, [
    { selector: '#f > button', formaction: `${base}/alt`, raw: '/alt', formmethod: 'get', form: '#f' },
    { selector: '#f > input:nth-of-type(3)', formaction: `${base}/alt2?mode=x`, raw: '/alt2?mode=x', formmethod: null, form: '#f' }]);
  assert.deepEqual(s.embeds, [{ src: `${base}/movie.swf`, raw: '/movie.swf', type: 'application/x-shockwave-flash' }]);
  assert.deepEqual(s.objects, [{ data: `${base}/obj.svg`, raw: '/obj.svg', type: 'image/svg+xml' }]);
  assert.deepEqual(s.metaRefresh, [{ url: `${base}/later?r=1`, raw: '/later?r=1', content: "3600; url='/later?r=1'" }]);
  assert.deepEqual(s.media, [
    { tag: 'img', src: `${base}/img.png`, raw: '/img.png', srcset: [{ url: `${base}/img-1x.png`, raw: '/img-1x.png' },
      { url: `${base}/img-2x.png`, raw: '/img-2x.png' }] },
    { tag: 'source', src: null, srcset: [{ url: `${base}/pic.webp`, raw: '/pic.webp' }] },
    { tag: 'img', src: `${base}/pic.png`, raw: '/pic.png', srcset: [] }]);

  const paths = pathsOf(info);
  assert.equal(info.paths.length, Object.keys(paths).length, 'one entry per URL');
  assert.ok(info.paths.every((p) => /^https?:\/\/[^#]*$/.test(p.url)), 'http(s) only, fragments dropped (no mailto:)');
  assert.deepEqual(paths[`${base}/sources`], DOC(`${base}/sources`));
  assert.deepEqual(paths[`${base}/a?x=1&y=2`], { url: `${base}/a?x=1&y=2`, sources: ['link', 'area'], methods: [], sameOrigin: true, params: ['x', 'y'] });
  assert.deepEqual(paths[`${base}/submit?step=1`], { url: `${base}/submit?step=1`, sources: ['form'], methods: ['POST'], sameOrigin: true,
    params: ['step', 'user', 'pw'] });
  assert.deepEqual([paths[`${base}/alt`].methods, paths[`${base}/alt`].params], [['GET'], ['user', 'pw']]);
  assert.deepEqual([paths[`${base}/alt2?mode=x`].methods, paths[`${base}/alt2?mode=x`].params], [['POST'], ['mode', 'user', 'pw']],
    'a formaction without formmethod submits with its form\'s method and fields');
  assert.ok(!/alice-secret|pw-secret/.test(JSON.stringify(info.paths)), 'parameter names only, never values');
  assert.deepEqual(paths[`${base}/feed.xml`].sources, ['link-rel:alternate']);
  assert.deepEqual(paths[`${base}/pre.png`].sources.sort(), ['link-rel:preload', 'request:image'], 'the preload was also requested');
  assert.deepEqual(paths[`${base}/later?r=1`].params, ['r']);
  assert.deepEqual(paths['https://example.invalid/ext'], { url: 'https://example.invalid/ext', sources: ['link'], methods: [],
    sameOrigin: false, params: [] });
  for (const [path, source] of [['/img.png', 'img'], ['/img-1x.png', 'srcset'], ['/img-2x.png', 'srcset'], ['/pic.webp', 'srcset'],
    ['/pic.png', 'img'], ['/movie.swf', 'embed'], ['/obj.svg', 'object'], ['/frame', 'iframe'], ['/app.js', 'script'],
    ['/canon', 'link-rel:canonical'], ['/site.webmanifest', 'link-rel:manifest'], ['/page/2', 'link-rel:next'],
    ['/page/0', 'link-rel:prev'], ['/later?r=1', 'meta-refresh']]) {
    assert.ok(paths[`${base}${path}`]?.sources.includes(source), `${path}: ${JSON.stringify(paths[`${base}${path}`])}`);
  }

  const frames = await collect(`${base}/frameset`);
  assert.deepEqual(frames.structure.frames, [{ src: `${base}/frame`, raw: '/frame' }, { src: `${base}/a`, raw: '/a' }]);
  assert.deepEqual(pathsOf(frames)[`${base}/a`].sources, ['request:document', 'frame']);
});

test('paths (c): a POST the page sends on load is in resources[].method and paths.methods', T, async () => {
  const info = await collect(`${base}/post-fetch`, { waitUntil: 'networkidle' });
  const url = `${base}/api/save?id=7`;
  assert.deepEqual(info.resources.find((r) => r.url === url), { kind: 'fetch', method: 'POST', url, status: 204 });
  assert.deepEqual(pathsOf(info)[url], { url, sources: ['request:fetch'], methods: ['POST'], sameOrigin: true, params: ['id'] });
});

test('paths (b)/(f): non-HTML text bodies as received; robots.txt and sitemap entries become paths; binary has no body', T, async () => {
  const robots = await collect(`${base}/robots.txt`);
  assert.deepEqual([robots.body, robots.html, core(robots)], [ROBOTS(), null, []]);
  assert.deepEqual(robots.paths, [
    DOC(`${base}/robots.txt`),
    { url: `${base}/admin/`, sources: ['robots:disallow'], methods: [], sameOrigin: true, params: [] },
    { url: `${base}/private/*.php$`, sources: ['robots:disallow'], methods: [], sameOrigin: true, params: [], wildcard: true },
    { url: `${base}/admin/public?view=1`, sources: ['robots:allow'], methods: [], sameOrigin: true, params: ['view'] },
    { url: `${base}/sitemap.xml`, sources: ['robots:sitemap'], methods: [], sameOrigin: true, params: [] },
  ]);
  assert.deepEqual(documents(robots), [`${base}/robots.txt`], 'listed paths are never requested');

  const sitemap = await collect(`${base}/sitemap.xml`);
  assert.deepEqual([sitemap.body, core(sitemap)], [SITEMAP(), []]);
  assert.deepEqual(sitemap.paths, [
    DOC(`${base}/sitemap.xml`),
    { url: `${base}/`, sources: ['sitemap'], methods: [], sameOrigin: true, params: [] },
    { url: `${base}/list?page=2&sort=asc`, sources: ['sitemap'], methods: [], sameOrigin: true, params: ['page', 'sort'] },
    { url: 'https://example.invalid/elsewhere', sources: ['sitemap'], methods: [], sameOrigin: false, params: [] },
  ]);

  const index = await collect(`${base}/sitemap-index.xml`);
  assert.equal(index.body, SITEMAP_INDEX());
  assert.deepEqual(index.paths.slice(1).map((p) => [p.url, p.sources]), [
    [`${base}/sitemap.xml`, ['sitemap-index']], [`${base}/sitemap-2.xml.gz`, ['sitemap-index']]]);

  const json = await collect(`${base}/data.json`);
  assert.equal(json.body, '{"a":"/a"}');
  assert.deepEqual(json.paths, [DOC(`${base}/data.json`)], 'paths inside JSON/JS are not extracted (backlog)');

  const bin = await collect(`${base}/bin.png`);
  assert.equal(bin.navigation.contentType, 'image/png');
  assert.deepEqual([bin.body, core(bin)], [null, []]);
});

test('crawler removed: exactly one endpoint is visited, maxPages is rejected, repeated items are kept', T, async () => {
  const info = await collect(`${base}/`);
  assert.deepEqual(documents(info).sort(), [`${base}/`, `${base}/frame`], 'links are collected, never followed');
  assert.ok(onLoopback(info));
  for (const maxPages of [1, 2]) {
    await assert.rejects(collect(`${base}/`, { maxPages }), /crawling removed: pass endpoints explicitly via collectEach/);
  }
  const dups = await collect(`${base}/dups`);
  assert.equal(dups.structure.links.length, 2, 'identical items on one page are data as received');
});

test('collectEach: input order, one failure does not stop the rest, a fresh session per URL', T, async () => {
  const before = await profiles();
  const urls = [`${base}/set`, 'ftp://example.invalid/', `http://127.0.0.1:${deadPort}/`, `${base}/echo`];
  const results = await collectEach(urls, { timeoutMs: 10000 });
  assert.deepEqual(results.map((r) => [r.url, r.ok]), [[urls[0], true], [urls[1], false], [urls[2], false], [urls[3], true]]);
  assert.match(results[1].error.message, /unsupported protocol/);
  assert.match(results[2].error.message, DEAD_ERR);
  assert.deepEqual(Object.keys(results[1]).sort(), ['error', 'ok', 'url']);
  assert.deepEqual(results[0].targetInfo.cookies.map((c) => c.name).sort(), ['pref', 'sid']);
  const echo = results[3].targetInfo;
  assert.deepEqual(echo.cookies, []);
  assert.equal(echo.meta.find((m) => m.name === 'seen-cookie').content, '', 'cookie from the previous URL must not leak');
  assert.equal(await profiles(), before);

  for (const bad of [[], 'http://x/', [1], null, [, `${base}/`], new Array(2)]) await assert.rejects(collectEach(bad), /non-empty array/);
  await assert.rejects(collectEach([`${base}/`], { timeoutMs: 0 }), /timeoutMs/, 'options are checked before any visit');
  await assert.rejects(collectEach([`${base}/`], { userAgent: 1 }), /userAgent must be a string/);
  await assert.rejects(collectEach([`${base}/`], 'fast'), /opts must be an object/);
});

test('follows HTTP redirects and records each hop with its raw headers', T, async () => {
  const info = await collect(`${base}/r1`);
  assert.equal(info.target.requestedUrl, `${base}/r1`);
  assert.equal(info.target.finalUrl, `${base}/`);
  assert.equal(info.navigation.status, 200);
  assert.deepEqual(header(info.headers, 'X-Fixture'), ['yes'], 'headers belong to the final document');
  const chain = info.navigation.redirectChain;
  assert.deepEqual(chain.map(({ from, to, status, kind }) => ({ from, to, status, kind })), [
    { from: `${base}/r1`, to: `${base}/r2`, status: 302, kind: 'http' },
    { from: `${base}/r2`, to: `${base}/`, status: 301, kind: 'http' },
  ]);
  assert.deepEqual(header(chain[0].headers, 'X-Hop'), ['one']);
  assert.deepEqual(header(chain[1].headers, 'location'), ['/']);
  assert.deepEqual(pathsOf(info)[`${base}/r2`].sources, ['redirect', 'request:document']);
});

test('V2: a 3xx that leads nowhere is a received response: resolve with it and a navigate error', T, async () => {
  const dead = await collect(`${base}/r-dead`, { timeoutMs: 10000 });
  assert.equal(dead.navigation.status, 302);
  assert.equal(dead.target.finalUrl, `${base}/r-dead`);
  assert.deepEqual(header(dead.headers, 'Set-Cookie'), ['hopc=1; Path=/']);
  assert.deepEqual(header(dead.headers, 'Server'), ['fixture']);
  assert.deepEqual(dead.errors.map((e) => e.stage), ['navigate']);
  assert.match(dead.errors[0].message, DEAD_ERR);
  assert.equal(dead.html, null);

  const loop = await collect(`${base}/loop`, { timeoutMs: 10000 });
  assert.equal(loop.navigation.status, 302);
  assert.ok(loop.navigation.redirectChain.length > 0 && loop.navigation.redirectChain.every((h) => h.kind === 'http'));
  assert.deepEqual(loop.errors.map((e) => e.stage), ['navigate']);
  assert.match(loop.errors[0].message, /ERR_TOO_MANY_REDIRECTS/);
});

test('client-side redirect: target, status, headers and structure all describe the landing document', T, async () => {
  const info = await collect(`${base}/client`);
  assert.equal(info.target.finalUrl, `${base}/landing`);
  assert.deepEqual(header(info.headers, 'x-page'), ['/landing']);
  assert.equal(info.navigation.status, 200);
  assert.deepEqual(info.navigation.redirectChain, [
    { from: `${base}/client`, to: `${base}/landing`, status: null, headers: null, kind: 'client' },
  ]);
  assert.deepEqual(info.meta, [{ name: 'who', content: 'landing' }]);
  assert.deepEqual(info.structure.forms.map((f) => f.action), [`${base}/landing`]);
});

test('V1: a reload of the same URL never pairs one document\'s headers with another\'s DOM', T, async () => {
  for (const d of [2, 5, 8, 8, 12]) {
    const info = await collect(`${base}/reload?d=${d}`);
    const doc = header(info.headers, 'x-doc')[0];
    const who = info.meta.find((m) => m.name === 'who')?.content;
    assert.equal(who, doc, `d=${d}: headers x-doc ${doc}, meta ${who}`);
    assert.ok(info.html.includes(`<p>${doc}</p>`), `d=${d}: html of the same document`);
  }
});

test('V0: non-HTML documents keep status/headers but no viewer DOM, judged by the document contentType', T, async () => {
  const missing = await collect(`${base}/missing`);
  assert.equal(missing.navigation.status, 404);
  assert.deepEqual(missing.errors, []);

  const json = await collect(`${base}/data.json`);
  assert.equal(json.navigation.contentType, 'application/json');
  assert.deepEqual([json.structure, json.meta, json.html], [EMPTY_STRUCTURE, [], null]);
  assert.deepEqual(json.errors, []);

  const plain = await collect(`${base}/plain`);
  assert.equal(plain.navigation.contentType, null, 'no Content-Type as received');
  assert.deepEqual([plain.structure, plain.meta, plain.html], [EMPTY_STRUCTURE, [], null], 'sniffed text/plain viewer dropped');
  assert.equal(plain.body, 'hello plain text body', 'sniffed text/plain body as received');

  const toJson = await collect(`${base}/to-json`);
  assert.equal(toJson.target.finalUrl, `${base}/data.json`);
  assert.equal(toJson.navigation.contentType, 'application/json');
  assert.deepEqual([toJson.meta, toJson.html], [[], null], 'JSON viewer DOM after a client redirect dropped');
});

test('a page that hangs after load still resolves within the budget and cleans up', T, async () => {
  const before = await profiles();
  const info = await collect(`${base}/busy`, { timeoutMs: 3000 });
  assert.equal(info.navigation.status, 200);
  assert.deepEqual(core(info), [{ stage: 'extract', message: `${base}/busy: timeout` }]);
  assert.equal(await profiles(), before);
});

test('V9: a JS-global read that spins in page code is terminated and the collect continues', T, async () => {
  const info = await collect(`${base}/proxy-hang`, { timeoutMs: 4000 });
  assert.deepEqual(core(info), [{ stage: 'js', message: `${base}/proxy-hang: timeout` }]);
  assert.equal(header(info.headers, 'x-page')[0], '/proxy-hang', 'later stages still ran');
  assert.match(info.html, /new Proxy/);
});

test('V8: core extraction comes first; slow DOM probes cost only their own stage', T, async () => {
  // The extra selectors cost ~17 ms each on 3000 siblings (O(n^2) `~` matching): ~35 s of probing on fast hardware,
  // against a probe slice of ~3 s, while the page loads and extracts in well under its 2.8 s.
  const slow = await moduleCopy('slow-probe', (data) => writeFile(join(data, 'technologies/zz-slow-probe.json'), JSON.stringify({
    'Slow probe': { cats: [59], website: 'https://example.invalid', dom: Object.fromEntries(Array.from({ length: 2000 }, (_, k) => [`b.k${k} ~ i`, { exists: '' }])) },
  })));
  const info = await slow.collect(`${base}/probe-dom`, { timeoutMs: 4000 });
  assert.deepEqual(info.errors, [{ stage: 'dom', message: `${base}/probe-dom: timeout` }]);
  assert.equal(info.technologies.find((t) => t.name === 'jQuery')?.version, '3.7.1', 'JS globals read before the slow DOM probes');
  assert.deepEqual(info.structure.links.map((l) => l.href), [`${base}/a`]);
});

test('W0: a document without a response (Chromium error page after a failed client navigation) is not target data', T, async () => {
  for (let i = 0; i < 3; i++) {
    const info = await collect(`${base}/to-dead`, { timeoutMs: 5000 });
    assert.equal(info.navigation.status, 200);
    assert.deepEqual(header(info.headers, 'x-page'), ['/to-dead']);
    assert.deepEqual([info.html, info.meta, info.structure], [null, [], EMPTY_STRUCTURE]);
    assert.deepEqual(core(info).map((e) => e.stage), ['extract']);
    assert.match(core(info)[0].message, new RegExp(`^${base}/to-dead: extracted document has no response \\(chrome-error://`));
  }
});

test('W1: a client redirect to a document that never loads still gets that document extracted', T, async () => {
  for (let i = 0; i < 2; i++) {
    const info = await collect(`${base}/to-slow`, { timeoutMs: 4000 });
    assert.equal(info.target.finalUrl, `${base}/slow-sub`);
    assert.deepEqual(header(info.headers, 'x-page'), ['/slow-sub']);
    assert.deepEqual(info.structure.links.map((l) => l.href), [`${base}/a`]);
    assert.ok(!info.errors.some((e) => e.stage === 'extract'), JSON.stringify(info.errors));
  }
});

test('G0/G2: a client redirect landing whose body is still arriving is read after it loads', T, async () => {
  for (let i = 0; i < 2; i++) {
    const info = await collect(`${base}/to-stream`, { timeoutMs: 8000 });
    assert.equal(info.target.finalUrl, `${base}/stream`);
    assert.deepEqual(info.structure.links.map((l) => l.href), [`${base}/early`, `${base}/late`]);
    assert.deepEqual(info.structure.forms.map((f) => f.action), [`${base}/late-form`]);
    assert.deepEqual(core(info), []);
  }
});

test('G1/G4: a never-answered navigation that starts during any renderer read is stopped; nothing is lost', T, async () => {
  const stopped = (info) => core(info).every((e) => e.message === `${info.target.requestedUrl}: pending navigation stopped`);
  for (const d of [0, 2, 4, 5, 6, 7, 8, 10, 12, 16, 25]) {
    const info = await collect(`${base}/late-nav?d=${d}`, { timeoutMs: 4000 });
    assert.deepEqual(info.structure.links.map((l) => l.href), [`${base}/landed`], `d=${d}`);
    assert.ok(stopped(info), `d=${d}: ${JSON.stringify(info.errors)}`);
    assert.equal(info.technologies.find((t) => t.name === 'jQuery')?.version, '3.7.1', `d=${d}: JS globals kept`);
  }
  for (let i = 0; i < 3; i++) {
    const info = await collect(`${base}/refresh-never`, { timeoutMs: 4000 });
    assert.deepEqual(info.structure.links.map((l) => l.href), [`${base}/landed`]);
    assert.ok(stopped(info), JSON.stringify(info.errors));
  }
});

test('W2: a pending navigation that never gets an answer is stopped and the committed DOM is extracted', T, async () => {
  for (const path of ['/stuck-load', '/stuck-after-load', '/form-autosubmit']) {
    const info = await collect(`${base}${path}`, { timeoutMs: 4000 });
    assert.deepEqual(header(info.headers, 'x-page'), [path]);
    assert.deepEqual(info.structure.links.map((l) => l.href), [`${base}/landed`], path);
    const extract = core(info).filter((e) => e.stage === 'extract');
    assert.deepEqual(extract, [{ stage: 'extract', message: `${base}${path}: pending navigation stopped` }], path);
  }
  const answered = await collect(`${base}/client`, { timeoutMs: 4000 });
  assert.equal(answered.target.finalUrl, `${base}/landing`, 'a client redirect that answers is followed, not stopped');
  assert.deepEqual(answered.errors, []);
});

test('W4: DOM-probe and JS-global value caps cut matcher input only, so they do not set truncated', T, async () => {
  for (const path of ['/style-long', '/js-long', '/a']) {
    const info = await collect(`${base}${path}`);
    assert.deepEqual([info.errors, info.truncated], [[], false], path);
  }
});

test('load timeout and download still resolve with the received response', T, async () => {
  const slow = await collect(`${base}/slow-sub`, { timeoutMs: 3000 });
  assert.equal(slow.navigation.status, 200);
  assert.deepEqual(header(slow.headers, 'x-page'), ['/slow-sub']);
  assert.deepEqual(core(slow).map((e) => e.stage), ['load']);
  assert.deepEqual(slow.structure.links.map((l) => l.href), [`${base}/a`], 'committed DOM still extracted');

  const dl = await collect(`${base}/download`, { timeoutMs: 5000 });
  assert.equal(dl.navigation.status, 200);
  assert.deepEqual(header(dl.headers, 'content-disposition'), ['attachment; filename=x.txt']);
  assert.deepEqual(core(dl).map((e) => e.stage), ['navigate']);
  assert.deepEqual(dl.structure.links, []);
});

test('page content cannot break or forge extraction (clobbering, monkey-patching)', T, async () => {
  const info = await collect(`${base}/clobber`, { timeoutMs: 10000 });
  assert.deepEqual(info.errors, []);
  assert.deepEqual(info.meta, [{ name: 'description', content: 'clobbered' }]);
  const [form] = info.structure.forms;
  assert.equal(form.selector, '#f');
  assert.equal(form.action, `${base}/post`);
  assert.equal(form.raw, ' /post ');
  assert.deepEqual(form.fields.map((f) => f.name), ['parentElement', 'elements', 'getAttribute', 'id', 'localName']);
  assert.deepEqual(info.structure.links.map((l) => l.href), [`${base}/ok`, `${base}/svg-link`], 'SVG <a> resolved, not {}');
  assert.deepEqual(info.structure.scripts.filter((s) => s.src).map((s) => s.src), [`${base}/svg.js`]);
});

test('form action: missing or empty submits to the document URL, others resolve against <base>', T, async () => {
  const info = await collect(`${base}/forms`);
  assert.deepEqual(info.structure.forms.map(({ selector, action, raw }) => ({ selector, action, raw })), [
    { selector: '#none', action: `${base}/forms`, raw: null },
    { selector: '#empty', action: `${base}/forms`, raw: '' },
    { selector: '#rel', action: `${base}/other/post`, raw: 'post' },
  ]);
});

test('records duplicate and mixed-case headers line by line; cookies are the browser jar', T, async () => {
  const info = await collect(`${base}/set`);
  assert.deepEqual(header(info.headers, 'Set-Cookie'), ['sid=secret1; Path=/; HttpOnly', 'pref=dark; Path=/']);
  assert.deepEqual(header(info.headers, 'X-Mixed-Case'), ['v']);
  assert.deepEqual(header(info.headers, 'X-Dup'), ['one', 'two']);
  const sid = info.cookies.find((c) => c.name === 'sid');
  for (const k of ['name', 'value', 'domain', 'path', 'httpOnly', 'secure', 'sameSite']) assert.ok(k in sid, k);
  assert.deepEqual([sid.value, sid.httpOnly, sid.path], ['secret1', true, '/']);
});

test('sets truncated at the structure, resource, html and text caps', T, async () => {
  const links = await collect(`${base}/many-links`);
  assert.equal(links.structure.links.length, MAX_STRUCTURE_ITEMS);
  assert.equal(links.truncated, true);
  const imgs = await collect(`${base}/many-imgs`);
  assert.equal(imgs.resources.length, MAX_RESOURCES);
  assert.equal(imgs.truncated, true);
  const big = await collect(`${base}/big-html`);
  assert.equal(big.html.length, MAX_HTML_LENGTH);
  assert.ok(big.html.startsWith('<html><head></head><body><p>xxx'));
  assert.equal(big.truncated, true);
  const text = await collect(`${base}/long-text`);
  assert.equal(text.structure.links[0].text.length, MAX_TEXT_LENGTH);
  assert.equal(text.truncated, true);
  const body = await collect(`${base}/big.txt`);
  assert.equal(body.body.length, MAX_BODY_LENGTH);
  assert.equal(body.truncated, true);
  const paths = await collect(`${base}/many-paths.txt`);
  assert.ok(paths.body.endsWith(`Disallow: /p/${MAX_PATHS - 1}\n`), 'the body itself is whole');
  assert.equal(paths.paths.length, MAX_PATHS);
  assert.equal(paths.truncated, true);
});

test('V4: a page far larger than any cap is bounded inside the page; the host process survives', T, async () => {
  const before = await profiles();
  const info = await collect(`${base}/huge`, { timeoutMs: 60000 });
  assert.equal(info.navigation.status, 200);
  assert.equal(info.html.length, MAX_HTML_LENGTH);
  assert.equal(info.truncated, true);
  assert.ok(!info.errors.some((e) => e.stage === 'extract'), JSON.stringify(info.errors));
  assert.equal(await profiles(), before);
});

test('V5: matching of pathological html runs in a Worker, off the caller\'s event loop', T, async () => {
  const before = posted.length;
  const info = await collect(`${base}/lt`, { timeoutMs: 5000 });
  assert.ok(info.html.length > 4_990_000);
  assert.deepEqual(posted.slice(before), [info.html.length], 'exactly one Worker message, carrying the page html');
});

test('V7: a broken dataset costs only the fingerprint stage; collect still resolves', T, async () => {
  const copy = join(TMP, 'broken-module');
  const broken = await moduleCopy('broken-module', (data) => writeFile(join(data, 'technologies/q.json'), '{"Q": {'));
  for (let i = 0; i < 2; i++) {
    const info = await broken.collect(`${base}/`);
    assert.equal(info.navigation.status, 200);
    assert.ok(info.structure.links.length > 0);
    assert.deepEqual(info.errors.map((e) => e.stage), ['fingerprint']);
    assert.match(info.errors[0].message, /JSON/);
    assert.deepEqual(info.technologies, []);
  }
  // No dataset at all (scripts/fetch-dataset.mjs never ran): same outcome.
  await rm(join(copy, 'data'), { recursive: true });
  const missing = await import(`${pathToFileURL(join(copy, 'collect.mjs')).href}?missing`);
  const info = await missing.collect(`${base}/`);
  assert.ok(info.structure.links.length > 0);
  assert.deepEqual(info.errors.map((e) => e.stage), ['fingerprint']);
  assert.match(info.errors[0].message, /ENOENT/);
});

test('no mixing between assets: back-to-back and concurrent collects of different pages stay separate', T, async () => {
  const check = (fp, b) => {
    assert.deepEqual([fp.cookies.map((c) => c.name), b.cookies.map((c) => c.name)], [['PHPSESSID'], ['bsid']]);
    assert.deepEqual([header(fp.headers, 'X-Asset'), header(b.headers, 'X-Powered-By')], [[], []]);
    assert.deepEqual(b.structure.links.map((l) => l.href), [`${base}/b-only`]);
    assert.deepEqual([fp.structure.forms, b.structure.forms.map((f) => f.action)], [[], [`${base}/b-form`]]);
    const names = (info) => info.technologies.map((t) => t.name);
    assert.ok(names(fp).includes('WordPress') && !names(fp).includes('Joomla'), JSON.stringify([names(fp), fp.errors]));
    assert.ok(names(b).includes('Joomla'), JSON.stringify([names(b), b.errors]));
    for (const t of ['WordPress', 'Express', 'jQuery', 'Node.js']) assert.ok(!names(b).includes(t), `${t} leaked into asset b`);
  };
  const fp = await collect(`${base}/fp`);
  const b = await collect(`${base}/asset-b`);
  check(fp, b);
  check(await collect(`${base}/fp`), await collect(`${base}/asset-b`));
  const [cfp, cb] = await Promise.all([collect(`${base}/fp`), collect(`${base}/asset-b`)]);
  check(cfp, cb);
});

test('each collect uses an isolated browser session and removes its profile', T, async () => {
  const before = await profiles();
  const first = await collect(`${base}/set`);
  assert.deepEqual(first.cookies.map((c) => c.name).sort(), ['pref', 'sid']);

  const second = await collect(`${base}/echo`);
  assert.deepEqual(second.cookies, []);
  assert.equal(second.meta[0].content, '', 'cookie from previous collect must not leak');
  assert.equal(await profiles(), before);
});

test('options: userAgent, networkidle, null opts', T, async () => {
  const ua = await collect(`${base}/echo`, { userAgent: 'wp-test/1' });
  assert.equal(ua.meta.find((m) => m.name === 'seen-ua').content, 'wp-test/1');
  const idle = await collect(`${base}/idle-wait`, { waitUntil: 'networkidle' });
  assert.deepEqual(idle.structure.links.map((l) => l.href), [`${base}/after-idle`], 'read only once the network went idle');
  assert.equal((await collect(`${base}/a`, null)).navigation.status, 200);
});

test('rejects non-http(s) URLs and bad options', T, async () => {
  await assert.rejects(collect('file:///etc/passwd'), /unsupported protocol/);
  await assert.rejects(collect('not a url'), /Invalid URL/);
  await assert.rejects(collect(`${base}/`, { timeoutMs: 0 }), /timeoutMs/);
  await assert.rejects(collect(`${base}/`, { timeoutMs: 2 ** 31 }), /timeoutMs/);
  await assert.rejects(collect(`${base}/`, { waitUntil: 'domcontentloaded' }), /waitUntil/);
  await assert.rejects(collect(`${base}/`, { ignoreHTTPSErrors: 'yes' }), /ignoreHTTPSErrors/);
});

test('rejects only when no response arrived, and still removes the profile', T, async () => {
  const before = await profiles();
  await assert.rejects(collect(`http://127.0.0.1:${deadPort}/`, { timeoutMs: 5000 }), DEAD_ERR);
  assert.equal(await profiles(), before);
});

// A server that never answers: `hits` lists the request paths, `arrived` resolves on the first one.
async function silentServer() {
  const hits = [];
  let arrive;
  const arrived = new Promise((r) => { arrive = r; });
  const silent = createServer((req) => { hits.push(req.url); arrive(); });
  await new Promise((r) => silent.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${silent.address().port}`, hits, arrived, close: () => { silent.closeAllConnections(); silent.close(); } };
}

test('signal: an aborted signal rejects with AbortError before any browser starts; an abort after success changes nothing', T, async () => {
  const launched = launches.length;
  const reason = new Error('budget spent');
  const aborted = (err) => err.name === 'AbortError' && err.cause === reason;
  await assert.rejects(collect(`${base}/a`, { signal: AbortSignal.abort(reason) }), aborted);
  await assert.rejects(collectEach([`${base}/a`, `${base}/b`], { signal: AbortSignal.abort(reason) }), aborted);
  assert.equal(launches.length, launched, 'no browser started');

  const ac = new AbortController();
  const info = await collect(`${base}/a`, { signal: ac.signal });
  assert.deepEqual(getEventListeners(ac.signal, 'abort'), [], 'no listener left behind');
  ac.abort();
  assert.equal(info.navigation.status, 200);
  assert.deepEqual(core(info), []);
});

test('signal: an abort mid-navigation rejects within 2 s; that call\'s Chromium and profile are gone', T, async () => {
  const silent = await silentServer();
  try {
    const ac = new AbortController();
    const launched = launches.length;
    const run = collect(`${silent.url}/`, { signal: ac.signal, timeoutMs: 60000 });
    run.catch(() => {});
    await silent.arrived;
    const profile = launches[launched];
    assert.ok((await browsersOn(profile)).length > 0, 'process list sees the running browser by its profile');
    const t0 = Date.now();
    ac.abort(new Error('cancelled'));
    await assert.rejects(run, (err) => err.name === 'AbortError' && err.cause.message === 'cancelled');
    const ms = Date.now() - t0;
    assert.ok(ms < 2000, `${ms} ms`);
    assert.deepEqual(await browsersOn(profile), []);
    assert.equal(existsSync(profile), false);
    assert.deepEqual(getEventListeners(ac.signal, 'abort'), []);
  } finally {
    silent.close();
  }
});

test('collectEach: an abort rejects the whole call and the remaining URLs never start', T, async () => {
  const silent = await silentServer();
  try {
    const ac = new AbortController();
    const launched = launches.length;
    const run = collectEach([`${base}/a`, `${silent.url}/second`, `${silent.url}/third`], { signal: ac.signal });
    run.catch(() => {});
    await silent.arrived;
    ac.abort();
    await assert.rejects(run, { name: 'AbortError' });
    assert.deepEqual(silent.hits, ['/second']);
    assert.equal(launches.length, launched + 2, 'the third URL never started');
  } finally {
    silent.close();
  }
});

test('cookies: planted on the requested host only, sent with the navigation and in the jar as received', T, async () => {
  const echo = await collect(`${base}/echo`, { cookies: [{ name: 'sid', value: 'lab-1' }, { name: 'pref', value: 'a=b' }] });
  assert.deepEqual(echo.meta.find((m) => m.name === 'seen-cookie').content.split('; ').sort(), ['pref=a=b', 'sid=lab-1']);
  assert.deepEqual(echo.cookies.map(({ name, value, domain, path }) => [name, value, domain, path]).sort(),
    [['pref', 'a=b', '127.0.0.1', '/'], ['sid', 'lab-1', '127.0.0.1', '/']]);

  const cookies = [{ name: 'sid', value: 'lab-1' }];
  cookieSeen.length = 0;
  await collect(`${base}/cross`, { cookies });
  assert.deepEqual(Object.fromEntries(cookieSeen), { '127.0.0.1': 'sid=lab-1', localhost: null }, 'a localhost subresource gets none');

  cookieSeen.length = 0;
  const moved = await collect(`${base}/to-localhost`, { cookies });
  assert.equal(moved.target.finalUrl, `http://localhost:${new URL(base).port}/echo`);
  assert.deepEqual(cookieSeen, [['127.0.0.1', 'sid=lab-1']]);
  assert.equal(moved.meta.find((m) => m.name === 'seen-cookie').content, '', 'not sent after the redirect to localhost');
});

test('cookies and signal: invalid values are rejected before any browser starts', T, async () => {
  const launched = launches.length;
  for (const [cookies, message] of [
    ['sid=v', /cookies must be an array of at most 50/],
    [null, /cookies must be an array/],
    [Array.from({ length: MAX_COOKIES + 1 }, (_, i) => ({ name: `c${i}`, value: 'v' })), /cookies must be an array of at most 50/],
    [[{ name: '', value: 'v' }], /cookies\[0\]\.name/],
    [[{ name: 'sid', value: 'v' }, { name: 'a b', value: 'v' }], /cookies\[1\]\.name/],
    [[{ name: 'a;b', value: 'v' }], /cookies\[0\]\.name/],
    [[{ name: 'sid=x', value: 'v' }], /cookies\[0\]\.name/],
    [[{ name: 1, value: 'v' }], /cookies\[0\]\.name/],
    [[null], /cookies\[0\]\.name/],
    [new Array(1), /cookies\[0\]\.name/],
    [[{ name: 'sid' }], /cookies\[0\]\.value/],
    [[{ name: 'sid', value: 1 }], /cookies\[0\]\.value/],
    [[{ name: 'sid', value: 'a;b' }], /cookies\[0\]\.value/],
    [[{ name: 'sid', value: 'a\r\nSet-Cookie: x=1' }], /cookies\[0\]\.value/],
    [[{ name: 'sid', value: ' lab-1' }], /cookies\[0\]\.value/],
    [[{ name: 'sid', value: 'x'.repeat(4094) }], /cookies\[0\]: name \+ value must be at most 4096 bytes/],
  ]) {
    await assert.rejects(collect(`${base}/echo`, { cookies }), message, JSON.stringify(cookies));
    await assert.rejects(collectEach([`${base}/echo`], { cookies }), message, JSON.stringify(cookies));
  }
  await assert.rejects(collect(`${base}/echo`, { signal: 'stop' }), /signal must be an AbortSignal/);
  await assert.rejects(collectEach([`${base}/echo`], { signal: {} }), /signal must be an AbortSignal/);
  assert.equal(launches.length, launched);
});

// A copy of the module in TMP whose dataset `mutate(dataDir)` changes; resolves the copy's collect.mjs exports.
async function moduleCopy(name, mutate) {
  const copy = join(TMP, name);
  await mkdir(copy);
  for (const f of ['collect.mjs', 'fingerprint.mjs', 'fingerprint-worker.mjs', 'package.json']) await cp(new URL(f, MODULE), join(copy, f));
  await cp(new URL('data', MODULE), join(copy, 'data'), { recursive: true });
  await mutate(join(copy, 'data/webappanalyzer'));
  // Own wapalyzer-core: its setTechnologies() corrupts state when called twice, so a copy must not share its instance.
  await mkdir(join(copy, 'node_modules'));
  await symlink(fileURLToPath(new URL('node_modules/playwright', MODULE)), join(copy, 'node_modules/playwright'),
    process.platform === 'win32' ? 'junction' : 'dir');
  await cp(new URL('node_modules/wapalyzer-core', MODULE), join(copy, 'node_modules/wapalyzer-core'), { recursive: true });
  return import(pathToFileURL(join(copy, 'collect.mjs')).href);
}

const run = (args) => promisify(execFile)(process.execPath, [CLI, ...args], { timeout: 60000 });
test('CLI: one URL prints a TargetInfo, several print the collectEach array; usage errors exit 1', T, async () => {
  const out = join(TMP, 'out.json');
  await run(['--url', `${base}/`, '--out', out, '--timeout-ms', '10000', '--ignore-https-errors', 'false']);
  const info = JSON.parse(await readFile(out, 'utf8'));
  assert.equal(info.schemaVersion, SCHEMA_VERSION);

  const { stdout } = await run(['--url', `${base}/a`]);
  assert.equal(JSON.parse(stdout).target.finalUrl, `${base}/a`);

  const list = join(TMP, 'urls.txt');
  await writeFile(list, `# endpoints\n${base}/b\n\n  ${base}/a  \n# done\n`);
  const many = JSON.parse((await run(['--url', 'ftp://example.invalid/', '--urls-file', list])).stdout);
  assert.deepEqual(many.map((r) => [r.url, r.ok]), [['ftp://example.invalid/', false], [`${base}/b`, true], [`${base}/a`, true]]);
  assert.equal(many[1].targetInfo.target.finalUrl, `${base}/b`);
  await run(['--urls-file', list, '--out', out]);
  assert.deepEqual(JSON.parse(await readFile(out, 'utf8')).map((r) => r.ok), [true, true], '--urls-file alone, streamed to --out');

  // --out is replaced only on success: a failed run leaves the previous results as they were.
  const kept = await readFile(out, 'utf8');
  for (const args of [['--url', 'ftp://example.invalid/'], ['--url', `${base}/`, '--timeout-ms', 'abc']]) {
    assert.equal((await run([...args, '--out', out]).catch((e) => e)).code, 1);
    assert.equal(await readFile(out, 'utf8'), kept, args.join(' '));
  }
  assert.deepEqual((await readdir(TMP)).filter((n) => n.startsWith('out.json.')), [], 'no temp file left behind');

  for (const [args, message] of [
    [['--url', 'ftp://example.invalid/'], /unsupported protocol/],
    [[], /usage/],
    [['--url', `${base}/`, '--bogus'], /Unknown option/],
    [['--url', `${base}/`, '--max-pages', '2'], /Unknown option '--max-pages'/],
    [['--url', `${base}/`, '--url', `${base}/a`, '--timeout-ms', 'abc'], /timeoutMs/],
    [['--urls-file', join(TMP, 'nope.txt')], /ENOENT/],
    [['--url', `${base}/`, '--ignore-https-errors', 'maybe'], /ignore-https-errors/],
    [['--url', `${base}/`, '--url', `${base}/a`, '--out', join(TMP, 'no-dir', 'out.json')], /ENOENT/],
  ]) {
    const err = await run(args).catch((e) => e);
    assert.equal(err.code, 1, args.join(' '));
    assert.match(JSON.parse(err.stderr).error.message, message);
  }
});

test('fingerprints technologies and libraries from meta, script src, JS globals, headers and cookies', T, async () => {
  const info = await collect(`${base}/fp`);
  assert.deepEqual(info.errors, [], 'a `constructor` meta name does not abort matching');
  const tech = Object.fromEntries(info.technologies.map((t) => [t.name, t]));
  const fields = (name) => tech[name].evidence.map((e) => e.field);

  assert.equal(tech.WordPress.version, '6.5');
  assert.ok(tech.WordPress.categories.includes('CMS'));
  assert.deepEqual(tech.WordPress.evidence, [{ field: 'meta', key: 'generator', match: 'WordPress 6.5' }]);
  assert.equal(tech.jQuery.version, '3.7.1', 'version from the JS global (script path has none)');
  assert.deepEqual(tech.jQuery.categories, ['JavaScript libraries']);
  assert.deepEqual(fields('jQuery'), ['js']);
  assert.ok(tech.Express.categories.includes('Web frameworks'));
  assert.deepEqual(tech.Express.evidence, [{ field: 'headers', key: 'x-powered-by', match: 'Express' }], 'X-Powered-By normalized');
  assert.ok(fields('PHP').includes('cookies'));
  assert.deepEqual(tech['Node.js'].evidence, [{ field: 'implies', match: 'Express' }]);
  assert.deepEqual(tech.MySQL.evidence, [{ field: 'implies', match: 'WordPress' }]);
  for (const t of info.technologies) assert.ok(t.confidence >= 0 && t.confidence <= 100, t.name);

  const jquery = info.libraries.find((l) => l.name === 'jQuery');
  assert.deepEqual([jquery.version, jquery.source], ['3.7.1', 'fingerprint']);
  assert.ok(info.libraries.some((l) => l.name === 'Express'));
  assert.ok(!info.libraries.some((l) => l.name === 'WordPress'), 'CMS is not a library');
  assert.ok(onLoopback(info));

  const src = await collect(`${base}/fp-src`);
  const jq = src.technologies.find((t) => t.name === 'jQuery');
  assert.deepEqual([jq.version, [...new Set(jq.evidence.map((e) => e.field))]], ['3.7.1', ['scriptSrc']], 'version from the file name alone');
});
