import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { chromium } from 'playwright';
import { openVerifierBrowser } from '../browser.mjs';

const CHROMIUM_AVAILABLE = existsSync(chromium.executablePath());
const PAGES = {
  '/ok': '<!doctype html><script>window.__ca3pXssProbe(\'m1\');</script>',
  '/with-asset': '<!doctype html><body><img src="/asset.png"></body>',
  '/writes': '<!doctype html><img src="http://127.0.0.1:9/x">'
    + '<script>fetch("/w", { method: "POST", body: "x" }).catch(() => {}); new WebSocket("ws://127.0.0.1:9");</script>',
  '/ready': '<!doctype html><body><script>setTimeout(() => { const el = document.createElement("div"); el.id = "ready"; el.textContent = "ready"; document.body.append(el); }, 100);</script>',
  '/never': '<!doctype html><p>never ready</p>',
  '/observe': '<!doctype html><title>Observed</title><body><script>'
    + 'alert(\'a1\'); console.log(\'c1\'); document.body.textContent = \'visible text\';'
    + 'setTimeout(() => { throw new Error(\'e1\'); }, 0);'
    + '</script></body>',
  '/long': '<!doctype html><body><script>document.body.textContent = \'가\'.repeat(5000);</script></body>',
  '/tall': '<!doctype html><body><div style="height:3000px">tall content</div></body>',
};
const DATA = { users: [{ id: 1, email: 'a@example.test', role: 'admin' }, { id: 2, token: 'x'.repeat(400) }] };

const seen = { writes: 0, cookies: [] };
let server;
let origin;

before(async () => {
  server = createServer((req, res) => {
    if (req.method !== 'GET') seen.writes += 1;
    seen.cookies.push(req.headers.cookie ?? '');
    if (req.method === 'GET' && req.url === '/data.json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(DATA));
    } else if (req.method === 'GET' && PAGES[req.url]) {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(PAGES[req.url]);
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise(resolve => {
  server.closeAllConnections();
  server.close(resolve);
}));

async function until(check, ms) {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() >= end) return false;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  return true;
}

async function observeWhen(session, check) {
  let snapshot = await session.observe();
  for (let i = 0; i < 100 && !check(snapshot); i += 1) {
    await new Promise(resolve => setTimeout(resolve, 25));
    snapshot = await session.observe();
  }
  return snapshot;
}

test('binding, selfCheck, cookies and screenshot work on a real page', { skip: !CHROMIUM_AVAILABLE }, async () => {
  const session = await openVerifierBrowser(origin, { cookies: [{ name: 'sid', value: 'v1' }] });
  try {
    const nav = await session.goto('/ok');
    assert.equal(nav.status, 200);
    assert.equal(nav.ready, true);
    assert.equal(await session.waitForBinding('m1', 2000), true);
    assert.equal(await session.waitForBinding('wrong', 300), false);
    assert.equal(await session.selfCheck(), true);
    assert.ok(seen.cookies.some(cookie => cookie.includes('sid=v1')));

    const dir = await mkdtemp(join(tmpdir(), 'verifier-browser-'));
    try {
      const shot = await session.screenshot(dir, 'viewport');
      const bytes = await readFile(join(dir, shot.file));
      assert.equal(shot.sha256, `sha256:${createHash('sha256').update(bytes).digest('hex')}`);
      assert.equal(shot.bytes, bytes.length);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  } finally {
    await session.close();
  }
});

test('request gate observes page resources and rejects before dispatch', { skip: !CHROMIUM_AVAILABLE }, async () => {
  const allowed = [];
  const session = await openVerifierBrowser(origin, { beforeRequest: request => { allowed.push(request.url); } });
  try {
    await session.goto('/with-asset');
    assert.equal(await until(() => allowed.some(url => url.endsWith('/asset.png')), 1000), true);
    assert.ok(allowed.some(url => url.endsWith('/with-asset')));
  } finally { await session.close(); }

  const denied = await openVerifierBrowser(origin, { beforeRequest: () => {
    throw Object.assign(new Error('quota'), { code: 'PARENT_TARGET_REQUEST_BUDGET_EXCEEDED', fatalProbe: true });
  } });
  try {
    await assert.rejects(denied.goto('/ok'), error => error.code === 'PARENT_TARGET_REQUEST_BUDGET_EXCEEDED');
  } finally { await denied.close(); }
});

test('writes are blocked while reads from other origins load', { skip: !CHROMIUM_AVAILABLE }, async () => {
  const session = await openVerifierBrowser(origin);
  try {
    await session.goto('/writes');
    const recorded = await until(() => session.blocked.some(entry => entry.reason === 'write blocked'), 3000);
    assert.equal(recorded, true);
    assert.equal(seen.writes, 0);
    assert.equal(session.blocked.some(entry => entry.reason === 'outside target origin'), false);
  } finally {
    await session.close();
  }
});

test('readySelector reports ready only when the element appears', { skip: !CHROMIUM_AVAILABLE }, async () => {
  const ready = await openVerifierBrowser(origin);
  try {
    assert.deepEqual(await ready.goto('/ready', { readySelector: '#ready' }), {
      status: 200,
      finalUrl: `${origin}/ready`,
      ready: true,
    });
  } finally {
    await ready.close();
  }

  const never = await openVerifierBrowser(origin, { timeoutMs: 2000 });
  try {
    const nav = await never.goto('/never', { readySelector: '#ready' });
    assert.equal(nav.ready, false);
    // A missing element must not use up the deadline: the page can still be observed.
    const observation = await never.observe();
    assert.equal(observation.finalUrl, `${origin}/never`);
  } finally {
    await never.close();
  }
});

test('an aborted signal rejects with AbortError', { skip: !CHROMIUM_AVAILABLE }, async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(openVerifierBrowser(origin, { signal: controller.signal }), { name: 'AbortError' });
});

test('close is idempotent', { skip: !CHROMIUM_AVAILABLE }, async () => {
  const session = await openVerifierBrowser(origin);
  await session.close();
  await session.close();
});

test('observe reports dialogs, console, page errors, title and text', { skip: !CHROMIUM_AVAILABLE }, async () => {
  const session = await openVerifierBrowser(origin);
  try {
    await session.goto('/observe');
    const snapshot = await observeWhen(session, snap => snap.dialogs.length
      && snap.console.length && snap.pageErrors.length && snap.text.includes('visible text'));
    assert.equal(snapshot.finalUrl, `${origin}/observe`);
    assert.equal(snapshot.title, 'Observed');
    assert.equal(snapshot.text, 'visible text');
    assert.deepEqual(snapshot.dialogs, [{ type: 'alert', message: 'a1' }]);
    assert.deepEqual(snapshot.console, [{ type: 'log', text: 'c1' }]);
    assert.deepEqual(snapshot.pageErrors, ['e1']);
    assert.equal(session.pageErrors(), 1);
    assert.deepEqual(snapshot.bindingCalls, []);
    assert.deepEqual(snapshot.blocked, []);
  } finally {
    await session.close();
  }
});

test('observe bounds text to 4096 utf8 bytes on whole characters', { skip: !CHROMIUM_AVAILABLE }, async () => {
  const session = await openVerifierBrowser(origin);
  try {
    await session.goto('/long');
    const snapshot = await observeWhen(session, snap => snap.text.length > 0);
    assert.ok(Buffer.byteLength(snapshot.text) <= 4096);
    assert.ok(snapshot.text.length > 0);
    assert.ok(!snapshot.text.includes('�'));
  } finally {
    await session.close();
  }
});

const pngSize = png => ({ width: png.readUInt32BE(16), height: png.readUInt32BE(20) });

test('a JSON page is shot as indented, wrapped JSON clipped to its content; HTML keeps the viewport up to a 2000px cap', { skip: !CHROMIUM_AVAILABLE }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'verifier-browser-'));
  const session = await openVerifierBrowser(origin);
  const shoot = async path => {
    await session.goto(path);
    const observation = await session.observe();
    const shot = await session.screenshot(dir, 'viewport');
    return { observation, size: pngSize(await readFile(join(dir, shot.file))) };
  };
  try {
    const json = await shoot('/data.json');
    // The model still reads the raw response; only the screenshot is formatted.
    assert.equal(json.observation.contentType, 'application/json');
    assert.equal(json.observation.text, JSON.stringify(DATA));
    const dom = await session.page.evaluate(() => {
      const pre = document.querySelector('body > pre');
      return { children: document.body.children.length, text: pre.textContent, overflow: pre.scrollWidth > pre.clientWidth };
    });
    assert.deepEqual(dom, { children: 1, text: JSON.stringify(DATA, null, 2), overflow: false });
    assert.equal(json.size.width, 1280);
    assert.ok(json.size.height > 100 && json.size.height < 720, `JSON shot height ${json.size.height}`);

    assert.deepEqual((await shoot('/ok')).size, { width: 1280, height: 720 });
    const tall = await shoot('/tall');
    assert.equal(tall.observation.contentType, 'text/html');
    assert.deepEqual(tall.size, { width: 1280, height: 2000 });
    assert.equal(seen.writes, 0);
  } finally {
    await session.close();
    await rm(dir, { recursive: true, force: true });
  }
});
