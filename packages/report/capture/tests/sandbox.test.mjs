import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { openSandbox } from '../sandbox.mjs';
import { capture } from '../screenshot.mjs';

const SWITCH = { method: 'POST', path: '/api/session', body: { userId: 'bob' } };

/** Tiny target that records every request and WebSocket upgrade it sees. */
async function target() {
  const hits = [];
  let upgrades = 0;
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    hits.push({ method: req.method, url: req.url, body: Buffer.concat(chunks).toString() });
    if (req.url === '/api/session' && req.method === 'POST') {
      res.setHeader('set-cookie', 'user=bob; Path=/');
      res.end('{}');
      return;
    }
    const user = /user=(\w+)/.exec(req.headers.cookie ?? '')?.[1] ?? 'alice';
    res.setHeader('content-type', 'text/html');
    res.end(`<!doctype html><title>t</title><p id="who">${user}</p>`);
  });
  server.on('upgrade', (req, socket) => { upgrades += 1; socket.destroy(); });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    hits,
    upgrades: () => upgrades,
    close: () => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }),
  };
}

async function sandboxOrSkip(t, origin, options) {
  try { return await openSandbox(origin, options); }
  catch (error) {
    if (error.code !== 'BROWSER_UNAVAILABLE') throw error;
    t.skip(`Chromium unavailable: ${error.message}`);
    return null;
  }
}

function send(page, url, method, body) {
  return page.evaluate(async request => {
    try { return (await fetch(request.url, { method: request.method, body: request.body })).status; }
    catch { return 'blocked'; }
  }, { url, method, body });
}

async function withTarget(t, options, run) {
  const server = await target();
  t.after(server.close);
  const sandbox = await sandboxOrSkip(t, server.origin, options);
  if (!sandbox) return;
  t.after(sandbox.close);
  await sandbox.page.goto(`${server.origin}/`);
  await run(server, sandbox);
}

test('origin that differs from expectedOrigin is refused before any browser starts', async () => {
  await assert.rejects(capture('http://127.0.0.1:4000', { outDir: tmpdir(), expectedOrigin: 'http://127.0.0.1:4001' }),
    { code: 'ORIGIN_MISMATCH' });
  await assert.rejects(capture('http://127.0.0.1:4000', { outDir: tmpdir() }), { code: 'ORIGIN_MISMATCH' });
  for (const origin of ['http://localhost:4000', 'https://127.0.0.1:4000', 'http://127.0.0.1:4000/', 'http://example.com']) {
    await assert.rejects(capture(origin, { outDir: tmpdir(), expectedOrigin: origin }), { code: 'INVALID_ORIGIN' });
  }
});

test('requests to another origin are blocked', async t => {
  const other = await target();
  t.after(other.close);
  await withTarget(t, {}, async (_server, { page, blocked }) => {
    assert.equal(await send(page, `${other.origin}/x`, 'GET'), 'blocked');
    assert.equal(other.hits.length, 0);
    assert.ok(blocked.some(entry => entry.reason === 'outside target origin'));
  });
});

test('same-origin POST and DELETE are blocked', async t => {
  await withTarget(t, {}, async (server, { page, blocked }) => {
    assert.equal(await send(page, '/api/posts', 'POST', '{"title":"x"}'), 'blocked');
    assert.equal(await send(page, '/api/posts/1', 'DELETE'), 'blocked');
    assert.equal(await send(page, '/', 'GET'), 200);
    assert.deepEqual(server.hits.filter(hit => hit.method !== 'GET'), []);
    assert.equal(blocked.filter(entry => entry.reason === 'write not in session-switch allow-list').length, 2);
  });
});

test('WebSocket connections are closed before reaching the target', async t => {
  await withTarget(t, {}, async (server, { page, blocked }) => {
    const opened = await page.evaluate(url => new Promise(resolve => {
      const socket = new WebSocket(url);
      socket.onopen = () => resolve(true);
      socket.onerror = socket.onclose = () => resolve(false);
    }), server.origin.replace('http', 'ws'));
    assert.equal(opened, false);
    assert.equal(server.upgrades(), 0);
    assert.ok(blocked.some(entry => entry.reason === 'websocket'));
  });
});

test('only the exact allow-listed session switch passes, once', async t => {
  await withTarget(t, { allowSessionSwitches: [SWITCH] }, async (server, { page, sessionSwitches }) => {
    assert.equal(await send(page, '/api/session', 'POST', '{"userId":"alice"}'), 'blocked');
    assert.equal(await send(page, '/api/session?x=1', 'POST', '{"userId":"bob"}'), 'blocked');
    assert.equal(await send(page, '/api/session', 'PUT', '{"userId":"bob"}'), 'blocked');
    assert.equal(await send(page, '/api/session', 'POST', '{"userId":"bob"}'), 200);
    assert.equal(await send(page, '/api/session', 'POST', '{"userId":"bob"}'), 'blocked');
    assert.deepEqual(server.hits.filter(hit => hit.method !== 'GET'),
      [{ method: 'POST', url: '/api/session', body: '{"userId":"bob"}' }]);
    assert.equal(sessionSwitches.length, 1);
  });
});

test('an empty allow-list permits no session switch', async t => {
  await withTarget(t, {}, async (server, { page }) => {
    assert.equal(await send(page, '/api/session', 'POST', '{"userId":"bob"}'), 'blocked');
    assert.equal(server.hits.filter(hit => hit.method === 'POST').length, 0);
  });
});

test('capture switches session, writes PNGs and returns hashed metadata', async t => {
  const server = await target();
  t.after(server.close);
  const outDir = await mkdtemp(join(tmpdir(), 'ca3p-capture-'));
  t.after(() => rm(outDir, { recursive: true, force: true }));
  let records;
  try {
    records = await capture(server.origin, {
      selector: '#who', fullPage: true, sessionSwitch: SWITCH, allowSessionSwitches: [SWITCH],
      outDir, expectedOrigin: server.origin,
    });
  } catch (error) {
    if (error.code !== 'BROWSER_UNAVAILABLE') throw error;
    t.skip(`Chromium unavailable: ${error.message}`);
    return;
  }
  assert.deepEqual(records.map(record => record.kind), ['element', 'fullPage']);
  for (const record of records) {
    const bytes = await readFile(record.path);
    assert.equal(record.sizeBytes, bytes.length);
    assert.equal(record.sha256, `sha256:${createHash('sha256').update(bytes).digest('hex')}`);
    assert.equal(record.mime, 'image/png');
    assert.equal(record.viewer, 'bob');
    assert.equal(record.pageUrl, `${server.origin}/`);
    assert.deepEqual(record.observations.sessionSwitch, { method: 'POST', path: '/api/session', body: '{"userId":"bob"}' });
  }
  assert.equal(server.hits.filter(hit => hit.method !== 'GET').length, 1);

  await assert.rejects(capture(server.origin, {
    sessionSwitch: { ...SWITCH, body: { userId: 'alice' } }, allowSessionSwitches: [SWITCH],
    outDir, expectedOrigin: server.origin,
  }), { code: 'SESSION_SWITCH_BLOCKED' });
});
