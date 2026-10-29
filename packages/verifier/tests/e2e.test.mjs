import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { executeCurlRecorded } from '../../adapters/attack-recorder.mjs';
import { verifyAttack } from '../index.mjs';
import { readReportHandoff, writeReportHandoff } from '../report-handoff.mjs';

const WAIT_FOR_POSTS = '#post-list[aria-busy="false"]';

function createStoredXssCanary() {
  const marker = `ca3p-${randomUUID()}`;
  return { marker, content: `<img src="/missing-canary.png" onerror="window.__ca3pXssProbe('${marker}')">` };
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/gu, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char]);
}

/** A contained loopback target for real browser and HTTP verifier tests. */
async function startLoopbackBoard({ safeMode = false } = {}) {
  const sessions = new Map();
  const posts = [];
  let nextPostId = 1;
  const sendJson = (res, status, value, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers });
    res.end(JSON.stringify(value));
  };
  const readJson = async req => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    return JSON.parse(raw);
  };
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://127.0.0.1');
      const sessionId = /(?:^|;\s*)sid=([^;]+)/u.exec(req.headers.cookie ?? '')?.[1];
      const userId = sessions.get(sessionId);
      if (req.method === 'POST' && url.pathname === '/api/session') {
        const input = await readJson(req);
        if (!['alice', 'bob'].includes(input.userId)) return sendJson(res, 400, { error: 'unknown user' });
        const id = randomUUID();
        sessions.set(id, input.userId);
        return sendJson(res, 200, { userId: input.userId }, { 'set-cookie': `sid=${id}; HttpOnly; Path=/` });
      }
      if (!userId) return sendJson(res, 401, { error: 'session required' });
      if (req.method === 'GET' && url.pathname === '/api/posts') return sendJson(res, 200, { posts });
      if (req.method === 'POST' && url.pathname === '/api/posts') {
        const input = await readJson(req);
        const post = { id: nextPostId++, authorId: userId,
          title: String(input.title ?? ''), content: String(input.content ?? '') };
        posts.push(post);
        return sendJson(res, 201, { post });
      }
      const postId = /^\/api\/posts\/(\d+)$/u.exec(url.pathname)?.[1];
      if (req.method === 'DELETE' && postId) {
        const index = posts.findIndex(post => post.id === Number(postId));
        if (index < 0) return sendJson(res, 404, { error: 'not found' });
        if (safeMode && posts[index].authorId !== userId) return sendJson(res, 403, { error: 'forbidden' });
        const [post] = posts.splice(index, 1);
        return sendJson(res, 200, { post });
      }
      if (req.method === 'GET' && url.pathname === '/') {
        const items = posts.map(post => `<li><h2>${escapeHtml(post.title)}</h2><div>${safeMode
          ? escapeHtml(post.content) : post.content}</div></li>`).join('');
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return res.end('<!doctype html><html><head><title>Posts</title></head><body>'
          + `<ul id="post-list" aria-busy="true">${items}</ul>`
          + '<script>window.addEventListener("load", () => document.getElementById("post-list")'
          + '.setAttribute("aria-busy", "false"))</script></body></html>');
      }
      return sendJson(res, 404, { error: 'not found' });
    } catch {
      if (!res.headersSent) sendJson(res, 400, { error: 'bad request' });
      else res.end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { origin, async close() {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  } };
}

async function login(origin, userId) {
  const response = await fetch(`${origin}/api/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ userId }),
  });
  await response.json();
  const pair = response.headers.get('set-cookie').split(';', 1)[0];
  const index = pair.indexOf('=');
  return { header: pair, cookie: { name: pair.slice(0, index), value: pair.slice(index + 1) } };
}

async function getText(url, cookie) {
  const response = await fetch(url, { headers: { cookie } });
  return response.text();
}

async function createPost(origin, cookie, title, content) {
  const response = await fetch(`${origin}/api/posts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ title, content }),
  });
  return (await response.json()).post;
}

async function tempOutDir(t) {
  const outDir = await mkdtemp(join(tmpdir(), 'ca3p-verifier-e2e-'));
  t.after(() => rm(outDir, { recursive: true, force: true }));
  return outDir;
}

// Stands in for the model: `reply(userPayload, round)` decides the answer; payloads are kept for assertions.
function scriptedModel(reply) {
  const model = {
    payloads: [],
    async completeJson({ userPayload }) {
      model.payloads.push(structuredClone(userPayload));
      return { value: reply(userPayload, model.payloads.length), metadata: { model: 'scripted' } };
    },
  };
  return model;
}

// Round 1 asks for alice's browser view; round 2 reads what the browser observed.
function xssModel(marker) {
  return scriptedModel((payload, round) => (round === 1
    ? { verdict: 'unknown', reason: 'the stored post only runs in alice\'s browser', browser: { path: '/', role: 'alice', waitFor: WAIT_FOR_POSTS } }
    : {
      verdict: (payload.browserObservation?.bindingCalls ?? []).some(call => call.value === marker) ? 'valid' : 'invalid',
      reason: 'checked the browser observation',
    }));
}

async function runStoredXss(origin, t, modelFor = () => undefined) {
  const bob = await login(origin, 'bob');
  const alice = await login(origin, 'alice');
  const { marker, content } = createStoredXssCanary();
  const { record } = await executeCurlRecorded(
    { method: 'POST', url: `${origin}/api/posts`, body: { title: 'verifier canary', content } },
    { allowedOrigin: origin, cookie: bob.header },
    {
      id: 'atk-xss-1',
      kind: 'stored_xss',
      session: 'bob',
      victim: { role: 'alice' },
      canary: { marker },
    },
  );
  assert.equal(record.response.status, 201);
  const outDir = await tempOutDir(t);
  const before = await getText(`${origin}/api/posts`, bob.header);
  const result = await verifyAttack(record, { outDir, sessions: { alice: [alice.cookie] }, model: modelFor(marker) });
  const after = await getText(`${origin}/api/posts`, bob.header);
  return { result, outDir, marker, before, after };
}

async function runCrossUserDelete(origin, t, model) {
  const bob = await login(origin, 'bob');
  const alice = await login(origin, 'alice');
  const post = await createPost(origin, bob.header, `verifier delete ${randomUUID()}`, 'verifier delete target');
  const { record } = await executeCurlRecorded(
    { method: 'DELETE', url: `${origin}/api/posts/${post.id}?authorId=bob` },
    { allowedOrigin: origin, cookie: alice.header },
    { id: 'atk-del-1', kind: 'cross_user_delete', session: 'alice', victim: { role: 'bob' } },
  );
  const outDir = await tempOutDir(t);
  let browserCalls = 0;
  const browserFactory = async () => {
    browserCalls += 1;
    throw new Error('the HTTP-only case must not open a browser');
  };
  const result = await verifyAttack(record, { outDir, model, browserFactory });
  return { result, browserCalls };
}

test('stored_xss is confirmed in a real browser on the vulnerable board', async t => {
  const lab = await startLoopbackBoard();
  t.after(() => lab.close());

  const hit = await runStoredXss(lab.origin, t, xssModel);
  assert.equal(hit.result.status, 'confirmed');
  assert.equal(hit.result.verdict, 'valid');
  assert.equal(hit.result.method, 'ai+browser');
  assert.ok(hit.result.browser.observation.bindingCalls.some(call => call.value === hit.marker));

  const screenshots = hit.result.artifacts.filter(artifact => artifact.kind === 'screenshot');
  assert.ok(screenshots.length >= 1);
  for (const shot of screenshots) assert.ok(existsSync(join(hit.outDir, shot.file)), shot.file);

  await writeReportHandoff(hit.result, { outDir: hit.outDir });
  const handoff = await readReportHandoff(hit.outDir);
  assert.equal(handoff.result.attackId, 'atk-xss-1');
  assert.equal(handoff.result.status, 'confirmed');
  assert.equal(handoff.images.length, screenshots.length);

  assert.equal(hit.after, hit.before, 'the verifier must not change the board');
});

test('stored_xss is not reproduced on the safe board: the marker shows as text only', async t => {
  const lab = await startLoopbackBoard({ safeMode: true });
  t.after(() => lab.close());

  const miss = await runStoredXss(lab.origin, t, xssModel);
  assert.equal(miss.result.status, 'not_reproduced');
  assert.equal(miss.result.verdict, 'invalid');
  const observation = miss.result.browser.observation;
  assert.equal(observation.bindingCalls.some(call => call.value === miss.marker), false);
  assert.ok(observation.text.includes(miss.marker), 'the canary should be visible as text');
});

test('cross_user_delete over HTTP is confirmed on the vulnerable board without a browser', async t => {
  const lab = await startLoopbackBoard();
  t.after(() => lab.close());
  const model = scriptedModel((payload) => ({
    verdict: payload.attack.response.status === 200 ? 'valid' : 'invalid',
    reason: 'the delete response status decides',
  }));

  const hit = await runCrossUserDelete(lab.origin, t, model);
  assert.equal(hit.result.status, 'confirmed');
  assert.equal(hit.result.method, 'ai');
  assert.equal(hit.browserCalls, 0);
});

test('cross_user_delete over HTTP is not reproduced on the safe board', async t => {
  const lab = await startLoopbackBoard({ safeMode: true });
  t.after(() => lab.close());
  const model = scriptedModel((payload) => ({
    verdict: payload.attack.response.status === 200 ? 'valid' : 'invalid',
    reason: 'the delete response status decides',
  }));

  const miss = await runCrossUserDelete(lab.origin, t, model);
  assert.equal(miss.result.status, 'not_reproduced');
  assert.equal(miss.browserCalls, 0);
});

// CI runs with zero skips and no live model calls, so this test exists only when opted in.
if (process.env.CA3P_VERIFIER_LIVE === '1') test('live model: stored_xss on the vulnerable board gets a verdict', async t => {
  const lab = await startLoopbackBoard();
  t.after(() => lab.close());

  const live = await runStoredXss(lab.origin, t);
  assert.equal(live.result.schemaVersion, 'verifier/1');
  assert.ok(['valid', 'invalid', 'unknown'].includes(live.result.verdict), `verdict was ${live.result.verdict}`);
  assert.ok(['confirmed', 'not_reproduced', 'inconclusive'].includes(live.result.status));
});
