import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import {
  createStoredXssCanary,
  observeStoredXssExecution,
  storedXssCanaryContent,
} from '../integrations/xss-parser.mjs';
import { startLocalLab } from '../local-lab-gateway.mjs';

const parserRequire = createRequire(new URL('../../xss-parser/package.json', import.meta.url));

function browserInstalled() {
  try {
    const { chromium } = parserRequire('playwright');
    return existsSync(process.env.XSS_PARSER_BROWSER_PATH || chromium.executablePath());
  } catch { return false; }
}

async function post(origin, title, content) {
  const response = await fetch(`${origin}/api/posts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title, content }),
  });
  assert.equal(response.status, 201);
  return (await response.json()).post;
}

test('the canonical canary has an unpredictable marker and fixed local-only payload', () => {
  const first = createStoredXssCanary();
  const second = createStoredXssCanary();
  assert.match(first.marker, /^[a-f0-9]{32}$/);
  assert.notEqual(first.marker, second.marker);
  assert.equal(first.content, storedXssCanaryContent(first.marker));
  assert.match(first.content, /src="data:image\/png;base64,AA"/);
  assert.throws(() => storedXssCanaryContent('bad'), /marker/);
});

test('the execution observer rejects non-local or ambiguous targets before launching Chromium', async () => {
  const { marker } = createStoredXssCanary();
  await assert.rejects(observeStoredXssExecution('https://example.org', { postId: 4, marker }), /loopback origin/);
  await assert.rejects(observeStoredXssExecution('http://127.0.0.1:1234/api/posts', { postId: 4, marker }), /loopback origin/);
  await assert.rejects(observeStoredXssExecution('http://127.0.0.1:1234', { postId: 0, marker }), /postId/);
  await assert.rejects(observeStoredXssExecution('http://127.0.0.1:1234', { postId: 4, marker: 'bad' }), /marker/);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(observeStoredXssExecution('http://127.0.0.1:1234', {
    postId: 4, marker, signal: controller.signal,
  }), error => error.name === 'AbortError');
});

test('a fresh browser confirms execution only for the exact stored canary and post', async t => {
  if (!browserInstalled()) {
    t.skip('Playwright Chromium is not installed in this environment.');
    return;
  }
  const lab = await startLocalLab();
  t.after(() => lab.close());
  const canary = createStoredXssCanary();
  const created = await post(lab.origin, 'stored XSS execution canary', canary.content);
  const before = await fetch(`${lab.origin}/api/posts`).then(response => response.json());

  const observed = await observeStoredXssExecution(lab.origin, {
    postId: created.id,
    marker: canary.marker,
  });
  assert.deepEqual(observed, {
    executed: true,
    marker: canary.marker,
    postId: created.id,
    pageUrl: `${lab.origin}/`,
    postVisible: true,
    payloadPresent: true,
    bindingCalled: true,
    errors: [],
  });

  const wrongPost = await observeStoredXssExecution(lab.origin, {
    postId: 1,
    marker: canary.marker,
  });
  assert.equal(wrongPost.bindingCalled, true);
  assert.equal(wrongPost.payloadPresent, false);
  assert.equal(wrongPost.executed, false);

  const after = await fetch(`${lab.origin}/api/posts`).then(response => response.json());
  assert.deepEqual(after.posts, before.posts);
});

test('browser observation blocks extra local writes and off-origin requests', async t => {
  if (!browserInstalled()) {
    t.skip('Playwright Chromium is not installed in this environment.');
    return;
  }
  const lab = await startLocalLab();
  t.after(() => lab.close());
  await post(lab.origin, 'unrelated browser requests',
    `<img src="http://127.0.0.1:9/outside" onerror="fetch('/api/posts',{method:'POST',body:'{}'})">`);
  const canary = createStoredXssCanary();
  const created = await post(lab.origin, 'bounded canary', canary.content);
  const before = await fetch(`${lab.origin}/api/posts`).then(response => response.json());
  const observed = await observeStoredXssExecution(lab.origin, {
    postId: created.id,
    marker: canary.marker,
  });
  const after = await fetch(`${lab.origin}/api/posts`).then(response => response.json());
  assert.equal(observed.executed, true);
  assert.ok(observed.errors.some(error => error.includes('outside target origin')));
  assert.ok(observed.errors.some(error => error.includes('local write')));
  assert.deepEqual(after.posts, before.posts);
});
