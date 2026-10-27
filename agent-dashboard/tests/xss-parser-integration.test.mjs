import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { parseLocalSite } from '../integrations/xss-parser.mjs';
import { startLocalLab } from '../local-lab-gateway.mjs';

const origin = 'http://127.0.0.1:8123';

function report(overrides = {}) {
  return {
    schemaVersion: '3.4',
    startUrl: `${origin}/`,
    pages: [{
      id: 'page-1',
      url: `${origin}/`,
      title: 'Board',
      posts: [{ id: '4', idSource: 'visible-label', title: 'canary', author: '밥' }],
    }],
    summary: { scope: 'visited-client-pages', truncated: false, errors: 0 },
    ...overrides,
  };
}

test('adapts visible xss-parser observations without inventing account ownership', async () => {
  let called = null;
  const result = await parseLocalSite(origin, { scanImpl: async (...args) => {
    called = args;
    return report();
  } });
  assert.deepEqual(called, [`${origin}/`, {
    maxPages: 1,
    hideBody: true,
    waitMs: 0,
    readySelector: '#post-list[aria-busy="false"]',
    signal: undefined,
  }]);
  assert.deepEqual(result.observedPosts, [{
    id: '4', idSource: 'visible-label', title: 'canary', author: '밥', pageUrl: `${origin}/`,
  }]);
  assert.equal('authorId' in result.observedPosts[0], false);
  assert.equal(result.report.schemaVersion, '3.4');
  assert.deepEqual(result.errors, []);
  assert.equal(result.truncated, false);
});

test('surfaces page load errors and truncation instead of simulating successful observation', async () => {
  const result = await parseLocalSite(origin, { scanImpl: async () => report({
    pages: [{ id: 'page-1', url: `${origin}/`, error: 'navigation failed' }],
    summary: { scope: 'visited-client-pages', truncated: true, errors: 1 },
  }) });
  assert.deepEqual(result.observedPosts, []);
  assert.deepEqual(result.errors, [{ url: `${origin}/`, message: 'navigation failed' }]);
  assert.equal(result.truncated, true);
});

test('rejects external input and parser results from another origin', async () => {
  const scanImpl = async () => report();
  await assert.rejects(parseLocalSite('https://example.org', { scanImpl }), /loopback origin/);
  await assert.rejects(parseLocalSite(`${origin}/api/posts`, { scanImpl }), /loopback origin/);
  await assert.rejects(parseLocalSite(origin, { scanImpl: async () => report({
    pages: [{ id: 'page-1', url: 'http://127.0.0.1:9000/', posts: [] }],
  }) }), /another origin/);
});

test('reports browser or parser execution failure clearly', async () => {
  await assert.rejects(
    parseLocalSite(origin, { scanImpl: async () => { throw new Error('Executable does not exist'); } }),
    error => error.code === 'XSS_PARSER_FAILED'
      && /Executable does not exist/.test(error.message)
      && /playwright install chromium/.test(error.message),
  );
});

test('forwards cancellation to the browser scanner without disguising it as a missing installation', async () => {
  const controller = new AbortController();
  let forwarded;
  const pending = parseLocalSite(origin, {
    signal: controller.signal,
    scanImpl: (_url, options) => {
      forwarded = options.signal;
      return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => {
        const error = new Error('scan stopped');
        error.name = 'AbortError';
        reject(error);
      }, { once: true }));
    },
  });
  controller.abort();
  await assert.rejects(pending, error => error.name === 'AbortError' && error.message === 'scan stopped');
  assert.equal(forwarded, controller.signal);
});

test('real xss-parser reads the isolated local board with no writes', async t => {
  let browserInstalled = false;
  try {
    const { chromium } = await import('../../xss-parser/node_modules/playwright/index.mjs');
    browserInstalled = existsSync(process.env.XSS_PARSER_BROWSER_PATH || chromium.executablePath());
  } catch { /* Dependency absence is covered by the clear adapter failure path. */ }
  if (!browserInstalled) {
    t.skip('Playwright Chromium is not installed in this environment.');
    return;
  }
  const lab = await startLocalLab();
  try {
    const before = await (await fetch(`${lab.origin}/api/posts`)).json();
    const result = await parseLocalSite(lab.origin);
    const after = await (await fetch(`${lab.origin}/api/posts`)).json();
    assert.equal(result.report.schemaVersion, '3.4');
    assert.equal(result.report.summary.scope, 'visited-client-pages');
    assert.deepEqual(result.errors, []);
    assert.equal(result.truncated, false);
    assert.ok(result.observedPosts.some(post => post.id === '3'
      && post.title === '오늘의 첫 인사 👋' && post.author === '밥'));
    assert.ok(result.report.pages[0].observedRequests.some(request =>
      request.method === 'GET' && request.url.endsWith('/api/posts') && request.status === 200));
    assert.ok(result.report.pages[0].posts.every(post => post.body.preview === null));
    assert.deepEqual(after.posts, before.posts);
  } finally {
    await lab.close();
  }
});
