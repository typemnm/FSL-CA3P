import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { scan } from '../parser.mjs';

test('finds rendered entry points and stays passive on a local site', async () => {
  let writeRequests = 0;
  const server = createServer((request, response) => {
    if (request.method !== 'GET') {
      writeRequests++;
      response.writeHead(204).end();
      return;
    }
    if (request.url.startsWith('/api/feed')) {
      response.writeHead(200, { 'content-type': 'application/json' }).end('{"items":[]}');
      return;
    }
    const html = request.url.startsWith('/search') ?
      '<title>Search</title><form><label>Search <input name="q" type="search"></label></form>' :
      `<!doctype html><title>Board</title>
      <form id="post-form" action="/submit" method="post">
        <input type="hidden" name="csrf" value="secret-value">
        <label for="title">Title</label><input id="title" name="title" required maxlength="120">
        <label for="content">Comment</label><textarea id="content" name="content"></textarea>
        <button type="submit">Publish</button>
      </form>
      <a href="/search?q=secret-value&page=2">Search page</a>
      <a href="/delete?id=1">Delete</a>
      <script>
        setTimeout(() => {
          const search = document.createElement('input');
          search.setAttribute('aria-label', 'Live search');
          search.name = 'live';
          document.body.append(search);
        }, 20);
        fetch('/api/feed').catch(() => {});
        fetch('/api/auto', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ token: 'secret-value' })
        }).catch(() => {});
      </script>`;
    response.writeHead(200, { 'content-type': 'text/html' }).end(html);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const url = 'http://127.0.0.1:' + server.address().port + '/?entry=secret-value';
    const report = await scan(url, { maxPages: 2, waitMs: 150, timeoutMs: 5000 });
    assert.equal(report.summary.pagesVisited, 2);
    assert.equal(report.summary.formsFound, 2);
    assert.equal(report.summary.blockedRequests >= 1, true);
    assert.equal(writeRequests, 0);
    assert.equal(report.pages[0].forms[0].submission.htmlDefault.method, 'POST');
    assert.deepEqual(report.pages[0].forms[0].fields.map(field => field.name), ['csrf', 'title', 'content']);
    assert.equal(report.pages[0].forms[0].fields[0].userEditable, false);
    assert.equal(report.pages[0].standaloneFields.some(field => field.name === 'live'), true);
    assert.equal(report.inputPoints.some(point => point.kind === 'url-query' && point.name === 'entry'), true);
    assert.equal(report.inputPoints.some(point => point.kind === 'url-query' && point.name === 'q'), true);
    assert.equal(report.pages[0].observedRequests.some(request => request.url.includes('/api/feed')), true);
    assert.equal(report.pages[0].scriptEndpointHints.some(hint =>
      hint.endpointUrlTemplate.includes('/api/auto') && hint.declaredMethod === 'POST' &&
      hint.bodyKeys.includes('token')), true);
    assert.equal(report.pages.some(page => page.url.includes('/delete')), false);
    assert.equal(JSON.stringify(report).includes('secret-value'), false);
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test('rejects a nonlocal URL before opening the browser', async () => {
  await assert.rejects(scan('https://example.com/'), /loopback URL/);
});
