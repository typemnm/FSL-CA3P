import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { spawn, execFile } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { scan } from '../parser.mjs';
import { analyzeScript } from '../script-hints.mjs';

async function localServer(handler) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { server, url: 'http://127.0.0.1:' + server.address().port };
}

async function close(server) {
  server.close();
  await once(server, 'close');
}

test('static behavior hints follow named functions without merging unrelated event handlers', () => {
  const source = `
    function remove() { fetch('/delete', {method:'DELETE'}); }
    function render(row) {
      document.querySelector('#result').innerHTML = row.content;
      document.querySelector('#remove').addEventListener('click', remove);
    }
    function load() { fetch('./api/list'); render(data); }
    document.querySelector('#send').addEventListener('click', () => {
      axios.post('./api/save', {title: 'sample'}); load();
    });`;
  const { behaviors, truncated } = analyzeScript(source, 'http://127.0.0.1:3000/app.js',
    'http://127.0.0.1:3000/board/');
  const send = behaviors.find(item => item.trigger.selector === '#send');
  assert.equal(truncated, false);
  assert.deepEqual(send.api.map(item => [item.method, item.url]), [
    ['POST', 'http://127.0.0.1:3000/board/api/save'],
    ['GET', 'http://127.0.0.1:3000/board/api/list']
  ]);
  assert.deepEqual(send.api[0].bodyKeys, ['title']);
  assert.ok(send.updates.some(item => item.selector === '#result' && item.value === 'row.content'));
  assert.equal(send.api.some(item => item.method === 'DELETE'), false);
});

test('describes pages and visible components in one small JSON structure', async () => {
  let writes = 0;
  const { server, url } = await localServer((request, response) => {
    if (request.method !== 'GET') writes++;
    const html = request.url.startsWith('/search') ?
      '<title>Search</title><main><h1>Search</h1><form><input name="q"><button>Go</button></form></main>' :
      `<!doctype html><title>Board</title><main><section><h2>Write</h2>
        <form action="/submit" method="post"><input type="hidden" name="csrf">
        <label>Title <input name="title"></label><textarea name="content"></textarea>
        <button type="submit">Publish</button></form></section>
        <section><h2>Feed</h2><div id="results" aria-live="polite">
          <article data-post-id="7"><h3>첫 번째 글</h3><span class="author-name">민수</span>
            <div class="post-content">본문 하나</div><button type="button">삭제</button></article>
          <article><span class="post-number">NO. 8</span><h3>두 번째 글</h3>
            <span class="author-name">지영</span><div class="post-content">본문 둘</div></article>
        </div></section>
        <a href="/search?q=secret-value">Search page</a><a href="/delete">Delete</a>
        <script>setTimeout(()=>{const x=document.createElement('input');x.name='late';document.body.append(x)},20);
          document.querySelector('form').addEventListener('submit',e=>{
            e.preventDefault();fetch('/api/save',{method:'POST',body:JSON.stringify({title:1})});
            document.querySelector('#results').innerHTML=title;
          });
          fetch('/write',{method:'POST'}).catch(()=>{});</script></main>`;
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(html);
  });
  try {
    const report = await scan(url + '/?entry=secret-value', { maxPages: 2, waitMs: 120 });
    assert.deepEqual(Object.keys(report), ['schemaVersion', 'startUrl', 'pages', 'summary']);
    assert.equal(report.schemaVersion, '3.4');
    assert.equal(report.summary.scope, 'visited-client-pages');
    assert.equal(report.summary.pages, 2);
    assert.equal(report.summary.forms, 2);
    assert.equal('posts' in report.pages[1], false);
    assert.equal(writes, 0);
    const writeArea = report.pages[0].areas.find(area => area.kind === 'section' && area.name === 'Write');
    assert.deepEqual(writeArea.forms[0].fields.map(field => field.name), ['csrf', 'title', 'content']);
    assert.equal(writeArea.forms[0].fields[0].editable, false);
    assert.equal(writeArea.forms[0].htmlMethod, 'POST');
    assert.equal(writeArea.forms[0].htmlAction, url + '/submit');
    assert.equal(writeArea.buttons[0].form, writeArea.forms[0].selector);
    assert.ok(report.pages[0].areas.some(area => area.fields?.some(field => field.name === 'late')));
    assert.ok(report.pages[0].areas.some(area => area.outputs?.some(output => output.selector === '#results')));
    assert.deepEqual(report.pages[0].posts.map(post => [post.id, post.author, post.title]),
      [['7', '민수', '첫 번째 글'], ['8', '지영', '두 번째 글']]);
    assert.equal(report.pages[0].posts[0].idSource, 'dom-attribute');
    assert.equal(report.pages[0].posts[1].idSource, 'visible-label');
    assert.equal(report.pages[0].posts[0].body.preview, '본문 하나');
    assert.equal(report.pages[0].posts[0].buttons[0].label, '삭제');
    assert.equal(report.pages[0].posts[1].buttons, undefined);
    assert.ok(report.pages[0].areas.flatMap(area => area.links || []).some(link =>
      link.url.includes('/search') && link.visited));
    assert.equal(report.pages.some(page => page.url.includes('/delete')), false);
    const submit = report.pages[0].behaviors.find(behavior => behavior.trigger.event === 'submit');
    assert.equal(submit.trigger.selector, 'form');
    assert.deepEqual(submit.api[0].bodyKeys, ['title']);
    assert.equal(submit.api[0].method, 'POST');
    assert.equal(submit.evidence, 'static-js');
    assert.ok(submit.renderRefs.some(ref => report.pages[0].renderRules.some(rule =>
      rule.id === ref && rule.selector === '#results' && rule.operation === 'innerHTML')));
    assert.equal('updates' in submit, false);
    assert.equal(JSON.stringify(report).includes('secret-value'), false);
    assert.equal('siteMap' in report, false);
    assert.equal('inputPoints' in report, false);
  } finally { await close(server); }
});

test('reports unvisited links when the page limit is reached', async () => {
  const { server, url } = await localServer((_request, response) =>
    response.writeHead(200, { 'content-type': 'text/html' }).end('<a href="/next">Next</a>'));
  try {
    const report = await scan(url, { maxPages: 1, waitMs: 0 });
    assert.equal(report.summary.truncated, true);
    assert.equal(report.pages[0].areas.flatMap(area => area.links || [])[0].visited, false);
  } finally { await close(server); }
});

test('waits for the local page post list to finish rendering before reading DOM', async () => {
  const { server, url } = await localServer((request, response) => {
    if (request.url === '/api/posts') {
      setTimeout(() => response.writeHead(200, { 'content-type': 'application/json' })
        .end(JSON.stringify({ id: 41, title: 'loaded post' })), 300);
      return;
    }
    response.writeHead(200, { 'content-type': 'text/html' }).end(`
      <div id="post-list" aria-busy="true"></div>
      <script>
        fetch('/api/posts').then(response => response.json()).then(post => {
          document.querySelector('#post-list').innerHTML =
            '<article data-post-id="' + post.id + '"><h3>' + post.title + '</h3></article>';
          document.querySelector('#post-list').setAttribute('aria-busy', 'false');
        });
      </script>`);
  });
  try {
    const report = await scan(url, {
      maxPages: 1, waitMs: 0, readySelector: '#post-list[aria-busy="false"]',
    });
    assert.equal(report.summary.errors, 0);
    assert.deepEqual(report.pages[0].posts.map(post => post.id), ['41']);
    assert.ok(report.pages[0].observedRequests.some(request =>
      request.method === 'GET' && request.url.endsWith('/api/posts') && request.status === 200));
  } finally { await close(server); }
});

test('aborting during an in-flight browser wait stops the scan promptly', async () => {
  const { server, url } = await localServer((_request, response) =>
    response.writeHead(200, { 'content-type': 'text/html' })
      .end('<div id="post-list" aria-busy="true"></div>'));
  const controller = new AbortController();
  const started = Date.now();
  try {
    const pending = scan(url, {
      maxPages: 1, waitMs: 0, timeoutMs: 10_000,
      readySelector: '#post-list[aria-busy="false"]', signal: controller.signal,
    });
    setTimeout(() => controller.abort(), 250);
    await assert.rejects(pending, error => error.name === 'AbortError');
    assert.ok(Date.now() - started < 3_000, 'aborted scan should not wait for selector timeout');
  } finally { await close(server); }
});

test('blocks another local port, writes, and redirect targets', async () => {
  let outsideHits = 0;
  let writes = 0;
  const outside = await localServer((_request, response) => {
    outsideHits++;
    response.writeHead(200).end('outside');
  });
  const inside = await localServer((request, response) => {
    if (request.method !== 'GET') writes++;
    if (request.url === '/redirect') {
      response.writeHead(302, { location: outside.url + '/escaped' }).end();
      return;
    }
    response.writeHead(200, { 'content-type': 'text/html' }).end(`
      <a href="/redirect">Next</a><script>
      fetch('${outside.url}/other').catch(()=>{});
      for(const method of ['POST','PUT','PATCH','DELETE']) fetch('/write',{method}).catch(()=>{});
      </script>`);
  });
  try {
    const report = await scan(inside.url, { maxPages: 2, waitMs: 100 });
    assert.equal(outsideHits, 0);
    assert.equal(writes, 0);
    assert.equal(report.summary.pages, 2);
  } finally {
    await close(inside.server);
    await close(outside.server);
  }
});

test('maps the real vul-web-1 as page areas, forms, buttons, links, and outputs', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), 'basic-parser-board-'));
  const child = spawn(process.execPath, ['vul-web-1/server.js'], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, HOST: '127.0.0.1', PORT: '0', BOARD_DATA_FILE: join(dataDir, 'posts.json') },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  try {
    const [chunk] = await once(child.stdout, 'data');
    const port = /127\.0\.0\.1:(\d+)/.exec(String(chunk))?.[1];
    assert.ok(port);
    const url = 'http://127.0.0.1:' + port;
    const report = await scan(url, { maxPages: 1, waitMs: 500 });
    const areas = report.pages[0].areas;
    assert.ok(areas.some(area => !('forms' in area) && !('fields' in area)));
    const writeArea = areas.find(area => area.name.includes('새 글 쓰기'));
    assert.ok(writeArea);
    assert.deepEqual(writeArea.forms[0].fields.map(field => field.name), ['title', 'content']);
    assert.equal(writeArea.forms[0].htmlMethod, 'GET');
    assert.equal(writeArea.forms[0].htmlAction, url + '/');
    assert.ok(areas.flatMap(area => area.buttons || []).some(button => button.label?.includes('새로고침')));
    assert.ok(areas.flatMap(area => area.outputs || []).some(output => output.selector === '#post-list'));
    assert.ok(areas.flatMap(area => area.outputs || []).some(output => output.kind === 'article' && output.count === 3));
    assert.equal(report.summary.posts, 3);
    assert.deepEqual(report.pages[0].posts.map(post => post.id), ['3', '2', '1']);
    assert.deepEqual(report.pages[0].posts.map(post => post.author), ['밥', '관리자', '관리자']);
    assert.equal(report.pages[0].posts[0].title, '오늘의 첫 인사 👋');
    assert.ok(report.pages[0].posts[0].body.preview.includes('반갑습니다'));
    const bodyRule = report.pages[0].renderRules.find(rule =>
      rule.id === report.pages[0].posts[0].body.renderRef);
    assert.equal(bodyRule.selector, '.post-content');
    assert.equal(bodyRule.operation, 'innerHTML');
    assert.equal(bodyRule.evidence, 'static-js');
    assert.ok(report.pages[0].posts.every(post => post.body.renderRef === bodyRule.id));
    assert.ok(report.pages[0].posts.every(post =>
      !('renderOperation' in post.body) && !('renderEvidence' in post.body)));
    assert.ok(report.pages[0].posts.every(post => !('buttons' in post)));
    assert.equal(report.pages[0].renderRules.filter(rule => rule.selector === '.post-content' &&
      rule.operation === 'innerHTML').length, 1);
    const ruleIds = new Set(report.pages[0].renderRules.map(rule => rule.id));
    assert.ok(report.pages[0].behaviors.every(behavior =>
      (behavior.renderRefs || []).every(ref => ruleIds.has(ref)) && !('updates' in behavior)));
    const publish = report.pages[0].behaviors.find(behavior =>
      behavior.trigger.event === 'submit' && behavior.trigger.selector === '#post-form');
    assert.ok(publish.api.some(api => api.method === 'POST' && api.url.endsWith('/api/posts') &&
      api.bodyKeys.join(',') === 'title,content'));
    assert.ok(publish.renderRefs.includes(bodyRule.id));
    assert.equal(bodyRule.value, 'post.content');
    assert.ok(publish.renderRefs.every(ref => report.pages[0].renderRules.some(rule => rule.id === ref)));
    assert.ok(report.pages[0].behaviors.some(behavior => behavior.trigger.selector === '.delete-button' &&
      behavior.api.some(api => api.method === 'DELETE' && api.url.includes('/api/posts/{post.id}'))));
    assert.ok(report.pages[0].observedRequests.some(request =>
      request.method === 'GET' && request.url.endsWith('/api/posts') && request.status === 200));
    assert.ok(report.pages[0].behaviors.some(behavior =>
      behavior.trigger.selector === '#refresh-button' && behavior.api.some(api => api.url.endsWith('/api/posts'))));
    assert.equal(report.summary.errors, 0);
    assert.ok(Buffer.byteLength(JSON.stringify(report)) < 30_000);
    const { stdout } = await promisify(execFile)(process.execPath,
      ['cli.mjs', '--url', url, '--max-pages', '1', '--hide-body'], { cwd: new URL('..', import.meta.url) });
    const hidden = JSON.parse(stdout);
    assert.deepEqual(Object.keys(hidden), ['schemaVersion', 'startUrl', 'pages', 'summary']);
    assert.ok(hidden.pages[0].posts.every(post => post.body.preview === null));
    assert.deepEqual(hidden.pages[0].posts.map(post => post.id), ['3', '2', '1']);
  } finally {
    child.kill();
    await once(child, 'exit');
    await rm(dataDir, { recursive: true, force: true });
  }
});

test('rejects nonlocal URLs and removed view modes', async () => {
  await assert.rejects(scan('https://example.com/'), /loopback URL/);
  await assert.rejects(promisify(execFile)(process.execPath,
    ['cli.mjs', '--url', 'http://127.0.0.1:3000/', '--view', 'full'],
    { cwd: new URL('..', import.meta.url) }), error => {
    assert.equal(JSON.parse(error.stdout).error.code, 'PARSER_ERROR');
    return true;
  });
});
