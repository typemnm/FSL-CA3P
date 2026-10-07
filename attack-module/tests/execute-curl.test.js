'use strict';

const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { after, before, test } = require('node:test');
const { executeCurl } = require('../index');

const requests = [];
let server;
let origin;

before(async () => {
  server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    requests.push({ method: request.method, url: request.url, body, cookie: request.headers.cookie });

    if (request.url === '/redirect') {
      response.writeHead(302, { Location: `${origin}/followed`, 'Content-Type': 'application/json' });
      response.end('{"redirect":true}');
      return;
    }
    if (request.url === '/large') {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ data: 'x'.repeat(1_100_000) }));
      return;
    }
    if (request.url === '/bad-json') {
      response.writeHead(200, { 'Content-Type': 'text/plain' });
      response.end('not json');
      return;
    }
    if (request.url === '/wait') {
      request.on('close', () => response.end());
      return;
    }
    response.writeHead(200, {
      'Content-Type': 'application/json',
      ...(request.url === '/session' ? { 'Set-Cookie': 'session=private-token; HttpOnly' } : {}),
    });
    response.end(JSON.stringify({ method: request.method, url: request.url, body }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
});

test('executes JSON GET, POST, and DELETE requests with trusted cookies', async () => {
  const get = await executeCurl({ method: 'GET', url: `${origin}/posts?owner=bob` }, { allowedOrigin: origin });
  assert.deepEqual(get, {
    success: true,
    status: 200,
    bodyJson: { method: 'GET', url: '/posts?owner=bob', body: '' },
    setCookie: null,
    error: null,
  });

  const post = await executeCurl({ method: 'POST', url: `${origin}/session`, body: { userId: 'bob' } }, { allowedOrigin: origin });
  assert.equal(post.success, true);
  assert.equal(post.setCookie, 'session=private-token; HttpOnly');
  assert.equal(post.bodyJson.body, '{"userId":"bob"}');

  const del = await executeCurl({ method: 'DELETE', url: `${origin}/posts/7?authorId=bob` }, {
    allowedOrigin: origin,
    cookie: 'session=private-token',
  });
  assert.equal(del.success, true);
  assert.equal(del.bodyJson.method, 'DELETE');
  assert.equal(requests.at(-1).cookie, 'session=private-token');
});

test('rejects off-origin URLs, extra curl flags, shell syntax, and bodies on DELETE', async () => {
  const count = requests.length;
  const commands = [
    { method: 'GET', url: 'http://example.com/api' },
    { method: 'GET', url: `${origin}/safe`, flags: ['--config', '/tmp/file'] },
    { method: 'GET', url: `${origin}/safe\r\nX-Injected: true` },
    { method: 'DELETE', url: `${origin}/safe`, body: {} },
    { method: 'GET', url: `${origin}/safe#fragment` },
    { method: 'GET', url: `${origin}/safe` },
  ];
  const expected = [
    'origin_not_allowed', 'invalid_command', 'invalid_url',
    'body_not_allowed', 'invalid_url', 'invalid_allowed_origin',
  ];
  for (let index = 0; index < commands.length; index += 1) {
    const result = await executeCurl(commands[index], {
      allowedOrigin: index === 5 ? 'https://127.0.0.1:443' : origin,
    });
    assert.equal(result.success, false);
    assert.equal(result.error, expected[index]);
  }
  assert.equal(requests.length, count);
});

test('does not follow redirects', async () => {
  const count = requests.length;
  const result = await executeCurl({ method: 'GET', url: `${origin}/redirect` }, { allowedOrigin: origin });
  assert.equal(result.success, false);
  assert.equal(result.status, 302);
  assert.equal(result.error, 'http_302');
  assert.equal(requests.length, count + 1);
  assert.equal(requests.at(-1).url, '/redirect');
});

test('caps responses and reports invalid JSON', async () => {
  const large = await executeCurl({ method: 'GET', url: `${origin}/large` }, { allowedOrigin: origin });
  assert.equal(large.success, false);
  assert.equal(large.error, 'response_too_large');

  const invalid = await executeCurl({ method: 'GET', url: `${origin}/bad-json` }, { allowedOrigin: origin });
  assert.equal(invalid.success, false);
  assert.equal(invalid.status, 200);
  assert.equal(invalid.error, 'invalid_json_response');
});

test('cancels an in-flight curl process', async () => {
  const controller = new AbortController();
  const pending = executeCurl({ method: 'GET', url: `${origin}/wait` }, {
    allowedOrigin: origin,
    signal: controller.signal,
  });
  setTimeout(() => controller.abort(), 50);
  const result = await pending;
  assert.equal(result.success, false);
  assert.equal(result.error, 'aborted');
});
