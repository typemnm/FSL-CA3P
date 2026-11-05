import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { executeCurlRecorded } from '../attack-recorder.mjs';

const hasCurl = spawnSync('curl', ['--version']).status === 0;
const COOKIE = 's=COOKIEVALUE123';
let server;
let origin;

before(async () => {
  server = createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/api/posts') {
      req.resume();
      req.on('end', () => {
        res.writeHead(201, { 'Content-Type': 'application/json', 'Set-Cookie': 's=abc' });
        res.end(JSON.stringify({ id: 7 }));
      });
      return;
    }
    if (req.method === 'GET' && req.url === '/x') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise(resolve => server.close(resolve)));

test('a POST is recorded with redacted cookie and without Set-Cookie', { skip: !hasCurl }, async () => {
  const command = { method: 'POST', url: `${origin}/api/posts`, body: { title: 'hello' } };
  const { result, record } = await executeCurlRecorded(
    command,
    { allowedOrigin: origin, cookie: COOKIE },
    { id: 'rec-1', kind: 'create-post', page: 'board' },
  );

  assert.equal(result.success, true);
  assert.equal(result.status, 201);
  assert.equal(result.setCookie, 's=abc');

  assert.equal(record.schemaVersion, 'attack-record/1');
  assert.equal(record.id, 'rec-1');
  assert.equal(record.kind, 'create-post');
  assert.deepEqual(record.target, { origin });
  assert.deepEqual(record.info, { page: 'board' });
  assert.deepEqual(record.request, {
    method: 'POST',
    url: `${origin}/api/posts`,
    headers: { cookie: '[redacted]' },
    body: { title: 'hello' },
  });
  assert.equal(record.response.status, 201);
  assert.deepEqual(record.response.headers, {});
  assert.deepEqual(record.response.bodyJson, { id: 7 });
  assert.equal(record.response.bodyText, '{"id":7}');
  assert.equal(record.response.error, null);
  assert.equal(typeof record.response.elapsedMs, 'number');
  assert.equal(Number.isNaN(Date.parse(record.observedAt)), false);

  const serialized = JSON.stringify(record);
  assert.equal(serialized.includes('COOKIEVALUE123'), false);
  assert.equal(serialized.includes('s=abc'), false);
});

test('a GET without cookie records empty headers and the JSON body', { skip: !hasCurl }, async () => {
  const { result, record } = await executeCurlRecorded(
    { method: 'GET', url: `${origin}/x` },
    { allowedOrigin: origin },
    { id: 'rec-2', kind: 'read' },
  );

  assert.equal(result.success, true);
  assert.deepEqual(record.request.headers, {});
  assert.equal(record.request.body, null);
  assert.equal(record.response.status, 200);
  assert.deepEqual(record.response.bodyJson, { ok: true });
  assert.deepEqual(record.info, {});
});

test('a command on another origin records an error and null status', { skip: !hasCurl }, async () => {
  const { result, record } = await executeCurlRecorded(
    { method: 'GET', url: 'http://127.0.0.1:1/x' },
    { allowedOrigin: origin },
    { id: 'rec-3', kind: 'read' },
  );

  assert.equal(result.success, false);
  assert.equal(record.response.status, null);
  assert.equal(record.response.error, 'origin_not_allowed');
  assert.equal(record.target.origin, origin);
});
