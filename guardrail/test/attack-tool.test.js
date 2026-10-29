'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const { createServer } = require('node:http');
const { DatabaseSync } = require('node:sqlite');
const test = require('node:test');
const { createAttackToolGuardrail } = require('../src');
const { MAX_RESPONSE_BYTES } = require('../src/attack-tool');

const packet = q => ({ method: 'GET', path: '/api/search', query: { q } });

async function fixture(t) {
  const database = new DatabaseSync(':memory:');
  database.exec("CREATE TABLE items (name TEXT); INSERT INTO items VALUES ('alpha'), ('beta');");
  const requests = [];
  const server = createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    requests.push({ path: url.pathname, q: url.searchParams.get('q') });
    if (url.pathname === '/redirect') {
      response.writeHead(302, { location: '/api/search?q=alpha' }).end(); return;
    }
    if (url.pathname === '/large') {
      response.end('x'.repeat(MAX_RESPONSE_BYTES + 100)); return;
    }
    const q = url.searchParams.get('q');
    const results = url.pathname === '/safe'
      ? database.prepare('SELECT name FROM items WHERE name LIKE ?').all(`%${q}%`)
      : database.prepare(`SELECT name FROM items WHERE name LIKE '%${q}%'`).all();
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ count: results.length, results }));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    database.close();
  });
  return { origin: `http://127.0.0.1:${server.address().port}`, requests };
}

test('guardrail sends the SQLi packet to the exact trusted fixture and returns actual results', async t => {
  const { origin, requests } = await fixture(t);
  const guardrail = createAttackToolGuardrail({ targetOrigin: origin });
  const baseline = await guardrail.execute(packet('zzqnomatch'), { agentId: 'sql-agent', runId: 'run-1' });
  const attack = await guardrail.execute(packet("' OR '1'='1"), { agentId: 'sql-agent', runId: 'run-1' });
  assert.equal(baseline.status, 200);
  assert.equal(baseline.json.count, 0);
  assert.equal(attack.json.count, 2);
  assert.equal(attack.truncated, false);
  assert.equal(requests[1].q, "' OR '1'='1");
  assert.equal(guardrail.metrics().requestCount, 2);
  assert.deepEqual(guardrail.audit().map(item => item.decision), ['ALLOW', 'ALLOW']);
  const audit = guardrail.audit();
  audit[0].decision = 'DENY';
  assert.equal(guardrail.audit()[0].decision, 'ALLOW');
});

test('parameterized fixture does not reproduce the same SQLi payload', async t => {
  const { origin } = await fixture(t);
  const guardrail = createAttackToolGuardrail({ targetOrigin: origin, allowedPaths: ['/safe'] });
  const result = await guardrail.execute({ ...packet("' OR '1'='1"), path: '/safe' });
  assert.equal(result.json.count, 0);
});

test('out-of-scope packet variants are denied before any HTTP request', async () => {
  let calls = 0;
  const guardrail = createAttackToolGuardrail({ targetOrigin: 'http://127.0.0.1:4101',
    fetchImpl: async () => { calls += 1; return new Response('{}'); } });
  const variants = [
    { ...packet('x'), method: 'POST' },
    { ...packet('x'), path: 'http://example.invalid/api/search' },
    { ...packet('x'), path: '//example.invalid/api/search' },
    { ...packet('x'), path: '/api/../api/search' },
    { ...packet('x'), path: '/api/search?q=x' },
    { ...packet('x'), path: '/api/search#fragment' },
    { ...packet('x'), path: '/api/delete' },
    { ...packet('x'), query: { q: ['one', 'two'] } },
    { ...packet('x'), query: { q: 'x', origin: 'http://example.invalid' } },
    { ...packet('x'), query: { q: 'x'.repeat(4097) } },
    { ...packet('x'), headers: { authorization: 'secret' } },
    { ...packet('x'), origin: 'http://example.invalid' },
    { ...packet('x'), curl: 'curl anything' },
  ];
  for (const value of variants) await assert.rejects(guardrail.execute(value), { code: 'GUARDRAIL_DENIED' });
  assert.equal(calls, 0);
  assert.equal(guardrail.metrics().requestCount, 0);
  assert.ok(guardrail.audit().every(item => item.decision === 'DENY'));
});

test('payload special characters remain a single encoded query value', async () => {
  let observed;
  const guardrail = createAttackToolGuardrail({ targetOrigin: 'https://lab.example',
    fetchImpl: async (url, options) => {
      observed = { url: new URL(url), options };
      return new Response('{"count":0}', { headers: { 'content-type': 'application/json' } });
    } });
  const payload = "'&origin=http://example.invalid&x=1#frag";
  await guardrail.execute(packet(payload));
  assert.equal(observed.url.origin, 'https://lab.example');
  assert.deepEqual([...observed.url.searchParams], [['q', payload]]);
  assert.equal(observed.options.redirect, 'manual');
});

test('trusted origin and path configuration must be canonical', () => {
  for (const targetOrigin of ['http://user:pass@127.0.0.1:4101', 'http://127.0.0.1:4101/',
    'http://127.0.0.1:4101/path', 'http://127.0.0.1:4101#x', 'file:///tmp']) {
    assert.throws(() => createAttackToolGuardrail({ targetOrigin }), TypeError);
  }
  for (const path of ['/api/../api/search', '//example.invalid', '/api/search?q=x']) {
    assert.throws(() => createAttackToolGuardrail({ targetOrigin: 'http://127.0.0.1:4101', allowedPaths: [path] }), TypeError);
  }
});

test('guardrail never follows redirects or contacts the redirect destination', async t => {
  const { origin, requests } = await fixture(t);
  const guardrail = createAttackToolGuardrail({ targetOrigin: origin, allowedPaths: ['/redirect'] });
  await assert.rejects(guardrail.execute({ ...packet('x'), path: '/redirect' }), { code: 'GUARDRAIL_DENIED' });
  assert.deepEqual(requests.map(item => item.path), ['/redirect']);
  assert.equal(guardrail.audit().at(-1).reason, 'redirect_not_allowed');
});

test('request slots are reserved before dispatch, including failed and concurrent requests', async () => {
  let calls = 0;
  const guardrail = createAttackToolGuardrail({ targetOrigin: 'http://127.0.0.1:4101', maxRequests: 1,
    fetchImpl: async () => { calls += 1; throw new Error('transport failed'); } });
  const outcomes = await Promise.allSettled([guardrail.execute(packet('a')), guardrail.execute(packet('b'))]);
  assert.equal(calls, 1);
  assert.equal(outcomes[0].reason.message, 'transport failed');
  assert.equal(outcomes[1].reason.code, 'GUARDRAIL_DENIED');
  assert.equal(guardrail.metrics().requestCount, 1);
});

test('large responses are bounded and explicitly marked incomplete', async t => {
  const { origin } = await fixture(t);
  const guardrail = createAttackToolGuardrail({ targetOrigin: origin, allowedPaths: ['/large'] });
  const response = await guardrail.execute({ ...packet('x'), path: '/large' });
  assert.equal(Buffer.byteLength(response.body), MAX_RESPONSE_BYTES);
  assert.equal(response.truncated, true);
  assert.equal(Object.hasOwn(response, 'json'), false);
});

test('abort and timeout reach HTTP transport without allowing a later budget bypass', async () => {
  let calls = 0;
  const guardrail = createAttackToolGuardrail({ targetOrigin: 'http://127.0.0.1:4101', timeoutMs: 10,
    fetchImpl: async (_url, { signal }) => {
      calls += 1;
      return new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
    } });
  await assert.rejects(guardrail.execute(packet('x')), { name: 'TimeoutError' });
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(guardrail.execute(packet('x'), { signal: controller.signal }), { name: 'AbortError' });
  assert.equal(calls, 1);
  assert.equal(guardrail.metrics().requestCount, 1);
});

test('invalid UTF-8 cannot expand the returned body beyond its evidence limit', async () => {
  const guardrail = createAttackToolGuardrail({ targetOrigin: 'http://127.0.0.1:4101',
    fetchImpl: async () => new Response(Buffer.alloc(MAX_RESPONSE_BYTES, 255)) });
  const response = await guardrail.execute(packet('x'));
  assert.ok(Buffer.byteLength(response.body) <= MAX_RESPONSE_BYTES);
  assert.equal(response.truncated, true);
});
