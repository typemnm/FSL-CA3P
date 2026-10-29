import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ID, LIMITS, STATUSES, loopbackOrigin, redactHeaders, validateAttackRecord, evidenceItem, bodyDigest,
} from '../contract.mjs';

function record(overrides = {}) {
  return {
    schemaVersion: 'attack-record/1',
    id: 'atk-1',
    kind: 'stored_xss',
    target: { origin: 'http://127.0.0.1:4174' },
    info: { session: 'bob', victim: { role: 'alice' } },
    request: { method: 'POST', url: 'http://127.0.0.1:4174/api/posts', headers: { 'content-type': 'application/json', Cookie: 'sid=abc' }, body: { content: 'x' } },
    response: { status: 201, headers: { 'Set-Cookie': 'sid=abc' }, bodyText: '{"ok":true}', bodyJson: { ok: true }, error: null, elapsedMs: 3 },
    ...overrides,
  };
}

test('exports the contract constants', () => {
  assert.equal(ID.test('atk-1'), true);
  assert.equal(ID.test('-bad'), false);
  assert.equal(LIMITS.summaryBytes, 2048);
  assert.deepEqual(STATUSES, ['confirmed', 'not_reproduced', 'inconclusive']);
});

test('loopbackOrigin accepts loopback http(s) origins and rejects others', () => {
  assert.equal(loopbackOrigin('http://127.0.0.1:4174/?q=1#x'), 'http://127.0.0.1:4174');
  assert.equal(loopbackOrigin('https://localhost'), 'https://localhost');
  assert.equal(loopbackOrigin('http://[::1]:8080'), 'http://[::1]:8080');
  for (const value of ['http://example.com', 'ftp://127.0.0.1', 'http://u:p@127.0.0.1', 'http://127.0.0.1/app', 'nope']) {
    assert.throws(() => loopbackOrigin(value), error => error.code === 'INVALID_ORIGIN', value);
  }
});

test('redactHeaders masks secret headers case-insensitively without mutating input', () => {
  const headers = { Cookie: 'a=1', 'SET-COOKIE': 'b=2', Authorization: 'x', 'proxy-authorization': 'y', Accept: '*/*' };
  const redacted = redactHeaders(headers);
  assert.deepEqual(redacted, {
    Cookie: '[redacted]', 'SET-COOKIE': '[redacted]', Authorization: '[redacted]', 'proxy-authorization': '[redacted]', Accept: '*/*',
  });
  assert.equal(headers.Cookie, 'a=1');
});

test('validateAttackRecord returns a clone with headers redacted', () => {
  const input = record();
  const copy = validateAttackRecord(input);
  assert.notEqual(copy, input);
  assert.equal(copy.request.headers.Cookie, '[redacted]');
  assert.equal(copy.response.headers['Set-Cookie'], '[redacted]');
  assert.equal(copy.request.headers['content-type'], 'application/json');
  assert.equal(input.request.headers.Cookie, 'sid=abc');
});

test('validateAttackRecord rejects invalid records', () => {
  const cases = [
    record({ target: { origin: 'http://example.com' } }),
    record({ request: { method: 'POST', url: 'http://127.0.0.1:9999/api/posts', headers: {}, body: null } }),
    record({ id: '-bad' }),
    record({ schemaVersion: 'attack-record/0' }),
    record({ kind: 'x'.repeat(65) }),
    record({ kind: 7 }),
    record({ response: { status: '201' } }),
  ];
  for (const bad of cases) {
    assert.throws(() => validateAttackRecord(bad), error => error.code === 'INVALID_ATTACK_RECORD');
  }
});

test('kind is a free-form label that defaults to unspecified', () => {
  assert.equal(validateAttackRecord(record({ kind: 'ssrf' })).kind, 'ssrf');
  assert.equal(validateAttackRecord(record({ kind: 'x'.repeat(64) })).kind, 'x'.repeat(64));
  assert.equal(validateAttackRecord(record({ kind: undefined })).kind, 'unspecified');
});

test('evidenceItem adds observedAt and enforces size limits', () => {
  const item = evidenceItem({ id: 'e1', source: 'attack-module', kind: 'attack-exchange', asset: '/api', summary: 'ok' });
  assert.equal(item.summary, 'ok');
  assert.match(item.observedAt, /^\d{4}-\d{2}-\d{2}T/u);
  assert.throws(() => evidenceItem({ id: 'e1', source: 's', kind: 'k', asset: 'a', summary: 'x'.repeat(2049) }));
  assert.throws(() => evidenceItem({ id: 'e1', source: 's', kind: 'k', asset: 'a'.repeat(4000), summary: 'ok' }));
});

test('bodyDigest returns a 12-hex sha256 prefix or null', () => {
  assert.match(bodyDigest('hello'), /^sha256:[0-9a-f]{12}$/u);
  assert.equal(bodyDigest('hello'), bodyDigest('hello'));
  assert.equal(bodyDigest(''), null);
  assert.equal(bodyDigest(undefined), null);
});
