import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ID, LIMITS, STATUSES, httpOrigin, redactHeaders, validateAttackRecord, evidenceItem, bodyDigest,
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

test('httpOrigin accepts any http(s) URL and returns its origin', () => {
  assert.equal(httpOrigin('http://127.0.0.1:4174/?q=1#x'), 'http://127.0.0.1:4174');
  assert.equal(httpOrigin('https://example.com/app'), 'https://example.com');
  assert.equal(httpOrigin('http://u:p@example.com'), 'http://example.com');
  for (const value of ['ftp://127.0.0.1', 'nope']) {
    assert.throws(() => httpOrigin(value), error => error.code === 'INVALID_ORIGIN', value);
  }
});

test('validateAttackRecord accepts external targets and requests to another origin', () => {
  const copy = validateAttackRecord(record({ target: { origin: 'https://example.com' },
    request: { method: 'POST', url: 'https://api.example.com/posts', headers: {}, body: null } }));
  assert.equal(copy.request.url, 'https://api.example.com/posts');
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
    record({ target: { origin: 'ftp://example.com' } }),
    record({ request: { method: 'POST', url: 'ftp://127.0.0.1/api/posts', headers: {}, body: null } }),
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

test('validateAttackRecord accepts setup exchanges, redacts them and rejects a bad setup', () => {
  const setup = [{ request: { method: 'POST', url: 'http://127.0.0.1:4174/api/posts', headers: { cookie: 'sid=abc' } },
    response: { status: 201 } }];
  const copy = validateAttackRecord(record({ setup }));
  assert.equal(copy.setup[0].request.headers.cookie, '[redacted]');
  for (const bad of [{ setup: {} }, { setup: ['x'] }, { setup: Array.from({ length: 9 }, () => ({})) }]) {
    assert.throws(() => validateAttackRecord(record(bad)), error => error.code === 'INVALID_ATTACK_RECORD');
  }
});
