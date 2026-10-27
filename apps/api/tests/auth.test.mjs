import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuthentication, hashAccount } from '../auth.mjs';
const request = (headers, remoteAddress = '127.0.0.1') => ({ headers, socket: { remoteAddress } });
test('sessions enforce viewer permissions, CSRF and logout', () => {
  const auth = createAuthentication({ users: [hashAccount('reader', 'secret-value', 'viewer'), hashAccount('owner', 'admin-secret', 'admin')] });
  assert.throws(() => auth.requireUser(request({})), { status: 401 });
  const reader = auth.login(request({}), { username: 'reader', password: 'secret-value' }, { secure: true });
  assert.match(reader.cookie, /HttpOnly; SameSite=Strict/); assert.match(reader.cookie, /Secure/);
  const readRequest = request({ cookie: reader.cookie.split(';')[0], 'x-csrf-token': reader.body.csrfToken });
  assert.equal(auth.requireUser(readRequest).user.role, 'viewer');
  assert.throws(() => auth.requireUser(readRequest, { mutate: true }), { status: 403 });
  const owner = auth.login(request({}), { username: 'owner', password: 'admin-secret' });
  const owned = request({ cookie: owner.cookie.split(';')[0] });
  assert.throws(() => auth.requireUser(owned, { mutate: true }), { status: 403 });
  owned.headers['x-csrf-token'] = owner.body.csrfToken; auth.requireUser(owned, { mutate: true }); auth.logout(owned);
  assert.equal(auth.describe(owned).authenticated, false);
});
test('login failures are bounded and sessions expire', () => {
  let clock = 1;
  const auth = createAuthentication({ users: [hashAccount('owner', 'correct', 'admin')], now: () => clock });
  const login = auth.login(request({}), { username: 'owner', password: 'correct' }); clock += 9 * 60 * 60 * 1000;
  assert.equal(auth.describe(request({ cookie: login.cookie.split(';')[0] })).authenticated, false);
  for (let i = 0; i < 10; i++) assert.throws(() => auth.login(request({}), { username: 'owner', password: 'wrong' }), { status: 401 });
  assert.throws(() => auth.login(request({}), { username: 'owner', password: 'correct' }), { status: 429 });
});

test('only an exact trusted proxy can supply the rightmost forwarded client IP for login limits', () => {
  const auth = createAuthentication({ users: [hashAccount('owner', 'correct', 'admin')], trustedProxyIps: ['192.168.0.3'] });
  const login = (remote, forwarded, password) => auth.login(request(
    forwarded === null ? {} : { 'x-forwarded-for': forwarded }, remote),
  { username: 'owner', password });
  for (let i = 0; i < 10; i++) assert.throws(() => login('192.168.0.3', 'spoofed-left, 203.0.113.10', 'wrong'), { status: 401 });
  assert.throws(() => login('192.168.0.3', 'another-spoof, 203.0.113.10', 'correct'), { status: 429 });
  assert.equal(login('192.168.0.3', '203.0.113.11', 'correct').body.authenticated, true);
  for (const forwarded of [null, '', '203.0.113.11, ', '203.0.113.11:5000', ['203.0.113.11']]) {
    assert.throws(() => login('192.168.0.3', forwarded, 'wrong'), { status: 400 });
  }
  assert.equal(login('192.168.0.3', '203.0.113.11', 'correct').body.authenticated, true);
  assert.equal(login('198.51.100.5', '203.0.113.10', 'correct').body.authenticated, true);
  for (let i = 0; i < 10; i++) assert.throws(() => login('198.51.100.6', `203.0.113.${i}`, 'wrong'), { status: 401 });
  assert.throws(() => login('198.51.100.6', '203.0.113.11', 'correct'), { status: 429 });
});

test('trusted IPv6 proxy and client addresses are normalized without trusting direct IPv6 headers', () => {
  const auth = createAuthentication({ users: [hashAccount('owner', 'correct', 'admin')],
    trustedProxyIps: '2001:0db8:0:0::10' });
  const body = { username: 'owner', password: 'correct' };
  assert.equal(auth.login(request({ 'x-forwarded-for': 'spoofed, [2001:db8::20]' }, '2001:db8::10'), body).body.authenticated, true);
  assert.equal(auth.login(request({ 'x-forwarded-for': '2001:db8::20' }, '2001:db8::21'), body).body.authenticated, true);
  assert.throws(() => createAuthentication({ users: [hashAccount('owner', 'correct', 'admin')],
    trustedProxyIps: ['192.168.0.3:81'] }), /Invalid trusted proxy IP configuration/);
});
