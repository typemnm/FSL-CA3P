import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuthentication, hashAccount } from '../auth.mjs';
const request = headers => ({ headers, socket: { remoteAddress: '127.0.0.1' } });
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
