import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SESSION_MS = 8 * 60 * 60 * 1000;
const passwordHash = (password, salt) => scryptSync(password, salt, 64).toString('hex');
const fail = (status, message) => Object.assign(new Error(message), { status });

export function hashAccount(username, password, role = 'operator') {
  const salt = randomBytes(16).toString('hex');
  return { username, role, salt, hash: passwordHash(password, salt) };
}

export function createAuthentication({ enabled = true,
  file = resolve(process.env.DASHBOARD_AUTH_FILE ?? fileURLToPath(new URL('../../.runtime/auth.json', import.meta.url))), users, now = Date.now,
} = {}) {
  const sessions = new Map(), attempts = new Map();
  let accounts = users;
  if (enabled && !accounts) {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    if (!existsSync(file)) {
      const passwords = { admin: randomBytes(18).toString('base64url'), viewer: randomBytes(18).toString('base64url') };
      const generated = Object.entries(passwords).map(([name, password]) => hashAccount(name, password, name));
      writeFileSync(file, JSON.stringify({ version: 1, users: generated }, null, 2), { mode: 0o600, flag: 'wx' });
      writeFileSync(join(dirname(file), 'access.txt'), Object.entries(passwords).map(([name, password]) => `${name}: ${password}`).join('\n') + '\n', { mode: 0o600 });
    }
    chmodSync(file, 0o600); accounts = JSON.parse(readFileSync(file, 'utf8')).users;
  }
  if (enabled && (!Array.isArray(accounts) || !accounts.length || accounts.some(user =>
    !/^[a-zA-Z0-9_-]{1,64}$/.test(user.username) || !['admin', 'operator', 'viewer'].includes(user.role)
    || !/^[a-f0-9]{32}$/.test(user.salt) || !/^[a-f0-9]{128}$/.test(user.hash)))) throw new Error('Invalid dashboard authentication configuration.');
  function session(req) {
    if (!enabled) return { user: { name: 'local', role: 'admin' }, csrfToken: null };
    const raw = /(?:^|;\s*)ca3p_session=([a-zA-Z0-9_-]{40,64})(?:;|$)/.exec(req.headers.cookie ?? '')?.[1];
    const value = raw ? sessions.get(raw) : undefined;
    if (!value || value.expiresAt <= now()) { if (raw) sessions.delete(raw); return null; }
    return { ...value, id: raw };
  }
  function describe(req) { const value = session(req); return { authRequired: enabled, authenticated: Boolean(value), user: value?.user ?? null, csrfToken: value?.csrfToken ?? null }; }
  function requireUser(req, { mutate = false, admin = false } = {}) {
    const value = session(req);
    if (!value) throw fail(401, '로그인이 필요합니다.');
    if (admin && value.user.role !== 'admin') throw fail(403, '관리자 권한이 필요합니다.');
    if (mutate && value.user.role === 'viewer') throw fail(403, '조회 계정으로 실행을 변경할 수 없습니다.');
    if (enabled && mutate && req.headers['x-csrf-token'] !== value.csrfToken) throw fail(403, 'CSRF token is required.');
    return value;
  }
  function login(req, body, { secure = false } = {}) {
    if (!enabled) return { body: describe(req), cookie: null };
    const ip = req.socket.remoteAddress ?? 'unknown', record = attempts.get(ip);
    if (record && record.until > now() && record.count >= 10) throw fail(429, '로그인 시도가 많습니다. 잠시 후 다시 시도하세요.');
    if (!body || typeof body.username !== 'string' || typeof body.password !== 'string'
      || body.username.length > 64 || body.password.length > 256 || Object.keys(body).some(k => !['username', 'password'].includes(k))) throw fail(400, '계정과 비밀번호를 확인하세요.');
    const user = accounts.find(value => value.username === body.username);
    const candidate = Buffer.from(passwordHash(body.password, user?.salt ?? '0'.repeat(32)), 'hex');
    const expected = Buffer.from(user?.hash ?? '0'.repeat(128), 'hex');
    if (!user || !timingSafeEqual(candidate, expected)) {
      attempts.set(ip, { count: record && record.until > now() ? record.count + 1 : 1, until: now() + 15 * 60 * 1000 });
      throw fail(401, '계정 또는 비밀번호가 맞지 않습니다.');
    }
    attempts.delete(ip);
    for (const [id, value] of sessions) if (value.expiresAt <= now()) sessions.delete(id);
    if (sessions.size >= 500) throw fail(429, 'Too many active sessions.');
    const id = randomBytes(32).toString('base64url');
    const value = { user: { name: user.username, role: user.role }, csrfToken: randomBytes(24).toString('base64url'), expiresAt: now() + SESSION_MS };
    sessions.set(id, value);
    return { body: { authRequired: true, authenticated: true, user: value.user, csrfToken: value.csrfToken },
      cookie: `ca3p_session=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${secure ? '; Secure' : ''}` };
  }
  function logout(req) {
    const value = session(req);
    if (enabled && value && req.headers['x-csrf-token'] !== value.csrfToken) throw fail(403, 'CSRF token is required.');
    if (value?.id) sessions.delete(value.id);
    return 'ca3p_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0';
  }
  return { enabled, describe, requireUser, login, logout };
}
