import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { lstat, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { basename, join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startDaehanResetSupervisor } from '../scripts/daehan-reset-supervisor.mjs';

const supervisorScript = fileURLToPath(new URL('../scripts/daehan-reset-supervisor.mjs', import.meta.url));

async function availablePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const chosen = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return chosen;
}

function count(dbPath, table) {
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try { return db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n; }
  finally { db.close(); }
}

test('local Daehan reset revokes sessions, reseeds and backs up its database, and is retryable', async t => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'ca3p-daehan-reset-test-'));
  const dbPath = join(temporaryRoot, 'data', 'daehan.sqlite');
  const token = 'isolated-test-reset-token-0123456789';
  const targetPort = await availablePort();
  const env = {
    ...process.env,
    NODE_ENV: 'test',
    CA3P_TEST_DAEHAN_DB_PATH: dbPath,
    CA3P_TEST_DAEHAN_PORT: String(targetPort),
    CA3P_DAEHAN_RESET_PORT: '0',
    CA3P_DAEHAN_RESET_TOKEN: token,
  };
  delete env.LAB_MEMORY_DB;
  let supervisor;
  t.after(async () => {
    if (supervisor) await supervisor.close();
    assert.equal(basename(temporaryRoot).startsWith('ca3p-daehan-reset-test-'), true);
    await rm(temporaryRoot, { recursive: true, force: true });
  });
  supervisor = await startDaehanResetSupervisor({ env });

  const body = {
    confirmation: 'reset-experiment-target',
    fixtureId: 'vul-web2-daehan',
    targetOrigin: supervisor.targetOrigin,
  };
  const reset = (candidate = body, bearer = token) => fetch(`${supervisor.origin}/_ca3p/experiment-reset`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${bearer}` },
    body: JSON.stringify(candidate),
  });

  assert.equal((await fetch(`${supervisor.origin}/health`)).status, 200);
  assert.equal((await fetch(`${supervisor.targetOrigin}/`)).status, 200);
  const baselinePosts = count(dbPath, 'posts');
  const firstPid = supervisor.childPid;
  assert.ok(firstPid > 0);

  const unauthorized = await reset(body, `${token}wrong`);
  assert.equal(unauthorized.status, 401);
  assert.equal((await reset({ ...body, targetOrigin: 'http://127.0.0.1:4101' })).status, 400);
  assert.equal((await reset({ ...body, databasePath: dbPath })).status, 400);
  assert.equal(supervisor.childPid, firstPid);

  const login = await fetch(`${supervisor.targetOrigin}/login`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'admin', password: 'admin1234', next: '/admin' }),
  });
  assert.equal(login.status, 302);
  const cookie = login.headers.get('set-cookie')?.split(';', 1)[0];
  assert.match(cookie, /^daehan_sid=/u);
  assert.equal((await (await fetch(`${supervisor.targetOrigin}/_diag/config`)).json()).activeSessions, 1);

  const createPost = await fetch(`${supervisor.targetOrigin}/admin/posts`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: new URLSearchParams({ type: 'notice', title: 'reset test mutation', body: 'temporary' }),
  });
  assert.equal(createPost.status, 302);
  assert.equal(count(dbPath, 'posts'), baselinePosts + 1);

  // A file outside the fixed SQLite set prevents a clean attestation and preserves state.
  const unknownFile = join(temporaryRoot, 'data', 'unexpected.txt');
  await writeFile(unknownFile, 'must not be deleted by reset');
  const refused = await reset();
  assert.equal(refused.status, 503);
  assert.equal(count(dbPath, 'posts'), baselinePosts + 1);
  assert.ok((await readdir(join(temporaryRoot, 'data'))).includes('unexpected.txt'));
  await rm(unknownFile);

  const clean = await reset();
  assert.equal(clean.status, 200);
  assert.deepEqual(await clean.json(), {
    status: 'clean', fixtureId: body.fixtureId, targetOrigin: body.targetOrigin,
    scopes: ['database', 'sessions', 'process', 'files'],
  });
  assert.notEqual(supervisor.childPid, firstPid);
  assert.equal(count(dbPath, 'posts'), baselinePosts);
  assert.equal((await (await fetch(`${supervisor.targetOrigin}/_diag/config`)).json()).activeSessions, 0);
  assert.equal((await fetch(`${supervisor.targetOrigin}/admin`, { headers: { cookie } })).status, 403);
  assert.deepEqual(await readdir(join(temporaryRoot, 'data')), ['daehan.sqlite']);

  const backupFolders = await readdir(join(temporaryRoot, '.reset-backups'));
  assert.equal(backupFolders.length, 1);
  assert.equal(count(join(temporaryRoot, '.reset-backups', backupFolders[0], 'daehan.sqlite'), 'posts'), baselinePosts + 1);

  const cleanPid = supervisor.childPid;
  const retry = await reset();
  assert.equal(retry.status, 200);
  assert.equal((await retry.json()).status, 'clean');
  assert.notEqual(supervisor.childPid, cleanPid);
  assert.equal(count(dbPath, 'posts'), baselinePosts);
  assert.equal((await readdir(join(temporaryRoot, '.reset-backups'))).length, 2);
});

test('Docker Daehan reset advertises its service origin while restarting the child and restoring data', async t => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'ca3p-daehan-reset-test-'));
  const dbPath = join(temporaryRoot, 'data', 'daehan.sqlite');
  const backupRoot = join(temporaryRoot, 'mounted-backups');
  const targetPort = await availablePort();
  const token = 'isolated-docker-reset-token-0123456789';
  const env = {
    ...process.env, NODE_ENV: 'test', LAB_MEMORY_DB: '0',
    CA3P_TEST_DAEHAN_DB_PATH: dbPath,
    CA3P_TEST_DAEHAN_PORT: String(targetPort),
    CA3P_DAEHAN_RESET_PORT: '0',
    CA3P_DAEHAN_RESET_TOKEN: token,
    CA3P_DAEHAN_RESET_BIND: '0.0.0.0',
    CA3P_DAEHAN_TARGET_BIND: '0.0.0.0',
    CA3P_DAEHAN_TARGET_ORIGIN: `http://daehan:${targetPort}`,
    CA3P_DAEHAN_RESET_BACKUP_ROOT: backupRoot,
  };
  let supervisor;
  t.after(async () => {
    if (supervisor) await supervisor.close();
    assert.equal(basename(temporaryRoot).startsWith('ca3p-daehan-reset-test-'), true);
    await rm(temporaryRoot, { recursive: true, force: true });
  });
  supervisor = await startDaehanResetSupervisor({ env });
  assert.equal(supervisor.targetOrigin, `http://daehan:${targetPort}`);
  assert.equal((await (await fetch(`${supervisor.origin}/health`)).json()).targetOrigin, supervisor.targetOrigin);
  const localTarget = `http://127.0.0.1:${targetPort}`;
  assert.equal((await fetch(localTarget)).status, 200);
  const baselinePosts = count(dbPath, 'posts');
  const firstPid = supervisor.childPid;

  const login = await fetch(`${localTarget}/login`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'admin', password: 'admin1234', next: '/admin' }),
  });
  assert.equal(login.status, 302);
  const cookie = login.headers.get('set-cookie')?.split(';', 1)[0];
  const created = await fetch(`${localTarget}/admin/posts`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: new URLSearchParams({ type: 'notice', title: 'docker reset mutation', body: 'temporary' }),
  });
  assert.equal(created.status, 302);
  assert.equal(count(dbPath, 'posts'), baselinePosts + 1);

  const body = { confirmation: 'reset-experiment-target', fixtureId: 'vul-web2-daehan', targetOrigin: supervisor.targetOrigin };
  const request = candidate => fetch(`${supervisor.origin}/_ca3p/experiment-reset`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify(candidate),
  });
  assert.equal((await request({ ...body, targetOrigin: localTarget })).status, 400);
  const clean = await request(body);
  assert.equal(clean.status, 200);
  assert.deepEqual(await clean.json(), {
    status: 'clean', fixtureId: body.fixtureId, targetOrigin: body.targetOrigin,
    scopes: ['database', 'sessions', 'process', 'files'],
  });
  assert.notEqual(supervisor.childPid, firstPid);
  assert.equal(count(dbPath, 'posts'), baselinePosts);
  assert.equal((await (await fetch(`${localTarget}/_diag/config`)).json()).activeSessions, 0);
  assert.equal((await fetch(`${localTarget}/admin`, { headers: { cookie } })).status, 403);
  assert.deepEqual(await readdir(join(temporaryRoot, 'data')), ['daehan.sqlite']);
  const backups = await readdir(backupRoot);
  assert.equal(backups.length, 1);
  assert.equal(count(join(backupRoot, backups[0], 'daehan.sqlite'), 'posts'), baselinePosts + 1);
});

test('Docker-wide binds require the fixed Daehan service origin and a separate absolute backup root', async () => {
  const dbPath = join(tmpdir(), 'ca3p-daehan-reset-configuration', 'data', 'daehan.sqlite');
  const baseline = {
    NODE_ENV: 'test', LAB_MEMORY_DB: '0',
    CA3P_TEST_DAEHAN_DB_PATH: dbPath,
    CA3P_TEST_DAEHAN_PORT: '52123', CA3P_DAEHAN_RESET_PORT: '0',
    CA3P_DAEHAN_RESET_TOKEN: 'isolated-docker-reset-token-0123456789',
    CA3P_DAEHAN_RESET_BIND: '0.0.0.0', CA3P_DAEHAN_TARGET_BIND: '0.0.0.0',
  };
  await assert.rejects(startDaehanResetSupervisor({ env: {
    ...baseline, CA3P_DAEHAN_TARGET_ORIGIN: 'http://other:52123',
  } }), /target origin must match/u);
  await assert.rejects(startDaehanResetSupervisor({ env: {
    ...baseline, CA3P_DAEHAN_TARGET_ORIGIN: 'http://daehan:4101',
  } }), /target origin must match/u);
  await assert.rejects(startDaehanResetSupervisor({ env: {
    ...baseline, CA3P_DAEHAN_TARGET_ORIGIN: 'http://daehan:52123',
    CA3P_DAEHAN_RESET_BACKUP_ROOT: join(tmpdir(), 'ca3p-daehan-reset-configuration', 'data', 'backups'),
  } }), /backup root must be an absolute path outside/u);
  await assert.rejects(startDaehanResetSupervisor({ env: {
    ...baseline, CA3P_DAEHAN_TARGET_ORIGIN: 'http://127.0.0.1:52123',
    CA3P_DAEHAN_RESET_BACKUP_ROOT: join(tmpdir(), 'ca3p-daehan-reset-configuration', 'data', 'backups'),
  } }), /backup root must be an absolute path outside/u);
});

test('supervisor rejects missing authentication before creating a child', async () => {
  await assert.rejects(startDaehanResetSupervisor({ env: {
    NODE_ENV: 'test', CA3P_TEST_DAEHAN_DB_PATH: join(tmpdir(), 'daehan.sqlite'),
    CA3P_TEST_DAEHAN_PORT: '52123', CA3P_DAEHAN_RESET_PORT: '0',
  } }), /CA3P_DAEHAN_RESET_TOKEN/u);
});

test('an occupied target port fails before opening the fixture database', async t => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'ca3p-daehan-reset-test-'));
  const blocker = createServer();
  await new Promise((resolve, reject) => {
    blocker.once('error', reject);
    blocker.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    await new Promise(resolve => blocker.close(resolve));
    assert.equal(basename(temporaryRoot).startsWith('ca3p-daehan-reset-test-'), true);
    await rm(temporaryRoot, { recursive: true, force: true });
  });
  const dbPath = join(temporaryRoot, 'data', 'daehan.sqlite');
  await assert.rejects(startDaehanResetSupervisor({ env: {
    ...process.env, NODE_ENV: 'test', CA3P_TEST_DAEHAN_DB_PATH: dbPath,
    CA3P_TEST_DAEHAN_PORT: String(blocker.address().port), CA3P_DAEHAN_RESET_PORT: '0',
    CA3P_DAEHAN_RESET_TOKEN: 'isolated-test-reset-token-0123456789',
  } }), /target port is already occupied/u);
  await assert.rejects(lstat(dbPath), { code: 'ENOENT' });
});

test('CLI publishes readiness without its token and stops its managed child', async t => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'ca3p-daehan-reset-test-'));
  const token = 'isolated-cli-reset-token-0123456789';
  const targetPort = await availablePort();
  const child = spawn(process.execPath, [supervisorScript], {
    env: { ...process.env, NODE_ENV: 'test',
      CA3P_TEST_DAEHAN_DB_PATH: join(temporaryRoot, 'data', 'daehan.sqlite'),
      CA3P_TEST_DAEHAN_PORT: String(targetPort), CA3P_DAEHAN_RESET_PORT: '0',
      CA3P_DAEHAN_RESET_TOKEN: token, LAB_MEMORY_DB: '0' },
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'], windowsHide: true,
  });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    assert.equal(basename(temporaryRoot).startsWith('ca3p-daehan-reset-test-'), true);
    await rm(temporaryRoot, { recursive: true, force: true });
  });
  const ready = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('CLI readiness timed out')), 10_000);
    child.on('message', message => {
      if (message?.type === 'ca3p-daehan-supervisor-ready') {
        clearTimeout(timer); resolve(message);
      }
    });
    child.once('exit', () => { clearTimeout(timer); reject(new Error('CLI exited before readiness')); });
  });
  assert.equal(ready.targetOrigin, `http://127.0.0.1:${targetPort}`);
  assert.equal((await fetch(`${ready.origin}/health`)).status, 200);
  child.send({ type: 'ca3p-daehan-supervisor-stop' });
  const exitCode = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('CLI stop timed out')), 10_000);
    child.once('exit', code => { clearTimeout(timer); resolve(code); });
  });
  assert.equal(exitCode, 0);
  assert.match(output, /Daehan reset supervisor ready on/u);
  assert.equal(output.includes(token), false);
  await assert.rejects(fetch(`${ready.targetOrigin}/health`));
});
