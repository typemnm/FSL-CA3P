#!/usr/bin/env node

// Owner of the Daehan fixture process and its experiment reset. Docker mode
// advertises the Compose service origin while probing the child over loopback.
import http from 'node:http';
import { spawn } from 'node:child_process';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { copyFile, lstat, mkdir, readdir, rm } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { basename, dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { daehanDatabasePath } from '../src/db.mjs';
import { siteConfigs } from '../src/sites.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const serverPath = join(root, 'src', 'server.mjs');
const fixtureId = 'vul-web2-daehan';
const scopes = Object.freeze(['database', 'sessions', 'process', 'files']);
const resetPath = '/_ca3p/experiment-reset';
const runtimeNames = Object.freeze(['daehan.sqlite', 'daehan.sqlite-wal', 'daehan.sqlite-shm', 'daehan.sqlite-journal']);

function port(value, name, allowZero = false) {
  if (!/^\d+$/u.test(String(value)) || !Number.isSafeInteger(Number(value))
    || Number(value) < (allowZero ? 0 : 1) || Number(value) > 65535) {
    throw new Error(`${name} must be a valid port.`);
  }
  return Number(value);
}

function configFrom(env) {
  if (env.LAB_MEMORY_DB === '1') throw new Error('A persistent Daehan database is required for managed reset.');
  const token = env.CA3P_DAEHAN_RESET_TOKEN;
  if (typeof token !== 'string' || !/^[A-Za-z0-9._~+/-]{32,512}$/u.test(token)) {
    throw new Error('CA3P_DAEHAN_RESET_TOKEN must be a 32–512 character management token.');
  }
  const managementPort = port(env.CA3P_DAEHAN_RESET_PORT ?? '54101', 'CA3P_DAEHAN_RESET_PORT', env.NODE_ENV === 'test');
  const targetPort = env.NODE_ENV === 'test' && env.CA3P_TEST_DAEHAN_PORT !== undefined
    ? port(env.CA3P_TEST_DAEHAN_PORT, 'CA3P_TEST_DAEHAN_PORT') : 4101;
  if (managementPort === targetPort) throw new Error('Management and target ports must differ.');
  const databasePath = daehanDatabasePath(env);
  if (basename(databasePath) !== 'daehan.sqlite') throw new Error('Unexpected Daehan database path.');
  const managementBind = env.CA3P_DAEHAN_RESET_BIND ?? '127.0.0.1';
  const targetBind = env.CA3P_DAEHAN_TARGET_BIND ?? '127.0.0.1';
  if (!['127.0.0.1', '0.0.0.0'].includes(managementBind)
    || targetBind !== managementBind) throw new Error('Daehan management and target binds must both be loopback or both be Docker-wide.');
  const dockerMode = managementBind === '0.0.0.0';
  const targetOrigin = env.CA3P_DAEHAN_TARGET_ORIGIN
    ?? `http://127.0.0.1:${targetPort}`;
  if (targetOrigin !== (dockerMode ? `http://daehan:${targetPort}` : `http://127.0.0.1:${targetPort}`)) {
    throw new Error('Daehan target origin must match the selected bind mode.');
  }
  const configuredBackupRoot = env.CA3P_DAEHAN_RESET_BACKUP_ROOT
    ?? join(dirname(dirname(databasePath)), '.reset-backups');
  if (typeof configuredBackupRoot !== 'string' || !isAbsolute(configuredBackupRoot)) {
    throw new Error('Daehan reset backup root must be an absolute path outside the data directory.');
  }
  const backupRoot = resolve(configuredBackupRoot);
  const dataDirectory = resolve(dirname(databasePath));
  if (backupRoot === dataDirectory || backupRoot.startsWith(`${dataDirectory}${sep}`)) {
    throw new Error('Daehan reset backup root must be an absolute path outside the data directory.');
  }
  return {
    token, managementPort, targetPort, databasePath,
    managementBind, targetBind, targetOrigin,
    targetHealthOrigin: `http://127.0.0.1:${targetPort}`,
    backupRoot,
  };
}

function authorized(header, token) {
  const candidate = typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : '';
  const candidateHash = createHash('sha256').update(candidate).digest();
  const expectedHash = createHash('sha256').update(token).digest();
  return /^[A-Za-z0-9._~+/-]{32,512}$/u.test(candidate) && timingSafeEqual(candidateHash, expectedHash);
}

function respond(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

async function requestBody(req) {
  if (!/^application\/json(?:\s*;|$)/iu.test(req.headers['content-type'] ?? '')) throw new Error('JSON required.');
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1024) throw new Error('Request too large.');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new Error('Invalid JSON.'); }
}

async function existingRuntimeFiles(databasePath) {
  const directory = dirname(databasePath);
  const details = await lstat(directory);
  if (!details.isDirectory() || details.isSymbolicLink()) throw new Error('Daehan data directory is not a regular directory.');
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (!runtimeNames.includes(entry.name) || !entry.isFile() || entry.isSymbolicLink()) {
      throw new Error('Unexpected Daehan runtime file.');
    }
  }
  if (!entries.some(entry => entry.name === 'daehan.sqlite')) throw new Error('Daehan database is missing.');
  return entries.map(entry => join(directory, entry.name));
}

async function backupRuntimeFiles(databasePath, backupRoot) {
  const files = await existingRuntimeFiles(databasePath);
  await mkdir(backupRoot, { recursive: true, mode: 0o700 });
  const backupDetails = await lstat(backupRoot);
  if (!backupDetails.isDirectory() || backupDetails.isSymbolicLink()) {
    throw new Error('Daehan backup directory is not a regular directory.');
  }
  const directory = join(backupRoot, `${new Date().toISOString().replace(/[:.]/gu, '-')}-${randomUUID()}`);
  await mkdir(directory, { mode: 0o700 });
  for (const file of files) await copyFile(file, join(directory, basename(file)), constants.COPYFILE_EXCL);
  return { directory, names: files.map(file => basename(file)) };
}

async function removeRuntimeFiles(databasePath) {
  const directory = dirname(databasePath);
  for (const name of runtimeNames) {
    const path = join(directory, name);
    let details;
    try { details = await lstat(path); }
    catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    if (!details.isFile() || details.isSymbolicLink()) throw new Error('Unsafe Daehan runtime file.');
    await rm(path);
  }
}

async function restoreRuntimeFiles(databasePath, backup) {
  await removeRuntimeFiles(databasePath);
  for (const name of backup.names) await copyFile(join(backup.directory, name), join(dirname(databasePath), name), constants.COPYFILE_EXCL);
}

function verifyBaseline(databasePath) {
  const db = new DatabaseSync(databasePath, { readOnly: true });
  try {
    if (db.prepare('PRAGMA integrity_check').get().integrity_check !== 'ok') throw new Error('SQLite integrity check failed.');
    const count = table => db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;
    const expected = {
      users: 5,
      posts: siteConfigs.daehan.noticeTitles.length + siteConfigs.daehan.newsTitles.length,
      events: siteConfigs.daehan.events.length,
      requests: 2,
      partner_applications: 4,
      staff_cases: 0,
      settings: 2,
    };
    for (const [table, total] of Object.entries(expected)) {
      if (count(table) !== total) throw new Error(`Daehan baseline ${table} count differs.`);
    }
  } finally { db.close(); }
}

async function exitWithin(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) return true;
  return new Promise(resolve => {
    const timer = setTimeout(() => { child.off('exit', onExit); resolve(false); }, timeoutMs);
    const onExit = () => { clearTimeout(timer); resolve(true); };
    child.once('exit', onExit);
  });
}

export async function startDaehanResetSupervisor({ env = process.env } = {}) {
  const config = configFrom(env);
  let child = null;
  let generation = 0;
  let busy = false;
  let closing = false;
  let resetPromise = null;
  let managementServer = null;

  async function checkTargetHealth() {
    const response = await fetch(`${config.targetHealthOrigin}/_diag/config`, {
      redirect: 'error', signal: AbortSignal.timeout(3000),
    });
    if (response.status !== 200 || response.redirected) throw new Error('Daehan target is unhealthy.');
    const result = await response.json();
    if (result.site !== 'daehan' || result.database !== config.databasePath
      || !Number.isSafeInteger(result.activeSessions)) throw new Error('Unexpected Daehan target.');
    return result;
  }

  async function checkTargetPortFree() {
    const probe = http.createServer();
    try {
      await new Promise((resolve, reject) => {
        probe.once('error', reject);
        probe.listen(config.targetPort, config.targetBind, resolve);
      });
    } catch {
      throw new Error('Daehan target port is already occupied.');
    } finally {
      if (probe.listening) await new Promise(resolve => probe.close(resolve));
    }
  }

  async function launchChild() {
    const childEnv = { ...env, NODE_ENV: env.NODE_ENV ?? 'production', HOST: config.targetBind, PORT: String(config.targetPort) };
    delete childEnv.CA3P_DAEHAN_RESET_TOKEN;
    delete childEnv.CA3P_EXPERIMENT_RESET_TARGETS;
    const next = spawn(process.execPath, [serverPath, 'daehan'], {
      cwd: root, env: childEnv, windowsHide: true, stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
    });
    child = next;
    try {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => finish(new Error('Daehan child startup timed out.')), 10_000);
        const onMessage = message => {
          if (message?.type === 'ca3p-daehan-ready' && message.host === config.targetBind && message.port === config.targetPort) finish();
        };
        const onExit = () => finish(new Error('Daehan child exited during startup.'));
        const onError = () => finish(new Error('Daehan child failed to start.'));
        function finish(error) {
          clearTimeout(timer);
          next.off('message', onMessage); next.off('exit', onExit); next.off('error', onError);
          if (error) reject(error); else resolve();
        }
        next.on('message', onMessage); next.once('exit', onExit); next.once('error', onError);
      });
      await checkTargetHealth();
      generation += 1;
    } catch (error) {
      await stopChild().catch(() => {});
      throw error;
    }
  }

  async function stopChild() {
    const running = child;
    child = null;
    if (!running || running.exitCode !== null || running.signalCode !== null) return;
    try { if (running.connected) running.send({ type: 'ca3p-daehan-stop' }); }
    catch { /* The termination fallback below still waits for exit. */ }
    if (await exitWithin(running, 5000)) return;
    running.kill('SIGTERM');
    if (await exitWithin(running, 3000)) return;
    running.kill('SIGKILL');
    if (!await exitWithin(running, 3000)) throw new Error('Daehan child did not stop.');
  }

  async function resetTarget() {
    await stopChild();
    let backup;
    try { backup = await backupRuntimeFiles(config.databasePath, config.backupRoot); }
    catch (error) {
      await launchChild().catch(() => {});
      throw error;
    }
    try {
      await removeRuntimeFiles(config.databasePath);
      await launchChild();
      const health = await checkTargetHealth();
      if (health.activeSessions !== 0) throw new Error('Daehan sessions remain active.');
      await existingRuntimeFiles(config.databasePath);
      verifyBaseline(config.databasePath);
      return { status: 'clean', fixtureId, targetOrigin: config.targetOrigin, scopes: [...scopes] };
    } catch (error) {
      await stopChild().catch(() => {});
      try {
        await restoreRuntimeFiles(config.databasePath, backup);
        await launchChild();
      } catch { /* The backup remains available for operator recovery. */ }
      throw error;
    }
  }

  async function handle(req, res) {
    if (req.method === 'GET' && req.url === '/health') {
      try {
        if (!child || child.exitCode !== null || child.signalCode !== null || busy || closing) throw new Error();
        await checkTargetHealth();
        if (busy || closing) throw new Error();
        respond(res, 200, { status: 'ready', fixtureId, targetOrigin: config.targetOrigin, generation });
      } catch { respond(res, 503, { status: 'unavailable' }); }
      return;
    }
    if (req.method !== 'POST' || req.url !== resetPath) { respond(res, 404, { error: 'not found' }); return; }
    if (!authorized(req.headers.authorization, config.token)) { respond(res, 401, { error: 'unauthorized' }); return; }
    let body;
    try { body = await requestBody(req); }
    catch { respond(res, 400, { error: 'invalid request' }); return; }
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).sort().join(',') !== 'confirmation,fixtureId,targetOrigin'
      || body.confirmation !== 'reset-experiment-target' || body.fixtureId !== fixtureId
      || body.targetOrigin !== config.targetOrigin) {
      respond(res, 400, { error: 'invalid target confirmation' }); return;
    }
    if (busy || closing) { respond(res, 409, { error: 'reset already in progress' }); return; }
    busy = true;
    resetPromise = resetTarget();
    try { respond(res, 200, await resetPromise); }
    catch { respond(res, 503, { error: 'Daehan reset could not be verified' }); }
    finally { busy = false; resetPromise = null; }
  }

  try {
    managementServer = http.createServer((req, res) => { void handle(req, res).catch(() => {
      if (!res.headersSent) respond(res, 503, { error: 'management request failed' });
      else res.end();
    }); });
    await new Promise((resolve, reject) => {
      managementServer.once('error', reject);
      managementServer.listen(config.managementPort, config.managementBind, () => {
        managementServer.off('error', reject); resolve();
      });
    });
    await checkTargetPortFree();
    await launchChild();
  } catch (error) {
    if (managementServer?.listening) managementServer.close();
    await stopChild().catch(() => {});
    throw error;
  }

  const address = managementServer.address();
  const origin = `http://127.0.0.1:${address.port}`;
  return {
    origin, targetOrigin: config.targetOrigin,
    get generation() { return generation; },
    get childPid() { return child?.pid ?? null; },
    async close() {
      closing = true;
      if (managementServer.listening) {
        const closed = new Promise(resolve => managementServer.close(resolve));
        managementServer.closeAllConnections();
        await closed;
      }
      if (resetPromise) await resetPromise.catch(() => {});
      await stopChild();
    },
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const supervisor = await startDaehanResetSupervisor();
    console.log(`Daehan reset supervisor ready on ${supervisor.origin}`);
    if (process.send) process.send({ type: 'ca3p-daehan-supervisor-ready', origin: supervisor.origin, targetOrigin: supervisor.targetOrigin });
    let stopping = false;
    const shutdown = async () => {
      if (stopping) return;
      stopping = true;
      try { await supervisor.close(); }
      catch { process.exitCode = 1; }
      if (process.connected) process.disconnect();
    };
    process.once('SIGINT', () => { void shutdown(); });
    process.once('SIGTERM', () => { void shutdown(); });
    process.once('disconnect', () => { void shutdown(); });
    if (process.send) process.on('message', message => {
      if (message?.type === 'ca3p-daehan-supervisor-stop') void shutdown();
    });
  } catch (error) {
    console.error(`Daehan reset supervisor failed: ${error.message}`);
    process.exitCode = 1;
  }
}
