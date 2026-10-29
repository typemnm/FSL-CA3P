import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { registerLabSession } from './lab-session-registry.mjs';

const TEMP_PREFIX = 'ca3p-local-lab-';
const START_TIMEOUT_MS = 10_000;
const STOP_TIMEOUT_MS = 3_000;
const BOARD_SERVER = fileURLToPath(new URL('../../vul-web-1/server.js', import.meta.url));

function isDirectTempChild(root, target) {
  const child = relative(root, target);
  return child.length > TEMP_PREFIX.length
    && child.startsWith(TEMP_PREFIX)
    && !child.startsWith('..')
    && !isAbsolute(child)
    && !child.includes(sep)
    && basename(target).startsWith(TEMP_PREFIX);
}

async function removePrivateBoardData(directory) {
  let actual;
  try {
    actual = await realpath(directory);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  const lexicalRoot = resolve(tmpdir());
  const lexicalTarget = resolve(directory);
  const actualRoot = await realpath(tmpdir());
  if (!isDirectTempChild(lexicalRoot, lexicalTarget)
    || !isDirectTempChild(actualRoot, actual)
    || basename(lexicalTarget).toLowerCase() !== basename(actual).toLowerCase()) {
    throw new Error('Refusing to remove a directory outside the private local lab temp area.');
  }
  await rm(actual, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

function closedProcess(child) {
  return new Promise(resolveClosed => child.once('close', (code, signal) => resolveClosed({ code, signal })));
}

function waitAtMost(promise, milliseconds) {
  return new Promise(resolveWait => {
    const timer = setTimeout(() => resolveWait(false), milliseconds);
    promise.then(() => { clearTimeout(timer); resolveWait(true); }, () => { clearTimeout(timer); resolveWait(true); });
  });
}

async function stopProcess(child, closed) {
  if (child.exitCode === null && child.signalCode === null) {
    try { child.kill('SIGTERM'); } catch { /* The process may already have exited. */ }
  }
  if (await waitAtMost(closed, STOP_TIMEOUT_MS)) return;
  try { child.kill('SIGKILL'); } catch { /* The process may already have exited. */ }
  if (!await waitAtMost(closed, STOP_TIMEOUT_MS)) {
    throw new Error('The local lab server did not exit after termination.');
  }
}

function awaitBoardOrigin(child) {
  return new Promise((resolveOrigin, rejectOrigin) => {
    let output = '';
    let settled = false;
    const finish = (error, origin) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.stdout.off('data', onOutput);
      child.off('error', onError);
      child.off('exit', onExit);
      child.stdout.resume();
      if (error) rejectOrigin(error);
      else resolveOrigin(origin);
    };
    const onOutput = chunk => {
      output = `${output}${chunk}`.slice(-2048);
      const match = /게시판 실행 중: http:\/\/127\.0\.0\.1:(\d+)/u.exec(output);
      if (!match) return;
      const port = Number(match[1]);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        finish(new Error('The local lab server reported an invalid port.'));
      } else {
        finish(null, `http://127.0.0.1:${port}`);
      }
    };
    const onError = error => finish(error);
    const onExit = (code, signal) => finish(new Error(`The local lab server exited before startup (${code ?? signal}).`));
    const timer = setTimeout(() => finish(new Error('The local lab server did not start within 10 seconds.')), START_TIMEOUT_MS);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', onOutput);
    child.once('error', onError);
    child.once('exit', onExit);
    child.stderr.resume();
  });
}

// A `profile` argument is ignored: apps/application/general-runtime.mjs still passes the retired 'stored_xss_canary'.
export async function startLocalLab({ safeMode = false, cleanupRegistryPath } = {}) {
  const directory = await mkdtemp(join(tmpdir(), TEMP_PREFIX));
  // The board process needs no model credentials or provider settings.
  const boardEnvironmentKeys = new Set(['PATH', 'HOME', 'USERPROFILE', 'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LC_ALL', 'TZ', 'SYSTEMROOT', 'WINDIR']);
  const boardEnv = Object.fromEntries(Object.entries(process.env).filter(([name]) => boardEnvironmentKeys.has(name.toUpperCase())));
  let child;
  let closed;
  let closeTask;
  let registration;
  try {
    child = spawn(process.execPath, [BOARD_SERVER], {
      env: {
        ...boardEnv,
        HOST: '127.0.0.1',
        PORT: '0',
        BOARD_DATA_FILE: join(directory, 'posts.json'),
        BOARD_COOKIE_SECRET: randomBytes(32).toString('hex'),
        BOARD_SAFE_MODE: safeMode ? '1' : '0',
      },
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      windowsHide: true,
    });
    // Keep an error listener after startup so a later child-process error cannot
    // become an unhandled EventEmitter error.
    child.on('error', () => {});
    closed = closedProcess(child);
    const origin = await awaitBoardOrigin(child);
    if (cleanupRegistryPath) registration = await registerLabSession({ registryPath: cleanupRegistryPath,
      directory, pid: child.pid });
    const close = () => {
      if (!closeTask) {
        closeTask = (async () => {
          try { await stopProcess(child, closed); }
          finally { await removePrivateBoardData(directory); await registration?.unregister(); }
        })();
      }
      return closeTask;
    };
    const closeAfterUnexpectedExit = () => { void close().catch(() => {}); };
    child.once('exit', closeAfterUnexpectedExit);
    child.once('error', closeAfterUnexpectedExit);
    if (child.exitCode !== null || child.signalCode !== null) closeAfterUnexpectedExit();
    return { origin, close };
  } catch (error) {
    try {
      if (child) await stopProcess(child, closed);
    } finally {
      await removePrivateBoardData(directory);
      await registration?.unregister();
    }
    throw error;
  }
}
