'use strict';

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { spawn } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');

const activeLabCapabilities = new WeakMap();
const LISTENING_PATTERN = /게시판 실행 중: http:\/\/127\.0\.0\.1:(\d+)/;

function hasStopped(child) {
  return child.exitCode !== null || child.signalCode !== null;
}

async function waitForExit(child, timeoutMs) {
  if (hasStopped(child)) return true;
  let removeListener = () => {};
  const exited = new Promise(resolve => {
    const onExit = () => {
      removeListener();
      resolve(true);
    };
    removeListener = () => child.removeListener('exit', onExit);
    child.once('exit', onExit);
    if (hasStopped(child)) onExit();
  });
  const didExit = await Promise.race([
    exited,
    delay(timeoutMs).then(() => false),
  ]);
  removeListener();
  return didExit || hasStopped(child);
}

async function stopChild(child) {
  if (hasStopped(child) || child.pid === undefined) return;
  child.kill();
  if (!await waitForExit(child, 3000)) {
    child.kill('SIGKILL');
    await waitForExit(child, 3000);
  }
  if (!hasStopped(child)) {
    throw new Error(`Failed to stop isolated lab process ${child.pid}`);
  }
}

function inheritedEnvironmentValue(name) {
  const match = Object.entries(process.env)
    .find(([key, value]) => key.toLowerCase() === name.toLowerCase() && value !== undefined);
  return match?.[1];
}

function minimalChildEnvironment({ dataFile, cookieSecret }) {
  const env = {
    HOST: '127.0.0.1',
    PORT: '0',
    BOARD_DATA_FILE: dataFile,
    BOARD_COOKIE_SECRET: cookieSecret,
    NODE_ENV: 'test',
  };
  for (const key of ['SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR']) {
    const value = inheritedEnvironmentValue(key);
    if (value !== undefined) env[key] = value;
  }
  return env;
}

function consumeIsolatedLabCapability(capability) {
  if ((typeof capability !== 'object' && typeof capability !== 'function') || capability === null) {
    throw new Error('A live isolated-lab capability from startIsolatedLab is required');
  }
  const target = activeLabCapabilities.get(capability);
  if (!target) throw new Error('A live isolated-lab capability from startIsolatedLab is required');
  activeLabCapabilities.delete(capability);
  if (hasStopped(target.child)) throw new Error('The isolated-lab capability is no longer active');
  return Object.freeze({ baseUrl: target.baseUrl });
}

async function startIsolatedLab({
  appDir = path.resolve(__dirname, '..', '..', 'vul-web-1'),
} = {}) {
  const serverFile = path.join(appDir, 'server.js');
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ca3p-agent-lab-'));
  const dataFile = path.join(tempDir, 'posts.json');
  let stdoutOutput = '';
  let stderrOutput = '';
  let startupError = null;
  let baseUrl = null;
  let capability = null;
  let stopped = false;
  let stopping = null;

  const child = spawn(process.execPath, [serverFile], {
    cwd: appDir,
    env: minimalChildEnvironment({ dataFile, cookieSecret: randomUUID() }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.once('error', error => { startupError = error; });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', chunk => {
    stdoutOutput = `${stdoutOutput}${chunk}`.slice(-8000);
    const match = stdoutOutput.match(LISTENING_PATTERN);
    const port = Number(match?.[1]);
    if (Number.isInteger(port) && port >= 1 && port <= 65535) {
      baseUrl = `http://127.0.0.1:${port}`;
    }
  });
  child.stderr.on('data', chunk => { stderrOutput = `${stderrOutput}${chunk}`.slice(-8000); });

  async function stop() {
    if (stopped) return;
    if (capability) activeLabCapabilities.delete(capability);
    if (stopping) return stopping;
    stopping = (async () => {
      await stopChild(child);
      await fs.rm(tempDir, { recursive: true, force: true });
      stopped = true;
    })();
    try {
      await stopping;
    } finally {
      if (!stopped) stopping = null;
    }
  }

  try {
    const deadline = Date.now() + 10_000;
    let ready = false;
    while (Date.now() < deadline) {
      if (startupError) throw startupError;
      if (hasStopped(child)) {
        throw new Error(`Lab server exited early (${child.exitCode}): ${stdoutOutput}${stderrOutput}`);
      }
      if (baseUrl) {
        try {
          const [response, persisted] = await Promise.all([
            fetch(`${baseUrl}/api/session`, { signal: AbortSignal.timeout(1000) }),
            fs.readFile(dataFile, 'utf8').then(text => JSON.parse(text)),
          ]);
          const session = await response.json();
          if (
            response.ok
            && session?.user?.id === 'alice'
            && Array.isArray(persisted.posts)
            && !hasStopped(child)
          ) {
            ready = true;
            break;
          }
        } catch {
          // The child may have announced its port before all startup I/O is observable.
        }
      }
      await delay(50);
    }
    if (!ready || !baseUrl) {
      throw new Error(`Lab server did not become ready: ${stdoutOutput}${stderrOutput}`);
    }

    capability = Object.freeze({});
    activeLabCapabilities.set(capability, { baseUrl, child });
    return { baseUrl, capability, dataFile, tempDir, child, stop };
  } catch (error) {
    try {
      await stop();
    } catch (cleanupError) {
      error.cause = cleanupError;
    }
    throw error;
  }
}

async function withIsolatedLab(task, options) {
  if (typeof task !== 'function') throw new TypeError('withIsolatedLab requires a task function');
  const target = await startIsolatedLab(options);
  let result;
  let taskError;
  try {
    result = await task(target);
  } catch (error) {
    taskError = error;
  }

  try {
    await target.stop();
  } catch (cleanupError) {
    if (taskError) {
      throw new AggregateError([taskError, cleanupError], 'The isolated-lab task and cleanup both failed');
    }
    throw cleanupError;
  }
  if (taskError) throw taskError;
  return result;
}

module.exports = { consumeIsolatedLabCapability, startIsolatedLab, withIsolatedLab };
