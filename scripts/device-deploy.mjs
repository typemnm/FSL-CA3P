import { spawn } from 'node:child_process';
import { randomBytes, scryptSync, createHash } from 'node:crypto';
import { access, chmod, copyFile, lstat, mkdir, readFile, readdir, readlink, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, delimiter } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isIP } from 'node:net';
import { request as httpRequest } from 'node:http';
import { selectVerifiedRelease, verifyWorkflowRun } from './device-deploy-verification.mjs';
import { prepareFixtures, stopFixtures, backupFixtures, activateFixtures, restoreFixtures, rollbackFixtures } from './device-fixtures.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const stamp = () => new Date().toISOString();
const hash = value => createHash('sha256').update(value).digest('hex');
const delay = ms => new Promise(done => setTimeout(done, ms));
const exists = async path => { try { await access(path); return true; } catch { return false; } };
const readJson = async (path, fallback = null) => { try { return JSON.parse(await readFile(path, 'utf8')); } catch { return fallback; } };

export async function atomicJson(path, value) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  await rename(temporary, path);
}

export function validateConfiguration(value) {
  const required = ['repoDir', 'deployRoot', 'runtimeDir', 'caseDbPath', 'legacyReportsDir', 'nodePath',
    'pythonPath', 'npmCli', 'servicePlistPath', 'credentialFile'];
  if (!value || value.repository !== 'typemnm/FSL-CA3P'
    || required.some(key => typeof value[key] !== 'string' || !value[key].startsWith('/'))
    || !/^kr\.or\.casper\.ca3p\.[a-z0-9-]+$/.test(value.serviceLabel ?? '')
    || !Number.isInteger(value.port) || !Number.isInteger(value.probePort)
    || value.port < 1024 || value.port > 65535 || value.probePort < 1024 || value.probePort > 65535
    || value.port === value.probePort || typeof value.host !== 'string') throw new Error('Invalid device deployment configuration.');
  const address = new URL(`http://${value.host}:${value.port}`);
  const octets = value.host.split('.').map(Number);
  if (isIP(value.host) !== 4 || address.hostname !== value.host || address.username || address.password
    || address.pathname !== '/' || address.search || address.hash
    || !(octets[0] === 127 || octets[0] === 10 || (octets[0] === 192 && octets[1] === 168)
      || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31))) {
    throw new Error('The local deployment probe must use a loopback/private IPv4 address.');
  }
  return value;
}

async function acquireLock(path) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  try { await mkdir(path, { mode: 0o700 }); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const owner = await readJson(join(path, 'owner.json'));
    // Do not race a new owner; recover an orphan left before owner.json was written.
    if (!owner?.pid) {
      if (Date.now() - (await stat(path)).mtimeMs < 60_000) return null;
    } else {
      try { process.kill(owner.pid, 0); return null; } catch (failure) { if (failure.code !== 'ESRCH') return null; }
    }
    await rm(path, { recursive: true });
    try { await mkdir(path, { mode: 0o700 }); } catch (failure) { if (failure.code === 'EEXIST') return null; throw failure; }
  }
  await atomicJson(join(path, 'owner.json'), { pid: process.pid, startedAt: stamp() });
  return () => rm(path, { recursive: true, force: true });
}

export function execute(command, args, { cwd, env = process.env, timeoutMs = 600_000, logFile, stdoutOnly = false } = {}) {
  return new Promise((done, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32' });
    const output = []; const stdout = []; let size = 0; let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
    }, timeoutMs);
    const accept = data => { if (size < 2_000_000) { output.push(data); size += data.length; } };
    child.stdout.on('data', data => { if (size < 2_000_000) stdout.push(data); accept(data); }); child.stderr.on('data', accept);
    child.on('error', reject);
    child.once('close', async code => {
      clearTimeout(timer);
      const text = Buffer.concat(output).toString('utf8');
      try {
        if (logFile) await writeFile(logFile, text, { mode: 0o600 });
        if (code !== 0 || timedOut) {
          const failure = new Error(`${command.split('/').at(-1)} ${timedOut ? 'timed out' : `failed (${code})`}${logFile ? '; see private deployment log' : ''}.`);
          failure.exitCode = code; throw failure;
        }
        done(stdoutOnly ? Buffer.concat(stdout).toString('utf8').trim() : text.trim());
      } catch (error) { reject(error); }
    });
  });
}

async function replaceLink(path, target) {
  const temporary = `${path}.${process.pid}.next`;
  await rm(temporary, { force: true });
  await symlink(target, temporary);
  await rename(temporary, path);
}

export async function deploymentTransaction({ stop, backup, migrate, activate, start, verify, restore, rollback, verifyRollback }) {
  let snapshot; let stopped = false;
  try {
    stopped = true; await stop();
    snapshot = await backup();
    await migrate(snapshot);
    await activate();
    await start();
    await verify();
    return { deployed: true };
  } catch (error) {
    if (stopped) {
      try {
        await stop();
        if (snapshot) await restore(snapshot);
        await rollback();
        await start();
        await verifyRollback();
      } catch (recovery) {
        const failed = new Error(`Deployment failed; automatic recovery also failed: ${recovery.message}`);
        failed.recoveryFailed = true; failed.cause = error; throw failed;
      }
    }
    throw error;
  }
}

function serviceEnvironment(config, release, overrides = {}) {
  return { ...process.env,
    PATH: [dirname(config.nodePath), dirname(config.pythonPath), '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin'].join(delimiter),
    CASPER_DB_PYTHON: join(release, '.venv/bin/python'), CA3P_REPORT_PYTHON: join(release, '.venv/bin/python'),
    CASPER_DB_PATH: config.caseDbPath, CA3P_STORE_PATH: join(config.runtimeDir, 'runs.sqlite'),
    CA3P_CHAT_DB_PATH: join(config.runtimeDir, 'chat.sqlite'),
    DASHBOARD_AUTH_FILE: join(config.runtimeDir, 'auth.json'),
    ...overrides };
}

export async function database(config, python, args, { targetSha, phase = args[0], env = process.env } = {}) {
  if (!/^[a-f0-9]{40}$/.test(targetSha ?? '') || !/^[a-z]+(?:-[a-z]+)*$/.test(phase ?? '')
    || !['inspect', 'backup', 'migrate', 'restore'].includes(args[0])) throw new Error('Invalid database diagnostic context.');
  const directory = join(config.deployRoot, 'logs', targetSha, 'database');
  await mkdir(directory, { recursive: true, mode: 0o700 }); await chmod(directory, 0o700);
  // A retry or crash recovery must retain the diagnostic from each prior attempt.
  const logFile = join(directory, `${phase}-${randomBytes(12).toString('hex')}.log`);
  const operationArgs = [...args];
  if (['inspect', 'backup', 'restore'].includes(args[0]) && !args.includes('--chat-db')) {
    // Old journals contain two-store snapshots; recover them using their original
    // identity. Every new snapshot also owns the separate conversation database.
    let includeChat = true;
    if (args[0] === 'restore') {
      const snapshotPath = args[args.indexOf('--backup') + 1];
      const manifest = JSON.parse(await readFile(join(snapshotPath, 'manifest.json'), 'utf8'));
      includeChat = Object.hasOwn(manifest.databases ?? {}, 'chat');
    }
    if (includeChat) operationArgs.push('--chat-db', join(config.runtimeDir, 'chat.sqlite'));
  }
  const output = await execute(python, [join(here, 'device-db.py'), ...operationArgs],
    { timeoutMs: 60_000, env, logFile, stdoutOnly: true });
  let result;
  try { result = JSON.parse(output); }
  catch { throw new Error('Device database response was invalid; see private deployment log.'); }
  if (!result?.ok) throw new Error('Device database operation failed; see private deployment log.');
  return result;
}

function serviceControl(config) {
  const domain = `gui/${process.getuid()}`;
  const service = `${domain}/${config.serviceLabel}`;
  const base = `http://${config.host}:${config.port}`;
  const knownPids = new Set();
  const alive = pid => { try { process.kill(pid, 0); return true; } catch (error) { return error.code !== 'ESRCH'; } };
  return {
    async stop() {
      let loaded = false;
      try {
        const info = await execute('/bin/launchctl', ['print', service], { timeoutMs: 10_000 });
        loaded = true;
        const pid = Number(/^\s*pid = (\d+)$/m.exec(info)?.[1]);
        if (pid) {
          knownPids.add(pid);
          const processes = await execute('/bin/ps', ['-axo', 'pid=,ppid='], { timeoutMs: 10_000 });
          for (const row of processes.split('\n')) {
            const [child, parent] = row.trim().split(/\s+/).map(Number);
            if (parent === pid) knownPids.add(child);
          }
        }
      } catch (error) { if (![3, 113].includes(error.exitCode)) throw error; }
      if (loaded) await execute('/bin/launchctl', ['bootout', service], { timeoutMs: 30_000 });
      const deadline = Date.now() + 30_000;
      while ([...knownPids].some(alive)) {
        if (Date.now() > deadline) throw new Error('Dashboard/worker did not stop; databases were not migrated.');
        await delay(200);
      }
      await waitHealth(base, false);
    },
    start: () => execute('/bin/launchctl', ['bootstrap', domain, config.servicePlistPath], { timeoutMs: 30_000 }),
  };
}

async function restoreAuthentication(config, snapshot) {
  const metadata = JSON.parse(await readFile(join(snapshot, 'auth-checksum.json'), 'utf8'));
  if (metadata.sha256 !== hash(await readFile(join(snapshot, 'auth.json')))) throw new Error('Authentication snapshot checksum mismatch.');
  const temporary = join(config.runtimeDir, `auth.json.${process.pid}.restore`);
  await copyFile(join(snapshot, 'auth.json'), temporary); await chmod(temporary, 0o600);
  await rename(temporary, join(config.runtimeDir, 'auth.json'));
}

async function recoverTransaction(config, journal, update) {
  if (journal === undefined) return;
  if (!journal || typeof journal !== 'object' || Array.isArray(journal)) throw Object.assign(new Error('Deployment journal is invalid.'), { recoveryFailed: true });
  if (!/^[a-f0-9]{40}$/.test(journal.previousSha ?? '') || typeof journal.previous !== 'string'
    || !journal.previous.startsWith('/') || (journal.backup && !journal.backup.startsWith(join(config.deployRoot, 'backups') + '/'))
    || await execute('/usr/bin/git', ['rev-parse', 'HEAD'], { cwd: journal.previous }) !== journal.previousSha) {
    throw Object.assign(new Error('Interrupted deployment journal is invalid; manual recovery is required.'), { recoveryFailed: true });
  }
  if (journal.committed) {
    await rm(join(config.deployRoot, 'transaction.json'), { force: true });
    await rm(join(config.deployRoot, 'maintenance.json'), { force: true }); return;
  }
  const control = serviceControl(config);
  try {
    await control.stop();
    await stopFixtures(journal.fixtures, { execute });
    if (journal.backup) {
      await database(config, config.pythonPath, ['restore', '--run-db', join(config.runtimeDir, 'runs.sqlite'), '--case-db', config.caseDbPath, '--backup', journal.backup],
        { targetSha: journal.targetSha, phase: 'recovery-restore' });
      await restoreAuthentication(config, journal.backup);
      await restoreFixtures(journal.backup, journal.fixtures, { execute });
    }
    await rollbackFixtures(journal.fixtures, { execute });
    await replaceLink(join(config.deployRoot, 'current'), journal.previous);
    await control.start();
    await checkApplication(`http://${config.host}:${config.port}`, await readCredentials(config), journal.previousSha);
    await update('failed', { deployedSha: journal.previousSha, failedSha: journal.targetSha, phase: null,
      message: 'An interrupted deployment was rolled back before accepting writes.' });
    await rm(join(config.deployRoot, 'transaction.json'), { force: true });
    await rm(join(config.deployRoot, 'maintenance.json'), { force: true });
  } catch (error) { error.recoveryFailed = true; throw error; }
}

async function idle(config) {
  const output = await execute(config.pythonPath, ['-c',
    "import sqlite3,sys,pathlib; p=pathlib.Path(sys.argv[1]); c=sqlite3.connect(p.resolve().as_uri()+'?mode=ro',uri=True) if p.exists() else None; print(c.execute(\"SELECT count(*) FROM jobs WHERE status IN ('queued','leased')\").fetchone()[0] if c else 0)",
    join(config.runtimeDir, 'runs.sqlite')], { timeoutMs: 10_000 });
  return output === '0';
}

export async function localRequest(base, path, { cookie, csrfToken, body, timeoutMs = 8000 } = {}) {
  const url = new URL(base + path);
  const bytes = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  // Node's fetch transport rewrites Host. The LAN-bound service still requires
  // its existing loopback Host policy, so set it explicitly with node:http.
  return new Promise((done, reject) => {
    const request = httpRequest(url, { method: bytes ? 'POST' : 'GET', signal: AbortSignal.timeout(timeoutMs),
      headers: { Host: `127.0.0.1:${url.port}`, ...(cookie ? { Cookie: cookie } : {}),
        ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}), ...(bytes ? { 'Content-Type': 'application/json', 'Content-Length': bytes.length } : {}) } }, response => {
      const chunks = []; let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > 2_000_000) response.destroy(new Error('Local deployment response is oversized.')); else chunks.push(chunk); });
      response.on('error', reject);
      response.on('end', () => {
        try {
          if (response.statusCode < 200 || response.statusCode >= 300) throw new Error(`Local deployment check ${path.split('?')[0]} returned ${response.statusCode}.`);
          done({ value: JSON.parse(Buffer.concat(chunks).toString('utf8')), cookie: response.headers['set-cookie']?.[0]?.split(';')[0] });
        } catch (error) { reject(error); }
      });
    });
    request.on('error', reject); request.end(bytes);
  });
}

async function waitHealth(base, ready = true, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let healthy = false;
    try { healthy = (await localRequest(base, '/api/health', { timeoutMs: 1500 })).value.status === 'ok'; } catch { /* Retry while process changes. */ }
    if (healthy === ready) return;
    await delay(400);
  }
  throw new Error(`Dashboard did not become ${ready ? 'healthy' : 'stopped'}.`);
}

async function checkApplication(base, credentials, expectedSha) {
  await waitHealth(base);
  const session = await localRequest(base, '/api/auth/login', { body: credentials });
  const auth = { cookie: session.cookie, csrfToken: session.value.csrfToken };
  if (!session.value.authenticated || !session.cookie) throw new Error('Authenticated deployment check failed.');
  const platform = (await localRequest(base, '/api/platform', auth)).value;
  if (platform.source?.commitSha !== expectedSha || platform.source?.dirty) throw new Error('Serving source does not match the verified release.');
  // Read-only smoke: the isolated probe has no model key or lab target, so it never starts a run.
  for (const path of ['/api/models', '/api/runs?limit=1', '/api/state']) await localRequest(base, path, auth);
  if (platform.modules?.some(module => module.id === 'chat-store' && module.status === 'active')) {
    const models = (await localRequest(base, '/api/chat/models', auth)).value;
    const sessions = (await localRequest(base, '/api/chat/sessions', auth)).value;
    if (!Array.isArray(models.models) || !Array.isArray(sessions.sessions)) throw new Error('Workspace chat health check failed.');
  }
  await localRequest(base, '/api/auth/logout', { ...auth, body: {} });
}

export async function normalizeTrackedModes(release) {
  const records = (await execute('/usr/bin/git', ['ls-files', '--stage', '-z'], { cwd: release })).split('\0').filter(Boolean);
  for (const record of records) {
    const tab = record.indexOf('\t');
    const [mode, , stage] = record.slice(0, tab).split(' ');
    const name = record.slice(tab + 1);
    if (tab < 0 || stage !== '0' || name.startsWith('/') || name.split('/').includes('..')) throw new Error('Invalid tracked release entry.');
    if (mode === '120000') continue;
    if (!['100644', '100755'].includes(mode)) throw new Error('Unsupported tracked release mode.');
    const path = join(release, name);
    const info = await lstat(path);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error('Tracked release file changed type.');
    // launchd's private umask also affects git checkout. Keep secrets private,
    // while source copied into non-root containers retains Git's standard modes.
    await chmod(path, mode === '100755' ? 0o755 : 0o644);
  }
}

const WEB_PARSER_DATASET_CHECK = `
  import { lstat, readFile } from 'node:fs/promises';
  const parser = new URL('./web-parser/', process.argv[1]);
  const files = ['categories.json', 'groups.json', ...'_abcdefghijklmnopqrstuvwxyz'.split('').map(letter => 'technologies/' + letter + '.json')];
  for (const file of files) {
    const target = new URL('data/webappanalyzer/' + file, parser);
    const stat = await lstat(target);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 10 * 1024 * 1024) throw new Error('Invalid web-parser dataset file.');
    const value = JSON.parse(await readFile(target, 'utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value) || !Object.keys(value).length) throw new Error('Empty or invalid web-parser dataset object.');
  }
  const { pageProbes } = await import(new URL('fingerprint.mjs', parser).href);
  const probes = pageProbes();
  if (!Array.isArray(probes?.js) || !probes.js.length || !probes.dom || typeof probes.dom !== 'object'
    || Array.isArray(probes.dom) || !Object.keys(probes.dom).length) throw new Error('The web-parser fingerprint dataset has no usable probes.');
  console.log('Web-parser fingerprint dataset ready.');
`;

export async function prepareRelease(config, candidate, phase, { execute: runCommand = execute } = {}) {
  const release = join(config.deployRoot, 'releases', candidate.sha);
  const env = serviceEnvironment(config, release);
  const logs = join(config.deployRoot, 'logs', candidate.sha); await mkdir(logs, { recursive: true, mode: 0o700 });
  const command = (name, executable, args, extra = {}) => runCommand(executable, args, { cwd: release, env,
    logFile: join(logs, `${name}.log`), ...extra });
  if (!await exists(release)) {
    await execute('/usr/bin/git', ['worktree', 'add', '--detach', release, candidate.sha], { cwd: config.repoDir });
  }
  if ((await execute('/usr/bin/git', ['rev-parse', 'HEAD'], { cwd: release })) !== candidate.sha
    || await execute('/usr/bin/git', ['status', '--porcelain', '--untracked-files=no'], { cwd: release })) throw new Error('Release worktree is not pristine.');
  await normalizeTrackedModes(release);
  const manifestPath = join(release, 'integration-manifest.json');
  const manifest = await exists(manifestPath) ? JSON.parse(await readFile(manifestPath, 'utf8')) : null;
  const webParser = manifest?.modules?.find(item => item.id === 'web-parser' && item.status === 'active');
  if (webParser && webParser.path !== 'web-parser') throw new Error('The active web-parser must use its fixed release directory.');
  const needsDependencies = !await exists(join(config.deployRoot, 'prepared', `${candidate.sha}.json`))
    || !await exists(join(release, '.venv/bin/python')) || !await exists(join(release, 'xss-parser/node_modules/playwright/package.json'))
    || !await exists(join(release, 'packages/report/capture/node_modules/playwright/package.json'))
    || (webParser && (!await exists(join(release, 'web-parser/node_modules/playwright/package.json'))
      || !await exists(join(release, 'web-parser/node_modules/wapalyzer-core/package.json'))));
  if (needsDependencies) {
    await phase('dependencies');
    if (!await exists(join(release, '.venv/bin/python'))) await command('venv', config.pythonPath, ['-m', 'venv', join(release, '.venv')]);
    const python = join(release, '.venv/bin/python');
    const tracked = (await execute('/usr/bin/git', ['ls-files'], { cwd: release })).split('\n');
    const active = manifest.modules.filter(item => item.status === 'active').map(item => item.path);
    const included = file => active.some(path => file.startsWith(`${path}/`));
    const locks = tracked.filter(file => file.endsWith('/package-lock.json') && included(file));
    for (const [i, lock] of locks.entries()) await command(`npm-${i}`, config.nodePath,
      [config.npmCli, 'ci', '--prefix', dirname(join(release, lock)), '--ignore-scripts', '--no-audit', '--no-fund']);
    const requirements = tracked.filter(file => file.endsWith('/requirements-ci.lock') && included(file));
    await command('python-requirements', python, ['-m', 'pip', 'install', ...requirements.flatMap(file => ['-r', join(release, file)])]);
    const packages = tracked.filter(file => file.endsWith('/pyproject.toml') && included(file));
    await command('python-packages', python, ['-m', 'pip', 'install', '--no-deps', ...packages.map(file => dirname(join(release, file)))]);
    await command('chromium', config.nodePath, [join(release, 'xss-parser/node_modules/playwright/cli.js'), 'install', 'chromium']);
  }
  if (webParser) {
    for (const name of ['web-parser', 'web-parser/scripts', 'web-parser/data', 'web-parser/data/webappanalyzer', 'web-parser/data/webappanalyzer/technologies']) {
      let entry;
      try { entry = await lstat(join(release, name)); } catch (failure) { if (failure.code !== 'ENOENT') throw failure; }
      if (entry && (!entry.isDirectory() || entry.isSymbolicLink())) throw new Error('The web-parser dataset directories must stay inside the release.');
    }
    for (const name of ['web-parser/scripts/fetch-dataset.mjs', 'web-parser/fingerprint.mjs']) {
      const entry = await lstat(join(release, name));
      if (!entry.isFile() || entry.isSymbolicLink()) throw new Error('The web-parser dataset entry points must be regular release files.');
    }
    await phase('web-parser-dataset');
    // npm lifecycle scripts remain disabled. Run this one audited, pinned-data
    // downloader explicitly, including when a prepared release lost its cache.
    await command('web-parser-dataset', config.nodePath, [join(release, 'web-parser/scripts/fetch-dataset.mjs')]);
    await command('web-parser-dataset-check', config.nodePath,
      ['--input-type=module', '-e', WEB_PARSER_DATASET_CHECK, pathToFileURL(release + '/').href]);
  }
  if (needsDependencies) {
    await command('preflight', config.nodePath, ['scripts/preflight.mjs'], { timeoutMs: 90_000 });
    await atomicJson(join(config.deployRoot, 'prepared', `${candidate.sha}.json`), { sha: candidate.sha, preparedAt: stamp() });
  }
  await phase('isolated-smoke');
  const probe = join(config.deployRoot, 'probe', candidate.sha);
  await rm(probe, { recursive: true, force: true }); await mkdir(probe, { recursive: true, mode: 0o700 });
  // The trial migration reads online backups, never the production run queue.
  const copied = join(probe, 'source-backup');
  await database(config, config.pythonPath, ['backup', '--run-db', join(config.runtimeDir, 'runs.sqlite'), '--case-db', config.caseDbPath, '--output', copied],
    { targetSha: candidate.sha, phase: 'trial-backup' });
  const casePath = join(copied, 'case.sqlite3');
  await database(config, join(release, '.venv/bin/python'), ['migrate', '--case-db', casePath],
    { targetSha: candidate.sha, phase: 'trial-migrate', env: { ...env, PYTHONPATH: join(release, 'casper-db/src') } });
  const password = randomBytes(24).toString('base64url'); const salt = randomBytes(16).toString('hex');
  await atomicJson(join(probe, 'auth.json'), { version: 1, users: [{ username: 'deploy-probe', role: 'admin', salt,
    hash: scryptSync(password, salt, 64).toString('hex') }] });
  await mkdir(join(probe, 'legacy'), { recursive: true, mode: 0o700 });
  await mkdir(join(release, 'reports'), { recursive: true });
  await replaceLink(join(release, '.runtime'), probe);
  await replaceLink(join(release, 'reports/pentest-db-runs'), join(probe, 'legacy'));
  const child = spawn(config.nodePath, [join(release, 'start.mjs')], { cwd: release,
    env: { ...env, PORT: String(config.probePort), DASHBOARD_HOST: '127.0.0.1', DASHBOARD_PUBLIC_ORIGIN: '',
      DASHBOARD_TRUSTED_PROXY_IPS: '', DASHBOARD_AUTH_FILE: join(probe, 'auth.json'), CA3P_STORE_PATH: join(probe, 'probe.sqlite'),
      CA3P_CHAT_DB_PATH: join(probe, 'chat.sqlite'),
      CASPER_DB_PATH: casePath, DEEPSEEK_API_KEY: '', CA3P_MODEL_ENV_FILE: join(probe, 'no-model.env') },
    stdio: ['ignore', 'ignore', 'ignore'] });
  let childClosed = false;
  const closed = new Promise(done => child.once('close', () => { childClosed = true; done(); }));
  let childError; child.on('error', error => { childError = error; });
  try {
    await checkApplication(`http://127.0.0.1:${config.probePort}`, { username: 'deploy-probe', password }, candidate.sha);
    if (childError || child.exitCode !== null) throw new Error('Candidate server exited during isolated verification.');
  } finally {
    if (!childClosed) child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 10_000);
    let deadline;
    try {
      await Promise.race([closed, new Promise((_, reject) => {
        deadline = setTimeout(() => reject(new Error('Candidate process did not terminate.')), 15_000);
      })]);
    } finally { clearTimeout(timer); clearTimeout(deadline); }
    await replaceLink(join(release, '.runtime'), config.runtimeDir);
    await replaceLink(join(release, 'reports/pentest-db-runs'), config.legacyReportsDir);
  }
  const modelEnv = join(config.repoDir, 'agent/.env');
  if (await exists(modelEnv)) { await chmod(modelEnv, 0o600); await replaceLink(join(release, 'agent/.env'), modelEnv); }
  await rm(probe, { recursive: true, force: true });
  return release;
}

async function readCredentials(config) {
  const text = await readFile(config.credentialFile, 'utf8');
  const password = /^admin:\s*(\S+)\s*$/m.exec(text)?.[1];
  if (!password) throw new Error('A local admin deployment-check credential is required.');
  return { username: 'admin', password };
}

async function retention(config, current, previous) {
  const directory = join(config.deployRoot, 'releases');
  const entries = await readdir(directory, { withFileTypes: true });
  const keep = new Set([current, previous]);
  for (const item of entries) {
    const path = join(directory, item.name);
    if (item.isDirectory() && /^[a-f0-9]{40}$/.test(item.name) && !keep.has(path)) {
      await execute('/usr/bin/git', ['worktree', 'remove', '--force', path], { cwd: config.repoDir });
      await rm(join(config.deployRoot, 'prepared', `${item.name}.json`), { force: true });
    }
  }
  const backupDir = join(config.deployRoot, 'backups');
  const backups = (await readdir(backupDir)).filter(name => /^[0-9TZ-]+-[a-f0-9]{12}$/.test(name)).sort().reverse();
  for (const name of backups.slice(5)) await rm(join(backupDir, name), { recursive: true, force: true });
}

export async function deploy(config, { retry = false, checkOnly = false, prepareOnly = false } = {}) {
  validateConfiguration(config);
  const releaseLock = await acquireLock(join(config.deployRoot, 'lock'));
  if (!releaseLock) return { status: 'busy' };
  const statusPath = join(config.deployRoot, 'status.json');
  const previousState = await readJson(statusPath, {});
  let state = { ...previousState, checkedAt: stamp() };
  const update = async (status, extra = {}) => { state = { ...state, status, ...extra, updatedAt: stamp() }; await atomicJson(statusPath, state); };
  let maintenance = false; let cuttingOver = false;
  try {
    const journalPath = join(config.deployRoot, 'transaction.json');
    let interrupted;
    try { interrupted = JSON.parse(await readFile(journalPath, 'utf8')); }
    catch (error) {
      if (error.code !== 'ENOENT') throw Object.assign(new Error('Deployment journal is unreadable; manual recovery is required.'), { recoveryFailed: true });
      if (await exists(join(config.deployRoot, 'maintenance.json'))) throw Object.assign(new Error('Unowned maintenance state requires operator recovery.'), { recoveryFailed: true });
    }
    await recoverTransaction(config, interrupted, update);
    const origin = await execute('/usr/bin/git', ['remote', 'get-url', 'origin'], { cwd: config.repoDir });
    if (origin !== `https://github.com/${config.repository}.git`) throw new Error('Deployment source must be the configured GitHub repository.');
    await execute('/usr/bin/git', ['fetch', 'origin', '+refs/heads/develop:refs/remotes/origin/develop',
      '+refs/heads/ci-results:refs/remotes/origin/ci-results'], { cwd: config.repoDir, timeoutMs: 60_000 });
    const headSha = await execute('/usr/bin/git', ['rev-parse', 'origin/develop'], { cwd: config.repoDir });
    const index = JSON.parse(await execute('/usr/bin/git', ['show', 'origin/ci-results:index.json'], { cwd: config.repoDir }));
    const selection = selectVerifiedRelease({ headSha, index, repository: config.repository });
    const current = await readlink(join(config.deployRoot, 'current'));
    const currentSha = await execute('/usr/bin/git', ['rev-parse', 'HEAD'], { cwd: current });
    await update('checking', { deployedSha: currentSha, targetSha: headSha, phase: 'ci-verification' });
    if (selection.status !== 'verified') { await update('waiting-ci', { message: selection.reason }); return state; }
    if (currentSha === selection.candidate.sha && !checkOnly) {
      await update('up-to-date', { phase: null, error: null, failedSha: null, lastFailedTargetSha: null, failedAt: null, retryAt: null,
        message: 'Verified develop is already deployed.' }); return state;
    }
    if (Number.isFinite(Date.parse(state.retryAt)) && Date.parse(state.retryAt) > Date.now()) {
      await update('waiting-ci', { phase: 'ci-verification', error: null, message: 'Waiting for the GitHub API rate limit to reset before verifying CI.' }); return state;
    }
    if (!retry && previousState.lastFailedTargetSha === headSha && Date.now() - Date.parse(previousState.failedAt) < 600_000) {
      await update('deferred', { phase: null, message: 'Deployment retry is backing off after a device error.' }); return state;
    }
    const candidate = await verifyWorkflowRun(selection.candidate, { repository: config.repository });
    state.retryAt = null;
    if (checkOnly) {
      await update('verified', { phase: null, runId: candidate.runId, message: 'The current develop revision passed GitHub workflow verification.' });
      return { ...state, candidate };
    }
    if (state.failedSha === candidate.sha && !retry) { await update('blocked', { phase: null, message: 'This release failed deployment; use --retry after correcting the device problem.' }); return state; }
    if (!await idle(config)) { await update('deferred', { phase: null, message: 'An inspection is active; deployment will retry after it finishes.' }); return state; }
    const credentials = await readCredentials(config);
    const authHash = hash(await readFile(join(config.runtimeDir, 'auth.json')));
    const release = await prepareRelease(config, candidate, phase => update('preparing', { phase }));
    await update('preparing', { phase: 'fixtures' });
    const fixtures = await prepareFixtures(config, release, candidate.sha, { execute });
    if (prepareOnly) { await update('prepared', { phase: null, message: 'Candidate dependencies, copied database migration and isolated smoke passed.' }); return state; }
    // Recheck CI and the remote branch after potentially lengthy dependency preparation.
    await verifyWorkflowRun(candidate, { repository: config.repository });
    const remote = await execute('/usr/bin/git', ['ls-remote', 'origin', 'refs/heads/develop'], { cwd: config.repoDir });
    if (remote.split(/\s/)[0] !== candidate.sha) { await update('superseded', { phase: null, message: 'A newer develop revision arrived during preparation.' }); return state; }
    if (!await idle(config)) { await update('deferred', { phase: null, message: 'An inspection started during preparation.' }); return state; }
    await atomicJson(join(config.deployRoot, 'maintenance.json'), { startedAt: stamp(), targetSha: candidate.sha }); maintenance = true;
    if (!await idle(config)) { await update('deferred', { phase: null, message: 'Waiting for an existing inspection to finish.' }); return state; }
    const base = `http://${config.host}:${config.port}`;
    const control = serviceControl(config);
    const stop = async () => { await control.stop(); await stopFixtures(fixtures, { execute }); };
    const start = control.start;
    cuttingOver = true;
    const journal = { previous: current, previousSha: currentSha, target: release, targetSha: candidate.sha, fixtures, backup: null, startedAt: stamp() };
    await atomicJson(join(config.deployRoot, 'transaction.json'), journal);
    await update('deploying', { phase: 'backup-and-migrate', runId: candidate.runId });
    await deploymentTransaction({ stop,
      backup: async () => {
        const path = join(config.deployRoot, 'backups', `${stamp().replace(/[:.]/g, '-')}-${candidate.sha.slice(0, 12)}`);
        await database(config, config.pythonPath, ['backup', '--run-db', join(config.runtimeDir, 'runs.sqlite'), '--case-db', config.caseDbPath, '--output', path],
          { targetSha: candidate.sha, phase: 'live-backup' });
        await copyFile(join(config.runtimeDir, 'auth.json'), join(path, 'auth.json')); await chmod(join(path, 'auth.json'), 0o600);
        await atomicJson(join(path, 'auth-checksum.json'), { sha256: hash(await readFile(join(path, 'auth.json'))) });
        await backupFixtures(path, fixtures, { execute });
        journal.backup = path; await atomicJson(join(config.deployRoot, 'transaction.json'), journal);
        return path;
      },
      migrate: () => database(config, join(release, '.venv/bin/python'), ['migrate', '--case-db', config.caseDbPath],
        { targetSha: candidate.sha, phase: 'live-migrate', env: { ...serviceEnvironment(config, release), PYTHONPATH: join(release, 'casper-db/src') } }),
      activate: async () => {
        await activateFixtures(fixtures, { execute });
        if (fixtures.enabled) await execute(config.nodePath, [join(release, 'vul-web2/scripts/deployment-check.mjs')], { timeoutMs: 60_000 });
        await replaceLink(join(config.deployRoot, 'current'), release);
      }, start,
      verify: async () => {
        await checkApplication(base, credentials, candidate.sha);
        if (hash(await readFile(join(config.runtimeDir, 'auth.json'))) !== authHash) throw new Error('Existing authentication accounts changed during deployment.');
      },
      restore: async path => {
        await database(config, config.pythonPath, ['restore', '--run-db', join(config.runtimeDir, 'runs.sqlite'), '--case-db', config.caseDbPath, '--backup', path],
          { targetSha: candidate.sha, phase: 'rollback-restore' });
        await restoreAuthentication(config, path);
        await restoreFixtures(path, fixtures, { execute });
      },
      rollback: async () => { await rollbackFixtures(fixtures, { execute }); await replaceLink(join(config.deployRoot, 'current'), current); },
      verifyRollback: () => checkApplication(base, credentials, currentSha),
    });
    await update('deployed', { deployedSha: candidate.sha, previousSha: currentSha, failedSha: null,
      phase: null, error: null, lastFailedTargetSha: null, failedAt: null, retryAt: null,
      deployedAt: stamp(), runId: candidate.runId, message: 'Verified develop deployed and authenticated health checks passed.' });
    await atomicJson(join(config.deployRoot, 'transaction.json'), { ...journal, committed: true });
    await rm(join(config.deployRoot, 'transaction.json'), { force: true });
    await retention(config, release, current).catch(() => {});
    return state;
  } catch (error) {
    if (!cuttingOver && ['CI_PENDING', 'GITHUB_RATE_LIMITED'].includes(error.code)) {
      await update('waiting-ci', { phase: 'ci-verification', error: null, lastFailedTargetSha: null, failedAt: null,
        retryAt: error.code === 'GITHUB_RATE_LIMITED' ? error.retryAt : null,
        message: error.code === 'CI_PENDING' ? 'The current develop workflow is still running; deployment will wait.' : 'GitHub API rate limit reached; deployment will retry after its reset.' });
      return state;
    }
    if (!error.recoveryFailed && cuttingOver) await rm(join(config.deployRoot, 'transaction.json'), { force: true });
    await update(error.recoveryFailed ? 'recovery-required' : 'failed', { phase: null,
      ...(cuttingOver ? { failedSha: state.targetSha } : {}), error: error.message,
      lastFailedTargetSha: state.targetSha, failedAt: stamp(),
      message: error.recoveryFailed ? 'Automatic recovery needs operator attention; writes remain paused.' : 'Deployment stopped; the previous release remains active.' });
    if (error.recoveryFailed) {
      await atomicJson(join(config.deployRoot, 'maintenance.json'), { recoveryRequired: true, updatedAt: stamp() });
      maintenance = false; // Keep writes paused until an operator restores a healthy release.
    }
    throw error;
  } finally {
    if (maintenance) await rm(join(config.deployRoot, 'maintenance.json'), { force: true });
    await releaseLock();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2); const index = args.indexOf('--config');
  try {
    if (index < 0 || !args[index + 1] || args.some((arg, i) => i !== index + 1 && !['--config', '--retry', '--check-only', '--prepare-only'].includes(arg))) throw new Error('Usage: device-deploy.mjs --config /absolute/config.json [--retry|--check-only|--prepare-only]');
    const result = await deploy(JSON.parse(await readFile(args[index + 1], 'utf8')), { retry: args.includes('--retry'), checkOnly: args.includes('--check-only'), prepareOnly: args.includes('--prepare-only') });
    console.log(JSON.stringify({ status: result.status, deployedSha: result.deployedSha ?? null, targetSha: result.targetSha ?? null }));
  } catch (error) { console.error(`Device deployment: ${error.message}`); process.exitCode = 1; }
}
