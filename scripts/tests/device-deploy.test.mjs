import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, symlink, readlink, rm, stat, utimes } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { createServer as createHttpServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { deploymentTransaction, validateConfiguration, prepareRelease, execute, atomicJson, deploy, localRequest } from '../device-deploy.mjs';

const config = { repository: 'typemnm/FSL-CA3P', repoDir: '/repo', deployRoot: '/private/deploy',
  runtimeDir: '/private/runtime', caseDbPath: '/private/cases.sqlite', legacyReportsDir: '/private/reports',
  nodePath: '/tools/node', pythonPath: '/tools/python3', npmCli: '/tools/npm-cli.js',
  serviceLabel: 'kr.or.casper.ca3p.macmini-dashboard', servicePlistPath: '/agents/dashboard.plist',
  host: '192.168.0.84', port: 4175, probePort: 4185, credentialFile: '/private/access.txt' };

function transactionFixture({ fail, recoveryFail } = {}) {
  const calls = [], snapshot = { privateBackup: '/private/backup' };
  const failure = new Error(`original ${fail} failure`), recovery = new Error(`recovery ${recoveryFail} failure`);
  const counts = new Map();
  const actions = Object.fromEntries(['stop', 'backup', 'migrate', 'activate', 'start', 'verify', 'restore',
    'rollback', 'verifyRollback'].map(name => [name, async value => {
    calls.push(name); const count = (counts.get(name) ?? 0) + 1; counts.set(name, count);
    if (name === fail && count === 1) throw failure;
    if (name === recoveryFail && (name !== fail || count > 1)) throw recovery;
    if (name === 'migrate' || name === 'restore') assert.equal(value, snapshot);
    if (name === 'backup') return snapshot;
  }]));
  return { actions, calls, failure, recovery };
}

test('successful transaction stops writers before backup and verifies activated release before success', async () => {
  const { actions, calls } = transactionFixture();
  assert.deepEqual(await deploymentTransaction(actions), { deployed: true });
  assert.deepEqual(calls, ['stop', 'backup', 'migrate', 'activate', 'start', 'verify']);
});

test('failed backup restarts old release without attempting to restore an incomplete snapshot', async () => {
  const { actions, calls, failure } = transactionFixture({ fail: 'backup' });
  await assert.rejects(deploymentTransaction(actions), error => error === failure);
  assert.deepEqual(calls, ['stop', 'backup', 'stop', 'rollback', 'start', 'verifyRollback']);
});

test('failed migration restores snapshot before old release starts and preserves original error', async () => {
  const { actions, calls, failure } = transactionFixture({ fail: 'migrate' });
  await assert.rejects(deploymentTransaction(actions), error => error === failure);
  assert.deepEqual(calls, ['stop', 'backup', 'migrate', 'stop', 'restore', 'rollback', 'start', 'verifyRollback']);
});

test('failed activation and startup restore DBs and previous release before rollback verification', async t => {
  for (const phase of ['activate', 'start', 'verify']) await t.test(phase, async () => {
    const { actions, calls, failure } = transactionFixture({ fail: phase });
    await assert.rejects(deploymentTransaction(actions), error => error === failure);
    const rollbackStart = calls.lastIndexOf('stop');
    assert.deepEqual(calls.slice(rollbackStart), ['stop', 'restore', 'rollback', 'start', 'verifyRollback']);
    assert.equal(calls.filter(name => name === 'backup').length, 1);
  });
});

test('partial initial stop failure also attempts recovery of the previous running release', async () => {
  const { actions, calls, failure } = transactionFixture({ fail: 'stop' });
  await assert.rejects(deploymentTransaction(actions), error => error === failure);
  assert.deepEqual(calls, ['stop', 'stop', 'rollback', 'start', 'verifyRollback']);
});

test('failed recovery is distinguished from successful rollback and retains original failure', async t => {
  for (const phase of ['restore', 'rollback', 'start', 'verifyRollback']) await t.test(phase, async () => {
    const { actions, calls, failure } = transactionFixture({ fail: 'verify', recoveryFail: phase });
    // start has a normal deployment invocation before the rollback invocation.
    if (phase === 'start') {
      let starts = 0;
      actions.start = async () => { calls.push('start'); if (++starts === 2) throw new Error('recovery start failure'); };
    }
    await assert.rejects(deploymentTransaction(actions), error => {
      assert.equal(error.recoveryFailed, true);
      assert.equal(error.cause, failure);
      assert.match(error.message, /automatic recovery also failed/);
      return true;
    });
    if (phase !== 'verifyRollback') assert.notEqual(calls.at(-1), 'verifyRollback');
  });
});

test('controller accepts literal loopback and private IPv4 addresses only', () => {
  for (const host of ['127.0.0.1', '10.0.0.1', '192.168.0.84', '172.16.0.1', '172.31.255.254']) {
    const value = { ...config, host };
    assert.equal(validateConfiguration(value), value);
  }
  for (const host of ['192.168.evil.example', '10.evil.example', '172.16.evil.example',
    '192.168.0.84.evil.example', '192.168.0.84@evil.example', 'localhost', '8.8.8.8',
    '172.15.0.1', '172.32.0.1', '0.0.0.0', '[::1]', '127.1', '192.168.999.1']) {
    assert.throws(() => validateConfiguration({ ...config, host }), undefined, host);
  }
});

test('controller rejects invalid repository, non-absolute paths, labels and unsafe port pairs', () => {
  for (const mutation of [{ repository: 'elsewhere/repo' }, { repoDir: 'repo' }, { caseDbPath: 'cases.sqlite' },
    { serviceLabel: 'another.label' }, { port: 81 }, { probePort: 65536 }, { probePort: 4175 }, { port: 4175.5 }]) {
    assert.throws(() => validateConfiguration({ ...config, ...mutation }));
  }
});

test('command failure never exposes captured output and writes diagnostics privately', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-execute-'));
  try {
    const logFile = join(directory, 'private.log');
    await assert.rejects(execute(process.execPath, ['-e', 'console.error("synthetic-private-value");process.exit(7)'], { logFile }), error => {
      assert.equal(error.exitCode, 7);
      assert.doesNotMatch(error.message, /synthetic-private-value/);
      return true;
    });
    assert.match(await readFile(logFile, 'utf8'), /synthetic-private-value/);
    assert.equal((await stat(logFile)).mode & 0o777, 0o600);
    await assert.rejects(execute(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { timeoutMs: 20 }), /timed out/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('an existing deployment owner prevents concurrent commands or live service operations', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-lock-'));
  try {
    await atomicJson(join(directory, 'lock/owner.json'), { pid: process.pid, startedAt: new Date().toISOString() });
    assert.deepEqual(await deploy({ ...config, deployRoot: directory, repoDir: '/nonexistent-do-not-execute' }), { status: 'busy' });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('ownerless locks protect a new writer but recover a stale pre-owner crash', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-orphan-lock-'));
  const lock = join(directory, 'lock');
  try {
    await mkdir(lock);
    const localConfig = { ...config, deployRoot: directory, repoDir: '/nonexistent-never-fetch' };
    assert.deepEqual(await deploy(localConfig), { status: 'busy' });
    const old = new Date(Date.now() - 120_000); await utimes(lock, old, old);
    // Once recovered, the first git cwd check fails before any network or service operation.
    await assert.rejects(deploy(localConfig), /spawn|ENOENT|failed/);
    await assert.rejects(stat(lock), { code: 'ENOENT' });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('unreadable or structurally invalid crash journals preserve maintenance and require manual recovery', async () => {
  for (const contents of ['{', 'null', 'false', '[]', '{}', '{"committed":true}']) {
    const directory = await mkdtemp(join(tmpdir(), 'ca3p-invalid-journal-'));
    try {
      await writeFile(join(directory, 'transaction.json'), contents, { mode: 0o600 });
      await assert.rejects(deploy({ ...config, deployRoot: directory, repoDir: '/nonexistent-never-fetch' }), error => {
        assert.equal(error.recoveryFailed, true, contents);
        return true;
      });
      assert.equal(await readFile(join(directory, 'transaction.json'), 'utf8'), contents);
      const maintenance = JSON.parse(await readFile(join(directory, 'maintenance.json'), 'utf8'));
      assert.equal(maintenance.recoveryRequired, true);
    } finally { await rm(directory, { recursive: true, force: true }); }
  }
});

test('unowned maintenance never silently clears or proceeds to repository and service operations', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-unowned-maintenance-'));
  try {
    await atomicJson(join(directory, 'maintenance.json'), { targetSha: 'a'.repeat(40) });
    await assert.rejects(deploy({ ...config, deployRoot: directory, repoDir: '/nonexistent-never-fetch' }), error => {
      assert.equal(error.recoveryFailed, true);
      assert.match(error.message, /Unowned maintenance/);
      return true;
    });
    assert.equal(JSON.parse(await readFile(join(directory, 'maintenance.json'), 'utf8')).recoveryRequired, true);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('a rollback stop failure prevents restore while writers might still be alive', async () => {
  const fixture = transactionFixture({ fail: 'verify' });
  let stops = 0;
  fixture.actions.stop = async () => { fixture.calls.push('stop'); if (++stops === 2) throw new Error('writers still alive'); };
  await assert.rejects(deploymentTransaction(fixture.actions), error => {
    assert.equal(error.recoveryFailed, true);
    assert.equal(error.cause, fixture.failure);
    return true;
  });
  assert.equal(fixture.calls.at(-1), 'stop');
  assert.equal(fixture.calls.includes('restore'), false);
  assert.equal(fixture.calls.includes('rollback'), false);
});

async function withLocalHttp(handler, run) {
  const server = createHttpServer(handler);
  await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '::', done); });
  try { await run(`http://localhost:${server.address().port}`, server.address().port); }
  finally {
    server.closeAllConnections();
    await new Promise(done => server.close(done));
  }
}

test('LAN health transport preserves loopback Host even when the requested hostname differs', async () => {
  const requests = [];
  await withLocalHttp(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    requests.push({ headers: request.headers, method: request.method, body: Buffer.concat(chunks).toString('utf8') });
    response.setHeader('Set-Cookie', 'ca3p_session=synthetic-session; HttpOnly; Path=/');
    response.end(JSON.stringify({ status: 'ok' }));
  }, async (base, port) => {
    const result = await localRequest(base, '/api/auth/login', { cookie: 'prior=synthetic', csrfToken: 'synthetic-csrf',
      body: { username: 'fixture', password: 'synthetic-local-password' } });
    assert.deepEqual(result, { value: { status: 'ok' }, cookie: 'ca3p_session=synthetic-session' });
    assert.equal(requests[0].headers.host, `127.0.0.1:${port}`);
    assert.equal(requests[0].headers.cookie, 'prior=synthetic');
    assert.equal(requests[0].headers['x-csrf-token'], 'synthetic-csrf');
    assert.equal(requests[0].headers['content-type'], 'application/json');
    assert.deepEqual(JSON.parse(requests[0].body), { username: 'fixture', password: 'synthetic-local-password' });
    assert.equal(requests[0].method, 'POST');
    await localRequest(base, '/api/health');
    assert.equal(requests[1].method, 'GET');
    assert.equal(requests[1].body, '');
  });
});

test('local health transport rejects redirects and oversized response streams', async () => {
  let requests = 0;
  await withLocalHttp((request, response) => {
    requests++;
    if (request.url === '/redirect') {
      response.writeHead(302, { Location: '/must-not-follow' }); response.end('{}');
    } else if (request.url === '/large') response.end('x'.repeat(2_000_001));
    else { response.statusCode = 500; response.end('{}'); }
  }, async base => {
    await assert.rejects(localRequest(base, '/redirect'), /returned 302/);
    assert.equal(requests, 1);
    await assert.rejects(localRequest(base, '/large'), /oversized/);
  });
});

test('local health timeout covers a connection with headers and a stalled JSON body', async () => {
  await withLocalHttp((request, response) => {
    if (request.url === '/body-stall') { response.writeHead(200); response.write('{'); }
    // /headers-stall intentionally writes nothing.
  }, async base => {
    for (const path of ['/headers-stall', '/body-stall']) {
      await assert.rejects(localRequest(base, path, { timeoutMs: 30 }), error => {
        assert.ok(['AbortError', 'Error'].includes(error.name));
        return true;
      });
    }
  });
});

async function availablePort() {
  const server = createServer();
  await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', done); });
  const port = server.address().port;
  await new Promise(done => server.close(done));
  return port;
}

test('isolated preparation masks inherited/file model keys and never uses production runtime paths', { timeout: 30_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-isolated-'));
  const previous = { key: process.env.DEEPSEEK_API_KEY, observation: process.env.CA3P_SMOKE_TEST_OBSERVATION };
  try {
    const repoDir = join(directory, 'repo');
    const deployRoot = join(directory, 'deploy');
    const runtimeDir = join(directory, 'production-runtime');
    const reports = join(directory, 'production-reports');
    const observation = join(directory, 'smoke-observation.json');
    await mkdir(repoDir); await mkdir(runtimeDir); await mkdir(reports);
    await writeFile(join(runtimeDir, 'sentinel'), 'production-data');
    const configModule = fileURLToPath(new URL('../../agent/src/deepseek-config.js', import.meta.url));
    // A minimal candidate HTTP app records the real child's environment and uses
    // the real model-option resolver with a synthetic agent/.env symlink.
    const source = `import {createServer} from 'node:http';
import {readFileSync,writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {join} from 'node:path';
const config=createRequire(import.meta.url)(${JSON.stringify(configModule)});
let modelAvailable=false;try{config.resolveDeepSeekOptions({env:process.env,envFile:join(process.cwd(),'agent/.env')});modelAvailable=true;}catch{}
writeFileSync(process.env.CA3P_SMOKE_TEST_OBSERVATION,JSON.stringify({modelAvailable,store:process.env.CA3P_STORE_PATH,caseDb:process.env.CASPER_DB_PATH,auth:process.env.DASHBOARD_AUTH_FILE,envFile:process.env.CA3P_MODEL_ENV_FILE,keyBlank:process.env.DEEPSEEK_API_KEY==='',runtimeLink:process.cwd()+'/.runtime'}));
const sha=execFileSync('/usr/bin/git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
const server=createServer((req,res)=>{let value={};
if(req.url==='/api/health')value={status:'ok'};
else if(req.url==='/api/auth/login'){res.setHeader('Set-Cookie','ca3p_session=synthetic; Path=/');value={authenticated:true,csrfToken:'synthetic-csrf'};}
else if(req.url==='/api/platform')value={source:{commitSha:sha,dirty:false}};
else if(req.url==='/api/models')value={models:[{id:'deepseek-flash',available:modelAvailable}]};
else if(req.url==='/api/runs'&&req.method==='POST')value={run:{id:'synthetic-fixture'}};
else if(req.url==='/api/runs/synthetic-fixture')value={run:{status:'completed',simulated:true,targetContacted:false}};
res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value));});
server.listen(Number(process.env.PORT),'127.0.0.1');
process.once('SIGTERM',()=>server.close());
`;
    await writeFile(join(repoDir, 'start.mjs'), source);
    const git = args => execFileSync('/usr/bin/git', args, { cwd: repoDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    git(['init', '-q']); git(['add', 'start.mjs']);
    git(['-c', 'user.name=CA3P fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'Isolated deployment fixture']);
    const sha = git(['rev-parse', 'HEAD']);
    const release = join(deployRoot, 'releases', sha);
    git(['worktree', 'add', '--detach', release, sha]);
    const fakePython = join(directory, 'fixture-python');
    await writeFile(fakePython, '#!/bin/sh\nprintf \'{"ok":true}\\n\'\n', { mode: 0o700 });
    for (const path of ['.venv/bin', 'xss-parser/node_modules/playwright', 'packages/report/capture/node_modules/playwright', 'agent']) await mkdir(join(release, path), { recursive: true });
    await symlink(fakePython, join(release, '.venv/bin/python'));
    for (const path of ['xss-parser/node_modules/playwright/package.json', 'packages/report/capture/node_modules/playwright/package.json']) await writeFile(join(release, path), '{}');
    await atomicJson(join(deployRoot, 'prepared', `${sha}.json`), { sha });
    await mkdir(join(repoDir, 'agent'));
    const envFile = join(repoDir, 'agent/.env');
    await writeFile(envFile, 'DEEPSEEK_API_KEY=synthetic-file-key\n', { mode: 0o600 });
    await symlink(envFile, join(release, 'agent/.env'));
    process.env.DEEPSEEK_API_KEY = 'synthetic-inherited-key';
    process.env.CA3P_SMOKE_TEST_OBSERVATION = observation;
    const probePort = await availablePort();
    const localConfig = { ...config, repoDir, deployRoot, runtimeDir, legacyReportsDir: reports,
      caseDbPath: join(directory, 'production-case.sqlite'), nodePath: process.execPath, pythonPath: fakePython, probePort };
    assert.equal(await prepareRelease(localConfig, { sha }, async () => {}), release);
    const observed = JSON.parse(await readFile(observation, 'utf8'));
    const probe = join(deployRoot, 'probe', sha);
    assert.equal(observed.modelAvailable, false);
    assert.equal(observed.keyBlank, true);
    assert.equal(observed.store, join(probe, 'probe.sqlite'));
    assert.equal(observed.caseDb, join(probe, 'source-backup/case.sqlite3'));
    assert.equal(observed.auth, join(probe, 'auth.json'));
    assert.equal(observed.envFile, join(probe, 'no-model.env'));
    assert.equal(await readlink(join(release, '.runtime')), runtimeDir);
    assert.equal(await readlink(join(release, 'reports/pentest-db-runs')), reports);
    assert.equal(await readFile(join(runtimeDir, 'sentinel'), 'utf8'), 'production-data');
    assert.equal(await readFile(envFile, 'utf8'), 'DEEPSEEK_API_KEY=synthetic-file-key\n');
  } finally {
    if (previous.key === undefined) delete process.env.DEEPSEEK_API_KEY; else process.env.DEEPSEEK_API_KEY = previous.key;
    if (previous.observation === undefined) delete process.env.CA3P_SMOKE_TEST_OBSERVATION; else process.env.CA3P_SMOKE_TEST_OBSERVATION = previous.observation;
    await rm(directory, { recursive: true, force: true });
  }
});
