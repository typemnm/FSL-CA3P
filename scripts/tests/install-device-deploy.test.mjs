import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, readlink, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { acquireInstallationLock, buildDashboardPlist, buildUpdaterPlist, installDeviceDeploy, UPDATER_LABEL, validateInstallerConfig } from '../install-device-deploy.mjs';

const config = { repository: 'typemnm/FSL-CA3P', repoDir: '/repo', deployRoot: '/private/deploy',
  runtimeDir: '/private/runtime', caseDbPath: '/private/cases.sqlite', legacyReportsDir: '/private/reports',
  nodePath: '/tools/node', pythonPath: '/tools/python3', npmCli: '/tools/npm-cli.js',
  serviceLabel: 'kr.or.casper.ca3p.macmini-dashboard', servicePlistPath: '/agents/dashboard.plist',
  host: '192.168.0.84', port: 4175, probePort: 4185, publicOrigin: 'https://macmini.casper.or.kr',
  trustedProxyIps: '192.168.0.3', credentialFile: '/private/credential.json' };

test('installer preserves dashboard authentication, proxy and restart policy while selecting stable current release', () => {
  const original = { Label: config.serviceLabel, RunAtLoad: true, KeepAlive: true, ThrottleInterval: 10,
    Umask: 0o077, StandardOutPath: '/logs/out', StandardErrorPath: '/logs/err',
    ProgramArguments: ['/old/node', '/old/start.mjs'], WorkingDirectory: '/old',
    EnvironmentVariables: { DASHBOARD_AUTH_FILE: '/private/auth.json', DASHBOARD_PUBLIC_ORIGIN: config.publicOrigin,
      DASHBOARD_TRUSTED_PROXY_IPS: config.trustedProxyIps, DASHBOARD_HOST: config.host, PORT: '4175', CUSTOM: 'keep' } };
  const before = structuredClone(original), result = buildDashboardPlist(original, config);
  assert.deepEqual(original, before);
  for (const key of ['RunAtLoad', 'KeepAlive', 'ThrottleInterval', 'Umask', 'StandardOutPath', 'StandardErrorPath']) assert.deepEqual(result[key], original[key]);
  for (const [key, value] of Object.entries(original.EnvironmentVariables)) assert.equal(result.EnvironmentVariables[key], value);
  assert.deepEqual(result.ProgramArguments, ['/tools/node', '/private/deploy/current/start.mjs']);
  assert.equal(result.WorkingDirectory, '/private/deploy/current');
  assert.equal(result.EnvironmentVariables.CASPER_DB_PATH, '/private/cases.sqlite');
  assert.equal(result.EnvironmentVariables.CA3P_REPORT_PYTHON, '/private/deploy/current/.venv/bin/python');
  assert.equal(result.EnvironmentVariables.DASHBOARD_DEPLOYMENT_LOCK_FILE, '/private/deploy/maintenance.json');
  assert.equal(result.EnvironmentVariables.DASHBOARD_DEPLOYMENT_STATUS_FILE, '/private/deploy/status.json');
  assert.throws(() => buildDashboardPlist({ Label: 'wrong' }, config), /label/);
});

test('updater polls every two minutes without launchd continuously restarting a completed check', () => {
  const plist = buildUpdaterPlist(config, '/private/deploy/config.json');
  assert.equal(plist.Label, UPDATER_LABEL);
  assert.equal(plist.RunAtLoad, true); assert.equal(plist.StartInterval, 120);
  assert.equal(Object.hasOwn(plist, 'KeepAlive'), false);
  assert.deepEqual(plist.ProgramArguments, ['/tools/node', '/private/deploy/controller/device-deploy.mjs', '--config', '/private/deploy/config.json']);
  assert.equal(plist.Umask, 0o077);
  assert.ok(plist.EnvironmentVariables.PATH.split(':').includes('/usr/local/bin'));
});

test('installer rejects relative data paths, overlapping probe port and credential-bearing public origins', () => {
  assert.equal(validateInstallerConfig(config), config);
  assert.throws(() => validateInstallerConfig({ ...config, caseDbPath: 'cases.sqlite' }), /absolute/);
  assert.throws(() => validateInstallerConfig({ ...config, probePort: 4175 }), /different/);
  assert.throws(() => validateInstallerConfig({ ...config, publicOrigin: 'https://secret@example.org' }), /plain HTTPS/);
  assert.throws(() => validateInstallerConfig({ ...config, serviceLabel: UPDATER_LABEL }), /serviceLabel/);
});

test('installer holds the updater lock and refuses to interrupt a live deployment', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-installer-lock-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const release = await acquireInstallationLock(directory);
  const owner = await readFile(join(directory, 'lock/owner.json'), 'utf8');
  await assert.rejects(acquireInstallationLock(directory), /active deployment/);
  assert.equal(await readFile(join(directory, 'lock/owner.json'), 'utf8'), owner);
  await release();
  const again = await acquireInstallationLock(directory); await again();
  await mkdir(join(directory, 'lock'));
  await assert.rejects(acquireInstallationLock(directory), /lock is held/);
});

test('no-start stages controller and plists without restarting dashboard and keeps first backup on reinstall', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ca3p-installer-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const old = join(directory, 'old'), scripts = join(directory, 'scripts'), agents = join(directory, 'agents');
  for (const path of [old, scripts, agents]) await mkdir(path);
  await writeFile(join(old, 'start.mjs'), '');
  await writeFile(join(directory, 'npm-cli.js'), ''); await writeFile(join(directory, 'credential.json'), '{}');
  for (const filename of ['device-deploy.mjs', 'device-deploy-verification.mjs', 'device-deploy-events.mjs', 'device-db.py', 'device-fixtures.mjs']) await writeFile(join(scripts, filename), filename);
  const fixtureConfig = { ...config, deployRoot: join(directory, 'deployment'), runtimeDir: join(directory, 'runtime'),
    nodePath: process.execPath, pythonPath: '/usr/bin/python3', servicePlistPath: join(agents, 'dashboard.plist'),
    npmCli: join(directory, 'npm-cli.js'), credentialFile: join(directory, 'credential.json') };
  const original = { Label: config.serviceLabel, WorkingDirectory: old, KeepAlive: true,
    EnvironmentVariables: { DASHBOARD_AUTH_FILE: '/keep/auth.json' } };
  const bytes = execFileSync(fixtureConfig.pythonPath, ['-c', 'import json,plistlib,sys;sys.stdout.buffer.write(plistlib.dumps(json.load(sys.stdin)))'], { input: JSON.stringify(original) });
  await writeFile(fixtureConfig.servicePlistPath, bytes);
  const configPath = join(directory, 'config.json'); await writeFile(configPath, JSON.stringify(fixtureConfig));
  const installed = await installDeviceDeploy({ configPath, noStart: true, sourceDirectory: scripts });
  assert.equal(installed.started, false); assert.equal(await readlink(join(fixtureConfig.deployRoot, 'current')), old);
  assert.deepEqual(await readFile(join(fixtureConfig.deployRoot, 'original-dashboard.plist')), bytes);
  assert.equal((await stat(configPath)).mode & 0o777, 0o600);
  assert.equal((await stat(join(fixtureConfig.deployRoot, 'controller'))).mode & 0o777, 0o700);
  assert.equal(await readFile(join(fixtureConfig.deployRoot, 'controller/device-deploy.mjs'), 'utf8'), 'device-deploy.mjs');
  assert.equal(await readFile(join(fixtureConfig.deployRoot, 'controller/device-deploy-events.mjs'), 'utf8'), 'device-deploy-events.mjs');
  const installedPlist = JSON.parse(execFileSync(fixtureConfig.pythonPath, ['-c', 'import json,plistlib,sys;json.dump(plistlib.load(open(sys.argv[1],"rb")),sys.stdout)', fixtureConfig.servicePlistPath], { encoding: 'utf8' }));
  assert.equal(installedPlist.EnvironmentVariables.DASHBOARD_AUTH_FILE, '/keep/auth.json');
  assert.equal(installedPlist.KeepAlive, true);
  await installDeviceDeploy({ configPath, noStart: true, sourceDirectory: scripts });
  assert.deepEqual(await readFile(join(fixtureConfig.deployRoot, 'original-dashboard.plist')), bytes);
});
