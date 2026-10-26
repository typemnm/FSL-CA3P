#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { access, chmod, copyFile, lstat, mkdir, readFile, readlink, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const UPDATER_LABEL = 'kr.or.casper.ca3p.device-deploy';
const CONTROLLER_FILES = ['device-deploy.mjs', 'device-deploy-verification.mjs', 'device-deploy-events.mjs', 'device-db.py', 'device-fixtures.mjs'];
const PATH_KEYS = ['repoDir', 'deployRoot', 'runtimeDir', 'caseDbPath', 'legacyReportsDir',
  'nodePath', 'pythonPath', 'npmCli', 'servicePlistPath', 'credentialFile'];

export function validateInstallerConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Provide a deployment configuration object.');
  for (const key of PATH_KEYS) {
    if (typeof config[key] !== 'string' || !isAbsolute(config[key]) || /[\u0000\r\n]/u.test(config[key])) {
      throw new Error(`${key} must be an absolute path.`);
    }
  }
  if (!/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/u.test(config.repository ?? '')) throw new Error('repository must be owner/name.');
  if (!/^[a-zA-Z0-9_.-]+$/u.test(config.serviceLabel ?? '') || config.serviceLabel === UPDATER_LABEL) throw new Error('Invalid dashboard serviceLabel.');
  if (typeof config.host !== 'string' || !config.host || /[\u0000\r\n]/u.test(config.host)) throw new Error('Invalid dashboard host.');
  for (const key of ['port', 'probePort']) {
    if (!Number.isInteger(config[key]) || config[key] < 1 || config[key] > 65535) throw new Error(`${key} must be a valid port.`);
  }
  if (config.port === config.probePort) throw new Error('The candidate probe must use a different port.');
  const origin = new URL(config.publicOrigin);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/') {
    throw new Error('publicOrigin must be a plain HTTPS origin.');
  }
  if (typeof config.trustedProxyIps !== 'string' || /[\u0000\r\n]/u.test(config.trustedProxyIps)) throw new Error('trustedProxyIps must be a string.');
  return config;
}

/** Preserve site-specific authentication, proxy settings, and launchd restart policy. */
export function buildDashboardPlist(original, config) {
  if (original.Label !== config.serviceLabel) throw new Error('The existing dashboard LaunchAgent label does not match configuration.');
  const current = join(config.deployRoot, 'current');
  return { ...original, WorkingDirectory: current, ProgramArguments: [config.nodePath, join(current, 'start.mjs')],
    EnvironmentVariables: { ...original.EnvironmentVariables,
      CASPER_DB_PYTHON: join(current, '.venv/bin/python'), CA3P_REPORT_PYTHON: join(current, '.venv/bin/python'),
      CASPER_DB_PATH: config.caseDbPath, CA3P_STORE_PATH: join(config.runtimeDir, 'runs.sqlite'),
      DASHBOARD_DEPLOYMENT_LOCK_FILE: join(config.deployRoot, 'maintenance.json'),
      DASHBOARD_DEPLOYMENT_STATUS_FILE: join(config.deployRoot, 'status.json') } };
}

export function buildUpdaterPlist(config, configPath) {
  return { Label: UPDATER_LABEL, RunAtLoad: true, StartInterval: 120, ProcessType: 'Background',
    ProgramArguments: [config.nodePath, join(config.deployRoot, 'controller/device-deploy.mjs'), '--config', configPath],
    WorkingDirectory: config.deployRoot, Umask: 0o077,
    EnvironmentVariables: { PATH: [...new Set([dirname(config.nodePath), dirname(config.pythonPath),
      '/usr/local/bin', '/opt/homebrew/bin', '/Applications/Docker.app/Contents/Resources/bin',
      '/usr/bin', '/bin', '/usr/sbin', '/sbin'])].join(':') },
    StandardOutPath: join(config.runtimeDir, 'device-deploy.out.log'),
    StandardErrorPath: join(config.runtimeDir, 'device-deploy.err.log') };
}

function parsePlist(path, python) {
  return JSON.parse(execFileSync(python, ['-c', 'import json,plistlib,sys;json.dump(plistlib.load(open(sys.argv[1],"rb")),sys.stdout)', path],
    { encoding: 'utf8', timeout: 15_000, maxBuffer: 1_000_000 }));
}

async function writePlist(path, value, python) {
  const bytes = execFileSync(python, ['-c', 'import json,plistlib,sys;sys.stdout.buffer.write(plistlib.dumps(json.load(sys.stdin)))'],
    { input: JSON.stringify(value), timeout: 15_000, maxBuffer: 1_000_000 });
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(temporary, bytes, { mode: 0o600 });
  await chmod(temporary, 0o600); await rename(temporary, path);
}

async function privateDirectory(path) { await mkdir(path, { recursive: true, mode: 0o700 }); await chmod(path, 0o700); }
async function exists(path) { try { await lstat(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } }

/** Share the updater's lock so reinstalling its LaunchAgent cannot interrupt a live cutover. */
export async function acquireInstallationLock(deployRoot) {
  await privateDirectory(deployRoot);
  const lock = join(deployRoot, 'lock');
  try { await mkdir(lock, { mode: 0o700 }); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    let owner;
    try { owner = JSON.parse(await readFile(join(lock, 'owner.json'), 'utf8')); } catch { /* A newly created or malformed lock is held. */ }
    if (!Number.isSafeInteger(owner?.pid) || owner.pid <= 0) throw new Error('Deployment lock is held; wait for the updater before reinstalling.');
    try { process.kill(owner.pid, 0); }
    catch (failure) {
      if (failure.code === 'ESRCH') {
        throw new Error('A stale deployment lock exists; let the controller recover it before reinstalling.');
      } else throw new Error('Cannot verify deployment lock owner; updater installation was not started.');
    }
    if (owner) throw new Error('An active deployment owns the lock; wait before reinstalling the updater.');
  }
  await writeFile(join(lock, 'owner.json'), JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }), { mode: 0o600 });
  return () => rm(lock, { recursive: true, force: true });
}

export async function installDeviceDeploy({ configPath, noStart = false,
  sourceDirectory = dirname(fileURLToPath(import.meta.url)) } = {}) {
  if (!isAbsolute(configPath ?? '')) throw new Error('--config requires an absolute path.');
  if (!noStart && process.platform !== 'darwin') throw new Error('LaunchAgent installation requires macOS; use --no-start to stage files.');
  const config = validateInstallerConfig(JSON.parse(await readFile(configPath, 'utf8')));
  for (const path of [config.nodePath, config.pythonPath]) await access(path, constants.X_OK);
  for (const path of [config.npmCli, config.credentialFile]) {
    if (!(await stat(path)).isFile()) throw new Error(`Required file is missing: ${path}`);
  }
  const original = parsePlist(config.servicePlistPath, config.pythonPath);
  const dashboard = buildDashboardPlist(original, config);
  const controller = join(config.deployRoot, 'controller');
  for (const name of CONTROLLER_FILES) {
    if (!(await stat(join(sourceDirectory, name))).isFile()) throw new Error(`Controller source is missing: ${name}`);
  }
  const current = join(config.deployRoot, 'current');
  if (await exists(current)) {
    if (!(await lstat(current)).isSymbolicLink()) throw new Error('deployRoot/current must be a symbolic link.');
    await access(join(current, 'start.mjs'));
  } else {
    if (!isAbsolute(original.WorkingDirectory ?? '')) throw new Error('The original service WorkingDirectory must be absolute.');
    await access(join(original.WorkingDirectory, 'start.mjs'));
  }

  // Hold the same lock as the updater before stopping it or replacing controller files.
  const releaseLock = await acquireInstallationLock(config.deployRoot);
  try {
    const domain = `gui/${process.getuid()}`;
    if (!noStart) {
      try { execFileSync('/bin/launchctl', ['bootout', `${domain}/${UPDATER_LABEL}`], { stdio: 'pipe', timeout: 15_000 }); }
      catch (error) { if (error.status !== 3 && error.status !== 113) throw new Error('Could not stop the previous deployment updater.'); }
    }
    await privateDirectory(controller); await privateDirectory(config.runtimeDir);
    await chmod(configPath, 0o600); await chmod(config.credentialFile, 0o600);
    const backup = join(config.deployRoot, 'original-dashboard.plist');
    if (!(await exists(backup))) { await copyFile(config.servicePlistPath, backup, constants.COPYFILE_EXCL); await chmod(backup, 0o600); }
    if (!(await exists(current))) await symlink(original.WorkingDirectory, current);
    for (const name of CONTROLLER_FILES) {
      const temporary = join(controller, `${name}.tmp-${process.pid}`);
      await copyFile(join(sourceDirectory, name), temporary); await chmod(temporary, 0o600);
      await rename(temporary, join(controller, name));
    }
    for (const filename of ['device-deploy.out.log', 'device-deploy.err.log']) {
      const path = join(config.runtimeDir, filename);
      await writeFile(path, '', { flag: 'a', mode: 0o600 }); await chmod(path, 0o600);
    }
    await writePlist(config.servicePlistPath, dashboard, config.pythonPath);
    const updaterPath = join(dirname(config.servicePlistPath), `${UPDATER_LABEL}.plist`);
    await writePlist(updaterPath, buildUpdaterPlist(config, configPath), config.pythonPath);
    if (!noStart) {
      execFileSync('/bin/launchctl', ['bootstrap', domain, updaterPath], { stdio: 'pipe', timeout: 15_000 });
    }
    return { updaterPath, controller, current: resolve(dirname(current), await readlink(current)), started: !noStart };
  } finally { await releaseLock(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2), index = args.indexOf('--config');
  try {
    if (index < 0 || !args[index + 1] || args.some((arg, i) => i !== index && i !== index + 1 && arg !== '--no-start')) {
      throw new Error('Usage: node scripts/install-device-deploy.mjs --config /absolute/config.json [--no-start]');
    }
    const result = await installDeviceDeploy({ configPath: args[index + 1], noStart: args.includes('--no-start') });
    console.log(JSON.stringify(result));
  } catch (error) { console.error(`Device deployment installation failed: ${error.message}`); process.exitCode = 1; }
}
