#!/usr/bin/env node

// Local development entry point for a Daehan lab whose full reset is supervised.
// The management token exists only in the two child processes for this session.
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const managementPort = Number(process.env.CA3P_DAEHAN_RESET_PORT ?? 54101);
if (!Number.isInteger(managementPort) || managementPort < 1 || managementPort > 65535 || [4101, 4174].includes(managementPort)) {
  throw new Error('CA3P_DAEHAN_RESET_PORT must be an unused TCP port.');
}
if (process.env.CA3P_EXPERIMENT_RESET_TARGETS) {
  throw new Error('Use the existing CA3P_EXPERIMENT_RESET_TARGETS configuration with the regular start command.');
}
if (process.env.NODE_ENV === 'test' || process.env.CA3P_TEST_DAEHAN_DB_PATH || process.env.CA3P_TEST_DAEHAN_PORT) {
  throw new Error('The managed local launcher does not accept Daehan test overrides.');
}

const token = randomBytes(48).toString('base64url');
const targetOrigin = 'http://127.0.0.1:4101';
const managementOrigin = `http://127.0.0.1:${managementPort}`;
const args = process.argv.slice(2);
const retryReset = args.includes('--retry-reset');
const dashboardArgs = args.filter(arg => arg !== '--retry-reset');

async function assertDashboardPortFree() {
  await new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', () => reject(new Error('Dashboard port 4174 is occupied or unavailable. Stop the existing server before retrying reset.')));
    probe.listen(4174, '127.0.0.1', () => probe.close(resolve));
  });
}

if (retryReset && dashboardArgs.length) throw new Error('--retry-reset uses the local dashboard port 4174 without extra options.');
if (retryReset) await assertDashboardPortFree();
const supervisor = spawn(process.execPath, [join(root, 'vul-web2/scripts/daehan-reset-supervisor.mjs')], {
  cwd: root,
  env: { ...process.env, CA3P_DAEHAN_RESET_TOKEN: token, CA3P_DAEHAN_RESET_PORT: String(managementPort) },
  stdio: ['inherit', 'inherit', 'inherit', 'ipc'],
  windowsHide: true,
});

async function waitForSupervisor() {
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error('Daehan reset supervisor did not become ready.')), 12_000);
    const onMessage = message => {
      if (message?.type === 'ca3p-daehan-supervisor-ready'
        && message.origin === managementOrigin && message.targetOrigin === targetOrigin) finish();
    };
    const onExit = () => finish(new Error('Daehan reset supervisor exited before readiness.'));
    const onError = () => finish(new Error('Daehan reset supervisor failed to start.'));
    function finish(error) {
      clearTimeout(timer);
      supervisor.off('message', onMessage);
      supervisor.off('exit', onExit);
      supervisor.off('error', onError);
      if (error) reject(error); else resolve();
    }
    supervisor.on('message', onMessage);
    supervisor.once('exit', onExit);
    supervisor.once('error', onError);
  });
  const response = await fetch(`${managementOrigin}/health`, { signal: AbortSignal.timeout(3000), cache: 'no-store' });
  const health = await response.json();
  if (!response.ok || health.status !== 'ready' || health.fixtureId !== 'vul-web2-daehan'
    || health.targetOrigin !== targetOrigin) throw new Error('Daehan reset supervisor health check failed.');
}

async function stopSupervisor() {
  if (supervisor.exitCode !== null || supervisor.signalCode !== null) return;
  const exited = new Promise(resolve => supervisor.once('exit', resolve));
  try { if (supervisor.connected) supervisor.send({ type: 'ca3p-daehan-supervisor-stop' }); }
  catch { /* The termination fallback below still runs. */ }
  if (await Promise.race([exited.then(() => true), new Promise(resolve => setTimeout(() => resolve(false), 5000))])) return;
  supervisor.kill('SIGTERM');
  await Promise.race([exited, new Promise(resolve => setTimeout(resolve, 3000))]);
}

let dashboard;
try {
  await waitForSupervisor();
  const resetTargets = { 'vul-web2-daehan': { origin: managementOrigin, targetOrigin, token } };
  const dashboardEnv = { ...process.env, CA3P_EXPERIMENT_RESET_TARGETS: JSON.stringify(resetTargets) };
  if (retryReset) {
    const { createRunService } = await import('../apps/application/run-service.mjs');
    const runtime = createRunService({ env: dashboardEnv });
    try {
      await runtime.resetExperiment({ confirmed: true });
      console.log('Full experiment reset completed; new runs are available.');
    } finally { await runtime.close(); }
  }
  dashboard = spawn(process.execPath, [join(root, 'start.mjs'), ...(dashboardArgs.length ? dashboardArgs : ['--port', '4174'])], {
    cwd: root,
    env: dashboardEnv,
    stdio: 'inherit',
    windowsHide: true,
  });
  console.log('Managed Daehan lab and CA3P dashboard are running.');
  const result = await new Promise(resolve => {
    dashboard.once('exit', code => resolve({ source: 'dashboard', code }));
    supervisor.once('exit', code => resolve({ source: 'supervisor', code }));
    process.once('SIGINT', () => resolve({ source: 'signal', code: 0 }));
    process.once('SIGTERM', () => resolve({ source: 'signal', code: 0 }));
  });
  if (result.source !== 'dashboard') dashboard.kill();
  if (result.source !== 'supervisor') await stopSupervisor();
  if (result.source !== 'signal') process.exitCode = result.source === 'dashboard' ? result.code ?? 1 : 1;
} catch (error) {
  dashboard?.kill();
  await stopSupervisor();
  console.error(`Managed Daehan start failed: ${error.message}`);
  process.exitCode = 1;
}
