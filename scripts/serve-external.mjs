import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, existsSync, appendFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createTunnelOriginDetector } from './tunnel-origin.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const runtimeDir = join(root, '.runtime');
mkdirSync(runtimeDir, { recursive: true, mode: 0o700 });
const port = Number(process.env.PORT ?? 4173);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT.');
const binary = process.env.CLOUDFLARED_BIN ?? join(runtimeDir, 'bin/cloudflared');
if (!existsSync(binary)) throw new Error('Install cloudflared and set CLOUDFLARED_BIN. See docs/DEVICE_DEPLOYMENT.md.');
const python = process.env.CASPER_DB_PYTHON ?? join(root, '.venv/bin/python');
let app; let stopping = false; let publicOrigin; let started = false;
const detectStdoutOrigin = createTunnelOriginDetector();
const detectStderrOrigin = createTunnelOriginDetector();
const tunnel = spawn(binary, ['tunnel', '--no-autoupdate', '--protocol', 'http2', '--url', `http://127.0.0.1:${port}`], {
  cwd: root, stdio: ['ignore', 'pipe', 'pipe'], env: process.env,
});
writeFileSync(join(runtimeDir, 'device-pids.json'), JSON.stringify({ supervisor: process.pid, tunnel: tunnel.pid, startedAt: new Date().toISOString() }), { mode: 0o600 });
const timeout = setTimeout(() => { console.error('Tunnel registration timed out.'); void stop(1); }, 60000);
function capture(chunk, detectOrigin) {
  const text = chunk.toString(); appendFileSync(join(runtimeDir, 'tunnel.log'), text, { mode: 0o600 });
  const origin = detectOrigin(text);
  if (!origin || started) return;
  started = true; publicOrigin = origin; clearTimeout(timeout);
  writeFileSync(join(runtimeDir, 'public-url.txt'), publicOrigin + '\n', { mode: 0o600 });
  app = spawn(process.execPath, [join(root, 'start.mjs')], { cwd: root,
    env: { ...process.env, PORT: String(port), DASHBOARD_HOST: '127.0.0.1', DASHBOARD_PUBLIC_ORIGIN: publicOrigin,
      ...(existsSync(python) ? { CASPER_DB_PYTHON: python } : {}) }, stdio: ['ignore', 'pipe', 'pipe'] });
  writeFileSync(join(runtimeDir, 'device-pids.json'), JSON.stringify({ supervisor: process.pid, tunnel: tunnel.pid, app: app.pid, publicOrigin, startedAt: new Date().toISOString() }), { mode: 0o600 });
  const log = data => { appendFileSync(join(runtimeDir, 'server.log'), data, { mode: 0o600 }); process.stdout.write(data); };
  app.stdout.on('data', log); app.stderr.on('data', log);
  app.once('error', error => { console.error(`Server process failed: ${error.code}`); void stop(1); });
  app.once('exit', code => { if (!stopping) { console.error(`Server exited (${code}).`); void stop(code ?? 1); } });
  console.log(`External dashboard: ${publicOrigin}\nLogin credentials: ${join(runtimeDir, 'access.txt')}\nThis URL remains active while this device and supervisor are running.`);
}
tunnel.stdout.on('data', chunk => capture(chunk, detectStdoutOrigin));
tunnel.stderr.on('data', chunk => capture(chunk, detectStderrOrigin));
tunnel.once('error', error => { console.error(`Tunnel failed: ${error.code}`); void stop(1); });
tunnel.once('exit', code => { if (!stopping) { console.error(`Tunnel exited (${code}).`); void stop(code ?? 1); } });
async function stop(code = 0) {
  if (stopping) return; stopping = true; clearTimeout(timeout);
  const children = [app, tunnel].filter(Boolean);
  await Promise.all(children.map(child => new Promise(resolveStop => {
    if (child.exitCode !== null || child.signalCode !== null) return resolveStop();
    child.once('exit', resolveStop); child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 10000); timer.unref();
  })));
  process.exitCode = code;
}
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void stop(); });
