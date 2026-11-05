import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { run } from './repeater.mjs';

const vulnType = process.argv[2] ?? 'idor';
const serverPath = fileURLToPath(new URL('../server.js', import.meta.url));
const port = 4100 + Math.floor(Math.random() * 400);
const origin = `http://127.0.0.1:${port}`;
const dataDir = mkdtempSync(join(tmpdir(), 'vulweb1-repeater-'));
const dataFile = join(dataDir, 'posts.json');

async function waitForServer() {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try { const response = await fetch(`${origin}/api/posts`); if (response.ok) return; } catch {}
    await sleep(100);
  }
  throw new Error('lab server did not start');
}

const child = spawn(process.execPath, [serverPath], {
  env: { ...process.env, HOST: '127.0.0.1', PORT: String(port), BOARD_DATA_FILE: dataFile },
  stdio: 'ignore',
});

try {
  await waitForServer();
  const report = await run({ origin, vulnType, application: process.env.REPEATER_APPLICATION });
  console.log(JSON.stringify(report, null, 2));
  process.exitCode = report.finding.status === 'confirmed' ? 0 : 1;
} catch (error) {
  console.error(JSON.stringify({ error: 'REPEATER_RUNNER_FAILED', reason: error?.message ?? 'unknown' }));
  process.exitCode = 1;
} finally {
  child.kill('SIGKILL');
  rmSync(dataDir, { recursive: true, force: true });
}
