import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
if (Number(process.versions.node.split('.')[0]) !== 24) throw new Error(`Node.js 24 is required; found ${process.version}. Run nvm use.`);
const python = process.env.CASPER_DB_PYTHON || 'python3';
for (const [command, args] of [
  [python, ['-c', 'import sys, pydantic, fastapi, pytest, httpx; assert sys.version_info >= (3, 11); print("Python and casper-db test dependencies ready")']],
  ['curl', ['--version']],
]) {
  const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', timeout: 30_000 });
  if (result.error || result.status !== 0) throw new Error(`${command} preflight failed: ${result.error?.message || result.stderr}`);
  console.log(result.stdout.split('\n')[0]);
}
const parserRequire = createRequire(new URL('../xss-parser/package.json', import.meta.url));
const { chromium } = parserRequire('playwright');
const browser = await chromium.launch({ headless: true, ...(process.env.XSS_PARSER_BROWSER_PATH ? { executablePath: process.env.XSS_PARSER_BROWSER_PATH } : {}) });
try { console.log(`Chromium ready: ${browser.version()}`); } finally { await browser.close(); }
