import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
if (Number(process.versions.node.split('.')[0]) !== 24) throw new Error(`Node.js 24 is required; found ${process.version}. Run nvm use.`);
const python = process.env.CASPER_DB_PYTHON || 'python3';
const reportPython = process.env.CA3P_REPORT_PYTHON || python;
for (const [command, args] of [
  [python, ['-c', 'import sys, pydantic, fastapi, pytest, httpx; assert sys.version_info >= (3, 11); print("Python and casper-db test dependencies ready")']],
  [reportPython, ['-c', 'import sys, hwpx, ca3p_report, pytest; assert sys.version_info >= (3, 11); print("Python and HWPX report dependencies ready")']],
  ['curl', ['--version']],
]) {
  const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', timeout: 30_000 });
  if (result.error || result.status !== 0) throw new Error(`${command} preflight failed: ${result.error?.message || result.stderr}`);
  console.log(result.stdout.split('\n')[0]);
}
const parserRequire = createRequire(new URL('../web-parser/package.json', import.meta.url));
const { chromium } = parserRequire('playwright');
const captureRequire = createRequire(new URL('../packages/report/capture/package.json', import.meta.url));
const capturePlaywright = captureRequire('playwright');
if (parserRequire('playwright/package.json').version !== captureRequire('playwright/package.json').version) {
  throw new Error('web-parser and report capture must use the same pinned Playwright version.');
}
const browserPath = process.env.WEB_PARSER_BROWSER_PATH || process.env.XSS_PARSER_BROWSER_PATH;
const browser = await chromium.launch({ headless: true, ...(browserPath ? { executablePath: browserPath } : {}) });
try { console.log(`Chromium ready: ${browser.version()}`); } finally { await browser.close(); }
const captureBrowser = await capturePlaywright.chromium.launch({ headless: true });
try { console.log(`Report capture Chromium ready: ${captureBrowser.version()}`); } finally { await captureBrowser.close(); }
