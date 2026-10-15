import { spawn } from 'node:child_process';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { resolve, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { parseTap, parseJUnit, suitePassed } from './ci-results.mjs';
import { createSuitePlan } from './ci-plan.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const reportDir = resolve(root, 'reports/ci');
const args = process.argv.slice(2);
const nodeOnly = args.includes('--node-only');
const skipPreflight = args.includes('--skip-preflight');
const selection = args.find(arg => arg.startsWith('--modules='))?.slice(10).split(',');
const dryRun = args.includes('--dry-run');
if (args.some(arg => !['--node-only', '--skip-preflight', '--dry-run'].includes(arg) && !arg.startsWith('--modules='))) throw new Error('Unknown CI option.');
const manifest = JSON.parse(await readFile(resolve(root, 'integration-manifest.json'), 'utf8'));
const { suites, problems, activeIds } = await createSuitePlan({ root, manifest, nodeOnly, selection });
if (dryRun) {
  console.log(JSON.stringify(suites.map(({ id, cwd, args }) => ({ id, cwd: relative(root, cwd), args })), null, 2));
  if (problems.length) { console.error(`CI suite discovery failed:\n${problems.join('\n')}`); process.exitCode = 1; }
  else process.exitCode = 0;
  process.exit();
}
await mkdir(reportDir, { recursive: true });
function execute(command, commandArgs, cwd, timeout = 300_000) {
  return new Promise(resolveResult => {
    const start = Date.now();
    let output = '';
    const child = spawn(command, commandArgs, { cwd, env: { ...process.env, CI: 'true', NO_COLOR: '1' }, shell: false, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
    let timedOut = false;
    let forceTimer;
    let settled = false;
    const finish = code => {
      if (settled) return;
      settled = true;
      clearTimeout(timer); clearTimeout(forceTimer);
      resolveResult({ exitCode: code ?? 1, durationMs: Date.now() - start, timedOut, output });
    };
    const stop = signal => {
      try { if (process.platform === 'win32') child.kill(signal); else if (child.pid) process.kill(-child.pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    };
    const timer = setTimeout(() => {
      timedOut = true; stop('SIGTERM');
      forceTimer = setTimeout(() => { stop('SIGKILL'); child.stdout.destroy(); child.stderr.destroy(); child.unref(); finish(1); }, 3000);
    }, timeout);
    const collect = chunk => { process.stdout.write(chunk); output += chunk.toString(); if (output.length > 4_000_000) output = output.slice(-4_000_000); };
    child.stdout.on('data', collect); child.stderr.on('data', collect);
    child.on('error', error => { output += `${error.message}\n`; });
    child.on('close', finish);
  });
}
const git = await execute('git', ['rev-parse', 'HEAD'], root, 10_000);
const branch = await execute('git', ['branch', '--show-current'], root, 10_000);
const worktree = await execute('git', ['status', '--porcelain'], root, 10_000);
const startedAt = new Date().toISOString();
const fullSuiteRequested = !nodeOnly && !selection && !skipPreflight;
const report = { schemaVersion: '1.0', id: randomUUID(), source: process.env.GITHUB_ACTIONS ? 'github-actions' : 'local', commitSha: git.exitCode === 0 ? git.output.trim() : null, branch: process.env.GITHUB_REF_NAME || branch.output.trim() || null, eventName: process.env.GITHUB_EVENT_NAME || null, testRef: process.env.GITHUB_REF || null, headBranch: process.env.GITHUB_HEAD_REF || null, baseBranch: process.env.GITHUB_BASE_REF || null, worktreeDirty: Boolean(worktree.output.trim()), nodeVersion: process.version, startedAt, completedAt: null, status: 'running', completeSuite: false, runUrl: process.env.GITHUB_RUN_ID && process.env.GITHUB_REPOSITORY ? `https://github.com/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}` : null, tests: 0, passed: 0, failed: 0, skipped: 0, jobs: [] };
async function saveReport() { const temp = join(reportDir, `.latest-${report.id}.tmp`); await writeFile(temp, JSON.stringify(report, null, 2)); await rename(temp, join(reportDir, 'latest.json')); }
await saveReport();
let prerequisites = problems.length === 0;
if (problems.length) {
  report.jobs.push({ id: 'discovery', status: 'failed', exitCode: 1,
    error: problems.join('\n') });
  await saveReport();
}
for (const [id, file] of [['boundaries', 'check-boundaries.mjs'], ...(!skipPreflight ? [['preflight', 'preflight.mjs']] : [])]) {
  const result = await execute(process.execPath, [resolve(root, 'scripts', file)], root);
  await writeFile(join(reportDir, `${id}.log`), result.output);
  report.jobs.push({ id, status: result.exitCode === 0 ? 'passed' : 'failed', exitCode: result.exitCode, durationMs: result.durationMs, log: `${id}.log` });
  if (result.exitCode !== 0) prerequisites = false;
}
if (prerequisites) for (const suite of suites) {
  console.log(`\nRunning ${suite.id} tests`);
  const result = await execute(suite.command, suite.args, suite.cwd);
  await writeFile(join(reportDir, `${suite.id}.log`), result.output);
  let totals;
  if (suite.id === 'casper-db') {
    let xml = '';
    try { xml = await readFile(join(reportDir, 'casper-db.xml'), 'utf8'); } catch { /* pytest startup failure is reflected by exitCode. */ }
    totals = parseJUnit(xml);
  } else totals = parseTap(result.output);
  const passed = suitePassed(result.exitCode, totals);
  report.jobs.push({ id: suite.id, status: passed ? 'passed' : 'failed', exitCode: result.exitCode, durationMs: result.durationMs, timedOut: result.timedOut, ...totals, ...(result.timedOut ? { error: 'Test process timed out; counters may be incomplete.' } : {}), log: `${suite.id}.log` });
  for (const key of ['tests', 'passed', 'failed', 'skipped']) report[key] += totals[key];
  await saveReport();
}
report.completedAt = new Date().toISOString();
report.completeSuite = fullSuiteRequested && prerequisites && activeIds.length > 0
  && activeIds.every(id => suites.some(suite => suite.id === id)
    && report.jobs.some(job => job.id === id));
report.status = prerequisites && report.jobs.every(job => job.status === 'passed')
  && suites.length > 0 && (!fullSuiteRequested || report.completeSuite) ? 'passed' : 'failed';
report.failedJobs = report.jobs.filter(job => job.status === 'failed').length;
await saveReport();
console.log(`\nCI ${report.status}: ${report.passed} passed, ${report.failed} failed tests, ${report.skipped} skipped, ${report.failedJobs} failed jobs. Report: reports/ci/latest.json`);
if (report.status !== 'passed') process.exitCode = 1;
