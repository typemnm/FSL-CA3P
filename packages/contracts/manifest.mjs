import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, lstatSync, readlinkSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { digest, CONTRACT_VERSIONS } from './index.mjs';

export const PROJECT_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const EXCLUDED = new Set(['node_modules', '.git', '.runtime', 'data', '__pycache__', '.pytest_cache', '.venv', 'reports', '.env']);
export function treeDigest(path) {
  if (!existsSync(path)) return null;
  const entries = [];
  const walk = item => {
    const info = lstatSync(item);
    if (info.isSymbolicLink()) { entries.push([relative(path, item), digest(`symlink:${readlinkSync(item)}`)]); return; }
    if (info.isDirectory()) {
      for (const name of readdirSync(item).sort()) if (!EXCLUDED.has(name) && !name.endsWith('.egg-info') && !name.startsWith('.env.')) walk(join(item, name));
    } else if (info.isFile()) entries.push([relative(path, item), digest(readFileSync(item))]);
  };
  walk(path);
  return digest(entries);
}
function git(args) {
  try { return execFileSync('git', args, { cwd: PROJECT_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); }
  catch { return null; }
}
function runtimeVersion(command, args) {
  try { return execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000 }).trim(); }
  catch { return null; }
}
export function createRunManifest({ runId, mode, modelId, options = {}, model = {}, env = process.env }) {
  const modules = Object.fromEntries(['agent', 'xss-parser', 'attack-module', 'guardrail', 'casper-db', 'pentest-db',
    'packages/adapters', 'packages/history', 'packages/evaluation', 'packages/report', 'apps/application', 'apps/worker']
    .map(name => [name, { contentDigest: treeDigest(join(PROJECT_ROOT, name)),
      packageVersion: (() => { try { return JSON.parse(readFileSync(join(PROJECT_ROOT, name, 'package.json'), 'utf8')).version; } catch { return null; } })() }]));
  const requestedModel = modelId === 'rule-baseline' ? null : modelId;
  return { schemaVersion: CONTRACT_VERSIONS.runManifest, runId, createdAt: new Date().toISOString(),
    source: { commitSha: git(['rev-parse', 'HEAD']), branch: git(['rev-parse', '--abbrev-ref', 'HEAD']),
      dirty: Boolean(git(['status', '--porcelain'])), baselineSha: null,
      ciWorkflowRunId: process.env.GITHUB_RUN_ID ?? null, ciAttempt: process.env.GITHUB_RUN_ATTEMPT ?? null },
    contracts: CONTRACT_VERSIONS, modules,
    shared: { contractDigest: treeDigest(join(PROJECT_ROOT, 'packages/contracts')),
      lockDigest: treeDigest(join(PROJECT_ROOT, 'xss-parser/package-lock.json')),
      modelRegistryDigest: treeDigest(join(PROJECT_ROOT, 'packages/models')) },
    execution: { mode, simulated: mode === 'core-fixture', maxIterations: 1, delayMs: options.delayMs ?? 0 },
    model: { id: modelId, provider: model.provider ?? (requestedModel ? 'deepseek' : 'rules'), requestedModel,
      reportedModel: null, snapshot: null, adapterDigest: treeDigest(join(PROJECT_ROOT, 'packages/models')),
      promptTemplateDigest: treeDigest(join(PROJECT_ROOT, 'agent/src/deepseek-reasoning-engine.js')),
      settings: model.settings ?? {}, actualPromptDigests: [] },
    data: { logicalInputDigest: digest({ mode, fixtureId: 'vul-web-1', testProfile: options.testProfile ?? 'stored_xss_canary' }),
      datasetDigest: treeDigest(join(PROJECT_ROOT, mode === 'core-fixture' ? 'apps/application/scripted-gateway.cjs' : 'vul-web-1')),
      catalogDigest: treeDigest(join(PROJECT_ROOT, 'pentest-db/cases.json')),
      caseSnapshotDigest: mode === 'core-fixture' ? treeDigest(join(PROJECT_ROOT, 'apps/application/scripted-gateway.cjs'))
        : treeDigest(process.env.CASPER_DB_PATH ?? join(PROJECT_ROOT, 'casper-db/data/cases.sqlite3')),
      caseRevisions: [] },
    target: { fixtureId: mode === 'core-fixture' ? 'scripted-contract-fixture' : 'vul-web-1',
      imageDigest: process.env.CA3P_FIXTURE_IMAGE_DIGEST ?? null,
      initialStateDigest: treeDigest(join(PROJECT_ROOT, 'vul-web-1/server.js')),
      testProfile: options.testProfile ?? (mode === 'core-fixture' ? 'agent_cross_user_delete_canary' : 'stored_xss_canary') },
    policy: { rulesetDigest: treeDigest(join(PROJECT_ROOT, 'guardrail/rules')),
      mutationRetry: 'never', recovery: 'interrupted-new-run-required', maxIterations: 1 },
    environment: { nodeVersion: process.version,
      pythonVersion: mode === 'core-fixture' ? 'not-applicable' : runtimeVersion(env.CASPER_DB_PYTHON ?? 'python', ['--version']),
      browserVersion: mode === 'core-fixture' ? 'not-applicable' : (() => {
        try {
          const require = createRequire(new URL('../../xss-parser/package.json', import.meta.url));
          const path = env.XSS_PARSER_BROWSER_PATH ?? require('playwright').chromium.executablePath();
          // Windows Chromium is a GUI executable and does not print --version.
          // Read the installed binary's version resource for the same manifest.
          if (process.platform === 'win32') return execFileSync('powershell.exe', [
            '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
            '(Get-Item -LiteralPath $env:CA3P_BROWSER_EXECUTABLE).VersionInfo.ProductVersion',
          ], { env: { ...process.env, CA3P_BROWSER_EXECUTABLE: path }, encoding: 'utf8',
            windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000 }).trim() || null;
          return runtimeVersion(path, ['--version']);
        } catch { return null; }
      })(),
      playwrightVersion: (() => { try { return JSON.parse(readFileSync(join(PROJECT_ROOT, 'xss-parser/node_modules/playwright/package.json'), 'utf8')).version; } catch { return null; } })(),
      runnerImageDigest: process.env.CA3P_RUNNER_IMAGE_DIGEST ?? null },
    provenance: 'captured-before-execution', missingValuesMean: 'unavailable' };
}
