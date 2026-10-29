import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, lstatSync, readlinkSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { DatabaseSync } from 'node:sqlite';
import { digest, redact, CONTRACT_VERSIONS } from './index.mjs';
import { GENERAL_LOOP_BUDGET_DEFAULTS, validateGeneralLoopBudget } from './general-loop-budget.mjs';

export const PROJECT_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const EXCLUDED = new Set(['node_modules', '.git', '.runtime', 'data', '__pycache__', '.pytest_cache', '.ruff_cache', '.venv', 'reports', '.env']);
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
function attackCatalogSnapshot(path) {
  if (!existsSync(path)) return null;
  let database;
  try {
    database = new DatabaseSync(path, { readOnly: true });
    const marker = database.prepare("SELECT value FROM attack_catalog_metadata WHERE key='schema'").get();
    if (marker?.value !== 'casper-attack-catalog-1') return null;
    return digest({
      patterns: database.prepare('SELECT pattern_id,revision,content_sha256 FROM attack_patterns ORDER BY pattern_id,revision').all(),
      templates: database.prepare('SELECT template_id,version,content_sha256 FROM attack_templates ORDER BY template_id,version').all(),
    });
  } catch { return null; }
  finally { database?.close(); }
}
export function createRunManifest({ runId, mode, modelId, options = {}, model = {}, env = process.env }) {
  if (mode === 'external-general') {
    const moduleNames = ['apps/application', 'apps/worker', 'packages/contracts', 'packages/run-store'];
    const modules = Object.fromEntries(moduleNames.map(name => [name,
      { contentDigest: treeDigest(join(PROJECT_ROOT, name)), packageVersion: null }]));
    return { schemaVersion: CONTRACT_VERSIONS.runManifest, runId, createdAt: new Date().toISOString(),
      source: { commitSha: git(['rev-parse', 'HEAD']), branch: git(['rev-parse', '--abbrev-ref', 'HEAD']),
        dirty: Boolean(git(['status', '--porcelain'])), baselineSha: null,
        ciWorkflowRunId: process.env.GITHUB_RUN_ID ?? null, ciAttempt: process.env.GITHUB_RUN_ATTEMPT ?? null },
      contracts: CONTRACT_VERSIONS, modules,
      shared: { contractDigest: treeDigest(join(PROJECT_ROOT, 'packages/contracts')),
        lockDigest: null, modelRegistryDigest: null },
      execution: { mode, simulated: false, maxIterations: 1, delayMs: 0,
        maxRequests: options.scope.maxRequests, maxDurationMs: options.scope.maxDurationMs,
        inspectionMode: 'external-read-only' },
      model: { id: modelId, provider: 'rules', requestedModel: null, reportedModel: null,
        snapshot: null, adapterDigest: null, promptTemplateDigest: null, settings: model.settings ?? {},
        actualPromptDigests: [], executionRole: 'not-used-read-only-observation' },
      data: { logicalInputDigest: digest({ mode, target: options.target, scope: options.scope }),
        datasetDigest: null, catalogDigest: null, caseSnapshotDigest: null, caseRevisions: [],
        unavailableInputs: ['casper-db', 'authenticated-sessions', 'independent-verifiers'] },
      target: { kind: 'external', fixtureId: null, entryUrl: redact(options.target),
        origin: options.scope.origin, scope: options.scope, initialStateDigest: null,
        stateCapture: 'external-live-state-not-snapshotted', testProfile: 'external-read-only' },
      policy: { rulesetDigest: treeDigest(join(PROJECT_ROOT, 'apps/application/external-target.mjs')),
        methods: ['GET', 'HEAD'], maxRequests: options.scope.maxRequests,
        maxResponseBytes: options.scope.maxResponseBytes, requestTimeoutMs: options.scope.requestTimeoutMs,
        maxDurationMs: options.scope.maxDurationMs,
        redirects: 'manual-no-follow', mutationRetry: 'never', targetReset: 'not-required-read-only',
        recovery: 'interrupted-new-run-required', maxIterations: 1 },
      environment: { nodeVersion: process.version, pythonVersion: 'not-applicable',
        browserVersion: 'not-applicable', playwrightVersion: 'not-applicable',
        runnerImageDigest: process.env.CA3P_RUNNER_IMAGE_DIGEST ?? null },
      provenance: 'captured-before-execution', missingValuesMean: 'unavailable' };
  }
  const fixtureId = options.fixtureId ?? 'vul-web-1';
  const general = mode === 'local-lab-general';
  const loopBudget = general ? validateGeneralLoopBudget(options.loopBudget ?? GENERAL_LOOP_BUDGET_DEFAULTS) : null;
  const universityOrigins = { 'vul-web2-daehan': 'http://127.0.0.1:4101', 'vul-web2-wonchang': 'http://127.0.0.1:4102' };
  const universityLab = mode !== 'core-fixture' && Object.hasOwn(universityOrigins, fixtureId);
  const fixedUniversityProbe = universityLab && !general;
  const universityOrigin = universityLab ? options.target ?? universityOrigins[fixtureId] : null;
  const testProfile = options.testProfile ?? (general ? 'general' : universityLab ? 'known_record_idor_read'
    : mode === 'core-fixture' ? 'agent_cross_user_delete_canary' : 'stored_xss_canary');
  const moduleNames = general
    ? ['agent', universityLab ? 'vul-web2' : 'vul-web-1', 'casper-db',
      'attack-module', 'guardrail', 'packages/models', 'packages/adapters', 'web-parser',
      'packages/report', 'packages/run-store', 'apps/application', 'apps/worker']
    : universityLab
    ? ['vul-web2', 'attack-module', 'guardrail', 'packages/adapters', 'packages/evaluation', 'apps/application', 'apps/worker']
    : ['agent', 'xss-parser', 'attack-module', 'guardrail', 'casper-db',
      'packages/adapters', 'packages/history', 'packages/evaluation', 'packages/report', 'apps/application', 'apps/worker'];
  const modules = Object.fromEntries(moduleNames
    .map(name => [name, { contentDigest: treeDigest(join(PROJECT_ROOT, name)),
      packageVersion: (() => { try { return JSON.parse(readFileSync(join(PROJECT_ROOT, name, 'package.json'), 'utf8')).version; } catch { return null; } })() }]));
  const requestedModel = modelId === 'rule-baseline' ? null : modelId;
  return { schemaVersion: CONTRACT_VERSIONS.runManifest, runId, createdAt: new Date().toISOString(),
    source: { commitSha: git(['rev-parse', 'HEAD']), branch: git(['rev-parse', '--abbrev-ref', 'HEAD']),
      dirty: Boolean(git(['status', '--porcelain'])), baselineSha: null,
      ciWorkflowRunId: process.env.GITHUB_RUN_ID ?? null, ciAttempt: process.env.GITHUB_RUN_ATTEMPT ?? null },
    contracts: CONTRACT_VERSIONS, modules,
    shared: { contractDigest: treeDigest(join(PROJECT_ROOT, 'packages/contracts')),
      lockDigest: universityLab || general ? null : treeDigest(join(PROJECT_ROOT, 'xss-parser/package-lock.json')),
      modelRegistryDigest: fixedUniversityProbe ? null : treeDigest(join(PROJECT_ROOT, 'packages/models')) },
    execution: { mode, simulated: mode === 'core-fixture', maxIterations: loopBudget?.maxIterations ?? 1,
      ...(general ? { loopBudget } : {}), delayMs: options.delayMs ?? 0 },
    model: { id: modelId, provider: model.provider ?? (requestedModel ? 'deepseek' : 'rules'), requestedModel,
      reportedModel: null, snapshot: null, adapterDigest: fixedUniversityProbe ? null : treeDigest(join(PROJECT_ROOT, 'packages/models')),
      promptTemplateDigest: general ? treeDigest(join(PROJECT_ROOT, 'agent/src/general-model-planner.js'))
        : fixedUniversityProbe ? null : treeDigest(join(PROJECT_ROOT, 'agent/src/deepseek-reasoning-engine.js')),
      ...(fixedUniversityProbe ? { executionRole: 'not-used-fixed-probe' } : {}),
      settings: model.settings ?? {}, actualPromptDigests: [] },
    data: { logicalInputDigest: digest({ mode, fixtureId, testProfile,
      ...(general ? { loopBudget } : {}), ...(universityLab ? { origin: universityOrigin } : {}) }),
      datasetDigest: treeDigest(join(PROJECT_ROOT, universityLab ? 'vul-web2'
        : mode === 'core-fixture' ? 'apps/application/scripted-gateway.cjs' : 'vul-web-1')),
      catalogDigest: general ? (options.caseSnapshot?.path ? attackCatalogSnapshot(options.caseSnapshot.path) : null)
        : universityLab ? null : mode === 'core-fixture'
        ? treeDigest(join(PROJECT_ROOT, 'apps/application/scripted-gateway.cjs'))
        : attackCatalogSnapshot(options.caseSnapshot?.path ?? env.CASPER_DB_PATH ?? join(PROJECT_ROOT, 'casper-db/data/cases.sqlite3')),
      catalogSeedDigest: fixedUniversityProbe ? null : treeDigest(join(PROJECT_ROOT, 'casper-db/src/casper_db/catalog_seed')),
      caseSnapshotDigest: general ? options.caseSnapshot?.contentDigest ?? null
        : universityLab ? null : mode === 'core-fixture' ? treeDigest(join(PROJECT_ROOT, 'apps/application/scripted-gateway.cjs'))
        : treeDigest(process.env.CASPER_DB_PATH ?? join(PROJECT_ROOT, 'casper-db/data/cases.sqlite3')),
      caseRevisions: [], ...(options.unavailableInputs ? { unavailableInputs: options.unavailableInputs } : {}) },
    target: { fixtureId: mode === 'core-fixture' ? 'scripted-contract-fixture' : fixtureId,
      imageDigest: process.env.CA3P_FIXTURE_IMAGE_DIGEST ?? null,
      initialStateDigest: universityLab ? null : treeDigest(join(PROJECT_ROOT, 'vul-web-1/server.js')),
      ...(universityLab ? { origin: universityOrigin, stateCapture: 'running-fixture-not-snapshotted' } : {}),
      testProfile },
    policy: { rulesetDigest: general && !universityLab ? null : treeDigest(join(PROJECT_ROOT, 'guardrail/rules')),
      mutationRetry: 'never', recovery: 'interrupted-new-run-required', maxIterations: loopBudget?.maxIterations ?? 1 },
    environment: { nodeVersion: process.version,
      pythonVersion: mode === 'core-fixture' || fixedUniversityProbe ? 'not-applicable' : runtimeVersion(env.CASPER_DB_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3'), ['--version']),
      browserVersion: mode === 'core-fixture' || universityLab || general ? 'not-applicable' : (() => {
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
      playwrightVersion: universityLab || general ? 'not-applicable' : (() => { try { return JSON.parse(readFileSync(join(PROJECT_ROOT, 'xss-parser/node_modules/playwright/package.json'), 'utf8')).version; } catch { return null; } })(),
      runnerImageDigest: process.env.CA3P_RUNNER_IMAGE_DIGEST ?? null },
    provenance: 'captured-before-execution', missingValuesMean: 'unavailable' };
}
