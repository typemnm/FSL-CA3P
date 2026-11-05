import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { treeDigest } from '../../packages/contracts/manifest.mjs';
import { deploymentStatus } from './deployment.mjs';
const root = fileURLToPath(new URL('../../', import.meta.url));
const run = promisify(execFile);
async function readJson(path, fallback = null) { try { return JSON.parse(await readFile(path, 'utf8')); } catch { return fallback; } }
// Asynchronous so a slow git (for example on WSL) never blocks other API requests.
async function git(...args) {
  try { return (await run('git', args, { cwd: root, encoding: 'utf8', timeout: 10_000, maxBuffer: 16 * 1024 * 1024 })).stdout.trim(); }
  catch { return null; }
}
const lines = value => (value ? value.split('\n').filter(Boolean) : []);
const within = (file, path) => file === path || file.startsWith(`${path.replace(/\/+$/u, '')}/`);

/** Repository and module state. Three repository-wide git calls are attributed to modules by path prefix. */
export async function computePlatformSnapshot() {
  const manifest = await readJson(resolve(root, 'integration-manifest.json'), { modules: [] });
  const tests = await readJson(resolve(root, 'reports/ci/latest.json'));
  const baseline = manifest.baselineSha ?? '0e850e0';
  const [committed, working, untracked, commitSha, branch, status] = await Promise.all([
    // --no-renames keeps a moved file's old path, as a per-module pathspec diff reports it;
    // core.quotepath=false returns non-ASCII names verbatim so they match module paths.
    git('-c', 'core.quotepath=false', 'diff', '--no-renames', '--name-only', baseline, 'HEAD'),
    git('-c', 'core.quotepath=false', 'diff', '--no-renames', '--name-only', 'HEAD'),
    git('-c', 'core.quotepath=false', 'ls-files', '--others', '--exclude-standard'), git('rev-parse', 'HEAD'), git('branch', '--show-current'),
    git('status', '--porcelain', '--untracked-files=no')]);
  const changed = [...new Set([...lines(committed), ...lines(working), ...lines(untracked)])];
  const modules = await Promise.all((manifest.modules ?? []).map(async item => {
    const path = item.path ?? item.id ?? item.name;
    const pkg = path ? await readJson(resolve(root, path, 'package.json')) : null;
    const changedFiles = path ? changed.filter(file => within(file, path)) : [];
    return { ...item, version: pkg?.version ?? null, packageVersion: pkg?.version ?? null,
      contentDigest: path && item.status !== 'replaced' ? treeDigest(resolve(root, path)) : null,
      changed: changedFiles.length > 0, changedFiles };
  }));
  return { source: { commitSha: process.env.CA3P_COMMIT_SHA ?? commitSha, branch, dirty: Boolean(status), baselineSha: baseline },
    modules, tests, integration: manifest };
}

/**
 * Cached platform provider: concurrent callers share one computation, a value
 * older than ttlMs is returned at once while a refresh runs in the background,
 * and deployment status is always read fresh.
 */
export function createPlatformProvider({ ttlMs = 60_000, compute = computePlatformSnapshot, deployment = deploymentStatus,
  now = Date.now } = {}) {
  let cached = null; let cachedAt = 0; let pending = null;
  function refresh() {
    pending ??= Promise.resolve().then(compute).then(value => { cached = value; cachedAt = now(); return value; })
      .finally(() => { pending = null; });
    return pending;
  }
  async function snapshot() {
    if (!cached) return refresh();
    if (now() - cachedAt >= ttlMs) refresh().catch(() => { /* Keep serving the last good snapshot. */ });
    return cached;
  }
  async function provider() {
    const [value, deploymentState] = await Promise.all([snapshot(), deployment()]);
    return { ...structuredClone(value), deployment: deploymentState,
      architecture: ['dashboard', 'api', 'application', 'worker', 'module-ports', 'sqlite-run-repository'],
      scope: '팀 내부 공유 · 격리된 실습 대상 및 승인된 외부 URL의 범위 제한 범용 점검',
      modelEvaluation: '제한된 행동 계획과 증거 기반 판정' };
  }
  provider.warm = () => refresh().catch(() => null);
  provider.invalidate = () => { cachedAt = 0; };
  return provider;
}

export const getPlatform = createPlatformProvider();
