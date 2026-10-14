import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { treeDigest } from '../../packages/contracts/manifest.mjs';
const root = fileURLToPath(new URL('../../', import.meta.url));
async function readJson(path, fallback = null) { try { return JSON.parse(await readFile(path, 'utf8')); } catch { return fallback; } }
function git(...args) { try { return execFileSync('git', args, { cwd: root, encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return null; } }
export async function getPlatform() {
  const manifest = await readJson(resolve(root, 'integration-manifest.json'), { modules: [] });
  const tests = await readJson(resolve(root, 'reports/ci/latest.json'));
  const modules = await Promise.all((manifest.modules ?? []).map(async item => {
    const path = item.path ?? item.id ?? item.name;
    const pkg = path ? await readJson(resolve(root, path, 'package.json')) : null;
    const baseline = manifest.baselineSha ?? '0e850e0';
    const committed = path ? git('diff', '--name-only', baseline, 'HEAD', '--', path) : null;
    const working = path ? git('diff', '--name-only', 'HEAD', '--', path) : null;
    const untracked = path ? git('ls-files', '--others', '--exclude-standard', '--', path) : null;
    const changedFiles = [...new Set([committed, working, untracked].filter(Boolean).flatMap(value => value.split('\n')))];
    return { ...item, version: pkg?.version ?? null, packageVersion: pkg?.version ?? null,
      contentDigest: path && item.status !== 'replaced' ? treeDigest(resolve(root, path)) : null,
      changed: changedFiles.length > 0, changedFiles };
  }));
  return { source: { commitSha: process.env.CA3P_COMMIT_SHA ?? git('rev-parse', 'HEAD'), branch: git('branch', '--show-current'),
    dirty: Boolean(git('status', '--porcelain', '--untracked-files=no')), baselineSha: manifest.baselineSha ?? '0e850e0' },
    modules, tests, integration: manifest,
    architecture: ['dashboard', 'api', 'application', 'worker', 'module-ports', 'sqlite-run-repository'],
    scope: '팀 내부 공유 · 격리된 실습 대상', modelEvaluation: '제한된 행동 계획과 증거 기반 판정' };
}
