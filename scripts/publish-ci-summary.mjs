import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const outcomes = new Set(['success', 'failure', 'cancelled', 'skipped', 'timed_out']);
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const outcome = value => outcomes.has(value) ? value : 'unknown';

export function summarizeReport(report, context) {
  const { sha, runId, runAttempt, repository, serverUrl, pipeline, now } = context;
  const valid = report?.schemaVersion === '1.0' && report.source === 'github-actions'
    && report.commitSha === sha && report.branch === 'develop' && Array.isArray(report.jobs);
  const result = valid ? report : null;
  const checks = {
    tests: outcome(pipeline.tests),
    containerSmoke: outcome(pipeline.containerSmoke),
    integrationGate: outcome(pipeline.integrationGate),
  };
  const failed = Object.values(checks).some(value => ['failure', 'cancelled', 'timed_out'].includes(value));
  const allSucceeded = Object.values(checks).every(value => value === 'success');
  const status = failed || result?.status === 'failed' ? 'failed'
    : allSucceeded && result?.status === 'passed' && result.completeSuite === true ? 'passed' : 'incomplete';
  return {
    runId: String(runId), runAttempt: count(Number(runAttempt)) || 1,
    commitSha: sha, branch: 'develop', eventName: 'push',
    startedAt: result?.startedAt ?? null, completedAt: result?.completedAt ?? now,
    status, completeSuite: result?.completeSuite === true,
    tests: count(result?.tests), passed: count(result?.passed),
    failed: count(result?.failed), skipped: count(result?.skipped),
    jobs: (result?.jobs ?? []).filter(job => /^[a-z0-9-]{1,64}$/.test(job?.id ?? ''))
      .map(job => ({ id: job.id, status: ['passed', 'failed'].includes(job.status) ? job.status : 'unknown',
        tests: count(job.tests), passed: count(job.passed), failed: count(job.failed), skipped: count(job.skipped) })),
    pipeline: checks,
    runUrl: `${serverUrl}/${repository}/actions/runs/${runId}`,
  };
}

export function mergeIndex(previous, summary, now) {
  const clean = item => {
    if (!/^\d{1,20}$/.test(String(item?.runId ?? '')) || !Number.isSafeInteger(item?.runAttempt)
      || !/^[a-f0-9]{40}$/.test(item?.commitSha ?? '')) return null;
    return {
      runId: String(item.runId), runAttempt: item.runAttempt, commitSha: item.commitSha,
      branch: 'develop', eventName: 'push',
      startedAt: typeof item.startedAt === 'string' ? item.startedAt : null,
      completedAt: typeof item.completedAt === 'string' ? item.completedAt : null,
      status: ['passed', 'failed', 'incomplete'].includes(item.status) ? item.status : 'incomplete',
      completeSuite: item.completeSuite === true,
      tests: count(item.tests), passed: count(item.passed), failed: count(item.failed), skipped: count(item.skipped),
      jobs: (Array.isArray(item.jobs) ? item.jobs : []).filter(job => /^[a-z0-9-]{1,64}$/.test(job?.id ?? ''))
        .slice(0, 40).map(job => ({ id: job.id, status: ['passed', 'failed'].includes(job.status) ? job.status : 'unknown',
          tests: count(job.tests), passed: count(job.passed), failed: count(job.failed), skipped: count(job.skipped) })),
      changedModules: item.changedModules === null ? null : (Array.isArray(item.changedModules)
        ? item.changedModules.filter(id => /^[a-z0-9-]{1,64}$/.test(id)).slice(0, 40) : null),
      pipeline: { tests: outcome(item.pipeline?.tests), containerSmoke: outcome(item.pipeline?.containerSmoke),
        integrationGate: outcome(item.pipeline?.integrationGate) },
      runUrl: typeof item.runUrl === 'string' && /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/actions\/runs\/\d+$/.test(item.runUrl)
        ? item.runUrl : null,
    };
  };
  const prior = Array.isArray(previous?.runs) ? previous.runs : [];
  const runs = [summary, ...prior].map(clean).filter(Boolean)
    .filter((item, position, all) => all.findIndex(other => other.runId === item.runId && other.runAttempt === item.runAttempt) === position)
    .sort((a, b) => {
      const aId = BigInt(a.runId), bId = BigInt(b.runId);
      return aId === bId ? b.runAttempt - a.runAttempt : aId > bId ? -1 : 1;
    }).slice(0, 50);
  return { schemaVersion: '1.0', generatedAt: now, runs };
}

export function changedModuleIds(currentManifest, previousManifest, changedFiles) {
  const current = new Map((currentManifest?.modules ?? []).map(item => [item.id, item]));
  const previous = new Map((previousManifest?.modules ?? []).map(item => [item.id, item]));
  return [...current.values()].filter(item => item.status === 'active' && (
    changedFiles.some(file => file === item.path || file.startsWith(`${item.path}/`))
    || (previousManifest && JSON.stringify(previous.get(item.id)) !== JSON.stringify(item))
  )).map(item => item.id);
}

async function changedModules(previousSha, currentSha) {
  if (!/^[a-f0-9]{40}$/.test(previousSha ?? '')) return null;
  try {
    const currentManifest = JSON.parse(await readFile(resolve(root, 'integration-manifest.json'), 'utf8'));
    const previousManifest = JSON.parse(execFileSync('git', ['show', `${previousSha}:integration-manifest.json`],
      { cwd: root, encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] }));
    const changedFiles = execFileSync('git', ['diff', '--name-only', previousSha, currentSha, '--'],
      { cwd: root, encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] }).trim().split('\n').filter(Boolean);
    return changedModuleIds(currentManifest, previousManifest, changedFiles);
  } catch { return null; }
}

export async function publish({ fetchImpl = fetch, reportPath = resolve('reports/ci/latest.json') } = {}) {
  const { GITHUB_TOKEN: token, GITHUB_REPOSITORY: repository, GITHUB_SHA: sha,
    GITHUB_RUN_ID: runId, GITHUB_RUN_ATTEMPT: runAttempt,
    GITHUB_EVENT_NAME: eventName, GITHUB_REF: ref } = process.env;
  if (eventName !== 'push' || ref !== 'refs/heads/develop') throw new Error('Only a trusted develop push may publish CI summaries.');
  if (!/^[a-f0-9]{40}$/.test(sha ?? '') || !/^\d+$/.test(runId ?? '')
    || !/^\d+$/.test(runAttempt ?? '') || !/^[\w.-]+\/[\w.-]+$/.test(repository ?? '') || !token) {
    throw new Error('Missing or invalid GitHub Actions publishing context.');
  }
  const now = new Date().toISOString();
  let report = null;
  try { report = JSON.parse(await readFile(reportPath, 'utf8')); }
  catch { /* A failed setup can leave no artifact; pipeline outcomes remain available. */ }
  const summary = summarizeReport(report, { sha, runId, runAttempt, repository,
    serverUrl: process.env.GITHUB_SERVER_URL || 'https://github.com', now,
    pipeline: { tests: process.env.CA3P_TEST_RESULT, containerSmoke: process.env.CA3P_CONTAINER_RESULT,
      integrationGate: process.env.CA3P_GATE_RESULT } });
  const base = `https://api.github.com/repos/${repository}`;
  async function api(method, path, data) {
    const response = await fetchImpl(`${base}${path}`, { method, headers: {
      Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'ca3p-ci-summary-publisher',
    }, body: data === undefined ? undefined : JSON.stringify(data) });
    if (![200, 201, 404, 409, 422].includes(response.status)) throw new Error(`GitHub API ${method} ${path} returned ${response.status}.`);
    return { status: response.status, data: response.status === 404 ? null : await response.json() };
  }
  for (let attempt = 0; attempt < 5; attempt++) {
    const refResult = await api('GET', '/git/ref/heads/ci-results');
    const head = refResult.status === 404 ? null : refResult.data?.object?.sha;
    if (refResult.status !== 404 && !/^[a-f0-9]{40}$/.test(head ?? '')) throw new Error('Invalid ci-results branch ref.');
    let previous = null;
    if (head) {
      const file = await api('GET', `/contents/index.json?ref=${head}`);
      if (file.status === 200) {
        if (file.data?.encoding !== 'base64' || typeof file.data.content !== 'string') throw new Error('Invalid CI index encoding.');
        previous = JSON.parse(Buffer.from(file.data.content, 'base64').toString('utf8'));
      }
    }
    const predecessor = (Array.isArray(previous?.runs) ? previous.runs : []).filter(item => /^\d+$/.test(String(item?.runId ?? ''))
      && BigInt(item.runId) < BigInt(runId) && /^[a-f0-9]{40}$/.test(item?.commitSha ?? ''))
      .sort((a, b) => BigInt(a.runId) === BigInt(b.runId) ? 0 : BigInt(a.runId) > BigInt(b.runId) ? -1 : 1)[0];
    summary.changedModules = await changedModules(predecessor?.commitSha ?? process.env.CA3P_BEFORE_SHA, sha);
    const index = mergeIndex(previous, summary, now);
    const tree = await api('POST', '/git/trees', { tree: [{ path: 'index.json', mode: '100644', type: 'blob', content: JSON.stringify(index, null, 2) + '\n' }] });
    if (tree.status !== 201) throw new Error(`Unable to create CI summary tree: ${tree.status}.`);
    const commit = await api('POST', '/git/commits', { message: `ci: record develop run ${runId} attempt ${runAttempt}`, tree: tree.data.sha, parents: head ? [head] : [] });
    if (commit.status !== 201) throw new Error(`Unable to create CI summary commit: ${commit.status}.`);
    const update = head
      ? await api('PATCH', '/git/refs/heads/ci-results', { sha: commit.data.sha, force: false })
      : await api('POST', '/git/refs', { ref: 'refs/heads/ci-results', sha: commit.data.sha });
    if ([200, 201].includes(update.status)) {
      process.stdout.write(`Published sanitized develop CI summary for ${sha} (run ${runId}).\n`);
      return;
    }
    if (![409, 422].includes(update.status)) throw new Error(`Unable to update ci-results branch: ${update.status}.`);
  }
  throw new Error('ci-results branch changed repeatedly; retry this workflow run.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await publish();
