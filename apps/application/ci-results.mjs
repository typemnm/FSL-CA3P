import { readFileSync } from 'node:fs';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

const REPOSITORY = 'typemnm/FSL-CA3P';
const FEED_URL = `https://raw.githubusercontent.com/${REPOSITORY}/ci-results/index.json`;
const RUNS_URL = `https://api.github.com/repos/${REPOSITORY}/actions/workflows/ci.yml/runs?branch=develop&event=push&per_page=10`;
const DEFAULT_CACHE = resolve(fileURLToPath(new URL('../../.runtime/ci-results/index.json', import.meta.url)));
const JOB_STATUS = new Set(['passed', 'failed', 'success', 'failure', 'cancelled', 'skipped', 'timed_out', 'in_progress', 'queued', 'unknown']);
const PIPELINE_STATUS = new Set(['success', 'failure', 'cancelled', 'skipped', 'timed_out', 'in_progress', 'queued', 'unknown']);
const WORKFLOW_STATUS = new Set(['completed', 'queued', 'in_progress', 'waiting', 'pending', 'requested']);
const WORKFLOW_CONCLUSION = new Set(['success', 'failure', 'cancelled', 'timed_out', 'action_required', 'neutral', 'skipped', 'stale', 'startup_failure']);
const sha = value => typeof value === 'string' && /^[a-f0-9]{40}$/i.test(value) ? value.toLowerCase() : null;
const count = value => Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000 ? value : null;
const timestamp = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null;
const runNumber = value => {
  if (typeof value !== 'number' && !(typeof value === 'string' && /^[1-9]\d*$/.test(value))) return null;
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : null;
};
const normalizedStatus = (value, allowed) => allowed.has(value) ? value : 'unknown';

function sanitizeJob(value) {
  if (!value || typeof value !== 'object' || !/^[a-zA-Z0-9_-]{1,64}$/.test(value.id)) return null;
  return { id: value.id, status: normalizedStatus(value.status, JOB_STATUS), tests: count(value.tests),
    passed: count(value.passed), failed: count(value.failed), skipped: count(value.skipped) };
}

function sanitizeRun(value) {
  if (!value || typeof value !== 'object') return null;
  const runId = runNumber(value.runId);
  const commitSha = sha(value.commitSha);
  if (!runId || !commitSha || value.branch !== 'develop' || value.eventName !== 'push') return null;
  const runAttempt = runNumber(value.runAttempt ?? value.attempt ?? 1);
  if (!runAttempt) return null;
  const pipeline = Object.fromEntries(['tests', 'containerSmoke', 'integrationGate'].map(key =>
    [key, normalizedStatus(value.pipeline?.[key], PIPELINE_STATUS)]));
  const jobs = Array.isArray(value.jobs) ? value.jobs.slice(0, 50).map(sanitizeJob).filter(Boolean) : [];
  const changedModules = Array.isArray(value.changedModules) && value.changedModules.length <= 50 &&
    value.changedModules.every(name => typeof name === 'string' && /^[a-zA-Z0-9._/-]{1,100}$/.test(name))
    ? [...new Set(value.changedModules)] : null;
  const changedFromSha = sha(value.changedFromSha);
  const completeSuite = value.completeSuite === true;
  const failed = count(value.failed); const skipped = count(value.skipped);
  const tests = count(value.tests); const passed = count(value.passed);
  const verified = value.status === 'passed' && completeSuite && tests > 0 && passed === tests && failed === 0 && skipped === 0 &&
    Object.values(pipeline).every(status => status === 'success');
  const status = verified ? 'passed' : value.status === 'failed' ? 'failed'
    : value.status === 'running' ? 'running' : 'incomplete';
  return { runId, runAttempt, commitSha, branch: 'develop', eventName: 'push', status,
    createdAt: timestamp(value.createdAt), startedAt: timestamp(value.startedAt), completedAt: timestamp(value.completedAt),
    runUrl: `https://github.com/${REPOSITORY}/actions/runs/${runId}`,
    completeSuite, tests, passed, failed, skipped,
    jobs, changedFromSha, changedModules, pipeline,
    workflowStatus: WORKFLOW_STATUS.has(value.workflowStatus) ? value.workflowStatus : null,
    workflowConclusion: WORKFLOW_CONCLUSION.has(value.workflowConclusion) ? value.workflowConclusion : null };
}

export function sanitizeCiFeed(value) {
  if (!value || value.schemaVersion !== '1.0' || !Array.isArray(value.runs)) throw new Error('Unsupported CI result format.');
  const seen = new Set();
  const runs = [];
  for (const raw of value.runs.slice(0, 50)) {
    const run = sanitizeRun(raw);
    if (!run) continue;
    const key = `${run.runId}:${run.runAttempt}`;
    if (seen.has(key)) continue;
    seen.add(key); runs.push(run);
  }
  return runs.sort((a, b) => b.runId - a.runId || b.runAttempt - a.runAttempt);
}

function rateLimitRetryAt(headers) {
  const now = Date.now(); const times = [now + 300_000];
  const reset = headers?.get('x-ratelimit-reset');
  const after = headers?.get('retry-after');
  if (/^\d{1,13}$/.test(reset ?? '')) times.push(Number(reset) * 1000);
  if (/^\d{1,10}$/.test(after ?? '')) times.push(now + Number(after) * 1000);
  return new Date(Math.min(now + 7_200_000, Math.max(...times))).toISOString();
}

async function fetchJson(fetchImpl, url, { timeoutMs, signal }) {
  const controller = new AbortController(); let timer;
  const combined = AbortSignal.any([controller.signal, signal]);
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => { controller.abort(); reject(new Error('CI source timed out.')); }, timeoutMs);
  });
  const aborted = new Promise((_, reject) => {
    if (signal.aborted) reject(new Error('CI source closed.'));
    else signal.addEventListener('abort', () => reject(new Error('CI source closed.')), { once: true, signal: controller.signal });
  });
  try {
    return await Promise.race([timeout, aborted, (async () => {
      const response = await fetchImpl(url, { method: 'GET', redirect: 'error', credentials: 'omit', cache: 'no-store',
        headers: { Accept: 'application/json', 'User-Agent': 'CA3P-dashboard-ci-reader', 'Cache-Control': 'no-cache' }, signal: combined });
      if (response.redirected || response.url && response.url !== url) throw new Error('CI source redirected.');
      if (response.status === 429 || response.status === 403 && response.headers?.get('x-ratelimit-remaining') === '0') {
        throw Object.assign(new Error('CI source rate limited.'), { retryAt: rateLimitRetryAt(response.headers) });
      }
      if (response.status !== 200) throw new Error('CI source is unavailable.');
      const declared = response.headers?.get('content-length');
      if (declared !== null && declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > 512_000)) throw new Error('CI result exceeds the size limit.');
      if (!response.body?.getReader) throw new Error('CI source has no response body.');
      const reader = response.body.getReader(); const chunks = []; let bytes = 0;
      try {
        while (true) {
          const next = await reader.read();
          if (combined.aborted) throw new Error('CI source closed.');
          if (next.done) break;
          bytes += next.value.byteLength;
          if (bytes > 512_000) throw new Error('CI result exceeds the size limit.');
          chunks.push(Buffer.from(next.value));
        }
        return JSON.parse(Buffer.concat(chunks, bytes).toString('utf8'));
      } finally { void reader.cancel().catch(() => {}); }
    })()]);
  } finally { clearTimeout(timer); controller.abort(); }
}

function actionsRuns(listing) {
  if (!listing || !Array.isArray(listing.workflow_runs) || listing.workflow_runs.length > 10
    || !Number.isSafeInteger(listing.total_count) || listing.total_count < 0
    || listing.workflow_runs.length !== Math.min(listing.total_count, 10)) throw new Error('Invalid Actions listing.');
  const seen = new Set();
  return listing.workflow_runs.map(run => {
    const id = runNumber(run?.id); const attempt = runNumber(run?.run_attempt);
    if (!id || !attempt || !sha(run?.head_sha) || run.event !== 'push' || run.head_branch !== 'develop'
      || run.repository?.full_name !== REPOSITORY || run.head_repository?.full_name !== REPOSITORY
      || run.path !== '.github/workflows/ci.yml' || run.html_url !== `https://github.com/${REPOSITORY}/actions/runs/${id}`
      || !WORKFLOW_STATUS.has(run.status) || seen.has(id)
      || (run.status === 'completed' ? !WORKFLOW_CONCLUSION.has(run.conclusion) : run.conclusion !== null)) throw new Error('Mismatched Actions run.');
    seen.add(id);
    return sanitizeRun({ runId: id, runAttempt: attempt, commitSha: run.head_sha,
      branch: 'develop', eventName: 'push', status: run.status === 'completed'
        ? run.conclusion === 'success' || ['neutral', 'skipped'].includes(run.conclusion) ? 'incomplete' : 'failed' : 'running',
      createdAt: run.created_at, startedAt: run.run_started_at || run.created_at, completedAt: run.status === 'completed' ? run.updated_at : null,
      workflowStatus: run.status, workflowConclusion: run.conclusion, completeSuite: false, pipeline: {}, jobs: [] });
  }).sort((a, b) => b.runId - a.runId || b.runAttempt - a.runAttempt);
}

async function fallbackJobs(runs, fetchImpl, options) {
  const detailed = await Promise.all(runs.slice(0, 2).map(async run => {
    try {
      const listing = await fetchJson(fetchImpl, `https://api.github.com/repos/${REPOSITORY}/actions/runs/${run.runId}/attempts/${run.runAttempt}/jobs?per_page=100`, options);
      if (!Array.isArray(listing.jobs) || listing.jobs.length > 100) throw new Error('Invalid Actions jobs.');
      const byName = new Map();
      for (const job of listing.jobs) {
        if (runNumber(job.run_id) !== run.runId || runNumber(job.run_attempt) !== run.runAttempt
          || sha(job.head_sha) !== run.commitSha || job.head_branch !== 'develop' || byName.has(job.name)) throw new Error('Mismatched Actions job.');
        byName.set(job.name, job.conclusion || job.status);
      }
      return { ...run, pipeline: { tests: normalizedStatus(byName.get('tests'), PIPELINE_STATUS),
        containerSmoke: normalizedStatus(byName.get('container-smoke'), PIPELINE_STATUS),
        integrationGate: normalizedStatus(byName.get('integration-gate'), PIPELINE_STATUS) } };
    } catch { return run; }
  }));
  return [...detailed, ...runs.slice(2)];
}

const emptyLive = () => ({ status: 'loading', checkedAt: null, runId: null, runAttempt: null, commitSha: null,
  workflowStatus: null, workflowConclusion: null, runUrl: null, retryAt: null });
function liveSnapshot(run, checkedAt) {
  return { ...emptyLive(), status: 'fresh', checkedAt,
    ...(run ? { runId: run.runId, runAttempt: run.runAttempt, commitSha: run.commitSha,
      workflowStatus: run.workflowStatus, workflowConclusion: run.workflowConclusion, runUrl: run.runUrl } : {}) };
}
function mergeRuns(stored, live) {
  const rows = new Map(stored.map(run => [`${run.runId}:${run.runAttempt}`, run]));
  for (const run of live) {
    const key = `${run.runId}:${run.runAttempt}`; const previous = rows.get(key);
    // A completed-success workflow may use the exact attempt's verified counts.
    // New attempts and running/failed observations never inherit an old success.
    rows.set(key, previous?.status === 'passed' && previous.commitSha === run.commitSha && run.workflowStatus === 'completed' && run.workflowConclusion === 'success'
      ? { ...previous, workflowStatus: run.workflowStatus, workflowConclusion: run.workflowConclusion } : run);
  }
  return [...rows.values()].sort((a, b) => b.runId - a.runId || b.runAttempt - a.runAttempt).slice(0, 50);
}

/** Pulls a public, data-minimized develop result feed. No GitHub token enters the dashboard. */
export function createCiResultsService({ cachePath = DEFAULT_CACHE, fetchImpl = fetch, intervalMs = 300_000,
  autoStart = true, now = () => new Date().toISOString(), requestTimeoutMs = 10_000 } = {}) {
  if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 60_000) throw new Error('Invalid CI request timeout.');
  let snapshot = { source: 'none', status: 'loading', updatedAt: null, lastAttemptAt: null, runs: [], live: emptyLive() };
  try {
    const cached = JSON.parse(readFileSync(cachePath, 'utf8'));
    if (['public-feed', 'actions-api'].includes(cached.source) && Array.isArray(cached.runs)) {
      snapshot = { source: cached.source, status: 'cached', updatedAt: timestamp(cached.updatedAt),
        lastAttemptAt: null, runs: sanitizeCiFeed({ schemaVersion: '1.0', runs: cached.runs }),
        live: { ...emptyLive(), status: 'cached', checkedAt: timestamp(cached.live?.checkedAt), retryAt: timestamp(cached.live?.retryAt) } };
    }
  } catch { /* A corrupt or absent cache never becomes a displayed result. */ }
  let timer = null; let pending = null; let closed = false;
  const closing = new AbortController();
  async function sync() {
    if (closed) return snapshot;
    if (pending) return pending;
    pending = (async () => {
      const attemptedAt = now();
      try {
        const options = { timeoutMs: requestTimeoutMs, signal: closing.signal };
        let feed = null; let latest = null; let live = { ...snapshot.live, status: 'unavailable' };
        try { feed = sanitizeCiFeed(await fetchJson(fetchImpl, FEED_URL, options)); } catch { /* Keep the last feed on source failure. */ }
        if (!live.retryAt || Date.parse(live.retryAt) <= Date.now()) {
          try {
            const observed = actionsRuns(await fetchJson(fetchImpl, RUNS_URL, options));
            const known = snapshot.runs[0]; const newest = observed[0];
            if (known && (!newest || newest.runId < known.runId
              || newest.runId === known.runId && newest.runAttempt < known.runAttempt)) throw new Error('Actions listing regressed.');
            latest = observed;
            live = liveSnapshot(latest[0], now());
          } catch (error) { live = { ...live, retryAt: error.retryAt ?? null }; }
        }
        if (feed === null && latest === null) {
          snapshot = { ...snapshot, status: snapshot.runs.length ? 'stale' : 'unavailable', lastAttemptAt: attemptedAt, live };
          return snapshot;
        }
        if (feed === null) latest = await fallbackJobs(latest, fetchImpl, options);
        // A counts feed can lag a live observation, especially during reruns.
        // An API outage must not resurrect its older successful attempt.
        const runs = mergeRuns(feed ?? snapshot.runs, latest ?? snapshot.runs.filter(run => run.workflowStatus !== null));
        if (closed) return snapshot;
        const next = { source: feed === null ? 'actions-api' : 'public-feed', status: 'fresh', updatedAt: now(), lastAttemptAt: attemptedAt, runs, live };
        await mkdir(dirname(cachePath), { recursive: true, mode: 0o700 });
        const temporary = `${cachePath}.${randomUUID()}.tmp`;
        await writeFile(temporary, JSON.stringify(next), { mode: 0o600, flag: 'wx' });
        await rename(temporary, cachePath);
        snapshot = next;
      } catch {
        if (!closed) snapshot = { ...snapshot, status: snapshot.runs.length ? 'stale' : 'unavailable', lastAttemptAt: attemptedAt,
          live: { ...snapshot.live, status: 'unavailable' } };
      }
      return snapshot;
    })();
    try { return await pending; } finally { pending = null; }
  }
  if (autoStart) {
    void sync(); timer = setInterval(() => void sync(), intervalMs); timer.unref();
  }
  return { getSnapshot: () => structuredClone(snapshot), sync, close() { closed = true; closing.abort(); clearInterval(timer); } };
}
