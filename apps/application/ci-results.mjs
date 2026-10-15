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
const sha = value => typeof value === 'string' && /^[a-f0-9]{40}$/i.test(value) ? value.toLowerCase() : null;
const count = value => Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000 ? value : null;
const timestamp = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null;
const runNumber = value => {
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
  const completeSuite = value.completeSuite === true;
  const failed = count(value.failed); const skipped = count(value.skipped);
  const verified = value.status === 'passed' && completeSuite && failed === 0 && skipped === 0 &&
    Object.values(pipeline).every(status => status === 'success');
  const status = verified ? 'passed' : value.status === 'failed' ? 'failed'
    : value.status === 'running' ? 'running' : 'incomplete';
  return { runId, runAttempt, commitSha, branch: 'develop', eventName: 'push', status,
    startedAt: timestamp(value.startedAt), completedAt: timestamp(value.completedAt),
    runUrl: `https://github.com/${REPOSITORY}/actions/runs/${runId}`,
    completeSuite, tests: count(value.tests), passed: count(value.passed), failed, skipped,
    jobs, changedModules, pipeline };
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

async function fetchJson(fetchImpl, url) {
  const response = await fetchImpl(url, { headers: { Accept: 'application/json', 'User-Agent': 'CA3P-dashboard-ci-reader',
    'Cache-Control': 'no-cache' }, signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`CI source returned HTTP ${response.status}.`);
  const body = await response.text();
  if (body.length > 512_000) throw new Error('CI result exceeds the size limit.');
  return JSON.parse(body);
}

async function fetchActionsFallback(fetchImpl) {
  const listing = await fetchJson(fetchImpl, RUNS_URL);
  const candidates = (Array.isArray(listing.workflow_runs) ? listing.workflow_runs : [])
    .filter(run => run.event === 'push' && run.head_branch === 'develop' && sha(run.head_sha) && runNumber(run.id))
    .slice(0, 2);
  const runs = await Promise.all(candidates.map(async run => {
    const jobs = await fetchJson(fetchImpl, `https://api.github.com/repos/${REPOSITORY}/actions/runs/${run.id}/jobs?per_page=100`);
    const byName = new Map((Array.isArray(jobs.jobs) ? jobs.jobs : []).map(job => [job.name, job.conclusion || job.status]));
    const pipeline = { tests: byName.get('tests') || 'unknown', containerSmoke: byName.get('container-smoke') || 'unknown',
      integrationGate: byName.get('integration-gate') || 'unknown' };
    return sanitizeRun({ runId: run.id, runAttempt: run.run_attempt ?? 1, commitSha: run.head_sha,
      branch: 'develop', eventName: 'push', status: run.status === 'completed'
        ? run.conclusion === 'success' ? 'incomplete' : 'failed' : 'running',
      startedAt: run.run_started_at || run.created_at, completedAt: run.status === 'completed' ? run.updated_at : null,
      completeSuite: false, pipeline, jobs: [] });
  }));
  return runs.filter(Boolean);
}

/** Pulls a public, data-minimized develop result feed. No GitHub token enters the dashboard. */
export function createCiResultsService({ cachePath = DEFAULT_CACHE, fetchImpl = fetch, intervalMs = 300_000,
  autoStart = true, now = () => new Date().toISOString() } = {}) {
  let snapshot = { source: 'none', status: 'loading', updatedAt: null, lastAttemptAt: null, runs: [] };
  try {
    const cached = JSON.parse(readFileSync(cachePath, 'utf8'));
    if (['public-feed', 'actions-api'].includes(cached.source) && Array.isArray(cached.runs)) {
      snapshot = { source: cached.source, status: 'cached', updatedAt: timestamp(cached.updatedAt),
        lastAttemptAt: null, runs: sanitizeCiFeed({ schemaVersion: '1.0', runs: cached.runs }) };
    }
  } catch { /* A corrupt or absent cache never becomes a displayed result. */ }
  let timer = null; let pending = null; let closed = false;
  async function sync() {
    if (closed) return snapshot;
    if (pending) return pending;
    pending = (async () => {
      const attemptedAt = now();
      try {
        let source = 'public-feed'; let runs;
        try {
          runs = sanitizeCiFeed(await fetchJson(fetchImpl, FEED_URL));
        } catch {
          source = 'actions-api'; runs = await fetchActionsFallback(fetchImpl);
        }
        const next = { source, status: 'fresh', updatedAt: now(), lastAttemptAt: attemptedAt, runs };
        await mkdir(dirname(cachePath), { recursive: true, mode: 0o700 });
        const temporary = `${cachePath}.${randomUUID()}.tmp`;
        await writeFile(temporary, JSON.stringify(next), { mode: 0o600, flag: 'wx' });
        await rename(temporary, cachePath);
        snapshot = next;
      } catch {
        snapshot = { ...snapshot, status: snapshot.runs.length ? 'stale' : 'unavailable', lastAttemptAt: attemptedAt };
      }
      return snapshot;
    })();
    try { return await pending; } finally { pending = null; }
  }
  if (autoStart) {
    void sync(); timer = setInterval(() => void sync(), intervalMs); timer.unref();
  }
  return { getSnapshot: () => structuredClone(snapshot), sync, close() { closed = true; clearInterval(timer); } };
}
