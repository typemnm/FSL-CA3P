/** Fail-closed selection and independent, credential-free verification of a develop release. */
const DEFAULT_REPOSITORY = 'typemnm/FSL-CA3P';
const REQUIRED_JOBS = ['tests', 'container-smoke', 'integration-gate'];
const PIPELINE_KEYS = ['tests', 'containerSmoke', 'integrationGate'];
const INDEX_KEYS = ['schemaVersion', 'generatedAt', 'runs'];
const RUN_KEYS = ['runId', 'runAttempt', 'commitSha', 'branch', 'eventName', 'startedAt', 'completedAt',
  'status', 'completeSuite', 'tests', 'passed', 'failed', 'skipped', 'jobs', 'pipeline', 'runUrl',
  'changedFromSha', 'changedModules'];
const JOB_KEYS = ['id', 'status', 'tests', 'passed', 'failed', 'skipped'];
const COUNTS = ['tests', 'passed', 'failed', 'skipped'];
const OUTCOMES = new Set(['success', 'failure', 'cancelled', 'skipped', 'timed_out', 'unknown']);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const onlyKeys = (value, keys) => object(value) && Object.keys(value).every(key => keys.includes(key));
const sha = value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value) && value !== '0'.repeat(40);
const repositoryName = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(value);
const identifier = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value);
const apiIdentifier = value => typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? String(value) : null;
const attempt = value => Number.isSafeInteger(value) && value > 0;
const count = value => value === null || Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000;
const timestamp = value => value === null || typeof value === 'string'
  && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));
const moduleId = value => typeof value === 'string' && /^[a-z0-9-]{1,64}$/.test(value);
const pending = reason => ({ status: 'pending', reason });
const runUrl = (repository, id) => `https://github.com/${repository}/actions/runs/${id}`;

function validFeedRun(run, repository) {
  if (!onlyKeys(run, RUN_KEYS) || !identifier(run.runId) || !attempt(run.runAttempt) || !sha(run.commitSha)
    || run.branch !== 'develop' || run.eventName !== 'push'
    || !['passed', 'failed', 'incomplete'].includes(run.status) || typeof run.completeSuite !== 'boolean'
    || !timestamp(run.startedAt) || !timestamp(run.completedAt) || !COUNTS.every(key => count(run[key]))
    || run.runUrl !== runUrl(repository, run.runId) || !onlyKeys(run.pipeline, PIPELINE_KEYS)
    || !PIPELINE_KEYS.every(key => OUTCOMES.has(run.pipeline[key])) || !Array.isArray(run.jobs)
    || run.jobs.length > 50) return false;
  if ('changedFromSha' in run && run.changedFromSha !== null && !sha(run.changedFromSha)) return false;
  if ('changedModules' in run && run.changedModules !== null && (!Array.isArray(run.changedModules)
    || run.changedModules.length > 50 || !run.changedModules.every(moduleId)
    || new Set(run.changedModules).size !== run.changedModules.length)) return false;
  const jobs = new Set();
  for (const job of run.jobs) {
    if (!onlyKeys(job, JOB_KEYS) || !moduleId(job.id) || jobs.has(job.id)
      || !['passed', 'failed', 'unknown'].includes(job.status) || !COUNTS.every(key => count(job[key]))) return false;
    jobs.add(job.id);
  }
  return true;
}

/** A failure or incomplete newer attempt always supersedes an earlier success at this exact HEAD. */
export function selectVerifiedRelease({ headSha, index, repository = DEFAULT_REPOSITORY } = {}) {
  if (!sha(headSha) || !repositoryName(repository)) return pending('Invalid develop HEAD or repository.');
  if (!onlyKeys(index, INDEX_KEYS) || index.schemaVersion !== '1.0' || !timestamp(index.generatedAt)
    || typeof index.generatedAt !== 'string' || !Array.isArray(index.runs) || index.runs.length > 50) {
    return pending('Invalid counts-only CI index.');
  }
  const seen = new Set(); const commits = new Map();
  for (const run of index.runs) {
    if (!validFeedRun(run, repository)) return pending('Invalid counts-only CI run.');
    const key = `${run.runId}:${run.runAttempt}`;
    if (seen.has(key) || commits.has(run.runId) && commits.get(run.runId) !== run.commitSha) {
      return pending('Ambiguous CI run identity.');
    }
    seen.add(key); commits.set(run.runId, run.commitSha);
  }
  const matches = index.runs.filter(run => run.commitSha === headSha).sort((a, b) => {
    const left = BigInt(a.runId); const right = BigInt(b.runId);
    return left === right ? b.runAttempt - a.runAttempt : left > right ? -1 : 1;
  });
  const latest = matches[0];
  if (!latest) return pending('No CI summary for the current develop HEAD.');
  if (latest.status !== 'passed' || latest.completeSuite !== true || latest.tests <= 0
    || latest.passed !== latest.tests || latest.failed !== 0 || latest.skipped !== 0
    || !latest.completedAt || !PIPELINE_KEYS.every(key => latest.pipeline[key] === 'success')
    || latest.jobs.length === 0 || !latest.jobs.every(job => job.status === 'passed' && (
      ['boundaries', 'preflight'].includes(job.id) && COUNTS.every(key => job[key] === null)
      || job.tests > 0 && job.passed === job.tests && job.failed === 0 && job.skipped === 0))
    || latest.jobs.reduce((sum, job) => sum + (job.tests ?? 0), 0) !== latest.tests) {
    return pending('The latest CI run for develop HEAD has not passed the complete gate.');
  }
  return { status: 'verified', candidate: { sha: headSha, runId: latest.runId,
    runAttempt: latest.runAttempt, runUrl: latest.runUrl } };
}

async function readJson(fetchImpl, url, signal, maxBytes) {
  const response = await fetchImpl(url, { method: 'GET', redirect: 'error', credentials: 'omit',
    cache: 'no-store', signal, headers: { Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'CA3P-device-release-verifier' } });
  if (response.status !== 200 || response.redirected || response.url && response.url !== url) {
    throw new Error(`Workflow verification returned unexpected HTTP ${response.status} or redirect.`);
  }
  const declared = response.headers?.get('content-length');
  if (declared !== null && declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > maxBytes)) {
    throw new Error('Workflow API response exceeds the size limit.');
  }
  if (!response.body?.getReader) throw new Error('Workflow API response has no readable body.');
  const reader = response.body.getReader(); const chunks = []; let size = 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  try {
    while (true) {
      if (signal.aborted) throw new Error('Workflow verification timed out.');
      const next = await reader.read();
      if (signal.aborted) throw new Error('Workflow verification timed out.');
      if (next.done) break;
      size += next.value.byteLength;
      if (size > maxBytes) throw new Error('Workflow API response exceeds the size limit.');
      chunks.push(Buffer.from(next.value));
    }
    let value;
    try { value = JSON.parse(Buffer.concat(chunks, size).toString('utf8')); }
    catch { throw new Error('Workflow API returned invalid JSON.'); }
    if (!object(value)) throw new Error('Workflow API returned an invalid object.');
    return value;
  } finally {
    signal.removeEventListener('abort', cancel);
    await reader.cancel().catch(() => {});
  }
}

function assertRun(run, candidate, repository) {
  if (apiIdentifier(run.id) !== candidate.runId || run.run_attempt !== candidate.runAttempt
    || run.repository?.full_name !== repository || run.head_repository?.full_name !== repository
    || run.event !== 'push' || run.head_branch !== 'develop' || run.head_sha !== candidate.sha
    || run.path !== '.github/workflows/ci.yml' || run.html_url !== candidate.runUrl
    || run.status !== 'completed' || run.conclusion !== 'success') {
    throw new Error('GitHub workflow identity, current attempt, or successful develop gate does not match.');
  }
}

function assertLatestRun(listing, candidate, repository) {
  if (!Number.isSafeInteger(listing.total_count) || listing.total_count < 1 || !Array.isArray(listing.workflow_runs)
    || listing.workflow_runs.length < 1 || listing.workflow_runs.length > 10
    || listing.workflow_runs.length !== Math.min(listing.total_count, 10)) throw new Error('GitHub workflow listing is invalid or incomplete.');
  const ids = new Set();
  for (const run of listing.workflow_runs) {
    const id = apiIdentifier(run?.id);
    if (!id || ids.has(id) || !attempt(run.run_attempt) || run.event !== 'push' || run.head_branch !== 'develop'
      || run.head_sha !== candidate.sha || run.path !== '.github/workflows/ci.yml'
      || run.repository && run.repository.full_name !== repository
      || run.head_repository && run.head_repository.full_name !== repository) {
      throw new Error('GitHub workflow listing contains mismatched or ambiguous runs.');
    }
    ids.add(id);
  }
  const newest = listing.workflow_runs.reduce((latest, run) => BigInt(run.id) > BigInt(latest.id) ? run : latest);
  if (String(newest.id) !== candidate.runId || newest.run_attempt !== candidate.runAttempt
    || newest.status !== 'completed' || newest.conclusion !== 'success') {
    throw new Error('A newer or unsuccessful GitHub workflow run supersedes this CI summary.');
  }
}

/** Independently checks the current GitHub run attempt and every jobs page. Never accepts credentials. */
export async function verifyWorkflowRun(candidate, { fetchImpl = fetch, repository = DEFAULT_REPOSITORY,
  timeoutMs = 15_000, maxBytes = 512_000, maxPages = 10 } = {}) {
  if (!repositoryName(repository) || !object(candidate) || !sha(candidate.sha) || !identifier(candidate.runId)
    || !attempt(candidate.runAttempt) || candidate.runUrl !== runUrl(repository, candidate.runId)
    || typeof fetchImpl !== 'function' || !Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60_000
    || !Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > 2_000_000
    || !Number.isSafeInteger(maxPages) || maxPages <= 0 || maxPages > 10) throw new Error('Invalid release verification input.');
  const base = `https://api.github.com/repos/${repository}/actions/runs/${candidate.runId}`;
  const listingUrl = `https://api.github.com/repos/${repository}/actions/workflows/ci.yml/runs?branch=develop&event=push&head_sha=${candidate.sha}&per_page=10`;
  const controller = new AbortController(); let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => { controller.abort(); reject(new Error('Workflow verification timed out.')); }, timeoutMs);
  });
  try {
    return await Promise.race([timeout, (async () => {
      const get = url => readJson(fetchImpl, url, controller.signal, maxBytes);
      assertLatestRun(await get(listingUrl), candidate, repository);
      assertRun(await get(base), candidate, repository);
      const jobs = []; const ids = new Set(); let total = null;
      for (let page = 1; page <= maxPages; page++) {
        const listing = await get(`${base}/attempts/${candidate.runAttempt}/jobs?per_page=100&page=${page}`);
        if (!Number.isSafeInteger(listing.total_count) || listing.total_count < 1 || listing.total_count > maxPages * 100
          || !Array.isArray(listing.jobs) || listing.jobs.length > 100 || total !== null && listing.total_count !== total) {
          throw new Error('GitHub jobs pagination is invalid or incomplete.');
        }
        total = listing.total_count;
        for (const job of listing.jobs) {
          const id = apiIdentifier(job?.id);
          if (!id || ids.has(id) || apiIdentifier(job.run_id) !== candidate.runId
            || job.run_attempt !== candidate.runAttempt || job.head_sha !== candidate.sha || job.head_branch !== 'develop'
            || typeof job.name !== 'string' || job.name.length > 200) throw new Error('GitHub jobs contain duplicate or stale identities.');
          ids.add(id); jobs.push(job);
        }
        if (jobs.length > total || jobs.length < total && listing.jobs.length !== 100) {
          throw new Error('GitHub jobs pagination is invalid or incomplete.');
        }
        if (jobs.length === total) break;
      }
      if (jobs.length !== total) throw new Error('GitHub jobs pagination is incomplete.');
      for (const name of REQUIRED_JOBS) {
        const matches = jobs.filter(job => job.name === name);
        if (matches.length !== 1 || matches[0].status !== 'completed' || matches[0].conclusion !== 'success') {
          throw new Error(`GitHub required job ${name} is missing, duplicated, or unsuccessful.`);
        }
      }
      // A rerun may have begun while jobs were being read. Check the current attempt again.
      assertLatestRun(await get(listingUrl), candidate, repository);
      assertRun(await get(base), candidate, repository);
      return { sha: candidate.sha, runId: candidate.runId, runAttempt: candidate.runAttempt, runUrl: candidate.runUrl };
    })()]);
  } finally { clearTimeout(timer); controller.abort(); }
}
