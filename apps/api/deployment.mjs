import { readFile, access } from 'node:fs/promises';

const STATES = new Set(['checking', 'waiting-ci', 'up-to-date', 'verified', 'preparing', 'prepared', 'deferred', 'superseded', 'deploying', 'deployed', 'blocked', 'failed', 'recovery-required']);
const PHASES = new Set(['ci-verification', 'dependencies', 'isolated-smoke', 'fixtures', 'backup-and-migrate']);
const REASONS = new Set(['develop-check', 'ci-summary-pending', 'ci-running', 'github-rate-limit', 'current-release', 'ci-verified', 'retry-backoff', 'failed-release', 'active-run', 'preparing-release', 'release-prepared', 'newer-release', 'deploying-release', 'deployment-complete', 'deployment-failed', 'rollback-complete', 'recovery-required']);
const sha = value => /^[a-f0-9]{40}$/.test(value ?? '') ? value : null;
const date = value => typeof value === 'string'
  && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
  && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null;
const runUrl = value => /^\d{1,20}$/.test(String(value ?? '')) ? `https://github.com/typemnm/FSL-CA3P/actions/runs/${value}` : null;

function publicEvent(value) {
  if (!value || typeof value !== 'object' || typeof value.id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(value.id)
    || !STATES.has(value.status) || !date(value.at)) return null;
  return { id: value.id, at: date(value.at), status: value.status,
    phase: PHASES.has(value.phase) ? value.phase : null,
    targetSha: sha(value.targetSha), deployedSha: sha(value.deployedSha), previousSha: sha(value.previousSha),
    runUrl: runUrl(value.runId), reasonCode: REASONS.has(value.reasonCode) ? value.reasonCode : null,
    retryAt: date(value.retryAt) };
}

export async function deploymentPaused(path = process.env.DASHBOARD_DEPLOYMENT_LOCK_FILE) {
  if (!path) return false;
  try { await access(path); return true; }
  catch (error) { if (error.code === 'ENOENT') return false; throw new Error('Deployment maintenance state is unavailable.'); }
}

export async function deploymentStatus(path = process.env.DASHBOARD_DEPLOYMENT_STATUS_FILE) {
  if (!path) return { enabled: false };
  try {
    const value = JSON.parse(await readFile(path, 'utf8'));
    const seen = new Set();
    const events = (Array.isArray(value.events) ? value.events.slice(-100) : []).map(publicEvent)
      .filter(event => { if (!event || seen.has(event.id)) return false; seen.add(event.id); return true; });
    return { enabled: true, status: STATES.has(value.status) ? value.status : 'unknown',
      deployedSha: sha(value.deployedSha), targetSha: sha(value.targetSha), previousSha: sha(value.previousSha),
      checkedAt: date(value.checkedAt), deployedAt: date(value.deployedAt), updatedAt: date(value.updatedAt), retryAt: date(value.retryAt),
      phase: PHASES.has(value.phase) ? value.phase : null, runUrl: runUrl(value.runId),
      reasonCode: REASONS.has(value.reasonCode) ? value.reasonCode : null,
      historyAvailable: Array.isArray(value.events), events };
  } catch { return { enabled: true, status: 'unavailable' }; }
}
