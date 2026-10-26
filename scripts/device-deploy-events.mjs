import { randomUUID } from 'node:crypto';

export const DEPLOYMENT_EVENT_STATUSES = Object.freeze(['checking', 'waiting-ci', 'up-to-date', 'verified',
  'preparing', 'prepared', 'deferred', 'superseded', 'deploying', 'deployed', 'blocked', 'failed', 'recovery-required']);
export const DEPLOYMENT_EVENT_PHASES = Object.freeze(['ci-verification', 'dependencies', 'isolated-smoke', 'fixtures', 'backup-and-migrate']);
export const DEPLOYMENT_REASON_CODES = Object.freeze(['develop-check', 'ci-summary-pending', 'ci-running',
  'github-rate-limit', 'current-release', 'ci-verified', 'retry-backoff', 'failed-release', 'active-run',
  'preparing-release', 'release-prepared', 'newer-release', 'deploying-release', 'deployment-complete',
  'deployment-failed', 'rollback-complete', 'recovery-required']);

const DEFAULT_REASON = { checking: 'develop-check', 'waiting-ci': 'ci-summary-pending', 'up-to-date': 'current-release',
  verified: 'ci-verified', preparing: 'preparing-release', prepared: 'release-prepared', deferred: 'active-run',
  superseded: 'newer-release', deploying: 'deploying-release', deployed: 'deployment-complete', blocked: 'failed-release',
  failed: 'deployment-failed', 'recovery-required': 'recovery-required' };
const timestamp = value => typeof value === 'string'
  && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
  && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null;
const sha = value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value) && value !== '0'.repeat(40) ? value : null;
const runId = value => typeof value === 'string' && /^[1-9]\d{0,19}$/.test(value) ? value
  : Number.isSafeInteger(value) && value > 0 ? String(value) : null;
const identifier = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);

function fields(value) {
  if (!value || !DEPLOYMENT_EVENT_STATUSES.includes(value.status)) return null;
  return { status: value.status, phase: DEPLOYMENT_EVENT_PHASES.includes(value.phase) ? value.phase : null,
    targetSha: sha(value.targetSha), deployedSha: sha(value.deployedSha), previousSha: sha(value.previousSha),
    runId: runId(value.runId), reasonCode: DEPLOYMENT_REASON_CODES.includes(value.reasonCode)
      ? value.reasonCode : DEFAULT_REASON[value.status], retryAt: timestamp(value.retryAt) };
}

/** Public history is an allowlist, never a copy of private errors, paths or messages. */
export function sanitizeDeploymentEvents(value) {
  const result = []; const ids = new Set();
  for (const candidate of Array.isArray(value) ? value.slice(-100) : []) {
    const entry = fields(candidate); const at = timestamp(candidate?.at);
    if (!entry || !at || !identifier(candidate.id) || ids.has(candidate.id)) continue;
    ids.add(candidate.id); result.push({ id: candidate.id, at, ...entry });
  }
  return result;
}

/** A recurring check updates status.json but emits only meaningful transitions. */
export function appendDeploymentEvent(previous, next, { at = next.updatedAt, idFactory = randomUUID } = {}) {
  const events = sanitizeDeploymentEvents(previous?.events);
  const entry = fields(next); const time = timestamp(at);
  if (!entry || !time) return events;
  const latest = events.at(-1);
  // Every updater invocation briefly checks the same HEAD. Do not turn that
  // heartbeat into a checking/up-to-date (or checking/waiting) notification pair.
  if (entry.status === 'checking' && latest && latest.targetSha === entry.targetSha
    && latest.deployedSha === entry.deployedSha) return events;
  if (latest && JSON.stringify(fields(latest)) === JSON.stringify(entry)) return events;
  const id = idFactory();
  if (!identifier(id)) throw new Error('Deployment event ID is invalid.');
  return [...events, { id, at: time, ...entry }].slice(-100);
}
