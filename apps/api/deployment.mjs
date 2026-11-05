import { readFile, access } from 'node:fs/promises';

export async function deploymentPaused(path = process.env.DASHBOARD_DEPLOYMENT_LOCK_FILE) {
  if (!path) return false;
  try { await access(path); return true; }
  catch (error) { if (error.code === 'ENOENT') return false; throw new Error('Deployment maintenance state is unavailable.'); }
}

export async function deploymentStatus(path = process.env.DASHBOARD_DEPLOYMENT_STATUS_FILE) {
  if (!path) return { enabled: false };
  try {
    const value = JSON.parse(await readFile(path, 'utf8'));
    const sha = key => /^[a-f0-9]{40}$/.test(value[key] ?? '') ? value[key] : null;
    const date = key => typeof value[key] === 'string' && Number.isFinite(Date.parse(value[key])) ? value[key] : null;
    const states = ['checking', 'waiting-ci', 'up-to-date', 'verified', 'preparing', 'prepared', 'deferred', 'superseded', 'deploying', 'deployed', 'blocked', 'failed', 'recovery-required'];
    return { enabled: true, status: states.includes(value.status) ? value.status : 'unknown',
      deployedSha: sha('deployedSha'), targetSha: sha('targetSha'), previousSha: sha('previousSha'),
      checkedAt: date('checkedAt'), deployedAt: date('deployedAt'), updatedAt: date('updatedAt'), retryAt: date('retryAt'),
      phase: ['ci-verification', 'dependencies', 'isolated-smoke', 'fixtures', 'backup-and-migrate'].includes(value.phase) ? value.phase : null,
      runUrl: /^\d+$/.test(String(value.runId ?? '')) ? `https://github.com/typemnm/FSL-CA3P/actions/runs/${value.runId}` : null };
  } catch { return { enabled: true, status: 'unavailable' }; }
}
