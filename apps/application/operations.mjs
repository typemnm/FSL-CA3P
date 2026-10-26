import { execFileSync } from 'node:child_process';
import { PROJECT_ROOT } from '../../packages/contracts/manifest.mjs';

const SHA = /^[a-f0-9]{40}$/;
const sha = value => typeof value === 'string' && SHA.test(value) ? value : null;
const date = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null;
const canonicalRunUrl = value => {
  const match = /^https:\/\/github\.com\/typemnm\/FSL-CA3P\/actions\/runs\/(\d{1,20})$/.exec(value ?? '');
  return match ? match[0] : null;
};
const DEPLOYMENT_COPY = {
  checking: ['info', 'develop 변경 확인', 'Mac mini가 develop 최신 버전과 CI 결과를 확인하고 있습니다.'],
  'waiting-ci': ['info', 'CI 검증 대기', '전체 CI와 검증 요약이 준비될 때까지 적용을 기다립니다.'],
  'up-to-date': ['success', '최신 검증 버전 실행 중', '장치가 확인한 develop 버전과 적용 버전이 같습니다.'],
  verified: ['success', 'CI 배포 기준 확인 완료', '배포 기준을 통과했습니다. 실제 적용 완료와는 별도 단계입니다.'],
  preparing: ['info', '새 버전 준비 중', '의존성·격리 점검·대학 실습 이미지를 준비하고 있습니다.'],
  prepared: ['info', '새 버전 준비 완료', '사전 점검을 마쳤습니다. 실행 서비스에는 아직 적용하지 않았습니다.'],
  deferred: ['warning', '배포 전환 대기', '기존 작업 종료 또는 안전한 재시도 시점을 기다립니다.'],
  superseded: ['info', '더 최신 develop 발견', '준비 중 더 최신 버전이 도착해 최신 CI 확인으로 돌아갑니다.'],
  deploying: ['info', 'Mac mini 최신화 적용 중', '데이터를 백업하고 검증된 새 버전으로 전환하고 있습니다.'],
  deployed: ['success', 'Mac mini 최신화 완료', '새 버전 적용 후 인증 및 서비스 점검이 통과했습니다.'],
  blocked: ['error', '배포 재시도에 운영자 확인 필요', '이 버전의 이전 적용이 실패했습니다. 장치에서 원인을 확인해야 합니다.'],
  failed: ['error', '배포 실패', '새 버전 적용을 완료하지 못했습니다. 이전 버전과 장치의 비공개 진단 정보를 확인하세요.'],
  'recovery-required': ['error', '장치 복구 확인 필요', '자동 복구가 완료되지 않아 쓰기가 차단돼 있습니다. 운영자 확인이 필요합니다.'],
  unavailable: ['warning', '장치 상태 조회 불가', '설정된 배포 상태 파일을 확인할 수 없습니다.'],
  unknown: ['warning', '장치 상태 미확인', '현재 배포 상태를 해석할 수 없습니다.'],
};
const REASON_COPY = {
  'github-rate-limit': 'GitHub API 한도 회복을 기다립니다. 표시된 재시도 시각 이후 다시 검증합니다.',
  'active-run': '진행 중인 검사나 보고서가 끝난 뒤 안전하게 전환합니다.',
  'retry-backoff': '직전 오류 후 재시도 대기 중입니다.',
  'ci-running': '같은 develop workflow가 아직 실행 중입니다. 완료 후 다시 확인합니다.',
  'ci-summary-pending': '현재 develop의 전체 검증 요약이 아직 준비되지 않았습니다.',
  'rollback-complete': '적용이 실패해 이전 버전으로 복원했고 복구 점검을 통과했습니다.',
};

/** One lightweight read when the HTTP process starts; never hash modules on each board poll. */
export function getRunningRevision(env = process.env) {
  if (sha(env.CA3P_COMMIT_SHA)) return env.CA3P_COMMIT_SHA;
  try { return sha(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: PROJECT_ROOT,
    encoding: 'utf8', timeout: 3000, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] }).trim()); }
  catch { return null; }
}

function deploymentEvent(value) {
  const copy = DEPLOYMENT_COPY[value.status];
  if (!copy) return null;
  return { id: value.id, at: date(value.at), kind: 'deployment', status: value.status,
    severity: copy[0], title: value.reasonCode === 'rollback-complete' ? '이전 버전 복원 완료' : copy[1],
    message: REASON_COPY[value.reasonCode] ?? copy[2], targetSha: sha(value.targetSha), deployedSha: sha(value.deployedSha),
    runUrl: canonicalRunUrl(value.runUrl), reasonCode: REASON_COPY[value.reasonCode] ? value.reasonCode : null,
    phase: value.phase ?? null, retryAt: date(value.retryAt) };
}

function ciEvent(run) {
  const valid = Number.isSafeInteger(run.runId) && run.runId > 0 && Number.isSafeInteger(run.runAttempt) && run.runAttempt > 0 && sha(run.commitSha);
  if (!valid) return null;
  const labels = {
    passed: ['success', 'develop 통합 검증 통과', '전체 테스트·컨테이너·통합 게이트가 통과했습니다. 장치 적용 여부는 별도로 확인하세요.'],
    failed: ['error', 'develop CI 실패', '현재 CI 검증을 통과하지 못했습니다. Actions에서 실패 단계를 확인하세요.'],
    running: ['info', 'develop CI 진행 중', '병합된 develop의 GitHub Actions 검증이 진행 중입니다.'],
    incomplete: ['warning', 'develop CI 결과 확인 필요', 'workflow 결과와 별개로 전체 suite 요약이 아직 확인되지 않았습니다.'],
  };
  const copy = labels[run.status] ?? labels.incomplete;
  return { id: `ci-${run.runId}-${run.runAttempt}-${run.status}-${run.status === 'running' ? run.workflowStatus ?? 'running' : 'result'}`,
    at: date(run.completedAt) ?? date(run.startedAt), kind: 'ci', status: run.status,
    severity: copy[0], title: copy[1], message: copy[2], targetSha: run.commitSha, deployedSha: null,
    runUrl: `https://github.com/typemnm/FSL-CA3P/actions/runs/${run.runId}`, reasonCode: null, phase: null, retryAt: null };
}

/** Observability only: CI success never becomes a claim that the device applied the release. */
export function buildOperationsSnapshot({ deployment = { enabled: false }, ci = {}, runningSha = null,
  now = new Date().toISOString(), staleAfterMs = 600_000 } = {}) {
  const generatedAt = date(now) ?? new Date().toISOString();
  const clock = Date.parse(generatedAt);
  const age = value => { const at = date(value); return at ? Math.max(0, Math.floor((clock - Date.parse(at)) / 1000)) : null; };
  const runs = (Array.isArray(ci.runs) ? ci.runs : []).filter(run => run && sha(run.commitSha)
    && run.branch === 'develop' && run.eventName === 'push').slice(0, 50)
    .sort((a, b) => b.runId - a.runId || b.runAttempt - a.runAttempt).slice(0, 10);
  const latest = runs[0] ?? null;
  const deviceAt = date(deployment.updatedAt) ?? date(deployment.checkedAt);
  const deviceAgeSeconds = age(deviceAt);
  const ciAgeSeconds = age(ci.live?.checkedAt ?? ci.updatedAt);
  const deviceFreshness = deployment.enabled !== true ? 'disabled' : deviceAgeSeconds === null ? 'unknown'
    : deviceAgeSeconds * 1000 > staleAfterMs || ['unavailable', 'unknown'].includes(deployment.status) ? 'stale' : 'fresh';
  const ciFreshness = ci.status === 'fresh' && ci.live?.status !== 'unavailable'
    && ciAgeSeconds !== null && ciAgeSeconds * 1000 <= staleAfterMs ? 'fresh'
    : runs.length ? 'stale' : 'unknown';
  // A queued workflow (or an old commit rerun) may start after a newer develop
  // was observed. Only the original push-run creation time is ordering evidence.
  const ciIsNewer = latest && date(latest.createdAt) && (!date(deployment.checkedAt)
    || Date.parse(latest.createdAt) > Date.parse(deployment.checkedAt));
  const deviceTarget = sha(deployment.targetSha);
  const targetSha = ciIsNewer ? latest.commitSha : deviceTarget ?? latest?.commitSha ?? null;
  const current = sha(runningSha);
  const events = (Array.isArray(deployment.events) ? deployment.events : []).map(deploymentEvent).filter(Boolean);
  if (deployment.enabled && !events.length && DEPLOYMENT_COPY[deployment.status]) events.push(deploymentEvent({
    ...deployment, id: `deployment-current-${deviceTarget ?? 'unknown'}-${deployment.status}-${deployment.phase ?? 'none'}`, at: deviceAt,
  }));
  events.push(...runs.map(ciEvent).filter(Boolean));
  const seen = new Set();
  const timeline = events.filter(event => {
    if (!/^[a-zA-Z0-9_-]{1,240}$/.test(event.id ?? '') || seen.has(event.id)) return false;
    seen.add(event.id); return true;
  }).sort((a, b) => (Date.parse(b.at) || 0) - (Date.parse(a.at) || 0)).slice(0, 100);
  return { schemaVersion: '1.0', generatedAt,
    source: { runningSha: current, targetSha, applied: current && targetSha ? current === targetSha : null,
      targetSource: ciIsNewer ? 'ci' : deviceTarget ? 'device' : latest ? 'ci' : 'unknown' },
    deployment, ci: { status: ci.status ?? 'unavailable', updatedAt: date(ci.updatedAt), lastAttemptAt: date(ci.lastAttemptAt),
      live: ci.live ?? null, latest, matched: runs.find(run => run.commitSha === targetSha) ?? null, runs },
    freshness: { device: deviceFreshness, ci: ciFreshness, deviceAgeSeconds, ciAgeSeconds }, events: timeline };
}
