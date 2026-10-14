/** Local telemetry simulation. This module never performs network requests. */
export const MODULES = [
  { id: 'parser', name: 'xss-parser', role: '사이트 응답 분석', icon: 'scan' },
  { id: 'casper', name: 'casper-db', role: '취약점 지식 조회', icon: 'database' },
  { id: 'attack', name: 'attack-module', role: 'curl 쓰기 요청', icon: 'terminal' },
  { id: 'guardrail', name: 'guardrail', role: '실행 전 요청 검사', icon: 'shield' },
  { id: 'pentest', name: 'pentest-db', role: '실행 기록', icon: 'archive' },
];

const TOTAL_STEPS = MODULES.length * 3;
const REVIEW_TOPICS = [
  {
    title: '응답 헤더 검토',
    description: '제공된 예시 응답의 보안 헤더 설정을 검토할 항목입니다.',
    evidence: '모사 응답 헤더 목록과 권장 설정 비교. 실제 대상의 응답을 수집하지 않았습니다.',
    reference: 'fixture:response-headers',
  },
  {
    title: '접근 정책 검토',
    description: '제공된 예시 접근 정책의 역할과 리소스 범위를 검토할 항목입니다.',
    evidence: '모사 역할별 접근 정책 표. 권한 우회나 실제 요청을 수행하지 않았습니다.',
    reference: 'fixture:access-policy',
  },
  {
    title: '세션 설정 검토',
    description: '제공된 예시 세션 설정의 속성과 만료 정책을 검토할 항목입니다.',
    evidence: '모사 세션 설정 메타데이터. 실제 쿠키나 세션 값을 읽지 않았습니다.',
    reference: 'fixture:session-settings',
  },
];

export function validateTarget(input) {
  if (typeof input !== 'string' || !input.trim()) {
    return { ok: false, url: '', error: '대상 URL을 입력하세요.' };
  }
  const candidate = input.trim();
  if (!/^https?:\/\//i.test(candidate)) {
    return { ok: false, url: '', error: 'http:// 또는 https://로 시작하는 URL을 입력하세요.' };
  }
  try {
    const target = new URL(candidate);
    if (!['http:', 'https:'].includes(target.protocol) || !target.hostname) {
      return { ok: false, url: '', error: '올바른 HTTP 또는 HTTPS URL을 입력하세요.' };
    }
    if (target.username || target.password) {
      return { ok: false, url: '', error: '사용자 이름이나 비밀번호가 포함된 URL은 사용할 수 없습니다.' };
    }
    return { ok: true, url: target.href, error: '' };
  } catch {
    return { ok: false, url: '', error: '올바른 URL을 입력하세요. 예: https://example.com' };
  }
}

export function formatElapsed(ms) {
  const totalSeconds = Math.floor(Math.max(0, Number.isFinite(ms) ? ms : 0) / 1000);
  const minutes = Math.floor(totalSeconds / 60).toString().padStart(2, '0');
  const seconds = (totalSeconds % 60).toString().padStart(2, '0');
  return `${minutes}:${seconds}`;
}

export function createRun(url, { id, initialSteps = 0 } = {}) {
  const target = validateTarget(url);
  if (!target.ok) throw new TypeError(target.error);
  const run = {
    id: id || `run-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    target: target.url,
    status: 'running',
    startedAt: new Date().toISOString(),
    elapsedMs: 0,
    step: 0,
    totalSteps: TOTAL_STEPS,
    events: [],
    snapshots: {},
    reviewItems: [],
  };
  const preload = Number.isFinite(initialSteps)
    ? Math.min(TOTAL_STEPS, Math.max(0, Math.floor(initialSteps)))
    : 0;
  if (preload) run.startedAt = new Date(Date.now() - preload * 1700).toISOString();
  for (let index = 0; index < preload; index += 1) tickRun(run, 1700);
  return run;
}

function buildStageData(run, moduleId, iteration, traceId) {
  const topic = REVIEW_TOPICS[iteration - 1];
  const common = {
    simulated: true,
    traceId,
    targetOrigin: new URL(run.target).origin,
    iteration,
    mode: 'observation-simulation',
  };
  const fixtureId = `fixture-${iteration.toString().padStart(2, '0')}`;
  switch (moduleId) {
    case 'parser':
      return {
        title: '관찰 데이터 준비',
        detail: '예시 사이트 구조와 응답 메타데이터를 준비했습니다.',
        request: { ...common, purpose: 'prepare-observation', input: { targetUrl: run.target, source: 'local-fixture' } },
        response: { ...common, status: 'ready', observationId: fixtureId, pages: 4 + iteration, inputPoints: 6 + iteration, source: 'local-fixture', targetContacted: false },
      };
    case 'casper':
      return {
        title: '검토 지식 조회',
        detail: `${topic.title}에 사용할 예시 체크리스트를 연결했습니다.`,
        request: { ...common, purpose: 'lookup-review-guidance', input: { observationId: fixtureId, topic: topic.title } },
        response: { ...common, status: 'matched', references: [{ id: `guidance-${iteration}`, title: topic.title, source: 'demo-review-checklist' }], confirmedVulnerabilities: 0 },
      };
    case 'guardrail':
      return {
        title: '관찰 범위 확인',
        detail: '로컬 예시 자료를 검토하는 시뮬레이션 범위를 확인했습니다.',
        request: { ...common, purpose: 'check-simulation-policy', input: { operation: 'review-supplied-observation', source: 'local-fixture', networkAccess: false } },
        response: { ...common, status: 'allowed', ruleId: 'SIMULATION_ONLY', networkAccess: false, allowedOperation: 'review-supplied-observation' },
      };
    case 'attack':
      return {
        title: '모의 쓰기 요청 검토',
        detail: '예시 curl 요청 JSON을 기록했습니다. 사이트로 전송하지 않았습니다.',
        request: { ...common, purpose: 'simulate-curl-write', input: { operation: 'execute_curl', curl: { method: 'POST', url: `fixture://review/${fixtureId}` } } },
        response: { ...common, status: 'simulated', executed: false, success: null, targetContacted: false },
      };
    case 'pentest':
      return {
        title: iteration === 3 ? '최종 기록 완료' : '반복 기록 완료',
        detail: `${iteration}번째 반복의 이벤트와 검토 항목을 기록했습니다.`,
        request: { ...common, purpose: 'record-simulation', input: { eventCount: run.events.length + 1, reviewItemCount: run.reviewItems.length, storage: 'in-memory' } },
        response: { ...common, status: 'recorded', recordId: `record-${iteration}`, storage: 'in-memory', reportStatus: iteration === 3 ? 'completed' : 'in-progress' },
      };
    default:
      throw new TypeError(`Unknown simulation module: ${moduleId}`);
  }
}

export function tickRun(run, deltaMs = 1700) {
  if (run.status !== 'running' || run.step >= TOTAL_STEPS) return run;
  const delta = Number.isFinite(deltaMs) ? Math.max(0, deltaMs) : 0;
  run.elapsedMs += delta;
  run.step += 1;
  const module = MODULES[(run.step - 1) % MODULES.length];
  const iteration = Math.floor((run.step - 1) / MODULES.length) + 1;
  const correlationId = `${run.id}:iteration-${iteration}:step-${run.step}`;
  const data = buildStageData(run, module.id, iteration, correlationId);
  const event = {
    id: `${run.id}:event-${run.step}`,
    time: new Date(Date.parse(run.startedAt) + run.elapsedMs).toISOString(),
    module: module.id,
    type: module.id === 'pentest' ? 'success' : 'info',
    title: data.title,
    detail: data.detail,
    latency: 90 + ((run.step * 47) % 310),
    iteration,
    correlationId,
    request: data.request,
    response: data.response,
  };
  if (data.agentInput) event.agentInput = data.agentInput;
  if (data.agentOutput) event.agentOutput = data.agentOutput;
  run.events.push(event);
  run.snapshots[module.id] = event;
  if (module.id === 'pentest') {
    const topic = REVIEW_TOPICS[iteration - 1];
    run.reviewItems.push({
      id: `${run.id}:review-${iteration}`,
      title: topic.title,
      severity: 'review',
      status: 'pending',
      module: module.id,
      iteration,
      description: topic.description,
      evidence: topic.evidence,
      evidenceId: `evidence-${iteration}`,
      reference: topic.reference,
      simulated: true,
      vulnerabilityConfirmed: false,
    });
  }
  if (run.step === TOTAL_STEPS) run.status = 'completed';
  return run;
}
