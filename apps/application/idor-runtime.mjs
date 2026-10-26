import { randomUUID } from 'node:crypto';
import { emptyRun, assertIdentifier } from '../../packages/contracts/index.mjs';
import { validateUniversityOrigin } from '../../packages/contracts/university-target.mjs';
import { probeSite } from '../../vul-web2/scripts/idor-probe.mjs';

const PROFILE = 'known_record_idor_read';
const ACTIVE = new Set(['preparing', 'running', 'stopping']);
const CHECKS = Object.freeze({ firstOwner: { recordId: 1, title: '첫 담당자의 본인 건 조회' },
  secondOwner: { recordId: 3, title: '두 번째 담당자의 본인 건 조회' },
  crossOwner: { recordId: 3, title: '다른 담당자 소유 건 조회' },
  studentRole: { recordId: 3, title: '학생 역할의 접근 제한 확인' } });
const FIXTURES = Object.freeze({
  'vul-web2-daehan': { siteKey: 'daehan', name: '대한대학교', origin: 'http://127.0.0.1:4101',
    endpoint: '/api/admissions/partner/applications' },
  'vul-web2-wonchang': { siteKey: 'wonchang', name: '원창대학교', origin: 'http://127.0.0.1:4102',
    endpoint: '/api/staff/mobile/cases' },
});
const fault = (status, message) => Object.assign(new Error(message), { status });

function safeObservation(value) {
  const check = value?.check;
  if (!Object.hasOwn(CHECKS, check) || value.recordId !== CHECKS[check].recordId) {
    throw new TypeError('Unexpected fixed IDOR observation.');
  }
  return { check, recordId: CHECKS[check].recordId,
    status: Number.isInteger(value.status) && value.status >= 100 && value.status <= 599 ? value.status : null,
    ownerId: Number.isSafeInteger(value.ownerId) && value.ownerId >= 0 ? value.ownerId : null };
}

/** One registered university fixture and one validated private origin per run. */
export function createIdorRuntime({ fixtureId, targetOrigin, runIdFactory = () => `run-${randomUUID()}`,
  probe = probeSite } = {}) {
  if (!Object.hasOwn(FIXTURES, fixtureId)) throw new TypeError('Choose a registered vul-web2 fixture.');
  if (typeof runIdFactory !== 'function' || typeof probe !== 'function') throw new TypeError('Invalid IDOR runtime dependency.');
  const fixture = { ...FIXTURES[fixtureId], origin: validateUniversityOrigin(targetOrigin ?? FIXTURES[fixtureId].origin) };
  const instanceId = randomUUID();
  const listeners = new Set();
  const initial = () => ({ ...emptyRun(), mode: 'local-lab-rule', fixtureId, testProfile: PROFILE,
    target: fixture.origin, coreTargetOrigin: fixture.origin, simulated: false,
    targetContacted: false, totalSteps: 6, modelId: 'rule-baseline', provider: 'rules' });
  let run = initial();
  let task = null;
  let controller = null;
  let closed = false;

  function getState() {
    if (ACTIVE.has(run.status)) run.elapsedMs = Date.now() - Date.parse(run.startedAt);
    return structuredClone({ run, mode: run.mode, instanceId,
      lab: { available: true, model: 'rule-baseline', provider: 'rules' } });
  }
  function publish() {
    const state = getState();
    for (const listener of listeners) {
      try { listener(structuredClone(state)); } catch { /* A subscriber must not stop the probe. */ }
    }
  }
  function appendEvent({ module, stage, title, detail, request = {}, response = {}, type = 'info' }) {
    const event = { id: `${run.id}:event-${run.events.length + 1}`, time: new Date().toISOString(),
      module, stage, title, detail, type, request, response, latency: null, iteration: 1,
      correlationId: `${run.id}:${stage}`, simulated: false, targetContacted: run.targetContacted,
      source: module === 'attack' ? 'vul-web2/guarded-idor-read' : 'vul-web2/fixed-idor-evaluation' };
    run.events.push(event); run.snapshots[module] = event; run.step = run.events.length;
    publish();
  }
  async function execute() {
    try {
      controller.signal.throwIfAborted();
      run.status = 'running';
      appendEvent({ module: 'agent', stage: 'idor.prepare', title: `${fixture.name} IDOR 검사 시작`,
        detail: '가상 계정과 알려진 조회번호 1·3으로 본인·교차 소유권·역할 제한을 비교합니다.',
        request: { fixtureId, testProfile: PROFILE }, response: { maximumReadRequests: 4, maximumMutations: 0 } });
      const seen = new Set();
      const result = await probe({ siteKey: fixture.siteKey, origin: fixture.origin,
        runId: run.id, signal: controller.signal, onContact() {
          if (!controller.signal.aborted && !run.targetContacted) { run.targetContacted = true; publish(); }
        }, onObservation(value) {
          if (controller.signal.aborted) return;
          const entry = safeObservation(value);
          if (seen.has(entry.check)) return;
          seen.add(entry.check);
          run.targetContacted = true;
          appendEvent({ module: 'attack', stage: `idor.${entry.check}`, title: CHECKS[entry.check].title,
            detail: `고정 조회번호 ${entry.recordId} · HTTP ${entry.status ?? '응답 없음'}`,
            request: { method: 'GET', url: `${fixture.origin}${fixture.endpoint}/${entry.recordId}` },
            response: entry });
        } });
      controller.signal.throwIfAborted();
      const findingStatus = result?.finding?.status;
      if (!['confirmed', 'not_confirmed', 'inconclusive'].includes(findingStatus)
        || !Array.isArray(result.evidence) || result.evidence.length !== 4) {
        throw new TypeError('The fixed probe did not return a complete result.');
      }
      const evidence = result.evidence.map(safeObservation);
      if (new Set(evidence.map(entry => entry.check)).size !== 4) throw new TypeError('The fixed probe returned duplicate checks.');
      const finding = { category: 'CWE-639', status: findingStatus,
        severity: findingStatus === 'confirmed' ? 'medium' : 'review' };
      run.report = { schemaVersion: '1.0', runId: run.id, status: 'completed', fixtureId,
        testProfile: PROFILE, startedAt: run.startedAt, completedAt: new Date().toISOString(),
        target: { origin: fixture.origin }, simulated: false, targetContacted: run.targetContacted,
        finding, evidence, provenance: { policy: `vul-web2-${fixture.siteKey}-known-record-idor`,
          guardrail: 'guardrail/GuardrailEvaluator', attack: 'attack-module/executeUniversityRead' } };
      run.reviewItems = [{ id: `${run.id}:review`, title: `${fixture.name} 담당자 간 상세 조회 권한 판정`,
        description: findingStatus === 'confirmed' ? '대조 조건을 만족한 상태에서 다른 담당자의 가상 건이 조회됐습니다.'
          : findingStatus === 'not_confirmed' ? '대조 조건을 만족했고 다른 담당자의 건은 차단됐습니다.'
            : '대조 조건이나 응답이 예상과 달라 소유권 검사 결과를 확정하지 못했습니다.',
        severity: finding.severity, status: 'pending', module: 'agent', iteration: 1,
        evidenceId: `${run.id}:known-record-idor`, evidence: JSON.stringify({ finding, evidence }, null, 2),
        simulated: false, vulnerabilityConfirmed: findingStatus === 'confirmed' }];
      appendEvent({ module: 'agent', stage: 'idor.reflect', title: '읽기 전용 IDOR 판정 완료',
        detail: run.reviewItems[0].description, type: 'success',
        request: { evidence }, response: { finding } });
      run.status = 'completed';
    } catch {
      run.status = controller.signal.aborted ? 'stopped' : 'failed';
      run.error = run.status === 'stopped' ? '사용자가 실행을 중지했습니다.'
        : `${fixture.name} 검사에 실패했습니다. Mac에서 vul-web2 컨테이너를 시작하고 ${fixture.origin} 및 가상 계정의 상태를 확인하세요.`;
      appendEvent({ module: 'agent', stage: 'idor.failed', title: run.status === 'stopped' ? '검사 중지' : '검사 실행 실패',
        detail: run.error, type: 'error', response: { code: run.status === 'stopped' ? 'CANCELLED' : 'IDOR_EXECUTION_FAILED' } });
    } finally {
      run.elapsedMs = Date.now() - Date.parse(run.startedAt);
      run.totalSteps = run.events.length;
      task = null;
      publish();
    }
  }
  function startLab(options = {}) {
    if (closed) throw fault(503, 'IDOR runtime is closed.');
    if (task || ACTIVE.has(run.status)) throw fault(409, 'A local IDOR run is already active.');
    if (!options || typeof options !== 'object' || Array.isArray(options) || Object.keys(options).length) {
      throw fault(400, 'The fixed IDOR fixture accepts no target or execution options.');
    }
    const id = assertIdentifier(runIdFactory(), 'runId');
    controller = new AbortController();
    run = { ...initial(), id, coreRunId: id, status: 'preparing', startedAt: new Date().toISOString() };
    task = Promise.resolve().then(execute);
    publish();
    return getState();
  }
  function stop(id) {
    if (!id || id !== run.id) throw fault(404, 'Local IDOR run not found.');
    if (ACTIVE.has(run.status)) {
      run.status = 'stopping'; controller.abort(); publish();
    }
    return getState();
  }
  async function close() {
    closed = true;
    if (ACTIVE.has(run.status)) stop(run.id);
    await task;
    listeners.clear();
  }
  return { getState, startLab, stop, close, subscribe(listener) {
    listeners.add(listener); return () => listeners.delete(listener);
  } };
}
