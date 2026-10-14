import { randomUUID } from 'node:crypto';
import orchestrator from '../agent/src/orchestrator.js';
import reasoning from '../agent/src/reasoning-engine.js';
import fixtures from '../agent/test-support/scripted-gateway.js';
import { validateTarget } from './dist/engine.js';
import { startLocalLab } from './local-lab-gateway.mjs';
import { checkLabReasoningConfig, createLabReasoning } from './lab-reasoning.mjs';

const CORE_ORIGIN = 'http://127.0.0.1:3000';
const DEFAULT_TARGET = 'https://demo.ca3p.local';
const TOTAL_EVENTS = 25;
const ACTIVE = new Set(['preparing', 'running', 'stopping']);
const STAGES = {
  'setup.attacker_session': '모의 curl 공격자 세션',
  'setup.fixture_session': '모의 curl fixture 세션',
  'setup.canary_post': '모의 curl canary 생성',
  'loop.observe': '모의 파서 화면 관찰',
  'loop.history': '모의 과거 사례 비교',
  'loop.catalog': '모의 공격 정보 조회',
  'loop.think': '코어 판단',
  'loop.act': '모의 curl 삭제 요청',
  'loop.verify': '모의 파서 재관찰',
  'loop.reflect': '코어 결과 검토',
};
const LAB_STAGES = {
  'setup.attacker_session': 'curl로 실습 계정 세션 준비',
  'setup.fixture_session': 'curl로 Bob 세션 준비',
  'setup.canary_post': 'curl로 로컬 canary 생성',
  'loop.observe': 'xss-parser로 게시판 관찰',
  'loop.history': 'casper-db 과거 XSS 사례 비교',
  'loop.catalog': 'pentest-db 공격 정보 조회',
  'loop.think': 'DeepSeek XSS 검사 후보 선택',
  'loop.act': 'curl로 무해한 XSS canary 게시',
  'loop.verify': '브라우저에서 canary 실행 확인',
  'loop.reflect': '실행 증거 기반 XSS 판정',
};
const LEGACY_BOLA_STAGES = {
  ...LAB_STAGES,
  'setup.attacker_session': 'curl로 Alice 세션 준비',
  'loop.think': 'DeepSeek 삭제 canary 요청 선택',
  'loop.act': 'curl로 로컬 canary 권한 검사',
  'loop.verify': 'xss-parser로 게시판 재관찰',
  'loop.reflect': '교차 사용자 삭제 결과 판정',
};
const MODULE_IDS = { 'xss-parser': 'parser', 'attack-module': 'attack',
  'casper-db': 'casper', 'pentest-db': 'pentest' };
const LAB_SOURCES = { parser: 'xss-parser/browser', attack: 'attack-module/curl',
  casper: 'casper-db/sqlite', pentest: 'pentest-db/local-json' };

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function validateDelay(value) {
  if (!Number.isInteger(value) || value < 0 || value > 3000) {
    throw fail(400, 'delayMs must be an integer between 0 and 3000.');
  }
  return value;
}

function emptyRun() {
  return {
    id: null, target: DEFAULT_TARGET, status: 'idle', mode: 'core-fixture',
    simulated: true, targetContacted: false, coreTargetOrigin: CORE_ORIGIN,
    startedAt: new Date().toISOString(), elapsedMs: 0, step: 0,
    totalSteps: TOTAL_EVENTS, iterations: 1, events: [], snapshots: {}, reviewItems: [],
  };
}

/** The browser can select only a scripted fixture or this repository's isolated local board. */
export function createLocalRuntime({
  defaultDelayMs = 1800,
  labFactory = startLocalLab,
  labReasoningFactory = createLabReasoning,
  labConfigProvider = checkLabReasoningConfig,
  labTestProfile = 'stored_xss_canary',
} = {}) {
  validateDelay(defaultDelayMs);
  if (!['stored_xss_canary', 'agent_cross_user_delete_canary'].includes(labTestProfile)) {
    throw new TypeError('Unsupported local lab test profile.');
  }
  const instanceId = randomUUID();
  const listeners = new Set();
  let run = emptyRun();
  let task = null;
  let setupTask = null;
  let cancellation = null;
  let labSession = null;
  let closed = false;
  let lab;
  try { lab = { available: true, ...labConfigProvider() }; }
  catch { lab = { available: false, error: 'DeepSeek 설정을 확인하세요. agent/.env 또는 DEEPSEEK_API_KEY가 필요합니다.' }; }

  function getState() {
    if (ACTIVE.has(run.status)) {
      run.elapsedMs = Date.now() - Date.parse(run.startedAt);
    }
    return structuredClone({ run, mode: run.mode, instanceId, lab });
  }

  function publish() {
    const state = getState();
    for (const listener of listeners) {
      try { listener(state); } catch { /* A subscriber must not interrupt the core. */ }
    }
  }

  function appendEvent(data) {
    const event = {
      id: `${run.id}:event-${run.events.length + 1}`,
      time: new Date().toISOString(), simulated: run.simulated, targetContacted: run.targetContacted,
      ...data,
    };
    run.events.push(event);
    run.snapshots[event.module] = event;
    run.step = run.events.length;
    publish();
  }

  async function waitForExchange(delayMs, signal, finalizing) {
    if (finalizing && cancellation.signal.aborted) return;
    const signals = [signal, cancellation.signal].filter(Boolean);
    if (signals.some(item => item.aborted)) throw new Error('Local fixture run stopped.');
    if (!delayMs) return;
    await new Promise((resolve, reject) => {
      let timer;
      const clean = () => {
        clearTimeout(timer);
        signals.forEach(item => item.removeEventListener('abort', abort));
      };
      const abort = () => { clean(); reject(new Error('Local fixture run stopped.')); };
      timer = setTimeout(() => { clean(); resolve(); }, delayMs);
      signals.forEach(item => item.addEventListener('abort', abort, { once: true }));
    });
  }

  async function execute(delayMs, { sourceGateway, targetOrigin = CORE_ORIGIN, reasoningEngine = new reasoning.RuleReasoningEngine() } = {}) {
    const stageTitle = stage => (run.mode !== 'local-lab-deepseek'
      ? STAGES : labTestProfile === 'stored_xss_canary' ? LAB_STAGES : LEGACY_BOLA_STAGES)[stage] || stage;
    const moduleSource = module => run.mode === 'local-lab-deepseek' ? LAB_SOURCES[module] : 'scripted-gateway';
    const stub = sourceGateway ?? fixtures.createScriptedGateway();
    const gateway = {
      async exchange(serializedRequest, { signal } = {}) {
        const request = JSON.parse(serializedRequest);
        const module = MODULE_IDS[request.receiver];
        const finalizing = request.receiver === 'pentest-db' && request.payload.operation === 'finalize';
        const started = performance.now();
        run.coreRunId = request.runId;
        let rawResponse;
        let response;
        try {
          await waitForExchange(delayMs, signal, finalizing);
          const controller = new AbortController();
          const abort = () => controller.abort();
          const signals = [signal, ...(finalizing ? [] : [cancellation.signal])].filter(Boolean);
          for (const item of signals) {
            if (item.aborted) abort();
            else item.addEventListener('abort', abort, { once: true });
          }
          try { rawResponse = await stub.exchange(serializedRequest, { signal: controller.signal }); }
          finally { signals.forEach(item => item.removeEventListener('abort', abort)); }
          response = JSON.parse(rawResponse);
        } catch (error) {
          const code = typeof error?.code === 'string' ? error.code : signal?.aborted ? 'CANCELLED' : 'GATEWAY_FAILURE';
          appendEvent({
            module, type: 'error', source: moduleSource(module), stage: request.payload.operation,
            title: `${request.receiver} 실패`, detail: error instanceof Error ? error.message : String(error),
            iteration: request.iteration, correlationId: request.correlationId,
            latency: Math.round((performance.now() - started) * 100) / 100,
            request, response: { sender: 'agent_gateway', receiver: 'agent', type: 'module.error',
              payload: { error: { code, message: error instanceof Error ? error.message : String(error) } } },
          });
          throw error;
        }
        if (run.mode === 'local-lab-deepseek' && request.receiver === 'xss-parser') run.targetContacted = true;
        if (run.mode === 'local-lab-deepseek' && request.receiver === 'attack-module'
          && Number.isInteger(response.payload?.response?.status)) run.targetContacted = true;
        const storedEvent = request.receiver === 'pentest-db' && request.payload.operation === 'append'
          ? request.payload.event : null;
        if (storedEvent?.stage === 'loop.think' || storedEvent?.stage === 'loop.reflect') {
          appendEvent({
            module: 'agent',
            type: 'info', stage: storedEvent.stage, source: 'core-internal-event',
            title: stageTitle(storedEvent.stage), detail: run.mode === 'local-lab-deepseek'
              ? '실제 코어의 입력·출력 · 로컬 실습 자료' : '실제 코어가 저장한 입력·출력 · fixture 자료',
            iteration: request.iteration, correlationId: request.correlationId,
            latency: null, request: storedEvent.request, response: storedEvent.response,
            agentInput: storedEvent.request.payload, agentOutput: storedEvent.response.payload,
          });
        }
        if (request.receiver === 'attack-module' && response.payload?.guardrail) {
          const decision = response.payload.guardrail;
          appendEvent({
            module: 'guardrail', type: decision.decision === 'ALLOW' ? 'info' : 'error',
            source: run.mode === 'local-lab-deepseek' ? 'guardrail-ruleset' : 'scripted-gateway',
            stage: decision.stage,
            title: `guardrail ${decision.decision === 'ALLOW' ? '허용' : '거부'}`,
            detail: `${decision.ruleId}: ${decision.reason ?? decision.decision}`,
            iteration: request.iteration, correlationId: request.correlationId,
            latency: null,
            request: { sender: 'attack-module', receiver: 'guardrail', type: 'guardrail.request',
              payload: { stage: decision.stage, curl: request.payload.curl } },
            response: { sender: 'guardrail', receiver: 'attack-module', type: 'guardrail.decision', payload: decision },
          });
        }
        appendEvent({
          module, type: finalizing ? 'success' : 'info', source: moduleSource(module),
          stage: storedEvent?.stage ?? request.payload.operation,
          title: finalizing ? '코어 보고서 저장' : storedEvent ? `${stageTitle(storedEvent.stage)} 기록` : `${request.receiver} 교환`,
          detail: run.mode === 'local-lab-deepseek' && module === 'parser'
            ? request.payload.operation === 'verify_stored_xss'
              ? '동일 시험 게시글의 실제 Chromium 콜백 실행 증거'
              : '로컬 실습 게시판의 실제 브라우저 분석 결과' : run.mode === 'local-lab-deepseek' && module === 'attack'
              ? '격리된 로컬 게시판에 전송한 curl 요청의 성공·실패 JSON'
              : run.mode === 'local-lab-deepseek' && module === 'casper'
                ? 'SQLite 과거 사례와 파서 관찰 결과의 비교'
                : run.mode === 'local-lab-deepseek' && module === 'pentest'
                  ? 'pentest-db의 참고 정보 또는 영속 실행 기록'
                  : '실제 JSON 계약 교환 · 이 모듈은 인메모리 테스트 대역',
          iteration: request.iteration, correlationId: request.correlationId,
          latency: Math.round((performance.now() - started) * 100) / 100,
          request, response,
        });
        return rawResponse;
      },
    };
    try {
      const result = await orchestrator.runOnce({
        gateway, targetOrigin,
        targetApplication: run.mode === 'local-lab-deepseek' ? 'owned-local-board' : 'dashboard-contract-fixture',
        maxIterations: 1,
        testProfile: run.mode === 'local-lab-deepseek'
          ? labTestProfile : 'agent_cross_user_delete_canary',
        reasoningEngine,
      });
      const labRun = run.mode === 'local-lab-deepseek';
      run.report = { ...result.report, simulated: !labRun, targetContacted: run.targetContacted,
        source: labRun ? 'isolated-local-board' : 'scripted-contract-fixture',
        ...(labRun ? { externalModules: { xssParser: 'playwright-browser', attackModule: 'local-curl',
          guardrail: 'ruleset-evaluator', casperDb: 'sqlite-history', pentestDb: 'local-json' } } : {}) };
      run.artifacts = result.artifacts;
      const finding = result.report.finding;
      if (finding) {
        const xssLab = labRun && result.report.testProfile === 'stored_xss_canary';
        run.reviewItems = [{
          id: `${run.id}:review`, title: xssLab ? '로컬 게시판 저장형 XSS 판정'
            : labRun ? '로컬 게시판 삭제 권한 판정' : '코어 fixture 판정',
          severity: labRun ? finding.severity : 'review', status: 'pending',
          module: 'agent', iteration: 1,
          description: xssLab ? '격리된 로컬 실습 게시판에 게시한 canary의 브라우저 실행 여부를 검증했습니다.'
            : labRun ? '격리된 로컬 실습 게시판에서 생성한 canary의 삭제 권한을 검증했습니다.'
            : '코어가 테스트 대역의 고정 자료를 판정한 결과입니다. 실제 사이트의 취약점 검증 결과가 아닙니다.',
          evidence: JSON.stringify(finding, null, 2), evidenceId: labRun ? 'local-board-canary' : 'scripted-contract-fixture',
          reference: labRun ? 'vul-web-1/server.js' : 'agent/test-support/scripted-gateway.js',
          simulated: !labRun, vulnerabilityConfirmed: labRun && finding.status === 'confirmed',
        }];
      }
      run.status = cancellation.signal.aborted ? 'stopped' : 'completed';
    } catch (error) {
      run.status = cancellation.signal.aborted ? 'stopped' : 'failed';
      run.error = run.status === 'stopped' ? '사용자가 실행을 중지했습니다.' : error.message;
      if (error.failureReport) {
        run.report = { ...error.failureReport, simulated: run.simulated, targetContacted: run.targetContacted,
          source: run.mode === 'local-lab-deepseek' ? 'isolated-local-board' : 'scripted-contract-fixture' };
      }
    } finally {
      run.elapsedMs = Date.now() - Date.parse(run.startedAt);
      if (run.status === 'completed') run.totalSteps = run.events.length;
      task = null;
      publish();
    }
  }

  function start(options = {}) {
    if (closed) throw fail(503, 'Local runtime is closed.');
    if (task || setupTask || ACTIVE.has(run.status)) throw fail(409, 'A local core run is already active.');
    if (!options || typeof options !== 'object' || Array.isArray(options) || Object.keys(options).some(key => !['target', 'delayMs'].includes(key))) {
      throw fail(400, 'Only target and delayMs are accepted.');
    }
    if (typeof options.target !== 'string' || options.target.length > 2048) throw fail(400, 'Provide a URL label up to 2048 characters.');
    const validated = validateTarget(options.target);
    if (!validated.ok) throw fail(400, validated.error);
    const delayMs = validateDelay(options.delayMs === undefined ? defaultDelayMs : options.delayMs);
    run = { ...emptyRun(), id: `local-${randomUUID()}`, target: validated.url, status: 'running', delayMs };
    cancellation = new AbortController();
    // Defer execution until task is assigned, including a zero-delay fixture run.
    task = Promise.resolve().then(() => execute(delayMs));
    publish();
    return getState();
  }

  async function startLab() {
    if (closed) throw fail(503, 'Local runtime is closed.');
    if (task || setupTask || ACTIVE.has(run.status)) throw fail(409, 'A local core run is already active.');
    if (!lab.available) throw fail(503, lab.error);
    cancellation = new AbortController();
    run = { ...emptyRun(), id: `lab-${randomUUID()}`, mode: 'local-lab-deepseek',
      target: 'http://127.0.0.1/', status: 'preparing', simulated: false,
      coreTargetOrigin: null, provider: 'deepseek', testProfile: labTestProfile,
      totalSteps: labTestProfile === 'stored_xss_canary' ? 19 : 25,
      externalModules: {
        xssParser: 'playwright-browser', attackModule: 'local-curl', guardrail: 'ruleset-evaluator',
        casperDb: 'sqlite-history', pentestDb: 'local-json',
      } };
    publish();
    setupTask = Promise.resolve().then(async () => {
      try {
        if (labSession) { await labSession.close(); labSession = null; }
        const session = await labFactory({ profile: labTestProfile });
        if (closed || cancellation.signal.aborted) {
          await session.close();
          run.status = 'stopped';
          publish();
          return getState();
        }
        labSession = session;
        const engine = labReasoningFactory({ signal: cancellation.signal });
        run.target = session.origin;
        run.coreTargetOrigin = session.origin;
        run.status = 'running';
        task = Promise.resolve().then(() => execute(0, {
          sourceGateway: session.gateway, targetOrigin: session.origin, reasoningEngine: engine,
        }));
        publish();
        return getState();
      } catch (error) {
        if (labSession) { await labSession.close(); labSession = null; }
        run.status = cancellation.signal.aborted ? 'stopped' : 'failed';
        run.error = '로컬 실습 시작에 실패했습니다. 게시판과 DeepSeek 설정을 확인하세요.';
        publish();
        throw fail(503, run.error);
      }
    });
    try { return await setupTask; }
    finally { setupTask = null; }
  }

  function stop(id) {
    if (id !== run.id || !run.id) throw fail(404, 'Local run not found.');
    if (run.status === 'running' || run.status === 'preparing') {
      run.status = 'stopping';
      cancellation.abort();
      publish();
    }
    return getState();
  }

  function reset() {
    if (task || setupTask || ACTIVE.has(run.status)) throw fail(409, 'Stop the active run before resetting.');
    run = emptyRun();
    publish();
    return getState();
  }

  async function close() {
    closed = true;
    if (run.status === 'running' || run.status === 'preparing') stop(run.id);
    try { await setupTask; } catch { /* Startup error is reflected in run state. */ }
    await task;
    if (labSession) { await labSession.close(); labSession = null; }
    listeners.clear();
  }

  return { getState, start, startLab, stop, reset, close, subscribe(listener) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  } };
}
