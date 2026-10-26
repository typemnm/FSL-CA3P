import { MODULES, validateTarget, formatElapsed } from './engine.js';
import { initStarfield } from './starfield.js';
import { createRuntimeClient } from './runtime-client.js';

const $ = (id) => document.getElementById(id);
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const iconPaths = {
  dashboard: '<rect x="3" y="3" width="7" height="7" rx="1.3"/><rect x="14" y="3" width="7" height="7" rx="1.3"/><rect x="3" y="14" width="7" height="7" rx="1.3"/><rect x="14" y="14" width="7" height="7" rx="1.3"/>',
  grid: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M10 4v16M4 10h16"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5ZM3 12l9 5 9-5M3 17l9 5 9-5"/>',
  box: '<path d="m12 3 9 5v9l-9 5-9-5V8l9-5ZM3 8l9 5 9-5M12 13v9M7 5.8l10 5.4"/>',
  file: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9l-6-6ZM14 3v6h6M8 13h8M8 17h6"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
  settings: '<path d="m10 3-.7 2.4-2.3 1-2.3-.7L3 9l1.7 1.7v2.6L3 15l1.7 3.3 2.3-.7 2.3 1L10 21h4l.7-2.4 2.3-1 2.3.7L21 15l-1.7-1.7v-2.6L21 9l-1.7-3.3-2.3.7-2.3-1L14 3h-4Z"/><circle cx="12" cy="12" r="3"/>',
  chevrons: '<path d="m8 8 4-4 4 4M8 16l4 4 4-4"/>',
  bell: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9ZM10 21h4"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  download: '<path d="M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4"/>',
  globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 16h4"/>',
  play: '<path d="m8 4 12 8-12 8V4Z"/>',
  pause: '<path d="M8 5v14M16 5v14" stroke-width="3"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="1"/>',
  pulse: '<path d="M2 12h5l3-8 4 16 3-8h5"/>',
  repeat: '<path d="m18 3 3 3-3 3M3 10V8a2 2 0 0 1 2-2h16M6 21l-3-3 3-3M21 14v2a2 2 0 0 1-2 2H3"/>',
  exchange: '<path d="M3 7h17m-4-4 4 4-4 4M21 17H4m4-4-4 4 4 4"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  orbit: '<circle cx="12" cy="12" r="3"/><ellipse cx="12" cy="12" rx="11" ry="5" transform="rotate(-35 12 12)"/><circle cx="18" cy="5" r="2" fill="currentColor" stroke="none"/>',
  database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0"/>',
  brain: '<path d="M12 4C9 1 5 3 5 6 1 7 2 12 4 13c-2 4 1 7 4 6 1 4 4 3 4 1V4ZM12 4c3-3 7-1 7 2 4 1 3 6 1 7 2 4-1 7-4 6-1 4-4 3-4 1M7 9l5 3M17 9l-5 3M7 16l5-2M17 16l-5-2"/>',
  scan: '<path d="M8 3H3v5M16 3h5v5M3 16v5h5M21 16v5h-5M7 12h10M12 7v10"/>',
  archive: '<rect x="3" y="3" width="18" height="5" rx="1"/><path d="M5 8v13h14V8M9 12h6"/>',
  search: '<circle cx="10" cy="10" r="6"/><path d="m15 15 6 6"/>',
  'arrow-down': '<path d="M12 3v17m-6-6 6 6 6-6"/>',
  code: '<path d="m8 6-6 6 6 6M16 6l6 6-6 6M14 3l-4 18"/>',
  copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  sparkles: '<path d="m12 3 2.4 6.6L21 12l-6.6 2.4L12 21l-2.4-6.6L3 12l6.6-2.4L12 3ZM21 1v4M19 3h4"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  check: '<path d="m5 12 5 5L20 7"/>',
};
function icon(name) { return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${iconPaths[name] || iconPaths.box}</svg>`; }
function hydrateIcons(root = document) { root.querySelectorAll('[data-icon]').forEach((el) => { el.innerHTML = icon(el.dataset.icon); }); }
hydrateIcons();

// Keep earlier browser-only demo records intact under their original key.
const STORAGE = 'ca3p.loop.core.sessions.v1';
const SETTINGS = 'ca3p.loop.settings.v1';
const EXPERIMENT_EPOCH = 'ca3p.loop.experiment.epoch.v1';
function readJSON(key, fallback) { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } }
function isObject(value) { return value && typeof value === 'object' && !Array.isArray(value); }
const EVENT_CHANNELS = {
  agent: { id: 'agent', name: 'Agent / RunOnce', role: '계획과 검증', icon: 'brain' },
  webpage: { id: 'webpage', name: 'Webpage', role: '실습 대상', icon: 'globe' },
  browser: { id: 'browser', name: '웹페이지 읽기 (이전 실행)', role: '사이트 읽기', icon: 'globe' },
  knowledge: { id: 'knowledge', name: '지식 조회 (이전 실행)', role: '지식 조회', icon: 'database' },
  reasoning: { id: 'reasoning', name: 'Agent 판단 (이전 실행)', role: '계획과 검증', icon: 'brain' },
  policy: { id: 'policy', name: '정책 검사 (이전 실행)', role: '정책 검사', icon: 'shield' },
  observer: { id: 'observer', name: 'Agent 검토 (이전 실행)', role: '관찰 검토', icon: 'scan' },
  recorder: { id: 'recorder', name: '실행 기록 (이전 실행)', role: '실행 기록', icon: 'archive' },
};
const SECRET_FIELD = /^(?:authorization|proxy-authorization|cookie|set-cookie|(?:x[_-])?api[_-]?key|deepseek[_-]?api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?(?:id|token)|password|secret)$/i;
function redactTelemetry(value, key = '') {
  if (SECRET_FIELD.test(key)) return '[redacted]';
  if (Array.isArray(value)) return value.map((item) => redactTelemetry(item));
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redactTelemetry(item, name)]));
  if (typeof value === 'string') return value.replace(/\bBearer\s+[^\s"',}]+/gi, 'Bearer [redacted]')
    .replace(/\b(?:Set-)?Cookie\s*:\s*[^\r\n]+/gi, 'Cookie: [redacted]');
  return value;
}
function isEvent(value) {
  return isObject(value) && (MODULES.some((module) => module.id === value.module) || Object.hasOwn(EVENT_CHANNELS, value.module)) &&
    ['id','time','title','detail','correlationId'].every((key) => typeof value[key] === 'string') &&
    Number.isFinite(Date.parse(value.time)) && (value.latency === null || (Number.isFinite(value.latency) && value.latency >= 0)) &&
    Number.isInteger(value.iteration) && value.iteration >= 0 &&
    isObject(value.request) && isObject(value.response) &&
    (value.agentInput === undefined || isObject(value.agentInput)) &&
    (value.agentOutput === undefined || isObject(value.agentOutput));
}
function isRun(value) {
  const fixture = value?.mode === 'core-fixture';
  const lab = ['local-lab-rule', 'local-lab-deepseek'].includes(value?.mode);
  return isObject(value) && (fixture || lab) && value.simulated === !lab &&
    (fixture ? value.targetContacted === false : typeof value.targetContacted === 'boolean') &&
    typeof value.id === 'string' && validateTarget(value.target).ok &&
    Number.isFinite(Date.parse(value.startedAt)) && Number.isFinite(value.elapsedMs) && value.elapsedMs >= 0 &&
    Number.isInteger(value.totalSteps) && value.totalSteps > 0 && value.totalSteps <= 128 &&
    Number.isInteger(value.step) && value.step >= 0 && value.step <= value.totalSteps &&
    Array.isArray(value.events) && value.events.length === value.step && value.events.every(isEvent) &&
    isObject(value.snapshots) && Object.entries(value.snapshots).every(([id,event]) => isEvent(event) && id === event.module) &&
    Array.isArray(value.reviewItems) && value.reviewItems.every((item) => isObject(item) &&
      (item.simulated === undefined || item.simulated === value.simulated) &&
      (item.vulnerabilityConfirmed === undefined || typeof item.vulnerabilityConfirmed === 'boolean') &&
      ['id','title','description','evidence','evidenceId'].every((key) => typeof item[key] === 'string')) &&
    ['queued','preparing','running','stopping','stopped','cancelled','interrupted','completed','failed'].includes(value.status);
}
function isLegacyRun(value) {
  return isObject(value) && value.mode === 'legacy-import' && typeof value.id === 'string'
    && Number.isFinite(Date.parse(value.startedAt)) && ['completed', 'failed'].includes(value.status)
    && Array.isArray(value.events) && isObject(value.report);
}
const saved = readJSON(STORAGE, []);
let history = Array.isArray(saved) ? saved.filter(isRun).slice(0, 12) : [];
const storedSettings = readJSON(SETTINGS, {});
const settings = { motion: storedSettings?.motion !== false, autoScroll: storedSettings?.autoScroll !== false, confirmModelReset: storedSettings?.confirmModelReset !== false, speed: [900,1800,3000].includes(Number(storedSettings?.speed)) ? Number(storedSettings.speed) : 1800 };
// Browser history is read-only context. Only the server can advance the current run.
let run = { id: '', target: '', status: 'idle', startedAt: null, elapsedMs: 0, step: 0, totalSteps: 19, iterations: 1, events: [], snapshots: {}, reviewItems: [], mode: 'core-fixture', simulated: true, targetContacted: false };
let instanceId = null;
let labReadiness = { available: false };
let connection = 'connecting';
let connectionTransport = 'polling';
let authSession = null;
let centralHistoryLoaded = false;
let historyRefreshPending = false;
let models = [];
let acceptedModelId = '';
let acceptedFixtureId = 'vul-web-1';
let pendingModelChange = null;
let modelChangeUnreset = storedSettings?.modelChangeUnreset === true;
let experimentEpoch = readJSON(EXPERIMENT_EPOCH, null);
let experimentStatus = 'ready';
let browserResetError = '';
let platform = null;
let ciResults = null;
let ciError = '';
let ciRefreshPending = false;
let comparison = null;
let comparisonPending = false;
let platformError = '';
let historyError = '';
let workspaceGeneration = 0;
const reviewDrafts = new Map();
const pendingReviews = new Set();
let historyReviewSignature = '';
let controlPending = false;
let inspectedRun = null;
let legacyDetail = null;
let selectedModule = 'parser';
let selectedEventId = null;
let activeTab = 'request';
let activeView = 'dashboard';
let toastTimer;
let stars;
const statusNames = { queued: '실행 대기', cancelled: '취소됨', interrupted: '실행 중단 · 새 실행 필요', preparing: '실습 준비 중', running: '진행 중', stopping: '중지 처리 중', completed: '완료', stopped: '중지됨', failed: '실패', idle: '대기 중' };
const moduleDescriptions = {
  parser: '제공된 fixture 응답에서 분석 결과를 반환합니다. 대상 URL에는 접속하지 않습니다.',
  casper: '고정 fixture에서 과거 취약점 지식을 조회합니다.',
  attack: 'Scripted fixture gateway가 쓰기 요청의 구조화된 curl JSON과 모의 결과를 반환합니다. 대상 URL에 요청하지 않습니다.',
  guardrail: '고정 fixture에서 실행 전 요청 검사 결과를 반환합니다.',
  pentest: '코어의 기록 요청과 fixture 응답을 확인합니다. 실제 DB에는 저장하지 않습니다.',
  agent: 'RunOnce의 plan과 reflect 입출력을 확인합니다.',
  webpage: '입력 URL은 fixture 모드에서 표시용 메타데이터입니다.',
};
const labModuleDescriptions = {
  parser: 'xss-parser가 입력 위치와 HTML 렌더링을 관찰하고, 시험 게시글의 마커가 Chromium에서 실행됐는지 확인합니다.',
  casper: 'casper-db가 파서 관찰값을 과거 XSS 사례와 대조해 참고 정보를 반환합니다.',
  attack: 'attack-module이 허용된 curl JSON으로 무해한 XSS 시험 게시글 한 건을 전송하고 HTTP 결과를 반환합니다.',
  guardrail: 'guardrail이 로컬 대상, 고정 시험 본문과 요청 횟수를 전송 전에 검사합니다.',
  pentest: '통합 취약점 DB가 공격 정보를 제공하고 실행 기록 저장기가 요청·응답·판정을 보존합니다.',
  agent: 'RunOnce가 관찰 근거로 후보를 만들고 DeepSeek의 제한된 POST 선택과 브라우저 실행 증거를 plan / reflect로 기록합니다.',
  webpage: '서버가 만든 격리된 127.0.0.1 게시판입니다. 입력 URL은 사용하지 않습니다.',
};
const legacyLabModuleDescriptions = {
  parser: 'xss-parser가 로컬 게시판을 삭제 전후로 관찰합니다.',
  casper: 'casper-db가 과거 XSS 사례를 참고 정보로 조회합니다.',
  attack: 'attack-module이 구조화된 curl JSON으로 제한된 게시글 삭제 요청을 전송합니다.',
  guardrail: 'guardrail이 교차 사용자 삭제 canary의 범위와 요청 예산을 검사합니다.',
  pentest: '실행 기록 저장기가 요청·응답·판정을 보존합니다.',
  agent: 'RunOnce가 삭제 권한 가설의 plan과 전후 관찰에 근거한 reflect를 기록합니다.',
  webpage: labModuleDescriptions.webpage,
};
const IDOR_FIXTURES = {
  'vul-web2-daehan': { name: '대한대학교', port: 4101 },
  'vul-web2-wonchang': { name: '원창대학교', port: 4102 },
};
const idorModuleDescriptions = {
  parser: '이 IDOR 실습은 xss-parser와 브라우저를 사용하지 않습니다.',
  casper: '이 IDOR 실습은 과거 XSS 사례 DB를 조회하지 않습니다.',
  attack: 'attack-module이 알려진 가상 레코드만 읽고, 본인·다른 담당자·학생 세션의 HTTP 결과를 비교합니다.',
  guardrail: 'guardrail이 고정된 로컬 원점, 레코드와 GET 요청 예산을 검사합니다.',
  pentest: '요청 결과와 최종 판정은 중앙 실행 이력에 저장합니다. XSS 카탈로그는 사용하지 않습니다.',
  agent: '정해진 IDOR 검증 절차와 대조군으로 접근 권한을 판정합니다. AI 모델을 호출하지 않습니다.',
  webpage: '서버 에이전트에서 접근하는 등록된 vul-web2 실습 원점입니다.',
};
function isLab(item) { return ['local-lab-rule', 'local-lab-deepseek'].includes(item?.mode); }
function isAiLab(item) { return item?.mode === 'local-lab-deepseek'; }
function canOperate() { return authSession && (!authSession.authRequired || authSession.authenticated) && authSession.user?.role !== 'viewer'; }
function selectedFixture() { return $('fixture-select').value || 'vul-web-1'; }
function selectedIdorFixture() { return IDOR_FIXTURES[selectedFixture()]; }
function selectedModel() { return models.find(item => item.id === (selectedIdorFixture() ? 'rule-baseline' : $('model-select').value)); }
function isXssLab(item) { return isLab(item) && (item.testProfile ?? item.report?.testProfile) === 'stored_xss_canary'; }
function isIdorLab(item) { return isLab(item) && (item.testProfile ?? item.report?.testProfile ?? item.manifest?.target?.testProfile) === 'known_record_idor_read'; }
function idorFixture(item) { return IDOR_FIXTURES[item.fixtureId ?? item.manifest?.target?.fixtureId ?? item.report?.fixtureId]; }
function describeModule(id, item = currentRun()) { const text = (isIdorLab(item) ? idorModuleDescriptions : isXssLab(item) ? labModuleDescriptions
  : isLab(item) ? legacyLabModuleDescriptions : moduleDescriptions)[id] || '이전 실행의 코어 이벤트입니다.';
  return isLab(item) && !isAiLab(item) ? text.replace('DeepSeek의 제한된 POST 선택', '규칙 엔진의 제한된 POST 선택') : text; }
function modeLabel(item) { return isLegacyRun(item) ? '이전 보고서 · 출처 일부 미기록' : isIdorLab(item) ? `${idorFixture(item)?.name || 'vul-web2'} IDOR 실습 · 규칙 엔진` : isLab(item) ? `${isXssLab(item) ? '저장형 XSS' : '격리'} 실제 실습 · ${isAiLab(item) ? 'DeepSeek' : '규칙 엔진'}` : '모의 코어 · fixture'; }
const viewMeta = {
  dashboard: ['대시보드', 'Observe. Decide. <span>Iterate.</span>', '에이전트의 모든 판단과 흐름을, 한눈에.'],
  sessions: ['실행 이력', 'Every run. <span>Remembered.</span>', '중앙에 저장된 실행과 모듈별 증거를 다시 살펴보세요.'],
  compare: ['실행 비교', 'Inspect the <span>difference.</span>', '코드·모델·입력 조건과 결과 차이를 함께 확인하세요.'],
  ci: ['통합 테스트', 'Verify the <span>merge.</span>', 'develop 전체 모듈 테스트와 이전 병합 결과를 비교하세요.'],
  platform: ['통합 상태', 'Build. Verify. <span>Integrate.</span>', '모듈 버전과 검증 상태, 실행 계층을 확인하세요.'],
  modules: ['모듈 탐색', 'Inside the <span>loop.</span>', '각 모듈이 주고받는 데이터와 상태를 확인하세요.'],
  reports: ['리포트', 'From signals to <span>insight.</span>', '코어 실행 리포트와 모드별 검토 항목을 확인하세요.'],
};
function currentRun() { return inspectedRun || run; }
function moduleById(id) { return MODULES.find((module) => module.id === id) || EVENT_CHANNELS[id] || { id, name: '알 수 없는 이벤트', role: '이벤트', icon: 'box' }; }
function notify(message) { $('toast').textContent = message; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3300); }
function saveRun() {
  if (run.status === 'idle' || !isRun(run)) return;
  history = [structuredClone(run), ...history.filter((item) => item.id !== run.id)].slice(0, centralHistoryLoaded ? 200 : 12);
  if (centralHistoryLoaded) { $('history-count').textContent = history.length; return; }
  try { localStorage.setItem(STORAGE, JSON.stringify(history)); } catch { notify('브라우저 저장 공간을 사용할 수 없습니다. 내보내기로 보관하세요.'); }
  $('history-count').textContent = history.length;
}
function showRuntimeError(message) {
  $('runtime-error').textContent = message;
  $('runtime-error').hidden = !message;
}
function acceptState(envelope) {
  let resetViews = false;
  const next = redactTelemetry(envelope.run);
  if (next.status !== 'idle' && !isRun(next)) throw new Error('코어 실행 상태의 데이터 형식이 올바르지 않습니다.');
  if (next.status === 'idle' && (!isObject(next.snapshots) || !Array.isArray(next.reviewItems) || next.step !== 0 || !Number.isInteger(next.totalSteps) || next.totalSteps < 1 || next.totalSteps > 128 || next.events.length !== 0)) throw new Error('코어 대기 상태의 데이터 형식이 올바르지 않습니다.');
  const nextEpoch = envelope.experiment?.epoch;
  if (Number.isSafeInteger(nextEpoch) && nextEpoch >= 0) {
    if (instanceId !== null && Number.isSafeInteger(experimentEpoch) && nextEpoch < experimentEpoch) return;
    if (nextEpoch !== experimentEpoch && (experimentEpoch !== null || nextEpoch > 0)) {
      clearExperimentView(); modelChangeUnreset = false;
      resetViews = true;
      settings.modelChangeUnreset = false; persistSettings();
    }
    experimentEpoch = nextEpoch;
    try { localStorage.setItem(EXPERIMENT_EPOCH, JSON.stringify(nextEpoch)); } catch { /* The state marker remains in memory. */ }
  }
  experimentStatus = envelope.experiment?.status ?? 'ready';
  const sameInstance = instanceId === envelope.instanceId;
  const rank = { idle: 0, queued: 1, preparing: 1, running: 2, stopping: 3, stopped: 4, interrupted: 4, cancelled: 4, completed: 4, failed: 4 };
  // A POST response can arrive after a newer SSE event. Keep the newer server state.
  if (sameInstance && next.id === run.id &&
      (next.step < run.step || (next.step === run.step && rank[next.status] < rank[run.status]))) return;
  const previousStatus = run.status;
  const previousId = run.id;
  if (!sameInstance && instanceId !== null) notify('로컬 런타임이 다시 시작되었습니다. 서버의 현재 상태를 표시합니다.');
  instanceId = envelope.instanceId;
  labReadiness = isObject(envelope.lab) && typeof envelope.lab.available === 'boolean'
    ? { available: envelope.lab.available, model: envelope.lab.model, possibleRetries: envelope.lab.possibleRetries }
    : { available: false };
  run = structuredClone(next);
  if (resetViews) renderAllExperimentViews();
  saveRun();
  if (next.id !== previousId || next.status !== previousStatus) void refreshHistory();
  if (!inspectedRun && !isLab(run) && (!sameInstance || previousId !== run.id) && document.activeElement !== $('target-url')) $('target-url').value = run.target || '';
  if (selectedEventId && !currentRun().events.some((event) => event.id === selectedEventId)) selectedEventId = null;
  showRuntimeError(browserResetError || (experimentStatus === 'failed' ? '이전 실험 초기화가 완료되지 않았습니다. 모델 변경 확인 창에서 초기화를 다시 시도하세요.'
    : run.status === 'failed' ? run.error || '코어 실행에 실패했습니다.' : ''));
  render();
  if (resetViews) void loadWorkspace();
  if (run.id === previousId && run.status !== previousStatus) {
    if (run.status === 'completed') notify('코어 실행이 완료되었습니다. 리포트를 확인하세요.');
    if (run.status === 'stopped') notify('코어 실행을 중지하고 수신한 기록을 저장했습니다.');
    if (run.status === 'failed') notify('코어 실행에 실패했습니다. 오류 내용을 확인하세요.');
  }
}
const runtime = createRuntimeClient({
  onState: acceptState,
  onConnection(state, transport) { connection = state; connectionTransport = transport || connectionTransport; renderStats(); },
  onError: showRuntimeError,
  onSession: acceptSession,
  onAuthRequired: requireLogin,
});
function persistSettings() { try { localStorage.setItem(SETTINGS, JSON.stringify(settings)); } catch { notify('설정을 브라우저에 저장할 수 없습니다.'); } }
function updateStars() {
  if (settings.motion && !stars) stars = initStarfield($('starfield'));
  if (!settings.motion && stars) { stars.destroy(); stars = null; }
  $('starfield').hidden = !settings.motion;
  stars?.setRunning(run.status === 'running');
}
function timeLabel(time) { return new Date(time).toLocaleTimeString('ko-KR', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'Asia/Seoul' }); }
function dateLabel(time) { return new Date(time).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }); }

function navigate(view) {
  if (!viewMeta[view]) view = 'dashboard';
  activeView = view;
  document.querySelectorAll('.view').forEach((el) => { el.hidden = el.id !== `view-${view}`; });
  document.querySelectorAll('[data-view]').forEach((el) => { el.classList.toggle('active', el.dataset.view === view); el.setAttribute('aria-current', el.dataset.view === view ? 'page' : 'false'); });
  $('breadcrumb-title').textContent = viewMeta[view][0];
  $('page-title').innerHTML = viewMeta[view][1];
  $('page-subtitle').textContent = viewMeta[view][2];
  $('sidebar').classList.remove('open'); $('menu-button').setAttribute('aria-expanded', 'false');
  if (location.hash !== `#${view}`) historyReplace(view);
  render();
}
function historyReplace(view) { window.history.replaceState(null, '', `#${view}`); }

function renderStats() {
  const item = currentRun();
  const running = !inspectedRun && run.status === 'running';
  const active = ['queued', 'preparing', 'running', 'stopping'].includes(run.status);
  const experimentBlocked = !!browserResetError || ['failed', 'resetting'].includes(experimentStatus);
  const lab = isLab(item);
  const stage = item.events.length ? moduleById(item.events.at(-1).module) : null;
  const connected = connection === 'connected';
  const connectionLabel = { connecting: '런타임 연결 중', connected: connectionTransport === 'polling' ? '1초 간격 상태 연결됨' : 'SSE 연결됨', disconnected: '연결 끊김 · 자동 재연결 중' }[connection];
  $('history-banner').hidden = !inspectedRun;
  $('run-status').textContent = inspectedRun ? '기록 보기' : statusNames[item.status];
  $('status-orb').className = `status-orb ${running && connected ? '' : 'stopped'}`;
  $('run-context').textContent = inspectedRun ? `${modeLabel(item)} · 저장한 실행` : !connected ? '마지막 수신 상태 · 진행 상태 갱신 대기' : isIdorLab(item) ? modeLabel(item) : lab ? `실제 격리 게시판 · ${isAiLab(item) ? 'DeepSeek' : '규칙 엔진'} 판단` : '실제 코어 · 외부 모듈 fixture';
  $('execution-label').textContent = isIdorLab(item) ? 'REAL LAB / IDOR' : lab ? isAiLab(item) ? 'REAL LAB / DEEPSEEK' : 'REAL LAB / RULE' : 'SIMULATED / FIXTURE';
  $('dashboard-mode').textContent = isIdorLab(item) ? modeLabel(item) : lab ? `실제 코어 / 격리 게시판 + ${isAiLab(item) ? 'DeepSeek' : '규칙 엔진'}` : '실제 코어 / 외부 모듈 fixture';
  $('elapsed-source').textContent = lab ? '로컬 실습 실행' : 'fixture 실행';
  $('iteration-value').textContent = '01';
  $('step-label').textContent = item.status === 'completed' ? '코어 실행 완료' : stage ? `최근 수신 · ${stage.role}` : '첫 이벤트 대기';
  $('total-event-count').textContent = `${item.totalSteps} 이벤트`;
  $('event-count').textContent = String(item.events.length).padStart(2, '0');
  $('elapsed-value').textContent = formatElapsed(item.elapsedMs);
  $('progress-label').textContent = item.status === 'completed' ? '모든 이벤트 수신 완료' : `수신한 코어 이벤트 · ${statusNames[item.status]}`;
  $('progress-number').textContent = `${String(item.step).padStart(2,'0')} / ${item.totalSteps} events`;
  $('progress-fill').style.width = `${Math.min(100, item.step / item.totalSteps * 100)}%`;
  $('core-state').textContent = inspectedRun ? 'SAVED SESSION' : !connected ? connection === 'connecting' ? 'CONNECTING' : 'CONNECTION LOST' : {queued:'QUEUED',preparing:'LAB PREPARING',running:'CORE RUNNING',stopping:'CORE STOPPING',stopped:'CORE STOPPED',cancelled:'CANCELLED',interrupted:'INTERRUPTED',completed:'CORE COMPLETE',failed:'CORE FAILED',idle:'READY TO START'}[item.status];
  $('live-label').innerHTML = `<span class="tiny-dot ${connected && running ? 'green' : 'gray'}"></span>${inspectedRun ? 'SAVED' : !connected ? 'OFFLINE' : running ? 'LIVE' : 'IDLE'}`;
  $('stream-status').textContent = connected ? connectionTransport === 'polling' ? 'Polling · 1s connected' : 'SSE connected' : '상태 연결 재시도 중';
  $('connection-status').textContent = connectionLabel;
  $('connection-dot').className = `tiny-dot ${connected ? 'green' : 'gray'}`;
  $('connection-notice').hidden = connected;
  $('connection-notice').textContent = `${connectionLabel}. 표시된 상태를 보존하고 실행 제어를 잠급니다.`;
  $('pause-button').disabled = true;
  $('pause-button').setAttribute('aria-label', '일시정지 및 재개 미지원');
  $('stop-button').disabled = !canOperate() || !!inspectedRun || !connected || controlPending || !['queued','preparing','running'].includes(run.status);
  $('run-button').disabled = !canOperate() || !connected || controlPending || active || experimentBlocked;
  const idor = selectedIdorFixture();
  if (idor) { $('model-select').value = 'rule-baseline'; acceptedModelId = 'rule-baseline'; }
  for (const option of $('model-select').options) {
    const entry = models.find(item => item.id === option.value);
    option.disabled = !entry?.available || (!!idor && entry.id !== 'rule-baseline');
    if (entry) option.textContent = idor && entry.id === 'rule-baseline' ? '규칙 기반 · 알려진 레코드 IDOR 검증' : `${entry.name || entry.id}${entry.available ? '' : ' · 사용 불가'}`;
  }
  const model = selectedModel();
  $('lab-run-button').disabled = !canOperate() || !connected || controlPending || active || experimentBlocked || !model?.available;
  $('fixture-select').disabled = controlPending || active || !canOperate();
  $('lab-target-origin').disabled = controlPending || active || !canOperate();
  $('lab-target-control').hidden = !idor;
  $('model-select').disabled = !!idor || controlPending || active || !canOperate();
  $('model-reset-toggle').checked = settings.confirmModelReset;
  $('model-reset-toggle').disabled = controlPending || !!pendingModelChange;
  $('experiment-reset-button').disabled = !canOperate() || !connected || controlPending || active || !!pendingModelChange;
  $('model-reset-warning').hidden = !modelChangeUnreset;
  $('lab-title').textContent = idor ? `vul-web2 · ${idor.name} IDOR 검증` : '실제 격리 실습 · 저장형 XSS 검증';
  $('lab-description').textContent = idor ? `${idor.name}의 실습 IP와 포트를 아래에 입력하세요. vul-web2 Compose를 먼저 시작해야 하며 기본 포트는 ${idor.port}입니다. 에이전트가 알려진 가상 레코드의 조회 권한만 비교합니다. 위 DISPLAY URL은 사용하지 않습니다.` : '서버가 격리된 로컬 게시판을 열어 시험 글 한 건을 게시하고 브라우저 실행 여부를 확인합니다. 위 입력 URL은 사용하지 않습니다.';
  $('lab-readiness').textContent = authSession?.user?.role === 'viewer' ? '조회 권한으로 로그인했습니다. 실행은 운영자만 시작할 수 있습니다.' : model?.available ? `${idor ? '규칙 기반 IDOR' : model.name || model.id} · 실행 준비됨` : '선택한 엔진을 사용할 수 없습니다. 서버 실행 환경과 모델 설정을 확인하세요.';
  $('model-scope').textContent = idor ? '이 실습은 정해진 IDOR 검증 절차를 사용하며 AI 모델과 보고서 모델을 호출하지 않습니다. 결과와 근거는 실행 이력 및 JSON 내보내기에서 확인할 수 있습니다.' : model?.mode === 'local-lab-deepseek' ? 'AI는 허용된 단일 후보를 선택하며 최종 판정은 브라우저 증거와 규칙 엔진이 수행합니다. 검사와 완료 후 보고서 생성의 모델 API 호출은 과금될 수 있습니다.' : '규칙 엔진 검사는 모델 API를 호출하지 않습니다. 완료 후 자동 보고서는 설정된 보고서 모델을 호출하며 과금될 수 있습니다.';
  $('new-session-button').disabled = !canOperate() || !connected || controlPending || active;
  $('export-button').disabled = item.events.length === 0;
  $('target-url').disabled = controlPending;
  $('loop-graph').classList.toggle('is-paused', !running || !connected);
  $('webpage-caption').textContent = isIdorLab(item) ? `${idorFixture(item)?.name || 'vul-web2'} · IDOR` : lab ? '격리된 로컬 게시판' : '표시용 URL';
  $('agent-core').querySelector('strong').textContent = isIdorLab(item) ? 'IDOR 검증' : 'Agent / RunOnce';
  document.querySelector('.graph-webpage').classList.toggle('contacted', item.targetContacted);
  const graphSources = isIdorLab(item)
    ? { parser: '미사용', casper: '미사용', attack: '로컬 레코드 GET', guardrail: '조회 범위 검사', pentest: '중앙 실행 이력' } : lab
    ? { parser: '응답 분석', casper: '이전 DB 조회', attack: '로컬 curl 쓰기', guardrail: '실행 전 검사', pentest: '실습 기록' }
    : { parser: 'Fixture 분석', casper: 'Fixture 조회', attack: '쓰기 Fixture', guardrail: 'Fixture 검사', pentest: 'Fixture 기록' };
  document.querySelectorAll('.graph-node').forEach((node) => {
    node.querySelector('.node-copy small').textContent = graphSources[node.dataset.module];
    node.classList.toggle('selected', node.dataset.module === selectedModule);
    node.classList.toggle('done', !!item.snapshots[node.dataset.module]);
    node.classList.toggle('current', running && connected && stage?.id === node.dataset.module);
    node.setAttribute('aria-pressed', String(node.dataset.module === selectedModule));
  });
  $('agent-core').classList.toggle('selected', selectedModule === 'agent');
  $('agent-core').classList.toggle('current', running && connected && stage?.id === 'agent');
  $('agent-core').setAttribute('aria-pressed', String(selectedModule === 'agent'));
}
function renderActivity() {
  const item = currentRun();
  const query = $('event-search').value.trim().toLowerCase();
  const events = item.events.filter((event) => `${moduleById(event.module).name} ${event.title} ${event.detail} ${event.correlationId}`.toLowerCase().includes(query)).slice().reverse();
  const previousScroll = $('activity-list').scrollTop;
  $('activity-counter').textContent = String(item.events.length).padStart(2,'0');
  $('activity-list').innerHTML = events.length ? events.map((event) => `<button class="activity-event ${event.id === selectedEventId ? 'active' : ''}" data-event="${escape(event.id)}"><span class="event-indicator">${icon(event.type === 'success' ? 'check' : moduleById(event.module).icon)}</span><span class="event-copy"><span class="event-meta"><span>${escape(moduleById(event.module).name.replace(' Engine','').replace('Observation Review','Observer'))}</span><span class="event-time">${escape(timeLabel(event.time))}</span></span><span class="event-title">${escape(event.title)}</span><span class="event-detail">${escape(event.detail)}</span></span></button>`).join('') : `<div class="empty-state compact"><span data-icon="pulse"></span><h3>${query ? '일치하는 이벤트가 없습니다' : '첫 코어 이벤트를 기다리는 중'}</h3><p>${query ? '다른 검색어를 입력해 보세요.' : isLab(item) ? '로컬 실습 서버가 준비되고 첫 이벤트가 도착하면 표시됩니다.' : '표시용 URL을 입력하고 코어 fixture를 시작하세요.'}</p></div>`;
  hydrateIcons($('activity-list'));
  $('activity-list').scrollTop = settings.autoScroll ? 0 : previousScroll;
  if (!$('notification-popover').hidden) renderNotifications();
}
function getSnapshot() { const item = currentRun(); return selectedEventId ? item.events.find((event) => event.id === selectedEventId) : item.snapshots[selectedModule]; }
function getAgentEvent() {
  const snapshot = getSnapshot();
  const hasIO = (event) => isObject(event?.agentInput) && isObject(event?.agentOutput);
  return hasIO(snapshot) ? snapshot : currentRun().events.filter((event) => hasIO(event) && (!snapshot || event.iteration === snapshot.iteration)).at(-1);
}
function traceData() {
  const snapshot = getSnapshot();
  const item = currentRun();
  const lab = isLab(item);
  if (activeTab === 'agent') {
    if (isIdorLab(item)) return { source: 'known-record-idor', mode: item.mode,
      input: { fixtureId: item.fixtureId ?? item.manifest?.target?.fixtureId, target: item.target, testProfile: 'known_record_idor_read' },
      output: item.report ?? { status: 'waiting', message: '정해진 IDOR 조회와 대조군의 결과를 기다리고 있습니다.' } };
    const reasoning = getAgentEvent();
    return reasoning ? { source: isAiLab(item) && reasoning.stage === 'loop.think' ? 'DeepSeek + RuleReasoningEngine' : 'RuleReasoningEngine', mode: item.mode, fixtureInputs: !lab, correlationId: reasoning.correlationId, input: reasoning.agentInput, output: reasoning.agentOutput } : { status: 'waiting', mode: item.mode, message: isAiLab(item) ? 'DeepSeek curl 요청과 코어 plan / reflect 입출력을 기다리고 있습니다.' : 'RuleReasoningEngine의 plan / reflect 입출력을 기다리고 있습니다.' };
  }
  return snapshot?.[activeTab] || { status: 'waiting', mode: item.mode, simulated: item.simulated, module: selectedModule, message: '이 모듈의 첫 코어 이벤트를 기다리고 있습니다.' };
}
function highlightJSON(data) {
  const raw = JSON.stringify(data ?? null, null, 2);
  return raw.split('\n').map((line, i) => {
    const colored = line.replace(/("(?:\\.|[^"\\])*"\s*:)|("(?:\\.|[^"\\])*")|\b(true|false|null)\b|(-?\b\d+(?:\.\d+)?\b)/g, (match, key, str, bool, number) => `<span class="code-${key ? 'key' : str ? 'string' : bool ? 'boolean' : 'number'}">${escape(match)}</span>`);
    // Indentation and punctuation outside tokens cannot contain user supplied strings.
    return `<span class="code-line"><span class="line-number" aria-hidden="true">${i + 1}</span><span>${colored}</span></span>`;
  }).join('');
}
function renderInspector() {
  const module = moduleById(selectedModule);
  const lab = isLab(currentRun());
  const snapshot = getSnapshot();
  const contextEvent = activeTab === 'agent' ? getAgentEvent() : snapshot;
  $('selected-module-name').textContent = module.name;
  $('context-module').textContent = activeTab === 'agent' && isIdorLab(currentRun()) ? 'IDOR 검증' : activeTab === 'agent' && isAiLab(currentRun()) ? 'Agent / RunOnce + DeepSeek' : activeTab === 'agent' ? 'Agent / RunOnce' : module.name;
  $('context-role').textContent = describeModule(activeTab === 'agent' ? 'agent' : selectedModule);
  $('correlation-value').textContent = contextEvent?.correlationId || '—';
  $('trace-source').textContent = activeTab === 'agent' ? isIdorLab(currentRun()) ? '정해진 IDOR 조회 권한 검증' : isAiLab(currentRun()) ? 'DeepSeek · Agent / RunOnce' : lab ? '규칙 엔진 · 실제 격리 실습' : 'Agent / RunOnce · fixture 입력'
    : contextEvent?.source === 'local-curl-board' ? 'local-curl-board · curl 실행'
      : contextEvent?.source === 'local-loopback-board' ? '격리된 로컬 게시판'
        : contextEvent?.source === 'core-internal-event' ? 'Agent / RunOnce'
          : contextEvent?.source === 'scripted-gateway' ? 'Scripted fixture gateway'
            : contextEvent?.source || (lab ? '로컬 모듈 이벤트 대기' : 'Fixture 이벤트 대기');
  $('trace-state').textContent = contextEvent ? '코어 이벤트 수신' : '이벤트 대기';
  $('trace-latency').textContent = contextEvent ? contextEvent.latency === null ? '코어 내부 I/O · 지연 미측정' : `${contextEvent.latency} ms · 실측` : '—';
  $('code-filename').textContent = activeTab === 'agent' ? 'agent-io.json' : `${activeTab}.json`;
  $('request-tab-count').textContent = $('response-tab-count').textContent = snapshot ? '01' : '00';
  document.querySelectorAll('[data-tab]').forEach((el) => { el.classList.toggle('active', el.dataset.tab === activeTab); el.setAttribute('aria-selected', String(el.dataset.tab === activeTab)); el.setAttribute('tabindex', el.dataset.tab === activeTab ? '0' : '-1'); el.setAttribute('aria-controls', 'trace-code'); });
  $('trace-code').setAttribute('role','tabpanel');
  $('trace-code').innerHTML = highlightJSON(traceData());
}
function renderSessions() {
  $('history-source').textContent = centralHistoryLoaded ? `중앙 영속 기록 · ${history.length}건${historyError ? ' · 갱신 실패, 마지막 수신 기록' : ''}` : historyError || '중앙 실행 기록 조회 중';
  $('session-list').innerHTML = history.length ? history.map((item) => `<div class="session-row"><div class="session-target">${escape(item.target || '대상 URL 미기록')}<small>${escape(modeLabel(item))} · ${escape(item.id)}</small><small>${escape(runModelName(item))} · SHA ${escape(runRevision(item).slice(0, 12))}</small></div><span class="state-chip ${escape(item.status)}"><span class="tiny-dot ${item.status === 'running' || item.status === 'completed' ? 'green' : 'gray'}"></span>${escape(statusNames[item.status] || item.status)}</span><span class="session-stat session-events">${item.events.length} events</span><span class="session-stat session-date">${escape(dateLabel(item.startedAt))}</span><button class="button secondary" data-session="${escape(item.id)}">${isLegacyRun(item) ? '이전 리포트' : '열기'} ${icon('code')}</button></div>`).join('') : `<div class="empty-state"><span data-icon="layers"></span><h3>아직 저장된 실행이 없습니다</h3><p>모의 코어 또는 실제 격리 실습을 시작하면 중앙 실행 기록에 저장됩니다.</p></div>`;
  hydrateIcons($('session-list'));
  $('legacy-detail').hidden = !legacyDetail;
  $('legacy-detail').innerHTML = legacyDetail ? `<section class="panel core-report"><div class="eyebrow">IMPORTED / LEGACY EVIDENCE</div><h2>이전 실행 보고서 · ${escape(legacyDetail.id)}</h2><p>기존 pentest-db 기록입니다. 원래 모듈·모델·입력 조건이 누락될 수 있어 같은 조건 비교로 단정하지 않습니다.</p></section>${jsonSection('원본 실행 보고서', legacyDetail.report)}${jsonSection('원본 이벤트', legacyDetail.events)}${jsonSection('가져오기 정보', legacyDetail.manifest || {})}` : '';
}

function renderModules() {
  const item = currentRun();
  $('module-grid').innerHTML = MODULES.map((module) => {
    const count = item.events.filter((event) => event.module === module.id).length;
    const snapshot = item.snapshots[module.id];
    const source = !snapshot ? 'EVENT WAITING' : snapshot.source === 'local-curl-board' ? 'LOCAL CURL'
      : snapshot.source === 'scripted-gateway' ? 'FIXTURE'
        : snapshot.source === 'core-internal-event' ? 'CORE EVENT'
          : snapshot.source === 'local-loopback-board' ? 'LOCAL BOARD'
            : isLab(item) ? 'LOCAL MODULE' : 'FIXTURE';
    return `<article class="panel module-card"><div class="module-card-top"><span data-icon="${module.icon}"></span><span class="local-chip">${source}</span></div><h2>${escape(module.name)}</h2><p>${escape(describeModule(module.id, item))}</p><div class="module-metrics"><span><strong>${String(count).padStart(2,'0')}</strong>EVENTS</span><span><strong>${escape(snapshot?.latency ?? '—')}</strong>ELAPSED MS</span></div><button class="button secondary" data-open-module="${module.id}">데이터 확인 ${icon('code')}</button></article>`;
  }).join('');
  hydrateIcons($('module-grid'));
}
function reportDocumentMarkup(item) {
  const document = item.reportDocument;
  const idor = isIdorLab(item);
  const status = document?.status ?? (idor || item.simulated || item.mode === 'core-fixture' ? 'skipped'
    : ['completed', 'failed', 'stopped', 'cancelled', 'interrupted'].includes(item.status) ? 'missing' : 'waiting');
  const labels = { generating: '보고서 생성 중', ready: 'HWPX 보고서 준비됨', failed: '보고서 생성 실패', unavailable: '보고서 모델 설정 필요', skipped: '보고서 생성 생략', waiting: '실행 완료 후 보고서 생성', missing: '저장된 HWPX 보고서 없음' };
  const descriptions = {
    generating: '검사 결과로 보고서를 작성하고 있습니다. 생성이 완료되면 다운로드할 수 있습니다.',
    ready: '저장된 HWPX 문서를 다운로드할 수 있습니다.',
    failed: '검사 결과는 보존되어 있습니다. 보고서 생성 중 오류가 발생했습니다.',
    unavailable: '보고서 모델 설정을 확인하세요. 검사 결과 JSON은 계속 확인할 수 있습니다.',
    skipped: idor ? 'IDOR 실습의 HWPX 보고서는 아직 지원하지 않습니다. 판정과 요청 근거는 아래에서 확인하고 JSON으로 내보낼 수 있습니다.' : '모의 fixture, 중지되었거나 최종 검사 결과가 없는 실행은 보고서를 생성하지 않습니다. 저장된 실행 기록은 JSON으로 내보낼 수 있습니다.',
    waiting: '실제 격리 실습이 완료되면 설정된 모델로 보고서를 자동 생성합니다.',
    missing: '이 실행에는 생성된 HWPX 보고서 기록이 없습니다. 검사 결과 JSON을 확인하세요.',
  };
  const ready = status === 'ready' && typeof document?.artifactId === 'string' && !!item.id;
  return `<section class="panel report-document" aria-labelledby="report-document-title"><div><h2 id="report-document-title">HWPX 보고서</h2><p id="report-document-status" role="status" aria-live="polite">${escape(labels[status] || labels.waiting)}</p><small>${escape(descriptions[status] || descriptions.waiting)}</small>${document?.message ? `<p class="report-document-message">${escape(document.message)}</p>` : ''}<small class="report-cost-note">${idor ? '이 IDOR 실습은 AI 및 보고서 모델을 호출하지 않습니다.' : '실제 실습의 자동 보고서는 모델 API를 호출하며 과금될 수 있습니다.'}</small></div>${ready ? `<a class="button primary" id="report-download-button" href="${escape(runtime.reportDownloadUrl(item.id))}" download="${escape(document.filename || 'ca3p-report.hwpx')}" aria-describedby="report-document-status">${icon('download')}HWPX 다운로드</a>` : `<button class="button secondary" id="report-download-button" disabled aria-describedby="report-document-status">${icon('download')}HWPX 다운로드</button>`}</section>`;
}
function renderReports() {
  const item = currentRun();
  const lab = isLab(item);
  const note = isIdorLab(item)
    ? `${escape(idorFixture(item)?.name || 'vul-web2')}의 등록된 실습 원점(${escape(item.target || '준비 중')})에서 알려진 가상 레코드의 IDOR를 검사합니다. 본인·다른 담당자·학생 세션의 조회 결과를 대조합니다. ${item.targetContacted ? '실습 사이트의 HTTP 응답을 수신했습니다.' : '아직 실습 사이트의 HTTP 응답을 수신하지 못했습니다.'} 정해진 검증 범위의 결과이며, 사이트 전체의 취약점 탐지나 자율 CERT 조사 결과를 뜻하지 않습니다. AI 모델과 브라우저를 사용하지 않습니다.`
    : isXssLab(item)
    ? `서버가 생성한 격리된 로컬 게시판(${escape(item.target || '준비 중')})에서 XSS 가설 한 건을 검사합니다. ${item.targetContacted ? '실습 사이트에 HTTP 요청을 보냈습니다.' : '아직 실습 사이트로 보낸 HTTP 요청은 없습니다.'} ${isAiLab(item) ? 'DeepSeek가 선택한' : '규칙 엔진이 만든'} 구조화된 curl 요청은 정책 검사를 거쳐 전송하며, finding은 동일 시험 게시글의 브라우저 실행 증거로 판정합니다. 입력 URL은 사용하지 않습니다.`
    : lab ? `서버가 생성한 격리된 로컬 게시판(${escape(item.target || '준비 중')})에서 삭제 권한 가설 한 건을 검사했습니다. 입력 URL은 사용하지 않았습니다.`
    : 'RunOnce와 RuleReasoningEngine의 실제 코어 실행 결과입니다. 외부 모듈의 응답은 scripted fixture이며, 입력 URL은 표시용 메타데이터입니다. 실제 대상에 접속하거나 취약점을 확인하지 않았습니다.';
  $('report-content').innerHTML = `<section class="panel report-top"><div><div class="eyebrow">${lab ? 'ISOLATED LOCAL LAB REPORT' : 'CORE FIXTURE REPORT'}</div><h2>${isIdorLab(item) ? `${escape(idorFixture(item)?.name || 'vul-web2')} IDOR 실행 결과` : lab ? '로컬 실습 게시판 실행 결과' : '코어 실행 결과와 fixture 검토 항목'}</h2><p>${escape(item.target || '실행 전')}</p><small>${escape(statusNames[item.status])} · ${item.step} / ${item.totalSteps} 이벤트 · ${escape(formatElapsed(item.elapsedMs))}</small></div><div class="report-count"><strong>${String(item.reviewItems.length).padStart(2,'0')}</strong><span>${lab ? '로컬 실습 검토 항목' : 'fixture 검토 항목'}</span></div></section><div class="report-items">${item.reviewItems.length ? item.reviewItems.map((review) => `<article class="panel report-item"><span class="review-tag"><span class="tiny-dot"></span>${lab ? review.vulnerabilityConfirmed ? 'LOCAL LAB · CONFIRMED' : 'LOCAL LAB · REVIEW' : 'FIXTURE · UNCONFIRMED'}</span><h2>${escape(review.title)}</h2><p>${escape(review.description)}</p><div class="evidence-box"><strong>${lab ? 'LOCAL LAB' : 'FIXTURE'} EVIDENCE / ${escape(review.evidenceId)}</strong>${escape(review.evidence)}</div></article>`).join('') : `<section class="panel empty-state"><span data-icon="file"></span><h3>최종 ${lab ? '실습' : 'fixture'} 결과 대기</h3><p>코어 실행 완료 후 검토 항목이 표시됩니다.</p></section>`}</div><div class="report-note">${note}</div>${item.report ? `<section class="panel core-report"><h2>${icon('file')}${isIdorLab(item) ? 'IDOR 최종 리포트' : 'RunOnce 최종 리포트'}</h2><p>${isIdorLab(item) ? '정해진 조회 권한 검증 결과' : '코어가 반환한 결과'} · 내부 실행 ID ${escape(item.coreRunId || '—')} · 코어 origin ${escape(item.coreTargetOrigin || (lab ? '—' : 'http://127.0.0.1:3000'))}</p><pre tabindex="0" aria-label="${isIdorLab(item) ? 'IDOR' : 'RunOnce'} 최종 리포트 JSON">${highlightJSON(item.report)}</pre></section>` : ''}`;
  $('report-content').insertAdjacentHTML('afterbegin', reportDocumentMarkup(item));
  hydrateIcons($('report-content'));
  if (item.manifest) $('report-content').insertAdjacentHTML('beforeend', jsonSection('실행 조건 · 코드 / 모델 / 입력 / 정책', item.manifest));
  if (item.historyWrite) $('report-content').insertAdjacentHTML('beforeend', historyCheckMarkup(item));
}
function renderNotifications() {
  $('notification-list').innerHTML = currentRun().events.slice(-3).reverse().map((event) => `<div class="notification-event">${escape(event.title)}<small>${escape(moduleById(event.module).name)} · ${escape(timeLabel(event.time))}</small></div>`).join('') || '<div class="notification-event">아직 이벤트가 없습니다.</div>';
}
function render() {
  $('history-count').textContent = history.length;
  renderStats();
  if (activeView === 'dashboard') { renderActivity(); renderInspector(); renderHistoryChecks(); }
  if (activeView === 'sessions') renderSessions();
  if (activeView === 'modules') renderModules();
  if (activeView === 'reports') renderReports();
  if (activeView === 'compare') renderComparison();
  if (activeView === 'ci') renderCiResults();
  if (activeView === 'platform') renderPlatform();
  if (!$('notification-popover').hidden) renderNotifications();
  updateStars();
}

document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => navigate(button.dataset.view)));
window.addEventListener('hashchange', () => navigate(location.hash.slice(1)));
async function submitControl(action) {
  if (!canOperate() || controlPending || connection !== 'connected') return;
  controlPending = true;
  showRuntimeError('');
  renderStats();
  try { await action(); }
  catch (error) { showRuntimeError(error.message); notify('로컬 런타임 요청에 실패했습니다. 오류 내용을 확인하세요.'); }
  finally { controlPending = false; render(); }
}
$('target-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (browserResetError || ['failed', 'resetting'].includes(experimentStatus) || pendingModelChange) return;
  if (['queued','preparing','running','stopping'].includes(run.status) || controlPending || connection !== 'connected') return;
  const validated = validateTarget($('target-url').value);
  $('url-error').hidden = validated.ok;
  $('target-url').setAttribute('aria-invalid', String(!validated.ok));
  if (!validated.ok) { $('url-error').textContent = validated.error; $('target-url').focus(); return; }
  await submitControl(async () => {
    await runtime.start(validated.url, settings.speed);
    inspectedRun = null;
    selectedEventId = null;
    $('target-url').value = validated.url;
    notify('실제 코어와 fixture gateway 실행을 시작했습니다. URL은 표시용이며 접속하지 않습니다.');
  });
});
$('lab-run-button').addEventListener('click', async () => {
  if (browserResetError || ['failed', 'resetting'].includes(experimentStatus) || pendingModelChange) return;
  const model = selectedModel();
  if (['queued','preparing','running','stopping'].includes(run.status) || controlPending || connection !== 'connected' || !model?.available) return;
  let target;
  if (selectedIdorFixture()) {
    try {
      const input = $('lab-target-origin').value.trim();
      const url = new URL(input.includes('://') ? input : `http://${input}`);
      if (url.protocol !== 'http:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error();
      target = url.origin;
      $('lab-target-origin').value = target;
      $('lab-target-origin').removeAttribute('aria-invalid');
    } catch {
      $('lab-target-origin').setAttribute('aria-invalid', 'true');
      showRuntimeError('실습 대상의 HTTP 원점(IP와 포트)만 입력하세요. 경로, 쿼리와 로그인 정보는 포함할 수 없습니다.');
      $('lab-target-origin').focus(); return;
    }
  }
  await submitControl(async () => {
    await runtime.startLab(model.id, model.mode, selectedFixture(), target);
    inspectedRun = null;
    selectedEventId = null;
    notify(selectedIdorFixture() ? `${selectedIdorFixture().name} IDOR 실습을 시작했습니다.` : `${model.name || model.id}로 실제 격리 실습을 시작했습니다.`);
  });
});
function commitFixture(id) {
  $('fixture-select').value = id;
  acceptedFixtureId = id;
  const fixture = selectedIdorFixture();
  if (fixture) $('lab-target-origin').value = `http://127.0.0.1:${fixture.port}`;
  $('lab-target-origin').removeAttribute('aria-invalid');
  renderStats();
}
$('fixture-select').addEventListener('change', () => {
  const targetFixtureId = $('fixture-select').value;
  if (pendingModelChange || controlPending || !canOperate()
    || ['queued','preparing','running','stopping'].includes(run.status)) {
    $('fixture-select').value = acceptedFixtureId; return;
  }
  if (IDOR_FIXTURES[targetFixtureId] && acceptedModelId && acceptedModelId !== 'rule-baseline') {
    $('fixture-select').value = acceptedFixtureId;
    if (settings.confirmModelReset) {
      openModelReset('rule-baseline');
      pendingModelChange.fixtureId = targetFixtureId;
      $('model-reset-description').textContent = `${IDOR_FIXTURES[targetFixtureId].name} IDOR 실습은 규칙 기반 엔진을 사용합니다. 엔진과 실습 대상을 바꾸기 전에 이전 실험의 상태를 초기화할까요?`;
    } else {
      completeModelChange('rule-baseline'); commitFixture(targetFixtureId);
    }
    return;
  }
  commitFixture(targetFixtureId);
});
$('target-url').addEventListener('input', () => { $('url-error').hidden = true; $('target-url').removeAttribute('aria-invalid'); });
$('stop-button').addEventListener('click', async () => {
  if (inspectedRun || !['queued','preparing','running'].includes(run.status)) return;
  await submitControl(() => runtime.stop(run.id));
});
$('new-session-button').addEventListener('click', async () => {
  if (['queued','preparing','running','stopping'].includes(run.status)) return;
  await submitControl(async () => {
    await runtime.reset();
    inspectedRun = null;
    selectedEventId = null;
    $('target-url').value = ''; $('url-error').hidden = true; $('target-url').removeAttribute('aria-invalid');
    navigate('dashboard');
    notify('표시용 URL을 입력해 새 로컬 코어 실행을 시작하세요.');
  });
  if (run.status === 'idle') $('target-url').focus();
});
function chooseModule(id, eventId = null) {
  selectedModule = id;
  selectedEventId = eventId;
  activeTab = ['agent','reasoning','observer'].includes(id) ? 'agent' : 'request';
  renderStats(); renderInspector(); renderActivity();
}
document.querySelectorAll('.graph-node').forEach((node) => node.addEventListener('click', () => chooseModule(node.dataset.module)));
$('agent-core').addEventListener('click', () => chooseModule('agent'));
$('activity-list').addEventListener('click', (event) => { const button = event.target.closest('[data-event]'); if (!button) return; const selected = currentRun().events.find((entry) => entry.id === button.dataset.event); if (selected) chooseModule(selected.module, selected.id); });
$('event-search').addEventListener('input', renderActivity);
document.querySelectorAll('[data-tab]').forEach((tab) => tab.addEventListener('click', () => { activeTab = tab.dataset.tab; renderInspector(); }));
document.querySelector('.inspector-tabs').addEventListener('keydown', (event) => {
  if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
  event.preventDefault(); const tabs = [...document.querySelectorAll('[data-tab]')]; const index = tabs.findIndex((tab) => tab.dataset.tab === activeTab);
  const next = event.key === 'Home' ? 0 : event.key === 'End' ? 2 : (index + (event.key === 'ArrowRight' ? 1 : 2)) % 3;
  activeTab = tabs[next].dataset.tab; renderInspector(); tabs[next].focus();
});
$('copy-button').addEventListener('click', async () => {
  const value = JSON.stringify(traceData(), null, 2);
  try { await navigator.clipboard.writeText(value); notify('JSON을 클립보드에 복사했습니다.'); }
  catch { notify('클립보드 접근이 제한되었습니다. JSON 텍스트를 선택해 복사하세요.'); }
});
$('export-button').addEventListener('click', () => {
  const item = currentRun();
  const payload = { schemaVersion: 2, mode: item.mode, simulated: item.simulated, targetContacted: item.targetContacted, exportedAt: new Date().toISOString(), session: item };
  const url = URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)], { type:'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = `ca3p-${item.id}.json`; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); notify(`${modeLabel(item)} 실행 기록의 JSON 다운로드를 요청했습니다.`);
});
$('session-list').addEventListener('click', (event) => {
  const button = event.target.closest('[data-session]'); if (!button) return;
  void openStoredRun(button.dataset.session);
});
$('return-current-button').addEventListener('click', () => { inspectedRun = null; selectedEventId = null; $('target-url').value = isLab(run) ? '' : run.target || ''; render(); notify('서버의 현재 실행으로 돌아왔습니다.'); });
$('module-grid').addEventListener('click', (event) => { const button = event.target.closest('[data-open-module]'); if (!button) return; selectedModule = button.dataset.openModule; selectedEventId = null; activeTab = 'request'; navigate('dashboard'); $('inspector-panel').scrollIntoView({ block:'start',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth' }); });
function setAutoScroll(enabled) { settings.autoScroll = enabled; $('autoscroll-button').setAttribute('aria-pressed', String(enabled)); $('scroll-setting').checked = enabled; persistSettings(); }
$('autoscroll-button').addEventListener('click', () => { setAutoScroll(!settings.autoScroll); if (settings.autoScroll) $('activity-list').scrollTop = 0; notify(settings.autoScroll ? '최신 이벤트를 자동으로 표시합니다.' : '자동 이벤트 표시를 끄었습니다.'); });
$('settings-button').addEventListener('click', () => { $('motion-setting').checked = settings.motion; $('scroll-setting').checked = settings.autoScroll; $('speed-setting').value = settings.speed; $('settings-dialog').showModal(); });
$('motion-setting').addEventListener('change', (event) => { settings.motion = event.target.checked; persistSettings(); updateStars(); });
$('scroll-setting').addEventListener('change', (event) => setAutoScroll(event.target.checked));
$('speed-setting').addEventListener('change', (event) => { settings.speed = Number(event.target.value); persistSettings(); });
$('settings-dialog').addEventListener('click', (event) => { if (event.target === $('settings-dialog')) { const rect = $('settings-dialog').getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) $('settings-dialog').close(); } });
$('notifications-button').addEventListener('click', () => { $('notification-popover').hidden = !$('notification-popover').hidden; $('notifications-button').setAttribute('aria-expanded', String(!$('notification-popover').hidden)); renderNotifications(); });
$('menu-button').addEventListener('click', () => { $('sidebar').classList.toggle('open'); $('menu-button').setAttribute('aria-expanded', String($('sidebar').classList.contains('open'))); });
document.addEventListener('click', (event) => { if (!event.target.closest('#notification-popover') && !event.target.closest('#notifications-button')) { $('notification-popover').hidden = true; $('notifications-button').setAttribute('aria-expanded','false'); } if (innerWidth <= 760 && !event.target.closest('#sidebar') && !event.target.closest('#menu-button')) { $('sidebar').classList.remove('open'); $('menu-button').setAttribute('aria-expanded','false'); } });
document.addEventListener('keydown', (event) => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); navigate('dashboard'); $('target-url').focus(); $('target-url').select(); } if (event.key === 'Escape') { $('notification-popover').hidden = true; $('notifications-button').setAttribute('aria-expanded','false'); $('sidebar').classList.remove('open'); $('menu-button').setAttribute('aria-expanded','false'); } });
function runModelName(item) {
  const model = item.manifest?.model || item.events?.find(event => event.agentOutput?.modelMetadata)?.agentOutput?.modelMetadata;
  return typeof model === 'string' ? model : model?.name || model?.model || model?.id || item.modelId || (isAiLab(item) ? 'DeepSeek' : 'RuleReasoningEngine');
}
function runRevision(item) {
  return String(item.manifest?.source?.commitSha || item.manifest?.source?.commit || item.manifest?.source?.sha || item.manifest?.commitSha || item.manifest?.gitSha || item.source?.commit || '미기록');
}
function jsonSection(title, value) {
  return `<section class="panel core-report"><h2>${escape(title)}</h2><pre tabindex="0" aria-label="${escape(title)}">${highlightJSON(redactTelemetry(value))}</pre></section>`;
}
function historyCheckMarkup(item) {
  const historyWrite = item.historyWrite;
  if (!historyWrite) return '';
  const checks = Array.isArray(historyWrite.checks) ? historyWrite.checks : [];
  return `<section class="panel history-checks"><div class="eyebrow">CASE HISTORY / EVIDENCE REVIEW</div><h2>과거 사례에 연결한 검증 기록</h2><p>${escape(({ synced: '현재 실행의 결과와 증거를 과거 사례의 check로 저장했습니다.', 'not-applicable': '이번 실행에 연결할 과거 사례가 없습니다.', failed: '과거 사례 check 저장에 실패했습니다. 실행 증거는 중앙 run에서 확인할 수 있습니다.' })[historyWrite.status] || historyWrite.status || '저장 상태 확인 중')}</p>${historyWrite.error ? `<p class="runtime-error">${escape(historyWrite.error)}</p>` : ''}${checks.map(check => {
    const id = String(check.check_id || check.id || ''); const key = `${item.id}:${id}`;
    const reviewed = check.review_status === 'reviewed';
    return `<article class="history-check"><div class="history-check-heading"><strong>${escape(check.case_id || 'case')} · revision ${escape(check.case_revision ?? '미기록')}</strong><span class="local-chip">${escape(check.result || '미판정')} / ${escape(check.review_status || '검토 대기')}</span></div><p class="mono">Check ${escape(id)}</p><details><summary>증거 메타데이터</summary><pre tabindex="0">${highlightJSON(redactTelemetry(check.evidence_metadata || check.evidence || {}))}</pre></details>${reviewed ? `<p class="review-complete">증거 검토 완료${check.review_note ? ` · ${escape(check.review_note)}` : ''}</p>` : `<form data-review-form data-run-id="${escape(item.id)}" data-check-id="${escape(id)}"><label>검토 메모<input data-review-note="${escape(key)}" value="${escape(reviewDrafts.get(key) || '')}" maxlength="1000" placeholder="확인한 증거와 검토 내용을 입력하세요" required${canOperate() ? '' : ' disabled'}></label><button class="button secondary" type="submit"${!canOperate() || pendingReviews.has(key) || !id ? ' disabled' : ''}>${pendingReviews.has(key) ? '증거 무결성 확인 중' : '증거 확인 후 검토 완료'}</button></form>`}</article>`;
  }).join('')}</section>`;
}
function renderHistoryChecks() {
  const item = currentRun(); const panel = $('history-review-panel');
  const signature = JSON.stringify([item.id, item.historyWrite, Boolean(canOperate()), [...pendingReviews]]);
  if (signature === historyReviewSignature) return;
  historyReviewSignature = signature;
  panel.innerHTML = historyCheckMarkup(item); panel.hidden = !item.historyWrite;
}
function requireLogin() {
  workspaceGeneration += 1;
  pendingModelChange = null; acceptedModelId = '';
  $('model-reset-dialog').close();
  authSession = { ...authSession, authenticated: false, authRequired: true, user: null };
  history = []; centralHistoryLoaded = false; inspectedRun = null; legacyDetail = null; comparison = null; platform = null; ciResults = null; ciError = ''; models = [];
  reviewDrafts.clear(); pendingReviews.clear(); historyReviewSignature = '';
  run = { id: '', target: '', status: 'idle', startedAt: null, elapsedMs: 0, step: 0, totalSteps: 19, iterations: 1, events: [], snapshots: {}, reviewItems: [], mode: 'core-fixture', simulated: true, targetContacted: false };
  $('user-name').textContent = '로그인 필요'; $('user-role').textContent = '인증된 세션으로 접근';
  $('logout-button').hidden = true;
  $('comparison-content').textContent = '';
  $('session-list').textContent = '';
  $('ci-content').textContent = '';
  $('ci-comparison').textContent = '';
  $('ci-count').textContent = '—';
  $('ci-source').textContent = '로그인 필요';
  $('trace-code').textContent = '';
  $('notification-list').textContent = '';
  if (!$('login-dialog').open) $('login-dialog').showModal();
  render();
}
function acceptSession(value) {
  workspaceGeneration += 1;
  authSession = value;
  $('user-name').textContent = value.user?.name || 'Local operator';
  $('user-role').textContent = ({ viewer: '조회 전용', operator: '실행 운영자', admin: '관리자' })[value.user?.role] || '로컬 운영자';
  $('logout-button').hidden = !value.authRequired || !value.authenticated;
  if (value.authRequired && !value.authenticated) { requireLogin(); return; }
  $('login-dialog').close(); $('login-error').hidden = true;
  void loadWorkspace();
}
async function loadWorkspace() {
  const generation = workspaceGeneration;
  await Promise.allSettled([refreshHistory(), refreshCiResults(), (async () => {
    const payload = await runtime.getModels();
    if (generation !== workspaceGeneration) return;
    const previous = $('model-select').value;
    models = Array.isArray(payload.models) ? payload.models.filter(item => item && typeof item.id === 'string' && ['local-lab-rule', 'local-lab-deepseek'].includes(item.mode)) : [];
    $('model-select').innerHTML = models.length ? models.map(item => `<option value="${escape(item.id)}"${item.available ? '' : ' disabled'}>${escape(item.name || item.id)}${item.available ? '' : ' · 사용 불가'}</option>`).join('') : '<option value="">실행 모델 없음</option>';
    $('model-select').value = models.find(item => item.id === previous && item.available)?.id || models.find(item => item.available)?.id || '';
    acceptedModelId = $('model-select').value;
    renderStats();
  })().catch(error => showRuntimeError(error.message)), (async () => {
    const payload = await runtime.getPlatform();
    if (generation !== workspaceGeneration) return;
    platform = redactTelemetry(payload); platformError = ''; if (activeView === 'platform') renderPlatform();
  })().catch(error => { platformError = error.message; if (activeView === 'platform') renderPlatform(); })]);
}
async function refreshCiResults() {
  if (ciRefreshPending || !authSession || (authSession.authRequired && !authSession.authenticated)) return;
  ciRefreshPending = true;
  const generation = workspaceGeneration;
  try {
    const payload = await runtime.getCiResults();
    if (generation !== workspaceGeneration) return;
    if (!payload || !Array.isArray(payload.runs)) throw new Error('통합 테스트 결과 형식을 확인할 수 없습니다.');
    ciResults = payload; ciError = '';
    $('ci-count').textContent = payload.runs.length ? String(payload.runs.length) : '—';
  } catch (error) { ciError = error.message; }
  finally { ciRefreshPending = false; if (activeView === 'ci') renderCiResults(); }
}
async function refreshHistory() {
  if (historyRefreshPending || !authSession || (authSession.authRequired && !authSession.authenticated)) return;
  historyRefreshPending = true;
  const generation = workspaceGeneration;
  try {
    const records = [];
    let offset = 0;
    while (true) {
      const payload = await runtime.listRuns({ limit: 200, offset });
      if (generation !== workspaceGeneration) return;
      if (!Array.isArray(payload.runs)) throw new Error('중앙 실행 목록 형식을 확인할 수 없습니다.');
      records.push(...payload.runs);
      offset += payload.runs.length;
      if (!payload.runs.length || !Number.isSafeInteger(payload.total) || offset >= payload.total) break;
    }
    history = records.map(item => redactTelemetry(item)).filter(item => isRun(item) || isLegacyRun(item)).sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt));
    const inspectedUpdate = inspectedRun && history.find(item => item.id === inspectedRun.id);
    if (inspectedUpdate) inspectedRun = { ...inspectedRun, reportDocument: inspectedUpdate.reportDocument };
    if (run.id && isRun(run) && !history.some(item => item.id === run.id)) history.unshift(structuredClone(run));
    centralHistoryLoaded = true; historyError = ''; updateComparisonSelectors(); render();
  } catch (error) { historyError = error.message; if (activeView === 'sessions') renderSessions(); }
  finally { historyRefreshPending = false; }
}
async function openStoredRun(id) {
  const generation = workspaceGeneration;
  try {
    const payload = await runtime.getRun(id);
    if (generation !== workspaceGeneration) return;
    const item = redactTelemetry(payload.run);
    if (isLegacyRun(item)) {
      inspectedRun = null; legacyDetail = item; selectedEventId = null;
      navigate('sessions'); $('legacy-detail').scrollIntoView({ block: 'start' });
      notify('이전 보고서를 열었습니다. 누락된 실행 조건은 비교 시 별도로 표시합니다.');
      return;
    }
    if (!isRun(item)) throw new Error('저장된 실행 형식을 확인할 수 없습니다.');
    legacyDetail = null; inspectedRun = item; selectedEventId = null; $('target-url').value = isLab(item) ? '' : item.target;
    navigate('dashboard'); notify('중앙에 저장된 실행을 열었습니다.');
  } catch (error) { showRuntimeError(error.message); }
}
function updateComparisonSelectors() {
  const options = history.map(item => `<option value="${escape(item.id)}">${escape(`${dateLabel(item.startedAt)} · ${runModelName(item)} · ${item.id}`)}</option>`).join('');
  const before = $('baseline-select').value; const after = $('candidate-select').value;
  $('baseline-select').innerHTML = $('candidate-select').innerHTML = options || '<option value="">저장된 실행 없음</option>';
  if (history.some(item => item.id === before)) $('baseline-select').value = before;
  else if (history.length > 1) $('baseline-select').value = history[1].id;
  if (history.some(item => item.id === after)) $('candidate-select').value = after;
  $('compare-button').disabled = comparisonPending || history.length < 2;
}
function comparisonConditions(conditions) {
  if (!Array.isArray(conditions)) return jsonSection('비교 조건', conditions || {});
  return `<section class="panel comparison-modules"><h2>비교 조건</h2><div class="comparison-table-wrap"><table class="comparison-table"><thead><tr><th>조건</th><th>기준</th><th>비교</th><th>확인</th></tr></thead><tbody>${conditions.map(item => `<tr><th>${escape(item.name)}</th><td>${escape(typeof item.before === 'object' ? JSON.stringify(item.before) : item.before ?? '미기록')}</td><td>${escape(typeof item.after === 'object' ? JSON.stringify(item.after) : item.after ?? '미기록')}</td><td class="${item.equal ? 'condition-match' : 'condition-difference'}">${item.available === false ? '자료 부족' : item.equal ? '동일' : '다름'}</td></tr>`).join('')}</tbody></table></div></section>`;
}
function comparisonMetrics(metrics) {
  if (!metrics?.baseline || !metrics?.candidate) return jsonSection('실행 시간 · 토큰 · 비용 · 오류 지표', metrics || {});
  const labels = { elapsedMs: '실행 시간 (ms)', events: '모듈 이벤트', modelCalls: '모델 호출', successfulModelCalls: '성공한 모델 호출', promptTokens: '입력 토큰', completionTokens: '출력 토큰', estimatedCost: '예상 비용' };
  return `<section class="panel comparison-modules"><h2>실행 지표 차이</h2><div class="comparison-table-wrap"><table class="comparison-table"><thead><tr><th>지표</th><th>기준</th><th>비교</th><th>차이</th></tr></thead><tbody>${Object.entries(labels).map(([key, label]) => {
    const measured = !['promptTokens', 'completionTokens'].includes(key) || (metrics.baseline.tokenUsageAvailable && metrics.candidate.tokenUsageAvailable);
    const before = measured ? metrics.baseline[key] : null; const after = measured ? metrics.candidate[key] : null;
    const delta = Number.isFinite(before) && Number.isFinite(after) ? after - before : null;
    return `<tr><th>${escape(label)}</th><td>${escape(before ?? '미측정')}</td><td>${escape(after ?? '미측정')}</td><td>${delta === null ? '—' : escape(`${delta > 0 ? '+' : ''}${delta}`)}</td></tr>`;
  }).join('')}</tbody></table></div><p>비용 또는 토큰 정보가 없는 경우 0으로 추정하지 않고 미측정으로 표시합니다.</p></section>`;
}
function renderComparison() {
  updateComparisonSelectors();
  if (!comparison) return;
  const compatible = comparison.compatible === true || comparison.comparable === true;
  const baseline = comparison.baseline?.run || comparison.baseline || history.find(item => item.id === comparison.baselineRunId);
  const candidate = comparison.candidate?.run || comparison.candidate || history.find(item => item.id === comparison.candidateRunId);
  const diffs = Array.isArray(comparison.moduleDiffs) ? comparison.moduleDiffs : Object.entries(comparison.moduleDiffs || {}).map(([module, diff]) => ({ module, ...diff }));
  $('comparison-content').innerHTML = `<section class="panel comparison-summary"><span class="review-tag">${compatible ? '동일 조건 비교 가능' : '조건 차이 확인 필요'}</span><h2>${escape(comparison.kind || comparison.type || '실행 결과 차이')}</h2><p>${compatible ? '서버가 기록한 비교 조건을 충족합니다.' : '코드·모델·입력·정책 중 함께 바뀐 조건이 있으면 한 모듈의 영향으로 단정할 수 없습니다.'}</p><div class="comparison-pair"><div><small>BASELINE</small><strong>${escape(baseline?.id || $('baseline-select').value)}</strong><span>${escape(baseline ? runModelName(baseline) : '')}</span></div><div><small>CANDIDATE</small><strong>${escape(candidate?.id || $('candidate-select').value)}</strong><span>${escape(candidate ? runModelName(candidate) : '')}</span></div></div></section>${comparisonConditions(comparison.conditions || comparison.compatibility)}${comparisonMetrics(comparison.metrics)}${jsonSection('Finding 추가 / 제거 / 변경', comparison.findingChanges || comparison.findingTransition || comparison.findings || {})}<section class="panel comparison-modules"><h2>모듈별 정규화 입출력 차이</h2>${diffs.length ? diffs.map(item => `<details><summary>${escape(item.module || item.name || item.id || 'module')} · ${escape(item.changed === false || item.changes?.length === 0 ? '동일' : '변경 상세')}</summary><pre tabindex="0">${highlightJSON(item)}</pre></details>`).join('') : '<p>모듈 차이가 없습니다.</p>'}</section><p class="runtime-scope">현재 AI는 규칙 엔진이 만든 단일 허용 후보를 선택합니다. 모델 비교값은 계약 준수·중단·실행 시간·토큰 비교이며 범용 취약점 탐지 정확도로 해석하지 않습니다.</p>`;
}
const ciStatusNames = { passed: '통과', failed: '실패', incomplete: '증거 부족', running: '진행 중', success: '통과', failure: '실패',
  cancelled: '취소', skipped: '건너뜀', timed_out: '시간 초과', in_progress: '진행 중', queued: '대기', unknown: '미확인' };
function ciCount(value) { return Number.isSafeInteger(value) ? value.toLocaleString('ko-KR') : '자료 없음'; }
function ciKey(item) { return `${item.runId}:${item.runAttempt}`; }
function ciJobTable(jobs) {
  return `<div class="comparison-table-wrap"><table class="comparison-table ci-table"><thead><tr><th>검증 단계 / 모듈</th><th>상태</th><th>전체</th><th>통과</th><th>실패</th><th>건너뜀</th></tr></thead><tbody>${jobs.map(job => `<tr><th>${escape(job.id)}</th><td><span class="ci-state ci-${escape(job.status)}">${escape(ciStatusNames[job.status] || job.status)}</span></td><td>${ciCount(job.tests)}</td><td>${ciCount(job.passed)}</td><td>${ciCount(job.failed)}</td><td>${ciCount(job.skipped)}</td></tr>`).join('')}</tbody></table></div>`;
}
function ciDelta(before, after) {
  if (!Number.isSafeInteger(before) || !Number.isSafeInteger(after)) return '자료 없음';
  const value = after - before;
  return value > 0 ? `+${value}` : String(value);
}
function renderCiComparison(baseline, candidate) {
  if (!baseline || !candidate) { $('ci-comparison').innerHTML = '<p class="ci-empty-compare">비교할 develop 실행이 두 건 이상 필요합니다.</p>'; return; }
  if (ciKey(baseline) === ciKey(candidate)) { $('ci-comparison').innerHTML = '<p class="ci-empty-compare">서로 다른 두 실행을 선택하세요.</p>'; return; }
  const beforeJobs = new Map((baseline.jobs || []).map(job => [job.id, job]));
  const afterJobs = new Map((candidate.jobs || []).map(job => [job.id, job]));
  const names = [...new Set([...beforeJobs.keys(), ...afterJobs.keys()])];
  const candidateIndex = ciResults?.runs?.findIndex(item => ciKey(item) === ciKey(candidate)) ?? -1;
  const sameCommit = baseline.commitSha === candidate.commitSha;
  const precedingCommit = candidateIndex >= 0
    ? ciResults.runs.slice(candidateIndex + 1).find(item => item.commitSha !== candidate.commitSha) : null;
  const matchingDiffBase = precedingCommit?.commitSha === baseline.commitSha && candidate.changedFromSha === baseline.commitSha;
  const changedModules = sameCommit ? [] : matchingDiffBase && Array.isArray(candidate.changedModules)
    ? candidate.changedModules : null;
  $('ci-comparison').innerHTML = `<p class="ci-compare-caption">기준 <strong>${escape(baseline.commitSha.slice(0, 12))}</strong> → 비교 <strong>${escape(candidate.commitSha.slice(0, 12))}</strong></p>
    <div class="ci-delta-grid"><span>전체 테스트 <strong>${ciDelta(baseline.tests, candidate.tests)}</strong></span><span>통과 <strong>${ciDelta(baseline.passed, candidate.passed)}</strong></span><span>실패 <strong>${ciDelta(baseline.failed, candidate.failed)}</strong></span><span>건너뜀 <strong>${ciDelta(baseline.skipped, candidate.skipped)}</strong></span></div>
    <p class="ci-changed-modules">코드가 바뀐 모듈: ${changedModules === null ? '이 비교 구간의 변경 경로 정보 없음' : changedModules.length ? changedModules.map(escape).join(', ') : '없음'}</p>
    ${names.length ? `<div class="comparison-table-wrap"><table class="comparison-table ci-table"><thead><tr><th>검증 단계 / 모듈</th><th>기준</th><th>비교</th><th>통과 차이</th><th>실패 차이</th><th>건너뜀 차이</th></tr></thead><tbody>${names.map(name => {
      const before = beforeJobs.get(name); const after = afterJobs.get(name);
      const changed = before?.status !== after?.status || before?.passed !== after?.passed || before?.failed !== after?.failed || before?.skipped !== after?.skipped;
      return `<tr class="${changed ? 'ci-changed-row' : ''}"><th>${escape(name)}</th><td>${escape(ciStatusNames[before?.status] || before?.status || '자료 없음')}</td><td>${escape(ciStatusNames[after?.status] || after?.status || '자료 없음')}</td><td>${ciDelta(before?.passed, after?.passed)}</td><td>${ciDelta(before?.failed, after?.failed)}</td><td>${ciDelta(before?.skipped, after?.skipped)}</td></tr>`;
    }).join('')}</tbody></table></div>` : '<p class="ci-empty-compare">Actions 단계 결과만 확인할 수 있습니다. 모듈별 수치는 공개 요약이 게시되면 표시됩니다.</p>'}
    <p class="runtime-scope">테스트 수나 통과 수 변화만으로 취약점 탐지 정확도의 향상을 뜻하지 않습니다. 코드 변경 모듈은 Git diff에서, 테스트 결과는 Actions 보고서에서 각각 기록합니다.</p>`;
}
function renderCiResults() {
  const rows = Array.isArray(ciResults?.runs) ? ciResults.runs : [];
  $('ci-count').textContent = rows.length ? String(rows.length) : '—';
  const source = ciResults?.source === 'public-feed' ? '공개 비민감 요약 · 모듈별 결과' : ciResults?.source === 'actions-api'
    ? 'GitHub Actions 공개 단계 결과 · 모듈별 수치 미제공' : '아직 수집된 결과 없음';
  const freshness = ciResults?.status === 'stale' || ciResults?.status === 'unavailable' ? ' · 동기화 실패, 마지막 저장값 표시' : '';
  $('ci-source').textContent = `${source}${ciResults?.updatedAt ? ` · ${dateLabel(ciResults.updatedAt)} 수집` : ''}${freshness}${ciError ? ` · ${ciError}` : ''}`;
  if (!rows.length) {
    $('ci-content').innerHTML = '<section class="panel empty-state"><span data-icon="check"></span><h3>develop 통합 결과를 기다리고 있습니다</h3><p>병합 후 GitHub Actions 실행과 공개 요약이 수집되면 전체 모듈 테스트를 표시합니다.</p></section>';
  } else {
    const latest = rows[0];
    const pipeline = [['tests', '전체 모듈 테스트'], ['containerSmoke', '컨테이너 기동'], ['integrationGate', '통합 게이트']];
    $('ci-content').innerHTML = `<section class="panel ci-latest"><div class="ci-latest-top"><div><div class="eyebrow">LATEST DEVELOP PUSH</div><h2><span class="ci-state ci-${escape(latest.status)}">${escape(ciStatusNames[latest.status] || latest.status)}</span> ${escape(latest.commitSha.slice(0, 12))}</h2><p>Actions 실행 ${escape(latest.runId)} · 시도 ${escape(latest.runAttempt)} · ${escape(latest.completedAt ? dateLabel(latest.completedAt) : '완료 시간 미기록')}</p></div><a class="button secondary" href="${escape(latest.runUrl)}" target="_blank" rel="noopener noreferrer">GitHub Actions에서 보기</a></div><div class="ci-totals"><div><small>전체 테스트</small><strong>${ciCount(latest.tests)}</strong></div><div><small>통과</small><strong>${ciCount(latest.passed)}</strong></div><div><small>실패</small><strong>${ciCount(latest.failed)}</strong></div><div><small>건너뜀</small><strong>${ciCount(latest.skipped)}</strong></div></div><div class="ci-pipeline">${pipeline.map(([key, name]) => `<div><span>${name}</span><strong class="ci-state ci-${escape(latest.pipeline?.[key] || 'unknown')}">${escape(ciStatusNames[latest.pipeline?.[key]] || '미확인')}</strong></div>`).join('')}</div><p class="ci-verification">${latest.status === 'passed' ? '전체 suite, 컨테이너 기동, 통합 게이트가 성공했고 실패·건너뜀 테스트가 없습니다.' : latest.completeSuite ? '실패·미완료 단계를 확인하세요. 병합된 코드의 검증을 통과했다고 표시하지 않습니다.' : '전체 suite 보고서가 없어 모듈별 검증 통과를 확인할 수 없습니다.'}</p></section>
      <section class="panel ci-jobs"><h2>모듈·검증 단계별 결과</h2>${latest.jobs?.length ? ciJobTable(latest.jobs) : '<p>공개 Actions 단계 결과만 수집했습니다. 모듈별 테스트 수는 요약 피드가 게시되면 표시됩니다.</p>'}</section>`;
  }
  const baselineSelect = $('ci-baseline'); const candidateSelect = $('ci-candidate');
  const previousBaseline = baselineSelect.value; const previousCandidate = candidateSelect.value;
  const options = rows.map(item => `<option value="${escape(ciKey(item))}">${escape(`${item.commitSha.slice(0, 12)} · ${ciStatusNames[item.status] || item.status} · ${item.completedAt ? dateLabel(item.completedAt) : '진행 중'}`)}</option>`).join('');
  baselineSelect.innerHTML = candidateSelect.innerHTML = options || '<option value="">실행 없음</option>';
  baselineSelect.value = rows.some(item => ciKey(item) === previousBaseline) ? previousBaseline : rows[1] ? ciKey(rows[1]) : '';
  candidateSelect.value = rows.some(item => ciKey(item) === previousCandidate) ? previousCandidate : rows[0] ? ciKey(rows[0]) : '';
  renderCiComparison(rows.find(item => ciKey(item) === baselineSelect.value), rows.find(item => ciKey(item) === candidateSelect.value));
}
function renderPlatform() {
  if (!platform) { $('platform-content').innerHTML = `<div class="panel empty-state"><h3>${platformError ? '통합 상태를 불러올 수 없습니다' : '통합 상태 조회 중'}</h3><p>${escape(platformError)}</p></div>`; return; }
  const source = platform.source || {};
  const modules = Array.isArray(platform.modules) ? platform.modules : Object.entries(platform.modules || {}).map(([name, value]) => ({ name, ...value }));
  $('platform-content').innerHTML = `<section class="panel platform-source"><div class="eyebrow">INTEGRATION PLATFORM</div><h2>${escape(source.branch || source.ref || '현재 통합 소스')}</h2><p class="mono">${escape(source.commitSha || source.commit || source.sha || 'SHA 미기록')}</p><p>${escape(source.dirty ? '작업 디렉터리에 변경 사항이 있습니다.' : '서버가 보고한 소스 버전과 모듈 정보를 표시합니다.')}</p><p>이 화면의 검증 파일은 서버 체크아웃에서 생성된 값입니다. develop 병합 커밋의 전체 모듈 검증은 ‘통합 테스트’에서 확인하세요.</p></section><div class="module-grid platform-modules">${modules.map(item => `<article class="panel module-card"><span class="local-chip">${escape(item.status || item.layer || 'MODULE')}</span><h2>${escape(item.name || item.id || 'module')}</h2><p>${escape(item.description || item.role || item.path || '')}</p><small>${escape(item.layer || '')}${item.sourceBranch ? ` · ${escape(item.sourceBranch)}` : ''}</small><p class="mono">${escape(item.version || item.packageVersion || item.hash || item.contentDigest || item.sha || '버전 미기록')}</p>${item.changed !== undefined ? `<small>${item.changed ? '기준 대비 변경됨' : '기준과 동일'}</small>` : ''}</article>`).join('')}</div>${jsonSection('현재 서버 체크아웃의 로컬 검증 파일', platform.tests || platform.validation || {})}${jsonSection('계층 및 모듈 연결', platform.architecture || {})}${jsonSection('소스 및 변경 모듈 상세', source)}`;
  const deployment = platform.deployment;
  if (deployment?.enabled) {
    const labels = { checking: '새 버전 확인 중', verified: 'develop CI 검증 완료', 'waiting-ci': '전체 CI 검증 대기', 'up-to-date': '최신 검증 버전 실행 중',
      preparing: '새 버전 준비 중', prepared: '배포 전 검증 완료', deferred: '배포 재시도 대기', superseded: '더 최신 버전 확인 중', deploying: '배포 적용 중',
      deployed: '자동 배포 완료', blocked: '배포 재시도에 운영자 확인 필요', failed: '배포 실패 · 이전 버전 유지',
      'recovery-required': '서비스 복구에 운영자 확인 필요', unavailable: '자동 배포 상태 확인 불가' };
    $('platform-content').insertAdjacentHTML('afterbegin', `<section class="panel platform-source"><div class="eyebrow">DEVICE DEPLOYMENT</div><h2>${escape(labels[deployment.status] || '자동 배포 상태 확인 중')}</h2><p>실행 SHA <span class="mono">${escape(deployment.deployedSha || source.commitSha || '미기록')}</span></p><p>develop SHA <span class="mono">${escape(deployment.targetSha || '확인 중')}</span></p><small>최근 확인 ${escape(dateLabel(deployment.checkedAt))} · 최근 배포 ${escape(dateLabel(deployment.deployedAt))}</small>${deployment.runUrl ? `<p><a href="${escape(deployment.runUrl)}" target="_blank" rel="noopener noreferrer">배포 대상의 전체 CI 결과</a></p>` : ''}</section>`);
    if (deployment.retryAt) $('platform-content').firstElementChild?.insertAdjacentHTML('beforeend', `<p>GitHub 검증 재시도 ${escape(dateLabel(deployment.retryAt))}</p>`);
  }
}
function completeModelChange(id, resetPerformed = false) {
  const fixtureId = pendingModelChange?.fixtureId;
  acceptedModelId = id;
  $('model-select').value = id;
  modelChangeUnreset = !resetPerformed;
  settings.modelChangeUnreset = modelChangeUnreset; persistSettings();
  pendingModelChange = null;
  if (fixtureId) commitFixture(fixtureId);
  $('model-reset-dialog').close();
  renderStats();
}
function clearExperimentView() {
  workspaceGeneration += 1;
  history = []; centralHistoryLoaded = false; inspectedRun = null; legacyDetail = null; comparison = null;
  reviewDrafts.clear(); pendingReviews.clear(); historyReviewSignature = '';
  selectedEventId = null; selectedModule = 'parser'; activeTab = 'request';
  $('event-search').value = '';
  $('comparison-content').textContent = '';
  $('legacy-detail').textContent = '';
  $('notification-list').textContent = '';
  $('target-url').value = ''; $('url-error').hidden = true; $('target-url').removeAttribute('aria-invalid');
  try { localStorage.removeItem(STORAGE); browserResetError = ''; }
  catch { browserResetError = '브라우저의 실행 캐시를 지울 수 없습니다. 이 브라우저의 사이트 데이터를 지우고 다시 초기화하세요.'; }
  updateComparisonSelectors();
  return !browserResetError;
}
function renderAllExperimentViews() {
  renderActivity(); renderInspector(); renderHistoryChecks(); renderSessions(); renderModules(); renderReports(); renderComparison();
}
$('model-reset-toggle').addEventListener('change', event => {
  settings.confirmModelReset = event.target.checked; persistSettings();
});
function openModelReset(targetId, manual = false) {
  const previousId = acceptedModelId;
  pendingModelChange = { previousId, targetId, manual };
  const target = models.find(item => item.id === targetId);
  $('model-reset-description').textContent = manual ? '현재 모델을 유지하며 이전 실험의 상태를 초기화할까요?'
    : `${target.name || target.id}로 변경하기 전에 이전 실험의 상태를 초기화할까요?`;
  $('model-reset-scope').textContent = '실행 이력, JSON·HWPX 보고서와 실험 체크를 삭제하고 관리되는 실습 상태를 초기화합니다. 비교할 이전 결과는 먼저 내보내세요. 인증, API 키, 모델 설정과 기준 지식 DB는 유지합니다. 관리되지 않는 사이트와 외부 AI 제공자의 기록은 여기서 삭제할 수 없습니다.';
  $('model-reset-error').hidden = true;
  $('model-reset-dialog').showModal(); renderStats();
}
$('model-select').addEventListener('change', () => {
  const targetId = $('model-select').value;
  const previousId = acceptedModelId;
  if (!previousId || targetId === previousId) { acceptedModelId = targetId; renderStats(); return; }
  $('model-select').value = previousId;
  if (pendingModelChange || controlPending || !canOperate() || connection !== 'connected'
    || ['queued','preparing','running','stopping'].includes(run.status)) return;
  if (!models.some(item => item.id === targetId && item.available)) return;
  if (!settings.confirmModelReset) { completeModelChange(targetId); return; }
  openModelReset(targetId);
});
$('experiment-reset-button').addEventListener('click', () => {
  if (pendingModelChange || controlPending || !canOperate() || connection !== 'connected'
    || ['queued','preparing','running','stopping'].includes(run.status)) return;
  openModelReset(acceptedModelId, true);
});
$('model-reset-no').addEventListener('click', () => {
  if (!pendingModelChange || controlPending) return;
  if (pendingModelChange.manual) { pendingModelChange = null; $('model-reset-dialog').close(); renderStats(); return; }
  completeModelChange(pendingModelChange.targetId);
  notify('실험 흔적을 유지하고 모델만 변경했습니다.');
});
$('model-reset-yes').addEventListener('click', async () => {
  if (!pendingModelChange || controlPending) return;
  const change = pendingModelChange;
  controlPending = true;
  $('model-reset-yes').disabled = true; $('model-reset-no').disabled = true;
  $('model-reset-yes').textContent = '초기화 중…'; $('model-reset-error').hidden = true;
  renderStats();
  try {
    await runtime.resetExperiment();
    if (!clearExperimentView()) throw new Error(browserResetError);
    renderAllExperimentViews();
    completeModelChange(change.targetId, true);
    await refreshHistory();
    notify(change.manual ? '모델을 유지하고 실험 흔적을 초기화했습니다.' : '실험 흔적을 초기화한 뒤 모델을 변경했습니다.');
  } catch (error) {
    $('model-select').value = change.previousId;
    $('model-reset-error').textContent = `${error.message} 모델은 변경하지 않았습니다.`;
    $('model-reset-error').hidden = false;
  } finally {
    controlPending = false;
    $('model-reset-yes').disabled = false; $('model-reset-no').disabled = false;
    $('model-reset-yes').textContent = '예'; render();
  }
});
$('model-reset-dialog').addEventListener('cancel', event => {
  if (controlPending) { event.preventDefault(); return; }
  pendingModelChange = null; renderStats();
});
document.addEventListener('input', event => { if (event.target.dataset.reviewNote) reviewDrafts.set(event.target.dataset.reviewNote, event.target.value); });
document.addEventListener('submit', async event => {
  const form = event.target.closest('[data-review-form]'); if (!form) return;
  event.preventDefault();
  const runId = form.dataset.runId; const checkId = form.dataset.checkId; const key = `${runId}:${checkId}`;
  const note = form.querySelector('[data-review-note]').value.trim();
  if (!canOperate() || pendingReviews.has(key)) return;
  if (!note) { notify('증거를 확인한 검토 메모를 입력하세요.'); return; }
  const generation = workspaceGeneration; pendingReviews.add(key); render();
  try {
    await runtime.reviewCheck(runId, checkId, note);
    const payload = await runtime.getRun(runId);
    if (generation !== workspaceGeneration) return;
    const updated = redactTelemetry(payload.run);
    if (!isRun(updated)) throw new Error('검토 후 실행 기록 형식을 확인할 수 없습니다.');
    if (inspectedRun?.id === runId) inspectedRun = updated;
    if (run.id === runId) run = updated;
    reviewDrafts.delete(key); await refreshHistory(); notify('서버가 증거 무결성을 확인하고 검토 완료를 저장했습니다.');
  } catch (error) { showRuntimeError(error.message); }
  finally { pendingReviews.delete(key); render(); }
});
$('refresh-history').addEventListener('click', () => void refreshHistory());
$('refresh-ci').addEventListener('click', () => void refreshCiResults());
$('ci-baseline').addEventListener('change', renderCiResults);
$('ci-candidate').addEventListener('change', renderCiResults);
$('compare-form').addEventListener('submit', async event => {
  event.preventDefault();
  const baseline = $('baseline-select').value; const candidate = $('candidate-select').value;
  if (!baseline || !candidate || comparisonPending) return;
  if (baseline === candidate) { notify('서로 다른 두 실행을 선택하세요.'); return; }
  const generation = workspaceGeneration;
  comparisonPending = true; $('compare-button').disabled = true;
  try {
    const value = await runtime.compare(baseline, candidate, $('comparison-kind').value);
    if (generation !== workspaceGeneration) return;
    comparison = redactTelemetry(value); renderComparison();
  }
  catch (error) { if (generation === workspaceGeneration) showRuntimeError(error.message); }
  finally { comparisonPending = false; $('compare-button').disabled = history.length < 2; }
});
$('login-dialog').addEventListener('cancel', event => event.preventDefault());
$('login-form').addEventListener('submit', async event => {
  event.preventDefault(); $('login-submit').disabled = true; $('login-error').hidden = true;
  try { await runtime.login($('login-username').value, $('login-password').value); $('login-password').value = ''; }
  catch (error) { $('login-error').textContent = error.message; $('login-error').hidden = false; }
  finally { $('login-submit').disabled = false; }
});
$('logout-button').addEventListener('click', async () => { try { await runtime.logout(); } catch (error) { showRuntimeError(error.message); } });
window.addEventListener('beforeunload', () => { saveRun(); runtime.close(); });
$('target-url').value = '';
$('autoscroll-button').setAttribute('aria-pressed', String(settings.autoScroll));
navigate(location.hash.slice(1) || 'dashboard');
runtime.connect();
setInterval(() => { if (authSession && (!authSession.authRequired || authSession.authenticated)) void refreshHistory(); }, 5000);
setInterval(() => { if (authSession && (!authSession.authRequired || authSession.authenticated)) void refreshCiResults(); }, 30_000);
