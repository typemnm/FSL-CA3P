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
  const lab = value?.mode === 'local-lab-deepseek';
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
    ['preparing','running','stopping','stopped','completed','failed'].includes(value.status);
}
const saved = readJSON(STORAGE, []);
let history = Array.isArray(saved) ? saved.filter(isRun).slice(0, 12) : [];
const storedSettings = readJSON(SETTINGS, {});
const settings = { motion: storedSettings?.motion !== false, autoScroll: storedSettings?.autoScroll !== false, speed: [900,1800,3000].includes(Number(storedSettings?.speed)) ? Number(storedSettings.speed) : 1800 };
// Browser history is read-only context. Only the server can advance the current run.
let run = { id: '', target: '', status: 'idle', startedAt: null, elapsedMs: 0, step: 0, totalSteps: 19, iterations: 1, events: [], snapshots: {}, reviewItems: [], mode: 'core-fixture', simulated: true, targetContacted: false };
let instanceId = null;
let labReadiness = { available: false };
let connection = 'connecting';
let controlPending = false;
let inspectedRun = null;
let selectedModule = 'parser';
let selectedEventId = null;
let activeTab = 'request';
let activeView = 'dashboard';
let toastTimer;
let stars;
const statusNames = { preparing: '실습 준비 중', running: '진행 중', stopping: '중지 처리 중', completed: '완료', stopped: '중지됨', failed: '실패', idle: '대기 중' };
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
  pentest: 'pentest-db가 초안 공격 정보를 제공하고 이번 실행의 요청·응답·판정을 저장합니다.',
  agent: 'RunOnce가 관찰 근거로 후보를 만들고 DeepSeek의 제한된 POST 선택과 브라우저 실행 증거를 plan / reflect로 기록합니다.',
  webpage: '서버가 만든 격리된 127.0.0.1 게시판입니다. 입력 URL은 사용하지 않습니다.',
};
const legacyLabModuleDescriptions = {
  parser: 'xss-parser가 로컬 게시판을 삭제 전후로 관찰합니다.',
  casper: 'casper-db가 과거 XSS 사례를 참고 정보로 조회합니다.',
  attack: 'attack-module이 구조화된 curl JSON으로 제한된 게시글 삭제 요청을 전송합니다.',
  guardrail: 'guardrail이 교차 사용자 삭제 canary의 범위와 요청 예산을 검사합니다.',
  pentest: 'pentest-db가 요청·응답·판정을 저장합니다.',
  agent: 'RunOnce가 삭제 권한 가설의 plan과 전후 관찰에 근거한 reflect를 기록합니다.',
  webpage: labModuleDescriptions.webpage,
};
function isLab(item) { return item?.mode === 'local-lab-deepseek'; }
function isXssLab(item) { return isLab(item) && (item.testProfile ?? item.report?.testProfile) === 'stored_xss_canary'; }
function describeModule(id, item = currentRun()) { return (isXssLab(item) ? labModuleDescriptions
  : isLab(item) ? legacyLabModuleDescriptions : moduleDescriptions)[id] || '이전 실행의 코어 이벤트입니다.'; }
function modeLabel(item) { return isXssLab(item) ? '저장형 XSS 실습 + DeepSeek'
  : isLab(item) ? '삭제 권한 실습 + DeepSeek' : '코어 fixture'; }
const viewMeta = {
  dashboard: ['대시보드', 'Observe. Decide. <span>Iterate.</span>', '에이전트의 모든 판단과 흐름을, 한눈에.'],
  sessions: ['실행 이력', 'Every run. <span>Remembered.</span>', '이 브라우저에 남아 있는 실행 기록을 다시 살펴보세요.'],
  modules: ['모듈 탐색', 'Inside the <span>loop.</span>', '각 모듈이 주고받는 데이터와 상태를 확인하세요.'],
  reports: ['리포트', 'From signals to <span>insight.</span>', '코어 실행 리포트와 모드별 검토 항목을 확인하세요.'],
};
function currentRun() { return inspectedRun || run; }
function moduleById(id) { return MODULES.find((module) => module.id === id) || EVENT_CHANNELS[id] || { id, name: '알 수 없는 이벤트', role: '이벤트', icon: 'box' }; }
function notify(message) { $('toast').textContent = message; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3300); }
function saveRun() {
  if (run.status === 'idle' || !isRun(run)) return;
  history = [structuredClone(run), ...history.filter((item) => item.id !== run.id)].slice(0, 12);
  try { localStorage.setItem(STORAGE, JSON.stringify(history)); } catch { notify('브라우저 저장 공간을 사용할 수 없습니다. 내보내기로 보관하세요.'); }
  $('history-count').textContent = history.length;
}
function showRuntimeError(message) {
  $('runtime-error').textContent = message;
  $('runtime-error').hidden = !message;
}
function acceptState(envelope) {
  const next = redactTelemetry(envelope.run);
  if (next.status !== 'idle' && !isRun(next)) throw new Error('코어 실행 상태의 데이터 형식이 올바르지 않습니다.');
  if (next.status === 'idle' && (!isObject(next.snapshots) || !Array.isArray(next.reviewItems) || next.step !== 0 || !Number.isInteger(next.totalSteps) || next.totalSteps < 1 || next.totalSteps > 128 || next.events.length !== 0)) throw new Error('코어 대기 상태의 데이터 형식이 올바르지 않습니다.');
  const sameInstance = instanceId === envelope.instanceId;
  const rank = { idle: 0, preparing: 1, running: 2, stopping: 3, stopped: 4, completed: 4, failed: 4 };
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
  saveRun();
  if (!inspectedRun && !isLab(run) && (!sameInstance || previousId !== run.id) && document.activeElement !== $('target-url')) $('target-url').value = run.target || '';
  if (selectedEventId && !currentRun().events.some((event) => event.id === selectedEventId)) selectedEventId = null;
  showRuntimeError(run.status === 'failed' ? run.error || '코어 실행에 실패했습니다.' : '');
  render();
  if (run.id === previousId && run.status !== previousStatus) {
    if (run.status === 'completed') notify('코어 실행이 완료되었습니다. 리포트를 확인하세요.');
    if (run.status === 'stopped') notify('코어 실행을 중지하고 수신한 기록을 저장했습니다.');
    if (run.status === 'failed') notify('코어 실행에 실패했습니다. 오류 내용을 확인하세요.');
  }
}
const runtime = createRuntimeClient({
  onState: acceptState,
  onConnection(state) { connection = state; renderStats(); },
  onError: showRuntimeError,
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
  const active = ['preparing', 'running', 'stopping'].includes(run.status);
  const lab = isLab(item);
  const stage = item.events.length ? moduleById(item.events.at(-1).module) : null;
  const connected = connection === 'connected';
  const connectionLabel = { connecting: '런타임 연결 중', connected: 'SSE 연결됨', disconnected: '연결 끊김 · 자동 재연결 중' }[connection];
  $('history-banner').hidden = !inspectedRun;
  $('run-status').textContent = inspectedRun ? '기록 보기' : statusNames[item.status];
  $('status-orb').className = `status-orb ${running && connected ? '' : 'stopped'}`;
  $('run-context').textContent = inspectedRun ? `${modeLabel(item)} · 저장한 실행` : !connected ? '마지막 수신 상태 · 진행 상태 갱신 대기' : lab ? '로컬 실습 게시판 · DeepSeek 판단' : '실제 코어 · 외부 모듈 fixture';
  $('execution-label').textContent = lab ? 'LOCAL LAB / DEEPSEEK' : 'CORE / FIXTURE';
  $('dashboard-mode').textContent = lab ? '실제 코어 / 로컬 실습 게시판 + DeepSeek' : '실제 코어 / 외부 모듈 fixture';
  $('elapsed-source').textContent = lab ? '로컬 실습 실행' : 'fixture 실행';
  $('iteration-value').textContent = '01';
  $('step-label').textContent = item.status === 'completed' ? '코어 실행 완료' : stage ? `최근 수신 · ${stage.role}` : '첫 이벤트 대기';
  $('total-event-count').textContent = `${item.totalSteps} 이벤트`;
  $('event-count').textContent = String(item.events.length).padStart(2, '0');
  $('elapsed-value').textContent = formatElapsed(item.elapsedMs);
  $('progress-label').textContent = item.status === 'completed' ? '모든 이벤트 수신 완료' : `수신한 코어 이벤트 · ${statusNames[item.status]}`;
  $('progress-number').textContent = `${String(item.step).padStart(2,'0')} / ${item.totalSteps} events`;
  $('progress-fill').style.width = `${Math.min(100, item.step / item.totalSteps * 100)}%`;
  $('core-state').textContent = inspectedRun ? 'SAVED SESSION' : !connected ? connection === 'connecting' ? 'CONNECTING' : 'CONNECTION LOST' : {preparing:'LAB PREPARING',running:'CORE RUNNING',stopping:'CORE STOPPING',stopped:'CORE STOPPED',completed:'CORE COMPLETE',failed:'CORE FAILED',idle:'READY TO START'}[item.status];
  $('live-label').innerHTML = `<span class="tiny-dot ${connected && running ? 'green' : 'gray'}"></span>${inspectedRun ? 'SAVED' : !connected ? 'OFFLINE' : running ? 'LIVE' : 'IDLE'}`;
  $('stream-status').textContent = connected ? 'SSE connected' : 'SSE reconnecting';
  $('connection-status').textContent = connectionLabel;
  $('connection-dot').className = `tiny-dot ${connected ? 'green' : 'gray'}`;
  $('connection-notice').hidden = connected;
  $('connection-notice').textContent = `${connectionLabel}. 표시된 상태를 보존하고 실행 제어를 잠급니다.`;
  $('pause-button').disabled = true;
  $('pause-button').setAttribute('aria-label', '일시정지 및 재개 미지원');
  $('stop-button').disabled = !!inspectedRun || !connected || controlPending || !['preparing','running'].includes(run.status);
  $('run-button').disabled = !connected || controlPending || active;
  $('lab-run-button').disabled = !connected || controlPending || active || !labReadiness.available;
  $('lab-readiness').textContent = labReadiness.available
    ? `${labReadiness.model || 'DeepSeek'} 준비됨 · 요청 실패 시 최대 ${Number.isInteger(labReadiness.possibleRetries) ? labReadiness.possibleRetries : 0}회 재시도`
    : '로컬 실습 실행이 준비되지 않았습니다. 서버의 DeepSeek 설정을 확인하세요.';
  $('new-session-button').disabled = !connected || controlPending || active;
  $('export-button').disabled = item.events.length === 0;
  $('target-url').disabled = controlPending;
  $('loop-graph').classList.toggle('is-paused', !running || !connected);
  $('webpage-caption').textContent = lab ? '격리된 로컬 게시판' : '표시용 URL';
  document.querySelector('.graph-webpage').classList.toggle('contacted', item.targetContacted);
  const graphSources = lab
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
    const reasoning = getAgentEvent();
    return reasoning ? { source: lab && reasoning.stage === 'loop.think' ? 'DeepSeek + RuleReasoningEngine' : 'RuleReasoningEngine', mode: item.mode, fixtureInputs: !lab, correlationId: reasoning.correlationId, input: reasoning.agentInput, output: reasoning.agentOutput } : { status: 'waiting', mode: item.mode, message: lab ? 'DeepSeek curl 요청과 코어 plan / reflect 입출력을 기다리고 있습니다.' : 'RuleReasoningEngine의 plan / reflect 입출력을 기다리고 있습니다.' };
  }
  return snapshot?.[activeTab] || { status: 'waiting', mode: item.mode, simulated: item.simulated, module: selectedModule, message: '이 모듈의 첫 코어 이벤트를 기다리고 있습니다.' };
}
function highlightJSON(data) {
  const raw = JSON.stringify(data, null, 2);
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
  $('context-module').textContent = activeTab === 'agent' && lab ? 'Agent / RunOnce + DeepSeek' : activeTab === 'agent' ? 'Agent / RunOnce' : module.name;
  $('context-role').textContent = describeModule(activeTab === 'agent' ? 'agent' : selectedModule);
  $('correlation-value').textContent = contextEvent?.correlationId || '—';
  $('trace-source').textContent = activeTab === 'agent' ? lab ? 'DeepSeek · Agent / RunOnce' : 'Agent / RunOnce · fixture 입력'
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
  $('session-list').innerHTML = history.length ? history.map((item) => `<div class="session-row"><div class="session-target">${escape(item.target)}<small>${escape(modeLabel(item))} · ${escape(item.id)}</small></div><span class="state-chip ${escape(item.status)}"><span class="tiny-dot ${item.status === 'running' || item.status === 'completed' ? 'green' : 'gray'}"></span>${statusNames[item.status]}</span><span class="session-stat session-events">${item.events.length} events</span><span class="session-stat session-date">${escape(dateLabel(item.startedAt))}</span><button class="button secondary" data-session="${escape(item.id)}">열기 ${icon('code')}</button></div>`).join('') : `<div class="empty-state"><span data-icon="layers"></span><h3>아직 저장된 실행이 없습니다</h3><p>로컬 코어 이벤트를 수신하면 실행 이력이 자동으로 기록됩니다.</p></div>`;
  hydrateIcons($('session-list'));
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
function renderReports() {
  const item = currentRun();
  const lab = isLab(item);
  const note = isXssLab(item)
    ? `서버가 생성한 격리된 로컬 게시판(${escape(item.target || '준비 중')})에서 XSS 가설 한 건을 검사합니다. ${item.targetContacted ? '실습 사이트에 HTTP 요청을 보냈습니다.' : '아직 실습 사이트로 보낸 HTTP 요청은 없습니다.'} DeepSeek가 선택한 구조화된 curl 요청은 정책 검사를 거쳐 전송하며, finding은 동일 시험 게시글의 브라우저 실행 증거로 판정합니다. 입력 URL은 사용하지 않습니다.`
    : lab ? `서버가 생성한 격리된 로컬 게시판(${escape(item.target || '준비 중')})에서 삭제 권한 가설 한 건을 검사했습니다. 입력 URL은 사용하지 않았습니다.`
    : 'RunOnce와 RuleReasoningEngine의 실제 코어 실행 결과입니다. 외부 모듈의 응답은 scripted fixture이며, 입력 URL은 표시용 메타데이터입니다. 실제 대상에 접속하거나 취약점을 확인하지 않았습니다.';
  $('report-content').innerHTML = `<section class="panel report-top"><div><div class="eyebrow">${lab ? 'ISOLATED LOCAL LAB REPORT' : 'CORE FIXTURE REPORT'}</div><h2>${lab ? '로컬 실습 게시판 실행 결과' : '코어 실행 결과와 fixture 검토 항목'}</h2><p>${escape(item.target || '실행 전')}</p><small>${escape(statusNames[item.status])} · ${item.step} / ${item.totalSteps} 이벤트 · ${escape(formatElapsed(item.elapsedMs))}</small></div><div class="report-count"><strong>${String(item.reviewItems.length).padStart(2,'0')}</strong><span>${lab ? '로컬 실습 검토 항목' : 'fixture 검토 항목'}</span></div></section><div class="report-items">${item.reviewItems.length ? item.reviewItems.map((review) => `<article class="panel report-item"><span class="review-tag"><span class="tiny-dot"></span>${lab ? review.vulnerabilityConfirmed ? 'LOCAL LAB · CONFIRMED' : 'LOCAL LAB · REVIEW' : 'FIXTURE · UNCONFIRMED'}</span><h2>${escape(review.title)}</h2><p>${escape(review.description)}</p><div class="evidence-box"><strong>${lab ? 'LOCAL LAB' : 'FIXTURE'} EVIDENCE / ${escape(review.evidenceId)}</strong>${escape(review.evidence)}</div></article>`).join('') : `<section class="panel empty-state"><span data-icon="file"></span><h3>최종 ${lab ? '실습' : 'fixture'} 결과 대기</h3><p>코어 실행 완료 후 검토 항목이 표시됩니다.</p></section>`}</div><div class="report-note">${note}</div>${item.report ? `<section class="panel core-report"><h2>${icon('file')}RunOnce 최종 리포트</h2><p>코어가 반환한 결과 · 내부 실행 ID ${escape(item.coreRunId || '—')} · 코어 origin ${escape(item.coreTargetOrigin || (lab ? '—' : 'http://127.0.0.1:3000'))}</p><pre tabindex="0" aria-label="RunOnce 최종 리포트 JSON">${highlightJSON(item.report)}</pre></section>` : ''}`;
  hydrateIcons($('report-content'));
}
function renderNotifications() {
  $('notification-list').innerHTML = currentRun().events.slice(-3).reverse().map((event) => `<div class="notification-event">${escape(event.title)}<small>${escape(moduleById(event.module).name)} · ${escape(timeLabel(event.time))}</small></div>`).join('') || '<div class="notification-event">아직 이벤트가 없습니다.</div>';
}
function render() {
  $('history-count').textContent = history.length;
  renderStats();
  if (activeView === 'dashboard') { renderActivity(); renderInspector(); }
  if (activeView === 'sessions') renderSessions();
  if (activeView === 'modules') renderModules();
  if (activeView === 'reports') renderReports();
  if (!$('notification-popover').hidden) renderNotifications();
  updateStars();
}

document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => navigate(button.dataset.view)));
window.addEventListener('hashchange', () => navigate(location.hash.slice(1)));
async function submitControl(action) {
  if (controlPending || connection !== 'connected') return;
  controlPending = true;
  showRuntimeError('');
  renderStats();
  try { await action(); }
  catch (error) { showRuntimeError(error.message); notify('로컬 런타임 요청에 실패했습니다. 오류 내용을 확인하세요.'); }
  finally { controlPending = false; render(); }
}
$('target-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (['preparing','running','stopping'].includes(run.status) || controlPending || connection !== 'connected') return;
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
  if (['preparing','running','stopping'].includes(run.status) || controlPending || connection !== 'connected' || !labReadiness.available) return;
  await submitControl(async () => {
    await runtime.startLab();
    inspectedRun = null;
    selectedEventId = null;
    notify('서버가 만든 로컬 실습 게시판을 시작했습니다. DeepSeek API 호출은 과금될 수 있습니다.');
  });
});
$('target-url').addEventListener('input', () => { $('url-error').hidden = true; $('target-url').removeAttribute('aria-invalid'); });
$('stop-button').addEventListener('click', async () => {
  if (inspectedRun || !['preparing','running'].includes(run.status)) return;
  await submitControl(() => runtime.stop(run.id));
});
$('new-session-button').addEventListener('click', async () => {
  if (['preparing','running','stopping'].includes(run.status)) return;
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
  const item = history.find((entry) => entry.id === button.dataset.session); if (!item) return;
  inspectedRun = structuredClone(item); selectedEventId = null; $('target-url').value = isLab(inspectedRun) ? '' : inspectedRun.target; navigate('dashboard'); notify('저장된 스냅샷을 열었습니다. 서버의 현재 실행은 계속 진행됩니다.');
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
window.addEventListener('beforeunload', () => { saveRun(); runtime.close(); });
$('target-url').value = '';
$('autoscroll-button').setAttribute('aria-pressed', String(settings.autoScroll));
navigate(location.hash.slice(1) || 'dashboard');
runtime.connect();
