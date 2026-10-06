import { MODULES, createRun, tickRun, validateTarget, formatElapsed } from './engine.js';
import { initStarfield } from './starfield.js';

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

const STORAGE = 'ca3p.loop.sessions.v1';
const SETTINGS = 'ca3p.loop.settings.v1';
function readJSON(key, fallback) { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } }
function isObject(value) { return value && typeof value === 'object' && !Array.isArray(value); }
function isEvent(value) {
  return isObject(value) && MODULES.some((module) => module.id === value.module) &&
    ['id','time','title','detail','correlationId'].every((key) => typeof value[key] === 'string') &&
    Number.isFinite(Date.parse(value.time)) && Number.isFinite(value.latency) && value.latency >= 0 &&
    Number.isInteger(value.iteration) && value.iteration >= 1 && value.iteration <= 3 &&
    isObject(value.request) && isObject(value.response) &&
    (value.module !== 'reasoning' || (isObject(value.agentInput) && isObject(value.agentOutput)));
}
function isRun(value) {
  return isObject(value) && typeof value.id === 'string' && validateTarget(value.target).ok &&
    Number.isFinite(Date.parse(value.startedAt)) && Number.isFinite(value.elapsedMs) && value.elapsedMs >= 0 &&
    Number.isInteger(value.step) && value.step >= 0 && value.step <= 18 && value.totalSteps === 18 &&
    Array.isArray(value.events) && value.events.length === value.step && value.events.every(isEvent) &&
    isObject(value.snapshots) && Object.entries(value.snapshots).every(([id,event]) => isEvent(event) && id === event.module) &&
    Array.isArray(value.reviewItems) && value.reviewItems.length <= 3 && value.reviewItems.every((item) => isObject(item) && ['id','title','description','evidence','evidenceId'].every((key) => typeof item[key] === 'string')) &&
    ['running','paused','stopped','completed'].includes(value.status);
}
const saved = readJSON(STORAGE, []);
let history = Array.isArray(saved) ? saved.filter(isRun).slice(0, 12) : [];
const storedSettings = readJSON(SETTINGS, {});
const settings = { motion: storedSettings?.motion !== false, autoScroll: storedSettings?.autoScroll !== false, speed: [900,1800,3000].includes(Number(storedSettings?.speed)) ? Number(storedSettings.speed) : 1800 };
let run = history.length ? structuredClone(history[0]) : createRun('https://demo.ca3p.local', { initialSteps: 8 });
if (history.length && run.status === 'running') run.status = 'paused';
let inspectedRun = null;
let selectedModule = 'reasoning';
let selectedEventId = null;
let activeTab = 'request';
let activeView = 'dashboard';
let accumulated = 0;
let lastFrame = performance.now();
let toastTimer;
let stars;
const statusNames = { running: '진행 중', paused: '일시정지', completed: '완료', stopped: '중지됨', idle: '대기 중' };
const moduleDescriptions = {
  browser: '예시 사이트 구조와 응답 메타데이터를 관찰합니다.',
  knowledge: '관찰 자료와 관련된 예시 검토 지식을 조회합니다.',
  reasoning: '관찰 근거를 입력받아 에이전트의 검토 요약을 출력합니다.',
  policy: '시뮬레이션 범위와 허용된 검토 작업을 확인합니다.',
  observer: '검토 항목의 예시 근거와 참조 정보를 확인합니다.',
  recorder: '반복별 이벤트와 검토 결과를 실행 기록으로 남깁니다.',
};
const viewMeta = {
  dashboard: ['대시보드', 'Observe. Decide. <span>Iterate.</span>', '에이전트의 모든 판단과 흐름을, 한눈에.'],
  sessions: ['실행 이력', 'Every run. <span>Remembered.</span>', '이 브라우저에 남아 있는 실행 기록을 다시 살펴보세요.'],
  modules: ['모듈 탐색', 'Inside the <span>loop.</span>', '각 모듈이 주고받는 데이터와 상태를 확인하세요.'],
  reports: ['리포트', 'From signals to <span>insight.</span>', '모의 관찰 결과와 사람이 검토할 항목을 모았습니다.'],
};
function currentRun() { return inspectedRun || run; }
function moduleById(id) { return MODULES.find((module) => module.id === id) || MODULES[0]; }
function notify(message) { $('toast').textContent = message; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3300); }
function saveRun() {
  if (run.status === 'idle') return;
  history = [structuredClone(run), ...history.filter((item) => item.id !== run.id)].slice(0, 12);
  try { localStorage.setItem(STORAGE, JSON.stringify(history)); } catch { notify('브라우저 저장 공간을 사용할 수 없습니다. 내보내기로 보관하세요.'); }
  $('history-count').textContent = history.length;
}
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
  const stage = MODULES[Math.min(item.step, item.totalSteps - 1) % MODULES.length];
  $('history-banner').hidden = !inspectedRun;
  $('run-status').textContent = inspectedRun ? '기록 보기' : statusNames[item.status];
  $('status-orb').className = `status-orb ${item.status === 'paused' ? 'paused' : running ? '' : 'stopped'}`;
  $('run-context').textContent = inspectedRun ? '저장한 실행 · 읽기 전용' : item.status === 'completed' ? '18단계 기록 완료' : '로컬 시뮬레이션';
  $('iteration-value').textContent = String(Math.min(3, Math.floor(item.step / 6) + 1)).padStart(2, '0');
  $('step-label').textContent = item.status === 'completed' ? '모든 반복 완료' : stage.role;
  $('event-count').textContent = String(item.events.length).padStart(2, '0');
  $('elapsed-value').textContent = formatElapsed(item.elapsedMs);
  $('progress-label').textContent = item.status === 'completed' ? '모든 단계 완료' : `${stage.role} ${item.status === 'paused' ? '· 일시정지' : item.status === 'stopped' ? '· 중지됨' : item.status === 'idle' ? '· 대기 중' : '진행'}`;
  $('progress-number').textContent = `${String(item.step).padStart(2,'0')} / 18 steps`;
  $('progress-fill').style.width = `${item.step / 18 * 100}%`;
  $('core-state').textContent = inspectedRun ? 'SAVED SESSION' : {running:'LOOP RUNNING',paused:'LOOP PAUSED',stopped:'LOOP STOPPED',completed:'LOOP COMPLETE',idle:'READY TO START'}[item.status];
  $('live-label').innerHTML = `<span class="tiny-dot ${running ? 'green' : 'gray'}"></span>${running ? 'LIVE' : inspectedRun ? 'SAVED' : 'IDLE'}`;
  $('stream-status').textContent = running ? 'stream active' : 'stream idle';
  $('pause-button').innerHTML = icon(item.status === 'paused' ? 'play' : 'pause');
  $('pause-button').setAttribute('aria-label', item.status === 'paused' ? '루프 재개' : '루프 일시정지');
  $('pause-button').disabled = !!inspectedRun || !['running','paused'].includes(run.status);
  $('stop-button').disabled = !!inspectedRun || !['running','paused'].includes(run.status);
  $('run-button').disabled = !inspectedRun && ['running','paused'].includes(run.status);
  $('export-button').disabled = item.events.length === 0;
  $('loop-graph').classList.toggle('is-paused', !running);
  document.querySelectorAll('.graph-node').forEach((node) => {
    node.classList.toggle('selected', node.dataset.module === selectedModule);
    node.classList.toggle('done', !!item.snapshots[node.dataset.module]);
    node.classList.toggle('current', ['running','paused'].includes(item.status) && node.dataset.module === stage.id);
    node.setAttribute('aria-pressed', String(node.dataset.module === selectedModule));
  });
}
function renderActivity() {
  const item = currentRun();
  const query = $('event-search').value.trim().toLowerCase();
  const events = item.events.filter((event) => `${moduleById(event.module).name} ${event.title} ${event.detail} ${event.correlationId}`.toLowerCase().includes(query)).slice().reverse();
  const previousScroll = $('activity-list').scrollTop;
  $('activity-counter').textContent = String(item.events.length).padStart(2,'0');
  $('activity-list').innerHTML = events.length ? events.map((event) => `<button class="activity-event ${event.id === selectedEventId ? 'active' : ''}" data-event="${escape(event.id)}"><span class="event-indicator">${icon(event.type === 'success' ? 'check' : moduleById(event.module).icon)}</span><span class="event-copy"><span class="event-meta"><span>${escape(moduleById(event.module).name.replace(' Engine','').replace('Observation Review','Observer'))}</span><span class="event-time">${escape(timeLabel(event.time))}</span></span><span class="event-title">${escape(event.title)}</span><span class="event-detail">${escape(event.detail)}</span></span></button>`).join('') : `<div class="empty-state compact"><span data-icon="pulse"></span><h3>${query ? '일치하는 이벤트가 없습니다' : '첫 이벤트를 기다리는 중'}</h3><p>${query ? '다른 검색어를 입력해 보세요.' : 'URL을 입력하고 모의 루프를 시작하세요.'}</p></div>`;
  hydrateIcons($('activity-list'));
  $('activity-list').scrollTop = settings.autoScroll ? 0 : previousScroll;
  if (!$('notification-popover').hidden) renderNotifications();
}
function getSnapshot() { const item = currentRun(); return selectedEventId ? item.events.find((event) => event.id === selectedEventId) : item.snapshots[selectedModule]; }
function getAgentEvent() { const snapshot = getSnapshot(); return snapshot?.module === 'reasoning' ? snapshot : currentRun().events.filter((event) => event.module === 'reasoning' && (!snapshot || event.iteration === snapshot.iteration)).at(-1); }
function traceData() {
  const snapshot = getSnapshot();
  const item = currentRun();
  if (activeTab === 'agent') {
    const reasoning = getAgentEvent();
    return reasoning ? { source: 'local-simulation', correlationId: reasoning.correlationId, input: reasoning.agentInput, output: reasoning.agentOutput } : { status: 'waiting', simulated: true, message: '해당 반복의 에이전트 입출력을 기다리고 있습니다.' };
  }
  return snapshot?.[activeTab] || { status: 'waiting', simulated: true, module: selectedModule, message: '이 모듈의 첫 이벤트를 기다리고 있습니다.' };
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
  const snapshot = getSnapshot();
  const contextEvent = activeTab === 'agent' ? getAgentEvent() : snapshot;
  $('selected-module-name').textContent = module.name;
  $('context-module').textContent = activeTab === 'agent' ? 'Reasoning Engine' : module.name;
  $('context-role').textContent = moduleDescriptions[activeTab === 'agent' ? 'reasoning' : selectedModule];
  $('correlation-value').textContent = contextEvent?.correlationId || '—';
  $('trace-state').textContent = contextEvent ? '응답 수신 · 모의 데이터' : '이벤트 대기';
  $('trace-latency').textContent = contextEvent ? `${contextEvent.latency} ms · 모의` : '—';
  $('code-filename').textContent = activeTab === 'agent' ? 'agent-io.json' : `${activeTab}.json`;
  $('request-tab-count').textContent = $('response-tab-count').textContent = snapshot ? '01' : '00';
  document.querySelectorAll('[data-tab]').forEach((el) => { el.classList.toggle('active', el.dataset.tab === activeTab); el.setAttribute('aria-selected', String(el.dataset.tab === activeTab)); el.setAttribute('tabindex', el.dataset.tab === activeTab ? '0' : '-1'); el.setAttribute('aria-controls', 'trace-code'); });
  $('trace-code').setAttribute('role','tabpanel');
  $('trace-code').innerHTML = highlightJSON(traceData());
}
function renderSessions() {
  $('session-list').innerHTML = history.length ? history.map((item) => `<div class="session-row"><div class="session-target">${escape(item.target)}<small>${escape(item.id)}</small></div><span class="state-chip ${escape(item.status)}"><span class="tiny-dot ${item.status === 'running' || item.status === 'completed' ? 'green' : 'gray'}"></span>${statusNames[item.status]}</span><span class="session-stat session-events">${item.events.length} events</span><span class="session-stat session-date">${escape(dateLabel(item.startedAt))}</span><button class="button secondary" data-session="${escape(item.id)}">열기 ${icon('code')}</button></div>`).join('') : `<div class="empty-state"><span data-icon="layers"></span><h3>아직 저장된 실행이 없습니다</h3><p>모의 루프를 시작하면 실행 이력이 자동으로 기록됩니다.</p></div>`;
  hydrateIcons($('session-list'));
}
function renderModules() {
  const item = currentRun();
  $('module-grid').innerHTML = MODULES.map((module) => {
    const count = item.events.filter((event) => event.module === module.id).length;
    const snapshot = item.snapshots[module.id];
    return `<article class="panel module-card"><div class="module-card-top"><span data-icon="${module.icon}"></span><span class="local-chip">SIMULATED</span></div><h2>${escape(module.name)}</h2><p>${escape(moduleDescriptions[module.id])}</p><div class="module-metrics"><span><strong>${String(count).padStart(2,'0')}</strong>REQUESTS</span><span><strong>${String(count).padStart(2,'0')}</strong>RESPONSES</span><span><strong>${snapshot?.latency || '—'}</strong>MOCK MS</span></div><button class="button secondary" data-open-module="${module.id}">데이터 확인 ${icon('code')}</button></article>`;
  }).join('');
  hydrateIcons($('module-grid'));
}
function renderReports() {
  const item = currentRun();
  $('report-content').innerHTML = `<section class="panel report-top"><div><div class="eyebrow">SIMULATION REPORT</div><h2>관찰 결과와 검토 항목</h2><p>${escape(item.target)}</p><small>${escape(statusNames[item.status])} · ${item.step} / 18 단계 · ${escape(formatElapsed(item.elapsedMs))}</small></div><div class="report-count"><strong>${String(item.reviewItems.length).padStart(2,'0')}</strong><span>검토 항목</span></div></section><div class="report-items">${item.reviewItems.length ? item.reviewItems.map((review) => `<article class="panel report-item"><span class="review-tag"><span class="tiny-dot"></span>HUMAN REVIEW</span><h2>${escape(review.title)}</h2><p>${escape(review.description)}</p><div class="evidence-box"><strong>SIMULATED EVIDENCE / ${escape(review.evidenceId)}</strong>${escape(review.evidence)}</div></article>`).join('') : `<section class="panel empty-state"><span data-icon="file"></span><h3>검토 항목을 기다리는 중</h3><p>결과 검토 단계가 완료되면 항목이 표시됩니다.</p></section>`}</div><div class="report-note">이 리포트는 로컬 예시 데이터로 생성했습니다. 실제 대상의 응답을 수집하거나 취약점을 확인한 결과가 아닙니다.</div><section class="panel recommendations"><h2>${icon('sparkles')}다음 단계 제안</h2><div class="recommendation-list"><div class="recommendation"><strong>승인 범위와 실행 예산</strong>운영 환경에서는 허용된 대상과 경로, 실행 시간, 단계 한도를 실행 기록과 함께 관리하세요.</div><div class="recommendation"><strong>민감정보 마스킹</strong>관측 로그를 연동할 때 토큰·쿠키·개인정보를 마스킹하고 원본 열람 권한을 분리하세요.</div><div class="recommendation"><strong>실제 관측 이벤트 연동</strong>읽기 전용 SSE 이벤트 스트림을 연결하면 기존 실행의 상태와 요청·응답을 실시간으로 표시할 수 있습니다.</div></div></section>`;
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
$('target-form').addEventListener('submit', (event) => {
  event.preventDefault();
  if (!inspectedRun && ['running','paused'].includes(run.status)) return;
  const validated = validateTarget($('target-url').value);
  $('url-error').hidden = validated.ok;
  $('target-url').setAttribute('aria-invalid', String(!validated.ok));
  if (!validated.ok) { $('url-error').textContent = validated.error; $('target-url').focus(); return; }
  if (run.status === 'running' || run.status === 'paused') { run.status = 'stopped'; saveRun(); }
  run = createRun(validated.url); inspectedRun = null; selectedEventId = null; accumulated = 0; lastFrame = performance.now();
  $('target-url').value = validated.url; saveRun(); render(); notify('모의 루프를 시작했습니다. 입력한 사이트에 접속하지 않습니다.');
});
$('target-url').addEventListener('input', () => { $('url-error').hidden = true; $('target-url').removeAttribute('aria-invalid'); });
$('pause-button').addEventListener('click', () => {
  if (inspectedRun || !['running','paused'].includes(run.status)) return;
  run.status = run.status === 'running' ? 'paused' : 'running'; lastFrame = performance.now(); saveRun(); render();
  notify(run.status === 'paused' ? '루프를 일시정지했습니다.' : '루프를 재개했습니다.');
});
$('stop-button').addEventListener('click', () => { if (inspectedRun || !['running','paused'].includes(run.status)) return; run.status = 'stopped'; saveRun(); render(); notify('루프를 중지하고 실행 기록을 저장했습니다.'); });
$('new-session-button').addEventListener('click', () => {
  if (['running','paused'].includes(run.status)) { run.status = 'stopped'; saveRun(); }
  run = createRun(run.target); run.status = 'idle'; inspectedRun = null; selectedEventId = null; accumulated = 0;
  $('target-url').value = ''; $('url-error').hidden = true; $('target-url').removeAttribute('aria-invalid'); navigate('dashboard'); $('target-url').focus();
  notify('대상 URL을 입력해 새 모의 루프를 시작하세요.');
});
function chooseModule(id, eventId = null) { selectedModule = id; selectedEventId = eventId; renderStats(); renderInspector(); renderActivity(); }
document.querySelectorAll('.graph-node').forEach((node) => node.addEventListener('click', () => chooseModule(node.dataset.module)));
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
  const payload = { schemaVersion: 1, mode: 'local-simulation', simulated: true, targetContacted: false, exportedAt: new Date().toISOString(), session: item };
  const url = URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)], { type:'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = `ca3p-${item.id}.json`; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); notify('모의 실행 기록의 JSON 다운로드를 요청했습니다.');
});
$('session-list').addEventListener('click', (event) => {
  const button = event.target.closest('[data-session]'); if (!button) return;
  const item = history.find((entry) => entry.id === button.dataset.session); if (!item) return;
  if (run.status === 'running') { run.status = 'paused'; saveRun(); }
  inspectedRun = structuredClone(item); selectedEventId = null; $('target-url').value = inspectedRun.target; navigate('dashboard'); notify('저장된 실행을 열었습니다. 새 실행으로 다시 시작할 수 있습니다.');
});
$('return-current-button').addEventListener('click', () => { inspectedRun = null; selectedEventId = null; $('target-url').value = run.target; render(); notify(run.status === 'paused' ? '현재 실행으로 돌아왔습니다. 일시정지된 루프를 재개할 수 있습니다.' : '현재 실행으로 돌아왔습니다.'); });
$('module-grid').addEventListener('click', (event) => { const button = event.target.closest('[data-open-module]'); if (!button) return; selectedModule = button.dataset.openModule; selectedEventId = null; navigate('dashboard'); $('inspector-panel').scrollIntoView({ block:'start',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth' }); });
function setAutoScroll(enabled) { settings.autoScroll = enabled; $('autoscroll-button').setAttribute('aria-pressed', String(enabled)); $('scroll-setting').checked = enabled; persistSettings(); }
$('autoscroll-button').addEventListener('click', () => { setAutoScroll(!settings.autoScroll); if (settings.autoScroll) $('activity-list').scrollTop = 0; notify(settings.autoScroll ? '최신 이벤트를 자동으로 표시합니다.' : '자동 이벤트 표시를 끄었습니다.'); });
$('settings-button').addEventListener('click', () => { $('motion-setting').checked = settings.motion; $('scroll-setting').checked = settings.autoScroll; $('speed-setting').value = settings.speed; $('settings-dialog').showModal(); });
$('motion-setting').addEventListener('change', (event) => { settings.motion = event.target.checked; persistSettings(); updateStars(); });
$('scroll-setting').addEventListener('change', (event) => setAutoScroll(event.target.checked));
$('speed-setting').addEventListener('change', (event) => { settings.speed = Number(event.target.value); accumulated = 0; persistSettings(); });
$('settings-dialog').addEventListener('click', (event) => { if (event.target === $('settings-dialog')) { const rect = $('settings-dialog').getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) $('settings-dialog').close(); } });
$('notifications-button').addEventListener('click', () => { $('notification-popover').hidden = !$('notification-popover').hidden; $('notifications-button').setAttribute('aria-expanded', String(!$('notification-popover').hidden)); renderNotifications(); });
$('menu-button').addEventListener('click', () => { $('sidebar').classList.toggle('open'); $('menu-button').setAttribute('aria-expanded', String($('sidebar').classList.contains('open'))); });
document.addEventListener('click', (event) => { if (!event.target.closest('#notification-popover') && !event.target.closest('#notifications-button')) { $('notification-popover').hidden = true; $('notifications-button').setAttribute('aria-expanded','false'); } if (innerWidth <= 760 && !event.target.closest('#sidebar') && !event.target.closest('#menu-button')) { $('sidebar').classList.remove('open'); $('menu-button').setAttribute('aria-expanded','false'); } });
document.addEventListener('keydown', (event) => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); navigate('dashboard'); $('target-url').focus(); $('target-url').select(); } if (event.key === 'Escape') { $('notification-popover').hidden = true; $('notifications-button').setAttribute('aria-expanded','false'); $('sidebar').classList.remove('open'); $('menu-button').setAttribute('aria-expanded','false'); } });
window.addEventListener('beforeunload', saveRun);
$('target-url').value = run.target;
$('autoscroll-button').setAttribute('aria-pressed', String(settings.autoScroll));
if (!history.length || run.status === 'paused') saveRun();
navigate(location.hash.slice(1) || 'dashboard');
setInterval(() => {
  const now = performance.now(); const delta = Math.max(0, now - lastFrame); lastFrame = now;
  if (run.status !== 'running') return;
  run.elapsedMs += delta; accumulated += delta;
  if (!inspectedRun) $('elapsed-value').textContent = formatElapsed(run.elapsedMs);
  if (accumulated >= settings.speed) {
    accumulated %= settings.speed; tickRun(run,0); saveRun(); render();
    if (run.status === 'completed') notify('3회 반복이 완료되었습니다. 리포트에서 검토 항목을 확인하세요.');
  }
},250);
