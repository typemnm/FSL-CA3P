/** Workspace DB and module operations. Server data remains the source of truth. */
import { renderIntakes, renderIntakeDetail } from './db-intakes.js';
import { collectReviewItem, candidateValue } from './db-review.js';
import { readProduct, renderAdvisories } from './db-advisories.js';
import { renderDbHealth } from './db-health.js';
const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char]);
const json = value => JSON.stringify(value ?? {}, null, 2);
const date = value => value ? new Date(value).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' }) : '—';
const moduleNames = { attack: 'Attack Module', 'web-parser': 'Web Parser', guardrail: 'Guardrail', llm: 'LLM', db: 'DB' };
const moduleAliases = { attack: ['attack-module', 'attack'], 'web-parser': ['web-parser', 'xss-parser'], guardrail: ['guardrail'], llm: ['llm', 'models', 'agent'], db: ['casper-db', 'db'] };
const editableCaseFields = [
  'title', 'vulnerability_type', 'severity', 'status', 'patch_status', 'description', 'remediation',
  'vulnerability_url', 'endpoint', 'method', 'parameter', 'parameter_location', 'route_template',
  'preconditions', 'procedure', 'payload', 'success_condition', 'prior_evidence', 'reported_on',
];
const caseLabels = {
  title: '제목', vulnerability_type: '취약점 유형', severity: '심각도', status: '상태', patch_status: '패치 상태',
  description: '설명', remediation: '해결 방안', vulnerability_url: '취약 URL', endpoint: '엔드포인트',
  method: '메서드', parameter: '파라미터', parameter_location: '파라미터 위치', route_template: '경로 템플릿',
  preconditions: '사전 조건', procedure: '재현 절차', payload: 'Payload', success_condition: '성공 조건',
  prior_evidence: '기존 증거', reported_on: '보고일',
};
const longFields = new Set(['description', 'remediation', 'preconditions', 'procedure', 'payload', 'success_condition', 'prior_evidence']);
const loopBudgetFields = [
  { key: 'maxIterations', label: '반복 횟수' },
  { key: 'maxProbes', label: '검사 요청 수' },
  { key: 'maxEvidenceItems', label: '증거 항목 수' },
];

function validLoopBudget(value) {
  return value && ['limits', 'defaults', 'caps'].every(group =>
    value[group] && loopBudgetFields.every(({ key }) => Number.isSafeInteger(value[group][key])
      && value[group][key] > 0));
}

export function createOperationsPages({ runtime, canEdit, notify }) {
  const dbRoot = document.getElementById('workspace-db-content');
  const moduleRoot = document.getElementById('module-detail-content');
  const llmLogPanel = document.getElementById('llm-call-log-panel');
  const db = { tab: 'cases', cases: [], intakes: [], total: 0, offset: 0, q: '', archived: 'false',
    caseDetail: null, versions: null, intakeDetail: null, selectedFile: null, loading: false, error: '',
    intakeTotal: 0, intakeOffset: 0, intakeQuery: '', intakeStatus: 'all', intakeSort: 'newest',
    ocrEnabled: false, ocrLanguage: 'ko', localLlmEnabled: false, llmBusy: false, health: null, defaultsLoaded: false, uploadTarget: '',
    uploadConflict: null, uploading: false, reviewDirty: false, reviewSaving: false, reviewIndex: 0, reviewStep: 'review', intakeNotice: '' };
  const advisory = { records: [], total: 0, offset: 0, q: '', source: 'all', product: {},
    matches: null, result: null, busy: false, truncated: false };
  const mod = { slug: '', id: '', summary: null, config: null, logs: [], models: [], loading: false, error: '', query: '',
    loopBudget: null, budgetDraft: null, budgetError: '', budgetNotice: '', budgetSaving: false };
  let llmLogRefreshPending = false;

  function reset() {
    db.cases = []; db.intakes = []; db.caseDetail = null; db.intakeDetail = null; db.selectedFile = null;
    db.health = null; db.defaultsLoaded = false; db.uploadTarget = '';
    advisory.records = []; advisory.matches = null; advisory.result = null; advisory.product = {};
    dbRoot.textContent = '로그인 후 DB 자료를 불러옵니다.';
    mod.slug = ''; mod.query = ''; mod.summary = null; mod.config = null; mod.logs = []; mod.models = [];
    mod.loopBudget = null; mod.budgetDraft = null; mod.budgetError = ''; mod.budgetNotice = ''; mod.budgetSaving = false;
    moduleRoot.textContent = '로그인 후 모듈 자료를 불러옵니다.';
    llmLogPanel.hidden = true;
  }

  async function refreshDb() {
    db.loading = true; db.error = ''; renderDb();
    try {
      const query = new URLSearchParams({ limit: '50', offset: String(db.offset), archived: db.archived });
      if (db.q) query.set('q', db.q);
      const intakeQuery = new URLSearchParams({ limit: '50', offset: String(db.intakeOffset),
        q: db.intakeQuery, status: db.intakeStatus, sort: db.intakeSort });
      const [cases, intakes, health] = await Promise.all([
        runtime.api(`/api/db/cases?${query}`), runtime.api(`/api/db/intakes?${intakeQuery}`),
        runtime.api('/api/db/status'),
      ]);
      db.health = health;
      if (!db.defaultsLoaded) {
        db.ocrEnabled = health.settings?.ocrEnabled ?? false;
        db.localLlmEnabled = health.settings?.localLlmEnabled ?? false;
        db.ocrLanguage = health.settings?.ocrLanguage ?? 'ko'; db.defaultsLoaded = true;
      }
      db.cases = Array.isArray(cases.cases) ? cases.cases : [];
      db.total = Number.isFinite(cases.total) ? cases.total : db.cases.length;
      db.intakes = Array.isArray(intakes.intakes) ? intakes.intakes : [];
      db.intakeTotal = intakes.total ?? db.intakes.length;
    } catch (error) { db.error = error.message; }
    finally { db.loading = false; renderDb(); }
  }

  function caseList() {
    return `<section class="panel ops-panel"><div class="ops-panel-head"><div><h2>취약점 사례</h2><p>등록된 보고서 자료·취약점 사례와 버전 이력을 검색합니다.</p></div><button class="button secondary" data-action="refresh-db">새로고침</button></div>
      <form id="case-search-form" class="ops-filters"><label>검색어<input id="case-query" type="search" value="${escape(db.q)}" placeholder="ID, 대상, 유형, URL"></label><label>보관 상태<select id="case-archived"><option value="false"${db.archived === 'false' ? ' selected' : ''}>현재 사례</option><option value="true"${db.archived === 'true' ? ' selected' : ''}>보관된 사례</option><option value="all"${db.archived === 'all' ? ' selected' : ''}>전체</option></select></label><button class="button primary" type="submit">검색</button></form>
      <p class="ops-caption">${db.loading ? '조회 중 · ' : ''}총 ${db.total}건</p>
      <div class="ops-list">${db.cases.length ? db.cases.map(item => `<button class="ops-row" data-case-id="${escape(item.case_id || item.id)}"><span><strong>${escape(item.title || item.display_title || item.case_id || item.id)}</strong><small>${escape(item.target_id || '대상 없음')} · ${escape(item.vulnerability_type || '유형 미기록')} · ${escape(item.endpoint || item.vulnerability_url || '')}</small></span><span class="state-chip">${escape(item.archived ? '보관됨' : item.record_kind === 'report_knowledge' ? '등록됨 · 재현 정보 보완 필요' : item.status || '등록됨')}</span></button>`).join('') : '<div class="ops-empty">일치하는 사례가 없습니다.</div>'}</div>
      <div class="ops-pagination"><button class="button secondary" data-action="case-prev" ${db.offset <= 0 ? 'disabled' : ''}>이전</button><span>${db.total ? db.offset + 1 : 0}–${Math.min(db.total, db.offset + db.cases.length)} / ${db.total}</span><button class="button secondary" data-action="case-next" ${db.offset + db.cases.length >= db.total ? 'disabled' : ''}>다음</button></div></section>`;
  }

  function caseDetail() {
    const detail = db.caseDetail;
    if (!detail) return '<section class="panel ops-panel ops-placeholder"><h2>사례 상세</h2><p>목록에서 사례를 선택하세요.</p></section>';
    const item = detail.case || detail;
    if (item.record_kind === 'report_knowledge') {
      return `<section class="panel ops-panel report-knowledge-detail"><h2>${escape(item.title || item.display_title)}</h2><p class="intake-feedback">취약점 DB에 등록된 보고서 자료입니다. 공격 재현에 필요한 정보는 아직 보완이 필요합니다.</p><p>대상 ${escape(item.target_id)} · ${escape(item.source_filename)} · 검토자 ${escape(item.reviewer)}</p><dl class="review-summary">${editableCaseFields.map(key => `<div><dt>${escape(caseLabels[key])}</dt><dd><pre>${escape(item[key] == null || Array.isArray(item[key]) && !item[key].length ? '아직 확인되지 않음' : Array.isArray(item[key]) ? item[key].join('\n') : item[key])}</pre></dd></div>`).join('')}</dl><button class="button primary" data-intake-id="${escape(item.draft_sha256)}">원본 보고서에서 내용 보완</button><details><summary>재현 정보의 보완 항목</summary><pre>${escape(json({ missing_fields: item.missing_fields, reasons: item.readiness_issues }))}</pre></details><details><summary>등록 기록과 버전 이력</summary><pre>${escape(json({ audit: detail.audit, versions: db.versions }))}</pre></details></section>`;
    }
    const archived = detail.archived === true || item.archived === true;
    const fields = editableCaseFields.filter(key => Object.hasOwn(item, key)).map(key => {
      const value = item[key] === null || item[key] === undefined ? '' : typeof item[key] === 'string' ? item[key] : json(item[key]);
      return `<label>${escape(caseLabels[key] || key)}${longFields.has(key)
        ? `<textarea data-case-field="${key}" rows="3">${escape(value)}</textarea>`
        : `<input data-case-field="${key}" value="${escape(value)}">`}</label>`;
    }).join('');
    return `<section class="panel ops-panel"><div class="ops-panel-head"><div><h2>${escape(item.title || item.case_id || item.id)}</h2><p>Case ID ${escape(item.case_id || item.id)} · revision ${escape(item.revision ?? '—')} · ${archived ? '보관됨' : '활성'}</p></div><button class="button secondary" data-action="close-case">닫기</button></div>
      <form id="case-edit-form" class="ops-edit-grid">${fields}<div class="ops-form-actions"><button class="button primary" type="submit" ${canEdit() && !archived ? '' : 'disabled'}>변경 저장</button>${archived ? `<button class="button secondary" type="button" data-action="restore-case" ${canEdit() ? '' : 'disabled'}>복구</button>` : `<button class="button secondary" type="button" data-action="archive-case" ${canEdit() ? '' : 'disabled'}>사례 보관</button>`}</div></form>
      <details><summary>원본 데이터와 감사 기록</summary><pre>${escape(json(item))}</pre><pre>${escape(json(detail.audit || []))}</pre></details><details><summary>버전 이력</summary><pre>${escape(json(db.versions || detail.versions || []))}</pre></details></section>`;
  }

  async function refreshAdvisories() {
    try {
      const query = new URLSearchParams({ q: advisory.q, source: advisory.source,
        limit: '50', offset: String(advisory.offset) });
      const result = await runtime.api(`/api/db/advisories?${query}`);
      advisory.records = result.records || []; advisory.total = result.total || 0;
      advisory.matches = null; db.error = '';
    } catch (error) { db.error = error.message; }
    renderDb();
  }

  function renderDb() {
    dbRoot.innerHTML = `<nav class="ops-tabs" aria-label="취약점 DB"><button data-db-tab="cases" class="${db.tab === 'cases' ? 'active' : ''}">취약점 사례</button><button data-db-tab="intakes" class="${db.tab === 'intakes' ? 'active' : ''}">보고서 접수</button><button data-db-tab="advisories" class="${db.tab === 'advisories' ? 'active' : ''}">외부 취약점 정보</button></nav>${db.error ? `<p class="runtime-error" data-db-error role="alert">${escape(db.error)}</p>` : ''}${db.tab === 'advisories' ? renderAdvisories(advisory, canEdit()) : db.tab === 'intakes' ? db.intakeDetail ? renderIntakeDetail(db, canEdit()) : renderIntakes(db, canEdit()) : `<div class="ops-two-column">${caseList()}${caseDetail()}</div>`}`;
  }

  async function showDb() { renderDb(); await refreshDb(); }

  async function showCase(id) {
    try {
      const [detail, versions] = await Promise.all([
        runtime.api(`/api/db/cases/${encodeURIComponent(id)}`),
        runtime.api(`/api/db/cases/${encodeURIComponent(id)}/versions`).catch(() => ({})),
      ]);
      db.caseDetail = detail;
      db.versions = versions.versions || versions;
      renderDb();
    } catch (error) { db.error = error.message; renderDb(); }
  }
  async function showIntake(id, { keepSelection = false } = {}) {
    try {
      db.tab = 'intakes';
      db.intakeDetail = await runtime.api(`/api/db/intakes/${encodeURIComponent(id)}`);
      db.reviewDirty = false; if (!keepSelection) { db.reviewIndex = 0; db.reviewStep = 'review'; }
      renderDb();
      dbRoot.scrollIntoView({ block: 'start', behavior: 'instant' });
    } catch (error) { db.error = error.message; renderDb(); }
  }

  async function publishReviewedIntake(item) {
    const result = await runtime.api(`/api/db/intakes/${encodeURIComponent(item.draft_sha256)}/publish`, {
      method: 'POST', body: { readyOnly: dbRoot.querySelector('#publish-ready-only')?.checked === true,
        expectedValidationSha: item.validation_sha256 },
    });
    const published = result.publish || {};
    const count = published.registered_case_ids?.length || published.created || 0;
    db.intakeNotice = count ? `${count}건을 취약점 DB에 등록했습니다.${published.incomplete_cases ? ` 재현 정보 보완 필요 ${published.incomplete_cases}건.` : ''}` : '등록할 내용으로 확인된 항목이 없습니다.';
    notify(db.intakeNotice);
    db.intakeDetail = { intake: result.intake }; db.reviewDirty = false;
    if (['applied', 'applied_subset'].includes(published.status) && !published.blocked?.length) {
      db.tab = 'cases'; db.q = result.intake.target_id; db.archived = 'false'; db.offset = 0; db.caseDetail = null;
      await refreshDb();
      const first = result.intake.findings.find(finding => finding.registered_record || finding.case_record);
      if (first) await showCase(first.case_id);
      dbRoot.scrollIntoView({ block: 'start', behavior: 'instant' });
    } else { await refreshDb(); await showIntake(item.draft_sha256, { keepSelection: true }); }
  }

  async function showModule(slug) {
    if (!moduleNames[slug]) return;
    if (mod.slug !== slug) { mod.query = ''; mod.logs = []; mod.loopBudget = null; mod.budgetDraft = null; }
    mod.budgetError = ''; mod.budgetNotice = '';
    mod.slug = slug; mod.loading = true; mod.error = ''; renderModule();
    try {
      const payload = await runtime.api('/api/modules');
      const modules = Array.isArray(payload.modules) ? payload.modules : [];
      mod.summary = modules.find(item => moduleAliases[slug].includes(item.id)) || null;
      mod.id = mod.summary?.id || moduleAliases[slug][0];
      const [config, logs, models, budgetResult] = await Promise.all([
        runtime.api(`/api/modules/${encodeURIComponent(mod.id)}/config`),
        runtime.api(`/api/modules/${encodeURIComponent(mod.id)}/logs`),
        slug === 'llm' ? runtime.getModels() : Promise.resolve({ models: [] }),
        slug === 'llm' ? runtime.api('/api/modules/llm/loop-budget').then(value => ({ value }), error => ({ error }))
          : Promise.resolve(null),
      ]);
      mod.config = config;
      mod.logs = Array.isArray(logs.logs) ? logs.logs : [];
      mod.models = Array.isArray(models.models) ? models.models : [];
      if (slug === 'llm') {
        if (budgetResult?.error) { mod.loopBudget = null; mod.budgetError = budgetResult.error.message; }
        else if (!validLoopBudget(budgetResult?.value)) {
          mod.loopBudget = null; mod.budgetError = '루프 예산 설정 형식을 확인할 수 없습니다.';
        } else {
          mod.loopBudget = budgetResult.value;
          mod.budgetDraft = { ...budgetResult.value.limits };
        }
      }
    } catch (error) { mod.error = error.message; }
    finally { mod.loading = false; renderModule(); }
  }

  function renderLlmBudget() {
    if (mod.slug !== 'llm') return '';
    const budget = mod.loopBudget;
    const fields = budget ? loopBudgetFields.map(({ key, label }) =>
      `<label for="llm-budget-${key}"><strong>${label}</strong><input id="llm-budget-${key}" name="${key}" type="number" min="1" max="${budget.caps[key]}" step="1" required value="${escape(mod.budgetDraft?.[key] ?? budget.limits[key])}" ${canEdit() ? '' : 'disabled'}><small>기본 ${budget.defaults[key]} · 최대 ${budget.caps[key]}</small></label>`).join('') : '';
    return `<section class="panel ops-panel llm-budget-panel" aria-labelledby="llm-budget-title"><h3 id="llm-budget-title">범용 루프 예산</h3><p>모델 계획의 반복 횟수와 검사 요청·증거 수의 상한입니다. 저장한 값은 다음 범용 실행부터 적용됩니다.</p>
      ${mod.budgetError ? `<p class="runtime-error" role="alert">${escape(mod.budgetError)}</p>` : ''}
      ${budget ? `<form id="llm-budget-form"><div class="llm-budget-fields">${fields}</div><div class="ops-form-actions"><button class="button primary" type="submit" ${canEdit() && !mod.budgetSaving ? '' : 'disabled'}>${mod.budgetSaving ? '저장 중…' : '예산 저장'}</button>${canEdit() ? '' : '<small>관리자만 변경할 수 있습니다.</small>'}</div></form>` : `<p role="status">${mod.loading ? '루프 예산을 불러오는 중입니다.' : '루프 예산을 표시할 수 없습니다.'}</p>`}
      ${mod.budgetNotice ? `<p class="llm-budget-notice" role="status">${escape(mod.budgetNotice)}</p>` : ''}</section>`;
  }

  function renderModule() {
    const name = moduleNames[mod.slug] || 'Module';
    const config = mod.config || {};
    const logs = mod.logs.filter(item => !mod.query || json(item).toLowerCase().includes(mod.query.toLowerCase()));
    moduleRoot.innerHTML = `<section class="panel ops-panel"><div class="ops-panel-head"><div><div class="eyebrow">MODULE OPERATIONS</div><h2>${escape(name)}</h2><p>모듈 ID ${escape(mod.id || '확인 중')} · ${escape(mod.summary?.status || '상태 확인 중')}</p></div><button class="button secondary" data-action="refresh-module">새로고침</button></div>${mod.error ? `<p class="runtime-error" role="alert">${escape(mod.error)}</p>` : ''}${mod.loading ? '<p role="status">설정과 로그를 불러오는 중입니다.</p>' : ''}
      <div class="ops-module-facts"><span><small>소스 경로</small><strong>${escape(config.config?.path || mod.summary?.path || '—')}</strong></span><span><small>버전 / revision</small><strong>${escape(config.revision || mod.summary?.revision || mod.summary?.version || '—')}</strong></span><span><small>설정 적용</small><strong>${config.editable ? '서버 관리' : '배포 설정 · 읽기 전용'}</strong></span></div>
      ${mod.slug === 'db' ? renderDbHealth(config, canEdit()) : ''}<div class="${mod.slug === 'llm' ? 'ops-llm-config' : 'ops-two-column'}"><section class="ops-subpanel"><h3>현재 유효 설정</h3><p>설정은 실행 환경과 배포 계약을 따릅니다. 변경 가능한 필드가 제공되지 않으면 이 화면에서 저장하지 않습니다.</p><pre>${escape(json(config.config || {}))}</pre>${mod.slug === 'llm' ? `<h3>등록 모델</h3><div class="ops-list">${mod.models.map(item => `<div class="ops-row"><span><strong>${escape(item.name || item.id)}</strong><small>${escape(item.provider || '')}</small></span><span class="state-chip">${item.available ? '사용 가능' : '사용 불가'}</span></div>`).join('') || '<p>등록 모델 없음</p>'}</div>` : ''}</section>${mod.slug === 'llm' ? '' : `<section class="ops-subpanel"><div class="ops-panel-head"><h3>모듈 로그</h3><label>검색<input id="module-log-search" type="search" value="${escape(mod.query)}" placeholder="실행 ID, 단계, 메시지"></label></div><div class="ops-log-list">${logs.length ? logs.map(item => `<details class="ops-log"><summary><span>${escape(date(item.createdAt || item.time || item.timestamp))}</span><strong>${escape(item.level || item.type || item.stage || '이벤트')}</strong><span>${escape(item.detail || item.message || item.title || '')}</span></summary><pre>${escape(json(item))}</pre></details>`).join('') : '<div class="ops-empty">표시할 로그가 없습니다.</div>'}</div></section>`}</div></section>`;
    moduleRoot.insertAdjacentHTML('beforeend', renderLlmBudget());
    renderLlmCallLog();
  }

  function renderLlmCallLog() {
    llmLogPanel.hidden = mod.slug !== 'llm';
    if (mod.slug !== 'llm') return;
    const logs = mod.logs.filter(item => item.stage === 'model.call'
      && (!mod.query || json(item).toLowerCase().includes(mod.query.toLowerCase())));
    const search = document.getElementById('llm-call-search');
    if (search.value !== mod.query) search.value = mod.query;
    document.getElementById('llm-call-count').textContent = String(logs.length).padStart(2, '0');
    document.getElementById('llm-call-list').innerHTML = logs.length ? logs.map(item =>
      `<details class="llm-call-entry"><summary><span class="event-time">${escape(date(item.createdAt || item.time || item.timestamp))}</span><span class="event-copy"><strong class="event-title">${escape(item.title || item.stage || '모델 호출')}</strong><small class="event-detail">${escape([item.runId, item.stage].filter(Boolean).join(' · '))}</small></span><span class="state-chip">${escape(item.status || '기록')}</span></summary><pre>${escape(json(item))}</pre></details>`).join('')
      : `<div class="empty-state compact"><span data-icon="brain"></span><h3>${mod.query ? '일치하는 호출 기록이 없습니다' : '모델 호출 기록이 없습니다'}</h3></div>`;
  }

  async function refreshLlmLogs() {
    if (mod.slug !== 'llm' || mod.loading || llmLogRefreshPending) return;
    llmLogRefreshPending = true;
    try {
      const response = await runtime.api(`/api/modules/${encodeURIComponent(mod.id)}/logs`);
      if (mod.slug !== 'llm') return;
      const next = Array.isArray(response.logs) ? response.logs : [];
      if (json(next) !== json(mod.logs)) {
        mod.logs = next;
        renderLlmCallLog();
      }
    } catch { /* Keep the last successful log view until the next refresh. */ }
    finally { llmLogRefreshPending = false; }
  }

  async function saveLoopBudget(form) {
    if (mod.slug !== 'llm' || !mod.loopBudget || mod.budgetSaving || !canEdit()) return;
    const draft = Object.fromEntries(loopBudgetFields.map(({ key }) =>
      [key, form.elements.namedItem(key)?.value.trim() ?? '']));
    mod.budgetDraft = draft;
    const limits = {};
    for (const { key, label } of loopBudgetFields) {
      const raw = draft[key];
      const value = Number(raw);
      if (!/^[1-9][0-9]*$/.test(raw) || !Number.isSafeInteger(value) || value > mod.loopBudget.caps[key]) {
        mod.budgetError = `${label}는 1부터 ${mod.loopBudget.caps[key]}까지의 정수여야 합니다.`;
        mod.budgetNotice = '';
        renderModule();
        return;
      }
      limits[key] = value;
    }
    mod.budgetSaving = true; mod.budgetError = ''; mod.budgetNotice = ''; renderModule();
    try {
      const saved = await runtime.api('/api/modules/llm/loop-budget', { method: 'PUT', body: { limits } });
      if (!validLoopBudget(saved)) throw new Error('저장된 루프 예산 설정 형식을 확인할 수 없습니다.');
      mod.loopBudget = saved;
      mod.budgetDraft = { ...saved.limits };
      mod.budgetNotice = '저장했습니다. 다음 범용 실행부터 적용됩니다.';
      notify('범용 루프 예산을 저장했습니다.');
    } catch (error) { mod.budgetError = error.message; }
    finally { mod.budgetSaving = false; renderModule(); }
  }

  dbRoot.addEventListener('click', async event => {
    if ((db.reviewSaving || db.llmBusy) && event.target.closest('[data-db-tab], [data-review-select], [data-action], [data-goto-review]')) return;
    const imageButton = event.target.closest('[data-preview-image]');
    if (imageButton) {
      const dialog = dbRoot.querySelector('#report-image-dialog');
      dialog.querySelector('img').src = imageButton.querySelector('img').src;
      dialog.showModal(); return;
    }
    if (event.target.closest('[data-action=close-image]')) { dbRoot.querySelector('#report-image-dialog').close(); return; }
    const nextCheck = event.target.closest('[data-goto-review]');
    if (nextCheck) {
      const index = Number(nextCheck.dataset.gotoReview);
      if (db.reviewStep === 'register') { db.reviewStep = 'review'; db.reviewIndex = index; renderDb(); }
      dbRoot.querySelector(`[data-review-select="${index}"]`)?.click();
      const panel = dbRoot.querySelector(`[data-candidate-panel="${index}"]`);
      const field = nextCheck.dataset.focusField;
      const input = field ? panel?.querySelector(`[data-resolution-field="${CSS.escape(field)}"] [data-resolution-value]`) : dbRoot.querySelector('[data-review-next]');
      if (input) { const details = input.closest('details'); if (details) details.open = true; input.scrollIntoView({ block: 'center', behavior: 'instant' }); input.focus({ preventScroll: true }); }
      return;
    }
    const choice = event.target.closest('[data-review-select]');
    if (choice) {
      db.reviewIndex = Number(choice.dataset.reviewSelect);
      if (db.reviewStep === 'register') { db.reviewStep = 'review'; renderDb(); }
      dbRoot.querySelectorAll('[data-candidate-panel]').forEach(node => { node.hidden = Number(node.dataset.candidatePanel) !== db.reviewIndex; });
      dbRoot.querySelectorAll('[data-review-select]').forEach(node => node.setAttribute('aria-pressed', String(Number(node.dataset.reviewSelect) === db.reviewIndex)));
      const intake = db.intakeDetail.intake || db.intakeDetail;
      dbRoot.querySelector('[data-review-next]').textContent = db.reviewIndex + 1 < intake.review.items.length ? '확인하고 다음' : '확인하고 DB에 등록';
      const progress = dbRoot.querySelector('.intake-guide strong'); if (progress) progress.textContent = `확인 ${db.reviewIndex + 1} / ${intake.review.items.length}`;
      return;
    }
    const candidateButton = event.target.closest('[data-use-candidate]');
    if (candidateButton) {
      const fieldset = candidateButton.closest('[data-review-index]');
      const intake = db.intakeDetail.intake || db.intakeDetail;
      const item = intake.review.items[Number(fieldset.dataset.reviewIndex)];
      const finding = intake.draft.findings.find(f => f.draft_id === item.draft_id);
      const candidate = candidateValue(finding, candidateButton.dataset.useCandidate, Number(candidateButton.dataset.evidenceIndex));
      const field = candidateButton.closest('[data-resolution-field]');
      const valueInput = field.querySelector('[data-resolution-value]');
      if (['preconditions', 'procedure', 'remediation', 'not_applicable_fields'].includes(candidateButton.dataset.useCandidate)) {
        valueInput.value = [...new Set([...valueInput.value.split('\n'), ...candidate.text.split('\n')].filter(Boolean))].join('\n');
      } else valueInput.value = candidate.text;
      const refs = field.querySelector('[data-resolution-refs]');
      refs.value = [...new Set([...refs.value.split('\n'), candidate.ref].filter(Boolean))].join('\n');
      field.querySelector('[data-resolution-value]').dispatchEvent(new Event('input', { bubbles: true }));
      return;
    }
    const tab = event.target.closest('[data-db-tab]');
    if (tab && db.reviewDirty && !window.confirm('아직 저장하지 않은 확인 내용이 있습니다. 저장하지 않고 이동할까요?')) return;
    if (tab) { db.tab = tab.dataset.dbTab; renderDb(); if (db.tab === 'advisories') await refreshAdvisories(); return; }
    const caseButton = event.target.closest('[data-case-id]');
    if (caseButton) { await showCase(caseButton.dataset.caseId); return; }
    const intakeButton = event.target.closest('[data-intake-id]');
    if (intakeButton) { await showIntake(intakeButton.dataset.intakeId); return; }
    const action = event.target.closest('[data-action]')?.dataset.action;
    if (!action) return;
    if (action === 'analyze-local') {
      if (db.reviewDirty) { notify('먼저 바꾼 검토 내용을 임시 저장하세요.'); return; }
      const item = db.intakeDetail.intake || db.intakeDetail;
      db.llmBusy = true; db.error = ''; renderDb();
      try {
        const result = await runtime.api(`/api/db/intakes/${encodeURIComponent(item.draft_sha256)}/analyze-local`, {
          method: 'POST', body: { expectedValidationSha: item.validation_sha256 },
        });
        db.intakeDetail = result; db.reviewIndex = 0; db.reviewStep = 'review'; db.reviewDirty = false;
        db.intakeNotice = '로컬 모델의 원문 대조를 마쳤습니다. 새 추출 결과를 확인하세요. 기존 등록 자료와 검토 기록은 보존했습니다.';
      } catch (error) { db.error = error.message; }
      finally { db.llmBusy = false; renderDb(); }
      return;
    }
    if (action === 'review-final') {
      if (db.reviewDirty) { notify('바꾼 내용은 먼저 확인하고 다음 또는 임시 저장으로 저장하세요.'); return; }
      db.reviewStep = 'register'; renderDb(); dbRoot.querySelector('.intake-final')?.scrollIntoView({ block: 'start', behavior: 'instant' }); return;
    }
    if (action === 'open-existing-intake' && db.uploadConflict?.existingDraftSha) {
      const id = db.uploadConflict.existingDraftSha;
      db.uploadConflict = null; db.error = ''; db.intakeNotice = '원래 보고서의 처리 결과를 열었습니다.';
      await showIntake(id); return;
    }
    if (action === 'use-existing-target' && db.uploadConflict) {
      db.uploadTarget = db.uploadConflict.existingTargetId; db.uploadConflict = null; db.error = ''; renderDb(); return;
    }
    if (action === 'refresh-db') await refreshDb();
    if (action === 'intake-prev') { db.intakeOffset = Math.max(0, db.intakeOffset - 50); await refreshDb(); }
    if (action === 'intake-next') { db.intakeOffset += 50; await refreshDb(); }
    if (action === 'advisory-prev') { advisory.offset = Math.max(0, advisory.offset - 50); await refreshAdvisories(); }
    if (action === 'advisory-next') { advisory.offset += 50; await refreshAdvisories(); }
    if (action === 'advisory-all') await refreshAdvisories();
    if (action === 'case-prev') { db.offset = Math.max(0, db.offset - 50); await refreshDb(); }
    if (action === 'case-next') { db.offset += 50; await refreshDb(); }
    if (action === 'close-case') { db.caseDetail = null; renderDb(); }
    if (action === 'close-intake') {
      if (db.reviewDirty && !window.confirm('아직 저장하지 않은 확인 내용이 있습니다. 목록으로 돌아갈까요?')) return;
      db.intakeDetail = null; db.reviewDirty = false; db.intakeNotice = ''; renderDb();
    }
    if (action === 'view-intake-cases') {
      const intake = db.intakeDetail.intake || db.intakeDetail;
      db.q = intake.target_id; db.offset = 0; db.tab = 'cases'; await refreshDb();
    }
    if (action === 'archive-case' && canEdit() && db.caseDetail) {
      const item = db.caseDetail.case || db.caseDetail;
      const reason = window.prompt('사례를 보관하는 이유를 입력하세요.');
      if (!reason?.trim()) return;
      try { await runtime.api(`/api/db/cases/${encodeURIComponent(item.case_id || item.id)}`, { method: 'DELETE', body: { reason: reason.trim(), expectedRevision: item.revision } });
        notify('사례를 보관했습니다.'); db.caseDetail = null; await refreshDb(); } catch (error) { db.error = error.message; renderDb(); }
    }
    if (action === 'restore-case' && canEdit() && db.caseDetail) {
      const item = db.caseDetail.case || db.caseDetail;
      try { await runtime.api(`/api/db/cases/${encodeURIComponent(item.case_id || item.id)}/restore`, { method: 'POST', body: {} });
        notify('사례를 복구했습니다.'); db.caseDetail = null; await refreshDb(); } catch (error) { db.error = error.message; renderDb(); }
    }
    if (action === 'publish-intake' && canEdit() && db.intakeDetail) {
      if (db.reviewDirty) { notify('바뀐 확인 내용을 먼저 저장하세요.'); return; }
      const item = db.intakeDetail.intake || db.intakeDetail;
      try { await publishReviewedIntake(item); }
      catch (error) { db.error = error.message; renderDb(); }
    }
    if (action === 'delete-intake' && canEdit() && db.intakeDetail) {
      const item = db.intakeDetail.intake || db.intakeDetail;
      if (!window.confirm('미등록 초안을 삭제할까요? 등록된 사례는 삭제되지 않습니다.')) return;
      try { await runtime.api(`/api/db/intakes/${encodeURIComponent(item.draft_sha256)}`, { method: 'DELETE', body: {} });
        db.intakeDetail = null; notify('미등록 초안을 삭제했습니다.'); await refreshDb(); } catch (error) { db.error = error.message; renderDb(); }
    }
  });

  dbRoot.addEventListener('submit', async event => {
    event.preventDefault();
    if (event.target.id === 'case-search-form') {
      db.q = document.getElementById('case-query').value.trim();
      db.archived = document.getElementById('case-archived').value;
      db.offset = 0; await refreshDb(); return;
    }
    if (event.target.id === 'intake-search-form') {
      db.intakeQuery = document.getElementById('intake-query').value.trim();
      db.intakeStatus = document.getElementById('intake-status').value;
      db.intakeSort = document.getElementById('intake-sort').value;
      db.intakeOffset = 0; await refreshDb(); return;
    }
    if (event.target.id === 'advisory-search-form') {
      advisory.q = document.getElementById('advisory-query').value.trim();
      advisory.source = document.getElementById('advisory-source').value;
      advisory.offset = 0; await refreshAdvisories(); return;
    }
    if (event.target.id === 'advisory-product-form') {
      if (advisory.busy) return;
      advisory.product = readProduct(event.target);
      const sync = event.submitter?.value === 'sync';
      if (sync && !canEdit()) return;
      advisory.busy = true; db.error = ''; renderDb();
      try {
        const result = sync ? await runtime.api('/api/db/advisories/sync', { method: 'POST', body: advisory.product })
          : await runtime.api(`/api/db/advisories/matches?${new URLSearchParams(advisory.product)}`);
        if (sync) advisory.result = result;
        const external = sync ? result.knowledge?.external : result.external;
        advisory.matches = external?.candidates || []; advisory.truncated = external?.truncated === true;
        if (external?.status && external.status !== 'ok') notify('저장된 외부 권고가 아직 없습니다. 공식 API 수집 후 다시 조회할 수 있습니다.');
      } catch (error) { db.error = error.message; }
      finally { advisory.busy = false; renderDb(); }
      return;
    }
    if (!canEdit()) return;
    if (event.target.id === 'intake-upload-form') {
      const file = db.selectedFile || document.getElementById('intake-file').files?.[0];
      if (!file) return;
      if (!/\.(?:hwp|hwpx)$/i.test(file.name) || file.size > 32_000_000) {
        db.error = 'HWP/HWPX 파일만 접수할 수 있으며 최대 크기는 32 MB입니다.';
        renderDb(); return;
      }
      if (db.loading) return;
      const form = new FormData(); form.append('file', file);
      db.uploadTarget = document.getElementById('intake-target-id').value.trim();
      form.append('targetId', db.uploadTarget);
      form.append('localOcr', String(document.getElementById('intake-ocr').checked));
      form.append('localLlm', String(document.getElementById('intake-local-llm').checked));
      form.append('ocrLanguage', document.getElementById('intake-ocr-language').value);
      db.error = ''; db.uploadConflict = null; db.loading = true; db.uploading = true; renderDb();
      try { const result = await runtime.api('/api/db/intakes', { method: 'POST', formData: form });
        db.selectedFile = null; db.tab = 'intakes';
        db.intakeNotice = result.stage?.reused ? '같은 파일의 처리 결과가 있어 중복 저장하지 않고 기존 내용을 열었습니다.' : '파일을 보관하고 내용을 읽었습니다. 이제 추출한 항목을 원문과 비교해 확인하세요.';
        notify(db.intakeNotice); await refreshDb();
        const id = result.intake?.draft_sha256 || result.draft_sha256;
        if (id) await showIntake(id);
      } catch (error) { db.error = error.message; if (error.code === 'REPORT_TARGET_CONFLICT') db.uploadConflict = error.details; db.loading = false; db.uploading = false; renderDb(); }
      finally { db.uploading = false; }
      return;
    }
    if (event.target.id === 'case-edit-form' && db.caseDetail) {
      const item = db.caseDetail.case || db.caseDetail;
      const patch = {};
      try {
        for (const input of event.target.querySelectorAll('[data-case-field]')) {
          const key = input.dataset.caseField;
          const value = input.value;
          const original = item[key];
          const originalText = original === null || original === undefined ? '' : typeof original === 'string' ? original : json(original);
          if (value === originalText) continue;
          if (Array.isArray(original)) {
            const parsed = JSON.parse(value);
            if (!Array.isArray(parsed)) throw new Error(`${caseLabels[key] || key}은 JSON 배열로 입력하세요.`);
            patch[key] = parsed;
          } else if (original && typeof original === 'object') patch[key] = JSON.parse(value);
          else if (typeof original === 'number') patch[key] = Number(value);
          else patch[key] = value;
        }
      } catch (error) { db.error = error.message; renderDb(); return; }
      if (!Object.keys(patch).length) { notify('변경된 필드가 없습니다.'); return; }
      try { await runtime.api(`/api/db/cases/${encodeURIComponent(item.case_id || item.id)}`, { method: 'PATCH', body: { patch, expectedRevision: item.revision } });
        notify('새 revision으로 저장했습니다.'); await refreshDb(); await showCase(item.case_id || item.id);
      } catch (error) { db.error = error.message; renderDb(); }
      return;
    }
    if (event.target.id === 'intake-review-form' && db.intakeDetail) {
      if (db.reviewSaving || !canEdit()) return;
      const intake = db.intakeDetail.intake || db.intakeDetail;
      const review = structuredClone(db.intakeDetail.review || intake.review || {});
      const form = event.target;
      const selectedIndex = db.reviewIndex;
      const mode = event.submitter?.value || 'draft';
      const advance = mode === 'confirm' || mode === 'defer';
      // Reviewer identity is assigned by the authenticated server.
      review.reviewed_at = new Date().toISOString();
      db.reviewSaving = true;
      event.target.querySelectorAll('button[type=submit]').forEach(button => { button.disabled = true; });
      dbRoot.querySelectorAll('[data-review-select], [data-action=review-final]').forEach(button => { button.disabled = true; });
      try {
        for (const fieldset of event.target.querySelectorAll('[data-review-index]')) {
          const index = Number(fieldset.dataset.reviewIndex);
          if (advance && index !== selectedIndex && !fieldset.hasAttribute('data-review-touched')) continue;
          const item = review.items[index];
          const finding = (intake.draft?.findings || db.intakeDetail.draft?.findings || []).find(f => f.draft_id === item.draft_id) || {};
          review.items[index] = collectReviewItem(fieldset, item, finding, { confirm: index === selectedIndex && mode === 'confirm', defer: index === selectedIndex && mode === 'defer' });
        }
        form.inert = true; form.setAttribute('aria-busy', 'true');
        const result = await runtime.api(`/api/db/intakes/${encodeURIComponent(intake.draft_sha256)}`, {
          method: 'PATCH', body: { review, expectedValidationSha: intake.validation_sha256 },
        });
        const registration = result.intake.findings || [];
        const count = registration.filter(item => item.registration_eligible && !item.registration_current).length;
        db.intakeNotice = `검토 내용을 저장했습니다. DB 등록 가능 ${count}건입니다.`;
        if (advance) {
          if (selectedIndex + 1 < review.items.length) db.reviewIndex = selectedIndex + 1;
          else db.reviewStep = 'register';
        }
        db.error = '';
        db.intakeDetail = { intake: result.intake }; db.reviewDirty = false;
        const allConfirmed = review.items.every(item => item.decision === 'accept' || item.decision === 'exclude');
        if (mode === 'confirm' && selectedIndex + 1 === review.items.length && allConfirmed) {
          await publishReviewedIntake(result.intake);
        } else {
          notify(db.intakeNotice); renderDb(); dbRoot.scrollIntoView({ block: 'start', behavior: 'instant' });
        }
      } catch (error) {
        db.error = error.message;
        let banner = dbRoot.querySelector('[data-db-error]');
        if (!banner) { banner = document.createElement('p'); banner.className = 'runtime-error'; banner.dataset.dbError = ''; banner.setAttribute('role', 'alert'); dbRoot.prepend(banner); }
        banner.textContent = error.message;
        banner.scrollIntoView({ block: 'center', behavior: 'instant' });
      } finally {
        db.reviewSaving = false;
        form.inert = false; form.removeAttribute('aria-busy');
        dbRoot.querySelectorAll('#intake-review-form button[type=submit]').forEach(button => { button.disabled = !canEdit(); });
        dbRoot.querySelectorAll('[data-review-select], [data-action=review-final]').forEach(button => { button.disabled = false; });
      }
    }
  });

  dbRoot.addEventListener('input', event => {
    if (!event.target.closest('#intake-review-form')) return;
    db.reviewDirty = true;
    event.target.closest('[data-review-index]')?.setAttribute('data-review-touched', '');
    const notice = dbRoot.querySelector('#intake-unsaved'); if (notice) notice.hidden = false;
    const publish = dbRoot.querySelector('[data-action=publish-intake]'); if (publish) publish.disabled = true;
    if (event.target.closest('[data-resolution-field=payload]')) event.target.closest('[data-review-index]').querySelector('[data-review-payload]').value = '';
  });
  dbRoot.addEventListener('change', event => {
    if (event.target.id === 'publish-ready-only') {
      dbRoot.querySelector('[data-action=publish-intake]').disabled = !canEdit() || db.reviewDirty || !event.target.checked;
    }
    if (event.target.id === 'intake-extraction-select') void showIntake(event.target.value);
    if (event.target.id === 'intake-target-id') db.uploadTarget = event.target.value;
    if (event.target.id === 'intake-local-llm') db.localLlmEnabled = event.target.checked;
    if (event.target.id === 'intake-ocr') db.ocrEnabled = event.target.checked;
    if (event.target.id === 'intake-ocr-language') db.ocrLanguage = event.target.value;
    if (event.target.id === 'intake-file') { db.selectedFile = event.target.files?.[0] || null;
      document.getElementById('intake-file-name').textContent = db.selectedFile?.name || '파일 미선택'; }
  });
  dbRoot.addEventListener('dragover', event => { if (event.target.closest('#intake-dropzone')) event.preventDefault(); });
  dbRoot.addEventListener('drop', event => {
    if (!event.target.closest('#intake-dropzone')) return;
    event.preventDefault();
    db.selectedFile = event.dataTransfer.files?.[0] || null;
    document.getElementById('intake-file').required = !db.selectedFile;
    document.getElementById('intake-file-name').textContent = db.selectedFile?.name || '파일 미선택';
  });
  moduleRoot.addEventListener('submit', async event => {
    if (event.target.id !== 'db-settings-form') return;
    event.preventDefault();
    if (!canEdit()) return;
    const form = new FormData(event.target);
    const settings = { localLlmEnabled: form.has('localLlmEnabled'), ocrEnabled: form.has('ocrEnabled'), ocrLanguage: form.get('ocrLanguage'),
      providers: form.getAll('providers'), maxPages: Number(form.get('maxPages')),
      maxRequests: Number(form.get('maxRequests')), timeoutSeconds: Number(form.get('timeoutSeconds')) };
    try {
      if (!settings.providers.length) throw new Error('외부 정보 제공처를 하나 이상 선택하세요.');
      await runtime.api('/api/db/settings', { method: 'PATCH', body: { settings, expectedRevision: mod.config.revision } });
      db.defaultsLoaded = false; notify('다음 접수·수집부터 사용할 기본 설정을 저장했습니다.');
      await showModule('db');
    } catch (error) { mod.error = error.message; renderModule(); }
  });
  moduleRoot.addEventListener('click', event => {
    if (event.target.closest('[data-action=open-report-intake]')) { db.tab = 'intakes'; window.location.hash = 'workspace/db'; }
    if (event.target.closest('[data-action="refresh-module"]') && !mod.budgetSaving) void showModule(mod.slug);
  });
  moduleRoot.addEventListener('submit', event => {
    if (event.target.id !== 'llm-budget-form') return;
    event.preventDefault();
    void saveLoopBudget(event.target);
  });
  moduleRoot.addEventListener('input', event => {
    if (event.target.id !== 'module-log-search') return;
    mod.query = event.target.value;
    // Preserve the focused search field while filtering the list.
    const list = moduleRoot.querySelector('.ops-log-list');
    const filtered = mod.logs.filter(item => json(item).toLowerCase().includes(mod.query.toLowerCase()));
    list.innerHTML = filtered.length ? filtered.map(item => `<details class="ops-log"><summary><span>${escape(date(item.createdAt || item.time || item.timestamp))}</span><strong>${escape(item.level || item.type || item.stage || '이벤트')}</strong><span>${escape(item.message || item.title || item.detail || '')}</span></summary><pre>${escape(json(item))}</pre></details>`).join('') : '<div class="ops-empty">표시할 로그가 없습니다.</div>';
  });
  llmLogPanel.addEventListener('input', event => {
    if (event.target.id !== 'llm-call-search') return;
    mod.query = event.target.value;
    renderLlmCallLog();
  });

  return { reset, showDb, showModule, refreshLlmLogs };
}
