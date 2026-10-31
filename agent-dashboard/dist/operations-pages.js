/** Workspace DB and module operations. Server data remains the source of truth. */
import { renderIntakes, renderIntakeDetail } from './db-intakes.js';
import { collectReviewItem, candidateValue } from './db-review.js';
import { readProduct, renderAdvisories } from './db-advisories.js';
import { renderDbHealth } from './db-health.js';
import { createWebInfoLoader, renderWebParserLog, renderWebParserLogBody } from './web-info-view.js';
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
  const templateRoot = document.getElementById('workspace-templates-content');
  const llmLogPanel = document.getElementById('llm-call-log-panel');
  const db = { tab: 'cases', cases: [], intakes: [], total: 0, offset: 0, q: '', archived: 'false',
    caseDetail: null, versions: null, intakeDetail: null, selectedFile: null, loading: false, error: '',
    intakeTotal: 0, intakeOffset: 0, intakeQuery: '', intakeStatus: 'all', intakeSort: 'newest',
    ocrEnabled: false, ocrLanguage: 'ko', localLlmEnabled: false, llmBusy: false, health: null, defaultsLoaded: false, uploadTarget: '',
    uploadConflict: null, uploading: false, reviewDirty: false, reviewSaving: false, reviewIndex: 0, reviewStep: 'review', intakeNotice: '' };
  const advisory = { records: [], total: 0, offset: 0, q: '', source: 'all', product: {},
    matches: null, result: null, busy: false, truncated: false };
  const mod = { slug: '', id: '', summary: null, config: null, logs: [], logTotal: null, failedOnly: false, models: [], loading: false, error: '', query: '',
    loopBudget: null, budgetDraft: null, budgetError: '', budgetNotice: '', budgetSaving: false };
  let llmLogRefreshPending = false;
  const templates = { items: [], support: {}, revisions: {}, q: '', type: '', selected: null, detail: null,
    loading: false, detailLoading: false, busy: false, error: '', notice: '', editor: null,
    draft: '', confirmDelete: false, generation: 0, request: 0 };

  function reset() {
    db.cases = []; db.intakes = []; db.caseDetail = null; db.intakeDetail = null; db.selectedFile = null;
    db.health = null; db.defaultsLoaded = false; db.uploadTarget = '';
    advisory.records = []; advisory.matches = null; advisory.result = null; advisory.product = {};
    dbRoot.textContent = '로그인 후 DB 자료를 불러옵니다.';
    mod.slug = ''; mod.query = ''; mod.summary = null; mod.config = null; mod.logs = []; mod.logTotal = null; mod.failedOnly = false; mod.models = [];
    mod.loopBudget = null; mod.budgetDraft = null; mod.budgetError = ''; mod.budgetNotice = ''; mod.budgetSaving = false;
    moduleRoot.textContent = '로그인 후 모듈 자료를 불러옵니다.';
    llmLogPanel.hidden = true;
    templates.generation += 1; templates.request += 1;
    Object.assign(templates, { items: [], support: {}, revisions: {}, selected: null, detail: null,
      loading: false, detailLoading: false, busy: false, error: '', notice: '', editor: null,
      draft: '', confirmDelete: false });
    if (templateRoot) templateRoot.textContent = '로그인 후 템플릿을 불러옵니다.';
  }

  const templateEndpoint = '/api/attack-templates';
  const templateLabel = item => item.title || item.templateId;
  const templateTarget = item => `${item.target?.method || item.request?.packet?.method || '—'} ${item.target?.endpoint || item.request?.packet?.path || '—'}`;
  const templateTrustLabel = '검증되지 않은 템플릿';
  const templateTrustNote = `<div class="template-trust-note" role="note"><strong>${templateTrustLabel}</strong><p>근거: 등록 과정에서는 실제 대상에 요청을 실행하거나 결과를 검증하지 않습니다.</p></div>`;
  function filteredTemplates() {
    const query = templates.q.toLowerCase();
    return templates.items.filter(item => (!templates.type || item.attackType?.name === templates.type)
      && (!query || json(item).toLowerCase().includes(query)));
  }
  function templateRows() {
    const items = filteredTemplates();
    if (templates.loading && !templates.items.length) return '<p class="ops-empty" role="status">템플릿을 불러오는 중입니다.</p>';
    if (!items.length) return `<div class="ops-empty">${templates.q || templates.type ? '검색 조건에 맞는 템플릿이 없습니다.' : '등록된 템플릿이 없습니다.'}</div>`;
    return items.map(item => `<button type="button" class="template-card${templates.selected === item.templateId ? ' selected' : ''}" data-template-id="${escape(item.templateId)}" aria-pressed="${templates.selected === item.templateId}"><span class="template-card-heading"><strong>${escape(templateLabel(item))}</strong><span class="state-chip">${templates.support[item.templateId]?.supported ? '실행 형식 지원' : '참고용'}</span></span><span class="state-chip template-unverified">${templateTrustLabel}</span><small class="mono">${escape(item.templateId)}</small><span>${escape(item.attackType?.name || '유형 미기록')} · ${escape(item.attackType?.cwe || 'CWE 미기록')}</span><span class="mono">${escape(templateTarget(item))}</span><small>${escape(Object.values(item.dependency || {}).filter(Boolean).join(' · ') || '의존성 미기록')} · payload ${item.payloads?.length || 0}개</small></button>`).join('');
  }
  function templateDetail() {
    if (templates.detailLoading) return '<section class="panel ops-panel"><p role="status">템플릿 상세를 불러오는 중입니다.</p></section>';
    const detail = templates.detail;
    if (!detail) return '<section class="panel ops-panel ops-placeholder"><h2>템플릿 상세</h2><p>목록에서 템플릿을 선택하면 요청·payload·검증 조건을 확인할 수 있습니다.</p></section>';
    const item = detail.template;
    const support = detail.executionSupport || templates.support[item.templateId] || {};
    const disabled = templates.busy ? ' disabled' : '';
    return `<section class="panel ops-panel template-detail" aria-labelledby="template-detail-title"><div class="ops-panel-head"><div><h2 id="template-detail-title">${escape(templateLabel(item))}</h2><p class="mono">${escape(item.templateId)}${item.version ? ` · ${escape(item.version)}` : ''}</p></div><span class="state-chip">${support.supported ? '실행 형식 지원' : '참고용'}</span></div>${templateTrustNote}${item.description ? `<p>${escape(item.description)}</p>` : ''}<dl class="template-facts"><div><dt>취약점 유형</dt><dd>${escape(item.attackType?.name)} · ${escape(item.attackType?.cwe)}</dd></div><div><dt>대상 요청</dt><dd class="mono">${escape(templateTarget(item))}</dd></div><div><dt>의존성</dt><dd>${escape(Object.entries(item.dependency || {}).map(([key, value]) => `${key}: ${value}`).join(' · ') || '미기록')}</dd></div><div><dt>검증 방식</dt><dd>${escape(item.verify?.mode || '미기록')}</dd></div><div><dt>실행기 / 신뢰 상태</dt><dd>${escape(item.executor)} / ${escape(item.trust)}</dd></div></dl><p class="template-support-note">${escape(support.reason || '실제 실행에는 서버가 허용한 대상과 가드레일 정책이 적용됩니다.')}</p><h3>Payload ${item.payloads?.length || 0}개</h3><ul class="template-payloads">${(item.payloads || []).map(payload => `<li><code>${escape(payload)}</code></li>`).join('')}</ul><details><summary>요청 패킷과 검증 조건</summary><pre>${escape(json({ request: item.request, verify: item.verify, blanks: item.blanks }))}</pre></details><details><summary>전체 JSON</summary><pre id="template-raw-json" tabindex="0">${escape(json(item))}</pre></details><div class="ops-form-actions"><button class="button secondary" type="button" data-template-action="download"${disabled}>JSON 다운로드</button>${canEdit() ? `<button class="button secondary" type="button" data-template-action="copy"${disabled}>복사해서 추가</button><button class="button secondary" type="button" data-template-action="edit"${disabled}>수정</button><button class="button secondary" type="button" data-template-action="delete"${disabled}>삭제</button>` : ''}</div>${templates.confirmDelete && canEdit() ? `<div class="template-delete-confirm"><p><strong>${escape(item.templateId)}</strong> 템플릿을 삭제합니다.</p><div class="ops-form-actions"><button class="button primary" type="button" data-template-action="confirm-delete"${disabled}>삭제 확인</button><button class="button secondary" type="button" data-template-action="cancel-delete"${disabled}>취소</button></div></div>` : ''}</section>`;
  }
  function templateEditor() {
    if (!templates.editor || !canEdit()) return '';
    const editing = templates.editor.mode === 'edit';
    return `<section class="panel ops-panel template-editor" aria-labelledby="template-editor-title"><div class="ops-panel-head"><div><h2 id="template-editor-title">${editing ? '템플릿 수정' : 'JSON 템플릿 추가'}</h2><p>${editing ? `템플릿 ID ${escape(templates.editor.id)}는 유지하세요. 저장 시 최신 버전을 확인합니다.` : '템플릿 객체 1개, 배열 또는 {"templates": [...]} 형식으로 입력하세요. 한 번에 최대 100개를 가져옵니다. 사전 검증 없이 바로 등록할 수 있습니다.'}</p></div><button class="button secondary" type="button" data-template-action="close-editor" ${templates.busy ? 'disabled' : ''}>닫기</button></div>${templateTrustNote}<form id="template-editor-form">${editing ? '' : `<label class="template-file-label">JSON 파일 가져오기<input id="template-json-file" type="file" accept=".json,application/json" ${templates.busy ? 'disabled' : ''}><small>최대 1 MB · 파일을 읽은 후 내용을 확인하고 등록합니다.</small></label>`}<label for="template-json-input">템플릿 JSON<textarea id="template-json-input" rows="16" spellcheck="false" required ${templates.busy ? 'disabled' : ''} placeholder='[{"templateId": "my-template", ...}]'>${escape(templates.draft)}</textarea></label><div class="ops-form-actions"><button class="button primary" type="submit" ${templates.busy || !templates.draft.trim() ? 'disabled' : ''}>${templates.busy ? '저장 중…' : editing ? '변경 저장' : '템플릿 등록'}</button></div></form></section>`;
  }
  function renderTemplates() {
    if (!templateRoot) return;
    const types = [...new Set(templates.items.map(item => item.attackType?.name).filter(Boolean))].sort();
    templateRoot.innerHTML = `<section class="panel ops-panel template-catalog-heading"><div class="ops-panel-head"><div><div class="eyebrow">WORKSPACE / TEMPLATES</div><h2>템플릿</h2><p>공격 유형과 요청·검증 조건을 확인하고 JSON 템플릿을 관리합니다.</p></div><div class="ops-form-actions"><button class="button secondary" type="button" data-template-action="refresh" ${templates.loading || templates.busy ? 'disabled' : ''}>새로고침</button>${canEdit() ? `<button class="button primary" type="button" data-template-action="new" ${templates.busy ? 'disabled' : ''}>템플릿 추가</button>` : '<span class="state-chip">조회 전용</span>'}</div></div><p class="template-scope">등록된 템플릿은 다음 실행의 참고 자료로 제공됩니다. 실행 가능 여부는 지원 형식과 대상별 정책에 따라 결정됩니다.</p>${templates.error ? `<p id="template-error" class="runtime-error" role="alert">${escape(templates.error)}</p>` : ''}${templates.notice ? `<p id="template-notice" class="template-notice" role="status">${escape(templates.notice)}</p>` : ''}</section><div class="template-workspace"><section class="panel ops-panel template-catalog"><form id="template-search-form" class="ops-filters"><label for="template-query">템플릿 검색<input id="template-query" type="search" value="${escape(templates.q)}" placeholder="ID, CWE, 의존성, 엔드포인트"></label><label for="template-type">취약점 유형<select id="template-type"><option value="">전체 유형</option>${types.map(type => `<option value="${escape(type)}"${templates.type === type ? ' selected' : ''}>${escape(type)}</option>`).join('')}</select></label></form><p id="template-count" class="ops-caption">${templates.loading ? '조회 중 · ' : ''}${filteredTemplates().length} / ${templates.items.length}개</p><div id="template-list" class="template-list">${templateRows()}</div></section><div class="template-main">${templateDetail()}${templateEditor()}</div></div>`;
  }
  async function refreshTemplates() {
    if (templates.loading || templates.busy) return;
    const generation = templates.generation;
    const request = ++templates.request;
    templates.loading = true; templates.error = ''; renderTemplates();
    try {
      const result = await runtime.api(templateEndpoint);
      if (generation !== templates.generation || request !== templates.request) return;
      templates.items = Array.isArray(result.templates) ? result.templates : [];
      templates.support = result.executionSupport || {}; templates.revisions = result.revisions || {};
      if (templates.selected && templates.editor?.mode !== 'edit') {
        const selected = templates.items.find(item => item.templateId === templates.selected);
        if (selected) templates.detail = { template: selected, executionSupport: templates.support[selected.templateId],
          revision: templates.revisions[selected.templateId] };
        else { templates.selected = null; templates.detail = null; }
      }
    } catch (error) { if (generation === templates.generation) templates.error = error.message; }
    finally { if (generation === templates.generation && request === templates.request) { templates.loading = false; renderTemplates(); } }
  }
  async function showTemplates() { renderTemplates(); await refreshTemplates(); }
  async function showTemplate(id) {
    if (templates.busy) return;
    if (templates.editor?.mode === 'edit' && templates.editor.id !== id) {
      templates.error = '수정 내용을 저장하거나 편집기를 닫은 후 다른 템플릿을 선택하세요.';
      renderTemplates(); return;
    }
    const generation = templates.generation;
    templates.selected = id; templates.detail = null; templates.detailLoading = true;
    templates.confirmDelete = false; templates.error = ''; renderTemplates();
    try {
      const result = await runtime.api(`${templateEndpoint}/${encodeURIComponent(id)}`);
      if (generation === templates.generation && templates.selected === id) templates.detail = result;
    } catch (error) { if (generation === templates.generation && templates.selected === id) templates.error = error.message; }
    finally { if (generation === templates.generation && templates.selected === id) { templates.detailLoading = false; renderTemplates(); } }
  }
  function startTemplateEditor(mode) {
    const item = templates.detail?.template;
    templates.editor = { mode, id: mode === 'edit' ? item.templateId : null,
      revision: mode === 'edit' ? templates.detail.revision : null };
    templates.draft = mode === 'edit' ? json(item) : mode === 'copy' ? json([{ ...item, templateId: `${item.templateId}-copy` }]) : '';
    templates.confirmDelete = false;
    templates.error = ''; templates.notice = ''; renderTemplates();
    document.getElementById('template-json-input')?.focus();
  }
  function importTemplatesInput() {
    const parsed = JSON.parse(templates.draft);
    const items = Array.isArray(parsed) ? parsed : parsed && Array.isArray(parsed.templates) ? parsed.templates : [parsed];
    if (!items.length || items.length > 100 || items.some(item => !item || typeof item !== 'object' || Array.isArray(item))) throw new Error('템플릿 객체를 1개부터 100개까지 입력하세요.');
    return items;
  }
  async function mutateTemplates(action) {
    if (!canEdit() || templates.busy || action !== 'delete' && !templates.editor) return;
    const generation = templates.generation;
    const source = templates.draft;
    templates.busy = true; templates.error = ''; templates.notice = ''; renderTemplates();
    try {
      if (action === 'delete') {
        const detail = templates.detail;
        await runtime.api(`${templateEndpoint}/${encodeURIComponent(detail.template.templateId)}`, { method: 'DELETE', body: { expectedRevision: detail.revision } });
        if (generation !== templates.generation) return;
        templates.notice = `${detail.template.templateId} 템플릿을 삭제했습니다.`;
        templates.selected = null; templates.detail = null; templates.confirmDelete = false; templates.editor = null;
      } else if (templates.editor.mode === 'edit') {
        const item = JSON.parse(source);
        if (!item || item.templateId !== templates.editor.id) throw new Error('수정할 때 templateId를 변경할 수 없습니다. 새 ID로 추가하려면 복사해서 추가를 사용하세요.');
        const result = await runtime.api(`${templateEndpoint}/${encodeURIComponent(templates.editor.id)}`, { method: 'PUT', body: { template: item, expectedRevision: templates.editor.revision } });
        if (generation !== templates.generation) return;
        templates.detail = result; templates.selected = result.template.templateId;
        templates.editor = null; templates.notice = '템플릿 변경을 저장했습니다.';
      } else {
        const result = await runtime.api(templateEndpoint, { method: 'POST', body: { templates: importTemplatesInput(), dryRun: false } });
        if (generation !== templates.generation) return;
        templates.notice = `템플릿 ${result.created}개를 추가했습니다. 같은 내용 ${result.unchanged}개 · 총 ${result.total}개`;
        templates.editor = null;
      }
      notify(templates.notice);
    } catch (error) { if (generation === templates.generation) {
      templates.error = error.message + (error.status === 409 && templates.editor
        ? ' 입력 내용은 유지됩니다. 편집기를 닫고 템플릿을 다시 선택한 후 최신 내용을 확인하세요.' : '');
    } }
    finally { if (generation === templates.generation) { templates.busy = false; renderTemplates(); } }
    if (generation === templates.generation && !templates.error) await refreshTemplates();
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
    if (mod.slug !== slug) { mod.query = ''; mod.failedOnly = false; mod.logs = []; mod.logTotal = null; mod.loopBudget = null; mod.budgetDraft = null; }
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
      mod.logTotal = Number.isSafeInteger(logs.total) ? logs.total : null;
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
      ${mod.slug === 'db' ? renderDbHealth(config, canEdit()) : ''}<div class="${mod.slug === 'llm' || mod.slug === 'web-parser' ? 'ops-llm-config' : 'ops-two-column'}"><section class="ops-subpanel"><h3>현재 유효 설정</h3><p>설정은 실행 환경과 배포 계약을 따릅니다. 변경 가능한 필드가 제공되지 않으면 이 화면에서 저장하지 않습니다.</p><pre>${escape(json(config.config || {}))}</pre>${mod.slug === 'llm' ? `<h3>등록 모델</h3><div class="ops-list">${mod.models.map(item => `<div class="ops-row"><span><strong>${escape(item.name || item.id)}</strong><small>${escape(item.provider || '')}</small></span><span class="state-chip">${item.available ? '사용 가능' : '사용 불가'}</span></div>`).join('') || '<p>등록 모델 없음</p>'}</div>` : ''}</section>${mod.slug === 'llm' || mod.slug === 'web-parser' ? '' : `<section class="ops-subpanel"><div class="ops-panel-head"><h3>모듈 로그</h3><label>검색<input id="module-log-search" type="search" value="${escape(mod.query)}" placeholder="실행 ID, 단계, 메시지"></label></div><div class="ops-log-list">${logs.length ? logs.map(item => `<details class="ops-log"><summary><span>${escape(date(item.createdAt || item.time || item.timestamp))}</span><strong>${escape(item.level || item.type || item.stage || '이벤트')}</strong><span>${escape(item.detail || item.message || item.title || '')}</span></summary><pre>${escape(json(item))}</pre></details>`).join('') : '<div class="ops-empty">표시할 로그가 없습니다.</div>'}</div></section>`}</div></section>`;
    if (mod.slug === 'web-parser' && !mod.loading) moduleRoot.insertAdjacentHTML('beforeend',
      renderWebParserLog(mod.logs, { query: mod.query, failedOnly: mod.failedOnly, total: mod.logTotal }));
    moduleRoot.insertAdjacentHTML('beforeend', renderLlmBudget());
    if (mod.slug === 'attack') moduleRoot.insertAdjacentHTML('afterbegin', '<section class="panel ops-panel template-catalog-heading"><div class="ops-panel-head"><div><h2>공격 템플릿</h2><p>Workspace의 템플릿 화면에서 JSON 템플릿을 조회·추가·수정·삭제합니다.</p></div><a class="button secondary" href="#workspace/templates">템플릿 관리</a></div></section>');
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
  // web-parser collection log: filter in place (keeps search focus and open rows), load details on first open.
  function renderWebParserRows() {
    const body = document.getElementById('web-parser-log-body');
    if (!body) return;
    const open = new Set([...body.querySelectorAll('details[data-log-id][open]')].map(row => row.dataset.logId));
    body.innerHTML = renderWebParserLogBody(mod.logs, mod);
    body.querySelectorAll('details[data-log-id]').forEach(row => { if (open.has(row.dataset.logId)) row.open = true; });
  }
  const loadWebInfoDetail = createWebInfoLoader(runtime.api);
  moduleRoot.addEventListener('input', event => {
    if (event.target.id === 'web-parser-log-search') { mod.query = event.target.value; renderWebParserRows(); }
  });
  moduleRoot.addEventListener('change', event => {
    if (event.target.id === 'web-parser-failed-only') { mod.failedOnly = event.target.checked; renderWebParserRows(); }
  });
  moduleRoot.addEventListener('toggle', event => {
    const row = event.target;
    if (!row.matches?.('details[data-web-info-artifact]') || !row.open) return;
    void loadWebInfoDetail(row.dataset.webInfoArtifact).then(html => { row.querySelector('.web-info-detail').innerHTML = html; });
  }, true);
  llmLogPanel.addEventListener('input', event => {
    if (event.target.id !== 'llm-call-search') return;
    mod.query = event.target.value;
    renderLlmCallLog();
  });

  templateRoot?.addEventListener('click', event => {
    const row = event.target.closest('[data-template-id]');
    if (row) { void showTemplate(row.dataset.templateId); return; }
    const button = event.target.closest('[data-template-action]');
    if (!button || button.disabled) return;
    const action = button.dataset.templateAction;
    if (action === 'refresh') { void refreshTemplates(); return; }
    if (action === 'download' && templates.detail) {
      const link = document.createElement('a');
      link.href = URL.createObjectURL(new Blob([json(templates.detail.template)], { type: 'application/json' }));
      link.download = `${templates.detail.template.templateId}.json`;
      link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000); return;
    }
    if (!canEdit() || templates.busy) return;
    if (action === 'new') startTemplateEditor('create');
    if (['edit', 'copy'].includes(action) && templates.detail) startTemplateEditor(action);
    if (action === 'close-editor') { templates.editor = null; renderTemplates(); }
    if (action === 'delete' && templates.detail) { templates.confirmDelete = true; renderTemplates(); }
    if (action === 'cancel-delete') { templates.confirmDelete = false; renderTemplates(); }
    if (action === 'confirm-delete' && templates.detail && templates.confirmDelete) void mutateTemplates('delete');
  });
  templateRoot?.addEventListener('submit', event => {
    event.preventDefault();
    if (event.target.id === 'template-editor-form') void mutateTemplates('save');
  });
  templateRoot?.addEventListener('input', event => {
    if (event.target.id === 'template-query') {
      templates.q = event.target.value;
      document.getElementById('template-list').innerHTML = templateRows();
      document.getElementById('template-count').textContent = `${filteredTemplates().length} / ${templates.items.length}개`;
    }
    if (event.target.id === 'template-json-input') {
      templates.draft = event.target.value;
      templateRoot.querySelector('#template-editor-form [type="submit"]').disabled = templates.busy || !templates.draft.trim();
    }
  });
  templateRoot?.addEventListener('change', async event => {
    if (event.target.id === 'template-type') { templates.type = event.target.value; renderTemplates(); }
    if (event.target.id !== 'template-json-file' || !canEdit() || templates.busy) return;
    const file = event.target.files?.[0];
    if (!file) return;
    const generation = templates.generation, editor = templates.editor;
    try {
      if (!/\.json$/i.test(file.name) || file.size > 1024 * 1024) throw new Error('최대 1 MB의 JSON 파일을 선택하세요.');
      const source = await file.text();
      if (generation !== templates.generation || editor !== templates.editor) return;
      templates.draft = source; templates.error = '';
      renderTemplates();
    } catch (error) { if (generation === templates.generation) { templates.error = error.message; renderTemplates(); } }
  });

  return { reset, showDb, showModule, showTemplates, refreshLlmLogs };
}
