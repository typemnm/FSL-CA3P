/** Workspace DB and module operations. Server data remains the source of truth. */
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

export function createOperationsPages({ runtime, canEdit, notify }) {
  const dbRoot = document.getElementById('workspace-db-content');
  const moduleRoot = document.getElementById('module-detail-content');
  const db = { tab: 'cases', cases: [], intakes: [], total: 0, offset: 0, q: '', archived: 'false',
    caseDetail: null, versions: null, intakeDetail: null, selectedFile: null, loading: false, error: '' };
  const mod = { slug: '', id: '', summary: null, config: null, logs: [], models: [], loading: false, error: '', query: '' };

  function reset() {
    db.cases = []; db.intakes = []; db.caseDetail = null; db.intakeDetail = null; db.selectedFile = null;
    dbRoot.textContent = '로그인 후 DB 자료를 불러옵니다.';
    mod.summary = null; mod.config = null; mod.logs = []; mod.models = [];
    moduleRoot.textContent = '로그인 후 모듈 자료를 불러옵니다.';
  }

  async function refreshDb() {
    db.loading = true; db.error = ''; renderDb();
    try {
      const query = new URLSearchParams({ limit: '50', offset: String(db.offset), archived: db.archived });
      if (db.q) query.set('q', db.q);
      const [cases, intakes] = await Promise.all([
        runtime.api(`/api/db/cases?${query}`), runtime.api('/api/db/intakes'),
      ]);
      db.cases = Array.isArray(cases.cases) ? cases.cases : [];
      db.total = Number.isFinite(cases.total) ? cases.total : db.cases.length;
      db.intakes = Array.isArray(intakes.intakes) ? intakes.intakes : [];
    } catch (error) { db.error = error.message; }
    finally { db.loading = false; renderDb(); }
  }

  function caseList() {
    return `<section class="panel ops-panel"><div class="ops-panel-head"><div><h2>취약점 사례</h2><p>등록된 Case와 버전 이력을 검색합니다.</p></div><button class="button secondary" data-action="refresh-db">새로고침</button></div>
      <form id="case-search-form" class="ops-filters"><label>검색어<input id="case-query" type="search" value="${escape(db.q)}" placeholder="ID, 대상, 유형, URL"></label><label>보관 상태<select id="case-archived"><option value="false"${db.archived === 'false' ? ' selected' : ''}>현재 사례</option><option value="true"${db.archived === 'true' ? ' selected' : ''}>보관된 사례</option><option value="all"${db.archived === 'all' ? ' selected' : ''}>전체</option></select></label><button class="button primary" type="submit">검색</button></form>
      <p class="ops-caption">${db.loading ? '조회 중 · ' : ''}총 ${db.total}건</p>
      <div class="ops-list">${db.cases.length ? db.cases.map(item => `<button class="ops-row" data-case-id="${escape(item.case_id || item.id)}"><span><strong>${escape(item.title || item.case_id || item.id)}</strong><small>${escape(item.target_id || '대상 없음')} · ${escape(item.vulnerability_type || '유형 미기록')} · ${escape(item.endpoint || item.vulnerability_url || '')}</small></span><span class="state-chip">${escape(item.archived ? '보관됨' : item.status || '등록됨')}</span></button>`).join('') : '<div class="ops-empty">일치하는 사례가 없습니다.</div>'}</div>
      <div class="ops-pagination"><button class="button secondary" data-action="case-prev" ${db.offset <= 0 ? 'disabled' : ''}>이전</button><span>${db.total ? db.offset + 1 : 0}–${Math.min(db.total, db.offset + db.cases.length)} / ${db.total}</span><button class="button secondary" data-action="case-next" ${db.offset + db.cases.length >= db.total ? 'disabled' : ''}>다음</button></div></section>`;
  }

  function caseDetail() {
    const detail = db.caseDetail;
    if (!detail) return '<section class="panel ops-panel ops-placeholder"><h2>사례 상세</h2><p>목록에서 사례를 선택하세요.</p></section>';
    const item = detail.case || detail;
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

  function intakeList() {
    return `<section class="panel ops-panel"><div class="ops-panel-head"><div><h2>보고서 접수</h2><p>HWP/HWPX를 접수한 뒤 근거를 검토하고 명시적으로 등록합니다.</p></div><button class="button secondary" data-action="refresh-db">새로고침</button></div>
      <form id="intake-upload-form" class="ops-upload-form"><label>대상 ID<input id="intake-target-id" name="targetId" required placeholder="대상 ID"></label><div class="ops-dropzone" id="intake-dropzone" tabindex="0"><strong>보고서를 여기에 놓거나 파일을 선택하세요</strong><small>HWP/HWPX · 최대 32 MB · 업로드만으로 사례가 등록되지 않습니다.</small><input id="intake-file" type="file" accept=".hwp,.hwpx" required><span id="intake-file-name">${escape(db.selectedFile?.name || '파일 미선택')}</span></div><button class="button primary" type="submit" ${canEdit() ? '' : 'disabled'}>보고서 접수</button></form>
      <div class="ops-list">${db.intakes.length ? db.intakes.map(item => `<button class="ops-row" data-intake-id="${escape(item.draft_sha256 || item.id)}"><span><strong>${escape(item.source_filename || item.filename || item.draft_sha256)}</strong><small>${escape(item.target_id || '대상 없음')} · ${escape(item.draft_sha256 || '')}</small></span><span class="state-chip">후보 ${Array.isArray(item.findings) ? item.findings.length : 0}건</span></button>`).join('') : '<div class="ops-empty">접수된 보고서가 없습니다.</div>'}</div></section>`;
  }

  function intakeDetail() {
    const detail = db.intakeDetail;
    if (!detail) return '<section class="panel ops-panel ops-placeholder"><h2>접수 상세</h2><p>접수된 보고서를 선택해 추출 결과와 근거를 검토하세요.</p></section>';
    const intake = detail.intake || detail;
    const review = detail.review || intake.review || {};
    const items = Array.isArray(review.items) ? review.items : [];
    const draftFindings = Array.isArray(intake.draft?.findings) ? intake.draft.findings : [];
    return `<section class="panel ops-panel"><div class="ops-panel-head"><div><h2>${escape(intake.source_filename || '접수 보고서')}</h2><p>초안 ${escape(intake.draft_sha256 || '')} · 대상 ${escape(intake.target_id || '—')}</p></div><button class="button secondary" data-action="close-intake">닫기</button></div>
      <div class="ops-caption">원본 근거를 확인한 뒤 항목별 결정을 저장하세요. 보류 항목은 등록되지 않습니다.</div>
      <form id="intake-review-form"><label>검토자<input id="reviewer-name" value="${escape(review.reviewer || '')}" required></label>${items.map((item, index) => `<fieldset class="ops-review-item" data-review-index="${index}"><legend>${escape(item.draft_id || `후보 ${index + 1}`)}</legend><label>결정<select data-review-decision><option value="pending"${item.decision === 'pending' ? ' selected' : ''}>보류</option><option value="accept"${item.decision === 'accept' ? ' selected' : ''}>수락</option><option value="exclude"${item.decision === 'exclude' ? ' selected' : ''}>제외</option></select></label><label>사유<input data-review-reason value="${escape(item.reason || '')}"></label><label>보완값·근거(JSON)<textarea data-review-resolutions rows="4">${escape(json(item.resolutions || {}))}</textarea></label><label>선택 payload 번호<input data-review-payload type="number" min="0" value="${escape(item.payload_variant_index ?? '')}"></label><label>확인한 이슈 코드<input data-review-issues value="${escape((item.acknowledged_issue_codes || []).join(', '))}"></label><details><summary>추출 후보와 원문 근거</summary><pre>${escape(json(draftFindings.find(finding => finding.draft_id === item.draft_id) || intake.findings?.[index] || {}))}</pre></details></fieldset>`).join('') || '<p>검토할 항목이 없습니다.</p>'}<div class="ops-form-actions"><button class="button primary" type="submit" ${canEdit() && items.length ? '' : 'disabled'}>검토 저장</button></div></form>
      <div class="ops-form-actions"><label><input id="publish-ready-only" type="checkbox"> 수락 가능한 항목만 등록</label><button class="button primary" data-action="publish-intake" ${canEdit() ? '' : 'disabled'}>검증 후 사례 등록</button><button class="button secondary" data-action="delete-intake" ${canEdit() ? '' : 'disabled'}>미등록 초안 삭제</button></div>
      <details><summary>검증 상태</summary><pre>${escape(json(intake.validation || {}))}</pre></details></section>`;
  }

  function renderDb() {
    dbRoot.innerHTML = `<nav class="ops-tabs" aria-label="취약점 DB"><button data-db-tab="cases" class="${db.tab === 'cases' ? 'active' : ''}">취약점 사례</button><button data-db-tab="intakes" class="${db.tab === 'intakes' ? 'active' : ''}">보고서 접수</button></nav>${db.error ? `<p class="runtime-error" role="alert">${escape(db.error)}</p>` : ''}<div class="ops-two-column">${db.tab === 'cases' ? `${caseList()}${caseDetail()}` : `${intakeList()}${intakeDetail()}`}</div>`;
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
  async function showIntake(id) {
    try {
      db.intakeDetail = await runtime.api(`/api/db/intakes/${encodeURIComponent(id)}`);
      renderDb();
    } catch (error) { db.error = error.message; renderDb(); }
  }

  async function showModule(slug) {
    if (!moduleNames[slug]) return;
    mod.slug = slug; mod.loading = true; mod.error = ''; renderModule();
    try {
      const payload = await runtime.api('/api/modules');
      const modules = Array.isArray(payload.modules) ? payload.modules : [];
      mod.summary = modules.find(item => moduleAliases[slug].includes(item.id)) || null;
      mod.id = mod.summary?.id || moduleAliases[slug][0];
      const [config, logs, models] = await Promise.all([
        runtime.api(`/api/modules/${encodeURIComponent(mod.id)}/config`),
        runtime.api(`/api/modules/${encodeURIComponent(mod.id)}/logs`),
        slug === 'llm' ? runtime.getModels() : Promise.resolve({ models: [] }),
      ]);
      mod.config = config;
      mod.logs = Array.isArray(logs.logs) ? logs.logs : [];
      mod.models = Array.isArray(models.models) ? models.models : [];
    } catch (error) { mod.error = error.message; }
    finally { mod.loading = false; renderModule(); }
  }

  function renderModule() {
    const name = moduleNames[mod.slug] || 'Module';
    const config = mod.config || {};
    const logs = mod.logs.filter(item => !mod.query || json(item).toLowerCase().includes(mod.query.toLowerCase()));
    moduleRoot.innerHTML = `<section class="panel ops-panel"><div class="ops-panel-head"><div><div class="eyebrow">MODULE OPERATIONS</div><h2>${escape(name)}</h2><p>모듈 ID ${escape(mod.id || '확인 중')} · ${escape(mod.summary?.status || '상태 확인 중')}</p></div><button class="button secondary" data-action="refresh-module">새로고침</button></div>${mod.error ? `<p class="runtime-error" role="alert">${escape(mod.error)}</p>` : ''}${mod.loading ? '<p role="status">설정과 로그를 불러오는 중입니다.</p>' : ''}
      <div class="ops-module-facts"><span><small>소스 경로</small><strong>${escape(config.config?.path || mod.summary?.path || '—')}</strong></span><span><small>버전 / revision</small><strong>${escape(config.revision || mod.summary?.revision || mod.summary?.version || '—')}</strong></span><span><small>설정 적용</small><strong>${config.editable ? '서버 관리' : '배포 설정 · 읽기 전용'}</strong></span></div>
      <div class="ops-two-column"><section class="ops-subpanel"><h3>현재 유효 설정</h3><p>설정은 실행 환경과 배포 계약을 따릅니다. 변경 가능한 필드가 제공되지 않으면 이 화면에서 저장하지 않습니다.</p><pre>${escape(json(config.config || {}))}</pre>${mod.slug === 'llm' ? `<h3>등록 모델</h3><div class="ops-list">${mod.models.map(item => `<div class="ops-row"><span><strong>${escape(item.name || item.id)}</strong><small>${escape(item.provider || '')}</small></span><span class="state-chip">${item.available ? '사용 가능' : '사용 불가'}</span></div>`).join('') || '<p>등록 모델 없음</p>'}</div>` : ''}</section><section class="ops-subpanel"><div class="ops-panel-head"><h3>모듈 로그</h3><label>검색<input id="module-log-search" type="search" value="${escape(mod.query)}" placeholder="실행 ID, 단계, 메시지"></label></div><div class="ops-log-list">${logs.length ? logs.map(item => `<details class="ops-log"><summary><span>${escape(date(item.createdAt || item.time || item.timestamp))}</span><strong>${escape(item.level || item.type || item.stage || '이벤트')}</strong><span>${escape(item.detail || item.message || item.title || '')}</span></summary><pre>${escape(json(item))}</pre></details>`).join('') : '<div class="ops-empty">표시할 로그가 없습니다.</div>'}</div></section></div></section>`;
  }

  dbRoot.addEventListener('click', async event => {
    const tab = event.target.closest('[data-db-tab]');
    if (tab) { db.tab = tab.dataset.dbTab; renderDb(); return; }
    const caseButton = event.target.closest('[data-case-id]');
    if (caseButton) { await showCase(caseButton.dataset.caseId); return; }
    const intakeButton = event.target.closest('[data-intake-id]');
    if (intakeButton) { await showIntake(intakeButton.dataset.intakeId); return; }
    const action = event.target.closest('[data-action]')?.dataset.action;
    if (!action) return;
    if (action === 'refresh-db') await refreshDb();
    if (action === 'case-prev') { db.offset = Math.max(0, db.offset - 50); await refreshDb(); }
    if (action === 'case-next') { db.offset += 50; await refreshDb(); }
    if (action === 'close-case') { db.caseDetail = null; renderDb(); }
    if (action === 'close-intake') { db.intakeDetail = null; renderDb(); }
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
      const item = db.intakeDetail.intake || db.intakeDetail;
      if (!window.confirm('검토와 검증을 통과한 항목을 DB에 등록할까요?')) return;
      try { await runtime.api(`/api/db/intakes/${encodeURIComponent(item.draft_sha256)}/publish`, {
        method: 'POST', body: { readyOnly: document.getElementById('publish-ready-only').checked,
          expectedValidationSha: item.validation_sha256 },
      });
        notify('보고서 등록 결과를 확인하세요.'); await refreshDb(); await showIntake(item.draft_sha256); } catch (error) { db.error = error.message; renderDb(); }
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
    if (!canEdit()) return;
    if (event.target.id === 'intake-upload-form') {
      const file = db.selectedFile || document.getElementById('intake-file').files?.[0];
      if (!file) return;
      if (!/\.(?:hwp|hwpx)$/i.test(file.name) || file.size > 32 * 1024 * 1024) {
        db.error = 'HWP/HWPX 파일만 접수할 수 있으며 최대 크기는 32 MB입니다.';
        renderDb(); return;
      }
      const form = new FormData(); form.append('file', file); form.append('targetId', document.getElementById('intake-target-id').value.trim());
      db.error = ''; db.loading = true; renderDb();
      try { const result = await runtime.api('/api/db/intakes', { method: 'POST', formData: form });
        db.selectedFile = null; db.tab = 'intakes'; notify('보고서를 접수했습니다. 초안을 검토해 주세요.'); await refreshDb();
        const id = result.intake?.draft_sha256 || result.draft_sha256;
        if (id) await showIntake(id);
      } catch (error) { db.error = error.message; db.loading = false; renderDb(); }
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
      const intake = db.intakeDetail.intake || db.intakeDetail;
      const review = structuredClone(db.intakeDetail.review || intake.review || {});
      review.reviewer = document.getElementById('reviewer-name').value.trim();
      review.reviewed_at = new Date().toISOString();
      try {
        for (const fieldset of event.target.querySelectorAll('[data-review-index]')) {
          const item = review.items[Number(fieldset.dataset.reviewIndex)];
          item.decision = fieldset.querySelector('[data-review-decision]').value;
          item.reason = fieldset.querySelector('[data-review-reason]').value.trim();
          item.resolutions = JSON.parse(fieldset.querySelector('[data-review-resolutions]').value || '{}');
          const payload = fieldset.querySelector('[data-review-payload]').value.trim();
          item.payload_variant_index = payload ? Number(payload) : null;
          item.acknowledged_issue_codes = fieldset.querySelector('[data-review-issues]').value.split(',').map(value => value.trim()).filter(Boolean);
        }
        await runtime.api(`/api/db/intakes/${encodeURIComponent(intake.draft_sha256)}`, {
          method: 'PATCH', body: { review, expectedValidationSha: intake.validation_sha256 },
        });
        notify('검토를 저장했습니다.'); await showIntake(intake.draft_sha256);
      } catch (error) { db.error = error.message; renderDb(); }
    }
  });

  dbRoot.addEventListener('change', event => {
    if (event.target.id === 'intake-file') { db.selectedFile = event.target.files?.[0] || null;
      document.getElementById('intake-file-name').textContent = db.selectedFile?.name || '파일 미선택'; }
  });
  dbRoot.addEventListener('dragover', event => { if (event.target.closest('#intake-dropzone')) event.preventDefault(); });
  dbRoot.addEventListener('drop', event => {
    if (!event.target.closest('#intake-dropzone')) return;
    event.preventDefault();
    db.selectedFile = event.dataTransfer.files?.[0] || null;
    document.getElementById('intake-file-name').textContent = db.selectedFile?.name || '파일 미선택';
  });
  moduleRoot.addEventListener('click', event => {
    if (event.target.closest('[data-action="refresh-module"]')) void showModule(mod.slug);
  });
  moduleRoot.addEventListener('input', event => {
    if (event.target.id !== 'module-log-search') return;
    mod.query = event.target.value;
    // Preserve the focused search field while filtering the list.
    const list = moduleRoot.querySelector('.ops-log-list');
    const filtered = mod.logs.filter(item => json(item).toLowerCase().includes(mod.query.toLowerCase()));
    list.innerHTML = filtered.length ? filtered.map(item => `<details class="ops-log"><summary><span>${escape(date(item.createdAt || item.time || item.timestamp))}</span><strong>${escape(item.level || item.type || item.stage || '이벤트')}</strong><span>${escape(item.message || item.title || item.detail || '')}</span></summary><pre>${escape(json(item))}</pre></details>`).join('') : '<div class="ops-empty">표시할 로그가 없습니다.</div>';
  });

  return { reset, showDb, showModule };
}
