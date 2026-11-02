/** LLM module: local LLM discovery and operator-entered AI API providers. Keys are write-only. */
const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char]);
const date = value => value ? new Date(value).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' }) : '—';

export function createLlmSettings({ root, runtime, canEdit, notify = () => {}, onChanged = () => {} }) {
  const state = { loaded: false, loading: false, providers: [], kinds: [], local: null, servers: null, discovering: false,
    busy: false, error: '', notice: '', tests: new Map(), confirmDelete: null,
    draft: { name: '', kind: '', baseUrl: '', model: '' } };
  let container = null;

  function accept(payload) {
    if (payload?.outputTokens) state.outputTokens = payload.outputTokens;
    state.providers = Array.isArray(payload?.providers) ? payload.providers : [];
    state.kinds = Array.isArray(payload?.kinds) ? payload.kinds : state.kinds;
    state.local = payload?.local && typeof payload.local === 'object' ? payload.local : null;
  }
  async function load() {
    state.loading = true; state.error = ''; render();
    try { accept(await runtime.api('/api/modules/llm/providers')); state.loaded = true; }
    catch (error) { state.error = error.message; }
    finally { state.loading = false; render(); }
    if (!state.servers && !state.discovering) await discover();
  }
  async function discover() {
    state.discovering = true; render();
    try {
      const payload = await runtime.api('/api/modules/llm/local/discover');
      state.servers = Array.isArray(payload.servers) ? payload.servers : [];
      if (payload.local !== undefined) state.local = payload.local;
    } catch (error) { state.error = error.message; }
    finally { state.discovering = false; render(); }
  }
  async function mutate(task, notice) {
    if (state.busy || !canEdit()) return;
    state.busy = true; state.error = ''; state.notice = ''; render();
    try { const payload = await task(); if (payload) accept(payload); state.notice = notice; notify(notice); onChanged(); }
    catch (error) { state.error = error.message; }
    finally { state.busy = false; render(); }
  }

  function localSection() {
    const servers = state.servers;
    const selected = state.local;
    const rows = (servers ?? []).map(server => {
      const models = server.models ?? [];
      const choices = models.map(model => {
        const active = selected?.label === server.label && selected?.model === model;
        return `<li class="llm-local-model${active ? ' is-selected' : ''}"><span class="mono">${escape(model)}</span>${active
          ? '<span class="state-chip">점검에 사용 중</span>'
          : `<button type="button" class="button secondary" data-llm-select-local="${escape(server.label)}" data-model="${escape(model)}" ${canEdit() && !state.busy ? '' : 'disabled'}>점검에 사용</button>`}</li>`;
      }).join('');
      return `<div class="llm-local-server ${server.reachable ? 'is-up' : 'is-down'}"><div class="llm-local-head"><span class="tiny-dot ${server.reachable ? 'green' : 'gray'}"></span><strong>${escape(server.runtime)}</strong><span class="mono muted">${escape(server.endpoint)}</span><span class="state-chip">${server.reachable ? `모델 ${models.length}개` : escape(server.error || '응답 없음')}</span></div>${choices ? `<ul class="llm-local-models">${choices}</ul>` : ''}</div>`;
    }).join('');
    return `<section class="panel ops-panel llm-settings-panel" aria-labelledby="llm-local-title"><div class="ops-panel-head"><div><h3 id="llm-local-title">로컬 LLM 탐지</h3><p>이 장치의 Ollama · LM Studio · llama.cpp · Docker Model Runner 기본 포트를 확인합니다. 선택한 모델은 점검 모델 목록의 <strong>로컬 LLM</strong>으로 사용됩니다.</p></div><button type="button" class="button secondary" data-llm-discover ${state.discovering ? 'disabled' : ''}>${state.discovering ? '탐지 중…' : '다시 탐지'}</button></div>
      <p class="llm-local-current" role="status">${selected ? `현재 지정: <strong>${escape(selected.runtime || selected.label)}</strong> · <span class="mono">${escape(selected.model)}</span>${canEdit() ? ` <button type="button" class="text-button" data-llm-clear-local ${state.busy ? 'disabled' : ''}>지정 해제</button>` : ''}` : '지정된 로컬 LLM이 없습니다. agent/.env에 로컬 주소가 있으면 그 설정이 우선합니다.'}</p>
      ${servers === null ? `<p role="status">${state.discovering ? '로컬 LLM 서버를 찾는 중입니다.' : '탐지를 시작하세요.'}</p>` : `<div class="llm-local-list">${rows}</div>${servers.some(server => server.reachable) ? '' : '<p class="muted">실행 중인 로컬 LLM 서버를 찾지 못했습니다. 서버를 켠 뒤 다시 탐지하세요.</p>'}`}</section>`;
  }

  function providerSection() {
    const kinds = state.kinds;
    const draft = state.draft;
    const fixedBase = kinds.find(kind => kind.id === draft.kind)?.baseUrl;
    const rows = state.providers.map(provider => {
      const test = state.tests.get(provider.id);
      const testLine = !test ? '' : test.pending ? '<small role="status">연결 확인 중…</small>'
        : test.ok ? `<small class="${test.modelFound === false ? 'llm-test-fail' : 'llm-test-ok'}" role="status">${test.modelFound === false
          ? `키는 유효하지만 모델 목록에 ${escape(provider.model)}이(가) 없습니다. 모델 ID를 확인하세요.${test.models?.length ? ` 예: ${escape(test.models.slice(0, 3).join(', '))}` : ''}`
          : test.method === 'chat' ? '연결 성공 · 짧은 응답으로 모델 동작 확인' : '연결 성공 · 모델 확인됨'}</small>`
          : `<small class="llm-test-fail" role="alert">${escape(test.error || '연결 실패')}</small>`;
      const confirming = state.confirmDelete === provider.id;
      return `<div class="ops-row llm-provider-row"><span><strong>${escape(provider.name)}</strong><small>${escape(provider.kindLabel)} · <span class="mono">${escape(provider.model)}</span> · ${escape(provider.baseUrl)}</small><small>API 키 <span class="mono">${escape(provider.keyHint)}</span> · 최대 출력 ${escape(provider.maxOutputTokens ?? '—')} 토큰 · 등록 ${escape(date(provider.createdAt))}</small>${testLine}</span>${canEdit() ? `<span class="llm-provider-actions">${confirming
        ? `<button type="button" class="button primary" data-llm-delete="${escape(provider.id)}" ${state.busy ? 'disabled' : ''}>삭제 확인</button><button type="button" class="button secondary" data-llm-cancel-delete>취소</button>`
        : `<button type="button" class="button secondary" data-llm-test="${escape(provider.id)}" ${test?.pending ? 'disabled' : ''}>연결 테스트</button><button type="button" class="button secondary" data-llm-ask-delete="${escape(provider.id)}">삭제</button>`}</span>` : ''}</div>`;
    }).join('');
    const form = canEdit() ? `<form id="llm-provider-form" class="llm-provider-form" autocomplete="off"><h4>공급자 추가</h4><div class="llm-provider-fields">
      <label>이름<input name="name" required maxlength="60" placeholder="예: 팀 DeepSeek" value="${escape(draft.name)}"></label>
      <label>종류<select name="kind" required><option value=""${draft.kind ? '' : ' selected'} disabled>키를 발급한 서비스 선택</option>${kinds.map(kind => `<option value="${escape(kind.id)}"${kind.id === draft.kind ? ' selected' : ''}>${escape(kind.label)}</option>`).join('')}</select><small>키가 이 서비스로 전송됩니다. 목록에 없는 서비스는 OpenAI 호환 API를 고르고 Base URL을 입력하세요.</small></label>
      <label>Base URL<input name="baseUrl" type="url" ${fixedBase ? `value="${escape(fixedBase)}" disabled` : draft.kind ? `required placeholder="https://api.example.com/v1" value="${escape(draft.baseUrl)}"` : 'disabled placeholder="종류를 먼저 선택하세요"'}></label>
      <label>모델 이름<input name="model" required maxlength="160" placeholder="${escape(kinds.find(kind => kind.id === draft.kind)?.modelHint ? `예: ${kinds.find(kind => kind.id === draft.kind).modelHint}` : '공급자 문서의 모델 ID')}" value="${escape(draft.model)}"></label>
      <label>최대 출력 토큰<input name="maxOutputTokens" type="number" min="${state.outputTokens?.min ?? 1024}" max="${state.outputTokens?.max ?? 32768}" step="1024" value="${escape(draft.maxOutputTokens ?? state.outputTokens?.default ?? 16384)}"><small>추론 모델은 생각에도 토큰을 씁니다. 답변이 비면 늘리세요.</small></label>
      <label class="llm-key-field">API 키<input name="apiKey" type="password" required minlength="8" autocomplete="new-password" spellcheck="false" placeholder="저장 후에는 끝 4자리만 표시됩니다"></label>
      </div><div class="ops-form-actions"><button class="button primary" type="submit" ${state.busy ? 'disabled' : ''}>${state.busy ? '저장 중…' : '공급자 추가'}</button><small>키는 서버의 .runtime 설정 파일에만 저장되고 화면·로그·실행 기록에 표시되지 않습니다. OpenAI 호환 API는 /chat/completions와 JSON 응답 형식을 지원해야 합니다.</small></div></form>`
      : '<p class="muted">공급자 추가와 삭제는 관리자만 할 수 있습니다.</p>';
    return `<section class="panel ops-panel llm-settings-panel" aria-labelledby="llm-provider-title"><div class="ops-panel-head"><div><h3 id="llm-provider-title">AI API 공급자</h3><p>이름과 API 키를 등록하면 점검 모델 목록에 추가되어 계획과 검증에 사용됩니다. 외부 API 호출에는 비용이 발생할 수 있습니다.</p></div></div>
      <div class="ops-list">${rows || `<p class="muted">${state.loading ? '불러오는 중입니다.' : '등록된 공급자가 없습니다.'}</p>`}</div>${form}</section>`;
  }

  function render() {
    if (!container?.isConnected) return;
    container.innerHTML = `${state.error ? `<p class="runtime-error" role="alert">${escape(state.error)}</p>` : ''}${state.notice ? `<p class="llm-budget-notice" role="status">${escape(state.notice)}</p>` : ''}${localSection()}${providerSection()}`;
  }
  function mount(target) {
    container = target;
    render();
    if (!state.loaded && !state.loading) void load();
  }

  root.addEventListener('click', event => {
    if (!container?.contains(event.target)) return;
    const discoverButton = event.target.closest('[data-llm-discover]');
    if (discoverButton) { void discover(); return; }
    const select = event.target.closest('[data-llm-select-local]');
    if (select) {
      void mutate(() => runtime.api('/api/modules/llm/local', { method: 'PUT', body: { label: select.dataset.llmSelectLocal, model: select.dataset.model } }),
        '로컬 LLM을 지정했습니다. 다음 점검부터 사용할 수 있습니다.');
      return;
    }
    if (event.target.closest('[data-llm-clear-local]')) {
      void mutate(() => runtime.api('/api/modules/llm/local', { method: 'PUT', body: { clear: true } }), '로컬 LLM 지정을 해제했습니다.');
      return;
    }
    const test = event.target.closest('[data-llm-test]');
    if (test) {
      const id = test.dataset.llmTest;
      state.tests.set(id, { pending: true }); render();
      runtime.api(`/api/modules/llm/providers/${encodeURIComponent(id)}/test`, { method: 'POST', body: {} })
        .then(result => state.tests.set(id, result), error => state.tests.set(id, { ok: false, error: error.message }))
        .finally(render);
      return;
    }
    const ask = event.target.closest('[data-llm-ask-delete]');
    if (ask) { state.confirmDelete = ask.dataset.llmAskDelete; render(); return; }
    if (event.target.closest('[data-llm-cancel-delete]')) { state.confirmDelete = null; render(); return; }
    const remove = event.target.closest('[data-llm-delete]');
    if (remove) {
      const id = remove.dataset.llmDelete; state.confirmDelete = null; state.tests.delete(id);
      void mutate(() => runtime.api(`/api/modules/llm/providers/${encodeURIComponent(id)}`, { method: 'DELETE' }), '공급자를 삭제했습니다.');
    }
  });
  root.addEventListener('change', event => {
    if (event.target.name !== 'kind' || !event.target.closest('#llm-provider-form')) return;
    const form = event.target.form;
    state.draft = { name: form.elements.name.value, kind: event.target.value, baseUrl: '', model: form.elements.model.value };
    render();
  });
  root.addEventListener('submit', event => {
    if (event.target.id !== 'llm-provider-form') return;
    event.preventDefault();
    const form = event.target;
    const kind = form.elements.kind.value;
    if (!kind) { state.error = '키를 발급한 서비스(종류)를 선택하세요.'; render(); return; }
    state.draft = { name: form.elements.name.value, kind, baseUrl: form.elements.baseUrl.disabled ? '' : form.elements.baseUrl.value, model: form.elements.model.value };
    state.draft.maxOutputTokens = form.elements.maxOutputTokens.value;
    const body = { name: form.elements.name.value, kind, model: form.elements.model.value, apiKey: form.elements.apiKey.value,
      maxOutputTokens: Number(form.elements.maxOutputTokens.value),
      ...(form.elements.baseUrl.disabled ? {} : { baseUrl: form.elements.baseUrl.value }) };
    form.elements.apiKey.value = '';
    void mutate(async () => {
      const payload = await runtime.api('/api/modules/llm/providers', { method: 'POST', body });
      state.draft = { name: '', kind, baseUrl: '', model: '' };
      return payload;
    }, `${body.name} 공급자를 추가했습니다. 점검 모델 목록에서 선택할 수 있습니다.`);
  });

  function reset() {
    Object.assign(state, { loaded: false, loading: false, providers: [], local: null, servers: null, discovering: false,
      busy: false, error: '', notice: '', confirmDelete: null, draft: { name: '', kind: '', baseUrl: '', model: '' } });
    state.tests.clear();
  }

  return { mount, reload: load, reset };
}
