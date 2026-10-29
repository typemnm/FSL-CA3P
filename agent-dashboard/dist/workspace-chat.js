/** Private workspace conversations. All model and file text is rendered as text. */
const number = value => Number.isFinite(Number(value)) ? Number(value).toLocaleString('ko-KR') : '—';
const when = value => value ? new Date(value).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : '';
const cleanError = error => error?.name === 'AbortError' ? '응답을 중지했습니다. 대화를 새로고침해 저장 상태를 확인하세요.' : error?.message || '요청을 완료하지 못했습니다. 다시 시도하세요.';
const prompts = ['최근 점검 결과에서 우선 대응할 항목을 정리해줘', '첨부한 코드의 입력 검증 흐름을 설명해줘', '현재 증거로 확정할 수 있는 내용과 추가 확인할 내용을 나눠줘'];

function node(tag, className, text) {
  const result = document.createElement(tag);
  if (className) result.className = className;
  if (text !== undefined) result.textContent = String(text);
  return result;
}
function button(text, className = 'text-button') { const result = node('button', className, text); result.type = 'button'; return result; }
function providerLabel(model) {
  if (model?.local || model?.provider === 'local') {
    const runtime = ({ ollama: 'Ollama', 'lm-studio': 'LM Studio', 'docker-model-runner': 'Docker Model Runner' })[model.runtime] || model.runtime;
    return runtime ? `${runtime} · 로컬` : '로컬 모델';
  }
  return ({ deepseek: 'DeepSeek API', ollama: 'Ollama · 로컬', 'lm-studio': 'LM Studio · 로컬', 'openai-compatible': 'OpenAI 호환 API' })[model?.provider] || model?.provider || '';
}

// Keep Markdown code fences readable without giving model output an HTML surface.
function messageBody(content) {
  const body = node('div', 'chat-message-body');
  for (const [index, part] of String(content ?? '').split('```').entries()) {
    if (!part) continue;
    if (index % 2) {
      const lines = part.split('\n');
      if (/^[\w#+.-]{0,30}$/.test(lines[0])) lines.shift();
      const pre = node('pre', 'chat-code'); pre.tabIndex = 0;
      pre.append(node('code', '', lines.join('\n').replace(/\n$/, ''))); body.append(pre);
    } else body.append(node('div', 'chat-message-text', part));
  }
  return body;
}

export function createWorkspaceChat({ api, canEdit, notify, getRuns = () => [] }) {
  const root = document.getElementById('workspace-chat-root');
  root.innerHTML = `
    <div class="chat-workspace">
      <aside class="chat-sessions panel" aria-label="AI 대화 세션">
        <div class="chat-sessions-heading"><div><small>YOUR WORKSPACE</small><h2>나의 대화 <span id="chat-session-count">0</span></h2></div><button type="button" class="button primary" id="chat-new-session">+ 새 대화</button></div>
        <label class="chat-search-label" for="chat-session-search">대화 검색<input type="search" id="chat-session-search" placeholder="제목으로 찾기" autocomplete="off"></label>
        <div id="chat-session-list" class="chat-session-list" aria-label="저장된 대화"></div>
        <p class="chat-private-note">대화는 로그인한 계정별로 저장됩니다.</p>
      </aside>
      <section class="chat-conversation panel" aria-label="AI 채팅">
        <header class="chat-toolbar"><div class="chat-title-copy"><small>AI CONVERSATION</small><h2 id="chat-session-title">새로운 대화를 시작하세요</h2></div><div class="chat-session-actions"><button type="button" class="text-button" id="chat-rename-session">이름 변경</button><button type="button" class="text-button" id="chat-delete-session">삭제</button><button type="button" class="text-button" id="chat-refresh">새로고침</button></div></header>
        <div class="chat-model-row"><label for="chat-model-select">AI 모델 <select id="chat-model-select" aria-describedby="chat-model-status"><option value="">모델 확인 중</option></select></label><span id="chat-model-status" role="status"></span></div>
        <p id="chat-local-model-notice" class="chat-readonly" role="status" hidden></p>
        <div class="chat-context-panel"><div class="chat-context-heading"><span id="chat-context-label">대화 컨텍스트 · 메시지를 보내면 사용량을 표시합니다.</span><button type="button" class="text-button" id="chat-compact">지금 압축</button></div><div id="chat-context-meter" class="chat-context-track" role="progressbar" aria-label="애플리케이션 컨텍스트 예산 사용률" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><span id="chat-context-fill"></span></div><p id="chat-context-help">대화·요약 기준 토큰 추정치입니다. 첨부 내용은 전송 시 합산하며 오래된 대화를 자동 요약해 원문 기록은 유지합니다.</p><p id="chat-provider-usage" hidden></p><details id="chat-summary-details" hidden><summary id="chat-summary-label">압축 요약 보기</summary><p id="chat-summary"></p></details></div>
        <p id="chat-error" class="chat-error" role="alert" hidden></p><p id="chat-readonly" class="chat-readonly" hidden>조회 전용 계정입니다. 새 대화와 메시지 전송은 운영자 권한이 필요합니다.</p>
        <div id="chat-messages" class="chat-messages" role="log" aria-label="대화 내용" aria-live="polite" aria-relevant="additions text"></div>
        <div id="chat-busy" class="chat-busy" role="status" hidden><span class="chat-spinner" aria-hidden="true"></span><span id="chat-busy-label">모델이 응답을 준비하고 있습니다.</span><button type="button" class="text-button" id="chat-cancel">응답 중지</button></div>
        <form id="chat-compose-form" class="chat-composer"><label class="chat-visually-hidden" for="chat-message-input">AI에게 보낼 메시지</label><div id="chat-attachments" class="chat-attachments"></div><textarea id="chat-message-input" rows="3" maxlength="6000" placeholder="점검 결과나 코드를 함께 살펴보세요…" aria-describedby="chat-compose-help" spellcheck="false"></textarea><div class="chat-composer-tools"><div class="chat-attachment-tools"><button type="button" class="button secondary" id="chat-open-files">+ 로컬 파일</button><label for="chat-run-select" class="chat-visually-hidden">참고할 실행 결과</label><select id="chat-run-select" aria-label="참고할 실행 결과"><option value="">실행 결과 첨부 안 함</option></select></div><button type="submit" class="button primary" id="chat-send">보내기 <span aria-hidden="true">↑</span></button></div><p id="chat-compose-help"><span id="chat-draft-count">0 / 6,000자</span> · Enter 전송 · Shift + Enter 줄바꿈<br>첨부한 파일과 실행 결과는 선택한 모델로 전송됩니다.</p></form>
      </section>
    </div>
    <dialog id="chat-rename-dialog" class="chat-dialog"><form id="chat-rename-form"><h2>대화 이름 변경</h2><label for="chat-rename-input">이름<input id="chat-rename-input" maxlength="120" required autocomplete="off"></label><div class="chat-dialog-actions"><button class="button secondary" id="chat-rename-cancel" type="button">취소</button><button class="button primary" type="submit">저장</button></div></form></dialog>
    <dialog id="chat-files-dialog" class="chat-dialog chat-files-dialog" aria-labelledby="chat-files-title"><div class="chat-files-header"><div><small>WORKSPACE FILES</small><h2 id="chat-files-title">로컬 파일 첨부</h2></div><button type="button" class="text-button" id="chat-close-files">닫기</button></div><p class="chat-files-note">서버 작업공간의 허용된 텍스트 파일을 읽습니다. 파일 내용은 메시지를 보낼 때 AI에 전달됩니다.</p><nav id="chat-file-breadcrumb" aria-label="파일 경로"></nav><p id="chat-file-error" class="chat-error" role="alert" hidden></p><div class="chat-file-columns"><div id="chat-file-list" class="chat-file-list" aria-label="파일 목록"></div><section class="chat-file-preview"><h3 id="chat-file-name">파일을 선택하세요</h3><p id="chat-file-meta"></p><pre id="chat-file-content" tabindex="0"></pre><button type="button" class="button primary" id="chat-attach-file" disabled>이 파일 첨부</button></section></div></dialog>`;
  const $ = id => root.querySelector(`#${id}`);
  const state = { models: [], modelError: '', sessions: [], selected: null, modelId: '', busy: false, loading: false, error: '', files: [], folder: '', entries: [], preview: null, fileLoading: false, generation: 0 };
  const drafts = new Map();
  let pending = null;
  let fileGeneration = 0;
  let initialized = false;

  function setError(error = '') { state.error = typeof error === 'string' ? error : cleanError(error); $('chat-error').textContent = state.error; $('chat-error').hidden = !state.error; }
  function availableModel() { return state.models.find(model => model.id === state.modelId)?.available === true; }
  function activeMessages() { return (state.selected?.messages || []).filter(message => message.sequence > (state.selected?.compactedThroughSequence || 0) && (!message.status || message.status === 'completed')); }
  function refreshPermissions() {
    const editable = canEdit() === true;
    const locked = state.busy || state.loading;
    $('chat-readonly').hidden = editable;
    $('chat-new-session').disabled = !editable || locked || !availableModel();
    $('chat-rename-session').disabled = !editable || locked || !state.selected;
    $('chat-delete-session').disabled = !editable || locked || !state.selected;
    $('chat-compact').disabled = !editable || locked || activeMessages().length <= 4 || !availableModel();
    $('chat-compact').title = activeMessages().length <= 4 ? '최근 메시지 4개를 남기고 이전 대화를 요약합니다.' : '오래된 대화를 요약해 다음 메시지의 컨텍스트를 줄입니다.';
    $('chat-model-select').disabled = !editable || locked || !state.models.length;
    $('chat-message-input').disabled = !editable || state.loading || state.busy;
    $('chat-open-files').disabled = !editable || locked || state.files.length >= 3;
    $('chat-run-select').disabled = !editable || locked;
    $('chat-send').disabled = !editable || locked || !availableModel() || !$('chat-message-input').value.trim();
    $('chat-draft-count').textContent = `${number($('chat-message-input').value.length)} / 6,000자`;
    $('chat-refresh').disabled = locked;
    $('chat-busy').hidden = !state.busy;
    $('chat-cancel').hidden = !pending;
    $('chat-session-list').querySelectorAll('button').forEach(item => { item.disabled = locked; });
    $('chat-messages').setAttribute('aria-busy', String(state.busy));
    renderAttachments();
  }
  function renderModels() {
    const select = $('chat-model-select'); select.replaceChildren();
    for (const model of state.models) {
      const provider = providerLabel(model);
      const option = node('option', '', `${model.name || model.id}${provider ? ` · ${provider}` : ''}${model.available ? '' : ` · ${model.reason || '사용 불가'}`}`);
      option.value = model.id; option.disabled = model.available !== true; select.append(option);
    }
    const model = state.models.find(item => item.id === state.modelId);
    if (state.modelId && !model) {
      const option = node('option', '', `${state.modelId} · 현재 연결 안 됨`); option.value = state.modelId; option.disabled = true; select.prepend(option);
    } else if (!state.models.length) { const option = node('option', '', state.loading ? '모델 확인 중' : '등록된 대화 모델 없음'); option.value = ''; select.append(option); }
    select.value = state.modelId;
    const provider = providerLabel(model);
    $('chat-model-status').textContent = state.loading ? '서버에서 모델 연결 상태를 확인하고 있습니다.'
      : state.modelError ? `모델 목록을 불러오지 못했습니다. ${state.modelError} 새로고침으로 다시 확인하세요.`
      : model?.available ? `${provider ? `${provider} · ` : ''}사용 가능`
      : model ? `${provider ? `${provider} · ` : ''}${model.reason || '모델을 사용할 수 없습니다.'} 새로고침으로 연결 상태를 다시 확인하세요.`
      : state.modelId ? '이 대화의 모델을 현재 서버에서 찾을 수 없습니다. 다른 모델을 선택하거나 새로고침하세요.'
      : '등록된 대화 모델이 없습니다. 모델 서버를 확인한 뒤 새로고침하세요.';
    const unavailableLocal = state.models.filter(item => (item.local || item.provider === 'local') && item.available === false);
    const notice = $('chat-local-model-notice'); notice.hidden = !unavailableLocal.length;
    notice.textContent = unavailableLocal.length ? `로컬 모델 연결 확인 · ${unavailableLocal.slice(0, 2).map(item => `${item.name || item.id}: ${item.reason || state.modelError || '모델 서버에 연결할 수 없습니다.'}`).join(' / ')}${unavailableLocal.length > 2 ? ` · 외 ${number(unavailableLocal.length - 2)}개 모델` : ''} 설정 확인 후 새로고침하세요.` : '';
  }
  function renderSessions() {
    const list = $('chat-session-list'); const filter = $('chat-session-search').value.trim().toLocaleLowerCase('ko-KR');
    list.replaceChildren(); $('chat-session-count').textContent = String(state.sessions.length);
    for (const session of state.sessions.filter(item => String(item.title || '').toLocaleLowerCase('ko-KR').includes(filter))) {
      const item = button('', `chat-session-item${session.id === state.selected?.id ? ' active' : ''}`);
      item.dataset.chatSession = session.id;
      item.setAttribute('aria-current', session.id === state.selected?.id ? 'true' : 'false');
      item.append(node('strong', '', session.title || '새 대화'));
      const meta = node('span', 'chat-session-meta'); meta.append(node('span', '', `${number(session.messageCount ?? session.messages?.length ?? 0)}개 메시지`), node('time', '', when(session.updatedAt)));
      item.append(meta); item.disabled = state.busy || state.loading;
      item.addEventListener('click', () => void selectSession(session.id)); list.append(item);
    }
    if (!list.children.length) list.append(node('p', 'chat-empty-list', state.loading ? '대화를 불러오는 중…' : filter ? '일치하는 대화가 없습니다.' : '첫 대화를 시작해 보세요.'));
  }
  function renderContext() {
    const context = state.selected?.context;
    const ratio = context ? Math.min(100, Math.max(0, Number(context.percentage) || 0)) : 0;
    $('chat-context-label').textContent = context ? `대화 컨텍스트 ${number(context.estimatedInputTokens)} / ${number(context.applicationBudgetTokens)} 토큰 · 약 ${number(context.percentage)}% (추정)` : '대화 컨텍스트 · 메시지를 보내면 사용량을 표시합니다.';
    $('chat-context-meter').setAttribute('aria-valuenow', String(ratio));
    $('chat-context-fill').style.width = `${ratio}%`;
    $('chat-context-meter').classList.toggle('near-limit', ratio >= 80);
    $('chat-context-help').textContent = context ? `대화·요약 기준 추정치이며 첨부 내용은 전송 시 합산합니다. ${number(context.compactionThresholdTokens)} 토큰에서 자동 압축하며 원문 기록은 유지합니다. 마지막 API 실제 사용량은 별도로 표시합니다.` : '대화·요약 기준 토큰 추정치입니다. 첨부 내용은 전송 시 합산하며 오래된 대화를 자동 요약해 원문 기록은 유지합니다.';
    const usage = context?.previousProviderUsage;
    $('chat-provider-usage').hidden = !usage;
    $('chat-provider-usage').textContent = usage ? `직전 모델 응답 실측 · 입력 ${number(usage.prompt_tokens)} / 출력 ${number(usage.completion_tokens)} 토큰` : '';
    $('chat-summary-details').hidden = !state.selected?.summary;
    $('chat-summary-label').textContent = `압축 요약 보기 · ${number(context?.compactionCount ?? state.selected?.compactionCount ?? 0)}회`;
    $('chat-summary').textContent = state.selected?.summary || '';
  }
  function renderMessages(scroll = false) {
    const messages = $('chat-messages'); messages.replaceChildren();
    $('chat-session-title').textContent = state.selected?.title || '새로운 대화를 시작하세요';
    if (!state.selected?.messages?.length) {
      const empty = node('div', 'chat-welcome'); empty.append(node('span', 'chat-welcome-symbol', '✦'), node('h3', '', '무엇을 함께 살펴볼까요?'), node('p', '', '점검 결과를 연결하거나 로컬 코드를 첨부해 대화를 시작하세요.'));
      const suggestions = node('div', 'chat-suggestions');
      for (const prompt of prompts) { const item = button(prompt, 'chat-suggestion'); item.disabled = !canEdit(); item.addEventListener('click', () => { $('chat-message-input').value = prompt; refreshPermissions(); $('chat-message-input').focus(); }); suggestions.append(item); }
      empty.append(suggestions); messages.append(empty);
    }
    for (const message of state.selected?.messages || []) {
      const article = node('article', `chat-message ${message.role === 'user' ? 'chat-message-user' : 'chat-message-assistant'}`);
      article.dataset.messageId = message.id;
      const heading = node('div', 'chat-message-heading'); heading.append(node('strong', '', message.role === 'user' ? '나' : 'AI'), node('time', '', when(message.createdAt)));
      if (message.role === 'assistant' && message.content) {
        const copy = button('복사'); copy.setAttribute('aria-label', 'AI 답변 복사');
        copy.addEventListener('click', async () => { try { await navigator.clipboard.writeText(message.content); notify('답변을 복사했습니다.'); } catch { notify('답변을 직접 선택해 복사하세요.'); } }); heading.append(copy);
      }
      article.append(heading, messageBody(message.content));
      const metadata = message.metadata || {};
      const fileNames = Array.isArray(metadata.files) ? metadata.files.map(file => typeof file === 'string' ? file : file.path).filter(Boolean) : [];
      if (fileNames.length) article.append(node('p', 'chat-message-reference', `첨부 · ${fileNames.join(', ')}`));
      if (metadata.runId) article.append(node('p', 'chat-message-reference', `참고 실행 · ${metadata.runId}`));
      if (message.sequence <= (state.selected.compactedThroughSequence || 0)) article.append(node('span', 'chat-compacted-label', '요약에 포함된 기록'));
      if (message.status && message.status !== 'completed') article.append(node('p', 'chat-message-reference', ({ failed: '응답 실패 · 다시 메시지를 보내세요.', cancelled: '응답이 중지되었습니다.', pending: '응답 준비 중' })[message.status] || message.status));
      messages.append(article);
    }
    if (scroll) messages.scrollTop = messages.scrollHeight;
  }
  function renderRuns() {
    const select = $('chat-run-select'); const selected = select.value; select.replaceChildren();
    const placeholder = node('option', '', '실행 결과 첨부 안 함'); placeholder.value = ''; select.append(placeholder);
    for (const run of getRuns().filter(item => item.id).slice(0, 100)) {
      const option = node('option', '', `${run.id} · ${run.target || run.status || '점검 실행'}`); option.value = run.id; select.append(option);
    }
    if ([...select.options].some(item => item.value === selected)) select.value = selected;
  }
  function renderAttachments() {
    const list = $('chat-attachments'); list.replaceChildren();
    for (const path of state.files) {
      const chip = node('span', 'chat-file-chip'); chip.append(node('span', '', path));
      const remove = button('×'); remove.setAttribute('aria-label', `${path} 첨부 제거`); remove.disabled = state.busy || !canEdit();
      remove.addEventListener('click', () => { state.files = state.files.filter(value => value !== path); refreshPermissions(); }); chip.append(remove); list.append(chip);
    }
  }
  function render(scroll = false) { renderModels(); renderSessions(); renderContext(); renderMessages(scroll); renderRuns(); refreshPermissions(); }
  function updateSession(session) {
    if (!session?.id) throw new Error('대화 응답 형식을 확인할 수 없습니다.');
    state.selected = session; state.modelId = session.modelId;
    state.sessions = [{ ...session, messages: undefined, messageCount: session.messages?.length ?? session.messageCount }, ...state.sessions.filter(item => item.id !== session.id)].sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
  }
  function rememberDraft() { drafts.set(state.selected?.id || 'new', { content: $('chat-message-input').value, files: [...state.files], runId: $('chat-run-select').value }); }
  function restoreDraft(id) {
    const draft = drafts.get(id || 'new');
    const previous = id ? [...(state.selected?.messages || [])].reverse().find(message => message.role === 'user')?.metadata : null;
    const references = Array.isArray(previous?.files) ? previous.files.map(file => typeof file === 'string' ? file : file.path).filter(Boolean).slice(0, 3) : [];
    $('chat-message-input').value = draft?.content || '';
    state.files = [...(draft?.files || references)];
    $('chat-run-select').value = draft?.runId ?? previous?.runId ?? '';
  }
  async function action(callback, label = '대화를 준비하고 있습니다.') {
    if (state.busy || state.loading) return;
    const generation = state.generation; setError(); state.busy = true; $('chat-busy-label').textContent = label; refreshPermissions();
    try { await callback(generation); }
    catch (error) { if (generation === state.generation) setError(error); }
    finally { if (generation === state.generation) { state.busy = false; pending = null; render(); } }
  }
  async function selectSession(id) {
    if (state.busy || state.loading) return;
    rememberDraft();
    await action(async generation => { const result = await api(`/api/chat/sessions/${encodeURIComponent(id)}`); if (generation !== state.generation) return; updateSession(result.session); restoreDraft(id); render(true); });
  }
  async function show() {
    if (state.busy || state.loading) { refreshPermissions(); return; }
    const generation = state.generation; state.loading = true; state.modelError = ''; setError(); refreshPermissions(); renderModels(); renderRuns();
    try {
      const [models, sessions] = await Promise.allSettled([api('/api/chat/models'), api('/api/chat/sessions')]);
      if (generation !== state.generation) return;
      if (models.status === 'fulfilled' && Array.isArray(models.value?.models)) state.models = models.value.models;
      else {
        state.modelError = models.status === 'rejected' ? cleanError(models.reason) : '서버의 모델 목록 형식을 확인할 수 없습니다.';
        state.models = state.models.map(model => ({ ...model, available: false }));
      }
      if (sessions.status === 'rejected') throw sessions.reason;
      if (!Array.isArray(sessions.value?.sessions)) throw new Error('저장된 대화 목록 형식을 확인할 수 없습니다.');
      state.sessions = sessions.value.sessions;
      if (state.selected && state.sessions.some(item => item.id === state.selected.id)) { const result = await api(`/api/chat/sessions/${encodeURIComponent(state.selected.id)}`); if (generation !== state.generation) return; updateSession(result.session); }
      else if (!initialized && state.sessions.length) { const result = await api(`/api/chat/sessions/${encodeURIComponent(state.sessions[0].id)}`); if (generation !== state.generation) return; updateSession(result.session); restoreDraft(state.selected.id); }
      else if (state.selected) { state.selected = null; restoreDraft(null); }
      if (!state.selected) state.modelId = state.models.find(model => model.available)?.id || state.models[0]?.id || '';
      initialized = true;
    } catch (error) { if (generation === state.generation) setError(error); }
    finally { if (generation === state.generation) { state.loading = false; render(); } }
  }
  async function createSession() {
    if (!canEdit() || !availableModel()) return;
    rememberDraft();
    await action(async generation => { const result = await api('/api/chat/sessions', { method: 'POST', body: { modelId: state.modelId } }); if (generation !== state.generation) return; updateSession(result.session); restoreDraft(result.session.id); render(true); $('chat-message-input').focus(); });
  }
  async function sendMessage() {
    const content = $('chat-message-input').value.trim();
    if (!canEdit() || !content || !availableModel()) return;
    if (content.length > 6000) { setError('메시지를 6,000자 이하로 줄여 주세요.'); return; }
    const files = [...state.files]; const runId = $('chat-run-select').value; rememberDraft();
    await action(async generation => {
      pending = new AbortController(); refreshPermissions();
      if (!state.selected) {
        const result = await api('/api/chat/sessions', { method: 'POST', body: { modelId: state.modelId }, signal: pending.signal });
        if (generation !== state.generation) return; updateSession(result.session); render();
      }
      const previousCompactions = state.selected.compactionCount || 0;
      const result = await api(`/api/chat/sessions/${encodeURIComponent(state.selected.id)}/messages`, { method: 'POST', body: { content, files, ...(runId ? { runId } : {}) }, signal: pending.signal });
      if (generation !== state.generation) return;
      updateSession(result.session); $('chat-message-input').value = ''; drafts.delete(state.selected.id); drafts.delete('new');
      render(true);
      if ((result.session.compactionCount || 0) > previousCompactions) notify('이전 대화를 자동 압축했습니다. 원문은 기록에서 확인할 수 있습니다.');
    }, '모델이 응답을 준비하고 있습니다.');
  }

  function fileError(error = '') { $('chat-file-error').textContent = error ? cleanError(error) : ''; $('chat-file-error').hidden = !error; }
  async function loadFolder(path = '') {
    const token = ++fileGeneration; state.fileLoading = true; state.preview = null; fileError(); renderFilePreview(); $('chat-file-list').replaceChildren(node('p', 'chat-empty-list', '파일 목록을 불러오는 중…'));
    try {
      const payload = await api(`/api/chat/files?${new URLSearchParams({ path })}`);
      if (token !== fileGeneration) return;
      state.folder = payload.path || ''; state.entries = Array.isArray(payload.entries) ? payload.entries : [];
      const breadcrumbs = $('chat-file-breadcrumb'); breadcrumbs.replaceChildren();
      const top = button(payload.rootLabel || '작업공간'); top.addEventListener('click', () => void loadFolder('')); breadcrumbs.append(top);
      const parts = state.folder.split('/').filter(Boolean);
      parts.forEach((part, index) => { breadcrumbs.append(node('span', '', '/')); const crumb = button(part); crumb.addEventListener('click', () => void loadFolder(parts.slice(0, index + 1).join('/'))); breadcrumbs.append(crumb); });
      const list = $('chat-file-list'); list.replaceChildren();
      for (const entry of state.entries) {
        const item = button('', 'chat-file-entry'); item.dataset.filePath = entry.path; item.dataset.fileType = entry.type;
        item.append(node('span', 'chat-file-kind', entry.type === 'directory' ? '▸' : '◇'), node('span', 'chat-file-entry-name', entry.name));
        if (entry.type === 'file') item.append(node('small', '', `${number(entry.size)} B`));
        item.addEventListener('click', () => void (entry.type === 'directory' ? loadFolder(entry.path) : loadFile(entry.path))); list.append(item);
      }
      if (!list.children.length) list.append(node('p', 'chat-empty-list', '이 폴더에 표시할 파일이 없습니다.'));
    } catch (error) { if (token === fileGeneration) { fileError(error); $('chat-file-list').replaceChildren(); } }
    finally { if (token === fileGeneration) state.fileLoading = false; }
  }
  async function loadFile(path) {
    const token = ++fileGeneration; state.fileLoading = true; state.preview = null; fileError(); renderFilePreview(); $('chat-file-name').textContent = '파일을 읽는 중…';
    try { const payload = await api(`/api/chat/file?${new URLSearchParams({ path })}`); if (token !== fileGeneration) return; state.preview = payload; }
    catch (error) { if (token === fileGeneration) fileError(error); }
    finally { if (token === fileGeneration) { state.fileLoading = false; renderFilePreview(); } }
  }
  function renderFilePreview() {
    const preview = state.preview;
    $('chat-file-name').textContent = preview?.path || '파일을 선택하세요';
    $('chat-file-meta').textContent = preview ? `${number(preview.size)} B${preview.truncated ? ' · 미리보기 일부만 표시' : ''}${preview.language ? ` · ${preview.language}` : ''}` : '';
    $('chat-file-content').textContent = preview?.content || '';
    $('chat-attach-file').disabled = !canEdit() || !preview?.path || state.files.length >= 3 || state.files.includes(preview.path);
    $('chat-attach-file').textContent = state.files.includes(preview?.path) ? '이미 첨부한 파일' : '이 파일 첨부';
  }
  function reset() {
    state.generation += 1; fileGeneration += 1; pending?.abort(); pending = null;
    Object.assign(state, { models: [], modelError: '', sessions: [], selected: null, modelId: '', busy: false, loading: false, files: [], folder: '', entries: [], preview: null, fileLoading: false });
    drafts.clear(); initialized = false; $('chat-message-input').value = ''; $('chat-session-search').value = ''; $('chat-run-select').replaceChildren(); setError();
    $('chat-files-dialog').close(); $('chat-rename-dialog').close(); $('chat-file-list').replaceChildren(); $('chat-file-breadcrumb').replaceChildren(); fileError(); renderFilePreview(); render();
  }

  $('chat-new-session').addEventListener('click', () => void createSession());
  $('chat-refresh').addEventListener('click', () => void show());
  $('chat-session-search').addEventListener('input', renderSessions);
  $('chat-message-input').addEventListener('input', refreshPermissions);
  $('chat-message-input').addEventListener('keydown', event => { if (event.key === 'Enter' && !event.shiftKey && !event.isComposing && event.keyCode !== 229) { event.preventDefault(); if (!$('chat-send').disabled) void sendMessage(); } });
  $('chat-compose-form').addEventListener('submit', event => { event.preventDefault(); if (!$('chat-send').disabled) void sendMessage(); });
  $('chat-cancel').addEventListener('click', () => pending?.abort());
  $('chat-model-select').addEventListener('change', () => {
    const modelId = $('chat-model-select').value;
    if (!state.selected) { state.modelId = modelId; renderModels(); refreshPermissions(); return; }
    void action(async generation => { const result = await api(`/api/chat/sessions/${encodeURIComponent(state.selected.id)}`, { method: 'PATCH', body: { modelId } }); if (generation === state.generation) updateSession(result.session); });
  });
  $('chat-compact').addEventListener('click', () => { if (!canEdit() || !state.selected) return; void action(async generation => { const result = await api(`/api/chat/sessions/${encodeURIComponent(state.selected.id)}/compact`, { method: 'POST', body: {} }); if (generation !== state.generation) return; updateSession(result.session); render(); notify('이전 대화를 압축했습니다. 원문 기록은 유지됩니다.'); }, '이전 대화를 요약하고 있습니다.'); });
  $('chat-rename-session').addEventListener('click', () => { if (!canEdit() || !state.selected) return; $('chat-rename-input').value = state.selected.title || ''; $('chat-rename-dialog').showModal(); $('chat-rename-input').focus(); });
  $('chat-rename-cancel').addEventListener('click', () => $('chat-rename-dialog').close());
  $('chat-rename-form').addEventListener('submit', event => { event.preventDefault(); const title = $('chat-rename-input').value.trim(); if (!title || !canEdit() || !state.selected) return; $('chat-rename-dialog').close(); void action(async generation => { const result = await api(`/api/chat/sessions/${encodeURIComponent(state.selected.id)}`, { method: 'PATCH', body: { title } }); if (generation === state.generation) updateSession(result.session); }); });
  $('chat-delete-session').addEventListener('click', () => {
    if (!canEdit() || !state.selected || !window.confirm('이 대화를 삭제할까요? 저장된 메시지와 요약이 함께 삭제됩니다.')) return;
    const id = state.selected.id;
    void action(async generation => { await api(`/api/chat/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' }); if (generation !== state.generation) return; state.sessions = state.sessions.filter(item => item.id !== id); drafts.delete(id); state.selected = null; state.modelId = state.models.find(model => model.available)?.id || state.models[0]?.id || ''; restoreDraft(null); render(); });
  });
  $('chat-open-files').addEventListener('click', () => { if (!canEdit() || state.busy) return; $('chat-files-dialog').showModal(); void loadFolder(state.folder); });
  $('chat-close-files').addEventListener('click', () => { fileGeneration += 1; $('chat-files-dialog').close(); });
  $('chat-files-dialog').addEventListener('close', () => { fileGeneration += 1; state.preview = null; renderFilePreview(); });
  $('chat-attach-file').addEventListener('click', () => { if (!canEdit() || !state.preview?.path || state.files.length >= 3 || state.files.includes(state.preview.path)) return; state.files.push(state.preview.path); $('chat-files-dialog').close(); refreshPermissions(); $('chat-message-input').focus(); });
  render();
  return { show, reset, refreshPermissions, refreshReferences: renderRuns };
}
