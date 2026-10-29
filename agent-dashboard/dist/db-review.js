/** Human review fields retain the existing hash-bound Python review contract. */
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const fields = {
  title: '제목', vulnerability_type: '취약점 유형', reported_on: '보고일 (YYYY-MM-DD)',
  vulnerability_url: '취약 URL', endpoint: '요청 경로', method: '보고서의 HTTP 메서드 (명시된 경우)',
  parameter: '파라미터', parameter_location: '파라미터 위치', severity: '심각도',
  description: '취약점 설명', remediation: '해결 방안', preconditions: '사전 조건',
  procedure: '재현 절차', payload: 'Payload', success_condition: '성공 조건',
  prior_evidence: '기존 증거', not_applicable_fields: '해당하지 않는 항목 (parameter, payload)',
  applicability_reason: '해당하지 않는 이유', route_template: '경로 템플릿',
};
export const reviewFieldLabel = key => fields[key] || key;
const choices = {
  severity: [['low','낮음'],['medium','보통'],['high','높음'],['critical','매우 높음']],
  method: ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].map(v => [v,v]),
  parameter_location: [['unknown','아직 확인하지 못함'],['query','URL의 ? 뒤 입력값'],['body','요청 본문'],['path','요청 경로'],['header','요청 헤더'],['cookie','쿠키'],['fragment','URL의 # 뒤 입력값']],
};
const arrays = new Set(['remediation', 'preconditions', 'procedure', 'not_applicable_fields']);
const text = (key, value) => arrays.has(key) ? (value || []).join('\n') : String(value ?? '');
const unknown = new Set(['미확인','미기재','확인필요','확인불가','알수없음','확인중','추후확인','확인하지못함','unknown','n/a','tbd','-']);
const supplied = value => Array.isArray(value) ? value.length > 0 && value.every(supplied)
  : typeof value === 'string' ? Boolean(value.trim()) && !unknown.has(value.replace(/\s/g, '').toLowerCase()) : value != null;
export const confirmationReason = '화면에 표시된 추출 내용과 주의사항을 원문과 비교하여 등록할 내용을 확인했습니다.';
const requiredIssues = finding => (finding.review_issues || []).filter(issue => ['endpoint_ambiguity', 'combined_vulnerability_types', 'typographic_quotes', 'image_text_not_processed', 'unreviewed_image_transcript', 'unreviewed_local_ocr', 'unreviewed_local_llm'].includes(issue.code));

/** Group exact copies for display; every original index and source stays available. */
export function groupedCandidates(finding, key) {
  const groups = new Map();
  const entries = key === 'payload' && finding.payload_variants?.length
    ? finding.payload_variants : finding.field_evidence?.[key] || [];
  entries.forEach((entry, index) => {
    if (!supplied(entry.value) || !(typeof entry.value === 'string' || Array.isArray(entry.value))) return;
    const identity = JSON.stringify(entry.value);
    if (!groups.has(identity)) groups.set(identity, { value: entry.value, indexes: [], source_refs: [] });
    const group = groups.get(identity);
    group.indexes.push(index);
    if (entry.source_ref && !group.source_refs.includes(entry.source_ref)) group.source_refs.push(entry.source_ref);
  });
  return [...groups.values()];
}

/** Proposals remain unapproved until the user explicitly confirms this finding. */
export function proposedReviewFields(finding, review = {}) {
  const proposals = {};
  for (const key of Object.keys(fields)) {
    if (review.resolutions?.[key] || supplied(finding.candidate?.[key])) continue;
    const semantic = (finding.field_evidence?.local_llm_selected || []).map(item => item.value)
      .filter(item => item.field === key && (key !== 'payload' || item.selected) && item.basis === 'explicit' && item.comparison?.verdict === 'supported');
    const semanticValues = [...new Set(semantic.map(item => item.value))];
    if (semanticValues.length && (arrays.has(key) || semanticValues.length === 1)) {
      const value = arrays.has(key) ? semanticValues : semanticValues[0];
      const payloadIndex = key === 'payload' ? finding.payload_variants?.findIndex(item => item.value === value) : undefined;
      proposals[key] = { value, source_refs: [...new Set(semantic.flatMap(item => item.source_refs))],
        origin: 'local_llm', evidence: semantic, ...(payloadIndex >= 0 ? { payloadIndex } : {}) };
      continue;
    }
    if ((finding.review_issues || []).some(issue => issue.field === key && ['unconfirmed_list_items', 'narrative_parameter_ambiguous'].includes(issue.code))) continue;
    if (key === 'payload' && (finding.payload_variants || []).length) {
      const variants = finding.payload_variants;
      if (new Set(variants.map(v => v.value)).size === 1 && supplied(variants[0].value)) proposals[key] = { value: variants[0].value, source_refs: [...new Set(variants.map(v => v.source_ref))], payloadIndex: 0 };
      continue;
    }
    const evidence = (finding.field_evidence?.[key] || []).filter(item => item.source_ref && (typeof item.value === 'string' || Array.isArray(item.value)) && supplied(item.value));
    if (!evidence.length) continue;
    const values = [...new Set(evidence.flatMap(item => arrays.has(key) ? (Array.isArray(item.value) ? item.value : item.value.split('\n')) : [item.value]).filter(supplied))];
    if (!values.length || (!arrays.has(key) && values.length !== 1)) continue;
    if (arrays.has(key) && (finding.review_issues || []).some(issue => issue.field === key && issue.code === 'multiple_field_values') && groupedCandidates(finding, key).length !== 1) continue;
    const value = arrays.has(key) ? values : values[0];
    if (choices[key] && !choices[key].some(([option]) => option === value)) continue;
    proposals[key] = { value, source_refs: [...new Set(evidence.map(item => item.source_ref))] };
  }
  return proposals;
}

export function displayedReviewValue(finding, review, key, proposals = proposedReviewFields(finding, review)) {
  if (review.resolutions?.[key]) return review.resolutions[key].value;
  return key === 'payload' && review.payload_variant_index != null
    ? finding.payload_variants?.[review.payload_variant_index]?.value : proposals[key]?.value ?? finding.candidate?.[key];
}

export function sourceLabel(ref = '') {
  const match = /^image-ocr:(.+)#line(\d+)$/.exec(ref);
  return match ? `이미지 ${match[1]} · ${Number(match[2]) + 1}번째 줄` : ref.startsWith('image:') ? `원본 이미지 ${ref.slice(6)}` : ref.startsWith('manual:') ? '직접 확인한 자료' : '보고서 본문·표';
}
export function candidateValue(finding, key, index) {
  const candidate = finding.field_evidence?.[key]?.[index];
  return candidate ? { text: text(key, arrays.has(key) && !Array.isArray(candidate.value) ? [String(candidate.value)] : candidate.value), ref: candidate.source_ref } : null;
}
export function renderReviewItem(finding, review, index, { state, blocked } = {}) {
  const candidate = finding.candidate || {};
  const proposals = proposedReviewFields(finding, review);
  const focus = new Set((blocked?.remaining_fields || (state && state.state !== 'needs_review' ? [] : [...(finding.missing_fields || []), ...(finding.unresolved_fields || [])])).filter(key => fields[key] && (key !== 'method' || finding.field_evidence?.method?.length)));
  const renderField = ([key, label]) => {
    const resolution = review.resolutions?.[key];
    const value = displayedReviewValue(finding, review, key, proposals);
    const refs = resolution?.source_refs || proposals[key]?.source_refs || [...new Set((finding.field_evidence?.[key] || []).map(e => e.source_ref).filter(Boolean))];
    if (!refs.length && finding.source_ref) refs.push(finding.source_ref);
    const control = choices[key] ? `<select data-resolution-value><option value="">선택하세요</option>${choices[key].map(([option,label]) => `<option value="${option}"${value === option ? ' selected' : ''}>${label}</option>`).join('')}</select>` : key === 'reported_on' ? `<input data-resolution-value type="date" value="${escape(value || '')}">` : `<textarea data-resolution-value rows="${['description', 'procedure', 'payload', 'success_condition'].includes(key) ? 3 : 1}">${escape(text(key, value))}</textarea>`;
    return `<div class="ops-review-field${focus.has(key) && !supplied(value) ? ' needs-attention' : ''}" data-resolution-field="${key}"><label>${escape(label)}${arrays.has(key) ? ' · 한 줄에 하나' : ''}${control}</label>${proposals[key] ? '<small>원문에서 찾은 후보를 미리 채웠습니다. 아래 확인 버튼으로 검토 결과를 남깁니다.</small>' : ''}
      ${focus.has(key) ? (finding.field_evidence?.[key] || []).map((e, i) => `<div class="review-suggestion"><small>문서에서 읽은 후보 · ${escape(sourceLabel(e.source_ref))}</small><pre>${escape(candidateValue(finding, key, i).text)}</pre><button type="button" class="button secondary" data-use-candidate="${key}" data-evidence-index="${i}">${arrays.has(key) ? '이 내용을 확인하고 추가' : '이 내용을 확인하고 사용'}</button></div>`).join('') : ''}
      <details class="review-source-settings"><summary>보완 이유·근거 위치 확인</summary><label>보완 이유<input data-resolution-reason value="${escape(resolution?.reason || '')}" placeholder="비워 두면 아래 확인 이유를 사용합니다"></label><label>근거 위치 · 한 줄에 하나<textarea data-resolution-refs rows="2">${escape(refs.join('\n'))}</textarea></label><small>별도 자료로 확인했다면 manual:자료 설명을 입력하세요.</small></details></div>`;
  };
  const summary = Object.keys(fields).map(key => {
    const value = displayedReviewValue(finding, review, key, proposals);
    return supplied(value) ? `<div><dt>${escape(fields[key])}${proposals[key] ? `<small>${proposals[key].origin === 'local_llm' ? '로컬 LLM · 원문 대조' : '확인용 후보'}</small>` : ''}</dt><dd><pre>${escape(text(key, value))}</pre>${proposals[key]?.evidence ? `<details><summary>이 값을 뽑은 원문 근거</summary>${proposals[key].evidence.map(item => item.quotes.map((quote, i) => `<small>${escape(sourceLabel(item.source_refs[i] || item.source_refs[0]))}</small><pre>${escape(quote)}</pre>`).join('')).join('')}<small>문자열 일치 및 별도 로컬 모델 대조 결과입니다. 최종 확인은 원문과 비교해 진행합니다.</small></details>` : ''}</dd></div>` : '';
  }).join('');
  const all = Object.entries(fields);
  const unresolved = all.filter(([key]) => !supplied(displayedReviewValue(finding, review, key, proposals)));
  const alternatives = unresolved.filter(([key]) => key !== 'payload' && !arrays.has(key) && groupedCandidates(finding, key).length > 1);
  const missing = unresolved.filter(([key]) => !alternatives.some(([other]) => other === key));
  const payloads = groupedCandidates(finding, 'payload');
  const chosenPayload = review.payload_variant_index ?? proposals.payload?.payloadIndex;
  const issues = requiredIssues(finding);
  const renderGroup = (key, group) => `<li><pre>${escape(text(key, group.value))}</pre><small>${group.indexes.length > 1 ? `같은 값 ${group.indexes.length}곳을 묶음 · ` : ''}원문 근거 ${group.source_refs.length}곳</small><details><summary>근거 위치 보기</summary>${group.source_refs.map(ref => `<small>${escape(sourceLabel(ref))} · ${escape(ref)}</small>`).join('<br>')}</details></li>`;
  const inferenceNotice = (finding.field_evidence?.local_llm_inferences || []).map(item => item.value).map(item => `<div class="ops-notice"><strong>${escape(fields[item.field])} · 문맥 추정</strong><pre>${escape(item.value)}</pre><p>원문에 명시된 값으로 확정하지 않았습니다. 자동 입력·자동 등록 값에 포함하지 않습니다.</p><details><summary>추정 근거 보기</summary>${item.quotes.map(quote => `<pre>${escape(quote)}</pre>`).join('')}</details></div>`).join('');
  return `<fieldset class="ops-review-item" data-review-index="${index}"><legend>${escape(candidate.title || `취약점 후보 ${index + 1}`)}</legend><h3>보고서에서 읽은 내용을 확인하세요</h3><p>읽어온 값과 원문을 비교하고 <b>확인하고 다음</b>을 누르면 됩니다. 여러 후보와 미확정 정보도 함께 보관하며, 지금 하나씩 선택하거나 빈칸을 채울 필요는 없습니다.</p>
    ${inferenceNotice}<dl class="review-summary">${summary || '<p>아직 항목별로 정리하지 못한 내용은 왼쪽 원문에 보관되어 있습니다.</p>'}</dl>
    ${payloads.length ? `<section class="review-preserved review-payloads"><h4>읽어온 Payload ${payloads.length}개 · 모두 보관</h4><p>대표값을 선택하지 않아도 각 문자열과 출처를 DB에 함께 저장합니다. 공백·따옴표·인코딩이 다른 표현은 원문 그대로 유지합니다.</p><ul>${payloads.map(group => renderGroup('payload', group)).join('')}</ul></section>` : ''}
    ${alternatives.length ? `<section class="review-alternatives"><h4>서로 다른 값이 있어 확인할 정보 ${alternatives.length}개</h4><p>원문에 여러 값이 있는지 확인하세요. 하나로 확정하지 않아도 후보와 출처를 모두 보관할 수 있습니다. 잘못된 값만 아래 수정 메뉴에서 고치세요.</p>${alternatives.map(([key, label]) => `<div data-unresolved-alternatives="${key}"><strong>${escape(label)}</strong><ul>${groupedCandidates(finding, key).map(group => renderGroup(key, group)).join('')}</ul></div>`).join('')}</section>` : ''}
    ${missing.length ? `<details class="review-missing"><summary>아직 확정하지 않은 정보 ${missing.length}개 · 등록 후 보완 가능</summary><p>${missing.map(([key, label]) => escape(label)).join(' · ')}</p><p>미확정 값은 비워 두고 자료를 등록합니다. 현재 대상의 GET·POST는 웹 파서의 관찰값으로 별도 확인하며, 과거 보고서에 추정해서 넣지 않습니다.</p></details>` : ''}
    <details class="review-other-fields"><summary>틀린 내용 수정·대표값 지정 (필요할 때만)</summary><p>자동 입력값은 그대로 확인할 수 있습니다. 원문과 다른 부분만 수정하세요.</p><div class="ops-review-fields">${all.map(renderField).join('')}</div>
    ${(finding.payload_variants || []).length ? `<label>재현용 대표 Payload · 선택사항<select data-review-payload><option value="">입력된 값이 없으면 대표값 없이 모두 보관</option>${payloads.map(group => { const i = group.indexes.includes(chosenPayload) ? chosenPayload : group.indexes[0]; return `<option value="${i}"${chosenPayload === i ? ' selected' : ''}>${escape(group.value)}</option>`; }).join('')}</select></label>` : '<select data-review-payload hidden><option value="">직접 확인한 입력값</option></select>'}</details>
    ${issues.length ? `<details class="review-issues-detail"><summary>이미지·추출 주의사항 ${issues.length}개 · 확인 버튼으로 함께 기록</summary><p>이미지 속 글자와 추출 내용을 원문과 비교하세요. 아래 표시를 따로 누르지 않아도 확인하고 다음을 누르면 확인 기록이 남습니다.</p><div class="ops-review-issues">${issues.map(issue => `<label><input type="checkbox" data-review-issue="${escape(issue.code)}"${review.acknowledged_issue_codes?.includes(issue.code) ? ' checked' : ''}> ${escape(issue.code === 'unreviewed_local_ocr' ? '왼쪽 원본 이미지와 읽힌 글자의 내용·따옴표·공백을 비교했습니다.' : issue.message)}</label>`).join('')}</div></details>` : ''}
    <p class="review-confirm-note">확인하면 이 자료를 보고서의 기록으로 보관합니다. 현재 사이트에서도 취약하거나 재현에 성공했다고 확정하는 것은 아닙니다. 검토자·시각·원문 출처는 자동으로 연결됩니다.</p><details class="review-decision"><summary>보류·제외·검토 이유 직접 설정</summary><label>DB 등록 대상인가요?<select data-review-decision>${[['pending','아직 확인하지 못함 · 보류'],['accept','내용 확인 완료 · DB 등록 대상으로 선택'],['exclude','이 보고서에서는 취약점 기록으로 남기지 않음']].map(([value,label]) => `<option value="${value}"${review.decision === value ? ' selected' : ''}>${label}</option>`).join('')}</select></label><label>별도로 남길 검토 이유<input data-review-reason value="${escape(review.reason)}" placeholder="확인하고 다음을 누르면 원문 대조 확인으로 기록됩니다"></label></details>
    ${blocked?.reasons?.length ? `<details><summary>재현 준비에 필요한 정보 · 자료 등록과 별개</summary><ul>${blocked.reasons.map(reason => `<li>${escape(reason)}</li>`).join('')}</ul></details>` : ''}</fieldset>`;
}

export function collectReviewItem(fieldset, original, finding, { confirm = false, defer = false } = {}) {
  const item = structuredClone(original);
  item.decision = defer ? 'pending' : confirm ? 'accept' : fieldset.querySelector('[data-review-decision]').value;
  item.reason = fieldset.querySelector('[data-review-reason]').value.trim() || (confirm ? confirmationReason : defer ? '추가 확인이 필요하여 보류했습니다.' : '추출된 내용을 임시 저장했습니다.');
  item.resolutions ||= {};
  const selectedPayload = fieldset.querySelector('[data-review-payload]').value;
  for (const node of fieldset.querySelectorAll('[data-resolution-field]')) {
    const key = node.dataset.resolutionField;
    if (key === 'payload' && selectedPayload !== '') { delete item.resolutions.payload; continue; }
    const previous = item.resolutions[key];
    const initial = previous ? previous.value : finding.candidate?.[key];
    const entered = node.querySelector('[data-resolution-value]').value;
    if (entered === text(key, initial) && !previous) continue;
    const value = arrays.has(key) ? entered.split('\n').map(s => s.trim()).filter(Boolean)
      : entered === '' ? null : entered;
    const reason = node.querySelector('[data-resolution-reason]').value.trim() || item.reason;
    const refs = node.querySelector('[data-resolution-refs]').value.split('\n').map(s => s.trim()).filter(Boolean);
    if (!reason || !refs.length) throw new Error(`${fields[key]}: 보완 이유와 근거 위치를 입력하세요.`);
    item.resolutions[key] = { value, reason, source_refs: refs };
  }
  const payload = fieldset.querySelector('[data-review-payload]').value;
  item.payload_variant_index = payload === '' ? null : Number(payload);
  if (item.decision !== 'pending' && !item.reason) throw new Error('확인 결과를 선택했다면 그렇게 판단한 이유도 입력하세요.');
  item.acknowledged_issue_codes = confirm ? [...new Set(requiredIssues(finding).map(issue => issue.code))]
    : [...fieldset.querySelectorAll('[data-review-issue]:checked')].map(node => node.dataset.reviewIssue);
  return item;
}

export function renderReportEvidence(draft, previews = []) {
  const document = draft.document || {};
  const images = document.local_ocr?.bundle?.images || [];
  const imageEntries = document.images || [];
  const cards = imageEntries.map(image => {
    const preview = previews.find(p => p.image_id === image.image_id);
    const ocr = images.find(p => p.image_id === image.image_id);
    return `<section class="report-image-card"><h4>문서 안의 이미지 ${escape(image.image_id)}</h4>${preview?.available && ['image/png','image/jpeg','image/gif','image/webp'].includes(preview.mime) && /^[A-Za-z0-9+/=]+$/.test(preview.base64) ? `<button type="button" data-preview-image class="report-image-link" aria-label="이미지 원본 크게 보기"><img src="data:${preview.mime};base64,${preview.base64}" alt="보고서에 포함된 원본 이미지 ${escape(image.image_id)}"></button><small>위 이미지를 누르면 크게 볼 수 있습니다.</small>` : `<p>${escape(preview?.reason || '미리보기가 없는 이미지입니다. 원본 문서에서 확인하세요.')}</p>`}
      <h4>이미지에서 읽은 글자</h4>${ocr?.recognition?.lines?.map((line, i) => `<div class="ops-source-text"><small>${i + 1}번째 줄</small><pre>${escape(line.text)}</pre></div>`).join('') || `<p>${escape(ocr?.error || (document.local_ocr ? '이 이미지에서 읽힌 글자가 없습니다.' : '이미지 읽기를 선택하지 않은 추출 결과입니다.'))}</p>`}</section>`;
  }).join('');
  return `<section class="ops-subpanel"><dialog id="report-image-dialog" class="report-image-dialog"><button type="button" class="button secondary" data-action="close-image">닫기</button><img alt="보고서 원본 이미지 크게 보기"></dialog><h3>보고서 원문과 읽어온 내용</h3><p>오른쪽 항목을 확인할 때 이 자료와 비교하세요. 이미지의 글자는 잘못 읽힐 수 있습니다.</p>${cards}
    <details${imageEntries.length ? '' : ' open'}><summary>본문·표에서 읽은 글자</summary>${(document.sections || []).map(section => (section.paragraphs || []).map(p => `<div class="ops-source-text"><pre>${escape(p.text)}</pre></div>`).join('')).join('') || '<p>문단에서 읽힌 내용이 없습니다.</p>'}${(document.tables || []).map(table => `<details><summary>보고서 표</summary>${(table.cells || []).map(cell => `<div class="ops-source-text"><pre>${escape(cell.text || (cell.paragraphs || []).map(p => p.text).join('\n'))}</pre></div>`).join('')}</details>`).join('')}</details></section>`;
}
