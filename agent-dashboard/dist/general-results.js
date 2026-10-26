const GENERAL_SCHEMA = 'general-assessment/1';
const STATUSES = new Set(['confirmed', 'not_reproduced', 'inconclusive', 'not_tested']);
const STATUS_LABELS = {
  confirmed: '확정',
  not_reproduced: '재현되지 않음',
  inconclusive: '판정 불가',
  not_tested: '미점검',
};

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = value => typeof value === 'string' ? value : '';
const list = value => Array.isArray(value) ? value : [];
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
const displayTarget = value => text(value) || (object(value) ? text(value.origin) || text(value.fixtureId) : '');
const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char]);

export function generalReport(item) {
  if (!object(item)) return null;
  const report = object(item.report) ? item.report : item;
  return report.schemaVersion === GENERAL_SCHEMA || report.assessmentMode === 'general' && Array.isArray(report.findings)
    ? report : null;
}

export function isGeneralAssessment(item) { return object(item)
  && (item.mode === 'local-lab-general' || item.assessmentMode === 'general' || generalReport(item) !== null); }

function normalizeEvent(event, index, fallbackTime, runId) {
  const source = object(event) ? event : {};
  const time = Number.isFinite(Date.parse(source.time)) ? source.time : fallbackTime;
  const moduleId = text(source.module);
  return {
    ...source,
    id: text(source.id) || `${runId}:general-event:${index + 1}`,
    time,
    module: !moduleId ? 'agent' : /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(moduleId) ? moduleId : 'unknown',
    type: text(source.type) || 'info',
    title: text(source.title) || text(source.stage) || '점검 이벤트',
    detail: text(source.detail),
    iteration: count(source.iteration) ?? 0,
    correlationId: text(source.correlationId),
    latency: typeof source.latency === 'number' && Number.isFinite(source.latency) && source.latency >= 0 ? source.latency : null,
    request: object(source.request) ? source.request : {},
    response: object(source.response) ? source.response : {},
  };
}

/** Adapt a future general run for the current read-only dashboard views. */
export function normalizeGeneralRun(item) {
  if (!isGeneralAssessment(item)) return item;
  const report = generalReport(item);
  const startedAt = Number.isFinite(Date.parse(item.startedAt)) ? item.startedAt
    : Number.isFinite(Date.parse(report?.startedAt)) ? report.startedAt : null;
  const events = list(item.events).map((event, index) => normalizeEvent(event, index, startedAt || '1970-01-01T00:00:00.000Z', text(item.id) || 'general'));
  const snapshots = Object.fromEntries(events.map(event => [event.module, event]));
  return {
    ...item,
    mode: text(item.mode) || 'local-lab-general',
    assessmentMode: 'general',
    report,
    target: displayTarget(item.target) || displayTarget(report?.target),
    startedAt,
    elapsedMs: typeof item.elapsedMs === 'number' && Number.isFinite(item.elapsedMs) && item.elapsedMs >= 0 ? item.elapsedMs : 0,
    simulated: false,
    targetContacted: item.targetContacted === true,
    events,
    snapshots,
    reviewItems: list(item.reviewItems),
    step: events.length,
    totalSteps: Math.max(1, events.length),
    iterations: count(item.iterations) ?? count(report?.iterations) ?? 0,
  };
}

export function generalSummary(item) {
  const report = generalReport(item);
  if (!report) return null;
  const findings = list(report.findings).filter(object);
  const hypotheses = list(report.hypotheses).filter(object);
  const coverage = object(report.coverage) ? report.coverage : {};
  const modelCalls = list(report.modelCalls).filter(object);
  const tokenValues = modelCalls.map(call => object(call.usage) ? [count(call.usage.prompt_tokens ?? call.usage.promptTokens), count(call.usage.completion_tokens ?? call.usage.completionTokens)] : [null, null]);
  const byStatus = status => findings.filter(finding => finding.status === status).length;
  return {
    report, findings, hypotheses,
    totalHypotheses: count(coverage.totalHypotheses) ?? hypotheses.length,
    confirmed: count(coverage.confirmed) ?? byStatus('confirmed'),
    notReproduced: count(coverage.notReproduced) ?? byStatus('not_reproduced'),
    inconclusive: count(coverage.inconclusive) ?? byStatus('inconclusive'),
    notTested: count(coverage.notTested) ?? byStatus('not_tested'),
    probes: list(report.probes).length,
    rejectedProposals: list(report.rejectedProposals).filter(object),
    partial: report.partial === true,
    iteration: count(report.iterations) ?? count(item.iterations) ?? 0,
    modelCalls: modelCalls.length,
    tokenUsage: tokenValues.length && tokenValues.every(pair => pair.every(value => value !== null))
      ? tokenValues.reduce((sum, pair) => sum + pair[0] + pair[1], 0) : null,
  };
}

export function renderGeneralOverview(item) {
  const summary = generalSummary(item);
  if (!summary) {
    const stage = text(list(item?.events).at(-1)?.stage) || text(item?.status) || '실행 대기';
    return `<section class="general-overview" aria-label="범용 점검 진행"><div class="eyebrow">GENERAL ASSESSMENT</div><h3>점검 결과 대기</h3><p>현재 단계: <strong>${escape(stage)}</strong></p><p class="muted">관측과 검증이 끝나면 근거가 있는 결과와 미점검 사유를 표시합니다.</p></section>`;
  }
  const last = list(item.events).at(-1);
  const stage = text(item.stage) || text(summary.report.stage) || text(last?.stage) || '실행 상태 수신 대기';
  const stopped = text(summary.report.stopReason);
  return `<section class="general-overview" aria-label="범용 점검 진행"><div class="eyebrow">GENERAL ASSESSMENT</div><h3>가설과 증거 기반 점검${summary.partial ? ' · 부분 결과' : ''}</h3><p>현재 단계: <strong>${escape(stage)}</strong></p><div class="general-overview-counts"><span>가설 <strong>${summary.totalHypotheses}</strong></span><span>검사 <strong>${summary.probes}</strong></span><span>확정 <strong>${summary.confirmed}</strong></span><span>미점검 <strong>${summary.notTested}</strong></span><span>거부 제안 <strong>${summary.rejectedProposals.length}</strong></span></div><p class="muted">발견한 공격면과 지원 가능한 검사의 범위만 집계합니다. 전체 취약점에 대한 완료율이 아닙니다.</p>${summary.partial ? '<p>일부 모델 제안이 실행되지 않아 점검 범위가 남아 있습니다.</p>' : ''}${stopped ? `<p>종료 사유: ${escape(stopped)}</p>` : ''}</section>`;
}

export function renderGeneralReport(item) {
  const summary = generalSummary(item);
  if (!summary) return '';
  const { report, findings, hypotheses } = summary;
  const evidence = new Map(list(report.evidence).filter(value => object(value) && text(value.id)).map(value => [value.id, value]));
  const unresolved = hypotheses.filter(value => value.status === 'not_tested' || value.status === 'inconclusive');
  const target = displayTarget(item.target) || displayTarget(report.target) || '대상 미기록';
  const findingCards = findings.map((finding, index) => {
    const status = STATUSES.has(finding.status) ? finding.status : 'inconclusive';
    const evidenceRefs = list(finding.evidenceIds).filter(id => typeof id === 'string');
    const evidenceText = evidenceRefs.map(id => {
      const entry = evidence.get(id);
      return `<li><span class="mono">${escape(id)}</span>${entry ? ` · ${escape(text(entry.source) || '출처 미기록')} · ${escape(text(entry.summary) || text(entry.kind) || '증거 내용 미기록')}` : ' · 증거 상세 미제공'}</li>`;
    }).join('');
    return `<article class="panel report-item general-finding"><span class="review-tag">${escape(STATUS_LABELS[status])}</span><h3>${escape(text(finding.category) || '분류 미기록')} · ${escape(text(finding.asset) || '위치 미기록')}</h3><p>${escape(text(finding.rationale) || text(finding.reason) || '설명 미기록')}</p><small>가설 ${escape(text(finding.hypothesisId) || '미기록')} · 결과 ${index + 1}</small>${evidenceRefs.length ? `<div class="evidence-box"><strong>연결된 증거</strong><ul>${evidenceText}</ul></div>` : '<div class="evidence-box"><strong>연결된 증거 없음</strong></div>'}${text(finding.reason) && text(finding.rationale) ? `<p>판정 사유: ${escape(finding.reason)}</p>` : ''}</article>`;
  }).join('');
  const unresolvedMarkup = unresolved.length ? `<section class="panel general-unresolved"><h3>미완료 가설</h3><ul>${unresolved.map(hypothesis => `<li>${escape(text(hypothesis.category) || '분류 미기록')} · ${escape(text(hypothesis.asset) || '위치 미기록')} · ${escape(STATUS_LABELS[hypothesis.status] || '판정 불가')}${text(hypothesis.reason) ? ` · ${escape(hypothesis.reason)}` : ''}</li>`).join('')}</ul></section>` : '';
  const rejectedMarkup = summary.rejectedProposals.length ? `<section class="panel general-unresolved"><h3>실행하지 않은 모델 제안 ${summary.rejectedProposals.length}건</h3><ul>${summary.rejectedProposals.map(row => `<li>반복 ${count(row.iteration) ?? '?'}${count(row.index) === null ? '' : ` · 제안 ${row.index + 1}`} · ${escape(text(row.reason) || '사유 미기록')}</li>`).join('')}</ul></section>` : '';
  return `<section class="panel report-top general-report-top"><div><div class="eyebrow">GENERAL ASSESSMENT / AVAILABLE EVIDENCE</div><h2>범용 점검 결과${summary.partial ? ' · 부분 결과' : ''}</h2><p>${escape(target)}</p><small>반복 ${summary.iteration}회 · 가설 ${summary.totalHypotheses}건 · 검사 ${summary.probes}건 · 거부 제안 ${summary.rejectedProposals.length}건 · 모델 호출 ${summary.modelCalls}건${summary.tokenUsage === null ? ' · 토큰 사용량 미기록' : ` · 기록된 토큰 ${summary.tokenUsage}`}</small></div><div class="report-count"><strong>${findings.length}</strong><span>기록된 결과</span></div></section><section class="panel general-coverage"><h3>점검 범위</h3><div class="general-overview-counts"><span>확정 <strong>${summary.confirmed}</strong></span><span>재현 안 됨 <strong>${summary.notReproduced}</strong></span><span>판정 불가 <strong>${summary.inconclusive}</strong></span><span>미점검 <strong>${summary.notTested}</strong></span></div><p>발견한 가설 기준입니다. 미점검과 판정 불가는 안전하다는 뜻이 아닙니다.</p>${summary.partial ? '<p>부분 결과입니다. 일부 제안이 실행되지 않았으며 남은 공격면은 점검되지 않았습니다.</p>' : ''}${text(report.stopReason) ? `<p>종료 사유: ${escape(report.stopReason)}</p>` : ''}</section><div class="report-items general-report-items">${findingCards || '<section class="panel empty-state"><h3>기록된 결과 없음</h3><p>검사가 끝나기 전이거나 증거가 부족합니다.</p></section>'}</div>${unresolvedMarkup}${rejectedMarkup}`;
}
