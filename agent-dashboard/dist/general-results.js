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

const PHASES = [
  { id: 'observe', label: '관측' }, { id: 'plan', label: '계획' },
  { id: 'policy', label: '정책' }, { id: 'execute', label: '실행' },
  { id: 'verify', label: '검증' },
];

function phaseFor(stage) {
  const value = text(stage).toLowerCase();
  const last = value.split(/[.:]/u).at(-1);
  if (value === 'inventory.collect') return 'observe';
  if (last === 'observe' || last === 'plan' || last === 'policy'
    || last === 'execute' || last === 'verify') return last;
  if (last === 'plan_rejected') return 'plan';
  return null;
}

function probeIdFor(event) {
  const id = text(event?.request?.probeId) || text(event?.probeId);
  return id.slice(0, 128);
}

const safeId = value => text(value).slice(0, 128);
const eventRequest = event => object(event?.request) ? event.request : {};
const eventResponse = event => object(event?.response) ? event.response : {};

function latestProgress(events) {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const value = eventResponse(events[index]).progress;
    if (!object(value)) continue;
    const progress = Object.fromEntries([
      'hypothesisCount', 'probeCount', 'evidenceCount', 'confirmedProbeCount',
      'notReproducedProbeCount', 'inconclusiveProbeCount', 'blockedProbeCount',
      'remainingProbeBudget',
    ].map(key => [key, count(value[key])]));
    if (Object.values(progress).some(value => value !== null)) return progress;
  }
  return null;
}

function progressCounts(progress, fields) {
  if (!progress) return '';
  const rows = fields.filter(([, key]) => progress[key] !== null);
  return rows.length ? '<div class="general-overview-counts">'
    + rows.map(([label, key]) => '<span>' + label + ' <strong>' + progress[key] + '</strong></span>').join('')
    + '</div>' : '';
}

function plannedProbeLinks(events) {
  const links = new Map();
  for (const event of events) {
    if (phaseFor(event?.stage) !== 'plan') continue;
    for (const link of list(eventRequest(event).probeLinks).slice(0, 32).filter(object)) {
      const probeId = safeId(link.probeId);
      if (links.size >= 128 && !links.has(probeId)) continue;
      if (probeId) links.set(probeId, { hypothesisId: safeId(link.hypothesisId), tool: safeId(link.tool) });
    }
  }
  return links;
}

function liveMetadata(events) {
  const hypotheses = new Map();
  const evidence = new Map();
  for (const event of events) {
    const phase = phaseFor(event?.stage);
    if (phase === 'plan') for (const item of list(eventRequest(event).hypothesisSummaries).slice(0, 32)) {
      if (!object(item)) continue;
      const id = safeId(item.id);
      const category = text(item.category).slice(0, 128);
      const asset = text(item.asset).slice(0, 512);
      if (id && category && asset && (hypotheses.has(id) || hypotheses.size < 128)) {
        hypotheses.set(id, { category, asset });
      }
    }
    if (phase === 'observe' || phase === 'execute') {
      for (const item of list(eventResponse(event).evidenceSummaries).slice(0, 32)) {
        if (!object(item)) continue;
        const id = safeId(item.id);
        const kind = text(item.kind).slice(0, 128);
        const asset = text(item.asset).slice(0, 512);
        if (id && kind && (evidence.has(id) || evidence.size < 256)) {
          evidence.set(id, { kind, asset });
        }
      }
    }
  }
  return { hypotheses, evidence };
}

function renderLiveMetadata(metadata) {
  const hypotheses = [...metadata.hypotheses].map(([id, item]) => '<li><span class="mono">'
    + escape(id) + '</span> · ' + escape(item.category) + ' · ' + escape(item.asset) + '</li>').join('');
  const evidence = [...metadata.evidence].map(([id, item]) => '<li><span class="mono">'
    + escape(id) + '</span> · ' + escape(item.kind) + ' · '
    + escape(item.asset || '자산 미기록') + '</li>').join('');
  return (hypotheses ? '<details class="general-live-metadata"><summary>계획한 가설 '
    + metadata.hypotheses.size + '건 · 잠정 정보</summary><ul>' + hypotheses + '</ul></details>' : '')
    + (evidence ? '<details class="general-live-metadata"><summary>수집된 증거 메타데이터 '
      + metadata.evidence.size + '건</summary><ul>' + evidence + '</ul></details>' : '');
}

export function generalObservedProbeCount(item) {
  return new Set(list(item?.events).map(probeIdFor).filter(Boolean)).size;
}

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

/** Show observed phases only. An unobserved phase is never counted as complete. */
export function renderGeneralLoop(item, selectedEventId = null) {
  const events = list(item?.events).filter(object);
  const progress = latestProgress(events);
  const phasesByIteration = new Map();
  for (const event of events) {
    const phase = phaseFor(event.stage);
    if (!phase) continue;
    const iteration = count(event.iteration) ?? 0;
    if (!phasesByIteration.has(iteration)) phasesByIteration.set(iteration, new Map());
    const phases = phasesByIteration.get(iteration);
    phases.set(phase, [...(phases.get(phase) ?? []), event]);
  }
  const rows = [...phasesByIteration].sort(([a], [b]) => a - b);
  if (!rows.length) rows.push([count(item?.iterations) ?? 0, new Map()]);
  const flow = rows.map(([iteration, phases]) => {
    const nodes = PHASES.map(phase => {
      const records = phases.get(phase.id) ?? [];
      const latest = records.at(-1);
      const content = '<strong>' + phase.label + '</strong><small>'
        + (records.length ? '기록 ' + records.length + '건' : '미관측') + '</small>';
      return latest
        ? '<button type="button" class="general-loop-phase is-observed'
          + (latest.id === selectedEventId ? ' is-selected' : '')
          + '" data-general-event="' + escape(text(latest.id)) + '">' + content + '</button>'
        : '<span class="general-loop-phase">' + content + '</span>';
    }).join('<span class="general-loop-arrow" aria-hidden="true">→</span>');
    return '<div class="general-loop-iteration"><h4>'
      + (iteration ? '반복 ' + iteration : '반복 번호 미기록')
      + '</h4><div class="general-loop-flow">' + nodes + '</div></div>';
  }).join('');
  const lastStage = text(events.at(-1)?.stage) || text(item?.status) || '실행 대기';
  const summary = generalSummary(item);
  const heading = summary ? '가설과 증거 기반 점검' + (summary.partial ? ' · 부분 결과' : '') : '점검 결과 대기';
  const counts = summary
    ? '<span>가설 <strong>' + summary.totalHypotheses + '</strong></span>'
      + '<span>검사 <strong>' + summary.probes + '</strong></span>'
      + '<span>확정 <strong>' + summary.confirmed + '</strong></span>'
      + '<span>미점검 <strong>' + summary.notTested + '</strong></span>'
    : progress
      ? '<span>가설 <strong>' + (progress.hypothesisCount ?? '?') + '</strong></span>'
        + '<span>실행 검사 <strong>' + (progress.probeCount ?? '?') + '</strong></span>'
        + '<span>수집 증거 <strong>' + (progress.evidenceCount ?? '?') + '</strong></span>'
        + '<span>남은 검사 예산 <strong>' + (progress.remainingProbeBudget ?? '?') + '</strong></span>'
    : '<span>수신 이벤트 <strong>' + events.length + '</strong></span>'
      + '<span>기록된 검사 ID <strong>' + generalObservedProbeCount(item) + '</strong></span>';
  return '<section class="general-loop" aria-label="범용 Agent loop">'
    + '<div class="eyebrow">GENERAL ASSESSMENT / OBSERVED LOOP</div><h3>' + heading + '</h3>'
    + '<p>최근 단계: <strong>' + escape(lastStage) + '</strong></p>'
    + '<div class="general-overview-counts">' + counts + '</div>'
    + '<div class="general-loop-iterations">' + flow + '</div>'
    + '<p class="general-loop-note">실제로 수신한 단계만 기록으로 표시합니다. 진행 수치는 검사 기준이며 전체 취약점에 대한 완료율이 아닙니다.</p>'
    + '</section>';
}

/** A verify event is a probe observation, not a persisted finding. */
export function renderGeneralLiveResults(item) {
  const summary = generalSummary(item);
  if (!summary) {
    const events = list(item?.events).filter(object);
    const progress = latestProgress(events);
    const links = plannedProbeLinks(events);
    const metadata = liveMetadata(events);
    const outcomes = events.filter(event => phaseFor(event.stage) === 'verify'
      || phaseFor(event.stage) === 'policy' && (text(eventResponse(event).status) || text(event.detail)) === 'blocked');
    const rows = outcomes.map(event => {
      const phase = phaseFor(event.stage);
      const response = eventResponse(event);
      const request = eventRequest(event);
      const verdict = text(response.status) || text(event.detail);
      const label = phase === 'policy' ? '정책 차단'
        : STATUSES.has(verdict) && verdict !== 'not_tested' ? STATUS_LABELS[verdict] : '상태 미확인';
      const probeId = probeIdFor(event);
      const link = links.get(probeId);
      const hypothesisId = safeId(request.hypothesisId) || link?.hypothesisId;
      const tool = safeId(request.tool) || link?.tool;
      const hypothesis = metadata.hypotheses.get(hypothesisId);
      const evidenceIds = list(response.evidenceIds).filter(value => typeof value === 'string')
        .slice(0, 32).map(safeId).filter(Boolean);
      const evidenceDescriptions = evidenceIds.map(id => {
        const entry = metadata.evidence.get(id);
        return entry ? '<small>증거 ' + escape(id) + ': ' + escape(entry.kind) + ' · '
          + escape(entry.asset || '자산 미기록') + '</small>' : '';
      }).join('');
      const reason = text(response.reason).slice(0, 128);
      const context = [hypothesisId && '가설 ' + hypothesisId, tool && '도구 ' + tool,
        '반복 ' + (count(event.iteration) ?? '?')].filter(Boolean).join(' · ');
      return '<li class="general-live-result"><strong>검사 '
        + escape(probeId || 'ID 미기록') + '</strong><span>' + escape(label)
        + ' · ' + escape(context) + '</span>'
        + (hypothesis ? '<small>가설 내용: ' + escape(hypothesis.category) + ' · '
          + escape(hypothesis.asset) + '</small>' : '')
        + (evidenceIds.length ? '<small>증거 ID: ' + evidenceIds.map(escape).join(', ') + '</small>' : '')
        + evidenceDescriptions
        + (reason ? '<small>사유: ' + escape(reason) + '</small>' : '') + '</li>';
    }).join('');
    return '<div class="general-live-body"><p>최종 보고서 전의 검사 이벤트입니다. 취약점 확정 건수로 집계하지 않습니다.</p>'
      + progressCounts(progress, [
        ['가설', 'hypothesisCount'], ['실행 검사', 'probeCount'], ['수집 증거', 'evidenceCount'],
        ['확정 판정 검사', 'confirmedProbeCount'], ['정책 차단 검사', 'blockedProbeCount'],
      ])
      + renderLiveMetadata(metadata)
      + (rows ? '<ul class="general-live-result-list">' + rows + '</ul>'
        : '<p class="general-live-empty">독립 검증 이벤트를 기다리는 중입니다.</p>')
      + '<p class="general-live-note">가설 분류·자산과 증거 종류·자산은 잠정 메타데이터입니다. 원문 근거와 최종 finding 수는 보고서 저장 후 표시됩니다. 메타데이터가 없는 이전 기록은 ID만 표시합니다.</p></div>';
  }
  const evidence = new Map(list(summary.report.evidence)
    .filter(value => object(value) && text(value.id)).map(value => [value.id, value]));
  const rows = summary.findings.map(finding => {
    const status = STATUSES.has(finding.status) ? finding.status : 'inconclusive';
    const references = list(finding.evidenceIds).filter(id => typeof id === 'string');
    const details = references.map(id => {
      const row = evidence.get(id);
      return '<li><span class="mono">' + escape(id) + '</span>'
        + (row ? ' · ' + escape(text(row.summary).slice(0, 250) || text(row.kind) || '증거 설명 미기록')
          : ' · 증거 상세 미제공') + '</li>';
    }).join('');
    return '<li class="general-live-result"><strong>'
      + escape(text(finding.category) || '분류 미기록') + ' · '
      + escape(text(finding.asset) || '위치 미기록') + '</strong><span>'
      + escape(STATUS_LABELS[status]) + '</span>'
      + (text(finding.reason) ? '<small>사유: ' + escape(finding.reason) + '</small>' : '')
      + (details ? '<ul class="general-live-evidence">' + details + '</ul>' : '') + '</li>';
  }).join('');
  return '<div class="general-live-body"><div class="general-overview-counts">'
    + '<span>확정 <strong>' + summary.confirmed + '</strong></span>'
    + '<span>재현 안 됨 <strong>' + summary.notReproduced + '</strong></span>'
    + '<span>판정 불가 <strong>' + summary.inconclusive + '</strong></span>'
    + '<span>미점검 <strong>' + summary.notTested + '</strong></span></div>'
    + (rows ? '<ul class="general-live-result-list">' + rows + '</ul>'
      : '<p class="general-live-empty">기록된 결과가 없습니다.</p>')
    + '<p class="general-live-note">발견한 가설 기준입니다. 미점검과 판정 불가는 안전 판정이 아닙니다.</p></div>';
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
