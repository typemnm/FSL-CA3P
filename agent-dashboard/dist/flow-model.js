/**
 * Read-only projection of one stored run into module-to-module transfers and
 * an activity summary. The input is the same run state the API already pushes
 * over SSE (`run.events`, `run.modelCalls`, `run.artifacts`,
 * `run.reportDocument(s)`), so no module has to emit anything new.
 */

export const FLOW_NODES = Object.freeze([
  { id: 'dashboard', name: '대시보드 · API', role: 'SSE · 승인', x: 90, y: 240, icon: 'grid' },
  { id: 'store', name: 'Run Store', role: 'SQLite 실행 기록', x: 250, y: 400, icon: 'archive' },
  { id: 'casper', name: 'Casper DB', role: '과거 사례 · 카탈로그', x: 250, y: 80, icon: 'database' },
  { id: 'llm', name: 'LLM', role: '계획 · 판정 모델', x: 500, y: 62, icon: 'sparkles' },
  { id: 'agent', name: 'Agent Core', role: 'worker · 점검 루프', x: 500, y: 240, icon: 'brain' },
  { id: 'report', name: 'Report Agent', role: 'HWPX 작성', x: 500, y: 418, icon: 'file' },
  { id: 'verifier', name: 'Verifier', role: '독립 판정', x: 730, y: 70, icon: 'check' },
  { id: 'guardrail', name: 'Guardrail', role: '정책 검사', x: 730, y: 180, icon: 'shield' },
  { id: 'parser', name: 'Web Parser', role: '브라우저 관찰', x: 730, y: 300, icon: 'scan' },
  { id: 'attack', name: 'Attack Tool', role: 'JSON-RPC 실행', x: 730, y: 410, icon: 'terminal' },
  { id: 'target', name: '점검 대상', role: '실습 · 외부 URL', x: 920, y: 240, icon: 'globe' },
].map(Object.freeze));

/** Undirected links. `via` bends a link around a node that sits on the straight line. */
export const FLOW_EDGES = Object.freeze([
  { a: 'dashboard', b: 'store', channel: 'HTTP · SSE' },
  { a: 'dashboard', b: 'agent', channel: 'IPC · 승인' },
  { a: 'store', b: 'agent', channel: 'SQLite' },
  { a: 'agent', b: 'casper', channel: 'snapshot' },
  { a: 'agent', b: 'llm', channel: 'HTTPS' },
  { a: 'agent', b: 'verifier', channel: 'port' },
  { a: 'verifier', b: 'llm', channel: 'HTTPS' },
  { a: 'agent', b: 'guardrail', channel: 'port' },
  { a: 'agent', b: 'parser', channel: 'Playwright' },
  { a: 'agent', b: 'attack', channel: 'JSON-RPC' },
  { a: 'attack', b: 'guardrail', channel: 'authorize', via: { x: 830, y: 295 } },
  { a: 'agent', b: 'target', channel: 'HTTP' },
  { a: 'parser', b: 'target', channel: 'browser' },
  { a: 'attack', b: 'target', channel: 'HTTP' },
  { a: 'store', b: 'report', channel: 'read-only' },
  { a: 'report', b: 'llm', channel: 'HTTPS', via: { x: 340, y: 240 } },
].map(Object.freeze));

export const edgeKey = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);

export const ARTIFACT_LABELS = Object.freeze({
  'run-report': '점검 결과 JSON',
  'web-info': '웹 정보 JSON',
  'hwpx-report': 'HWPX 보고서',
  'report-preview': '보고서 미리보기',
  'report-preview-html': '보고서 미리보기',
});

const TOOL_LABELS = { execute_attack_template: '공격 템플릿', http_get: 'HTTP GET', web_info: '웹 정보 수집', repository_read: '소스 읽기' };
const STATUS_LABELS = {
  allowed: '허용', blocked: '차단', confirmed: '취약점 확인', not_reproduced: '재현 안 됨', inconclusive: '판단 보류',
  approved: '승인', rejected: '거절', timed_out: '승인 시간 초과', completed: '완료', failed: '실패', cancelled: '취소',
  stopped: '중지', interrupted: '중단', pending: '대기', invalid_model_plan: '계획 형식 오류', invalid_model_proposal: '제안 형식 오류',
};
const TERMINAL = new Set(['completed', 'failed', 'stopped', 'cancelled', 'interrupted']);
const CASPER_EVIDENCE = new Set(['historical-reference', 'draft-advisory']);
const TARGET_EVIDENCE = new Set(['surface-observation', 'authenticated-surface', 'http-response', 'source-excerpt',
  'dependency-manifest', 'dependency-reference', 'template-exchange']);
/** Event `module` ids from current and archived runs mapped to graph nodes. */
const MODULE_NODES = {
  agent: 'agent', 'web-parser': 'parser', parser: 'parser', browser: 'parser', casper: 'casper', knowledge: 'casper',
  attack: 'attack', guardrail: 'guardrail', policy: 'guardrail', pentest: 'store', recorder: 'store',
  reasoning: 'llm', observer: 'verifier', webpage: 'target', 'external-observer': 'target', 'external-general': 'agent',
};
const ARTIFACT_ID = /^[a-f0-9]{64}$/u;

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const list = value => (Array.isArray(value) ? value : []);
const text = value => (typeof value === 'string' ? value : '');
const count = value => (Number.isSafeInteger(value) && value >= 0 ? value : null);
const status = value => STATUS_LABELS[value] || text(value);
const tone = value => (value === 'confirmed' ? 'success' : ['blocked', 'rejected', 'timed_out', 'inconclusive'].includes(value)
  ? 'warning' : ['failed', 'interrupted'].includes(value) ? 'error' : value === 'not_reproduced' ? 'muted' : 'info');

/** Route of an executed probe through the modules that carried it. */
function toolRoute(tool) {
  if (tool === 'execute_attack_template') return ['agent', 'attack', 'guardrail', 'attack', 'target', 'attack', 'agent'];
  if (tool === 'web_info') return ['agent', 'parser', 'target', 'parser', 'agent'];
  if (tool === 'http_get' || tool === 'repository_read') return ['agent', 'target', 'agent'];
  return ['agent'];
}

function observeRoute(summaries) {
  const kinds = new Set(list(summaries).map(item => text(item?.kind)));
  const route = ['agent'];
  if ([...kinds].some(kind => CASPER_EVIDENCE.has(kind))) route.push('casper', 'agent');
  if (!kinds.size || [...kinds].some(kind => TARGET_EVIDENCE.has(kind))) route.push('target', 'agent');
  return route;
}

function modelSummary(calls) {
  if (!calls.length) return '';
  const tokens = calls.reduce((sum, call) => sum + (count(call?.usage?.total_tokens)
    ?? (count(call?.usage?.prompt_tokens) ?? 0) + (count(call?.usage?.completion_tokens) ?? 0)), 0);
  const latency = calls.reduce((sum, call) => sum + (Number.isFinite(call?.latencyMs) ? call.latencyMs : 0), 0);
  const model = text(calls.at(-1)?.reportedModel) || text(calls.at(-1)?.model) || text(calls.at(-1)?.requestedModel);
  return [model, tokens ? `${tokens.toLocaleString('ko-KR')} tok` : '', latency ? `${(latency / 1000).toFixed(1)}s` : '']
    .filter(Boolean).join(' · ');
}

function eventActivity(event, modelCalls) {
  const request = object(event.request) ? event.request : {};
  const response = object(event.response) ? event.response : {};
  const stage = text(event.stage);
  const probe = text(request.probeId) || text(event.probeId);
  const tool = text(request.tool) || text(event.tool);
  const result = text(response.status) || text(event.status);
  const reason = text(response.reason);
  const probeLabel = probe ? ` · ${probe}` : '';
  const evidence = list(response.evidenceIds).length;
  const iteration = count(event.iteration);
  const round = iteration ? `반복 ${iteration}` : '';
  const base = { eventId: text(event.id), time: event.time };
  switch (stage) {
    case 'observe': {
      const external = event.module === 'external-observer';
      return { ...base, node: external ? 'target' : 'agent', tone: 'info', title: external ? '공개 페이지 관찰' : '공격면 관찰',
        detail: [round, external ? text(event.detail) : `증거 ${evidence}건 수집`].filter(Boolean).join(' · '),
        route: external ? ['agent', 'target', 'agent'] : observeRoute(response.evidenceSummaries) };
    }
    case 'plan': {
      const hypotheses = list(request.hypothesisIds).length;
      const probes = list(request.probeIds).length;
      const calls = modelCalls.get(iteration) ?? [];
      return { ...base, node: 'llm', tone: 'info', title: request.done ? 'LLM 점검 종료 판단' : 'LLM 계획 수립',
        detail: [`가설 ${hypotheses}건 · 검사 ${probes}건 제안`, modelSummary(calls)].filter(Boolean).join(' · '),
        route: ['agent', 'llm', 'agent'] };
    }
    case 'plan_rejected':
      return { ...base, node: 'llm', tone: 'warning', title: 'LLM 제안 거부',
        detail: [status(result), count(response.rejectedCount) ? `${response.rejectedCount}건` : ''].filter(Boolean).join(' · '),
        route: ['agent', 'llm', 'agent'] };
    case 'policy':
      return { ...base, node: 'guardrail', tone: result === 'blocked' ? 'warning' : 'success',
        title: `가드레일 ${status(result) || '검사'}`, detail: `${TOOL_LABELS[tool] || tool || '검사'}${probeLabel}${reason ? ` · ${reason}` : ''}`,
        route: ['agent', 'guardrail', 'agent'] };
    case 'approval.requested':
      return { ...base, node: 'dashboard', tone: 'warning', title: '관리자 승인 요청',
        detail: `실행 전 승인 대기${request.probeId ? ` · ${request.probeId}` : ''}`, route: ['agent', 'dashboard'] };
    case 'approval.resolved':
      return { ...base, node: 'dashboard', tone: tone(text(response.decision)), title: `승인 결정 · ${status(text(response.decision)) || '반영'}`,
        detail: text(response.actor) ? `결정자 ${response.actor}` : '', route: ['dashboard', 'agent'] };
    case 'approval':
      return { ...base, node: 'agent', tone: tone(result), title: `승인 결과 반영 · ${status(result)}`,
        detail: `${TOOL_LABELS[tool] || tool || '검사'}${probeLabel}`, route: [] };
    case 'execute':
      return { ...base, node: tool === 'execute_attack_template' ? 'attack' : tool === 'web_info' ? 'parser' : 'target',
        tone: 'info', title: `${TOOL_LABELS[tool] || tool || '검사'} 실행`, detail: `${probe || '검사'} · 증거 ${evidence}건`,
        route: toolRoute(tool) };
    case 'verify':
      return { ...base, node: 'verifier', tone: tone(result), title: `검증 · ${status(result) || '판정'}`,
        detail: `${TOOL_LABELS[tool] || tool || '검사'}${probeLabel}${reason ? ` · ${reason}` : ''}`,
        route: evidence ? ['agent', 'verifier', 'llm', 'verifier', 'agent'] : ['agent', 'verifier', 'agent'] };
    case 'complete': {
      const coverage = object(response.coverage) ? response.coverage : {};
      const parts = [['확인', coverage.confirmed], ['미재현', coverage.notReproduced], ['보류', coverage.inconclusive], ['미점검', coverage.notTested]]
        .filter(([, value]) => count(value)).map(([label, value]) => `${label} ${value}`);
      return { ...base, node: 'agent', tone: result === 'failed' ? 'error' : 'success', title: '점검 루프 종료',
        detail: parts.join(' · ') || text(event.detail) || status(result), route: ['agent', 'store'] };
    }
    case 'web_info.collected':
      return { ...base, node: 'parser', tone: event.ok === false ? 'warning' : 'info',
        title: event.ok === false ? '웹 정보 수집 실패' : '웹 정보 수집', detail: text(event.detail) || text(event.asset),
        route: ['parser', 'agent', 'store'] };
    default: {
      const node = MODULE_NODES[text(event.module)] ?? 'agent';
      const failed = text(event.type) === 'error' || /\.failed$/u.test(stage);
      const route = /^idor\.(?!prepare|skipped|reflect|failed)/u.test(stage) ? toolRoute('execute_attack_template')
        : stage === 'scope.rejected' ? ['agent', 'guardrail', 'agent']
          : /^observe\./u.test(stage) ? ['agent', 'target', 'agent']
            : node === 'agent' ? [] : ['agent', node, 'agent'];
      return { ...base, node: stage === 'scope.rejected' ? 'guardrail' : node,
        tone: failed ? 'error' : text(event.type) === 'warning' ? 'warning' : 'info',
        title: text(event.title) || stage || '점검 이벤트', detail: text(event.detail), route };
    }
  }
}

function documentEntries(run) {
  const documents = run.reportDocuments;
  if (object(documents) && documents.schemaVersion === 'general-report-documents/1') {
    return { items: list(documents.items).filter(object), summary: documents };
  }
  return object(run.reportDocument) ? { items: [{ ...run.reportDocument, findingId: null }], summary: null } : { items: [], summary: null };
}

/**
 * Builds the ordered activity list for one run. Every activity has a stable
 * `id`, so a view can tell new activity apart from activity it already showed.
 */
export function deriveFlow(run) {
  if (!object(run) || !text(run.id)) return { runId: null, activities: [] };
  const runId = run.id;
  const activities = [];
  let order = 0;
  const push = activity => { activities.push({ route: [], detail: '', ...activity, order: order++ }); };
  const findings = new Map(list(run.report?.findings).filter(object).map(item => [text(item.id), item]));
  const findingLabel = id => {
    const finding = findings.get(text(id));
    return finding ? `${text(finding.category) || '분류 미상'} · ${text(finding.asset) || '위치 미상'}` : text(id);
  };
  const artifacts = list(run.artifacts).filter(item => object(item) && ARTIFACT_ID.test(text(item.id)));
  const artifactById = new Map(artifacts.map(item => [item.id, item]));
  const covered = new Set();
  const modelCalls = new Map();
  for (const call of list(run.modelCalls).length ? run.modelCalls : list(run.report?.modelCalls)) {
    if (!object(call)) continue;
    const key = count(call.iteration);
    modelCalls.set(key, [...(modelCalls.get(key) ?? []), call]);
  }
  const target = text(run.target) || text(run.report?.target?.origin);

  push({ id: `${runId}:start`, time: run.startedAt, node: 'agent', tone: 'info', title: '점검 시작',
    detail: [target, text(run.modelId)].filter(Boolean).join(' · '), route: ['dashboard', 'store', 'agent'] });

  for (const event of list(run.events)) {
    if (!object(event) || !text(event.id)) continue;
    const activity = eventActivity(event, modelCalls);
    if (!activity) continue;
    const artifactId = text(event.artifactId);
    if (event.stage === 'web_info.collected' && ARTIFACT_ID.test(artifactId)) {
      covered.add(artifactId);
      activity.tone = 'artifact';
      activity.title = `산출물 · ${ARTIFACT_LABELS['web-info']}`;
      activity.artifact = { kind: 'web-info', artifactId, label: ARTIFACT_LABELS['web-info'] };
    }
    push({ id: event.id, ...activity });
  }

  const lastEventTime = list(run.events).at(-1)?.time ?? run.startedAt;
  const { items: documents, summary } = documentEntries(run);
  const reportStarted = summary?.startedAt ?? documents[0]?.startedAt ?? null;
  for (const artifact of artifacts.filter(item => item.kind === 'run-report')) {
    covered.add(artifact.id);
    push({ id: `${runId}:artifact:${artifact.id}`, time: reportStarted ?? run.completedAt ?? lastEventTime, node: 'store',
      tone: 'artifact', title: `산출물 · ${ARTIFACT_LABELS['run-report']}`, detail: '검증된 최종 결과와 근거',
      route: ['agent', 'store'], artifact: { kind: 'run-report', artifactId: artifact.id, label: ARTIFACT_LABELS['run-report'] } });
  }
  for (const document of documents) {
    const findingId = text(document.findingId) || null;
    const key = `${runId}:report:${findingId ?? 'single'}`;
    const label = findingId ? findingLabel(findingId) : '실행 보고서';
    if (document.startedAt) {
      push({ id: `${key}:start`, time: document.startedAt, node: 'report', tone: 'info', title: '보고서 작성 시작',
        detail: label, route: ['store', 'report', 'llm', 'report'] });
    }
    if (document.status === 'ready' && ARTIFACT_ID.test(text(document.artifactId))) {
      for (const id of [document.artifactId, document.previewArtifactId, document.previewHtmlArtifactId]) if (id) covered.add(id);
      push({ id: `${key}:ready:${document.artifactId}`, time: document.completedAt ?? document.startedAt ?? lastEventTime,
        node: 'report', tone: 'artifact', title: `산출물 · ${ARTIFACT_LABELS['hwpx-report']}`, detail: label,
        route: ['report', 'store', 'dashboard'],
        artifact: { kind: 'hwpx-report', artifactId: document.artifactId, findingId, label: ARTIFACT_LABELS['hwpx-report'],
          filename: text(document.filename) || text(artifactById.get(document.artifactId)?.filename) || 'ca3p-report.hwpx',
          preview: Boolean(document.previewHtmlArtifactId || document.previewArtifactId) } });
    } else if (['failed', 'unavailable'].includes(document.status)) {
      push({ id: `${key}:${document.status}`, time: document.completedAt ?? document.startedAt ?? lastEventTime, node: 'report',
        tone: 'error', title: document.status === 'failed' ? '보고서 생성 실패' : '보고서 생성 환경 확인 필요',
        detail: [label, text(document.message)].filter(Boolean).join(' · '), route: ['report', 'store'] });
    }
  }
  if (summary && summary.status === 'skipped' && summary.completedAt) {
    push({ id: `${runId}:report:skipped`, time: summary.completedAt, node: 'report', tone: 'muted',
      title: '보고서 작성 생략', detail: text(summary.message), route: [] });
  }
  for (const artifact of artifacts) {
    if (covered.has(artifact.id)) continue;
    const kind = text(artifact.kind);
    const findingId = text(artifact.findingId) || null;
    push({ id: `${runId}:artifact:${artifact.id}`, time: lastEventTime, node: kind === 'web-info' ? 'parser' : kind.startsWith('report') || kind === 'hwpx-report' ? 'report' : 'store',
      tone: 'artifact', title: `산출물 · ${ARTIFACT_LABELS[kind] || kind}`, detail: findingId ? findingLabel(findingId) : text(artifact.filename),
      route: [], artifact: { kind, artifactId: artifact.id, findingId, label: ARTIFACT_LABELS[kind] || kind, filename: text(artifact.filename) } });
  }
  if (TERMINAL.has(run.status)) {
    push({ id: `${runId}:end:${run.status}`, time: run.completedAt ?? summary?.completedAt ?? documents.at(-1)?.completedAt
      ?? run.reportDocument?.completedAt ?? lastEventTime, node: 'agent',
    tone: run.status === 'completed' ? 'success' : run.status === 'failed' || run.status === 'interrupted' ? 'error' : 'muted',
    title: `점검 종료 · ${status(run.status)}`, detail: text(run.error), route: ['agent', 'store', 'dashboard'] });
  }

  // Keep stored order for equal or missing timestamps; never move an entry before its predecessor's time.
  let previous = Date.parse(run.startedAt) || 0;
  for (const activity of activities) {
    const parsed = Date.parse(activity.time);
    activity.timestamp = Number.isFinite(parsed) ? parsed : previous;
    if (Number.isFinite(parsed)) previous = parsed;
  }
  activities.sort((a, b) => a.timestamp - b.timestamp || a.order - b.order);
  return { runId, activities };
}

/** Number of activities that passed through each node; used for node badges. */
export function nodeActivityCounts(activities) {
  const counts = Object.fromEntries(FLOW_NODES.map(node => [node.id, 0]));
  for (const activity of activities) {
    for (const id of new Set([activity.node, ...activity.route])) if (Object.hasOwn(counts, id)) counts[id] += 1;
  }
  return counts;
}

/** Splits a route into hops that have a drawn link. Hops without one are skipped. */
export function routeHops(route) {
  const edges = new Set(FLOW_EDGES.map(edge => edgeKey(edge.a, edge.b)));
  const hops = [];
  for (let index = 1; index < route.length; index += 1) {
    const from = route[index - 1]; const to = route[index];
    if (from !== to && edges.has(edgeKey(from, to))) hops.push([from, to]);
  }
  return hops;
}
