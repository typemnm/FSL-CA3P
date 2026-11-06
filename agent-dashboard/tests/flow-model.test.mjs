import test from 'node:test';
import assert from 'node:assert/strict';
import { FLOW_EDGES, FLOW_NODES, deriveFlow, edgeKey, nodeActivityCounts, routeHops } from '../dist/flow-model.js';

const A1 = 'a'.repeat(64); const A2 = 'b'.repeat(64); const A3 = 'c'.repeat(64); const A4 = 'd'.repeat(64);
const at = second => `2026-11-02T01:00:${String(second).padStart(2, '0')}.000Z`;
const event = (n, fields) => ({ id: `run-1:event-${n}`, time: at(n), module: 'agent', type: 'info',
  title: `범용 점검 · ${fields.stage}`, request: {}, response: {}, ...fields });

function generalRun(overrides = {}) {
  return {
    id: 'run-1', mode: 'local-lab-general', status: 'completed', startedAt: at(0), target: 'http://127.0.0.1:4101',
    modelId: 'deepseek-flash',
    events: [
      event(1, { stage: 'observe', iteration: 1, response: { evidenceIds: ['e1', 'e2'],
        evidenceSummaries: [{ id: 'e1', kind: 'surface-observation' }, { id: 'e2', kind: 'historical-reference' }] } }),
      event(2, { stage: 'plan', iteration: 1, request: { hypothesisIds: ['h1'], probeIds: ['p1', 'p2'] } }),
      event(3, { stage: 'policy', iteration: 1, request: { probeId: 'p1', tool: 'execute_attack_template' }, response: { status: 'allowed' } }),
      event(4, { stage: 'execute', iteration: 1, request: { probeId: 'p1', tool: 'execute_attack_template' }, response: { status: 'completed', evidenceIds: ['e3'] } }),
      event(5, { stage: 'verify', iteration: 1, request: { probeId: 'p1', tool: 'execute_attack_template' }, response: { status: 'confirmed', evidenceIds: ['e3'] } }),
      event(6, { stage: 'policy', iteration: 1, request: { probeId: 'p2', tool: 'web_info' }, response: { status: 'blocked', reason: 'out_of_scope' } }),
      event(7, { stage: 'web_info.collected', module: 'web-parser', probeId: 'p3', artifactId: A1, ok: true, detail: 'GET / → HTTP 200' }),
      event(8, { stage: 'complete', response: { status: 'completed', coverage: { confirmed: 1, notTested: 2 } } }),
    ],
    modelCalls: [{ iteration: 1, model: 'deepseek-chat', latencyMs: 1500, usage: { total_tokens: 1200 } }],
    artifacts: [{ id: A1, kind: 'web-info' }, { id: A2, kind: 'run-report' }, { id: A3, kind: 'hwpx-report', findingId: 'f1' }, { id: A4, kind: 'report-preview-html', findingId: 'f1' }],
    report: { findings: [{ id: 'f1', category: 'xss', asset: '/board', status: 'confirmed' }] },
    reportDocuments: { schemaVersion: 'general-report-documents/1', status: 'ready', startedAt: at(9), completedAt: at(20),
      items: [{ findingId: 'f1', status: 'ready', artifactId: A3, previewHtmlArtifactId: A4, filename: 'r.hwpx', startedAt: at(10), completedAt: at(19) }] },
    ...overrides,
  };
}

test('every edge joins two known nodes and nodes have unique ids', () => {
  const ids = new Set(FLOW_NODES.map(node => node.id));
  assert.equal(ids.size, FLOW_NODES.length);
  for (const edge of FLOW_EDGES) assert.ok(ids.has(edge.a) && ids.has(edge.b), `${edge.a}-${edge.b}`);
  assert.equal(new Set(FLOW_EDGES.map(edge => edgeKey(edge.a, edge.b))).size, FLOW_EDGES.length);
});

test('a general run is projected into ordered, routed activities', () => {
  const { runId, activities } = deriveFlow(generalRun());
  assert.equal(runId, 'run-1');
  const titles = activities.map(item => item.title);
  assert.deepEqual(titles.slice(0, 3), ['점검 시작', '공격면 관찰', 'LLM 계획 수립']);
  const observe = activities[1];
  assert.deepEqual(observe.route, ['agent', 'casper', 'agent', 'target', 'agent']);
  const plan = activities[2];
  assert.match(plan.detail, /가설 1건 · 검사 2건 제안/u);
  assert.match(plan.detail, /deepseek-chat · 1,200 tok · 1\.5s/u);
  const template = activities.find(item => item.title === '공격 템플릿 실행');
  assert.deepEqual(template.route, ['agent', 'attack', 'guardrail', 'attack', 'target', 'attack', 'agent']);
  assert.equal(activities.find(item => item.title === '검증 · 취약점 확인').tone, 'success');
  const blocked = activities.find(item => item.eventId === 'run-1:event-6');
  assert.equal(blocked.tone, 'warning');
  assert.match(blocked.detail, /out_of_scope/u);
  assert.equal(activities.at(-1).title, '점검 종료 · 완료');
  const times = activities.map(item => item.timestamp);
  assert.deepEqual(times, [...times].sort((a, b) => a - b));
  assert.equal(new Set(activities.map(item => item.id)).size, activities.length);
});

test('external probe flow shows sLLM review and attack-tool transport', () => {
  const run = generalRun({ mode: 'external-general', events: [
    event(1, { stage: 'guardrail', module: 'guardrail', request: { probeId: 'p1', packetRole: 'single' },
      response: { status: 'IN_SCOPE', reasonCode: 'IN_SCOPE' } }),
    event(2, { stage: 'execute', request: { probeId: 'p1', tool: 'http_get' },
      response: { status: 'completed', evidenceIds: ['e1'] } }),
  ], artifacts: [], reportDocuments: undefined });
  const { activities } = deriveFlow(run);
  const guardrail = activities.find(item => item.title === 'sLLM 요청 판정 · 허용');
  const probe = activities.find(item => item.title === 'HTTP GET 실행');
  assert.deepEqual(guardrail.route, ['agent', 'guardrail', 'agent']);
  assert.deepEqual(probe.route, ['agent', 'attack', 'target', 'attack', 'agent']);
});

test('artifacts are highlighted once each and point to their report area', () => {
  const { activities } = deriveFlow(generalRun());
  const artifacts = activities.filter(item => item.artifact);
  assert.deepEqual(artifacts.map(item => item.artifact.kind), ['web-info', 'run-report', 'hwpx-report']);
  assert.ok(artifacts.every(item => item.tone === 'artifact'));
  const hwpx = artifacts.at(-1);
  assert.deepEqual(hwpx.artifact, { kind: 'hwpx-report', artifactId: A3, findingId: 'f1', label: 'HWPX 보고서', filename: 'r.hwpx', preview: true });
  assert.equal(hwpx.detail, 'xss · /board');
  assert.deepEqual(hwpx.route, ['report', 'store', 'dashboard']);
  // The run-report JSON is stored before the report agent starts.
  const order = activities.map(item => item.title);
  assert.ok(order.indexOf('산출물 · 점검 결과 JSON') < order.indexOf('보고서 작성 시작'));
});

test('activity ids stay stable while a run grows, so a view can find new entries', () => {
  const running = generalRun({ status: 'running', events: generalRun().events.slice(0, 3), artifacts: [], reportDocuments: undefined });
  const first = deriveFlow(running).activities.map(item => item.id);
  const later = deriveFlow(generalRun()).activities.map(item => item.id);
  for (const id of first) assert.ok(later.includes(id), id);
  const generating = generalRun({ status: 'running', reportDocuments: { schemaVersion: 'general-report-documents/1', status: 'generating',
    startedAt: at(9), items: [{ findingId: 'f1', status: 'generating', startedAt: at(10) }] }, artifacts: [{ id: A2, kind: 'run-report' }] });
  const before = deriveFlow(generating).activities;
  assert.ok(before.some(item => item.title === '보고서 작성 시작'));
  assert.ok(!before.some(item => item.artifact?.kind === 'hwpx-report'));
});

test('failures, empty runs and archived modules degrade without throwing', () => {
  assert.deepEqual(deriveFlow(null), { runId: null, activities: [] });
  assert.deepEqual(deriveFlow({ id: null, events: [] }).activities, []);
  const failed = deriveFlow({ id: 'run-2', status: 'failed', startedAt: 'not a date', error: 'GENERAL_RUNTIME_FAILED',
    events: [{ id: 'x1', stage: 'general.failed', type: 'error', title: '범용 점검 실패', time: 'bad', request: {}, response: {} },
      { id: 'x2', module: 'guardrail', title: '정책 검사', time: at(3) }, 'garbage'],
    reportDocument: { status: 'failed', startedAt: at(4), completedAt: at(5), message: 'boom' } }).activities;
  assert.equal(failed.find(item => item.id === 'x1').tone, 'error');
  assert.deepEqual(failed.find(item => item.id === 'x2').route, ['agent', 'guardrail', 'agent']);
  assert.ok(failed.some(item => item.title === '보고서 생성 실패' && item.detail.includes('boom')));
  assert.equal(failed.at(-1).tone, 'error');
});

test('routes only use drawn links and node counts include every visited node', () => {
  assert.deepEqual(routeHops(['agent', 'attack', 'guardrail', 'attack']), [['agent', 'attack'], ['attack', 'guardrail'], ['guardrail', 'attack']]);
  assert.deepEqual(routeHops(['parser', 'store']), []);
  const counts = nodeActivityCounts(deriveFlow(generalRun()).activities);
  assert.ok(counts.agent > 0 && counts.guardrail >= 3 && counts.report >= 2 && counts.casper === 1);
  for (const activity of deriveFlow(generalRun()).activities) {
    for (let index = 1; index < activity.route.length; index += 1) {
      const pair = [activity.route[index - 1], activity.route[index]];
      assert.equal(routeHops(pair).length, 1, `${activity.title}: ${pair.join('→')} has no link`);
    }
  }
});
