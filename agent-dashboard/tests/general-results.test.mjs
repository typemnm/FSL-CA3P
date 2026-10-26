import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generalReport, generalSummary, isGeneralAssessment, normalizeGeneralRun,
  renderGeneralOverview, renderGeneralReport,
} from '../dist/general-results.js';

function result() {
  return {
    schemaVersion: 'general-assessment/1', assessmentMode: 'general', target: { fixtureId: 'vul-web2-daehan', origin: 'http://127.0.0.1:4101' },
    status: 'completed', iterations: 3, stopReason: 'request budget reached',
    inventory: [{ asset: '/search' }],
    evidence: [{ id: 'e-1', source: 'http-response', kind: 'status', summary: 'different role response' }],
    hypotheses: [
      { id: 'h-1', category: 'access_control', asset: '/api/item/1', status: 'confirmed' },
      { id: 'h-2', category: 'injection', asset: '/search', status: 'not_tested', reason: 'observer_unavailable' },
    ],
    probes: [{ id: 'p-1', hypothesisId: 'h-1', tool: 'http', status: 'completed', evidenceIds: ['e-1'] }],
    findings: [
      { id: 'f-1', hypothesisId: 'h-1', category: 'access_control', asset: '/api/item/1', status: 'confirmed', evidenceIds: ['e-1'], rationale: 'owner check absent' },
      { id: 'f-2', hypothesisId: 'h-2', category: '<img src=x onerror=alert(1)>', asset: '/search', status: 'not_tested', evidenceIds: [], reason: 'observer_unavailable' },
    ],
    coverage: { totalHypotheses: 2, confirmed: 1, notReproduced: 0, inconclusive: 0, notTested: 1 },
    modelCalls: [{ usage: { prompt_tokens: 12, completion_tokens: 8 } }],
  };
}

test('general report normalization keeps variable events and does not change legacy runs', () => {
  const report = result();
  const raw = { id: 'run-general', mode: 'local-lab-general', startedAt: '2026-10-26T00:00:00Z',
    status: 'completed', report, events: Array.from({ length: 150 }, (_, index) => ({ stage: `scan.${index}` })) };
  const normalized = normalizeGeneralRun(raw);
  assert.equal(normalized.events.length, 150);
  assert.equal(normalized.step, 150);
  assert.equal(normalized.events[149].title, 'scan.149');
  assert.equal(normalized.events[149].module, 'agent');
  assert.equal(normalized.snapshots.agent.id, 'run-general:general-event:150');
  assert.equal(normalized.report, report);
  assert.equal(normalized.target, 'http://127.0.0.1:4101');
  assert.equal(normalized.iterations, 3);
  const legacy = { mode: 'local-lab-rule', report: { finding: { status: 'confirmed' } } };
  assert.equal(isGeneralAssessment(legacy), false);
  assert.equal(normalizeGeneralRun(legacy), legacy);
  assert.equal(generalReport(legacy), null);
});

test('queued general run stays a waiting state until a report exists', () => {
  const run = { id: 'run-pending', mode: 'local-lab-general', assessmentMode: 'general',
    startedAt: '2026-10-26T00:00:00Z', status: 'queued', events: [] };
  assert.equal(isGeneralAssessment(run), true);
  assert.equal(generalReport(run), null);
  const normalized = normalizeGeneralRun(run);
  assert.equal(normalized.report, null);
  assert.equal(generalSummary(normalized), null);
  assert.match(renderGeneralOverview(normalized), /점검 결과 대기/);
  assert.equal(renderGeneralReport(normalized), '');
});

test('general report shows evidence, incomplete coverage, model usage and escapes untrusted text', () => {
  const item = { report: result(), events: [{ stage: 'probe.verify' }] };
  const summary = generalSummary(item);
  assert.equal(summary.totalHypotheses, 2);
  assert.equal(summary.notTested, 1);
  assert.equal(summary.modelCalls, 1);
  assert.equal(summary.tokenUsage, 20);
  const html = renderGeneralReport(item);
  assert.match(html, /확정/);
  assert.match(html, /미점검/);
  assert.match(html, /observer_unavailable/);
  assert.match(html, /different role response/);
  assert.match(html, /모델 호출 1건/);
  assert.match(html, /http:\/\/127\.0\.0\.1:4101/);
  assert.match(html, /기록된 토큰 20/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(html, /<img src=x/);
  assert.match(html, /미점검과 판정 불가는 안전하다는 뜻이 아닙니다/);
  const overview = renderGeneralOverview(item);
  assert.match(overview, /probe.verify/);
  assert.match(overview, /전체 취약점에 대한 완료율이 아닙니다/);
});

test('missing evidence and unknown statuses never display as confirmed', () => {
  const report = result();
  report.findings = [{ id: 'f-unknown', category: 'other', asset: '/x', status: 'made_up', evidenceIds: ['absent'] }];
  report.coverage = {};
  report.modelCalls = [{ usage: null }];
  const item = { report };
  const html = renderGeneralReport(item);
  assert.match(html, /판정 불가/);
  assert.match(html, /증거 상세 미제공/);
  assert.match(html, /토큰 사용량 미기록/);
  assert.doesNotMatch(html, /<span class="review-tag">확정<\/span>/);
});

test('partial general results show rejected model proposals without hiding verified findings', () => {
  const report = result();
  report.partial = true;
  report.stopReason = 'invalid_model_proposal';
  report.rejectedProposals = [{ iteration: 3, index: 0,
    reason: '<unknown_hypothesis_id>' }];
  const item = { report, events: [] };
  const summary = generalSummary(item);
  assert.equal(summary.confirmed, 1);
  assert.equal(summary.partial, true);
  assert.equal(summary.rejectedProposals.length, 1);
  const overview = renderGeneralOverview(item);
  const html = renderGeneralReport(item);
  assert.match(overview, /부분 결과/);
  assert.match(overview, /거부 제안 <strong>1<\/strong>/);
  assert.match(html, /실행하지 않은 모델 제안 1건/);
  assert.match(html, /invalid_model_proposal/);
  assert.match(html, /&lt;unknown_hypothesis_id&gt;/);
  assert.doesNotMatch(html, /<unknown_hypothesis_id>/);
  assert.match(html, /<span class="review-tag">확정<\/span>/);
});
