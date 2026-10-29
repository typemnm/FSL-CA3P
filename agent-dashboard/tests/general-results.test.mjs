import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generalObservedProbeCount, generalReport, generalSummary, isGeneralAssessment, normalizeGeneralRun,
  renderGeneralLiveResults, renderGeneralOverview, renderGeneralReport,
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

test('external report displays observed scope, rejections and response receipt separately', () => {
  const run = normalizeGeneralRun({ id: 'external-view', mode: 'external-general', status: 'completed',
    target: 'https://example.org/start', requestAttempted: true, targetContacted: false,
    startedAt: '2026-10-28T00:00:00Z', events: [{ id: 'event-1', stage: 'scope.rejected',
      title: '외부 요청 후보 거부', module: 'external-observer', time: '2026-10-28T00:00:01Z' }],
    report: { schemaVersion: 'general-assessment/1', assessmentMode: 'general',
      inspectionMode: 'external-read-only', partial: true, stopReason: 'partial_observation',
      requestAttempted: true, targetContacted: false,
      scope: { origin: 'https://example.org', pathPrefix: '/start', methods: ['GET'], maxRequests: 8 },
      inventory: { pages: [{ url: 'https://example.org/start', status: 200, contentType: 'text/html', truncated: true }] },
      coverage: { requestsUsed: 1, observedPages: 1, rejectedCandidates: 2 },
      policyRejections: { total: 2, byReason: { query_link: 2 } },
      observationErrors: [{ code: 'EXTERNAL_TIMEOUT', url: 'https://example.org/start/next' }],
      findings: [], hypotheses: [], evidence: [], probes: [] },
  });
  assert.match(renderGeneralOverview(run), /공개 페이지 관찰/);
  assert.equal(run.events[0].stage, 'scope.rejected');
  const html = renderGeneralReport(run);
  assert.match(html, /요청 시도/);
  assert.match(html, /HTTP 응답 수신/);
  assert.match(html, /query_link 2건/);
  assert.match(html, /본문 제한으로 일부만 수신/);
  assert.doesNotMatch(html, /모델 제안|가설 기준/);
});

test('external report shows observed technologies and libraries without rendering page text as HTML', () => {
  const report = { ...result(), inspectionMode: 'external-read-only',
    scope: { origin: 'https://example.org', pathPrefix: '/', methods: ['GET'], maxRequests: 8 },
    inventory: { pages: [{ url: 'https://example.org/', status: 200, contentType: 'text/html',
      parser: { status: 'observed', mode: 'http-response',
        technologies: [{ name: 'React <script>', version: '18.2.0', evidenceFields: ['html'] }],
        libraries: [{ name: 'jQuery', version: '3.6.0', evidenceFields: ['scriptSrc'] }] } },
    { url: 'https://example.org/other', status: 200, contentType: 'text/html',
      parser: { status: 'unavailable' } }] },
    findings: [], hypotheses: [], probes: [], evidence: [], modelCalls: [] };
  const html = renderGeneralReport({ mode: 'external-general', target: 'https://example.org/', report });
  assert.match(html, /Web Parser · HTTP 응답 지문/);
  assert.match(html, /외부 라이브러리 단서 1건/);
  assert.match(html, /jQuery 3\.6\.0/);
  assert.match(html, /근거 유형: scriptSrc/);
  assert.match(html, /React &lt;script&gt; 18\.2\.0/);
  assert.doesNotMatch(html, /React <script>/);
  assert.match(html, /지문 분석을 완료하지 못했습니다/);
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

test('general normalization preserves repeated stages and identifiers across iterations', () => {
  const item = normalizeGeneralRun({ id: 'run-loop', mode: 'local-lab-general',
    status: 'running', startedAt: '2026-10-26T00:00:00Z', iterations: 2,
    events: [
      { id: 'observe-1', stage: 'observe', iteration: 1 },
      { id: 'policy-1', stage: 'policy', iteration: 1, detail: 'allowed',
        request: { probeId: 'p1' } },
      { id: 'verify-1', stage: 'verify', iteration: 1, detail: 'confirmed',
        request: { probeId: 'p1' } },
      { id: 'observe-2\"><script>alert(1)</script>', stage: 'observe', iteration: 2 },
    ] });
  assert.equal(generalObservedProbeCount(item), 1);
  assert.deepEqual(item.events.map(event => event.iteration), [1, 1, 1, 2]);
  assert.deepEqual(item.events.map(event => event.stage), ['observe', 'policy', 'verify', 'observe']);
  assert.equal(item.events.at(-1).id, 'observe-2\"><script>alert(1)</script>');
  assert.equal(item.events.length, 4);
  assert.equal(item.iterations, 2);
});

test('policy events are not shown as verified findings before a report exists', () => {
  const item = { mode: 'local-lab-general', status: 'running',
    events: [{ stage: 'policy', iteration: 1, detail: 'allowed', request: { probeId: 'p1' } }] };
  const pending = renderGeneralLiveResults(item);
  assert.match(pending, /독립 검증 이벤트를 기다리는 중/);
  assert.doesNotMatch(pending, /검사 p1/);
  item.events.push({ stage: 'verify', iteration: 1, detail: 'confirmed',
    request: { probeId: '<img src=x onerror=alert(1)>' } });
  const observed = renderGeneralLiveResults(item);
  assert.match(observed, /최종 보고서 전의 검사 이벤트/);
  assert.match(observed, /확정/);
  assert.match(observed, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(observed, /<img src/);
  assert.doesNotMatch(observed, /확정 <strong>1/);
});

test('live general events show projected progress and linked probe outcomes before the final report', () => {
  const item = normalizeGeneralRun({ id: 'run-projected', mode: 'local-lab-general', status: 'running',
    startedAt: '2026-10-26T00:00:00Z', events: [
      { id: 'observed', stage: 'observe', iteration: 1, response: { evidenceSummaries: [
        { id: 'e-observed', kind: '<script>alert(1)</script>', asset: '/search' },
      ] } },
      { id: 'planned', stage: 'plan', iteration: 1, request: { hypothesisSummaries: [
        { id: 'h-wrong', category: 'xss', asset: '/search' },
        { id: 'h-valid', category: 'access_control', asset: '/api/item/:id' },
      ], probeLinks: [
        { probeId: 'p-blocked', hypothesisId: 'h-wrong', tool: 'known_record_idor_read' },
        { probeId: 'p-valid', hypothesisId: 'h-valid', tool: 'known_record_idor_read' },
      ] }, response: { progress: { hypothesisCount: 2, probeCount: 0, evidenceCount: 1,
        confirmedProbeCount: 0, blockedProbeCount: 0, remainingProbeBudget: 4 } } },
      { id: 'blocked', stage: 'policy', iteration: 1, detail: 'blocked',
        request: { probeId: 'p-blocked' }, response: { status: 'blocked',
          reason: '<hypothesis_tool_mismatch>', progress: { hypothesisCount: 2, probeCount: 1,
            evidenceCount: 1, confirmedProbeCount: 0, blockedProbeCount: 1, remainingProbeBudget: 3 } } },
      { id: 'executed', stage: 'execute', iteration: 1, response: { evidenceSummaries: [
        { id: 'e-1', kind: 'role-comparison', asset: '/api/item/:id' },
      ] } },
      { id: 'verified', stage: 'verify', iteration: 1, detail: 'confirmed',
        request: { probeId: 'p-valid', hypothesisId: 'h-valid', tool: 'known_record_idor_read' },
        response: { status: 'confirmed', evidenceIds: ['e-1', '<img src=x onerror=alert(1)>'],
          progress: { hypothesisCount: 2, probeCount: 2, evidenceCount: 3,
            confirmedProbeCount: 1, blockedProbeCount: 1, remainingProbeBudget: 2 } } },
      { id: 'completed', stage: 'complete', iteration: 1,
        response: { progress: { hypothesisCount: 2, probeCount: 2, evidenceCount: 3,
          confirmedProbeCount: 1, blockedProbeCount: 1, remainingProbeBudget: 2 } } },
    ] });
  const live = renderGeneralLiveResults(item);
  assert.match(live, /가설 <strong>2<\/strong>/);
  assert.match(live, /실행 검사 <strong>2<\/strong>/);
  assert.match(live, /수집 증거 <strong>3<\/strong>/);
  assert.match(live, /정책 차단 검사 <strong>1<\/strong>/);
  assert.match(live, /검사 p-blocked/);
  assert.match(live, /정책 차단 · 가설 h-wrong · 도구 known_record_idor_read/);
  assert.match(live, /&lt;hypothesis_tool_mismatch&gt;/);
  assert.match(live, /검사 p-valid/);
  assert.match(live, /확정 · 가설 h-valid · 도구 known_record_idor_read/);
  assert.match(live, /가설 내용: access_control · \/api\/item\/:id/);
  assert.match(live, /증거 e-1: role-comparison · \/api\/item\/:id/);
  assert.match(live, /계획한 가설 2건 · 잠정 정보/);
  assert.match(live, /수집된 증거 메타데이터 2건/);
  assert.match(live, /증거 ID: e-1, &lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(live, /확정 판정 검사 <strong>1<\/strong>/);
  assert.match(live, /취약점 확정 건수로 집계하지 않습니다/);
  assert.doesNotMatch(live, /<img src/);
  assert.doesNotMatch(live, /<script>/);
  assert.match(live, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(live, /<hypothesis_tool_mismatch>/);
});

test('planned hypotheses and observed evidence remain provisional before any probe verdict', () => {
  const item = { mode: 'local-lab-general', status: 'running', events: [
    { stage: 'observe', iteration: 1, response: { evidenceSummaries: [
      { id: 'e-1', kind: 'status-metadata', asset: '/search' },
    ] } },
    { stage: 'plan', iteration: 1, request: { hypothesisSummaries: [
      { id: 'h-1', category: 'xss', asset: '/search' },
    ] } },
  ] };
  const live = renderGeneralLiveResults(item);
  assert.match(live, /계획한 가설 1건 · 잠정 정보/);
  assert.match(live, /h-1<\/span> · xss · \/search/);
  assert.match(live, /수집된 증거 메타데이터 1건/);
  assert.match(live, /e-1<\/span> · status-metadata · \/search/);
  assert.match(live, /독립 검증 이벤트를 기다리는 중/);
  assert.doesNotMatch(live, /확정 판정 검사/);
});

test('live result panel uses final findings and linked evidence only after report arrives', () => {
  const item = { mode: 'local-lab-general', report: result(), events: [] };
  const html = renderGeneralLiveResults(item);
  assert.match(html, /access_control/);
  assert.match(html, /different role response/);
  assert.match(html, /observer_unavailable/);
  assert.match(html, /미점검과 판정 불가는 안전 판정이 아닙니다/);
  assert.doesNotMatch(html, /<img src=x/);
});
