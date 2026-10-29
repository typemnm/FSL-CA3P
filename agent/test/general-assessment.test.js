'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { runGeneralAssessment, SCHEMA_VERSION } = require('../src/general-assessment');
const { createGeneralModelPlanner } = require('../src/general-model-planner');

const target = { fixtureId: 'isolated-lab', origin: 'http://127.0.0.1:3000' };
const observed = { inventory: { assets: ['/search', '/records/1'], roles: ['alice', 'bob'] },
  evidence: [{ id: 'observation-1', source: 'lab-observer', kind: 'http',
    summary: 'Search and record endpoints were observed.', asset: '/search' }] };

function ports(overrides = {}) {
  return {
    target,
    availableTools: ['http-read'],
    limits: { maxIterations: 2, maxProbes: 4, maxEvidenceItems: 16 },
    observer: { async observe({ iteration }) { return iteration === 1 ? observed : { inventory: observed.inventory, evidence: [] }; } },
    planner: { async propose({ iteration }) { return iteration === 1 ? {
      hypotheses: [{ id: 'access-1', category: 'access-control', asset: '/records/1',
        rationale: 'The record route may not check its owner.', evidenceIds: ['observation-1'] }],
      probes: [{ id: 'read-other-record', hypothesisId: 'access-1', tool: 'http-read', input: { path: '/records/1' } }],
    } : { hypotheses: [], probes: [], done: true }; } },
    policy: { async authorize() { return { allowed: true }; } },
    executor: { async execute() { return { evidence: [{ id: 'probe-1', source: 'http-read', kind: 'http',
      summary: 'Cross-user response was returned.', asset: '/records/1' }] }; } },
    verifier: { async verify() { return { status: 'confirmed', completed: true, evidenceIds: ['probe-1'] }; } },
    ...overrides,
  };
}

test('general core rejects an unbounded model attempt list', async () => {
  const { report } = await runGeneralAssessment(ports({
    planner: { async propose() { return { done: true, hypotheses: [], probes: [],
      modelAttempts: Array.from({ length: 3 }, () => ({ provider: 'deepseek' })) }; } },
  }));
  assert.equal(report.status, 'failed');
  assert.equal(report.error.code, 'INVALID_PLAN');
  assert.deepEqual(report.modelCalls, []);
});

test('general core evaluates multiple vulnerability categories and keeps evidence provenance', async () => {
  const events = [];
  const options = ports({
    availableTools: ['http-read', 'header-read'],
    planner: { async propose({ iteration, availableTools, budget, evidence, hypotheses }) {
      assert.deepEqual(availableTools, ['http-read', 'header-read']);
      assert.equal(budget.remainingProbes, iteration === 1 ? 4 : 2);
      assert.equal(evidence.length, iteration === 1 ? 1 : 3);
      if (iteration === 2) assert.deepEqual(hypotheses.map(item => item.status), ['confirmed', 'not_reproduced']);
      return iteration === 1 ? {
        hypotheses: [
          { id: 'access-1', category: 'access-control', asset: '/records/1',
            rationale: 'Cross-user access may be possible.', evidenceIds: ['observation-1'] },
          { id: 'config-1', category: 'security-configuration', asset: '/_diag/config',
            rationale: 'The diagnostics endpoint may be public.', evidenceIds: ['observation-1'] },
        ],
        probes: [
          { id: 'probe-access', hypothesisId: 'access-1', tool: 'http-read', input: { path: '/records/1' } },
          { id: 'probe-config', hypothesisId: 'config-1', tool: 'header-read', input: { path: '/_diag/config' } },
        ],
        modelMetadata: { provider: 'deepseek', reportedModel: 'model-1', usage: { prompt_tokens: 10 },
          rawPrompt: 'PRIVATE MODEL INPUT' },
      } : { hypotheses: [], probes: [], done: true };
    } },
    executor: { async execute({ probe }) { return { evidence: [{ id: `evidence-${probe.id}`,
      source: probe.tool, kind: 'http', summary: `Checked ${probe.id}.`,
      data: { token: 'PRIVATE RESPONSE' } }], rawBody: 'PRIVATE RESPONSE' }; } },
    verifier: { async verify({ probe }) { return { status: probe.id === 'probe-access' ? 'confirmed' : 'not_reproduced',
      completed: true, evidenceIds: [`evidence-${probe.id}`] }; } },
    onEvent: event => events.push(event),
  });
  const { report } = await runGeneralAssessment(options);
  assert.equal(report.schemaVersion, SCHEMA_VERSION);
  assert.equal(report.status, 'completed');
  assert.equal(report.stopReason, 'planner_done');
  assert.equal(report.iterations, 2);
  assert.equal(report.budget.usedProbes, 2);
  assert.deepEqual(report.findings.map(row => row.status), ['confirmed', 'not_reproduced']);
  assert.deepEqual(report.coverage, { totalHypotheses: 2, confirmed: 1, notReproduced: 1,
    inconclusive: 0, notTested: 0 });
  assert.deepEqual(report.evidence.map(item => item.id),
    ['observation-1', 'evidence-probe-access', 'evidence-probe-config']);
  assert.equal(report.modelCalls[0].usage.prompt_tokens, 10);
  assert.doesNotMatch(JSON.stringify({ report, events }), /PRIVATE/);
  assert.deepEqual(events.filter(item => item.stage === 'verify').map(item => item.status),
    ['confirmed', 'not_reproduced']);
  assert.deepEqual(events.find(item => item.stage === 'plan').probeLinks, [
    { probeId: 'probe-access', hypothesisId: 'access-1', tool: 'http-read' },
    { probeId: 'probe-config', hypothesisId: 'config-1', tool: 'header-read' },
  ]);
  assert.deepEqual(events.find(item => item.stage === 'observe' && item.iteration === 1).evidenceSummaries,
    [{ id: 'observation-1', kind: 'http', asset: '/search' }]);
  assert.deepEqual(events.find(item => item.stage === 'plan' && item.iteration === 1).hypothesisSummaries, [
    { id: 'access-1', category: 'access-control', asset: '/records/1' },
    { id: 'config-1', category: 'security-configuration', asset: '/_diag/config' },
  ]);
  assert.deepEqual(events.filter(item => item.stage === 'execute').map(item => item.evidenceSummaries), [
    [{ id: 'evidence-probe-access', kind: 'http' }],
    [{ id: 'evidence-probe-config', kind: 'http' }],
  ]);
  assert.doesNotMatch(JSON.stringify(events), /Cross-user access may be possible|Checked probe-access/u);
  assert.deepEqual(events.filter(item => item.stage === 'verify').map(item =>
    ({ hypothesisId: item.hypothesisId, probeId: item.probeId, tool: item.tool,
      evidenceIds: item.evidenceIds })), [
    { hypothesisId: 'access-1', probeId: 'probe-access', tool: 'http-read',
      evidenceIds: ['evidence-probe-access'] },
    { hypothesisId: 'config-1', probeId: 'probe-config', tool: 'header-read',
      evidenceIds: ['evidence-probe-config'] },
  ]);
  assert.deepEqual(events.at(-1).progress, {
    hypothesisCount: 2, probeCount: 2, evidenceCount: 3,
    confirmedProbeCount: 1, notReproducedProbeCount: 1, inconclusiveProbeCount: 0,
    blockedProbeCount: 0, remainingProbeBudget: 2,
  });
});

test('live metadata is bounded and omits observation summaries and secret query values', async () => {
  const events = [];
  const evidence = Array.from({ length: 16 }, (_, index) => ({
    id: `observation-${index}`, source: 'lab-observer', kind: 'http',
    asset: index === 0
      ? `https://observer.example/records/${index}?opaque=PRIVATE_QUERY_${index}#PRIVATE_FRAGMENT`
      : `/records/${index}?opaque=PRIVATE_QUERY_${index}#PRIVATE_FRAGMENT`,
    summary: `PRIVATE_BODY_${index}`,
  }));
  const { report } = await runGeneralAssessment(ports({
    observer: { async observe({ iteration }) { return { inventory: {}, evidence: iteration === 1 ? evidence : [] }; } },
    planner: { async propose({ iteration }) { return iteration === 1 ? {
      hypotheses: [{ id: 'query-asset', category: 'access-control',
        asset: 'https://target.example/records?opaque=PRIVATE_ASSET#PRIVATE_FRAGMENT',
        rationale: 'PRIVATE_RATIONALE', evidenceIds: ['observation-0'] }], probes: [],
    } : { done: true, hypotheses: [], probes: [] }; } },
    onEvent: event => events.push(event),
  }));
  assert.equal(report.status, 'completed');
  const summaries = events.find(event => event.stage === 'observe').evidenceSummaries;
  assert.equal(summaries.length, 16);
  assert.ok(summaries.every(item => Object.keys(item).sort().join(',') === 'asset,id,kind'));
  assert.deepEqual(summaries.map(item => item.asset),
    Array.from({ length: 16 }, (_, index) => `/records/${index}`));
  assert.deepEqual(events.find(event => event.stage === 'plan' && event.iteration === 1).hypothesisSummaries,
    [{ id: 'query-asset', category: 'access-control', asset: '/records' }]);
  assert.doesNotMatch(JSON.stringify(events), /PRIVATE_BODY|PRIVATE_QUERY|PRIVATE_ASSET|PRIVATE_FRAGMENT|PRIVATE_RATIONALE|observer\.example|target\.example/u);
  assert.equal(report.evidence.length, 16);
});

test('same category and asset keep distinct hypothesis findings and evidence', async () => {
  const { report } = await runGeneralAssessment(ports({
    observer: { async observe({ iteration }) { return { inventory: {}, evidence: iteration === 1 ? [
      { id: 'source-a', source: 'observer', kind: 'http', summary: 'First input was observed.' },
      { id: 'source-b', source: 'observer', kind: 'http', summary: 'Second input was observed.' },
    ] : [] }; } },
    planner: { async propose({ iteration }) { return iteration === 1 ? {
      hypotheses: [
        { id: 'issue-a', category: 'access-control', asset: '/records/:id',
          rationale: 'Owner check on the read path.', evidenceIds: ['source-a'] },
        { id: 'issue-b', category: 'access-control', asset: '/records/:id',
          rationale: 'Owner check on the write path.', evidenceIds: ['source-b'] },
      ], probes: [
        { id: 'probe-a', hypothesisId: 'issue-a', tool: 'http-read', input: {} },
        { id: 'probe-b', hypothesisId: 'issue-b', tool: 'http-read', input: {} },
      ],
    } : { done: true, hypotheses: [], probes: [] }; } },
    executor: { async execute({ probe }) { return { evidence: [{ id: `result-${probe.id}`,
      source: 'http-read', kind: 'http', summary: `Checked ${probe.id}.` }] }; } },
    verifier: { async verify({ probe }) { return { status: probe.id === 'probe-a' ? 'confirmed' : 'not_reproduced',
      completed: true, evidenceIds: [`result-${probe.id}`] }; } },
  }));
  assert.equal(report.status, 'completed');
  assert.deepEqual(report.findings.map(item => item.id), ['finding:issue-a', 'finding:issue-b']);
  assert.deepEqual(report.findings.map(item => item.status), ['confirmed', 'not_reproduced']);
  assert.deepEqual(report.findings.map(item => item.evidenceIds), [
    ['source-a', 'result-probe-a'], ['source-b', 'result-probe-b'],
  ]);
});

test('mandatory policy blocks execution and leaves the hypothesis not tested', async () => {
  let calls = 0;
  let policyHypothesis;
  const events = [];
  const { report } = await runGeneralAssessment(ports({
    policy: { async authorize({ hypothesis }) { policyHypothesis = hypothesis;
      hypothesis.asset = '/tampered'; return { allowed: false, reason: 'unsafe' }; } },
    executor: { async execute() { calls += 1; return { evidence: [] }; } },
    onEvent: event => events.push(event),
  }));
  assert.equal(calls, 0);
  assert.equal(policyHypothesis.category, 'access-control');
  assert.equal(policyHypothesis.id, 'access-1');
  assert.equal(report.status, 'completed');
  assert.equal(report.probes[0].status, 'blocked');
  assert.equal(report.findings[0].status, 'not_tested');
  assert.equal(report.findings[0].reason, 'unsafe');
  assert.equal(report.findings[0].asset, '/records/1');
  assert.deepEqual(events.find(item => item.stage === 'policy').progress,
    { hypothesisCount: 1, probeCount: 1, evidenceCount: 1, confirmedProbeCount: 0,
      notReproducedProbeCount: 0, inconclusiveProbeCount: 0,
      blockedProbeCount: 1, remainingProbeBudget: 3 });
});

test('a probe without evidence emits an inconclusive verification event', async () => {
  const events = [];
  const { report } = await runGeneralAssessment(ports({
    executor: { async execute() { return { evidence: [] }; } },
    onEvent: event => events.push(event),
  }));
  assert.equal(report.status, 'completed');
  assert.equal(report.findings[0].status, 'inconclusive');
  assert.deepEqual(events.find(item => item.stage === 'verify'), {
    runId: report.runId, iteration: 1, stage: 'verify', hypothesisId: 'access-1',
    probeId: 'read-other-record', tool: 'http-read', status: 'inconclusive',
    reason: 'no_evidence', evidenceIds: [], progress: {
      hypothesisCount: 1, probeCount: 1, evidenceCount: 1,
      confirmedProbeCount: 0, notReproducedProbeCount: 0,
      inconclusiveProbeCount: 1, blockedProbeCount: 0, remainingProbeBudget: 3,
    },
  });
});

test('unavailable tools, stale references and duplicate IDs fail before the executor', async () => {
  for (const [plan, code] of [
    [{ hypotheses: [{ id: 'h1', category: 'config', asset: '/', rationale: 'Check it.', evidenceIds: ['missing'] }], probes: [] }, 'UNKNOWN_HYPOTHESIS_EVIDENCE'],
    [{ hypotheses: [{ id: 'h1', category: 'config', asset: '/', rationale: 'Check it.', evidenceIds: ['observation-1'] }],
      probes: [{ id: 'p1', hypothesisId: 'h1', tool: 'delete-record', input: {} }] }, 'UNAVAILABLE_TOOL'],
    [{ hypotheses: [{ id: 'h1', category: 'config', asset: '/', rationale: 'Check it.', evidenceIds: ['observation-1'] },
      { id: 'h1', category: 'config', asset: '/', rationale: 'Duplicate.', evidenceIds: ['observation-1'] }], probes: [] }, 'DUPLICATE_HYPOTHESIS_ID'],
  ]) {
    let calls = 0;
    const { report } = await runGeneralAssessment(ports({
      planner: { async propose() { return plan; } },
      executor: { async execute() { calls += 1; return { evidence: [] }; } },
    }));
    assert.equal(report.status, 'failed');
    assert.equal(report.error.code, code);
    assert.equal(calls, 0);
  }
});

test('verifier cannot confirm or negate a finding without completed current-probe evidence', async () => {
  for (const status of ['confirmed', 'not_reproduced']) {
    const { report } = await runGeneralAssessment(ports({
      verifier: { async verify() { return { status, completed: true, evidenceIds: ['observation-1'] }; } },
    }));
    assert.equal(report.status, 'failed');
    assert.equal(report.error.code, 'UNSUPPORTED_VERDICT');
    assert.equal(report.findings[0].status, 'not_tested');
  }
});

test('abort returns a partial, non-confirmed report and never calls a later port', async () => {
  const controller = new AbortController();
  let planned = false;
  const { report } = await runGeneralAssessment(ports({
    signal: controller.signal,
    observer: { async observe() { controller.abort(); return observed; } },
    planner: { async propose() { planned = true; return { hypotheses: [], probes: [] }; } },
  }));
  assert.equal(report.status, 'cancelled');
  assert.equal(report.stopReason, 'cancelled');
  assert.equal(planned, false);
  assert.equal(report.coverage.confirmed, 0);
});

test('probe budget is enforced before excess model actions are sent to policy', async () => {
  let policies = 0;
  const { report } = await runGeneralAssessment(ports({
    limits: { maxIterations: 2, maxProbes: 1, maxEvidenceItems: 16 },
    planner: { async propose() { return {
      hypotheses: [{ id: 'h1', category: 'config', asset: '/', rationale: 'Check it.', evidenceIds: ['observation-1'] }],
      probes: [
        { id: 'p1', hypothesisId: 'h1', tool: 'http-read', input: {} },
        { id: 'p2', hypothesisId: 'h1', tool: 'http-read', input: {} },
      ],
    }; } },
    policy: { async authorize() { policies += 1; return { allowed: true }; } },
  }));
  assert.equal(report.status, 'failed');
  assert.equal(report.error.code, 'PROBE_BUDGET_EXCEEDED');
  assert.equal(policies, 0);
});

test('inventory credentials are redacted and forbidden tool fields never reach policy', async () => {
  let policies = 0;
  const { report } = await runGeneralAssessment(ports({
    target: { fixtureId: 'synthetic', origin: 'http://127.0.0.1:4101', headers: { 'X-API-Key': 'PRIVATE_TARGET' } },
    observer: { async observe() { return { inventory: { headers: { Authorization: 'Bearer PRIVATE_TOKEN',
      'X-API-Key': 'PRIVATE_API_KEY', 'X-Auth-Token': 'PRIVATE_AUTH_TOKEN' },
      password: 'PRIVATE_PASSWORD', note: 'token=PRIVATE_VALUE' }, evidence: observed.evidence }; } },
    planner: { async propose() { return {
      hypotheses: [{ id: 'h1', category: 'config', asset: '/', rationale: 'Check it.', evidenceIds: ['observation-1'] }],
      probes: [{ id: 'p1', hypothesisId: 'h1', tool: 'http-read', input: { headers: { 'X-API-Key': 'PRIVATE_HEADER' } } }],
    }; } },
    policy: { async authorize() { policies += 1; return { allowed: true }; } },
  }));
  assert.equal(report.status, 'failed');
  assert.equal(report.error.code, 'FORBIDDEN_PROBE_INPUT');
  assert.equal(policies, 0);
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE/);
  assert.equal(report.inventory.headers.Authorization, '[redacted]');
  assert.equal(report.inventory.headers['X-API-Key'], '[redacted]');
  assert.equal(report.inventory.headers['X-Auth-Token'], '[redacted]');
  assert.equal(report.target.headers['X-API-Key'], '[redacted]');
});

test('the model planner port drives the general core and receives verified prior status', async () => {
  const planner = createGeneralModelPlanner({ client: { async completeJson({ userPayload }) {
    if (userPayload.iteration === 2) {
      assert.equal(userPayload.hypotheses[0].status, 'confirmed');
      return { value: { done: true, hypotheses: [], probes: [] },
        metadata: { model: 'deepseek-flash', usage: { prompt_tokens: 15 } } };
    }
    assert.deepEqual(userPayload.availableTools, ['http-read']);
    return { value: { done: false, hypotheses: [{ id: 'access-1', category: 'access-control',
      asset: '/records/1', rationale: 'The record may be exposed.', evidenceIds: ['observation-1'] }],
    probes: [{ id: 'read-other-record', hypothesisId: 'access-1', tool: 'http-read',
      input: { path: '/records/1' } }] },
    metadata: { model: 'deepseek-flash', usage: { prompt_tokens: 10 } } };
  } } });
  const { report } = await runGeneralAssessment(ports({ planner }));
  assert.equal(report.status, 'completed');
  assert.equal(report.findings[0].status, 'confirmed');
  assert.equal(report.modelCalls.length, 2);
  assert.equal(report.modelCalls[0].model, 'deepseek-flash');
  assert.equal(report.modelCalls[1].usage.prompt_tokens, 15);
});

test('an invalid model probe is recorded but valid probes still run and retain confirmed evidence', async () => {
  let plannerCalls = 0;
  let executions = 0;
  const base = ports();
  const { report } = await runGeneralAssessment(ports({
    planner: { async propose(context) {
      plannerCalls += 1;
      if (context.iteration === 2) return { done: true, hypotheses: [], probes: [] };
      return { ...(await base.planner.propose(context)),
        rejectedProbes: [{ index: 1, reason: 'unknown_hypothesis_id' }] };
    } },
    executor: { async execute(context) { executions += 1; return base.executor.execute(context); } },
  }));
  assert.equal(report.status, 'completed');
  assert.equal(report.stopReason, 'planner_done');
  assert.equal(report.partial, true);
  assert.equal(plannerCalls, 2);
  assert.equal(executions, 1);
  assert.equal(report.findings[0].status, 'confirmed');
  assert.deepEqual(report.rejectedProposals,
    [{ iteration: 1, index: 1, reason: 'unknown_hypothesis_id' }]);
});

test('new hypotheses receive one bounded follow-up when all initial probes are rejected', async () => {
  const events = [];
  let plannerCalls = 0;
  let executions = 0;
  const { report } = await runGeneralAssessment(ports({
    planner: { async propose(context) {
      plannerCalls += 1;
      if (context.iteration === 1) return {
        hypotheses: [{ id: 'wonchang-record', category: 'access-control', asset: '/records/1',
          rationale: 'A role comparison may reveal missing ownership checks.', evidenceIds: ['observation-1'] }],
        probes: [], rejectedProbes: [{ index: 0, reason: 'unknown_hypothesis_id' }],
      };
      assert.equal(context.iteration, 2);
      assert.deepEqual(context.hypotheses.map(item => item.id), ['wonchang-record']);
      assert.deepEqual(context.usedProbeIds, []);
      assert.equal(context.budget.usedProbes, 0);
      return { hypotheses: [], probes: [{ id: 'read-owner-record', hypothesisId: 'wonchang-record',
        tool: 'http-read', input: { path: '/records/1' } }] };
    } },
    executor: { async execute() { executions += 1; return { evidence: [{ id: 'probe-1',
      source: 'http-read', kind: 'http', summary: 'The second role returned a record.', asset: '/records/1' }] }; } },
    onEvent: event => events.push(event),
  }));
  assert.equal(report.status, 'completed');
  assert.equal(report.stopReason, 'iteration_budget');
  assert.equal(report.partial, true);
  assert.equal(report.iterations, 2);
  assert.equal(plannerCalls, 2);
  assert.equal(executions, 1);
  assert.equal(report.budget.usedProbes, 1);
  assert.equal(report.findings[0].status, 'confirmed');
  assert.deepEqual(report.rejectedProposals,
    [{ iteration: 1, index: 0, reason: 'unknown_hypothesis_id' }]);
  assert.deepEqual(events.filter(item => item.stage === 'verify').map(item => item.iteration), [2]);
});

test('a second all-invalid plan stops before another model call or target action', async () => {
  let plannerCalls = 0;
  let executions = 0;
  const { report } = await runGeneralAssessment(ports({
    limits: { maxIterations: 3, maxProbes: 4, maxEvidenceItems: 16 },
    planner: { async propose({ iteration }) {
      plannerCalls += 1;
      return iteration === 1 ? {
        hypotheses: [{ id: 'h-new', category: 'access-control', asset: '/records/1',
          rationale: 'The route may expose a record.', evidenceIds: ['observation-1'] }],
        probes: [], rejectedProbes: [{ index: 0, reason: 'unknown_hypothesis_id' }],
      } : { hypotheses: [], probes: [],
        rejectedProbes: [{ index: 0, reason: 'unknown_hypothesis_id' }] };
    } },
    executor: { async execute() { executions += 1; return { evidence: [] }; } },
  }));
  assert.equal(report.status, 'completed');
  assert.equal(report.stopReason, 'invalid_model_proposal');
  assert.equal(report.partial, true);
  assert.equal(report.iterations, 2);
  assert.equal(plannerCalls, 2);
  assert.equal(executions, 0);
  assert.equal(report.budget.usedProbes, 0);
  assert.equal(report.findings[0].status, 'not_tested');
  assert.deepEqual(report.rejectedProposals.map(item => item.iteration), [1, 2]);
});

test('only invalid follow-up probes stop as an explicit partial result', async () => {
  const base = ports();
  const { report } = await runGeneralAssessment(ports({
    planner: { async propose(context) { return context.iteration === 1
      ? base.planner.propose(context)
      : { hypotheses: [], probes: [], rejectedProbes: [{ index: 0, reason: 'unknown_hypothesis_id' }] }; } },
  }));
  assert.equal(report.status, 'completed');
  assert.equal(report.stopReason, 'invalid_model_proposal');
  assert.equal(report.partial, true);
  assert.equal(report.findings[0].status, 'confirmed');
  assert.equal(report.rejectedProposals.length, 1);
});

test('a late model schema error preserves verified findings as an explicit partial result', async () => {
  const base = ports();
  const { report } = await runGeneralAssessment(ports({
    planner: { async propose(context) {
      if (context.iteration === 1) return base.planner.propose(context);
      throw Object.assign(new Error('Probe references unknown hypothesis'),
        { code: 'GENERAL_PLANNER_SCHEMA_ERROR' });
    } },
  }));
  assert.equal(report.status, 'completed');
  assert.equal(report.stopReason, 'invalid_model_plan');
  assert.equal(report.partial, true);
  assert.equal(report.findings[0].status, 'confirmed');
  assert.deepEqual(report.rejectedProposals, [{ iteration: 2, reason: 'invalid_model_plan' }]);
});
