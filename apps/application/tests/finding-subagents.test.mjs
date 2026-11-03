import test from 'node:test';
import assert from 'node:assert/strict';
import { selectFindingSubtasks, runFindingSubtasks, createSharedExecutionBudget,
  createTargetRequestGate } from '../finding-subagents.mjs';

test('shared execution budget reserves concurrent transport attempts and settles known model usage', () => {
  const budget = createSharedExecutionBudget({ maxTargetRequests: 2,
    maxModelRequests: 2, maxModelTokens: 20, deadlineMs: 1000 });
  budget.reserveTargetRequest();
  budget.reserveTargetRequest();
  assert.throws(() => budget.reserveTargetRequest(), { code: 'PARENT_TARGET_REQUEST_BUDGET_EXCEEDED' });
  const first = budget.reserveModelRequest(12);
  assert.throws(() => budget.reserveModelRequest(9), { code: 'PARENT_MODEL_TOKEN_BUDGET_EXCEEDED' });
  first(4);
  const second = budget.reserveModelRequest(9);
  second();
  assert.throws(() => budget.reserveModelRequest(1), { code: 'PARENT_MODEL_REQUEST_BUDGET_EXCEEDED' });
  assert.deepEqual(budget.snapshot(), { targetRequests: 2, pendingTargetRequests: 0,
    modelRequests: 2, modelTokens: 13,
    maxTargetRequests: 2, maxModelRequests: 2, maxModelTokens: 20, deadlineMs: 1000 });
});

test('browser redirect reservations are conservative until settled to actual hops', () => {
  const budget = createSharedExecutionBudget({ maxTargetRequests: 26,
    maxModelRequests: 1, maxModelTokens: 100, deadlineMs: 1000 });
  budget.reserveTargetRequest(2);
  const settle = budget.reserveBrowserRequest();
  assert.equal(budget.snapshot().targetRequests, 2);
  assert.equal(budget.snapshot().pendingTargetRequests, 21);
  assert.throws(() => budget.reserveBrowserRequest(), { code: 'PARENT_TARGET_REQUEST_BUDGET_EXCEEDED' });
  settle(3);
  settle(21);
  assert.equal(budget.snapshot().targetRequests, 5);
  assert.equal(budget.snapshot().pendingTargetRequests, 0);
  const interrupted = budget.reserveBrowserRequest();
  interrupted(2, false);
  assert.equal(budget.snapshot().targetRequests, 7);
  assert.equal(budget.snapshot().pendingTargetRequests, 19,
    'unfinished redirect capacity remains explicitly reserved');
});

test('target gate lets reads overlap but excludes writes and drops aborted waiters', async () => {
  const gate = createTargetRequestGate();
  const first = await gate.acquire('GET');
  const second = await gate.acquire('HEAD');
  let writerEntered = false;
  const waitingWriter = gate.acquire('POST').then(release => { writerEntered = true; return release; });
  const abort = new AbortController();
  const waitingRead = gate.acquire('GET', abort.signal);
  abort.abort();
  await assert.rejects(waitingRead);
  first(); second(); second();
  const releaseWriter = await waitingWriter;
  assert.equal(writerEntered, true);
  let nextRead = false;
  const pending = gate.acquire('GET').then(release => { nextRead = true; release(); });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(nextRead, false);
  releaseWriter();
  await pending;
  assert.equal(nextRead, true);
});

test('finding selection prioritizes unresolved work and bounds assigned probe budgets', () => {
  const statuses = ['confirmed', 'not_reproduced', 'not_tested', 'inconclusive'];
  const report = { hypotheses: statuses.map((status, index) => ({ id: `h${index}`,
    category: 'access_control', asset: `/p${index}`, rationale: 'Observed path', evidenceIds: ['e1'] })),
  evidence: [{ id: 'e1', source: 'observer', kind: 'http-response', summary: 'Observed' }],
  findings: statuses.map((status, index) => ({ id: `finding:h${index}`, hypothesisId: `h${index}`,
    category: 'access_control', asset: `/p${index}`, status, evidenceIds: ['e1'] })) };
  const selected = selectFindingSubtasks(report, { runId: 'run-one', maxTasks: 4, probeBudget: 3 });
  assert.deepEqual(selected.map(item => item.finding.status), ['inconclusive', 'not_tested']);
  assert.deepEqual(selected.map(item => item.maxProbes), [2, 1]);
  assert.equal(selectFindingSubtasks(report, { runId: 'run-one', maxTasks: 4, probeBudget: 0 }).length, 0);
  assert.equal(selectFindingSubtasks(report, { runId: 'run-one', maxTasks: 4, probeBudget: 3 })[0].id,
    selected[0].id, 'same finding snapshot has a stable task ID');
});

test('finding selection never reassigns refused probes or unsupported templates', () => {
  const reasons = ['human_rejected', 'approval_timeout', 'policy_denied',
    'path_out_of_scope', 'session_unavailable', 'no_probe'];
  const report = { hypotheses: reasons.map((reason, index) => ({ id: `h${index}`,
    category: 'access_control', asset: `/p${index}`, rationale: 'Observed', evidenceIds: ['e1'] })),
  evidence: [{ id: 'e1', source: 'observer', kind: 'http-response', summary: 'Observed' }],
  findings: reasons.map((reason, index) => ({ id: `finding:h${index}`, hypothesisId: `h${index}`,
    status: 'not_tested', reason, category: 'access_control', asset: `/p${index}` })) };
  assert.deepEqual(selectFindingSubtasks(report, { runId: 'run-refused', maxTasks: 4, probeBudget: 8 })
    .map(task => task.sourceFindingId), ['finding:h5']);
  report.findings[5].templateId = 'registered-template';
  assert.deepEqual(selectFindingSubtasks(report, { runId: 'run-refused', maxTasks: 4, probeBudget: 8 }), []);
});

test('finding selection applies the caller supplied eligibility boundary', () => {
  const report = { hypotheses: ['h-a', 'h-b'].map(id => ({ id,
    category: 'access_control', asset: `/${id}`, rationale: 'Observed', evidenceIds: ['e1'] })),
  evidence: [{ id: 'e1', source: 'observer', kind: 'http-response', summary: 'Observed' }],
  findings: ['h-a', 'h-b'].map(id => ({ id: `finding:${id}`, hypothesisId: id,
    status: 'inconclusive', category: 'access_control', asset: `/${id}` })) };
  const options = { runId: 'run-eligible', maxTasks: 2, probeBudget: 4 };
  assert.equal(selectFindingSubtasks(report, options).length, 2);
  assert.deepEqual(selectFindingSubtasks(report, { ...options,
    eligible: finding => finding.asset === '/h-b' }).map(task => task.sourceFindingId), ['finding:h-b']);
  assert.throws(() => selectFindingSubtasks(report, { ...options, eligible: true }), TypeError);
});

test('a child receives the finding evidence snapshot as well as the hypothesis seed', () => {
  const report = { hypotheses: [{ id: 'h1', category: 'access_control', asset: '/about',
    rationale: 'Observed', evidenceIds: ['initial'] }],
  evidence: [{ id: 'initial', source: 'observer', kind: 'http-response', summary: 'Initial' },
    { id: 'verified', source: 'http', kind: 'http-response', summary: 'Follow-up result' }],
  findings: [{ id: 'finding:h1', hypothesisId: 'h1', status: 'inconclusive',
    category: 'access_control', asset: '/about', evidenceIds: ['initial', 'verified'] }] };
  const options = { runId: 'run-evidence', maxTasks: 1, probeBudget: 2 };
  const [task] = selectFindingSubtasks(report, options);
  assert.deepEqual(task.evidence.map(item => item.id), ['initial', 'verified']);
  report.evidence[1].summary = 'Changed snapshot';
  assert.notEqual(selectFindingSubtasks(report, options)[0].sourceFindingDigest, task.sourceFindingDigest);
  report.findings[0].evidenceIds.push('missing');
  assert.deepEqual(selectFindingSubtasks(report, options), []);
});

test('subtask pool runs at most the configured number of child loops', async () => {
  let active = 0;
  let peak = 0;
  const release = [];
  const running = runFindingSubtasks([0, 1, 2], 2, async value => {
    peak = Math.max(peak, ++active);
    await new Promise(resolve => { release.push(resolve); });
    active -= 1;
    return value;
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(peak, 2);
  release.shift()();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(peak, 2);
  release.splice(0).forEach(resolve => resolve());
  await running;
  assert.equal(active, 0);
});
