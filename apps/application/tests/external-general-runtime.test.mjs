import test from 'node:test';
import assert from 'node:assert/strict';
import { createExternalRuntime } from '../external-runtime.mjs';

async function completedRun(runtime) {
  const completed = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('external general runtime timeout')), 5000);
    const detach = runtime.subscribe(state => {
      if (['completed', 'failed', 'stopped'].includes(state.run.status)) {
        clearTimeout(timer); detach(); resolve(state.run);
      }
    });
  });
  runtime.startLab();
  return completed;
}

const metadata = iteration => ({ provider: 'deepseek', model: 'deepseek-flash',
  status: 'completed', iteration });

test('external model loop follows discovered public links and leaves hypotheses unconfirmed', async () => {
  const requested = [];
  const recordedCalls = [];
  const entry = 'https://8.8.8.8/start?view=private-value';
  const runtime = createExternalRuntime({ targetUrl: entry,
    scope: { pathPrefix: '/start' }, modelId: 'deepseek-flash',
    runIdFactory: () => 'external-model-loop', onModelCall: call => recordedCalls.push(call),
    requestImpl: async (url, options) => {
      assert.equal(options.method, 'GET');
      requested.push(url);
      return { status: 200, contentType: 'text/html', durationMs: 1, truncated: false,
        body: url === entry ? '<title>Start</title><a href="/start/child">child</a>'
          + '<a href="/start/signed?view=private-value">signed</a>'
          + '<a href="https://other.example/out">outside</a>'
          : '<title>Child</title>' };
    },
    plannerFactory: async ({ assessmentContext }) => {
      assert.equal(assessmentContext, 'external-read-only');
      return { async propose({ iteration, inventory, evidence, availableTools }) {
        assert.deepEqual(availableTools, ['http_get']);
        assert.equal(JSON.stringify({ inventory, evidence }).includes('private-value'), false);
        if (iteration === 1) return { done: false,
          hypotheses: [{ id: 'h1', category: 'information_disclosure', asset: '/start/child',
            rationale: 'The linked page needs another observation.', evidenceIds: [evidence[0].id] }],
          probes: [{ id: 'p1', hypothesisId: 'h1', tool: 'http_get', input: { path: '/start/child' } }],
          modelMetadata: metadata(iteration) };
        return { done: true, hypotheses: [], probes: [], modelMetadata: metadata(iteration) };
      } };
    } });
  try {
    const run = await completedRun(runtime);
    assert.equal(run.status, 'completed');
    assert.equal(run.testProfile, 'external-general-read-only');
    assert.equal(run.provider, 'deepseek');
    assert.deepEqual(requested, [entry, 'https://8.8.8.8/start/child']);
    assert.equal(run.report.inspectionMode, 'external-general-read-only');
    assert.equal(run.report.probes[0].status, 'inconclusive');
    assert.equal(run.report.findings[0].status, 'inconclusive');
    assert.equal(run.report.coverage.confirmed, 0);
    assert.equal(run.report.coverage.requestsUsed, 2);
    assert.equal(run.report.modelCalls.length, 2);
    assert.equal(recordedCalls.length, 2);
    assert.equal(run.report.policyRejections.byReason.query_link, 1);
    assert.equal(run.report.policyRejections.byReason.out_of_scope_origin, 1);
    assert.equal(JSON.stringify(run).includes('private-value'), false);
  } finally { await runtime.close(); }
});

test('external model probes cannot leave discovered query-free paths', async () => {
  const requested = [];
  const paths = ['/outside', '/start/unknown', '/start/child?view=1',
    'https://8.8.8.8/start/child'];
  const runtime = createExternalRuntime({ targetUrl: 'https://8.8.8.8/start',
    scope: { pathPrefix: '/start' }, modelId: 'deepseek-flash',
    requestImpl: async url => {
      requested.push(url);
      return { status: 200, contentType: 'text/html', durationMs: 1,
        body: '<a href="/start/child">child</a>' };
    },
    plannerFactory: async () => ({ async propose({ iteration, evidence }) {
      if (iteration > 1) return { done: true, hypotheses: [], probes: [],
        modelMetadata: metadata(iteration) };
      return { done: false,
        hypotheses: paths.map((path, index) => ({ id: `h${index}`, category: 'candidate',
          asset: path, rationale: 'Unverified candidate.', evidenceIds: [evidence[0].id] })),
        probes: paths.map((path, index) => ({ id: `p${index}`, hypothesisId: `h${index}`,
          tool: 'http_get', input: { path } })), modelMetadata: metadata(iteration) };
    } }) });
  try {
    const run = await completedRun(runtime);
    assert.equal(run.status, 'completed');
    assert.deepEqual(requested, ['https://8.8.8.8/start']);
    assert.equal(run.report.coverage.requestsUsed, 1);
    assert.deepEqual(run.report.probes.map(probe => probe.status),
      ['blocked', 'blocked', 'blocked', 'blocked']);
    assert.ok(run.report.findings.every(finding => finding.status === 'not_tested'));
  } finally { await runtime.close(); }
});

test('external model loop shares the eight-request cap across entry and probes', async () => {
  const requested = [];
  const links = Array.from({ length: 8 }, (_item, index) => `/start/child-${index}`);
  const runtime = createExternalRuntime({ targetUrl: 'https://8.8.8.8/start',
    modelId: 'deepseek-flash', requestImpl: async url => {
      requested.push(url);
      return { status: 200, contentType: 'text/html', durationMs: 1,
        body: url.endsWith('/start') ? links.map(path => `<a href="${path}">child</a>`).join('') : '' };
    },
    plannerFactory: async () => ({ async propose({ evidence }) {
      return { done: false,
        hypotheses: links.slice(0, 7).map((_path, index) => ({ id: `h${index}`,
          category: 'candidate', asset: links[index], rationale: 'Read linked page.',
          evidenceIds: [evidence[0].id] })),
        probes: links.slice(0, 7).map((path, index) => ({ id: `p${index}`,
          hypothesisId: `h${index}`, tool: 'http_get', input: { path } })),
        modelMetadata: metadata(1) };
    } }) });
  try {
    const run = await completedRun(runtime);
    assert.equal(run.status, 'completed');
    assert.equal(requested.length, 8);
    assert.equal(run.report.coverage.requestsUsed, 8);
    assert.equal(run.report.inventory.pages.length, 8);
    assert.equal(run.report.budget.maxProbes, 7);
    assert.equal(run.report.coverage.confirmed, 0);
  } finally { await runtime.close(); }
});

test('failed entry observation stops before model planning', async () => {
  let modelCalls = 0;
  const runtime = createExternalRuntime({ targetUrl: 'https://8.8.8.8/start',
    modelId: 'deepseek-flash', requestImpl: async () => {
      throw Object.assign(new Error('network unavailable'), { code: 'TEST_NETWORK_UNAVAILABLE' });
    }, plannerFactory: async () => ({ async propose() { modelCalls += 1; return null; } }) });
  try {
    const run = await completedRun(runtime);
    assert.equal(run.status, 'failed');
    assert.equal(modelCalls, 0);
    assert.equal(run.report.status, 'failed');
    assert.equal(run.report.coverage.observedPages, 0);
    assert.equal(run.report.observationErrors[0].code, 'TEST_NETWORK_UNAVAILABLE');
  } finally { await runtime.close(); }
});

test('a one-item evidence budget blocks further reads without failing the run', async () => {
  const requested = [];
  const runtime = createExternalRuntime({ targetUrl: 'https://8.8.8.8/start',
    modelId: 'deepseek-flash', limits: { maxIterations: 2, maxProbes: 4, maxEvidenceItems: 1 },
    requestImpl: async url => {
      requested.push(url);
      return { status: 200, contentType: 'text/html', durationMs: 1,
        body: '<a href="/start/child">child</a>' };
    }, plannerFactory: async () => ({ async propose({ iteration, evidence }) {
      if (iteration > 1) return { done: true, hypotheses: [], probes: [],
        modelMetadata: metadata(iteration) };
      return { done: false,
        hypotheses: [{ id: 'h1', category: 'candidate', asset: '/start/child',
          rationale: 'Read linked page.', evidenceIds: [evidence[0].id] }],
        probes: [{ id: 'p1', hypothesisId: 'h1', tool: 'http_get',
          input: { path: '/start/child' } }], modelMetadata: metadata(iteration) };
    } }) });
  try {
    const run = await completedRun(runtime);
    assert.equal(run.status, 'completed');
    assert.deepEqual(requested, ['https://8.8.8.8/start']);
    assert.equal(run.report.probes[0].status, 'blocked');
    assert.equal(run.report.probes[0].reason, 'evidence_budget');
  } finally { await runtime.close(); }
});
