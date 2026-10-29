import test from 'node:test';
import assert from 'node:assert/strict';
import { createExternalGeneralRuntime } from '../external-runtime.mjs';
import { normalizeExternalTarget } from '../external-target.mjs';

const target = 'https://8.8.8.8/start';
const response = (body, status = 200) => ({ status, contentType: 'text/html', body,
  headers: { 'x-content-type-options': 'nosniff' }, truncated: false, durationMs: 1 });
function terminal(runtime) {
  return new Promise(resolve => {
    const detach = runtime.subscribe(({ run }) => {
      if (['completed', 'failed', 'stopped'].includes(run.status)) { detach(); resolve(run); }
    });
  });
}

test('external general loop plans scoped comparisons and uses the independent verifier', async () => {
  const requests = []; const records = []; const modelCalls = [];
  const runtime = createExternalGeneralRuntime({ targetUrl: target,
    modelId: 'deepseek-flash', runIdFactory: () => 'external-general-verified',
    requestImpl: async (url, options) => {
      requests.push([url, options.method]);
      if (url === target) return response('<title>Start</title><a href="/start/search">Search</a>');
      if (url.endsWith('/start/search')) return response('<title>Search</title>');
      if (url.includes('probe=canary')) return response('<p>canary was reflected</p>');
      return response('<p>ordinary result</p>');
    },
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [],
        modelMetadata: { provider: 'deepseek', model: 'deepseek-flash' } };
      assert.deepEqual(context.availableTools, ['http_get', 'http_compare']);
      return { done: false, hypotheses: [{ id: 'h-reflect', category: 'reflected_input',
        asset: '/start/search', rationale: 'Compare reflected and ordinary query values.',
        evidenceIds: [context.evidence[0].id] }],
      probes: [{ id: 'p-compare', hypothesisId: 'h-reflect', tool: 'http_compare',
        input: { path: '/start/search?probe=canary', controlPath: '/start/search?probe=ordinary' } }],
      modelMetadata: { provider: 'deepseek', model: 'deepseek-flash' } };
    } }),
    verifyAttackImpl: async (attack, options) => {
      records.push({ attack, options });
      return { schemaVersion: 'verifier/1', attackId: attack.id, status: 'confirmed',
        reason: 'The candidate response reflects the marker and the control does not.', artifacts: [],
        model: [{ provider: 'deepseek', model: 'deepseek-flash',
          usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } }] };
    },
    onModelCall: async metadata => { modelCalls.push(metadata); },
  });
  try {
    const done = terminal(runtime); runtime.startLab(); const run = await done;
    assert.equal(run.status, 'completed', run.error);
    assert.equal(run.report.inspectionMode, 'external-general');
    assert.equal(run.report.findings[0].status, 'confirmed');
    assert.equal(run.report.probes[0].status, 'confirmed');
    assert.equal(run.report.coverage.supportedIndependentChecks, 1);
    assert.equal(run.report.coverage.requestsUsed, 4);
    assert.equal(run.report.modelCalls.length, 3);
    assert.equal(modelCalls.length, 3);
    assert.equal(run.report.modelCalls.at(-1).role, 'verifier');
    assert.equal(run.report.modelCalls.at(-1).usage.total_tokens, 15);
    const verified = run.events.find(event => event.stage === 'verify');
    assert.equal(verified.module, 'agent');
    assert.equal(verified.source, 'agent/general-assessment');
    assert.equal(verified.request.probeId, 'p-compare');
    assert.equal(verified.response.status, 'confirmed');
    assert.equal(records.length, 1);
    assert.equal(records[0].attack.control.response.status, 200);
    assert.match(records[0].attack.response.bodyText, /canary was reflected/u);
    assert.equal(records[0].options.env.CA3P_VERIFIER_MODEL, 'deepseek-flash');
    assert.equal(typeof records[0].options.browserFactory, 'function');
    await assert.rejects(records[0].options.browserFactory(), { code: 'EXTERNAL_BROWSER_DISABLED' });
    assert.deepEqual(requests.map(([url]) => url), [target, 'https://8.8.8.8/start/search',
      'https://8.8.8.8/start/search?probe=ordinary', 'https://8.8.8.8/start/search?probe=canary']);
  } finally { await runtime.close(); }
});

test('external general policy blocks unobserved paths and credential queries', async () => {
  const requests = [];
  const runtime = createExternalGeneralRuntime({ targetUrl: target,
    scope: normalizeExternalTarget({ target, scope: { pathPrefix: '/start' } }).scope,
    modelId: 'deepseek-flash', runIdFactory: () => 'external-general-scope',
    requestImpl: async url => {
      requests.push(url);
      return response('<title>Start</title><a href="/outside">Outside</a>'
        + '<a href="http://169.254.169.254/latest">Metadata</a>');
    },
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      return { done: false, hypotheses: [{ id: 'h-scope', category: 'configuration',
        asset: '/start', rationale: 'Inspect the permitted page.', evidenceIds: [context.evidence[0].id] }],
      probes: [
        { id: 'p-admin', hypothesisId: 'h-scope', tool: 'http_get', input: { path: '/admin' } },
        { id: 'p-secret', hypothesisId: 'h-scope', tool: 'http_get', input: { path: '/start?token=private' } },
        { id: 'p-off', hypothesisId: 'h-scope', tool: 'http_get', input: { path: 'http://169.254.169.254/latest' } },
        { id: 'p-allowed', hypothesisId: 'h-scope', tool: 'http_get', input: { path: '/start?view=public' } },
      ] };
    } }),
    verifyAttackImpl: async attack => ({ schemaVersion: 'verifier/1', attackId: attack.id,
      status: 'not_reproduced', reason: 'No weakness was demonstrated.', artifacts: [] }),
  });
  try {
    const done = terminal(runtime); runtime.startLab(); const run = await done;
    assert.equal(run.status, 'completed', run.error);
    assert.deepEqual(requests, [target, 'https://8.8.8.8/start?view=public']);
    assert.deepEqual(run.report.probes.map(item => item.status),
      ['blocked', 'blocked', 'blocked', 'not_reproduced']);
    assert.equal(run.report.coverage.requestsUsed, 2);
    assert.equal(run.report.policyRejections.byReason.out_of_scope_path, 1);
    assert.equal(run.report.policyRejections.byReason.out_of_scope_origin, 1);
    assert.doesNotMatch(JSON.stringify(run), /169\.254\.169\.254|token=private/u);
  } finally { await runtime.close(); }
});

test('external general loop counts both requests in each comparison and stops at the scope budget', async () => {
  const requests = [];
  const runtime = createExternalGeneralRuntime({ targetUrl: target,
    modelId: 'deepseek-flash', runIdFactory: () => 'external-general-budget',
    requestImpl: async url => { requests.push(url); return response('<title>Start</title>'); },
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      return { done: false, hypotheses: [{ id: 'h-budget', category: 'configuration',
        asset: '/start', rationale: 'Compare responses within the request budget.',
        evidenceIds: [context.evidence[0].id] }],
      probes: Array.from({ length: 4 }, (_, index) => ({ id: `p-budget-${index + 1}`,
        hypothesisId: 'h-budget', tool: 'http_compare',
        input: { path: `/start?probe=${index}`, controlPath: `/start?control=${index}` } })) };
    } }),
    verifyAttackImpl: async attack => ({ schemaVersion: 'verifier/1', attackId: attack.id,
      status: 'not_reproduced', reason: 'No weakness was demonstrated.', artifacts: [] }),
  });
  try {
    const done = terminal(runtime); runtime.startLab(); const run = await done;
    assert.equal(run.status, 'completed', run.error);
    assert.equal(requests.length, 7);
    assert.equal(run.report.coverage.requestsUsed, 7);
    assert.equal(run.report.probes.at(-1).status, 'blocked');
    assert.equal(run.report.probes.at(-1).reason, 'request_budget');
    assert.equal(run.report.stopReason, 'request_budget');
    assert.equal(run.report.partial, true);
  } finally { await runtime.close(); }
});

test('truncated external responses cannot produce confirmed findings', async () => {
  let verifierCalls = 0;
  const runtime = createExternalGeneralRuntime({ targetUrl: target,
    modelId: 'deepseek-flash', runIdFactory: () => 'external-general-truncated',
    requestImpl: async url => ({ ...response('<title>Start</title>'),
      truncated: url.includes('probe=') }),
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      return { done: false, hypotheses: [{ id: 'h-truncated', category: 'configuration',
        asset: '/start', rationale: 'Check a bounded response.', evidenceIds: [context.evidence[0].id] }],
      probes: [{ id: 'p-truncated', hypothesisId: 'h-truncated', tool: 'http_get',
        input: { path: '/start?probe=one' } }] };
    } }),
    verifyAttackImpl: async () => { verifierCalls += 1; throw new Error('must not verify partial body'); },
  });
  try {
    const done = terminal(runtime); runtime.startLab(); const run = await done;
    assert.equal(run.status, 'completed', run.error);
    assert.equal(run.report.probes[0].status, 'inconclusive');
    assert.equal(run.report.findings[0].status, 'inconclusive');
    assert.equal(verifierCalls, 0);
    assert.equal(run.report.partial, true);
  } finally { await runtime.close(); }
});
