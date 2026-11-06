import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createExternalGeneralRuntime } from '../external-runtime.mjs';
import { normalizeExternalTarget } from '../external-target.mjs';

const target = 'https://8.8.8.8/start';
const response = (body, status = 200) => ({ status, contentType: 'text/html', body,
  headers: { 'x-content-type-options': 'nosniff' }, truncated: false, durationMs: 1 });
const allowPacket = async () => ({ verdict: 'IN_SCOPE', reasonCode: 'IN_SCOPE',
  allowExecution: true, modelCalled: false });
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
    scope: normalizeExternalTarget({ target, scope: { maxRequests: 12 } }).scope,
    sllmCheckImpl: allowPacket,
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
    assert.equal(run.report.scope.maxRequests, 12);
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
    sllmCheckImpl: allowPacket,
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

test('external comparison sends neither packet when the candidate fails sLLM review', async () => {
  const requests = []; const roles = [];
  const runtime = createExternalGeneralRuntime({ targetUrl: target,
    modelId: 'deepseek-flash', runIdFactory: () => 'external-sllm-denied',
    requestImpl: async url => {
      requests.push(url);
      return response(url === target
        ? '<title>Start</title><a href="/start/search">Search</a>' : '<title>Search</title>');
    },
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      return { done: false, hypotheses: [{ id: 'h-one', category: 'reflected_input',
        asset: '/start/search', rationale: 'Compare a public marker.', evidenceIds: [context.evidence[0].id] }],
      probes: [{ id: 'p-one', hypothesisId: 'h-one', tool: 'http_compare',
        input: { path: '/start/search?q=candidate', controlPath: '/start/search?q=control' } }] };
    } }),
    sllmCheckImpl: async (_packet, trusted) => {
      roles.push(trusted.packetRole);
      return trusted.packetRole === 'control' ? allowPacket()
        : { verdict: 'DENY', reasonCode: 'DENY', allowExecution: false, modelCalled: false };
    },
  });
  try {
    const done = terminal(runtime); runtime.startLab(); const run = await done;
    assert.equal(run.status, 'completed', run.error);
    assert.deepEqual(roles, ['control', 'candidate']);
    assert.deepEqual(requests, [target, 'https://8.8.8.8/start/search']);
    assert.equal(run.report.probes[0].status, 'blocked');
    assert.equal(run.report.probes[0].reason, 'sllm_deny');
    assert.equal(run.report.sllm.evaluatedPackets, 2);
    assert.equal(run.report.coverage.requestsUsed, 2);
  } finally { await runtime.close(); }
});

test('external probe uses the configured local sLLM before attack-tool sends requests', async t => {
  const modelRequests = []; const targetRequests = [];
  const modelServer = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const message = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    const input = JSON.parse(message.messages[1].content);
    modelRequests.push(input);
    const output = { verdict: 'IN_SCOPE',
      evidence: [{ source: 'query', key: 'q', value: input.request.query.q }],
      checks: { testPurposeClear: true, noSensitiveAccess: true,
        noDangerousImpact: true, commonCriteriaSatisfied: true },
      reason: 'Bounded public read-only request.', confidence: 0.9 };
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ message: { content: JSON.stringify(output) },
      prompt_eval_count: 20, eval_count: 10 }));
  });
  await new Promise(resolve => modelServer.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => modelServer.close(resolve)));
  const runtime = createExternalGeneralRuntime({ targetUrl: target,
    modelId: 'deepseek-flash', runIdFactory: () => 'external-live-local-sllm',
    env: { CA3P_GUARDRAIL_SLLM_ENDPOINT: `http://127.0.0.1:${modelServer.address().port}`,
      CA3P_GUARDRAIL_SLLM_MODEL: 'guardrail-local' },
    requestImpl: async url => {
      targetRequests.push(url);
      return response(url === target
        ? '<title>Start</title><a href="/start/search">Search</a>' : '<title>Search</title>');
    },
    plannerFactory: () => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      return { done: false, hypotheses: [{ id: 'h-live', category: 'reflected_input',
        asset: '/start/search', rationale: 'Compare a public marker.', evidenceIds: [context.evidence[0].id] }],
      probes: [{ id: 'p-live', hypothesisId: 'h-live', tool: 'http_compare',
        input: { path: '/start/search?q=marker', controlPath: '/start/search?q=ordinary' } }] };
    } }),
    verifyAttackImpl: async attack => ({ schemaVersion: 'verifier/1', attackId: attack.id,
      status: 'not_reproduced', reason: 'No reflection observed.', artifacts: [] }),
  });
  try {
    const done = terminal(runtime); runtime.startLab(); const run = await done;
    assert.equal(run.status, 'completed', run.error);
    assert.equal(run.report.probes[0].status, 'not_reproduced');
    assert.equal(run.report.sllm.modelCalls, 2);
    assert.equal(run.report.attackTool.metrics.requests, 1);
    assert.deepEqual(modelRequests.map(item => item.request.packetRole), ['control', 'candidate']);
    assert.deepEqual(targetRequests.slice(2), [
      'https://8.8.8.8/start/search?q=ordinary', 'https://8.8.8.8/start/search?q=marker']);
  } finally { await runtime.close(); }
});

test('external general loop counts both requests in each comparison and stops at the scope budget', async () => {
  const requests = [];
  const runtime = createExternalGeneralRuntime({ targetUrl: target,
    sllmCheckImpl: allowPacket,
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
    sllmCheckImpl: allowPacket,
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

test('external follow-up stores an independent child report within the original GET scope and request cap', async () => {
  const requests = [];
  const subtasks = new Map();
  const runtime = createExternalGeneralRuntime({ targetUrl: target,
    sllmCheckImpl: allowPacket,
    modelId: 'deepseek-flash', runIdFactory: () => 'external-general-followup',
    multiAgent: { enabled: true, maxTasks: 1, maxConcurrentAgents: 1,
      maxTargetRequests: 5 },
    subtaskRepository: {
      create: async task => { subtasks.set(task.id, { ...task, status: 'queued' }); },
      start: async id => { subtasks.get(id).status = 'running'; },
      finish: async (id, outcome) => { Object.assign(subtasks.get(id), outcome); },
    },
    requestImpl: async (url, options) => {
      requests.push({ url, method: options.method });
      return response('<title>Start</title>');
    },
    plannerFactory: ({ taskId }) => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      if (taskId) {
        assert.deepEqual(context.availableTools, ['http_get']);
        assert.equal(context.hypotheses[0].id, 'h-followup');
        return { done: false, hypotheses: [], probes: [{ id: 'p-child',
          hypothesisId: 'h-followup', tool: 'http_get', input: { path: '/start?probe=child' } }] };
      }
      return { done: false, hypotheses: [{ id: 'h-followup', category: 'configuration',
        asset: '/start', rationale: 'Inspect the bounded public page.',
        evidenceIds: [context.evidence[0].id] }],
      probes: [{ id: 'p-main', hypothesisId: 'h-followup', tool: 'http_get',
        input: { path: '/start?probe=main' } }] };
    } }),
    verifyAttackImpl: async attack => ({ schemaVersion: 'verifier/1', attackId: attack.id,
      status: 'confirmed', reason: 'The bounded response supports the hypothesis.', artifacts: [] }),
  });
  try {
    const done = terminal(runtime); runtime.startLab(); const run = await done;
    assert.equal(run.status, 'completed', run.error);
    assert.equal(run.multiAgent.status, 'completed');
    assert.equal(run.multiAgent.tasks.length, 1);
    const [task] = subtasks.values();
    assert.equal(task.status, 'completed');
    assert.equal(task.result.report.runId, task.id);
    assert.equal(task.result.report.status, 'completed');
    assert.equal(task.result.report.findings[0].status, 'confirmed');
    assert.equal(task.result.report.sllm.evaluatedPackets, 1);
    assert.equal(task.result.report.scope.focusPath, '/start');
    const childVerify = run.events.find(event => event.stage === 'verify'
      && event.source === 'agent/finding-subagent');
    assert.equal(childVerify.module, 'subagent');
    assert.equal(childVerify.taskId, task.id);
    assert.equal(childVerify.agentId, task.agentId);
    assert.equal(childVerify.response.status, 'confirmed');
    assert.notEqual(childVerify.request.probeId, 'p-main');
    assert.equal(run.report.coverage.requestsUsed, requests.length);
    assert.ok(requests.length <= 5);
    assert.ok(requests.every(item => item.method === 'GET'
      && item.url.startsWith('https://8.8.8.8/start')));
  } finally { await runtime.close(); }
});

test('external child cannot probe another discovered path outside its assigned finding', async () => {
  const requests = [];
  const subtasks = new Map();
  const runtime = createExternalGeneralRuntime({ targetUrl: target,
    sllmCheckImpl: allowPacket,
    modelId: 'deepseek-flash', runIdFactory: () => 'external-general-child-scope',
    multiAgent: { enabled: true, maxTasks: 1, maxConcurrentAgents: 1 },
    subtaskRepository: {
      create: task => { subtasks.set(task.id, { ...task }); },
      start: () => {},
      finish: (id, outcome) => { Object.assign(subtasks.get(id), outcome); },
    },
    requestImpl: async (url, options) => {
      requests.push([url, options.method]);
      return response(url === target ? '<a href="/start/other">Other</a>' : '<title>Page</title>');
    },
    plannerFactory: ({ taskId }) => ({ async propose(context) {
      if (context.iteration > 1) return { done: true, hypotheses: [], probes: [] };
      if (taskId) return { done: false, hypotheses: [], probes: [
        { id: 'p-other', hypothesisId: 'h-focus', tool: 'http_get', input: { path: '/start/other' } },
        { id: 'p-focus', hypothesisId: 'h-focus', tool: 'http_get', input: { path: '/start?probe=child' } },
      ] };
      return { done: false, hypotheses: [{ id: 'h-focus', category: 'configuration',
        asset: '/start', rationale: 'Recheck this page only.', evidenceIds: [context.evidence[0].id] }],
      probes: [{ id: 'p-main', hypothesisId: 'h-focus', tool: 'http_get',
        input: { path: '/start?probe=main' } }] };
    } }),
    verifyAttackImpl: async attack => ({ schemaVersion: 'verifier/1', attackId: attack.id,
      status: 'confirmed', reason: 'The response supports the hypothesis.', artifacts: [] }),
  });
  try {
    const done = terminal(runtime); runtime.startLab(); const run = await done;
    assert.equal(run.status, 'completed', run.error);
    const [task] = subtasks.values();
    assert.equal(task.result.report.probes[0].status, 'blocked');
    assert.equal(task.result.report.probes[0].reason, 'path_out_of_scope');
    assert.equal(task.result.report.probes[1].status, 'confirmed');
    assert.equal(requests.filter(([url]) => url === 'https://8.8.8.8/start/other').length, 1);
    assert.ok(requests.every(([, method]) => method === 'GET'));
    assert.ok(requests.length <= 8);
  } finally { await runtime.close(); }
});
