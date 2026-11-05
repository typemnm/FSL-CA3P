'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createGeneralModelPlanner, runGeneralAssessment } = require('../src');

test('general model proposals drive a bounded assessment through independent evidence verification', async () => {
  const prompts = [];
  const client = { async completeJson(request) {
    prompts.push(request.userPayload);
    return { value: prompts.length === 1
      ? { done: false, hypotheses: [{ id: 'h1', category: 'configuration_exposure', asset: '/_diag/config',
        rationale: 'The observed route appears to expose runtime configuration.', evidenceIds: ['observed-route'] }],
      probes: [{ id: 'p1', hypothesisId: 'h1', tool: 'http_read', input: { path: '/_diag/config' } }] }
      : prompts.length === 2
        ? { done: false, hypotheses: [], probes: [
          { id: 'p1', hypothesisId: 'h1', tool: 'http_read', input: { path: '/_diag/config' } }] }
        : { done: true, hypotheses: [], probes: [] },
    metadata: { provider: 'deepseek', model: 'deepseek-flash', finishReason: 'stop',
      usage: { prompt_tokens: 30, completion_tokens: 12 } } };
  } };
  const planner = createGeneralModelPlanner({ client });
  const executed = [];
  const events = [];
  const { report } = await runGeneralAssessment({
    target: { fixtureId: 'vul-web2-daehan', origin: 'http://127.0.0.1:4101' },
    availableTools: ['http_read'],
    limits: { maxIterations: 3, maxProbes: 3, maxEvidenceItems: 8 },
    observer: { async observe() { return prompts.length === 0
      ? { inventory: { routes: ['/_diag/config'], authorization: 'Bearer PRIVATE' },
        evidence: [{ id: 'observed-route', source: 'synthetic-http-inventory', kind: 'route',
          summary: 'GET /_diag/config is reachable without a session.', asset: '/_diag/config' }] }
      : { inventory: { routes: ['/_diag/config'], authorization: 'Bearer PRIVATE' }, evidence: [] }; } },
    planner,
    policy: { async authorize({ probe }) { return { allowed: probe.tool === 'http_read' }; } },
    executor: { async execute({ probe }) {
      executed.push(probe.id);
      return { evidence: [{ id: `verified-response-${probe.id}`, source: 'synthetic-http-response', kind: 'response',
        summary: 'GET /_diag/config returned runtime configuration without authentication.', asset: '/_diag/config' }] };
    } },
    verifier: { async verify({ execution }) { return { status: 'confirmed', completed: true,
      evidenceIds: execution.evidence.map(item => item.id) }; } },
    onEvent: async event => { events.push(event.stage); },
  });

  assert.equal(report.status, 'completed');
  assert.equal(report.stopReason, 'planner_done');
  assert.deepEqual(executed, ['p1', 'iteration2:probe1:1']);
  assert.deepEqual(report.coverage, { totalHypotheses: 1, confirmed: 1,
    notReproduced: 0, inconclusive: 0, notTested: 0 });
  assert.deepEqual(report.findings[0].evidenceIds,
    ['observed-route', 'verified-response-p1', 'verified-response-iteration2:probe1:1']);
  assert.equal(report.modelCalls.length, 3);
  assert.deepEqual(prompts[1].usedProbeIds, ['p1']);
  assert.ok(events.includes('verify'));
  assert.equal(prompts[0].inventory.authorization, '[redacted]');
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE/);
});
