'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { DeepSeekReasoningEngine, RuleReasoningEngine } = require('../src');
const { storedXssCanaryContent } = require('../src/xss-canary');

const MARKER = 'a'.repeat(32);
const TITLE = `agent-xss-canary-run-123-${MARKER}`;
const ORIGIN = 'http://127.0.0.1:3000';
const CATALOG_ID = 'create_stored_xss_canary_post';

function planInput() {
  const content = storedXssCanaryContent(MARKER);
  return {
    testProfile: 'stored_xss_canary',
    expectedTarget: { marker: MARKER, title: TITLE, content, attackerId: 'alice' },
    targetOrigin: ORIGIN,
    candidates: [{
      knowledgeId: 'local-stored-xss',
      cwe: 'CWE-79',
      severity: 'high',
      severityBasis: 'bounded_local_canary_hypothesis',
      attackerId: 'alice', marker: MARKER, title: TITLE, content,
      actionTemplate: { method: 'POST', pathTemplate: '/api/posts' },
      successCriteria: ['201 created', 'browser callback for matching post and marker'],
      provenance: { source: 'agent_bound_local_canary' },
    }],
  };
}

function reflectInput() {
  return {
    testProfile: 'stored_xss_canary',
    runId: 'run-123',
    targetOrigin: ORIGIN,
    target: { marker: MARKER, title: TITLE, attackerId: 'alice', postId: 17 },
    actionResult: { status: 201, postId: 17 },
    after: {
      executed: true,
      marker: MARKER,
      postId: '17',
      pageUrl: `${ORIGIN}/`,
      postVisible: true,
      payloadPresent: true,
      bindingCalled: true,
      errors: [],
    },
    evidenceRefs: ['evidence-http-post', 'evidence-browser-observation'],
    knowledge: { cwe: 'CWE-79', severity: 'high', severityBasis: 'local-canary' },
  };
}

function clientForDecision(decide) {
  const calls = [];
  return {
    calls,
    async completeJson(input) {
      calls.push(input);
      return {
        value: decide(input),
        metadata: { provider: 'deepseek', model: 'deepseek-flash' },
      };
    },
  };
}

test('stored-XSS profile emits one exact harmless marker-bound POST action', () => {
  const input = planInput();
  const plan = new RuleReasoningEngine().plan(input);

  assert.equal(plan.state, 'act');
  assert.deepEqual(plan.action, {
    operation: 'http_request',
    session: 'attacker',
    method: 'POST',
    path: '/api/posts',
    body: { title: TITLE, content: storedXssCanaryContent(MARKER) },
  });
  assert.deepEqual(plan.target, { marker: MARKER, title: TITLE, attackerId: 'alice' });
  assert.equal(plan.knowledge.cwe, 'CWE-79');
});

test('stored-XSS plan stops on mismatched canary, payload, or action template', async t => {
  const cases = [
    ['more than one candidate', input => input.candidates.push({ ...input.candidates[0] })],
    ['candidate marker', input => { input.candidates[0].marker = 'b'.repeat(32); }],
    ['candidate title', input => { input.candidates[0].title = 'other'; }],
    ['candidate content', input => { input.candidates[0].content = 'other'; }],
    ['payload body', input => { input.expectedTarget.content += '<script>oops</script>'; }],
    ['malformed marker', input => { input.expectedTarget.marker = 'not-a-marker'; }],
    ['unbound title', input => { input.expectedTarget.title = 'unrelated'; }],
    ['wrong method', input => { input.candidates[0].actionTemplate.method = 'PUT'; }],
    ['wrong path', input => { input.candidates[0].actionTemplate.pathTemplate = '/api/session'; }],
    ['extra template field', input => { input.candidates[0].actionTemplate.url = 'https://example.com'; }],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, () => {
      const input = planInput();
      mutate(input);
      const plan = new RuleReasoningEngine().plan(input);
      assert.equal(plan.state, 'stop');
      assert.equal(plan.action, null);
    });
  }
});

test('stored-XSS reflection confirms only HTTP creation plus marker/post-bound browser execution', async t => {
  const engine = new RuleReasoningEngine();
  const confirmed = engine.reflect(reflectInput());
  assert.equal(confirmed.state, 'stop');
  assert.equal(confirmed.finding.status, 'confirmed');
  assert.equal(confirmed.finding.cwe, 'CWE-79');
  assert.deepEqual(Object.values(confirmed.finding.checks), Array(10).fill(true));

  const cases = [
    ['HTTP not created', input => { input.actionResult.status = 200; }],
    ['HTTP post mismatch', input => { input.actionResult.postId = 18; }],
    ['browser post mismatch', input => { input.after.postId = '18'; }],
    ['marker mismatch', input => { input.after.marker = 'b'.repeat(32); }],
    ['off-origin page', input => { input.after.pageUrl = 'https://example.com/'; }],
    ['post hidden', input => { input.after.postVisible = false; }],
    ['payload absent', input => { input.after.payloadPresent = false; }],
    ['binding not called', input => { input.after.bindingCalled = false; }],
    ['script not executed', input => { input.after.executed = false; }],
    ['browser error', input => { input.after.errors = ['page failed']; }],
    ['missing evidence reference', input => { input.evidenceRefs = ['only-http']; }],
    ['duplicate evidence reference', input => { input.evidenceRefs = ['same', 'same']; }],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, () => {
      const input = reflectInput();
      mutate(input);
      assert.equal(engine.reflect(input).finding.status, 'not_confirmed');
    });
  }
});

test('DeepSeek may approve only the bounded stored-XSS action and exact structured curl body', async () => {
  const client = clientForDecision(({ userPayload }) => ({
    state: 'act',
    candidateId: 'candidate-0',
    actionCatalogId: CATALOG_ID,
    curl: { ...userPayload.allowedCurl, body: { ...userPayload.allowedCurl.body } },
  }));
  const engine = new DeepSeekReasoningEngine({ client, curlMode: true });
  const plan = await engine.plan(planInput());

  assert.equal(plan.state, 'act');
  assert.deepEqual(plan.curl, {
    method: 'POST',
    url: `${ORIGIN}/api/posts`,
    body: { title: TITLE, content: storedXssCanaryContent(MARKER) },
  });
  assert.deepEqual(plan.action.body, plan.curl.body);
  assert.deepEqual(client.calls[0].userPayload.allowedActionCatalogIds, [CATALOG_ID]);
  assert.equal(client.calls[0].userPayload.allowedCandidates[0].candidateId, 'candidate-0');
});

test('DeepSeek rejects any altered stored-XSS curl body or action identifier', async t => {
  const cases = [
    ['missing body', decision => { delete decision.curl.body; }],
    ['changed content', decision => { decision.curl.body.content = 'different'; }],
    ['changed title', decision => { decision.curl.body.title = 'different'; }],
    ['extra body field', decision => { decision.curl.body.secret = 'extra'; }],
    ['changed path', decision => { decision.curl.url = `${ORIGIN}/api/session`; }],
    ['shell field', decision => { decision.curl.flags = ['--config']; }],
    ['wrong catalog', decision => { decision.actionCatalogId = 'delete_observed_canary'; }],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const client = clientForDecision(({ userPayload }) => {
        const decision = {
          state: 'act', candidateId: 'candidate-0', actionCatalogId: CATALOG_ID,
          curl: { ...userPayload.allowedCurl, body: { ...userPayload.allowedCurl.body } },
        };
        mutate(decision);
        return decision;
      });
      const engine = new DeepSeekReasoningEngine({ client, curlMode: true });
      await assert.rejects(() => engine.plan(planInput()), error => {
        assert.equal(error.code, 'DEEPSEEK_SCHEMA_ERROR');
        return true;
      });
    });
  }
});

test('DeepSeek does not receive an invalid stored-XSS candidate', async () => {
  const input = planInput();
  input.candidates[0].content = 'arbitrary';
  const client = clientForDecision(() => { throw new Error('model must not be called'); });
  const plan = await new DeepSeekReasoningEngine({ client, curlMode: true }).plan(input);
  assert.equal(plan.state, 'stop');
  assert.equal(client.calls.length, 0);
});
