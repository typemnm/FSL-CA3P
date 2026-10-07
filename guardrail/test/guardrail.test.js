'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { GuardrailEvaluator, loadRuleset, normalizeString } = require('../src');

const rulesetPath = path.join(__dirname, '..', 'rules', 'fsl-ca3p-guardrail-ruleset.json');
const ruleset = loadRuleset(rulesetPath);

function trusted(overrides = {}) {
  return {
    targetMode: 'isolated_local_lab',
    targetOrigin: 'http://127.0.0.1:3000',
    testProfile: 'agent_cross_user_delete_canary',
    runId: 'run-test-1',
    iteration: 1,
    currentUser: { id: 'alice' },
    fixtureOwner: { id: 'bob' },
    boundCanary: { resourceId: 4, ownerId: 'bob', createdByRunId: 'run-test-1' },
    networkPolicy: { externalRequests: 'DENY' },
    budget: {
      requestCount: 4,
      mutationCount: 1,
      deleteCount: 0,
      xssSubmissionCount: 0,
    },
    ...overrides,
  };
}

test('loads the final Notion ruleset', () => {
  assert.equal(ruleset.rulesetId, 'fsl-ca3p-vul-web-1-guardrail');
  assert.equal(ruleset.version, '1.0.1');
  assert.equal(ruleset.engine.defaultDecision, 'DENY');
});

test('allows exactly the Bob canary deletion bound to this run', () => {
  const evaluator = new GuardrailEvaluator(ruleset);
  const result = evaluator.evaluate({
    stage: 'loop.act',
    action: {
      operation: 'http_request', session: 'attacker', method: 'DELETE',
      path: '/api/posts/4', query: { authorId: 'bob' },
    },
    trustedContext: trusted(),
  });
  assert.equal(result.decision, 'ALLOW');
  assert.equal(result.ruleId, 'PROFILE.agent_cross_user_delete_canary.loop.act');
});

test('hard-denies deletion of seeded admin posts', () => {
  const evaluator = new GuardrailEvaluator(ruleset);
  const result = evaluator.evaluate({
    stage: 'loop.act',
    action: {
      operation: 'http_request', session: 'attacker', method: 'DELETE',
      path: '/api/posts/1', query: { authorId: 'admin' },
    },
    trustedContext: trusted(),
  });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.ruleId, 'DELETE-002');
});

test('denies a resource that is not the bound canary', () => {
  const evaluator = new GuardrailEvaluator(ruleset);
  const result = evaluator.evaluate({
    stage: 'loop.act',
    action: {
      operation: 'http_request', session: 'attacker', method: 'DELETE',
      path: '/api/posts/5', query: { authorId: 'bob' },
    },
    trustedContext: trusted(),
  });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.ruleId, 'PROFILE-CONSTRAINT-FAILED');
});

test('denies duplicate authority parameters before execution', () => {
  const evaluator = new GuardrailEvaluator(ruleset);
  const result = evaluator.evaluate({
    stage: 'loop.act',
    action: {
      operation: 'http_request', session: 'attacker', method: 'DELETE',
      path: '/api/posts/4', query: { authorId: ['bob', 'admin'] },
    },
    trustedContext: trusted(),
  });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.ruleId, 'CONTRACT-002');
});

test('classifies double-encoded XSS and denies it outside an XSS profile', () => {
  const evaluator = new GuardrailEvaluator(ruleset);
  const result = evaluator.evaluate({
    stage: 'setup.canary_post',
    action: {
      operation: 'http_request', session: 'fixture', method: 'POST', path: '/api/posts',
      body: { title: 'agent-canary-run-test-1', content: '%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E' },
    },
    trustedContext: trusted(),
  });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.ruleId, 'XSS-OUT-OF-PROFILE');
  assert.ok(result.matchedClassifiers.includes('XSS_EVENT_HANDLER'));
});

test('allows one stored-XSS canary only in the isolated XSS profile', () => {
  const evaluator = new GuardrailEvaluator(ruleset);
  const runId = 'run-xss-1';
  const result = evaluator.evaluate({
    stage: 'xss.inject_canary',
    action: {
      operation: 'http_request', session: 'attacker', method: 'POST', path: '/api/posts',
      body: { title: 'agent-xss-canary-run-xss-1', content: '<img src=x onerror=alert(1)>' },
    },
    trustedContext: trusted({
      testProfile: 'stored_xss_canary', runId,
      boundCanary: { titlePrefix: 'agent-xss-canary-', createdByRunId: runId },
      budget: { requestCount: 0, mutationCount: 0, deleteCount: 0, xssSubmissionCount: 0 },
    }),
  });
  assert.equal(result.decision, 'ALLOW');
  assert.ok(result.matchedClassifiers.includes('XSS_EVENT_HANDLER'));
});

test('allows the fsl-ca3p fuzzer only in its offline browser sandbox', () => {
  const evaluator = new GuardrailEvaluator(ruleset);
  const result = evaluator.evaluate({
    stage: 'fuzzer.run',
    action: { operation: 'browser_fuzz', profile: 'fsl-ca3p', maxCases: 150 },
    trustedContext: trusted({
      testProfile: 'offline_xss_fuzzer',
      fuzzerEnvironment: {
        mode: 'offline-browser', virtualOrigin: 'http://xss-fuzzer.test', realServerTested: false,
      },
      budget: {},
    }),
  });
  assert.equal(result.decision, 'ALLOW');
  assert.equal(result.ruleId, 'PROFILE.offline_xss_fuzzer');
});

test('fails closed for an unknown operator', () => {
  const changed = structuredClone(ruleset);
  changed.hardDenyRules.unshift({ id: 'BROKEN-001', reason: 'broken', when: { operator: 'unknown_operator' } });
  const evaluator = new GuardrailEvaluator(changed);
  const result = evaluator.evaluate({
    stage: 'loop.observe',
    action: { operation: 'http_request', session: 'attacker', method: 'GET', path: '/api/posts' },
    trustedContext: trusted(),
  });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.ruleId, 'EVALUATOR-ERROR');
  assert.match(result.reason, /Unsupported operator/);
});

test('normalizer rejects NUL bytes', () => {
  assert.throws(() => normalizeString('safe\0unsafe', ruleset.normalization), /NUL/);
});

test('allows setup stages before a canary has been created', () => {
  const evaluator = new GuardrailEvaluator(ruleset);
  const context = trusted();
  delete context.boundCanary;
  context.iteration = 0;
  context.budget = { requestCount: 0, mutationCount: 0, deleteCount: 0, xssSubmissionCount: 0 };
  const result = evaluator.evaluate({
    stage: 'setup.attacker_session',
    action: { operation: 'http_request', session: 'attacker', method: 'GET', path: '/api/session' },
    trustedContext: context,
  });
  assert.equal(result.decision, 'ALLOW');
});

test('requires every declared canary field when the current stage uses the canary', () => {
  const evaluator = new GuardrailEvaluator(ruleset);
  const context = trusted({ boundCanary: { resourceId: 4, ownerId: 'bob' } });
  const result = evaluator.evaluate({
    stage: 'loop.act',
    action: {
      operation: 'http_request', session: 'attacker', method: 'DELETE',
      path: '/api/posts/4', query: { authorId: 'bob' },
    },
    trustedContext: context,
  });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.ruleId, 'EVALUATOR-ERROR');
  assert.match(result.reason, /createdByRunId/);
});

test('denies an XSS canary when its trusted title prefix is missing', () => {
  const evaluator = new GuardrailEvaluator(ruleset);
  const runId = 'run-xss-missing-prefix';
  const result = evaluator.evaluate({
    stage: 'xss.inject_canary',
    action: {
      operation: 'http_request', session: 'attacker', method: 'POST', path: '/api/posts',
      body: { title: 'anything', content: '<img src=x onerror=alert(1)>' },
    },
    trustedContext: trusted({
      testProfile: 'stored_xss_canary', runId,
      boundCanary: { createdByRunId: runId },
      budget: { requestCount: 0, mutationCount: 0, deleteCount: 0, xssSubmissionCount: 0 },
    }),
  });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.ruleId, 'PROFILE-CONSTRAINT-FAILED');
});

test('denies unregistered top-level fields instead of ignoring a spoofed policyContext', () => {
  const evaluator = new GuardrailEvaluator(ruleset);
  const result = evaluator.evaluate({
    stage: 'loop.observe',
    policyContext: { targetOrigin: 'https://evil.example' },
    action: { operation: 'http_request', session: 'attacker', method: 'GET', path: '/api/posts' },
    trustedContext: trusted(),
  });
  assert.equal(result.decision, 'DENY');
  assert.equal(result.ruleId, 'EVALUATOR-ERROR');
  assert.match(result.reason, /Unsupported top-level input fields/);
});
