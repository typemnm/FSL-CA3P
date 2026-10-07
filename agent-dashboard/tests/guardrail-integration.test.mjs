import assert from 'node:assert/strict';
import test from 'node:test';
import xssCanary from '../../agent/src/xss-canary.js';
import { createLocalGuardrail, GuardrailDeniedError } from '../integrations/guardrail.mjs';

const { storedXssCanaryContent } = xssCanary;

const origin = 'http://127.0.0.1:41337';
const runId = 'run-guardrail-test';

function newGuardrail() {
  return createLocalGuardrail({ origin, runId });
}

function read(path) {
  return { operation: 'http_request', session: 'attacker', method: 'GET', path };
}

function curl(session, method, path, body) {
  const command = { method, url: `${origin}${path}` };
  if (body !== undefined) command.body = body;
  return { operation: 'execute_curl', session, curl: command };
}

test('the real guardrail evaluator authorizes each local request and reserves mutation budget', () => {
  const guardrail = newGuardrail();
  assert.equal(guardrail.rulesetId, 'fsl-ca3p-vul-web-1-guardrail');
  assert.equal(guardrail.authorize('setup.attacker_session', read('/api/session')).decision, 'ALLOW');
  assert.equal(guardrail.authorize('setup.fixture_session',
    curl('fixture', 'POST', '/api/session', { userId: 'bob' })).decision, 'ALLOW');
  assert.equal(guardrail.authorize('setup.canary_post', curl('fixture', 'POST', '/api/posts', {
    title: `agent-canary-${runId}`,
    content: 'Authorization-test canary requested by the agent.',
  })).decision, 'ALLOW');
  guardrail.bindCanary({ resourceId: 4, ownerId: 'bob', createdByRunId: runId });
  assert.equal(guardrail.authorize('loop.observe', read('/api/posts')).decision, 'ALLOW');
  const result = guardrail.authorize('loop.act', curl('attacker', 'DELETE', '/api/posts/4?authorId=bob'));
  assert.equal(result.decision, 'ALLOW');
  assert.equal(result.ruleId, 'PROFILE.agent_cross_user_delete_canary.loop.act');
  assert.equal(guardrail.authorize('loop.verify', read('/api/posts')).decision, 'ALLOW');
  assert.deepEqual(guardrail.metrics(), {
    requestCount: 6, mutationCount: 2, deleteCount: 1,
    xssSubmissionCount: 0, maxRequests: 8, maxIterations: 1,
  });
  assert.equal(guardrail.audit().length, 6);
});

test('guardrail blocks an unbound or different DELETE canary before curl', () => {
  const guardrail = newGuardrail();
  assert.throws(() => guardrail.authorize('loop.act',
    curl('attacker', 'DELETE', '/api/posts/4?authorId=bob')), error => (
    error instanceof GuardrailDeniedError && error.guardrailDecision.decision === 'DENY'
  ));
  guardrail.bindCanary({ resourceId: 4, ownerId: 'bob', createdByRunId: runId });
  assert.throws(() => guardrail.authorize('loop.act',
    curl('attacker', 'DELETE', '/api/posts/5?authorId=bob')), error => (
    error instanceof GuardrailDeniedError && error.guardrailDecision.ruleId === 'PROFILE-CONSTRAINT-FAILED'
  ));
  assert.equal(guardrail.metrics().requestCount, 0);
});

test('guardrail rejects external destinations, duplicate parameters and extra curl fields', () => {
  const guardrail = newGuardrail();
  guardrail.bindCanary({ resourceId: 4, ownerId: 'bob', createdByRunId: runId });
  assert.throws(() => guardrail.authorize('loop.act', {
    ...curl('attacker', 'DELETE', '/api/posts/4?authorId=bob'),
    curl: { method: 'DELETE', url: 'https://example.com/api/posts/4?authorId=bob' },
  }), /private lab origin/);
  assert.throws(() => guardrail.authorize('loop.act',
    curl('attacker', 'DELETE', '/api/posts/4?authorId=bob&authorId=admin')), /duplicate/);
  assert.throws(() => guardrail.authorize('loop.act', {
    operation: 'execute_curl', session: 'attacker',
    curl: { method: 'DELETE', url: `${origin}/api/posts/4?authorId=bob`, headers: { Cookie: 'secret' } },
  }), /structured/);
  assert.equal(guardrail.metrics().requestCount, 0);
});

test('XSS content is denied in the cross-user delete profile', () => {
  const guardrail = newGuardrail();
  assert.throws(() => guardrail.authorize('setup.canary_post', curl('fixture', 'POST', '/api/posts', {
    title: `agent-canary-${runId}`, content: '<img src=x onerror=alert(1)>',
  })), error => (
    error instanceof GuardrailDeniedError
      && error.guardrailDecision.ruleId === 'XSS-OUT-OF-PROFILE'
  ));
  assert.equal(guardrail.metrics().requestCount, 0);
});

test('a permitted DELETE consumes its only mutation slot even without an HTTP response', () => {
  const guardrail = newGuardrail();
  guardrail.bindCanary({ resourceId: 4, ownerId: 'bob', createdByRunId: runId });
  guardrail.authorize('loop.act', curl('attacker', 'DELETE', '/api/posts/4?authorId=bob'));
  assert.throws(() => guardrail.authorize('loop.act',
    curl('attacker', 'DELETE', '/api/posts/4?authorId=bob')), error => (
    error instanceof GuardrailDeniedError && error.guardrailDecision.ruleId === 'PROFILE-CONSTRAINT-FAILED'
  ));
  assert.equal(guardrail.metrics().deleteCount, 1);
});

test('guardrail refuses nonlocal origins and cannot rebind the run canary', () => {
  assert.throws(() => createLocalGuardrail({ origin: 'https://example.com', runId }), /private 127\.0\.0\.1/);
  const guardrail = newGuardrail();
  const boundCanary = { resourceId: 4, ownerId: 'bob', createdByRunId: runId };
  guardrail.authorize('loop.observe', read('/api/posts'), { boundCanary });
  assert.throws(() => guardrail.authorize('loop.verify', read('/api/posts'), {
    boundCanary: { ...boundCanary, resourceId: 5 },
  }), /cannot change/);
});

test('stored-XSS profile permits one fixed local canary submission and reserves its budget', () => {
  const guardrail = createLocalGuardrail({ origin, runId, profile: 'stored_xss_canary' });
  const marker = '0123456789abcdef0123456789abcdef';
  const canary = curl('attacker', 'POST', '/api/posts', {
    title: `agent-xss-canary-${runId}-${marker}`,
    content: storedXssCanaryContent(marker),
  });
  assert.equal(guardrail.authorizeRead('xss.setup_session', read('/api/session')).decision, 'ALLOW');
  assert.equal(guardrail.authorizeRead('xss.observe', read('/api/posts')).decision, 'ALLOW');
  const decision = guardrail.authorizeCurl('xss.inject_canary', canary);
  assert.equal(decision.ruleId, 'PROFILE.stored_xss_canary.xss.inject_canary');
  guardrail.bindCanary({ resourceId: 4, ownerId: 'alice', createdByRunId: runId });
  assert.equal(guardrail.authorizeRead('xss.observe', read('/api/posts')).decision, 'ALLOW');
  assert.deepEqual(guardrail.metrics(), {
    requestCount: 4, mutationCount: 1, deleteCount: 0,
    xssSubmissionCount: 1, maxRequests: 6, maxIterations: 1,
  });
  assert.throws(() => guardrail.authorizeCurl('xss.inject_canary', canary), error => (
    error instanceof GuardrailDeniedError && error.guardrailDecision.decision === 'DENY'
  ));
  assert.equal(guardrail.metrics().mutationCount, 1);
});

test('stored-XSS profile denies mismatched probe content and untrusted destinations', () => {
  const guardrail = createLocalGuardrail({ origin, runId, profile: 'stored_xss_canary' });
  const marker = '0123456789abcdef0123456789abcdef';
  const title = `agent-xss-canary-${runId}-${marker}`;
  assert.throws(() => guardrail.authorizeCurl('xss.inject_canary', curl('attacker', 'POST', '/api/posts', {
    title, content: '<img src=x onerror=fetch("https://example.com")>',
  })), error => error instanceof GuardrailDeniedError && error.guardrailDecision.decision === 'DENY');
  assert.throws(() => guardrail.authorizeCurl('xss.inject_canary', {
    operation: 'execute_curl', session: 'attacker',
    curl: { method: 'POST', url: 'http://127.0.0.1:1/api/posts', body: {
      title, content: storedXssCanaryContent(marker),
    } },
  }), /private lab origin/);
  assert.equal(guardrail.metrics().requestCount, 0);
});
