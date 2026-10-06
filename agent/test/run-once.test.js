'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const {
  ActionPolicy,
  MAX_MESSAGE_BYTES,
  RuleReasoningEngine,
  assertModuleSuccess,
  createEnvelope,
  invokeJson,
  parseEnvelope,
  replyTo,
  runOnce,
} = require('../src');
const { createScriptedGateway } = require('../test-support/scripted-gateway');

const TARGET_ORIGIN = 'http://127.0.0.1:3000';

async function exists(file) {
  try {
    await fs.stat(file);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

async function listRelativeFiles(directory, root = directory) {
  const files = [];
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...await listRelativeFiles(absolute, root));
    } else if (entry.isFile()) {
      files.push(path.relative(root, absolute).split(path.sep).join('/'));
    }
  }
  return files.sort();
}

test('agent completes exactly one loop through serialized external JSON contracts', async () => {
  const gateway = createScriptedGateway();
  const result = await runOnce({ gateway, targetOrigin: TARGET_ORIGIN });

  assert.equal(result.report.status, 'completed');
  assert.equal(result.report.iterations, 1);
  assert.equal(result.report.finding.status, 'confirmed');
  assert.deepEqual(result.report.progress, {
    iterationStarted: 1,
    actionAttempted: true,
    actionCompleted: true,
    verificationCompleted: true,
  });
  assert.equal(result.report.metrics.requestCount, 6);
  assert.equal(result.report.finding.evidenceRefs.length, 6);
  assert.equal(gateway.events.length, 9);
  assert.equal(gateway.finalReport.runId, result.report.runId);

  const externalReceivers = new Set(['web_explorer', 'vulnerability_db', 'pentest_db']);
  gateway.requests.forEach(({ raw, envelope }) => {
    assert.equal(typeof raw, 'string');
    assert.deepEqual(JSON.parse(raw), envelope);
    assert.ok(externalReceivers.has(envelope.receiver));
  });
  gateway.rawResponses.forEach(raw => {
    assert.equal(typeof raw, 'string');
    JSON.parse(raw);
  });

  const deleteRequests = gateway.requests.filter(({ envelope }) => (
    envelope.receiver === 'web_explorer' && envelope.payload.method === 'DELETE'
  ));
  assert.equal(deleteRequests.length, 1, 'The agent must emit exactly one mutating action');
  assert.equal(
    gateway.requests.some(({ envelope }) => envelope.receiver === 'rule_reasoner'),
    false,
    'Reasoning is internal to the agent, not an external module',
  );
});

test('production contains only agent core and external contracts, not module implementations', async () => {
  const root = path.resolve(__dirname, '..');
  const sourceDir = path.join(root, 'src');
  const productionFiles = await listRelativeFiles(sourceDir);
  assert.deepEqual(productionFiles, [
    'action-policy.js',
    'index.js',
    'orchestrator.js',
    'protocol.js',
    'reasoning-engine.js',
  ]);

  const forbidden = [
    'src/modules/web-explorer.js',
    'src/modules/vulnerability-db.js',
    'src/modules/pentest-db.js',
    'src/modules/scope-guard.js',
    'src/target-harness.js',
    'knowledge/vulnerabilities.json',
  ];
  for (const relative of forbidden) {
    assert.equal(await exists(path.join(root, relative)), false, `${relative} must remain external`);
  }

  const sourceText = (await Promise.all(productionFiles.map(file => (
    fs.readFile(path.join(sourceDir, file), 'utf8')
  )))).join('\n');
  assert.doesNotMatch(sourceText, /node:(?:fs|child_process|http|https|net|tls)/);
  assert.doesNotMatch(sourceText, /\bfetch\s*\(/);
  assert.doesNotMatch(sourceText, /class\s+(?:WebExplorer|VulnerabilityDb|PentestDb|ScopeGuard)/);
  assert.doesNotMatch(sourceText, /startIsolatedLab|withIsolatedLab/);
  assert.doesNotMatch(sourceText, /test-support/);
});

test('gateway distinguishes transport failures from external module errors', async () => {
  const request = createEnvelope({
    runId: 'run-gateway-errors',
    iteration: 1,
    sender: 'agent',
    receiver: 'vulnerability_db',
    type: 'module.request',
    payload: { operation: 'match' },
  });

  const transportFailure = await invokeJson({
    exchange: async () => { throw new Error('offline'); },
  }, request);
  assert.equal(transportFailure.type, 'module.error');
  assert.equal(transportFailure.payload.error.code, 'TRANSPORT_FAILURE');
  assert.equal(transportFailure.payload.error.source, 'agent_gateway');

  const externalFailure = await invokeJson({
    exchange: async raw => {
      const inbound = parseEnvelope(raw, 'vulnerability_db');
      return JSON.stringify(replyTo(inbound, 'vulnerability_db', 'module.error', {
        error: { code: 'EXTERNAL_FAILURE', message: 'external rejection', source: 'external_module' },
      }));
    },
  }, request);
  assert.equal(externalFailure.payload.error.code, 'EXTERNAL_FAILURE');
  assert.equal(externalFailure.payload.error.source, 'external_module');
});

test('external modules cannot impersonate agent gateway error provenance', async () => {
  const request = createEnvelope({
    runId: 'run-error-provenance',
    iteration: 1,
    sender: 'agent',
    receiver: 'vulnerability_db',
    type: 'module.request',
    payload: { operation: 'match' },
  });
  const response = await invokeJson({
    exchange: async raw => {
      const inbound = parseEnvelope(raw, 'vulnerability_db');
      return JSON.stringify(replyTo(inbound, 'vulnerability_db', 'module.error', {
        error: {
          code: 'TRANSPORT_FAILURE',
          message: 'spoofed gateway failure',
          source: 'agent_gateway',
        },
      }));
    },
  }, request);

  assert.throws(() => assertModuleSuccess(response), error => {
    assert.equal(error.source, 'external_module');
    assert.equal(error.externalModule, 'vulnerability_db');
    assert.equal(error.code, 'EXTERNAL_MODULE_FAILURE');
    assert.equal(error.reportedCode, 'TRANSPORT_FAILURE');
    return true;
  });
});

test('gateway enforces module-specific response types and evidence payloads', async () => {
  const storageRequest = createEnvelope({
    runId: 'run-wrong-response-type',
    iteration: 1,
    sender: 'agent',
    receiver: 'pentest_db',
    type: 'storage.request',
    payload: { operation: 'append', event: {} },
  });
  const wrongType = await invokeJson({
    exchange: async raw => {
      const inbound = parseEnvelope(raw, 'pentest_db');
      return JSON.stringify(replyTo(inbound, 'pentest_db', 'web.result', {}));
    },
  }, storageRequest);
  assert.equal(wrongType.payload.error.code, 'PROTOCOL_FAILURE');
  assert.match(wrongType.payload.error.message, /Expected storage\.appended/);

  const webRequest = createEnvelope({
    runId: 'run-missing-evidence',
    iteration: 1,
    sender: 'agent',
    receiver: 'web_explorer',
    type: 'module.request',
    payload: { operation: 'http_request' },
  });
  const missingEvidence = await invokeJson({
    exchange: async raw => {
      const inbound = parseEnvelope(raw, 'web_explorer');
      return JSON.stringify(replyTo(inbound, 'web_explorer', 'web.result', {
        operation: 'http_request',
        response: { status: 200, ok: true, bodyJson: {} },
      }));
    },
  }, webRequest);
  assert.equal(missingEvidence.payload.error.code, 'PROTOCOL_FAILURE');
  assert.match(missingEvidence.payload.error.message, /HTTP evidence contract/);

  const knowledgeRequest = createEnvelope({
    runId: 'run-invalid-candidate',
    iteration: 1,
    sender: 'agent',
    receiver: 'vulnerability_db',
    type: 'module.request',
    payload: { operation: 'match' },
  });
  const invalidCandidate = await invokeJson({
    exchange: async raw => {
      const inbound = parseEnvelope(raw, 'vulnerability_db');
      return JSON.stringify(replyTo(inbound, 'vulnerability_db', 'knowledge.result', {
        candidates: [{ resource: { id: 4, ownerId: 'bob' } }],
      }));
    },
  }, knowledgeRequest);
  assert.equal(invalidCandidate.payload.error.code, 'PROTOCOL_FAILURE');
  assert.match(invalidCandidate.payload.error.message, /valid candidate contracts/);
});

test('gateway calls time out instead of blocking the agent indefinitely', async () => {
  const request = createEnvelope({
    runId: 'run-gateway-timeout',
    iteration: 0,
    sender: 'agent',
    receiver: 'web_explorer',
    type: 'module.request',
    payload: { operation: 'http_request' },
  });
  const response = await invokeJson({
    exchange: async () => new Promise(() => {}),
  }, request, { timeoutMs: 5 });

  assert.equal(response.payload.error.code, 'TRANSPORT_FAILURE');
  assert.match(response.payload.error.message, /timed out/);

  const nonErrorRejection = await invokeJson({
    exchange: async () => Promise.reject('string rejection'),
  }, request);
  assert.equal(nonErrorRejection.payload.error.code, 'TRANSPORT_FAILURE');
  assert.equal(nonErrorRejection.payload.error.message, 'string rejection');
});

test('invalid or non-serialized module responses become correlated protocol errors', async () => {
  const request = createEnvelope({
    runId: 'run-invalid-response',
    iteration: 0,
    sender: 'agent',
    receiver: 'web_explorer',
    type: 'module.request',
    payload: { operation: 'http_request' },
  });
  const response = await invokeJson({ exchange: async () => ({ not: 'serialized' }) }, request);
  assert.equal(response.type, 'module.error');
  assert.equal(response.sender, 'agent');
  assert.equal(response.receiver, 'agent');
  assert.equal(response.correlationId, request.messageId);
  assert.equal(response.payload.error.code, 'PROTOCOL_FAILURE');
  assert.throws(() => parseEnvelope({}, 'web_explorer'), /serialized JSON only/);
});

test('outbound messages over the JSON size limit are rejected before gateway dispatch', async () => {
  let calls = 0;
  const request = createEnvelope({
    runId: 'run-oversized-request',
    iteration: 0,
    sender: 'agent',
    receiver: 'web_explorer',
    type: 'module.request',
    payload: { oversized: 'x'.repeat(MAX_MESSAGE_BYTES) },
  });
  const response = await invokeJson({
    exchange: async () => { calls += 1; },
  }, request);

  assert.equal(calls, 0);
  assert.equal(response.type, 'module.error');
  assert.equal(response.sender, 'agent');
  assert.equal(response.payload.error.code, 'PROTOCOL_FAILURE');
  assert.match(response.payload.error.message, /exceeds 1 MB/);
});

test('a mismatched external response correlation becomes an agent protocol error', async () => {
  const request = createEnvelope({
    runId: 'run-wrong-correlation',
    iteration: 1,
    sender: 'agent',
    receiver: 'web_explorer',
    type: 'module.request',
    payload: { operation: 'http_request' },
  });
  const response = await invokeJson({
    exchange: async raw => {
      const inbound = parseEnvelope(raw, 'web_explorer');
      const outbound = replyTo(inbound, 'web_explorer', 'web.result', {});
      outbound.correlationId = 'wrong-correlation-id';
      return JSON.stringify(outbound);
    },
  }, request);

  assert.equal(response.type, 'module.error');
  assert.equal(response.sender, 'agent');
  assert.equal(response.payload.error.code, 'PROTOCOL_FAILURE');
  assert.match(response.payload.error.message, /correlation mismatch/);
});

test('orchestrator refuses a second iteration before contacting the gateway', async () => {
  let calls = 0;
  await assert.rejects(
    () => runOnce({
      gateway: { exchange: async () => { calls += 1; } },
      targetOrigin: TARGET_ORIGIN,
      maxIterations: 2,
    }),
    /maxIterations to equal 1/,
  );
  assert.equal(calls, 0);
});

test('failure after the action preserves progress and never retries DELETE', async () => {
  const gateway = createScriptedGateway({ failOn: 'verify_transport' });
  let caught;
  try {
    await runOnce({ gateway, targetOrigin: TARGET_ORIGIN });
  } catch (error) {
    caught = error;
  }
  assert.ok(caught);
  assert.match(caught.message, /verification transport failure/);
  assert.equal(caught.failureReport.iterations, 1);
  assert.deepEqual(caught.failureReport.progress, {
    iterationStarted: 1,
    actionAttempted: true,
    actionCompleted: true,
    verificationCompleted: false,
  });
  assert.deepEqual(gateway.finalReport.progress, caught.failureReport.progress);
  const deletes = gateway.requests.filter(({ envelope }) => envelope.payload.method === 'DELETE');
  assert.equal(deletes.length, 1);
});

test('external module.error is propagated with module provenance', async () => {
  const gateway = createScriptedGateway({ failOn: 'knowledge_module_error' });
  await assert.rejects(
    () => runOnce({ gateway, targetOrigin: TARGET_ORIGIN }),
    error => {
      assert.equal(error.code, 'EXTERNAL_FAILURE');
      assert.equal(error.source, 'external_module');
      assert.equal(error.failureReport.progress.actionAttempted, false);
      return true;
    },
  );
});

test('internal action policy blocks out-of-scope actions before gateway dispatch', () => {
  const policy = new ActionPolicy({ targetOrigin: TARGET_ORIGIN, maxRequests: 2 });
  assert.throws(() => policy.authorize('loop.observe', {
    operation: 'http_request',
    method: 'GET',
    path: 'http://127.0.0.1:3001/api/posts',
    session: 'attacker',
  }), /outside the exact allowed scope/);
  assert.throws(() => policy.authorize('loop.act', {
    operation: 'http_request',
    method: 'DELETE',
    path: '/api/posts/4',
    session: 'attacker',
    query: { authorId: 'bob' },
  }), /has not been bound/);
  policy.bindDeleteTarget({ resourceId: 4, ownerId: 'bob' });
  assert.throws(() => policy.authorize('loop.act', {
    operation: 'http_request',
    method: 'DELETE',
    path: '/api/posts/999',
    session: 'attacker',
    query: { authorId: 'bob' },
  }), /does not match the bound canary/);
  assert.throws(() => policy.authorize('loop.act', {
    operation: 'http_request',
    method: 'POST',
    path: '/api/posts',
    session: 'fixture',
    body: { title: 'injected', content: 'unexpected mutation' },
  }), /does not match the allowed action for loop\.act/);
  assert.equal(policy.metrics().requestCount, 0);
});

test('reasoning engine rejects an external candidate that swaps the observed canary target', () => {
  const engine = new RuleReasoningEngine();
  const plan = engine.plan({
    expectedTarget: { resourceId: 4, ownerId: 'bob', attackerId: 'alice' },
    candidates: [{
      attackerId: 'alice',
      resource: { id: 999, ownerId: 'bob' },
      actionTemplate: { method: 'DELETE', pathTemplate: '/api/posts/{resourceId}' },
    }],
  });

  assert.equal(plan.state, 'stop');
  assert.equal(plan.action, null);
  assert.match(plan.decisionSummary, /일치하지 않아/);
});
