'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const {
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

function attackCommands(gateway) {
  return gateway.requests.filter(({ envelope }) => envelope.receiver === 'attack-module')
    .map(({ envelope }) => envelope.payload.curl);
}

test('agent completes a bounded canary loop through the real module wire names', async () => {
  const gateway = createScriptedGateway();
  const { report } = await runOnce({ gateway, targetOrigin: TARGET_ORIGIN });
  assert.equal(report.status, 'completed');
  assert.equal(report.finding.status, 'confirmed');
  assert.deepEqual(report.metrics, { requestCount: 4, parserRuns: 2, iterations: 1 });
  assert.deepEqual(report.progress, {
    iterationStarted: 1, actionAttempted: true,
    actionCompleted: true, verificationCompleted: true,
  });
  assert.equal(report.finding.evidenceRefs.length, 6);
  assert.equal(report.referenceContext.casperDb.category, 'historical_xss_only');
  assert.equal(report.referenceContext.pentestDb.category, 'stored_xss_reference_only');
  assert.equal(report.guardrail.decisions.length, 4);
  assert.ok(report.guardrail.decisions.every(decision => decision.decision === 'ALLOW'));
  assert.equal(gateway.events.length, 10);
  assert.equal(gateway.finalReport.runId, report.runId);

  const receivers = gateway.requests.map(({ envelope }) => envelope.receiver);
  assert.deepEqual(receivers.filter(receiver => receiver !== 'pentest-db'), [
    'attack-module', 'attack-module', 'attack-module',
    'xss-parser', 'casper-db', 'attack-module', 'xss-parser',
  ]);
  assert.ok(!receivers.includes('web_explorer'));
  assert.ok(!receivers.includes('vulnerability_db'));
  assert.deepEqual(attackCommands(gateway).map(command => command.method), [
    'GET', 'POST', 'POST', 'DELETE',
  ]);
  const phases = gateway.requests.filter(({ envelope }) => envelope.receiver === 'xss-parser')
    .map(({ envelope }) => envelope.payload.phase);
  assert.deepEqual(phases, ['before', 'after']);
  assert.ok(gateway.requests.some(({ envelope }) => envelope.receiver === 'pentest-db'
    && envelope.payload.operation === 'get_attack_info'));
  assert.ok(gateway.requests.every(({ raw, envelope }) => JSON.stringify(envelope) === raw));
  gateway.rawResponses.forEach(raw => JSON.parse(raw));
});

test('agent source no longer imports or implements Web Explorer and ActionPolicy', async () => {
  const directory = path.join(__dirname, '..', 'src');
  const files = (await fs.readdir(directory, { withFileTypes: true }))
    .filter(entry => entry.isFile()).map(entry => entry.name).sort();
  assert.deepEqual(files, [
    'curl-command.js', 'deepseek-client.js', 'deepseek-config.js',
    'deepseek-reasoning-engine.js', 'index.js', 'orchestrator.js',
    'protocol.js', 'reasoning-engine.js', 'xss-canary.js',
  ]);
  const source = (await Promise.all(files.map(file => fs.readFile(path.join(directory, file), 'utf8')))).join('\n');
  assert.doesNotMatch(source, /action-policy|ActionPolicy|web_explorer|vulnerability_db/);
  assert.doesNotMatch(source, /node:(?:child_process|http|https|net|tls)/);
});

test('parser ID and title must both agree with the trusted creation response', async () => {
  const gateway = createScriptedGateway({
    beforePosts: canary => [{ ...canary, title: 'different visible title' }],
  });
  await assert.rejects(
    () => runOnce({ gateway, targetOrigin: TARGET_ORIGIN }),
    /exact canary ID and title/,
  );
  assert.equal(attackCommands(gateway).filter(command => command.method === 'DELETE').length, 0);
  assert.equal(gateway.requests.some(({ envelope }) => envelope.receiver === 'casper-db'), false);
  assert.equal(gateway.finalReport.progress.actionAttempted, false);
});

test('historical XSS assessments remain separate from the BOLA canary plan', async () => {
  const gateway = createScriptedGateway({
    historyAssessments: [{ decision: 'retest_candidate', matches: [{ vulnerability_type: 'stored_xss' }] }],
  });
  const { report } = await runOnce({ gateway, targetOrigin: TARGET_ORIGIN });
  const thought = gateway.events.find(event => event.stage === 'loop.think');
  assert.equal(report.referenceContext.casperDb.assessments, 1);
  assert.equal(thought.request.payload.candidates[0].knowledgeId, 'local-canary-cross-user-delete');
  assert.equal(thought.request.payload.candidates[0].provenance.source, 'agent_bound_local_canary');
  assert.equal(thought.request.payload.candidates[0].cwe, 'CWE-639');
  assert.equal(report.finding.cwe, 'CWE-639');
});

test('failed historical module response stops before DELETE with external provenance', async () => {
  const gateway = createScriptedGateway({ failOn: 'history_module_error' });
  await assert.rejects(() => runOnce({ gateway, targetOrigin: TARGET_ORIGIN }), error => {
    assert.equal(error.code, 'EXTERNAL_FAILURE');
    assert.equal(error.source, 'external_module');
    assert.equal(error.externalModule, 'casper-db');
    assert.equal(error.failureReport.progress.actionAttempted, false);
    return true;
  });
  assert.equal(attackCommands(gateway).filter(command => command.method === 'DELETE').length, 0);
});

test('a DENY result from guardrail is preserved as JSON and prevents verification', async () => {
  const gateway = createScriptedGateway({ failOn: 'guardrail_denied' });
  await assert.rejects(() => runOnce({ gateway, targetOrigin: TARGET_ORIGIN }), error => {
    assert.equal(error.code, 'GUARDRAIL_DENIED');
    assert.equal(error.source, 'external_module');
    assert.deepEqual(error.failureReport.progress, {
      iterationStarted: 1, actionAttempted: true,
      actionCompleted: false, verificationCompleted: false,
    });
    assert.equal(error.failureReport.guardrail.decisions.at(-1).decision, 'DENY');
    return true;
  });
  const action = gateway.events.find(event => event.stage === 'loop.act');
  assert.equal(action.response.payload.guardrail.decision, 'DENY');
  assert.equal(gateway.events.some(event => event.stage === 'loop.verify'), false);
});

test('parser truncation after DELETE cannot confirm a vulnerability', async () => {
  const gateway = createScriptedGateway({ failOn: 'parser_incomplete' });
  await assert.rejects(() => runOnce({ gateway, targetOrigin: TARGET_ORIGIN }), error => {
    assert.equal(error.code, 'XSS_PARSER_INCOMPLETE');
    assert.equal(error.failureReport.progress.actionCompleted, true);
    assert.equal(error.failureReport.progress.verificationCompleted, false);
    return true;
  });
  assert.equal(attackCommands(gateway).filter(command => command.method === 'DELETE').length, 1);
  assert.equal(gateway.events.some(event => event.stage === 'loop.reflect'), false);
});

test('an unchanged browser observation yields a not_confirmed finding', async () => {
  const gateway = createScriptedGateway({ afterPosts: canary => [canary] });
  const { report } = await runOnce({ gateway, targetOrigin: TARGET_ORIGIN });
  assert.equal(report.finding.status, 'not_confirmed');
  assert.equal(report.finding.checks.absentAfter, false);
});

test('reasoning engine cannot send a DELETE for a different resource or curl URL', async () => {
  const local = new RuleReasoningEngine();
  for (const mutation of [
    plan => ({ ...plan, action: { ...plan.action, path: '/api/posts/999' } }),
    plan => ({ ...plan, curl: { method: 'DELETE', url: `${TARGET_ORIGIN}/api/posts/999?authorId=bob` } }),
  ]) {
    const gateway = createScriptedGateway();
    await assert.rejects(() => runOnce({
      gateway, targetOrigin: TARGET_ORIGIN,
      reasoningEngine: {
        plan: input => mutation(local.plan(input)),
        reflect: input => local.reflect(input),
      },
    }));
    assert.equal(attackCommands(gateway).filter(command => command.method === 'DELETE').length, 0);
    assert.equal(gateway.finalReport.progress.actionAttempted, false);
  }
});

test('verification transport failure never retries the completed DELETE', async () => {
  const gateway = createScriptedGateway({ failOn: 'verify_transport' });
  await assert.rejects(() => runOnce({ gateway, targetOrigin: TARGET_ORIGIN }), error => {
    assert.match(error.message, /verification transport failure/);
    assert.equal(error.failureReport.progress.actionCompleted, true);
    assert.equal(error.failureReport.progress.verificationCompleted, false);
    return true;
  });
  assert.equal(attackCommands(gateway).filter(command => command.method === 'DELETE').length, 1);
});

test('invalid target and unsupported iteration count stop before any module contact', async () => {
  let calls = 0;
  const gateway = { exchange: async () => { calls += 1; } };
  await assert.rejects(() => runOnce({ gateway, targetOrigin: 'https://example.org' }), /local HTTP origin/);
  await assert.rejects(() => runOnce({ gateway, targetOrigin: TARGET_ORIGIN, maxIterations: 2 }), /equal 1/);
  assert.equal(calls, 0);
});

test('protocol rejects old receiver names and forged attack evidence', async () => {
  assert.throws(() => createEnvelope({
    runId: 'run-old', iteration: 0, sender: 'agent', receiver: 'web_explorer', type: 'module.request',
  }), /known module names/);
  const request = createEnvelope({
    runId: 'run-forged-attack', iteration: 1,
    sender: 'agent', receiver: 'attack-module', type: 'module.request',
    payload: { operation: 'execute_curl', session: 'attacker',
      curl: { method: 'DELETE', url: `${TARGET_ORIGIN}/api/posts/4?authorId=bob` } },
  });
  const response = await invokeJson({ exchange: async raw => {
    const inbound = parseEnvelope(raw, 'attack-module');
    return JSON.stringify(replyTo(inbound, 'attack-module', 'attack.result', {
      operation: 'execute_curl', success: true,
      request: { method: 'DELETE', url: inbound.payload.curl.url, session: 'attacker' },
      response: { status: 200, ok: true, bodyJson: { deletedId: 4 } },
      error: null, evidenceId: 'evidence-without-guardrail',
    }));
  } }, request);
  assert.equal(response.type, 'module.error');
  assert.equal(response.payload.error.code, 'PROTOCOL_FAILURE');
  assert.match(response.payload.error.message, /curl result contract/);
});

test('protocol rejects parser reports from a different target origin', async () => {
  const request = createEnvelope({
    runId: 'run-parser-origin', iteration: 1,
    sender: 'agent', receiver: 'xss-parser', type: 'module.request',
    payload: { operation: 'parse_site', origin: TARGET_ORIGIN, phase: 'before' },
  });
  const response = await invokeJson({ exchange: async raw => {
    const inbound = parseEnvelope(raw, 'xss-parser');
    return JSON.stringify(replyTo(inbound, 'xss-parser', 'parser.result', {
      operation: 'parse_site', phase: 'before',
      report: { schemaVersion: '3.4', startUrl: 'http://127.0.0.1:9000/', pages: [] },
      observedPosts: [], errors: [], truncated: false, evidenceId: 'parser-evidence',
    }));
  } }, request);
  assert.equal(response.payload.error.code, 'PROTOCOL_FAILURE');
  assert.match(response.payload.error.message, /site observation contract/);
});

test('gateway timeouts and oversized outbound JSON are correlated failures', async () => {
  const request = createEnvelope({
    runId: 'run-transport', iteration: 1,
    sender: 'agent', receiver: 'xss-parser', type: 'module.request',
    payload: { operation: 'parse_site', origin: TARGET_ORIGIN, phase: 'before' },
  });
  const timedOut = await invokeJson({ exchange: async () => new Promise(() => {}) }, request, { timeoutMs: 5 });
  assert.equal(timedOut.payload.error.code, 'TRANSPORT_FAILURE');
  assert.match(timedOut.payload.error.message, /timed out/);
  assert.throws(() => assertModuleSuccess(timedOut), /timed out/);
  const oversized = createEnvelope({
    runId: 'run-oversized', iteration: 1,
    sender: 'agent', receiver: 'casper-db', type: 'module.request',
    payload: { parserReport: 'x'.repeat(MAX_MESSAGE_BYTES) },
  });
  const tooLarge = await invokeJson({ exchange: async () => { throw new Error('must not dispatch'); } }, oversized);
  assert.equal(tooLarge.payload.error.code, 'PROTOCOL_FAILURE');
});
