'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const {
  MAX_MESSAGE_BYTES,
  assertModuleSuccess,
  createEnvelope,
  invokeJson,
  parseEnvelope,
  replyTo,
} = require('../src');

const TARGET_ORIGIN = 'http://127.0.0.1:3000';

test('agent source no longer imports or implements Web Explorer and ActionPolicy', async () => {
  const directory = path.join(__dirname, '..', 'src');
  const files = (await fs.readdir(directory, { withFileTypes: true }))
    .filter(entry => entry.isFile()).map(entry => entry.name).sort();
  assert.deepEqual(files, [
    'deepseek-client.js', 'deepseek-config.js',
    'general-assessment.js', 'general-model-planner.js',
    'index.js', 'model-definitions.js',
    'protocol.js', 'xss-canary.js',
  ]);
  const source = (await Promise.all(files.map(file => fs.readFile(path.join(directory, file), 'utf8')))).join('\n');
  assert.doesNotMatch(source, /action-policy|ActionPolicy|web_explorer|vulnerability_db/);
  assert.doesNotMatch(source, /node:(?:child_process|http|https|net|tls)/);
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

test('gateway timeouts and oversized outbound JSON are correlated failures', async () => {
  const request = createEnvelope({
    runId: 'run-transport', iteration: 1,
    sender: 'agent', receiver: 'casper-db', type: 'module.request',
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
