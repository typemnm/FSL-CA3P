'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { buildExternalPacketInput, checkExternalPacketWithSllm } = require('../src/external-packet');

const packet = { method: 'GET', url: 'https://example.org/audit/search?q=marker', body: null };
const trusted = () => ({ runId: 'run-1', probeId: 'probe-1', packetRole: 'single',
  origin: 'https://example.org', pathPrefix: '/audit', allowedPaths: ['/audit/search'],
  maxRequests: 8, requestsUsed: 2, upstreamDecision: 'ALLOW',
  category: 'reflected_input', purpose: 'Inspect a bounded public search response.' });
const settings = fetchFunction => ({ endpoint: 'http://127.0.0.1:11434', model: 'guardrail-local', fetchFunction });
const allowedOutput = () => ({ verdict: 'IN_SCOPE',
  evidence: [{ source: 'query', key: 'q', value: 'marker' }],
  checks: { testPurposeClear: true, noSensitiveAccess: true,
    noDangerousImpact: true, commonCriteriaSatisfied: true },
  reason: 'Bounded public read-only request.', confidence: 0.9 });

test('external profile reuses common criteria without requiring a fixture', async () => {
  let request;
  const result = await checkExternalPacketWithSllm(packet, trusted(), settings(async (_url, init) => {
    request = JSON.parse(init.body);
    return { ok: true, json: async () => ({ message: { content: JSON.stringify(allowedOutput()) },
      prompt_eval_count: 40, eval_count: 20 }) };
  }));
  assert.equal(result.allowExecution, true);
  assert.equal(result.verdict, 'IN_SCOPE');
  assert.equal(result.modelCalled, true);
  assert.equal(request.messages[1].content.includes('fixtureIds'), false);
  assert.match(request.messages[0].content, /민감정보/u);
  assert.equal(JSON.parse(request.messages[1].content).scopeChecks.approvedOrigin, true);
});

test('external profile rejects scope and credential violations before calling the model', async () => {
  let calls = 0;
  const mock = settings(async () => { calls += 1; throw new Error('must not call'); });
  for (const altered of [
    { ...packet, url: 'https://other.example/audit/search?q=marker' },
    { ...packet, url: 'https://example.org/outside?q=marker' },
    { ...packet, url: 'https://example.org/audit/search?token=secret' },
    { ...packet, url: 'https://example.org/audit/search?q=sleep(5)' },
    { ...packet, method: 'POST' },
  ]) {
    const result = await checkExternalPacketWithSllm(altered, trusted(), mock);
    assert.equal(result.allowExecution, false);
    assert.equal(result.modelCalled, false);
  }
  const exhausted = await checkExternalPacketWithSllm(packet,
    { ...trusted(), requestsUsed: 8 }, mock);
  assert.equal(exhausted.allowExecution, false);
  assert.equal(calls, 0);
});

test('an ordinary search word is not a blanket SQL deny', () => {
  const input = buildExternalPacketInput({ ...packet,
    url: 'https://example.org/audit/search?q=update' }, trusted());
  assert.equal(input.scopeChecks.noHighRiskPayload, true);
});

test('external model cannot cite invented request evidence or skip a check', async () => {
  for (const output of [
    { ...allowedOutput(), evidence: [{ source: 'query', key: 'q', value: 'invented' }] },
    { ...allowedOutput(), evidence: [...allowedOutput().evidence,
      { source: 'origin', key: 'origin', value: 'https://example.org' }] },
    { ...allowedOutput(), checks: { ...allowedOutput().checks, noDangerousImpact: null } },
  ]) {
    const result = await checkExternalPacketWithSllm(packet, trusted(), settings(async () =>
      ({ ok: true, json: async () => ({ message: { content: JSON.stringify(output) } }) })));
    assert.equal(result.verdict, 'ERROR');
    assert.equal(result.reasonCode, 'INVALID_SLLM_OUTPUT');
    assert.equal(result.allowExecution, false);
  }
});

test('duplicate query values remain visible and evidence must match one real value', () => {
  const input = buildExternalPacketInput({ ...packet,
    url: 'https://example.org/audit/search?q=first&q=second' }, trusted());
  assert.deepEqual(input.request.query.q, ['first', 'second']);
});

test('external profile rejects a remote sLLM endpoint', async () => {
  const result = await checkExternalPacketWithSllm(packet, trusted(), {
    endpoint: 'https://model.example', model: 'guardrail-local' });
  assert.equal(result.verdict, 'ERROR');
  assert.equal(result.reasonCode, 'INVALID_SLLM_ENDPOINT');
  assert.equal(result.allowExecution, false);
});

test('external profile times out and fails closed', async () => {
  const result = await checkExternalPacketWithSllm(packet, trusted(), {
    ...settings((_url, init) => new Promise((_, reject) => {
      init.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'),
        { name: 'AbortError' })), { once: true });
    })), timeoutMs: 10,
  });
  assert.equal(result.verdict, 'ERROR');
  assert.equal(result.reasonCode, 'SLLM_TIMEOUT');
  assert.equal(result.allowExecution, false);
});
