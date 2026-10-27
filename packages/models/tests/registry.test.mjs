import test from 'node:test';
import assert from 'node:assert/strict';
import { createModelReasoning, listModels } from '../registry.mjs';

test('model registry exposes a real rule baseline without credentials', () => {
  const models = listModels({ env: {}, envFile: false });
  assert.equal(models[0].available, true);
  assert.ok(models.slice(1).every(row => !row.available));
  assert.equal(typeof createModelReasoning('rule-baseline').reflect, 'function');
  assert.throws(() => createModelReasoning('unregistered'), /등록되지/);
});

test('registry collects prompt and usage metadata without credentials', async () => {
  const calls = [];
  const key = 'private-test-key';
  const engine = createModelReasoning('deepseek-flash', { envFile: false, env: { DEEPSEEK_API_KEY: key },
    onModelCall: value => calls.push(value), fetchImpl: async () => new Response(JSON.stringify({
      choices: [{ finish_reason: 'stop', message: { content: '{"state":"stop","candidateId":null,"actionCatalogId":null,"curl":null}' } }],
      usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 },
    }), { status: 200 }) });
  await engine.client.completeJson({ systemPrompt: 'Return JSON according to policy.', userPayload: { input: 'sample' } });
  assert.equal(calls[0].usage.total_tokens, 30);
  assert.equal(calls[0].promptDigest.length, 64);
  assert.equal(calls[0].reportedModel, null);
  assert.ok(!JSON.stringify(calls).includes(key));
});

test('an aborted run ends the model request immediately without a retry or network call', async () => {
  const controller = new AbortController(); controller.abort();
  let requests = 0; const calls = [];
  const engine = createModelReasoning('deepseek-flash', { envFile: false,
    env: { DEEPSEEK_API_KEY: 'private-test-key' }, signal: controller.signal,
    fetchImpl: async () => { requests += 1; throw new Error('network must stay unused'); },
    onModelCall: value => calls.push(value),
  });
  await assert.rejects(() => engine.client.completeJson({ systemPrompt: 'Return JSON.', userPayload: { input: 'sample' } }),
    { code: 'DEEPSEEK_ABORTED', retryable: false });
  assert.equal(requests, 0);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].error.code, 'DEEPSEEK_ABORTED');
});
