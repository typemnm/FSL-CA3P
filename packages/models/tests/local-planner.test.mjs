import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LOCAL_PLANNER_MODEL_ID, parsePlannerJson, listLocalPlannerModels, createLocalJsonClient,
  isGeneralPlannerModel,
} from '../local-planner.mjs';

const localEnv = { CA3P_CHAT_LOCAL_ENDPOINT: 'http://127.0.0.1:18080/v1', CA3P_CHAT_LOCAL_RUNTIME: 'llama-cpp',
  CA3P_CHAT_LOCAL_API_KEY: 'private-local-test-key', CA3P_CHAT_LOCAL_MODEL: 'qwen-local' };

test('planner JSON recovery strips think tags and markdown fences', () => {
  assert.deepEqual(parsePlannerJson('<think>scratch</think>\n```json\n{"done":true,"hypotheses":[],"probes":[]}\n```\n'),
    { done: true, hypotheses: [], probes: [] });
  assert.throws(() => parsePlannerJson('not json'), { code: 'LOCAL_PLANNER_OUTPUT_INVALID' });
});

test('local planner is listed only when a loopback endpoint is configured', () => {
  const missing = listLocalPlannerModels({ env: {}, envFile: false })[0];
  assert.equal(missing.id, LOCAL_PLANNER_MODEL_ID);
  assert.equal(missing.available, false);
  const ready = listLocalPlannerModels({ env: localEnv, envFile: false })[0];
  assert.equal(ready.available, true);
  assert.equal(ready.provider, 'local');
  assert.ok(isGeneralPlannerModel(LOCAL_PLANNER_MODEL_ID));
  assert.ok(isGeneralPlannerModel('deepseek-flash'));
  assert.equal(isGeneralPlannerModel('rule-baseline'), false);
});

test('local JSON client talks OpenAI-compat without DeepSeek thinking fields', async () => {
  const requests = [];
  const client = await createLocalJsonClient({ env: localEnv, envFile: false, fetchImpl: async (url, init) => {
    requests.push({ url, ...init });
    return new Response(JSON.stringify({
      model: 'qwen-local',
      choices: [{ finish_reason: 'stop', message: { content: '<think>x</think>{"done":true,"hypotheses":[],"probes":[]}' } }],
      usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
    }), { status: 200 });
  } });
  const result = await client.completeJson({ systemPrompt: 'Return JSON only.', userPayload: { task: 'propose' } });
  assert.deepEqual(result.value, { done: true, hypotheses: [], probes: [] });
  assert.equal(result.metadata.provider, 'local');
  assert.equal(result.metadata.model, LOCAL_PLANNER_MODEL_ID);
  assert.equal(result.metadata.reportedModel, 'qwen-local');
  const body = JSON.parse(requests[0].body);
  assert.equal(body.model, 'qwen-local');
  assert.equal(body.response_format.type, 'json_object');
  assert.equal(Object.hasOwn(body, 'thinking'), false);
  assert.equal(requests[0].headers.Authorization, 'Bearer private-local-test-key');
  assert.equal(JSON.stringify(result).includes('private-local-test-key'), false);
});
