import test from 'node:test';
import assert from 'node:assert/strict';
import { listModels } from '../registry.mjs';

test('model registry exposes a real rule baseline without credentials', () => {
  const models = listModels({ env: {}, envFile: false });
  assert.equal(models[0].available, true);
  assert.ok(models.slice(1).every(row => !row.available));
  assert.ok(models.filter(row => row.id !== 'rule-baseline').every(row => row.supportedModes.includes('local-lab-general')));
  assert.ok(!models[0].supportedModes.includes('local-lab-general'));
  assert.deepEqual(models.map(row => row.id), ['rule-baseline', 'deepseek-flash', 'deepseek-v4-pro', 'local-llm']);
  assert.deepEqual(models.map(row => row.mode), ['local-lab-rule', 'local-lab-general', 'local-lab-general', 'local-lab-general']);
  assert.ok(models.every(row => !row.supportedModes.some(mode => ['core-fixture', 'local-lab-deepseek'].includes(mode))));
});

test('model registry marks the local planner available from the chat local endpoint', () => {
  const models = listModels({ envFile: false, env: {
    CA3P_CHAT_LOCAL_ENDPOINT: 'http://127.0.0.1:11434', CA3P_CHAT_LOCAL_RUNTIME: 'ollama',
    CA3P_CHAT_LOCAL_MODEL: 'qwen3',
  } });
  const local = models.find(row => row.id === 'local-llm');
  assert.equal(local.available, true);
  assert.equal(local.provider, 'local');
  assert.ok(local.supportedModes.includes('local-lab-general'));
  assert.equal(JSON.stringify(models).includes('qwen3'), true);
});
