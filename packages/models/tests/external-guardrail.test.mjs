import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveExternalGuardrail } from '../external-guardrail.mjs';

test('external guardrail requires local settings and fails closed', () => {
  const env = { CA3P_GUARDRAIL_SLLM_ENDPOINT: 'http://127.0.0.1:11434',
    CA3P_GUARDRAIL_SLLM_MODEL: 'guardrail-local' };
  assert.deepEqual(resolveExternalGuardrail({ env, envFile: null }), {
    provider: 'local', endpoint: env.CA3P_GUARDRAIL_SLLM_ENDPOINT, model: 'guardrail-local',
  });
  assert.equal(resolveExternalGuardrail({ env: { ...env,
    CA3P_GUARDRAIL_SLLM_MODEL: '' }, envFile: null }).provider, 'unavailable');
  assert.equal(resolveExternalGuardrail({ env: { ...env,
    CA3P_GUARDRAIL_SLLM_ENDPOINT: 'https://model.example' }, envFile: null }).provider,
  'unavailable');
  assert.equal(resolveExternalGuardrail({ env: { DEEPSEEK_API_KEY: 'test-key' }, envFile: null }).provider,
    'unavailable');
});
