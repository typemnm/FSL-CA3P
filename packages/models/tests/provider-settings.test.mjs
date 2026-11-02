import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  addProvider, customModelEntries, discoverLocalServers, listProviderSettings, normalizeProviderBaseUrl,
  removeProvider, resolveProvider, setLocalSelection, testProvider,
} from '../provider-settings.mjs';
import { createCustomJsonClient, isGeneralPlannerModel, listLocalPlannerModels, plannerProvider, usesJsonClient } from '../local-planner.mjs';
import { listModels } from '../registry.mjs';

const KEY = 'sk-test-0123456789abcdef';
function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), 'ca3p-llm-settings-'));
  return { env: { CA3P_LLM_PROVIDERS_PATH: join(dir, 'llm-providers.json') }, path: join(dir, 'llm-providers.json') };
}
const response = (status, body) => ({ ok: status >= 200 && status < 300, status, headers: { get: () => null },
  text: async () => JSON.stringify(body), body: null });

test('a provider is stored server-side and its key never appears in the public view', () => {
  const { env, path } = sandbox();
  const created = addProvider({ name: '팀 DeepSeek', kind: 'deepseek', model: 'deepseek-chat', apiKey: KEY }, { env });
  assert.match(created.id, /^custom-[a-f0-9]{12}$/u);
  assert.equal(created.baseUrl, 'https://api.deepseek.com');
  assert.equal(created.keyHint, '…cdef');
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.ok(readFileSync(path, 'utf8').includes(KEY));
  const listed = listProviderSettings({ env });
  assert.ok(!JSON.stringify(listed).includes(KEY));
  assert.ok(!JSON.stringify(customModelEntries({ env })).includes(KEY));
  assert.equal(resolveProvider(created.id, { env }).apiKey, KEY);
  assert.throws(() => addProvider({ name: '팀 deepseek', kind: 'openai', model: 'gpt-4o-mini', apiKey: KEY }, { env }), { code: 'LLM_PROVIDER_DUPLICATE' });
  assert.deepEqual(removeProvider(created.id, { env }), { removed: created.id });
  assert.equal(listProviderSettings({ env }).providers.length, 0);
  assert.throws(() => removeProvider(created.id, { env }), { status: 404 });
});

test('provider input is validated before anything is written', () => {
  const { env } = sandbox();
  const base = { name: 'Custom', kind: 'openai-compatible', model: 'm', apiKey: KEY, baseUrl: 'https://llm.example.com/v1/' };
  assert.equal(addProvider(base, { env }).baseUrl, 'https://llm.example.com/v1');
  for (const baseUrl of ['http://llm.example.com/v1', 'https://localhost:8000/v1', 'https://127.0.0.1/v1', 'https://user:pw@llm.example.com',
    'https://llm.example.com/v1?key=x', 'not a url']) {
    assert.throws(() => normalizeProviderBaseUrl(baseUrl), { code: 'LLM_PROVIDER_INVALID' }, baseUrl);
  }
  for (const patch of [{ kind: 'anthropic' }, { apiKey: 'short' }, { apiKey: 'has space key 123' }, { name: '' }, { model: 'x\ny' }, { extra: 1 }]) {
    assert.throws(() => addProvider({ ...base, name: `n${Math.random()}`, ...patch }, { env }), { code: 'LLM_PROVIDER_INVALID' }, JSON.stringify(patch));
  }
  // A fixed provider ignores a submitted base URL.
  assert.equal(addProvider({ ...base, name: 'OpenAI', kind: 'openai', baseUrl: 'https://evil.example' }, { env }).baseUrl, 'https://api.openai.com/v1');
});

test('registered providers become general planner models and run through the JSON client', async () => {
  const { env } = sandbox();
  const openai = addProvider({ name: 'OpenAI', kind: 'openai', model: 'gpt-4o-mini', apiKey: KEY }, { env });
  const models = listModels({ env, envFile: false });
  const row = models.find(item => item.id === openai.id);
  assert.equal(row.provider, 'custom');
  assert.equal(row.available, true);
  assert.deepEqual(row.supportedModes, ['local-lab-general', 'external-general']);
  assert.deepEqual(row.settings, { kind: 'openai', endpoint: 'https://api.openai.com', model: 'gpt-4o-mini' });
  assert.ok(isGeneralPlannerModel(openai.id) && usesJsonClient(openai.id));
  assert.equal(plannerProvider(openai.id), 'custom');
  assert.equal(plannerProvider('local-llm'), 'local');
  assert.equal(plannerProvider('deepseek-flash'), 'deepseek');

  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init, body: JSON.parse(init.body) });
    return response(200, { model: 'gpt-4o-mini-2024', choices: [{ finish_reason: 'stop', message: { content: '{"done":true}' } }],
      usage: { prompt_tokens: 10, completion_tokens: 3, total_tokens: 13 } });
  };
  const client = await createCustomJsonClient({ modelId: openai.id, env, fetchImpl });
  const result = await client.completeJson({ systemPrompt: 'Return JSON.', userPayload: { a: 1 } });
  assert.deepEqual(result.value, { done: true });
  assert.equal(calls[0].url, 'https://api.openai.com/v1/chat/completions');
  assert.equal(calls[0].init.headers.Authorization, `Bearer ${KEY}`);
  assert.equal(calls[0].body.max_completion_tokens, 2048);
  assert.equal(calls[0].body.temperature, undefined);
  assert.equal(result.metadata.provider, 'custom');
  assert.equal(result.metadata.requestedModel, openai.id);
  assert.equal(result.metadata.reportedModel, 'gpt-4o-mini-2024');
  assert.ok(!JSON.stringify(result.metadata).includes(KEY));

  const deepseek = addProvider({ name: 'DS', kind: 'deepseek', model: 'deepseek-chat', apiKey: KEY }, { env });
  const dsClient = await createCustomJsonClient({ modelId: deepseek.id, env, fetchImpl });
  await dsClient.completeJson({ systemPrompt: 'Return JSON.', userPayload: {} });
  assert.equal(calls[1].url, 'https://api.deepseek.com/chat/completions');
  assert.equal(calls[1].body.max_tokens, 2048);
  assert.equal(calls[1].body.temperature, 0);

  const rejected = await createCustomJsonClient({ modelId: deepseek.id, env, fetchImpl: async () => response(401, {}) });
  await assert.rejects(rejected.completeJson({ systemPrompt: 'Return JSON.', userPayload: {} }), { code: 'LLM_PROVIDER_AUTH_FAILED' });
  removeProvider(deepseek.id, { env });
  await assert.rejects(createCustomJsonClient({ modelId: deepseek.id, env, fetchImpl }), { code: 'LLM_PROVIDER_UNAVAILABLE' });
});

test('connection test lists the provider models with the stored key', async () => {
  const { env } = sandbox();
  const provider = addProvider({ name: 'DS', kind: 'deepseek', model: 'deepseek-chat', apiKey: KEY }, { env });
  let seen;
  const ok = await testProvider(provider.id, { env, fetchImpl: async (url, init) => { seen = { url, auth: init.headers.Authorization };
    return response(200, { data: [{ id: 'deepseek-chat' }, { id: 'deepseek-reasoner' }] }); } });
  assert.deepEqual(ok, { ok: true, method: 'models', modelFound: true, models: ['deepseek-chat', 'deepseek-reasoner'] });
  assert.deepEqual(seen, { url: 'https://api.deepseek.com/models', auth: `Bearer ${KEY}` });
  const failed = await testProvider(provider.id, { env, fetchImpl: async () => response(403, {}) });
  assert.equal(failed.ok, false);
  assert.equal(failed.code, 'LLM_PROVIDER_AUTH_FAILED');
  assert.ok(!JSON.stringify(failed).includes(KEY));
});

test('local discovery probes the default loopback runtimes and a chosen model becomes local-llm', async () => {
  const { env } = sandbox();
  const servers = await discoverLocalServers({ fetchImpl: async url => {
    if (url === 'http://127.0.0.1:11434/api/tags') return response(200, { models: [{ name: 'qwen3:8b' }, { name: 'llama3.2' }] });
    if (url === 'http://127.0.0.1:1234/v1/models') return response(401, {});
    throw new Error('connection refused');
  } });
  assert.deepEqual(servers.map(item => [item.label, item.reachable]), [['ollama', true], ['lm-studio', false], ['llama-cpp', false], ['docker-model-runner', false]]);
  assert.deepEqual(servers[0].models, ['qwen3:8b', 'llama3.2']);
  assert.equal(servers[1].error, '서버가 인증 키를 요구합니다.');

  assert.equal(listLocalPlannerModels({ env, envFile: false })[0].available, false);
  setLocalSelection({ label: 'ollama', model: 'qwen3:8b' }, { env });
  const local = listLocalPlannerModels({ env, envFile: false })[0];
  assert.equal(local.available, true);
  assert.equal(local.name, '로컬 LLM · qwen3:8b');
  assert.equal(local.runtime, 'Ollama');
  // An endpoint configured in the environment keeps priority over the module selection.
  const configured = listLocalPlannerModels({ env: { ...env, CA3P_CHAT_LOCAL_ENDPOINT: 'http://127.0.0.1:1234/v1', CA3P_CHAT_LOCAL_MODEL: 'phi' }, envFile: false })[0];
  assert.equal(configured.name, '로컬 LLM · phi');
  assert.throws(() => setLocalSelection({ label: 'remote', model: 'x' }, { env }), { code: 'LLM_LOCAL_INVALID' });
  assert.throws(() => setLocalSelection({ label: 'ollama', model: 'x', endpoint: 'http://10.0.0.1' }, { env }), { code: 'LLM_LOCAL_INVALID' });
  setLocalSelection({ clear: true }, { env });
  assert.equal(listProviderSettings({ env }).local, null);
});

test('deploy.com gateway preset: fixed base URL, JSON-mode retry and chat fallback for the connection test', async () => {
  const { env } = sandbox();
  const model = 'deepseek-ai/deepseek-v4.1-flash-1017';
  const deploy = addProvider({ name: 'deploy', kind: 'deploy', model, apiKey: KEY, baseUrl: 'https://ignored.example' }, { env });
  assert.equal(deploy.baseUrl, 'https://api-sf1-cdn.deploy.com/api/v1');
  assert.ok(listProviderSettings({ env }).kinds.some(kind => kind.id === 'deploy' && kind.modelHint === model));

  // The gateway rejects JSON mode once; the client retries without response_format and still parses the JSON reply.
  const bodies = [];
  const client = await createCustomJsonClient({ modelId: deploy.id, env, fetchImpl: async (url, init) => {
    const body = JSON.parse(init.body); bodies.push(body);
    assert.equal(url, 'https://api-sf1-cdn.deploy.com/api/v1/chat/completions');
    if (body.response_format) return response(400, { error: 'response_format unsupported' });
    return response(200, { choices: [{ finish_reason: 'stop', message: { content: 'Plan:\n```json\n{"done":true}\n```' } }] });
  } });
  const result = await client.completeJson({ systemPrompt: 'Return JSON.', userPayload: {} });
  assert.deepEqual(result.value, { done: true });
  assert.deepEqual(bodies.map(body => Boolean(body.response_format)), [true, false]);
  assert.equal(bodies[1].model, model);
  assert.equal(bodies[1].stream, false);

  // No /models endpoint: one minimal chat completion proves key and model.
  const seen = [];
  const tested = await testProvider(deploy.id, { env, fetchImpl: async (url, init) => {
    seen.push(url);
    if (url.endsWith('/models')) return response(404, {});
    assert.equal(init.headers.Authorization, `Bearer ${KEY}`);
    return response(200, { choices: [{ finish_reason: 'stop', message: { content: 'OK' } }] });
  } });
  assert.deepEqual(tested, { ok: true, method: 'chat', modelFound: true, models: [] });
  assert.deepEqual(seen, ['https://api-sf1-cdn.deploy.com/api/v1/models', 'https://api-sf1-cdn.deploy.com/api/v1/chat/completions']);
  // A rejected key stops at the first request.
  const denied = await testProvider(deploy.id, { env, fetchImpl: async () => response(401, {}) });
  assert.equal(denied.code, 'LLM_PROVIDER_AUTH_FAILED');
});
