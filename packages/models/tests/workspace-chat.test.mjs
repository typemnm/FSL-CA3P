import test from 'node:test';
import assert from 'node:assert/strict';
import { createWorkspaceChatModel, estimateTokens, computeContext, isLocalChatModelId } from '../workspace-chat.mjs';

const envelope = (value, extra = {}) => new Response(JSON.stringify({ model: 'deepseek-flash',
  choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(value) } }],
  usage: { prompt_tokens: 17, completion_tokens: 9, total_tokens: 26 }, ...extra }), { status: 200 });
const configured = fetchImpl => createWorkspaceChatModel({ envFile: false,
  env: { DEEPSEEK_API_KEY: 'private-chat-test-key' }, fetchImpl: fetchImpl ?? (async () => { throw new Error('Network disabled'); }) });

test('chat model lists only usable text models and does not publish configuration values', async () => {
  const disabledFetch = async () => { throw new Error('Network disabled'); };
  const rows = await createWorkspaceChatModel({ env: {}, envFile: false, fetchImpl: disabledFetch }).listModels();
  assert.deepEqual(rows.map(row => row.id), ['deepseek-flash', 'deepseek-v4-pro']);
  assert.ok(rows.every(row => !row.available));
  assert.ok((await configured().listModels()).every(row => row.available));
  const local = createWorkspaceChatModel({ envFile: false,
    env: { DEEPSEEK_API_KEY: 'secret', DEEPSEEK_BASE_URL: 'http://127.0.0.1:1234' }, fetchImpl: disabledFetch });
  assert.ok((await local.listModels()).every(row => !row.available));
  assert.equal(JSON.stringify(rows).includes('private-chat-test-key'), false);
});

const localEnv = { CA3P_CHAT_LOCAL_ENDPOINT: 'http://127.0.0.1:18080/v1', CA3P_CHAT_LOCAL_RUNTIME: 'llama-cpp',
  CA3P_CHAT_LOCAL_API_KEY: 'private-local-test-key', CA3P_CHAT_LOCAL_MODEL: 'qwen-local' };
const localCatalog = () => new Response(JSON.stringify({ data: [{ id: 'qwen-local' }] }), { status: 200 });

test('local OpenAI runtime discovery supports chat and compaction with its own credentials and token reserve', async () => {
  const requests = [];
  const adapter = createWorkspaceChatModel({ envFile: false, env: localEnv, fetchImpl: async (url, init) => {
    requests.push({ url, ...init });
    if (url.endsWith('/models')) return localCatalog();
    const payload = JSON.parse(JSON.parse(init.body).messages[1].content);
    return envelope(payload.purpose === 'compact' ? { summary: '로컬 요약' } : { content: '로컬 답변 private-local-test-key' }, { model: 'qwen-local' });
  } });
  const rows = await adapter.listModels(); const local = rows.find(row => row.provider === 'local');
  assert.equal(local.available, true); assert.equal(local.runtime, 'llama.cpp');
  assert.equal(local.applicationBudgetTokens, 5632); assert.equal(local.maxOutputTokens, 2048);
  assert.equal(isLocalChatModelId(local.id), true); assert.equal(local.id.length < 160, true);
  assert.equal(JSON.stringify(rows).includes('private-local-test-key'), false);
  const answer = await adapter.complete({ modelId: local.id, messages: [{ role: 'user', content: '안녕' }] });
  assert.match(answer.content, /로컬 답변/); assert.equal(answer.content.includes('private-local-test-key'), false);
  assert.equal(answer.usage.total_tokens, 26); assert.equal(answer.provider, 'local'); assert.equal(answer.reportedModel, 'qwen-local');
  assert.equal((await adapter.complete({ modelId: local.id, purpose: 'compact' })).content, '로컬 요약');
  assert.equal(requests[1].url, 'http://127.0.0.1:18080/v1/chat/completions');
  assert.equal(requests[1].headers.Authorization, 'Bearer private-local-test-key');
  assert.equal(JSON.parse(requests[1].body).max_tokens, 2048);
  assert.equal(adapter.contextBudget(local.id).applicationBudgetTokens, 5632);
  assert.equal(computeContext({ modelId: local.id, messages: [] }).applicationBudgetTokens, 5632);
});

test('Ollama discovery and generation use its bounded native JSON protocol and actual usage', async () => {
  const requests = [];
  const adapter = createWorkspaceChatModel({ envFile: false, env: { SLLM_ENDPOINT: 'http://localhost:11434', SLLM_MODEL: 'gemma4:e2b' },
    fetchImpl: async (url, init) => {
      requests.push({ url, ...init });
      if (url.endsWith('/api/tags')) return new Response(JSON.stringify({ models: [{ name: 'gemma4:e2b' }] }));
      return new Response(JSON.stringify({ model: 'gemma4:e2b', done: true, done_reason: 'stop',
        message: { content: '{"content":"Ollama 응답"}' }, prompt_eval_count: 30, eval_count: 12 }));
    } });
  const row = (await adapter.listModels()).find(item => item.available);
  const answer = await adapter.complete({ modelId: row.id });
  assert.equal(requests[0].url, 'http://127.0.0.1:11434/api/tags');
  assert.equal(requests[1].url, 'http://127.0.0.1:11434/api/chat');
  const payload = JSON.parse(requests[1].body);
  assert.equal(payload.format, 'json'); assert.equal(payload.stream, false); assert.equal(payload.options.num_ctx, 8192);
  assert.deepEqual(answer.usage, { prompt_tokens: 30, completion_tokens: 12, total_tokens: 42 });
});

test('local authorization failures remain visible without publishing server configuration or retrying generation', async () => {
  let count = 0;
  const adapter = createWorkspaceChatModel({ envFile: false, env: localEnv, fetchImpl: async () => { count += 1; return new Response('', { status: 401 }); } });
  const row = (await adapter.listModels()).find(item => item.provider === 'local');
  assert.equal(row.available, false); assert.match(row.reason, /인증 키/); assert.match(row.name, /qwen-local/);
  await assert.rejects(() => adapter.complete({ modelId: row.id }), { code: 'LOCAL_CHAT_UNAVAILABLE' });
  assert.equal(count, 1); assert.equal(JSON.stringify(row).includes('private-local-test-key'), false);
});

test('discovery keeps known local models visible when their runtime goes offline and context reads never perform network', async () => {
  let online = true; let requests = 0;
  const adapter = createWorkspaceChatModel({ envFile: false, env: localEnv, fetchImpl: async () => {
    requests += 1; if (!online) throw new Error('Raw private transport detail'); return localCatalog();
  } });
  const before = (await adapter.listModels()).find(row => row.provider === 'local'); online = false;
  const after = (await adapter.listModels({ refresh: true })).find(row => row.provider === 'local');
  assert.equal(after.id, before.id); assert.equal(after.available, false); assert.match(after.reason, /연결/);
  assert.equal(JSON.stringify(after).includes('Raw private'), false);
  adapter.contextBudget(after.id); adapter.contextBudget(after.id); assert.equal(requests, 2);
});

test('local endpoints reject arbitrary hosts, credentials, queries, paths and inherited remote keys before network', async () => {
  for (const endpoint of ['https://external.example/v1', 'http://192.168.0.3:1234/v1', 'http://127.0.0.1.evil.test/v1',
    'http://user:pass@127.0.0.1/v1', 'http://127.0.0.1/v1?key=private', 'http://127.0.0.1/private']) {
    let requests = 0;
    const adapter = createWorkspaceChatModel({ envFile: false, env: { ...localEnv, CA3P_CHAT_LOCAL_ENDPOINT: endpoint },
      fetchImpl: async () => { requests += 1; return localCatalog(); } });
    const row = (await adapter.listModels()).find(item => item.provider === 'local');
    assert.equal(row.available, false); assert.equal(requests, 0); assert.equal(JSON.stringify(row).includes(endpoint), false);
  }
  const noEndpoint = createWorkspaceChatModel({ envFile: false, env: { CA3P_CHAT_LOCAL_API_KEY: 'local-key' },
    fetchImpl: async () => { throw new Error('No endpoint must be contacted'); } });
  assert.match((await noEndpoint.listModels()).find(row => row.provider === 'local').reason, /함께/);
  const scoped = createWorkspaceChatModel({ envFile: false,
    env: { CA3P_CHAT_LOCAL_ENDPOINT: localEnv.CA3P_CHAT_LOCAL_ENDPOINT, SLLM_ENDPOINT: 'http://127.0.0.1:11434',
      SLLM_API_KEY: 'different-local-server-key', DEEPSEEK_API_KEY: 'remote-provider-key' },
    fetchImpl: async (url, init) => { assert.equal(init.headers.Authorization, undefined); return localCatalog(); } });
  assert.equal((await scoped.listModels()).some(row => row.provider === 'local' && row.available), true);
});

test('local completion rejects over-budget prompts, incomplete output, invalid JSON and oversized streaming bodies', async () => {
  let mode = 'incomplete'; let posts = 0;
  const adapter = createWorkspaceChatModel({ envFile: false, env: localEnv, fetchImpl: async url => {
    if (url.endsWith('/models')) return localCatalog(); posts += 1;
    if (mode === 'oversized') return new Response('x'.repeat(512 * 1024 + 1));
    if (mode === 'invalid') return envelope({ content: 'text' }, { choices: [{ finish_reason: 'stop', message: { content: 'not-json' } }] });
    return envelope({ content: 'partial' }, { choices: [{ finish_reason: 'length', message: { content: '{"content":"partial"}' } }] });
  } });
  const row = (await adapter.listModels()).find(item => item.available);
  await assert.rejects(() => adapter.complete({ modelId: row.id, messages: [{ role: 'user', content: '한'.repeat(3000) }] }), { code: 'CHAT_CONTEXT_TOO_LARGE' });
  assert.equal(posts, 0);
  for (mode of ['incomplete', 'invalid', 'oversized']) await assert.rejects(() => adapter.complete({ modelId: row.id }), { code: 'CHAT_OUTPUT_INVALID' });
  assert.equal(posts, 3);
});

test('local cancellation is propagated and custom context size reserves enough generation tokens', async () => {
  const adapter = createWorkspaceChatModel({ envFile: false, env: { ...localEnv, CA3P_CHAT_LOCAL_CONTEXT_TOKENS: '4096' },
    fetchImpl: async (url, init) => {
      if (url.endsWith('/models')) return localCatalog();
      return new Promise((resolve, reject) => init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true }));
    } });
  const row = (await adapter.listModels()).find(item => item.available);
  assert.equal(row.applicationBudgetTokens, 1536);
  assert.equal(adapter.contextBudget(row.id).applicationBudgetTokens, 1536);
  const controller = new AbortController();
  const answer = adapter.complete({ modelId: row.id, signal: controller.signal });
  await new Promise(resolve => setImmediate(resolve)); controller.abort();
  await assert.rejects(() => answer, { code: 'LOCAL_CHAT_ABORTED' });
});

test('chat invokes the existing JSON client, bounds settings and reports actual provider usage', async () => {
  let request;
  const adapter = configured(async (url, init) => { request = { url, ...init }; return envelope({ content: '확인된 결과입니다.' }); });
  const result = await adapter.complete({ modelId: 'deepseek-v4-pro', messages: [{ role: 'user', content: '안녕' }],
    context: { files: [{ path: 'README.md', content: 'Untrusted sample' }] } });
  assert.equal(request.url, 'https://api.deepseek.com/chat/completions');
  const payload = JSON.parse(request.body);
  assert.equal(payload.model, 'deepseek-v4-pro'); assert.equal(payload.stream, false);
  assert.ok(payload.max_tokens >= 2048 && payload.max_tokens <= 4096);
  assert.equal(payload.response_format.type, 'json_object');
  assert.match(payload.messages[0].content, /신뢰하지 않는/);
  assert.equal(JSON.parse(payload.messages[1].content).messages[0].content, '안녕');
  assert.equal(result.content, '확인된 결과입니다.'); assert.equal(result.usage.total_tokens, 26);
  assert.equal(result.reportedModel, 'deepseek-flash');
});

test('no retry on upstream errors, no request after cancellation, and no provider key in output', async () => {
  let requests = 0;
  const failed = configured(async () => { requests += 1; return new Response('', { status: 503 }); });
  await assert.rejects(() => failed.complete({ modelId: 'deepseek-flash' }), { code: 'DEEPSEEK_UPSTREAM_ERROR' });
  assert.equal(requests, 1);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(() => failed.complete({ modelId: 'deepseek-flash', signal: controller.signal }), { code: 'DEEPSEEK_ABORTED' });
  assert.equal(requests, 1);
  const redacted = configured(async () => envelope({ content: '키 private-chat-test-key' }));
  assert.equal((await redacted.complete({ modelId: 'deepseek-flash' })).content.includes('private-chat-test-key'), false);
});

test('compact uses its own output schema; invalid output and oversized prompts are rejected', async () => {
  const adapter = configured(async () => envelope({ summary: '결정과 미완료 작업을 보존한 요약' }));
  assert.match((await adapter.complete({ modelId: 'deepseek-flash', purpose: 'compact' })).content, /미완료/);
  await assert.rejects(() => adapter.complete({ modelId: 'deepseek-flash' }), { code: 'CHAT_OUTPUT_INVALID' });
  await assert.rejects(() => adapter.complete({ modelId: 'deepseek-flash', messages: [{ role: 'user', content: '한'.repeat(25000) }] }),
    { code: 'CHAT_CONTEXT_TOO_LARGE' });
});

test('context count includes CJK, system prompt, summary and attachment data, excludes failed/pending messages', () => {
  assert.ok(estimateTokens('한국어 문장') > estimateTokens('ascii text'));
  assert.ok(estimateTokens('😀'.repeat(10)) >= 10);
  const session = { summary: '지난 대화', compactedThroughSequence: 1, compactionCount: 1, messages: [
    { sequence: 1, role: 'user', content: 'old'.repeat(5000), status: 'completed' },
    { sequence: 2, role: 'user', content: 'hello', status: 'completed' },
    { sequence: 3, role: 'assistant', content: 'no'.repeat(5000), status: 'failed' },
    { sequence: 4, role: 'assistant', content: 'yes', status: 'completed', metadata: { usage: { total_tokens: 26 } } },
  ] };
  const metrics = computeContext(session);
  assert.equal(metrics.applicationBudgetTokens, 8000); assert.equal(metrics.budgetKind, 'application');
  assert.equal(metrics.previousProviderUsage.total_tokens, 26); assert.ok(metrics.estimatedInputTokens < 1200);
  assert.ok(computeContext(session, { context: { file: '한'.repeat(100) } }).estimatedInputTokens > metrics.estimatedInputTokens + 190);
});
