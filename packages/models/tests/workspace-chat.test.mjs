import test from 'node:test';
import assert from 'node:assert/strict';
import { createWorkspaceChatModel, estimateTokens, computeContext } from '../workspace-chat.mjs';

const envelope = (value, extra = {}) => new Response(JSON.stringify({ model: 'deepseek-flash',
  choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(value) } }],
  usage: { prompt_tokens: 17, completion_tokens: 9, total_tokens: 26 }, ...extra }), { status: 200 });
const configured = fetchImpl => createWorkspaceChatModel({ envFile: false,
  env: { DEEPSEEK_API_KEY: 'private-chat-test-key' }, fetchImpl });

test('chat model lists only usable text models and does not publish configuration values', () => {
  const rows = createWorkspaceChatModel({ env: {}, envFile: false }).listModels();
  assert.deepEqual(rows.map(row => row.id), ['deepseek-flash', 'deepseek-v4-pro']);
  assert.ok(rows.every(row => !row.available));
  assert.ok(configured().listModels().every(row => row.available));
  const local = createWorkspaceChatModel({ envFile: false,
    env: { DEEPSEEK_API_KEY: 'secret', DEEPSEEK_BASE_URL: 'http://127.0.0.1:1234' } });
  assert.ok(local.listModels().every(row => !row.available));
  assert.equal(JSON.stringify(rows).includes('private-chat-test-key'), false);
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
