import test from 'node:test';
import assert from 'node:assert/strict';
import { createLocalRuntime } from '../local-runtime.mjs';
import { createDashboardServer } from '../local-server.mjs';
import deepSeek from '../../agent/src/deepseek-reasoning-engine.js';
import reasoning from '../../agent/src/reasoning-engine.js';
import fixtures from '../../agent/test-support/scripted-gateway.js';

const { DeepSeekReasoningEngine, ACTION_CATALOG_ID } = deepSeek;
const { RuleReasoningEngine } = reasoning;

function waitFor(runtime, predicate, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { unsubscribe(); reject(new Error('Local lab did not finish in time.')); }, timeoutMs);
    const unsubscribe = runtime.subscribe(state => {
      if (!predicate(state)) return;
      clearTimeout(timer);
      unsubscribe();
      resolve(state);
    });
    const state = runtime.getState();
    if (predicate(state)) { clearTimeout(timer); unsubscribe(); resolve(state); }
  });
}

test('the real loopback board and model decision adapter complete one isolated canary check', async t => {
  let modelCalls = 0;
  let allowedCurl;
  const runtime = createLocalRuntime({
    labTestProfile: 'agent_cross_user_delete_canary',
    defaultDelayMs: 0,
    labConfigProvider: () => ({ provider: 'deepseek', model: 'deepseek-flash', possibleRetries: 0 }),
    labReasoningFactory: () => new DeepSeekReasoningEngine({
      curlMode: true,
      client: { async completeJson({ userPayload }) {
        modelCalls += 1;
        allowedCurl = userPayload.allowedCurl;
        return {
          value: { state: 'act', candidateId: 'candidate-0', actionCatalogId: ACTION_CATALOG_ID, curl: allowedCurl },
          metadata: { model: 'deepseek-flash', finishReason: 'stop', usage: { total_tokens: 12 } },
        };
      } },
    }),
  });
  t.after(() => runtime.close());
  const initial = await runtime.startLab();
  assert.match(initial.run.target, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.equal(initial.run.mode, 'local-lab-deepseek');
  const completed = await waitFor(runtime, state => ['completed', 'failed'].includes(state.run.status));
  const run = completed.run;
  assert.equal(run.status, 'completed', run.error);
  assert.equal(modelCalls, 1);
  assert.equal(run.simulated, false);
  assert.equal(run.targetContacted, true);
  assert.equal(run.events.length, 25);
  assert.equal(run.events.filter(event => event.source === 'xss-parser/browser').length, 2);
  assert.equal(run.events.filter(event => event.source === 'attack-module/curl').length, 4);
  assert.equal(run.events.filter(event => event.source === 'guardrail-ruleset').length, 4);
  assert.equal(run.events.filter(event => event.source === 'casper-db/sqlite').length, 1);
  assert.equal(run.events.filter(event => event.source === 'pentest-db/local-json').length, 12);
  assert.equal(run.events.filter(event => event.source === 'scripted-gateway').length, 0);
  assert.equal(run.events.filter(event => event.source === 'core-internal-event').length, 2);
  assert.equal(run.report.target.origin, run.target);
  assert.equal(run.report.finding.status, 'confirmed');
  assert.equal(run.report.externalModules.xssParser, 'playwright-browser');
  assert.equal(run.report.externalModules.attackModule, 'local-curl');
  assert.equal(run.report.externalModules.guardrail, 'ruleset-evaluator');
  assert.equal(run.report.externalModules.casperDb, 'sqlite-history');
  assert.equal(run.report.externalModules.pentestDb, 'local-json');
  assert.equal(run.reviewItems[0].vulnerabilityConfirmed, true);
  assert.equal(run.events.find(event => event.stage === 'loop.think').agentOutput.modelMetadata.provider, 'deepseek');
  const action = run.events.find(event => event.module === 'attack' && event.request.payload.curl.method === 'DELETE');
  assert.deepEqual(action.request.payload.curl, allowedCurl);
  assert.equal(action.response.payload.success, true);
  assert.equal(action.response.payload.guardrail.decision, 'ALLOW');
  assert.equal(action.response.payload.response.bodyJson.deletedId > 0, true);
  const board = await fetch(`${run.target}/api/posts`).then(response => response.json());
  assert.equal(board.posts.length, 3);
  assert.equal(board.posts.some(post => post.title.startsWith('agent-canary-')), false);
  assert.equal(board.posts.filter(post => post.authorId === 'admin').length, 2);
  await runtime.close();
  await assert.rejects(fetch(`${run.target}/api/posts`));
});

test('an off-scope model curl URL is rejected before the attack-module sends the canary DELETE', async t => {
  const runtime = createLocalRuntime({
    labTestProfile: 'agent_cross_user_delete_canary',
    defaultDelayMs: 0,
    labConfigProvider: () => ({ provider: 'deepseek', model: 'deepseek-flash', possibleRetries: 0 }),
    labReasoningFactory: () => new DeepSeekReasoningEngine({
      curlMode: true,
      client: { async completeJson({ userPayload }) {
        return {
          value: {
            state: 'act', candidateId: 'candidate-0', actionCatalogId: ACTION_CATALOG_ID,
            curl: { ...userPayload.allowedCurl, url: 'http://127.0.0.1:1/api/posts/4?authorId=bob' },
          },
          metadata: { model: 'deepseek-flash', finishReason: 'stop' },
        };
      } },
    }),
  });
  t.after(() => runtime.close());
  await runtime.startLab();
  const terminal = await waitFor(runtime, state => ['completed', 'failed'].includes(state.run.status));
  assert.equal(terminal.run.status, 'failed');
  assert.equal(terminal.run.report.error.code, 'DEEPSEEK_SCHEMA_ERROR');
  assert.equal(terminal.run.events.some(event => event.module === 'attack' && event.request.payload.curl.method === 'DELETE'), false);
  const board = await fetch(`${terminal.run.target}/api/posts`).then(response => response.json());
  assert.equal(board.posts.some(post => post.title.startsWith('agent-canary-')), true);
});

test('the lab option fails closed without model configuration and leaves the fixture path usable', async t => {
  const runtime = createLocalRuntime({ labTestProfile: 'agent_cross_user_delete_canary',
    defaultDelayMs: 0, labConfigProvider: () => { throw new Error('no key'); } });
  t.after(() => runtime.close());
  assert.equal(runtime.getState().lab.available, false);
  await assert.rejects(runtime.startLab(), error => error.status === 503 && !error.message.includes('no key'));
  const fixture = runtime.start({ target: 'https://metadata-only.invalid', delayMs: 0 });
  assert.equal(fixture.run.mode, 'core-fixture');
  await waitFor(runtime, state => state.run.status === 'completed');
});

test('an adapter exception leaves a visible failed module request and response in the loop', async t => {
  const scripted = fixtures.createScriptedGateway();
  let closed = false;
  const runtime = createLocalRuntime({
    labTestProfile: 'agent_cross_user_delete_canary',
    defaultDelayMs: 0,
    labConfigProvider: () => ({ provider: 'deepseek', model: 'deepseek-flash' }),
    labReasoningFactory: () => new RuleReasoningEngine(),
    labFactory: async () => ({
      origin: 'http://127.0.0.1:3000',
      gateway: { exchange(serializedRequest, options) {
        if (JSON.parse(serializedRequest).receiver === 'xss-parser') {
          const error = new Error('Chromium unavailable');
          error.code = 'XSS_PARSER_UNAVAILABLE';
          throw error;
        }
        return scripted.exchange(serializedRequest, options);
      } },
      async close() { closed = true; },
    }),
  });
  t.after(() => runtime.close());
  await runtime.startLab();
  const { run } = await waitFor(runtime, state => state.run.status === 'failed');
  assert.equal(run.report.error.code, 'TRANSPORT_FAILURE');
  const failedParser = run.events.find(event => event.module === 'parser' && event.type === 'error');
  assert.ok(failedParser);
  assert.equal(failedParser.request.receiver, 'xss-parser');
  assert.equal(failedParser.request.payload.operation, 'parse_site');
  assert.equal(failedParser.response.type, 'module.error');
  assert.equal(failedParser.response.payload.error.code, 'XSS_PARSER_UNAVAILABLE');
  assert.equal(run.snapshots.parser.id, failedParser.id);
  assert.equal(run.events.some(event => event.module === 'attack' && event.request.payload.curl.method === 'DELETE'), false);
  await runtime.close();
  assert.equal(closed, true);
});

test('stopping a pending model decision prevents the canary action and closes the private board', async t => {
  let enteredModel;
  const modelEntered = new Promise(resolve => { enteredModel = resolve; });
  const runtime = createLocalRuntime({
    labTestProfile: 'agent_cross_user_delete_canary',
    labConfigProvider: () => ({ provider: 'deepseek', model: 'deepseek-flash', possibleRetries: 0 }),
    labReasoningFactory: ({ signal }) => new DeepSeekReasoningEngine({
      client: { completeJson() {
        enteredModel();
        return new Promise((resolve, reject) => {
          if (signal.aborted) reject(new Error('stopped'));
          else signal.addEventListener('abort', () => reject(new Error('stopped')), { once: true });
        });
      } },
    }),
  });
  t.after(() => runtime.close());
  const started = await runtime.startLab();
  await modelEntered;
  const origin = started.run.target;
  runtime.stop(started.run.id);
  const stopped = await waitFor(runtime, state => state.run.status === 'stopped');
  assert.equal(stopped.run.report.status, 'failed');
  assert.equal(stopped.run.events.filter(event => event.source === 'xss-parser/browser').length, 1);
  assert.equal(stopped.run.events.filter(event => event.source === 'attack-module/curl').length, 3);
  assert.equal(stopped.run.events.some(event => event.stage === 'loop.act'), false);
  await runtime.close();
  await assert.rejects(fetch(`${origin}/api/posts`));
});

test('the HTTP lab start route cannot accept an arbitrary target URL', async t => {
  const runtime = createLocalRuntime({
    labTestProfile: 'agent_cross_user_delete_canary',
    defaultDelayMs: 0,
    labConfigProvider: () => ({ provider: 'deepseek', model: 'deepseek-flash', possibleRetries: 0 }),
    labReasoningFactory: () => new DeepSeekReasoningEngine({
      client: { async completeJson() { return { value: {
        state: 'stop', candidateId: null, actionCatalogId: null,
      }, metadata: { model: 'deepseek-flash', finishReason: 'stop' } }; } },
    }),
  });
  const server = createDashboardServer({ runtime });
  t.after(() => server.shutdown());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bad = await fetch(`${origin}/api/lab-runs`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: 'https://example.com' }) });
  assert.equal(bad.status, 400);
  assert.equal(runtime.getState().run.status, 'idle');
  const started = await fetch(`${origin}/api/lab-runs`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(started.status, 201);
  const envelope = await started.json();
  assert.equal(envelope.run.mode, 'local-lab-deepseek');
  assert.match(envelope.run.target, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.notEqual(envelope.run.target, origin);
  const terminal = await waitFor(runtime, state => ['failed', 'completed'].includes(state.run.status));
  assert.equal(terminal.run.status, 'failed');
  assert.equal(terminal.run.targetContacted, true);
  assert.equal(terminal.run.events.some(event => event.stage === 'loop.act'), false);
});
