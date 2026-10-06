'use strict';

const {
  createDeepSeekReasoningEngineFromEnv,
  runOnce,
} = require('../src');
const { createScriptedGateway } = require('./scripted-gateway');

async function main() {
  console.warn('WARNING: this opt-in command can make billable DeepSeek API requests; HTTP retries may add requests. No real target will be contacted.');
  const startedAt = Date.now();
  const gateway = createScriptedGateway();
  const reasoningEngine = createDeepSeekReasoningEngineFromEnv();
  const result = await runOnce({
    gateway,
    reasoningEngine,
    targetOrigin: 'http://127.0.0.1:3000',
    targetApplication: 'deepseek-contract-fixture',
  });
  const thinkEvent = gateway.events.find(event => event.stage === 'loop.think');
  console.log(JSON.stringify({
    mode: 'deepseek-agent-contract-demo',
    warning: 'This opt-in command can make billable DeepSeek API requests, including bounded retries. External modules remain scripted test doubles; no real target was contacted.',
    liveProvider: {
      invoked: true,
      elapsedMs: Date.now() - startedAt,
      metadata: thinkEvent?.response?.payload?.modelMetadata || null,
    },
    report: result.report,
    artifacts: result.artifacts,
    externalRequestCount: gateway.requests.length,
  }, null, 2));
}

main().catch(error => {
  console.error(JSON.stringify({
    status: 'failed',
    runId: error.runId || null,
    error: {
      name: error.name,
      code: error.code || 'AGENT_FAILURE',
      source: error.source || 'agent',
      message: error.message,
    },
    failureReport: error.failureReport || null,
  }, null, 2));
  process.exitCode = 1;
});
