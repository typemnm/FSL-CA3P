'use strict';

const { runOnce } = require('../src');
const { createScriptedGateway } = require('./scripted-gateway');

async function main() {
  const gateway = createScriptedGateway();
  const result = await runOnce({
    gateway,
    targetOrigin: 'http://127.0.0.1:3000',
    targetApplication: 'contract-fixture',
  });
  console.log(JSON.stringify({
    mode: 'agent-contract-demo',
    warning: 'External modules are scripted test doubles; no real target was contacted.',
    report: result.report,
    artifacts: result.artifacts,
    externalRequestCount: gateway.requests.length,
  }, null, 2));
}

main().catch(error => {
  console.error(JSON.stringify({
    status: 'failed',
    runId: error.runId || null,
    error: error.message,
    failureReport: error.failureReport || null,
  }, null, 2));
  process.exitCode = 1;
});
