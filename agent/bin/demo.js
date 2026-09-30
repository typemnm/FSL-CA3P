'use strict';

const path = require('node:path');
const { runOnce } = require('../src/orchestrator');
const { withIsolatedLab } = require('../src/target-harness');

async function main() {
  await withIsolatedLab(async target => {
    const result = await runOnce({
      harnessCapability: target.capability,
      outputRoot: path.resolve(__dirname, '..', 'runs'),
      targetMode: 'isolated_local_lab',
      maxIterations: 1,
    });
    console.log(JSON.stringify({
      runId: result.report.runId,
      status: result.report.status,
      finding: result.report.finding,
      metrics: result.report.metrics,
      artifacts: result.artifacts,
    }, null, 2));
    if (result.report.finding.status !== 'confirmed') process.exitCode = 1;
  });
}

main().catch(error => {
  console.error(JSON.stringify({
    status: 'failed',
    runId: error.runId || null,
    error: error.message,
  }, null, 2));
  process.exitCode = 1;
});
