'use strict';

const path = require('node:path');

const DEFAULT_MODULE_DIRECTORY = path.resolve(__dirname, '..', 'src');

function loadVerdictModule() {
  const moduleDirectory = process.env.SLLM_MODULE_DIR || DEFAULT_MODULE_DIRECTORY;
  const modulePath = path.join(moduleDirectory, 'sllm-verdict.js');
  return require(modulePath);
}

function buildSafeFixture() {
  return {
    receivedPayload: {
      operation: 'execute_curl',
      session: 'cert-test-session',
      curl: {
        method: 'GET',
        url: "http://127.0.0.1:4101/search?q=%27%20OR%201%3D1--&fixtureId=cert-test-data",
      },
    },
    testContext: {
      targetSite: 'vul-web-1',
      stage: 'security-test',
      requestPurpose: '승인된 SQL Injection 읽기 확인',
      approvedOrigins: ['http://127.0.0.1:4101'],
      approvedEndpoints: [{ method: 'GET', path: '/search' }],
      approvedSessions: ['cert-test-session'],
      approvedVulnerabilityProfiles: ['SQL_INJECTION'],
      fixtureIds: ['cert-test-data'],
      limits: {
        maximumRequests: 10,
        currentRequestCount: 0,
        maximumMutations: 0,
        currentMutationCount: 0,
      },
      permissions: {
        allowDataMutation: false,
        allowExternalNetwork: false,
        allowSensitiveDataAccess: false,
        allowCodeExecution: false,
        allowFileSystemAccess: false,
      },
      upstreamGuardrail: {
        decision: 'ALLOW',
        ruleId: 'PROFILE.SQL_INJECTION.READ_ONLY',
      },
    },
  };
}

async function main() {
  const model = process.env.SLLM_MODEL || 'gemma4:e2b';

  const { checkPayloadWithSllm } = loadVerdictModule();
  const fixture = buildSafeFixture();
  const result = await checkPayloadWithSllm(
    fixture.receivedPayload,
    fixture.testContext,
    {
      endpoint: process.env.SLLM_ENDPOINT || 'http://127.0.0.1:11434',
      model,
      // 최초 모델 적재 시간을 고려한다. 운영값은 측정 후 낮춘다.
      timeoutMs: Number(process.env.SLLM_TIMEOUT_MS || 120000),
    },
  );

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.verdict === 'ERROR' ? 1 : 0;
}

main().catch(error => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});

