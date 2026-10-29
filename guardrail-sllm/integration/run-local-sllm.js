'use strict';

/**
 * 로컬 Ollama와 guardrail-sllm의 실제 통신을 한 건으로 확인하는 실행기다.
 * 판정 결과만 출력하며 요청 URL로 실제 HTTP 공격을 전송하지 않는다.
 *
 * 환경 변수:
 * - SLLM_MODULE_DIR: 기본 src 디렉터리 대신 사용할 모듈 경로
 * - SLLM_MODEL: Ollama 모델명(기본 gemma4:e2b)
 * - SLLM_ENDPOINT: Ollama 주소(기본 localhost:11434)
 * - SLLM_TIMEOUT_MS: 응답 제한시간
 */

const path = require('node:path');

const DEFAULT_MODULE_DIRECTORY = path.resolve(__dirname, '..', 'src');

// 저장소 기본 src 또는 환경 변수로 지정한 구현을 동적으로 로드한다.
// 같은 실행기로 다른 체크아웃의 sLLM 구현도 검증할 수 있게 한다.
function loadVerdictModule() {
  const moduleDirectory = process.env.SLLM_MODULE_DIR || DEFAULT_MODULE_DIRECTORY;
  const modulePath = path.join(moduleDirectory, 'sllm-verdict.js');
  return require(modulePath);
}

// 실제 서비스 데이터 대신 승인된 fixture만 사용하는 읽기 전용 SQLi 예제를 만든다.
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
      targetSite: 'sllm-cert-fixture',
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
  // 환경 변수가 없으면 현재 프로젝트에서 검증한 기본 로컬 모델을 사용한다.
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

  // 사람이 evidence와 scopeChecks를 확인할 수 있도록 들여쓴 JSON을 출력한다.
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  // ERROR는 연동 실패이므로 프로세스 실패 코드로 반환한다.
  process.exitCode = result.verdict === 'ERROR' ? 1 : 0;
}

main().catch(error => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});

