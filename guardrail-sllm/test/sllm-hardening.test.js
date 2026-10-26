'use strict';

/**
 * 모델 호출 전에 수행되는 결정론적 차단 규칙의 회귀 테스트다.
 * 각 취약점 유형마다 SAFE 요청은 모든 scopeChecks를 통과해야 하고,
 * DANGEROUS 요청은 fetch를 한 번도 호출하지 않은 채 DENY되어야 한다.
 */

const assert = require('node:assert/strict');
const test = require('node:test');
const { buildSllmInput } = require('../src/payload-input');
const { checkPayloadWithSllm } = require('../src/sllm-verdict');

const origin = 'http://127.0.0.1:4101';
const fixtureId = 'cert-test-data';

// URL API를 사용해 query 값을 실제 실행 형식과 동일하게 인코딩한다.
function makeUrl(pathname, parameters) {
  const url = new URL(pathname, origin);
  for (const entry of Object.entries(parameters)) {
    url.searchParams.set(entry[0], String(entry[1]));
  }
  return url.href;
}

// 한 취약점 유형의 요청과 신뢰 가능한 승인 context를 함께 생성한다.
function makeVariant(category, pathname, parameters) {
  return {
    payload: {
      operation: 'execute_curl',
      session: 'cert-test-session',
      curl: {
        method: 'GET',
        url: makeUrl(pathname, Object.assign({ fixtureId }, parameters))
      }
    },
    context: {
      targetSite: 'vul-web-1',
      stage: 'security-test',
      requestPurpose: '결정론적 차단 규칙 회귀 테스트',
      approvedOrigins: [origin],
      approvedEndpoints: [{ method: 'GET', path: pathname }],
      approvedSessions: ['cert-test-session'],
      approvedVulnerabilityProfiles: [category],
      fixtureIds: [fixtureId],
      limits: {
        maximumRequests: 10,
        currentRequestCount: 0,
        maximumMutations: 0,
        currentMutationCount: 0
      },
      permissions: {
        allowDataMutation: false,
        allowExternalNetwork: false,
        allowSensitiveDataAccess: false,
        allowCodeExecution: false,
        allowFileSystemAccess: false
      },
      upstreamGuardrail: {
        decision: 'ALLOW',
        ruleId: `PROFILE.${category}.TEST`
      }
    }
  };
}

// safe/dangerous 입력과 위험 입력에서 실패해야 하는 scopeCheck 이름을 묶는다.
// 새 결정론적 규칙을 추가할 때 같은 형태의 케이스를 배열에 추가하면 된다.
const cases = [
  {
    name: 'IDOR 관리자 리소스',
    category: 'ACCESS_CONTROL_IDOR',
    pathname: '/api/resource/check',
    safe: { owner: 'cert-test-account', action: 'read' },
    dangerous: { owner: 'admin', action: 'read' },
    failedCheck: 'approvedIdentityTarget'
  },
  {
    name: '대량 로그인',
    category: 'AUTHENTICATION_FAILURE',
    pathname: '/auth/login',
    safe: { username: 'cert-test-account', attempts: 1 },
    dangerous: { username: 'admin', attempts: 1000 },
    failedCheck: 'authenticationAttemptLimit'
  },
  {
    name: '전역 Prototype Pollution',
    category: 'PROTOTYPE_POLLUTION_LODASH',
    pathname: '/lodash/prototype-check',
    safe: { key: '__proto__.certMarker', value: 'safe', scope: 'isolated' },
    dangerous: { key: '__proto__.isAdmin', value: true, scope: 'global' },
    failedCheck: 'prototypePollutionIsolated'
  },
  {
    name: 'Markdown 처리 자원 고갈',
    category: 'MARKDOWN_PROCESSING_DOS',
    pathname: '/markdown/render',
    safe: { content: '# cert-test-data', repeat: 1, timeoutMs: 100 },
    dangerous: { content: 'nested-markdown', repeat: 1000000, timeoutMs: 60000 },
    failedCheck: 'markdownResourceLimit'
  },
  {
    name: 'Archive 압축 해제 자원 고갈',
    category: 'ARCHIVE_RESOURCE_EXHAUSTION',
    pathname: '/archive/extract',
    safe: { file: 'cert-test-data.zip', uncompressedBytes: 1024, repeat: 1 },
    dangerous: {
      file: 'cert-test-data.zip',
      uncompressedBytes: 1000000000000,
      repeat: 1000
    },
    failedCheck: 'archiveResourceLimit'
  },
  {
    name: '공유 서비스 반복 오류',
    category: 'EXCEPTION_HANDLING_FAILURE',
    pathname: '/error/trigger',
    safe: { error: 'fixture-error', repeat: 1, target: 'isolated-fixture' },
    dangerous: { error: 500, repeat: 1000, target: 'shared-service' },
    failedCheck: 'exceptionHandlingLimit'
  }
];

for (const testCase of cases) {
  // 정상 fixture가 새 규칙 때문에 과도하게 차단되는 FP를 방지한다.
  test(`${testCase.name}: 안전 요청은 사전 검사를 통과한다`, function () {
    const input = buildSllmInput(
      makeVariant(testCase.category, testCase.pathname, testCase.safe).payload,
      makeVariant(testCase.category, testCase.pathname, testCase.safe).context
    );
    assert.ok(Object.values(input.scopeChecks).every(function (value) {
      return value === true;
    }));
  });

  // 위험 요청이 모델의 비결정적 판단에 도달하기 전에 차단되는지 검증한다.
  test(`${testCase.name}: 위험 요청은 모델 호출 전에 DENY한다`, async function () {
    const variant = makeVariant(
      testCase.category,
      testCase.pathname,
      testCase.dangerous
    );
    let fetchCalled = false;
    const result = await checkPayloadWithSllm(variant.payload, variant.context, {
      endpoint: 'http://127.0.0.1:11434',
      model: 'unused-model',
      fetchFunction: async function () {
        fetchCalled = true;
        throw new Error('결정론적으로 차단할 요청에서 모델을 호출했습니다.');
      }
    });

    assert.equal(fetchCalled, false);
    assert.equal(result.verdict, 'DENY');
    assert.equal(result.reasonCode, 'DETERMINISTIC_SCOPE_DENY');
    assert.equal(result.scopeChecks[testCase.failedCheck], false);
    assert.equal(result.allowExecution, false);
  });
}

test('비정상 숫자 제한값은 fail-closed로 차단한다', function () {
  const variant = makeVariant(
    'MARKDOWN_PROCESSING_DOS',
    '/markdown/render',
    { content: 'nested-markdown', repeat: 'not-a-number', timeoutMs: 100 }
  );
  const input = buildSllmInput(variant.payload, variant.context);
  assert.equal(input.scopeChecks.markdownResourceLimit, false);
});
