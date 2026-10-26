'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { buildSllmInput } = require('../src/payload-input');
const { checkPayloadWithSllm } = require('../src/sllm-verdict');

const origin = 'http://127.0.0.1:4101';
const fixtureId = 'cert-test-data';

function makeUrl(pathname, parameters) {
  const url = new URL(pathname, origin);
  for (const entry of Object.entries(parameters)) {
    url.searchParams.set(entry[0], String(entry[1]));
  }
  return url.href;
}

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
  test(`${testCase.name}: 안전 요청은 사전 검사를 통과한다`, function () {
    const input = buildSllmInput(
      makeVariant(testCase.category, testCase.pathname, testCase.safe).payload,
      makeVariant(testCase.category, testCase.pathname, testCase.safe).context
    );
    assert.ok(Object.values(input.scopeChecks).every(function (value) {
      return value === true;
    }));
  });

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
