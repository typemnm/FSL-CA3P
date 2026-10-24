'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { buildSllmInput } = require('../src/payload-input');
const {
  JUDGMENT_CRITERIA,
  VULNERABILITY_GUIDELINES,
  buildJudgmentPrompt
} = require('../src/judgment-criteria');
const { makeErrorResult } = require('../src/error-result');
const { checkPayloadWithSllm, parseSllmOutput } = require('../src/sllm-verdict');

function makeSamplePayload() {
  return {
    operation: 'execute_curl',
    session: 'attacker',
    curl: {
      method: 'GET',
      url: 'http://127.0.0.1:4101/notices?q=test&id=1&id=2'
    }
  };
}

function makeTestContext() {
  return {
    targetSite: '대한대학교',
    stage: 'probe',
    requestPurpose: '공지사항 검색 기능의 SQL Injection 안전 테스트',
    approvedOrigins: ['http://127.0.0.1:4101'],
    approvedEndpoints: [
      {
        method: 'GET',
        path: '/notices'
      }
    ],
    approvedSessions: ['attacker'],
    approvedVulnerabilityProfiles: ['SQL_INJECTION'],
    fixtureIds: ['notice-fixture-1'],
    limits: {
      maximumRequests: 3,
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
    }
  };
}

function makeModelOutput(verdict) {
  let checkValue = true;

  if (verdict === 'UNCERTAIN') {
    checkValue = null;
  } else if (verdict === 'DENY') {
    checkValue = false;
  }

  return {
    verdict: verdict,
    vulnerabilityCategory: 'SQL_INJECTION',
    matchedProfile: 'SQL_INJECTION',
    checks: {
      profileMatched: checkValue,
      testDataOnly: checkValue,
      noDangerousImpact: checkValue,
      commonCriteriaSatisfied: checkValue
    },
    reason: '테스트를 위한 모델 판정입니다.',
    confidence: 0.95
  };
}

function makeFakeFetch(modelOutput) {
  return async function () {
    return {
      ok: true,
      status: 200,
      json: async function () {
        return {
          message: {
            content: JSON.stringify(modelOutput)
          }
        };
      }
    };
  };
}

test('1. 수신 페이로드를 sLLM 입력 JSON으로 구성한다', function () {
  const sllmInput = buildSllmInput(makeSamplePayload(), makeTestContext());

  assert.equal(sllmInput.schemaVersion, '2.0');
  assert.equal(sllmInput.testContext.stage, 'probe');
  assert.equal(sllmInput.request.method, 'GET');
  assert.equal(sllmInput.request.path, '/notices');
  assert.deepEqual(sllmInput.request.query.id, ['1', '2']);
  assert.equal(sllmInput.scopeChecks.approvedTarget, true);
  assert.equal(sllmInput.scopeChecks.approvedEndpoint, true);
  assert.equal(sllmInput.scopeChecks.approvedSession, true);
  assert.equal(sllmInput.scopeChecks.withinRequestLimit, true);
  assert.equal(sllmInput.scopeChecks.mutationAllowed, true);
  assert.equal(sllmInput.scopeChecks.networkAllowed, true);
});

test('2. 사용자가 정한 일곱 가지 판단 기준을 prompt에 넣는다', function () {
  const prompt = buildJudgmentPrompt();

  assert.equal(JUDGMENT_CRITERIA.length, 7);
  assert.match(prompt, /민감정보/);
  assert.match(prompt, /IN_SCOPE/);
  assert.match(prompt, /DENY/);
  assert.match(prompt, /UNCERTAIN/);
});

test('2. 웹사이트 취약점별 판단 지침을 prompt에 넣는다', function () {
  const prompt = buildJudgmentPrompt();

  assert.equal(VULNERABILITY_GUIDELINES.length, 14);
  assert.match(prompt, /ACCESS_CONTROL_IDOR/);
  assert.match(prompt, /SQL_INJECTION/);
  assert.match(prompt, /CVE-2020-8203/);
  assert.match(prompt, /CVE-2022-1471/);
  assert.match(prompt, /IN_SCOPE 조건/);
  assert.match(prompt, /DENY 조건/);
});

test('3. IN_SCOPE 판정만 실행을 허용한다', async function () {
  const result = await checkPayloadWithSllm(makeSamplePayload(), makeTestContext(), {
    endpoint: 'http://127.0.0.1:11434',
    model: 'local-guardrail-model',
    fetchFunction: makeFakeFetch(makeModelOutput('IN_SCOPE'))
  });

  assert.equal(result.verdict, 'IN_SCOPE');
  assert.equal(result.allowExecution, true);
});

test('3. DENY 판정은 실행을 차단한다', async function () {
  const result = await checkPayloadWithSllm(makeSamplePayload(), makeTestContext(), {
    endpoint: 'http://127.0.0.1:11434',
    model: 'local-guardrail-model',
    fetchFunction: makeFakeFetch(makeModelOutput('DENY'))
  });

  assert.equal(result.verdict, 'DENY');
  assert.equal(result.allowExecution, false);
});

test('3. UNCERTAIN 판정은 실행을 차단한다', async function () {
  const result = await checkPayloadWithSllm(makeSamplePayload(), makeTestContext(), {
    endpoint: 'http://127.0.0.1:11434',
    model: 'local-guardrail-model',
    fetchFunction: makeFakeFetch(makeModelOutput('UNCERTAIN'))
  });

  assert.equal(result.verdict, 'UNCERTAIN');
  assert.equal(result.allowExecution, false);
});

test('신뢰할 수 있는 테스트 범위가 없으면 ERROR로 차단한다', async function () {
  const result = await checkPayloadWithSllm(makeSamplePayload(), {}, {
    endpoint: 'http://127.0.0.1:11434',
    model: 'local-guardrail-model',
    fetchFunction: makeFakeFetch(makeModelOutput('IN_SCOPE'))
  });

  assert.equal(result.verdict, 'ERROR');
  assert.equal(result.reasonCode, 'INVALID_TEST_CONTEXT');
  assert.equal(result.allowExecution, false);
});

test('승인되지 않은 endpoint를 모델이 IN_SCOPE로 판정해도 차단한다', async function () {
  const testContext = makeTestContext();
  testContext.approvedEndpoints = [
    {
      method: 'GET',
      path: '/approved-only'
    }
  ];

  const result = await checkPayloadWithSllm(makeSamplePayload(), testContext, {
    endpoint: 'http://127.0.0.1:11434',
    model: 'local-guardrail-model',
    fetchFunction: makeFakeFetch(makeModelOutput('IN_SCOPE'))
  });

  assert.equal(result.verdict, 'ERROR');
  assert.equal(result.reasonCode, 'INVALID_SLLM_OUTPUT');
  assert.equal(result.allowExecution, false);
});

test('승인되지 않은 취약점 프로필을 모델이 선택하면 차단한다', async function () {
  const modelOutput = makeModelOutput('IN_SCOPE');
  modelOutput.vulnerabilityCategory = 'ACCESS_CONTROL_IDOR';
  modelOutput.matchedProfile = 'ACCESS_CONTROL_IDOR';

  const result = await checkPayloadWithSllm(
    makeSamplePayload(),
    makeTestContext(),
    {
      endpoint: 'http://127.0.0.1:11434',
      model: 'local-guardrail-model',
      fetchFunction: makeFakeFetch(modelOutput)
    }
  );

  assert.equal(result.verdict, 'ERROR');
  assert.equal(result.allowExecution, false);
});

test('고정 출력 JSON에 없는 verdict는 오류로 처리한다', function () {
  const invalidOutput = makeModelOutput('IN_SCOPE');
  invalidOutput.verdict = 'ALLOW';

  assert.throws(function () {
    parseSllmOutput({
      message: {
        content: JSON.stringify(invalidOutput)
      }
    });
  }, /알 수 없는 verdict/);
});

test('4. 모델 출력 JSON이 잘못되면 ERROR로 차단한다', async function () {
  const result = await checkPayloadWithSllm(makeSamplePayload(), makeTestContext(), {
    endpoint: 'http://127.0.0.1:11434',
    model: 'local-guardrail-model',
    fetchFunction: async function () {
      return {
        ok: true,
        status: 200,
        json: async function () {
          return { message: { content: 'JSON이 아닌 응답' } };
        }
      };
    }
  });

  assert.equal(result.verdict, 'ERROR');
  assert.equal(result.reasonCode, 'INVALID_SLLM_OUTPUT');
  assert.equal(result.allowExecution, false);
});

test('4. 알 수 없는 오류도 ERROR로 차단한다', function () {
  const result = makeErrorResult(new Error('예상하지 못한 오류'));

  assert.equal(result.verdict, 'ERROR');
  assert.equal(result.reasonCode, 'UNKNOWN_ERROR');
  assert.equal(result.allowExecution, false);
});

test('외부 sLLM 주소는 사용하지 않는다', async function () {
  const result = await checkPayloadWithSllm(makeSamplePayload(), makeTestContext(), {
    endpoint: 'https://model.example/api/chat',
    model: 'local-guardrail-model',
    fetchFunction: async function () {}
  });

  assert.equal(result.verdict, 'ERROR');
  assert.equal(result.reasonCode, 'INVALID_SLLM_ENDPOINT');
  assert.equal(result.allowExecution, false);
});
