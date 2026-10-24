'use strict';

// 다른 파일에서 필요한 기능을 가져온다.
// buildSllmInput: 수신 페이로드를 sLLM 판정용 JSON으로 구성한다.
const { buildSllmInput } = require('./payload-input');
// buildJudgmentPrompt: 판단 기준이 포함된 system message를 만든다.
const {
  VULNERABILITY_GUIDELINES,
  buildJudgmentPrompt
} = require('./judgment-criteria');
// makeErrorResult: 발생한 오류를 실행 차단 결과로 바꾼다.
const { makeErrorResult } = require('./error-result');

// sLLM이 5초 동안 응답하지 않으면 timeout 오류로 처리한다.
const DEFAULT_TIMEOUT_MS = 5000;

// sLLM이 정상적으로 반환할 수 있는 판정값 목록이다.
// ERROR는 모델의 정상 판정이 아니라 코드에서 오류 발생 시 만드는 결과이므로 제외한다.
const ALLOWED_VERDICTS = ['IN_SCOPE', 'DENY', 'UNCERTAIN'];
const ALLOWED_VULNERABILITY_CATEGORIES = VULNERABILITY_GUIDELINES.map(
  function (guideline) {
    return guideline.category;
  }
);

// 오류 코드와 오류 메시지를 함께 가진 Error 객체를 만드는 함수이다.
function createSllmError(errorCode, errorMessage) {
  const sllmError = new Error(errorMessage);
  sllmError.code = errorCode;
  return sllmError;
}

// 전달받은 값이 배열이 아닌 일반 JSON 객체인지 확인한다.
// null과 배열은 JSON 객체로 인정하지 않는다.
function isJsonObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value);
}

// sLLM 서버에 보낼 요청 JSON을 만든다.
function buildSllmRequestBody(sllmInput, modelName) {
  // 호출할 모델 이름이 없으면 어떤 모델을 사용할 수 없으므로 오류로 처리한다.
  if (typeof modelName !== 'string' || modelName.length === 0) {
    throw createSllmError('INVALID_MODEL', '사용할 로컬 sLLM 모델 이름이 필요합니다.');
  }

  // 로컬 Ollama의 /api/chat 형식에 맞는 요청 객체를 반환한다.
  return {
    // 로컬 서버에서 사용할 모델 이름이다.
    model: modelName,
    // 응답을 여러 조각으로 받지 않고 한 번에 받는다.
    stream: false,
    // 모델이 JSON 형식으로 답하도록 요청한다.
    format: 'json',
    options: {
      // 같은 입력에 가능한 한 일관된 판정을 내리도록 무작위성을 낮춘다.
      temperature: 0
    },
    messages: [
      {
        // system message에는 모델의 역할과 판단 기준을 넣는다.
        role: 'system',
        content: buildJudgmentPrompt()
      },
      {
        // user message에는 실제로 검사할 sLLM 입력 JSON을 넣는다.
        role: 'user',
        content: JSON.stringify(sllmInput)
      }
    ]
  };
}

// 설정으로 전달된 주소가 허용된 로컬 sLLM 주소인지 검사한다.
function getLocalSllmEndpoint(configuredEndpoint) {
  let endpointUrl;

  try {
    // 문자열 주소를 URL 객체로 바꿔 protocol과 hostname을 확인한다.
    endpointUrl = new URL(configuredEndpoint);
  } catch (error) {
    throw createSllmError('INVALID_SLLM_ENDPOINT', 'sLLM 서버 주소가 올바르지 않습니다.');
  }

  // 외부 서버로 페이로드가 전송되지 않도록 로컬 주소만 허용한다.
  const allowedHosts = ['127.0.0.1', 'localhost', '[::1]'];

  // 암호화된 외부 HTTPS 주소가 아니라 로컬 HTTP 주소만 사용한다.
  if (endpointUrl.protocol !== 'http:'
    || !allowedHosts.includes(endpointUrl.hostname)) {
    throw createSllmError(
      'INVALID_SLLM_ENDPOINT',
      'sLLM은 로컬 HTTP 주소만 사용할 수 있습니다.'
    );
  }

  // 사용자가 입력한 경로와 관계없이 Ollama chat API 경로를 사용한다.
  return new URL('/api/chat', endpointUrl.origin).href;
}

// 로컬 sLLM 서버를 호출한다.
async function sendToSllm(sllmInput, settings) {
  // 별도 설정이 전달되지 않은 경우 빈 객체를 사용한다.
  settings = settings || {};

  // 서버 주소를 검사하고 모델에 보낼 최종 요청 JSON을 만든다.
  const endpoint = getLocalSllmEndpoint(settings.endpoint);
  const requestBody = buildSllmRequestBody(sllmInput, settings.model);

  // 테스트에서는 가짜 fetch 함수를 사용할 수 있고,
  // 실제 실행에서는 Node.js의 기본 fetch 함수를 사용한다.
  const fetchFunction = settings.fetchFunction || globalThis.fetch;

  // 별도 timeout 값이 없으면 기본값인 5초를 사용한다.
  const timeoutMs = settings.timeoutMs || DEFAULT_TIMEOUT_MS;

  // 현재 실행 환경에서 HTTP 요청 함수를 사용할 수 있는지 확인한다.
  if (typeof fetchFunction !== 'function') {
    throw createSllmError('SLLM_CONNECTION_ERROR', 'HTTP 요청 기능을 사용할 수 없습니다.');
  }

  // AbortController는 timeout이 발생했을 때 실행 중인 HTTP 요청을 취소한다.
  const abortController = new AbortController();
  const timeoutId = setTimeout(function () {
    abortController.abort();
  }, timeoutMs);

  let response;

  try {
    // 판단 기준과 페이로드가 들어 있는 JSON을 로컬 sLLM에 POST로 전송한다.
    response = await fetchFunction(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify(requestBody),
      signal: abortController.signal
    });
  } catch (error) {
    // AbortController가 요청을 취소했다면 timeout 오류로 구분한다.
    if (error && error.name === 'AbortError') {
      throw createSllmError('SLLM_TIMEOUT', 'sLLM 응답 시간이 초과되었습니다.');
    }

    // timeout 이외의 요청 실패는 서버 연결 오류로 처리한다.
    throw createSllmError('SLLM_CONNECTION_ERROR', '로컬 sLLM 서버에 연결하지 못했습니다.');
  } finally {
    // 요청이 성공하거나 실패해도 예약한 timeout을 반드시 제거한다.
    clearTimeout(timeoutId);
  }

  // 서버가 200번대 성공 응답을 반환하지 않으면 HTTP 오류로 처리한다.
  if (!response.ok) {
    throw createSllmError(
      'SLLM_HTTP_ERROR',
      'sLLM 서버가 HTTP ' + response.status + ' 오류를 반환했습니다.'
    );
  }

  try {
    // sLLM 서버가 반환한 응답 본문을 JSON으로 읽는다.
    return await response.json();
  } catch (error) {
    throw createSllmError('INVALID_SLLM_RESPONSE', 'sLLM 서버 응답이 JSON 형식이 아닙니다.');
  }
}

// 모델 응답에서 content를 꺼내 JSON으로 읽는다.
function parseSllmOutput(sllmResponse) {
  // Ollama 응답에 message 객체와 문자열 content가 있는지 확인한다.
  if (!isJsonObject(sllmResponse)
    || !isJsonObject(sllmResponse.message)
    || typeof sllmResponse.message.content !== 'string') {
    throw createSllmError('INVALID_SLLM_RESPONSE', 'sLLM 응답 구조가 올바르지 않습니다.');
  }

  let modelOutput;

  try {
    // message.content는 JSON 모양의 문자열이므로 실제 객체로 변환한다.
    modelOutput = JSON.parse(sllmResponse.message.content);
  } catch (error) {
    throw createSllmError('INVALID_SLLM_OUTPUT', 'sLLM 판정 결과가 JSON 형식이 아닙니다.');
  }

  // JSON 변환에 성공한 뒤에도 필수 항목과 각 값의 형식을 검사한다.
  validateSllmOutput(modelOutput);
  return modelOutput;
}

// 모델이 고정된 출력 JSON 구조를 지켰는지 확인한다.
function validateSllmOutput(modelOutput) {
  // 모델 출력 전체가 일반 JSON 객체인지 확인한다.
  if (!isJsonObject(modelOutput)) {
    throw createSllmError('INVALID_SLLM_OUTPUT', 'sLLM 판정 결과는 JSON 객체여야 합니다.');
  }

  // 모델이 실제로 반환한 항목과 반드시 있어야 하는 항목을 구한다.
  const outputFields = Object.keys(modelOutput);
  const requiredFields = [
    'verdict',
    'vulnerabilityCategory',
    'matchedProfile',
    'checks',
    'reason',
    'confidence'
  ];

  // verdict, reason, confidence 중 빠진 항목이 있는지 확인한다.
  for (const fieldName of requiredFields) {
    if (!outputFields.includes(fieldName)) {
      throw createSllmError('INVALID_SLLM_OUTPUT', fieldName + ' 항목이 없습니다.');
    }
  }

  // 고정된 출력 구조에 없는 항목을 모델이 추가했는지 확인한다.
  for (const fieldName of outputFields) {
    if (!requiredFields.includes(fieldName)) {
      throw createSllmError('INVALID_SLLM_OUTPUT', '허용되지 않은 출력 항목이 있습니다.');
    }
  }

  // verdict는 IN_SCOPE, DENY, UNCERTAIN 중 하나만 허용한다.
  if (!ALLOWED_VERDICTS.includes(modelOutput.verdict)) {
    throw createSllmError('INVALID_SLLM_OUTPUT', '알 수 없는 verdict입니다.');
  }

  // vulnerabilityCategory는 프로젝트에 정의된 취약점 또는 UNKNOWN이어야 한다.
  if (typeof modelOutput.vulnerabilityCategory !== 'string'
    || (modelOutput.vulnerabilityCategory !== 'UNKNOWN'
      && !ALLOWED_VULNERABILITY_CATEGORIES.includes(
        modelOutput.vulnerabilityCategory
      ))) {
    throw createSllmError(
      'INVALID_SLLM_OUTPUT',
      '알 수 없는 vulnerabilityCategory입니다.'
    );
  }

  // matchedProfile은 승인 프로필 이름 또는 NONE을 담는 문자열이다.
  if (typeof modelOutput.matchedProfile !== 'string'
    || modelOutput.matchedProfile.length === 0) {
    throw createSllmError('INVALID_SLLM_OUTPUT', 'matchedProfile이 필요합니다.');
  }

  // 모델이 의미를 분석한 결과를 네 가지 check로 나눠 반환하게 한다.
  const requiredCheckNames = [
    'profileMatched',
    'testDataOnly',
    'noDangerousImpact',
    'commonCriteriaSatisfied'
  ];

  if (!isJsonObject(modelOutput.checks)) {
    throw createSllmError('INVALID_SLLM_OUTPUT', 'checks는 JSON 객체여야 합니다.');
  }

  const receivedCheckNames = Object.keys(modelOutput.checks);

  for (const checkName of requiredCheckNames) {
    if (!receivedCheckNames.includes(checkName)) {
      throw createSllmError('INVALID_SLLM_OUTPUT', checkName + ' 검사가 없습니다.');
    }

    const checkValue = modelOutput.checks[checkName];
    if (checkValue !== true && checkValue !== false && checkValue !== null) {
      throw createSllmError(
        'INVALID_SLLM_OUTPUT',
        checkName + '은 true, false 또는 null이어야 합니다.'
      );
    }
  }

  for (const checkName of receivedCheckNames) {
    if (!requiredCheckNames.includes(checkName)) {
      throw createSllmError('INVALID_SLLM_OUTPUT', '허용되지 않은 check가 있습니다.');
    }
  }

  // 사람이 판정 이유를 확인할 수 있도록 비어 있지 않은 reason이 필요하다.
  if (typeof modelOutput.reason !== 'string' || modelOutput.reason.length === 0) {
    throw createSllmError('INVALID_SLLM_OUTPUT', '판정 이유가 필요합니다.');
  }

  // confidence는 모델의 확신 정도를 나타내는 0부터 1 사이의 숫자여야 한다.
  if (typeof modelOutput.confidence !== 'number'
    || modelOutput.confidence < 0
    || modelOutput.confidence > 1) {
    throw createSllmError('INVALID_SLLM_OUTPUT', 'confidence는 0부터 1 사이의 숫자여야 합니다.');
  }

  // IN_SCOPE 판정은 취약점과 프로필이 분명하고 모든 의미 검사가 true여야 한다.
  if (modelOutput.verdict === 'IN_SCOPE') {
    if (modelOutput.vulnerabilityCategory === 'UNKNOWN'
      || modelOutput.matchedProfile === 'NONE') {
      throw createSllmError(
        'INVALID_SLLM_OUTPUT',
        'IN_SCOPE에는 분류된 취약점과 승인 프로필이 필요합니다.'
      );
    }

    for (const checkName of requiredCheckNames) {
      if (modelOutput.checks[checkName] !== true) {
        throw createSllmError(
          'INVALID_SLLM_OUTPUT',
          'IN_SCOPE의 모든 check는 true여야 합니다.'
        );
      }
    }
  }
}

// 정상 판정 결과에 실제 실행 허용 여부를 추가한다.
function makeDecisionResult(modelOutput, sllmInput) {
  // origin, endpoint, session, 요청 한도 등의 코드 검사 결과를 확인한다.
  const scopeCheckValues = Object.values(sllmInput.scopeChecks);
  const allScopeChecksPassed = scopeCheckValues.every(function (checkValue) {
    return checkValue === true;
  });

  // 모델이 반환한 취약점별 의미 검사 결과를 확인한다.
  const modelCheckValues = Object.values(modelOutput.checks);
  const allModelChecksPassed = modelCheckValues.every(function (checkValue) {
    return checkValue === true;
  });

  // 모델이 선택한 프로필이 신뢰 가능한 테스트 범위에 실제로 포함되는지 확인한다.
  const profileIsApproved = sllmInput.testContext
    .approvedVulnerabilityProfiles.includes(modelOutput.matchedProfile);

  // 현재 프로필 이름은 취약점 category를 사용하므로 두 값도 일치해야 한다.
  const categoryMatchesProfile = modelOutput.vulnerabilityCategory
    === modelOutput.matchedProfile;

  const executionIsSafe = allScopeChecksPassed
    && allModelChecksPassed
    && profileIsApproved
    && categoryMatchesProfile;

  // 모델이 IN_SCOPE라고 했지만 코드 검사 결과가 다르면 모델 출력을 신뢰하지 않는다.
  if (modelOutput.verdict === 'IN_SCOPE' && !executionIsSafe) {
    throw createSllmError(
      'INVALID_SLLM_OUTPUT',
      'IN_SCOPE 판정이 승인된 테스트 범위와 일치하지 않습니다.'
    );
  }

  return {
    verdict: modelOutput.verdict,
    vulnerabilityCategory: modelOutput.vulnerabilityCategory,
    matchedProfile: modelOutput.matchedProfile,
    scopeChecks: sllmInput.scopeChecks,
    checks: modelOutput.checks,
    reason: modelOutput.reason,
    confidence: modelOutput.confidence,
    // 안전하다고 확실하게 판정된 IN_SCOPE만 실행을 허용한다.
    // DENY와 UNCERTAIN은 모두 false가 되어 실행이 차단된다.
    allowExecution: modelOutput.verdict === 'IN_SCOPE' && executionIsSafe
  };
}

// 입력부터 판정까지 실행한다. 어느 단계에서든 오류가 나면 ERROR로 차단한다.
async function checkPayloadWithSllm(receivedPayload, testContext, settings) {
  try {
    // 1. 수신된 페이로드를 sLLM 판정용 JSON으로 구성한다.
    const sllmInput = buildSllmInput(receivedPayload, testContext);

    // 2. 판정용 JSON과 판단 기준을 로컬 sLLM에 전달한다.
    const sllmResponse = await sendToSllm(sllmInput, settings);

    // 3. 모델의 응답을 JSON으로 읽고 고정 출력 구조를 검사한다.
    const modelOutput = parseSllmOutput(sllmResponse);

    // 4. 최종 판정과 페이로드 실행 허용 여부를 반환한다.
    return makeDecisionResult(modelOutput, sllmInput);
  } catch (error) {
    // 어느 단계에서든 오류가 발생하면 ERROR 결과를 만들고 실행을 차단한다.
    return makeErrorResult(error);
  }
}

// 다른 파일과 테스트 코드에서 사용할 함수들을 내보낸다.
module.exports = {
  buildSllmRequestBody,
  checkPayloadWithSllm,
  makeDecisionResult,
  parseSllmOutput,
  sendToSllm,
  validateSllmOutput
};
