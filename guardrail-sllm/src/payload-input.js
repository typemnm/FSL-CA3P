'use strict';

// sLLM에 전달할 입력 JSON의 최대 크기이다.
// 16 * 1024는 16 KiB를 byte 단위로 나타낸 값이다.
// 너무 큰 입력으로 모델이나 서버에 부담을 주는 것을 막는다.
const MAX_INPUT_BYTES = 16 * 1024;
const MUTATION_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

// 오류 메시지와 오류 코드를 함께 가진 Error 객체를 만드는 함수이다.
// errorCode는 나중에 error-result.js에서 오류 종류를 구분할 때 사용한다.
function createInputError(errorCode, errorMessage) {
  const inputError = new Error(errorMessage);
  inputError.code = errorCode;
  return inputError;
}

// 전달받은 값이 배열이 아닌 일반 JSON 객체인지 확인한다.
// null과 배열도 JavaScript에서는 typeof 결과가 object이므로 따로 제외한다.
function isJsonObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value);
}

// JSON 객체에 허용된 항목만 들어 있는지 확인한다.
// 예를 들어 curl 객체에는 method, url, body만 허용한다.
function checkAllowedFields(jsonObject, allowedFieldNames) {
  // Object.keys()는 객체가 가진 항목의 이름을 배열로 반환한다.
  const receivedFieldNames = Object.keys(jsonObject);

  // 수신된 항목 이름을 하나씩 확인한다.
  for (const fieldName of receivedFieldNames) {
    // 허용 목록에 없는 항목을 하나라도 발견하면 false를 반환한다.
    if (!allowedFieldNames.includes(fieldName)) {
      return false;
    }
  }

  // 모든 항목이 허용 목록에 있으면 true를 반환한다.
  return true;
}

// body 등의 값을 JSON으로 복사하는 함수이다.
// 원본 객체를 직접 사용하지 않아 이후 원본이 변경되는 영향을 줄인다.
function copyJsonValue(value, fieldName) {
  try {
    // 값을 JSON 문자열로 바꾼 다음 다시 객체로 바꿔 새로운 값을 만든다.
    const jsonText = JSON.stringify(value);

    // 함수나 undefined처럼 JSON 문자열로 바꿀 수 없는 값은 거부한다.
    if (jsonText === undefined) {
      throw new Error('JSON으로 바꿀 수 없는 값입니다.');
    }

    return JSON.parse(jsonText);
  } catch (error) {
    // JSON 변환 중 문제가 생기면 정해진 입력 오류로 바꿔서 전달한다.
    throw createInputError(
      'INVALID_JSON_VALUE',
      fieldName + '에는 JSON 형식의 값만 사용할 수 있습니다.'
    );
  }
}

// 수신된 페이로드가 프로젝트에서 사용하는 기본 형식인지 확인한다.
function validatePayload(receivedPayload) {
  // 페이로드 전체가 일반 JSON 객체인지 확인한다.
  if (!isJsonObject(receivedPayload)) {
    throw createInputError('INVALID_PAYLOAD', '페이로드는 JSON 객체여야 합니다.');
  }

  // 최상위 객체에는 operation, session, curl만 들어올 수 있다.
  // 예상하지 못한 항목은 조용히 무시하지 않고 오류로 처리한다.
  const allowedPayloadFields = ['operation', 'session', 'curl'];
  if (!checkAllowedFields(receivedPayload, allowedPayloadFields)) {
    throw createInputError('INVALID_PAYLOAD', '페이로드에 허용되지 않은 항목이 있습니다.');
  }

  // 현재 가드레일은 curl 실행 요청만 처리한다.
  if (receivedPayload.operation !== 'execute_curl') {
    throw createInputError('INVALID_PAYLOAD', 'operation은 execute_curl이어야 합니다.');
  }

  // 어떤 세션에서 보낸 요청인지 확인할 수 있도록 빈 문자열을 허용하지 않는다.
  if (typeof receivedPayload.session !== 'string'
    || receivedPayload.session.length === 0) {
    throw createInputError('INVALID_PAYLOAD', 'session이 필요합니다.');
  }

  // HTTP 요청 정보가 들어 있는 curl도 일반 JSON 객체여야 한다.
  if (!isJsonObject(receivedPayload.curl)) {
    throw createInputError('INVALID_PAYLOAD', 'curl은 JSON 객체여야 합니다.');
  }

  // curl 객체에는 method, url, 선택 항목인 body만 허용한다.
  const allowedCurlFields = ['method', 'url', 'body'];
  if (!checkAllowedFields(receivedPayload.curl, allowedCurlFields)) {
    throw createInputError('INVALID_PAYLOAD', 'curl에 허용되지 않은 항목이 있습니다.');
  }

  // HTTP method는 GET, POST 등의 요청 방식을 나타낸다.
  // 이 단계에서는 문자열인지와 비어 있지 않은지만 확인한다.
  if (typeof receivedPayload.curl.method !== 'string'
    || receivedPayload.curl.method.length === 0) {
    throw createInputError('INVALID_PAYLOAD', 'HTTP method가 필요합니다.');
  }

  // sLLM이 요청 대상을 판단할 수 있도록 URL이 반드시 필요하다.
  if (typeof receivedPayload.curl.url !== 'string'
    || receivedPayload.curl.url.length === 0) {
    throw createInputError('INVALID_PAYLOAD', '요청 URL이 필요합니다.');
  }
}

// 문자열 배열인지 확인한다.
function isStringArray(value) {
  if (!Array.isArray(value) || value.length === 0) {
    return false;
  }

  for (const item of value) {
    if (typeof item !== 'string' || item.length === 0) {
      return false;
    }
  }

  return true;
}

// approvedEndpoints가 { method, path } 형태의 배열인지 확인한다.
function validateApprovedEndpoints(approvedEndpoints) {
  if (!Array.isArray(approvedEndpoints) || approvedEndpoints.length === 0) {
    throw createInputError(
      'INVALID_TEST_CONTEXT',
      'approvedEndpoints에는 승인된 endpoint가 하나 이상 필요합니다.'
    );
  }

  for (const endpoint of approvedEndpoints) {
    if (!isJsonObject(endpoint)
      || !checkAllowedFields(endpoint, ['method', 'path'])
      || typeof endpoint.method !== 'string'
      || endpoint.method.length === 0
      || typeof endpoint.path !== 'string'
      || endpoint.path.length === 0) {
      throw createInputError(
        'INVALID_TEST_CONTEXT',
        'approvedEndpoints의 각 항목에는 method와 path가 필요합니다.'
      );
    }
  }
}

// 요청 횟수와 데이터 변경 횟수 제한이 올바른 숫자인지 확인한다.
function validateLimits(limits) {
  if (!isJsonObject(limits)
    || !Number.isInteger(limits.maximumRequests)
    || !Number.isInteger(limits.currentRequestCount)
    || !Number.isInteger(limits.maximumMutations)
    || !Number.isInteger(limits.currentMutationCount)
    || limits.maximumRequests < 1
    || limits.currentRequestCount < 0
    || limits.maximumMutations < 0
    || limits.currentMutationCount < 0) {
    throw createInputError(
      'INVALID_TEST_CONTEXT',
      'limits에는 올바른 요청 및 변경 횟수 제한이 필요합니다.'
    );
  }
}

// 위험한 기능을 허용하는지 나타내는 값이 모두 boolean인지 확인한다.
function validatePermissions(permissions) {
  const requiredPermissionNames = [
    'allowDataMutation',
    'allowExternalNetwork',
    'allowSensitiveDataAccess',
    'allowCodeExecution',
    'allowFileSystemAccess'
  ];

  if (!isJsonObject(permissions)
    || !checkAllowedFields(permissions, requiredPermissionNames)) {
    throw createInputError(
      'INVALID_TEST_CONTEXT',
      'permissions 형식이 올바르지 않습니다.'
    );
  }

  for (const permissionName of requiredPermissionNames) {
    if (typeof permissions[permissionName] !== 'boolean') {
      throw createInputError(
        'INVALID_TEST_CONTEXT',
        permissionName + '에는 true 또는 false가 필요합니다.'
      );
    }
  }
}

// Orchestrator 또는 Gateway가 전달한 신뢰 가능한 테스트 범위를 검사한다.
// 페이로드 자체에서 이 정보를 가져오면 공격자가 승인 범위를 바꿀 수 있으므로
// receivedPayload와 별도의 매개변수로 전달받는다.
function validateTestContext(testContext) {
  if (!isJsonObject(testContext)) {
    throw createInputError(
      'INVALID_TEST_CONTEXT',
      '신뢰할 수 있는 테스트 범위 정보가 필요합니다.'
    );
  }

  const allowedContextFields = [
    'targetSite',
    'stage',
    'requestPurpose',
    'approvedOrigins',
    'approvedEndpoints',
    'approvedSessions',
    'approvedVulnerabilityProfiles',
    'fixtureIds',
    'limits',
    'permissions'
  ];

  if (!checkAllowedFields(testContext, allowedContextFields)) {
    throw createInputError(
      'INVALID_TEST_CONTEXT',
      '테스트 범위 정보에 허용되지 않은 항목이 있습니다.'
    );
  }

  if (typeof testContext.targetSite !== 'string'
    || testContext.targetSite.length === 0) {
    throw createInputError('INVALID_TEST_CONTEXT', 'targetSite가 필요합니다.');
  }

  if (!isStringArray(testContext.approvedOrigins)) {
    throw createInputError('INVALID_TEST_CONTEXT', 'approvedOrigins가 필요합니다.');
  }

  validateApprovedEndpoints(testContext.approvedEndpoints);

  if (!isStringArray(testContext.approvedSessions)) {
    throw createInputError('INVALID_TEST_CONTEXT', 'approvedSessions가 필요합니다.');
  }

  if (!isStringArray(testContext.approvedVulnerabilityProfiles)) {
    throw createInputError(
      'INVALID_TEST_CONTEXT',
      'approvedVulnerabilityProfiles가 필요합니다.'
    );
  }

  if (!Array.isArray(testContext.fixtureIds)) {
    throw createInputError('INVALID_TEST_CONTEXT', 'fixtureIds는 배열이어야 합니다.');
  }

  validateLimits(testContext.limits);
  validatePermissions(testContext.permissions);
}

// 코드로 정확히 비교할 수 있는 승인 범위 조건을 먼저 계산한다.
function buildScopeChecks(receivedPayload, requestUrl, testContext) {
  const requestMethod = receivedPayload.curl.method.toUpperCase();
  const requestPath = requestUrl.pathname;

  const endpointIsApproved = testContext.approvedEndpoints.some(function (endpoint) {
    return endpoint.method.toUpperCase() === requestMethod
      && endpoint.path === requestPath;
  });

  const requestLimitIsValid = testContext.limits.currentRequestCount
    < testContext.limits.maximumRequests;

  const isMutationRequest = MUTATION_METHODS.includes(requestMethod);
  let mutationIsApproved = true;

  if (isMutationRequest) {
    mutationIsApproved = testContext.permissions.allowDataMutation
      && testContext.limits.currentMutationCount
        < testContext.limits.maximumMutations;
  }

  // 로컬 주소는 외부 네트워크 요청으로 보지 않는다.
  // 로컬 주소가 아니라면 permissions에서 외부 네트워크가 허용된 경우만 통과한다.
  const localHostNames = ['127.0.0.1', 'localhost', '[::1]'];
  const networkIsApproved = localHostNames.includes(requestUrl.hostname)
    || testContext.permissions.allowExternalNetwork;

  return {
    approvedTarget: testContext.approvedOrigins.includes(requestUrl.origin),
    approvedEndpoint: endpointIsApproved,
    approvedSession: testContext.approvedSessions.includes(receivedPayload.session),
    withinRequestLimit: requestLimitIsValid,
    mutationAllowed: mutationIsApproved,
    networkAllowed: networkIsApproved
  };
}

// URLSearchParams를 sLLM이 읽기 쉬운 일반 JSON 객체로 바꾼다.
// 예: ?name=test&id=1&id=2 -> { name: 'test', id: ['1', '2'] }
function makeQueryObject(searchParameters) {
  const query = {};

  // URL에 들어 있는 query parameter를 하나씩 꺼낸다.
  for (const queryEntry of searchParameters.entries()) {
    const queryName = queryEntry[0];
    const queryValue = queryEntry[1];

    // 같은 이름이 처음 나오면 문자열 값으로 저장한다.
    if (query[queryName] === undefined) {
      query[queryName] = queryValue;
    // 같은 이름의 값이 이미 배열이면 새로운 값을 배열 뒤에 추가한다.
    } else if (Array.isArray(query[queryName])) {
      query[queryName].push(queryValue);
    // 같은 이름이 두 번째로 나오면 기존 값과 새로운 값을 배열로 만든다.
    } else {
      query[queryName] = [query[queryName], queryValue];
    }
  }

  return query;
}

// 수신된 페이로드를 sLLM이 판정할 JSON 객체로 구성한다.
function buildSllmInput(receivedPayload, testContext) {
  // JSON을 구성하기 전에 페이로드의 기본 구조부터 검사한다.
  validatePayload(receivedPayload);

  // 승인 범위 정보가 빠지거나 잘못된 경우 모델에 전달하지 않는다.
  validateTestContext(testContext);

  let requestUrl;

  try {
    // URL 문자열을 URL 객체로 바꿔 protocol, origin, path 등을 분리한다.
    requestUrl = new URL(receivedPayload.curl.url);
  } catch (error) {
    throw createInputError('INVALID_PAYLOAD_URL', '요청 URL 형식이 올바르지 않습니다.');
  }

  // 페이로드의 HTTP 요청 정보를 sLLM이 확인하기 쉬운 구조로 정리한다.
  const requestInformation = {
    operation: 'http_request',
    session: receivedPayload.session,
    // method 표기를 GET, POST처럼 통일하기 위해 대문자로 바꾼다.
    method: receivedPayload.curl.method.toUpperCase(),
    // rawUrl은 입력으로 받은 원본 URL을 그대로 보관한다.
    rawUrl: receivedPayload.curl.url,
    protocol: requestUrl.protocol,
    origin: requestUrl.origin,
    path: requestUrl.pathname,
    query: makeQueryObject(requestUrl.searchParams)
  };

  // body는 선택 항목이므로 실제로 전달된 경우에만 추가한다.
  if (receivedPayload.curl.body !== undefined) {
    requestInformation.body = copyJsonValue(receivedPayload.curl.body, 'body');
  }

  // origin, endpoint, session, 요청 한도처럼 코드로 정확히 비교할 수 있는
  // 조건은 모델에 맡기지 않고 미리 true 또는 false로 계산한다.
  const scopeChecks = buildScopeChecks(receivedPayload, requestUrl, testContext);

  // 테스트 범위 정보와 실제 요청 정보를 하나의 판정용 JSON으로 구성한다.
  // sLLM은 testContext와 request를 함께 보고 안전 여부를 판단한다.
  const sllmInput = {
    schemaVersion: '2.0',
    testContext: copyJsonValue(testContext, 'testContext'),
    request: requestInformation,
    scopeChecks: scopeChecks
  };

  // 완성된 입력을 JSON 문자열로 바꿨을 때의 실제 byte 크기를 계산한다.
  const inputSize = Buffer.byteLength(JSON.stringify(sllmInput), 'utf8');

  // 정해진 최대 크기를 넘으면 모델에 전달하지 않고 오류로 처리한다.
  if (inputSize > MAX_INPUT_BYTES) {
    throw createInputError('SLLM_INPUT_TOO_LARGE', 'sLLM 입력은 16 KiB를 넘을 수 없습니다.');
  }

  // 모든 검사와 구성이 끝난 sLLM 판정용 JSON 객체를 반환한다.
  return sllmInput;
}

// 다른 파일에서 입력 구성 함수와 검증 함수를 사용할 수 있도록 내보낸다.
module.exports = {
  buildScopeChecks,
  buildSllmInput,
  validatePayload,
  validateTestContext
};
