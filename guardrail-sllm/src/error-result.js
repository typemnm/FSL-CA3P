'use strict';

/**
 * 입력 검증, Ollama 통신, 모델 출력 검증 과정에서 발생한 예외를
 * 공통 ERROR 응답으로 변환한다. 오류 종류와 관계없이 실행은 항상 차단한다.
 */

// 프로그램에서 미리 예상하고 처리할 수 있는 오류 코드 목록이다.
// 목록에 없는 오류 코드는 UNKNOWN_ERROR로 처리한다.
const KNOWN_ERROR_CODES = [
  'INVALID_PAYLOAD',
  'INVALID_PAYLOAD_URL',
  'INVALID_JSON_VALUE',
  'INVALID_TEST_CONTEXT',
  'SLLM_INPUT_TOO_LARGE',
  'INVALID_MODEL',
  'INVALID_SLLM_ENDPOINT',
  'SLLM_TIMEOUT',
  'SLLM_CONNECTION_ERROR',
  'SLLM_HTTP_ERROR',
  'INVALID_SLLM_RESPONSE',
  'INVALID_SLLM_OUTPUT'
];

// sLLM 처리 중 발생한 오류를 정해진 JSON 형식으로 바꾸는 함수이다.
// 오류가 발생하면 안전한 요청인지 확인할 수 없으므로 실행을 허용하지 않는다.
function makeErrorResult(error) {
  // 오류 정보가 없거나 예상하지 못한 오류일 때 사용할 기본값이다.
  let reasonCode = 'UNKNOWN_ERROR';
  let reason = '알 수 없는 오류가 발생했습니다.';

  // 전달받은 오류 코드가 미리 정의한 목록에 있는지 확인한다.
  // 알려진 오류라면 해당 코드를 최종 결과에 사용한다.
  if (error && KNOWN_ERROR_CODES.includes(error.code)) {
    reasonCode = error.code;
  }

  // 오류에 읽을 수 있는 메시지가 있으면 기본 메시지 대신 사용한다.
  // error가 없는 경우도 있으므로 error의 존재 여부를 먼저 확인한다.
  if (error && typeof error.message === 'string' && error.message.length > 0) {
    reason = error.message;
  }

  // 모든 오류는 동일한 JSON 구조로 반환한다.
  // 정상적인 sLLM 판정이 아니므로 confidence는 0으로 설정한다.
  // allowExecution을 false로 설정하여 페이로드 실행을 차단한다.
  return {
    verdict: 'ERROR',
    reasonCode: reasonCode,
    reason: reason,
    confidence: 0,
    allowExecution: false
  };
}

// 다른 파일에서 makeErrorResult 함수를 사용할 수 있도록 내보낸다.
module.exports = {
  makeErrorResult
};
