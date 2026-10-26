# sLLM Guardrail

수신된 공격 페이로드를 로컬 sLLM으로 검사하고, 안전하다고 확실하게 판정된 요청만 실행하도록 허용하는 독립 모듈입니다.

기존 가드레일의 판정 결과를 `testContext.upstreamGuardrail`로 받아 함께 사용합니다.
기존 가드레일이 `DENY`한 요청은 sLLM이 다시 허용할 수 없습니다.

## 네 가지 기능 파일

| 파일 | 기능 |
| --- | --- |
| `src/payload-input.js` | 수신된 JSON 페이로드를 검사하고 sLLM 판정용 JSON으로 구성합니다. |
| `src/judgment-criteria.js` | CERT 안전 테스트 판단 기준과 sLLM 판정 방법을 정의합니다. |
| `src/sllm-verdict.js` | 로컬 sLLM을 호출하고 `IN_SCOPE`, `DENY`, `UNCERTAIN` 판정을 처리합니다. |
| `src/error-result.js` | 타임아웃, 통신 실패, 잘못된 JSON 등의 오류를 `ERROR` 차단 결과로 만듭니다. |
| `test/` | Ollama 없이 실행 가능한 단위·모의 연동 테스트입니다. |
| `integration/` | 실제 Ollama 연동 및 취약점 매트릭스입니다. |

## 실행 흐름

```text
페이로드 수신
  -> 신뢰 가능한 테스트 범위 검사
  -> 기존 가드레일 결과, origin, endpoint, session, fixture, 요청 한도를 코드로 비교
  -> 명확한 위험 조건을 모델 호출 전에 DENY
  -> sLLM이 취약점 유형 분류
  -> 취약점별 조건과 공통 판단 기준 비교
  -> 고정된 출력 JSON과 세부 check 검사
  -> 모든 검사에 통과한 IN_SCOPE만 실행 허용
  -> DENY / UNCERTAIN / ERROR는 실행 차단
```

## 입력 형식

```json
{
  "operation": "execute_curl",
  "session": "attacker",
  "curl": {
    "method": "GET",
    "url": "http://127.0.0.1:4101/notices?q=test",
    "body": {}
  }
}
```

## sLLM의 고정 출력 JSON

```json
{
  "verdict": "IN_SCOPE",
  "vulnerabilityCategory": "SQL_INJECTION",
  "matchedProfile": "SQL_INJECTION",
  "evidence": [
    {
      "source": "query",
      "key": "q",
      "value": "' OR 1=1--"
    }
  ],
  "checks": {
    "profileMatched": true,
    "testDataOnly": true,
    "noDangerousImpact": true,
    "commonCriteriaSatisfied": true
  },
  "reason": "승인된 범위 안의 안전한 테스트입니다.",
  "confidence": 0.95
}
```

- `verdict`는 `IN_SCOPE`, `DENY`, `UNCERTAIN` 중 하나여야 합니다.
- `vulnerabilityCategory`는 sLLM이 분류한 취약점 유형입니다.
- `matchedProfile`은 승인 범위와 일치한 취약점 프로필입니다.
- `evidence`는 모델이 실제 요청에서 찾은 구조화된 판단 근거입니다.
- `source`는 `path`, `query`, `body` 중 하나입니다.
- `key`는 실제 필드 이름이며, 중첩 body는 `user.name`처럼 점 표기법을 사용합니다.
- `value`는 요청 JSON에 들어 있는 실제 타입과 값을 그대로 사용합니다.
- evidence가 하나라도 실제 요청과 다르면 `IN_SCOPE`를 `UNCERTAIN`으로 변경합니다.
- `checks`는 프로필, 테스트 데이터, 위험한 영향, 공통 기준 검사 결과입니다.
- `reason`은 판정 이유입니다.
- `confidence`는 `0`부터 `1` 사이의 숫자입니다.
- 구조가 다르거나 값을 읽을 수 없으면 `ERROR`로 차단합니다.

## 사용 예시

```js
const { checkPayloadWithSllm } = require('./src/sllm-verdict');

const trustedTestContext = {
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
  },
  upstreamGuardrail: {
    decision: 'ALLOW',
    ruleId: 'PROFILE.SQL_INJECTION.READ_ONLY'
  }
};

const sllmSettings = {
  endpoint: 'http://127.0.0.1:11434',
  model: 'local-guardrail-model'
};

const result = await checkPayloadWithSllm(
  payload,
  trustedTestContext,
  sllmSettings
);

if (result.allowExecution) {
  // 페이로드 실행
} else {
  // 페이로드 차단
}
```

## 테스트

```bash
cd guardrail-sllm
npm test
```

위 명령은 Ollama 없이 실행됩니다. 로컬 Ollama와 `gemma4:e2b`를 이용한 실제
연동 테스트는 다음처럼 별도로 실행합니다.

```bash
npm run ollama:check
npm run test:ollama:core
npm run test:ollama
```

통합 테스트는 판정만 수행하며 실제 대상 서버에 공격 요청을 보내지 않습니다.

## 현재 추가된 결정론적 제한

- 관리자·실사용자 대상 IDOR 또는 인증 테스트 차단
- 인증 시도 5회 초과 차단
- 전역 또는 권한 관련 Prototype Pollution 차단
- Markdown 반복 100회 또는 처리시간 5,000ms 초과 차단
- 압축 해제 반복 10회, 예상 크기 100MiB, 엔트리 10,000개 초과 차단
- 예외 처리 테스트 반복 10회 초과 또는 공유·운영 서비스 대상 차단

모델 출력의 `evidence`는 자유 문자열을 허용하지 않습니다. 모든 항목이
`source`, `key`, `value`만 가진 객체여야 하며 실제 요청과 정확히 일치해야 합니다.
