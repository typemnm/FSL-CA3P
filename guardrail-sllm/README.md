# sLLM Guardrail

수신된 공격 페이로드를 로컬 sLLM으로 검사하고, 안전하다고 확실하게 판정된 요청만 실행하도록 허용하는 독립 모듈입니다.

기존 1차 `guardrail` 코드는 import하거나 수정하지 않습니다.

## 네 가지 기능 파일

| 파일 | 기능 |
| --- | --- |
| `src/payload-input.js` | 수신된 JSON 페이로드를 검사하고 sLLM 판정용 JSON으로 구성합니다. |
| `src/judgment-criteria.js` | CERT 안전 테스트 판단 기준과 sLLM 판정 방법을 정의합니다. |
| `src/sllm-verdict.js` | 로컬 sLLM을 호출하고 `IN_SCOPE`, `DENY`, `UNCERTAIN` 판정을 처리합니다. |
| `src/error-result.js` | 타임아웃, 통신 실패, 잘못된 JSON 등의 오류를 `ERROR` 차단 결과로 만듭니다. |

## 실행 흐름

```text
페이로드 수신
  -> 신뢰 가능한 테스트 범위 검사
  -> origin, endpoint, session, 요청 한도를 코드로 비교
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
