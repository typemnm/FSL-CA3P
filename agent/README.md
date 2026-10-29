# CA3P 펜테스팅 에이전트 코어

## 범용 점검 코어와 운영 연결

`src/general-assessment.js`의 `runGeneralAssessment()`는 범용 판단 루프다. 호출자가 `observer.observe`, `planner.propose`, `policy.authorize`, `executor.execute`, `verifier.verify` 포트를 제공한다. 코어는 관측 증거를 바탕으로 여러 가설과 검사를 반복하고, 허용 도구·반복·검사·증거 예산을 확인한다. 정책을 거부한 검사는 실행하지 않으며, 완료된 검사의 독립 증거가 없으면 `confirmed`나 `not_reproduced`로 판정하지 않는다. 결과에는 `findings[]`, 미점검 수, 증거 출처와 종료 사유를 남긴다.

`src/general-model-planner.js`는 기존 DeepSeek 클라이언트를 사용하는 구조화 플래너다. `createGeneralModelPlannerFromEnv()`를 선택해 호출하면 실제 모델 API를 사용한다. 대상 페이지와 관측 자료는 비신뢰 데이터로 취급하고, 허용된 도구·증거 ID를 벗어난 출력은 거부한다. 문맥이 모델 입력 한도를 넘으면 자료를 조용히 생략하지 않고 오류를 반환한다.

범용 점검은 운영 경로의 API → 실행 서비스 → worker → `apps/application/general-runtime.mjs`를 통해 두 대학 실습 대상에 연결돼 있다. 외부 URL은 별도 읽기 전용 관찰 경로에서 처리한다. 에이전트 모듈은 판단 코어와 모델 플래너를 제공하고, 대상 요청·실행 정책·독립 검증과 실행 상태 저장은 런타임이 담당한다. 범용 런타임에는 브라우저 실행을 확인하는 도구가 없어서 브라우저 증거가 필요한 XSS는 확정으로 표시하지 않는다.

코어의 `onEvent`는 `observe`, `plan`, `policy`, `execute`, `verify`, `complete` 단계와 반복 번호를 보낸다. 계획 이벤트에는 가설·검사 ID와 도구 연결, 가설의 분류·자산이 있고, 관측·실행 이벤트에는 새 증거의 유형·자산이 있다. 검사 이벤트에는 가설·검사 ID, 도구, 판정 상태, 증거 ID 참조가 있다. 모든 이벤트의 `progress`는 가설·검사·증거 수와 **검사별** 판정 수를 기록한다. 이는 최종 `findings[]` 수나 전체 취약점 완료율이 아니다. 운영 런타임은 이 제한된 메타데이터를 실행 상태와 대시보드로 전달한다. 원본 HTTP 응답, 쿠키, 모델 출력, 가설의 원문 rationale과 증거의 원문 summary는 진행 이벤트에 넣지 않는다. 자세한 근거와 최종 finding은 보고서가 저장된 뒤 표시한다.

```powershell
npm --prefix agent run test:general
```

이 검증은 관측·모델·도구 계약 대역을 통해 범용 에이전트의 판단, 정책, 증거 흐름을 확인한다. 실제 사이트 발견율이나 전체 `integration-gate` 성공을 뜻하지 않는다.

이 디렉터리의 production 범위는 범용 판단 코어, DeepSeek 클라이언트·설정, JSON envelope 프로토콜이다. 대상 요청, 관측, 정책 평가, 독립 검증과 실행 기록 저장은 `apps/application`과 `packages/adapters`가 담당한다.

## finding 식별과 중복 처리

현재 `finding:${hypothesis.id}`는 **한 실행 안에서만** 쓰는 ID다. 저장된 검토 항목은 실행 ID를 앞에 붙여 구별하지만, 이 값을 서로 다른 실행의 동일 취약점 판정에 사용하지 않는다. 같은 분류와 자산 경로만으로 자동 병합하면 한 엔드포인트의 서로 다른 파라미터·권한 경계·약점 원인을 합칠 수 있다. 따라서 현재 `findings[]`는 가설별 기록을 유지한다.

실행 간 안정적인 문제 키와 중복 병합을 추가하려면 보고서 계약에 검증기가 확인한 **정확한 위치**(경로와 파라미터 또는 리소스), **약점 원인/검증 규칙**, **대상 식별자**를 정규화해 넣어야 한다. 같은 키의 여러 가설에서 증거와 상충 판정을 어떻게 합칠지도 함께 합의해야 한다. 이 정보가 없는 미점검·판정 불가 가설은 자동으로 같은 문제라고 단정하지 않는다.

## 폐기된 단일 검사

기존 단일 검사는 폐기됐고 코드도 삭제됐다. 여기에는 `src/orchestrator.js`의 `runOnce()`, 규칙·DeepSeek Reasoning Engine, scripted gateway, `stored_xss_canary`·`agent_cross_user_delete_canary` 프로필, `xss-parser` receiver가 포함된다. 저장된 과거 실행은 실행 이력과 보고서에서 계속 읽는다. 큐에 남아 있던 퇴역 모드 실행은 worker가 `RETIRED_MODE`로 실패 처리한다.

`src/protocol.js`는 JSON envelope, 상관관계, 오류 정규화를 제공한다. 런타임에서 쓰는 곳은 `parseEnvelope`·`replyTo`이고, `casper-db` 지식 조회와 과거 실행 가져오기가 사용한다. 남은 JSON envelope 계약은 [EXTERNAL_MODULE_CONTRACTS.md](./EXTERNAL_MODULE_CONTRACTS.md)에 있다.

## DeepSeek 클라이언트

`src/deepseek-client.js`는 DeepSeek의 OpenAI 호환 Chat Completions API를 호출한다. 기본 endpoint는 `https://api.deepseek.com/chat/completions`, 기본 모델은 `deepseek-flash`다. 범용 플래너가 이 클라이언트를 사용한다. 구현 기준은 [DeepSeek API 문서](https://api-docs.deepseek.com/guides/codex), [JSON Output 문서](https://api-docs.deepseek.com/guides/json_mode/), [오류 코드 문서](https://api-docs.deepseek.com/quick_start/error_codes/)다.

- API 키, Authorization header, provider request ID, 원문 모델 응답과 raw chain-of-thought는 이벤트나 보고서에 저장하지 않는다.
- 모델 JSON은 키·enum·ID·길이를 로컬에서 다시 검증한다. 빈 응답, 잘린 응답, 추가 필드, 알 수 없는 ID와 schema 오류는 행동 전에 실패한다.

설정은 `agent/.env` 또는 프로세스 환경변수에서 읽으며 프로세스 환경변수가 우선한다.

| 변수 | 기본값 | 제약 |
| --- | --- | --- |
| `DEEPSEEK_API_KEY` | 없음 | 필수, 출력·커밋 금지 |
| `DEEPSEEK_MODEL` | `deepseek-flash` | `deepseek-flash` 또는 `deepseek-v4-pro` |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | 공식 HTTPS host, 또는 명시적인 loopback HTTP만 허용 |
| `DEEPSEEK_TIMEOUT_MS` | `60000` | 1~600000ms |
| `DEEPSEEK_MAX_RETRIES` | `1` | 0~2 |
| `DEEPSEEK_MAX_TOKENS` | `512`(범용 플래너는 `2048`) | 64~8192 |

[DEEPSEEK_ADAPTER_PLAN.md](./DEEPSEEK_ADAPTER_PLAN.md)와 [2026-10-06 실제 API 테스트 기록](./DEEPSEEK_LIVE_API_TEST_REPORT_2026-10-06.md)은 폐기된 단일 검사 어댑터 기준의 과거 문서다.

## 실행과 검증

```powershell
cd .\agent
npm test
```

`npm test`와 `npm run test:general`은 DeepSeek 네트워크를 호출하지 않는다.

## Production 파일

- `src/general-assessment.js`: 주입된 관측·정책·실행·검증 포트로 동작하는 범용 다중 가설 루프
- `src/general-model-planner.js`: 실제 DeepSeek 또는 테스트 클라이언트로 구조화된 다중 가설·검사를 제안하는 플래너
- `src/deepseek-client.js`: timeout·재시도·JSON Output 검증을 포함한 DeepSeek 전용 HTTP client
- `src/deepseek-config.js`: `.env`/환경변수 설정 로딩
- `src/model-definitions.js`: 허용 DeepSeek 모델 목록
- `src/protocol.js`: JSON envelope, 상관관계, 오류 정규화
- `src/index.js`: 공개 API

Production 소스에는 타깃 사이트·외부 모듈용 HTTP client/server, 파일 DB, 자식 프로세스가 없다. 유일한 직접 HTTP client는 DeepSeek 전용이다.
