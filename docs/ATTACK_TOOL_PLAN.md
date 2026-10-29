# Issue #32: attack-tool 구조와 구현 계획

관련 이슈: [에이전트 모듈 구조 변경 및 attack-tool 모듈 추가](https://github.com/typemnm/FSL-CA3P/issues/32)

## 목표와 첫 구현 범위

에이전트가 통합 취약점 DB를 참고해 공격용 도구를 선택하고, `attack-tool` daemon에 구조화된 JSON 요청을 보내도록 한다. 도구는 가드레일의 허용 결과를 받은 요청만 실행하며, 응답과 검증 자료를 호출한 에이전트에 돌려준다. 여러 에이전트가 서로 다른 포트와 자격 증명으로 같은 도구에 접근할 수 있어야 한다.

첫 버전은 SQL injection 결과 개수 비교용 패킷 템플릿 하나를 제공한다. 템플릿은 공격 유형, CWE, 외부 의존성, 대상 method/endpoint, 빈칸, 후보 payload와 검증 조건을 포함한다. 임의 shell 명령 실행, ZAP 연동, 템플릿 자동 생성·등록은 후속 범위다. DB의 초안 템플릿 등록 상태를 실행 허가로 사용하지 않는다.

## 기존 구조

| 위치 | 현재 역할 | attack-tool 연결 위치 |
| --- | --- | --- |
| `agent/src/general-assessment.js` | 관찰·계획·정책·실행·검증 루프; 도구 구현은 주입받음 | 코어의 의존성 경계를 유지하고 실행 어댑터를 주입 |
| `apps/application/general-runtime.mjs` | 도구 목록·입력 검증·실제 실행·증거와 판정 연결 | 공격 도구 능력 안내와 executor 연결 |
| `packages/adapters/integrations/knowledge-db.mjs` | casper-db의 카탈로그 조회 | 실행 시점에 고정한 DB snapshot의 공격 유형·패턴 revision·payload 정보를 참고 |
| `packages/adapters/integrations/guardrail.mjs` | 기존 격리 게시판 카나리 정책 | 고정 실습 경로의 기존 정책 유지 |
| `guardrail/src` | 결정론적 GuardrailEvaluator | 새 도구의 trusted 실행 범위를 평가 |
| `attack-module` | 구조화된 HTTP 요청의 기존 실행기 | 필요한 기존 실행을 도구 어댑터 뒤에서 재사용 |
| `web-parser` | 독립 `.mjs` API·CLI·계약·테스트 구성 | 새 모듈의 파일·패키지·계약 구조 참고 |

일반 평가의 카탈로그는 `caseSnapshot.path`와 동일한 고정 DB를 읽는다. 과거 사례·공격 패턴은 모델의 계획 자료이며, 현재 실행의 취약점 확인 근거와 구분한다. 기존 XSS/BOLA 실습은 순서·대상·카나리를 고정한 별도 경로를 사용한다.

## 새 통신 흐름

```mermaid
sequenceDiagram
  participant DB as casper-db snapshot
  participant AI as Agent / 취약점별 client
  participant AT as attack-tool daemon
  participant GR as Guardrail
  participant Target as 등록된 실습 대상
  DB-->>AI: 유형·패턴·payload·출처 정보
  AI->>AT: JSON-RPC 도구 목록/템플릿 조회
  AT-->>AI: 입력 계약·템플릿 1개
  AI->>AT: 실행 요청 + request ID
  AT->>GR: 서버에 고정된 범위로 정책 평가
  alt 허용
    GR-->>AT: ALLOW
    AT->>Target: 구조화된 HTTP 패킷
    Target-->>AT: 응답
    AT-->>AI: 상관관계 ID·정책 결과·응답·증거
  else 차단
    GR-->>AT: DENY
    AT-->>AI: 차단 결과; 대상 요청 없음
  end
```

모델은 대상에 직접 HTTP 요청을 보내는 대신 선언된 도구 입력을 제안한다. application의 실행 어댑터가 모델 제안을 검증하고 daemon client를 선택한다. 취약점별 client는 해당 범주의 요청을 처리하는 논리적 실행 주체다. 첫 버전에서 독립적인 다중 모델 계획 루프를 추가하는 경우에는 각 루프의 예산·취소·증거 수명주기도 별도로 연결해야 한다.

## API와 다중 포트

전송은 HTTP 위의 JSON-RPC를 사용한다. `tools/list`로 이름·설명·입력 schema를 확인하고 `tools/call`로 다음 도구를 호출한다.

`GET /health`는 서비스 상태를 반환한다. `POST /rpc`는 `Content-Type: application/json`과 포트별 `Authorization: Bearer ...`를 요구한다. `initialize` 결과는 protocol version과 서버에 등록된 agent/run 식별자를 제공한다. 실행 응답은 원래 JSON-RPC `id`, `result`, `context.agentId/runId`를 포함하며, 도구 오류는 `error`로 반환한다. client는 요청 ID와 identity를 모두 확인한다.

| 도구 | 입력과 결과 |
| --- | --- |
| `list_attack_templates` | 사용 가능한 고정 템플릿과 공격 유형·의존성 정보 반환 |
| `execute_attack_template` | 템플릿 ID와 빈칸을 검증하고 baseline/attack 요청 결과 반환 |
| `execute_probe` | application에서 허용한 기존 probe를 가드레일을 거쳐 실행하고 구조화된 결과 반환 |

초기 `execute_attack_template`의 인자는 `{templateId, payload}`다. 템플릿의 `origin` 빈칸은 가드레일을 생성한 host 설정에서 채우므로 AI 인자로 받지 않는다. 후보 payload는 템플릿의 `payloads` 목록에 포함되어야 한다.

템플릿 검증은 가드레일이 읽은 응답으로 먼저 수행한다. AI에게 반환하는 baseline/attack에는 HTTP 상태, content type, 최대 4096 UTF-8 byte 본문 발췌와 읽은 본문 크기를 담는다. `truncated`는 원본 응답 수집이 불완전함을, `excerptTruncated`는 반환용 발췌만 짧아졌음을 뜻한다. 원본 수집이 잘린 결과로 취약점을 확정하지 않는다.

요청 ID와 호출자 식별자를 응답에 연결한다. bearer 자격 증명은 서버 설정의 포트별 principal에 묶이며, 모델이 요청 본문에 넣은 agent ID나 policy context로 권한을 바꿀 수 없다. 연결별 결과와 오류를 분리하고, 다른 client의 실행 자료를 공유하는 전역 마지막 결과를 두지 않는다.

application bridge는 취약점별 client를 만들고 두 개의 임시 포트를 이용해 통신한다. daemon의 독립 실행 설정에서는 여러 포트를 선언할 수 있다. 임시 포트는 OS가 할당하므로 동시에 실행되는 평가끼리 충돌하지 않는다. 원격 AI 접근은 명시한 bind 주소와 client 자격 증명을 사용하며, 공개 dashboard 인증을 도구 접근 권한으로 대신하지 않는다.

## 신뢰·검증 경계

1. AI 입력과 DB의 payload·템플릿 설명은 검증할 데이터다. 입력 자체가 실행 권한을 부여하지 않는다.
2. 서버가 대상 origin, 허용 method/path, principal, 실행 예산을 고정한다. 허용되지 않은 템플릿 ID·빈칸·타입·도구는 실행 전에 거부한다.
3. 가드레일 허용은 각 실제 요청에 적용한다. baseline과 공격 패킷 모두 같은 정책을 통과해야 하며, 차단 시 대상에 요청하지 않는다.
4. 패킷을 JSON과 URL API로 구성한다. curl 문자열이나 payload를 shell 명령으로 해석하지 않는다. 임의 host로의 redirect도 실행 범위를 바꾸는 근거가 되지 않는다.
5. 응답은 크기·시간·취소를 제한한다. 오류·실행 결과·독립 verifier 판정을 구분하고, 실패를 취약점 미존재로 표시하지 않는다.
6. 실행 증거에는 요청 ID, 템플릿 ID, 정책 결과와 응답 관측을 연결한다. 모델의 확인 주장이나 과거 DB 이력만으로 현재 취약점을 확정하지 않는다.
7. API 키·bearer token·세션 값은 로그와 모델 관찰 자료에 포함하지 않는다. daemon/client 종료는 평가 종료·취소 수명주기에 연결한다.

## 검증과 develop 반영 순서

1. 고정 템플릿의 형태, 빈칸·payload 검증과 HTTP 패킷 인코딩을 검사한다.
2. 실제 로컬 서버를 사용해 JSON-RPC 요청/응답, 서로 다른 포트의 동시 호출, principal 혼용 거부, 오류와 취소를 검사한다.
3. 허용·차단 가드레일과 baseline/공격 결과를 확인한다. 차단된 요청이 대상에 도달하지 않는지도 검사한다.
4. DB snapshot을 참고한 에이전트의 도구 선택부터 응답 증거·verifier·dashboard 이벤트까지 통합 검사한다.
5. 기존 XSS/BOLA, 일반 평가, module boundary 및 전체 CI를 통과시킨다. 테스트에서 외부 모델 응답은 대역을 사용하고, 별도 실제 DeepSeek API 실험의 모델·호출 결과와 실행 ID를 기록한다.
6. 검증한 변경을 develop에 병합한다. develop push의 전체 CI와 배포 완료 후 dashboard의 실제 실행 SHA 및 새 실행 결과를 확인한다.

`macmini.casper.or.kr` 자동 배포는 전체 suite 완료, 필수 CI job 성공과 실패·skip 0건을 확인한 develop SHA를 적용한다. CI 성공과 장치의 실행 버전은 배포 대기 동안 다를 수 있으므로 각각 확인한다. 자세한 장치 검증 절차는 [DEVICE_DEPLOYMENT.md](DEVICE_DEPLOYMENT.md)를 따른다.
