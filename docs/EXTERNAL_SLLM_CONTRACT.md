# 외부 점검용 sLLM 패킷 계약

## 목적과 범위

`external-general` 실행에서 Agent가 제안한 `http_get` 및 `http_compare`의 실제 GET 요청을 대상 전송 전에 검사한다. 사전 점검 HEAD와 최초 공개 페이지 관찰은 취약점 가설이 없는 탐색 요청이며 이 계약의 대상이 아니다. 이 두 경로는 기존 외부 URL 범위, 공개 IP, DNS 고정, 시간 및 응답 크기 제한을 계속 적용한다.

sLLM은 **요청을 보내도 되는지** 판단한다. 대상 응답을 받은 후 취약점 재현 여부는 독립 AI verifier가 판단한다. `DENY`, `UNCERTAIN`, `ERROR`는 취약점 부재가 아니라 미실행 또는 판정 불가다.

## 기존 공통 규칙의 사용

- `guardrail-sllm/src/judgment-criteria.js`의 일곱 공통 기준을 프롬프트에 사용한다: 승인 범위, 실제 사용자와 관리자 보호, 민감정보 보호, 미승인 대상 통신 금지, 가용성 보호, 요청과 자원 한도, 변경 데이터 복구 가능성.
- 입력 형식, 요청 한도, 위험 요청의 선행 차단 및 fail-closed 원칙은 기존 sLLM 가드레일과 동일하다. 모델 출력의 구조와 요청 근거를 코드에서 재검증한다.
- 기존 fixture 기반 `execute_curl` 계약과 로컬 실습 프로필은 유지한다. 외부 프로필은 fixture ID, 테스트 계정, 고정 endpoint 또는 프로젝트 CVE가 없는 환경으로 다룬다. 모델의 자유로운 취약점 분류를 실행 권한으로 사용하지 않는다.
- `guardrail/src/guardrail.js`의 평가 순서와 fail-closed 원칙은 참고하지만, 현재 ruleset 자체는 `vul-web-1`의 고정 origin·endpoint·canary에 묶여 있으므로 외부 실행에 그대로 적용하지 않는다. 외부 실행의 선행 정책은 `external-target.mjs`와 이 계약의 결정론적 검사가 맡는다.
- 승인된 외부 대상 원점으로의 GET만 통신 허용 범위에 포함한다. 다른 외부 또는 내부 대상은 허용하지 않는다.
- 사이트별 URL이나 쿼리 이름에 위험 단어가 포함될 수 있으므로, 기존 문자열 차단 패턴을 외부 사이트에 일괄 적용하지 않는다. 명확한 지연 함수·시스템 카탈로그·셸 명령·경로 순회 패턴은 재사용하고, 단독 SQL 동사처럼 정상 검색어일 수 있는 값은 모델 판단과 오탐 테스트에 맡긴다.

## 입력 및 신뢰 경계

| 항목 | 내용 | 생성 주체 |
| --- | --- | --- |
| 계약 버전 | `external-packet/1`, `external-read-only` | 가드레일 |
| 패킷 식별 | `runId`, `probeId`, `single`/`control`/`candidate` | 실행기 |
| 실제 패킷 | 정규화된 GET URL, 본문 없음 | 실행기 |
| 승인 범위 | 정확한 origin, 경로 접두사, 관찰 또는 발견된 경로, 총 요청 한도와 사용 횟수 | 서버 |
| 점검 의도 | 가설 범주와 대상 자산 | Agent 제안; 판단 자료일 뿐 권한이 아님 |
| 선행 결정 | 기존 정책의 ALLOW/DENY | 서버 |

패킷을 승인한 후에는 run, probe, 범위, 실제 URL의 해시를 다시 비교한다. Agent는 신뢰된 범위나 sLLM 설정을 요청 본문으로 바꿀 수 없다. `http_compare`는 control과 candidate를 각각 평가하고 둘 다 허용된 후 첫 요청을 보낸다. 대상 요청 횟수는 두 건으로 계산한다.

대시보드는 외부 점검의 `scope.maxRequests`를 4~64 사이의 정수로 받으며 기본값은 8이다. 사전 점검 토큰은 이 값을 포함한 범위 전체에 묶이고, 실행 시 값이 달라지면 거부한다. 사전 점검 HTTP 요청은 실행 요청 한도에 포함되지 않는다. 요청 한도를 늘려도 최초 페이지 관찰은 최대 두 곳이다.

## 선행 검사와 모델 판정

1. origin·경로 접두사·허용된 경로·GET·본문 없음·인증정보 쿼리 부재·명확한 위험 패턴 부재·요청 예산을 코드로 확인한다. 실패하면 모델을 호출하지 않고 `DETERMINISTIC_SCOPE_DENY`로 차단한다.
2. 통과한 요청만 로컬 sLLM의 `/api/chat`에 전달한다. 패킷과 점검 의도의 문장은 명령이 아닌 검사 데이터로 취급한다.
3. 모델 출력은 `verdict`, `evidence`, `checks`, `reason`, `confidence`만 허용한다. verdict는 `IN_SCOPE`, `DENY`, `UNCERTAIN` 중 하나다. checks는 `testPurposeClear`, `noSensitiveAccess`, `noDangerousImpact`, `commonCriteriaSatisfied`이며 각각 boolean 또는 null이다.
4. 근거는 실제 path 또는 query 값과 일치해야 한다. `IN_SCOPE`에는 근거 하나 이상과 모든 check의 true가 필요하다. 최종 `allowExecution`은 모델이 아닌 코드가 계산한다.
5. 잘못된 출력, 연결 실패, 시간 초과, 미설정은 `ERROR`로 차단한다. 실행 중지 신호를 sLLM 요청까지 전달한다.

모델의 의미 판단은 대상의 공개 여부나 DNS 안전성을 증명하지 않는다. 실제 HTTP 요청 직전에 기존 `requestExternalHttp`가 공개 주소와 DNS 고정, 리다이렉트 미추적, 요청 및 응답 한도를 다시 집행한다.

## 기록과 운영

로컬 설정은 `CA3P_GUARDRAIL_SLLM_ENDPOINT`, `CA3P_GUARDRAIL_SLLM_MODEL`을 사용하며, 기존 `SLLM_ENDPOINT`, `SLLM_MODEL`도 대체 값으로 받는다. endpoint는 로컬 HTTP 주소여야 한다. 설정이 없거나 잘못되면 외부 점검을 시작하지 않는다.

인증정보로 보이는 query 키와 고위험 패턴은 모델 호출 전에 차단한다. 로컬 sLLM 응답은 근거·스키마 검사와 fail-closed 결정을 거친다. 모델 호출의 사용량과 제공자를 실행 기록에 남긴다.

Docker로 대시보드를 실행할 때 `127.0.0.1`은 대시보드 컨테이너 자신을 가리킨다. 로컬 Ollama를 사용하려면 Ollama가 같은 네트워크 네임스페이스에서 실행돼야 한다. 현재 Compose의 별도 `report-llm` 컨테이너 주소는 로컬 전용 계약의 허용 주소가 아니다.

보고서에는 패킷 역할별 판정 코드, 지연 시간, 모델 호출 수 및 attack-tool 실행 횟수를 남긴다. 원본 query 값과 인증정보는 이벤트 및 보고서에 기록하지 않는다. 외부 실행 manifest에는 attack-tool, sLLM, adapter의 코드 해시와 가드레일 제공자·모델 및 endpoint 해시를 포함한다. 모델 호출과 대상 HTTP 요청은 별도로 계산한다.

## 필수 검증 사례

- 승인된 공개 GET만 전송되며, sLLM이 검토한 URL과 실제 전송 URL이 같다.
- 범위 밖 origin·경로, 인증정보 쿼리, 변경 방식, 요청 예산 초과는 모델 호출 또는 대상 전송 전에 차단된다.
- `http_compare`에서 한 패킷이라도 거부되면 대상에는 두 패킷 모두 보내지 않는다.
- 모델의 허위 근거·누락된 check·잘못된 JSON·원격 모델 주소·시간 초과·취소는 실행 허용으로 바뀌지 않는다.
- 사이트의 정상 경로와 쿼리에 위험 단어가 있는 경우의 오탐, 내부 실습 fixture 계약, worker 이력 및 결과 화면을 회귀 검사한다.
