# 리피터 (Repeater) — 에이전트 사용 설명서

리피터는 요청을 받아 특정 값만 바꿔 다시 보내고, 응답을 비교해 취약점을 판정하는 공격 도구다. "같은 요청에서 값 하나를 바꿨을 때 거부가 통과로 뒤집히는지"를 보는, 파라미터 변조 계열 공격(IDOR 등)에 쓴다.

## 언제 쓰나

같은 자원에 대한 요청을, 식별자나 파라미터 값만 바꿔서 다시 보냈을 때 권한 판정이 달라지는 공격. 예: 삭제 요청의 `authorId`를 내 계정에서 글 주인으로 바꾸면 거부(403)가 통과(200)로 바뀌는 IDOR.

브라우저에서 스크립트 실행을 확인해야 하는 공격(저장형 XSS 등)에는 쓰지 않는다. 그런 유형은 리피터가 처리하지 않고 명시적으로 거부한다.

## 어떻게 호출하나

리피터에 `vulnType`과 대상 `origin`을 준다. 공격 정의 자체(요청, 변조 값, 성공 조건)는 `casper-db`의 SQLite 공격 카탈로그에서 읽는다. `CASPER_DB_PATH`로 절대 DB 경로, `CASPER_DB_PYTHON`으로 모듈이 설치된 Python 실행 파일을 지정한다. 실행 중에 독립 `pentest-db` JSON 파일을 읽지 않는다.

- 입력: `vulnType`(예: `idor`), 대상 `origin`(격리 랩의 `http://127.0.0.1:<port>`).
- 공격 정의 출처: 카탈로그의 해당 케이스 `successCheck.expect`(baseline 요청·기대 상태, attack 요청·기대 상태, 선택적 resourceRemoved).

저장소 최상위에서 `npm --prefix vul-web-1 run repeater -- idor`를 실행하면 임시 loopback 게시판과 별도 데이터 파일로 IDOR 검사를 수행하고 종료 후 정리한다. 기존 `npm --prefix vul-web-1 run probe:idor`도 같은 호출로 유지한다. Node 24와 설치된 Python 환경이 필요하다.

이미 실행 중인 승인된 실습 대상은 `REPEATER_ORIGIN=http://127.0.0.1:4101 node vul-web-1/scripts/repeater.mjs broken_access_control`로 지정한다. 이 호출은 정의된 변조 요청을 실제 전송한다. `REPEATER_APPLICATION`으로 애플리케이션을 선택할 수 있으며, 정의가 여러 개면 선택 없이 실행하지 않는다.

Node API는 `run({ origin, vulnType, databasePath?, application?, signal? })`다. `loadPlan(catalogPath?, vulnType?, options?)`와 명시적 `catalogPath`는 이전 JSON 입력의 호환 경로다. 기본 저장소를 따로 소유하지 않는다.

## 동작

1. control — 정상 값으로 요청을 보낸다. 권한이 없으면 거부(기대 상태)돼야 한다.
2. tamper — 같은 요청에서 값만 변조해 다시 보낸다. 통과(기대 상태)되면 권한 판정이 값에 의해 뒤집힌 것이다.
3. verify (선택) — 리소스 변화를 다시 조회해 확인한다(예: 글이 실제로 삭제됐는지).

verify는 두 방식 중 하나다: 리소스 조회로 변화 확인(`resourceRemoved`), 또는 재요청의 상태 코드 확인(`verify.status` — 예: 삭제 뒤 `GET /`가 500으로 깨지는지). 후자로 A01 무인증 삭제가 홈 가용성을 깨는 A01+A10 연계까지 판정한다.

두 방식 모두 control과 tamper의 HTTP 상태가 선언된 조건에 먼저 일치해야 한다. 공격이 401·403·404로 거부되면 후속 상태만으로 성공을 반환하지 않는다. 리소스 삭제 확인에는 성공한 HTTP 조회와 구조화된 목록도 필요하다. `verify.status=500`은 특정 정의가 선언한 후속 조건이며 일반적인 서버 오류를 성공 신호로 사용하지 않는다.

모든 요청은 guardrail 룰셋으로 사전 검사되며, 격리 랩(`isolated_local_lab`)에서만, 정해진 요청 예산 안에서만 실행된다. 외부 요청은 금지된다.

## 결과

```
{
  "vulnType": "...",
  "finding": { "category": "<CWE>", "status": "confirmed | not_confirmed | inconclusive" },
  "evidence": [ { "check": "control", "status": ... }, { "check": "tamper", "status": ... }, { "check": "verify", "removed": ... } ]
}
```

- confirmed — control이 기대 거부 상태이고 tamper가 기대 통과 상태이며(verify가 있으면 리소스 변화까지 확인됨).
- not_confirmed — 변조해도 통과되지 않음(권한 판정이 값에 의존하지 않음).
- inconclusive — 기준선 불일치, 예상하지 않은 오류, 응답 구조·후속 근거 누락으로 판정 불가.

결과의 `provenance`에는 `catalog=casper-db.attack_catalog`, `patternId`, `patternRevision`, `definitionSha256`, `catalogSha256`이 포함된다. 실행 뒤 DB가 갱신돼도 당시 사용한 정의를 구분한다. 과거 검증 메모를 현재 실행의 성공 증거로 사용하지 않는다.

## 새 공격 유형 추가

통합 DB에 새 `vulnType` 케이스를 등록하고 `successCheck.expect`를 지원하는 요청 변조 형식(`observe: "httpResponse"`, `baseline.request`·`baseline.status`, `attack.request`·`attack.status`, 선택적 `resourceRemoved`·`verify`)으로 제공한다. 지원하지 않는 형식은 실행 전에 거부한다. 이 CLI는 향후 실행 템플릿을 자동 등록·활성화하지 않으며, 범용 Agent의 자동 도구 선택과 sLLM 가드레일 연결은 별도 작업이다.
