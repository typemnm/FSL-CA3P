# 인트루더 (Intruder) — 에이전트 사용 설명서

인트루더는 한 주입 지점에 여러 페이로드를 자동으로 연속 발사하고, 응답을 기준선과 비교해 어떤 페이로드가 적중했는지 판정하는 공격 도구다. 리피터가 "값 하나를 바꿔 한 발"이라면, 인트루더는 "같은 지점에 후보 페이로드를 줄줄이" 쏜다(자동 퍼징).

## 언제 쓰나

같은 파라미터에 여러 후보 입력을 넣어보며, 응답 결과가 정상 범위를 벗어나는지로 판정하는 공격. 예: 검색 파라미터 `q`에 SQL 인젝션 후보들(`' OR '1'='1`, `' OR 1=1--` 등)을 넣어, 정상 검색은 0건인데 주입은 결과 집합이 늘어나면 SQL 인젝션으로 판정.

브라우저에서 스크립트 실행을 확인해야 하는 공격(저장형 XSS 등)에는 쓰지 않는다. 그런 유형은 fuzzable 페이로드가 없어 명시적으로 거부된다.

## 어떻게 호출하나

인트루더에 `vulnType`과 대상 `origin`을 준다. 어떤 페이로드를 전송하고 어떤 응답을 적중으로 볼지는 `casper-db`의 SQLite 공격 카탈로그에서 읽는다. `CASPER_DB_PATH`는 절대 DB 경로, `CASPER_DB_PYTHON`은 모듈이 설치된 Python 실행 파일이다. 독립 `pentest-db` JSON 파일은 필요하지 않다.

- 입력: `vulnType`(예: `sql_injection`), 대상 `origin`(격리 랩의 `http://127.0.0.1:<port>`).
- 페이로드 출처: 카탈로그 각 페이로드의 `value`와 `successCheck.expect`(baseline 요청·기대 건수, attack 요청·`resultCountMin`).

저장소 최상위에서 `INTRUDER_ORIGIN=http://127.0.0.1:4101 npm --prefix vul-web-1 run intruder -- sql_injection`으로 호출한다. 승인된 loopback 실습 서버가 떠 있어야 한다. Node 24와 설치된 Python 환경을 사용한다. `INTRUDER_APPLICATION`으로 애플리케이션을 고르고, 같은 유형의 정의가 겹치면 선택 없이 실행하지 않는다.

Node API는 `run({ origin, vulnType, databasePath?, application?, signal? })`다. `loadIntruderPlan(catalogPath?, vulnType?, options?)`와 명시적 `catalogPath`는 이전 JSON 입력의 호환 경로이며 기본 데이터 소유자는 통합 DB다.

## 동작

1. baseline — 정상 입력으로 한 번 쏴 결과 건수를 기준선으로 잡는다.
2. shots — 카탈로그의 페이로드를 하나씩 쏜다. 각 응답의 결과 건수(또는 상태)가 기대치를 넘으면 그 페이로드는 적중으로 기록한다.

판정 조건은 케이스가 정한다: `resultCountMin`(결과 건수 증가), `status`(상태 코드), `containsFields`(응답 필드 존재)다. 선언된 조건을 모두 확인하며, 상태가 생략된 경우 2xx를 요구한다. 기준선에도 선언된 상태 또는 2xx와 지정된 결과 건수 조건을 적용한다. 빈 필드 목록·잘못된 상태값·성공 조건이 없는 정의는 요청 전에 거부한다.

모든 요청은 guardrail 룰셋으로 사전 검사되며, 격리 랩(`isolated_local_lab`)에서만, 페이로드 수에 맞춘 요청 예산 안에서만 실행된다. 외부 요청은 금지된다.

## 결과

```
{
  "vulnType": "...",
  "finding": { "category": "<CWE>", "status": "confirmed | not_confirmed | inconclusive", "hits": ["<적중 payloadId>"] },
  "evidence": [ { "check": "baseline", "resultCount": ... }, { "check": "<payloadId>", "status": ..., "resultCount": ..., "hit": true|false } ]
}
```

- confirmed — 기준선이 정상이고 하나 이상의 페이로드가 적중.
- not_confirmed — 기준선은 정상인데 어떤 페이로드도 적중하지 않음(주입이 먹지 않음).
- inconclusive — 기준선 오류, 서버 오류·호출 제한, 필요한 응답 구조 누락으로 판정 불가.

HTTP 500 응답에 결과 배열이나 민감 필드 이름이 들어 있다는 이유만으로 적중 처리하지 않는다. `evidence`에는 기준선의 HTTP 상태·유효성 및 요청별 `inconclusive`도 남는다. `not_confirmed`는 전체 서비스가 안전하다는 판정이 아니다.

`provenance`의 `patternId`, `patternRevision`, `definitionSha256`, `catalogSha256`으로 사용한 정의를 추적한다. 새 실행 템플릿을 자동 등록·활성화하지 않으며, 범용 Agent와 sLLM 가드레일 연결은 별도 작업이다.

## 새 공격 유형 추가

통합 DB에 새 `vulnType` 블록을 등록하고 페이로드별 `successCheck.expect`에 지원되는 기준선과 공격 응답 조건을 제공한다. 지원하지 않는 조건은 실행 전에 거부한다. 등록 절차는 `casper-db/README.md`를 따른다.
