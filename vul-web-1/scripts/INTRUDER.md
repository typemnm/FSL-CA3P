# 인트루더 (Intruder) — 에이전트 사용 설명서

인트루더는 한 주입 지점에 여러 페이로드를 자동으로 연속 발사하고, 응답을 기준선과 비교해 어떤 페이로드가 적중했는지 판정하는 공격 도구다. 리피터가 "값 하나를 바꿔 한 발"이라면, 인트루더는 "같은 지점에 후보 페이로드를 줄줄이" 쏜다(자동 퍼징).

## 언제 쓰나

같은 파라미터에 여러 후보 입력을 넣어보며, 응답 결과가 정상 범위를 벗어나는지로 판정하는 공격. 예: 검색 파라미터 `q`에 SQL 인젝션 후보들(`' OR '1'='1`, `' OR 1=1--` 등)을 넣어, 정상 검색은 0건인데 주입은 결과 집합이 늘어나면 SQL 인젝션으로 판정.

브라우저에서 스크립트 실행을 확인해야 하는 공격(저장형 XSS 등)에는 쓰지 않는다. 그런 유형은 fuzzable 페이로드가 없어 명시적으로 거부된다.

## 어떻게 호출하나

인트루더에 `vulnType`과 대상 `origin`만 주면 된다. 어떤 페이로드를 쏘고, 응답이 어떻게 되면 적중인지는 코드가 아니라 pentest-db 카탈로그(`pentest-db/cases.multi.draft.json`)에 들어 있다. 인트루더는 해당 `vulnType` 블록의 `httpResponse` 페이로드를 전부 꺼내 발사한다.

- 입력: `vulnType`(예: `sql_injection`), 대상 `origin`(격리 랩의 `http://127.0.0.1:<port>`).
- 페이로드 출처: 카탈로그 각 페이로드의 `value`와 `successCheck.expect`(baseline 요청·기대 건수, attack 요청·`resultCountMin`).

CLI로 직접 확인: `INTRUDER_ORIGIN=http://127.0.0.1:4101 npm run intruder -- <vulnType>` (기본값 `sql_injection`). 대상 사이트(예: vul-web2)가 떠 있어야 한다.

## 동작

1. baseline — 정상 입력으로 한 번 쏴 결과 건수를 기준선으로 잡는다.
2. shots — 카탈로그의 페이로드를 하나씩 쏜다. 각 응답의 결과 건수(또는 상태)가 기대치를 넘으면 그 페이로드는 적중으로 기록한다.

판정 방식은 케이스가 정한다: `resultCountMin`(결과 건수 증가 — SQLi), `status`(상태 코드), `containsFields`(응답에 민감 필드 존재 — 정보 노출) 중 하나.

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
- inconclusive — 기준선이 어긋나 판정 불가.

## 새 공격 유형 추가

코드를 고칠 필요 없다. 카탈로그에 새 `vulnType` 블록을 추가하고, 페이로드마다 `successCheck.expect`를 `observe: "httpResponse"`, `baseline.request`·`resultCount`, `attack.request`·`resultCountMin`(또는 `status`) 형식으로 적으면, 인트루더가 그 `vulnType`으로 전부 발사한다.
