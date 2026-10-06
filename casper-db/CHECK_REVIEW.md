# 재점검 기록의 저장과 검토

과거 보고서와 연결할지 결정하는 것과, 이번 결과를 검토 완료로 처리하는 것은 별도 단계다.

## 1. 참고한 보고서 버전을 지정한다

`match` 결과의 `case_id`, `case_revision`을 `check-add` 입력에 넣는다. 보고서가 점검 중 수정되더라도 처음 참고한 내용을 다시 조회할 수 있다. 버전을 생략하면 저장 시점의 최신 버전을 사용한다.

```powershell
.\.venv\Scripts\python.exe -m casper_db --db data/cases.sqlite3 get CASE-001 --revision 1
.\.venv\Scripts\python.exe -m casper_db --db data/cases.sqlite3 history CASE-001
```

보고서 입력의 `source`는 `synthetic`(가상), `manual`(사람이 작성), `imported`(가져온 보고서), `unknown`이다. 이는 출처 표시이며 검토 승인이나 실제 취약 여부를 보증하지 않는다. 기존 DB의 출처는 추정하지 않고 `unknown`으로 옮긴다.

## 2. 관찰한 결과를 초안으로 저장한다

입력 스키마는 [check.schema.json](schemas/check.schema.json)이다. `check-add`는 `review_status=draft`만 받는다. 결과는 `confirmed`, `not_reproduced`, `inconclusive` 중 점검 도구가 실제 관찰한 값으로 기록한다. DB가 이 값의 의미를 자동 검증하지는 않는다.

`evidence_refs`에는 증거 디렉터리 안의 상대 경로를 `/`로 구분해 넣는다. 실제 증거 파일은 Git에 올리지 않는다.

```json
{
  "check_id": "CHECK-REAL-001",
  "case_id": "CASE-001",
  "case_revision": 1,
  "run_id": "RUN-REAL-001",
  "target_id": "LAB-DEMO",
  "endpoint": "/search",
  "method": "GET",
  "parameter": "q",
  "parameter_location": "query",
  "observed_at": "2026-10-06T14:00:00+09:00",
  "result": "inconclusive",
  "observation": "실제 점검 도구의 관찰 내용으로 채운다.",
  "evidence_refs": ["RUN-REAL-001/browser-proof.png"],
  "source": "tool",
  "review_status": "draft"
}
```

위 JSON은 형식 설명이다. 실제 도구와 파일이 준비되기 전에는 실측 결과로 등록하지 않는다. 실행 가능한 가상 입력은 [check.example.json](examples/check.example.json)이며 `source=synthetic`이므로 검토 완료로 처리할 수 없다.

관찰 시각은 저장할 때 UTC와 고정된 소수점 형식으로 바꾼다. 따라서 여러 시간대의 기록도 실제 시간순으로 조회된다.

## 3. 입력 위치가 바뀌었다면 연결을 따로 확인한다

`q`가 `term`으로 바뀌었거나 경로·메서드·입력 위치가 달라진 경우, 사람이 같은 사례와의 관계를 확인하고 다음 `link_review`를 추가한다.

```json
{
  "link_review": {
    "reviewer": "검토자 ID",
    "reason": "입력 이름 변경을 확인했으며 동일 기능의 재점검으로 연결한다.",
    "reviewed_at": "2026-10-06T14:10:00+09:00"
  }
}
```

이 객체를 체크 JSON 안에 넣는다. 과거 보고서의 위치를 수정하지 않고 이번 관찰 위치를 그대로 남긴다. 입력 위치가 `unknown`인 경우에도 연결 검토가 필요하다. 다른 `target_id`로의 연결은 검토 기록이 있어도 거부한다.

`link_review`는 보고서와 관찰의 관계 확인이다. 결과의 검토 완료와는 별도이며, 실제 점검을 자동으로 허가하지 않는다.

## 4. 증거를 확인하고 결과를 검토 완료로 처리한다

검토자는 파일 내용을 읽어 관찰·결과가 맞는지 판단한 뒤 다음 명령을 실행한다.

```powershell
.\.venv\Scripts\python.exe -m casper_db --db data/cases.sqlite3 --evidence-root data/evidence check-review CHECK-REAL-001 --reviewer "검토자 ID" --note "브라우저 증거와 관찰 내용을 확인함"
```

코드는 파일이 설정한 디렉터리 안에 있는지, 실제 파일인지 확인하고 SHA-256·크기·검토 시각·검토자·메모를 저장한다. 누락된 파일, 외부 경로, 중복 참조와 가상 결과는 승인하지 않는다. 승인 중 오류가 나면 초안 상태를 유지한다.

검토 이후 파일이 바뀌었는지 다시 확인할 수 있다.

```powershell
.\.venv\Scripts\python.exe -m casper_db --db data/cases.sqlite3 --evidence-root data/evidence check-evidence CHECK-REAL-001
```

해시는 파일의 바이트가 같은지 확인하는 값이다. XSS 실행 여부를 판정하지 않는다. 검토가 끝난 결과를 덮어쓰지 않으며, 재점검이나 정정이 필요하면 새 체크 ID를 만든다.

## 기존 DB를 변환할 때

v1~v4를 v5로 변환한다. 변환 전체가 성공하면 새 구조를 저장하고, 실패하면 컬럼·데이터·버전 번호를 함께 원상 복구한다. 변환 전에는 기존 서비스 작업을 멈추고 DB 파일을 별도로 백업한다. 이 명령이 백업 파일을 자동 생성하는 것은 아니다.

현재 존재하는 보고서를 첫 번째 버전으로 보존한다. 변환 전에 이미 덮어쓴 보고서 내용이나 예전 체크가 사용한 실제 보고서 버전은 복구할 수 없다. 예전 체크는 변환 당시 보존한 버전 1에 연결하며, 당시 입력 위치가 없던 체크는 `unknown`으로 남긴다.

예전 `reviewed` 기록은 실제 파일을 검사했다는 근거가 없어 초안으로 옮긴다. 이전 승인 상태·검토자 값은 `legacy_review`에 보존하며, 증거를 준비해 새 검토 절차를 거쳐야 한다.

현재 검토자 이름은 로컬 사용자가 입력하는 감사 기록이다. 로그인한 사용자 신원을 확인하는 인증 기능은 중앙 서버를 연결할 때 추가해야 한다.
