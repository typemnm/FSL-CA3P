# CASPER 취약점 보고서 DB — 1차 구현

지난달 CERT에서 발견한 취약점 보고서를 보관하고, 이번 달 CERT의 재점검에 제공하는 작은 DB다. 팀이 준비하는 모의 사이트 하나와 XSS 사례 하나로 시작한다.

**CASE-001은 가상 보고서다.** 주소·심각도·증거도 예시이며, `https://lab.example.invalid/search`는 존재하지 않는 호스트다. 팀 저장소의 `vul-web-1`은 저장형 XSS 실습 사이트이고, 이 모듈의 검색 입력 예시는 별도 가정이다. 해당 사이트와의 실측 보고서·재점검 연결은 아직 검증하지 않았다.

패키지 버전은 0.2.0, SQLite 구조 버전은 v5다.

## Agent Loop 연결 범위

로컬 Agent Loop의 [`casper-db` 어댑터](../agent-dashboard/integrations/casper-db.mjs)는 실제 이 패키지의 SQLite 저장소를 조회한다. `xss-parser`가 명시적으로 관찰한 같은 원점 API 입력 위치를 추출해 `assess_observation`으로 과거 사례와 비교하고, 결과를 `history.result` JSON으로 Agent에 돌려준다. 기본 DB는 `casper-db/data/cases.sqlite3`이며, `CASPER_DB_PATH` 환경변수에 절대 경로를 넣어 기존 SQLite 파일을 지정할 수 있다. DB가 비어 있으면 과거 사례가 없다는 결과를 반환한다.

이 연결은 사례를 자동 생성하거나 이번 실행의 재현 결과를 `checks`에 기록하지 않는다. 과거 XSS 위치 일치는 참고 판정이며, 현재 XSS 취약점의 재현·확정을 뜻하지 않는다. 기본 로컬 루프는 별도의 고정 canary 게시와 Chromium 실행 관찰로 저장형 XSS 한 건을 검증한다. Bob canary 삭제 권한 검사는 명시적으로 선택하는 레거시 프로필이다.

## 왜 이 DB를 만드는가

```text
지난달 CERT: XSS 발견 → 보고서 작성 → 보고서 내용을 DB에 등록
이번 달 CERT: 사이트를 파서로 조사 → 발견된 엔드포인트와 DB의 전월 사례를 비교
               → 관련 사례가 있으면 LLM이 절차를 참고해 재점검 제안
               → 가드레일·점검 도구가 허용된 요청 수행 → 이번 달 결과를 별도 이력으로 저장
```

**위치 일치는 재점검 후보를 찾는 단계다.** 사이트가 수정되었을 수 있으므로 DB에 전월 XSS가 기록되었다는 이유만으로 이번 달에도 취약하다고 단정하지 않는다. 1차 후보 선정 규칙은 [MATCHING_POLICY.md](MATCHING_POLICY.md)에 정리했다.

## 전월 보고서 → DB 필드

| 지난달 보고서 항목 | DB 필드 | 예시 |
|---|---|---|
| 발견 날짜 | `reported_on` | `2026-08-20` |
| 취약점 종류 | `vulnerability_type` | `XSS` |
| 발생한 URL | `vulnerability_url` | `https://lab.example.invalid/search?q=sample` |
| 심각도 | `severity` | `medium` |
| 자세한 발생 설명 | `description` | 검색어가 인코딩 없이 HTML 본문에 포함됨 |
| 실제 당시 확인한 증거 | `prior_evidence` | 증거 위치 또는 관찰 내용. 예시에서는 가정임을 명시 |
| 발생 조건·재현 과정 | `preconditions`, `procedure`, `payload` | 로그인 상태, 시험 입력, 실행 순서 |
| 입력 항목의 위치 | `parameter_location` | `query`, `body` 등. 이름이 같아도 다른 입력 지점을 구분 |
| 확인할 현상 | `success_condition` | 브라우저에서 실행 결과를 관찰 |
| 조치 방안 | `remediation` | 문맥에 맞는 출력 인코딩, 수정 후 재점검 |
| 원문 보고서 위치 | `source_report` | 보고서 파일 경로 또는 식별자 |
| 보고서 당시 패치 상태 | `patch_status` | unknown / unpatched / patched |
| 보고서 출처 | `source` | synthetic / manual / imported / unknown |

`target_id`는 모의 사이트를 가리키는 공통 ID다. `endpoint`는 URL의 경로(`/search`), `method`는 HTTP 메서드(`GET`), `parameter`는 입력 항목(`q`), `parameter_location`은 그 항목의 위치(`query`)다. 전체 URL도 보존하고, 비교할 필드를 따로 저장한다. 기존 DB의 입력 위치는 보고서 URL의 쿼리에서 확인되는 경우에만 `query`로 옮기고, 나머지는 `unknown`으로 남긴다.

`status=draft`이면 작성 중이라 LLM이 쓰는 기본 조회에서 제외한다. 팀의 실제 보고서 내용을 확인해 필드를 완성한 뒤 `ready`로 바꾼다. `ready`는 **전월 보고서를 조회에 제공할 상태**이며, 이번 달 재현 성공이나 현재 취약 상태를 뜻하지 않는다.

## 지금까지 구현된 것

- JSON 보고서 데이터 한 건을 검증하고 SQLite 파일에 저장.
- 명시적 수정, 사례 ID로 조회, 대상 ID로 전월 사례 목록 조회.
- 대상 ID·경로·메서드·입력변수가 정확히 같은 사례 조회.
- 저장된 HTML의 폼·같은 출처 링크를 읽어 입력 지점 JSON을 만드는 로컬 파서 시제품. 네트워크 요청과 XSS 시험은 하지 않음.
- 사이트·경로·방식·입력 이름·입력 위치를 비교해 `retest_candidate`·`manual_review`·`no_match`로 분류하고 근거 및 다음 단계를 출력.
- 재점검 결과를 전월 보고서와 별도의 `checks` 테이블에 추가하고 이력 조회. 가상 결과는 검토 완료로 바꿀 수 없도록 검증.
- 보고서를 수정할 때 `case_versions`에 이전·새 버전을 보존하고, 체크에 참고한 `case_revision`을 연결.
- 입력 위치가 달라진 결과는 사람이 관계를 확인한 `link_review`가 있을 때 저장. 과거 위치와 이번 위치는 각각 보존.
- 관찰 시각을 UTC로 통일하고, 실제 파일·SHA-256·검토자·시각을 확인하는 별도 결과 검토 명령 제공.
- 다른 프로세스에서 쓸 수 있는 **조회 전용** HTTP API.
- 기존 DB v1~v4를 v5로 이동. 구조·데이터·버전 번호를 한 트랜잭션에서 변경하며 실패하면 함께 롤백.

`cases`는 최신 보고서, `case_versions`는 보고서 전체 버전, `checks`는 각 관찰·결과·검토 기록을 보관한다. DB 파일은 Git 공유 대상이 아니다. 예시 JSON과 코드를 받아 각자 DB를 만든다. 기존 DB 변환 전에는 서비스 작업을 멈추고 별도로 백업한다. `init`이 백업 파일을 자동 생성하는 것은 아니다.

## 먼저 2분 데모 보기

```powershell
Set-Location '<클론한 저장소 경로>\casper-db'
.\.venv\Scripts\python.exe demo.py
```

설치 후 실행한다. 데모는 별도 `data/demo/cases.sqlite3`와 가상 입력 `data/demo/parser-observations.json`을 사용하고 `data/demo/index.html`을 브라우저에서 연다. 입력 파일이 없으면 `examples/parser-observations.json`을 복사한다. 실제 점검이 없었다는 `inconclusive` 이력도 `checks` 테이블에 저장한다. 실행 후 파일이 남고 다시 실행해도 같은 예시 기록이 중복되지 않는다. **실제 사이트나 LLM은 실행하지 않는다.** 브라우저 화면은 실행 시점의 DB를 읽어 만든 정적 HTML이다.

데모의 DB에 직접 이력을 추가해 보려면 다음 명령을 실행한 뒤 `demo.py`를 다시 실행하면 된다. `check-add`는 같은 ID를 두 번 넣으면 거부한다.

```powershell
.\.venv\Scripts\python.exe -m casper_db --db data/demo/cases.sqlite3 check-add examples/check.example.json
.\.venv\Scripts\python.exe -m casper_db --db data/demo/cases.sqlite3 check-list CASE-001
.\.venv\Scripts\python.exe demo.py
```

## 로컬 HTML 파서 → DB 후보 선정

이 모듈의 검증은 저장된 [모의 HTML](examples/mock-site/search.html)에서 입력 지점을 추출하는 방식으로 진행했다. 이 HTML에는 취약점이 없으며 파서는 네트워크 요청이나 XSS 시험을 하지 않는다. 아래 명령으로 파서 출력 JSON을 만들고 DB의 전월 사례와 비교할 수 있다.

```powershell
Set-Location '<클론한 저장소 경로>\casper-db'
.\.venv\Scripts\python.exe -m casper_db parse-html --target LAB-DEMO --page-url https://lab.example.invalid/search --html examples/mock-site/search.html --output data/demo/parsed-observations.json
.\.venv\Scripts\python.exe -m casper_db --db data/demo/cases.sqlite3 match data/demo/parsed-observations.json
.\.venv\Scripts\python.exe demo.py --parser-input data/demo/parsed-observations.json --no-open
```

파서는 `GET /search`의 `q`와 `page`, `POST /feedback`의 `message`를 찾는다. DB는 순서대로 재점검 후보·수동 확인·일치 없음으로 분류한다. 마지막 명령은 같은 결과를 `data/demo/index.html`에 다시 그린다. [팀원에게 줄 JSON 계약](PARSER_INPUT_PROPOSAL.md)과 [파서 관찰 스키마](schemas/parser-observation.schema.json)에 필드와 한계를 정리했다.

## 터미널에서 데이터 확인

이 PC의 독립 `.venv`에 필요한 패키지를 설치해 두었다. 다른 PC에서는 다음 명령으로 준비한다.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[api,dev]"
```

Mac mini 등 macOS에서는 `casper-db` 폴더에서 Python 3.11 이상을 확인한 뒤 다음처럼 설치한다. 이 환경에서의 실행은 아직 검증하지 않았다.

```sh
python3 --version
python3 -m venv .venv
./.venv/bin/python -m pip install -e '.[api,dev]'
./.venv/bin/python -m pytest
```

아래 명령 예시는 Windows PowerShell 기준이다.

현재 폴더에서 실행한다.

```powershell
# 기존 DB도 검사·업그레이드하고, 새 PC에서는 DB를 만든다.
.\.venv\Scripts\python.exe -m casper_db init

# 새 실습 DB에 가상 초안 등록. 같은 ID가 이미 있으면 add를 반복하지 않는다.
.\.venv\Scripts\python.exe -m casper_db add examples/case.example.json

# 전월 보고서 예시의 전체 내용을 확인한다. draft도 보인다.
.\.venv\Scripts\python.exe -m casper_db get CASE-001

# LLM 담당자에게 줄 이번 사이트의 전월 보고서 목록. 지금은 draft라 [].
.\.venv\Scripts\python.exe -m casper_db list --target LAB-DEMO

# 입력변수까지 같은 전월 사례를 찾는다. 초안을 직접 확인할 때만 옵션을 붙인다.
.\.venv\Scripts\python.exe -m casper_db find --target LAB-DEMO --endpoint /search --method GET --parameter q --parameter-location query --include-drafts
```

다른 DB 파일을 쓰려면 명령어 앞에 `--db data/다른이름.sqlite3`을 둔다.

팀의 실제 전월 보고서를 받으면 [예시 입력 JSON](examples/case.example.json)의 날짜·URL·심각도·재현 방법·조치 방안을 교체한다. `status`를 `ready`로 바꾸고 `data/case.local.json`으로 저장한 뒤 아래처럼 수정한다.

```powershell
.\.venv\Scripts\python.exe -m casper_db update data/case.local.json
```

새로운 ID의 보고서라면 `update` 대신 `add`를 사용한다. 같은 ID를 다시 `add`하면 중복으로 거부한다. URL의 경로와 `endpoint`는 같아야 하며, `ready`에는 보고 날짜·URL·심각도·설명·조치 방안·시험 입력이 필요하다.

실제 보고서는 `source`를 `manual` 또는 `imported`로 지정한다. `ready`는 내용의 준비 상태이며 별도의 승인이나 실측 결과를 보증하지 않는다.

수정은 새 버전을 보존한다. `update data/case.local.json --expected-revision 1`처럼 버전을 지정하면 다른 사람의 수정과 충돌했을 때 덮어쓰지 않는다. 사례의 `target_id`는 변경할 수 없다.

```powershell
.\.venv\Scripts\python.exe -m casper_db history CASE-001
.\.venv\Scripts\python.exe -m casper_db get CASE-001 --revision 1
```

체크는 초안으로 저장하고 실제 증거를 확인하는 별도 절차로 검토 완료 처리한다. 버전 지정, 바뀐 입력의 연결, 검토 명령은 [CHECK_REVIEW.md](CHECK_REVIEW.md)에 있다. 예전 승인 정보는 `legacy_review`에 보존하며, 확인되지 않은 예전 파일을 현재 검증 완료로 간주하지 않는다.

## 팀원에게 제공할 조회 방법

같은 Python 환경이면:

```python
from casper_db import CaseStore

store = CaseStore("data/cases.sqlite3")
previous_reports = store.list_for_target("LAB-DEMO")
for case in previous_reports:
    print(case.model_dump())  # 전월 보고서의 JSON 데이터
```

이 목록과 **이번 달 엔드포인트 파서 출력**을 LLM 담당자가 함께 받아 비교할 수 있다. 코드에서도 정확한 경로·메서드 비교가 가능하다.

```python
matches = store.find(target_id="LAB-DEMO", endpoint="/search", method="GET",
                     parameter="q", parameter_location="query")
```

1차 후보 선정기를 직접 실행하려면 다음 명령을 사용한다. 출력에는 각 파서 관찰의 분류와 일치·차이 필드가 포함된다. 가상 파서 입력의 `parameter`를 바꾸고 다시 실행해 규칙을 확인할 수 있다.

```powershell
.\.venv\Scripts\python.exe -m casper_db --db data/demo/cases.sqlite3 match data/demo/parsed-observations.json
```

다른 프로세스에서 연결할 때는 로컬 조회 API를 시작한다.

```powershell
.\.venv\Scripts\python.exe -m casper_db serve --port 8001
```

| 요청 | 반환 |
|---|---|
| `GET /cases?target_id=LAB-DEMO` | 그 사이트의 준비된 전월 보고서 목록 |
| `GET /cases?target_id=LAB-DEMO&endpoint=%2Fsearch&method=GET&parameter=q` | 위치와 입력변수가 같은 전월 사례 |
| `GET /cases?target_id=LAB-DEMO&endpoint=%2Fsearch&method=GET&parameter=q&parameter_location=query` | 입력 위치까지 같은 전월 사례 |
| `GET /cases/CASE-001` | 준비된 특정 사례의 상세 내용. 초안은 409 |

서버는 `127.0.0.1`에서 실행된다. API 문서는 `http://127.0.0.1:8001/docs`에 있다. API는 조회만 제공하며, DB 내용을 자동으로 LLM에 넣거나 사이트를 점검하지는 않는다.

## 지금 확인된 것과 남은 연결

2026-10-06 기준 저장·조회, 필드 검증, API·CLI, 스키마 이동, 재점검 이력, HTML 데모와 로컬 HTML 파서·후보 선정을 검사했다. 결과는 [검증 기록](VERIFICATION.md)에 있다.

다음 연결에 필요한 팀 정보는 실제 모의 사이트의 URL·메서드·입력 항목, 지난달 보고서의 심각도·증거·조치 방안, 팀 파서 출력 JSON 형식, 이번 달 재현 성공 기준이다. **전월 보고서 저장·조회와 로컬 HTML 파서의 입력 지점 추출·후보 선정까지 연결했다.** 실제 사이트·팀 파서·LLM·점검 도구의 통합 결과는 아직 없다. 현재 `checks` 기록은 CLI 또는 Python으로 입력한다. 실제 판정과 보고서 자동 생성에는 검증 도구 및 사람의 검토를 연결해야 한다.

한 건의 이전 취약점을 이미 알고 재점검하는 시연이다. 이 구조를 사용해 성공하더라도 LLM이 알려지지 않은 취약점을 새로 발견했다고 해석하지 않는다.

코드 읽는 순서: [HTML 입력 추출](src/casper_db/parser.py) → [후보 판정](src/casper_db/matching.py) → [사례 형식](src/casper_db/models.py) → [SQLite 저장·조회](src/casper_db/repository.py) → [증거 파일 확인](src/casper_db/evidence.py). 입력 스키마는 [사례](schemas/case.schema.json), [체크](schemas/check.schema.json), [파서](schemas/parser-observation.schema.json)이며, 비교 출력은 [후보 판정](schemas/candidate-assessment.schema.json)에 있다.

검토자 이름은 로컬 사용자가 입력하는 기록이다. 중앙 서버의 사용자 인증·권한과 쓰기 API, 실제 XSS 재현·LLM 연동·자동 보고서 생성은 남은 작업이다. `procedure`와 `success_condition`의 자연어를 그대로 자동 실행하지 않고 점검 담당 모듈과 실행·관찰 형식을 합의해야 한다.
