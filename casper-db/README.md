# CASPER 취약점 DB

기존 CERT 보고서의 취약점 정보를 추출하고, 원문 근거를 확인한 검토 기록을 거쳐 SQLite DB에 등록한다. 외부 공개 취약점 정보는 별도 DB에 정규화해 관리한다.

보고서에 기록된 URL·입력 위치·재현 절차·payload·해결 방안을 구조화해 이후 점검에서 조회할 수 있도록 한다. 새 보고서 작성, payload 실행, 현재 서비스의 취약 여부 판정은 이 모듈의 범위에 포함하지 않는다.

## 기능

- HWPX의 XML·표·명시적 항목명 문단 및 HWP v5 리더 결과에서 취약점별 JSON 초안 생성
- 서술형 문장의 파라미터·사전 조건·재현 절차·관찰 결과 분류와 근거 구간 보존
- 필드별 원문 위치, 매핑되지 않은 항목, 서로 다른 payload 표기 보존
- Windows 로컬 OCR을 통한 내장 이미지의 텍스트·행·단어 좌표 추출
- 누락값·미확정 후보를 유지하는 검토 기록과 등록 전 검증
- 원본·초안·검토·검증·등록 이력의 지속 보관
- 검토된 사례의 명시적 일괄 등록, 동일 내용 재등록 방지, 충돌 시 롤백
- NVD·GitHub Advisory 정보의 정규화·별도 저장·조회와 설정 기반 일괄 처리
- 대상 소프트웨어 목록과 공개 영향 범위 비교, 근거·판정 이력 보존
- 입력 위치별 재점검 결과의 일괄 등록과 관찰 시점 증거 해시 보존
- 파일 선택과 JSON 검토 도구, 정적 HTML 검토 화면

기존 Case CRUD, 버전 이력, 위치 기반 재점검 후보 선정, `checks` 기록·검토와 조회 API를 유지한다. 패키지 버전은 `0.4.0`, Case DB 스키마는 `v7`이며 접수 이력은 별도 DB에 저장한다.

## 처리 흐름

단계별 함수와 저장 관계는 [처리 흐름 도식](WORKFLOW.md)에서 확인한다.

```text
HWP / HWPX → 문단·표 추출 / 선택적 이미지 OCR
  → 취약점별 초안 → 근거 대조·검토 기록 → 등록 전 검증
  → 명시적 등록 → Case DB 조회
```

추출본은 최종 사례가 아니다. 근거 없는 값은 생성하지 않으며, 관련 내용이 있어도 확정할 수 없으면 검토 대상으로 보관한다. 검토·검증을 통과한 사례만 `ready`로 등록한다. `ready`는 과거 보고서의 조회 준비 상태이며 현재 취약점의 재현 성공을 뜻하지 않는다.

## 저장 구조

`report-db init`은 존재하지 않는 새 디렉터리에 독립 작업 공간을 만든다.

```text
<작업 공간>/
├── workspace.json
├── intake.sqlite3
├── cases.sqlite3
└── exports/<draft_sha256>/
    ├── report.draft.json
    ├── report.review.pending.json
    └── report.review.json
```

| 위치 | 내용 |
|---|---|
| `intake.sqlite3` | 접수한 원본 문서 BLOB, 초안, 검토·검증 스냅샷, 현재 검토 연결, 등록 영수증 |
| `cases.sqlite3` | 명시적으로 등록한 조회용 Case와 기존 버전·점검 이력 |
| `report.draft.json` | 문서 구조와 취약점별 필드 후보·근거·누락·미확정 정보 |
| `report.review.pending.json` | 최초 검토 대기 양식 |
| `report.review.json` | 사용자가 편집해 제출할 검토 기록 |

`exports`는 비교·편집용 파일이다. 검토 파일은 `report-db review`로 제출해야 intake DB에 반영된다. 제출 후 파일을 수정했다면 다시 제출한다. 재접수 시 기존 편집 파일은 자동 덮어쓰지 않는다.

### 추출 JSON

| 경로 | 의미 |
|---|---|
| `source` | 입력 파일 경로·이름·SHA-256 등 출처 |
| `document.sections`, `document.tables` | 읽어 낸 문단·표와 원문 위치 식별자 |
| `document.labeled_sections` | `취약점 유형: …` 등 명시적 항목명으로 묶은 본문 문단과 필드 근거 |
| `document.images` | 내장 이미지 정보와 문서 내 참조 |
| `document.local_ocr.bundle` | OCR 원출력·행·단어·좌표, 원본 해시, 처리 상태 |
| `findings[].candidate` | Case 필드로 옮길 후보 |
| `findings[].field_evidence` | 필드별 원문 값·위치와 직접 추출/정규화/파생/검토 후보 구분 |
| `findings[].payload_variants` | payload의 개별 표기, 표현 방식, 원문과 위치 |
| `findings[].missing_fields` | 값을 뒷받침할 근거를 확보하지 못한 필드 |
| `findings[].unresolved_fields` | 후보·관련 내용은 있지만 값을 확정하지 못한 필드 |
| `findings[].unmapped_fields`, `review_issues` | 매핑되지 않은 항목과 검토할 문제 |

payload의 따옴표·공백·URL 인코딩 표기는 임의로 교정하거나 통합하지 않는다. 디코딩 참고값이 있더라도 원문 값은 유지하며 검토자가 대표 후보를 선택한다. OCR에서 읽힌 재현 절차와 payload는 근거 후보로 보관하고 검토 전에 자동 확정하지 않는다.

표가 없는 문서는 `취약점 종류:` 또는 `취약점 유형:`으로 시작하는 문단 묶음을 처리한다. 다음 유형 항목·표·섹션에서 경계를 나누고, 다른 명시적 항목까지 이어지는 문단을 해당 값으로 보존한다. 추론한 사례 경계는 검토 문제로 표시한다. 표의 payload 필드와 본문의 `payload:`·`페이로드:` 표기는 취약점 종류와 무관하게 보존한다. 항목명 없는 임의의 문장 전체를 확정값으로 변환하지 않는다.

`missing_fields`·`unresolved_fields`, 모든 payload 후보와 OCR 결과는 intake의 초안 스냅샷에 남긴다. Case 테이블에는 검토한 대표값을 저장한다. 원본 이미지는 intake의 문서 BLOB에 포함된다.

### 최종 Case 필드

| 구분 | 필드 |
|---|---|
| 보고서 정보 | `title`, `vulnerability_type`, `reported_on`, `vulnerability_url`, `severity`, `description`, `remediation`, `prior_evidence` |
| 발생 위치 | `endpoint`, `method`, `parameter`, `parameter_location` |
| 재현 정보 | `preconditions`, `procedure`, `payload`, `success_condition` |
| 식별·출처·상태 | `case_id`, `target_id`, `source_report`, `source`, `status`, `patch_status` |
| 입력 적용 여부 | `not_applicable_fields`, `applicability_reason` |
| 경로 연결 | `route_template` |
| 저장 메타데이터 | `revision`, `created_at`, `updated_at` |

`case_id`는 원본 해시와 취약점 위치로 결정한다. `target_id`는 대상 관리 체계의 ID를 지정한다. 패치 상태의 기본값은 `unknown`이며 근거 없이 변경하지 않는다. 기존 출처 구분과의 호환성을 유지한다.

필수값과 형식은 [Case 모델](src/casper_db/models.py)과 [등록 전 검증](src/casper_db/import_workflow.py)에서 확인한다. 사전 조건·재현 절차와 등록 필수 항목이 비어 있거나 미확인 표시만 있는 경우 등록을 보류한다.

`parameter`·`payload`는 기본적으로 필요하다. 정보 노출·보안 설정 오류·암호화 실패·설계 결함·로깅 실패·예외 처리 실패 등 입력이 적용되지 않을 수 있는 유형은, 검토자가 `not_applicable_fields`에 해당 필드를 지정하고 `applicability_reason` 및 보완 근거를 남긴 경우에만 `null`로 등록할 수 있다. 값의 누락만으로 미적용을 추론하지 않으며, 입력이 필요한 XSS·SQL 인젝션·IDOR 등의 누락값을 이 방식으로 면제할 수 없다. 미적용 필드에 값이 들어 있거나 근거가 없으면 거부한다. 정확한 허용 유형은 [입력 정책](src/casper_db/case_policy.py)에 정의돼 있다.

`route_template`은 검토된 경로의 식별자 자리 하나만 중괄호로 표시한다. 슬롯 이름은 `parameter`와 같고 `parameter_location=path`여야 한다. 현재 정수·UUID 식별자를 지원하며, 고정 경로·대소문자·끝의 슬래시와 식별자 형식은 그대로 비교한다. 템플릿이 없으면 기존의 정확한 경로 비교를 유지한다. 템플릿 일치도 재점검 후보를 연결하는 정보이며 현재 취약점의 확정이나 실행 권한이 아니다.

## 설치

`casper-db` 폴더에서 Python 3.11 이상으로 설치한다. Windows PowerShell 기준:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[api]"
```

이후 명령의 `python`은 이 가상환경의 인터프리터를 뜻한다. Windows에서는 `.\.venv\Scripts\python.exe`로 대체해 실행할 수 있다.

HWPX 텍스트 추출에는 한글 프로그램이 필요하지 않다. 바이너리 HWP v5 지원은 선택 의존성을 설치한다.

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[hwp]"
```

macOS/Linux에서는 `.venv/bin/python`을 사용한다. 이미지 OCR은 Windows 전용이며 사용할 언어의 인식기가 설치돼 있어야 한다. 한국어는 `ko`를 사용한다.

```powershell
.\.venv\Scripts\python.exe -m casper_db ocr-status
```

OCR은 Windows `Windows.Media.Ocr`와 Windows PowerShell 5.1 워커를 사용한다. 보고서 추출·OCR·검토는 로컬에서 수행한다.

## 보고서 접수·검토·등록

다음 명령의 `<...>`는 실제 경로·대상 ID·반환된 해시로 교체한다. 원본과 산출물은 Git에서 제외되는 `data/` 등의 로컬 경로에 보관한다.

```powershell
python -m casper_db report-db init '<새 작업 공간>'
python -m casper_db report-db stage '<작업 공간>' '<보고서 경로>' --target '<대상 ID>'
```

이미지 인식이 필요하면 `stage`에 `--ocr --ocr-language ko`를 추가한다. `stage`는 원본·초안을 intake에 저장하고 `draft_sha256`, `draft_file`, `review_file`을 출력한다. 이 단계에서는 Case를 등록하지 않는다.

원문과 `report.draft.json`을 대조하고 `report.review.json`에 다음을 기록한다.

- `reviewer`, 시간대가 포함된 `reviewed_at`
- 취약점별 `decision=pending|accept|exclude`와 이유 `reason`
- 확인한 `payload_variant_index`와 필요한 `acknowledged_issue_codes`
- 값을 보완했다면 `resolutions.<필드>`의 `value`, `reason`, `source_refs`

미적용 선언과 경로 템플릿도 같은 `resolutions` 형식으로 기록한다. `not_applicable_fields`는 문자열 배열이며 `applicability_reason`과 `route_template`은 문자열이다. 원문 초안은 수정하지 않는다.

근거를 확보하지 못한 값은 `pending`으로 남긴다. 보완 근거는 해당 취약점의 문서 내 참조 또는 명시적인 `manual:` 참조로 기록한다. 다른 보고서·초안의 검토 기록을 재사용하면 해시 검증에서 거부한다.

```powershell
python -m casper_db report-db review '<작업 공간>' '<초안 해시>' '<검토 파일 경로>'
python -m casper_db report-db publish '<작업 공간>' '<초안 해시>'
python -m casper_db report-db show '<작업 공간>' --draft '<초안 해시>'
```

`publish` 기본 동작은 저장 전 검증이다. Case를 실제 등록하려는 경우에만 `--apply`를 지정한다.

```powershell
python -m casper_db report-db publish '<작업 공간>' '<초안 해시>' --apply
python -m casper_db --db '<작업 공간>/cases.sqlite3' list --target '<대상 ID>'
```

검토 대기가 남으면 기본적으로 보고서 전체의 등록을 보류한다. 등록 가능한 일부만 처리하려면 `--ready-only --apply`를 명시한다. 동일 내용은 `unchanged`로 처리하고 동일 ID의 다른 내용은 충돌로 거부한다. 한 배치의 Case 저장은 한 트랜잭션으로 처리한다.

intake와 Case DB의 커밋 전체가 하나의 트랜잭션인 것은 아니다. Case 저장 후 영수증 기록이 실패하면 동일 작업의 재실행으로 영수증을 복구한다. `report-db`는 생성한 독립 작업 공간만 사용하며 전역 `--db`를 접수 DB로 재사용하지 않는다.

### 다른 모듈에 검토 상태 전달

`report-db references '<작업 공간>' --target '<대상 ID>'`는 읽기 전용 `casper-reference-1` JSON을 반환한다. 원문에서 추출한 후보, payload 표현, 필드별 근거, 누락·미확정 필드, 현재 검토 결정과 보완값을 함께 전달한다. 등록 상태와 재현 판정은 별개이며, 이 응답은 실행 권한을 부여하지 않는다. 다른 대상의 보고서와 원본 파일 바이트·로컬 원문 경로는 포함하지 않는다.

`--external-db '<외부 정보 DB>'`를 지정하면 보고서에 명시된 CVE의 저장된 권고와 대상별 영향 범위 평가도 포함한다. 추가 조회에는 `--cve '<CVE ID>'`를 반복한다. 외부 원문 레코드의 `applicability=not_assessed`와 별도로 `external.assessments`에 대상 평가·근거·최신 여부를 제공한다. 자료 원천의 `not_configured`·`unavailable`은 조회 성공 후 결과가 없는 상태와 구분한다. 이 명령은 DB를 만들거나 변환하지 않는다.

로컬 API의 `serve --intake-workspace '<작업 공간>' --external-db '<외부 정보 DB>'`는 `GET /references?target_id=<대상 ID>`를 추가한다. 반복 가능한 `cve_id` 쿼리로 외부 권고 ID를 지정할 수 있다. 원천을 지정하지 않으면 기존 `/cases` API만 제공한다.

팀 어댑터는 선택한 Case DB와 같은 폴더의 접수 작업 공간을 인식한다. 원천을 명시하려면 `CASPER_DB_INTAKE_WORKSPACE`·`CASPER_DB_EXTERNAL_PATH`를 사용한다. 반환된 `referenceContext`는 실행 이벤트와 보고서 수집 자료에 보존되며, 보고서의 HWPX·Markdown·JSON에 원본 검토 상태가 자동 반영된다.

입력 위치를 확인하지 못한 요청은 `unresolved_requests`로 전달한다. 같은 경로나 검토된 경로 템플릿의 관련 사례도 수동 확인 대상으로 연결한다. 명시적인 입력 위치는 어댑터의 `locationHints`로 전달할 수 있으며, 파라미터를 발견하지 못했다는 이유만으로 입력 미적용을 추론하지 않는다.

파서 출력의 선택적 `inputLocations` 계약은 [파서 입력](PARSER_INPUT_PROPOSAL.md)에 정의한다. 검증기가 반환한 `casper-check-results-1`은 [재점검 결과](CHECK_REVIEW.md)의 일괄 입력으로 저장한다. 두 계약은 XSS 전용 필드를 요구하지 않는다.

### 파일만 사용하는 검토

DB에 접수하지 않고 추출·검토·등록 패키지 생성만 수행할 수도 있다.

```powershell
python -m casper_db parse-report '<보고서 경로>' --output '<초안.json>'
python -m casper_db review-template '<초안.json>' --output '<검토.json>'
python -m casper_db prepare-import '<초안.json>' --review '<검토.json>' --target '<대상 ID>' --output '<등록 패키지.json>'
```

파일 선택 창을 사용하려면 `python -m casper_db.local_review start --state-dir '<로컬 검토 폴더>'`를 실행한다. `validate` 명령으로 현재 검토 기록을 검증한다. 이 도구는 Case를 저장하지 않는다.

`review-hwpx '<초안.json>' --output '<검토.html>'`은 정적 검토 화면을 만든다. 원본 이미지 표시에는 `--source-hwpx`로 해시가 일치하는 HWPX를 지정한다. 화면은 검토 JSON 편집·내려받기를 제공하며 DB 쓰기 API는 제공하지 않는다.

## 외부 취약점 정보·일괄 처리

공개 취약점 정보는 내부 CERT Case와 별도 DB로 관리한다. CVE·Advisory ID, 설명, 공개·수정일, 철회 여부, 심각도·metrics, CWE, 영향 제품·버전, 참고 링크, 원문·해시를 보존한다. 서비스 적용 여부는 `applicability=not_assessed`로 유지한다.

```powershell
python -m casper_db normalize-external github '<공개 응답.json>' --output '<정규화.json>'
python -m casper_db external-import '<정규화.json>'
python -m casper_db external-import '<정규화.json>' --external-db '<외부 정보 DB 경로>' --apply
python -m casper_db external-get '<외부 정보 DB 경로>' '<CVE ID>'
```

`collect-external nvd|github --output '<수집.json>'`은 공개 API를 조회한다. `--params`로 조회 조건 JSON을, `--max-pages`로 페이지 한도를 지정한다.

대상에 대한 버전 비교는 근거가 포함된 [소프트웨어 목록 스키마](schemas/software-inventory.schema.json)로 수행한다.

```powershell
python -m casper_db external-assess '<외부 정보 DB>' '<소프트웨어 목록.json>' --cve '<CVE ID>'
python -m casper_db external-assess '<외부 정보 DB>' '<소프트웨어 목록.json>' --cve '<CVE ID>' --apply
python -m casper_db external-assessments '<외부 정보 DB>' --target '<대상 ID>' --cve '<CVE ID>'
```

기본 동작은 읽기 전용이다. 명시적 저장은 기존 외부 DB에 평가 스냅샷을 추가하며 CERT Case를 만들지 않는다. 비교 문법·판정·자료 갱신 시 처리 기준은 [외부 영향 범위 평가](APPLICABILITY.md)에 정의한다. 버전 일치는 현재 서비스의 취약점 재현이나 공격 허가를 뜻하지 않는다.

[일괄 처리 설정](examples/automation.example.json)에 보고서·대상 ID·검토 파일·외부 자료를 지정해 `automate '<설정.json>' --output-dir '<출력 폴더>'`로 처리한다. 제공 설정은 로컬 파일 입력 형식이며 실제 보고서나 응답을 포함하지 않는다. 경로는 설정 파일 기준이다. 대상 ID와 검토 기록을 지정해야 등록 준비를 완료할 수 있다.

`automate`는 기본 dry run이며 DB 저장에는 `--apply`와 명시적인 `--cert-db`·`--external-db` 경로가 필요하다. 설정의 `collect=true`는 dry run에서도 공개 API를 조회한다. 보고서·외부 DB 전체 실행은 분산 트랜잭션이 아니며 일부 실패는 실행 결과에 남긴다.

## 코드 구조

| 역할 | 파일 |
|---|---|
| HWP/HWPX 입력·필드 매핑 | [hwp.py](src/casper_db/hwp.py), [hwpx.py](src/casper_db/hwpx.py) |
| 서술형 분류·값 확인 | [narrative.py](src/casper_db/narrative.py), [field_values.py](src/casper_db/field_values.py) |
| 입력 적용 여부·경로 규칙 | [case_policy.py](src/casper_db/case_policy.py) |
| OCR·근거 후보 연결 | [local_ocr.py](src/casper_db/local_ocr.py), [ocr_review.py](src/casper_db/ocr_review.py) |
| 초안·검토·등록 패키지 | [report_drafts.py](src/casper_db/report_drafts.py), [import_workflow.py](src/casper_db/import_workflow.py) |
| 접수·이력·등록·조회 | [report_intake.py](src/casper_db/report_intake.py), [repository.py](src/casper_db/repository.py) |
| 검토 대기·외부 권고 인계 | [reference_context.py](src/casper_db/reference_context.py) |
| 외부 정보·일괄 처리 | [external_vulnerabilities.py](src/casper_db/external_vulnerabilities.py), [automation.py](src/casper_db/automation.py) |
| 대상별 영향 범위 평가 | [applicability.py](src/casper_db/applicability.py), [version_ranges.py](src/casper_db/version_ranges.py) |
| 검증기 결과 계약·일괄 저장 | [retest.py](src/casper_db/retest.py) |

## 지원 범위와 제약

### DB 버전 전환

v6는 Case의 조건부 입력 미적용과 경로 템플릿, v7는 Check의 조건부 입력 미적용과 관찰 시점 증거 메타데이터를 추가한다. 기존 v1~v6 DB는 쓰기 작업을 중지하고 백업한 뒤 `init`으로 명시적으로 전환한다. 조회가 기존 DB를 자동 변경하지는 않는다. 변환은 구조·데이터·버전 번호를 한 트랜잭션에서 처리하며 실패하면 롤백한다. 기존 보고서 버전 JSON·점검 이력·외래키 연결을 보존한다. 기존 Check의 관찰 시점 해시는 소급 생성하지 않는다. `init` 자체가 백업을 생성하는 것은 아니다. 예전 등록 패키지는 현재 규칙으로 다시 준비하고 검증한다.

### 입력과 실행 범위

- 추출은 표 레이블·명시적 항목명 문단과 서술형 규칙에 기반한다. 미지원 양식도 원문을 보존하고 미분류·검토 상태를 반환한다. 임의의 보고서 양식·모든 문장을 정확히 해석한다고 보장하지 않는다.
- 원본은 intake에 보존하지만 추출 JSON은 페이지 배치나 모든 문서 개체를 완전히 재현하지 않는다.
- HWP는 선택 리더의 v5 지원 범위에 제한된다. 암호화·손상·미지원 문서는 처리에 실패할 수 있다.
- OCR은 따옴표·공백·숫자를 잘못 읽거나 흐린 글자를 인식하지 못할 수 있다. 엔진이 신뢰도 점수를 제공하지 않아 `confidence=null`을 유지한다. 검토 전 자동 확정하지 않는다.
- 입력 파일은 32 MB, OCR은 이미지 8개·개별 16 MB·8백만 픽셀 등의 한도가 있다. 벡터 개체는 래스터 OCR 대상이 아니다.
- 해시는 원본·초안·검토의 일관성을 확인한다. 로컬 검토자 이름은 사용자 입력이며 중앙 신원 인증을 대신하지 않는다.
- 기존 팀 DB 전환·운영 배포·접근 권한·민감 자료 보관/폐기·백업 정책은 운영 통합에서 별도로 구성해야 한다.

기존 조회 API는 기본 `127.0.0.1:8001`의 `GET /cases?target_id=...`, `GET /cases/<case_id>`를 제공한다. 기본 조회는 `ready` 사례 대상이며 쓰기 API는 없다. 새 접수 작업 공간을 팀 서비스 DB로 자동 연결하지 않는다.

관련 계약: [매칭 정책](MATCHING_POLICY.md), [파서 입력](PARSER_INPUT_PROPOSAL.md), [체크 검토](CHECK_REVIEW.md), [Case 스키마](schemas/case.schema.json), [체크 스키마](schemas/check.schema.json).
