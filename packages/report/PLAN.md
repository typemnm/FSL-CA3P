# 보고서 생성 모듈 — 조사 결과 및 개발 PLAN

- 작성일: 2026-10-18
- 브랜치: `woohyun212/report-module`. `origin/develop`(`1560b1c`)에서 새로 만들었다.
- 모듈 위치: `packages/report/`. 이 문서도 모듈 안에 둔다.
- 상태: **조사 + 계획만 함. 코드 구현 없음.**
- 근거: §0.1~0.3에 인용한 경로와 줄 번호는 최초 조사 시점(`main` `0c820a0`) 기준이다. `origin/develop` 기준이면 따로 표시했다.

> **결정됨 (2026-10-18):**
> - Q1: develop에서 새 브랜치를 만들어 작업한다.
> - Q2: `integration-manifest.json`, CI 등 통합 관리는 별도 담당자가 맡는다. 이 모듈은 `packages/report/` 안에서만 작업하고 **커밋까지만** 한다(push와 PR은 하지 않음). manifest 등록은 통합 담당자에게 넘긴다(§5 M1 참고).

---

## 0. 조사 요약 (근거)

### 0.1 실행 보고서와 이벤트 — pentest-db 디스크 저장 규약
`agent-dashboard/integrations/pentest-db.mjs`에서 확인한 내용. develop에서는 `packages/adapters/integrations/pentest-db.mjs`로 옮겨졌고, 기존 경로는 재수출(re-export)만 한다.

| 항목 | 내용 | 근거 |
|---|---|---|
| 루트 | `reports/pentest-db-runs/` (gitignore 대상, 첫 finalize 때 생성) | `:9`, `.gitignore` |
| 실행 디렉터리 | `sha256(runId)`. runId는 `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`로 먼저 검증 | `:11`, `:28-34` |
| 이벤트 파일 | `events/<sha256(messageId)>.json` = `{schemaVersion:'1.0', runId, messageId, iteration, recordedAt, event:{stage, request, response}}` | `:185-191` |
| 보고서 파일 | `report.json` = `{schemaVersion:'1.0', runId, storedAt, provenance:{source:'agent-supplied-run-report', storage:'pentest-db-local-json', verifiedByStorage:false}, report}` | `:207-215` |
| 읽기 API | `createPentestDb({reportsDir}).readRun(runId)` → `{runId, events(recordedAt→messageId 순 정렬), report}`. 데이터가 없으면 `null`이고, runId가 다르면 throw | `:225-244` |
| 쓰기 성질 | 0600 임시 파일 → fsync → hard-link로 원자적·불변 기록. 같은 이름의 파일은 내용이 바이트 단위로 같을 때만 허용 | `:122-149` |

`report` 객체는 `agent/src/orchestrator.js`의 `runOnce`가 만든다.
- **성공**(`:425-445`): `{schemaVersion, runId, status:'completed', testProfile, target:{origin,mode,application}, iterations, progress, finding, metrics:{requestCount,parserRuns,iterations}, guardrail:{decisions[]}, referenceContext:{casperDb:{category,assessments(개수),readyCaseCount,evidenceId}, pentestDb:{category,available,evidenceId}}, safety{…}, startedAt, completedAt}`
- **실패**(`:450-468`): `finding`, `referenceContext`, `safety`가 빠지고 `error:{name,code,source,message}`가 들어간다.
- **`finding`**(`agent/src/reasoning-engine.js:205-234`, stored-XSS 기준): `findingId, title, cwe, severity, severityBasis, confidence, status('confirmed'|'not_confirmed'), actorId, resourceId, marker, evidenceRefs[], checks{postCreated…evidencePresent}`, 그리고 한국어 `summary/limitations/remediation`.

> **중요한 발견:** `report.referenceContext.casperDb`에는 **개수와 evidenceId만** 있다(`orchestrator.js:307-312`).
> 재점검 triage의 상세 내용(`observations`, `assessments[]`)은 **`stage==='loop.history'` 이벤트의 `event.response.payload`** 에만 있다(`local-lab-gateway.mjs:213-219`).
> 그러므로 보고서 모듈은 `report.json` 하나만 읽어서는 안 되고 **이벤트까지 함께 읽어야 한다.**

### 0.2 과거 CERT 사례와 재점검 check — casper-db (Python, 읽기 전용)
- 공개 API(`casper-db/src/casper_db/__init__.py`): `CaseStore`, `assess_observation`, `initialize_database`, 모델 `Case/CaseRecord/Check/CheckRecord`.
- 읽기 전용 경로:
  - `CaseStore._connect()`의 기본값은 `mode=ro`(`repository.py:172-190`)이다.
  - 읽기 메서드는 `get`(`:284`, draft 포함), `get_version(case_id, revision)`(`:258`, 스냅숏), `list_versions`(`:272`), `list_for_target`(`:316`, ready만), `find`(`:294`), `list_checks(case_id)`(`:432`, `observed_at` 순)이다.
- ⚠️ `initialize_database()`는 **쓰기 작업**이다. 디렉터리와 테이블을 만들고 마이그레이션을 실행한다(`:127-164`). 대시보드 어댑터는 DB가 없으면 이 함수를 호출한다(`casper-db.mjs:19-20`).
  보고서 모듈은 이 함수를 **절대 호출하지 않는다.** DB가 없거나 스키마 버전이 다르면 보고서에 "과거 사례 DB 사용 불가"라고 표시한다.
- 핵심 필드(`models.py`):
  - `Case`의 필수 필드는 `case_id, title, vulnerability_type, target_id, endpoint, method, parameter, preconditions[], procedure[], success_condition, source_report`이다. `ready` 상태가 되려면 `payload, reported_on, vulnerability_url, severity, description, remediation[]`도 필요하다(`:108-122`).
  - `payload`는 **원문 그대로 저장된다**(`:72-73`).
  - `CheckRecord`의 필드는 `result('confirmed'|'not_reproduced'|'inconclusive'), source('synthetic'|'tool'|'manual'), review_status('draft'|'reviewed'), reviewer, evidence_refs[], evidence_metadata[{reference, sha256, size_bytes}], case_revision, link_review, legacy_review`이다.
  - synthetic check는 reviewed 상태가 될 수 없다(`:198-200`).
- triage(`matching.py`): `ObservationAssessment{observation, decision('retest_candidate'|'manual_review'|'no_match'), matches[CandidateMatch{case_id, case_revision, report_source, vulnerability_type, decision, matched_fields, changed_fields, reason, next_step}], explanation}`.
  reason, next_step, explanation은 이미 보고서에 넣을 수 있는 한국어 문장이고, "현재 취약하다는 판정은 아님"이라는 문구도 들어 있다(`:107-112`).
- 렌더링 선례(`demo.py`): `escaped()`가 모든 값에 `html.escape(str(v), quote=True)`를 적용한다(`:18-19`). 의미 레이블은 `{"retest_candidate":"재점검 후보","manual_review":"수동 확인","no_match":"일치 없음"}`(`:119-123`)이고, 상단에 "모두 모의 자료입니다" 고지 배너를 둔다(`:64`).

### 0.3 보고서 양식
- `casper-db/examples/mock-report-template.md`: 아직 작성하지 않은 양식이다. 항목은 보고 날짜, 사례 번호, 대상과 URL, 종류와 심각도, 발생 방법, 전월 증거, 조치 방안, 패치 상태이며 `Case` 필수 필드와 대응한다.
- `casper-db/examples/previous-month-xss-report.md`: 2열 표 `| 보고서 항목 | 내용 |` 아래 8행으로 구성된다(보고일, 취약점 유형, 발생 URL, 심각도, 상세 발생 방법, 전월 증거, 조치 방안, 현재 패치 상태). **이 표를 표준 레이아웃으로 삼는다.**

### 0.4 develop에서 바뀐 점 (계획에 영향)
- `packages/run-store/index.mjs`: `node:sqlite` 기반 `.runtime/runs.sqlite`를 쓴다.
  - 테이블은 `runs(state_json)`, `run_events`, `artifacts`(sha256), `review_audit`, `model_calls`이다.
  - `state.historyWrite.checks`와 `writeArtifact(id, kind, value)`가 있다. 보고서 산출물을 run에 붙일 수 있는 자리다.
  - ⚠️ `createRunRepository()`는 열 때마다 DDL과 `PRAGMA user_version=1`을 실행하므로 **읽기 전용이 아니다.**
- `packages/contracts/index.mjs`: 공용 `redact()`가 있다(authorization, cookie, set-cookie, apikey, Bearer, URL 자격증명). `assertIdentifier`, `TERMINAL_STATUSES = completed/failed/cancelled/interrupted`도 여기 있다.
- `packages/history/check-sync.mjs`: casper-db에 접근할 때 `spawn(python, ['-c', …], {PYTHONPATH: casper-db/src})`로 Python 서브프로세스와 JSON을 주고받는다. 이것이 **Node→casper-db 연동의 프로젝트 관례**이고, 대시보드 `casper-db.mjs`도 같은 방식이다.
- `integration-manifest.json`: 모듈 id, path, layer, dependencies를 등록하고, `scripts/check-boundaries.mjs`가 상대경로 import를 dependencies 기준으로 검사한다. 새 모듈은 **반드시 manifest에 등록**해야 하며, 이 파일은 공용이므로 사람과 합의가 필요하다.
- 런타임은 Node `>=24 <25`이다(develop의 루트 `package.json`).

---

## 1. 목표와 범위

### 1.1 정의
**한 번의 CA3P 실행(runId)마다 "점검 결과 보고서" 한 부**를 만든다. 보고서 한 부에는 다음 세 가지가 함께 들어간다.
1. 이번 실행의 결과: `finding`, 진행 상태, 가드레일 결정, 지표
2. 과거 사례 대조(재점검 triage): 이번 파서가 관찰한 입력 지점과 전월 CERT 사례의 위치 일치 여부
3. 관련 전월 보고서 원문과 재점검 이력: casper-db의 사례 스냅숏(revision 고정)과 check 기록

### 1.2 하는 일
- 읽기 전용으로 데이터를 모은다(pentest-db 디스크, casper-db SQLite, 이후 run-store).
- 정규화된 **ReportModel(JSON)** 을 만든다.
- 그 모델을 **Markdown(기본)** 과 **HTML(선택, 독립 실행 파일)** 로 렌더링한다.
- 모든 출력에 고지 문구, 출처, 한계를 넣는다.
- 출력할 때 값은 HTML 이스케이프하고 비밀값은 마스킹한다.
- CLI와 프로그램 API를 함께 제공한다.

### 1.3 하지 않는 일
- 취약점을 판정하거나 다시 판정하지 않는다. `finding.status`를 그대로 옮기고, triage 결과를 "취약함"으로 바꾸지 않는다.
- 어떤 저장소에도 쓰지 않는다: casper-db(`add_check`, `review_check`, `initialize_database`), pentest-db(`append`, `finalize`), run-store 모두 해당한다. 출력 파일만 쓴다.
- 대상 사이트, 외부 호스트, LLM에 접근하지 않는다. 네트워크 import를 금지하고 테스트로 강제한다.
- 증거 캡처를 **직접 만들지 않는다**(브라우저 실행 없음). 이미 존재하고 해시가 검증된 이미지 파일만 첨부한다(§2.6).
- 다른 담당자 모듈을 수정하지 않는다. 필요해지면 §7에 적은 합의 항목으로 처리한다.

### 1.4 반드시 지킬 프레이밍 (렌더러 불변식)
| 규칙 | 구현 방법 |
|---|---|
| 위치 일치는 재점검 후보일 뿐이고 현재 취약하다는 판정이 아니다 | triage 섹션 머리에 고정 문구를 넣는다. 레이블은 `demo.py`를 그대로 따른다. "취약", "확인됨" 같은 표현은 이 섹션에서 쓰지 않는다 |
| `ready`/`reviewed`는 상태 표시일 뿐 취약 판정이 아니다 | 상태 열 머리말에 "(상태 표시)"를 붙이고 각주를 단다 |
| 현재 데이터는 전부 synthetic이다 | 문서 맨 위 배너에 넣는다. `source==='synthetic'`인 사례와 check는 행마다 `[가상]` 표시를 붙인다. `run.simulated`가 true이면 배너를 더 강하게 한다 |
| 해시는 바이트를 증명할 뿐 XSS를 증명하지 않는다 | `evidence_metadata` 표 바로 밑에 고정 각주를 넣는다 |
| 저장소는 내용을 검증하지 않는다 | `provenance.verifiedByStorage:false`를 그대로 표시한다. "에이전트가 제출한 결과이며 저장소가 검증하지 않음" |
| 카탈로그는 draft 참고 자료다 | `referenceContext.pentestDb.category`와 `draft_advisory` 문구를 함께 표시한다 |

---

## 2. 입력과 출력

### 2.1 입력 1 — 실행 보고서와 이벤트 (pentest-db 디스크)
- 입력값: `runId`(검증 대상), `reportsDir`(절대 경로, 기본값 `<repo>/reports/pentest-db-runs/`)
- 읽기 방법: `createPentestDb({ reportsDir }).readRun(runId)`를 재사용한다. 디스크 규약을 다시 구현하지 않는다(§7 Q4).
- 사용할 필드:
  - `report.json`: `storedAt`, `provenance`, `report.*`
  - 이벤트에서 꺼낼 것:
    - `stage==='loop.history'` → `event.response.payload.{readyCaseCount, observations[], assessments[], evidenceId}`
    - `stage==='loop.catalog'` → `payload.attackInfo.provenance`. 카탈로그 상태만 쓰고 payload 목록은 출력하지 않는다.
    - `stage` 목록 → 타임라인 부록
- 결측 처리: `report===null`이면 "미완료 실행"으로 표시하고 종료 코드를 따로 둔다. `loop.history` 이벤트가 없으면 triage 섹션을 "자료 없음"으로 렌더링한다.

### 2.2 입력 2 — casper-db (읽기 전용 Python API)
- 입력값: `casperDbPath`(절대 경로, **필수 입력**, 기본값 없음 — `data/*.sqlite3`는 gitignore 대상이다), 선택 입력 `python`(기본값은 `CASPER_DB_PYTHON` 또는 `python3`)
- 읽기 방법: `packages/history/check-sync.mjs`와 같은 구조의 브리지를 쓴다.
  `spawn(python, ['-I', '-c', PROGRAM], { shell:false, env:{PYTHONPATH:<repo>/casper-db/src}, stdin:JSON })`
  - `-I` 플래그는 cwd 오염을 막는다. 단, `PYTHONPATH`까지 무시하므로 `sys.path.insert`로 경로를 넣는다(§7 Q6).
- Python 프로그램이 하는 일(읽기만):
  ```
  store = CaseStore(db)                     # initialize_database 호출 금지
  for (case_id, rev) in 요청된 쌍:           # assessments[].matches[]의 (case_id, case_revision)
      snapshot = store.get_version(case_id, rev).model_dump()   # 대조 당시 revision으로 고정
      current  = store.get(case_id).model_dump()                # 현재 revision과의 차이 표시용
      checks   = [c.model_dump() for c in store.list_checks(case_id)]
  → {status:'ok'|'unavailable', reason?, cases:[{case_id, revision, snapshot, currentRevision, checks}]}
  ```
- 출력 크기 1MB 상한, 시간 제한 15초, stderr는 보고서에 넣지 않는다(경로 노출 방지). 대시보드 어댑터의 `MAX_OUTPUT_BYTES`와 15초 타임아웃 관례를 따른다.
- `assess_observation`을 **다시 실행하지 않는다.** 실행 당시 이벤트에 저장된 assessments를 그대로 쓰는 것이 재현성 면에서 맞다. 다시 실행할지는 "현재 DB 기준 재평가" 옵션으로 둘지 §7 Q5에서 결정한다.

### 2.3 입력 3 — 보고서 양식
- `previous-month-xss-report.md`의 2열 표 행 정의를 **코드 상수(필드 매핑 표)** 로 둔다. 런타임에 md 파일을 파싱하지 않는다. 양식이 바뀌면 테스트가 깨지도록 골든 테스트에서 행 레이블 목록이 같은지 대조한다.
- 매핑(`Case` → 표 행):

| 보고서 항목 | Case 필드 | 비고 |
|---|---|---|
| 보고일 | `reported_on` | |
| 취약점 유형 | `vulnerability_type` | |
| 발생 URL | `vulnerability_url` | 링크로 만들지 않고 코드 스팬으로 출력 |
| 심각도 | `severity` | |
| 상세 발생 방법 | `description` + `preconditions[]` + `procedure[]` | 목록은 `<br>`로 잇지 않고 번호를 붙여 한 줄로 직렬화 |
| 시험 입력 | `payload` | **HTML 이스케이프 + 코드 스팬**. 양식에는 없는 행이므로 접힘 처리 여부는 §7 Q8 |
| 성공 조건 | `success_condition` | |
| 전월 증거 | `prior_evidence` | |
| 조치 방안 | `remediation[]` | |
| 현재 패치 상태 | `patch_status` | "보고서 작성 당시 값" 각주 |
| 출처 | `source`, `source_report`, `revision`, `updated_at` | synthetic이면 `[가상]` 표시 |

### 2.4 출력 포맷 결정
| 포맷 | 용도 | 결정 |
|---|---|---|
| **ReportModel JSON** | 렌더러 입력, 테스트 기준, 다른 모듈(대시보드, run-store artifact) 연동 | **MVP 포함.** `schemaVersion:'report-1.0'` |
| **Markdown** | 기존 양식(`previous-month-xss-report.md`)과 같은 형식, diff 가능, 한국어 CERT 문서 관례 | **MVP 기본 출력** |
| **HTML** | 브라우저 열람과 인쇄. `demo.py`의 독립 HTML 선례 | M4. 외부 리소스와 `<script>` 없이 만들고, `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`를 넣는다 |

이유: 판정과 상태는 모델(JSON)에서 한 번만 계산하고 렌더러는 표현만 맡게 한다. 그래야 프레이밍 불변식과 이스케이프를 렌더러마다 따로 검증할 수 있다. Markdown은 많은 뷰어가 **원시 HTML을 그대로 렌더링하므로**, Markdown에서도 HTML 이스케이프는 필수다.

### 2.5 한 문서로 합치는 섹션 구조 (Markdown 기준)
```
# CA3P 점검 결과 보고서 — <runId>
> [고지 배너] 격리된 로컬 실습 결과 / 데이터 synthetic 여부 / 저장소 미검증(verifiedByStorage:false) / 위치 일치≠취약 판정

## 1. 실행 요약                 (2열 표: 실행 ID, 상태, 시험 프로필, 대상(origin·mode·application), 출처(source/simulated/targetContacted),
                                 시작/종료 시각, 요청 수·파서 실행 수·반복 수, 진행 단계(progress), 저장 시각·provenance)
## 2. 이번 실행 결과(finding)    (표준 2열 레이아웃 재사용 —
                                 보고일=completedAt | 취약점 유형=title+cwe | 발생 위치=target.origin + 행위(POST /api/posts) |
                                 심각도=severity(+severityBasis) | 판정 상태=status·confidence (에이전트의 결정론적 판정, 저장소 미검증) |
                                 상세=summary + checks 표(항목별 true/false) | 증거 참조=evidenceRefs(불투명 ID, 원본 미포함) |
                                 조치 방안=remediation | 한계=limitations)
   실패 실행이면 → "2. 실행 실패" (error.code/source/message, progress 단계별 도달 여부)
## 3. 과거 사례 대조 (재점검 triage)   [고정 문구: "위치 일치는 재점검 후보 신호이며 현재 취약 판정이 아님"]
   표: 요청 위치 | 입력 변수 | 입력 위치 | 판정(재점검 후보/수동 확인/일치 없음) | 관련 사례(case_id@rev) | 일치/변경 필드 | 이유 | 다음 단계
   + readyCaseCount, casper evidenceId
## 4. 관련 전월 보고서           사례마다 "### CASE-001 (rev N) [가상]" + 표준 2열 표(§2.3 매핑) — 대조 당시 revision 스냅숏
                                 현재 revision이 다르면 "이후 rev M으로 갱신됨" 표시
## 5. 재점검 이력                사례별 표: 관찰 시각 | 결과 | 출처 | 검토 상태(상태 표시) | 검토자 | run_id | 증거 참조
                                 evidence_metadata 표(reference, sha256, size) + 각주 "해시는 바이트 일치만 증명, XSS 증명 아님"
                                 이번 runId와 같은 run_id의 check는 강조 표시(develop의 historyWrite 연동)
## 6. 가드레일 결정과 안전 속성     decisions 표(stage, decision, ruleId, reason) + safety 불리언 표
## 7. 참고 자료 출처와 한계         pentest-db 카탈로그(draft_advisory, currentRunVerified:false), casper-db 경로·스키마 버전, 생성기 버전
## 부록 A. 실행 타임라인            이벤트 stage·recordedAt·iteration 목록 (요청·응답 본문은 기본 생략, --include-payloads로 마스킹 후 포함)
```

### 2.6 증거 이미지(캡처) — 현재 구조로 가능한가?

**결론: 지금은 불가능하다.** 첨부할 캡처가 만들어지지도 저장되지도 않는다. 근거는 모두 `origin/develop` 기준이다.

| # | 단계 | 현황 | 근거 |
|---|---|---|---|
| 1 | **생성** | 브라우저 검증 함수 `observeStoredXssExecution`은 `{executed, marker, postId, pageUrl, postVisible, payloadPresent, bindingCalled, errors}` 불리언과 문자열만 반환한다. `page.screenshot` 호출이 저장소 전체에 없다 | `packages/adapters/integrations/xss-parser.mjs:194-302`. `git grep screenshot` 결과 0건 |
| 2 | **참조** | `evidenceId`/`evidenceRefs`는 `parser-evidence-<uuid>`, `lab-evidence-<uuid>` 같은 **무작위 ID**이고 파일을 가리키지 않는다 | `packages/adapters/local-lab-gateway.mjs:218, 241, 295` |
| 3 | **저장(run-store)** | `writeArtifact(id, kind, value)`는 값을 JSON으로 직렬화해 `<sha256>.json`으로만 쓴다. API `/api/artifacts/:id`도 `application/json` 첨부로만 내보낸다. **바이너리를 지원하지 않는다** | `packages/run-store/index.mjs:240-251`, `apps/api/server.mjs:89-100` |
| 4 | **저장(pentest-db)** | 이벤트와 보고서는 JSON이고 envelope 상한이 1MB다. 이미지를 base64로 넣는 것은 부적절하다 | `agent/src/protocol.js:6` (`MAX_MESSAGE_BYTES`) |
| 5 | **전월 사례** | `Case.prior_evidence`는 텍스트 필드 하나뿐이다. 파일 참조 필드가 없다 | `models.py:67` |
| 6 | **재점검 check** | ✅ **유일하게 파일을 다룰 수 있는 경로.** `evidence_refs`(evidence_root 기준 상대 경로) + `evidence_metadata{reference, sha256, size_bytes}`로 기록되고, `inspect_evidence`는 **어떤 형식의 파일이든** 바이트 해시를 계산한다(PNG도 가능). 문서 예시에도 `RUN-REAL-001/browser-proof.png`가 있다. 다만 현재 worker가 연결하는 파일은 run-report JSON artifact 하나뿐이다 | `casper_db/evidence.py`, `CHECK_REVIEW.md:36`, `packages/history/check-sync.mjs:47-48` |

**보고서 모듈 범위 안에서 할 수 있는 것(계획에 포함):** 이미지를 *받아서 검증하고 넣는* 쪽만 만든다. 캡처가 생기면 바로 쓸 수 있게 해 둔다.

- **입력 경로 2가지**
  - (a) casper check의 `evidence_refs`를 `--evidence-root` 아래에서 찾아 sha256을 다시 계산한다. `evidence_metadata`와 일치할 때만 넣고, 다르면 "무결성 불일치 — 이미지 생략" 자리표시를 넣는다.
  - (b) 점검자가 수동으로 찍은 캡처를 `--attach <file>[:caption]`으로 넘긴다. 이 경우 보고서에 해시와 "수동 첨부(출처 미검증)" 표시를 남긴다.
- **파일 검증**
  - 확장자가 아니라 매직 바이트로 PNG, JPEG, WebP만 허용한다. **SVG는 거부**한다(스크립트 위험).
  - 크기 상한은 파일당 5MB, 전체 20MB로 한다.
  - realpath가 루트 안에 있어야 하고 심링크는 거부한다. 경로 규칙은 `inspect_evidence`와 같게 맞춘다.
- **렌더링**
  - HTML: `data:` URI로 넣고 CSP는 `img-src data:`만 연다.
  - Markdown: `<out>/assets/<sha256>.<ext>`로 복사하고 상대 링크를 단다.
  - ReportModel JSON: 메타데이터(ref, sha256, size, mime, caption, source)만 넣고 바이트는 넣지 않는다.
- **프레이밍:** 모든 이미지 캡션 아래에 "캡처는 화면의 바이트일 뿐 XSS 실행을 증명하지 않음. 실행 판정 근거는 `finding.checks.bindingCalled` 등 결정론적 검사"라는 문구를 고정으로 넣는다. synthetic이면 `[가상]`을 붙인다.
- **민감정보:** 이미지는 자동 마스킹이 불가능하다. 그래서 `--no-images` 옵션을 두고, 이미지가 들어간 출력에는 "이미지 내 민감정보는 사람이 확인해야 함" 경고를 단다.

**다른 담당자 작업이 필요한 것(제안만 하고 직접 수정하지 않음):** 자동 캡처를 하려면 아래 세 가지가 필요하다.
1. **xss-parser 어댑터**(`packages/adapters`): 검증 직후 해당 `.post-card` 요소를 `page.screenshot({type:'png'})`로 찍는다. 결과는 envelope에 넣지 않고 artifacts 디렉터리에 파일로 쓴 다음, `{kind:'screenshot', sha256, ref}`만 반환한다.
2. **run-store**: 바이너리 artifact API를 추가한다. 예: `writeArtifactBytes(runId, kind, bytes, {contentType})`. 지금은 `.json` 전용이다.
3. **worker/history**: 스크린샷 artifact를 check의 `evidence_refs`에 연결해 casper 리뷰 대상에 포함시킨다.

→ 위 세 가지가 생기면 보고서 모듈은 경로 (a)로 **코드 변경 없이** 자동 첨부할 수 있다.

---

## 3. 모듈 위치와 언어 결정

| 안 | 내용 | 장점 | 단점 |
|---|---|---|---|
| **A. Node ESM 모듈 신설** (`packages/report/`, develop 기준) | Node 내장 기능만 사용. casper-db는 Python 서브프로세스 브리지로 읽기 | 프로젝트 관례(Node 내장만, `node --test`, 서브프로세스 브리지)와 같다. pentest-db `readRun`과 contracts `redact()`를 그대로 재사용할 수 있다. 이후 대시보드, worker, run-store artifact 연동이 자연스럽다. 소유 경계가 분명하다(새 디렉터리) | casper-db 모델을 Python 쪽에서 직렬화한 JSON으로만 받는다(타입 공유 없음). Python 런타임이 필요하지만 DB가 없을 때는 우아하게 강등한다 |
| B. casper-db Python 확장 (`casper_db/report.py`) | `demo.py`의 `render()`를 발전시킨다 | pydantic 모델을 직접 쓰고 `html.escape` 선례가 있다 | **다른 담당자(gyun) 모듈을 수정해야 한다**(PR 규칙 위반 소지). pentest-db JSON과 contracts `redact()`를 Python으로 다시 구현해야 하고 Node 쪽과 이중 관리가 된다. 대시보드 연동 시 또 서브프로세스가 필요하다 |
| C. 대시보드 통합 (`agent-dashboard/` 또는 `apps/`) | 실행 직후 UI에서 바로 생성 | 사용자 동선이 짧다 | 표현 계층에 도메인 로직이 섞인다. 대시보드 담당 영역이고, develop에서 구조가 이미 크게 바뀌었다. CLI와 배치 생성이 어렵다 |

**추천: A안.** 핵심 근거는 다음과 같다.
1. 다른 담당자 모듈을 수정하지 않고(새 디렉터리) 저장된 산출물만 읽는다.
2. Node에서 casper-db를 쓰는 관례는 이미 두 곳(`casper-db.mjs`, `check-sync.mjs`)에 있다.
3. 비밀값 마스킹은 develop의 공용 `redact()`를 재사용해 다른 모듈과 같은 기준을 지킨다.
4. C안(대시보드 버튼, API 엔드포인트)은 A안 위에 얇은 연동으로 나중에 붙인다(M5, 담당자 합의 후).

- 위치: develop 기준이면 **`packages/report/`**(layer `reporting`), main 기준이면 루트 `report/`.
- 브랜치: `woohyun212/report-module`. README 규칙이 `닉네임/모듈명`이므로 이미 맞다.
- 언어 규약: `.mjs`, Node 내장 기능만, `'use strict'`가 필요 없는 ESM, 런타임 의존성 0개.

---

## 4. 인터페이스와 계약

### 4.1 다른 모듈과의 경계 (전부 읽기 전용)
| 대상 | 접근 방식 | 금지 사항 |
|---|---|---|
| pentest-db 디스크 | `readRun(runId)` (develop: `packages/adapters/integrations/pentest-db.mjs` import → manifest 의존성 `adapters`) | `exchange()`(append, finalize) 호출 금지 |
| casper-db | Python 서브프로세스. `CaseStore` 읽기 메서드만 사용 | `initialize_database`, `add*`, `update`, `review_check` 금지. DB 경로 기본값 금지 |
| run-store (M5) | 별도 읽기 함수. `createRunRepository`는 DDL을 실행하므로 쓰지 않는다. `new DatabaseSync(path, {readOnly:true})`로 직접 SELECT하거나 run-store 담당자에게 `openReadOnly` 추가를 요청(§7 Q3) | runs, artifacts 테이블 쓰기 금지 |
| contracts | `redact`, `assertIdentifier`, `digest` import | — |
| 네트워크 | 없음. `node:http/https/net/tls`와 `fetch` 사용 금지(테스트로 강제) | — |

### 4.2 호출 방식
- **CLI**
  ```
  node packages/report/cli.mjs --run-id <id> --reports-dir <abs> [--casper-db <abs>] \
       [--format md|html|json] [--out <path>|-] [--include-payloads] [--generated-at <iso>]
  ```
  - 종료 코드: `0` 성공, `2` 입력 오류(runId 형식, 상대 경로), `3` 실행 없음, `4` 보고서 미완료(이벤트만 있음)
  - `--out` 파일은 `wx` 플래그(0600)로 쓰고 기존 파일을 덮어쓰지 않는다.
- **프로그램 API**
  ```js
  loadRun({ runId, reportsDir })                         // → { runId, events, report } | null
  loadCasperContext({ dbPath, refs, python, signal })    // → { status, cases[] } (unavailable 허용)
  buildReportModel({ run, casper, generatedAt, generator }) // 순수 함수 → ReportModel
  renderMarkdown(model) / renderHtml(model)              // 순수 함수 → string
  ```
  `buildReportModel`과 렌더러는 순수 함수이고, I/O는 `load*`에만 둔다. 같은 입력이면 같은 바이트가 나오도록 결정적으로 만든다. `generatedAt`은 주입받는다.

### 4.3 데이터 계약 — ReportModel `report-1.0` (요지)
```jsonc
{
  "schemaVersion": "report-1.0",
  "generator": { "module": "report", "version": "0.1.0" },
  "generatedAt": "<ISO>",
  "notices": ["synthetic", "isolated-local-lab", "storage-unverified", "location-match-is-not-verdict"],
  "run": { "runId", "status", "testProfile", "target", "source", "simulated", "targetContacted",
           "startedAt", "completedAt", "storedAt", "provenance": { "verifiedByStorage": false, ... },
           "progress", "metrics", "error"? },
  "finding": { ...finding 원본 필드, "verdictSource": "agent-deterministic-reflect" } | null,
  "triage": { "available": bool, "readyCaseCount", "evidenceId",
              "rows": [{ "observation", "decision", "decisionLabel", "explanation", "matches": [...] }] },
  "priorCases": { "status": "ok|unavailable|not-requested", "reason"?,
                  "cases": [{ "caseId", "revision", "currentRevision", "synthetic": bool, "fields": {...}, "checks": [...] }] },
  "guardrail": { "decisions": [...] },
  "safety": {...} | null,
  "references": { "catalog": { "status": "draft_advisory", "currentRunVerified": false, "evidenceId" } },
  "timeline": [{ "stage", "recordedAt", "iteration" }]
}
```
- ReportModel에 들어가는 문자열은 **원문**이다(이스케이프 전). 이스케이프는 **렌더러 출력 경계에서만** 한다. 이중 이스케이프를 막고, JSON 소비자가 직접 이스케이프 책임을 진다는 점을 계약에 명시한다.
- 마스킹은 **모델을 만들 때 먼저** 적용한다(`redact()` + 보조 규칙). 모델 JSON 자체에도 비밀값이 남지 않게 한다.
  - 보조 규칙: `reasoning_content`, `reasoning`, `chainOfThought`, `rawResponse`, `prompt`, `messages` 키는 삭제한다.
  - `sk-[A-Za-z0-9]{16,}` 형태 문자열은 `[REDACTED]`로 바꾼다.
- 이스케이프 규칙:
  - HTML: `& < > " '`를 엔티티로 바꾼다(`demo.py`의 `escaped()`와 같다).
  - Markdown 표 셀: 위 HTML 이스케이프를 한 뒤 `|`→`\|`로 바꾸고 개행은 공백으로 바꾼다. 코드 스팬은 내용 안의 백틱 길이보다 긴 펜스로 감싼다.
  - URL은 절대 자동 링크로 만들지 않는다. `vulnerability_url`과 `target.origin`은 코드 스팬으로 출력한다.

---

## 5. 마일스톤

| 단계 | 작업 | 산출물 | 완료 기준 |
|---|---|---|---|
| **M0. 합의와 기준 정리** | ✅ Q1(develop 기준), Q2(모듈 범위 내 작업, 커밋만) 결정. 나머지 Q3 이후 항목 확인 | 이 문서 | 완료 |
| **M1. 스캐폴딩** | `packages/report/{package.json, index.mjs, cli.mjs, README.md, tests/}`. 네트워크와 쓰기 금지 경계 테스트. manifest는 **수정하지 않는다.** 통합 담당자에게 넘길 등록안 `{id:'report', path:'packages/report', layer:'reporting', dependencies:['contracts','adapters']}`을 README에 적는다 | 빈 API와 CLI `--help`, 경계 테스트 | `node --test packages/report/tests/` 통과 |
| **M2. 데이터 로더** | `loadRun`(readRun 래핑, runId 검증, 미완료와 실패 구분, `loop.history`·`loop.catalog` 추출), `loadCasperContext`(Python 브리지, 읽기 전용, unavailable 강등, 1MB와 15s 제한) | 로더 2종과 synthetic fixture 생성기 | 정상, 실패 run, 이벤트만 있는 run, 없는 run, DB 없음, 스키마 불일치 모두 테스트 |
| **M3. 모델과 Markdown 렌더러** | `buildReportModel`(마스킹, 프레이밍 notices, 레이블 매핑), `renderMarkdown`(§2.5 구조, 이스케이프 유틸) | `report.md` 골든 파일(completed와 failed 2종) | 골든 일치, 이스케이프·마스킹·프레이밍 테스트 통과 |
| **M3.5 증거 이미지 첨부** | §2.6 경로 (a) casper `evidence_refs` 재해시 검증, (b) `--attach`. 매직 바이트, 크기, 경로 검증. MD는 assets 복사, HTML은 data URI | 이미지 포함 골든 출력 | 해시 불일치 시 생략, SVG와 심링크와 루트 밖 경로 거부, `--no-images` 동작 |
| **M4. HTML 렌더러** | 독립 HTML(CSP meta, 스크립트 없음). `demo.py` 스타일을 참고 | `report.html` 골든 | `<script`, `on*=` 속성이 없음을 검증. 페이로드가 이스케이프된 형태로만 나타남 |
| **M5. 연동 (선택, 합의 필요)** | run-store 읽기 어댑터. `writeArtifact(runId,'report',model)`로 보고서를 붙이는 훅(worker 또는 application 담당과 합의). 대시보드 "보고서 내려받기" 버튼 | 연동 PR(각 담당자 리뷰) | 담당자 승인과 해당 모듈 테스트 통과 |
| **M6. 검증과 문서** | 독립 리뷰(code-reviewer, security-reviewer). README와 AGENTS.md 작성. VERIFICATION 기록 | 리뷰 결과, 문서 | 리뷰 지적 해소, CI 통과 |

---

## 6. 테스트 전략

- **러너:** `node --test packages/report/tests/`. ⚠️ manifest에 등록하기 전까지는 `scripts/ci-plan.mjs`(active 모듈만 탐색)와 `check-boundaries.mjs`가 **이 모듈을 검사하지 않는다.** 따라서 커밋 전에 직접 실행하고, import 경계(contracts와 adapters만 허용)는 모듈 자체 테스트로 확인한다.
  - casper-db 쪽 코드는 수정하지 않으므로 pytest는 추가하지 않는다.
  - Python 브리지는 node 테스트에서 실제 Python으로 검증한다. Python이나 pydantic이 없으면 `t.skip`하고, CI 환경(`requirements-ci.lock`)에서는 실행한다.
- **synthetic fixture 구성**
  1. pentest-db: 임시 디렉터리에서 **실제 `createPentestDb({reportsDir:tmp}).exchange()`** 로 append·finalize envelope를 써서 run을 만든다. 손으로 JSON을 만드는 것보다 디스크 규약이 바뀔 때 테스트가 깨지므로 계약 테스트 역할을 한다. completed(confirmed와 not_confirmed), failed(`GUARDRAIL_DENIED`) 세 종류를 만든다.
  2. casper-db: 임시 경로에서 `initialize_database`와 `add`(`case.example.json` 기반으로 `target_id='vul-web-1'`, `/api/posts`, `content`, `body`, `ready` — `scripts/seed-lab-history.mjs`와 같은 형태), `add_check`(synthetic, draft)를 실행한다. **이 쓰기는 테스트 준비 단계에서만** 하고, 보고서 코드는 읽기만 한다.
- **검증 항목**

| 범주 | 테스트 |
|---|---|
| 정합성 | finding 필드, triage assessments, 사례 스냅숏(revision 고정), checks가 모델과 출력에 빠짐없이 그대로 반영된다. `loop.history` 이벤트가 정확히 매핑된다 |
| 프레이밍 | 모든 출력에 고지 배너와 triage 고정 문구가 있다. `retest_candidate` 행 근처에 "취약/확인됨" 단어가 없다. synthetic 행에 `[가상]`이 붙는다. `verifiedByStorage:false`가 노출된다. 해시 각주가 있다 |
| 이스케이프 | payload `"<script>alert(1)</script>"`, `<img src=x onerror=…>`, `"`, `'`, `` ` ``, `|`, 개행이 들어 있는 사례 → MD와 HTML 출력에 원문 `<script`, `onerror=`가 없고 엔티티 형태만 있다. 이중 이스케이프(`&amp;lt;`)가 없다 |
| 마스킹 | fixture 이벤트에 `Authorization`, `Cookie`, `Set-Cookie: sid=…`, `deepseekApiKey`, `sk-…`, `reasoning_content`를 심는다 → 모델 JSON, MD, HTML 어디에도 원문이 없다 |
| 실패와 결측 | failed run → error 섹션. 이벤트만 있는 run → 종료 코드 4. DB 경로 미지정이나 파일 없음 → `priorCases.status='unavailable'`이고 크래시하지 않는다. DB 파일이 없을 때 **새로 만들지 않는다**(실행 후 파일 부재 확인) |
| 읽기 전용 | 보고서 생성 전후로 casper DB 파일과 reports 디렉터리의 sha256이 같다 |
| 보안 경계 | runId `../x`와 129자 거부. 상대 경로 거부. 소스에 `node:http(s)|net|tls|fetch(`가 없다(`run-once.test.js`의 방식). 출력 파일이 이미 있으면 덮어쓰지 않는다 |
| 결정성 | 같은 입력과 `generatedAt`이면 바이트가 같다(골든 파일) |

---

## 7. 미해결 질문과 결정이 필요한 항목

| # | 질문 | 담당자 | 제안 |
|---|---|---|---|
| Q1 | ~~develop 기준으로 개발할지~~ | — | ✅ **결정:** develop에서 새 브랜치 |
| Q2 | ~~manifest 등록~~ | 통합 담당 | ✅ **결정:** 통합 담당자가 처리. 이 모듈은 범위 안에서 작업하고 커밋만 한다 |
| Q13 | 자동 증거 캡처(§2.6의 1~3번: xss-parser 스크린샷, run-store 바이너리 artifact, check 연결)를 각 담당자에게 요청할지 | adapters/run-store/worker 담당 | 요청한다. 보고서 모듈은 그 전까지 수동 첨부와 casper `evidence_refs`로 대응 |
| Q14 | 이미지 내 민감정보 확인 책임자(자동 마스킹 불가) | 사용자/보안 | 보고서 생성자가 확인. 기본은 이미지 포함, `--no-images` 제공 |
| Q3 | run-store(`.runtime/runs.sqlite`)도 입력으로 지원해야 하는가? 그렇다면 읽기 전용 열기 API(`openReadOnly`)를 run-store에 추가해 줄 수 있는가? | run-store 담당 | MVP는 pentest-db 디스크만 지원, M5에서 추가 |
| Q4 | pentest-db `readRun`을 adapters에서 import해 재사용할지, 보고서 모듈 안에서 읽기 전용 리더를 별도로 둘지 | pentest-db 담당(nahyun06) | 재사용(디스크 규약의 단일 소스) |
| Q5 | triage는 실행 당시 저장된 assessments만 쓸지, "현재 DB 기준 재평가"(`assess_observation` 재실행)를 옵션으로 둘지 | casper-db 담당(gyun) | 저장값만 기본으로 하고, 재평가는 별도 섹션으로 둘지 추후 논의 |
| Q6 | Python 브리지에 `-I`(격리 모드)를 쓰고 `sys.path`를 직접 주입할지, 기존 관례(`PYTHONPATH`, `-I` 없음)를 따를지 | casper-db/보안 | `-I` + 명시 주입 |
| Q7 | 보고서 단위: run 1건당 1부만인가, 월간 집계(여러 run과 사례 묶음)도 필요한가? | PM/사용자 | MVP는 run 단위 |
| Q8 | 시험 입력(payload) 원문을 보고서 본문에 보일지, 해시나 접힘 처리만 할지 | 사용자/보안 | 이스케이프한 코드 스팬으로 노출하되 `--redact-payloads` 옵션 제공 |
| Q9 | 생성된 보고서 파일의 저장 위치와 보존 정책(`reports/generated/`? gitignore?) | 팀 | `reports/generated/<sha256(runId)>/report.{md,html,json}`, gitignore 대상 |
| Q10 | BOLA 레거시 프로필(`agent_cross_user_delete_canary`)의 finding도 지원해야 하는가? (checks 필드 구성이 다름) | agent 담당 | 공통 필드만 렌더링하고 checks는 일반 키-값 표로 처리 |
| Q11 | 대시보드나 API에 "보고서 생성" 버튼과 엔드포인트를 둘지, 둔다면 누가 구현할지 | dashboard/api 담당 | M5, 담당자 구현 + 보고서 모듈 API 제공 |
| Q12 | 출력 언어: 한국어만인가, 영문 병기가 필요한가? | 사용자 | 한국어만 |
