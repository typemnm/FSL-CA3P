# 보고서 생성 모듈(Report Agent) — 조사 결과 및 개발 PLAN

- 작성일: 2026-10-18 / 개정: 2026-10-19
- 브랜치: `woohyun212/report-module`. `origin/develop`(`1560b1c`)에서 새로 만들었다.
- 모듈 위치: `packages/report/`. 이 문서도 모듈 안에 둔다.
- 상태: **조사 + 계획만 함. 코드 구현 없음.**
- 근거: §0.1~0.3에 인용한 경로와 줄 번호는 최초 조사 시점(`main` `0c820a0`) 기준이다. `origin/develop` 기준이면 따로 표시했다.

> **결정됨:**
> - (10-18) develop에서 새 브랜치를 만들어 작업한다.
> - (10-18) 통합 관리(`integration-manifest.json`, CI, docker-compose)는 별도 담당자가 맡는다. 이 모듈은 `packages/report/` 안에서만 작업하고 **커밋까지만** 한다.
> - (10-19) 보고서 모듈은 파이프라인 안의 **독립 Agent**다. 단계는 두 개다.
>   1. **촬영(capture):** 실습 환경이 내려가기 **전에** 대상 origin에 접속해 사진 2장을 찍는다.
>   2. **작성(build):** 환경이 내려간 **뒤에** 저장된 데이터와 사진으로 보고서를 만든다.
> - (10-19) 사진은 ① 입력 지점, ② 피해자 관점 결과 화면 두 장만 넣는다. PoC 요청, 응답, 점검 페이로드는 **텍스트**로 넣는다.
> - (10-19) 보고서 문서는 [python-hwpx](https://github.com/airmang/python-hwpx)를 써서 **HWPX**로 만든다.
> - (10-19) **범용 설계:** 코어(취약점 종류를 모름) + 취약점 프로필(stored_xss, generic, bola) + 대상 어댑터(vul-web-1)의 3계층으로 나눈다(§3).
> - (10-19) dashboard/worker 앱 경로는 테스트용이고, 실제 agent 파이프라인은 따로 있다(아직 원격 저장소에 없음, §7 Q1). 이 모듈은 특정 호출자에 묶이지 않는 계약(§4)으로 만든다.

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

### 0.5 실습 게시판 수명과 촬영 관련 사실 (develop, 10-19 확인)
- **테스트용 app 경로에서는 게시판이 run마다 생성되고 종료된다.**
  - `startLocalLab`이 임시 디렉터리, `PORT=0`, run별 쿠키 비밀값으로 vul-web-1을 띄운다(`packages/adapters/local-lab-gateway.mjs:520-566`).
  - run이 끝나면 worker의 `finally`에서 `runtime.close()`가 호출되고, 이어서 프로세스 SIGTERM/SIGKILL과 임시 데이터 삭제가 일어난다(`apps/worker/worker.mjs:110`, `local-runtime.mjs:366-372`).
  - 상시 실행되는 vul-web-1 서비스는 없다(`docker-compose.yml`에는 `dashboard` 하나뿐).
  - 따라서 **촬영은 환경을 정리하기 전에** 해야 한다.
- 원격 브랜치 15개를 확인한 결과, 테스트·데모 외에 `runOnce()`를 호출하는 곳은 `apps/application/local-runtime.mjs:238`뿐이다. 실제 파이프라인 코드는 아직 원격 저장소에 없다.
- core는 대상을 `http://127.0.0.1:<port>` origin으로만 받는다(`orchestrator.js:14-25`). 게시판 수명은 호출자가 정한다.
- 게시판은 쿠키가 없는 요청을 **alice로 로그인시킨다**(`vul-web-1/server.js:114-118`). 공격자도 alice다(`orchestrator.js:266-267`). 계정 전환은 `POST /api/session {userId}`로 하고, 이때 쿠키만 바뀐다(`server.js:152-166`).
- `loop.act` 이벤트 구조
  - 요청 payload: `{operation:'execute_curl', session, curl:{method, url, body}}` (`agent/src/curl-command.js:16-18`)
  - 응답 payload: `{success, guardrail, request:{method,url,session}, response:{status, ok, bodyJson}, evidenceId}` (`local-lab-gateway.mjs:286-296`)

---

## 1. 목표와 범위

### 1.1 정의
Report Agent는 **한 번의 실행(runId)마다 한글(HWPX) 취약점 보고서 한 부**를 만든다. 특정 취약점에 묶이지 않는 **범용 보고서 모듈**이다.
- 취약점별 차이(재현 절차, 텍스트 증거의 이름, 촬영할 장면, 검사 항목 레이블, 영향 설명)는 **취약점 프로필**이 정한다.
- 사이트별 차이(선택자, 계정 전환 방법)는 **대상 어댑터**가 정한다(§3).
- 코어는 취약점 종류를 모른다.

보고서 한 부에는 다음이 들어간다.
1. 이번 실행의 취약점(finding) 목록: 상세, 재현 절차, PoC 요청과 응답, 입력값(모두 텍스트), 증거 사진, 판정 검사표
2. 과거 사례 대조(재점검 triage), 관련 전월 보고서, 재점검 이력(casper-db)
3. 가드레일 결정, 출처와 한계

현재 구현 대상 프로필은 다음과 같다.
| 프로필 | 상류 `testProfile` | 상태 |
|---|---|---|
| `stored_xss` | `stored_xss_canary` | **1순위 구현** (사진: ① 입력 지점, ② 피해자 관점 결과 화면) |
| `generic` | (미등록 프로필 전부) | **1순위 구현.** 공통 필드, checks 키-값 표, PoC 텍스트만 넣고 사진은 넣지 않는다. "프로필 미등록 — 일부 섹션 생략" 고지를 붙인다 |
| `bola` | `agent_cross_user_delete_canary` | 2순위. **인터페이스 검증용 두 번째 구현체.** 상류 데이터가 이미 있어 비용이 작다 |

### 1.2 두 단계 구조
```
 실제 agent 파이프라인
 ─ observe → knowledge → think → act → verify → reflect → finalize ─┐
                                                                     │ (환경 종료 전)
                     ┌───────────────────────────────────────────────▼─────────────┐
                     │ ① report.capture  (Node + Playwright)                       │
                     │   프로필의 촬영 계획 × 대상 어댑터의 선택자                       │
                     │   → 범용 촬영 엔진(샌드박스) → PNG + sha256 → 영속 볼륨          │
                     └───────────────────────────────────────────────┬─────────────┘
                                                      실습 환경 / Docker 종료
                     ┌───────────────────────────────────────────────▼─────────────┐
                     │ ② report.build    (Python + python-hwpx)                    │
                     │   로더(run 데이터, casper-db, 사진) → 프로필이 finding 해석      │
                     │   → 범용 ReportModel(JSON) → 범용 렌더러 → report.hwpx           │
                     └─────────────────────────────────────────────────────────────┘
```

### 1.3 하는 일
- **capture:** 프로필과 어댑터가 만든 **선언적 촬영 계획**을 읽기 전용 샌드박스 브라우저로 실행하고, 사진을 해시·메타데이터와 함께 저장한다.
- **build:** 저장소를 읽기 전용으로 읽고, 프로필로 finding을 해석해 범용 ReportModel을 만든 뒤 HWPX로 렌더링한다. Markdown 미리보기는 선택 출력이다.
- 모든 출력에 고지 문구, 출처, 한계를 넣는다. 비밀값은 마스킹한다.

### 1.4 하지 않는 일
- **판정하지 않는다.** `finding.status`를 그대로 옮긴다. 프로필은 표현만 매핑하고 판정 로직을 갖지 않는다. 촬영 중 관찰한 신호(예: canary 콜백)는 기록만 하고 판정에 쓰지 않는다.
- **공격하지 않는다.** capture는 대상의 데이터를 만들거나 바꾸는 요청을 보내지 않는다. 상태를 바꾸는 요청은 **대상 어댑터의 허용 목록**에 있는 것(예: 계정 전환)만 보낸다(§2.6).
- **저장소에 쓰지 않는다.** casper-db, pentest-db, run-store는 모두 읽기만 한다.
- 기록된 loopback origin이 아닌 곳(외부 호스트, 임의 URL)에는 접속하지 않는다.
- 다른 담당자 모듈을 수정하지 않는다. 필요한 변경은 §7에 요청 항목으로 적는다.

### 1.5 반드시 지킬 프레이밍 (불변식, 코어가 강제하며 프로필이 끌 수 없다)
| 규칙 | 구현 방법 |
|---|---|
| 위치 일치는 재점검 후보일 뿐 현재 취약 판정이 아니다 | triage 섹션 머리에 고정 문구. 레이블은 `demo.py`와 같게 "재점검 후보 / 수동 확인 / 일치 없음" |
| `ready`/`reviewed`는 상태 표시일 뿐 취약 판정이 아니다 | 상태 열 머리말에 "(상태 표시)"와 각주 |
| 현재 데이터는 전부 synthetic이다 | 표지 고지 상자. synthetic 행에는 `[가상]` |
| 해시는 바이트만 증명할 뿐 취약점을 증명하지 않는다 | 해시 표 각주 |
| **사진은 보조 자료이며 판정 근거가 아니다** | 모든 사진 캡션 아래 고정 문구: "판정 근거는 결정론적 검사(판정 검사표)" |
| 저장소는 내용을 검증하지 않는다 | `verifiedByStorage:false`를 그대로 표시 |
| 카탈로그는 draft 참고 자료다 | `draft_advisory` 표시 |

---

## 2. 입력과 출력

### 2.1 입력 — 실행 보고서와 이벤트 (공통 로더)
- 1차 원천은 pentest-db 디스크 규약(§0.1)이다: `reports/pentest-db-runs/<sha256(runId)>/report.json`, `events/*.json`.
  실제 파이프라인이 run-store(SQLite)를 쓴다면 읽기 전용 로더를 추가한다(§7 Q3).
  로더는 원천 형식만 다루고, 취약점 의미는 해석하지 않는다.
- **공통 코어가 직접 쓰는 필드**(두 프로필 모두 같은 구조. `reasoning-engine.js`의 BOLA `:154-171`, XSS `:205-234`)

| 보고서 항목 | 원천 |
|---|---|
| 실행 메타 | `report.{runId, status, testProfile, target, startedAt, completedAt, metrics, progress}`, `storedAt`, `provenance` |
| finding 공통 필드 | `findingId, title, cwe, severity, severityBasis, confidence, status, evidenceRefs, checks, summary, limitations, remediation` |
| PoC 요청(텍스트) | `stage==='loop.act'` 이벤트의 `event.request.payload.curl` (method, url, body). HTTP 요청이면 프로필과 무관하게 같은 형식이다. `redact()`를 한 번 더 적용한다 |
| 응답(텍스트) | `loop.act` 이벤트의 `event.response.payload.response` (status, bodyJson). `setCookie`가 있으면 제거한다 |
| triage | `stage==='loop.history'` 이벤트의 `payload.{readyCaseCount, observations, assessments}` |
| 가드레일, 안전 속성 | `report.guardrail.decisions`, `report.safety` |

- **프로필이 해석하는 필드**

| 항목 | stored_xss | bola | generic |
|---|---|---|---|
| finding 고유 필드 → `profileData` | `marker`, `actorId`, `resourceId`(postId) | `actorId`, `ownerId`, `resourceId` | 공통 필드에 없는 키 전부 |
| 추가 텍스트 증거 | "점검 페이로드" = `curl.body.content`, "marker" | "대상 리소스" = `DELETE` 경로와 `authorId` 쿼리 | 없음 |
| 재현 절차 문장 | 세션 준비 → 입력 지점 관찰 → 페이로드 게시 → 다른 사용자 화면에서 실행 확인 | 소유자 리소스 준비 → 공격자 세션으로 삭제 요청 → 소유자 화면에서 부재 확인 | 이벤트 stage 이름을 그대로 나열 |
| checks 레이블 | `bindingCalled`→"브라우저 콜백 실행" 등 10개 | `differentUsers`→"서로 다른 사용자" 등 4개 | 키 이름을 그대로 |
| 영향 설명 | 저장형 XSS 영향 문단(고정 문구) | 권한 우회 영향 문단 | 생략 |

### 2.2 입력 — casper-db
build가 Python이므로 **`casper_db.CaseStore`를 직접 import해서 읽는다.**
- 사용 메서드: `get_version(case_id, revision)`(대조 당시 스냅숏), `get(case_id)`(현재 revision), `list_checks(case_id)`
- `initialize_database()`는 호출하지 않는다. DB가 없거나 스키마 버전이 다르면 "과거 사례 DB 사용 불가"로 표시하고 계속 진행한다.
- DB 경로는 필수 입력이다(기본값 없음).
- 매칭은 위치(endpoint, method, parameter) 기반이고 `vulnerability_type`은 자유 텍스트라서 **취약점 종류에 무관하게 쓸 수 있다.**

### 2.3 입력 — 증거 사진
capture가 남긴 `captures.json` 매니페스트와 PNG를 읽는다(§2.6). sha256을 다시 계산해 매니페스트와 다르면 그 사진은 넣지 않고 "무결성 불일치" 자리표시를 넣는다. 사진의 의미(캡션, 배치할 섹션)는 매니페스트의 `shotId`로 프로필이 정한다.

### 2.4 출력
| 출력 | 용도 | 비고 |
|---|---|---|
| **`report.hwpx`** | 최종 보고서(한글) | python-hwpx 템플릿(§3.4) |
| `report-model.json` | 렌더러 입력, 테스트 기준, 다른 모듈 연동 | `schemaVersion:'report-1.0'`. 사진은 메타데이터만 넣는다 |
| `report.md` (선택) | 한글 프로그램 없이 확인하는 미리보기, diff | 사진은 상대 링크 |

**형식별 이스케이프 규칙**(ReportModel에는 원문을 저장하고, 렌더러 출력 경계에서만 처리한다)
- **HWPX:** 텍스트 증거는 **텍스트 노드로만** 넣는다. lxml이 XML 이스케이프를 해 준다. HTML 이스케이프를 따로 하면 문서에 `&lt;`가 그대로 보이므로 하지 않는다. 원시 XML 조각을 끼워 넣는 API는 쓰지 않고, 테스트로 금지한다.
- **Markdown:** 많은 뷰어가 원시 HTML을 렌더링하므로 HTML 이스케이프를 한다. 표 안의 `|`와 개행도 처리한다.
- **JSON:** 원문을 그대로 넣는다. 소비자가 출력할 때 이스케이프할 책임이 있다는 점을 계약에 명시한다.

### 2.5 범용 보고서 목차 (HWPX 템플릿 = 코어 소유)
```
[표지] CA3P 취약점 점검 보고서 — <runId>, 생성일, 고지 상자(격리 실습 / synthetic / 저장소 미검증 / 위치 일치≠판정)

1. 점검 개요          2열 표: 실행 ID, 상태, 시험 프로필, 대상(loopback origin), 시작/종료 시각, 요청 수, 출처
2. 취약점 요약        표: 번호 | 제목 | CWE | 심각도 | 판정 상태
3. 취약점 상세        findings[] 각각 반복:
   3.n.1 상세         표준 2열 표(previous-month-xss-report.md 레이아웃):
                      보고일 | 취약점 유형(title, CWE) | 발생 위치(origin + method path, 파라미터) | 심각도(+근거) |
                      판정 상태(에이전트의 결정론적 판정, 저장소 미검증) | 상세 설명 | 조치 방안 | 한계
   3.n.2 재현 절차     번호 목록(steps[]). 단계에 사진이 연결되어 있으면 그 자리에 사진 + 캡션
   3.n.3 텍스트 증거   textEvidence[] 반복(코드 블록): PoC 요청, 응답, + 프로필 추가 항목(예: 점검 페이로드)
   3.n.4 판정 검사표   checks: 레이블 | 결과(참/거짓)
   3.n.5 영향         프로필이 주면 넣고, 없으면 생략
   3.n.6 기타 정보     profileData 키-값 표
4. 과거 사례 대조(재점검 triage)   고정 문구 + 표
5. 관련 전월 보고서    사례별 2열 표(대조 당시 revision)
6. 재점검 이력        check 표 + 해시 표 + 각주
7. 가드레일 결정과 안전 속성
8. 출처와 한계        사용한 프로필과 어댑터 이름·버전, generic fallback 여부 포함
```
- 실패한 run이면 3절을 "실행 실패"(error code, source, message, 도달한 단계)로 바꾸고, 사진은 찍힌 것만 넣는다.
- **템플릿은 하나뿐이다.** 프로필은 템플릿을 바꾸지 않고 모델의 데이터(제목 문구, 단계, 텍스트 증거, 레이블)만 채운다.

### 2.6 증거 사진 촬영 (capture 단계, 범용 엔진)

**촬영 계획 = 프로필의 장면 선언 × 대상 어댑터의 선택자.** 엔진은 계획을 실행하기만 하고, 취약점이나 사이트를 모른다.

```jsonc
// 프로필 stored_xss: 어떤 장면이 필요한가 (논리 이름만 사용)
{ "profile": "stored_xss", "version": "1",
  "shots": [
    { "shotId": "input-point", "caption": "입력 지점", "path": "/", "viewer": "attacker",
      "target": "compose_form", "variants": ["element", "full-page"] },
    { "shotId": "result-view", "caption": "피해자 관점 결과 화면", "path": "/", "viewer": "victim",
      "target": "resource_card", "resource": "finding.resourceId", "variants": ["element", "full-page"],
      "observe": { "binding": "__ca3pXssProbe", "expect": "finding.marker" } } ] }   // 기록만 하고 판정에 쓰지 않음

// 프로필 bola: 같은 엔진, 다른 계획
{ "profile": "bola", "version": "1",
  "shots": [ { "shotId": "result-view", "caption": "소유자 관점: 리소스 부재", "path": "/", "viewer": "owner",
               "target": "resource_list", "variants": ["element", "full-page"] } ] }

// 대상 어댑터 vul-web-1: 논리 이름 → 실제 선택자, 계정 전환 방법
{ "application": "vul-web-1", "version": "1",
  "targets": {
    "compose_form":  { "selector": "#post-form" },
    "resource_list": { "selector": "#post-list", "ready": "#post-list[aria-busy=\"false\"]" },
    "resource_card": { "list": "#post-list .post-card", "match": ".post-number", "text": "NO. {id}",
                       "ready": "#post-list[aria-busy=\"false\"]" } },
  "viewers": { "attacker": "alice", "victim": "bob", "owner": "bob" },
  "sessionSwitch": { "method": "POST", "path": "/api/session", "body": { "userId": "{viewer}" } },
  "defaultViewer": "alice" }
```
- 어댑터는 `report.target.application`으로 고른다. 지금 값(`owned-local-board`, `external_target`)으로는 사이트를 알 수 없으므로 매핑 규칙이 필요하다(§7 Q11). 어댑터가 없으면 **촬영하지 않고** 매니페스트에 `skipped: no-target-adapter`를 남긴다.
- 프로필이 없으면(generic) 촬영하지 않는다.
- 계획과 어댑터는 코드가 아닌 **JSON 데이터 + JSON Schema 검증**으로 둔다. 로딩은 정적 레지스트리만 쓰고 동적 import는 하지 않는다.
- 메타데이터: `shotId, variant, runId, profile, adapter, capturedAt, pageUrl, viewport, selector, viewerUserId, sessionSwitched, observations, sha256, sizeBytes, mime`

**샌드박스**(verify 단계 `observeStoredXssExecution`과 같은 수준). 촬영 페이지에서 저장된 payload가 실행될 수 있기 때문이다.
- origin은 run 보고서의 `target.origin`이고 `http://127.0.0.1:<port>` 형식일 때만 접속한다.
- 같은 origin의 GET/HEAD만 허용하고, 나머지는 `route.abort`로 막는다. **예외는 어댑터의 `sessionSwitch` 한 건**뿐이며, 정확한 method·path·body로만 허용하고 기록한다(§7 Q4).
- WebSocket 차단, service worker 차단, 다운로드 거부, 팝업 즉시 닫기, 대화상자 자동 닫기를 적용한다.
- 시간 상한은 장면당 15초·전체 60초, 출력 크기 상한은 장당 5MB다.

**vul-web-1 사실 확인(§0.5):** 쿠키가 없으면 alice로 로그인되고, 공격자도 alice다. 그래서 `viewer:"victim"`(bob) 장면에는 계정 전환 1회가 필요하다. 전환이 허용되지 않으면 그 장면은 `defaultViewer`로 찍고, 캡션에 "기본 계정(alice) 화면"이라고 명시한다.

**저장과 영속성(⚠️ 차단 요소, §7 Q2)**
- 저장 위치: `<outputRoot>/<sha256(runId)>/captures/<shotId>-<variant>.png`와 `captures.json`
- 파일 쓰기 방식은 pentest-db 규약과 같다: 0600 권한, 임시 파일 → fsync → hard-link, 덮어쓰지 않음.
- Docker가 내려간 뒤 build가 읽으려면 `outputRoot`가 영속 볼륨에 있어야 한다. 지금 볼륨은 `casper-db/data`, `reports/pentest-db-runs`, `.runtime` 세 개뿐이므로 **새 볼륨(예: `report-output:/app/reports/report-module`)이 필요하다.** 통합 담당자 소관이다.

---

## 3. 모듈 구조, 언어, 확장 방식

### 3.1 3계층 구조
```
┌──────────────── 공통 코어 (취약점 종류를 모름) ─────────────────┐
│ 로더 · 범용 ReportModel · HWPX/MD 렌더러 · 마스킹/이스케이프       │
│ 프레이밍 불변식 · casper 대조 · 가드레일 · 무결성 검증              │
│ capture 엔진: 촬영 계획(JSON)을 샌드박스에서 실행만 함              │
└───────────────▲─────────────────────────────────▲─────────────┘
                │ report.testProfile로 선택         │ report.target.application으로 선택
┌───────────────┴───────────────┐   ┌─────────────┴─────────────────┐
│ 취약점 프로필                   │   │ 대상 어댑터                     │
│ stored_xss / bola / generic     │   │ vul-web-1 / (추후 다른 실습 사이트) │
│ - finding → profileData 분리    │   │ - 논리 대상 이름 → CSS 선택자     │
│ - 재현 단계·텍스트 증거 추출      │   │ - viewer 역할 → 계정            │
│ - checks 레이블, 영향 문구        │   │ - 허용된 계정 전환 방법           │
│ - 촬영 계획(장면 선언)            │   │                                │
└───────────────────────────────┘   └────────────────────────────────┘
```
- 취약점과 사이트를 **독립 축**으로 나눈다. 같은 stored_xss 프로필을 다른 게시판에 쓸 때는 어댑터만 추가하면 되고, 같은 vul-web-1에 새 취약점을 추가할 때는 프로필만 추가하면 된다.

### 3.2 프로필 인터페이스 (Python, build 측)
```python
class VulnProfile(Protocol):
    id: str                          # 'stored_xss'
    upstream_profiles: tuple[str]    # ('stored_xss_canary',)
    version: str

    def split_finding(self, finding: dict) -> tuple[CommonFinding, dict]          # 공통 필드 / profileData
    def reproduction(self, run: RunData) -> list[Step]                            # 단계 문장 + 연결된 shotId
    def text_evidence(self, run: RunData) -> list[TextEvidence]                   # PoC 요청·응답 외 추가 항목
    def check_labels(self) -> dict[str, str]                                      # checks 키 → 한글 레이블
    def impact(self) -> str | None
    def shot_captions(self) -> dict[str, str]                                     # shotId → 캡션
```
- capture 측 프로필은 Python 코드가 아니라 **장면 선언 JSON**이다(§2.6). `profiles/<id>/shots.json`을 Node와 Python이 함께 읽으므로 캡션과 shotId가 어긋나지 않는다.
- 레지스트리: `PROFILES = {'stored_xss_canary': StoredXss, 'agent_cross_user_delete_canary': Bola}`. 없으면 `Generic`을 쓴다.
- 프로필은 **순수 함수**만 가진다. I/O, 네트워크, 판정 로직은 넣지 않는다. 코어가 프로필 출력을 스키마로 검증한 뒤 모델에 넣는다.
- **프레이밍 불변식과 마스킹은 프로필 출력 뒤에 코어가 적용한다.** 프로필이 우회할 수 없다.

### 3.3 언어
| 단계 | 언어 | 근거 |
|---|---|---|
| **capture** | Node ESM(`.mjs`) + Playwright | 대상이 살아 있는 동안 파이프라인 안에서 실행된다. Playwright와 Chromium이 이미 Docker 이미지와 xss-parser에 있다. 샌드박스 패턴(`observeStoredXssExecution`)을 그대로 따를 수 있다 |
| **build** | **Python ≥3.11** | python-hwpx가 Python 전용이다. casper-db를 `CaseStore`로 직접 읽는다. Docker 이미지에 Python venv(`/opt/ca3p-venv`)가 이미 있다 |

- 이전 안("Node 단일 모듈 + Python 브리지")은 폐기했다.
- 의존성
  - capture: `playwright`. 기존 버전(1.58.2)과 맞춘다.
  - build: `python-hwpx`(Apache-2.0, `lxml` 의존), `pydantic`(casper-db와 공유)

### 3.4 python-hwpx 사용 방침
- **Alpha 단계라 API가 바뀔 수 있다.** 정확한 버전이나 커밋 SHA로 고정하고, 모든 호출을 `hwpx_writer.py` 한 파일로 감싼다.
- **템플릿 방식:** 범용 목차(§2.5) 하나를 `templates/ca3p-report.hwpx`로 만들어 두고 `HwpxDocument.open()` → `tables.fill_by_path()` / `add_heading()` / `add_paragraph()` / `add_picture()`로 채운다.
- **취약점 상세(3.n)가 finding 수만큼 반복되므로, 섹션 반복 생성이 가능한지가 핵심 확인 사항이다.**
- **스파이크로 먼저 확인할 것(M1):**
  1. 행 수가 바뀌는 표(triage, 재점검 이력, checks)를 만들 수 있는가
  2. 섹션 블록(제목 + 2열 표 + 코드 블록 + 사진)을 N회 반복해 넣을 수 있는가
  3. 이미지 크기와 캡션을 지정할 수 있는가
  4. 코드 블록(고정폭 글꼴, 줄바꿈 유지)을 표현할 수 있는가
  5. 한글이나 한컴 뷰어에서 깨지지 않고 열리는가(라이브러리 검증 + 육안 확인)
  6. `<script>`, `&`, `]]>` 같은 문자열이 텍스트로 정확히 보이는가
- 스파이크에서 막히면 대안은 **HWPX의 XML(OWPML)을 lxml로 직접 다루는 것**이다. 이 경우 범위가 커지므로 다시 상의한다.

### 3.5 디렉터리 구성(안)
```
packages/report/
  PLAN.md  README.md
  profiles/                         # Node·Python 공용 데이터
    schema/shots.schema.json  schema/adapter.schema.json
    stored_xss/shots.json  bola/shots.json
  adapters/
    vul-web-1.json
  capture/                          # Node
    package.json  engine.mjs  sandbox.mjs  plan.mjs  cli.mjs  tests/
  build/                            # Python
    pyproject.toml
    src/ca3p_report/
      core/       loaders.py  model.py  redact.py  escape.py  framing.py  integrity.py
      profiles/   base.py  registry.py  generic.py  stored_xss.py  bola.py
      render/     hwpx_writer.py  markdown_writer.py
      cli.py
    templates/ca3p-report.hwpx
    tests/
```

### 3.6 새 취약점·새 사이트를 추가하는 절차
1. **새 취약점:** `profiles/<id>/shots.json` 추가, `build/.../profiles/<id>.py` 구현, 레지스트리에 한 줄 등록, 골든 fixture 하나 추가. 코어, 템플릿, 엔진은 바꾸지 않는다.
2. **새 실습 사이트:** `adapters/<application>.json` 추가. 계정 전환이 필요하면 `sessionSwitch`를 명시하고, 이 허용 범위는 보안 리뷰를 거친다.
3. 상류(agent core)가 새 `testProfile`을 내보내기 전에는 generic fallback으로 보고서가 만들어진다. 생성이 실패하지 않는다.

### 3.7 "Agent"의 범위
사실 항목(판정, 상태, 심각도, 요청과 응답, 고지 문구)은 **결정론적 코드가 채운다.** LLM은 "점검 개요" 서술 문단 하나만 맡기는 선택 기능으로 둔다. 입력은 마스킹된 ReportModel로 한정하고, 출력에 판정 관련 단어가 없는지 검사한다. 기본값은 끈다(§7 Q6).

---

## 4. 인터페이스와 계약
특정 호출자(테스트용 app 또는 실제 파이프라인)에 묶이지 않도록, **CLI와 JSON 입출력**을 기본 계약으로 둔다. agent의 JSON envelope 형식(`receiver:'report'`)으로 감싸는 일은 실제 파이프라인 담당자와 정한다(§7 Q1).

### 4.1 capture
```
node packages/report/capture/cli.mjs --run-report <abs path to report.json> --output-root <abs> \
     [--profile <id>] [--adapter <application>] [--no-session-switch]
```
- **입력은 run 보고서 하나뿐이다.** origin(`target.origin`), 프로필(`testProfile`), 어댑터(`target.application`), 리소스 ID(`finding.resourceId`), 관찰 기대값(`finding.marker` 등)은 모두 보고서에서 읽는다.
  - 호출자는 취약점 종류를 몰라도 된다.
  - `--profile`/`--adapter`는 테스트와 매핑 보정용이다.
- 프로필의 `resource` 참조 값이 없는 경우(실패 run 등) 해당 장면은 건너뛰고 기록한다.
- 출력: 표준출력으로 JSON 한 개
  ```json
  { "schemaVersion": "report-capture-1.0", "runId": "...", "profile": "stored_xss@1", "adapter": "vul-web-1@1",
    "status": "captured|partial|skipped|failed",
    "captures": [{ "shotId": "result-view", "variant": "element", "ref": "<runHash>/captures/result-view-element.png",
                   "sha256": "...", "sizeBytes": 0, "mime": "image/png", "capturedAt": "...", "pageUrl": "...",
                   "viewport": {}, "selector": "...", "viewerUserId": "bob", "sessionSwitched": true,
                   "observations": { "binding:__ca3pXssProbe": true } }],
    "skipped": [{ "shotId": "...", "reason": "no-resource-id|no-target-adapter|generic-profile" }],
    "errors": [] }
  ```
- 종료 코드: `0` 전부 성공 또는 정상 skip, `5` 일부 성공, `6` 대상에 접속할 수 없음.
- **파이프라인을 멈추지 않는다.** 실패는 매니페스트에만 기록한다.
- 호출 시점: run finalize **뒤**, 실습 환경을 정리(`labSession.close()`나 컨테이너 종료)하기 **전**.

### 4.2 build
```
python -m ca3p_report build --run-id <id> --reports-dir <abs> --casper-db <abs> \
       --captures-root <abs> --out-dir <abs> [--format hwpx,json,md] [--generated-at <iso>] \
       [--no-images] [--profile <id>]
```
- 출력: `<out-dir>/<sha256(runId)>/report.hwpx`, `report-model.json`, 그리고 선택 시 `report.md`와 `assets/`
- 기존 파일은 덮어쓰지 않는다(`wx`). 종료 코드: `0` 성공, `2` 입력 오류, `3` run 없음, `4` 보고서 미완료.
- 프로그램 API(순수 함수와 I/O 분리)
  ```python
  load_run(run_id, reports_dir) -> RunData | None
  load_casper(db_path, refs) -> CasperContext            # unavailable 허용
  load_captures(captures_root, run_id) -> CaptureSet      # 해시 재검증
  resolve_profile(run) -> VulnProfile                     # 레지스트리, 없으면 Generic
  build_model(run, casper, captures, profile, generated_at) -> ReportModel   # 순수 함수
  write_hwpx(model, template, out) / write_markdown(model, out)
  ```

### 4.3 경계(읽기 전용)
| 대상 | 접근 | 금지 |
|---|---|---|
| 대상 사이트 | capture만 접속. 기록된 loopback origin에 GET/HEAD, 그리고 어댑터 `sessionSwitch` 1건 | 데이터 생성·수정·삭제. 외부 origin |
| pentest-db 디스크 | 파일 읽기만. runId 검증 후 `sha256(runId)` 디렉터리 | 쓰기 |
| casper-db | `CaseStore` 읽기 메서드만(`mode=ro`) | `initialize_database`, `add*`, `update`, `review_check` |
| run-store | (필요 시) `sqlite3` `?mode=ro` URI | DDL, 쓰기 |
| 네트워크 | capture의 loopback 접속 외에는 없음 | build의 모든 네트워크 |

### 4.4 ReportModel `report-1.0` (범용 스키마)
```jsonc
{
  "schemaVersion": "report-1.0",
  "generator": { "module": "report", "version": "0.1.0", "profile": "stored_xss@1", "adapter": "vul-web-1@1",
                 "fallback": false },
  "generatedAt": "<ISO>",
  "notices": ["synthetic", "isolated-local-lab", "storage-unverified", "location-match-is-not-verdict"],
  "run": { "runId", "status", "testProfile", "target", "startedAt", "completedAt", "storedAt", "provenance",
           "progress", "metrics", "error?" },
  "findings": [{                          // 지금은 run당 0~1개, 스키마는 N개
    "common": { "findingId", "title", "cwe", "severity", "severityBasis", "confidence", "status",
                "summary", "limitations", "remediation", "evidenceRefs", "location": { "method", "path", "parameter?" } },
    "checks": [{ "key", "label", "value" }],
    "reproduction": [{ "order", "text", "shotIds": [] }],
    "textEvidence": [{ "label", "language": "http|json|text", "content" }],   // PoC 요청, 응답, 프로필 추가 항목
    "images": [{ "shotId", "variant", "caption", "ref", "sha256", "integrity": "ok|mismatch|missing", "viewerUserId" }],
    "impact": "string|null",
    "profileData": { }                    // 프로필 고유 값. 렌더러는 키-값 표로만 출력
  }],
  "triage": { "available", "readyCaseCount", "evidenceId", "rows": [...] },
  "priorCases": { "status": "ok|unavailable|not-requested", "cases": [...] },
  "guardrail": { "decisions": [...] }, "safety": { },
  "references": { "catalog": { "status": "draft_advisory", "currentRunVerified": false } }
}
```
- 문자열은 원문(이스케이프 전)으로 저장한다.
- 마스킹은 모델을 만드는 마지막 단계에서 **코어가** 적용한다. 대상: authorization, cookie, set-cookie, api key, Bearer, `sk-…` 형태 문자열, `reasoning_content`/`prompt`/`rawResponse` 키.
- Python 마스킹 규칙은 `packages/contracts/index.mjs`의 `redact()`와 **같은 테스트 벡터**로 검증한다.
- 렌더러는 `findings[].common`, `checks`, `reproduction`, `textEvidence`, `images`, `profileData`만 안다. 취약점 이름으로 분기하지 않는다(정적 검사로 강제, §6).

---

## 5. 마일스톤
| 단계 | 작업 | 산출물 | 완료 기준 |
|---|---|---|---|
| **M0. 결정 정리** | ✅ 브랜치, 작업 범위, 2단계 구조, 사진 2장, HWPX, **범용 3계층 설계** | 이 문서 | 완료 |
| **M1. python-hwpx 스파이크** | §3.4의 1~6번 확인. 특히 섹션 반복 | `spike/` 결과와 짧은 보고 | 한글/뷰어에서 정상으로 열림. 막히면 대안 결정 |
| **M2. 스캐폴딩** | §3.5 구조. 공용 JSON Schema(`shots`, `adapter`). 빈 CLI. 경계 테스트(build에 네트워크 없음, capture는 loopback만) | 실행 가능한 `--help`, 스키마 | `node --test`와 `pytest` 통과 |
| **M3. capture 엔진** | 범용 엔진(계획 해석 → 샌드박스 → 촬영 → 매니페스트 → 원자적 저장) + `stored_xss/shots.json` + `adapters/vul-web-1.json` | `engine.mjs`, 계획 2종 | vul-web-1에서 stored_xss 장면 4장 생성. 쓰기 요청 차단, 허용 목록 밖의 `sessionSwitch` 차단, 어댑터 없을 때 skip |
| **M4. build 코어 + generic 프로필** | 로더, 범용 모델, 마스킹, 프레이밍, 무결성, 프로필 레지스트리, `Generic` | generic 골든 `report-model.json` | 미등록 프로필 run으로도 보고서 생성. 정상, 실패, 미완료, DB 없음, 해시 불일치 케이스 |
| **M5. stored_xss 프로필** | `stored_xss.py`(재현 단계, 텍스트 증거, checks 레이블, 영향, 캡션) | stored_xss 골든 | 코어와 렌더러 무수정으로 추가됨 |
| **M6. HWPX 렌더러** | 템플릿 채우기, 섹션 반복, 사진, 코드 블록, 표 (+ MD 미리보기) | `report.hwpx`, `report.md` | XML 구조 골든, 이스케이프 테스트, 육안 확인 |
| **M7. bola 프로필 (인터페이스 검증)** | `bola.py` + `bola/shots.json` | bola 골든과 사진 | **코어·렌더러·엔진 변경 없이** 추가됨. 변경이 필요했다면 인터페이스를 고치고 기록 |
| **M8. 연동 요청과 문서** | 호출 지점, 볼륨, 계정 전환 허용, `target.application` 매핑을 담당자에게 요청할 문안. README에 프로필·어댑터 추가 가이드(§3.6) | 요청 문안, README | 담당자 회신 |
| **M9. 검증** | 독립 리뷰(code-reviewer, security-reviewer) | 리뷰 결과 | 지적 해소 |

---

## 6. 테스트 전략
- **러너:** capture는 `node --test packages/report/capture/tests/`, build는 `pytest packages/report/build/tests`.
  manifest에 등록되기 전까지는 CI가 이 모듈을 실행하지 않으므로 커밋 전에 직접 돌린다.
- **fixture(모두 synthetic)**
  - 사이트: vul-web-1을 `PORT=0`, 임시 데이터 파일로 직접 띄운다. canary 게시글(XSS), bob 소유 게시글(BOLA)은 **테스트 준비 단계에서만** 만든다. capture 코드 자체는 쓰지 않는다.
  - run 데이터: pentest-db 규약대로 `report.json`과 이벤트 파일을 만든다. 종류는 stored_xss(confirmed / not_confirmed), bola, **미등록 프로필(`future_profile_x`)**, failed.
  - casper-db: 임시 DB에 synthetic 사례와 check를 넣는다(테스트 준비 단계에서만).

| 범주 | 검증 |
|---|---|
| **범용성** | 미등록 프로필 run → generic 보고서 생성, "프로필 미등록" 고지, 사진 없음, 실패 없음. 렌더러와 코어 소스에 프로필 이름(`stored_xss`, `bola`, `xss`) 문자열 분기가 없다(정적 검사). 프로필 추가 시 코어 파일 diff가 없다(M5, M7 완료 조건) |
| 프로필 계약 | 각 프로필 출력이 스키마를 통과한다. 프로필이 notices를 지우거나 판정 상태를 바꾸려 해도 코어가 덮어쓴다 |
| 촬영 계획 | `shots.json`과 어댑터가 JSON Schema를 통과한다. 모르는 target 이름이나 viewer가 있으면 촬영 전에 거부한다 |
| capture 샌드박스 | 외부 origin, POST/DELETE, WebSocket이 차단되고 기록된다. `sessionSwitch`는 정확히 일치할 때만 허용되고 body가 다르면 차단된다. 잘못된 origin 입력(`http://example.com`, `https://127.0.0.1`, 경로 포함)은 거부된다 |
| capture 결과 | 장면별 요소 캡처에 대상 선택자가 들어 있다. 매니페스트 sha256이 파일과 일치한다. 대상에 접속할 수 없으면 종료 코드 6이고 예외가 없다 |
| 이스케이프 | payload `<img src=x onerror=…>`, `<script>`, `&`, `]]>`, `|`가 HWPX XML에서 텍스트 노드로 있다. MD에서는 엔티티 형태다. 이중 이스케이프가 없다 |
| 마스킹 | fixture에 심은 `Cookie`, `Set-Cookie`, `Authorization`, `sk-…`, `reasoning_content`가 JSON, MD, HWPX 어디에도 없다. contracts `redact()`와 같은 벡터로 결과가 일치한다 |
| 프레이밍 | 고지 상자, triage 고정 문구, 사진 캡션의 "판정 근거 아님" 문구, `[가상]`, `verifiedByStorage:false`가 **모든 프로필의** 출력에 있다 |
| 무결성 | 사진 파일을 1바이트 바꾸면 그 사진이 빠지고 "무결성 불일치"가 표시된다 |
| 읽기 전용 | build 전후로 casper DB와 reports 디렉터리의 해시가 같다. DB가 없으면 새로 만들지 않는다 |
| 결정성 | 같은 입력과 `--generated-at`이면 `report-model.json`이 바이트 단위로 같다. HWPX는 XML 내용 기준으로 비교한다 |

---

## 7. 미해결 질문과 요청 항목
| # | 질문/요청 | 대상 | 제안 |
|---|---|---|---|
| Q1 | **실제 agent 파이프라인 코드의 위치**(원격 저장소에 없음). report 단계를 어디서, 어떤 형식(CLI, envelope)으로 호출할지 | 파이프라인 담당 | §4 CLI 계약. capture 입력은 `report.json` 경로 하나 |
| Q2 | **capture 출력의 영속 볼륨**(예: `report-output:/app/reports/report-module`) 추가 | 통합 담당(docker-compose) | 새 볼륨. 다른 모듈의 볼륨을 공유하지 않는다 |
| Q3 | 실제 파이프라인이 run 결과를 pentest-db JSON에 저장하는가, run-store에 저장하는가 | 파이프라인 담당 | 로더를 원천별로 분리해 둘 다 지원 |
| Q4 | 어댑터 `sessionSwitch`(vul-web-1: `POST /api/session {userId:'bob'}`) 1건 허용 여부 | 사용자/보안/guardrail 담당 | 허용(데이터 변경 없음, 정확 일치만, 기록). 불허 시 기본 계정 화면 + 캡션 명시 |
| Q5 | 촬영 호출 시점 보장: finalize 뒤, 환경 정리 전 | 파이프라인 담당 | 실패해도 run을 막지 않는 best-effort 호출 |
| Q6 | "점검 개요" 서술에 LLM을 쓸지 | 사용자 | 기본은 끄고, 선택 기능으로 둔다 |
| Q7 | HWPX 템플릿(표지, 기관 양식)을 누가 만드는가. 기존 CERT 양식이 있는가 | 사용자/팀 | 있으면 그 양식을 범용 목차(§2.5)에 맞춰 쓰고, 없으면 직접 만든다 |
| Q8 | 보고서 단위: run 1건당 1부인가, 여러 run을 묶은 월간 집계도 필요한가 | 사용자 | MVP는 run 단위. 모델의 `findings[]`가 배열이라 집계로 확장할 수 있다 |
| Q9 | 보고서 출력의 보존 정책, gitignore | 팀 | 출력 루트는 gitignore 대상 |
| Q10 | 상류가 추가할 취약점 프로필 로드맵(예: 반사형 XSS, SQLi …) | agent/파이프라인 담당 | 로드맵을 알면 프로필 인터페이스를 미리 점검할 수 있다 |
| Q11 | `report.target.application` 값 규약. core 기본값은 `'external_target'`(`orchestrator.js:148`)이고, 테스트 app은 `'owned-local-board'`를 넣는다(`apps/application/local-runtime.mjs:241`). 둘 다 사이트를 식별하지 못해 어댑터를 고를 수 없다 | 파이프라인 담당 | 실제 사이트 식별자(예: `vul-web-1`)를 넣어 달라고 요청한다. 그 전까지는 별칭 매핑(`owned-local-board`→`vul-web-1`)과 `--adapter`로 대응 |
| Q12 | 심각도 체계: 지금처럼 low~critical만 쓸지, CVSS 벡터 필드를 추가할지 | 사용자 | 모델에 선택 필드 `cvss`만 마련해 둔다 |
