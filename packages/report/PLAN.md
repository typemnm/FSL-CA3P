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
Report Agent는 **한 번의 실행(runId)마다 한글(HWPX) 취약점 보고서 한 부**를 만든다. 보고서에는 다음이 들어간다.
1. 이번 실행 결과: 판정(finding), 재현 절차, PoC 요청과 응답(텍스트), 점검 페이로드(텍스트)
2. 증거 사진 2장: ① 입력 지점 ② 피해자 관점 결과 화면
3. 과거 사례 대조(재점검 triage)와 관련 전월 보고서, 재점검 이력(casper-db)

### 1.2 두 단계 구조
```
 실제 agent 파이프라인
 ─ observe → knowledge → think → act → verify → reflect → finalize ─┐
                                                                     │ (환경 종료 전)
                                     ┌───────────────────────────────▼──────────────┐
                                     │ ① report.capture  (Node + Playwright)        │
                                     │   target origin 접속 → 사진 2장 → PNG + 해시  │
                                     │   → 영속 볼륨에 저장                          │
                                     └───────────────────────────────┬──────────────┘
                                                      실습 환경 / Docker 종료
                                     ┌───────────────────────────────▼──────────────┐
                                     │ ② report.build    (Python + python-hwpx)     │
                                     │   run 보고서·이벤트 + casper-db + 사진 2장     │
                                     │   → ReportModel(JSON) → report.hwpx           │
                                     └──────────────────────────────────────────────┘
```

### 1.3 하는 일
- **capture:** 대상 origin을 읽기 전용 샌드박스 브라우저로 열어 두 화면을 찍고, 해시와 메타데이터를 함께 저장한다.
- **build:** 저장소를 읽기 전용으로 읽어 ReportModel을 만들고, 이를 HWPX로 렌더링한다. Markdown 미리보기는 선택 출력이다.
- 모든 출력에 고지 문구, 출처, 한계를 넣는다. 비밀값은 마스킹한다.

### 1.4 하지 않는 일
- **판정하지 않는다.** `finding.status`를 그대로 옮긴다. 사진 촬영 중 canary가 실행되었는지는 기록할 수 있지만 판정에 쓰지 않는다.
- **공격하지 않는다.** capture는 대상 게시판에 데이터를 만들거나 바꾸는 요청을 보내지 않는다(§2.6 샌드박스).
- **저장소에 쓰지 않는다.** casper-db, pentest-db, run-store는 모두 읽기만 한다. 쓰는 곳은 이 모듈의 출력 디렉터리뿐이다.
- 기록된 loopback origin이 아닌 곳(외부 호스트, 임의 URL)에는 접속하지 않는다.
- 다른 담당자 모듈을 수정하지 않는다. 필요한 변경은 §7에 요청 항목으로 적는다.

### 1.5 반드시 지킬 프레이밍 (불변식)
| 규칙 | 구현 방법 |
|---|---|
| 위치 일치는 재점검 후보일 뿐 현재 취약 판정이 아니다 | triage 섹션 머리에 고정 문구를 넣는다. 레이블은 `demo.py`와 같게 "재점검 후보 / 수동 확인 / 일치 없음"을 쓴다 |
| `ready`/`reviewed`는 상태 표시일 뿐 취약 판정이 아니다 | 상태 열 머리말에 "(상태 표시)"를 붙이고 각주를 단다 |
| 현재 데이터는 전부 synthetic이다 | 문서 첫 페이지에 고지 상자를 넣고, synthetic 행에는 `[가상]`을 붙인다 |
| 해시는 바이트만 증명할 뿐 XSS를 증명하지 않는다 | 해시 표 각주 |
| **사진은 보조 자료이며 실행 판정 근거가 아니다** | 두 사진 캡션 아래에 고정 문구: "실행 판정 근거는 결정론적 검사(`finding.checks`)" |
| 저장소는 내용을 검증하지 않는다 | `verifiedByStorage:false`를 그대로 표시한다 |
| 카탈로그는 draft 참고 자료다 | `draft_advisory` 표시 |

---

## 2. 입력과 출력

### 2.1 입력 — 실행 보고서와 이벤트
- 1차 원천은 pentest-db 디스크 규약(§0.1)이다: `reports/pentest-db-runs/<sha256(runId)>/report.json`, `events/*.json`.
  실제 파이프라인이 run-store(SQLite)를 쓴다면 읽기 전용 로더를 추가한다(§7 Q3).
- 보고서에 쓰는 필드

| 보고서 항목 | 원천 |
|---|---|
| 실행 메타 | `report.{runId, status, testProfile, target, startedAt, completedAt, metrics, progress}`, `storedAt`, `provenance` |
| 판정 | `report.finding` (status, confidence, severity, cwe, checks, summary, limitations, remediation, evidenceRefs) |
| **PoC 요청(텍스트)** | `stage==='loop.act'` 이벤트의 `event.request.payload.curl` (method, url, body). 쿠키는 agent가 다루지 않으므로(`agentHandlesCookies:false`) 포함되지 않지만, `redact()`를 한 번 더 적용한다 |
| **응답(텍스트)** | `loop.act` 이벤트의 `event.response.payload.response` (status, bodyJson). `setCookie`가 있으면 제거한다 |
| **점검 페이로드(텍스트)** | `loop.act` request body의 `content` (= canary 원문). 대조용으로 `finding.marker`도 넣는다 |
| 재현 절차 | 이벤트 stage 순서로 자동 생성한다: 세션 준비(`setup.attacker_session`) → 입력 지점 관찰(`loop.observe`) → PoC 전송(`loop.act`) → 새 브라우저로 재방문해 확인(`loop.verify`) |
| triage | `stage==='loop.history'` 이벤트의 `payload.{readyCaseCount, observations, assessments}` |
| 가드레일 | `report.guardrail.decisions` |

### 2.2 입력 — casper-db
build를 Python으로 만들기 때문에 **`casper_db.CaseStore`를 직접 import해서 읽는다**(서브프로세스 브리지가 필요 없음).
- 사용 메서드: `get_version(case_id, revision)`(대조 당시 스냅숏), `get(case_id)`(현재 revision), `list_checks(case_id)`
- `initialize_database()`는 호출하지 않는다. DB가 없거나 스키마 버전이 다르면 "과거 사례 DB 사용 불가"로 표시하고 계속 진행한다.
- DB 경로는 필수 입력이다(기본값 없음).

### 2.3 입력 — 증거 사진
capture 단계가 남긴 `captures.json` 매니페스트와 PNG 파일을 읽는다(§2.6). 각 파일의 sha256을 다시 계산해 매니페스트와 다르면 그 사진은 넣지 않고 "무결성 불일치" 자리표시를 넣는다.

### 2.4 출력
| 출력 | 용도 | 비고 |
|---|---|---|
| **`report.hwpx`** | 최종 보고서(한글) | python-hwpx로 만든다. 2열 표 레이아웃 템플릿을 사용한다(§3.2) |
| `report-model.json` | 렌더러 입력, 테스트 기준, 다른 모듈 연동 | `schemaVersion:'report-1.0'`. 사진은 메타데이터만 넣고 바이트는 넣지 않는다 |
| `report.md` (선택) | 한글 프로그램 없이 내용을 확인하는 미리보기, diff | 사진은 상대 링크 |

**형식별 이스케이프 규칙**(ReportModel에는 원문을 저장하고, 렌더러 출력 경계에서만 처리한다)
- **HWPX:** payload와 응답은 **텍스트 노드로만** 넣는다. lxml이 XML 이스케이프를 해 준다. HTML 이스케이프를 따로 하면 문서에 `&lt;`가 그대로 보이므로 하지 않는다. 원시 XML 조각을 끼워 넣는 API는 쓰지 않고, 테스트로 금지한다.
- **Markdown:** 많은 뷰어가 원시 HTML을 렌더링하므로 HTML 이스케이프를 한다. 표 안의 `|`와 개행도 처리한다.
- **JSON:** 원문을 그대로 넣는다. 소비자가 출력할 때 이스케이프할 책임이 있다는 점을 계약에 명시한다.

### 2.5 보고서 목차 (HWPX)
```
[표지] CA3P 취약점 점검 보고서 — <runId>, 생성일, 고지 상자(격리 실습 / synthetic / 저장소 미검증 / 위치 일치≠판정)

1. 점검 개요        2열 표: 실행 ID, 상태, 시험 프로필, 대상(loopback origin), 시작/종료 시각, 요청 수, 출처(source)
2. 취약점 상세      표준 2열 표(previous-month-xss-report.md 레이아웃):
                    보고일 | 취약점 유형(title, CWE) | 발생 위치(origin + POST /api/posts, content) |
                    심각도(+근거) | 판정 상태(status, confidence — 에이전트의 결정론적 판정, 저장소 미검증) |
                    상세 설명(summary) | 조치 방안(remediation) | 한계(limitations)
3. 재현 절차        번호 목록(§2.1 stage 순서)
   3.1 입력 지점     [사진 ①] + 캡션
   3.2 PoC 요청     코드 블록(텍스트): method, url, body
   3.3 점검 페이로드  코드 블록(텍스트): canary 원문, marker
   3.4 응답         코드 블록(텍스트): status, body
   3.5 결과 확인     [사진 ②] + 캡션 + 판정 검사표(checks, 항목별 참/거짓)
4. 과거 사례 대조(재점검 triage)   고정 문구 + 표
5. 관련 전월 보고서  사례별 2열 표(대조 당시 revision)
6. 재점검 이력      check 표 + 해시 표 + 각주
7. 가드레일 결정과 안전 속성
8. 출처와 한계
```
실패한 run이면 2절을 "실행 실패"(error code, source, message, 도달한 단계)로 바꾸고, 사진은 찍힌 것만 넣는다.

### 2.6 증거 사진 촬영 (capture 단계)

**무엇을 찍는가**(vul-web-1 마크업 기준. `vul-web-1/public/index.html`, `app.js`)
| 사진 | 화면 | 선택자 | 범위 |
|---|---|---|---|
| ① 입력 지점 | 게시판 첫 화면의 글쓰기 폼(제목, 내용 입력란) | `#post-form` (`#post-title`, `#post-content`) | 요소 캡처 + 전체 페이지 1장 |
| ② 피해자 결과 화면 | canary 게시글이 렌더링된 게시글 목록 | `#post-list .post-card` 중 `.post-number`가 `NO. <postId>`인 카드 | 요소 캡처 + 전체 페이지 1장 |

- 입력값은 run 보고서에 이미 있다: `target.origin`, `finding.resourceId`(postId), `finding.marker`.
- 메타데이터: `kind, runId, capturedAt, pageUrl, viewport, selector, viewerUserId, canaryCallbackObserved, sha256, sizeBytes, mime`

**샌드박스**(verify 단계 `observeStoredXssExecution`과 같은 수준). 이 화면은 저장된 payload가 실제로 실행되는 페이지이기 때문이다.
- origin은 run 보고서의 `target.origin`이고 `http://127.0.0.1:<port>` 형식일 때만 접속한다.
- 같은 origin의 GET/HEAD만 허용하고, 그 밖의 요청은 `route.abort`로 막는다. WebSocket 차단, service worker 차단, 다운로드 거부, 팝업 즉시 닫기, 대화상자 자동 닫기를 적용한다.
- canary 콜백 이름(`__ca3pXssProbe`)에 기록만 하는 바인딩을 걸어 `canaryCallbackObserved`로 남긴다. **판정에는 쓰지 않는다.**
- 시간 상한은 전체 30초, 출력 크기 상한은 장당 5MB로 둔다.

⚠️ **"피해자 관점"의 실제 의미 — 확인 필요(§7 Q4).**
- vul-web-1은 쿠키가 없는 새 브라우저를 **기본 계정 alice로 로그인시킨다**(`server.js:114-118`, `currentUser`).
- 그런데 공격자도 alice다(`orchestrator.js:266-267`). 그러니까 지금 verify 단계의 "새 브라우저"는 **공격자와 같은 계정**의 다른 브라우저일 뿐이다.
- 진짜 피해자(bob) 화면을 찍으려면 `POST /api/session {userId:'bob'}` 요청이 한 번 필요하다. 게시판 데이터는 바꾸지 않고 세션 쿠키만 바꾸는 요청이다.
- 제안: capture 샌드박스에서 **이 요청 하나만** 허용 목록에 넣고, 메타데이터에 `viewerUserId:'bob'`과 "세션 전환 요청 1회"를 기록한다.

**저장과 영속성(⚠️ 차단 요소, §7 Q2)**
- 저장 위치: `<outputRoot>/<sha256(runId)>/captures/{input-point,victim-view}[-full].png`와 `captures.json`
- 파일 쓰기 방식은 pentest-db 규약과 같다: 0600 권한, 임시 파일 → fsync → hard-link, 같은 이름이 있으면 덮어쓰지 않는다.
- **Docker가 내려간 뒤 build가 읽으려면 `outputRoot`가 영속 볼륨에 있어야 한다.** 지금 `docker-compose.yml`의 볼륨은 `casper-db/data`, `reports/pentest-db-runs`, `.runtime` 세 개뿐이다.
  다른 모듈의 디렉터리에 끼워 쓰지 않으려면 **새 볼륨(예: `report-output:/app/reports/report-module`)이 필요하다.** 이는 통합 담당자 소관이다.

---

## 3. 모듈 위치와 언어 결정

### 3.1 결정
| 단계 | 언어 | 근거 |
|---|---|---|
| **capture** | Node ESM(`.mjs`) + Playwright | 대상이 살아 있는 동안 파이프라인 안에서 실행된다. Playwright와 Chromium은 이미 Docker 이미지와 xss-parser에 있다. 샌드박스 패턴(`observeStoredXssExecution`)을 그대로 따를 수 있다 |
| **build** | **Python ≥3.11** | python-hwpx가 Python 전용이다. casper-db를 `CaseStore`로 직접 읽을 수 있다. pentest-db JSON과 SQLite도 표준 라이브러리로 읽는다. Docker 이미지에 Python venv(`/opt/ca3p-venv`)가 이미 있다 |

- 기존 PLAN의 "Node 단일 모듈 + Python 서브프로세스 브리지" 안은 **폐기한다.** HWPX 생성 요구 때문에 build의 중심이 Python으로 옮겨 갔다.
- 의존성
  - capture: `playwright`. 이미 있는 버전(1.58.2, manifest runtime 기준)과 맞춘다.
  - build: `python-hwpx`(Apache-2.0, `lxml` 의존), `pydantic`(casper-db와 공유)

### 3.2 python-hwpx 사용 방침
- **Alpha 단계라 API가 바뀔 수 있다.** 커밋 SHA나 정확한 버전으로 고정하고, 모든 호출을 `hwpx_writer.py` 한 파일로 감싼다. 라이브러리를 교체하거나 버전을 올릴 때 바꿀 곳이 하나가 된다.
- **템플릿 방식:** 한글에서 `templates/ca3p-report.hwpx`(표지, 목차 제목, 2열 표 양식)를 만들어 두고, `HwpxDocument.open()` → `tables.fill_by_path()`로 라벨 칸을 채운다. 사진은 `add_picture()`, 제목은 `add_heading()`, 문단은 `add_paragraph()`로 넣는다.
- **스파이크로 먼저 확인할 것(M1):**
  1. 행 수가 바뀌는 표(재점검 이력, triage)를 만들 수 있는가. 표 생성 API가 README에 명확하지 않다.
  2. 이미지를 넣고 크기와 캡션을 지정할 수 있는가.
  3. 코드 블록(고정폭 글꼴, 줄바꿈 유지)을 표현할 수 있는가.
  4. 만든 파일이 한글이나 한컴 뷰어에서 깨지지 않고 열리는가. 라이브러리의 검증 기능과 사람의 육안 확인을 함께 쓴다.
  5. `<script>`, `&`, `]]>` 같은 문자열이 텍스트로 정확히 보이는가.
- 스파이크에서 막히면 대안은 **HWPX 템플릿의 XML을 직접 다루는 것**이다(lxml, OWPML). 이 경우 범위가 커지므로 다시 상의한다.

### 3.3 디렉터리 구성(안)
```
packages/report/
  PLAN.md  README.md
  capture/            # Node
    package.json  capture.mjs  sandbox.mjs  cli.mjs  tests/
  build/              # Python
    pyproject.toml
    src/ca3p_report/  __init__.py  loaders.py  model.py  redact.py  escape.py
                      hwpx_writer.py  markdown_writer.py  cli.py
    templates/ca3p-report.hwpx
    tests/
```

### 3.4 "Agent"의 범위
보고서의 사실 항목(판정, 상태, 심각도, 요청과 응답, 고지 문구)은 **결정론적 코드가 채운다.** LLM을 쓴다면 "점검 개요" 서술 문단 하나만 맡기는 선택 기능으로 둔다. 이때 입력은 마스킹된 ReportModel로 한정하고, 출력에 판정 관련 단어가 들어가지 않았는지 검사한다. 기본값은 끈다(§7 Q6).

---

## 4. 인터페이스와 계약
특정 호출자(테스트용 app 또는 실제 파이프라인)에 묶이지 않도록, **CLI와 JSON 입출력**을 기본 계약으로 둔다. agent의 JSON envelope 형식(`receiver:'report'`)으로 감싸는 일은 실제 파이프라인 담당자와 정한다(§7 Q1).

### 4.1 capture
```
node packages/report/capture/cli.mjs --run-id <id> --origin http://127.0.0.1:<port> \
     --post-id <n> --marker <m> --output-root <abs> [--viewer bob|default]
```
- 입력은 run 보고서에서 그대로 가져온다: `target.origin`, `finding.resourceId`, `finding.marker`.
  finding이 없는 실패 run이면 ①만 찍는다.
- 출력은 표준출력으로 JSON 한 개를 낸다.
  ```json
  { "schemaVersion": "report-capture-1.0", "runId": "...", "status": "captured|partial|failed",
    "captures": [{ "kind": "input-point|victim-view", "variant": "element|full-page",
                   "ref": "<runHash>/captures/victim-view.png", "sha256": "...", "sizeBytes": 0,
                   "mime": "image/png", "capturedAt": "...", "pageUrl": "...", "viewport": {...},
                   "selector": "...", "viewerUserId": "alice|bob", "canaryCallbackObserved": true }],
    "errors": [] }
  ```
- 종료 코드: `0` 전부 성공, `5` 일부 성공, `6` 대상에 접속할 수 없음.
- **파이프라인을 멈추지 않는다.** 촬영이 실패해도 run 결과에는 영향을 주지 않는다. 실패는 매니페스트에만 기록한다.
- 호출 시점: run finalize **뒤**, 실습 환경을 정리(`labSession.close()`나 컨테이너 종료)하기 **전**.

### 4.2 build
```
python -m ca3p_report build --run-id <id> --reports-dir <abs> --casper-db <abs> \
       --captures-root <abs> --out-dir <abs> [--format hwpx,json,md] [--generated-at <iso>] [--no-images]
```
- 출력: `<out-dir>/<sha256(runId)>/report.hwpx`, `report-model.json`, 그리고 선택 시 `report.md`와 `assets/`
- 기존 파일은 덮어쓰지 않는다(`wx`). 종료 코드: `0` 성공, `2` 입력 오류, `3` run 없음, `4` 보고서 미완료.
- 프로그램 API(순수 함수와 I/O 분리)
  ```python
  load_run(run_id, reports_dir) -> RunData | None
  load_casper(db_path, refs) -> CasperContext          # unavailable 허용
  load_captures(captures_root, run_id) -> list[Capture] # 해시 재검증
  build_model(run, casper, captures, generated_at) -> ReportModel   # 순수 함수
  write_hwpx(model, template, out) / write_markdown(model, out)
  ```

### 4.3 경계(읽기 전용)
| 대상 | 접근 | 금지 |
|---|---|---|
| 대상 게시판 | capture만 접속. 기록된 loopback origin에 GET/HEAD만, 그리고 (합의 시) `POST /api/session` 1회 | 게시글 생성, 수정, 삭제. 외부 origin |
| pentest-db 디스크 | 파일 읽기만. runId 검증 후 `sha256(runId)` 디렉터리 | 쓰기 |
| casper-db | `CaseStore` 읽기 메서드만(`mode=ro`) | `initialize_database`, `add*`, `update`, `review_check` |
| run-store | (필요 시) `sqlite3` `?mode=ro` URI | DDL, 쓰기 |
| 네트워크 | capture의 loopback 접속 외에는 없음 | build의 모든 네트워크 |

### 4.4 ReportModel `report-1.0`
§0과 §2.1의 필드를 정규화한다. 주요 키는 `run, finding, reproduction{steps[], poc{request,response,payload,marker}}, captures[], triage, priorCases, guardrail, safety, notices[], references, generator, generatedAt`이다.
- 문자열은 원문(이스케이프 전)으로 저장한다.
- 마스킹은 모델을 만들 때 먼저 적용한다. 대상: authorization, cookie, set-cookie, api key, Bearer, `sk-…` 형태 문자열, `reasoning_content`/`prompt`/`rawResponse` 키.
- Python 쪽 마스킹 규칙은 `packages/contracts/index.mjs`의 `redact()`와 **같은 테스트 벡터**로 검증해 두 구현이 어긋나지 않게 한다.

---

## 5. 마일스톤
| 단계 | 작업 | 산출물 | 완료 기준 |
|---|---|---|---|
| **M0. 결정 정리** | ✅ 브랜치, 작업 범위, 2단계 구조, 사진 2장, HWPX 결정 | 이 문서 | 완료 |
| **M1. python-hwpx 스파이크** | §3.2의 1~5번 확인. 간이 템플릿으로 2열 표, 이미지, 코드 블록, 가변 행 표를 만든다 | `spike/` 결과와 짧은 보고 | 한글/뷰어에서 정상으로 열림. 막히면 대안 결정 |
| **M2. 스캐폴딩** | §3.3 구조. 두 하위 패키지와 빈 CLI. 경계 테스트(build에 네트워크 없음, capture는 loopback만) | 실행 가능한 `--help` | `node --test`와 `pytest` 통과 |
| **M3. capture** | 샌드박스 브라우저, 사진 ①②, 매니페스트, 원자적 저장. synthetic 게시판으로 테스트 | `capture.mjs`, 매니페스트 계약 | 로컬 vul-web-1에서 사진 4장(요소 + 전체) 생성. 쓰기 요청이 차단됨을 검증 |
| **M4. build 로더와 모델** | `load_run`/`load_casper`/`load_captures`, `build_model`, 마스킹 | `report-model.json` 골든 | 정상, 실패, 미완료, DB 없음, 해시 불일치 케이스 |
| **M5. HWPX 렌더러** | 템플릿 채우기, 사진, 코드 블록, 표 | `report.hwpx`(+ md 미리보기) | 골든 구조 검사(XML), 이스케이프 테스트, 육안 확인 |
| **M6. 연동 요청과 문서** | 호출 지점, 볼륨, 세션 전환 허용을 담당자에게 요청할 문안. README | 요청 문안, README | 담당자 회신 |
| **M7. 검증** | 독립 리뷰(code-reviewer, security-reviewer) | 리뷰 결과 | 지적 해소 |

---

## 6. 테스트 전략
- **러너:** capture는 `node --test packages/report/capture/tests/`, build는 `pytest packages/report/build/tests`.
  manifest에 등록되기 전까지는 CI가 이 모듈을 실행하지 않으므로 커밋 전에 직접 돌린다.
- **fixture(모두 synthetic)**
  - 게시판: 테스트에서 vul-web-1을 `PORT=0`, 임시 데이터 파일로 직접 띄운다. canary 게시글은 **테스트 준비 단계에서만** POST로 만든다. capture 코드 자체는 쓰지 않는다.
  - run 데이터: 임시 디렉터리에 pentest-db 규약대로 `report.json`과 이벤트 파일을 만든다(`loop.act`, `loop.history` 포함).
  - casper-db: 임시 DB에 `initialize_database`와 `add`로 synthetic 사례와 check를 넣는다. 이 쓰기도 테스트 준비 단계에서만 한다.

| 범주 | 검증 |
|---|---|
| capture 샌드박스 | 외부 origin, POST/DELETE, WebSocket 시도가 차단되고 `errors`에 기록된다. 허용되지 않은 origin 입력(`http://example.com`, `https://127.0.0.1`, 경로 포함)은 거부된다 |
| capture 결과 | 사진 ①②의 요소 캡처에 대상 선택자가 들어 있다. 매니페스트 sha256이 파일과 일치한다. 대상에 접속할 수 없을 때 종료 코드 6이고 파이프라인 예외가 없다 |
| 이스케이프 | payload `<img src=x onerror=…>`, `<script>`, `&`, `]]>`, `|`가 HWPX XML에서 텍스트 노드로 있다(원시 요소로 들어가지 않음). MD에서는 엔티티 형태다. 이중 이스케이프가 없다 |
| 마스킹 | fixture에 심은 `Cookie`, `Set-Cookie`, `Authorization`, `sk-…`, `reasoning_content`가 JSON, MD, HWPX 어디에도 없다. contracts `redact()`와 같은 벡터로 결과가 일치한다 |
| 프레이밍 | 고지 상자, triage 고정 문구, 사진 캡션의 "판정 근거 아님" 문구, `[가상]`, `verifiedByStorage:false`가 출력에 있다 |
| 무결성 | 사진 파일을 1바이트 바꾸면 해당 사진이 빠지고 "무결성 불일치"가 표시된다 |
| 읽기 전용 | build 전후로 casper DB와 reports 디렉터리의 해시가 같다. DB 경로에 파일이 없으면 새로 만들지 않는다 |
| 결정성 | 같은 입력과 `--generated-at`이면 `report-model.json`이 바이트 단위로 같다. HWPX는 ZIP 타임스탬프 때문에 XML 내용 기준으로 비교한다 |

---

## 7. 미해결 질문과 요청 항목
| # | 질문/요청 | 대상 | 제안 |
|---|---|---|---|
| Q1 | **실제 agent 파이프라인 코드의 위치**(원격 저장소에 없음). report 단계를 어디서, 어떤 형식(CLI, envelope)으로 호출할지 | 파이프라인 담당 | §4 CLI 계약을 기준으로 맞춘다 |
| Q2 | **capture 출력의 영속 볼륨**(예: `report-output:/app/reports/report-module`) 추가 | 통합 담당(docker-compose) | 새 볼륨. 다른 모듈의 볼륨을 공유하지 않는다 |
| Q3 | 실제 파이프라인이 run 결과를 pentest-db JSON에 저장하는가, run-store에 저장하는가 | 파이프라인 담당 | 둘 다 지원할 수 있게 로더를 분리한다 |
| Q4 | 피해자 화면을 **bob 계정**으로 찍기 위해 capture 샌드박스에서 `POST /api/session {userId:'bob'}` 1회를 허용할지 | 사용자/보안/guardrail 담당 | 허용(데이터 변경 없음, 메타데이터에 기록). 불허 시 "기본 계정(alice) 새 브라우저"로 캡션 |
| Q5 | 촬영 호출 시점 보장: finalize 뒤, 환경 정리 전 | 파이프라인 담당 | 실패해도 run을 막지 않는 best-effort 호출 |
| Q6 | "점검 개요" 서술에 LLM을 쓸지 | 사용자 | 기본은 끄고, 선택 기능으로 둔다 |
| Q7 | HWPX 템플릿(표지, 기관 양식)을 누가 만드는가. 기존 CERT 양식이 있는가 | 사용자/팀 | 있으면 그 양식을 기반으로 하고, 없으면 2열 표 기본 양식을 직접 만든다 |
| Q8 | 보고서 단위: run 1건당 1부인가, 월간 집계도 필요한가 | 사용자 | MVP는 run 단위 |
| Q9 | 보고서 출력의 보존 정책, gitignore | 팀 | 출력 루트는 gitignore 대상 |
| Q10 | BOLA 레거시 프로필도 지원하는가 | agent 담당 | 공통 필드와 일반 checks 표만 지원 |
