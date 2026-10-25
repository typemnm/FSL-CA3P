# 보고서 생성 모듈(Report Agent) — 조사 결과 및 개발 PLAN

- 작성일: 2026-10-18 / 개정: 2026-10-19
- 브랜치: `woohyun212/report-module`. `origin/develop`(`1560b1c`)에서 새로 만들었다.
- 모듈 위치: `packages/report/`. 이 문서도 모듈 안에 둔다.
- 상태: **조사 + 계획만 함. 코드 구현 없음.**
- 근거: §0.1~0.3에 인용한 경로와 줄 번호는 최초 조사 시점(`main` `0c820a0`) 기준이다. `origin/develop` 기준이면 따로 표시했다.

> **한 줄 정의:** Report Agent는 **main Agent가 트리거하면, 기존 모듈들이 실행한 결과를 수집하고 대상을 직접 촬영해서 HWPX 보고서를 만드는 Agent**다.
> 보고서는 무엇보다 **① 어떤 취약점인지 ② 공격 대상이 무엇인지 ③ 실제로 exploit 되었는지**를 알 수 있어야 한다.

> **결정됨:**
> - (10-18) develop에서 새 브랜치를 만들어 작업한다. 통합 관리(`integration-manifest.json`, CI, docker-compose)는 별도 담당자가 맡고, 이 모듈은 `packages/report/` 안에서만 작업하고 **커밋까지만** 한다.
> - (10-19) **환경 정보 무보유:** Agent는 경로, 원천 종류, 대상 URL, 배포 형태(Docker 등)를 하드코딩하거나 추측하지 않는다. 이런 값은 **모두 트리거 요청으로 받는다**(§4.1). 보고서에도 배포 환경 정보(볼륨 경로 등)를 넣지 않는다.
> - (10-19) **수집기는 모듈 안에 둔다.** pentest-db, run-store, casper-db에서 다른 모듈의 결과를 가져온다. 원천마다 교체 가능한 드라이버로 만든다.
> - (10-19) **Report Agent가 직접 촬영한다.** 사진은 ① 입력 지점 ② 피해자 관점 결과 화면이다. 환경을 정리하기 전에 트리거되어 대상에 직접 접속한다.
> - (10-19) PoC 요청, 응답, 점검 페이로드는 **텍스트**로 넣는다. 과거 사례 대조, 재점검 이력, 가드레일 결정은 수집기 결과로 함께 들어간다.
> - (10-19) **코어는 수집된 ReportInput 번들만 입력으로 받는다**(§2.3). 수집기와 촬영만 외부에 접근하고, 코어는 번들 밖을 보지 않는다.
> - (10-19) 문서는 [python-hwpx](https://github.com/airmang/python-hwpx)로 **HWPX**를 만든다.
> - (10-19) **범용 설계:** 코어(취약점 종류를 모름) + 취약점 프로필(stored_xss, generic, bola)로 나눈다. 사이트별 어댑터는 두지 않는다(10-20, §3.2).
> - (10-19) dashboard/worker 앱 경로는 테스트용이다. 실제 main Agent 파이프라인은 따로 있다(아직 원격 저장소에 없음, §7 Q1).
> - (10-20) **트리거 시점은 finalize 직후(attack 수행 후)**다.
> - (10-20) **수집기를 먼저 개발한다.** 결과 원천은 각 DB의 API와 스키마를 분석해 필요한 것을 가져오게 한다. → `collect` 구현 완료(§5 M3, README).
> - (10-20) **보고서 출력 파일 이름은 LLM Agent가 짓는다.** 단, 경로 문자 제거, 길이 상한, 예약어 회피 같은 정규화를 거치고, 실패하면 `<runId>.hwpx`로 대체한다(§3.8).
> - (10-20) **보고서 작성은 LLM Agent가 한다(§3.8).** OpenAI-compatible API로 호출하고, 수집된 정보와 context를 전부 전달한다. LLM은 도구(사진 촬영, HWPX 작성)를 호출해 보고서를 만든다.
>   - LLM 접속 정보는 agent core와 같은 환경변수 `DEEPSEEK_BASE_URL`, `DEEPSEEK_API_KEY`, `DEEPSEEK_MODEL`에서 읽는다. 같은 시스템 파이프라인 안이기 때문이며, "환경 정보 무보유" 원칙의 유일한 예외다.
>   - LLM 데이터 정책(외부 전송 여부)은 지금 다루지 않는다. 나중에 로컬 LLM으로 전환할 예정이다.
>   - LLM이 실패하면 템플릿으로 다시 만들지 않고, 실패(`LLM_FAILED`)를 agent core에 그대로 전달한다.
>   - 반복 횟수, 촬영 장수, 시간에 상한을 두지 않는다.
> - (10-20) **촬영에 필요한 정보는 수집기가 찾아서 번들에 담는다(Q4).** 파서 보고서(`loop.observe`)에 폼 선택자, 필드, JS에서 찾은 API(`POST /api/session`, `bodyKeys:["userId"]`)가 들어 있다. 이를 `hints/capture.json`으로 추려 두고, 부족하면 LLM이 페이지에서 직접 찾는다(§2.2, §2.5).
> - (10-20) **사이트 어댑터와 `target.application` 식별은 제거(Q11).** 촬영을 LLM이 직접 하므로 사이트별 선택자 목록이 필요 없다.
> - (10-20) **호출 방식은 우리가 설계한다(Q1/Q5).** main Agent가 finalize 직후 이 모듈의 CLI를 `ReportTrigger`로 호출한다. 외부 담당자 결정에 의존하지 않는다.
> - (10-20) **이미지는 LLM이 필요에 따라 PNG로 촬영하고, 보고서 본문에 해시를 표기하지 않는다(Q13).** 해시는 번들 무결성 확인용으로 manifest에만 둔다.

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

### 1.1 보고서가 답해야 할 것
| 질문 | 보고서 위치 | 원천(수집기) |
|---|---|---|
| **① 어떤 취약점인가** | 취약점 요약, 상세 2열 표 | run 보고서 `finding.{title, cwe, severity, severityBasis}`, `testProfile`. 심각도는 LLM이 CVSS 3.1로 평가해 적음 |
| **② 공격 대상은 무엇인가** | 점검 개요, 상세 표의 "발생 위치" | run 보고서 `target.origin` + `loop.act`의 `curl.{method, url}`, 파라미터 |
| **③ 실제로 exploit 되었는가** | 상세 표의 "판정 상태" + 판정 검사표 + 피해자 화면 사진 | `finding.{status, confidence, checks}`, 실패 run은 `status:'failed'` + `error` |
| 어떻게 재현하나 | 재현 절차, PoC 요청·응답·페이로드(텍스트), 입력 지점 사진 | `loop.act` 이벤트 + 직접 촬영 |
| 과거에도 있었나 | 과거 사례 대조, 관련 전월 보고서, 재점검 이력 | `loop.history` 이벤트 + casper-db |
| 안전하게 수행되었나 | 가드레일 결정, 안전 속성 | `report.guardrail.decisions`, `report.safety` |

③은 **상류의 결정론적 판정을 그대로 옮긴다.** Report Agent는 판정하지 않는다.

### 1.2 전체 흐름
```
 main Agent ── 트리거(ReportTrigger JSON: runId, 원천 위치들, 대상 URL, 출력 위치) ──┐
                                                                                 ▼
 ┌───────────────────────────── Report Agent (packages/report) ──────────────────────────────┐
 │                                                                                            │
 │  [수집 단계 — 트리거가 준 위치에만 접근, 읽기 전용]                                           │
 │   collect-run       pentest-db 디스크 | run-store                ─┐                          │
 │   collect-history   casper-db | (없음)                           ─┤                          │
 │   collect-hints     파서 보고서 → 촬영 힌트(선택자·세션 API)       ─┼─▶ ReportInput 번들        │
 │   seal              manifest.json(해시·수집기 종류) 확정          ─┘     (수집분 봉인)         │
 │                                                                            │               │
 │  [작성 단계 — LLM Agent 루프]                                                ▼               │
 │   LLM(OpenAI-compatible, tool calling) ← 번들 전체(마스킹) + 작성 규칙                        │
 │     도구: read_bundle · capture_screenshot · hwpx_* · finish_report                        │
 │   finish_report → report.hwpx 확정 (검증기 없음; 작성 규칙은 프롬프트로만 전달)              │
 └───────────────────────────────────────────────────────────┬────────────────────────────────┘
                                                             ▼
                                              ReportResult(JSON) → main Agent
```
- **트리거 시점:** run이 finalize된 **뒤**, 실습 환경을 정리하기 **전**이다. 촬영에 살아 있는 대상이 필요하기 때문이다.
- 수집이 끝나면 수집분(run/·history/·hints/·manifest)을 봉인(seal)한다. **촬영은 수집 단계가 아니라 작성 단계에서 LLM이 `capture_screenshot` 도구로 한다(§2.5).** 사진은 봉인 뒤 `evidence/`에 추가된다. 작성은 대상이 살아 있는 동안 같은 트리거 안에서 실행한다.

### 1.3 하는 일
- 트리거가 지정한 원천에서 다른 모듈의 결과를 **읽기 전용으로** 수집한다.
- 트리거가 지정한 대상 URL에 **직접 접속해** 프로필이 정한 장면을 샌드박스 브라우저로 촬영한다.
- 수집 결과와 사진을 ReportInput 번들로 봉인하고, 번들만으로 HWPX 보고서를 만든다.
- 모든 출력에 고지 문구, 출처, 한계를 넣는다. 비밀값은 마스킹한다.

### 1.4 하지 않는 일
- **판정하지 않는다.** `finding.status`를 그대로 옮긴다. 촬영 중 관찰한 신호(canary 콜백 등)는 기록만 하고 판정에 쓰지 않는다.
- **공격하지 않는다.** 촬영은 대상의 데이터를 만들거나 바꾸는 요청을 보내지 않는다. 상태를 바꾸는 요청은 수집기가 번들에 담아 둔 계정 전환 정의와 일치할 때만 보낸다(§2.5).
- **저장소에 쓰지 않는다.** casper-db, pentest-db, run-store는 읽기만 한다. 쓰는 곳은 트리거가 지정한 출력 위치뿐이다.
- **환경 정보를 갖고 있지 않는다.** 기본 경로, 기본 포트, 컨테이너 이름, 볼륨 경로가 없다. 트리거에 없는 곳에는 접근하지 않는다.
- 트리거의 대상 URL이 run 보고서에 기록된 `target.origin`과 다르거나 loopback이 아니면 접속하지 않는다. 외부 호스트는 금지다.
- 다른 담당자 모듈을 수정하지 않는다. 필요한 변경은 §7에 요청 항목으로 적는다.

### 1.4.1 운영 전제 — 보고서는 사람이 최종 검토한다
- 이 모듈의 산출물은 **초안**이다. 사람이 읽고 최종 검토·승인한 뒤 배포한다. LLM 결과물을 100% 신뢰하지 않는다.
- 그래서 보고서 내용의 **의미적 정확성(서술·조치 방안·CVSS 타당성)을 코드로 검증하지 않는다.** 검증기를 두지 않은 이유가 이것이다. 과설계 대신 사람 검토에 맡긴다.
- 코드가 강제하는 것은 **행동 경계뿐**이다(도구 샌드박스: 대상 외 접속·쓰기·번들 밖 읽기 차단, 비밀값 마스킹). 아래 §1.5의 프레이밍 규칙은 **프롬프트 지침**으로 LLM을 유도할 뿐, 코드가 보장하지 않는다.
- ⚠️ 현재 데이터는 synthetic이고 실습용이라 이 전제가 성립한다. **실제 findings에 쓰려면** 사람 검토를 거치기 전에는 배포하지 않는다는 규칙을 반드시 지켜야 한다.

### 1.5 프레이밍 지침 (프롬프트로 LLM에 유도, 코드 강제 아님)
아래는 **프롬프트 지침**이다(§1.4.1). 코드가 강제하는 것은 도구 샌드박스(대상 외 접속·쓰기·번들 밖 읽기 차단)와 마스킹뿐이고, 표의 규칙들은 LLM 준수에 의존한다.

| 규칙 | 보고서 표기 방법 |
|---|---|
| exploit 여부는 상류가 전달한 판정이다 | 판정 상태 칸에 "에이전트의 결정론적 판정(전달받음), 보고서 모듈과 저장소는 검증하지 않음" |
| CVSS는 LLM이 매긴 값이다 | 심각도 칸에 "LLM이 CVSS 3.1로 산출"을 명시하고 벡터를 함께 보인다. exploit 판정과 혼동하지 않게 분리 표기한다 |
| 위치 일치는 재점검 후보일 뿐 현재 취약 판정이 아니다 | triage 섹션 머리에 고정 문구. 레이블은 `demo.py`와 같게 "재점검 후보 / 수동 확인 / 일치 없음" |
| `ready`/`reviewed`는 상태 표시일 뿐 취약 판정이 아니다 | 상태 열 머리말에 "(상태 표시)"와 각주 |
| 현재 데이터는 전부 synthetic이다 | 표지 고지 상자. synthetic 행에는 `[가상]` |
| 해시는 바이트만 증명할 뿐 취약점을 증명하지 않는다 | 해시 표 각주 |
| 사진은 보조 자료이며 판정 근거가 아니다 | 모든 사진 캡션 아래 고정 문구 |
| 저장소는 내용을 검증하지 않는다 | `verifiedByStorage:false`를 그대로 표시 |
| 카탈로그는 draft 참고 자료다 | `draft_advisory` 표시 |

---

## 2. 입력과 출력

### 2.1 Agent 입력 = 트리거 하나
main Agent가 보내는 `ReportTrigger`가 Agent의 **유일한 외부 입력**이다. 환경에 관한 모든 값이 여기에 있다(§4.1).
- 무엇에 대한 보고서인가: `runId`
- 결과를 어디서 가져오나: `sources.run`, `sources.history` (종류 + 위치)
- 어디를 촬영하나: `capture.targetUrl`
- 어디에 쓰나: `output.dir`

### 2.2 수집기 (환경 의존 부분을 전부 여기에 모은다)
| 수집기 | 원천 종류(`kind`) | 가져오는 것 | 번들 산출물 | 원천이 없을 때 |
|---|---|---|---|---|
| `collect-run` | `pentest-db-disk`: §0.1 디렉터리 규약, `readRun` 동등 / `run-store`: SQLite `?mode=ro`  (`file` 직접 입력은 미구현) | 최종 run 보고서와 이벤트 전체 | `run/report.json`, `run/events.json` | **보고서 생성 불가**(종료 코드 3) |
| `collect-history` | `casper-db`: `CaseStore` 읽기 메서드만 / `none` | `loop.history` 이벤트가 가리키는 사례의 대조 당시 스냅숏(`get_version`), 현재 revision(`get`), check 목록(`list_checks`) | `history/casper.json` | `status:'unavailable'`로 기록하고 계속 진행 |
| `collect-hints` | `collect-run` 결과(파서 보고서) | 촬영에 필요하면 찾아 둔다(Q4): 입력 폼 선택자·필드, 세션/계정 전환 API(`POST …/session`, `bodyKeys`), 공격자 계정. **없으면 비워 둔다** | `hints/capture.json` | 힌트 없이 진행(LLM이 페이지에서 직접 판단) |
| `seal` | 번들 디렉터리 | 파일 해시, 수집기 종류·상태 | `manifest.json` | — |

- 촬영(스크린샷)은 **작성 단계에서 LLM이 `capture_screenshot` 도구로** 한다(§2.5). 수집 단계는 촬영에 쓸 **힌트만** 번들에 담는다.
- 가드레일 결정, 안전 속성, triage 원본(`loop.history` 이벤트)은 `collect-run` 결과 안에 이미 있다. 따로 수집하지 않는다.
- 수집기는 **읽기 전용**이다. casper-db는 `initialize_database()`를 호출하지 않는다. run-store는 `createRunRepository()`가 DDL을 실행하므로 쓰지 않고, 읽기 전용 SQLite 연결로 직접 SELECT한다(§0.4).
- 새 원천 형식이 생기면 수집기 드라이버만 추가한다. 코어는 바뀌지 않는다.

### 2.3 코어 입력 = ReportInput 번들 (고정)
```
<bundle>/
  manifest.json              # 스키마 버전, runId, 파일 목록(경로·해시·크기·역할), 수집기 종류·상태
  run/report.json            # 저장 원본 레코드 그대로
  run/events.json            # 이벤트 배열 (recordedAt → messageId 순)
  history/casper.json        # { status, reason?, cases:[{ snapshot, currentRevision, checks }] }
  hints/capture.json         # 촬영 힌트(폼 선택자, 세션 전환 API, 공격자 계정) — 없으면 비어 있음
  evidence/captures.json     # 작성 단계에서 LLM이 찍은 사진의 메타데이터
  evidence/images/*.png      # 작성 단계에서 추가됨
```
- 수집 단계는 `run/`, `history/`, `hints/`를 채우고 봉인한다. `evidence/`는 **작성 단계에서 LLM 촬영 도구가** 채운다.
- build는 manifest와 실제 파일을 대조한다. 봉인된 파일이 바뀌었으면 해당 섹션에서 빼고 "무결성 불일치"로 표시한다.
- 번들은 증적 보관 단위가 된다. 파일 해시는 이 무결성 확인에만 쓰고 **보고서 본문에는 표기하지 않는다(Q13).**
- 이미지 형식·장수는 고정하지 않는다. LLM이 PNG로 필요에 따라 찍는다(Q13).

manifest 예시(초안):
```jsonc
{ "schemaVersion": "report-input-1.0", "runId": "run-…", "collectedAt": "…",
  "collectors": [ { "name": "collect-run", "driver": "pentest-db-disk", "status": "ok" },
                  { "name": "collect-history", "driver": "casper-db", "status": "unavailable", "reason": "db-not-found" },
                  { "name": "collect-hints", "status": "ok" } ],
  "files": [ { "path": "run/report.json", "role": "run-report", "sha256": "sha256:…", "size": 0,
               "mediaType": "application/json" } ] }
```
- `collectors[].driver`에는 원천의 **종류만** 남긴다. 원천의 위치(경로, 포트)는 번들에도 보고서에도 남기지 않는다. 단, 공격 대상 origin은 보고서의 "공격 대상" 항목에 필요하므로 `run/report.json`의 `target.origin`을 쓴다.

### 2.4 run 보고서에서 쓰는 필드
| 보고서 항목 | 원천(번들 `run/`) |
|---|---|
| 실행 메타 | `report.{runId, status, testProfile, target, startedAt, completedAt, metrics, progress}`, `storedAt`, `provenance` |
| finding 공통 필드 | `findingId, title, cwe, severity, severityBasis, confidence, status, evidenceRefs, checks, summary, limitations, remediation` (두 프로필 공통, `reasoning-engine.js`) |
| PoC 요청(텍스트) | `stage==='loop.act'` 이벤트의 `event.request.payload.curl` (method, url, body). `redact()`를 한 번 더 적용한다 |
| 응답(텍스트) | `loop.act` 이벤트의 `event.response.payload.response` (status, bodyJson). `setCookie`는 제거한다 |
| 프로필 추가 텍스트 | stored_xss: 점검 페이로드(`curl.body.content`), marker / bola: 대상 리소스와 쿼리 |
| triage | `stage==='loop.history'` 이벤트의 `payload.{readyCaseCount, observations, assessments}` |
| 가드레일, 안전 속성 | `report.guardrail.decisions`, `report.safety` |

### 2.5 직접 촬영 (capture, LLM이 도구로 호출)
**사이트별 선택자 목록(어댑터)은 두지 않는다(10-20 결정, Q11).** 촬영은 LLM Agent가 `capture_screenshot` 도구로 수행한다. LLM은 대상 페이지를 열어 보고, 번들의 수집 데이터(파서 보고서의 폼 선택자, 세션 API, 공격자 계정)를 참고해 **무엇을 어느 선택자로 찍을지 스스로 정한다.** 그래서 사이트를 미리 식별할 필요가 없다.

`capture_screenshot(url, selector?, session?)` — LLM이 선택자와 (필요 시) 세션을 넘긴다. 도구는 다음을 **LLM의 요청과 무관하게 강제**한다.
- **대상 URL:** 번들 `run/report.json`의 `target.origin`과 정확히 같고 `http://127.0.0.1:<port>` 형식일 때만 접속한다. 그 밖이면 거부한다. (트리거가 `targetUrl`을 주면 이 값과도 일치해야 한다.)
- **샌드박스:** verify 단계 `observeStoredXssExecution`과 같은 수준. 같은 origin의 GET/HEAD만 허용한다. WebSocket·service worker 차단, 다운로드 거부, 팝업·대화상자 자동 닫기.
- **세션 전환(§2.2에서 수집):** 상태를 바꾸지 않는 계정 전환 요청(예: `POST /api/session {userId}`)만, **수집기가 번들에 담아 둔 정의와 정확히 일치할 때** 허용하고 기록한다. `hints/capture.json`가 없거나 세션 전환 정의가 비어 있으면 **허용 목록이 비어 전환을 전혀 허용하지 않는다(빈 목록 = 금지).** 그 외 쓰기 요청은 모두 차단한다.
- 저장: 사진은 `evidence/images/`에, 메타데이터(촬영 URL, 선택자, 세션 주체, 시각, 크기)는 `evidence/captures.json`에 추가한다. 파일 해시는 번들 무결성 확인용으로 manifest에만 기록하고, **보고서 본문에는 해시를 넣지 않는다(Q13).**
- **형식·장수는 고정하지 않는다.** LLM이 필요에 따라 찍는다. PNG로 저장한다.
- **vul-web-1 사실(§0.5):** 쿠키가 없으면 alice로 로그인되고 공격자도 alice다. 피해자 관점이 필요하면 수집기가 담아 둔 계정 전환으로 LLM이 전환해 찍고, 불가하면 기본 계정으로 찍되 그 사실을 캡션에 쓴다.
- **촬영에 실패해도 보고서는 만든다.** 해당 사진만 빠지고, LLM이 그 사실을 본문에 적는다.

### 2.6 출력
| 출력 | 위치 | 비고 |
|---|---|---|
| **`report.hwpx`** | 트리거의 `output.dir` | 최종 보고서 |
| `report-model.json` | 같은 위치 | 렌더러 입력, 테스트 기준. `schemaVersion:'report-1.0'`. 사진은 메타데이터만 |
| `report.md` (선택) | 같은 위치 | 한글 프로그램 없이 확인하는 미리보기 |
| ReportInput 번들 | `output.dir/bundle/` (보존 여부는 트리거 옵션) | 재렌더링과 증적 보관용 |
| **`ReportResult`** | 표준출력 JSON → main Agent | `{ ok, runId, files:[{name, sha256}], sections:{captured, history, …}, warnings[] }` |

**형식별 이스케이프**(ReportModel에는 원문을 저장하고, 출력 경계에서만 처리한다)
- **HWPX:** 텍스트 노드로만 넣는다. lxml이 XML 이스케이프를 해 주므로 HTML 이스케이프는 하지 않는다. 원시 XML 조각 삽입 API는 쓰지 않고 테스트로 금지한다.
- **Markdown:** HTML 이스케이프를 하고, 표 안의 `|`와 개행도 처리한다.
- **JSON:** 원문 그대로 넣는다. 소비자가 이스케이프한다.

### 2.7 HWPX 보고서 목차 (확정, Q7)
```
[표지] CA3P 취약점 점검 보고서 — <runId>, 생성일, 고지 상자(격리 실습 / synthetic / 판정은 전달받은 값 / 위치 일치≠판정)

1. 점검 개요          2열 표: 실행 ID, 상태, 시험 프로필, 공격 대상(origin), 시작/종료 시각, 요청 수
2. 취약점 요약        표: 번호 | 취약점 | CWE | CVSS 점수·등급 | 공격 대상 | exploit 여부(판정 상태)   ← 핵심 3가지를 한눈에
3. 취약점 상세        findings[] 반복 (보통 1건):
   3.n.1 기본 정보     2열 표(previous-month-xss-report.md 레이아웃):
                      취약점 유형(title, CWE) | 발생 위치(method path, 파라미터) |
                      심각도(CVSS 벡터·점수·등급, LLM 산출 명시 + 상류 severity) |
                      판정 상태(에이전트 결정론적 판정, 보고서·저장소 미검증) | 상세 설명 | 조치 방안 | 한계
   3.n.2 재현 절차     번호 목록. 단계에 연결된 사진(① 입력 지점, ② 피해자 화면)과 캡션
   3.n.3 텍스트 증거   PoC 요청, 응답, + 프로필 추가 항목(예: 점검 페이로드)
   3.n.4 판정 검사표   checks: 레이블 | 결과
   3.n.5 영향 / 3.n.6 기타 정보(profileData)
4. 과거 사례 대조(재점검 triage)   고정 문구 + 표
5. 관련 전월 보고서    사례별 2열 표(대조 당시 revision)
6. 재점검 이력        check 표 + 각주(해시는 표기하지 않음, Q13)
7. 가드레일 결정과 안전 속성
8. 출처와 한계        수집기 상태(원천 종류만), 프로필 이름, 생략된 섹션과 사유
```
- **보고서 단위는 run 1건 = 1부다(Q8).** 월간/다건 집계는 범위 밖. `findings[]`가 배열인 것은 한 run이 여러 finding을 낼 수 있어서이지 여러 run을 묶기 위함이 아니다.
- **심각도는 LLM이 CVSS 3.1로 평가한다(Q12, A안).** LLM이 수집 자료를 보고 벡터·점수·등급을 매긴다. 재계산·검증은 하지 않는다. 보고서에 "LLM 산출"임을 적고 상류 `severity`도 함께 둔다(프롬프트 지침). exploit 판정도 같은 방식으로 프롬프트에서 "`finding.status`를 그대로 쓰라"고 지시한다.
- 실패한 run이면 3절을 "실행 실패"(error code, source, message, 도달한 단계)로 바꾼다.

---

## 3. 모듈 구조, 언어, 확장 방식

### 3.1 구조
```
┌──────────── 수집 계층 (트리거가 준 위치에만 접근, 읽기 전용, 원천별 드라이버) ────────────┐
│ collect-run[pentest-db-disk | run-store] · collect-history[casper-db | none]            │
│ collect-hints(파서 보고서 → 촬영 힌트) · seal                                            │
└──────────────────────────────────┬──────────────────────────────────────────────────┘
                                   ▼ ReportInput 번들 (계약 고정, 봉인)
┌──────────── 작성 계층 (LLM Agent 루프) ────────────────────────────────────────────────┐
│ 마스킹 → LLM(OpenAI-compatible, tool calling) → HWPX  (검증기 없음)                      │
│ 도구: read_bundle · capture_screenshot(Node/Playwright 샌드박스) · hwpx_* · finish_report │
│ 환경변수 DEEPSEEK_* 는 LLM 클라이언트만 읽음. 그 외 네트워크·사이트 지식 없음              │
└───────────────▲────────────────────────────────────────────────────────────────────────┘
                │ testProfile
┌───────────────┴──────────────────────────────┐
│ 취약점 프로필 (LLM 작성 힌트 + check 표시 레이블)│   ← 사이트별 어댑터는 없음.
│ stored_xss / bola / generic(미등록 대체)       │     촬영 대상은 LLM이 번들 힌트와 페이지로 판단
└───────────────────────────────────────────────┘
```

### 3.2 프로필 선택 (사이트 어댑터는 두지 않음)
**사이트별 어댑터와 `target.application` 식별자는 설계에서 뺐다(10-20 결정, Q11).** 촬영을 LLM이 직접 하므로 사이트별 선택자 목록을 미리 둘 필요가 없다. 남는 가변 축은 **취약점 프로필** 하나다.

| | 프로필 |
|---|---|
| 무엇인가 | 취약점 종류별 LLM 작성 힌트(재현 절차 뼈대, check 표시 레이블, 텍스트 증거 이름) |
| 선택 기준 | `report.testProfile` → 정적 레지스트리. 모르는 값이면 `generic` |
| 없을 때 | `generic`: 공통 필드와 checks 키-값 표만. "프로필 미등록" 고지 |

- 촬영 대상 사이트 정보는 미리 알 필요가 없다. LLM이 번들의 수집 힌트(`hints/capture.json`: 폼 선택자, 세션 전환 API, 공격자 계정 — §2.2 `collect-hints`)와 실제 페이지를 보고 정한다.
- 필요한데 힌트에 없으면 LLM이 페이지에서 직접 찾는다. 상태를 바꾸는 요청은 수집기가 담아 둔 정의와 일치할 때만 허용된다(§2.5).

### 3.3 프로필 인터페이스 (Python, build 측)
```python
class VulnProfile(Protocol):
    id: str; upstream_profiles: tuple[str, ...]; version: str
    def split_finding(self, finding: dict) -> tuple[CommonFinding, dict]   # 공통 필드 / profileData
    def reproduction(self, run: RunData) -> list[Step]                     # 단계 문장 + 연결된 shotId
    def text_evidence(self, run: RunData) -> list[TextEvidence]            # PoC 요청·응답 외 추가 항목
    def check_labels(self) -> dict[str, str]
    def impact(self) -> str | None
```
- 프로필은 LLM에 주는 작성 힌트(system 프롬프트 조각)만 제공한다. 촬영 장면을 코드로 선언하지 않는다.
- 프로필은 LLM에 줄 작성 힌트 데이터만 제공한다. I/O, 네트워크, 판정 로직은 넣지 않는다. 마스킹은 LLM에 번들을 넘기기 전에 코어가 적용하므로 프로필이 우회할 수 없다(프레이밍은 프롬프트 지침이며 코드 강제가 아니다, §1.4.1).

### 3.4 언어
| 부분 | 언어 | 근거 |
|---|---|---|
| capture(스크린샷 도구) | Node ESM + Playwright | Playwright와 Chromium이 이미 이미지와 xss-parser에 있다. verify 샌드박스 패턴을 그대로 따른다 |
| 수집기(run, history), seal, LLM 루프·도구, HWPX 작성, CLI 진입점 | Python ≥3.11 | python-hwpx가 Python 전용이다. casper-db `CaseStore`를 직접 읽는다. JSON과 SQLite는 표준 라이브러리로 읽는다 |

- **진입점은 하나다.** `python -m ca3p_report run --trigger <file|->`가 수집 → seal → LLM 작성 루프(도구로 capture와 HWPX 호출)를 순서대로 실행한다. 단계별 서브명령(`collect`, `build`)도 따로 제공한다.
- `capture_screenshot` 도구는 Node 스크린샷 스크립트를 서브프로세스로 호출한다. LLM이 직접 Node를 실행하지는 않는다.
- LLM 호출은 `urllib`나 최소 HTTP 클라이언트로 OpenAI-compatible 엔드포인트에 보낸다. 이 네트워크는 LLM 루프 모듈에만 둔다.
- 의존성: 스크린샷 도구는 `playwright`(1.58.2와 맞춤). Python 쪽은 `python-hwpx`(Apache-2.0, `lxml`), `pydantic`. casper-db는 `collect-history` 드라이버에서만 import한다.

### 3.5 python-hwpx 사용 방침
- **Alpha 단계라 API가 바뀔 수 있다.** 정확한 버전이나 커밋 SHA로 고정하고, 모든 호출을 `hwpx_writer.py` 한 파일로 감싼다.
- 템플릿 방식: 범용 목차(§2.7) 하나를 `templates/ca3p-report.hwpx`로 만들어 두고 `open()` → `tables.fill_by_path()` / `add_heading()` / `add_paragraph()` / `add_picture()`로 채운다.
- **스파이크로 먼저 확인할 것(M1):**
  1. 행 수가 바뀌는 표
  2. 섹션 블록(제목 + 2열 표 + 코드 블록 + 사진)을 N회 반복
  3. 이미지 크기와 캡션 지정
  4. 코드 블록(고정폭 글꼴, 줄바꿈 유지)
  5. 한글이나 한컴 뷰어에서 정상으로 열리는가
  6. `<script>`, `&`, `]]>` 같은 문자열이 텍스트로 정확히 보이는가
- 막히면 대안은 HWPX XML(OWPML)을 lxml로 직접 다루는 것이다. 이 경우 다시 상의한다.

### 3.6 디렉터리 구성(안)
```
packages/report/
  PLAN.md  README.md
  schemas/        trigger.schema.json  manifest.schema.json  result.schema.json
  profiles/       registry.py  generic.py  stored_xss.py  bola.py   (py/src 아래, 아래 참조)
  capture/        screenshot.mjs  sandbox.mjs  cli.mjs  tests/                            # Node 스크린샷 도구
  py/             pyproject.toml                                                           # Python
    src/ca3p_report/
      trigger.py                                                              # 구현 완료
      collect/    model.py  pentest_db.py  run_store.py  casper.py  bundle.py  collector.py   # 구현 완료
      llm/        client.py(OpenAI-compatible)  loop.py  tools.py  redact.py
      hwpx/       writer.py  templates/ca3p-report.hwpx
      profiles/   registry.py  generic.py  stored_xss.py  bola.py            # LLM 작성 힌트 + check 표시 레이블
      cli.py      # run | collect
    tests/
```

### 3.7 새 취약점·새 사이트·새 원천을 추가하는 절차
- **새 취약점:** `profiles/<id>.py`(LLM 작성 힌트 + check 표시 레이블)를 추가하고 레지스트리에 한 줄 등록한다. LLM 루프, 도구, HWPX 작성기는 바꾸지 않는다.
- **새 실습 사이트:** 추가 작업이 없다. LLM이 수집 힌트와 페이지를 보고 촬영한다. 수집 힌트를 더 풍부하게 하려면 `collect-hints`만 보강한다.
- **새 결과 원천:** `collect/` 아래에 드라이버를 추가한다. 번들 계약은 유지한다.

### 3.8 "Agent"의 범위
**출력 파일 이름(10-20 결정):** LLM Agent가 보고서 파일 이름을 짓는다. 입력은 마스킹된 ReportModel의 요약(취약점, 대상, 결과)으로 한정한다. 결과는 다음 정규화를 거친다: 경로 구분자·제어문자·`..` 제거, NFC 정규화, 120자 상한, Windows 예약어 회피, 확장자 `.hwpx` 강제. 비었거나 이미 존재하면 `<runId>.hwpx`로 대체한다. 파일 이름이 보고서 내용(판정 등)을 바꾸지는 않는다.

**보고서 작성 주체(10-20 결정): LLM Agent.** 이전 안("사실 항목은 결정론적 코드가 채우고 LLM은 개요 문단만")을 대체한다.

| 요소 | 내용 |
|---|---|
| 호출 | OpenAI-compatible `POST {DEEPSEEK_BASE_URL}/chat/completions`, `tools`/`tool_calls` 사용. 모델은 `DEEPSEEK_MODEL` |
| 입력 context | 작성 규칙(필수 섹션, §1.5 프레이밍, 출력 형식)을 system 메시지로, 봉인된 번들 전체를 마스킹한 뒤 데이터로 전달. 수집 자료는 지시가 아닌 데이터로 구분해서 넣는다 |
| 도구 | `read_bundle`(번들 안 파일 읽기), `capture_screenshot`(번들에 기록된 대상 origin에만 접속, §2.5 샌드박스), `hwpx_*`(제목·문단·표·코드 블록·이미지 추가, python-hwpx), `finish_report`(파일 이름 확정 후 보고서 확정) |
| 도구 쪽 제약 | 도구가 스스로 강제한다: 대상 origin 고정, 쓰기 요청 차단, 번들 밖 읽기 차단, 텍스트는 텍스트 노드로만 삽입. LLM의 요청과 무관하게 적용된다 |
| 검증기 | **없음(10-20 결정).** LLM이 쓴 보고서를 그대로 확정한다. 사실성과 고지 포함은 아래 프롬프트 지침으로만 유도한다 |
| 프롬프트 지침 | system 메시지에 넣는 규칙(강제 아님): exploit 여부는 번들의 `finding.status`를 그대로 쓸 것, 필수 고지 문구를 넣을 것, 심각도는 CVSS 3.1로 평가하고 "LLM 산출"로 표기할 것, 비밀값을 쓰지 말 것 |
| 실패 처리 | API 오류, 응답 형식 오류 등 LLM이 끝내 보고서를 완성하지 못하면 템플릿 대체 없이 `ReportResult{ok:false, error:{code:'LLM_FAILED'}}`를 agent core에 전달한다 |
| 상한 | 반복 횟수, 촬영 장수, 시간 모두 상한 없음. 루프는 LLM이 `finish_report`를 호출하면 끝난다. 호출하지 않으면 프로세스가 외부에서 종료될 때까지 계속된다(C-1). LLM API 호출에는 요청별 HTTP 타임아웃을 둔다 |
| 기록 | LLM 대화와 도구 호출 로그를 출력 위치에 남긴다(마스킹 적용, API 키 제외) |

- 판정(exploit 여부)과 CVSS는 LLM이 보고서에 적는다. 코드로 강제하거나 재계산하지 않는다. 사실성은 프롬프트 지침과 LLM 품질에 맡긴다.
- 프로필(§3.2~3.3)은 LLM에 주는 취약점별 작성 힌트 역할만 한다.

---

## 4. 인터페이스와 계약

### 4.1 트리거: `ReportTrigger` (main Agent → Report Agent)
```jsonc
{
  "schemaVersion": "report-trigger-1.0",
  "runId": "run-…",
  "sources": {
    "run":     { "kind": "pentest-db-disk | run-store", "location": "<절대 경로>" },
    "history": { "kind": "casper-db | none", "location": "<절대 경로>" }
  },
  "capture": {                                      // 선택. 통째로 생략 가능(기본 촬영 켬)
    "enabled": true,                                // 선택, 기본 true. false면 촬영 생략
    "targetUrl": "http://127.0.0.1:<port>"          // 선택. 생략 시 run/report.json의 target.origin 사용.
                                                    //        주면 그 값이 target.origin과 같아야 함
  },
  "output": { "dir": "<절대 경로>", "formats": ["hwpx", "json"], "keepBundle": true },
  "options": { "generatedAt": "<ISO, 선택>", "images": true }
}
```
- **Agent가 접근하는 위치는 이 트리거에 있는 것뿐이다.** 기본 경로나 환경변수 fallback은 없다.
- 전달 방식은 CLI(`--trigger <file|->`)를 기본으로 한다. main Agent가 쓰는 JSON envelope(`receiver:'report'`, `type:'report.request'`)로 감쌀지는 파이프라인 담당자와 정한다(§7 Q1).
- 검증
  - runId 형식: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`
  - 경로: 절대 경로만 허용
  - `capture` 객체도 트리거 파서가 읽어 `Trigger`에 담는다(현재 구현은 키만 통과시키고 값을 무시하므로 build 단계 전에 보완, C-2/SF-4 참조).
  - `targetUrl`: 주어지면 loopback이어야 하고 수집된 `report.target.origin`과 일치해야 한다. 생략하면 `target.origin`을 쓴다. 불일치하면 촬영하지 않는다.

### 4.2 결과: `ReportResult` (Report Agent → main Agent)
```jsonc
{ "schemaVersion": "report-result-1.0", "ok": true, "runId": "run-…",
  "files": [ { "name": "report.hwpx", "sha256": "sha256:…", "size": 0 },
             { "name": "report-model.json", "sha256": "sha256:…", "size": 0 } ],
  "summary": { "vulnerability": "저장형 XSS 브라우저 실행 (CWE-79)", "target": "http://127.0.0.1:…",
               "exploit": "confirmed" },                                // 핵심 3가지 요약
  "sections": { "capture": "ok|partial|skipped|failed", "history": "ok|unavailable" },
  "warnings": [] }
```
- 종료 코드: `0` 성공, `1` 내부 오류(`INTERNAL_ERROR`, traceback·경로 노출 없이 클래스명만), `2` 트리거 오류, `3` run 없음, `4` run 미완료, `5` 원천 데이터 이상, `6` 번들이 이미 있음, `7` 출력 위치에 쓸 수 없음, `8` LLM 실패(`LLM_FAILED`, 템플릿 대체 없음).
- **파이프라인을 멈추지 않는다.** 보고서 생성이 실패해도 run 결과에는 영향을 주지 않는다. main Agent는 `ok`만 확인하면 된다.

### 4.3 내부 계약
- **번들:** §2.3. 수집 계층과 코어 사이의 유일한 계약이다.
- **코어 API**(순수 함수와 I/O 분리)
  ```python
  open_bundle(path) -> Bundle                          # manifest 검증, 해시 대조
  resolve_profile(bundle) -> VulnProfile               # manifest.resolution.profile
  build_model(bundle, profile, generated_at) -> ReportModel   # 순수 함수
  write_hwpx(model, template, out) / write_markdown(model, out)
  ```
- **ReportModel `report-1.0`:** `run`, `findings[]{common, checks[], reproduction[], textEvidence[], images[], impact, profileData}`, `triage`, `priorCases`, `guardrail`, `safety`, `notices[]`, `references`, `generator{profile, fallback}`, `generatedAt`
  - `common`에 `severity`(상류 값)와 `cvss{version:'3.1', vector, score, rating, source:'llm'}`를 둔다. `cvss`는 LLM이 채운다. 재계산·검증은 하지 않는다.
  - **보고서는 run 1건만 담는다(Q8).** `findings[]`는 한 run의 여러 finding을 위한 것이다.
  - 문자열은 원문으로 저장한다. 마스킹은 모델을 만드는 마지막 단계에서 코어가 적용한다.
  - Python 마스킹은 `packages/contracts/index.mjs`의 `redact()`와 같은 테스트 벡터로 검증한다.

### 4.4 경계
| 대상 | 접근 주체 | 허용 | 금지 |
|---|---|---|---|
| run 결과 원천 | collect-run | 트리거가 지정한 위치를 읽기만 함 | 쓰기, 지정되지 않은 위치 |
| casper-db | collect-history | `CaseStore` 읽기 메서드(`mode=ro`) | `initialize_database`, `add*`, `update`, `review_check` |
| 대상 사이트 | `capture_screenshot` 도구(작성 단계) | 번들 `target.origin`(loopback)에 GET/HEAD + 수집기가 담아 둔 계정 전환만 | 데이터 생성·수정·삭제, 외부 origin |
| 번들 | seal 이후 코어 | 읽기만 | 수정 |
| 네트워크(대상) | capture_screenshot 도구 | 번들 origin(loopback) | 그 외 대상 |
| 네트워크(LLM) | `llm/client.py` | `DEEPSEEK_BASE_URL`(환경변수)에 HTTPS | 그 외 대상, 수집기·HWPX 작성기에서의 네트워크 |

---

## 5. 마일스톤
| 단계 | 작업 | 산출물 | 완료 기준 |
|---|---|---|---|
| **M0. 결정 정리** | ✅ 브랜치·범위, 트리거 기반 Agent, 수집기 내장, 직접 촬영, 번들, HWPX, 범용 3계층 | 이 문서 | 완료 |
| **M1. 수집기 + seal** | ✅ (10-20) `collect-run`(pentest-db-disk, run-store), `collect-history`(casper-db, none), 번들 봉인, CLI `collect` | `py/src/ca3p_report/collect/`, 테스트 55개 | 실제 Node writer로 만든 원천으로 검증. 두 원천의 정규화 결과 동일. 원천 내용 불변, DB가 없을 때 생성 안 함, 번들 1회 쓰기·실패 시 잔여물 없음, 원천 위치·traceback 미노출 |
| **M2. python-hwpx 스파이크** | ✅ (10-20) python-hwpx 6.8.0 확인 | 스파이크 코드 | **GO.** `new/add_heading/add_paragraph/add_table+set_cell_text/add_picture/validate/export_markdown` 동작. 가변 행 표·섹션 반복 OK. 특수문자 자동 이스케이프(`<script>`→`&lt;`). lxml 대안 불필요. 남은 확인: 한컴/한글 뷰어 육안 |
| **M3. HWPX 작성기** | `hwpx/writer.py`: 제목·문단·표·코드 블록·이미지 추가, 텍스트 노드 삽입(이스케이프), 파일 이름 정규화 | 단위 테스트 | 특수문자가 텍스트로 보임, 원시 XML 삽입 불가, 이미지는 번들 경로만 |
| **M4. 스크린샷 도구** | Node `capture/`: 샌드박스(대상 origin 고정, GET 위주, 허용된 세션 전환만), 사진 저장, `captures.json` | `node --test` | 쓰기 요청 차단, 허용 목록 밖 요청 차단, origin 불일치 시 촬영 안 함 |
| **M5. LLM 도구 계층** | `llm/tools.py`: `read_bundle`·`capture_screenshot`(M4 서브프로세스)·`hwpx_*`(M3)·`finish_report`. 각 도구가 자체 제약을 강제 | 도구 단위 테스트(LLM 없이) | 번들 밖 읽기·대상 외 접속·원시 XML 모두 거부 |
| **M6. 마스킹** | `llm/redact.py`(core redact 벡터와 동일) | 단위 테스트 | 비밀값이 LLM 입력·로그·출력에 없음 |
| **M7. LLM 루프 + 클라이언트** | `llm/client.py`(OpenAI-compatible, 환경변수 접속), `llm/loop.py`(tool calling, 상한 없음), system 프롬프트에 작성 지침 | 가짜 LLM(스크립트된 tool_calls)로 테스트 | 가짜 LLM이 번들로 HWPX 생성. LLM 오류 → `LLM_FAILED`(exit 8), 템플릿 대체 없음 |
| **M8. 진입점 `run` + stored_xss 프로필** | 트리거 하나로 수집 → seal → LLM 작성 → `ReportResult`. `profiles/stored_xss.py` | end-to-end(가짜 LLM) | 로컬 vul-web-1 + synthetic 원천으로 보고서 1부 |
| **M9. generic·bola 프로필** | `generic`(미등록 대체), `bola` | 각 프로필 테스트 | 루프·도구·작성기 무수정으로 추가. 미등록 프로필도 보고서 생성 |
| **M10. 라이브 LLM 점검(opt-in)** | 환경변수 있을 때만 실제 엔드포인트로 1회 | 수동/표시 | 기본 테스트는 네트워크·키 없이 가짜 LLM만 사용 |
| **M11. 연동·문서·검증** | main Agent가 CLI를 호출하는 지점·시점을 우리 설계대로 붙인다(Q1/Q5). 환경변수(`DEEPSEEK_*`)·출력 위치만 공유 확인. README. 독립 리뷰 | 호출 연동, README, 리뷰 결과 | end-to-end 동작, 지적 해소 |

---

## 6. 테스트 전략
- **러너:** 스크린샷 도구는 `node --test packages/report/capture/tests/`, Python 부분은 `pytest packages/report/py/tests`.
  manifest에 등록되기 전까지는 CI가 이 모듈을 실행하지 않으므로 커밋 전에 직접 돌린다.
- **LLM은 테스트에서 가짜로 대체한다.** 스크립트된 `tool_calls` 시퀀스를 돌려주는 가짜 클라이언트를 주입한다. 기본 테스트는 **네트워크와 API 키 없이** 돈다. 실제 엔드포인트 호출은 opt-in이다(M10).
- **fixture(모두 synthetic)**
  - 사이트: vul-web-1을 `PORT=0`, 임시 데이터 파일로 직접 띄운다. canary 게시글은 **테스트 준비 단계에서만** 만든다.
  - run 원천: 실제 Node writer(`tests/write_sources.mjs`)로 pentest-db 디스크와 run-store를 만든다. 종류는 stored_xss(confirmed / not_confirmed), bola, 미등록 프로필, failed.
  - casper-db: 임시 DB에 synthetic 사례와 check를 넣는다(테스트 준비 단계에서만).

| 범주 | 검증 |
|---|---|
| **환경 정보 무보유** | 트리거에 없는 경로·URL에 접근하지 않는다. 소스에 기본 경로, 포트가 없다(정적 검사). 환경변수는 LLM 접속 정보(`DEEPSEEK_*`)만, `llm/client.py`에서만 읽는다. 번들과 보고서에 원천 위치가 남지 않는다. ⚠️ `test_boundaries.py`의 네트워크 import·환경변수 금지 정적 검사는 `llm/client.py`를 명시적으로 예외 처리한다(C-4) |
| 수집기 격리 | 수집기 모듈에 `socket`·`urllib`·네트워크 import가 없다. 번들 밖 파일을 열지 않는다. 네트워크는 `llm/` 아래에만 있다 |
| 핵심 3가지 | 지침을 따르는 가짜 LLM이 쓰면 보고서에 취약점·공격 대상·exploit 여부가 들어간다(강제 아님, 지침과 LLM 품질에 의존) |
| LLM 경계 | 가짜 LLM이 번들 밖 읽기·대상 외 접속·원시 XML을 요청하면 도구가 거부한다. LLM 오류 시 `LLM_FAILED`(exit 8)이고 템플릿 대체가 없다. (내용의 사실성은 도구가 강제하지 않는다) |
| 범용성 | 미등록 프로필로 generic 보고서가 나온다. 프로필 추가 시 LLM 루프·도구·작성기 diff가 없다 |
| 수집기 | 원천 전후 해시가 같다(읽기 전용). casper DB가 없으면 `unavailable`로 기록하고 새로 만들지 않는다. run 원천이 없으면 종료 코드 3 |
| capture 샌드박스 | 외부 origin, POST/DELETE, WebSocket이 차단·기록된다. 허용된 세션 전환만 정확히 일치할 때 통과한다. `targetUrl`과 `target.origin`이 다르면 촬영하지 않는다 |
| 번들 무결성 | 봉인 후 파일을 1바이트 바꾸면 그 항목이 빠지고 "무결성 불일치"가 표시된다. SVG나 확장자 위장 이미지는 거부된다 |
| 이스케이프 | payload `<img src=x onerror=…>`, `<script>`, `&`, `]]>`, `|`가 HWPX XML에서 텍스트 노드로 들어간다 |
| 마스킹 | fixture에 심은 `Cookie`, `Set-Cookie`, `Authorization`, `sk-…`, `reasoning_content`가 LLM 입력·도구 로그·출력에 없다. contracts `redact()`와 같은 벡터로 결과가 일치한다 |
| 프롬프트 인젝션 | 수집 자료(payload·대상 페이지)에 "지금까지 지시 무시" 같은 문장을 심어도, **도구 제약** 때문에 금지된 행동(대상 외 접속, 쓰기, 번들 밖 읽기)이 일어나지 않는다. 보고서 내용 오염은 도구로 막지 못하므로 한계로 인정한다 |
| 프레이밍 | 고지 문구, triage 고정 문구, 사진 캡션 문구, `[가상]`, `verifiedByStorage:false`가 완성된 보고서에 있다 |

---

## 7. 미해결 질문과 요청 항목
| # | 질문/요청 | 대상 | 제안 |
|---|---|---|---|
| Q1 | main Agent가 report Agent를 호출하는 방식 | 우리 설계 | ✅ (10-20) 우리가 정한다. finalize 직후 이 모듈의 CLI를 `ReportTrigger` JSON으로 호출(§4.1) |
| Q2 | 출력과 번들을 어디에 둘지(보존이 필요하면 영속 위치) | 파이프라인/통합 담당 | 트리거의 `output.dir`로 받는다. 위치 결정은 호출자 몫이다 |
| Q3 | 실제 파이프라인의 run 결과 원천: pentest-db JSON인가 run-store인가 | 파이프라인 담당 | ✅ 두 드라이버 모두 구현. 실제 파이프라인이 다른 원천을 쓰면 드라이버를 추가 |
| Q4 | 촬영에 필요한 정보(계정 전환 등)를 어디서 얻나 | 우리 설계 | ✅ (10-20) 수집기가 필요하면 찾아서 번들(`hints/capture.json`)에 담는다. 없으면 LLM이 페이지에서 직접 찾는다 |
| Q5 | 트리거 시점 | 우리 설계 | ✅ (10-20) finalize 직후(attack 수행 후), 환경 정리 전. 호출 연동을 우리가 붙이므로 이 순서를 보장한다 |
| Q6 | LLM을 어디까지 쓸지 | 사용자 | ✅ (10-20) 보고서 작성 전체를 LLM Agent가 도구 호출로 수행한다(§3.8) |
| Q7 | HWPX 템플릿(표지, 기관 양식). 기존 CERT 양식이 있는가 | 사용자/팀 | 있으면 범용 목차에 맞춰 쓰고, 없으면 직접 만든다 |
| Q8 | 보고서 단위 | 사용자 | ✅ (10-20) run 1건 = 1부. 월간/다건 집계는 범위 밖 |
| Q10 | 상류가 추가할 취약점 프로필 로드맵 | agent/파이프라인 담당 | 프로필 인터페이스 사전 점검용 |
| Q11 | `target.application`이 사이트를 식별해야 하나 | — | ✅ (10-20) 불필요. 촬영을 LLM이 직접 하므로 사이트 어댑터를 없앴다. `target.origin`만 있으면 된다 |
| Q12 | 심각도 체계 | 사용자 | ✅ (10-20) LLM이 CVSS 3.1 벡터·점수·등급 산출(A안). "LLM 산출" 명시, 상류 severity 병기. **재계산·검증 없음(사용자 결정): LLM이 쓴 값을 그대로 둠** |
| Q13 | 이미지 형식과 보고서 해시 표기 | 사용자 | ✅ (10-20) 이미지는 LLM이 필요에 따라 PNG로 촬영. 보고서 본문에 해시 표기 없음. 해시는 번들 무결성 확인용으로 manifest에만 둠 |
| Q14 | LLM 접속 환경변수를 agent core와 공유(`DEEPSEEK_*`)할지, report 전용 변수를 둘지 | 파이프라인 담당 | ✅ (10-20) 공유. 로컬 LLM 전환 시 `DEEPSEEK_BASE_URL`만 바꾸면 된다 |
| Q15 | LLM 데이터 정책(수집 자료 외부 전송) | 사용자 | ✅ (10-20) 지금은 다루지 않음. 로컬 LLM 전환 예정이고 데이터는 synthetic |
| Q16 | 상한 없음(반복·촬영·시간)으로 인한 비용·무한 루프 위험을 감수할지 | 사용자 | ✅ (10-20) 상한 없음. 필요하면 나중에 안전 상한만 추가 |
