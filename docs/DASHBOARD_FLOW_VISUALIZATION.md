# 점검 흐름 시각화 — 모듈 통신 분석과 기록 수집 방식

공격 작업공간(`#workspace/attack`)의 **점검 흐름** 패널은 에이전트가 모듈과 데이터를 주고받으며 점검하고, 취약점을 확인하고, 보고서를 만드는 과정을 모듈 그래프와 **활동 요약**으로 보여준다. 이 문서는 (1) 메인 에이전트와 통신하는 모듈, (2) 각 통신 방식, (3) 모듈을 바꾸지 않고 그 통신 기록을 가져오는 방법을 정리한다.

## 1. 결론

- 메인 에이전트(`agent/src/general-assessment.js`의 `runGeneralAssessment`)는 worker 프로세스 안에서 **포트 객체**(observer · planner · policy · approval · executor · verifier)를 호출한다. 각 호출이 끝날 때 `onEvent`로 단계 이벤트를 내보내고, runtime이 이를 `run.events`에 붙인다.
- worker는 이 상태를 run-store(SQLite `run_events`, `model_calls`, `artifacts`)에 저장하고, API는 같은 상태를 `/api/events`(SSE) · `/api/state`(polling)로 대시보드에 이미 보내고 있다.
- 따라서 **새 수집 코드 없이** 대시보드가 이미 받는 run 상태를 읽기 전용으로 투영해 시각화한다. 에이전트 · 어댑터 · worker · API · run-store 코드는 바꾸지 않았다.

## 2. 메인 에이전트와 통신하는 모듈

| 모듈 (그래프 노드) | 코드 위치 | 통신 방식 | 주고받는 데이터 | 남는 기록 (대시보드 수신 필드) |
| --- | --- | --- | --- | --- |
| 대시보드 · API | `agent-dashboard/dist`, `apps/api/server.mjs` | HTTP + SSE `/api/events`, `POST /api/runs/:id/approvals/:approvalId` | 실행 시작 · 중지, 사람 승인 | `approval.requested` · `approval.resolved` 이벤트, `run.pendingApproval` |
| application → worker | `apps/application/run-service.mjs`, `apps/worker/worker.mjs` | `child_process.fork` IPC (`wake`, `cancel`, `approval-decision`, `shutdown` ↔ `state`, `approval-result`) | 작업 lease, 취소, 승인 결정 | run 상태 전이(`queued` → `preparing` → `running` → 종료) |
| Run Store | `packages/run-store/index.mjs` | SQLite(WAL) 트랜잭션 — `saveState`, `recordModelCall`, `writeArtifact`, `writeBinaryArtifact` | 이벤트 · 모델 호출 메타데이터 · 산출물 | `run.events[]`, `run.modelCalls[]`, `run.artifacts[]` |
| LLM (planner) | `agent/src/general-model-planner.js`, `packages/models/local-planner.mjs` | DeepSeek HTTPS 또는 로컬 LLM HTTP | 관찰 요약 → 가설 · probe 제안 | `plan` · `plan_rejected` 이벤트, `run.modelCalls[]`(모델 · 토큰 · 지연, iteration 단위) |
| Casper DB | `apps/application/case-snapshot.mjs`, `packages/adapters/integrations/knowledge-db.mjs` | 실행 전 고정 snapshot 파일 + 읽기 전용 카탈로그 조회 | 과거 사례 · 권고 · 템플릿 카탈로그 | `observe` 이벤트의 `evidenceSummaries[].kind` = `historical-reference` / `draft-advisory` |
| Guardrail (policy) | `general-runtime.mjs`의 `policy.authorize`, attack-tool daemon의 principal `authorize` | 프로세스 내 함수 호출 | probe 허용 / 차단과 사유 | `policy` 이벤트(`status` = `allowed`/`blocked`, `reason`) |
| Attack Tool | `attack-tool/`, `packages/adapters/integrations/attack-tool.mjs` | loopback HTTP JSON-RPC daemon(`execute_probe`), 카테고리별 인증 client | 템플릿 요청 → guardrail 재검사 → 대상 HTTP → 응답 투영 | `execute` 이벤트(`tool` = `execute_attack_template`, evidence ID), 종료 후 `report.attackTool.metrics` |
| Web Parser | `web-parser/`, `packages/adapters/integrations/web-parser.mjs` | Playwright 브라우저 | 페이지 구조 · 기술 · 경로 · 폼 수집 | `execute`(`tool` = `web_info`) + `web_info.collected` 이벤트, `web-info` 산출물 |
| 점검 대상 | 실습 게시판 · vul-web2 · 외부 URL | HTTP (`http_get`, 템플릿 실행, 브라우저 관찰) | 요청 · 응답 | `observe` · `execute` 이벤트, `run.targetContacted` |
| Verifier | `packages/verifier/index.mjs` | 프로세스 내 호출 + DeepSeek(AI 판정) + 읽기 전용 브라우저 | 실행 기록 → 판정 | `verify` 이벤트(`confirmed` / `not_reproduced` / `inconclusive`) |
| Report Agent | `packages/report/index.mjs` → `packages/report/py` | Python 자식 프로세스(stdin/stdout), run-store 읽기 전용, Chromium 촬영 | 확정 finding → HWPX · 미리보기 | `run.reportDocuments.items[]` 상태 전이, `hwpx-report` · `report-preview*` · `run-report` 산출물 |

## 3. 통신 기록을 가져오는 방법

| 방법 | 모듈 영향 | 채택 |
| --- | --- | --- |
| **A. 기존 SSE/polling 상태 구독** — 대시보드가 이미 받는 `run`을 `flow-model.js`의 순수 함수로 투영 | 없음 | **채택** |
| B. `GET /api/runs/:id/events?after=<sequence>` 커서 조회 | 없음 | 저장된 실행을 다른 도구로 내보낼 때 사용 가능 |
| C. run-store SQLite 읽기 전용 조회(`run_events`, `model_calls`, `artifacts`) | 없음 (WAL이므로 읽기 전용 연결은 worker를 막지 않음) | 오프라인 분석 · 재생용 |
| D. 어댑터 래핑 · 포트 프록시로 호출마다 별도 로그 송출 | 어댑터 · runtime 수정 필요 | 비채택 |

A는 서버가 이미 `redact()`를 거친 상태만 받으므로 비밀값 처리도 기존 경로를 그대로 따른다. 활동 ID는 저장 이벤트 ID · 산출물 ID에서 만들기 때문에 새로고침 · 재연결 후에도 같은 항목을 같은 ID로 다시 만든다. 화면은 이전에 본 ID와 비교해 **새로 도착한 활동만** 점으로 움직인다.

### 기록이 단계 단위로만 남는 구간

다음 통신은 개별 프레임이 저장되지 않아 그래프는 이벤트에서 경로를 **추정**한다. 판정에는 영향을 주지 않는다.

- attack-tool daemon 내부 JSON-RPC 프레임과 daemon 안의 guardrail 재검사: `execute` 이벤트 하나로 `Agent → Attack Tool → Guardrail → Attack Tool → 대상 → Attack Tool → Agent` 경로를 그린다.
- Verifier의 모델 호출: `verify` 이벤트에 증거가 있으면 `Verifier → LLM` 구간을 함께 그린다. 호출 메타데이터는 저장되지 않는다.
- Report Agent의 Python 내부 모델 호출 · Chromium 촬영: `reportDocuments` 항목의 `generating` → `ready`/`failed` 전이만 보인다.
- Casper DB snapshot 준비는 실행 생성 시 application에서 일어난다. 그래프에는 `observe` 증거에 과거 사례가 있을 때 `Agent ↔ Casper DB`로 나타난다.

더 세밀한 기록이 필요하면 모듈이 아니라 **worker가 이미 runtime에 넘기는 hook**(`onModelCall`, `beforeProbe`/`afterProbe`, `onWebInfo`)에서 run-store로 추가 기록하는 방법이 가장 영향이 작다.

## 4. 화면 동작

- **그래프**: 11개 노드와 16개 링크. 링크에 마우스를 올리면 통신 채널(HTTPS, JSON-RPC, IPC 등)을 보여준다. 노드 배지는 그 노드를 거친 활동 수다.
- **점**: 새 활동마다 경로를 따라 이동한다. 색은 데이터 전달(민트) · 허용/확인(초록) · 차단/보류(호박색) · 실패(주황) · 산출물(보라)이다. 이벤트가 몰리면 속도를 높이고, `prefers-reduced-motion`에서는 점 대신 노드만 강조한다.
- **활동 요약**: 최신 순 150건. 이벤트 항목을 누르면 아래 Trace inspector에서 해당 이벤트의 요청 · 응답을 연다. 노드를 누르면 그 모듈을 거친 활동만 남긴다.
- **산출물**: 웹 정보 JSON, 점검 결과 JSON, HWPX 보고서를 보라색 항목과 `산출물` 표시로 구분하고, 실행 중 새로 생기면 `NEW` 표시와 강조를 90초 동안 유지한다. 항목이나 상단의 산출물 버튼을 누르면 **보고서 화면의 해당 위치로 이동해 강조**한다. HWPX와 웹 정보 JSON은 항목에서 바로 내려받을 수 있다. 다른 화면에 있을 때 새 산출물이 생기면 알림을 띄운다.
- **흐름 재생**: 저장된 실행을 포함해 현재 실행의 전체 흐름을 처음부터 다시 움직인다.

## 5. 파일과 검증

- `agent-dashboard/dist/flow-model.js` — 노드 · 링크 정의와 run → 활동 투영(순수 함수)
- `agent-dashboard/dist/flow-view.js` — SVG 그래프, 점 애니메이션, 활동 요약, 산출물 이동
- `agent-dashboard/dist/app.js` — 패널 연결, 산출물 위치 이동(`data-report-finding`, `data-report-anchor`), 이벤트 선택
- `agent-dashboard/tests/flow-model.test.mjs` — 투영 · 산출물 · ID 안정성 · 실패 입력 · 경로 검증
