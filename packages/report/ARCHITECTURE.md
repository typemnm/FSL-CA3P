# Report Agent — 현재 구현과 플랫폼 연동

취약점 한 건의 검사 결과를 읽기 전용으로 수집하고 LLM이 HWPX 보고서 한 부를 작성한다.
범용 검사는 확정 finding마다, 기존 단일 검사는 `report.finding` 한 건으로 같은 경로를 탄다.
현재 설계는 [REDESIGN.md](REDESIGN.md), 최초 설계의 이력은 [PLAN.md](PLAN.md)에 보존한다.

## 실행 흐름

```mermaid
flowchart TB
  CORE[Agent 검사와 최종 JSON] --> WORKER[apps/worker/worker.mjs]
  WORKER -->|JSON 먼저 저장| STORE[(run-store SQLite)]
  WORKER -->|finding마다 호출| RUNNER[packages/report/index.mjs]
  RUNNER -->|ReportTrigger · findingId · 실행 모델| CLI[Python ca3p_report run]
  STORE -. 읽기 전용 .-> COLLECT[collect: finding · attack · verification · history]
  HISTORY[(casper-db)] -. 읽기 전용 .-> COLLECT
  HANDOFF[(verifier handoff)] -. 읽기 전용 .-> COLLECT
  CLI --> COLLECT --> BUNDLE[봉인 ReportInput 번들]
  BUNDLE -->|마스킹한 읽기 뷰| LLM[LLM 도구 호출 루프]
  LLM --> FINISH[finish_report: 판정·ID·증거·캡처를 번들 값으로 고정]
  FINISH --> FILES[HWPX · report-model.json · report.md · report.html]
  FILES -->|식별자·증거·경계·해시 검증| RUNNER
  RUNNER -->|검증된 bytes| ARTIFACT[run-store binary artifact]
  ARTIFACT --> API[인증된 HWPX 다운로드 API]
  API --> UI[대시보드 리포트 화면]
```

worker는 실제 실습의 완료·실패 보고서를 저장한 뒤 문서 생성을 시작한다. 범용 검사는
`confirmed` finding을 하나씩 순서대로 처리하고 나머지 판정에는 문서를 만들지 않는다. 문서 생성 실패는
검사의 finding이나 완료·실패 결과를 변경하지 않는다. 코어 fixture와 중지된 실행은 생성을 건너뛴다.
보고서용 LLM 설정이 없거나 실행 모델이 로컬 LLM이면 `unavailable`로 표시한다.

## 계층과 책임

| 경로 | 구현된 책임 |
| --- | --- |
| `apps/worker/worker.mjs` | 최종 검사 JSON 저장, 자동 생성 호출, 상태 발행, binary artifact 저장, 게시판 수명 관리 |
| `packages/report/index.mjs` | 범용 finding 선택 검증, 실행 모델로 DeepSeek 설정 해석, Python 실행, 취소·시간·출력 제한, 산출물 검증 |
| `py/src/ca3p_report/trigger.py` | run ID·선택 finding ID·원천 종류·절대 경로 검증, 원천과 출력 위치의 겹침 거부 |
| `py/src/ca3p_report/collect/` | run·과거 사례·verifier handoff 수집, finding 한 건 정규화(`finding.py`), 범용 확정 finding과 현재 검증 증거 선택(`general.py`), SHA-256 manifest와 번들 봉인 |
| `py/src/ca3p_report/llm/` | OpenAI-compatible 클라이언트, 도구 호출 루프, 읽기 뷰와 출력 모델 마스킹, 검증된 필드 고정 |
| `py/src/ca3p_report/hwpx/` | 파일명 정규화, [REPORT_SPEC.md](REPORT_SPEC.md) 레이아웃을 python-hwpx 서식 API로 HWPX·Markdown·HTML 렌더링(캡처 PNG 포함) |
| `packages/run-store/index.mjs` | `hwpx-report` binary artifact의 bytes·해시·크기·파일명·선택 finding ID 보관 |
| `apps/api/server.mjs` | 실행과 artifact의 연결·무결성 검사 후 인증된 사용자에게 다운로드 제공 |
| `agent-dashboard/dist/` | 문서 상태·과금 안내 표시, 준비된 실행의 HWPX 다운로드 |

## 입력과 출력

Python CLI는 파일 또는 stdin의 `ReportTrigger` JSON을 받는다. 필수 입력은
`schemaVersion: "report-trigger-1.0"`, `runId`, `sources.run{kind,location}`, `output.dir`이다.
범용 검사에서는 `options.findingId`도 필수이며 기존 단일 검사에서는 허용하지 않는다.
`sources.history`와 `sources.verification`은 생략하면 `none`이다.

| 명령 | 결과와 호출 범위 |
| --- | --- |
| `python -m ca3p_report collect --trigger ...` | LLM 호출 없이 `bundle/`만 생성 |
| `python -m ca3p_report run --trigger ...` | 새 번들 수집 후 LLM 작성, 문서 생성 |

`run`은 기존 번들에서 재개하는 명령이 아니다. 같은 출력 위치에 `collect` 후 `run`을 호출하면
이미 봉인된 번들이 있어 거부된다. 플랫폼 runner는 실행별·시도별 별도 출력 위치를 만든다.

| 수집 원천 | 읽는 내용과 경계 |
| --- | --- |
| `pentest-db-disk` | `sha256(runId)` 아래 최종 보고서와 정렬된 이벤트. run 하위 심링크·특수 파일 거부, 파일당 5MB 제한 |
| `run-store` | SQLite `mode=ro`, `runs.state_json`의 report, sequence 순서의 승인된 append·legacy-import 이벤트. 범용 검증 이벤트는 최종 state의 Agent 이벤트에서 수집 |
| `casper-db` | `loop.history`가 참조한 당시 revision snapshot·현재 revision·재점검 checks. 없거나 읽지 못하면 `unavailable` |
| `handoff-dir` | verifier 판정·사유·캡처. 이미지 해시·크기 확인, attackId가 선택 finding의 confirmed probe인지 확인 |

원천 DB의 내용은 변경하지 않는다. SQLite WAL을 읽을 때 빈 `-wal`/`-shm` 파일은 생길 수 있다.
번들에는 `manifest.json`, `run/report.json`, `run/events.json`, `run/finding.json`, `run/attack.json`,
`history/casper.json`을 저장하고, handoff가 있으면 `run/verification.json`과 `evidence/images/`도 봉인한다.
`run/finding.json`에는 원본 finding, 판정, 보고서가 인용할 증거 ID, 점검 미완료 여부를 기록한다.
수집분의 해시와 수집기 상태를 봉인하고 원천 경로는 manifest에 기록하지 않는다.

작성 결과는 `report/<이름>.hwpx`, `report/report-model.json`, `report/report.md`, `report/report.html`과
한 줄의 `report-result-1.0` JSON이다. 결과와 ReportModel은 `findingId`/`sourceFindingId`와 증거 ID를 포함한다.
runner는 CLI 응답과 ReportModel의 run ID·finding ID·판정·증거 ID, 파일명·출력 경계,
파일 크기·SHA-256·ZIP signature를 검사하고 HWPX bytes를 별도 artifact로 보관한다.

## 플랫폼 상태와 다운로드

`run.report`는 원래 검사 JSON이다. 범용 검사 문서 상태는 `run.reportDocuments.items[]`에 finding별로,
기존 단일 검사 문서 상태는 `run.reportDocument`에 저장한다.

| 상태 | 의미 |
| --- | --- |
| `generating` | 문서 작성 중 |
| `ready` | `artifactId`, `filename`이 있는 다운로드 가능 상태 |
| `failed` | 모델·실행 환경·시간 제한·산출물 검사 등의 실패 또는 문서 생성 취소 |
| `unavailable` | 보고서용 LLM 설정 없음·오류, 또는 로컬 LLM 실행 |
| `skipped` | fixture·중지·최종 검사 보고서 부재로 생성 생략 |

상태에는 안전한 메시지·오류 코드·시각을 담으며 로컬 출력 경로나 API 키를 담지 않는다.
범용 문서는 `GET /api/runs/:runId/reports/:artifactId.hwpx`, 기존 단일 문서는
`GET /api/runs/:runId/report.hwpx`에서 다운로드한다. 로그인한 viewer도 이용할 수 있다. API는 해당
실행의 준비된 `hwpx-report` artifact와 범용 finding 연결만 허용하고 bytes의 크기·해시를 다시 확인한다.

## 실행·보호 경계와 한계

- LLM은 CWE·CVSS 3.1·설명·재현 절차·PoC·조치·영향을 쓴다. finding ID·판정·실행 상태·증거 ID·캡처
  이미지는 `finish_report`가 봉인된 번들 값으로 덮어쓰므로 모델이 바꿀 수 없다. 캡처는 verifier handoff의
  봉인된 PNG만 실리며 모델이 만든 ref는 버린다.
- Node runner는 실행 모델이 DeepSeek 모델이면 그 모델을, 규칙 기반 실행이면 설정된 기본 모델을
  `agent/src/deepseek-config.js`로 해석해 Python에 전달한다. 그 밖의 모델(로컬 LLM)은 외부 API로
  보내지 않도록 거부한다. 직접 CLI 실행에는 `DEEPSEEK_BASE_URL`, `DEEPSEEK_API_KEY`, `DEEPSEEK_MODEL`이 필요하다.
- 플랫폼 runner는 기본 5분, 합산 stdout/stderr 1MB, HWPX 20MB 제한과 AbortSignal 취소를 적용한다.
  Python 실행 파일은 `CA3P_REPORT_PYTHON`, `CASPER_DB_PYTHON`, OS 기본 Python 순으로 선택한다.
  Python의 개별 모델 요청 제한은 300초이며 도구 호출 루프에는 반복 상한이 없다.
- `read_bundle`은 원본 봉인 bytes를 유지하면서 JSON 구조·텍스트를 마스킹한 뷰를 모델에 보낸다.
  `finish_report`도 출력 모델을 마스킹한다. 모델의 원시 XML 삽입 대신 text-node API를 사용한다.
- 취약점 판정의 사실성과 CVSS의 의미적 정확성은 검증하지 않는다. 모델 실패 시 템플릿으로 대체하지 않으며
  사람이 초안을 최종 검토한다. 과거 사례 대조는 단일 검사의 `loop.history`에만 있다(범용 대조는 백로그).
- 보고서는 finding 한 건당 한 부다. 월간·다건 집계와 기관 표지·로고 양식은 별도 후속 작업이다.

## 검증 범위

`report`는 integration manifest의 활성 모듈이며 CI는 Node runner·capture 테스트와 Python 테스트를
실행한다. 스크립트된 가짜 모델로 수집·경로·마스킹·검증 필드 고정·렌더링·취소·실패·다운로드를 검사한다.
`tests/integration.test.mjs`는 loopback 가짜 HTTP 모델 2턴으로 실제 Python CLI와 HWPX writer를 실행하고,
ZIP·XML·한국어·escaping, binary 저장, viewer 다운로드, DB 재오픈 후 동일 bytes를 검증한다.
유료 live LLM의 보고서 품질을 검증한 결과는 이 문서에 포함하지 않는다.
