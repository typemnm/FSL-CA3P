# report — CA3P 보고서 Agent

main Agent가 트리거하면 기존 모듈들의 실행 결과를 수집해 HWPX 보고서를 만듭니다.
범용 검사는 확인된 finding마다 문서 한 개를 생성하며, 기존 단일 취약점 검사는 LLM 작성 경로를 유지합니다.
설계 결정의 이력은 [`PLAN.md`](PLAN.md)에 있습니다.

## 통합 대시보드

실제 로컬 실습의 최종 검사 JSON을 저장한 뒤 worker가 이 모듈의 `run` CLI를 자동 실행합니다. 범용 검사는 `confirmed` finding마다 `options.findingId`를 전달하며 결과를 `run.reportDocuments.items[]`에 저장합니다. `not_reproduced`·`inconclusive`·`not_tested` finding의 문서는 만들지 않습니다. 기존 단일 검사 상태는 `run.reportDocument`에 저장합니다. 실패해도 원래 검사 결과와 finding은 유지됩니다.

Node 연결부 `index.mjs`는 180초 제한·취소·자식 프로세스 정리·실행 ID·선택 finding ID·산출물 경로·해시·크기를 확인합니다. Python 실행 파일은 `CA3P_REPORT_PYTHON` 또는 `CASPER_DB_PYTHON`으로 지정합니다. 범용 검사는 결정론적 작성 경로라 DeepSeek 설정이나 모델 호출이 필요하지 않습니다. 기존 단일 취약점 검사에는 모델 설정과 호출 비용이 필요할 수 있습니다.

범용 문서는 `GET /api/runs/<runId>/reports/<artifactId>.hwpx`, 기존 단일 문서는 `GET /api/runs/<runId>/report.hwpx`에서 다운로드합니다. 서버는 실행·finding·artifact 연결과 바이너리 무결성을 확인해 attachment로 반환합니다.

## 구현 현황

- **수집 단계 `collect`** — pentest-db-disk / run-store에서 run을, casper-db에서 과거 사례를 읽고, 파서 보고서에서 촬영 힌트를 뽑아 봉인된 ReportInput 번들을 만듭니다(읽기 전용).
- **범용 작성 단계 `run`** — 봉인된 `run/selection.json`에서 확정 finding 한 건과 현재 probe의 검증 증거를 읽어 ReportModel을 결정론적으로 만듭니다. 없는 CWE·CVSS·재현 요청·조치 방안은 추정하지 않습니다. 실패한 실행에서 이미 확정된 finding은 상세 결과와 점검 미완료 표시를 함께 렌더링합니다.
- **기존 작성 단계 `run`** — LLM(OpenAI-compatible, `DEEPSEEK_*` 환경변수)이 도구(`read_bundle`, `capture_screenshot`, `finish_report`)를 호출합니다. 촬영은 `packages/report/capture/`의 Node 샌드박스가, HWPX 렌더링은 `hwpx/writer.py`(python-hwpx)가 맡습니다.

```bash
cd packages/report/py && .venv/bin/python -m ca3p_report run --trigger trigger.json
# 결과: <output.dir>/report/{<보고서>.hwpx, report-model.json, report.md}, 그리고 ReportResult JSON
```

기존 단일 검사에서 LLM 접속 정보는 agent core와 공유하는 `DEEPSEEK_BASE_URL`·`DEEPSEEK_API_KEY`·`DEEPSEEK_MODEL`에서 읽습니다. 범용 선택 모드는 이 환경변수가 필요하지 않습니다. 모든 보고서는 사람이 최종 검토합니다. 기존 경로에서 LLM 실패 시 종료 코드 8(`LLM_FAILED`)이며, 봉인된 입력 번들을 보존하고 LLM에 전달하는 파일 뷰에는 자격 증명 마스킹을 적용합니다.

casper-db의 실행 응답에 `referenceContext`(`casper-reference-1`)가 있으면 수집기는 검토 대기 자료·외부 권고·입력 위치 확인 필요 사항을 `history/casper.json`에 함께 보존합니다. 작성 완료 도구는 봉인된 파일의 해시를 확인하고 해당 검토 정보를 보고서 모델에 직접 반영합니다. 작성자가 생략하거나 다른 승인 상태로 바꾼 값은 사용하지 않습니다. HWPX·Markdown·JSON에 원문 위치, 후보와 보완값, 누락·미확정 필드, 외부 권고의 대상 적용 여부가 포함됩니다. 자료의 등록 상태는 현재 실행의 재현 판정과 별개입니다.

## 수집 단계

트리거(`ReportTrigger`) 하나를 받아 결과 원천을 **읽기 전용으로** 읽고, 봉인된 ReportInput 번들을 만듭니다.
Agent는 기본 경로나 환경변수를 갖고 있지 않습니다. 원천 위치는 모두 트리거로 받습니다.

```bash
cd packages/report/py
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -e '.[dev]' -e ../../../casper-db   # casper-db: collect-history용
.venv/bin/python -m ca3p_report collect --trigger trigger.json              # 또는 --trigger - (stdin)
```

```jsonc
{
  "schemaVersion": "report-trigger-1.0",
  "runId": "run-1760918400000-abcd1234",
  "sources": {
    "run":     { "kind": "pentest-db-disk", "location": "/abs/reports/pentest-db-runs" },  // 또는 run-store + runs.sqlite 경로
    "history": { "kind": "casper-db", "location": "/abs/casper-db/data/cases.sqlite3" }   // 생략하면 none
  },
  "output": { "dir": "/abs/out/run-1760918400000-abcd1234" }
}
```

범용 `general-assessment/1` 보고서에는 `"options": {"findingId": "finding:<hypothesisId>"}`를 추가해야 합니다. `run-store`의 최종 보고서에 같은 ID의 `confirmed` finding이 정확히 하나 있고, 해당 가설의 confirmed verify 이벤트에 현재 probe 증거가 있어야 수집합니다. 기존 단일 검사에는 `findingId`를 전달하지 않습니다.

| 원천 `kind` | 읽는 방법 | 비고 |
|---|---|---|
| `pentest-db-disk` | `readRun`(packages/adapters/integrations/pentest-db.mjs)과 같은 규칙: `sha256(runId)` 디렉터리, 이벤트 정렬, `report.json` | 심링크와 특수 파일은 읽지 않음. 파일당 5MB 상한 |
| `run-store` | SQLite `?mode=ro`. `runs.state_json`의 report와, runtime 이벤트 중 pentest-db `append` 요청에 담긴 core 이벤트. 범용 모드는 최종 state의 Agent verify 이벤트도 수집 | WAL 모드라 읽기만 해도 빈 `-wal`/`-shm` 파일이 생길 수 있음(DB 내용은 불변) |
| `casper-db` | `CaseStore.get_version`/`get`/`list_checks`. 대상 사례는 run의 `loop.history` 판정 결과에서 꺼냄 | DB가 없으면 `unavailable`로 기록하고 새로 만들지 않음 |

출력은 `<output.dir>/bundle/` 아래에 생깁니다.

```
manifest.json          # 파일 해시(sha256:<hex>), 수집기 종류·상태. 원천 위치는 기록하지 않음
run/report.json        # 최종 run 보고서 + storedAt + provenance(verifiedByStorage:false 유지)
run/events.json        # core 이벤트 {stage, iteration, recordedAt, messageId, request, response}
run/selection.json     # 범용 선택 시 원본 finding ID, 확정 probe, 현재 검증 증거(선택적)
history/casper.json    # { status, reason?, cases:[{caseId, revision, currentRevision, snapshot, checks}] }
```

- 번들은 한 번만 씁니다. 같은 위치에 다시 수집하면 거부합니다(종료 코드 6).
- 실패하면 번들을 남기지 않습니다.
- 종료 코드: `0` 성공, `2` 트리거 오류, `3` run 없음, `4` 최종 보고서 없음, `5` 원천 데이터 이상, `6` 번들이 이미 있음
- 결과는 표준출력으로 JSON 한 줄을 냅니다.

## 테스트

```bash
cd packages/report/py && .venv/bin/python -m pytest -q && .venv/bin/ruff check src tests   # Python
cd packages/report/capture && npm install && node --test                                   # Node 촬영 도구
```

- 원천 fixture는 실제 pentest-db 어댑터와 run-store 저장소 코드(`tests/write_sources.mjs`, Node + `node:sqlite`)로 만듭니다. 그래서 저장 규약이 바뀌면 테스트가 깨집니다. Node가 없으면 해당 테스트는 건너뜁니다.
- 이 모듈은 `integration-manifest.json`에 활성 모듈로 등록됐습니다. 루트 `npm run verify`는 Node 연결부·촬영 sandbox와 Python 수집·작성 테스트를 모두 실행합니다. 가짜 모델을 사용하므로 통합 검증은 유료 API를 호출하지 않습니다.
