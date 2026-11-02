# report — CA3P 보고서 Agent

취약점 한 건의 점검 결과를 수집해 LLM이 HWPX 보고서 한 부를 작성합니다.
취약점 유형에 따른 프로필 없이 번들의 자료만으로 다양한 취약점의 보고서를 씁니다.
현재 설계는 [`REDESIGN.md`](REDESIGN.md), 보고서 내용·모양은 [`REPORT_SPEC.md`](REPORT_SPEC.md), 최초 설계의 이력은 [`PLAN.md`](PLAN.md)에 있습니다.

## 통합 대시보드

실제 로컬 실습의 최종 검사 JSON을 저장한 뒤 worker가 이 모듈의 `run` CLI를 자동 실행합니다. 범용 검사는 `confirmed` finding마다 `options.findingId`를 전달하며 결과를 `run.reportDocuments.items[]`에 저장합니다. `not_reproduced`·`inconclusive`·`not_tested` finding의 문서는 만들지 않습니다. 기존 단일 검사(`report.finding`)는 run당 한 부이며 상태는 `run.reportDocument`에 저장합니다. 실패해도 원래 검사 결과와 finding은 유지됩니다.

Node 연결부 `index.mjs`는 5분 제한·취소·자식 프로세스 정리·실행 ID·finding ID·증거 ID·산출물 경로·해시·크기를 확인합니다. Python 실행 파일은 `CA3P_REPORT_PYTHON` 또는 `CASPER_DB_PYTHON`으로 지정합니다. 모든 보고서는 모델 호출 비용이 들 수 있습니다.

범용 문서는 `GET /api/runs/<runId>/reports/<artifactId>.hwpx`, 기존 단일 문서는 `GET /api/runs/<runId>/report.hwpx`에서 다운로드합니다. 서버는 실행·finding·artifact 연결과 바이너리 무결성을 확인해 attachment로 반환합니다.

## 구현 현황

- **수집 단계 `collect`** — pentest-db-disk / run-store에서 run을, casper-db에서 과거 사례를, verifier handoff에서 판정·캡처를 읽어 봉인된 ReportInput 번들을 만듭니다(읽기 전용). 보고서가 다룰 finding 한 건은 `run/finding.json`, attack 모듈의 요청·응답은 `run/attack.json`으로 정리합니다.
- **작성 단계 `run`** — LLM(OpenAI-compatible)이 `read_bundle`로 번들을 읽고 `finish_report`로 끝냅니다. LLM은 CWE·CVSS 3.1·설명·재현 절차·PoC·조치·영향을 씁니다. finding ID·판정·증거 ID·verifier 캡처는 `finish_report`가 봉인된 번들 값으로 덮어씁니다. HWPX 렌더링은 `hwpx/writer.py`(python-hwpx)가 맡습니다.

```bash
cd packages/report/py && .venv/bin/python -m ca3p_report run --trigger trigger.json
# 결과: <output.dir>/report/{<보고서>.hwpx, report-model.json, report.md, report.html}, 그리고 ReportResult JSON
```

LLM 접속 정보는 `DEEPSEEK_BASE_URL`·`DEEPSEEK_API_KEY`·`DEEPSEEK_MODEL`에서 읽습니다. 플랫폼 runner는 실행에 쓴 DeepSeek 모델(`run.modelId`)을 그대로 쓰고, 규칙 기반 실행은 설정된 기본 모델을 씁니다. 로컬 LLM으로 실행한 run은 아직 보고서를 만들지 않습니다(외부 API로 보내지 않기 위해). LLM 실패 시 종료 코드 8(`LLM_FAILED`)이며, 봉인된 입력 번들을 보존하고 LLM에 전달하는 파일 뷰에는 자격 증명 마스킹을 적용합니다. 모든 보고서는 사람이 최종 검토합니다.

casper-db의 실행 응답에 `referenceContext`(`casper-reference-1`)가 있으면 수집기는 검토 대기 자료·외부 권고·입력 위치 확인 필요 사항을 `history/casper.json`에 함께 보존합니다. 작성 완료 도구는 봉인된 파일의 해시를 확인하고 해당 검토 정보를 보고서 모델에 직접 반영합니다. 작성자가 생략하거나 다른 승인 상태로 바꾼 값은 사용하지 않습니다. 자료의 등록 상태는 현재 실행의 재현 판정과 별개입니다.

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
    "history": { "kind": "casper-db", "location": "/abs/casper-db/data/cases.sqlite3" },  // 생략하면 none
    "verification": { "kind": "handoff-dir", "location": "/abs/verifications/<probeId>" } // 생략하면 none
  },
  "output": { "dir": "/abs/out/run-1760918400000-abcd1234" }
}
```

범용 `general-assessment/1` 보고서에는 `"options": {"findingId": "finding:<hypothesisId>"}`를 추가해야 합니다. `run-store`의 최종 보고서에 같은 ID의 `confirmed` finding이 정확히 하나 있고, 해당 가설의 confirmed verify 이벤트에 현재 probe 증거가 있어야 수집합니다. 기존 단일 검사에는 `findingId`를 전달하지 않으며 `report.finding`이 있어야 합니다.

| 원천 `kind` | 읽는 방법 | 비고 |
|---|---|---|
| `pentest-db-disk` | `readRun`(packages/adapters/integrations/pentest-db.mjs)과 같은 규칙: `sha256(runId)` 디렉터리, 이벤트 정렬, `report.json` | 심링크와 특수 파일은 읽지 않음. 파일당 5MB 상한 |
| `run-store` | SQLite `?mode=ro`. `runs.state_json`의 report와, runtime 이벤트 중 pentest-db `append` 요청에 담긴 core 이벤트. 범용 모드는 최종 state의 Agent verify 이벤트도 수집 | WAL 모드라 읽기만 해도 빈 `-wal`/`-shm` 파일이 생길 수 있음(DB 내용은 불변) |
| `casper-db` | `CaseStore.get_version`/`get`/`list_checks`. 대상 사례는 run의 `loop.history` 판정 결과에서 꺼냄 | DB가 없으면 `unavailable`로 기록하고 새로 만들지 않음 |
| `handoff-dir` | verifier의 `verification-handoff/1`(`verification.json`, `images/`) | 이미지마다 sha256·크기를 확인. attackId가 선택한 finding의 confirmed probe여야 함 |

출력은 `<output.dir>/bundle/` 아래에 생깁니다.

```
manifest.json          # 파일 해시(sha256:<hex>), 수집기 종류·상태. 원천 위치는 기록하지 않음
run/report.json        # 최종 run 보고서 + storedAt + provenance(verifiedByStorage:false 유지)
run/events.json        # core 이벤트 {stage, iteration, recordedAt, messageId, request, response}
run/finding.json       # 보고서가 다루는 finding 한 건: 원본 finding, 판정, 증거 ID, incomplete
run/attack.json        # attack 모듈의 요청·응답(verifier handoff의 result.attack, 또는 loop.act)
run/verification.json  # verifier 판정·사유와 캡처 목록(handoff가 있을 때)
evidence/images/*.png  # verifier 캡처(handoff가 있을 때)
history/casper.json    # { status, reason?, cases:[{caseId, revision, currentRevision, snapshot, checks}] }
```

- 번들은 한 번만 씁니다. 같은 위치에 다시 수집하면 거부합니다(종료 코드 6).
- 실패하면 번들을 남기지 않습니다.
- 종료 코드: `0` 성공, `2` 트리거 오류, `3` run 없음, `4` 최종 보고서 없음, `5` 원천 데이터 이상, `6` 번들이 이미 있음, `8` LLM 실패
- 결과는 표준출력으로 JSON 한 줄을 냅니다.

## 테스트

```bash
cd packages/report/py && .venv/bin/python -m pytest -q && .venv/bin/ruff check src tests   # Python
node --test packages/report/tests/*.test.mjs                                               # Node runner (저장소 루트에서)
```

- 원천 fixture는 실제 pentest-db 어댑터와 run-store 저장소 코드(`tests/write_sources.mjs`, Node + `node:sqlite`)로 만듭니다. 그래서 저장 규약이 바뀌면 테스트가 깨집니다. Node가 없으면 해당 테스트는 건너뜁니다.
- 작성 단계 테스트는 스크립트된 가짜 LLM을 씁니다. 통합 검증은 유료 API를 호출하지 않습니다.
- `capture/`(Playwright 촬영 sandbox)는 작성 도구에서 빠졌지만 패키지는 남아 있습니다. 정리는 [`REDESIGN.md`](REDESIGN.md) §7을 따릅니다.
