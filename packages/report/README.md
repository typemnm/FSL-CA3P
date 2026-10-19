# report — CA3P 보고서 Agent

main Agent가 트리거하면 기존 모듈들의 실행 결과를 수집하고, 대상을 직접 촬영해 HWPX 보고서를 만드는 Agent입니다.
설계와 결정 사항은 [`PLAN.md`](PLAN.md)에 있습니다.

> 현재 구현된 범위는 **수집 단계**(`collect`)뿐입니다. 촬영, HWPX 렌더링, 전체 실행(`run`)은 아직 없습니다.

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

| 원천 `kind` | 읽는 방법 | 비고 |
|---|---|---|
| `pentest-db-disk` | `readRun`(packages/adapters/integrations/pentest-db.mjs)과 같은 규칙: `sha256(runId)` 디렉터리, 이벤트 정렬, `report.json` | 심링크와 특수 파일은 읽지 않음. 파일당 5MB 상한 |
| `run-store` | SQLite `?mode=ro`. `runs.state_json`의 report와, runtime 이벤트 중 pentest-db `append` 요청에 담긴 core 이벤트 | WAL 모드라 읽기만 해도 빈 `-wal`/`-shm` 파일이 생길 수 있음(DB 내용은 불변) |
| `casper-db` | `CaseStore.get_version`/`get`/`list_checks`. 대상 사례는 run의 `loop.history` 판정 결과에서 꺼냄 | DB가 없으면 `unavailable`로 기록하고 새로 만들지 않음 |

출력은 `<output.dir>/bundle/` 아래에 생깁니다.

```
manifest.json          # 파일 해시(sha256:<hex>), 수집기 종류·상태. 원천 위치는 기록하지 않음
run/report.json        # 최종 run 보고서 + storedAt + provenance(verifiedByStorage:false 유지)
run/events.json        # core 이벤트 {stage, iteration, recordedAt, messageId, request, response}
history/casper.json    # { status, reason?, cases:[{caseId, revision, currentRevision, snapshot, checks}] }
```

- 번들은 한 번만 씁니다. 같은 위치에 다시 수집하면 거부합니다(종료 코드 6).
- 실패하면 번들을 남기지 않습니다.
- 종료 코드: `0` 성공, `2` 트리거 오류, `3` run 없음, `4` 최종 보고서 없음, `5` 원천 데이터 이상, `6` 번들이 이미 있음
- 결과는 표준출력으로 JSON 한 줄을 냅니다.

## 테스트

```bash
cd packages/report/py && .venv/bin/python -m pytest -q && .venv/bin/ruff check src tests
```

- 원천 fixture는 실제 pentest-db 어댑터와 run-store 저장소 코드(`tests/write_sources.mjs`, Node + `node:sqlite`)로 만듭니다. 그래서 저장 규약이 바뀌면 테스트가 깨집니다. Node가 없으면 해당 테스트는 건너뜁니다.
- 이 모듈은 아직 `integration-manifest.json`에 등록되지 않았습니다. CI가 실행하지 않으므로 직접 돌려야 합니다. 등록은 통합 담당자가 합니다.
