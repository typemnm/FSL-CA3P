"""Read a run from the run-store SQLite database (packages/run-store).

run-store has no Python API and `createRunRepository()` runs DDL on open, so this driver
opens the file read-only and only SELECTs. The runtime records every gateway exchange; the
core's own events are the payloads of pentest-db `append` requests, which carry exactly the
{stage, request, response} records that the pentest-db disk layout stores.

run-store uses WAL mode. A read-only connection still needs the WAL index, so SQLite may
leave empty `-wal`/`-shm` sidecar files next to the database; the database bytes are never
changed. `immutable=1` would avoid the sidecars but would also skip writes the worker has not
checkpointed yet, and this agent runs right after finalize, so it is not used.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .model import CollectError, RunRecord, StoredEvent

DRIVER = "run-store"
SUPPORTED_USER_VERSION = 1


def _load(value: str | None, what: str) -> object:
    if value is None:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise CollectError(f"run-store {what} is not valid JSON") from exc


def _structured(event: object) -> bool:
    return (
        isinstance(event, dict)
        and isinstance(event.get("stage"), str)
        and isinstance(event.get("request"), dict)
        and isinstance(event.get("response"), dict)
    )


def _legacy_event(runtime_event: dict) -> StoredEvent | None:
    # importLegacyRun stores each pentest-db record's inner event as
    # {...event, sequence, provenance:'legacy-import'}; iteration and time were not kept.
    if runtime_event.get("provenance") != "legacy-import" or not _structured(runtime_event):
        return None
    return StoredEvent(
        stage=runtime_event["stage"],
        iteration=None,
        recorded_at=None,
        message_id=None,
        request=runtime_event["request"],
        response=runtime_event["response"],
    )


def _stored(runtime_event: dict) -> bool:
    """The append reached pentest-db and was acknowledged. Failed exchanges are also recorded
    by the runtime (type 'error', module.error response) but were never stored."""
    response = runtime_event.get("response")
    payload = response.get("payload") if isinstance(response, dict) else None
    return (
        runtime_event.get("type") != "error"
        and isinstance(response, dict)
        and response.get("type") == "storage.appended"
        and isinstance(payload, dict)
        and payload.get("ok") is True
    )


def _core_event(runtime_event: dict) -> StoredEvent | None:
    if (legacy := _legacy_event(runtime_event)) is not None:
        return legacy
    request = runtime_event.get("request")
    if not isinstance(request, dict) or request.get("receiver") not in {"casper-db", "pentest-db"}:
        return None
    payload = request.get("payload")
    if not isinstance(payload, dict) or payload.get("operation") != "append":
        return None
    if not _stored(runtime_event):
        return None
    event = payload.get("event")
    if not _structured(event):
        raise CollectError("run-store append request has no structured event")
    return StoredEvent(
        stage=event["stage"],
        iteration=request.get("iteration"),
        recorded_at=runtime_event.get("time"),
        message_id=request.get("messageId"),
        request=event["request"],
        response=event["response"],
    )


def read_run(db_path: Path, run_id: str) -> RunRecord | None:
    if not db_path.is_file():
        raise CollectError("run-store database not found")
    try:
        connection = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error as exc:
        raise CollectError("run-store database cannot be opened") from exc
    try:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version != SUPPORTED_USER_VERSION:
            raise CollectError(f"unsupported run-store schema version: {version}")
        row = connection.execute(
            "SELECT state_json, updated_at FROM runs WHERE id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return None
        rows = connection.execute(
            "SELECT event_json FROM run_events WHERE run_id = ? ORDER BY sequence", (run_id,)
        ).fetchall()
    except sqlite3.Error as exc:
        # The class name only: sqlite messages can name files.
        raise CollectError(f"run-store query failed: {type(exc).__name__}") from exc
    finally:
        connection.close()
    state = _load(row[0], "state")
    if not isinstance(state, dict) or state.get("id") != run_id:
        raise CollectError("run-store state does not match the requested runId")
    report = state.get("report")
    if report is not None and (not isinstance(report, dict) or report.get("runId") != run_id):
        raise CollectError("run-store report does not match the requested runId")
    events = []
    for (value,) in rows:
        runtime_event = _load(value, "event")
        if isinstance(runtime_event, dict) and (event := _core_event(runtime_event)):
            events.append(event)
    return RunRecord(
        run_id=run_id,
        driver=DRIVER,
        report=report,
        stored_at=row[1],
        provenance={
            "source": "run-store",
            "runStatus": state.get("status"),
            "verifiedByStorage": False,
        },
        events=events,
    )
