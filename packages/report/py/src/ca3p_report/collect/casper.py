"""Collect prior CERT cases and retest checks from casper-db through its read-only API.

Which cases to read comes from the run itself: the `loop.history` event holds the
assessments the run made, including (case_id, case_revision) for every match. The snapshot
is read at that revision so the report cites what the run compared against.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .model import StoredEvent

DRIVER = "casper-db"


def history_refs(events: list[StoredEvent]) -> list[tuple[str, int]]:
    refs: list[tuple[str, int]] = []
    for event in events:
        if event.stage != "loop.history":
            continue
        payload = event.response.get("payload")
        assessments = payload.get("assessments") if isinstance(payload, dict) else None
        for assessment in assessments if isinstance(assessments, list) else []:
            matches = assessment.get("matches") if isinstance(assessment, dict) else None
            for match in matches if isinstance(matches, list) else []:
                case_id = match.get("case_id") if isinstance(match, dict) else None
                revision = match.get("case_revision") if isinstance(match, dict) else None
                ref = (case_id, revision)
                if (
                    isinstance(case_id, str)
                    and isinstance(revision, int)
                    and not isinstance(revision, bool)
                    and ref not in refs
                ):
                    refs.append(ref)
    return refs


def unavailable(reason: str) -> dict:
    return {"status": "unavailable", "reason": reason, "cases": []}


def read_history(db_path: Path, refs: list[tuple[str, int]]) -> dict:
    try:
        from casper_db import CaseStore
        from casper_db.repository import NotFoundError
    except ImportError:
        return unavailable("casper-db-package-missing")
    # CaseStore opens read-only; checking first also guarantees no file is ever created.
    if not db_path.is_file():
        return unavailable("db-not-found")
    store = CaseStore(db_path)
    cases = []
    try:
        for case_id, revision in refs:
            try:
                snapshot = store.get_version(case_id, revision)
                current = store.get(case_id)
                checks = store.list_checks(case_id)
            except NotFoundError:
                cases.append({"caseId": case_id, "revision": revision, "status": "not-found"})
                continue
            cases.append(
                {
                    "caseId": case_id,
                    "revision": revision,
                    "status": "ok",
                    "currentRevision": current.revision,
                    "snapshot": snapshot.model_dump(mode="json"),
                    "checks": [item.model_dump(mode="json") for item in checks],
                }
            )
    except (ValueError, sqlite3.Error) as exc:
        # Unsupported schema version, rows that fail model validation, or a damaged file.
        # Only the error class: messages can carry source paths, which the bundle never records.
        return unavailable(f"unreadable-database: {type(exc).__name__}")
    return {"status": "ok", "cases": cases}
