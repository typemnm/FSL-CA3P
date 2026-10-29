"""JSON bridge for the authenticated dashboard's vulnerability DB screens."""

from __future__ import annotations

import json
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from .import_workflow import ReportReview
from .report_intake import ReportIntake
from .repository import COLUMNS, CaseStore, ConflictError, NotFoundError


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _actor(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 120:
        raise ValueError("a named authenticated actor is required")
    return value.strip()


def _setup_case_metadata(case_path: Path) -> None:
    connection = sqlite3.connect(case_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS dashboard_case_state ("
            "case_id TEXT PRIMARY KEY REFERENCES cases(case_id), "
            "archived_at TEXT NOT NULL, archived_by TEXT NOT NULL, reason TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS dashboard_case_audit ("
            "id INTEGER PRIMARY KEY, case_id TEXT NOT NULL, action TEXT NOT NULL, "
            "actor TEXT NOT NULL, recorded_at TEXT NOT NULL, details TEXT NOT NULL)"
        )
        connection.commit()
    finally:
        connection.close()


def _setup_intake_metadata(intake: ReportIntake) -> None:
    with intake._connect(write=True) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS dashboard_intake_audit ("
            "id INTEGER PRIMARY KEY, draft_sha TEXT NOT NULL, action TEXT NOT NULL, "
            "actor TEXT NOT NULL, recorded_at TEXT NOT NULL, details TEXT NOT NULL)"
        )


def _log_intake(intake: ReportIntake, draft_sha: str, action: str, actor: str,
                details: dict | None = None) -> None:
    with intake._connect(write=True) as connection:
        connection.execute(
            "INSERT INTO dashboard_intake_audit "
            "(draft_sha, action, actor, recorded_at, details) VALUES (?, ?, ?, ?, ?)",
            (draft_sha, action, actor, _now(), json.dumps(details or {}, ensure_ascii=False)),
        )


def _log_case(connection: sqlite3.Connection, case_id: str, action: str,
              actor: str, details: dict | None = None) -> None:
    connection.execute(
        "INSERT INTO dashboard_case_audit "
        "(case_id, action, actor, recorded_at, details) VALUES (?, ?, ?, ?, ?)",
        (case_id, action, actor, _now(), json.dumps(details or {}, ensure_ascii=False)),
    )


def _open(payload: dict) -> tuple[ReportIntake, CaseStore]:
    case_path = Path(payload["case_path"]).expanduser().resolve()
    workspace_path = Path(payload["workspace_path"]).expanduser().resolve()
    try:
        intake = ReportIntake(workspace_path)
    except FileNotFoundError:
        try:
            intake = ReportIntake.create_attached(workspace_path, case_path)
        except FileExistsError:
            intake = ReportIntake(workspace_path)
    if intake.case_path != case_path:
        raise ValueError("intake workspace is attached to a different Case DB")
    _setup_case_metadata(case_path)
    _setup_intake_metadata(intake)
    return intake, CaseStore(case_path)


def _intake_item(intake: ReportIntake, draft_sha: str) -> dict:
    reports = intake.show(draft_sha)["reports"]
    if not reports:
        raise NotFoundError(draft_sha)
    with intake._connect() as connection:
        rows = connection.execute(
            "SELECT action, actor, recorded_at FROM dashboard_intake_audit "
            "WHERE draft_sha = ? ORDER BY id DESC LIMIT 100", (draft_sha,),
        ).fetchall()
    return {**reports[0], "audit": [dict(row) for row in rows]}


def _case_state(connection: sqlite3.Connection, case_id: str) -> dict | None:
    row = connection.execute(
        "SELECT archived_at, archived_by, reason FROM dashboard_case_state WHERE case_id = ?",
        (case_id,),
    ).fetchone()
    return dict(row) if row else None


def _case_audit(connection: sqlite3.Connection, case_id: str) -> list[dict]:
    rows = connection.execute(
        "SELECT action, actor, recorded_at, details FROM dashboard_case_audit "
        "WHERE case_id = ? ORDER BY id DESC LIMIT 100", (case_id,),
    ).fetchall()
    return [{**dict(row), "details": json.loads(row["details"])} for row in rows]


def _list_cases(store: CaseStore, payload: dict) -> dict:
    limit = payload.get("limit", 50)
    offset = payload.get("offset", 0)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("offset must be a non-negative integer")
    where, params = [], []
    archived = payload.get("archived", False)
    if archived == "true":
        archived = True
    elif archived == "false":
        archived = False
    if archived not in (True, False, "all"):
        raise ValueError("archived must be true, false or all")
    if archived is True:
        where.append("s.case_id IS NOT NULL")
    elif archived is False:
        where.append("s.case_id IS NULL")
    for incoming, column in (("targetId", "c.target_id"), ("status", "c.status"),
                             ("severity", "c.severity"), ("vulnerabilityType", "c.vulnerability_type")):
        value = payload.get(incoming)
        if value is not None:
            if not isinstance(value, str) or not value.strip() or len(value) > 200:
                raise ValueError(f"invalid {incoming}")
            where.append(f"{column} = ?")
            params.append(value.strip())
    search = payload.get("q")
    if search is not None:
        if not isinstance(search, str) or len(search) > 200:
            raise ValueError("invalid search query")
        if search.strip():
            escaped = search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where.append("(c.case_id LIKE ? ESCAPE '\\' OR c.title LIKE ? ESCAPE '\\' "
                         "OR c.target_id LIKE ? ESCAPE '\\' OR c.vulnerability_url LIKE ? ESCAPE '\\' "
                         "OR c.endpoint LIKE ? ESCAPE '\\' OR c.vulnerability_type LIKE ? ESCAPE '\\')")
            params.extend([f"%{escaped}%"] * 6)
    base = "FROM cases c LEFT JOIN dashboard_case_state s ON s.case_id = c.case_id"
    clause = " WHERE " + " AND ".join(where) if where else ""
    with store._connect() as connection:
        total = connection.execute("SELECT COUNT(*) " + base + clause, params).fetchone()[0]
        rows = connection.execute(
            "SELECT c.*, s.archived_at " + base + clause +
            " ORDER BY c.updated_at DESC, c.case_id LIMIT ? OFFSET ?", params + [limit, offset]
        ).fetchall()
    records = []
    for row in rows:
        data = dict(row)
        archived_at = data.pop("archived_at")
        records.append({**store._record(data).model_dump(mode="json"),
                        "archived": archived_at is not None})
    return {"cases": records,
            "total": total, "limit": limit, "offset": offset}


def _case_detail(store: CaseStore, case_id: str) -> dict:
    record = store.get(case_id).model_dump(mode="json")
    with store._connect() as connection:
        state = _case_state(connection, case_id)
        audit = _case_audit(connection, case_id)
    return {"case": record, "archived": state is not None,
            "archive": state, "audit": audit}


def _list_audit(intake: ReportIntake, store: CaseStore, payload: dict) -> dict:
    limit = payload.get("limit", 50)
    offset = payload.get("offset", 0)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("offset must be a non-negative integer")
    take = limit + offset
    with intake._connect() as connection:
        intake_total = connection.execute("SELECT COUNT(*) FROM dashboard_intake_audit").fetchone()[0]
        intake_rows = connection.execute(
            "SELECT draft_sha, action, actor, recorded_at FROM dashboard_intake_audit "
            "ORDER BY recorded_at DESC, id DESC LIMIT ?", (take,),
        ).fetchall()
    with store._connect() as connection:
        case_total = connection.execute("SELECT COUNT(*) FROM dashboard_case_audit").fetchone()[0]
        case_rows = connection.execute(
            "SELECT case_id, action, actor, recorded_at FROM dashboard_case_audit "
            "ORDER BY recorded_at DESC, id DESC LIMIT ?", (take,),
        ).fetchall()
    logs = ([{"draftSha": row["draft_sha"], "action": row["action"],
              "actor": row["actor"], "recordedAt": row["recorded_at"]} for row in intake_rows]
            + [{"caseId": row["case_id"], "action": row["action"],
                "actor": row["actor"], "recordedAt": row["recorded_at"]} for row in case_rows])
    logs.sort(key=lambda item: item["recordedAt"], reverse=True)
    return {"logs": logs[offset:offset + limit], "total": intake_total + case_total,
            "limit": limit, "offset": offset}


def _update_case(store: CaseStore, payload: dict) -> dict:
    case_id = payload["case_id"]
    actor = _actor(payload.get("actor"))
    patch = payload.get("patch")
    revision = payload.get("expectedRevision")
    if not isinstance(patch, dict) or not patch:
        raise ValueError("provide a non-empty Case patch")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise ValueError("expectedRevision is required")
    immutable = {"case_id", "target_id", "revision", "created_at", "updated_at"}
    if set(patch) - (set(COLUMNS) - immutable):
        raise ValueError("patch contains an unknown or immutable Case field")
    with store._connect(write=True) as connection:
        row = connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if not row:
            raise NotFoundError(case_id)
        if _case_state(connection, case_id):
            raise ConflictError("restore the archived Case before editing")
        current = store._record(row)
        merged = {name: getattr(current, name) for name in COLUMNS}
        merged.update(patch)
        updated = store.update(merged, expected_revision=revision, _connection=connection)
        _log_case(connection, case_id, "update", actor,
                  {"fromRevision": current.revision, "toRevision": updated.revision,
                   "fields": sorted(patch)})
    return _case_detail(store, case_id)


def _archive_case(store: CaseStore, payload: dict, restore: bool = False) -> dict:
    case_id = payload["case_id"]
    actor = _actor(payload.get("actor"))
    reason = payload.get("reason")
    if not restore and (not isinstance(reason, str) or not reason.strip() or len(reason) > 500):
        raise ValueError("an archive reason is required")
    with store._connect(write=True) as connection:
        row = connection.execute("SELECT revision FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if not row:
            raise NotFoundError(case_id)
        expected = payload.get("expectedRevision")
        if expected is not None and expected != row["revision"]:
            raise ConflictError("case revision changed; reload before changing archive state")
        state = _case_state(connection, case_id)
        if restore:
            if not state:
                raise ConflictError("Case is not archived")
            connection.execute("DELETE FROM dashboard_case_state WHERE case_id = ?", (case_id,))
            _log_case(connection, case_id, "restore", actor)
        else:
            if state:
                raise ConflictError("Case is already archived")
            connection.execute(
                "INSERT INTO dashboard_case_state VALUES (?, ?, ?, ?)",
                (case_id, _now(), actor, reason.strip()),
            )
            _log_case(connection, case_id, "archive", actor, {"reason": reason.strip()})
    return _case_detail(store, case_id)


def dispatch(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("request must be an object")
    intake, store = _open(payload)
    op = payload.get("operation")
    if op == "bootstrap":
        return {"workspace": str(intake.root), "caseDatabase": str(intake.case_path)}
    if op == "list_intakes":
        return {"intakes": intake.show()["reports"]}
    if op == "get_intake":
        return {"intake": _intake_item(intake, payload["draft_sha"])}
    if op == "stage":
        actor = _actor(payload.get("actor"))
        result = intake.stage(Path(payload["source_path"]), target_id=payload["target_id"],
                              managed_source=True)
        _log_intake(intake, result["draft_sha256"], "stage", actor,
                    {"targetId": payload["target_id"], "reused": result["reused"]})
        public_result = {key: value for key, value in result.items()
                         if key not in ("draft_file", "review_file")}
        return {"intake": _intake_item(intake, result["draft_sha256"]), "stage": public_result}
    if op == "review":
        actor = _actor(payload.get("actor"))
        raw = payload.get("review")
        if not isinstance(raw, dict):
            raise ValueError("provide a complete review")
        review = ReportReview.model_validate({**raw, "reviewer": actor,
                                              "reviewed_at": raw.get("reviewed_at") or _now()})
        result = intake.submit_review(payload["draft_sha"], review,
                                      expected_validation_sha=payload["expectedValidationSha"])
        _log_intake(intake, payload["draft_sha"], "review", actor,
                    {"validationSha256": result["validation_sha256"]})
        return {"intake": _intake_item(intake, payload["draft_sha"]), "review": result}
    if op == "publish":
        actor = _actor(payload.get("actor"))
        result = intake.publish(payload["draft_sha"], apply=True,
                                ready_only=payload.get("readyOnly") is True,
                                expected_validation_sha=payload["expectedValidationSha"])
        _log_intake(intake, payload["draft_sha"], "publish", actor, result)
        return {"intake": _intake_item(intake, payload["draft_sha"]), "publish": result}
    if op == "delete_intake":
        actor = _actor(payload.get("actor"))
        result = intake.delete_draft(payload["draft_sha"])
        _log_intake(intake, payload["draft_sha"], "delete", actor)
        return result
    if op == "list_cases":
        return _list_cases(store, payload)
    if op == "get_case":
        return _case_detail(store, payload["case_id"])
    if op == "get_case_versions":
        return {"versions": [item.model_dump(mode="json") for item in
                             store.list_versions(payload["case_id"])]}
    if op == "list_audit":
        return _list_audit(intake, store, payload)
    if op == "update_case":
        return _update_case(store, payload)
    if op == "archive_case":
        return _archive_case(store, payload)
    if op == "restore_case":
        return _archive_case(store, payload, restore=True)
    raise ValueError("unsupported DB operation")


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        result = dispatch(payload)
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=False))
    except (NotFoundError, FileNotFoundError) as exc:
        print(json.dumps({"ok": False, "status": 404, "error": str(exc)}, ensure_ascii=False))
    except (ConflictError, sqlite3.IntegrityError) as exc:
        print(json.dumps({"ok": False, "status": 409, "error": str(exc)}, ensure_ascii=False))
    except (ValueError, KeyError, ValidationError) as exc:
        print(json.dumps({"ok": False, "status": 400, "error": str(exc)}, ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({"ok": False, "status": 500,
                          "error": f"DB operation failed: {type(exc).__name__}"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
