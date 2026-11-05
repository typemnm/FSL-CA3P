"""JSON bridge for the authenticated dashboard's vulnerability DB screens."""

from __future__ import annotations

import json
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from .dashboard_operations import (
    operation_status,
    query_product,
    save_settings,
    settings,
    sync_product,
    sync_summary,
)
from .dashboard_queries import list_advisories, list_intakes
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
        connection.execute("CREATE INDEX IF NOT EXISTS drafts_by_source ON drafts(source_sha)")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS dashboard_settings (id INTEGER PRIMARY KEY CHECK(id=1), "
            "revision INTEGER NOT NULL,snapshot TEXT NOT NULL,updated_at TEXT NOT NULL,"
            "updated_by TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS dashboard_intake_audit ("
            "id INTEGER PRIMARY KEY, draft_sha TEXT NOT NULL, action TEXT NOT NULL, "
            "actor TEXT NOT NULL, recorded_at TEXT NOT NULL, details TEXT NOT NULL)"
        )


def _log_intake(
    intake: ReportIntake, draft_sha: str, action: str, actor: str, details: dict | None = None
) -> None:
    with intake._connect(write=True) as connection:
        connection.execute(
            "INSERT INTO dashboard_intake_audit "
            "(draft_sha, action, actor, recorded_at, details) VALUES (?, ?, ?, ?, ?)",
            (draft_sha, action, actor, _now(), json.dumps(details or {}, ensure_ascii=False)),
        )


def _log_case(
    connection: sqlite3.Connection,
    case_id: str,
    action: str,
    actor: str,
    details: dict | None = None,
) -> None:
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
    # Report knowledge is owned by the report feature, not a core Case migration.
    from .report_knowledge import setup_schema

    with sqlite3.connect(case_path) as connection:
        setup_schema(connection)
    _setup_intake_metadata(intake)
    return intake, CaseStore(case_path)


def _intake_item(intake: ReportIntake, draft_sha: str) -> dict:
    from .report_preview import image_previews

    reports = intake.show(draft_sha)["reports"]
    if not reports:
        raise NotFoundError(draft_sha)
    with intake._connect() as connection:
        rows = connection.execute(
            "SELECT action, actor, recorded_at FROM dashboard_intake_audit "
            "WHERE draft_sha = ? ORDER BY id DESC LIMIT 100",
            (draft_sha,),
        ).fetchall()
        versions = connection.execute(
            "SELECT draft_sha FROM drafts WHERE source_sha=? ORDER BY rowid DESC",
            (reports[0]["source_sha256"],),
        ).fetchall()
    return {
        **reports[0],
        "audit": [dict(row) for row in rows],
        "extractionVersions": [{"draft_sha256": row[0]} for row in versions],
        "imagePreviews": image_previews(intake, draft_sha),
    }


def _case_state(connection: sqlite3.Connection, case_id: str) -> dict | None:
    row = connection.execute(
        "SELECT archived_at, archived_by, reason FROM dashboard_case_state WHERE case_id = ?",
        (case_id,),
    ).fetchone()
    return dict(row) if row else None


def _case_audit(connection: sqlite3.Connection, case_id: str) -> list[dict]:
    rows = connection.execute(
        "SELECT action, actor, recorded_at, details FROM dashboard_case_audit "
        "WHERE case_id = ? ORDER BY id DESC LIMIT 100",
        (case_id,),
    ).fetchall()
    return [{**dict(row), "details": json.loads(row["details"])} for row in rows]


def _list_cases(store: CaseStore, payload: dict) -> dict:
    from .dashboard_queries import pagination

    limit, offset = pagination(payload)
    archived = payload.get("archived", False)
    if archived == "true":
        archived = True
    elif archived == "false":
        archived = False
    if archived not in (True, False, "all"):
        raise ValueError("archived must be true, false or all")
    where, params = [], []
    if archived != "all":
        where.append("s.archived_at IS NOT NULL" if archived else "s.archived_at IS NULL")
    for incoming, column in (("targetId", "target_id"), ("status", "status"),
                             ("severity", "severity"), ("vulnerabilityType", "vulnerability_type")):
        value = payload.get(incoming)
        if value is not None:
            if not isinstance(value, str) or not value.strip() or len(value) > 200:
                raise ValueError(f"invalid {incoming}")
            where.append(f"json_extract(c.snapshot,'$.{column}')=?")
            params.append(value.strip())
    search = payload.get("q", "")
    if not isinstance(search, str) or len(search) > 200:
        raise ValueError("invalid search query")
    if search.strip():
        names = ("case_id", "title", "target_id", "vulnerability_url", "endpoint",
                 "vulnerability_type", "source_filename")
        where.append("(" + " OR ".join(
            f"instr(lower(coalesce(json_extract(c.snapshot,'$.{key}'),'')),lower(?))>0"
            for key in names
        ) + ")")
        params.extend([search.strip()] * len(names))
    # Both kinds are persisted in the same DB. A promoted strict Case has one list row.
    source = (
        "WITH records AS (SELECT c.case_id,v.snapshot,c.updated_at FROM cases c "
        "JOIN case_versions v ON v.case_id=c.case_id AND v.revision=c.revision "
        "UNION ALL SELECT k.case_id,json_remove(k.snapshot,'$.field_evidence',"
        "'$.payload_variants','$.resolutions'),k.updated_at FROM report_knowledge_records k "
        "WHERE NOT EXISTS(SELECT 1 FROM cases c WHERE c.case_id=k.case_id)) "
    )
    base = "FROM records c LEFT JOIN dashboard_case_state s ON s.case_id=c.case_id"
    clause = " WHERE " + " AND ".join(where) if where else ""
    with store._connect() as connection:
        total = connection.execute(
            source + "SELECT count(*) " + base + clause, params
        ).fetchone()[0]
        rows = connection.execute(
            source + "SELECT c.snapshot,s.archived_at " + base + clause +
            " ORDER BY c.updated_at DESC,c.case_id LIMIT ? OFFSET ?", params + [limit, offset],
        ).fetchall()
    return {"cases": [{**json.loads(row["snapshot"]), "archived": row["archived_at"] is not None}
                      for row in rows], "total": total, "limit": limit, "offset": offset}


def _case_detail(store: CaseStore, case_id: str) -> dict:
    from .report_knowledge import get_record

    try:
        record = store.get(case_id).model_dump(mode="json")
    except NotFoundError:
        with store._connect() as connection:
            record = get_record(connection, case_id)
        if record is None:
            raise
        return {"case": record, "archived": False, "audit": [{
            "action": "register_report_knowledge", "actor": record["reviewer"],
            "recorded_at": record["updated_at"], "reason": record["review_reason"],
        }]}
    with store._connect() as connection:
        state = _case_state(connection, case_id)
        audit = _case_audit(connection, case_id)
    return {"case": record, "archived": state is not None, "archive": state, "audit": audit}


def _list_audit(intake: ReportIntake, store: CaseStore, payload: dict) -> dict:
    limit = payload.get("limit", 50)
    offset = payload.get("offset", 0)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("offset must be a non-negative integer")
    take = limit + offset
    with intake._connect() as connection:
        intake_total = connection.execute("SELECT COUNT(*) FROM dashboard_intake_audit").fetchone()[
            0
        ]
        intake_rows = connection.execute(
            "SELECT draft_sha, action, actor, recorded_at, "
            "json_extract(details,'$.status') AS status FROM dashboard_intake_audit "
            "ORDER BY recorded_at DESC, id DESC LIMIT ?",
            (take,),
        ).fetchall()
    with store._connect() as connection:
        case_total = connection.execute("SELECT COUNT(*) FROM dashboard_case_audit").fetchone()[0]
        case_rows = connection.execute(
            "SELECT case_id, action, actor, recorded_at FROM dashboard_case_audit "
            "ORDER BY recorded_at DESC, id DESC LIMIT ?",
            (take,),
        ).fetchall()
    logs = [
        {
            "draftSha": row["draft_sha"],
            "action": row["action"],
            "actor": row["actor"],
            "recordedAt": row["recorded_at"],
            "status": row["status"]
            or ("running" if row["action"] == "advisory_sync_requested" else "completed"),
        }
        for row in intake_rows
    ] + [
        {
            "caseId": row["case_id"],
            "action": row["action"],
            "actor": row["actor"],
            "recordedAt": row["recorded_at"],
        }
        for row in case_rows
    ]
    logs.sort(key=lambda item: item["recordedAt"], reverse=True)
    from .sync_journal import list_sync_runs

    jobs = [sync_summary(row) for row in list_sync_runs(store.path)]
    logs.extend(
        {**job, "action": "advisory_sync", "recordedAt": job["completedAt"] or job["startedAt"]}
        for job in jobs
    )
    logs.sort(key=lambda item: item["recordedAt"], reverse=True)
    return {
        "logs": logs[offset : offset + limit],
        "total": intake_total + case_total + len(jobs),
        "limit": limit,
        "offset": offset,
    }


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
        _log_case(
            connection,
            case_id,
            "update",
            actor,
            {
                "fromRevision": current.revision,
                "toRevision": updated.revision,
                "fields": sorted(patch),
            },
        )
    return _case_detail(store, case_id)


def _archive_case(store: CaseStore, payload: dict, restore: bool = False) -> dict:
    case_id = payload["case_id"]
    actor = _actor(payload.get("actor"))
    reason = payload.get("reason")
    if not restore and (not isinstance(reason, str) or not reason.strip() or len(reason) > 500):
        raise ValueError("an archive reason is required")
    with store._connect(write=True) as connection:
        row = connection.execute(
            "SELECT revision FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
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
    if op == "status":
        return operation_status(intake, store)
    if op == "get_settings":
        return settings(intake)
    if op == "save_settings":
        actor = _actor(payload.get("actor"))
        result = save_settings(intake, payload, actor)
        _log_intake(intake, "settings", "settings_update", actor, {"revision": result["revision"]})
        return result
    if op == "list_advisories":
        return list_advisories(store, payload)
    if op == "query_advisories":
        return query_product(store, payload)
    if op == "sync_advisories":
        actor = _actor(payload.get("actor"))
        _log_intake(intake, "advisories", "advisory_sync_requested", actor)
        try:
            result = sync_product(intake, store, payload)
        except Exception as exc:
            _log_intake(
                intake,
                "advisories",
                "advisory_sync_failed",
                actor,
                {"status": "failed", "errorType": type(exc).__name__},
            )
            raise
        _log_intake(
            intake, "advisories", "advisory_sync_finished", actor, {"status": result["status"]}
        )
        return result
    if op == "list_intakes":
        return list_intakes(intake, store, payload)
    if op == "get_intake":
        return {"intake": _intake_item(intake, payload["draft_sha"])}
    if op == "stage":
        actor = _actor(payload.get("actor"))
        configured = settings(intake)["settings"]
        local_ocr = payload.get("localOcr", configured["ocrEnabled"])
        language = payload.get("ocrLanguage", configured["ocrLanguage"])
        local_llm = payload.get('localLlm', configured['localLlmEnabled'])
        if type(local_llm) is not bool:
            raise ValueError('invalid local LLM option')
        if type(local_ocr) is not bool or language not in {"ko", "en", "kor", "eng", "kor+eng"}:
            raise ValueError("invalid OCR options")
        result = intake.stage(
            Path(payload["source_path"]),
            target_id=payload["target_id"],
            managed_source=True,
            local_ocr=local_ocr,
            ocr_language=language,
            local_llm=local_llm,
        )
        _log_intake(
            intake,
            result["draft_sha256"],
            "stage",
            actor,
            {"targetId": payload["target_id"], "reused": result["reused"]},
        )
        public_result = {
            key: value for key, value in result.items() if key not in ("draft_file", "review_file")
        }
        return {"intake": _intake_item(intake, result["draft_sha256"]), "stage": public_result}
    if op == 'analyze_local':
        actor = _actor(payload.get('actor'))
        result = intake.analyze_local(
            payload['draft_sha'], expected_validation_sha=payload['expectedValidationSha']
        )
        _log_intake(intake, result['draft_sha256'], 'local_llm_analysis', actor,
                    {'previousDraft': payload['draft_sha']})
        return {'intake': _intake_item(intake, result['draft_sha256'])}
    if op == "review":
        actor = _actor(payload.get("actor"))
        raw = payload.get("review")
        if not isinstance(raw, dict):
            raise ValueError("provide a complete review")
        review = ReportReview.model_validate(
            {**raw, "reviewer": actor, "reviewed_at": _now()}
        )
        result = intake.submit_review(
            payload["draft_sha"], review, expected_validation_sha=payload["expectedValidationSha"]
        )
        _log_intake(
            intake,
            payload["draft_sha"],
            "review",
            actor,
            {"validationSha256": result["validation_sha256"]},
        )
        return {"intake": _intake_item(intake, payload["draft_sha"]), "review": result}
    if op == "publish":
        actor = _actor(payload.get("actor"))
        result = intake.publish(
            payload["draft_sha"],
            apply=True,
            ready_only=payload.get("readyOnly") is True,
            expected_validation_sha=payload["expectedValidationSha"],
            include_incomplete=True,
        )
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
        from .report_knowledge import get_record

        with store._connect() as connection:
            knowledge = get_record(connection, payload["case_id"])
            strict = connection.execute("SELECT 1 FROM cases WHERE case_id=?",
                                        (payload["case_id"],)).fetchone()
            if knowledge and not strict:
                return {"versions": [json.loads(row[0]) for row in connection.execute(
                    "SELECT snapshot FROM report_knowledge_versions WHERE case_id=? "
                    "ORDER BY revision DESC", (payload["case_id"],),
                )]}
        return {
            "versions": [
                item.model_dump(mode="json") for item in store.list_versions(payload["case_id"])
            ]
        }
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
    from .dashboard_errors import public_error

    payload = {}
    try:
        payload = json.load(sys.stdin)
        result = dispatch(payload)
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=False))
    except (NotFoundError, FileNotFoundError) as exc:
        print(
            json.dumps(
                public_error(exc, payload.get("operation") if isinstance(payload, dict) else None),
                ensure_ascii=False,
            )
        )
    except (ConflictError, sqlite3.IntegrityError) as exc:
        print(
            json.dumps(
                public_error(exc, payload.get("operation") if isinstance(payload, dict) else None),
                ensure_ascii=False,
            )
        )
    except (ValueError, KeyError, ValidationError) as exc:
        print(
            json.dumps(
                public_error(exc, payload.get("operation") if isinstance(payload, dict) else None),
                ensure_ascii=False,
            )
        )
    except Exception as exc:
        print(
            json.dumps(
                {"ok": False, "status": 500, "error": f"DB operation failed: {type(exc).__name__}"},
                ensure_ascii=False,
            )
        )


if __name__ == "__main__":
    main()
