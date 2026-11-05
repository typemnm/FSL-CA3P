from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from pydantic import TypeAdapter

from .case_policy import same_reviewed_route
from .evidence import inspect_evidence
from .models import Case, CaseQuery, CaseRecord, Check, CheckRecord, Identifier, utc_timestamp

SCHEMA_VERSION = 7
TARGET_ID_ADAPTER = TypeAdapter(Identifier)
# These identifiers come from our model, never from an incoming request.
COLUMNS = tuple(Case.model_fields)
CHECK_COLUMNS = tuple(Check.model_fields)
CHECK_RECORD_COLUMNS = CHECK_COLUMNS + (
    "created_at",
    "reviewed_at",
    "review_note",
    "evidence_metadata",
    "legacy_review",
)


class NotFoundError(LookupError):
    pass


class ConflictError(ValueError):
    pass


def _sql(name: str) -> str:
    return files("casper_db").joinpath(name).read_text(encoding="utf-8")


def _run_schema(connection: sqlite3.Connection, sql: str) -> None:
    """Execute bundled statements without executescript's implicit commit."""
    statement = ""
    for line in sql.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            connection.execute(statement)
            statement = ""
    if statement.strip():
        raise ValueError("incomplete bundled schema statement")


def _save_version(connection: sqlite3.Connection, record: CaseRecord) -> None:
    connection.execute(
        "INSERT INTO case_versions (case_id, revision, snapshot, recorded_at) VALUES (?, ?, ?, ?)",
        (record.case_id, record.revision, record.model_dump_json(), record.updated_at),
    )


def _migrate_legacy(connection: sqlite3.Connection, version: int) -> None:
    if version == 1:
        for column in (
            "reported_on TEXT",
            "vulnerability_url TEXT",
            "severity TEXT",
            "description TEXT",
            "remediation TEXT NOT NULL DEFAULT '[]'",
            "prior_evidence TEXT",
        ):
            connection.execute(f"ALTER TABLE cases ADD COLUMN {column}")
        connection.execute("UPDATE cases SET status = 'draft' WHERE status = 'ready'")
    if version in (1, 2, 3):
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(cases)")}
        if "parameter_location" not in columns:
            connection.execute(
                "ALTER TABLE cases ADD COLUMN parameter_location TEXT NOT NULL DEFAULT 'unknown'"
            )
        for row in connection.execute(
            "SELECT case_id, parameter, vulnerability_url FROM cases"
        ).fetchall():
            if row["vulnerability_url"] and row["parameter"] in {
                name
                for name, _ in parse_qsl(
                    urlsplit(row["vulnerability_url"]).query, keep_blank_values=True
                )
            }:
                connection.execute(
                    "UPDATE cases SET parameter_location = 'query' WHERE case_id = ?",
                    (row["case_id"],),
                )
    for column in (
        "source TEXT NOT NULL DEFAULT 'unknown'",
        "revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1)",
    ):
        connection.execute(f"ALTER TABLE cases ADD COLUMN {column}")
    _run_schema(connection, _sql("history.sql"))
    for row in connection.execute("SELECT * FROM cases").fetchall():
        _save_version(connection, CaseStore._record(row))

    has_checks = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='checks'"
    ).fetchone()
    old_checks = connection.execute("SELECT * FROM checks").fetchall() if has_checks else []
    # Rebuild so migrated databases get the same version foreign key as new ones.
    create = _sql("checks.sql").split(";", 1)[0] + ";"
    connection.execute(
        create.replace("CREATE TABLE IF NOT EXISTS checks (", "CREATE TABLE checks_new (", 1)
    )
    for old in old_checks:
        data = dict(old)
        data["case_revision"] = 1
        data["observed_at"] = utc_timestamp(data["observed_at"])
        # Older observations did not record their location; do not infer it from a parent.
        data.setdefault("parameter_location", "unknown")
        data.setdefault("parameter_not_applicable", 0)
        data.setdefault("observed_evidence", "[]")
        data.update(link_review=None, reviewed_at=None, review_note=None, evidence_metadata="[]")
        data["legacy_review"] = None
        if data["review_status"] == "reviewed":
            data["legacy_review"] = json.dumps(
                {"review_status": "reviewed", "reviewer": data["reviewer"]}
            )
            data["review_status"] = "draft"
            data["reviewer"] = None
        CaseStore._check_record(data)
        connection.execute(
            f"INSERT INTO checks_new ({', '.join(CHECK_RECORD_COLUMNS)}) "
            f"VALUES ({', '.join('?' for _ in CHECK_RECORD_COLUMNS)})",
            [data[key] for key in CHECK_RECORD_COLUMNS],
        )
    if has_checks:
        connection.execute("DROP TABLE checks")
    connection.execute("ALTER TABLE checks_new RENAME TO checks")
    _run_schema(connection, _sql("checks.sql"))


def _migrate_v5(connection: sqlite3.Connection) -> None:
    """Rebuild the parent table while preserving history/check foreign-key names."""
    create = _sql("schema.sql").split(";", 1)[0] + ";"
    connection.execute(
        create.replace("CREATE TABLE IF NOT EXISTS cases (", "CREATE TABLE cases_new (", 1)
    )
    columns = COLUMNS + ("revision", "created_at", "updated_at")
    for row in connection.execute("SELECT * FROM cases").fetchall():
        record = CaseStore._record(row)
        data = CaseStore._values(record)
        data.update(
            revision=record.revision, created_at=record.created_at, updated_at=record.updated_at
        )
        connection.execute(
            f"INSERT INTO cases_new ({', '.join(columns)}) "
            f"VALUES ({', '.join('?' for _ in columns)})",
            [data[key] for key in columns],
        )
    connection.execute("DROP TABLE cases")
    connection.execute("ALTER TABLE cases_new RENAME TO cases")
    _run_schema(connection, _sql("schema.sql"))


def _migrate_v6_checks(connection: sqlite3.Connection) -> None:
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(checks)")}
    if "observed_evidence" in columns and "parameter_not_applicable" in columns:
        return
    create = _sql("checks.sql").split(";", 1)[0] + ";"
    connection.execute(
        create.replace("CREATE TABLE IF NOT EXISTS checks (", "CREATE TABLE checks_new (", 1)
    )
    for row in connection.execute("SELECT * FROM checks").fetchall():
        data = dict(row)
        data.update(parameter_not_applicable=0, observed_evidence="[]")
        CaseStore._check_record(data)
        connection.execute(
            f"INSERT INTO checks_new ({', '.join(CHECK_RECORD_COLUMNS)}) "
            f"VALUES ({', '.join('?' for _ in CHECK_RECORD_COLUMNS)})",
            [data[key] for key in CHECK_RECORD_COLUMNS],
        )
    connection.execute("DROP TABLE checks")
    connection.execute("ALTER TABLE checks_new RENAME TO checks")
    _run_schema(connection, _sql("checks.sql"))


def initialize_database(path: str | Path) -> Path:
    resolved = Path(path).expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(resolved)
    connection.row_factory = sqlite3.Row
    try:
        # Parent-table replacement requires this before BEGIN. Every relationship is
        # checked before committing; normal readers/writers always enable enforcement.
        connection.execute("PRAGMA foreign_keys = OFF")
        # DDL, data, snapshots and user_version must all succeed or all roll back.
        connection.execute("BEGIN IMMEDIATE")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1, 2, 3, 4, 5, 6, SCHEMA_VERSION):
            raise ValueError(f"unsupported database schema version: {version}")
        if version == 0:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            if tables:
                from .external_vulnerabilities import EXTERNAL_TABLES

                names = {row["name"] for row in tables}
                owned = names.issubset(EXTERNAL_TABLES) and "external_metadata" in names
                marker = connection.execute(
                    "SELECT value FROM external_metadata WHERE key='schema'"
                ).fetchone() if owned else None
                if not marker or marker[0] != "external-vuln-1":
                    raise ValueError(
                        "refusing to initialize a database that already has unknown tables"
                    )
            for name in ("schema.sql", "history.sql", "checks.sql"):
                _run_schema(connection, _sql(name))
        elif version < SCHEMA_VERSION:
            if version < 5:
                _migrate_legacy(connection, version)
            if version < 6:
                _migrate_v5(connection)
            _migrate_v6_checks(connection)
        connection.execute("SELECT " + ", ".join(COLUMNS) + ", revision FROM cases LIMIT 0")
        connection.execute("SELECT " + ", ".join(CHECK_RECORD_COLUMNS) + " FROM checks LIMIT 0")
        connection.execute("SELECT case_id, revision, snapshot FROM case_versions LIMIT 0")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("database contains broken case/check relationships")
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        connection.commit()
        connection.execute("PRAGMA foreign_keys = ON")
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return resolved


class CaseStore:
    def __init__(self, path: str | Path, *, evidence_root: str | Path | None = None):
        self.path = Path(path).expanduser().resolve()
        self.evidence_root = Path(evidence_root).expanduser().resolve() if evidence_root else None

    @contextmanager
    def _connect(self, *, write: bool = False):
        if not self.path.is_file():
            raise FileNotFoundError("database not found; run the init command first")
        mode = "rw" if write else "ro"
        connection = sqlite3.connect(self.path.as_uri() + f"?mode={mode}", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version != SCHEMA_VERSION:
                raise ValueError(f"unsupported database schema version: {version}")
            if write:
                # Serialize read-then-write operations (revision allocation and review).
                connection.execute("BEGIN IMMEDIATE")
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _record(row: sqlite3.Row) -> CaseRecord:
        data = dict(row)
        data["preconditions"] = json.loads(data["preconditions"])
        data["procedure"] = json.loads(data["procedure"])
        data["remediation"] = json.loads(data["remediation"])
        data["not_applicable_fields"] = json.loads(data.get("not_applicable_fields", "[]"))
        return CaseRecord.model_validate(data)

    @staticmethod
    def _values(case: Case | dict) -> dict:
        raw = {key: getattr(case, key) for key in COLUMNS} if isinstance(case, Case) else case
        data = Case.model_validate(raw).model_dump()
        for key in ("preconditions", "procedure", "remediation", "not_applicable_fields"):
            data[key] = json.dumps(data[key], ensure_ascii=False)
        return data

    def add(self, case: Case | dict) -> CaseRecord:
        data = self._values(case)
        now = datetime.now(UTC).isoformat()
        columns = COLUMNS + ("created_at", "updated_at")
        values = [data[key] for key in COLUMNS] + [now, now]
        sql = f"INSERT INTO cases ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})"
        with self._connect(write=True) as connection:
            try:
                connection.execute(sql, values)
            except sqlite3.IntegrityError as exc:
                raise ConflictError("case ID already exists; use update to change it") from exc
            row = connection.execute(
                "SELECT * FROM cases WHERE case_id = ?", (data["case_id"],)
            ).fetchone()
            result = self._record(row)
            _save_version(connection, result)
        return result

    def add_many(
        self, cases: list[Case | dict], *, _connection: sqlite3.Connection | None = None,
    ) -> dict[str, list[CaseRecord]]:
        """Atomically import reviewed cases; identical retries do not add revisions."""
        validated = [Case.model_validate(case) for case in cases]
        ids = [case.case_id for case in validated]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate case IDs in batch")
        if not validated or any(case.status != "ready" for case in validated):
            raise ValueError("batch import requires at least one ready case")
        result: dict[str, list[CaseRecord]] = {"created": [], "unchanged": []}
        now = datetime.now(UTC).isoformat()
        columns = COLUMNS + ("created_at", "updated_at")
        sql = f"INSERT INTO cases ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})"
        context = self._connect(write=True) if _connection is None else nullcontext(_connection)
        with context as connection:
            for case in validated:
                existing = connection.execute(
                    "SELECT * FROM cases WHERE case_id = ?", (case.case_id,)
                ).fetchone()
                if existing is not None:
                    record = self._record(existing)
                    if any(getattr(record, key) != getattr(case, key) for key in COLUMNS):
                        raise ConflictError("case ID has different content; review and use update")
                    result["unchanged"].append(record)
                    continue
                data = self._values(case)
                connection.execute(sql, [data[key] for key in COLUMNS] + [now, now])
                row = connection.execute(
                    "SELECT * FROM cases WHERE case_id = ?", (case.case_id,)
                ).fetchone()
                record = self._record(row)
                _save_version(connection, record)
                result["created"].append(record)
        return result

    def update(self, case: Case | dict, *, expected_revision: int | None = None,
               _connection: sqlite3.Connection | None = None) -> CaseRecord:
        data = self._values(case)
        fields = tuple(key for key in COLUMNS if key != "case_id")
        sql = (
            "UPDATE cases SET "
            + ", ".join(f"{key} = ?" for key in fields)
            + ", updated_at = ?, revision = revision + 1 WHERE case_id = ?"
        )
        values = [data[key] for key in fields] + [datetime.now(UTC).isoformat(), data["case_id"]]
        context = self._connect(write=True) if _connection is None else nullcontext(_connection)
        with context as connection:
            current = connection.execute(
                "SELECT target_id, revision FROM cases WHERE case_id = ?", (data["case_id"],)
            ).fetchone()
            if current is None:
                raise NotFoundError(data["case_id"])
            if current["target_id"] != data["target_id"]:
                raise ValueError(
                    "a case must keep its target_id; create a new case for another site"
                )
            if expected_revision is not None and expected_revision != current["revision"]:
                raise ConflictError("case revision changed; reload before updating")
            if connection.execute(sql, values).rowcount == 0:
                raise NotFoundError(data["case_id"])
            row = connection.execute(
                "SELECT * FROM cases WHERE case_id = ?", (data["case_id"],)
            ).fetchone()
            result = self._record(row)
            _save_version(connection, result)
        return result

    def get_version(self, case_id: str, revision: int) -> CaseRecord:
        with self._connect() as connection:
            return self._version(connection, case_id, revision)

    @staticmethod
    def _version(connection: sqlite3.Connection, case_id: str, revision: int) -> CaseRecord:
        row = connection.execute(
            "SELECT snapshot FROM case_versions WHERE case_id = ? AND revision = ?",
            (case_id, revision),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"{case_id} revision {revision}")
        return CaseRecord.model_validate_json(row["snapshot"])

    def list_versions(self, case_id: str) -> list[CaseRecord]:
        with self._connect() as connection:
            if (
                connection.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone()
                is None
            ):
                raise NotFoundError(case_id)
            rows = connection.execute(
                "SELECT snapshot FROM case_versions WHERE case_id = ? ORDER BY revision",
                (case_id,),
            ).fetchall()
            return [CaseRecord.model_validate_json(row["snapshot"]) for row in rows]

    def get(self, case_id: str) -> CaseRecord:
        """Authoring lookup: returns drafts as well as ready records."""
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if row is None:
                raise NotFoundError(case_id)
            return self._record(row)

    def find(
        self,
        *,
        target_id: str,
        endpoint: str,
        method: str,
        parameter: str | None = None,
        parameter_location: str | None = None,
        include_drafts: bool = False,
    ) -> list[CaseRecord]:
        query = CaseQuery(
            target_id=target_id,
            endpoint=endpoint,
            method=method,
            parameter=parameter,
            parameter_location=parameter_location,
        )
        sql = "SELECT * FROM cases WHERE target_id = ? AND endpoint = ? AND method = ?"
        values = [query.target_id, query.endpoint, query.method]
        if query.parameter is not None:
            sql += " AND parameter = ?"
            values.append(query.parameter)
        if query.parameter_location is not None:
            sql += " AND parameter_location = ?"
            values.append(query.parameter_location)
        if not include_drafts:
            sql += " AND status = 'ready'"
        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='dashboard_case_state'"
            ).fetchone():
                sql += (
                    " AND NOT EXISTS (SELECT 1 FROM dashboard_case_state a "
                    "WHERE a.case_id = cases.case_id)"
                )
            sql += " ORDER BY case_id"
            rows = connection.execute(sql, values).fetchall()
            return [self._record(row) for row in rows]

    def list_for_target(self, target_id: str) -> list[CaseRecord]:
        """Return prior ready reports for the LLM to compare with parser output."""
        target = TARGET_ID_ADAPTER.validate_python(target_id, strict=True)
        with self._connect() as connection:
            sql = "SELECT * FROM cases WHERE target_id = ? AND status = 'ready'"
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='dashboard_case_state'"
            ).fetchone():
                sql += (
                    " AND NOT EXISTS (SELECT 1 FROM dashboard_case_state a "
                    "WHERE a.case_id = cases.case_id)"
                )
            rows = connection.execute(
                sql + " ORDER BY reported_on DESC, case_id", (target,)
            ).fetchall()
            return [self._record(row) for row in rows]

    @staticmethod
    def _check_record(row: sqlite3.Row | dict) -> CheckRecord:
        data = dict(row)
        data["parameter_not_applicable"] = bool(data.get("parameter_not_applicable", False))
        data.setdefault("observed_evidence", "[]")
        for field in (
            "evidence_refs",
            "evidence_metadata",
            "link_review",
            "legacy_review",
            "observed_evidence",
        ):
            if data[field] is not None:
                data[field] = json.loads(data[field])
        return CheckRecord.model_validate(data)

    def _prepare_check(self, connection, check: Check | dict) -> tuple[Check, dict]:
        raw = (
            {key: getattr(check, key) for key in CHECK_COLUMNS}
            if isinstance(check, Check)
            else check
        )
        validated = Check.model_validate(raw)
        if validated.review_status != "draft" or validated.reviewer is not None:
            raise ValueError("add checks as drafts; use review_check to verify evidence")
        data = validated.model_dump()
        for field in ("evidence_refs", "link_review", "observed_evidence"):
            if data[field] is not None:
                data[field] = json.dumps(data[field], ensure_ascii=False)
        current = connection.execute(
            "SELECT revision FROM cases WHERE case_id = ?",
            (validated.case_id,),
        ).fetchone()
        if current is None:
            raise NotFoundError(validated.case_id)
        revision = validated.case_revision or current["revision"]
        parent = self._version(connection, validated.case_id, revision)
        data["case_revision"] = revision
        if validated.target_id != parent.target_id:
            raise ValueError("check target_id does not match its prior case")
        if validated.parameter_not_applicable and "parameter" not in parent.not_applicable_fields:
            raise ValueError("prior case has not reviewed parameter as non-applicable")
        changed = [
            key
            for key in ("endpoint", "method", "parameter", "parameter_location")
            if data[key] != getattr(parent, key)
        ]
        if (
            "endpoint" in changed
            and parent.route_template
            and same_reviewed_route(
                parent.route_template, parent.endpoint, validated.endpoint, parent.parameter
            )
        ):
            changed.remove("endpoint")
        if (
            (validated.parameter_location == "unknown" or parent.parameter_location == "unknown")
            and not validated.parameter_not_applicable
            and "parameter_location" not in changed
        ):
            changed.append("parameter_location")
        if changed and validated.link_review is None:
            raise ValueError(
                f"check {', '.join(changed)} differs or is unknown; a link_review is required"
            )
        if validated.observed_evidence:
            if (
                inspect_evidence(self.evidence_root, validated.evidence_refs)
                != validated.observed_evidence
            ):
                raise ValueError("evidence differs from the recorded observation")
        return validated, data

    def prepare_checks(self, checks: list[Check | dict]) -> list[Check]:
        with self._connect() as connection:
            prepared = [self._prepare_check(connection, item) for item in checks]
        return [
            item.model_copy(update={"case_revision": data["case_revision"]})
            for item, data in prepared
        ]

    def add_check(self, check: Check | dict) -> CheckRecord:
        return self.add_checks([check])[0]

    def add_checks(self, checks: list[Check | dict], *, allow_unchanged=False) -> list[CheckRecord]:
        """Validate and append a batch atomically; retries must preserve every observation."""
        records = []
        columns = CHECK_COLUMNS + ("created_at",)
        with self._connect(write=True) as connection:
            prepared = [self._prepare_check(connection, item) for item in checks]
            for validated, data in prepared:
                existing = connection.execute(
                    "SELECT * FROM checks WHERE check_id = ?", (validated.check_id,)
                ).fetchone()
                if existing:
                    record = self._check_record(existing)
                    immutable = set(CHECK_COLUMNS) - {"review_status", "reviewer"}
                    expected = validated.model_copy(update={"case_revision": data["case_revision"]})
                    if not allow_unchanged or any(
                        getattr(record, key) != getattr(expected, key) for key in immutable
                    ):
                        raise ConflictError("check ID already exists with conflicting observation")
                    records.append(record)
                    continue
                sql = (
                    f"INSERT INTO checks ({', '.join(columns)}) "
                    f"VALUES ({', '.join('?' for _ in columns)})"
                )
                values = [data[key] for key in CHECK_COLUMNS] + [datetime.now(UTC).isoformat()]
                try:
                    connection.execute(sql, values)
                except sqlite3.IntegrityError as exc:
                    raise ConflictError("check ID already exists") from exc
                row = connection.execute(
                    "SELECT * FROM checks WHERE check_id = ?", (validated.check_id,)
                ).fetchone()
                records.append(self._check_record(row))
        return records

    def get_check(self, check_id: str) -> CheckRecord:
        with self._connect() as connection:
            return self._get_check(connection, check_id)

    @staticmethod
    def _get_check(connection: sqlite3.Connection, check_id: str) -> CheckRecord:
        row = connection.execute("SELECT * FROM checks WHERE check_id = ?", (check_id,)).fetchone()
        if row is None:
            raise NotFoundError(check_id)
        return CaseStore._check_record(row)

    def review_check(self, check_id: str, *, reviewer: str, note: str) -> CheckRecord:
        with self._connect(write=True) as connection:
            record = self._get_check(connection, check_id)
            if record.review_status == "reviewed":
                raise ConflictError(
                    "check is already reviewed; create a new check for a correction"
                )
            if record.source == "synthetic":
                raise ValueError("synthetic checks cannot be reviewed as real results")
            evidence = inspect_evidence(self.evidence_root, record.evidence_refs)
            if record.observed_evidence and evidence != record.observed_evidence:
                raise ValueError("evidence changed since observation; keep the original check")
            reviewed = CheckRecord.model_validate(
                {
                    **record.model_dump(),
                    "review_status": "reviewed",
                    "reviewer": reviewer,
                    "review_note": note,
                    "reviewed_at": datetime.now(UTC).isoformat(timespec="microseconds"),
                    "evidence_metadata": [item.model_dump() for item in evidence],
                }
            )
            connection.execute(
                "UPDATE checks SET review_status = ?, reviewer = ?, review_note = ?, "
                "reviewed_at = ?, evidence_metadata = ? WHERE check_id = ?",
                (
                    "reviewed",
                    reviewed.reviewer,
                    reviewed.review_note,
                    reviewed.reviewed_at,
                    json.dumps([item.model_dump() for item in evidence]),
                    check_id,
                ),
            )
            return self._get_check(connection, check_id)

    def verify_check_evidence(self, check_id: str) -> bool:
        record = self.get_check(check_id)
        if record.review_status != "reviewed":
            raise ValueError("check has not been reviewed with evidence")
        current = inspect_evidence(self.evidence_root, record.evidence_refs)
        return current == record.evidence_metadata

    def list_checks(self, case_id: str) -> list[CheckRecord]:
        with self._connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if exists is None:
                raise NotFoundError(case_id)
            rows = connection.execute(
                "SELECT * FROM checks WHERE case_id = ? ORDER BY observed_at, check_id",
                (case_id,),
            ).fetchall()
            return [self._check_record(row) for row in rows]
