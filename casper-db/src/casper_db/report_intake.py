"""Durable offline intake, review and explicit publication in a NEW owned workspace."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .hwp import parse_report
from .import_workflow import (
    ImportPackage,
    ReportReview,
    assigned_case_id,
    digest,
    prepare_import,
    review_template,
)
from .narrative import VERSION as NARRATIVE_VERSION
from .report_drafts import ReportDraft
from .repository import COLUMNS, CaseStore, ConflictError, NotFoundError, initialize_database

INTAKE_APP_ID = 0x43415051
CASE_APP_ID = 0x43415043
SCHEMA = """
CREATE TABLE metadata (workspace_id TEXT PRIMARY KEY);
CREATE TABLE sources (
    source_sha TEXT PRIMARY KEY, filename TEXT NOT NULL, target_id TEXT NOT NULL,
    source_kind TEXT NOT NULL, raw BLOB NOT NULL
);
CREATE TABLE drafts (
    draft_sha TEXT PRIMARY KEY, extraction_key TEXT UNIQUE NOT NULL,
    source_sha TEXT NOT NULL REFERENCES sources(source_sha), snapshot TEXT NOT NULL
);
CREATE TABLE reviews (
    review_sha TEXT PRIMARY KEY, draft_sha TEXT NOT NULL REFERENCES drafts(draft_sha),
    snapshot TEXT NOT NULL, recorded_at TEXT NOT NULL
);
CREATE TABLE validations (
    validation_sha TEXT PRIMARY KEY, review_sha TEXT NOT NULL REFERENCES reviews(review_sha),
    snapshot TEXT NOT NULL, recorded_at TEXT NOT NULL
);
CREATE TABLE active_validations (
    draft_sha TEXT PRIMARY KEY REFERENCES drafts(draft_sha),
    validation_sha TEXT NOT NULL REFERENCES validations(validation_sha)
);
CREATE TABLE receipts (
    draft_sha TEXT NOT NULL REFERENCES drafts(draft_sha),
    validation_sha TEXT NOT NULL REFERENCES validations(validation_sha),
    case_id TEXT NOT NULL, case_sha TEXT NOT NULL, outcome TEXT NOT NULL,
    recorded_at TEXT NOT NULL, PRIMARY KEY(draft_sha, validation_sha, case_id)
);
"""


class ReportIntake:
    """Only open databases created together by create(); never use global --db."""

    def __init__(self, workspace: Path):
        self.root = Path(workspace).expanduser().resolve(strict=True)
        manifest_path = self.root / "workspace.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema_version") not in ("report-db-workspace-1", "report-db-workspace-2"):
            raise ValueError("not an owned report DB workspace")
        self.workspace_id = manifest["workspace_id"]
        self.attached = manifest["schema_version"] == "report-db-workspace-2"
        self.state_path = self._owned_path("intake.sqlite3")
        self.case_path = (
            Path(manifest["case_path"]).expanduser().resolve(strict=True)
            if self.attached else self._owned_path("cases.sqlite3")
        )
        self._verify_database(self.state_path, INTAKE_APP_ID)
        if self.attached:
            if not self.case_path.is_file():
                raise ValueError("attached Case DB is not a file")
            with CaseStore(self.case_path)._connect():
                pass
        else:
            self._verify_database(self.case_path, CASE_APP_ID)
        with self._connect() as connection:
            row = connection.execute("SELECT workspace_id FROM metadata").fetchone()
            if row is None or row[0] != self.workspace_id:
                raise ValueError("workspace identity does not match intake DB")

    @classmethod
    def create(cls, workspace: Path) -> ReportIntake:
        root = Path(workspace).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=False)
        workspace_id = uuid4().hex
        connection = sqlite3.connect(root / "intake.sqlite3")
        try:
            connection.executescript(SCHEMA)
            connection.execute("INSERT INTO metadata VALUES (?)", (workspace_id,))
            connection.execute(f"PRAGMA application_id = {INTAKE_APP_ID}")
            connection.execute("PRAGMA user_version = 1")
            connection.commit()
        finally:
            connection.close()
        case_path = initialize_database(root / "cases.sqlite3")
        connection = sqlite3.connect(case_path)
        try:
            connection.execute(f"PRAGMA application_id = {CASE_APP_ID}")
            connection.commit()
        finally:
            connection.close()
        with (root / "workspace.json").open("x", encoding="utf-8") as stream:
            json.dump(
                {"schema_version": "report-db-workspace-1", "workspace_id": workspace_id}, stream
            )
        return cls(root)

    @classmethod
    def create_attached(cls, workspace: Path, case_path: Path) -> ReportIntake:
        """Create an intake next to an existing Case DB used by the runtime.

        The Case DB path is supplied by server configuration, never by an upload.
        Existing Case rows and versions stay in place.
        """
        case_path = initialize_database(case_path)
        root = Path(workspace).expanduser().resolve()
        if root == case_path.parent or case_path.is_relative_to(root):
            raise ValueError("intake workspace must be separate from the Case DB")
        root.mkdir(parents=True, exist_ok=False)
        workspace_id = uuid4().hex
        connection = sqlite3.connect(root / "intake.sqlite3")
        try:
            connection.executescript(SCHEMA)
            connection.execute("INSERT INTO metadata VALUES (?)", (workspace_id,))
            connection.execute(f"PRAGMA application_id = {INTAKE_APP_ID}")
            connection.execute("PRAGMA user_version = 1")
            connection.commit()
        finally:
            connection.close()
        with (root / "workspace.json").open("x", encoding="utf-8") as stream:
            json.dump({"schema_version": "report-db-workspace-2", "workspace_id": workspace_id,
                       "case_path": str(case_path)}, stream)
        return cls(root)

    def _owned_path(self, filename):
        path = (self.root / filename).resolve(strict=True)
        if path.parent != self.root or not path.is_file():
            raise ValueError("workspace DB must be an owned local file")
        return path

    @staticmethod
    def _verify_database(path, application_id):
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        try:
            if connection.execute("PRAGMA application_id").fetchone()[0] != application_id:
                raise ValueError("refusing a database not created for this workspace")
        finally:
            connection.close()

    @contextmanager
    def _connect(self, *, write=False):
        path = self._owned_path("intake.sqlite3")
        connection = sqlite3.connect(
            path.as_uri() + ("?mode=rw" if write else "?mode=ro"), uri=True, timeout=5
        )
        connection.row_factory = sqlite3.Row
        try:
            if connection.execute("PRAGMA application_id").fetchone()[0] != INTAKE_APP_ID:
                raise ValueError("not an intake database")
            connection.execute("PRAGMA foreign_keys = ON")
            if write:
                connection.execute("BEGIN IMMEDIATE")
            with connection:
                yield connection
        finally:
            connection.close()

    def _case_store(self):
        if not self.attached:
            self._verify_database(self.case_path, CASE_APP_ID)
        return CaseStore(self.case_path)

    @staticmethod
    def _load(connection, draft_sha):
        row = connection.execute(
            "SELECT d.snapshot, s.* FROM drafts d JOIN sources s USING(source_sha) "
            "WHERE d.draft_sha = ?",
            (draft_sha,),
        ).fetchone()
        if row is None:
            raise NotFoundError(draft_sha)
        report = ReportDraft.model_validate_json(row["snapshot"])
        if (
            digest(report) != draft_sha
            or hashlib.sha256(row["raw"]).hexdigest() != row["source_sha"]
        ):
            raise ValueError("stored report or raw source integrity mismatch")
        if report.source["sha256"] != row["source_sha"]:
            raise ValueError("stored draft does not match raw source")
        return report, row

    @staticmethod
    def _save_validation(connection, report, review, target_id):
        for item in review.items:
            target = item.resolutions.get("target_id")
            if target and target.value != target_id:
                raise ValueError("report must keep its staged target_id")
        package = prepare_import(report, review, target_id=target_id)
        draft_sha, review_sha = digest(report), digest(review)
        now = datetime.now(UTC).isoformat()
        connection.execute(
            "INSERT OR IGNORE INTO reviews VALUES (?, ?, ?, ?)",
            (review_sha, draft_sha, review.model_dump_json(), now),
        )
        connection.execute(
            "INSERT OR IGNORE INTO validations VALUES (?, ?, ?, ?)",
            (package.package_sha256, review_sha, package.model_dump_json(), now),
        )
        connection.execute(
            "INSERT INTO active_validations VALUES (?, ?) ON CONFLICT(draft_sha) "
            "DO UPDATE SET validation_sha = excluded.validation_sha",
            (draft_sha, package.package_sha256),
        )
        return package

    @staticmethod
    def _active(connection, report, target_id):
        row = connection.execute(
            "SELECT v.validation_sha, v.snapshot FROM active_validations a JOIN validations v "
            "USING(validation_sha) WHERE a.draft_sha = ?",
            (digest(report),),
        ).fetchone()
        if row is None:
            raise ValueError("stored report has no active validation")
        package = ImportPackage.model_validate_json(row["snapshot"])
        expected = prepare_import(report, package.review, target_id=target_id)
        if expected != package or expected.package_sha256 != row["validation_sha"]:
            raise ValueError("validation is stale or altered; inspect and submit a review again")
        return expected

    def stage(
        self,
        source: Path,
        *,
        target_id: str,
        source_kind="imported",
        local_ocr=False,
        ocr_language="ko",
        managed_source=False,
    ):
        report = parse_report(
            source,
            target_id=target_id,
            source_kind=source_kind,
            local_ocr=local_ocr,
            ocr_language=ocr_language,
        )
        if managed_source:
            reference = f"intake:{report.source['sha256']}"
            report.source["path"] = reference
            for finding in report.findings:
                finding.candidate.source_report = reference
        raw = Path(source).read_bytes()
        if hashlib.sha256(raw).hexdigest() != report.source["sha256"]:
            raise ValueError("source changed during extraction")
        key = digest(
            {
                "source": report.source["sha256"],
                "target": target_id,
                "kind": source_kind,
                "extractor": report.extractor_version,
                "narrative": NARRATIVE_VERSION,
                "ocr": report.document.get("local_ocr", {}).get("fingerprint"),
            }
        )
        with self._connect(write=True) as connection:
            existing = connection.execute(
                "SELECT * FROM sources WHERE source_sha = ?", (report.source["sha256"],)
            ).fetchone()
            if existing and (
                existing["target_id"] != target_id or existing["source_kind"] != source_kind
            ):
                raise ValueError("the same report must keep its target and source_kind")
            duplicate = connection.execute(
                "SELECT draft_sha FROM drafts WHERE extraction_key = ?", (key,)
            ).fetchone()
            if duplicate:
                self._load(connection, duplicate[0])
                draft_sha = duplicate[0]
            else:
                connection.execute(
                    "INSERT OR IGNORE INTO sources VALUES (?, ?, ?, ?, ?)",
                    (
                        report.source["sha256"],
                        report.source["filename"],
                        target_id,
                        source_kind,
                        raw,
                    ),
                )
                draft_sha = digest(report)
                connection.execute(
                    "INSERT INTO drafts VALUES (?, ?, ?, ?)",
                    (draft_sha, key, report.source["sha256"], report.model_dump_json()),
                )
                self._save_validation(connection, report, review_template(report), target_id)
        exported = self.export(draft_sha)
        return {
            "draft_sha256": draft_sha,
            "findings": len(report.findings),
            "staging_database_written": not bool(duplicate),
            "case_database_written": False,
            **exported,
            "reused": bool(duplicate),
        }

    def export(self, draft_sha):
        with self._connect() as connection:
            report, _ = self._load(connection, draft_sha)
        folder = (self.root / "exports" / draft_sha).resolve()
        if not folder.is_relative_to(self.root):
            raise ValueError("exports must stay inside workspace")
        folder.mkdir(parents=True, exist_ok=True)
        pending = review_template(report).model_dump(mode="json")
        values = {
            "report.draft.json": report.model_dump(mode="json"),
            "report.review.pending.json": pending,
            "report.review.json": pending,
        }
        for name, value in values.items():
            path = folder / name
            if not path.exists():
                with path.open("x", encoding="utf-8") as stream:
                    json.dump(value, stream, ensure_ascii=False, indent=2)
                    stream.write("\n")
        return {
            "draft_file": str(folder / "report.draft.json"),
            "review_file": str(folder / "report.review.json"),
        }

    def submit_review(self, draft_sha: str, review: ReportReview,
                      *, expected_validation_sha: str | None = None):
        with self._connect(write=True) as connection:
            report, source = self._load(connection, draft_sha)
            if expected_validation_sha is not None:
                active = connection.execute(
                    "SELECT validation_sha FROM active_validations WHERE draft_sha = ?",
                    (draft_sha,),
                ).fetchone()
                if active is None or active[0] != expected_validation_sha:
                    raise ConflictError("review changed since it was opened")
            package = self._save_validation(connection, report, review, source["target_id"])
        return {
            "draft_sha256": draft_sha,
            "validation_sha256": package.package_sha256,
            "ready_cases": len(package.cases),
            "blocked": package.blocked,
            "staging_database_written": True,
            "case_database_written": False,
        }

    @staticmethod
    def _write_receipt(connection, draft_sha, package, record, outcome):
        case_sha = digest({name: getattr(record, name) for name in COLUMNS})
        connection.execute(
            "INSERT OR IGNORE INTO receipts VALUES (?, ?, ?, ?, ?, ?)",
            (
                draft_sha,
                package.package_sha256,
                record.case_id,
                case_sha,
                outcome,
                datetime.now(UTC).isoformat(),
            ),
        )

    def publish(self, draft_sha: str, *, apply=False, ready_only=False,
                expected_validation_sha: str | None = None):
        # Lock the active review until Case commit and receipt are complete. If a process
        # dies between the two DB commits, add_many's unchanged result repairs the receipt.
        with self._connect(write=apply) as connection:
            report, source = self._load(connection, draft_sha)
            package = self._active(connection, report, source["target_id"])
            if expected_validation_sha is not None and package.package_sha256 != expected_validation_sha:
                raise ConflictError("review changed since it was opened")
            eligible = package.cases if ready_only or not package.blocked else []
            result = {
                "draft_sha256": draft_sha,
                "mode": "apply" if apply else "dry_run",
                "ready_only": ready_only,
                "eligible_cases": len(eligible),
                "blocked": package.blocked,
                "case_database_written": False,
                "created": 0,
                "unchanged": 0,
            }
            if not eligible:
                result["status"] = (
                    "excluded" if package.excluded and not package.blocked else "needs_review"
                )
                return result
            result["status"] = "ready_subset" if package.blocked else "ready"
            if not apply:
                return result
            records = self._case_store().add_many(eligible)
            for outcome, rows in records.items():
                result[outcome] = len(rows)
                for record in rows:
                    self._write_receipt(connection, draft_sha, package, record, outcome)
            result.update(
                status="applied_subset" if package.blocked else "applied",
                case_database_written=bool(records["created"]),
            )
            return result

    def show(self, draft_sha: str | None = None):
        reports = []
        store = self._case_store()
        with self._connect() as connection:
            ids = (
                [draft_sha]
                if draft_sha
                else [
                    row[0]
                    for row in connection.execute("SELECT draft_sha FROM drafts ORDER BY rowid")
                ]
            )
            for selected in ids:
                report, source = self._load(connection, selected)
                package = self._active(connection, report, source["target_id"])
                blocked = {entry["draft_id"]: entry for entry in package.blocked}
                excluded = {entry["draft_id"] for entry in package.excluded}
                ready = {case.case_id: case for case in package.cases}
                findings = []
                for finding in report.findings:
                    case_id = assigned_case_id(report, finding.source_ref)
                    state = (
                        "excluded"
                        if finding.draft_id in excluded
                        else ("ready" if case_id in ready else "needs_review")
                    )
                    try:
                        record = store.get(case_id)
                    except NotFoundError:
                        record = None
                    receipt = connection.execute(
                        "SELECT case_sha FROM receipts WHERE draft_sha = ? AND validation_sha = ? "
                        "AND case_id = ?",
                        (selected, package.package_sha256, case_id),
                    ).fetchone()
                    if record:
                        actual = {name: getattr(record, name) for name in COLUMNS}
                        expected = ready.get(case_id)
                        if expected is None:
                            state = "published_previous_review"
                        elif digest(actual) != digest(expected):
                            state = "conflict"
                        elif receipt:
                            if receipt[0] != digest(actual):
                                raise ValueError("receipt does not match stored Case")
                            state = "published"
                        else:
                            state = "stored_awaiting_receipt"
                    entry = {
                        "draft_id": finding.draft_id,
                        "case_id": case_id,
                        "endpoint": finding.candidate.endpoint,
                        "state": state,
                        "missing_fields": finding.missing_fields,
                        "unresolved_fields": finding.unresolved_fields,
                        "remaining_fields": blocked.get(finding.draft_id, {}).get(
                            "remaining_fields", []
                        ),
                        "case_record": record.model_dump(mode="json") if record else None,
                    }
                    if draft_sha:
                        entry["finding"] = finding.model_dump(mode="json")
                    findings.append(entry)
                item = {
                    "draft_sha256": selected,
                    "source_sha256": source["source_sha"],
                    "source_filename": source["filename"],
                    "source_bytes": len(source["raw"]),
                    "target_id": source["target_id"],
                    "source_kind": source["source_kind"],
                    "review_sha256": package.review_sha256,
                    "validation_sha256": package.package_sha256,
                    "findings": findings,
                }
                if draft_sha:
                    item.update(
                        draft=report.model_dump(mode="json"),
                        review=package.review.model_dump(mode="json"),
                        validation=package.model_dump(mode="json"),
                    )
                reports.append(item)
        return {
            "workspace": str(self.root),
            "intake_database": str(self.state_path),
            "case_database": str(self.case_path),
            "reports": reports,
            "case_database_written": False,
        }

    def delete_draft(self, draft_sha: str):
        """Remove only an unpublished intake; published Case evidence is immutable."""
        if not isinstance(draft_sha, str) or len(draft_sha) != 64 or any(
            char not in "0123456789abcdef" for char in draft_sha
        ):
            raise ValueError("invalid draft SHA-256")
        store = self._case_store()
        with self._connect(write=True) as connection:
            report, source = self._load(connection, draft_sha)
            receipt = connection.execute(
                "SELECT 1 FROM receipts WHERE draft_sha = ? LIMIT 1", (draft_sha,)
            ).fetchone()
            if receipt:
                raise ValueError("published intake cannot be deleted")
            for finding in report.findings:
                try:
                    store.get(assigned_case_id(report, finding.source_ref))
                except NotFoundError:
                    continue
                raise ValueError("intake has a stored Case and cannot be deleted")
            connection.execute("DELETE FROM active_validations WHERE draft_sha = ?", (draft_sha,))
            connection.execute(
                "DELETE FROM validations WHERE review_sha IN "
                "(SELECT review_sha FROM reviews WHERE draft_sha = ?)", (draft_sha,)
            )
            connection.execute("DELETE FROM reviews WHERE draft_sha = ?", (draft_sha,))
            connection.execute("DELETE FROM drafts WHERE draft_sha = ?", (draft_sha,))
            if not connection.execute(
                "SELECT 1 FROM drafts WHERE source_sha = ? LIMIT 1", (source["source_sha"],)
            ).fetchone():
                connection.execute("DELETE FROM sources WHERE source_sha = ?", (source["source_sha"],))
        folder = (self.root / "exports" / draft_sha).resolve()
        if folder.is_relative_to(self.root) and folder.is_dir():
            shutil.rmtree(folder)
        return {"draft_sha256": draft_sha, "deleted": True}
