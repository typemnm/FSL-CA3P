#!/usr/bin/env python3
"""Private SQLite snapshots and explicit device schema migration.

The deployer must stop all writers before migrate/restore. Backup uses SQLite's
online backup API through a read-only source connection, including committed WAL
records. No service, credentials, or deployment configuration is accessed here.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone


BACKUP_FORMAT = 1
FILES = {"run": "run.sqlite3", "case": "case.sqlite3", "chat": "chat.sqlite3"}
CHAT_TABLES = {"chat_sessions", "chat_messages"}
CASE_REQUIRED_TABLES = {"cases", "checks", "case_versions"}
# These namespaces share the versioned Case database, but are created only when
# their owning feature is used. Keep legacy Case stores valid rollback targets.
CASE_OPTIONAL_COLUMNS = {
    "attack_catalog_metadata": {"key", "value"},
    "attack_catalog_sources": {"source_ref", "content_sha256", "schema_version", "snapshot", "imported_at"},
    "attack_patterns": {"pattern_id", "revision", "content_sha256", "vulnerability_type", "application",
                        "endpoint", "cwe", "source_ref", "source_sha256", "snapshot", "created_at"},
    "attack_payloads": {"pattern_id", "pattern_revision", "payload_id", "snapshot"},
    "attack_verification_rules": {"rule_id", "pattern_id", "pattern_revision", "payload_id", "snapshot"},
    "attack_templates": {"template_id", "version", "pattern_id", "pattern_revision", "content_sha256", "snapshot", "created_at"},
    "attack_template_rules": {"template_id", "template_version", "rule_id"},
    "external_metadata": {"key", "value"},
    "external_sources": {"raw_sha256", "source", "source_url", "retrieved_at", "raw_json"},
    "external_revisions": {"record_id", "content_sha256", "record_json"},
    "external_records": {"record_id", "cve_id", "modified_at", "content_sha256", "record_json"},
    "external_provenance": {"record_id", "content_sha256", "raw_sha256"},
    "external_assessments": {"assessment_id", "target_id", "cve_id", "record_id", "inventory_sha", "snapshot"},
    "external_active_inventory": {"target_id", "inventory_sha", "observed_at"},
    "external_sync_runs": {"job_id", "target_id", "started_at", "status", "receipt"},
    "dashboard_case_state": {"case_id", "archived_at", "archived_by", "reason"},
    "dashboard_case_audit": {"id", "case_id", "action", "actor", "recorded_at", "details"},
}
CASE_NAMESPACE_MARKERS = {
    "attack_catalog_metadata": "casper-attack-catalog-1",
    "external_metadata": "external-vuln-1",
}
CASE_TABLES = CASE_REQUIRED_TABLES | CASE_OPTIONAL_COLUMNS.keys()
RUN_REQUIRED_TABLES = {"runs", "jobs", "run_events", "action_intents", "model_calls", "artifacts", "review_audit"}
# Version 1 stores gained these tables without changing user_version. Older
# releases remain valid rollback targets, so validate additions only if present.
RUN_OPTIONAL_COLUMNS = {
    "experiment_control": {"id", "status", "owner", "epoch", "last_reset_at", "summary_json", "error"},
    "pending_target_resets": {"id", "obligations_json"},
}
RUN_TABLES = RUN_REQUIRED_TABLES | RUN_OPTIONAL_COLUMNS.keys()


def resolved(value: str | Path) -> Path:
    return Path(value).expanduser().resolve()


def connect_readonly(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)


def columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')}


def inspect_db(path: Path, kind: str) -> dict:
    result = {"path": str(path), "exists": path.exists(), "userVersion": None,
              "counts": {}, "quickCheck": None, "foreignKeyCheck": None}
    if not result["exists"]:
        if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
            raise ValueError(f"{kind} database is absent but SQLite sidecars exist")
        return result
    if not path.is_file():
        raise ValueError(f"{kind} database is not a regular file")
    with closing(connect_readonly(path)) as connection:
        result["userVersion"] = connection.execute("PRAGMA user_version").fetchone()[0]
        tables = sorted(row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"))
        # Count known tables only; do not interpolate names from an unrelated DB.
        known = CASE_TABLES if kind == "case" else CHAT_TABLES if kind == "chat" else RUN_TABLES
        result["tables"] = tables
        result["counts"] = {name: connection.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]
                            for name in tables if name in known}
        checks = [row[0] for row in connection.execute("PRAGMA quick_check")]
        result["quickCheck"] = "ok" if checks == ["ok"] else "failed"
        result["foreignKeyCheck"] = "ok" if not connection.execute("PRAGMA foreign_key_check").fetchmany(1) else "failed"
    return result


def validate_identity(info: dict, kind: str) -> None:
    """Refuse to migrate/delete a database belonging to another application."""
    if not info["exists"]:
        return
    if info["quickCheck"] != "ok" or info["foreignKeyCheck"] != "ok":
        raise ValueError(f"{kind} database failed SQLite integrity checks")
    tables = set(info.get("tables", []))
    version = info["userVersion"]
    if version == 0 and not tables:
        return
    allowed = CASE_TABLES if kind == "case" else CHAT_TABLES if kind == "chat" else RUN_TABLES
    if tables - allowed:
        raise ValueError(f"refusing unrelated {kind} database with unknown tables")
    if kind == "chat":
        if version != 1 or tables != CHAT_TABLES:
            raise ValueError("unsupported or unrelated chat database schema")
        with closing(connect_readonly(Path(info["path"]))) as connection:
            if not {"id", "owner", "title", "model_id", "summary", "compacted_through_sequence",
                    "compaction_count", "created_at", "updated_at"} <= columns(connection, "chat_sessions"):
                raise ValueError("refusing unrelated chat session columns")
            if not {"id", "session_id", "sequence", "role", "content", "status", "metadata_json",
                    "created_at"} <= columns(connection, "chat_messages"):
                raise ValueError("refusing unrelated chat message columns")
    elif kind == "case":
        if version not in range(1, 8) or "cases" not in tables:
            raise ValueError("unsupported or unrelated case database schema")
        required = {"case_id", "target_id", "title", "endpoint", "method", "parameter",
                    "preconditions", "procedure", "success_condition", "source_report", "status"}
        with closing(connect_readonly(Path(info["path"]))) as connection:
            if not required <= columns(connection, "cases"):
                raise ValueError("refusing unrelated case database columns")
            for table, required in CASE_OPTIONAL_COLUMNS.items():
                if table in tables and not required <= columns(connection, table):
                    raise ValueError(f"refusing unrelated case database columns in {table}")
            for table, expected in CASE_NAMESPACE_MARKERS.items():
                if table in tables:
                    marker = connection.execute(f'SELECT value FROM "{table}" WHERE key=?', ("schema",)).fetchone()
                    if marker is None or marker[0] != expected:
                        raise ValueError(f"unsupported case database namespace marker in {table}")
        if version >= 5 and not CASE_REQUIRED_TABLES <= tables:
            raise ValueError("incomplete versioned case database schema")
    else:
        if version != 1 or not RUN_REQUIRED_TABLES <= tables:
            raise ValueError("unsupported or unrelated run database schema")
        with closing(connect_readonly(Path(info["path"]))) as connection:
            if not {"id", "status", "manifest_json", "state_json"} <= columns(connection, "runs"):
                raise ValueError("refusing unrelated run database columns")
            for table, required in RUN_OPTIONAL_COLUMNS.items():
                if table in tables and not required <= columns(connection, table):
                    raise ValueError(f"refusing unrelated run database columns in {table}")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def fsync_file(path: Path) -> None:
    with path.open("rb") as file:
        os.fsync(file.fileno())


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def snapshot(source: Path, target: Path) -> None:
    # The destination is a standalone database; do not copy an uncheckpointed
    # main file or retain a dependency on its original -wal/-shm files.
    with closing(connect_readonly(source)) as source_connection, closing(sqlite3.connect(target)) as destination:
        source_connection.backup(destination)
        destination.execute("PRAGMA journal_mode=DELETE")
    os.chmod(target, 0o600)
    fsync_file(target)


def paths(args: argparse.Namespace) -> dict[str, Path]:
    result = {"run": resolved(args.run_db), "case": resolved(args.case_db)}
    if getattr(args, "chat_db", None):
        result["chat"] = resolved(args.chat_db)
    if len(set(result.values())) != len(result):
        raise ValueError("database paths must be different")
    return result


def inspect_command(args: argparse.Namespace) -> dict:
    return {"databases": {kind: inspect_db(path, kind) for kind, path in paths(args).items()}}


def backup_command(args: argparse.Namespace) -> dict:
    source_paths = paths(args)
    output = resolved(args.output)
    for filename in FILES.values():
        if output / filename in source_paths.values():
            raise ValueError("backup output would overwrite a source database")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("backup output must be a new or empty directory")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output, 0o700)
    entries = {}
    for kind, source in source_paths.items():
        before = inspect_db(source, kind)
        validate_identity(before, kind)
        entry = {"source": str(source), "exists": before["exists"], "file": None,
                 "sha256": None, "size": None, "info": before}
        if before["exists"]:
            destination = output / FILES[kind]
            snapshot(source, destination)
            copied = inspect_db(destination, kind)
            validate_identity(copied, kind)
            entry.update(file=FILES[kind], sha256=digest(destination), size=destination.stat().st_size,
                         info={**copied, "path": str(source)})
        entries[kind] = entry
    manifest = {"format": BACKUP_FORMAT, "createdAt": datetime.now(timezone.utc).isoformat(),
                "databases": entries}
    manifest_path = output / "manifest.json"
    with manifest_path.open("x", encoding="utf-8") as file:
        json.dump(manifest, file, ensure_ascii=False, indent=2)
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())
    os.chmod(manifest_path, 0o600)
    fsync_directory(output)
    return {"backup": str(output), "manifest": str(manifest_path), "databases": entries}


def validate_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.is_symlink() or (sidecar.exists() and not sidecar.is_file()):
            raise ValueError("refusing non-file SQLite sidecar")


def remove_sidecars(path: Path) -> None:
    # Only migrate/restore call this, after the deployer has stopped all writers.
    validate_sidecars(path)
    for suffix in ("-wal", "-shm", "-journal"):
        Path(str(path) + suffix).unlink(missing_ok=True)


def stage_path(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".device-", dir=path.parent)
    os.close(descriptor)
    return Path(temporary)


def migrate_command(args: argparse.Namespace) -> dict:
    path = resolved(args.case_db)
    before = inspect_db(path, "case")
    validate_identity(before, "case")
    # Import only for explicit migration, using this release's venv and source.
    from casper_db import initialize_database
    from casper_db.repository import SCHEMA_VERSION

    staged = stage_path(path)
    try:
        if before["exists"]:
            snapshot(path, staged)
        initialize_database(staged)
        with closing(sqlite3.connect(staged)) as connection:
            connection.execute("PRAGMA journal_mode=DELETE")
        after = inspect_db(staged, "case")
        validate_identity(after, "case")
        if after["userVersion"] != SCHEMA_VERSION:
            raise ValueError("case migration did not reach the release schema")
        for table, count in before["counts"].items():
            if after["counts"].get(table) != count:
                raise ValueError(f"migration changed the preserved {table} row count")
        changed = not before["exists"] or before["userVersion"] != after["userVersion"]
        if changed:
            os.chmod(staged, 0o600)
            fsync_file(staged)
            remove_sidecars(path)
            os.replace(staged, path)
            fsync_directory(path.parent)
        return {"before": before, "after": {**after, "path": str(path)},
                "changed": changed, "preservedCounts": before["counts"]}
    finally:
        staged.unlink(missing_ok=True)
        for suffix in ("-wal", "-shm", "-journal"):
            Path(str(staged) + suffix).unlink(missing_ok=True)


def restore_command(args: argparse.Namespace) -> dict:
    target_paths = paths(args)
    backup = resolved(args.backup)
    manifest_path = backup / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > 100_000:
        raise ValueError("invalid backup manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("format") != BACKUP_FORMAT:
        raise ValueError("unsupported backup manifest")
    entries = manifest.get("databases")
    if not isinstance(entries, dict) or set(entries) != set(target_paths):
        raise ValueError("backup must describe exactly the requested databases")
    staged = {}
    try:
        # Validate *every* source and target before changing either target.
        for kind, path in target_paths.items():
            entry = entries[kind]
            if not isinstance(entry, dict) or entry.get("source") != str(path) or type(entry.get("exists")) is not bool:
                raise ValueError("backup database source path does not match the restore target")
            # A failed/new release may have left a corrupt or newer schema. The
            # private snapshot's exact original path authorizes rollback there;
            # requiring the broken live DB to pass checks would prevent recovery.
            if path.exists() and not path.is_file():
                raise ValueError("restore target is not a regular file")
            validate_sidecars(path)
            if not entry["exists"]:
                if any(entry.get(key) is not None for key in ("file", "sha256", "size")):
                    raise ValueError("invalid absent database backup")
                staged[kind] = None
                continue
            source = backup / FILES[kind]
            if entry.get("file") != FILES[kind] or source.is_symlink() or not source.is_file():
                raise ValueError("invalid backup database file")
            if any(Path(str(source) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
                raise ValueError("backup database must be a standalone snapshot without sidecars")
            if type(entry.get("size")) is not int or source.stat().st_size != entry["size"] or digest(source) != entry.get("sha256"):
                raise ValueError("backup database hash or size mismatch")
            info = inspect_db(source, kind)
            validate_identity(info, kind)
            expected = entry.get("info", {})
            if not isinstance(expected, dict) or any(info.get(key) != expected.get(key) for key in ("userVersion", "counts", "quickCheck", "foreignKeyCheck")):
                raise ValueError("backup metadata does not match the database")
            temporary = stage_path(path)
            staged[kind] = temporary
            shutil.copyfile(source, temporary)
            os.chmod(temporary, 0o600)
            fsync_file(temporary)
        for kind, path in target_paths.items():
            remove_sidecars(path)
            if staged[kind] is None:
                path.unlink(missing_ok=True)
            else:
                os.replace(staged[kind], path)
            if path.parent.exists():
                fsync_directory(path.parent)
        return {"backup": str(backup), "databases": {kind: inspect_db(path, kind) for kind, path in target_paths.items()}}
    finally:
        for temporary in staged.values():
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "backup", "restore"):
        command = commands.add_parser(name)
        command.add_argument("--run-db", required=True)
        command.add_argument("--case-db", required=True)
        command.add_argument("--chat-db")
        if name == "backup":
            command.add_argument("--output", required=True)
        elif name == "restore":
            command.add_argument("--backup", required=True)
    commands.add_parser("migrate").add_argument("--case-db", required=True)
    args = parser.parse_args()
    try:
        result = globals()[args.command + "_command"](args)
        print(json.dumps({"ok": True, "command": args.command, **result}, ensure_ascii=False))
        return 0
    except Exception as error:
        print(json.dumps({"ok": False, "command": args.command, "error": str(error)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
