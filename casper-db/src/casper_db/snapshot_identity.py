"""Logical knowledge identity: source revisions, independent of SQLite pages and import times."""

import sqlite3

from .import_workflow import digest


def knowledge_identity(connection: sqlite3.Connection, cases: list, checks: list) -> str:
    tables = {
        row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    value = {"cases": cases, "checks": checks}
    for table, columns in (
        ("external_records", "record_id, content_sha256"),
        ("attack_patterns", "pattern_id, revision, content_sha256"),
        ("attack_templates", "template_id, version, content_sha256"),
    ):
        value[table] = (
            [
                tuple(row)
                for row in connection.execute(
                    f"SELECT {columns} FROM {table} ORDER BY {columns}",
                )
            ]
            if table in tables
            else []
        )
    return digest(value)
