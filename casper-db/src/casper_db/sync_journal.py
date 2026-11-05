"""Local collection job receipts, including interrupted jobs in an existing owned DB."""

import json
from uuid import uuid4

from .repository import CaseStore


def begin_sync(database, result):
    if not database.is_file():
        return None
    with CaseStore(database)._connect(write=True) as connection:
        from .external_vulnerabilities import _validate_destination

        _validate_destination(connection)
        connection.execute(
            "CREATE TABLE IF NOT EXISTS external_sync_runs "
            "(job_id TEXT PRIMARY KEY, target_id TEXT NOT NULL, started_at TEXT NOT NULL, "
            "status TEXT NOT NULL, receipt TEXT NOT NULL)"
        )
        job_id = "SYNC-" + uuid4().hex
        connection.execute(
            "INSERT INTO external_sync_runs VALUES (?,?,?,?,?)",
            (
                job_id,
                result["target_id"],
                result["started_at"],
                "running",
                json.dumps({"inventory_sha256": result["inventory_sha256"], "status": "running"}),
            ),
        )
    return job_id


def finish_sync(database, job_id, result):
    if job_id is None:
        job_id = begin_sync(database, result)
    if job_id is None:
        return
    result["journal_id"] = job_id
    with CaseStore(database)._connect(write=True) as connection:
        connection.execute(
            "UPDATE external_sync_runs SET status=?, receipt=? WHERE job_id=?",
            (
                result["status"],
                json.dumps(result, ensure_ascii=False),
                job_id,
            ),
        )


def list_sync_runs(database):
    with CaseStore(database)._connect() as connection:
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='external_sync_runs'"
        ).fetchone()
        if not exists:
            return []
        return [
            {
                "job_id": row[0],
                "target_id": row[1],
                "started_at": row[2],
                "status": row[3],
                "receipt": json.loads(row[4]),
            }
            for row in connection.execute(
                "SELECT * FROM external_sync_runs ORDER BY rowid DESC LIMIT 20",
            )
        ]
