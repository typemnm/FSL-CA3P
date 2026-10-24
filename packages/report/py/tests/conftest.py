from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest
from fixtures import CASE_ID, stored_xss_events, stored_xss_report

HELPER = Path(__file__).with_name("write_sources.mjs")
REPO = Path(__file__).resolve().parents[4]


def _node_ready() -> bool:
    node = shutil.which("node")
    if not node:
        return False
    probe = subprocess.run([node, "-e", "require('node:sqlite')"], capture_output=True)
    return probe.returncode == 0


NODE_READY = _node_ready()
needs_node = pytest.mark.skipif(not NODE_READY, reason="node with node:sqlite is required")


@contextmanager
def linked_entry(target: Path, link: Path, *, directory: bool = False):
    """Use a real link when permitted; emulate its stat on Windows without link privilege.

    Linux CI keeps the filesystem integration checks. The Windows fallback still exercises
    the production link guards, without requiring an administrator or skipping the check.
    """
    try:
        os.symlink(target, link, target_is_directory=directory)
    except OSError as exc:
        if getattr(exc, "winerror", None) != 1314:
            raise
        original_lstat, original_is_symlink = Path.lstat, Path.is_symlink

        def lstat(path, *args, **kwargs):
            if path == link:
                return os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            return original_lstat(path, *args, **kwargs)

        def is_symlink(path):
            return path == link or original_is_symlink(path)

        with patch.object(Path, "lstat", lstat), patch.object(Path, "is_symlink", is_symlink):
            yield False
    else:
        yield True


def write_sources(
    *,
    run_id: str,
    events: list[dict],
    report: dict | None,
    reports_dir: Path | None = None,
    store_path: Path | None = None,
    legacy_store_path: Path | None = None,
    failed_append: bool = False,
) -> None:
    spec = {
        "runId": run_id,
        "events": events,
        "report": report,
        "reportsDir": str(reports_dir) if reports_dir else None,
        "storePath": str(store_path) if store_path else None,
        "legacyStorePath": str(legacy_store_path) if legacy_store_path else None,
        "failedAppend": failed_append,
    }
    result = subprocess.run(
        ["node", str(HELPER)], input=json.dumps(spec), text=True, capture_output=True, cwd=REPO
    )
    assert result.returncode == 0, result.stderr


SQLITE_SIDECARS = ("-wal", "-shm")


def tree_digest(root: Path) -> dict[str, str]:
    """Content digest of a source tree. SQLite WAL sidecars that a read-only connection may
    create are excluded, but any non-empty WAL fails the check: it would hold changed data."""
    digests = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name.endswith(SQLITE_SIDECARS):
            assert not path.name.endswith("-wal") or path.stat().st_size == 0, path
            continue
        digests[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


@pytest.fixture
def run_id() -> str:
    return "run-1760918400000-abcd1234"


@pytest.fixture
def stored_run(tmp_path: Path, run_id: str) -> dict:
    """The same synthetic run written to both pentest-db disk and run-store."""
    if not NODE_READY:
        pytest.skip("node with node:sqlite is required")
    reports_dir = tmp_path / "pentest-db-runs"
    store_path = tmp_path / "runtime" / "runs.sqlite"
    write_sources(
        run_id=run_id,
        events=stored_xss_events(),
        report=stored_xss_report(run_id),
        reports_dir=reports_dir,
        store_path=store_path,
        failed_append=True,
    )
    return {"reports_dir": reports_dir, "store_path": store_path}


@pytest.fixture
def casper_db(tmp_path: Path) -> Path:
    """A casper-db file built through casper-db's own API (setup only; collectors never write)."""
    casper = pytest.importorskip("casper_db")
    path = casper.initialize_database(tmp_path / "casper" / "cases.sqlite3")
    store = casper.CaseStore(path)
    example = json.loads(
        (REPO / "casper-db/examples/case.example.json").read_text(encoding="utf-8")
    )
    example.update(
        case_id=CASE_ID,
        target_id="vul-web-1",
        endpoint="/api/posts",
        method="POST",
        parameter="content",
        parameter_location="body",
        status="ready",
        vulnerability_url="http://127.0.0.1/api/posts",
        source="synthetic",
    )
    store.add(example)
    store.add_check(
        {
            "check_id": "CHECK-SYN-1",
            "case_id": CASE_ID,
            "run_id": "RUN-SYN-1",
            "target_id": "vul-web-1",
            "endpoint": "/api/posts",
            "method": "POST",
            "parameter": "content",
            "parameter_location": "body",
            "observed_at": "2026-10-01T00:00:00+00:00",
            "result": "inconclusive",
            "observation": "synthetic check",
            "source": "synthetic",
        }
    )
    return path
