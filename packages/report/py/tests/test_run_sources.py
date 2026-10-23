"""Run collectors against data written by the real pentest-db and run-store code."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest
from conftest import needs_node, tree_digest, write_sources
from fixtures import PAYLOAD, stored_xss_events, stored_xss_report

from ca3p_report.collect import CollectError, pentest_db, run_store

STAGES = ["setup.attacker_session", "loop.observe", "loop.history", "loop.act"]


def run_dir(reports_dir: Path, run_id: str) -> Path:
    return reports_dir / hashlib.sha256(run_id.encode()).hexdigest()


def as_set(events) -> list[str]:
    return sorted(
        json.dumps(
            event.to_json() | {"recordedAt": None},
            sort_keys=True,
        )
        for event in events
    )


@needs_node
def test_pentest_db_reads_events_and_final_report(stored_run, run_id):
    run = pentest_db.read_run(stored_run["reports_dir"], run_id)
    assert run.driver == "pentest-db-disk"
    keys = [(event.recorded_at, event.message_id) for event in run.events]
    assert keys == sorted(keys) and all(event.message_id for event in run.events)
    assert [
        event.iteration for event in sorted(run.events, key=lambda e: STAGES.index(e.stage))
    ] == [
        0,
        1,
        1,
        1,
    ]
    assert sorted(event.stage for event in run.events) == sorted(STAGES)
    assert run.report == stored_xss_report(run_id)
    assert run.provenance["verifiedByStorage"] is False
    act = next(event for event in run.events if event.stage == "loop.act")
    # Payload bytes are carried verbatim; escaping is the renderer's job.
    assert act.request["payload"]["curl"]["body"]["content"] == PAYLOAD


@needs_node
def test_run_store_normalizes_to_the_same_run(stored_run, run_id):
    disk = pentest_db.read_run(stored_run["reports_dir"], run_id)
    store = run_store.read_run(stored_run["store_path"], run_id)
    assert store.driver == "run-store"
    assert [
        event.stage for event in store.events
    ] == STAGES  # insertion order, unrelated exchanges dropped
    assert store.report == disk.report
    assert as_set(store.events) == as_set(disk.events)
    assert store.provenance["verifiedByStorage"] is False


@needs_node
def test_sources_are_left_untouched(stored_run, run_id):
    before = tree_digest(stored_run["reports_dir"].parent)
    pentest_db.read_run(stored_run["reports_dir"], run_id)
    run_store.read_run(stored_run["store_path"], run_id)
    assert tree_digest(stored_run["reports_dir"].parent) == before


@needs_node
def test_unknown_run_is_none_in_both_sources(stored_run):
    assert pentest_db.read_run(stored_run["reports_dir"], "run-unknown") is None
    assert run_store.read_run(stored_run["store_path"], "run-unknown") is None


@needs_node
def test_events_without_final_report(tmp_path, run_id):
    reports_dir = tmp_path / "runs"
    write_sources(run_id=run_id, events=stored_xss_events(), report=None, reports_dir=reports_dir)
    run = pentest_db.read_run(reports_dir, run_id)
    assert run.report is None and len(run.events) == len(STAGES)


@needs_node
def test_pentest_db_rejects_mismatched_run_id(stored_run, run_id):
    report_file = run_dir(stored_run["reports_dir"], run_id) / "report.json"
    record = json.loads(report_file.read_text())
    report_file.chmod(0o600)
    report_file.write_text(json.dumps({**record, "runId": "run-other"}))
    with pytest.raises(CollectError, match="mismatched runId"):
        pentest_db.read_run(stored_run["reports_dir"], run_id)


@needs_node
def test_pentest_db_refuses_symlinked_artifacts(stored_run, run_id, tmp_path):
    report_file = run_dir(stored_run["reports_dir"], run_id) / "report.json"
    outside = tmp_path / "outside.json"
    outside.write_text(report_file.read_text())
    report_file.unlink()
    os.symlink(outside, report_file)
    with pytest.raises(CollectError, match="not a regular file"):
        pentest_db.read_run(stored_run["reports_dir"], run_id)


@needs_node
def test_pentest_db_ignores_foreign_files(stored_run, run_id):
    (run_dir(stored_run["reports_dir"], run_id) / "events" / "notes.json").write_text("{}")
    assert len(pentest_db.read_run(stored_run["reports_dir"], run_id).events) == len(STAGES)


def test_run_store_requires_an_existing_database(tmp_path):
    missing = tmp_path / "absent.sqlite"
    with pytest.raises(CollectError, match="not found"):
        run_store.read_run(missing, "run-1")
    assert not missing.exists()


def test_run_store_rejects_unknown_schema_version(tmp_path):
    path = tmp_path / "other.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version = 7")
    connection.close()
    with pytest.raises(CollectError, match="schema version"):
        run_store.read_run(path, "run-1")


@needs_node
def test_run_store_sees_writes_not_yet_checkpointed(stored_run, run_id):
    # A live worker may still hold recent writes only in the WAL; they must be visible.
    writer = sqlite3.connect(stored_run["store_path"])
    try:
        writer.execute("PRAGMA wal_autocheckpoint = 0")
        state = json.loads(
            writer.execute("SELECT state_json FROM runs WHERE id = ?", (run_id,)).fetchone()[0]
        )
        state["report"]["completedAt"] = "2026-10-20T09:09:09.000Z"
        writer.execute("UPDATE runs SET state_json = ? WHERE id = ?", (json.dumps(state), run_id))
        writer.commit()
        assert (stored_run["store_path"].parent / "runs.sqlite-wal").stat().st_size > 0
        run = run_store.read_run(stored_run["store_path"], run_id)
        assert run.report["completedAt"] == "2026-10-20T09:09:09.000Z"
    finally:
        writer.close()


@needs_node
def test_run_store_skips_appends_that_were_never_stored(stored_run, run_id):
    # The fixture also records a failed pentest-db append (type 'error', module.error reply).
    stages = [event.stage for event in run_store.read_run(stored_run["store_path"], run_id).events]
    assert "loop.never_stored" not in stages


@needs_node
def test_run_store_reads_legacy_imported_runs(tmp_path, run_id):
    reports_dir = tmp_path / "runs"
    legacy = tmp_path / "legacy" / "runs.sqlite"
    write_sources(
        run_id=run_id,
        events=stored_xss_events(),
        report=stored_xss_report(run_id),
        reports_dir=reports_dir,
        legacy_store_path=legacy,
    )
    disk = pentest_db.read_run(reports_dir, run_id)
    imported = run_store.read_run(legacy, run_id)
    assert imported.report == disk.report
    assert sorted(event.stage for event in imported.events) == sorted(STAGES)
    assert [event.request for event in imported.events] == [event.request for event in disk.events]


def test_pentest_db_missing_store_is_a_source_error(tmp_path):
    with pytest.raises(CollectError, match="reports directory not found"):
        pentest_db.read_run(tmp_path / "typo", "run-1")


@needs_node
def test_pentest_db_refuses_a_symlinked_run_directory(stored_run, run_id, tmp_path):
    real = run_dir(stored_run["reports_dir"], run_id)
    moved = tmp_path / "elsewhere"
    real.rename(moved)
    os.symlink(moved, real)
    with pytest.raises(CollectError, match="run entry is not a directory"):
        pentest_db.read_run(stored_run["reports_dir"], run_id)


@needs_node
def test_pentest_db_refuses_a_symlinked_events_directory(stored_run, run_id, tmp_path):
    events = run_dir(stored_run["reports_dir"], run_id) / "events"
    moved = tmp_path / "events-elsewhere"
    events.rename(moved)
    os.symlink(moved, events)
    with pytest.raises(CollectError, match="events entry is not a directory"):
        pentest_db.read_run(stored_run["reports_dir"], run_id)
