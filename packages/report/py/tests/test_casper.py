from __future__ import annotations

import sys

from conftest import tree_digest
from fixtures import CASE_ID, stored_xss_events

from ca3p_report.collect import casper
from ca3p_report.collect.model import StoredEvent


def events() -> list[StoredEvent]:
    return [
        StoredEvent(
            stage=item["stage"],
            iteration=item["iteration"],
            recorded_at=None,
            message_id=None,
            request=item["request"],
            response=item["response"],
        )
        for item in stored_xss_events()
    ]


def test_refs_come_from_the_runs_own_assessments():
    assert casper.history_refs(events()) == [(CASE_ID, 1), ("CASE-MISSING", 3)]


def test_refs_ignore_malformed_matches():
    bad = StoredEvent(
        "loop.history",
        1,
        None,
        None,
        {},
        {
            "payload": {
                "assessments": [
                    {
                        "matches": [
                            {"case_id": "A", "case_revision": True},
                            {"case_id": 5, "case_revision": 1},
                            "junk",
                        ]
                    },
                    None,
                ]
            }
        },
    )
    assert casper.history_refs([bad]) == []


def test_reads_snapshot_at_compared_revision_and_checks(casper_db):
    history = casper.read_history(casper_db, casper.history_refs(events()))
    assert history["status"] == "ok"
    found, missing = history["cases"]
    assert found["caseId"] == CASE_ID and found["revision"] == 1 and found["currentRevision"] == 1
    assert found["snapshot"]["case_id"] == CASE_ID and found["snapshot"]["source"] == "synthetic"
    assert [check["check_id"] for check in found["checks"]] == ["CHECK-SYN-1"]
    assert missing == {"caseId": "CASE-MISSING", "revision": 3, "status": "not-found"}


def test_database_is_read_only(casper_db):
    before = tree_digest(casper_db.parent)
    casper.read_history(casper_db, casper.history_refs(events()))
    assert tree_digest(casper_db.parent) == before


def test_missing_database_is_reported_not_created(tmp_path):
    path = tmp_path / "nowhere" / "cases.sqlite3"
    assert casper.read_history(path, [(CASE_ID, 1)]) == casper.unavailable("db-not-found")
    assert not path.exists() and not path.parent.exists()


def test_unreadable_database_hides_the_location(tmp_path):
    path = tmp_path / "secret-location" / "cases.sqlite3"
    path.parent.mkdir()
    path.write_bytes(b"not a database")
    history = casper.read_history(path, [(CASE_ID, 1)])
    assert history["status"] == "unavailable"
    assert "secret-location" not in history["reason"]


def test_missing_package_is_reported(monkeypatch, casper_db):
    monkeypatch.setitem(sys.modules, "casper_db", None)
    assert casper.read_history(casper_db, [(CASE_ID, 1)])["reason"] == "casper-db-package-missing"
