import hashlib
import sqlite3
from contextlib import closing

import pytest

from casper_db import CaseStore, ConflictError, NotFoundError, initialize_database
from casper_db.matching import assess_observation
from casper_db.repository import SCHEMA_VERSION


def check_data(case_data, **changes):
    return {
        "check_id": "CHECK-001", "case_id": case_data["case_id"], "run_id": "RUN-001",
        **{key: case_data[key] for key in (
            "target_id", "endpoint", "method", "parameter", "parameter_location"
        )},
        "observed_at": "2026-10-06T09:30:00+09:00", "result": "confirmed",
        "observation": "Test fixture only", "source": "manual", "evidence_refs": ["proof.txt"],
        **changes,
    }


def link_review():
    return {
        "reviewer": "tester", "reason": "Mock fixture maps q to term",
        "reviewed_at": "2026-10-06T09:00:00+09:00",
    }


def test_report_revisions_remain_available_and_checks_keep_the_used_revision(store, case_data):
    first = store.add(case_data)
    saved = store.add_check(check_data(case_data))
    updated = store.update({**case_data, "description": "Changed report"})
    assert [item.revision for item in store.list_versions(first.case_id)] == [1, 2]
    assert store.get_version(first.case_id, 1) == first
    assert store.get_version(first.case_id, 2) == updated
    assert store.get_check(saved.check_id).case_revision == 1
    with pytest.raises(NotFoundError):
        store.get_version(first.case_id, 3)


def test_stale_updates_and_target_changes_do_not_create_a_report_revision(store, case_data):
    store.add(case_data)
    store.update({**case_data, "title": "Revision two"}, expected_revision=1)
    with pytest.raises(ConflictError):
        store.update(case_data, expected_revision=1)
    with pytest.raises(ValueError, match="target_id"):
        store.update({**case_data, "target_id": "OTHER"})
    assert [item.revision for item in store.list_versions(case_data["case_id"])] == [1, 2]


def test_version_snapshot_failure_rolls_back_the_case_update(store, case_data, monkeypatch):
    before = store.add(case_data)

    def fail(*args):
        raise sqlite3.OperationalError("simulated history write failure")

    monkeypatch.setattr("casper_db.repository._save_version", fail)
    with pytest.raises(sqlite3.OperationalError):
        store.update({**case_data, "description": "Should roll back"})
    assert store.get(before.case_id) == before
    assert store.list_versions(before.case_id) == [before]


def test_changed_location_requires_explicit_link_review_and_keeps_both_locations(store, case_data):
    first = store.add({**case_data, "status": "ready"})
    changed = check_data(case_data, parameter="term")
    observation = {key: changed[key] for key in (
        "target_id", "endpoint", "method", "parameter", "parameter_location"
    )}
    candidate = assess_observation(store, observation)
    assert candidate.decision == "manual_review"
    assert candidate.matches[0].case_revision == first.revision
    assert candidate.matches[0].report_source == "synthetic"
    with pytest.raises(ValueError, match="link_review"):
        store.add_check(changed)
    saved = store.add_check({**changed, "case_revision": 1, "link_review": link_review()})
    assert saved.parameter == "term"
    assert saved.link_review.reviewer == "tester"
    assert store.get_version(first.case_id, saved.case_revision).parameter == "q"
    with pytest.raises(ValueError, match="target_id"):
        store.add_check({
            **changed, "check_id": "CROSS-SITE", "target_id": "OTHER",
            "link_review": link_review(),
        })


def test_check_can_pin_the_report_version_it_saw_before_a_later_update(store, case_data):
    store.add(case_data)
    store.update({
        **case_data, "endpoint": "/search-new",
        "vulnerability_url": "https://lab.example.invalid/search-new?q=sample",
    })
    saved = store.add_check(check_data(case_data, case_revision=1))
    assert saved.endpoint == "/search"
    assert saved.case_revision == 1
    with pytest.raises(NotFoundError):
        store.add_check(check_data(case_data, check_id="BAD-VERSION", case_revision=99))


def test_observations_use_fixed_utc_format_and_sort_by_actual_time(store, case_data):
    store.add(case_data)
    store.add_check(check_data(case_data, check_id="EARLY"))
    store.add_check(check_data(
        case_data, check_id="LATE", observed_at="2026-10-06T01:00:00+00:00"
    ))
    rows = store.list_checks(case_data["case_id"])
    assert [item.check_id for item in rows] == ["EARLY", "LATE"]
    assert rows[0].observed_at == "2026-10-06T00:30:00.000000+00:00"
    assert rows[1].observed_at == "2026-10-06T01:00:00.000000+00:00"


def test_review_records_file_hash_and_detects_subsequent_changes(store, case_data, tmp_path):
    store.add(case_data)
    store.add_check(check_data(case_data))
    proof = tmp_path / "proof.txt"
    proof.write_bytes(b"test evidence bytes")
    reviewer = CaseStore(store.path, evidence_root=tmp_path)
    reviewed = reviewer.review_check("CHECK-001", reviewer="tester", note="Fixture bytes checked")
    assert reviewed.review_status == "reviewed"
    assert reviewed.reviewed_at is not None
    assert reviewed.evidence_metadata[0].sha256 == hashlib.sha256(proof.read_bytes()).hexdigest()
    assert reviewed.evidence_metadata[0].size_bytes == len(proof.read_bytes())
    assert CaseStore(store.path).get_check("CHECK-001") == reviewed
    assert reviewer.verify_check_evidence("CHECK-001") is True
    proof.write_bytes(b"changed")
    assert reviewer.verify_check_evidence("CHECK-001") is False
    with pytest.raises(ConflictError):
        reviewer.review_check("CHECK-001", reviewer="another", note="No overwrite")


@pytest.mark.parametrize("reference", [
    "../outside.txt", "/outside.txt", "C:/outside.txt", "https://example.invalid/proof",
    "folder\\proof.txt", "./proof.txt", "missing.txt",
])
def test_invalid_evidence_cannot_approve_a_check(store, case_data, tmp_path, reference):
    store.add(case_data)
    store.add_check(check_data(case_data, evidence_refs=[reference]))
    reviewer = CaseStore(store.path, evidence_root=tmp_path)
    with pytest.raises((ValueError, OSError)):
        reviewer.review_check("CHECK-001", reviewer="tester", note="Should fail")
    assert store.get_check("CHECK-001").review_status == "draft"
    assert store.get_check("CHECK-001").evidence_metadata == []


def test_review_requires_real_source_configured_root_and_separate_approval(store, case_data):
    store.add(case_data)
    with pytest.raises(ValueError, match="draft"):
        store.add_check(check_data(
            case_data, review_status="reviewed", reviewer="tester"
        ))
    store.add_check(check_data(case_data))
    with pytest.raises(ValueError, match="evidence_root"):
        store.review_check("CHECK-001", reviewer="tester", note="No root configured")
    store.add_check(check_data(case_data, check_id="SYNTHETIC", source="synthetic"))
    with pytest.raises(ValueError, match="synthetic"):
        store.review_check("SYNTHETIC", reviewer="tester", note="Not a real finding")


def test_duplicate_references_and_blank_approval_notes_leave_results_in_draft(
    store, case_data, tmp_path,
):
    store.add(case_data)
    store.add_check(check_data(case_data))
    store.add_check(check_data(
        case_data, check_id="DUPLICATE", evidence_refs=["proof.txt", "proof.txt"]
    ))
    (tmp_path / "proof.txt").write_bytes(b"Fixture")
    reviewer = CaseStore(store.path, evidence_root=tmp_path)
    with pytest.raises(ValueError):
        reviewer.review_check("DUPLICATE", reviewer="tester", note="Duplicate files")
    with pytest.raises(ValueError):
        reviewer.review_check("CHECK-001", reviewer="tester", note=" ")
    assert store.get_check("DUPLICATE").review_status == "draft"
    assert store.get_check("CHECK-001").review_status == "draft"


def test_migration_failure_rolls_back_ddl_data_and_version_and_is_retryable(
    legacy_database, case_data,
):
    path = legacy_database(3, case_data)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("UPDATE cases SET vulnerability_url = ?", ("http://[broken",))
        before_schema = connection.execute(
            "SELECT name, sql FROM sqlite_master ORDER BY name"
        ).fetchall()
    with pytest.raises(ValueError):
        initialize_database(path)
    with closing(sqlite3.connect(path)) as connection, connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert connection.execute(
            "SELECT name, sql FROM sqlite_master ORDER BY name"
        ).fetchall() == before_schema
        assert connection.execute(
            "SELECT vulnerability_url FROM cases"
        ).fetchone()[0] == "http://[broken"
        connection.execute(
            "UPDATE cases SET vulnerability_url = ?", (case_data["vulnerability_url"],)
        )
    initialize_database(path)
    assert CaseStore(path).get(case_data["case_id"]).revision == 1


def test_migration_failure_after_snapshot_creation_rolls_back_everything(
    legacy_database, case_data,
):
    path = legacy_database(4, case_data, check_data(case_data, observed_at="bad-date"))
    with pytest.raises(ValueError):
        initialize_database(path)
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name IN ('case_versions', 'checks_new')"
        ).fetchall() == []
        assert "source" not in {
            row[1] for row in connection.execute("PRAGMA table_info(cases)")
        }


def test_v4_approval_assertion_is_preserved_without_claiming_verified_files(
    legacy_database, case_data,
):
    path = legacy_database(4, case_data, check_data(
        case_data, review_status="reviewed", reviewer="old-reviewer"
    ))
    initialize_database(path)
    store = CaseStore(path)
    before = store.get(case_data["case_id"])
    saved = store.get_check("CHECK-001")
    assert before.source == "unknown"
    assert store.get_version(before.case_id, 1) == before
    assert saved.review_status == "draft"
    assert saved.reviewer is None
    assert saved.legacy_review.reviewer == "old-reviewer"
    assert saved.evidence_refs == ["proof.txt"]
    assert saved.evidence_metadata == []
    initialize_database(path)
    assert store.list_versions(before.case_id) == [before]
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM case_versions")
