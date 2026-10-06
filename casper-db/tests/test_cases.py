import sqlite3

import pytest
from pydantic import ValidationError

from casper_db import Case, CaseStore, ConflictError, NotFoundError, initialize_database
from casper_db.repository import SCHEMA_VERSION


def test_disk_round_trip_preserves_unicode_payload_and_lists(store, case_data):
    case_data["payload"] = " \n<script data-x=\"한글\">' ; DROP TABLE cases; --</script>\n "
    original = Case.model_validate(case_data)
    store.add(original)
    reloaded = CaseStore(store.path).get("CASE-001")
    for field in Case.model_fields:
        assert getattr(reloaded, field) == getattr(original, field)
    assert reloaded.created_at == reloaded.updated_at


def test_duplicate_requires_explicit_update_and_preserves_created_at(store, case_data):
    original = store.add(case_data)
    with pytest.raises(ConflictError):
        store.add({**case_data, "title": "accidental overwrite"})
    assert store.get(original.case_id).title == original.title
    changed = store.update({**case_data, "title": "의도한 수정", "status": "ready"})
    assert changed.title == "의도한 수정"
    assert changed.created_at == original.created_at
    assert changed.updated_at >= original.updated_at
    assert CaseStore(store.path).get(original.case_id) == changed


def test_invalid_update_does_not_change_existing_record(store, case_data):
    original = store.add(case_data)
    with pytest.raises(ValidationError):
        store.update({**case_data, "status": "ready", "payload": None})
    assert store.get(original.case_id) == original


def test_update_of_missing_case_does_not_insert(store, case_data):
    with pytest.raises(NotFoundError):
        store.update(case_data)
    with pytest.raises(NotFoundError):
        store.get(case_data["case_id"])


def test_lookup_excludes_drafts_and_matches_target_path_and_method_exactly(store, case_data):
    store.add(case_data)
    location = {key: case_data[key] for key in ("target_id", "endpoint", "method")}
    assert store.find(**location) == []
    assert len(store.find(**location, include_drafts=True)) == 1
    store.update({**case_data, "status": "ready"})
    assert len(store.find(**{**location, "method": "get"})) == 1
    assert len(store.find(**location, parameter="q")) == 1
    assert len(store.find(**location, parameter="q", parameter_location="query")) == 1
    assert store.find(**location, parameter="q", parameter_location="body") == []
    assert store.find(**location, parameter="page") == []
    for change in ({"target_id": "OTHER"}, {"endpoint": "/Search"}, {"method": "POST"}):
        assert store.find(**{**location, **change}) == []
    assert store.find(**{**location, "endpoint": "/search'OR'1'='1"}) == []
    with pytest.raises(NotFoundError):
        store.get("' OR 1=1 --")
    assert store.get("CASE-001").case_id == "CASE-001"


def test_previous_report_is_available_by_site_for_comparison(store, case_data):
    store.add(case_data)
    assert store.list_for_target("LAB-DEMO") == []
    store.update({**case_data, "status": "ready"})
    reports = store.list_for_target("LAB-DEMO")
    assert len(reports) == 1
    assert reports[0].vulnerability_url == case_data["vulnerability_url"]
    assert reports[0].severity == "medium"
    assert reports[0].remediation == case_data["remediation"]
    assert store.list_for_target("OTHER") == []


@pytest.mark.parametrize(
    "change",
    [
        {"reported_on": None},
        {"vulnerability_url": None},
        {"severity": None},
        {"description": None},
        {"remediation": []},
    ],
)
def test_ready_prior_report_requires_its_core_fields(case_data, change):
    with pytest.raises(ValidationError):
        Case.model_validate({**case_data, "status": "ready", **change})


@pytest.mark.parametrize("payload", [None, "", " \t\n"])
def test_ready_requires_payload(case_data, payload):
    with pytest.raises(ValidationError):
        Case.model_validate({**case_data, "status": "ready", "payload": payload})


@pytest.mark.parametrize(
    "change",
    [
        {"procedure": []},
        {"preconditions": ["   "]},
        {"parameter": 42},
        {"method": "NOT_A_METHOD"},
        {"endpoint": "https://example.invalid/search"},
        {"endpoint": "/search?q=test"},
        {"endpoint": "/search#fragment"},
        {"status": "confirmed_vulnerable"},
        {"reported_on": "2026-02-30"},
        {"severity": "catastrophic"},
        {"vulnerability_url": "https://lab.example.invalid/other?q=sample"},
        {"vulnerability_url": "file:///search"},
        {"vulnerability_url": "https://user:pass@lab.example.invalid/search"},
        {"unexpected_field": "should not disappear silently"},
    ],
)
def test_invalid_contract_is_rejected(case_data, change):
    with pytest.raises(ValidationError):
        Case.model_validate({**case_data, **change})


def test_failed_reads_do_not_create_database(tmp_path):
    path = tmp_path / "missing.sqlite3"
    with pytest.raises(FileNotFoundError):
        CaseStore(path).get("CASE-001")
    assert not path.exists()


def test_initialization_preserves_existing_data_and_rejects_foreign_database(
    store, case_data, tmp_path
):
    original = store.add(case_data)
    initialize_database(store.path)
    assert store.get(original.case_id) == original
    foreign = tmp_path / "foreign.sqlite3"
    with sqlite3.connect(foreign) as connection:
        connection.execute("CREATE TABLE other (id INTEGER)")
    with pytest.raises(ValueError, match="unknown tables"):
        initialize_database(foreign)
    with sqlite3.connect(foreign) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        row = connection.execute("SELECT name FROM sqlite_master WHERE name='cases'").fetchone()
        assert row is None


def test_unsupported_schema_is_not_overwritten(store):
    with sqlite3.connect(store.path) as connection:
        connection.execute("PRAGMA user_version = 999")
    with pytest.raises(ValueError, match="schema version"):
        initialize_database(store.path)
    with pytest.raises(ValueError, match="schema version"):
        store.get("CASE-001")


def test_v1_database_is_migrated_without_losing_the_old_case(tmp_path):
    path = tmp_path / "old.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "CREATE TABLE cases ("
            "case_id TEXT PRIMARY KEY, target_id TEXT, title TEXT, vulnerability_type TEXT, "
            "endpoint TEXT, method TEXT, parameter TEXT, preconditions TEXT, procedure TEXT, "
            "payload TEXT, success_condition TEXT, source_report TEXT, status TEXT, "
            "patch_status TEXT, created_at TEXT, updated_at TEXT);"
            "PRAGMA user_version = 1;"
        )
        connection.execute(
            "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "OLD-001", "LAB-DEMO", "Old case", "XSS", "/search", "GET", "q",
                '["public page"]', '["send input"]', "old payload", "marker appears",
                "old-report", "ready", "unknown", "2026-08-01", "2026-08-01",
            ),
        )
    initialize_database(path)
    record = CaseStore(path).get("OLD-001")
    assert record.payload == "old payload"
    assert record.status == "draft"
    assert record.severity is None
    assert record.remediation == []
    assert CaseStore(path).list_for_target("LAB-DEMO") == []
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
