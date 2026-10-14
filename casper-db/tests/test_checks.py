import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from casper_db import CaseStore, ConflictError, NotFoundError, initialize_database
from casper_db.repository import SCHEMA_VERSION


def example_check(case_data):
    return {
        "check_id": "CHECK-001",
        "case_id": case_data["case_id"],
        "run_id": "RUN-001",
        "target_id": case_data["target_id"],
        "endpoint": case_data["endpoint"],
        "method": case_data["method"],
        "parameter": case_data["parameter"],
        "parameter_location": case_data["parameter_location"],
        "observed_at": "2026-09-30T09:00:00+09:00",
        "result": "inconclusive",
        "observation": "No site was checked; example only",
        "source": "synthetic",
    }


def test_check_is_separate_persistent_history(store, case_data):
    store.add(case_data)
    check = store.add_check(example_check(case_data))
    assert check.review_status == "draft"
    assert CaseStore(store.path).list_checks("CASE-001") == [check]
    assert store.get("CASE-001").title == case_data["title"]
    with pytest.raises(ConflictError):
        store.add_check(example_check(case_data))
    with pytest.raises(NotFoundError):
        store.list_checks("NO-CASE")


def test_check_requires_parent_and_matching_location(store, case_data):
    check = example_check(case_data)
    with pytest.raises(NotFoundError):
        store.add_check(check)
    store.add(case_data)
    with pytest.raises(ValueError, match="parameter"):
        store.add_check({**check, "parameter": "page"})
    with pytest.raises(ValueError, match="parameter_location"):
        store.add_check({**check, "parameter_location": "body"})
    assert store.list_checks("CASE-001") == []


def test_synthetic_result_cannot_be_reviewed_as_real(store, case_data):
    store.add(case_data)
    with pytest.raises(ValidationError):
        store.add_check({
            **example_check(case_data),
            "result": "confirmed",
            "review_status": "reviewed",
            "reviewer": "CERT",
            "evidence_refs": ["proof.png"],
        })


def test_v2_migration_adds_checks_without_changing_case(legacy_database, case_data):
    path = legacy_database(2, case_data)
    initialize_database(path)
    record = CaseStore(path).get("CASE-001")
    for key, value in case_data.items():
        if key != "source":
            assert getattr(record, key) == value
    assert record.source == "unknown"
    assert record.revision == 1
    assert CaseStore(path).list_checks("CASE-001") == []


def test_v3_migration_preserves_case_and_unknown_check_location(legacy_database, case_data):
    path = legacy_database(3, case_data, example_check(case_data))
    store = CaseStore(path)
    initialize_database(path)
    assert store.get("CASE-001").parameter_location == "query"
    assert store.list_checks("CASE-001")[0].parameter_location == "unknown"
    assert store.list_checks("CASE-001")[0].case_revision == 1
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_demo_persists_db_and_escapes_payload(tmp_path):
    project = Path(__file__).resolve().parents[1]
    output = tmp_path / "demo"
    command = [sys.executable, str(project / "demo.py"), "--no-open", "--output-dir", str(output)]
    for _ in range(2):
        run = subprocess.run(
            command, cwd=project, capture_output=True, text=True, encoding="utf-8", check=False
        )
        assert run.returncode == 0, run.stderr
    db = output / "cases.sqlite3"
    parser_file = output / "parser-observations.json"
    page = (output / "index.html").read_text(encoding="utf-8")
    store = CaseStore(db)
    assert store.get("CASE-001").status == "ready"
    assert len(store.list_checks("CASE-001")) == 1
    assert "&lt;script&gt;" in page
    assert "모두 모의 자료" in page
    assert "재점검 후보" in page
    assert "수동 확인" in page
    assert "일치 없음" in page
    assert "0건" in page and "1건" in page
    observations = json.loads(parser_file.read_text(encoding="utf-8"))
    observations[1]["parameter"] = "q"
    parser_file.write_text(json.dumps(observations, ensure_ascii=False), encoding="utf-8")
    rerun = subprocess.run(
        command, cwd=project, capture_output=True, text=True, encoding="utf-8", check=False
    )
    assert rerun.returncode == 0, rerun.stderr
    updated = (output / "index.html").read_text(encoding="utf-8")
    assert "<td>수동 확인</td>" not in updated
    assert updated.count("<td>재점검 후보</td>") == 2
    assert len(store.list_checks("CASE-001")) == 1
