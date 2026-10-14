import json
import subprocess
import sys


def run_cli(path, *args):
    return subprocess.run(
        [sys.executable, "-m", "casper_db", "--db", str(path), *args],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


def test_cli_round_trip_and_error_exit_codes(tmp_path, case_data):
    path = tmp_path / "cases.sqlite3"
    case_file = tmp_path / "case.json"
    case_file.write_text(json.dumps(case_data, ensure_ascii=False), encoding="utf-8-sig")
    assert run_cli(path, "init").returncode == 0
    added = run_cli(path, "add", str(case_file))
    assert added.returncode == 0, added.stderr
    assert json.loads(added.stdout)["status"] == "draft"
    duplicate = run_cli(path, "add", str(case_file))
    assert duplicate.returncode == 2
    assert json.loads(duplicate.stderr)["error"] == "conflict"
    queried = run_cli(path, "get", "CASE-001")
    assert queried.returncode == 0
    assert json.loads(queried.stdout)["payload"] == case_data["payload"]
    location = ("--target", "LAB-DEMO", "--endpoint", "/search", "--method", "GET")
    assert json.loads(run_cli(path, "find", *location).stdout) == []
    assert len(json.loads(run_cli(path, "find", *location, "--include-drafts").stdout)) == 1
    case_file.write_text(json.dumps({**case_data, "status": "ready"}), encoding="utf-8")
    assert run_cli(path, "update", str(case_file)).returncode == 0
    assert len(json.loads(run_cli(path, "find", *location).stdout)) == 1
    assert json.loads(run_cli(path, "find", *location, "--parameter", "page").stdout) == []
    assert json.loads(run_cli(
        path, "find", *location, "--parameter", "q", "--parameter-location", "body"
    ).stdout) == []
    prior = run_cli(path, "list", "--target", "LAB-DEMO")
    assert prior.returncode == 0
    assert json.loads(prior.stdout)[0]["severity"] == "medium"
    missing = run_cli(path, "get", "MISSING")
    assert missing.returncode == 2
    assert json.loads(missing.stderr)["error"] == "not_found"


def test_cli_adds_and_lists_check(tmp_path, case_data):
    path = tmp_path / "cases.sqlite3"
    case_file = tmp_path / "case.json"
    check_file = tmp_path / "check.json"
    case_file.write_text(json.dumps(case_data, ensure_ascii=False), encoding="utf-8")
    assert run_cli(path, "init").returncode == 0
    assert run_cli(path, "add", str(case_file)).returncode == 0
    check = {
        "check_id": "CHECK-001", "case_id": "CASE-001", "run_id": "RUN-001",
        "target_id": "LAB-DEMO", "endpoint": "/search", "method": "GET",
        "parameter": "q", "observed_at": "2026-09-30T11:00:00+09:00",
        "parameter_location": "query",
        "result": "inconclusive", "observation": "Example only", "source": "synthetic",
    }
    check_file.write_text(json.dumps(check), encoding="utf-8")
    assert run_cli(path, "check-add", str(check_file)).returncode == 0
    listed = run_cli(path, "check-list", "CASE-001")
    assert listed.returncode == 0
    assert json.loads(listed.stdout)[0]["result"] == "inconclusive"


def test_cli_matches_parser_observations_and_explains_decisions(tmp_path, case_data):
    path = tmp_path / "cases.sqlite3"
    case_file = tmp_path / "case.json"
    parser_file = tmp_path / "parser.json"
    case_file.write_text(json.dumps({**case_data, "status": "ready"}), encoding="utf-8")
    common = {"target_id": "LAB-DEMO", "method": "GET", "parameter_location": "query"}
    parser_file.write_text(json.dumps([
        {**common, "endpoint": "/search", "parameter": "q"},
        {**common, "endpoint": "/search", "parameter": "page"},
        {**common, "endpoint": "/about", "parameter": "q"},
    ]), encoding="utf-8")
    assert run_cli(path, "init").returncode == 0
    assert run_cli(path, "add", str(case_file)).returncode == 0
    result = run_cli(path, "match", str(parser_file))
    assert result.returncode == 0, result.stderr
    decisions = [item["decision"] for item in json.loads(result.stdout)]
    assert decisions == ["retest_candidate", "manual_review", "no_match"]


def test_schema_export_and_invalid_json_do_not_create_database(tmp_path):
    path = tmp_path / "not-created.sqlite3"
    schema = run_cli(path, "schema")
    assert schema.returncode == 0
    assert "case_id" in json.loads(schema.stdout)["properties"]
    malformed = tmp_path / "bad.json"
    malformed.write_text("not JSON", encoding="utf-8")
    result = run_cli(path, "add", str(malformed))
    assert result.returncode == 2
    assert not path.exists()


def test_cli_preserves_report_history_and_detects_stale_revision(tmp_path, case_data):
    path = tmp_path / "cases.sqlite3"
    file = tmp_path / "case.json"
    file.write_text(json.dumps(case_data), encoding="utf-8")
    assert run_cli(path, "init").returncode == 0
    assert run_cli(path, "add", str(file)).returncode == 0
    file.write_text(json.dumps({**case_data, "title": "Updated title"}), encoding="utf-8")
    assert run_cli(path, "update", str(file), "--expected-revision", "1").returncode == 0
    stale = run_cli(path, "update", str(file), "--expected-revision", "1")
    assert stale.returncode == 2
    assert json.loads(stale.stderr)["error"] == "conflict"
    assert json.loads(run_cli(path, "get", "CASE-001", "--revision", "1").stdout)["title"] == (
        case_data["title"]
    )
    assert [item["revision"] for item in json.loads(
        run_cli(path, "history", "CASE-001").stdout
    )] == [1, 2]


def test_cli_review_and_evidence_verification(tmp_path, case_data):
    path = tmp_path / "cases.sqlite3"
    case_file = tmp_path / "case.json"
    check_file = tmp_path / "check.json"
    case_file.write_text(json.dumps(case_data), encoding="utf-8")
    assert run_cli(path, "init").returncode == 0
    assert run_cli(path, "add", str(case_file)).returncode == 0
    check = {
        "check_id": "CHECK-001", "case_id": "CASE-001", "run_id": "RUN-001",
        "target_id": "LAB-DEMO", "endpoint": "/search", "method": "GET", "parameter": "q",
        "parameter_location": "query", "observed_at": "2026-10-06T09:00:00+09:00",
        "result": "confirmed", "observation": "CLI fixture only", "source": "manual",
        "evidence_refs": ["proof.txt"],
    }
    check_file.write_text(json.dumps(check), encoding="utf-8")
    assert run_cli(path, "check-add", str(check_file)).returncode == 0
    proof = tmp_path / "proof.txt"
    proof.write_text("CLI fixture evidence", encoding="utf-8")
    root = ("--evidence-root", str(tmp_path))
    reviewed = run_cli(
        path, *root, "check-review", "CHECK-001", "--reviewer", "tester", "--note", "Checked"
    )
    assert reviewed.returncode == 0, reviewed.stderr
    assert json.loads(reviewed.stdout)["review_status"] == "reviewed"
    assert run_cli(path, *root, "check-evidence", "CHECK-001").returncode == 0
    proof.write_text("changed bytes", encoding="utf-8")
    assert run_cli(path, *root, "check-evidence", "CHECK-001").returncode == 2
