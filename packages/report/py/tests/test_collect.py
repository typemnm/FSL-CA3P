"""End-to-end: one trigger in, one sealed bundle out, through the CLI."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import needs_node, tree_digest, write_sources
from fixtures import stored_xss_events

SRC = Path(__file__).resolve().parents[1] / "src"


def run_cli_raw(stdin: bytes, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "ca3p_report", "collect", "--trigger", "-"],
        input=stdin,
        capture_output=True,
        cwd=cwd,
        env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
    )


def run_cli(trigger: dict, cwd: Path) -> tuple[int, dict]:
    result = run_cli_raw(json.dumps(trigger).encode(), cwd)
    # The contract on every path: one JSON line on stdout, nothing on stderr, no locations.
    assert result.stderr == b"", result.stderr.decode(errors="replace")
    assert str(cwd).encode() not in result.stdout
    return result.returncode, json.loads(result.stdout)


def make_trigger(run_id: str, run_source: dict, out: Path, history: dict | None = None) -> dict:
    sources = {"run": run_source}
    if history:
        sources["history"] = history
    return {
        "schemaVersion": "report-trigger-1.0",
        "runId": run_id,
        "sources": sources,
        "output": {"dir": str(out)},
    }


@needs_node
@pytest.mark.parametrize("kind", ["pentest-db-disk", "run-store"])
def test_collects_a_sealed_bundle(stored_run, casper_db, run_id, tmp_path, kind):
    location = stored_run["reports_dir"] if kind == "pentest-db-disk" else stored_run["store_path"]
    out = tmp_path / "out"
    watched = [tmp_path / "pentest-db-runs", tmp_path / "runtime", casper_db.parent]
    sources_before = [tree_digest(path) for path in watched]
    code, result = run_cli(
        make_trigger(
            run_id,
            {"kind": kind, "location": str(location)},
            out,
            {"kind": "casper-db", "location": str(casper_db)},
        ),
        tmp_path,
    )
    assert code == 0 and result["ok"] is True
    bundle = out / "bundle"
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["schemaVersion"] == "report-input-1.0" and manifest["runId"] == run_id
    assert {item["path"] for item in manifest["files"]} == {
        "run/report.json",
        "run/events.json",
        "history/casper.json",
    }
    for item in manifest["files"]:
        data = (bundle / item["path"]).read_bytes()
        assert item["sha256"] == "sha256:" + hashlib.sha256(data).hexdigest()
        assert item["size"] == len(data)
    assert [c["driver"] for c in manifest["collectors"]] == [kind, "casper-db"]
    assert json.loads((bundle / "history/casper.json").read_text())["status"] == "ok"
    # The bundle names source kinds only, never where the sources live.
    text = "".join(path.read_text() for path in bundle.rglob("*.json"))
    assert str(tmp_path) not in text
    assert [tree_digest(path) for path in watched] == sources_before
    assert not list(out.glob(".bundle.*.partial"))


@needs_node
def test_history_is_optional(stored_run, run_id, tmp_path):
    out = tmp_path / "out"
    code, result = run_cli(
        make_trigger(
            run_id, {"kind": "pentest-db-disk", "location": str(stored_run["reports_dir"])}, out
        ),
        tmp_path,
    )
    assert code == 0
    assert result["collectors"][1] == {
        "name": "collect-history",
        "driver": "none",
        "status": "unavailable",
        "reason": "not-requested",
    }


@needs_node
def test_bundle_is_write_once(stored_run, run_id, tmp_path):
    trigger = make_trigger(
        run_id,
        {"kind": "pentest-db-disk", "location": str(stored_run["reports_dir"])},
        tmp_path / "out",
    )
    assert run_cli(trigger, tmp_path)[0] == 0
    before = tree_digest(tmp_path / "out")
    code, result = run_cli(trigger, tmp_path)
    assert code == 6 and result["error"]["code"] == "BUNDLE_EXISTS"
    assert tree_digest(tmp_path / "out") == before


@needs_node
def test_unknown_and_incomplete_runs(stored_run, tmp_path, run_id):
    reports = str(stored_run["reports_dir"])
    code, result = run_cli(
        make_trigger(
            "run-unknown", {"kind": "pentest-db-disk", "location": reports}, tmp_path / "a"
        ),
        tmp_path,
    )
    assert code == 3 and result["error"]["code"] == "RUN_NOT_FOUND"
    write_sources(
        run_id="run-partial",
        events=stored_xss_events(),
        report=None,
        reports_dir=stored_run["reports_dir"],
    )
    code, result = run_cli(
        make_trigger(
            "run-partial", {"kind": "pentest-db-disk", "location": reports}, tmp_path / "b"
        ),
        tmp_path,
    )
    assert code == 4 and result["error"]["code"] == "RUN_INCOMPLETE"
    assert not (tmp_path / "a").exists() and not (tmp_path / "b").exists()


def test_invalid_trigger_touches_nothing(tmp_path):
    code, result = run_cli({"schemaVersion": "report-trigger-1.0", "runId": "../x"}, tmp_path)
    assert code == 2 and result["error"]["code"] == "TRIGGER_INVALID"
    assert list(tmp_path.iterdir()) == []


def pentest_trigger(stored_run, run_id, out):
    return make_trigger(
        run_id, {"kind": "pentest-db-disk", "location": str(stored_run["reports_dir"])}, out
    )


@needs_node
def test_unreadable_source_file_is_a_json_error(stored_run, run_id, tmp_path):
    digest = hashlib.sha256(run_id.encode()).hexdigest()
    report = stored_run["reports_dir"] / digest / "report.json"
    report.chmod(0o000)
    try:
        code, result = run_cli(pentest_trigger(stored_run, run_id, tmp_path / "out"), tmp_path)
    finally:
        report.chmod(0o600)
    assert code == 5 and result["error"]["code"] == "SOURCE_INVALID"


@needs_node
def test_deeply_nested_json_is_a_json_error(stored_run, run_id, tmp_path):
    digest = hashlib.sha256(run_id.encode()).hexdigest()
    report = stored_run["reports_dir"] / digest / "report.json"
    report.chmod(0o600)
    report.write_text("[" * 200_000)
    code, result = run_cli(pentest_trigger(stored_run, run_id, tmp_path / "out"), tmp_path)
    assert code == 5 and result["error"]["code"] == "SOURCE_INVALID"


def test_unreadable_run_store_is_a_json_error(tmp_path, run_id):
    store = tmp_path / "runs.sqlite"
    store.write_bytes(b"")
    store.chmod(0o000)
    try:
        code, result = run_cli(
            make_trigger(run_id, {"kind": "run-store", "location": str(store)}, tmp_path / "o"),
            tmp_path,
        )
    finally:
        store.chmod(0o600)
    assert code == 5 and result["error"]["code"] == "SOURCE_INVALID"


@needs_node
def test_unwritable_output_is_a_json_error(stored_run, run_id, tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        code, result = run_cli(pentest_trigger(stored_run, run_id, locked / "out"), tmp_path)
    finally:
        locked.chmod(0o700)
    assert code == 7 and result["error"]["code"] == "OUTPUT_UNWRITABLE"


@needs_node
def test_symlinked_bundle_path_is_refused(stored_run, run_id, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (tmp_path / "empty").mkdir()
    os.symlink(tmp_path / "empty", out / "bundle")
    code, result = run_cli(pentest_trigger(stored_run, run_id, out), tmp_path)
    assert code == 6 and result["error"]["code"] == "BUNDLE_EXISTS"
    assert list((tmp_path / "empty").iterdir()) == []


@needs_node
def test_output_inside_a_source_is_refused(stored_run, run_id, tmp_path):
    inside = stored_run["reports_dir"] / "reports-out"
    before = tree_digest(stored_run["reports_dir"])
    code, result = run_cli(pentest_trigger(stored_run, run_id, inside), tmp_path)
    assert code == 2 and result["error"]["code"] == "TRIGGER_INVALID"
    assert tree_digest(stored_run["reports_dir"]) == before


def test_non_utf8_trigger_is_a_json_error(tmp_path):
    result = run_cli_raw(b"\xff\xfe{", tmp_path)
    assert result.returncode == 2 and result.stderr == b""
    assert json.loads(result.stdout)["error"]["code"] == "TRIGGER_UNREADABLE"


def test_deeply_nested_trigger_is_a_json_error(tmp_path):
    result = run_cli_raw(b"[" * 200_000, tmp_path)
    assert result.returncode == 2 and result.stderr == b""


@needs_node
def test_concurrent_collections_cannot_both_seal(stored_run, run_id, tmp_path):
    from ca3p_report.collect.bundle import BundleExistsError, BundleWriter

    root = tmp_path / "out" / "bundle"
    first, second = BundleWriter(root), BundleWriter(root)
    for writer in (first, second):
        writer.add_json("run/report.json", "run-report", {"n": id(writer)})
    first.seal(run_id=run_id, collected_at="t", collectors=[])
    sealed = tree_digest(root)
    with pytest.raises(BundleExistsError):
        second.seal(run_id=run_id, collected_at="t", collectors=[])
    second.discard()
    assert tree_digest(root) == sealed
    assert not list(root.parent.glob(".bundle.*.partial"))


@pytest.mark.parametrize("field", ["output", "source"])
def test_symlink_loop_in_a_trigger_path_is_a_json_error(tmp_path, field):
    os.symlink("loop", tmp_path / "loop")
    looping = str(tmp_path / "loop" / "x")
    trigger = make_trigger(
        "run-1",
        {"kind": "pentest-db-disk", "location": looping if field == "source" else "/nonexistent"},
        tmp_path / "loop" / "x" if field == "output" else tmp_path / "out",
    )
    code, result = run_cli(trigger, tmp_path)
    assert code == 2 and result["error"]["code"] == "TRIGGER_INVALID"
