"""Selected general findings render one evidence-bound HWPX without an LLM."""

from __future__ import annotations

import json
import sqlite3
import zipfile
from copy import deepcopy
from pathlib import Path

import pytest

from ca3p_report.cli import EXIT_OK, EXIT_SOURCE, _run
from ca3p_report.collect.collector import collect
from ca3p_report.general_model import build_general_model
from ca3p_report.llm.tools import ReportTools, ToolError
from ca3p_report.trigger import parse_trigger


def _report(run_id: str, *, status: str = "completed") -> dict:
    return {
        "schemaVersion": "general-assessment/1",
        "assessmentMode": "general",
        "runId": run_id,
        "status": status,
        "target": {"fixtureId": "vul-web-1", "origin": "http://127.0.0.1:40123"},
        "hypotheses": [
            {"id": "h-a", "category": "access_control", "asset": "/api/posts/:id"},
            {"id": "h-b", "category": "access_control", "asset": "/api/records/:id"},
            {"id": "h-c", "category": "xss", "asset": "/api/posts"},
        ],
        "findings": [
            {"id": "finding:h-a", "hypothesisId": "h-a", "category": "access_control",
             "asset": "/api/posts/:id", "status": "confirmed", "evidenceIds": ["prior-a", "ev-a"]},
            {"id": "finding:h-b", "hypothesisId": "h-b", "category": "access_control",
             "asset": "/api/records/:id", "status": "confirmed", "evidenceIds": ["ev-b"]},
            {"id": "finding:h-c", "hypothesisId": "h-c", "category": "xss",
             "asset": "/api/posts", "status": "not_reproduced", "evidenceIds": ["ev-c"]},
        ],
        "evidence": [
            {"id": "prior-a", "kind": "historical-reference", "summary": "past note is not proof"},
            {"id": "ev-a", "kind": "role-comparison", "summary": "cross-owner delete returned 200"},
            {"id": "ev-b", "kind": "role-comparison", "summary": "cross-owner read returned 200"},
            {"id": "ev-c", "kind": "browser", "summary": "no callback"},
        ],
        "probes": [
            {"id": "p-a", "hypothesisId": "h-a", "tool": "known_cross_user_delete_canary",
             "status": "confirmed", "evidenceIds": ["ev-a"]},
            {"id": "p-b", "hypothesisId": "h-b", "tool": "known_record_idor_read",
             "status": "confirmed", "evidenceIds": ["ev-b"]},
            {"id": "p-c", "hypothesisId": "h-c", "tool": "http_get",
             "status": "not_reproduced", "evidenceIds": ["ev-c"]},
        ],
        "partial": status == "failed",
        "stopReason": "failure" if status == "failed" else "no_progress",
        "coverage": {"totalHypotheses": 3, "confirmed": 2, "notReproduced": 1,
                     "inconclusive": 0, "notTested": 0},
    }


def _event(run_id: str, hypothesis_id: str, probe_id: str, evidence_id: str) -> dict:
    return {"id": f"{run_id}:event-{probe_id}", "module": "agent", "type": "info",
            "source": "agent/general-assessment", "stage": "verify", "iteration": 1,
            "request": {"hypothesisId": hypothesis_id, "probeId": probe_id},
            "response": {"status": "confirmed", "evidenceIds": [evidence_id]}}


def _store(path: Path, report: dict, *, events: list[dict] | None = None) -> None:
    events = events if events is not None else [
        _event(report["runId"], "h-a", "p-a", "ev-a"),
        _event(report["runId"], "h-b", "p-b", "ev-b"),
    ]
    state = {"id": report["runId"], "report": report, "events": events}
    with sqlite3.connect(path) as db:
        db.executescript("PRAGMA user_version=1;"
                         "CREATE TABLE runs (id TEXT, state_json TEXT, updated_at TEXT);"
                         "CREATE TABLE run_events (run_id TEXT, sequence INTEGER, event_json TEXT);"
                         )
        db.execute("INSERT INTO runs VALUES (?,?,?)",
                   (report["runId"], json.dumps(state), "2026-10-28T00:00:00Z"))


def _trigger(db: Path, output: Path, finding_id: str | None) -> str:
    value = {"schemaVersion": "report-trigger-1.0", "runId": "run-general",
             "sources": {"run": {"kind": "run-store", "location": str(db)},
                         "history": {"kind": "none"}},
             "output": {"dir": str(output)}}
    if finding_id is not None:
        value["options"] = {"findingId": finding_id}
    return json.dumps(value)


def _result(capsys) -> dict:
    return json.loads(capsys.readouterr().out.strip())


def test_two_confirmed_findings_create_distinct_single_finding_documents(
    tmp_path, capsys, monkeypatch
):
    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general"))
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    paths = []
    for finding_id in ("finding:h-a", "finding:h-b"):
        output = tmp_path / finding_id.replace(":", "-")
        assert _run(_trigger(db, output, finding_id)) == EXIT_OK
        result = _result(capsys)
        assert result["findingId"] == finding_id
        model = json.loads((output / "report" / "report-model.json").read_text("utf-8"))
        assert model["sourceFindingId"] == finding_id
        assert len(model["findings"]) == 1
        assert model["findings"][0]["common"]["findingId"] == finding_id
        assert model["findings"][0]["common"]["status"] == "confirmed"
        assert model["findings"][0]["common"]["cwe"] is None
        assert model["findings"][0]["common"]["cvss"] is None
        document = output / "report" / result["reportFilename"]
        with zipfile.ZipFile(document) as archive:
            xml = "".join(archive.read(name).decode("utf-8") for name in archive.namelist()
                          if name.startswith("Contents/section"))
        assert finding_id in xml
        assert "past note is not proof" not in xml
        paths.append((document, model))
    assert paths[0][0].name != paths[1][0].name
    assert paths[0][0].read_bytes() != paths[1][0].read_bytes()
    assert paths[0][1]["sourceEvidenceIds"] == ["ev-a"]
    assert paths[1][1]["sourceEvidenceIds"] == ["ev-b"]


def test_nonconfirmed_or_unverified_selection_never_writes_a_document(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general"))
    for finding_id in (None, "finding:h-c", "finding:missing"):
        output = tmp_path / (finding_id or "missing").replace(":", "-")
        assert _run(_trigger(db, output, finding_id)) == EXIT_SOURCE
        assert _result(capsys)["error"]["code"] == "SOURCE_INVALID"
        assert not (output / "report").exists()


def test_failed_run_preserves_confirmed_detail_with_incomplete_notice(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general", status="failed"))
    output = tmp_path / "failed"
    assert _run(_trigger(db, output, "finding:h-a")) == EXIT_OK
    result = _result(capsys)
    preview = (output / "report" / "report.md").read_text("utf-8")
    assert result["findingId"] == "finding:h-a"
    assert "점검 미완료" in preview
    assert "finding:h-a" in preview
    assert "cross-owner delete returned 200" in preview
    assert "취약점 상세 대신 실패 정보" not in preview


def test_confirmed_probe_requires_adopted_current_evidence(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general"), events=[
        _event("run-general", "h-a", "p-a", "prior-a")])
    output = tmp_path / "invalid"
    assert _run(_trigger(db, output, "finding:h-a")) == EXIT_SOURCE
    assert _result(capsys)["error"]["code"] == "SOURCE_INVALID"


def test_historical_reference_in_verdict_is_not_labeled_current_probe_evidence(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    current = _event("run-general", "h-a", "p-a", "ev-a")
    current["response"]["evidenceIds"] = ["ev-a", "prior-a"]
    _store(db, _report("run-general"), events=[current])
    output = tmp_path / "mixed-evidence"
    assert _run(_trigger(db, output, "finding:h-a")) == EXIT_OK
    _result(capsys)
    model = json.loads((output / "report" / "report-model.json").read_text("utf-8"))
    assert model["sourceEvidenceIds"] == ["ev-a"]
    assert "past note is not proof" not in (output / "report" / "report.md").read_text("utf-8")


def test_legacy_report_cannot_use_general_finding_selection(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    _store(db, {"runId": "run-general", "status": "completed",
                "finding": {"status": "confirmed"}}, events=[])
    assert _run(_trigger(db, tmp_path / "output", "finding:h-a")) == EXIT_SOURCE
    assert _result(capsys)["error"]["code"] == "SOURCE_INVALID"


def test_finish_report_rejects_source_identity_or_status_changes(tmp_path):
    db = tmp_path / "runs.sqlite"
    report = _report("run-general")
    _store(db, report)
    trigger = parse_trigger(json.loads(_trigger(db, tmp_path / "bundle-output", "finding:h-a")))
    collected = collect(trigger)
    valid = build_general_model(collected.selection, report, collected.manifest)
    tools = ReportTools(collected.bundle, tmp_path / "document",
                        origin="http://127.0.0.1:40123", session_switch=None)
    for altered in (
        lambda item: item.update(sourceFindingId="finding:h-b"),
        lambda item: item.update(sourceEvidenceIds=["prior-a"]),
        lambda item: item["findings"][0]["common"].update(status="not_reproduced"),
        lambda item: item["run"].update(
            status="completed" if report["status"] == "failed" else "failed"
        ),
        lambda item: item["generator"].update(method="llm"),
        lambda item: item["findings"].append(deepcopy(item["findings"][0])),
    ):
        model = deepcopy(valid)
        altered(model)
        with pytest.raises(ToolError):
            tools.finish_report(model=model)
    assert not (tmp_path / "document").exists()
