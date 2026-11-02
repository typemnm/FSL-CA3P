"""A selected general finding is written by the LLM; verified fields come from the bundle."""

from __future__ import annotations

import json
import sqlite3
import zipfile
from copy import deepcopy
from pathlib import Path

import pytest

from ca3p_report.cli import EXIT_OK, EXIT_SOURCE, _run
from ca3p_report.collect.collector import collect
from ca3p_report.llm.tools import ReportTools, ToolError
from ca3p_report.trigger import parse_trigger
from test_build_loop import FakeLLM, _call


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


def llm_model(run_id: str = "run-general") -> dict:
    """What a model writes. It also tries to claim another finding, verdict and evidence."""
    return {
        "generatedAt": "2026-11-02T00:00:00Z",
        "notices": [],
        "sourceFindingId": "finding:h-b",
        "sourceEvidenceIds": ["prior-a"],
        "generator": {"method": "deterministic"},
        "guardrail": {"decisions": [{"decision": "ALLOW", "ruleId": "R-1"}]},
        "safety": {"synthetic": True},
        "run": {"runId": "another-run", "status": "completed", "testProfile": "general",
                "target": {"origin": "http://127.0.0.1:40123"}},
        "findings": [{
            "common": {
                "findingId": "finding:h-b", "status": "not_reproduced",
                "title": "CWE-639 사용자 제어 키를 통한 권한 우회", "cwe": "CWE-639",
                "location": {"method": "DELETE", "path": "/api/posts/1", "parameter": "id"},
                "cvss": {"version": "3.1", "score": 6.5, "rating": "Medium",
                         "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"},
                "summary": "다른 사용자의 게시글을 삭제할 수 있습니다.",
                "remediation": "서버에서 소유자를 확인합니다.",
                "limitations": "격리 실습 결과입니다.",
            },
            "reproduction": [{"step": 1, "text": "공격자 세션으로 삭제를 요청합니다."}],
            "images": [{"ref": "evidence/images/forged.png", "integrity": "ok"}],
            "textEvidence": [{"label": "요청", "text": "DELETE /api/posts/1"}],
            "checks": [{"label": "검증 판정", "result": "confirmed"}],
            "impact": "타인 데이터가 삭제될 수 있습니다.",
        }],
        "references": {"collectors": [], "verifiedByStorage": False},
    }


def writer(model: dict | None = None) -> FakeLLM:
    return FakeLLM([
        _call("read_bundle", {"path": "run/finding.json"}),
        _call("finish_report", {"model": model or llm_model()}),
    ])


def test_two_confirmed_findings_create_distinct_single_finding_documents(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general"))
    paths = []
    for finding_id in ("finding:h-a", "finding:h-b"):
        output = tmp_path / finding_id.replace(":", "-")
        assert _run(_trigger(db, output, finding_id), client=writer()) == EXIT_OK
        result = _result(capsys)
        assert result["findingId"] == finding_id
        model = json.loads((output / "report" / "report-model.json").read_text("utf-8"))
        assert model["sourceFindingId"] == finding_id
        assert len(model["findings"]) == 1
        assert model["findings"][0]["common"]["findingId"] == finding_id
        assert model["findings"][0]["common"]["status"] == "confirmed"
        assert model["findings"][0]["common"]["cwe"] == "CWE-639"
        assert model["findings"][0]["common"]["cvss"]["score"] == 6.5
        assert model["generator"] == {"method": "llm"}
        document = output / "report" / result["reportFilename"]
        with zipfile.ZipFile(document) as archive:
            xml = "".join(archive.read(name).decode("utf-8") for name in archive.namelist()
                          if name.startswith("Contents/section"))
        assert finding_id in xml
        assert "past note is not proof" not in xml
        paths.append((document, model))
    assert paths[0][0].name != paths[1][0].name  # fallback names differ per finding
    assert paths[0][0].read_bytes() != paths[1][0].read_bytes()
    assert paths[0][1]["sourceEvidenceIds"] == ["ev-a"]
    assert paths[1][1]["sourceEvidenceIds"] == ["ev-b"]


def test_nonconfirmed_or_unverified_selection_never_writes_a_document(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general"))
    for finding_id in (None, "finding:h-c", "finding:missing"):
        output = tmp_path / (finding_id or "missing").replace(":", "-")
        assert _run(_trigger(db, output, finding_id), client=FakeLLM([])) == EXIT_SOURCE
        assert _result(capsys)["error"]["code"] == "SOURCE_INVALID"
        assert not (output / "report").exists()


def test_failed_run_preserves_confirmed_detail_with_incomplete_notice(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general", status="failed"))
    output = tmp_path / "failed"
    assert _run(_trigger(db, output, "finding:h-a"), client=writer()) == EXIT_OK
    result = _result(capsys)
    preview = (output / "report" / "report.md").read_text("utf-8")
    model = json.loads((output / "report" / "report-model.json").read_text("utf-8"))
    assert result["findingId"] == "finding:h-a"
    assert model["run"]["status"] == "failed" and model["run"]["incomplete"] is True
    assert "점검 미완료" in preview
    assert "finding:h-a" in preview
    assert "다른 사용자의 게시글을 삭제할 수 있습니다." in preview


def test_report_has_no_llm_label_cover_notices_or_guardrail_section(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general"))
    output = tmp_path / "clean"
    noisy = llm_model()
    noisy["notices"] = ["run/attack.json의 records가 비어 있습니다."]
    assert _run(_trigger(db, output, "finding:h-a"), client=writer(noisy)) == EXIT_OK
    _result(capsys)
    preview = (output / "report" / "report.md").read_text("utf-8")
    model = json.loads((output / "report" / "report-model.json").read_text("utf-8"))
    assert "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N / 6.5 (Medium)" in preview
    for absent in ("LLM", "상류 severity", "가드레일", "안전 속성", "프로필:",
                   "격리된 실습", "synthetic", "run/attack.json"):
        assert absent not in preview
    for key in ("guardrail", "safety", "notices"):
        assert key not in model


def test_confirmed_probe_requires_adopted_current_evidence(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general"), events=[
        _event("run-general", "h-a", "p-a", "prior-a")])
    output = tmp_path / "invalid"
    assert _run(_trigger(db, output, "finding:h-a"), client=FakeLLM([])) == EXIT_SOURCE
    assert _result(capsys)["error"]["code"] == "SOURCE_INVALID"


def test_historical_reference_in_verdict_is_not_labeled_current_probe_evidence(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    current = _event("run-general", "h-a", "p-a", "ev-a")
    current["response"]["evidenceIds"] = ["ev-a", "prior-a"]
    _store(db, _report("run-general"), events=[current])
    output = tmp_path / "mixed-evidence"
    assert _run(_trigger(db, output, "finding:h-a"), client=writer()) == EXIT_OK
    _result(capsys)
    model = json.loads((output / "report" / "report-model.json").read_text("utf-8"))
    assert model["sourceEvidenceIds"] == ["ev-a"]
    finding = json.loads((output / "bundle" / "run" / "finding.json").read_text("utf-8"))
    assert [item["id"] for item in finding["evidence"]] == ["ev-a"]


def test_template_finding_id_and_remapped_category_writes_document(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    report = _report("run-general")
    report["findings"][0] = {
        "id": "finding:t-fa34bb39e407db7e", "hypothesisId": "h-c",
        "hypothesisIds": ["h-c", "h-a"], "category": "sql_injection",
        "asset": "/api/search", "status": "confirmed", "evidenceIds": ["ev-a"],
        "templateId": "search-sqli-template",
    }
    report["probes"][0]["hypothesisId"] = "h-c"
    _store(db, report, events=[_event("run-general", "h-c", "p-a", "ev-a")])
    output = tmp_path / "template-finding"
    assert _run(_trigger(db, output, "finding:t-fa34bb39e407db7e"), client=writer()) == EXIT_OK
    result = _result(capsys)
    assert result["findingId"] == "finding:t-fa34bb39e407db7e"
    assert "sql_injection" in result["summary"]["vulnerability"]
    model = json.loads((output / "report" / "report-model.json").read_text("utf-8"))
    assert model["sourceFindingId"] == "finding:t-fa34bb39e407db7e"
    assert model["findings"][0]["common"]["findingId"] == "finding:t-fa34bb39e407db7e"
    assert "finding:t-fa34bb39e407db7e" in (output / "report" / "report.md").read_text("utf-8")


def test_legacy_report_cannot_use_general_finding_selection(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    _store(db, {"runId": "run-general", "status": "completed",
                "finding": {"status": "confirmed"}}, events=[])
    assert _run(_trigger(db, tmp_path / "output", "finding:h-a"), client=FakeLLM([])) == EXIT_SOURCE
    assert _result(capsys)["error"]["code"] == "SOURCE_INVALID"


def test_finish_report_overwrites_verified_fields_and_requires_one_finding(tmp_path):
    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general"))
    trigger = parse_trigger(json.loads(_trigger(db, tmp_path / "bundle-output", "finding:h-a")))
    collected = collect(trigger)
    tools = ReportTools(collected.bundle, tmp_path / "document")
    two = llm_model()
    two["findings"].append(deepcopy(two["findings"][0]))
    with pytest.raises(ToolError):
        tools.finish_report(model=two)
    assert not (tmp_path / "document").exists()
    tools.finish_report(model=llm_model())
    model = json.loads((tmp_path / "document" / "report-model.json").read_text("utf-8"))
    assert model["sourceFindingId"] == "finding:h-a"
    assert model["sourceEvidenceIds"] == ["ev-a"]
    assert model["run"]["runId"] == "run-general" and model["run"]["status"] == "completed"
    assert model["generatedAt"] != llm_model()["generatedAt"]  # stamped by code, not the model
    common = model["findings"][0]["common"]
    assert (common["findingId"], common["status"]) == ("finding:h-a", "confirmed")
    # Without a verifier handoff there is no screenshot; a model-invented ref is dropped.
    assert model["findings"][0]["images"] == []
