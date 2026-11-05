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


def _progress(run_id: str, stage: str, time: str) -> dict:
    return {"id": f"{run_id}:event-{stage}-{time}", "module": "agent", "type": "info",
            "source": "agent/general-assessment", "stage": stage, "time": time,
            "request": {}, "response": {}}


def _store(path: Path, report: dict, *, events: list[dict] | None = None) -> None:
    run_id = report["runId"]
    events = events if events is not None else [
        _progress(run_id, "execute", "2026-10-28T00:00:01Z"),
        _event(run_id, "h-a", "p-a", "ev-a"),
        _progress(run_id, "execute", "2026-10-28T00:00:02Z"),
        _event(run_id, "h-b", "p-b", "ev-b"),
        _progress(run_id, "complete", "2026-10-28T00:00:03Z"),
    ]
    state = {"id": run_id, "report": report, "events": events, "testProfile": "general",
             "startedAt": "2026-10-28T09:00:00+09:00", "fixtureId": "vul-web-1",
             "target": "http://127.0.0.1:40123"}
    with sqlite3.connect(path) as db:
        db.executescript("PRAGMA user_version=1;"
                         "CREATE TABLE runs (id TEXT, state_json TEXT, updated_at TEXT);"
                         "CREATE TABLE run_events (run_id TEXT, sequence INTEGER, event_json TEXT);"
                         "CREATE TABLE run_subtasks (run_id TEXT, id TEXT, source_finding_id TEXT,"
                         " kind TEXT, agent_id TEXT, status TEXT, input_json TEXT, result_json TEXT);"
                         )
        db.execute("INSERT INTO runs VALUES (?,?,?)",
                   (report["runId"], json.dumps(state), "2026-10-28T00:00:00Z"))


def _trigger(db: Path, output: Path, finding_id: str | None,
             subtask_id: str | None = None) -> str:
    value = {"schemaVersion": "report-trigger-1.0", "runId": "run-general",
             "sources": {"run": {"kind": "run-store", "location": str(db)},
                         "history": {"kind": "none"}},
             "output": {"dir": str(output)}}
    if finding_id is not None or subtask_id is not None:
        value["options"] = {"findingId": finding_id}
        if subtask_id is not None:
            value["options"]["subtaskId"] = subtask_id
    return json.dumps(value)


def _add_subtask(db_path: Path, *, child: dict | None = None,
                 task_status: str = "completed", event: dict | None = None) -> None:
    child = child or _report("sub-one")
    event = event or _event("run-general", "h-a", "p-a", "ev-a")
    event = {**event, "source": "agent/finding-subagent", "module": "subagent",
             "taskId": "sub-one", "agentId": "sub-one"}
    with sqlite3.connect(db_path) as db:
        db.execute("INSERT INTO run_subtasks VALUES (?,?,?,?,?,?,?,?)",
                   ("run-general", "sub-one", "finding:h-a", "finding-followup", "sub-one",
                    task_status, json.dumps({"hypothesisId": "h-a"}),
                    json.dumps({"report": child})))
        state = json.loads(db.execute("SELECT state_json FROM runs").fetchone()[0])
        state["events"].append(event)
        db.execute("UPDATE runs SET state_json=?", (json.dumps(state),))


def _result(capsys) -> dict:
    return json.loads(capsys.readouterr().out.strip())


SPEC_KEYS = {"run", "executive_summary", "objective", "scope", "run_limitations", "findings",
             "classification", "sourceFindingId", "sourceEvidenceIds",
             "generator", "sources"}
FINDING_KEYS = {"id", "finding_id", "verdict", "screenshots", "title", "severity", "cvss_score",
                "cvss_vector", "cwe", "location", "privilege", "description", "impact", "steps",
                "evidence", "checks", "fix_summary", "fix_short", "fix_long", "limitations",
                "references"}


def llm_model() -> dict:
    """What a model writes (REPORT_SPEC). It also tries to set every code-owned field."""
    return {
        "run": {"run_id": "another-run", "status": "completed", "target_origin": "http://x.test",
                "request_count": 999, "generated_at": "2020-01-01 00:00:00 UTC"},
        "review_status": "최종본", "classification": "공개",
        "sourceFindingId": "finding:h-b",
        "sourceEvidenceIds": ["prior-a"],
        "generator": {"method": "deterministic"},
        "notices": ["격리된 실습"],
        "guardrail": {"decisions": [{"decision": "ALLOW", "ruleId": "R-1"}]},
        "safety": {"synthetic": True},
        "executive_summary": "다른 사용자의 게시글을 삭제할 수 있는 "
        "접근 제어 취약점 1건을 확인했습니다.",
        "objective": "게시글 삭제 기능의 객체 수준 인가를 확인합니다.",
        "scope": "http://127.0.0.1:40123 (시험 환경). 공격자·피해자 계정을 사용했습니다.",
        "run_limitations": "확인한 경로 밖의 취약점이 없다는 의미는 아닙니다.",
        "findings": [{
            "id": "V-09", "finding_id": "finding:h-b", "verdict": "not_reproduced",
            "screenshots": [{"caption": "없는 사진", "ref": "evidence/images/forged.png"}],
            "title": "사용자 제어 키를 통한 권한 우회 (Authorization Bypass)",
            "severity": "medium", "cvss_score": 6.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", "cwe": "CWE-639",
            "location": "DELETE /api/posts/:id (id)", "privilege": "일반 사용자",
            "description": "다른 사용자의 게시글을 삭제할 수 있습니다.",
            "impact": "타인 데이터가 삭제될 수 있습니다.",
            "steps": ["소유자 세션으로 삭제를 요청한다.", "공격자 세션으로 같은 삭제를 요청한다.",
                      "두 응답과 목록 변화를 비교해 판정한다."],
            "evidence": [{"label": "[대조 요청]", "content": "DELETE /api/posts/2"},
                         {"label": "[공격 요청]", "content": "DELETE /api/posts/1"},
                         {"label": "[공격 응답] (일부 발췌)", "content": "HTTP/1.1 200"}],
            "checks": [{"item": "대조군 대비 결과 차이", "result": "타인 게시글 삭제 성공"}],
            "fix_summary": "서버에서 소유자를 확인", "fix_short": "삭제 전에 소유자를 비교합니다.",
            "fix_long": "객체 수준 인가 미들웨어와 회귀 테스트를 둡니다.",
            "limitations": "삭제 1건만 확인했습니다.", "references": ["CWE-639"],
        }],
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
        [finding] = model["findings"]
        assert (finding["id"], finding["finding_id"], finding["verdict"]) == (
            "V-01", finding_id, "confirmed")
        assert finding["cwe"] == "CWE-639" and finding["cvss_score"] == "6.5"
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


def test_completed_child_uses_its_own_verification_and_preserves_parent_origin(tmp_path, capsys):
    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general"))
    _add_subtask(db)
    output = tmp_path / "child"
    assert _run(_trigger(db, output, "finding:h-a", "sub-one"), client=writer()) == EXIT_OK
    result = _result(capsys)
    assert (result["runId"], result["subtaskId"], result["findingId"]) == (
        "run-general", "sub-one", "finding:h-a")
    source = json.loads((output / "bundle" / "run" / "finding.json").read_text("utf-8"))
    stored = json.loads((output / "bundle" / "run" / "report.json").read_text("utf-8"))
    events = json.loads((output / "bundle" / "run" / "events.json").read_text("utf-8"))
    model = json.loads((output / "report" / "report-model.json").read_text("utf-8"))
    assert source["subtaskId"] == "sub-one" and source["parentFindingId"] == "finding:h-a"
    assert source["confirmedProbes"] == [{"id": "p-a", "tool": "known_cross_user_delete_canary",
                                          "evidenceIds": ["ev-a"]}]
    assert stored["report"]["runId"] == "sub-one"
    assert stored["provenance"]["sourceFindingId"] == "finding:h-a"
    assert stored["provenance"]["sourceHypothesisId"] == "h-a"
    assert len(events["events"]) == 1 and events["events"][0]["stage"] == "verify"
    assert model["run"]["run_id"] == "run-general"
    assert model["sourceEvidenceIds"] == ["ev-a"]


def test_child_selection_rejects_unfinished_task_and_foreign_verification(tmp_path, capsys):
    for case in ("failed", "wrong-run", "foreign-verification"):
        db = tmp_path / f"{case}.sqlite"
        _store(db, _report("run-general"))
        child = _report("sub-one")
        if case == "wrong-run":
            child["runId"] = "other-task"
        event = _event("run-general", "h-a", "p-a", "ev-a")
        if case == "foreign-verification":
            event["response"]["evidenceIds"] = ["ev-b"]
        _add_subtask(db, child=child, task_status="failed" if case == "failed" else "completed",
                     event=event)
        output = tmp_path / case
        assert _run(_trigger(db, output, "finding:h-a", "sub-one"), client=FakeLLM([])) == EXIT_SOURCE
        assert _result(capsys)["error"]["code"] == "SOURCE_INVALID"
        assert not (output / "report").exists()


def test_child_trigger_requires_a_finding_and_run_store_source(tmp_path):
    data = json.loads(_trigger(tmp_path / "source.sqlite", tmp_path / "out", None, "sub-one"))
    with pytest.raises(ValueError, match="requires options.findingId"):
        parse_trigger(data)
    data["options"]["findingId"] = "finding:h-a"
    data["sources"]["run"]["kind"] = "pentest-db-disk"
    with pytest.raises(ValueError, match="requires a run-store source"):
        parse_trigger(data)


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
    assert "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" in preview and "6.5" in preview
    for absent in ("LLM", "상류 severity", "가드레일", "안전 속성", "프로필:",
                   "격리된 실습", "synthetic", "run/attack.json"):
        assert absent not in preview
    assert set(model) == SPEC_KEYS and set(model["findings"][0]) == FINDING_KEYS


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
    assert model["findings"][0]["finding_id"] == "finding:t-fa34bb39e407db7e"
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
    none = llm_model()
    none["findings"] = []
    with pytest.raises(ToolError, match="exactly one"):
        tools.finish_report(model=two)
    with pytest.raises(ToolError, match="exactly one"):
        tools.finish_report(model=none)
    assert not (tmp_path / "document").exists()
    tools.finish_report(model=llm_model())
    model = json.loads((tmp_path / "document" / "report-model.json").read_text("utf-8"))
    assert set(model) == SPEC_KEYS
    run = model.pop("run")
    assert run.pop("generated_at") != "2020-01-01 00:00:00 UTC"  # stamped by code
    assert run == {
        "run_id": "run-general", "target_origin": "http://127.0.0.1:40123",
        "target_name": "vul-web-1", "profile": "general",
        "started_at": "2026-10-28 00:00:00 UTC", "finished_at": "2026-10-28 00:00:03 UTC",
        "request_count": 2, "status": "completed", "incomplete": False,
    }
    assert "review_status" not in model  # internal report: no review-status line
    assert model["classification"] == "대외비 (CONFIDENTIAL)"
    assert model["sourceFindingId"] == "finding:h-a"
    assert model["sourceEvidenceIds"] == ["ev-a"]
    assert model["generator"] == {"method": "llm"}
    finding = model["findings"][0]
    assert (finding["id"], finding["finding_id"], finding["verdict"]) == (
        "V-01", "finding:h-a", "confirmed")
    # Without a verifier handoff there is no screenshot; a model-invented one is dropped.
    assert finding["screenshots"] == []


@pytest.mark.parametrize("change, problem", [
    (lambda m: m.pop("executive_summary"), "executive_summary"),
    (lambda m: m["findings"][0].update(severity="severe"), "severity"),
    (lambda m: m["findings"][0].update(cwe="639"), "cwe"),
    (lambda m: m["findings"][0].update(steps=["공격한다.", "비교한다."]), "steps"),
    (lambda m: m["findings"][0].update(
        evidence=[{"label": "[공격 요청]", "content": "DELETE /api/posts/1"}]), "evidence"),
    (lambda m: m["findings"][0].update(checks=[]), "checks"),
    (lambda m: m.update(sources=[{"collector": "c", "kind": "k", "status": "done", "note": ""}]),
     "sources"),
])
def test_finish_report_returns_what_the_llm_must_fix(tmp_path, change, problem):
    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general"))
    trigger = parse_trigger(json.loads(_trigger(db, tmp_path / "bundle-output", "finding:h-a")))
    tools = ReportTools(collect(trigger).bundle, tmp_path / "document")
    model = llm_model()
    change(model)
    with pytest.raises(ToolError, match=problem):
        tools.finish_report(model=model)
    assert not (tmp_path / "document").exists()


def test_run_header_falls_back_to_report_and_store_times(tmp_path):
    """Legacy report fields win; without them the store's own record is used."""
    db = tmp_path / "runs.sqlite"
    report = _report("run-general")
    report.update(startedAt="2026-10-27T00:00:00Z", completedAt="2026-10-27T00:10:00Z",
                  metrics={"requestCount": 7}, target={"origin": "http://127.0.0.1:40123",
                                                       "name": "대한대학교"})
    _store(db, report)
    trigger = parse_trigger(json.loads(_trigger(db, tmp_path / "out", "finding:h-a")))
    run = json.loads((collect(trigger).bundle / "run" / "finding.json").read_text("utf-8"))["run"]
    # State startedAt still wins (spec order); completedAt and metrics come from the report.
    assert (run["target_name"], run["started_at"], run["finished_at"], run["request_count"]) == (
        "대한대학교", "2026-10-28 00:00:00 UTC", "2026-10-27 00:10:00 UTC", 7)
