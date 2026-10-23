"""End-to-end build stage with a scripted fake LLM (no network, no real model)."""

from __future__ import annotations

import json
import zipfile

import pytest
from conftest import needs_node, write_sources
from fixtures import PAYLOAD, stored_xss_report

from ca3p_report.llm.client import LLMError
from ca3p_report.llm.loop import run_build


def model_for(run_id: str) -> dict:
    report = stored_xss_report(run_id)
    finding = report["finding"]
    return {
        "generatedAt": "2026-10-20T00:00:00Z",
        "notices": ["격리 실습", "데이터 synthetic", "판정은 전달받은 값"],
        "generator": {"profile": "stored_xss"},
        "run": {
            "runId": run_id,
            "status": "completed",
            "testProfile": "stored_xss_canary",
            "target": {"origin": report["target"]["origin"]},
            "startedAt": report["startedAt"],
            "completedAt": report["completedAt"],
            "metrics": {"requestCount": 1},
        },
        "findings": [
            {
                "common": {
                    "title": finding["title"],
                    "cwe": finding["cwe"],
                    "location": {"method": "POST", "path": "/api/posts", "parameter": "content"},
                    "cvss": {
                        "version": "3.1",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        "score": 6.1,
                        "rating": "Medium",
                    },
                    "severity": finding["severity"],
                    "status": finding["status"],
                    "summary": "저장형 XSS가 브라우저에서 실행되었습니다.",
                    "remediation": "출력 인코딩/HTML 정화를 적용합니다.",
                    "limitations": "격리 실습 단일 반복 판정입니다.",
                },
                "reproduction": [{"step": 1, "text": "canary를 게시합니다."}],
                "textEvidence": [{"label": "점검 페이로드", "text": PAYLOAD}],
                "checks": [{"label": "브라우저 콜백 실행", "result": "예"}],
                "impact": "세션 탈취로 이어질 수 있습니다.",
                "profileData": {"marker": finding["marker"]},
            }
        ],
        "triage": {
            "status": "ok",
            "rows": [
                {"caseId": "LAB-STORED-XSS", "location": "POST /api/posts", "label": "재점검 후보"}
            ],
        },
        "priorCases": [],
        "guardrail": {"decisions": []},
        "safety": {},
        "references": {"collectors": [], "verifiedByStorage": False},
    }


class FakeLLM:
    """Returns a scripted sequence of assistant messages (OpenAI shape)."""

    def __init__(self, scripted):
        self._scripted = list(scripted)
        self.calls = 0

    def complete(self, messages, tools):
        self.calls += 1
        if not self._scripted:
            raise AssertionError("fake LLM ran out of scripted turns")
        return self._scripted.pop(0)


def _call(name, args):
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": name,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(args)},
            }
        ],
    }


def _bundle(tmp_path, run_id):
    reports_dir = tmp_path / "runs"
    from fixtures import stored_xss_events

    write_sources(
        run_id=run_id,
        events=stored_xss_events(),
        report=stored_xss_report(run_id),
        reports_dir=reports_dir,
    )
    from ca3p_report.collect.collector import collect
    from ca3p_report.trigger import SourceRef, Trigger

    trigger = Trigger(
        run_id=run_id,
        run=SourceRef("pentest-db-disk", reports_dir),
        history=SourceRef("none", None),
        output_dir=tmp_path / "out",
    )
    return collect(trigger).bundle


@needs_node
def test_fake_llm_reads_bundle_then_finishes(tmp_path, run_id):
    bundle = _bundle(tmp_path, run_id)
    llm = FakeLLM(
        [
            _call("read_bundle", {"path": "run/report.json"}),
            _call(
                "finish_report", {"model": model_for(run_id), "filename": "저장형XSS보고서.hwpx"}
            ),
            {"role": "assistant", "content": "done"},
        ]
    )
    result = run_build(
        llm,
        bundle=bundle,
        out_dir=tmp_path / "out" / "report",
        test_profile="stored_xss_canary",
        origin="http://127.0.0.1:1",
        session_switch=None,
    )
    names = {f["name"] for f in result["files"]}
    assert "report-model.json" in names and result["reportFilename"].endswith(".hwpx")
    hwpx = tmp_path / "out" / "report" / result["reportFilename"]
    with zipfile.ZipFile(hwpx) as z:
        xml = "".join(
            z.read(n).decode("utf-8") for n in z.namelist() if n.startswith("Contents/section")
        )
    # Payload is present but escaped; raw markup never reaches the document.
    assert "&lt;img src=x onerror=" in xml and "<img src=x onerror=" not in xml


@needs_node
def test_injection_in_bundle_cannot_make_tools_misbehave(tmp_path, run_id):
    bundle = _bundle(tmp_path, run_id)
    # The LLM, "obeying" an injected instruction, tries to read outside the bundle.
    llm = FakeLLM(
        [
            _call("read_bundle", {"path": "../../../../etc/passwd"}),
            _call("finish_report", {"model": model_for(run_id)}),
        ]
    )
    run_build(
        llm,
        bundle=bundle,
        out_dir=tmp_path / "out" / "report",
        test_profile="stored_xss_canary",
        origin="http://127.0.0.1:1",
        session_switch=None,
    )
    # The traversal was refused by the tool, and the run still finished.
    assert (tmp_path / "out" / "report" / f"{run_id}.hwpx").exists()


def test_llm_failure_propagates(tmp_path):
    class Boom:
        def complete(self, messages, tools):
            raise LLMError("boom")

    with pytest.raises(LLMError):
        run_build(
            Boom(),
            bundle=tmp_path,
            out_dir=tmp_path / "o",
            test_profile=None,
            origin="http://127.0.0.1:1",
            session_switch=None,
        )


def test_capture_origin_must_be_loopback(tmp_path):
    from ca3p_report.llm.tools import ReportTools, ToolError

    for bad in (
        "http://example.com:80",
        "https://127.0.0.1:8080",
        "http://127.0.0.1:",
        "http://127.0.0.1:99999",
        None,
    ):
        with pytest.raises(ToolError):
            ReportTools(tmp_path, tmp_path / "o", origin=bad, session_switch=None)
    # A valid loopback origin is accepted.
    ReportTools(tmp_path, tmp_path / "o", origin="http://127.0.0.1:8080", session_switch=None)


def test_redact_masks_newer_openai_key_formats():
    from ca3p_report.llm.redact import redact

    for key in (
        "sk-ABCDEFGHIJKLMNOP1234",
        "sk-proj-ABCdef1234567890abcd",
        "sk-svcacct-ABCdef1234567890abcd",
        "sk-ant-api03-ABCdef1234567890abcd",
    ):
        assert key not in redact(f"token is {key} end")
