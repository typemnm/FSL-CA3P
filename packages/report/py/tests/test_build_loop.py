"""End-to-end build stage with a scripted fake LLM (no network, no real model)."""

from __future__ import annotations

import json
import zipfile

import pytest
from conftest import needs_node, write_sources
from fixtures import ORIGIN, PAYLOAD, stored_xss_report

from ca3p_report.llm.client import LLMError
from ca3p_report.llm.loop import run_build


def model_for(run_id: str) -> dict:
    """What a model writes for the stored-XSS fixture: REPORT_SPEC JSON with one finding."""
    report = stored_xss_report(run_id)
    return {
        "executive_summary": "게시글 본문에서 저장형 XSS 1건을 확인했습니다. "
        "즉시 출력 인코딩을 적용해야 합니다.",
        "objective": "게시판의 저장형 XSS 여부를 확인합니다.",
        "scope": f"{report['target']['origin']} (시험 환경). 공격자 세션을 사용했습니다.",
        "run_limitations": "단일 반복으로 점검했습니다.",
        "omitted": ["세션 쿠키 — 사유: 비밀값에 해당하여 기재하지 않음"],
        "findings": [
            {
                "title": "저장형 XSS (Stored Cross-Site Scripting)",
                "severity": "medium",
                "cvss_score": "6.1",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cwe": report["finding"]["cwe"],
                "location": "POST /api/posts (content)",
                "privilege": "일반 사용자",
                "description": "게시글 본문이 인코딩 없이 화면에 출력됩니다.",
                "impact": "세션 탈취로 이어질 수 있습니다.",
                "steps": [
                    "일반 문자열로 게시글을 작성한다.",
                    "canary 페이로드를 담아 게시글을 작성한다.",
                    "브라우저 콜백 실행 여부를 비교해 판정한다.",
                ],
                "evidence": [
                    {"label": "[대조 요청]", "content": "기록된 대조 요청이 없습니다."},
                    {"label": "[공격 요청]", "content": f"POST /api/posts\n{PAYLOAD}"},
                ],
                "checks": [{"item": "브라우저 콜백 실행", "result": "예"}],
                "fix_summary": "출력 인코딩 적용",
                "fix_short": "본문을 HTML 인코딩해 출력합니다.",
                "fix_long": "HTML 정화 라이브러리와 회귀 테스트를 도입합니다.",
                "limitations": "",
                "references": ["CWE-79"],
            }
        ],
    }


class FakeLLM:
    """Returns a scripted sequence of assistant messages (OpenAI shape)."""

    def __init__(self, scripted):
        self._scripted = list(scripted)
        self.calls = 0

    def complete(self, messages, tools):
        self.calls += 1
        self.messages = list(messages)
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
    )
    # The traversal was refused by the tool, and the run still finished.
    [document] = (tmp_path / "out" / "report").glob("*.hwpx")
    assert document.name.startswith(f"{run_id}-") and len(document.stem) == len(run_id) + 9


@needs_node
def test_refused_report_is_returned_to_the_llm_to_fix(tmp_path, run_id):
    bundle = _bundle(tmp_path, run_id)
    broken = model_for(run_id)
    broken["findings"][0]["severity"] = "severe"
    broken["findings"][0]["steps"] = ["한 단계만 쓴다."]
    llm = FakeLLM(
        [
            _call("finish_report", {"model": broken}),
            _call("finish_report", {"model": model_for(run_id)}),
        ]
    )
    run_build(llm, bundle=bundle, out_dir=tmp_path / "out" / "report")
    refusal = json.loads(llm.messages[-1]["content"])
    assert refusal["ok"] is False and "severity" in refusal["error"] and "steps" in refusal["error"]
    assert llm.calls == 2 and (tmp_path / "out" / "report" / "report-model.json").is_file()


def test_llm_failure_propagates(tmp_path):
    class Boom:
        def complete(self, messages, tools):
            raise LLMError("boom")

    with pytest.raises(LLMError):
        run_build(
            Boom(),
            bundle=tmp_path,
            out_dir=tmp_path / "o",
        )


def test_redact_masks_newer_openai_key_formats():
    from ca3p_report.llm.redact import redact

    for key in (
        "sk-ABCDEFGHIJKLMNOP1234",
        "sk-proj-ABCdef1234567890abcd",
        "sk-svcacct-ABCdef1234567890abcd",
        "sk-ant-api03-ABCdef1234567890abcd",
    ):
        assert key not in redact(f"token is {key} end")


@needs_node
def test_legacy_loop_act_is_sealed_as_the_attack_source(tmp_path, run_id):
    bundle = _bundle(tmp_path, run_id)
    attack = json.loads((bundle / "run" / "attack.json").read_text("utf-8"))
    finding = json.loads((bundle / "run" / "finding.json").read_text("utf-8"))
    [record] = attack["records"]
    assert record["kind"] == "loop.act" and record["session"] == "attacker"
    assert record["request"]["method"] == "POST" and record["request"]["body"]["content"] == PAYLOAD
    assert record["response"]["status"] == 201
    assert finding["sourceFindingId"] == f"finding-{run_id}-stored-xss-canary"
    assert finding["status"] == "confirmed" and finding["evidenceIds"] == []
    # The header comes from the legacy report; it records no request count.
    assert finding["run"] == {
        "run_id": run_id,
        "target_origin": ORIGIN,
        "target_name": ORIGIN,
        "profile": "stored_xss_canary",
        "started_at": "2026-10-20 00:00:00 UTC",
        "finished_at": "2026-10-20 00:00:05 UTC",
        "request_count": None,
        "status": "completed",
        "incomplete": False,
    }
