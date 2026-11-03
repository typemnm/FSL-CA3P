"""The report model sees masked credentials while sealed evidence stays unchanged."""

import json

from ca3p_report.llm.tools import ReportTools


def test_read_bundle_masks_structured_credentials_without_rewriting_evidence(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    source = bundle / "report.json"
    original = json.dumps(
        {
            "runId": "synthetic-report",
            "headers": {"Cookie": "synthetic-cookie", "Authorization": "Bearer synthetic-key"},
            "history": [{"password": "synthetic-password", "observation": "marker observed"}],
            "usage": {"prompt_tokens": 123},
        }
    ).encode()
    source.write_bytes(original)
    tools = ReportTools(bundle, tmp_path / "out")
    view = json.loads(tools.read_bundle("report.json"))
    assert view["headers"] == {"Cookie": "[REDACTED]", "Authorization": "[REDACTED]"}
    assert view["history"][0]["password"] == "[REDACTED]"
    assert view["history"][0]["observation"] == "marker observed"
    assert view["usage"]["prompt_tokens"] == 123
    assert source.read_bytes() == original


def test_read_bundle_masks_plain_text_headers_without_rewriting_evidence(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    source = bundle / "observation.txt"
    original = b"Synthetic observation\nAuthorization: Bearer synthetic-token\nmarker=ok"
    source.write_bytes(original)
    tools = ReportTools(bundle, tmp_path / "out")
    view = tools.read_bundle("observation.txt")
    assert "synthetic-token" not in view
    assert "marker=ok" in view
    assert source.read_bytes() == original


def test_finish_report_masks_secrets_the_model_wrote(tmp_path):
    from test_general_report import _report, _store, _trigger, llm_model

    from ca3p_report.collect.collector import collect
    from ca3p_report.trigger import parse_trigger

    db = tmp_path / "runs.sqlite"
    _store(db, _report("run-general"))
    collected = collect(parse_trigger(json.loads(_trigger(db, tmp_path / "out", "finding:h-a"))))
    model = llm_model()
    model["findings"][0]["evidence"][1]["content"] = (
        "DELETE /api/posts/1\nCookie: session=synthetic-session-value"
    )
    tools = ReportTools(collected.bundle, tmp_path / "document")
    tools.finish_report(model=model)
    for name in ("report-model.json", "report.md", "report.html"):
        assert "synthetic-session-value" not in (tmp_path / "document" / name).read_text("utf-8")
