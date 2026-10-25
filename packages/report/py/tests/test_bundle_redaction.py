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
    tools = ReportTools(bundle, tmp_path / "out", origin="http://127.0.0.1:4100", session_switch=None)
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
    tools = ReportTools(bundle, tmp_path / "out", origin="http://127.0.0.1:4100", session_switch=None)
    view = tools.read_bundle("observation.txt")
    assert "synthetic-token" not in view
    assert "marker=ok" in view
    assert source.read_bytes() == original
