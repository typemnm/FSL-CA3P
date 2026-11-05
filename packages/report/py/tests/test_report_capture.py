"""Fresh report-time screenshots are separate from verifier evidence."""

from __future__ import annotations

import json
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ca3p_report.cli import EXIT_OK, _run
from ca3p_report.llm.tools import ReportTools, ToolError
from test_build_loop import FakeLLM, _call
from test_general_report import _report, _result, _store, _trigger, llm_model, writer


def _site():
    class Page(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<!doctype html><title>Fresh view</title><h1>Target page</h1>"
            self.send_response(500 if self.path == "/" else 200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Page)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_fresh_capture_falls_back_from_broken_home_and_enters_hwpx(tmp_path, capsys):
    server, thread = _site()
    try:
        report = _report("run-general")
        report["target"]["origin"] = f"http://127.0.0.1:{server.server_port}"
        report["findings"][1]["asset"] = "/notices"
        db = tmp_path / "runs.sqlite"
        _store(db, report)
        output = tmp_path / "captured"
        assert _run(_trigger(db, output, "finding:h-a"), client=writer()) == EXIT_OK
        result = _result(capsys)
        model = json.loads((output / "report" / "report-model.json").read_text("utf-8"))
        images = model["findings"][0]["screenshots"]
        assert len(images) == 1
        assert "취약점 재현 증거 아님" in images[0]["caption"]
        assert (output / "bundle" / images[0]["ref"]).read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        assert any("/notices" in row["note"] for row in model["sources"])
        with zipfile.ZipFile(output / "report" / result["reportFilename"]) as archive:
            assert sum(name.startswith("BinData/") for name in archive.namelist()) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_llm_capture_tool_uses_same_report_image_path(tmp_path, capsys):
    server, thread = _site()
    try:
        report = _report("run-general")
        report["target"]["origin"] = f"http://127.0.0.1:{server.server_port}"
        db = tmp_path / "runs.sqlite"
        _store(db, report)
        output = tmp_path / "tool-captured"
        llm = FakeLLM([
            _call("capture_screenshot", {"path": "/notices"}),
            _call("finish_report", {"model": llm_model()}),
        ])
        assert _run(_trigger(db, output, "finding:h-a"), client=llm) == EXIT_OK
        _result(capsys)
        model = json.loads((output / "report" / "report-model.json").read_text("utf-8"))
        assert len(model["findings"][0]["screenshots"]) == 1
        assert any("/notices" in row["note"] for row in model["sources"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_capture_failure_is_recorded_without_discarding_report(tmp_path, capsys):
    report = _report("run-general")
    report["target"]["origin"] = "http://127.0.0.1:1"
    db = tmp_path / "runs.sqlite"
    _store(db, report)
    output = tmp_path / "offline"
    assert _run(_trigger(db, output, "finding:h-a"), client=writer()) == EXIT_OK
    result = _result(capsys)
    model = json.loads((output / "report" / "report-model.json").read_text("utf-8"))
    assert model["findings"][0]["screenshots"] == []
    assert any("촬영 실패" in row["note"] for row in model["sources"])
    assert (output / "report" / result["reportFilename"]).is_file()


def test_capture_origin_accepts_docker_alias_and_https(tmp_path):
    from ca3p_report.llm.tools import _validate_origin

    for origin in ("http://daehan:4101", "https://example.com"):
        assert _validate_origin(origin) == origin
    for origin in ("http://daehan:4101/", "http://user@daehan:4101", "ftp://example.com"):
        try:
            _validate_origin(origin)
        except ToolError:
            pass
        else:
            raise AssertionError(f"accepted invalid origin: {origin}")
