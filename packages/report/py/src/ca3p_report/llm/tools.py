"""The tools the LLM calls to write the report. Each enforces its own limits.

- read_bundle: read a file from inside the sealed bundle only.
- capture_screenshot: drive the Node sandbox against the bundle's loopback origin only,
  replaying at most the one session-switch the collector recorded.
- finish_report: mask the LLM-assembled ReportModel, render HWPX + Markdown + JSON, and end.

Nothing here verifies the report's content (no verifier, PLAN §1.4.1); the tools only
bound actions. Content accuracy rests on the prompt and human review.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..hwpx.filename import normalize_filename
from ..hwpx.writer import write_hwpx, write_markdown
from .redact import redact

CAPTURE_CLI = Path(__file__).resolve().parents[4] / "capture" / "cli.mjs"
MAX_READ_BYTES = 2_000_000


class ToolError(RuntimeError):
    """A tool refused an argument. Returned to the LLM so it can correct course."""


@dataclass
class FinishResult:
    files: list[dict]
    out_dir: Path
    report_filename: str


class ReportTools:
    def __init__(
        self,
        bundle: Path,
        out_dir: Path,
        *,
        origin: str,
        session_switch: dict | None,
        node: str = "node",
    ):
        self._bundle = Path(bundle).resolve()
        self._out = Path(out_dir)
        self._origin = origin
        self._session_switch = session_switch
        self._node = node
        self._evidence = self._bundle / "evidence" / "images"
        self.finished: FinishResult | None = None

    # -- read_bundle -------------------------------------------------------------------
    def read_bundle(self, path: str) -> str:
        if not isinstance(path, str) or not path:
            raise ToolError("path must be a non-empty string")
        target = (self._bundle / path).resolve()
        if target != self._bundle and not target.is_relative_to(self._bundle):
            raise ToolError("path escapes the bundle")
        if target.is_symlink() or not target.is_file():
            raise ToolError("not a readable file inside the bundle")
        data = target.read_bytes()
        if len(data) > MAX_READ_BYTES:
            raise ToolError("file too large to read")
        return data.decode("utf-8", errors="replace")

    # -- capture_screenshot ------------------------------------------------------------
    def capture_screenshot(
        self, *, selector: str | None = None, full_page: bool = False, viewer: str | None = None
    ) -> dict:
        self._evidence.mkdir(parents=True, exist_ok=True)
        args = [
            self._node,
            str(CAPTURE_CLI),
            "--origin",
            self._origin,
            "--expected-origin",
            self._origin,
            "--out",
            str(self._evidence),
        ]
        if selector:
            args += ["--selector", selector]
        if full_page:
            args.append("--full-page")
        # A viewer switch is built from the collector's recorded method/path only; the LLM
        # supplies just the account id. The sandbox also checks it against the allow-list.
        if viewer is not None:
            if not self._session_switch:
                raise ToolError("no session-switch is permitted for this run")
            switch = {
                "method": self._session_switch.get("method", "POST"),
                "path": self._session_switch.get("path"),
                "body": {"userId": viewer},
            }
            args += ["--session", json.dumps(switch), "--allow-session", json.dumps([switch])]
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolError(f"capture failed: {type(exc).__name__}") from exc
        try:
            result = json.loads(proc.stdout.splitlines()[-1]) if proc.stdout.strip() else {}
        except (ValueError, IndexError):
            raise ToolError("capture returned no JSON") from None
        return result

    # -- finish_report -----------------------------------------------------------------
    def finish_report(self, *, model: dict, filename: str | None = None) -> dict:
        if not isinstance(model, dict):
            raise ToolError("model must be an object")
        run_id = str(
            ((model.get("run") or {}) if isinstance(model.get("run"), dict) else {}).get("runId")
            or "report"
        )
        safe_model = redact(model)
        self._out.mkdir(parents=True, exist_ok=True)
        name = normalize_filename(filename, run_id)
        hwpx_path = self._out / name
        model_path = self._out / "report-model.json"
        md_path = self._out / "report.md"
        write_hwpx(safe_model, hwpx_path, image_root=self._evidence)
        write_markdown(safe_model, md_path)
        model_path.write_text(json.dumps(safe_model, ensure_ascii=False, indent=2), "utf-8")
        files = [_file_entry(p) for p in (hwpx_path, model_path, md_path)]
        self.finished = FinishResult(files=files, out_dir=self._out, report_filename=name)
        return {"ok": True, "files": files}


def _file_entry(path: Path) -> dict:
    import hashlib

    data = path.read_bytes()
    return {
        "name": path.name,
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def tool_schemas() -> list[dict]:
    """OpenAI-compatible function tool definitions."""
    return [
        {
            "type": "function",
            "function": {
                "name": "read_bundle",
                "description": "Read a UTF-8 file from inside the sealed ReportInput bundle.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path relative to the bundle root, "
                            "e.g. run/report.json, run/events.json, history/casper.json, "
                            "hints/capture.json, manifest.json",
                        }
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "capture_screenshot",
                "description": "Screenshot the live loopback target. GET-only sandbox; an optional "
                "viewer switch replays only the collector's recorded session request.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "selector": {
                            "type": "string",
                            "description": "CSS selector to capture; omit for a full page",
                        },
                        "full_page": {"type": "boolean"},
                        "viewer": {
                            "type": "string",
                            "description": "Account id to switch to before the "
                            "shot, e.g. the victim; omit to stay as the default viewer",
                        },
                    },
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "finish_report",
                "description": "Render the ReportModel to HWPX (+ Markdown + JSON) and end. "
                "Secrets are masked before rendering.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "model": {
                            "type": "object",
                            "description": "The full ReportModel (report-1.0).",
                        },
                        "filename": {"type": "string", "description": "Proposed .hwpx file name."},
                    },
                    "required": ["model"],
                },
            },
        },
    ]
