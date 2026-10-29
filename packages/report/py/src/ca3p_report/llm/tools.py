"""The tools the LLM calls to write the report. Each enforces its own limits.

- read_bundle: read a redacted view of a file inside the sealed bundle only.
- capture_screenshot: drive the Node sandbox against the bundle's loopback origin only,
  replaying at most the one session-switch the collector recorded.
- finish_report: mask the LLM-assembled ReportModel, render HWPX + Markdown + JSON, and end.

The legacy LLM path remains a draft for human review. General findings are
selected and rendered from verified source data, with their identity checked here.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..hwpx.filename import normalize_filename
from ..hwpx.writer import write_hwpx, write_markdown
from .redact import redact

CAPTURE_CLI = Path(__file__).resolve().parents[4] / "capture" / "cli.mjs"
MAX_READ_BYTES = 2_000_000
# The capture target must be a loopback origin with a valid port (defense-in-depth on the
# Python side; the Node sandbox enforces the same). Blocks SSRF to an arbitrary host/port.
_LOOPBACK_ORIGIN = re.compile(r"^http://(?:127\.0\.0\.1|\[::1\]):([1-9]\d{0,4})$")


def _validate_origin(origin: object) -> str:
    match = _LOOPBACK_ORIGIN.fullmatch(origin) if isinstance(origin, str) else None
    if not match or int(match.group(1)) > 65535:
        raise ToolError("capture origin must be http://127.0.0.1:<port>")
    return origin


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
        self._origin = _validate_origin(origin)
        self._session_switch = session_switch
        self._node = node
        self._evidence = self._bundle / "evidence" / "images"
        self.finished: FinishResult | None = None

    # -- read_bundle -------------------------------------------------------------------
    def _read_bundle_bytes(self, path: str) -> bytes:
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
        return data

    def read_bundle(self, path: str) -> str:
        data = self._read_bundle_bytes(path)
        text = data.decode("utf-8", errors="replace")
        try:
            value = json.loads(text)
        except ValueError:
            return redact(text)
        # Keep the sealed evidence and its hashes unchanged; only the view sent
        # to the report model is masked, including structured credential keys.
        return json.dumps(redact(value), ensure_ascii=False)

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
            path = self._session_switch.get("path")
            # The path comes from the collector, but a crafted hints file could carry an
            # odd value; require a plain absolute path (no scheme/host/query) before replay.
            if (
                not isinstance(path, str)
                or not path.startswith("/")
                or any(c in path for c in " ?#\\")
                or path.startswith("//")
            ):
                raise ToolError("session-switch path is not a plain absolute path")
            switch = {
                "method": self._session_switch.get("method", "POST"),
                "path": path,
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
        # The writer resolves images[].ref against the bundle root; hand the LLM that exact
        # value so it copies it instead of guessing from the absolute path.
        for record in result.get("captures") or []:
            if isinstance(record, dict) and isinstance(record.get("path"), str):
                record["ref"] = f"evidence/images/{Path(record['path']).name}"
        return result

    # -- finish_report -----------------------------------------------------------------
    def finish_report(self, *, model: dict, filename: str | None = None) -> dict:
        if not isinstance(model, dict):
            raise ToolError("model must be an object")
        selection_path = self._bundle / "run" / "selection.json"
        if selection_path.is_file():
            try:
                selection = json.loads(self._read_bundle_bytes("run/selection.json"))
            except (ValueError, KeyError) as exc:
                raise ToolError("general finding selection is invalid") from exc
            finding_rows = model.get("findings")
            finding = (
                finding_rows[0]
                if isinstance(finding_rows, list) and len(finding_rows) == 1 else None
            )
            common = finding.get("common") if isinstance(finding, dict) else None
            model_run = model.get("run") if isinstance(model.get("run"), dict) else {}
            generator = model.get("generator") if isinstance(model.get("generator"), dict) else {}
            if (not isinstance(selection, dict)
                or selection.get("schemaVersion") != "general-finding-selection/1"
                or model.get("sourceFindingId") != selection.get("sourceFindingId")
                or model.get("sourceEvidenceIds") != selection.get("verificationEvidenceIds")
                or not isinstance(common, dict)
                or common.get("findingId") != selection.get("sourceFindingId")
                or common.get("status") != "confirmed"
                or model_run.get("runId") != selection.get("runId")
                or model_run.get("status") != selection.get("runStatus")
                or generator.get("method") != "deterministic"):
                raise ToolError("general report does not match the confirmed source finding")
        elif "sourceFindingId" in model:
            raise ToolError("legacy report cannot claim a general source finding")
        run_id = str(
            ((model.get("run") or {}) if isinstance(model.get("run"), dict) else {}).get("runId")
            or "report"
        )
        safe_model = redact(model)
        for finding in safe_model.get("findings") or []:
            for image in (finding.get("images") or []) if isinstance(finding, dict) else []:
                ref = image.get("ref") if isinstance(image, dict) else None
                if isinstance(ref, str) and ref and "/" not in ref:
                    image["ref"] = f"evidence/images/{ref}"  # bare file name from the LLM
        # Source review state is carried deterministically, independent of prose
        # generation. A writer cannot omit it or replace it with invented approval.
        safe_model.pop("referenceContext", None)
        history_path = self._bundle / "history" / "casper.json"
        if history_path.is_file():
            history_bytes = self._read_bundle_bytes("history/casper.json")
            history = json.loads(history_bytes)
            if "referenceContext" in history:
                manifest = json.loads(self._read_bundle_bytes("manifest.json"))
                entry = next(
                    (item for item in manifest["files"] if item["path"] == "history/casper.json"),
                    None,
                )
                expected = "sha256:" + hashlib.sha256(history_bytes).hexdigest()
                if entry is None or entry["sha256"] != expected:
                    raise ToolError("reference context does not match the sealed manifest")
                context = history["referenceContext"]
                if (
                    not isinstance(context, dict)
                    or context.get("schema_version") != "casper-reference-1"
                    or context.get("automatic_execution_allowed") is not False
                ):
                    raise ToolError("unsupported reference context")
                safe_model["referenceContext"] = redact(context)
        self._out.mkdir(parents=True, exist_ok=True)
        name = normalize_filename(filename, run_id)
        hwpx_path = self._out / name
        model_path = self._out / "report-model.json"
        md_path = self._out / "report.md"
        write_hwpx(safe_model, hwpx_path, image_root=self._bundle)
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
