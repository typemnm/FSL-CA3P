"""The tools the LLM calls to write the report. Each enforces its own limits.

- read_bundle: read a redacted view of a file inside the sealed bundle only.
- finish_report: mask the LLM-assembled ReportModel, overwrite the fields the sealed bundle
  already decides (finding identity, verdict, evidence IDs, verifier screenshots), render
  HWPX + Markdown + HTML + JSON, and end.

The LLM writes the prose (CWE, CVSS, summary, reproduction, remediation, impact). It cannot
change what was verified: those fields come from run/finding.json and run/verification.json.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..hwpx.filename import normalize_filename
from ..hwpx.writer import write_html, write_hwpx, write_markdown
from .redact import redact

MAX_READ_BYTES = 2_000_000


class ToolError(RuntimeError):
    """A tool refused an argument. Returned to the LLM so it can correct course."""


@dataclass
class FinishResult:
    files: list[dict]
    out_dir: Path
    report_filename: str


def _object(parent: dict, key: str) -> dict:
    value = parent.get(key)
    if not isinstance(value, dict):
        value = parent[key] = {}
    return value


def _image_ref(ref: object) -> str | None:
    if not isinstance(ref, str) or not ref:
        return None
    return ref if "/" in ref else f"evidence/images/{ref}"  # bare file name from the LLM


class ReportTools:
    def __init__(self, bundle: Path, out_dir: Path):
        self._bundle = Path(bundle).resolve()
        self._out = Path(out_dir)
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

    def _read_json(self, path: str) -> object:
        try:
            return json.loads(self._read_bundle_bytes(path))
        except ValueError as exc:
            raise ToolError(f"{path} is not valid JSON") from exc

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

    # -- finish_report -----------------------------------------------------------------
    def _verification_images(self, proposed: object) -> list[dict]:
        """The verifier's sealed screenshots. The LLM may only place them (step, caption)."""
        if not (self._bundle / "run" / "verification.json").is_file():
            return []
        document = self._read_json("run/verification.json")
        placed = {
            _image_ref(item.get("ref")): item
            for item in (proposed if isinstance(proposed, list) else [])
            if isinstance(item, dict)
        }
        images = []
        for record in document.get("images") or []:
            llm = placed.get(record["ref"], {})
            step = llm.get("step")
            caption = llm.get("caption")
            images.append({
                "step": step if isinstance(step, int) and not isinstance(step, bool) else None,
                "caption": caption if isinstance(caption, str) and caption.strip()
                else record.get("label") or "검증 캡처",
                "ref": record["ref"],
                "integrity": "ok",
            })
        return images

    def _fix_verified_fields(self, model: dict) -> None:
        source = self._read_json("run/finding.json")
        finding = model["findings"][0]
        common = _object(finding, "common")
        common["findingId"] = source["sourceFindingId"]
        common["status"] = source["status"]
        run = _object(model, "run")
        run["runId"] = source["runId"]
        run["status"] = source["runStatus"]
        run["incomplete"] = source["incomplete"]
        model["sourceFindingId"] = source["sourceFindingId"]
        model["sourceEvidenceIds"] = list(source["evidenceIds"])
        model["generator"] = {"method": "llm"}
        model["generatedAt"] = datetime.now(UTC).isoformat()
        finding["images"] = self._verification_images(finding.get("images"))
        # Notices are dropped: the report states facts in its sections, not in a cover box.
        for key in ("notices", "guardrail", "safety", "referenceContext"):
            model.pop(key, None)

    def _reference_context(self) -> dict | None:
        """Source review state is carried deterministically, independent of prose generation."""
        if not (self._bundle / "history" / "casper.json").is_file():
            return None
        history_bytes = self._read_bundle_bytes("history/casper.json")
        history = json.loads(history_bytes)
        if "referenceContext" not in history:
            return None
        manifest = self._read_json("manifest.json")
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
        return redact(context)

    def finish_report(self, *, model: dict, filename: str | None = None) -> dict:
        if not isinstance(model, dict):
            raise ToolError("model must be an object")
        findings = model.get("findings")
        one = isinstance(findings, list) and len(findings) == 1 and isinstance(findings[0], dict)
        if not one:
            raise ToolError("model.findings must hold exactly one finding")
        safe_model = redact(model)
        # After masking, so the sealed identifiers are never altered by it.
        self._fix_verified_fields(safe_model)
        if (context := self._reference_context()) is not None:
            safe_model["referenceContext"] = context
        self._out.mkdir(parents=True, exist_ok=True)
        # Fallback differs per finding so two reports of one run never share a name.
        finding_hash = hashlib.sha256(safe_model["sourceFindingId"].encode("utf-8")).hexdigest()
        fallback = f"{safe_model['run']['runId'][:100]}-{finding_hash[:8]}"
        name = normalize_filename(filename, fallback)
        hwpx_path = self._out / name
        model_path = self._out / "report-model.json"
        md_path = self._out / "report.md"
        html_path = self._out / "report.html"
        write_hwpx(safe_model, hwpx_path, image_root=self._bundle)
        write_markdown(safe_model, md_path)
        write_html(safe_model, html_path, image_root=self._bundle)
        model_path.write_text(json.dumps(safe_model, ensure_ascii=False, indent=2), "utf-8")
        files = [_file_entry(p) for p in (hwpx_path, model_path, md_path, html_path)]
        self.finished = FinishResult(files=files, out_dir=self._out, report_filename=name)
        return {"ok": True, "files": files}


def _file_entry(path: Path) -> dict:
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
                            "description": "Path relative to the bundle root, e.g. "
                            "run/finding.json, run/attack.json, run/verification.json, "
                            "run/report.json, run/events.json, history/casper.json, manifest.json",
                        }
                    },
                    "required": ["path"],
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
