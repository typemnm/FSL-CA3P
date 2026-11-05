"""The tools the LLM calls to write the report. Each enforces its own limits.

- read_bundle: read a redacted view of a file inside the sealed bundle only.
- capture_screenshot: capture a new view of the run target, within its origin and scope.
- finish_report: check and mask the LLM-written REPORT_SPEC JSON, overwrite the fields the
  sealed bundle already decides (run header, finding identity, verdict, evidence IDs, verifier
  screenshots), render HWPX + Markdown + HTML + JSON, and end.

The LLM writes the prose (CWE, CVSS, summary, steps, evidence, remediation, impact). It cannot
change what was verified: those fields come from run/finding.json and run/verification.json.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from ..collect.finding import TIME_FORMAT
from ..hwpx.filename import normalize_filename
from ..hwpx.writer import write_html, write_hwpx, write_markdown
from .redact import redact

MAX_READ_BYTES = 2_000_000
_SOURCE_CAPTURE_CLI = Path(__file__).resolve().parents[4] / "capture" / "cli.mjs"
CAPTURE_CLI = next((candidate for candidate in (
    _SOURCE_CAPTURE_CLI,
    *(parent / "packages" / "report" / "capture" / "cli.mjs"
      for parent in (Path.cwd(), *Path.cwd().parents)),
) if candidate.is_file()), _SOURCE_CAPTURE_CLI)
CLASSIFICATION = "대외비 (CONFIDENTIAL)"
SCREENSHOT_NOTE = " (보조 자료, 판정 근거 아님)"
SEVERITIES = ("critical", "high", "medium", "low", "info")
SOURCE_STATUSES = ("captured", "completed", "available", "empty")
CWE = re.compile(r"CWE-\d+")
# REPORT_SPEC §3: what the LLM writes. Anything else it sends is dropped.
REQUIRED_TEXT = ("executive_summary", "objective", "scope", "run_limitations")
LLM_KEYS = (*REQUIRED_TEXT, "method", "sources", "history", "omitted", "findings")
FINDING_TEXT = ("title", "cvss_score", "cvss_vector", "cwe", "location", "privilege",
                "description", "impact", "fix_summary", "fix_short", "fix_long")
FINDING_KEYS = (*FINDING_TEXT, "severity", "steps", "evidence", "checks", "limitations",
                "references")


class ToolError(RuntimeError):
    """A tool refused an argument. Returned to the LLM so it can correct course."""


def _validate_origin(origin: object) -> str:
    try:
        parsed = urlsplit(origin) if isinstance(origin, str) else None
        valid = (parsed is not None and parsed.scheme in ("http", "https")
                 and parsed.hostname and parsed.port != 0 and not parsed.username
                 and not parsed.password and not parsed.path and not parsed.query
                 and not parsed.fragment and "@" not in parsed.netloc
                 and not parsed.netloc.endswith(":")
                 and origin == f"{parsed.scheme}://{parsed.netloc}")
    except ValueError:
        valid = False
    if not valid:
        raise ToolError("capture origin must be a bare HTTP(S) origin")
    return origin


@dataclass
class FinishResult:
    files: list[dict]
    out_dir: Path
    report_filename: str


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _texts(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _rows(value: object, keys: tuple[str, ...]) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, dict) and all(isinstance(item.get(key), str) for key in keys)
        for item in value
    )


def _problems(model: dict) -> list[str]:
    """What keeps this model from being a REPORT_SPEC report; told to the LLM to fix."""
    finding = model["findings"][0]
    problems = [f"{key} is required" for key in REQUIRED_TEXT if not _text(model.get(key))]
    problems += [f"findings[0].{key} is required" for key in FINDING_TEXT
                 if not _text(finding.get(key))]
    if finding.get("severity") not in SEVERITIES:
        problems.append(f"findings[0].severity must be one of {', '.join(SEVERITIES)}")
    if _text(finding.get("cwe")) and not CWE.fullmatch(finding["cwe"]):
        problems.append("findings[0].cwe must look like CWE-89")
    if _text(finding.get("cvss_vector")) and not finding["cvss_vector"].startswith("CVSS:3.1/"):
        problems.append("findings[0].cvss_vector must be a CVSS:3.1/ vector")
    steps = finding.get("steps")
    if not _texts(steps) or len(steps) < 3 or not all(_text(step) for step in steps):
        problems.append("findings[0].steps needs at least 3 steps: control, attack, comparison")
    evidence = finding.get("evidence")
    if not _rows(evidence, ("label", "content")) or not all(
        any(word in item["label"] for item in evidence) for word in ("대조", "공격")
    ):
        problems.append("findings[0].evidence needs [{label, content}] items with both a "
                        "control ([대조 ...]) and an attack ([공격 ...]) item")
    if not _rows(finding.get("checks"), ("item", "result")) or not finding["checks"]:
        problems.append("findings[0].checks needs [{item, result}] rows")
    if not isinstance(finding.get("limitations"), str):
        problems.append("findings[0].limitations must be a string")
    if not _texts(finding.get("references")):
        problems.append("findings[0].references must be a list of strings")
    if not isinstance(model.get("method", ""), str):
        problems.append("method must be a string")
    sources = model.get("sources", [])
    if not _rows(sources, ("collector", "kind", "status", "note")) or any(
        item["status"] not in SOURCE_STATUSES for item in sources
    ):
        problems.append("sources must be [{collector, kind, status, note}] with status one of "
                        + ", ".join(SOURCE_STATUSES))
    if not _rows(model.get("history", []), ("date", "finding", "result")):
        problems.append("history must be [{date, finding, result}]")
    if not _texts(model.get("omitted", [])):
        problems.append("omitted must be a list of strings")
    return problems


class ReportTools:
    def __init__(self, bundle: Path, out_dir: Path, *, node: str = "node"):
        self._bundle = Path(bundle).resolve()
        self._out = Path(out_dir)
        self._node = node
        self._evidence = self._bundle / "evidence" / "images"
        self._capture_records: list[dict] = []
        self._capture_error: str | None = None
        self._capture_attempted = False
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

    # -- capture_screenshot ------------------------------------------------------------
    def _capture_target(self) -> tuple[str, dict | None, dict]:
        envelope = self._read_json("run/report.json")
        report = envelope.get("report") if isinstance(envelope, dict) else None
        if not isinstance(report, dict):
            raise ToolError("run report has no capture target")
        target = report.get("target") if isinstance(report.get("target"), dict) else {}
        origin = _validate_origin(target.get("origin"))
        external = target.get("kind") == "external" or report.get("inspectionMode") == "external-general"
        scope = report.get("scope") if external else None
        if external and not isinstance(scope, dict):
            raise ToolError("external capture scope is missing")
        return origin, scope, report

    def _capture_paths(self, origin: str, scope: dict | None, report: dict) -> list[str]:
        if scope is not None:
            target = report.get("target") or {}
            entry = target.get("entryUrl")
            try:
                parsed = urlsplit(entry) if isinstance(entry, str) else None
            except ValueError:
                parsed = None
            if parsed and f"{parsed.scheme}://{parsed.netloc}" == origin:
                return [(parsed.path or "/") + ("?" + parsed.query if parsed.query else "")]
            return [scope.get("pathPrefix", "/")]
        paths = ["/"]
        source = self._read_json("run/finding.json")
        selected = source.get("finding") if isinstance(source, dict) else None
        findings = report.get("findings") if isinstance(report.get("findings"), list) else []
        for row in ([selected] if selected else []) + findings:
            asset = row.get("asset") if isinstance(row, dict) else None
            if (isinstance(asset, str) and asset.startswith("/") and not asset.startswith("//")
                and not any(char in asset for char in "?#:\\")
                and not asset.startswith("/api/")
                and not any(part in {"delete", "import", "logout", "reset"}
                            for part in asset.strip("/").lower().split("/"))
                and asset not in paths):
                paths.append(asset)
            if len(paths) >= 4:
                break
        return paths

    def capture_screenshot(
        self, *, selector: str | None = None, full_page: bool = False, path: str | None = None
    ) -> dict:
        if path is not None and not isinstance(path, str):
            raise ToolError("capture path must be a string")
        if selector is not None and not isinstance(selector, str):
            raise ToolError("capture selector must be a string")
        if not isinstance(full_page, bool):
            raise ToolError("full_page must be a boolean")
        if len(self._capture_records) >= 2:
            raise ToolError("report capture limit reached")
        origin, scope, report = self._capture_target()
        capture_path = path if path is not None else self._capture_paths(origin, scope, report)[0]
        self._evidence.mkdir(parents=True, exist_ok=True)
        args = [self._node, str(CAPTURE_CLI), "--origin", origin,
                "--expected-origin", origin, "--out", str(self._evidence),
                "--path", capture_path]
        if scope is not None:
            args += ["--external-scope", json.dumps(scope)]
        if selector is not None:
            args += ["--selector", selector]
        if full_page:
            args.append("--full-page")
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolError(f"capture failed: {type(exc).__name__}") from exc
        try:
            result = json.loads(proc.stdout.splitlines()[-1]) if proc.stdout.strip() else {}
        except (ValueError, IndexError):
            raise ToolError("capture returned no JSON") from None
        if proc.returncode != 0 or not isinstance(result, dict) or result.get("ok") is not True:
            error = result.get("error") if isinstance(result, dict) else None
            code = error.get("code") if isinstance(error, dict) else "CAPTURE_FAILED"
            raise ToolError(f"capture failed: {code}")
        captures = result.get("captures")
        if not isinstance(captures, list) or not captures or len(captures) + len(self._capture_records) > 2:
            raise ToolError("capture returned an invalid image count")
        for record in captures:
            if (not isinstance(record, dict) or not isinstance(record.get("path"), str)
                or not isinstance(record.get("pageUrl"), str)
                or not isinstance(record.get("capturedAt"), str)):
                raise ToolError("capture returned invalid image metadata")
            image = Path(record["path"]).resolve()
            if image.parent != self._evidence.resolve() or not image.is_file():
                raise ToolError("capture returned an image outside the evidence directory")
            data = image.read_bytes()
            if not data.startswith(b"\x89PNG\r\n\x1a\n") or record.get("sizeBytes") != len(data) \
               or record.get("sha256") != "sha256:" + hashlib.sha256(data).hexdigest():
                raise ToolError("capture image integrity check failed")
            record["ref"] = f"evidence/images/{image.name}"
        self._capture_records.extend(captures)
        return result

    def _capture_report_view(self) -> None:
        if self._capture_records or self._capture_attempted:
            return
        self._capture_attempted = True
        try:
            origin, scope, report = self._capture_target()
            paths = self._capture_paths(origin, scope, report)
        except ToolError as exc:
            self._capture_error = str(exc)
            return
        for path in paths:
            try:
                self.capture_screenshot(path=path)
                return
            except ToolError as exc:
                self._capture_error = str(exc)

    def _attach_report_capture(self, model: dict) -> None:
        self._capture_report_view()
        finding = model["findings"][0]
        screenshots = finding["screenshots"]
        sources = model.setdefault("sources", [])
        for shot in self._capture_records:
            screenshots.append({
                "caption": "보고서 작성 시 새로 촬영한 대상 화면 (취약점 재현 증거 아님)"
                           + SCREENSHOT_NOTE,
                "ref": shot["ref"],
            })
            sources.append({"collector": "보고서 화면 촬영", "kind": "대상 화면",
                            "status": "captured",
                            "note": f"주소: {redact(shot['pageUrl'])}; 촬영 시각: {shot['capturedAt']}"})
        if not self._capture_records:
            sources.append({"collector": "보고서 화면 촬영", "kind": "대상 화면",
                            "status": "empty",
                            "note": f"촬영 실패: {self._capture_error or '화면 없음'}"})

    # -- finish_report -----------------------------------------------------------------
    def _screenshots(self) -> list[dict]:
        """The verifier's sealed screenshots; the LLM cannot add, drop or caption them."""
        if not (self._bundle / "run" / "verification.json").is_file():
            return []
        document = self._read_json("run/verification.json")
        return [
            {"caption": redact(record.get("label") or "검증 화면") + SCREENSHOT_NOTE,
             "ref": record["ref"]}
            for record in document.get("images") or []
        ]

    def _fix_verified_fields(self, model: dict) -> None:
        source = self._read_json("run/finding.json")
        model["run"] = {**source["run"], "generated_at": datetime.now(UTC).strftime(TIME_FORMAT)}
        finding = model["findings"][0]
        finding["id"] = "V-01"
        finding["finding_id"] = source["sourceFindingId"]
        finding["verdict"] = "confirmed" if source["status"] == "confirmed" else "unverified"
        finding["screenshots"] = self._screenshots()
        model.pop("review_status", None)
        model["classification"] = CLASSIFICATION
        model["sourceFindingId"] = source["sourceFindingId"]
        model["sourceEvidenceIds"] = list(source["evidenceIds"])
        model["generator"] = {"method": "llm"}

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
            raise ToolError("model.findings must hold exactly one finding object")
        written = {key: model[key] for key in LLM_KEYS if model.get(key) is not None}
        written["findings"] = [{key: findings[0][key] for key in FINDING_KEYS
                                if findings[0].get(key) is not None}]
        score = written["findings"][0].get("cvss_score")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            written["findings"][0]["cvss_score"] = str(score)
        safe_model = redact(written)
        if problems := _problems(safe_model):
            raise ToolError("fix and call finish_report again: " + "; ".join(problems))
        # After masking, so the sealed identifiers are never altered by it.
        self._fix_verified_fields(safe_model)
        self._attach_report_capture(safe_model)
        if (context := self._reference_context()) is not None:
            safe_model["referenceContext"] = context
        self._out.mkdir(parents=True, exist_ok=True)
        # Fallback differs per finding so two reports of one run never share a name.
        finding_hash = hashlib.sha256(safe_model["sourceFindingId"].encode("utf-8")).hexdigest()
        fallback = f"{safe_model['run']['run_id'][:100]}-{finding_hash[:8]}"
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
                "name": "capture_screenshot",
                "description": "Capture a fresh view of the run target. The target origin and external scope are fixed by the run.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Same-origin absolute path; defaults to the run entry page."},
                        "selector": {"type": "string", "description": "Optional visible element selector."},
                        "full_page": {"type": "boolean", "description": "Capture the full page."},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "finish_report",
                "description": "Check the report JSON, render it to HWPX (+ Markdown + HTML + "
                "JSON) and end. A refusal says what to fix. Secrets are masked before rendering.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "model": {
                            "type": "object",
                            "description": "The report JSON (REPORT_SPEC) with exactly one "
                            "finding.",
                        },
                        "filename": {"type": "string", "description": "Proposed .hwpx file name."},
                    },
                    "required": ["model"],
                },
            },
        },
    ]
