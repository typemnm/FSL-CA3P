"""One-shot local ingestion jobs. Preparing artifacts never opens a database."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import Field, model_validator

from .external_vulnerabilities import (
    ExternalBundle,
    collect_external,
    normalize_external,
    store_external,
)
from .hwp import parse_report
from .hwpx import MAX_FILE_BYTES
from .hwpx_review import render_hwpx_review
from .import_workflow import ReportReview, WorkflowModel, digest, prepare_import, review_template
from .local_ocr import VERSION as OCR_VERSION
from .local_ocr import ocr_cache_identity
from .narrative import VERSION as NARRATIVE_VERSION
from .report_drafts import ReportDraft
from .repository import CaseStore


class ReportInput(WorkflowModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
    file: str | None = None
    hwpx: str | None = None
    draft: str | None = None
    source_file: str | None = None
    source_hwpx: str | None = None
    image_transcripts: str | None = None
    review: str | None = None
    target_id: str | None = None
    source_kind: Literal["imported", "synthetic"] | None = None
    local_ocr: bool = False
    ocr_language: str = "ko"

    @model_validator(mode="after")
    def input_kind(self):
        if sum(bool(value) for value in (self.file, self.hwpx, self.draft)) != 1:
            raise ValueError("report requires exactly one of file, hwpx or draft")
        if self.source_file and self.source_hwpx:
            raise ValueError("choose source_file or source_hwpx, not both")
        if (self.file or self.hwpx) and (self.source_file or self.source_hwpx):
            raise ValueError("source_file/source_hwpx is only used with an existing draft")
        if self.draft and self.image_transcripts:
            raise ValueError("image_transcripts must be attached during HWPX extraction")
        if self.draft and self.local_ocr:
            raise ValueError(
                "local_ocr requires the source file; re-extract instead of editing a draft"
            )
        return self


class ExternalInput(WorkflowModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
    source: Literal["nvd", "github"]
    file: str | None = None
    collect: bool = False
    params: dict[str, str | int] = Field(default_factory=dict)
    max_pages: int = Field(default=1, ge=1, le=20)

    @model_validator(mode="after")
    def input_kind(self):
        if bool(self.file) == self.collect:
            raise ValueError("external input requires a file or explicit collect=true")
        if self.file and self.params:
            raise ValueError("params are only used for collection")
        return self


class AutomationConfig(WorkflowModel):
    schema_version: Literal["db-automation-1"] = "db-automation-1"
    reports: list[ReportInput] = Field(default_factory=list, max_length=100)
    external: list[ExternalInput] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def unique_inputs(self):
        ids = [item.id.casefold() for item in [*self.reports, *self.external]]
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("job needs at least one input and unique IDs (case insensitive)")
        return self


def read_json(path: Path):
    if path.stat().st_size > 32_000_000:
        raise ValueError("automation JSON exceeds 32 MB")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    # Each output has a new run ID, and cache entries are immutable.
    with path.open("x", encoding="utf-8") as stream:
        stream.write(text)


def load_external(path: Path, source: str) -> list[ExternalBundle]:
    raw = read_json(path)
    if isinstance(raw, dict) and raw.get("schema_version") == "external-collection-1":
        bundles = [ExternalBundle.model_validate(value) for value in raw["bundles"]]
    elif isinstance(raw, dict) and raw.get("schema_version") == "external-vuln-1":
        bundles = [ExternalBundle.model_validate(raw)]
    else:
        bundles = [normalize_external(source, raw)]
    if not bundles:
        raise ValueError("external collection has no pages")
    for bundle in bundles:
        if bundle.source != source or digest(bundle.raw) != bundle.raw_sha256:
            raise ValueError("external source or raw SHA-256 mismatch")
        rebuilt = normalize_external(source, bundle.raw, source_url=bundle.source_url)
        if rebuilt.records != bundle.records or rebuilt.rejected_items != bundle.rejected_items:
            raise ValueError("external normalization does not match source")
    return bundles


def _extract(item, base, output):
    if item.draft:
        report = ReportDraft.model_validate(read_json(base / item.draft))
        original = item.source_file or item.source_hwpx
        source = (base / original).resolve(strict=True) if original else None
        if source and hashlib.sha256(source.read_bytes()).hexdigest() != report.source["sha256"]:
            raise ValueError("original report does not match the draft SHA-256")
        if item.source_kind and any(
            finding.candidate.source != item.source_kind for finding in report.findings
        ):
            raise ValueError("draft provenance does not match source_kind; re-extract first")
        return report, source, False
    source = (base / (item.file or item.hwpx)).resolve(strict=True)
    if item.hwpx and source.suffix.lower() != ".hwpx":
        raise ValueError("hwpx accepts HWPX only; use file for binary HWP")
    if source.suffix.lower() not in {".hwp", ".hwpx"}:
        raise ValueError("file must be HWP or HWPX")
    if source.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("source report exceeds the file size limit")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    transcripts = read_json(base / item.image_transcripts) if item.image_transcripts else None
    fingerprint = digest(
        {
            "source": str(source),
            "sha256": source_hash,
            "target": item.target_id,
            "transcripts": transcripts,
            "extractor": "unified-report-reader-3",
            "narrative_extractor": NARRATIVE_VERSION,
            "source_kind": item.source_kind or "imported",
            "local_ocr": {
                "enabled": item.local_ocr,
                "language": item.ocr_language,
                "version": OCR_VERSION,
                "runtime": ocr_cache_identity(item.ocr_language) if item.local_ocr else None,
            },
        }
    )
    cache = output / "cache" / f"{fingerprint}.json"
    if cache.exists():
        cached = read_json(cache)
        report = ReportDraft.model_validate(cached["report"])
        if cached["draft_sha256"] != digest(report) or report.source["sha256"] != source_hash:
            raise ValueError("cached draft integrity mismatch; inspect the cache before retrying")
        return report, source, True
    report = parse_report(
        source,
        target_id=item.target_id,
        image_transcripts=transcripts,
        source_kind=item.source_kind or "imported",
        local_ocr=item.local_ocr,
        ocr_language=item.ocr_language,
    )
    if report.source["sha256"] != source_hash:
        raise ValueError("report changed during extraction; retry with a stable source file")
    _write(cache, {"draft_sha256": digest(report), "report": report.model_dump(mode="json")})
    return report, source, False


def run_automation(
    config_path: Path,
    output_dir: Path,
    *,
    apply: bool = False,
    cert_db: Path | None = None,
    external_db: Path | None = None,
    knowledge_db: Path | None = None,
) -> dict:
    """Prepare all inputs before explicit writes; record each store's commit separately."""
    config_path = config_path.resolve(strict=True)
    config = AutomationConfig.model_validate(read_json(config_path))
    base, output = config_path.parent, output_dir.resolve()
    inputs = [config_path]
    for item in config.reports:
        inputs.extend(
            base / path
            for path in (
                item.file,
                item.hwpx,
                item.draft,
                item.source_file,
                item.source_hwpx,
                item.image_transcripts,
                item.review,
            )
            if path
        )
    inputs.extend(base / item.file for item in config.external if item.file)
    if any(path.resolve().is_relative_to(output) for path in inputs):
        raise ValueError("keep job inputs outside the automation output directory")
    if knowledge_db is not None:
        if cert_db is not None or external_db is not None:
            raise ValueError("choose --knowledge-db or explicit --cert-db / --external-db")
        cert_db = external_db = knowledge_db
    databases = [path.resolve() for path in (cert_db, external_db) if path is not None]
    if any(
        path in {item.resolve() for item in inputs} or path.is_relative_to(output)
        for path in databases
    ):
        raise ValueError("database paths must not overlap inputs or automation outputs")
    if apply and (
        (config.reports and cert_db is None) or (config.external and external_db is None)
    ):
        raise ValueError("--apply requires explicit --cert-db / --external-db for active inputs")

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    run_dir = output / "runs" / run_id
    result = {
        "schema_version": "db-automation-run-1",
        "run_id": run_id,
        "started_at": datetime.now(UTC).isoformat(),
        "mode": "apply" if apply else "dry_run",
        "config_sha256": digest(config),
        "reports": [],
        "external": [],
        "errors": [],
        "database_written": False,
        "commits": {},
        "execution_enabled": False,
        "run_file": str(run_dir / "run.json"),
    }
    packages, collected = [], []
    for item in config.reports:
        try:
            report, source, reused = _extract(item, base, output)
            review = (
                ReportReview.model_validate(read_json(base / item.review))
                if item.review
                else review_template(report)
            )
            package = prepare_import(report, review, target_id=item.target_id)
            folder = run_dir / item.id
            _write(folder / "report.draft.json", report.model_dump(mode="json"))
            _write(folder / "report.review.json", review.model_dump(mode="json"))
            _write(folder / "cases.import.json", package.model_dump(mode="json"))
            html = render_hwpx_review(
                report,
                source_hwpx=source if source and source.suffix.lower() == ".hwpx" else None,
                review=review,
            )
            with (folder / "index.html").open("x", encoding="utf-8") as stream:
                stream.write(html)
            entry = {
                "id": item.id,
                "findings": len(report.findings),
                "cache_reused": reused,
                "draft": str(folder / "report.draft.json"),
                "review": str(folder / "report.review.json"),
                "review_page": str(folder / "index.html"),
                "ready_cases": len(package.cases),
                "blocked": package.blocked,
                "excluded": package.excluded,
                "status": (
                    "ready"
                    if package.ready_for_import
                    else "excluded"
                    if package.excluded and not package.blocked
                    else "needs_review"
                ),
            }
            if not report.findings:
                entry["status"] = "needs_review"
                entry["note"] = "No vulnerability table recognized; inspect preserved document."
            result["reports"].append(entry)
            if package.ready_for_import:
                package.verify()
                packages.append(package)
        except (ValueError, OSError, KeyError) as exc:
            result["errors"].append({"id": item.id, "stage": "report", "message": str(exc)})
    for item in config.external:
        try:
            bundles = (
                collect_external(item.source, params=item.params, max_pages=item.max_pages)
                if item.collect
                else load_external(base / item.file, item.source)
            )
            destination = run_dir / item.id / "external.json"
            _write(
                destination,
                {
                    "schema_version": "external-collection-1",
                    "bundles": [bundle.model_dump(mode="json") for bundle in bundles],
                },
            )
            rejected = sum(len(bundle.rejected_items) for bundle in bundles)
            result["external"].append(
                {
                    "id": item.id,
                    "source": item.source,
                    "output": str(destination),
                    "pages": len(bundles),
                    "records": sum(len(b.records) for b in bundles),
                    "rejected": rejected,
                    "status": "needs_review" if rejected else "ready",
                    "pagination": [b.pagination for b in bundles],
                    "applicability": "not_assessed",
                }
            )
            collected.extend(bundles)
        except (ValueError, OSError, KeyError) as exc:
            result["errors"].append({"id": item.id, "stage": "external", "message": str(exc)})
    pending = any(
        item["status"] == "needs_review" for item in (*result["reports"], *result["external"])
    )
    cases = [case for package in packages for case in package.cases]
    if len({case.case_id for case in cases}) != len(cases):
        result["errors"].append(
            {"stage": "prepare", "message": "duplicate Case IDs across report inputs"}
        )
    result["status"] = "failed" if result["errors"] else "needs_review" if pending else "ready"
    if apply and result["status"] == "ready":
        try:
            shared = cert_db is not None and external_db is not None and (
                cert_db.resolve() == external_db.resolve()
            )
            if shared and (cases or collected):
                from .knowledge import store_knowledge

                result["commits"] = store_knowledge(cert_db, cases, collected)
                result["database_written"] = True
            else:
                if cases:
                    stored = CaseStore(cert_db).add_many(cases)
                    result["commits"]["cert"] = {key: len(rows) for key, rows in stored.items()}
                    result["database_written"] = True
                if collected:
                    result["commits"]["external"] = store_external(external_db, collected)
                    result["database_written"] = True
            result["status"] = "applied"
        except (ValueError, OSError, sqlite3.Error) as exc:
            result["errors"].append({"stage": "apply", "message": str(exc)})
            result["status"] = "partial_failure" if result["commits"] else "failed"
    result["finished_at"] = datetime.now(UTC).isoformat()
    _write(run_dir / "run.json", result)
    return result
