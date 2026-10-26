"""Read-only handoff of reviewed and pending source material to other modules."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from pydantic import TypeAdapter

from .external_vulnerabilities import lookup_external
from .models import Identifier
from .report_intake import ReportIntake

SCHEMA_VERSION = "casper-reference-1"
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")


def build_reference_context(
    target_id: str,
    *,
    workspace: Path | None = None,
    external_database: Path | None = None,
    cve_ids: list[str] | None = None,
) -> dict:
    """Never create/migrate a DB, publish a case, or assess exploit success.

    Source snapshots stay in the owned intake DB. This projection omits raw file
    bytes and local source paths, but keeps candidates and the current review's
    resolutions separate so a consumer cannot mistake an extraction for approval.
    """
    target_id = TypeAdapter(Identifier).validate_python(target_id)
    if cve_ids is not None and (
        not isinstance(cve_ids, list) or any(not isinstance(value, str) for value in cve_ids)
    ):
        raise ValueError("CVE identifiers must be an array of strings")
    requested = list(dict.fromkeys(cve_ids or []))
    if len(requested) > 100 or any(not CVE.fullmatch(value) for value in requested):
        raise ValueError("at most 100 exact CVE identifiers are allowed")
    result = {
        "schema_version": SCHEMA_VERSION,
        "target_id": target_id,
        "automatic_execution_allowed": False,
        "intake": {"status": "not_configured", "counts": None},
        "findings": [],
        "external": {"status": "not_configured", "records": []},
    }
    if workspace is not None:
        try:
            intake = ReportIntake(Path(workspace))
            reports = intake.show()["reports"]
            counts = {}
            for report in reports:
                if report["target_id"] != target_id:
                    continue
                detailed = intake.show(report["draft_sha256"])["reports"][0]
                review = detailed["review"]
                decisions = {item["draft_id"]: item for item in review["items"]}
                for entry in detailed["findings"]:
                    finding = entry["finding"]
                    candidate = dict(finding["candidate"])
                    candidate.pop("source_report", None)
                    state = entry["state"]
                    counts[state] = counts.get(state, 0) + 1
                    decision = decisions.get(finding["draft_id"], {})
                    result["findings"].append(
                        {
                            "draft_id": finding["draft_id"],
                            "draft_sha256": report["draft_sha256"],
                            "source_sha256": report["source_sha256"],
                            "source_ref": finding["source_ref"],
                            "case_id": entry["case_id"],
                            "registration_state": state,
                            "reproduction_state": "not_assessed_by_importer",
                            "candidate": candidate,
                            "missing_fields": finding["missing_fields"],
                            "unresolved_fields": finding["unresolved_fields"],
                            "remaining_fields": entry["remaining_fields"],
                            "field_evidence": finding["field_evidence"],
                            "payload_variants": finding["payload_variants"],
                            "review_issues": finding["review_issues"],
                            "image_refs": finding["image_refs"],
                            "review": {
                                "decision": decision.get("decision", "pending"),
                                "reason": decision.get("reason", ""),
                                "resolutions": decision.get("resolutions", {}),
                                "reviewer": review["reviewer"],
                                "reviewed_at": review["reviewed_at"],
                            },
                        }
                    )
                    text = " ".join(
                        str(candidate.get(field) or "")
                        for field in ("title", "description", "vulnerability_type")
                    )
                    requested.extend(value for value in CVE.findall(text) if value not in requested)
            result["intake"] = {"status": "ok", "counts": counts}
        except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
            result["findings"] = []
            result["intake"] = {
                "status": "unavailable",
                "reason": type(exc).__name__,
                "counts": None,
            }
    if len(requested) > 100:
        raise ValueError("reference context exceeds 100 CVEs; narrow the requested source")
    result["external"]["requested_cve_ids"] = requested
    if external_database is not None:
        try:
            # Verify even an empty selection, without creating a SQLite file.
            path = Path(external_database).resolve(strict=True)
            with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
                marker = connection.execute(
                    "SELECT value FROM external_metadata WHERE key='schema'"
                ).fetchone()
                if marker != ("external-vuln-1",):
                    raise ValueError("unsupported external database schema")
            records, absent = [], []
            for cve_id in requested:
                found = lookup_external(path, cve_id)
                if not found:
                    absent.append(cve_id)
                for record in found:
                    data = record.model_dump(mode="json")
                    data.pop("raw", None)
                    records.append(data)
            from .applicability import lookup_assessments

            assessments = [
                item for cve in requested for item in lookup_assessments(path, target_id, cve)
            ]
            result["external"].update(status="ok", records=records, not_found_cve_ids=absent)
            result["external"]["assessments"] = assessments
        except (OSError, ValueError, sqlite3.Error) as exc:
            result["external"].update(status="unavailable", reason=type(exc).__name__)
    return result
