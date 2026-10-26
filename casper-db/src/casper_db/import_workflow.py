"""Hash-bound human review and deterministic Case import packages. No implicit DB access."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .field_values import has_supplied_value
from .models import Case, utc_timestamp
from .report_drafts import ReportDraft


class WorkflowModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def digest(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class Resolution(WorkflowModel):
    value: Any
    reason: str = Field(min_length=1)
    source_refs: list[str] = Field(min_length=1)


class FindingReview(WorkflowModel):
    draft_id: str
    decision: Literal["pending", "accept", "exclude"] = "pending"
    reason: str = ""
    resolutions: dict[str, Resolution] = Field(default_factory=dict)
    payload_variant_index: int | None = Field(default=None, ge=0)
    acknowledged_issue_codes: list[str] = Field(default_factory=list)


class ReportReview(WorkflowModel):
    schema_version: Literal["case-review-1"] = "case-review-1"
    report_sha256: str
    draft_sha256: str
    reviewer: str = ""
    reviewed_at: str | None = None
    items: list[FindingReview]


class ImportPackage(WorkflowModel):
    schema_version: Literal["case-import-1"] = "case-import-1"
    source_sha256: str
    draft_sha256: str
    review_sha256: str
    reviewer: str
    reviewed_at: str | None
    assigned_target_id: str | None = None
    ready_for_import: bool
    cases: list[Case]
    blocked: list[dict[str, Any]]
    excluded: list[dict[str, str]]
    review: ReportReview
    package_sha256: str = ""

    def seal(self) -> ImportPackage:
        self.package_sha256 = digest(self.model_dump(exclude={"package_sha256"}, mode="json"))
        return self

    def verify(self) -> None:
        expected = digest(self.model_dump(exclude={"package_sha256"}, mode="json"))
        if self.package_sha256 != expected:
            raise ValueError("import package SHA-256 mismatch")
        if self.review_sha256 != digest(self.review):
            raise ValueError("review SHA-256 mismatch")
        if (
            self.source_sha256 != self.review.report_sha256
            or self.draft_sha256 != self.review.draft_sha256
        ):
            raise ValueError("review provenance does not match package")
        if not self.ready_for_import or self.blocked or not self.cases:
            raise ValueError("review package still has blocked or pending findings")
        if not self.reviewer.strip() or self.reviewed_at is None:
            raise ValueError("import requires a named local reviewer and timestamp")
        utc_timestamp(self.reviewed_at)
        if any(case.status != "ready" for case in self.cases):
            raise ValueError("only ready cases can be imported")
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("duplicate case IDs in import package")


def review_template(report: ReportDraft) -> ReportReview:
    return ReportReview(
        report_sha256=report.source["sha256"],
        draft_sha256=digest(report),
        items=[FindingReview(draft_id=f.draft_id) for f in report.findings],
    )


def assigned_case_id(report: ReportDraft, source_ref: str) -> str:
    return "CASE-" + digest({"report": report.source["sha256"], "finding": source_ref})[:24]


def prepare_import(
    report: ReportDraft,
    review: ReportReview | None = None,
    *,
    target_id: str | None = None,
) -> ImportPackage:
    review = review or review_template(report)
    if review.report_sha256 != report.source["sha256"] or review.draft_sha256 != digest(report):
        raise ValueError("review belongs to a different report or extraction revision")
    ids = [item.draft_id for item in review.items]
    known = {f.draft_id for f in report.findings}
    if len(ids) != len(set(ids)) or set(ids) - known:
        raise ValueError("review contains duplicate or unknown finding IDs")
    reviews = {item.draft_id: item for item in review.items}
    refs = {p["source_ref"] for s in report.document["sections"] for p in s["paragraphs"]} | {
        c["source_ref"] for t in report.document["tables"] for c in t["cells"]
    }
    refs |= {t["source_ref"] for t in report.document["tables"]}
    refs |= {f"image-transcript:{t.image_id}" for t in report.image_transcripts}
    refs |= {f"image:{i['image_id']}" for i in report.document["images"]}
    ocr_refs = {
        item["image_id"]: {
            f"image-ocr:{item['image_id']}#line{index}"
            for index, _ in enumerate((item.get("recognition") or {}).get("lines", []))
        }
        for item in report.document.get("local_ocr", {}).get("bundle", {}).get("images", [])
    }
    refs |= {ref for entries in ocr_refs.values() for ref in entries}
    tables_by_ref = {table["source_ref"]: table for table in report.document["tables"]}
    cases, blocked, excluded = [], [], []
    for finding in report.findings:
        # References from a different finding cannot silently support this one.
        finding_refs = {finding.source_ref}
        finding_refs |= {f"image:{image_id}" for image_id in finding.image_refs}
        finding_refs |= {f"image-transcript:{image_id}" for image_id in finding.image_refs}
        finding_refs |= {
            ref for image_id in finding.image_refs for ref in ocr_refs.get(image_id, set())
        }
        finding_refs |= {
            evidence.source_ref
            for entries in finding.field_evidence.values()
            for evidence in entries
        }
        table = tables_by_ref.get(finding.source_ref)
        if table:
            for cell in table["cells"]:
                finding_refs.add(cell["source_ref"])
                finding_refs.update(p["source_ref"] for p in cell["paragraphs"])
            if table.get("preceding_paragraph"):
                finding_refs.add(table["preceding_paragraph"]["source_ref"])
        finding_refs &= refs
        item = reviews.get(finding.draft_id, FindingReview(draft_id=finding.draft_id))
        problems = []
        remaining_fields = []
        if item.decision == "exclude" and item.reason.strip():
            excluded.append({"draft_id": item.draft_id, "reason": item.reason})
            continue
        if item.decision != "accept":
            problems.append("사람의 검토 결정이 아직 없습니다.")
        if not review.reviewer.strip() or not item.reason.strip():
            problems.append("검토자와 결정 근거가 필요합니다.")
        try:
            if review.reviewed_at is None:
                raise ValueError("missing")
            reviewed_at = utc_timestamp(review.reviewed_at)
            if datetime.fromisoformat(reviewed_at) > datetime.now(UTC):
                raise ValueError("future")
        except ValueError:
            problems.append(
                "실제 검토 시각이 필요합니다. 시간대를 포함하고 미래 시각을 쓰지 않습니다."
            )
        raw = finding.candidate.model_dump()
        if target_id is not None:
            raw["target_id"] = target_id
        raw["case_id"] = assigned_case_id(report, finding.source_ref)
        for name, resolution in item.resolutions.items():
            if name not in Case.model_fields or name in {
                "case_id",
                "status",
                "source",
                "source_report",
            }:
                raise ValueError(f"field is not review-editable: {name}")
            invalid_refs = [
                ref
                for ref in resolution.source_refs
                if ref not in finding_refs and not (ref.startswith("manual:") and ref[7:].strip())
            ]
            if not resolution.reason.strip() or invalid_refs:
                raise ValueError(
                    f"{name}: resolution requires a source for this finding "
                    "or a named manual reference; "
                    f"invalid references: {', '.join(invalid_refs) or '(blank reason)'}"
                )
            raw[name] = resolution.value
        if item.payload_variant_index is not None:
            if "payload" in item.resolutions:
                raise ValueError("choose a payload variant or a payload resolution, not both")
            if item.payload_variant_index >= len(finding.payload_variants):
                raise ValueError("payload variant index is out of range")
            raw["payload"] = finding.payload_variants[item.payload_variant_index].value
        required_ack = {
            issue.code
            for issue in finding.review_issues
            if issue.code
            in {
                "endpoint_ambiguity",
                "combined_vulnerability_types",
                "typographic_quotes",
                "image_text_not_processed",
                "unreviewed_image_transcript",
                "unreviewed_local_ocr",
            }
        }
        if required_ack - set(item.acknowledged_issue_codes):
            problems.append(
                "검토 표시가 필요한 항목: "
                + ", ".join(sorted(required_ack - set(item.acknowledged_issue_codes)))
            )
        raw["status"] = "ready"
        ready_required = (
            "reported_on",
            "vulnerability_url",
            "severity",
            "description",
            "payload",
            "remediation",
        )
        required_values = (
            set(ready_required)
            | {name for name, field in Case.model_fields.items() if field.is_required()}
            | {"parameter"}
        )
        declared = raw.get("not_applicable_fields", [])
        if not isinstance(declared, list) or any(not isinstance(name, str) for name in declared):
            raise ValueError("not_applicable_fields must be an array of field names")
        required_values -= set(declared)
        for name in sorted(required_values):
            value = raw.get(name)
            if not has_supplied_value(value):
                remaining_fields.append(name)
                problems.append(
                    f"{name}: 등록 준비에 필요한 값이 비어 있거나 미확인 표시가 있습니다."
                )
        try:
            case = Case.model_validate(raw)
        except ValidationError as exc:
            remaining_fields = sorted(
                set(remaining_fields)
                | {
                    str(error["loc"][0]) if error["loc"] else "case"
                    for error in exc.errors(include_input=False)
                }
            )
            problems.extend(
                f"{'.'.join(map(str, e['loc'])) or 'case'}: {e['msg']}"
                for e in exc.errors(include_input=False)
            )
        else:
            if not problems:
                cases.append(case)
        if problems:
            blocked.append(
                {
                    "draft_id": finding.draft_id,
                    "source_ref": finding.source_ref,
                    "extraction_missing_fields": finding.missing_fields,
                    "extraction_unresolved_fields": finding.unresolved_fields,
                    "remaining_fields": remaining_fields,
                    "reasons": problems,
                }
            )
    return ImportPackage(
        source_sha256=report.source["sha256"],
        draft_sha256=digest(report),
        review_sha256=digest(review),
        reviewer=review.reviewer,
        reviewed_at=review.reviewed_at,
        ready_for_import=bool(cases) and not blocked,
        cases=cases,
        blocked=blocked,
        excluded=excluded,
        review=review,
        assigned_target_id=target_id,
    ).seal()
