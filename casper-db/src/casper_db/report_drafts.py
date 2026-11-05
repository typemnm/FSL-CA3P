"""Reviewable extraction records; these are deliberately not database Case inputs."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_serializer

from .models import HttpMethod, InputLocation


class DraftModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CaseDraft(DraftModel):
    # Missing required Case fields are permitted at this extraction stage.
    case_id: str | None = None
    target_id: str | None = None
    title: str | None = None
    vulnerability_type: str | None = None
    reported_on: str | None = None
    vulnerability_url: str | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    description: str | None = None
    remediation: list[str] = Field(default_factory=list)
    prior_evidence: str | None = None
    endpoint: str | None = None
    method: HttpMethod | None = None
    parameter: str | None = None
    parameter_location: InputLocation = "unknown"
    preconditions: list[str] = Field(default_factory=list)
    procedure: list[str] = Field(default_factory=list)
    payload: str | None = None
    success_condition: str | None = None
    source_report: str
    status: Literal["draft"] = "draft"
    patch_status: Literal["unknown", "unpatched", "patched"] = "unknown"
    source: Literal["imported", "synthetic"] = "imported"
    not_applicable_fields: list[Literal["parameter", "payload"]] = Field(default_factory=list)
    applicability_reason: str | None = None
    route_template: str | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_shape(self, handler):
        data = handler(self)
        for name, default in (
            ("not_applicable_fields", []),
            ("applicability_reason", None),
            ("route_template", None),
        ):
            if data.get(name) == default:
                data.pop(name, None)
        return data


class ReviewIssue(DraftModel):
    code: str
    field: str | None = None
    message: str
    source_refs: list[str] = Field(default_factory=list)


class FieldEvidence(DraftModel):
    value: Any
    source_ref: str
    method: Literal["direct", "normalized", "derived", "review_candidate"] = "direct"


class PayloadVariant(DraftModel):
    value: str
    representation: Literal[
        "literal", "url_encoded", "url_query", "image_transcription", "image_ocr"
    ]
    source_ref: str
    source_text: str
    parameter: str | None = None
    percent_decoded_value: str | None = None


class ImageTranscript(DraftModel):
    image_id: str
    text: str
    transcribed_by: str
    method: Literal["visual_transcription"] = "visual_transcription"
    review_status: Literal["unreviewed"] = "unreviewed"


class ImageTranscriptBundle(DraftModel):
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    items: list[ImageTranscript]


class FindingDraft(DraftModel):
    draft_id: str
    source_ref: str
    review_status: Literal["needs_review"] = "needs_review"
    candidate: CaseDraft
    field_evidence: dict[str, list[FieldEvidence]] = Field(default_factory=dict)
    payload_variants: list[PayloadVariant] = Field(default_factory=list)
    image_refs: list[str] = Field(default_factory=list)
    unmapped_fields: list[dict[str, Any]] = Field(default_factory=list)
    missing_fields: list[str] = Field(default_factory=list)
    unresolved_fields: list[str] = Field(default_factory=list)
    review_issues: list[ReviewIssue] = Field(default_factory=list)
    case_validation_errors: list[dict[str, str]] = Field(default_factory=list)


class ReportDraft(DraftModel):
    schema_version: Literal["hwpx-draft-1", "report-draft-1"] = "hwpx-draft-1"
    extractor_version: Literal[
        "hwpx-local-1",
        "hwpx-local-2",
        "hwpx-local-3",
        "hwpx-local-4",
        "hwpx-local-5",
        "hwpx-local-6",
        "hwp5-local-1",
        "hwp5-local-2",
        "hwp5-local-3",
        "hwp5-local-4",
        "hwp5-local-5",
    ] = "hwpx-local-6"
    source: dict[str, Any]
    document: dict[str, Any]
    findings: list[FindingDraft]
    review_issues: list[ReviewIssue] = Field(default_factory=list)
    image_transcripts: list[ImageTranscript] = Field(default_factory=list)
