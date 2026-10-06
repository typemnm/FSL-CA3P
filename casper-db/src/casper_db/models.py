from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]
HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
InputLocation = Literal["query", "body", "path", "header", "cookie", "fragment", "unknown"]
ReportSource = Literal["synthetic", "manual", "imported", "unknown"]


def utc_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("timestamp must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(UTC).isoformat(timespec="microseconds")


class Location(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_assignment=True)

    target_id: Identifier
    endpoint: str = Field(min_length=1, max_length=2000)
    method: HttpMethod

    @field_validator("endpoint")
    @classmethod
    def path_only(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or value.startswith("//")
            or any(c in value for c in "?#\\")
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise ValueError("endpoint must be a path such as /search, without query or fragment")
        return value

    @field_validator("method", mode="before")
    @classmethod
    def uppercase_method(cls, value):
        return value.upper() if isinstance(value, str) else value


class Case(Location):
    case_id: Identifier
    title: Text
    vulnerability_type: Text
    reported_on: str | None = None
    vulnerability_url: str | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    description: Text | None = None
    remediation: list[Text] = Field(default_factory=list, max_length=30)
    prior_evidence: Text | None = None
    parameter: Text
    parameter_location: InputLocation = "unknown"
    preconditions: list[Text] = Field(min_length=1, max_length=30)
    procedure: list[Text] = Field(min_length=1, max_length=30)
    # Payload bytes expressed as text must not be stripped, escaped, or executed.
    payload: str | None = Field(default=None, max_length=20000)
    success_condition: Text
    source_report: Text
    status: Literal["draft", "ready"] = "draft"
    patch_status: Literal["unknown", "unpatched", "patched"] = "unknown"
    source: ReportSource = "unknown"

    @field_validator("reported_on")
    @classmethod
    def valid_report_date(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                if date.fromisoformat(value).isoformat() != value:
                    raise ValueError("reported_on must use YYYY-MM-DD")
            except ValueError as exc:
                raise ValueError("reported_on must be a real date in YYYY-MM-DD") from exc
        return value

    @field_validator("vulnerability_url")
    @classmethod
    def full_http_url(cls, value: str | None) -> str | None:
        if value is None:
            return value
        parts = urlsplit(value)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or any(c.isspace() or ord(c) < 32 for c in value)
        ):
            raise ValueError("vulnerability_url must be a full HTTP(S) URL without credentials")
        return value

    @model_validator(mode="after")
    def check_historical_report(self):
        if (
            self.vulnerability_url
            and (urlsplit(self.vulnerability_url).path or "/") != self.endpoint
        ):
            raise ValueError("vulnerability_url path must match endpoint")
        if self.status == "ready":
            if self.payload is None or not self.payload.strip():
                raise ValueError("ready cases require a non-empty payload")
            if not all((self.reported_on, self.vulnerability_url, self.severity, self.description)):
                raise ValueError("ready cases require report date, URL, severity and description")
            if not self.remediation:
                raise ValueError("ready cases require a remediation from the prior report")
        return self


class CaseRecord(Case):
    revision: int = Field(ge=1)
    created_at: str
    updated_at: str


class CaseQuery(Location):
    """Exact lookup by observed location; this does not infer vulnerability."""

    parameter: Text | None = None
    parameter_location: InputLocation | None = None

    @model_validator(mode="after")
    def location_requires_parameter(self):
        if self.parameter_location is not None and self.parameter is None:
            raise ValueError("parameter_location requires parameter")
        return self


class LinkReview(BaseModel):
    """A local reviewer explicitly associates a changed location with an old report."""

    model_config = ConfigDict(extra="forbid", strict=True)
    reviewer: Text
    reason: Text
    reviewed_at: str

    @field_validator("reviewed_at")
    @classmethod
    def valid_reviewed_at(cls, value: str) -> str:
        return utc_timestamp(value)


class EvidenceMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    reference: Text
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)


class LegacyReview(BaseModel):
    """Preserves an older approval assertion whose files were never verified."""

    model_config = ConfigDict(extra="forbid", strict=True)
    review_status: Literal["reviewed"]
    reviewer: Text


class Check(Location):
    """One later observation of an earlier case, never a rewrite of its report."""

    check_id: Identifier
    case_id: Identifier
    run_id: Identifier
    case_revision: int | None = Field(default=None, ge=1)
    observed_at: str
    parameter: Text
    parameter_location: InputLocation = "unknown"
    result: Literal["confirmed", "not_reproduced", "inconclusive"]
    observation: Text
    evidence_refs: list[Text] = Field(default_factory=list, max_length=30)
    source: Literal["synthetic", "tool", "manual"]
    review_status: Literal["draft"] = "draft"
    reviewer: None = None
    link_review: LinkReview | None = None

    @field_validator("observed_at")
    @classmethod
    def valid_observed_at(cls, value: str) -> str:
        return utc_timestamp(value)

    @model_validator(mode="after")
    def reviewed_needs_evidence(self):
        if self.review_status == "reviewed":
            if self.source == "synthetic":
                raise ValueError("synthetic checks cannot be reviewed as real results")
            if not self.reviewer or not self.evidence_refs:
                raise ValueError("reviewed checks require reviewer and evidence references")
        return self


class CheckRecord(Check):
    review_status: Literal["draft", "reviewed"] = "draft"
    reviewer: Text | None = None
    case_revision: int = Field(ge=1)
    created_at: str
    reviewed_at: str | None = None
    review_note: Text | None = None
    evidence_metadata: list[EvidenceMetadata] = Field(default_factory=list)
    legacy_review: LegacyReview | None = None

    @field_validator("reviewed_at")
    @classmethod
    def valid_review_time(cls, value: str | None) -> str | None:
        return utc_timestamp(value) if value is not None else None

    @model_validator(mode="after")
    def verified_review_has_metadata(self):
        if self.review_status == "reviewed":
            if not self.reviewed_at or not self.review_note or not self.evidence_metadata:
                raise ValueError("reviewed records require a note and verified evidence metadata")
            if [item.reference for item in self.evidence_metadata] != self.evidence_refs:
                raise ValueError("evidence metadata must match the recorded references")
        return self
