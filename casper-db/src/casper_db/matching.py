"""Explainable candidate selection from parser locations and prior ready reports.

Location similarity is a triage signal. It never asserts a current vulnerability.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, model_serializer, model_validator

from .case_policy import same_reviewed_route
from .models import Identifier, InputLocation, Location, ReportSource, Text
from .repository import CaseStore

FieldName = Literal[
    "target_id", "endpoint", "method", "parameter", "parameter_location", "route_template"
]
Decision = Literal["retest_candidate", "manual_review", "no_match"]


class ParserObservation(Location):
    """Minimum agreed output from the endpoint parser for one input point."""

    parameter: Text | None = None
    parameter_location: InputLocation = "unknown"
    parameter_not_applicable: bool = False

    @model_validator(mode="after")
    def require_explicit_input_scope(self):
        if self.parameter_not_applicable:
            if self.parameter is not None or self.parameter_location != "unknown":
                raise ValueError("a non-applicable parameter must be null with unknown location")
        elif self.parameter is None:
            raise ValueError("parameter is required unless explicitly not applicable")
        return self

    @model_serializer(mode="wrap")
    def preserve_input_contract(self, handler):
        data = handler(self)
        if not self.parameter_not_applicable:
            data.pop("parameter_not_applicable", None)
        return data


class CandidateMatch(BaseModel):
    case_id: Identifier
    case_revision: int
    report_source: ReportSource
    vulnerability_type: Text
    decision: Literal["retest_candidate", "manual_review"]
    matched_fields: list[FieldName]
    changed_fields: list[FieldName]
    reason: str
    next_step: str


class ObservationAssessment(BaseModel):
    observation: ParserObservation
    decision: Decision
    matches: list[CandidateMatch]
    explanation: str


def assess_observation(
    store: CaseStore, observation: ParserObservation | dict
) -> ObservationAssessment:
    observed = ParserObservation.model_validate(observation)
    matches: list[CandidateMatch] = []
    # list_for_target excludes drafts; a report must be reviewed before normal triage.
    for case in store.list_for_target(observed.target_id):
        exact_endpoint = case.endpoint == observed.endpoint
        reviewed_route = bool(
            case.route_template
            and case.parameter_location == observed.parameter_location == "path"
            and case.parameter == observed.parameter
            and same_reviewed_route(
                case.route_template, case.endpoint, observed.endpoint, case.parameter
            )
        )
        if not exact_endpoint and not reviewed_route:
            continue
        method_same = case.method == observed.method
        parameter_same = case.parameter == observed.parameter
        if not (method_same or parameter_same):
            continue
        same: list[FieldName] = ["target_id"]
        changed: list[FieldName] = []
        if exact_endpoint:
            same.append("endpoint")
        else:
            same.append("route_template")
            changed.append("endpoint")
        for field, is_same in (("method", method_same), ("parameter", parameter_same)):
            (same if is_same else changed).append(field)
        location_same = (
            observed.parameter_location != "unknown"
            and case.parameter_location != "unknown"
            and observed.parameter_location == case.parameter_location
        ) or (
            observed.parameter_not_applicable
            and "parameter" in case.not_applicable_fields
            and case.parameter is None
        )
        (same if location_same else changed).append("parameter_location")
        material_changes = [field for field in changed if field != "endpoint"]
        if not material_changes:
            matches.append(
                CandidateMatch(
                    case_id=case.case_id,
                    case_revision=case.revision,
                    report_source=case.source,
                    vulnerability_type=case.vulnerability_type,
                    decision="retest_candidate",
                    matched_fields=same,
                    changed_fields=changed,
                    reason=(
                        "사이트·경로·요청 방식·입력 항목·입력 위치가 전월 보고서와 모두 일치"
                        if exact_endpoint
                        else f"검토된 경로 템플릿 {case.route_template}과 입력 위치가 일치. "
                        "레코드 식별자가 달라 실제 경로는 별도로 보존"
                    ),
                    next_step="허용된 범위에서 전월 절차를 검토하고 현재 결과를 별도로 검증",
                )
            )
        else:
            matches.append(
                CandidateMatch(
                    case_id=case.case_id,
                    case_revision=case.revision,
                    report_source=case.source,
                    vulnerability_type=case.vulnerability_type,
                    decision="manual_review",
                    matched_fields=same,
                    changed_fields=changed,
                    reason=(
                        f"경로는 같지만 {', '.join(changed)} 값이 다르거나 확인되지 않아 "
                        "같은 입력 지점인지 불확실"
                    ),
                    next_step="파서 출력과 실제 입력 지점을 사람이 확인한 뒤 재점검 여부 결정",
                )
            )
    # Keep the prior-report order within each decision level.
    matches.sort(
        key=lambda item: (
            0 if item.decision == "retest_candidate" else 1,
            "endpoint" in item.changed_fields,
        )
    )
    if not matches:
        return ObservationAssessment(
            observation=observed,
            decision="no_match",
            matches=[],
            explanation=(
                "재점검 후보로 올릴 만큼 위치가 일치하지 않음. 새 취약점이 없다는 뜻은 아님"
            ),
        )
    if matches[0].decision == "retest_candidate":
        decision: Decision = "retest_candidate"
        explanation = (
            "전월 위치 또는 검토된 경로와 일치하므로 재점검 후보. 현재 취약하다는 판정은 아님"
        )
    else:
        decision = "manual_review"
        explanation = "일부 위치만 일치하므로 자동 재점검 대상으로 삼지 않고 수동 확인"
    return ObservationAssessment(
        observation=observed,
        decision=decision,
        matches=matches,
        explanation=explanation,
    )
