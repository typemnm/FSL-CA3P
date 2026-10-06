"""Explainable candidate selection from parser locations and prior ready reports.

Location similarity is a triage signal. It never asserts a current vulnerability.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from .models import Identifier, InputLocation, Location, ReportSource, Text
from .repository import CaseStore

FieldName = Literal["target_id", "endpoint", "method", "parameter", "parameter_location"]
Decision = Literal["retest_candidate", "manual_review", "no_match"]


class ParserObservation(Location):
    """Minimum agreed output from the endpoint parser for one input point."""

    parameter: Text
    parameter_location: InputLocation = "unknown"


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
        if case.endpoint != observed.endpoint:
            continue
        method_same = case.method == observed.method
        parameter_same = case.parameter == observed.parameter
        if not (method_same or parameter_same):
            continue
        same: list[FieldName] = ["target_id", "endpoint"]
        changed: list[FieldName] = []
        for field, is_same in (("method", method_same), ("parameter", parameter_same)):
            (same if is_same else changed).append(field)
        location_same = (
            observed.parameter_location != "unknown"
            and case.parameter_location != "unknown"
            and observed.parameter_location == case.parameter_location
        )
        (same if location_same else changed).append("parameter_location")
        if not changed:
            matches.append(CandidateMatch(
                case_id=case.case_id,
                case_revision=case.revision,
                report_source=case.source,
                vulnerability_type=case.vulnerability_type,
                decision="retest_candidate",
                matched_fields=same,
                changed_fields=[],
                reason="사이트·경로·요청 방식·입력 항목·입력 위치가 전월 보고서와 모두 일치",
                next_step="허용된 범위에서 전월 절차를 검토하고 현재 결과를 별도로 검증",
            ))
        else:
            matches.append(CandidateMatch(
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
            ))
    # Keep the prior-report order within each decision level.
    matches.sort(key=lambda item: 0 if item.decision == "retest_candidate" else 1)
    if not matches:
        return ObservationAssessment(
            observation=observed,
            decision="no_match",
            matches=[],
            explanation=(
                "재점검 후보로 올릴 만큼 위치가 일치하지 않음. "
                "새 취약점이 없다는 뜻은 아님"
            ),
        )
    if matches[0].decision == "retest_candidate":
        decision: Decision = "retest_candidate"
        explanation = "전월 위치와 일치하므로 재점검 후보. 현재 취약하다는 판정은 아님"
    else:
        decision = "manual_review"
        explanation = "일부 위치만 일치하므로 자동 재점검 대상으로 삼지 않고 수동 확인"
    return ObservationAssessment(
        observation=observed, decision=decision, matches=matches,
        explanation=explanation,
    )
