"""Type-independent, evidence-bound import of results produced by a verifier."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from .evidence import inspect_evidence
from .import_workflow import WorkflowModel, digest
from .matching import ParserObservation
from .models import Check, Identifier, LinkReview, Text
from .repository import CaseStore


class RetestResult(WorkflowModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    case_id: Identifier
    case_revision: int = Field(ge=1)
    location: ParserObservation
    result: Literal["confirmed", "not_reproduced", "inconclusive"]
    verification_completed: bool
    observed_at: str
    observation: Text
    evidence_refs: list[Text] = Field(min_length=1, max_length=30)
    source: Literal["tool", "manual", "synthetic"] = "tool"
    link_review: LinkReview | None = None

    @model_validator(mode="after")
    def completed_before_conclusive_result(self):
        if not self.verification_completed and self.result != "inconclusive":
            raise ValueError("incomplete verification can only be inconclusive")
        return self


class RetestResults(WorkflowModel):
    schema_version: Literal["casper-check-results-1"]
    run_id: Identifier
    results: list[RetestResult] = Field(min_length=1, max_length=100)


def import_retest_results(store: CaseStore, value: dict | RetestResults, *, apply=False) -> dict:
    """Keep verifier assertions as draft checks; never turn an import into approval."""
    envelope = RetestResults.model_validate(value)
    checks, ids = [], set()
    for item in envelope.results:
        location = item.location.model_dump(mode="json")
        identity = {
            "run_id": envelope.run_id,
            "case_id": item.case_id,
            "case_revision": item.case_revision,
            "location": location,
        }
        check_id = "CHECK-" + digest(identity)[:48]
        if check_id in ids:
            raise ValueError("duplicate case/location result in one verification batch")
        ids.add(check_id)
        evidence = inspect_evidence(store.evidence_root, item.evidence_refs)
        checks.append(
            Check(
                check_id=check_id,
                case_id=item.case_id,
                case_revision=item.case_revision,
                run_id=envelope.run_id,
                **location,
                observed_at=item.observed_at,
                result=item.result,
                observation=item.observation,
                evidence_refs=item.evidence_refs,
                observed_evidence=evidence,
                source=item.source,
                link_review=item.link_review,
            )
        )
    prepared = store.prepare_checks(checks)
    records = store.add_checks(prepared, allow_unchanged=True) if apply else prepared
    return {
        "schema_version": "casper-check-import-1",
        "status": "synced" if apply else "ready",
        "run_id": envelope.run_id,
        "database_written": apply,
        "checks": [item.model_dump(mode="json") for item in records],
    }
