import pytest
from pydantic import ValidationError

from casper_db.matching import assess_observation


def observed(**changes):
    return {
        "target_id": "LAB-DEMO", "endpoint": "/search", "method": "GET",
        "parameter": "q", "parameter_location": "query", **changes,
    }


def test_exact_location_is_a_retest_candidate_but_never_a_finding(store, case_data):
    store.add({**case_data, "status": "ready"})
    assessment = assess_observation(store, observed())
    assert assessment.decision == "retest_candidate"
    assert len(assessment.matches) == 1
    assert assessment.matches[0].case_id == "CASE-001"
    assert assessment.matches[0].changed_fields == []
    assert assessment.matches[0].matched_fields == [
        "target_id", "endpoint", "method", "parameter", "parameter_location"
    ]
    assert "판정은 아님" in assessment.explanation


def test_changed_method_or_parameter_requires_manual_review(store, case_data):
    store.add({**case_data, "status": "ready"})
    for change, field in (({"parameter": "page"}, "parameter"), ({"method": "POST"}, "method")):
        assessment = assess_observation(store, observed(**change))
        assert assessment.decision == "manual_review"
        assert assessment.matches[0].changed_fields == [field]


@pytest.mark.parametrize(
    "change",
    [
        {"target_id": "OTHER"},
        {"endpoint": "/about"},
        {"endpoint": "/Search"},
        {"method": "POST", "parameter": "page"},
    ],
)
def test_weak_location_similarity_is_not_promoted(store, case_data, change):
    store.add({**case_data, "status": "ready"})
    assessment = assess_observation(store, observed(**change))
    assert assessment.decision == "no_match"
    assert assessment.matches == []


def test_draft_is_not_used_for_normal_candidate_matching(store, case_data):
    store.add(case_data)
    assert assess_observation(store, observed()).decision == "no_match"


def test_input_location_mismatch_or_missing_location_requires_review(store, case_data):
    store.add({**case_data, "status": "ready"})
    for location in ("body", "unknown"):
        assessment = assess_observation(store, observed(parameter_location=location))
        assert assessment.decision == "manual_review"
        assert assessment.matches[0].changed_fields == ["parameter_location"]
    legacy = observed()
    del legacy["parameter_location"]
    assert assess_observation(store, legacy).decision == "manual_review"


def test_parser_contract_rejects_ambiguous_or_extra_input(store):
    with pytest.raises(ValidationError):
        assess_observation(store, observed(endpoint="/search?q=test"))
    with pytest.raises(ValidationError):
        assess_observation(store, observed(input_location="query"))
