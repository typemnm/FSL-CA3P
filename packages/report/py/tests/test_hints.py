from __future__ import annotations

from fixtures import stored_xss_events

from ca3p_report.collect.hints import capture_hints
from ca3p_report.collect.model import StoredEvent


def events() -> list[StoredEvent]:
    return [
        StoredEvent(
            stage=item["stage"],
            iteration=item["iteration"],
            recorded_at=None,
            message_id=None,
            request=item["request"],
            response=item["response"],
        )
        for item in stored_xss_events()
    ]


def test_extracts_input_form_session_switch_and_attacker():
    hints = capture_hints(events())
    assert hints["schemaVersion"] == "report-input-hints-1.0"
    # The compose form carries both attack body keys (title, content).
    compose = [f for f in hints["inputForms"] if f["selector"] == "#post-form"]
    assert compose and compose[0]["carries_attack_param"] is True
    assert set(compose[0]["fields"]) >= {"title", "content"}
    assert hints["sessionSwitch"] == {
        "method": "POST",
        "path": "/api/session",
        "bodyKeys": ["userId"],
    }
    assert hints["attackerAccount"] == "alice"


def test_absent_signals_are_omitted_not_guessed():
    # Only a history event, no parser report / act / session.
    bare = [StoredEvent("loop.history", 1, None, None, {}, {"payload": {"assessments": []}})]
    hints = capture_hints(bare)
    assert hints == {"schemaVersion": "report-input-hints-1.0"}


def test_form_without_attack_param_is_not_marked():
    evs = events()
    # Drop the act event so there are no known attack body keys.
    evs = [e for e in evs if e.stage != "loop.act"]
    hints = capture_hints(evs)
    assert all(f["carries_attack_param"] is False for f in hints.get("inputForms", []))
