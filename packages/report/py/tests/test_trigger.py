from __future__ import annotations

import pytest

from ca3p_report.trigger import TriggerError, parse_trigger


def trigger(**overrides) -> dict:
    value = {
        "schemaVersion": "report-trigger-1.0",
        "runId": "run-1-abc",
        "sources": {
            "run": {"kind": "pentest-db-disk", "location": "/data/runs"},
            "history": {"kind": "casper-db", "location": "/data/cases.sqlite3"},
        },
        "output": {"dir": "/out/run-1-abc"},
    }
    value.update(overrides)
    return value


def test_parses_sources_and_output():
    parsed = parse_trigger(trigger())
    assert parsed.run.kind == "pentest-db-disk"
    assert str(parsed.history.location) == "/data/cases.sqlite3"
    assert str(parsed.output_dir) == "/out/run-1-abc"


def test_history_defaults_to_none():
    parsed = parse_trigger(trigger(sources={"run": {"kind": "run-store", "location": "/r.sqlite"}}))
    assert parsed.history.kind == "none" and parsed.history.location is None


@pytest.mark.parametrize(
    "value",
    [
        trigger(runId="../escape"),
        trigger(runId="x" * 129),
        trigger(schemaVersion="report-trigger-0.9"),
        trigger(unexpected=True),
        trigger(output={"dir": "relative/out"}),
        trigger(sources={"run": {"kind": "pentest-db-disk", "location": "runs"}}),
        trigger(sources={"run": {"kind": "ftp", "location": "/x"}}),
        trigger(sources={"run": {"kind": "run-store", "location": "/r", "extra": 1}}),
        trigger(
            sources={
                "run": {"kind": "run-store", "location": "/r"},
                "history": {"kind": "none", "location": "/x"},
            }
        ),
        [],
    ],
)
def test_rejects_malformed_triggers(value):
    with pytest.raises(TriggerError):
        parse_trigger(value)
