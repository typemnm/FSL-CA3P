from __future__ import annotations

from pathlib import Path

import pytest

from ca3p_report.trigger import TriggerError, parse_trigger


def trigger(root: Path, **overrides) -> dict:
    value = {
        "schemaVersion": "report-trigger-1.0",
        "runId": "run-1-abc",
        "sources": {
            "run": {"kind": "pentest-db-disk", "location": str(root / "data/runs")},
            "history": {"kind": "casper-db", "location": str(root / "data/cases.sqlite3")},
        },
        "output": {"dir": str(root / "out/run-1-abc")},
    }
    value.update(overrides)
    return value


def test_parses_sources_and_output(tmp_path):
    parsed = parse_trigger(trigger(tmp_path))
    assert parsed.run.kind == "pentest-db-disk"
    assert parsed.history.location == tmp_path / "data/cases.sqlite3"
    assert parsed.output_dir == tmp_path / "out/run-1-abc"


def test_history_defaults_to_none(tmp_path):
    parsed = parse_trigger(trigger(tmp_path,
        sources={"run": {"kind": "run-store", "location": str(tmp_path / "r.sqlite")}}))
    assert parsed.history.kind == "none" and parsed.history.location is None


def test_optional_general_finding_selection(tmp_path):
    parsed = parse_trigger(trigger(tmp_path, options={"findingId": "finding:h-a"}))
    assert parsed.finding_id == "finding:h-a"
    for options in ({"findingId": "../escape"}, {"findingId": 1}, {"other": "x"}):
        with pytest.raises(TriggerError):
            parse_trigger(trigger(tmp_path, options=options))


@pytest.mark.parametrize(
    "malform",
    [
        lambda value: value.update(runId="../escape"),
        lambda value: value.update(runId="x" * 129),
        lambda value: value.update(schemaVersion="report-trigger-0.9"),
        lambda value: value.update(unexpected=True),
        lambda value: value.update(output={"dir": "relative/out"}),
        lambda value: value["sources"]["run"].update(location="runs"),
        lambda value: value["sources"]["run"].update(kind="ftp"),
        lambda value: value["sources"]["run"].update(extra=1),
        lambda value: value["sources"]["history"].update(kind="none"),
        lambda value: [],
    ],
)
def test_rejects_malformed_triggers(tmp_path, malform):
    value = trigger(tmp_path)
    changed = malform(value)
    if changed is not None:
        value = changed
    with pytest.raises(TriggerError):
        parse_trigger(value)
