"""Run every collector named in a trigger and seal the results into one bundle."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..trigger import Trigger
from . import casper, pentest_db, run_store
from .bundle import EVENTS_SCHEMA, HISTORY_SCHEMA, RUN_SCHEMA, BundleWriter
from .hints import capture_hints
from .model import RunRecord

RUN_DRIVERS = {
    pentest_db.DRIVER: pentest_db.read_run,
    run_store.DRIVER: run_store.read_run,
}


class RunNotFound(LookupError):
    """The run source has no record of this runId."""


class RunIncomplete(RuntimeError):
    """The run has events but never stored a final report."""


@dataclass(frozen=True)
class CollectResult:
    bundle: Path
    manifest: dict
    run: RunRecord


def collect(trigger: Trigger, *, now: datetime | None = None) -> CollectResult:
    run = RUN_DRIVERS[trigger.run.kind](trigger.run.location, trigger.run_id)
    if run is None:
        raise RunNotFound(trigger.run_id)
    if run.report is None:
        raise RunIncomplete(trigger.run_id)

    if trigger.history.kind == casper.DRIVER:
        history = casper.read_history(trigger.history.location, casper.history_refs(run.events))
    else:
        history = casper.unavailable("not-requested")

    writer = BundleWriter(trigger.output_dir / "bundle")
    try:
        writer.add_json(
            "run/report.json",
            "run-report",
            {
                "schemaVersion": RUN_SCHEMA,
                "runId": run.run_id,
                "storedAt": run.stored_at,
                "provenance": run.provenance,
                "report": run.report,
            },
        )
        writer.add_json(
            "run/events.json",
            "run-events",
            {
                "schemaVersion": EVENTS_SCHEMA,
                "runId": run.run_id,
                "events": [event.to_json() for event in run.events],
            },
        )
        writer.add_json(
            "history/casper.json",
            "history",
            {
                "schemaVersion": HISTORY_SCHEMA,
                "runId": run.run_id,
                **history,
            },
        )
        hints = capture_hints(run.events)
        writer.add_json("hints/capture.json", "capture-hints", {"runId": run.run_id, **hints})
        collected_at = (now or datetime.now(UTC)).isoformat()
        collectors = [
            {
                "name": "collect-run",
                "driver": run.driver,
                "status": "ok",
                "events": len(run.events),
            },
            {
                "name": "collect-history",
                "driver": trigger.history.kind,
                "status": history["status"],
                **({"reason": history["reason"]} if "reason" in history else {}),
            },
            {
                "name": "collect-hints",
                "status": "ok",
                "forms": len(hints.get("inputForms", [])),
                "sessionSwitch": "sessionSwitch" in hints,
            },
        ]
        manifest = writer.seal(run_id=run.run_id, collected_at=collected_at, collectors=collectors)
    except BaseException:
        writer.discard()
        raise
    return CollectResult(bundle=writer.root, manifest=manifest, run=run)
