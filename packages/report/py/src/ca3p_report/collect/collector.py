"""Run every collector named in a trigger and seal the results into one bundle."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..trigger import Trigger
from . import casper, pentest_db, run_store
from .bundle import EVENTS_SCHEMA, HISTORY_SCHEMA, RUN_SCHEMA, VERIFICATION_SCHEMA, BundleWriter
from .general import select_finding
from .hints import capture_hints
from .model import CollectError, RunRecord
from .verification import VerificationHandoffError, load_verification_handoff

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
    selection: dict | None = None


def _verification(run_id: str, location: Path, selection: dict | None) -> tuple[dict, list]:
    """The sealed verification document and the (ref, bytes) pairs of its images."""
    try:
        handoff = load_verification_handoff(location)
    except VerificationHandoffError as exc:
        raise CollectError(str(exc)) from exc
    attack_id = handoff["result"].get("attackId")
    if selection is not None and attack_id not in {p["id"] for p in selection["confirmedProbes"]}:
        raise CollectError("verification attackId is not a confirmed probe of the selected finding")
    names = [image["path"].name for image in handoff["images"]]
    if len(set(names)) != len(names):
        raise CollectError("verification image names are duplicated")
    records, blobs = [], []
    for image in handoff["images"]:
        data = image["path"].read_bytes()
        if "sha256:" + hashlib.sha256(data).hexdigest() != image["sha256"]:
            raise CollectError("verification image changed after its integrity check")
        ref = f"evidence/images/{image['path'].name}"
        records.append({"ref": ref, "sha256": image["sha256"], "bytes": image["bytes"],
                        "label": image["label"]})
        blobs.append((ref, data))
    document = {"schemaVersion": VERIFICATION_SCHEMA, "runId": run_id,
                "result": handoff["result"], "images": records}
    return document, blobs


def collect(trigger: Trigger, *, now: datetime | None = None) -> CollectResult:
    run = RUN_DRIVERS[trigger.run.kind](trigger.run.location, trigger.run_id)
    if run is None:
        raise RunNotFound(trigger.run_id)
    if run.report is None:
        raise RunIncomplete(trigger.run_id)
    if run.report.get("assessmentMode") == "general" and trigger.finding_id is None:
        raise CollectError("general report collection requires options.findingId")
    selection = select_finding(run, trigger.finding_id) if trigger.finding_id else None

    if trigger.history.kind == casper.DRIVER:
        history = casper.read_history(trigger.history.location, casper.history_refs(run.events))
    else:
        history = casper.unavailable("not-requested")

    context = casper.reference_context(run.events)
    if context is not None:
        history["referenceContext"] = context

    verification, blobs = (None, [])
    if trigger.verification.kind == "handoff-dir":
        verification, blobs = _verification(run.run_id, trigger.verification.location, selection)

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
        if selection is not None:
            writer.add_json("run/selection.json", "general-finding-selection", selection)
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
        if verification is not None:
            writer.add_json("run/verification.json", "verification-handoff", verification)
            for ref, data in blobs:
                writer.add_bytes(ref, "verification-image", data)
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
    if selection is not None and verification is not None:
        # The general model reads the verification through the selection it already receives.
        selection = {**selection, "verification": verification}
    return CollectResult(bundle=writer.root, manifest=manifest, run=run, selection=selection)
