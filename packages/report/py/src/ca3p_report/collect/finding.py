"""Normalize the run into the one finding a report covers, plus that finding's attack records.

A report covers exactly one finding. A legacy run report carries it as `report.finding`; a
general run carries `findings[]` and the trigger names one with `options.findingId`, which is
selected and cross-checked by `general.select_finding`. Both become `report-finding-1.0`.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..trigger import FINDING_ID
from .general import select_finding
from .model import CollectError, RunRecord, StoredEvent

FINDING_SCHEMA = "report-finding-1.0"
ATTACK_SCHEMA = "report-attack-1.0"
ATTACK_KEYS = ("kind", "request", "response", "control", "followUp", "setup")
TIME_FORMAT = "%Y-%m-%d %H:%M:%S UTC"


def legacy_finding_id(finding: dict) -> str:
    """The id a legacy finding is reported under. Mirrored by index.mjs."""
    for key in ("findingId", "id"):
        value = finding.get(key)
        if isinstance(value, str) and FINDING_ID.fullmatch(value):
            return value
    return "finding"


def report_time(value: object) -> str | None:
    """A source timestamp as the report prints it; text that is not ISO 8601 is kept as is."""
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return value
    return (moment.astimezone(UTC) if moment.tzinfo else moment).strftime(TIME_FORMAT)


def run_header(run: RunRecord, incomplete: bool) -> dict:
    """REPORT_SPEC `run` (except generated_at), from the run record only. Never from the LLM."""
    report = run.report or {}
    state = run.meta
    target = report.get("target") if isinstance(report.get("target"), dict) else {}
    state_target = state.get("target")
    origin = target.get("origin") or (state_target if isinstance(state_target, str) else None)
    completed = next((e.recorded_at for e in reversed(run.events) if e.stage == "complete"), None)
    metrics = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    count = metrics.get("requestCount")
    if not isinstance(count, int) or isinstance(count, bool):
        # Only general runs record Agent `execute` events; legacy runs without metrics stay unknown.
        general = report.get("assessmentMode") == "general"
        count = sum(e.stage == "execute" for e in run.events) if general else None
    return {
        "run_id": run.run_id,
        "target_origin": origin,
        "target_name": target.get("name") or target.get("fixtureId") or state.get("fixtureId")
        or origin,
        "profile": state.get("testProfile") or report.get("testProfile"),
        "started_at": report_time(state.get("startedAt") or report.get("startedAt")),
        "finished_at": report_time(report.get("completedAt") or completed or run.stored_at),
        "request_count": count,
        "status": report.get("status"),
        "incomplete": incomplete,
    }


def finding_document(run: RunRecord, finding_id: str | None) -> dict:
    document = _document(run, finding_id)
    document["run"] = run_header(run, document["incomplete"])
    return document


def _document(run: RunRecord, finding_id: str | None) -> dict:
    report = run.report or {}
    if report.get("assessmentMode") == "general":
        if finding_id is None:
            raise CollectError("general report collection requires options.findingId")
        selection = select_finding(run, finding_id)
        return {
            "schemaVersion": FINDING_SCHEMA,
            "runId": run.run_id,
            "sourceFindingId": finding_id,
            "status": "confirmed",
            "runStatus": report["status"],
            "incomplete": report["status"] == "failed" or selection["partial"],
            "stopReason": selection["stopReason"],
            "finding": selection["finding"],
            "hypothesis": selection["hypothesis"],
            "confirmedProbes": selection["confirmedProbes"],
            "evidenceIds": selection["verificationEvidenceIds"],
            "evidence": selection["verificationEvidence"],
        }
    if finding_id is not None:
        raise CollectError("finding selection requires a general run report")
    finding = report.get("finding")
    if not isinstance(finding, dict):
        raise CollectError("run report has no finding")
    refs = finding.get("evidenceRefs")
    evidence_ids = list(dict.fromkeys(
        ref for ref in (refs if isinstance(refs, list) else []) if isinstance(ref, str)
    ))
    evidence = report.get("evidence")
    return {
        "schemaVersion": FINDING_SCHEMA,
        "runId": run.run_id,
        "sourceFindingId": legacy_finding_id(finding),
        "status": finding.get("status"),
        "runStatus": report.get("status"),
        "incomplete": report.get("status") == "failed" or report.get("partial") is True,
        "stopReason": report.get("stopReason"),
        "finding": finding,
        "evidenceIds": evidence_ids,
        "evidence": evidence if isinstance(evidence, list) else [],
    }


def _payload(envelope: dict) -> dict:
    payload = envelope.get("payload")
    return payload if isinstance(payload, dict) else {}


def attack_records(events: list[StoredEvent], verification: dict | None) -> list[dict]:
    """The attack module's requests and responses: the verifier's AttackRecord when the
    handoff carries one, and the `loop.act` exchanges of legacy runs."""
    records = []
    attack = (verification or {}).get("result", {}).get("attack")
    if isinstance(attack, dict) and isinstance(attack.get("request"), dict):
        records.append({key: attack[key] for key in ATTACK_KEYS if key in attack})
    for event in events:
        if event.stage != "loop.act":
            continue
        curl = _payload(event.request).get("curl")
        if not isinstance(curl, dict):
            continue
        response = _payload(event.response).get("response")
        records.append({
            "kind": "loop.act",
            "request": {key: curl[key] for key in ("method", "url", "body") if key in curl},
            "response": response if isinstance(response, dict) else {},
            **({"session": _payload(event.request)["session"]}
               if isinstance(_payload(event.request).get("session"), str) else {}),
        })
    return records
