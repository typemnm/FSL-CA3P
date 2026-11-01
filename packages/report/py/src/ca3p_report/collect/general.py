"""Select one independently confirmed general finding from a stored run."""

from __future__ import annotations

from .model import CollectError, RunRecord


def _rows(value: object, name: str) -> list[dict]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise CollectError(f"general report {name} is invalid")
    return value


def _ids(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CollectError(f"general report {name} is invalid")
    return value


def select_finding(run: RunRecord, finding_id: str) -> dict:
    report = run.report
    if (run.driver != "run-store" or not isinstance(report, dict)
        or report.get("schemaVersion") != "general-assessment/1"
        or report.get("assessmentMode") != "general"
        or report.get("runId") != run.run_id
        or report.get("status") not in ("completed", "failed")):
        raise CollectError("selected finding requires a final general run-store report")

    findings = _rows(report.get("findings"), "findings")
    selected = [item for item in findings if item.get("id") == finding_id]
    if len(selected) != 1 or selected[0].get("status") != "confirmed":
        raise CollectError("selected finding must be uniquely confirmed")
    finding = selected[0]
    linked: list[str] = []
    primary = finding.get("hypothesisId")
    if isinstance(primary, str):
        linked.append(primary)
    extra = finding.get("hypothesisIds")
    if isinstance(extra, list):
        for item in extra:
            if isinstance(item, str) and item not in linked:
                linked.append(item)
    if not linked:
        raise CollectError("selected finding has no hypothesis ID")
    by_hypothesis = {item.get("id"): item for item in _rows(report.get("hypotheses"), "hypotheses")
                     if isinstance(item.get("id"), str)}
    if any(item not in by_hypothesis for item in linked):
        raise CollectError("selected finding hypothesis is missing or ambiguous")
    hypothesis = by_hypothesis[linked[0]]

    evidence = _rows(report.get("evidence"), "evidence")
    by_id = {item.get("id"): item for item in evidence if isinstance(item.get("id"), str)}
    if len(by_id) != len(evidence):
        raise CollectError("general report evidence IDs are invalid or duplicate")
    finding_refs = set(_ids(finding.get("evidenceIds"), "finding evidence IDs"))
    probes = _rows(report.get("probes"), "probes")
    probes_by_id = {item.get("id"): item for item in probes if isinstance(item.get("id"), str)}
    if len(probes_by_id) != len(probes):
        raise CollectError("general report probe IDs are invalid or duplicate")

    verified_ids: list[str] = []
    confirmed_probes: list[dict] = []
    seen_probes: set[str] = set()
    linked_set = set(linked)
    for event in run.events:
        if (event.stage != "verify" or event.request.get("hypothesisId") not in linked_set
            or event.response.get("status") != "confirmed"):
            continue
        probe_id = event.request.get("probeId")
        probe = probes_by_id.get(probe_id)
        if (not isinstance(probe_id, str) or probe_id in seen_probes or not probe
            or probe.get("hypothesisId") not in linked_set or probe.get("status") != "confirmed"):
            raise CollectError("confirmed verification has no matching probe")
        probe_refs = set(_ids(probe.get("evidenceIds"), "probe evidence IDs"))
        verdict_refs = _ids(event.response.get("evidenceIds"), "verification evidence IDs")
        current_refs = list(dict.fromkeys(ref for ref in verdict_refs if ref in probe_refs))
        if not current_refs:
            raise CollectError("confirmed verification has no current probe evidence")
        if any(ref not in finding_refs or ref not in by_id for ref in verdict_refs):
            raise CollectError("confirmed verification cites unrelated evidence")
        seen_probes.add(probe_id)
        confirmed_probes.append({
            "id": probe_id,
            "tool": probe.get("tool"),
            "evidenceIds": current_refs,
        })
        verified_ids.extend(current_refs)
    verified_ids = list(dict.fromkeys(verified_ids))
    if not verified_ids:
        raise CollectError("selected finding has no confirmed verification event")

    background_ids = [ref for ref in finding.get("evidenceIds", [])
                      if ref not in verified_ids and ref in by_id]
    return {
        "schemaVersion": "general-finding-selection/1",
        "runId": run.run_id,
        "sourceFindingId": finding_id,
        "finding": finding,
        "hypothesis": hypothesis,
        "confirmedProbes": confirmed_probes,
        "verificationEvidenceIds": verified_ids,
        "verificationEvidence": [by_id[ref] for ref in verified_ids],
        "backgroundEvidenceIds": background_ids,
        "runStatus": report["status"],
        "partial": report.get("partial") is True,
        "stopReason": report.get("stopReason"),
        "target": report.get("target"),
        "coverage": report.get("coverage"),
    }
