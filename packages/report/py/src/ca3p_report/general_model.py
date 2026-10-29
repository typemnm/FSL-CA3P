"""Evidence-bound ReportModel for one confirmed general finding.

The general assessor does not provide CVSS, CWE, raw HTTP transcripts or a
remediation. Leave those fields empty instead of asking a model to infer them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlsplit


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _asset_path(value: object) -> str | None:
    asset = _text(value)
    if asset is None:
        return None
    if asset.startswith("/"):
        return asset.split("?", 1)[0].split("#", 1)[0]
    parsed = urlsplit(asset)
    return (parsed.path or None) if parsed.scheme in ("http", "https") else None


def build_general_model(
    selection: dict, report: dict, manifest: dict, *, stored_at: str | None = None
) -> dict:
    finding = selection["finding"]
    category = _text(finding.get("category")) or "유형 미기록"
    asset = _text(finding.get("asset")) or "위치 미기록"
    evidence = selection["verificationEvidence"]
    source_id = selection["sourceFindingId"]
    incomplete = report.get("status") == "failed" or selection["partial"]
    limitations = ["확정 판정은 선택한 가설의 현재 실행 검증 증거에 한정됩니다."]
    if incomplete:
        limitations.append(
            "실행이 실패했거나 점검 범위가 부분적이므로 다른 공격면의 점검은 완료되지 않았습니다."
        )
    if _text(selection.get("stopReason")):
        limitations.append(f"종료 사유: {selection['stopReason']}")
    notices = [
        "이 문서는 현재 실행에서 확정된 finding 한 건의 검증 결과입니다.",
        f"원본 finding ID: {source_id}",
        "CWE, CVSS, 재현 요청·응답 및 조치 방안은 원본에 없으면 자료 없음으로 표시합니다.",
    ]
    if incomplete:
        notices.append(
            "점검 미완료: 이미 확인된 결과만 기록하며 전체 범위의 완료를 뜻하지 않습니다."
        )
    target = report.get("target") if isinstance(report.get("target"), dict) else {}
    text_evidence = [{
        "label": f"검증 증거 {item['id']} ({_text(item.get('kind')) or '종류 미기록'})",
        "text": _text(item.get("summary")) or "요약 자료 없음",
    } for item in evidence]
    verification = selection.get("verification")
    images = []
    if verification is not None:
        verdict = verification["result"]
        reason = _text(verdict.get("reason")) or "사유 미기록"
        text_evidence.append({
            "label": "AI 검증 판정",
            "text": f"{_text(verdict.get('status')) or '상태 미기록'} — {reason}",
        })
        images = [{
            "step": None,
            "caption": f"{_text(image.get('label')) or '검증 캡처'} — AI verifier: {reason[:200]}",
            "ref": image["ref"],
            "integrity": "ok",
        } for image in verification["images"]]
    return {
        "schemaVersion": "report-1.0",
        "sourceFindingId": source_id,
        "sourceEvidenceIds": list(selection["verificationEvidenceIds"]),
        "generatedAt": datetime.now(UTC).isoformat(),
        "notices": notices,
        "generator": {"profile": "general", "method": "deterministic"},
        "run": {
            "runId": selection["runId"],
            "status": report.get("status"),
            "testProfile": "general",
            "target": {"origin": target.get("origin")},
            "startedAt": report.get("startedAt"),
            "completedAt": report.get("completedAt") or stored_at,
            "metrics": {"requestCount": None},
            "error": report.get("error") if report.get("status") == "failed" else None,
        },
        "findings": [{
            "common": {
                "findingId": source_id,
                "title": f"{category} · {asset}",
                "cwe": None,
                "location": {
                    "method": None,
                    "path": _asset_path(finding.get("asset")),
                    "parameter": None,
                },
                "cvss": None,
                "severity": None,
                "status": "confirmed",
                "summary": "현재 실행의 독립 검증에서 이 finding이 confirmed로 판정되었습니다.",
                "remediation": None,
                "limitations": " ".join(limitations),
            },
            "reproduction": [],
            "images": images,
            "textEvidence": text_evidence,
            "checks": [{
                "label": f"{_text(probe.get('tool')) or '검사'} · {probe['id']}",
                "result": f"confirmed; 채택 증거: {', '.join(probe['evidenceIds'])}",
            } for probe in selection["confirmedProbes"]],
            "impact": None,
            "profileData": {
                "원본 finding ID": source_id,
                "가설 ID": finding.get("hypothesisId"),
                "확정 증거 ID": ", ".join(selection["verificationEvidenceIds"]),
            },
        }],
        "triage": {"status": "not_assessed", "rows": []},
        "priorCases": [],
        "guardrail": {"decisions": []},
        "safety": {},
        "references": {"collectors": manifest.get("collectors", []), "verifiedByStorage": False},
    }
