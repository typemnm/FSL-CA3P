"""Turn raw OCR lines into source-linked review candidates, never confirmed fields."""

from __future__ import annotations

import re

from .hwpx import CODE_PATTERN, refresh_field_status
from .local_ocr import OcrBundle, ocr_fingerprint, validate_recognition
from .narrative import classify_paragraph
from .report_drafts import FieldEvidence, PayloadVariant, ReviewIssue

_PAYLOAD = re.compile(r"^\s*(?:payload|페이로드|URL\s*인코딩)\s*[:：]\s*(?P<value>.+)$", re.I)
_STEP = re.compile(r"^\s*\d+[.)]\s*.*(?:접속|클릭|입력|전송|변경|선택|조회)")


def ocr_ref(image_id, line_index):
    return f"image-ocr:{image_id}#line{line_index}"


def apply_ocr_evidence(report, bundle: OcrBundle):
    if bundle.source_sha256 != report.source["sha256"]:
        raise ValueError("OCR bundle belongs to a different source report")
    if "local_ocr" in report.document:
        raise ValueError("draft already has OCR evidence; re-extract instead of stacking results")
    images = {image["image_id"]: image for image in report.document["images"]}
    ids = [result.image_id for result in bundle.images]
    if len(ids) != len(set(ids)) or set(ids) != set(images):
        raise ValueError("OCR bundle has unknown, missing or duplicate image IDs")
    for result in bundle.images:
        if result.archive_sha256 != images[result.image_id].get("sha256"):
            raise ValueError("OCR image hash does not match the source image")
        if result.status in {"recognized", "no_text"}:
            if result.recognition is None or not result.image_sha256:
                raise ValueError("recognized image has no OCR evidence")
            validate_recognition(result.recognition)
            if not images[result.image_id].get("embedded"):
                raise ValueError("recognized image is not embedded in the report")
            if (result.status == "recognized") != bool(result.recognition.text.strip()):
                raise ValueError("OCR image status and text disagree")
            if (
                report.source.get("format") != "hwp"
                and result.image_sha256 != result.archive_sha256
            ):
                raise ValueError("OCR raster hash does not match embedded image")
    updated = report.model_copy(deep=True)
    updated.document["local_ocr"] = {
        "fingerprint": ocr_fingerprint(bundle),
        "bundle": bundle.model_dump(mode="json"),
        "notice": (
            "OCR output is unreviewed. Original pixels define original glyphs; "
            "recognized text may contain substitutions."
        ),
    }
    by_id = {result.image_id: result for result in bundle.images}
    for image in updated.document["images"]:
        result = by_id[image["image_id"]]
        image["text_extraction"] = "unreviewed_local_ocr_" + result.status
    for finding in updated.findings:
        relevant = [by_id[image_id] for image_id in finding.image_refs if image_id in by_id]
        if not relevant:
            continue
        attempted = {
            f"image:{item.image_id}"
            for item in relevant
            if item.status in {"recognized", "no_text", "failed"}
        }
        finding.review_issues = [
            issue
            for issue in finding.review_issues
            if not (
                issue.code == "image_text_not_processed" and set(issue.source_refs) <= attempted
            )
        ]
        finding.review_issues.append(
            ReviewIssue(
                code="unreviewed_local_ocr",
                message=(
                    "로컬 OCR 후보입니다. 공백·따옴표·문자 오인식을 캡처 원본과 대조해야 합니다."
                ),
                source_refs=[f"image:{item.image_id}" for item in relevant],
            )
        )

        def evidence(field, value, ref, finding=finding):
            item = FieldEvidence(value=value, source_ref=ref, method="review_candidate")
            bucket = finding.field_evidence.setdefault(field, [])
            if item not in bucket:
                bucket.append(item)

        for image in relevant:
            if image.status != "recognized":
                finding.review_issues.append(
                    ReviewIssue(
                        code="ocr_" + image.status,
                        message=(
                            "OCR에서 확인할 문자를 확보하지 못했습니다. 캡처 원본은 보존했습니다."
                            + (" " + image.error if image.error else "")
                        ),
                        source_refs=[f"image:{image.image_id}"],
                    )
                )
                continue
            for index, line in enumerate(image.recognition.lines):
                ref = ocr_ref(image.image_id, index)
                evidence(
                    "ocr_lines",
                    {
                        "text": line.text,
                        "image_id": image.image_id,
                        "image_sha256": image.image_sha256,
                        "line_index": index,
                        "words": [word.model_dump(mode="json") for word in line.words],
                        "confidence": None,
                        "review_status": "unreviewed",
                    },
                    ref,
                )
                explicit = _PAYLOAD.search(line.text)
                payload = (
                    explicit["value"]
                    if explicit
                    else (
                        line.text
                        if CODE_PATTERN.search(line.text) and not re.search(r"[가-힣]", line.text)
                        else None
                    )
                )
                if payload and len(payload) <= 20000:
                    evidence("payload", payload, ref)
                    evidence(
                        "ocr_payload_spans",
                        {
                            "text": payload,
                            "start": explicit.start("value") if explicit else 0,
                            "end": explicit.end("value") if explicit else len(line.text),
                            "normalization_applied": False,
                        },
                        ref,
                    )
                    finding.payload_variants.append(
                        PayloadVariant(
                            value=payload,
                            representation="image_ocr",
                            source_ref=ref,
                            source_text=line.text,
                        )
                    )
                    continue
                for segment in classify_paragraph(line.text, ref):
                    role = segment.role
                    if role == "unclassified" and _STEP.search(segment.text):
                        role = "procedure"
                    evidence(
                        "ocr_segments",
                        {
                            "role": role,
                            "text": segment.text,
                            "start": segment.start,
                            "end": segment.end,
                            "rule": segment.rule,
                        },
                        ref,
                    )
                    if role in {"procedure", "preconditions"}:
                        evidence(role, segment.text, ref)
                    elif role == "observed_result":
                        evidence("observed_result", segment.text, ref)
                        evidence("success_condition", segment.text, ref)
                    elif role == "mixed":
                        evidence("procedure", segment.text, ref)
                        evidence("success_condition", segment.text, ref)
                    for name in segment.parameters:
                        evidence("parameter", name, ref)
        ocr_payloads = [
            item for item in finding.payload_variants if item.representation == "image_ocr"
        ]
        if len({item.value for item in finding.payload_variants}) > 1 and ocr_payloads:
            finding.review_issues.append(
                ReviewIssue(
                    code="ocr_payload_variants_differ",
                    field="payload",
                    message=(
                        "OCR·본문의 payload 후보 표기가 다릅니다. "
                        "공백·따옴표·인코딩을 자동 통일하지 않았습니다."
                    ),
                    source_refs=[item.source_ref for item in ocr_payloads],
                )
            )
        refresh_field_status(finding)
    return updated
