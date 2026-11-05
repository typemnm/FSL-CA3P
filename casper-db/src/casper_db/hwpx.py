"""Read local HWPX archives into loss-aware JSON drafts. No network or DB access."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, date, datetime
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree as ET
from zipfile import BadZipFile, ZipFile

from pydantic import TypeAdapter, ValidationError

from .field_values import has_supplied_value, is_unknown
from .models import Case, Identifier
from .narrative import apply_narrative_analysis
from .report_drafts import (
    CaseDraft,
    FieldEvidence,
    FindingDraft,
    ImageTranscriptBundle,
    PayloadVariant,
    ReportDraft,
    ReviewIssue,
)

MAX_FILE_BYTES = 32_000_000
MAX_UNPACKED_BYTES = 96_000_000
MAX_PART_BYTES = 16_000_000
MAX_ENTRIES = 512
URL_PATTERN = re.compile(r"https?://[^\s<>]+", re.IGNORECASE)
CODE_PATTERN = re.compile(r"alert\s*\(|<script\b|javascript:", re.IGNORECASE)
INLINE_PAYLOAD = re.compile(r"(?:payload|페이로드|시험\s*입력)\s*[:：]\s*(.+)", re.IGNORECASE)
ENCODED_PATTERN = re.compile(
    r"(?:URL\s*인코딩|URL[- ]?encoded)\s*[:：]\s*(?P<value>.*?)\)?$", re.IGNORECASE
)
LABELS = {
    "취약점종류": "vulnerability_type",
    "취약유형": "vulnerability_type",
    "취약점유형": "vulnerability_type",
    "설명": "description",
    "영향": "impact",
    "내용": "narrative",
    "영향url": "vulnerability_url",
    "발생url": "vulnerability_url",
    "취약url": "vulnerability_url",
    "대상url": "vulnerability_url",
    "해결방안": "remediation",
    "조치방안": "remediation",
    "대응방안": "remediation",
    "제목": "title",
    "심각도": "severity",
    "위험도": "severity",
    "발견일": "reported_on",
    "점검일": "reported_on",
    "발견날짜": "reported_on",
    "재현조건": "preconditions",
    "전제조건": "preconditions",
    "사전조건": "preconditions",
    "재현절차": "procedure",
    "재현방법": "procedure",
    "재현과정": "procedure",
    "payload": "payload",
    "페이로드": "payload",
    "시험입력": "payload",
    "성공조건": "success_condition",
    "재현성공조건": "success_condition",
    "요청방식": "method",
    "http메서드": "method",
    "메서드": "method",
    "파라미터": "parameter",
    "입력항목": "parameter",
    "입력위치": "parameter_location",
    "조치상태": "patch_status",
    "증거": "prior_evidence",
}
SEVERITIES = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "하": "low",
    "중": "medium",
    "상": "high",
    "최상": "critical",
}


def _has_value(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return any(_has_value(item) for item in value)
    return value is not None


def _tag(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _xml(data: bytes) -> ET.Element:
    # DTD/entity processing and external resources are outside this file reader's scope.
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", data.replace(b"\x00", b""), re.IGNORECASE):
        raise ValueError("HWPX XML declarations with DTD/entities are not supported")
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError("invalid HWPX XML") from exc


def _text(paragraph: ET.Element) -> str:
    pieces: list[str] = []

    def walk(node: ET.Element) -> None:
        name = _tag(node)
        if name == "tbl":
            return
        if name in {"lineBreak", "tab"}:
            pieces.append("\n" if name == "lineBreak" else "\t")
        if name == "t" and node.text:
            pieces.append(node.text)
        for child in node:
            walk(child)
            if name == "t" and child.tail:
                pieces.append(child.tail)

    walk(paragraph)
    return "".join(pieces)


def _label(text: str) -> str:
    return re.sub(r"[\s:：]", "", text).casefold()


def _section_names(archive: ZipFile, manifest: ET.Element | None) -> list[str]:
    available = set(archive.namelist())
    sections = {name for name in available if re.fullmatch(r"Contents/section\d+\.xml", name)}
    ordered: list[str] = []
    if manifest is not None:
        items = {n.get("id"): n.get("href") for n in manifest.iter() if _tag(n) == "item"}
        for node in manifest.iter():
            if _tag(node) == "itemref" and items.get(node.get("idref")) in sections:
                name = items[node.get("idref")]
                if name not in ordered:
                    ordered.append(name)
    # Keep even unlisted body sections rather than silently discarding them.
    return ordered + sorted(sections - set(ordered), key=lambda n: int(re.search(r"\d+", n)[0]))


def _read_document(archive: ZipFile) -> dict[str, Any]:
    names = set(archive.namelist())
    manifest = (
        _xml(archive.read("Contents/content.hpf")) if "Contents/content.hpf" in names else None
    )
    metadata = (
        []
        if manifest is None
        else [
            {"tag": _tag(n), "attributes": dict(n.attrib), "text": n.text or ""}
            for n in manifest.iter()
            if _tag(n) in {"meta", "title", "language"}
        ]
    )
    images: list[dict[str, Any]] = []
    if manifest is not None:
        for node in manifest.iter():
            if _tag(node) != "item" or not node.get("media-type", "").startswith("image/"):
                continue
            part = node.get("href", "")
            embedded = part in names and not PurePosixPath(part).is_absolute()
            data = archive.read(part) if embedded else None
            images.append(
                {
                    "image_id": node.get("id"),
                    "archive_part": part,
                    "media_type": node.get("media-type"),
                    "embedded": embedded,
                    "sha256": _sha(data) if data is not None else None,
                    "text_extraction": "not_processed",
                }
            )
    sections: list[dict[str, Any]] = []
    tables: list[dict[str, Any]] = []
    for part in _section_names(archive, manifest):
        root = _xml(archive.read(part))
        parents = {child: node for node in root.iter() for child in node}
        order = {node: index for index, node in enumerate(root.iter())}
        paragraph_map: dict[ET.Element, dict[str, Any]] = {}
        for index, node in enumerate((n for n in root.iter() if _tag(n) == "p"), 1):
            ancestor = parents.get(node)
            in_table = False
            while ancestor is not None:
                in_table = in_table or _tag(ancestor) == "tbl"
                ancestor = parents.get(ancestor)
            controls = [
                {
                    "type": _tag(n),
                    "attributes": dict(n.attrib),
                    "parameters": [
                        {"attributes": dict(p.attrib), "text": p.text or ""}
                        for p in n.iter()
                        if _tag(p).endswith("Param")
                    ],
                }
                for n in node.iter()
                if _tag(n) == "fieldBegin"
            ]
            paragraph_map[node] = {
                "source_ref": f"{part}#p{index}",
                "text": _text(node),
                "in_table": in_table,
                "order": order[node],
                "image_ids": [n.get("binaryItemIDRef") for n in node.iter() if _tag(n) == "img"],
                "controls": controls,
            }
        for local_index, table in enumerate((n for n in root.iter() if _tag(n) == "tbl"), 1):
            ref = f"{part}#table{local_index}"
            preceding = [
                p
                for p in paragraph_map.values()
                if not p["in_table"] and p["text"].strip() and p["order"] < order[table]
            ]
            cells = []
            for row in (n for n in table if _tag(n) == "tr"):
                for cell in (n for n in row if _tag(n) == "tc"):
                    address = next((n.attrib for n in cell if _tag(n) == "cellAddr"), {})
                    span = next((n.attrib for n in cell if _tag(n) == "cellSpan"), {})
                    r, c = int(address.get("rowAddr", 0)) + 1, int(address.get("colAddr", 0)) + 1
                    paragraphs = [paragraph_map[n] for n in cell.iter() if n in paragraph_map]
                    cells.append(
                        {
                            "source_ref": f"{ref}/r{r}c{c}",
                            "row": r,
                            "column": c,
                            "row_span": int(span.get("rowSpan", 1)),
                            "column_span": int(span.get("colSpan", 1)),
                            "paragraphs": paragraphs,
                            "text": "\n".join(p["text"] for p in paragraphs),
                        }
                    )
            tables.append(
                {
                    "source_ref": ref,
                    "section": part,
                    "table_index": local_index,
                    "table_id": table.get("id"),
                    "cells": cells,
                    "preceding_paragraph": preceding[-1] if preceding else None,
                }
            )
        sections.append({"archive_part": part, "paragraphs": list(paragraph_map.values())})
    if not sections:
        raise ValueError("no Contents/sectionN.xml body found; input must be HWPX")
    return {"metadata": metadata, "sections": sections, "tables": tables, "images": images}


def _fields(table: dict) -> list[dict]:
    result = []
    cells = table["cells"]
    for label in cells:
        key = LABELS.get(_label(label["text"]))
        if key is None:
            continue
        right = sorted(
            (
                c
                for c in cells
                if c["row"] == label["row"]
                and c["column"] >= label["column"] + label["column_span"]
            ),
            key=lambda c: c["column"],
        )
        if right and _label(right[0]["text"]) not in LABELS:
            result.append(
                {
                    "field": key,
                    "label_raw": label["text"],
                    "value_raw": right[0]["text"],
                    "source_ref": right[0]["source_ref"],
                    "cell": right[0],
                }
            )
    return result


def _urls(paragraphs: list[dict]) -> list[dict]:
    return [
        {"url": match.group(), "source_ref": p["source_ref"], "source_text": p["text"]}
        for p in paragraphs
        for match in URL_PATTERN.finditer(p["text"])
    ]


def _labeled_sections(document: dict) -> list[dict]:
    """Group explicitly labeled body paragraphs without altering the original structure."""
    blocks = []
    for section in document["sections"]:
        active, field = None, None
        for paragraph in section["paragraphs"]:
            if paragraph["in_table"]:
                active, field = None, None
                continue
            text = paragraph["text"]
            match = re.match(r"^\s*([^:：\n]{1,40})\s*[:：]\s*(.*)$", text, re.DOTALL)
            key = LABELS.get(_label(match[1])) if match else None
            if key == "vulnerability_type":
                active = {
                    "source_ref": paragraph["source_ref"],
                    "cells": [],
                    "preceding_paragraph": None,
                    "recognized_fields": [],
                }
                blocks.append(active)
            if active is None:
                continue
            if key:
                value = {**paragraph, "text": match[2]}
                cell = {"source_ref": paragraph["source_ref"], "paragraphs": [value]}
                field = {
                    "field": key,
                    "label_raw": match[1],
                    "value_raw": match[2],
                    "source_ref": paragraph["source_ref"],
                    "cell": cell,
                }
                active["cells"].append(cell)
                active["recognized_fields"].append(field)
            elif field is not None and text.strip():
                field["cell"]["paragraphs"].append(paragraph)
                field["value_raw"] += "\n" + text
            elif paragraph.get("image_ids"):
                active["cells"].append({"paragraphs": [paragraph]})
    return blocks


def _query(url: str) -> list[tuple[str, str]]:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return []
    return [
        (unquote(item.partition("=")[0]), item.partition("=")[2])
        for item in parts.query.split("&")
        if "=" in item
    ]


def _payloads(
    paragraphs: list[dict], urls: list[dict], explicit: list[dict]
) -> list[PayloadVariant]:
    variants: list[PayloadVariant] = []
    for field in explicit:
        variants.append(
            PayloadVariant(
                value=field["value_raw"],
                representation="literal",
                source_ref=field["source_ref"],
                source_text=field["value_raw"],
            )
        )
    for paragraph_index, p in enumerate(paragraphs):
        text = p["text"]
        for line in text.splitlines():
            labeled = INLINE_PAYLOAD.search(line)
            if labeled:
                variants.append(
                    PayloadVariant(
                        value=labeled[1],
                        representation=p.get("representation", "literal"),
                        source_ref=p["source_ref"],
                        source_text=line,
                    )
                )
        encoded = ENCODED_PATTERN.search(text)
        if encoded:
            raw = encoded.group("value")
            # Compare typography only to identify an adjacent companion representation.
            # Both original strings are retained unchanged and still require review.
            preceding_lines = text[: encoded.start()].rstrip().splitlines()
            previous = (
                {**p, "text": preceding_lines[-1]}
                if preceding_lines
                else paragraphs[paragraph_index - 1]
                if paragraph_index
                else None
            )
            if previous:
                companion = previous["text"]
                quotes = str.maketrans({"“": '"', "”": '"', "‘": "'", "’": "'"})
                if (
                    has_supplied_value(companion)
                    and len(companion) <= 2000
                    and companion.translate(quotes).strip()
                    == unquote(raw).translate(quotes).strip()
                ):
                    variants.append(
                        PayloadVariant(
                            value=companion,
                            representation=previous.get("representation", "literal"),
                            source_ref=previous["source_ref"],
                            source_text=companion,
                        )
                    )
            variants.append(
                PayloadVariant(
                    value=raw,
                    representation="url_encoded",
                    source_ref=p["source_ref"],
                    source_text=text,
                    percent_decoded_value=unquote(raw),
                )
            )
        elif (
            CODE_PATTERN.search(text)
            and len(text) <= 2000
            and not re.search(r"[가-힣]", text)
            and not URL_PATTERN.search(text)
        ):
            variants.append(
                PayloadVariant(
                    value=text,
                    representation=p.get("representation", "literal"),
                    source_ref=p["source_ref"],
                    source_text=text,
                )
            )
    for item in urls:
        for key, raw in _query(item["url"]):
            if CODE_PATTERN.search(unquote(raw)):
                variants.append(
                    PayloadVariant(
                        value=raw,
                        representation="url_query",
                        parameter=key,
                        source_ref=item["source_ref"],
                        source_text=item["source_text"],
                        percent_decoded_value=unquote(raw),
                    )
                )
    seen = set()
    unique = []
    for variant in variants:
        identity = (variant.value, variant.representation, variant.source_ref)
        if identity not in seen:
            seen.add(identity)
            unique.append(variant)
    return unique


def _finding(
    table: dict,
    fields: list[dict],
    source: dict,
    target_id: str | None,
    transcripts: dict[str, Any],
) -> FindingDraft:
    candidate = CaseDraft(target_id=target_id, source_report=source["path"])
    finding = FindingDraft(
        draft_id=f"{source.get('format', 'hwpx')}-{source['sha256'][:16]}-{table['source_ref']}",
        source_ref=table["source_ref"],
        candidate=candidate,
    )

    def issue(code: str, field: str | None, message: str, refs: list[str] | None = None) -> None:
        finding.review_issues.append(
            ReviewIssue(
                code=code, field=field, message=message, source_refs=refs or [table["source_ref"]]
            )
        )

    grouped: dict[str, list[dict]] = {}
    for item in fields:
        grouped.setdefault(item["field"], []).append(item)
        finding.field_evidence.setdefault(item["field"], []).append(
            FieldEvidence(
                value=item["value_raw"],
                source_ref=item["source_ref"],
            )
        )
    list_fields = {"preconditions", "procedure", "remediation"}
    direct_fields = {
        "title",
        "vulnerability_type",
        "description",
        "prior_evidence",
        "success_condition",
        "vulnerability_url",
        "parameter",
    } | list_fields
    for key in direct_fields:
        items = grouped.get(key, [])
        if len(items) == 1:
            texts = [p["text"] for p in items[0]["cell"]["paragraphs"] if _has_value(p["text"])]
            if key in list_fields and any(is_unknown(text) for text in texts):
                if any(not is_unknown(text) for text in texts):
                    issue(
                        "unconfirmed_list_items",
                        key,
                        "목록에 미확인 항목이 포함되어 전체 값의 확정을 보류했습니다.",
                        [items[0]["source_ref"]],
                    )
                texts = []
            setattr(
                candidate,
                key,
                texts if key in list_fields else items[0]["value_raw"].strip() or None,
            )
            if key not in list_fields and is_unknown(getattr(candidate, key)):
                setattr(candidate, key, None)
        elif len(items) > 1:
            issue(
                "multiple_field_values", key, "같은 항목이 반복되어 대표값을 선택하지 않았습니다."
            )
    for item in fields:
        if item["field"] not in CaseDraft.model_fields:
            finding.unmapped_fields.append(
                {k: item[k] for k in ("field", "label_raw", "value_raw", "source_ref")}
            )
    preceding = table["preceding_paragraph"]
    severity_fields = grouped.get("severity", [])
    if len(severity_fields) > 1:
        issue(
            "multiple_field_values", "severity", " 심각도 항목이 반복되어 자동 선택하지 않았습니다."
        )
        raw, ref = None, None
    elif severity_fields:
        raw, ref = severity_fields[0]["value_raw"].strip(), severity_fields[0]["source_ref"]
    else:
        match = (
            re.search(r"심각도\s*[:：]\s*([A-Za-z가-힣]+)", preceding["text"])
            if preceding
            else None
        )
        raw, ref = (match[1], preceding["source_ref"]) if match else (None, None)
    if raw:
        candidate.severity = SEVERITIES.get(raw.casefold())
        finding.field_evidence.setdefault("severity", []).append(
            FieldEvidence(
                value=raw,
                source_ref=ref,
                method="direct",
            )
        )
        if candidate.severity is None:
            issue("unknown_severity", "severity", "원문 심각도를 허용값으로 변환하지 못했습니다.")
    for key in ("method", "parameter_location", "patch_status", "reported_on"):
        items = grouped.get(key, [])
        if len(items) > 1:
            issue(
                "multiple_field_values", key, "같은 항목이 반복되어 대표값을 선택하지 않았습니다."
            )
        if len(items) != 1:
            continue
        raw = items[0]["value_raw"].strip()
        allowed = {
            "method": {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
            "parameter_location": {"query", "body", "path", "header", "cookie", "fragment"},
            "patch_status": {"unknown", "unpatched", "patched"},
        }
        converted = raw.upper() if key == "method" else raw
        if key == "reported_on":
            try:
                converted = date.fromisoformat(raw).isoformat()
            except ValueError:
                converted = None
        elif converted not in allowed[key]:
            converted = None
        if converted is None:
            issue("invalid_field_value", key, "원문 값을 현재 필드 형식으로 확정하지 못했습니다.")
        else:
            setattr(candidate, key, converted)
    paragraphs = [p for cell in table["cells"] for p in cell["paragraphs"]]
    finding.image_refs = list(dict.fromkeys(i for p in paragraphs for i in p["image_ids"]))
    for image_id in finding.image_refs:
        if image_id in transcripts:
            item = transcripts[image_id]
            paragraphs.append(
                {
                    "source_ref": f"image-transcript:{image_id}",
                    "text": item.text,
                    "representation": "image_transcription",
                }
            )
            issue(
                "unreviewed_image_transcript",
                "payload",
                "그림의 별도 전사값은 자동 OCR 결과가 아닙니다.",
                [f"image-transcript:{image_id}"],
            )
        else:
            issue(
                "image_text_not_processed",
                None,
                "그림 참조는 보존했지만 그림 속 문자는 판독하지 않았습니다.",
                [f"image:{image_id}"],
            )
    urls = _urls(paragraphs)
    finding.field_evidence["url_occurrences"] = [
        FieldEvidence(
            value=item["url"],
            source_ref=item["source_ref"],
            method="review_candidate",
        )
        for item in urls
    ]
    relevant_urls = [
        item
        for item in urls
        if item["url"] == candidate.vulnerability_url or CODE_PATTERN.search(unquote(item["url"]))
    ]
    endpoint_paths = {urlsplit(item["url"]).path for item in relevant_urls}
    if candidate.vulnerability_url and len(endpoint_paths) > 1:
        issue(
            "endpoint_ambiguity",
            "vulnerability_url",
            "영향 URL과 내용에 다른 경로가 있어 취약 지점을 자동 확정하지 않았습니다.",
        )
        finding.field_evidence["endpoint"] = [
            FieldEvidence(
                value=urlsplit(item["url"]).path or "/",
                source_ref=item["source_ref"],
                method="review_candidate",
            )
            for item in relevant_urls
        ]
        candidate.vulnerability_url = None
    if candidate.vulnerability_url:
        candidate.endpoint = urlsplit(candidate.vulnerability_url).path or "/"
        finding.field_evidence["endpoint"] = [
            FieldEvidence(
                value=candidate.endpoint,
                source_ref=grouped["vulnerability_url"][0]["source_ref"],
                method="derived",
            )
        ]
    parameters = {key for item in relevant_urls for key, _ in _query(item["url"])}
    if candidate.parameter is None and len(parameters) == 1 and not grouped.get("parameter"):
        candidate.parameter = next(iter(parameters))
        finding.field_evidence["parameter"] = [
            FieldEvidence(
                value=candidate.parameter,
                source_ref=item["source_ref"],
                method="derived",
            )
            for item in relevant_urls
            if any(key == candidate.parameter for key, _ in _query(item["url"]))
        ]
    apply_narrative_analysis(finding, grouped)
    if candidate.parameter in parameters and not grouped.get("parameter_location"):
        candidate.parameter_location = "query"
        finding.field_evidence["parameter_location"] = [
            FieldEvidence(
                value="query",
                source_ref=item["source_ref"],
                method="derived",
            )
            for item in relevant_urls
            if any(key == candidate.parameter for key, _ in _query(item["url"]))
        ]
    if len(parameters) > 1 and candidate.parameter is None:
        issue(
            "parameter_ambiguity",
            "parameter",
            "복수 입력 이름의 원문을 보존하고 자동 선택을 보류했습니다.",
        )
    finding.payload_variants = _payloads(paragraphs, urls, grouped.get("payload", []))
    decoded = {
        v.percent_decoded_value if v.percent_decoded_value is not None else v.value
        for v in finding.payload_variants
    }
    raw_values = {v.value for v in finding.payload_variants}
    if len(decoded) > 1:
        issue(
            "payload_value_difference",
            "payload",
            "payload 표기가 서로 다릅니다. 다른 시험 변형일 수 있어 원문 오류로 단정하지 않습니다.",
        )
    elif len(raw_values) > 1:
        issue(
            "payload_representation_difference",
            "payload",
            "원문 표현은 다르지만 퍼센트 디코딩 비교값은 같습니다. 각 표현을 보존했습니다.",
        )
    if any(re.search(r"[“”‘’]", v.value) for v in finding.payload_variants):
        issue(
            "typographic_quotes", "payload", "곡선 따옴표를 일반 따옴표로 자동 치환하지 않았습니다."
        )
    if (
        len(grouped.get("payload", [])) == 1
        and has_supplied_value(grouped["payload"][0]["value_raw"])
        and len(decoded) == 1
        and not finding.image_refs
        and not any(re.search(r"[“”‘’]", v) for v in raw_values)
    ):
        candidate.payload = grouped["payload"][0]["value_raw"]
    elif finding.payload_variants:
        issue(
            "payload_selection_required",
            "payload",
            "표현별 후보를 보존하고 대표 payload는 미확정으로 남겼습니다.",
        )
    if candidate.vulnerability_type and "," in candidate.vulnerability_type:
        issue(
            "combined_vulnerability_types",
            "vulnerability_type",
            "한 표에 여러 취약점 종류가 기재되어 있습니다. 사례 분리 여부를 확인해야 합니다.",
        )
    if finding.image_refs and not candidate.prior_evidence:
        candidate.prior_evidence = "; ".join(
            f"{table['source_ref']} / image:{i}" for i in finding.image_refs
        )
        finding.field_evidence["prior_evidence"] = [
            FieldEvidence(
                value=f"{table['source_ref']} / image:{image_id}",
                source_ref=f"image:{image_id}",
                method="derived",
            )
            for image_id in finding.image_refs
        ]
    # This is in-memory validation only. Importing/constructing a Case does not open a DB.
    try:
        Case.model_validate(candidate.model_dump())
    except ValidationError as exc:
        finding.case_validation_errors = [
            {"field": ".".join(map(str, err["loc"])), "type": err["type"], "message": err["msg"]}
            for err in exc.errors(include_input=False, include_url=False, include_context=False)
        ]
    refresh_field_status(finding)
    return finding


def refresh_field_status(finding: FindingDraft) -> None:
    """Reclassify missing/candidate evidence, including later OCR evidence."""
    candidate = finding.candidate
    finding.review_issues = [
        item
        for item in finding.review_issues
        if item.code not in {"missing_field", "unresolved_field"}
    ]

    def issue(code, field, message, refs=None):
        finding.review_issues.append(
            ReviewIssue(
                code=code, field=field, message=message, source_refs=refs or [finding.source_ref]
            )
        )

    needed = {name for name, field in Case.model_fields.items() if field.is_required()}
    needed.update(
        {
            "reported_on",
            "vulnerability_url",
            "severity",
            "description",
            "parameter",
            "payload",
            "remediation",
        }
    )
    incomplete = {name for name in needed if not _has_value(getattr(candidate, name))}

    def has_review_evidence(name: str) -> bool:
        evidence = finding.field_evidence.get(name, [])

        def meaningful(value):
            if isinstance(value, str):
                return any(has_supplied_value(line) for line in value.splitlines())
            if isinstance(value, list):
                return any(meaningful(item) for item in value)
            return has_supplied_value(value)

        return any(meaningful(item.value) for item in evidence) or (
            name == "payload" and any(has_supplied_value(v.value) for v in finding.payload_variants)
        )

    finding.unresolved_fields = sorted(name for name in incomplete if has_review_evidence(name))
    finding.missing_fields = sorted(incomplete - set(finding.unresolved_fields))
    missing_reasons = {
        "case_id": "프로그램에서 부여할 사례 ID가 아직 없습니다. 보고서 내용의 누락과 구분합니다.",
        "target_id": "기존 대상과 연결할 관리 ID가 지정되지 않았습니다.",
        "title": "사례 제목으로 명시된 값을 확보하지 못했습니다.",
        "method": "명시적인 HTTP 요청 메서드를 확보하지 못했습니다. URL만으로 확정하지 않습니다.",
        "reported_on": (
            "발견일·점검일로 명시된 값을 확보하지 못했습니다. 문서 작성일로 대체하지 않습니다."
        ),
        "preconditions": (
            "명시적인 사전 조건 값이 없거나 비어 있거나 미기재로 표시되어 있습니다. "
            "조건이 없다고 확정한 것은 아닙니다."
        ),
    }
    for name in finding.missing_fields:
        issue(
            "missing_field",
            name,
            missing_reasons.get(
                name, "확인된 값이나 관리 정보가 없습니다. 근거 없이 채우지 않았습니다."
            ),
            [item.source_ref for item in finding.field_evidence.get(name, [])] or None,
        )
    for name in finding.unresolved_fields:
        evidence = finding.field_evidence.get(name, [])
        refs = list(
            dict.fromkeys(
                [item.source_ref for item in evidence]
                + ([v.source_ref for v in finding.payload_variants] if name == "payload" else [])
            )
        )
        if any(
            i.code == "multiple_field_values" and i.field == name for i in finding.review_issues
        ):
            message = (
                "같은 항목의 값이 반복되어 하나로 확정하지 않았습니다. 각 원문을 대조해야 합니다."
            )
        elif name == "payload":
            message = (
                "payload 표현과 출처를 보존했습니다. "
                "표기 차이와 이미지 전사 여부를 검토한 뒤 대표 값을 선택해야 합니다."
            )
        elif any(item.method == "review_candidate" for item in evidence):
            message = (
                "관련 문단을 후보 근거로 연결했습니다. "
                "문장 의미를 검토하기 전에는 구조화된 값으로 확정하지 않습니다."
            )
        else:
            message = "원문 값은 있지만 현재 필드 형식에 맞는 값을 확정하지 못했습니다."
        issue("unresolved_field", name, message, refs or None)


def parse_hwpx_report(
    path: str | Path,
    *,
    target_id: str | None = None,
    image_transcripts: ImageTranscriptBundle | dict | None = None,
) -> ReportDraft:
    """Preserve source text/tables and build one review draft per vulnerability table."""
    path = Path(path).resolve()
    if target_id is not None:
        target_id = TypeAdapter(Identifier).validate_python(target_id)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("HWPX file exceeds the 32 MB limit")
    body = path.read_bytes()
    if len(body) > MAX_FILE_BYTES:
        raise ValueError("HWPX file exceeds the 32 MB limit")
    source = {
        "path": str(path),
        "filename": path.name,
        "sha256": _sha(body),
        "bytes": len(body),
        "extracted_at": datetime.now(UTC).isoformat(),
    }
    try:
        with ZipFile(BytesIO(body)) as archive:
            entries = archive.infolist()
            if (
                len(entries) > MAX_ENTRIES
                or sum(i.file_size for i in entries) > MAX_UNPACKED_BYTES
                or any(i.file_size > MAX_PART_BYTES for i in entries)
            ):
                raise ValueError("HWPX archive exceeds extraction size limits")
            if len({i.filename for i in entries}) != len(entries):
                raise ValueError("duplicate HWPX archive entries are not supported")
            document = _read_document(archive)
            document["archive_entries"] = [
                {"name": i.filename, "bytes": i.file_size} for i in entries
            ]
    except (BadZipFile, RuntimeError) as exc:
        raise ValueError("input is not a readable HWPX archive") from exc
    bundle = (
        ImageTranscriptBundle.model_validate(image_transcripts)
        if image_transcripts is not None
        else None
    )
    transcripts = {}
    if bundle is not None:
        if bundle.source_sha256 != source["sha256"]:
            raise ValueError("image transcripts refer to a different source SHA-256")
        known = {i["image_id"] for i in document["images"]}
        for item in bundle.items:
            if item.image_id not in known or item.image_id in transcripts:
                raise ValueError("unknown or duplicate image transcript ID")
            transcripts[item.image_id] = item
        for image in document["images"]:
            if image["image_id"] in transcripts:
                image["text_extraction"] = "unreviewed_visual_transcription"
    return build_report_draft(source, document, target_id=target_id, transcripts=transcripts)


def build_report_draft(
    source: dict,
    document: dict,
    *,
    target_id: str | None = None,
    transcripts: dict | None = None,
    schema_version: str = "hwpx-draft-1",
    extractor_version: str = "hwpx-local-6",
) -> ReportDraft:
    """Map preserved tables and explicitly labeled body sections to review drafts."""
    transcripts = transcripts or {}
    findings = []
    issues = []
    for table in document["tables"]:
        fields = _fields(table)
        table["recognized_fields"] = [
            {k: item[k] for k in ("field", "label_raw", "value_raw", "source_ref")}
            for item in fields
        ]
        keys = {item["field"] for item in fields}
        if "vulnerability_type" in keys and keys & {
            "description",
            "vulnerability_url",
            "narrative",
        }:
            findings.append(_finding(table, fields, source, target_id, transcripts))
        else:
            issues.append(
                ReviewIssue(
                    code="unclassified_table",
                    message="미분류 표의 원문도 보존했습니다.",
                    source_refs=[table["source_ref"]],
                )
            )
    document["labeled_sections"] = []
    for block in _labeled_sections(document):
        fields = block["recognized_fields"]
        keys = {item["field"] for item in fields}
        document["labeled_sections"].append(
            {
                "source_ref": block["source_ref"],
                "recognized_fields": [
                    {k: item[k] for k in ("field", "label_raw", "value_raw", "source_ref")}
                    for item in fields
                ],
            }
        )
        if keys & {"description", "vulnerability_url", "narrative"}:
            finding = _finding(block, fields, source, target_id, transcripts)
            finding.review_issues.append(
                ReviewIssue(
                    code="labeled_section_boundary",
                    message="취약점 유형 표기를 기준으로 묶은 문단입니다. 사례 경계를 대조하세요.",
                    source_refs=[block["source_ref"]],
                )
            )
            findings.append(finding)
        else:
            issues.append(
                ReviewIssue(
                    code="unclassified_labeled_section",
                    message="항목 경계가 부족한 문단 묶음을 보존했습니다.",
                    source_refs=[block["source_ref"]],
                )
            )
    if not findings:
        issues.append(
            ReviewIssue(
                code="no_findings",
                message="인식된 취약점 항목이 없습니다. 보존된 원문을 확인하세요.",
            )
        )
    return ReportDraft(
        schema_version=schema_version,
        extractor_version=extractor_version,
        source=source,
        document=document,
        findings=findings,
        review_issues=issues,
        image_transcripts=list(transcripts.values()),
    )
