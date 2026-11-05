"""Read-only HWP v5 adapter; preserves binary-source provenance and reader XML."""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from xml.etree import ElementTree as ET

from pydantic import TypeAdapter

from .hwpx import MAX_FILE_BYTES, _xml, build_report_draft, parse_hwpx_report
from .models import Identifier


def _reader_xml(source: Path):
    with TemporaryDirectory(prefix="casper-hwp-") as temporary:
        directory = Path(temporary)
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            filter(None, (str(Path(__file__).resolve().parents[1]), environment.get("PYTHONPATH")))
        )
        try:
            process = subprocess.run(
                [sys.executable, "-m", "casper_db.hwp_worker", str(source), str(directory)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=45,
                check=False,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValueError(
                "HWP 추출 시간이 45초를 넘었습니다. 기존 검토 기록은 유지됩니다."
            ) from exc
        if process.returncode:
            error = directory / "error.json"
            message = (
                json.loads(error.read_text(encoding="utf-8"))["error"]
                if error.exists()
                else ("HWP reader failed before completing the document")
            )
            raise ValueError(message)
        return (directory / "reader.xml").read_bytes(), json.loads(
            (directory / "metadata.json").read_text(encoding="utf-8")
        )


def _paragraph_text(paragraph):
    pieces = []

    def walk(node):
        if node is not paragraph and node.tag in {"Paragraph", "TableControl"}:
            return
        if node.tag == "Text":
            pieces.append(node.text or "")
        elif node.tag == "ControlChar":
            name = node.get("name", "")
            if name in {"LINE_BREAK", "TAB"}:
                pieces.append("\n" if name == "LINE_BREAK" else "\t")
        for child in node:
            walk(child)

    walk(paragraph)
    return "".join(pieces)


def _read_document(xml: bytes, metadata: dict):
    root = _xml(xml)
    if root.tag != "HwpDoc":
        raise ValueError("unexpected HWP reader XML root")
    streams = {item["path"]: item for item in metadata["streams"]}
    images = []
    for index, binary in enumerate(root.findall("./DocInfo//BinData"), 1):
        embedding = binary.find("BinDataEmbedding")
        if embedding is None:
            images.append(
                {
                    "image_id": f"image{index}",
                    "archive_part": None,
                    "embedded": False,
                    "media_type": None,
                    "text_extraction": "not_processed",
                }
            )
            continue
        part = f"BinData/{embedding.get('storage-id')}.{embedding.get('ext')}"
        images.append(
            {
                "image_id": f"image{index}",
                "archive_part": part,
                "embedded": part in streams,
                "media_type": mimetypes.guess_type(part)[0],
                "sha256": streams.get(part, {}).get("sha256"),
                "sha256_scope": "raw_ole_stream",
                "text_extraction": "not_processed",
            }
        )
    sections, tables = [], []
    for section_index, section in enumerate(root.findall("./BodyText/SectionDef")):
        part = f"BodyText/Section{int(section.get('section-id', section_index))}"
        parents = {child: node for node in section.iter() for child in node}
        order = {node: index for index, node in enumerate(section.iter())}

        def nearest(node, tag, parents=parents):
            ancestor = parents.get(node)
            while ancestor is not None and ancestor.tag != tag:
                ancestor = parents.get(ancestor)
            return ancestor

        paragraphs = {}
        for index, node in enumerate(section.iter("Paragraph"), 1):
            paragraphs[node] = {
                "source_ref": f"{part}#p{index}",
                "text": _paragraph_text(node),
                "in_table": nearest(node, "TableControl") is not None,
                "order": order[node],
                "image_ids": list(
                    dict.fromkeys(
                        f"image{info.get('bindata-id')}" for info in node.iter("PictureInfo")
                    )
                ),
                "controls": [
                    {"type": child.tag, "attributes": dict(child.attrib)}
                    for child in node.iter()
                    if child.tag.startswith("Field")
                ],
            }
        for index, table in enumerate(section.iter("TableControl"), 1):
            ref = f"{part}#table{index}"
            cells = []
            for cell in table.iter("TableCell"):
                if nearest(cell, "TableControl") is not table:
                    continue
                row, column = int(cell.get("row", 0)) + 1, int(cell.get("col", 0)) + 1
                contents = [
                    value
                    for node, value in paragraphs.items()
                    if nearest(node, "TableCell") is cell
                ]
                cells.append(
                    {
                        "source_ref": f"{ref}/r{row}c{column}",
                        "row": row,
                        "column": column,
                        "row_span": int(cell.get("rowspan", 1)),
                        "column_span": int(cell.get("colspan", 1)),
                        "paragraphs": contents,
                        "text": "\n".join(p["text"] for p in contents),
                    }
                )
            preceding = [
                p
                for p in paragraphs.values()
                if not p["in_table"] and p["text"].strip() and p["order"] < order[table]
            ]
            tables.append(
                {
                    "source_ref": ref,
                    "section": part,
                    "table_index": index,
                    "table_id": table.get("table-id"),
                    "cells": cells,
                    "preceding_paragraph": preceding[-1] if preceding else None,
                }
            )
        sections.append({"archive_part": part, "paragraphs": list(paragraphs.values())})
    if not sections:
        raise ValueError("HWP reader returned no body sections; incomplete extraction refused")
    return {
        "metadata": [
            {"tag": "HwpSummaryInfo", "xml": ET.tostring(node, encoding="unicode")}
            for node in root.findall("HwpSummaryInfo")
        ],
        "sections": sections,
        "tables": tables,
        "images": images,
        "archive_entries": metadata["streams"],
        "reader_xml": xml.decode("utf-8"),
        "reader_note": (
            "pyhwp structured XML; original layout and binary assets remain in source HWP"
        ),
    }


def parse_hwp_report(path: str | Path, *, target_id: str | None = None):
    path = Path(path).resolve(strict=True)
    if target_id is not None:
        target_id = TypeAdapter(Identifier).validate_python(target_id)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("HWP file exceeds the 32 MB limit")
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES or not raw.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        raise ValueError("input must be a binary HWP v5 OLE document")
    source = {
        "path": str(path),
        "filename": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "extracted_at": datetime.now(UTC).isoformat(),
        "format": "hwp",
    }
    xml, metadata = _reader_xml(path)
    if hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]:
        raise ValueError("HWP source changed while extracting; retry with a stable file")
    source.update(hwp_version=metadata["version"], reader="pyhwp 0.1b15")
    document = _read_document(xml, metadata)
    return build_report_draft(
        source,
        document,
        target_id=target_id,
        schema_version="report-draft-1",
        extractor_version="hwp5-local-5",
    )


def parse_report(
    path: str | Path,
    *,
    target_id=None,
    image_transcripts=None,
    source_kind="imported",
    local_ocr=False,
    ocr_language="ko",
    local_llm=False,
):
    """Read a local report and retain its explicitly assigned provenance."""
    if source_kind not in {"imported", "synthetic"}:
        raise ValueError("source_kind must be imported or synthetic")
    suffix = Path(path).suffix.lower()
    if suffix == ".hwpx":
        report = parse_hwpx_report(path, target_id=target_id, image_transcripts=image_transcripts)
    elif suffix == ".hwp":
        if image_transcripts is not None:
            raise ValueError(
                "HWP용 이미지 전사 연결은 아직 지원하지 않습니다. 원본에서 별도 대조하세요."
            )
        report = parse_hwp_report(path, target_id=target_id)
    else:
        raise ValueError("HWP 또는 HWPX 보고서를 선택하세요.")
    # Do not alter existing imported drafts or their review hashes.
    if source_kind == "synthetic":
        report.source["record_source"] = "synthetic"
        for finding in report.findings:
            finding.candidate.source = "synthetic"
    if local_ocr:
        from .local_ocr import extract_local_ocr
        from .ocr_review import apply_ocr_evidence

        bundle = extract_local_ocr(Path(path), report, language=ocr_language)
        report = apply_ocr_evidence(report, bundle)
    if local_llm:
        from .report_semantic import enrich_report

        report = enrich_report(Path(path), report)
    return report
