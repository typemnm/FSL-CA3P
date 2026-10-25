"""Offline Windows OCR with image/source binding. OCR text is always unreviewed."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import zlib
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal
from zipfile import ZipFile

from pydantic import BaseModel, ConfigDict, Field

from .import_workflow import digest

VERSION = "local-windows-ocr-1"
MAX_IMAGES = 8
MAX_RASTER_BYTES = 16_000_000
MAX_PIXELS = 8_000_000


class OcrModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Box(OcrModel):
    x: float = Field(ge=0)
    y: float = Field(ge=0)
    width: float = Field(gt=0)
    height: float = Field(gt=0)


class Word(OcrModel):
    text: str = Field(max_length=2000)
    box: Box


class Line(OcrModel):
    text: str = Field(max_length=20000)
    words: list[Word] = Field(default_factory=list, max_length=5000)


class Recognition(OcrModel):
    engine: Literal["windows-media-ocr"]
    language: str
    width: int = Field(gt=0, le=10000)
    height: int = Field(gt=0, le=10000)
    text: str = Field(max_length=80000)
    lines: list[Line] = Field(max_length=2000)
    text_angle: float | None = None
    confidence: None = None
    pixel_conversion: str


class OcrImage(OcrModel):
    image_id: str
    archive_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    image_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    status: Literal["recognized", "no_text", "failed", "unsupported", "limit_exceeded"]
    recognition: Recognition | None = None
    error: str | None = None


class OcrBundle(OcrModel):
    schema_version: Literal["local-ocr-1"] = "local-ocr-1"
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    version: Literal["local-windows-ocr-1"] = VERSION
    language: str
    images: list[OcrImage]
    review_status: Literal["unreviewed"] = "unreviewed"


def run_windows_worker(asset: str, request: dict, *, timeout=25):
    """Only a bundled script is run; document text never becomes shell code."""
    if os.name != "nt":
        raise ValueError("Windows local OCR is unavailable on this platform")
    executable = Path(os.environ.get("WINDIR", "C:/Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    script = Path(__file__).parent / "ocr_assets" / asset
    if asset != "windows_ocr.ps1":
        raise ValueError("unknown bundled OCR worker")
    try:
        result = subprocess.run(
            [
                str(executable),
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
            ],
            input=json.dumps(request, ensure_ascii=False),
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("local OCR worker exceeded its time limit") from exc
    if len(result.stdout) > 4_000_000:
        raise ValueError("local OCR output exceeds limits")
    try:
        output = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise ValueError("local OCR worker returned invalid output") from exc
    if not isinstance(output, dict):
        raise ValueError("local OCR worker returned a non-object result")
    if result.returncode:
        raise ValueError(str(output.get("message", "local OCR failed"))[:500])
    return output


def windows_ocr_status():
    return run_windows_worker("windows_ocr.ps1", {"action": "status"})


def recognize_raster(raw: bytes, *, language="ko") -> Recognition:
    if not 0 < len(raw) <= MAX_RASTER_BYTES:
        raise ValueError("raster bytes exceed OCR limits")
    with TemporaryDirectory(prefix="casper-ocr-") as temporary:
        path = Path(temporary) / "image.bin"
        path.write_bytes(raw)
        output = run_windows_worker(
            "windows_ocr.ps1", {"action": "recognize", "path": str(path), "language": language}
        )
    return validate_recognition(output)


def validate_recognition(output):
    recognition = Recognition.model_validate(output)
    if recognition.width * recognition.height > MAX_PIXELS:
        raise ValueError("raster pixel count exceeds OCR limits")
    if bool(recognition.text.strip()) != any(line.text.strip() for line in recognition.lines):
        raise ValueError("OCR raw text and line results disagree")
    for line in recognition.lines:
        for word in line.words:
            box = word.box
            if (
                box.x + box.width > recognition.width + 1
                or box.y + box.height > recognition.height + 1
            ):
                raise ValueError("OCR bounding box is outside the image")
    return recognition


def _is_raster(raw):
    return raw.startswith(
        (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF8", b"BM", b"II*\x00", b"MM\x00*")
    ) or (raw.startswith(b"RIFF") and raw[8:12] == b"WEBP")


def _hwp_raster(source, image):
    import olefile

    with olefile.OleFileIO(BytesIO(source)) as archive:
        part = image["archive_part"]
        if not part.startswith("BinData/") or ".." in part.split("/"):
            raise ValueError("unsupported HWP image reference")
        if archive.get_size(part) > MAX_RASTER_BYTES:
            raise ValueError("HWP image stream exceeds limits")
        raw = archive.openstream(part).read(MAX_RASTER_BYTES + 1)
    if hashlib.sha256(raw).hexdigest() != image.get("sha256"):
        raise ValueError("HWP image stream hash mismatch")
    if _is_raster(raw):
        return raw
    decoder = zlib.decompressobj(-15)
    decoded = decoder.decompress(raw, MAX_RASTER_BYTES + 1)
    if (
        len(decoded) > MAX_RASTER_BYTES
        or decoder.unconsumed_tail
        or not decoder.eof
        or decoder.unused_data
    ):
        raise ValueError("compressed HWP image exceeds limits or is incomplete")
    return decoded


def extract_local_ocr(source: Path, report, *, language="ko", recognizer=None) -> OcrBundle:
    """Extract embedded raster pixels from the hash-matched source document."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z-]{0,30}", language):
        raise ValueError("invalid OCR language tag")
    raw = Path(source).read_bytes()
    if hashlib.sha256(raw).hexdigest() != report.source["sha256"]:
        raise ValueError("OCR input source does not match draft SHA-256")
    images = report.document["images"]
    ids = [image["image_id"] for image in images]
    if any(not image_id for image_id in ids) or len(ids) != len(set(ids)):
        raise ValueError("OCR requires unique image IDs")
    recognizer = recognizer or recognize_raster
    results, used = [], 0
    for image in images:
        item = {"image_id": image["image_id"], "archive_sha256": image.get("sha256")}
        if not image.get("embedded") or not (image.get("media_type") or "").startswith("image/"):
            results.append(OcrImage(**item, status="unsupported", error="image is not embedded"))
            continue
        if used >= MAX_IMAGES:
            results.append(OcrImage(**item, status="limit_exceeded", error="OCR image count limit"))
            continue
        used += 1
        try:
            if report.source.get("format") == "hwp":
                raster = _hwp_raster(raw, image)
            else:
                with ZipFile(BytesIO(raw)) as archive:
                    entry = archive.getinfo(image["archive_part"])
                    if entry.file_size > MAX_RASTER_BYTES:
                        raise ValueError("HWPX image exceeds OCR size limit")
                    raster = archive.read(entry)
                if hashlib.sha256(raster).hexdigest() != image.get("sha256"):
                    raise ValueError("image bytes do not match the declared SHA-256")
            if not _is_raster(raster):
                results.append(
                    OcrImage(**item, status="unsupported", error="unsupported raster format")
                )
                continue
            image_sha = hashlib.sha256(raster).hexdigest()
            recognition = recognizer(raster, language=language)
            recognition = validate_recognition(recognition)
            results.append(
                OcrImage(
                    **item,
                    image_sha256=image_sha,
                    status="recognized" if recognition.text.strip() else "no_text",
                    recognition=recognition,
                )
            )
        except (ValueError, OSError, KeyError, zlib.error) as exc:
            results.append(OcrImage(**item, status="failed", error=str(exc)[:500]))
    return OcrBundle(source_sha256=report.source["sha256"], language=language, images=results)


def ocr_fingerprint(bundle: OcrBundle):
    raw = bundle.model_dump(mode="json")
    for image in raw["images"]:
        image.pop("error", None)  # Temporary worker paths are not extraction identities.
    return digest(raw)
