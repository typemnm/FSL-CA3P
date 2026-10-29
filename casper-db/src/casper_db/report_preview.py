"""Bounded raster previews from the hash-checked local intake, never remote images."""

from __future__ import annotations

import base64
import hashlib
import zlib
from io import BytesIO
from zipfile import BadZipFile, ZipFile


def image_previews(intake, draft_sha):
    try:
        from PIL import Image
    except ImportError:
        return []

    from .local_ocr import _hwp_raster

    with intake._connect() as connection:
        report, source = intake._load(connection, draft_sha)
    previews, used = [], 0
    for image in report.document.get("images", [])[:6]:
        entry = {"image_id": image["image_id"], "available": False}
        try:
            if not image.get("embedded"):
                raise ValueError("external images are not fetched")
            if report.source.get("format") == "hwp":
                raw = _hwp_raster(source["raw"], image)
            else:
                with ZipFile(BytesIO(source["raw"])) as archive:
                    part = archive.getinfo(image["archive_part"])
                    if part.file_size > 2_000_000 - used:
                        raise ValueError("preview size limit")
                    raw = archive.read(part)
                if hashlib.sha256(raw).hexdigest() != image.get("sha256"):
                    raise ValueError("image integrity mismatch")
            if len(raw) > 2_000_000 - used:
                raise ValueError("preview size limit")
            with Image.open(BytesIO(raw)) as picture:
                mime = {
                    "PNG": "image/png",
                    "JPEG": "image/jpeg",
                    "GIF": "image/gif",
                    "WEBP": "image/webp",
                }.get(picture.format)
                if not mime or picture.width * picture.height > 12_000_000:
                    raise ValueError("unsupported preview format or dimensions")
                picture.verify()
            used += len(raw)
            entry.update(available=True, mime=mime, base64=base64.b64encode(raw).decode("ascii"))
        except (
            ValueError,
            OSError,
            KeyError,
            BadZipFile,
            zlib.error,
            Image.DecompressionBombError,
        ):
            entry["reason"] = "미리보기를 제공할 수 없는 이미지입니다. 원본 문서에서 확인하세요."
        previews.append(entry)
    return previews
