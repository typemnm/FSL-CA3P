"""Offline Tesseract CLI backend. No shell, network, model download, or GUI."""

from __future__ import annotations

import csv
import hashlib
import os
import re
import shutil
import subprocess
import sys
from importlib.util import find_spec
from io import BytesIO, StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

BACKEND_VERSION = "local-tesseract-ocr-1"
MAX_OUTPUT_BYTES = 4_000_000
MAX_PIXELS = 8_000_000
MAX_RASTER_BYTES = 16_000_000
TSV_COLUMNS = {
    "level", "page_num", "block_num", "par_num", "line_num", "word_num",
    "left", "top", "width", "height", "conf", "text",
}


def _sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def language_codes(language):
    if not isinstance(language, str) or len(language) > 40:
        raise ValueError("invalid OCR language")
    aliases = {"ko": "kor+eng", "ko-kr": "kor+eng", "kor": "kor+eng",
               "en": "eng", "en-us": "eng"}
    value = aliases.get(language.lower(), language.lower())
    if not re.fullmatch(r"[a-z]{3}(?:_vert)?(?:\+[a-z]{3}(?:_vert)?){0,4}", value):
        raise ValueError("use ko, en, or Tesseract language codes such as kor+eng")
    return list(dict.fromkeys(value.split("+")))


def _executable():
    configured = os.environ.get("CASPER_DB_TESSERACT")
    candidate = shutil.which(configured or "tesseract")
    # launchd services need not inherit Homebrew's interactive-shell PATH.
    if not candidate and not configured and sys.platform == "darwin":
        candidate = next((str(path) for path in (
            Path("/opt/homebrew/bin/tesseract"), Path("/usr/local/bin/tesseract"),
        ) if path.is_file() and os.access(path, os.X_OK)), None)
    if not candidate:
        raise ValueError(
            "Tesseract was not found. Install it and its language data, then set PATH "
            "or CASPER_DB_TESSERACT to the executable path. See MAC_MINI_SETUP.ko.md."
        )
    return str(Path(candidate).resolve(strict=True))


def _data_arguments():
    configured = os.environ.get("CASPER_DB_TESSDATA_DIR")
    if not configured:
        return []
    path = Path(configured).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise ValueError("CASPER_DB_TESSDATA_DIR must point to a tessdata directory")
    return ["--tessdata-dir", str(path)]


def _process(arguments, *, timeout=25, capture=True):
    try:
        result = subprocess.run(
            arguments, shell=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
            env={**os.environ, "OMP_THREAD_LIMIT": "1"},
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("Tesseract exceeded its time limit") from exc
    except OSError as exc:
        raise ValueError("Tesseract could not be started") from exc
    if result.returncode:
        # Temporary paths and image contents do not belong in persistent diagnostics.
        raise ValueError(f"Tesseract failed with exit code {result.returncode}")
    if capture and len(result.stdout) > MAX_OUTPUT_BYTES:
        raise ValueError("Tesseract status output exceeds limits")
    return result.stdout.decode("utf-8", errors="strict") if capture else ""


def runtime_profile(language="ko"):
    requested = language_codes(language)
    executable = _executable()
    engine_version = _process([executable, "--version"]).splitlines()[0]
    if not engine_version.lower().startswith("tesseract "):
        raise ValueError("configured executable did not identify itself as Tesseract")
    arguments = _data_arguments()
    output = _process([executable, "--list-langs", *arguments])
    available = [line.strip() for line in output.splitlines()
                 if re.fullmatch(r"[A-Za-z0-9_/.-]+", line.strip())]
    missing = sorted(set(requested) - set(available))
    if missing:
        raise ValueError("Tesseract language data is missing: " + ", ".join(missing))
    match = re.search(r'List of available languages in "([^"]+)"', output)
    directory = Path(arguments[1]) if arguments else Path(match[1]) if match else None
    if directory is None or not directory.is_dir():
        raise ValueError("cannot locate model files; set CASPER_DB_TESSDATA_DIR explicitly")
    models = {code: directory / f"{code}.traineddata" for code in requested}
    if any(not path.is_file() for path in models.values()):
        raise ValueError("listed Tesseract model files could not be verified")
    return {
        "engine": "tesseract", "engine_version": engine_version,
        "executable": executable, "executable_sha256": _sha(executable),
        "tessdata_directory": str(directory.resolve()), "available_languages": available,
        "language_codes": requested, "traineddata_sha256": {
            code: _sha(path) for code, path in models.items()
        }, "page_segmentation": 3, "backend_version": BACKEND_VERSION,
    }


def cache_identity(language="ko"):
    profile = runtime_profile(language)
    return {key: profile[key] for key in (
        "engine", "engine_version", "executable_sha256", "language_codes",
        "traineddata_sha256", "page_segmentation", "backend_version",
    )}


def ocr_status(language="ko"):
    try:
        profile = runtime_profile(language)
        pillow_available = find_spec("PIL") is not None
        return {"available": pillow_available, **profile, "pillow_available": pillow_available,
                "offline": True, "confidence_supported": False,
                "reason": None if pillow_available else 'Install the Python extra: ".[ocr]"'}
    except (ValueError, OSError, UnicodeError) as exc:
        return {"available": False, "engine": "tesseract", "offline": True,
                "reason": str(exc), "requested_language": language}


def parse_tsv(tsv, raw_text, *, width, height):
    reader = csv.DictReader(StringIO(tsv), delimiter="\t", quoting=csv.QUOTE_NONE)
    if set(reader.fieldnames or []) != TSV_COLUMNS:
        raise ValueError("invalid Tesseract TSV columns")
    groups = {}
    page_seen = False
    for row in reader:
        if None in row or any(value is None for value in row.values()):
            raise ValueError("malformed Tesseract TSV row")
        level = int(row["level"])
        if level == 1:
            if page_seen or int(row["width"]) != width or int(row["height"]) != height:
                raise ValueError("Tesseract page dimensions do not match the original image")
            page_seen = True
        if level != 5 or not row["text"].strip():
            continue
        if int(row["page_num"]) != 1:
            raise ValueError("only a single raster page may be recognized")
        key = tuple(int(row[name]) for name in ("page_num", "block_num", "par_num", "line_num"))
        groups.setdefault(key, []).append({
            "text": row["text"], "box": {
                "x": int(row["left"]), "y": int(row["top"]),
                "width": int(row["width"]), "height": int(row["height"]),
            },
        })
    if not page_seen:
        raise ValueError("Tesseract TSV has no image page")
    lines = [{"text": " ".join(word["text"] for word in words), "words": words}
             for words in groups.values()]
    plain_lines = [line for line in raw_text.splitlines() if line.strip()]
    if len(plain_lines) == len(lines):
        for line, plain in zip(lines, plain_lines, strict=True):
            if re.sub(r"\s", "", plain) == re.sub(r"\s", "", line["text"]):
                line["text"] = plain
    return lines


def recognize_raster(raw, *, language="ko"):
    if not 0 < len(raw) <= MAX_RASTER_BYTES:
        raise ValueError("raster bytes exceed OCR limits")
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError as exc:
        raise ValueError('OCR requires Pillow: install the Python extra ".[ocr]"') from exc
    profile = runtime_profile(language)
    with TemporaryDirectory(prefix="casper-ocr-") as temporary:
        folder = Path(temporary)
        raster, base = folder / "image.png", folder / "result"
        try:
            with Image.open(BytesIO(raw)) as image:
                width, height = image.size
                if (width <= 0 or height <= 0 or width > 10000 or height > 10000
                        or width * height > MAX_PIXELS):
                    raise ValueError("raster pixel count exceeds OCR limits")
                if getattr(image, "n_frames", 1) != 1:
                    raise ValueError("multi-frame images need explicit page selection")
                # Conversion preserves original dimensions; no rotation, resize, or correction.
                with image.convert("RGB") as decoded:
                    decoded.save(raster, format="PNG")
        except (UnidentifiedImageError, Image.DecompressionBombError, OSError) as exc:
            raise ValueError("cannot decode the embedded raster safely") from exc
        _process([
            profile["executable"], str(raster), str(base), "--tessdata-dir",
            profile["tessdata_directory"], "-l", "+".join(profile["language_codes"]),
            "--psm", str(profile["page_segmentation"]), "tsv", "txt",
        ], capture=False)
        outputs = []
        for suffix in (".tsv", ".txt"):
            path = base.with_suffix(suffix)
            if not path.is_file() or path.stat().st_size > MAX_OUTPUT_BYTES:
                raise ValueError("Tesseract output is missing or exceeds limits")
            outputs.append(path.read_text(encoding="utf-8"))
        tsv, text = outputs
        return {
            "engine": "tesseract", "engine_version": profile["engine_version"],
            "traineddata_sha256": profile["traineddata_sha256"],
            "configuration": {"page_segmentation": profile["page_segmentation"],
                              "backend_version": BACKEND_VERSION,
                              "line_text": "plain text when token-aligned, otherwise TSV"},
            "raw_tsv": tsv, "language": "+".join(profile["language_codes"]),
            "width": width, "height": height, "text": text,
            "lines": parse_tsv(tsv, text, width=width, height=height),
            "text_angle": None, "confidence": None,
            "pixel_conversion": "RGB; original dimensions and original source bytes preserved",
        }
