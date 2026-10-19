"""Normalize an LLM-proposed report file name (PLAN 3.8). Pure: never touches the filesystem."""

from __future__ import annotations

import re
import unicodedata

MAX_LENGTH = 120
EXTENSION = ".hwpx"
RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10))}
UNSAFE = re.compile(r'[\x00-\x1f\x7f/\\:*?"<>|]')


def normalize_filename(proposed: str | None, run_id: str) -> str:
    fallback = f"{run_id}{EXTENSION}"
    if not isinstance(proposed, str):
        return fallback
    name = UNSAFE.sub("", unicodedata.normalize("NFC", proposed))
    while ".." in name:
        name = name.replace("..", "")
    stem = name.strip()
    while stem.lower().endswith(EXTENSION):
        stem = stem[: -len(EXTENSION)]
    # Windows drops trailing dots/spaces, and a leading dot would hide the file.
    stem = stem.strip(". ")[: MAX_LENGTH - len(EXTENSION)].rstrip(". ")
    if not stem or stem.split(".")[0].strip().upper() in RESERVED:
        return fallback
    return stem + EXTENSION
