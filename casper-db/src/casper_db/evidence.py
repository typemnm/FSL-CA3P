"""Inspect local evidence files. Hashes record bytes, not vulnerability correctness."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath

from .models import EvidenceMetadata


def inspect_evidence(root: Path | None, references: list[str]) -> list[EvidenceMetadata]:
    if root is None:
        raise ValueError("configure evidence_root before reviewing evidence")
    resolved_root = root.resolve(strict=True)
    if not resolved_root.is_dir():
        raise ValueError("evidence_root must be a directory")
    if not references or len(set(references)) != len(references):
        raise ValueError("evidence references must be non-empty and unique")
    result = []
    for reference in references:
        relative = PurePosixPath(reference)
        if (
            relative.is_absolute()
            or "\\" in reference
            or ":" in reference
            or ".." in relative.parts
            or relative.as_posix() != reference
        ):
            raise ValueError("evidence references must be relative paths inside evidence_root")
        path = resolved_root.joinpath(*relative.parts).resolve(strict=True)
        if not path.is_relative_to(resolved_root) or not path.is_file():
            raise ValueError("evidence must be a file inside evidence_root")
        digest = hashlib.sha256()
        with path.open("rb") as artifact:
            before = os.fstat(artifact.fileno())
            while chunk := artifact.read(1024 * 1024):
                digest.update(chunk)
            after = os.fstat(artifact.fileno())
        current = path.stat()
        def signature(stat):
            return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns

        if signature(before) != signature(after) or signature(after) != signature(current):
            raise ValueError("evidence changed while its hash was being calculated")
        result.append(EvidenceMetadata(
            reference=reference, sha256=digest.hexdigest(), size_bytes=after.st_size
        ))
    return result
