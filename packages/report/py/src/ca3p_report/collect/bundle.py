"""Write a ReportInput bundle: collected files plus a manifest of hashes and collector status.

The bundle is the report core's only input. It records which kind of source each collector
read, never where that source lives. Files are staged in a private sibling directory and the
bundle appears under its final name only once sealed, so a failed collection leaves nothing.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import uuid
from pathlib import Path

SCHEMA_VERSION = "report-input-1.0"
RUN_SCHEMA = "report-input-run-1.0"
EVENTS_SCHEMA = "report-input-events-1.0"
HISTORY_SCHEMA = "report-input-history-1.0"


class BundleExistsError(FileExistsError):
    """The target bundle directory already holds files; bundles are write-once."""


class OutputError(OSError):
    """The output location cannot be written."""


def _bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


class BundleWriter:
    def __init__(self, root: Path):
        self.root = root
        self._refuse_existing()
        try:
            root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.staging = root.parent / f".{root.name}.{uuid.uuid4().hex}.partial"
            self.staging.mkdir(mode=0o700)
        except OSError as exc:
            raise OutputError("output directory cannot be written") from exc
        self.files: list[dict] = []

    def _refuse_existing(self) -> None:
        # Only a real, empty directory may be replaced; links are never followed.
        if self.root.is_symlink():
            raise BundleExistsError("bundle path is a symbolic link")
        try:
            occupied = self.root.exists() and (
                not self.root.is_dir() or any(True for _ in self.root.iterdir())
            )
        except OSError as exc:
            raise OutputError("output directory cannot be read") from exc
        if occupied:
            raise BundleExistsError("bundle directory already exists and is not empty")

    def add_json(self, relative: str, role: str, value: object) -> None:
        data = _bytes(value)
        try:
            _write_exclusive(self.staging / relative, data)
        except OSError as exc:
            raise OutputError("bundle file cannot be written") from exc
        self.files.append(
            {
                "path": relative,
                "role": role,
                "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "mediaType": "application/json",
            }
        )

    def seal(self, *, run_id: str, collected_at: str, collectors: list[dict]) -> dict:
        manifest = {
            "schemaVersion": SCHEMA_VERSION,
            "runId": run_id,
            "collectedAt": collected_at,
            "collectors": collectors,
            "files": sorted(self.files, key=lambda item: item["path"]),
        }
        try:
            _write_exclusive(self.staging / "manifest.json", _bytes(manifest))
        except OSError as exc:
            raise OutputError("bundle manifest cannot be written") from exc
        # Re-check: another collector may have sealed the same bundle in the meantime.
        self._refuse_existing()
        try:
            if self.root.exists():
                self.root.rmdir()  # Only an empty directory reaches here.
            os.rename(self.staging, self.root)
        except OSError as exc:
            if exc.errno in (errno.ENOTEMPTY, errno.EEXIST, errno.ENOTDIR):
                raise BundleExistsError("bundle directory was created concurrently") from exc
            raise OutputError("bundle cannot be moved into place") from exc
        return manifest

    def discard(self) -> None:
        if self.staging.exists():
            shutil.rmtree(self.staging, ignore_errors=True)
