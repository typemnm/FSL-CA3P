"""Read the verifier's verification-handoff/1 directory and copy its images into a report bundle.

The handoff is untrusted input: every image is checked against its declared sha256 and size
before any of it is read into the bundle.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

SCHEMA_VERSION = "verification-handoff/1"
STATUSES = {"confirmed", "not_reproduced", "inconclusive"}
MAX_IMAGE_BYTES = 5 * 1024 * 1024


class VerificationHandoffError(ValueError):
    """The verification handoff is missing, malformed or fails its integrity checks."""


def _image_path(directory: Path, name: object) -> Path:
    if not isinstance(name, str) or not name:
        raise VerificationHandoffError("image file must be a non-empty string")
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("images",):
        raise VerificationHandoffError("image file escapes images/")
    images = directory / "images"
    candidate = directory / relative
    if candidate.is_symlink() or not candidate.is_file():
        raise VerificationHandoffError("image file is missing or a symbolic link")
    if not candidate.resolve().is_relative_to(images.resolve()):
        raise VerificationHandoffError("image file escapes images/")
    return candidate


def _image(directory: Path, entry: object) -> dict:
    if not isinstance(entry, dict):
        raise VerificationHandoffError("image entry must be an object")
    path = _image_path(directory, entry.get("file"))
    size = path.stat().st_size
    if size > MAX_IMAGE_BYTES:
        raise VerificationHandoffError("image exceeds 5 MiB")
    data = path.read_bytes()
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if entry.get("sha256") != digest:
        raise VerificationHandoffError("image sha256 does not match")
    label = entry.get("label", "")
    if not isinstance(label, str):
        raise VerificationHandoffError("image label must be a string")
    return {"path": path, "sha256": digest, "bytes": size, "label": label}


def load_verification_handoff(directory: Path) -> dict:
    try:
        document = json.loads((directory / "verification.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationHandoffError("verification.json cannot be read") from exc
    if not isinstance(document, dict) or document.get("schemaVersion") != SCHEMA_VERSION:
        raise VerificationHandoffError("unsupported verification handoff schema")
    result = document.get("result")
    if not isinstance(result, dict) or result.get("status") not in STATUSES:
        raise VerificationHandoffError("verification result status is invalid")
    images = document.get("images")
    if not isinstance(images, list):
        raise VerificationHandoffError("images must be a list")
    return {"result": result, "images": [_image(directory, entry) for entry in images]}


def copy_handoff_images(handoff: dict, bundle_dir: Path) -> list[str]:
    target_dir = bundle_dir / "evidence" / "images"
    target_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for image in handoff["images"]:
        target = target_dir / image["path"].name
        try:
            with image["path"].open("rb") as source, target.open("xb") as destination:
                shutil.copyfileobj(source, destination)
        except FileExistsError as exc:
            raise VerificationHandoffError(f"evidence image already exists: {target.name}") from exc
        copied.append(target.relative_to(bundle_dir).as_posix())
    return copied
