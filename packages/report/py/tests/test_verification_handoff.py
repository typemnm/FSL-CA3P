from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from ca3p_report.collect.verification import (
    VerificationHandoffError,
    copy_handoff_images,
    load_verification_handoff,
)

PNG = b"\x89PNG\r\n\x1a\nfake-image-bytes"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _handoff(directory: Path, **overrides) -> Path:
    images_dir = directory / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    (images_dir / "shot.png").write_bytes(PNG)
    document = {
        "schemaVersion": "verification-handoff/1",
        "result": {"status": "confirmed"},
        "images": [{"file": "shot.png", "sha256": _digest(PNG), "bytes": len(PNG), "label": "XSS"}],
    }
    document.update(overrides)
    (directory / "verification.json").write_text(json.dumps(document), encoding="utf-8")
    return directory


def _with_image(entry: dict, directory: Path) -> Path:
    return _handoff(directory, images=[entry])


def test_valid_handoff_round_trip(tmp_path: Path):
    directory = _handoff(tmp_path / "handoff")

    handoff = load_verification_handoff(directory)
    assert handoff["result"] == {"status": "confirmed"}
    assert handoff["images"] == [
        {
            "path": directory / "images" / "shot.png",
            "sha256": _digest(PNG),
            "bytes": len(PNG),
            "label": "XSS",
        }
    ]

    bundle = tmp_path / "bundle"
    assert copy_handoff_images(handoff, bundle) == ["evidence/images/shot.png"]
    assert (bundle / "evidence" / "images" / "shot.png").read_bytes() == PNG


def test_tampered_sha_is_rejected(tmp_path: Path):
    directory = _handoff(tmp_path / "handoff")
    (directory / "images" / "shot.png").write_bytes(PNG + b"tampered")

    with pytest.raises(VerificationHandoffError, match="sha256"):
        load_verification_handoff(directory)


def test_parent_directory_path_is_rejected(tmp_path: Path):
    directory = _handoff(tmp_path / "handoff")
    (directory / "secret.png").write_bytes(PNG)
    entry = {"file": "../secret.png", "sha256": _digest(PNG), "bytes": len(PNG), "label": ""}

    with pytest.raises(VerificationHandoffError, match="escapes"):
        load_verification_handoff(_with_image(entry, directory))


def test_absolute_path_is_rejected(tmp_path: Path):
    directory = _handoff(tmp_path / "handoff")
    outside = tmp_path / "outside.png"
    outside.write_bytes(PNG)
    entry = {"file": str(outside), "sha256": _digest(PNG), "bytes": len(PNG), "label": ""}

    with pytest.raises(VerificationHandoffError, match="escapes"):
        load_verification_handoff(_with_image(entry, directory))


def test_missing_file_is_rejected(tmp_path: Path):
    directory = _handoff(tmp_path / "handoff")
    (directory / "images" / "shot.png").unlink()

    with pytest.raises(VerificationHandoffError, match="missing"):
        load_verification_handoff(directory)


def test_wrong_schema_version_is_rejected(tmp_path: Path):
    directory = _handoff(tmp_path / "handoff", schemaVersion="verification-handoff/2")

    with pytest.raises(VerificationHandoffError, match="schema"):
        load_verification_handoff(directory)


def test_bad_status_is_rejected(tmp_path: Path):
    directory = _handoff(tmp_path / "handoff", result={"status": "maybe"})

    with pytest.raises(VerificationHandoffError, match="status"):
        load_verification_handoff(directory)


def test_copy_refuses_to_overwrite(tmp_path: Path):
    handoff = load_verification_handoff(_handoff(tmp_path / "handoff"))
    bundle = tmp_path / "bundle"
    copy_handoff_images(handoff, bundle)

    with pytest.raises(VerificationHandoffError, match="already exists"):
        copy_handoff_images(handoff, bundle)


def test_this_worktree_package_is_imported():
    import ca3p_report

    assert "packages/report/py/src" in str(Path(ca3p_report.__file__).resolve())
