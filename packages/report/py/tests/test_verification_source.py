"""A verifier handoff directory is a sealed report source; its images and attack reach the HWPX."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from ca3p_report.collect.bundle import BundleWriter, OutputError
from ca3p_report.collect.collector import collect
from ca3p_report.collect.model import CollectError
from ca3p_report.llm.tools import ReportTools
from ca3p_report.trigger import TriggerError, parse_trigger
from test_general_report import _report, _store, _trigger, llm_model
from test_hwpx_writer import png

IMAGE = png()
DIGEST = "sha256:" + hashlib.sha256(IMAGE).hexdigest()
REASON = "교차 사용자 삭제 응답이 확인됨"


ATTACK = {"kind": "http", "request": {"method": "DELETE", "url": "http://127.0.0.1:40123/api/posts/1",
                                     "headers": {"cookie": "[redacted]"}},
          "response": {"status": 200, "bodyJson": {"deleted": True}}}


def _handoff(directory: Path, *, attack_id: str = "p-a", schema: str = "verification-handoff/1",
             attack: dict | None = None) -> Path:
    (directory / "images").mkdir(parents=True)
    (directory / "images" / "shot.png").write_bytes(IMAGE)
    document = {
        "schemaVersion": schema,
        "result": {"status": "confirmed", "attackId": attack_id, "reason": REASON,
                   **({"attack": attack} if attack else {})},
        "images": [{"file": "images/shot.png", "sha256": DIGEST, "bytes": len(IMAGE), "label": "삭제 응답"}],
    }
    (directory / "verification.json").write_text(json.dumps(document), encoding="utf-8")
    return directory


def _trigger_with(tmp_path: Path, handoff: Path | None, finding_id: str = "finding:h-a"):
    db = tmp_path / "runs.sqlite"
    if not db.exists():
        _store(db, _report("run-general"))
    value = json.loads(_trigger(db, tmp_path / "out", finding_id))
    if handoff is not None:
        value["sources"]["verification"] = {"kind": "handoff-dir", "location": str(handoff)}
    return parse_trigger(value)


def test_trigger_accepts_handoff_dir_and_defaults_to_none(tmp_path):
    handoff = _handoff(tmp_path / "handoff")
    assert _trigger_with(tmp_path, handoff).verification.kind == "handoff-dir"
    assert _trigger_with(tmp_path, handoff).verification.location == handoff
    assert _trigger_with(tmp_path, None).verification.kind == "none"


@pytest.mark.parametrize(
    "source",
    [
        {"kind": "ftp", "location": "/tmp/handoff"},
        {"kind": "handoff-dir", "location": "relative/handoff"},
        {"kind": "none", "location": "/tmp/handoff"},
        {"kind": "handoff-dir"},
        {"kind": "handoff-dir", "location": "/tmp/handoff", "extra": 1},
    ],
)
def test_trigger_rejects_malformed_verification_source(tmp_path, source):
    value = json.loads(_trigger(tmp_path / "runs.sqlite", tmp_path / "out", "finding:h-a"))
    value["sources"]["verification"] = source
    with pytest.raises(TriggerError):
        parse_trigger(value)


def test_trigger_refuses_output_inside_verification_source(tmp_path):
    handoff = _handoff(tmp_path / "handoff")
    value = json.loads(_trigger(tmp_path / "runs.sqlite", handoff / "out", "finding:h-a"))
    value["sources"]["verification"] = {"kind": "handoff-dir", "location": str(handoff)}
    with pytest.raises(TriggerError, match="overlap"):
        parse_trigger(value)


def test_bundle_add_bytes_is_sealed_and_write_once(tmp_path):
    writer = BundleWriter(tmp_path / "bundle")
    writer.add_bytes("evidence/images/a.png", "verification-image", b"abc")
    manifest = writer.seal(run_id="run-x", collected_at="2026-10-29T00:00:00+00:00", collectors=[])
    assert manifest["files"] == [{
        "path": "evidence/images/a.png",
        "role": "verification-image",
        "sha256": "sha256:" + hashlib.sha256(b"abc").hexdigest(),
        "size": 3,
        "mediaType": "application/octet-stream",
    }]
    assert (tmp_path / "bundle" / "evidence" / "images" / "a.png").read_bytes() == b"abc"

    writer = BundleWriter(tmp_path / "again")
    writer.add_bytes("evidence/images/a.png", "verification-image", b"abc")
    with pytest.raises(OutputError):
        writer.add_bytes("evidence/images/a.png", "verification-image", b"other")
    for escaping in ("../escape.png", "/abs.png"):
        with pytest.raises(ValueError):
            writer.add_bytes(escaping, "verification-image", b"x")
    writer.discard()


def test_valid_handoff_images_are_sealed_into_the_manifest(tmp_path):
    handoff = _handoff(tmp_path / "handoff")
    collected = collect(_trigger_with(tmp_path, handoff))
    bundle = collected.bundle
    assert (bundle / "evidence" / "images" / "shot.png").read_bytes() == IMAGE
    files = {item["path"]: item for item in collected.manifest["files"]}
    assert files["evidence/images/shot.png"]["sha256"] == DIGEST
    assert files["evidence/images/shot.png"]["size"] == len(IMAGE)
    assert files["run/verification.json"]["role"] == "verification-handoff"
    verification = json.loads((bundle / "run" / "verification.json").read_text("utf-8"))
    assert verification["images"][0]["ref"] == "evidence/images/shot.png"
    assert verification["result"]["status"] == "confirmed"


def test_collection_without_verification_source_is_unchanged(tmp_path):
    collected = collect(_trigger_with(tmp_path, None))
    assert not (collected.bundle / "run" / "verification.json").exists()
    attack = json.loads((collected.bundle / "run" / "attack.json").read_text("utf-8"))
    assert attack["records"] == []


def test_tampered_image_is_refused_and_nothing_is_sealed(tmp_path):
    handoff = _handoff(tmp_path / "handoff")
    (handoff / "images" / "shot.png").write_bytes(IMAGE + b"tampered")
    with pytest.raises(CollectError):
        collect(_trigger_with(tmp_path, handoff))
    assert not (tmp_path / "out" / "bundle").exists()


def test_unsupported_handoff_schema_is_refused(tmp_path):
    handoff = _handoff(tmp_path / "handoff", schema="verification-handoff/2")
    with pytest.raises(CollectError, match="schema"):
        collect(_trigger_with(tmp_path, handoff))


def test_attack_that_is_not_a_confirmed_probe_is_refused(tmp_path):
    handoff = _handoff(tmp_path / "handoff", attack_id="p-c")
    with pytest.raises(CollectError, match="confirmed probe"):
        collect(_trigger_with(tmp_path, handoff))
    assert not (tmp_path / "out" / "bundle").exists()


def test_handoff_attack_record_is_sealed_as_the_attack_source(tmp_path):
    collected = collect(_trigger_with(tmp_path, _handoff(tmp_path / "handoff", attack=ATTACK)))
    attack = json.loads((collected.bundle / "run" / "attack.json").read_text("utf-8"))
    assert attack["records"] == [ATTACK]


def test_handoff_screenshot_and_verified_values_are_in_the_hwpx(tmp_path):
    collected = collect(_trigger_with(tmp_path, _handoff(tmp_path / "handoff")))
    model = llm_model()
    # The model places the real screenshot and also invents one that does not exist.
    model["findings"][0]["images"] = [
        {"ref": "shot.png", "step": 1, "caption": "삭제 요청 뒤 목록"},
        {"ref": "evidence/images/forged.png", "step": 1, "caption": "없는 사진"},
    ]
    tools = ReportTools(collected.bundle, tmp_path / "document")
    tools.finish_report(model=model)
    saved = json.loads((tmp_path / "document" / "report-model.json").read_text("utf-8"))
    assert saved["findings"][0]["images"] == [{
        "step": 1, "caption": "삭제 요청 뒤 목록", "ref": "evidence/images/shot.png", "integrity": "ok",
    }]
    with zipfile.ZipFile(tmp_path / "document" / tools.finished.report_filename) as archive:
        pictures = [name for name in archive.namelist() if name.startswith("BinData/")]
        assert [archive.read(name) for name in pictures] == [IMAGE]
        xml = "".join(archive.read(name).decode("utf-8") for name in archive.namelist()
                      if name.startswith("Contents/section"))
    for value in ("finding:h-a", "confirmed", "run-general", "삭제 요청 뒤 목록", "CWE-639"):
        assert value in xml
    for forged in ("finding:h-b", "not_reproduced", "another-run", "없는 사진"):
        assert forged not in xml


def test_without_verification_the_report_has_no_screenshot(tmp_path):
    collected = collect(_trigger_with(tmp_path, None))
    tools = ReportTools(collected.bundle, tmp_path / "document")
    tools.finish_report(model=llm_model())
    with zipfile.ZipFile(tmp_path / "document" / tools.finished.report_filename) as archive:
        assert not any(name.startswith("BinData/") for name in archive.namelist())
