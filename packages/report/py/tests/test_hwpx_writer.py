import struct
import zipfile
import zlib

import pytest
from hwpx import HwpxDocument

from ca3p_report.hwpx import write_html, write_hwpx, write_markdown
from ca3p_report.hwpx.writer import PHOTO_MISSING, PHOTO_NOTE, TRIAGE_CAVEAT, VERDICT_CAVEAT

RUN = "run-20261020-xss"
PAYLOAD = "<img src=x onerror=alert(document.cookie)> & ]]> | <script>alert(1)</script>"
HEADINGS = [
    f"CA3P 취약점 점검 보고서 — {RUN}",
    "1. 점검 개요",
    "2. 취약점 요약",
    "3. 취약점 상세",
    "4. 과거 사례 대조(재점검 triage)",
    "5. 관련 전월 보고서",
    "6. 재점검 이력",
    "7. 가드레일 결정과 안전 속성",
    "8. 출처와 한계",
]


def png(width=4, height=2):
    def chunk(kind, data):
        crc = struct.pack(">I", zlib.crc32(kind + data))
        return struct.pack(">I", len(data)) + kind + data + crc

    rows = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"IEND", b"")
    )


def model(status="completed"):
    return {
        "schemaVersion": "report-1.0",
        "generatedAt": "2026-10-20T09:00:00Z",
        "run": {
            "runId": RUN,
            "status": status,
            "testProfile": "stored_xss_canary",
            "target": {"origin": "http://127.0.0.1:18080"},
            "startedAt": "2026-10-20T00:00:00Z",
            "completedAt": "2026-10-20T00:00:05Z",
            "metrics": {"requests": 4},
            "error": {
                "code": "TARGET_UNREACHABLE",
                "source": "attack-module",
                "message": "connect ECONNREFUSED <script>alert(1)</script>",
                "stage": "loop.act",
            },
        },
        "findings": [
            {
                "common": {
                    "findingId": f"finding-{RUN}-stored-xss",
                    "title": "저장형 XSS 브라우저 실행",
                    "cwe": "CWE-79",
                    "severity": "medium",
                    "status": "confirmed",
                    "location": {"method": "POST", "path": "/api/posts", "parameter": "content"},
                    "cvss": {
                        "version": "3.1",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                        "score": 5.4,
                        "rating": "Medium",
                        "source": "llm",
                    },
                    "summary": "게시글 본문에 저장된 스크립트가 열람자 브라우저에서 실행됩니다.",
                    "remediation": "출력 시 HTML 이스케이프를 적용합니다.",
                    "limitations": "[가상] synthetic 데이터로 점검했습니다.",
                },
                "checks": [{"label": "브라우저 실행 확인", "result": True}],
                "reproduction": [
                    {"text": "게시글 작성 폼에 페이로드를 입력합니다."},
                    "피해자 계정으로 게시글을 엽니다.",
                ],
                "textEvidence": [
                    {"label": "PoC 요청", "text": f'POST /api/posts\n{{"content": "{PAYLOAD}"}}'},
                    {"label": "응답", "text": "201 Created"},
                    {"label": "점검 페이로드", "text": PAYLOAD},
                ],
                "images": [
                    {
                        "ref": "evidence/images/input.png",
                        "integrity": "ok",
                        "step": 1,
                        "caption": "① 입력 지점",
                    },
                    {
                        "ref": "evidence/images/victim.png",
                        "integrity": "mismatch",
                        "step": 2,
                        "caption": "② 피해자 화면",
                    },
                    {"ref": "../../outside.png", "integrity": "ok", "caption": "범위 밖 경로"},
                ],
                "impact": "열람자 세션에서 임의 스크립트가 실행될 수 있습니다.",
                "profileData": {"marker": "m-1a2b", "payload": PAYLOAD, "sha256": "sha256:abc"},
            }
        ],
        "triage": {
            "readyCaseCount": 1,
            "rows": [
                {
                    "caseId": "CERT-2026-09",
                    "location": "POST /api/posts content",
                    "label": "재점검 후보",
                }
            ],
        },
        "priorCases": [
            {
                "caseId": "CERT-2026-09",
                "revision": 2,
                "title": "9월 저장형 XSS",
                "checks": [{"checkId": "chk-1", "status": "ready", "createdAt": "2026-10-19"}],
            }
        ],
        "guardrail": {"decisions": [{"decision": "ALLOW", "ruleId": "XSS-CANARY"}]},
        "safety": {"isolatedLab": True},
        "notices": ["[가상] 이 run은 synthetic 데이터입니다."],
        "references": {
            "collectors": [{"name": "collect-run", "driver": "pentest-db-disk", "status": "ok"}],
            "verifiedByStorage": False,
        },
        "generator": {"profile": "stored_xss"},
    }


@pytest.fixture
def image_root(tmp_path):
    root = tmp_path / "bundle"
    (root / "evidence/images").mkdir(parents=True)
    (root / "evidence/images/input.png").write_bytes(png())
    (root / "evidence/images/victim.png").write_bytes(png())
    (tmp_path / "outside.png").write_bytes(png())
    return root


def section_xml(path):
    with zipfile.ZipFile(path) as archive:
        return "".join(
            archive.read(name).decode("utf-8")
            for name in archive.namelist()
            if name.startswith("Contents/section")
        )


def test_hwpx_saves_validates_and_carries_the_outline(tmp_path, image_root):
    out = write_hwpx(model(), tmp_path / "report.hwpx", image_root=image_root)
    doc = HwpxDocument.open(out)
    assert doc.validate().ok
    preview = doc.text.markdown()
    for heading in HEADINGS:
        assert heading in preview
    assert VERDICT_CAVEAT in preview and TRIAGE_CAVEAT in preview
    assert "LLM이 CVSS 3.1로 산출" in preview and "상류 severity: medium" in preview


def test_payload_is_stored_escaped_never_as_raw_markup(tmp_path, image_root):
    out = write_hwpx(model(), tmp_path / "report.hwpx", image_root=image_root)
    xml = section_xml(out)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in xml
    assert "&lt;img src=x onerror=" in xml
    assert "]]&gt;" in xml
    assert "<script>alert" not in xml
    assert "<img src=x" not in xml


def test_images_only_ok_and_inside_root_are_embedded(tmp_path, image_root):
    out = write_hwpx(model(), tmp_path / "report.hwpx", image_root=image_root)
    with zipfile.ZipFile(out) as archive:
        pictures = [n for n in archive.namelist() if n.startswith("BinData/")]
    assert len(pictures) == 1  # input.png only; mismatch and out-of-root become placeholders
    text = HwpxDocument.open(out).text.markdown()
    assert PHOTO_NOTE in text
    assert text.count(PHOTO_MISSING) == 2


def test_body_has_no_hashes(tmp_path, image_root):
    xml = section_xml(write_hwpx(model(), tmp_path / "report.hwpx", image_root=image_root))
    assert "sha256" not in xml


def test_failed_run_renders_the_failure_variant(tmp_path):
    out = write_hwpx(model(status="failed"), tmp_path / "failed.hwpx")
    text = HwpxDocument.open(out).text.markdown()
    assert "3. 실행 실패" in text and "3. 취약점 상세" not in text
    assert "TARGET_UNREACHABLE" in text and "loop.act" in text
    assert "실행이 실패하여 요약할 취약점이 없습니다." in text
    assert "<script>alert" not in section_xml(out)


def test_markdown_preview_is_html_escaped(tmp_path):
    text = write_markdown(model(), tmp_path / "report.md").read_text(encoding="utf-8")
    for heading in HEADINGS[1:]:
        assert heading in text
    assert "<script>" not in text and "&lt;script&gt;" in text
    assert "\\|" in text  # pipe in a table cell does not split the row


def test_html_preview_renders_tables_and_intact_images_without_executing_payload(tmp_path, image_root):
    text = write_html(model(), tmp_path / "report.html", image_root=image_root).read_text(encoding="utf-8")
    assert "<table><tbody>" in text
    assert 'src="data:image/png;base64,' in text
    assert text.count('src="data:image/png;base64,') == 1
    assert text.count(PHOTO_MISSING) == 2
    assert "<script>alert" not in text and "&lt;script&gt;alert" in text
    assert "default-src 'none'" in text


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda m: m["run"].update(target="127.0.0.1", error="boom", status="failed"),
        lambda m: m["findings"][0]["common"].update(cvss="9.8", location="POST /api/posts"),
        lambda m: m["findings"][0].update(images=["a.png"], checks=["ok"], textEvidence=["x"]),
        lambda m: m.update(findings=["x"], priorCases=["x"], triage=[], guardrail="x"),
        lambda m: m.clear(),
    ],
)
def test_malformed_llm_built_model_still_renders(tmp_path, corrupt):
    broken = model()
    corrupt(broken)
    assert write_hwpx(broken, tmp_path / "broken.hwpx").exists()
    assert write_markdown(broken, tmp_path / "broken.md").exists()
