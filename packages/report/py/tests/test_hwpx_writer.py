import re
import struct
import zipfile
import zlib

import pytest
from hwpx import HwpxDocument
from lxml import etree

from ca3p_report.hwpx import write_html, write_hwpx, write_markdown
from ca3p_report.hwpx.writer import INCOMPLETE, NONE, SHOT_MISSING, SHOT_NOTE

PAYLOAD = "<img src=x onerror=alert(document.cookie)> & ]]> | <script>alert(1)</script>"
SECTIONS = [
    "1. 점검 결과 요약",
    "1.1 우선 조치 권고",
    "2. 점검 개요",
    "3. 취약점 목록",
    "4. 취약점 상세",
    "5. 점검 한계 및 면책",
    "부록 A. 심각도 기준 (CVSS 3.1)",
    "부록 B. 증적 출처 및 재점검 이력",
    "B.1 증적 수집 상태",
    "B.2 재점검 이력",
    "B.3 생략된 정보",
    "B.4 참고 자료의 검토 상태와 미확정 사항",
]
DETAILS = [
    "■ 취약점 설명",
    "■ 영향",
    "■ 재현 절차",
    "■ 증거",
    "■ 판정 근거",
    "■ 조치 방안",
    "■ 검증 한계",
    "[즉시 조치]",
    "[근본 대책]",
    "CWE-89 · OWASP Top 10 A03:2021 Injection",  # the 참고 line
]
CSP = (
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:; '
    "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
)
SEVERITY_COLORS = ["#7030A0", "#C00000", "#BF8F00", "#2E74B5", "#7F7F7F"]
FILLS = ["#1F4E79", "#EAF1FA", "#F4F4F7", "#FFF8E5", "#EEF7EE"]
HP = "{http://www.hancom.co.kr/hwpml/2011/paragraph}"
HH = "{http://www.hancom.co.kr/hwpml/2011/head}"
HC = "{http://www.hancom.co.kr/hwpml/2011/core}"


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
    """First finding of the team kit's sample_run.json, plus screenshots and a payload."""
    return {
        "classification": "대외비 (CONFIDENTIAL)",
        "run": {
            "target_name": "대한대학교 웹사이트 (시험 환경)",
            "target_origin": "http://127.0.0.1:4101",
            "run_id": "run-627fb6ae-f86e-4bfc-abdc-b7e5bb4a3dc5",
            "profile": "general",
            "started_at": "2026-11-02 15:22:19 UTC",
            "finished_at": "2026-11-02 15:23:34 UTC",
            "generated_at": "2026-11-02 15:27 UTC",
            "request_count": 17,
            "status": status,
            "incomplete": False,
        },
        "executive_summary": (
            "대한대학교 웹사이트 시험 환경에서 확정 취약점 1건(높음)을 확인했습니다. "
            "인증 없이 검색 API의 SQL 조회문을 조작할 수 있습니다."
        ),
        "objective": "대한대학교 웹사이트의 공개·인증 기능에 대해 자동 침투테스트를 수행합니다.",
        "scope": "http://127.0.0.1:4101 (격리된 시험용 사이트). 공개 세션, 학생 계정.",
        "run_limitations": (
            "이번 실행은 점검 예산(프로브 24회)을 모두 사용하여 종료되었습니다.\n\n"
            "세션 쿠키와 인증 헤더 값은 비밀값으로 분류하여 기재하지 않았습니다."
        ),
        "sources": [
            {
                "collector": "공격 실행 증적 수집",
                "kind": "attack-tool/http",
                "status": "captured",
                "note": "기준·공격 요청과 응답 원문, 화면 캡처 확보",
            },
            {
                "collector": "과거 사례·재점검 이력",
                "kind": "history-store",
                "status": "empty",
                "note": "조회된 과거 사례 없음",
            },
        ],
        "history": [],
        "omitted": ["세션 쿠키·인증 헤더 값 — 사유: 비밀값에 해당하여 기재하지 않음"],
        "findings": [
            {
                "id": "V-01",
                "title": "검색 API SQL 삽입 (SQL Injection)",
                "severity": "high",
                "cvss_score": "7.5",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe": "CWE-89",
                "location": "GET /api/search (q)",
                "verdict": "confirmed",
                "privilege": "없음",
                "finding_id": "finding:t-fa34bb39e407db7e",
                "description": (
                    "검색 API(GET /api/search)는 q 파라미터 값을 SQL 질의문에 그대로 이어 붙여 "
                    "실행합니다.\n\n대조 0건 대 공격 18건으로 결과가 갈렸습니다."
                ),
                "impact": "인증 없이 누구나 데이터베이스 조회문을 조작할 수 있습니다.",
                "steps": [
                    "공개 세션에서 GET /api/search?q=zzqnomatch 를 전송한다.",
                    "q 에 참 조건 페이로드를 넣어 GET /api/search?q=%27+OR+%271 을 전송한다.",
                    "응답이 결과 18건으로 대조군과 구분되는지 확인하고 SQL 삽입으로 판정한다.",
                ],
                "evidence": [
                    {
                        "label": "[대조 요청]",
                        "content": "GET /api/search?q=zzqnomatch HTTP/1.1\nHost: 127.0.0.1:4101",
                    },
                    {
                        "label": "[공격 응답] (일부 발췌)",
                        "content": f'HTTP/1.1 200\n{{"q":"{PAYLOAD}","results":[]}}',
                    },
                ],
                "screenshots": [
                    {
                        "caption": f'전체 18건이 표시된 "검색 결과" 화면 {SHOT_NOTE}\n',
                        "ref": "evidence/images/search.png",
                    },
                    {"caption": "삭제된 화면", "ref": "evidence/images/gone.png"},
                    {"caption": "IHDR 없는 화면", "ref": "evidence/images/broken.png"},
                    {"caption": "크기 0 화면", "ref": "evidence/images/zero.png"},
                    {"caption": "범위 밖 경로", "ref": "../outside.png"},
                ],
                "checks": [
                    {"item": "대조군 대비 결과 차이", "result": f"대조 0건 → 공격 18건 {PAYLOAD}"},
                    {"item": "검증 판정", "result": "valid — 참 조건 페이로드가 WHERE 필터를 우회"},
                ],
                "fix_summary": "q 값을 파라미터 바인딩(prepared statement)으로만 전달",
                "fix_short": "검색 질의를 SELECT ... WHERE title LIKE ? 형태로 고정합니다.",
                "fix_long": "DB 계정은 조회에 필요한 최소 권한만 부여합니다.",
                "limitations": "참 조건 페이로드 1종으로만 확인했습니다.",
                "references": ["CWE-89", "OWASP Top 10 A03:2021 Injection"],
            }
        ],
        "referenceContext": {
            "intake": {"status": "available"},
            "external": {"status": "unavailable", "reason": "외부 권고 저장소 미연결"},
            "findings": [
                {
                    "candidate": {"title": "9월 검색 SQL 삽입", "endpoint": "/api/search"},
                    "registration_state": "registered",
                    "review": {"decision": "approved"},
                    "payload_variants": [{"representation": "raw", "value": PAYLOAD}],
                }
            ],
        },
    }


@pytest.fixture
def image_root(tmp_path):
    root = tmp_path / "bundle"
    (root / "evidence/images").mkdir(parents=True)
    (root / "evidence/images/search.png").write_bytes(png())
    no_ihdr = png()[:12] + b"IDAT" + png()[16:]  # PNG magic and sizes, but no IHDR chunk
    (root / "evidence/images/broken.png").write_bytes(no_ihdr)
    (root / "evidence/images/zero.png").write_bytes(png(0, 1))
    (tmp_path / "outside.png").write_bytes(png())
    return root


def parts(path):
    with zipfile.ZipFile(path) as archive:
        section = "".join(
            archive.read(n).decode("utf-8")
            for n in archive.namelist()
            if n.startswith("Contents/section")
        )
        return archive.read("Contents/header.xml").decode("utf-8"), section, archive.namelist()


def text_of(path):
    _, section, _ = parts(path)
    return "\n".join(etree.fromstring(section.encode("utf-8")).itertext())


def used_colors(path):
    """Fill colors of the cells and text colors of the runs the body actually uses."""
    header, section, _ = parts(path)
    head, body = etree.fromstring(header.encode()), etree.fromstring(section.encode())
    faces = {
        n.get("id"): n.find(f".//{HC}winBrush").get("faceColor")
        for n in head.iter(f"{HH}borderFill")
        if n.find(f".//{HC}winBrush") is not None
    }
    texts = {n.get("id"): n.get("textColor") for n in head.iter(f"{HH}charPr")}
    cells = list(body.iter(f"{HP}tc"))
    return (
        {"".join(tc.itertext()): faces.get(tc.get("borderFillIDRef")) for tc in cells},
        {texts.get(run.get("charPrIDRef")) for run in body.iter(f"{HP}run")},
        {faces.get(tc.get("borderFillIDRef")) for tc in cells if tc.get("header") == "1"},
    )


def breaks_page(path, heading):
    header, section, _ = parts(path)
    para = next(
        p for p in etree.fromstring(section.encode()).iter(f"{HP}p")
        if "".join(p.itertext()) == heading
    )
    pr = next(
        n for n in etree.fromstring(header.encode()).iter(f"{HH}paraPr")
        if n.get("id") == para.get("paraPrIDRef")
    )
    return pr.find(f".//{HH}breakSetting").get("pageBreakBefore") == "1"


def structure_errors(path):
    """The team kit's validate_hwpx.py checks, except that binary items are allowed."""
    header, section, _ = parts(path)
    errors, defined = [], {}
    for container, tag in [
        ("borderFills", "borderFill"),
        ("charProperties", "charPr"),
        ("paraProperties", "paraPr"),
    ]:
        match = re.search(rf'<hh:{container} itemCnt="(\d+)">(.*?)</hh:{container}>', header, re.S)
        ids = re.findall(rf'<hh:{tag}\b[^>]*?\bid="(\d+)"', match.group(2))
        if int(match.group(1)) != len(ids) or len(set(ids)) != len(ids):
            errors.append(f"{container}: itemCnt {match.group(1)} vs ids {ids}")
        defined[tag] = set(ids)
    for attr, tag in [
        ("charPrIDRef", "charPr"),
        ("paraPrIDRef", "paraPr"),
        ("borderFillIDRef", "borderFill"),
    ]:
        missing = set(re.findall(rf'{attr}="(\d+)"', section)) - defined[tag]
        if missing:
            errors.append(f"{attr} undefined: {sorted(missing)}")
    ids = re.findall(r'<hp:p\b[^>]*?\bid="(\d+)"', section)
    duplicates = {i for i in ids if ids.count(i) > 1 and i != "0"}
    if duplicates:
        errors.append(f"duplicate paragraph ids: {sorted(duplicates)[:5]}")
    for table in re.finditer(r"<hp:tbl\b([^>]*)>(.*?)</hp:tbl>", section, re.S):
        attrs, body = table.groups()
        rows = re.findall(r"<hp:tr>(.*?)</hp:tr>", body, re.S)
        if int(re.search(r'rowCnt="(\d+)"', attrs).group(1)) != len(rows):
            errors.append("rowCnt mismatch")
        columns = int(re.search(r'colCnt="(\d+)"', attrs).group(1))
        for r, row in enumerate(rows):
            spans = [int(x) for x in re.findall(r'colSpan="(\d+)"', row)]
            if sum(spans) != columns or set(re.findall(r'rowAddr="(\d+)"', row)) != {str(r)}:
                errors.append(f"row {r}: spans {spans} vs colCnt {columns}")
    return errors


def test_hwpx_validates_and_is_structurally_sound(tmp_path, image_root):
    out = write_hwpx(model(), tmp_path / "report.hwpx", image_root=image_root)
    assert HwpxDocument.open(out).validate().ok
    assert structure_errors(out) == []


def test_hwpx_carries_the_spec_sections_and_formatting(tmp_path, image_root):
    out = write_hwpx(model(), tmp_path / "report.hwpx", image_root=image_root)
    header, section, _ = parts(out)
    text = text_of(out)
    for heading in SECTIONS + DETAILS:
        assert heading in text
    fills, text_colors, header_fills = used_colors(out)
    assert set(SEVERITY_COLORS + FILLS) <= set(fills.values())
    assert fills["High 7.5"] == "#C00000"  # the finding's own severity badge
    assert set(SEVERITY_COLORS) <= text_colors and "#DCE6F2" in text_colors
    assert header_fills == {"#1F4E79"} and 'repeatHeader="1"' in section
    for heading in ("1. 점검 결과 요약", "4. 취약점 상세", "5. 점검 한계 및 면책"):
        assert breaks_page(out, heading)
    assert not breaks_page(out, "2. 점검 개요")
    assert "D2Coding" in header


def test_confirmed_verdict_is_green_bold(tmp_path):
    out = write_hwpx(model(), tmp_path / "report.hwpx")
    header, section, _ = parts(out)
    green = {
        node.get("id")
        for node in etree.fromstring(header.encode("utf-8")).iter(f"{HH}charPr")
        if node.get("textColor") == "#2F8F46" and node.find(f"{HH}bold") is not None
    }
    runs = etree.fromstring(section.encode("utf-8")).iter(f"{HP}run")
    assert any(r.get("charPrIDRef") in green and "".join(r.itertext()) == "confirmed" for r in runs)


def test_only_intact_screenshots_inside_root_are_embedded(tmp_path, image_root):
    out = write_hwpx(model(), tmp_path / "report.hwpx", image_root=image_root)
    pictures = [n for n in parts(out)[2] if n.startswith("BinData/")]
    assert len(pictures) == 1  # search.png; missing, broken, zero-size, out-of-root get a box
    text = text_of(out)
    assert text.count(SHOT_MISSING) == 4
    assert '전체 18건이 표시된 "검색 결과" 화면 (보조 자료, 판정 근거 아님)' in text
    assert f"삭제된 화면 {SHOT_NOTE}" in text
    assert text.count(SHOT_NOTE) == 5  # the code adds the note once, never twice

    bare = write_hwpx(model(), tmp_path / "bare.hwpx")  # no image_root: nothing is embedded
    assert not [n for n in parts(bare)[2] if n.startswith("BinData/")]


def test_payload_is_stored_escaped_never_as_raw_markup(tmp_path, image_root):
    _, section, _ = parts(write_hwpx(model(), tmp_path / "r.hwpx", image_root=image_root))
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in section
    assert "&lt;img src=x onerror=" in section and "]]&gt;" in section
    assert "<script>alert" not in section and "<img src=x" not in section


def test_failed_or_partial_run_shows_the_incomplete_notice(tmp_path):
    for status, incomplete in (("failed", False), ("completed", True)):
        value = model(status=status)
        value["run"]["incomplete"] = incomplete
        text = text_of(write_hwpx(value, tmp_path / f"{status}.hwpx"))
        assert "4. 취약점 상세" in text and INCOMPLETE in text
    assert INCOMPLETE not in text_of(write_hwpx(model(), tmp_path / "done.hwpx"))


def test_markdown_preview_has_the_same_sections_and_is_escaped(tmp_path):
    text = write_markdown(model(), tmp_path / "report.md").read_text(encoding="utf-8")
    for heading in SECTIONS + DETAILS:
        assert heading in text
    assert "evidence/images" not in text  # bundle paths stay out of the report
    assert "# 1. 점검 결과 요약" in text and "### ■ 판정 근거" in text
    assert "| 0 | 1 | 0 | 0 | 0 |" in text  # severity counts come from the finding
    assert "<script>" not in text and "&lt;script&gt;" in text
    assert "\\|" in text  # a pipe in a table cell does not split the row


def test_html_preview_is_inert_and_embeds_only_intact_images(tmp_path, image_root):
    out = write_html(model(), tmp_path / "report.html", image_root=image_root)
    text = out.read_text(encoding="utf-8")
    for heading in SECTIONS + DETAILS:
        assert heading in text
    assert CSP in text
    assert text.count('src="data:image/png;base64,') == 1
    assert 'alt="전체 18건이 표시된 &quot;검색 결과&quot; 화면' in text
    assert text.count(SHOT_MISSING) == 4
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert not re.search(r"<script|<iframe|<object|<embed|javascript:", text, re.I)
    assert not re.search(r"<[a-z][^>]*\son\w+\s*=", text, re.I)


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda m: m.update(run="127.0.0.1", sources="x", history=[1], omitted={"a": 1}),
        lambda m: m["findings"][0].update(
            severity=5, cvss_score=["x"], steps="한 단계", evidence=["x"], checks=None,
            references="CWE-89", verdict=None, title=None,
        ),
        lambda m: m["findings"][0].update(
            screenshots=[{"ref": {"a": 1}}, {"ref": "evidence/\x00bad.png"}, "옛 캡션"]
        ),
        lambda m: m.update(findings=["x"], referenceContext=[]),
        lambda m: (  # lone surrogates are valid JSON escapes
            m["findings"][0].update(
                description="a\ud800b", screenshots=[{"caption": "\udc80", "ref": "\ud800.png"}]
            ),
            m["referenceContext"]["findings"][0]["review"].update(resolutions={"\ud800": "x"}),
        ),
        lambda m: m.clear(),
    ],
)
def test_malformed_llm_built_model_still_renders(tmp_path, image_root, corrupt):
    broken = model()
    corrupt(broken)
    out = write_hwpx(broken, tmp_path / "broken.hwpx", image_root=image_root)
    assert structure_errors(out) == [] and NONE in text_of(out)
    assert write_markdown(broken, tmp_path / "broken.md").exists()
    assert write_html(broken, tmp_path / "broken.html", image_root=image_root).exists()


def test_cvss_vector_is_explained_per_metric_in_korean(tmp_path):
    from ca3p_report.hwpx.writer import cvss_breakdown

    rows = cvss_breakdown("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert [(m, v) for m, _, v, _ in rows] == [
        ("AV", "네트워크"), ("AC", "특정 정보/조건 불필요"), ("PR", "없음"), ("UI", "없음"),
        ("S", "해당자원 한정"), ("C", "높음"), ("I", "없음"), ("A", "없음"),
    ]
    assert rows[0][1] == "공격자의 접근 방법"
    assert rows[0][3] == "네트워크 / 제한된 네트워크 / 로컬 / 물리"
    other = cvss_breakdown("CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:H")
    assert {m: v for m, _, v, _ in other} == {
        "AV": "제한된 네트워크", "AC": "특정 정보/조건 필요", "PR": "상위권한 (관리자)",
        "UI": "필요 (메일열람, 페이지접근, 실행 등)", "S": "해당자원 이상",
        "C": "낮음", "I": "낮음", "A": "높음",
    }
    for broken in (None, "", "AV:N/AC:L", "CVSS:3.1/AV:Z"):
        assert {v for _, _, v, _ in cvss_breakdown(broken)} == {NONE}
    text = write_markdown(model(), tmp_path / "report.md").read_text(encoding="utf-8")
    for expected in ("CVSS 3.1 평가", "공격자의 접근 방법", "특정 정보/조건 불필요"):
        assert expected in text


def test_internal_report_has_no_review_status_or_verdict_guide(tmp_path, image_root):
    md = write_markdown(model(), tmp_path / "report.md").read_text(encoding="utf-8")
    out = write_hwpx(model(), tmp_path / "r.hwpx", image_root=image_root)
    for text in (md, HwpxDocument.open(out).text.markdown()):
        # The cover row and draft notice are gone; B.4 (casper case review) is another topic.
        for absent in ("사람 검토 후 배포", "판정 기준", "재현·검증 완료 / unverified"):
            assert absent not in text
    assert "| 검토 상태 |" not in md
