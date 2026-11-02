"""Render the REPORT_SPEC.md report JSON into one .hwpx, plus Markdown and HTML previews.

The writer renders what it is given and verifies nothing. Every python-hwpx call lives in this
file. Text goes in only through text APIs, which XML-escape it; raw XML is never inserted.
The REPORT_SPEC.md §2 outline is built once as a block list and rendered three ways, so every
output carries the same sections. §4 formatting comes from the CHAR/PARA/FILL tables below.

Blocks: ("p", runs, para_style, page_break), ("table", rows, column_weights, header_row),
("image", caption, ref). A run is (text, char_style); a cell is a dict made by _cell.
"""

from __future__ import annotations

import base64
import html
import json
import struct
from pathlib import Path

from hwpx import HwpxDocument

NONE = "자료 없음"
INCOMPLETE = (
    "점검 미완료: 실행이 끝나기 전에 확인된 결과만 기록했으며, "
    "전체 점검 범위의 완료를 뜻하지 않습니다."
)
SHOT_NOTE = "(보조 자료, 판정 근거 아님)"
SHOT_MISSING = "[화면 캡처] 이미지를 불러올 수 없어 싣지 않았습니다."
PHOTO_WIDTH_MM = 150.0
PHOTO_MAX_HEIGHT_MM = 200.0
PHOTO_MAX_BYTES = 10_000_000
CLASSIFICATION = "대외비 (CONFIDENTIAL)"
REVIEW_STATUS = "초안 — 사람 검토 후 배포"
AUTHOR = "CA3P 자동 침투테스트 에이전트"
METHOD = (
    "CA3P 자동 침투테스트 에이전트가 정찰 → 취약점 탐색 → 재현 검증 → 보고 순으로 수행했습니다. "
    "검증 단계에서 대조 요청과 공격 요청의 응답 차이로 판정했습니다."
)
VERDICT_GUIDE = "confirmed: 재현·검증 완료 / unverified: 미검증"
DISCLAIMER = (
    "본 보고서는 승인된 범위와 기간 내에서 수행한 점검 결과이며, 점검 시점 이후의 변경 사항은 "
    "반영하지 않습니다. 보고서에 기재되지 않았다고 해서 취약점이 없음을 의미하지 않습니다. "
    "본 문서는 대외비로 취급하며 무단 배포를 금합니다."
)
SOURCE_OK = ("captured", "completed", "available")

NAVY = "#1F4E79"
BODY_FONT = "함초롬돋움"
# key: (label, 한글, color, CVSS range, 부록 A guide)
SEV = {
    "critical": ("Critical", "긴급", "#7030A0", "9.0 – 10.0",
                 "원격에서 시스템 장악·대량 정보 유출이 가능. 즉시 조치 및 서비스 영향 검토"),
    "high": ("High", "높음", "#C00000", "7.0 – 8.9",
             "중요 정보 유출·권한 우회가 가능. 단기(우선) 조치"),
    "medium": ("Medium", "중간", "#BF8F00", "4.0 – 6.9",
               "제한된 조건에서 정보 노출·기능 오용이 가능. 계획 조치"),
    "low": ("Low", "낮음", "#2E74B5", "0.1 – 3.9", "악용 가능성·영향이 낮음. 개선 권고"),
    "info": ("Info", "정보", "#7F7F7F", "0.0", "보안 모범사례 관점의 참고 사항"),
}
# styles.ensure_run arguments (size in pt); BODY_FONT unless "font" is given.
CHAR = {
    "body": {"size": 10, "color": "#222222"},
    "body_b": {"size": 10, "color": "#222222", "bold": True},
    "small": {"size": 9, "color": "#595959"},
    "hint": {"size": 8.5, "color": "#8C8C8C"},
    "th": {"size": 9.5, "color": "#FFFFFF", "bold": True},
    "label": {"size": 9.5, "color": NAVY, "bold": True},
    "code": {"size": 8.5, "color": "#262626", "font": "D2Coding"},
    "title": {"size": 24, "color": "#FFFFFF", "bold": True},
    "subtitle": {"size": 13, "color": "#DCE6F2"},
    "conf": {"size": 9, "color": "#C00000", "bold": True},
    "h1": {"size": 15, "color": NAVY, "bold": True},
    "h2": {"size": 12, "color": "#1A1A1A", "bold": True},
    "h3": {"size": 10.5, "color": NAVY, "bold": True},
    "ok": {"size": 10, "color": "#2F8F46", "bold": True},
    **{f"sev_{k}": {"size": 10, "color": v[2], "bold": True} for k, v in SEV.items()},
    **{f"big_{k}": {"size": 22, "color": v[2], "bold": True} for k, v in SEV.items()},
}
# name: (alignment, space before, space after (HWPUNIT), line spacing %); h* keep with next.
PARA = {
    "body": ("JUSTIFY", 0, 300, 160),
    "tight": ("LEFT", 0, 0, 130),
    "center": ("CENTER", 0, 0, 130),
    "code": ("LEFT", 0, 0, 115),
    "h1": ("LEFT", 1400, 500, 130),
    "h2": ("LEFT", 1000, 300, 130),
    "h3": ("LEFT", 600, 200, 130),
}
# name: (fill, border color, border type)
FILL = {
    "cell": (None, "#C7D7EA", "SOLID"),
    "navy": (NAVY, NAVY, "SOLID"),
    "label": ("#EAF1FA", "#C7D7EA", "SOLID"),
    "code": ("#F4F4F7", "#D6D6DE", "SOLID"),
    "note": ("#FFF8E5", "#E6C35C", "SOLID"),
    "fix": ("#EEF7EE", "#9CCB9C", "SOLID"),
    "shot": ("#FAFAFA", "#A6A6A6", "DASH"),
    **{f"sev_{k}": (v[2], v[2], "SOLID") for k, v in SEV.items()},
}


# ---- reading LLM-built input: never raise, fall back to NONE ----

def _obj(parent: object, key: str) -> dict:
    value = parent.get(key) if isinstance(parent, dict) else None
    return value if isinstance(value, dict) else {}


def _dicts(parent: object, key: str) -> list[dict]:
    value = parent.get(key) if isinstance(parent, dict) else None
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _text(value: object) -> str:
    if value is None or value == "":
        return NONE
    if isinstance(value, bool):
        return "예" if value else "아니오"
    text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
    return text.encode("utf-8", "replace").decode("utf-8")  # a lone surrogate would crash writers


def _strings(value: object) -> list[str]:
    """A list field as strings; a lone string counts as one item."""
    if isinstance(value, list):
        return [_text(item) for item in value]
    return [] if value is None or value == "" else [_text(value)]


def _paras(value: object) -> list[str]:
    """Paragraphs split on blank lines, or [NONE]."""
    parts = [part.strip() for item in _strings(value) for part in item.split("\n\n")]
    return [part for part in parts if part] or [NONE]


def _sev(value: object) -> str | None:
    key = str(value).strip().lower() if isinstance(value, str) else ""
    return key if key in SEV else None


def _score(finding: dict) -> str:
    value = finding.get("cvss_score")
    ok = isinstance(value, (str, int, float)) and not isinstance(value, bool)
    return str(value) if ok else ""


def _verdict(finding: dict) -> tuple[str, str]:
    value = finding.get("verdict")
    return _text(value), "ok" if value == "confirmed" else "body_b"


def _caption(shot: dict) -> str:
    caption = _text(shot.get("caption")).strip()
    return caption if SHOT_NOTE in caption else f"{caption} {SHOT_NOTE}"


# ---- block constructors ----

def _p(runs, pp: str = "body", page_break: bool = False) -> tuple:
    return ("p", [(runs, "body")] if isinstance(runs, str) else runs, pp, page_break)


def _h(level: int, text: str, page_break: bool = False) -> tuple:
    return _p([(("■ " if level == 3 else "") + text, f"h{level}")], f"h{level}", page_break)


def _cell(content, cp="body", *, fill="cell", pp="tight", span=1, margin=None) -> dict:
    """content: one string in style cp, or paragraphs given as lists of (text, style) runs."""
    paras = [[(content, cp)]] if isinstance(content, str) else content
    return {"paras": paras, "fill": fill, "pp": pp, "span": span, "margin": margin}


def _table(rows: list, widths: list, *, header: bool = False) -> tuple:
    return ("table", rows, widths, header)


def _head(*titles: str) -> list[dict]:
    return [_cell(title, "th", fill="navy", pp="center") for title in titles]


def _rows(head: list[dict], body: list) -> list:
    return [head, *(body or [[_cell(NONE, "small", pp="center", span=len(head))]])]


def _box(paras: list, fill: str, *, pp="tight", margin=(900, 900, 450, 450)) -> tuple:
    return _table([[_cell(paras, fill=fill, pp=pp, margin=margin)]], [1])


def _kv(pairs: list, label_width: int = 24) -> tuple:
    rows = [[_cell(key, "label", fill="label"), _cell(value)] for key, value in pairs]
    return _table(rows, [label_width, 100 - label_width])


def _code(label: str, text: str) -> list[tuple]:
    lines = [[(line, "code")] for line in text.splitlines()] or [[("", "code")]]
    box = _box(lines, "code", pp="code", margin=(700, 700, 350, 350))
    return [_p([(label, "small")], "tight"), box]


def _sev_cell(severity: object, score: str = "") -> dict:
    key = _sev(severity)
    if key is None:
        return _cell(NONE, "small", pp="center")
    return _cell(f"{SEV[key][0]} {score}".strip(), "th", fill=f"sev_{key}", pp="center")


def _missing_shot(caption: str) -> tuple:
    paras = [[(SHOT_MISSING, "small")], [(caption, "hint")]]
    return _table([[_cell(paras, fill="shot", pp="center", margin=(700, 700, 900, 900))]], [1])


# ---- REPORT_SPEC.md §2 sections ----

def _period(run: dict) -> str:
    return f"{_text(run.get('started_at'))}  ~  {_text(run.get('finished_at'))}"


def _cover(model: dict, run: dict) -> list[tuple]:
    name = _text(run.get("target_name"))
    gap = _p("", "tight")
    band = [[("웹 애플리케이션", "subtitle")], [("취약점 점검 보고서", "title")],
            [("", "subtitle")], [(name, "subtitle")]]
    return [
        gap, gap, gap,
        _p([(_text(model.get("classification") or CLASSIFICATION), "conf")], "tight"),
        _box(band, "navy", margin=(1400, 1400, 1600, 1600)),
        gap, gap,
        _kv(
            [
                ("점검 대상", f"{name}  ({_text(run.get('target_origin'))})"),
                ("점검 기간", _period(run)),
                ("실행 ID", _text(run.get("run_id"))),
                ("시험 프로필", _text(run.get("profile"))),
                ("보고서 생성", _text(run.get("generated_at"))),
                ("작성", _text(run.get("author") or AUTHOR)),
                ("검토 상태", [[(_text(model.get("review_status") or REVIEW_STATUS), "sev_high")]]),
            ],
            22,
        ),
        *[gap] * 6,
        _p([(DISCLAIMER, "hint")], "tight"),
    ]


def _summary(model: dict, findings: list[dict]) -> list[tuple]:
    counts = {key: sum(_sev(f.get("severity")) == key for f in findings) for key in SEV}
    total = [[("총 발견 취약점  ", "body_b"), (f"{len(findings)}건", "h2")]]
    priority = [
        [
            _cell(str(n), pp="center"),
            _sev_cell(f.get("severity")),
            _cell(_text(f.get("title")), "body_b"),
            _cell(_text(f.get("fix_summary"))),
        ]
        for n, f in enumerate(findings, 1)
    ]
    summary = [[(part, "body")] for part in _paras(model.get("executive_summary"))]
    return [
        _h(1, "1. 점검 결과 요약", page_break=True),
        _table(
            [
                [_cell(f"{v[1]}  {v[0]}", "th", fill=f"sev_{k}", pp="center")
                 for k, v in SEV.items()],
                [_cell(str(counts[k]), f"big_{k}", pp="center", margin=(200, 200, 350, 350))
                 for k in SEV],
                [_cell(total, fill="label", pp="center", span=len(SEV))],
            ],
            [1] * len(SEV),
        ),
        _box([[("총평", "body_b")], *summary], "note"),
        _h(2, "1.1 우선 조치 권고"),
        _table(_rows(_head("순위", "심각도", "취약점", "핵심 조치"), priority), [8, 14, 36, 42],
               header=True),
    ]


def _overview(model: dict, run: dict) -> list[tuple]:
    return [
        _h(1, "2. 점검 개요"),
        _kv(
            [
                ("점검 목적", _text(model.get("objective"))),
                ("점검 범위", _text(model.get("scope"))),
                ("점검 방법", _text(model.get("method") or METHOD)),
                ("점검 기간", _period(run)),
                ("총 요청 수", _text(run.get("request_count"))),
                ("판정 기준", VERDICT_GUIDE),
            ]
        ),
    ]


def _inventory(findings: list[dict]) -> list[tuple]:
    narrow = {"pp": "center", "margin": (150, 150, 200, 200)}
    body = [
        [
            _cell(_text(f.get("id")), "small", **narrow),
            _cell(_text(f.get("title")), "body_b"),
            _cell(_text(f.get("cwe")), "small", **narrow),
            _sev_cell(f.get("severity"), _score(f)),
            _cell(_text(f.get("location")), "code"),
            _cell([[_verdict(f)]], pp="center"),
        ]
        for f in findings
    ]
    head = _head("No", "취약점명", "CWE", "심각도 (CVSS)", "발생 위치", "판정")
    return [
        _h(1, "3. 취약점 목록"),
        _table(_rows(head, body), [9, 27, 12, 13, 28, 11], header=True),
        _p([("※ 판정 — " + VERDICT_GUIDE, "hint")], "tight"),
    ]


def _finding(n: int, f: dict) -> list[tuple]:
    steps = [
        _p([(f"{i}. ", "body_b"), (step, "body")])
        for i, step in enumerate(_strings(f.get("steps")), 1)
    ]
    evidence = [
        block
        for item in _dicts(f, "evidence")
        for block in _code(_text(item.get("label")), _text(item.get("content")))
    ]
    shots = f.get("screenshots") if isinstance(f.get("screenshots"), list) else []
    shots = [shot if isinstance(shot, dict) else {"caption": shot} for shot in shots]
    checks = [
        [_cell(_text(c.get("item")), "body_b", fill="label"), _cell(_text(c.get("result")))]
        for c in _dicts(f, "checks")
    ]
    fix = [
        [("[즉시 조치]", "body_b")],
        *[[(part, "body")] for part in _paras(f.get("fix_short"))],
        [("", "body")],
        [("[근본 대책]", "body_b")],
        *[[(part, "body")] for part in _paras(f.get("fix_long"))],
    ]
    blocks = [
        _h(2, f"4.{n}  [{_text(f.get('id'))}] {_text(f.get('title'))}", page_break=n > 1),
        _table(
            [[
                _sev_cell(f.get("severity"), _score(f)),
                _cell(_text(f.get("cwe")), "body_b", fill="label", pp="center"),
                _cell([[("판정 ", "small"), _verdict(f)]], fill="label", pp="center"),
                _cell([[("필요 권한 ", "small"), (_text(f.get("privilege")), "body_b")]],
                      fill="label", pp="center"),
            ]],
            [1, 1, 1, 1],
        ),
        _kv(
            [
                ("발생 위치", [[(_text(f.get("location")), "code")]]),
                ("CVSS 3.1 벡터", [[(_text(f.get("cvss_vector")), "code")]]),
                ("finding ID", [[(_text(f.get("finding_id")), "small")]]),
            ]
        ),
        _h(3, "취약점 설명"),
        *[_p(part) for part in _paras(f.get("description"))],
        _h(3, "영향"),
        *[_p(part) for part in _paras(f.get("impact"))],
        _h(3, "재현 절차"),
        *(steps or [_p(NONE)]),
        _h(3, "증거"),
        *(evidence or [_p(NONE)]),
        *[("image", _caption(shot), shot.get("ref")) for shot in shots],
        _h(3, "판정 근거"),
        _table(_rows(_head("검사 항목", "결과"), checks), [30, 70], header=True),
        _h(3, "조치 방안"),
        _box(fix, "fix"),
    ]
    if f.get("limitations"):
        blocks += [_h(3, "검증 한계"), *[_p([(p, "small")]) for p in _paras(f["limitations"])]]
    if references := _strings(f.get("references")):
        blocks.append(_p([("참고: ", "hint"), (" · ".join(references), "hint")], "tight"))
    return blocks


def _details(run: dict, findings: list[dict]) -> list[tuple]:
    blocks = [_h(1, "4. 취약점 상세", page_break=True)]
    if run.get("status") == "failed" or run.get("incomplete") is True:
        blocks.append(_box([[(INCOMPLETE, "sev_high")]], "note"))
    for n, finding in enumerate(findings, 1):
        blocks += _finding(n, finding)
    return blocks if findings else [*blocks, _p(NONE)]


def _limits(model: dict) -> list[tuple]:
    return [
        _h(1, "5. 점검 한계 및 면책", page_break=True),
        *[_p(part) for part in _paras(model.get("run_limitations"))],
        _p([(DISCLAIMER, "small")]),
    ]


def _severity_guide() -> list[tuple]:
    body = [[_sev_cell(k), _cell(v[3], pp="center"), _cell(v[4])] for k, v in SEV.items()]
    return [
        _h(1, "부록 A. 심각도 기준 (CVSS 3.1)"),
        _table(_rows(_head("등급", "점수", "의미 및 조치 권고"), body), [16, 16, 68], header=True),
    ]


def _appendix_b(model: dict) -> list[tuple]:
    sources = [
        [
            _cell(_text(s.get("collector")), "body_b", fill="label"),
            _cell(_text(s.get("kind")), "code"),
            _cell(_text(s.get("status")), "ok" if s.get("status") in SOURCE_OK else "body_b",
                  pp="center"),
            _cell(_text(s.get("note"))),
        ]
        for s in _dicts(model, "sources")
    ]
    history = [
        [
            _cell(_text(h.get("date")), "small", pp="center"),
            _cell(_text(h.get("finding"))),
            _cell(_text(h.get("result"))),
        ]
        for h in _dicts(model, "history")
    ]
    omitted = [_p([("• ", "small"), (item, "small")], "tight")
               for item in _strings(model.get("omitted"))]
    return [
        _h(1, "부록 B. 증적 출처 및 재점검 이력"),
        _h(2, "B.1 증적 수집 상태"),
        _table(_rows(_head("수집기", "원천", "상태", "비고"), sources), [22, 26, 14, 38],
               header=True),
        _h(2, "B.2 재점검 이력"),
        _table(_rows(_head("일시", "대상 취약점", "결과"), history), [20, 40, 40], header=True)
        if history
        else _p([("재점검 이력이 없습니다.", "small")]),
        _h(2, "B.3 생략된 정보"),
        *(omitted or [_p([(NONE, "small")])]),
        *_reference_review(model),
    ]


def _reference_review(model: dict) -> list[tuple]:
    """casper referenceContext: review state of reference material, never a verdict."""
    context = _obj(model, "referenceContext")
    if not context:
        return []
    intake = _obj(context, "intake")
    external = _obj(context, "external")
    blocks = [
        _h(2, "B.4 참고 자료의 검토 상태와 미확정 사항"),
        _p(
            "등록·검토 상태는 현재 대상의 재현 판정과 별개입니다. "
            "이 자료는 자동 실행 권한을 부여하지 않습니다."
        ),
        _p(
            f"보고서 자료 조회: {_text(intake.get('status'))} / "
            f"외부 권고 조회: {_text(external.get('status'))}"
        ),
    ]
    for finding in _dicts(context, "findings"):
        candidate = _obj(finding, "candidate")
        review = _obj(finding, "review")
        blocks += [
            _h(3, _text(candidate.get("title"))),
            _kv(
                [
                    ("원문 위치", _text(finding.get("source_ref"))),
                    ("대상 경로", _text(candidate.get("endpoint"))),
                    ("등록 상태", _text(finding.get("registration_state"))),
                    ("재현 평가", _text(finding.get("reproduction_state"))),
                    ("검토 결정", _text(review.get("decision"))),
                    (
                        "검토자·시각",
                        f"{_text(review.get('reviewer'))} / {_text(review.get('reviewed_at'))}",
                    ),
                    ("검토 근거", _text(review.get("reason"))),
                    ("원문 누락 필드", _text(finding.get("missing_fields"))),
                    ("후보 미확정 필드", _text(finding.get("unresolved_fields"))),
                    ("등록 전 보완 필드", _text(finding.get("remaining_fields"))),
                ]
            ),
            _p(f"확인된 서술: {_text(candidate.get('description'))}"),
        ]
        for variant in _dicts(finding, "payload_variants"):
            blocks += _code(
                f"원문 payload 표현 ({_text(variant.get('representation'))}) — "
                f"{_text(variant.get('source_ref'))}",
                _text(variant.get("value")),
            )
        for field, resolution in _obj(review, "resolutions").items():
            blocks.append(_p(f"검토 보완 {_text(field)}: {_text(resolution)}"))
    for record in _dicts(external, "records"):
        blocks += [
            _h(3, f"외부 권고 {_text(record.get('cve_id'))}"),
            _p(_text(record.get("description"))),
            _kv(
                [
                    ("대상 적용 여부", _text(record.get("applicability"))),
                    ("공식 권고 심각도", _text(record.get("severity"))),
                    ("영향 제품·버전", _text(record.get("affected"))),
                    ("권고 출처", _text(record.get("source"))),
                    ("권고 링크", _text(record.get("references"))),
                    ("철회 여부", _text(record.get("withdrawn"))),
                ]
            ),
        ]
    for item in _dicts(context, "unresolved_requests"):
        blocks.append(
            _p(
                f"입력 위치 확인 필요: {_text(item.get('method'))} "
                f"{_text(item.get('endpoint'))} — {_text(item.get('reason'))}"
            )
        )
    for assessment in _dicts(external, "assessments"):
        blocks += [
            _h(3, f"대상 버전 대조 {_text(assessment.get('cve_id'))}"),
            _kv(
                [
                    ("영향 버전 대조", _text(assessment.get("decision"))),
                    ("현재 자료 기준 여부", _text(assessment.get("current"))),
                    ("구성 정보 관찰 시각", _text(assessment.get("inventory_observed_at"))),
                    ("판정 근거", _text(assessment.get("reason"))),
                    ("버전·원문 근거", _text(assessment.get("component_matches"))),
                    ("재현 상태", _text(assessment.get("reproduction_state"))),
                ]
            ),
        ]
    for source in (intake, external):
        if source.get("reason"):
            blocks.append(_p(f"조회 한계: {_text(source['reason'])}"))
    if external.get("not_found_cve_ids"):
        blocks.append(_p(f"저장된 외부 권고 없음: {_text(external['not_found_cve_ids'])}"))
    return blocks


def build_blocks(model: dict) -> list[tuple]:
    model = model if isinstance(model, dict) else {}
    run, findings = _obj(model, "run"), _dicts(model, "findings")
    return [
        *_cover(model, run),
        *_summary(model, findings),
        *_overview(model, run),
        *_inventory(findings),
        *_details(run, findings),
        *_limits(model),
        *_severity_guide(),
        *_appendix_b(model),
    ]


def _load_png(ref: object, image_root) -> tuple[bytes, float, float] | None:
    """PNG bytes and (width, height) in mm, or None unless the file is intact and inside root."""
    if image_root is None or not isinstance(ref, str) or not ref:
        return None
    try:
        root = Path(image_root).resolve()
        path = (root / ref).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            return None
        if path.stat().st_size > PHOTO_MAX_BYTES:
            return None
        data = path.read_bytes()
    except (OSError, ValueError):
        return None
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", data[16:24])
    if not width or not height:
        return None
    width_mm, height_mm = PHOTO_WIDTH_MM, PHOTO_WIDTH_MM * height / width
    if height_mm > PHOTO_MAX_HEIGHT_MM:  # a tall capture must still fit one page
        width_mm, height_mm = width_mm * PHOTO_MAX_HEIGHT_MM / height_mm, PHOTO_MAX_HEIGHT_MM
    return data, max(width_mm, 1.0), max(height_mm, 1.0)  # extreme aspect ratios stay visible


# ---- HWPX ----

def write_hwpx(model: dict, out_path, *, image_root=None) -> Path:
    # HwpxDocument.new() is A4 with 30 mm side margins: the kit's 42520-HWPUNIT text width.
    doc = HwpxDocument.new()
    styles = doc.styles
    char = {name: styles.ensure_run(**{"font": BODY_FONT, **spec}) for name, spec in CHAR.items()}
    para = {
        (name, brk): styles.ensure_paragraph_format(
            alignment=align,
            line_spacing_percent=spacing,
            margins={"prev": before, "next": after},
            break_setting={"keep_with_next": name.startswith("h"), "page_break_before": brk},
        )
        for name, (align, before, after, spacing) in PARA.items()
        for brk in ((False, True) if name in ("h1", "h2") else (False,))
    }
    fill = {
        name: styles.ensure_border_fill(fill_color=face, border_color=line, border_type=kind)
        for name, (face, line, kind) in FILL.items()
    }

    def write_runs(add, runs, pp_id):
        (text, cp), *rest = runs or [("", "body")]
        paragraph = add(text, para_pr_id_ref=pp_id, char_pr_id_ref=char[cp])
        for text, cp in rest:
            paragraph.add_run(text, char_pr_id_ref=char[cp])

    def write_table(rows, widths, header):
        table = doc.add_table(
            len(rows),
            len(widths),
            border_fill_id_ref=fill["cell"],
            para_pr_id_ref=para["tight", False],
            char_pr_id_ref=char["body"],
        )
        table.set_column_widths(widths)
        for r, row in enumerate(rows):
            c = 0
            for spec in row:
                end = c + spec["span"] - 1
                cell = table.merge_cells(r, c, r, end) if end > c else table.cell(r, c)
                table.set_cell_border_fill(r, c, fill[spec["fill"]])
                stale = cell.paragraphs
                for runs in spec["paras"]:
                    write_runs(cell.add_paragraph, runs, para[spec["pp"], False])
                for paragraph in stale:
                    paragraph.remove()
                if spec["margin"]:
                    left, right, top, bottom = spec["margin"]
                    cell.set_margins(left=left, right=right, top=top, bottom=bottom)
                if header and r == 0:
                    cell.element.set("header", "1")  # no API marks a header cell
                c = end + 1
        if header:
            table.element.set("repeatHeader", "1")  # no API repeats the header row per page
        doc.add_paragraph("", para_pr_id_ref=para["tight", False], char_pr_id_ref=char["body"])

    for block in build_blocks(model):
        kind = block[0]
        if kind == "p":
            write_runs(doc.add_paragraph, block[1], para[block[2], block[3]])
        elif kind == "table":
            write_table(*block[1:])
        else:
            caption, ref = block[1], block[2]
            loaded = _load_png(ref, image_root)
            if loaded is None:
                write_table(*_missing_shot(caption)[1:])
                continue
            data, width_mm, height_mm = loaded
            doc.add_picture(data, "png", width_mm=width_mm, height_mm=height_mm,
                            para_pr_id_ref=para["center", False])
            write_runs(doc.add_paragraph, [(caption, "small")], para["center", False])
    report = doc.validate()
    if not report.ok:
        raise ValueError(f"HWPX validation failed: {report.issues}")
    out = Path(out_path)
    doc.save_to_path(out)
    return out


# ---- Markdown preview ----

def _md(value: str, *, cell: bool = False) -> str:
    text = html.escape(value, quote=True)
    return text.replace("|", "\\|").replace("\n", "<br>") if cell else text


def _plain(runs: list) -> str:
    return "".join(text for text, _ in runs)


def _md_row(row: list[dict]) -> str:
    parts: list[str] = []
    for cell in row:  # a spanning cell is followed by empty cells to keep the column count
        text = "\n".join(_plain(runs) for runs in cell["paras"])
        parts += [_md(text, cell=True)] + [""] * (cell["span"] - 1)
    return "| " + " | ".join(parts) + " |"


def write_markdown(model: dict, out_path) -> Path:
    """Preview without the HWP program; HTML-escaped, with `|` and newlines handled in tables."""
    lines: list[str] = []
    for block in build_blocks(model):
        kind = block[0]
        if kind == "p":
            text = _md(_plain(block[1]))
            if text.strip():
                marks = {"h1": "# ", "h2": "## ", "h3": "### "}.get(block[2], "")
                lines += [marks + text, ""]
        elif kind == "table":
            rows, widths, header = block[1:]
            if len(rows) == 1 and len(rows[0]) == 1:  # a box
                cell = rows[0][0]
                texts = [_plain(runs) for runs in cell["paras"]]
                if cell["fill"] == "code":
                    lines += ["<pre>" + _md("\n".join(texts)) + "</pre>", ""]
                else:
                    lines += [("> " + _md(text)).rstrip() for text in texts] + [""]
                continue
            grid = [_md_row(row) for row in rows]
            head = grid.pop(0) if header else "|" + "  |" * len(widths)
            lines += [head, "|" + " --- |" * len(widths), *grid, ""]
        else:
            lines += [_md(f"[화면 캡처] {block[1]}"), ""]  # no bundle path in the report
    out = Path(out_path)
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


# ---- HTML preview ----

def _css(cp: str) -> str:
    spec = CHAR[cp]
    css = f"color:{spec['color']};font-size:{spec['size']}pt"
    css += ";font-weight:700" if spec.get("bold") else ""
    return css + (";font-family:D2Coding,monospace" if spec.get("font") else "")


def _html_runs(runs: list) -> str:
    return "".join(
        f'<span style="{_css(cp)}">{html.escape(text, quote=True)}</span>' for text, cp in runs
    )


def _html_table(rows: list, widths: list, header: bool) -> list[str]:
    total = sum(widths)
    lines = ["<table><colgroup>"]
    lines += [f'<col style="width:{100 * w / total:.1f}%">' for w in widths]
    lines.append("</colgroup><tbody>")
    for r, row in enumerate(rows):
        tag = "th" if header and r == 0 else "td"
        cells = []
        for cell in row:
            face = FILL[cell["fill"]][0] or "#FFFFFF"
            align = "center" if cell["pp"] == "center" else "left"
            body = "".join(f"<div>{_html_runs(runs)}</div>" for runs in cell["paras"])
            cells.append(
                f'<{tag} colspan="{cell["span"]}" style="background:{face};text-align:{align}">'
                f"{body}</{tag}>"
            )
        lines.append("<tr>" + "".join(cells) + "</tr>")
    return [*lines, "</tbody></table>"]


def write_html(model: dict, out_path, *, image_root=None) -> Path:
    """Self-contained, inert preview of the same blocks rendered into the HWPX document."""
    lines = [
        "<!doctype html>",
        '<html lang="ko"><head><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>CA3P 보고서 미리보기</title>",
        "<style>body{font:15px/1.6 '함초롬돋움',system-ui,sans-serif;color:#222;max-width:960px;"
        "margin:0 auto;padding:32px 24px;background:#fff}h1,h2,h3{line-height:1.3;"
        "margin:1.6em 0 .6em}p,div{white-space:pre-wrap;overflow-wrap:anywhere}"
        ".pb{break-before:page}table{border-collapse:collapse;width:100%;margin:.6em 0 1em;"
        "table-layout:fixed}th,td{border:1px solid #C7D7EA;padding:.45em .6em;"
        "vertical-align:middle}figure{margin:1.2em 0;text-align:center}"
        "img{display:block;max-width:100%;height:auto;margin:0 auto}"
        "figcaption{font-size:.85em;color:#595959;margin-top:.4em}</style></head><body>",
    ]
    for block in build_blocks(model):
        kind = block[0]
        if kind == "p":
            runs, pp, brk = block[1:]
            if not _plain(runs).strip():
                continue
            tag = pp if pp in ("h1", "h2", "h3") else "p"
            attrs = ' class="pb"' if brk else ""
            lines.append(f"<{tag}{attrs}>{_html_runs(runs)}</{tag}>")
        elif kind == "table":
            lines += _html_table(*block[1:])
        else:
            caption, ref = block[1], block[2]
            loaded = _load_png(ref, image_root)
            if loaded is None:
                lines += _html_table(*_missing_shot(caption)[1:])
                continue
            encoded = base64.b64encode(loaded[0]).decode("ascii")
            text = html.escape(caption, quote=True)
            lines.append(
                f'<figure><img src="data:image/png;base64,{encoded}" alt="{text}">'
                f"<figcaption>{text}</figcaption></figure>"
            )
    lines.append("</body></html>")
    out = Path(out_path)
    out.write_text("\n".join(lines), encoding="utf-8")
    return out
