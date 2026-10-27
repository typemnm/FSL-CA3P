"""Render a ReportModel (`report-1.0`, PLAN 4.3) into one .hwpx following the PLAN 2.7 outline.

The writer renders what it is given and verifies nothing (PLAN 1.4.1). Every python-hwpx call
lives in this file (PLAN 3.5). Text goes in only through text-node APIs, which XML-escape it;
raw XML is never inserted. The outline is built once as a block list and rendered to HWPX or to
a Markdown preview, so both outputs carry the same sections.
"""

from __future__ import annotations

import html
import json
import struct
from pathlib import Path

from hwpx import HwpxDocument

NONE = "자료 없음"
COVER_NOTICES = (
    "이 보고서는 격리된 실습 환경에서 수행한 점검 결과입니다.",
    "현재 데이터는 모두 synthetic(가상) 데이터입니다.",
    "exploit 판정은 상류 에이전트가 전달한 값이며, 보고서 모듈은 판정을 검증하지 않습니다.",
    "과거 사례와의 위치 일치는 재점검 후보일 뿐 현재 취약 판정이 아닙니다.",
)
VERDICT_CAVEAT = (
    "에이전트의 결정론적 판정(전달받음)이며, 보고서 모듈과 저장소는 검증하지 않았습니다."
)
CVSS_NOTE = "LLM이 CVSS 3.1로 산출한 값이며, 재계산·검증하지 않았습니다."
TRIAGE_CAVEAT = "위치 일치는 재점검 후보일 뿐 현재 취약 판정이 아닙니다."
CHECK_FOOTNOTE = (
    "상태 열은 상태 표시일 뿐 취약 판정이 아닙니다. "
    "파일 해시는 번들 무결성 확인에만 쓰며 본문에는 표기하지 않습니다."
)
PHOTO_NOTE = "이 사진은 보조 자료이며 판정 근거가 아닙니다."
PHOTO_MISSING = "[사진] 무결성 불일치/자료 없음: 해당 사진을 싣지 않았습니다."
PHOTO_WIDTH_MM = 150.0


def _obj(parent: object, key: str) -> dict:
    """A nested object, or {} when the model holds something else there (LLM-built input)."""
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
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _kv_rows(mapping: object) -> list[list[str]]:
    if not isinstance(mapping, dict) or not mapping:
        return [["항목", NONE]]
    # Hashes prove bytes, not vulnerabilities; they stay out of the body (PLAN Q13).
    return [
        [str(key), _text(value)]
        for key, value in mapping.items()
        if "hash" not in str(key).lower() and "sha256" not in str(key).lower()
    ] or [["항목", NONE]]


def _location(common: dict) -> str:
    loc = common.get("location") or {}
    if not isinstance(loc, dict):
        return _text(loc)
    where = " ".join(str(loc[k]) for k in ("method", "path") if loc.get(k))
    if loc.get("parameter"):
        where = f"{where} (파라미터: {loc['parameter']})".strip()
    return where or NONE


def _cvss(common: dict) -> tuple[str, str]:
    cvss = _obj(common, "cvss")
    score = f"{_text(cvss.get('score'))} ({_text(cvss.get('rating'))})" if cvss else NONE
    return score, f"CVSS {cvss.get('version', '3.1')} {_text(cvss.get('vector'))}"


def _cover(model: dict) -> list[tuple]:
    run = _obj(model, "run")
    return [
        ("h", 1, f"CA3P 취약점 점검 보고서 — {_text(run.get('runId'))}"),
        ("p", f"생성일: {_text(model.get('generatedAt'))}"),
        ("box", [*COVER_NOTICES, *(_text(n) for n in model.get("notices") or [])]),
    ]


def _overview(run: dict) -> list[tuple]:
    metrics = run.get("metrics")
    metrics = metrics if isinstance(metrics, dict) else {}
    requests = metrics.get("requests", metrics.get("requestCount"))
    return [
        ("h", 1, "1. 점검 개요"),
        (
            "table",
            [
                ["실행 ID", _text(run.get("runId"))],
                ["상태", _text(run.get("status"))],
                ["시험 프로필", _text(run.get("testProfile"))],
                ["공격 대상(origin)", _text(_obj(run, "target").get("origin"))],
                ["시작 시각", _text(run.get("startedAt"))],
                ["종료 시각", _text(run.get("completedAt"))],
                ["요청 수", _text(requests)],
            ],
        ),
    ]


def _summary(model: dict, failed: bool) -> list[tuple]:
    blocks: list[tuple] = [("h", 1, "2. 취약점 요약")]
    findings = _dicts(model, "findings")
    if not failed and not findings and _obj(model, "referenceContext"):
        return [
            ("h", 1, "2. 취약점 요약"),
            (
                "p",
                "현재 실행의 취약점 상세 항목이 없습니다. 참고 자료의 검토 대기 항목과 "
                "입력 위치 확인 필요 사항은 별도 검토 상태 절에 포함했습니다.",
            ),
        ]
    if failed or not findings:
        reason = "실행이 실패하여" if failed else "보고된 취약점이 없어"
        return [*blocks, ("p", f"{reason} 요약할 취약점이 없습니다.")]
    origin = _text(_obj(_obj(model, "run"), "target").get("origin"))
    rows = [["번호", "취약점", "CWE", "CVSS 점수·등급", "공격 대상", "exploit 여부(판정 상태)"]]
    for index, finding in enumerate(findings, 1):
        common = _obj(finding, "common")
        rows.append(
            [
                str(index),
                _text(common.get("title")),
                _text(common.get("cwe")),
                _cvss(common)[0],
                origin,
                _text(common.get("status")),
            ]
        )
    return [*blocks, ("table", rows), ("p", f"CVSS: {CVSS_NOTE} 판정 상태: {VERDICT_CAVEAT}")]


def _finding(n: int, finding: dict) -> list[tuple]:
    common = _obj(finding, "common")
    score, vector = _cvss(common)
    blocks: list[tuple] = [
        ("h", 2, f"3.{n} {_text(common.get('title'))}"),
        ("h", 3, f"3.{n}.1 기본 정보"),
        (
            "table",
            [
                ["취약점 유형", f"{_text(common.get('title'))} ({_text(common.get('cwe'))})"],
                ["발생 위치", _location(common)],
                [
                    "심각도",
                    f"{vector} / {score} — {CVSS_NOTE} 상류 severity: "
                    f"{_text(common.get('severity'))}",
                ],
                ["판정 상태", f"{_text(common.get('status'))} — {VERDICT_CAVEAT}"],
                ["상세 설명", _text(common.get("summary"))],
                ["조치 방안", _text(common.get("remediation"))],
                ["한계", _text(common.get("limitations"))],
            ],
        ),
        ("h", 3, f"3.{n}.2 재현 절차"),
    ]
    images = _dicts(finding, "images")
    steps = finding.get("reproduction") or []
    for step, item in enumerate(steps, 1):
        text = item.get("text") if isinstance(item, dict) else item
        blocks.append(("p", f"{step}. {_text(text)}"))
        blocks += [("image", image) for image in images if image.get("step") == step]
    if not steps:
        blocks.append(("p", NONE))
    linked = range(1, len(steps) + 1)
    blocks += [("image", image) for image in images if image.get("step") not in linked]

    blocks.append(("h", 3, f"3.{n}.3 텍스트 증거"))
    for evidence in _dicts(finding, "textEvidence") or [{"label": "증거", "text": None}]:
        blocks += [("p", _text(evidence.get("label"))), ("code", _text(evidence.get("text")))]

    checks = _dicts(finding, "checks")
    blocks += [
        ("h", 3, f"3.{n}.4 판정 검사표"),
        (
            "table",
            [["레이블", "결과"]] + [[_text(c.get("label")), _text(c.get("result"))] for c in checks]
            if checks
            else [["레이블", "결과"], [NONE, NONE]],
        ),
        ("h", 3, f"3.{n}.5 영향"),
        ("p", _text(finding.get("impact"))),
        ("h", 3, f"3.{n}.6 기타 정보"),
        ("table", _kv_rows(finding.get("profileData"))),
    ]
    return blocks


def _failure(run: dict) -> list[tuple]:
    error = _obj(run, "error")
    return [
        ("h", 1, "3. 실행 실패"),
        ("p", "실행이 실패하여 취약점 상세 대신 실패 정보를 적습니다."),
        (
            "table",
            [
                ["오류 코드", _text(error.get("code"))],
                ["발생 위치(source)", _text(error.get("source"))],
                ["메시지", _text(error.get("message"))],
                ["도달한 단계", _text(error.get("stage"))],
            ],
        ),
    ]


def _history(model: dict) -> list[tuple]:
    triage = _obj(model, "triage")
    blocks: list[tuple] = [("h", 1, "4. 과거 사례 대조(재점검 triage)"), ("p", TRIAGE_CAVEAT)]
    rows = _dicts(triage, "rows")
    if triage.get("status") == "unavailable" or not rows:
        blocks.append(("p", f"대조 결과가 없습니다. 사유: {_text(triage.get('reason'))}"))
    else:
        blocks.append(
            (
                "table",
                [["사례", "위치", "대조 결과"]]
                + [
                    [_text(r.get("caseId")), _text(r.get("location")), _text(r.get("label"))]
                    for r in rows
                ],
            )
        )

    cases = _dicts(model, "priorCases")
    blocks.append(("h", 1, "5. 관련 전월 보고서"))
    if not cases:
        blocks.append(("p", "관련 전월 보고서가 없습니다."))
    for case in cases:
        blocks += [
            (
                "h",
                2,
                f"{_text(case.get('caseId'))} (대조 당시 revision {_text(case.get('revision'))})",
            ),
            ("table", _kv_rows({k: v for k, v in case.items() if k != "checks"})),
        ]

    checks = [(case, check) for case in cases for check in _dicts(case, "checks")]
    blocks.append(("h", 1, "6. 재점검 이력"))
    if checks:
        blocks.append(
            (
                "table",
                [["사례", "check", "상태(상태 표시)", "시각"]]
                + [
                    [
                        _text(case.get("caseId")),
                        _text(c.get("checkId")),
                        _text(c.get("status")),
                        _text(c.get("reviewedAt") or c.get("createdAt")),
                    ]
                    for case, c in checks
                ],
            )
        )
    else:
        blocks.append(("p", "재점검 이력이 없습니다."))
    return [*blocks, ("p", CHECK_FOOTNOTE)]


def _reference_review(model: dict) -> list[tuple]:
    context = _obj(model, "referenceContext")
    if not context:
        return []
    intake = _obj(context, "intake")
    external = _obj(context, "external")
    blocks: list[tuple] = [
        ("h", 1, "참고 자료의 검토 상태와 미확정 사항"),
        (
            "p",
            "등록·검토 상태는 현재 대상의 재현 판정과 별개입니다. "
            "이 자료는 자동 실행 권한을 부여하지 않습니다.",
        ),
        (
            "p",
            f"보고서 자료 조회: {_text(intake.get('status'))} / "
            f"외부 권고 조회: {_text(external.get('status'))}",
        ),
    ]
    for finding in _dicts(context, "findings"):
        candidate = _obj(finding, "candidate")
        review = _obj(finding, "review")
        blocks += [
            ("h", 2, _text(candidate.get("title"))),
            (
                "table",
                [
                    ["원문 위치", _text(finding.get("source_ref"))],
                    ["대상 경로", _text(candidate.get("endpoint"))],
                    ["등록 상태", _text(finding.get("registration_state"))],
                    ["재현 평가", _text(finding.get("reproduction_state"))],
                    ["검토 결정", _text(review.get("decision"))],
                    [
                        "검토자·시각",
                        f"{_text(review.get('reviewer'))} / {_text(review.get('reviewed_at'))}",
                    ],
                    ["검토 근거", _text(review.get("reason"))],
                    ["원문 누락 필드", _text(finding.get("missing_fields"))],
                    ["후보 미확정 필드", _text(finding.get("unresolved_fields"))],
                    ["등록 전 보완 필드", _text(finding.get("remaining_fields"))],
                ],
            ),
            ("p", f"확인된 서술: {_text(candidate.get('description'))}"),
        ]
        for variant in _dicts(finding, "payload_variants"):
            blocks += [
                (
                    "p",
                    f"원문 payload 표현 ({_text(variant.get('representation'))}) — "
                    f"{_text(variant.get('source_ref'))}",
                ),
                ("code", _text(variant.get("value"))),
            ]
        for field, resolution in _obj(review, "resolutions").items():
            blocks.append(("p", f"검토 보완 {field}: {_text(resolution)}"))
    for record in _dicts(external, "records"):
        blocks += [
            ("h", 2, f"외부 권고 {_text(record.get('cve_id'))}"),
            ("p", _text(record.get("description"))),
            (
                "table",
                [
                    ["대상 적용 여부", _text(record.get("applicability"))],
                    ["공식 권고 심각도", _text(record.get("severity"))],
                    ["영향 제품·버전", _text(record.get("affected"))],
                    ["권고 출처", _text(record.get("source"))],
                    ["권고 링크", _text(record.get("references"))],
                    ["철회 여부", _text(record.get("withdrawn"))],
                ],
            ),
        ]
    for item in _dicts(context, "unresolved_requests"):
        blocks.append(
            (
                "p",
                f"입력 위치 확인 필요: {_text(item.get('method'))} "
                f"{_text(item.get('endpoint'))} — {_text(item.get('reason'))}",
            )
        )
    for assessment in _dicts(external, "assessments"):
        blocks += [
            ("h", 2, f"대상 버전 대조 {_text(assessment.get('cve_id'))}"),
            (
                "table",
                [
                    ["영향 버전 대조", _text(assessment.get("decision"))],
                    ["현재 자료 기준 여부", _text(assessment.get("current"))],
                    ["구성 정보 관찰 시각", _text(assessment.get("inventory_observed_at"))],
                    ["판정 근거", _text(assessment.get("reason"))],
                    ["버전·원문 근거", _text(assessment.get("component_matches"))],
                    ["재현 상태", _text(assessment.get("reproduction_state"))],
                ],
            ),
        ]
    for source in (intake, external):
        if source.get("reason"):
            blocks.append(("p", f"조회 한계: {_text(source['reason'])}"))
    if external.get("not_found_cve_ids"):
        blocks.append(("p", f"저장된 외부 권고 없음: {_text(external['not_found_cve_ids'])}"))
    return blocks


def _safety(model: dict) -> list[tuple]:
    decisions = _dicts(_obj(model, "guardrail"), "decisions")
    rows = [["결정", "규칙", "사유"]] + [
        [_text(d.get("decision")), _text(d.get("ruleId")), _text(d.get("reason"))]
        for d in decisions
    ]
    return [
        ("h", 1, "7. 가드레일 결정과 안전 속성"),
        ("table", rows if decisions else [*rows, [NONE, NONE, NONE]]),
        ("table", _kv_rows(model.get("safety"))),
    ]


def _sources(model: dict) -> list[tuple]:
    refs = _obj(model, "references")
    collectors = _dicts(refs, "collectors")
    omitted = _dicts(refs, "omittedSections")
    blocks: list[tuple] = [
        ("h", 1, "8. 출처와 한계"),
        ("p", f"프로필: {_text(_obj(model, 'generator').get('profile'))}"),
        (
            "table",
            [["수집기", "원천 종류", "상태", "사유"]]
            + [
                [
                    _text(c.get("name")),
                    _text(c.get("driver")),
                    _text(c.get("status")),
                    _text(c.get("reason")),
                ]
                for c in collectors
            ]
            if collectors
            else [["수집기", "상태"], [NONE, NONE]],
        ),
    ]
    if "verifiedByStorage" in refs:
        verified = _text(refs["verifiedByStorage"])
        blocks.append(("p", f"저장소 검증 여부(verifiedByStorage): {verified}"))
    blocks += [
        ("p", f"생략된 섹션: {_text(o.get('section'))} — 사유: {_text(o.get('reason'))}")
        for o in omitted
    ]
    return [*blocks, ("p", "이 보고서는 초안이며, 사람이 최종 검토한 뒤 배포합니다.")]


def build_blocks(model: dict) -> list[tuple]:
    run = _obj(model, "run")
    failed = run.get("status") == "failed"
    body = (
        _failure(run)
        if failed
        else [("h", 1, "3. 취약점 상세")]
        + [block for n, f in enumerate(_dicts(model, "findings"), 1) for block in _finding(n, f)]
    )
    return [
        *_cover(model),
        *_overview(run),
        *_summary(model, failed),
        *body,
        *_history(model),
        *_reference_review(model),
        *_safety(model),
        *_sources(model),
    ]


def _caption(image: dict) -> str:
    return f"{_text(image.get('caption'))} — {PHOTO_NOTE}"


def _load_png(image: dict, image_root: Path | None) -> tuple[bytes, float] | None:
    """PNG bytes and height in mm, or None unless the file is intact and inside image_root."""
    if image_root is None or image.get("integrity") != "ok" or not image.get("ref"):
        return None
    root = Path(image_root).resolve()
    path = (root / str(image["ref"])).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        return None
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n" or len(data) < 24:
        return None
    width, height = struct.unpack(">II", data[16:24])
    if not width or not height:
        return None
    return data, PHOTO_WIDTH_MM * height / width


def write_hwpx(model: dict, out_path, *, image_root=None) -> Path:
    doc = HwpxDocument.new()
    mono = doc.styles.ensure_run(font="D2Coding")
    for block in build_blocks(model):
        kind = block[0]
        if kind == "h":
            doc.add_heading(block[2], level=block[1])
        elif kind == "p":
            doc.add_paragraph(block[1])
        elif kind == "code":
            for line in block[1].splitlines() or [""]:
                doc.add_paragraph(line, char_pr_id_ref=mono)
        elif kind in ("table", "box"):
            rows = block[1] if kind == "table" else [["\n".join(block[1])]]
            table = doc.add_table(len(rows), len(rows[0]))
            for r, row in enumerate(rows):
                for c, cell in enumerate(row):
                    table.set_cell_text(r, c, cell)
        elif kind == "image":
            loaded = _load_png(block[1], image_root)
            if loaded is None:
                doc.add_paragraph(PHOTO_MISSING)
            else:
                doc.add_picture(loaded[0], "png", width_mm=PHOTO_WIDTH_MM, height_mm=loaded[1])
                doc.add_paragraph(_caption(block[1]))
    report = doc.validate()
    if not report.ok:
        raise ValueError(f"HWPX validation failed: {report.issues}")
    out = Path(out_path)
    doc.save_to_path(out)
    return out


def _md(value: str, *, cell: bool = False) -> str:
    text = html.escape(value, quote=True)
    return text.replace("|", "\\|").replace("\n", "<br>") if cell else text


def write_markdown(model: dict, out_path) -> Path:
    """Preview without the HWP program; HTML-escaped, with `|` and newlines handled in tables."""
    lines: list[str] = []
    for block in build_blocks(model):
        kind = block[0]
        if kind == "h":
            lines += ["#" * block[1] + " " + _md(block[2]), ""]
        elif kind == "p":
            lines += [_md(block[1]), ""]
        elif kind == "code":
            lines += ["<pre>" + _md(block[1]) + "</pre>", ""]
        elif kind == "box":
            lines += ["> " + _md(line) for line in block[1]] + [""]
        elif kind == "table":
            rows = block[1]
            lines.append("| " + " | ".join(_md(c, cell=True) for c in rows[0]) + " |")
            lines.append("|" + " --- |" * len(rows[0]))
            lines += ["| " + " | ".join(_md(c, cell=True) for c in row) + " |" for row in rows[1:]]
            lines.append("")
        elif kind == "image":
            image = block[1]
            text = (
                f"[사진: {image.get('ref')}] {_caption(image)}"
                if image.get("integrity") == "ok"
                else PHOTO_MISSING
            )
            lines += [_md(text), ""]
    out = Path(out_path)
    out.write_text("\n".join(lines), encoding="utf-8")
    return out
