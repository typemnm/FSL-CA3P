"""Conservative, offline classification of report statements with exact text spans."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .field_values import is_unknown
from .report_drafts import FieldEvidence, FindingDraft, ReviewIssue

VERSION = "narrative-rules-3"
_NAME = r"[A-Za-z_](?:[A-Za-z0-9_.\[\]-]{0,62}[A-Za-z0-9_\[\]-])?"
_QUOTE = r"[\x60'\"“”‘’]*"
_PARAMETERS = [
    re.compile(
        rf"(?:파라미터|매개변수|입력\s*항목|입력값\s*(?:이름|명))"
        rf"(?:\s*(?:이름|명))?\s*(?:는|은|인|가|[:：])?\s*{_QUOTE}(?P<name>{_NAME})"
    ),
    re.compile(rf"(?<![A-Za-z0-9_])(?P<name>{_NAME}){_QUOTE}\s*(?:라는\s*)?(?:파라미터|매개변수)"),
    re.compile(
        rf"(?:본문|내용|제목|댓글|검색어|필드)\s*[\(（]\s*(?P<name>{_NAME})\s*[\)）]"
        rf"\s*(?:입력값|파라미터|매개변수)"
    ),
]
_ANOTHER = re.compile(rf"\s*{_QUOTE}\s*(?:와|과|또는|혹은|및|,)\s*{_QUOTE}(?P<name>{_NAME})")
_RESERVED = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "HTTP", "URL", "JSON"}
_CAPTION = re.compile(r"^\s*[<〈＜]?\s*(?:그림|표|figure|table)\s*\d", re.I)
_CODE = re.compile(
    r"^\s*(?:\x60{3}|https?://|<script\b|document\.|(?:var|let|const)\s+|"
    r"[\(（]?(?:URL\s*인코딩|URL[- ]?encoded)\s*[:：]|"
    r"[\"'“”‘’]?\d+[^가-힣]*alert\s*\()",
    re.I,
)
_UNAVAILABLE = re.compile(
    r"미확인|미기재|확인하지\s*못|확인할\s*수\s*없|알\s*수\s*없|확인\s*불가|"
    r"기록(?:되어)?\s*있지\s*않|기록되지|제공되지"
)
_HYPOTHESIS = re.compile(
    r"가능성|위험성|우려|추정|예상|가정|권장|권고|제안|예정|"
    r"(?:했다|한다|되었다)면"
)
_MODAL = re.compile(r"(?:할|될|일|필요할)\s*수\s*(?:있|없)")
_PARAMETER_DENIAL = re.compile(r"(?:파라미터|매개변수|입력값).{0,60}(?:아니다|아니라|아닌)")
_OBSERVED = re.compile(
    r"(?:확인|관찰)(?:했다|하였(?:다|음)|했음|됐(?:다|음)|되었(?:다|음))|"
    r"(?:표시|출력|반환|노출|실행|조회|재현)(?:되었다|되었음|되지\s*않았다|되지\s*않았음)"
)
_ACTION = re.compile(
    r"(?:접속|클릭|입력|전송|요청|변경|변조|제출|실행|조회|로그인|로그아웃|선택)"
    r"(?:한다|했다|하였(?:다|음)|했(?:음|으며|고)|함)"
)
_VERIFY_ACTION = re.compile(r"확인(?:한다|함|해\s*본다)")
_CONDITION_LABEL = re.compile(r"^(?:\d+[.)]\s*)?(?:사전|전제|재현)\s*조건\s*[:：]\s*(.+)$")
_CONDITION = re.compile(
    r"(?:로그인|로그아웃|인증|권한|계정|세션).{0,60}"
    r"(?:상태(?:여야|이어야|에서)|필요하다|필요함|필수다|필수임|"
    r"필요하지\s*않다|불필요하다|되어\s*있어야)"
)
_CONDITION_PREFIX = re.compile(r"(?:로그인|로그아웃|인증).{0,40}?상태에서(?=\s)")
_SENTENCE_END = re.compile(r"(?<!\d)[.!?](?=\s+(?:\d+[.)]\s*)?[가-힣A-Za-z])")


@dataclass(frozen=True)
class Segment:
    text: str
    source_ref: str
    start: int
    end: int
    role: str
    rule: str
    parameters: tuple[str, ...] = ()
    tentative: bool = False


def _parameter_names(text: str) -> tuple[str, ...]:
    found = []
    for pattern in _PARAMETERS:
        for match in pattern.finditer(text):
            name = match["name"]
            if name.upper() in _RESERVED:
                continue
            found.append((match.start("name"), name))
            position = match.end("name")
            while another := _ANOTHER.match(text, position):
                if another["name"].upper() not in _RESERVED:
                    found.append((another.start("name"), another["name"]))
                position = another.end("name")
    return tuple(dict.fromkeys(name for _, name in sorted(found)))


def _spans(text: str):
    start = 0
    for end in [match.end() for match in _SENTENCE_END.finditer(text)] + [len(text)]:
        left = start + len(text[start:end]) - len(text[start:end].lstrip())
        right = end - (len(text[start:end]) - len(text[start:end].rstrip()))
        start = end
        if left >= right:
            continue
        piece = text[left:right]
        prefix = _CONDITION_PREFIX.search(piece)
        uncertain = _UNAVAILABLE.search(piece) or _HYPOTHESIS.search(piece) or _MODAL.search(piece)
        if prefix and prefix.end() < len(piece) and not uncertain:
            split = left + prefix.end()
            yield left, split
            next_start = split + len(text[split:right]) - len(text[split:right].lstrip())
            if next_start < right:
                yield next_start, right
        else:
            yield left, right


def classify_paragraph(text: str, source_ref: str) -> list[Segment]:
    """Classify statements, never rewrite their wording or execute their contents."""
    results = []
    if _CAPTION.search(text) or _CODE.search(text):
        role = "caption" if _CAPTION.search(text) else "code"
        return [Segment(text, source_ref, 0, len(text), role, "opaque-" + role)]
    for start, end in _spans(text):
        piece = text[start:end]
        names = _parameter_names(piece)
        observed = bool(_OBSERVED.search(piece))
        tentative = bool(
            _UNAVAILABLE.search(piece)
            or _HYPOTHESIS.search(piece)
            or _MODAL.search(piece)
            or (names and _PARAMETER_DENIAL.search(piece))
        )
        condition = _CONDITION_LABEL.search(piece)
        if tentative or (condition and is_unknown(condition[1])):
            role, rule = "uncertain", "uncertainty-or-hypothesis"
        else:
            has_condition = bool(condition or _CONDITION.search(piece))
            action = bool(_ACTION.search(piece))
            if (observed and action) or (has_condition and (observed or action)):
                role, rule = "mixed", "mixed-clause-needs-review"
            elif has_condition:
                role, rule = "preconditions", "explicit-condition"
            elif observed:
                role, rule = "observed_result", "past-observation"
            elif action or _VERIFY_ACTION.search(piece):
                role, rule = "procedure", "explicit-action"
            else:
                role, rule = "unclassified", "no-supported-rule"
        results.append(Segment(piece, source_ref, start, end, role, rule, names, tentative))
    return results


def apply_narrative_analysis(finding: FindingDraft, grouped: dict) -> None:
    """Promote clear fields, retain alternatives, and keep observation vs oracle separate."""
    segments = []
    for field in ("description", "narrative"):
        for item in grouped.get(field, []):
            for paragraph in item["cell"]["paragraphs"]:
                text = paragraph["text"]
                if text.strip():
                    segments.extend(classify_paragraph(text, paragraph["source_ref"]))
    if not segments:
        return

    def evidence(field, value, segment, method):
        item = FieldEvidence(value=value, source_ref=segment.source_ref, method=method)
        bucket = finding.field_evidence.setdefault(field, [])
        if item not in bucket:
            bucket.append(item)

    def issue(code, field, message, relevant):
        finding.review_issues.append(
            ReviewIssue(
                code=code,
                field=field,
                message=message,
                source_refs=list(dict.fromkeys(segment.source_ref for segment in relevant)),
            )
        )

    for segment in segments:
        evidence(
            "narrative_segments",
            {
                "role": segment.role,
                "text": segment.text,
                "start": segment.start,
                "end": segment.end,
                "rule": segment.rule,
                "parameters": list(segment.parameters),
            },
            segment,
            "derived",
        )

    mentions = [segment for segment in segments if segment.parameters]
    if mentions:
        names = {name for segment in mentions for name in segment.parameters}
        original = finding.candidate.parameter
        if is_unknown(original):
            finding.candidate.parameter = original = None
        direct_items = grouped.get("parameter", [])
        direct_names = {
            item["value_raw"].strip()
            for item in direct_items
            if item["value_raw"].strip() and not is_unknown(item["value_raw"])
        }
        combined = names | direct_names | ({original} if original else set())
        ambiguous = (
            len(combined) != 1
            or len(direct_items) > 1
            or any(segment.tentative for segment in mentions)
        )
        unspecified_direct = any(
            is_unknown(item["value_raw"]) for item in grouped.get("parameter", [])
        )
        for segment in mentions:
            for name in segment.parameters:
                evidence(
                    "parameter",
                    name,
                    segment,
                    "review_candidate" if ambiguous or unspecified_direct else "derived",
                )
        if ambiguous:
            finding.candidate.parameter = None
            issue(
                "narrative_parameter_ambiguous",
                "parameter",
                "파라미터 후보가 불확실하거나 다른 출처와 충돌하여 확정하지 않았습니다.",
                mentions,
            )
        elif unspecified_direct:
            finding.candidate.parameter = None
        else:
            finding.candidate.parameter = next(iter(combined))

    mixed = [segment for segment in segments if segment.role == "mixed"]
    if mixed:
        issue(
            "narrative_mixed_clause",
            "procedure",
            "한 절에 조건·행동·관찰이 섞여 있어 자동 분리를 보류했습니다.",
            mixed,
        )
        for segment in mixed:
            evidence("procedure", segment.text, segment, "review_candidate")
            evidence("success_condition", segment.text, segment, "review_candidate")

    partial_procedure = [
        segment
        for segment in segments
        if segment.role == "uncertain" and re.search(r"절차|단계|순서", segment.text)
    ]
    for field in ("preconditions", "procedure"):
        relevant = [segment for segment in segments if segment.role == field]
        values = []
        for segment in relevant:
            label = _CONDITION_LABEL.search(segment.text) if field == "preconditions" else None
            value = label[1] if label else segment.text
            values.append(value)
            review_only = bool(grouped.get(field)) or (
                field == "procedure" and bool(mixed or partial_procedure)
            )
            evidence(field, value, segment, "review_candidate" if review_only else "derived")
        if (
            values
            and not grouped.get(field)
            and not (field == "procedure" and (mixed or partial_procedure))
        ):
            setattr(finding.candidate, field, list(dict.fromkeys(values)))
        if field == "procedure" and values and partial_procedure:
            issue(
                "narrative_procedure_incomplete",
                field,
                "일부 절차는 읽었지만 나머지 단계가 미확인으로 명시되어 확정을 보류했습니다.",
                partial_procedure,
            )

    observed = [segment for segment in segments if segment.role == "observed_result"]
    for segment in observed:
        evidence("observed_result", segment.text, segment, "derived")
        if not grouped.get("success_condition"):
            evidence("success_condition", segment.text, segment, "review_candidate")
    if observed and not grouped.get("success_condition"):
        issue(
            "observed_result_requires_review",
            "success_condition",
            "원문의 관찰 결과를 분리했습니다. 재현 성공 판정 기준으로의 확정은 검토가 필요합니다.",
            observed,
        )
