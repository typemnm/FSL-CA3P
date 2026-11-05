"""Field applicability and reviewed route constraints for vulnerability cases."""

from __future__ import annotations

import re

from .field_values import has_supplied_value

OPTIONAL_INPUT_FIELDS = frozenset({"parameter", "payload"})
_NON_INPUT_TYPES = frozenset(
    re.sub(r"[\s_-]+", "", value).casefold()
    for value in (
        "Information Exposure",
        "Information Disclosure",
        "Sensitive Information Exposure",
        "Security Misconfiguration",
        "Cryptographic Failure",
        "Cryptographic Failures",
        "Weak Cryptography",
        "Insecure Design",
        "Security Logging Failure",
        "Logging and Monitoring Failures",
        "Security Logging and Alerting Failures",
        "Exception Handling Failure",
        "Mishandling of Exceptional Conditions",
        "정보 노출",
        "정보 유출",
        "보안 설정 오류",
        "암호화 실패",
        "취약한 암호화",
        "불안전한 설계",
        "보안 로깅 및 경보 실패",
        "예외 조건 처리 실패",
        "CWE-200",
        "CWE-209",
        "CWE-327",
        "CWE-532",
        "CWE-755",
        "CWE-778",
    )
)
_SLOT = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_INTEGER = re.compile(r"[0-9]+")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


def validate_applicability(
    vulnerability_type, not_applicable_fields, reason, parameter, parameter_location, payload
):
    """Absence is exempt only with an explicit, type-compatible declaration."""
    fields = set(not_applicable_fields)
    if len(fields) != len(not_applicable_fields) or fields - OPTIONAL_INPUT_FIELDS:
        raise ValueError("not_applicable_fields must contain unique supported field names")
    if fields:
        normalized = re.sub(r"[\s_-]+", "", vulnerability_type).casefold()
        if normalized not in _NON_INPUT_TYPES:
            raise ValueError("this vulnerability type requires its input fields")
        if not has_supplied_value(reason):
            raise ValueError("non-applicable input fields require an applicability_reason")
    elif reason is not None:
        raise ValueError("applicability_reason requires non-applicable fields")
    if "parameter" in fields:
        if parameter is not None or parameter_location != "unknown":
            raise ValueError("a non-applicable parameter must be null with unknown location")
    elif not has_supplied_value(parameter):
        raise ValueError("parameter is required unless explicitly not applicable")
    if "payload" in fields and payload is not None:
        raise ValueError("a non-applicable payload must be null")


def _parts(template, parameter):
    if not template.startswith("/") or template.startswith("//"):
        raise ValueError("route_template must be an absolute path")
    if any(char in template for char in "?#\\%") or any(char.isspace() for char in template):
        raise ValueError("route_template must not contain query, escapes or whitespace")
    parts = template.split("/")
    slots = []
    for index, part in enumerate(parts):
        slot = _SLOT.fullmatch(part)
        if slot:
            slots.append(index)
            if slot[1] != parameter:
                raise ValueError("route slot must name the reported path parameter")
        elif "{" in part or "}" in part or part in {".", ".."}:
            raise ValueError("route slots must occupy complete path segments")
    if len(slots) != 1:
        raise ValueError("route_template requires exactly one named path slot")
    return parts, slots[0]


def validate_route_template(template, endpoint, parameter, parameter_location):
    if template is None:
        return
    if parameter is None or parameter_location != "path":
        raise ValueError("route_template requires a known path parameter")
    parts, slot = _parts(template, parameter)
    actual = endpoint.split("/")
    if len(parts) != len(actual) or any(
        part != actual[index] for index, part in enumerate(parts) if index != slot
    ):
        raise ValueError("route_template does not match the recorded endpoint")
    if not (_INTEGER.fullmatch(actual[slot]) or _UUID.fullmatch(actual[slot])):
        raise ValueError("reviewed route slots currently support integer or UUID identifiers")


def same_reviewed_route(template, reference, observed, parameter):
    """Only the declared identifier changes; fixed segments stay byte-for-byte equal."""
    if template is None:
        return False
    try:
        validate_route_template(template, reference, parameter, "path")
        parts, slot = _parts(template, parameter)
    except ValueError:
        return False
    old, new = reference.split("/"), observed.split("/")
    if len(new) != len(parts) or any(
        part != new[index] for index, part in enumerate(parts) if index != slot
    ):
        return False
    pattern = _INTEGER if _INTEGER.fullmatch(old[slot]) else _UUID
    return bool(pattern.fullmatch(new[slot]))
