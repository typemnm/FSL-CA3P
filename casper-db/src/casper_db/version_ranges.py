"""Conservative version comparisons: an unrecognized expression is not a safe result."""

from __future__ import annotations

import re


class UnresolvedVersion(ValueError):
    pass


def _version(value: str, ecosystem: str):
    match = re.fullmatch(r"(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?", value)
    if not match:
        raise UnresolvedVersion("version syntax requires review")
    numbers = tuple(int(part) for part in match[1].split("."))
    pre = match[2]
    if ecosystem == "npm":
        if len(numbers) != 3 or any(
            len(part) > 1 and part.startswith("0") for part in match[1].split(".")
        ):
            raise UnresolvedVersion("npm comparison requires a full SemVer")
        if pre and any(
            not part or (part.isdigit() and len(part) > 1 and part.startswith("0"))
            for part in pre.split(".")
        ):
            raise UnresolvedVersion("invalid SemVer prerelease")
        if match[3] and any(not part for part in match[3].split(".")):
            raise UnresolvedVersion("invalid SemVer build metadata")
    elif pre or match[3]:
        raise UnresolvedVersion("qualified non-SemVer releases require review")
    return numbers, pre


def compare_versions(left: str, right: str, ecosystem: str) -> int:
    a, ap = _version(left, ecosystem)
    b, bp = _version(right, ecosystem)
    length = max(len(a), len(b))
    a, b = a + (0,) * (length - len(a)), b + (0,) * (length - len(b))
    if a != b:
        return (a > b) - (a < b)
    if ap == bp:
        return 0
    if ap is None or bp is None:
        return 1 if ap is None else -1
    for x, y in zip(ap.split("."), bp.split("."), strict=False):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return (int(x) > int(y)) - (int(x) < int(y))
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1
        return (x > y) - (x < y)
    return (len(ap.split(".")) > len(bp.split("."))) * 2 - 1


def matches_range(version: str, expression: str, ecosystem: str) -> bool | None:
    """Evaluate advisory comparator ranges; None explicitly requests review."""
    if ecosystem not in {"npm", "maven", "pip", "cpe"}:
        return None
    try:
        _version(version, ecosystem)
        alternatives = []
        for branch in expression.split("||"):
            branch = branch.strip()
            if not branch:
                raise UnresolvedVersion("empty version range")
            if branch == "*":
                alternatives.append(True)
                continue
            interval = re.fullmatch(r"([\[(])\s*([^,]*)\s*,\s*([^\])]*)([\])])", branch)
            if interval:
                start, stop = interval[2].strip(), interval[3].strip()
                checks = []
                if start:
                    c = compare_versions(version, start, ecosystem)
                    checks.append(c >= 0 if interval[1] == "[" else c > 0)
                if stop:
                    c = compare_versions(version, stop, ecosystem)
                    checks.append(c <= 0 if interval[4] == "]" else c < 0)
                if not checks:
                    raise UnresolvedVersion("unbounded interval")
                alternatives.append(all(checks))
                continue
            checks = []
            for term in branch.split(","):
                match = re.fullmatch(r"\s*(>=|<=|==|=|>|<)?\s*([^\s,]+)\s*", term)
                if not match:
                    raise UnresolvedVersion("unsupported comparator")
                op, bound = match[1] or "=", match[2]
                c = compare_versions(version, bound, ecosystem)
                checks.append(
                    {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0, "==": c == 0}[
                        op
                    ]
                )
            alternatives.append(all(checks))
        # Stable ranges do not implicitly include npm prereleases.
        if ecosystem == "npm" and _version(version, ecosystem)[1] and "-" not in expression:
            return None
        return any(alternatives)
    except (UnresolvedVersion, KeyError, TypeError):
        return None
