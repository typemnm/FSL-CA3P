"""Recognize standalone missing-value markers without rewriting report content."""

from __future__ import annotations

import re
from typing import Any

UNKNOWN = frozenset(
    {
        "미확인",
        "미기재",
        "확인필요",
        "확인불가",
        "알수없음",
        "확인중",
        "추후확인",
        "확인하지못함",
        "unknown",
        "n/a",
        "tbd",
        "-",
    }
)


def is_unknown(value: Any) -> bool:
    # Substrings in ordinary prose or executable-looking payload text are data.
    return isinstance(value, str) and re.sub(r"\s", "", value).casefold() in UNKNOWN


def has_supplied_value(value: Any) -> bool:
    """Check presence/markers, not truth; lists must not hide a missing item."""
    if isinstance(value, list):
        return bool(value) and all(has_supplied_value(item) for item in value)
    if isinstance(value, str):
        return bool(value.strip()) and not is_unknown(value)
    return value is not None
