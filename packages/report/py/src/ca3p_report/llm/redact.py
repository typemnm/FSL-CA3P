"""Mask secrets before anything reaches the LLM, tool logs or report output.

Port of redact() in packages/contracts/index.mjs. Keep the two in sync: the
secret-key set, the [REDACTED] token, URL, header and Bearer rules must give the
same result on the shared vectors in tests/test_redact.py. Report-only rules on
top: drop model-internal keys (DROP_KEYS) and mask sk-... API keys.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, quote_plus

REDACTED = "[REDACTED]"

# Token counts and boolean policy fields are telemetry, so do not redact by substring.
_SECRET_KEY = re.compile(
    r"(?:authorization|proxyauthorization|cookie|setcookie|(?:x)?apikey|password|passwd|secret"
    r"|accesstoken|refreshtoken|sessiontoken|clientsecret|bearertoken|jwt)"
)
_SECRET_SUFFIX = re.compile(
    r"(?:apikey|cookiesecret|clientsecret|accesstoken|refreshtoken|sessiontoken)$"
)
_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_HEADER = re.compile(
    r"\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|session-token|access-token)"
    r"(\s*:\s*)[^\r\n]*?(?=(?:\\n|[\r\n]|\Z))",
    re.IGNORECASE | re.ASCII,
)
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]+", re.IGNORECASE | re.ASCII)
# Classic sk-... plus newer prefixed formats (sk-proj-, sk-svcacct-, sk-ant-...).
_OPENAI_KEY = re.compile(r"sk-(?:proj-|svcacct-|ant-(?:api\d+-)?)?[A-Za-z0-9_-]{16,}")

# Model reasoning, raw responses and the prompt itself never leave the LLM stage.
DROP_KEYS = frozenset(
    {
        "reasoning_content",
        "reasoning",
        "chainOfThought",
        "raw_response",
        "rawResponse",
        "prompt",
        "messages",
    }
)


def is_secret_key(key: str) -> bool:
    folded = re.sub(r"[^a-z0-9]", "", key.lower())
    return bool(_SECRET_KEY.fullmatch(folded) or _SECRET_SUFFIX.search(folded))


def _form_encode(text: str) -> str:
    # WHATWG urlencoded serializer: like quote_plus, but '*' stays and '~' is escaped.
    return quote_plus(text, safe="*").replace("~", "%7E")


def _replace_url(candidate: str) -> str:
    # shortcut: mirrors WHATWG URL only for what changes here (userinfo, secret params,
    # lowercased host, "/" for an empty path); no default-port or percent re-encoding.
    match = re.fullmatch(r"(?i)(https?)://([^/?#]*)([^?#]*)(?:\?([^#]*))?(#.*)?", candidate)
    if not match:
        return candidate
    scheme, authority, path, query, fragment = match.groups()
    userinfo, at, host = authority.rpartition("@")
    if not host:
        return candidate
    changed = bool(at and userinfo)
    if query is not None:
        pairs, seen = [], set()
        for key, value in parse_qsl(query, keep_blank_values=True):
            if is_secret_key(key):
                changed = True
                if key in seen:
                    continue  # URLSearchParams.set() keeps only the first entry
                seen.add(key)
                value = REDACTED
            pairs.append((key, value))
        if changed and seen:
            query = "&".join(f"{_form_encode(k)}={_form_encode(v)}" for k, v in pairs)
    if not changed:
        return candidate
    query_part = "" if query is None else f"?{query}"
    return f"{scheme.lower()}://{host.lower()}{path or '/'}{query_part}{fragment or ''}"


def redact_string(value: str) -> str:
    if re.match(r"(?i)https?://", value):
        value = _replace_url(value)
    else:
        value = _URL.sub(lambda m: _replace_url(m.group(0)), value)
    value = _HEADER.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", value)
    value = _BEARER.sub(f"Bearer {REDACTED}", value)
    return _OPENAI_KEY.sub(REDACTED, value)


def redact(value: Any) -> Any:
    if isinstance(value, list | tuple):
        return [redact(entry) for entry in value]
    if isinstance(value, dict):
        return {
            key: REDACTED if is_secret_key(str(key)) else redact(entry)
            for key, entry in value.items()
            if key not in DROP_KEYS
        }
    if isinstance(value, str):
        return redact_string(value)
    return value
