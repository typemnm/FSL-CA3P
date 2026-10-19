from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ca3p_report.llm.redact import REDACTED, redact

CONTRACTS = Path(__file__).resolve().parents[4] / "packages" / "contracts" / "index.mjs"

# Mirrored from packages/contracts/index.mjs redact():
#   token        "[REDACTED]"
#   secret keys  authorization proxyauthorization cookie setcookie (x)apikey password passwd
#                secret accesstoken refreshtoken sessiontoken clientsecret bearertoken jwt
#                (exact, after lowercase + strip non-alphanumerics)
#   key suffixes apikey cookiesecret clientsecret accesstoken refreshtoken sessiontoken
#   headers      authorization proxy-authorization cookie set-cookie x-api-key api-key
#                session-token access-token  ("<label>: <value>" up to newline or literal \n)
#   strings      URL user:pass@ stripped, secret query params set to [REDACTED], Bearer <token>
# Shared vectors: run through both implementations by test_matches_contracts.
SHARED = [
    ({"cookie": "a=b", "Set-Cookie": "s=1", "Authorization": "Basic x"},
     {"cookie": REDACTED, "Set-Cookie": REDACTED, "Authorization": REDACTED}),
    ({"x-api-key": "k", "client_secret": "c", "githubAccessToken": "t", "jwt": "j"},
     {"x-api-key": REDACTED, "client_secret": REDACTED,
      "githubAccessToken": REDACTED, "jwt": REDACTED}),
    ({"a": [{"password": "p", "keep": "v"}, ["Bearer abc.def"]]},
     {"a": [{"password": REDACTED, "keep": "v"}, [f"Bearer {REDACTED}"]]}),
    ("Bearer abc.def", f"Bearer {REDACTED}"),
    ("x bearer abc.def y", f"x Bearer {REDACTED} y"),
    ("https://user:pass@Example.com?api_key=abc&q=a b&t=1~*",
     "https://example.com/?api_key=%5BREDACTED%5D&q=a+b&t=1%7E*"),
    ("see http://u:p@a.com/x?token=1&access_token=2&access_token=3#f ok",
     "see http://a.com/x?token=1&access_token=%5BREDACTED%5D#f ok"),
    ("https://a.com/?q=1", "https://a.com/?q=1"),
    ("Authorization: Bearer abc.def\nnext", f"Authorization: {REDACTED}\nnext"),
    ("Cookie: sid=1\\nHost: a", f"Cookie: {REDACTED}\\nHost: a"),
    # Known contracts gap, mirrored on purpose: no \b between a literal "\n" and the label.
    ("GET / HTTP/1.1\\nCookie: sid=1", "GET / HTTP/1.1\\nCookie: sid=1"),
    ("set-cookie : s=1\r\nx-api-key:k", f"set-cookie : {REDACTED}\r\nx-api-key:{REDACTED}"),
    # Benign telemetry stays: token counts, boolean policy fields, non-strings.
    ({"usage": {"total_tokens": 1234, "tokenCount": 9}, "allowSecrets": False, "n": None},
     {"usage": {"total_tokens": 1234, "tokenCount": 9}, "allowSecrets": False, "n": None}),
]

# Report-only rules, not in contracts redact().
REPORT_ONLY = [
    ("key sk-ABCDEFGHIJKLMNOP1234 end", f"key {REDACTED} end"),
    ("sk-short1234", "sk-short1234"),
    ({"reasoning_content": "x", "choices": [{"message": {"content": "ok", "reasoning": "r"}}]},
     {"choices": [{"message": {"content": "ok"}}]}),
    ({"chainOfThought": 1, "raw_response": 2, "rawResponse": 3,
      "prompt": 4, "messages": [], "k": 5},
     {"k": 5}),
]


@pytest.mark.parametrize(("value", "expected"), SHARED + REPORT_ONLY)
def test_redact_vectors(value, expected):
    assert redact(value) == expected


def test_matches_contracts():
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    script = (
        f"const {{ redact }} = await import({json.dumps(CONTRACTS.as_uri())});"
        "let s = ''; for await (const c of process.stdin) s += c;"
        "process.stdout.write(JSON.stringify(JSON.parse(s).map(redact)));"
    )
    inputs = [value for value, _ in SHARED]
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps(inputs), capture_output=True, text=True, check=True,
    )
    assert json.loads(result.stdout) == [redact(value) for value in inputs]
