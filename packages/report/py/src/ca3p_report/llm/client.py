"""OpenAI-compatible chat client — the ONE module allowed to read env and the network.

Connection settings come from the agent core's environment (DEEPSEEK_BASE_URL,
DEEPSEEK_API_KEY, DEEPSEEK_MODEL); see PLAN §3.8 and the §4.4 boundary. Every other
module is network-free and env-free, enforced by tests/test_boundaries.py, which exempts
this file by path.
"""

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass

DEFAULT_TIMEOUT_S = 300.0


class LLMError(RuntimeError):
    """The LLM call failed or returned something unusable. Maps to LLM_FAILED (exit 8)."""


@dataclass(frozen=True)
class LLMConfig:
    base_url: str
    api_key: str
    model: str
    timeout_s: float = DEFAULT_TIMEOUT_S

    @classmethod
    def from_env(cls, env: dict | None = None) -> LLMConfig:
        env = env if env is not None else os.environ
        base = (env.get("DEEPSEEK_BASE_URL") or "").rstrip("/")
        key = env.get("DEEPSEEK_API_KEY") or ""
        model = env.get("DEEPSEEK_MODEL") or ""
        missing = [
            n
            for n, v in (
                ("DEEPSEEK_BASE_URL", base),
                ("DEEPSEEK_API_KEY", key),
                ("DEEPSEEK_MODEL", model),
            )
            if not v
        ]
        if missing:
            raise LLMError(f"missing LLM environment: {', '.join(missing)}")
        return cls(base_url=base, api_key=key, model=model)


class HttpChatClient:
    """Minimal /chat/completions caller with tool-calling, over urllib with a timeout."""

    def __init__(self, config: LLMConfig):
        self._config = config

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        body = json.dumps(
            {
                "model": self._config.model,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self._config.base_url}/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self._config.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._config.timeout_s) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError) as exc:
            # Class name only: URLs/paths in the message could carry secrets.
            raise LLMError(f"LLM request failed: {type(exc).__name__}") from exc
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LLMError("LLM response had no choices")
        message = choices[0].get("message")
        if not isinstance(message, dict):
            raise LLMError("LLM response had no message")
        return message
