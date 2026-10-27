"""The build-stage tool-calling loop.

An injected chat client (real or fake) drives the conversation. The LLM reads the bundle,
optionally captures screenshots, and assembles a ReportModel it submits via finish_report,
which ends the loop. There is no verifier and no iteration cap (PLAN §3.8); the loop ends
only when finish_report succeeds. Any client/transport failure raises LLMError → LLM_FAILED.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..profiles import resolve_profile
from .client import LLMError
from .prompt import build_system_prompt
from .tools import ReportTools, ToolError, tool_schemas


def _bundle_summary(bundle: Path) -> str:
    try:
        manifest = json.loads((bundle / "manifest.json").read_text("utf-8"))
    except (OSError, ValueError):
        return "manifest.json을 읽을 수 없습니다."
    files = ", ".join(f.get("path", "?") for f in manifest.get("files", []))
    return f"번들 runId={manifest.get('runId')}. 파일: {files}. read_bundle로 내용을 읽으십시오."


def _dispatch(tools: ReportTools, name: str, args: dict) -> dict:
    try:
        if name == "read_bundle":
            return {"ok": True, "content": tools.read_bundle(args.get("path"))}
        if name == "capture_screenshot":
            return {
                "ok": True,
                "result": tools.capture_screenshot(
                    selector=args.get("selector"),
                    full_page=bool(args.get("full_page")),
                    viewer=args.get("viewer"),
                ),
            }
        if name == "finish_report":
            return tools.finish_report(model=args.get("model"), filename=args.get("filename"))
        return {"ok": False, "error": f"unknown tool: {name}"}
    except ToolError as exc:
        # Tool refusals are returned to the LLM so it can correct, not fatal.
        return {"ok": False, "error": str(exc)}


def run_build(
    client,
    *,
    bundle: Path,
    out_dir: Path,
    test_profile: str | None,
    origin: str,
    session_switch: dict | None,
    node: str = "node",
) -> dict:
    """Drive the LLM until finish_report succeeds. Returns the finish result dict."""
    bundle = Path(bundle)
    profile = resolve_profile(test_profile)
    tools = ReportTools(bundle, out_dir, origin=origin, session_switch=session_switch, node=node)
    messages = [
        {"role": "system", "content": build_system_prompt(profile)},
        {"role": "user", "content": _bundle_summary(bundle)},
    ]
    schemas = tool_schemas()
    while True:
        message = client.complete(messages, schemas)  # raises LLMError on failure
        calls = message.get("tool_calls") or []
        if not calls:
            if tools.finished is not None:
                break
            # No tool call and not finished: nudge once via the conversation, then insist.
            messages.append(message)
            messages.append(
                {
                    "role": "user",
                    "content": "finish_report로 보고서를 완성하거나 도구를 호출하십시오.",
                }
            )
            continue
        messages.append(message)
        for call in calls:
            fn = call.get("function", {})
            name = fn.get("name", "")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except ValueError:
                args = {}
            result = _dispatch(tools, name, args if isinstance(args, dict) else {})
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.get("id", name),
                    "content": json.dumps(result, ensure_ascii=False),
                }
            )
        if tools.finished is not None:
            break
    if tools.finished is None:  # pragma: no cover - defensive
        raise LLMError("the loop ended without a finished report")
    return {
        "files": tools.finished.files,
        "reportFilename": tools.finished.report_filename,
        "outDir": str(tools.finished.out_dir),
    }
