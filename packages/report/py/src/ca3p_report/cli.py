"""Command line entry point. Reads a ReportTrigger and prints one JSON result."""

from __future__ import annotations

import argparse
import hashlib
import json
import json as _json
import sys
from pathlib import Path

from .collect.bundle import BundleExistsError, OutputError
from .collect.collector import RunIncomplete, RunNotFound, collect
from .collect.model import CollectError
from .trigger import TriggerError, parse_trigger

EXIT_OK = 0
EXIT_TRIGGER = 2
EXIT_RUN_NOT_FOUND = 3
EXIT_RUN_INCOMPLETE = 4
EXIT_SOURCE = 5
EXIT_BUNDLE_EXISTS = 6
EXIT_OUTPUT = 7
EXIT_INTERNAL = 1
EXIT_LLM = 8


def _emit(result: dict) -> None:
    sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")


def _failure(run_id: str | None, code: str, message: str) -> dict:
    return {
        "schemaVersion": "report-result-1.0",
        "ok": False,
        "runId": run_id,
        "error": {"code": code, "message": message},
    }


def _collect(trigger_text: str) -> int:
    try:
        trigger = parse_trigger(json.loads(trigger_text))
    except (json.JSONDecodeError, RecursionError, TriggerError) as exc:
        _emit(_failure(None, "TRIGGER_INVALID", str(exc)))
        return EXIT_TRIGGER
    except Exception as exc:  # noqa: BLE001 - same JSON-only contract as collect below
        _emit(_failure(None, "TRIGGER_INVALID", type(exc).__name__))
        return EXIT_TRIGGER
    try:
        result = collect(trigger)
    except RunNotFound:
        _emit(_failure(trigger.run_id, "RUN_NOT_FOUND", "the run source has no such run"))
        return EXIT_RUN_NOT_FOUND
    except RunIncomplete:
        _emit(_failure(trigger.run_id, "RUN_INCOMPLETE", "the run has no final report"))
        return EXIT_RUN_INCOMPLETE
    except BundleExistsError as exc:
        _emit(_failure(trigger.run_id, "BUNDLE_EXISTS", str(exc)))
        return EXIT_BUNDLE_EXISTS
    except CollectError as exc:
        _emit(_failure(trigger.run_id, "SOURCE_INVALID", str(exc)))
        return EXIT_SOURCE
    except OutputError as exc:
        _emit(_failure(trigger.run_id, "OUTPUT_UNWRITABLE", str(exc)))
        return EXIT_OUTPUT
    except Exception as exc:  # noqa: BLE001 - last line of defence for the JSON contract
        # Never print a traceback: OS and library messages can name source locations.
        _emit(_failure(trigger.run_id, "INTERNAL_ERROR", type(exc).__name__))
        return EXIT_INTERNAL
    _emit(
        {
            "schemaVersion": "report-result-1.0",
            "ok": True,
            "runId": trigger.run_id,
            "stage": "collected",
            "collectors": result.manifest["collectors"],
            "files": result.manifest["files"],
        }
    )
    return EXIT_OK


def _origin_and_switch(bundle: Path, run_report: dict) -> tuple[str, dict | None]:
    target = run_report.get("target") if isinstance(run_report, dict) else None
    origin = target.get("origin") if isinstance(target, dict) else None
    switch = None
    try:
        hints = _json.loads((bundle / "hints" / "capture.json").read_text("utf-8"))
        switch = hints.get("sessionSwitch") if isinstance(hints, dict) else None
    except (OSError, ValueError):
        pass
    return origin, switch


def _run(trigger_text: str, *, client=None, node: str = "node") -> int:
    """Collect and render a selected general finding or run the legacy LLM writer."""
    try:
        trigger = parse_trigger(json.loads(trigger_text))
    except (json.JSONDecodeError, RecursionError, TriggerError) as exc:
        _emit(_failure(None, "TRIGGER_INVALID", str(exc)))
        return EXIT_TRIGGER
    except Exception as exc:  # noqa: BLE001
        _emit(_failure(None, "TRIGGER_INVALID", type(exc).__name__))
        return EXIT_TRIGGER
    try:
        collected = collect(trigger)
    except RunNotFound:
        _emit(_failure(trigger.run_id, "RUN_NOT_FOUND", "the run source has no such run"))
        return EXIT_RUN_NOT_FOUND
    except RunIncomplete:
        _emit(_failure(trigger.run_id, "RUN_INCOMPLETE", "the run has no final report"))
        return EXIT_RUN_INCOMPLETE
    except BundleExistsError as exc:
        _emit(_failure(trigger.run_id, "BUNDLE_EXISTS", str(exc)))
        return EXIT_BUNDLE_EXISTS
    except CollectError as exc:
        _emit(_failure(trigger.run_id, "SOURCE_INVALID", str(exc)))
        return EXIT_SOURCE
    except OutputError as exc:
        _emit(_failure(trigger.run_id, "OUTPUT_UNWRITABLE", str(exc)))
        return EXIT_OUTPUT
    except Exception as exc:  # noqa: BLE001
        _emit(_failure(trigger.run_id, "INTERNAL_ERROR", type(exc).__name__))
        return EXIT_INTERNAL

    # Imported here so `collect` stays free of the LLM/network surface.
    from .collect.collector import collect as _c  # noqa: F401  (keep import graph obvious)
    from .llm.client import HttpChatClient, LLMConfig, LLMError
    from .llm.loop import run_build

    report = collected.run.report or {}
    origin, switch = _origin_and_switch(collected.bundle, report)
    try:
        if collected.selection is not None:
            from .general_model import build_general_model
            from .llm.tools import ReportTools

            model = build_general_model(
                collected.selection, report, collected.manifest,
                stored_at=collected.run.stored_at,
            )
            tools = ReportTools(
                collected.bundle, trigger.output_dir / "report",
                origin=origin, session_switch=None, node=node,
            )
            suffix = hashlib.sha256(trigger.finding_id.encode("utf-8")).hexdigest()[:16]
            tools.finish_report(model=model, filename=f"issue-{suffix}-{trigger.run_id[:80]}.hwpx")
            built = {
                "files": tools.finished.files,
                "reportFilename": tools.finished.report_filename,
            }
        else:
            if client is None:
                client = HttpChatClient(LLMConfig.from_env())
            built = run_build(
                client,
                bundle=collected.bundle,
                out_dir=trigger.output_dir / "report",
                test_profile=report.get("testProfile"),
                origin=origin,
                session_switch=switch,
                node=node,
            )
    except LLMError as exc:
        _emit(_failure(trigger.run_id, "LLM_FAILED", str(exc)))
        return EXIT_LLM
    except Exception as exc:  # noqa: BLE001
        _emit(_failure(trigger.run_id, "INTERNAL_ERROR", type(exc).__name__))
        return EXIT_INTERNAL

    finding = (collected.selection["finding"] if collected.selection is not None
               else report.get("finding") if isinstance(report.get("finding"), dict) else {})
    vulnerability = (
        f"{finding.get('category', '')} · {finding.get('asset', '')}".strip(" ·")
        if collected.selection is not None
        else f"{finding.get('title', '')} ({finding.get('cwe', '')})".strip()
    )
    _emit(
        {
            "schemaVersion": "report-result-1.0",
            "ok": True,
            "runId": trigger.run_id,
            "stage": "reported",
            **({"findingId": trigger.finding_id} if collected.selection is not None else {}),
            "summary": {
                "vulnerability": vulnerability,
                "target": origin or "",
                "exploit": finding.get("status", ""),
            },
            "files": built["files"],
            "reportFilename": built["reportFilename"],
            "collectors": collected.manifest["collectors"],
        }
    )
    return EXIT_OK


def _read_trigger(path: str) -> str | None:
    try:
        if path == "-":
            return sys.stdin.buffer.read().decode("utf-8")
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        reason = "not UTF-8" if isinstance(exc, UnicodeDecodeError) else "not readable"
        _emit(_failure(None, "TRIGGER_UNREADABLE", f"trigger is {reason}"))
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ca3p-report", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect_cmd = commands.add_parser("collect", help="collect run results into a bundle")
    collect_cmd.add_argument("--trigger", required=True, help="trigger JSON file, or - for stdin")
    run_cmd = commands.add_parser("run", help="collect then write the HWPX report")
    run_cmd.add_argument("--trigger", required=True, help="trigger JSON file, or - for stdin")
    args = parser.parse_args(argv)
    text = _read_trigger(args.trigger)
    if text is None:
        return EXIT_TRIGGER
    return _run(text) if args.command == "run" else _collect(text)
