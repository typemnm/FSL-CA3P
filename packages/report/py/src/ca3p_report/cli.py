"""Command line entry point. Reads a ReportTrigger and prints one JSON result."""

from __future__ import annotations

import argparse
import json
import sys

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ca3p-report", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect_cmd = commands.add_parser("collect", help="collect run results into a bundle")
    collect_cmd.add_argument("--trigger", required=True, help="trigger JSON file, or - for stdin")
    args = parser.parse_args(argv)
    try:
        if args.trigger == "-":
            text = sys.stdin.buffer.read().decode("utf-8")
        else:
            with open(args.trigger, encoding="utf-8") as handle:
                text = handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        reason = "not UTF-8" if isinstance(exc, UnicodeDecodeError) else "not readable"
        _emit(_failure(None, "TRIGGER_UNREADABLE", f"trigger is {reason}"))
        return EXIT_TRIGGER
    return _collect(text)
