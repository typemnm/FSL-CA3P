"""ReportTrigger: the agent's only external input.

Every environment-specific value (source kinds and locations, output location) arrives
here. The agent has no default paths and reads no environment variables.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = "report-trigger-1.0"
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RUN_KINDS = frozenset({"pentest-db-disk", "run-store"})
HISTORY_KINDS = frozenset({"casper-db", "none"})
TOP_LEVEL_KEYS = frozenset({"schemaVersion", "runId", "sources", "capture", "output", "options"})


class TriggerError(ValueError):
    """The trigger is malformed. Nothing has been read or written."""


@dataclass(frozen=True)
class SourceRef:
    kind: str
    location: Path | None


@dataclass(frozen=True)
class Trigger:
    run_id: str
    run: SourceRef
    history: SourceRef
    output_dir: Path


def _record(value: object, name: str) -> dict:
    if not isinstance(value, dict):
        raise TriggerError(f"{name} must be an object")
    return value


def _absolute(value: object, name: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise TriggerError(f"{name} must be a non-empty path string")
    path = Path(value)
    if not path.is_absolute():
        raise TriggerError(f"{name} must be an absolute path")
    return path


def _source(value: object, name: str, kinds: frozenset[str]) -> SourceRef:
    source = _record(value, name)
    if set(source) - {"kind", "location"}:
        raise TriggerError(f"{name} has unknown keys")
    kind = source.get("kind")
    if kind not in kinds:
        raise TriggerError(f"{name}.kind must be one of {sorted(kinds)}")
    if kind == "none":
        if "location" in source:
            raise TriggerError(f"{name}.location is not allowed for kind none")
        return SourceRef(kind, None)
    return SourceRef(kind, _absolute(source.get("location"), f"{name}.location"))


def parse_trigger(data: object) -> Trigger:
    trigger = _record(data, "trigger")
    if set(trigger) - TOP_LEVEL_KEYS:
        raise TriggerError("trigger has unknown keys")
    if trigger.get("schemaVersion") != SCHEMA_VERSION:
        raise TriggerError(f"schemaVersion must be {SCHEMA_VERSION}")
    run_id = trigger.get("runId")
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise TriggerError("runId must be a safe identifier of at most 128 characters")
    sources = _record(trigger.get("sources"), "sources")
    if set(sources) - {"run", "history"}:
        raise TriggerError("sources has unknown keys")
    history = sources.get("history", {"kind": "none"})
    output = _record(trigger.get("output"), "output")
    parsed = Trigger(
        run_id=run_id,
        run=_source(sources.get("run"), "sources.run", RUN_KINDS),
        history=_source(history, "sources.history", HISTORY_KINDS),
        output_dir=_absolute(output.get("dir"), "output.dir"),
    )
    _refuse_output_inside_sources(parsed)
    return parsed


def _resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError) as exc:
        # Python 3.11 reports symlink loops as RuntimeError; its message names the path.
        raise TriggerError("a trigger path cannot be resolved") from exc


def _refuse_output_inside_sources(trigger: Trigger) -> None:
    """Writing the bundle into a source would modify what the agent must only read."""
    output = _resolved(trigger.output_dir)
    bundle = output / "bundle"
    for source in (trigger.run, trigger.history):
        if source.location is None:
            continue
        location = _resolved(source.location)
        if output.is_relative_to(location) or location.is_relative_to(bundle):
            raise TriggerError("output.dir must not overlap a source location")
