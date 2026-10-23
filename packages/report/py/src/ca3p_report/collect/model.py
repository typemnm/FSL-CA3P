"""Source-neutral run shape shared by every run collector."""

from __future__ import annotations

from dataclasses import dataclass, field


class CollectError(RuntimeError):
    """A source exists but holds data that contradicts its own contract."""


@dataclass(frozen=True)
class StoredEvent:
    """One agent event as the core recorded it: {stage, request, response}."""

    stage: str
    iteration: int | None
    recorded_at: str | None
    message_id: str | None
    request: dict
    response: dict

    def to_json(self) -> dict:
        return {
            "stage": self.stage,
            "iteration": self.iteration,
            "recordedAt": self.recorded_at,
            "messageId": self.message_id,
            "request": self.request,
            "response": self.response,
        }


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    driver: str
    # The orchestrator's final report object, or None when the run never finalized.
    report: dict | None
    stored_at: str | None
    # Provenance as the source recorded it; never upgraded to "verified" here.
    provenance: dict | None
    events: list[StoredEvent] = field(default_factory=list)
