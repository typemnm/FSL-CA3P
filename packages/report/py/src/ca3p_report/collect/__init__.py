"""Read-only collectors. Each driver turns one result source into the bundle's run shape."""

from .model import CollectError, RunRecord, StoredEvent

__all__ = ["CollectError", "RunRecord", "StoredEvent"]
