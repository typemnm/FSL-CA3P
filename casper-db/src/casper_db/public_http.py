"""Bounded public GET transport with a portable, cross-process provider rate gate."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError

_CURRENT = ContextVar("casper_public_http_policy", default=None)
INTERVALS = {"github": 1.0, "nvd": 6.1}


class PublicCollectionError(ValueError):
    def __init__(self, message, *, code="collection_failed", retryable=False, retry_after=None):
        super().__init__(message)
        self.code, self.retryable, self.retry_after = code, retryable, retry_after


class RequestPolicy:
    def __init__(self, *, max_requests=64, timeout_seconds=180):
        self.max_requests = max_requests
        self.deadline = time.monotonic() + timeout_seconds
        self.requests = 0
        self.used = False

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise PublicCollectionError(
                "public collection reached its total deadline", code="deadline", retryable=True
            )
        return remaining

    def spend(self):
        self.remaining()
        if self.requests >= self.max_requests:
            raise PublicCollectionError(
                "public request budget exhausted", code="request_limit", retryable=True
            )
        self.requests += 1


@contextmanager
def using_policy(policy):
    token = _CURRENT.set(policy)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def current_policy():
    return _CURRENT.get()


def _rate_path():
    path = Path(
        os.environ.get("CASPER_DB_RATE_STATE", Path.home() / ".cache/casper-db/public-rate.sqlite3")
    )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _validate_rate_state(connection):
    names = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    if names - {"provider_rate"}:
        raise PublicCollectionError(
            "provider rate state must use its own SQLite file",
            code="rate_state",
        )


def defer_provider(source, until):
    with sqlite3.connect(_rate_path(), timeout=5) as connection:
        _validate_rate_state(connection)
        connection.execute(
            "CREATE TABLE IF NOT EXISTS provider_rate "
            "(provider TEXT PRIMARY KEY, next_at REAL NOT NULL)"
        )
        connection.execute(
            "INSERT INTO provider_rate VALUES (?,?) ON CONFLICT(provider) DO UPDATE "
            "SET next_at=MAX(next_at,excluded.next_at)",
            (source, until),
        )


def reserve_slot(source, policy, *, not_before=0):
    # Wall time is shared across processes; monotonic time bounds this operation.
    path = _rate_path()
    with sqlite3.connect(path, timeout=min(5, policy.remaining())) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _validate_rate_state(connection)
        connection.execute(
            "CREATE TABLE IF NOT EXISTS provider_rate "
            "(provider TEXT PRIMARY KEY, next_at REAL NOT NULL)"
        )
        previous = connection.execute(
            "SELECT next_at FROM provider_rate WHERE provider=?", (source,)
        ).fetchone()
        now = time.time()
        slot = max(now, not_before, previous[0] if previous else now)
        delay = max(0, slot - now)
        if delay >= policy.remaining():
            raise PublicCollectionError(
                "provider cooldown exceeds the remaining deadline",
                code="cooldown",
                retryable=True,
                retry_after=delay,
            )
        connection.execute(
            "INSERT INTO provider_rate VALUES (?,?) ON CONFLICT(provider) "
            "DO UPDATE SET next_at=excluded.next_at",
            (source, slot + INTERVALS[source]),
        )
    if delay:
        time.sleep(delay)
    policy.remaining()


def _retry_delay(headers, attempt):
    value = headers.get("Retry-After")
    if value:
        try:
            return max(0, float(value))
        except ValueError:
            try:
                return max(0, parsedate_to_datetime(value).timestamp() - time.time())
            except (ValueError, TypeError, OverflowError):
                pass
    if headers.get("X-RateLimit-Remaining") == "0":
        try:
            return max(1, float(headers["X-RateLimit-Reset"]) - time.time())
        except (KeyError, ValueError):
            pass
    return 2**attempt


def read_public_json(opener, request, source, *, max_bytes, policy=None):
    policy = policy or _CURRENT.get() or RequestPolicy()
    policy.used = True
    not_before = 0
    for attempt in range(3):
        if policy.requests >= policy.max_requests:
            raise PublicCollectionError(
                "public request budget exhausted",
                code="request_limit",
                retryable=True,
            )
        try:
            reserve_slot(source, policy, not_before=not_before)
        except sqlite3.Error:
            raise PublicCollectionError(
                "provider rate state is unavailable",
                code="rate_state",
                retryable=True,
            ) from None
        policy.spend()
        try:
            with opener.open(request, timeout=min(30, policy.remaining())) as response:
                content = response.read(max_bytes + 1)
                policy.remaining()
                if len(content) > max_bytes:
                    raise ValueError("public response exceeds the 16 MB limit")
                return json.loads(content), response.headers
        except HTTPError as exc:
            headers = exc.headers or {}
            retryable = (
                exc.code == 429
                or exc.code >= 500
                or (
                    exc.code == 403
                    and (headers.get("Retry-After") or headers.get("X-RateLimit-Remaining") == "0")
                )
            )
            delay = _retry_delay(headers, attempt)
            status = exc.code
            exc.close()
            if retryable:
                defer_provider(source, time.time() + delay)
            if not retryable or attempt == 2:
                raise PublicCollectionError(
                    f"public provider returned HTTP {status}; no DB was written by this collector",
                    code=f"http_{status}",
                    retryable=bool(retryable),
                    retry_after=delay if retryable else None,
                ) from None
            not_before = time.time() + delay
        except (URLError, OSError) as exc:
            if attempt == 2:
                raise PublicCollectionError(
                    "public provider connection failed; no DB was written by this collector",
                    code="connection",
                    retryable=True,
                ) from exc
            not_before = time.time() + 2**attempt
    raise AssertionError("unreachable")


def error_details(error):
    return {
        "code": getattr(error, "code", "invalid_source"),
        "retryable": getattr(error, "retryable", False),
        "retry_after_seconds": getattr(error, "retry_after", None),
        "recorded_at": datetime.now(UTC).isoformat(),
    }
