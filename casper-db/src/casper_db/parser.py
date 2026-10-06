"""Extract input locations from a saved HTML page without making network requests.

This is a first-pass endpoint parser for the single mock-site exercise. It observes
HTML forms and same-origin links with query strings; it does not test for XSS.
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

from pydantic import TypeAdapter, ValidationError

from .matching import ParserObservation
from .models import Identifier

TARGET_ID = TypeAdapter(Identifier)


@dataclass
class ParseResult:
    observations: list[ParserObservation]
    warnings: list[str]


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        raise ValueError("page URL must be an absolute HTTP(S) URL without credentials")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, parts.hostname.lower(), port


class _InputCollector(HTMLParser):
    def __init__(self, target_id: str, page_url: str):
        super().__init__(convert_charrefs=True)
        self.target_id = target_id
        self.page_url = page_url
        self.allowed_origin = _origin(page_url)
        self.form: tuple[str, str] | None = None
        self.warnings: list[str] = []
        self.observations: list[ParserObservation] = []
        self.seen: set[tuple[str, str, str, str, str]] = set()

    def _local_path(self, value: str, kind: str) -> tuple[str, str] | None:
        try:
            resolved = urljoin(self.page_url, value)
            if _origin(resolved) != self.allowed_origin:
                self.warnings.append(f"ignored cross-origin {kind}")
                return None
            parts = urlsplit(resolved)
            return parts.path or "/", parts.query
        except ValueError:
            self.warnings.append(f"ignored invalid {kind}")
            return None

    def _add(self, endpoint: str, method: str, parameter: str, location: str) -> None:
        try:
            item = ParserObservation(
                target_id=self.target_id,
                endpoint=endpoint,
                method=method,
                parameter=parameter,
                parameter_location=location,
            )
        except ValidationError:
            self.warnings.append(f"ignored invalid input name or path: {parameter!r}")
            return
        key = (
            item.target_id, item.endpoint, item.method,
            item.parameter, item.parameter_location,
        )
        if key not in self.seen:
            self.seen.add(key)
            self.observations.append(item)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form":
            if self.form is not None:
                self.warnings.append("ignored nested form")
                self.form = None
                return
            method = (values.get("method") or "GET").upper()
            if method not in ("GET", "POST"):
                self.warnings.append(f"ignored unsupported form method: {method}")
                return
            target = self._local_path(values.get("action") or self.page_url, "form action")
            if target is None:
                return
            endpoint, query = target
            self.form = (endpoint, method)
            for name, _ in parse_qsl(query, keep_blank_values=True):
                self._add(endpoint, method, name, "query")
        elif tag in ("input", "textarea", "select") and self.form is not None:
            if "disabled" in values:
                return
            if tag == "input" and (values.get("type") or "text").lower() in (
                "button", "reset", "submit", "image", "file"
            ):
                return
            name = values.get("name")
            if name:
                endpoint, method = self.form
                self._add(endpoint, method, name, "query" if method == "GET" else "body")
        elif tag == "a" and values.get("href"):
            target = self._local_path(values["href"], "link")
            if target is not None:
                endpoint, query = target
                for name, _ in parse_qsl(query, keep_blank_values=True):
                    self._add(endpoint, "GET", name, "query")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.form = None


def parse_html_inputs(html_text: str, *, page_url: str, target_id: str) -> ParseResult:
    """Parse one already-saved page; no fetch, browser execution, or vulnerability test."""
    if len(html_text) > 2_000_000:
        raise ValueError("HTML snapshot exceeds the 2,000,000-character prototype limit")
    TARGET_ID.validate_python(target_id, strict=True)
    collector = _InputCollector(target_id, page_url)
    collector.feed(html_text)
    collector.close()
    return ParseResult(collector.observations, collector.warnings)
