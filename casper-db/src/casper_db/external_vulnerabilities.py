"""Public advisory collection, normalization and a separate, explicit SQLite store.

Public product/version claims are never converted into a confirmed site vulnerability.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import Field

from .import_workflow import WorkflowModel, digest

ENDPOINTS = {
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "github": "https://api.github.com/advisories",
}
PARAMETERS = {
    "nvd": {
        "cveId",
        "keywordSearch",
        "lastModStartDate",
        "lastModEndDate",
        "startIndex",
        "resultsPerPage",
    },
    "github": {
        "cve_id",
        "ghsa_id",
        "ecosystem",
        "updated",
        "modified",
        "after",
        "per_page",
        "type",
        "sort",
        "direction",
    },
}
MAX_RESPONSE_BYTES = 16_000_000


class ExternalRecord(WorkflowModel):
    record_id: str
    cve_id: str | None = None
    advisory_id: str
    source: Literal["nvd", "github"]
    description: str
    published_at: str | None = None
    modified_at: str | None = None
    withdrawn: bool = False
    severity: str | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)
    cwe_ids: list[str] = Field(default_factory=list)
    affected: list[dict[str, Any]] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    source_item_sha256: str
    raw: dict[str, Any]
    applicability: Literal["not_assessed"] = "not_assessed"


class ExternalBundle(WorkflowModel):
    schema_version: Literal["external-vuln-1"] = "external-vuln-1"
    source: Literal["nvd", "github"]
    source_url: str | None = None
    retrieved_at: str
    raw_sha256: str
    raw: Any
    records: list[ExternalRecord]
    rejected_items: list[dict[str, Any]] = Field(default_factory=list)
    pagination: dict[str, Any] = Field(default_factory=dict)


def _timestamp(value, *, source):
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        if source != "nvd":
            raise ValueError("public advisory timestamp must include a timezone")
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat()


def normalize_external(
    source: Literal["nvd", "github"],
    raw: Any,
    *,
    source_url: str | None = None,
) -> ExternalBundle:
    if source not in ENDPOINTS:
        raise ValueError("unsupported public source")
    if source == "nvd":
        if not isinstance(raw, dict) or not isinstance(raw.get("vulnerabilities"), list):
            raise ValueError("expected an NVD 2.0 vulnerabilities page")
        items = raw["vulnerabilities"]
    else:
        if not isinstance(raw, list):
            raise ValueError("expected a GitHub global advisory list")
        items = raw
    records, rejected, seen = [], [], set()
    for index, item in enumerate(items):
        try:
            if not isinstance(item, dict):
                raise ValueError("entry is not an object")
            data = item.get("cve") if source == "nvd" else item
            if not isinstance(data, dict):
                raise ValueError("missing CVE object")
            cve = data.get("id") if source == "nvd" else data.get("cve_id")
            cve = cve.upper() if isinstance(cve, str) else None
            advisory = cve if source == "nvd" else data.get("ghsa_id")
            if cve is not None and not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
                raise ValueError("invalid CVE identifier")
            if not advisory or (
                source == "github"
                and not re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", advisory)
            ):
                raise ValueError("missing or invalid advisory identifier")
            identity = f"{source}:{advisory}"
            if identity in seen:
                raise ValueError("duplicate advisory in source page")
            seen.add(identity)
            if source == "nvd":
                descriptions = data.get("descriptions", [])
                description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                description = description or next((d.get("value", "") for d in descriptions), "")
                cwes = sorted(
                    {
                        d["value"]
                        for w in data.get("weaknesses", [])
                        for d in w.get("description", [])
                        if re.fullmatch(r"CWE-\d+", d.get("value", ""))
                    }
                )
                affected, metrics = data.get("configurations", []), data.get("metrics", {})
                references = [
                    ref["url"]
                    for ref in data.get("references", [])
                    if isinstance(ref, dict) and ref.get("url")
                ]
                withdrawn = data.get("vulnStatus", "").casefold() == "rejected"
                published, modified, severity = (
                    data.get("published"),
                    data.get("lastModified"),
                    None,
                )
                levels = {
                    str(
                        metric.get("cvssData", {}).get("baseSeverity") or metric.get("baseSeverity")
                    ).lower()
                    for values in metrics.values()
                    if isinstance(values, list)
                    for metric in values
                    if metric.get("cvssData", {}).get("baseSeverity") or metric.get("baseSeverity")
                }
                severity = next(iter(levels)) if len(levels) == 1 else None
            else:
                description = data.get("description") or data.get("summary") or ""
                cwes = [
                    w["cwe_id"]
                    for w in data.get("cwes", [])
                    if re.fullmatch(r"CWE-\d+", w.get("cwe_id", ""))
                ]
                affected = data.get("vulnerabilities", [])
                metrics = {k: data[k] for k in ("cvss", "cvss_severities", "epss") if k in data}
                references = data.get("references", [])
                withdrawn = bool(data.get("withdrawn_at"))
                published, modified, severity = (
                    data.get("published_at"),
                    data.get("updated_at"),
                    data.get("severity"),
                )
            records.append(
                ExternalRecord(
                    record_id=identity,
                    cve_id=cve,
                    advisory_id=advisory,
                    source=source,
                    description=description,
                    published_at=_timestamp(published, source=source),
                    modified_at=_timestamp(modified, source=source),
                    withdrawn=withdrawn,
                    severity=severity,
                    metrics=metrics,
                    cwe_ids=cwes,
                    affected=affected,
                    references=references,
                    source_item_sha256=digest(item),
                    raw=item,
                )
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            rejected.append({"index": index, "reason": str(exc), "raw": item})
    pagination = {
        k: raw[k]
        for k in ("startIndex", "resultsPerPage", "totalResults")
        if source == "nvd" and k in raw
    }
    if source == "nvd" and all(k in pagination for k in ("startIndex", "totalResults")):
        pagination["next_start_index"] = int(pagination["startIndex"]) + len(items)
        pagination["has_more"] = pagination["next_start_index"] < int(pagination["totalResults"])
    return ExternalBundle(
        source=source,
        source_url=source_url,
        retrieved_at=datetime.now(UTC).isoformat(),
        raw_sha256=digest(raw),
        raw=raw,
        records=records,
        rejected_items=rejected,
        pagination=pagination,
    )


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("public collector refuses redirects")


def collect_external(
    source: Literal["nvd", "github"],
    *,
    params: dict[str, str | int] | None = None,
    max_pages: int = 1,
) -> list[ExternalBundle]:
    """Explicit bounded public GETs; no report text, target URLs or tokens are sent."""
    if source not in ENDPOINTS or not 1 <= max_pages <= 20:
        raise ValueError("unsupported source or page limit (1..20)")
    query = dict(params or {})
    if query.keys() - PARAMETERS[source]:
        raise ValueError("unsupported public-source query parameter")
    if source == "nvd":
        query.setdefault("resultsPerPage", 100)
        query.setdefault("startIndex", 0)
        if not 1 <= int(query["resultsPerPage"]) <= 2000 or int(query["startIndex"]) < 0:
            raise ValueError("invalid NVD pagination")
        if bool(query.get("lastModStartDate")) != bool(query.get("lastModEndDate")):
            raise ValueError("NVD modified time window requires both dates")
        if query.get("lastModStartDate"):
            start = datetime.fromisoformat(str(query["lastModStartDate"]))
            end = datetime.fromisoformat(str(query["lastModEndDate"]))
            if (
                start.tzinfo is None
                or end.tzinfo is None
                or not timedelta(0) < end - start <= timedelta(days=120)
            ):
                raise ValueError(
                    "NVD window requires timezone-aware dates, ascending within 120 days"
                )
    else:
        query.setdefault("per_page", 100)
        if not 1 <= int(query["per_page"]) <= 100:
            raise ValueError("invalid GitHub page size")
    opener = build_opener(NoRedirect())
    bundles = []
    for page in range(max_pages):
        if page:
            time.sleep(6.1 if source == "nvd" else 1)
        url = ENDPOINTS[source] + "?" + urlencode(query)
        headers = {"Accept": "application/json", "User-Agent": "CASPER-local-vuln-db/0.2"}
        if source == "github":
            headers.update(
                {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"}
            )
        try:
            with opener.open(Request(url, headers=headers), timeout=30) as response:
                content = response.read(MAX_RESPONSE_BYTES + 1)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise ValueError("public response exceeds the 16 MB limit")
                bundle = normalize_external(source, json.loads(content), source_url=url)
                bundles.append(bundle)
                link = response.headers.get("Link", "")
        except (HTTPError, URLError, OSError) as exc:
            raise ValueError(f"public collection failed; no DB was written: {exc}") from exc
        if source == "nvd":
            next_index = int(query["startIndex"]) + len(bundle.raw["vulnerabilities"])
            if next_index >= int(bundle.raw.get("totalResults", 0)) or not bundle.records:
                break
            query["startIndex"] = next_index
        else:
            match = re.search(r'<([^>]+)>;\s*rel="next"', link)
            bundle.pagination["has_more"] = bool(match)
            if not match:
                break
            next_page = urlsplit(match[1])
            if (next_page.scheme, next_page.netloc, next_page.path) != (
                "https",
                "api.github.com",
                "/advisories",
            ):
                raise ValueError("unexpected GitHub pagination origin")
            cursors = parse_qs(next_page.query).get("after", [])
            if len(cursors) != 1:
                raise ValueError("missing GitHub pagination cursor")
            query["after"] = cursors[0]
            bundle.pagination["next_after"] = cursors[0]
    return bundles


def store_external(path: Path, bundles: list[ExternalBundle]) -> dict[str, int]:
    """Explicit storage only. Keep provider claims separate and all content revisions."""
    if not bundles or any(bundle.rejected_items for bundle in bundles):
        raise ValueError("external bundle has rejected entries; review before storing")
    for bundle in bundles:
        if digest(bundle.raw) != bundle.raw_sha256:
            raise ValueError("external raw SHA-256 mismatch")
        rebuilt = normalize_external(bundle.source, bundle.raw, source_url=bundle.source_url)
        if rebuilt.records != bundle.records:
            raise ValueError("external normalized records do not match their raw source")
    if path.exists():
        readonly = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        try:
            names = {
                row[0]
                for row in readonly.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if "cases" in names or (names and "external_metadata" not in names):
                raise ValueError("external records require a separate external database")
        finally:
            readonly.close()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    result = {"created": 0, "updated": 0, "unchanged": 0, "historical_only": 0}
    try:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS external_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            marker = connection.execute(
                "SELECT value FROM external_metadata WHERE key='schema'"
            ).fetchone()
            if marker is not None and marker[0] != "external-vuln-1":
                raise ValueError("unsupported external database schema")
            if connection.execute("SELECT 1 FROM sqlite_master WHERE name='cases'").fetchone():
                raise ValueError("external records require a separate external database")
            connection.execute(
                "INSERT OR IGNORE INTO external_metadata VALUES ('schema','external-vuln-1')"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS external_sources "
                "(raw_sha256 TEXT PRIMARY KEY, source TEXT NOT NULL, source_url TEXT, "
                "retrieved_at TEXT NOT NULL, raw_json TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS external_revisions "
                "(record_id TEXT NOT NULL, content_sha256 TEXT NOT NULL, "
                "record_json TEXT NOT NULL, "
                "PRIMARY KEY(record_id, content_sha256))"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS external_records "
                "(record_id TEXT PRIMARY KEY, cve_id TEXT, modified_at TEXT, "
                "content_sha256 TEXT NOT NULL, record_json TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS external_provenance "
                "(record_id TEXT NOT NULL, content_sha256 TEXT NOT NULL, raw_sha256 TEXT NOT NULL, "
                "PRIMARY KEY(record_id, content_sha256, raw_sha256))"
            )
            for bundle in bundles:
                connection.execute(
                    "INSERT OR IGNORE INTO external_sources VALUES (?,?,?,?,?)",
                    (
                        bundle.raw_sha256,
                        bundle.source,
                        bundle.source_url,
                        bundle.retrieved_at,
                        json.dumps(bundle.raw, ensure_ascii=False),
                    ),
                )
                for record in bundle.records:
                    body, content_hash = record.model_dump_json(), digest(record)
                    old = connection.execute(
                        "SELECT content_sha256, modified_at FROM external_records "
                        "WHERE record_id=?",
                        (record.record_id,),
                    ).fetchone()
                    connection.execute(
                        "INSERT OR IGNORE INTO external_revisions VALUES (?,?,?)",
                        (record.record_id, content_hash, body),
                    )
                    connection.execute(
                        "INSERT OR IGNORE INTO external_provenance VALUES (?,?,?)",
                        (record.record_id, content_hash, bundle.raw_sha256),
                    )
                    if old is not None and old[0] == content_hash:
                        result["unchanged"] += 1
                        continue
                    if old and old[1] and (not record.modified_at or old[1] > record.modified_at):
                        result["historical_only"] += 1
                        continue
                    connection.execute(
                        "INSERT INTO external_records VALUES (?,?,?,?,?) "
                        "ON CONFLICT(record_id) DO UPDATE SET cve_id=excluded.cve_id, "
                        "modified_at=excluded.modified_at, content_sha256=excluded.content_sha256, "
                        "record_json=excluded.record_json",
                        (record.record_id, record.cve_id, record.modified_at, content_hash, body),
                    )
                    result["updated" if old else "created"] += 1
    finally:
        connection.close()
    return result


def lookup_external(path: Path, cve_id: str) -> list[ExternalRecord]:
    """Read provider records for an exact CVE; never create or migrate a database."""
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise ValueError("lookup requires an exact CVE identifier")
    resolved = path.resolve(strict=True)
    connection = sqlite3.connect(resolved.as_uri() + "?mode=ro", uri=True)
    try:
        schema = connection.execute(
            "SELECT value FROM external_metadata WHERE key='schema'"
        ).fetchone()
        if schema != ("external-vuln-1",):
            raise ValueError("unsupported external database schema")
        rows = connection.execute(
            "SELECT record_json FROM external_records WHERE cve_id=? ORDER BY record_id",
            (cve_id,),
        )
        return [ExternalRecord.model_validate_json(row[0]) for row in rows]
    finally:
        connection.close()
