"""Inventory-driven public collection, explicit unified storage, then a local query.

Only package identities and versions leave this process. Report contents, target URLs,
inventory evidence, and call paths are never passed to the public collectors.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .applicability import SoftwareInventory, _cpe_parts, _product_matches
from .external_vulnerabilities import ExternalBundle, collect_external, normalize_external
from .import_workflow import WorkflowModel, digest
from .knowledge import KnowledgeQuery, query_knowledge, store_knowledge
from .public_http import RequestPolicy, error_details, using_policy
from .repository import initialize_database
from .sync_journal import begin_sync, finish_sync
from .version_ranges import matches_range

GITHUB_ECOSYSTEMS = {
    "rubygems",
    "npm",
    "pip",
    "maven",
    "nuget",
    "composer",
    "go",
    "rust",
    "erlang",
    "actions",
    "pub",
    "other",
    "swift",
}


class KnowledgeSync(WorkflowModel):
    query: KnowledgeQuery
    providers: list[Literal["github", "nvd"]] = Field(
        default_factory=lambda: ["github", "nvd"],
        min_length=1,
        max_length=2,
    )
    max_pages: int = Field(default=2, ge=1, le=20, strict=True)
    max_requests: int = Field(default=20, ge=1, le=64, strict=True)
    timeout_seconds: int = Field(default=180, ge=1, le=600, strict=True)
    input_truncated: bool = False
    omitted_components: int = Field(default=0, ge=0, le=100000, strict=True)

    @model_validator(mode="after")
    def bounded_inventory(self):
        if len(set(self.providers)) != len(self.providers):
            raise ValueError("providers must be unique")
        inventory = self.query.inventory
        if inventory is None or len(inventory.components) > 20:
            raise ValueError("sync requires an inventory with 1..20 observed components")
        for component in inventory.components:
            # Commas and @version suffixes must not become extra GitHub affects filters.
            if not re.fullmatch(r"@?[A-Za-z0-9][A-Za-z0-9._/:+ -]{0,198}", component.package):
                raise ValueError("package must be a product name or canonical package identity")
            if component.version is not None and not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,99}",
                component.version,
            ):
                raise ValueError("version contains unsupported query characters")
            if component.cpe is not None:
                parts = _cpe_parts(component.cpe)
                if (
                    parts is None
                    or parts[2] not in {"a", "o", "h"}
                    or any(part in {"*", "-"} for part in parts[3:5])
                    or any(char.isspace() for char in component.cpe)
                ):
                    raise ValueError("cpe must identify a CPE 2.3 vendor and product")
        return self


def _github_params(component):
    if component.ecosystem not in GITHUB_ECOSYSTEMS or " " in component.package:
        return None
    package = component.package
    if component.ecosystem == "pip":
        package = re.sub(r"[-_.]+", "-", package).lower()
    if "@" in package[1:]:
        return None
    version = (
        component.version
        if component.version
        and matches_range(
            component.version,
            "*",
            component.ecosystem,
        )
        is True
        else None
    )
    return {
        "ecosystem": component.ecosystem,
        "affects": package + ("@" + version if version else ""),
        "type": "reviewed",
        "per_page": 100,
    }


def sync_knowledge(database: Path, value: dict | KnowledgeSync, *, apply: bool = False) -> dict:
    """Discover CVEs from observed products; never require a CVE in the input."""
    request = KnowledgeSync.model_validate(value)
    inventory = request.query.inventory
    result = {
        "schema_version": "casper-knowledge-sync-1",
        "target_id": request.query.target_id,
        "mode": "apply" if apply else "dry_run",
        "started_at": datetime.now(UTC).isoformat(),
        "inventory_sha256": digest(inventory),
        "jobs": [],
        "errors": [],
        "database_written": False,
        "commits": {},
        "automatic_execution_allowed": False,
        "coverage": {
            "all_public_advisories": False,
            "max_pages_per_job": request.max_pages,
            "input_truncated": request.input_truncated,
            "omitted_components": request.omitted_components,
            "max_requests": request.max_requests,
            "nvd_strategy": "discovered_github_cve_then_cpe_or_keyword_fallback",
        },
    }
    bundles: list[ExternalBundle] = []
    journal_id = begin_sync(database, result) if apply else None
    seen = {}
    requests = 0
    started = time.monotonic()
    policy = RequestPolicy(
        max_requests=request.max_requests, timeout_seconds=request.timeout_seconds
    )

    def collect(source, params, component_index, basis):
        nonlocal requests
        key = digest({"source": source, "params": params})
        if key in seen:
            job, previous = seen[key]
            if component_index not in job["components"]:
                job["components"].append(component_index)
            return previous
        job = {
            "source": source,
            "params": params,
            "basis": basis,
            "components": [component_index],
            "pages": 0,
            "records": 0,
        }
        result["jobs"].append(job)
        seen[key] = job, []
        remaining = request.max_requests - requests
        if remaining <= 0:
            job.update(status="request_limit", complete=False)
            return []
        pages = min(request.max_pages, remaining)
        requests += pages
        try:
            with using_policy(policy):
                collected = collect_external(source, params=params, max_pages=pages)
            if not collected or any(bundle.rejected_items for bundle in collected):
                raise ValueError("source returned no valid page or contains rejected entries")
            for bundle in collected:
                if (
                    bundle.source != source
                    or digest(bundle.raw) != bundle.raw_sha256
                    or (normalize_external(source, bundle.raw).records != bundle.records)
                ):
                    raise ValueError("collected records do not match their provider raw source")
            requests -= pages - len(collected)
            last = collected[-1].pagination
            complete = not bool(last.get("has_more"))
            job.update(
                status="collected" if complete else "page_limit",
                complete=complete,
                pages=len(collected),
                records=sum(len(b.records) for b in collected),
                sources=[
                    {
                        "url": b.source_url,
                        "retrieved_at": b.retrieved_at,
                        "raw_sha256": b.raw_sha256,
                    }
                    for b in collected
                ],
            )
            bundles.extend(collected)
            seen[key] = job, collected
            return collected
        except (ValueError, OSError) as exc:
            # A failure after partial pagination still consumes its reserved budget.
            job.update(status="failed", complete=False)
            result["errors"].append(
                {
                    "source": source,
                    "components": [component_index],
                    "message": str(exc),
                    **error_details(exc),
                }
            )
            partial = getattr(exc, "partial_bundles", [])
            if partial and all(
                bundle.source == source
                and not bundle.rejected_items
                and digest(bundle.raw) == bundle.raw_sha256
                and normalize_external(source, bundle.raw).records == bundle.records
                for bundle in partial
            ):
                bundles.extend(partial)
                job.update(
                    status="partial_failure",
                    pages=len(partial),
                    records=sum(len(bundle.records) for bundle in partial),
                )
                seen[key] = job, partial
                return partial
            return []
        finally:
            if policy.used:
                requests = policy.requests

    for index, component in enumerate(inventory.components):
        github = []
        if "github" in request.providers:
            params = _github_params(component)
            if params is None:
                result["jobs"].append(
                    {
                        "source": "github",
                        "components": [index],
                        "status": "unsupported_identity",
                        "complete": False,
                    }
                )
            else:
                github = collect("github", params, index, "observed_package_and_version")
        if "nvd" not in request.providers:
            continue
        single = SoftwareInventory(
            target_id=inventory.target_id,
            observed_at=inventory.observed_at,
            schema_version=inventory.schema_version,
            components=[component],
        )
        cves = sorted(
            {
                record.cve_id
                for bundle in github
                for record in bundle.records
                if record.cve_id and not record.withdrawn and _product_matches(record, single)
            }
        )
        for offset, cve in enumerate(cves):
            if requests >= request.max_requests:
                result["jobs"].append(
                    {
                        "source": "nvd",
                        "components": [index],
                        "status": "request_limit",
                        "basis": "cve_discovered_from_matching_github_package",
                        "complete": False,
                        "deferred_queries": len(cves) - offset,
                    }
                )
                break
            collect(
                "nvd",
                {"cveId": cve, "resultsPerPage": 100},
                index,
                "cve_discovered_from_matching_github_package",
            )
        if component.cpe:
            key = "virtualMatchString" if "*" in component.cpe.split(":")[2:6] else "cpeName"
            collect("nvd", {key: component.cpe, "resultsPerPage": 100}, index, "observed_cpe")
        elif not cves:
            # No inferred vendor or CPE is promoted to an observed installed identity.
            collect(
                "nvd",
                {"keywordSearch": component.package, "resultsPerPage": 100},
                index,
                "product_keyword_candidates_require_identity_review",
            )

    if apply and bundles:
        initialize_database(database)
        result["commits"] = store_knowledge(database, [], bundles)
        result["database_written"] = True
    complete = not request.input_truncated and all(job["complete"] for job in result["jobs"])
    result.update(
        status="complete" if complete else "partial",
        request_count=requests,
        elapsed_seconds=round(time.monotonic() - started, 3),
        collection_complete=complete,
        completed_at=datetime.now(UTC).isoformat(),
    )
    result["knowledge"] = query_knowledge(database, request.query)
    if apply:
        finish_sync(database, journal_id, result)
    return result
