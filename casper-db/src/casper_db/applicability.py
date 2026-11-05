"""Evidence-backed software inventories and version applicability, never exploitation."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_serializer, model_validator

from .external_vulnerabilities import ExternalRecord, external_connection, lookup_external
from .import_workflow import WorkflowModel, digest
from .models import Identifier, Text, utc_timestamp
from .version_ranges import matches_range


def _ecosystem(value: str) -> str:
    normalized = value.strip().lower()
    return {"pypi": "pip"}.get(normalized, normalized)


class SoftwareComponent(WorkflowModel):
    ecosystem: Text
    package: Text
    version: Text | None = None
    cpe: Text | None = None
    source_refs: list[Text] = Field(min_length=1, max_length=30)
    call_paths: list[Text] = Field(default_factory=list, max_length=30)
    identification: Literal["observed", "indicator", "declared"] = "observed"
    version_status: Text | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list, max_length=30)

    @field_validator("ecosystem")
    @classmethod
    def normalize_ecosystem(cls, value):
        return _ecosystem(value)

    @model_serializer(mode="wrap")
    def preserve_legacy_inventory_identity(self, handler):
        data = handler(self)
        if self.identification == "observed":
            data.pop("identification", None)
        if self.version_status is None:
            data.pop("version_status", None)
        if not self.evidence:
            data.pop("evidence", None)
        return data


class SoftwareInventory(WorkflowModel):
    schema_version: Literal["casper-software-inventory-1"]
    target_id: Identifier
    observed_at: str
    components: list[SoftwareComponent] = Field(min_length=1, max_length=1000)

    @field_validator("observed_at")
    @classmethod
    def valid_timestamp(cls, value):
        return utc_timestamp(value)

    @model_validator(mode="after")
    def unique_components(self):
        keys = [(item.ecosystem, item.package, item.version, item.cpe) for item in self.components]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate inventory components")
        if datetime.fromisoformat(self.observed_at) > datetime.now(UTC):
            raise ValueError("inventory observation cannot be in the future")
        return self


def _any(values):
    return True if True in values else (None if None in values else False)


def _all(values):
    return False if False in values else (None if None in values else True)


def _package_name(value, ecosystem):
    return re.sub(r"[-_.]+", "-", value).lower() if ecosystem == "pip" else value


def _github(record, inventory):
    matches, details = [], []
    for affected in record.affected:
        package = affected.get("package") or {}
        if not isinstance(package, dict):
            matches.append(None)
            continue
        ecosystem, name = package.get("ecosystem"), package.get("name")
        if not isinstance(ecosystem, str) or not isinstance(name, str):
            matches.append(None)
            continue
        ecosystem = _ecosystem(ecosystem)
        found = [
            c
            for c in inventory.components
            if c.ecosystem == ecosystem
            and _package_name(c.package, ecosystem) == _package_name(name or "", ecosystem)
        ]
        if not found:
            matches.append(None)
        for component in found:
            expression = affected.get("vulnerable_version_range")
            outcome = (
                matches_range(component.version, expression, ecosystem)
                if (component.version and isinstance(expression, str))
                else None
            )
            matches.append(outcome)
            details.append(
                {
                    "package": component.package,
                    "version": component.version,
                    "range": expression,
                    "matches": outcome,
                    "source_refs": component.source_refs,
                    "call_paths": component.call_paths,
                    "identification": component.identification,
                    "version_status": component.version_status,
                }
            )
    return _any(matches) if matches else None, details


def _cpe_parts(value):
    if not isinstance(value, str) or "\\" in value:
        return None
    parts = value.split(":")
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
        return None
    return parts


def _nvd(record, inventory):
    details = []
    relevant = False

    def entry(item):
        nonlocal relevant
        if not isinstance(item, dict) or not isinstance(item.get("vulnerable"), bool):
            return None, None
        relevant = relevant or item["vulnerable"]
        criteria = _cpe_parts(item.get("criteria"))
        if criteria is None:
            return None, None if item.get("vulnerable") else False
        values = []
        for component in inventory.components:
            actual = _cpe_parts(component.cpe)
            if actual is None:
                continue
            if any(x != "*" and x != y for x, y in zip(criteria[2:5], actual[2:5], strict=True)):
                continue
            if any("?" in value or ("*" in value and value != "*") for value in criteria):
                values.append(None)
                continue
            version = component.version or (actual[5] if actual[5] not in {"*", "-"} else None)
            if component.version and actual[5] not in {"*", component.version}:
                values.append(None)
                continue
            predicates = []
            if criteria[5] != "*":
                predicates.append(matches_range(version, "= " + criteria[5], component.ecosystem))
            for key, op in (
                ("versionStartIncluding", ">="),
                ("versionStartExcluding", ">"),
                ("versionEndIncluding", "<="),
                ("versionEndExcluding", "<"),
            ):
                if item.get(key) is not None:
                    predicates.append(
                        matches_range(version, op + " " + item[key], component.ecosystem)
                        if isinstance(item[key], str)
                        else None
                    )
            for expected, observed in zip(criteria[6:], actual[6:], strict=True):
                if expected != "*":
                    predicates.append(None if observed == "*" else expected == observed)
            value = _all(predicates) if version else None
            values.append(value)
            details.append(
                {
                    "package": component.package,
                    "version": version,
                    "criteria": item["criteria"],
                    "matches": value,
                    "source_refs": component.source_refs,
                    "call_paths": component.call_paths,
                    "identification": component.identification,
                    "version_status": component.version_status,
                }
            )
        condition = _any(values) if values else None
        return condition, condition if item.get("vulnerable") is True else False

    def node(value):
        if not isinstance(value, dict):
            return None, None
        if value.get("negate"):
            return None, None
        entries, nodes, children = (
            value.get("cpeMatch", []),
            value.get("nodes", []),
            value.get("children", []),
        )
        if not all(isinstance(items, list) for items in (entries, nodes, children)):
            return None, None
        pairs = [entry(item) for item in entries]
        pairs += [node(child) for child in nodes + children]
        if not pairs:
            return None, None
        operator = value.get("operator", "OR")
        if operator not in {"AND", "OR"}:
            return None, None
        condition = (_all if operator == "AND" else _any)([p[0] for p in pairs])
        risk = _any([p[1] for p in pairs])
        return condition, _all([condition, risk]) if operator == "AND" else risk

    outcomes = [node(value)[1] for value in record.affected]
    return _any(outcomes) if outcomes and relevant else None, details


def assess_record(record: ExternalRecord, inventory: SoftwareInventory) -> dict:
    outcome, details = (_github if record.source == "github" else _nvd)(record, inventory)
    decision = {True: "affected_version", False: "outside_affected_scope", None: "needs_review"}[
        outcome
    ]
    range_decision = decision
    if details and any(item.get("identification", "observed") != "observed" for item in details):
        decision = "needs_review"
    if record.withdrawn:
        decision = "withdrawn"
    payload = {
        "schema_version": "casper-applicability-1",
        "target_id": inventory.target_id,
        "record_id": record.record_id,
        "cve_id": record.cve_id,
        "source_item_sha256": record.source_item_sha256,
        "inventory_sha256": digest(inventory),
        "inventory_observed_at": inventory.observed_at,
        "decision": decision,
        "range_decision": range_decision,
        "component_matches": details,
        "reproduction_state": "not_assessed",
        "automatic_execution_allowed": False,
        "reason": {
            "affected_version": (
                "제공된 구성 요소 버전이 공개 권고의 영향 범위와 일치함. 재현 판정은 별도임."
            ),
            "outside_affected_scope": (
                "제공된 구성 요소와 환경이 평가한 권고의 영향 조건에 해당하지 않음."
            ),
            "needs_review": "구성 요소 식별·버전·범위 또는 환경 조건을 확정할 근거가 부족함.",
            "withdrawn": "철회된 공개 권고이며 현재 취약성의 근거로 사용하지 않음.",
        }[decision],
    }
    return {"assessment_id": "APP-" + digest(payload)[:48], **payload}


def _product_matches(record: ExternalRecord, inventory: SoftwareInventory) -> list[dict]:
    """Select exact product identities before evaluating versions or environment."""
    matches = {}
    if record.source == "github":
        for affected in record.affected:
            package = affected.get("package") if isinstance(affected, dict) else None
            if not isinstance(package, dict):
                continue
            ecosystem, name = package.get("ecosystem"), package.get("name")
            if not isinstance(ecosystem, str) or not isinstance(name, str):
                continue
            ecosystem = _ecosystem(ecosystem)
            for index, component in enumerate(inventory.components):
                if component.ecosystem == ecosystem and (
                    _package_name(component.package, ecosystem) == _package_name(name, ecosystem)
                ):
                    matches[index] = {"component_index": index, "basis": "ecosystem_and_package"}
    else:

        def walk(value):
            if not isinstance(value, dict):
                return
            entries = value.get("cpeMatch", [])
            for item in entries if isinstance(entries, list) else []:
                if not isinstance(item, dict) or item.get("vulnerable") is not True:
                    continue
                criteria = _cpe_parts(item.get("criteria"))
                if criteria is None or any(x in {"*", "-"} for x in criteria[2:5]):
                    continue
                for index, component in enumerate(inventory.components):
                    observed = _cpe_parts(component.cpe)
                    if observed is not None and criteria[2:5] == observed[2:5]:
                        matches[index] = {"component_index": index, "basis": "cpe_product_identity"}
            for key in ("nodes", "children"):
                if isinstance(value.get(key), list):
                    for child in value[key]:
                        walk(child)

        for value in record.affected:
            walk(value)
    return list(matches.values())


def discover_advisories(
    path: Path,
    value: dict | SoftwareInventory,
    *,
    limit: int = 100,
) -> dict:
    """Find locally stored provider records from observed products, without CVE input."""
    inventory = SoftwareInventory.model_validate(value)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("advisory result limit must be between 1 and 500")
    candidates, truncated = [], False
    with external_connection(path) as connection:
        records = [
            ExternalRecord.model_validate_json(snapshot)
            for (snapshot,) in connection.execute(
                "SELECT record_json FROM external_records ORDER BY record_id",
            )
        ]
        aliases = {}
        for record in records:
            if record.source == "github" and record.cve_id and not record.withdrawn:
                for match in _product_matches(record, inventory):
                    aliases.setdefault(record.cve_id, []).append(
                        {
                            "component_index": match["component_index"],
                            "basis": "cve_alias_from_matching_github_package",
                            "source_record_id": record.record_id,
                        }
                    )
        for record in records:
            reasons = _product_matches(record, inventory)
            if record.source == "nvd" and not reasons:
                reasons = [
                    match
                    for match in aliases.get(record.cve_id, [])
                    if inventory.components[match["component_index"]].cpe is None
                ]
                reasons = reasons or _nvd_name_candidates(record, inventory)
            if not reasons:
                continue
            if len(candidates) == limit:
                truncated = True
                break
            data = record.model_dump(mode="json")
            data.pop("raw", None)
            candidates.append(
                {
                    "record": data,
                    "match_reasons": reasons,
                    "assessment": assess_record(record, inventory),
                }
            )
    return {
        "schema_version": "casper-advisory-search-1",
        "target_id": inventory.target_id,
        "inventory_sha256": digest(inventory),
        "candidates": candidates,
        "limit": limit,
        "truncated": truncated,
        "database_written": False,
        "coverage": "stored_advisories_only",
    }


def _nvd_name_candidates(record, inventory):
    """Name-only links may be reviewed, but never create observed CPE identities."""
    products = set()

    def walk(value):
        if not isinstance(value, dict):
            return
        entries = value.get("cpeMatch", [])
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict) or entry.get("vulnerable") is not True:
                continue
            parts = _cpe_parts(entry.get("criteria"))
            if parts is not None and parts[4] not in {"*", "-"}:
                products.add(parts[4].lower().replace("_", "-"))
        for key in ("nodes", "children"):
            if isinstance(value.get(key), list):
                for child in value[key]:
                    walk(child)

    for value in record.affected:
        walk(value)
    return [
        {"component_index": index, "basis": "unconfirmed_product_name_requires_review"}
        for index, component in enumerate(inventory.components)
        if component.cpe is None and component.package.lower().replace("_", "-") in products
    ]


def assess_database(
    path: Path, value: dict | SoftwareInventory, cve_ids: list[str], *, apply=False
):
    inventory = SoftwareInventory.model_validate(value)
    if not cve_ids or len(cve_ids) > 100:
        raise ValueError("provide 1 to 100 CVE identifiers")
    rows, missing = [], []
    for cve_id in dict.fromkeys(cve_ids):
        records = lookup_external(path, cve_id)
        if not records:
            missing.append(cve_id)
        rows.extend(assess_record(record, inventory) for record in records)
    if apply:
        with (
            closing(
                sqlite3.connect(path.resolve(strict=True).as_uri() + "?mode=rw", uri=True)
            ) as connection,
            connection,
        ):
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS external_assessments "
                "(assessment_id TEXT PRIMARY KEY, target_id TEXT NOT NULL, "
                "cve_id TEXT, record_id TEXT NOT NULL, inventory_sha TEXT NOT NULL, "
                "snapshot TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS external_active_inventory "
                "(target_id TEXT PRIMARY KEY, inventory_sha TEXT NOT NULL, "
                "observed_at TEXT NOT NULL)"
            )
            previous = connection.execute(
                "SELECT inventory_sha, observed_at FROM external_active_inventory "
                "WHERE target_id=?",
                (inventory.target_id,),
            ).fetchone()
            inv_sha = digest(inventory)
            if previous and previous[1] == inventory.observed_at and previous[0] != inv_sha:
                raise ValueError("conflicting inventories share one observation timestamp")
            if not previous or previous[1] < inventory.observed_at:
                connection.execute(
                    "INSERT INTO external_active_inventory VALUES (?,?,?) "
                    "ON CONFLICT(target_id) DO UPDATE SET inventory_sha=excluded.inventory_sha, "
                    "observed_at=excluded.observed_at",
                    (inventory.target_id, inv_sha, inventory.observed_at),
                )
            for row in rows:
                current = connection.execute(
                    "SELECT record_json FROM external_records WHERE record_id=?",
                    (row["record_id"],),
                ).fetchone()
                if (
                    not current
                    or json.loads(current[0])["source_item_sha256"] != row["source_item_sha256"]
                ):
                    raise ValueError(
                        "advisory changed during assessment; assess the current revision"
                    )
                connection.execute(
                    "INSERT OR IGNORE INTO external_assessments VALUES (?,?,?,?,?,?)",
                    (
                        row["assessment_id"],
                        inventory.target_id,
                        row["cve_id"],
                        row["record_id"],
                        inv_sha,
                        json.dumps(row, ensure_ascii=False),
                    ),
                )
    return {
        "schema_version": "casper-applicability-batch-1",
        "target_id": inventory.target_id,
        "assessments": rows,
        "missing_advisories": missing,
        "database_written": apply,
    }


def lookup_assessments(path: Path, target_id: str, cve_id: str) -> list[dict]:
    # Source lookup validates the owned external schema and the exact CVE ID.
    current = {r.record_id: r.source_item_sha256 for r in lookup_external(path, cve_id)}
    with closing(
        sqlite3.connect(path.resolve(strict=True).as_uri() + "?mode=ro", uri=True)
    ) as connection:
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='external_assessments'"
        ).fetchone()
        if not exists:
            return []
        active = connection.execute(
            "SELECT inventory_sha FROM external_active_inventory WHERE target_id=?", (target_id,)
        ).fetchone()
        result = []
        for row in connection.execute(
            "SELECT snapshot FROM external_assessments WHERE target_id=? AND cve_id=? "
            "ORDER BY rowid",
            (target_id, cve_id),
        ):
            data = json.loads(row[0])
            payload = {key: value for key, value in data.items() if key != "assessment_id"}
            if data["assessment_id"] != "APP-" + digest(payload)[:48]:
                raise ValueError("stored applicability assessment integrity mismatch")
            data["current"] = bool(
                active
                and active[0] == data["inventory_sha256"]
                and current.get(data["record_id"]) == data["source_item_sha256"]
            )
            result.append(data)
        return result
