"""One read-only query for prior CERT cases and observed-product advisory candidates."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .applicability import SoftwareInventory, discover_advisories
from .attack_catalog import AttackInfoQuery, list_attack_patterns, lookup_attack_info
from .external_vulnerabilities import ExternalBundle, store_external
from .import_workflow import WorkflowModel
from .matching import ParserObservation, assess_observation
from .models import Case, Identifier
from .repository import CaseStore


class KnowledgeQuery(WorkflowModel):
    schema_version: Literal["casper-knowledge-query-1"] = "casper-knowledge-query-1"
    target_id: Identifier
    observations: list[ParserObservation] = Field(default_factory=list, max_length=48)
    inventory: SoftwareInventory | None = None
    attack_queries: list[AttackInfoQuery] = Field(default_factory=list, max_length=20)
    limit: int = Field(default=100, ge=1, le=500, strict=True)

    @model_validator(mode="after")
    def one_target(self):
        if any(item.target_id != self.target_id for item in self.observations):
            raise ValueError("all parser observations must belong to the requested target")
        if self.inventory is not None and self.inventory.target_id != self.target_id:
            raise ValueError("software inventory must belong to the requested target")
        return self


def query_knowledge(
    database: Path, value: dict | KnowledgeQuery, *, external_database: Path | None = None,
) -> dict:
    query = KnowledgeQuery.model_validate(value)
    result = {
        "schema_version": "casper-knowledge-context-1",
        "target_id": query.target_id,
        "automatic_execution_allowed": False,
        "database_written": False,
        "history": {"status": "unavailable", "cases": [], "assessments": []},
        "report_knowledge": {"status": "not_configured", "records": []},
        "external": {"status": "not_requested", "candidates": []},
        "attack_catalog": {"status": "not_configured", "pattern_count": 0, "results": []},
    }
    try:
        store = CaseStore(database)
        cases = store.list_for_target(query.target_id)
        assessments = [assess_observation(store, item) for item in query.observations]
        selected = {match.case_id for item in assessments for match in item.matches}
        relevant = [item for item in cases
                    if not query.observations or item.case_id in selected]
        result["history"] = {
            "status": "ok", "ready_case_count": len(cases),
            "cases": [item.model_dump(mode="json") for item in relevant[:query.limit]],
            "truncated": len(relevant) > query.limit,
            "assessments": [item.model_dump(mode="json") for item in assessments],
        }
        from .report_knowledge import available, target_records

        with store._connect() as connection:
            if available(connection):
                records = target_records(connection, query.target_id, query.limit)
                result['report_knowledge'] = {
                    'status': 'ok', 'truncated': len(records) > query.limit,
                    'records': [
                        {
                            **{key: value for key, value in record.items()
                               if key not in {'field_evidence', 'payload_variants', 'resolutions'}},
                            'runtime_observations': [
                                {**item.model_dump(mode='json'), 'method_source': 'web_parser',
                                 'automatic_execution_allowed': False}
                                for item in query.observations
                                if item.endpoint == record.get('endpoint')
                            ],
                        }
                        for record in records[:query.limit]
                    ],
                }
    except (OSError, ValueError, sqlite3.Error) as exc:
        result["history"]["reason"] = type(exc).__name__
    if query.inventory is not None:
        external = Path(external_database) if external_database is not None else Path(database)
        try:
            with closing(sqlite3.connect(
                external.resolve(strict=True).as_uri() + "?mode=ro", uri=True,
            )) as connection:
                configured = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='external_metadata'"
                ).fetchone()
            if not configured and external_database is None:
                result["external"]["status"] = "not_configured"
            else:
                result["external"] = {
                    "status": "ok",
                    **discover_advisories(external, query.inventory, limit=query.limit),
                }
        except (OSError, ValueError, sqlite3.Error) as exc:
            result["external"].update(status="unavailable", reason=type(exc).__name__)
    try:
        catalog = list_attack_patterns(database)
        result["attack_catalog"] = {
            "status": catalog["status"], "pattern_count": len(catalog["patterns"]),
            "results": [{"query": item.model_dump(mode="json"),
                         "attack_info": lookup_attack_info(database, item)}
                        for item in query.attack_queries],
        }
    except (OSError, ValueError, sqlite3.Error) as exc:
        result["attack_catalog"].update(status="unavailable", reason=type(exc).__name__)
    return result


def store_knowledge(database: Path, cases: list[Case], bundles: list[ExternalBundle]) -> dict:
    """Commit reviewed cases and provider records together in one owned database."""
    if not cases and not bundles:
        raise ValueError("a knowledge import requires cases or advisory bundles")
    result = {}
    store = CaseStore(database)
    with store._connect(write=True) as connection:
        if cases:
            stored = store.add_many(cases, _connection=connection)
            result["cert"] = {key: len(rows) for key, rows in stored.items()}
        if bundles:
            result["external"] = store_external(database, bundles, _connection=connection)
    return result
