"""Read-only queries, plus an explicitly enabled advisory ingestion endpoint."""

import sqlite3
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query
from pydantic import ValidationError

from .advisory_sync import KnowledgeSync, sync_knowledge
from .attack_catalog import (
    AttackInfoQuery,
    get_attack_template,
    list_attack_patterns,
    lookup_attack_info,
)
from .knowledge import KnowledgeQuery, query_knowledge
from .models import CaseRecord
from .repository import CaseStore, NotFoundError


def create_app(
    database_path: str | Path, *, intake_workspace: Path | None = None,
    external_database: Path | None = None,
    enable_advisory_sync: bool = False,
) -> FastAPI:
    store = CaseStore(database_path)
    app = FastAPI(
        title="CASPER Knowledge DB",
        version="0.4.0",
        description="CERT case and product advisory queries; no exploit execution.",
    )

    if enable_advisory_sync:
        if external_database is not None and (
            external_database.resolve() != Path(database_path).resolve()
        ):
            raise ValueError("advisory sync requires one unified database")

        @app.post("/knowledge/sync")
        def knowledge_sync(request: KnowledgeSync):
            try:
                return sync_knowledge(Path(database_path), request, apply=True)
            except (ValueError, OSError, sqlite3.Error):
                raise HTTPException(
                    status_code=409, detail="advisory sync could not commit",
                ) from None

    @app.post("/knowledge/query")
    def knowledge_query(request: KnowledgeQuery):
        return query_knowledge(
            Path(database_path), request, external_database=external_database,
        )

    @app.get("/attack-patterns")
    def attack_patterns():
        return list_attack_patterns(Path(database_path))

    @app.post("/attack-info/query")
    def attack_info_query(request: AttackInfoQuery):
        try:
            return {"schema_version": "casper-attack-info-1",
                    "attack_info": lookup_attack_info(Path(database_path), request)}
        except ValueError:
            raise HTTPException(
                status_code=422, detail="ambiguous or invalid attack query",
            ) from None

    @app.get("/attack-templates/{template_id}/versions/{version}")
    def attack_template(template_id: str, version: str):
        template = get_attack_template(Path(database_path), template_id, version)
        if template is None:
            raise HTTPException(status_code=404, detail="attack template not registered")
        return template

    def references(target_id: str, cve_id: Annotated[list[str] | None, Query()] = None):
        from .reference_context import build_reference_context

        try:
            return build_reference_context(
                target_id, workspace=intake_workspace, external_database=external_database,
                cve_ids=cve_id,
            )
        except ValueError:
            raise HTTPException(status_code=422, detail="invalid reference request") from None

    if intake_workspace is not None or external_database is not None:
        app.get("/references")(references)

    @app.get("/cases", response_model=list[CaseRecord])
    def find_cases(
        target_id: str, endpoint: str | None = None, method: str | None = None,
        parameter: str | None = None, parameter_location: str | None = None,
    ):
        if (endpoint is None) != (method is None):
            raise HTTPException(
                status_code=422, detail="endpoint and method must be given together"
            )
        if parameter is not None and endpoint is None:
            raise HTTPException(status_code=422, detail="parameter requires endpoint and method")
        if parameter_location is not None and parameter is None:
            raise HTTPException(status_code=422, detail="parameter_location requires parameter")
        try:
            if endpoint is None:
                return store.list_for_target(target_id)
            return store.find(target_id=target_id, endpoint=endpoint, method=method,
                              parameter=parameter, parameter_location=parameter_location)
        except ValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail=exc.errors(include_input=False, include_url=False, include_context=False),
            ) from exc

    @app.get("/cases/{case_id}", response_model=CaseRecord)
    def get_case(case_id: str):
        try:
            record = store.get(case_id)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail="case not found") from exc
        if record.status != "ready":
            raise HTTPException(status_code=409, detail="case is draft; complete it before LLM use")
        return record

    return app
