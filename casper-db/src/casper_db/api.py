"""Optional read-only adapter for a separate LLM coordinator process."""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

from .models import CaseRecord
from .repository import CaseStore, NotFoundError


def create_app(database_path: str | Path) -> FastAPI:
    store = CaseStore(database_path)
    app = FastAPI(
        title="CASPER Case DB",
        version="0.2.0",
        description="Read-only case lookup. Returned cases are reference data, not findings.",
    )

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
