"""Bounded dashboard configuration, local health and existing advisory workflows."""

from __future__ import annotations

from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .advisory_sync import sync_knowledge
from .applicability import SoftwareInventory
from .knowledge import query_knowledge
from .local_ocr import ocr_status
from .repository import SCHEMA_VERSION, ConflictError
from .sync_journal import list_sync_runs


class DashboardSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    ocrEnabled: bool = False
    ocrLanguage: Literal["ko", "en", "kor", "eng", "kor+eng"] = "ko"
    localLlmEnabled: bool = False
    providers: list[Literal["github", "nvd"]] = Field(
        default_factory=lambda: ["github", "nvd"], min_length=1, max_length=2
    )
    maxPages: int = Field(default=2, ge=1, le=20)
    maxRequests: int = Field(default=20, ge=1, le=64)
    timeoutSeconds: int = Field(default=180, ge=10, le=600)

    @model_validator(mode="after")
    def unique_providers(self):
        if len(self.providers) != len(set(self.providers)):
            raise ValueError("providers must be unique")
        return self


def settings(intake):
    with intake._connect() as connection:
        row = connection.execute("SELECT * FROM dashboard_settings WHERE id=1").fetchone()
    return {
        "settings": DashboardSettings.model_validate_json(row["snapshot"]).model_dump()
        if row
        else DashboardSettings().model_dump(),
        "revision": row["revision"] if row else 0,
        "updated_at": row["updated_at"] if row else None,
        "updated_by": row["updated_by"] if row else None,
        "scope": "dashboard-intake-and-manual-advisory-sync",
    }


def save_settings(intake, payload, actor):
    validated = DashboardSettings.model_validate(payload["settings"])
    expected = payload.get("expectedRevision")
    if type(expected) is not int or expected < 0:
        raise ValueError("expectedRevision is required")
    with intake._connect(write=True) as connection:
        row = connection.execute("SELECT revision FROM dashboard_settings WHERE id=1").fetchone()
        revision = row[0] if row else 0
        if expected != revision:
            raise ConflictError("settings changed; reload before saving")
        connection.execute(
            "INSERT INTO dashboard_settings VALUES (1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "revision=excluded.revision,snapshot=excluded.snapshot,"
            "updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            (revision + 1, validated.model_dump_json(), datetime.now(UTC).isoformat(), actor),
        )
    return settings(intake)


def sync_summary(row):
    receipt = row["receipt"]
    return {
        "jobId": row["job_id"],
        "targetId": row["target_id"],
        "status": row["status"],
        "startedAt": row["started_at"],
        "completedAt": receipt.get("completed_at"),
        "requestCount": receipt.get("request_count", 0),
        "complete": receipt.get("collection_complete", False),
        "errorCount": len(receipt.get("errors", [])),
    }


def operation_status(intake, store):
    from .report_llm_client import local_llm_status

    configured = settings(intake)
    with store._connect() as connection:
        actual_version = connection.execute("PRAGMA user_version").fetchone()[0]
        case_count = connection.execute("SELECT count(*) FROM cases").fetchone()[0]
        ready_count = connection.execute(
            "SELECT count(*) FROM cases WHERE status='ready' AND NOT EXISTS ("
            "SELECT 1 FROM dashboard_case_state a WHERE a.case_id=cases.case_id)"
        ).fetchone()[0]
        knowledge_count = connection.execute(
            "SELECT count(*) FROM report_knowledge_records k "
            "WHERE NOT EXISTS(SELECT 1 FROM cases c WHERE c.case_id=k.case_id)"
        ).fetchone()[0]
        incomplete = connection.execute(
            "SELECT count(*) FROM report_knowledge_records "
            "WHERE json_extract(snapshot,'$.reproduction_status')='incomplete'"
        ).fetchone()[0]
        archived = connection.execute("SELECT count(*) FROM dashboard_case_state").fetchone()[0]
        has_external = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='external_records'"
        ).fetchone()
        providers = {"github": 0, "nvd": 0}
        if has_external:
            providers.update(
                dict(
                    connection.execute(
                        "SELECT json_extract(record_json,'$.source'),count(*) "
                        "FROM external_records GROUP BY json_extract(record_json,'$.source')"
                    )
                )
            )
    with intake._connect() as connection:
        reports = connection.execute("SELECT count(*) FROM sources").fetchone()[0]
        drafts = connection.execute("SELECT count(*) FROM drafts").fetchone()[0]
    try:
        hwp_version = version("pyhwp")
    except PackageNotFoundError:
        hwp_version = None
    jobs = [sync_summary(row) for row in list_sync_runs(store.path)]
    return {
        "checkedAt": datetime.now(UTC).isoformat(),
        "database": {
            "available": actual_version == SCHEMA_VERSION,
            "schemaVersion": actual_version,
            "expectedSchemaVersion": SCHEMA_VERSION,
            "cases": case_count + knowledge_count,
            "reproductionReadyCases": ready_count,
            "incompleteReportRecords": incomplete,
            "archivedCases": archived,
            "reports": reports,
            "extractionVersions": drafts,
        },
        "hwp": {"available": hwp_version is not None, "reader": "pyhwp", "version": hwp_version},
        "ocr": ocr_status(configured["settings"]["ocrLanguage"]),
        "localLlm": local_llm_status(),
        "advisories": {"providers": providers, "recentJobs": jobs},
        **configured,
    }


def product_query(payload):
    # Manual dashboard input is declared software, never silently observed by the parser.
    target = payload.get("targetId")
    if not isinstance(target, str):
        raise ValueError("targetId is required")
    component = {
        "ecosystem": payload.get("ecosystem"),
        "package": payload.get("package"),
        "version": payload.get("version") or None,
        "cpe": payload.get("cpe") or None,
        "identification": "declared",
        "source_refs": ["manual:dashboard-product-entry"],
    }
    inventory = SoftwareInventory.model_validate(
        {
            "schema_version": "casper-software-inventory-1",
            "target_id": target,
            "observed_at": datetime.now(UTC).isoformat(),
            "components": [component],
        }
    )
    return {"target_id": target, "inventory": inventory.model_dump(mode="json"), "limit": 200}


def query_product(store, payload):
    return query_knowledge(store.path, product_query(payload))


def sync_product(intake, store, payload):
    configured = settings(intake)["settings"]
    return sync_knowledge(
        store.path,
        {
            "query": product_query(payload),
            "providers": configured["providers"],
            "max_pages": configured["maxPages"],
            "max_requests": configured["maxRequests"],
            "timeout_seconds": configured["timeoutSeconds"],
        },
        apply=True,
    )
