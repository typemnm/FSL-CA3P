"""Versioned attack guidance and future template contracts owned by the knowledge DB.

Catalog payloads and historical verification notes are data. This module never
executes them or promotes a historical observation into a current finding.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from .import_workflow import WorkflowModel, digest
from .models import Identifier, Text
from .repository import SCHEMA_VERSION, CaseStore, ConflictError, _run_schema, initialize_database

CATALOG_SCHEMA = "casper-attack-catalog-1"
RETIRED_APPLICATIONS = frozenset({"vul-web-1"})
ATTACK_TABLES = {
    "attack_catalog_metadata", "attack_catalog_sources", "attack_patterns", "attack_payloads",
    "attack_verification_rules", "attack_templates", "attack_template_rules",
}


class AttackTarget(WorkflowModel):
    endpoint: Text
    parameter: Text
    application: Text | None = None


class AttackInfoQuery(WorkflowModel):
    vulnType: Text
    target: AttackTarget


class AttackTemplate(WorkflowModel):
    schema_version: Literal["casper-attack-template-1"] = "casper-attack-template-1"
    template_id: Identifier
    version: Text
    pattern_id: Identifier
    pattern_revision: int = Field(ge=1, strict=True)
    executor_id: Identifier
    executor_contract_version: Text
    input_schema: dict[str, Any]
    required_capabilities: list[Text] = Field(min_length=1, max_length=30)
    verification_rule_ids: list[Identifier] = Field(min_length=1, max_length=30)
    origin: Literal["imported", "human_authored", "ai_generated"]
    source_refs: list[Text] = Field(min_length=1, max_length=30)
    parent_template_id: Identifier | None = None
    parent_template_version: Text | None = None
    generation_metadata: dict[str, Any] = Field(default_factory=dict)
    registration_state: Literal["draft"] = "draft"
    execution_enabled: Literal[False] = False

    @model_validator(mode="after")
    def validate_lineage(self):
        if (self.parent_template_id is None) != (self.parent_template_version is None):
            raise ValueError("a parent template requires both ID and version")
        if self.origin == "ai_generated" and not self.generation_metadata:
            raise ValueError("AI-generated templates require generation metadata")
        if self.input_schema.get("type") != "object":
            raise ValueError("the executor input schema must describe an object")
        if len(set(self.verification_rule_ids)) != len(self.verification_rule_ids):
            raise ValueError("duplicate verification rule references")
        return self


def _ensure_schema(connection):
    connection.execute("SELECT case_id, revision FROM cases LIMIT 0")
    connection.execute("SELECT case_id, revision, snapshot FROM case_versions LIMIT 0")
    connection.execute("SELECT check_id, case_id, case_revision FROM checks LIMIT 0")
    _run_schema(connection, files("casper_db").joinpath("attack_catalog.sql").read_text("utf-8"))
    marker = connection.execute(
        "SELECT value FROM attack_catalog_metadata WHERE key='schema'"
    ).fetchone()
    if marker is not None and marker[0] != CATALOG_SCHEMA:
        raise ValueError("unsupported attack catalog schema")
    connection.execute(
        "INSERT OR IGNORE INTO attack_catalog_metadata VALUES ('schema', ?)", (CATALOG_SCHEMA,),
    )


def _configured(connection) -> bool:
    if not connection.execute(
        "SELECT 1 FROM sqlite_master WHERE name='attack_catalog_metadata' AND type='table'"
    ).fetchone():
        return False
    marker = connection.execute(
        "SELECT value FROM attack_catalog_metadata WHERE key='schema'"
    ).fetchone()
    if marker is None or marker[0] != CATALOG_SCHEMA:
        raise ValueError("unsupported attack catalog schema")
    return True


def _blocks(catalog: dict) -> list[dict]:
    if not isinstance(catalog, dict) or catalog.get("schemaVersion") not in {
        "0.1-draft", "0.2-draft",
    }:
        raise ValueError("unsupported draft schema for attack catalog")
    blocks = catalog.get("responses") if catalog["schemaVersion"] == "0.2-draft" else [
        catalog.get("response"),
    ]
    if not isinstance(blocks, list) or not blocks:
        raise ValueError("unsupported draft schema for attack catalog")
    identities = set()
    for block in blocks:
        if not isinstance(block, dict) or not isinstance(block.get("target"), dict):
            raise ValueError("unsupported draft schema for attack catalog")
        target, payloads = block["target"], block.get("payloads")
        identity = (block.get("vulnType"), target.get("application"), target.get("endpoint"))
        if any(not isinstance(value, str) or not value.strip() for value in identity):
            raise ValueError("attack guidance needs a type, application and endpoint")
        if identity in identities:
            raise ValueError("duplicate attack guidance identity")
        identities.add(identity)
        if not isinstance(payloads, list) or not payloads:
            raise ValueError("attack guidance needs payload definitions")
        ids = set()
        for payload in payloads:
            if (not isinstance(payload, dict) or not isinstance(payload.get("payloadId"), str)
                    or not payload["payloadId"] or not isinstance(payload.get("value"), str)
                    or not isinstance(payload.get("injectionPoint"), dict)
                    or not isinstance(payload["injectionPoint"].get("parameter"), str)):
                raise ValueError("unsupported draft schema for attack payload")
            if payload["payloadId"] in ids:
                raise ValueError("duplicate payload ID in attack guidance")
            ids.add(payload["payloadId"])
            if "successCheck" in payload and not isinstance(payload["successCheck"], dict):
                raise ValueError("verification criteria must be structured data")
    return blocks


def import_attack_catalog(database: Path, catalog: dict, *, source_ref: str) -> dict:
    blocks = _blocks(catalog)
    if not isinstance(source_ref, str) or not source_ref.strip():
        raise ValueError("a catalog source reference is required")
    source_sha = digest(catalog)
    result = {"created": 0, "unchanged": 0, "patterns": []}
    with CaseStore(database)._connect(write=True) as connection:
        _ensure_schema(connection)
        now = datetime.now(UTC).isoformat()
        connection.execute(
            "INSERT OR IGNORE INTO attack_catalog_sources VALUES (?, ?, ?, ?, ?)",
            (source_ref, source_sha, catalog["schemaVersion"], json.dumps(catalog), now),
        )
        for block in blocks:
            identity = {
                "vulnType": block["vulnType"], "application": block["target"]["application"],
                "endpoint": block["target"]["endpoint"],
            }
            pattern_id = "PAT-" + digest(identity)[:40]
            content_sha = digest(block)
            existing = connection.execute(
                "SELECT revision FROM attack_patterns WHERE pattern_id=? AND content_sha256=?",
                (pattern_id, content_sha),
            ).fetchone()
            if existing:
                result["unchanged"] += 1
                result["patterns"].append({"pattern_id": pattern_id, "revision": existing[0]})
                continue
            revision = connection.execute(
                "SELECT COALESCE(MAX(revision), 0) + 1 FROM attack_patterns WHERE pattern_id=?",
                (pattern_id,),
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO attack_patterns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (pattern_id, revision, content_sha, block["vulnType"],
                 block["target"]["application"], block["target"]["endpoint"],
                 block.get("cwe"), source_ref, source_sha,
                 json.dumps(block, ensure_ascii=False), now),
            )
            for payload in block["payloads"]:
                payload_id = payload["payloadId"]
                connection.execute("INSERT INTO attack_payloads VALUES (?, ?, ?, ?)", (
                    pattern_id, revision, payload_id, json.dumps(payload, ensure_ascii=False),
                ))
                if payload.get("successCheck"):
                    rule_id = "RULE-" + digest([pattern_id, revision, payload_id])[:40]
                    connection.execute(
                        "INSERT INTO attack_verification_rules VALUES (?, ?, ?, ?, ?)",
                        (rule_id, pattern_id, revision, payload_id,
                         json.dumps(payload["successCheck"], ensure_ascii=False)),
                    )
            result["created"] += 1
            result["patterns"].append({"pattern_id": pattern_id, "revision": revision})
    return {"schema_version": CATALOG_SCHEMA, "source_sha256": source_sha, **result}


def bundled_catalogs() -> list[tuple[str, dict]]:
    # Keep historical snapshots on disk, but bootstrap only guidance for active targets.
    catalog = json.loads(files("casper_db").joinpath(
        "catalog_seed", "expanded-v2.json").read_text("utf-8"))
    catalog["responses"] = [block for block in _blocks(catalog)
                            if block["target"]["application"] not in RETIRED_APPLICATIONS]
    return [("bundled:expanded-v2.json#active-targets", catalog)]


def import_bundled_catalogs(database: Path) -> list[dict]:
    return [import_attack_catalog(database, catalog, source_ref=source)
            for source, catalog in bundled_catalogs()]


def prepare_catalog_database(
    database: Path, *, catalog: dict | None = None, source_ref: str | None = None,
) -> list[dict] | dict:
    """Explicit runtime bootstrap; existing Case migrations remain operator-controlled."""
    if catalog is not None:
        _blocks(catalog)
        if source_ref is None:
            raise ValueError("a custom catalog requires a source reference")
    if database.exists():
        with closing(sqlite3.connect(
            database.resolve(strict=True).as_uri() + "?mode=ro", uri=True,
        )) as connection, connection:
            connection.execute("BEGIN")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            empty = not connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table'"
            ).fetchone()
        if version == 0 and empty:
            initialize_database(database)
        elif version != SCHEMA_VERSION:
            raise ValueError("explicit Case migration is required before catalog import")
    else:
        initialize_database(database)
    if catalog is not None:
        return import_attack_catalog(database, catalog, source_ref=source_ref)
    return import_bundled_catalogs(database)


def list_attack_patterns(database: Path) -> dict:
    with CaseStore(database)._connect() as connection:
        if not _configured(connection):
            return {"schemaVersion": CATALOG_SCHEMA, "status": "not_configured", "patterns": []}
        rows = connection.execute(
            "SELECT * FROM attack_patterns p WHERE revision=(SELECT MAX(revision) "
            "FROM attack_patterns WHERE pattern_id=p.pattern_id) ORDER BY pattern_id"
        ).fetchall()
        patterns = [{"pattern_id": row["pattern_id"], "revision": row["revision"],
                     "content_sha256": row["content_sha256"], "definition_kind": "attack_guidance",
                     "source_ref": row["source_ref"], "source_sha256": row["source_sha256"],
                     "definition": json.loads(row["snapshot"])} for row in rows
                    if row["application"] not in RETIRED_APPLICATIONS]
    return {"schemaVersion": CATALOG_SCHEMA, "status": "ok", "patterns": patterns,
            "provenance": {"source": "casper-db.attack_catalog", "status": "draft_advisory",
                           "currentRunVerified": False, "sha256": digest(patterns)}}


def lookup_attack_info(database: Path, value: dict | AttackInfoQuery) -> dict | None:
    query = AttackInfoQuery.model_validate(value)
    matches = []
    for item in list_attack_patterns(database)["patterns"]:
        definition = item["definition"]
        if (definition["vulnType"] == query.vulnType
                and definition["target"]["endpoint"] == query.target.endpoint
                and (query.target.application is None
                     or definition["target"]["application"] == query.target.application)):
            matches.append(item)
    if len(matches) > 1:
        raise ValueError("ambiguous attack guidance; specify target.application")
    if not matches:
        return None
    item = matches[0]
    payloads = [payload for payload in item["definition"]["payloads"]
                if payload["injectionPoint"]["parameter"] == query.target.parameter]
    if not payloads:
        return None
    with CaseStore(database)._connect() as connection:
        rules = connection.execute(
            "SELECT rule_id, payload_id FROM attack_verification_rules "
            "WHERE pattern_id=? AND pattern_revision=? ORDER BY payload_id",
            (item["pattern_id"], item["revision"]),
        ).fetchall()
        templates = [json.loads(row[0]) for row in connection.execute(
            "SELECT snapshot FROM attack_templates WHERE pattern_id=? AND pattern_revision=? "
            "ORDER BY template_id, version", (item["pattern_id"], item["revision"]),
        )]
    payload_ids = {item["payloadId"] for item in payloads}
    rules = [dict(row) for row in rules if row["payload_id"] in payload_ids]
    rule_ids = {item["rule_id"] for item in rules}
    templates = [item for item in templates if set(item["verification_rule_ids"]) <= rule_ids]
    return {**item["definition"], "payloads": payloads,
            "patternId": item["pattern_id"], "patternRevision": item["revision"],
            "verificationRuleRefs": rules, "templates": templates,
            "executionTemplateState": "draft_registered" if templates else "not_registered",
            "provenance": {"source": "casper-db.attack_catalog", "status": "draft_advisory",
                           "currentRunVerified": False, "content_sha256": item["content_sha256"],
                           "source_ref": item["source_ref"], "source_sha256": item["source_sha256"],
                           "verificationNote": "Historical notes are not current findings."}}


def register_attack_template(database: Path, value: dict | AttackTemplate) -> dict:
    template = AttackTemplate.model_validate(value)
    content_sha = digest(template)
    with CaseStore(database)._connect(write=True) as connection:
        if not _configured(connection):
            raise ValueError("import attack guidance before registering templates")
        if not connection.execute(
            "SELECT 1 FROM attack_patterns WHERE pattern_id=? AND revision=?",
            (template.pattern_id, template.pattern_revision),
        ).fetchone():
            raise ValueError("template references an unknown pattern revision")
        for rule in template.verification_rule_ids:
            if not connection.execute(
                "SELECT 1 FROM attack_verification_rules WHERE rule_id=? "
                "AND pattern_id=? AND pattern_revision=?",
                (rule, template.pattern_id, template.pattern_revision),
            ).fetchone():
                raise ValueError("verification rule does not belong to this pattern revision")
        if template.parent_template_id is not None and not connection.execute(
            "SELECT 1 FROM attack_templates WHERE template_id=? AND version=?",
            (template.parent_template_id, template.parent_template_version),
        ).fetchone():
            raise ValueError("parent template is not registered")
        existing = connection.execute(
            "SELECT content_sha256 FROM attack_templates WHERE template_id=? AND version=?",
            (template.template_id, template.version),
        ).fetchone()
        if existing:
            if existing[0] != content_sha:
                raise ConflictError("template versions are immutable; register a new version")
            return {"created": False, "template_id": template.template_id,
                    "version": template.version, "execution_enabled": False}
        connection.execute("INSERT INTO attack_templates VALUES (?, ?, ?, ?, ?, ?, ?)", (
            template.template_id, template.version, template.pattern_id, template.pattern_revision,
            content_sha, template.model_dump_json(), datetime.now(UTC).isoformat(),
        ))
        connection.executemany("INSERT INTO attack_template_rules VALUES (?, ?, ?)", [
            (template.template_id, template.version, rule)
            for rule in template.verification_rule_ids
        ])
    return {"created": True, "template_id": template.template_id, "version": template.version,
            "execution_enabled": False}


def get_attack_template(database: Path, template_id: str, version: str) -> dict | None:
    with CaseStore(database)._connect() as connection:
        if not _configured(connection):
            return None
        row = connection.execute(
            "SELECT snapshot FROM attack_templates WHERE template_id=? AND version=?",
            (template_id, version),
        ).fetchone()
        return json.loads(row[0]) if row else None
