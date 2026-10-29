"""Dashboard projections; report lists never load original document BLOBs."""

from __future__ import annotations

import json

from .import_workflow import digest


def pagination(payload):
    limit, offset = payload.get("limit", 50), payload.get("offset", 0)
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    if type(offset) is not int or not 0 <= offset <= 100000:
        raise ValueError("offset must be between 0 and 100000")
    return limit, offset


def list_intakes(intake, store, payload):
    limit, offset = pagination(payload)
    query = payload.get("q", "")
    state = payload.get("status", "all")
    order = payload.get("sort", "newest")
    if not isinstance(query, str) or len(query) > 200:
        raise ValueError("invalid report query")
    if state not in {"all", "needs_review", "ready", "partial", "published", "excluded"}:
        raise ValueError("invalid report status")
    if order not in {"newest", "oldest", "filename"}:
        raise ValueError("invalid report order")
    with store._connect() as connection:
        stored = {row[0] for row in connection.execute("SELECT case_id FROM cases")}
        knowledge = {row['case_id']: row['validation_sha'] for row in connection.execute(
            'SELECT case_id,validation_sha FROM report_knowledge_records'
        )}
    with intake._connect() as connection:
        # Project only finding identities and validation counts, not document text/images/raw.
        rows = connection.execute(
            "SELECT d.draft_sha, s.source_sha, s.filename, s.target_id, length(s.raw) AS size, "
            "(SELECT count(*) FROM drafts x WHERE x.source_sha=d.source_sha) AS versions, "
            "(SELECT min(recorded_at) FROM dashboard_intake_audit a "
            " JOIN drafts ad ON ad.draft_sha=a.draft_sha "
            " WHERE ad.source_sha=s.source_sha AND a.action='stage') AS received_at, "
            "(SELECT json_group_array(json_object("
            "'source_ref',json_extract(f.value,'$.source_ref'),"
            "'draft_id',json_extract(f.value,'$.draft_id'))) "
            " FROM json_each(d.snapshot,'$.findings') f) AS identities, "
            "json_extract(v.snapshot,'$.cases') AS ready_cases, "
            "v.validation_sha AS validation_sha, "
            "json_extract(v.snapshot,'$.review.items') AS reviews, "
            "json_array_length(v.snapshot,'$.blocked') AS blocked, "
            "json_array_length(v.snapshot,'$.excluded') AS excluded "
            "FROM drafts d JOIN sources s USING(source_sha) "
            "JOIN active_validations a USING(draft_sha) "
            "JOIN validations v USING(validation_sha) "
            "WHERE d.rowid=(SELECT max(x.rowid) FROM drafts x WHERE x.source_sha=d.source_sha) "
            "ORDER BY d.rowid DESC"
        ).fetchall()
    reports = []
    for row in rows:
        if query.casefold() not in (row["filename"] + " " + row["target_id"]).casefold():
            continue
        identities = json.loads(row["identities"])
        ids = {
            "CASE-" + digest({"report": row["source_sha"], "finding": f["source_ref"]})[:24]
            for f in identities
        }
        persisted = stored | set(knowledge)
        published = len(ids & persisted)
        review_items = {item['draft_id']: item for item in json.loads(row['reviews'] or '[]')}
        accepted = {
            'CASE-' + digest({'report': row['source_sha'], 'finding': f['source_ref']})[:24]
            for f in identities if review_items.get(f['draft_id'], {}).get('decision') == 'accept'
            and review_items[f['draft_id']].get('reason', '').strip()
        }
        complete = {c['case_id'] for c in json.loads(row['ready_cases'] or '[]')}
        current = {case_id for case_id in ids if knowledge.get(case_id) == row['validation_sha']}
        current |= complete & stored
        ready = len(accepted - current)
        excluded = row["excluded"] or 0
        # A case published from an older extraction must not hide this version's review needs.
        pending = max(0, len(identities) - len(accepted) - excluded)
        status = (
            "partial"
            if published and (pending or ready)
            else "published"
            if published
            else "needs_review"
            if pending or not identities
            else "ready"
            if ready
            else "excluded"
        )
        if state != "all" and state != status:
            continue
        reports.append(
            {
                "draft_sha256": row["draft_sha"],
                "source_sha256": row["source_sha"],
                "source_filename": row["filename"],
                "target_id": row["target_id"],
                "source_bytes": row["size"],
                "received_at": row["received_at"],
                "extraction_versions": row["versions"],
                "status": status,
                "finding_count": len(identities),
                "counts": {
                    "published": published,
                    "ready": ready,
                    "needs_review": pending,
                    "excluded": excluded,
                    "needs_enrichment": len(accepted - complete),
                    "reproduction_ready": len(complete),
                },
            }
        )
    if order == "oldest":
        reports.reverse()
    elif order == "filename":
        reports.sort(key=lambda item: item["source_filename"].casefold())
    return {
        "intakes": reports[offset : offset + limit],
        "total": len(reports),
        "limit": limit,
        "offset": offset,
    }


def list_advisories(store, payload):
    limit, offset = pagination(payload)
    query, provider = payload.get("q", ""), payload.get("source", "all")
    if not isinstance(query, str) or len(query) > 200 or provider not in {"all", "nvd", "github"}:
        raise ValueError("invalid advisory filters")
    with store._connect() as connection:
        if not connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='external_records'"
        ).fetchone():
            return {"records": [], "total": 0, "limit": limit, "offset": offset}
        where, params = [], []
        if provider != "all":
            where.append("json_extract(record_json,'$.source')=?")
            params.append(provider)
        if query:
            where.append("instr(lower(record_json),lower(?))>0")
            params.append(query)
        clause = " WHERE " + " AND ".join(where) if where else ""
        total = connection.execute(
            "SELECT count(*) FROM external_records" + clause, params
        ).fetchone()[0]
        rows = connection.execute(
            "SELECT json_remove(record_json,'$.raw') FROM external_records"
            + clause
            + " ORDER BY modified_at DESC, record_id LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    return {
        "records": [json.loads(row[0]) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }
