"""Reviewed report knowledge in the unified DB, independent of replay completeness.

These records preserve unknown values. Only the existing strict Case import path
can make a record eligible for location matching and later reproduction.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from .import_workflow import assigned_case_id
from .models import utc_timestamp


def setup_schema(connection):
    # An additive extension like the advisory/catalog tables; core Case schema is unchanged.
    connection.execute(
        "CREATE TABLE IF NOT EXISTS report_knowledge_records ("
        "case_id TEXT PRIMARY KEY, target_id TEXT NOT NULL, source_sha TEXT NOT NULL, "
        "draft_sha TEXT NOT NULL, validation_sha TEXT NOT NULL, "
        "revision INTEGER NOT NULL CHECK(revision>=1), snapshot TEXT NOT NULL "
        "CHECK(json_valid(snapshot)), updated_at TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS report_knowledge_versions ("
        "case_id TEXT NOT NULL REFERENCES report_knowledge_records(case_id), "
        "revision INTEGER NOT NULL, snapshot TEXT NOT NULL CHECK(json_valid(snapshot)), "
        "PRIMARY KEY(case_id,revision))"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS report_knowledge_by_target "
        "ON report_knowledge_records(target_id,updated_at)"
    )


def available(connection):
    return bool(connection.execute(
        "SELECT 1 FROM sqlite_master WHERE name='report_knowledge_records'"
    ).fetchone())


def get_record(connection, case_id):
    if not available(connection):
        return None
    row = connection.execute(
        "SELECT snapshot FROM report_knowledge_records WHERE case_id=?", (case_id,)
    ).fetchone()
    return json.loads(row[0]) if row else None


def target_records(connection, target_id, limit=100):
    if not available(connection):
        return []
    archived = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE name='dashboard_case_state'"
    ).fetchone()
    where = (
        ' AND NOT EXISTS(SELECT 1 FROM dashboard_case_state a WHERE a.case_id=k.case_id)'
        if archived else ''
    )
    rows = connection.execute(
        'SELECT snapshot FROM report_knowledge_records k WHERE target_id=?' + where +
        ' ORDER BY updated_at DESC,case_id LIMIT ?', (target_id, limit + 1),
    ).fetchall()
    return [json.loads(row[0]) for row in rows]


def registration_records(report, package, target_id):
    """Build data records only for explicit human acceptance, never for pending items."""
    if not package.review.reviewer.strip() or package.review.reviewed_at is None:
        return []
    if any('실제 검토 시각이 필요합니다.' in reason
           for item in package.blocked for reason in item['reasons']):
        return []
    reviewed_at = utc_timestamp(package.review.reviewed_at)
    if datetime.fromisoformat(reviewed_at) > datetime.now(UTC):
        return []
    reviews = {item.draft_id: item for item in package.review.items}
    complete = {case.case_id for case in package.cases}
    blocked = {item['draft_id']: item for item in package.blocked}
    records = []
    for finding in report.findings:
        review = reviews.get(finding.draft_id)
        if not review or review.decision != 'accept' or not review.reason.strip():
            continue
        fields = finding.candidate.model_dump(mode='json')
        fields.update({key: item.value for key, item in review.resolutions.items()})
        if review.payload_variant_index is not None:
            fields['payload'] = finding.payload_variants[review.payload_variant_index].value
        case_id = assigned_case_id(report, finding.source_ref)
        fields.update(case_id=case_id, target_id=target_id,
                      status='ready' if case_id in complete else 'draft')
        title = fields.get('title')
        kind = fields.get('vulnerability_type')
        display_title = title if isinstance(title, str) and title.strip() else (
            f"{kind if isinstance(kind, str) and kind else '취약점 자료'} · 제목 미확인"
        )
        problem = blocked.get(finding.draft_id, {})
        records.append({
            **fields, 'display_title': display_title, 'record_kind': 'report_knowledge',
            'registration_status': 'registered', 'review_status': 'reviewed',
            'reproduction_status': 'ready' if case_id in complete else 'incomplete',
            'automatic_execution_allowed': False,
            'missing_fields': problem.get('remaining_fields', []),
            'readiness_issues': problem.get('reasons', []),
            'source_sha256': report.source['sha256'], 'draft_sha256': package.draft_sha256,
            'validation_sha256': package.package_sha256, 'source_ref': finding.source_ref,
            'source_filename': report.source['filename'], 'draft_id': finding.draft_id,
            'reviewer': package.review.reviewer, 'reviewed_at': reviewed_at,
            'review_reason': review.reason,
            'acknowledged_issue_codes': review.acknowledged_issue_codes,
            'field_evidence': {key: [item.model_dump(mode='json') for item in items]
                               for key, items in finding.field_evidence.items()},
            'payload_variants': [item.model_dump(mode='json')
                                 for item in finding.payload_variants],
            'resolutions': {key: item.model_dump(mode='json')
                            for key, item in review.resolutions.items()},
        })
    return records


def write_records(connection, records):
    from .repository import ConflictError

    setup_schema(connection)
    result = {'created': [], 'unchanged': [], 'updated': []}
    now = datetime.now(UTC).isoformat()
    for item in records:
        previous = get_record(connection, item['case_id'])
        if previous and (previous['target_id'] != item['target_id'] or
                         previous['source_sha256'] != item['source_sha256']):
            raise ConflictError('report knowledge ownership differs from stored record')
        if previous and previous['validation_sha256'] == item['validation_sha256']:
            result['unchanged'].append(previous)
            continue
        saved = {**item, 'revision': previous['revision'] + 1 if previous else 1,
                 'created_at': previous['created_at'] if previous else now, 'updated_at': now}
        encoded = json.dumps(saved, ensure_ascii=False)
        connection.execute(
            "INSERT INTO report_knowledge_records VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(case_id) DO UPDATE SET draft_sha=excluded.draft_sha, "
            "validation_sha=excluded.validation_sha,revision=excluded.revision, "
            "snapshot=excluded.snapshot,updated_at=excluded.updated_at",
            (saved['case_id'], saved['target_id'], saved['source_sha256'],
             saved['draft_sha256'], saved['validation_sha256'], saved['revision'], encoded, now),
        )
        connection.execute("INSERT INTO report_knowledge_versions VALUES (?,?,?)",
                           (saved['case_id'], saved['revision'], encoded))
        result['updated' if previous else 'created'].append(saved)
    return result
