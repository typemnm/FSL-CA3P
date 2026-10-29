"""Synthetic stored-XSS run shaped like agent/src/orchestrator.js output. Nothing here is real."""

from __future__ import annotations

ORIGIN = "http://127.0.0.1:43123"
PAYLOAD = "<img src=x onerror=\"__ca3pXssProbe('m-1a2b')\"> & ]]> | `tick`"
CASE_ID = "LAB-STORED-XSS"
EXPLANATION = "전월 위치와 일치하므로 재점검 후보. 현재 취약하다는 판정은 아님"


def envelope(receiver: str, payload: dict, *, sender: str = "agent") -> dict:
    return {"sender": sender, "receiver": receiver, "payload": payload}


def stored_xss_events() -> list[dict]:
    parser_report = {
        "schemaVersion": "3.4",
        "pages": [
            {
                "url": f"{ORIGIN}/",
                "areas": [
                    {
                        "forms": [
                            {
                                "selector": "#post-form",
                                "fields": [{"name": "title"}, {"name": "content"}],
                            }
                        ]
                    }
                ],
                "behaviors": [
                    {
                        "api": [
                            {
                                "method": "POST",
                                "url": f"{ORIGIN}/api/posts",
                                "bodyKeys": ["title", "content"],
                            },
                            {
                                "method": "POST",
                                "url": f"{ORIGIN}/api/session",
                                "bodyKeys": ["userId"],
                            },
                        ]
                    }
                ],
            }
        ],
    }
    return [
        {
            "stage": "setup.attacker_session",
            "iteration": 0,
            "request": envelope(
                "attack-module",
                {
                    "operation": "execute_curl",
                    "session": "attacker",
                    "curl": {"method": "GET", "url": f"{ORIGIN}/api/session"},
                },
            ),
            "response": envelope(
                "agent",
                {"response": {"status": 200, "bodyJson": {"user": {"id": "alice"}}}},
                sender="attack-module",
            ),
        },
        {
            "stage": "loop.observe",
            "iteration": 1,
            "request": envelope("xss-parser", {"operation": "parse_site", "origin": ORIGIN}),
            "response": envelope(
                "agent",
                {"report": parser_report, "evidenceId": "parser-evidence-1"},
                sender="xss-parser",
            ),
        },
        {
            "stage": "loop.history",
            "iteration": 1,
            "request": envelope("casper-db", {"operation": "assess_xss_history"}),
            "response": envelope(
                "agent",
                {
                    "operation": "assess_xss_history",
                    "readyCaseCount": 1,
                    "evidenceId": "casper-evidence-1",
                    "assessments": [
                        {
                            "observation": {
                                "target_id": "LAB-DEMO",
                                "endpoint": "/api/posts",
                                "method": "POST",
                                "parameter": "content",
                                "parameter_location": "body",
                            },
                            "decision": "retest_candidate",
                            "explanation": EXPLANATION,
                            "matches": [
                                {
                                    "case_id": CASE_ID,
                                    "case_revision": 1,
                                    "decision": "retest_candidate",
                                },
                                {
                                    "case_id": "CASE-MISSING",
                                    "case_revision": 3,
                                    "decision": "manual_review",
                                },
                            ],
                        }
                    ],
                },
                sender="casper-db",
            ),
        },
        {
            "stage": "loop.act",
            "iteration": 1,
            "request": envelope(
                "attack-module",
                {
                    "operation": "execute_curl",
                    "session": "attacker",
                    "curl": {
                        "method": "POST",
                        "url": f"{ORIGIN}/api/posts",
                        "body": {"title": "agent-xss-canary", "content": PAYLOAD},
                    },
                },
            ),
            "response": envelope(
                "agent",
                {
                    "success": True,
                    "response": {
                        "status": 201,
                        "ok": True,
                        "bodyJson": {"post": {"id": 3, "authorId": "alice", "content": PAYLOAD}},
                    },
                },
                sender="attack-module",
            ),
        },
    ]


def stored_xss_report(run_id: str) -> dict:
    return {
        "schemaVersion": "1.0",
        "runId": run_id,
        "status": "completed",
        "testProfile": "stored_xss_canary",
        "target": {
            "origin": ORIGIN,
            "mode": "isolated_local_lab",
            "application": "owned-local-board",
        },
        "iterations": 1,
        "finding": {
            "findingId": f"finding-{run_id}-stored-xss-canary",
            "title": "저장형 XSS 브라우저 실행",
            "cwe": "CWE-79",
            "severity": "medium",
            "status": "confirmed",
            "confidence": "high",
            "resourceId": 3,
            "marker": "m-1a2b",
            "checks": {"executed": True},
        },
        "guardrail": {"decisions": [{"decision": "ALLOW", "ruleId": "XSS-CANARY"}]},
        "startedAt": "2026-10-20T00:00:00.000Z",
        "completedAt": "2026-10-20T00:00:05.000Z",
    }
