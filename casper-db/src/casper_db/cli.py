from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from pydantic import ValidationError

from .matching import ParserObservation, assess_observation
from .models import Case, Check
from .parser import parse_html_inputs
from .repository import SCHEMA_VERSION, CaseStore, ConflictError, NotFoundError, initialize_database


def output(value, *, stream=None):
    stream = stream or sys.stdout
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")
    print(json.dumps(value, ensure_ascii=False, indent=2), file=stream)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CASPER single-case database")
    parser.add_argument("--db", type=Path, default=Path("data/cases.sqlite3"))
    parser.add_argument("--evidence-root", type=Path, help="Approved local evidence directory")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create a new database, or verify an existing one")
    commands.add_parser("schema", help="Print the JSON input schema")
    commands.add_parser("check-schema", help="Print the later-check JSON input schema")
    commands.add_parser("parser-schema", help="Print the parser observation JSON schema")
    parse_html = commands.add_parser(
        "parse-html", help="Extract input points from a saved HTML page; makes no network requests"
    )
    parse_html.add_argument("--target", required=True)
    parse_html.add_argument("--page-url", required=True)
    parse_html.add_argument("--html", type=Path, required=True)
    parse_html.add_argument("--output", type=Path)
    for name in ("add", "update"):
        command = commands.add_parser(name, help=f"{name.title()} one case from a UTF-8 JSON file")
        command.add_argument("file", type=Path)
        if name == "update":
            command.add_argument("--expected-revision", type=int)
    get = commands.add_parser("get", help="Inspect one case, including drafts")
    get.add_argument("case_id")
    get.add_argument("--revision", type=int)
    commands.add_parser("history", help="List preserved report versions").add_argument("case_id")
    by_target = commands.add_parser("list", help="List prior ready reports for one site")
    by_target.add_argument("--target", required=True)
    find = commands.add_parser("find", help="Find cases by exact target, path and method")
    find.add_argument("--target", required=True)
    find.add_argument("--endpoint", required=True)
    find.add_argument("--method", required=True)
    find.add_argument("--parameter")
    find.add_argument("--parameter-location")
    find.add_argument("--include-drafts", action="store_true")
    commands.add_parser("match", help="Assess parser observations from a JSON array").add_argument(
        "file", type=Path
    )
    check_add = commands.add_parser("check-add", help="Store a later observation from JSON")
    check_add.add_argument("file", type=Path)
    commands.add_parser("check-list", help="Show observations for one prior case").add_argument(
        "case_id"
    )
    review = commands.add_parser("check-review", help="Approve a real check after verifying files")
    review.add_argument("check_id")
    review.add_argument("--reviewer", required=True)
    review.add_argument("--note", required=True)
    commands.add_parser(
        "check-evidence", help="Compare reviewed evidence files with their saved hashes"
    ).add_argument("check_id")
    serve = commands.add_parser("serve", help="Run the optional read-only API on localhost")
    serve.add_argument("--port", type=int, default=8001)
    args = parser.parse_args(argv)
    try:
        if args.command == "schema":
            output(Case.model_json_schema())
        elif args.command == "check-schema":
            output(Check.model_json_schema())
        elif args.command == "parser-schema":
            output(ParserObservation.model_json_schema())
        elif args.command == "parse-html":
            if args.output and args.output.resolve() == args.html.resolve():
                raise ValueError("output must not overwrite the HTML input")
            if args.html.stat().st_size > 4_000_000:
                raise ValueError("HTML snapshot exceeds the 4 MB file limit")
            parsed = parse_html_inputs(
                args.html.read_text(encoding="utf-8-sig"),
                page_url=args.page_url,
                target_id=args.target,
            )
            rows = [item.model_dump() for item in parsed.observations]
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(
                    json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                )
                output({"output": str(args.output), "observations": len(rows)})
            else:
                output(rows)
            if parsed.warnings:
                output({"warnings": parsed.warnings}, stream=sys.stderr)
        elif args.command == "init":
            output(
                {"database": str(initialize_database(args.db)), "schema_version": SCHEMA_VERSION}
            )
        else:
            store = CaseStore(args.db, evidence_root=args.evidence_root)
            if args.command in ("add", "update"):
                raw = json.loads(args.file.read_text(encoding="utf-8-sig"))
                record = (
                    store.update(raw, expected_revision=args.expected_revision)
                    if args.command == "update" else store.add(raw)
                )
                output(record.model_dump())
            elif args.command == "get":
                record = (
                    store.get_version(args.case_id, args.revision)
                    if args.revision is not None else store.get(args.case_id)
                )
                output(record.model_dump())
            elif args.command == "history":
                output([item.model_dump() for item in store.list_versions(args.case_id)])
            elif args.command == "list":
                output([record.model_dump() for record in store.list_for_target(args.target)])
            elif args.command == "find":
                records = store.find(
                    target_id=args.target,
                    endpoint=args.endpoint,
                    method=args.method,
                    parameter=args.parameter,
                    parameter_location=args.parameter_location,
                    include_drafts=args.include_drafts,
                )
                output([record.model_dump() for record in records])
            elif args.command == "match":
                raw = json.loads(args.file.read_text(encoding="utf-8-sig"))
                if not isinstance(raw, list):
                    raise ValueError("parser observations must be a JSON array")
                output([assess_observation(store, item).model_dump() for item in raw])
            elif args.command == "check-add":
                raw = json.loads(args.file.read_text(encoding="utf-8-sig"))
                output(store.add_check(raw).model_dump())
            elif args.command == "check-list":
                output([record.model_dump() for record in store.list_checks(args.case_id)])
            elif args.command == "check-review":
                output(store.review_check(
                    args.check_id, reviewer=args.reviewer, note=args.note
                ).model_dump())
            elif args.command == "check-evidence":
                if not store.verify_check_evidence(args.check_id):
                    raise ValueError("evidence bytes changed since review")
                output({"check_id": args.check_id, "verified": True})
            elif args.command == "serve":
                if not 1 <= args.port <= 65535:
                    raise ValueError("port must be between 1 and 65535")
                # Validate the database without creating it or changing its schema.
                with store._connect() as connection:
                    connection.execute("SELECT case_id FROM cases LIMIT 0")
                try:
                    import uvicorn

                    from .api import create_app
                except ImportError as exc:
                    raise ValueError(
                        'API dependencies missing; install with pip install -e ".[api]"'
                    ) from exc
                uvicorn.run(create_app(args.db), host="127.0.0.1", port=args.port)
    except ValidationError as exc:
        output(
            {
                "error": "validation_error",
                "details": exc.errors(
                    include_input=False, include_url=False, include_context=False
                ),
            },
            stream=sys.stderr,
        )
        return 2
    except (OSError, ValueError, NotFoundError, sqlite3.Error) as exc:
        code = "conflict" if isinstance(exc, ConflictError) else "error"
        if isinstance(exc, NotFoundError):
            code = "not_found"
        output({"error": code, "message": str(exc)}, stream=sys.stderr)
        return 2
    return 0
