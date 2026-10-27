from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from pydantic import ValidationError

from .hwp import parse_report
from .hwpx_review import make_review_server, render_hwpx_review
from .matching import ParserObservation, assess_observation
from .models import Case, Check
from .parser import parse_html_inputs
from .report_drafts import ReportDraft
from .repository import SCHEMA_VERSION, CaseStore, ConflictError, NotFoundError, initialize_database
from .workflow_cli import COMMANDS, register_commands, run_command


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
    commands.add_parser("check-results-schema", help="Print the typed verifier result schema")
    check_results = commands.add_parser(
        "check-results", help="Validate verifier results; writes require --apply"
    )
    check_results.add_argument("file", type=Path)
    check_results.add_argument("--apply", action="store_true")
    commands.add_parser("parser-schema", help="Print the parser observation JSON schema")
    parse_html = commands.add_parser(
        "parse-html", help="Extract input points from a saved HTML page; makes no network requests"
    )
    parse_html.add_argument("--target", required=True)
    parse_html.add_argument("--page-url", required=True)
    parse_html.add_argument("--html", type=Path, required=True)
    parse_html.add_argument("--output", type=Path)
    for name in ("parse-hwpx", "parse-report"):
        parse_hwpx = commands.add_parser(
            name, help="Read a local report into review drafts; no database or network access"
        )
        parse_hwpx.add_argument("file", type=Path)
        parse_hwpx.add_argument(
            "--ocr", action="store_true", help="Offline Tesseract OCR; unreviewed candidates"
        )
        parse_hwpx.add_argument("--ocr-language", default="ko")
        parse_hwpx.add_argument("--target", help="Existing team target ID, if known")
        parse_hwpx.add_argument(
            "--image-transcripts", type=Path, help="Optional unreviewed transcriptions (HWPX only)"
        )
        parse_hwpx.add_argument("--output", type=Path)
        parse_hwpx.add_argument("--overwrite", action="store_true")
        parse_hwpx.add_argument(
            "--source-kind",
            choices=["imported", "synthetic"],
            default="imported",
            help="Report provenance label; defaults to imported",
        )
    commands.add_parser("hwpx-draft-schema", help="Print the extraction draft JSON Schema")
    review_hwpx = commands.add_parser(
        "review-hwpx", help="Build a standalone local review HTML from a draft JSON; no database"
    )
    review_hwpx.add_argument("file", type=Path)
    review_hwpx.add_argument(
        "--source-hwpx", type=Path, help="Hash-matched source for capture images"
    )
    review_hwpx.add_argument("--output", type=Path, required=True)
    review_hwpx.add_argument("--overwrite", action="store_true")
    serve_review = commands.add_parser(
        "serve-hwpx-review", help="Serve one review HTML on 127.0.0.1; no database or write API"
    )
    serve_review.add_argument("file", type=Path)
    serve_review.add_argument("--port", type=int, default=8765)
    register_commands(commands)
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
    serve.add_argument("--intake-workspace", type=Path)
    serve.add_argument("--external-db", type=Path)
    serve.add_argument("--allow-advisory-sync", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command in COMMANDS:
            return run_command(args, output)
        if args.command == "schema":
            output(Case.model_json_schema())
        elif args.command == "check-schema":
            output(Check.model_json_schema())
        elif args.command == "check-results-schema":
            from .retest import RetestResults

            output(RetestResults.model_json_schema())
        elif args.command == "parser-schema":
            output(ParserObservation.model_json_schema())
        elif args.command == "hwpx-draft-schema":
            output(ReportDraft.model_json_schema())
        elif args.command in {"parse-hwpx", "parse-report"}:
            if args.output:
                if args.output.suffix.lower() != ".json":
                    raise ValueError("HWPX output must be a .json file")
                inputs = [args.file] + ([args.image_transcripts] if args.image_transcripts else [])
                if any(args.output.resolve() == item.resolve() for item in inputs):
                    raise ValueError("output must not overwrite an input")
                if args.output.exists() and not args.overwrite:
                    raise ValueError("output already exists; use --overwrite explicitly")
            transcripts = None
            if args.image_transcripts:
                if args.image_transcripts.stat().st_size > 1_000_000:
                    raise ValueError("image transcripts exceed the 1 MB limit")
                transcripts = json.loads(args.image_transcripts.read_text(encoding="utf-8-sig"))
            if args.command == "parse-hwpx" and args.file.suffix.lower() != ".hwpx":
                raise ValueError("parse-hwpx requires HWPX; use parse-report for HWP")
            parsed = parse_report(
                args.file,
                target_id=args.target,
                image_transcripts=transcripts,
                source_kind=args.source_kind,
                local_ocr=args.ocr,
                ocr_language=args.ocr_language,
            )
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                mode = "w" if args.overwrite else "x"
                with args.output.open(mode, encoding="utf-8") as stream:
                    stream.write(parsed.model_dump_json(indent=2) + "\n")
                output(
                    {
                        "output": str(args.output),
                        "findings": len(parsed.findings),
                        "database_written": False,
                        "image_transcripts": len(parsed.image_transcripts),
                    }
                )
            else:
                output(parsed.model_dump(mode="json"))
        elif args.command == "review-hwpx":
            if args.output.suffix.lower() != ".html":
                raise ValueError("review output must be a .html file")
            inputs = [args.file] + ([args.source_hwpx] if args.source_hwpx else [])
            if any(args.output.resolve() == item.resolve() for item in inputs):
                raise ValueError("output must not overwrite an input")
            if args.output.exists() and not args.overwrite:
                raise ValueError("output already exists; use --overwrite explicitly")
            if args.file.stat().st_size > 32_000_000:
                raise ValueError("draft JSON exceeds the 32 MB review limit")
            report = ReportDraft.model_validate_json(args.file.read_text(encoding="utf-8-sig"))
            html = render_hwpx_review(report, source_hwpx=args.source_hwpx)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("w" if args.overwrite else "x", encoding="utf-8") as stream:
                stream.write(html)
            output(
                {
                    "output": str(args.output),
                    "findings": len(report.findings),
                    "database_written": False,
                }
            )
        elif args.command == "serve-hwpx-review":
            with make_review_server(args.file, port=args.port) as server:
                output(
                    {"url": f"http://127.0.0.1:{server.server_port}/", "database_written": False}
                )
                sys.stdout.flush()
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
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
                    if args.command == "update"
                    else store.add(raw)
                )
                output(record.model_dump())
            elif args.command == "get":
                record = (
                    store.get_version(args.case_id, args.revision)
                    if args.revision is not None
                    else store.get(args.case_id)
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
            elif args.command == "check-results":
                from .retest import import_retest_results

                if args.file.stat().st_size > 5_000_000:
                    raise ValueError("verification result JSON exceeds 5 MB")
                raw = json.loads(args.file.read_text(encoding="utf-8-sig"))
                output(import_retest_results(store, raw, apply=args.apply))
            elif args.command == "check-list":
                output([record.model_dump() for record in store.list_checks(args.case_id)])
            elif args.command == "check-review":
                output(
                    store.review_check(
                        args.check_id, reviewer=args.reviewer, note=args.note
                    ).model_dump()
                )
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
                uvicorn.run(
                    create_app(
                        args.db,
                        intake_workspace=args.intake_workspace,
                        external_database=args.external_db,
                        enable_advisory_sync=args.allow_advisory_sync,
                    ),
                    host="127.0.0.1",
                    port=args.port,
                )
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
