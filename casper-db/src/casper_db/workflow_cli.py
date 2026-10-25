"""Preparation commands default to files and dry runs; writes require --apply."""

from __future__ import annotations

import json
from pathlib import Path

from .automation import run_automation
from .external_vulnerabilities import (
    ExternalBundle,
    collect_external,
    lookup_external,
    normalize_external,
    store_external,
)
from .import_workflow import ImportPackage, ReportReview, digest, prepare_import, review_template
from .report_drafts import ReportDraft
from .repository import CaseStore

COMMANDS = {
    "ocr-status",
    "report-db",
    "automate",
    "review-template",
    "prepare-import",
    "import-reviewed",
    "normalize-external",
    "collect-external",
    "external-import",
    "external-get",
    "external-assess",
    "external-assessments",
}


def register_commands(commands):
    for name in sorted(COMMANDS):
        command = commands.add_parser(
            name,
            help={
                "ocr-status": "Inspect the installed offline Windows OCR recognizer",
                "report-db": "Stage reports and publish reviewed Cases in a NEW owned workspace",
                "automate": "Run a local multi-input ingestion job; default is dry run",
                "review-template": "Create pending human review JSON",
                "prepare-import": "Validate reviewed findings into a dry-run Case package",
                "import-reviewed": "Dry-run a Case package; DB writes require --apply and --draft",
                "normalize-external": "Normalize a saved public advisory JSON; no network or DB",
                "collect-external": "Collect bounded public advisory pages; writes JSON only",
                "external-import": "Dry-run public records; separate DB writes require --apply",
                "external-get": "Read stored provider records for one exact CVE; no writes",
                "external-assess": (
                    "Compare software inventory with advisories; writes require --apply"
                ),
                "external-assessments": "Read target-specific applicability history",
            }[name],
        )
        if name == "report-db":
            from .report_intake_cli import register_commands as register_intake

            register_intake(command)
            continue
        if name == "ocr-status":
            continue
        if name in {"external-assess", "external-assessments"}:
            command.add_argument("database", type=Path)
            if name == "external-assess":
                command.add_argument("inventory", type=Path)
                command.add_argument("--cve", action="append", required=True)
                command.add_argument("--apply", action="store_true")
            else:
                command.add_argument("--target", required=True)
                command.add_argument("--cve", required=True)
            continue
        if name == "automate":
            command.add_argument("file", type=Path)
            command.add_argument("--output-dir", type=Path, required=True)
            command.add_argument("--apply", action="store_true")
            command.add_argument("--cert-db", type=Path)
            command.add_argument("--external-db", type=Path)
            continue
        if name in {"normalize-external", "collect-external"}:
            command.add_argument("source", choices=["nvd", "github"])
        if name != "collect-external":
            command.add_argument("file", type=Path)
        if name in {"review-template", "prepare-import", "normalize-external", "collect-external"}:
            command.add_argument("--output", type=Path, required=True)
        if name in {
            "review-template",
            "prepare-import",
            "normalize-external",
            "collect-external",
        }:
            command.add_argument("--overwrite", action="store_true")
        if name == "prepare-import":
            command.add_argument("--review", type=Path)
            command.add_argument("--target")
        if name in {"import-reviewed", "external-import"}:
            command.add_argument("--apply", action="store_true")
        if name == "import-reviewed":
            command.add_argument("--draft", type=Path, required=True)
        if name == "external-import":
            command.add_argument("--external-db", type=Path)
        if name == "external-get":
            command.add_argument("cve_id")
        if name == "collect-external":
            command.add_argument("--params", type=Path)
            command.add_argument("--max-pages", type=int, default=1)


def _read(path):
    if path.stat().st_size > 32_000_000:
        raise ValueError("workflow JSON exceeds 32 MB")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write(value, path, *, overwrite=False, inputs=()):
    if path.suffix.lower() != ".json":
        raise ValueError("workflow output must be a .json file")
    if any(path.resolve() == item.resolve() for item in inputs if item is not None):
        raise ValueError("output must not overwrite an input")
    if path.exists() and not overwrite:
        raise ValueError("output already exists; use --overwrite explicitly")
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w" if overwrite else "x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _bundles(path):
    raw = _read(path)
    bundles = [
        ExternalBundle.model_validate(item)
        for item in (raw["bundles"] if isinstance(raw, dict) and "bundles" in raw else [raw])
    ]
    for bundle in bundles:
        if (
            digest(bundle.raw) != bundle.raw_sha256
            or normalize_external(bundle.source, bundle.raw).records != bundle.records
        ):
            raise ValueError("external source or normalization integrity mismatch")
    return bundles


def run_command(args, emit):
    if args.command == "external-assess":
        from .applicability import assess_database

        emit(assess_database(args.database, _read(args.inventory), args.cve, apply=args.apply))
        return 0
    if args.command == "external-assessments":
        from .applicability import lookup_assessments

        emit(lookup_assessments(args.database, args.target, args.cve))
        return 0
    if args.command == "ocr-status":
        from .local_ocr import windows_ocr_status

        emit(windows_ocr_status())
        return 0
    if args.command == "report-db":
        from .report_intake_cli import run_command as run_intake

        result = run_intake(args)
        emit(result)
        return 3 if result.get("status") == "needs_review" else 0
    if args.command == "automate":
        result = run_automation(
            args.file,
            args.output_dir,
            apply=args.apply,
            cert_db=args.cert_db,
            external_db=args.external_db,
        )
        emit(result)
        return {"failed": 2, "partial_failure": 2, "needs_review": 3}.get(result["status"], 0)
    if args.command == "external-get":
        emit([record.model_dump(mode="json") for record in lookup_external(args.file, args.cve_id)])
        return 0
    if args.command == "review-template":
        report = ReportDraft.model_validate(_read(args.file))
        _write(review_template(report), args.output, overwrite=args.overwrite, inputs=[args.file])
    elif args.command == "prepare-import":
        report = ReportDraft.model_validate(_read(args.file))
        review = ReportReview.model_validate(_read(args.review)) if args.review else None
        package = prepare_import(report, review, target_id=args.target)
        _write(package, args.output, overwrite=args.overwrite, inputs=[args.file, args.review])
        emit(
            {
                "output": str(args.output),
                "ready_for_import": package.ready_for_import,
                "ready_cases": len(package.cases),
                "blocked": package.blocked,
                "database_written": False,
            }
        )
        return 0
    elif args.command == "import-reviewed":
        package = ImportPackage.model_validate(_read(args.file))
        package.verify()
        report = ReportDraft.model_validate(_read(args.draft))
        expected = prepare_import(report, package.review, target_id=package.assigned_target_id)
        if expected.package_sha256 != package.package_sha256:
            raise ValueError("import package does not match source draft and review")
        if args.apply:
            result = CaseStore(args.db).add_many(package.cases)
            emit({"database_written": True, **{key: len(rows) for key, rows in result.items()}})
        else:
            emit(
                {
                    "database_written": False,
                    "dry_run": True,
                    "case_ids": [case.case_id for case in package.cases],
                }
            )
        return 0
    elif args.command == "normalize-external":
        bundle = normalize_external(args.source, _read(args.file))
        _write(bundle, args.output, overwrite=args.overwrite, inputs=[args.file])
        emit(
            {
                "output": str(args.output),
                "records": len(bundle.records),
                "rejected": len(bundle.rejected_items),
                "database_written": False,
            }
        )
        return 0
    elif args.command == "collect-external":
        bundles = collect_external(
            args.source,
            params=_read(args.params) if args.params else None,
            max_pages=args.max_pages,
        )
        _write(
            {
                "schema_version": "external-collection-1",
                "bundles": [b.model_dump(mode="json") for b in bundles],
            },
            args.output,
            overwrite=args.overwrite,
            inputs=[args.params],
        )
        emit(
            {
                "output": str(args.output),
                "pages": len(bundles),
                "records": sum(len(b.records) for b in bundles),
                "database_written": False,
            }
        )
        return 0
    elif args.command == "external-import":
        bundles = _bundles(args.file)
        if any(b.rejected_items for b in bundles):
            raise ValueError("external import has rejected entries")
        for bundle in bundles:
            if (
                digest(bundle.raw) != bundle.raw_sha256
                or normalize_external(bundle.source, bundle.raw).records != bundle.records
            ):
                raise ValueError("external source or normalization integrity mismatch")
        if args.apply:
            if args.external_db is None:
                raise ValueError("--apply requires an explicit --external-db")
            emit({"database_written": True, **store_external(args.external_db, bundles)})
        else:
            emit(
                {
                    "database_written": False,
                    "dry_run": True,
                    "records": sum(len(b.records) for b in bundles),
                }
            )
        return 0
    emit({"output": str(args.output), "database_written": False})
    return 0
