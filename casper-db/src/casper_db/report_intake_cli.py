"""CLI for the isolated report-to-DB workspace; no global database is consulted."""

from pathlib import Path

from .import_workflow import ReportReview
from .report_intake import ReportIntake


def register_commands(command):
    actions = command.add_subparsers(dest="intake_action", required=True)
    actions.add_parser(
        "init", help="Create a NEW owned directory and empty databases"
    ).add_argument("workspace", type=Path)
    references = actions.add_parser("references", help="Read pending and reviewed handoff context")
    references.add_argument("workspace", type=Path)
    references.add_argument("--target", required=True)
    references.add_argument("--external-db", type=Path)
    references.add_argument("--cve", action="append", default=[])
    for name in ("stage", "review", "publish", "show"):
        action = actions.add_parser(name)
        action.add_argument("workspace", type=Path)
        if name == "stage":
            action.add_argument("file", type=Path)
            action.add_argument("--target", required=True)
            action.add_argument(
                "--ocr", action="store_true", help="Local Windows OCR; review candidates only"
            )
            action.add_argument("--ocr-language", default="ko")
            action.add_argument(
                "--source-kind", choices=["imported", "synthetic"], default="imported"
            )
        if name in {"review", "publish"}:
            action.add_argument("draft_sha256")
        if name == "review":
            action.add_argument("file", type=Path)
        if name == "publish":
            action.add_argument("--apply", action="store_true")
            action.add_argument("--ready-only", action="store_true")
        if name == "show":
            action.add_argument("--draft", dest="draft_sha256")


def run_command(args):
    if args.intake_action == "init":
        return ReportIntake.create(args.workspace).show()
    if args.intake_action == "references":
        from .reference_context import build_reference_context

        return build_reference_context(
            args.target, workspace=args.workspace,
            external_database=args.external_db, cve_ids=args.cve,
        )
    intake = ReportIntake(args.workspace)
    if args.intake_action == "stage":
        return intake.stage(
            args.file,
            target_id=args.target,
            source_kind=args.source_kind,
            local_ocr=args.ocr,
            ocr_language=args.ocr_language,
        )
    if args.intake_action == "review":
        if args.file.stat().st_size > 32_000_000:
            raise ValueError("review JSON exceeds 32 MB")
        review = ReportReview.model_validate_json(args.file.read_text(encoding="utf-8-sig"))
        return intake.submit_review(args.draft_sha256, review)
    if args.intake_action == "publish":
        return intake.publish(args.draft_sha256, apply=args.apply, ready_only=args.ready_only)
    return intake.show(args.draft_sha256)
