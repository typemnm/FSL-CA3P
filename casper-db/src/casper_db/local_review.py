"""Local report selection, extraction, editable review and pre-import validation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .hwp import parse_report
from .import_workflow import ReportReview, digest, prepare_import, review_template
from .report_drafts import ReportDraft

SESSION_ID = re.compile(r"\d{8}T\d{6}Z-[a-f0-9]{12}")


def _id():
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:12]


def _read(path):
    if path.stat().st_size > 32_000_000:
        raise ValueError("local review JSON exceeds 32 MB")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write(path, value):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _pointer(path, value):
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    _write(temporary, value)
    os.replace(temporary, path)


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pick_hwpx() -> Path | None:
    """A user-operated dialog. Cancelling does not change the active session."""
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError as exc:
        raise ValueError(
            "file picker needs tkinter; on a server pass --file <report-path>"
        ) from exc
    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = filedialog.askopenfilename(
            parent=root,
            title="CERT 보고서 HWP / HWPX 선택 · 추출 및 검토",
            filetypes=[
                ("한글 보고서", "*.hwp *.hwpx"),
                ("HWP 보고서", "*.hwp"),
                ("HWPX 보고서", "*.hwpx"),
            ],
        )
        return Path(selected) if selected else None
    except tk.TclError as exc:
        raise ValueError(
            "file picker could not open; on a server pass --file <report-path>"
        ) from exc
    finally:
        if root is not None:
            root.destroy()


def _guide(report):
    lines = [
        f"선택한 보고서: {report.source['filename']}",
        "",
        "1. findings.json에서 추출 후보와 원문 근거를 확인합니다.",
        "2. report.review.json에 확인한 내용만 기록하고 Ctrl+S로 저장합니다.",
        "3. 터미널에서 Enter 또는 '새 보고서 · 현재 보고서 등록 전 검증' 작업을 실행합니다.",
        "",
        "미확인 값은 비워 두고 decision=pending을 유지할 수 있습니다.",
        "reviewer와 reviewed_at은 실제 검토자·시각입니다. 취약점 발견일과 별도입니다.",
        "resolutions의 각 필드에는 value, reason, source_refs를 함께 기록합니다.",
        "근거는 해당 취약점의 표·문단 식별자 또는 manual:확인 자료 이름을 사용합니다.",
        "목록 필드(preconditions, procedure, remediation, not_applicable_fields)는 "
        "문자열 배열입니다.",
        "입력이 없는 유형은 not_applicable_fields에 parameter·payload 중 해당 항목을 기록합니다.",
        "applicability_reason과 각 보완 항목의 원문 근거가 필요하며, 미확인과 미적용은 다릅니다.",
        "route_template은 확인된 경로의 식별자 자리만 {파라미터명}으로 표시합니다.",
        "경로 템플릿은 현재 정수·UUID 식별자 한 자리를 지원하며 다른 부분은 정확히 비교합니다.",
        "payload_variant_index는 아래 후보의 0부터 시작하는 번호이며, 미확정이면 null입니다.",
        "payload 보완값과 후보 선택을 동시에 쓰지 않습니다. 원문 따옴표를 임의 치환하지 않습니다.",
        "acknowledged_issue_codes에는 실제로 대조·검토한 항목만 기록합니다.",
        "원문·report.draft.json·session.json의 해시/ID는 편집하지 않습니다.",
        "",
        "OCR은 --ocr로 명시한 실행에서만 사용하며 결과는 미검토 후보입니다.",
        "새 보고서에는 이전 캡처 전사를 자동 연결하지 않습니다.",
        "취약점 표가 0개면 report.draft.json의 document에 보존된 원문을 확인합니다.",
        "이 기능은 검증까지만 제공하며 DB 저장·네트워크 요청을 하지 않습니다.",
    ]
    for index, finding in enumerate(report.findings, 1):
        lines.extend(
            [
                "",
                f"[{index}] {finding.candidate.endpoint or '경로 미확정'}",
                f"draft_id: {finding.draft_id}",
                f"원문 표: {finding.source_ref}",
                "missing_fields: " + ", ".join(finding.missing_fields),
                "unresolved_fields: " + ", ".join(finding.unresolved_fields),
            ]
        )
        lines.append("추출 후보 (검토 전):")
        for name, value in finding.candidate.model_dump(mode="json").items():
            lines.append(f"  {name}: " + json.dumps(value, ensure_ascii=False))
        lines.append("원문 근거와 문장 분류:")
        for name, evidence in finding.field_evidence.items():
            for entry in evidence:
                if name in {"narrative_segments", "ocr_segments"}:
                    segment = entry.value
                    lines.append(
                        f"  [{segment['role']}] {segment['text']!r}"
                        f" / {entry.source_ref} [{segment['start']}:{segment['end']}]"
                    )
                else:
                    lines.append(
                        f"  {name} ({entry.method}): "
                        + json.dumps(entry.value, ensure_ascii=False)
                        + f" / {entry.source_ref}"
                    )
        for number, variant in enumerate(finding.payload_variants):
            lines.append(
                f"  payload[{number}] {variant.representation}: {variant.value!r}"
                f" / {variant.source_ref}"
            )
        codes = sorted({issue.code for issue in finding.review_issues})
        lines.append("검토 항목: " + ", ".join(codes))
    return "\n".join(lines) + "\n"


def start_session(source: Path, state_dir: Path, *, local_ocr=False, ocr_language="ko") -> dict:
    """Create fresh pending review files; never reuse another report's review."""
    source = source.expanduser().resolve(strict=True)
    report = parse_report(source, local_ocr=local_ocr, ocr_language=ocr_language)
    if _hash(source) != report.source["sha256"]:
        raise ValueError("원문이 추출 도중 변경됐습니다. 안정된 파일로 다시 시작하세요.")
    state_dir = state_dir.resolve()
    session_id = _id()
    folder = state_dir / "runs" / session_id
    folder.mkdir(parents=True)
    session = {
        "schema_version": "vscode-hwpx-session-1",
        "session_id": session_id,
        "source_path": str(source),
        "source_sha256": report.source["sha256"],
        "source_filename": source.name,
        "draft_sha256": digest(report),
        "created_at": datetime.now(UTC).isoformat(),
    }
    _write(folder / "report.draft.json", report.model_dump(mode="json"))
    _write(
        folder / "findings.json",
        {
            "source": report.source,
            "findings": [finding.model_dump(mode="json") for finding in report.findings],
        },
    )
    _write(folder / "report.review.json", review_template(report).model_dump(mode="json"))
    with (folder / "review-guide.txt").open("x", encoding="utf-8") as stream:
        stream.write(_guide(report))
    _write(folder / "session.json", session)
    _pointer(state_dir / "active.json", {"session_id": session_id})
    return {
        **session,
        "session_directory": str(folder),
        "findings": len(report.findings),
        "database_written": False,
    }


def current_session(state_dir: Path):
    state_dir = state_dir.resolve()
    active = _read(state_dir / "active.json")
    session_id = active.get("session_id", "")
    if not isinstance(session_id, str) or not SESSION_ID.fullmatch(session_id):
        raise ValueError("invalid active session ID; choose the report again")
    folder = (state_dir / "runs" / session_id).resolve(strict=True)
    if not folder.is_relative_to(state_dir / "runs"):
        raise ValueError("session must stay inside its output directory")
    session = _read(folder / "session.json")
    if (
        session.get("schema_version") != "vscode-hwpx-session-1"
        or session.get("session_id") != session_id
    ):
        raise ValueError("session metadata mismatch")
    return folder, session


def validate_session(state_dir: Path) -> dict:
    """Read the saved review again each time; return artifacts and no DB operation."""
    folder, session = current_session(state_dir)
    check_dir = folder / "checks" / _id()
    check_dir.mkdir(parents=True)
    result = {
        "schema_version": "vscode-hwpx-check-1",
        "session_id": session["session_id"],
        "source_filename": session["source_filename"],
        "validated_at": datetime.now(UTC).isoformat(),
        "status": "error",
        "ready_for_import": False,
        "ready_cases": 0,
        "database_written": False,
        "review_file": str(folder / "report.review.json"),
        "validation_file": str(check_dir / "validation.json"),
        "errors": [],
    }
    try:
        report = ReportDraft.model_validate(_read(folder / "report.draft.json"))
        if digest(report) != session["draft_sha256"]:
            raise ValueError(
                "추출본 내용이 변경됐습니다. 보고서를 다시 선택해 새 검토를 시작하세요."
            )
        if (
            report.source["sha256"] != session["source_sha256"]
            or report.source["path"] != session["source_path"]
        ):
            raise ValueError("source metadata mismatch")
        if _hash(Path(session["source_path"])) != session["source_sha256"]:
            raise ValueError("원본 보고서가 변경됐습니다. 파일을 다시 선택해 새 검토를 시작하세요.")
        # No re-extraction here: the review stays bound to the exact draft revision.
        review = ReportReview.model_validate(_read(folder / "report.review.json"))
        package = prepare_import(report, review)
        _write(check_dir / "cases.import.json", package.model_dump(mode="json"))
        result.update(
            status="ready" if package.ready_for_import else "needs_review",
            ready_for_import=package.ready_for_import,
            ready_cases=len(package.cases),
            findings=len(report.findings),
            blocked=package.blocked,
            excluded=package.excluded,
            review_sha256=digest(review),
            import_package=str(check_dir / "cases.import.json"),
        )
        if not report.findings:
            result["note"] = "인식된 취약점 표가 없습니다. document의 원문을 확인하세요."
        elif package.excluded and not package.blocked and not package.cases:
            result["status"] = "excluded"
    except (ValueError, OSError, KeyError) as exc:
        result["errors"].append(str(exc))
    _write(check_dir / "validation.json", result)
    _pointer(folder / "last-validation.json", {"validation_file": result["validation_file"]})
    return result


def open_in_vscode(editor: Path, paths: list[Path]):
    """Use the installed editor executable; never interpolate paths into a shell."""
    if not editor.is_file():
        raise ValueError("VS Code executable was not found; open the printed JSON paths manually")
    environment = dict(os.environ)
    environment.pop("ELECTRON_RUN_AS_NODE", None)
    subprocess.Popen(
        [str(editor), "--reuse-window", *[str(path.resolve()) for path in paths]],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["start", "review", "validate"])
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--file", type=Path, help="Optional explicit HWP/HWPX instead of a dialog")
    parser.add_argument("--ocr", action="store_true", help="Local OCR; results remain unreviewed")
    parser.add_argument("--ocr-language", default="ko")
    parser.add_argument("--editor", type=Path, help="Installed VS Code executable")
    parser.add_argument(
        "--pause", action="store_true", help="Start, edit JSON, then Enter to validate"
    )
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        if args.command != "start" and (args.file or args.pause):
            raise ValueError("--file and --pause are only used with start")
        if args.command == "start":
            source = args.file or pick_hwpx()
            if source is None:
                print("선택을 취소했습니다. 기존 보고서와 검토 기록은 그대로 유지됩니다.")
                return 0
            session = start_session(
                source, args.state_dir, local_ocr=args.ocr, ocr_language=args.ocr_language
            )
            print(json.dumps(session, ensure_ascii=False, indent=2))
        folder, session = current_session(args.state_dir)
        print(f"\n현재 보고서: {session['source_filename']} / {session['session_id']}")
        if args.command in {"start", "review"}:
            paths = [
                folder / name
                for name in ("findings.json", "review-guide.txt", "report.review.json")
            ]
            if args.editor:
                open_in_vscode(args.editor, paths)
            for path in paths:
                print(path)
            print("\n확인한 값만 검토 JSON에 기록하고 Ctrl+S로 저장하세요.")
            print("모르는 값과 payload 후보 선택은 비워 두고 pending을 유지할 수 있습니다.")
            if args.command == "review" or not args.pause:
                return 0
            input("저장 후 이 터미널에서 Enter를 누르면 등록 전 검증을 실행합니다. ")
        result = validate_session(args.state_dir)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.editor:
            open_in_vscode(args.editor, [Path(result["validation_file"])])
        print("\nDB 저장·네트워크 요청은 수행하지 않았습니다.")
        return 2 if result["status"] == "error" else 0
    except (ValueError, OSError, KeyError, EOFError) as exc:
        print(f"보고서 검토 오류: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
