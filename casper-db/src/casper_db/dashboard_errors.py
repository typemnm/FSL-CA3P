"""Public error messages: actionable fields, without raw report text or server paths."""

import sqlite3

from pydantic import ValidationError

from .report_intake import ReportTargetConflict
from .report_llm_client import LocalLlmError
from .repository import ConflictError, NotFoundError


def public_error(exc, operation):
    status, code, message, details = 400, "DB_INPUT_INVALID", "입력한 내용을 확인해 주세요.", {}
    if isinstance(exc, ReportTargetConflict):
        status, code = 409, "REPORT_TARGET_CONFLICT"
        message = (
            f"같은 보고서가 이미 '{exc.target_id}' 대상으로 접수되어 있습니다. "
            "원래 대상 이름을 사용하거나 기존 보고서를 열어 주세요."
        )
        details = {
            "existingTargetId": exc.target_id,
            "existingSourceKind": exc.source_kind,
            "existingDraftSha": exc.draft_sha,
        }
    elif isinstance(exc, LocalLlmError):
        status, code, message = (
            503, 'REPORT_LLM_UNAVAILABLE',
            '로컬 보고서 모델을 사용할 수 없거나 원문 대조에 실패했습니다. '
            '모델 설치·내부 연결·서버 로그의 오류 종류를 확인하세요. 외부 API로 전환하지 않습니다.'
        )
    elif isinstance(exc, (NotFoundError, FileNotFoundError)):
        status, code, message = (
            404,
            "DB_RECORD_NOT_FOUND",
            "보고서나 사례를 찾을 수 없습니다. 목록을 새로고침해 주세요.",
        )
    elif isinstance(exc, ConflictError):
        status, code, message = (
            409,
            "DB_REVISION_CONFLICT",
            "다른 작업에서 내용이 변경됐습니다. 최신 내용을 다시 열어 주세요.",
        )
    elif isinstance(exc, sqlite3.IntegrityError):
        status, code, message = (
            409,
            "DB_STORAGE_CONFLICT",
            "기존 자료와 중복되거나 충돌하는 값이 있습니다. 기존 기록을 확인해 주세요.",
        )
    elif isinstance(exc, ValidationError):
        labels = {
            "target_id": "보고서 원래 대상 이름",
            "targetId": "대상 이름",
            "reason": "확인 이유",
            "source_refs": "근거 위치",
            "reported_on": "보고일",
            "method": "HTTP 메서드",
            "severity": "심각도",
            "parameter_location": "입력 위치",
            "expectedRevision": "설정 버전",
        }
        fields = list(
            dict.fromkeys(
                str(e["loc"][-1])
                for e in exc.errors(include_input=False, include_url=False)
                if e["loc"]
            )
        )[:8]
        message = "입력 형식을 확인해 주세요: " + ", ".join(
            labels.get(field, field) for field in fields
        )
        details = {"fields": fields}
    else:
        known = {
            "input is not a readable HWPX archive": (
                "HWPX 파일을 열 수 없습니다. 파일 확장자와 실제 형식, 손상 여부를 확인해 주세요."
            ),
            "no Contents/sectionN.xml body found; input must be HWPX": (
                "HWPX 본문을 찾지 못했습니다. 문서 프로그램에서 HWPX 형식으로 다시 저장해 주세요."
            ),
            "input must be a binary HWP v5 OLE document": (
                "지원하는 HWP v5 파일 형식이 아닙니다. HWPX로 저장한 파일을 사용해 주세요."
            ),
            "HWPX XML declarations with DTD/entities are not supported": (
                "지원하지 않는 XML 선언이 포함된 HWPX입니다. 문서 프로그램에서 다시 저장해 주세요."
            ),
            "invalid HWPX XML": (
                "문서 내부 XML을 읽을 수 없습니다. "
                "문서를 다시 저장하거나 파일 손상 여부를 확인해 주세요."
            ),
            "report must keep its staged target_id": (
                "접수한 보고서의 원래 대상은 검토 과정에서 변경할 수 없습니다."
            ),
            "published intake cannot be deleted": (
                "이미 등록된 사례가 연결된 보고서는 삭제할 수 없습니다."
            ),
        }
        if str(exc) in known:
            code, message = "REPORT_INPUT_INVALID", known[str(exc)]
        elif operation == "stage":
            code = "REPORT_READ_FAILED"
            message = (
                "보고서 내용을 읽지 못했습니다. "
                "HWP/HWPX 형식과 문서 보호·암호 여부를 확인해 주세요."
            )
        elif operation == "review":
            code = "REVIEW_INPUT_INVALID"
            message = "확인 내용의 형식·근거 위치 또는 시험 문자열 선택을 확인해 주세요."
    return {
        "ok": False,
        "status": status,
        "error": message,
        "public_error": {"code": code, "message": message, "details": details},
    }
