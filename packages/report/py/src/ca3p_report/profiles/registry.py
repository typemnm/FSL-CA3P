"""Profile registry. A profile only supplies LLM writing hints and check labels.

It selects on the run's ``testProfile``; an unknown value falls back to ``generic`` so a
report is always produced (PLAN §3.2). Profiles hold NO enforcement logic — the LLM writes
the report and a human reviews it (PLAN §1.4.1).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Profile:
    id: str
    # Upstream testProfile values that map to this profile.
    upstream: tuple[str, ...]
    # One-line description of the vulnerability class for the LLM.
    summary: str
    # Ordered reproduction-step hints (the LLM adapts them to the run's events).
    reproduction_hints: tuple[str, ...]
    # finding.checks key -> Korean display label.
    check_labels: dict[str, str] = field(default_factory=dict)
    # Extra text-evidence labels beyond PoC request/response the LLM should include.
    evidence_hints: tuple[str, ...] = ()
    # Impact paragraph hint.
    impact_hint: str = ""
    fallback: bool = False


_STORED_XSS = Profile(
    id="stored_xss",
    upstream=("stored_xss_canary",),
    summary="저장형 XSS: 공격자가 저장한 입력이 다른 사용자의 브라우저에서 실행됩니다.",
    reproduction_hints=(
        "공격자 세션을 확인합니다(setup.attacker_session).",
        "입력 지점을 관찰합니다(loop.observe). 입력 지점 화면을 촬영합니다.",
        "무해한 canary를 게시합니다(loop.act). 요청/응답/페이로드를 텍스트로 싣습니다.",
        "피해자 관점에서 새 브라우저로 결과를 확인하고 촬영합니다(loop.verify).",
    ),
    check_labels={
        "postCreated": "게시글 생성",
        "postIdMatches": "게시글 ID 일치",
        "markerMatches": "marker 일치",
        "pageOnTarget": "대상 origin 유지",
        "postVisible": "게시글 노출",
        "payloadPresent": "페이로드 삽입",
        "bindingCalled": "브라우저 콜백 실행",
        "executed": "실행 확인",
        "noObservationErrors": "관찰 오류 없음",
        "evidencePresent": "증거 존재",
    },
    evidence_hints=("점검 페이로드(canary 내용)", "marker"),
    impact_hint="저장형 XSS는 세션 탈취, 피싱, 피해자 권한 내 동작으로 이어질 수 있습니다.",
)

_BOLA = Profile(
    id="bola",
    upstream=("agent_cross_user_delete_canary",),
    summary="교차 사용자 객체 접근(BOLA, CWE-639): 요청 파라미터만으로 타인 리소스를 조작합니다.",
    reproduction_hints=(
        "서로 다른 두 사용자(공격자/소유자)를 준비합니다.",
        "소유자 리소스를 준비합니다(setup.canary_post).",
        "공격자 세션으로 삭제를 요청합니다(loop.act).",
        "소유자 관점에서 리소스 부재를 확인합니다(loop.verify).",
    ),
    check_labels={
        "differentUsers": "서로 다른 사용자",
        "existedBefore": "사전 존재",
        "deleteAccepted": "삭제 수락",
        "absentAfter": "사후 부재",
    },
    impact_hint="권한 우회는 무단 열람·수정·삭제로 이어질 수 있습니다.",
)

_GENERIC = Profile(
    id="generic",
    upstream=(),
    summary="미등록 취약점 유형입니다. 공통 필드와 검사표만으로 보고서를 작성합니다.",
    reproduction_hints=("실행 이벤트(stage) 순서를 그대로 재현 절차로 적습니다.",),
    fallback=True,
)

_PROFILES = (_STORED_XSS, _BOLA, _GENERIC)
_BY_UPSTREAM = {name: p for p in _PROFILES for name in p.upstream}


def resolve_profile(test_profile: str | None) -> Profile:
    return _BY_UPSTREAM.get(test_profile or "", _GENERIC)
