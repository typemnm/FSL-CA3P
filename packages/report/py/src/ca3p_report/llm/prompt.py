"""System prompt builder. Framing rules are guidance here, not code-enforced (PLAN §1.4.1)."""

from __future__ import annotations

from ..profiles import Profile

_SCHEMA = """ReportModel (report-1.0) you must assemble and pass to finish_report(model):
{
  "generatedAt": "<ISO>", "notices": [..],
  "generator": {"profile": "<profile id>"},
  "run": {"runId","status","testProfile","target":{"origin"},"startedAt","completedAt",
          "metrics":{"requestCount"}, "error":{"code","source","message","stage"}?},
  "findings": [{
    "common": {"title","cwe","location":{"method","path","parameter"},
               "cvss":{"version":"3.1","vector","score","rating"},
               "severity","status","summary","remediation","limitations"},
    "reproduction": [{"text","step"?}],
    "images": [{"step","caption","ref","integrity":"ok"}],
    "textEvidence": [{"label","text"}],
    "checks": [{"label","result"}],
    "impact": "<str>", "profileData": {..}
  }],
  "triage": {"status","reason"?,"rows":[{"caseId","location","label"}]},
  "priorCases": [{"caseId","revision",...,"checks":[{"checkId","status","reviewedAt"}]}],
  "guardrail": {"decisions":[{"decision","ruleId","reason"}]},
  "safety": {..},
  "references": {"collectors":[{"name","driver","status","reason"}],
                 "verifiedByStorage": false, "omittedSections":[{"section","reason"}]}
}"""


def build_system_prompt(profile: Profile) -> str:
    labels = ", ".join(f"{k}→{v}" for k, v in profile.check_labels.items()) or "(없음)"
    hints = "\n".join(f"  - {h}" for h in profile.reproduction_hints)
    return f"""당신은 CA3P 격리 실습의 취약점 점검 **보고서 초안**을 쓰는 작성자입니다.
한국어 합니다체로 작성합니다.

작업 방식:
- read_bundle로 번들 파일을 읽습니다: manifest.json, run/report.json, run/events.json,
  history/casper.json, hints/capture.json.
- 필요하면 capture_screenshot로 대상 화면을 촬영합니다(입력 지점, 피해자 관점 결과).
  촬영 결과의 ref/sha256을 해당 finding.images 항목에 integrity "ok"로 넣습니다.
- 모든 내용을 담은 ReportModel을 조립해 finish_report(model, filename)로 끝냅니다.

지켜야 할 작성 규칙(지침이며, 코드가 강제하지 않습니다. 사람이 최종 검토합니다):
- exploit 판정(status)은 run/report.json의 finding.status를 **그대로** 옮깁니다. 바꾸지 않습니다.
- 심각도는 당신이 CVSS 3.1 벡터·점수·등급으로 평가하되 "LLM 산출"임을 전제로 하고,
  상류 severity도 함께 둡니다(common.severity).
- 고지: 격리 실습 / 데이터 synthetic / 판정은 전달받은 값 / 위치 일치는 재점검 후보일 뿐
  현재 취약 판정이 아님. notices에 반영합니다.
- 비밀값(쿠키, Set-Cookie, API 키, chain-of-thought)은 적지 않습니다(렌더 시에도 마스킹됩니다).
- 사진은 보조 자료이며 판정 근거가 아닙니다.

이번 취약점 유형: {profile.id} — {profile.summary}
재현 절차 힌트:
{hints}
판정 검사 레이블 매핑(checks[].label): {labels}
영향 힌트: {profile.impact_hint or "(프로필 없음 — 일반 서술)"}

{_SCHEMA}

취약점이 미등록 유형이면 공통 필드와 검사표만으로 작성하고 사진은 생략합니다."""
