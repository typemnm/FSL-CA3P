# 보고서 모듈 재설계 — 취약점 1건, LLM 작성

- 작성일: 2026-11-02
- 상태: **구현 완료. 커밋 전.** packages/report와 함께 §6-1(verifier)·§6-2(worker 테스트)도 반영. 남은 일은 §6-3·§6-5.
- 기준 코드: `woohyun212/report` (`1358648`)
- 원래 설계: [PLAN.md](./PLAN.md). 이 문서가 PLAN과 다르면 이 문서를 따른다.
- 보고서 내용(JSON)과 모양: [REPORT_SPEC.md](./REPORT_SPEC.md) (팀 보고서 키트 기준, 11-03). 아래 §4의 필드 이름은 이 명세를 따른다.

## 0. 배경

최초 설계에서는 취약점 하나를 맡은 Agent가 attack → verifier → report 모듈을 차례로 호출한다.
모듈은 모두 **취약점 하나**를 다룬다. 그래서 보고서 입력도 finding 하나이고 보고서도 한 부다.

이 보고서 모듈은 취약점 프로필 같은 유형별 의존성 없이 다양한 취약점의 보고서를 낸다.
유형을 미리 알 수 없으므로 작성은 LLM이 한다.

재설계 전에는 작성 경로가 두 가지였다. 단일 경로(`report.finding`)는 LLM이, 범용 경로(`findings[]`)는
`general_model.py`가 코드로 작성했다. 이제 **LLM 경로 하나**다. 범용 실행은 수집 단계에서 finding 한 건으로
정규화해 같은 경로에 넣는다.

## 1. 결정 사항

| 항목 | 결정 |
|---|---|
| 입력 | finding **한 건**. 단일 실행은 `report.finding`, 범용 실행은 `options.findingId`로 고른 확정 finding |
| 보고서 단위 | finding 1건 = 보고서 1부 |
| 작성 주체 | LLM(도구 호출 루프). 도구는 `read_bundle`, `finish_report` 둘 |
| 원천 | pentest-db-disk, run-store, verifier handoff, casper-db. attack 모듈의 요청·응답은 `run/attack.json` |
| CWE·CVSS | LLM이 CWE를 고르고 CVSS 3.1 벡터·점수·등급을 산출. **"LLM 산출" 같은 표기는 하지 않는다** |
| 취약점 이름 | LLM이 고른 CWE의 이름. 취약점 프로필(`profiles/`)은 제거 |
| 요약·조치·영향·재현·PoC | LLM 서술. 재현·PoC는 `run/attack.json`으로 구성 |
| 사진 | verifier가 넘긴 캡처만. LLM 직접 촬영(`capture_screenshot`)은 제거 |
| 판정·ID·증거·사진 | `finish_report`가 봉인된 번들 값으로 덮어씀(§4.2). HWPX에 실제 PNG와 값이 실리는 것을 테스트로 확인 |
| 과거 사례·재점검 이력 | 단일 실행의 `loop.history` 기반 4~6절은 유지. **범용 실행의 과거 사례 대조는 백로그** |
| 가드레일·안전 | **보고서에서 제외** |
| 표지 고지문 | **없음.** 실습 전제 고정 문구(`COVER_NOTICES`)와 LLM `notices`를 모두 제거. 점검 미완료는 상세 본문에 코드가 표시 |
| 파일 이름 | LLM이 짓고 `hwpx/filename.py`로 정규화. 없거나 쓸 수 없으면 `<runId 앞 100자>-<finding ID 해시 8자>.hwpx` |
| 실패·부분 실행 | finding 상세를 유지하고 "점검 미완료"를 표시 |
| LLM 모델 | 실행에 쓴 DeepSeek 모델(`run.modelId`). 규칙 기반 실행은 기본 모델. 로컬 LLM 실행은 거부(§6) |
| 시간 제한 | 보고서 프로세스 5분 |
| Node 출력 검증 | runId, HWPX 형식, `sourceFindingId`, finding 판정, 증거 ID ⊂ 원본 finding의 증거 |

## 2. 흐름

```
worker ── ReportTrigger(runId, findingId?, sources, output) ──▶ index.mjs ──▶ python -m ca3p_report run
  [수집]  run · finding 정규화 · attack 기록 · verifier handoff · casper-db → 번들 봉인
  [작성]  LLM ← 마스킹한 번들 / 도구: read_bundle, finish_report
  [확정]  finish_report: 검증된 필드를 번들 값으로 덮어씀 → HWPX/MD/HTML/JSON
index.mjs: runId · finding ID · 판정 · 증거 ID · HWPX 형식 검증 ──▶ worker
```

## 3. 번들

```
<bundle>/
  manifest.json
  run/report.json          # 원본 그대로
  run/events.json          # 원본 그대로
  run/finding.json         # report-finding-1.0: finding 한 건
  run/attack.json          # report-attack-1.0: attack 실행 기록
  run/verification.json    # verifier handoff (있을 때)
  evidence/images/*.png    # verifier 캡처 (있을 때)
  history/casper.json      # 과거 사례·재점검 이력
```

### 3.1 `run/finding.json`
`collect/finding.py`의 `finding_document()`가 만든다.

| 필드 | 단일 실행 | 범용 실행 |
|---|---|---|
| `sourceFindingId` | `finding.findingId` → `finding.id` → `"finding"` (`index.mjs`의 `legacyFindingId`와 같은 규칙) | `options.findingId` |
| `status` | `finding.status` | `"confirmed"` |
| `incomplete` | run 실패 또는 `partial` | run 실패 또는 `partial` |
| `evidenceIds` | `finding.evidenceRefs` | 현재 검증 증거(`general.select_finding`의 교차 검증 결과) |
| 기타 | `finding`, `evidence`, `stopReason` | `finding`, `hypothesis`, `confirmedProbes`, `evidence`, `stopReason` |

### 3.2 `run/attack.json`
`collect/finding.py`의 `attack_records()`가 만든다. 각 기록은 verifier AttackRecord 형태
(`request{method,url,headers,body}`, `response{status,bodyText,bodyJson}`, `control?`, `followUp?`, `setup?`)다.

| 실행 종류 | 원천 |
|---|---|
| 범용 | verifier handoff의 `result.attack` (verifier가 판정한 교환. 본문 16KiB/4KiB로 자르고 쿠키 헤더는 `[redacted]`, `info` 제외) |
| 단일(레거시 import) | `loop.act` 이벤트의 `curl` 요청과 응답 |
| 단일(IDOR 규칙 실행) | 없음. LLM은 `run/finding.json`의 `evidence` 요약을 쓴다 |

## 4. 작성

### 4.1 프롬프트(`llm/prompt.py`)
CWE를 하나 골라 그 이름을 제목으로 쓰고, CVSS 3.1을 평가하고, 재현·PoC를 `run/attack.json`으로 쓰게 한다.
판정·ID·증거·캡처는 코드가 채운다고 알린다. 캡처는 `run/verification.json`의 ref로 step과 caption만 정한다.

### 4.2 `finish_report`가 고정하는 필드(`llm/tools.py`)
LLM이 보낸 REPORT_SPEC JSON을 마스킹한 뒤, 필수 필드가 빠졌거나 형식이 틀리면 `ToolError`로 되돌려 LLM이 고치게 한다
(finding이 정확히 1건, severity 값, CWE·CVSS 형식, 재현 절차 3단계 이상, 대조·공격 증거 둘 다 등). 통과하면 아래를 번들 값으로 덮어쓴다.

| 필드 | 값 |
|---|---|
| `run` | `run/finding.json`의 실행 메타데이터(실행 기록에서 수집) + `generated_at` |
| `findings[0].id`, `finding_id`, `verdict` | `V-01`, 원본 finding ID, 원본 판정(confirmed → `confirmed`, 그 밖 → `unverified`) |
| `findings[0].screenshots` | `run/verification.json` 캡처 `[{caption, ref}]`, 캡션 끝에 `(보조 자료, 판정 근거 아님)` |
| `classification` | `대외비 (CONFIDENTIAL)` (내부용 보고서라 검토 상태는 두지 않음) |
| `sourceFindingId`, `sourceEvidenceIds`, `generator`, `referenceContext` | 출력 검증과 casper 참고 자료용 |

렌더링은 `hwpx/writer.py`가 python-hwpx 6.11 서식 API로 키트 레이아웃(표지·요약·개요·목록·상세·한계·부록)을 그린다.

## 5. 확인한 것

- Python 155개, report Node 9개 테스트 통과. `scripts/check-boundaries.mjs` 통과.
- 이미지와 값: `test_verification_source.py::test_handoff_screenshot_and_verified_values_are_in_the_hwpx`가
  HWPX의 `BinData/` 안 바이트가 verifier PNG와 같은지, 섹션 XML에 finding ID·판정·run ID·캡션·CWE가 있고
  LLM이 바꾸려던 값(다른 finding·판정·run·없는 사진)이 없는지 확인한다.
- 실행 모델 재사용과 세션: 보고서는 검사가 끝난 뒤 worker가 finding마다 순서대로 만든다(`apps/worker/worker.mjs:236`).
  LLM 호출은 매번 독립된 HTTP 요청이고 대화 기록은 보고서 프로세스 안에만 있어 검사 플래너·verifier와 세션을 공유하지 않는다.

## 6. 남은 일 (packages/report 밖)

1. ✅ **verifier handoff에 AttackRecord 포함**(`packages/verifier/index.mjs`, `CONTRACT.md`): `verifier/1` 결과에 `attack`이 생겼다.
   `writeReportHandoff`가 그대로 `verification.json`에 쓰고 수집기가 `run/attack.json`에 옮긴다. `bodyJson`은 자르지 않는다
   (모델 입력과 같음. 범용 런타임이 실행 결과를 64KiB로 제한한다).
2. ✅ **worker 테스트 2개 갱신**(`apps/worker/tests/general-worker.test.mjs`, `general-integration.test.mjs`): loopback 가짜
   OpenAI-compatible 서버를 `DEEPSEEK_BASE_URL`로 준다. 외부 프록시를 막은 상태에서 worker 테스트 22개 통과.
3. **로컬 LLM 실행의 보고서**: `packages/models`의 로컬 설정(`localConfigs`)을 읽어야 한다.
   `integration-manifest.json`의 report 의존성에 `models`를 추가해야 import할 수 있다(통합 담당).
4. ✅ **모든 공격 결과를 verifier가 판정하고 증거 화면을 남김**(11-03): 템플릿 지름길(`template_compare_*`)을 없애
   템플릿 결과도 AI verifier가 판정한다(`apps/application/general-runtime.mjs`). verifier에는 판정 없이 측정값
   (`info.measurements`: 상태 코드·크기·결과 건수)과 사용자에게 보이는 페이지 목록(`info.pages`)을 넘긴다.
   verifier는 confirmed이면 증거 화면을 확보한다(`packages/verifier`): 후보가 없으면 공격 URL을 먼저 캡처하고,
   JSON은 정렬해 내용 높이로 자르며, 결정적 검사(오류·4xx·빈 화면 아님)와 모델 승인(한국어 캡션)을 모두 통과한
   화면만 넘기고 나머지 파일은 지운다. 11-03 로컬 실행에서 확정 10건(대한대 5·원창대 5) 모두 캡처가 실렸다.
5. **범용 원칙과의 충돌 공유**: `docs/GENERAL_VULNERABILITY_PIPELINE_PLAN.md:39`의
   "CWE·심각도·재현 절차는 추정하지 않는다"와 다르다. 범용 HWPX를 만든 담당자(1mn2147)와 공유한다.

## 7. 백로그

| 항목 | 내용 |
|---|---|
| 범용 실행의 과거 사례 대조 | 범용 실행에는 `loop.history`가 없다. casper-db `assess_observation`(읽기 전용)에 finding의 method·경로·유형을 넣는 방안. target_id 매핑 확인 필요 |
| `capture/` 정리 | 작성 도구에서는 빠졌다. `Dockerfile:18,22`, `.github/workflows/ci.yml:32,41`, 그리고 `agent-dashboard/tests/*`가 이 패키지의 Playwright를 쓰므로 함께 정리해야 한다 |
| 보고서 LLM 호출 기록 | 보고서의 모델 호출은 run의 `model_calls`에 기록되지 않는다(토큰 사용량이 보이지 않음) |
