# CA3P 취약점 점검 보고서 명세

보고서 모듈이 만드는 보고서의 **내용(JSON)과 모양**을 정한다. 작성자(LLM)는 아래 JSON만 만들고,
서식은 `py/src/ca3p_report/hwpx/writer.py`가 python-hwpx로 입힌다. HWPX XML을 직접 쓰지 않는다.

원본은 팀 보고서 키트(`REPORT_SPEC.md`, `CA3P_보고서_템플릿.hwpx`)다. 이 저장소에서 다른 점은 다음과 같다.

| 항목 | 키트 | 이 모듈 |
|---|---|---|
| 보고서 단위 | 실행 1건 = 1부 | **finding 1건 = 1부.** `findings` 배열은 항상 1건 |
| 화면 캡처 | 캡션만 담은 자리 상자 | **verifier가 승인한 실제 PNG**를 싣고 캡션을 붙인다 |
| 서식 구현 | XML 문자열 조립 | python-hwpx API(`ensure_run`, `ensure_paragraph_format`, `ensure_border_fill`, 표·그림 API) |
| 실행 메타데이터·판정·식별자 | 작성 규칙 | **코드가 봉인된 번들 값으로 채운다**(`llm/tools.py` `finish_report`) |

## 1. 작성 규칙

1. 실행 메타데이터(`run`)는 실행 기록에서 코드가 채운다. 작성자는 쓰지 않는다.
2. 실행 공통 한계는 `run_limitations`에 한 번만 쓴다. finding의 `limitations`에는 그 취약점에만 해당하는 미검증 범위만 쓴다.
3. 판정 근거는 대조 요청과 공격 요청의 결과 차이로 쓴다. "200 응답을 받았다"는 근거가 아니다.
4. 증거는 원문 그대로 쓴다. 긴 응답은 앞부분만 남기고 `... (이하 생략, 총 N건 / N바이트)`처럼 생략 사실을 밝힌다.
5. 화면 캡처는 보조 자료다. 캡션 끝에 `(보조 자료, 판정 근거 아님)`을 코드가 붙인다.
6. 비밀값(세션 쿠키, 인증 헤더, 토큰, 비밀번호)은 쓰지 않고 `omitted`에 사유를 남긴다.
7. 문체는 "~합니다"로 통일한다. 재현 절차(`steps`)만 "~한다"를 허용한다.
8. 보고서는 초안이다. `review_status` 기본값은 `초안 — 사람 검토 후 배포`.
9. 번들 파일 이름(`run/finding.json` 등)과 내부 필드 이름은 보고서 어디에도 쓰지 않는다.

## 2. 문서 구조

| 순서 | 섹션 | 채우는 필드 |
|---|---|---|
| 표지 | 등급 문구, 제목 띠, 점검 정보 표, 검토 상태, 면책 문구 | `run`, `classification`, `review_status` |
| 1 | 점검 결과 요약: 심각도별 건수(자동), 총평, 우선 조치 권고 표 | `executive_summary`, `findings[].fix_summary` |
| 2 | 점검 개요 | `objective`, `scope`, `method`(선택) |
| 3 | 취약점 목록 | `findings[]` |
| 4 | 취약점 상세(새 페이지): 배지, 위치·벡터·ID, 설명, 영향, 재현 절차, 증거, 화면 캡처, 판정 근거, 조치 방안, 검증 한계, 참고 | `findings[]` |
| 5 | 점검 한계 및 면책 | `run_limitations` |
| 부록 A | 심각도 기준(고정 문구) | 없음 |
| 부록 B | 증적 수집 상태, 재점검 이력, 생략된 정보, 참고 자료 검토 상태 | `sources`, `history`, `omitted`, `referenceContext` |

## 3. JSON

### 최상위

| 필드 | 작성 | 내용 |
|---|---|---|
| `run` | 코드 | 실행 메타데이터(아래) |
| `executive_summary` | LLM ● | 2~4문장. 위험 수준 → 가장 심각한 취약점과 이유 → 즉시 조치 |
| `objective` | LLM ● | 점검 목적 1~2문장 |
| `scope` | LLM ● | 대상 origin, 사용한 세션·역할, 시험 환경 여부 |
| `run_limitations` | LLM ● | 실행 공통 한계. 문단은 빈 줄(`\n\n`)로 나눈다 |
| `findings` | LLM ● | 정확히 1건 |
| `method` | LLM | 생략하면 기본 점검 방법 문구 |
| `sources` | LLM | `[{collector, kind, status, note}]` status: captured / completed / available / empty |
| `history` | LLM | `[{date, finding, result}]` 재점검 이력(과거 사례 자료가 있을 때) |
| `omitted` | LLM | `["항목 — 사유: ..."]` |
| `review_status` | 코드 | `초안 — 사람 검토 후 배포` |
| `classification` | 코드 | `대외비 (CONFIDENTIAL)` |
| `sourceFindingId`, `sourceEvidenceIds`, `generator`, `referenceContext` | 코드 | 출력 검증과 casper 참고 자료용(렌더링: `referenceContext`만 부록 B) |

### `run` (코드가 채움)

| 필드 | 원천 |
|---|---|
| `run_id` | 실행 ID |
| `target_origin` | `report.target.origin` 또는 실행 상태의 target |
| `target_name` | `report.target.name` → fixtureId → origin 순 |
| `profile` | 실행 상태 `testProfile` → `report.testProfile` |
| `started_at` | 실행 상태 `startedAt` → `report.startedAt` |
| `finished_at` | `report.completedAt` → 실행 완료(`complete`) 이벤트 시각 → 저장 시각 |
| `generated_at` | 보고서 확정 시각 |
| `request_count` | `report.metrics.requestCount` → 실행된 공격 수(`execute` 이벤트) |
| `status`, `incomplete` | 실행 상태와 점검 미완료 여부(미완료면 상세에 표시) |

### `findings[0]`

| 필드 | 작성 | 내용 / 예시 |
|---|---|---|
| `id` | 코드 | `V-01` |
| `finding_id` | 코드 | 원본 finding ID |
| `verdict` | 코드 | 원본 판정 confirmed → `confirmed`, 그 밖 → `unverified` |
| `screenshots` | 코드 | `[{caption, ref}]` verifier 캡처. 캡션 끝에 `(보조 자료, 판정 근거 아님)` |
| `title` | LLM | 짧은 한국어 이름 + 필요하면 영문. `검색 API SQL 삽입 (SQL Injection)` |
| `severity` | LLM | `critical` / `high` / `medium` / `low` / `info` |
| `cvss_score`, `cvss_vector` | LLM | `"7.5"`, `"CVSS:3.1/AV:N/..."` |
| `cwe` | LLM | `CWE-89` |
| `location` | LLM | `GET /api/search (q)` |
| `privilege` | LLM | 공격에 필요한 권한. `없음`, `학생` 등 |
| `description` | LLM | 무엇이 왜 취약한지, 대조 대비 공격 결과 차이. 2문단 이내 |
| `impact` | LLM | 확인된 영향과 가능성을 구분 |
| `steps` | LLM | 최소 대조 요청 → 공격 요청 → 비교·판정 3단계 |
| `evidence` | LLM | `[{label, content}]` `[대조 요청]`, `[대조 응답]`, `[공격 요청]`, `[공격 응답] (일부 발췌)` |
| `checks` | LLM | 판정 근거 표 `[{item, result}]` 3~5행 |
| `fix_summary` | LLM | 한 줄 핵심 조치 |
| `fix_short` | LLM | 즉시 조치(코드·설정 수준) |
| `fix_long` | LLM | 근본 대책(구조 개선, 회귀 테스트, 모니터링) |
| `limitations` | LLM | 이 취약점에만 해당하는 미검증 범위 |
| `references` | LLM | `["CWE-89", "OWASP Top 10 A03:2021 Injection"]` |

## 4. 서식

| 요소 | 서식 |
|---|---|
| 심각도 색 | Critical `#7030A0` · High `#C00000` · Medium `#BF8F00` · Low `#2E74B5` · Info `#7F7F7F` |
| 표 머리행 | 네이비 `#1F4E79` 배경, 흰 굵은 글씨, 페이지가 넘어가면 반복 |
| 항목명 셀 | 연한 파랑 `#EAF1FA`, 네이비 굵은 글씨 |
| 요청/응답 증거 | 회색 `#F4F4F7` 박스, D2Coding 8.5pt |
| 총평 / 조치 방안 | 연노랑 `#FFF8E5` / 연녹색 `#EEF7EE` 박스 |
| 판정 confirmed | 녹색 `#2F8F46` 굵게 |
| 표지 | 등급 문구 빨강 `#C00000`, 네이비 제목 띠(흰 24pt 제목, `#DCE6F2` 부제) |
| 글꼴 | 본문 함초롬돋움 10pt, 코드 D2Coding 8.5pt |
| 화면 캡처 | 실제 PNG(폭 150mm 이내), 아래에 캡션(작은 회색 글씨) |
