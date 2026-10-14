# 1차 DB 검증 기록

확인일: 2026-09-30. 새로 만든 `casper-db` 모듈의 검증 결과.

| 확인 | 결과 |
|---|---|
| 독립 가상환경·패키지 설치 | 완료 |
| `python -m pytest` | 51 passed, 1 warning |
| `python -m ruff check .` | 통과 |
| 전월 보고서 필드 | URL·날짜·심각도·상세 설명·조치 방안·전월 증거 저장·조회 확인 |
| 가상 이번 달 파서 비교 데모 | `/search?q` 재점검 후보, `/search?page` 수동 확인, `/about?q` 일치 없음 |
| 시연 산출물 | `data/demo/cases.sqlite3`, 가상 파서 입력 JSON, `data/demo/index.html` 생성. 입력 JSON 수정 후 판정 변화와 이력 중복 방지 확인 |
| 기존 DB 파일 | v2→v3 이동 후 기존 CASE-001의 초안·내용 보존 확인 |
| 기존 DB 백업 | `data/cases.v1-backup.sqlite3`, `data/cases.v2-backup.sqlite3` 보관 |
| 실사용 예시 | `data/cases.sqlite3`의 CASE-001은 `draft`, 기본 목록에서 제외 |

테스트에는 스키마 v1·v2 이동, 재점검 이력 저장·중복 차단·부모 사례 연결, 가상 결과의 검토 완료 차단, 후보 선정에서 초안 제외·위치 차이 처리, HTML 이스케이프와 재실행 시 중복 방지가 포함된다. 경고는 Starlette TestClient의 httpx 관련 deprecation이다. 실제 팀 사이트에서 XSS를 재현하거나 파서·LLM과 통합한 결과는 포함하지 않는다. 예시 보고서 값은 사용자 설명을 바탕으로 만든 가상 자료다.

## 2026-10-01 추가 검증

| 확인 | 결과 |
| --- | --- |
| `python -m pytest` | 58 passed, 1 warning |
| `python -m ruff check .` | 통과 |
| 로컬 HTML 파서 | 모의 페이지의 `GET /search?q`, `GET /search?page`, `POST /feedback message` 추출. 중복·외부 출처 제외 확인 |
| 파서 출력 → DB 후보 선정 | 순서대로 `retest_candidate`, `manual_review`, `no_match` 반환 |
| 입력 위치 구분 | `query`와 `body`가 다르거나 위치가 없으면 자동 후보가 아닌 수동 확인 |
| 기존 DB 이동 | 기존 `data/cases.sqlite3`, 데모 DB, 연습용 DB를 v3에서 v4로 이동. 먼저 각각 `*.v3-backup.sqlite3`를 생성했고 `CASE-001`의 `query`를 보고서 URL에서 확인해 보존 |
| HTML 시연 | `demo.py --parser-input data/demo/parsed-observations.json --no-open` 실행 후 세 분류와 `query`·`body` 표시 확인 |

여기서 파서는 **저장된 HTML 파일만** 읽었다. 실제 모의 사이트의 네트워크 응답, 자바스크립트가 만든 입력, XSS 실행 결과, LLM 연동은 아직 검증하지 않았다. 이전 2026-09-30 기록의 “파서 미연결”은 당시 상태이며, 현재는 로컬 HTML 파서 시제품까지 연결된 상태다.

## 2026-10-06 공유 전 재검증

- 새 위치의 독립 Python 환경에서 `python -m pytest`: 58 passed, 1 warning.
- `python -m ruff check .`: 통과.
- 1건의 가상 전월 XSS 보고서와 로컬 HTML 입력 지점으로 후보 분류를 확인했다. 실제 사이트, XSS 실행, LLM 연동은 아직 검증하지 않았다.
- 검증 환경은 Windows/Python 3.11이다. 중앙 Mac mini에서의 설치·실행은 별도 확인이 필요하다.

## 2026-10-06 v5 변경 검증

- 패키지 0.2.0, DB 구조 v5.
- 전체 테스트: 79 passed, 1 warning. Ruff 검사 통과.
- v1~v4 변환, 변환 중 실패 시 DDL·데이터·버전 롤백, 수정 후 재시도 검증.
- UTC 시간순, 보고서 버전 보존, 실패한 수정의 롤백, 버전 충돌 검증.
- 바뀐 입력의 수동 연결, 다른 사이트 연결 거부, 참고한 보고서 버전 고정 검증.
- 초안→결과 검토, 실제 파일·경로 범위·SHA-256, 파일 변경 감지, 승인 실패 시 초안 유지 검증.
- 가상 결과의 승인 거부, 예전 승인 정보 보존과 재검토 필요 처리 검증.
- 새 CLI 명령과 데모 DB→HTML 파서→세 후보 분류 확인.
- 설치 패키지 생성 및 SQL 리소스 포함 확인. 공유용 JSON Schema와 모델의 일치 확인.
- 원래 사용하던 data/cases.sqlite3와 data/demo/cases.sqlite3는 변환하지 않았다. 테스트용 DB만 사용했다.
- 실제 XSS 재현, LLM·팀 파서 통합, 사용자 인증, Mac mini 운영은 아직 검증하지 않았다.
