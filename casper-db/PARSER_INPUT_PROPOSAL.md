# 파서 → 취약점 DB 입력 계약 (팀 협의안)

초안 작성일: 2026-10-01, 공유 갱신일: 2026-10-06. 이 모듈은 저장된 HTML 한 장으로 입출력을 검증했다. 이 문서는 파서 담당자와 합의할 **출력 형식**이며, 수집 방법을 강제하지 않는다. 저장소의 실제 사이트·팀 파서와의 통합은 별도로 검증해야 한다.

## 전달할 JSON

**입력 지점 하나 = 객체 하나**, 파일 전체는 객체 배열로 한다. 같은 경로에 여러 입력 항목이 있으면 각각 별도 객체다.

```json
[
  {
    "target_id": "LAB-DEMO",
    "endpoint": "/search",
    "method": "GET",
    "parameter": "q",
    "parameter_location": "query"
  },
  {
    "target_id": "LAB-DEMO",
    "endpoint": "/feedback",
    "method": "POST",
    "parameter": "message",
    "parameter_location": "body"
  }
]
```

| 필드 | 뜻 | 약속 |
| --- | --- | --- |
| `target_id` | 점검 대상 사이트의 공통 ID | 지난 보고서의 ID와 동일해야 한다. URL에서 임의 생성하지 않는다. |
| `endpoint` | 요청 경로 | `/search`처럼 /로 시작한다. 호스트·쿼리·fragment는 넣지 않는다. |
| `method` | HTTP 방식 | 대문자 `GET`, `POST` 등으로 보낸다. |
| `parameter` | 입력 항목의 이름 | `q`처럼 이름만 보낸다. 실제 값·토큰·시험 payload는 넣지 않는다. |
| `parameter_location` | 입력이 전달되는 위치 | `query`, `body`, `path`, `header`, `cookie`, `fragment` 중 관찰된 값. 모르면 `unknown`. |

`parameter_location`을 강조하는 이유는 같은 `GET /search`의 `q`라도 URL 쿼리와 다른 입력 위치를 같은 지점으로 자동 확정하면 안 되기 때문이다. **새 파서 출력에는 위치를 넣는 것을 팀 규칙으로 제안한다.** 예전 네 필드 JSON도 현재 코드는 받아들이지만, 위치가 `unknown`으로 처리되어 자동 재점검 후보가 아니라 **수동 확인**이 된다.

경로만 발견하고 입력 항목을 발견하지 못한 경우는 이 배열에 빈 `parameter`로 넣지 않는다. 그 경로의 목록은 파서가 따로 보관하거나, 팀이 별도의 엔드포인트 목록 형식을 합의해야 한다.

## DB가 이 JSON으로 하는 일

현재 후보 선정은 전월 보고서의 `target_id + endpoint + method + parameter + parameter_location`과 비교한다.

1. 다섯 값이 모두 확인되고 같음 → `retest_candidate`
2. 사이트·경로는 같지만 방식·이름·위치 중 하나가 다르거나 위치가 미확인 → `manual_review`
3. 사이트·경로가 다르거나 방식과 이름이 모두 다름 → 해당 전월 사례와 `no_match`

같은 입력 지점이라는 결과도 **이번 달 XSS가 존재한다는 판정이 아니다.** 파서는 입력 위치를 관찰한다. 실제 취약 여부는 허가된 재현 절차의 실행 결과와 증거를 별도로 남겨야 한다. 파서 JSON에는 취약점 종류, 심각도, 조치 방안, “XSS 확인” 같은 판정을 넣지 않는다.

현재 검증 스키마: [parser-observation.schema.json](schemas/parser-observation.schema.json). 형식을 바꿀 때는 이 스키마와 DB 입력 검증을 함께 바꾼다. `run_id`, 관찰 시각, 로그인 역할, 요청 기록 참조는 운영 단계에 필요할 수 있지만 현재 `match` 명령에는 넣을 수 없다. 팀의 실제 파서가 이 값을 제공한다면 별도 실행 기록 형식이나 입력 모델 확장을 함께 정한다.

## 지금 실행되는 파서 시제품

`parse-html`은 **로컬 HTML 파일을 읽기만** 한다. 네트워크 요청, 자바스크립트 실행, XSS 시험을 하지 않는다. HTML 폼의 이름 있는 입력 항목과 같은 출처의 링크에 있는 쿼리 항목을 추출한다. 외부 출처의 폼·링크는 건너뛰고, 같은 입력 항목이 여러 번 보이면 한 줄로 묶는다.

먼저 `demo.py --no-open`으로 데모 DB를 준비한 뒤 아래 명령을 실행한다.

```powershell
Set-Location '<클론한 저장소 경로>\casper-db'
.\.venv\Scripts\python.exe -m casper_db parse-html --target LAB-DEMO --page-url https://lab.example.invalid/search --html examples/mock-site/search.html --output data/demo/parsed-observations.json
.\.venv\Scripts\python.exe -m casper_db --db data/demo/cases.sqlite3 match data/demo/parsed-observations.json
```

현재 모의 HTML에서는 `/search`의 `q`가 재점검 후보, 같은 경로의 `page`는 수동 확인, `POST /feedback`의 `message`는 이전 XSS 보고서와 일치 없음으로 나온다. HTML 자체에는 XSS 취약점이 없다.

이 시제품은 자바스크립트가 나중에 만드는 입력, DOM 기반 처리, 로그인 후 페이지, 저장형 XSS의 입력·출력 페이지 관계를 찾지 못한다. 실제 사이트를 연결할 때는 수집 방법·접근 범위·입력과 출력 페이지의 관계를 팀 파서 담당자와 합의한다. 학교 내부 자료는 Mac mini 또는 팀이 승인한 내부 저장소에만 둔다.

## 팀원에게 확인할 것

파서의 입력 형식은 유지했다. 비교 출력의 각 `matches`에 `case_id`, `case_revision`, `report_source`를 제공한다. 출력 형식은 [candidate-assessment.schema.json](schemas/candidate-assessment.schema.json)에 있다. 점검 모듈은 참고한 버전을 체크 입력에 지정하며, 위치가 달라졌다면 `link_review`로 사람이 확인한 연결 근거를 남긴다. [CHECK_REVIEW.md](CHECK_REVIEW.md)에 저장·증거 검토 절차가 있다.

- 파서가 “경로 하나”가 아니라 **입력 항목 하나씩** 내보낼 수 있는가?
- `target_id`는 누가 부여하고, 전월 보고서와 어떻게 동일하게 유지할 것인가?
- 입력 위치를 `query`와 `body` 이상으로 구분할 수 있는가?
- 같은 입력을 한 번의 점검에서 여러 번 발견하면 파서에서 중복을 묶을 것인가?
- 실제 점검 실행 ID·시간·증거 참조는 파서 파일과 별도 실행 기록 중 어디에 둘 것인가?
