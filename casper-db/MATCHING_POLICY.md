# 재점검 후보 선정 규칙 — 1차 구현

이 규칙은 **전월 보고서를 이번 달 어디에서 다시 확인할지** 정한다. 현재 취약점 존재 여부를 판정하지 않는다. 현재 파서 출력은 한 입력 지점마다 `target_id`, `endpoint`, `method`, `parameter`, `parameter_location`을 제공한다. 팀원의 실제 파서와는 이 형식을 합의해야 한다.

| 전월 보고서와 이번 달 관찰의 관계 | 결과 | 처리 |
|---|---|---|
| 같은 사이트·경로·메서드·입력 항목·입력 위치 | `retest_candidate` | 지난달 재현 조건을 검토하고 허가된 범위에서 재점검 대상으로 제안 |
| 사이트·경로가 같고, 메서드·입력 항목·입력 위치 일부가 다르거나 입력 위치가 미확인 | `manual_review` | 같은 입력 지점인지 사람이 확인. 자동 재점검 후보로 확정하지 않음 |
| 사이트나 경로가 다르거나, 메서드와 입력 항목이 모두 다름 | `no_match` | 이 전월 보고서를 자동 연결하지 않음. 새 취약점이 없다는 뜻은 아님 |

`draft` 보고서는 정상 후보 조회에서 제외한다. 예전 네 필드 JSON에 입력 위치가 없으면 `unknown`으로 받아 수동 확인으로 보낸다. 결과에는 일치한 필드, 달라진 필드, 이유, 다음 단계를 넣어 팀원이 설명할 수 있게 했다. 숫자 점수는 아직 쓰지 않는다. 이 값들만으로 “73% 같은 취약점” 같은 확률을 계산할 근거가 없기 때문이다. `severity`는 재점검 우선순위에는 쓸 수 있지만 **같은 위치인지**를 결정하는 신호는 아니다.

## 왜 이 기준인가

OWASP는 웹 애플리케이션의 진입점을 기록할 때 요청 경로, 메서드, 파라미터 및 인증·다단계 흐름을 함께 보도록 안내한다. 반사형 XSS는 입력이 응답에 어떻게 포함되고 인코딩되는지도 확인해야 한다. 쿼리의 `q`와 본문의 `q`를 혼동하지 않기 위해 입력 위치를 별도 필드로 추가했다. **위치의 구조적 일치**는 점검 후보 선정에는 유용하지만 XSS의 현재 존재 여부를 증명하지 못한다. [OWASP 진입점 식별](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points/), [OWASP 반사형 XSS 점검](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/01-Reflected_Cross_Site_Scripting/)

현재 경로 비교는 대소문자와 끝의 `/`까지 정확히 비교한다. `/search`와 `/search/`, `/users/1`과 `/users/2`를 멋대로 같다고 취급하지 않는다. 파서가 라우트 템플릿이나 명시적인 별칭을 제공하면 그때 별도 규칙으로 다룬다.

## 직접 실행해 보기

`demo.py`로 별도 데모 DB를 만들고, [파서 입력 계약](PARSER_INPUT_PROPOSAL.md)의 `parse-html` 명령으로 모의 HTML을 읽는다. 예시 입력의 `parameter`를 바꾸고 `match`를 실행하면 판정 변화를 확인할 수 있다.

동일한 판정 내용을 JSON으로 보려면 프로젝트 폴더의 터미널에서 다음 명령을 실행한다.

```powershell
.\.venv\Scripts\python.exe -m casper_db --db data/demo/cases.sqlite3 match data/demo/parsed-observations.json
```

이 명령은 **읽기만 한다.** 예시 입력을 편집해도 과거 보고서나 점검 이력이 바뀌지 않는다. `match`의 결과를 본 뒤 실제 점검을 수행하고 증거를 확보해야 `checks` 이력에 결과를 넣을 수 있다.

각 사례에는 `case_revision`과 `report_source`도 반환한다. 재점검 기록에는 참고한 버전을 지정한다. 바뀌거나 미확인인 위치는 사람이 연결을 확인한 `link_review`를 남겨야 저장할 수 있다. 연결 검토와 실제 결과의 검토 완료는 별도 단계다. [저장·검토 절차](CHECK_REVIEW.md)에 JSON과 명령이 있다.

## 다음 단계에 필요한 정보

- HTML 파서 시제품은 폼의 쿼리·본문을 구분한다. 팀 파서가 헤더·쿠키·DOM 입력까지 구분하는지
- 로그인 역할, 선행 화면, 라우트 템플릿을 기록하는지
- 반사형 XSS라면 입력이 응답의 어느 문맥에 나오는지, 인코딩 여부를 어떤 도구가 관찰할지
- 저장형 XSS라면 입력 페이지와 출력 페이지의 관계를 어떻게 기록할지

이 정보가 없는데 LLM이 경로가 비슷하다는 이유로 “같은 취약점”이라고 판단하게 해서는 안 된다. DOM 기반 XSS는 브라우저 코드의 입력 지점과 출력 지점을 분석해야 하므로 별도 점검 정보가 필요하다. [OWASP 저장형 XSS 점검](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/02-Stored_Cross_Site_Scripting/), [OWASP DOM 기반 XSS 점검](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting/)
