# 파서 → 취약점 DB 입력 계약

`match`는 관찰된 요청 위치의 객체 배열을 받는다. 같은 경로에서 입력 항목이 여러 개 관찰됐으면 항목별 객체로 전달한다. 파서는 취약점 확정이나 심각도 대신 요청 위치를 제공한다.

| 필드 | 형식·의미 |
|---|---|
| `target_id` | 대상 관리 ID. 과거 보고서와 같은 ID를 사용하며 URL에서 임의 생성하지 않는다. |
| `endpoint` | 실제 요청 경로. 호스트·쿼리·fragment를 포함하지 않는다. |
| `method` | 확인한 HTTP 메서드. |
| `parameter` | 입력 이름. 실제 값·토큰·payload를 넣지 않는다. 입력이 적용되지 않는 경우에만 명시적으로 `null`을 사용할 수 있다. |
| `parameter_location` | `query`, `body`, `path`, `header`, `cookie`, `fragment`, `unknown`. 관찰한 위치를 사용한다. |
| `parameter_not_applicable` | 기본 `false`. 별도 입력이 적용되지 않는 요청임을 확인한 경우에만 `true`. |

일반 입력에는 `parameter`가 필요하다. 예전 출력에서 위치를 생략하면 `unknown`으로 받아 수동 확인 대상으로 남긴다. 새 선택 필드의 기본값은 기존 일반 입력의 직렬화 결과에 추가하지 않는다.

## 입력이 적용되지 않는 경우

입력이 없는 고정 요청임을 확인한 경우 `parameter=null`, `parameter_location=unknown`, `parameter_not_applicable=true`를 함께 전달한다. 입력의 적용 여부를 확인하지 못했거나 파라미터를 발견하지 못한 것만으로 이 선언을 만들지 않는다. 빈 문자열은 파라미터 이름을 대신하지 않는다.

과거 Case 역시 해당 필드를 미적용으로 검토한 경우에만 입력 없음의 일치로 비교한다. Case의 미적용 선언에는 취약점 유형 제약과 근거가 필요하며 파서 관찰만으로 과거 보고서를 변경하지 않는다.

## 경로 파라미터

관찰의 `endpoint`에는 요청한 실제 경로를 유지하고 입력 이름과 `parameter_location=path`를 전달한다. 과거 Case에 검토된 `route_template`이 있을 때만 식별자 변형을 같은 API의 후보로 연결한다. 현재 정수·UUID 슬롯 하나를 지원한다.

`route_template`은 Case의 보고서 검토 기록에 지정하는 필드다. 파서 관찰에 임의 필드로 추가하거나 경로의 모든 숫자를 같은 값으로 치환하지 않는다. 상세 기준은 [MATCHING_POLICY.md](MATCHING_POLICY.md)에 있다.

## 결과의 의미

- `retest_candidate`: 정확한 요청 위치 또는 검토된 경로 구조가 일치한다.
- `manual_review`: 일부 필드가 다르거나 위치가 확인되지 않았다.
- `no_match`: 관련 과거 사례로 연결할 충분한 위치 근거가 없다.

이 결과는 현재 취약점의 존재 여부를 확정하지 않는다. 실제 실행 결과·증거·검토는 별도로 기록한다. 기본 조회에는 `ready` Case만 포함된다.

현재 JSON 구조는 [parser-observation.schema.json](schemas/parser-observation.schema.json), 결과는 [candidate-assessment.schema.json](schemas/candidate-assessment.schema.json)에 있다. 현재 모델에 없는 실행 ID·계정·쿠키·관찰 본문을 이 입력에 섞지 않는다.

## 팀 파서 출력의 선택적 입력 위치

기존 파서 응답을 유지하면서 다음 블록을 추가할 수 있다. `observations`의 각 객체는 위 입력 계약과 같다.

```json
{
  "inputLocations": {
    "schema_version": "casper-parser-locations-1",
    "observations": [
      {
        "target_id": "<대상 ID>",
        "endpoint": "/items/3",
        "method": "GET",
        "parameter": "id",
        "parameter_location": "path"
      }
    ]
  }
}
```

어댑터는 같은 대상·출처이며 실제 파서에 관찰된 URL 경로와 메서드에 해당하는 위치만 사용한다. 다른 대상이나 계약 버전은 거부한다. 호출 옵션의 `locationHints`도 사용할 수 있다. 선택 블록이 없으면 기존 query·body 추출을 유지하며 미확인 요청은 `unresolved_requests`에 남긴다. 헤더·쿠키의 이름만 전달하고 실제 값·인증 토큰은 전달하지 않는다.

## 로컬 HTML 입력 추출

`parse-html`은 저장된 HTML에서 이름 있는 폼 입력과 같은 출처 링크의 쿼리 항목을 추출한다. 네트워크 요청·브라우저 스크립트 실행은 하지 않는다. 헤더·쿠키·동적 API와 경로 템플릿을 자동 발견하는 기능은 포함하지 않는다.
