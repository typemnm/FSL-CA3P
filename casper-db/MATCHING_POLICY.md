# 재점검 후보 선정 규칙

과거 보고서와 현재 관찰된 요청 위치를 연결한다. 결과는 재점검 후보 선정이며 현재 취약점의 존재·재현 성공·실행 권한을 확정하지 않는다.

## 기본 비교

준비된 `ready` Case만 사용한다. `target_id`, 실제 `endpoint`, `method`, `parameter`, `parameter_location`을 비교하며 기본 경로 비교는 대소문자와 끝의 슬래시를 포함한 정확한 비교다.

| 관계 | 결과 |
|---|---|
| 같은 대상·경로·메서드·입력 항목·확인된 입력 위치 | `retest_candidate` |
| 같은 대상·경로이고 방식·이름·위치 중 일부가 다르거나 위치가 미확인 | `manual_review` |
| 대상이나 경로가 다르거나 메서드와 입력 항목이 모두 다름 | `no_match` |

`unknown` 위치끼리 같다는 이유로 자동 후보로 올리지 않는다. 심각도는 같은 입력 지점인지 결정하는 신호가 아니다. 결과에는 일치·차이 필드, 근거와 다음 단계, 참고한 `case_revision`·`report_source`를 포함한다.

## 검토된 경로 템플릿

Case에 `route_template`이 있으면 해당 템플릿의 식별자 자리만 달라진 요청을 연결할 수 있다.

- 템플릿에는 `parameter`와 이름이 같은 완전한 경로 슬롯 하나만 허용한다.
- Case와 관찰 모두 `parameter_location=path`이고 같은 입력 이름이어야 한다.
- 현재 정수 또는 UUID 식별자를 지원하며 저장된 식별자와 같은 형식만 연결한다.
- 고정 경로, 대소문자, 경로 세그먼트 수, 끝의 슬래시는 정확히 비교한다.
- 템플릿이 없으면 숫자나 경로의 유사성으로 자동 연결하지 않는다.

템플릿·메서드·입력 이름·위치가 일치하면 `retest_candidate`다. 실제 URL이 달랐다는 사실은 `changed_fields`의 `endpoint`에, 구조적 연결은 `matched_fields`의 `route_template`에 기록한다. 메서드가 달라졌으면 수동 검토 대상으로 남긴다. 정확히 일치하는 후보를 템플릿으로 연결한 후보보다 먼저 제시한다.

`route_template`은 보고서의 검토 기록에 원문 또는 명시적 확인 자료의 근거를 연결해 지정한다. 임의 정규식이나 무제한 와일드카드는 받지 않는다.

## 입력이 적용되지 않는 요청

관찰에 `parameter=null`, `parameter_location=unknown`, `parameter_not_applicable=true`가 명시되고, Case에도 `not_applicable_fields`에 `parameter`가 기록된 경우에는 입력 없음이 서로 확인된 것으로 비교한다. 대상·경로·메서드가 같으면 후보로 연결한다.

단순히 파라미터를 발견하지 못한 경우에는 이 선언을 사용하지 않는다. 선언 없이 파라미터가 없는 관찰은 입력 검증에서 거부한다. Case의 미적용은 허용된 취약점 유형과 검토 근거를 요구한다.

## 조회와 이력

`find`와 조회 API의 위치 필터는 정확한 경로 조회를 유지한다. 구조적 후보 선정은 `match` 또는 `assess_observation`에서 수행한다. 후보 연결은 과거 Case의 실제 URL이나 payload를 수정하지 않는다.

입력 위치가 바뀐 재점검 결과를 기존 `checks` 계약으로 저장할 때는 별도의 `link_review`가 필요하다. 경로 템플릿 일치는 실제 증거 검토를 대신하지 않는다. 관련 절차는 [CHECK_REVIEW.md](CHECK_REVIEW.md)에 있다.

입력·출력 구조: [파서 계약](PARSER_INPUT_PROPOSAL.md), [관찰 스키마](schemas/parser-observation.schema.json), [후보 결과 스키마](schemas/candidate-assessment.schema.json).
