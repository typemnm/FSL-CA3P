# attack-tool 템플릿 저장소

AI(공격 서브에이전트)가 참고하거나 바로 사용할 수 있는 공격 템플릿. 템플릿 하나 = 파일 하나 = 빈칸 있는 공격 레시피.

## 저장 구조

```
templates/
  <취약점>/           # 1축: 취약점 종류 (sql_injection, idor, ...)
    <templateId>.json # 카드 한 장
  schema.json         # 포맷 규격 (attack-tool-template-1)
```
- 1축 = 취약점(폴더). 2축 = 의존성(카드 안 `dependency` 트리: runtime→framework→library, 또는 scope:generic).

## 카드 필드

| 필드 | 뜻 |
| --- | --- |
| `attackType` | `{name, cwe}` — 이름(AI용) + CWE(표준 코드) |
| `dependency` | runtime→framework→library 트리, 또는 scope:generic |
| `target` | method·endpoint·application |
| `request.curl` | `{{blank}}` 마커가 든 실제 요청 (바로 복사·실행) |
| `blanks` | 각 `{{blank}}`의 요구사항: required·type·desc·example·pickFrom |
| `payloads` | 빈칸에 넣을 값 목록 |
| `verify` | 성공 판정 규칙 (resultCount / fieldsPresent / statusChain / idorDelete / browser / manual) |
| `executor` | repeater(한 발) / intruder(스윕) / browser / manual |
| `trust` | unverified → 실증·검수되면 confirmed |

## 빈칸 규칙

`{{name}}` = AI가 채워야 할 자리. 뭘 채울지는 `blanks.name`의 `desc`·`type`·`example`을 본다.

## 검증

`node scripts/verify-templates.mjs` — 응답 기반(resultCount/fieldsPresent/statusChain/idorDelete) 템플릿을 실제 사이트에 쏴 confirmed 확인. browser/manual 유형은 자동 검증 대상 아님.
