# Attack tool protocol v1

`GET /health`는 인증 없이 `{status:"ok",service:"attack-tool",protocolVersion:"ca3p-attack-tool-1"}`를 반환한다. 도구 호출은 `POST /rpc`, JSON content type, `Authorization: Bearer <private-token>`을 사용한다. 브라우저 Origin 헤더가 있는 호출은 거부한다.

```json
{"jsonrpc":"2.0","id":"request-uuid","method":"tools/call","params":{"name":"execute_attack_template","arguments":{"templateId":"sqli-like-tautology","payload":"' OR '1'='1"}}}
```

성공 응답은 `{jsonrpc,id,result,context:{agentId,runId}}`다. client는 ID와 등록된 identity를 확인한다. identity와 target은 요청 인자로 변경할 수 없다. 인증 실패는 HTTP 401, 경로 오류는 404, content type/Origin 오류는 415다. JSON-RPC 및 실행 오류는 HTTP 200의 `{jsonrpc,id,error:{code,message}}`로 반환한다. 파싱할 수 없는 요청의 ID는 null이다. 오류에는 payload·token·응답 본문을 포함하지 않는다.

| Method/tool | 계약 |
| --- | --- |
| `initialize` | protocol version, 등록된 agent/run, capabilities 반환 |
| `tools/list` | 해당 principal에 등록된 tool 설명과 JSON input schema 반환. 실행 schema의 ID·payload는 길이 제한 문자열이며 서버가 등록된 조합인지 확인 |
| `tools/call:list_attack_templates` | 선택적인 attackType/runtime/framework/library 문자열 필터와 limit/offset 정수, `{templates:[...],total,nextOffset}` 반환 |
| `tools/call:execute_attack_template` | `{templateId,payload}`만 허용. 선택한 템플릿의 baseline/attack을 순서대로 가드레일에 요청 |
| `tools/call:execute_probe` | `{probe,hypothesis}`만 허용. host가 등록한 authorize와 execute callback이 있어야 실행 가능 |

현재 지원하는 패킷은 `{method:"GET",path:template.request.packet.path,query:{q:payload}}`다. baseline은 같은 경로에 `template.verify.baseline.q`를 전송한다. `executor:guardrail`, GET, `q` 하나의 query 입력, `verify.mode:resultCount`를 지원하며 다른 형태는 참고용이다. 참고용 템플릿도 목록에 포함하지만 실행 요청은 거부한다. 지원하는 템플릿이 하나도 없으면 실행 도구를 노출하지 않는다. 가드레일은 서버 설정의 origin/path, 입력 형태, 1회 요청 예산을 검사한다. HTTP redirect를 따라가지 않으며 request timeout과 취소 신호를 연결한다. baseline과 attack은 각각 예산 1개를 소비한다. AI에 execute callback이나 정책 설치 기능을 제공하지 않는다.

템플릿 결과는 `{templateId,baseline,attack,verification}`이다. `verification`은 `{status,baselineCount,attackCount}`로, HTTP 200이고 잘리지 않은 JSON 배열 또는 `{results:[]}`에서만 count를 읽는다. baseline이 `verify.baseline.expect`와 같고 attack이 `verify.attack.expectMin` 이상이면 `confirmed`, 유효한 baseline에서 attack이 최소 개수 미만이면 `not_reproduced`, 나머지는 `inconclusive`다. 템플릿 `trust:unverified`는 일반적인 취약점 보증을 의미하지 않는다.

daemon은 시작할 때 전체 카탈로그를 복사한다. 목록·실행 schema·렌더링·검증은 같은 복사본을 사용하며 실행 중 Workspace 수정·삭제가 적용되지 않는다. application bridge도 이 복사본의 템플릿을 평가 자료로 사용한다. 다음 daemon 또는 평가부터 최신 카탈로그를 읽는다. Workspace 관리 API의 인증·revision·일괄 등록 계약은 [README](README.md#workspace-템플릿-관리)에 있다.

목록의 `limit` 기본값은 25, 허용 범위는 1~100이고 `offset` 기본값은 0, 허용 범위는 0~1000이다. 필터를 적용한 결과의 전체 개수를 `total`로 반환한다. 응답은 JSON-RPC envelope를 포함한 128KiB 제한 아래로 페이지를 줄일 수 있으므로, 호출자는 `offset + limit` 대신 `nextOffset`을 사용한다. 마지막 페이지의 `nextOffset`은 `null`이다. 단일 템플릿은 직렬화한 JSON 64KiB 이하로 제한해 유효한 항목이 있는 페이지는 최소 한 개를 반환한다. 실행 도구에는 템플릿 전체나 payload 목록을 스키마에 복제하지 않으며, ID와 payload 조합은 실행 직전에 같은 snapshot에서 확인한다.

각 응답 관측에는 `status`, content-type, 원본 수집의 `truncated`, 최대 4096 UTF-8 바이트의 `bodyExcerpt`, 발췌의 `excerptTruncated`, `bodyBytes`가 있다. 검증은 발췌 전에 원본으로 수행한다. 원본이 잘리면 확정하지 않는다. 기존 `execute_probe`는 기존 evidence/verifier 결과를 그대로 반환한다.

기본 요청·RPC 응답 크기는 128KiB, 각 가드레일 응답은 64KiB다. daemon 기본 timeout은 30초, application bridge는 120초다. client timeout은 그보다 길게 설정한다. 연결 종료/취소는 host callback에 AbortSignal로 전달한다. 등록한 host callback은 이 신호를 준수해야 한다.

하나의 principal은 하나의 포트에 묶인다. 같은 principal의 요청은 직렬로 처리하여 상태를 가진 정책의 순서를 보장한다. 서로 다른 principal은 병렬 처리할 수 있다. 결과를 공유하는 전역 last-result 상태는 없다. `ports:[0,0]`은 OS가 서로 다른 두 임시 포트를 할당하며, `[4241,4242]`처럼 고정 포트도 지원한다. 시작 중 포트 바인딩이 실패하면 이미 열린 listener를 정리한다. 종료 시 처리 중인 요청을 취소하고 모든 listener를 닫는다.
