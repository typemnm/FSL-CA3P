# Attack tool protocol v1

`GET /health`는 인증 없이 `{status:"ok",service:"attack-tool",protocolVersion:"ca3p-attack-tool-1"}`를 반환한다. 도구 호출은 `POST /rpc`, JSON content type, `Authorization: Bearer <private-token>`을 사용한다. 브라우저 Origin 헤더가 있는 호출은 거부한다.

```json
{"jsonrpc":"2.0","id":"request-uuid","method":"tools/call","params":{"name":"execute_attack_template","arguments":{"templateId":"sqli-like-tautology","payload":"' OR '1'='1"}}}
```

성공 응답은 `{jsonrpc,id,result,context:{agentId,runId}}`다. client는 ID와 등록된 identity를 확인한다. identity와 target은 요청 인자로 변경할 수 없다. 인증 실패는 HTTP 401, 경로 오류는 404, content type/Origin 오류는 415다. JSON-RPC 및 실행 오류는 HTTP 200의 `{jsonrpc,id,error:{code,message}}`로 반환한다. 파싱할 수 없는 요청의 ID는 null이다. 오류에는 payload·token·응답 본문을 포함하지 않는다.

| Method/tool | 계약 |
| --- | --- |
| `initialize` | protocol version, 등록된 agent/run, capabilities 반환 |
| `tools/list` | 해당 principal에 등록된 tool 설명과 JSON input schema 반환 |
| `tools/call:list_attack_templates` | 선택적인 attackType/runtime/framework/library 문자열 필터, `{templates:[...]}` 반환 |
| `tools/call:execute_attack_template` | `{templateId,payload}`만 허용. 고정 템플릿의 baseline/attack을 순서대로 가드레일에 요청 |
| `tools/call:execute_probe` | `{probe,hypothesis}`만 허용. host가 등록한 authorize와 execute callback이 있어야 실행 가능 |

템플릿의 패킷은 `{method:"GET",path:"/api/search",query:{q:payload}}`다. 가드레일은 신뢰된 origin/path, 입력 형태, 1회 요청 예산을 검사한다. HTTP redirect를 따라가지 않으며 request timeout과 취소 신호를 연결한다. baseline과 attack은 각각 예산 1개를 소비한다. AI에 execute callback이나 정책 설치 기능을 제공하지 않는다.

템플릿 결과는 `{templateId,baseline,attack,verification}`이다. `verification`은 `{status,baselineCount,attackCount}`로, HTTP 200이고 잘리지 않은 JSON 배열 또는 `{results:[]}`에서만 count를 읽는다. baseline=0과 attack>=1이면 `confirmed`, baseline=0과 attack=0이면 `not_reproduced`, 나머지는 `inconclusive`다. 템플릿 `trust:unverified`는 일반적인 취약점 보증을 의미하지 않는다.

각 응답 관측에는 `status`, content-type, 원본 수집의 `truncated`, 최대 4096 UTF-8 바이트의 `bodyExcerpt`, 발췌의 `excerptTruncated`, `bodyBytes`가 있다. 검증은 발췌 전에 원본으로 수행한다. 원본이 잘리면 확정하지 않는다. 기존 `execute_probe`는 기존 evidence/verifier 결과를 그대로 반환한다.

기본 요청·RPC 응답 크기는 128KiB, 각 가드레일 응답은 64KiB다. daemon 기본 timeout은 30초, application bridge는 120초다. client timeout은 그보다 길게 설정한다. 연결 종료/취소는 host callback에 AbortSignal로 전달한다. 등록한 host callback은 이 신호를 준수해야 한다.

하나의 principal은 하나의 포트에 묶인다. 같은 principal의 요청은 직렬로 처리하여 상태를 가진 정책의 순서를 보장한다. 서로 다른 principal은 병렬 처리할 수 있다. 결과를 공유하는 전역 last-result 상태는 없다. `ports:[0,0]`은 OS가 서로 다른 두 임시 포트를 할당하며, `[4241,4242]`처럼 고정 포트도 지원한다. 시작 중 포트 바인딩이 실패하면 이미 열린 listener를 정리한다. 종료 시 처리 중인 요청을 취소하고 모든 listener를 닫는다.
