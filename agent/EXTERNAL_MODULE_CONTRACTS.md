# 외부 모듈 JSON 계약

이 문서는 에이전트가 호출하는 외부 모듈의 최소 계약만 정의한다. Web Explorer, 취약점 DB, 펜테스팅 DB의 구현은 이 저장소와 에이전트 담당 범위에 포함되지 않는다.

## 전송 포트

에이전트는 다음 인터페이스 하나만 요구한다.

```text
gateway.exchange(serializedRequest: string, { signal }?) -> Promise<serializedResponse: string>
```

- 요청과 응답은 UTF-8 JSON 문자열이어야 한다.
- gateway는 envelope의 `receiver`를 보고 실제 외부 모듈로 라우팅한다.
- HTTP, 메시지 큐, stdio 등 실제 전송 방식은 통합 계층이 결정한다.
- 에이전트는 기본 10초 timeout에 도달하면 선택적 `AbortSignal`을 중단하고 `TRANSPORT_FAILURE`로 처리한다.
- 변경 요청의 `messageId`는 외부 모듈에서 idempotency key로 사용할 수 있다.
- 에이전트는 DELETE와 같은 변경 요청을 transport 오류 후 자동 재시도하지 않는다.

## 공통 envelope

```json
{
  "schemaVersion": "1.0",
  "runId": "run-...",
  "iteration": 1,
  "messageId": "uuid",
  "correlationId": "uuid",
  "timestamp": "ISO-8601",
  "sender": "agent",
  "receiver": "web_explorer",
  "type": "module.request",
  "payload": {},
  "evidence": [],
  "policyContext": {
    "targetMode": "isolated_local_lab",
    "targetOrigin": "http://127.0.0.1:3000",
    "maxIterations": 1,
    "rawChainOfThoughtStored": false
  }
}
```

응답은 `receiver: "agent"`, `sender: <요청 receiver>`, `correlationId: <요청 messageId>`를 사용해야 한다. `runId`와 `iteration`도 요청과 일치해야 한다.
에이전트는 receiver와 operation별 성공 응답 type 및 필수 payload를 검증한다. Web Explorer 성공 응답에는 비어 있지 않은 `evidenceId`가 반드시 포함되어야 한다.

## Web Explorer

요청 receiver는 `web_explorer`다.

```json
{
  "operation": "http_request",
  "session": "attacker",
  "method": "GET",
  "path": "/api/posts",
  "query": {},
  "body": {}
}
```

성공 응답 type은 `web.result`다.

```json
{
  "operation": "http_request",
  "trust": "untrusted_observation",
  "request": {
    "method": "GET",
    "path": "/api/posts",
    "session": "attacker"
  },
  "response": {
    "status": 200,
    "ok": true,
    "bodyJson": {}
  },
  "evidenceId": "evidence-id"
}
```

세션 쿠키, 브라우저 격리, HTTP 실행과 raw evidence 보관은 Web Explorer 담당이다. 에이전트는 쿠키를 받거나 저장하지 않는다.

## 취약점 DB

요청 receiver는 `vulnerability_db`다.

```json
{
  "operation": "match",
  "observation": {
    "posts": [],
    "resourceId": 4,
    "attackerId": "alice"
  }
}
```

성공 응답 type은 `knowledge.result`이며 `payload.candidates` 배열을 반환한다. 후보는 최소한 다음 필드를 포함한다.

```json
{
  "knowledgeId": "source-backed-id",
  "cwe": "CWE-639",
  "severity": "high",
  "severityBasis": "basis",
  "attackerId": "alice",
  "resource": { "id": 4, "ownerId": "bob" },
  "actionTemplate": {
    "method": "DELETE",
    "pathTemplate": "/api/posts/{resourceId}"
  },
  "successCriteria": [],
  "provenance": {}
}
```

## 펜테스팅 DB

요청 receiver는 `pentest_db`, type은 `storage.request`다.

- 이벤트 추가: `payload.operation = "append"`, `payload.event` 포함
- 최종 보고서: `payload.operation = "finalize"`, `payload.report` 포함

성공 응답 type은 각각 `storage.appended`, `storage.finalized`다. 실제 저장소 형식, 접근통제, 보존 기간과 변조 방지는 펜테스팅 DB 담당이다.

## 오류

외부 모듈이 정상적으로 거부한 경우 type `module.error`를 반환한다.

```json
{
  "error": {
    "code": "EXTERNAL_FAILURE",
    "message": "reason",
    "source": "external_module",
    "retryable": false
  }
}
```

gateway 호출 실패나 잘못된 응답은 에이전트가 각각 `TRANSPORT_FAILURE`, `PROTOCOL_FAILURE`로 정규화한다. 이 로컬 오류 envelope은 `sender: "agent"`, `receiver: "agent"`, `source: "agent_gateway"`를 사용하므로 외부 모듈 오류로 가장하지 않는다. 반대로 외부 `module.error`의 `source` 주장은 신뢰하지 않으며 envelope sender를 기준으로 `external_module` provenance를 부여한다.
