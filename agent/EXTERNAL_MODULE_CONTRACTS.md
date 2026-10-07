# 외부 모듈 JSON 계약

이 문서는 현재 에이전트가 호출하는 외부 모듈의 JSON 계약을 정의한다. 대시보드 기본 로컬 실습은 `stored_xss_canary`로, 서버가 시작한 소유 loopback 게시판에서 한 번의 XSS canary POST와 독립 브라우저 실행 확인을 수행한다. 로컬 실습에서는 `agent-dashboard/local-lab-gateway.mjs`가 실제 `xss-parser`, `attack-module`, `guardrail`, `casper-db`, `pentest-db`에 연결한다. 기존 `agent_cross_user_delete_canary` BOLA 프로필은 명시적으로 선택할 때 사용한다. 코어 fixture와 `agent` 데모는 같은 계약의 scripted 테스트 대역을 사용한다.

## 전송 포트

에이전트는 다음 인터페이스 하나만 요구한다.

```text
gateway.exchange(serializedRequest: string, { signal }?) -> Promise<serializedResponse: string>
```

- 요청과 응답은 UTF-8 JSON 문자열이어야 한다.
- gateway는 envelope의 `receiver`를 보고 실제 외부 모듈로 라우팅한다.
- HTTP, 메시지 큐, stdio 등 실제 전송 방식은 통합 계층이 결정한다.
- 에이전트는 기본 10초 timeout에 도달하면 선택적 `AbortSignal`을 중단하고 `TRANSPORT_FAILURE`로 처리한다. `xss-parser`에는 30초, `casper-db`에는 15초를 적용한다.
- 변경 요청의 `messageId`는 외부 모듈에서 idempotency key로 사용할 수 있다.
- 에이전트는 검사 POST와 레거시 DELETE 같은 변경 요청을 transport 오류 후 자동 재시도하지 않는다.

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
  "receiver": "xss-parser",
  "type": "module.request",
  "payload": {},
  "evidence": [],
  "policyContext": {
    "targetMode": "isolated_local_lab",
    "targetOrigin": "http://127.0.0.1:3000",
    "testProfile": "stored_xss_canary",
    "maxIterations": 1,
    "rawChainOfThoughtStored": false
  }
}
```

응답은 `receiver: "agent"`, `sender: <요청 receiver>`, `correlationId: <요청 messageId>`를 사용해야 한다. `runId`와 `iteration`도 요청과 일치해야 한다.
에이전트는 receiver와 operation별 응답 type 및 필수 payload를 검증한다. `xss-parser`, `attack-module`, `casper-db`, `pentest-db` 카탈로그 조회 응답에는 비어 있지 않은 `evidenceId`가 필요하다.

## xss-parser

요청 receiver는 `xss-parser`, type은 `module.request`다. 기본 XSS 실습에서는 먼저 `parse_site`의 `before` 단계에서 Chromium으로 한 페이지를 변경 없이 관찰한다. 레거시 BOLA 실습에서는 삭제 뒤 `after` 단계의 `parse_site`도 사용한다.

```json
{ "operation": "parse_site", "origin": "http://127.0.0.1:3000", "phase": "before" }
```

`parse_site` 응답 type은 `parser.result`다. payload에는 같은 `operation`·`phase`, parser의 원본 `report`(schemaVersion `3.4`), `observedPosts`, `errors`, `truncated`, `evidenceId`가 포함된다. `observedPosts` 항목은 화면에 표시된 `id`, `idSource`, `title`, `author`, `pageUrl`만 담는다. 표시된 `author`는 신뢰된 소유자 ID가 아니다. 에이전트는 parser 결과가 잘렸거나 오류가 있으면 중단한다. 기본 XSS 후보는 같은 원점의 `title`·`content` 폼, `POST /api/posts` 입력, `.post-content`의 `innerHTML` sink가 관찰되어야 한다. 레거시 BOLA 프로필은 준비 응답의 신뢰된 canary ID·제목을 parser 표시값과 교차 확인한다. 이 첫 관찰만으로 XSS 실행은 확정되지 않는다.

기본 XSS 검사 POST 후에는 별도의 `verify_stored_xss` 요청을 보낸다.

```json
{ "operation": "verify_stored_xss", "origin": "http://127.0.0.1:3000", "postId": 4, "marker": "0123456789abcdef0123456789abcdef" }
```

응답 type은 `parser.result`이고 payload에 `operation: "verify_stored_xss"`, `phase: "after"`, `execution`, `evidenceId`를 담는다. `execution`은 `postId`, `marker`, 같은 원점의 `pageUrl`, 불리언 `postVisible`·`payloadPresent`·`bindingCalled`·`executed`, 문자열 배열 `errors`를 포함한다. 어댑터는 새 Chromium 브라우저에서 해당 게시글의 고유 마커 콜백이 실제로 호출됐는지 확인한다. 브라우저 요청은 같은 원점의 GET·HEAD로 제한하고 외부 요청, 쓰기 요청과 WebSocket을 차단한다. DOM에 payload가 보이는 것만으로 `executed`가 되지 않는다. 최종 확인은 Agent의 결정론적 `reflect()`가 같은 게시글·마커·원점·콜백·오류 부재와 증거 참조를 함께 검사해 수행한다.

## Attack Module

요청 receiver는 `attack-module`, type은 `module.request`다. `curl`은 셸 문자열이나 자유로운 curl 옵션이 아닌 구조화된 JSON 값이다. 기본 XSS 프로필은 Alice 세션 준비 GET과 검사 `POST /api/posts` 한 번만 전송한다. 코어가 생성한 제목·본문·고유 마커가 담긴 `{method,url,body}`를 DeepSeek가 정확히 복사하도록 요청하고, 코어와 gateway가 동등성을 다시 검사한다. 레거시 BOLA 프로필은 Bob 세션·canary 게시글을 준비한 뒤 `{method,url}` DELETE를 사용한다.

```json
{
  "operation": "execute_curl",
  "session": "attacker",
  "curl": {
    "method": "POST",
    "url": "http://127.0.0.1:3000/api/posts",
    "body": {
      "title": "agent-xss-canary-run-1-0123456789abcdef0123456789abcdef",
      "content": "<img data-ca3p-xss-marker=\"0123456789abcdef0123456789abcdef\" src=\"data:image/png;base64,AA\" onerror=\"window.__ca3pXssProbe?.('0123456789abcdef0123456789abcdef')\">"
    }
  }
}
```

응답 type은 `attack.result`다. `success`는 curl 실행과 HTTP 응답 처리의 성공 여부이며, `response.ok`는 HTTP 상태가 2xx인지 표시한다. HTTP 실패 또는 전송 실패도 응답 JSON으로 기록한 뒤 에이전트가 루프를 중단한다. 전송 실패 시 `response.status`는 `null`, `response.bodyJson`은 `{}`, `error`는 오류 코드다.

```json
{
  "operation": "execute_curl",
  "success": true,
  "error": null,
  "guardrail": { "decision": "ALLOW", "ruleId": "profile-rule", "stage": "loop.act" },
  "request": {
    "method": "POST",
    "url": "http://127.0.0.1:3000/api/posts",
    "session": "attacker"
  },
  "response": {
    "status": 201,
    "ok": true,
    "bodyJson": {
      "post": {
        "id": 4,
        "authorId": "alice",
        "title": "agent-xss-canary-run-1-0123456789abcdef0123456789abcdef",
        "content": "<img data-ca3p-xss-marker=\"0123456789abcdef0123456789abcdef\" src=\"data:image/png;base64,AA\" onerror=\"window.__ca3pXssProbe?.('0123456789abcdef0123456789abcdef')\">"
      }
    }
  },
  "evidenceId": "evidence-id"
}
```

예시의 제목은 설명용이며 실제 값은 현재 `runId`와 고유 마커에 바인딩된다. 코어는 생성 응답의 `post.id`, `authorId`, `title`, `content`가 검사 요청과 일치하는지 확인한다. 로컬 gateway는 허용된 loopback 원점, canary 경로, 메서드, 본문과 고정 순서를 검사하고 실제 `guardrail` 규칙을 전송 직전에 평가한다. 거부되면 `success:false`, `error:"guardrail_denied"`, `guardrail.decision:"DENY"`로 반환하고 curl을 실행하지 않는다. 실제 `attack-module`은 인수 배열로 curl을 실행하며 리다이렉트와 임의 헤더·옵션을 허용하지 않는다. 세션 쿠키는 gateway에서만 주입하고 `attack.result`에는 포함하지 않는다. 임의 URL은 이 경로의 대상이 될 수 없다.

## casper-db

요청 receiver는 `casper-db`, type은 `module.request`다.

```json
{ "operation": "assess_xss_history", "parserReport": { "schemaVersion": "3.4", "pages": [] } }
```

응답 type은 `history.result`이고 payload에는 `operation`, `readyCaseCount`, `observations`, `assessments`, `evidenceId`가 포함된다. 로컬 어댑터는 parser의 명시적인 같은 원점 API 입력 위치만 추출해 실제 `casper-db` SQLite의 준비된 과거 XSS 사례와 비교한다. 각 `assessments[].decision`은 `retest_candidate`, `manual_review`, `no_match` 중 하나다. 이는 과거 사례의 재검토 신호이며 현재 XSS 실행의 증거가 아니다. 기본 DB가 비어 있으면 생성하고, `CASPER_DB_PATH`로 기존 SQLite 파일을 지정할 수 있다.

## 펜테스팅 DB

요청 receiver는 `pentest-db`, type은 `storage.request`다.

- 초안 공격 정보 조회: `payload.operation = "get_attack_info"`, `vulnType: "stored_xss"`, `target: { "endpoint": "POST /api/posts", "parameter": "content" }`. 응답 type은 `storage.attack_info`이며 `attackInfo` 객체 또는 `null`, `evidenceId`를 반환한다. `pentest-db/cases.json`의 `0.1-draft` 카탈로그는 기본 XSS 후보의 입력 위치와 브라우저 확인 방법에 대한 조언이다. 이 카탈로그 자체는 현재 실행의 XSS 증거가 아니다.
- 이벤트 추가: `payload.operation = "append"`, `payload.event` 포함
- 최종 보고서: `payload.operation = "finalize"`, `payload.report` 포함

저장 응답 type은 각각 `storage.appended`와 `storage.finalized`다. 로컬 실습 어댑터는 `reports/pentest-db-runs/<runId의 SHA-256>/`에 이벤트별 JSON과 최종 `report.json`을 생성하며 `storage.finalized.payload.artifactRef`는 해당 파일의 URL이다. 서버를 종료해도 파일은 남는다. fixture 모드의 저장은 인메모리 테스트 대역이다.

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
