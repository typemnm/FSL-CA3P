# 리피터 (Repeater) — 에이전트 사용 설명서

리피터는 요청을 받아 특정 값만 바꿔 다시 보내고, 응답을 비교해 취약점을 판정하는 공격 도구다. "같은 요청에서 값 하나를 바꿨을 때 거부가 통과로 뒤집히는지"를 보는, 파라미터 변조 계열 공격(IDOR 등)에 쓴다.

## 언제 쓰나

같은 자원에 대한 요청을, 식별자나 파라미터 값만 바꿔서 다시 보냈을 때 권한 판정이 달라지는 공격. 예: 삭제 요청의 `authorId`를 내 계정에서 글 주인으로 바꾸면 거부(403)가 통과(200)로 바뀌는 IDOR.

브라우저에서 스크립트 실행을 확인해야 하는 공격(저장형 XSS 등)에는 쓰지 않는다. 그런 유형은 리피터가 처리하지 않고 명시적으로 거부한다.

## 어떻게 호출하나

리피터에 `vulnType`과 대상 `origin`만 주면 된다. 공격 정의 자체(어떤 요청을 보내고, 어떤 값을 무엇으로 바꾸고, 응답이 어떻게 되면 성공인지)는 코드가 아니라 pentest-db 카탈로그(`pentest-db/cases.multi.draft.json`)에 들어 있다. 리피터는 그 카탈로그에서 `vulnType`에 맞는 케이스를 읽어 실행한다.

- 입력: `vulnType`(예: `idor`), 대상 `origin`(격리 랩의 `http://127.0.0.1:<port>`).
- 공격 정의 출처: 카탈로그의 해당 케이스 `successCheck.expect`(baseline 요청·기대 상태, attack 요청·기대 상태, 선택적 resourceRemoved).

CLI로 직접 확인: 격리 랩에서 `npm run repeater -- <vulnType>` (기본값 `idor`).

## 동작

1. control — 정상 값으로 요청을 보낸다. 권한이 없으면 거부(기대 상태)돼야 한다.
2. tamper — 같은 요청에서 값만 변조해 다시 보낸다. 통과(기대 상태)되면 권한 판정이 값에 의해 뒤집힌 것이다.
3. verify (선택) — 리소스 변화를 다시 조회해 확인한다(예: 글이 실제로 삭제됐는지).

verify는 두 방식 중 하나다: 리소스 조회로 변화 확인(`resourceRemoved`), 또는 재요청의 상태 코드 확인(`verify.status` — 예: 삭제 뒤 `GET /`가 500으로 깨지는지). 후자로 A01 무인증 삭제가 홈 가용성을 깨는 A01+A10 연계까지 판정한다.

모든 요청은 guardrail 룰셋으로 사전 검사되며, 격리 랩(`isolated_local_lab`)에서만, 정해진 요청 예산 안에서만 실행된다. 외부 요청은 금지된다.

## 결과

```
{
  "vulnType": "...",
  "finding": { "category": "<CWE>", "status": "confirmed | not_confirmed | inconclusive" },
  "evidence": [ { "check": "control", "status": ... }, { "check": "tamper", "status": ... }, { "check": "verify", "removed": ... } ]
}
```

- confirmed — control이 기대 거부 상태이고 tamper가 기대 통과 상태이며(verify가 있으면 리소스 변화까지 확인됨).
- not_confirmed — 변조해도 통과되지 않음(권한 판정이 값에 의존하지 않음).
- inconclusive — 기준선이 맞지 않는 등 판정 불가.

## 새 공격 유형 추가

코드를 고칠 필요 없다. 카탈로그에 새 `vulnType` 케이스를 추가하되, `successCheck.expect`를 요청 변조 형식(`observe: "httpResponse"`, `baseline.request`·`baseline.status`, `attack.request`·`attack.status`, 선택적 `resourceRemoved`)으로 적으면, 리피터가 그 `vulnType`으로 그대로 실행한다.
