# 외부 모듈 JSON 계약

`agent/src/protocol.js`는 `casper-db` 지식 조회와 이전 실행 기록을 위한 JSON envelope의 구문·상관관계·오류를 검증한다. 현재 범용 점검은 `runGeneralAssessment()`의 `observer`, `planner`, `policy`, `executor`, `verifier` 포트를 통해 실행된다. 퇴역한 `vul-web-1` 게이트웨이와 `stored_xss_canary`·`agent_cross_user_delete_canary` 단일 검사는 신규 실행하지 않는다.

## 공통 envelope

`createEnvelope()`는 `schemaVersion: "1.0"`, `runId`, `iteration`, `messageId`, `correlationId`, `timestamp`, `sender`, `receiver`, `type`, `payload`, `evidence`, `policyContext`를 생성한다. `parseEnvelope()`는 UTF-8 JSON 문자열만 받고 1 MB를 넘는 메시지와 알 수 없는 모듈·타입을 거부한다. `replyTo()`는 요청의 `runId`·`iteration`·`policyContext`를 유지하고 요청 `messageId`를 응답 `correlationId`로 기록한다.

지원되는 모듈 ID는 `agent`, `attack-module`, `casper-db`, 과거 저장 계약의 `pentest-db` 별칭이다. `pentest-db`는 독립 저장소가 아니다.

## 현재 사용하는 저장 계약

[knowledge-db 어댑터](../packages/adapters/integrations/knowledge-db.mjs)는 `receiver: "casper-db"`와 `type: "storage.request"`를 받는다. `operation: "get_attack_info"`에는 공격 정보 또는 `null`과 근거 ID를 `storage.attack_info`로 돌려준다. 이는 과거 사례·카탈로그 조회이며 현재 취약점의 확정 판정이 아니다.

[run-evidence 어댑터](../packages/adapters/integrations/run-evidence.mjs)는 `storage.request`의 `append`와 `finalize`를 받는다. 응답은 각각 `storage.appended`, `storage.finalized`다. 저장 경로 `reports/pentest-db-runs/<run ID의 SHA-256>/`에는 이전 형식의 이벤트·보고서가 남아 있고, `readRun(runId)`으로 다시 읽을 수 있다. 새로운 `vul-web-1` 실행을 시작한다는 뜻은 아니다.

## 과거 단일 검사 응답과 오류

`validateResponseContract()`에는 과거 `attack.result`와 `history.result`의 구조 검증이 남아 있다. 이 타입의 존재는 해당 게시판·검사 경로의 재활성화를 뜻하지 않는다. `invokeJson()`을 사용하는 호출자는 응답의 `runId`, `iteration`, 송신 모듈, `correlationId`가 요청과 일치해야 한다. 전송 실패는 `TRANSPORT_FAILURE`, 잘못된 응답은 `PROTOCOL_FAILURE`의 로컬 `module.error`로 정규화한다. `assertModuleSuccess()`는 외부 모듈 오류와 로컬 gateway 오류의 출처를 구분한다.
