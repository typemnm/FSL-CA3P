# 로컬 펜테스팅 에이전트 MVP

`vul-web-1`을 격리된 임시 데이터 파일과 임의의 `127.0.0.1` 포트로 실행한 뒤, 한 번의 에이전트 반복으로 삭제 권한 우회를 검증합니다. 원본 게시판 데이터는 사용하지 않습니다.

현재 MVP는 범용 취약점 발견기나 LLM 자율 에이전트가 아닙니다. 미리 정의한 CWE-639 playbook 하나를 구조화된 관찰에 적용하는 결정론적 재현기이며, LLM/LangChain 연동은 다음 단계입니다.

## 실행

Node.js 18 이상에서 저장소 루트 `FSL-CA3P`를 기준으로 다음을 실행합니다.

```powershell
cd .\agent
npm test
npm run demo

cd ..\vul-web-1
npm test
```

`npm run demo`는 다음 순서로 동작합니다. 여기서 “1회 루프”는 전체 HTTP 호출이 한 번이라는 뜻이 아니라 `iteration=1`이고 변경 행동인 DELETE가 한 번이라는 뜻입니다. 준비 3회, 반복 내부 3회로 HTTP 요청은 총 6회입니다.

1. 예시 사이트가 OS에서 임의 포트(`PORT=0`)를 직접 할당받고 임시 `BOARD_DATA_FILE`로 시작합니다. 자식 프로세스가 알린 실제 포트에 연결된 일회용 opaque capability가 있어야 orchestrator를 실행할 수 있습니다.
2. Bob 세션으로 식별 가능한 canary 게시글을 준비합니다.
3. Alice 세션으로 게시글과 취약점 지식을 관찰합니다.
4. JSON 의사결정으로 `authorId=bob` 삭제 요청을 한 번 실행합니다.
5. 재조회 결과로 게시글 부재를 확인하고 결과를 `runs/<run-id>/`에 기록합니다.
6. 서버를 종료하고 임시 사이트 데이터를 삭제합니다.

성공 시 `confirmed`, `iterations: 1`, `requestCount: 6`이 출력됩니다. `events.jsonl`과 `report.json`은 재검토를 위해 `runs/<run-id>/`에 남고, 임시 사이트 데이터만 삭제됩니다. 실패 시 종료 코드는 0이 아니며 가능한 경우 실패 보고서도 같은 위치에 기록됩니다. 실패 보고서의 `progress`는 반복 시작, 행동 시도·HTTP 응답 수신, 검증 응답 수신을 각각 기록하므로 DELETE 뒤 검증이 실패해도 실행된 변경을 숨기지 않습니다.

실행 로그에는 쿠키를 저장하지 않습니다. 다만 검증에 사용한 구조화 HTTP 본문과 제한된 응답 excerpt는 기록하므로 실제 비밀정보를 입력해서는 안 됩니다. 웹 응답은 모두 `untrusted_observation`으로 표시되며, 실행기는 정확한 로컬 origin과 허용된 API 경로만 호출할 수 있습니다.

## 모듈 경계

모든 모듈 호출은 프로세스 내부 JSON bus에서 문자열로 직렬화된 envelope를 통해 이루어집니다. 모듈 예외와 잘못된 응답도 `module.error` JSON envelope로 정규화되며 `correlationId`로 원 요청에 연결됩니다. 유효한 envelope 자체를 만들 수 없는 입력은 transport 오류로 거부됩니다.

- `scope_guard`: 정확한 loopback origin, HTTP 메서드, 경로, 요청 예산 검사
- `web_explorer`: 세션별 쿠키를 메모리에만 유지하며 HTTP 관찰/실행
- `vulnerability_db`: 출처가 있는 정적 취약점 playbook 조회
- `rule_reasoner`: 구조화된 관찰을 받아 행동을 결정하고 결과를 반증/검증
- `pentest_db`: 실행 중 JSONL append 방식으로 이벤트를 쓰고 최종 JSON 보고서를 기록(변조 방지 저장소는 아님)
- `orchestrator`: 준비 단계와 `observe → think → act → verify → reflect → stop` 1회 루프 관리

현재 reasoner는 재현 가능한 규칙 기반 어댑터입니다. LLM/LangChain은 동일 JSON 계약 뒤에 추가하되, 모델이 임의 HTTP 요청을 직접 실행하지 못하도록 허용 목록 실행기를 유지합니다.
