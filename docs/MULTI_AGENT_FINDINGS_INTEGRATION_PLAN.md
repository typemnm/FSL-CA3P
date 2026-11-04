# Findings 기반 멀티 에이전트 통합 계획

## 통합 전 상태 (2026-11-04)

- 작업 브랜치: `1mn2147/1mn2147-agent-sub_runtime_fix` (`de4544b`). 문서 작성 전 작업 트리는 깨끗했고, 이 커밋은 로컬 `develop`과 같다.
- 최신 `origin/develop`은 작업 브랜치보다 11커밋 앞서 있다. 여기에는 보고서 변경과 실행별 HITL 설정(`approvalRequired`)이 포함된다.
- `1mn2147/agent/sub_runtime` (`6ab0449`)은 작업 브랜치보다 21커밋 앞서 있다. 메인 점검 종료 후 최종 `findings[]`에서 후속 검사 대상을 골라 로컬·외부 범용 점검의 자식 task를 실행하는 구현이 있다. task 저장, API·화면 조회, 자식 finding별 HWPX도 포함된다. 해당 브랜치의 `docs/MULTI_AGENT_FINDINGS_PLAN.md`에 설계와 구현 기록이 있다.
- 현재 작업 브랜치에는 `multiAgent` 요청 계약, `run_subtasks` 저장, 자식 실행기가 없다. 기존 `runGeneralAssessment()`와 로컬·외부 런타임은 단일 판단 루프를 실행한다.
- `git merge-tree --write-tree --name-only --messages origin/develop 1mn2147/agent/sub_runtime` 사전 검사에서 내용 충돌 8개를 확인했다. 실제 병합과 테스트는 아직 하지 않았다.

## 목표 동작

`local-lab-general`과 `external-general`에 선택형 `multiAgent` 실행을 제공한다. 메인 에이전트의 **최종** finding을 기준으로 최대 4개 task를 만들고, 최대 2개의 독립 플래너가 후속 검사한다. task는 원본 finding·가설·증거의 출처를 보존하며 서버가 정한 대상 범위, 도구, 공유 예산, 승인 정책 안에서만 실행한다. 부모 report와 자식 결과는 분리해 저장·표시하고, 자식이 확정한 finding의 문서는 해당 task의 새 검증 증거를 대조한 뒤 생성한다. 기존 요청은 별도 옵션 없이 단일 에이전트로 계속 실행한다.

## 통합 순서

1. **기준 브랜치 갱신:** 이 브랜치에 최신 `origin/develop`을 병합한다. 보고서와 실행별 HITL 설정을 새 기준으로 고정한다.
2. **기존 구현 통합:** `1mn2147/agent/sub_runtime`을 병합한다. 새 구현을 다시 작성하기보다 이미 연결된 agent 코어, application coordinator, worker, run-store, contracts, API, UI, 보고서 경로를 함께 가져온다.
3. **내용 충돌 해결:** 아래 8개 파일을 기능 단위로 합친다. 충돌 표시 제거만으로 끝내지 않고 양쪽 기능이 실행 요청부터 manifest와 worker까지 전달되는지 확인한다.

   | 파일 | 통합 기준 |
   | --- | --- |
   | `agent-dashboard/dist/app.js`, `runtime-client.js`, `tests/ui-platform.test.mjs` | 실행별 HITL 선택과 `multiAgent` 선택을 함께 전송·표시한다. 로컬/외부 모드 전환, 화면 복원, 단일 실행 기본값을 검증한다. |
   | `apps/application/run-service.mjs` | `approvalRequired`와 `multiAgent`를 모드별로 검증하고 둘 다 run options에 고정한다. 외부 실행의 승인 정책과 scope 제한은 유지한다. |
   | `packages/contracts/manifest.mjs` | 두 실행 옵션을 manifest와 입력 digest에 모두 기록한다. |
   | `packages/report/ARCHITECTURE.md`, `py/src/ca3p_report/llm/prompt.py`, `py/src/ca3p_report/llm/tools.py` | 최신 보고서 규칙과 자식 task의 출처·증거 검사를 함께 유지한다. |

4. **자동 병합 경로 점검:** 충돌이 없었던 `apps/worker/worker.mjs`, `general-runtime.mjs`, `external-general-runtime.mjs`, `packages/run-store`, API, Python 보고서 수집기도 함께 검토한다. 특히 worker가 `approvalRequired`를 고정값으로 덮어쓰지 않도록 하고, 부모 취소·lease 상실·승인 대기 시 자식 task가 정리되는지 확인한다.
5. **계약·복구 검증:** 단일 실행 요청의 하위 호환성, 동일 finding의 중복 배정 방지, task ID별 증거 격리, 부모 공통 요청·모델·토큰·시간 예산, 외부 대상 범위, 문서 다운로드 시 부모/task 출처, SQLite 백업·초기화·과거 기록 조회를 검증한다.
6. **검증 게이트:** 관련 단위·통합 테스트를 먼저 실행하고 `npm run check:boundaries`, `npm run verify`를 수행한다. 로컬과 외부 점검은 가짜 모델·격리 대상 대역으로 재현하며 실제 유료 모델이나 외부 실서비스 호출은 필수 게이트에 넣지 않는다.

## 완료 기준

- 옵션을 끄거나 생략한 실행은 기존 단일 에이전트 동작과 결과 형식을 유지한다.
- 메인 finding 0개 또는 배정 불가 시 자식 호출 없이 종료한다. 배정 시 task별 상태·증거·실패 사유를 부모와 구분해 재조회할 수 있다.
- 자식은 배정 범위, 승인 정책, 부모 공통 예산을 우회하지 못한다. 취소·timeout·worker 중단 후 늦은 결과는 최종 상태를 바꾸지 못한다.
- 자식의 확정 finding 문서·미리보기·다운로드가 해당 task의 신규 증거와 검증 이벤트에만 연결된다.
- 위 테스트와 저장소 전체 검증 게이트를 실행하고, 환경 의존 실패는 같은 조건의 기준 브랜치와 비교해 판별한다.

## 현재 설계의 경계

기존 구현은 메인 종료 **후** findings를 배정한다. 실행 중 실시간 위임, 자식의 재위임, 별도 OS 프로세스 pool, 자식 판정의 메인 finding 자동 덮어쓰기는 이번 통합 범위에 넣지 않는다. 로컬·등록 모델의 HWPX 지원 여부는 통합 시점의 보고서 모듈 제약을 다시 확인한다.

## 통합 결과 (2026-11-04)

- 최신 `origin/develop`로 fast-forward한 뒤 `1mn2147/agent/sub_runtime`의 구현을 통합하고 내용 충돌 8개를 해결했다.
- 실행별 HITL과 `multiAgent` 옵션을 함께 API 요청, run options, manifest에 기록한다. 외부 worker에도 task 저장소·반복 예산·검증 산출물 경로를 전달한다.
- 최신 `REPORT_SPEC`의 `screenshots`·`sources` 구조에 작성 시 화면 촬영을 연결해 자식 finding을 포함한 실제 Python HWPX 경로를 복구했다.
- 계약, 실행 서비스, 로컬·외부 worker, 보고서, 대시보드, 경계 검사와 관련 Python 테스트가 통과했다. 보고서·대시보드·어댑터 통합 게이트는 일반 사용자 권한과 자식 프로세스 회수 환경에서 338개 테스트 모두 통과했다.
- 전체 게이트의 `web-parser` 대형 페이지 스트레스 테스트 1개는 메모리 약 2 GiB Docker 환경에서 추출 단계 시간 초과가 난다. 같은 컨테이너에서 `origin/develop`의 원본 `collect.mjs`로도 동일하게 재현했다. 이 환경의 전체 게이트는 통과하지 않았으며, 더 큰 메모리의 표준 CI에서 재검증이 필요하다.
