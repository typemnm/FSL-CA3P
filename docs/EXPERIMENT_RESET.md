# 모델 변경 시 실험 초기화

조사 기준: `develop`의 `86e1f54` 이후 구현. 목적은 이전 실행의 관찰·게시물·세션·사례 체크가 다음 모델의 입력과 결과에 섞이지 않게 하는 것이다. 이 기능은 관리하는 실험 상태를 삭제한다. 디스크 포렌식 수준의 보안 삭제나 외부 제공자 기록 삭제를 의미하지 않는다.

## 사용 흐름

1. 모델 선택 아래 **모델 변경 시 초기화 확인**을 켠다. 기본값은 켜짐이며 브라우저 설정에 보존된다.
2. 다른 모델을 선택하면 **전체 실험 흔적을 제거할까요?** 확인창이 열린다. 실행·보고서 작성 중에는 모델을 바꿀 수 없다.
3. **예**는 초기화 API를 호출한다. 모든 단계가 성공한 뒤 새 모델을 선택한다. **아니오**는 기존 상태를 유지하며 모델을 바꾼다. Escape는 변경을 취소한다.
4. 토글을 끄면 확인창 없이 모델을 바꾼다. 초기화하지 않은 변경에는 이전 흔적이 남을 수 있음을 표시한다.
5. 수동 **실험 초기화** 버튼으로도 같은 확인창을 열 수 있다. 일부 단계 실패 시 다음 실행을 막고 이 버튼으로 재시도한다.

**예를 누르면 이전 실행 이력·비교 자료·JSON/HWPX가 삭제된다. 비교에 사용할 결과는 먼저 내보내야 한다.** 내보낸 파일은 이 기능의 삭제 대상에 포함되지 않는다. 초기화 후 기존 두 run을 대시보드 내부에서 다시 비교할 수는 없다.

## 영향 범위 조사와 처리

| 범위 | 남는 상태와 영향 | 초기화 처리 / 보존 경계 |
| --- | --- | --- |
| 실행 registry | `.runtime/runs.sqlite` 또는 `CA3P_STORE_PATH`: runs/jobs/events/action intents/model calls/review audit/artifact index. 이전 이력·비교·모델 출력이 다시 표시됨 | 모든 실험 행 삭제, SQLite secure_delete·VACUUM·WAL checkpoint. 삭제 완료 여부와 epoch만 보존 |
| 실행 파일 | registry 옆 `artifacts/<run hash>`, `reports/<run hash>`, `case-snapshots/<run hash>.sqlite` 및 WAL/SHM | 알려진 run의 소유 경로만 삭제. 인증 파일과 다른 디렉터리는 보존. 연결 파일·경계 이상은 중단 |
| pentest-db | `reports/pentest-db-runs/<run hash>`의 events/report 파일, 서버 시작 시 legacy 자동 가져오기 | 알려진 실행 파일 삭제. 첫 초기화 이후 자동 legacy 재가져오기 비활성화로 이력 부활 방지 |
| CASPER DB | `packages/history/check-sync.mjs`가 원본 DB에 실험 check를 기록. 사람이 검토하면 다음 snapshot과 과거 사례 매칭에 영향을 줄 수 있음 | 삭제 대상 run ID에 연결된 draft/reviewed check만 삭제. curated cases·case_versions와 무관한 check는 보존. 저장 당시와 다른 DB 설정이면 중단 |
| `vul-web-1` | canary 게시글·삭제/수정·랜덤 쿠키·세션·메모리 | 매 run 새 임시 게시판/secret/process. worker 종료를 기다린 후 닫음. 신규 실행은 소유권 registry+토큰으로 crash 잔류를 추적하고, IPC 단절 시 게시판 종료 |
| `vul-web2` | 대한/원창 SQLite volume, 게시물·조회수·요청·일정·설정·서버 세션, 프로세스와 파일 상태 | 로그인 probe는 finally 로그아웃. 전체 초기화는 운영자가 등록한 관리 훅이 DB·세션·프로세스·파일 복원을 확인해야 함. 미설정·실패 시 전체 초기화 차단 |
| 외부 URL 읽기 관찰 | 등록된 `external-general` 경로는 비인증 GET/HEAD로 공개 페이지만 관찰 | 앱 소유 실행 기록·파일은 삭제한다. 대상 복원 훅은 요구하지 않으며 외부 사이트의 로그·조회 기록은 복원하지 않는다. 다른 미등록 외부 실행은 계속 차단 |
| parser/관찰 브라우저 | 쿠키·local/session storage·IndexedDB·서비스워커·HTTP cache | `xss-parser/parser.mjs`와 보고서 capture는 새 browser/context를 만들고 finally close; 서비스워커 차단. 영구 사용자 profile 재사용 없음 |
| attack/guardrail/agent | gateway 쿠키, request budget, canary ID, 모델 messages/응답 | 실행별 closure/engine/child runtime 생성. 초기화 전 worker의 종료 확인으로 이전 메모리 제거 |
| 대시보드 브라우저 | 앱 소유 localStorage fallback 이력, 상세·비교·검토 초안·진행 중 조회/SSE | 앱 실행 cache만 비우고 epoch로 늦은 응답을 거부. 같은 브라우저 탭은 storage event, 연결된 다른 브라우저는 SSE epoch로 폐기. 인증·사용자 설정 보존 |
| 기준 입력 | 소스·ruleset·pentest catalog·검토된 사례·API 자격 증명 | 삭제하지 않음. 같은 조건을 재현할 연구 기준값이며 각 manifest에 digest 기록 |

연결이 끊긴 다른 브라우저의 로컬 파일·메모리를 서버에서 강제로 삭제할 수는 없다. 재접속 시 서버 epoch를 확인해 해당 앱 캐시를 폐기한다. 서로 다른 PC의 결과 내보내기는 사용자 소유다.

## 구현 순서와 실패 처리

`GET /api/experiment-reset`은 삭제 범위·개수·현재 초기화 상태를 조회한다. `POST /api/experiment-reset`은 정확히 `{ "confirmed": true }`를 요구한다. 기존 인증·운영자 권한·CSRF·배포 중 mutation 차단을 적용한다. 기존 `/api/reset`은 화면 초기화로 유지한다.

실행 목록만 정리할 때는 운영자/관리자 인증과 CSRF 토큰으로 `POST /api/run-history/clear`에 정확히 `{ "confirmed": true }`를 보낸다. 이 경로는 실행 registry의 이력·비교 자료, 실행별 JSON/HWPX·snapshot·보고서 파일, 해당 run에 연결된 CASPER check를 삭제하고 epoch를 올려 대시보드 캐시와 legacy 재가져오기를 차단한다. 계정·API 설정·검토된 사례와 대학 실습 대상의 상태는 보존한다. 대학 대상의 복원 의무는 별도 DB 기록으로 남으므로, 관리 훅이 필요한 경우 또는 이전 전체 초기화가 실패한 경우 새 실행은 계속 차단된다. 등록된 외부 URL 읽기 관찰은 대상 복원 의무를 만들지 않는다. 이후 `POST /api/experiment-reset`은 남은 의무를 확인하고 전체 대상 복원을 마쳐야 실행을 다시 허용한다.

이전 버전에서 출처 정보 없이 저장된 외부 대상 복원 의무는 읽기 전용 실행인지 확인할 수 없으므로 자동 면제하지 않는다. 원본 실행 기록이 남아 있는 실패 상태는 새 코드로 전체 초기화를 재시도할 수 있다.

1. 영구 maintenance 상태를 잠근다. 어떤 실행이든 queued/leased/running이면 409로 거부한다. 다른 reset과 CASPER 검토 쓰기도 상호 배제한다.
2. idle worker가 실제로 종료될 때까지 기다려 보고서 촬영·게시판 정리와의 경쟁을 없앤다.
3. 전체 run과 삭제 경로, DB identity, 소유권, 대상 관리 훅 설정을 사전 검증한다.
4. 관리 대상 복원 → CASPER 실험 check 삭제 → run 소유 파일 삭제 → registry 행 삭제 순서로 처리한다.
5. 모든 처리가 성공하면 epoch를 증가시키고 초기 상태를 SSE로 보낸 뒤 worker를 새로 시작한다.

여러 DB·HTTP 대상·파일시스템에 걸친 원자적 transaction은 없다. 따라서 중간 실패는 성공으로 표시하지 않는다. 영구 failed 상태로 신규 실행을 차단하며 같은 정리를 재시도한다. 프로세스 중단 후에도 다음 서버에서 이 상태를 확인한다. 파괴적 API에는 사용자가 지정한 경로·URL을 받지 않는다.

## 대학 실습 관리 훅

대학 실습의 현재 경로는 고정 IDOR 읽기 검증이며 AI 모델을 호출하지 않는다. 실제 대학 서버에 기본으로 공개되는 파괴적 reset endpoint는 추가하지 않았다. 복원 권한이 있는 운영 서비스가 필요한 경우 서버 환경에 등록한다.

```json
{
  "vul-web2-daehan": {
    "origin": "http://127.0.0.1:54101",
    "targetOrigin": "http://127.0.0.1:4101",
    "token": "replace-with-at-least-32-random-characters"
  }
}
```

위 JSON을 `CA3P_EXPERIMENT_RESET_TARGETS`에 설정한다. 관리 origin은 실험의 target URL과 별개다. `targetOrigin`은 저장된 실행의 실제 대상 origin과 일치해야 하며, 같은 fixture로 서로 다른 서버를 검사했다면 초기화를 차단한다. HTTP는 등록된 로컬/사설 주소 규칙을 따르고 HTTPS 관리 origin도 가능하다. 관리 서비스는 인증된 `POST /_ca3p/experiment-reset`을 처리하고, 요청의 `targetOrigin`에 해당하는 fixture의 기준 데이터·세션·프로세스·파일까지 복원한 후 다음을 반환해야 한다. redirect·대상 불일치·누락된 scope는 실패다. `process`는 단순 DB seed만 한 상태에서 선언하면 안 된다.

```json
{ "status": "clean", "fixtureId": "vul-web2-daehan", "targetOrigin": "http://127.0.0.1:4101", "scopes": ["database", "sessions", "process", "files"] }
```

대학을 접촉한 이력이 있는데 훅이 없으면 초기화를 완료할 수 없다. dashboard 컨테이너에 Docker socket을 노출하거나 임의 서버에 삭제 요청을 보내는 우회는 하지 않는다. 대학 전체 복원 서비스 배포는 운영 환경에 맞춰 별도로 준비해야 한다.

### 로컬 대한대 실습 실행

직접 실행하는 대한대 실습(`http://127.0.0.1:4101`)에는 별도의 로컬 관리 프로세스를 사용할 수 있다. 기존 4101·4174 서버를 중지하고 실험 기록과 `vul-web2/data/daehan.sqlite`를 백업한 뒤 다음 명령으로 시작한다.

```sh
npm run start:managed-daehan -- --retry-reset
```

이 명령은 127.0.0.1:54101에만 바인딩되는 관리 서비스를 시작하고, 4101의 대한대 프로세스를 관리하며, 일회성 비밀 토큰과 `CA3P_EXPERIMENT_RESET_TARGETS`를 대시보드 프로세스 환경에 전달한다. `--retry-reset`은 실패한 전체 초기화를 다시 실행한 뒤 4174 대시보드를 시작한다. 초기화가 완료되면 기존 실행 기록과 보고서, 대한대 실습 DB 및 세션 상태가 새 기준 상태로 바뀐다. 이후 일반 시작에는 `npm run start:managed-daehan`을 사용한다. 이 경로는 로컬 직접 실행 전용이며 Docker volume이나 다른 호스트의 대학 서버를 복원한다고 주장하지 않는다.

## 연구 해석과 범위의 한계

현재 모델 registry는 규칙 엔진과 DeepSeek Flash/V4 Pro를 제공한다. **규칙 엔진은 로컬 LLM이 아니다.** Ollama/vLLM 등 실제 로컬 LLM adapter·모델 unload/KV cache 제어는 아직 제공하지 않는다. 이 기능만으로 로컬 LLM 대 API 비교가 완성됐다고 해석하면 안 된다.

API 제공자 보관 기록·prompt caching·계정 rate limit·모델 가중치, OS page cache·GPU/CPU 온도·동시 부하·DNS/TLS cache·프록시/컨테이너/배포 로그, 이 기능 도입 전에 소유권 없이 남은 tmp, 수동 대상 브라우저 상태, 백업·다운로드는 자동 삭제를 보장하지 않는다. 새 lab은 고유 디렉터리를 사용해 미등록 tmp를 입력으로 재사용하지 않는다. 속도 비교에는 cold/warm 정책·동일 시간대의 부하·랜덤 순서·반복 횟수도 통제해야 한다.

규칙 검사도 완료 후 HWPX 보고서는 설정된 별도 API 모델을 호출할 수 있다. 검사 모델의 비용·시간과 보고서 비용·시간을 분리해 해석한다. run manifest의 source/module/prompt/catalog/case/fixture digest와 `experiment`의 epoch·lastResetAt·previousRunCount를 함께 기록한다. 초기화 없는 변경을 동일 조건의 새 실험으로 단정하지 않는다.

실험 결과를 사람이 새 기준 사례·사례 버전·카탈로그로 승격한 변경은 자동으로 되돌리지 않는다. 비교 기간에는 이 기준을 고정해야 한다. 사례 snapshot의 비교 해시는 사례와 연결된 check 모두를 포함하므로 체크만 달라져도 입력 차이를 기록한다.

## 검증 계획

- 실제 저장소 대역을 심은 임시 디렉터리에서 전체 초기화, 설정·기준 사례·다른 파일 보존, 재시작 후 이력 부활 방지를 확인한다.
- queued/leased/보고서 생성 중 거부, 동시 reset/검토·late SSE/poll 경쟁, 실패 후 신규 실행 차단과 재시도를 검증한다.
- CASPER의 run 연결 check만 지우고 구형/다른 DB·연결 경로를 거부하는지 확인한다.
- 브라우저에서 토글 ON/OFF, 예/아니오/Escape, API 실패, 여러 탭의 epoch 폐기와 localStorage 설정 보존을 검증한다.
- 실제 isolated board와 worker 급사 대역으로 process 종료·소유권 temp 회수를 확인하고, 미등록 대학·위조 관리 응답을 거부한다.
- 전체 기존 CI suite로 모듈 경계·인증·브라우저 실습·보고서 회귀를 확인한다. 테스트는 임시 대역만 초기화하며 사용자 운영 데이터는 지우지 않는다.
