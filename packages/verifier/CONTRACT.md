# AI verifier 계약

verifier는 공격 모듈이 실행한 공격 한 건이 실제로 먹혔는지 AI 모델이 판정하게 하는 경계다. 코드에는 유형별 규칙, 허용 kind 목록, 결정적 판정 규칙이 없다. 모델이 `valid` / `invalid` / `unknown`을 정하고, 코드는 입력을 검증하고 증거를 모아 status로 옮긴다.
## 1. 입력: AttackRecord (`attack-record/1`)

`executeCurlRecorded`(`packages/adapters/attack-recorder.mjs`)가 만든다.

| 필드 | 내용 |
|---|---|
| `schemaVersion` | 고정값 `attack-record/1` |
| `id` | `^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$` |
| `kind` | 자유 라벨, 최대 64자. 생략하면 `unspecified`. 판정 분기에 쓰지 않는다 |
| `target.origin` | loopback http(s) origin만 허용 |
| `info` | 공격 모듈이 받은 작업 정보(객체). 예: `session`, `victim`, `canary` |
| `request` | `method`, `url`(origin 일치 필수), `headers`(cookie는 `[redacted]`), `body` |
| `response` | `status`, `bodyText`, `bodyJson`, `error`, `elapsedMs` |
| `control`, `followUp` | 선택. 같은 request/response 형태의 추가 교환 |

형식이 틀리면 모델을 호출하기 전에 `INVALID_ATTACK_RECORD`로 거부한다. 쿠키 값은 어떤 프롬프트·증거·결과에도 들어가지 않는다.

## 2. 모델 프로토콜 (두 라운드)

system prompt는 `VERIFIER_SYSTEM_PROMPT`(`index.mjs`)다.

**Round 1** 입력: `{ round: 1, attack: { kind, info, request, response } }`

응답 `{ verdict, reason, browser? }`:
- `valid` 또는 `invalid`: 끝. `method: 'ai'`.
- `unknown` + `browser`: 브라우저 관찰 후 Round 2로 간다. `method: 'ai+browser'`.
- `unknown`만: 끝. `status: 'inconclusive'`.

`browser` 요청은 `{ path, role?, waitFor? }`다. `path`는 `/`로 시작하고 `//`이 아니어야 하는 같은 origin 경로다. `role`은 세션 쿠키 묶음의 키이고, `waitFor`는 CSS 선택자다.

**Round 2** 입력: `{ round: 2, attack, browserRequest, browserObservation }`. 응답은 `valid` 또는 `invalid`다. `unknown`이면 `inconclusive`다.

`reason`은 최대 1024바이트로 자른다. 모델 호출 실패, JSON 형식 오류, 허용되지 않은 verdict는 `verdict: null`이 되어 `inconclusive`로 끝난다.

## 3. 브라우저 관찰 (`browserObservation`)

샌드박스 Chromium을 매번 새로 띄운다. 대상 origin의 GET/HEAD만 허용하고 WebSocket, 서비스 워커, 다운로드는 막는다. 팝업은 닫고 dialog는 해제한다.

| 필드 | 내용 |
|---|---|
| `finalUrl`, `title` | 최종 URL, 제목(200자 이내) |
| `text` | `body` innerText, 4096바이트 이내 |
| `dialogs`, `console` | 각각 최대 10개, 20개 |
| `pageErrors` | 최대 10개 메시지 |
| `bindingCalls` | `{ value, mainFrame }`. 페이지가 probe를 부른 기록 |
| `blocked` | `{ method, url, reason }`, 최대 32개 |

관찰이 실패하면 `{ error: <code> }`만 모델에 전달한다. 스크린샷은 `images/viewport-*.png`로 저장하고 sha256과 바이트 수를 기록한다.

## 4. 출력: `verifier/1`

| 필드 | 내용 |
|---|---|
| `schemaVersion` | `verifier/1` |
| `attackId`, `kind` | 입력 기록의 id와 kind |
| `verdict` | `valid` / `invalid` / `unknown` / `null` |
| `status` | 아래 표 |
| `reason`, `method` | 모델 사유, `ai` 또는 `ai+browser` |
| `evidence` | 최대 2개. `attack-exchange`(경로, status, body 다이제스트)와 `ai-verdict`(verdict, reason, 관찰 배열 길이). 각 summary 2048바이트 이내 |
| `artifacts` | 스크린샷 목록 `{ id, kind, label, file, sha256, bytes }` |
| `browser` | `{ request, observation }` 또는 `null` |
| `model`, `verifiedAt` | 모델 호출 메타데이터 배열, 판정 시각 |

**status 매핑**

| verdict | status |
|---|---|
| `valid` | `confirmed` |
| `invalid` | `not_reproduced` |
| `unknown`, `null` | `inconclusive` |

## 5. 보고서 핸드오프 (`verification-handoff/1`)

`writeReportHandoff(result, { outDir })`는 `outDir/verification.json`을 쓴다. 내용은 `{ schemaVersion, result, images: [{ file, sha256, bytes, label }] }`다.

- 이미지는 `outDir/images/` 안에만 둔다. 쓸 때와 읽을 때 sha256과 바이트 수를 다시 확인하고, 어긋나면 `HANDOFF_INTEGRITY`다.
- 보고서 쪽 읽기 함수는 `packages/report/py/src/ca3p_report/collect/verification.py`의 `load_verification_handoff`, `copy_handoff_images`다.

## 6. 연결 구조

모두 같은 worker 프로세스 안의 함수 호출이다. 별도 HTTP API는 없다.

| 단계 | 함수 | 입력 → 출력 |
|---|---|---|
| 공격 기록 | `executeCurlRecorded(command, { allowedOrigin, cookie, signal }, info)` (`packages/adapters/attack-recorder.mjs`) | attack-module `executeCurl` 명령 → `{ result, record: AttackRecord }` |
| 판정 | `verifyAttack(record, { outDir, sessions, signal, timeoutMs, model })` | AttackRecord → `verifier/1` |
| 전달 | `writeReportHandoff(result, { outDir })` | `verifier/1` → `outDir/verification.json`, `outDir/images/` |
| 보고서 읽기 | `load_verification_handoff(dir)`, `copy_handoff_images(handoff, bundle_dir)` | handoff 디렉터리 → 검증된 dict, 번들 `evidence/images/` |

아직 연결되지 않은 곳(후속 PR):
1. **attack 쪽**: 범용 점검 실행기 `apps/application/general-runtime.mjs`는 요청을 대부분 `fetchImpl`로 직접 보낸다. attack-module은 IDOR 읽기(`executeUniversityRead`)에서만 쓴다. 할 일은 두 가지다.
   - 공격 요청을 `executeCurlRecorded`로 보내고, 실행 결과에 `attackRecord`를 실어 보낸다.
   - 같은 파일의 `verifier` 포트에서 `verifyAttack`을 부르고 결과를 `{ status, completed, evidenceIds, reason }`로 바꾼다.

   코어는 판정이 그 probe의 증거 id를 참조해야 받아 준다(`agent/src/general-assessment.js`의 `UNSUPPORTED_VERDICT`). verifier 포트는 새 증거를 추가할 수 없으므로 스크린샷은 handoff 디렉터리 `<store 디렉터리>/verifications/<sha256(runId)>/<probeId>/`에 둔다.
2. **보고서 쪽**: worker(`apps/worker/worker.mjs`)가 confirmed finding마다 `generateReportDocument`를 부를 때 해당 probe의 handoff 디렉터리를 넘긴다. 이를 위해 다음을 추가한다.
   - trigger에 `sources.verification: { kind: 'handoff-dir', location }`를 넣는다(`trigger.py`의 `sources` 키).
   - collector가 위 두 함수로 handoff를 번들에 넣는다.
   - `general_model.py`의 빈 `images: []`를 `{ step, caption, ref: 'evidence/images/<file>', integrity: 'ok' }`로 채운다. HWPX writer는 이 형식을 이미 받는다.
3. `apps/api`에는 새 경로가 필요 없다. 결과 열람은 기존 실행 JSON과 HWPX 다운로드로 충분하다.
