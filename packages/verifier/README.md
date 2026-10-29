# packages/verifier

공격 모듈이 실행한 공격이 **실제로 먹혔는지** 판정하는 것이 이 패키지의 한 가지 일이다. verifier는 공격하지 않는다. 주어진 공격 정보와 attack 모듈의 수행 결과만 보고 AI 모델이 판정하고, 추가 확인이 필요하면 Playwright로 페이지를 읽기만 한다. 코드는 입력을 검증하고, 증거를 모으고, 결과를 status로 옮길 뿐이다. 유형별 규칙은 없다.

## 흐름
1. 공격 모듈 실행 → `executeCurlRecorded`(`packages/adapters/attack-recorder.mjs`)가 AttackRecord를 만든다.
2. `verifyAttack(record, { outDir, sessions, model })`가 라운드 1을 보낸다. 모델이 브라우저 확인을 요청하면 샌드박스 Chromium으로 페이지를 관찰하고(쓰기 요청은 차단), 라운드 2를 보낸다.
3. `writeReportHandoff(result, { outDir })`가 `verification.json`과 `images/`를 쓴다.
4. 보고서는 `readReportHandoff(outDir)`로 해시를 다시 확인하고 읽는다.

파일: `index.mjs`(`verifyAttack`, 시스템 프롬프트), `browser.mjs`(`observe`), `contract.mjs`(입력 검증, 증거), `report-handoff.mjs`.

입출력 상세와 status 매핑은 [CONTRACT.md](./CONTRACT.md)를 본다.

## 테스트
저장소 루트에서 실행한다. API 키는 필요 없다.

```sh
PATH=/opt/homebrew/opt/node@24/bin:$PATH TMPDIR=/private/tmp/ca3p-verifier-tmp \
  node --test --test-force-exit packages/verifier/tests/*.test.mjs packages/adapters/tests/attack-recorder.test.mjs
PATH=/opt/homebrew/opt/node@24/bin:$PATH node scripts/check-boundaries.mjs
```

- `tests/e2e.test.mjs`는 실제 vul-web-1 보드(`startLocalLab`, 취약/안전 모드)와 Chromium을 쓰고, 스크립트 모델로 판정한다.
- Chromium이 없으면 `packages/verifier`에서 `npx playwright install chromium`을 실행한다.
- 실제 모델 테스트는 `CA3P_VERIFIER_LIVE=1`일 때만 등록된다(키는 `DEEPSEEK_API_KEY` 환경 변수나 저장소 루트 `.env`). CI가 skip 0개와 live 모델 호출 금지를 요구하기 때문이다.

## 모델 지정
- 기본값은 DeepSeek다. 키는 `DEEPSEEK_API_KEY`로 주고, 모델명은 `CA3P_VERIFIER_MODEL`로 주며 기본값은 `deepseek-flash`다.
- 직접 주입할 수도 있다. `verifyAttack(record, { model })`의 `model`은 `completeJson({ systemPrompt, userPayload, signal })`를 가지고 `{ value, metadata }`를 돌려주면 된다. 테스트는 이 방식으로 스크립트 모델을 넣는다.

## 현재 한계
- 범용 점검은 실행된 모든 probe를 이 verifier로 판정하고, 가설마다 가장 최근의 AI 판정이 결과다. 모델은 항상 유효 또는 무효로 답하며, 판정이 없는 경우는 모델 호출 실패뿐이다. verifier와 범용 점검은 실습 대상(vul-web-1, vul-web2)에 의존하지 않는다.
- 보고서는 worker가 넘긴 handoff에서 판정 사유와 스크린샷을 HWPX에 싣는다. 연결 흐름은 [CONTRACT.md](./CONTRACT.md) 6절에 있다.
- 브라우저 방문은 최대 2번이다.
