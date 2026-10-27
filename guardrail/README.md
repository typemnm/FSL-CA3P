# CA3P Guardrail Evaluator

`fsl-ca3p-guardrail-ruleset.json`을 실행하는 Node.js 평가기입니다. 패키지 자체에는 외부 npm 의존성이 없습니다. 로컬 Agent Loop에서는 `agent-dashboard/integrations/guardrail.mjs`가 이 평가기를 실제 `attack-module` 전송 경계에 연결합니다.

## 구성

- `rules/`: Notion 최종본과 동일한 ruleset
- `src/ruleset-loader.js`: JSON 로딩 및 fail-closed 구조 검증
- `src/normalizer.js`: percent·HTML entity·Unicode 정규화와 XSS 분류
- `src/condition-evaluator.js`: ruleset의 operator 실행
- `src/guardrail.js`: hard deny, 프로필, canary, budget을 종합해 ALLOW/DENY 반환
- `test/guardrail.test.js`: 권한 우회, 관리자 보호, XSS, 퍼저 격리, 오류 처리 회귀 테스트

## 실행

```powershell
cd guardrail
npm test
```

## 사용

```js
const path = require('node:path');
const { GuardrailEvaluator, loadRuleset } = require('./src');

const ruleset = loadRuleset(path.join(__dirname, 'rules/fsl-ca3p-guardrail-ruleset.json'));
const guardrail = new GuardrailEvaluator(ruleset);
const result = guardrail.evaluate({ stage, action, trustedContext });

if (result.decision !== 'ALLOW') {
  throw new Error(`Guardrail denied [${result.ruleId}]: ${result.reason}`);
}
```

`trustedContext`는 LLM 응답에서 가져오면 안 됩니다. Orchestrator 또는 Gateway가 검증한 세션, run ID, canary, network policy와 budget으로 구성해야 합니다.

## Agent Loop 연결

로컬 실습에서는 gateway가 `attack-module`에 전달할 구조화된 curl JSON을 canonical HTTP action으로 변환하고 `GuardrailEvaluator.evaluate()`를 호출합니다. `ALLOW`이면 실제 curl을 한 번 실행하고, `DENY`이면 전송하지 않습니다. 판정의 `decision`, `ruleId`, `stage` 등이 `attack.result.payload.guardrail`에 담기므로 Agent와 대시보드에서 확인할 수 있습니다. 공격자 세션 GET도 canonical 읽기 action으로 평가합니다.

실행마다 저장소의 규칙을 복제해 임시 게시판의 정확한 `127.0.0.1` 포트에 바인딩합니다. `agent_cross_user_delete_canary` 프로필은 현재 한 번의 로컬 Alice/Bob canary 검사에만 사용됩니다. canary ID와 소유자, run ID, 요청 예산은 gateway가 검증한 값으로 구성하며 모델 출력에서 받지 않습니다.

이 패키지는 정책 평가만 수행합니다. HTTP 요청, 브라우저 실행, 쿠키 처리와 사이트 수정은 담당하지 않습니다.
