# CA3P Guardrail Evaluator

`fsl-ca3p-guardrail-ruleset.json`을 실행하는 Node.js 18+ 평가기입니다. 원본 `FSL-CA3P` 저장소를 수정하지 않은 독립 패키지이며 외부 패키지를 사용하지 않습니다.

## 구성

- `rules/`: Notion 최종본과 동일한 ruleset
- `src/ruleset-loader.js`: JSON 로딩 및 fail-closed 구조 검증
- `src/normalizer.js`: percent·HTML entity·Unicode 정규화와 XSS 분류
- `src/condition-evaluator.js`: ruleset의 operator 실행
- `src/guardrail.js`: hard deny, 프로필, canary, budget을 종합해 ALLOW/DENY 반환
- `test/guardrail.test.js`: 권한 우회, 관리자 보호, XSS, 퍼저 격리, 오류 처리 회귀 테스트

## 실행

```powershell
cd guardrail-evaluator
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

## Agent 연결 위치

기존 `loop_agent`의 `ActionPolicy`는 유지하고 Web Explorer gateway 호출 직전에 추가합니다.

```js
actionPolicy.authorize(stage, action);
const result = guardrail.evaluate({ stage, action, trustedContext });
if (result.decision !== 'ALLOW') throw new Error(result.reason);
await gateway.exchange(serializedRequest);
```

이 패키지는 정책 평가만 수행하며 HTTP 요청, 브라우저 실행, 쿠키 처리 또는 사이트 수정을 하지 않습니다.
