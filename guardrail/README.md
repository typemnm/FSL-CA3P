# CA3P Guardrail Evaluator

이 모듈은 신뢰된 대상 범위와 요청 예산을 검사한다. 현재 대학 IDOR 검사는 [vul-web2/scripts/idor-probe.mjs](../vul-web2/scripts/idor-probe.mjs)의 `createIdorRuleset()`이 대상별 규칙을 만들고 `GuardrailEvaluator`가 요청 직전에 평가한다. [guardrail/src/attack-tool.js](src/attack-tool.js)는 attack-tool의 제한된 GET 패킷을 검사한다. 삭제된 `vul-web-1` 전용 규칙 파일과 로컬 gateway는 신규 실행에 사용하지 않는다.

## 구성

- `src/guardrail.js`: 구조화된 규칙의 ALLOW/DENY 평가
- `src/ruleset-loader.js`: 규칙 객체의 fail-closed 검증
- `src/normalizer.js`: 입력 정규화와 XSS 분류
- `src/attack-tool.js`: 지정된 원점·경로·GET 방식과 요청 예산을 적용하는 attack-tool 전송 경계
- `test/attack-tool.test.js`: 범위·예산·응답 크기 회귀 검증

## 검증

```sh
npm --prefix guardrail test
```

호출자는 대상 원점과 허용 경로를 신뢰된 설정에서 전달한다. 모델 응답으로 이 값을 정하지 않는다. 이 모듈은 검사 정책을 제공하고, 대학 IDOR 요청은 `vul-web2`가 `attack-module`로 전송한다.
