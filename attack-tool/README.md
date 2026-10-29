# attack-tool

여러 AI가 구조화된 요청을 보내고, 가드레일을 거친 실행 결과를 받는 Node.js daemon이다. `web-parser`와 동일하게 독립 `.mjs` API, CLI, 계약 문서, native Node 테스트로 구성한다.

```text
casper-db snapshot → Agent → attack-tool HTTP JSON-RPC → Guardrail → target
                      ↑          실행 결과·증거·검증 결과 ←────────┘
```

첫 버전에는 `sqli-like-tautology` 패킷 템플릿 하나만 있다. 공격 유형/CWE와 runtime/framework/library로 검색한다. `origin`은 서버가 고정하며 AI는 템플릿 ID와 후보 payload만 보낸다. baseline과 공격 패킷 모두 `guardrail` 모듈의 검사를 통과해야 한다. 문자열을 shell에서 실행하지 않는다.

## 독립 실행

Node.js 24에서 private 설정 파일을 만든다. 각 token은 별도로 생성한 32바이트 이상의 난수로 교체한다. 파일은 Git에 추가하지 않는다.

```json
{
  "host": "127.0.0.1",
  "ports": [4241, 4242],
  "agents": [
    { "agentId": "sql-agent-a", "runId": "assessment-a", "portIndex": 0,
      "token": "REPLACE_WITH_A_PRIVATE_RANDOM_TOKEN_A",
      "targetOrigin": "http://127.0.0.1:4101", "maxRequests": 16 },
    { "agentId": "sql-agent-b", "runId": "assessment-b", "portIndex": 1,
      "token": "REPLACE_WITH_A_PRIVATE_RANDOM_TOKEN_B",
      "targetOrigin": "http://127.0.0.1:4101", "maxRequests": 16 }
  ]
}
```

```sh
node attack-tool/cli.mjs --config attack-tool/config.json
node --test attack-tool/test/*.test.mjs
```

CLI는 SIGINT/SIGTERM 때 요청을 취소하고 포트를 닫는다. 다른 머신의 AI가 접근할 때는 서버 설정의 bind 주소와 포트를 명시하고 TLS를 제공하는 사설 프록시를 통해 연결한다. 기본 loopback 설정은 같은 머신의 여러 AI 프로세스가 사용할 수 있다.

## AI 연결

```js
import { createAttackToolClient } from './client.mjs';

const client = createAttackToolClient({
  endpoint: 'http://127.0.0.1:4241',
  token: process.env.ATTACK_TOOL_TOKEN,
  agentId: 'sql-agent-a', runId: 'assessment-a',
});
await client.initialize();
const capabilities = await client.listTools();
const { templates } = await client.call('list_attack_templates', {
  attackType: 'CWE-89', runtime: 'node',
});
const result = await client.call('execute_attack_template', {
  templateId: templates[0].templateId, payload: templates[0].payloads[0],
});
```

`capabilities.tools`의 설명과 `inputSchema`를 모델에게 제공하고, 모델의 도구 호출 JSON을 `client.call`로 전달하면 된다. 이 프로토콜은 이 프로젝트의 JSON-RPC 계약이며 MCP 서버 호환성을 주장하지 않는다.

## 대시보드 연결

`packages/adapters/integrations/attack-tool.mjs`가 평가마다 두 임시 포트를 열고 취약점별 인증 client를 만든다. 일반 분석의 DB snapshot 정보는 기존 observation으로 모델에 전달된다. 모델이 제안한 probe는 `execute_probe`로 daemon에 들어가 서버에 고정된 정책을 다시 통과한 후 실행되며, 기존 evidence/verifier 계약으로 반환된다. 실행 보고서의 `attackTool`에 포트·worker ID·템플릿 ID·통신 횟수가 기록된다.

이 client들은 취약점별 논리적 실행 워커다. 첫 버전의 모델 계획 루프는 기존 일반 평가 루프를 사용한다. 기존 게시판에는 `/api/search`가 없으므로 SQLi 템플릿은 그 평가에서 참고 자료로 제공되며 실행 권한은 부여되지 않는다. 독립 daemon에서 해당 endpoint를 가진 승인된 대상에 연결하면 템플릿을 실행할 수 있다.

자세한 전송·오류·취소 계약은 [CONTRACT.md](CONTRACT.md), 구조 및 통합 계획은 [ATTACK_TOOL_PLAN.md](../docs/ATTACK_TOOL_PLAN.md)를 참조한다.
