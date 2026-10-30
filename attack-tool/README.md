# attack-tool

여러 AI가 구조화된 요청을 보내고, 가드레일을 거친 실행 결과를 받는 Node.js daemon이다. `web-parser`와 동일하게 독립 `.mjs` API, CLI, 계약 문서, native Node 테스트로 구성한다.

```text
casper-db snapshot → Agent → attack-tool HTTP JSON-RPC → Guardrail → target
                      ↑          실행 결과·증거·검증 결과 ←────────┘
```

`templates/`의 기본 패킷 템플릿과 Workspace에서 등록한 JSON 템플릿을 함께 사용한다. 공격 유형/CWE와 runtime/framework/library로 검색한다. `origin`은 서버가 고정하며 AI는 템플릿 ID와 후보 payload만 보낸다. baseline과 공격 패킷 모두 `guardrail` 모듈의 검사를 통과해야 한다. 문자열을 shell에서 실행하지 않는다.

## 기본 점검 템플릿

모든 기본 템플릿의 신뢰 상태는 `unverified`다. 등록 과정에서는 실제 대상 요청이나 결과 검증을 수행하지 않는다. 일반 평가 Agent에는 전체 카탈로그가 참고 자료로 전달되며, 전용 자동 실행 도구는 지원 형식과 서버의 대상별 정책을 모두 충족하는 템플릿만 실행한다.

| ID | 의존성 / 점검 내용 | 전용 자동 실행 |
| --- | --- | --- |
| `sqli-like-tautology` | 기존 `node:sqlite` SQLi 후보 | GET `q` + `resultCount` 지원 |
| `search-sqli-template` | 사용자 제공 검색 SQLi | GET `q` + `resultCount` 지원 |
| `access-control-idor-template` | 담당자 간 접수 상세의 객체 인가 비교 | 참고용: 담당자 세션, 경로 ID 치환, 응답 소유자 비교 필요 |
| `json5-inherited-filter-template` | JSON5 반환 객체의 상속 검색 필터 | 참고용: `filters` 입력과 결과 배열의 길이·유형 비교 필요 |
| `lodash-prototype-canary-template` | lodash 설정 경로의 프로토타입 canary | 참고용: 관리자 POST, 동일 프로세스의 속성 관찰·정리 필요 |
| `commons-text-interpolation-template` | Commons Text 보간 입력 도달 경로 | 참고용: 관리자 POST, 저장된 설정값·lookup 정책 확인 필요 |
| `snakeyaml-type-tag-template` | SnakeYAML Java 타입 태그 수용 | 참고용: 관리자 POST와 YAML 미리보기 비교 필요 |

`access-control-idor-template`는 동일하게 제공된 네 건을 한 건으로 정리했다. 저장 계약에 맞춰 `target.endpoint`와 `request.packet.path`를 `/api/admissions/partner/applications/:id`로 통일하고, `integer`/`ids` 선언을 ID 문자열 `payloads: ["1", "3"]`로 표현했다. HTTP 상태 코드는 숫자로 저장한다. 실제 대한대학교 API는 `daehan_sid` 세션 쿠키와 `partner` 역할을 요구하므로 원문의 관리자 Bearer 헤더는 실행 패킷에 저장하지 않았다. `partner1`의 본인 접수 1과 다른 담당자 소유 접수 3을 같은 세션으로 비교하며, `partner_user_id` 확인이 필요하다. 관리자 200 응답만으로 객체 인가 결함을 판정하지 않는다.

외부 의존성 템플릿의 근거와 관찰 범위는 다음과 같다. 대상 버전과 호출 경로는 `vul-web2/package.json`, `vul-web2/wonchang/pom.xml` 및 해당 서버 구현을 기준으로 정했다.

- JSON5 2.2.1: [개발자 권고 CVE-2022-46175](https://github.com/json5/json5/security/advisories/GHSA-9c47-m6qq-7p4h). 상속된 `type`·`limit`가 결과에 적용되는지 비교한다. 전역 `Object.prototype` 오염으로 판정하지 않는다.
- lodash 4.17.15: [프로젝트 변경 이력](https://github.com/lodash/lodash/wiki/Changelog)과 [CVE-2020-8203 권고](https://github.com/advisories/GHSA-p6mc-m468-83gw). 임시 인스턴스에서 프로토타입 canary를 직접 관찰하고 삭제한다. HTTP 302는 판정 근거로 충분하지 않다.
- Commons Text 1.9: [Apache 보안 권고](https://commons.apache.org/proper/commons-text/security.html)와 [공식 lookup API](https://commons.apache.org/proper/commons-text/javadocs/api-release/org/apache/commons/text/lookup/StringLookupFactory.html). 부작용이 없는 `base64Decoder` 보간으로 입력 도달 경로를 확인한다. 보간 자체는 수정 버전에서도 제공되므로 CVE나 코드 실행 확정에는 버전·lookup 정책의 추가 근거가 필요하다.
- SnakeYAML 1.33: [Google Security Research 권고 CVE-2022-1471](https://github.com/google/security-research/security/advisories/GHSA-mjmj-j48q-9wg2). `java.util.ArrayList` 태그와 짧은 문자열로 타입 태그 수용 여부를 확인한다. 코드 실행이나 외부 연결은 시험하지 않는다.

각 참고용 템플릿의 `description`과 `blanks.payload.desc`에 필요한 세션, 기준 입력, 판정 근거를 기록했다. 카탈로그 등록·조회는 실제 취약성 재현을 의미하지 않으며, 미지원 형식은 `executionSupport.supported: false`와 이유를 반환한다.

## Workspace 템플릿 관리

대시보드의 **Workspace → 템플릿**에서 목록·상세·JSON 원문을 확인하고, JSON 단건 또는 배열을 붙여 넣거나 파일로 가져온다. 관리자는 등록·수정·삭제할 수 있다. 수정과 삭제는 조회한 revision을 전송하므로 다른 사람이 먼저 바꾼 내용을 덮어쓰지 않는다. 기본 템플릿도 수정하거나 삭제할 수 있으며 변경 내용은 로컬 카탈로그에 저장된다.

등록 파일은 기본 `.runtime/attack-templates.json`이고 `CA3P_ATTACK_TEMPLATES_PATH`로 변경한다. 기본 JSON 파일은 `attack-tool/templates/`에서 읽고, 로컬 수정본과 삭제 기록을 그 위에 적용한다. 별도의 실행 중 daemon은 시작 시 카탈로그를 복사하므로 편집 내용은 다음 daemon 또는 다음 평가부터 적용된다.

대시보드와 같은 인증을 사용하는 관리 API는 다음과 같다. 쓰기에는 관리자 권한이 필요하다.

| 요청 | 내용 |
| --- | --- |
| `GET /api/attack-templates` | `attackType`, `runtime`, `framework`, `library`, `q` 필터로 목록 조회. `templates`, `total`, `executionSupport`, `revisions` 반환 |
| `GET /api/attack-templates/:id` | 템플릿과 `executionSupport`, `revision` 조회 |
| `POST /api/attack-templates` | JSON 객체, 배열 또는 `{ "templates": [...], "dryRun": true }` 일괄 검사·등록 |
| `PUT /api/attack-templates/:id` | `{ "template": {...}, "expectedRevision": "조회한 revision" }`으로 수정 |
| `DELETE /api/attack-templates/:id` | `{ "expectedRevision": "조회한 revision" }`으로 삭제 |

일괄 가져오기는 전체를 검증한 다음 저장한다. 같은 ID와 같은 내용은 변경하지 않고, 같은 ID에 다른 내용을 가져오면 충돌을 반환한다. 기존 내용 변경은 수정 API를 사용한다. `dryRun`은 저장 없이 등록 결과를 확인한다. 템플릿 하나의 직렬화한 JSON은 64KiB 이하이고, 한 번에 최대 100개를 가져올 수 있다. 로컬 카탈로그는 최대 1000개·4MiB를 지원한다.

여러 템플릿은 다음처럼 JSON 배열로 전달한다. 각 템플릿의 `templateId`는 고유해야 한다.

```json
[
  {
    "templateId": "search-baseline-a",
    "attackType": { "name": "sql_injection", "cwe": "CWE-89" },
    "dependency": { "runtime": "node", "framework": "express", "library": "node:sqlite" },
    "target": { "method": "GET", "endpoint": "/api/search" },
    "request": { "packet": { "method": "GET", "path": "/api/search", "query": { "q": "{{payload}}" } } },
    "blanks": {
      "origin": { "required": true, "type": "url", "desc": "Trusted server-side target origin" },
      "payload": { "required": true, "type": "string", "pickFrom": "payloads" }
    },
    "payloads": ["' OR '1'='1"],
    "verify": { "mode": "resultCount", "baseline": { "q": "zzqnomatch", "expect": 0 }, "attack": { "expectMin": 1 } },
    "executor": "guardrail", "trust": "unverified"
  },
  {
    "templateId": "search-baseline-b",
    "attackType": { "name": "sql_injection", "cwe": "CWE-89" },
    "dependency": { "runtime": "node", "framework": "express", "library": "node:sqlite" },
    "target": { "method": "GET", "endpoint": "/api/search" },
    "request": { "packet": { "method": "GET", "path": "/api/search", "query": { "q": "{{payload}}" } } },
    "blanks": {
      "origin": { "required": true, "type": "url", "desc": "Trusted server-side target origin" },
      "payload": { "required": true, "type": "string", "pickFrom": "payloads" }
    },
    "payloads": ["' OR 1=1--"],
    "verify": { "mode": "resultCount", "baseline": { "q": "another-nomatch", "expect": 0 }, "attack": { "expectMin": 2 } },
    "executor": "guardrail", "trust": "unverified"
  }
]
```

현재 실행기는 GET 패킷, `q` 하나의 query 입력, `resultCount` 검증을 지원한다. 그 밖의 템플릿은 목록과 상세에서 참고용으로 확인하며 실행 도구에는 포함하지 않는다. 지원되는 템플릿도 서버에 설정한 origin·허용 경로·예산을 통과해야 실행된다. JSON을 등록한다고 허용 경로가 추가되지는 않는다.

## 독립 실행

Node.js 24에서 private 설정 파일을 만든다. 각 token은 별도로 생성한 32바이트 이상의 난수로 교체한다. 파일은 Git에 추가하지 않는다.

```json
{
  "host": "127.0.0.1",
  "ports": [4241, 4242],
  "templateCatalogPath": ".runtime/attack-templates.json",
  "agents": [
    { "agentId": "sql-agent-a", "runId": "assessment-a", "portIndex": 0,
      "token": "REPLACE_WITH_A_PRIVATE_RANDOM_TOKEN_A",
      "targetOrigin": "http://127.0.0.1:4101", "maxRequests": 16,
      "allowedPaths": ["/api/search"] },
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

`templateCatalogPath`는 Workspace와 같은 로컬 카탈로그를 지정한다. 각 agent의 `allowedPaths`는 운영자가 정하는 실행 범위이며 기본값은 `["/api/search"]`다. 템플릿의 `target.endpoint`나 `request.packet.path`에서 실행 범위를 자동 생성하지 않는다.

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

`list_attack_templates`는 `{templates,total,nextOffset}`을 반환한다. `limit`은 기본 25개, 최대 100개이며 `offset`은 기본 0이다. 응답의 128KiB 제한을 지키도록 실제 페이지는 요청한 개수보다 작아질 수 있다. 전체 목록이 필요하면 `nextOffset`이 `null`이 될 때까지 그 값을 다음 호출의 `offset`으로 전달한다. 실행 도구의 스키마는 카탈로그 크기에 관계없이 일정한 크기이며, 서버가 선택한 ID와 payload의 조합을 확인한다.

## 대시보드 연결

`packages/adapters/integrations/attack-tool.mjs`가 평가마다 두 임시 포트를 열고 취약점별 인증 client를 만든다. 일반 분석의 DB snapshot 정보는 기존 observation으로 모델에 전달된다. 모델이 제안한 probe는 `execute_probe`로 daemon에 들어가 서버에 고정된 정책을 다시 통과한 후 실행되며, 기존 evidence/verifier 계약으로 반환된다. 실행 보고서의 `attackTool`에 포트·worker ID·템플릿 ID·통신 횟수가 기록된다.

이 client들은 취약점별 논리적 실행 워커다. 첫 버전의 모델 계획 루프는 기존 일반 평가 루프를 사용한다. 기존 게시판에는 `/api/search`가 없으므로 SQLi 템플릿은 그 평가에서 참고 자료로 제공되며 실행 권한은 부여되지 않는다. 독립 daemon에서 해당 endpoint를 가진 승인된 대상에 연결하면 템플릿을 실행할 수 있다.

자세한 전송·오류·취소 계약은 [CONTRACT.md](CONTRACT.md), 구조 및 통합 계획은 [ATTACK_TOOL_PLAN.md](../docs/ATTACK_TOOL_PLAN.md)를 참조한다.
