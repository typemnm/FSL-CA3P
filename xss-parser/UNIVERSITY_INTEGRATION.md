# 대학 사이트 파서 통합 (읽기 전용)

`develop`의 `vul-web2` 대학 2곳을 대상으로 브라우저 구조 파싱과 직접 의존성 CVE 카탈로그 매칭을 수행합니다.

## 실행

```sh
cd vul-web2
docker compose up --build -d
cd ../xss-parser
npm ci
npx playwright install chromium
node university-cli.mjs daehan --out daehan.json
node university-cli.mjs wonchang --out wonchang.json
npm test
```

- 대한대학교: `http://127.0.0.1:4101/` (Express / Nunjucks)
- 원창대학교: `http://127.0.0.1:4102/` (Spring Boot / Thymeleaf)
- JSON: `{ site, origin, report, dependencies }`. `report`는 기존 스키마 3.4를 그대로 유지합니다.
- `dependencies`는 직접 의존성의 버전만 확인합니다. 의존성 선언에서 해결되지 않은 Maven 상위 BOM 버전은 `unresolved`에 기록합니다.
- 카탈로그는 `vul-web2`의 선정된 CVE 6건만 포함합니다. 전체 npm/Maven 전이 의존성 취약점 검사와 실제 취약점 재현은 **수행하지 않습니다**.
- 페이지 로드는 기존 파서와 동일하게 동일 출처·GET/HEAD/OPTIONS로 제한됩니다. 서비스 코드의 GET 부작용(예: 게시글 조회수)은 있을 수 있으므로 복제한 로컬 실습 환경에서 실행하세요.
- 인증을 위한 POST 로그인, 폼 제출, 탐지 공격은 수행하지 않습니다. 로그인 뒤의 페이지는 수집 범위에 포함하지 않습니다.

## Agent JSON 연동

`packages/adapters/integrations/university-parser.mjs`의 `createUniversityParserGateway()`를 사용합니다. 기존 `startLocalLab()`의 고정 XSS/BOLA 루프는 변경하지 않습니다. 호출 측은 `agent/src/protocol.js`의 `createEnvelope` + `invokeJson`을 사용합니다.

```js
import protocol from '../agent/src/protocol.js';
import { createUniversityParserGateway } from '../packages/adapters/integrations/university-parser.mjs';
const { createEnvelope, invokeJson } = protocol;
const origin = 'http://127.0.0.1:4101';
const request = createEnvelope({
  runId: 'lab-university-read', iteration: 0,
  sender: 'agent', receiver: 'xss-parser', type: 'module.request',
  payload: { operation: 'parse_site', site: 'daehan', origin, phase: 'before' },
  policyContext: { targetMode: 'isolated_local_lab', targetOrigin: origin },
});
const response = await invokeJson(createUniversityParserGateway(), request);
console.log(response.payload.dependencies);
```

실제 Agent 실행기의 시나리오 등록/대시보드 노출은 별도 작업입니다. 이 변경은 호출 가능한 어댑터와 프로토콜 검증을 제공하지만 **현재 기본 에이전트 루프가 자동으로 두 대학을 스캔한다고 주장하지 않습니다**.

## 구현 한계 / 추후 작업

- `maxPages=20`: 같은 출처 공개 페이지의 링크를 방문하지만 로그인 뒤 컨텐츠는 탐색하지 않습니다.
- `posts[]`는 기존의 `article` 기반 추출이라 새 대학 사이트의 `.board-row` 카드는 구조화된 게시글 목록으로 변환되지 않습니다. 링크/영역으로만 수집됩니다.
- 순수 CVE 데이터베이스 전체를 받아오는 SCA 스캐너가 아니라 프로젝트 내 6건의 잠긴 카탈로그 비교입니다.
- `node --test xss-parser/test/university.test.mjs` 포함한 CI 검증이 필요합니다. 실제 Docker가 구동되는지와 브라우저 실제 실행까지는 PR CI 결과로 확인해야 합니다.
