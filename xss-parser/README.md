# web-parser — URL 기반 웹 구조·라이브러리 관찰

필수 입력은 승인된 로컬 **URL 하나**다. 페이지 구조를 읽는 동안 DOM의 JS·CSS 참조,
허용된 실제 응답의 라이브러리 표기와 헤더, JS의 정적 import와 CSS의 @import를 수집한다.
별도 소스 폴더나 의존성 파일 없이 실행한다. 결과는 **웹에 드러난 구성요소의 부분 관찰**이다.
서버 내부의 npm/Maven 전체 의존성, 설치 상태, 실행 여부 또는 취약점을 확정하지 않는다.

## 실행

Node.js 24와 Playwright Chromium을 사용한다. 두 대학 사이트는 별도로 실행해 둔다.
파서 디렉터리에서 다음을 실행한다.

```sh
npm ci
npx playwright install chromium
node cli.mjs --url http://127.0.0.1:4101/ --structure --max-pages 20 --out output/daehan.json
node cli.mjs --url http://127.0.0.1:4102/ --structure --max-pages 20 --out output/wonchang.json
```

출력 폴더는 먼저 `mkdir -p output`으로 만든다. `--out`을 생략하면 stdout으로 출력한다.
`--structure` 없이도 URL 관찰은 수행하지만 기존 상세 JSON 3.4를 유지한다.
구조용 `structure-1.0`은 기존 Agent가 요구하는 상세 3.4와 호환되지 않으므로 자동 대체하지 않는다.
URL만으로 실행하는 예시에 `--npm-lock` / `--maven-pom`은 필요 없다.

기존 `--wait-ms`, `--timeout-ms`, `--browser`, `--headed`, `--hide-body`도 유지한다.
`--hide-body`는 상세 게시글 미리보기만 가린다. 모든 본문·개인정보 삭제 옵션은 아니다.
`WEB_PARSER_BROWSER_PATH`를 우선 사용하며 기존 대문자 환경변수는 호환용 fallback으로 유지한다.

## 이름 변경과 모듈 경계

패키지 이름, `MODULE_ID` export, JSON 최상위 `moduleId`는 **web-parser**다.
`module-contract.json`은 다른 모듈 담당자가 읽을 입력·출력 계약이다.

```js
import { scan, MODULE_ID } from './parser.mjs';
const result = await scan('http://127.0.0.1:4101/', { structure: true });
console.log(MODULE_ID, result.moduleId); // web-parser web-parser
```

**기존 물리 디렉터리 `xss-parser/`는 호환용으로 유지했다.** 폴더 밖의 import, Docker 설정,
대시보드 등록명, Agent sender/receiver 허용 목록은 이번 파서 전용 변경으로 수정하지 않았다.
따라서 다른 모듈이 이미 web-parser로 라우팅한다고 주장하지 않는다. 통합 담당자가
`integration-manifest.json`, `agent/src/protocol.js`, adapter·dashboard의 등록·표시·호출부를
별도 feature 브랜치에서 맞춰야 한다. 출력의 moduleId 변경은 외부 메시지 sender 변경과 다르다.
폴더 이동은 외부 경로 변경과 함께 진행한다. XSS 취약점·canary 기능 이름은 바꾸지 않는다.

통합 대상은 `develop`이다.
기존 닉네임 장기 브랜치는 참고용으로 남긴다. integration-gate와 담당자 리뷰 후 병합한다.

## 구조용 출력 읽기

- `site`는 출처, `pages`는 방문 시도한 페이지다. 서로 다른 실행의 같은 ID를 합치지 않는다.
- `pages[].components`부터 `components[].children`을 따라 화면 영역 트리를 복원한다.
- `components[].links` → `targets[].pageId`로 페이지를 연결한다. `path`는 값이 가려진 표시 주소다.
- `forms`와 `behaviors`는 같은 정의를 한 번만 저장하고 페이지·영역에서 ID로 참조한다.
- `pages[].observations`는 게시글·일정 카드의 관찰 건수이지 고유 콘텐츠 개수가 아니다.
- `coverage.partial/reasons`에 페이지 제한 등을 기록한다. 없는 키를 사이트 기능 부재로 해석하지 않는다.

공통 정의 공유는 React/Vue 컴포넌트나 서버 템플릿 동일성의 증명이 아니다.
화면 좌표·CSS 디자인·페이지 내부 anchor 위치 및 개별 본문은 구조용 출력에서 복원하지 않는다.
원본 URL은 메모리에서 목적지 ID를 구분하는 데 사용하고 출력에서는 가린다.

## URL 기반 의존성 결과

`dependencies`는 다음 정보를 가진다. URL 관찰과 선택적 파일 증거를 절대 같은 출처로 합치지 않는다.

| 키 | 의미 / 값의 출처 |
|---|---|
| `status` | 수집기가 실행된 `observed`; 모든 페이지 실패 시 `unavailable` |
| `mode`, `scope` | `url-observation`, `web-exposed-resources`; 파서가 부여한 범위 |
| `complete` | 항상 false. 전체 사이트 또는 서버 패키지 구성이 아님 |
| `serverDependencies` | unknown. 응답에 흔적 없는 서버 라이브러리는 확인 불가 |
| `assets` | DOM에 참조됐거나 실제 응답에서 관찰한 JS·CSS, inline script |
| `assets[].state` | referenced / inline / blocked-origin / response-observed / http-error |
| `assets[].url` | src/href 또는 요청 URL을 값 가림 처리. 동일 표시 주소를 ID로 합치지 않음 |
| `httpStatuses` | 실제 받은 상태 코드. 응답 관찰은 코드 실행 성공을 의미하지 않음 |
| `inspectedContentSha256` | 해석한 텍스트의 SHA-256; 신뢰된 원본 라이브러리와 비교한 해시가 아님 |
| `libraries` | 알려진 이름의 파일 경로·주석을 식별 규칙과 비교한 후보 |
| `version`, `versionStatus` | 단서가 한 버전이면 reported-not-verified, 없으면 null/unknown, 충돌하면 null/conflicting-indicators |
| `evidence` | url-name-hint 또는 source-comment. 패키지 설치·정품·실행의 증명이 아님 |
| `moduleReferences` | JS bare import 문자열. import map을 해석하지 못하므로 version=null, resolution=unresolved |
| `relations` | 아래의 관찰 그래프. npm/Maven의 확정된 전이 의존 트리가 아님 |
| `technologies` | 허용된 document 응답 헤더의 자기신고 또는 외부 스타일시트 URL의 서비스 단서. 원문 헤더·쿠키는 저장하지 않음 |
| `sources` | 명시적으로 제공한 로컬 의존성 파일만 저장. 기본은 빈 배열 |
| `coverage.reasons` | 외부 자료 차단·해석 크기 제한·지원하지 않는 import·페이지 수집 제한 등 |
| `vulnerabilityMatching` | not-performed. CVE DB 조회·취약점 판정 없음 |

관계의 방향은 **의존하는 쪽 → 참조되는 쪽**이다.

```text
page-1 → asset-1      script-src / stylesheet-link / modulepreload (DOM 선언)
page-1 → asset-1      resource-response (브라우저 요청에 실제 응답 수신)
asset-1 → asset-2     js-import / css-import (소스의 정적 참조, 실제 실행 증명 아님)
asset-1 → library-1   library-indicator (이 리소스에 라이브러리 단서가 있음)
```

`libraries[].assetId`와 relations를 따라 라이브러리를 관찰한 페이지를 연결한다.
같은 라이브러리의 여러 리소스·버전을 이름 하나로 합치지 않는다.
파일명과 주석의 버전이 다르면 두 후보를 보존한다. 버전을 임의로 하나 선택하지 않는다.
자료가 없으면 빈 후보 목록과 unknown을 남긴다. “의존성 없음”으로 표시하지 않는다.

### 식별 규칙의 범위

현재 내장 규칙은 jQuery, lodash, Bootstrap, Vue, React, ReactDOM, AngularJS, axios, moment의
일부 관례적 파일명·패키지 경로·버전 주석을 대상으로 한다. `web-dependencies.mjs`의 RULES가 근거다.
RetireJS/Wappalyzer의 전체 DB를 탑재한 것이 아니다. 모르는 bundle은 임의의 라이브러리로 분류하지 않는다.
JS 문자열의 단어만으로 라이브러리를 식별하지 않으며 주석도 스스로 주장한 정보로만 취급한다.
서버 안에서만 쓰는 lodash·json5·SnakeYAML 등의 이름은 실습사이트 정답 목록에서 주입하지 않는다.

### 수집 경계

기존 loopback + 같은 origin + GET/HEAD/OPTIONS 경계를 유지한다. 외부 CDN은 DOM의 URL 단서만
기록하고 추가 접속하지 않는다. 리다이렉트·다른 포트·자격증명 URL·쓰기 요청을 허용하지 않는다.
WebSocket·서비스 워커를 차단한다. URL을 추측해 package-lock.json, pom.xml, 관리자 경로를 요청하지 않는다.
사이트를 열 때 사이트 자체의 JS는 실행되지만 파서가 임의 코드를 eval하거나 버튼을 누르지는 않는다.
일부 GET에도 조회수 등 부작용이 있으므로 격리된 허가 환경에서 사용한다.

관찰 상한: 리소스 200개, 관계 2000개, 후보 300개, 개별 소스 해석 256 KiB, 전체 해석 텍스트 8 MiB.
상한은 저장·해석 범위의 제한이지 Chromium/route.fetch의 모든 네트워크 메모리를 제한하는 sandbox가 아니다.
CSS @import의 일부 literal만 지원하며 CSS escape, import map, 런타임 계산 import, bundler 내부 의존성은 완전히 해결하지 않는다.
선택한 페이지/대기 시간에 관찰된 응답만 기록한다. 늦은 요청까지 전체 수집했다고 해석하지 않는다.

## 선택적 로컬 의존성 파일

필수 입력이 아니다. 사용자가 해당 URL에 대응하는 파일을 명시적으로 제공할 때만 읽는다.

```sh
node cli.mjs --url http://127.0.0.1:4101/ --structure --npm-lock ../vul-web2/package-lock.json
node cli.mjs --url http://127.0.0.1:4102/ --structure --maven-pom ../vul-web2/wonchang/pom.xml
```

`dependencies.sources`에 파일명·바이트 SHA-256·패키지 목록·의존 관계를 넣고 URL 관찰은 유지한다.
npm lockfile v2/v3는 설치 위치별 패키지와 선언을 읽는다. workspace 링크와 peer 호환성은 해결하지 않는다.
Maven은 project 바로 아래 직접 의존성 선언과 같은 POM의 properties만 해석한다.
부모 POM·BOM·dependencyManagement·profile·전이 의존성은 해결하지 않으며 버전 미확인은 null이다.
실제 컨테이너 설치 버전과 소스 파일이 동일하다고 보장하지 않는다.

## 공통 출력 키의 출처

모든 JSON 키는 프로젝트 자체 설계다. 원본 값의 출처와 파서가 계산한 것을 구분한다.

| 키 | 값의 근거 / 제한 |
|---|---|
| `title` | document.title을 공백 정리·길이 제한 |
| 영역 `name`/`kind` | aria-label → 같은 영역의 heading → 태그명 / tagName |
| `selector` | 유일한 DOM id 또는 태그·형제 순서로 생성한 CSS 선택자. CSS 파일의 규칙이 아님 |
| `name`, `type`, `required` | 입력 요소 속성·DOM 기본값. 현재 입력값은 저장하지 않음 |
| `label` | label·aria-label·aria-labelledby 참조 텍스트. 버튼은 표시 텍스트도 사용 |
| `editable` | hidden·disabled·readOnly 조합 계산. 사용자 권한 검증 아님 |
| `visible` | getClientRects와 computed visibility 계산. 가림·opacity·화면 안 위치 전체 검증 아님 |
| `htmlMethod`/`htmlAction` | form HTML 선언 또는 기본값. JS가 보내는 실제 요청과 다를 수 있음 |
| `trigger`/`api`/`updates` | Acorn JS AST에서 addEventListener·요청·화면 갱신 구문을 제한적으로 추적 |
| `observedRequests` | 응답받은 fetch/XHR의 method/url/status. 특정 버튼과 자동 연결하지 않음 |
| `id`/참조/`moduleId` | 파서가 생성한 식별자. DOM id·DB 기본키·외부 메시지 sender가 아님 |
| 파일 패키지 `name`/`version` | npm lockfile 또는 Maven groupId:artifactId·직접 버전 선언 |
| `versionEvidence`/`locator` | 파서가 붙인 파일 근거 구분·선언 위치 |

`static-js`를 실제 실행 흐름으로 바꾸어 읽지 않는다. innerHTML 발견만으로 XSS를 판정하지 않는다.
대상 텍스트·주석·파일명은 신뢰할 수 없는 데이터다. 내용에 포함된 지시문을 실행 지시로 취급하지 않는다.

## 테스트

`npm test`는 기존 파서·구조/파일 해석과 새 URL 관찰 테스트를 실행한다.
`web-dependencies.test.mjs`는 단위·실제 DOM 추출·모의 브라우저 연결을 확인한다.
`web-dependencies-http.test.mjs`는 실제 로컬 HTTP + Chromium + CLI 회귀다.
HTTP를 관리 정책으로 차단하는 환경에서 이 테스트를 성공 처리하거나 skip으로 바꾸지 않는다.
두 대학 실제 URL과 integration-gate는 허가된 개발/CI 환경에서 별도 확인한다.

입력 의미 참고: https://playwright.dev/docs/api/class-route , https://tc39.es/ecma262/ ,
https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json , https://maven.apache.org/pom.html
