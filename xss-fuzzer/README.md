# HTML·JS → JSON XSS 퍼저

HTML·JavaScript를 받아 실제 Chromium에서 페이로드를 실행하고 결과를 JSON으로 출력합니다. 같은 저장소의 `vul-web-1` 게시판을 위한 API 모사 프로필을 포함합니다.

## 설치 및 실행

Node.js 20 이상이 필요합니다. 포크 저장소의 루트에서 다음처럼 실행하세요:

```sh
cd xss-fuzzer
npm install
node cli.mjs --html ../vul-web-1/public/index.html --js ../vul-web-1/public/app.js --profile fsl-ca3p --out practice.json
```

macOS에 Chrome이 있으면 자동으로 사용합니다. Chrome이나 Chromium이 없다면 `npx playwright install chromium`을 먼저 실행하세요. 다른 브라우저 실행 파일은 `--browser /absolute/path/to/chrome` 또는 `XSS_BROWSER_PATH`로 지정합니다. 브라우저는 새 임시 프로필로 실행됩니다.

JSON 입력도 지원합니다:

```sh
node cli.mjs --input examples/request.json --out practice.json
cat examples/request.json | node cli.mjs
npm test
```

`--out`을 생략하면 표준 출력에 JSON만 출력합니다. 실패하면 JSON 오류 객체와 종료 코드 1을 반환합니다. 결과 파일은 실행 후 생성됩니다. 예시의 `practice.json`은 Git에 포함되지 않습니다.

## 명령어 옵션

`node cli.mjs` 뒤에 쓰는 `--...`는 JavaScript 코드가 직접 읽는 명령어 옵션입니다. `--html` 방식, `--input` 방식, 표준 입력(JSON) 방식 중 하나로 입력을 전달합니다.

| 옵션 | 필요 여부 | 하는 일 |
| --- | --- | --- |
| `--html FILE` | 파일 입력 방식에서 필수 | 검사할 HTML 파일을 읽습니다. |
| `--js FILE` | 외부 JS가 있을 때 필요 | 검사할 JS 파일을 읽습니다. 여러 개면 반복해서 적습니다. HTML에 인라인 JS만 있으면 생략할 수 있습니다. |
| `--input FILE` | JSON 파일 방식에서 필수 | `html`, `js` 등을 담은 JSON 파일을 읽습니다. `--html` 방식 대신 사용합니다. |
| `--profile generic\|fsl-ca3p` | 선택 | API 모사 방식입니다. 기본값은 `generic`이고, 이 게시판 예제에서는 `fsl-ca3p`를 씁니다. |
| `--out FILE` | 선택 | 결과 JSON을 파일에 저장합니다. 생략하면 터미널에 출력합니다. 같은 이름의 파일은 덮어씁니다. |
| `--max-cases N` | 선택 | 최대 시험 수(1~500). 기본값은 150입니다. |
| `--settle-ms N` | 선택 | 화면 반응을 기다리는 시간(20~5000ms). 기본값은 200ms입니다. |
| `--browser FILE` | 선택 | 사용할 브라우저 실행 파일 경로를 직접 지정합니다. |
| `--help` | 선택 | 사용법만 보여줍니다. |

예를 들어 위 실행 명령에서 `--html`과 `--js`는 입력 파일이고, `--profile`과 `--out`은 선택 설정입니다.

## JSON 입력

```json
{
  "html": "<form><input id=q><button>Go</button></form><div id=out></div>",
  "js": "document.querySelector('form').onsubmit=e=>{e.preventDefault();document.querySelector('#out').innerHTML=document.querySelector('#q').value}",
  "profile": "generic",
  "queryParams": ["q"],
  "maxCases": 150,
  "settleMs": 200,
  "timeoutMs": 3000
}
```

JSON 파일에서는 `html`과 `js`가 필수 필드입니다. `html`은 문자열이고 `js`는 문자열 또는 `[{"path":"/app.js","code":"..."}]`입니다. 여러 파일은 `--js`를 반복하거나 JSON 배열로 전달합니다. JSON 배열의 `path`는 HTML의 스크립트 URL 경로와 맞춰야 합니다. HTML이 해당 JS를 참조하지 않으면 자동으로 추가합니다. JS 문자열의 기본 경로는 `/app.js`입니다.

아래 JSON 필드는 모두 선택 설정입니다. 적지 않으면 기본값을 사용합니다.

- `profile`: `generic` 기본값 또는 `fsl-ca3p`.
- `queryParams`: 시험할 쿼리 키. 기본값은 `q`, `search`, `name`, `content`; 빈 배열로 쿼리 시험을 생략할 수 있습니다. 해시는 별도로 시험합니다.
- `maxCases`: 최대 시험 수(1~500), 기본값 150. 초과 시 `summary.truncated`가 true입니다.
- `settleMs`: 페이지 로드·입력·재로드 이후 대기 시간(20~5000ms). 비동기 앱에서는 늘리세요.
- `timeoutMs`: 개별 브라우저 작업 제한(100~30000ms). 전체 실행 시간 제한은 아닙니다.
- `fixtures`: 모사 API 응답. 예: `[{"path":"/api/data","method":"GET","body":{"html":"{{PAYLOAD}}"}}]`. `{{PAYLOAD}}`를 현재 페이로드로 치환합니다. 실제 API는 호출하지 않습니다.
- `actions`: 각 시험에서 추가할 동작. 예: `[{"type":"fill","selector":"#q","value":"{{PAYLOAD}}"},{"type":"click","selector":"#go"}]`. `submit`은 폼 또는 폼에 속한 입력 요소를 선택합니다. actions에 `{{PAYLOAD}}`를 쓰면 자동 시험 대상과 함께 추가 입력에도 같은 페이로드가 들어가므로 결과 해석 시 확인하세요.

## 동작과 결과 해석

1. Acorn으로 외부·인라인 JS의 `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` 등의 위험 구문 후보를 수집합니다. 문자열·주석의 단순 키워드에는 반응하지 않습니다.
2. HTML의 수정 가능한 텍스트 입력과 textarea를 찾아 한 필드씩 시험합니다. 같은 폼의 나머지 필드는 정상 값으로 채우고 `requestSubmit()`을 호출합니다. URL 쿼리·해시·지정 API 응답도 시험합니다.
3. HTML 태그, 속성/문자열 탈출, SVG, iframe 등 10개 페이로드를 새 브라우저 컨텍스트에서 각각 실행합니다. 고유 토큰이 포함된 실행 콜백이 관측되어야 `confirmed`입니다. HTML 반사만으로 확인 처리하지 않습니다.
4. sink 호출 스택, 입력 필드, 페이로드, API 요청과 오류를 JSON에 남깁니다.

`candidates`는 위험 구문 후보이고, `findings`는 실행이 관측된 시험입니다. `cases`의 `not_observed`는 해당 시간·경로에서 실행을 보지 못했다는 의미이며 안전 판정이 아닙니다. `error`는 입력 제약, 페이지 오류, 시간 초과 등을 포함합니다. `summary.verdict`는 `xss_execution_confirmed` 또는 `no_execution_observed`입니다. 오류·생략된 시험과 `diagnostics`도 함께 확인하세요.

`fsl-ca3p`는 `/api/session`과 `/api/posts`를 메모리에서 모사합니다. 입력한 글을 모사 POST로 보낸 뒤 GET과 재로드로 렌더링해 본문 XSS를 시험합니다. 실제 서버 DB 저장까지 검증한 결과는 아니므로 `realServerVerified:false`와 `stored-xss-client-with-modeled-api`로 표시합니다. `server.js`를 실행하거나 실제 글을 게시하지 않습니다.

브라우저 요청은 로컬 가상 원점에서 처리되고 알 수 없는 요청은 차단합니다. 이것은 완전한 악성코드 격리 환경이 아닙니다. 제공한 HTML·JS를 브라우저에서 실행하는 도구입니다.

범위: 일반 스크립트와 DOM 입력 경로를 지원합니다. 서버 템플릿, HTTP 응답 CSP/헤더, 로그인, 번들 의존성, 모듈 import, 복잡한 사용자 동작과 브라우저 전체 API는 자동으로 복원하지 않습니다. 외부 의존성도 JS 배열에 넣고 경로를 맞춰 제공해야 합니다. AST 후보는 데이터 흐름 분석이 아니므로 sanitization·attacker control 여부를 단정하지 않습니다.
