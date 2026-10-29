# web-parser — 모듈 계약 (초안)

- 상태: 초안 v0.6 (P2.4: `paths` 통합 색인, 비 HTML 텍스트 `body`, robots/sitemap 경로, URL 출처 추가, `resources[].method`) · 2026-10-29 · 브랜치 `woohyun212/web-parser` (← develop `a7e62b3`)
- 소유: woohyun. **xss-parser를 대체**(xss-parser는 deprecated 예정).

## 1. 역할
**Agent가 정한 endpoint**를 입력받아 그 문서의 **웹 정보를 수집**해 Agent에 넘기는 **취약점 종류 무관(XSS/IDOR/SQLi 독립)
범용 웹 정보 수집기**. 판정하지 않고, 공격하지 않는다. 크롤하지 않는다 — 다음에 볼 endpoint는 Agent가 `paths`(이 문서에서
갈 수 있는 경로의 통합 색인, §3)를 보고 골라 **URL마다 따로 요청**한다. 수집기는 목록만 만들고 그 경로를 방문하지 않는다.
- **수집기 자신은** 그 URL로의 GET 탐색 1회만 보내고 클릭·입력·제출을 하지 않는다. 그러나 일반 브라우저 방문처럼 **대상
  페이지 자신의 JS가 실행되고**, 그 JS가 보내는 요청(POST·폼 자동 제출·XHR/fetch·beacon 포함)과 내비게이션도 **받은 그대로
  보내지고 따라가며 기록된다**(요청 차단 없음, 사용자 결정 — §6). 즉 "상태를 바꾸지 않는다"는 보장은 **없다**: 페이지가
  스스로 상태를 바꾸는 요청을 보내면 그것도 일어난다. 클라이언트 홉은 메서드를 기록하지 않는다(POST 폼 제출도 `kind:"client"`).
- 모듈 API는 http/https URL을 받는다.

## 2. 입력 — endpoint는 Agent가 정한다
- `collect(url, opts) -> Promise<TargetInfo>`: **정확히 그 endpoint 하나**를 가져온다. HTTP 리다이렉트와 페이지가 시작한
  모든 메인 프레임 내비게이션(JS `location`, meta refresh, 폼 자동 제출 등)은 따라가며 받은 대로 기록하고, iframe도 받은 대로.
  링크는 수집만 하고 따라가지 않는다(수집기 자신은 클릭하지 않는다, §1).
- `collectEach(targetURLs, opts) -> Promise<Result[]>`: 비어 있지 않은 URL 문자열 배열을 **입력 순서대로 하나씩** `collect()`
  (URL마다 별도 격리 브라우저 세션, §5). 결과도 입력 순서:
  `{ url, ok:true, targetInfo } | { url, ok:false, error:{ message } }`. 한 URL의 실패(reject)는 배열 안에 담기고 나머지를
  멈추지 않는다. 배열·`opts` 검증 오류만 reject(방문 전에): 배열이 아니거나 비었거나, 문자열이 아닌 항목·빈 슬롯(희소 배열),
  `opts`가 객체가 아님, `timeoutMs`·`waitUntil`·`ignoreHTTPSErrors`·`userAgent`(문자열) 오류, `maxPages`.
- **필수**: `url` (http/https 임의 대상).
- **선택** (`opts`는 생략·`null` 모두 `{}`로 취급):
  - `timeoutMs` (기본 30000, 1..2^31-1): **endpoint 1개의 예산(goto + 추출)**. 시점은 모두 goto 시작 기준: 탐색은 50%까지,
    핵심 추출(클라이언트 리다이렉트 대기 포함)은 70%까지, JS 전역 읽기는 그 끝부터 80%까지, DOM probe는 그 끝부터 90%까지,
    나머지는 헤더·리다이렉트 체인 읽기. 핵심 추출 안에서 새 문서의 load 대기와 렌더러 첫 응답 대기는 각각 **남은 시간의
    절반까지**만 쓴다(§3). goto 이후 어떤 단계도 무한 대기하지 않는다 — 만료 시 `errors`에 `{stage, message:'<url>: timeout'}`
    (`cookies`·`fingerprint`는 접두어 없이 `'timeout'`)를 남기고 계속 진행하며,
    만료된 페이지 내 평가는 CDP `Runtime.evaluate`의 `timeout` + `Runtime.terminateExecution`으로 **실제로 종료**해 렌더러를
    비운다. 종료 시 컨텍스트를 닫는다. 수집 후 `cookies` 읽기와 지문 매칭도 각각 `timeoutMs`로 제한.
    전체 소요는 최대 대략 `3 × timeoutMs` + 브라우저 기동(보통은 `timeoutMs` 이내).
  - `maxPages`: **삭제됨**. 넘기면 reject `"maxPages: crawling removed: pass endpoints explicitly via collectEach"`.
  - `waitUntil` (`load`|`networkidle`, 기본 load), `userAgent`.
  - `ignoreHTTPSErrors` (기본 **true**): 자체서명·만료·스테이징 인증서도 받은 대로 수집(새 프로필이라 자격증명 없음).
    인증서 정보는 `navigation.securityDetails`에 기록. `false`면 인증서 오류 hop은 응답 없음으로 취급 — 그 전에 받은 3xx가
    없으면 reject, 있으면 그 3xx로 resolve + `navigate` 에러(§3 탐색 실패 정책). (TLS 동작은 테스트 없음, §9.)
- CLI: `web-parser (--url <URL> | --urls-file <file>)... [--out file] [--timeout-ms N] [--wait-until load|networkidle]
  [--user-agent UA] [--ignore-https-errors true|false]`. `--url`은 반복 가능, `--urls-file`은 단독으로도 되고 한 줄에 URL 하나
  (빈 줄과 **줄 전체가** `#`로 시작하는 주석만 무시 — 줄 끝 ` # note`는 URL에 남는다), 둘 다 주면 `--url` 먼저. URL이 **1개**면
  `TargetInfo` 객체 출력, 실패 시 exit 1 + stderr `{"error":{"message"}}`. **2개 이상**이면 `collectEach` 결과 배열(JSON 배열)을
  **항목마다 나눠 쓴다**(전체를 한 문자열로 만들지 않음; 한 항목이 직렬화 불가면 그 자리에 `{url, ok:false, error}`), exit 0
  (URL별 실패는 배열 안). exit 1은 사용법·옵션 오류와 `--out` 열기 실패·쓰기 실패. `--out`은 같은 디렉토리의 임시 파일
  (`<out>.<pid>.tmp`)을 방문 **전에** 열어(쓸 수 없는 위치면 방문 전에 실패) 거기에 쓰고, **성공했을 때만** `<out>`으로 rename
  한다 — 실패한 실행은 기존 `<out>`을 건드리지 않는다.
- 환경변수 `WEB_PARSER_BROWSER_PATH`: Chromium 실행 파일 경로 지정(선택).

## 3. 출력 — `TargetInfo` (원본 그대로)
수집기는 **받아지는 정보를 그대로** 담는다(필터·마스킹·차단 없음). 리다이렉트/iframe도 받은 대로 기록.

```
{
  schemaVersion: "web-parser-1",
  target:    { requestedUrl, finalUrl, origin },
  navigation:{ status, contentType, redirectChain:[hop], loadTimingMs, securityDetails|null },
  headers:   [ { name, value } ],             // 최종 문서 응답의 원본 헤더 (받은 그대로, §6)
  cookies:   [ { name, value, domain, path, expires, httpOnly, secure, sameSite, partitionKey?, _crHasCrossSiteAncestor? } ],
  meta:      [ { name?|property?|http-equiv?|itemprop?, content } ],
  html:      string|null,                    // 추출한 문서의 document.documentElement.outerHTML 원본 (HTML 문서 아니거나, 추출 없거나, 응답 없는 문서면 null)
  body:      string|null,                    // 추출한 문서가 HTML이 아닌 텍스트형이면 응답 본문 원본 (아래 "body"; HTML·바이너리·추출 없음이면 null)
  technologies: [ { name, categories:[카테고리명], version|null, confidence:0-100, evidence:[{field, key?, match}] } ],
  libraries:    [ { name, version|null, source:"fingerprint", evidence:[{field, key?, match}] } ],
  structure: {   // 그 endpoint의 문서 하나에서 나온 그대로 (같은 항목이 여러 번 있으면 여러 번)
    forms:   [ { selector, action, raw?, method, fields:[{name,type}] } ],
    links:   [ { href, raw?, text } ],
    scripts: [ { src, raw?, type|null } | { inline, type|null } ],
    iframes: [ { src|null, raw?, sandbox|null } ],  // 받은 대로 (차단 안 함)
    inputs:  [ { selector, tag, name|null, type, form|null } ],
    linkTags:    [ { href, raw?, rel|null, type|null } ],      // <link href> (canonical·alternate·manifest·preload·next·prev 등 모든 rel)
    areas:       [ { href, raw? } ],                           // <area href>
    formActions: [ { selector, formaction, raw?, formmethod|null, form|null } ],  // <button|input formaction>; form = 소속 폼 selector
    frames:      [ { src, raw? } ],                            // <frame src>
    embeds:      [ { src, raw?, type|null } ],                 // <embed src>
    objects:     [ { data, raw?, type|null } ],                // <object data>
    metaRefresh: [ { url|null, raw?, content } ],              // <meta http-equiv=refresh>의 content에서 파싱한 URL (URL 부분 없으면 null)
    media:       [ { tag:"img"|"source", src|null, raw?, srcset:[{ url, raw? }] } ]  // <img|source src|srcset>; srcset 후보마다 URL
  },
  resources: [ { kind, method, url, status } ],  // 로드된 리소스 (method = 요청의 HTTP 메서드; 실패는 status null, 응답 후 abort된 요청은 응답 1건만)
  paths:     [ { url, sources:[...], methods:[...], sameOrigin, params:[...], wildcard? } ],  // Agent용 경로 통합 색인 (아래 "paths")
  errors:    [ { stage, message } ],         // stage: navigate|load|extract|dom|js|headers|body|cookies|fingerprint; navigate|load|extract|dom|js|headers|body의 message는 "<requestedUrl>: <사유>", cookies|fingerprint는 사유만
  truncated: false                           // 아래 상한 중 하나라도 걸리면 true (예외 없음)
}
hop = { from, to, status, headers:[{name,value}]|null, kind: "http"|"client" }
```
- **문서 일관성**: `target.finalUrl/origin`, `navigation.status/contentType`, `headers`, `meta`, `html`, `structure`, JS 전역·DOM
  probe는 모두 **같은 커밋된 문서**(추출이 읽은 문서)의 것. 문서 동일성은 URL이 아니라 **CDP loaderId**(`Page.getFrameTree`의
  메인 프레임 loaderId ↔ `Network.responseReceived`(type Document)의 loaderId)로 판정 — 같은 URL 재로드(`location.reload()` 등)도
  다른 문서로 구분하고, 추출 전후 loaderId가 바뀌면 다시 추출한다(History API 변경은 같은 문서). load 후 페이지가 시작한
  내비게이션(JS `location`, meta refresh, 폼 제출 등)으로 문서가 바뀌면 다시 추출하고, `redirectChain`에
  `{from, to, status:null, headers:null, kind:"client"}` 홉을 넣는다(메서드 없음). HTTP 3xx 홉은 `kind:"http"`이며 그 3xx
  응답의 원본 헤더를 함께 담는다.
  - **응답 없는 문서는 보고하지 않는다**: 추출한 문서의 loaderId에 메인 프레임 응답이 없으면(빨리 실패한 클라이언트
    내비게이션 뒤 Chromium이 커밋한 에러 페이지 `chrome-error://…`, `about:blank` 등) 그 DOM은 브라우저가 만든 것이다 —
    `meta`/`html`/`structure`/DOM probe/JS 전역을 비우고 `{stage:'extract', message:'<url>: extracted document has no response
    (<문서 URL>)'}`를 남긴다. `target`·`navigation`·`headers`는 받은 마지막 최종 응답(없으면 마지막 3xx)의 것. 실패한 그
    내비게이션 요청은 `resources`에 `{kind:'document', status:null}`로만 남는다(별도 `navigate` 에러·client 홉 없음).
  - **새 문서 대기**: 읽은 문서가 goto가 기다린 문서가 아니고(클라이언트 리다이렉트의 착지 문서) `document.readyState`가
    `'complete'`가 아니면(본문이 아직 오는 중) 그 문서의 load/networkidle을 남은 핵심 추출 시간의 절반까지 **한 번** 기다린 뒤
    다시 읽는다. 그 대기가 타임아웃이면 `{stage:'load', message:'<url>: timeout'}`(직접 goto의 load 타임아웃과 같은 의미: 커밋된
    DOM은 추출하지만 불완전할 수 있음)을 남기고 그때까지 커밋된 DOM을 읽는다 — 끝나지 않는 하위 리소스가 있는 착지 문서도
    추출된다. 응답 없는 읽기(문서 교체 중)도 같은 절반 대기 후 다시 읽는다.
  - **진행 중인 내비게이션**: 메인 프레임 내비게이션이 진행 중이면 Chromium은 렌더러로 가는 CDP 명령을 그 내비게이션이 커밋/실패할
    때까지 붙잡는다. 그래서 **모든 렌더러 읽기**(핵심 추출 시도마다, JS 전역, DOM probe)는 자기 몫 시간의 절반이 지나도 끝나지
    않았고 **답을 못 받은 메인 프레임 문서 요청이 있을 때만** 같은 CDP 세션에서 `Page.stopLoading`을 보내 그 내비게이션을 멈추고,
    붙잡혀 있던 읽기가 커밋된 문서를 읽는다 → `{stage:<그 읽기의 stage: extract|js|dom>, message:'<url>: pending navigation
    stopped'}`. 읽기 자체는 끝까지 자기 시간을 쓴다(느리지만 도는 추출은 자르지 않음). 제때 응답하는 클라이언트 리다이렉트는
    멈추지 않고 따라간다. 페이지 JS로 렌더러만 바쁜 경우(진행 중 내비게이션 없음)는 멈추지 않고 그대로 `<stage>: timeout`.
- **headers**: Chromium이 보고한 응답 헤더 **줄마다 1항목**, 이름 대소문자 원본 유지(각 `Set-Cookie` 줄 포함, 병합 없음).
  순서는 Chromium(CDP)이 보고한 순서이며 와이어 순서와 다를 수 있다. `navigation.contentType`은 Playwright의 헤더 맵 값이라
  `Content-Type` 줄이 둘 이상이면 `'값1\n값2'`로 이어 붙은 형태다(각 줄 원본은 `headers`에; HTML 판정은 `document.contentType`).
- **cookies**: 수집 종료 시점의 **브라우저 cookie jar 전체**(Chromium/Playwright 정규화 결과) 그대로(partitioned 쿠키는
  Playwright가 붙이는 `_crHasCrossSiteAncestor?`도 그대로) — SameSite 미지정은
  `Lax`로 보이고, 브라우저가 거부한 쿠키는 없으며, 덮어쓰기 후 값만 남는다. **받은 그대로의 `Set-Cookie` 원문**은
  최종 문서의 `headers`와 각 HTTP 홉의 `headers`에 있다.
- **script `href`**: `src`가 없으면 `href` 속성을 쓴다 — SVG `<script>`용이지만 **모든** `<script>`에 적용된다(HTML
  `<script href=x>본문</script>`도 외부 `{src, raw}`로 보고되고 실제 실행된 인라인 본문은 빠진다; 받은 대로 기록하는 대가).
- **URL 필드**: `href`/`src`/`action`/`formaction`/`data`/`url`(metaRefresh·srcset 후보)은 `document.baseURI` 기준으로 resolve한
  절대 URL. 속성 원문이 그와 다르면 `raw`에 원문. `action`·`formaction` 속성이 없거나 빈 문자열이면 브라우저처럼 **문서 URL**
  (`<base>`와 무관; `raw`는 `null`/`''`). SVG `<a>`/`<script>`도 속성값 기준.
  - `formmethod`는 소문자로, 없으면 `null`(소속 폼의 method를 따름). `linkTags[].rel`은 받은 그대로(대소문자·여러 토큰).
  - `metaRefresh`: HTML 선언적 refresh 규칙대로 `<시간>(;|,|공백)[url=]['|"]<URL>`에서 URL을 뽑는다(따옴표는 닫는 따옴표까지).
  - `srcset`: HTML srcset 규칙대로 후보마다 URL만(공백 아닌 연속 문자열; 서술자 `1x`·`100w`는 버림; 쉼표 없는 `a.jpg,b.jpg`는
    URL 하나). 후보 목록도 `MAX_STRUCTURE_ITEMS`까지.
- **body**: 추출한 문서(응답과 짝지어진 커밋 문서)의 `document.contentType`이 HTML이 아닌 텍스트형(`text/*`,
  `application/json|xml|javascript|ecmascript|x-javascript`, `*/*+json`, `*/*+xml`)이면 그 응답 본문을 받은 그대로(UTF-8로 디코딩)
  담는다 — robots.txt·sitemap·JSON·JS 등. HTML 문서는 지금처럼 `html`만(본문 중복 저장 안 함), 바이너리(이미지 등)는 `null`.
  커밋되지 않은 문서(다운로드, 실패한 리다이렉트, 3xx로 끝남)도 읽을 본문이 없어 `null`(에러 없음). 읽기 실패·타임아웃은
  `{stage:'body'}`. `MAX_BODY_LENGTH`(5,000,000자) 초과 시 앞부분 + `truncated: true`.
- **paths** (Agent용 통합 색인 — 원본 필드 `structure`/`resources`/`redirectChain`/`body`는 그대로 두고 따로 만든다): 이 문서에서
  발견한 **http(s) URL**(`mailto:`·`javascript:`·`data:` 등은 structure에만)을 **fragment를 뺀 절대 URL** 하나당 1항목으로, 처음
  발견한 순서대로(리다이렉트 → resources → structure → body). 수집기는 이 URL들을 **요청하지 않는다**(Agent가 필요할 때 따로 요청).
  - `sources`: 발견 위치(중복 없이) — `redirect`(redirectChain 홉의 from/to), `request:<resources[].kind>`(실제 요청),
    `form`, `formaction`, `link`(`<a>`), `link-rel:<rel>`(`<link>`; rel 토큰마다 소문자, rel 없으면 `link-rel:`), `area`, `script`,
    `iframe`, `frame`, `embed`, `object`, `meta-refresh`, `img`/`source`(`src`), `srcset`, `robots:allow|disallow|sitemap`,
    `sitemap`(`<urlset><url><loc>`), `sitemap-index`(`<sitemapindex><sitemap><loc>`).
  - `methods`: 대문자, 중복 없이 — 폼 `method`(속성 원문 그대로, 기본 GET), `formmethod`(없으면 소속 폼의 method), 실제 요청의
    메서드. 모르면 `[]`.
  - `sameOrigin`: `target.origin`과 같은 origin인지. `params`: 쿼리 파라미터 **이름** ∪ (폼 action·formaction이면 소속 폼의 필드
    **이름**) — **값은 담지 않는다**.
  - `wildcard: true`: robots `Allow`/`Disallow` 값에 `*`·`$`가 있으면 붙는다 — 경로가 아니라 **패턴**이며 원문 그대로 둔다
    (`/private/*.php$` → `<origin>/private/*.php$`).
  - **robots**: `body`에 `User-agent:` 또는 `Sitemap:` 줄이 있으면(파일 이름·URL 무관, 내용으로 판정) `Allow`/`Disallow`/`Sitemap`
    줄의 값(`#` 주석 제외, 빈 값 무시)을 문서 URL 기준으로 resolve. **sitemap**: `body`에 `<sitemapindex`가 있으면 `sitemap-index`,
    `<urlset`이 있으면 `sitemap`으로 `<loc>` 텍스트(XML 이름 엔티티 5종 디코딩; CDATA·숫자 참조는 미지원). web-parser가 robots.txt나
    sitemap을 **알아서 요청하지는 않는다** — Agent가 그 URL을 따로 요청하면 그 응답의 `paths`에 나온다.
  - JS 코드·JSON 안의 문자열 경로는 추출하지 않는다(§11 백로그).
  - `MAX_PATHS`(2000)개 초과 시 그 뒤의 새 URL은 버리고 `truncated: true`(이미 있는 항목의 sources 등은 계속 합친다).
- **탐색 실패 정책**: 메인 프레임 응답을 **하나라도 받았다면 resolve** — 3xx 홉도 받은 응답이다. status/headers를 채우고
  `errors`에 `{stage:'load'}`(load/networkidle 타임아웃: 커밋된 DOM은 추출) 또는 `{stage:'navigate'}`(다운로드형 응답, 죽은
  호스트로의 리다이렉트, 리다이렉트 루프 등: DOM 추출 없음)를 기록. 응답을 하나라도 받은 뒤의 goto 타임아웃은 항상
  `load`다(응답을 받기 전에 타임아웃이면 받은 응답이 없으므로 아래 규칙대로 reject) — 3xx 뒤 대상이 응답하지 않아 아무것도 커밋되지 않은 경우도 `load`이며, 이때 추출은 진행 중 내비게이션을 멈추고
  (`pending navigation stopped`) `about:blank`를 읽으므로 `extracted document has no response (about:blank)`가 이어진다. 최종 문서 없이 3xx에서 끝났으면 `target.finalUrl`·status·
  headers는 **마지막으로 받은 3xx 응답**의 것, `redirectChain`은 그 앞 홉들. HTTP 4xx/5xx도 정상 resolve. **응답이 전혀 없을
  때만 reject**(DNS 실패, 연결 거부, 3xx 없이 `ignoreHTTPSErrors:false`의 인증서 오류). **알려진 예외**: Chromium이 따르기를
  거부하는 Location(`file:`·`data:`·`chrome:` 등)의 3xx는 Playwright 응답 객체가 생기지 않는다. 그 3xx가 **첫 응답**이면
  `net::ERR_UNSAFE_REDIRECT`로 **reject**, 앞서 받은 3xx 홉이 있으면 그 3xx로 resolve + `navigate` 에러. 어느 쪽이든 그 unsafe
  3xx 자체의 status·헤더(`Set-Cookie` 포함)는 잃는다(미수정, §8).
- **비 HTML 문서**: 판정은 응답 헤더가 아니라 **추출한 문서의 `document.contentType`**(프로토타입 getter, Content-Type이 없으면
  Chromium이 스니핑한 값)이 text/html·application/xhtml+xml인지로. 아니면 `contentType`(받은 헤더 그대로, 없으면 null)·status·
  headers(텍스트형이면 `body`도, 위 "body")만 기록하고 `meta`/`html`/`structure`/DOM probe/JS 전역은 비운다(브라우저 뷰어가 만든
  DOM을 대상 데이터로 보고하지 않음). load 후 클라이언트 리다이렉트로 비 HTML 문서에 착지해도 같다.
- **추출 안전**: DOM 추출은 **격리 world**(CDP `Page.createIsolatedWorld`)에서 실행하고 DOM은 프로토타입 getter/메서드로
  읽는다(폼 컨트롤의 `type`·`form`만 직접 읽음 — 폼 컨트롤엔 named-property getter가 없어 무해) — 페이지 JS의 DOM API 몽키패칭이나 named-property DOM clobbering(`<input name=parentElement>`,
  `<img name=querySelectorAll>` 등)이 추출을 깨거나 위조하지 못한다.
- **상한(페이지 안에서 적용)**: 추출 결과는 CDP를 건너기 **전에 페이지 안에서** 자른다 — 호스트 프로세스가 거대한 문자열로
  죽지 않도록. `html`은 `MAX_HTML_LENGTH`(5,000,000자)까지 앞부분, `meta`와 `structure`의 각 배열(폼의 `fields` 포함)은
  `MAX_STRUCTURE_ITEMS`(500)개, 그 안의 문자열 값(링크 텍스트, 인라인 스크립트, 속성값, selector 등)은 각각
  `MAX_TEXT_LENGTH`(10,000자), 한 문서의 meta+structure 문자열 합계는 `MAX_SNAPSHOT_TEXT`(10,000,000자), DOM probe 값은
  `MAX_TEXT_LENGTH`, JS 전역 값은 1000자. `resources`는 `MAX_RESOURCES`(500)개, `body`는 `MAX_BODY_LENGTH`(5,000,000자; 본문은
  Chromium 버퍼에서 받아 호스트에서 자른다), `paths`는 `MAX_PATHS`(2000)개. `truncated: true`는 **TargetInfo에 들어가는
  데이터가 잘렸을 때만**(위 html·meta·structure·resources·body·paths 상한). DOM probe·JS 전역 값 상한과 매처의 html/scripts 표본
  (`MATCH_SAMPLE_LENGTH`)은 지문 매칭용 내부 입력만 자르므로 `truncated`를 세우지 않는다(기록도 없음).
- **알려진 한계** (미수정):
  - html은 페이지 안에서 `outerHTML` 전체를 직렬화한 뒤 자른다. 직렬화가 텍스트보다 커지는 페이지(예: `&` 약 1억 개 →
    `&amp;`로 5배)는 그 읽기에서 렌더러가 죽고, 핵심 추출이 70% 시점까지 기다린 뒤 `extract: timeout`만 남는다(html·meta·
    structure 없음, `truncated: false`).
  - `Runtime.terminateExecution`은 **실행 중인 JS**만 멈춘다. 페이지 코드가 동기 대기(예: Proxy 트랩 안의 동기 XHR)에 묶여
    있으면 렌더러는 계속 바쁘고, 뒤 단계(DOM probe)도 `timeout`이 된다.
  - 문서가 되지 않는 메인 프레임 내비게이션(204/205 응답, 다운로드)도 문서 사이에 `kind:"client"` 홉으로 들어간다.
- **html**: 추출한 커밋 문서의 `outerHTML`을 격리 world에서 받은 그대로(위 상한까지).
- **technologies / libraries** (§7): 수집 후 지문 매칭. 매처 입력 = `url`(finalUrl), `headers`(원본 배열 → 어댑터가
  `{소문자이름:[값...]}`로 변환, 출력 `headers`는 원본 유지), `cookies`(분석 문서 URL `finalUrl`에 적용되는 쿠키의 이름+값만;
  출력 `cookies`는 jar 전체), `meta`(name 없으면 property), `html`·`scripts`(`structure.scripts` 인라인을 이은 문자열) — 둘 다
  `MATCH_SAMPLE_LENGTH`(50,000자, 이 모듈 자체 상한: 데이터셋 패턴 `<[^>]{1,250}`의 페이지 통제 최악 비용(V5)을 묶기 위함) 초과 시
  **앞 25,000 + 뒤 25,000자 표본**(Wappalyzer 드라이버의 앞/뒤 표본과 모양만 비슷하고, 드라이버 창은 약 3M+3M자로 훨씬 큼 —
  50k 넘는 문서의 가운데에 있는 html 패턴은 매치되지 않는다), `scriptSrc`(`structure.scripts`의 src),
  `xhr`(`resources`의 xhr/fetch URL에서 **host+path만** — 쿼리·프래그먼트 제외, 출력 `resources`는 원본 URL), JS 전역·DOM 셀렉터.
  이름 맵은 null-prototype이라 `constructor`·`__proto__` 같은 이름도 일반 키다. 매처가 받지 않는 관계: `certIssuer`, `css`,
  `text`, `robots`, `dns`, `probe`, 외부 스크립트 본문.
  - **데이터셋**: 레포에 포함하지 않는다(§7). 없거나 깨졌으면 아래 "데이터셋 로드 실패"와 같다.
  - **실행**: 매칭은 `worker_threads` Worker에서 돌고 `timeoutMs` 데드라인에 terminate된다 → `errors`에
    `{stage:'fingerprint', message:'timeout'}`, 수집 결과는 그대로 resolve. 호출자의 이벤트 루프를 막지 않는다. 프로세스당
    유휴 Worker 1개를 유지해(데이터셋을 한 번만 파싱; `unref`라 프로세스 종료를 막지 않음) 재사용하고, 타임아웃·크래시 시에만
    terminate 후 다음 호출에서 새로 만든다. 동시 호출은 각자 Worker를 받는다.
  - JS 전역·DOM probe는 **핵심 추출(structure/meta/html) 뒤**, 핵심 추출과 같은 문서(loaderId)에서만 읽는다: 먼저 JS 전역
    (핵심 추출 끝 → 80% 시점), 그다음 DOM probe(그 끝 → 90% 시점) — 큰 DOM에서 DOM probe가 늦어도 JS 전역(버전 단서)은
    잃지 않는다. 평가 실패·타임아웃·문서 변경(실행 컨텍스트 파괴 포함)은 각각 `{stage:'js'}`/`{stage:'dom'}`로 남기고 핵심
    데이터는 유지. 이 단계에서 시작된 응답 없는 내비게이션도 위 "진행 중인 내비게이션" 규칙으로 멈춘다.
  - JS 전역: 데이터셋 `js` 키 경로(예 `jQuery.fn.jquery`)를 **메인 world**에서 읽는다(페이지의 실제 `window` 필요). **데이터
    프로퍼티만** 따라가고(일반 getter 미실행; Proxy 트랩은 실행될 수 있어 위 데드라인으로 종료) 값은 문자열화(문자열·숫자는
    `String`, 그 외 `"true"/"false"`, 1000자 상한)해서만 가져온다. 페이지가 노출하는 값은 페이지가 조작할 수 있다. 체인별
    예외(예: 던지는 Proxy 트랩)는 그 체인만 **조용히 건너뛴다**(기록 없음) — 기록되는 것은 평가 전체의 실패·타임아웃·문서 변경뿐.
  - DOM: 데이터셋 `dom` 셀렉터마다 격리 world에서 `querySelector` 첫 매치의 존재·텍스트·요청 속성만 읽는다(파싱 불가 셀렉터는 건너뜀,
    `properties` 패턴은 미지원).
  - `requires`/`requiresCategory`: **resolve된 집합**(implies로 생긴 기술·카테고리 포함, excludes 적용) 기준으로 잠금 해제된 그룹을
    분석하고, 새로 풀리는 것이 없을 때까지 반복(고정점).
  - 같은 기술·패턴·키·버전의 중복 detection은 resolve 전에 1건으로(반복된 약한 신호가 confidence 100이 되지 않게).
  - `evidence[]` = 매치된 패턴의 `{field, key?, match}`(field: headers|cookies|meta|html|scriptSrc|scripts|xhr|url|js|dom).
    `key`는 headers/cookies/meta의 이름(데이터셋 키, 소문자), js의 chain, dom의 selector; 그 외 field에는 없음.
    `implies`로만 추가된 기술은 `{field:'implies', match:<함의한 기술명>}`.
  - `libraries` = technologies 중 카테고리 id ∈ {12 JavaScript frameworks, 18 Web frameworks, 25 JavaScript graphics,
    26 Mobile frameworks, 59 JavaScript libraries, 66 UI frameworks} (`fingerprint.mjs`의 `LIBRARY_CATEGORIES`).
    24 Rich text editors는 페이지 위젯이라 제외(결정).
  - 데이터셋 로드 실패·매칭 예외는 `errors`에 `{stage:'fingerprint'}` 1건, 수집 결과는 그대로 반환(reject 안 함).
- `schemaVersion`은 **자체 네임스페이스**(`web-parser-1`) — 기존 xss-parser의 `3.4`와 무관.
- 취약점 흔적/판정 필드 없음(역할상 중립).

## 4. Agent 호출 입출력 구조 (와이어)
- 모듈은 **독립 완성이 우선**(§8 P1). Agent 연동은 입출력 **형태만 지금 정리**하고 결선은 P3.
- **URL 하나당 요청 1회 (사용자 결정)**: operation `collect_web_info`, payload `{ url, opts? }` → result
  `{ type:"web_info", targetInfo }` (`targetInfo` = `collect(url, opts)`의 `TargetInfo`, §3). Agent는 필요할 때 같은 URL을
  **언제든 다시 요청**할 수 있고, 호출마다 새 격리 세션(§5)이라 이전 호출의 영향이 없다. web-parser는 **호출 사이에 아무 상태도
  기억하지 않는다**(커서·세션·결과 보관 없음). 목록을 한 번에 보내고 묶음으로 받는 방식은 검토 후 기각.
- `collectEach`는 CLI·일괄 처리용 편의 기능(§2)이며 Agent 경로가 아니다(Agent 경로는 `collect(url)`).
- ⚠️ **P3 제약**(현재 `agent/src/protocol.js` 기준, 모듈은 수정하지 않음):
  1. **시간**: Agent의 기본 invoke 타임아웃(`DEFAULT_GATEWAY_TIMEOUT_MS`) 10,000ms < 페이지 예산(`timeoutMs` 기본 30,000,
     최대 약 `3 × timeoutMs` + 기동, §2) — 호출 측이 그보다 긴 타임아웃을 넘겨야 한다.
  2. **크기**: 봉투 상한은 직렬화된 메시지 전체 1,000,000 UTF-8 바이트(`MAX_MESSAGE_BYTES`). `html` 상한이 5,000,000자이므로
     아주 큰 페이지는 `TargetInfo` 하나만으로 1MB 봉투를 넘을 수 있다.
- ⚠️ **이 와이어 결선(protocol.js의 sender id·operation·result 검증, orchestrator 호출)은 agent 코어
  소유자(1mn2147) 조율 필요.** xss-parser를 대체하므로 기존 `parser.result`/`parse_site`/sender
  `xss-parser` 경로의 처분도 함께 정해야 함. 모듈 쪽 계약(이 문서)은 그와 독립으로 먼저 확정.

## 5. 브라우저 세션 격리 (요구사항)
- **다른 모듈/Agent와 같은 Chrome을 공유하지 않는다.** 매 수집마다 **자체 Chromium 인스턴스**를
  `chromium.launchPersistentContext(<mkdtemp 프로필>)`로 띄우고 **전용 임시 user-data-dir / context**를 쓴다.
  공유 CDP 엔드포인트에 `connect`하지 않는다(격리 world용 CDP 세션은 자기 페이지에만 연다). 종료 시(성공·reject·타임아웃
  모두) 컨텍스트·프로필 정리. `collectEach`도 URL마다 새 인스턴스·프로필(쿠키 등 상태가 다음 URL로 새지 않는다).

## 6. 원본 전달 원칙 (결정됨)
- 수집기는 **redaction/리다이렉트 차단/요청 차단을 하지 않는다**(원본 충실도 우선; 페이지 JS의 요청도 받은 그대로 전달, §1). Agent는 완전한 정보를 받는다.
- **redaction은 web-parser의 역할이 아니다** — 쿠키·헤더·토큰도 받은 대로 담아 전달. 비밀 처리가 필요하면
  그건 전적으로 **다운스트림(영속화/전송 측) 책임**이며 이 모듈의 범위 밖. 모듈은 웹 정보 전달에만 집중.

## 7. 지문(technologies) 소스
- Wappalyzer를 활용(사용자 결정). 원본 npm `wappalyzer`는 deprecated, 본체는 상용 전환.
  **살아있는 경로**: 커뮤니티 지문 데이터셋 포크(`enthec/webappanalyzer`, 동일 JSON 구조) + 매처 npm `wapalyzer-core@6.11.0`.
  대상이 임의 외부 URL이므로 넓은 커버리지의 데이터셋 채용이 타당.
- **데이터셋**: 지문 데이터셋은 레포에 포함하지 않고(`.gitignore`), 설치 시 `scripts/fetch-dataset.mjs`(`postinstall`·
  `pretest`, 수동은 `npm run fetch-dataset`)가 `enthec/webappanalyzer` 커밋 `d91f7e510e93457041bea874e8a9ffb011e3e4fe`에서
  `src/categories.json`, `src/groups.json`, `src/technologies/{_,a..z}.json`을 내려받아 `data/webappanalyzer/`에 둔다
  (`src/` 접두어 제거). 출처(저장소·커밋·파일 목록)는 스크립트의 상수가 단일 기준. 파일이 모두 있고 JSON으로 파싱되면 네트워크
  없이 끝나고, 빠졌거나 깨진 파일만 다시 받는다(임시 파일 → rename; 실패 시 메시지 + exit 1).
- **구현**: 매처는 `wapalyzer-core`의 매칭·`implies`/`excludes`·버전 해석을 재사용하고(패키지 번들 데이터는 쓰지 않음), 코어에
  없는 `js`/`dom` 매칭과 `requires`/`requiresCategory` 고정점 반복(§3)은 `fingerprint.mjs` 어댑터가 수행하며, 매칭은
  `fingerprint-worker.mjs`(Worker)에서 돈다. 수집 중 런타임 네트워크 접근 없음.

## 8. 단계 계획
- **P1 (모듈 단독, 의존성 없음)**: `collect()` + CLI + `TargetInfo` 출력 + 세션 격리 + 테스트
  (테스트 프로세스 안의 127.0.0.1 HTTP 픽스처). Agent 결선 없이 단독 테스트 통과.
- **P2 (지문)**: Wappalyzer 데이터셋/매처 결합 → `technologies`/`libraries` 채움.
- **P2.1**: 크롤러 삭제(endpoint는 Agent가 정함) + `collectEach` + 통합 리뷰 지적(V0–V9) 수정.
- **P2.2**: 최종 검증 W0–W5 수정(응답 없는 문서 미보고, 리다이렉트 재추출 예산, 진행 중 내비게이션 정지, probe 상한의
  `truncated`, §1 문구) + JS 전역 우선, CLI 스트리밍, 검증 보강, 지문 Worker 재사용. 미수정: `ERR_UNSAFE_REDIRECT` 3xx 보존(§3).
- **P2.3**: 데이터셋을 레포에서 빼고 설치 시 고정 커밋에서 다운로드(§7), §4 URL마다 요청 1회, 최종 게이트 G0–G6(착지 문서
  load 대기, 모든 렌더러 읽기의 내비게이션 정지, 결정적 Worker 검사, V8 예산 여유), `truncated` 범위(TargetInfo 데이터만),
  CLI `--out` 임시 파일, 테스트 신뢰성.
- **P2.4**: `paths` 통합 색인(§3), 빠진 URL 출처(`<link>`·`<area>`·formaction·`<frame>`·`<embed>`·`<object>`·meta refresh·srcset)를
  structure에 추가, `resources[].method`, 비 HTML 텍스트 응답 `body`, robots.txt/sitemap 파싱. 동시 실행 상한은 넣지 않음(결정).
- **P3 (Agent 연동, 1mn2147 조율)**: §4 결선과 Agent 쪽 시간·봉투 1MB 제약(§4), xss-parser 경로 대체·폐기,
  integration-manifest에서 모듈 id 교체.
- **P4 (정리)**: xss-parser deprecate(매니페스트·어댑터·테스트 정리), 문서화.

## 9. 테스트
- `npm test` = `test/collect.test.mjs`(실제 Chromium, 테스트 프로세스 안 127.0.0.1 HTTP 픽스처) + `test/fingerprint.test.mjs`
  (브라우저 없이 `fingerprint()` 직접 호출). 외부 호스트 접근 없음(`pretest`의 데이터셋 다운로드는 파일이 없을 때만). 테스트마다
  파일 안에 타임아웃. 부하에 민감한 벽시계 단언은 두지 않는다 — Worker 재사용·Worker 경유는 생성/메시지 횟수로 확인.
- 수집: `TargetInfo` 형태, 크롤 없음(endpoint 1개만 방문, `maxPages` 거부), `collectEach`(순서·실패 격리·세션 격리), 리다이렉트
  체인, 3xx 후 실패(V2), 같은 URL 재로드의 문서 일관성(V1), 비 HTML 판정(V0), 행 걸린 페이지·JS 전역 종료(V9), 큰 DOM에서 핵심
  추출 우선 + JS 전역 유지(V8: 비싼 DOM 셀렉터를 더한 데이터셋 사본, 정확히 `dom: timeout`), 페이지 안 상한(V4: 60M자 페이지),
  매처 최악 입력이 Worker 메시지 1건으로 처리됨(V5), 깨진·없는 데이터셋(V7), 응답 없는 에러 페이지 미보고(W0), 끝나지 않는 착지
  문서 재추출 + `load: timeout`(W1), 본문이 나눠 오는 착지 문서의 늦은 링크까지 추출(G0/G2), 진행 중 내비게이션 정지(W2: load
  전·후·POST 폼, 응답하는 리다이렉트는 따라감; G1/G4: load 후 0–25ms 지연으로 시작하는 내비게이션·meta refresh 0 — DOM·JS 전역
  유지), DOM probe·JS 전역 상한은 `truncated`를 세우지 않음(W4), **자산 간 섞임 없음**(서로 다른 두 페이지를 연달아·동시에 수집:
  쿠키·헤더·structure·technologies), clobbering, form action, 헤더 줄 단위, 상한 시 `truncated`, `collectEach` 검증(희소 배열·
  `userAgent`·`opts` 타입), CLI(단일·다중·`--urls-file` 단독·`--out` 열기 실패·실패 시 기존 `--out` 보존·사용법 오류).
- paths(P2.4): 모든 URL 출처가 담긴 페이지 → structure 각 항목과 `paths.sources`(frameset 포함), 중복 제거(fragment만 다른 링크 +
  area → 1항목), `sameOrigin`, `params`(이름만, 폼 값이 색인에 없음), formaction의 method·필드 상속, 로드 시 POST fetch →
  `resources[].method`·`paths.methods`, 리다이렉트 홉, robots.txt(와일드카드 표시)·sitemap·sitemap index·JSON의 `body` 원본과 경로,
  나열된 경로를 요청하지 않음, 바이너리 `body:null`, `body`·`paths` 상한 시 `truncated`.
- TLS(`ignoreHTTPSErrors` 기본 true의 자체서명 수용, `securityDetails`, false의 reject)는 **테스트 없음**.
- 어댑터: dom 속성 버전, xhr(host+path), 3단계 `requires` 체인, `requiresCategory`, implies로만 충족되는 requirement, excludes,
  중복 detection confidence, 이름 정규화·`constructor`/`__proto__`(V6), html 표본(가운데는 버리고 끝은 매치), Worker 데드라인(V5),
  Worker 재사용·타임아웃 후 재생성·동시 호출(생성 횟수로), 재사용 Worker에 서로 다른 입력을 순차·동시에 넣어도 자기 탐지만
  (자산 간 섞임 없음), 유휴 Worker `unref`(자식 프로세스가 스스로 종료), 데이터셋 정합성
  (`LIBRARY_CATEGORIES` 이름, implies/excludes/requires 대상 존재).
- 비밀 경계는 수집기 밖(영속화/전송) 책임이므로 모듈 테스트 범위 밖 — 경계 지점에서 별도 검증.

## 10. xss-parser 폐기(deprecation)
- web-parser가 Agent 경로를 대체하면 xss-parser의 wire(`xss-parser` sender, `parse_site`),
  integration-manifest 항목, 어댑터, 테스트 스위트를 순차 제거/치환. P3~P4에서 1mn2147·매니페스트와 조율.

## 11. 백로그
- **JS 코드 안의 API 경로 추출**(정적 분석) — 백로그. 인라인·외부 스크립트(와 JSON 본문)의 문자열·`fetch`/XHR 호출에서 경로를
  뽑아 `paths`에 넣으려면 **추론임을 표시**해야 한다(예: 별도 source와 확신도) — 받은 그대로의 출처와 섞이지 않게.
