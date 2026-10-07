# CA3P Agent Loop — 로컬 통합 대시보드

`DESIGN.md`의 검정 배경, 민트·제이드 별빛과 주변광을 적용한 로컬 대시보드입니다. 저장소의 Agent 코어가 수행하는 단일 루프를 두 방식으로 관측합니다. **코어 fixture**는 네트워크 대상과 모델을 모사합니다. **저장형 XSS 1회 실습 + DeepSeek**는 저장소의 게시판을 격리해 실행하고 모델 API를 호출하며, 기본으로 한 번의 저장형 XSS canary 검사를 수행합니다.

## 실행

대시보드 서버만 실행하려면 Node.js 20 이상이 필요합니다. 실제 로컬 실습에는 PATH에서 실행할 수 있는 `curl`, `xss-parser`의 npm 의존성과 Playwright Chromium, Python 3.11 이상과 `casper-db`의 Pydantic 의존성이 필요합니다. 설치 명령은 [루트 README](../README.md)에 있습니다. 프로젝트 루트에서 실행합니다.

```powershell
npm start
```

또는 대시보드 디렉터리에서 직접 실행할 수 있습니다.

```powershell
cd agent-dashboard
npm run dev
```

브라우저에서 <http://127.0.0.1:4173>을 엽니다. 서버는 `127.0.0.1`에만 바인딩합니다. 터미널에서 `Ctrl+C`로 종료합니다. 루트 시작 명령에 `npm start -- --port 4174`를 사용하거나 대시보드에서 `$env:PORT = '4174'`를 설정한 뒤 실행하면 포트를 변경할 수 있습니다.

## 사용 방법

1. 고정 응답으로 화면과 코어를 확인하려면 URL을 입력하고 **코어 fixture 시작**을 누릅니다. 이 URL은 기록용이며 접속하지 않습니다.
2. 실제 로컬 검증을 실행하려면 `agent/.env` 또는 프로세스 환경변수에 `DEEPSEEK_API_KEY`를 설정한 뒤 **저장형 XSS 1회 실습 + DeepSeek**의 **로컬 실습 시작**을 누릅니다. 이 키는 UI 실습에 필수이며 API 호출은 과금될 수 있습니다. 서버가 소유한 `vul-web-1` 게시판을 `127.0.0.1`의 임시 포트와 별도 임시 데이터 파일로 시작합니다. 입력 URL은 실습 대상에 사용하지 않습니다.
3. 실시간 진행 상태와 모듈별 요청·응답 JSON, Correlation ID, Agent I/O를 확인합니다. 중지를 누르면 다음 gateway 경계 또는 진행 중인 요청에서 중단을 시도합니다.
4. 실행 이력에서 기록을 열거나 현재 실행으로 돌아갑니다. 보관할 실행은 JSON으로 내보냅니다.

대시보드의 기본 로컬 실습 프로필은 `stored_xss_canary`입니다. Alice 세션 준비 GET 후 `xss-parser`가 Chromium으로 게시판 한 페이지의 입력 폼, `POST /api/posts`와 HTML 렌더링 위치를 변경 없이 관찰합니다. `casper-db`는 관찰한 API 입력 위치를 SQLite의 과거 XSS 사례와 대조해 참고 판정을 반환합니다. `pentest-db`는 `cases.json`의 초안 XSS 정보를 입력 위치·브라우저 확인 방법에 대한 조언으로 반환합니다. 과거 일치나 카탈로그만으로 현재 취약점을 확정하지 않습니다.

Agent가 실행별 고유 마커를 가진 무해한 canary를 만들고 DeepSeek가 단일 `{method,url,body}` POST를 제안합니다. 모델 출력은 코어가 만든 허용 요청과 정확히 같아야 합니다. 로컬 gateway가 게시판 원점·canary 본문·순서를 확인하고 `guardrail`이 요청 예산과 범위를 전송 직전에 평가합니다. 그 뒤 `attack-module`이 `POST /api/posts`를 한 번 실행합니다. 별도 Chromium 브라우저가 생성된 같은 게시글을 다시 열어 고유 마커의 콜백이 실제 호출됐는지 확인합니다. 코어의 결정론적 `reflect()`는 게시글 ID·마커·원점·표시·콜백·오류와 증거 참조를 확인해 finding을 판정합니다. `pentest-db`는 이벤트·보고서를 `reports/pentest-db-runs/`에 저장합니다. 모델 요청은 실패 시 기본 1회, 설정에 따라 최대 2회 재시도할 수 있지만 검사 POST는 자동 재시도하지 않습니다. `npm start`만으로는 모델 호출이나 검증이 시작되지 않습니다.

기존 교차 사용자 삭제 검사(`agent_cross_user_delete_canary`)는 명시적으로 선택하는 레거시 프로필입니다. 대시보드의 **로컬 실습 시작**은 저장형 XSS 프로필을 사용합니다. 코어 fixture는 모의 응답을 사용하며 입력 URL에 접속하지 않습니다.

모의 응답 지연은 fixture 모드에서 0.9초·1.8초·3초로 선택하며 다음 실행에 적용됩니다. 이는 실제 대상이나 모델의 응답 시간 측정값이 아닙니다. 배경 애니메이션과 reduced-motion 설정, 이벤트 검색, JSON 복사, 모바일 화면과 Ctrl/Cmd+K URL 입력을 지원합니다.

일시정지는 지원하지 않습니다. 코어의 gateway timeout은 기본 10초이며, Chromium parser와 `casper-db` 조회에는 더 긴 제한을 적용합니다.

## 실행 범위

두 모드 모두 `agent/src/orchestrator.js`의 `runOnce()`를 사용하고 `maxIterations`는 1입니다. 실제 모듈의 요청·응답, `guardrail` 판정, 내부 `loop.think`·`loop.reflect` 입출력을 실시간 SSE로 표시합니다. 화면의 Agent Loop는 실제 모듈 이름인 `xss-parser`, `casper-db`, `pentest-db`, `attack-module`, `guardrail`을 사용합니다.

| 모드 | Agent 판단 | 읽기·과거 자료 | HTTP 요청·정책 | 실행 기록 |
| --- | --- | --- | --- | --- |
| 코어 fixture | `RuleReasoningEngine` | `xss-parser`·`casper-db` 고정 응답 | `attack-module`·`guardrail` 고정 응답 | `pentest-db` 인메모리 테스트 대역 |
| 로컬 실습 | `DeepSeekReasoningEngine` | 실제 Chromium parser와 SQLite 매칭 | 실제 curl과 규칙 평가기 | 초안 카탈로그 조회·로컬 JSON 파일 저장 |

로컬 실습의 대상은 서버가 만든 소유 게시판으로 고정됩니다. 임의 URL로의 펜테스팅과 범용 크롤링은 이 경로에 포함되지 않습니다. `xss-parser`의 첫 읽기 전용 관찰은 후보를 찾고, POST 후 별도 브라우저 관찰은 같은 canary의 실행 증거를 수집합니다. 현재 실습의 finding은 이 로컬 게시글의 저장형 XSS 실행 판정에 한정됩니다. `xss-fuzzer`는 통합 제외 범위를 유지합니다. 두 모드는 보고서의 `mode`, `simulated`, `targetContacted`, 외부 모듈 출처로 구분합니다. fixture의 finding은 모의 증거 판정입니다.

사용자가 중지한 세션의 실행 상태는 `stopped`이며, 코어가 중단 때문에 생성한 보고서는 기존 계약의 `failed` 상태를 유지합니다. 최종 저장 응답을 허용해 중단 보고서도 관측할 수 있게 합니다.

## 연결과 기록 보관

현재 실행은 서버가 관리합니다. 브라우저 새로고침 후 SSE가 재연결되면 서버의 현재 실행을 다시 표시하고, 서버에서 진행 중인 루프는 계속됩니다. 연결이 끊기면 화면에 연결 상태를 표시하며 재연결을 시도합니다. 연결이 끊긴 동안의 화면 상태를 완료로 판단하지 마세요.

현재 화면 상태와 보고서는 서버 메모리에 저장되어 서버 종료 시 사라집니다. 브라우저의 `localStorage`에는 최근 12개 실행 이력과 화면 설정만 저장됩니다. 코어 실행 이력은 기존 브라우저 모의 실행과 다른 키로 저장하여 이전 기록을 덮어쓰지 않습니다. 실제 로컬 실습에서 `pentest-db` 어댑터는 이벤트와 최종 보고서를 `reports/pentest-db-runs/`의 로컬 JSON 파일에도 저장합니다. 화면에서 보관·공유할 보고서는 JSON 내보내기를 사용하세요.

## 파일 구성

| 파일 | 역할 |
| --- | --- |
| `dist/index.html` | 대시보드 구조와 접근성 |
| `dist/styles.css` | 레이아웃과 반응형 디자인 |
| `dist/app.js` | 화면 상태, 세션 제어, 이력·검색·내보내기 |
| `dist/runtime-client.js` | 로컬 API 호출과 SSE 연결·현재 실행 복원 |
| `dist/engine.js` | 기존 오프라인 fixture와 기록 처리 helper; 브라우저 tick 루프는 사용하지 않음 |
| `dist/starfield.js` | DESIGN.md에서 영감을 받은 Canvas 별빛 배경 |
| `local-runtime.mjs` | 두 모드의 Agent 코어 실행·상태·중지 컨트롤러 |
| `local-lab-gateway.mjs` | 임시 로컬 게시판 수명 관리와 실제 모듈 라우팅 |
| `integrations/xss-parser.mjs` | 한 페이지 Chromium 입력 관찰과 별도 브라우저 canary 실행 확인 |
| `integrations/casper-db.mjs` | parser 결과에서 입력 위치를 추출하고 SQLite 과거 사례 대조 |
| `integrations/pentest-db.mjs` | 초안 카탈로그 조회와 실행 JSON 파일 저장 |
| `integrations/guardrail.mjs` | 로컬 실행에 바인딩된 규칙 평가와 예산 관리 |
| `../attack-module/index.js` | 검증된 JSON curl 요청 실행과 결과 JSON 생성 |
| `lab-reasoning.mjs` | DeepSeek 설정 확인·모델 요청 취소 연결과 제한된 curl JSON 계획 |
| `local-server.mjs` | 정적 파일·실행 API·SSE를 제공하는 loopback 서버 |
| `server.mjs` | 서버 listen 진입점 |
| `../start.mjs` | 프로젝트 루트 시작 스크립트 |

## 검증

대시보드 디렉터리에서 다음 명령을 사용합니다.

```powershell
npm run check
npm test
```

검증 범위는 engine fixture와 기록 직렬화, 코어의 단일 반복·요청/응답 관측·중단 처리, 서버 API와 SSE, loopback 제한, 실제 모듈 어댑터와 정적 파일 응답입니다. 로컬 XSS 통합 테스트는 임시 게시판에서 관찰 → DB 참고 조회 → 제한된 POST → 독립 브라우저 실행 증거 → finding·보고서까지 확인합니다. 잘못된 마커·게시글·순서·요청 범위를 거부하는 테스트도 포함합니다. DeepSeek 요청은 가짜 클라이언트로 대체해 비용 없이 검사하며, 브라우저 테스트에는 Playwright Chromium 설치가 필요합니다. 브라우저에서는 두 시작 경로, 진행·중지, 새로고침 후 현재 실행 복원, Agent I/O, 이력과 JSON 내보내기를 확인합니다.

앱 내 브라우저에서는 JSON 내보내기의 파일 저장 완료를 확인하지 못했습니다. 최종 다운로드는 Chrome 또는 Edge에서 확인하세요.

## 추가 제안

1. 저장된 로컬 실행 보고서를 화면에서 다시 읽고 실행 간 비교.
2. 이력 삭제와 보관 기간 설정.
3. 수집 로그가 추가될 때 토큰·쿠키·개인정보 마스킹과 열람 권한 분리.

외부 업로드와 배포는 이 실행 경로에 포함하지 않습니다.
