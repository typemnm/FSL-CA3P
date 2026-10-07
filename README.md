# CA3P
Future Security Lab 지원사업으로 진행하는 CA3P 프로젝트에 대한
국립창원대학교 CASPER의 자료 공유 repository 입니다.

# 로컬 워크스페이스 실행

통합 로컬 실습에는 Node.js 20 이상, Python 3.11 이상과 `curl`이 필요합니다. 먼저 실제 `xss-parser` 브라우저와 `casper-db` 의존성을 준비합니다.

```powershell
cd xss-parser
npm ci
npx playwright install chromium
cd ..
python -m pip install -e .\casper-db
```

프로젝트 루트에서 다음 명령으로 대시보드를 시작합니다. 코어 fixture만 확인할 때는 위 설치가 필요하지 않습니다.

```powershell
npm start
```

또는 루트 시작 스크립트를 직접 실행합니다.

```powershell
node start.mjs
```

브라우저에서 [CA3P 로컬 대시보드](http://127.0.0.1:4173)를 엽니다. 실행 중인 터미널에서 `Ctrl+C`를 누르면 서버가 종료됩니다. 대시보드 서버는 `127.0.0.1`에만 바인딩됩니다. 로컬 실습을 선택하면 게시판용 자식 프로세스를 추가로 시작하고 종료 시 함께 정리합니다.

다른 포트가 필요하면 다음과 같이 지정합니다. 포트는 `1~65535` 범위의 정수여야 하며, 이미 사용 중인 포트를 지정하면 시작이 실패합니다.

```powershell
npm start -- --port 4174
node start.mjs --help
```

`--port`를 생략하면 환경변수 `PORT`, 그다음 기본값 `4173`을 사용합니다. 스크립트의 파일 경로를 기준으로 서버를 찾으므로 다른 디렉터리에서도 `node <프로젝트 경로>/start.mjs`로 실행할 수 있습니다.

## 현재 시작 범위

루트 시작 스크립트는 대시보드와 로컬 실행 서버를 엽니다. 화면의 **코어 fixture 시작**을 누르면 `agent/src/orchestrator.js`의 `runOnce()`가 규칙 기반 Reasoning Engine과 모의 모듈을 한 번 실행합니다. 입력한 URL은 이 모드에서 표시용이며 접속하지 않습니다.

화면의 **저장형 XSS 1회 실습 + DeepSeek**에서 **로컬 실습 시작**을 누르면 저장소의 `vul-web-1` 게시판을 `127.0.0.1`의 임시 포트와 별도 임시 데이터 파일로 시작합니다. 기본 실습은 `stored_xss_canary` 프로필의 단일 반복 저장형 XSS 검사입니다. `xss-parser`가 Chromium으로 게시판 한 페이지의 폼·POST 입력과 HTML 렌더링 위치를 읽기 전용으로 관찰합니다. `casper-db`는 그 관찰값을 SQLite의 과거 XSS 사례와 대조하고, `pentest-db`는 초안 공격 정보 카탈로그를 참고 자료로 반환합니다. 과거 일치나 카탈로그 항목만으로 현재 취약점을 확정하지 않습니다.

Agent는 관찰한 입력 위치와 카탈로그 조언을 확인한 뒤 실행별 고유 마커를 가진 무해한 canary 게시글을 계획합니다. DeepSeek가 제안한 구조화된 curl JSON은 코어가 계산한 허용 `POST /api/posts` 요청과 정확히 일치해야 합니다. `guardrail`이 로컬 게시판·canary·요청 예산을 전송 직전에 평가하고, 허용된 한 번의 검사 POST를 `attack-module`이 실행합니다. 이어서 독립된 Chromium 관찰이 같은 게시글의 마커 콜백 실행 여부를 확인합니다. 코어의 결정론적 `reflect()`가 게시글 생성·표시·마커·브라우저 실행 증거를 묶어 finding을 판정하고 `pentest-db`에 이벤트와 보고서를 저장합니다. 각 요청·응답, guardrail 판정과 Agent 입출력은 실시간으로 표시합니다.

이 실습을 시작하려면 `agent/.env` 또는 프로세스 환경변수에 `DEEPSEEK_API_KEY`가 필요합니다. API 호출에는 과금이 발생할 수 있고 실패 시 기본 1회, 설정에 따라 최대 2회 재시도할 수 있습니다. `npm start` 자체로는 게시판 검증이나 모델 호출을 시작하지 않습니다. 실습 대상은 서버가 만든 소유 로컬 게시판으로 고정되며, 화면에 입력한 임의 URL은 실습 대상이 되지 않습니다. `casper-db`의 기본 SQLite 파일은 비어 있으면 생성되며, 기존 사례가 없을 때 과거 일치 결과도 없습니다. 기존 교차 사용자 삭제 검사(`agent_cross_user_delete_canary`)는 명시적으로 선택할 수 있는 레거시 프로필이며, 대시보드 기본 실습은 XSS입니다. 코어 fixture는 모의 응답을 사용하고 입력 URL에 접속하지 않습니다.

| 모듈 | 현재 형태 | 루트 스크립트 동작 |
| --- | --- | --- |
| `agent-dashboard` | 정적 화면·로컬 실행 API·SSE 서버 | 시작 |
| `agent` | 단일 반복 코어·Reasoning Engine | fixture 또는 로컬 실습 모드에서 실행 |
| `xss-parser` | Chromium 기반 읽기 전용 관찰과 브라우저 실행 확인 | 검사 전 입력·sink 관찰, POST 후 별도 브라우저에서 canary 실행 확인 |
| `casper-db` | SQLite 과거 XSS 사례 매칭 | parser 관찰값을 대조하고 참고 판정 반환 |
| `pentest-db` | 초안 XSS 카탈로그·로컬 실행 기록 | 참고 정보 조회와 이벤트·보고서 파일 저장 |
| `attack-module` | JSON curl 요청의 검증·전송·성공/실패 JSON 응답 | 기본 실습에서 세션 GET과 제한된 검사 POST 실행 |
| `guardrail` | canary 범위·요청 예산 정책 평가 | `attack-module` 전송 직전에 실행; 별도 상주 프로세스 없음 |
| `vul-web-1` | 독립 실습용 서버 | 로컬 실습 버튼을 누르면 격리된 임시 인스턴스 시작 |

코어는 `maxIterations: 1`을 지원합니다. 일시정지는 지원하지 않습니다. 중지 시 진행 중인 게시판·모델 요청을 취소하고, 코어의 실패 보고서와 화면의 중지 상태를 구분합니다. 검증은 `cd agent; npm test`와 `cd agent-dashboard; npm run check; npm test`로 실행할 수 있습니다. 대시보드 테스트는 DeepSeek를 가짜 클라이언트로 대체하며, Chromium이 설치된 경우 실제 로컬 게시판의 XSS 한 번 실행과 브라우저 증거까지 확인합니다.

브라우저를 새로고침해도 서버가 살아 있으면 SSE 연결을 다시 맺고 현재 실행을 복원합니다. 화면의 현재 실행 상태는 서버 메모리에 있고 브라우저에는 최근 12개 실행 이력이 저장됩니다. 실제 로컬 실습의 이벤트와 최종 보고서는 `reports/pentest-db-runs/`에도 저장됩니다. 화면에서 다시 열 수 있는 이력과 로컬 저장 파일은 별개이므로 공유가 필요하면 JSON 내보내기를 사용하세요.

`xss-fuzzer`는 기존 통합 제외 범위를 유지합니다. 세션 제어, 연결 상태와 검증 명령은 [agent-dashboard/README.md](./agent-dashboard/README.md)에 있습니다.

# PR 규칙
## 브랜치
각 모듈마다 브랜치를 새로 설정합니다.
브랜치명은 `닉네임/디렉토리이름(혹은 모듈명)`으로 통일합니다.
## 수정
다른 사람의 작업을 마음대로 수정하지 않기로 합니다.
우선 수정해도 되는지, 어떤 범위를 수정할 것인지 모듈 담당자와 얘기 후 진행합니다.
