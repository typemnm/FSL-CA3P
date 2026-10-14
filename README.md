# CA3P
Future Security Lab 지원사업으로 진행하는 CA3P 프로젝트에 대한
국립창원대학교 CASPER의 자료 공유 repository 입니다.

팀 내부에서 실행 입출력, 모델 선택, 영속 실행 이력, 모듈 변경 및 결과 비교를 확인하는 통합 대시보드입니다. API·application·worker·contracts·run-store·evaluation을 분리하고 기존 parser/attack/guardrail/knowledge 모듈을 계약 어댑터로 연결합니다. `integration-manifest.json`이 포함·대체 모듈 및 의존 경계를 명시합니다.

[CI/CD 실행·배포 안내](docs/CI_CD.md), [이 장치에서 외부 접속하기](docs/DEVICE_DEPLOYMENT.md), [모듈 구조](docs/ARCHITECTURE.md)를 참고하세요. Node.js 24, Python 3.11+를 사용하며 전체 검증은 `npm run verify`입니다. GitHub PR의 `integration-gate`는 모든 모듈, 실제 Chromium 통합 및 Docker health check를 요구합니다.

# Docker Compose 실행

Docker Engine과 Docker Compose v2.24 이상이 필요합니다. 프로젝트 루트에서 대시보드를 빌드하고 시작합니다.

```powershell
docker compose up --build -d
docker compose logs -f dashboard
```

브라우저에서 [CA3P 로컬 대시보드](http://127.0.0.1:4173)를 엽니다. Compose는 호스트의 `127.0.0.1:4173`에만 포트를 공개합니다. 컨테이너 시작만으로 모델 API 호출이나 사이트 검사는 진행되지 않습니다. 화면에서 **코어 fixture 시작** 또는 **로컬 실습 시작**을 눌러 실행합니다.

시작 시 관리자(`admin`)와 조회 전용(`viewer`) 계정을 생성합니다. 로컬 접속 정보는 `.runtime/access.txt`에 저장되고 Docker에서는 `/app/.runtime/access.txt`에 있습니다. 이 파일은 Git과 이미지에 포함되지 않습니다. 로그인 후 모델을 선택하고 실행 이력·모듈·리포트·결과 비교를 확인합니다. 외부 공유 주소는 `DASHBOARD_PUBLIC_ORIGIN`을 해당 HTTPS origin으로 설정합니다.

DeepSeek를 사용하는 로컬 실습에는 `agent/.env.example`을 참고해 `agent/.env`에 `DEEPSEEK_API_KEY`를 설정한 뒤 컨테이너를 시작하세요. 이 파일은 선택 사항이며 코어 fixture에는 필요하지 않습니다. 키는 Git이나 Docker 이미지에 포함하지 마세요. 로컬 실습은 저장소의 격리된 게시판만 대상으로 사용하며 모델 API 호출에는 과금이 발생할 수 있습니다.

`casper-db`의 SQLite 파일과 `pentest-db` 실행 보고서는 Docker named volume에 보존됩니다. 컨테이너를 내렸다가 다시 올려도 이 데이터는 남습니다. 기존 호스트의 `casper-db/data/cases.sqlite3`와 `reports/`는 새 컨테이너에 자동으로 복사되지 않습니다. 기존 과거 사례 DB가 필요하면 실습을 실행하지 않는 상태에서 `docker compose cp casper-db/data/cases.sqlite3 dashboard:/app/casper-db/data/cases.sqlite3`로 가져올 수 있습니다. 개별 보고서는 대시보드의 JSON 내보내기로 저장할 수 있습니다.

```powershell
docker compose down
```

저장된 DB와 보고서까지 삭제하려는 경우에만 `docker compose down -v`를 사용합니다.

# 로컬 워크스페이스 실행

통합 로컬 실습에는 Node.js 24, Python 3.11 이상과 `curl`이 필요합니다. 먼저 실제 `xss-parser` 브라우저와 `casper-db` 의존성을 준비합니다.

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

모델 선택에서 규칙 baseline 또는 등록된 DeepSeek 모델을 선택하고 **로컬 실습 시작**을 누르면 `vul-web-1` 게시판을 `127.0.0.1`의 임시 포트와 별도 데이터 파일로 시작합니다. 기본 실습은 `stored_xss_canary`의 단일 반복 저장형 XSS 검사입니다. `xss-parser`가 Chromium으로 입력 위치와 HTML 렌더링을 관찰하고 `casper-db`가 과거 사례와 대조하며 `pentest-db`가 초안 카탈로그를 반환합니다. 과거 일치나 카탈로그만으로 현재 취약점을 확정하지 않습니다.

Agent는 관찰한 입력 위치와 카탈로그 조언을 확인한 뒤 실행별 고유 마커를 가진 무해한 canary 게시글을 계획합니다. DeepSeek가 제안한 구조화된 curl JSON은 코어가 계산한 허용 `POST /api/posts` 요청과 정확히 일치해야 합니다. `guardrail`이 로컬 게시판·canary·요청 예산을 전송 직전에 평가하고, 허용된 한 번의 검사 POST를 `attack-module`이 실행합니다. 이어서 독립된 Chromium 관찰이 같은 게시글의 마커 콜백 실행 여부를 확인합니다. 코어의 결정론적 `reflect()`가 게시글 생성·표시·마커·브라우저 실행 증거를 묶어 finding을 판정하고 `pentest-db`에 이벤트와 보고서를 저장합니다. 각 요청·응답, guardrail 판정과 Agent 입출력은 실시간으로 표시합니다.

규칙 baseline은 API key 없이 실제 브라우저 실습을 수행합니다. DeepSeek 모델을 선택할 때는 `agent/.env` 또는 환경변수의 `DEEPSEEK_API_KEY`가 필요하고 API 호출에 과금이 발생할 수 있습니다. `npm start` 자체로는 실습이나 모델 호출을 시작하지 않습니다. 대상은 서버가 만든 로컬 게시판으로 고정하며 입력한 임의 URL에는 접속하지 않습니다. 과거 사례가 비어 있으면 일치 결과도 없습니다. 기존 삭제 권한 검사는 레거시 프로필로 유지합니다.

| 모듈 | 현재 형태 | 루트 스크립트 동작 |
| --- | --- | --- |
| `agent-dashboard` | 정적 화면 | API와 연결 |
| `apps/api` | 인증·HTTP·SSE 및 플랫폼 상태 | 시작 |
| `apps/application`, `apps/worker` | 실행 서비스·독립 실행 프로세스 | 실행 요청 때 worker 시작 |
| `packages/contracts`, `run-store`, `evaluation`, `models` | 계약·SQLite 기록·비교·모델 선택 | API와 worker에서 사용 |
| `packages/adapters`, `history` | parser·attack·guardrail·지식 DB 연결 및 검증 이력 동기화 | worker에서 사용 |
| `agent` | 단일 반복 코어·Reasoning Engine | fixture 또는 로컬 실습 모드에서 실행 |
| `xss-parser` | Chromium 기반 읽기 전용 관찰과 브라우저 실행 확인 | 검사 전 입력·sink 관찰, POST 후 별도 브라우저에서 canary 실행 확인 |
| `casper-db` | SQLite 과거 XSS 사례 매칭 | parser 관찰값을 대조하고 참고 판정 반환 |
| `pentest-db` | 초안 XSS 카탈로그·로컬 실행 기록 | 참고 정보 조회와 이벤트·보고서 파일 저장 |
| `attack-module` | JSON curl 요청의 검증·전송·성공/실패 JSON 응답 | 기본 실습에서 세션 GET과 제한된 검사 POST 실행 |
| `guardrail` | canary 범위·요청 예산 정책 평가 | `attack-module` 전송 직전에 실행; 별도 상주 프로세스 없음 |
| `vul-web-1` | 독립 실습용 서버 | 로컬 실습 버튼을 누르면 격리된 임시 인스턴스 시작 |

코어는 `maxIterations: 1`을 지원합니다. 중지는 진행 중인 게시판·모델 요청을 취소하며 일시정지는 지원하지 않습니다. 전체 검증은 `npm run verify`입니다. CI에서는 Chromium을 반드시 준비하고 필수 테스트 skip을 실패로 처리합니다. DeepSeek는 가짜 클라이언트로 대체해 모델 비용 없이 실행 계약과 브라우저 증거를 검증합니다.

실행과 이벤트는 중앙 SQLite registry에 저장하고 서버 조회로 이력을 다시 엽니다. `CA3P_STORE_PATH`로 DB 위치를 설정하며 Docker는 `.runtime` named volume을 사용합니다. 기존 실습 이벤트·보고서는 `reports/pentest-db-runs/`에도 유지합니다. 결과 비교에서 기준·후보 run을 골라 모델, 모듈 digest와 finding 및 처리 지연 차이를 확인합니다. 입력·환경이 다른 실행은 동등한 조건의 실험과 구분합니다.

`xss-fuzzer`는 현재 parser/attack 실행 경로로 대체됐습니다. 원래 브랜치는 참고용으로 유지하며 상태는 integration-manifest에 기록합니다.

# PR 규칙
## 브랜치
작은 변경마다 `feature/<module>/<change>` 브랜치를 만들고 develop에 PR로 통합합니다. 기존 닉네임/모듈 장기 브랜치는 참고용으로 유지합니다.
`integration-gate`와 담당자 리뷰를 통과한 변경을 머지하고 main에는 검증된 release를 승격합니다.
## 수정
모듈별 담당 리뷰를 유지하고, 계약·공통 어댑터 변경에는 영향을 받는 모듈의 테스트를 함께 수행합니다.
