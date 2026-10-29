# CA3P
Future Security Lab 지원사업으로 진행하는 CA3P 프로젝트에 대한
국립창원대학교 CASPER의 자료 공유 repository 입니다.

팀 내부에서 실행 입출력, 모델 선택, 영속 실행 이력, 모듈 변경 및 결과 비교를 확인하는 통합 대시보드입니다. API·application·worker·contracts·run-store·evaluation을 분리하고 기존 parser/attack/guardrail/knowledge 모듈을 계약 어댑터로 연결합니다. `integration-manifest.json`이 포함·대체 모듈 및 의존 경계를 명시합니다.

[CI/CD 실행·배포 안내](docs/CI_CD.md), [이 장치에서 외부 접속하기](docs/DEVICE_DEPLOYMENT.md), [모듈 구조](docs/ARCHITECTURE.md)를 참고하세요. Node.js 24, Python 3.11+를 사용하며 전체 검증은 `npm run verify`입니다. GitHub PR의 `integration-gate`는 모든 모듈, 실제 Chromium 통합 및 Docker health check를 요구합니다.

## 별도 대학 사이트 실습

[`vul-web2`](vul-web2/README.md)의 대한대학교와 원창대학교는 기존 `vul-web-1` 게시판과 별도 이미지·컨테이너·네트워크·SQLite 볼륨에서 실행합니다. 각 사이트는 호스트의 `127.0.0.1:4101`과 `127.0.0.1:4102`에만 공개됩니다. 대시보드의 **실습 대상**에서 대학을 선택하고 에이전트가 접속할 IP·포트를 입력하면, 기존 IDOR 검증을 worker에서 실행하고 이벤트·판정·JSON 보고서를 중앙 실행 이력에 저장합니다. 실행 권한이 있는 관리자 계정이 필요하며 조회 계정은 저장된 결과만 볼 수 있습니다.

```sh
npm ci --prefix vul-web2
docker compose -f vul-web2/compose.yaml up --build -d --wait
node vul-web2/scripts/deployment-check.mjs
npm --prefix vul-web2 run probe:idor
docker compose -f vul-web2/compose.yaml down
```

`probe:idor`는 기존 `guardrail`의 정책 평가기와 `attack-module`의 제한된 curl 실행기를 사용해 두 사이트의 알려진 가상 레코드만 읽습니다. 담당자 본인·다른 담당자·학생 세션의 응답을 비교하며 로그인 정보와 레코드 본문은 결과에 남기지 않습니다. CLI는 두 고정 루프백 주소를 사용합니다. 대시보드에서는 대학 프로필과 내부 HTTP 원점만 선택할 수 있고, 본문·경로·임의 명령은 입력하지 않습니다. 알려진 조회번호 1·3에 대한 GET 네 건을 허용하며, 규칙 기반 판정으로 모델 API를 호출하지 않습니다. IDOR는 JSON 보고서를 제공하고 XSS용 과거 사례 DB 기록과 HWPX 생성은 건너뜁니다. 이 검사는 범용 CERT 자동 탐색을 수행하지 않습니다. 더 넓은 사이트 기능 검증은 `npm --prefix vul-web2 run smoke`로 실행하며 임시 DB와 컨테이너를 사용합니다.

Mac의 대시보드가 직접 실행 중이면 대한대는 `127.0.0.1:4101`, 원창대는 `127.0.0.1:4102`를 입력합니다. 주소는 사용자 브라우저가 아닌 **에이전트 서버 기준**입니다. 내부 IPv4(10/8, 172.16/12, 192.168/16)·루프백과 `localhost`, `host.docker.internal`, `daehan`, `wonchang`만 허용합니다. 사이트를 외부에 공개할 필요는 없습니다.

대시보드도 Docker로 실행하면 별도 대학 네트워크에 연결하는 overlay를 사용합니다. 대학 Compose를 먼저 시작하고 다음 명령으로 대시보드를 올린 뒤, 주소에 각각 `daehan:4101`, `wonchang:4102`를 입력합니다.

```sh
docker compose -f vul-web2/compose.yaml up --build -d
docker compose -f docker-compose.yml -f docker-compose.vul-web2.yml up --build -d
```

기존 `127.0.0.1:4173` 대시보드와 실행 이력을 유지하면서 별도 내부 사이트 실험 환경을 준비하려면 Windows PowerShell에서 다음 스크립트를 실행합니다. 대학 사이트를 시작하고, 전용 Compose 프로젝트·볼륨을 사용하는 대시보드를 `127.0.0.1:4175`에 띄운 뒤 두 사이트의 컨테이너 내부 접속과 HTTP 상태를 검증합니다. 기존 4173 컨테이너는 재생성하지 않습니다.

```powershell
.\scripts\start-local-internal-experiment.ps1
```

스크립트가 출력하는 명령으로 **4175 실험 대시보드의 별도 관리자 계정**을 확인하세요. 실습 대상을 선택하면 대한대학교 `http://daehan:4101`, 원창대학교 `http://wonchang:4102`가 기본 주소로 입력됩니다. 범용 루프 실행에는 `agent/.env`의 모델 API 설정이 필요합니다.

# CI/CD 및 대시보드 테스트 가이드

## 1. 변경 전 로컬 검증

프로젝트 루트에서 아래 명령을 실행합니다(Bash/macOS/Linux 기준). Node.js 24, Python 3.11+, `curl`이 필요하고, Linux의 Chromium 시스템 의존성 설치 방법은 [CI/CD 안내](docs/CI_CD.md)를 참고하세요.

```sh
npm ci --prefix web-parser
npm ci --prefix packages/report/capture
python3 -m venv .venv
.venv/bin/python -m pip install -r casper-db/requirements-ci.lock
.venv/bin/python -m pip install -r packages/report/requirements-ci.lock
.venv/bin/python -m pip install --no-deps -e ./casper-db -e ./packages/report/py
(cd web-parser && npx playwright install chromium)
CASPER_DB_PYTHON="$PWD/.venv/bin/python" npm run verify
```

`reports/ci/latest.json`에서 `completeSuite: true`, `status: "passed"`, 실패·skip 0건을 확인합니다. 모듈별 로그와 pytest XML도 `reports/ci/`에 남습니다. 준비 단계에서 중단되면 `completeSuite`는 `false`이며 실패 보고서가 남습니다. `--node-only`, `--modules`, `--skip-preflight`는 부분 점검용이므로 PR의 전체 검증을 대신하지 않습니다. CI는 실제 Chromium과 격리 실습 대상을 사용하지만 유료 모델 API를 호출하지 않습니다.

## 2. PR 및 배포 확인

`feature/<module>/<change>` 브랜치에서 `develop`으로 PR을 엽니다. GitHub Actions는 PR 브랜치와 현재 `develop`을 합친 후보 커밋에서 **활성 모듈 전체**를 검사합니다. `tests`와 `container-smoke`가 모두 통과하고 최종 `integration-gate`가 성공했는지 확인한 뒤 담당자 승인을 받아 병합합니다. 실패한 경우 해당 Actions 실행의 `ci-report-<검사한 SHA>` artifact에서 JSON·모듈별 로그·pytest XML을 확인하세요.

병합 후 `develop`의 실제 커밋에 대해 같은 전체 검증을 다시 실행합니다. `publish-ci-summary`는 그 실행의 테스트 건수·통과/실패/건너뜀, 이전 통합 실행 이후 변경된 모듈 ID 및 세 CI job 결론만 공개 `ci-results` 브랜치에 기록합니다. 장치 서버는 시작할 때와 이후 5분마다 이 요약을 가져와 `.runtime/ci-results/index.json`에 보관합니다. 인증 후 **통합 테스트** 화면에서 `develop` 실행 이력과 모듈별 변화를 확인합니다. 공개 피드에는 입력값·취약점 증거·모듈 로그가 없으며, 상세 원인은 Actions artifact에서 확인합니다. 피드가 아직 없을 때는 Actions 단계별 결론만 표시되고 모듈별 수치는 `자료 없음`으로 표시됩니다. 이 CI 결과는 대시보드에서 직접 실행한 격리 실습 run의 finding·모델 결과와 별개입니다.

PR 실행은 병합 전 후보 검증으로 Actions에서 확인합니다. 담당자의 리뷰와 저장소 보호 규칙에 따라 사람이 병합하며, 장치 updater는 PR을 승인하거나 병합하지 않습니다. `develop`/`main`의 성공한 push는 GHCR 이미지 게시까지 수행합니다. 별도의 Linux staging 자동 배포는 `ca3p-deploy` self-hosted runner와 `CA3P_AUTO_DEPLOY=true`가 설정된 경우에만 실행됩니다.

이 Mac에는 [장치 updater](docs/DEVICE_DEPLOYMENT.md#검증된-develop-자동-배포)를 설치할 수 있습니다. 설치하면 **120초마다 현재 `develop` HEAD와 정확히 같은 병합 후 push CI**의 전체 성공을 확인한 뒤 대시보드·활성 모듈과 대학 실습 이미지를 배포합니다. PR 브랜치·이전 SHA의 성공 결과는 배포 근거로 사용하지 않습니다. 검사가 진행 중이면 종료할 때까지 미루고, 후보별 Python 환경·복제 DB 이전·격리 smoke 검증을 통과한 후 서비스와 DB를 전환합니다. 계정·모델 키·HTTPS 프록시·저장 데이터는 유지하며, 전환 실패 시 백업과 이전 릴리스로 자동 복구합니다. 구성 예시는 [`docs/device-deploy.example.json`](docs/device-deploy.example.json)에 있습니다. CI 요약 수집만 사용하는 장치에는 자동 배포가 적용되지 않습니다.

## 3. 대시보드 기능 테스트

Docker Compose로 시작하거나, 위 로컬 의존성을 준비한 뒤 다음 명령으로 시작합니다. 기본 주소는 `http://127.0.0.1:4173`입니다.

```sh
CASPER_DB_PYTHON="$PWD/.venv/bin/python" npm start
```

첫 시작 때 생성되는 `.runtime/access.txt`의 `admin` 계정으로 로그인합니다(Docker에서는 `docker compose exec dashboard cat /app/.runtime/access.txt`). `viewer` 계정은 결과 조회만 할 수 있습니다. 다음 순서로 확인합니다.

1. **실습 실행**: 서버가 생성한 격리 게시판 `vul-web-1`은 **범용 취약점 점검**으로 실행합니다. `agent/.env`에 DeepSeek 키가 필요하며 API 비용이 발생할 수 있습니다. 키 없이 확인하려면 대학 사이트를 시작한 뒤(위 `vul-web2` 안내) 대학 대상에서 **기존 IDOR 검사**와 규칙 기반 모델을 고릅니다. 실행이 완료되는지 확인합니다.
2. **결과 확인**: **대시보드**의 모듈 노드에서 요청·응답과 Agent I/O를 보고, **실행 이력**에서 같은 run을 다시 엽니다. **리포트**에서 finding의 증거와 실행 조건을 확인합니다. 두 번 실행한 뒤 **실행 비교**에서 모델·모듈 digest·finding·처리 지연 차이를 확인하고, **통합 테스트**에서 수집된 `develop` 전체 모듈 검증 결과를 봅니다. 입력·환경이 다른 실행은 동등한 조건의 성능 비교로 해석하지 않습니다.

### Workspace AI 채팅

**AI 채팅 → 새 대화**에서 DeepSeek Flash·V4 Pro 또는 이 장치의 로컬 모델을 선택합니다. 로컬 모델은 서버에서 Ollama·LM Studio·llama.cpp·Docker Model Runner의 모델 목록을 조회하며, 인증이 필요하거나 연결할 수 없으면 그 상태를 표시합니다. 대화별로 이름·모델·기록을 관리하며, 같은 계정으로 다시 로그인하면 대화를 이어갈 수 있습니다. `admin`·`operator`는 채팅을 사용할 수 있고 `viewer`는 자신의 저장된 대화를 조회합니다. 모델 키는 서버 설정에서만 사용하며 브라우저에는 전달하지 않습니다.

DeepSeek는 기존 `agent/.env` 설정을 사용합니다. 로컬 서버의 주소·인증 키는 같은 파일 또는 서버 환경변수의 `CA3P_CHAT_LOCAL_ENDPOINT`, `CA3P_CHAT_LOCAL_API_KEY`로 지정합니다. 예를 들어 llama.cpp는 `CA3P_CHAT_LOCAL_ENDPOINT=http://127.0.0.1:18080/v1`, `CA3P_CHAT_LOCAL_RUNTIME=llama-cpp`로 설정합니다. `CA3P_CHAT_LOCAL_MODEL`은 모델 이름, `CA3P_CHAT_LOCAL_CONTEXT_TOKENS`는 서버에 설정한 문맥 한도입니다. 설정 후 대시보드 서버를 재시작하고 **새로고침**으로 모델 목록을 다시 확인합니다. 주소는 루프백만 허용하며 키가 포함된 설정 파일은 Git에 올리지 않습니다.

**로컬 파일**에서 작업 폴더를 탐색하고 내용을 미리 본 뒤 파일을 첨부합니다. 최대 세 개의 파일과 저장된 실행 결과를 질문에 함께 전달할 수 있습니다. 첨부 선택은 대화별로 유지되며 직접 제거하거나 변경할 수 있습니다. 파일 접근은 서버 작업 폴더 안의 소스·문서 읽기로 제공됩니다. 기본 작업 폴더는 실행 중인 프로젝트이고, 운영자가 `CA3P_CHAT_WORKSPACE_ROOT`로 실제 폴더 경로를 지정할 수 있습니다.

컨텍스트 막대는 **선택한 모델의 애플리케이션 입력 예산에 대한 추정치**입니다. DeepSeek는 8,000토큰이며, 로컬 모델은 서버 문맥 한도에서 응답 공간과 여유분을 뺀 값을 사용합니다(기본 8,192토큰 서버에서 입력 예산 5,632토큰). 모델 제공자의 전체 컨텍스트 한도와는 별도이며, 마지막 응답의 실제 입력·출력 토큰도 함께 표시합니다. 다음 요청의 예상 입력이 입력 예산의 80%에 도달하면 오래된 대화를 같은 모델로 자동 요약합니다. 긴 메시지가 있으면 남겨둘 최근 대화 수를 조정하고, 원문 기록과 압축 요약은 각각 보존합니다. **지금 압축**으로 수동 요약도 가능합니다. 채팅·요약 모두 선택한 모델을 사용합니다.

긴 기록은 모델 입력 한도에 맞춰 최대 8회로 나누어 요약하며, 모든 요약이 성공한 뒤에만 저장한 압축 경계를 갱신합니다. 중간에 실패하면 기존 요약과 원문을 유지합니다.

대화는 사용자별로 분리된 SQLite 저장소 `.runtime/chat.sqlite`에 저장합니다. 경로는 `CA3P_CHAT_DB_PATH`로 지정할 수 있습니다. 장치 updater는 이 저장소도 실행 기록·Case DB와 함께 백업·복원합니다. CI는 가짜 모델 응답으로 대화·압축·파일 접근·인증을 검증하며 실제 모델을 호출하지 않습니다.

## 4. 이 장치에서 외부 접속 테스트

이 Mac의 고정 접속 주소는 [https://macmini.casper.or.kr](https://macmini.casper.or.kr)입니다. Nginx Proxy Manager가 HTTPS를 종료하고 이 장치의 4175 포트로 전달합니다. 외부 브라우저에서 `viewer`로 로그인해 실행 이력·리포트·비교와 **통합 테스트**를 확인하세요. 비밀번호는 이 장치의 `.runtime/access.txt`에 있으며 Git에 올리지 않습니다.

```sh
curl -fsS https://macmini.casper.or.kr/api/health
curl -sS -o /dev/null -w '%{http_code}\n' https://macmini.casper.or.kr/api/runs
```

첫 명령은 `{"status":"ok"}`, 두 번째는 미로그인 상태에서 `401`이어야 합니다. Mac의 서비스와 updater는 사용자 로그인 후 자동 시작됩니다. 서비스 상태는 `launchctl print gui/$(id -u)/kr.or.casper.ca3p.macmini-dashboard`, 배포 감시는 `launchctl print gui/$(id -u)/kr.or.casper.ca3p.device-deploy`로 확인합니다. **통합 상태**의 실행 소스 SHA와 장치 배포 상태를 함께 확인하세요. **통합 테스트**의 최신 CI 성공만으로 배포 완료를 판단하지 않습니다. 자동 배포 설치·중지·재개·실패 진단과 임시 Cloudflare 주소는 [장치 배포 안내](docs/DEVICE_DEPLOYMENT.md)를 참고하세요.

# Docker Compose 실행

Docker Engine과 Docker Compose v2.24 이상이 필요합니다. 프로젝트 루트에서 대시보드를 빌드하고 시작합니다.

```powershell
docker compose up --build -d
docker compose logs -f dashboard
```

Windows에서 화면 코드를 수정한 뒤 실행 중인 대시보드에 반영하려면 `.\scripts\redeploy-local-dashboard.ps1`을 실행합니다. 스크립트는 이미지를 빌드하고 대시보드 컨테이너만 재생성한 뒤 이미지·화면 파일·HTTP 응답을 확인합니다. 처음으로 내부 사이트 네트워크를 연결할 때는 `-InternalSites` 옵션을 사용하며, 이후 재배포에서는 연결을 유지합니다. 이미지 삭제나 빌드만으로는 실행 중인 컨테이너가 교체되지 않으며, 저장된 계정·DB·보고서 볼륨은 유지됩니다.

브라우저에서 [CA3P 로컬 대시보드](http://127.0.0.1:4173)를 엽니다. Compose는 호스트의 `127.0.0.1:4173`에만 포트를 공개합니다. 컨테이너 시작만으로 모델 API 호출이나 사이트 검사는 진행되지 않습니다. 화면에서 실습 대상과 검사 방식을 고른 뒤 실행합니다.

시작 시 관리자(`admin`)와 조회 전용(`viewer`) 계정을 생성합니다. 로컬 접속 정보는 `.runtime/access.txt`에 저장되고 Docker에서는 `/app/.runtime/access.txt`에 있습니다. 이 파일은 Git과 이미지에 포함되지 않습니다. 로그인 후 모델을 선택하고 실행 이력·모듈·리포트·결과 비교를 확인합니다. 외부 공유 주소는 `DASHBOARD_PUBLIC_ORIGIN`을 해당 HTTPS origin으로 설정합니다.

DeepSeek를 사용하는 로컬 실습에는 `agent/.env.example`을 참고해 `agent/.env`에 `DEEPSEEK_API_KEY`를 설정한 뒤 컨테이너를 시작하세요. 대학 IDOR 검사에는 이 파일이 필요하지 않습니다. 키는 Git이나 Docker 이미지에 포함하지 마세요. 로컬 실습은 저장소의 격리된 게시판만 대상으로 사용하며 모델 API 호출에는 과금이 발생할 수 있습니다.

`casper-db`의 통합 SQLite 파일과 기존 실행 보고서는 Docker named volume에 보존됩니다. 컨테이너를 내렸다가 다시 올려도 이 데이터는 남습니다. 기존 호스트의 `casper-db/data/cases.sqlite3`와 `reports/`는 새 컨테이너에 자동으로 복사되지 않습니다. 기존 과거 사례 DB가 필요하면 실습을 실행하지 않는 상태에서 `docker compose cp casper-db/data/cases.sqlite3 dashboard:/app/casper-db/data/cases.sqlite3`로 가져올 수 있습니다. 개별 보고서는 대시보드의 JSON 내보내기로 저장할 수 있습니다.

```powershell
docker compose down
```

저장된 DB와 보고서까지 삭제하려는 경우에만 `docker compose down -v`를 사용합니다.

# 로컬 워크스페이스 실행

통합 로컬 실습에는 Node.js 24, Python 3.11 이상과 `curl`이 필요합니다. 먼저 `web-parser`의 브라우저와 `casper-db` 의존성을 준비합니다.

```powershell
cd web-parser
npm ci
npx playwright install chromium
cd ..
python -m pip install -e .\casper-db
python -m pip install -r .\packages\report\requirements-ci.lock
python -m pip install --no-deps -e .\packages\report\py
npm ci --prefix packages/report/capture
```

프로젝트 루트에서 다음 명령으로 대시보드를 시작합니다.

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

루트 시작 스크립트는 대시보드와 로컬 실행 서버를 엽니다. 실습 대상과 검사 방식을 고르고 실행하면 worker가 실행을 처리합니다.

`vul-web-1` 게시판을 고르면 서버가 게시판을 `127.0.0.1`의 임시 포트와 별도 데이터 파일로 시작하고 **범용 취약점 점검**을 실행합니다. DeepSeek 모델이 여러 가설을 제안하고, 런타임은 등록된 대상·경로·요청 예산 안에서 읽기 관측과 독립 확정 도구를 실행합니다. 범용 경로에는 브라우저 실행을 확인하는 도구가 없어서 브라우저 증거가 필요한 XSS는 확정하지 않습니다. 대학 대상(`vul-web2`)에서는 범용 점검이나 규칙 기반 **기존 IDOR 검사**를 고를 수 있습니다.

기존 단일 검사는 폐기됐습니다. 여기에는 코어 fixture, 게시판 저장형 XSS `stored_xss_canary`, 교차 사용자 삭제 `agent_cross_user_delete_canary`가 포함됩니다. 이전에 저장된 실행은 실행 이력·리포트·비교에서 계속 읽습니다.

DeepSeek 모델을 선택할 때는 `agent/.env` 또는 환경변수의 `DEEPSEEK_API_KEY`가 필요하고 API 호출에 과금이 발생할 수 있습니다. `npm start` 자체로는 실습이나 모델 호출을 시작하지 않습니다. 게시판 대상은 서버가 만든 로컬 게시판으로 고정하며 입력한 임의 URL에는 접속하지 않습니다.

| 모듈 | 현재 형태 | 루트 스크립트 동작 |
| --- | --- | --- |
| `agent-dashboard` | 정적 화면 | API와 연결 |
| `apps/api` | 인증·HTTP·SSE 및 플랫폼 상태 | 시작 |
| `apps/application`, `apps/worker` | 실행 서비스·독립 실행 프로세스 | 실행 요청 때 worker 시작 |
| `packages/contracts`, `run-store`, `evaluation`, `models` | 계약·SQLite 기록·비교·모델 선택 | API와 worker에서 사용 |
| `packages/adapters`, `history` | web-parser·attack·guardrail·지식 DB 연결 및 검증 이력 동기화 | worker에서 사용 |
| `agent` | 범용 판단 코어·DeepSeek 플래너 | 범용 점검에서 실행 |
| `web-parser` | Chromium 기반 대상 페이지 읽기 전용 수집 | 범용 점검의 관측 단계에서 실행 |
| `casper-db` | 사례·공개 권고·공격 정보·미래 템플릿의 통합 DB | 위치·제품 기반 조회와 버전·근거 제공 |
| `attack-module` | JSON curl 요청의 검증·전송·성공/실패 JSON 응답 | 대학 IDOR 검사의 제한된 GET 실행 |
| `guardrail` | 요청 범위·예산 정책 평가 | 대학 IDOR 검사의 `attack-module` 전송 직전에 실행; 별도 상주 프로세스 없음 |
| `vul-web-1` | 독립 실습용 서버 | 로컬 실습 버튼을 누르면 격리된 임시 인스턴스 시작 |

중지는 진행 중인 게시판·모델 요청을 취소하며 일시정지는 지원하지 않습니다. 전체 검증은 `npm run verify`입니다. CI에서는 Chromium을 반드시 준비하고 필수 테스트 skip을 실패로 처리합니다. DeepSeek는 가짜 클라이언트로 대체해 모델 비용 없이 실행 계약을 검증합니다.

실행과 이벤트는 중앙 SQLite registry에 저장하고 서버 조회로 이력을 다시 엽니다. `CA3P_STORE_PATH`로 DB 위치를 설정하며 Docker는 `.runtime` named volume을 사용합니다. 기존 실습 이벤트·보고서는 `reports/pentest-db-runs/`에도 유지합니다. 결과 비교에서 기준·후보 run을 골라 모델, 모듈 digest와 finding 및 처리 지연 차이를 확인합니다. 입력·환경이 다른 실행은 동등한 조건의 실험과 구분합니다.

`xss-fuzzer`는 현재 parser/attack 실행 경로로 대체됐고, `xss-parser`는 `web-parser`로 대체되어 저장소에서 삭제됐습니다. 원래 브랜치는 참고용으로 유지하며 상태는 integration-manifest에 기록합니다.

## 실행 후 HWPX 보고서

실제 로컬 실습의 검사 결과를 저장한 뒤 worker가 보고서 모듈을 자동 실행합니다. 범용 점검에서는 최종 `findings[]` 중 현재 검사 증거로 `confirmed` 판정을 받은 항목마다 HWPX 초안 한 개를 작성합니다. 다른 판정은 실행 JSON과 대시보드에 남으며, 확정 항목이 없으면 HWPX를 만들지 않습니다. 이번 문서 생성은 가설별 finding을 기준으로 하므로 같은 취약점을 설명하는 확정 가설이 둘이면 문서도 둘입니다. 보고서 작성이 끝날 때까지 해당 실습 게시판을 유지하며, 문서 생성 실패가 기존 finding을 바꾸지 않습니다.

대시보드의 **리포트** 화면에 범용 점검의 finding별 문서 생성 상태와 다운로드 버튼이 표시됩니다. 저장된 과거 단일 검사에는 실행당 한 개의 다운로드 버튼이 표시됩니다. 로그인한 조회 계정도 내려받을 수 있고, 서버를 재시작하거나 **실행 이력**에서 해당 run을 열어도 파일이 유지됩니다. 기존 JSON 내보내기도 사용할 수 있습니다. 생성 전의 과거 이력에는 HWPX 파일이 없습니다.

범용 점검의 HWPX는 저장된 확정 finding과 증거로 작성하므로 보고서 모델을 추가로 호출하지 않습니다. 범용 점검 자체의 Agent 모델 호출에는 비용이 발생할 수 있습니다. 취소된 실행은 보고서 생성을 건너뜁니다.

Python은 `CA3P_REPORT_PYTHON`, `CASPER_DB_PYTHON`, 플랫폼 기본 Python 순서로 선택합니다. Windows의 프로젝트 가상환경을 사용한다면 실행 전에 아래처럼 지정하세요.

```powershell
$env:CASPER_DB_PYTHON = (Resolve-Path .\.venv\Scripts\python.exe).Path
$env:CA3P_REPORT_PYTHON = $env:CASPER_DB_PYTHON
npm start
```

보고서 작성은 문서별 기본 180초와 출력 크기 제한을 적용합니다. 완성된 HWPX는 실행 registry 옆 `artifacts/`에 해시로 보관하며 다운로드 때 실행 연결과 파일 무결성을 확인합니다. Docker에서는 기존 `.runtime` 볼륨에 보존됩니다. 보고서는 초안이므로 공유 전에 내용을 검토하세요. 상세 CLI와 출력 규약은 [보고서 모듈](packages/report/README.md)에 있습니다.

모델을 바꿔 비교할 때는 모델 선택 아래 **모델 변경 시 초기화 확인**을 사용할 수 있습니다. **예**를 선택하면 실행 이력·보고서·실험 체크를 삭제한 뒤 모델을 변경합니다. 비교 자료는 먼저 내보내세요. 수동 **실험 초기화**도 지원하며, 관리 훅이 없는 지속형 대학 대상은 전체 초기화를 완료할 수 없습니다. 조사 범위·기능 설계·관리 훅·연구상 한계는 [실험 초기화](docs/EXPERIMENT_RESET.md)를 확인하세요.

# PR 규칙
## 브랜치
작은 변경마다 `feature/<module>/<change>` 브랜치를 만들고 develop에 PR로 통합합니다. 기존 닉네임/모듈 장기 브랜치는 참고용으로 유지합니다.
`integration-gate`와 담당자 리뷰를 통과한 변경을 머지하고 main에는 검증된 release를 승격합니다.
## 수정
모듈별 담당 리뷰를 유지하고, 계약·공통 어댑터 변경에는 영향을 받는 모듈의 테스트를 함께 수행합니다.

`pentest-db` 독립 모듈은 `casper-db`로 대체했습니다. 기존 공격 정보는 같은 SQLite DB의 `attack_*` 테이블로 이관하며 향후 공격 템플릿은 그 revision과 검증 규칙을 참조해 등록합니다. 이관·템플릿 계약·호환 범위는 [DB 안내](casper-db/README.md#pentest-db-통합과-폐기)에 있습니다.

HTTP 기반 공격 정의를 실행하는 [Repeater](vul-web-1/scripts/REPEATER.md)와 [Intruder](vul-web-1/scripts/INTRUDER.md)도 같은 DB를 조회합니다. 실행 결과에는 사용한 공격 정보의 ID·revision·내용 해시와 단계별 근거를 남깁니다. 호출은 CLI·Node API로 제공하며 범용 Agent의 자동 도구 선택과 sLLM 연결은 별도 범위입니다.

### Attack tool

여러 AI가 접근하는 복수 포트 attack-tool daemon과 SQLi 패킷 템플릿이 추가되었습니다. 일반 평가 실행은 Agent → attack-tool → Guardrail → 실행기 경로를 사용합니다. [모듈 사용법](attack-tool/README.md)과 [이슈 #32 구현 계획](docs/ATTACK_TOOL_PLAN.md)을 참고하세요.
