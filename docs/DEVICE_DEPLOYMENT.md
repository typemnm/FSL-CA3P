# 이 Mac에서 팀 대시보드 외부 접속

고정 주소는 [https://macmini.casper.or.kr](https://macmini.casper.or.kr)이다. 공개 DNS는 이 네트워크의 공인 IP를 가리키고, 내부 DNS는 Nginx Proxy Manager(`192.168.0.3`)를 가리킨다. Proxy Host는 `macmini.casper.or.kr`의 HTTP 요청을 HTTPS로 전환하고 Let's Encrypt 인증서로 TLS를 종료한 다음 이 Mac의 `192.168.0.84:4175`에 전달한다. 기존 `ca3p.casper.or.kr:4173` Docker 대시보드는 별도 서비스다. Nginx Proxy Manager의 관리 포트 81을 외부 대시보드 주소로 프록시하지 않는다.

## 접속 및 검증

브라우저에서 고정 주소를 연다. 첫 시작 때 생성된 `.runtime/access.txt`의 `viewer`는 실행 이력·모델·입출력·모듈 및 두 실행의 차이·병합 후 **통합 테스트**를 조회할 수 있다. `admin`은 실행과 검토 작업을 할 수 있다. 이 파일은 장치 사용자만 읽을 수 있으며 Git과 이미지에서 제외된다. 팀원에게 필요한 계정의 비밀번호는 별도 안전한 경로로 전달한다. 로그인 세션은 8시간이며 변경 요청에는 CSRF 토큰이 필요하다.

```sh
curl -fsS https://macmini.casper.or.kr/api/health
curl -sS -o /dev/null -w '%{http_code}\n' https://macmini.casper.or.kr/api/runs
curl -sS -I http://macmini.casper.or.kr/
```

차례로 `{"status":"ok"}`, 미로그인 `401`, HTTPS 주소로 향하는 `301`이 나와야 한다. 2026-10-15에는 Nginx Proxy Manager에서 인증서와 호스트가 **Online**임을 확인했고, 외부 검사 노드 3곳에서 HTTPS `/api/health`가 200을 반환했다. 인증서 만료와 자동 갱신 상태는 Nginx Proxy Manager의 **Certificates**에서 확인한다.

## 이 장치의 서버 운영

대시보드는 사용자 LaunchAgent `kr.or.casper.ca3p.macmini-dashboard`가 로그인 시 시작하고 장애 후 재시작한다. updater를 설치하면 서비스는 `deployRoot/current/start.mjs`와 해당 릴리스의 `.venv`를 사용한다. 인증·실행 DB·증거·기존 JSON 보고서는 원래 공유 경로에 남는다. `current`는 검증된 릴리스를 가리키는 심볼릭 링크다. Mac 재부팅 후 사용자가 로그인하기 전에는 대시보드와 updater 모두 시작되지 않으며, 대학 실습 갱신에는 Docker Desktop도 실행 중이어야 한다.

```sh
launchctl print gui/$(id -u)/kr.or.casper.ca3p.macmini-dashboard
tail -n 100 .runtime/macmini-dashboard.err.log
```

현재 프로세스의 포트는 4175이고, Nginx Proxy Manager가 이 포트에 접근하려면 Mac의 LAN IP가 `192.168.0.84`로 유지돼야 한다. IP가 바뀌면 Nginx Proxy Manager의 Forward Hostname/IP 및 서버의 `DASHBOARD_HOST`를 함께 수정한다. Nginx Proxy Manager 뒤에서 로그인 시도 제한을 방문자별로 적용하려면 LaunchAgent 환경에 `DASHBOARD_TRUSTED_PROXY_IPS=192.168.0.3`을 설정한다. 프록시의 **IP만** 적고 관리 포트 `:81`은 넣지 않는다. 이 주소에서 온 요청에 한해 프록시가 전달한 `X-Forwarded-For`의 마지막 IP를 사용하며, 그 밖의 접속자가 보낸 헤더는 신뢰하지 않는다. 설정 변경·수동 재시작은 검사와 배포가 끝난 뒤 수행한다. 데이터는 `.runtime/runs.sqlite`, 인증 계정은 `.runtime/auth.json`, 서비스 로그는 `.runtime/macmini-dashboard.*.log`에 남는다. 파일을 초기화하거나 계정 비밀번호를 재생성하기 전에 백업한다.

`develop`에 PR을 병합하면 GitHub Actions가 병합된 코드의 전체 모듈을 검증한다. 신뢰된 `develop` 실행의 비민감 요약은 공개 `ci-results` 피드를 통해 장치가 주기적으로 읽고 **통합 테스트** 화면에 표시한다. 요약 수집과 코드 배포는 별도 기능이다. 아래 updater를 설치해야 이 Mac의 실행 모듈과 UI도 자동 갱신된다. CI 판정·요약 범위와 장애 진단은 [CI/CD 안내](CI_CD.md)에 있다.

## 검증된 develop 자동 배포

`kr.or.casper.ca3p.device-deploy` LaunchAgent는 로그인 후 시작하고 120초마다 저장소를 확인한다. 현재 `origin/develop` HEAD의 **push** 실행에 대해 `tests`, `container-smoke`, `integration-gate`의 성공, 전체 suite 완료, 실패·skip 0건을 검증한다. 공개 요약뿐 아니라 GitHub Actions API에서도 저장소·workflow·브랜치·SHA·실행 attempt와 각 필수 job을 확인한다. PR/merge 후보 브랜치는 배포하지 않고, CI가 끝나지 않았거나 더 최신 develop이 준비 중 도착하면 다음 확인을 기다린다. 담당자 리뷰·보호 규칙·사람의 PR 병합 과정은 그대로 유지한다.

배포는 다음 순서로 진행한다.

1. SHA별 Git worktree와 독립 `.venv`를 만들고 활성 모듈의 lockfile 의존성·Chromium을 준비한다. controller는 별도 안정 경로에 설치돼 있어 릴리스 전환에 영향받지 않는다.
2. SQLite backup API로 복제한 DB를 새 코드의 스키마로 이전하고, 별도 포트·별도 인증·빈 작업 DB에서 로그인·주요 API·core fixture를 검증한다. 실제 키를 비활성화하므로 배포 점검으로 유료 AI 호출을 하지 않는다.
3. 대학 실습은 SHA 태그 이미지로 미리 빌드한다. 활성 검사·대기 작업이 있으면 전환을 미루고, 전환 직전 유지보수 잠금으로 새 검사·검토 요청을 막는다.
4. 대시보드·worker·대학 컨테이너를 정지하고 실행 DB·사례 DB·인증 및 대학 실습 볼륨을 백업한다. 사례 DB를 이전하고, 동일한 Compose project/볼륨으로 새 이미지를 시작해 조회 검증한 뒤 `current`를 전환한다.
5. 기존 관리자 계정으로 로그인·실행 SHA·API·인증 파일 보존을 확인한다. 실패하면 서비스를 다시 정지하고 DB·인증·실습 볼륨과 이전 이미지·릴리스를 복구한다. 도중 프로세스가 종료돼도 transaction journal을 바탕으로 다음 실행이 먼저 복구한다.

기존 `agent/.env`는 릴리스에서 공유 참조하고 `0600` 권한을 사용한다. API 키·계정은 Git·CI 피드·문서에 기록하지 않는다. Nginx Proxy Manager의 HTTPS 호스트, 기존 인증·프록시 환경과 저장 데이터 경로는 유지한다. 배포 중 로그인 세션은 서버 재시작으로 만료될 수 있다.

### 설치

[`device-deploy.example.json`](device-deploy.example.json)을 장치의 private 경로로 복사하고 실제 절대 경로를 확인한다. `credentialFile`은 기존 `admin:` 항목이 있는 `.runtime/access.txt`를 가리키며 비밀번호를 JSON에 넣지 않는다. `pythonPath`는 새 venv를 만들 수 있는 Python 3.11 이상, `npmCli`는 Node로 실행할 `npm-cli.js` 파일 경로다. university 자동 배포를 사용하려면 예시처럼 `fixtures.enabled=true`로 설정한다. project는 `ca3p-universities`, 볼륨은 `ca3p-universities_daehan-data`·`ca3p-universities_wonchang-data`를 유지한다.

아래 경로는 예시다. 기존 장치 설정을 사용할 때에는 `config.json`에 맞춰 변수만 바꾼다.

```sh
CA3P_NODE=/Users/casper/dev/CA3P/FSL-CA3P/.runtime/bin/node
CA3P_DEPLOY_ROOT=/Users/casper/dev/CA3P/FSL-CA3P/.runtime/device-deploy
CA3P_DEPLOY_CONFIG="$CA3P_DEPLOY_ROOT/config.json"
install -d -m 700 "$CA3P_DEPLOY_ROOT"
cp docs/device-deploy.example.json "$CA3P_DEPLOY_CONFIG"
chmod 600 "$CA3P_DEPLOY_CONFIG"
```

설정 경로를 확인한 뒤 저장소 루트에서 설치한다. `--no-start`도 controller와 plist를 설치하지만 현재 dashboard 프로세스와 updater를 시작·재시작하지 않는다. 설치기는 활성 배포 PID의 잠금을 확인하고 배포 도중 updater를 중단하지 않는다. 이전 dashboard plist는 `original-dashboard.plist`로 보존한다.

```sh
"$CA3P_NODE" scripts/install-device-deploy.mjs --config "$CA3P_DEPLOY_CONFIG" --no-start
"$CA3P_NODE" "$CA3P_DEPLOY_ROOT/controller/device-deploy.mjs" --config "$CA3P_DEPLOY_CONFIG" --check-only
"$CA3P_NODE" "$CA3P_DEPLOY_ROOT/controller/device-deploy.mjs" --config "$CA3P_DEPLOY_CONFIG" --prepare-only
"$CA3P_NODE" scripts/install-device-deploy.mjs --config "$CA3P_DEPLOY_CONFIG"
```

`--check-only`는 현재 HEAD의 CI를 확인하고, `--prepare-only`는 의존성·복제 DB·격리 smoke·이미지 준비까지 수행하며 실행 서비스로 전환하지 않는다. 두 옵션도 기존 미완료 transaction이 있으면 먼저 복구하고 상태 파일을 갱신한다. 정상 설치 뒤 updater가 다음 120초 확인에서 배포한다. 새 controller 버전은 리뷰된 소스에서 설치기를 다시 실행해 갱신한다.

### 상태·실패·재시도

대시보드의 **배포 알림**과 상단 종 아이콘에서 CI 진행·실제 실행/대상 SHA·적용 단계·실패 및 복원 이력을 볼 수 있다. 현재 상태는 20초마다 다시 읽으며 오래된 상태는 구분한다. 단계 이력 누적에는 새 controller를 한 번 다시 설치해야 한다. 설정·신선도·권한과 보존 범위는 [배포 알림 보드](DEPLOYMENT_NOTIFICATIONS.md)를 참고한다.

**통합 상태**의 `source.commitSha`가 실제 실행 버전이다. 인증된 `/api/platform`의 `deployment`는 배포 상태·대상/실행 SHA·시각을 제공한다. 원시 오류·설정·파일 경로는 외부 응답에 노출하지 않는다. **통합 테스트**의 최신 CI 결과와 실제 실행 SHA는 배포 대기 중 다를 수 있다.

```sh
launchctl print gui/$(id -u)/kr.or.casper.ca3p.device-deploy
cat "$CA3P_DEPLOY_ROOT/status.json"
tail -n 100 /Users/casper/dev/CA3P/FSL-CA3P/.runtime/device-deploy.err.log
```

상태가 `waiting-ci`이면 CI/요약 게시 완료를 기다린다. 전체 테스트가 끝나도 같은 workflow의 이미지 게시·배포 작업이 진행 중이면 완료까지 기다린다. GitHub 비인증 API 한도(같은 공인 IP에서 공유)를 소진하면 `retryAt`까지 검증을 미루며 배포 실패로 처리하지 않는다. `deferred`이면 기존 검사 종료 또는 오류 재시도 대기를 확인한다. `failed`/`blocked`이면 private `status.json`, `.runtime/device-deploy.*.log`, `deployRoot/logs/<SHA>/`를 확인한다. Docker 작업별 출력과 실패한 후보 컨테이너 로그는 `logs/<SHA>/fixtures/`에 비공개로 기록한다. 전환 실패 SHA는 원인을 해결하기 전 자동 반복 배포하지 않는다. 네트워크·의존성 준비 오류에는 재시도 대기가 적용된다. 문제를 해결한 뒤 명시적으로 재시도한다.

LaunchAgent의 `Umask=077`은 유지한다. 이 설정으로 checkout된 Git 추적 소스 파일만 Git 모드에 따라 `0644`/`0755`로 정상화한다. 추적하지 않는 `.env`·인증·DB·설정과 심볼릭 링크 대상은 변경하지 않는다. 대한대 컨테이너는 root 소유 package manifest를 일반 사용자도 읽도록 `COPY --chmod=0644`를 명시한다.

```sh
"$CA3P_NODE" "$CA3P_DEPLOY_ROOT/controller/device-deploy.mjs" --config "$CA3P_DEPLOY_CONFIG" --retry
```

`recovery-required`는 자동 복구가 완료되지 않아 쓰기가 계속 차단된 상태다. updater를 강제 재시작하거나 `maintenance.json`·`transaction.json`·DB를 삭제하지 말고 private 오류·백업을 먼저 확인한다. 현재·직전 릴리스와 최근 DB 백업을 보존하며 대학 이미지/볼륨은 자동 prune하지 않는다. 백업과 모델 설정이 있는 디렉터리는 `0700`, 파일은 `0600`으로 관리한다.

### 자동 배포 중지·재개

진행 중인 배포가 없는지 `status.json`과 `deployRoot/lock/owner.json`을 먼저 확인한다. `preparing`, `deploying`, 복구 작업이 실행 중이면 완료될 때까지 기다린 뒤 updater를 내린다. 도중 `bootout`·`kickstart -k`를 사용하면 배포를 중단할 수 있다. updater만 중지하면 현재 dashboard와 실습 컨테이너는 계속 실행된다.

```sh
launchctl bootout gui/$(id -u)/kr.or.casper.ca3p.device-deploy
```

재개하거나 로그인 후 등록 상태를 복구하려면 다음을 실행한다.

```sh
launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/kr.or.casper.ca3p.device-deploy.plist"
```

이미 등록돼 있고 실행 중이 아닐 때 즉시 확인하려면 강제 종료 옵션 없이 실행한다.

```sh
launchctl kickstart gui/$(id -u)/kr.or.casper.ca3p.device-deploy
```

이 방식은 사용자 LaunchAgent이므로 전원 종료·절전·로그아웃·로그인 전에는 확인할 수 없다. GitHub·패키지 저장소·Docker가 사용 가능하고 모든 검증을 통과한 최신 develop을 배포하며, 장치가 항상 무중단으로 최신 SHA를 실행한다는 보장은 아니다.

## 임시 Cloudflare 경로

기존 Quick Tunnel은 고정 도메인의 대체 경로로 유지한다. 새 장치에서 사용하려면 Cloudflare 공식 `cloudflared`, Node.js 24, Python 3.11 이상, 설치된 Playwright/Chromium 및 `casper-db` 패키지가 필요하다. 이 장치의 검증된 `cloudflared` 실행 파일은 `.runtime/bin/cloudflared`에 있다.

```sh
CASPER_DB_PYTHON="$PWD/.venv/bin/python" PORT=4174 npm run serve:external
```

출력과 `.runtime/public-url.txt`에서 임시 HTTPS 주소를 확인한다. 서버·터널 로그는 `.runtime/server.log`, `.runtime/tunnel.log`에 저장된다. 주소는 터널 재시작 시 바뀔 수 있다. 이미 4174 포트의 Quick Tunnel이 실행 중이면 두 번째 인스턴스를 시작하지 않는다.

기존 게시판 실습은 서버가 생성한 `vul-web-1`에서 실행한다. 모의 코어의 fixture 입력 URL은 표시용이며 접속하지 않는다. 게시판 실습 시작을 누를 때만 별도 브라우저와 게시판을 실행한다. DeepSeek 모델은 API 키를 별도로 설정한 경우에만 호출되며 비용이 발생할 수 있다. 아래 대학 실습은 별도로 실행 중인 컨테이너의 입력 원점에 접속한다.

## 대학 사이트 실습 반영

대시보드의 대학 실습 선택과 IP·포트 입력 기능은 해당 변경이 포함된 릴리스가 배포된 뒤 사용할 수 있다. updater의 `fixtures.enabled=true`이면 최신 develop의 대학 실습 이미지도 동일한 배포에서 갱신하며 기존 볼륨을 보존한다. **통합 상태**의 소스 SHA와 배포 상태로 실제 반영 여부를 확인한다.

updater를 사용하지 않는 수동 운영에서는 Mac의 실행 체크아웃에서 대학 사이트를 시작한다. 자동 배포와 동시에 아래 명령으로 컨테이너를 교체하지 않는다.

```sh
docker compose -f vul-web2/compose.yaml up --build -d
docker compose -f vul-web2/compose.yaml ps
```

대시보드 배포가 완료된 뒤 관리자 계정으로 대학 실습을 실행한다. 현재처럼 대시보드를 Mac에서 직접 실행하면 대한대 주소는 `127.0.0.1:4101`, 원창대 주소는 `127.0.0.1:4102`다. 사이트 포트를 외부 공개하거나 Nginx Proxy Manager에 추가할 필요는 없다. 조회 전용 계정은 실행 이력과 JSON 결과를 볼 수 있지만 실행을 시작하지 못한다.

대시보드를 Docker로 전환하면 `docker-compose.yml`(또는 `docker-compose.deploy.yml`)과 `docker-compose.vul-web2.yml`을 함께 적용한다. 대학 Compose의 전용 네트워크가 이미 존재해야 하며 입력 주소는 `daehan:4101`, `wonchang:4102`다. 컨테이너의 `127.0.0.1`은 Mac 호스트를 가리키지 않는다.

대학 실습은 가상 계정 로그인 후 알려진 레코드 네 건을 읽는 IDOR 검증이며 모델 API·HWPX를 호출하지 않는다. 실행 이력의 대학명·입력 원점·증거·판정과 JSON 내보내기로 확인한다. 임의 CERT 탐색이나 vul-web2의 다른 취약점 검사는 포함하지 않는다.
