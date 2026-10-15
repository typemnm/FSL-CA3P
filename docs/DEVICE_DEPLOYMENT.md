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

대시보드는 사용자 LaunchAgent `kr.or.casper.ca3p.macmini-dashboard`가 로그인 시 시작하고 장애 후 재시작한다. Node.js 24와 Python 가상환경, 인증·실행 데이터는 이 장치의 `.runtime` 및 `.venv`에 보관된다. 현재 서비스는 장치 배포 체크아웃의 `start.mjs`를 실행한다. 체크아웃을 이동하거나 삭제하기 전에 LaunchAgent의 `WorkingDirectory`와 스크립트 경로를 갱신해야 한다. Mac 재부팅 후 사용자가 로그인하기 전에는 이 LaunchAgent가 시작되지 않는다.

```sh
launchctl print gui/$(id -u)/kr.or.casper.ca3p.macmini-dashboard
tail -n 100 .runtime/macmini-dashboard.err.log
launchctl kickstart -k gui/$(id -u)/kr.or.casper.ca3p.macmini-dashboard
```

마지막 명령은 새 코드가 배포된 뒤 서버를 재시작할 때만 실행한다. 현재 프로세스의 포트는 4175이고, Nginx Proxy Manager가 이 포트에 접근하려면 Mac의 LAN IP가 `192.168.0.84`로 유지돼야 한다. IP가 바뀌면 Nginx Proxy Manager의 Forward Hostname/IP 및 서버의 `DASHBOARD_HOST`를 함께 수정한다. 데이터는 `.runtime/runs.sqlite`, 인증 계정은 `.runtime/auth.json`, 서비스 로그는 `.runtime/macmini-dashboard.*.log`에 남는다. 파일을 초기화하거나 계정 비밀번호를 재생성하기 전에 백업한다.

`develop`에 PR을 병합하면 GitHub Actions가 병합된 코드의 전체 모듈을 검증한다. 신뢰된 `develop` 실행의 비민감 요약은 공개 `ci-results` 피드를 통해 장치가 주기적으로 읽고 **통합 테스트** 화면에 표시한다. 이는 코드 자동 배포가 아니다. 이 Mac의 실행 모듈과 UI를 변경하려면 체크아웃을 갱신하고 위 서비스를 재시작해야 한다. CI 판정·요약 범위와 장애 진단은 [CI/CD 안내](CI_CD.md)에 있다.

## 임시 Cloudflare 경로

기존 Quick Tunnel은 고정 도메인의 대체 경로로 유지한다. 새 장치에서 사용하려면 Cloudflare 공식 `cloudflared`, Node.js 24, Python 3.11 이상, 설치된 Playwright/Chromium 및 `casper-db` 패키지가 필요하다. 이 장치의 검증된 `cloudflared` 실행 파일은 `.runtime/bin/cloudflared`에 있다.

```sh
CASPER_DB_PYTHON="$PWD/.venv/bin/python" PORT=4174 npm run serve:external
```

출력과 `.runtime/public-url.txt`에서 임시 HTTPS 주소를 확인한다. 서버·터널 로그는 `.runtime/server.log`, `.runtime/tunnel.log`에 저장된다. 주소는 터널 재시작 시 바뀔 수 있다. 이미 4174 포트의 Quick Tunnel이 실행 중이면 두 번째 인스턴스를 시작하지 않는다.

외부 사용자의 실제 검사는 서버가 생성한 `vul-web-1` 격리 게시판으로 제한된다. fixture 입력 URL은 표시용이며 접속하지 않는다. 실습 시작을 누를 때만 별도 브라우저와 게시판을 실행한다. DeepSeek 모델은 API 키를 별도로 설정한 경우에만 호출되며 비용이 발생할 수 있다.
