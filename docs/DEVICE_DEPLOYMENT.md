# 이 장치에서 팀 대시보드 외부 접속

현재 장치의 Node 서버는 `127.0.0.1:4173`에만 바인딩한다. Cloudflare Quick Tunnel이 임시 HTTPS 주소를 이 포트로 연결한다. 웹 화면은 로그인 후 실행 목록·모델·입출력·모듈별 차이·CI 결과를 조회한다. 외부 주소에서는 1초 간격 조회로 상태를 갱신한다.

## 준비 및 시작

Node.js 24, Python 3.11 이상, Docker 없이 설치한 `xss-parser`의 Playwright/Chromium, `casper-db` Python 패키지, `curl`이 필요하다. 전체 설치·검증 방법은 [CI/CD 안내](CI_CD.md)에 있다. 이 장치에 검증된 `cloudflared` 실행 파일은 `.runtime/bin/cloudflared`에 있다. 새 장치에서는 Cloudflare 공식 배포판을 설치한 뒤 `CLOUDFLARED_BIN`에 절대 경로를 지정한다.

```sh
CASPER_DB_PYTHON="$PWD/.venv/bin/python" npm run verify
CASPER_DB_PYTHON="$PWD/.venv/bin/python" npm run seed:lab-history
CASPER_DB_PYTHON="$PWD/.venv/bin/python" npm run serve:external
```

마지막 명령은 터널과 서버를 함께 실행한다. 출력과 `.runtime/public-url.txt`에 현재 외부 HTTPS 주소가 기록된다. 첫 시작 때 `.runtime/access.txt`에 `admin`과 읽기 전용 `viewer`의 비밀번호가 생성된다. 이 파일은 장치 사용자만 읽을 수 있게 저장되며 Git과 이미지에서 제외된다. 팀원에게는 URL과 필요한 역할의 비밀번호를 별도 안전한 경로로 전달한다. 조회 전용 계정은 실행·중지·검토를 할 수 없다. 로그인 세션은 8시간이고 변경 요청에는 CSRF 토큰이 필요하다.

`seed:lab-history`는 격리 게시판의 합성 과거 사례 하나만 추가하며, 기존 일치 사례가 있으면 추가하지 않는다. 이 사례는 실제 취약점 증거가 아니다. 실습을 실행하면 고유 canary의 실제 Chromium 결과가 별도 실행 이력과 검토 초안으로 저장된다. DeepSeek API 키 없이 규칙 기반 모델을 선택해 전체 경로를 확인할 수 있다.

## 운영과 확인

프로세스가 실행 중일 때 `http://127.0.0.1:4173/api/health`와 외부 주소의 `/api/health`가 `{"status":"ok"}`을 반환한다. 미로그인 상태의 `/api/runs`는 401을 반환한다. 서버·터널 로그는 `.runtime/server.log`, `.runtime/tunnel.log`에 저장된다. 종료는 실행 중인 터미널에서 `Ctrl+C`를 누른다. 터널이나 앱이 종료되면 감독 스크립트가 나머지도 종료한다.

Quick Tunnel 주소는 임시이며 장치·네트워크·프로세스가 중단되면 사용할 수 없다. 다시 시작하면 URL이 바뀔 수 있다. 고정 주소와 재부팅 후 자동 시작이 필요하면 팀 소유 도메인 및 Cloudflare 계정에 등록된 named tunnel을 별도로 구성해야 한다. 이 구성은 현재 임시 URL의 정상 동작에 필요하지 않다.

외부 사용자는 서버가 만든 `vul-web-1` 격리 실습 대상만 검사할 수 있다. 표시용 URL을 입력하는 fixture 실행은 그 주소에 접속하지 않는다. 대시보드의 실습 시작만 실제 로컬 게시판과 브라우저를 실행한다.
