# 대한대학교 · 원창대학교 웹사이트

두 가상 대학의 다중 페이지 웹사이트입니다. 공개 화면에는 대학 소개, 입학, 단과대학, 학사, 연구·산학, 대학생활, 공지, 대학소식, 일정, FAQ, 시설대여가 있습니다. 로그인 후 마이페이지에서 문의를 접수할 수 있고 관리자는 게시글과 일정을 관리할 수 있습니다. 대한대학교에는 협력기관 입학 접수 조회, 원창대학교에는 교직원 모바일 업무 조회가 있습니다. 공개 화면은 실제 대학 포털처럼 구성했으며 평가 환경 안내 문구는 표시하지 않습니다.

이 저장소는 허가된 보안 평가용으로 의도적인 결함을 포함합니다. 모든 계정과 콘텐츠는 가상입니다. **로컬 환경에서만 실행하고 외부에 공개하거나 실제 개인정보를 입력하지 마세요.**

## Docker Compose로 시작

Docker Engine과 Compose 플러그인이 실행 중인 환경에서 다음 명령을 사용합니다.

```powershell
cd vul-web2
docker compose up --build -d
docker compose ps
```

- 대한대학교: http://127.0.0.1:4101/
- 원창대학교: http://127.0.0.1:4102/

`compose.yaml`은 **서로 다른 이미지·컨테이너**에 각 사이트를 실행합니다. 대한대학교와 원창대학교는 각각 전용 브리지 네트워크와 `daehan-data`, `wonchang-data` 볼륨을 사용합니다. 호스트 공개 포트는 `127.0.0.1`에만 묶여 있습니다. 컨테이너 안에서는 서비스가 `0.0.0.0`에 바인딩되어 Compose 포트 전달을 받습니다. 이미지는 각자의 `package-lock.json`으로 `npm ci`를 실행하며, 이미지 안의 런타임 의존성도 분리됩니다.

중지할 때는 `docker compose down`을 사용합니다. 이 명령은 데이터 볼륨을 유지하므로 다음 실행에서도 더미 데이터와 사용 중 변경한 내용이 남습니다. 기존 볼륨을 사용해 새 버전을 실행하면 `CREATE TABLE IF NOT EXISTS`와 `INSERT OR IGNORE`로 부속 업무 테이블·가상 계정·조회 건을 추가합니다. 기존 게시글과 수정된 더미 데이터는 덮어쓰지 않으며 재시작해도 같은 초기 건이 중복 삽입되지 않습니다.

## Node.js에서 직접 시작

Node.js 24 이상이 필요합니다. 두 사이트의 패키지 설치 위치가 다르므로 각각 설치합니다.

```powershell
cd vul-web2
npm ci
npm --prefix wonchang ci
npm start
```

루트에서 `npm run start:daehan` 또는 `npm run start:wonchang`으로 하나씩 실행할 수도 있습니다. 기본 바인딩은 `127.0.0.1`이고, 최초 실행 시 `data/daehan.sqlite`, `data/wonchang.sqlite`에 별도 더미 DB가 생성됩니다. 초기 상태로 되돌릴 때는 서버를 중지한 뒤 해당 DB 파일을 백업하고 삭제하면 됩니다.

`npm start`로 두 사이트를 함께 실행할 때 포트를 바꾸려면 `DAEHAN_PORT`와 `WONCHANG_PORT`를 각각 지정합니다. 함께 실행하는 스크립트는 포트 충돌을 막기 위해 공통 `PORT` 값을 적용하지 않습니다.

| 사이트 | 역할 | 아이디 | 비밀번호 |
| --- | --- | --- | --- |
| 양쪽 | 관리자 | `admin` | `admin1234` |
| 양쪽 | 학생 1·2 | `student1`, `student2` | `Welcome2026` |
| 대한대학교 | 입학 협력기관 담당자 | `partner1`, `partner2` | `Partner2026` |
| 원창대학교 | 학생지원팀 담당자 | `staff1`, `staff2` | `Staff2026` |

## 주요 기능과 경로

| 기능 | 경로 |
| --- | --- |
| 대학 안내·입학·단과대학 | `/about`, `/admissions`, `/colleges` |
| 학사·연구·대학생활 | `/academics`, `/research`, `/campus` |
| 공지·대학소식 | `/notices`, `/news`, 상세 `/notices/:id`, `/news/:id` |
| 학사일정·FAQ·시설 | `/schedule`, `/faq`, `/facilities` |
| 검색 | `/api/search?q=...`, 게시판 검색 폼 |
| 로그인·문의 접수 | `/login`, `/mypage`, `POST /mypage/requests` |
| 게시글 관리·일정 가져오기 | `/admin`, `/admin/posts/new`, `POST /admin/import` |
| 대한대학교 협력기관 입학 접수 조회 | `/admissions/partner`, `/api/admissions/partner/applications/:id` |
| 원창대학교 교직원 모바일 업무 조회 | `/staff/mobile`, `/api/staff/mobile/cases/:id` |

두 부속 업무 화면은 해당 역할로 로그인해야 열리며, 일반 학생 계정은 403을 받습니다. 각 화면의 기본 목록에는 로그인한 담당자의 건만 나타나지만 숫자 조회번호를 직접 넣는 상세 화면과 API는 건별 소유권을 확인하지 않습니다. 이 동작은 [사전 침해분석 및 취약점 보고서](docs/사전_침해분석_및_취약점_보고서.md)에 기록한 의도된 IDOR 평가 대상입니다. 이름과 연락처는 전부 가상이며 연락처 도메인은 `example.invalid`입니다.

## ARTEX 사건을 참고한 평가 시나리오

[CrowdStrike의 2026년 10월 7일 분석](https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/)은 2026년 9월 말~10월 초 한국 금융권 공격에서 대출모집인용 조회 및 직원 모바일 업무지원 같은 외부 접점이 표적이 됐다고 전하며, 공격자 인프라에서 ARTEX 설정과 LLM 세션을 확인했습니다. [금융위원회의 10월 14일 발표](https://www.fsc.go.kr/po010101/87927)는 신한은행 사고 전후 16개 금융회사 침해를 확인했지만, 동일 공격자·AI 활용 여부는 조사 중이라고 명시합니다. 따라서 16건을 모두 ARTEX의 결과로 취급하지 않습니다.

두 대학의 입학 협력기관 조회와 교직원 업무지원 조회는 그 **업무 형태를 차용한 가상 설계**입니다. 공개 자료는 정확한 최초 침입 취약점이나 ARTEX가 IDOR를 발견했다는 사실을 확정하지 않습니다. 이 프로젝트의 건별 인가 누락, 연속된 숫자 조회, 관제 공백은 별도의 모의 평가 가정이며 실제 기관의 경로나 개인정보를 사용하지 않습니다. 상세 근거와 판정 범위는 보고서를 참조하세요.

## 서로 다른 외부 의존성

| 사이트 | 서버·화면 구성 | 직접 외부 의존성 | 잠금 파일 |
| --- | --- | --- | --- |
| 대한대학교 | Express · Nunjucks | `express@4.21.2`, `nunjucks@3.2.4`, `cookie-parser@1.4.7`, `dayjs@1.11.13`, `lodash@4.17.15` | 루트 `package-lock.json` |
| 원창대학교 | Koa · EJS | `koa@2.16.2`, `@koa/router@14.0.0`, `koa-bodyparser@4.4.1`, `koa-static@5.0.0`, `ejs@3.1.10`, `luxon@3.5.0`, `dot-prop@4.2.0` | `wonchang/package-lock.json` |

두 사이트는 직접 의존성 이름이 겹치지 않습니다. DB는 각각 Node.js 내장 `node:sqlite`를 사용합니다. `lodash`와 `dot-prop`은 보안 평가를 위해 취약 버전으로 고정돼 있습니다.

두 메인 캠퍼스 사진은 가상 대학 전용으로 생성한 로컬 파일입니다. 제작 방식과 최종 프롬프트는 [이미지 제작 기록](docs/이미지_제작기록.md)에 있습니다.

## 검증

```powershell
docker compose config --quiet
npm run smoke
node scripts/deployment-check.mjs
```

`docker compose config --quiet`는 Compose 설정을 확인하며 컨테이너를 실행하지는 않습니다. `npm run smoke`는 두 서버를 메모리 DB와 임시 로컬 포트에서 구동해 직접 의존성 분리, 공개 페이지와 정적 자산, 게시판 검색·페이지 이동, 로그인·로그아웃, 문의 접수, 역할 제한, 두 부속 업무 화면의 조회와 오류 경로, 관리자 게시글 작성·수정·일정 가져오기 및 대표 취약 동작을 확인합니다. A01~A08과 A10의 대표 동작은 자동 검증됐고 A09는 정적 코드 검토만 수행했습니다. 실행 중인 사이트의 지속 DB는 변경하지 않습니다.

`node scripts/deployment-check.mjs`는 **Compose로 두 사이트가 실행 중일 때** `127.0.0.1:4101`·`127.0.0.1:4102`에 요청해 공개 화면과 읽기 경로를 점검합니다. 가상 계정으로 로그인 세션을 생성하지만 지속 DB의 글·일정·문의를 작성하거나 삭제하지 않습니다. 분석 범위와 위험·재현 결과는 [사전 침해분석 및 취약점 보고서](docs/사전_침해분석_및_취약점_보고서.md)에 기록합니다.

Docker Desktop 장애 복구와 재검증 범위는 [장애 원인 및 기능 재검증](docs/장애_원인_및_기능_재검증.md)에 정리했습니다.
