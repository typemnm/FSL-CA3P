# 대한대학교 · 원창대학교 웹사이트

두 가상 대학의 다중 페이지 웹사이트입니다. 공개 화면에는 대학 소개, 입학, 단과대학, 학사, 연구·산학, 대학생활, 공지, 대학소식, 일정, FAQ, 시설대여가 있습니다. 로그인 후 마이페이지에서 문의를 접수할 수 있고 관리자는 게시글과 일정을 관리할 수 있습니다. 대한대학교에는 협력기관 입학 접수 조회·JSON5 검색 필터·Markdown 게시글이, 원창대학교에는 교직원 모바일 업무 조회·관리자 YAML 일정 원고 및 TAR 자료 묶음 미리보기가 있습니다. 공개 화면은 실제 대학 포털처럼 구성했으며 평가 환경 안내 문구는 표시하지 않습니다.

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

`compose.yaml`은 **서로 다른 이미지·컨테이너**에 각 사이트를 실행합니다. 대한대학교와 원창대학교는 각각 전용 브리지 네트워크와 `daehan-data`, `wonchang-data` 볼륨을 사용합니다. 호스트 공개 포트는 `127.0.0.1`에만 묶여 있습니다. 컨테이너 안에서는 서비스가 `0.0.0.0`에 바인딩되어 Compose 포트 전달을 받습니다. 대한대학교 이미지는 Node.js 패키지를 `package-lock.json`으로 설치하고, 원창대학교 이미지는 Maven으로 Spring Boot JAR을 빌드합니다.

중지할 때는 `docker compose down`을 사용합니다. 이 명령은 데이터 볼륨을 유지하므로 다음 실행에서도 더미 데이터와 사용 중 변경한 내용이 남습니다. 기존 볼륨을 사용해 새 버전을 실행하면 `CREATE TABLE IF NOT EXISTS`와 `INSERT OR IGNORE`로 부속 업무 테이블·가상 계정·조회 건을 추가합니다. 기존 게시글과 수정된 더미 데이터는 덮어쓰지 않으며 재시작해도 같은 초기 건이 중복 삽입되지 않습니다.

## 개발 환경에서 직접 시작

대한대학교는 Node.js 24 이상, 원창대학교는 Java 17 및 Maven 3.9 이상이 필요합니다. 로컬에 Maven이 없다면 위 Docker Compose 명령으로 두 사이트를 실행하세요.

```powershell
cd vul-web2
npm ci
npm run start:daehan
```

원창대학교는 별도 터미널에서 실행합니다.

```powershell
cd vul-web2/wonchang
mvn spring-boot:run
```

기본 바인딩은 `127.0.0.1`이며 대한대학교는 4101, 원창대학교는 4102 포트를 사용합니다. 최초 실행 시 대한대학교는 `data/daehan.sqlite`, 원창대학교는 `wonchang/data/wonchang.sqlite`에 각각 더미 DB를 생성합니다. 원창대학교는 `SERVER_PORT`, `SERVER_ADDRESS`, `WONCHANG_DB_PATH` 환경변수로 설정을 변경할 수 있습니다. 초기 상태로 되돌릴 때는 서버를 중지한 뒤 해당 DB 파일을 백업하고 삭제하면 됩니다.

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
| 대한대학교 검색 범위 필터 | `/api/search?q=...&filters={type:"notice",limit:8,}` |
| 대한대학교 Markdown 게시글 | `/notices/:id`, `/news/:id` |
| 로그인·문의 접수 | `/login`, `/mypage`, `POST /mypage/requests` |
| 게시글 관리·일정 가져오기 | `/admin`, `/admin/posts/new`, `POST /admin/import` |
| 원창대학교 일정·자료 미리보기 | `POST /admin/schedule/preview`, `POST /admin/archive/preview` |
| 대한대학교 협력기관 입학 접수 조회 | `/admissions/partner`, `/api/admissions/partner/applications/:id` |
| 원창대학교 교직원 모바일 업무 조회 | `/staff/mobile`, `/api/staff/mobile/cases/:id` |

두 부속 업무 화면은 해당 역할로 로그인해야 열리며, 일반 학생 계정은 403을 받습니다. 각 화면의 기본 목록에는 로그인한 담당자의 건만 나타나지만 숫자 조회번호를 직접 넣는 상세 화면과 API는 건별 소유권을 확인하지 않습니다. 이 동작은 [사전 침해분석 및 취약점 보고서](docs/사전_침해분석_및_취약점_보고서.md)에 기록한 의도된 IDOR 평가 대상입니다. 이름과 연락처는 전부 가상이며 연락처 도메인은 `example.invalid`입니다.

## ARTEX 사건을 참고한 평가 시나리오

[CrowdStrike의 2026년 10월 7일 분석](https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/)은 2026년 9월 말~10월 초 한국 금융권 공격에서 대출모집인용 조회 및 직원 모바일 업무지원 같은 외부 접점이 표적이 됐다고 전하며, 공격자 인프라에서 ARTEX 설정과 LLM 세션을 확인했습니다. [금융위원회의 10월 14일 발표](https://www.fsc.go.kr/po010101/87927)는 신한은행 사고 전후 16개 금융회사 침해를 확인했지만, 동일 공격자·AI 활용 여부는 조사 중이라고 명시합니다. 따라서 16건을 모두 ARTEX의 결과로 취급하지 않습니다.

두 대학의 입학 협력기관 조회와 교직원 업무지원 조회는 그 **업무 형태를 차용한 가상 설계**입니다. 공개 자료는 정확한 최초 침입 취약점이나 ARTEX가 IDOR를 발견했다는 사실을 확정하지 않습니다. 이 프로젝트의 건별 인가 누락, 연속된 숫자 조회, 관제 공백은 별도의 모의 평가 가정이며 실제 기관의 경로나 개인정보를 사용하지 않습니다. 상세 근거와 판정 범위는 보고서를 참조하세요.

## 서로 다른 외부 의존성

| 사이트 | 서버·화면 구성 | 직접 외부 의존성 | 버전 관리 |
| --- | --- | --- | --- |
| 대한대학교 | Express · Nunjucks | `express@4.21.2`, `nunjucks@3.2.4`, `cookie-parser@1.4.7`, `dayjs@1.11.13`, `lodash@4.17.15`, `json5@2.2.1`, `markdown-it@12.3.1` | 루트 `package-lock.json` |
| 원창대학교 | Spring Boot 4.1.1 · Spring MVC · Thymeleaf | `spring-boot-starter-webmvc`, `spring-boot-starter-thymeleaf`, `sqlite-jdbc@3.53.4.0`, `gson`, `commons-text@1.9`, `snakeyaml@1.33`, `commons-compress@1.23.0` | `wonchang/pom.xml`의 명시 버전과 Spring Boot 의존성 관리 |

두 사이트는 서로 다른 런타임과 직접 의존성 집합을 사용합니다. 대한대학교 DB는 Node.js 내장 `node:sqlite`, 원창대학교 DB는 SQLite JDBC를 사용합니다. 각 사이트의 직접 의존성 세 개가 공개 CVE의 영향 버전에 해당하며 호출 경로와 검증 범위는 [취약점 보고서](docs/사전_침해분석_및_취약점_보고서.md)에 기록했습니다. 원창대학교의 HTTP 응답에는 `X-Powered-By: Spring Boot`가 포함돼 서버 기술을 확인할 수 있습니다. Wappalyzer의 실제 표시는 확장 프로그램의 탐지 규칙과 캐시에 따라 달라질 수 있습니다.

두 메인 캠퍼스 사진은 가상 대학 전용으로 생성한 로컬 파일입니다. 제작 방식과 최종 프롬프트는 [이미지 제작 기록](docs/이미지_제작기록.md)에 있습니다.

## 검증

```powershell
docker compose config --quiet
npm ci
npm run smoke
node scripts/deployment-check.mjs
```

`docker compose config --quiet`는 Compose 설정을 확인하며 컨테이너를 실행하지는 않습니다. `npm run smoke`는 대한대학교를 메모리 DB·임시 로컬 포트로 실행하고 원창대학교 Spring 이미지를 빌드해 **임시 컨테이너와 임시 SQLite DB**에서 검증합니다. Docker Engine이 필요하며 실행 중인 Compose 컨테이너의 지속 DB는 변경하지 않습니다. 공개 페이지와 정적 자산, 게시판 검색·페이지 이동, 로그인·로그아웃, 문의 접수, 역할 제한, 부속 업무 조회와 오류 경로, 관리자 게시글 작성·수정·일정 가져오기를 확인합니다. 대한대학교의 JSON5 필터·Markdown 렌더링, 원창대학교의 YAML·TAR 미리보기와 대표 취약 동작도 검사합니다. 장시간 자원 소모나 코드 실행 형태의 CVE 재현은 수행하지 않았으며 A09는 정적 코드 검토만 수행했습니다.

`node scripts/deployment-check.mjs`는 **Compose로 두 사이트가 실행 중일 때** `127.0.0.1:4101`·`127.0.0.1:4102`에 요청해 공개 화면과 읽기 경로를 점검합니다. 가상 계정으로 로그인 세션을 생성하지만 지속 DB의 글·일정·문의를 작성하거나 삭제하지 않습니다. 분석 범위와 위험·재현 결과는 [사전 침해분석 및 취약점 보고서](docs/사전_침해분석_및_취약점_보고서.md)에 기록합니다.

Docker Desktop 장애 복구와 재검증 범위는 [장애 원인 및 기능 재검증](docs/장애_원인_및_기능_재검증.md)에 정리했습니다.
