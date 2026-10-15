# CA3P 통합 및 배포

## 로컬 검증

Node.js 24와 Python 3.11 이상을 사용한다. `.nvmrc`와 모든 Node 모듈의 engines가 동일한 주 버전을 지정한다.

```sh
nvm use
npm ci --prefix xss-parser
python3 -m venv .venv
.venv/bin/python -m pip install -r casper-db/requirements-ci.lock
.venv/bin/python -m pip install --no-deps -e ./casper-db
cd xss-parser
npx playwright install --with-deps chromium
cd ..
CASPER_DB_PYTHON="$PWD/.venv/bin/python" npm run verify
```

`scripts/ci.mjs`는 integration-manifest에 등록된 활성 모듈의 test/tests를 자동 탐색한다. 새 파일을 package.json에 매번 열거하지 않는다. 독립 테스트 디렉터리가 없는 활성 모듈은 manifest의 `ci.suiteAssignments`에서 실제 통합 테스트 파일의 소유 suite를 지정한다. `pentest-db`는 카탈로그 조회·저장 영속성·잘못된 입력 거부, `adapters`는 casper-db·guardrail·xss-parser·gateway 경계, `worker`는 별도 프로세스의 큐 실행·기록 재개·취소를 검증한다. 배정한 파일이 사라지거나 활성 모듈의 suite가 비면 CI는 실패하고 `completeSuite=false`를 기록한다. Node skip/todo/cancelled, pytest skip/error는 게이트 실패다. Chromium 실제 실행, curl, Python 의존성을 먼저 확인한다.

요약의 `jobs`는 테스트 suite 단위이며 모든 활성 모듈에 별도 행이 있다. 배정된 통합 테스트는 한 suite에서만 실행·집계해 건수를 중복하지 않는다. `changedModules`는 코드 경로 변경을 나타내며 suite의 소유와 별개다.

결과는 `reports/ci/latest.json`, 모듈별 로그, pytest JUnit XML에 저장한다. 보고서는 검사한 `commitSha`, GitHub event/ref, branch, worktreeDirty, completeSuite, 시각, 모듈별 통과·실패·skip을 기록한다. 준비 단계나 검증 프로세스가 중단되면 실패 보고서를 남기고 completeSuite=false로 표시한다. 일부 모듈이 실패해도 나머지 suite를 실행한 경우 completeSuite=true일 수 있으며, 이때 status는 failed다. `--node-only`, `--modules=agent,guardrail`, `--skip-preflight`는 일부 확인용이며 completeSuite=false다. 정식 검증은 옵션 없는 `npm run verify`다.

## GitHub Actions

`ci.yml`은 develop/main의 PR·push, workflow_dispatch, merge_group에서 실행한다. PR에서는 GitHub가 만든 PR 브랜치와 대상 브랜치의 병합 후보 커밋을 checkout해 **활성 모듈 전체**를 검사한다. 병합 후 develop push에서는 실제 통합 커밋을 다시 전체 검사한다. public PR은 GitHub hosted Ubuntu runner의 read-only 권한으로 검증한다. 테스트와 Docker smoke가 모두 성공해야 항상 종료하는 `integration-gate`가 성공한다. 경로 필터로 required check가 pending으로 남는 설정을 사용하지 않는다.

`tests` job은 성공·실패와 관계없이 `ci-report-<검사한 SHA>` artifact에 구조화된 보고서를 14일간 보존한다. 의존성 설치 등 검증 시작 전에 실패한 경우에도 최소 실패 보고서를 기록한다. `container-smoke`와 `integration-gate`의 결론은 별도 Actions job 결과로 확인한다. 신뢰된 `develop` push에서만 `publish-ci-summary`가 보고서와 세 job 결론을 합쳐 공개 `ci-results` 브랜치의 `index.json`에 최근 50개 실행을 기록한다. 장치 서버는 시작할 때와 이후 5분마다 피드를 읽어 `.runtime/ci-results/index.json`에 보관하고 인증된 **통합 테스트** 화면에 표시한다. 피드가 아직 없을 때는 Actions job 결론만 보여주며 모듈 수치는 `자료 없음`으로 표시한다. PR 후보의 결과는 해당 PR의 Checks/Actions에서 확인한다. `npm run verify`로 만든 로컬 보고서와 GitHub의 병합 후 보고서를 구분한다.

공개 요약에는 commit SHA, Actions 실행 주소·시각, 모듈별 통과/실패/건너뜀 **건수**, 변경 비교 기준 `changedFromSha`와 그 커밋 이후 변경된 활성 모듈 **ID**, `tests`·`container-smoke`·`integration-gate` 결론만 포함한다. 기준은 이전의 **서로 다른** develop SHA다. 같은 커밋의 재실행은 이 기준을 유지하며, 대시보드는 같은 SHA끼리 비교할 때 변경 모듈 목록을 표시하지 않는다. 이전 커밋을 비교할 수 없으면 변경 모듈은 `null`로 기록하며 추정하지 않는다. 준비 실패로 테스트 보고서가 없거나 수치가 기록되지 않았다면 건수는 `null`이며 실제 0건과 구분한다. 테스트 로그, 입력값, 모델 출력, 취약점 증거, 인증정보는 포함하지 않는다. 자세한 실패 원인은 Actions artifact와 로그에서 확인한다. `publish-ci-summary`가 실패해도 기존 `integration-gate` 판정은 바뀌지 않으며 대시보드의 최신 결과가 갱신되지 않는다. 이 경우 해당 Actions job의 오류와 저장소 `GITHUB_TOKEN`의 `contents: write` 권한, `ci-results` 브랜치 규칙을 확인한다. 장치 서버에는 GitHub 토큰이나 외부 쓰기 API가 필요하지 않다.

저장소 보호 규칙에 `integration-gate`를 required check로 등록하고 PR 승인 및 최신 base 반영을 요구한다. 이 설정 변경은 저장소 관리자 권한이 필요하다. 조직 저장소에서 merge queue를 사용할 때도 merge_group 검증을 이용할 수 있다.

신뢰된 develop/main의 push 또는 해당 ref 수동 실행만 GHCR 이미지를 게시한다. tag는 commit SHA이고 배포는 immutable digest다. 장치의 결과 수집은 코드 배포가 아니다. 이 PC의 실행 모듈은 별도 배포·재시작 전까지 기존 버전이다. API key 없이 실제 Chromium·고정 실습 웹·가짜 모델·규칙 기반 회귀를 검증한다. CI와 health check가 실제 모델 호출을 시작하지 않는다.

Actions는 공식 release commit에 고정했으며 Dependabot 변경 PR을 같은 게이트로 검증한다.

| Action | Version | 공식 commit |
| --- | --- | --- |
| checkout | v4.2.2 | [11bd719](https://github.com/actions/checkout/commit/11bd71901bbe5b1630ceea73d27597364c9af683) |
| setup-node | v4.4.0 | [49933ea](https://github.com/actions/setup-node/commit/49933ea5288caeca8642d1e84afbd3f7d6820020) |
| setup-python | v5.6.0 | [a26af69](https://github.com/actions/setup-python/commit/a26af69be951a213d495a4c3e4e4022e16d87065) |
| upload-artifact | v4.6.2 | [ea165f8](https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02) |
| download-artifact | v4.3.0 | [d3f86a1](https://github.com/actions/download-artifact/commit/d3f86a106a0bac45b974a628896c90dbdf5c8093) |

## Docker 실행 및 영속화

```sh
CA3P_COMMIT_SHA="$(git rev-parse HEAD)" docker compose -p ca3p up --build -d --wait
docker compose -p ca3p logs -f dashboard
```

컨테이너는 Node 24.19.0, lockfile의 Playwright 1.58.2와 같은 패키지가 설치한 Chromium, Python exact requirements lock을 사용한다. API와 worker는 같은 이미지에서 실행하고 실습 웹은 실행마다 임시 인스턴스를 만든다.

| Volume | Container path | 내용 |
| --- | --- | --- |
| platform-runtime | /app/.runtime | run SQLite registry, 공유 접속 계정·인증 설정 |
| casper-db-data | /app/casper-db/data | 과거 사례 SQLite |
| pentest-reports | /app/reports/pentest-db-runs | 기존 이벤트·보고서 |

`.runtime`, `.venv`, `.env`, local DB와 일반 reports는 Git·이미지에서 제외한다. `reports/ci/latest.json`만 빌드 결과 표시를 위해 이미지에 포함할 수 있다. 인증 파일은 런타임 볼륨에 준비하고 API key는 실행 환경이나 agent/.env로 공급한다. `down -v`는 저장된 기록과 인증까지 삭제한다.

## 신뢰된 배포 runner

1. Docker Engine과 Compose v2.24+를 갖춘 Linux runner에 `ca3p-deploy` label을 설정한다.
2. GitHub staging/production environment의 허용 브랜치를 develop/main으로 제한한다. production에는 승인자를 등록한다.
3. runner의 런타임 볼륨에 인증을 준비하고 GHCR 읽기 권한을 부여한다.
4. 저장소 변수 `CA3P_AUTO_DEPLOY=true`이면 develop 검증·게시 성공 후 staging workflow를 실행한다. 설정 전에는 게시까지만 수행한다.

재사용 deploy workflow는 PR/merge_group과 다른 ref를 runner에 배정하지 않는다. 이미지 입력은 현재 저장소의 GHCR 경로와 SHA-256 digest만 허용한다. 배포 runner를 PR 빌드에 재사용하지 않는다.

검증된 digest를 직접 배포하거나 rollback할 때:

```sh
export CA3P_IMAGE='ghcr.io/typemnm/fsl-ca3p@sha256:<검증된-64자리-digest>'
docker compose -p ca3p -f docker-compose.deploy.yml pull
docker compose -p ca3p -f docker-compose.deploy.yml up -d --wait
```

재사용 workflow는 environment, runner, GHCR 권한이 준비돼야 동작한다. 로컬 빌드·대시보드는 외부 설정 없이 실행한다.

## 통합 규칙

develop은 모든 모듈 브랜치 tip을 포함한 baseline이다. 전체 장기 브랜치를 반복 머지하지 않고 `feature/<module>/<change>` PR을 develop에 넣는다. 모듈 담당자 리뷰를 유지하고 JSON 계약 변경은 소비자 검증을 함께 수행한다. main은 release 승격에 쓴다. CI 안정화 후 main을 공통 개발 기준으로 올리고 짧은 feature PR로 전환할 수 있다.

manifest의 active/replaced는 Git ancestry와 별도로 관리한다. xss-fuzzer는 현재 parser/attack 실행 경로로 대체됐으며 원래 브랜치는 참고용이다. parser 내부의 중복 실습 웹을 제거하고 root vul-web-1 하나를 start·테스트에서 공동 사용한다.

경계 검사는 contracts, persistence/evaluation과 adapters의 선언된 의존, UI dist의 backend import 금지를 확인한다. 실행 어댑터와 local-lab-gateway 구현은 `packages/adapters`에 두고, 예전 dashboard 경로는 기존 테스트·호출자를 위한 호환 진입점으로 유지한다. 경로별 CI 최적화는 의존 그래프가 안정화된 뒤 적용한다. 현재는 모든 모듈을 매번 검증한다.
