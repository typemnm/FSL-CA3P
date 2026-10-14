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

`scripts/ci.mjs`는 integration-manifest에 등록된 활성 모듈의 test/tests를 자동 탐색한다. 새 파일을 package.json에 매번 열거하지 않는다. JSON 카탈로그 모듈 pentest-db는 카탈로그·저장 어댑터 통합 테스트에서 검증한다. Node skip/todo/cancelled, pytest skip/error는 게이트 실패다. Chromium 실제 실행, curl, Python 의존성을 먼저 확인한다.

결과는 `reports/ci/latest.json`, 모듈별 로그, pytest JUnit XML에 저장한다. 플랫폼 API가 JSON을 읽어 commitSha, branch, worktreeDirty, completeSuite, 시각, 모듈별 통과·실패·skip을 표시한다. `--node-only`, `--modules=agent,guardrail`, `--skip-preflight`는 일부 확인용이며 completeSuite=false다. 정식 검증은 옵션 없는 `npm run verify`다.

## GitHub Actions

`ci.yml`은 develop/main의 PR·push, workflow_dispatch, merge_group에서 실행한다. public PR은 GitHub hosted Ubuntu runner의 read-only 권한으로 검증한다. 테스트와 Docker smoke가 모두 성공해야 항상 종료하는 `integration-gate`가 성공한다. 경로 필터로 required check가 pending으로 남는 설정을 사용하지 않는다.

저장소 보호 규칙에 `integration-gate`를 required check로 등록하고 PR 승인 및 최신 base 반영을 요구한다. 이 설정 변경은 저장소 관리자 권한이 필요하다. 조직 저장소에서 merge queue를 사용할 때도 merge_group 검증을 이용할 수 있다.

신뢰된 develop/main의 push 또는 해당 ref 수동 실행만 GHCR 이미지를 게시한다. tag는 commit SHA이고 배포는 immutable digest다. API key 없이 실제 Chromium·고정 실습 웹·가짜 모델·규칙 기반 회귀를 검증한다. CI와 health check가 실제 모델 호출을 시작하지 않는다.

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
