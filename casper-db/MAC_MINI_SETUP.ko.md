# 맥 미니에서 설치하고 직접 검증하기

맥 미니에서 보고서를 접수하고 공개 권고를 수집·조회하기 위한 설치 및 운영 안내입니다. macOS 실기 실행은 아직 확인하지 않았습니다.

## 설치 환경

저장소 최상위에서 실행합니다. `uname -m`이 Apple Silicon에서는 `arm64`, Intel에서는 `x86_64`인지 확인합니다. Windows의 `.venv`, `node_modules`를 복사하지 않고 맥에서 새로 설치합니다.

```bash
uname -m
brew install python@3.12 node@24 tesseract tesseract-lang
export PATH="$(brew --prefix node@24)/bin:$PATH"
"$(brew --prefix python@3.12)/bin/python3.12" -m venv .venv
source .venv/bin/activate
python -m pip install -r casper-db/requirements-runtime.lock
python -m pip install --no-deps -e ./casper-db
npm ci --prefix xss-parser
(cd xss-parser && npx playwright install chromium)
export CASPER_DB_PYTHON="$PWD/.venv/bin/python"
export CASPER_DB_TESSERACT="$(brew --prefix)/bin/tesseract"
```

Tesseract는 이미지 속 글자를 읽는 도구입니다. `tesseract-lang`은 한국어 등의 언어 데이터입니다. 설치 때 다운로드하는 것과 보고서 처리 중 외부 전송은 별개입니다. HWP/HWPX 읽기와 OCR은 로컬에서 동작합니다. 로컬 LLM을 호출하는 기능은 현재 포함하지 않습니다.

## 실행 환경 확인

```bash
node --version
python --version
python -m casper_db ocr-status --language ko --require
```

Node 24와 Python 3.11 이상을 사용합니다. OCR 상태에서 `available=true`, `kor`와 `eng` 언어 데이터, 실제 엔진 경로를 확인합니다. 설치가 누락되면 보고서 처리 전에 오류를 해결합니다.

## 실제 보고서 접수·검토·등록

실제 보고서는 맥의 로컬 경로에서 사용합니다. 접수 DB에는 원본 바이트도 보관하므로 결과 DB도 원본과 같은 범위로 관리합니다. 새 작업 공간을 사용합니다.

```bash
python -m casper_db report-db init casper-db/data/server-workspace
python -m casper_db report-db stage casper-db/data/server-workspace \
  '/absolute/path/CERT-report.hwp' --target YOUR-TARGET --ocr --ocr-language ko
```

반환된 `draft_sha256`, 초안 파일과 검토 파일 경로를 확인합니다. 원문과 초안을 비교하고 검토 JSON에 판단·이유·누락 필드의 근거를 작성합니다. 아래 자리표시는 실제 값으로 바꿉니다.

```bash
python -m casper_db report-db review casper-db/data/server-workspace \
  DRAFT_SHA256 '/absolute/path/report.review.json'
python -m casper_db report-db publish casper-db/data/server-workspace DRAFT_SHA256
python -m casper_db report-db publish casper-db/data/server-workspace DRAFT_SHA256 --apply
```

첫 publish는 등록 전 확인이고 `--apply`에서 최종 사례를 저장합니다. HWP v5와 HWPX를 지원하며 암호·DRM 문서는 지원하지 않습니다. OCR은 내장된 지원 이미지 형식에 적용하고 현재 최대 8개·이미지당 800만 픽셀 제한이 있습니다. 페이지 전체를 렌더링한 OCR이 아닙니다. 실제 보고서에서는 표 경계, URL, 파라미터, payload의 따옴표·공백·인코딩, 이미지 누락을 대조합니다.

## 실제 파서 결과 → GitHub/NVD → 같은 DB 저장·조회

같은 대상 ID를 사용합니다. 파서는 승인된 loopback URL만 받으므로 서버에서 실행 중인 대상의 로컬 포트를 지정합니다. `YOUR-TARGET`, 포트, 경로는 실제 값으로 바꿉니다.

```bash
export CASPER_DB_PATH="$PWD/casper-db/data/server-workspace/cases.sqlite3"
mkdir -p .runtime/mac-parser-check
node xss-parser/cli.mjs --url http://127.0.0.1:4101/ --structure \
  --out .runtime/mac-parser-check/parser.json
node packages/adapters/ingest-parser.mjs \
  --report .runtime/mac-parser-check/parser.json \
  --db "$CASPER_DB_PATH" --target YOUR-TARGET \
  --output .runtime/mac-parser-check/sync-result.json
```

기본 3.4 출력도 지원합니다. 외부 수집에는 패키지 생태계·제품 식별·버전과 이미 알려진 공개 CVE/CPE 검색 조건만 보냅니다. 보고서 내용, 대상 URL, 파일 경로, 파서 근거는 공개 공급자에게 보내지 않습니다. 로컬 lockfile/POM의 루트 프로젝트는 공개 의존성 검색에서 제외합니다.

실제 제품 단서가 없는 페이지에서는 제품을 만들어 넣지 않습니다. URL 단서와 선언만으로 실제 설치를 확정하지 않습니다. `input_coverage`, `jobs`, `errors`, `collection_complete`, `commits`, `knowledge.external.candidates`를 확인합니다. 범위 계산값은 `range_decision`, 최종 판단은 `decision`이며 단서·선언은 `needs_review`를 유지합니다. 종료 코드 2는 부분 수집 또는 입력 오류이므로 응답과 오류를 확인합니다. 새 output 파일 이름으로 다시 실행할 수 있습니다.

조회 전용 입력은 `casper-db/schemas/knowledge-query.schema.json`에 맞춰 대상 ID, 입력 위치, 제품·버전·근거를 JSON으로 작성합니다.

```bash
python -m casper_db --db "$CASPER_DB_PATH" knowledge-query '/absolute/path/query.json'
python -m casper_db --db "$CASPER_DB_PATH" knowledge-sync-runs
```

조회는 네트워크를 사용하지 않습니다. 수집 이력에서 `partial`은 일부 검색 실패·잘림, `running`은 완료 영수증이 남지 않은 작업을 뜻합니다. 강제 종료된 작업은 자동 성공이나 자동 재개로 처리하지 않습니다. 원인을 확인하고 새 작업으로 재시도합니다. 같은 권고 내용은 중복 등록되지 않습니다.

## 통합 DB를 사용하는 공격 툴 확인

Python 설치 후 임시 loopback 게시판에서 DB 조회와 IDOR 검사를 함께 확인할 수 있습니다. 아래 호출은 별도 공격 정보 DB와 임시 게시판 데이터를 사용합니다.

```bash
mkdir -p .runtime
CASPER_DB_PATH="$PWD/.runtime/mac-attack-knowledge.sqlite3" npm --prefix vul-web-1 run repeater -- idor
```

JSON의 `provenance.catalog=casper-db.attack_catalog`, `patternId`·`patternRevision`·`definitionSha256`, `finding`과 단계별 `evidence`를 확인합니다. runner는 완료 후 임시 게시판을 닫습니다. Intruder는 별도로 실행 중인 승인된 실습 서버가 필요하며 [사용 안내](../vul-web-1/scripts/INTRUDER.md)를 따릅니다.

## 에이전트와 서비스 실행

```bash
export CASPER_DB_INTAKE_WORKSPACE="$PWD/casper-db/data/server-workspace"
```

실제 로컬 에이전트의 과거 사례 조회 경로는 파서에 제품 단서가 있으면 원본 DB에 수집·저장합니다. 이미 준비된 사례·공격 카탈로그 사본은 바꾸지 않고, 그 사본의 조회 결과와 새 공개 권고 결과를 묶어 반환합니다. 공개 권고 결과와 내용 해시는 실행의 JSON 증거에 고정합니다. 따라서 실행 중 수집한 권고가 준비 단계의 DB 사본에 없더라도 전달이 누락되지 않습니다.

서비스 계정은 터미널의 환경을 그대로 받지 않을 수 있습니다. launchd 등에 Python·Tesseract·DB·접수 작업 공간의 절대 경로와 WorkingDirectory를 명시합니다. 공급자 공통 대기 상태는 기본 `~/.cache/casper-db/public-rate.sqlite3`에 저장합니다. 여러 서비스 프로세스는 같은 서비스 계정 또는 같은 `CASPER_DB_RATE_STATE` 절대 경로를 사용해야 같은 호출 제한을 공유합니다. 이 파일은 취약점 DB와 별개의 전송 제어 상태입니다.

프로세스 재시작 후 같은 DB·접수 기록·공개 권고가 조회되는지 확인합니다. 실행 중 DB를 파일 복사만으로 백업하지 말고 SQLite backup을 사용하며 접수 DB와 원본 보관 정책도 함께 적용합니다.

## Docker를 사용하는 경우

macOS 직접 실행과 Linux 컨테이너 실행은 별도로 확인합니다. Dockerfile은 HWP 리더, Tesseract, 한국어 언어 데이터와 운영 의존성을 설치합니다. 현재 PC에서는 Docker 데몬이 실행 중이지 않아 이미지 빌드는 확인하지 못했습니다. Apple Silicon의 네이티브 설치 결과만으로 컨테이너 동작을 판단하지 않습니다.
