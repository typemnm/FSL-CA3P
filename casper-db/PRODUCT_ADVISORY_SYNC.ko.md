# 파서의 제품 정보로 공개 권고 수집·저장·조회하기

이 기능은 CVE 없는 제품 입력으로 GitHub Advisory와 NVD를 검색하고 기존 취약점 DB에 저장한 뒤 조회합니다. 취약점 재현이나 공격 성공을 판정하지 않습니다.

## 최신 web-parser 입력

`develop`에 병합된 파서의 기본 3.4 출력과 `structure-1.0` 출력을 모두 받습니다.

| 파서 입력 | DB 입력에 보존하는 내용 |
| --- | --- |
| `dependencies.libraries` | 생태계·이름·버전, 자산·라이브러리 ID, 식별 근거, 버전 충돌 |
| `dependencies.sources` | npm lockfile/Maven 선언의 패키지·버전, 원본 SHA-256, 항목 위치, 해석 한계 |
| `dependencies.technologies` | 응답 헤더의 제품·버전 주장. CPE는 생성하지 않고 NVD 키워드 후보로 검색 |
| 기존 `softwareInventory` | 기존 입력 계약 유지. 대상 ID 검사 및 수집 한도 적용 |

URL 단서는 `identification=indicator`, lockfile/POM은 `declared`로 전달합니다. 실제 설치가 확인된 기존 입력은 `observed`입니다. 버전 충돌은 임의로 하나를 고르지 않고 버전을 미확정으로 유지합니다. 로컬 파일의 루트 프로젝트 이름은 공개 의존성으로 검색하지 않습니다.

## 제품용 실행 명령

저장한 실제 파서 JSON과 절대 DB 경로를 지정합니다. Node 24와 설치된 casper-db Python 환경이 필요합니다.

```bash
export CASPER_DB_PYTHON="$PWD/.venv/bin/python"
node packages/adapters/ingest-parser.mjs \
  --report /absolute/path/parser.json \
  --db /absolute/path/cases.sqlite3 --target YOUR-TARGET \
  --output /absolute/path/new-sync-result.json
```

처리 순서는 다음과 같습니다.

1. 파서 출력에서 제품과 근거를 변환합니다. 최대 20개를 수집하고 잘림·제외 항목을 표시합니다.
2. GitHub에 생태계와 `package@version` 조건으로 요청합니다. 예: `npm`, `jquery@1.12.4`.
3. 응답에서 발견한 CVE로 NVD를 조회합니다. 관찰 CPE가 있으면 그 조건도 검색합니다.
4. CVE/CPE가 없으면 제품 키워드로 NVD 후보를 수집합니다. CPE를 추정하지 않습니다.
5. 원문·출처·정규화 결과를 검증하고 같은 DB의 `external_*` 영역에 저장합니다.
6. 기존 사례·공격 정보와 제품 권고를 조회해 `knowledge`로 반환합니다.

원본 보고서, 대상 URL, 파일 경로, 파서 근거와 호출 경로는 공개 공급자에게 보내지 않습니다. API 요청에는 제품 식별·버전과 공개 CVE/CPE 검색 조건만 사용합니다. 공급자 원문은 DB의 `external_sources`, 내용 이력은 `external_revisions`에 보존합니다.

제품 단서가 없는 파서 결과에서는 관련 제품을 만들어 넣지 않습니다. 직접 입력은 `casper-db/schemas/knowledge-sync.schema.json`에 맞춰 `knowledge-sync`로 실행할 수 있습니다.

```bash
python -m casper_db --db /absolute/path/cases.sqlite3 knowledge-sync \
  /absolute/path/normalized-input.json --apply --output /absolute/path/new-result.json
```

`--apply`를 빼면 수집만 하고 DB에는 쓰지 않습니다. 기존 `knowledge-query`는 네트워크와 저장 없이 조회만 합니다.

## 에이전트 연결과 재현성

로컬 에이전트의 history 요청은 `prepareParserKnowledge`를 호출합니다. 제품 단서가 있으면 원본 DB에 동기화하고, 고정된 사례 DB의 조회와 새 권고 결과를 합쳐 `knowledgeContext`로 전달합니다. 작업 전 생성한 DB 사본에 새 권고를 쓰지 않습니다. 공개 권고 결과는 실행 이벤트와 보고서 JSON에 보관하며 내용 해시를 실행 비교에 사용합니다.

- 사례·점검 이력·공격 정보의 기존 DB 사본은 유지합니다.
- 준비 시점의 통합 DB 비교 해시는 논리적인 내용·revision을 사용합니다. SQLite 페이지나 수집 영수증 시각 때문에 달라지지 않습니다.
- 파서 입력 후 사용한 공개 권고의 ID·내용 해시·판단·수집 완전성도 별도로 비교합니다.
- 같은 CVE와 공격 payload를 자동으로 연결하거나 공개 권고를 현재 공격 성공으로 취급하지 않습니다.

## 판정과 실패 상태

`range_decision=affected_version`은 제공된 버전이 권고의 범위와 맞는다는 계산입니다. 식별이 단서·선언인 경우 최종 `decision`은 `needs_review`입니다. 설치가 확인된 입력도 현재 공격 성공은 별도로 검증해야 합니다. NVD의 이름·CVE 별칭 연결만 있고 관찰 CPE가 없으면 검토 상태를 유지합니다.

기본 한도는 구성 요소 20개, 검색당 2페이지, 전체 HTTP 요청 20회, 전체 수집 제한 시간 180초입니다. 재시도도 요청 예산을 소모합니다. 공급자별 공통 대기 상태를 SQLite로 공유하며, 제한 응답의 Retry-After/리셋 시각과 연결 오류에 제한된 재시도를 적용합니다. 긴 대기 때문에 기한을 넘겨야 하면 `partial`로 반환합니다.

뒤 페이지가 실패해도 앞 페이지의 검증된 자료는 보관합니다. 오류·페이지 잘림·요청 한도·입력 잘림은 `jobs`, `errors`, `input_coverage`, `coverage`에 표시됩니다. `collection_complete=true`는 계획한 한도 안의 요청이 끝났다는 의미이며 전체 공개 취약점의 완전한 수집을 의미하지 않습니다. CLI는 부분 결과에서 종료 코드 2를 반환합니다.

```bash
python -m casper_db --db /absolute/path/cases.sqlite3 knowledge-sync-runs
```

소유한 DB가 있으면 수집 시작과 완료 영수증을 `external_sync_runs`에 남깁니다. 완료 영수증 없는 `running`은 미완료 작업입니다. 자동 성공·자동 재개로 해석하지 않습니다. 처음 만드는 DB에서 모든 공급자가 실패하면 빈 DB를 만들지 않으며 CLI 결과 파일이나 호출자의 실행 오류 기록을 확인합니다. 자료 저장 중 오류가 생기면 권고 입력 배치는 롤백합니다.

기본 API는 조회 전용입니다. `serve --allow-advisory-sync`에서만 `POST /knowledge/sync`를 켜며 localhost에서 수신합니다. API의 sync 본문은 정규화된 KnowledgeSync 계약입니다. 파서 원출력 변환은 위 Node 진입점을 사용합니다.

맥 설치와 실제 보고서·공개 API 사용 순서는 [맥 미니 안내](MAC_MINI_SETUP.ko.md)를 따릅니다. 현재 파서는 서버 내부 Python 패키지를 URL만으로 알아내는 도구가 아닙니다.
