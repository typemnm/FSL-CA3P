# Graph Report - FSL-CA3P  (2026-10-29)

## Corpus Check
- 387 files · ~290,712 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 35 file(s) not represented in the graph (top: .njk 13, (none) 12, .css 4)

## Summary
- 3503 nodes · 8507 edges · 185 communities (158 shown, 27 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 473 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `d2147f3f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- CaseStore
- ref_node_assert
- ref_node_crypto
- pathlib
- adapters/local-lab-gateway.mjs
- device-deploy.mjs
- createRunService
- digest
- sllm-verdict.js
- ReportIntake
- attack_catalog.py
- src/server.mjs
- sqlite3
- daehan
- ref_node_url
- deepseek-adapter.test.js
- subprocess
- general-assessment.js
- db-management.mjs
- write_sources.mjs
- steps
- smoke.mjs
- deepseek-config.js
- dashboard
- RuleReasoningEngine
- PortalController
- test_collect.py
- device-deploy-verification.mjs
- repeater.test.mjs
- dashboard
- adapters/integrations/knowledge-db.mjs
- protocol.js
- general-model-planner.js
- collector.py
- collect
- parse_hwpx_report
- README.md
- run-once.test.js
- createGeneralRuntime
- device-db.py
- application/ci-results.mjs
- general-runtime.mjs
- _run
- 3. 모듈 구조, 언어, 확장 방식
- trigger.py
- adapters/integrations/guardrail.mjs
- run-repeater.mjs
- test_hwpx_writer.py
- ci.mjs
- deepseek-reasoning-engine.js
- deepseek-client.js
- test_run_sources.py
- test_build_loop.py
- ref_node_fs
- review.js
- StoredEvent
- hwpx.py
- json
- tools.py
- idor-probe.mjs
- CASPER 취약점 DB
- publish-ci-summary.mjs
- org.springframework.web.bind.annotation.GetMapping
- writer.py
- 대한대학교 · 원창대학교 웹사이트
- intruder.mjs
- web-dependencies.test.mjs
- validateUniversityOrigin
- idor-runtime.mjs
- local_ocr.py
- env
- isPlainObject
- ref_node_url
- loop.py
- parser.mjs
- script-hints.mjs
- 파서 → 취약점 DB 입력 계약
- casper-db/README.md
- re
- scripts
- report — CA3P 보고서 Agent
- ca3p_report/cli.py
- normalize_filename
- xss-parser/package.json
- server.js
- ui-runtime-client.test.mjs
- 외부 모듈 JSON 계약
- DeepSeek 실제 API 통합 테스트 보고서
- 펜테스팅 에이전트 개발 계획
- stored_xss_events
- device-deploy-verification.test.mjs
- ocr_review.py
- test_cli.py
- pytest
- install-device-deploy.mjs
- application/local-runtime.mjs
- attack-module/index.js
- 대시보드 재구성 계획
- guardrail-sllm/package.json
- LLMError
- DeviceDatabaseTests
- app.js
- agent-dashboard/package.json
- CA3P 펜테스팅 에이전트 코어 MVP
- 재점검 기록의 저장과 검토
- matches_range
- serve-external.mjs
- vul-web-1/package.json
- dependency-inventory.mjs
- agent/package.json
- narrative.py
- jobs
- GuardrailEvaluator
- lab-session-registry.mjs
- unavailable
- capture/package.json
- run_store.py
- SiteCatalog
- web-parser — URL 기반 웹 구조·라이브러리 관찰
- 대한대학교·원창대학교 웹사이트 사전 침해분석 및 취약점 보고서
- general-assessment.test.js
- hwp_worker.py
- networks
- steps
- with
- guardrail/src/index.js
- SpringHeaderFilter.java
- ci.yml
- guardrail/package.json
- sLLM Guardrail
- 외부 모듈 JSON 계약
- redact
- CA3P Agent Loop — 로컬 통합 대시보드
- test_boundaries.py
- attack-module/package.json
- test_matching.py
- 이 Mac에서 팀 대시보드 외부 접속
- build_report_draft
- demo.py
- _InputCollector
- 모델 변경 시 실험 초기화
- updates
- deploy-staging
- 맥 미니에서 설치하고 직접 검증하기
- make_review_server
- publish-ci-summary
- publish-image
- True
- run-verdict-matrix.js
- 2. 입력과 출력
- contracts/package.json
- evaluation/package.json
- 1. 목표와 범위
- run-store/package.json
- CA3P 취약한 바닐라 JS 게시판
- 인트루더 (Intruder) — 에이전트 사용 설명서
- 리피터 (Repeater) — 에이전트 사용 설명서
- public/js/site.js
- deployment-check.mjs
- static/js/site.js
- 보고서 기반 DB 처리와 모듈 연결
- run-local-sllm.js
- WonchangApplication.java
- 보고서 생성 모듈(Report Agent) — 조사 결과 및 개발 PLAN
- attack-module/README.md
- mock-report-template.md
- previous-month-xss-report.md
- contracts/README.md
- ca3p-report
- casper-case-db
- edu.wonchang:wonchang-university
- 파서의 제품 정보로 공개 권고 수집·저장·조회하기
- 보고서 접수·검토·등록

## God Nodes (most connected - your core abstractions)
1. `CaseStore` - 87 edges
2. `digest()` - 49 edges
3. `PortalController` - 49 edges
4. `createRunService()` - 42 edges
5. `main()` - 35 edges
6. `ReportIntake` - 35 edges
7. `initialize_database()` - 33 edges
8. `run_command()` - 32 edges
9. `runOnce()` - 31 edges
10. `createRunRepository()` - 31 edges

## Surprising Connections (you probably didn't know these)
- `현재 시작 범위` --references--> `runOnce()`  [INFERRED]
  README.md → agent/src/orchestrator.js
- `0.3 보고서 양식` --references--> `Case`  [INFERRED]
  packages/report/PLAN.md → casper-db/src/casper_db/models.py
- `3.4 언어` --references--> `CaseStore`  [INFERRED]
  packages/report/PLAN.md → casper-db/src/casper_db/repository.py
- `사례·권고 통합 조회` --references--> `matchCasperHistory()`  [INFERRED]
  casper-db/README.md → packages/adapters/integrations/casper-db.mjs
- `에이전트 연결과 재현성` --references--> `prepareParserKnowledge()`  [INFERRED]
  casper-db/PRODUCT_ADVISORY_SYNC.ko.md → packages/adapters/integrations/casper-db.mjs

## Import Cycles
- None detected.

## Communities (185 total, 27 thin omitted)

### Community 0 - "CaseStore"
Cohesion: 0.07
Nodes (36): main(), main(), output(), inspect_evidence(), assess_observation(), Case, CaseQuery, CaseRecord (+28 more)

### Community 1 - "ref_node_assert"
Cohesion: 0.06
Nodes (45): serve(), { chromium }, event, idle, resetModels, setup(), snapshot(), wrap() (+37 more)

### Community 2 - "ref_node_crypto"
Cohesion: 0.06
Nodes (34): createModuleManagement(), definition(), fault(), MODULES, safeLog(), runWithFindings(), setup(), waitFor() (+26 more)

### Community 3 - "pathlib"
Cohesion: 0.05
Nodes (20): _parts(), same_reviewed_route(), validate_applicability(), validate_route_template(), CandidateMatch, ObservationAssessment, ParserObservation, EvidenceMetadata (+12 more)

### Community 4 - "adapters/local-lab-gateway.mjs"
Cohesion: 0.09
Nodes (34): browserAvailable(), browserInstalled(), parserRequire, browserAvailable(), exchange(), request(), prepareParserKnowledge(), createKnowledgeDb() (+26 more)

### Community 5 - "device-deploy.mjs"
Cohesion: 0.09
Nodes (52): execute(), spawn(), acquireLock(), atomicJson(), checkApplication(), database(), delay(), deploy() (+44 more)

### Community 6 - "createRunService"
Cohesion: 0.05
Nodes (81): prepareCaseSnapshot(), fault(), info(), inspect(), visit(), legacyRoot, prepareRunFileCleanup(), targetResetObligationsForRuns() (+73 more)

### Community 7 - "digest"
Cohesion: 0.08
Nodes (19): assess_database(), assess_record(), _cpe_parts(), discover_advisories(), _ecosystem(), _github(), lookup_assessments(), _nvd_name_candidates() (+11 more)

### Community 8 - "sllm-verdict.js"
Cohesion: 0.08
Nodes (46): KNOWN_ERROR_CODES, makeErrorResult(), buildJudgmentPrompt(), buildVulnerabilityGuidelinesText(), JUDGMENT_CRITERIA, VULNERABILITY_GUIDELINES, buildScopeChecks(), buildSllmInput() (+38 more)

### Community 9 - "ReportIntake"
Cohesion: 0.10
Nodes (24): references(), _actor(), _archive_case(), _case_audit(), _case_detail(), _case_state(), dispatch(), _intake_item() (+16 more)

### Community 10 - "attack_catalog.py"
Cohesion: 0.05
Nodes (53): _github_params(), KnowledgeSync, sync_knowledge(), collect(), create_app(), attack_info_query(), attack_patterns(), attack_template() (+45 more)

### Community 11 - "src/server.mjs"
Cohesion: 0.06
Nodes (47): cookie-parser, dayjs, express, json5, lodash, markdown-it, nunjucks, dependencies (+39 more)

### Community 13 - "sqlite3"
Cohesion: 0.10
Nodes (17): defer_provider(), PublicCollectionError, _rate_path(), read_public_json(), reserve_slot(), _retry_delay(), _validate_rate_state(), case_data() (+9 more)

### Community 14 - "daehan"
Cohesion: 0.05
Nodes (42): context, dockerfile, build, cap_drop, environment, image, init, driver (+34 more)

### Community 15 - "ref_node_url"
Cohesion: 0.13
Nodes (19): adapterSource, casperSource, CONCURRENT_COMMIT, pythonEnvironment, report, main(), absoluteDatabasePath(), DEFAULT_DB (+11 more)

### Community 16 - "deepseek-adapter.test.js"
Cohesion: 0.08
Nodes (5): createStoredXssCanary(), storedXssCanaryContent(), VALID_DECISION, MARKER, planInput()

### Community 17 - "subprocess"
Cohesion: 0.16
Nodes (8): casper_db(), linked_entry(), _node_ready(), run_id(), stored_run(), tree_digest(), write_sources(), test_matches_contracts()

### Community 18 - "general-assessment.js"
Cohesion: 0.12
Nodes (36): aborted(), assertPort(), assertSafeToolInput(), boundedString(), buildFindings(), eventAsset(), evidenceRefs(), fault() (+28 more)

### Community 19 - "db-management.mjs"
Cohesion: 0.40
Nodes (8): createDbManagement(), DbManagementError, PYTHON_SOURCE, readLimited(), readMultipart(), reportName(), ROOT, runBridge()

### Community 20 - "write_sources.mjs"
Cohesion: 0.09
Nodes (18): { chromium }, report, run, { chromium }, idle, run, pentestDb, replies (+10 more)

### Community 21 - "steps"
Cohesion: 0.06
Nodes (35): concurrency, cancel-in-progress, group, environment, if, runs-on, steps, timeout-minutes (+27 more)

### Community 22 - "smoke.mjs"
Cohesion: 0.10
Nodes (24): json(), main(), bodyText(), CaptureError, DEFAULT_TIMEOUT_MS, normalizeSwitch(), normalizeSwitches(), openSandbox() (+16 more)

### Community 23 - "deepseek-config.js"
Cohesion: 0.15
Nodes (16): 9. 공개 API와 기존 계약 영향, DeepSeekClient, configError(), createDeepSeekReasoningEngineFromEnv(), DEFAULT_ENV_FILE, normalizeBaseUrl(), parseEnvText(), parseIntegerSetting() (+8 more)

### Community 24 - "dashboard"
Cohesion: 0.06
Nodes (32): VCS_REF, args, context, dockerfile, build, env_file, environment, healthcheck (+24 more)

### Community 25 - "RuleReasoningEngine"
Cohesion: 0.07
Nodes (29): 실행 범위, 10. 테스트 계획, 11. Opt-in live contract demo, 12. 단계적 rollout과 rollback, 13. 완료 기준, 1. 목적과 범위, 2. 공식 API 사실과 프로젝트 정책, 3. 목표 구조 (+21 more)

### Community 27 - "test_collect.py"
Cohesion: 0.16
Nodes (20): make_trigger(), pentest_trigger(), run_cli(), run_cli_raw(), test_bundle_is_write_once(), test_collects_a_sealed_bundle(), test_concurrent_collections_cannot_both_seal(), test_deeply_nested_json_is_a_json_error() (+12 more)

### Community 28 - "device-deploy-verification.mjs"
Cohesion: 0.15
Nodes (27): apiIdentifier(), assertLatestRun(), assertRun(), attempt(), count(), COUNTS, identifier(), INDEX_KEYS (+19 more)

### Community 29 - "repeater.test.mjs"
Cohesion: 0.17
Nodes (17): lookupAttackInfoSync(), PROGRAM, readAttackCatalogSync(), requestKnowledgeSync(), ROOT, loadAttackInfo(), createGuardedRequest(), createRuleset() (+9 more)

### Community 30 - "dashboard"
Cohesion: 0.07
Nodes (28): env_file, environment, healthcheck, image, init, ports, restart, shm_size (+20 more)

### Community 31 - "adapters/integrations/knowledge-db.mjs"
Cohesion: 0.07
Nodes (20): MULTI_CATALOG, request(), importLegacyRuns(), runRealBoardCanary(), terminal(), absolutePath(), initialize(), DEFAULT_DATABASE (+12 more)

### Community 32 - "protocol.js"
Cohesion: 0.12
Nodes (36): request(), assertBoundDeleteAction(), assertBoundXssAction(), assertGateway(), ensureCompleteParserResult(), findTrustedCanary(), localCanaryCandidate(), localOrigin() (+28 more)

### Community 33 - "general-model-planner.js"
Cohesion: 0.21
Nodes (19): boundedString(), createGeneralModelPlanner(), EVIDENCE_KEYS, evidenceForPrompt(), exactKeys(), GeneralModelPlanner, identifier(), isRecord() (+11 more)

### Community 34 - "collector.py"
Cohesion: 0.17
Nodes (11): CollectResult, _ids(), _rows(), select_finding(), CollectError, RunRecord, _digest(), _event() (+3 more)

### Community 35 - "collect"
Cohesion: 0.17
Nodes (7): BundleExistsError, BundleWriter, _bytes(), OutputError, _write_exclusive(), read_history(), collect()

### Community 36 - "parse_hwpx_report"
Cohesion: 0.27
Nodes (8): parse_hwpx_report(), _read_document(), _section_names(), _sha(), _tag(), _text(), walk(), _xml()

### Community 37 - "README.md"
Cohesion: 0.11
Nodes (16): CA3P 모듈 경계, 통합 취약점 DB, 1. 변경 전 로컬 검증, 2. PR 및 배포 확인, 3. 대시보드 기능 테스트, 4. 이 장치에서 외부 접속 테스트, CA3P, CI/CD 및 대시보드 테스트 가이드 (+8 more)

### Community 38 - "run-once.test.js"
Cohesion: 0.17
Nodes (8): main(), main(), createScriptedGateway(), attackResponse(), evidenceId(), exchange(), parserResponse(), respond()

### Community 39 - "createGeneralRuntime"
Cohesion: 0.19
Nodes (22): createGeneralRuntime(), appendEvent(), authenticatedObservation(), boardCrossUserDeleteCanary(), request(), checkedRequest(), close(), execute() (+14 more)

### Community 40 - "device-db.py"
Cohesion: 0.26
Nodes (17): backup_command(), columns(), connect_readonly(), digest(), fsync_directory(), fsync_file(), inspect_command(), inspect_db() (+9 more)

### Community 41 - "application/ci-results.mjs"
Cohesion: 0.13
Nodes (23): auth, ciResults, port, publicOrigins, runtime, server, count(), createCiResultsService() (+15 more)

### Community 42 - "general-runtime.mjs"
Cohesion: 0.16
Nodes (20): ACTIVE, sourceReferences(), DEMO_PASSWORDS, eventCount(), eventIdentifier(), eventIdentifiers(), eventMetadataText(), FIXTURES (+12 more)

### Community 43 - "_run"
Cohesion: 0.25
Nodes (16): _run(), _asset_path(), build_general_model(), _text(), _event(), _report(), _result(), _store() (+8 more)

### Community 44 - "3. 모듈 구조, 언어, 확장 방식"
Cohesion: 0.22
Nodes (9): 3.1 구조, 3.2 프로필 선택 (사이트 어댑터는 두지 않음), 3.3 프로필 인터페이스 (Python, build 측), 3.4 언어, 3.5 python-hwpx 사용 방침, 3.6 디렉터리 구성(안), 3.7 새 취약점·새 사이트·새 원천을 추가하는 절차, 3.8 "Agent"의 범위 (+1 more)

### Community 45 - "trigger.py"
Cohesion: 0.19
Nodes (14): _absolute(), parse_trigger(), _record(), _refuse_output_inside_sources(), _resolved(), _source(), SourceRef, Trigger (+6 more)

### Community 46 - "adapters/integrations/guardrail.mjs"
Cohesion: 0.14
Nodes (15): newGuardrail(), 사용, createGuardrailForRun(), createLocalGuardrail(), authorizeAction(), trustedContext(), exactKeys(), GuardrailDeniedError (+7 more)

### Community 47 - "run-repeater.mjs"
Cohesion: 0.18
Nodes (4): child, dataDir, dataFile, serverPath

### Community 48 - "test_hwpx_writer.py"
Cohesion: 0.36
Nodes (11): write_hwpx(), model(), section_xml(), test_body_has_no_hashes(), test_failed_run_renders_the_failure_variant(), test_html_preview_renders_tables_and_intact_images_without_executing_payload(), test_hwpx_saves_validates_and_carries_the_outline(), test_images_only_ok_and_inside_root_are_embedded() (+3 more)

### Community 49 - "ci.mjs"
Cohesion: 0.12
Nodes (16): args, dryRun, manifest, nodeOnly, completeSuiteCoverage(), createSuitePlan(), testFiles(), report (+8 more)

### Community 50 - "deepseek-reasoning-engine.js"
Cohesion: 0.25
Nodes (13): curlFromHttpAction(), isPlainObject(), boundedText(), CURL_DECISION_KEYS, DECISION_KEYS, isPlainObject(), promptCandidate(), sanitizeMetadata() (+5 more)

### Community 51 - "deepseek-client.js"
Cohesion: 0.20
Nodes (14): boundedInteger(), cancelBody(), configError(), declaredContentLength(), DeepSeekError, normalizeBaseUrl(), readBoundedResponseText(), responseError() (+6 more)

### Community 52 - "test_run_sources.py"
Cohesion: 0.14
Nodes (20): envelope(), stored_xss_events(), as_set(), run_dir(), test_events_without_final_report(), test_pentest_db_ignores_foreign_files(), test_pentest_db_missing_store_is_a_source_error(), test_pentest_db_reads_events_and_final_report() (+12 more)

### Community 53 - "test_build_loop.py"
Cohesion: 0.18
Nodes (10): stored_xss_report(), _bundle(), _call(), FakeLLM, model_for(), test_captured_ref_is_embedded_in_hwpx(), complete(), fake_capture() (+2 more)

### Community 54 - "ref_node_fs"
Cohesion: 0.07
Nodes (25): CASE_FIXTURES, SNAPSHOT_CODE, assertRegularDatabase(), fault(), historyOperation(), prepareExperimentCleanup(), prepareHistoryReset(), PROGRAM (+17 more)

### Community 55 - "review.js"
Cohesion: 0.30
Nodes (20): badge(), downloadJSON(), endpointTitle(), fieldView(), findingList(), inputField(), navigate(), node() (+12 more)

### Community 56 - "StoredEvent"
Cohesion: 0.20
Nodes (12): _attack_body_keys(), _attacker_account(), capture_hints(), _event(), _input_forms(), _parser_report(), _path_of(), _session_switch() (+4 more)

### Community 57 - "hwpx.py"
Cohesion: 0.16
Nodes (16): _finding(), issue(), _has_value(), _payloads(), _query(), refresh_field_status(), issue(), _urls() (+8 more)

### Community 58 - "json"
Cohesion: 0.07
Nodes (33): _extract(), load_external(), read_json(), run_automation(), _write(), _paragraph_text(), walk(), parse_hwp_report() (+25 more)

### Community 59 - "tools.py"
Cohesion: 0.19
Nodes (9): _dispatch(), _file_entry(), FinishResult, ReportTools, ToolError, _validate_origin(), test_capture_origin_must_be_loopback(), test_read_bundle_masks_plain_text_headers_without_rewriting_evidence() (+1 more)

### Community 60 - "idor-probe.mjs"
Cohesion: 0.21
Nodes (16): createGuardedGet(), createIdorRuleset(), exactTargetOrigin(), findingStatus(), login(), logout(), observation(), pathFor() (+8 more)

### Community 61 - "CASPER 취약점 DB"
Cohesion: 0.13
Nodes (15): CASPER 취약점 DB, DB 버전 전환, pentest-db 통합과 폐기, 기능, 사례·권고 통합 조회, 설치, 외부 취약점 정보·일괄 처리, 이후 공격 툴 연결 계약 (+7 more)

### Community 62 - "publish-ci-summary.mjs"
Cohesion: 0.10
Nodes (27): CA3P 통합 및 배포, Docker 실행 및 영속화, GitHub Actions, 로컬 검증, 신뢰된 배포 runner, 통합 규칙, cases, DEFAULT_MODULE_DIRECTORY (+19 more)

### Community 64 - "writer.py"
Cohesion: 0.37
Nodes (16): build_blocks(), _cover(), _cvss(), _dicts(), _failure(), _finding(), _history(), _kv_rows() (+8 more)

### Community 65 - "대한대학교 · 원창대학교 웹사이트"
Cohesion: 0.11
Nodes (15): 대한대학교 최종 프롬프트, 메인 캠퍼스 이미지 제작 기록, 원창대학교 최종 프롬프트, 1. 장애 원인과 조치, 2. 재검증 결과, 3. 검증 범위, Docker 장애 원인 및 두 대학 사이트 기능 재검증, ARTEX 사건을 참고한 평가 시나리오 (+7 more)

### Community 66 - "intruder.mjs"
Cohesion: 0.23
Nodes (14): buildPath(), countField(), createGuardedRequest(), createRuleset(), escapeRegex(), exactLoopbackOrigin(), IntruderDeniedError, loadIntruderPlan() (+6 more)

### Community 67 - "web-dependencies.test.mjs"
Cohesion: 0.17
Nodes (10): main(), parseArgs(), inventory(), createWebInventory(), digest(), LIMITS, MODULE_ID, readResourceReferences() (+2 more)

### Community 68 - "validateUniversityOrigin"
Cohesion: 0.17
Nodes (11): fault(), ISOLATED_FIXTURES, managementOrigin(), prepareTargetReset(), REQUIRED_SCOPES, UNIVERSITY_FIXTURES, env, run (+3 more)

### Community 69 - "idor-runtime.mjs"
Cohesion: 0.22
Nodes (14): ACTIVE, CHECKS, createIdorRuntime(), appendEvent(), close(), execute(), getState(), publish() (+6 more)

### Community 70 - "local_ocr.py"
Cohesion: 0.19
Nodes (10): Box, extract_local_ocr(), _hwp_raster(), _is_raster(), Line, OcrImage, OcrModel, Recognition (+2 more)

### Community 71 - "env"
Cohesion: 0.12
Nodes (17): ACTOR, CA3P_BEFORE_SHA, CA3P_COMMIT_SHA, CA3P_CONTAINER_RESULT, CA3P_GATE_RESULT, CA3P_REPORT_PYTHON, CA3P_REQUIRE_BROWSER, CA3P_TEST_RESULT (+9 more)

### Community 72 - "isPlainObject"
Cohesion: 0.31
Nodes (8): bodyKeys(), ConditionEvaluator, queryKeys(), containsKeyDeep(), deepEqual(), getField(), isPlainObject(), isSubset()

### Community 73 - "ref_node_url"
Cohesion: 0.06
Nodes (33): generalDocumentsStatus(), tick(), storeReportPreviews(), canonical(), program, pythonJson(), resultProgram, reviewRunCheck() (+25 more)

### Community 74 - "loop.py"
Cohesion: 0.21
Nodes (6): _bundle_summary(), run_build(), build_system_prompt(), tool_schemas(), Profile, resolve_profile()

### Community 75 - "parser.mjs"
Cohesion: 0.26
Nodes (15): readDom(), abortError(), awaitWithSignal(), checkLocalUrl(), compactReport(), displayStaticApiUrl(), displayUrl(), navigationKey() (+7 more)

### Community 76 - "script-hints.mjs"
Cohesion: 0.35
Nodes (16): analyzeScript(), bodyKeys(), callRequest(), defaultGetWrapper(), effects(), expressionName(), name(), objectValue() (+8 more)

### Community 77 - "파서 → 취약점 DB 입력 계약"
Cohesion: 0.12
Nodes (15): 6. `deepseek-reasoning-engine.js`, hybrid safety boundary, 모델 출력 schema, 결과의 의미, 경로 파라미터, 로컬 HTML 입력 추출, 입력이 적용되지 않는 경우, 팀 파서 출력의 선택적 입력 위치 (+7 more)

### Community 78 - "casper-db/README.md"
Cohesion: 0.22
Nodes (4): 공개 권고와 대상 소프트웨어의 영향 범위 비교, 비교 기준, 입력과 결과, 저장과 갱신

### Community 79 - "re"
Cohesion: 0.26
Nodes (9): cache_identity(), _data_arguments(), _executable(), ocr_status(), parse_tsv(), _process(), recognize_raster(), runtime_profile() (+1 more)

### Community 81 - "scripts"
Cohesion: 0.12
Nodes (15): description, engines, node, name, private, scripts, check:boundaries, ci:plan (+7 more)

### Community 82 - "report — CA3P 보고서 Agent"
Cohesion: 0.25
Nodes (5): report — CA3P 보고서 Agent, 구현 현황, 수집 단계, 테스트, 통합 대시보드

### Community 83 - "ca3p_report/cli.py"
Cohesion: 0.19
Nodes (8): _collect(), _emit(), _failure(), main(), _origin_and_switch(), _read_trigger(), RunIncomplete, RunNotFound

### Community 84 - "normalize_filename"
Cohesion: 0.25
Nodes (9): normalize_filename(), test_control_chars_are_removed_and_text_is_nfc(), test_empty_or_invalid_falls_back_to_run_id(), test_extension_is_forced_to_a_single_hwpx(), test_overlong_name_is_capped_at_120(), test_reserved_prefix_inside_longer_name_is_allowed(), test_traversal_keeps_the_readable_part(), test_traversal_never_leaves_a_separator_or_dotdot() (+1 more)

### Community 85 - "xss-parser/package.json"
Cohesion: 0.14
Nodes (15): acorn, dependencies, acorn@8.15.0, playwright@1.58.2, engines, node, playwright, name (+7 more)

### Community 86 - "server.js"
Cohesion: 0.22
Nodes (15): currentUser(), ensureDataFile(), handleApi(), handler(), initialPosts(), parseUserCookie(), PORT, readJson() (+7 more)

### Community 87 - "ui-runtime-client.test.mjs"
Cohesion: 0.13
Nodes (3): envelope, session, Source

### Community 88 - "외부 모듈 JSON 계약"
Cohesion: 0.25
Nodes (8): report(), xss-parser, 검증 범위, 0.1 실행 보고서와 이벤트 — pentest-db 디스크 저장 규약, 0.3 보고서 양식, 0.4 develop에서 바뀐 점 (계획에 영향), 0.5 실습 게시판 수명과 촬영 관련 사실 (develop, 10-19 확인), 0. 조사 요약 (근거)

### Community 89 - "DeepSeek 실제 API 통합 테스트 보고서"
Cohesion: 0.13
Nodes (15): 10. 기준 문서, 1. 결론, 2. 테스트 범위와 경계, 3. 실행 환경, 4. 절차와 합격 기준, 5. 결과, 6. 정규화된 실행 증거, 7. 보안 및 비용 확인 (+7 more)

### Community 90 - "펜테스팅 에이전트 개발 계획"
Cohesion: 0.13
Nodes (14): 1. 담당 범위, 2. 논문에서 가져온 설계 원칙, 3. 외부 통신 계약, 4. 최초 단일 루프, 5. 오류와 안전 규칙, 6. 단계별 계획, 7. Agent 완료 기준, Phase 0 — Agent Core (+6 more)

### Community 91 - "stored_xss_events"
Cohesion: 0.27
Nodes (5): events(), test_database_is_read_only(), test_reads_snapshot_at_compared_revision_and_checks(), test_refs_come_from_the_runs_own_assessments(), test_refs_ignore_malformed_matches()

### Community 92 - "device-deploy-verification.test.mjs"
Cohesion: 0.16
Nodes (8): GitHubRateLimitError, api(), candidate, headSha, job(), jobs(), json(), select()

### Community 93 - "ocr_review.py"
Cohesion: 0.36
Nodes (8): ocr_fingerprint(), OcrBundle, validate_recognition(), evidence(), apply_ocr_evidence(), evidence(), ocr_ref(), FieldEvidence

### Community 94 - "test_cli.py"
Cohesion: 0.46
Nodes (7): run_cli(), test_cli_adds_and_lists_check(), test_cli_matches_parser_observations_and_explains_decisions(), test_cli_preserves_report_history_and_detects_stale_revision(), test_cli_review_and_evidence_verification(), test_cli_round_trip_and_error_exit_codes(), test_schema_export_and_invalid_json_do_not_create_database()

### Community 95 - "pytest"
Cohesion: 0.25
Nodes (11): test_disk_round_trip_preserves_unicode_payload_and_lists(), test_duplicate_requires_explicit_update_and_preserves_created_at(), test_failed_reads_do_not_create_database(), test_initialization_preserves_existing_data_and_rejects_foreign_database(), test_invalid_contract_is_rejected(), test_invalid_update_does_not_change_existing_record(), test_lookup_excludes_drafts_and_matches_target_path_and_method_exactly(), test_ready_prior_report_requires_its_core_fields() (+3 more)

### Community 96 - "install-device-deploy.mjs"
Cohesion: 0.28
Nodes (13): acquireInstallationLock(), buildDashboardPlist(), buildUpdaterPlist(), CONTROLLER_FILES, exists(), installDeviceDeploy(), parsePlist(), PATH_KEYS (+5 more)

### Community 97 - "application/local-runtime.mjs"
Cohesion: 0.14
Nodes (25): ACTIVE, createLocalRuntime(), appendEvent(), close(), execute(), getState(), publish(), reset() (+17 more)

### Community 98 - "attack-module/index.js"
Cohesion: 0.30
Nodes (13): childEnv(), executeCurl(), executePinnedCurl(), finish(), executeUniversityRead(), failure(), findHeaderEnd(), isJsonValue() (+5 more)

### Community 99 - "대시보드 재구성 계획"
Cohesion: 0.14
Nodes (13): 1. 목표와 현재 경계, 2. 정보 구조와 이동 경로, 3.1 공격, 3.2 보고서, 3.3 DB — 취약점 자료 관리, 3. Workspace 화면, 4. Modules 화면, 5. 필요한 서버 계약 (+5 more)

### Community 100 - "guardrail-sllm/package.json"
Cohesion: 0.14
Nodes (13): description, engines, node, main, name, private, scripts, ollama:check (+5 more)

### Community 101 - "LLMError"
Cohesion: 0.19
Nodes (5): HttpChatClient, LLMConfig, LLMError, test_llm_failure_propagates(), complete()

### Community 103 - "app.js"
Cohesion: 0.34
Nodes (13): api(), createListMessage(), deletePost(), elements, formatDate(), initialize(), loadPosts(), makePostCard() (+5 more)

### Community 104 - "agent-dashboard/package.json"
Cohesion: 0.15
Nodes (12): engines, node, name, private, scripts, check, dev, start (+4 more)

### Community 105 - "CA3P 펜테스팅 에이전트 코어 MVP"
Cohesion: 0.15
Nodes (9): CA3P 펜테스팅 에이전트 코어 MVP, DeepSeek API 어댑터, finding 식별과 중복 처리, Production 파일, 범용 점검 코어와 운영 연결, 실행과 검증, 에이전트 루프, 현재 계약 (+1 more)

### Community 106 - "재점검 기록의 저장과 검토"
Cohesion: 0.15
Nodes (13): 1. 참고한 보고서 버전을 지정한다, 2. 관찰한 결과를 초안으로 저장한다, 3. 입력 위치가 바뀌었다면 연결을 따로 확인한다, 4. 증거를 확인하고 결과를 검토 완료로 처리한다, 검증기의 여러 결과를 한 번에 저장한다, 기존 DB를 변환할 때, 재점검 기록의 저장과 검토, 검토된 경로 템플릿 (+5 more)

### Community 107 - "matches_range"
Cohesion: 0.27
Nodes (9): _all(), _any(), _nvd(), entry(), node(), compare_versions(), matches_range(), UnresolvedVersion (+1 more)

### Community 108 - "serve-external.mjs"
Cohesion: 0.21
Nodes (10): capture(), detectStderrOrigin, detectStdoutOrigin, port, root, runtimeDir, stop(), timeout (+2 more)

### Community 109 - "vul-web-1/package.json"
Cohesion: 0.15
Nodes (12): description, engines, node, name, private, scripts, intruder, probe:idor (+4 more)

### Community 110 - "dependency-inventory.mjs"
Cohesion: 0.24
Nodes (12): bounded(), child(), object(), parseNpmLock(), parsePom(), readInventory(), string(), value() (+4 more)

### Community 112 - "agent/package.json"
Cohesion: 0.17
Nodes (11): description, engines, node, name, private, scripts, demo, demo:deepseek (+3 more)

### Community 113 - "narrative.py"
Cohesion: 0.19
Nodes (9): has_supplied_value(), is_unknown(), has_review_evidence(), meaningful(), apply_narrative_analysis(), classify_paragraph(), _parameter_names(), Segment (+1 more)

### Community 114 - "jobs"
Cohesion: 0.17
Nodes (12): runs-on, timeout-minutes, if, name, needs, runs-on, jobs, container-smoke (+4 more)

### Community 115 - "GuardrailEvaluator"
Cohesion: 0.26
Nodes (5): Agent Loop 연결, CA3P Guardrail Evaluator, 구성, 실행, GuardrailEvaluator

### Community 116 - "lab-session-registry.mjs"
Cohesion: 0.47
Nodes (11): alive(), exists(), failure(), inspect(), plainPath(), prepareLabSessionCleanup(), privateJson(), registerLabSession() (+3 more)

### Community 117 - "unavailable"
Cohesion: 0.32
Nodes (8): Report Agent — 현재 구현과 플랫폼 연동, 계층과 책임, 실행·보호 경계와 한계, 실행 흐름, 입력과 출력, 플랫폼 상태와 다운로드, 6. 테스트 전략, unavailable()

### Community 118 - "capture/package.json"
Cohesion: 0.18
Nodes (11): dependencies, playwright@1.58.2, engines, node, playwright, name, private, scripts (+3 more)

### Community 119 - "run_store.py"
Cohesion: 0.17
Nodes (10): history_refs(), reference_context(), StoredEvent, _core_event(), _general_events(), _legacy_event(), _load(), read_run() (+2 more)

### Community 121 - "web-parser — URL 기반 웹 구조·라이브러리 관찰"
Cohesion: 0.18
Nodes (11): moduleId(), URL 기반 의존성 결과, web-parser — URL 기반 웹 구조·라이브러리 관찰, 공통 출력 키의 출처, 구조용 출력 읽기, 선택적 로컬 의존성 파일, 수집 경계, 식별 규칙의 범위 (+3 more)

### Community 122 - "대한대학교·원창대학교 웹사이트 사전 침해분석 및 취약점 보고서"
Cohesion: 0.17
Nodes (12): 1. 요약과 판정 기준, 2. 서비스 구성과 정상 기능, 3.1 대한대학교: 선정한 CVE 세 건, 3.2 원창대학교: 선정한 CVE 세 건, 3. 외부 의존성 및 CVE 평가, 4. OWASP Top 10:2025별 사전 분석, 5. 중점 시나리오: 게시글 삭제와 사이트 가용성, 6. ARTEX 사건을 참고한 부속 업무 위험 (+4 more)

### Community 124 - "hwp_worker.py"
Cohesion: 0.27
Nodes (4): inspect_hwp(), main(), image_root(), png()

### Community 125 - "networks"
Cohesion: 0.18
Nodes (10): networks, networks, university-daehan, university-wonchang, services, dashboard, external, name (+2 more)

### Community 126 - "steps"
Cohesion: 0.36
Nodes (11): steps, steps, steps, steps, continue-on-error, id, if, name (+3 more)

### Community 127 - "with"
Cohesion: 0.18
Nodes (11): with, cache, cache-dependency-path, fetch-depth, if-no-files-found, name, node-version-file, path (+3 more)

### Community 128 - "guardrail/src/index.js"
Cohesion: 0.17
Nodes (8): classify(), decodeHtmlEntities(), NAMED_ENTITIES, normalizeString(), loadRuleset(), validateRuleset(), ruleset, rulesetPath

### Community 130 - "ci.yml"
Cohesion: 0.22
Nodes (9): concurrency, cancel-in-progress, group, permissions, name, permissions, contents, packages (+1 more)

### Community 131 - "guardrail/package.json"
Cohesion: 0.20
Nodes (9): description, engines, node, main, name, private, scripts, test (+1 more)

### Community 132 - "sLLM Guardrail"
Cohesion: 0.20
Nodes (9): package.json script 설명, sLLM Guardrail, 네 가지 기능 파일, 사용 예시, 실행 흐름, 입력 형식, 코드 읽기 가이드, 테스트 (+1 more)

### Community 133 - "외부 모듈 JSON 계약"
Cohesion: 0.29
Nodes (7): Attack Module, casper-db, 공통 envelope, 오류, 외부 모듈 JSON 계약, 전송 포트, 통합 DB의 공격 정보와 실행 기록

### Community 134 - "redact"
Cohesion: 0.27
Nodes (7): _form_encode(), is_secret_key(), redact(), redact_string(), _replace_url(), test_redact_masks_newer_openai_key_formats(), test_redact_vectors()

### Community 135 - "CA3P Agent Loop — 로컬 통합 대시보드"
Cohesion: 0.22
Nodes (8): CA3P Agent Loop — 로컬 통합 대시보드, 검증, 로컬 실측 기록, 사용 방법, 실행, 연결과 기록 보관, 추가 제안, 파일 구성

### Community 136 - "test_boundaries.py"
Cohesion: 0.44
Nodes (5): _rel(), sources(), test_no_environment_variable_reads(), test_no_hardcoded_absolute_paths(), test_no_network_modules()

### Community 137 - "attack-module/package.json"
Cohesion: 0.22
Nodes (8): description, engines, node, name, private, scripts, test, version

### Community 138 - "test_matching.py"
Cohesion: 0.39
Nodes (7): observed(), test_changed_method_or_parameter_requires_manual_review(), test_draft_is_not_used_for_normal_candidate_matching(), test_exact_location_is_a_retest_candidate_but_never_a_finding(), test_input_location_mismatch_or_missing_location_requires_review(), test_parser_contract_rejects_ambiguous_or_extra_input(), test_weak_location_similarity_is_not_promoted()

### Community 139 - "이 Mac에서 팀 대시보드 외부 접속"
Cohesion: 0.22
Nodes (9): 검증된 develop 자동 배포, 대학 사이트 실습 반영, 상태·실패·재시도, 설치, 이 Mac에서 팀 대시보드 외부 접속, 이 장치의 서버 운영, 임시 Cloudflare 경로, 자동 배포 중지·재개 (+1 more)

### Community 140 - "build_report_draft"
Cohesion: 0.33
Nodes (5): build_report_draft(), _fields(), _label(), _labeled_sections(), 문서 접수와 후보 추출

### Community 142 - "demo.py"
Cohesion: 0.17
Nodes (8): escaped(), pretty(), render(), _caption(), _load_png(), _md(), write_html(), write_markdown()

### Community 144 - "모델 변경 시 실험 초기화"
Cohesion: 0.25
Nodes (7): 검증 계획, 구현 순서와 실패 처리, 대학 실습 관리 훅, 모델 변경 시 실험 초기화, 사용 흐름, 연구 해석과 범위의 한계, 영향 범위 조사와 처리

### Community 145 - "updates"
Cohesion: 0.25
Nodes (7): interval, updates, directory, package-ecosystem, schedule, target-branch, version

### Community 146 - "deploy-staging"
Cohesion: 0.25
Nodes (8): if, needs, secrets, uses, with, deploy-staging, environment, image

### Community 148 - "맥 미니에서 설치하고 직접 검증하기"
Cohesion: 0.25
Nodes (8): Docker를 사용하는 경우, 맥 미니에서 설치하고 직접 검증하기, 설치 환경, 실제 보고서 접수·검토·등록, 실제 파서 결과 → GitHub/NVD → 같은 DB 저장·조회, 실행 환경 확인, 에이전트와 서비스 실행, 통합 DB를 사용하는 공격 툴 확인

### Community 149 - "make_review_server"
Cohesion: 0.38
Nodes (4): make_review_server(), do_GET(), do_HEAD(), _page()

### Community 150 - "publish-ci-summary"
Cohesion: 0.29
Nodes (7): publish-ci-summary, actions, if, needs, permissions, runs-on, timeout-minutes

### Community 151 - "publish-image"
Cohesion: 0.29
Nodes (7): publish-image, image, if, needs, outputs, runs-on, timeout-minutes

### Community 152 - "True"
Cohesion: 0.29
Nodes (7): branches, branches, True, merge_group, pull_request, push, workflow_dispatch

### Community 153 - "run-verdict-matrix.js"
Cohesion: 0.33
Nodes (5): cases, DEFAULT_MODULE_DIRECTORY, main(), runCase(), timeoutMs

### Community 154 - "2. 입력과 출력"
Cohesion: 0.29
Nodes (7): 2.1 Agent 입력 = 트리거 하나, 2.3 코어 입력 = ReportInput 번들 (고정), 2.4 run 보고서에서 쓰는 필드, 2.5 직접 촬영 (capture, LLM이 도구로 호출), 2.6 출력, 2.7 HWPX 보고서 목차 (확정, Q7), 2. 입력과 출력

### Community 155 - "contracts/package.json"
Cohesion: 0.29
Nodes (6): engines, node, name, private, type, version

### Community 156 - "evaluation/package.json"
Cohesion: 0.29
Nodes (6): engines, node, name, private, type, version

### Community 157 - "1. 목표와 범위"
Cohesion: 0.29
Nodes (7): 1.1 보고서가 답해야 할 것, 1.2 전체 흐름, 1.3 하는 일, 1.4.1 운영 전제 — 보고서는 사람이 최종 검토한다, 1.4 하지 않는 일, 1.5 프레이밍 지침 (프롬프트로 LLM에 유도, 코드 강제 아님), 1. 목표와 범위

### Community 158 - "run-store/package.json"
Cohesion: 0.29
Nodes (6): engines, node, name, private, type, version

### Community 159 - "CA3P 취약한 바닐라 JS 게시판"
Cohesion: 0.29
Nodes (6): 1. 저장형 XSS, 2. 파라미터 변조로 관리자 글 삭제, CA3P 취약한 바닐라 JS 게시판, 계정과 게시판, 실행, 취약점 재현

### Community 160 - "인트루더 (Intruder) — 에이전트 사용 설명서"
Cohesion: 0.33
Nodes (6): 결과, 동작, 새 공격 유형 추가, 어떻게 호출하나, 언제 쓰나, 인트루더 (Intruder) — 에이전트 사용 설명서

### Community 161 - "리피터 (Repeater) — 에이전트 사용 설명서"
Cohesion: 0.29
Nodes (6): 결과, 동작, 리피터 (Repeater) — 에이전트 사용 설명서, 새 공격 유형 추가, 어떻게 호출하나, 언제 쓰나

### Community 162 - "public/js/site.js"
Cohesion: 0.60
Nodes (4): clearResults(), performSearch(), renderResults(), resultUrl()

### Community 163 - "deployment-check.mjs"
Cohesion: 0.47
Nodes (4): expect(), login(), request(), sites

### Community 164 - "static/js/site.js"
Cohesion: 0.60
Nodes (4): clearResults(), performSearch(), renderResults(), resultUrl()

### Community 165 - "보고서 기반 DB 처리와 모듈 연결"
Cohesion: 0.40
Nodes (5): 검토와 등록, 공개 취약점 정보, 보고서 기반 DB 처리와 모듈 연결, 조회·재점검·보고서 연결, 팀 환경에서 확인할 사항

### Community 166 - "run-local-sllm.js"
Cohesion: 0.60
Nodes (4): buildSafeFixture(), DEFAULT_MODULE_DIRECTORY, loadVerdictModule(), main()

### Community 168 - "보고서 생성 모듈(Report Agent) — 조사 결과 및 개발 PLAN"
Cohesion: 0.33
Nodes (6): 4.1 트리거: `ReportTrigger` (main Agent → Report Agent), 4.2 결과: `ReportResult` (Report Agent → main Agent), 4. 인터페이스와 계약, 5. 마일스톤, 7. 미해결 질문과 요청 항목, 보고서 생성 모듈(Report Agent) — 조사 결과 및 개발 PLAN

### Community 183 - "파서의 제품 정보로 공개 권고 수집·저장·조회하기"
Cohesion: 0.40
Nodes (5): 에이전트 연결과 재현성, 제품용 실행 명령, 최신 web-parser 입력, 파서의 제품 정보로 공개 권고 수집·저장·조회하기, 판정과 실패 상태

### Community 184 - "보고서 접수·검토·등록"
Cohesion: 0.50
Nodes (4): 다른 모듈에 검토 상태 전달, 보고서 접수·검토·등록, 파일만 사용하는 검토, pending()

## Knowledge Gaps
- **3 isolated node(s):** `casper-case-db`, `ca3p-report`, `edu.wonchang:wonchang-university`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1245 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **27 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `2.2 수집기 (환경 의존 부분을 전부 여기에 모은다)` connect `CaseStore` to `ref_node_crypto`, `2. 입력과 출력`?**
  _High betweenness centrality (0.237) - this node is a cross-community bridge._
- **Are the 20 inferred relationships involving `CaseStore` (e.g. with `_archive_case()` and `_case_detail()`) actually correct?**
  _`CaseStore` has 20 INFERRED edges - model-reasoned connections that need verification._
- **What connects `casper-case-db`, `ca3p-report`, `edu.wonchang:wonchang-university` to the rest of the system?**
  _3 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `CaseStore` be split into smaller, more focused modules?**
  _Cohesion score 0.07359781121751026 - nodes in this community are weakly interconnected._
- **Why does `createRunRepository()` connect `ref_node_crypto` to `CaseStore`, `createRunService`, `ref_node_url`, `ref_node_fs`, `외부 모듈 JSON 계약`?**
  _High betweenness centrality (0.234) - this node is a cross-community bridge._
- **Should `ref_node_assert` be split into smaller, more focused modules?**
  _Cohesion score 0.06293965198074787 - nodes in this community are weakly interconnected._
- **Why does `CaseStore` connect `CaseStore` to `pathlib`, `collect`, `DeviceDatabaseTests`, `ReportIntake`, `attack_catalog.py`, `3. 모듈 구조, 언어, 확장 방식`, `sqlite3`, `json`, `pytest`?**
  _High betweenness centrality (0.160) - this node is a cross-community bridge._