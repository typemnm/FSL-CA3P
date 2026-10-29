# Graph Report - FSL-CA3P  (2026-10-29)

## Corpus Check
- 405 files · ~325,007 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 36 file(s) not represented in the graph (top: (none) 13, .njk 13, .css 4)

## Summary
- 3728 nodes · 8998 edges · 194 communities (164 shown, 30 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 516 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `01bb5d7a`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- CaseStore
- ref_node_fs
- ref_node_crypto
- casper_db/cli.py
- public_http.py
- device-deploy.mjs
- createRunService
- guardrail/src/index.js
- sllm-verdict.js
- collect.test.mjs
- pathlib
- src/server.mjs
- device-fixtures.mjs
- daehan
- adapters/integrations/casper-db.mjs
- deepseek-adapter.test.js
- hwpx.py
- general-assessment.js
- collect.mjs
- run-evidence.mjs
- steps
- smoke.mjs
- deepseek-config.js
- dashboard
- RuleReasoningEngine
- PortalController
- test_collect.py
- device-deploy-verification.mjs
- json
- dashboard
- adapters/integrations/knowledge-db.mjs
- protocol.js
- general-model-planner.js
- collector.py
- collect
- web-parser.mjs
- README.md
- check-sync.mjs
- createGeneralRuntime
- device-db.py
- application/ci-results.mjs
- general-runtime.mjs
- _run
- 3. 모듈 구조, 언어, 확장 방식
- trigger.py
- adapters/integrations/guardrail.mjs
- fingerprint.mjs
- writer.py
- ci.mjs
- deepseek-reasoning-engine.js
- deepseek-client.js
- test_run_sources.py
- test_build_loop.py
- module-management.mjs
- review.js
- StoredEvent
- adapters/integrations/xss-parser.mjs
- digest
- tools.py
- idor-probe.mjs
- CASPER 취약점 DB
- publish-ci-summary.mjs
- org.springframework.web.bind.annotation.GetMapping
- ReportIntake
- 대한대학교 · 원창대학교 웹사이트
- repeater.test.mjs
- createRunService
- experiment-targets.mjs
- idor-runtime.mjs
- re
- env
- daehan-reset-supervisor.mjs
- runner.test.mjs
- loop.py
- parser.mjs
- script-hints.mjs
- 파서 → 취약점 DB 입력 계약
- casper-db/README.md
- py/tests/conftest.py
- scripts
- report — CA3P 보고서 Agent
- ca3p_report/cli.py
- attack-module/index.js
- xss-parser/package.json
- server.js
- ui-runtime-client.test.mjs
- run_store.py
- DeepSeek 실제 API 통합 테스트 보고서
- 펜테스팅 에이전트 개발 계획
- db-management.test.mjs
- device-deploy-verification.test.mjs
- vul-web2/package.json
- sandbox.test.mjs
- pytest
- install-device-deploy.mjs
- application/local-runtime.mjs
- start-managed-daehan.mjs
- 대시보드 재구성 계획
- guardrail-sllm/package.json
- stored_xss_events
- DeviceDatabaseTests
- app.js
- agent-dashboard/package.json
- local-xss-loop.test.mjs
- lab-session-registry.mjs
- general-assessment.test.js
- serve-external.mjs
- vul-web-1/package.json
- dependency-inventory.mjs
- agent/package.json
- unavailable
- jobs
- 범용 취약점 점검 파이프라인 전환 계획과 구현 상태
- _InputCollector
- capture/package.json
- web-parser/package.json
- SiteCatalog
- web-parser — URL 기반 웹 구조·라이브러리 관찰
- 5. `deepseek-client.js`
- xss-canary.js
- 재점검 기록의 저장과 검토
- networks
- steps
- with
- web-dependencies.test.mjs
- SpringHeaderFilter.java
- ci.yml
- guardrail/package.json
- sLLM Guardrail
- 외부 모듈 JSON 계약
- general-runtime.test.mjs
- CA3P Agent Loop — 로컬 통합 대시보드
- test_boundaries.py
- attack-module/package.json
- sandbox.test.mjs
- 이 Mac에서 팀 대시보드 외부 접속
- ref_node_module
- general-model-planner.test.js
- db.mjs
- xss-execution-observer.test.mjs
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
- 0. 조사 요약 (근거)
- evaluation/index.mjs
- public/js/site.js
- deployment-check.mjs
- static/js/site.js
- 보고서 접수·검토·등록
- run-local-sllm.js
- WonchangApplication.java
- attack-module/README.md
- mock-report-template.md
- previous-month-xss-report.md
- contracts/README.md
- web-parser — 모듈 계약 (초안)
- ca3p-report
- casper-case-db
- edu.wonchang:wonchang-university
- CA3P Guardrail Evaluator
- adapters/local-lab-gateway.mjs
- CI/CD 및 대시보드 테스트 가이드
- createRunRepository
- fetch-dataset.mjs
- run-notion-vulnerability-matrix.js
- 공개 권고와 대상 소프트웨어의 영향 범위 비교
- scripts
- 인트루더 (Intruder) — 에이전트 사용 설명서
- createScriptedGateway

## God Nodes (most connected - your core abstractions)
1. `CaseStore` - 88 edges
2. `digest()` - 49 edges
3. `PortalController` - 49 edges
4. `createRunService()` - 42 edges
5. `initialize_database()` - 36 edges
6. `main()` - 35 edges
7. `ReportIntake` - 35 edges
8. `createRunRepository()` - 34 edges
9. `runOnce()` - 32 edges
10. `run_command()` - 32 edges

## Surprising Connections (you probably didn't know these)
- `현재 시작 범위` --references--> `runOnce()`  [INFERRED]
  README.md → agent/src/orchestrator.js
- `0.3 보고서 양식` --references--> `Case`  [INFERRED]
  packages/report/PLAN.md → casper-db/src/casper_db/models.py
- `에이전트 연결과 재현성` --references--> `prepareParserKnowledge()`  [INFERRED]
  casper-db/PRODUCT_ADVISORY_SYNC.ko.md → packages/adapters/integrations/casper-db.mjs
- `로컬 실측 기록` --references--> `unavailable()`  [INFERRED]
  agent-dashboard/README.md → packages/report/py/src/ca3p_report/collect/casper.py
- `다른 모듈에 검토 상태 전달` --references--> `unavailable()`  [INFERRED]
  casper-db/README.md → packages/report/py/src/ca3p_report/collect/casper.py

## Import Cycles
- None detected.

## Communities (194 total, 30 thin omitted)

### Community 0 - "CaseStore"
Cohesion: 0.06
Nodes (44): main(), main(), _list_cases(), inspect_evidence(), store_knowledge(), Case, CaseQuery, CaseRecord (+36 more)

### Community 1 - "ref_node_fs"
Cohesion: 0.06
Nodes (26): adapterSource, casperSource, CONCURRENT_COMMIT, pythonEnvironment, report, root, CASE_FIXTURES, SNAPSHOT_CODE (+18 more)

### Community 2 - "ref_node_crypto"
Cohesion: 0.06
Nodes (46): auth, ciResults, port, publicOrigins, runtime, server, serve(), { chromium } (+38 more)

### Community 3 - "casper_db/cli.py"
Cohesion: 0.05
Nodes (28): _parts(), same_reviewed_route(), validate_applicability(), validate_route_template(), assess_observation(), CandidateMatch, ObservationAssessment, ParserObservation (+20 more)

### Community 4 - "public_http.py"
Cohesion: 0.20
Nodes (8): defer_provider(), PublicCollectionError, _rate_path(), read_public_json(), RequestPolicy, reserve_slot(), _retry_delay(), _validate_rate_state()

### Community 5 - "device-deploy.mjs"
Cohesion: 0.16
Nodes (27): execute(), acquireLock(), atomicJson(), checkApplication(), database(), delay(), deploy(), deploymentTransaction() (+19 more)

### Community 6 - "createRunService"
Cohesion: 0.13
Nodes (33): ACTIVE, createExternalRuntime(), appendEvent(), close(), getState(), publish(), runTask(), recordRejections() (+25 more)

### Community 7 - "guardrail/src/index.js"
Cohesion: 0.12
Nodes (17): bodyKeys(), ConditionEvaluator, queryKeys(), GuardrailEvaluator, classify(), decodeHtmlEntities(), NAMED_ENTITIES, normalizeString() (+9 more)

### Community 8 - "sllm-verdict.js"
Cohesion: 0.08
Nodes (46): KNOWN_ERROR_CODES, makeErrorResult(), buildJudgmentPrompt(), buildVulnerabilityGuidelinesText(), JUDGMENT_CRITERIA, VULNERABILITY_GUIDELINES, buildScopeChecks(), buildSllmInput() (+38 more)

### Community 9 - "collect.test.mjs"
Cohesion: 0.08
Nodes (11): CLI, cookieSeen, EMPTY_STRUCTURE, launches, MODULE, PAGES, posted, postMessage() (+3 more)

### Community 10 - "pathlib"
Cohesion: 0.04
Nodes (55): pentest-db 통합과 폐기, 이후 공격 툴 연결 계약, _github_params(), KnowledgeSync, sync_knowledge(), collect(), create_app(), attack_info_query() (+47 more)

### Community 11 - "src/server.mjs"
Cohesion: 0.18
Nodes (14): configuredPorts, createApp(), markdown, redirectWithFlash(), requireAdmin(), requireLogin(), requirePartner(), root (+6 more)

### Community 13 - "device-fixtures.mjs"
Cohesion: 0.17
Nodes (25): spawn(), activateFixtures(), assertStoppedVolumes(), backupFixtures(), command(), compose(), copyArgs(), defaultExecute() (+17 more)

### Community 14 - "daehan"
Cohesion: 0.05
Nodes (42): context, dockerfile, build, cap_drop, environment, image, init, driver (+34 more)

### Community 15 - "adapters/integrations/casper-db.mjs"
Cohesion: 0.17
Nodes (17): 사례·권고 통합 조회, main(), absoluteDatabasePath(), DEFAULT_DB, matchCasperHistory(), observationsFromParser(), parserReferenceLocations(), prepareParserKnowledge() (+9 more)

### Community 16 - "deepseek-adapter.test.js"
Cohesion: 0.07
Nodes (9): VALID_DECISION, main(), main(), createScriptedGateway(), attackResponse(), evidenceId(), exchange(), parserResponse() (+1 more)

### Community 17 - "hwpx.py"
Cohesion: 0.05
Nodes (57): has_supplied_value(), is_unknown(), _paragraph_text(), walk(), parse_hwp_report(), parse_report(), _read_document(), _reader_xml() (+49 more)

### Community 18 - "general-assessment.js"
Cohesion: 0.22
Nodes (25): aborted(), assertPort(), assertSafeToolInput(), boundedString(), buildFindings(), eventAsset(), evidenceRefs(), fault() (+17 more)

### Community 19 - "collect.mjs"
Cohesion: 0.12
Nodes (27): abortError(), bounded(), checkOptions(), collect(), collectEach(), documentChain(), evaluate(), evaluateIn() (+19 more)

### Community 20 - "run-evidence.mjs"
Cohesion: 0.22
Nodes (7): importLegacyRuns(), absolutePath(), assertStorageRequest(), createRunEvidenceStore(), DEFAULT_REPORTS_DIR, digest(), runDirectory()

### Community 21 - "steps"
Cohesion: 0.06
Nodes (35): concurrency, cancel-in-progress, group, environment, if, runs-on, steps, timeout-minutes (+27 more)

### Community 22 - "smoke.mjs"
Cohesion: 0.15
Nodes (12): daehanDeps, daehanPackage, docker(), expectStatus(), instances, login(), pom, projectRoot (+4 more)

### Community 23 - "deepseek-config.js"
Cohesion: 0.14
Nodes (15): 9. 공개 API와 기존 계약 영향, DeepSeekClient, configError(), createDeepSeekReasoningEngineFromEnv(), DEFAULT_ENV_FILE, normalizeBaseUrl(), parseEnvText(), parseIntegerSetting() (+7 more)

### Community 24 - "dashboard"
Cohesion: 0.06
Nodes (32): VCS_REF, args, context, dockerfile, build, env_file, environment, healthcheck (+24 more)

### Community 25 - "RuleReasoningEngine"
Cohesion: 0.11
Nodes (22): 실행 범위, 10. 테스트 계획, 11. Opt-in live contract demo, 12. 단계적 rollout과 rollback, 13. 완료 기준, 1. 목적과 범위, 2. 공식 API 사실과 프로젝트 정책, 3. 목표 구조 (+14 more)

### Community 27 - "test_collect.py"
Cohesion: 0.16
Nodes (20): make_trigger(), pentest_trigger(), run_cli(), run_cli_raw(), test_bundle_is_write_once(), test_collects_a_sealed_bundle(), test_concurrent_collections_cannot_both_seal(), test_deeply_nested_json_is_a_json_error() (+12 more)

### Community 28 - "device-deploy-verification.mjs"
Cohesion: 0.13
Nodes (29): apiIdentifier(), assertLatestRun(), assertRun(), attempt(), count(), COUNTS, GitHubRateLimitError, identifier() (+21 more)

### Community 29 - "json"
Cohesion: 0.12
Nodes (23): output(), _validate_destination(), current_session(), _guide(), _hash(), _id(), main(), open_in_vscode() (+15 more)

### Community 30 - "dashboard"
Cohesion: 0.07
Nodes (28): env_file, environment, healthcheck, image, init, ports, restart, shm_size (+20 more)

### Community 31 - "adapters/integrations/knowledge-db.mjs"
Cohesion: 0.19
Nodes (12): MULTI_CATALOG, request(), absolutePath(), createKnowledgeDb(), initialize(), DEFAULT_DATABASE, exchangePython(), PROGRAM (+4 more)

### Community 32 - "protocol.js"
Cohesion: 0.13
Nodes (30): request(), assertBoundDeleteAction(), assertBoundXssAction(), assertGateway(), ensureCompleteParserResult(), findTrustedCanary(), localCanaryCandidate(), localOrigin() (+22 more)

### Community 33 - "general-model-planner.js"
Cohesion: 0.31
Nodes (19): boundedString(), EVIDENCE_KEYS, evidenceForPrompt(), exactKeys(), fitPromptContext(), identifier(), isRecord(), modelText() (+11 more)

### Community 34 - "collector.py"
Cohesion: 0.14
Nodes (14): history_refs(), reference_context(), collect(), CollectResult, _ids(), _rows(), select_finding(), CollectError (+6 more)

### Community 35 - "collect"
Cohesion: 0.22
Nodes (5): BundleExistsError, BundleWriter, _bytes(), OutputError, _write_exclusive()

### Community 36 - "web-parser.mjs"
Cohesion: 0.16
Nodes (19): build(), capped(), CAPS, collectWebInfo(), compact(), DEFAULT_TIMEOUT_MS, EVIDENCE_SUMMARY_BYTES, evidenceFromTargetInfo() (+11 more)

### Community 37 - "README.md"
Cohesion: 0.11
Nodes (16): CA3P 모듈 경계, 통합 취약점 DB, CA3P 통합 및 배포, Docker 실행 및 영속화, GitHub Actions, 신뢰된 배포 runner, 통합 규칙, CA3P (+8 more)

### Community 38 - "check-sync.mjs"
Cohesion: 0.09
Nodes (23): getPlatform(), git(), readJson(), root, generalDocumentsStatus(), tick(), storeReportPreviews(), treeDigest() (+15 more)

### Community 39 - "createGeneralRuntime"
Cohesion: 0.18
Nodes (25): createGeneralRuntime(), appendEvent(), authenticatedObservation(), boardCrossUserDeleteCanary(), request(), boardStoredXssCanary(), request(), checkedRequest() (+17 more)

### Community 40 - "device-db.py"
Cohesion: 0.26
Nodes (17): backup_command(), columns(), connect_readonly(), digest(), fsync_directory(), fsync_file(), inspect_command(), inspect_db() (+9 more)

### Community 41 - "application/ci-results.mjs"
Cohesion: 0.28
Nodes (15): count(), createCiResultsService(), sync(), DEFAULT_CACHE, fetchActionsFallback(), fetchJson(), JOB_STATUS, normalizedStatus() (+7 more)

### Community 42 - "general-runtime.mjs"
Cohesion: 0.18
Nodes (18): ACTIVE, DEMO_PASSWORDS, eventCount(), eventIdentifier(), eventIdentifiers(), eventMetadataText(), FIXTURES, htmlAttribute() (+10 more)

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

### Community 47 - "fingerprint.mjs"
Cohesion: 0.11
Nodes (20): 2. 입력 — endpoint는 Agent가 정한다, allTechnologies(), analyzePage(), DATA, detect(), fingerprint(), fingerprintWithin(), hostPath() (+12 more)

### Community 48 - "writer.py"
Cohesion: 0.07
Nodes (48): escaped(), pretty(), render(), inspect_hwp(), main(), normalize_filename(), build_blocks(), _caption() (+40 more)

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
Cohesion: 0.16
Nodes (17): as_set(), run_dir(), test_events_without_final_report(), test_pentest_db_ignores_foreign_files(), test_pentest_db_missing_store_is_a_source_error(), test_pentest_db_reads_events_and_final_report(), test_pentest_db_refuses_a_symlinked_events_directory(), test_pentest_db_refuses_a_symlinked_run_directory() (+9 more)

### Community 53 - "test_build_loop.py"
Cohesion: 0.18
Nodes (10): stored_xss_report(), _bundle(), _call(), FakeLLM, model_for(), test_captured_ref_is_embedded_in_hwpx(), complete(), fake_capture() (+2 more)

### Community 54 - "module-management.mjs"
Cohesion: 0.20
Nodes (10): createModuleManagement(), definition(), fault(), MODULES, fields, GENERAL_LOOP_BUDGET_CAPS, GENERAL_LOOP_BUDGET_DEFAULTS, invalid() (+2 more)

### Community 55 - "review.js"
Cohesion: 0.30
Nodes (20): badge(), downloadJSON(), endpointTitle(), fieldView(), findingList(), inputField(), navigate(), node() (+12 more)

### Community 56 - "StoredEvent"
Cohesion: 0.20
Nodes (13): _attack_body_keys(), _attacker_account(), capture_hints(), _event(), _input_forms(), _parser_report(), _path_of(), _session_switch() (+5 more)

### Community 57 - "adapters/integrations/xss-parser.mjs"
Cohesion: 0.38
Nodes (11): abortError(), loadChromium(), loadScan(), localOrigin(), normalizeReport(), observeStoredXssExecution(), parseLocalSite(), parserFailure() (+3 more)

### Community 58 - "digest"
Cohesion: 0.07
Nodes (42): assess_database(), lookup_assessments(), AttackTemplate, bundled_catalogs(), register_attack_template(), AutomationConfig, ExternalInput, _extract() (+34 more)

### Community 59 - "tools.py"
Cohesion: 0.19
Nodes (9): _dispatch(), _file_entry(), FinishResult, ReportTools, ToolError, _validate_origin(), test_capture_origin_must_be_loopback(), test_read_bundle_masks_plain_text_headers_without_rewriting_evidence() (+1 more)

### Community 60 - "idor-probe.mjs"
Cohesion: 0.21
Nodes (16): createGuardedGet(), createIdorRuleset(), exactTargetOrigin(), findingStatus(), login(), logout(), observation(), pathFor() (+8 more)

### Community 61 - "CASPER 취약점 DB"
Cohesion: 0.17
Nodes (12): CASPER 취약점 DB, DB 버전 전환, 기능, 설치, 외부 취약점 정보·일괄 처리, 입력과 실행 범위, 저장 구조, 지원 범위와 제약 (+4 more)

### Community 62 - "publish-ci-summary.mjs"
Cohesion: 0.21
Nodes (16): 로컬 검증, changedModuleIds(), changedModules(), commitSha(), count(), measured(), mergeIndex(), outcome() (+8 more)

### Community 64 - "ReportIntake"
Cohesion: 0.10
Nodes (25): references(), _actor(), _archive_case(), _case_audit(), _case_detail(), _case_state(), dispatch(), _intake_item() (+17 more)

### Community 65 - "대한대학교 · 원창대학교 웹사이트"
Cohesion: 0.07
Nodes (27): 1. 요약과 판정 기준, 2. 서비스 구성과 정상 기능, 3.1 대한대학교: 선정한 CVE 세 건, 3.2 원창대학교: 선정한 CVE 세 건, 3. 외부 의존성 및 CVE 평가, 4. OWASP Top 10:2025별 사전 분석, 5. 중점 시나리오: 게시글 삭제와 사이트 가용성, 6. ARTEX 사건을 참고한 부속 업무 위험 (+19 more)

### Community 66 - "repeater.test.mjs"
Cohesion: 0.08
Nodes (35): lookupAttackInfoSync(), PROGRAM, readAttackCatalogSync(), requestKnowledgeSync(), ROOT, loadAttackInfo(), buildPath(), countField() (+27 more)

### Community 67 - "createRunService"
Cohesion: 0.23
Nodes (20): prepareCaseSnapshot(), targetResetObligationsForRuns(), createRunService(), clearRunHistory(), ensureWorker(), getState(), listModels(), performExperimentReset() (+12 more)

### Community 68 - "experiment-targets.mjs"
Cohesion: 0.15
Nodes (13): fault(), ISOLATED_FIXTURES, isReadOnlyExternalObservation(), managementOrigin(), prepareTargetReset(), REQUIRED_SCOPES, UNIVERSITY_FIXTURES, env (+5 more)

### Community 69 - "idor-runtime.mjs"
Cohesion: 0.22
Nodes (14): ACTIVE, CHECKS, createIdorRuntime(), appendEvent(), close(), execute(), getState(), publish() (+6 more)

### Community 70 - "re"
Cohesion: 0.07
Nodes (28): Box, extract_local_ocr(), _hwp_raster(), _is_raster(), Line, OcrImage, OcrModel, Recognition (+20 more)

### Community 71 - "env"
Cohesion: 0.12
Nodes (17): ACTOR, CA3P_BEFORE_SHA, CA3P_COMMIT_SHA, CA3P_CONTAINER_RESULT, CA3P_GATE_RESULT, CA3P_REPORT_PYTHON, CA3P_REQUIRE_BROWSER, CA3P_TEST_RESULT (+9 more)

### Community 72 - "daehan-reset-supervisor.mjs"
Cohesion: 0.16
Nodes (21): authorized(), backupRuntimeFiles(), configFrom(), existingRuntimeFiles(), exitWithin(), port(), removeRuntimeFiles(), requestBody() (+13 more)

### Community 73 - "runner.test.mjs"
Cohesion: 0.18
Nodes (13): executeReportProcess(), failure(), generateReportDocument(), PYTHON_ROOT, readVerifiedFile(), terminate(), env, htmlPreview (+5 more)

### Community 74 - "loop.py"
Cohesion: 0.11
Nodes (11): HttpChatClient, LLMConfig, LLMError, _bundle_summary(), run_build(), build_system_prompt(), tool_schemas(), Profile (+3 more)

### Community 75 - "parser.mjs"
Cohesion: 0.24
Nodes (16): readDom(), abortError(), awaitWithSignal(), checkLocalUrl(), compactReport(), displayStaticApiUrl(), displayUrl(), navigationKey() (+8 more)

### Community 76 - "script-hints.mjs"
Cohesion: 0.35
Nodes (16): analyzeScript(), bodyKeys(), callRequest(), defaultGetWrapper(), effects(), expressionName(), name(), objectValue() (+8 more)

### Community 77 - "파서 → 취약점 DB 입력 계약"
Cohesion: 0.29
Nodes (7): 결과의 의미, 경로 파라미터, 로컬 HTML 입력 추출, 입력이 적용되지 않는 경우, 팀 파서 출력의 선택적 입력 위치, 파서 → 취약점 DB 입력 계약, header()

### Community 78 - "casper-db/README.md"
Cohesion: 0.17
Nodes (6): 결과, 동작, 리피터 (Repeater) — 에이전트 사용 설명서, 새 공격 유형 추가, 어떻게 호출하나, 언제 쓰나

### Community 79 - "py/tests/conftest.py"
Cohesion: 0.18
Nodes (6): casper_db(), linked_entry(), run_id(), stored_run(), tree_digest(), write_sources()

### Community 81 - "scripts"
Cohesion: 0.12
Nodes (16): description, engines, node, name, private, scripts, check:boundaries, ci:plan (+8 more)

### Community 82 - "report — CA3P 보고서 Agent"
Cohesion: 0.25
Nodes (5): report — CA3P 보고서 Agent, 구현 현황, 수집 단계, 테스트, 통합 대시보드

### Community 83 - "ca3p_report/cli.py"
Cohesion: 0.20
Nodes (8): _collect(), _emit(), _failure(), main(), _origin_and_switch(), _read_trigger(), RunIncomplete, RunNotFound

### Community 84 - "attack-module/index.js"
Cohesion: 0.30
Nodes (12): childEnv(), executeCurl(), executePinnedCurl(), executeUniversityRead(), failure(), findHeaderEnd(), isJsonValue(), isPlainObject() (+4 more)

### Community 85 - "xss-parser/package.json"
Cohesion: 0.14
Nodes (15): acorn, dependencies, acorn@8.15.0, playwright@1.58.2, engines, node, playwright, name (+7 more)

### Community 86 - "server.js"
Cohesion: 0.22
Nodes (15): currentUser(), ensureDataFile(), handleApi(), handler(), initialPosts(), parseUserCookie(), PORT, readJson() (+7 more)

### Community 87 - "ui-runtime-client.test.mjs"
Cohesion: 0.13
Nodes (3): envelope, session, Source

### Community 88 - "run_store.py"
Cohesion: 0.29
Nodes (7): _core_event(), _general_events(), _legacy_event(), _load(), read_run(), _stored(), _structured()

### Community 89 - "DeepSeek 실제 API 통합 테스트 보고서"
Cohesion: 0.13
Nodes (15): 10. 기준 문서, 1. 결론, 2. 테스트 범위와 경계, 3. 실행 환경, 4. 절차와 합격 기준, 5. 결과, 6. 정규화된 실행 증거, 7. 보안 및 비용 확인 (+7 more)

### Community 90 - "펜테스팅 에이전트 개발 계획"
Cohesion: 0.13
Nodes (14): 1. 담당 범위, 2. 논문에서 가져온 설계 원칙, 3. 외부 통신 계약, 4. 최초 단일 루프, 5. 오류와 안전 규칙, 6. 단계별 계획, 7. Agent 완료 기준, Phase 0 — Agent Core (+6 more)

### Community 91 - "db-management.test.mjs"
Cohesion: 0.40
Nodes (8): createDbManagement(), DbManagementError, PYTHON_SOURCE, readLimited(), readMultipart(), reportName(), ROOT, runBridge()

### Community 92 - "device-deploy-verification.test.mjs"
Cohesion: 0.22
Nodes (5): api(), candidate, headSha, json(), select()

### Community 93 - "vul-web2/package.json"
Cohesion: 0.11
Nodes (22): cookie-parser, dayjs, express, json5, lodash, markdown-it, nunjucks, dependencies (+14 more)

### Community 94 - "sandbox.test.mjs"
Cohesion: 0.30
Nodes (12): json(), main(), bodyText(), CaptureError, DEFAULT_TIMEOUT_MS, normalizeSwitch(), normalizeSwitches(), openSandbox() (+4 more)

### Community 95 - "pytest"
Cohesion: 0.25
Nodes (11): test_disk_round_trip_preserves_unicode_payload_and_lists(), test_duplicate_requires_explicit_update_and_preserves_created_at(), test_failed_reads_do_not_create_database(), test_initialization_preserves_existing_data_and_rejects_foreign_database(), test_invalid_contract_is_rejected(), test_invalid_update_does_not_change_existing_record(), test_lookup_excludes_drafts_and_matches_target_path_and_method_exactly(), test_ready_prior_report_requires_its_core_fields() (+3 more)

### Community 96 - "install-device-deploy.mjs"
Cohesion: 0.28
Nodes (13): acquireInstallationLock(), buildDashboardPlist(), buildUpdaterPlist(), CONTROLLER_FILES, exists(), installDeviceDeploy(), parsePlist(), PATH_KEYS (+5 more)

### Community 97 - "application/local-runtime.mjs"
Cohesion: 0.12
Nodes (24): ACTIVE, createLocalRuntime(), appendEvent(), close(), execute(), getState(), publish(), reset() (+16 more)

### Community 98 - "start-managed-daehan.mjs"
Cohesion: 0.17
Nodes (8): args, dashboardArgs, managementPort, retryReset, root, supervisor, token, waitForSupervisor()

### Community 99 - "대시보드 재구성 계획"
Cohesion: 0.14
Nodes (13): 1. 목표와 현재 경계, 2. 정보 구조와 이동 경로, 3.1 공격, 3.2 보고서, 3.3 DB — 취약점 자료 관리, 3. Workspace 화면, 4. Modules 화면, 5. 필요한 서버 계약 (+5 more)

### Community 100 - "guardrail-sllm/package.json"
Cohesion: 0.14
Nodes (13): description, engines, node, main, name, private, scripts, ollama:check (+5 more)

### Community 101 - "stored_xss_events"
Cohesion: 0.19
Nodes (8): envelope(), stored_xss_events(), events(), test_database_is_read_only(), test_reads_snapshot_at_compared_revision_and_checks(), test_refs_come_from_the_runs_own_assessments(), test_refs_ignore_malformed_matches(), test_run_store_reads_legacy_imported_runs()

### Community 103 - "app.js"
Cohesion: 0.34
Nodes (13): api(), createListMessage(), deletePost(), elements, formatDate(), initialize(), loadPosts(), makePostCard() (+5 more)

### Community 104 - "agent-dashboard/package.json"
Cohesion: 0.15
Nodes (12): engines, node, name, private, scripts, check, dev, start (+4 more)

### Community 105 - "local-xss-loop.test.mjs"
Cohesion: 0.25
Nodes (4): browserAvailable(), browserAvailable(), exchange(), request()

### Community 106 - "lab-session-registry.mjs"
Cohesion: 0.47
Nodes (11): alive(), exists(), failure(), inspect(), plainPath(), prepareLabSessionCleanup(), privateJson(), registerLabSession() (+3 more)

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

### Community 113 - "unavailable"
Cohesion: 0.32
Nodes (8): Report Agent — 현재 구현과 플랫폼 연동, 계층과 책임, 실행·보호 경계와 한계, 실행 흐름, 입력과 출력, 플랫폼 상태와 다운로드, 6. 테스트 전략, unavailable()

### Community 114 - "jobs"
Cohesion: 0.17
Nodes (12): runs-on, timeout-minutes, if, name, needs, runs-on, jobs, container-smoke (+4 more)

### Community 115 - "범용 취약점 점검 파이프라인 전환 계획과 구현 상태"
Cohesion: 0.18
Nodes (10): 1. 목표와 완료 기준, 2. 현행 구조에서 바꿀 경계, 4. 수집, 모델 판단, 검증 설계, 5. 대시보드와 실습 흐름, 6. 이 브랜치의 구현 단위, 7. `xss-parser` 보류 중 검증과 실측 결과, 8. 후속 확장 순서, 9. 결정 이력과 해석 (+2 more)

### Community 118 - "capture/package.json"
Cohesion: 0.18
Nodes (11): dependencies, playwright@1.58.2, engines, node, playwright, name, private, scripts (+3 more)

### Community 119 - "web-parser/package.json"
Cohesion: 0.10
Nodes (20): wapalyzer-core, bin, web-parser, dependencies, playwright@1.58.2, wapalyzer-core@6.11.0, engines, node (+12 more)

### Community 121 - "web-parser — URL 기반 웹 구조·라이브러리 관찰"
Cohesion: 0.18
Nodes (11): moduleId(), URL 기반 의존성 결과, web-parser — URL 기반 웹 구조·라이브러리 관찰, 공통 출력 키의 출처, 구조용 출력 읽기, 선택적 로컬 의존성 파일, 수집 경계, 식별 규칙의 범위 (+3 more)

### Community 122 - "5. `deepseek-client.js`"
Cohesion: 0.33
Nodes (6): 5. `deepseek-client.js`, timeout과 retry, 생성자와 주입, 오류 taxonomy, 요청, 응답 검증

### Community 123 - "xss-canary.js"
Cohesion: 0.16
Nodes (5): sameOrigin(), createStoredXssCanary(), storedXssCanaryContent(), MARKER, planInput()

### Community 124 - "재점검 기록의 저장과 검토"
Cohesion: 0.15
Nodes (13): 1. 참고한 보고서 버전을 지정한다, 2. 관찰한 결과를 초안으로 저장한다, 3. 입력 위치가 바뀌었다면 연결을 따로 확인한다, 4. 증거를 확인하고 결과를 검토 완료로 처리한다, 검증기의 여러 결과를 한 번에 저장한다, 기존 DB를 변환할 때, 재점검 기록의 저장과 검토, 검토된 경로 템플릿 (+5 more)

### Community 125 - "networks"
Cohesion: 0.14
Nodes (13): environment, networks, CA3P_DAEHAN_ORIGIN, CA3P_WONCHANG_ORIGIN, networks, university-daehan, university-wonchang, services (+5 more)

### Community 126 - "steps"
Cohesion: 0.36
Nodes (11): steps, steps, steps, steps, continue-on-error, id, if, name (+3 more)

### Community 127 - "with"
Cohesion: 0.18
Nodes (11): with, cache, cache-dependency-path, fetch-depth, if-no-files-found, name, node-version-file, path (+3 more)

### Community 128 - "web-dependencies.test.mjs"
Cohesion: 0.16
Nodes (10): 3. 목표 실행 계약, main(), parseArgs(), inventory(), createWebInventory(), digest(), LIMITS, MODULE_ID (+2 more)

### Community 130 - "ci.yml"
Cohesion: 0.22
Nodes (9): concurrency, cancel-in-progress, group, permissions, name, permissions, contents, packages (+1 more)

### Community 131 - "guardrail/package.json"
Cohesion: 0.20
Nodes (9): description, engines, node, main, name, private, scripts, test (+1 more)

### Community 132 - "sLLM Guardrail"
Cohesion: 0.18
Nodes (10): package.json script 설명, sLLM Guardrail, sLLM의 고정 출력 JSON, 네 가지 기능 파일, 사용 예시, 실행 흐름, 입력 형식, 코드 읽기 가이드 (+2 more)

### Community 133 - "외부 모듈 JSON 계약"
Cohesion: 0.11
Nodes (15): Attack Module, casper-db, 공통 envelope, 오류, 외부 모듈 JSON 계약, 전송 포트, 통합 DB의 공격 정보와 실행 기록, CA3P 펜테스팅 에이전트 코어 MVP (+7 more)

### Community 134 - "general-runtime.test.mjs"
Cohesion: 0.18
Nodes (8): fakeTargetInfo(), heavyTargetInfo(), largeTargetInfo(), runRealBoardCanary(), runRealBoardXssCanary(), runWebInfoBudget(), terminal(), universityLoginFetch()

### Community 135 - "CA3P Agent Loop — 로컬 통합 대시보드"
Cohesion: 0.22
Nodes (8): CA3P Agent Loop — 로컬 통합 대시보드, 검증, 로컬 실측 기록, 사용 방법, 실행, 연결과 기록 보관, 추가 제안, 파일 구성

### Community 136 - "test_boundaries.py"
Cohesion: 0.44
Nodes (5): _rel(), sources(), test_no_environment_variable_reads(), test_no_hardcoded_absolute_paths(), test_no_network_modules()

### Community 137 - "attack-module/package.json"
Cohesion: 0.22
Nodes (8): description, engines, node, name, private, scripts, test, version

### Community 138 - "sandbox.test.mjs"
Cohesion: 0.47
Nodes (4): sandboxOrSkip(), SWITCH, target(), withTarget()

### Community 139 - "이 Mac에서 팀 대시보드 외부 접속"
Cohesion: 0.22
Nodes (9): 검증된 develop 자동 배포, 대학 사이트 실습 반영, 상태·실패·재시도, 설치, 이 Mac에서 팀 대시보드 외부 접속, 이 장치의 서버 운영, 임시 Cloudflare 경로, 자동 배포 중지·재개 (+1 more)

### Community 140 - "ref_node_module"
Cohesion: 0.09
Nodes (18): { chromium }, report, run, { chromium }, idle, run, pentestDb, replies (+10 more)

### Community 141 - "general-model-planner.test.js"
Cohesion: 0.20
Nodes (4): 범용 점검 코어와 운영 연결, createGeneralModelPlanner(), createGeneralModelPlannerFromEnv(), GeneralModelPlanner

### Community 142 - "db.mjs"
Cohesion: 0.53
Nodes (5): daehanDatabasePath(), daysBefore(), openDatabase(), root, sha1()

### Community 144 - "모델 변경 시 실험 초기화"
Cohesion: 0.22
Nodes (8): 검증 계획, 구현 순서와 실패 처리, 대학 실습 관리 훅, 로컬 대한대 실습 실행, 모델 변경 시 실험 초기화, 사용 흐름, 연구 해석과 범위의 한계, 영향 범위 조사와 처리

### Community 145 - "updates"
Cohesion: 0.25
Nodes (7): interval, updates, directory, package-ecosystem, schedule, target-branch, version

### Community 146 - "deploy-staging"
Cohesion: 0.25
Nodes (8): if, needs, secrets, uses, with, deploy-staging, environment, image

### Community 148 - "맥 미니에서 설치하고 직접 검증하기"
Cohesion: 0.13
Nodes (15): Docker를 사용하는 경우, 맥 미니에서 설치하고 직접 검증하기, 설치 환경, 실제 보고서 접수·검토·등록, 실제 파서 결과 → GitHub/NVD → 같은 DB 저장·조회, 실행 환경 확인, 에이전트와 서비스 실행, 통합 DB를 사용하는 공격 툴 확인 (+7 more)

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
Cohesion: 0.20
Nodes (10): 1.1 보고서가 답해야 할 것, 1.2 전체 흐름, 1.3 하는 일, 1.4.1 운영 전제 — 보고서는 사람이 최종 검토한다, 1.4 하지 않는 일, 1.5 프레이밍 지침 (프롬프트로 LLM에 유도, 코드 강제 아님), 1. 목표와 범위, 5. 마일스톤 (+2 more)

### Community 158 - "run-store/package.json"
Cohesion: 0.29
Nodes (6): engines, node, name, private, type, version

### Community 159 - "CA3P 취약한 바닐라 JS 게시판"
Cohesion: 0.29
Nodes (6): 1. 저장형 XSS, 2. 파라미터 변조로 관리자 글 삭제, CA3P 취약한 바닐라 JS 게시판, 계정과 게시판, 실행, 취약점 재현

### Community 160 - "0. 조사 요약 (근거)"
Cohesion: 0.29
Nodes (7): report(), xss-parser, 검증 범위, 0.1 실행 보고서와 이벤트 — pentest-db 디스크 저장 규약, 0.3 보고서 양식, 0.5 실습 게시판 수명과 촬영 관련 사실 (develop, 10-19 확인), 0. 조사 요약 (근거)

### Community 161 - "evaluation/index.mjs"
Cohesion: 0.26
Nodes (10): affectedModules(), changes(), compareRunRecords(), collectMarkers(), CONTRACT_DEPENDENCIES, evaluateCases(), metrics(), NORMALIZATION_VERSION (+2 more)

### Community 162 - "public/js/site.js"
Cohesion: 0.60
Nodes (4): clearResults(), performSearch(), renderResults(), resultUrl()

### Community 163 - "deployment-check.mjs"
Cohesion: 0.47
Nodes (4): expect(), login(), request(), sites

### Community 164 - "static/js/site.js"
Cohesion: 0.60
Nodes (4): clearResults(), performSearch(), renderResults(), resultUrl()

### Community 165 - "보고서 접수·검토·등록"
Cohesion: 0.67
Nodes (3): 다른 모듈에 검토 상태 전달, 보고서 접수·검토·등록, 파일만 사용하는 검토

### Community 166 - "run-local-sllm.js"
Cohesion: 0.60
Nodes (4): buildSafeFixture(), DEFAULT_MODULE_DIRECTORY, loadVerdictModule(), main()

### Community 177 - "web-parser — 모듈 계약 (초안)"
Cohesion: 0.10
Nodes (19): 6. `deepseek-reasoning-engine.js`, hybrid safety boundary, 모델 출력 schema, 1차 DB 검증 기록, 2026-10-01 추가 검증, 2026-10-06 v5 변경 검증, 2026-10-06 공유 전 재검증, body() (+11 more)

### Community 183 - "CA3P Guardrail Evaluator"
Cohesion: 0.40
Nodes (4): Agent Loop 연결, CA3P Guardrail Evaluator, 구성, 실행

### Community 184 - "adapters/local-lab-gateway.mjs"
Cohesion: 0.23
Nodes (15): run(), assertAttackRequest(), assertXssAttackRequest(), awaitBoardOrigin(), BOARD_SERVER, closedProcess(), createXssGateway(), handle() (+7 more)

### Community 185 - "CI/CD 및 대시보드 테스트 가이드"
Cohesion: 0.40
Nodes (5): 1. 변경 전 로컬 검증, 2. PR 및 배포 확인, 3. 대시보드 기능 테스트, 4. 이 장치에서 외부 접속 테스트, CI/CD 및 대시보드 테스트 가이드

### Community 186 - "createRunRepository"
Cohesion: 0.06
Nodes (56): safeLog(), fault(), info(), inspect(), visit(), legacyRoot, prepareRunFileCleanup(), IDOR_FIXTURES (+48 more)

### Community 190 - "run-notion-vulnerability-matrix.js"
Cohesion: 0.28
Nodes (6): cases, DEFAULT_MODULE_DIRECTORY, main(), runCase(), timeoutMs, worker()

### Community 191 - "공개 권고와 대상 소프트웨어의 영향 범위 비교"
Cohesion: 0.50
Nodes (4): 공개 권고와 대상 소프트웨어의 영향 범위 비교, 비교 기준, 입력과 결과, 저장과 갱신

### Community 193 - "scripts"
Cohesion: 0.25
Nodes (8): scripts, probe:idor, smoke, start, start:daehan, start:wonchang, test:idor, test:reset

### Community 196 - "인트루더 (Intruder) — 에이전트 사용 설명서"
Cohesion: 0.33
Nodes (6): 결과, 동작, 새 공격 유형 추가, 어떻게 호출하나, 언제 쓰나, 인트루더 (Intruder) — 에이전트 사용 설명서

### Community 197 - "createScriptedGateway"
Cohesion: 0.87
Nodes (6): createScriptedGateway(), attackResponse(), evidenceId(), exchange(), parserResponse(), respond()

## Knowledge Gaps
- **3 isolated node(s):** `casper-case-db`, `ca3p-report`, `edu.wonchang:wonchang-university`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1337 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **30 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `createRunRepository()` connect `createRunRepository` to `CaseStore`, `ref_node_fs`, `ref_node_crypto`, `createRunService`, `module-management.mjs`?**
  _High betweenness centrality (0.219) - this node is a cross-community bridge._
- **Are the 21 inferred relationships involving `CaseStore` (e.g. with `_archive_case()` and `_case_detail()`) actually correct?**
  _`CaseStore` has 21 INFERRED edges - model-reasoned connections that need verification._
- **What connects `casper-case-db`, `ca3p-report`, `edu.wonchang:wonchang-university` to the rest of the system?**
  _3 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `CaseStore` be split into smaller, more focused modules?**
  _Cohesion score 0.06421821305841924 - nodes in this community are weakly interconnected._
- **Why does `2.2 수집기 (환경 의존 부분을 전부 여기에 모은다)` connect `CaseStore` to `createRunRepository`, `2. 입력과 출력`?**
  _High betweenness centrality (0.218) - this node is a cross-community bridge._
- **Should `ref_node_fs` be split into smaller, more focused modules?**
  _Cohesion score 0.06414565826330532 - nodes in this community are weakly interconnected._
- **Why does `CaseStore` connect `CaseStore` to `ReportIntake`, `casper_db/cli.py`, `DeviceDatabaseTests`, `pathlib`, `3. 모듈 구조, 언어, 확장 방식`, `digest`, `json`, `pytest`?**
  _High betweenness centrality (0.159) - this node is a cross-community bridge._