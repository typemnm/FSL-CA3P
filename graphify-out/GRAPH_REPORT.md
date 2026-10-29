# Graph Report - FSL-CA3P  (2026-10-29)

## Corpus Check
- 431 files · ~351,005 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 37 file(s) not represented in the graph (top: (none) 14, .njk 13, .css 4)

## Summary
- 3915 nodes · 9453 edges · 198 communities (171 shown, 27 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 519 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `8722fd0e`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- CaseStore
- api/server.mjs
- check-sync.mjs
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
- casper_db/cli.py
- general-assessment.js
- collect.mjs
- ref_node_fs
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
- hwpx.py
- README.md
- check-sync.mjs
- redact
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
- guardrail/src/index.js
- ref_node_crypto
- experiment-targets.mjs
- external-runtime.mjs
- local_ocr.py
- env
- daehan-reset-supervisor.mjs
- runner.test.mjs
- loop.py
- parser.mjs
- script-hints.mjs
- 파서 → 취약점 DB 입력 계약
- casper-db/README.md
- idor-runtime.mjs
- scripts
- report — CA3P 보고서 Agent
- ca3p_report/cli.py
- chat-files.mjs
- xss-parser/package.json
- external-target.mjs
- ui-runtime-client.test.mjs
- run_store.py
- run-once.test.js
- 펜테스팅 에이전트 개발 계획
- db-management.test.mjs
- device-deploy-verification.test.mjs
- vul-web2/package.json
- sandbox.test.mjs
- repository.py
- install-device-deploy.mjs
- application/local-runtime.mjs
- experiment-targets.mjs
- 대시보드 재구성 계획
- guardrail-sllm/package.json
- stored_xss_events
- DeviceDatabaseTests
- app.js
- agent-dashboard/package.json
- local-xss-loop.test.mjs
- ref_node_path
- general-assessment.test.js
- serve-external.mjs
- vul-web-1/package.json
- dependency-inventory.mjs
- general-results.test.mjs
- agent/package.json
- test_history_review.py
- jobs
- intruder.mjs
- general-pipeline.test.js
- attack-module/index.js
- capture/package.json
- web-parser/package.json
- SiteCatalog
- web-parser — URL 기반 웹 구조·라이브러리 관찰
- registry.mjs
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
- ref_node_os
- CA3P Agent Loop — 로컬 통합 대시보드
- test_boundaries.py
- attack-module/package.json
- assess_observation
- 이 Mac에서 팀 대시보드 외부 접속
- 대한대학교·원창대학교 웹사이트 사전 침해분석 및 취약점 보고서
- ref_node_assert
- general-assessment.test.js
- xss-execution-observer.test.mjs
- 모델 변경 시 실험 초기화
- updates
- deploy-staging
- demo.py
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
- 보고서 기반 DB 처리와 모듈 연결
- run-local-sllm.js
- WonchangApplication.java
- 보고서 생성 모듈(Report Agent) — 조사 결과 및 개발 PLAN
- attack-module/README.md
- mock-report-template.md
- previous-month-xss-report.md
- contracts/README.md
- web-parser — 모듈 계약 (초안)
- ca3p-report
- casper-case-db
- edu.wonchang:wonchang-university
- attack-tool/package.json
- adapters/local-lab-gateway.mjs
- CI/CD 및 대시보드 테스트 가이드
- createRunRepository
- ui-platform.test.mjs
- 리피터 (Repeater) — 에이전트 사용 설명서
- general_model.py
- run-notion-vulnerability-matrix.js
- PR 규칙
- daehan-reset-supervisor.test.mjs
- scripts
- structure-output.test.mjs
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
9. `run_command()` - 32 edges
10. `runOnce()` - 31 edges

## Surprising Connections (you probably didn't know these)
- `현재 시작 범위` --references--> `runOnce()`  [INFERRED]
  README.md → agent/src/orchestrator.js
- `0.3 보고서 양식` --references--> `Case`  [INFERRED]
  packages/report/PLAN.md → casper-db/src/casper_db/models.py
- `사례·권고 통합 조회` --references--> `matchCasperHistory()`  [INFERRED]
  casper-db/README.md → packages/adapters/integrations/casper-db.mjs
- `에이전트 연결과 재현성` --references--> `prepareParserKnowledge()`  [INFERRED]
  casper-db/PRODUCT_ADVISORY_SYNC.ko.md → packages/adapters/integrations/casper-db.mjs
- `11. 백로그` --references--> `paths()`  [INFERRED]
  web-parser/CONTRACT.md → scripts/device-db.py

## Import Cycles
- None detected.

## Communities (198 total, 27 thin omitted)

### Community 0 - "CaseStore"
Cohesion: 0.18
Nodes (11): main(), _list_cases(), Case, CaseRecord, CheckRecord, CaseStore, _save_version(), test_demo_persists_db_and_escapes_payload() (+3 more)

### Community 1 - "api/server.mjs"
Cohesion: 0.07
Nodes (45): auth, ciResults, port, publicOrigins, runtime, server, configuredProxyIps(), createAuthentication() (+37 more)

### Community 2 - "check-sync.mjs"
Cohesion: 0.27
Nodes (8): canonical(), program, pythonJson(), resultProgram, reviewRunCheck(), root, syncRunChecks(), root

### Community 3 - "casper_db/cli.py"
Cohesion: 0.07
Nodes (15): _parts(), same_reviewed_route(), validate_applicability(), validate_route_template(), inspect_evidence(), CaseQuery, Check, EvidenceMetadata (+7 more)

### Community 4 - "public_http.py"
Cohesion: 0.10
Nodes (13): NoRedirect, _timestamp(), current_policy(), defer_provider(), PublicCollectionError, _rate_path(), read_public_json(), RequestPolicy (+5 more)

### Community 5 - "device-deploy.mjs"
Cohesion: 0.07
Nodes (59): acquireLock(), atomicJson(), checkApplication(), database(), delay(), deploy(), deploymentTransaction(), execute() (+51 more)

### Community 6 - "createRunService"
Cohesion: 0.23
Nodes (18): targetResetObligationsForRuns(), createRunService(), clearRunHistory(), ensureWorker(), getState(), listModels(), performExperimentReset(), performRunHistoryClear() (+10 more)

### Community 7 - "guardrail/src/index.js"
Cohesion: 0.09
Nodes (22): _all(), _any(), assess_database(), assess_record(), _cpe_parts(), discover_advisories(), _ecosystem(), _github() (+14 more)

### Community 8 - "sllm-verdict.js"
Cohesion: 0.08
Nodes (46): KNOWN_ERROR_CODES, makeErrorResult(), buildJudgmentPrompt(), buildVulnerabilityGuidelinesText(), JUDGMENT_CRITERIA, VULNERABILITY_GUIDELINES, buildScopeChecks(), buildSllmInput() (+38 more)

### Community 9 - "collect.test.mjs"
Cohesion: 0.08
Nodes (11): CLI, cookieSeen, EMPTY_STRUCTURE, launches, MODULE, PAGES, posted, postMessage() (+3 more)

### Community 10 - "pathlib"
Cohesion: 0.07
Nodes (45): KnowledgeSync, sync_knowledge(), collect(), create_app(), attack_info_query(), attack_patterns(), attack_template(), knowledge_query() (+37 more)

### Community 11 - "src/server.mjs"
Cohesion: 0.15
Nodes (19): daehanDatabasePath(), daysBefore(), openDatabase(), root, sha1(), configuredPorts, createApp(), markdown (+11 more)

### Community 13 - "device-fixtures.mjs"
Cohesion: 0.37
Nodes (16): build_blocks(), _cover(), _cvss(), _dicts(), _failure(), _finding(), _history(), _kv_rows() (+8 more)

### Community 14 - "daehan"
Cohesion: 0.05
Nodes (42): context, dockerfile, build, cap_drop, environment, image, init, driver (+34 more)

### Community 15 - "adapters/integrations/casper-db.mjs"
Cohesion: 0.13
Nodes (19): adapterSource, casperSource, CONCURRENT_COMMIT, pythonEnvironment, report, main(), absoluteDatabasePath(), DEFAULT_DB (+11 more)

### Community 17 - "casper_db/cli.py"
Cohesion: 0.10
Nodes (10): output(), ParserObservation, _InputCollector, _origin(), parse_html_inputs(), ParseResult, register_commands(), test_parser_ignores_external_forms_disabled_inputs_and_duplicates() (+2 more)

### Community 18 - "general-assessment.js"
Cohesion: 0.05
Nodes (59): 10. 기준 문서, 1. 결론, 2. 테스트 범위와 경계, 3. 실행 환경, 4. 절차와 합격 기준, 5. 결과, 6. 정규화된 실행 증거, 7. 보안 및 비용 확인 (+51 more)

### Community 19 - "collect.mjs"
Cohesion: 0.11
Nodes (28): abortError(), bounded(), checkOptions(), collect(), collectEach(), documentChain(), evaluate(), evaluateIn() (+20 more)

### Community 20 - "ref_node_fs"
Cohesion: 0.06
Nodes (25): importLegacyRuns(), absolutePath(), assertStorageRequest(), createRunEvidenceStore(), DEFAULT_REPORTS_DIR, digest(), runDirectory(), pentestDb (+17 more)

### Community 21 - "steps"
Cohesion: 0.06
Nodes (35): concurrency, cancel-in-progress, group, environment, if, runs-on, steps, timeout-minutes (+27 more)

### Community 22 - "smoke.mjs"
Cohesion: 0.15
Nodes (12): daehanDeps, daehanPackage, docker(), expectStatus(), instances, login(), pom, projectRoot (+4 more)

### Community 23 - "deepseek-config.js"
Cohesion: 0.15
Nodes (17): 9. 공개 API와 기존 계약 영향, 범용 점검 코어와 운영 연결, DeepSeekClient, configError(), createDeepSeekReasoningEngineFromEnv(), DEFAULT_ENV_FILE, normalizeBaseUrl(), parseEnvText() (+9 more)

### Community 24 - "dashboard"
Cohesion: 0.06
Nodes (32): VCS_REF, args, context, dockerfile, build, env_file, environment, healthcheck (+24 more)

### Community 25 - "RuleReasoningEngine"
Cohesion: 0.08
Nodes (28): 실행 범위, 10. 테스트 계획, 11. Opt-in live contract demo, 12. 단계적 rollout과 rollback, 13. 완료 기준, 1. 목적과 범위, 2. 공식 API 사실과 프로젝트 정책, 3. 목표 구조 (+20 more)

### Community 27 - "test_collect.py"
Cohesion: 0.16
Nodes (20): make_trigger(), pentest_trigger(), run_cli(), run_cli_raw(), test_bundle_is_write_once(), test_collects_a_sealed_bundle(), test_concurrent_collections_cannot_both_seal(), test_deeply_nested_json_is_a_json_error() (+12 more)

### Community 28 - "device-deploy-verification.mjs"
Cohesion: 0.14
Nodes (28): apiIdentifier(), assertLatestRun(), assertRun(), attempt(), count(), COUNTS, identifier(), INDEX_KEYS (+20 more)

### Community 29 - "json"
Cohesion: 0.06
Nodes (34): _paragraph_text(), walk(), parse_hwp_report(), parse_report(), _read_document(), _reader_xml(), current_session(), _guide() (+26 more)

### Community 30 - "dashboard"
Cohesion: 0.07
Nodes (28): env_file, environment, healthcheck, image, init, ports, restart, shm_size (+20 more)

### Community 31 - "adapters/integrations/knowledge-db.mjs"
Cohesion: 0.16
Nodes (13): request(), MULTI_CATALOG, request(), absolutePath(), createKnowledgeDb(), initialize(), DEFAULT_DATABASE, exchangePython() (+5 more)

### Community 32 - "protocol.js"
Cohesion: 0.14
Nodes (29): assertBoundDeleteAction(), assertBoundXssAction(), assertGateway(), ensureCompleteParserResult(), findTrustedCanary(), localCanaryCandidate(), localOrigin(), localXssCandidate() (+21 more)

### Community 33 - "general-model-planner.js"
Cohesion: 0.19
Nodes (19): boundedString(), createGeneralModelPlanner(), EVIDENCE_KEYS, evidenceForPrompt(), exactKeys(), GeneralModelPlanner, identifier(), isRecord() (+11 more)

### Community 34 - "collector.py"
Cohesion: 0.17
Nodes (11): CollectResult, _ids(), _rows(), select_finding(), CollectError, RunRecord, _digest(), _event() (+3 more)

### Community 35 - "collect"
Cohesion: 0.17
Nodes (9): BundleWriter, _bytes(), OutputError, _write_exclusive(), history_refs(), read_history(), reference_context(), unavailable() (+1 more)

### Community 36 - "hwpx.py"
Cohesion: 0.07
Nodes (46): has_supplied_value(), is_unknown(), build_report_draft(), _fields(), _finding(), issue(), _has_value(), _label() (+38 more)

### Community 37 - "README.md"
Cohesion: 0.08
Nodes (19): Attack tool protocol v1, AI 연결, attack-tool, 대시보드 연결, 독립 실행, CA3P 모듈 경계, 공격 도구 통신, 통합 취약점 DB (+11 more)

### Community 38 - "check-sync.mjs"
Cohesion: 0.11
Nodes (31): CASE_FIXTURES, prepareCaseSnapshot(), SNAPSHOT_CODE, assertRegularDatabase(), fault(), historyOperation(), prepareExperimentCleanup(), prepareHistoryReset() (+23 more)

### Community 39 - "redact"
Cohesion: 0.06
Nodes (71): fixture(), createWorkspaceChatService(), availableModel(), compactInternal(), contextFor(), getSession(), listModels(), managed() (+63 more)

### Community 40 - "device-db.py"
Cohesion: 0.26
Nodes (17): backup_command(), columns(), connect_readonly(), digest(), fsync_directory(), fsync_file(), inspect_command(), inspect_db() (+9 more)

### Community 41 - "application/ci-results.mjs"
Cohesion: 0.21
Nodes (17): count(), createCiResultsService(), sync(), DEFAULT_CACHE, fetchActionsFallback(), fetchJson(), JOB_STATUS, normalizedStatus() (+9 more)

### Community 42 - "general-runtime.mjs"
Cohesion: 0.05
Nodes (63): ACTIVE, createGeneralRuntime(), appendEvent(), authenticatedObservation(), boardCrossUserDeleteCanary(), request(), checkedRequest(), close() (+55 more)

### Community 43 - "_run"
Cohesion: 0.38
Nodes (12): _event(), _report(), _result(), _store(), test_confirmed_probe_requires_adopted_current_evidence(), test_failed_run_preserves_confirmed_detail_with_incomplete_notice(), test_finish_report_rejects_source_identity_or_status_changes(), test_historical_reference_in_verdict_is_not_labeled_current_probe_evidence() (+4 more)

### Community 44 - "3. 모듈 구조, 언어, 확장 방식"
Cohesion: 0.25
Nodes (8): 3.1 구조, 3.2 프로필 선택 (사이트 어댑터는 두지 않음), 3.3 프로필 인터페이스 (Python, build 측), 3.5 python-hwpx 사용 방침, 3.6 디렉터리 구성(안), 3.7 새 취약점·새 사이트·새 원천을 추가하는 절차, 3.8 "Agent"의 범위, 3. 모듈 구조, 언어, 확장 방식

### Community 45 - "trigger.py"
Cohesion: 0.19
Nodes (14): _absolute(), parse_trigger(), _record(), _refuse_output_inside_sources(), _resolved(), _source(), SourceRef, Trigger (+6 more)

### Community 46 - "adapters/integrations/guardrail.mjs"
Cohesion: 0.11
Nodes (19): newGuardrail(), Agent Loop 연결, CA3P Guardrail Evaluator, 구성, 사용, 실행, createGuardrailForRun(), createLocalGuardrail() (+11 more)

### Community 47 - "fingerprint.mjs"
Cohesion: 0.09
Nodes (24): capturePlaywright, captureRequire, { chromium }, parserRequire, root, allTechnologies(), analyzePage(), DATA (+16 more)

### Community 48 - "writer.py"
Cohesion: 0.19
Nodes (15): _caption(), _load_png(), write_html(), write_hwpx(), write_markdown(), model(), section_xml(), test_body_has_no_hashes() (+7 more)

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
Cohesion: 0.18
Nodes (16): as_set(), run_dir(), test_events_without_final_report(), test_pentest_db_ignores_foreign_files(), test_pentest_db_missing_store_is_a_source_error(), test_pentest_db_reads_events_and_final_report(), test_pentest_db_refuses_a_symlinked_events_directory(), test_pentest_db_refuses_a_symlinked_run_directory() (+8 more)

### Community 53 - "test_build_loop.py"
Cohesion: 0.17
Nodes (11): stored_xss_report(), _bundle(), _call(), FakeLLM, model_for(), test_capture_origin_must_be_loopback(), test_captured_ref_is_embedded_in_hwpx(), complete() (+3 more)

### Community 54 - "module-management.mjs"
Cohesion: 0.20
Nodes (10): definition(), fault(), MODULES, safeLog(), fields, GENERAL_LOOP_BUDGET_CAPS, GENERAL_LOOP_BUDGET_DEFAULTS, invalid() (+2 more)

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
Cohesion: 0.10
Nodes (18): AutomationConfig, ExternalInput, _extract(), load_external(), read_json(), ReportInput, run_automation(), _write() (+10 more)

### Community 59 - "tools.py"
Cohesion: 0.19
Nodes (8): _dispatch(), _file_entry(), FinishResult, ReportTools, ToolError, _validate_origin(), test_read_bundle_masks_plain_text_headers_without_rewriting_evidence(), test_read_bundle_masks_structured_credentials_without_rewriting_evidence()

### Community 60 - "idor-probe.mjs"
Cohesion: 0.21
Nodes (16): createGuardedGet(), createIdorRuleset(), exactTargetOrigin(), findingStatus(), login(), logout(), observation(), pathFor() (+8 more)

### Community 61 - "CASPER 취약점 DB"
Cohesion: 0.11
Nodes (19): CASPER 취약점 DB, DB 버전 전환, pentest-db 통합과 폐기, 기능, 다른 모듈에 검토 상태 전달, 보고서 접수·검토·등록, 사례·권고 통합 조회, 설치 (+11 more)

### Community 62 - "publish-ci-summary.mjs"
Cohesion: 0.22
Nodes (15): changedModuleIds(), changedModules(), commitSha(), count(), measured(), mergeIndex(), outcome(), outcomes (+7 more)

### Community 64 - "ReportIntake"
Cohesion: 0.11
Nodes (21): _actor(), _archive_case(), _case_audit(), _case_detail(), _case_state(), dispatch(), _intake_item(), _list_audit() (+13 more)

### Community 65 - "대한대학교 · 원창대학교 웹사이트"
Cohesion: 0.11
Nodes (15): 대한대학교 최종 프롬프트, 메인 캠퍼스 이미지 제작 기록, 원창대학교 최종 프롬프트, 1. 장애 원인과 조치, 2. 재검증 결과, 3. 검증 범위, Docker 장애 원인 및 두 대학 사이트 기능 재검증, ARTEX 사건을 참고한 평가 시나리오 (+7 more)

### Community 66 - "guardrail/src/index.js"
Cohesion: 0.12
Nodes (21): createAttackToolGuardrail(), denied(), exactOrigin(), exactPath(), keys(), record(), bodyKeys(), ConditionEvaluator (+13 more)

### Community 67 - "ref_node_crypto"
Cohesion: 0.19
Nodes (18): createAttackToolClient(), createAttackTool(), dispatch(), registerPrincipal(), fault(), readJson(), record(), tools (+10 more)

### Community 68 - "experiment-targets.mjs"
Cohesion: 0.30
Nodes (9): normalize_filename(), test_control_chars_are_removed_and_text_is_nfc(), test_empty_or_invalid_falls_back_to_run_id(), test_extension_is_forced_to_a_single_hwpx(), test_overlong_name_is_capped_at_120(), test_reserved_prefix_inside_longer_name_is_allowed(), test_traversal_keeps_the_readable_part(), test_traversal_never_leaves_a_separator_or_dotdot() (+1 more)

### Community 69 - "external-runtime.mjs"
Cohesion: 0.17
Nodes (25): ACTIVE, createExternalRuntime(), appendEvent(), close(), getState(), publish(), runModelTask(), inventory() (+17 more)

### Community 70 - "local_ocr.py"
Cohesion: 0.11
Nodes (20): Box, extract_local_ocr(), _hwp_raster(), _is_raster(), Line, ocr_cache_identity(), OcrImage, OcrModel (+12 more)

### Community 71 - "env"
Cohesion: 0.12
Nodes (17): ACTOR, CA3P_BEFORE_SHA, CA3P_COMMIT_SHA, CA3P_CONTAINER_RESULT, CA3P_GATE_RESULT, CA3P_REPORT_PYTHON, CA3P_REQUIRE_BROWSER, CA3P_TEST_RESULT (+9 more)

### Community 72 - "daehan-reset-supervisor.mjs"
Cohesion: 0.16
Nodes (21): authorized(), backupRuntimeFiles(), configFrom(), existingRuntimeFiles(), exitWithin(), port(), removeRuntimeFiles(), requestBody() (+13 more)

### Community 73 - "runner.test.mjs"
Cohesion: 0.15
Nodes (13): executeReportProcess(), failure(), generateReportDocument(), PYTHON_ROOT, readVerifiedFile(), terminate(), env, htmlPreview (+5 more)

### Community 74 - "loop.py"
Cohesion: 0.21
Nodes (6): _bundle_summary(), run_build(), build_system_prompt(), tool_schemas(), Profile, resolve_profile()

### Community 75 - "parser.mjs"
Cohesion: 0.17
Nodes (15): readDom(), abortError(), awaitWithSignal(), checkLocalUrl(), compactReport(), displayStaticApiUrl(), displayUrl(), navigationKey() (+7 more)

### Community 76 - "script-hints.mjs"
Cohesion: 0.35
Nodes (16): analyzeScript(), bodyKeys(), callRequest(), defaultGetWrapper(), effects(), expressionName(), name(), objectValue() (+8 more)

### Community 77 - "파서 → 취약점 DB 입력 계약"
Cohesion: 0.29
Nodes (7): 결과의 의미, 경로 파라미터, 로컬 HTML 입력 추출, 입력이 적용되지 않는 경우, 팀 파서 출력의 선택적 입력 위치, 파서 → 취약점 DB 입력 계약, header()

### Community 78 - "casper-db/README.md"
Cohesion: 0.21
Nodes (6): 결과, 동작, 새 공격 유형 추가, 어떻게 호출하나, 언제 쓰나, 인트루더 (Intruder) — 에이전트 사용 설명서

### Community 79 - "idor-runtime.mjs"
Cohesion: 0.16
Nodes (21): fault(), info(), inspect(), visit(), legacyRoot, prepareRunFileCleanup(), ACTIVE, CHECKS (+13 more)

### Community 81 - "scripts"
Cohesion: 0.12
Nodes (16): description, engines, node, name, private, scripts, check:boundaries, ci:plan (+8 more)

### Community 82 - "report — CA3P 보고서 Agent"
Cohesion: 0.14
Nodes (11): Report Agent — 현재 구현과 플랫폼 연동, 계층과 책임, 실행·보호 경계와 한계, 실행 흐름, 입력과 출력, 플랫폼 상태와 다운로드, report — CA3P 보고서 Agent, 구현 현황 (+3 more)

### Community 83 - "ca3p_report/cli.py"
Cohesion: 0.10
Nodes (15): _collect(), _emit(), _failure(), main(), _origin_and_switch(), _read_trigger(), _run(), BundleExistsError (+7 more)

### Community 84 - "chat-files.mjs"
Cohesion: 0.14
Nodes (17): createWorkspaceChatRoutes(), allowedExtensions, allowedNames, blockedDirectories, CHAT_FILE_LIMITS, components(), createChatFiles(), confirm() (+9 more)

### Community 85 - "xss-parser/package.json"
Cohesion: 0.14
Nodes (15): acorn, dependencies, acorn@8.15.0, playwright@1.58.2, engines, node, playwright, name (+7 more)

### Community 86 - "external-target.mjs"
Cohesion: 0.18
Nodes (16): abortable(), blockedV4, blockedV6, fault(), globalV6, hasCredentialQuery(), hostWithoutBrackets(), isPublicAddress() (+8 more)

### Community 87 - "ui-runtime-client.test.mjs"
Cohesion: 0.13
Nodes (3): envelope, session, Source

### Community 88 - "run_store.py"
Cohesion: 0.29
Nodes (7): _core_event(), _general_events(), _legacy_event(), _load(), read_run(), _stored(), _structured()

### Community 89 - "run-once.test.js"
Cohesion: 0.16
Nodes (8): main(), main(), createScriptedGateway(), attackResponse(), evidenceId(), exchange(), parserResponse(), respond()

### Community 90 - "펜테스팅 에이전트 개발 계획"
Cohesion: 0.13
Nodes (14): 1. 담당 범위, 2. 논문에서 가져온 설계 원칙, 3. 외부 통신 계약, 4. 최초 단일 루프, 5. 오류와 안전 규칙, 6. 단계별 계획, 7. Agent 완료 기준, Phase 0 — Agent Core (+6 more)

### Community 91 - "db-management.test.mjs"
Cohesion: 0.40
Nodes (8): createDbManagement(), DbManagementError, PYTHON_SOURCE, readLimited(), readMultipart(), reportName(), ROOT, runBridge()

### Community 92 - "device-deploy-verification.test.mjs"
Cohesion: 0.20
Nodes (5): GitHubRateLimitError, api(), candidate, headSha, json()

### Community 93 - "vul-web2/package.json"
Cohesion: 0.11
Nodes (22): cookie-parser, dayjs, express, json5, lodash, markdown-it, nunjucks, dependencies (+14 more)

### Community 94 - "sandbox.test.mjs"
Cohesion: 0.11
Nodes (31): json(), main(), bodyText(), CaptureError, DEFAULT_TIMEOUT_MS, normalizeSwitch(), normalizeSwitches(), openSandbox() (+23 more)

### Community 95 - "repository.py"
Cohesion: 0.12
Nodes (26): initialize_database(), _migrate_legacy(), _migrate_v5(), _migrate_v6_checks(), _run_schema(), _sql(), store(), test_disk_round_trip_preserves_unicode_payload_and_lists() (+18 more)

### Community 96 - "install-device-deploy.mjs"
Cohesion: 0.28
Nodes (13): acquireInstallationLock(), buildDashboardPlist(), buildUpdaterPlist(), CONTROLLER_FILES, exists(), installDeviceDeploy(), parsePlist(), PATH_KEYS (+5 more)

### Community 97 - "application/local-runtime.mjs"
Cohesion: 0.15
Nodes (25): ACTIVE, createLocalRuntime(), appendEvent(), close(), execute(), getState(), publish(), reset() (+17 more)

### Community 98 - "experiment-targets.mjs"
Cohesion: 0.15
Nodes (13): fault(), ISOLATED_FIXTURES, isReadOnlyExternalObservation(), managementOrigin(), prepareTargetReset(), REQUIRED_SCOPES, UNIVERSITY_FIXTURES, env (+5 more)

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
Cohesion: 0.22
Nodes (4): browserAvailable(), browserAvailable(), exchange(), request()

### Community 106 - "ref_node_path"
Cohesion: 0.13
Nodes (21): lookupAttackInfoSync(), PROGRAM, readAttackCatalogSync(), requestKnowledgeSync(), ROOT, loadAttackInfo(), createGuardedRequest(), createRuleset() (+13 more)

### Community 107 - "general-assessment.test.js"
Cohesion: 0.27
Nodes (4): inspect_hwp(), main(), image_root(), png()

### Community 108 - "serve-external.mjs"
Cohesion: 0.21
Nodes (10): capture(), detectStderrOrigin, detectStdoutOrigin, port, root, runtimeDir, stop(), timeout (+2 more)

### Community 109 - "vul-web-1/package.json"
Cohesion: 0.15
Nodes (12): description, engines, node, name, private, scripts, intruder, probe:idor (+4 more)

### Community 110 - "dependency-inventory.mjs"
Cohesion: 0.30
Nodes (12): 현재 추가된 결정론적 제한, main(), parseArgs(), bounded(), child(), object(), parseNpmLock(), parsePom() (+4 more)

### Community 111 - "general-results.test.mjs"
Cohesion: 0.11
Nodes (8): result(), API와 다중 포트, Issue #32: attack-tool 구조와 구현 계획, 검증과 develop 반영 순서, 기존 구조, 목표와 첫 구현 범위, 새 통신 흐름, 신뢰·검증 경계

### Community 112 - "agent/package.json"
Cohesion: 0.17
Nodes (11): description, engines, node, name, private, scripts, demo, demo:deepseek (+3 more)

### Community 113 - "test_history_review.py"
Cohesion: 0.18
Nodes (14): check_data(), link_review(), test_changed_location_requires_explicit_link_review_and_keeps_both_locations(), test_check_can_pin_the_report_version_it_saw_before_a_later_update(), test_duplicate_references_and_blank_approval_notes_leave_results_in_draft(), test_invalid_evidence_cannot_approve_a_check(), test_migration_failure_after_snapshot_creation_rolls_back_everything(), test_migration_failure_rolls_back_ddl_data_and_version_and_is_retryable() (+6 more)

### Community 114 - "jobs"
Cohesion: 0.17
Nodes (12): runs-on, timeout-minutes, if, name, needs, runs-on, jobs, container-smoke (+4 more)

### Community 115 - "intruder.mjs"
Cohesion: 0.23
Nodes (14): buildPath(), countField(), createGuardedRequest(), createRuleset(), escapeRegex(), exactLoopbackOrigin(), IntruderDeniedError, loadIntruderPlan() (+6 more)

### Community 116 - "general-pipeline.test.js"
Cohesion: 0.17
Nodes (12): _github_params(), compare_versions(), matches_range(), UnresolvedVersion, _version(), _form_encode(), is_secret_key(), redact() (+4 more)

### Community 117 - "attack-module/index.js"
Cohesion: 0.30
Nodes (12): childEnv(), executeCurl(), executePinnedCurl(), executeUniversityRead(), failure(), findHeaderEnd(), isJsonValue(), isPlainObject() (+4 more)

### Community 118 - "capture/package.json"
Cohesion: 0.18
Nodes (11): dependencies, playwright@1.58.2, engines, node, playwright, name, private, scripts (+3 more)

### Community 119 - "web-parser/package.json"
Cohesion: 0.10
Nodes (20): wapalyzer-core, bin, web-parser, dependencies, playwright@1.58.2, wapalyzer-core@6.11.0, engines, node (+12 more)

### Community 121 - "web-parser — URL 기반 웹 구조·라이브러리 관찰"
Cohesion: 0.18
Nodes (11): moduleId(), URL 기반 의존성 결과, web-parser — URL 기반 웹 구조·라이브러리 관찰, 공통 출력 키의 출처, 구조용 출력 읽기, 선택적 로컬 의존성 파일, 수집 경계, 식별 규칙의 범위 (+3 more)

### Community 122 - "registry.mjs"
Cohesion: 0.20
Nodes (12): generalDocumentsStatus(), tick(), storeReportPreviews(), abortError(), createModelReasoning(), definitions, digest(), fetchWithRunSignal() (+4 more)

### Community 123 - "xss-canary.js"
Cohesion: 0.15
Nodes (5): sameOrigin(), createStoredXssCanary(), storedXssCanaryContent(), MARKER, planInput()

### Community 124 - "재점검 기록의 저장과 검토"
Cohesion: 0.29
Nodes (7): 1. 참고한 보고서 버전을 지정한다, 2. 관찰한 결과를 초안으로 저장한다, 3. 입력 위치가 바뀌었다면 연결을 따로 확인한다, 4. 증거를 확인하고 결과를 검토 완료로 처리한다, 검증기의 여러 결과를 한 번에 저장한다, 기존 DB를 변환할 때, 재점검 기록의 저장과 검토

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
Cohesion: 0.18
Nodes (8): inventory(), createWebInventory(), digest(), LIMITS, MODULE_ID, readResourceReferences(), RULES, RULESET_VERSION

### Community 130 - "ci.yml"
Cohesion: 0.22
Nodes (9): concurrency, cancel-in-progress, group, permissions, name, permissions, contents, packages (+1 more)

### Community 131 - "guardrail/package.json"
Cohesion: 0.20
Nodes (9): description, engines, node, main, name, private, scripts, test (+1 more)

### Community 132 - "sLLM Guardrail"
Cohesion: 0.20
Nodes (9): package.json script 설명, sLLM Guardrail, sLLM의 고정 출력 JSON, 네 가지 기능 파일, 사용 예시, 실행 흐름, 입력 형식, 코드 읽기 가이드 (+1 more)

### Community 133 - "외부 모듈 JSON 계약"
Cohesion: 0.29
Nodes (7): Attack Module, casper-db, 공통 envelope, 오류, 외부 모듈 JSON 계약, 전송 포트, 통합 DB의 공격 정보와 실행 기록

### Community 134 - "ref_node_os"
Cohesion: 0.41
Nodes (11): alive(), exists(), failure(), inspect(), plainPath(), prepareLabSessionCleanup(), privateJson(), registerLabSession() (+3 more)

### Community 135 - "CA3P Agent Loop — 로컬 통합 대시보드"
Cohesion: 0.22
Nodes (9): CA3P Security Workspace — 로컬 통합 대시보드, 검증, 기존 단일 검사 경로와 기록 호환성, 로컬 실측 기록, 사용 방법, 실행, 연결과 기록 보관, 추가 제안 (+1 more)

### Community 136 - "test_boundaries.py"
Cohesion: 0.44
Nodes (5): _rel(), sources(), test_no_environment_variable_reads(), test_no_hardcoded_absolute_paths(), test_no_network_modules()

### Community 137 - "attack-module/package.json"
Cohesion: 0.22
Nodes (8): description, engines, node, name, private, scripts, test, version

### Community 138 - "assess_observation"
Cohesion: 0.18
Nodes (15): 검토된 경로 템플릿, 기본 비교, 입력이 적용되지 않는 요청, 재점검 후보 선정 규칙, 조회와 이력, assess_observation(), CandidateMatch, ObservationAssessment (+7 more)

### Community 139 - "이 Mac에서 팀 대시보드 외부 접속"
Cohesion: 0.22
Nodes (9): 검증된 develop 자동 배포, 대학 사이트 실습 반영, 상태·실패·재시도, 설치, 이 Mac에서 팀 대시보드 외부 접속, 이 장치의 서버 운영, 임시 Cloudflare 경로, 자동 배포 중지·재개 (+1 more)

### Community 140 - "대한대학교·원창대학교 웹사이트 사전 침해분석 및 취약점 보고서"
Cohesion: 0.17
Nodes (12): 1. 요약과 판정 기준, 2. 서비스 구성과 정상 기능, 3.1 대한대학교: 선정한 CVE 세 건, 3.2 원창대학교: 선정한 CVE 세 건, 3. 외부 의존성 및 CVE 평가, 4. OWASP Top 10:2025별 사전 분석, 5. 중점 시나리오: 게시글 삭제와 사이트 가용성, 6. ARTEX 사건을 참고한 부속 업무 위험 (+4 more)

### Community 141 - "ref_node_assert"
Cohesion: 0.04
Nodes (15): { chromium }, report, run, serve(), { chromium }, context, first(), idle (+7 more)

### Community 144 - "모델 변경 시 실험 초기화"
Cohesion: 0.25
Nodes (8): 검증 계획, 구현 순서와 실패 처리, 대학 실습 관리 훅, 로컬 대한대 실습 실행, 모델 변경 시 실험 초기화, 사용 흐름, 연구 해석과 범위의 한계, 영향 범위 조사와 처리

### Community 145 - "updates"
Cohesion: 0.25
Nodes (7): interval, updates, directory, package-ecosystem, schedule, target-branch, version

### Community 146 - "deploy-staging"
Cohesion: 0.25
Nodes (8): if, needs, secrets, uses, with, deploy-staging, environment, image

### Community 147 - "demo.py"
Cohesion: 0.31
Nodes (5): escaped(), main(), pretty(), render(), _md()

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
Cohesion: 0.29
Nodes (7): 1.1 보고서가 답해야 할 것, 1.2 전체 흐름, 1.3 하는 일, 1.4.1 운영 전제 — 보고서는 사람이 최종 검토한다, 1.4 하지 않는 일, 1.5 프레이밍 지침 (프롬프트로 LLM에 유도, 코드 강제 아님), 1. 목표와 범위

### Community 158 - "run-store/package.json"
Cohesion: 0.29
Nodes (6): engines, node, name, private, type, version

### Community 159 - "CA3P 취약한 바닐라 JS 게시판"
Cohesion: 0.29
Nodes (6): 1. 저장형 XSS, 2. 파라미터 변조로 관리자 글 삭제, CA3P 취약한 바닐라 JS 게시판, 계정과 게시판, 실행, 취약점 재현

### Community 160 - "0. 조사 요약 (근거)"
Cohesion: 0.25
Nodes (8): report(), xss-parser, 검증 범위, 0.1 실행 보고서와 이벤트 — pentest-db 디스크 저장 규약, 0.3 보고서 양식, 0.4 develop에서 바뀐 점 (계획에 영향), 0.5 실습 게시판 수명과 촬영 관련 사실 (develop, 10-19 확인), 0. 조사 요약 (근거)

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

### Community 165 - "보고서 기반 DB 처리와 모듈 연결"
Cohesion: 0.18
Nodes (9): 공개 권고와 대상 소프트웨어의 영향 범위 비교, 비교 기준, 입력과 결과, 저장과 갱신, 검토와 등록, 공개 취약점 정보, 보고서 기반 DB 처리와 모듈 연결, 조회·재점검·보고서 연결 (+1 more)

### Community 166 - "run-local-sllm.js"
Cohesion: 0.60
Nodes (4): buildSafeFixture(), DEFAULT_MODULE_DIRECTORY, loadVerdictModule(), main()

### Community 168 - "보고서 생성 모듈(Report Agent) — 조사 결과 및 개발 PLAN"
Cohesion: 0.22
Nodes (9): references(), 4.1 트리거: `ReportTrigger` (main Agent → Report Agent), 4.2 결과: `ReportResult` (Report Agent → main Agent), 4.3 내부 계약, 4. 인터페이스와 계약, 5. 마일스톤, 6. 테스트 전략, 7. 미해결 질문과 요청 항목 (+1 more)

### Community 177 - "web-parser — 모듈 계약 (초안)"
Cohesion: 0.09
Nodes (21): 6. `deepseek-reasoning-engine.js`, hybrid safety boundary, 모델 출력 schema, 1차 DB 검증 기록, 2026-10-01 추가 검증, 2026-10-06 v5 변경 검증, 2026-10-06 공유 전 재검증, targetInfo() (+13 more)

### Community 183 - "attack-tool/package.json"
Cohesion: 0.18
Nodes (10): description, engines, node, name, private, scripts, start, test (+2 more)

### Community 184 - "adapters/local-lab-gateway.mjs"
Cohesion: 0.22
Nodes (17): run(), prepareParserKnowledge(), assertAttackRequest(), assertXssAttackRequest(), awaitBoardOrigin(), BOARD_SERVER, closedProcess(), createBolaGateway() (+9 more)

### Community 185 - "CI/CD 및 대시보드 테스트 가이드"
Cohesion: 0.33
Nodes (6): 1. 변경 전 로컬 검증, 2. PR 및 배포 확인, 3. 대시보드 기능 테스트, 4. 이 장치에서 외부 접속 테스트, CI/CD 및 대시보드 테스트 가이드, Workspace AI 채팅

### Community 186 - "createRunRepository"
Cohesion: 0.09
Nodes (22): runWithFindings(), setup(), waitFor(), setup(), runWorker(), createRunRepository(), assertExperimentReady(), assertLease() (+14 more)

### Community 187 - "ui-platform.test.mjs"
Cohesion: 0.28
Nodes (7): { chromium }, event, idle, resetModels, setup(), snapshot(), wrap()

### Community 188 - "리피터 (Repeater) — 에이전트 사용 설명서"
Cohesion: 0.29
Nodes (6): 결과, 동작, 리피터 (Repeater) — 에이전트 사용 설명서, 새 공격 유형 추가, 어떻게 호출하나, 언제 쓰나

### Community 189 - "general_model.py"
Cohesion: 0.70
Nodes (3): _asset_path(), build_general_model(), _text()

### Community 190 - "run-notion-vulnerability-matrix.js"
Cohesion: 0.24
Nodes (7): 로컬 검증, cases, DEFAULT_MODULE_DIRECTORY, main(), runCase(), timeoutMs, worker()

### Community 191 - "PR 규칙"
Cohesion: 0.50
Nodes (4): Attack tool, PR 규칙, 브랜치, 수정

### Community 193 - "scripts"
Cohesion: 0.25
Nodes (8): scripts, probe:idor, smoke, start, start:daehan, start:wonchang, test:idor, test:reset

### Community 195 - "structure-output.test.mjs"
Cohesion: 0.43
Nodes (3): catalogue(), toStructure(), unique()

### Community 197 - "createScriptedGateway"
Cohesion: 0.87
Nodes (6): createScriptedGateway(), attackResponse(), evidenceId(), exchange(), parserResponse(), respond()

## Knowledge Gaps
- **3 isolated node(s):** `casper-case-db`, `ca3p-report`, `edu.wonchang:wonchang-university`
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1402 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **27 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `2.2 수집기 (환경 의존 부분을 전부 여기에 모은다)` connect `CaseStore` to `createRunRepository`, `2. 입력과 출력`, `repository.py`?**
  _High betweenness centrality (0.223) - this node is a cross-community bridge._
- **What connects `casper-case-db`, `ca3p-report`, `edu.wonchang:wonchang-university` to the rest of the system?**
  _3 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `api/server.mjs` be split into smaller, more focused modules?**
  _Cohesion score 0.07111501316944688 - nodes in this community are weakly interconnected._
- **Why does `createRunRepository()` connect `createRunRepository` to `0. 조사 요약 (근거)`, `CaseStore`, `check-sync.mjs`, `createRunService`, `redact`, `runner.test.mjs`, `idor-runtime.mjs`, `external-target.mjs`, `module-management.mjs`?**
  _High betweenness centrality (0.221) - this node is a cross-community bridge._
- **Should `casper_db/cli.py` be split into smaller, more focused modules?**
  _Cohesion score 0.06693877551020408 - nodes in this community are weakly interconnected._
- **Why does `CaseStore` connect `CaseStore` to `ReportIntake`, `casper_db/cli.py`, `collect`, `DeviceDatabaseTests`, `pathlib`, `assess_observation`, `general-runtime.mjs`, `casper_db/cli.py`, `test_history_review.py`, `demo.py`, `digest`, `repository.py`?**
  _High betweenness centrality (0.175) - this node is a cross-community bridge._
- **Should `public_http.py` be split into smaller, more focused modules?**
  _Cohesion score 0.09841269841269841 - nodes in this community are weakly interconnected._