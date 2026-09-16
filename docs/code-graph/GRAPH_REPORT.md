# Graph Report - code-graph  (2026-09-16)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 2226 nodes · 4800 edges · 133 communities (103 shown, 13 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 134 edges (avg confidence: 0.93)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `d62ab079`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- ecs/variables.tf
- RouteInfo
- success_thresholds
- FileCoverage
- TestGenerator
- module.ecs
- create_job
- test_telemetry.py
- test_cve_analyst.py
- api.ts
- test_reliability.py
- PrometheusTab.tsx
- test_images.py
- ScanOutcome
- findings.py
- format.ts
- test_queue.py
- Suppression
- iam/main.tf
- test_cli.py
- orchestrator.py
- test_reporting.py
- [jobId]/page.tsx
- api/images.py
- cicd/main.tf
- compilerOptions
- test_injection_resistance.py
- run.py
- mint_token
- networking/main.tf
- test_report_enrichment.py
- vulnerabilities.py
- test_registry_mode.py
- jobs.py
- extract_layers
- test_diff.py
- AgentOutcome
- outcomes_by_agent
- run_and_store
- drift.test.tsx
- test_exports_api.py
- AgentTimings.tsx
- test_node_progress.py
- enrich_cve_findings
- scan.ts
- test_api.py
- threat_modeler.py
- enrich.py
- next-app-router.json
- login/page.tsx
- constraints
- remix-or-sveltekit.json
- secret_scanner.py
- dependencies
- run_structured_agent
- aws_ecr_repository.api
- ScanSummary
- vite-spa.json
- devDependencies
- cn
- untrusted_block
- ProgressEvent
- main
- test_auth_hardening.py
- stack
- aws_secretsmanager_secret.llm
- is_permanent_failure
- frontend_decision_engine.py
- frontend_scaffolder.py
- aws_elasticache_replication_group.main
- aws_cognito_user_pool.main
- scans.py
- aws_sqs_queue.dlq
- aws_s3_bucket.reports
- sarif.py
- main
- telemetry/metrics.py
- ci_gates
- stack
- stack
- success_thresholds
- generate_component
- aws_dynamodb_table.jobs
- check_code_blocks.py
- run_scan_from_raw
- success_thresholds
- package.json
- extract_secrets
- success_thresholds
- _report_node
- component_library_options
- constraints
- constraints
- ProgressBus
- job_progress
- _key
- ScanCoverage
- _channel
- upload_image
- api.py
- deduplicate
- .terraform.lock.hcl
- counts_by_severity
- _serve_jwks
- eslint
- eslint.config.mjs
- next.config.ts
- tailwindcss
- @testing-library/react
- @types/node
- @types/react-dom
- vitest
- postcss.config.mjs
- .matches
- .close
- worker

## God Nodes (most connected - your core abstractions)
1. `AgentOutcome` - 42 edges
2. `cn()` - 38 edges
3. `run_scan_from_raw()` - 34 edges
4. `ScanOutcome` - 33 edges
5. `create_job()` - 29 edges
6. `store_result()` - 25 edges
7. `DockerHistoryError` - 24 edges
8. `extract_vulnerabilities()` - 24 edges
9. `run_and_store()` - 23 edges
10. `CVEFinding` - 22 edges

## Surprising Connections (you probably didn't know these)
- `_segment()` --uses--> `BlobKeyError`  [INFERRED]
  worker/app/images.py → worker/app/storage/blobs.py
- `upload_image()` --uses--> `UploadError`  [INFERRED]
  worker/app/api/images.py → worker/app/images.py
- `ScanOutcome` --uses--> `ScanCoverage`  [INFERRED]
  worker/app/models/outcomes.py → worker/app/models/coverage.py
- `ScanOutcome` --uses--> `DockerfileResult`  [INFERRED]
  worker/app/models/outcomes.py → worker/app/models/findings.py
- `ScanOutcome` --uses--> `ScoredRisk`  [INFERRED]
  worker/app/models/outcomes.py → worker/app/models/findings.py

## Import Cycles
- None detected.

## Communities (133 total, 13 thin omitted)

### Community 0 - "ecs/variables.tf"
Cohesion: 0.09
Nodes (59): aws_cloudwatch_log_group.api, aws_cloudwatch_log_group.frontend, aws_cloudwatch_log_group.redis, aws_cloudwatch_log_group.worker, aws_ecs_cluster.main, aws_ecs_service.api, aws_ecs_service.frontend, aws_ecs_service.redis (+51 more)

### Community 1 - "RouteInfo"
Cohesion: 0.06
Nodes (33): ConfigGenerator, E2ETestScaffolder, main(), PageObject, PageObjectGenerator, Path, Recursively scan directory for routes, Process a potential page file (+25 more)

### Community 2 - "success_thresholds"
Cohesion: 0.04
Nodes (47): anti_recommendations, custom-cms-build, google-tag-manager-on-marketing, next-app-router-for-static-marketing, react-app-on-every-page, spa-for-marketing, third-party-tag-soup, canon_references (+39 more)

### Community 3 - "FileCoverage"
Cohesion: 0.07
Nodes (27): CoverageAnalyzer, CoverageAnalyzerTool, CoverageGap, CoverageParser, CoverageSummary, FileCoverage, main(), Any (+19 more)

### Community 4 - "TestGenerator"
Cohesion: 0.08
Nodes (28): ComponentInfo, ComponentScanner, main(), Path, Scan a single file for components, Add a component to the list if not already present, Generates Jest + React Testing Library test files, Generate a test file for a component (+20 more)

### Community 5 - "module.ecs"
Cohesion: 0.12
Nodes (40): local.name, local.tags, module.auth, module.cache, module.cicd, module.database, module.ecr, module.ecs (+32 more)

### Community 6 - "create_job"
Cohesion: 0.10
Nodes (41): claim_job(), create_job(), get_job(), lease_is_live(), JobStatus, Move a job from queued to running, returning False if someone won. This is what…, Whether a running job is still held by a worker that is alive. The question…, Overwrite a job's status, percentage and step. An update rather than a put so… (+33 more)

### Community 7 - "test_telemetry.py"
Cohesion: 0.08
Nodes (35): Logger, LogRecord, StringIO, Metrics and structured logs for the scan pipeline. Nothing here is required to…, configure_logging(), _fields(), job_context(), JobFilter (+27 more)

### Community 8 - "test_cve_analyst.py"
Cohesion: 0.11
Nodes (36): CVEAnalysisResult, BaseModel, CVEFinding, Stop the model reporting a CVE as less severe than the scanner did. The…, Triage scanner vulnerabilities into ranked, explained findings. No…, reconcile_severities(), run_cve_analyst(), AgentError (+28 more)

### Community 9 - "api.ts"
Cohesion: 0.11
Nodes (29): HomePage(), ImageSource(), PRESETS, repoFor(), Selection, Tab, TABS, IMAGES (+21 more)

### Community 10 - "test_reliability.py"
Cohesion: 0.09
Nodes (36): handle_scan(), Claim a job and run it, tolerating redelivery of the same message. Losing the…, BlobKeyError, _checked(), _client(), get_blob(), _path(), put_blob() (+28 more)

### Community 11 - "PrometheusTab.tsx"
Cohesion: 0.14
Nodes (28): AnalyticsPage(), TabId, TABS, GET(), GatewayTab(), usd(), OtelTab(), PrometheusTab() (+20 more)

### Community 12 - "test_images.py"
Cohesion: 0.12
Nodes (35): discard_upload(), Path, ValueError, Store an uploaded image tar and return the target that names it. Written…, Turn a scan target into something the scanners can read. A registry reference…, Delete a resolved upload once its scan is done. One scan per upload: keeping…, Raised when an upload is refused before anything is stored., Return a path segment, refusing anything that could escape the dir. Both halves… (+27 more)

### Community 13 - "ScanOutcome"
Cohesion: 0.10
Nodes (31): ScanOutcome, main(), _counts(), get_full_report(), previous_scan(), Build the composite partition key the results GSI is keyed on. Combining the…, Load a scan's full report, following the summary to its blob., Find the scan before this one for the same tenant and repo. Fetches two and… (+23 more)

### Community 14 - "findings.py"
Cohesion: 0.12
Nodes (27): BaseImageResult, BaseModel, ImageProfile, Suggest a better base image and say what switching would cost. The saving is…, run_base_image_strategist(), BloatAnalysisResult, BaseModel, AgentOutcome (+19 more)

### Community 15 - "format.ts"
Cohesion: 0.11
Nodes (25): CATEGORY_ICON, CategoryDetails(), EXPLOITABILITY_CLASS, EXPLOITABILITY_LABEL, FindingCard(), CategoryFilter, FindingsList(), SeverityFilter (+17 more)

### Community 16 - "test_queue.py"
Cohesion: 0.12
Nodes (31): Handler, _install_handlers(), main(), poll_forever(), Ask the event loop to set the shutdown flag on SIGTERM or SIGINT. Windows has…, Poll the queue until asked to stop, backing off after a failure. The flag is…, Install signal handlers and run the poll loop., consume_once() (+23 more)

### Community 17 - "Suppression"
Cohesion: 0.16
Nodes (28): apply_policy(), _first_match(), datetime, Apply suppressions to findings - by marking them, never by deleting them. The…, Return the report with suppressed findings marked. The input is not mutated:…, Every finding the report still stands behind. What the gate counts and what the…, unsuppressed_findings(), load_policy() (+20 more)

### Community 18 - "iam/main.tf"
Cohesion: 0.16
Nodes (30): aws_iam_role.execution_app, aws_iam_role.execution_redis, aws_iam_role.execution_web, aws_iam_role_policy_attachment.execution_managed, aws_iam_role_policy.execution_app_secrets, aws_iam_role_policy.execution_redis_secrets, aws_iam_role_policy.task_api, aws_iam_role_policy.task_worker (+22 more)

### Community 19 - "test_cli.py"
Cohesion: 0.11
Nodes (31): Namespace, breaches(), build_parser(), main(), ArgumentParser, Scan an image from a pipeline and fail the build on what it finds. python -m…, The same shape store_result writes, so exporters see one format. Exporters take…, Unsuppressed findings at or above the threshold. Ordered by SEVERITY_ORDER… (+23 more)

### Community 20 - "orchestrator.py"
Cohesion: 0.15
Nodes (24): list_local_images(), List the images on the Docker daemon, newest first. Only meaningful in socket…, _fetch_raw(), Gather the three scanners, reporting each one separately. They are independent,…, Scan an image end to end, fetching the raw data first., run_scan(), DockerHistoryError, ensure_image_present() (+16 more)

### Community 21 - "test_reporting.py"
Cohesion: 0.11
Nodes (29): all_findings(), Every finding, suppressed or not. What an export shows., Where a severity sits in SEVERITY_ORDER. Lower is worse., severity_rank(), _bom_ref(), _component(), CycloneDX 1.5, from the package inventory the scan already collected. Trivy…, Render a stored report as a CycloneDX 1.5 BOM. (+21 more)

### Community 22 - "[jobId]/page.tsx"
Cohesion: 0.14
Nodes (18): DockerfileDiff(), Optimization, EffortBreakdown(), ExportMenu(), save(), FORMATS, ImageProfileCard(), PackagesTable() (+10 more)

### Community 23 - "api/images.py"
Cohesion: 0.11
Nodes (27): HTTPAuthorizationCredentials, HTTPException, local_images(), get, 404 the whole feature where there is no Docker daemon to talk to. Registry…, List the images on the daemon this API can reach. ponytail: the daemon's images…, _socket_mode_only(), current_principal() (+19 more)

### Community 24 - "cicd/main.tf"
Cohesion: 0.15
Nodes (26): aws_iam_openid_connect_provider.github, aws_iam_role.build, aws_iam_role.deploy, aws_iam_role_policy_attachment.terraform_read, aws_iam_role_policy.build, aws_iam_role_policy.deploy, aws_iam_role_policy.terraform_state, aws_iam_role.terraform (+18 more)

### Community 25 - "compilerOptions"
Cohesion: 0.07
Nodes (28): compilerOptions, allowJs, esModuleInterop, incremental, isolatedModules, jsx, lib, module (+20 more)

### Community 26 - "test_injection_resistance.py"
Cohesion: 0.16
Nodes (26): ComplianceFinding, check_deterministic_controls(), _no_healthcheck(), _privileged_ports(), ComplianceFinding, ImageProfile, CIS controls decided in Python, not asked of a model. Three of the seven…, CIS 4.1 - a non-root USER is set. (+18 more)

### Community 27 - "run.py"
Cohesion: 0.13
Nodes (18): ExpectationResult, PrecisionReport, RecallReport, StabilityReport, _load(), main(), measure_precision(), measure_recall() (+10 more)

### Community 28 - "mint_token"
Cohesion: 0.11
Nodes (24): integration, dev_jwks(), dev_token(), health(), get, Report that the process is up, for load balancers and ECS., _b64(), jwks() (+16 more)

### Community 29 - "networking/main.tf"
Cohesion: 0.20
Nodes (25): aws_eip.nat, aws_internet_gateway.main, aws_nat_gateway.main, aws_route_table_association.private, aws_route_table_association.public, aws_route_table.private, aws_route_table.public, aws_security_group.task (+17 more)

### Community 30 - "test_report_enrichment.py"
Cohesion: 0.12
Nodes (27): fingerprint_findings(), fingerprint_of(), T, Return a stable identity for a finding, across scans and wording. Built only…, Stamp every finding with its fingerprint., axis_scores(), overall_score(), AgentOutcome (+19 more)

### Community 31 - "vulnerabilities.py"
Cohesion: 0.14
Nodes (23): Severity, _extract_cvss(), _extract_cvss_vector(), extract_vulnerabilities(), normalise_severity(), prioritise(), Map a severity string onto our own five-level scale. Anything unrecognised…, Pull the V3 vector string, preferring the same source as the score. The vector… (+15 more)

### Community 32 - "test_registry_mode.py"
Cohesion: 0.10
Nodes (9): history_from_report(), Rebuild `docker history` output from a Trivy report. Trivy carries the full…, inspect_from_report(), Shape a Trivy report's image config like `docker image inspect` output. Trivy's…, TestHistoryFromReport, TestInspectFromReport, TestPermanentFlag, TestScannerMode (+1 more)

### Community 33 - "jobs.py"
Cohesion: 0.13
Nodes (19): _delete(), _heartbeat(), Any, Run a coroutine with a heartbeat alongside it, cancelled after., Delete one message, off the event loop., Keep this worker's claim alive while its scan runs. Two things, on one clock,…, _with_heartbeat(), get_resource() (+11 more)

### Community 34 - "extract_layers"
Cohesion: 0.14
Nodes (22): _clean_command(), extract_layers(), ImageLayer, parse_size(), BaseModel, Sum every layer's bytes, which is the image's uncompressed size., Turn a Docker size string like `180MB` into bytes. Raises rather than…, Recover the Dockerfile instruction from a history entry. Docker records… (+14 more)

### Community 35 - "test_diff.py"
Cohesion: 0.14
Nodes (22): diff_against_previous(), _fingerprints(), _previous_fingerprints(), BaseModel, What changed since the last scan of this repo. `previous_scan()` has been…, Whether this scan found something the last one did not., Read the prior report's fingerprints, or None if it is unusable. None rather…, Classify this scan's findings against the previous one. Returns None when there… (+14 more)

### Community 36 - "AgentOutcome"
Cohesion: 0.14
Nodes (21): AgentOutcome, BaseModel, Whether this outcome is evidence, rather than an absence of it.…, evaluate_expectation(), finding_matches(), AgentOutcome, Any, Flatten the prose fields of any finding into one lowercase string. Every… (+13 more)

### Community 37 - "outcomes_by_agent"
Cohesion: 0.19
Nodes (21): AgentOutcome, Reconstruct a Dockerfile from the layers and rewrite it. Depends on the earlier…, run_dockerfile_optimizer(), input_confidence(), missing_inputs(), outcomes_by_agent(), AgentOutcome, Report whether every named input agent produced usable output. Trustworthy is… (+13 more)

### Community 38 - "run_and_store"
Cohesion: 0.12
Nodes (17): PermanentFailure, Exception, Raised when retrying cannot help: bad input, missing image, 4xx., ScanSummary, Time one stage of a scan. Three stages, matching the three things a scan spends…, Run a scan for a queued job and persist the result. The entry point the worker…, run_and_store(), _stage() (+9 more)

### Community 39 - "drift.test.tsx"
Cohesion: 0.16
Nodes (14): CoverageNotice(), Connection, CONNECTION_COPY, ScanProgress(), STEPS, ScoreBars(), ScoreRing(), bandColor() (+6 more)

### Community 40 - "test_exports_api.py"
Cohesion: 0.15
Nodes (20): extract_packages(), Package, BaseModel, The image's full package inventory, for the SBOM. Trivy already reports every…, Flatten every package Trivy listed into one inventory. Deduplicated on (name,…, _auth(), fixture, parametrize (+12 more)

### Community 41 - "AgentTimings.tsx"
Cohesion: 0.13
Nodes (15): AgentTimings(), DegradedNotice(), STATUS_LABELS, FindingsEmpty(), AGENTS, isAgentStatus(), Node(), PipelineView() (+7 more)

### Community 42 - "test_node_progress.py"
Cohesion: 0.17
Nodes (18): _node_reporter(), Build the callback that turns node transitions into progress frames. The bar is…, parametrize, ProgressEvent, Cover the per-node progress frames the pipeline graph is built on. The…, Scanners must finish exactly where "Running agents" starts, and agents exactly…, hooks/useScanProgress.ts drops any frame without a numeric progress and a…, Only a settled node is progress. Otherwise starting four agents at once would… (+10 more)

### Community 43 - "enrich_cve_findings"
Cohesion: 0.12
Nodes (18): enrich_cve_findings(), Enrichment, CVEFinding, The feeds, fetched once per scan. `kev`/`epss` are None when the feed could not…, Copy the scanner's facts, and the feeds', onto each finding. Everything here is…, A wall of unfixable criticals used to crowd out actionable ones., We could not check' and 'not exploited' must never render alike., Sending them cost tokens and bought nothing - they are stapled on after the… (+10 more)

### Community 44 - "scan.ts"
Cohesion: 0.14
Nodes (18): ScanPage(), backoffMs(), Connection, NO_RETRY_CODES, useScanProgress(), BaseFinding, BaseImageFinding, BloatFinding (+10 more)

### Community 45 - "test_api.py"
Cohesion: 0.16
Nodes (15): _auth(), fixture, Every authed test needs the JWKS endpoint reachable over HTTP., 202 must not hand back a job_id that GET immediately 404s. Nothing consumes the…, _serve_jwks(), _stored(), test_a_started_scan_is_readable_before_a_worker_runs(), test_history_is_scoped_to_the_caller() (+7 more)

### Community 46 - "threat_modeler.py"
Cohesion: 0.19
Nodes (16): calculate_dread_score(), format_json_report(), format_threat_report(), get_threats_for_component(), interactive_mode(), list_all_threats(), main(), Enum (+8 more)

### Community 47 - "enrich.py"
Cohesion: 0.17
Nodes (15): _batch(), load_epss_scores(), EPSS scores from FIRST: the probability a CVE is exploited in 30 days. CVSS…, Return EPSS scores for the ids that have one. None means the API could not be…, _cache_path(), _download(), _fresh(), load_kev_ids() (+7 more)

### Community 48 - "next-app-router.json"
Cohesion: 0.11
Nodes (17): anti_recommendations, csr-only-on-seo-routes, css-in-js-runtime, default-imports-for-icons, global-state-in-context-everywhere, redux-without-justification, use-client-everywhere, canon_references (+9 more)

### Community 49 - "login/page.tsx"
Cohesion: 0.20
Nodes (12): geistMono, geistSans, metadata, LoginForm(), AuthGate(), clearSession(), cognitoConfigured, cognitoIdToken() (+4 more)

### Community 50 - "constraints"
Cohesion: 0.12
Nodes (17): constraints, auth_walled_only, primary_device, read_write_ratio_min, rendering, seo_dependent, team_size_max, team_size_min (+9 more)

### Community 51 - "remix-or-sveltekit.json"
Cohesion: 0.12
Nodes (16): anti_recommendations, client-router-on-top, heavy-client-state-libs, no-progressive-enhancement, rsc-style-data-flow, swr-or-react-query, canon_references, description (+8 more)

### Community 52 - "secret_scanner.py"
Cohesion: 0.24
Nodes (16): format_json_report(), format_text_report(), list_patterns(), main(), Enum, Path, Scan a single file for secrets., Scan all files in a directory for secrets. (+8 more)

### Community 53 - "dependencies"
Cohesion: 0.12
Nodes (17): amazon-cognito-identity-js, clsx, dependencies, amazon-cognito-identity-js, clsx, lucide-react, motion, next (+9 more)

### Community 54 - "run_structured_agent"
Cohesion: 0.15
Nodes (16): ChatOpenAI, assert_not_suppressed(), build_client(), parse_structured(), BaseModel, T, Build the chat client every agent shares. JSON response format is requested at…, Parse a model reply into a schema, or raise saying why it failed. Bad JSON, a… (+8 more)

### Community 55 - "aws_ecr_repository.api"
Cohesion: 0.23
Nodes (14): aws_ecr_lifecycle_policy.api, aws_ecr_lifecycle_policy.frontend, aws_ecr_lifecycle_policy.worker, aws_ecr_repository.api, aws_ecr_repository.frontend, aws_ecr_repository.worker, output.api_repository_arn, output.api_repository_url (+6 more)

### Community 56 - "ScanSummary"
Cohesion: 0.17
Nodes (16): Response, owned_scan(), ScanSummary, Load a scan and prove the caller owns it, as a route dependency. Authenticating…, history(), get, ScanSummary, Return a scan's scores and counts. (+8 more)

### Community 57 - "vite-spa.json"
Cohesion: 0.12
Nodes (15): anti_recommendations, context-as-global-state, next-or-remix-for-pure-spa, no-code-splitting, redux-without-justification, ssr-on-spa-only-surface, canon_references, description (+7 more)

### Community 58 - "devDependencies"
Cohesion: 0.13
Nodes (16): eslint-config-next, devDependencies, eslint-config-next, jsdom, @tailwindcss/postcss, @testing-library/dom, @testing-library/jest-dom, @types/react (+8 more)

### Community 59 - "cn"
Cohesion: 0.23
Nodes (11): DASHBOARDS, grafanaConfigured, GrafanaTab(), Chip(), band(), RecentScans(), Badge(), SEVERITY_CLASS (+3 more)

### Community 60 - "untrusted_block"
Cohesion: 0.17
Nodes (15): ComplianceResult, _guard(), BaseModel, ImageProfile, Reject controls that are not in the known CIS set. Without this the model can…, Check an image profile and its layers against the judgement controls. 4.1, 4.6…, run_compliance_checker(), Wrap scanner output in the fence the system prompt refers to. (+7 more)

### Community 61 - "ProgressEvent"
Cohesion: 0.28
Nodes (10): ProgressEvent, BaseModel, RedisProgressBus, test_a_subscription_confirmation_is_not_an_event(), test_publish_reaches_a_subscriber(), test_two_subscribers_both_receive(), test_ws_rejects_a_missing_token(), fixture (+2 more)

### Community 62 - "main"
Cohesion: 0.23
Nodes (14): analyze_dependencies(), analyze_imports(), calculate_score(), check_nextjs_config(), load_package_json(), main(), print_report(), Path (+6 more)

### Community 63 - "test_auth_hardening.py"
Cohesion: 0.17
Nodes (14): fixture, parametrize, Cover the auth and input-validation properties the audit found unguarded. Every…, Reload app.config.api under altered env, then always put it back. The restore…, A deploy that forgets JWKS_URL must not silently trust the dev issuer., The worker imports this module for REDIS_URL and verifies no tokens. Importing…, `"a, b".split(",")` yields " b", which matches no browser Origin., reload_config() (+6 more)

### Community 64 - "stack"
Cohesion: 0.14
Nodes (14): stack, build_tool, code_split, data_fetching, forms, framework_options, language, router (+6 more)

### Community 65 - "aws_secretsmanager_secret.llm"
Cohesion: 0.24
Nodes (11): aws_secretsmanager_secret.llm, aws_secretsmanager_secret.redis, aws_secretsmanager_secret_version.llm, aws_secretsmanager_secret_version.redis, output.llm_secret_arn, output.redis_auth_token, output.redis_secret_arn, random_password.redis (+3 more)

### Community 66 - "is_permanent_failure"
Cohesion: 0.15
Nodes (13): build_command(), _execute(), is_permanent_failure(), RuntimeError, Run Trivy once and return its parsed JSON report. A non-zero exit, a timeout…, Decide whether a Trivy failure is worth retrying. Wrong by default in the safe…, Build the Trivy invocation for whichever mode this deployment runs. Registry…, TrivyScanError (+5 more)

### Community 67 - "frontend_decision_engine.py"
Cohesion: 0.37
Nodes (11): build_parser(), Inputs, load_profiles(), main(), Match, Any, ArgumentParser, rank() (+3 more)

### Community 68 - "frontend_scaffolder.py"
Cohesion: 0.26
Nodes (12): generate_config_files(), generate_structure(), get_config_templates(), main(), print_result(), Path, Generate directory structure recursively., Generate configuration files. (+4 more)

### Community 69 - "aws_elasticache_replication_group.main"
Cohesion: 0.29
Nodes (10): aws_elasticache_replication_group.main, aws_elasticache_subnet_group.main, local.managed, output.redis_host, var.auth_token, var.name, var.security_group_id, var.subnet_ids (+2 more)

### Community 70 - "aws_cognito_user_pool.main"
Cohesion: 0.29
Nodes (9): aws_cognito_user_pool_client.web, aws_cognito_user_pool.main, output.client_id, output.issuer, output.jwks_url, output.user_pool_id, var.name, var.region (+1 more)

### Community 71 - "scans.py"
Cohesion: 0.29
Nodes (10): JobStatusResponse, JobStatusResponse, BaseModel, ScanAccepted, StartScanRequest, job_status(), post, Accept a scan request, queue it, and return the job id at 202. Enqueue first… (+2 more)

### Community 72 - "aws_sqs_queue.dlq"
Cohesion: 0.30
Nodes (9): aws_sqs_queue.dlq, aws_sqs_queue_redrive_allow_policy.dlq, aws_sqs_queue.scan, output.dlq_arn, output.dlq_url, output.scan_queue_arn, output.scan_queue_url, var.name (+1 more)

### Community 73 - "aws_s3_bucket.reports"
Cohesion: 0.26
Nodes (9): aws_s3_bucket_lifecycle_configuration.reports, aws_s3_bucket_public_access_block.reports, aws_s3_bucket.reports, aws_s3_bucket_server_side_encryption_configuration.reports, aws_s3_bucket_versioning.reports, output.reports_bucket, output.reports_bucket_arn, var.name (+1 more)

### Community 74 - "sarif.py"
Cohesion: 0.26
Nodes (11): _location(), SARIF 2.1.0, built from our findings rather than passed through from Trivy.…, Where to point the annotation. Only a secret finding knows a real file and…, Render a stored report as SARIF 2.1.0., A stable rule id per finding class, not per finding. SARIF rules are the…, _result(), _rule(), _rule_id() (+3 more)

### Community 75 - "main"
Cohesion: 0.21
Nodes (11): _enable_ttl(), main(), Any, Turn on TTL over `expires_at`, tolerating it already being on. Re-enabling…, _free_port(), jwks_server(), fixture, Ask the OS for a port nothing is using. (+3 more)

### Community 76 - "telemetry/metrics.py"
Cohesion: 0.23
Nodes (9): _counter(), _histogram(), _meter(), _NoopInstrument, Any, The instruments, created once and imported by the call sites. Every one of…, Stands in for a counter or histogram when OpenTelemetry is absent., The path every test run and every profile-less compose up takes. Recording a… (+1 more)

### Community 77 - "ci_gates"
Cohesion: 0.24
Nodes (11): ci_gates, bundlewatch-per-route, lighthouse-ci, ci_gates, ci_gates, a11y-axe-checks, typecheck-strict, bundlewatch-initial-and-per-route (+3 more)

### Community 78 - "stack"
Cohesion: 0.18
Nodes (11): stack, data_fetching, fonts, forms, framework, icons, language, state_client (+3 more)

### Community 79 - "stack"
Cohesion: 0.18
Nodes (11): stack, component_pattern, data_fetching, forms, framework_options, language, state, styling (+3 more)

### Community 80 - "success_thresholds"
Cohesion: 0.18
Nodes (11): success_thresholds, bundle_kb_gzip_per_route_max, cls_p75, framework_overhead_kb_gzip_max, inp_ms_p75, javascript_disabled_works, lcp_ms_mobile_4g_p75, lighthouse_a11y_min (+3 more)

### Community 81 - "generate_component"
Cohesion: 0.29
Nodes (10): generate_component(), main(), print_result(), Path, Convert string to PascalCase., Convert PascalCase to kebab-case., Generate component files., Print generation result. (+2 more)

### Community 82 - "aws_dynamodb_table.jobs"
Cohesion: 0.29
Nodes (8): aws_dynamodb_table.jobs, aws_dynamodb_table.results, output.jobs_table_arn, output.jobs_table_name, output.results_table_arn, output.results_table_name, var.name, var.tags

### Community 83 - "check_code_blocks.py"
Cohesion: 0.25
Nodes (10): apply(), compare(), main(), Path, Every code block in the phase 9-14 docs that names a repo file must match it.…, Replace each drifting block in a doc with its file's contents. Applied back to…, Report drift between the phase docs and the files they quote., Find the repo file a doc block names, or None if it does not exist. Paths are… (+2 more)

### Community 84 - "run_scan_from_raw"
Cohesion: 0.22
Nodes (11): Find wasted space in an image's layers and name the instruction. No layers is…, run_bloat_detective(), _degrade(), AgentOutcome, Exception, Turn an agent's exception into a recorded outcome, not a lost one. A timeout…, Run all six agents over already-fetched scanner output. Split from run_scan so…, Run one agent and record how long it took. The duration lands in the outcome… (+3 more)

### Community 85 - "success_thresholds"
Cohesion: 0.20
Nodes (10): success_thresholds, bundle_kb_gzip_per_route_max, cls_p75, framework_overhead_kb_gzip_max, inp_ms_p75, lcp_ms_mobile_4g_p75, lighthouse_a11y_min, lighthouse_perf_min (+2 more)

### Community 86 - "package.json"
Cohesion: 0.20
Nodes (9): name, private, scripts, build, dev, lint, start, test (+1 more)

### Community 87 - "extract_secrets"
Cohesion: 0.20
Nodes (10): SecretFinding, extract_secrets(), Return a locator for a secret, never the secret. `Match` is the line Trivy…, Flatten Trivy's secret hits into findings. Severity comes straight from Trivy…, _redact(), They were fetched on every scan and dropped on the floor., The matched line CONTAINS a live credential. A vulnerability report is exactly…, test_a_report_with_no_secrets_yields_none() (+2 more)

### Community 88 - "success_thresholds"
Cohesion: 0.22
Nodes (9): success_thresholds, cls_p75, initial_bundle_kb_gzip_max, inp_ms_p75, lcp_ms_corporate_network_p75, lighthouse_a11y_min, lighthouse_perf_min, per_route_chunk_kb_gzip_max (+1 more)

### Community 89 - "_report_node"
Cohesion: 0.25
Nodes (9): NodeReporter, Run one scanner, announcing when it starts and when it lands. Unlike an agent,…, Tell the reporter a node changed state, if anyone is listening. Swallows its…, _report_node(), _scanned(), run_scan_from_raw(..., on_node=None) must behave exactly as before., A progress frame is a nice-to-have; the scan result is not., test_a_reporter_failure_never_reaches_the_scan() (+1 more)

### Community 90 - "component_library_options"
Cohesion: 0.25
Nodes (8): component_library_options, shadcn-ui, component_library_options, ant-design, ark-ui, chakra-ui, mantine, radix-primitives

### Community 91 - "constraints"
Cohesion: 0.25
Nodes (8): constraints, auth_walled_only, primary_device, rendering, seo_dependent, team_size_max, team_size_min, low-end-android

### Community 92 - "constraints"
Cohesion: 0.25
Nodes (8): constraints, auth_walled_only, primary_device, rendering, seo_dependent, team_size_max, team_size_min, corporate-network

### Community 93 - "ProgressBus"
Cohesion: 0.25
Nodes (5): Protocol, JobStatus, Record progress in the job row and publish it to the bus. The publish has its…, _report(), ProgressBus

### Community 94 - "job_progress"
Cohesion: 0.29
Nodes (8): Task, WebSocket, _finish(), job_progress(), _keepalive(), Send a ping often enough to keep an idle socket open., Cancel a task and wait for it, ignoring how it ended., Stream one job's progress to a subscriber until it finishes. Subscribes before…

### Community 95 - "_key"
Cohesion: 0.29
Nodes (8): _key(), load(), Any, Path, Return the cache file for one target and scanner kind., Read cached scanner output, or None if it was never stored., Write scanner output to the cache., save()

### Community 96 - "ScanCoverage"
Cohesion: 0.29
Nodes (5): BaseModel, What the scan actually looked at, as opposed to what the model wrote up. A…, Whether every vulnerability found was actually analysed., ScanCoverage, test_coverage_knows_when_a_report_is_a_sample()

### Community 97 - "_channel"
Cohesion: 0.33
Nodes (5): _channel(), ProgressEvent, Return the pub/sub channel one job's events travel on., Broadcast one progress event to that job's channel., Yield a job's progress events until the caller stops listening. Subscribing…

### Community 98 - "upload_image"
Cohesion: 0.40
Nodes (6): UploadFile, _chunks(), post, Yield an upload's body a chunk at a time., Accept a `docker save` tar and return the target that names it. The tar is not…, upload_image()

### Community 99 - "api.py"
Cohesion: 0.40
Nodes (5): assert_production_auth(), InsecureAuthConfig, RuntimeError, Raised at import when a deployment would accept dev-minted tokens., Refuse to start with dev auth settings outside a local run. Every value here…

### Community 100 - "deduplicate"
Cohesion: 0.40
Nodes (5): deduplicate(), Collapse the same vulnerability reported against the same package. Trivy…, One CVE vendored into forty jars used to eat forty of the 150 slots., test_the_same_cve_at_different_versions_is_kept_apart(), test_the_same_cve_in_many_jars_collapses()

### Community 102 - "counts_by_severity"
Cohesion: 0.67
Nodes (3): counts_by_severity(), Count every vulnerability by severity, including the zeros. The scanner's own…, test_counts_include_the_zeros()

### Community 103 - "_serve_jwks"
Cohesion: 0.67
Nodes (3): fixture, The WS handler verifies the token over real HTTP, same as the API., _serve_jwks()

## Knowledge Gaps
- **276 isolated node(s):** `TabId`, `SERIES`, `PromSeries`, `PanelKind`, `CategoryFilter` (+271 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 846 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **13 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `test_every_format_parses_with_a_real_parser()` connect `test_exports_api.py` to `FileCoverage`?**
  _High betweenness centrality (0.026) - this node is a cross-community bridge._
- **Why does `stack` connect `stack` to `vite-spa.json`, `component_library_options`?**
  _High betweenness centrality (0.023) - this node is a cross-community bridge._
- **Why does `react` connect `[jobId]/page.tsx` to `stack`, `drift.test.tsx`, `api.ts`, `PrometheusTab.tsx`, `scan.ts`, `format.ts`, `login/page.tsx`, `cn`?**
  _High betweenness centrality (0.023) - this node is a cross-community bridge._
- **Are the 8 inferred relationships involving `AgentOutcome` (e.g. with `run_dockerfile_optimizer()` and `run_risk_scorer()`) actually correct?**
  _`AgentOutcome` has 8 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `run_scan_from_raw()` (e.g. with `CVEFinding` and `fetch_enrichment()`) actually correct?**
  _`run_scan_from_raw()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 10 inferred relationships involving `ScanOutcome` (e.g. with `ScanCoverage` and `DockerfileResult`) actually correct?**
  _`ScanOutcome` has 10 INFERRED edges - model-reasoned connections that need verification._
- **What connects `TabId`, `SERIES`, `PromSeries` to the rest of the system?**
  _276 weakly-connected nodes found - possible documentation gaps or missing edges._