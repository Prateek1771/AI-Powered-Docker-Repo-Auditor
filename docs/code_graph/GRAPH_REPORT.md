# Code Graph - AI-Powered Docker Repo Auditor  (2026-08-30)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 1113 nodes · 2480 edges · 89 communities (58 shown, 13 thin omitted)
- Extraction: 96% EXTRACTED · 4% INFERRED · 0% AMBIGUOUS · INFERRED: 90 edges (avg confidence: 0.94)
- Token cost: 3,942 input · 825 output

## Graph Freshness
- Built from commit: `b907982e`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- AWS ECS and CloudWatch
- CVE Vulnerability Analysis
- Error Handling and Queue
- Terraform Modules
- Job Processing and Storage
- Findings UI Components
- Scan Job Management
- Dockerfile Optimization
- TypeScript Configuration
- Metrics and Reports
- AWS Networking Resources
- Frontend Image UI
- Image Scanning Orchestration
- Scan Status and Diff UI
- Agent Output Trust
- AWS IAM Roles and Policies
- Docker History from Reports
- AWS IAM Execution Roles
- Job Progress Events
- API Initialization and Auth
- Image Upload API
- JWT Authentication
- Image Upload Integration
- Scan Status UI
- AWS ECR Repositories and Policies
- Scan Execution and Storage
- API Tests and Auth
- Scan Outcome Management
- Frontend Dependencies
- Compliance Finding Evaluation
- Scan Progress UI
- Report Storage and Retrieval
- Image Bloat Analysis
- Frontend Dev Dependencies
- Compliance Checking
- Docker Layer Parsing
- Image Layer Metadata
- Scan Result Storage
- AWS ElastiCache Configuration
- Severity Badge UI
- AWS SQS Queues
- AWS S3 Storage Configuration
- AWS Cognito User Pools
- AWS DynamoDB Tables
- Documentation Drift Checking
- Project Package Configuration
- AWS Secrets Manager
- DynamoDB Serialization
- Agent Scan Execution
- WebSocket Job Management
- Scan Cache Management
- Scan Progress Hook
- Progress Event Pub/Sub
- Trivy Scan Execution
- JWKS Server Fixture
- App Layout
- JWKS Test Fixture
- WebSocket Auth Fixture
- ESLint
- ESLint Configuration
- Next.js Configuration
- jsdom Testing Environment
- React Testing Library
- Node.js Types
- React DOM Types
- Vite React Plugin
- Vitest Testing Framework
- PostCSS Configuration
- Terraform AWS Provider
- Redis Connection Management
- Worker Process

## God Nodes (most connected - your core abstractions)
1. `cn()` - 30 edges
2. `AgentOutcome` - 29 edges
3. `DockerHistoryError` - 25 edges
4. `create_job()` - 24 edges
5. `ScanOutcome` - 23 edges
6. `run_and_store()` - 21 edges
7. `run_scan_from_raw()` - 21 edges
8. `store_result()` - 20 edges
9. `extract_vulnerabilities()` - 19 edges
10. `outcomes_by_agent()` - 19 edges

## Surprising Connections (you probably didn't know these)
- `CVEAnalysisResult` --uses--> `CVEFinding`  [INFERRED]
  worker/app/agents/cve_analyst.py → worker/app/models/findings.py
- `run_dockerfile_optimizer()` --uses--> `AgentOutcome`  [INFERRED]
  worker/app/agents/dockerfile_optimizer.py → worker/app/models/outcomes.py
- `run_risk_scorer()` --uses--> `AgentOutcome`  [INFERRED]
  worker/app/agents/risk_scorer.py → worker/app/models/outcomes.py
- `evaluate_expectation()` --uses--> `AgentOutcome`  [INFERRED]
  worker/eval/matcher.py → worker/app/models/outcomes.py
- `TestHistoryFromReport` --uses--> `DockerHistoryError`  [INFERRED]
  worker/tests/test_registry_mode.py → worker/app/scanners/docker_history.py

## Import Cycles
- None detected.

## Communities (89 total, 13 thin omitted)

### Community 0 - "AWS ECS and CloudWatch"
Cohesion: 0.11
Nodes (50): aws_cloudwatch_log_group.api, aws_cloudwatch_log_group.frontend, aws_cloudwatch_log_group.redis, aws_cloudwatch_log_group.worker, aws_ecs_cluster.main, aws_ecs_service.api, aws_ecs_service.frontend, aws_ecs_service.redis (+42 more)

### Community 1 - "CVE Vulnerability Analysis"
Cohesion: 0.09
Nodes (42): BaseMessage, CVEFinding, _build_messages(), CVEAnalysisError, CVEAnalysisResult, parse_analysis(), BaseModel, RuntimeError (+34 more)

### Community 2 - "Error Handling and Queue"
Cohesion: 0.09
Nodes (37): Exception, Handler, PermanentFailure, Raised when retrying cannot help: bad input, missing image, 4xx., _install_handlers(), main(), poll_forever(), Ask the event loop to set the shutdown flag on SIGTERM or SIGINT. Windows has… (+29 more)

### Community 3 - "Terraform Modules"
Cohesion: 0.13
Nodes (36): local.name, local.tags, module.auth, module.cache, module.cicd, module.database, module.ecr, module.ecs (+28 more)

### Community 4 - "Job Processing and Storage"
Cohesion: 0.09
Nodes (35): handle_scan(), Claim a job and run it, tolerating redelivery of the same message. Losing the…, get_resource(), Any, Build the DynamoDB resource, pointed at Local when configured. With…, Return one of the two tables by its logical name., table(), claim_job() (+27 more)

### Community 5 - "Findings UI Components"
Cohesion: 0.12
Nodes (24): CATEGORY_ICON, CategoryDetails(), EXPLOITABILITY_CLASS, EXPLOITABILITY_LABEL, FindingCard(), CategoryFilter, Chip(), FindingsList() (+16 more)

### Community 6 - "Scan Job Management"
Cohesion: 0.12
Nodes (28): owned_scan(), ScanSummary, Load a scan and prove the caller owns it, as a route dependency. Authenticating…, JobStatusResponse, BaseModel, ScanAccepted, StartScanRequest, history() (+20 more)

### Community 7 - "Dockerfile Optimization"
Cohesion: 0.15
Nodes (24): BaseImageResult, BaseModel, Suggest a better base image and say what switching would cost. The saving is…, run_base_image_strategist(), AgentOutcome, Reconstruct a Dockerfile from the layers and rewrite it. Depends on the earlier…, run_dockerfile_optimizer(), AgentOutcome (+16 more)

### Community 8 - "TypeScript Configuration"
Cohesion: 0.07
Nodes (28): compilerOptions, allowJs, esModuleInterop, incremental, isolatedModules, jsx, lib, module (+20 more)

### Community 9 - "Metrics and Reports"
Cohesion: 0.13
Nodes (18): ExpectationResult, PrecisionReport, RecallReport, StabilityReport, _load(), main(), measure_precision(), measure_recall() (+10 more)

### Community 10 - "AWS Networking Resources"
Cohesion: 0.20
Nodes (25): aws_eip.nat, aws_internet_gateway.main, aws_nat_gateway.main, aws_route_table_association.private, aws_route_table_association.public, aws_route_table.private, aws_route_table.public, aws_security_group.task (+17 more)

### Community 11 - "Frontend Image UI"
Cohesion: 0.14
Nodes (20): HomePage(), ImageSource(), PRESETS, repoFor(), Selection, Tab, TABS, IMAGES (+12 more)

### Community 12 - "Image Scanning Orchestration"
Cohesion: 0.20
Nodes (18): Scan an image end to end, fetching the raw data first. The three scanners are…, run_scan(), ensure_image_present(), Return an image's build history, newest layer first. Socket mode shells out to…, Run a docker CLI command, returning code, stdout and stderr. Never raises on a…, Make sure an image is on the daemon, pulling it if it is not. Only used in…, _run(), run_docker_history() (+10 more)

### Community 13 - "Scan Status and Diff UI"
Cohesion: 0.17
Nodes (14): AgentTimings(), STATUS_LABEL, STATUS_TEXT, DockerfileDiff(), Optimization, EffortBreakdown(), TopPriorities(), Button() (+6 more)

### Community 14 - "Agent Output Trust"
Cohesion: 0.22
Nodes (20): input_confidence(), missing_inputs(), outcomes_by_agent(), AgentOutcome, Report whether every named input agent produced usable output. Trustworthy is…, Name the required agents whose output cannot be trusted. The list is what the…, Return the fraction of an agent's inputs that were trustworthy. Confidence is…, Index a list of agent outcomes by agent name. (+12 more)

### Community 15 - "AWS IAM Roles and Policies"
Cohesion: 0.18
Nodes (19): aws_iam_openid_connect_provider.github, aws_iam_role.build, aws_iam_role.deploy, aws_iam_role_policy.build, aws_iam_role_policy.deploy, data.aws_iam_policy_document.build, data.aws_iam_policy_document.build_assume, data.aws_iam_policy_document.deploy (+11 more)

### Community 16 - "Docker History from Reports"
Cohesion: 0.13
Nodes (8): history_from_report(), Rebuild `docker history` output from a Trivy report. Trivy carries the full…, inspect_from_report(), Shape a Trivy report's image config like `docker image inspect` output. Trivy's…, TestHistoryFromReport, TestInspectFromReport, TestScannerMode, TestSingleFlight

### Community 17 - "AWS IAM Execution Roles"
Cohesion: 0.19
Nodes (18): aws_iam_role.execution, aws_iam_role_policy_attachment.execution_managed, aws_iam_role_policy.execution_extra, aws_iam_role_policy.task, aws_iam_role.task, data.aws_iam_policy_document.assume, data.aws_iam_policy_document.execution_extra, data.aws_iam_policy_document.task (+10 more)

### Community 18 - "Job Progress Events"
Cohesion: 0.20
Nodes (12): Protocol, JobStatus, Record progress in the job row and publish it to the bus. The publish has its…, _report(), ProgressBus, ProgressEvent, BaseModel, RedisProgressBus (+4 more)

### Community 19 - "API Initialization and Auth"
Cohesion: 0.15
Nodes (17): dev_jwks(), dev_token(), health(), get, Report that the process is up, for load balancers and ECS., _b64(), jwks(), mint_token() (+9 more)

### Community 20 - "Image Upload API"
Cohesion: 0.13
Nodes (18): UploadFile, _chunks(), local_images(), get, post, 404 the whole feature where there is no Docker daemon to talk to. Registry…, List the images on the daemon this API can reach. ponytail: the daemon's images…, Yield an upload's body a chunk at a time. (+10 more)

### Community 21 - "JWT Authentication"
Cohesion: 0.15
Nodes (16): HTTPAuthorizationCredentials, current_principal(), _fetch_jwks(), _find_key(), Resolve the caller from the bearer token, for use as a dependency., Return the identity provider's signing keys, cached for a window. `force` skips…, Find the signing key a token's `kid` names, refreshing once if new. The single…, Verify a JWT's signature, audience, expiry and type, and return it. Raises 401… (+8 more)

### Community 22 - "Image Upload Integration"
Cohesion: 0.22
Nodes (18): integration, Store an uploaded image tar and return the target that names it. Written…, Raised when an upload is refused before anything is stored., save_upload(), UploadError, blob_dir(), _chunks(), fixture (+10 more)

### Community 23 - "Scan Status UI"
Cohesion: 0.18
Nodes (13): DegradedNotice(), STATUS_LABELS, FindingsEmpty(), AGENT_LABELS, AgentStatus, BaseFinding, BaseImageFinding, BloatFinding (+5 more)

### Community 24 - "AWS ECR Repositories and Policies"
Cohesion: 0.23
Nodes (14): aws_ecr_lifecycle_policy.api, aws_ecr_lifecycle_policy.frontend, aws_ecr_lifecycle_policy.worker, aws_ecr_repository.api, aws_ecr_repository.frontend, aws_ecr_repository.worker, output.api_repository_arn, output.api_repository_url (+6 more)

### Community 25 - "Scan Execution and Storage"
Cohesion: 0.15
Nodes (12): Turn a scan target into an image reference the scanners can use. A registry…, resolve_target(), ScanSummary, Run a scan for a queued job and persist the result. The entry point the worker…, run_and_store(), DockerHistoryError, RuntimeError, test_a_missing_upload_is_permanent() (+4 more)

### Community 26 - "API Tests and Auth"
Cohesion: 0.21
Nodes (12): _auth(), 202 must not hand back a job_id that GET immediately 404s. Nothing consumes the…, _stored(), test_a_started_scan_is_readable_before_a_worker_runs(), test_history_is_scoped_to_the_caller(), test_limit_is_bounded(), test_other_tenant_gets_404_not_403(), test_owner_can_read_their_scan() (+4 more)

### Community 27 - "Scan Outcome Management"
Cohesion: 0.17
Nodes (9): BaseModel, ScanOutcome, _FakeBus, _outcome(), AgentOutcome, A ProgressBus double - run_and_store only ever publishes and closes it., test_clean_scan_is_not_degraded(), test_empty_findings_alone_does_not_mean_clean() (+1 more)

### Community 28 - "Frontend Dependencies"
Cohesion: 0.13
Nodes (15): clsx, dependencies, clsx, lucide-react, motion, next, react, react-dom (+7 more)

### Community 29 - "Compliance Finding Evaluation"
Cohesion: 0.24
Nodes (13): ComplianceFinding, evaluate_expectation(), finding_matches(), AgentOutcome, Any, Flatten the prose fields of any finding into one lowercase string. Every…, Test one finding against an expectation's match rules. Identifiers must be…, Decide whether one expectation was met, and say why if not. An agent that did… (+5 more)

### Community 30 - "Scan Progress UI"
Cohesion: 0.21
Nodes (11): Connection, CONNECTION_COPY, ScanProgress(), STEPS, bandColor(), ScoreBars(), bandColor(), ScoreRing() (+3 more)

### Community 31 - "Report Storage and Retrieval"
Cohesion: 0.22
Nodes (12): main(), _client(), get_blob(), _path(), put_blob(), Any, Build an S3 client for the configured region., Return the local file a blob key maps to, creating its parent. (+4 more)

### Community 32 - "Image Bloat Analysis"
Cohesion: 0.20
Nodes (13): BloatFinding, ChatOpenAI, BloatAnalysisError, BloatAnalysisResult, parse_bloat_analysis(), BaseModel, RuntimeError, Parse a bloat analysis and reject layer indexes not in the input. Same contract… (+5 more)

### Community 33 - "Frontend Dev Dependencies"
Cohesion: 0.15
Nodes (14): eslint-config-next, devDependencies, eslint-config-next, tailwindcss, @tailwindcss/postcss, @testing-library/dom, @testing-library/jest-dom, @types/react (+6 more)

### Community 34 - "Compliance Checking"
Cohesion: 0.22
Nodes (12): T, ComplianceResult, _guard(), BaseModel, Reject controls that are not in the known CIS set. Without this the model can…, Check an image profile and its layers against the CIS controls., run_compliance_checker(), AgentError (+4 more)

### Community 35 - "Docker Layer Parsing"
Cohesion: 0.21
Nodes (13): ValueError, _clean_command(), extract_layers(), parse_size(), Turn a Docker size string like `180MB` into bytes. Raises rather than…, Recover the Dockerfile instruction from a history entry. Docker records…, Turn raw history entries into indexed layers, oldest first. The docker CLI…, parametrize (+5 more)

### Community 36 - "Image Layer Metadata"
Cohesion: 0.23
Nodes (12): ImageLayer, BaseModel, Sum every layer's bytes, which is the image's uncompressed size., total_size(), build_profile(), _env_keys(), ImageProfile, _parse_ports() (+4 more)

### Community 37 - "Scan Result Storage"
Cohesion: 0.26
Nodes (12): _counts(), previous_scan(), Find the scan before this one for the same tenant and repo. Fetches two and…, Build the composite partition key the results GSI is keyed on. Combining the…, Count total, critical and high findings across every agent., Persist a finished scan: body to blob storage, summary to DynamoDB. The size…, store_result(), tenant_repo_key() (+4 more)

### Community 38 - "AWS ElastiCache Configuration"
Cohesion: 0.32
Nodes (9): aws_elasticache_replication_group.main, aws_elasticache_subnet_group.main, local.managed, output.redis_host, var.name, var.security_group_id, var.subnet_ids, var.tags (+1 more)

### Community 39 - "Severity Badge UI"
Cohesion: 0.33
Nodes (8): band(), RecentScans(), Badge(), SEVERITY_CLASS, SeverityBadge(), Skeleton(), getHistory(), cn()

### Community 40 - "AWS SQS Queues"
Cohesion: 0.30
Nodes (9): aws_sqs_queue.dlq, aws_sqs_queue_redrive_allow_policy.dlq, aws_sqs_queue.scan, output.dlq_arn, output.dlq_url, output.scan_queue_arn, output.scan_queue_url, var.name (+1 more)

### Community 41 - "AWS S3 Storage Configuration"
Cohesion: 0.26
Nodes (9): aws_s3_bucket_lifecycle_configuration.reports, aws_s3_bucket_public_access_block.reports, aws_s3_bucket.reports, aws_s3_bucket_server_side_encryption_configuration.reports, aws_s3_bucket_versioning.reports, output.reports_bucket, output.reports_bucket_arn, var.name (+1 more)

### Community 42 - "AWS Cognito User Pools"
Cohesion: 0.29
Nodes (8): aws_cognito_user_pool_client.web, aws_cognito_user_pool.main, output.client_id, output.jwks_url, output.user_pool_id, var.name, var.region, var.tags

### Community 43 - "AWS DynamoDB Tables"
Cohesion: 0.29
Nodes (8): aws_dynamodb_table.jobs, aws_dynamodb_table.results, output.jobs_table_arn, output.jobs_table_name, output.results_table_arn, output.results_table_name, var.name, var.tags

### Community 44 - "Documentation Drift Checking"
Cohesion: 0.25
Nodes (10): apply(), compare(), main(), Path, Every code block in the phase 9-13 docs that names a repo file must match it.…, Replace each drifting block in a doc with its file's contents. Applied back to…, Report drift between the phase docs and the files they quote., Find the repo file a doc block names, or None if it does not exist. Paths are… (+2 more)

### Community 45 - "Project Package Configuration"
Cohesion: 0.20
Nodes (9): name, private, scripts, build, dev, lint, start, test (+1 more)

### Community 46 - "AWS Secrets Manager"
Cohesion: 0.31
Nodes (6): aws_secretsmanager_secret.llm, aws_secretsmanager_secret_version.llm, output.llm_secret_arn, var.llm_api_key, var.name, var.tags

### Community 47 - "DynamoDB Serialization"
Cohesion: 0.22
Nodes (8): item_size(), Any, BaseModel, Convert a Pydantic model into a DynamoDB-safe item. The round trip through JSON…, Convert a plain dict into a DynamoDB-safe item., Measure an item's encoded size in bytes. Used to refuse a write before DynamoDB…, to_item(), to_item_dict()

### Community 48 - "Agent Scan Execution"
Cohesion: 0.32
Nodes (8): BaseException, _degrade(), AgentOutcome, Run all six agents over already-fetched scanner output. Split from run_scan so…, Run one agent and record how long it took. The duration lands in the outcome…, Turn an agent's exception into a recorded outcome, not a lost one. A timeout…, run_scan_from_raw(), _timed()

### Community 49 - "WebSocket Job Management"
Cohesion: 0.29
Nodes (8): Task, WebSocket, _finish(), job_progress(), _keepalive(), Send a ping often enough to keep an idle socket open., Cancel a task and wait for it, ignoring how it ended., Stream one job's progress to a subscriber until it finishes. Subscribes before…

### Community 50 - "Scan Cache Management"
Cohesion: 0.29
Nodes (8): _key(), load(), Any, Path, Return the cache file for one target and scanner kind., Read cached scanner output, or None if it was never stored., Write scanner output to the cache., save()

### Community 51 - "Scan Progress Hook"
Cohesion: 0.33
Nodes (6): ScanPage(), backoffMs(), Connection, NO_RETRY_CODES, useScanProgress(), ProgressEvent

### Community 52 - "Progress Event Pub/Sub"
Cohesion: 0.33
Nodes (5): ProgressEvent, _channel(), Return the pub/sub channel one job's events travel on., Broadcast one progress event to that job's channel., Yield a job's progress events until the caller stops listening. Subscribing…

### Community 53 - "Trivy Scan Execution"
Cohesion: 0.29
Nodes (6): build_command(), _execute(), RuntimeError, Build the Trivy invocation for whichever mode this deployment runs. Registry…, Run Trivy once and return its parsed JSON report. A non-zero exit, a timeout…, TrivyScanError

### Community 54 - "JWKS Server Fixture"
Cohesion: 0.43
Nodes (6): main(), jwks_server(), fixture, Serve the dev JWKS over real HTTP on the port JWKS_URL points at. app.core.auth…, tables(), tenant()

### Community 55 - "App Layout"
Cohesion: 0.40
Nodes (3): geistMono, geistSans, metadata

### Community 56 - "JWKS Test Fixture"
Cohesion: 0.67
Nodes (3): fixture, Every authed test needs the JWKS endpoint reachable over HTTP., _serve_jwks()

### Community 57 - "WebSocket Auth Fixture"
Cohesion: 0.67
Nodes (3): fixture, The WS handler verifies the token over real HTTP, same as the API., _serve_jwks()

## Knowledge Gaps
- **90 isolated node(s):** `Tab`, `Optimization`, `Props`, `Effort`, `ScanStatus` (+85 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 351 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **13 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AgentOutcome` connect `Agent Output Trust` to `Scan Result Storage`, `Dockerfile Optimization`, `Image Scanning Orchestration`, `Agent Scan Execution`, `API Tests and Auth`, `Scan Outcome Management`, `Compliance Finding Evaluation`?**
  _High betweenness centrality (0.019) - this node is a cross-community bridge._
- **Why does `extract_vulnerabilities()` connect `CVE Vulnerability Analysis` to `Agent Scan Execution`, `Image Scanning Orchestration`?**
  _High betweenness centrality (0.018) - this node is a cross-community bridge._
- **Why does `create_job()` connect `Job Processing and Storage` to `Error Handling and Queue`, `Scan Result Storage`, `Scan Job Management`, `DynamoDB Serialization`, `Job Progress Events`, `API Initialization and Auth`, `Report Storage and Retrieval`?**
  _High betweenness centrality (0.014) - this node is a cross-community bridge._
- **Are the 7 inferred relationships involving `AgentOutcome` (e.g. with `run_dockerfile_optimizer()` and `run_risk_scorer()`) actually correct?**
  _`AgentOutcome` has 7 INFERRED edges - model-reasoned connections that need verification._
- **Are the 6 inferred relationships involving `DockerHistoryError` (e.g. with `test_a_missing_upload_is_permanent()` and `test_a_tar_docker_cannot_load_is_permanent()`) actually correct?**
  _`DockerHistoryError` has 6 INFERRED edges - model-reasoned connections that need verification._
- **Are the 7 inferred relationships involving `ScanOutcome` (e.g. with `DockerfileResult` and `ScoredRisk`) actually correct?**
  _`ScanOutcome` has 7 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Tab`, `Optimization`, `Props` to the rest of the system?**
  _90 weakly-connected nodes found - possible documentation gaps or missing edges._