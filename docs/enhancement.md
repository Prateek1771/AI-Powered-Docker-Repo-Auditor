I searched GitHub broadly across container vulnerability scanners, Docker image auditors, SBOM platforms, AI DevSecOps tools, and CI integrations.

The main conclusion is:

> Your project should not compete with Trivy on raw vulnerability detection. It should sit above deterministic scanners and win on prioritization, explanation, remediation, workflow integration, and trustworthy developer experience.

Trivy, Grype, Dockle, Harbor, and KubeClarity already cover much of the underlying scanning problem. Your opportunity is to create the best **Docker security decision and remediation workflow**, not another scanner wrapper.

GitHub’s search results were noisy and included many small/unfinished repositories. One search returned **30 of 100 repositories**; the broader result set can be viewed here:

[View GitHub repository search results](https://github.com/search?q=Docker+image+vulnerability+scanner&type=repositories&sort=stars)

# 1. Most important comparable projects

## Tier 1: Projects you must understand deeply

| Repository | Approx. GitHub stars | Main strength | Relevance |
|---|---:|---|---|
| [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | 37,951 | Broad, fast security scanner | Core engine you currently depend on |
| [anchore/grype](https://github.com/anchore/grype) | 12,894 | Vulnerability matching, EPSS/KEV, VEX, risk prioritization | Strong alternative scanner and data model |
| [anchore/syft](https://github.com/anchore/syft) | 9,568 | SBOM generation and formats | Important for your product’s evidence layer |
| [goharbor/harbor](https://github.com/goharbor/harbor) | 29,394 | Registry, policies, RBAC, scanning, auditing | Mature product/workflow reference |
| [goodwithtech/dockle](https://github.com/goodwithtech/dockle) | 3,294 | Docker best-practice and CIS-style image linting | Closest open-source comparison to your Docker-specific checks |
| [aquasecurity/trivy-action](https://github.com/aquasecurity/trivy-action) | 1,418 | Simple GitHub Actions integration | Important lesson in distribution and adoption |
| [xeol-io/xeol](https://github.com/xeol-io/xeol) | 448 | End-of-life package detection | Useful additional product dimension |
| [openclarity/kubeclarity](https://github.com/openclarity/kubeclarity) | 45, archived | SBOM/vulnerability management platform | Architecture and lifecycle reference, but no longer active |

## Tier 2: AI-adjacent projects

| Repository | Approx. stars | Main idea |
|---|---:|---|
| [AI-DevSecOps-Sentinel](https://github.com/ravisinghrajput95/AI-DevSecOps-Sentinel) | 0 | AI reasoning over 11 deterministic scanners |
| [AIROM](https://github.com/airomhq/airom) | 15 | Evidence-first AI Bill of Materials with file/line provenance |
| [vnaiscan](https://github.com/vnai-dev/vnaiscan) | 0 | AI-agent image scanner for CVEs, secrets, malware, suspicious binaries |
| [container-guardian-mcp](https://github.com/rawasaditya/container-guardian-mcp) | 0 | AI-powered Docker registry auditing through MCP |
| [keelix](https://github.com/jakelamon/keelix) | 2 | Local-first infrastructure and container security |
| [ai-security-scanner](https://github.com/teddashh/ai-security-scanner) | 5 | Desktop security scanner across multiple surfaces |

The AI projects are useful conceptually, but they do not yet have the adoption, maturity, or ecosystem strength of Trivy, Grype, Syft, Harbor, or Dockle.

# 2. Trivy: learn distribution, not just scanning

Repository:

[https://github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy)

Trivy is not successful only because it detects CVEs. It is successful because it is:

- Easy to install
- Easy to run locally
- Docker-friendly
- CI-friendly
- Broad in scope
- Well documented
- Available as a GitHub Action
- Available for images, filesystems, repositories, Kubernetes, and VM images
- Able to scan vulnerabilities, secrets, misconfigurations, licenses, and SBOMs
- Available in many output formats

It also has integrations for:

- GitHub Actions
- Kubernetes
- VS Code
- SBOM workflows
- GitHub Dependency Graph
- Private registries

## What you should copy

### 1. A zero-friction CLI

Your first product interface should be:

```bash
docker-auditor scan myimage:tag
```

Not:

```text
Clone repo → start Docker Compose → configure DynamoDB → configure Redis → configure OpenAI → configure local auth → open browser
```

Offer:

- Native binaries
- Docker image
- `pipx install`
- Homebrew
- GitHub Action
- GitLab CI template

### 2. Multiple scan targets

Your current focus is mostly the image. Add:

```text
docker-auditor image myimage:tag
docker-auditor archive image.tar
docker-auditor dockerfile ./Dockerfile
docker-auditor repo .
docker-auditor registry ghcr.io/org/image:tag
docker-auditor sbom ./bom.cyclonedx.json
```

### 3. Standard output formats

Support early:

- JSON
- SARIF
- CycloneDX
- SPDX
- JUnit
- CSV
- Human-readable terminal output

Do not invent a proprietary report format as the primary integration surface.

### 4. Database and cache management

Trivy explicitly documents vulnerability database caching and update control. Your production architecture should avoid downloading a large vulnerability database for every scan.

Implement:

- Shared Trivy database cache
- Database version in every report
- Database timestamp
- Offline mode
- Mirror configuration
- Warm worker caches
- Retryable database update failures
- Air-gapped deployment support

### 5. Make integrations first-class

Trivy’s GitHub Action is more valuable than a polished dashboard because it is inserted directly into the user’s workflow.

Your product should provide:

```yaml
- uses: your-org/docker-auditor-action@v1
  with:
    image: ghcr.io/org/app:${{ github.sha }}
    fail-on: critical,high
    sarif: auditor.sarif
```

# 3. Grype and Syft: learn data quality and evidence preservation

Repositories:

- [Grype](https://github.com/anchore/grype)
- [Syft](https://github.com/anchore/syft)

These projects are especially important because they separate responsibilities:

```text
Syft → generate accurate SBOM
Grype → match SBOM packages against vulnerability data
```

That separation is better than treating the LLM as the place where all security interpretation happens.

Grype supports:

- Container images
- Filesystems
- SBOMs
- Multiple package ecosystems
- EPSS
- CISA KEV
- Risk prioritization
- OpenVEX
- CycloneDX
- Vulnerability matching

Syft supports:

- Container images
- Filesystems
- Archives
- Multiple package ecosystems
- CycloneDX
- SPDX
- Syft JSON
- Signed SBOM attestations
- Library usage

## What you should copy

### 1. Preserve raw evidence

Your current architecture reduces scanner results before sending them to the model. That is acceptable for token control, but do not discard the original facts.

Store:

```json
{
  "image_digest": "...",
  "scanner": "trivy",
  "scanner_version": "...",
  "database_version": "...",
  "package": "openssl",
  "installed_version": "...",
  "fixed_version": "...",
  "severity": "CRITICAL",
  "cvss": 9.8,
  "epss": 0.91,
  "kev": true,
  "references": [],
  "layer": 4,
  "fingerprint": "..."
}
```

The LLM should enrich this, never replace it.

### 2. Add EPSS and CISA KEV

A plain `CRITICAL` severity is not enough to prioritize work.

Prioritize using:

```text
severity
+ CVSS
+ EPSS
+ CISA KEV
+ fix availability
+ internet exposure
+ package reachability
+ runtime usage
```

This is a much stronger product feature than a model-generated risk score.

### 3. Support VEX and suppressions

Grype’s OpenVEX support is a valuable example. Enterprises need a way to say:

- This vulnerability is not affected
- This component is unreachable
- The vendor has not released a fix
- This issue is accepted until a date
- This result is suppressed for a documented reason

Implement VEX/suppression as structured, reviewable data—not an ignore button that deletes findings.

### 4. Use stable schemas

Syft and Grype treat output formats as ecosystem interfaces. You should define a versioned report schema:

```json
{
  "schema_version": "1",
  "scan_id": "...",
  "image": {
    "reference": "...",
    "digest": "..."
  },
  "evidence": {},
  "findings": [],
  "policy_result": {},
  "ai_analysis": {}
}
```

Make schema changes additive within a major version.

### 5. Add SBOM attestations

Use:

- Cosign
- in-toto
- SLSA provenance
- CycloneDX
- SPDX

This allows users to verify that the report belongs to the exact image digest they built.

# 4. Dockle: your closest Docker-specific competitor

Repository:

[https://github.com/goodwithtech/dockle](https://github.com/goodwithtech/dockle)

Dockle is much narrower than your project but has a very clear value proposition:

> “Container Image Linter for Security, Helping build the Best-Practice Docker Image.”

It focuses on:

- CIS Docker benchmarks
- Root user
- `HEALTHCHECK`
- `ADD` versus `COPY`
- Secrets in environment variables/files
- `sudo`
- Sensitive mounts
- Package cache cleanup
- `latest` tags
- Setuid/setgid files
- Empty passwords
- Image best practices

Its strengths are:

- Simple CLI
- Clear checkpoint IDs
- Explicit severity levels
- JSON output
- SARIF output
- Exit codes
- Ignore files
- GitHub Action
- Private registry support
- Multiple installation methods
- Very direct documentation

## What you should copy

### 1. Stable rule identifiers

Every rule in your product needs a stable ID:

```text
DOCKER-ROOT-001
DOCKER-HEALTHCHECK-001
DOCKER-SECRET-001
DOCKER-BASE-001
DOCKER-LAYER-001
CVE-TRIVY-001
```

Do not depend only on model-generated titles.

### 2. Explainable rule details

Each finding should have:

```text
Rule ID
Title
Severity
Evidence
Why it matters
Remediation
Reference
Suppression support
```

### 3. User-controlled policies

Dockle supports:

- Ignore rules
- Exit levels
- Exit codes
- Accepted environment variables/files
- Configuration files

Your product should allow:

```yaml
ignore:
  - DOCKER-HEALTHCHECK-001

fail_on:
  - critical
  - high

exceptions:
  - rule: DOCKER-ROOT-001
    reason: "Required by legacy vendor image"
    expires: 2026-12-01
```

### 4. Avoid unsafe automated remediation

Your README currently suggests Dockerfile rewriting. Dockle highlights a known risk: replacing `ADD` with `COPY` can be incorrect when `ADD` is intentionally extracting an archive.

AI-generated fixes should be classified as:

```text
Suggested
Generated
Build-verified
Runtime-verified
```

Never present an untested Dockerfile rewrite as a guaranteed fix.

# 5. Harbor: learn productization and operational workflow

Repository:

[https://github.com/goharbor/harbor](https://github.com/goharbor/harbor)

Harbor is not simply a scanner. It is a complete container security workflow:

- Registry
- RBAC
- Projects
- Image storage
- Image signing
- Vulnerability scanning
- Policy checks
- Replication
- Audit logs
- OIDC/LDAP
- Garbage collection
- APIs
- Web UI
- Kubernetes/Helm deployment
- Enterprise operations

Harbor’s value is that it sits where images already exist and can enforce policies before deployment.

## What you should copy

### 1. Scan the image lifecycle, not only on-demand scans

Support:

```text
on push
on pull
on deployment
scheduled rescans
on vulnerability database update
on policy change
```

A critical vulnerability can be discovered after an image was built. Scheduled rescanning is essential.

### 2. Add registry integrations

Start with:

- Amazon ECR
- GitHub Container Registry
- Docker Hub
- Google Artifact Registry
- Azure Container Registry
- Harbor
- Generic OCI registries

Prefer digest-based scans:

```text
ghcr.io/org/app@sha256:...
```

Tags are mutable and should not be the primary identity.

### 3. Add policy gates

Harbor can prevent vulnerable images from being deployed. Your product should provide:

```text
Allow image
Block image
Warn only
Require approval
```

Policy examples:

- No critical vulnerabilities
- No secrets
- No unsigned image
- No image older than 90 days
- No EOL base image
- No root execution
- No prohibited license
- Maximum number of high findings

### 4. Add organization and team features

Your current tenant model is too basic for a SaaS product.

You need:

- Organizations
- Projects/repositories
- Teams
- Roles
- Repository ownership
- Policy inheritance
- Audit logs
- Invitations
- Per-team access
- API keys/service accounts

### 5. Add auditability

Security users need to know:

```text
Who changed the policy?
Who suppressed the finding?
Who approved the deployment?
Who accessed the report?
When was the image rescanned?
```

# 6. KubeClarity: learn asset and vulnerability management

Repository:

[https://github.com/openclarity/kubeclarity](https://github.com/openclarity/kubeclarity)

Important: KubeClarity is archived and points users to OpenClarity. It is still useful as an architectural reference.

KubeClarity separates:

```text
applications
→ resources/images
→ packages
→ vulnerabilities
→ licenses
```

It supports:

- Multiple SBOM generators
- Multiple vulnerability scanners
- Runtime Kubernetes scans
- CI/CD scans
- SBOM merging
- Package-level navigation
- Application-level relationships
- Vulnerability trends
- Fixable-vulnerability dashboards
- Private registries
- Remote scanner servers
- Helm installation

## What you should copy

### 1. Model relationships, not only scan documents

Your data model should represent:

```text
Organization
  → Repository
    → Image
      → Digest
        → Layer
          → Package
            → Vulnerability
```

This enables useful questions:

- Which repositories contain this CVE?
- Which images use this package?
- Which applications are exposed?
- Which findings are fixed across all environments?
- Which base image creates most of the risk?

### 2. Separate discovery from vulnerability matching

Use this pipeline:

```text
Image
→ SBOM
→ vulnerability matching
→ deterministic policy
→ AI explanation
```

This will make rescans faster when a new vulnerability database is released.

### 3. Support scanner plugins

Design scanner adapters around a common interface:

```python
class Scanner(Protocol):
    name: str
    version: str

    async def scan(self, target: ScanTarget) -> RawScanResult:
        ...
```

Then add:

- Trivy
- Grype
- Syft
- Dockle
- Docker Scout
- Custom enterprise scanners

### 4. Support remote scanner workers

This is useful for enterprises that do not want your SaaS to pull private images directly.

Possible deployment modes:

```text
Hosted SaaS scans public images
Private worker scans private registries
Worker sends signed result to SaaS
```

That could become a major product differentiator.

# 7. Xeol: learn how to own a narrow adjacent problem

Repository:

[https://github.com/xeol-io/xeol](https://github.com/xeol-io/xeol)

Xeol focuses on end-of-life software and packages. It has a clear, narrow concept:

- Scan images
- Scan filesystems
- Scan SBOMs
- Identify EOL software
- Support lookahead windows
- Support database management
- Support private registries
- Support offline environments
- Support CI gating
- Provide signed/SLSA releases
- Provide a GitHub Action

## What you should copy

Your product currently has broad messaging around:

- Vulnerabilities
- Compliance
- Base image freshness
- Waste
- Risk
- Dockerfile optimization
- LLM analysis

That is too broad.

You should add focused product modules with clear value:

```text
Vulnerability risk
Docker hardening
EOL/base-image freshness
Secret detection
SBOM
Supply-chain provenance
```

Each module should have:

- Its own rules
- Its own evidence
- Its own policy
- Its own metrics
- Its own documentation

Do not force everything into one generic AI score.

# 8. AI DevSecOps Sentinel: your closest AI philosophy comparison

Repository:

[https://github.com/ravisinghrajput95/AI-DevSecOps-Sentinel](https://github.com/ravisinghrajput95/AI-DevSecOps-Sentinel)

This project is conceptually close to yours. Its central claim is:

> The AI reasons on top of deterministic scanners, rather than pretending to be the scanner.

It supports:

- Multiple security scanners
- Secret redaction
- Prompt-injection defense
- Scanner-grounded findings
- Evidence
- Compliance mapping
- SARIF/SBOM ingestion
- Report generation
- Repository upload
- GitHub URLs
- Async ingestion
- Dockerfile generation
- CI/CD
- Kubernetes deployment
- Cosign
- SBOM generation
- OIDC
- Playwright E2E tests
- Explicit AI quality evaluation

The README specifically emphasizes:

```text
[SCANNER-VERIFIED]
[AI-DETECTED]
```

This is a good pattern for your product.

## What you should copy

### 1. Clearly distinguish evidence sources

Every statement in your UI should be labeled:

```text
Scanner verified
Deterministic rule
Model interpretation
Model suggestion
Unverified observation
```

Example:

```text
CRITICAL — CVE-2025-1234
Source: Trivy
Confidence: Scanner verified

This package is installed in layer 4.
Source: Image metadata

Upgrade recommendation:
AI-generated suggestion, not build-verified
```

### 2. Evaluate AI-specific behavior

Your evaluation suite should include explicit tests for:

- No fabricated CVEs
- No fabricated files
- No secret leakage
- Prompt injection resistance
- Coverage of critical/high findings
- Correct severity preservation
- Correct rule references
- Correct remediation
- Correct degraded-state behavior
- Output stability
- Cost per scan
- Latency

### 3. Prefer one auditable AI call over unnecessary agent complexity

Your six-agent architecture is technically interesting, but it increases:

- Cost
- Latency
- Failure modes
- Prompt-injection surface
- Debugging complexity
- Evaluation burden

Consider whether every agent adds measurable value.

A simpler architecture could be:

```text
Deterministic scanners
→ normalization/deduplication
→ deterministic prioritization
→ one grounded analysis call
→ deterministic validation
→ report
```

Add agents only if evaluation proves that they improve outcomes.

### 4. Add real end-to-end deployment tests

Sentinel’s README highlights:

- In-image smoke tests
- Post-deploy smoke tests
- Browser tests
- Scanner availability checks
- Auth checks
- Upload limit checks
- Async ingestion checks
- Supply-chain checks

Your project needs similar proof before claiming product readiness.

# 9. AIROM: learn evidence-first product design

Repository:

[https://github.com/airomhq/airom](https://github.com/airomhq/airom)

AIROM is not a direct Docker auditor, but it has an excellent product idea:

> Every result shows exactly where the evidence came from.

It provides:

- File/line evidence
- Evidence-weighted confidence
- CycloneDX output
- SPDX output
- SARIF output
- AIBOM
- CVE overlays
- VEX
- Model lifecycle data
- Compliance mappings
- Scan diffs
- CI exit codes
- Signed rule updates
- Rule packs
- Offline scanning
- Fuzzed parsers
- No execution of discovered model files

## What you should copy

### 1. Evidence must be a first-class field

Your finding model should contain:

```json
{
  "evidence": [
    {
      "source": "docker_history",
      "layer": 4,
      "text": "RUN apt-get install openssl",
      "location": "layer:4"
    },
    {
      "source": "trivy",
      "package": "openssl",
      "installed_version": "3.0.1"
    }
  ]
}
```

### 2. Do not guess unknown values

If you cannot determine:

- Base image freshness
- Exploitability
- Reachability
- Fixed version
- Runtime usage

return:

```text
unknown
```

Do not let the LLM fill gaps from memory.

### 3. Build a rule-pack system

Your Docker rules will evolve frequently. Make rules data-driven:

```yaml
id: docker/non-root-user
severity: high
title: Image runs as root
references:
  - cis: "4.1"
message: "The final image user is root."
remediation: "Create and select a non-root user."
```

This allows:

- Rule updates without full application releases
- User-defined rules
- Organization-specific rules
- Rule versioning
- Positive/negative fixtures
- Rule ownership
- Rule deprecation

### 4. Add a diff command

```bash
docker-auditor diff baseline.json current.json
```

Show:

- New findings
- Fixed findings
- Changed severity
- Changed base image
- Changed packages
- Changed policy outcome
- Changed scanner/database version

# 10. Smaller AI/container repositories: what they teach

## [vnaiscan](https://github.com/vnai-dev/vnaiscan)

Its positioning includes:

- CVEs
- Secrets
- Malware
- Suspicious binaries
- AI-agent image security

The useful lesson is not necessarily implementation maturity. It is market positioning:

> AI workloads have special container security risks.

You could target:

- Containers running LLM services
- Images containing model weights
- RAG applications
- MCP servers
- GPU images
- Python ML dependencies
- Unsafe deserialization
- Prompt/config files embedded in images
- Model supply-chain risks

This would give you a more specific niche than generic Docker security.

## [container-guardian-mcp](https://github.com/rawasaditya/container-guardian-mcp)

The MCP angle suggests a future integration:

```text
Developer asks Claude/Cursor:
“Why is this Docker image unsafe?”
```

Your service could expose tools such as:

```text
scan_image
explain_finding
compare_scans
suggest_fix
verify_fix
get_policy_result
```

But do this after the core CLI/API is reliable. MCP should be an integration layer, not your primary product architecture.

## [keelix](https://github.com/jakelamon/keelix)

The local-first approach is relevant for security users who do not want to upload images or reports to a SaaS.

Offer deployment modes:

```text
Hosted SaaS
Self-hosted Docker Compose
Private worker
Air-gapped CLI
```

A hybrid model may be especially valuable:

- Cloud control plane
- Customer-side scanning worker
- No image bytes leave the customer network
- Only normalized findings are uploaded

# 11. What the popular projects do better than your current repository

## They are easier to adopt

Trivy:

```bash
trivy image nginx:latest
```

Dockle:

```bash
dockle nginx:latest
```

Grype:

```bash
grype nginx:latest
```

Your current project requires a much heavier setup.

### Improvement

Create a standalone executable path that does not require:

- DynamoDB
- Redis
- ElasticMQ
- Frontend
- Terraform
- Cognito
- Docker Compose

A user should be able to run:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/your-org/auditor:latest \
  scan nginx:latest
```

Then offer the hosted platform separately.

## They produce standard artifacts

Trivy, Grype, Syft, Dockle, and AIROM all emphasize standard formats or integrations.

### Improvement

Make SARIF and CycloneDX release-blocking milestones.

## They have narrow, understandable positioning

- Trivy: comprehensive security scanner
- Grype: vulnerability scanner
- Syft: SBOM generator
- Dockle: Docker image linter
- Xeol: EOL scanner
- Harbor: trusted registry
- AIROM: AI bill of materials

Your current message is more complicated:

```text
Six LLM agents analyze container images, Docker history, CIS violations,
risk scores, base images, layer bloat, reports, WebSockets, AWS infrastructure...
```

### Better positioning

Choose one:

> **The evidence-backed Docker security gate for GitHub Actions.**

Or:

> **A Docker security scanner that explains what to fix without hiding uncertainty.**

Or:

> **Container security prioritization and remediation for teams that already use Trivy.**

The third positioning is probably strongest because it complements existing tools instead of competing with them.

# 12. Where your product can differentiate

Do not compete on:

- Number of CVEs
- Number of scanners
- Number of LLM agents
- Number of dashboards
- Number of Terraform modules

Compete on:

## 1. Better prioritization

Combine:

```text
CVSS
+ EPSS
+ CISA KEV
+ package reachability
+ internet exposure
+ fix availability
+ image usage
+ exploit path
```

## 2. Better remediation

Provide:

```text
exact Dockerfile patch
→ rebuild
→ rescan
→ smoke test
→ verified result
```

## 3. Better context

Explain:

```text
This vulnerability exists because of layer 7,
is inherited from the base image,
is reachable by the production entrypoint,
has a fix available,
and affects an internet-facing service.
```

## 4. Better uncertainty handling

Show:

```text
Complete
Degraded
Scanner failed
Partially analysed
Not enough evidence
```

This can become your strongest differentiator.

## 5. Better developer workflow

Provide:

- GitHub Action
- PR comments
- SARIF
- One-click fix branch
- Scan diff
- Policy checks
- Suppression with expiry
- Slack/Jira integration
- CLI
- IDE integration

# 13. Recommended product architecture

A stronger future architecture would look like this:

```text
                   ┌────────────────────┐
                   │ GitHub Action / CLI│
                   └─────────┬──────────┘
                             │
                             ▼
                   ┌────────────────────┐
                   │ Hosted API         │
                   │ API keys/OIDC      │
                   └─────────┬──────────┘
                             │
                             ▼
                   ┌────────────────────┐
                   │ Scan orchestrator  │
                   └─────────┬──────────┘
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
    ┌───────────┐      ┌───────────┐      ┌───────────┐
    │ Syft/SBOM │      │ Trivy     │      │ Dockle    │
    │ packages  │      │ CVE/secret│      │ Docker CIS│
    └───────────┘      └───────────┘      └───────────┘
          │                  │                  │
          └──────────────────┼──────────────────┘
                             ▼
                   ┌────────────────────┐
                   │ Normalized evidence│
                   │ dedup/fingerprints │
                   └─────────┬──────────┘
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
    ┌────────────┐     ┌────────────┐     ┌────────────┐
    │ Policy     │     │ Risk       │     │ AI         │
    │ engine     │     │ enrichment │     │ explanation│
    └────────────┘     └────────────┘     └────────────┘
          │                  │                  │
          └──────────────────┼──────────────────┘
                             ▼
                   ┌────────────────────┐
                   │ SARIF/SBOM/JSON    │
                   │ PR comment/report  │
                   │ exit code           │
                   └────────────────────┘
```

The key design rule:

> **The policy engine decides whether the build passes. The LLM explains the decision.**

# 14. Practical roadmap based on competitor lessons

## First 30 days: adoption foundation

- Standalone CLI
- Docker image distribution
- Public demo
- SARIF output
- JSON output
- CycloneDX SBOM
- Stable finding IDs
- Image digest tracking
- GitHub Action
- Clear README quick start
- Sample GitHub workflow
- No mandatory AWS setup

## Days 31–60: trust and workflow

- Deterministic secret extraction
- Scanner severity preservation
- EPSS/KEV enrichment
- Prompt-injection tests
- False-clean detection
- Policy files
- Exit codes
- Suppression workflow
- Scan diff
- PR comments
- API keys/service accounts

## Days 61–90: product foundation

- Hosted API
- Organization/team model
- Registry integrations
- Scheduled rescans
- Audit logs
- Usage/cost limits
- Notifications
- Stable HTTPS deployment
- Monitoring and alerts
- Data retention
- Private worker option

## After 90 days: differentiation

- Registry-backed base-image recommendations
- Reachability analysis
- Verified Dockerfile fixes
- Multi-scanner consensus
- MCP integration
- Jira/Slack integrations
- Kubernetes admission policy
- EOL and license intelligence

# Final recommendation

The best strategic move is to position the product as:

> **An evidence-backed Docker security decision engine that works with Trivy, Grype, Syft, and Dockle—and makes their output understandable and actionable for developers.**

Do not replace those tools. Orchestrate and improve their usability.

Your winning workflow should be:

```text
Build image
→ scan with trusted deterministic tools
→ normalize and preserve evidence
→ prioritize with real security data
→ explain with AI
→ generate a verified remediation
→ rescan
→ post SARIF and PR feedback
→ enforce policy
```

If you achieve that, you will have a product with a clear reason to exist. If you remain primarily a six-agent dashboard around one Trivy scan, users will likely compare it directly with mature tools and ask why they should add another layer.