# Backend Security & Quality Audit

**Scope:** `worker/` (scanning, agents, reporting, API) and `terraform/`
**Method:** static review of the full backend, with every headline claim re-verified against the source
**Status:** Phases 0, 1 and 2A landed — see §10-§12. Phase 2B and 3-5 outstanding.

---

## 1. Executive summary

This is a well-built codebase. Base images are digest-pinned, containers run non-root, the
upload path handles traversal correctly, environment variable *names* reach the model while
their *values* never do, object authz returns 404-not-403, `iam:PassRole` is scoped with a
`PassedToService` condition, the SQS redrive policy is correct, and the whole system is
designed around an explicit principle that failure must stay visible rather than silently
scoring clean. The README already discloses three limitations honestly, which is rarer than
it should be.

The problems found here are a different class. Three of them matter more than everything
else combined.

### 1.1 An attacker who builds the image can get a clean bill of health

Everything the model reads — Dockerfile lines recovered from layer history, package names,
environment variable names, entrypoints — is controlled by whoever built the image being
scanned. None of it is marked as data rather than instructions. The guards that exist check
only that the model did not *invent* a CVE ID. Nothing checks that it did not *omit* one.

A model persuaded to return `{"findings": []}` produces `status="analysed"`, which the
pipeline classifies as trustworthy. The scan is not marked degraded. It scores clean.

For a security scanner this is the only defect class that makes the product actively harmful
rather than merely incomplete. A missing feature leaves the user where they started; a false
clean tells them they are safe.

### 1.2 The report has had its machine-readable data stripped out

The pipeline computes package name, installed version, fixed version, CVSS score and severity
for every vulnerability — then discards all of it. What reaches storage is a CVE ID plus four
fields of model-written prose.

There is no SARIF, no SBOM, no CSV, no CI gate, no scan-to-scan diff, and no policy engine.
The 0-100 risk score users will treat as authoritative is a number an LLM chose, with no
formula and no reproducibility.

The data is not missing. It is in memory at the moment it is thrown away.

### 1.3 There is no detective control anywhere in the infrastructure

No CloudTrail, no GuardDuty, no VPC flow logs, no alarms, no SNS topic, no budget — and no
application instrumentation of any kind: no metrics, no traces, no structured logs, no
correlation IDs.

The gap between the quality of the IAM reasoning in this repo and the total absence of
detection is the most striking thing in the audit. Every failure mode documented below is
currently invisible in production. The DLQ will fill in silence. The fail-open rate limiter
will spend the OpenAI budget in silence. A degraded scan looks exactly like a clean one on
every dashboard, because there are no dashboards.

---

## 2. Methodology and scope

**Read in full:** all of `worker/app/` (scanners, processors, agents, queue, storage, API,
core, progress, models, config), `worker/eval/`, all 14 test modules, `worker/Dockerfile`,
`docker-compose.yml`, `.github/workflows/ci.yml`, and all 39 files of `terraform/` (root plus
11 modules).

**Verified first-hand** — re-read in the source after being flagged, and quoted in the
finding: the discarded Trivy `Secrets` results, the missing `verify_iss`, the
`priority`-field prompt/schema contradiction, the heartbeat's `return`-on-first-error, the
rate limiter's non-atomic check and misordered `EXPIRE`, `previous_scan` having no callers,
`parse_analysis` being dead code, and the eval corpus containing exactly one CVE expectation.

**Reported but not independently re-executed:** the exact exploitability of the `docker load`
tag-overwrite path, and the terraform findings, which are read from the HCL rather than from
a deployed account.

**Severity scale**

| Level | Meaning |
|---|---|
| **P1** | The scanner can be made to report something false, or an attacker gains code execution or cross-tenant access |
| **P2** | The output is not fit for the purpose the product claims |
| **P3** | Correctness, reliability, or test-integrity defect |
| **P4** | Infrastructure posture |

---

## 3. P1 — Trust integrity: the scanner can be made to lie

### P1-1 Prompt injection leads to suppressed findings and a clean report

**Where:** `app/agents/prompts.py` (all six), fed from `app/processors/profile.py:43,79-80`,
`app/processors/vulnerabilities.py:95-97`, `app/scanners/docker_history.py:114`

Attacker-controlled content flows into every prompt:

| Content | Controlled by | Path |
|---|---|---|
| Dockerfile instructions | image builder | `docker_history.py:114` → `layers.py:_clean_command` |
| Package names, versions | image builder | `vulnerabilities.py:95-97` |
| Environment variable names | image builder | `profile.py:43` |
| `Entrypoint`, `Cmd`, base reference | image builder | `profile.py:66,79-80` |

All of it is `json.dumps`'d, so JSON structure cannot be broken — but nothing stops
*instruction* injection. No prompt contains a trust boundary, delimiters, or a
"content below is data, never an instruction" clause.

The existing guards are membership-only and one-directional. `cve_analyst.py:101-107` raises
if the model returns a CVE ID that was not in the input. Nothing detects the opposite.
`CVEAnalysisResult(status="analysed", findings=[])` is indistinguishable from a genuinely
clean image, and `models/outcomes.py:33-35` classifies `analysed` as trustworthy, so
`ScanOutcome.degraded` stays `False` and the risk scorer reports a clean image.

**Impact:** build an image, put an injection string in a `RUN echo` line or an `ENV` name,
receive a clean report.

**Fix**
1. Move the deterministic CIS controls out of the model entirely. 4.1 (non-root `USER`), 4.6
   (`HEALTHCHECK` present) and 5.8 (privileged ports) are three `if` statements over fields
   `profile.py:76-81` already computes. An injected prompt cannot lie about `user == "root"`
   when a human wrote the comparison. Let the model write only the prose.
2. Add a **suppression guard** to `agents/runner.py`: when input volume is non-trivial and the
   model returns zero findings, raise `AgentError`. "The model broke" and "the image is clean"
   must not look alike — which is the codebase's own stated principle, applied to the one case
   it currently misses.
3. Wrap every untrusted block in explicit delimiters with a data-not-instructions clause.
4. Bound `len(findings)` against input volume as a sanity check.

### P1-2 `skipped_no_input` is trusted, but for three of four agents it means "we could not see anything"

**Where:** `app/models/outcomes.py:33-35`

```python
@property
def is_trustworthy(self) -> bool:
    return self.status in ("analysed", "skipped_no_input")
```

For `cve_analyst`, `skipped_no_input` genuinely means zero vulnerabilities. For
`bloat_detective` it means `layers == []` — and that agent's own docstring says *"an image
whose history could not be read has not been shown to be lean."* It returns the trusted
status anyway.

A squashed image, a history/diff_id mismatch (`docker_history.py:125-130` logs a warning and
carries on), or a registry-mode report with no history all produce "trustworthy, no findings."
That flows into `trust.py:21` so the Dockerfile optimizer runs on it, and into `trust.py:52-54`
so confidence reads 1.0.

**Fix:** split the status — `skipped_no_input` (nothing to analyse, trustworthy) versus
`skipped_missing_input` (input unavailable, not trustworthy) — and return the latter from
`bloat_detective`.

### P1-3 Model-assigned severity is never reconciled against scanner severity

**Where:** `app/models/findings.py:24`, guard at `app/agents/cve_analyst.py:99-107`

`CVEFinding.severity` is whatever the model emitted. The guard validates the CVE *id* only.
Nothing asserts the model's severity matches Trivy's normalised severity for that same CVE —
even though `RawVulnerability.severity` holds exactly that answer, for exactly that CVE, in
memory, at that moment.

A model can downgrade a CRITICAL to `low` and the pipeline accepts it silently.

**Fix:** in the guard, compare each finding's severity against the scanner's for the same ID.
Keep both as `severity` and `scanner_severity` where they differ, and treat the disagreement
itself as a reportable signal.

### P1-4 `docker load` of a tenant tar poisons the shared daemon, across tenants

**Where:** `app/images.py:166-190`, marker regex at `app/images.py:32`

A `docker save` archive carries its own `RepoTags`. `docker load` applies **all** of them,
while `_LOADED.search` reads only the first `Loaded image:` line. There is no content
inspection and no per-tenant daemon; the only gate is a client-supplied `.tar` suffix
(`images.py:115`) and a 2 GiB cap.

Tenant A uploads an archive tagged `python:3.12-slim`. The daemon's real `python:3.12-slim` is
overwritten. Every subsequent socket-mode scan of that tag — including other tenants' —
analyses the attacker's image. The API container shares the same socket.

**Fix:** stop using `docker load`. `trivy image --input <path>` scans the archive directly,
needs no daemon, and cannot mutate shared state. If load must stay, reject any archive
declaring more than one `RepoTag` and `docker rmi` in a `finally`.

### P1-5 Argument injection through an unvalidated `target`

**Where:** `app/api/models.py:8`; reaches `scanners/trivy.py:41,61`,
`scanners/docker_history.py:58,65,156`, `scanners/image_inspect.py:48`

```python
target: str = Field(min_length=1, max_length=300)
```

That is the entire validation. No image-reference grammar is enforced anywhere in the
codebase. The string flows through SQS to `trivy image … <target>`, `docker pull <target>`,
and `docker image inspect <target>`.

`create_subprocess_exec` means there is no *shell* injection. But there is no `--` separator,
and both cobra (docker) and Trivy parse flags positionally-anywhere. A target beginning with
`-` is read as a flag: `--server https://attacker/` points Trivy at an attacker-controlled
server. In socket mode the docker CLI holds the host daemon socket.

**Fix:** two lines. An OCI-reference regex at `api/models.py` with an explicit `upload://`
branch, and `"--"` inserted before `target` in every argv listed above.

### P1-6 The JWT issuer is never verified, and the defaults fail open

**Where:** `app/core/auth.py:100-106`, `app/config/api.py:5-10`, `app/api/main.py:48-54`

```python
claims = jwt.decode(
    token,
    jwk_construct(key),
    algorithms=["RS256"],
    audience=TOKEN_AUDIENCE,
    options={"verify_exp": True, "verify_aud": True},
)
```

No `issuer=`, no `verify_iss`. python-jose skips the check entirely when no issuer is supplied.

On its own that is a hardening gap. Combined with the defaults it is a bypass:
`config/api.py` defaults `JWKS_URL` to `http://localhost:8080/dev/.well-known/jwks.json` and
`TOKEN_AUDIENCE` to `"local-client-id"`. A deployment that forgets one environment variable
**does not fail** — it silently accepts tokens minted by the local dev issuer, and
`/dev/token` hands those out to any unauthenticated caller for any `tenant_id`.

The CI smoke test at `ci.yml:451` asserts `/dev/token` returns 404, which is the right
instinct — but it catches `DEV_AUTH=1`, not a mis-set `JWKS_URL`.

**Fix:** pass `issuer=TOKEN_ISSUER` with `"verify_iss": True`, and fail fast at import when
`DEV_AUTH` is on or `JWKS_URL` still holds the localhost default outside a local run.

**Verified sound, for the record:** `alg: none` and HS256 key-confusion are correctly blocked
by the `algorithms=["RS256"]` allowlist, and `tests/test_api.py:57` covers it.

---

## 4. P2 — The report is not a security report

### P2-1 Machine-readable data is stripped before storage

**Where:** `app/models/findings.py:21-66` versus `app/processors/vulnerabilities.py:33-41`

`RawVulnerability` carries `package`, `installed_version`, `fixed_version`, `cvss_score`,
`severity`, `target`. `CVEFinding` carries **none of them** — only `vulnerability_id` plus
`severity`, `title`, `impact`, `fix`, `effort`, `priority`, `exploitability`. And
`model_config = ConfigDict(extra="forbid")` means provenance cannot even be added without a
schema change.

| Field a security report needs | Present | Note |
|---|---|---|
| CVSS score | No | computed at `vulnerabilities.py:56-74`, then dropped |
| CVSS vector | No | `_extract_cvss` reads only `V3Score`, never `V3Vector` |
| CWE | No | Trivy's `CweIDs` never read |
| Package name | No | on `RawVulnerability`, dropped at the finding |
| Installed / fixed version | No | same — the only remediation is model prose |
| Layer attribution for CVEs | No | only `BloatFinding.layer_index` exists |
| References / `PrimaryURL` | No | discarded |
| EPSS / CISA KEV | No | `exploitability` (`findings.py:13-18`) is a model guess |
| Per-finding confidence | No | one scan-wide number measuring *pipeline health* |
| Scanner provenance, Trivy DB version | No | `AgentOutcome.agent` names the agent, not the scanner |

**Fix:** add those fields to `CVEFinding` and populate them **deterministically from
`RawVulnerability` after the model returns**, keyed on `vulnerability_id`. Never ask the model
for a fact the scanner already knows.

### P2-2 Trivy's secret findings are collected and thrown away

**Where:** `app/config/scanning.py:19`, `app/processors/vulnerabilities.py:88-105`

```python
TRIVY_SCANNERS = "vuln,secret"
```

The only consumer of the report is:

```python
for result in trivy_data.get("Results") or []:
    target = result.get("Target", "")
    for entry in result.get("Vulnerabilities") or []:
```

Trivy puts secret hits in `result["Secrets"]`, never `result["Vulnerabilities"]`.
`grep -rn "Secrets" worker/app/` returns **zero hits**.

A hardcoded AWS key baked into a layer is found by Trivy, parsed into memory, and dropped on
the floor. It is not in the report, not in any count, and no agent ever sees it. Meanwhile the
compliance agent is asked to *guess* at secrets from environment variable names
(`prompts.py:150-152`) while the real detection sits unread in the same dict.

**Fix:** add `extract_secrets(trivy_data)` reading `result["Secrets"]` (`RuleID`, `Category`,
`Title`, `Severity`, `StartLine`, `Match`), redact `Match` before it reaches a prompt or a
blob, and emit deterministic `SecretFinding` objects with no model in the loop. Largest single
coverage win available, for roughly 30 lines.

### P2-3 The truncation is silent and unrecoverable

**Where:** `app/processors/vulnerabilities.py:110-128`, `app/config/scanning.py:25`,
`app/storage/results.py:65-76`, `app/orchestrator.py:41-46`

`prioritise()` sorts by `(severity, -cvss, id)` and slices to 150. That part is deterministic
and correct. What follows is not: `store_result` persists only `outcomes`, `dockerfile`,
`risk` and `profile`. The raw Trivy report, the full `RawVulnerability` list, and the
prioritised slice are **never stored**.

- A 900-CVE image reports on 150. The other 750 are unrecoverable — not in the blob, not in
  DynamoDB, nowhere.
- `CVEAnalysisResult.vulnerabilities_examined` exists at `cve_analyst.py:19`, but `_timed()`
  builds `AgentOutcome` without it, so even the sample size is discarded before storage.
- No dedup: `extract_vulnerabilities` appends per `(Result, entry)` with no `(id, package)`
  collapsing. A Java image where 40 jars are flagged for one CVE burns 40 of the 150 slots on
  one issue.
- `fixed_version` is not in the sort key, so unfixable criticals crowd out actionable highs.

The README discloses the sampling. It does not disclose that the dropped data is gone.

**Fix:** persist scanner ground truth — `total_vulnerabilities`, `analysed_count`,
`dropped_count`, `counts_by_severity`, Trivy DB version, scan timestamp. Dedup on
`(id, package, installed_version)`. Add `bool(fixed_version)` to the sort key ahead of CVSS.

### P2-4 The scan counts are model opinion, not measurement

**Where:** `app/storage/results.py:44-51`

`finding_count`, `critical_count` and `high_count` are computed from `scan.all_findings` — that
is, from whatever the model chose to write up, using **model-assigned severities**. If the
model returns 4 findings for a 400-CVE image, `critical_count` is whatever those 4 say.

These are surfaced as scan metrics. They are not scanner measurements.

**Fix:** drive them from the Trivy counts persisted in P2-3, and keep the model's count as a
separate, clearly-labelled number.

### P2-5 No export, no CI gate, no diff

Grep across the repo for `sarif|cyclonedx|spdx|sbom|junit|csv|export` returns zero hits.

- **No SARIF, no SBOM, no CSV, no PDF.** The only consumer surface is
  `GET /api/v1/scans/{job_id}/report` returning the raw dict.
- **No CI gate is possible.** There is no CLI entrypoint — `pyproject.toml:25` declares
  `worker = "worker:main"`, which points at `src/worker/__init__.py`, an empty uv-init stub.
  No exit codes, no `--fail-on-severity`, no policy thresholds. Nothing here can fail a build.
- **`previous_scan()` is dead code.** Fully implemented at `results.py:139-164`, tested at
  `test_storage.py:81`, and *verified* called by nothing in the codebase. There is no
  new/fixed/persisting classification anywhere.
- **A differ is not currently possible.** Findings have no stable identity — no fingerprint
  over `(cve, package, layer)` — and the text is model-generated, so two scans of the same
  image cannot be joined.

**Fix:** add a `fingerprint` to `BaseFinding` (`sha256` over category, identifier, package,
layer). Then wire up the already-written `previous_scan` into a diff in `store_result`, add
SARIF 2.1.0 and CycloneDX exports, and give the CLI real exit codes.

### P2-6 The risk score is a model opinion, and "degraded" does not affect it

**Where:** `app/agents/risk_scorer.py:39-46`, `app/agents/prompts.py:219-249`

The four 0-100 scores come entirely from one model call. `prompts.py` gives only prose
guidance ("security carries the heaviest weight", "be willing to give low scores"). There is
no formula, no `seed`, and `temperature=0` on gpt-4o is not deterministic. Two runs over
identical cached scanner output produce different scores — and the eval harness compares
against expectations, so the gate measures a moving target.

**Degraded does nothing to the score.** `ScanOutcome.degraded` and `ScoredRisk.confidence` are
stored *beside* the score and never applied *to* it. With `bloat_detective` and
`compliance_checker` both failed, the model is handed "findings from 2 of 4 agents" and will
return `compliance: 85` on zero compliance evidence. Absence of findings reads as absence of
problems, and `overall` is then displayed at full weight next to a confidence most UIs render
as a footnote.

**Fix:** compute the four sub-scores in Python from finding counts × severity weights ×
priority — roughly 15 lines, and the thing users will actually diff across scans. Let the model
write only `summary` and `top_priorities`. Return `None` for a sub-score whose input agent is
untrustworthy rather than a number, and clamp `overall` instead of reporting it at full weight.

### P2-7 No policy engine

No allowlist, no `.trivyignore` (`--ignorefile` is never passed), no VEX or OpenVEX ingestion,
no suppression, no per-tenant exception config, no expiry-dated waivers, no false-positive
workflow, and no `accepted_risk` field on any model.

The 150 cap is itself an undisclosed policy — the most consequential filtering decision in the
system, with no user control.

### P2-8 What the scanner never collects at all

Confirmed absent: SBOM (CycloneDX/SPDX), misconfiguration/IaC scanning (`--scanners misconfig`),
license compliance, malware, image signing / provenance / attestation verification, VEX,
severity thresholds, `--exit-code` gating, EPSS scores, the CISA KEV catalog, and any registry
lookup for base-image freshness.

That last one is the README's own known-limitation #2: `base_image_strategist` performs no
registry lookup and recommends from model memory. It is addressed in §7.2.

> **Correction (Phase 2B).** This section originally wrote the scanner value as `config`.
> Trivy's allowed values are `vuln,misconfig,secret,license` — `config` is not one of them, so
> the flag as written would have failed rather than scanned. Corrected throughout.

**On the Trivy invocation itself** (`scanners/trivy.py:22-62`):

```
trivy image --format json --quiet --scanners vuln,secret --timeout 10m <target>
```

Omitted: `--scanners misconfig`, `--scanners license`, `--severity`, `--ignore-unfixed`,
`--exit-code`, `--ignorefile`, `--db-repository` (mirror fallback), `--offline-scan`,
`--platform`, `--format cyclonedx`, and the `--` separator. DB update handling: none — every
scan does an implicit refresh from GHCR, and on Fargate `TRIVY_CACHE_DIR=/tmp/trivy-cache`
(`Dockerfile:83`) is ephemeral, so every cold task re-downloads it.

---

## 5. P3 — Correctness, reliability and QA

### P3-1 Every Trivy failure is marked permanent, so the job is deleted and never retried

**Where:** `app/scanners/trivy.py:97-105` → `app/orchestrator.py:260` → `app/queue/consumer.py:110-119`

```python
if process.returncode != 0:
    raise TrivyScanError(f"Trivy exited {process.returncode}: ...", permanent=True)
```

`permanent` becomes `PermanentFailure`, which the consumer treats as final and **deletes the
message**. A GHCR rate-limit on the vuln-DB pull, a registry 5xx, a network blip, an OOM-killed
Trivy, or transient ECR auth all produce a job that is failed, un-retried, and never reaches
the DLQ.

Combined with the ephemeral Fargate cache, this is the *expected* failure mode under load, not
an edge case. The `ponytail:` comment at `trivy.py:98-101` names the risk and ships it anyway.

**Fix:** classify. `permanent=True` only when exit code is 2 or stderr matches
unknown-manifest / not-found / unauthorized. Everything else stays retryable. Pre-warm the DB
and pass `--db-repository` with a mirror.

### P3-2 The heartbeat gives up permanently after one error, causing duplicate concurrent scans

**Where:** `app/queue/consumer.py:30-45`, `app/queue/handler.py:10-45`

```python
except Exception as exc:
    logger.warning("Heartbeat failed: %s", exc)
    return
```

One throttle or one transient error and the heartbeat is dead for the rest of the scan.
Visibility is 300s while a scan can legitimately run 600s (Trivy) plus six agents at 120s each,
so visibility expiry mid-scan is routine once the heartbeat dies.

On redelivery, `handler.py` cannot distinguish "a live worker is still running this" from "a
dead worker abandoned it" — a job in state `running` looks the same either way — and it
reprocesses regardless. Two workers scan the same image simultaneously: double LLM spend,
racing `update_progress` writes, racing `store_result` puts, and interleaved WebSocket progress
events jumping backwards.

**Fix:** `continue` with a bounded failure count instead of `return`, and make the claim a real
lease — add `lease_expires_at` to `JobRecord`, let `claim_job` also succeed when
`status = running AND lease_expires_at < now`, and refresh it from the same heartbeat. That
answers the question `handler.py` is currently guessing at.

### P3-3 The rate limiter fails open, is non-atomic, and leaks keys

**Where:** `app/core/ratelimit.py:52-86`. All three verified.

**Fails open.** On any Redis error the limiter logs a warning and allows the request. This is
on the one route that spends unbounded LLM money. The comment defends it as "a broken rate
limiter costs money" — the tradeoff is inverted. Fail-open is what *causes* the cost.

**Non-atomic.** `zremrangebyscore` / `zcard` / `expire` run in a pipeline, then `zadd` runs
*separately*. N concurrent requests all observe `count < limit` and all commit. The test at
`test_api.py:171-181` is a sequential list comprehension and structurally cannot catch it.

**Leaks keys.** `expire` is issued at `:65`, before the first `zadd` at `:81`. On a brand-new
key that EXPIRE is a no-op against a nonexistent key, so every tenant who makes exactly one
request leaves an immortal sorted set in Redis.

**Fix:** a single Lua script for atomicity; move `expire` after `zadd`; fail **closed** with 503
on `POST /scans` and `/images/upload`, keeping fail-open only for read routes.

### P3-4 All six prompts demand a `priority` field two schemas forbid

**Where:** `app/agents/prompts.py:37,93,134,177,216,248` versus `app/models/findings.py:29`

Every prompt ends with:

> Every field shown above is required on every object; priority is an integer from 1 to 100.

`priority` exists only on `BaseFinding`. `RiskScore` and `DockerfileOptimization` have no such
field, and both are `extra="forbid"`. A model that *obeys* the instruction emits `priority` and
is hard-rejected by `parse_structured` with no retry.

A copy-paste bug that surfaces as a random-seeming agent failure.

**Fix:** delete that sentence from the two prompts whose schemas forbid the field.

### P3-5 No retry on malformed model output, and the retry budget is fiction

**Where:** `app/agents/runner.py:41-75,91`, `app/config/scanning.py:38-41`, `app/orchestrator.py:122`

`parse_structured` raises `AgentError` on bad JSON, schema violation, or guard failure. There
is **no re-ask**. `MODEL_MAX_RETRIES = 6` is the OpenAI SDK's *HTTP* retry — it covers 429 and
5xx, never a 200 containing bad JSON. So one schema slip degrades the agent, which makes
`scan.degraded` true, which makes `dockerfile_optimizer` refuse to run, which lowers
confidence — all over a recoverable formatting error.

The timeouts also contradict each other: `CVE_TIMEOUT_SECONDS = 90` per HTTP call, up to 6 SDK
retries, all wrapped in `asyncio.wait_for(timeout=AGENT_TIMEOUT_SECONDS=120)`. The agent
timeout fires during the second retry at the latest, so retries 3-6 are unreachable.

**Fix:** one re-ask on `AgentError` with the validation error appended to the user message —
that recovers the large majority of schema slips. Then either raise `AGENT_TIMEOUT_SECONDS` to
match the retry budget or drop `MODEL_MAX_RETRIES` to 2 so the config stops lying.

### P3-6 Dead code is what the hallucination-guard tests actually test

**Where:** `app/agents/cve_analyst.py:26-79`, `tests/test_cve_analyst.py`

`parse_analysis` and `_build_messages` are unreachable from production — `run_cve_analyst` uses
`run_structured_agent` with the inline `guard` closure at `:101-107`. But **all seven** tests in
`test_cve_analyst.py` exercise `parse_analysis`.

The production guard has zero direct test coverage. The two implementations are equivalent
today; nothing keeps them so. And the README cites this guard as one of the things verified
sound.

**Fix:** delete the dead pair and repoint the tests at the production path.

### P3-7 The eval gate barely measures the headline feature

**Where:** `worker/eval/expectations/bad.yaml`, `worker/tests/test_eval_gate.py`, `worker/eval/metrics.py`

The corpus is 12 expectations across two synthetic fixture images:

| Agent | Expectations |
|---|---|
| `compliance_checker` | 7 |
| `bloat_detective` | 3 |
| `base_image_strategist` | 1 |
| **`cve_analyst`** | **1** |

`MIN_RECALL = 0.90` over 12 items means one miss (0.917) passes. The CVE agent — the product's
headline feature — is effectively unmeasured.

Separately, `StabilityReport` in `eval/metrics.py` computes `score_stdev`, `score_range` and
`mean_jaccard`, and `test_eval_gate.py` asserts **none** of them. Stability is measured and
never gated — which matters directly, because P2-6 shows the score is non-deterministic.

**Fix:** grow the CVE expectations, add a small real-world image corpus alongside the synthetic
fixtures, gate the stability metrics that already exist, and add a prompt-injection fixture as
the regression test for P1-1.

### P3-8 Test coverage gaps

**Modules with zero direct tests:** `core/auth.py` internals, `core/ratelimit.py` failure modes,
`api/deps.py`, `storage/blobs.py` (the S3 branch never executes anywhere in the suite),
`storage/client.py`, `storage/serialization.py`, `config/*`, `api/main.py`, and **five of six
agents plus the shared runner** — only `cve_analyst` has parse/validation tests, and those test
dead code (P3-6).

**Security properties with no test:** expired token; wrong audience; foreign issuer (it would
pass today — P1-6); unknown-`kid` rotation, despite `_find_key` existing specifically for it;
JWKS unreachable (currently a 500, not a 401/503); concurrent rate-limit bypass; Redis-down
fail-open; `/report` cross-tenant; and `GET /scans/jobs/{job_id}` cross-tenant — which is the
one authz check that does *not* route through `owned_scan` (`scans.py:72-74`), making it both
the divergent path and the unguarded one.

**No test asserts what a stored report contains.** `test_storage.py:69-79` stores a scan with
`findings=[]` and asserts only `report["job_id"]`. A regression that dropped `severity` from
every finding in the blob would pass the entire suite.

**Injection/fuzzing:** nothing sends a `target` containing a leading `-`, a newline, or
non-ASCII; no oversized or deeply-nested JSON body test.

**Flakiness:** three bare `asyncio.sleep(0.2)` sync points (`test_progress.py:33,60,84`); a real
uvicorn bound to a hardcoded `127.0.0.1:8080` (`conftest.py:35-60`); `pytest.raises(Exception)`
with `noqa: B017`, which passes on any failure including an import error; `integration` and
`eval` markers unregistered in `pyproject.toml`, so every run emits warnings; and no coverage
tooling configured at all.

### P3-9 Async and resource hygiene

- **Blocking boto3 on the event loop:** `consumer.py:75` (a 20-second synchronous block),
  `:103`, `:116`, `:34` (inside the heartbeat task), and `orchestrator.py:197`.
  `change_message_visibility` blocking the loop stalls the four concurrent agent calls.
- **Blocking file I/O in a coroutine:** `images.py:136` — a 2 GB upload blocks the entire
  uvicorn event loop in 1 MB bursts, stalling every other request including WebSocket
  keepalives.
- **Orphaned coroutines:** `orchestrator.py:87-91,233-237` use `asyncio.gather` with default
  `return_exceptions=False`. When one scanner raises, the other two are not cancelled and run to
  completion unawaited. With `asyncio.shield` at `trivy.py:140`, a cancelled caller still leaves
  the Trivy subprocess running.
- **One Redis connection pool per WebSocket:** `ws.py:80` → `redis_bus.py:19`, with no cap and no
  rate limit on the route. An authenticated tenant opening many sockets exhausts Redis
  `maxclients` and takes down progress for everyone.
- **Loaded images are never removed:** `images.py:170-173` unlinks the tar but never
  `docker rmi`s the image. Orphaned tars are never swept either — an upload whose scan never
  runs leaves the file permanently.
- **`boto3.resource` rebuilt on every call:** `client.py:36-38`, twice per `GET /report`.

### P3-10 Other findings

| Issue | Where | Note |
|---|---|---|
| No TTL on `scan_results` | `scripts/create_tables.py:64-85` | TTL is set only on the jobs table. Vulnerability findings and their blobs are retained forever — a retention/GDPR gap and unbounded cost |
| Path traversal reachable in blob storage | `storage/results.py:65` → `storage/blobs.py:15-21` | No validation, while `images.py:39-44` has a correct `_SAFE_SEGMENT` guard it does not reuse. With `DEV_AUTH=1`, `/dev/token?tenant_id=../../..` mints a token whose `sub` escapes `BLOB_DIR` |
| `GET /api/v1/images` is not tenant-scoped | `api/images.py:26-41` | Lists every image on the shared daemon, including other tenants' uploads. Acknowledged in the docstring; the mitigation is a comment, not a control |
| Bearer token in the WebSocket query string | `api/ws.py:43` | Lands in access logs, browser history and `Referer`. Authz is also checked once at connect, so a revoked token keeps streaming |
| Uploads broken in the deployed topology | `images.py:55` vs `blobs.py:30` | Uploads always use local `BLOB_DIR` while reports switch to S3. On Fargate the API and worker are separate tasks with no shared mount, so the worker cannot find the file the API wrote |
| Jobs orphaned in permanent `running` | `storage/jobs.py`, `api/scans.py:61-83` | No reaper and no staleness check, so a DLQ'd job shows "in progress" for the full 30-day TTL |
| Poison message aborts the poll cycle | `queue/consumer.py:86` | The body is parsed *outside* the try at `:96`. Self-heals via `maxReceiveCount=3`, but burns three cycles |
| Non-atomic blob write | `storage/blobs.py:31` | A crash mid-write leaves truncated JSON, which surfaces as a 500 rather than the intended 404 |
| CORS origins unvalidated | `api/main.py:15-21` | `allow_credentials=True` with unstripped `.split(",")` values |
| Unbounded forced JWKS refresh | `core/auth.py:59-80` | Every unknown `kid` forces a live fetch with no negative cache and no rate limit — unauthenticated amplification against the IdP |
| Socket and registry modes disagree | `processors/layers.py:85` | `is_empty` is derived differently, so the two modes produce different bloat findings for the same image. Registry mode is correct; one of the two is untested |
| `UNKNOWN` severity is deprioritised | `processors/vulnerabilities.py:28` | Trivy emits `UNKNOWN` for genuinely unscored-but-real CVEs; mapping it to `informational` sorts it below `low` and makes it first to be dropped by the cap |
| `bloat_detective` bypasses the shared runner | `agents/bloat_detective.py:79-95` | Calls `build_client().ainvoke` directly with hand-rolled parsing, so every fix to the shared path — injection delimiters, retry, suppression guard — silently skips it |
| `_degrade` catches `BaseException` | `orchestrator.py:53` | A SIGTERM mid-scan is recorded as an agent *failure* in a stored report rather than aborting cleanly |

---

## 6. P4 — Infrastructure (terraform)

Read from the HCL, not from a deployed account.

### P4-1 CRITICAL — mutable `:latest` plus a branch-wildcard build role is an RCE chain

This is *not* the classic OIDC bug. The repo is pinned (`repo:owner/repo:`), a fork cannot
assume the role, and the **deploy** role is correctly `StringEquals` on an exact ref
(`cicd/main.tf:54-64`). The problem is the chain the build role enables:

| Link | Evidence |
|---|---|
| Build role assumable from any branch or PR | `cicd/main.tf:35-39` — `StringLike` on `repo:X:*` |
| Build role can `ecr:PutImage` to all three repos | `cicd/main.tf:81-92` |
| ECR tags are mutable | `ecr/main.tf:3,14,27` — `image_tag_mutability = "MUTABLE"` |
| **Task definitions run `:latest`** | `main.tf:99-101` |
| No repository policy restricting pushes | the ECR module has no `aws_ecr_repository_policy` |

Anyone with write access to a branch — a compromised contributor token, a malicious dependency
in a build step, a stale collaborator — pushes a branch, mints an OIDC token whose `sub`
matches `repo:X:*`, and overwrites `auditor-dev-worker:latest`. The deploy job won't pick it up
(it deploys the SHA tag, correctly), but the next `terraform apply` will, because the task
definition body is literally `:latest`. So does any task restart.

The attacker then holds the task role: `dynamodb:Query` on `TenantIndex` and `TenantRepoIndex`
across **every tenant** (`iam/main.tf:53-70`), read/write on the reports bucket, and — via the
execution role at `ecs/main.tf:89` — the OpenAI key.

**Fix, in order of value:** `image_tag_mutability = "IMMUTABLE"` (this alone breaks the chain);
stop referencing `:latest` in `main.tf:99-101` and pass the SHA tag CI already computes at
`ci.yml:320`; narrow the build trust to `refs/heads/main` and `pull_request` — `ci.yml:299-303`
already gates the build job to `main`, so the wildcard is buying nothing.

### P4-2 CRITICAL — the OpenAI key is written to Terraform state, and the state bucket is unmanaged

`secrets/main.tf:8-11` writes `var.llm_api_key` into state. `variables.tf:27-31` is admirably
honest about it:

> `sensitive` keeps it out of plan output, NOT out of state — which is why the state bucket is
> encrypted and private.

Except the state bucket is **not in this repo**. `versions.tf:4-7` is a deliberately empty
`backend "s3" {}`. The only encryption guarantee is `-backend-config="encrypt=true"` at
`ci.yml:234` — a CI flag, not infrastructure. Nothing versions the bucket, blocks public access,
enforces TLS, or applies object lock.

Worse: `tf-plan` runs on **`pull_request`** events (`ci.yml:206-244` has no `event_name` guard,
unlike the build job) with `TF_VAR_llm_api_key` set, producing a `tfplan` artifact containing
the key.

**Fix:** a bootstrap stack creating the state bucket with versioning, a CMK, a public access
block and a TLS-only policy. Gate `tf-plan` on `push`. Better still, create the secret
*container* in Terraform and set its value out-of-band so the key never enters state.

### P4-3 CRITICAL — unauthenticated, unencrypted Redis on a public IP

`ecs/main.tf:422-435` sets `assign_public_ip = true` — hardcoded, unlike the `local.public`
the other three services use. `ecs/main.tf:392-398` starts it with no `--requirepass`, no
`--tls-port`, no `--bind`.

The only control is the self-referencing security group, and `networking/main.tf:121-124` says
so outright:

> On the learning tier the tasks hold public IPs, so this rule is the only thing standing
> between Redis and the internet.

One ingress rule added for debugging, one `0.0.0.0/0` typo, and an unauthenticated attacker has
`FLUSHALL`, `CONFIG SET`, pub/sub injection into the progress channel, and `MONITOR` on every
scan in flight.

**Fix:** `--requirepass` from Secrets Manager at minimum. Properly: a private subnet with
`assign_public_ip = false`. It needs no public IP under any tier.

> **Fixed; see §15 — with two corrections to this entry.** The hardcoded `assign_public_ip` is
> unreachable-but-wrong rather than a live differential (the whole Redis task is
> `count = local.public ? 1 : 0`), and the private-subnet fix is not achievable on the learning
> tier, which has no private subnets, no NAT and no VPC endpoints — the task would fail to pull
> its image. Authentication is what closes this, on both paths.

### P4-4 HIGH

> **Partially fixed; see §16.** The IAM split, container hardening and state locking are landed,
> with three corrections to the text below — "everything runs as uid 0" is false, the line
> numbers are 243/253, and the "nothing can reach the API" aside is correct and belongs in the
> body. ALB/TLS/WAF, VPC endpoints + egress, and detective controls are deferred with costs
> recorded.

- **No ALB, no TLS, no WAF.** No `aws_lb`, `aws_acm_certificate` or `aws_wafv2_web_acl` anywhere.
  Cognito access tokens traverse the internet in cleartext; no request logging, which is often
  the only forensic record available; no rate limiting in front of an LLM-billed endpoint. Note
  that with the SG allowing ingress only from itself, nothing outside the VPC can reach the API
  at all — so the deployed reality likely differs from this code.
- **One task role shared by the worker and the API** (`main.tf:96-97`). The policy is the union:
  the API gets `s3:PutObject` and ECR pull it never needs; the worker gets `sqs:SendMessage`, an
  amplification primitive. The worker is the component that fetches and unpacks
  attacker-supplied images — the most likely thing here to be compromised — and when it is, the
  attacker inherits the API's permissions too. Separately, the **frontend's** execution role
  carries `secretsmanager:GetSecretValue` on the OpenAI key (`iam/main.tf:30-33`).
- **No container hardening on any task definition.** None of the four sets
  `readonlyRootFilesystem`, a non-root `user`, `cap_drop: ALL`, or `ulimits`. Everything runs
  as uid 0.
- **Egress wide open and zero VPC endpoints.** `networking/main.tf:114-119` allows all protocols
  to `0.0.0.0/0`, and there is no `aws_vpc_endpoint` for S3, DynamoDB, ECR, SQS, Secrets Manager
  or Logs. A compromised worker exfiltrates cross-tenant findings and the OpenAI key anywhere.
- **`AWS_TERRAFORM_ROLE_ARN` is referenced by CI but created nowhere** (`ci.yml:222`, with a
  `||` fallback to the deploy role). Either the plan fails, or someone hand-created a role
  outside Terraform — and the likely shape of that is `AdministratorAccess`, invisible to this
  audit and to drift detection.
- **The backend uses a removed argument.** `ci.yml:233` passes `dynamodb_table` while
  `TF_VERSION` is pinned to 1.14.5; that argument was deprecated in 1.11 and removed in 1.13.
  Locking either errors or is silently dropped — and state locking is an integrity control on a
  stack holding IAM roles and a secret.
- **Zero detective controls.** No CloudTrail, GuardDuty, VPC flow logs, CloudWatch alarms, SNS
  topic, or budget. The DLQ at `queue/main.tf:1-10` is correctly configured and will fill in
  total silence.

### P4-5 MEDIUM

No customer-managed KMS keys anywhere — DynamoDB, S3, SQS, Secrets Manager, ElastiCache and all
four log groups use AWS-managed defaults. None of it is *unencrypted*, so it passes a naive
scanner; what it lacks is a key-policy boundary and a revocation lever for what is, precisely, a
map of how to break into the customer.

Also: ~~no transit encryption or auth token on ElastiCache~~ (landed with P4-3, §15), and a
single cache node with no failover. `force_destroy = true` on the reports bucket with no `prevent_destroy` on any stateful
resource, no `deletion_protection_enabled` on either table, and no `deletion_protection` on the
Cognito user pool — PITR is on, which is good, but PITR does not survive table deletion and
there is no AWS Backup vault. Cognito has no MFA, no `advanced_security_mode`, and
`prevent_user_existence_errors` unset, which allows email enumeration against the customer list.
No TLS-only bucket or queue policies. ECR lifecycle reaps only untagged images, and there is no
Inspector enhanced scanning — *a vulnerability scanner whose own images are scanned once, ever.*
`containerInsights` disabled; log retention 14 days, 3 for Redis. And no environment separation:
a second apply with `environment = "prod"` fails on the account-global OIDC provider.

### P4-6 What this repo gets right

Worth recording, because an audit that lists only problems misrepresents the thing it audited,
and these are the parts worth not regressing:

`iam:PassRole` scoped to exactly two ARNs with a `PassedToService` condition — the single thing
most repos get wrong. Deploy trust as `StringEquals` on an exact ref. Execution role and task
role properly separated, with the reasoning documented at `iam/main.tf:12-14`. No
`dynamodb:Scan` or `DeleteItem` in the task policy, deliberately. `/index/*` present in the
resource list — the denial everyone debugs for an hour. S3 public access block complete, all
four flags. A DLQ with a `redrive_allow_policy` scoped to one source queue. TTL attribute
matched to what the application actually writes, and lifecycle rules matched to the
application's own TTL constant. PITR enabled on both tables. `github_repository` required, regex-
validated, and with no default.

---

## 7. Remediation plan

Ordered by damage prevented per unit of effort, not by severity label.

### Phase 0 — Stop the bleeding

Hours of work. Every item is a single-digit-line diff, and this phase has the highest ratio in
the plan.

| Fix | Where | Closes |
|---|---|---|
| `image_tag_mutability = "IMMUTABLE"` | `ecr/main.tf:3,14,27` | P4-1 (by itself) |
| Stop referencing `:latest`; pass the SHA tag CI computes | `main.tf:99-101` | P4-1 |
| Add `issuer=` and `"verify_iss": True` | `core/auth.py:100-106` | P1-6 |
| Fail fast when `DEV_AUTH=1` or `JWKS_URL` is the localhost default outside local | `config/api.py` | P1-6 |
| Insert `"--"` before `target` in every argv | `trivy.py:41,61`, `docker_history.py:58,65,156`, `image_inspect.py:48` | P1-5 |
| OCI-reference regex on `target` | `api/models.py:8` | P1-5 |
| Delete the `priority` sentence from the two prompts whose schemas forbid it | `prompts.py:216,248` | P3-4 |
| Move `expire` after `zadd` | `ratelimit.py:65→81` | P3-3 |
| `continue` with a bounded failure count instead of `return` | `consumer.py:30-45` | P3-2 |
| Narrow build-role trust to `refs/heads/main` and `pull_request` | `cicd/main.tf:35-39` | P4-1 |
| Gate `tf-plan` on `event_name == 'push'` | `ci.yml:206` | P4-2 |

### Phase 1 — Make the scanner honest

The class of defect that makes the product actively harmful. Nothing else in this plan matters
if the scanner can be talked into a clean report.

1. Move the deterministic CIS controls (4.1, 4.6, 5.8) out of the model into Python over
   `ImageProfile`.
2. Add the suppression guard to `agents/runner.py`.
3. Add trust-boundary delimiters and a data-not-instructions clause to every prompt.
4. Reconcile model severity against scanner severity in the CVE guard.
5. Split `skipped_no_input` from `skipped_missing_input`.
6. Replace `docker load` with `trivy image --input`.
7. Pin `TRIVY_IMAGE` by digest and add `--memory`, `--cpus`, `--pids-limit`, `--cap-drop=ALL`,
   `--security-opt=no-new-privileges`.
8. Convert `bloat_detective` to `run_structured_agent` so it stops bypassing all of the above.

### Phase 2 — Make the report a security report

The largest product win, and mostly the removal of a lossy step rather than new features — the
data already exists in memory at the moment it is discarded.

1. Carry `package`, `installed_version`, `fixed_version`, `cvss_score`, `cvss_vector`,
   `cwe_ids`, `references`, `layer_index`, `scanner_severity` and `source` onto `CVEFinding`,
   populated deterministically from `RawVulnerability` after the model returns.
2. Wire up `Results[].Secrets` into a `SecretFinding` category, with `Match` redacted.
3. Enrich with EPSS and the CISA KEV catalog — both free, both deterministic, and both precisely
   what `exploitability` should mean instead of a model guess.
4. Persist scanner ground truth: totals, counts by severity, analysed count, dropped count,
   Trivy DB version. Drive `critical_count` and `high_count` from these, not from findings.
5. Compute the four risk sub-scores deterministically in Python; leave the model only `summary`
   and `top_priorities`; return `None` for a sub-score whose input agent is untrustworthy.
6. Add a stable `fingerprint` to `BaseFinding`.
7. Wire up the already-written `previous_scan` into a new/fixed/persisting diff.
8. Add SARIF 2.1.0 and CycloneDX exports, plus a real CLI with `--fail-on-severity` and exit
   codes — that is what turns this from a dashboard into a CI gate.
9. Add a policy engine: per-tenant ignore list, `--ignorefile`, OpenVEX ingestion.
10. Enable `--scanners misconfig` and `license`; emit CycloneDX for the SBOM.
11. Dedup on `(id, package, installed_version)`; add `bool(fixed_version)` to the sort key ahead
    of CVSS so actionable findings outrank unfixable ones.

### Phase 3 — Reliability and QA

Classify Trivy exits properly (P3-1). Add a real lease to job claiming (P3-2). Make the rate
limiter atomic and fail-closed on write routes (P3-3). Add one re-ask on `AgentError` and
reconcile the timeout budget (P3-5). Delete the dead guard code and repoint its tests (P3-6).
Move blocking calls to `asyncio.to_thread` and the scanner gather to `asyncio.TaskGroup` (P3-9).
Share one progress bus per process with fan-out by `job_id`, and move the WS token out of the
query string (P3-9, P3-10). Reuse `_segment` in `blobs._path` and validate `tenant_id` charset
(P3-10). Add TTL and `expires_at` to `scan_results` plus a matching S3 lifecycle rule (P3-10).
Tenant-scope or delete `GET /api/v1/images`, and move `GET /scans/jobs/{id}` onto `owned_scan`
(P3-10). Fix uploads for the deployed topology, add a sweeper and a per-tenant quota (P3-9).
Add a job reaper for stale `running` rows (P3-10).

**Eval and tests** — the part that stops all of the above from regressing:

- Grow the CVE expectations well beyond one; add a small real-world image corpus.
- Gate the stability metrics that are already computed and currently assert nothing.
- Add a prompt-injection fixture image — the regression test for Phase 1.
- Add tests for: expired token, wrong audience, foreign issuer, unknown-`kid` rotation, JWKS
  down, concurrent rate-limit bypass, Redis-down behaviour, `/report` cross-tenant,
  `GET /scans/jobs/{id}` cross-tenant, and **report field presence**.
- Replace the three `asyncio.sleep` sync points; bind the test uvicorn to port 0.
- Register the markers; add `pytest-cov`.

### Phase 4 — Infrastructure

A bootstrap stack for the state bucket. ~~Redis onto a private subnet with~~ a password from
Secrets Manager (landed, §15 — the private subnet is not available on the learning tier). ~~Split worker and API task roles and give the frontend a bare execution role. Container
hardening on all four task definitions.~~ (landed, §16) Detective controls: SNS topic, CloudTrail with log-file
validation, GuardDuty with ECS runtime monitoring, VPC flow logs, and alarms on DLQ depth,
running-task count and a monthly budget. ALB with ACM and an HTTPS redirect, tasks to private
subnets, SG ingress from the ALB only, WAF with the common rule set and a rate-based rule on the
scan route. VPC endpoints, then egress restricted to 443. Create the missing terraform role and
remove the `||` fallbacks so a missing secret fails loudly. `use_lockfile=true` and a bounded
`required_version`. CMKs with rotation, `prevent_destroy` and deletion protection on stateful
resources. Cognito MFA, advanced security mode, `prevent_user_existence_errors`, shorter refresh
validity, and an immutable `custom:tenant_id`. Inspector enhanced ECR scanning, a lifecycle rule
for tagged images, 90-day log retention, container insights, and a deployment circuit breaker.

---

## 8. Additions: Docker Scout and the observability stack

### 8.1 Docker Scout as a second scanner

Not redundancy for its own sake. It closes two gaps Trivy alone cannot.

**It fixes the README's known-limitation #2.** `docker scout recommendations` performs a real
registry lookup. Today `base_image_strategist` performs none and recommends from model memory,
so it names tags that were current at training time. Feeding Scout's actual available-tag data
to the agent as *input* keeps the judgement with the model and moves the facts to the registry,
where they belong.

**Two-scanner consensus is a false-negative and hallucination control.** Running Scout's CVE
output alongside Trivy's and recording agreement per CVE gives `CVEFinding` a real per-finding
confidence — the field §4 (P2-1) identifies as missing — computed from evidence rather than
asked of a model. A CVE both scanners report is high-confidence; one only Trivy has is still
reported, and flagged.

Also usable: `docker scout sbom` (CycloneDX, feeding Phase 2 item 8) and `docker scout policy`
for the policy engine in Phase 2 item 9.

**Implementation:** a new `app/scanners/scout.py` mirroring `trivy.py` — the same
`build_command` / `_execute` / single-flight shape, and the same permanent-versus-retryable
classification once Phase 3 fixes it. Gate behind `SCOUT_ENABLED`, default off, so it cannot
break existing scans, and let it degrade like any agent rather than failing the scan. Scout
needs a Docker Hub login for full CVE data, so on Fargate that means a token in Secrets Manager
— plan for socket-mode-only at first.

### 8.2 Observability: OpenTelemetry Collector, Prometheus, Loki, Grafana

**Current state, verified:** zero instrumentation. `logging.basicConfig` with a plain-text
format at `app/main.py:9` and `app/api/main.py:9`. No metrics, no traces, no correlation IDs, no
structured logs. Grep for `opentelemetry|prometheus|otel|statsd|grafana|loki` across the repo
returns nothing.

Every failure mode in this document is currently invisible in production. This is what makes the
audit enforceable rather than a one-off.

#### Topology

```
worker ─┐
api    ─┼─ OTLP → OpenTelemetry Collector ─┬─ prometheusremotewrite → Prometheus ─┐
                                            ├─ loki                  → Loki       ─┼→ Grafana
                                            └─ otlp                  → Tempo*     ─┘
```

One Collector as the single egress point: the application speaks OTLP and never learns which
backend is behind it, so swapping Loki for CloudWatch on Fargate becomes a Collector config
change rather than a code change. *Traces are optional and were not requested — but a span tree
over one scan is the highest-value view for this pipeline, and the Collector makes adding it
nearly free later.*

Locally this is five services in `docker-compose.yml`. Deployed, the Collector runs as a sidecar
per ECS task, with Prometheus/Loki/Grafana either self-hosted or swapped for AMP and AMG.

#### Application instrumentation

- `opentelemetry-distro` and `opentelemetry-exporter-otlp`, plus auto-instrumentation for
  FastAPI, httpx (the OpenAI calls), boto3 and redis — that covers the transport layer for free.
- Replace `basicConfig` with a structured JSON formatter carrying `job_id`, `tenant_id`,
  `repo_id`, `target`, `trace_id` and `span_id` on every record. Today `job_id` appears in some
  log messages as interpolated text and in none as a field, so it cannot be filtered on.
- **`job_id` is the correlation key.** As a span attribute, a Loki label and a Prometheus
  exemplar, one `job_id` pivots logs, metrics and traces. This single change is what makes
  debugging a failed scan tractable.
- Manual spans on the stages `orchestrator.py:41-46` already times — `_timed()` is *already*
  measuring per-agent duration and putting it in a Pydantic field nobody aggregates. Emitting it
  as a histogram is a few lines.

#### Metric catalogue

The plumbing is generic; these are not. Each maps to a specific finding above.

| Metric | Type | What it catches |
|---|---|---|
| `scan_duration_seconds{stage}` | histogram | stage = trivy / scout / agents / store. Whether the 300s visibility timeout is actually too short (P3-2) |
| `agent_outcome_total{agent,status}` | counter | The core product-quality signal. The degraded rate is unobservable today |
| `agent_duration_seconds{agent}` | histogram | Already computed at `orchestrator.py:41-46` and currently discarded |
| `vulnerabilities_total{severity}`, `_sent_to_model`, `_dropped` | gauge | Makes the silent truncation visible (P2-3) — alert when `dropped > 0` |
| `llm_tokens_total{agent,kind}`, `llm_cost_usd_total` | counter | There is no cost visibility at all today, and no budget (P4-4) |
| `agent_guard_rejection_total{agent,reason}` | counter | reason = hallucinated_id / suppression / schema. **The production regression signal for Phase 1** — a spike means someone is probing the injection path |
| `ratelimit_decision_total{action,decision}` | counter | decision = allowed / rejected / **fail_open**. The fail-open path is a silent billing DoS today (P3-3) |
| `scan_queue_depth`, `dlq_depth`, `message_age_seconds` | gauge | The DLQ fills in total silence today (P4-4) |
| `heartbeat_failure_total` | counter | Catches P3-2 before it becomes duplicate concurrent scans |
| `trivy_failure_total{classification}` | counter | permanent vs retryable — validates that the P3-1 reclassification is correct in the wild |
| `scan_result_total{outcome}` | counter | clean / findings / degraded / failed |

Exposure: an in-process Prometheus endpoint on `/metrics` for the API, and OTLP push for the
worker — it has no port to scrape, which is the same reason its healthcheck probes SQS rather
than a socket (`Dockerfile:63-66`).

> **Superseded on implementation — see §18.** The `/metrics` half of this is wrong. The API
> runs `uvicorn --workers 2`, so an in-process registry lives in one of two processes and
> Prometheus would scrape whichever answered, making every counter appear to halve and jump
> backwards at random. Both processes push OTLP instead.

#### Dashboards

1. **Scan pipeline health** — throughput, p50/p95/p99 duration by stage, degraded rate, failure
   rate by classification.
2. **Agent quality** — outcome breakdown per agent, guard rejections, timeout rate, latency.
   This is the dashboard that tells you a prompt edit regressed something.
3. **Cost** — tokens and USD per scan, per agent, per tenant. Currently unknowable.
4. **Queue and reliability** — depth, DLQ, message age, heartbeat failures, redelivery rate.
5. **Security signal** — findings by severity over time, secret findings, guard rejections,
   rate-limit rejections, fail-open events.

#### Alerts

Routed to the SNS topic Phase 4 creates:

- `dlq_depth > 0` — currently fills silently.
- `ratelimit_decision_total{decision="fail_open"} > 0` — unbounded LLM spend in progress.
- Degraded-scan rate above 10% over 15 minutes — the pipeline is quietly producing worse reports.
- `agent_guard_rejection_total{reason="suppression"}` rising — active probing of the injection path.
- `llm_cost_usd_total` daily burn above threshold.
- p99 scan duration approaching the visibility timeout.
- `heartbeat_failure_total > 0`.

#### Sequencing

The *plumbing* — Collector, structured logs, `job_id` correlation — can land alongside Phase 0
and pays for itself immediately during the rest of the work. The *metrics* mostly land after
Phases 1-3, because several of them measure controls that do not exist yet:
`agent_guard_rejection_total` needs Phase 1's guards, and `vulnerabilities_dropped` needs
Phase 2's ground-truth persistence.

---

## 9. Appendix: coverage-gap matrix

| Capability | Status | Addressed by |
|---|---|---|
| Vulnerability scanning (OS + language) | Present | — |
| Secret scanning | **Run, then discarded** | Phase 2 item 2 |
| Misconfiguration / IaC | Absent | Phase 2 item 10 |
| License compliance | Absent | Phase 2 item 10 |
| SBOM (CycloneDX / SPDX) | Absent | Phase 2 items 8, 10; Scout |
| Signing / provenance / attestation | Absent | not planned — flag for a later phase |
| Malware | Absent | out of scope for Trivy; note only |
| EPSS scores | Absent | Phase 2 item 3 |
| CISA KEV catalog | Absent | Phase 2 item 3 |
| Base-image freshness (registry lookup) | Absent — model memory only | Scout (§8.1) |
| CVSS score / vector on findings | Computed, then dropped | Phase 2 item 1 |
| CWE on findings | Absent | Phase 2 item 1 |
| Package / version / fixed-version on findings | Computed, then dropped | Phase 2 item 1 |
| Layer attribution for CVEs | Absent | Phase 2 item 1 |
| SARIF export | Absent | Phase 2 item 8 |
| CI gate / exit codes | Absent | Phase 2 item 8 |
| Scan-to-scan diff | Dead code, no fingerprint | Phase 2 items 6, 7 |
| Suppression / VEX / ignore file | Absent | Phase 2 item 9 |
| Deterministic risk score | Absent — model output | Phase 2 item 5 |
| Prompt-injection resistance | Absent | Phase 1 |
| Metrics / logs | Landed locally, absent on AWS | §18 |
| Traces | Absent — instrumentors installed, no provider | §18 |
| CloudTrail / GuardDuty / flow logs | Absent | Phase 4 |
| Alarms / budget | Rules written, routed nowhere | Phase 4, §18 |

---

## 10. Remediation status

### Phase 0 — landed

Verified: `ruff`, `ruff format`, `mypy app eval`, 103 unit tests, 43 integration tests,
the docs gate at 34/34, and `terraform fmt -check` + `validate` on 1.14.5. Each item was
also exercised against a running stack, not just a test.

| Finding | Fix | Evidence |
|---|---|---|
| **P1-5** argument injection | OCI-reference pattern on `StartScanRequest.target`, plus `--` before the target in every `trivy` / `docker` argv | Live API returns 422 for `--server=https://attacker.example`, `-v/:/host`, `alpine --output=/tmp/x`; 202 for `auditor-eval:clean` |
| **P1-6** issuer never verified | `issuer=TOKEN_ISSUER` with `verify_iss`; the dev issuer now sets `iss`; `assert_production_auth()` refuses dev defaults outside a local run | A token signed by the right key with a foreign `iss` now returns 401 (was 200); the dev issuer still returns 200 |
| **P3-3** rate limiter | One Lua script, so check-and-charge is atomic; `EXPIRE` moved after `ZADD`; **fails closed** on the scan and upload routes | 12 concurrent requests against a limit of 5 → exactly 5×202 and 7×429 |
| **P3-2** heartbeat | **PARTIAL.** Retries with a bounded failure count instead of giving up on the first error, and the boto3 call moved off the event loop. The root cause is untouched: there is still no lease, so if the heartbeat does exhaust its retries, `handler.py` still cannot tell a live holder from an abandoned job and two workers still scan the same image | `MAX_HEARTBEAT_FAILURES` |
| **P3-4** `priority` prompt/schema contradiction | Sentence removed from the two prompts whose schemas forbid the field; the four finding prompts keep it | `grep "priority is an integer"` → 4, all finding prompts |
| **P4-1** mutable `:latest` RCE chain | ECR `IMMUTABLE`; task definitions read `var.image_tag`; build-role trust narrowed from `repo:X:*` to `StringEquals` on the deploy branch and `pull_request`; CI stops pushing `:latest`; services `ignore_changes` on `task_definition` so an apply cannot roll back a CI deploy | `terraform validate` passes |
| **P4-2** secret on PR-triggered plans | `tf-plan` gated on `github.event_name == 'push'` | `ci.yml` |
| **M9** `deploy_branch` never wired | Root variable added and passed to the `cicd` module | `terraform validate` passes |
| CORS origins unstripped | `.strip()` each, drop empties | `test_cors_origins_are_stripped` |

### Fixed along the way

- **The CI lint job was failing.** `docs/learning/` had been renamed to `docs/build_phases/`
  without updating `ci.yml`, `pages.yml`, the README, or the path hardcoded *inside*
  `check_code_blocks.py`. All four fixed; the gate now runs and reports 34/34.
- **The test suite could not run beside another project.** `conftest.py` bound the JWKS
  server to a hardcoded `127.0.0.1:8080`, and `JWKS_URL` said `localhost` — which resolves
  to `::1` first, so any container publishing `[::]:8080` answered the JWKS fetch instead.
  Now an OS-assigned port and an explicit `127.0.0.1`.

### New tests

`tests/test_auth_hardening.py` (19) and `tests/test_node_progress.py` (15). Every one of
them fails against the code as it was. They cover the properties §5 (P3-8) listed as
untested: foreign issuer, expired token, wrong audience, hostile targets, the production
fail-fast, and progress-frame monotonicity.

### Also landed: per-agent progress events

`ProgressEvent` gained optional `node` / `node_state`, and `orchestrator.py` announces each
scanner and agent as it starts and settles. This is the instrumentation point §8.2 specifies
for `agent_outcome_total` and `agent_duration_seconds`, and the data source for the pipeline
graph in [PIPELINE_GRAPH.md](PIPELINE_GRAPH.md). Side benefit: the progress bar no longer
sits at 40% for the whole agent phase.

### Not fixed — still open

Everything in Phases 1-5: prompt injection and the suppression guard (**P1-1**, the finding
that matters most), `skipped_no_input` being trusted (**P1-2**), severity reconciliation
(**P1-3**), `docker load` tag poisoning (**P1-4**), the whole of §4 (the report itself —
discarded secret findings, stripped CVE metadata, no export, no diff, LLM-authored risk
score), Trivy failure classification (**P3-1**), and every infrastructure item beyond the
four above.

### Environment notes from the verification run

- Agents returned `failed` during the live scans because the OpenAI account is returning
  **429 quota exceeded**. Unrelated to any change here — and the pipeline degraded visibly
  rather than crashing, which is the behaviour the design intends.
- Port 8080 on this machine is held by an unrelated container, so the stack was exercised
  with the API published on 18080.


---

## 11. Phase 1 — landed

The class of defect that let a scanned image talk the scanner into reporting
nothing. Verified: ruff, format, mypy, **137 unit tests**, 42 integration, docs gate 34/34.

| Finding | Fix |
|---|---|
| **P1-1** prompt injection | Three separate defences, below |
| **P1-2** `skipped_no_input` trusted for every agent | Split into `skipped_no_input` (a real answer) and `skipped_missing_input` (evidence never arrived, **not** trustworthy). `bloat_detective` now returns the latter for an unreadable history |
| **P1-3** model severity never reconciled | `reconcile_severities()` overwrites any severity the model set *below* the scanner's. Escalation is left alone — the model sees context the scanner does not, and escalation cannot hide a problem |
| **P1-4** `docker load` poisons the shared daemon | Uploads resolve to a `tarfile://` path and are read with `trivy --input`. Never loaded, so an archive's own RepoTags cannot replace the daemon's real `python:3.12-slim`. History and config come from the Trivy report, reusing the registry-mode path that already existed |
| **P3-1** every Trivy failure marked permanent | `is_permanent_failure()` — permanent only for exit 2 or a stderr naming a bad reference. A GHCR rate-limit, registry 5xx or OOM is retryable again instead of silently deleting the job |
| **P3-6** dead code was what the tests tested | `parse_analysis` and `_build_messages` deleted; the seven tests now exercise the guard production actually runs |
| **P3-5** no retry on malformed output | One re-ask with the validation error fed back, before degrading the agent |
| **M9 / 4.9** destructive CIS advice | The prompt now forbids recommending COPY where ADD is auto-extracting or fetching — README known-limitation #1 |
| — | `bloat_detective` moved onto the shared runner; it had its own client and parser, so every fix above would have skipped it |
| — | `TRIVY_IMAGE` pinned by digest (it was the last floating `:latest` in a repo that digest-pins everything, and it runs with the host socket mounted) and given `--memory`, `--cpus`, `--pids-limit`, `--cap-drop=ALL`, `--security-opt=no-new-privileges` |

### The three defences against P1-1

1. **A trust boundary.** Every block of scanner output is fenced by
   `untrusted_block()` and the system prompt says what the fence means: data,
   never instructions, and never a reason to report less. Content containing the
   end marker has it stripped, so it cannot close the fence early and write
   outside it.
2. **A suppression guard.** `assert_not_suppressed()` refuses an empty result the
   input size says is not credible. Every prior guard was one-directional —
   they rejected identifiers the model *invented* and said nothing about a model
   that *omitted* everything, which is exactly what a successful injection
   produces.
3. **Taking the decision away entirely.** CIS 4.1, 4.6 and 5.8 are comparisons,
   not judgements. They moved to `app/processors/compliance.py`, run in the
   orchestrator before any model call, and are emitted as their own
   `cis_controls` outcome. A prompt cannot argue with `user == "root"`.

### Proven end to end

The OpenAI account ran out of credits mid-verification
(`credit_balance_exhausted`), which turned out to be the ideal test. Scanning
`auditor-eval:bad` with **every agent failing**:

```
cis_controls          analysed   findings=3
cve_analyst           failed     findings=0
bloat_detective       failed     findings=0
base_image_strategist failed     findings=0
compliance_checker    failed     findings=0
dockerfile_optimizer  skipped_degraded_input
risk_scorer           failed     findings=0
```

The three surviving findings were CIS 4.1 (runs as root), 4.6 (no HEALTHCHECK)
and 5.8 (privileged ports 22, 80) — each verified against
`eval/fixtures/bad/Dockerfile`, which has no `USER`, no `HEALTHCHECK`, and
`EXPOSE 22` / `EXPOSE 80`. Correct findings from a completely dead LLM.

### Still open

**Phase 2 in full** — the report layer. Trivy's secret results are still
discarded, `CVEFinding` still carries no package, version, CVSS, CWE or
references, there is still no SARIF/SBOM export, no scan diff, no policy
engine, and the risk score is still whatever the model returns. Plus **P3-2**'s
lease, **P3-7** the eval corpus, **P3-9** the remaining blocking calls, **P3-10**,
**P4-3/4/5**, and §8.1-8.2.


---

## 12. Phase 2A — landed

The report layer. Verified: ruff, format, mypy, **163 unit tests**, 48 integration, docs gate
34/34, and a real scan with a working model key.

| Finding | Fix |
|---|---|
| **P2-1** machine-readable data stripped | `RawVulnerability` now reads `CweIDs`, `References`, `PrimaryURL`, the CVSS **vector** (the score was already parsed out of that same block) and the layer DiffID. `CVEFinding` carries them plus `scanner_severity` — all optional and populated **after** the model replies, never requested |
| **P2-2** Trivy secrets discarded | `processors/secrets.py` reads `Results[].Secrets` into a `SecretFinding`, emitted deterministically like the CIS controls. The matched line is **redacted** — it contains the live credential, and a vulnerability report is exactly the document an attacker wants |
| **P2-3** exploitability was a guess | CISA KEV (cached daily) and FIRST EPSS. Both fail open but **visible**: unavailable records as `None`, never as "not exploited" |
| **P2-4** counts were model opinion | `ScanCoverage` persists the scanner's own tally; `critical_count`/`high_count` now come from Trivy |
| **P2-5** no diff, `previous_scan` dead | `fingerprint` on every finding, built from facts not prose, and `storage/diff.py` classifies new/fixed/persisting. Also fixed `previous_scan`'s `Limit=2`, which could return None with a prior scan present |
| **P2-6** risk score was an LLM opinion | `processors/scoring.py` computes all four axes. The model call shrank to `RiskNarrative` — summary and priorities only. An axis with no trustworthy evidence scores **None**, not zero, and `overall` is clamped to the worst axis |
| — | Dedup on `(id, package, installed_version)`; `fixed_version` added to the sort key ahead of CVSS, so actionable findings outrank unfixable ones inside the budget |
| — | TTL on `scan_results`. The S3 lifecycle expired report bodies at 30 days while the Dynamo row lived forever, so `/report` 404'd on scans the UI still listed. `create_tables.py` also ended in a bare `return` that would have silently skipped the new table |
| — | `httpx` declared as a direct dependency; `core/auth.py` had been importing it transitively |

### Proven end to end

A real scan of `auditor-eval:bad`, every agent `analysed`. A stored CVE finding now reads:

```
vulnerability_id   CVE-2024-56171
severity           critical          scanner_severity  critical
package            libxml2-dev
installed_version  2.9.14+dfsg-1.3~deb12u1
fixed_version      2.9.14+dfsg-1.3~deb12u2
cvss_score         9.8
cvss_vector        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
cwe_ids            ['CWE-416']
kev_listed         False             epss_score        0.01178
fingerprint        3de8c69f42683f7a
```

Before this phase that finding was a CVE id and four fields of prose. There was no way to act
on it without going back to the scanner.

**The coverage record, cross-checked against an independent `trivy image` run — exact match:**

| | independent Trivy | our coverage record |
|---|---|---|
| total | 11,028 | 11,028 |
| critical | 224 | 224 |
| high | 2,472 | 2,472 |
| medium | 6,336 | 6,336 |
| low | 1,948 | 1,948 |

**11,028 vulnerabilities, 150 analysed, 10,878 dropped.** The report used to say none of that —
it showed a handful of findings and implied completeness. `critical_count` on the summary row
now reads 224 where it previously reported whatever the model happened to write up.

The diff resolved against the previous scan of the same repo: 5 new, 11 persisting — correct,
because the earlier scan's `cve_analyst` had failed.

### Two bugs the live run caught that tests did not

1. **A regression I introduced.** Enriching `RawVulnerability` also enlarged the *prompt*,
   because the payload was `model_dump()`. Five reference URLs and a CVSS vector per entry
   across the 150-vulnerability budget took one request from ~20k to 44,692 tokens and past the
   account's 30k TPM limit — `cve_analyst` failed outright. Fixed with `for_prompt()`, a lean
   projection: the enrichment is stapled on afterwards, so sending it was pure cost. The same
   principle as the rest of the phase — do not show a model facts it is not being asked about.
2. **Phase 1's re-ask earning its place.** `compliance_checker` returned four findings missing
   `priority`, the retry fed the validation error back, and the second attempt succeeded. Before
   Phase 1 that scan would have degraded on a recoverable formatting slip.

### Still open

**Phase 2B** — SARIF, CycloneDX SBOM, CSV/JUnit, the CLI gate with `--fail-on-severity`, and
the policy engine. *Landed; see §13.* `--scanners misconfig,license` was split out of it and
remains deferred. Then **P3-2**'s lease, **P3-7**'s eval corpus, **P3-9**'s remaining blocking
calls, **P3-10**, **P4-3/4/5**, and §8.1-8.2.

**Frontend drift.** *Landed; see §17.* `frontend/types/scan.ts` is now further behind: it lacks
`skipped_missing_input`, the `secret` category, every enriched `CVEFinding` field, `coverage`,
`diff`, and the scores are typed `number` where they are now `number | null`. Adding optional
fields is non-breaking at runtime, but a null score would render as a missing value. This
belongs with the deferred `docs/PIPELINE_GRAPH.md` work.

---

## 13. Phase 2B — landed

Phase 2A made the report carry real data. Nothing could *consume* it: `GET /{job_id}/report`
returned a JSON blob, there was no export of any kind, and the only console script in
`pyproject.toml` pointed at a `uv init` stub that printed `Hello from worker!`. Nothing in the
product could fail a build.

### What shipped

| Area | Change |
|---|---|
| **P2-5** SARIF | `app/reporting/sarif.py` — built from *our* findings, not passed through from Trivy. Trivy's own SARIF knows only about vulnerabilities, so it would discard the CIS controls, the secrets, the bloat analysis and the base-image work — everything the product adds. `partialFingerprints` carries the 2A fingerprint, so GitHub tracks a finding across scans instead of closing and reopening it every run. |
| **P2-8** SBOM | `app/reporting/cyclonedx.py` + `app/processors/packages.py`. CycloneDX 1.5, components and vulnerabilities in one document cross-referenced by `bom-ref`. |
| **P2-5** CSV / JUnit | `app/reporting/tabular.py`. Both stdlib. JUnit means findings land in the test-report pane every CI system already renders. |
| **P2-6** Export API | `GET /api/v1/scans/{job_id}/report?format=sarif\|cyclonedx\|csv\|junit`, default `json`. |
| **P2-7** Policy | `app/policy/`. Per-tenant suppressions with a **required reason** and an optional expiry, stored at blob key `policy/{tenant_id}`. |
| **P2-9** CI gate | `python -m app.cli scan <target> --fail-on-severity high`. Exit `0`/`1`/`2`. |

### No second Trivy run was needed

The approved plan assumed the SBOM required a second invocation, roughly doubling scan time.
It does not: `--list-all-pkgs` ("output all packages in the JSON report regardless of
vulnerability") **defaults true**, so `Results[].Packages` was already in every report we
fetched — and nothing read it. The one run we already pay for has always carried a complete
bill of materials and thrown it away.

The flag is now passed explicitly in all four branches of `build_command` rather than relied on
as a default, since the Trivy image is digest-pinned and a default can change under a bump.

While in that file: the Trivy timeout was expressed twice and in different units —
`TRIVY_TIMEOUT_SECONDS = 600` bounded the `asyncio.wait_for` while a hardcoded `"10m"` went to
Trivy's own `--timeout`. They agreed, and nothing enforced it. Now one constant.

### Suppression marks, it does not delete

This is the design the whole policy layer rests on. A suppressed finding stays in the report,
carrying the reason it was accepted, and is excluded only from the gate and the score:

- SARIF emits it as a `suppressions` entry with the justification — GitHub honours this.
- CycloneDX emits an `analysis` block with `state: not_affected`.
- CSV carries `suppressed` and `suppressed_reason` columns; JUnit renders it as `<skipped>`.

Dropping the finding instead would mean nobody can review what was accepted, an expiry would
have nothing to un-hide, and the report would quietly disagree with the scanner about what is
in the image. Policy is applied **at read time**, not at scan time, for the same reason: the
stored report is evidence, and should not depend on what the policy happened to say the day it
was written.

An unparseable `expires_at` is treated as **expired** — the safe direction is for the finding to
come back, not to stay hidden forever on the strength of a typo. A policy that cannot be loaded
at all fails open to *no* suppressions, for the same reason.

### Deviation: `--vex` and `--ignorefile` were not wired

The plan listed both as pass-throughs to Trivy. They were not built, deliberately. Both are
Trivy-side suppression mechanisms that *hide* findings before we ever see them — exactly the
behaviour the policy layer exists to avoid — and wiring them in socket mode also means mounting
files into the scanner container. The policy engine above is strictly better on every axis that
matters here: per-tenant, reason-required, expiring, reviewable, and structurally unable to
delete evidence. Revisit only if a consumer needs to import an externally-authored VEX document.

### `src/worker` is gone

The `[project.scripts] worker = "worker:main"` entry pointed at an untouched `uv init` stub. A
console script that lies about what it does, sitting next to a real CLI, is worse than having
neither — and a *working* one would need `[tool.uv.build-backend]` module config, because
`uv_build` assumes a `src/` layout while the real package is `app/` at the project root.

`pyproject.toml` now declares `[tool.uv] package = false`, which is the explicit form of what
`worker/Dockerfile` has always done with `--no-install-project`. Every entrypoint, the new CLI
included, is `python -m app.X` — the house convention.

### Verification

Everything below is from a live run, not from the test suite.

**1. Schema validation, not eyeballing.** A malformed SARIF is rejected *silently* by GitHub,
which is the worst possible failure mode for this feature. Both documents were validated against
the published schemas — `sarif-schema-2.1.0.json` from oasis-tcs/sarif-spec and
`bom-1.5.schema.json` from CycloneDX/specification — generated from a real scan of
`auditor-eval:bad`, and again with a policy applied so the `suppressions` and `analysis` paths
were exercised rather than skipped:

```
PASS SARIF 2.1.0
PASS CycloneDX 1.5
```

**2. The SBOM is exactly what the scanner saw.** Our inventory was compared set-for-set against
an independent `trivy image --list-all-pkgs` run of the same image:

| | packages |
|---|---|
| Independent Trivy run | 598 |
| Our `extract_packages` | 598 |
| Symmetric difference | **0** |

598 components across three ecosystems (453 Debian, 130 Python, 15 Node.js), 598 with a purl,
497 with licence data.

**3. Every format, from the live API, through a real parser.** `json`, `sarif`, `cyclonedx`,
`csv` and `junit` fetched over HTTP and parsed with `json`, `csv.DictReader` and
`xml.etree` — plus the media type, the `Content-Disposition` filename, a 422 on an unknown
format, and 404-not-403 for another tenant's scan.

**4. `?format=json` is byte-identical** to the response before this phase, so nothing that reads
the report today breaks. Asserted directly: default response `==` `?format=json` response.

**5. The gate, end to end.** `python -m app.cli scan auditor-eval:bad --fail-on-severity high`
exited **1** with 12 findings at or above the threshold (6 critical, 6 high), naming the worst
ten. A scan that cannot run exits **2**, never 1 — *we found criticals* and *we never looked*
must not look the same to a pipeline.

`auditor-eval:clean` also exits 1 at `--fail-on-severity high`: it carries 6 high findings, all
bloat and base-image, and no criticals. That is the correct answer, not a regression — the image
is *clean of planted CVEs*, which is what the eval harness measures, not clean of everything.
The gate reports what is there.

**6. A suppressed finding passes the gate while staying in the report.** The distinction the
whole design rests on, asserted end to end through the CLI: gate exit 0, and the finding still
present in the written report with `suppressed: true` and its reason.

**7. Suite.** 189 unit (was 163), 56 integration (was 48), docs gate 34/34, `ruff check`,
`ruff format --check` and `mypy app eval` all clean.

### One thing the type checker caught worth recording

`SEVERITY_ORDER` is keyed by the `Severity` *Literal*, but stored findings are plain dicts whose
severity has decayed to `str` — so every export and the gate wanted a `str` lookup. The wrong
fix is a cast at each call site; the worse one is a second ordering table. Added
`severity_rank()` next to `SEVERITY_ORDER`, one str-keyed view of the same data, with unknown
severities sorting last so an unrecognised value can neither outrank a critical nor fail a gate
on its own.

### Still open

**P3-2**'s lease (only the symptom was fixed in Phase 0), **P3-7**'s eval corpus, **P3-9**'s
remaining blocking calls, **P3-10**, **P4-3/4/5**, and §8.1-8.2 (Docker Scout, OpenTelemetry,
Loki, Grafana, Prometheus). *P3-2, P3-9 and P3-10 landed in Phase 3; see §14.* The `misconfig` and `license` scanners remain deferred to their own
phase — they are a detection-surface change, not a reporting one, and belong with the work that
can evaluate their false-positive rate.

**Frontend drift is now the largest single gap.** *Landed; see §17.* `frontend/types/scan.ts` lacks
`skipped_missing_input`, the `secret` category, every enriched `CVEFinding` field, `coverage`,
`diff`, `packages`, and now `suppressed`; the scores are typed `number` where they are
`number | null`. None of the new exports are reachable from the UI. This belongs with the
deferred `docs/PIPELINE_GRAPH.md` work.

---

## 14. Phase 3 — landed

Correctness and reliability. Phase 0 fixed the *symptom* of P3-2 and said so; this fixes the
cause, and takes the rest of §5's async and hygiene findings with it.

### P3-2 — the lease, and a worse bug underneath it

A job row in state `running` was ambiguous. A worker mid-scan and a worker that died forty
minutes ago looked identical, so when SQS redelivered a message `handle_scan` had to guess. It
guessed *reprocess*, and two workers scanned the same image: double model spend, racing
`update_progress` writes, racing `store_result` puts, and progress events interleaving
backwards on the WebSocket.

`JobRecord` now carries `lease_expires_at`, an integer epoch:

- `claim_job` wins on three conditions — the row does not exist, the row is `queued`, **or** the
  row is `running` with a lapsed lease. A live lease now loses, where before every redelivery
  won.
- The heartbeat renews the lease on the same clock as the SQS visibility extension, in the same
  `try`, against the same three-strike budget. The two answer the same question in the two
  places it gets asked: SQS decides whether to **redeliver**, the lease decides whether whoever
  receives it should **act**. Extending only the first is what let a lapsed heartbeat become two
  scans.
- A renewal that comes back `False` means the row is no longer `running` under us — finished, or
  taken over — and the heartbeat stops rather than keeping a doomed scan's message alive.
- `JOB_LEASE_SECONDS = HEARTBEAT_INTERVAL_SECONDS * 3`, so a single slow renewal cannot hand a
  live scan away.
- `lease_expires_at` defaults to `0`, which reads as expired. That is the right answer for rows
  written before the field existed, and for any row nobody has heartbeated.

**The live run then found a worse bug the lease had been hiding.** `GET /jobs/{id}` reported
`stale: true` on a scan that was actively running. The cause: `POST /scans` enqueues *before* it
writes the queued row, and on a warm queue the worker routinely claims the job first — at which
point the API's unconditional `put_item` overwrote the claim with `queued` and wiped the lease.
So a live scan advertised itself as unclaimed, and the duplicate-scan hole was wider than the
audit described: not just after a heartbeat lapse, but on **every** fast scan.

`create_job` is now conditional on `attribute_not_exists(job_id)` and returns the row that
actually exists. Losing that race is normal, not an error — the row a worker wrote is strictly
newer than the one the API is trying to write.

No test caught this. Only running it did.

### P3-10 — path traversal in blob storage

`images.py` had a `_SAFE_SEGMENT` guard on upload paths. `storage/blobs.py`, which builds
report and policy keys from the same class of input, had none — so with `DEV_AUTH=1`,
`/dev/token?tenant_id=../../..` minted a token whose `sub` produced a key that escaped
`BLOB_DIR`.

The guard now lives in `storage/blobs.py` and `images.py` imports it, so there is one check
rather than two that can drift — which is exactly how only one of them came to have it. It is
applied to the **key**, not only to the local path, because `reports/../other-tenant/job` is a
perfectly valid S3 key and reads someone else's report.

### P3-10 — non-atomic blob write

A crash partway through `write_text` left truncated JSON, which surfaced later as a 500 from
`json.loads` where a missing report is meant to be a 404. Now write-to-temp and `os.replace`,
which is atomic within a filesystem: a reader sees the whole old file or the whole new one.

### P3-9 — blocking calls on the event loop

Each of these froze the loop that was simultaneously running four concurrent agents, serving
every other API request, and answering WebSocket keepalives:

| Call | Was |
|---|---|
| `receive_message` | a **20-second** synchronous block per poll |
| `delete_message` | one per message, twice on the failure path |
| `update_progress` | a DynamoDB write at every stage frame |
| `store_result` | the largest of them — report body plus summary row |
| `handle.write` in `save_upload` | a 2 GB tar as thousands of blocking 1 MB writes |

All now `asyncio.to_thread`.

### P3-9 — orphaned scanner coroutines

`_fetch_raw` used `asyncio.gather` with the default `return_exceptions=False`, which returns the
moment one scanner raises and leaves the other two running unawaited — two coroutines holding a
Docker subprocess each, with nobody left to notice when they finish. Now `return_exceptions=True`
and re-raise, which costs at most one scanner's remaining runtime on a path that is already
failing.

### P3-10 — a cancellation is not an agent failure

The agent gather also runs with `return_exceptions=True`, and `_degrade` was typed to accept
`BaseException`. A SIGTERM mid-scan therefore arrived looking exactly like an agent failure and
was written into a stored report as one — claiming an agent had been tried and failed when it
had not. `_degrade` now takes `Exception`, and a bare `BaseException` is re-raised so the scan
aborts.

### P3-10 — UNKNOWN is not informational

Trivy emits `UNKNOWN` when it has no severity for a CVE, which is routine for the first days
after an advisory is published. Mapped to `informational` it sorted *below* `low`, which made it
the first thing dropped by the `MAX_VULNERABILITIES_TO_MODEL` cap: the vulnerabilities nobody
had assessed yet were the ones nobody assessed. Now `low` — high enough to survive the cap,
low enough not to inflate the counts anyone reports on. `NEGLIGIBLE` is a real assessment and
stays `informational`.

The live scan shows the effect directly: `informational` went from a populated bucket to `0`,
with those vulnerabilities now counted in `low`.

### P3-10 — the rest

- **Poison message aborted the poll cycle.** The body was parsed *outside* the `try`, so one
  unreadable message took the whole batch down with it and burned three redeliveries before the
  DLQ caught it. Parsed inside, and deleted rather than retried — a body that will not parse now
  will not parse on the third attempt either.
- **Jobs orphaned in permanent `running`.** There is no reaper, so a job whose worker died read
  "in progress" for the full 30-day TTL, indistinguishable from a slow scan. The lease answers
  it: `GET /jobs/{id}` now returns `stale`. Reported rather than rewritten to `failed`, because
  a redelivery can still pick the job up and the row would then be wrong in the other direction.
- **`boto3.resource` rebuilt on every call**, twice per `GET /report`. `@lru_cache(maxsize=1)` —
  every input is a module-level constant read at import, so there is nothing to go stale against.

### Verification

**1. The lease, against the live stack.** A real scan of `auditor-eval:clean` through the API,
and while it was running, a second worker asked for the same job:

```
status      : running
lease left  : 163 s
lease_is_live: True
second worker claim -> False
```

Before this change that call returned `True` and a second scan started.

**2. The heartbeat renews both things.** `_heartbeat` driven at a one-second interval against
the real DynamoDB row:

```
visibility extensions: 2
lease advanced by    : 2 s
lease still ahead    : 180 s
```

**3. `stale` is honest in both directions.** It read `true` on a live scan — which is what
exposed the `create_job` race — and reads `false` now, for the whole scan and after it
completes.

**4. The pipeline is unchanged by any of it.** The same scan completed `degraded: false`, and
all five report formats still serve: `200 application/sarif+json`,
`200 application/vnd.cyclonedx+json`, `200 text/csv`, `200 application/xml`, plus JSON with
88 packages and a coverage record of 213 vulnerabilities.

**5. Suite.** 209 unit (was 189), 65 integration (was 56), docs gate 34/34, `ruff check`,
`ruff format --check` and `mypy app eval` clean. New: `tests/test_lease.py` (9, integration —
the lease is a DynamoDB condition expression and testing it against a mock would test the
mock) and `tests/test_reliability.py` (20, unit). Every one of them fails against the code as
it was.

### Fixed along the way: the queue tests raced the worker

`tests/test_queue.py` purged and then shared the one real `scan-jobs.fifo`, so it failed
whenever the worker **container** happened to be running locally — the container consumed the
messages the tests enqueued, and the failure read as a bug in the code under test rather than in
the test. Pre-existing and unrelated to this phase, but it makes the suite unusable exactly when
you are also exercising the stack by hand, which is what this phase needed.

Each test now creates its own FIFO queue in ElasticMQ under a random name and deletes it
afterwards, with `SCAN_QUEUE_URL` patched in both `app.queue.producer` and `app.queue.consumer`
(both read it at import). A queue nobody else knows the name of cannot be raced, and the purge
disappears with it.

Verified the way the bug presented: `tests/test_queue.py` 10/10 and the full suite 274/274 with
`docker compose up worker` running, where two tests failed before. No queues are left behind —
ElasticMQ still lists only `scan-jobs.fifo` and `scan-jobs-dlq.fifo` afterwards.

### Still open

**P3-7**'s eval corpus, **P4-3/4/5** (the whole infrastructure tier, including the CRITICAL
unauthenticated Redis on a public IP), §8.1-8.2 (Docker Scout, OpenTelemetry, Loki, Grafana,
Prometheus), and the `misconfig` / `license` scanners.

Two P3-9 items were left deliberately:

- **One Redis connection pool per WebSocket** with no cap and no rate limit on the route. Real,
  but the fix is a shared pool plus a per-tenant connection limit, which is its own change.
- **Loaded images are never `docker rmi`'d, and orphaned upload tars are never swept.** Needs a
  sweeper with a retention policy, not a line in the upload path.

**Frontend drift** remains the largest single gap, now also missing `stale`.

---

## 15. P4-3 — landed

The first infrastructure finding fixed, and the highest-severity item that was still open.
Redis is not incidental here: Phase 9 made it the progress bus and Phase 0 made it the rate
limiter's store, so an open one hands an attacker `FLUSHALL`, `CONFIG SET`, `MONITOR` on every
scan in flight, and pub/sub injection into the channel the browser trusts.

**One token, generated by Terraform, used by both deployment paths.**

```
random_password ──→ Secrets Manager ──┬─→ ECS Redis task   --requirepass   (learning)
                                      ├─→ ElastiCache      auth_token      (production)
                                      └─→ worker + api     REDIS_PASSWORD  (both)
```

`REDIS_URL` stays an ordinary environment variable holding only the address; the credential
travels separately through the ECS `secrets` block, which the agent resolves at task start. A
password *inside* the URL would have forced the whole URL into Secrets Manager, because
`environment` values are console-readable — the comment at `ecs/main.tf` already said so.

### Two corrections to this document

Same discipline as the `misconfig` correction in Phase 2B: the audit was wrong about half of
P4-3, and the fix is recorded against what is actually true.

1. **`assign_public_ip = true` on the Redis service was unreachable-but-wrong, not a live
   differential.** P4-3 presents it as Redis diverging from the other three services. It does
   diverge — but the whole Redis task is `count = local.public ? 1 : 0`, so it is only ever
   evaluated when `local.public` is already `true`. It now reads `local.public` for consistency,
   because a hardcoded exception is how the next person learns the wrong rule. It changes no
   plan, and calling it a security fix would have been a lie.

2. **"Properly: a private subnet with `assign_public_ip = false`" is not achievable on the
   learning tier.** `networking/main.tf` gates private subnets, the NAT gateway and its route
   table on `local.private = var.tier == "production"`, and there are no VPC endpoints anywhere.
   So at the default tier `assign_public_ip = false` puts the task in a *public* subnet with no
   route to anything: it cannot pull `public.ecr.aws/docker/library/redis:7-alpine`, cannot
   reach Secrets Manager, cannot reach CloudWatch Logs. It fails to start with
   `CannotPullContainerError`. Making it viable costs a NAT gateway (~$32/mo) or four interface
   endpoints (~$7/mo each, plus mirroring the image into private ECR). Both were considered and
   rejected: **the password is what closes the hole**, and on the production tier Redis is
   ElastiCache in a private subnet already.

The security group comment in `networking/main.tf` — *"this rule is the only thing standing
between Redis and the internet"* — was true when it was written and is now false. It says
"first thing" instead, which is the whole point of the change.

### Both paths, not one

The production tier runs ElastiCache, which had `at_rest_encryption_enabled = true` and no auth
token and no transit encryption — the same defect, filed under P4-5. Fixing only the learning
tier would have left the *more* production-shaped path unauthenticated, so it is included:
`transit_encryption_enabled` with `transit_encryption_mode = "required"` (*preferred* keeps
accepting plaintext clients, which is the setting that looks fixed and is not), plus the same
token. AWS rejects an auth token without transit encryption — the two are one control.
`REDIS_URL` becomes `rediss://` on that path and stays `redis://` for the in-cluster task, which
has no certificate to verify and would need one generated and mounted to gain anything.

### The application needed one line

Every Redis client already went through `from_url` with the full URL and no host/port
decomposition, so `config/api.py` gained `REDIS_PASSWORD: str | None` and the two call sites
pass it. `or None` rather than a default of `""`: redis-py skips AUTH entirely for `None`, where
an empty string sends an empty AUTH that a server without `requirepass` rejects.

**Not fixed, deliberately:** the never-invalidated `_client` global in `ratelimit.py`. It looks
like a bug next to new credentials, but `from_url` does not connect eagerly — the cached client's
pool reconnects on its own, so a wrong password gives 503s while it is wrong and stops when it
is fixed. Nothing to invalidate.

### The bug this change nearly introduced

The Redis container needs a shell to expand `$REDIS_PASSWORD`, so `entryPoint` becomes
`["sh","-c"]`. **That silently promoted Redis from uid 999 to root.** The image's
`docker-entrypoint.sh` drops privileges with `setpriv` when `$1` is `redis-server`; overriding
the entrypoint skips that branch entirely.

Caught by running it, not by reading it:

```
# with the sh -c shim, no `user`
USER     COMMAND
root     redis-server *:6379

# stock image
USER     COMMAND
redis    redis-server *:6379
```

Fixed with `user = "999"` on the container definition — numeric rather than `"redis"`, because a
name has to resolve inside the image and that fails at task-start rather than at plan. A
hardening change that silently un-hardens the thing it touches is the worst kind, and in a
product that ships a CIS *run as non-root* check it would have been quite the finding.

The health check gets the same secret a second time under the name `REDISCLI_AUTH`, which
`redis-cli` reads by itself — so the probe needs no `-a` flag and the token never reaches its
argv, every thirty seconds. It greps for `PONG` rather than trusting the exit code, because an
unauthenticated ping prints `NOAUTH Authentication required.`

### Local and CI run the same authenticated Redis

A credential that exists only in AWS is never exercised, and the AUTH/health-check interaction
is exactly what breaks on first deploy. Both health checks had to learn to authenticate, or the
container never reports healthy and `api` and `worker` — which gate on `condition:
service_healthy` — never start.

- `docker-compose.yml` passes `--requirepass ${REDIS_PASSWORD:-localdev}`. The default is
  load-bearing: unset, the variable substitutes empty, `--requirepass ""` *disables* auth, and a
  fresh clone would come up silently unauthenticated — worse than not doing this at all.
- `.github/workflows/ci.yml`: Redis stops being a service container. `services:` takes only
  image/env/ports/volumes/options — there is no `command`, and the official image takes
  `--requirepass` as an argument, not an environment variable. It moves to an explicit
  `docker run` with a readiness loop, which is what ElasticMQ a few lines below already does,
  for a comparable reason.
- `conftest.py`, compose and CI all use the literal `localdev`. Three different defaults is how
  you get a green CI and a broken laptop.

### Verification

**1. The finding, reproduced as a before/after** against the real compose service:

```
$ docker compose exec -e REDISCLI_AUTH= redis redis-cli ping
NOAUTH Authentication required.          # was: PONG

$ docker compose exec redis redis-cli ping
PONG
```

**2. The password is load-bearing, not decorative.** `tests/test_progress.py` is the only suite
that opens a real Redis connection. Run against the authenticated server it passes; run with the
wrong password, or none, the pub/sub tests fail. A change like this that cannot be made to fail
has not been tested.

**3. End to end through the whole stack.** A real scan of `auditor-eval:clean` via the API:
accepted at 202, completed `degraded: false`, 14 findings, and **zero** `Progress publish
failed` warnings in the worker log — which is the pub/sub path working under AUTH. The 202 is
itself a proof: the rate limiter fails closed, so a broken credential returns 503 there.

**4. That 503 is not hypothetical — it happened.** The first live attempt returned
`{"detail":"Rate limiting is unavailable, refusing to start a scan"}` with
`HELLO must be called with the client already authenticated` in the log. The cause was a stale
image, not a config error, but it is the exact failure mode a mis-plumbed password produces, and
it fails loudly and closed rather than quietly accepting scans against an unusable Redis.

**5. The token cannot reach a task definition.** Traced statically: `random_password.redis.result`
flows only into `aws_secretsmanager_secret_version` and ElastiCache's `auth_token`. The entire
ECS module sees `redis_secret_arn` — an ARN, never the value.

**6. Terraform.** `fmt -recursive -check`, `init -backend=false`, `validate` — the three commands
CI runs — all clean on 1.14.5. `.terraform.lock.hcl` regenerated for linux/darwin/windows so the
new `random` provider does not dirty the file for whoever inits next.

**7. Suite.** 274 tests (209 unit, 65 integration) against the authenticated Redis, `ruff check`,
`ruff format --check`, `mypy app eval`, **docs gate 34/34**.

### Rollout note — read before the first apply

`aws_ecs_service.{worker,api,frontend}` carry `ignore_changes = [desired_count,
task_definition]`; `aws_ecs_service.redis` carries only `[desired_count]`. So `terraform apply`
rolls Redis onto `requirepass` **immediately**, while worker and API stay pinned to their
previous revision with no `REDIS_PASSWORD` until the next deploy — and in that window the rate
limiter fails closed and every scan-start returns 503.

Apply, then move the two services onto the new revisions in the same sitting:

```
terraform apply
aws ecs update-service --cluster <name> --service <name>-api    --task-definition <name>-api
aws ecs update-service --cluster <name> --service <name>-worker --task-definition <name>-worker
```

`--force-new-deployment` is not enough; the service is still pinned to the old revision ARN.
Nothing is deployed from this repo today, so this is a note for the first apply rather than a
migration.

### Still open

**P4-4** (no ALB/TLS/WAF, the shared task role, no container hardening on the other three task
definitions, open egress and zero VPC endpoints, missing detective controls) and the rest of
**P4-5** (customer-managed KMS keys, deletion protection, Cognito MFA, Inspector). Also
**P3-7**'s eval corpus, §8.1-8.2, and the `misconfig` / `license` scanners.

Worth stating rather than quietly doing: adding the Redis token to the **shared** execution role
widens that role's blast radius — the frontend's execution role can now read it too. Splitting
those roles is P4-4's job and is the right place to fix it.

---

## 16. P4-4 — partially landed

P4-4 is seven sub-items filed as one finding. Three are done: **the IAM split, container
hardening, and state locking.** Four are deferred by decision, with costs and blockers recorded
below rather than left implied.

### Three corrections to this document

1. **"Everything runs as uid 0" is false.** All three application images already drop to uid 1001
   at build time (`worker/Dockerfile:53,59` / `:87,91` / `:109,115`,
   `frontend/Dockerfile:51,58`), and Redis got `user = "999"` in §15. Verified against the built
   images: `auditor-worker:latest` → `uid=1001(worker)`, `auditor-api:latest` → `uid=1001(api)`.
   The real finding is that **nothing asserted it in the task definition** — which is what stops
   an image regression from silently promoting a task to root, and §15 is the record of that
   exact failure nearly happening to Redis. `readonlyRootFilesystem`, `cap_drop` and `ulimits`
   were genuinely absent everywhere.

2. **Line numbers.** The entry cites `ci.yml:222` and `:233`; they are **243** and **253**.

3. **"Nothing can reach the API" is correct, and understated.** The only ingress rule in the VPC
   is the security-group self-reference, so nothing on the internet reaches the API on 8080 or
   the frontend on 3000, on any tier. The repo already knew: the smoke job's own comment says
   *"Fargate tasks get a fresh public IP on every deployment and there is no load balancer, so
   there is no stable hostname to bake in"*, and that job is gated on a manually-set
   `vars.API_URL`. There is no Terraform output for any application address. This belongs in the
   body of the finding, not a parenthetical — **by this code the deployed stack does not serve
   traffic.**

### Three bugs found while reading, not in the audit

Each was a prerequisite for doing the hardening honestly, so each is fixed here.

1. **The deployed API ran in `socket` mode.** `SCANNER_MODE=registry` was set only on the worker
   task; the `api` image does not bake it and the default is `"socket"`. So `_socket_mode_only()`
   never fired on Fargate — `POST /api/v1/images/upload` did not return the 404 its docstring
   promises, it tried `mkdir /app/.blobs` as uid 1001 against a root-owned `/app` and 500'd. The
   guard had **no test**, which is how it survived; it has one now.

2. **The KEV cache had never worked in the deployed worker.** `ENRICHMENT_CACHE_DIR` defaulted to
   `.enrichment-cache` relative to CWD — `/app`, root-owned. The write failed and `kev.py`
   swallowed it in `except OSError`, so the CISA catalog was silently re-downloaded on every
   scan instead of cached. Now `/tmp/enrichment-cache`.

3. **`sqs:GetQueueAttributes` looks dead and is not.** No caller in `app/` — it is the worker's
   *container health check*. Dropping it during a least-privilege pass would leave the task
   permanently unhealthy in an ECS kill-restart loop. Recorded because it is precisely the trap
   this kind of change sets.

### The IAM split

One execution role and one task role became **three and two**. Every grant is derived from an
actual call site rather than from what the old policy happened to contain.

| | before | after |
|---|---|---|
| worker task role | 15 actions (the union) | 15 — but no longer `sqs:SendMessage` |
| **api task role** | **15 actions (the same union)** | **5** |

The API lost `s3:PutObject`, every `ecr:*` action, `sqs:ReceiveMessage`/`DeleteMessage`/
`ChangeMessageVisibility`, `dynamodb:UpdateItem`, and `PutItem` on the results table. The worker
lost `sqs:SendMessage` — an amplification primitive in the one component that fetches and
unpacks attacker-supplied images, which is the whole reason this finding matters. Both lost
`dynamodb:Query` on the *jobs* table, whose only caller is a test.

Execution roles split three ways because "which secrets may this agent read?" has three answers:
`execution_app` (worker + api, both secrets), `execution_redis` (the Redis token only), and
`execution_web` — the frontend, which now has **no Secrets Manager statement at all**. It was
carrying `GetSecretValue` on the OpenAI key for a container that declares no secrets and talks
to nothing in AWS.

The trap in this change is not the policies: `module.cicd` receives the role list as the deploy
role's `iam:PassRole` scope, and a role missing from it fails `RegisterTaskDefinition` with a
denial that names PassRole rather than the role. It is now `module.iam.all_role_arns`, derived
in the module, so adding a role cannot silently break the deploy.

### Container hardening

All four task definitions now set `user`, `readonlyRootFilesystem`, `cap_drop: ALL`,
`no-new-privileges` and a `nofile` ulimit.

**`linuxParameters.tmpfs` is EC2-only.** On Fargate the only writable-directory mechanism under
a read-only root is a task-level `volume {}` with no configuration block — ephemeral task
storage — plus `mountPoints`. The worker and API get one at `/tmp`; the worker genuinely needs
it because `TRIVY_CACHE_DIR=/tmp/trivy-cache` is baked into the image and Trivy needs scratch
space to extract layers. These are the first volumes in the stack. The frontend needs none (all
client components, no ISR, no `next/image`, and the runner image does not even copy
`.next/cache`) and neither does Redis (persistence already off).

`cap_drop: ALL` is safe throughout: registry mode needs no Docker socket and Fargate has none,
nothing binds a port below 1024, and privilege is dropped at build time so nothing needs
`CAP_SETUID`. The repo already runs Trivy itself under `--cap-drop=ALL` in socket mode.

### State locking, and a role that did not exist

- **`dynamodb_table` → `use_lockfile = true`.** The backend argument CI passed was deprecated in
  Terraform 1.11 and **removed in 1.13**, against a pinned 1.14.5 — so `init` errored on it and
  locking was not in place at all on a stack holding IAM roles and a secret. S3 has locked
  natively since 1.10, writing `<key>.tflock` beside the state. The bootstrap section of phase 12
  no longer creates a lock table.
- **`required_version` is bounded at both ends** — `>= 1.10.0, < 2.0.0`. The missing upper bound
  is *why* nothing caught the removal.
- **`AWS_TERRAFORM_ROLE_ARN` now exists.** `modules/cicd` creates it beside the build and deploy
  roles: same OIDC provider, trusted for the deploy branch *and* pull requests (a plan changes
  nothing, and a plan on a PR is the point), `ReadOnlyAccess` plus write on the state object and
  its lock. Plan-only — a compromised workflow can see the account's shape but not change it.
- **Both `||` fallbacks removed.** `secrets.X || secrets.AWS_DEPLOY_ROLE_ARN` meant a missing
  secret silently ran as the deploy role — which holds nothing on the state bucket, so the plan
  could not work even in principle, and failed confusingly instead of obviously.

### Verification

No AWS credentials and no state, so Terraform is checked statically — but the hardening is
proven for real, locally, which is the half that would otherwise only fail on deploy.

**1. The least-privilege split, asserted against the real config.** The two policy documents are
parsed out of `modules/iam/main.tf` and checked action by action — 15 assertions, all passing,
including the three that are easy to get backwards:

```
PASS  worker has the health-check permission   (sqs:GetQueueAttributes)
PASS  worker cannot enqueue                    (no sqs:SendMessage)
PASS  api cannot write reports                 (no s3:PutObject)
PASS  api has no ECR at all
PASS  neither can Scan or DeleteItem

worker actions (15) · api actions (5)
```

**2. A full scan through a genuinely hardened stack.** The local compose now applies the same
controls as the task definitions, so this is exercised rather than assumed. Confirmed by
`docker inspect`, not by the config that asked for it:

```
worker ReadonlyRootfs=true CapDrop=[ALL] User=worker
api    ReadonlyRootfs=true CapDrop=[ALL] User=api
```

and through that stack a scan of `auditor-eval:clean` completed: **14 findings, `degraded:
false`**.

**3. Local parity earned its keep immediately.** The read-only root broke the dev token signer —
`app/dev/keys.py` writes to `.dev-keys` relative to CWD. That path does not exist on Fargate
(`DEV_AUTH` is unset and CI asserts `/dev/token` returns non-200 after every deploy), so the fix
is a local-only tmpfs mount rather than a change to the deployed config. Worth stating plainly:
this is the class of breakage that otherwise appears for the first time as
`CannotStartContainerError` in a Fargate task.

**4. The KEV cache now actually caches.** In the running worker:

```
/tmp/enrichment-cache/kev.json   30089 bytes
$ touch /app/.enrichment-cache
touch: cannot touch '/app/.enrichment-cache': Read-only file system
```

The second line is the old default, and the reason the catalog was re-downloaded every scan.

**5. Suite.** 276 tests (was 274 — two new for the socket-mode guard), `ruff check`,
`ruff format --check`, `mypy app eval`, `terraform fmt -recursive -check`, `terraform validate`,
**docs gate 34/34**.

### Rollout note

The IAM split renames roles, so the first `apply` creates five and destroys two. Task definitions
referencing the old ARNs are replaced in the same apply. `aws_ecs_service.{worker,api,frontend}`
carry `ignore_changes = [task_definition]`, so — exactly as in §15 — the services stay on their
old revisions until a deploy moves them. Sequence the `update-service` calls in the same sitting,
and note the old roles cannot be deleted while a running task still references them.

### Deferred, with the reason

| Item | Blocker / cost |
|---|---|
| **ALB + TLS + WAF** | ACM will not issue for `*.elb.amazonaws.com`, so this needs a domain that does not exist in this stack — a hard external prerequisite, not a config gap. ~$16/mo ALB + ~$5/mo WAF. `CORS_ORIGINS` and the **build-time** `NEXT_PUBLIC_API_URL` would both have to change, and the latter means rebuilding the frontend image, not just re-applying. This is also what would make the deployed stack reachable at all (correction 3). |
| **VPC endpoints + egress to 443** | 4-6 interface endpoints at ~$7/mo each, plus free S3/DynamoDB gateway endpoints. Egress cannot be narrowed before they exist, because every AWS API call currently leaves via the IGW. The same cost trade the learning tier already makes on NAT. |
| **Detective controls** | SNS + CloudWatch alarms on DLQ depth and running-task count + a Budget are near-free and are the obvious next step; the DLQ still fills in total silence. CloudTrail's first management-event trail is free. GuardDuty and VPC flow logs carry ongoing cost. |

### Noted, not done

The `assume_role_policy` shared by every role in `modules/iam` has no `aws:SourceArn` /
`aws:SourceAccount` confused-deputy condition. Cheap to add and worth doing — but it is not part
of P4-4, and adding it quietly while the file was open would have put an unreviewed security
change in a diff about something else.

---

## 17. Frontend catch-up — landed

Five backend phases, zero frontend phases. `frontend/types/scan.ts` had not been touched since
the original build, so the UI's model of the API was five phases stale — and because the types
were *internally* consistent, `tsc --noEmit` passed and CI stayed green throughout. **The drift
was invisible to every gate this repo has**, which is the finding underneath all of the ones
below.

Rewriting the type file first was the method, not a chore: it turned the drift into eleven
compile errors and each one pointed at a component that was lying.

### The UI crashed on a finding the backend produces on every scan

`CATEGORY_ICON` had four keys and no `secret`. `FindingCard` read
`CATEGORY_ICON[finding.category]` and rendered `<Icon />`, which for a secret finding is
`undefined` — and React throws on that. There was **no `app/error.tsx`**, so the whole scan
report was replaced by Next's default error page.

TypeScript could not catch it: `Finding` was a four-member union without `SecretFinding`, so the
lookup type-checked as always-defined. Proven before fixing, with the test first:

```
Error: Element type is invalid: expected a string ... but got: undefined
Check the render method of `FindingCard`.
```

Fixed at the root rather than at the symptom. `SecretFinding` joins the union *and* an unknown
category now degrades: a fallback icon, a `default` arm on the evidence switch, and a route-level
error boundary. The first fixes today's category; the rest mean the next one the backend adds is
a missing label, not an outage.

> `app/error.tsx` takes `retry`, not `reset` — the prop was renamed in Next 16. Caught by reading
> `node_modules/next/dist/docs/`, which `frontend/AGENTS.md` exists to point at.

### The UI stated things that were not true

**Null scores rendered as a red 0/100.** The backend is explicit that `None` means "no
trustworthy evidence" and that showing it as zero is "the same class of lie this phase exists to
remove". The frontend typed all eight score fields as `number`. Verified in node:

```
null >= 80 → false     (so bandColor fell through to critical red)
Math.round(null) → 0
`${null}%` → "null%"   (an invalid CSS width, in ScoreBars)
```

So "we could not tell" displayed as "as bad as it gets", in red. Now the ring renders no numeral
at all — a dash reads as a value and `0/100` reads as a verdict, and null is neither.
`bandColor()` was duplicated identically in two components; it moved to `lib/format.ts`, because
two copies of the null handling would have diverged immediately.

**`skipped_missing_input` was invisible and did not count as degraded.** The sixth `AgentStatus`,
added in Phase 1 for exactly this, was missing from the frontend's five — so `AgentTimings`
rendered a blank status cell and `DegradedNotice` did not flag it. That is **P1-2 re-introduced
at the UI layer**: an agent that never saw its input read as a healthy row. The degraded
predicate was also written inline in three places, each omitting it; there is now one
`isDegraded()`.

**Suppressed findings rendered as live ones.** The policy layer marks rather than deletes on
purpose, so the report carries `suppressed` and its reason. The UI knew neither, so an accepted
risk was counted in every total, the severity strip, the effort breakdown and the filter chips —
which defeats the point of marking rather than deleting. They now render dimmed and badged, with
the reason, and are excluded from the counts but not from the report.

### Five phases of backend work were invisible

New: `CoverageNotice`, `ScanDiffSummary`, `ExportMenu`. Plus the CVE enrichment inside
`FindingCard` — package and installed version, **fixed-in version** (the single most actionable
field in a vulnerability report), CVSS score and vector, CWE ids, CISA KEV, EPSS as a
percentage, and the model's exploitability now labelled as a judgement to distinguish it from
the measured signals beside it.

`primary_url` replaces a guessed NVD link. The old code regex-matched `CVE-\d{4}-\d{4,}` and
linked nothing else, so every GHSA and vendor advisory was unlinkable — while the backend had
been supplying the authoritative URL all along.

Exports needed one structural change: `request<T>()` ended in `resp.json()`, so it could not
carry SARIF, CSV or JUnit at all. Split into `send()` (auth, error mapping) and `request<T>()`
(JSON on top), so the four formats reuse the error handling instead of copying it. The filename
comes from `Content-Disposition`, readable only because Phase 2B added `expose_headers` for it.

### A regression the backend had introduced

`ScanProgress` rendered `event.step` unfiltered. Since Phase 0 the orchestrator also publishes
per-node frames whose step is `f"{node}: {state}"`, so the live UI flickered `cve_analyst:
running` at the user in place of the four prose stage labels.

Progress still advances from every frame — that is what stopped the bar parking at 40% for the
whole agent phase — but the *label* now comes only from the last frame that named no node.

### Verification

**1. The crash, reproduced and then fixed.** The failing test came first and is quoted above.

**2. A real image with real secrets, end to end.** The existing eval images report
`total_secrets: 0`, which is why this path had never been exercised. Built a throwaway image
with two synthetic credentials — and note the first attempt failed honestly:
`AKIAIOSFODNN7EXAMPLE` is AWS's documented example key and Trivy allow-lists it. With patterns
Trivy actually flags, the full path works:

```
trivy secrets detected: 2
  aws-access-key-id | line 2 | AWS_ACCESS_KEY_ID = "********************"
  github-pat        | line 3 | GITHUB_TOKEN = "****...****"

report:
  critical | Hardcoded secret: AWS Access Key ID
     /app/settings.py:2 | rule: aws-access-key-id
     match: 'AWS_ACCESS_K... <redacted, 42 chars>'
  coverage.total_secrets: 2
```

That payload — captured verbatim from the live API, not hand-written — is now a test fixture,
because a hand-written fixture is a guess at the payload and the guess is what was wrong for
five phases. It asserts the page renders, that each secret's location is shown, and that
**neither credential shape ever reaches the DOM**: a report that leaked the secret it warns
about would be worse than no report.

**3. Suppression, live.** Suppressed one of those two findings through the policy store and
re-read the report:

```
secret findings still present: 2
  Hardcoded secret: AWS Access Key ID      | suppressed: True  | Fixture key, not real
  Hardcoded secret: GitHub Personal Access | suppressed: False |
```

Both present, one marked — the distinction the whole policy design rests on, now visible.

**4. Suite.** 45 frontend tests across 7 files (was 30 across 5), `tsc --noEmit`, `eslint`,
`next build`, docs gate 34/34, and the Python suite at 276 to confirm nothing backend moved.

### Deleted

`components/ScoreCard.tsx` — dead code, imported nowhere, still on pre-token `text-neutral-600`
classes. It would otherwise have needed the null-score fix for no reason.

### The real fix is not this phase

**There is no contract test between the Python models and the TypeScript types.** That is the
root cause of everything above, and hand-patching the mirror does not remove it — it just resets
the clock. The permanent answer is generating `types/scan.ts` from the API's OpenAPI schema,
which FastAPI already produces, and failing CI when the committed types differ. That is its own
change and is the single highest-value item left in this document.

Until then, the new tests are the partial substitute: they encode what the payload actually
looks like, using a fixture captured from the live API.

### Still open

The React Flow pipeline graph, tracked in [PIPELINE_GRAPH.md](PIPELINE_GRAPH.md) — backend
landed, frontend deferred, and it needs one dependency (`@xyflow/react`). The contract work
happened first deliberately: a graph over types that could not express half the payload would
have been built on the same sand.

Also still open: **P3-7**'s eval corpus, the deferred halves of **P4-4** (ALB/TLS/WAF, VPC
endpoints and egress, detective controls), **P4-5**, §8.1-8.2, and the `misconfig`/`license`
scanners.

---

## 18. Observability — landed

§8.2 said the plumbing could land alongside Phase 0 and pay for itself during the rest of the
work. It landed last instead, after the phases it was meant to measure. That ordering cost
something real and it is worth naming: every regression Phases 1-3 fixed was verified by
reading test output, because there was no production signal to check against. The controls
are correct as far as the tests reach, and nothing here can say whether they hold in the wild
until this stack has watched a few hundred real scans.

What §8.2 asked for is otherwise built, with two deliberate departures and one gap.

### What shipped

`observability/` holds the stack and `worker/app/telemetry/` holds the instrumentation.

| Piece | Where |
|---|---|
| OTLP collector, single egress, fans out to Prometheus and Loki | `observability/otel-collector.yaml` |
| Prometheus, one scrape target, 15d retention | `observability/prometheus.yml` |
| 7 alert rules across 3 groups | `observability/alerts.yml` |
| Loki 3, OTLP ingest, no promtail | `observability/loki.yml` |
| 5 dashboards + datasources, provisioned as files | `observability/grafana/` |
| 13 instruments, no-op unless configured | `worker/app/telemetry/metrics.py` |
| JSON logs, `job_id`/`tenant_id`/`repo_id` as fields | `worker/app/telemetry/logs.py` |
| Provider wiring, gated on `OTEL_EXPORTER_OTLP_ENDPOINT` | `worker/app/telemetry/setup.py` |

Every metric in §8.2's catalogue exists except `llm_cost_usd_total`, `scan_queue_depth`,
`dlq_depth` and `message_age_seconds`. The cost metric is deferred because a USD figure needs
a per-model price table that has to be maintained against a vendor's pricing page, and a
wrong number is worse than none; `llm_tokens_total` carries the raw counts a rate can be
derived from. The three queue gauges are point-in-time facts about SQS rather than events the
worker observes, so they belong to a poller that does not exist yet — `message_redelivery_total`
covers the part the worker can see, which is the part CloudWatch queue depth cannot give.

The whole layer is behind a compose profile. `docker compose up` is byte-for-byte the
experience it was before; `--profile observability` adds four containers.

### Two deliberate departures from §8.2

**No `/metrics` endpoint.** Covered in the note above §8.2's exposure paragraph. Both
processes push.

**No traces.** §8.2 called them optional and they stayed optional. The botocore, httpx and
redis instrumentors are installed by `_instrument()`, but no `TracerProvider` is ever set, so
they resolve to the API's no-op and cost nothing; the collector has no traces pipeline to
match. This is consistent, not half-finished — but it is the highest-value thing still
missing, because a span tree over one scan answers "which agent held this up" without anyone
reading a log.

### Verification

Run against the real stack, not reviewed on paper.

```text
prometheus target otel-collector   UP
alert rules loaded                 7, across 3 groups
grafana datasources                Prometheus (default), Loki — provisioned
grafana dashboards                 5 — provisioned
loki                               ingesting; {service_name="worker"} | json | job_id="..."
                                   returns that scan's lines, including boto3's and httpx's
```

Every panel expression in all five dashboards was evaluated against the live server:
**11 returned data, 9 returned empty, 0 returned an error.** Zero errors is the result that
matters — no panel names a metric the code does not emit, which is the defect this class of
work fails on most often. The nine empty panels are event-driven instruments that had no
events during the run.

The first scan through the instrumented pipeline returned `scan_result_total{outcome="degraded"}`
with four of eight agents at `status="failed"` — the OpenAI account was out of credits, HTTP
429 — and still produced a report. That is precisely the failure shape §1.2 and P2-1 describe,
and before this it was indistinguishable from success.

### A finding this work produced

**Three entrypoints run a scan; only two were instrumented.** `app/main.py` and
`app/api/main.py` both called `setup()`. `app/cli.py` — the CI gate, the one entrypoint that
runs unattended with nobody watching a terminal — still called `logging.basicConfig` and
emitted no metrics at all. Fixed by calling `setup("cli")`, which routes JSON to stderr and
leaves `--format json` on stdout machine-readable. Confirmed by running it: `agent_outcome_total`
now carries 8 series under `service_name="cli"` alongside 8 under `worker`.

`llm_tokens_total` shipped **unverified** — no model call in the verification run returned a
usage object to count, because of the 429s above.

### Still open

- **Nothing on AWS.** `terraform/modules/ecs/main.tf` has four `aws_cloudwatch_log_group`
  resources and nothing else: no `OTEL_*` in any task definition, no ADOT sidecar, no
  `aws_cloudwatch_metric_alarm`, no `aws_cloudwatch_dashboard`, no SNS topic. Deployed today,
  every instrument in this section pushes to an unset endpoint and does nothing. **This is the
  detective-control gap §1.3 names, and it is not closed.** A local Grafana is not a control.
- **Alert routing.** Seven rules evaluate against real series and reach no receiver. No
  Alertmanager locally, no SNS topic deployed — §8.2 routed these to a topic Phase 4 was to
  create and did not.
- **Traces**, per above.
- **`llm_cost_usd_total`** and the three SQS queue gauges.
