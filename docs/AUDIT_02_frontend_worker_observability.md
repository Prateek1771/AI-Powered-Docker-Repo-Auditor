# Second Audit — Frontend, Worker, Observability

Scope: `frontend/`, `worker/`, `observability/`. Read against the working tree on
2026-09-16, with the stack running and a real scan pushed through it. Findings marked
**[verified]** were reproduced against the live system rather than reasoned about.

`docs/AUDIT.md` is the first audit and is still the reference for backend security; this
one does not repeat its findings. Where a finding here is the *residue* of one there, it
says so.

---

## 1. Executive summary

The code is in good shape. The first audit's P1-P3 fixes hold up under reading, the test
suites pass (284 worker, 45 frontend, `tsc --noEmit` clean), and the worker's concurrency,
tenancy and injection boundaries are carefully built and carefully explained.

Three things are wrong, and they share a shape: **each one passes every gate this repo
has and is still wrong at a boundary no gate looks at.**

### 1.1 The deployed product cannot log in

`frontend/lib/api.ts:24` is the only authentication path in the entire frontend, and it
calls `/dev/token` — the endpoint that exists only when `DEV_AUTH=1`.
`terraform/modules/ecs/main.tf:266` says "DEV_AUTH stays unset", correctly, because
`/dev/token` mints a token for any tenant to any caller. Cognito is provisioned
(`terraform/modules/auth/main.tf`), wired into the API's verification path, and referenced
by **no frontend code at all**.

So the deployed frontend calls an endpoint that 404s, `getToken()` throws *"Could not get a
token. Is the API running with DEV_AUTH=1?"*, and every page fails. TypeScript is clean and
45 tests pass, because the tests mock the API client and the type of a token is `string`
either way.

This is §17's finding recurring one layer out. There, the frontend's *model of the API* was
stale and internally consistent. Here, the frontend's *model of authentication* is a
development affordance and internally consistent.

### 1.2 The instrument built to catch a hang reads zero when things hang

**[verified]** `agent_duration_seconds` records `0` for six of the eight agents, including
every agent that failed or timed out. Live data from one scan:

```text
agent                    recorded sum   actual outcome
base_image_strategist    0              failed
bloat_detective          0              failed
compliance_checker       0              failed
risk_scorer              0              failed      (~21s of real wall time)
cis_controls             0              analysed    (never timed at all)
secret_scan              0              analysed    (never timed at all)
cve_analyst              1.91           skipped_no_input
dockerfile_optimizer     0.0021         skipped_degraded_input
```

§8.2 introduced this metric to catch P3-2 — whether the 300s visibility timeout is too
short. It is zero in precisely the cases that would answer that question.

### 1.3 Four of seven alert rules do not work

**[verified]** One fires when it should not, one watches a label no code path emits, and
two have thresholds this pipeline's throughput cannot reach. Detail in §4.

---

## 2. Methodology

Read every file in the three directories. Ran the stack (`--profile observability`),
pushed one scan of `alpine:3.18` through the API, evaluated every Grafana panel expression
and every alert expression against the live Prometheus, and queried Loki for the resulting
log stream. Ran the worker suite, the frontend suite and `tsc --noEmit`.

The OpenAI account was out of credits throughout, which produced a genuinely degraded scan
— four agents returning HTTP 429. That was useful: the degraded path is the one this
pipeline is built around and the hardest to exercise deliberately.

---

## 3. F1 — The frontend cannot authenticate anywhere but a laptop

**Severity: critical. The product does not work as deployed.**

`frontend/lib/api.ts:19-41`:

```ts
export async function getToken(): Promise<string> {
  if (cachedToken && Date.now() < cachedToken.expiresAt) {
    return cachedToken.value;
  }

  const resp = await fetch(`${API_URL}/dev/token`);
```

Every authenticated call in the frontend routes through this — `send()`, `uploadImage()`
and `useScanProgress`'s WebSocket all call `getToken()`. There is no other token source:

```text
grep -rn "getToken|dev/token|cognito|oauth" frontend/
  -> 3 call sites, all of getToken(); zero references to Cognito or OAuth
```

Meanwhile the backend is ready for the real thing. `verify_token` checks signature,
audience, issuer, expiry and `token_use` against a JWKS URL, and
`app/config/api.py:59-98` refuses to start with dev defaults outside a local run. The
identity provider exists in Terraform. Only the browser half was never written.

**Fix.** Either wire the frontend to Cognito's hosted UI (authorization-code + PKCE, token
in memory, refresh on 401), or state plainly in the README that the deployment is
API-only and the UI is local-development. The second is a one-line change and an honest
one; the first is a phase. What should not persist is a deployed, paid-for Cognito pool
and a UI that cannot reach it.

**Related, lower severity.** `getToken()` has no in-flight deduplication: the scan page
mounts several components that call it concurrently on first paint, and each cache miss
issues its own request. Harmless against `/dev/token`; against a real token endpoint with
its own rate limit, less so.

---

## 4. Observability — the instruments

### F2 — `agent_duration_seconds` is zero for most agents **[verified]**

**Severity: high for the metric's stated purpose.**

Two separate causes.

**Failed and timed-out agents.** `orchestrator.py:_degrade()` builds an `AgentOutcome`
without `duration_seconds`, and `models/outcomes.py:45` defaults it to `0.0`:

```python
return AgentOutcome(
    agent=name,
    status=status,
    findings=[],
    error=str(error) or error.__class__.__name__,
)
```

`_timed()` does record it, but an agent killed by `asyncio.wait_for` never reaches
`_timed`'s return statement — which is exactly the reasoning the code already applies, one
block down, to explain why `agent_outcome` is recorded in a separate pass:

> *"an agent killed by `asyncio.wait_for` never reaches its recording lines at all - so
> hanging this off `_timed` would omit precisely the failures worth alerting on."*

The argument is right and was applied to the counter but not to the histogram.

**The two deterministic agents.** `cis_controls` and `secret_scan` are constructed as
literal `AgentOutcome(...)` values (`orchestrator.py:229`, `:240`) and never pass through
`_timed`, so they always record `0`. They are genuinely fast, but a bucket at `le="0"` is
still not a measurement.

The visible result is that `agent_duration_seconds_bucket{le="0"}` collects most
observations, so the "Agent duration (p95)" panel reports near-zero latency *while agents
are hanging* — it is anti-correlated with the thing it exists to show.

**Fix.** Pass the elapsed time into `_degrade`, and time the two deterministic outcomes.
Roughly:

```python
def _degrade(name: str, error: Exception, elapsed: float = 0.0) -> AgentOutcome:
    ...
    duration_seconds=elapsed,
```

with the caller supplying `time.perf_counter() - start`. The four independent agents need a
start timestamp captured before `gather`, since their own `_timed` frame is gone by then.

### F3 — `RateLimiterFailingOpen` watches a label nothing emits **[verified]**

**Severity: high. A `critical`-severity alert that cannot fire.**

`observability/alerts.yml` alerts on `ratelimit_decision_total{decision="fail_open"}`.
In `core/ratelimit.py` that label is only produced on the `fail_open=True` branch:

```python
_decided(action, "fail_open" if fail_open else "fail_closed")
```

`check_limit()` defaults to `fail_open=False`, and **every caller uses the default** —
`scan_rate_limit` is the only wrapper, and `api/scans.py:32` and `api/images.py:53` are
the only routes. The `fail_open=True` path has no callers anywhere in the repo.

Live confirmation: the only series that exists is `{decision="allowed", action="scan"}`.

This is the first audit's P3-3 fix working correctly — the limiter was changed to fail
*closed* — with the alert left pointing at the behaviour that was removed. The comment
above the rule still describes the old semantics.

The real risk moved with the fix and is now unalerted: when Redis is unreachable the
limiter raises **503 on every scan**. That is a full outage of the product's only
write path, and it emits `decision="fail_closed"` with nothing watching.

**Fix.** Re-point the rule at `fail_closed` and re-word it as an availability alert. If
the `fail_open=True` parameter is genuinely dead, delete it.

### F4 — Two rules have thresholds this pipeline cannot reach **[verified]**

**Severity: medium.**

```text
AgentsTimingOut        rate(...[15m]) by (agent) > 0.05   = 45 timeouts per agent per 15m
GuardRejectionsRising  rate(...[15m]) by (reason) > 0.1   = 90 rejections per 15m
```

A scan runs each agent once. For `AgentsTimingOut` to fire, one agent would have to time
out 45 times in 15 minutes — 45 scans in 15 minutes, all timing out on the same agent. The
rule is named for the condition "an agent is timing out" and will not fire for it.

`GuardRejectionsRising` is the stated production regression signal for the prompt-injection
work. At 90 rejections per 15 minutes, a targeted campaign against the suppression path at
this pipeline's throughput is invisible.

**Fix.** These want absolute counts over a window, not per-second rates:
`increase(agent_outcome_total{status="timed_out"}[1h]) > 3`. Rate thresholds are a habit
from high-QPS services and do not transfer to a pipeline that runs single-digit scans an
hour.

### F5 — `DegradedScanRate` fires on a single degraded scan **[verified]**

**Severity: medium. This one fired on the verification run.**

```yaml
expr: sum(rate(scan_result_total{outcome="degraded"}[15m]))
        / clamp_min(sum(rate(scan_result_total[15m])), 0.001) > 0.2
for: 15m
```

The `clamp_min` guards division by zero but not *low volume*. With one degraded scan and
nothing else, numerator and denominator are the same tiny number and the ratio is exactly
`1.0`.

Measured against the live server over the three hours after one degraded scan:

```text
peak ratio                    1.0
consecutive minutes > 0.2     16
alert requires                > 0.2 sustained for 15m
verdict                       WOULD FIRE
```

Sixteen minutes above threshold against a `for: 15m` clause — it fires by one minute. The
comment directly above the rule reads *"A single degraded scan is normal; a fifth of them
is a broken agent nobody was told about."* The expression does not implement the comment.

**Fix.** Gate on volume:

```promql
... > 0.2 and sum(rate(scan_result_total[15m])) > 0.01
```

### F6 — 15-day retention on storage that does not survive a restart

**Severity: medium (local), and it undercuts §18's own claims.**

`docker-compose.yml` sets `--storage.tsdb.retention.time=15d` on Prometheus, and neither
Prometheus nor Loki has a data volume — both mount only their read-only config. The
`volumes:` block at the bottom declares `dynamodb-data` and `blobs` and nothing else.

So every metric and every log is in the container writable layer and is gone on
`docker compose down`, or on any image bump. Configuring a fortnight of retention on
storage with a lifetime of one `down` is a contradiction, and it quietly defeats the point
of `GuardRejectionsRising` — a regression signal you cannot compare against last week is
not a regression signal.

**Fix.** Two named volumes, three lines. The retention setting then means what it says.

### F7 — No `memory_limiter` in the collector pipeline

**Severity: low.**

`observability/otel-collector.yaml` has `batch` and nothing else. The collector is the
single egress point for every signal, so it is also the single point that OOMs under a
burst, taking metrics and logs down together at exactly the moment they are interesting.
`memory_limiter` first in the processor list is the standard remedy and is four lines.

### F8 — `llm_tokens_total` documents a `kind` it never records

**Severity: low, but it is a doc-versus-code drift of the kind this repo gates against.**

`metrics.py` describes the counter as *"Tokens by agent and kind (input, output,
cache_read)"*. `agents/runner.py:_record_usage` iterates exactly two kinds:

```python
for kind, key in (("input", "input_tokens"), ("output", "output_tokens")):
```

Cache reads are where the money actually goes once prompts stabilise, and a dashboard
legend promising a third series that never appears reads as a broken panel.

Related: §18 already records that `llm_tokens_total` shipped unverified. It is still
unverified — the account has no credits, so no usage object has ever been returned.

---

## 5. Worker

The worker is the strongest part of this codebase. The concurrency handling in
`orchestrator.py` and `queue/consumer.py` is genuinely careful — `return_exceptions=True`
with an explicit `BaseException` re-raise so a SIGTERM is not recorded as an agent failure,
`to_thread` on every blocking boto3 call, the unparseable-body path deleting rather than
burning redeliveries, the atomic Lua sliding window with `EXPIRE` after `ZADD`. Tenancy is
enforced on every read path, and missing-versus-forbidden correctly collapse to one 404.

Four things worth changing, none of them structural.

### F9 — An unknown `kid` forces an uncached JWKS fetch, before any rate limit

**Severity: medium.**

`core/auth.py:_find_key()` refreshes the JWKS when a token's `kid` is unknown:

```python
logger.info("Unknown kid %s, refreshing JWKS", kid)

key = next(
    (k for k in _fetch_jwks(force=True) if k["kid"] == kid),
    None,
)
```

`force=True` bypasses the cache. This runs inside `current_principal`, which is the
dependency the rate limiter *wraps* — so it happens before any quota is consulted, on a
request that has not proved anything. An unauthenticated caller sending tokens with random
`kid` values drives one outbound HTTPS request to the identity provider per inbound
request, with a 10-second timeout each and no upper bound.

The rotation handling is correct and worth keeping. What is missing is a floor on how often
a forced refresh may happen.

**Fix.** A cooldown — refuse a forced refresh within, say, 60 seconds of the last one and
fall through to 401. Two lines against the existing `_jwks_cache["fetched_at"]`.

### F10 — `repo_id` is unvalidated where `target` is carefully validated

**Severity: low.**

`api/models.py` constrains `target` with a deliberate pattern and a good comment about
`trivy image ... <target>` parsing flags positionally. `repo_id` next to it gets only
`Field(min_length=1, max_length=200)`.

`repo_id` reaches `tenant_repo_key()` as `f"{tenant_id}#{repo_id}"`. Cross-tenant collision
is *not* possible — `tenant_id` is the Cognito `sub` and contains no `#`, so the key parses
unambiguously from the left. The exposure is limited to a tenant confusing its own history,
plus whatever a 200-character arbitrary string does to the frontend (see F11).

**Fix.** Give it the same treatment as `target`: a conservative pattern.

### F11 — Frontend interpolates path segments without encoding

**Severity: low.**

`lib/api.ts` builds every path by template literal:

```ts
return request<ScanSummary[]>(`/api/v1/scans/history/${repoId}`);
```

`repoId` is user-entered and unvalidated server-side (F10). A value containing `/`, `?`,
`#` or `..` changes which endpoint is called — `fetch` normalises `..` before the request
leaves the browser. The caller only ever attacks themselves with their own token, so this
is correctness rather than security, but `encodeURIComponent` is the one-word fix and it is
already used correctly for the WebSocket token.

### F12 — A new model client per agent invocation

**Severity: low.**

`agents/runner.py:run_structured_agent` calls `build_client()` on every invocation — eight
per scan — and each `ChatOpenAI` owns an httpx client that is never closed. Connection
pools are not reused across agents or scans, and sockets are left to the garbage collector.

A module-level client built once would be the obvious shape, since every agent uses
identical settings.

### Also noted, not findings

- The WebSocket carries its JWT in the query string (`?token=`), which lands in proxy and
  access logs. This is a browser limitation rather than a design error — the WebSocket API
  cannot set headers — but the tokens are 1-hour and the exposure is real. A short-lived
  ticket exchanged for the socket is the usual mitigation.
- `/ws/jobs/{job_id}` has no per-tenant connection cap. Each accepted socket holds a Redis
  pubsub connection, and the same token opens arbitrarily many.
- `check_limit`'s `fail_open` parameter is dead (see F3).

---

## 6. Frontend

`tsc --noEmit` is clean, 45 tests pass across 7 files, and there is no `dangerouslySetInnerHTML`
anywhere — model-authored prose is rendered as text throughout, which is the right call for
a tool whose input is attacker-controlled. `useScanProgress` is a careful piece of work:
jittered backoff, a `cancelled` flag checked after every await, correct handling of close
codes 1000 and 1008, and an `abandoned` state the page surfaces instead of spinning forever.
`types/scan.ts` has kept pace with the backend — `coverage`, `diff`, `packages`,
`kev_listed`, `epss_score` and the suppression fields are all present and correctly optional.

Beyond F1 and F11, the substantive gap is that backend work is again invisible.

### F13 — `profile` is stored in every report and rendered nowhere

**Severity: medium.**

`storage/results.py:112` writes `profile` into every report blob. The frontend has zero
references to it — it is not in `FullReport` in `types/scan.ts`, and no component reads it.

What is in it (`processors/profile.py`): `os_family`, `os_name`, `base_reference`, `user`,
`exposed_ports`, `env_keys`, `entrypoint`, `cmd`, `has_healthcheck`, `layer_count`,
`total_size_bytes`.

That list matters more than most report content, for a specific reason the first audit
established: it is read from the image config **before any model is called**, so no amount
of injected text can change it, and it survives every agent failing. On the verification
run — four agents down, risk score null, scores blank — the profile was the only
trustworthy content in the report, and the UI showed none of it.

"Runs as root, no healthcheck, exposes 22" is a security finding a user can act on, derived
deterministically, already computed, already stored, already paid for.

### F14 — The SBOM is stored, exported, and never shown

**Severity: low.**

`packages` is in `types/scan.ts` as `Package[]`, is written to every report blob, and
CycloneDX export renders it. No component displays it. A user can download the SBOM but
cannot see it — and the download is the less likely path for someone who came to look at a
scan.

---

## 7. What this codebase gets right

Worth recording, because the findings above are a short list against a lot of code.

- **Degradation is data, not a log line.** `AgentOutcome.is_trustworthy` distinguishing
  `skipped_no_input` from `skipped_missing_input` is the single best idea here, and it is
  applied consistently from the model layer through to the UI's dashed ring.
- **The untrusted fence strips its own end marker.** `untrusted_block()` removes `_FENCE_END`
  from the payload rather than escaping it. Most implementations of this pattern do not.
- **The suppression guard.** `assert_not_suppressed` is deliberately outside the retry loop
  so a rejected model cannot argue its way past it on attempt two, and the comment says why.
- **Comments explain the rejected alternative.** `to_thread` on boto3 calls, `EXPIRE` after
  `ZADD`, `Exception` rather than `BaseException` in the gather loop, accepting the
  WebSocket before closing it so the browser sees 1008 rather than 1006 — each names the bug
  that the obvious version causes. This is rare and it is why the audit above is short.
- **The docs gate.** `check_code_blocks.py` enforcing that every phase-doc code block still
  matches its file is a real control, and it currently passes 40/40.

---

## 8. Remediation order

| # | Finding | Why this order |
|---|---|---|
| 1 | **F1** frontend auth | The product does not work as deployed. Everything else is a quality issue on a system nobody can reach. |
| 2 | **F3** fail_open alert | A `critical` rule that cannot fire is worse than no rule; the live failure mode is unwatched. |
| 3 | **F2** agent duration | Small diff, and it unblocks the P3-2 question §8.2 raised. |
| 4 | **F5, F4** alert thresholds | Cheap, and F5 is actively generating a false positive. |
| 5 | **F9** JWKS cooldown | Two lines, pre-auth amplification. |
| 6 | **F6** volumes | Three lines; makes retention mean something. |
| 7 | **F13** profile in UI | The highest-value content currently invisible. |
| 8 | F7, F8, F10, F11, F12, F14 | Low, batchable. |

Nothing here needs a redesign. F1 needs a decision — build Cognito into the UI, or say in
the README that the deployment is API-only — and the rest are small diffs against code that
is, on the whole, unusually well reasoned.

---

## 9. Remediation — landed

All fifteen are fixed. What follows separates what was *proved* from what was only
*written*, because three of the original findings were things that read correctly and
behaved wrongly, and that distinction is the whole lesson of this audit.

### F16, found while fixing

**`TOKEN_ISSUER` was never set on the API task.** `terraform/modules/ecs/main.tf` passed
`JWKS_URL`, `TOKEN_AUDIENCE` and `CORS_ORIGINS` and stopped there.
`assert_production_auth()` treats an unset `TOKEN_ISSUER` as a refuse-to-start condition —
correctly, because `python-jose` skips issuer validation entirely when none is supplied —
so the deployed API raised `InsecureAuthConfig` and crash-looped. The guard did its job;
nobody had run it. Fixed with a new `issuer` output on the auth module, a `token_issuer`
variable on the ECS module, and one line in `terraform/main.tf`.

That makes F1 a two-sided break: the API would not start, and the frontend could not have
logged into it if it had.

### Verified by running

| # | Evidence |
|---|---|
| **F2** | Same scan, before and after, side by side. Before: `base_image_strategist 0.00000`, `bloat_detective 0.00000`, `compliance_checker 0.00000`, `risk_scorer 0.00000`, `cis_controls 0.00000`, `secret_scan 0.00000` — six of eight. After: `28.09499`, `28.09423`, `28.09558`, `23.86212`, `0.00035`, `0.00001`. Every agent now reports real time, and the four that failed report the ~28s they actually spent. |
| **F4, F3** | All 7 rules load with no parse error, including the renamed `RateLimiterUnavailable`. |
| **F7** | Collector recreated with `memory_limiter` first in both pipelines; 0 errors in its log. |
| **F6** | `prometheus-data` and `loki-data` volumes created and mounted. |
| **F11, F13, F14** | `tsc --noEmit` clean; 49 frontend tests pass (45 before, 4 new). |
| **F9, F10, F12, F8** | 284 worker tests pass. The one failure, `test_eval_gate.py::test_recall_meets_threshold`, is a live OpenAI call against an account with no credits and predates this work. |

### Written but not proved, and why

Saying so is the point of the section.

- **F3** — the limiter now records `fail_closed` and the alert watches it. Proving it
  end to end needs Redis taken down under a live scan, which was not done. The change is
  a label rename on a path that already executed; the risk is low but it is not zero.
- **F5** — the guard is `and sum(rate(scan_result_total[15m])) > 0.01`. One scan in
  fifteen minutes is `1/900 = 0.0011`, comfortably under the floor, so the single-scan
  case that fired before cannot. The original sixteen-minute reproduction could not be
  re-run because F6's new volume discarded the TSDB that held it. Arithmetic, not
  measurement.
- **F8** — `llm_tokens_total{kind="cache_read"}` is still unverified for the same reason
  it was unverified in §18: no model call has returned a usage object. It was already the
  one instrument shipped blind and it still is.
- **F1, F16** — `terraform validate` passes and the dev-auth path is covered by new
  tests that assert *which* branch runs. A real Cognito round trip is not reachable from
  here. **The SRP sign-in has never spoken to a Cognito pool.** That is the honest state
  of it, and it is the first thing to exercise on the next deploy.

### What changed, by area

**Auth (F1, F16).** `frontend/lib/auth.ts` does SRP against the pool as provisioned —
`ALLOW_USER_SRP_AUTH`, no domain, no callback URL, so no hosted-UI infrastructure and no
stable hostname required. `frontend/app/login/page.tsx` is the form;
`frontend/components/AuthGate.tsx` redirects once in the layout rather than in every page.
`getToken()` picks Cognito when `NEXT_PUBLIC_COGNITO_*` are set and `/dev/token` when they
are not, so local runs are untouched. It returns the **ID** token, because
`EXPECTED_TOKEN_USE = "id"` and `TOKEN_AUDIENCE` is the client id — only an id token
carries that as `aud`. A 401 now clears the session instead of surfacing as a failed
request. The ids are `NEXT_PUBLIC_*`, so they bake in at image build: they are Docker
build args in `docker-compose.yml`, `frontend/Dockerfile` and the CI build step, not task
environment.

**Observability (F2-F8).** `_degrade()` takes the elapsed time from its caller, because it
is reached precisely when `_timed()` was not; the two deterministic outcomes are timed
rather than left at the default. The dead `fail_open` parameter is gone from
`check_limit()` along with the branch it guarded. The two model alerts moved from
per-second rates to `increase(...[1h])`. `memory_limiter` leads both collector pipelines.
Cache-read tokens are recorded.

**Worker (F9, F10, F12).** A 60-second floor under forced JWKS refreshes, so an unknown
`kid` can no longer drive one outbound request per inbound one ahead of the rate limiter.
`repo_id` gets a pattern. The `ChatOpenAI` client is built once rather than eight times a
scan.

**Frontend (F11, F13, F14).** Path segments are encoded. `ImageProfileCard` renders the
deterministic image facts that were stored on every report and shown on none — placed
above coverage and findings deliberately, because when every agent has failed it is the
only section with anything trustworthy in it, and it calls out running as root.
`PackagesTable` shows the SBOM.

### Still open, unchanged by this work

Everything §18 listed: nothing pushes telemetry on AWS, the seven rules still route
nowhere, there is no Alertmanager and no SNS topic, and traces remain deliberately absent.
Those are infrastructure, not defects in the three areas this audit covered.
