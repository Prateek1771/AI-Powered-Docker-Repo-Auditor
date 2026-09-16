# Observability

**Audience:** anyone debugging a scan that went wrong in production, or adding an
instrument.
**Scope:** the telemetry the running system emits and where it goes. How it was built is
[phase 14](../history/build-phases/14-observability.md); the finding that forced it is
[audit-01 §18](../audits/audit-01-backend.md) and [audit-02 §4](../audits/audit-02-frontend-worker-observability.md).

**Prerequisite:** the whole stack is gated on `OTEL_EXPORTER_OTLP_ENDPOINT`. Unset - the
default, and what CI runs - there is no exporter, no network call, and behaviour in the
tests and the eval harness is unchanged.

```bash
docker compose --profile observability up
```

---

## Why it exists

Every failure this project has had was one that does not raise. An agent that returns
`{"findings": []}` after being talked into it. A rate limiter that fails closed because
Redis is gone. A scan that drops 90% of its vulnerabilities to the token budget and reports
the rest as though that were the whole picture. None of these throw; all of them produce a
confident number computed from less evidence.

So the instruments are chosen to make *silent degradation* countable, not to measure
latency.

## Topology

```
worker / api  ──OTLP/HTTP :4318──▶  OTel Collector  ──▶  :8889  ◀──scrape── Prometheus
                                          │                                     │
                                          ├──▶ :8888 (its own health)  ◀────────┤
                                          └──▶ Loki  (structured logs)          │
                                                 │                              │
                        Bifrost :8080/metrics  ◀─┼──────────────────────────────┤
                                                 ▼                              ▼
                                              Grafana ◀──────────────────── 5 dashboards
```

One collector rather than three exporters in the application: the alternative was each
process owning its own exporter config, which is how two of them end up scraped
inconsistently. The collector runs a `memory_limiter` - under pressure a dropped batch
costs less than a restarted collector.

Prometheus scrapes three jobs: the collector's Prometheus exporter (`:8889`), the
collector's own internal telemetry (`:8888` - "is the thing that reports coping?"), and
the [LLM gateway](llm-gateway.md) (`:8080`), which knows two things the application cannot:
real USD per model, and whether a provider key still works.

## The instruments

Defined once in `worker/app/telemetry/metrics.py`.

**The scan as a whole**

| Instrument | What it catches |
|---|---|
| `scan_result_total{outcome}` | `failed` vs `degraded` vs `ok`, separately - a degraded scan is not a failed one, and collapsing them hides the interesting case |
| `scan_duration_seconds` | |

**The agents**

| Instrument | What it catches |
|---|---|
| `agent_outcome_total{agent,status}` | which agent degraded, not that something did |
| `agent_duration_seconds{agent}` | per-agent, so one slow agent is visible against five fast ones |
| `agent_guard_rejection_total{agent,reason}` | the prompt-injection regression signal. `reason` is carried as an attribute rather than parsed out of prose, so rewording a message cannot break the classification. `suppression` is the one that matters: a model talked into returning nothing |

**What the model cost**

`llm_tokens_total{agent,kind}` with `kind` in `input` / `output` / `cache_read`. LangChain
always attached usage to the response and nothing read it, so the only record of what a
scan cost was the invoice. USD is *not* computed here - see [the gateway](llm-gateway.md)
for why, and for where the real figure comes from.

**What the scan actually covered**

`vulnerabilities_found_total`, `vulnerabilities_analysed_total`, and
`vulnerabilities_dropped_total`. The third is the point: `python:3.8` yields 10,189 Trivy
findings and 150 reach the model. A report that does not say so is a report about 1.5% of
the image presented as a report about the image.

**The plumbing**

`ratelimit_decision_total{decision}` (including `fail_closed`), `heartbeat_failure_total`,
`message_redelivery_total`, `trivy_failure_total`.

## Alerts

`observability/alerts.yml`. Seven rules, each tied to a failure this codebase has actually
had:

| Alert | Fires on |
|---|---|
| `DegradedScanRate` | scans completing degraded, sustained 15m |
| `ScansFailing` | any sustained failure rate |
| `MostVulnerabilitiesDropped` | the coverage ratio collapsing |
| `GuardRejectionsRising` | `increase(...[1h]) by (reason) > 3` |
| `AgentsTimingOut` | |
| `RateLimiterUnavailable` | any `fail_closed` decision - Redis is gone and the API is returning 503 |
| `HeartbeatExhausted` | a worker that can no longer extend its visibility timeout |

`increase()` rather than `rate()` on the low-volume ones, and no percentile thresholds on
them: `histogram_quantile` returns `NaN` at this request volume, and an alert that cannot
fire is worse than none.

## Logs

Structured JSON with a correlation key, so a line found in Loki can be joined to the scan
that produced it. Anything set through `extra=` is emitted; everything `LogRecord` defines
by default is not.

## In the product

The Analytics page renders this data in-app rather than in a second tab nobody opens - four
tabs, one per source: Prometheus (what the pipeline did), OpenTelemetry (whether the
collector is coping), Gateway (what the models cost and whether the keys work), and Grafana
(the five provisioned dashboards, embedded).

The browser never queries Prometheus directly. `frontend/app/api/metrics/route.ts` is a
server-side proxy that accepts a **named panel** from a whitelist in `frontend/lib/panels.ts`
and never raw PromQL, which is why `PROMETHEUS_URL` is deliberately not a `NEXT_PUBLIC_`
variable. Charts are hand-rolled SVG in `frontend/components/charts/`, with a non-finite
guard before render - `histogram_quantile` over a sparse series returns `NaN`, and one
`NaN` poisons an entire SVG path.

Five dashboards are provisioned as files in `observability/grafana/dashboards/`:
`auditor-pipeline`, `auditor-agents`, `auditor-cost`, `auditor-queue`, `auditor-security`.

## Known sharp edges

- Counters reset when a container restarts, and Prometheus drops a series 5 minutes after
  its process goes away. A `cache_read` series that is simply absent means no cache hit has
  occurred *in the current worker process*, not that the instrument is broken - a
  distinction that cost real debugging time.
- Node-level progress frames are published to Redis but deliberately **not** written to the
  job row, so a live pipeline view cannot be replayed after the fact. Nine DynamoDB writes
  per scan to move a bar is a cost the row does not need.

---

## Related

- [Configuration](../operations/configuration.md) - `OTEL_EXPORTER_OTLP_ENDPOINT`
- [LLM gateway](llm-gateway.md) - cost and provider-key health
- [Phase 14](../history/build-phases/14-observability.md) - how it was built, with the code
- [Audit 02 §4](../audits/audit-02-frontend-worker-observability.md) - the instruments that shipped unverified
