# Phase 14 - Observability: Instruments for a Pipeline That Had None

Thirteen phases built a scanner. None of them built a way to know it was working.

```text
worker -+
api    -+- OTLP push --> OpenTelemetry Collector -+- :8889 scrape -> Prometheus -+
cli    -+                                         |                              +-> Grafana
                                                  +- OTLP --------> Loki --------+
```

The rule for this phase:

```text
a metric you cannot tie
to a job_id is a number,
not an answer
```

---

# 1. The finding: every failure in this repo was invisible

The audit that drives this phase opens section 8.2 with a one-line verification: grep the
repository for `opentelemetry|prometheus|otel|statsd|grafana|loki` and nothing comes back.
Both entrypoints called `logging.basicConfig` with a plain-text format, and that was the
whole observability story.

That matters more here than in most projects, because of what this pipeline does when it
goes wrong. It does not crash. It **degrades**:

```text
an agent times out          -> the report is missing a section
the model returns bad JSON  -> the guard rejects it, the section is empty
Trivy finds 400 CVEs        -> 40 reach the model, 360 are dropped silently
the rate limiter fails open -> every request is allowed, the bill is the only signal
the heartbeat dies          -> the message redelivers, two workers scan the same image
```

Every one of those produces a 200 response and a report that looks like a report. The
difference between a clean image and an image nobody actually looked at is a field in a
JSON blob that nothing aggregates. That is the gap this phase closes, and it is why the
metric list below is not a generic RED-method dashboard - each instrument exists because
the audit found a specific failure that had no signal.

---

# 2. One collector, not three exporters

The application speaks OTLP to a single collector and never learns what is behind it.

```text
without a collector              with one

app imports prometheus_client    app imports opentelemetry
app imports a loki handler       app pushes OTLP
app imports an otlp tracer       collector fans out

swapping Loki for CloudWatch     swapping Loki for CloudWatch
= a code change, a rebuild,      = four lines of collector YAML
  a redeploy
```

That is the whole argument. On Fargate the collector becomes a sidecar in each task
definition and the application does not change. The alternative - three exporter libraries
wired into `app/` - puts a deployment decision inside the code that runs the scan.

---

# 3. The instruments

`app/telemetry/metrics.py`:

```python
"""The instruments, created once and imported by the call sites.

Every one of these corresponds to a failure this audit found and could not
otherwise observe in production: the degraded-scan rate, the vulnerabilities
dropped before the model ever sees them, the rate limiter refusing every scan
because Redis is gone, the guard rejections that are the regression signal for
the injection work, and a heartbeat that dies silently into duplicate
concurrent scans.

Instruments are built at import and are safe to call whether or not a provider
was ever installed. OpenTelemetry's own API returns a no-op meter when no SDK
is configured, and _NoopInstrument covers the case where the `otel` extra is
not installed at all - so no call site needs an `if enabled` guard, and adding
a metric never adds a branch to the hot path.
"""

from typing import Any


class _NoopInstrument:
    """Stands in for a counter or histogram when OpenTelemetry is absent."""

    def add(self, amount: float, attributes: dict | None = None) -> None:
        pass

    def record(self, amount: float, attributes: dict | None = None) -> None:
        pass


def _meter() -> Any:
    try:
        from opentelemetry.metrics import get_meter
    except ImportError:
        return None

    # Deliberately before any provider is set: OpenTelemetry's meter is a
    # proxy that picks up the real provider when setup() installs one, so
    # import order between this module and setup() does not matter.
    return get_meter("app")


_m = _meter()


def _counter(name: str, unit: str, description: str) -> Any:
    if _m is None:
        return _NoopInstrument()

    return _m.create_counter(name, unit=unit, description=description)


def _histogram(name: str, unit: str, description: str) -> Any:
    if _m is None:
        return _NoopInstrument()

    return _m.create_histogram(name, unit=unit, description=description)


# --- the scan as a whole -------------------------------------------------

scan_result = _counter(
    "scan_result_total",
    "1",
    "Scans by outcome: clean, findings, degraded or failed.",
)

scan_duration = _histogram(
    "scan_duration_seconds",
    "s",
    "Wall time per scan stage: fetch, agents, store.",
)

# --- the agents ----------------------------------------------------------

agent_outcome = _counter(
    "agent_outcome_total",
    "1",
    "Agent runs by agent and status. A rising timed_out or "
    "skipped_missing_input rate is a degraded report nobody was told about.",
)

agent_duration = _histogram(
    "agent_duration_seconds",
    "s",
    "Wall time per agent.",
)

agent_guard_rejection = _counter(
    "agent_guard_rejection_total",
    "1",
    "Model responses refused by a guard, by reason: schema, non_json, "
    "hallucinated_id or suppression. The production regression signal for "
    "the prompt-injection work.",
)

# --- what the model cost -------------------------------------------------

llm_tokens = _counter(
    "llm_tokens_total",
    "1",
    "Tokens by agent and kind (input, output, cache_read). Counted per "
    "attempt, so a retry storm shows up here rather than only on the bill.",
)

# --- what the scan actually covered --------------------------------------

vulnerabilities_found = _counter(
    "vulnerabilities_total",
    "1",
    "Vulnerabilities reported by the scanner, by severity.",
)

vulnerabilities_analysed = _counter(
    "vulnerabilities_sent_to_model_total",
    "1",
    "Vulnerabilities that reached an agent.",
)

vulnerabilities_dropped = _counter(
    "vulnerabilities_dropped_total",
    "1",
    "Vulnerabilities counted and then discarded before analysis. The "
    "difference between a report and a sample presented as one.",
)

# --- the plumbing --------------------------------------------------------

ratelimit_decision = _counter(
    "ratelimit_decision_total",
    "1",
    "Rate limit decisions by action and decision: allowed, rejected or "
    "fail_closed. fail_closed means Redis is unreachable and every scan "
    "is being refused - a full outage of the only write path there is.",
)

heartbeat_failure = _counter(
    "heartbeat_failure_total",
    "1",
    "Visibility-heartbeat failures by reason. Exhaustion means the message "
    "becomes visible again while this worker is still scanning it.",
)

message_redelivery = _counter(
    "message_redelivery_total",
    "1",
    "Queue messages received more than once. The per-message signal "
    "CloudWatch queue depth cannot give.",
)

trivy_failure = _counter(
    "trivy_failure_total",
    "1",
    "Scanner failures by classification: permanent, retryable, timeout or "
    "empty_output. Validates the permanent/retryable split against reality.",
)
```

Two things in there are worth slowing down for.

**The no-op fallback is what makes the call sites clean.** Every instrument is created at
import time and is safe to call whether or not anything is configured. OpenTelemetry's API
already returns a no-op meter when no SDK is installed; `_NoopInstrument` covers the
narrower case where the `otel` extra was never installed at all and the import itself
fails. The payoff is at the call site:

```python
metrics.agent_outcome.add(1, {"agent": name, "status": status})
```

No `if telemetry_enabled:`. No recorder object threaded down through six layers. Adding a
metric never adds a branch to the scan path, which means adding a metric never adds a way
for the scan path to break.

**`vulnerabilities_dropped_total` is the one to watch.** The audit's finding P2-3 is that
truncation is silent and unrecoverable: the scanner counts 400 vulnerabilities, 40 go to
the model, and the report says nothing about the other 360. The counter is three numbers -
found, analysed, dropped - and the ratio between them is the honest answer to "did you
actually look at this image?"

---

# 4. Structured logs and the correlation key

`app/telemetry/logs.py`:

```python
"""Structured logs, so a failed scan can be found by its job id.

Before this the pipeline logged plain text and interpolated the job id into
the message body, which meant the one identifier that ties a scan together
could not be filtered on - you could read a failure but not find the rest of
its story. tenant_id and repo_id were threaded through run_and_store and
appeared in no log line at all.

The job context is a contextvar rather than a logger argument so that records
emitted by boto3, httpx and langchain - which know nothing about this project -
carry the correlation key too. contextvars are copied into asyncio.to_thread,
which matters here: store_result, update_progress and every SQS call run
there.
"""

import contextvars
import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager

# Everything LogRecord defines. Anything else on a record was put there by an
# `extra=`, and is worth emitting.
_STANDARD = frozenset(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {
    "message",
    "asctime",
    "taskName",
    # uvicorn attaches an ANSI-coloured copy of its own message. Useful in a
    # terminal, noise in a log store.
    "color_message",
}

# Default None rather than {}: a mutable default on a ContextVar is shared by
# every context that never sets one.
_job: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar(
    "job", default=None
)


def _fields() -> dict[str, str]:
    return _job.get() or {}


@contextmanager
def job_context(**fields: str) -> Iterator[None]:
    """Attach these fields to every log record emitted inside the block."""
    token = _job.set({**_fields(), **{k: v for k, v in fields.items() if v}})

    try:
        yield
    finally:
        _job.reset(token)


class JobFilter(logging.Filter):
    """Copy the job context onto every record the handler is about to emit.

    A filter on the handler rather than fields read by the formatter, because
    there are two handlers: one writing JSON to stdout and one exporting to
    the collector. Injecting here means both see the same fields, and the
    exporter carries the correlation key as a log attribute rather than only
    inside a formatted string.

    Handler-level, not logger-level: a filter on a logger never runs for
    records that propagate up from boto3 or httpx, which are exactly the
    records worth correlating.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in _fields().items():
            setattr(record, key, value)

        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line, which is what a log pipeline can index."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Keep whatever a caller passed as extra=, so a metric label and its
        # log line can carry the same attribute names.
        payload.update({k: v for k, v in record.__dict__.items() if k not in _STANDARD})

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_logging(service: str) -> None:
    """Replace the root handler with one that emits JSON.

    Explicitly, not via basicConfig: that is a no-op once the root logger has
    handlers, and under uvicorn it is already partially inert because uvicorn
    installs its own configuration before this module is imported. Formatting
    uvicorn's own loggers too is the difference between structured application
    logs and a mix of JSON and prose in the same stream.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(JobFilter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)

    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = True

    logging.getLogger("app.telemetry").info(
        "Structured logging enabled", extra={"service": service}
    )
```

The design decision here is the contextvar.

Before this, `job_id` was interpolated into message bodies, which means you can read a
failure but you cannot find the rest of its story. A substring search across a log store is
not a filter; it breaks the moment two ids share a prefix or a message wraps.

```text
job_id in the message        job_id as a field

grep, and hope               {job_id="b6fdc89f-..."}
one line                     every line from that scan
breaks on line wrapping      including boto3's and httpx's
```

That last point is why it is a contextvar and a filter on the *handler*, rather than an
argument to each logging call. Records emitted by boto3, httpx and langchain know nothing
about this project, and they are exactly the records you need when the failure is in a
transport. A handler-level filter tags them anyway. And because contextvars copy into
`asyncio.to_thread`, the correlation survives into `store_result`, `update_progress` and
every SQS call - all of which run there.

---

# 5. Wiring it up

`app/telemetry/setup.py`:

```python
"""Wire the process up to an OpenTelemetry collector, if one is configured.

Both processes push OTLP rather than exposing a scrape endpoint. The audit
suggested an in-process /metrics route for the API, which does not work here:
the API runs `uvicorn --workers 2`, so an in-process registry lives in one of
two processes and Prometheus would scrape whichever answered - counters would
appear to halve and jump backwards at random. Pushing from both processes
makes them symmetric and removes the whole class of problem.

Everything is gated on OTEL_EXPORTER_OTLP_ENDPOINT. Unset, this returns
immediately and the application behaves exactly as it did before, which is how
the test suite, the eval harness and a profile-less `docker compose up` run.
"""

import logging
import os

logger = logging.getLogger(__name__)

_done = False


def setup(service: str) -> bool:
    """Install the meter provider and JSON logging for this process.

    Returns whether telemetry was actually enabled. Safe to call twice; the
    second call does nothing, because uvicorn imports the app module once per
    worker process but reloaders can import it again.
    """
    global _done

    from app.telemetry.logs import configure_logging

    configure_logging(service)

    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()

    if not endpoint or _done:
        return False

    try:
        from opentelemetry import metrics
        from opentelemetry._logs import set_logger_provider
        from opentelemetry.exporter.otlp.proto.http._log_exporter import (
            OTLPLogExporter,
        )
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
            OTLPMetricExporter,
        )
        from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
    except ImportError:
        # An endpoint was configured but the extra is not installed. Say so
        # once and carry on: a missing exporter must never stop a scan.
        logger.warning(
            "OTEL_EXPORTER_OTLP_ENDPOINT is set but the otel extra is not "
            "installed; metrics are disabled",
            extra={"service": service},
        )
        return False

    resource = Resource.create(
        {
            "service.name": service,
            "service.namespace": "docker-repo-auditor",
        }
    )

    metrics.set_meter_provider(
        MeterProvider(
            resource=resource,
            metric_readers=[
                PeriodicExportingMetricReader(
                    OTLPMetricExporter(endpoint=f"{endpoint}/v1/metrics"),
                    export_interval_millis=15_000,
                )
            ],
        )
    )

    logger_provider = LoggerProvider(resource=resource)

    logger_provider.add_log_record_processor(
        BatchLogRecordProcessor(OTLPLogExporter(endpoint=f"{endpoint}/v1/logs"))
    )

    set_logger_provider(logger_provider)

    # Added alongside the JSON stdout handler rather than replacing it: a
    # container's own logs staying readable with `docker logs` is worth more
    # than the duplication costs, and it is the fallback when the collector
    # is the thing that is down.
    from app.telemetry.logs import JobFilter

    otlp_handler = LoggingHandler(level=logging.INFO, logger_provider=logger_provider)
    otlp_handler.addFilter(JobFilter())

    logging.getLogger().addHandler(otlp_handler)

    _instrument()

    _done = True

    logger.info("Telemetry enabled", extra={"service": service, "endpoint": endpoint})

    return True


def _instrument() -> None:
    """Auto-instrument the transports, so tracing needs no application code.

    Each is optional and independent: a missing package disables its own
    instrumentation rather than the whole process.
    """
    for module, attr in (
        ("opentelemetry.instrumentation.botocore", "BotocoreInstrumentor"),
        ("opentelemetry.instrumentation.httpx", "HTTPXClientInstrumentor"),
        ("opentelemetry.instrumentation.redis", "RedisInstrumentor"),
    ):
        try:
            __import__(module)

            import sys

            getattr(sys.modules[module], attr)().instrument()
        except Exception:  # noqa: BLE001 - instrumentation is never load-bearing
            logger.debug("No instrumentation for %s", module)
```

## Why push, and not a `/metrics` endpoint

This is the one place the implementation deliberately contradicts the audit that
commissioned it. Section 8.2 proposed "an in-process Prometheus endpoint on `/metrics` for
the API". That does not work here:

```text
uvicorn --workers 2

  process A: counter = 41
  process B: counter = 17

Prometheus scrapes whichever answers.
The series appears to halve and jump backwards at random.
```

An in-process registry belongs to one process. The API runs two. Sharing a registry between
them means a multiprocess directory on a shared filesystem - a mode that has to be
configured consistently in three places and silently produces wrong numbers when it is not.
Pushing OTLP from both processes makes them symmetric and deletes the whole class of
problem: the collector merges the streams, and adding a third worker changes nothing
anywhere.

The worker settles this on its own, incidentally. It has no HTTP server to hang a route on,
which is the same reason its healthcheck probes SQS rather than a socket.

---

# 6. The collector

`observability/otel-collector.yaml`:

```yaml
# The single egress point for telemetry.
#
# The application speaks OTLP and never learns what is behind this file, so
# moving to CloudWatch on Fargate is a change here rather than a change in
# app/. Both the worker and the API push; neither exposes a scrape endpoint,
# because the API runs two uvicorn workers and an in-process registry would be
# scraped inconsistently between them. See docs/audits/audit-01-backend.md 18.

receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  # First in every pipeline, before batch. This process is the single egress
  # point for every signal, which makes it the single thing that OOMs under a
  # burst - taking metrics and logs down together at exactly the moment they
  # become interesting. Refusing data is the better failure: the SDKs retry,
  # and a dropped batch costs less than a restart. See docs/audits/audit-02-frontend-worker-observability.md F7.
  memory_limiter:
    check_interval: 1s
    limit_percentage: 80
    spike_limit_percentage: 25

  # Trades a little delay for far fewer outbound requests. 10s is well under
  # Prometheus's 15s scrape interval, so no sample is ever stale on arrival.
  batch:
    timeout: 10s

exporters:
  # Prometheus scrapes this rather than the applications. The collector holds
  # the merged series, which is what makes two API worker processes look like
  # one service.
  prometheus:
    endpoint: 0.0.0.0:8889
    resource_to_telemetry_conversion:
      # Without this, service.name stays a resource attribute and every query
      # would have to join on target_info to say which service a metric came
      # from.
      enabled: true

  # Loki 3 ingests OTLP directly, so no loki exporter and no promtail
  # sidecar: the application's log records arrive with their attributes
  # intact, which is what makes job_id filterable rather than a substring.
  otlphttp/loki:
    endpoint: http://loki:3100/otlp
    tls:
      insecure: true

  debug:
    verbosity: basic

service:
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [prometheus, debug]
    logs:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlphttp/loki]
  telemetry:
    logs:
      level: info
    metrics:
      # 0.0.0.0, not the default localhost: these are the collector's own
      # counters - points accepted, points refused, exports failed - and
      # Prometheus scrapes them from another container. Bound to loopback they
      # exist and nobody can read them, which is how the one process that sees
      # every signal was the one process nothing watched.
      readers:
        - pull:
            exporter:
              prometheus:
                host: 0.0.0.0
                port: 8888
```

`memory_limiter` goes first in both pipelines. This process is the single egress point for
every signal, which also makes it the single thing that OOMs under a burst - taking metrics
and logs down together at the moment they become worth reading. Refusing data is the better
failure, because the SDKs retry and a dropped batch costs less than a restart.

`resource_to_telemetry_conversion` is the small setting that decides whether the dashboards
are readable. Without it, `service.name` stays a resource attribute, lands in a separate
`target_info` series, and every panel query needs a join to say which process a number came
from. With it, `service_name` is an ordinary label and a panel is one line.

Loki 3 ingests OTLP directly, which is why there is no `loki` exporter here and no promtail
sidecar anywhere. The log record arrives with its attributes intact - the mechanism that
makes `job_id` a filterable field rather than a substring.

---

# 7. Prometheus, and a naming trap worth knowing about

`observability/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - /etc/prometheus/alerts.yml

scrape_configs:
  # One target, not three. The collector holds the merged series for every
  # process that pushes to it, so adding a worker replica changes nothing here.
  - job_name: otel-collector
    static_configs:
      - targets: ["otel-collector:8889"]

  # The collector's own health, which is a different question from the
  # application's. 8889 is what the app pushed; 8888 is how the collector is
  # coping with it - and if the memory_limiter ever sheds load, this is the
  # only place that says so.
  - job_name: otel-collector-internal
    static_configs:
      - targets: ["otel-collector:8888"]

  # The LLM gateway, which knows two things the application cannot.
  #
  # bifrost_cost_total is real money per model and provider. The audit asked
  # for llm_cost_usd_total and it was deferred because a USD figure needs a
  # per-model price table maintained against a vendor's pricing page, and a
  # wrong number is worse than none. The gateway maintains that table.
  #
  # bifrost_provider_key_up is the other one: 1 while a key works, 0 after it
  # fails. Every scan in this project 429'd for hours against an exhausted
  # key with nothing to say so.
  - job_name: bifrost
    static_configs:
      - targets: ["bifrost:8080"]
```

Two scrape jobs, for two different questions. `otel-collector` on **8889** is what the
applications pushed - one target however many worker replicas there are, because the
collector holds the merged series. `otel-collector-internal` on **8888** is the collector's
own counters: points accepted, points refused, exports failed.

That second job was added later, and the gap it closed is worth naming. The collector is
the single egress point for every signal in this stack, which makes it the single thing
that can silently drop them - and its internal telemetry binds to `localhost` by default,
so the metrics existed and nothing on another container could read them. The one process
that sees everything was the one process nothing watched. `service.telemetry.metrics` in
the collector config binds it to `0.0.0.0` so this job can reach it, and it is the only
place the `memory_limiter` shedding load would ever show up.

Now the trap. The OTLP-to-Prometheus translation appends suffixes: `_total` for monotonic
counters, and the unit for everything else. Read that naively and an instrument named
`scan_result_total` with unit `"1"` becomes `scan_result_total_total_1`, and every dashboard
panel silently returns empty.

It does not, and it is worth knowing exactly why, because "my panels are all empty" is the
single most common way a setup like this fails:

```text
scan_result_total       counter, unit "1"
  unit "1" -> mapped to the empty string, so no unit suffix
  "total"  -> removed from the name tokens, then appended
  result: scan_result_total

agent_duration_seconds  histogram, unit "s"
  unit "s" -> "seconds", but the name already contains "seconds"
  result: agent_duration_seconds
```

The translator removes an existing `total` token before appending one, and skips a unit
suffix the name already carries. Both rules are idempotent, so instruments named the way
Prometheus would name them survive the round trip unchanged. That is not luck - it is the
reason the instruments in section 3 are named `..._total` and `..._seconds` in the first
place, rather than `scan_result` and `agent_duration`.

---

# 8. Alerts

`observability/alerts.yml`:

```yaml
# One rule per failure this audit found and could not otherwise see.
#
# Routing is deliberately absent: the audit said these would go to "the SNS
# topic Phase 4 creates" and that topic does not exist - detective controls
# were deferred out of P4-4. The rules are the part worth version-controlling
# either way; a receiver is a config block to add once there is something to
# send to.

groups:
  - name: scan-pipeline
    rules:
      # The failure this whole audit is about: a report that looks complete
      # and is not. A single degraded scan is normal; a fifth of them is a
      # broken agent nobody was told about.
      #
      # The `and` is not decoration. clamp_min stops a divide by zero and does
      # nothing about low volume: with one degraded scan and nothing else,
      # numerator and denominator are the same tiny number and the ratio is
      # exactly 1.0. Measured against a real server, a single degraded scan
      # held this above 0.2 for sixteen consecutive minutes - one minute past
      # the `for` clause, so it fired. A share is meaningless until there is
      # something to take a share of. See docs/audits/audit-02-frontend-worker-observability.md F5.
      - alert: DegradedScanRate
        expr: |
          sum(rate(scan_result_total{outcome="degraded"}[15m]))
            / clamp_min(sum(rate(scan_result_total[15m])), 0.001) > 0.2
          and sum(rate(scan_result_total[15m])) > 0.01
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Over a fifth of scans are returning degraded reports"

      - alert: ScansFailing
        expr: sum(rate(scan_result_total{outcome="failed"}[10m])) > 0
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Scans are failing outright"

      # Not a threshold on the count - a large image legitimately has
      # thousands. This fires when the *share* analysed collapses, which is
      # what turns a report into a sample presented as one.
      - alert: MostVulnerabilitiesDropped
        expr: |
          sum(rate(vulnerabilities_dropped_total[1h]))
            / clamp_min(sum(rate(vulnerabilities_total[1h])), 0.001) > 0.95
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "Almost nothing the scanner found is reaching an agent"

  - name: model
    rules:
      # The regression signal for the prompt-injection work. A guard that
      # starts rejecting means either the model drifted or something is
      # trying to talk past it; both want a human.
      #
      # increase() over an hour, not a per-second rate. `> 0.1/s` is ninety
      # rejections per fifteen minutes; this pipeline runs single-digit scans
      # an hour, so the threshold could not be reached and the signal it
      # guards - someone probing the suppression path - was invisible. Rate
      # thresholds are a habit from high-QPS services. See docs/audits/audit-02-frontend-worker-observability.md F4.
      - alert: GuardRejectionsRising
        expr: sum(increase(agent_guard_rejection_total[1h])) by (reason) > 3
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Agent responses are being refused ({{ $labels.reason }})"

      # Same correction: `> 0.05/s` meant forty-five timeouts in fifteen
      # minutes for one agent, which is more scans than this pipeline runs in
      # a day. Three in an hour is a real signal at this scale.
      - alert: AgentsTimingOut
        expr: |
          sum(increase(agent_outcome_total{status="timed_out"}[1h])) by (agent) > 3
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.agent }} is timing out"

  - name: plumbing
    rules:
      # This watched decision="fail_open" until the limiter was changed to fail
      # closed, after which no code path emitted that label and a critical
      # alert could never fire. The risk moved with the fix: Redis unreachable
      # now means 503 on every scan, which is a full outage of the only write
      # path this product has. See docs/audits/audit-02-frontend-worker-observability.md F3.
      - alert: RateLimiterUnavailable
        expr: sum(rate(ratelimit_decision_total{decision="fail_closed"}[5m])) > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Redis is unreachable, so every scan is being refused"

      # Exhaustion means the message becomes visible again while this worker
      # is still scanning it - two workers, one job, two bills.
      - alert: HeartbeatExhausted
        expr: sum(rate(heartbeat_failure_total{reason="exhausted"}[15m])) > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "A scan lost its visibility heartbeat and may be redelivered"
```

Each rule is a finding from the audit given a trigger. `MostVulnerabilitiesDropped` is
P2-3. `RateLimiterUnavailable` is the other side of P3-3: the limiter was changed to fail
*closed*, so Redis being unreachable now refuses every scan rather than allowing every
scan. `GuardRejectionsRising` is the production regression signal for the prompt-injection
work - a spike means someone is probing the suppression path.

Four of these were rewritten after the second audit, and the reason is worth reading even
if you never run this stack:

- `RateLimiterUnavailable` was `RateLimiterFailingOpen`, watching
  `decision="fail_open"`. That label stopped being emitted when the limiter was fixed to
  fail closed, so a `critical` rule sat there unable to fire while the failure it cared
  about had moved. **An alert is coupled to a label value, and fixing the code silently
  invalidates it.**
- `GuardRejectionsRising` and `AgentsTimingOut` were per-second rates with thresholds of
  `0.1` and `0.05` - ninety rejections and forty-five timeouts per fifteen minutes. This
  pipeline runs single-digit scans an hour. They are `increase(...[1h]) > 3` now. **Rate
  thresholds are a habit from high-QPS services and do not survive the move to a
  low-volume one.**
- `DegradedScanRate` divides one rate by another, and `clamp_min` guards a zero
  denominator but not a tiny one. One degraded scan in an idle system is a ratio of
  exactly 1.0 - measured, it held above the 0.2 threshold for sixteen consecutive minutes
  against a `for: 15m` clause, so it fired. **A share needs a floor on what it is a share
  of.** See docs/audits/audit-02-frontend-worker-observability.md F3-F5.

They evaluate, and they currently route nowhere. There is no Alertmanager in the compose
stack and no SNS topic in Terraform, because the audit routed these to a topic Phase 4 was
supposed to create and did not. The rules are still worth having ahead of the routing: they
are visible in Prometheus's own UI, and an alert expression that has never been evaluated
against real series is usually wrong - which is exactly how three of these shipped wrong.

---

# 9. The dashboards, and the profile gate

Five dashboards, provisioned as files rather than clicked into a database, so they are
reviewable in a pull request:

```text
auditor-pipeline  throughput, p50/p95 by stage, degraded share
auditor-agents    outcome per agent, guard rejections, latency
auditor-cost      tokens and USD per scan, per agent
auditor-queue     depth, DLQ, redeliveries, heartbeat failures
auditor-security  findings by severity, dropped share, rate-limit decisions
```

All four containers sit behind a compose profile:

```yaml
profiles: ["observability"]
```

`docker compose up` starts none of them and behaves exactly as it did before.
`docker compose --profile observability up` adds them. Four containers of memory is a real
cost and nobody should pay it for a scan they are not measuring.

Two port choices that are not arbitrary. Grafana is published on **3001**, because the
frontend already owns 3000. Loki is published on **3101** rather than its default 3100,
which collides readily with other local stacks - inside the compose network both Grafana
and the collector still reach it as `loki:3100`, so no config file has to know.

---

# 10. Running it, which is the part that matters

A doc describing instruments nobody watched emit is the same failure mode as a report
nobody reads. So: stack up, one scan of `alpine:3.18` through the API, then look.

```text
prometheus target otel-collector   UP
alert rules loaded                 7, across 3 groups
grafana datasources provisioned    Prometheus (default), Loki
grafana dashboards provisioned     5
loki labels                        service_name, service_namespace, service_instance_id
```

Then every panel expression in all five dashboards, evaluated against the real server:

```text
11 panels returned data
 9 panels returned empty
 0 panels returned an error
```

Zero errors is the result that mattered - it means no panel names a metric the code does not
emit. The nine empty panels are all event-driven instruments that had no events: no guard
rejected anything, no heartbeat failed, no message redelivered, Trivy did not fail.

And the first scan immediately paid for the whole phase:

```text
scan_result_total{outcome="degraded"}  1

agent_outcome_total
  cis_controls          analysed
  secret_scan           analysed
  base_image_strategist failed
  bloat_detective       failed
  compliance_checker    failed
  risk_scorer           failed
  cve_analyst           skipped_no_input
  dockerfile_optimizer  skipped_degraded_input
```

Four of eight agents failed and the scan still returned a report. The cause was mundane -
the OpenAI account was out of credits, HTTP 429 - but the shape of the result is exactly the
failure mode section 1 describes: a degraded report that looks like a report. Before this
phase, that scan was a success as far as any observer could tell.

It also explains the one instrument this phase could not verify. `llm_tokens_total` has no
series, because no model call ever returned a usage object to count. The code path is there
and untested in the wild; better to say so here than to imply otherwise with a screenshot.

---

# 11. The bug that only running it could find

Three processes run a scan in this repo. Two of them called `setup()`:

```text
app/main.py      worker      setup("worker")   yes
app/api/main.py  API         setup("api")      yes
app/cli.py       CI gate     logging.basicConfig(...)
```

`app/cli.py` is the entrypoint a pipeline calls to fail a build. It had plain-text logs and
no metrics - so the one scan that runs unattended, in CI, with nobody watching a terminal,
was the only scan that produced no telemetry at all. A gap that exact is easy to miss
reading the code and impossible to miss running it.

The fix is what the other two entrypoints already do:

```python
from app.telemetry import setup


def main() -> int:
    setup("cli")
```

`configure_logging` attaches a `StreamHandler`, which defaults to **stderr** - so
`--format json` on stdout stays machine-readable and the CI gate's exit-code contract is
untouched.

Verified the same way as everything else, by running it and looking:

```text
count by (service_name) (agent_outcome_total)
  worker -> 8 series
  cli    -> 8 series
```

Worth noting why that works at all. The CLI is a short-lived process and the metric reader
exports on a 15-second interval, so a naive reading says a 40-second scan flushes nothing on
exit. The SDK registers an atexit hook that shuts the provider down and drains the buffer.
Confirmed rather than assumed: the `cli` series arrived after the process had exited.

---

# 12. What is deliberately not here

**Traces.** `_instrument()` installs the botocore, httpx and redis instrumentors, and no
`TracerProvider` is ever set - so those spans go to the API's default no-op and cost
nothing. The collector has no traces pipeline either, which is consistent rather than
broken. A span tree over one scan is the highest-value view this pipeline could have, and
the collector makes adding it later nearly free; it is not here because nothing asked for it
yet, and an unused pipeline is one more thing to maintain.

**Anything on AWS.** This is the honest gap. Terraform has four `aws_cloudwatch_log_group`
resources and nothing else: no OTLP environment in any task definition, no ADOT sidecar, no
`aws_cloudwatch_metric_alarm`, no SNS topic. Deployed to Fargate today, every instrument in
this phase pushes to an endpoint that is not set, and therefore does nothing. The local
stack is real; the production story is not written.

**Alertmanager.** Seven rules, no receiver. See section 8.

---

# 13. What you built

```text
1  collector, one egress point for every signal
13 instruments, each mapped to a named audit finding
1  contextvar tying logs, metrics and a scan together
5  dashboards, provisioned as reviewable files
7  alert rules that evaluate and route nowhere yet
3  entrypoints instrumented, up from 2
```

The ideas worth carrying to the next project:

**Instrument the failure you cannot see, not the request you can.** Request rate and latency
are free from any framework. This pipeline's real failure mode is a 200 response containing
a worse answer, and no framework will ever measure that for you. Every instrument here
started as a sentence in an audit describing something that had gone wrong invisibly.

**One correlation key, attached at the handler.** `job_id` as a contextvar is four lines,
and it is the difference between reading a failure and reconstructing one. Attach it below
the application, so libraries that have never heard of your project carry it too.

**Make the disabled path the default path.** `setup()` returns immediately when
`OTEL_EXPORTER_OTLP_ENDPOINT` is unset, and the instruments are no-ops until something
installs a provider. Tests, the eval harness and a profile-less `docker compose up` behave
exactly as they did before. Telemetry that can break the thing it measures will eventually
be deleted by someone at 3am.

**Run it before you write it down.** Static review said the dashboards were fine. Running
them proved it - and running the scan found `cli.py`, which no amount of reading the
observability code would have surfaced, because the bug was in the one file that did not
import it.

```text
an instrument nobody has
watched emit is a guess
with a metric name
```

---

## Where to go next

Roughly by value.

**Put the telemetry on Fargate.** The local stack proves the code works; nothing proves the
deployment does. An ADOT sidecar in the task definition and `OTEL_EXPORTER_OTLP_ENDPOINT`
pointing at `localhost:4318` is most of it, and it is the difference between an observable
pipeline and an observable laptop.

**Create the SNS topic and route the seven rules.** They have been evaluating against real
series since section 10, which is the hard part. Alertmanager locally; `aws_sns_topic` plus
`aws_cloudwatch_metric_alarm` deployed.

**Add the traces pipeline.** The instrumentors are already installed. A `TracerProvider` in
`setup()`, a `traces` pipeline in the collector, Tempo in the compose profile, and manual
spans on the stages `orchestrator.py` already times. A span tree over one degraded scan
answers "which agent held this up" without anyone reading a log.

**Get `llm_tokens_total` a real reading.** It is the only instrument this phase shipped
unverified, and it is the one that becomes a budget.
