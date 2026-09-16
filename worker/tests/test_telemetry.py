"""The instruments fire, with the labels a dashboard and an alert rely on.

These run with no collector and no network: an InMemoryMetricReader is a real
SDK provider that keeps its output in the process. The point is not that
OpenTelemetry works - it is that each call site passes the labels the alert
rules query by, because a metric that exists and reports the wrong thing is
worse than no metric at all.
"""

import importlib
import io
import json
import logging

import pytest

otel = pytest.importorskip(
    "opentelemetry.sdk.metrics",
    reason="the otel extra is not installed; the no-op path is covered below",
)

from opentelemetry import metrics as otel_metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from app.telemetry.logs import JobFilter, JsonFormatter, job_context


@pytest.fixture(scope="module")
def reader():
    """Install a real provider once, then re-import the instruments under it.

    Module scope because a meter provider can only be set once per process,
    and the instruments bind to whatever provider existed when they were
    created.
    """
    reader = InMemoryMetricReader()

    otel_metrics.set_meter_provider(MeterProvider(metric_readers=[reader]))

    import app.telemetry.metrics as metrics_module

    importlib.reload(metrics_module)

    return reader


def collect(reader) -> dict[str, list[tuple[dict, float]]]:
    """Flatten the export into {metric name: [(attributes, value)]}."""
    out: dict[str, list[tuple[dict, float]]] = {}

    data = reader.get_metrics_data()

    if data is None:
        return out

    for resource in data.resource_metrics:
        for scope in resource.scope_metrics:
            for metric in scope.metrics:
                out.setdefault(metric.name, []).extend(
                    (dict(point.attributes), point.value)
                    for point in metric.data.data_points
                )

    return out


def test_agent_outcome_is_labelled_by_agent_and_status(reader):
    """The label pair the degraded-scan alert groups by.

    Without `status` the metric counts runs and cannot distinguish an agent
    that analysed an image from one that timed out - which is the entire
    signal.
    """
    import app.telemetry.metrics as m

    m.agent_outcome.add(1, {"agent": "cve_analyst", "status": "analysed"})
    m.agent_outcome.add(1, {"agent": "bloat_detective", "status": "timed_out"})

    points = {
        tuple(sorted(attrs.items())): value
        for attrs, value in collect(reader)["agent_outcome_total"]
    }

    assert points[(("agent", "cve_analyst"), ("status", "analysed"))] == 1
    assert points[(("agent", "bloat_detective"), ("status", "timed_out"))] == 1


def test_dropped_vulnerabilities_are_counted_separately(reader):
    """`dropped` is the difference between a report and a sample.

    It is its own series rather than a ratio because the alert fires on the
    absolute count: one dropped vulnerability on a small image means
    something different from ten thousand on a large one.
    """
    import app.telemetry.metrics as m

    m.vulnerabilities_dropped.add(10_878)
    m.vulnerabilities_analysed.add(150)

    assert collect(reader)["vulnerabilities_dropped_total"][0][1] == 10_878
    assert collect(reader)["vulnerabilities_sent_to_model_total"][0][1] == 150


def test_fail_closed_is_distinguishable_from_rejected(reader):
    """Two refusals that mean opposite things must not share a label.

    `rejected` is the limiter working: a tenant used its quota. `fail_closed`
    is the limiter unable to work at all, so every scan is refused - a full
    outage rather than a busy tenant. Both return an error to the caller and
    only one of them wants waking someone up.
    """
    import app.telemetry.metrics as m

    m.ratelimit_decision.add(1, {"action": "scan", "decision": "rejected"})
    m.ratelimit_decision.add(1, {"action": "scan", "decision": "fail_closed"})

    decisions = {
        attrs["decision"] for attrs, _ in collect(reader)["ratelimit_decision_total"]
    }

    assert {"rejected", "fail_closed"} <= decisions


def test_instruments_work_without_a_provider():
    """The path every test run and every profile-less compose up takes.

    Recording a metric must never raise when nothing is listening, or
    telemetry becomes a way to fail a scan.
    """
    from app.telemetry.metrics import _NoopInstrument

    noop = _NoopInstrument()

    assert noop.add(1, {"agent": "x"}) is None
    assert noop.record(0.4) is None


def _capture(logger_name: str = "t") -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()

    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    # Same pairing configure_logging uses: the filter injects the context, the
    # formatter serialises it. Either alone drops the correlation key.
    handler.addFilter(JobFilter())

    logger = logging.getLogger(logger_name)
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)

    return logger, stream


def test_job_id_is_a_field_not_a_message():
    """The correlation key, which is the whole reason for structured logs.

    Interpolated into the message it could be read but not filtered on, so a
    failed scan could be seen and the rest of its story could not be found.
    """
    logger, stream = _capture()

    with job_context(job_id="job-1", tenant_id="acme", repo_id=""):
        logger.info("Scan failed")

    record = json.loads(stream.getvalue())

    assert record["job_id"] == "job-1"
    assert record["tenant_id"] == "acme"
    # An empty field is worse than an absent one: it reads as a value.
    assert "repo_id" not in record


def test_the_context_does_not_leak_past_the_scan():
    """Two scans in one worker process must not be attributed to each other."""
    logger, stream = _capture("t2")

    with job_context(job_id="job-1"):
        logger.info("inside")

    logger.info("outside")

    inside, outside = (json.loads(line) for line in stream.getvalue().splitlines())

    assert inside["job_id"] == "job-1"
    assert "job_id" not in outside


def test_extra_fields_survive():
    """So a log line and a metric can be filtered by the same attribute name."""
    logger, stream = _capture("t3")

    logger.warning("rejected", extra={"agent": "cve_analyst", "reason": "schema"})

    record = json.loads(stream.getvalue())

    assert record["agent"] == "cve_analyst"
    assert record["reason"] == "schema"
    assert record["level"] == "WARNING"
