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
