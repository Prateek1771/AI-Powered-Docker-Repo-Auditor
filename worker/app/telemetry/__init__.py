"""Metrics and structured logs for the scan pipeline.

Nothing here is required to run a scan. `setup()` is a no-op unless
OTEL_EXPORTER_OTLP_ENDPOINT is set, and the instruments in `metrics` fall back
to a no-op when the `otel` extra is not installed - so the tests, the eval
harness and a plain `docker compose up` behave exactly as they did before.

See docs/audits/audit-01-backend.md 18.
"""

from app.telemetry.logs import configure_logging, job_context
from app.telemetry.setup import setup

__all__ = ["configure_logging", "job_context", "setup"]
