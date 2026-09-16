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
