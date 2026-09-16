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
