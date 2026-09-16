import logging
import time
import uuid
from typing import Any

from fastapi import Depends, HTTPException

from app.config.api import (
    REDIS_PASSWORD,
    REDIS_URL,
    SCAN_LIMIT,
    SCAN_WINDOW_SECONDS,
)
from app.core.auth import Principal, current_principal
from app.telemetry import metrics

logger = logging.getLogger(__name__)


def _decided(action: str, decision: str) -> None:
    """Count what the limiter decided.

    fail_closed is the one worth watching. When Redis is unreachable every
    scan is refused with a 503, which is a full outage of the only write path
    this product has - and it is invisible in every log this service writes.
    The alert used to watch `fail_open` instead, a decision no code path has
    emitted since this limiter was changed to fail closed. See docs/AUDIT_02 F3.
    """
    metrics.ratelimit_decision.add(1, {"action": action, "decision": decision})


_client: Any = None


def _redis() -> Any:
    """Return the shared Redis client, or None if it cannot be reached.

    None rather than raising, so the one caller decides what an outage
    means. It decides 503.
    """
    global _client

    if _client is None:
        try:
            import redis

            _client = redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_timeout=2,
                password=REDIS_PASSWORD,
            )
        except Exception as exc:  # noqa: BLE001 - the caller turns None into a 503
            logger.warning("Redis unavailable: %s", exc)

            return None

    return _client


# Trim the window, count it, and charge for the request in ONE round trip.
#
# The previous version read the count in a pipeline and then ran ZADD
# separately, so N concurrent requests all saw count < limit and all
# committed - the limit was bypassable by firing requests in parallel, which
# a sequential test cannot catch. Redis runs a script atomically, which is the
# whole fix.
#
# EXPIRE goes after ZADD deliberately: on a brand-new key, EXPIRE before the
# first member is a no-op against a key that does not exist yet, and every
# tenant who made exactly one request left an immortal sorted set behind.
_SLIDING_WINDOW = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[1])

local used = redis.call('ZCARD', KEYS[1])

if used >= tonumber(ARGV[2]) then
  return used
end

redis.call('ZADD', KEYS[1], ARGV[3], ARGV[4])
redis.call('EXPIRE', KEYS[1], ARGV[5])

return -1
"""

_script: Any = None


def _too_many(action: str, limit: int, window_seconds: int) -> HTTPException:
    return HTTPException(
        status_code=429,
        detail=(
            f"Rate limit exceeded: {limit} {action}s per {window_seconds // 3600}h"
        ),
        headers={"Retry-After": str(window_seconds)},
    )


def check_limit(
    tenant_id: str,
    action: str,
    limit: int,
    window_seconds: int,
) -> None:
    """Raise 429 if a tenant has used up its quota for an action.

    A sliding window over a sorted set, so the quota frees up gradually
    rather than all at once on a fixed boundary.

    FAILS CLOSED. The old comment here argued that a broken rate limiter
    costs money, so it allowed the request - but that has the trade
    inverted. Every route behind this limiter starts a scan, and a scan is a
    Trivy run plus an unbounded set of model calls. Allowing unlimited scans
    while Redis is down is not the cheap option, it is the expensive one,
    and it is reachable by anyone who can knock Redis over.

    There was a `fail_open=True` parameter here for read routes. No route
    ever passed it - the only wrapper is scan_rate_limit - so it was a
    branch that could not execute and an alert watching a label nothing
    emitted. Deleted rather than left for a future caller.
    """
    global _script

    client = _redis()

    if client is None:
        _decided(action, "fail_closed")

        raise HTTPException(
            status_code=503,
            detail="Rate limiting is unavailable, refusing to start a scan",
            headers={"Retry-After": "30"},
        )

    key = f"ratelimit:{action}:{tenant_id}"

    now = time.time()

    try:
        if _script is None:
            _script = client.register_script(_SLIDING_WINDOW)

        used = _script(
            keys=[key],
            args=[
                now - window_seconds,
                limit,
                now,
                # Unique per request: two calls in the same float second would
                # otherwise be one member, and the second would be free.
                f"{now}:{uuid.uuid4()}",
                window_seconds,
            ],
        )
    except Exception as exc:
        logger.warning("Rate limit check failed: %s", exc)

        _decided(action, "fail_closed")

        raise HTTPException(
            status_code=503,
            detail="Rate limiting is unavailable, refusing to start a scan",
            headers={"Retry-After": "30"},
        ) from exc

    if int(used) >= 0:
        _decided(action, "rejected")

        raise _too_many(action, limit, window_seconds)

    _decided(action, "allowed")


def scan_rate_limit(
    principal: Principal = Depends(current_principal),
) -> Principal:
    """Authenticate the caller and charge one scan against their quota.

    Wraps current_principal rather than replacing it, so a route asking
    for this gets authentication and rate limiting in one dependency.
    """
    check_limit(
        principal.tenant_id,
        "scan",
        SCAN_LIMIT,
        SCAN_WINDOW_SECONDS,
    )

    return principal
