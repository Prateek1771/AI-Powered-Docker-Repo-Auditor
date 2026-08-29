import logging
import time
from typing import Any

from fastapi import Depends, HTTPException

from app.config.api import REDIS_URL, SCAN_LIMIT, SCAN_WINDOW_SECONDS
from app.core.auth import Principal, current_principal

logger = logging.getLogger(__name__)

_client: Any = None


def _redis() -> Any:
    global _client

    if _client is None:
        try:
            import redis

            _client = redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_timeout=2,
            )
        except Exception as exc:  # noqa: BLE001 - see fail-open note below
            logger.warning("Redis unavailable: %s", exc)

            return None

    return _client


def check_limit(
    tenant_id: str,
    action: str,
    limit: int,
    window_seconds: int,
) -> None:
    client = _redis()

    # Deliberately FAIL OPEN. A broken rate limiter costs money; a broken
    # authenticator costs everything. Do not "fix" this to match auth.py.
    if client is None:
        return

    key = f"ratelimit:{action}:{tenant_id}"

    now = time.time()

    try:
        pipe = client.pipeline()
        pipe.zremrangebyscore(key, 0, now - window_seconds)
        pipe.zcard(key)
        pipe.expire(key, window_seconds)

        count = pipe.execute()[1]

        if count >= limit:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Rate limit exceeded: {limit} {action}s "
                    f"per {window_seconds // 3600}h"
                ),
                headers={"Retry-After": str(window_seconds)},
            )

        # Only charge quota for requests we actually allowed, so a client
        # retrying on 429 can eventually recover.
        client.zadd(key, {f"{now}:{action}": now})

    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - fail open, see above
        logger.warning("Rate limit check failed, allowing: %s", exc)


def scan_rate_limit(
    principal: Principal = Depends(current_principal),
) -> Principal:
    check_limit(
        principal.tenant_id,
        "scan",
        SCAN_LIMIT,
        SCAN_WINDOW_SECONDS,
    )

    return principal
