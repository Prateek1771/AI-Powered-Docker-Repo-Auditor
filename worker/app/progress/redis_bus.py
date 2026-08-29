import logging
from collections.abc import AsyncGenerator

import redis.asyncio as aioredis

from app.config.api import REDIS_URL
from app.progress.bus import ProgressEvent

logger = logging.getLogger(__name__)


def _channel(job_id: str) -> str:
    return f"progress:{job_id}"


class RedisProgressBus:
    def __init__(self, url: str = REDIS_URL) -> None:
        self._redis = aioredis.from_url(url, decode_responses=True)

    async def publish(self, event: ProgressEvent) -> None:
        await self._redis.publish(
            _channel(event.job_id),
            event.model_dump_json(),
        )

    async def listen(self, job_id: str) -> AsyncGenerator[ProgressEvent, None]:
        pubsub = self._redis.pubsub()

        await pubsub.subscribe(_channel(job_id))

        try:
            async for raw in pubsub.listen():
                # listen() also yields the subscribe confirmation; without this
                # the first "event" is a {"type": "subscribe"} dict.
                if raw["type"] != "message":
                    continue

                try:
                    yield ProgressEvent.model_validate_json(raw["data"])
                except ValueError:
                    logger.warning("Dropping malformed progress event")

        finally:
            # Without this every closed tab leaves a live subscription on the
            # connection, and they accumulate for the life of the process.
            await pubsub.unsubscribe(_channel(job_id))
            await pubsub.aclose()

    async def close(self) -> None:
        await self._redis.aclose()
