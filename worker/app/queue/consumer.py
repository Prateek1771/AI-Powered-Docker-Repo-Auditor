import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from app.config.queue import (
    HEARTBEAT_EXTENSION_SECONDS,
    HEARTBEAT_INTERVAL_SECONDS,
    MAX_MESSAGES_PER_POLL,
    POLL_WAIT_SECONDS,
    SCAN_QUEUE_URL,
    VISIBILITY_TIMEOUT_SECONDS,
)
from app.queue.producer import ScanMessage

logger = logging.getLogger(__name__)

Handler = Callable[[ScanMessage, int], Awaitable[None]]


class PermanentFailure(Exception):
    """Raised when retrying cannot help: bad input, missing image, 4xx."""


async def _heartbeat(client: Any, receipt_handle: str) -> None:
    """Keep extending a message's visibility while its scan runs.

    This is what lets VISIBILITY_TIMEOUT_SECONDS stay short. A dead worker
    is redelivered in five minutes, and a slow one is never cut off. Give
    up quietly on error rather than killing the scan the heartbeat serves.
    """
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)

        try:
            client.change_message_visibility(
                QueueUrl=SCAN_QUEUE_URL,
                ReceiptHandle=receipt_handle,
                VisibilityTimeout=HEARTBEAT_EXTENSION_SECONDS,
            )

            logger.debug("Extended visibility by %ds", HEARTBEAT_EXTENSION_SECONDS)

        except Exception as exc:  # noqa: BLE001 - a dead heartbeat must not kill the scan
            logger.warning("Heartbeat failed: %s", exc)

            return


async def _with_heartbeat(
    client: Any,
    receipt_handle: str,
    coro: Awaitable[None],
) -> None:
    """Run a coroutine with a heartbeat alongside it, cancelled after."""
    task = asyncio.create_task(_heartbeat(client, receipt_handle))

    try:
        return await coro
    finally:
        task.cancel()

        with contextlib.suppress(asyncio.CancelledError):
            await task


async def consume_once(client: Any, handler: Handler) -> int:
    """Poll the queue once and run the handler over whatever arrived.

    Deleting only after the handler returns is what makes delivery
    at-least-once: a crash mid-scan leaves the message for redelivery, and
    claim_job decides which worker wins. A generic exception is left for
    retry so ApproximateReceiveCount can reach the redrive threshold and
    the DLQ can catch it; PermanentFailure skips that, because a bad
    reference will not become good on a third attempt.
    """
    resp = client.receive_message(
        QueueUrl=SCAN_QUEUE_URL,
        MaxNumberOfMessages=MAX_MESSAGES_PER_POLL,
        WaitTimeSeconds=POLL_WAIT_SECONDS,
        VisibilityTimeout=VISIBILITY_TIMEOUT_SECONDS,
        AttributeNames=["ApproximateReceiveCount"],
    )

    messages = resp.get("Messages", [])

    for raw in messages:
        message = ScanMessage.model_validate_json(raw["Body"])

        attempt = int(raw.get("Attributes", {}).get("ApproximateReceiveCount", "1"))

        logger.info(
            "Received job %s (attempt %d)",
            message.job_id,
            attempt,
        )

        try:
            await _with_heartbeat(
                client,
                raw["ReceiptHandle"],
                handler(message, attempt),
            )

            client.delete_message(
                QueueUrl=SCAN_QUEUE_URL,
                ReceiptHandle=raw["ReceiptHandle"],
            )

            logger.info("Job %s complete, message deleted", message.job_id)

        except PermanentFailure:
            logger.error(
                "Job %s failed permanently, not retrying",
                message.job_id,
            )

            client.delete_message(
                QueueUrl=SCAN_QUEUE_URL,
                ReceiptHandle=raw["ReceiptHandle"],
            )

        except Exception:
            logger.exception(
                "Job %s failed on attempt %d, leaving for redelivery",
                message.job_id,
                attempt,
            )

    return len(messages)
