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
from app.errors import PermanentFailure
from app.queue.producer import ScanMessage
from app.storage.jobs import renew_lease
from app.telemetry import metrics

logger = logging.getLogger(__name__)

Handler = Callable[[ScanMessage, int], Awaitable[None]]


# How many consecutive extension failures before the heartbeat gives up.
#
# One was the old behaviour and it was too few: a single throttle or network
# blip killed the heartbeat for the rest of the scan, visibility then expired
# mid-scan, and the redelivered message got picked up by a second worker while
# the first was still running - two workers on one image, double model spend,
# and progress events interleaving backwards.
#
# Three strikes at HEARTBEAT_INTERVAL_SECONDS apart still gives up well inside
# the visibility window, so a genuinely unreachable queue is not retried
# forever.
MAX_HEARTBEAT_FAILURES = 3


async def _heartbeat(client: Any, receipt_handle: str, job_id: str) -> None:
    """Keep this worker's claim alive while its scan runs.

    Two things, on one clock, because they answer the same question in the
    two places it gets asked: SQS decides whether to REDELIVER the message,
    and the job lease decides whether whoever receives it should ACT.
    Extending only the first is what let a lapsed heartbeat turn into two
    workers scanning one image. See docs/AUDIT.md P3-2.

    This is also what lets VISIBILITY_TIMEOUT_SECONDS stay short. A dead
    worker is redelivered in five minutes, and a slow one is never cut off.
    A failure never kills the scan the heartbeat serves - it retries, and
    only gives up after MAX_HEARTBEAT_FAILURES in a row.
    """
    failures = 0

    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)

        try:
            # to_thread because this is a blocking boto3 call on the event
            # loop, and the loop is running four concurrent agents. Without
            # it every heartbeat stalls them for the length of the call.
            await asyncio.to_thread(
                lambda: client.change_message_visibility(
                    QueueUrl=SCAN_QUEUE_URL,
                    ReceiptHandle=receipt_handle,
                    VisibilityTimeout=HEARTBEAT_EXTENSION_SECONDS,
                )
            )

            # The lease, on the same clock and in the same try: a renewal
            # that fails is exactly as serious as a visibility extension that
            # fails, and both should count toward the same strike budget.
            held = await asyncio.to_thread(renew_lease, job_id)

            if not held:
                # The row is no longer `running` under us - another worker
                # took a lapsed lease over, or the job was already finished.
                # Keeping the visibility alive for a scan whose result will
                # be overwritten is worse than stopping.
                logger.warning(
                    "Lost the lease on job %s; stopping the heartbeat",
                    job_id,
                )

                metrics.heartbeat_failure.add(1, {"reason": "lease_lost"})

                return

            failures = 0

            logger.debug("Extended visibility by %ds", HEARTBEAT_EXTENSION_SECONDS)

        except Exception as exc:  # noqa: BLE001 - a dead heartbeat must not kill the scan
            failures += 1

            # Every failure, not only the third: `failures` resets on success,
            # so a heartbeat failing every other cycle never trips the give-up
            # branch and would otherwise be completely silent.
            metrics.heartbeat_failure.add(1, {"reason": "extend_failed"})

            logger.warning(
                "Heartbeat failed (%d/%d): %s",
                failures,
                MAX_HEARTBEAT_FAILURES,
                exc,
            )

            if failures >= MAX_HEARTBEAT_FAILURES:
                logger.error(
                    "Heartbeat giving up after %d consecutive failures; "
                    "this message may be redelivered while the scan is still running",
                    failures,
                )

                metrics.heartbeat_failure.add(1, {"reason": "exhausted"})

                return


async def _with_heartbeat(
    client: Any,
    receipt_handle: str,
    job_id: str,
    coro: Awaitable[None],
) -> None:
    """Run a coroutine with a heartbeat alongside it, cancelled after."""
    task = asyncio.create_task(_heartbeat(client, receipt_handle, job_id))

    try:
        return await coro
    finally:
        task.cancel()

        with contextlib.suppress(asyncio.CancelledError):
            await task


async def _delete(client: Any, receipt_handle: str) -> None:
    """Delete one message, off the event loop."""
    await asyncio.to_thread(
        lambda: client.delete_message(
            QueueUrl=SCAN_QUEUE_URL,
            ReceiptHandle=receipt_handle,
        )
    )


async def consume_once(client: Any, handler: Handler) -> int:
    """Poll the queue once and run the handler over whatever arrived.

    Deleting only after the handler returns is what makes delivery
    at-least-once: a crash mid-scan leaves the message for redelivery, and
    claim_job decides which worker wins. A generic exception is left for
    retry so ApproximateReceiveCount can reach the redrive threshold and
    the DLQ can catch it; PermanentFailure skips that, because a bad
    reference will not become good on a third attempt.
    """
    # to_thread: this is a blocking boto3 call that waits POLL_WAIT_SECONDS
    # for a message - twenty seconds with the event loop frozen, during
    # which nothing else on it runs. See docs/AUDIT.md P3-9.
    resp = await asyncio.to_thread(
        lambda: client.receive_message(
            QueueUrl=SCAN_QUEUE_URL,
            MaxNumberOfMessages=MAX_MESSAGES_PER_POLL,
            WaitTimeSeconds=POLL_WAIT_SECONDS,
            VisibilityTimeout=VISIBILITY_TIMEOUT_SECONDS,
            AttributeNames=["ApproximateReceiveCount"],
        )
    )

    messages = resp.get("Messages", [])

    for raw in messages:
        attempt = int(raw.get("Attributes", {}).get("ApproximateReceiveCount", "1"))

        if attempt > 1:
            # The per-message signal queue depth cannot give: this one is
            # going round again, which is the trajectory toward the DLQ.
            metrics.message_redelivery.add(1)

        try:
            # Inside the try. Parsed outside it, an unreadable body raised
            # past the loop and aborted the whole poll cycle - including any
            # other message in the batch - and burned three redeliveries
            # before the DLQ caught it. A body we cannot parse will not parse
            # on the third attempt either, so it goes straight to the DLQ.
            message = ScanMessage.model_validate_json(raw["Body"])
        except Exception:
            logger.exception(
                "Unparseable message body, deleting rather than retrying: %.200s",
                raw.get("Body", ""),
            )

            await _delete(client, raw["ReceiptHandle"])

            continue

        logger.info(
            "Received job %s (attempt %d)",
            message.job_id,
            attempt,
        )

        try:
            await _with_heartbeat(
                client,
                raw["ReceiptHandle"],
                message.job_id,
                handler(message, attempt),
            )

            await _delete(client, raw["ReceiptHandle"])

            logger.info("Job %s complete, message deleted", message.job_id)

        except PermanentFailure:
            logger.error(
                "Job %s failed permanently, not retrying",
                message.job_id,
            )

            await _delete(client, raw["ReceiptHandle"])

        except Exception:
            logger.exception(
                "Job %s failed on attempt %d, leaving for redelivery",
                message.job_id,
                attempt,
            )

    return len(messages)
