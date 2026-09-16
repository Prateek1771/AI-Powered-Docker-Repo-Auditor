import logging

from app.orchestrator import run_and_store
from app.queue.producer import ScanMessage
from app.storage.jobs import claim_job, get_job, lease_is_live

logger = logging.getLogger(__name__)


async def handle_scan(message: ScanMessage, attempt: int) -> None:
    """Claim a job and run it, tolerating redelivery of the same message.

    Losing the claim is not an error, but it is three different things and
    they need telling apart:

      - the job is already `completed` - a duplicate delivery, dropped;
      - the job is `running` with a LIVE lease - another worker is on it
        right now, so running it again would mean two scans of one image:
        double model spend, racing `store_result` puts and progress events
        interleaving backwards. Dropped;
      - anything else - a worker that died mid-scan. Reprocessing is the
        recovery, and claim_job has already taken the lapsed lease over.

    Before the lease existed the second and third cases were
    indistinguishable, and this reprocessed both. See docs/AUDIT.md P3-2.
    """
    claimed = claim_job(
        message.job_id,
        message.tenant_id,
        message.repo_id,
        message.target,
    )

    if not claimed:
        existing = get_job(message.job_id)

        if existing and existing.status == "completed":
            logger.info(
                "Job %s already completed, skipping duplicate",
                message.job_id,
            )

            return

        if existing and lease_is_live(existing):
            # Returning means the consumer deletes this copy of the message.
            # That is the right call: the live holder is heartbeating, so it
            # is going to finish and store the result. Leaving the message
            # would only redeliver it into the same check.
            logger.warning(
                "Job %s is held by a live worker until %d, skipping attempt %d",
                message.job_id,
                existing.lease_expires_at,
                attempt,
            )

            return

        logger.info(
            "Job %s exists in state %s with no live lease, reprocessing as attempt %d",
            message.job_id,
            existing.status if existing else "unknown",
            attempt,
        )

    await run_and_store(
        message.job_id,
        message.tenant_id,
        message.repo_id,
        message.target,
    )
