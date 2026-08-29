import logging

from app.orchestrator import run_and_store
from app.queue.producer import ScanMessage
from app.storage.jobs import claim_job, get_job

logger = logging.getLogger(__name__)


async def handle_scan(message: ScanMessage, attempt: int) -> None:
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

        logger.info(
            "Job %s exists in state %s, reprocessing as attempt %d",
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
