import logging
from typing import Literal

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from pydantic import BaseModel

from app.config.queue import JOB_LEASE_SECONDS
from app.config.storage import JOB_TTL_DAYS
from app.storage.client import table
from app.storage.serialization import epoch_in, now_epoch, now_iso, to_item, ttl_epoch

logger = logging.getLogger(__name__)

JobStatus = Literal["queued", "running", "completed", "failed"]


class JobRecord(BaseModel):
    job_id: str
    tenant_id: str
    repo_id: str
    target: str
    status: JobStatus
    progress: int = 0
    current_step: str = ""
    started_at: str
    updated_at: str
    expires_at: int

    # When this worker's claim lapses, as a Unix timestamp.
    #
    # Without it a row in state `running` is ambiguous - a live worker
    # mid-scan and a worker that died forty minutes ago look identical - and
    # the redelivery handler had to guess. It guessed "reprocess", so two
    # workers scanned the same image: double model spend, racing progress
    # writes, and progress events jumping backwards. See docs/audits/audit-01-backend.md P3-2.
    #
    # Zero on a row written before this existed, which reads as "expired" and
    # is the right answer for a job nobody has heartbeated since.
    lease_expires_at: int = 0


def create_job(
    job_id: str,
    tenant_id: str,
    repo_id: str,
    target: str,
) -> JobRecord:
    """Write the queued row for a job the API has just accepted.

    Called at 202 rather than when a worker picks the message up, so the
    job_id handed back is immediately readable and subscribable.

    Conditional, because the API enqueues BEFORE it writes this row and a
    worker on a warm queue routinely claims the job first. An unconditional
    put then overwrote that claim with `queued` and wiped the lease - so a
    live scan advertised itself as unclaimed, and a redelivery would have
    started a second one. Losing the race is normal and not an error: the
    row a worker wrote is strictly newer than this one.
    """
    now = now_iso()

    record = JobRecord(
        job_id=job_id,
        tenant_id=tenant_id,
        repo_id=repo_id,
        target=target,
        status="queued",
        progress=0,
        current_step="Queued",
        started_at=now,
        updated_at=now,
        expires_at=ttl_epoch(JOB_TTL_DAYS),
    )

    try:
        table("scan_jobs").put_item(
            Item=to_item(record),
            ConditionExpression="attribute_not_exists(job_id)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise

        logger.info(
            "Job %s was already claimed before its queued row was written",
            job_id,
        )

        existing = get_job(job_id)

        if existing is not None:
            return existing

    return record


def claim_job(
    job_id: str,
    tenant_id: str,
    repo_id: str,
    target: str,
) -> bool:
    """Move a job from queued to running, returning False if someone won.

    This is what makes at-least-once delivery safe: two workers handed the
    same message both call this, and exactly one gets True.
    """
    now = now_iso()

    record = JobRecord(
        job_id=job_id,
        tenant_id=tenant_id,
        repo_id=repo_id,
        target=target,
        status="running",
        progress=0,
        current_step="Starting",
        started_at=now,
        updated_at=now,
        expires_at=ttl_epoch(JOB_TTL_DAYS),
        lease_expires_at=epoch_in(JOB_LEASE_SECONDS),
    )

    try:
        table("scan_jobs").put_item(
            Item=to_item(record),
            # Three ways to win, and the third is the lease.
            #
            # "queued" counts as unclaimed: the API writes that row at 202 so
            # the client can poll and subscribe before a worker exists. Bare
            # attribute_not_exists would then fail every first delivery.
            #
            # A `running` row whose lease has lapsed is a job whose worker
            # stopped heartbeating - dead, or wedged past the point SQS has
            # already redelivered the message. Taking it over is the recovery.
            # A `running` row with a LIVE lease is a worker still working, and
            # this now returns False for it instead of starting a second scan
            # of the same image. See docs/audits/audit-01-backend.md P3-2.
            #
            # attribute_not_exists(lease_expires_at) covers rows written
            # before the field existed.
            ConditionExpression=(
                "attribute_not_exists(job_id) "
                "OR #status = :queued "
                "OR (#status = :running AND ("
                "attribute_not_exists(lease_expires_at) OR lease_expires_at < :now"
                "))"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":queued": "queued",
                ":running": "running",
                ":now": now_epoch(),
            },
        )

        return True

    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False

        raise


def renew_lease(job_id: str) -> bool:
    """Push this worker's claim out by another lease period.

    Called from the heartbeat, alongside the SQS visibility extension, so
    the two answer the same question in the two places it gets asked: SQS
    decides whether to redeliver, and the lease decides whether whoever
    receives it should act.

    Returns False when the job is no longer `running` - it finished, or
    another worker took the lease over - which tells the caller its claim
    is gone.
    """
    try:
        table("scan_jobs").update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET lease_expires_at = :lease, updated_at = :updated",
            ConditionExpression="#status = :running",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":lease": epoch_in(JOB_LEASE_SECONDS),
                ":updated": now_iso(),
                ":running": "running",
            },
        )

        return True

    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False

        raise


def lease_is_live(job: JobRecord, now: int | None = None) -> bool:
    """Whether a running job is still held by a worker that is alive.

    The question `handle_scan` used to have no way to ask.
    """
    return job.status == "running" and job.lease_expires_at > (now or now_epoch())


def update_progress(
    job_id: str,
    status: JobStatus,
    progress: int,
    step: str,
) -> None:
    """Overwrite a job's status, percentage and step.

    An update rather than a put so it cannot resurrect a row the TTL has
    already collected, and cannot clobber fields it does not name.
    """
    table("scan_jobs").update_item(
        Key={"job_id": job_id},
        UpdateExpression=(
            "SET #status = :status, "
            "progress = :progress, "
            "current_step = :step, "
            "updated_at = :updated"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": status,
            ":progress": progress,
            ":step": step,
            ":updated": now_iso(),
        },
    )


def get_job(job_id: str) -> JobRecord | None:
    """Load one job by id, or None when no such row exists."""
    resp = table("scan_jobs").get_item(Key={"job_id": job_id})

    item = resp.get("Item")

    return JobRecord.model_validate(item) if item else None


def recent_jobs(tenant_id: str, limit: int = 20) -> list[JobRecord]:
    """List a tenant's most recent jobs, newest first.

    Answered by the TenantIndex GSI, so it never reads another tenant's
    rows rather than reading and then filtering them.
    """
    resp = table("scan_jobs").query(
        IndexName="TenantIndex",
        KeyConditionExpression=Key("tenant_id").eq(tenant_id),
        ScanIndexForward=False,
        Limit=limit,
    )

    return [JobRecord.model_validate(item) for item in resp.get("Items", [])]
