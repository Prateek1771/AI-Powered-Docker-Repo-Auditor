import logging
from typing import Literal

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from pydantic import BaseModel

from app.config.storage import JOB_TTL_DAYS
from app.storage.client import table
from app.storage.serialization import now_iso, to_item, ttl_epoch

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


def create_job(
    job_id: str,
    tenant_id: str,
    repo_id: str,
    target: str,
) -> JobRecord:
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

    table("scan_jobs").put_item(Item=to_item(record))

    return record


def claim_job(
    job_id: str,
    tenant_id: str,
    repo_id: str,
    target: str,
) -> bool:
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
    )

    try:
        table("scan_jobs").put_item(
            Item=to_item(record),
            # "queued" counts as unclaimed: the API writes that row at 202 so
            # the client can poll and subscribe before a worker exists. Bare
            # attribute_not_exists would then fail every first delivery.
            # Claiming still means "I moved this from queued to running", so a
            # redelivery landing on a running or completed job loses the race.
            ConditionExpression=("attribute_not_exists(job_id) OR #status = :queued"),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":queued": "queued"},
        )

        return True

    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False

        raise


def update_progress(
    job_id: str,
    status: JobStatus,
    progress: int,
    step: str,
) -> None:
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
    resp = table("scan_jobs").get_item(Key={"job_id": job_id})

    item = resp.get("Item")

    return JobRecord.model_validate(item) if item else None


def recent_jobs(tenant_id: str, limit: int = 20) -> list[JobRecord]:
    resp = table("scan_jobs").query(
        IndexName="TenantIndex",
        KeyConditionExpression=Key("tenant_id").eq(tenant_id),
        ScanIndexForward=False,
        Limit=limit,
    )

    return [JobRecord.model_validate(item) for item in resp.get("Items", [])]
