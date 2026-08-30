import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import boto3
from pydantic import BaseModel

from app.config.queue import (
    DEDUP_WINDOW_SECONDS,
    SCAN_QUEUE_URL,
    SQS_ENDPOINT_URL,
)
from app.config.storage import AWS_REGION

logger = logging.getLogger(__name__)


def get_client() -> Any:
    """Build the SQS client, pointed at ElasticMQ when running locally."""
    kwargs: dict[str, Any] = {"region_name": AWS_REGION}

    if SQS_ENDPOINT_URL:
        kwargs.update(
            endpoint_url=SQS_ENDPOINT_URL,
            aws_access_key_id="local",
            aws_secret_access_key="local",
        )

    return boto3.client("sqs", **kwargs)


class ScanMessage(BaseModel):
    job_id: str
    tenant_id: str
    repo_id: str
    target: str
    enqueued_at: str


def _dedup_id(tenant_id: str, repo_id: str) -> str:
    """Build a dedup id that collapses repeat clicks within a window.

    Derived from tenant, repo and a coarse time bucket rather than being
    random, because SQS only suppresses duplicates that share an id - a
    fresh uuid here would mean deduplication never fires at all.
    """
    window = int(datetime.now(UTC).timestamp() // DEDUP_WINDOW_SECONDS)

    return f"{tenant_id}:{repo_id}:{window}"


def enqueue_scan(
    tenant_id: str,
    repo_id: str,
    target: str,
) -> ScanMessage:
    """Put a scan on the queue and return the message that was sent.

    The group id is tenant#repo, so scans of one repo stay ordered while
    different repos run concurrently.
    """
    message = ScanMessage(
        job_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        repo_id=repo_id,
        target=target,
        enqueued_at=datetime.now(UTC).isoformat(),
    )

    get_client().send_message(
        QueueUrl=SCAN_QUEUE_URL,
        MessageBody=message.model_dump_json(),
        MessageGroupId=f"{tenant_id}#{repo_id}",
        MessageDeduplicationId=_dedup_id(tenant_id, repo_id),
    )

    logger.info(
        "Enqueued scan %s for %s",
        message.job_id,
        target,
    )

    return message
