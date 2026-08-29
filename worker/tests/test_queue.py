import uuid

import pytest

from app.config.queue import SCAN_QUEUE_URL
from app.queue.consumer import consume_once
from app.queue.producer import ScanMessage, enqueue_scan, get_client
from app.storage.jobs import claim_job, create_job, get_job

pytestmark = pytest.mark.integration


@pytest.fixture
def drained():
    client = get_client()

    client.purge_queue(QueueUrl=SCAN_QUEUE_URL)

    return client


def test_enqueue_returns_a_job_id(drained, tenant: str) -> None:
    message = enqueue_scan(tenant, "repo-a", "alpine:3.20")

    assert message.job_id
    assert message.target == "alpine:3.20"


async def test_message_roundtrips(drained, tenant: str) -> None:
    sent = enqueue_scan(tenant, "repo-a", "alpine:3.20")

    received: list[ScanMessage] = []

    async def handler(message: ScanMessage, attempt: int) -> None:
        received.append(message)

    count = await consume_once(drained, handler)

    assert count == 1
    assert received[0].job_id == sent.job_id


async def test_success_deletes_the_message(drained, tenant: str) -> None:
    enqueue_scan(tenant, "repo-a", "alpine:3.20")

    async def handler(message: ScanMessage, attempt: int) -> None:
        return None

    await consume_once(drained, handler)

    assert await consume_once(drained, handler) == 0


async def test_failure_leaves_the_message(
    drained,
    tenant: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Production leans on the full 300s visibility window as the retry backoff,
    # so shrink it here - the 20s long poll then picks the message back up as
    # soon as it reappears, instead of the test waiting five minutes.
    monkeypatch.setattr("app.queue.consumer.VISIBILITY_TIMEOUT_SECONDS", 1)

    enqueue_scan(tenant, "repo-a", "alpine:3.20")

    async def failing(message: ScanMessage, attempt: int) -> None:
        raise RuntimeError("boom")

    await consume_once(drained, failing)

    seen: list[int] = []

    async def recording(message: ScanMessage, attempt: int) -> None:
        seen.append(attempt)

    await consume_once(drained, recording)

    assert seen == [2]


def test_dedup_suppresses_a_rapid_second_click(drained, tenant: str) -> None:
    first = enqueue_scan(tenant, "repo-a", "alpine:3.20")
    second = enqueue_scan(tenant, "repo-a", "alpine:3.20")

    assert first.job_id != second.job_id

    resp = drained.receive_message(
        QueueUrl=SCAN_QUEUE_URL,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=2,
    )

    assert len(resp.get("Messages", [])) == 1


def test_claim_is_exclusive(tenant: str) -> None:
    job_id = str(uuid.uuid4())

    assert claim_job(job_id, tenant, "repo-a", "alpine:3.20") is True
    assert claim_job(job_id, tenant, "repo-a", "alpine:3.20") is False

    job = get_job(job_id)

    assert job is not None
    assert job.status == "running"


def test_claiming_a_queued_job_succeeds(tenant: str) -> None:
    """The API pre-creates the row as queued; the worker must still claim it."""
    job_id = f"{tenant}-claim-queued"

    create_job(job_id, tenant, "repo-a", "alpine:3.20")

    assert claim_job(job_id, tenant, "repo-a", "alpine:3.20") is True


def test_claiming_a_running_job_fails(tenant: str) -> None:
    """A redelivery landing on a job someone else is already running loses."""
    job_id = f"{tenant}-claim-running"

    create_job(job_id, tenant, "repo-a", "alpine:3.20")

    assert claim_job(job_id, tenant, "repo-a", "alpine:3.20") is True
    assert claim_job(job_id, tenant, "repo-a", "alpine:3.20") is False
