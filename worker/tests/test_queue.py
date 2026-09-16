import uuid
from typing import Any, NamedTuple

import pytest

from app.errors import PermanentFailure
from app.queue.consumer import consume_once
from app.queue.producer import ScanMessage, enqueue_scan, get_client
from app.storage.jobs import claim_job, create_job, get_job

pytestmark = pytest.mark.integration


class Queue(NamedTuple):
    client: Any
    url: str


@pytest.fixture
def queue(monkeypatch: pytest.MonkeyPatch):
    """A FIFO queue belonging to this test alone.

    These tests used to purge and then share the one real `scan-jobs.fifo`,
    which meant they failed whenever the worker CONTAINER happened to be
    running locally - it consumed the messages they enqueued, and the
    failure looked like a bug in the code under test rather than a bug in
    the test. A queue nobody else knows the name of cannot be raced.

    Both modules read SCAN_QUEUE_URL at import, so both are patched.
    """
    client = get_client()

    url = client.create_queue(
        QueueName=f"test-{uuid.uuid4().hex[:20]}.fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false"},
    )["QueueUrl"]

    monkeypatch.setattr("app.queue.producer.SCAN_QUEUE_URL", url)
    monkeypatch.setattr("app.queue.consumer.SCAN_QUEUE_URL", url)

    yield Queue(client, url)

    client.delete_queue(QueueUrl=url)


def test_enqueue_returns_a_job_id(queue: Queue, tenant: str) -> None:
    message = enqueue_scan(tenant, "repo-a", "alpine:3.20")

    assert message.job_id
    assert message.target == "alpine:3.20"


async def test_message_roundtrips(queue: Queue, tenant: str) -> None:
    sent = enqueue_scan(tenant, "repo-a", "alpine:3.20")

    received: list[ScanMessage] = []

    async def handler(message: ScanMessage, attempt: int) -> None:
        received.append(message)

    count = await consume_once(queue.client, handler)

    assert count == 1
    assert received[0].job_id == sent.job_id


async def test_success_deletes_the_message(queue: Queue, tenant: str) -> None:
    enqueue_scan(tenant, "repo-a", "alpine:3.20")

    async def handler(message: ScanMessage, attempt: int) -> None:
        return None

    await consume_once(queue.client, handler)

    assert await consume_once(queue.client, handler) == 0


async def test_failure_leaves_the_message(
    queue: Queue,
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

    await consume_once(queue.client, failing)

    seen: list[int] = []

    async def recording(message: ScanMessage, attempt: int) -> None:
        seen.append(attempt)

    await consume_once(queue.client, recording)

    assert seen == [2]


async def test_permanent_failure_deletes_the_message_without_retry(
    queue: Queue,
    tenant: str,
) -> None:
    # A bad image reference will not become good on redelivery - this is the
    # bug that let it retry 3x and block its FIFO message group for minutes.
    enqueue_scan(tenant, "repo-a", "does-not-exist:bogus")

    async def bad_reference(message: ScanMessage, attempt: int) -> None:
        raise PermanentFailure("missing image")

    await consume_once(queue.client, bad_reference)

    seen: list[int] = []

    async def recording(message: ScanMessage, attempt: int) -> None:
        seen.append(attempt)

    await consume_once(queue.client, recording)

    assert seen == []


def test_dedup_suppresses_a_rapid_second_click(queue: Queue, tenant: str) -> None:
    first = enqueue_scan(tenant, "repo-a", "alpine:3.20")
    second = enqueue_scan(tenant, "repo-a", "alpine:3.20")

    assert first.job_id != second.job_id

    resp = queue.client.receive_message(
        QueueUrl=queue.url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=2,
    )

    assert len(resp.get("Messages", [])) == 1


def test_a_different_target_is_not_deduped(queue: Queue, tenant: str) -> None:
    # Two images are two scans. Before the target was part of the dedup id,
    # correcting a bad tag and rescanning inside the window was dropped -
    # and the row the API already wrote sat at 'queued' forever.
    enqueue_scan(tenant, "repo-a", "alpine:nope-not-real")
    enqueue_scan(tenant, "repo-a", "alpine:3.20")

    resp = queue.client.receive_message(
        QueueUrl=queue.url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=2,
    )

    assert len(resp.get("Messages", [])) == 2


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
