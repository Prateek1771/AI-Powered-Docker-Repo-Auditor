# Phase 7 — The Queue: FIFO Groups, Visibility Arithmetic & Idempotency

A scan takes 90 seconds. An HTTP request cannot wait that long.

```text
   POST /scans                        worker process
        │                                    │
        ▼                                    ▼
   mint job_id                        long-poll the queue
        │                                    │
        ▼                                    ▼
   enqueue message  ───────────────────→  receive one
        │                                    │
        ▼                                    ▼
   return in ~50ms                     claim the job
   { job_id, queued }                  (conditional write)
                                             │
                                             ▼
                                       heartbeat task
                                       extends visibility
                                             │
                                             ▼
                                       run_and_store
                                             │
                                  ┌──────────┴──────────┐
                                  ▼                     ▼
                              success                failure
                                  │                     │
                                  ▼                     ▼
                          delete_message          let it raise
                                                        │
                                                        ▼
                                                  redelivery
                                                  then the DLQ
```

The rule for this phase:

```text
the queue will deliver your message
more than once, and you cannot stop it
```

Everything still runs in Docker. ElasticMQ speaks the SQS wire protocol, so the code you write here is the code that runs in AWS.

---

# 1. Run ElasticMQ

Create `elasticmq.conf` in your `worker/` directory:

```text
include classpath("application.conf")

node-address {
    protocol = http
    host = "localhost"
    port = 9324
    context-path = ""
}

rest-sqs {
    enabled = true
    bind-port = 9324
    bind-hostname = "0.0.0.0"
    sqs-limits = strict
}

queues {
    "scan-jobs.fifo" {
        fifo = true
        contentBasedDeduplication = false
        deadLettersQueue {
            name = "scan-jobs-dlq.fifo"
            maxReceiveCount = 3
        }
    }

    "scan-jobs-dlq.fifo" {
        fifo = true
        contentBasedDeduplication = false
    }
}
```

```powershell
docker run -d --name elasticmq -p 9324:9324 -p 9325:9325 `
  -v ${PWD}\elasticmq.conf:/opt/elasticmq.conf `
  softwaremill/elasticmq-native
```

Check it:

```powershell
docker logs elasticmq --tail 10
```

The queue UI is at `http://localhost:9325`, which is genuinely useful — you can watch message counts move as you work.

`sqs-limits = strict` makes ElasticMQ enforce the same constraints as real SQS: the 256 KB message ceiling, the 12-hour visibility maximum, the 20-second long-poll maximum. Without it you can write code that works locally and fails in AWS.

---

# 2. Why a queue at all

Three separate problems, one solution.

```text
duration     90s exceeds LB and browser timeouts
retry        a timed-out request gets retried, starting a duplicate scan
scaling      web tasks and scan workers need different resources
```

The API's job shrinks to almost nothing: mint an id, put a message on a queue, return. Fifty milliseconds. The browser then subscribes to that id for progress, which is Phase 9.

The consequence is that you now own a distributed system. Messages arrive out of order, arrive twice, or arrive at a worker that dies halfway through. The rest of this phase is about that.

---

# 3. FIFO, message groups, and deduplication

Create:

```text
worker/app/config/queue.py
```

```python
import os

SQS_ENDPOINT_URL = os.environ.get("SQS_ENDPOINT_URL")

SCAN_QUEUE_URL = os.environ.get(
    "SCAN_QUEUE_URL",
    "http://localhost:9324/000000000000/scan-jobs.fifo",
)

POLL_WAIT_SECONDS = 20

VISIBILITY_TIMEOUT_SECONDS = 300

HEARTBEAT_INTERVAL_SECONDS = 60

HEARTBEAT_EXTENSION_SECONDS = 300

MAX_MESSAGES_PER_POLL = 1

DEDUP_WINDOW_SECONDS = 60
```

Set it in your shell:

```powershell
$env:SQS_ENDPOINT_URL = "http://localhost:9324"
```

Now the producer. Create:

```text
worker/app/queue/producer.py
```

```python
import json
import logging
import uuid
from datetime import UTC, datetime

import boto3
from pydantic import BaseModel

from app.config.queue import (
    DEDUP_WINDOW_SECONDS,
    SCAN_QUEUE_URL,
    SQS_ENDPOINT_URL,
)
from app.config.storage import AWS_REGION

logger = logging.getLogger(__name__)


def get_client():
    kwargs: dict = {"region_name": AWS_REGION}

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
    window = int(
        datetime.now(UTC).timestamp() // DEDUP_WINDOW_SECONDS
    )

    return f"{tenant_id}:{repo_id}:{window}"


def enqueue_scan(
    tenant_id: str,
    repo_id: str,
    target: str,
) -> ScanMessage:
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
```

Three parameters, three different jobs.

**`MessageGroupId`** controls ordering. Messages sharing a group are delivered strictly one at a time, in order. Different groups run concurrently. Keying it on `tenant#repo` means two scans of the same repo serialise, so they never race to write "the latest result", while scans of different repos still fan out across workers.

**`MessageDeduplicationId`** suppresses duplicates within a five-minute window. This is where the reference implementation goes wrong:

```python
MessageDeduplicationId=job_id,   # a fresh uuid4 every call
```

A fresh UUID is unique by construction, so it can never collide, so deduplication never fires. The queue also sets `content_based_deduplication = true` in Terraform, but an explicit dedup ID overrides that. The feature is configured in two places and works in neither.

A user double-clicking Scan produces two UUIDs, two messages, and two full scans — serialised by the group id, but both paying for six model calls.

The version above buckets time into windows:

```text
tenant-a:nginx:29384710
```

Two clicks in the same minute produce the same string, and SQS silently drops the second. A deliberate rescan a minute later gets through.

```text
dedup id must be derived from the
REQUEST, never from a fresh uuid
```

---

# 4. The consumer loop

Create:

```text
worker/app/queue/consumer.py
```

```python
import asyncio
import contextlib
import logging

from app.config.queue import (
    HEARTBEAT_EXTENSION_SECONDS,
    HEARTBEAT_INTERVAL_SECONDS,
    MAX_MESSAGES_PER_POLL,
    POLL_WAIT_SECONDS,
    SCAN_QUEUE_URL,
    VISIBILITY_TIMEOUT_SECONDS,
)
from app.queue.producer import ScanMessage, get_client

logger = logging.getLogger(__name__)


async def _heartbeat(client, receipt_handle: str) -> None:
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)

        try:
            client.change_message_visibility(
                QueueUrl=SCAN_QUEUE_URL,
                ReceiptHandle=receipt_handle,
                VisibilityTimeout=HEARTBEAT_EXTENSION_SECONDS,
            )

            logger.debug("Extended visibility by %ds", HEARTBEAT_EXTENSION_SECONDS)

        except Exception as exc:
            logger.warning("Heartbeat failed: %s", exc)

            return


async def _with_heartbeat(client, receipt_handle: str, coro):
    task = asyncio.create_task(_heartbeat(client, receipt_handle))

    try:
        return await coro
    finally:
        task.cancel()

        with contextlib.suppress(asyncio.CancelledError):
            await task


async def consume_once(client, handler) -> int:
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

        attempt = int(
            raw.get("Attributes", {}).get("ApproximateReceiveCount", "1")
        )

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

        except Exception:
            logger.exception(
                "Job %s failed on attempt %d, leaving for redelivery",
                message.job_id,
                attempt,
            )

    return len(messages)
```

Read the `except` block carefully. It logs and **does not delete the message**. That single decision is the difference between a working retry policy and a dead-letter queue that stays empty forever.

---

# 5. Long polling

```python
WaitTimeSeconds=POLL_WAIT_SECONDS,   # 20
```

Without it, `receive_message` returns immediately with an empty list and your loop spins, billing you for every empty poll. With it, the call blocks up to twenty seconds waiting for work.

```text
short polling   ~2,000,000 requests/month per worker
long polling    ~130,000 requests/month per worker
```

Twenty is the maximum SQS allows. There is no reason to use less.

---

# 6. The visibility timeout arithmetic

When a worker receives a message, SQS hides it for `VisibilityTimeout` seconds. If the worker hasn't deleted it by then, the message reappears and another worker picks it up.

So the timeout must exceed your worst-case processing time. Do the arithmetic for the reference implementation:

```text
VisibilityTimeout                     900s

worst case inside the orchestrator:
  Trivy scan timeout                  600s
  dockerfile optimizer timeout        120s
  risk scorer timeout                 120s
                                    ──────
  timeouts alone                      840s

  plus manifest fetch, DynamoDB writes,
  S3 upload, SES email                 ???
                                    ──────
  total                             > 900s
```

A slow scan exceeds the window, reappears, and gets processed a second time — while the first worker is still running it. Two workers, one job, both writing results.

You could raise the number and guess again. Better: stop guessing.

---

# 7. Heartbeat instead of guessing

`_with_heartbeat` starts a background task that calls `change_message_visibility` every sixty seconds while the handler runs.

```text
t=0     receive, hidden for 300s
t=60    heartbeat  → hidden for another 300s
t=120   heartbeat  → hidden for another 300s
t=180   handler finishes, delete_message
        heartbeat task cancelled in finally
```

This inverts the failure mode, which is the real win:

```text
fixed timeout:  worker alive but slow    → duplicate processing
heartbeat:      worker dead              → message returns in 300s
                worker alive             → message stays hidden
```

A short timeout plus a heartbeat gives you fast recovery from crashes *and* no duplicates from slow runs. A long fixed timeout gives you neither.

The `finally` block is load-bearing. Without cancelling the task, every processed message leaves a coroutine extending the visibility of a message that no longer exists, forever.

One catch worth knowing: this only works because the handler is genuinely `async`. If your Trivy call were `subprocess.run` instead of `asyncio.create_subprocess_exec`, it would block the event loop and the heartbeat task would never get scheduled. Phase 1's choice pays off here.

---

# 8. At-least-once delivery, and what it costs you

SQS guarantees at-least-once delivery. Duplicates are not an edge case:

```text
worker crashes after storing results
    but before delete_message
        → redelivery

network drops the delete_message call
        → redelivery

visibility expires mid-scan
        → concurrent duplicate
```

The only defence is to make processing idempotent. Add a conditional claim to `app/storage/jobs.py`:

```python
from botocore.exceptions import ClientError


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
            ConditionExpression="attribute_not_exists(job_id)",
        )

        return True

    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False

        raise
```

`ConditionExpression="attribute_not_exists(job_id)"` makes the write succeed only if no row exists. DynamoDB evaluates it atomically, so two workers racing on the same `job_id` produce exactly one winner. No lock, no extra service.

Then the handler:

```python
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
```

Two distinct cases, handled differently.

```text
claim failed, status completed  →  a true duplicate. Return,
                                   the caller deletes the message.

claim failed, status running    →  a previous attempt died.
                                   Reprocess.
```

Returning normally on a duplicate is what lets the consumer delete the message. Raising there would send a successfully-completed job to the dead-letter queue.

---

# 9. The dead-letter queue that never fills

This is the most instructive bug in the reference implementation, because the infrastructure is correct and the application makes it inert.

The Terraform is right:

```hcl
redrive_policy = jsonencode({
  deadLetterTargetArn = aws_sqs_queue.scan_dlq.arn
  maxReceiveCount     = 3
})
```

Three failed attempts and the message moves to the DLQ, which retains it for fourteen days. Exactly what you want.

Now the consumer:

```python
for msg in messages:
    try:
        await process_message(msg)
        client.delete_message(...)
    except Exception as exc:
        logger.error("Failed to process message: %s", exc)
```

That looks like it handles failure. Follow `process_message`:

```python
async def process_message(message: dict) -> None:
    ...
    try:
        await run_orchestrator(job_id, user_id, repo_id, image_id, email)
    except Exception as exc:
        logger.error("Scan job %s failed: %s", job_id, exc)
        await update_job_status(job_id, "failed", 0, f"Error: {exc}")
        await publish_progress(job_id, "failed", 0, f"Scan failed: {exc}")
```

It catches everything and returns normally. So `process_message` almost never raises. So the outer `except` almost never runs. So `delete_message` always runs.

```text
scan fails
    ↓
inner except catches it
    ↓
process_message returns normally
    ↓
delete_message runs
    ↓
message gone. ApproximateReceiveCount never reaches 3.
    ↓
DLQ empty forever. Nothing ever retried.
```

Two try/except blocks, both individually reasonable, combining into a system with no retry policy at all. The failure is recorded in DynamoDB and dropped.

The fix is one line — re-raise after recording:

```python
except Exception as exc:
    logger.exception("Scan %s failed", job_id)
    update_progress(job_id, "failed", 0, str(exc)[:200])
    raise
```

Which is exactly what Phase 6's `run_and_store` already does.

```text
record the failure  →  the UI can show it
re-raise            →  the queue can retry it
```

Do only the first and you have a UI that reports failures and a system that never recovers from them.

---

# 10. Not everything deserves a retry

Retrying an OpenAI timeout is sensible. Retrying a malformed message body three times is three guaranteed failures and a wasted DLQ slot.

```python
class PermanentFailure(Exception):
    pass
```

In the consumer:

```python
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
```

The split:

```text
transient   network, timeout, throttle, 5xx    →  retry
permanent   bad input, missing image, 4xx      →  delete, record, move on
```

Raise `PermanentFailure` when Docker reports the image does not exist, or when the message fails schema validation. Everything else stays retryable by default, because guessing wrong in that direction only costs you two extra attempts.

---

# 11. Graceful shutdown, done properly

The reference implementation does this:

```python
_shutdown = asyncio.Event()

def _handle_signal(sig, frame):
    _shutdown.set()

signal.signal(signal.SIGTERM, _handle_signal)
```

Calling `asyncio.Event.set()` from a signal handler is not loop-safe. Signal handlers run between bytecode instructions on the main thread, not inside the event loop, so the waiters may not wake. Python provides `loop.add_signal_handler` precisely for this.

Create:

```text
worker/app/main.py
```

```python
import asyncio
import logging
import signal

from app.queue.consumer import consume_once
from app.queue.producer import get_client
from app.queue.handler import handle_scan

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

logger = logging.getLogger(__name__)

_shutdown = asyncio.Event()


def _install_handlers() -> None:
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _shutdown.set)
        except NotImplementedError:
            signal.signal(sig, lambda *_: _shutdown.set())


async def poll_forever() -> None:
    client = get_client()

    logger.info("Worker started, polling for scan jobs")

    while not _shutdown.is_set():
        try:
            await consume_once(client, handle_scan)

        except Exception:
            logger.exception("Poll cycle failed, backing off")

            await asyncio.sleep(5)

    logger.info("Shutdown complete")


async def main() -> None:
    _install_handlers()

    await poll_forever()


if __name__ == "__main__":
    asyncio.run(main())
```

`add_signal_handler` is not implemented on Windows, hence the fallback. You are developing on Windows and deploying to Linux, so you need both branches.

One honest limitation. `_shutdown.is_set()` is checked at the top of the loop, so a SIGTERM arriving 10 seconds into a 90-second scan is not noticed until that scan finishes. ECS sends SIGTERM, waits 30 seconds, then sends SIGKILL. Your worker gets hard-killed mid-scan.

That is survivable precisely because of the work in section 8: the message was never deleted, so it reappears after the visibility window and another worker claims it. **Idempotency is what makes an ungraceful shutdown merely inefficient rather than data-losing.**

---

# 12. Tests

Create `worker/tests/test_queue.py`:

```python
import uuid

import pytest

from app.config.queue import SCAN_QUEUE_URL
from app.queue.consumer import consume_once
from app.queue.producer import ScanMessage, enqueue_scan, get_client
from app.storage.jobs import claim_job, get_job

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
```

```powershell
uv run pytest tests/test_queue.py -v
```

Two of these are the phase in miniature.

`test_failure_leaves_the_message` asserts `seen == [2]` — the redelivered message carries `ApproximateReceiveCount` of 2. Write the consumer the reference implementation's way and this test fails, because the message was deleted despite the failure.

`test_claim_is_exclusive` proves the conditional write. Remove `ConditionExpression` and the second claim returns `True`, which is a duplicate scan.

---

# 13. Run it end to end

You now need two terminals.

Terminal one, the worker:

```powershell
$env:DYNAMODB_ENDPOINT_URL = "http://localhost:8000"
$env:SQS_ENDPOINT_URL = "http://localhost:9324"
uv run python -m app.main
```

Terminal two, the producer. Create `worker/app/scripts/enqueue.py`:

```python
import sys

from app.queue.producer import enqueue_scan


def main() -> None:
    target = sys.argv[1]

    message = enqueue_scan("demo-tenant", target.split(":")[0], target)

    print(f"enqueued {message.job_id}")


if __name__ == "__main__":
    main()
```

```powershell
$env:SQS_ENDPOINT_URL = "http://localhost:9324"
uv run python -m app.scripts.enqueue python:3.8
```

Watch terminal one pick it up, log progress, and delete the message.

Now test the interesting paths.

**Duplicate suppression.** Run `enqueue` twice within a minute. Only one scan should run.

**Ordering within a group.** Enqueue two different repos and watch both get picked up. Enqueue the same repo twice, more than a minute apart, and watch them serialise.

**Crash recovery.** Enqueue a scan, and while the worker is mid-scan, kill it:

```powershell
docker restart elasticmq
```

Restart the worker. After the visibility window the message returns, the claim fails, the job is found in `running` state, and it reprocesses. The queue UI at `http://localhost:9325` shows the message count going back up.

**The DLQ.** Temporarily make `handle_scan` raise unconditionally, enqueue a job, and let it fail three times. The message lands in `scan-jobs-dlq.fifo` and you can see it in the UI. Then try the same experiment with the reference implementation's swallow-everything handler and watch the DLQ stay at zero.

---

# 14. Quality gate

```powershell
uv run ruff check .
```

```powershell
uv run ruff format --check .
```

```powershell
uv run mypy app eval
```

```powershell
uv run pytest -m "not eval and not integration" -v
```

```powershell
uv run pytest -m integration -v
```

You should have:

```text
✓ Producer returns in milliseconds, work happens elsewhere
✓ Message group keyed on tenant#repo, ordering where it matters
✓ Dedup id derived from the request, not a fresh uuid
✓ Heartbeat extends visibility instead of guessing a timeout
✓ Conditional claim makes duplicate delivery harmless
✓ Failures re-raise, messages redeliver, the DLQ fills
✓ Permanent failures deleted rather than retried three times
✓ Signal handlers installed through the event loop
```

---

# 15. Where this sits

```text
  Phases 1-5          Phase 6              Phase 7  ◄── here
 ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
 │ measurable   │→ │ results that │→ │ jobs that survive│
 │ AI system    │  │ survive exit │  │ a worker dying   │
 └──────────────┘  └──────────────┘  └──────────────────┘
                                              │
                                              ▼
                                     ┌──────────────────┐
                                     │     Phase 8      │
                                     │   the API layer  │
                                     └──────────────────┘
```

The worker is now a proper background service. It can be killed at any moment, restarted, and run in multiples without corrupting anything. That property came from three specific decisions: never delete a message on failure, claim work with a conditional write, and extend visibility rather than guess at it.

---

# Errata — found while implementing this phase

**`elasticmq.conf` will not parse as written.** HOCON treats an unquoted dot as a path
separator, so `scan-jobs.fifo { fifo = true }` becomes `scan-jobs { fifo { fifo = true } }`
and ElasticMQ exits with `fifo has type OBJECT rather than BOOLEAN`. Quote both queue
names. The container still reports as started for a moment before dying, so check
`docker logs` rather than `docker ps`.

**`test_failure_leaves_the_message` cannot pass as written.** It asserts the redelivered
message arrives on the very next `consume_once`, but the consumer receives with
`VisibilityTimeout=300` and — correctly — does not reset it on failure. The message is
hidden for five minutes and the immediate second poll returns nothing.

Here the code is right and the test is wrong, which is worth sitting with. That 300-second
window *is* the retry backoff. Resetting visibility to zero on failure would make the test
pass and would burn all three receives in milliseconds, sending a transient failure to the
dead-letter queue before the condition it tripped on had any chance to clear. Fix the test
— shrink the window with `monkeypatch`, and let the 20-second long poll catch the
redelivery — rather than damaging the backoff to satisfy an assertion.

**`datetime.now(timezone.utc)` trips ruff UP017.** Use `datetime.now(UTC)`.

**Nothing else may be polling the queue while you test.** This bit hard enough to be worth
naming. A worker left running — including one orphaned after its parent shell was killed,
which is easy on Windows — long-polls continuously and takes every message you enqueue
within milliseconds. The symptom is that `enqueue_scan` returns a job id, the queue shows
`ApproximateNumberOfMessages = 0` and `NotVisible = 1`, and your own `receive_message`
gets nothing. It reads exactly like a broken producer. Check for strays first:

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*app.main*' }
```

**What the DLQ proof looks like when it works.** Three failed receives, then the fourth
finds nothing because the message moved:

```text
DLQ depth before: 0
  receive 1: got 1 message(s)
  receive 2: got 1 message(s)
  receive 3: got 1 message(s)
  receive 4: got 0 message(s)
DLQ depth after:  1
```

With the reference implementation's swallow-everything handler that final number stays 0,
which is the entire point of section 9.

---

## Next: Phase 8 — The API Layer

The producer needs an HTTP front door, and the moment it has one, every request is untrusted.

```text
     request
        │
        ▼
   ┌─────────────┐
   │ verify JWT  │   signature, not decode
   │ JWKS + RS256│
   └──────┬──────┘
          ▼
   ┌─────────────┐
   │ rate limit  │   scans cost real money
   │ sliding win │
   └──────┬──────┘
          ▼
   ┌─────────────┐
   │ authorise   │   is this repo yours
   └──────┬──────┘
          ▼
    enqueue_scan
          │
          ▼
   202 { job_id }
```

We build it with FastAPI, and run Redis in Docker for the rate limiter, so still no AWS account.

Three things worth getting right:

```text
1. verifying a JWT means checking the RS256 signature
   against the provider's JWKS, not decoding the payload
   and trusting what it says

2. a rate limiter should fail OPEN and an authenticator
   should fail CLOSED — the reference implementation gets
   this right, and it is worth understanding why

3. the tenant id must come from the verified token and
   never from the request body, or your Phase 6 tenant
   isolation is decorative
```

That third one is where most tutorial APIs quietly break, usually by accepting a `user_id` field in the JSON body.