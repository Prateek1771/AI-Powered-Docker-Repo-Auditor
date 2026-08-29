# Phase 9 — Real-Time Progress: Why In-Memory Fan-Out Cannot Work

Polling works. It is also the wrong shape: a ninety-second scan means forty-five requests per client, forty-four of which return bytes the client already has.

```text
      THE NAIVE VERSION                  THE ONE THAT WORKS

  browser ──ws──→ API process        browser ──ws──→ API process
                      │                                  │
              dict in memory                     subscribe to
                      │                          progress:{job_id}
                      ▲                                  ▲
                      │                                  │
              worker process                      Redis pub/sub
              publishes to...                            ▲
              which dict?                                │
                                                  worker publishes
```

The rule for this phase:

```text
you cannot move a TCP socket between
processes, so move the ROUTING instead
```

Redis is already running from Phase 8. No new infrastructure.

---

# 1. Build the naive version first

Do this properly before you throw it away. The failure is more instructive than the fix.

Create:

```text
app/api/ws_naive.py
```

```python
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, job_id: str) -> None:
        await websocket.accept()

        self._connections.setdefault(job_id, []).append(websocket)

    def disconnect(self, websocket: WebSocket, job_id: str) -> None:
        remaining = [
            ws
            for ws in self._connections.get(job_id, [])
            if ws is not websocket
        ]

        self._connections[job_id] = remaining

    async def broadcast(self, job_id: str, data: dict) -> None:
        dead: list[WebSocket] = []

        for ws in self._connections.get(job_id, []):
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws, job_id)


manager = ConnectionManager()


@router.websocket("/ws-naive")
async def websocket_naive(websocket: WebSocket) -> None:
    job_id = ""

    try:
        await websocket.accept()

        message = json.loads(await websocket.receive_text())

        job_id = message.get("jobId", "")

        if not job_id:
            await websocket.close(code=1008)

            return

        await manager.connect(websocket, job_id)

        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        if job_id:
            manager.disconnect(websocket, job_id)
```

This is competent code. Dead-connection cleanup, clean disconnect handling, correct close codes. It also cannot work, for two independent reasons.

---

# 2. Reason one: the publisher is a different process

Trace who calls `manager.broadcast`.

```text
manager lives in    the API process
progress comes from the worker process
```

They are separate processes. In Phase 11 they become separate containers. The worker cannot call a method on an object in another process's heap — there is no mechanism by which that could happen.

You could import `manager` in the worker. Python will happily let you. You would get a *second, empty* `ConnectionManager` in the worker's own memory, broadcast into it, and nothing would reach anyone.

```text
worker:  manager._connections = {}          ← its own copy
API:     manager._connections = {job: [ws]} ← where the socket is
```

No error. No warning. Progress events published into a void.

The reference implementation has exactly this file, registered at line 43 of `main.py`, complete and non-functional. Progress actually flows through a different path entirely.

---

# 3. Reason two: it would still fail at two tasks

Suppose you merged the API and worker into one process to dodge reason one. Now scale to two tasks behind a load balancer:

```text
browser opens ws  →  load balancer  →  task A
                                        _connections = {job-1: [ws]}

scan runs on                            task B
                                        _connections = {}
                                        broadcast(job-1) → nobody
```

With three tasks you deliver roughly a third of your events, and which third is random.

---

# 4. The actual diagnosis

The lesson is usually stated as "don't keep state in process memory." That is too vague to act on, because a WebSocket **is** a TCP socket owned by one process. You cannot put it in Redis. It has to live in memory somewhere.

The precise problem is different:

```text
the socket must stay in one process
the publisher is in another process
therefore the MESSAGE must cross the gap
```

You don't move the connection. You move the routing. Every API task subscribes to a shared channel; whichever one happens to hold the socket forwards the message on.

```text
worker ──publish──→ Redis channel ──→ every API task
                                            │
                                    holds a socket for
                                    this job? forward it.
                                    otherwise ignore.
```

That is a fan-out bus, and it is the general shape of every solution to this problem. Redis pub/sub, NATS, and AWS API Gateway's connection registry are the same idea with different operational trade-offs.

---

# 5. The progress bus interface

Define the contract before either implementation.

Create:

```text
app/progress/__init__.py
app/progress/bus.py
```

```python
from collections.abc import AsyncGenerator
from typing import Protocol

from pydantic import BaseModel

from app.storage.serialization import now_iso


class ProgressEvent(BaseModel):
    job_id: str
    status: str
    progress: int
    step: str
    at: str = ""

    @classmethod
    def create(
        cls,
        job_id: str,
        status: str,
        progress: int,
        step: str,
    ) -> "ProgressEvent":
        return cls(
            job_id=job_id,
            status=status,
            progress=progress,
            step=step,
            # now_iso() is datetime.now(UTC).isoformat() - timezone-aware, so
            # the browser reads a real instant rather than guessing local time.
            at=now_iso(),
        )


class ProgressBus(Protocol):
    async def publish(self, event: ProgressEvent) -> None: ...

    # AsyncGenerator, not AsyncIterator: the WS endpoint needs anext() to hand
    # create_task a real coroutine, and aclose() to run the unsubscribe on the
    # early-return path. Neither is on AsyncIterator.
    def listen(self, job_id: str) -> AsyncGenerator[ProgressEvent, None]: ...

    async def close(self) -> None: ...
```

A note on `datetime.now(timezone.utc)`. The reference implementation writes:

```python
"timestamp": __import__("datetime").datetime.utcnow().isoformat(),
```

Two problems in one line. `utcnow()` is deprecated from Python 3.12 and returns a **naive**
datetime with no timezone, so the ISO string has no `Z` or offset and a browser will
interpret it as local time. And `__import__` inline runs the import machinery on every
single call instead of once at module load.

The fix is already in the repo. `app.storage.serialization.now_iso()` is
`datetime.now(UTC).isoformat()` and is what every other timestamp here uses, so reach for
it rather than adding a second way to spell the same thing.

One note on the `Protocol`. `listen` is typed `AsyncGenerator`, not `AsyncIterator`,
because the WebSocket endpoint in section 10 needs `anext()` to hand `create_task` a real
coroutine and `aclose()` to run the unsubscribe on its early-return path. Neither is on
`AsyncIterator`, and declaring the narrower type is what makes the Protocol type-check
instead of decorate.

---

# 6. The Redis implementation

`redis` is already a direct dependency from Phase 8 — `app/core/ratelimit.py` uses the
sync client — and it ships `redis.asyncio`. Nothing to install. The `[hiredis]` extra is a
parsing speedup for a bus carrying four messages per scan; skip it.

Create:

```text
app/progress/redis_bus.py
```

```python
import logging
from collections.abc import AsyncGenerator

import redis.asyncio as aioredis

from app.config.api import REDIS_URL
from app.progress.bus import ProgressEvent

logger = logging.getLogger(__name__)


def _channel(job_id: str) -> str:
    return f"progress:{job_id}"


class RedisProgressBus:
    def __init__(self, url: str = REDIS_URL) -> None:
        self._redis = aioredis.from_url(url, decode_responses=True)

    async def publish(self, event: ProgressEvent) -> None:
        await self._redis.publish(
            _channel(event.job_id),
            event.model_dump_json(),
        )

    async def listen(self, job_id: str) -> AsyncGenerator[ProgressEvent, None]:
        pubsub = self._redis.pubsub()

        await pubsub.subscribe(_channel(job_id))

        try:
            async for raw in pubsub.listen():
                # listen() also yields the subscribe confirmation; without this
                # the first "event" is a {"type": "subscribe"} dict.
                if raw["type"] != "message":
                    continue

                try:
                    yield ProgressEvent.model_validate_json(raw["data"])
                except ValueError:
                    logger.warning("Dropping malformed progress event")

        finally:
            # Without this every closed tab leaves a live subscription on the
            # connection, and they accumulate for the life of the process.
            await pubsub.unsubscribe(_channel(job_id))
            await pubsub.aclose()

    async def close(self) -> None:
        await self._redis.aclose()
```

The `finally` block matters. Without unsubscribing, every closed browser tab leaves a subscription on the Redis connection, and they accumulate for the lifetime of the process.

`pubsub.listen()` yields subscription confirmations as well as messages, hence the `type` check. Skip it and your first event will be a `{"type": "subscribe"}` dict that fails validation.

---

# 7. Pub/sub has no memory

Redis pub/sub is fire-and-forget. A message published while nobody is subscribed is gone.

```text
t=0   POST /scans           job queued
t=1   worker: progress 10%  published, nobody listening
t=2   browser connects      subscribes
t=3   worker: progress 40%  received
```

The client's first render shows 40% with no idea what happened before. Worse, if it connects after the scan finishes it sees nothing at all and hangs on a spinner forever.

The fix is **snapshot then stream**, and it is the standard pattern for any live-updating view:

```text
1. read the current state from the database
2. send it immediately
3. subscribe and forward everything after
```

DynamoDB is already the source of truth for job state, updated by `update_progress` on every tick. Read it once at connect, then go live.

There is a small race between the snapshot read and the subscribe. Subscribe **first**, then read the snapshot, and you may deliver one event twice instead of missing one. Duplicate progress events are harmless if the client treats them as idempotent state; missed ones are not.

```text
order: subscribe, then snapshot   →  possible duplicate  →  fine
order: snapshot, then subscribe   →  possible gap        →  a stuck UI
```

---

# 8. Publish from the worker

Update `run_and_store` in `app/orchestrator.py`:

```python
from app.progress.bus import ProgressEvent
from app.progress.redis_bus import RedisProgressBus


async def _report(
    bus: RedisProgressBus,
    job_id: str,
    status: str,
    progress: int,
    step: str,
) -> None:
    update_progress(job_id, status, progress, step)

    try:
        await bus.publish(
            ProgressEvent.create(job_id, status, progress, step)
        )
    except Exception:
        logger.warning("Progress publish failed for %s", job_id, exc_info=True)


async def run_and_store(
    job_id: str,
    tenant_id: str,
    repo_id: str,
    target: str,
) -> ScanSummary:
    bus = RedisProgressBus()

    try:
        await _report(bus, job_id, "running", 10, "Fetching image data")

        trivy_raw, history_raw, inspect_raw = await asyncio.gather(
            run_trivy_scan(target),
            run_docker_history(target),
            run_image_inspect(target),
        )

        await _report(bus, job_id, "running", 40, "Running agents")

        scan = await run_scan_from_raw(
            target, trivy_raw, history_raw, inspect_raw
        )

        await _report(bus, job_id, "running", 90, "Storing results")

        summary = store_result(job_id, tenant_id, repo_id, scan)

        await _report(bus, job_id, "completed", 100, "Scan complete")

        return summary

    except Exception as exc:
        logger.exception("Scan %s failed", job_id)

        await _report(bus, job_id, "failed", 0, str(exc)[:200])

        raise

    finally:
        await bus.close()
```

Two things to notice.

`_report` writes to DynamoDB **before** publishing. The database is the source of truth; the bus is an optimisation. A client that misses an event can always recover by reading state.

The publish is wrapped in its own `try`. A Redis outage must not fail a scan that is otherwise working. Progress delivery is a nice-to-have; the scan result is not.

The `finally` closes the Redis connection. Without it, each processed message leaks a
connection and the worker eventually exhausts Redis's client limit.

Notice what is **not** here: `create_job`. The row now exists before this function runs,
because the API writes it when it returns 202 — otherwise the `job_id` it hands back is
unwatchable until a worker happens to pick the message up. Creating it again here would
stomp the `running` state `claim_job` just won. That change reaches back into Phase 7 and
Phase 8; the errata at the end of this phase has the diffs.

---

# 9. Authorizing the subscription

Before writing the endpoint, look at how the reference implementation handles subscribe:

```python
@router.post("/ws/message")
async def ws_message(request: Request):
    connection_id = request.headers.get("x-connection-id", "")
    body = await request.json()

    if body.get("action") == "subscribe":
        job_id = body.get("jobId", "")

        if connection_id and job_id:
            await save_ws_connection(job_id, connection_id)
```

A Lambda authorizer validated the token at connect time, so the caller is authenticated. Then any authenticated user can subscribe to **any** `job_id` and receive another tenant's scan progress in real time.

```text
gateway authorizer  →  proves you are a valid user
subscribe handler   →  never checks the job is yours
```

This is the same Broken Object Level Authorization bug from Phase 8, in a different shape. Authentication happened once, at the door, and was then treated as authorization for every subsequent action.

```text
authenticating the CONNECTION
is not authorizing the SUBSCRIPTION
```

Every message on a long-lived connection is a separate request and needs its own check.

---

# 10. The WebSocket endpoint

Browsers cannot set headers on a WebSocket handshake, so the token goes in the query string. That is the standard workaround and it has a real cost: tokens land in access logs, proxy logs, and browser history.

```text
mitigations that actually help:
  short token TTL (15 minutes, not 12 hours)
  redact the token param in log config
  a dedicated short-lived ws token, not the API token
```

Create:

```text
app/api/ws.py
```

```python
import asyncio
import contextlib
import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.core.auth import verify_token
from app.progress.bus import ProgressBus, ProgressEvent
from app.progress.redis_bus import RedisProgressBus
from app.storage.jobs import get_job

logger = logging.getLogger(__name__)

router = APIRouter()

PING_INTERVAL_SECONDS = 25

TERMINAL = ("completed", "failed")


async def _keepalive(websocket: WebSocket) -> None:
    # Load balancers cut idle connections - 60s is the ALB default. A 90s scan
    # with a quiet stretch in the middle loses its socket without this.
    while True:
        await asyncio.sleep(PING_INTERVAL_SECONDS)

        await websocket.send_json({"type": "ping"})


async def _finish(task: asyncio.Task) -> None:
    task.cancel()

    with contextlib.suppress(asyncio.CancelledError, Exception):
        await task


@router.websocket("/ws/jobs/{job_id}")
async def job_progress(
    websocket: WebSocket,
    job_id: str,
    token: str = Query(...),
) -> None:
    # to_thread, not a direct call: verify_token fetches the JWKS with a
    # blocking httpx client. Run on the event loop it stalls every other
    # connection, and self-deadlocks outright when JWKS_URL points back at
    # this same app. Same reason app.core.auth.current_principal is sync.
    try:
        claims = await asyncio.to_thread(verify_token, token)
    except Exception:  # noqa: BLE001 - any auth failure is one close frame
        await websocket.close(code=1008, reason="Unauthorized")

        return

    tenant_id = claims["sub"]

    job = await asyncio.to_thread(get_job, job_id)

    # Authenticating the CONNECTION is not authorizing the SUBSCRIPTION. The
    # close fires before accept(), so an unauthorized client never holds a
    # socket at all.
    if job is None or job.tenant_id != tenant_id:
        await websocket.close(code=1008, reason="Not found")

        return

    await websocket.accept()

    bus: ProgressBus = RedisProgressBus()

    stream = bus.listen(job_id)

    # Subscribe BEFORE reading the snapshot. Reversed, an event published in
    # the gap is lost forever; this way it can arrive twice, and duplicate
    # progress is harmless to a client treating it as state.
    first = asyncio.create_task(anext(stream))

    ping = asyncio.create_task(_keepalive(websocket))

    try:
        snapshot = await asyncio.to_thread(get_job, job_id)

        if snapshot is not None:
            await websocket.send_json(
                ProgressEvent.create(
                    snapshot.job_id,
                    snapshot.status,
                    snapshot.progress,
                    snapshot.current_step,
                ).model_dump()
            )

            # Already finished: send the final state and go. Otherwise a client
            # opening yesterday's scan waits on the spinner forever.
            if snapshot.status in TERMINAL:
                return

        event = await first

        await websocket.send_json(event.model_dump())

        if event.status not in TERMINAL:
            async for event in stream:
                await websocket.send_json(event.model_dump())

                if event.status in TERMINAL:
                    break

    except WebSocketDisconnect:
        logger.info("Client disconnected from job %s", job_id)

    except Exception:
        logger.exception("WebSocket error on job %s", job_id)

    finally:
        await _finish(ping)

        # first has to be settled before aclose(), or the generator is still
        # running. aclose() is what actually runs listen()'s unsubscribe.
        await _finish(first)

        with contextlib.suppress(Exception):
            await stream.aclose()

        await bus.close()

        with contextlib.suppress(Exception):
            await websocket.close()
```

Register it in `app/api/main.py`:

```python
from app.api import scans, ws

app.include_router(scans.router)
app.include_router(ws.router)
```

Seven things this endpoint gets right.

**Authorization before accept.** `websocket.close(code=1008)` fires before `accept()`, so an
unauthorized client never gets an open socket at all.

**Neither blocking call runs on the event loop.** `verify_token` fetches the JWKS with a
blocking `httpx.Client`, and `get_job` is blocking boto3. Awaited directly from an `async def`
handler they stall every other connection on the loop — and `verify_token` deadlocks a
single-worker uvicorn outright when `JWKS_URL` points back at this same app, which is the dev
default. This is the identical trap Phase 8 hit in `current_principal`, and `app/core/auth.py`
still carries the comment about it. A route dependency gets FastAPI's threadpool for free; a
WebSocket route has no dependency to lean on, so `asyncio.to_thread` does it by hand. Same
call length, no extra code.

**Subscribe before snapshot.** `anext(stream)` starts the subscription, then the snapshot is
read. Reversed, an event published in between would be lost — and a duplicate is harmless to a
client treating progress as state, while a gap is a stuck spinner.

**Terminal states end the connection.** If the job already finished, send the final state and
close. Otherwise a client opening a page for yesterday's scan waits forever.

**The first streamed event gets the same check.** `first` is sent before the `async for`, so
without checking its status there too, a client that connects just as the scan finishes
receives the terminal event and then hangs on a bar sitting at 100%.

**The generator is closed, not just cancelled.** `first` is settled in the `finally` before
`stream.aclose()` — an async generator cannot be closed while a task is still pending on
`__anext__`. Cancelling the task and returning would skip `listen`'s `finally` and with it the
unsubscribe that section 6 argues for.

**Keepalive.** Load balancers close idle connections — 60 seconds is the AWS ALB default. A
90-second scan with a quiet stretch in the middle gets its socket cut without the ping.

---

# 11. Connection cleanup, and two bugs that compound

The reference implementation's connection registry has a pair of bugs that make each other worse.

The writer:

```python
async def save_ws_connection(job_id: str, connection_id: str) -> None:
    table.put_item(Item={"job_id": job_id, "connection_id": connection_id})
```

The table declares `ttl { attribute_name = "expires_at" }` and this writer never sets `expires_at`. Same bug as `scan_jobs` in Phase 6. Stale connection rows accumulate forever.

The deleter:

```python
async def delete_ws_connection(connection_id: str) -> None:
    resp = table.scan(FilterExpression=Attr("connection_id").eq(connection_id))

    for item in resp.get("Items", []):
        table.delete_item(Key={"job_id": item["job_id"], "connection_id": connection_id})
```

The table's key is `(job_id, connection_id)`, but disconnect only knows `connection_id`. So it **scans the entire table** on every disconnect. It also reads only the first page, so past 1 MB of data some connections are never deleted at all.

```text
no TTL          →  table grows without bound
scan on delete  →  every disconnect gets slower
missing pages   →  more rows survive → table grows faster
```

Each bug accelerates the other. This is what a slow production outage looks like: fine at ten users, unusable at ten thousand, and nothing in the code changed.

Both fixes are small. Add a GSI on `connection_id` so disconnect is a query rather than a scan, and write `expires_at` as an epoch integer so the TTL sweeps anything the disconnect handler missed.

The Redis version sidesteps all of it — an unsubscribed channel simply stops existing, and a dropped connection takes its subscription with it. **Choosing infrastructure whose cleanup is automatic is worth more than writing careful cleanup code.**

---

# 12. What changes in AWS

Redis pub/sub works in production. Plenty of systems run exactly this. AWS's managed alternative moves the socket out of your process entirely:

```text
              REDIS (yours)              API GATEWAY (managed)

socket        your API task              the gateway holds it
registry      Redis subscriptions        DynamoDB table
fan-out       PUBLISH                    post_to_connection per id
cleanup       automatic                  GoneException + TTL
scaling       your tasks                 gateway's problem
cost          one Redis node             per message + per minute
```

The reason the interface in section 5 is a `Protocol` is that Phase 12 adds a third implementation and nothing above it changes:

```python
class ApiGatewayProgressBus:
    async def publish(self, event: ProgressEvent) -> None:
        for connection_id in self._connection_ids(event.job_id):
            try:
                self._client.post_to_connection(
                    ConnectionId=connection_id,
                    Data=event.model_dump_json().encode(),
                )
            except self._client.exceptions.GoneException:
                self._forget(event.job_id, connection_id)
```

`GoneException` is the socket-closed signal, and pruning on it is what keeps the registry from growing. Catching it is not optional cleanup — it is the only cleanup that runs promptly.

---

# 13. Tests

Create `tests/test_progress.py`:

```python
import asyncio

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.dev.keys import mint_token
from app.progress.bus import ProgressEvent
from app.progress.redis_bus import RedisProgressBus
from app.storage.jobs import create_job, update_progress

pytestmark = pytest.mark.integration

client = TestClient(app)


@pytest.fixture(autouse=True)
def _serve_jwks(jwks_server):
    """The WS handler verifies the token over real HTTP, same as the API."""


async def test_publish_reaches_a_subscriber() -> None:
    bus = RedisProgressBus()

    received: list[ProgressEvent] = []

    async def reader() -> None:
        async for event in bus.listen("job-1"):
            received.append(event)

            return

    task = asyncio.create_task(reader())

    await asyncio.sleep(0.2)

    await bus.publish(ProgressEvent.create("job-1", "running", 40, "Agents"))

    await asyncio.wait_for(task, timeout=3)

    await bus.close()

    assert received[0].progress == 40
    assert received[0].step == "Agents"


async def test_two_subscribers_both_receive() -> None:
    bus = RedisProgressBus()

    counts = {"a": 0, "b": 0}

    async def reader(name: str) -> None:
        async for _ in bus.listen("job-2"):
            counts[name] += 1

            return

    tasks = [
        asyncio.create_task(reader("a")),
        asyncio.create_task(reader("b")),
    ]

    await asyncio.sleep(0.2)

    await bus.publish(ProgressEvent.create("job-2", "running", 10, "Start"))

    await asyncio.wait_for(asyncio.gather(*tasks), timeout=3)

    await bus.close()

    assert counts == {"a": 1, "b": 1}


async def test_a_subscription_confirmation_is_not_an_event() -> None:
    bus = RedisProgressBus()

    stream = bus.listen("job-confirm")

    first = asyncio.create_task(anext(stream))

    await asyncio.sleep(0.2)

    await bus.publish(ProgressEvent.create("job-confirm", "running", 90, "Storing"))

    event = await asyncio.wait_for(first, timeout=3)

    await stream.aclose()
    await bus.close()

    assert event.progress == 90


def test_ws_rejects_a_missing_token(tenant: str) -> None:
    job_id = f"{tenant}-job-3"

    create_job(job_id, tenant, "repo-a", "alpine:3.20")

    with (
        pytest.raises(Exception),  # noqa: B017
        client.websocket_connect(f"/ws/jobs/{job_id}"),
    ):
        pass


def test_ws_rejects_another_tenants_job(tenant: str) -> None:
    job_id = f"{tenant}-job-4"

    create_job(job_id, tenant, "repo-a", "alpine:3.20")

    attacker = mint_token(f"{tenant}-attacker")

    with (
        pytest.raises(Exception),  # noqa: B017
        client.websocket_connect(f"/ws/jobs/{job_id}?token={attacker}") as ws,
    ):
        ws.receive_json()


def test_ws_sends_a_snapshot_immediately(tenant: str) -> None:
    job_id = f"{tenant}-job-5"

    create_job(job_id, tenant, "repo-a", "alpine:3.20")

    update_progress(job_id, "running", 40, "Running agents")

    token = mint_token(tenant)

    with client.websocket_connect(f"/ws/jobs/{job_id}?token={token}") as ws:
        first = ws.receive_json()

    assert first["progress"] == 40
    assert first["step"] == "Running agents"


def test_ws_closes_on_a_finished_job(tenant: str) -> None:
    job_id = f"{tenant}-job-6"

    create_job(job_id, tenant, "repo-a", "alpine:3.20")

    update_progress(job_id, "completed", 100, "Scan complete")

    token = mint_token(tenant)

    with client.websocket_connect(f"/ws/jobs/{job_id}?token={token}") as ws:
        first = ws.receive_json()

    assert first["status"] == "completed"
```

```powershell
uv run pytest tests/test_progress.py -v
```

`test_ws_rejects_another_tenants_job` is the one that matters. Delete the `job.tenant_id != tenant_id` check and it goes green — which is the reference implementation's behaviour.

`test_ws_sends_a_snapshot_immediately` guards against the pub/sub amnesia problem. Remove
the snapshot and a client connecting mid-scan receives nothing until the next tick.

The autouse `_serve_jwks` fixture is not optional. The WS handler verifies the token over
real HTTP, and without the dev JWKS server listening every authorized test fails on a 1008
close that looks exactly like the tenant check misfiring.

---

# 14. Run it

```powershell
docker start dynamodb-local elasticmq redis
```

Three terminals as before: API on 8080, worker, and a client.

For the client, create `app/scripts/watch.py`:

```python
import asyncio
import json
import sys

import websockets

from app.dev.keys import mint_token


async def main() -> None:
    job_id = sys.argv[1]

    token = mint_token("demo-tenant")

    url = f"ws://localhost:8080/ws/jobs/{job_id}?token={token}"

    async with websockets.connect(url) as ws:
        async for raw in ws:
            event = json.loads(raw)

            if event.get("type") == "ping":
                continue

            bar = "#" * (event["progress"] // 5)

            print(f"{event['progress']:3d}% |{bar:<20}| {event['step']}")

            if event["status"] in ("completed", "failed"):
                break


if __name__ == "__main__":
    asyncio.run(main())
```

```powershell
uv add --dev websockets
```

Start a scan, grab the job id, then watch it:

```powershell
uv run python -m app.scripts.watch PASTE_JOB_ID
```

You should see:

```text
 10% |##                  | Fetching image data
 40% |########            | Running agents
 90% |##################  | Storing results
100% |####################| Scan complete
```

Now prove the point. Run a **second** API process on a different port:

```powershell
uv run uvicorn app.api.main:app --port 8081
```

Point the watcher at 8081 while the worker publishes as before. It still works, because the routing goes through Redis and both API processes are subscribed. Swap in the naive endpoint from section 1 and neither port receives anything.

Two more worth trying. Open two watchers on the same job and confirm both get every event. And connect a watcher to a job that already finished — it should print the final line and exit rather than hanging.

---

# 15. Quality gate

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
✓ Routing moved to a shared bus, sockets stay in process
✓ Works across multiple API processes, proven on two ports
✓ Snapshot then stream, no gap for late subscribers
✓ Subscribe before snapshot, duplicates over gaps
✓ Every subscription authorized, not just the connection
✓ Terminal states close the socket
✓ Keepalive beats the load balancer idle timeout
✓ Subscriptions and Redis connections closed in finally
✓ Bus behind a Protocol, ready for a third implementation
```

Delete `app/api/ws_naive.py` now. Dead code that looks live is a trap for whoever reads this next — which is the mistake the reference implementation is still shipping at line 43 of its `main.py`.

---

# 16. Where this sits

```text
 Phase 6      Phase 7       Phase 8        Phase 9  ◄── here
┌─────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────┐
│ storage │→│ queue    │→│ API +     │→│ live progress│
│         │ │          │ │ authz     │ │ over a bus   │
└─────────┘ └──────────┘ └───────────┘ └──────────────┘
                                              │
                                              ▼
                                       ┌──────────────┐
                                       │   Phase 10   │
                                       │  the frontend│
                                       └──────────────┘
```

The backend is complete. Scans are triggered over HTTP, queued, processed by workers that can die and recover, persisted with tenant isolation, and streamed live to whoever is allowed to watch.

---

# Errata — found while implementing this phase

*The code above has been corrected. This section records what was wrong with it and why,
which is the part worth keeping.*

**`POST /scans` hands back a `job_id` that nothing can watch yet.** This is the one that
matters, and the WebSocket is what exposed it. `enqueue_scan` publishes to SQS; the
DynamoDB row is written by `create_job` inside `run_and_store`, which only runs once a
worker has claimed the message. So between the 202 and the worker picking it up, the job
does not exist. The endpoint in section 10 does exactly the right thing with that:

```text
job = get_job(job_id)          →  None
close(code=1008, "Not found")  →  handshake rejected with HTTP 403
```

Which is what you actually see if you follow section 14 in the order it is written —
start a scan, then run the watcher:

```text
websockets.exceptions.InvalidStatus: server rejected WebSocket connection: HTTP 403
```

It looks like the auth check misfiring. It is not. The same gap makes
`GET /api/v1/scans/jobs/{id}` return 404 for a job the API just told you was queued, so
this was a Phase 8 bug all along — polling clients simply retried through it and never
noticed. A WebSocket gets one connect attempt and no second chance.

The fix is that the API owns the queued row, since the API is what promised it exists:

```python
# app/api/scans.py - enqueue first, that is the durable part, then the row
message = enqueue_scan(principal.tenant_id, request.repo_id, request.target)

create_job(message.job_id, principal.tenant_id, message.repo_id, request.target)
```

That collides with Phase 7. `claim_job` uses the *absence* of the row as its idempotency
token — `ConditionExpression="attribute_not_exists(job_id)"` — so a pre-created row makes
every first delivery fail to claim. Widen the condition from existence to state:

```python
ConditionExpression="attribute_not_exists(job_id) OR #status = :queued",
ExpressionAttributeNames={"#status": "status"},
ExpressionAttributeValues={":queued": "queued"},
```

Claiming now means "I am the one that moved this from queued to running", which is what it
always meant in spirit. A redelivery landing on a `running` or `completed` job still loses
the race, so the at-least-once protection is intact.

Then drop `create_job` from `run_and_store` entirely — with the API creating the row,
calling it again *after* `claim_job` won would stomp `running` straight back to `queued`.
Both remaining callers own their row: the API at 202, and `app/scripts/scan_and_store.py`
right before it calls in.

**`verify_token` must not be called directly from the WebSocket handler.** It reaches
`_fetch_jwks`, which uses a **blocking** `httpx.Client`. Awaiting nothing on an event loop
that owns every other connection stalls all of them — and when `JWKS_URL` points back at
this same app, which is the dev default, a single-worker uvicorn deadlocks against itself.
This is the identical bug Phase 8 hit in `current_principal`, and `app/core/auth.py`
carries a comment about it. FastAPI's threadpool solves it for sync dependencies; a
WebSocket route has no dependency to lean on, so do it by hand:

```python
claims = await asyncio.to_thread(verify_token, token)
```

`get_job` is boto3 and blocking for the same reason. Same treatment, same call length.

**The first streamed event never gets its terminal check.** Section 10 sends `await first`
and only *then* enters the `async for`, where the `completed`/`failed` break lives. If the
first event to arrive after connect is the terminal one — which is exactly what happens
when you connect near the end of a scan — the socket never closes and the client hangs on
a bar sitting at 100%. Check `first.status` before entering the loop.

**`first.cancel()` on the early-return path skips the unsubscribe.** Cancelling the task
abandons the async generator mid-suspend, so `listen`'s `finally` — the `unsubscribe` the
section itself argues for — never runs. `bus.close()` drops the whole connection so nothing
leaks in practice, but the guarantee is not there. Hoist `stream` above the `try`, settle
`first` in the `finally`, then `await stream.aclose()`; the generator cannot be closed while
a task is still pending on `__anext__`.

**`ProgressBus.listen` should be typed `AsyncGenerator`, not `AsyncIterator`.** The consumer
needs `anext()` to return a real coroutine for `create_task`, and `aclose()` for the fix
above. Neither is on `AsyncIterator`, so mypy rejects the endpoint against the Protocol as
written. Declaring the narrower type is also what makes the Protocol worth having — annotate
the call sites `bus: ProgressBus = RedisProgressBus()` and it is type-checked rather than
decorative.

**`tests/test_progress.py` needs the JWKS server.** The WS tests take `tenant`, which pulls
in `tables`, but nothing starts the dev JWKS endpoint that `verify_token` fetches from.
`tests/test_api.py` gets it from a module-local autouse fixture; copy it, or every
authorized test fails on a 1008 close that looks like the tenant check misfiring.

**No new dependencies are needed.** `redis` is already a direct dependency from Phase 8 —
`app/core/ratelimit.py` uses the sync client — and it ships `redis.asyncio`. The `[hiredis]`
extra is a parsing speedup for a bus carrying four messages per scan; skip it. `websockets`
is already installed as part of `uvicorn[standard]`, so `uv add --dev websockets` only
declares what `app/scripts/watch.py` imports.

**`types-redis` has to go.** It is pinned four major versions behind the installed `redis`
and reports the async API as missing:

```text
app/progress/redis_bus.py:47: error: "PubSub" has no attribute "aclose"; maybe "close"?
```

`redis` 8.x ships `py.typed`, and stub packages take precedence over inline types, so the
stale stubs win and are wrong. Remove `types-redis` from the dev group and mypy passes on
the real signatures.

**A note on `ProgressEvent.create`.** The section is right that `utcnow()` is the bug, but
this repo already solved it: `app.storage.serialization.now_iso()` is
`datetime.now(UTC).isoformat()` and is what every other timestamp here uses. Reuse it
rather than adding a second way to spell the same thing.

**What the proof looks like when it works.** Two API processes on 8080 and 8081, a scan
started through the API, both watchers connected *before* the worker was running, then the
worker started:

```text
  0% |                    | Queued          ← snapshot, from DynamoDB
 10% |##                  | Fetching image data
 40% |########            | Running agents
 90% |##################  | Storing results
100% |####################| Scan complete
```

Identical on both ports. The worker published to one Redis channel and never knew how many
processes were listening, which is the entire point of the phase. The `0%` line is worth
noticing too — that is the snapshot arriving for a job that had not started yet, which is
only possible because the API wrote the queued row.

---

## Next: Phase 10 — The Frontend

Next.js, and the first UI decision matters more than the rest combined:

```text
        state that arrives           state that is fetched
       ┌──────────────────┐         ┌──────────────────┐
       │  WebSocket event │         │  GET /scans/{id} │
       │  progress, step  │         │  findings, score │
       └────────┬─────────┘         └────────┬─────────┘
                │                            │
                ▼                            ▼
          useScanProgress              useScanResult
                │                            │
                └────────────┬───────────────┘
                             ▼
                       the scan page
```

Live progress and final results are different data with different lifecycles, and merging them into one state object is the mistake that makes these pages hard to reason about.

```text
1. a reconnect loop with no backoff and no cap —
   the reference retries every 3 seconds forever,
   including after the job has finished

2. rendering degraded scans honestly: a score of
   82 at 75% confidence must not look identical
   to 82 at 100%

3. why the token goes in the query string, and
   how to keep it out of your logs
```

That second one is where Phase 4's `degraded` flag finally earns its place — a UI that hides it makes every earlier safeguard pointless.