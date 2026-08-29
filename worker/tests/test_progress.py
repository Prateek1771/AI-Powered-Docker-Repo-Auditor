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
