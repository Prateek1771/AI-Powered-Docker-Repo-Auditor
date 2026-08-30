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
    """Send a ping often enough to keep an idle socket open."""
    while True:
        await asyncio.sleep(PING_INTERVAL_SECONDS)

        await websocket.send_json({"type": "ping"})


async def _finish(task: asyncio.Task) -> None:
    """Cancel a task and wait for it, ignoring how it ended."""
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
    """Stream one job's progress to a subscriber until it finishes.

    Subscribes before reading the snapshot, so an event published in
    between is duplicated rather than lost - a client can tolerate seeing
    a step twice and cannot tolerate never seeing the last one.
    """
    try:
        claims = await asyncio.to_thread(verify_token, token)
    except Exception:  # noqa: BLE001 - any auth failure is one close frame
        # ASGI never completes the handshake for a close() before accept(),
        # so the browser sees code 1006 (abnormal) instead of 1008, and
        # useScanProgress.ts's NO_RETRY_CODES check for 1008 never matches -
        # it retries a rejection that will never succeed. Accepting first is
        # what makes the real close code reach the client.
        await websocket.accept()
        await websocket.close(code=1008, reason="Unauthorized")

        return

    tenant_id = claims["sub"]

    job = await asyncio.to_thread(get_job, job_id)

    if job is None or job.tenant_id != tenant_id:
        await websocket.accept()
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
