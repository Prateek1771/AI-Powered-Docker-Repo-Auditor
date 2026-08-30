import asyncio
import logging
import signal

from app.queue.consumer import consume_once
from app.queue.handler import handle_scan
from app.queue.producer import get_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

logger = logging.getLogger(__name__)

_shutdown = asyncio.Event()


def _install_handlers() -> None:
    """Ask the event loop to set the shutdown flag on SIGTERM or SIGINT.

    Windows has no add_signal_handler, so it falls back to the plain one.
    This process deploys to Linux; the fallback is for local runs.
    """
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _shutdown.set)
        except NotImplementedError:
            # Windows has no add_signal_handler; the plain handler is the
            # only option there, and this process deploys to Linux.
            signal.signal(sig, lambda *_: _shutdown.set())


async def poll_forever() -> None:
    """Poll the queue until asked to stop, backing off after a failure.

    The flag is only checked between messages, which is why the ECS task
    definition allows 120 seconds to stop rather than the default 30.
    """
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
    """Install signal handlers and run the poll loop."""
    _install_handlers()

    await poll_forever()


if __name__ == "__main__":
    asyncio.run(main())
