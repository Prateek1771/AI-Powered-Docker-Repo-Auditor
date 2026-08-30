import asyncio
import json
import logging

from app.config.scanning import (
    SCANNER_MODE,
    TRIVY_CACHE_VOLUME,
    TRIVY_IMAGE,
    TRIVY_SCANNERS,
    TRIVY_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)


class TrivyScanError(RuntimeError):
    pass


def build_command(target: str) -> list[str]:
    """Build the Trivy invocation for whichever mode this deployment runs.

    Registry mode calls the binary directly and needs no daemon; socket
    mode runs Trivy as a sibling container through the host's Docker.
    """
    if SCANNER_MODE == "registry":
        # No daemon, no socket. Trivy pulls the image itself with whatever
        # credentials the environment gives it - the task role, on Fargate.
        return [
            "trivy",
            "image",
            "--format",
            "json",
            "--quiet",
            "--scanners",
            TRIVY_SCANNERS,
            "--timeout",
            "10m",
            target,
        ]

    return [
        "docker",
        "run",
        "--rm",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        f"{TRIVY_CACHE_VOLUME}:/root/.cache/trivy",
        TRIVY_IMAGE,
        "image",
        "--format",
        "json",
        "--quiet",
        "--scanners",
        TRIVY_SCANNERS,
        "--timeout",
        "10m",
        target,
    ]


async def _execute(target: str) -> dict:
    """Run Trivy once and return its parsed JSON report.

    A non-zero exit, a timeout and empty output are three different
    failures and each raises with the detail needed to tell them apart.
    """
    command = build_command(target)

    logger.info(
        "Starting Trivy scan: %s",
        target,
    )

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=TRIVY_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        process.kill()
        await process.wait()

        raise TrivyScanError(
            f"Trivy scan timed out after {TRIVY_TIMEOUT_SECONDS}s: {target}"
        )

    if process.returncode != 0:
        raise TrivyScanError(
            f"Trivy exited {process.returncode}: {stderr.decode()[:500]}"
        )

    if not stdout.strip():
        raise TrivyScanError(f"Trivy returned empty output for {target}")

    return json.loads(stdout)


# In registry mode the layer history and the image config both come out of the
# Trivy report, so the three scanners the orchestrator gathers would otherwise
# run Trivy three times over.
#
# This shares the run between callers that are ALREADY WAITING, and keeps
# nothing afterwards. A result cache would be smaller code and would hand a
# rescan of the same tag its pre-rebuild report - the one answer this tool must
# never give.
_inflight: dict[str, asyncio.Task[dict]] = {}


async def image_report(target: str) -> dict:
    """Return the Trivy report for an image, sharing concurrent runs.

    In registry mode all three scanners want this same report and the
    orchestrator asks for them at once, so without sharing Trivy would run
    three times over one image.
    """
    task = _inflight.get(target)

    if task is None:
        task = asyncio.create_task(_execute(target))

        _inflight[target] = task

        task.add_done_callback(lambda _: _inflight.pop(target, None))

    return await asyncio.shield(task)


async def run_trivy_scan(target: str) -> dict:
    """Scan an image and return Trivy's raw JSON report."""
    return await image_report(target)
