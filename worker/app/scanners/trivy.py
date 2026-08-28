import asyncio
import json
import logging

from app.config.scanning import (
    TRIVY_CACHE_VOLUME,
    TRIVY_IMAGE,
    TRIVY_SCANNERS,
    TRIVY_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)


class TrivyScanError(RuntimeError):
    pass


def build_command(target: str) -> list[str]:
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


async def run_trivy_scan(target: str) -> dict:
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
