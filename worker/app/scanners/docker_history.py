import asyncio
import json
import logging

logger = logging.getLogger(__name__)

HISTORY_TIMEOUT_SECONDS = 60


class DockerHistoryError(RuntimeError):
    pass


async def _run(command: list[str]) -> tuple[int, bytes, bytes]:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=HISTORY_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        process.kill()
        await process.wait()

        raise DockerHistoryError(f"Command timed out: {' '.join(command)}")

    assert process.returncode is not None

    return process.returncode, stdout, stderr


async def ensure_image_present(target: str) -> None:
    code, _, _ = await _run(["docker", "image", "inspect", target])

    if code == 0:
        return

    logger.info("Image not local, pulling: %s", target)

    code, _, stderr = await _run(["docker", "pull", target])

    if code != 0:
        raise DockerHistoryError(f"Could not pull {target}: {stderr.decode()[:300]}")


async def run_docker_history(target: str) -> list[dict]:
    await ensure_image_present(target)

    code, stdout, stderr = await _run(
        [
            "docker",
            "history",
            "--no-trunc",
            "--format",
            "{{json .}}",
            target,
        ]
    )

    if code != 0:
        raise DockerHistoryError(
            f"docker history exited {code}: {stderr.decode()[:300]}"
        )

    entries = []

    for line in stdout.decode().splitlines():
        if line.strip():
            entries.append(json.loads(line))

    return entries
