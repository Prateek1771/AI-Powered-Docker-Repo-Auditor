import json

from app.scanners.docker_history import (
    DockerHistoryError,
    _run,
    ensure_image_present,
)


async def run_image_inspect(target: str) -> dict:
    await ensure_image_present(target)

    code, stdout, stderr = await _run(["docker", "image", "inspect", target])

    if code != 0:
        raise DockerHistoryError(
            f"docker image inspect exited {code}: {stderr.decode()[:300]}"
        )

    payload = json.loads(stdout)

    if not payload:
        raise DockerHistoryError(f"Empty inspect output for {target}")

    return payload[0]
