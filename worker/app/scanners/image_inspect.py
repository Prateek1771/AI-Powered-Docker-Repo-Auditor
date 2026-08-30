import json

from app.config.scanning import SCANNER_MODE
from app.scanners.docker_history import (
    DockerHistoryError,
    _run,
    ensure_image_present,
)
from app.scanners.trivy import image_report


def inspect_from_report(report: dict) -> dict:
    """Shape a Trivy report's image config like `docker image inspect` output.

    Trivy's `Metadata.ImageConfig.config` is the OCI config block and already
    uses the capitalised keys the CLI emits (User, Env, ExposedPorts, Cmd,
    Entrypoint, Healthcheck), so processors/profile.py needs no branch of its
    own - it keeps reading `.Config`.
    """
    metadata = report.get("Metadata") or {}
    config = metadata.get("ImageConfig") or {}

    if not config:
        raise DockerHistoryError("Trivy report carries no image config")

    return {
        "Config": config.get("config") or {},
        "Architecture": config.get("architecture", ""),
        "Os": config.get("os", ""),
        "Id": metadata.get("ImageID", ""),
        "RepoTags": metadata.get("RepoTags") or [],
        "RepoDigests": metadata.get("RepoDigests") or [],
        "Size": metadata.get("Size", 0),
    }


async def run_image_inspect(target: str) -> dict:
    """Return an image's config in `docker image inspect` shape.

    Registry mode reads it out of the Trivy report instead of the daemon,
    so processors/profile.py keeps reading `.Config` either way.
    """
    if SCANNER_MODE == "registry":
        return inspect_from_report(await image_report(target))

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
