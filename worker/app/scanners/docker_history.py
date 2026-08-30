import asyncio
import json
import logging

from app.config.scanning import SCANNER_MODE
from app.scanners.trivy import image_report

logger = logging.getLogger(__name__)

HISTORY_TIMEOUT_SECONDS = 60


class DockerHistoryError(RuntimeError):
    def __init__(self, message: str, *, permanent: bool = False) -> None:
        super().__init__(message)
        self.permanent = permanent


async def _run(
    command: list[str],
    timeout: float = HISTORY_TIMEOUT_SECONDS,
) -> tuple[int, bytes, bytes]:
    """Run a docker CLI command, returning code, stdout and stderr.

    Never raises on a non-zero exit - callers decide what a failure means,
    and `ensure_image_present` treats one as 'not local yet'. The timeout is
    a parameter because app/images.py loads multi-gigabyte tars through this
    same runner and a minute is nowhere near enough for that.
    """
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
    except TimeoutError:
        process.kill()
        await process.wait()

        raise DockerHistoryError(f"Command timed out: {' '.join(command)}")

    assert process.returncode is not None

    return process.returncode, stdout, stderr


async def ensure_image_present(target: str) -> None:
    """Make sure an image is on the daemon, pulling it if it is not.

    Only used in socket mode. A pull that fails is permanent for this scan
    - a bad reference will not become good on a retry.
    """
    code, _, _ = await _run(["docker", "image", "inspect", target])

    if code == 0:
        return

    logger.info("Image not local, pulling: %s", target)

    code, _, stderr = await _run(["docker", "pull", target])

    if code != 0:
        raise DockerHistoryError(
            f"Could not pull {target}: {stderr.decode()[:300]}", permanent=True
        )


def history_from_report(report: dict) -> list[dict]:
    """Rebuild `docker history` output from a Trivy report.

    Trivy carries the full image config, which is enough to reconstruct the
    history exactly rather than estimate it. The config's `history` is every
    build instruction oldest-first, including the ones that produced no
    filesystem change; `rootfs.diff_ids` is the ordered list of layers that DID
    change something. Walking them together assigns each instruction its own
    layer, and `Metadata.Layers` gives that layer's size.

    Returns entries newest-first, which is the order the docker CLI prints and
    the order app/processors/layers.py reverses.
    """
    config = (report.get("Metadata") or {}).get("ImageConfig") or {}
    history = config.get("history") or []

    if not history:
        raise DockerHistoryError("Trivy report carries no image history")

    diff_ids = ((config.get("rootfs") or {}).get("diff_ids")) or []
    sizes = {
        layer.get("DiffID"): layer.get("Size", 0)
        for layer in ((report.get("Metadata") or {}).get("Layers") or [])
    }

    entries = []
    consumed = 0

    for step in history:
        empty = bool(step.get("empty_layer"))

        size = 0

        if not empty:
            if consumed < len(diff_ids):
                size = sizes.get(diff_ids[consumed], 0)

            consumed += 1

        entries.append(
            {
                "CreatedBy": step.get("created_by", ""),
                # layers.py parses this back out, so it has to be a string in
                # the shape the CLI emits.
                "Size": f"{size}B",
                "Comment": step.get("comment", ""),
                # Without this a sizeless-but-real layer would be indistinguishable
                # from an ENV line, and the bloat agent reasons about the difference.
                "EmptyLayer": empty,
            }
        )

    if consumed != len(diff_ids):
        logger.warning(
            "History/diff_id mismatch for image: %d non-empty steps, %d layers",
            consumed,
            len(diff_ids),
        )

    entries.reverse()

    return entries


async def run_docker_history(target: str) -> list[dict]:
    """Return an image's build history, newest layer first.

    Socket mode shells out to `docker history`; registry mode rebuilds the
    same shape from Trivy's report, so callers never learn which ran.
    """
    if SCANNER_MODE == "registry":
        return history_from_report(await image_report(target))

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
