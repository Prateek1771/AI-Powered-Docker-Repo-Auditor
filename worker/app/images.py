import json
import logging
import re
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

from app.config.scanning import SCANNER_MODE
from app.config.storage import BLOB_DIR, MAX_UPLOAD_BYTES
from app.scanners.docker_history import DockerHistoryError, _run

logger = logging.getLogger(__name__)

# Not a real URL scheme - a marker the API hands the client and the worker
# resolves back to an image reference. Kept in the `target` string so the queue
# message, the job row and the WebSocket all stay exactly as they were.
UPLOAD_SCHEME = "upload://"

LIST_TIMEOUT_SECONDS = 15

# A `docker save` tar of a real image is hundreds of megabytes and loading it
# is disk-bound, so this is much longer than any other docker call here.
LOAD_TIMEOUT_SECONDS = 600

CHUNK_BYTES = 1024 * 1024

# Both halves of the upload path come from outside: the tenant id from a token
# claim, the upload id from a client-supplied target string. Anything with a
# separator or a dot-segment in it must never reach the filesystem.
_SAFE_SEGMENT = re.compile(r"\A[A-Za-z0-9._-]{1,128}\Z")

_LOADED = re.compile(r"Loaded image(?: ID)?:\s*(\S+)")


class UploadError(ValueError):
    """Raised when an upload is refused before anything is stored."""


def _segment(value: str) -> str:
    """Return a path segment, refusing anything that could escape the dir."""
    if not _SAFE_SEGMENT.fullmatch(value) or value in {".", ".."}:
        raise UploadError(f"Unusable path segment: {value[:64]!r}")

    return value


def _upload_path(tenant_id: str, upload_id: str) -> Path:
    """Return where one tenant's upload lives.

    The tenant is a directory rather than a field to compare, so an id
    guessed from another tenant simply resolves to a path that does not
    exist - there is no ownership check to forget to write.
    """
    return (
        Path(BLOB_DIR) / "uploads" / _segment(tenant_id) / f"{_segment(upload_id)}.tar"
    )


async def list_local_images() -> list[dict]:
    """List the images on the Docker daemon, newest first.

    Only meaningful in socket mode - registry deployments have no daemon
    to ask, so callers get an empty list and hide the feature.
    """
    if SCANNER_MODE != "socket":
        return []

    code, stdout, stderr = await _run(
        ["docker", "image", "ls", "--format", "{{json .}}"],
        timeout=LIST_TIMEOUT_SECONDS,
    )

    if code != 0:
        raise DockerHistoryError(
            f"docker image ls exited {code}: {stderr.decode()[:300]}"
        )

    images = []

    for line in stdout.decode().splitlines():
        if not line.strip():
            continue

        entry = json.loads(line)

        # Dangling layers from earlier builds. There is no reference to scan
        # by, and the id alone is not something a person recognises.
        if entry.get("Repository") in (None, "<none>") or entry.get("Tag") == "<none>":
            continue

        images.append(
            {
                "reference": f"{entry['Repository']}:{entry['Tag']}",
                "image_id": entry.get("ID", ""),
                "size": entry.get("Size", ""),
                "created": entry.get("CreatedSince", ""),
            }
        )

    return images


async def save_upload(
    tenant_id: str,
    filename: str,
    chunks: AsyncIterator[bytes],
) -> str:
    """Store an uploaded image tar and return the target that names it.

    Written straight to disk in chunks rather than read into memory,
    because a `docker save` tar is routinely larger than the container's
    whole memory limit. A file that runs past the cap is deleted rather
    than truncated, so a partial tar can never reach `docker load`.
    """
    if not filename.lower().endswith(".tar"):
        raise UploadError("Expected a .tar produced by `docker save`")

    upload_id = uuid.uuid4().hex

    path = _upload_path(tenant_id, upload_id)

    path.parent.mkdir(parents=True, exist_ok=True)

    written = 0

    try:
        with path.open("wb") as handle:
            async for chunk in chunks:
                written += len(chunk)

                if written > MAX_UPLOAD_BYTES:
                    raise UploadError(
                        f"Upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)}MB"
                    )

                handle.write(chunk)
    except BaseException:
        path.unlink(missing_ok=True)

        raise

    logger.info("Stored upload %s for %s (%d bytes)", upload_id, tenant_id, written)

    return f"{UPLOAD_SCHEME}{upload_id}"


async def resolve_target(tenant_id: str, target: str) -> str:
    """Turn a scan target into an image reference the scanners can use.

    A registry reference passes straight through; an upload is loaded into
    the daemon first and replaced by whatever tag it carried. Every failure
    here is permanent - a tar that will not load will not load on a retry
    either - so it reuses the flag app/errors.py keys off.
    """
    if not target.startswith(UPLOAD_SCHEME):
        return target

    path = _upload_path(tenant_id, target[len(UPLOAD_SCHEME) :])

    if not path.exists():
        raise DockerHistoryError(f"Upload {target} is gone", permanent=True)

    logger.info("Loading uploaded image %s", path.name)

    try:
        code, stdout, stderr = await _run(
            ["docker", "load", "-i", str(path)],
            timeout=LOAD_TIMEOUT_SECONDS,
        )
    finally:
        # One scan per upload. Keeping it would mean a disk that only grows,
        # and a re-scan is a fresh upload anyway.
        path.unlink(missing_ok=True)

    if code != 0:
        raise DockerHistoryError(
            f"docker load failed: {stderr.decode()[:300]}", permanent=True
        )

    match = _LOADED.search(stdout.decode())

    if match is None:
        raise DockerHistoryError(
            f"docker load said nothing loadable: {stdout.decode()[:200]}",
            permanent=True,
        )

    # An untagged save yields a bare sha256 id, which Trivy and docker history
    # both accept as a reference - so there is nothing to special-case.
    return match.group(1)


__all__ = [
    "UPLOAD_SCHEME",
    "UploadError",
    "list_local_images",
    "resolve_target",
    "save_upload",
]
