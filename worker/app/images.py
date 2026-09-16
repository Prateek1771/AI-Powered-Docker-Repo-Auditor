import asyncio
import json
import logging
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

from app.config.scanning import SCANNER_MODE, TAR_SCHEME
from app.config.storage import BLOB_DIR, MAX_UPLOAD_BYTES
from app.scanners.docker_history import DockerHistoryError, _run
from app.storage.blobs import BlobKeyError, safe_segment

logger = logging.getLogger(__name__)

# Not a real URL scheme - a marker the API hands the client and the worker
# resolves back to an image reference. Kept in the `target` string so the queue
# message, the job row and the WebSocket all stay exactly as they were.
UPLOAD_SCHEME = "upload://"

LIST_TIMEOUT_SECONDS = 15

CHUNK_BYTES = 1024 * 1024


class UploadError(ValueError):
    """Raised when an upload is refused before anything is stored."""


def _segment(value: str) -> str:
    """Return a path segment, refusing anything that could escape the dir.

    Both halves of an upload path come from outside: the tenant id from a
    token claim, the upload id from a client-supplied target string. The
    check itself now lives in storage.blobs, so report keys and upload
    paths cannot drift apart - only one of the two had it before.
    """
    try:
        return safe_segment(value)
    except BlobKeyError as exc:
        raise UploadError(str(exc)) from exc


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
    than truncated, so a partial tar can never reach a scanner.
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

                # to_thread: a multi-gigabyte tar arrives as thousands of
                # blocking 1 MB writes, each one freezing the event loop that
                # is also serving every other request and every WebSocket
                # keepalive. See docs/audits/audit-01-backend.md P3-9.
                await asyncio.to_thread(handle.write, chunk)
    except BaseException:
        path.unlink(missing_ok=True)

        raise

    logger.info("Stored upload %s for %s (%d bytes)", upload_id, tenant_id, written)

    return f"{UPLOAD_SCHEME}{upload_id}"


async def resolve_target(tenant_id: str, target: str) -> str:
    """Turn a scan target into something the scanners can read.

    A registry reference passes straight through; an upload becomes a
    `tarfile://` path the scanners hand to `trivy --input`.

    It is NOT loaded into the daemon. `docker load` applies whatever
    RepoTags the archive's own manifest declares, so an upload tagged
    `python:3.12-slim` replaced the daemon's real one and every later
    socket-mode scan of that tag - across tenants - analysed the
    attacker's image instead. Trivy reads the tar directly and can mutate
    nothing. See docs/audits/audit-01-backend.md P1-4.

    A missing upload is permanent: it will not reappear on a retry.
    """
    if not target.startswith(UPLOAD_SCHEME):
        return target

    path = _upload_path(tenant_id, target[len(UPLOAD_SCHEME) :])

    if not path.exists():
        raise DockerHistoryError(f"Upload {target} is gone", permanent=True)

    logger.info("Scanning uploaded image %s from disk", path.name)

    return f"{TAR_SCHEME}{path}"


def discard_upload(target: str) -> None:
    """Delete a resolved upload once its scan is done.

    One scan per upload: keeping them means a disk that only grows, and a
    re-scan is a fresh upload anyway. Called from the orchestrator's
    `finally` rather than from resolve_target, because the file now has to
    survive until the scanners have actually read it.
    """
    if not target.startswith(TAR_SCHEME):
        return

    Path(target[len(TAR_SCHEME) :]).unlink(missing_ok=True)


__all__ = [
    "UPLOAD_SCHEME",
    "UploadError",
    "discard_upload",
    "list_local_images",
    "resolve_target",
    "save_upload",
]
