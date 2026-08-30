import logging
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from app.config.scanning import SCANNER_MODE
from app.core.auth import Principal, current_principal
from app.core.ratelimit import scan_rate_limit
from app.images import CHUNK_BYTES, UploadError, list_local_images, save_upload

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/images", tags=["images"])


def _socket_mode_only() -> None:
    """404 the whole feature where there is no Docker daemon to talk to.

    Registry deployments (Fargate) have no socket, so listing local images
    and loading a tar are not degraded there - they are absent.
    """
    if SCANNER_MODE != "socket":
        raise HTTPException(status_code=404, detail="No local Docker daemon")


@router.get("", dependencies=[Depends(_socket_mode_only)])
async def local_images(
    principal: Principal = Depends(current_principal),
) -> list[dict]:
    """List the images on the daemon this API can reach.

    ponytail: the daemon's images are not tenant-scoped, so every caller
    sees the same list. That is acceptable only because the route exists
    solely in socket mode - one developer, one laptop, one daemon.
    """
    try:
        return await list_local_images()
    except Exception as exc:  # noqa: BLE001 - an unreachable daemon is not a 500
        logger.warning("Could not list local images: %s", exc)

        return []


async def _chunks(upload: UploadFile) -> AsyncIterator[bytes]:
    """Yield an upload's body a chunk at a time."""
    while chunk := await upload.read(CHUNK_BYTES):
        yield chunk


@router.post("/upload", dependencies=[Depends(_socket_mode_only)])
async def upload_image(
    file: UploadFile = File(...),
    principal: Principal = Depends(scan_rate_limit),
) -> dict:
    """Accept a `docker save` tar and return the target that names it.

    The tar is not loaded here: the API has no business running a
    multi-minute docker command inside a request. It is stored under the
    caller's tenant and resolved by the worker when the scan runs.
    """
    filename = file.filename or ""

    try:
        target = await save_upload(principal.tenant_id, filename, _chunks(file))
    except UploadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Only a grouping key for history - the real reference is not known until
    # the worker loads the tar.
    repo_id = filename.rsplit("/", 1)[-1].removesuffix(".tar") or "upload"

    return {"target": target, "repo_id": repo_id}
