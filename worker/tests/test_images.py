from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.config.scanning import TAR_SCHEME
from app.images import UploadError, discard_upload, resolve_target, save_upload
from app.scanners.docker_history import DockerHistoryError
from app.scanners.trivy import is_permanent_failure

TENANT = "tenant-images"


async def _chunks(*parts: bytes) -> AsyncIterator[bytes]:
    for part in parts:
        yield part


@pytest.fixture(autouse=True)
def blob_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point uploads at a temp dir so tests never touch the real blob volume."""
    monkeypatch.setattr("app.images.BLOB_DIR", str(tmp_path))

    return tmp_path


async def test_upload_is_stored_under_its_tenant(blob_dir: Path) -> None:
    target = await save_upload(TENANT, "alpine.tar", _chunks(b"tar-bytes"))

    upload_id = target.removeprefix("upload://")

    assert (blob_dir / "uploads" / TENANT / f"{upload_id}.tar").read_bytes() == (
        b"tar-bytes"
    )


async def test_a_non_tar_is_refused() -> None:
    with pytest.raises(UploadError):
        await save_upload(TENANT, "image.zip", _chunks(b"anything"))


async def test_an_oversize_upload_leaves_no_partial_file(
    blob_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A truncated tar that survived on disk would reach `docker load` and fail
    # there instead - much later, and as a scan failure rather than a 400.
    monkeypatch.setattr("app.images.MAX_UPLOAD_BYTES", 4)

    with pytest.raises(UploadError):
        await save_upload(TENANT, "big.tar", _chunks(b"12", b"34", b"56"))

    assert list((blob_dir / "uploads" / TENANT).glob("*.tar")) == []


@pytest.mark.parametrize("bad", ["../escape", "a/b", "", "."])
async def test_a_traversing_tenant_id_is_refused(bad: str) -> None:
    with pytest.raises(UploadError):
        await save_upload(bad, "alpine.tar", _chunks(b"x"))


async def test_a_registry_reference_passes_straight_through() -> None:
    assert await resolve_target(TENANT, "alpine:3.20") == "alpine:3.20"


async def test_another_tenants_upload_id_does_not_resolve(
    blob_dir: Path,
) -> None:
    # The tenant is a directory, not a field to compare - so an id guessed from
    # someone else lands on a path that was never written.
    target = await save_upload(TENANT, "alpine.tar", _chunks(b"tar-bytes"))

    with pytest.raises(DockerHistoryError) as exc_info:
        await resolve_target(f"{TENANT}-attacker", target)

    assert exc_info.value.permanent is True


async def test_a_missing_upload_is_permanent() -> None:
    # Nothing about redelivery brings a deleted tar back, so this must not
    # cost the queue three attempts and its message group.
    with pytest.raises(DockerHistoryError) as exc_info:
        await resolve_target(TENANT, "upload://deadbeef")

    assert exc_info.value.permanent is True


async def test_an_upload_resolves_to_a_path_and_is_never_loaded() -> None:
    """The archive must not reach `docker load`.

    `docker load` applies whatever RepoTags the archive's own manifest
    declares, so an upload tagged python:3.12-slim replaced the daemon's
    real one and poisoned every later socket-mode scan of that tag, across
    tenants. Trivy reads the tar with --input instead and can mutate
    nothing. See docs/audits/audit-01-backend.md P1-4.

    A malformed archive is therefore no longer rejected here - Trivy
    rejects it at scan time, and is_permanent_failure classifies it.
    """
    target = await save_upload(TENANT, "junk.tar", _chunks(b"not a tar at all"))

    resolved = await resolve_target(TENANT, target)

    assert resolved.startswith(TAR_SCHEME)
    assert Path(resolved[len(TAR_SCHEME) :]).exists()


async def test_a_resolved_upload_is_deleted_after_its_scan() -> None:
    target = await save_upload(TENANT, "x.tar", _chunks(b"anything"))

    resolved = await resolve_target(TENANT, target)
    path = Path(resolved[len(TAR_SCHEME) :])

    assert path.exists()

    discard_upload(resolved)

    assert not path.exists()


def test_discarding_a_registry_reference_is_a_no_op() -> None:
    discard_upload("alpine:3.20")


@pytest.mark.parametrize(
    "stderr",
    [
        "FATAL unable to open: no such file or directory",
        "manifest unknown",
        "UNAUTHORIZED: authentication required",
        "invalid reference format",
    ],
)
def test_a_bad_target_is_permanent(stderr: str) -> None:
    assert is_permanent_failure(1, stderr) is True


@pytest.mark.parametrize(
    "stderr",
    [
        "TOOMANYREQUESTS: retry-after",
        "failed to download vulnerability DB",
        "context deadline exceeded",
        "500 Internal Server Error",
        "",
    ],
)
def test_a_transient_failure_is_retryable(stderr: str) -> None:
    """The old code marked every non-zero exit permanent, which deleted the
    queue message. A GHCR rate-limit on the vuln DB then lost the scan
    outright - and on Fargate that cache is ephemeral, so it was the
    expected failure under load. See docs/audits/audit-01-backend.md P3-1."""
    assert is_permanent_failure(1, stderr) is False


def test_a_usage_error_is_permanent() -> None:
    assert is_permanent_failure(2, "unknown flag: --nope") is True


# The route-level guard. Untested until now, which is how the deployed API
# came to run with SCANNER_MODE unset - defaulting to "socket" - so these
# routes never 404'd on Fargate as their docstring claims. They failed at a
# lower layer instead, as a 500 from a permission error on a root-owned /app.
# See docs/audits/audit-01-backend.md P4-4.


def test_the_upload_feature_is_absent_without_a_daemon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.api.images as images_api

    monkeypatch.setattr(images_api, "SCANNER_MODE", "registry")

    with pytest.raises(HTTPException) as caught:
        images_api._socket_mode_only()

    # 404, not 503: on a registry deployment the feature is not degraded,
    # it does not exist.
    assert caught.value.status_code == 404


def test_the_upload_feature_is_present_with_a_daemon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.api.images as images_api

    monkeypatch.setattr(images_api, "SCANNER_MODE", "socket")

    assert images_api._socket_mode_only() is None
