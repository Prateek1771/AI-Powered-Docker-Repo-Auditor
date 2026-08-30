from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from app.images import UploadError, resolve_target, save_upload
from app.scanners.docker_history import DockerHistoryError

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


@pytest.mark.integration
async def test_a_tar_docker_cannot_load_is_permanent() -> None:
    target = await save_upload(TENANT, "junk.tar", _chunks(b"not a tar at all"))

    with pytest.raises(DockerHistoryError) as exc_info:
        await resolve_target(TENANT, target)

    assert exc_info.value.permanent is True
