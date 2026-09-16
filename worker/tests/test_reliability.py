"""Phase 3: the correctness fixes, each tested at the point it went wrong.

Every test here fails against the code as it was.
"""

import asyncio
import json

import pytest

from app.processors.vulnerabilities import SEVERITY_ORDER, extract_vulnerabilities
from app.queue.handler import handle_scan
from app.queue.producer import ScanMessage
from app.storage.blobs import BlobKeyError, _checked, safe_segment
from app.storage.jobs import JobRecord, lease_is_live
from app.storage.serialization import now_epoch

# --------------------------------------------------------------------------
# P3-10  Path traversal reachable in blob storage
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "reports/../../etc/passwd",
        "reports/../other-tenant/job",
        "policy/..",
        "reports//job",
        "reports/ten ant/job",
        "/reports/tenant/job",
        "",
    ],
)
def test_a_key_that_could_escape_is_refused(key: str) -> None:
    """With DEV_AUTH=1 the tenant id comes straight from a query param."""
    with pytest.raises(BlobKeyError):
        _checked(key)


def test_ordinary_keys_pass() -> None:
    assert _checked("reports/tenant-a/job-1") == "reports/tenant-a/job-1"
    assert _checked("policy/tenant-a") == "policy/tenant-a"
    assert safe_segment("tenant-a") == "tenant-a"


def test_upload_paths_and_report_keys_share_one_guard() -> None:
    """They drifted before: only one of the two had the check."""
    from app.images import UploadError, _segment

    with pytest.raises(UploadError):
        _segment("../escape")


# --------------------------------------------------------------------------
# P3-10  Non-atomic blob write
# --------------------------------------------------------------------------


def test_a_failed_write_leaves_no_truncated_json(tmp_path, monkeypatch) -> None:
    """Truncated JSON surfaced as a 500, where a 404 was intended."""
    from app.storage import blobs

    monkeypatch.setattr(blobs, "BLOB_DIR", str(tmp_path))
    monkeypatch.setattr(blobs, "REPORTS_BUCKET", "")

    blobs.put_blob("reports/t/j", {"findings": ["first"]})

    def explode(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(blobs.os, "replace", explode)

    with pytest.raises(OSError):
        blobs.put_blob("reports/t/j", {"findings": ["second"]})

    # The old report, whole - not a half-written new one.
    assert blobs.get_blob("reports/t/j") == {"findings": ["first"]}

    # And no temp file left lying next to it.
    assert [p.name for p in tmp_path.rglob("*.tmp")] == []


def test_blob_round_trip_is_unchanged(tmp_path, monkeypatch) -> None:
    from app.storage import blobs

    monkeypatch.setattr(blobs, "BLOB_DIR", str(tmp_path))
    monkeypatch.setattr(blobs, "REPORTS_BUCKET", "")

    blobs.put_blob("reports/t/j", {"a": 1})

    assert blobs.get_blob("reports/t/j") == {"a": 1}
    assert blobs.get_blob("reports/t/missing") is None


# --------------------------------------------------------------------------
# P3-2  The handler can now tell a live worker from a dead one
# --------------------------------------------------------------------------


def _job(status: str, lease_offset: int) -> JobRecord:
    return JobRecord(
        job_id="job-1",
        tenant_id="t",
        repo_id="r",
        target="alpine:3.20",
        status=status,  # type: ignore[arg-type]
        started_at="now",
        updated_at="now",
        expires_at=0,
        lease_expires_at=(0 if lease_offset == 0 else now_epoch() + lease_offset),
    )


def test_lease_is_live_only_while_running_and_unexpired() -> None:
    assert lease_is_live(_job("running", 300))
    assert not lease_is_live(_job("running", -1))
    assert not lease_is_live(_job("running", 0))
    assert not lease_is_live(_job("completed", 300))


def _message() -> ScanMessage:
    return ScanMessage(
        job_id="job-1",
        tenant_id="t",
        repo_id="r",
        target="alpine:3.20",
        enqueued_at="now",
    )


@pytest.mark.parametrize(
    ("existing", "should_run"),
    [
        # A live holder: running it again is the duplicate scan this exists
        # to prevent - double model spend and racing store_result puts.
        (_job("running", 300), False),
        # Already done: a duplicate delivery.
        (_job("completed", 300), False),
        # A lapsed lease: the worker died. Reprocessing IS the recovery.
        (_job("running", -1), True),
        (_job("failed", 0), True),
    ],
)
def test_handler_runs_only_when_nobody_holds_the_job(
    monkeypatch, existing: JobRecord, should_run: bool
) -> None:
    ran: list[str] = []

    async def fake_run(job_id, tenant_id, repo_id, target):
        ran.append(job_id)

    monkeypatch.setattr("app.queue.handler.claim_job", lambda *a: False)
    monkeypatch.setattr("app.queue.handler.get_job", lambda _id: existing)
    monkeypatch.setattr("app.queue.handler.run_and_store", fake_run)

    asyncio.run(handle_scan(_message(), attempt=2))

    assert bool(ran) is should_run


def test_a_won_claim_always_runs(monkeypatch) -> None:
    ran: list[str] = []

    async def fake_run(job_id, tenant_id, repo_id, target):
        ran.append(job_id)

    monkeypatch.setattr("app.queue.handler.claim_job", lambda *a: True)
    monkeypatch.setattr("app.queue.handler.run_and_store", fake_run)

    asyncio.run(handle_scan(_message(), attempt=1))

    assert ran == ["job-1"]


# --------------------------------------------------------------------------
# P3-10  UNKNOWN is not informational
# --------------------------------------------------------------------------


def test_unknown_severity_outranks_informational() -> None:
    """Unscored is not harmless, and was first to be dropped by the cap."""
    found = extract_vulnerabilities(
        {
            "Results": [
                {
                    "Target": "debian",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "a",
                            "InstalledVersion": "1",
                            "Severity": "UNKNOWN",
                        },
                        {
                            "VulnerabilityID": "CVE-2",
                            "PkgName": "b",
                            "InstalledVersion": "1",
                            "Severity": "NEGLIGIBLE",
                        },
                    ],
                }
            ]
        }
    )

    by_id = {v.id: v.severity for v in found}

    assert by_id["CVE-1"] == "low"
    assert by_id["CVE-2"] == "informational"

    assert SEVERITY_ORDER["low"] < SEVERITY_ORDER["informational"]


# --------------------------------------------------------------------------
# P3-9  Orphaned scanner coroutines
# --------------------------------------------------------------------------


def test_a_failing_scanner_does_not_orphan_the_other_two(monkeypatch) -> None:
    """Default gather returns on the first raise and abandons the rest."""
    import app.orchestrator as orch

    finished: list[str] = []

    async def slow(_target):
        try:
            await asyncio.sleep(0.05)
        finally:
            finished.append("slow")

        return {}

    async def fails(_target):
        raise RuntimeError("trivy is not installed")

    monkeypatch.setattr(orch, "run_trivy_scan", fails)
    monkeypatch.setattr(orch, "run_docker_history", slow)
    monkeypatch.setattr(orch, "run_image_inspect", slow)

    async def go():
        with pytest.raises(RuntimeError):
            await orch._fetch_raw("alpine:3.20")

    asyncio.run(go())

    # Both siblings were awaited to completion rather than left running
    # unattended with a subprocess each.
    assert finished == ["slow", "slow"]


# --------------------------------------------------------------------------
# P3-10  Poison message does not abort the poll cycle
# --------------------------------------------------------------------------


def test_an_unparseable_body_is_deleted_not_retried(monkeypatch) -> None:
    from app.queue import consumer

    deleted: list[str] = []

    class FakeSQS:
        def receive_message(self, **_kwargs):
            return {
                "Messages": [
                    {"Body": "not json at all", "ReceiptHandle": "rh-1"},
                    {
                        "Body": json.dumps(
                            {
                                "job_id": "job-2",
                                "tenant_id": "t",
                                "repo_id": "r",
                                "target": "alpine:3.20",
                                "enqueued_at": "now",
                            }
                        ),
                        "ReceiptHandle": "rh-2",
                    },
                ]
            }

        def delete_message(self, **kwargs):
            deleted.append(kwargs["ReceiptHandle"])

        def change_message_visibility(self, **_kwargs):
            pass

    handled: list[str] = []

    async def handler(message, attempt):
        handled.append(message.job_id)

    count = asyncio.run(consumer.consume_once(FakeSQS(), handler))

    # The poison message did not take the good one down with it.
    assert count == 2
    assert handled == ["job-2"]
    assert deleted == ["rh-1", "rh-2"]
