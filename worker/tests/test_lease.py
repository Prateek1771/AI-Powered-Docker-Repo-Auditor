"""The job lease: what stops two workers scanning one image.

Before this, a row in state `running` meant either "a worker is on it" or
"a worker died forty minutes ago" and nothing could tell them apart, so
redelivery reprocessed both. See docs/audits/audit-01-backend.md P3-2.
"""

import uuid

import pytest

from app.config.queue import HEARTBEAT_INTERVAL_SECONDS, JOB_LEASE_SECONDS
from app.storage.jobs import (
    claim_job,
    create_job,
    get_job,
    lease_is_live,
    renew_lease,
    update_progress,
)
from app.storage.serialization import now_epoch

pytestmark = pytest.mark.integration


def _claim(tenant: str) -> str:
    job_id = str(uuid.uuid4())

    create_job(job_id, tenant, "repo-lease", "alpine:3.20")

    assert claim_job(job_id, tenant, "repo-lease", "alpine:3.20")

    return job_id


def test_lease_outlives_the_heartbeat_interval() -> None:
    """A single slow renewal must not hand a live scan to a second worker."""
    assert JOB_LEASE_SECONDS > HEARTBEAT_INTERVAL_SECONDS


def test_claiming_sets_a_live_lease(tenant: str) -> None:
    job = get_job(_claim(tenant))

    assert job is not None
    assert job.status == "running"
    assert job.lease_expires_at > now_epoch()
    assert lease_is_live(job)


def test_a_second_worker_loses_against_a_live_lease(tenant: str) -> None:
    """The whole point: one image, one scan."""
    job_id = _claim(tenant)

    assert claim_job(job_id, tenant, "repo-lease", "alpine:3.20") is False


def test_a_second_worker_takes_over_a_lapsed_lease(tenant: str) -> None:
    """A worker that died must not hold the job until the 30-day TTL."""
    job_id = _claim(tenant)

    _expire_lease(job_id)

    assert claim_job(job_id, tenant, "repo-lease", "alpine:3.20") is True


def test_a_row_with_no_lease_field_is_claimable(tenant: str) -> None:
    """Rows written before the lease existed read as expired, not as held."""
    job_id = str(uuid.uuid4())

    create_job(job_id, tenant, "repo-lease", "alpine:3.20")

    update_progress(job_id, "running", 40, "Running agents")

    job = get_job(job_id)

    assert job is not None
    assert job.lease_expires_at == 0
    assert not lease_is_live(job)

    assert claim_job(job_id, tenant, "repo-lease", "alpine:3.20") is True


def test_renew_pushes_the_lease_out(tenant: str) -> None:
    job_id = _claim(tenant)

    _expire_lease(job_id)

    assert renew_lease(job_id) is True

    job = get_job(job_id)

    assert job is not None
    assert job.lease_expires_at > now_epoch()

    # And the takeover window is closed again.
    assert claim_job(job_id, tenant, "repo-lease", "alpine:3.20") is False


def test_renew_reports_a_lost_claim(tenant: str) -> None:
    """A finished job is not `running`, so its heartbeat learns to stop."""
    job_id = _claim(tenant)

    update_progress(job_id, "completed", 100, "Scan complete")

    assert renew_lease(job_id) is False


def test_a_completed_job_is_never_reclaimed(tenant: str) -> None:
    job_id = _claim(tenant)

    update_progress(job_id, "completed", 100, "Scan complete")

    assert claim_job(job_id, tenant, "repo-lease", "alpine:3.20") is False


def test_the_api_row_never_overwrites_a_worker_claim(tenant: str) -> None:
    """The API enqueues before it writes the row, so the worker often wins.

    An unconditional put here wiped the claim and the lease, which made a
    live scan advertise itself as unclaimed. Caught by a live run, not by
    the suite - see docs/audits/audit-01-backend.md P3-2.
    """
    job_id = _claim(tenant)

    # The API's create_job, arriving late.
    returned = create_job(job_id, tenant, "repo-lease", "alpine:3.20")

    job = get_job(job_id)

    assert job is not None
    assert job.status == "running"
    assert lease_is_live(job)

    # And the caller is handed the row that actually exists, not the one it
    # tried to write.
    assert returned.status == "running"


def _expire_lease(job_id: str) -> None:
    """Age a lease out without sleeping through JOB_LEASE_SECONDS."""
    from app.storage.client import table

    table("scan_jobs").update_item(
        Key={"job_id": job_id},
        UpdateExpression="SET lease_expires_at = :past",
        ExpressionAttributeValues={":past": now_epoch() - 1},
    )
