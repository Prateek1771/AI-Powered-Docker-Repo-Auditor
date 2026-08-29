import uuid

import pytest

from app.models.outcomes import AgentOutcome, ScanOutcome
from app.storage.jobs import create_job, get_job, recent_jobs, update_progress
from app.storage.results import (
    get_full_report,
    previous_scan,
    scan_history,
    store_result,
)

pytestmark = pytest.mark.integration


def _scan(target: str = "python:3.8") -> ScanOutcome:
    return ScanOutcome(
        target=target,
        outcomes=[
            AgentOutcome(
                agent="cve_analyst",
                status="analysed",
                findings=[],
            )
        ],
    )


def test_job_roundtrip(tenant: str) -> None:
    job_id = str(uuid.uuid4())

    create_job(job_id, tenant, "repo-a", "python:3.8")

    update_progress(job_id, "running", 40, "Running agents")

    job = get_job(job_id)

    assert job is not None
    assert job.status == "running"
    assert job.progress == 40
    assert job.current_step == "Running agents"


def test_ttl_is_an_integer_epoch(tenant: str) -> None:
    job_id = str(uuid.uuid4())

    record = create_job(job_id, tenant, "repo-a", "python:3.8")

    assert isinstance(record.expires_at, int)
    assert record.expires_at > 1_700_000_000


def test_update_preserves_unnamed_attributes(tenant: str) -> None:
    job_id = str(uuid.uuid4())

    create_job(job_id, tenant, "repo-a", "python:3.8")

    update_progress(job_id, "running", 10, "Working")

    job = get_job(job_id)

    assert job is not None
    assert job.target == "python:3.8"
    assert job.expires_at > 0


def test_floats_survive_the_roundtrip(tenant: str) -> None:
    job_id = str(uuid.uuid4())

    summary = store_result(job_id, tenant, "repo-a", _scan())

    assert isinstance(summary.confidence, float)

    report = get_full_report(job_id)

    assert report is not None
    assert report["job_id"] == job_id


def test_previous_scan_finds_the_prior_run(tenant: str) -> None:
    first = str(uuid.uuid4())
    second = str(uuid.uuid4())

    store_result(first, tenant, "repo-a", _scan())
    store_result(second, tenant, "repo-a", _scan())

    prev = previous_scan(tenant, "repo-a", before_job_id=second)

    assert prev is not None
    assert prev.job_id == first


def test_tenants_do_not_see_each_other(tenant: str) -> None:
    other = f"{tenant}-other"

    mine = str(uuid.uuid4())
    theirs = str(uuid.uuid4())

    store_result(mine, tenant, "nginx", _scan())
    store_result(theirs, other, "nginx", _scan())

    history = scan_history(tenant, "nginx")

    assert [s.job_id for s in history] == [mine]


def test_recent_jobs_are_newest_first(tenant: str) -> None:
    ids = [str(uuid.uuid4()) for _ in range(3)]

    for job_id in ids:
        create_job(job_id, tenant, "repo-a", "python:3.8")

    jobs = recent_jobs(tenant)

    assert [j.job_id for j in jobs] == list(reversed(ids))
