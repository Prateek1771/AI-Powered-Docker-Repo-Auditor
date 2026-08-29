import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import owned_scan
from app.api.models import (
    JobStatusResponse,
    ScanAccepted,
    StartScanRequest,
)
from app.core.auth import Principal, current_principal
from app.core.ratelimit import scan_rate_limit
from app.queue.producer import enqueue_scan
from app.storage.jobs import create_job, get_job
from app.storage.results import (
    ScanSummary,
    get_full_report,
    scan_history,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


@router.post("", response_model=ScanAccepted, status_code=202)
def start_scan(
    request: StartScanRequest,
    principal: Principal = Depends(scan_rate_limit),
) -> ScanAccepted:
    message = enqueue_scan(
        principal.tenant_id,
        request.repo_id,
        request.target,
    )

    # Enqueue first - that is the durable part - then write the queued row, so
    # the job_id we hand back is readable by GET /jobs and subscribable over
    # the WebSocket immediately. Without it both 404 until a worker picks the
    # message up, which is a window the client has no way to wait out.
    create_job(
        message.job_id,
        principal.tenant_id,
        message.repo_id,
        request.target,
    )

    return ScanAccepted(
        job_id=message.job_id,
        status="queued",
        repo_id=message.repo_id,
        enqueued_at=message.enqueued_at,
    )


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
def job_status(
    job_id: str,
    principal: Principal = Depends(current_principal),
) -> JobStatusResponse:
    job = get_job(job_id)

    if job is None or job.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Job not found")

    return JobStatusResponse(
        job_id=job.job_id,
        status=job.status,
        progress=job.progress,
        current_step=job.current_step,
        started_at=job.started_at,
        updated_at=job.updated_at,
    )


@router.get("/history/{repo_id}", response_model=list[ScanSummary])
def history(
    repo_id: str,
    principal: Principal = Depends(current_principal),
    limit: int = Query(default=30, ge=1, le=100),
) -> list[ScanSummary]:
    return scan_history(principal.tenant_id, repo_id, limit=limit)


@router.get("/{job_id}", response_model=ScanSummary)
def scan_summary(summary: ScanSummary = Depends(owned_scan)) -> ScanSummary:
    return summary


@router.get("/{job_id}/report")
def scan_report(summary: ScanSummary = Depends(owned_scan)) -> dict:
    report = get_full_report(summary.job_id)

    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    return report
