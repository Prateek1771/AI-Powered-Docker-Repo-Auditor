from fastapi import Depends, HTTPException

from app.core.auth import Principal, current_principal
from app.storage.results import ScanSummary, get_summary


def owned_scan(
    job_id: str,
    principal: Principal = Depends(current_principal),
) -> ScanSummary:
    summary = get_summary(job_id)

    # Missing and forbidden return the SAME 404. A 403 for "exists but not
    # yours" leaks existence and lets an attacker enumerate job ids.
    if summary is None or summary.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    return summary
