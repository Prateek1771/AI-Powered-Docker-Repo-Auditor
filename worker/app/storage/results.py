import logging

from boto3.dynamodb.conditions import Key
from pydantic import BaseModel

from app.config.storage import MAX_ITEM_BYTES
from app.models.outcomes import ScanOutcome
from app.storage.blobs import get_blob, put_blob
from app.storage.client import table
from app.storage.serialization import item_size, now_iso, to_item

logger = logging.getLogger(__name__)


def tenant_repo_key(tenant_id: str, repo_id: str) -> str:
    return f"{tenant_id}#{repo_id}"


class ScanSummary(BaseModel):
    job_id: str
    tenant_id: str
    repo_id: str
    tenant_repo: str
    target: str
    scan_date: str
    degraded: bool
    confidence: float = 0.0
    overall: int = 0
    security: int = 0
    efficiency: int = 0
    compliance: int = 0
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    report_key: str


def _counts(scan: ScanOutcome) -> tuple[int, int, int]:
    findings = scan.all_findings

    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")

    return len(findings), critical, high


def store_result(
    job_id: str,
    tenant_id: str,
    repo_id: str,
    scan: ScanOutcome,
) -> ScanSummary:
    report_key = f"reports/{tenant_id}/{job_id}"

    put_blob(
        report_key,
        {
            "job_id": job_id,
            "outcomes": [o.model_dump() for o in scan.outcomes],
            "dockerfile": scan.dockerfile.model_dump() if scan.dockerfile else None,
            "risk": scan.risk.model_dump() if scan.risk else None,
            "profile": scan.profile.model_dump() if scan.profile else None,
        },
    )

    total, critical, high = _counts(scan)

    summary = ScanSummary(
        job_id=job_id,
        tenant_id=tenant_id,
        repo_id=repo_id,
        tenant_repo=tenant_repo_key(tenant_id, repo_id),
        target=scan.target,
        scan_date=now_iso(),
        degraded=scan.degraded,
        confidence=scan.risk.confidence if scan.risk else 0.0,
        overall=scan.risk.score.overall if scan.risk else 0,
        security=scan.risk.score.security if scan.risk else 0,
        efficiency=scan.risk.score.efficiency if scan.risk else 0,
        compliance=scan.risk.score.compliance if scan.risk else 0,
        finding_count=total,
        critical_count=critical,
        high_count=high,
        report_key=report_key,
    )

    item = to_item(summary)

    size = item_size(item)

    if size > MAX_ITEM_BYTES:
        raise ValueError(
            f"Summary item is {size} bytes, over the {MAX_ITEM_BYTES} limit"
        )

    table("scan_results").put_item(Item=item)

    logger.info(
        "Stored scan %s: %d findings, %d bytes in dynamo",
        job_id,
        total,
        size,
    )

    return summary


def get_summary(job_id: str) -> ScanSummary | None:
    resp = table("scan_results").get_item(Key={"job_id": job_id})

    item = resp.get("Item")

    return ScanSummary.model_validate(item) if item else None


def get_full_report(job_id: str) -> dict | None:
    summary = get_summary(job_id)

    if summary is None:
        return None

    return get_blob(summary.report_key)


def previous_scan(
    tenant_id: str,
    repo_id: str,
    before_job_id: str | None = None,
) -> ScanSummary | None:
    resp = table("scan_results").query(
        IndexName="TenantRepoIndex",
        KeyConditionExpression=Key("tenant_repo").eq(
            tenant_repo_key(tenant_id, repo_id)
        ),
        ScanIndexForward=False,
        Limit=2,
    )

    for item in resp.get("Items", []):
        summary = ScanSummary.model_validate(item)

        if summary.job_id != before_job_id:
            return summary

    return None


def scan_history(
    tenant_id: str,
    repo_id: str,
    limit: int = 30,
) -> list[ScanSummary]:
    resp = table("scan_results").query(
        IndexName="TenantRepoIndex",
        KeyConditionExpression=Key("tenant_repo").eq(
            tenant_repo_key(tenant_id, repo_id)
        ),
        ScanIndexForward=False,
        Limit=limit,
    )

    return [ScanSummary.model_validate(item) for item in resp.get("Items", [])]
