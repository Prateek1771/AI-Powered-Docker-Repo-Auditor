import logging

from boto3.dynamodb.conditions import Key
from pydantic import BaseModel

from app.config.storage import MAX_ITEM_BYTES, SCAN_TTL_DAYS
from app.models.outcomes import ScanOutcome
from app.storage.blobs import get_blob, put_blob
from app.storage.client import table
from app.storage.diff import diff_against_previous
from app.storage.serialization import item_size, now_iso, to_item, ttl_epoch

logger = logging.getLogger(__name__)


def tenant_repo_key(tenant_id: str, repo_id: str) -> str:
    """Build the composite partition key the results GSI is keyed on.

    Combining the two into one attribute is the tenancy fix. Keyed on repo
    alone, a query has to filter after the limit, which lets one tenant's
    rows hide another's.
    """
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
    # None where the axis had no trustworthy evidence. NOT zero: zero is a
    # real score meaning "as bad as it gets", and rendering "we could not
    # tell" as that is the same class of lie this phase exists to remove.
    overall: int | None = None
    security: int | None = None
    efficiency: int | None = None
    compliance: int | None = None
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    report_key: str

    # The results table had no TTL while the S3 lifecycle expired report
    # bodies at 30 days - and terraform's own comment claimed the row expired
    # too. So summaries outlived their bodies and /report 404'd forever after.
    # Mirrors the jobs table, which has always done this. See docs/audits/audit-01-backend.md.
    expires_at: int = 0


def _counts(scan: ScanOutcome) -> tuple[int, int, int]:
    """Count findings for the summary row.

    critical/high come from the SCANNER's tally when there is one, not from
    the findings the model chose to write up. These are displayed as scan
    metrics, and computing them from model output meant a 400-CVE image
    whose agent returned four findings reported four - with the model's own
    severities. See docs/audits/audit-01-backend.md P2-4.

    `finding_count` stays the number of written-up findings, because that
    is what it honestly is: how many things the report tells you about.
    """
    findings = scan.all_findings

    if scan.coverage is not None:
        counts = scan.coverage.counts_by_severity

        return (
            len(findings),
            counts.get("critical", 0),
            counts.get("high", 0),
        )

    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")

    return len(findings), critical, high


def store_result(
    job_id: str,
    tenant_id: str,
    repo_id: str,
    scan: ScanOutcome,
) -> ScanSummary:
    """Persist a finished scan: body to blob storage, summary to DynamoDB.

    The size check refuses an oversized item deliberately rather than
    letting DynamoDB reject it, so the failure names our limit.
    """
    report_key = f"reports/{tenant_id}/{job_id}"

    # What changed since the last scan of this repo. previous_scan() has
    # existed and been tested since Phase 6 and was called by nothing, so a
    # report could never say whether it was better or worse than the last
    # one. See docs/audits/audit-01-backend.md P2-5.
    diff = diff_against_previous(tenant_id, repo_id, job_id, scan)

    put_blob(
        report_key,
        {
            "job_id": job_id,
            # The image reference lived only on the summary row, so the blob
            # could not say what it was a report ABOUT. Any export needs it.
            "target": scan.target,
            "outcomes": [o.model_dump() for o in scan.outcomes],
            "dockerfile": scan.dockerfile.model_dump() if scan.dockerfile else None,
            "risk": scan.risk.model_dump() if scan.risk else None,
            "profile": scan.profile.model_dump() if scan.profile else None,
            "coverage": scan.coverage.model_dump() if scan.coverage else None,
            "packages": [p.model_dump() for p in scan.packages],
            "diff": diff.model_dump() if diff else None,
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
        expires_at=ttl_epoch(SCAN_TTL_DAYS),
        degraded=scan.degraded,
        confidence=scan.risk.confidence if scan.risk else 0.0,
        overall=scan.risk.score.overall if scan.risk else None,
        security=scan.risk.score.security if scan.risk else None,
        efficiency=scan.risk.score.efficiency if scan.risk else None,
        compliance=scan.risk.score.compliance if scan.risk else None,
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
    """Load a scan's summary row, or None if there is none."""
    resp = table("scan_results").get_item(Key={"job_id": job_id})

    item = resp.get("Item")

    return ScanSummary.model_validate(item) if item else None


def get_full_report(job_id: str) -> dict | None:
    """Load a scan's full report, following the summary to its blob."""
    summary = get_summary(job_id)

    if summary is None:
        return None

    return get_blob(summary.report_key)


def previous_scan(
    tenant_id: str,
    repo_id: str,
    before_job_id: str | None = None,
) -> ScanSummary | None:
    """Find the scan before this one for the same tenant and repo.

    Fetches two and skips `before_job_id`, because the newest row is
    usually the scan asking the question.
    """
    resp = table("scan_results").query(
        IndexName="TenantRepoIndex",
        KeyConditionExpression=Key("tenant_repo").eq(
            tenant_repo_key(tenant_id, repo_id)
        ),
        ScanIndexForward=False,
        # Three, not two. The filter below drops before_job_id, and Limit is
        # applied by DynamoDB BEFORE that filter - so with two, a repo whose
        # newest row is the scan asking the question plus one unrelated
        # ordering quirk returned None even though a prior scan existed.
        Limit=3,
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
    """List a tenant's scans of one repo, newest first."""
    resp = table("scan_results").query(
        IndexName="TenantRepoIndex",
        KeyConditionExpression=Key("tenant_repo").eq(
            tenant_repo_key(tenant_id, repo_id)
        ),
        ScanIndexForward=False,
        Limit=limit,
    )

    return [ScanSummary.model_validate(item) for item in resp.get("Items", [])]
