import asyncio
import sys
import uuid

from app.orchestrator import run_and_store
from app.storage.jobs import create_job
from app.storage.results import get_full_report, scan_history


async def main() -> None:
    target = sys.argv[1]
    tenant = "demo-tenant"
    repo = target.split(":")[0]

    job_id = str(uuid.uuid4())

    create_job(job_id, tenant, repo, target)

    summary = await run_and_store(job_id, tenant, repo, target)

    print(f"job:        {summary.job_id}")
    print(f"overall:    {summary.overall}/100")
    print(f"confidence: {summary.confidence:.0%}")
    print(f"findings:   {summary.finding_count}")
    print(f"degraded:   {summary.degraded}")
    print(f"report key: {summary.report_key}")

    print("\nhistory:")

    for entry in scan_history(tenant, repo):
        print(f"  {entry.scan_date}  {entry.overall:3d}/100  {entry.job_id[:8]}")

    report = get_full_report(job_id)

    if report is None:
        print("\nfull report missing")
    else:
        print(f"\nfull report agents: {len(report['outcomes'])}")


if __name__ == "__main__":
    asyncio.run(main())
