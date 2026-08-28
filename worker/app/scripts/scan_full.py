import asyncio
import sys

from app.orchestrator import run_scan


async def main() -> None:
    scan = await run_scan(sys.argv[1])

    print(f"target:   {scan.target}")
    print(f"degraded: {scan.degraded}")
    print()

    for outcome in scan.outcomes:
        print(
            f"  {outcome.agent:18} {outcome.status:18} "
            f"{len(outcome.findings):3d} findings  "
            f"{outcome.duration_seconds:5.1f}s"
        )
        if outcome.error:
            print(f"    error: {outcome.error}")

    print()

    for finding in sorted(
        scan.all_findings,
        key=lambda item: -item.priority,
    )[:8]:
        print(f"[{finding.priority:3d}] ({finding.category}) {finding.title}")
        print(f"       fix: {finding.fix}")


if __name__ == "__main__":
    asyncio.run(main())
