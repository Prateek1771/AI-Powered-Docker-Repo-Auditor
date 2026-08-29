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
            f"  {outcome.agent:22} {outcome.status:22} "
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

    print()

    if scan.risk:
        print(f"overall:    {scan.risk.score.overall}/100")
        print(f"security:   {scan.risk.score.security}/100")
        print(f"efficiency: {scan.risk.score.efficiency}/100")
        print(f"compliance: {scan.risk.score.compliance}/100")
        print(f"confidence: {scan.risk.confidence:.0%}")

        if scan.risk.inputs_missing:
            print(f"missing:    {', '.join(scan.risk.inputs_missing)}")

        print()
        print(scan.risk.score.summary)

    if scan.dockerfile and scan.dockerfile.status == "skipped_degraded_input":
        print()
        print(
            "Dockerfile skipped, unsound inputs: "
            f"{', '.join(scan.dockerfile.skipped_because)}"
        )
    elif scan.dockerfile and scan.dockerfile.optimization:
        print()
        print("Optimized Dockerfile:")
        print(scan.dockerfile.optimization.optimized)


if __name__ == "__main__":
    asyncio.run(main())
