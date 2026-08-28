import asyncio
import sys

from app.agents.cve_analyst import run_cve_analyst
from app.processors.vulnerabilities import extract_vulnerabilities
from app.scanners.trivy import run_trivy_scan


async def main() -> None:
    target = sys.argv[1]

    raw = await run_trivy_scan(target)

    vulnerabilities = extract_vulnerabilities(raw)

    result = await run_cve_analyst(vulnerabilities)

    print(f"status:    {result.status}")
    print(f"examined:  {result.vulnerabilities_examined}")
    print(f"findings:  {len(result.findings)}")
    print()

    for finding in sorted(
        result.findings,
        key=lambda item: -item.priority,
    )[:5]:
        print(
            f"[{finding.priority:3d}] {finding.vulnerability_id}  ({finding.severity})"
        )
        print(f"       {finding.title}")
        print(f"       fix: {finding.fix}")
        print(f"       effort: {finding.effort} | {finding.exploitability}")
        print()


if __name__ == "__main__":
    asyncio.run(main())
