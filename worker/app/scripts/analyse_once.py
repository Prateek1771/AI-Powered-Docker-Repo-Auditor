import asyncio
import os
import sys
from pathlib import Path

from app.agents.cve_analyst import run_cve_analyst
from app.processors.vulnerabilities import extract_vulnerabilities
from app.scanners.trivy import run_trivy_scan

# ponytail: 4-line .env loader beats adding python-dotenv; swap for
# pydantic-settings if config outgrows a handful of keys.
_ENV_FILE = Path(__file__).parents[2] / ".env"
if _ENV_FILE.exists():
    for line in _ENV_FILE.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


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
