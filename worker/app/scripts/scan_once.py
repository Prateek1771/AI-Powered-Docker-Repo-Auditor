import asyncio
import json
import sys

from app.processors.vulnerabilities import (
    extract_vulnerabilities,
    prioritise,
)
from app.scanners.trivy import run_trivy_scan


async def main() -> None:
    target = sys.argv[1]

    raw = await run_trivy_scan(target)

    raw_bytes = len(json.dumps(raw))

    vulnerabilities = extract_vulnerabilities(raw)

    top = prioritise(vulnerabilities)

    reduced = json.dumps(
        [item.model_dump() for item in top],
        indent=2,
    )

    print(f"target:        {target}")
    print(f"raw bytes:     {raw_bytes:,}")
    print(f"vulns found:   {len(vulnerabilities):,}")
    print(f"sent to model: {len(top):,}")
    print(f"reduced bytes: {len(reduced):,}")
    print(f"reduction:     {raw_bytes / max(len(reduced), 1):.1f}x")


if __name__ == "__main__":
    asyncio.run(main())
