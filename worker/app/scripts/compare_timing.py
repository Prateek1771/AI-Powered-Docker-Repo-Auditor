import asyncio
import sys
import time

from app.agents.bloat_detective import run_bloat_detective
from app.agents.cve_analyst import run_cve_analyst
from app.processors.layers import extract_layers
from app.processors.vulnerabilities import extract_vulnerabilities
from app.scanners.docker_history import run_docker_history
from app.scanners.trivy import run_trivy_scan


async def main() -> None:
    target = sys.argv[1]

    trivy_raw, history_raw = await asyncio.gather(
        run_trivy_scan(target),
        run_docker_history(target),
    )

    vulnerabilities = extract_vulnerabilities(trivy_raw)
    layers = extract_layers(history_raw)

    start = time.perf_counter()
    await run_cve_analyst(vulnerabilities)
    await run_bloat_detective(layers)
    sequential = time.perf_counter() - start

    start = time.perf_counter()
    await asyncio.gather(
        run_cve_analyst(vulnerabilities),
        run_bloat_detective(layers),
    )
    parallel = time.perf_counter() - start

    print(f"sequential: {sequential:.1f}s")
    print(f"parallel:   {parallel:.1f}s")
    print(f"speedup:    {sequential / parallel:.2f}x")


if __name__ == "__main__":
    asyncio.run(main())
