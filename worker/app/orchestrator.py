import asyncio
import logging
import time
from collections.abc import Awaitable

from app.agents.bloat_detective import run_bloat_detective
from app.agents.cve_analyst import run_cve_analyst
from app.config.scanning import AGENT_TIMEOUT_SECONDS
from app.models.outcomes import AgentOutcome, AgentStatus, ScanOutcome
from app.processors.layers import extract_layers
from app.processors.vulnerabilities import extract_vulnerabilities
from app.scanners.docker_history import run_docker_history
from app.scanners.trivy import run_trivy_scan

logger = logging.getLogger(__name__)


async def _timed(
    name: str,
    coroutine: Awaitable,
) -> AgentOutcome:
    start = time.perf_counter()

    result = await coroutine

    return AgentOutcome(
        agent=name,
        status=result.status,
        findings=result.findings,
        duration_seconds=time.perf_counter() - start,
    )


def _degrade(
    name: str,
    error: BaseException,
) -> AgentOutcome:
    status: AgentStatus = (
        "timed_out" if isinstance(error, asyncio.TimeoutError) else "failed"
    )

    logger.warning(
        "Agent %s %s: %s",
        name,
        status,
        error,
    )

    return AgentOutcome(
        agent=name,
        status=status,
        findings=[],
        error=str(error) or error.__class__.__name__,
    )


async def run_scan(target: str) -> ScanOutcome:
    trivy_raw, history_raw = await asyncio.gather(
        run_trivy_scan(target),
        run_docker_history(target),
    )

    vulnerabilities = extract_vulnerabilities(trivy_raw)
    layers = extract_layers(history_raw)

    results = await asyncio.gather(
        asyncio.wait_for(
            _timed("cve_analyst", run_cve_analyst(vulnerabilities)),
            timeout=AGENT_TIMEOUT_SECONDS,
        ),
        asyncio.wait_for(
            _timed("bloat_detective", run_bloat_detective(layers)),
            timeout=AGENT_TIMEOUT_SECONDS,
        ),
        return_exceptions=True,
    )

    names = ["cve_analyst", "bloat_detective"]

    outcomes = [
        _degrade(name, result) if isinstance(result, BaseException) else result
        for name, result in zip(names, results)
    ]

    return ScanOutcome(target=target, outcomes=outcomes)
