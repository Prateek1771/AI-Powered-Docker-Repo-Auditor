import asyncio
import logging
import time
from collections.abc import Awaitable

from app.agents.base_image_strategist import run_base_image_strategist
from app.agents.bloat_detective import run_bloat_detective
from app.agents.compliance_checker import run_compliance_checker
from app.agents.cve_analyst import run_cve_analyst
from app.agents.dockerfile_optimizer import run_dockerfile_optimizer
from app.agents.risk_scorer import run_risk_scorer
from app.agents.trust import outcomes_by_agent
from app.config.scanning import AGENT_TIMEOUT_SECONDS
from app.models.outcomes import AgentOutcome, AgentStatus, ScanOutcome
from app.processors.layers import extract_layers
from app.processors.profile import build_profile
from app.processors.vulnerabilities import extract_vulnerabilities
from app.scanners.docker_history import run_docker_history
from app.scanners.image_inspect import run_image_inspect
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
    trivy_raw, history_raw, inspect_raw = await asyncio.gather(
        run_trivy_scan(target),
        run_docker_history(target),
        run_image_inspect(target),
    )

    return await run_scan_from_raw(target, trivy_raw, history_raw, inspect_raw)


async def run_scan_from_raw(
    target: str,
    trivy_raw: dict,
    history_raw: list,
    inspect_raw: dict,
) -> ScanOutcome:
    vulnerabilities = extract_vulnerabilities(trivy_raw)
    layers = extract_layers(history_raw)
    profile = build_profile(target, inspect_raw, trivy_raw, layers)

    independent = {
        "cve_analyst": run_cve_analyst(vulnerabilities),
        "bloat_detective": run_bloat_detective(layers),
        "base_image_strategist": run_base_image_strategist(profile),
        "compliance_checker": run_compliance_checker(profile, layers),
    }

    results = await asyncio.gather(
        *(
            asyncio.wait_for(_timed(name, coro), timeout=AGENT_TIMEOUT_SECONDS)
            for name, coro in independent.items()
        ),
        return_exceptions=True,
    )

    outcomes = [
        _degrade(name, result) if isinstance(result, BaseException) else result
        for name, result in zip(independent, results)
    ]

    prior = outcomes_by_agent(outcomes)

    dockerfile = None
    start = time.perf_counter()

    try:
        dockerfile = await asyncio.wait_for(
            run_dockerfile_optimizer(layers, prior),
            timeout=AGENT_TIMEOUT_SECONDS,
        )
        outcomes.append(
            AgentOutcome(
                agent="dockerfile_optimizer",
                status=dockerfile.status,
                findings=[],
                duration_seconds=time.perf_counter() - start,
            )
        )
    except Exception as exc:  # noqa: BLE001 - any agent failure degrades, never kills the scan
        outcomes.append(_degrade("dockerfile_optimizer", exc))

    risk = None
    start = time.perf_counter()

    try:
        risk = await asyncio.wait_for(
            run_risk_scorer(prior),
            timeout=AGENT_TIMEOUT_SECONDS,
        )
        outcomes.append(
            AgentOutcome(
                agent="risk_scorer",
                status="analysed",
                findings=[],
                duration_seconds=time.perf_counter() - start,
            )
        )
    except Exception as exc:  # noqa: BLE001 - any agent failure degrades, never kills the scan
        outcomes.append(_degrade("risk_scorer", exc))

    return ScanOutcome(
        target=target,
        outcomes=outcomes,
        profile=profile,
        dockerfile=dockerfile,
        risk=risk,
    )
