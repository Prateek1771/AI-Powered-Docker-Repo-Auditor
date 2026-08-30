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
from app.progress.bus import ProgressBus, ProgressEvent
from app.progress.redis_bus import RedisProgressBus
from app.scanners.docker_history import run_docker_history
from app.scanners.image_inspect import run_image_inspect
from app.scanners.trivy import run_trivy_scan
from app.storage.jobs import JobStatus, update_progress
from app.storage.results import ScanSummary, store_result

logger = logging.getLogger(__name__)


async def _timed(
    name: str,
    coroutine: Awaitable,
) -> AgentOutcome:
    """Run one agent and record how long it took.

    The duration lands in the outcome rather than only in a log, so the UI
    can show which agent is slow without anyone reading CloudWatch.
    """
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
    """Turn an agent's exception into a recorded outcome, not a lost one.

    A timeout and a failure are kept apart because they mean different
    things to a reader, and both carry the error text forward - a scan
    that quietly dropped an agent would score as though it had run.
    """
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
    """Scan an image end to end, fetching the raw data first.

    The three scanners are gathered because they are independent; in
    registry mode they also share a single Trivy run underneath.
    """
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
    """Run all six agents over already-fetched scanner output.

    Split from run_scan so the eval harness can replay cached scanner
    output and measure the agents alone. The four independent agents run
    concurrently under a per-agent timeout, and the dependent two run
    after, seeing exactly which of their inputs can be trusted.
    """
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


async def _report(
    bus: ProgressBus,
    job_id: str,
    status: JobStatus,
    progress: int,
    step: str,
) -> None:
    # DynamoDB first, then the bus. The database is the source of truth and a
    # client that misses an event can always recover by reading state, so a
    # Redis outage must not fail a scan that is otherwise working.
    """Record progress in the job row and publish it to the bus.

    The publish has its own try because delivery of a progress event is a
    nice-to-have and the scan result is not.
    """
    update_progress(job_id, status, progress, step)

    # Its own try: progress delivery is a nice-to-have, the scan result is not.
    try:
        await bus.publish(ProgressEvent.create(job_id, status, progress, step))
    except Exception:
        logger.warning("Progress publish failed for %s", job_id, exc_info=True)


async def run_and_store(
    job_id: str,
    tenant_id: str,
    repo_id: str,
    target: str,
) -> ScanSummary:
    # The job row is the caller's to create: the API writes it at 202 so
    # the client can subscribe immediately, and creating it again here
    # would stomp the running state claim_job just won.
    """Run a scan for a queued job and persist the result.

    The entry point the worker calls. Reports progress at each stage and
    always closes the bus, because a leaked connection per message would
    eventually exhaust Redis's client limit.
    """
    bus: ProgressBus = RedisProgressBus()

    try:
        await _report(bus, job_id, "running", 10, "Fetching image data")

        trivy_raw, history_raw, inspect_raw = await asyncio.gather(
            run_trivy_scan(target),
            run_docker_history(target),
            run_image_inspect(target),
        )

        await _report(bus, job_id, "running", 40, "Running agents")

        scan = await run_scan_from_raw(target, trivy_raw, history_raw, inspect_raw)

        await _report(bus, job_id, "running", 90, "Storing results")

        summary = store_result(job_id, tenant_id, repo_id, scan)

        await _report(bus, job_id, "completed", 100, "Scan complete")

        return summary

    except Exception as exc:
        logger.exception("Scan %s failed", job_id)

        await _report(bus, job_id, "failed", 0, str(exc)[:200])

        raise

    finally:
        # Without this each processed queue message leaks a connection and the
        # worker eventually exhausts Redis's client limit.
        await bus.close()
