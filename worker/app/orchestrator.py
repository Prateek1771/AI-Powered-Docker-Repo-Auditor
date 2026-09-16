import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager

from app.agents.base_image_strategist import run_base_image_strategist
from app.agents.bloat_detective import run_bloat_detective
from app.agents.compliance_checker import run_compliance_checker
from app.agents.cve_analyst import run_cve_analyst
from app.agents.dockerfile_optimizer import run_dockerfile_optimizer
from app.agents.risk_scorer import run_risk_scorer
from app.agents.trust import outcomes_by_agent
from app.config.scanning import AGENT_TIMEOUT_SECONDS, TRIVY_IMAGE
from app.errors import PermanentFailure
from app.images import UPLOAD_SCHEME, discard_upload, resolve_target
from app.models.coverage import ScanCoverage
from app.models.findings import CVEFinding, fingerprint_findings
from app.models.outcomes import AgentOutcome, AgentStatus, ScanOutcome
from app.processors.compliance import check_deterministic_controls
from app.processors.enrich import enrich_cve_findings, fetch_enrichment
from app.processors.layers import extract_layers
from app.processors.packages import extract_packages
from app.processors.profile import build_profile
from app.processors.secrets import extract_secrets
from app.processors.vulnerabilities import (
    counts_by_severity,
    deduplicate,
    extract_vulnerabilities,
    prioritise,
)
from app.progress.bus import ProgressBus, ProgressEvent
from app.progress.redis_bus import RedisProgressBus
from app.scanners.docker_history import run_docker_history
from app.scanners.image_inspect import run_image_inspect
from app.scanners.trivy import run_trivy_scan
from app.storage.jobs import JobStatus, update_progress
from app.storage.results import ScanSummary, store_result
from app.telemetry import job_context, metrics

logger = logging.getLogger(__name__)

# Told when a pipeline node starts and when it settles. Optional everywhere:
# run_and_store supplies one that publishes to the progress bus, and the eval
# harness supplies nothing, which is what keeps the harness free of a bus.
NodeReporter = Callable[[str, str], Awaitable[None]]


async def _report_node(
    on_node: NodeReporter | None,
    name: str,
    state: str,
) -> None:
    """Tell the reporter a node changed state, if anyone is listening.

    Swallows its own failures for the same reason _report() does: a progress
    frame is a nice-to-have and the scan result is not.
    """
    if on_node is None:
        return

    try:
        await on_node(name, state)
    except Exception:
        logger.warning("Node progress publish failed for %s", name, exc_info=True)


async def _timed(
    name: str,
    coroutine: Awaitable,
    on_node: NodeReporter | None = None,
) -> AgentOutcome:
    """Run one agent and record how long it took.

    The duration lands in the outcome rather than only in a log, so the UI
    can show which agent is slow without anyone reading CloudWatch. The same
    two moments are announced to `on_node`, so a live client learns which
    agent is running instead of watching one bar sit at 40% for a minute.
    """
    start = time.perf_counter()

    await _report_node(on_node, name, "running")

    result = await coroutine

    await _report_node(on_node, name, result.status)

    return AgentOutcome(
        agent=name,
        status=result.status,
        findings=result.findings,
        duration_seconds=time.perf_counter() - start,
    )


def _degrade(
    name: str,
    error: Exception,
    elapsed: float = 0.0,
) -> AgentOutcome:
    """Turn an agent's exception into a recorded outcome, not a lost one.

    A timeout and a failure are kept apart because they mean different
    things to a reader, and both carry the error text forward - a scan
    that quietly dropped an agent would score as though it had run.

    `elapsed` is measured by the caller because this function is reached
    precisely when _timed() was not: an agent killed by asyncio.wait_for
    never returns, so its own timer dies with it. Left at the 0.0 default,
    every failed and timed-out agent recorded a duration of zero - so
    agent_duration_seconds read fastest exactly when an agent was hanging,
    which is the one case it exists to show. See docs/AUDIT_02 F2.
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
        duration_seconds=elapsed,
    )


async def _scanned(
    name: str,
    coroutine: Awaitable,
    on_node: NodeReporter | None = None,
) -> object:
    """Run one scanner, announcing when it starts and when it lands.

    Unlike an agent, a scanner failure is fatal to the scan - the gather
    below lets it propagate. The "failed" frame goes out first so a client
    sees which of the three died rather than only that something did.
    """
    await _report_node(on_node, name, "running")

    try:
        result = await coroutine
    except BaseException:
        await _report_node(on_node, name, "failed")
        raise

    await _report_node(on_node, name, "analysed")

    return result


async def _fetch_raw(
    target: str,
    on_node: NodeReporter | None = None,
) -> tuple:
    """Gather the three scanners, reporting each one separately.

    They are independent, so they run together; in registry mode they also
    share a single Trivy run underneath.

    `return_exceptions=True` and re-raise, rather than letting gather raise
    on the first failure. Default gather returns as soon as one raises and
    leaves the other two running, unawaited - two orphaned coroutines
    holding a Docker subprocess each, with nobody left to notice when they
    finish. Waiting for all three and then raising costs at most one
    scanner's remaining runtime on a path that is already failing. See
    docs/AUDIT.md P3-9.
    """
    results = await asyncio.gather(
        _scanned("trivy", run_trivy_scan(target), on_node),
        _scanned("docker_history", run_docker_history(target), on_node),
        _scanned("image_inspect", run_image_inspect(target), on_node),
        return_exceptions=True,
    )

    for result in results:
        if isinstance(result, BaseException):
            raise result

    return tuple(results)


async def run_scan(
    target: str,
    on_node: NodeReporter | None = None,
) -> ScanOutcome:
    """Scan an image end to end, fetching the raw data first."""
    trivy_raw, history_raw, inspect_raw = await _fetch_raw(target, on_node)

    return await run_scan_from_raw(
        target,
        trivy_raw,
        history_raw,
        inspect_raw,
        on_node,
    )


async def run_scan_from_raw(
    target: str,
    trivy_raw: dict,
    history_raw: list,
    inspect_raw: dict,
    on_node: NodeReporter | None = None,
) -> ScanOutcome:
    """Run all six agents over already-fetched scanner output.

    Split from run_scan so the eval harness can replay cached scanner
    output and measure the agents alone. The four independent agents run
    concurrently under a per-agent timeout, and the dependent two run
    after, seeing exactly which of their inputs can be trusted.

    `on_node` is optional throughout: passing nothing is exactly the old
    behaviour, which is what lets the eval harness call this without a bus.
    """
    found = extract_vulnerabilities(trivy_raw)

    # Collapse the same CVE reported against the same package before the cap
    # is applied, so one issue vendored into forty jars stops eating forty of
    # the 150 slots the model ever sees.
    vulnerabilities = deduplicate(found)

    layers = extract_layers(history_raw)
    profile = build_profile(target, inspect_raw, trivy_raw, layers)

    # Decided from the image config before any model is called, so these
    # controls are in the report even when every agent times out - and no
    # amount of injected text in the image can change the answer. This is
    # the half of the compliance check that needed reading, not judgement.
    # See docs/AUDIT.md P1-1.
    # Timed like every other outcome. These are fast, but a histogram where
    # two of eight agents only ever report the le="0" bucket is not measuring
    # them - it is diluting every quantile over the ones it does measure.
    cis_started = time.perf_counter()

    cis = AgentOutcome(
        agent="cis_controls",
        status="analysed",
        findings=fingerprint_findings(check_deterministic_controls(profile)),
        duration_seconds=time.perf_counter() - cis_started,
    )

    # Trivy has always been asked for these and the report has always carried
    # them; nothing ever read them. Deterministic, so like the CIS controls
    # they survive every agent failing. See docs/AUDIT.md P2-2.
    secrets_started = time.perf_counter()

    secrets = extract_secrets(trivy_raw)

    secret_scan = AgentOutcome(
        agent="secret_scan",
        status="analysed",
        findings=fingerprint_findings(secrets),
        duration_seconds=time.perf_counter() - secrets_started,
    )

    # Fetched once per scan, off the event loop: both are blocking HTTP and
    # the four agents are about to run concurrently.
    enrichment = await asyncio.to_thread(
        fetch_enrichment,
        [v.id for v in prioritise(vulnerabilities)],
    )

    independent = {
        "cve_analyst": run_cve_analyst(vulnerabilities),
        "bloat_detective": run_bloat_detective(layers),
        "base_image_strategist": run_base_image_strategist(profile),
        "compliance_checker": run_compliance_checker(profile, layers),
    }

    # All four start here, so elapsed-since-this-line IS each one's own
    # elapsed time - not an approximation of it. _timed() reports the exact
    # figure for the ones that return; this is for the ones that do not.
    independent_started = time.perf_counter()

    results = await asyncio.gather(
        *(
            asyncio.wait_for(
                _timed(name, coro, on_node),
                timeout=AGENT_TIMEOUT_SECONDS,
            )
            for name, coro in independent.items()
        ),
        return_exceptions=True,
    )

    outcomes = []

    for name, result in zip(independent, results):
        # Exception, not BaseException. With return_exceptions=True a
        # cancellation - a SIGTERM mid-scan, say - arrives here looking
        # exactly like an agent failure, and recording it as one writes a
        # stored report claiming the agent was tried and failed. It was
        # not. Re-raise so the scan aborts instead. See docs/AUDIT.md P3-10.
        if isinstance(result, BaseException) and not isinstance(result, Exception):
            raise result

        outcomes.append(
            _degrade(name, result, time.perf_counter() - independent_started)
            if isinstance(result, Exception)
            else result
        )

    # Staple the scanner's facts and the exploitability feeds onto whatever
    # the CVE agent wrote up. Unconditional: the scanner is the authority on
    # package, version and CVSS, and a model's second opinion on a measured
    # value is only a chance to be wrong. See docs/AUDIT.md P2-1.
    by_id = {item.id: item for item in prioritise(vulnerabilities)}

    for outcome in outcomes:
        if outcome.agent == "cve_analyst" and outcome.findings:
            outcome.findings = list(
                enrich_cve_findings(
                    [f for f in outcome.findings if isinstance(f, CVEFinding)],
                    by_id,
                    enrichment,
                )
            )

    # Every finding gets a stable identity, so two scans of the same repo can
    # be joined into a diff. Model prose varies run to run; a fingerprint
    # built from facts does not.
    for outcome in outcomes:
        outcome.findings = fingerprint_findings(outcome.findings)

    # Prepended, not appended: both ran first and neither can have failed.
    outcomes.insert(0, secret_scan)
    outcomes.insert(0, cis)

    # A timeout kills _timed before it can announce the result, so the
    # degraded outcomes are announced here instead. Without this a timed-out
    # agent stays "running" in the UI for the rest of the scan.
    for outcome in outcomes:
        if outcome.error is not None:
            await _report_node(on_node, outcome.agent, outcome.status)

    prior = outcomes_by_agent(outcomes)

    dockerfile = None
    start = time.perf_counter()

    await _report_node(on_node, "dockerfile_optimizer", "running")

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
        await _report_node(on_node, "dockerfile_optimizer", dockerfile.status)
    except Exception as exc:  # noqa: BLE001 - any agent failure degrades, never kills the scan
        degraded = _degrade("dockerfile_optimizer", exc, time.perf_counter() - start)
        outcomes.append(degraded)
        await _report_node(on_node, "dockerfile_optimizer", degraded.status)

    risk = None
    start = time.perf_counter()

    await _report_node(on_node, "risk_scorer", "running")

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
        await _report_node(on_node, "risk_scorer", "analysed")
    except Exception as exc:  # noqa: BLE001 - any agent failure degrades, never kills the scan
        degraded = _degrade("risk_scorer", exc, time.perf_counter() - start)
        outcomes.append(degraded)
        await _report_node(on_node, "risk_scorer", degraded.status)

    # What the scan actually looked at, as opposed to what got written up.
    # Without this the report silently claimed to be complete: only the worst
    # MAX_VULNERABILITIES_TO_MODEL ever reach a model and the rest were
    # unrecoverable. See docs/AUDIT.md P2-3, P2-4.
    metadata = trivy_raw.get("Metadata") or {}

    analysed = prioritise(vulnerabilities)

    coverage = ScanCoverage(
        total_vulnerabilities=len(vulnerabilities),
        counts_by_severity=counts_by_severity(vulnerabilities),
        dedup_removed=len(found) - len(vulnerabilities),
        sent_to_model=len(analysed),
        dropped=len(vulnerabilities) - len(analysed),
        total_secrets=len(secrets),
        kev_available=enrichment.kev_available,
        epss_available=enrichment.epss_available,
        image_id=metadata.get("ImageID", ""),
        repo_digests=list(metadata.get("RepoDigests") or []),
        scanner_image=TRIVY_IMAGE,
        trivy_schema_version=int(trivy_raw.get("SchemaVersion") or 0),
        scanned_at=trivy_raw.get("CreatedAt", ""),
    )

    # One pass over the finished list rather than instrumentation inside
    # _timed(). _timed only wraps the four independent agents, and an agent
    # killed by asyncio.wait_for never reaches its recording lines at all -
    # so hanging this off _timed would omit precisely the failures worth
    # alerting on. Every path, however it failed, appends to `outcomes`.
    for outcome in outcomes:
        metrics.agent_outcome.add(1, {"agent": outcome.agent, "status": outcome.status})
        metrics.agent_duration.record(
            outcome.duration_seconds, {"agent": outcome.agent}
        )

    for severity, count in coverage.counts_by_severity.items():
        metrics.vulnerabilities_found.add(count, {"severity": severity})

    metrics.vulnerabilities_analysed.add(coverage.sent_to_model)
    metrics.vulnerabilities_dropped.add(coverage.dropped)

    return ScanOutcome(
        target=target,
        outcomes=outcomes,
        profile=profile,
        dockerfile=dockerfile,
        risk=risk,
        coverage=coverage,
        packages=extract_packages(trivy_raw),
    )


@contextmanager
def _stage(name: str) -> Iterator[None]:
    """Time one stage of a scan.

    Three stages, matching the three things a scan spends time on: pulling and
    scanning the image, running the agents, and writing the result. Which one
    is slow is the first question anyone asks about a slow scan, and until now
    the answer needed a stopwatch.
    """
    start = time.perf_counter()

    try:
        yield
    finally:
        metrics.scan_duration.record(time.perf_counter() - start, {"stage": name})


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
    # to_thread: update_progress is a blocking DynamoDB write, and this
    # runs while four agents are in flight on the same loop. See
    # docs/AUDIT.md P3-9.
    await asyncio.to_thread(update_progress, job_id, status, progress, step)

    # Its own try: progress delivery is a nice-to-have, the scan result is not.
    try:
        await bus.publish(ProgressEvent.create(job_id, status, progress, step))
    except Exception:
        logger.warning("Progress publish failed for %s", job_id, exc_info=True)


# The nodes that settle during a scan, split into the two bands the stage
# frames already mark out: scanners occupy 10->40 ("Fetching image data" to
# "Running agents") and agents occupy 40->90 ("Running agents" to "Storing
# results").
#
# Sharing one 10->90 span across all nine was the obvious version and it made
# the bar go backwards: three settled scanners computed 37 while the stage
# frame published immediately after them said 40. Matching the bands to the
# stage numbers is what keeps the sequence monotonic.
_SCANNER_NODES = ("trivy", "docker_history", "image_inspect")

_AGENT_NODES = (
    "cve_analyst",
    "bloat_detective",
    "base_image_strategist",
    "compliance_checker",
    "dockerfile_optimizer",
    "risk_scorer",
)

_FETCHING_AT = 10

_AGENTS_AT = 40

_STORING_AT = 90


def _node_reporter(bus: ProgressBus, job_id: str) -> NodeReporter:
    """Build the callback that turns node transitions into progress frames.

    The bar is the reason this owns counters. Every settled node advances
    it a share of its band, so a run stops sitting at 40% for the whole
    agent phase - which is most of the scan.

    Node frames are published but deliberately NOT written to the job row:
    update_progress is a DynamoDB write, and nine extra writes per scan to
    move a bar is a cost the row does not need. A client that misses them
    still recovers the real state from the stage frames and the report.
    """
    settled = {"scanner": 0, "agent": 0}

    def _progress(node: str) -> int:
        if node in _SCANNER_NODES:
            share = settled["scanner"] / len(_SCANNER_NODES)

            return _FETCHING_AT + round(share * (_AGENTS_AT - _FETCHING_AT))

        share = settled["agent"] / len(_AGENT_NODES)

        return _AGENTS_AT + round(share * (_STORING_AT - _AGENTS_AT))

    async def report(node: str, state: str) -> None:
        if state != "running":
            settled["scanner" if node in _SCANNER_NODES else "agent"] += 1

        await bus.publish(
            ProgressEvent.create(
                job_id,
                "running",
                min(_progress(node), _STORING_AT),
                f"{node}: {state}",
                node=node,
                node_state=state,
            )
        )

    return report


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

    on_node = _node_reporter(bus, job_id)

    # Every log record emitted from here on carries the job id as a field,
    # including records from boto3, httpx and langchain. Previously the id was
    # interpolated into a message body, so a failure could be read but the
    # rest of its story could not be found. contextvars are copied into
    # asyncio.to_thread, so the store and progress writes below are covered.
    with job_context(job_id=job_id, tenant_id=tenant_id, repo_id=repo_id):
        try:
            if target.startswith(UPLOAD_SCHEME):
                await _report(bus, job_id, "running", 5, "Reading uploaded image")

            # An uploaded tar becomes a tarfile:// path here, before any scanner
            # sees it. It is never loaded into the daemon - see resolve_target.
            target = await resolve_target(tenant_id, target)

            await _report(bus, job_id, "running", 10, "Fetching image data")

            with _stage("fetch"):
                trivy_raw, history_raw, inspect_raw = await _fetch_raw(target, on_node)

            await _report(bus, job_id, "running", 40, "Running agents")

            with _stage("agents"):
                scan = await run_scan_from_raw(
                    target,
                    trivy_raw,
                    history_raw,
                    inspect_raw,
                    on_node,
                )

            await _report(bus, job_id, "running", 90, "Storing results")

            # Blocking DynamoDB + blob write, and the largest of them: the
            # report body plus the summary row.
            with _stage("store"):
                summary = await asyncio.to_thread(
                    store_result, job_id, tenant_id, repo_id, scan
                )

            await _report(bus, job_id, "completed", 100, "Scan complete")

            # Three outcomes, not two: a scan that finished is not the same as
            # a scan that finished with every agent intact, and the difference
            # is the whole point of tracking degradation.
            metrics.scan_result.add(
                1,
                {
                    "outcome": "degraded"
                    if summary.degraded
                    else ("findings" if summary.finding_count else "clean")
                },
            )

            return summary

        except Exception as exc:
            logger.exception("Scan %s failed", job_id)

            metrics.scan_result.add(
                1,
                {
                    "outcome": "failed",
                    "permanent": bool(getattr(exc, "permanent", False)),
                },
            )

            await _report(bus, job_id, "failed", 0, str(exc)[:200])

            # A scanner-level exception marked permanent (see app/errors.py) will
            # not succeed on redelivery, so translate it here - the one place
            # that already catches everything - into what the queue consumer
            # treats as final rather than retryable.
            if getattr(exc, "permanent", False):
                raise PermanentFailure(str(exc)) from exc

            raise

        finally:
            # One scan per upload, deleted whether the scan worked or not.
            # resolve_target used to do this, but the file now has to survive
            # until the scanners have actually read it off disk.
            discard_upload(target)

            # Without this each processed queue message leaks a connection and the
            # worker eventually exhausts Redis's client limit.
            await bus.close()
