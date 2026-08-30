import asyncio

import pytest

from app.errors import PermanentFailure
from app.models.outcomes import AgentOutcome, ScanOutcome
from app.orchestrator import run_and_store
from app.scanners.docker_history import DockerHistoryError


def _outcome(name: str, status: str, count: int = 0) -> AgentOutcome:
    return AgentOutcome(
        agent=name,
        status=status,
        findings=[],
        error=None if status == "analysed" else "boom",
    )


def test_scan_is_degraded_when_an_agent_fails() -> None:
    scan = ScanOutcome(
        target="python:3.8",
        outcomes=[
            _outcome("cve_analyst", "analysed"),
            _outcome("bloat_detective", "failed"),
        ],
    )

    assert scan.degraded is True


def test_clean_scan_is_not_degraded() -> None:
    scan = ScanOutcome(
        target="alpine:3.20",
        outcomes=[
            _outcome("cve_analyst", "skipped_no_input"),
            _outcome("bloat_detective", "analysed"),
        ],
    )

    assert scan.degraded is False


def test_empty_findings_alone_does_not_mean_clean() -> None:
    degraded = ScanOutcome(
        target="python:3.8",
        outcomes=[_outcome("cve_analyst", "failed")],
    )

    clean = ScanOutcome(
        target="alpine:3.20",
        outcomes=[_outcome("cve_analyst", "skipped_no_input")],
    )

    assert degraded.all_findings == clean.all_findings == []
    assert degraded.degraded != clean.degraded


async def test_gather_isolates_failure() -> None:
    async def good() -> str:
        await asyncio.sleep(0.01)
        return "ok"

    async def bad() -> str:
        raise RuntimeError("boom")

    results = await asyncio.gather(
        good(),
        bad(),
        return_exceptions=True,
    )

    assert results[0] == "ok"
    assert isinstance(results[1], BaseException)


async def test_wait_for_produces_timeout_error() -> None:
    async def slow() -> str:
        await asyncio.sleep(5)
        return "never"

    results = await asyncio.gather(
        asyncio.wait_for(slow(), timeout=0.05),
        return_exceptions=True,
    )

    assert isinstance(results[0], asyncio.TimeoutError)


class _FakeBus:
    """A ProgressBus double - run_and_store only ever publishes and closes it."""

    async def publish(self, event) -> None:
        return None

    async def close(self) -> None:
        return None


async def test_a_permanent_scanner_failure_raises_permanent_failure(
    monkeypatch,
) -> None:
    # A bad/missing image reference should short-circuit the queue's retry
    # loop instead of falling into the generic redeliver-and-retry path.
    async def bad_reference(target: str):
        raise DockerHistoryError(
            f"Could not pull {target}: manifest unknown", permanent=True
        )

    monkeypatch.setattr("app.orchestrator.run_trivy_scan", bad_reference)
    monkeypatch.setattr("app.orchestrator.run_docker_history", bad_reference)
    monkeypatch.setattr("app.orchestrator.run_image_inspect", bad_reference)
    monkeypatch.setattr("app.orchestrator.RedisProgressBus", _FakeBus)
    monkeypatch.setattr("app.orchestrator.update_progress", lambda *a, **k: None)
    monkeypatch.setattr(
        "app.orchestrator.store_result",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError),
    )

    with pytest.raises(PermanentFailure):
        await run_and_store("job-1", "tenant-a", "repo-a", "does-not-exist:bogus")


async def test_a_transient_scanner_failure_stays_a_plain_exception(
    monkeypatch,
) -> None:
    async def timed_out(target: str):
        raise DockerHistoryError(f"Command timed out: docker pull {target}")

    monkeypatch.setattr("app.orchestrator.run_trivy_scan", timed_out)
    monkeypatch.setattr("app.orchestrator.run_docker_history", timed_out)
    monkeypatch.setattr("app.orchestrator.run_image_inspect", timed_out)
    monkeypatch.setattr("app.orchestrator.RedisProgressBus", _FakeBus)
    monkeypatch.setattr("app.orchestrator.update_progress", lambda *a, **k: None)

    with pytest.raises(DockerHistoryError):
        await run_and_store("job-2", "tenant-a", "repo-a", "alpine:3.20")
